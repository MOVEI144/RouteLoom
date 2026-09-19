#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "driver/usb_serial_jtag.h"
#include "esp_attr.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#if CONFIG_ROUTELOOM_DISCOVERY
#include "routeloom/espnow_autonomy.hpp"
#endif
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/psk_security.hpp"
#include "routeloom/usb_bridge.hpp"

namespace {
constexpr char kTag[] = "RouteLoomBr";

using routeloom::ByteView;
using routeloom::Status;
using routeloom::StatusCode;
using routeloom::espnow::DevelopmentPskSecurityProvider;
using routeloom::espnow::EspNowRuntime;
using routeloom::espnow::EspNowRuntimeConfig;
using routeloom::espnow::MacAddress;
using routeloom::espnow::NvsCounterStore;

// UsbBridge emits COBS+CRC32 frames through this stream. Partial writes are
// expected: the bridge retries the remainder on the next poll.
class UsbSerialStream final : public routeloom::usb::ByteStream {
 public:
  Status write(ByteView data, std::size_t& written) noexcept override {
    written = 0;
    if (data.data == nullptr || data.size == 0) {
      return Status::success();
    }
    const int result = usb_serial_jtag_write_bytes(
        data.data, data.size, pdMS_TO_TICKS(20));
    if (result < 0) {
      return Status::error(StatusCode::RadioFailure, "usb jtag write failed");
    }
    written = static_cast<std::size_t>(result);
    return Status::success();
  }
};

int hex_value(const char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  const char lower =
      static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
  if (lower >= 'a' && lower <= 'f') return lower - 'a' + 10;
  return -1;
}

template <std::size_t Size>
bool parse_hex(const char* text,
               std::array<std::uint8_t, Size>& output) noexcept {
  if (text == nullptr || std::strlen(text) != Size * 2U) return false;
  for (std::size_t i = 0; i < Size; ++i) {
    const int high = hex_value(text[i * 2]);
    const int low = hex_value(text[i * 2 + 1]);
    if (high < 0 || low < 0) return false;
    output[i] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

bool parse_mac(const char* text, MacAddress& mac) noexcept {
  if (text == nullptr) return false;
  unsigned values[6]{};
  if (std::sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x", &values[0], &values[1],
                  &values[2], &values[3], &values[4], &values[5]) != 6) {
    return false;
  }
  for (std::size_t i = 0; i < mac.bytes.size(); ++i) {
    if (values[i] > 0xffU) return false;
    mac.bytes[i] = static_cast<std::uint8_t>(values[i]);
  }
  return true;
}

Status next_boot_session(std::uint32_t& session) noexcept {
  nvs_handle_t handle = 0;
  esp_err_t error = nvs_open("rlboot", NVS_READWRITE, &handle);
  if (error != ESP_OK) {
    return Status::error(StatusCode::StorageFailure,
                         "boot nvs_open failed");
  }
  std::uint32_t stored = 0;
  error = nvs_get_u32(handle, "session", &stored);
  if (error != ESP_OK && error != ESP_ERR_NVS_NOT_FOUND) {
    nvs_close(handle);
    return Status::error(StatusCode::StorageFailure,
                         "boot session read failed");
  }
  session = stored + 1U;
  if (session == 0) {
    nvs_close(handle);
    return Status::error(StatusCode::CounterExhausted,
                         "boot session exhausted");
  }
  error = nvs_set_u32(handle, "session", session);
  if (error == ESP_OK) error = nvs_commit(handle);
  nvs_close(handle);
  return error == ESP_OK
             ? Status::success()
             : Status::error(StatusCode::StorageFailure,
                             "boot session commit failed");
}

[[noreturn]] void fail(const char* detail) {
  ESP_LOGE(kTag, "fatal: %s", detail);
  for (;;) vTaskDelay(pdMS_TO_TICKS(1000));
}

routeloom::MonotonicMs monotonic_now_ms() noexcept {
  return static_cast<routeloom::MonotonicMs>(esp_timer_get_time() / 1000);
}

}  // namespace

extern "C" void app_main(void) {
  // Identity, nonce reservations, replay state and message sessions share NVS.
  // Never erase it automatically after a version/capacity error: that would
  // silently turn a recoverable storage problem into key/counter rollback.
  const esp_err_t nvs_error = nvs_flash_init();
  if (nvs_error != ESP_OK) {
    ESP_LOGE(kTag,
             "NVS init failed (%s); automatic erase is disabled, explicit "
             "recovery is required",
             esp_err_to_name(nvs_error));
    fail("NVS initialization failed");
  }

  static NvsCounterStore counter_store;
  auto status = counter_store.open("rlcounter");
  if (!status) fail(status.detail);

  std::array<std::uint8_t,
             DevelopmentPskSecurityProvider::kMasterKeySize>
      key{};
  if (!parse_hex(CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX, key)) {
    fail("invalid development key");
  }
  static DevelopmentPskSecurityProvider security;
  status = security.initialize(key, counter_store, "rlreplay");
  std::fill(key.begin(), key.end(), 0);
  if (!status) fail(status.detail);

  std::uint32_t message_session = 0;
  status = next_boot_session(message_session);
  if (!status) fail(status.detail);

  // The bridge protocol owns USB Serial/JTAG exclusively; the console was
  // moved to UART0 in sdkconfig.defaults so log text can never interleave
  // into the COBS stream.
  usb_serial_jtag_driver_config_t usb_config{};
  usb_config.rx_buffer_size = 1024;
  usb_config.tx_buffer_size = 1024;
  if (usb_serial_jtag_driver_install(&usb_config) != ESP_OK) {
    fail("usb serial jtag install failed");
  }

  static UsbSerialStream stream;
  static routeloom::usb::UsbBridge::Config bridge_config;
  const char* secret = CONFIG_ROUTELOOM_USB_DEV_SECRET;
  bridge_config.secret =
      ByteView{reinterpret_cast<const std::uint8_t*>(secret),
               std::strlen(secret)};
  bridge_config.node = CONFIG_ROUTELOOM_NODE_ID;
  bridge_config.network = CONFIG_ROUTELOOM_NETWORK_ID;
  // Boot ID doubles as the persisted boot session: a host can tell a reboot
  // apart from a reconnect and must never see the value regress.
  bridge_config.boot_id = message_session;
  bridge_config.capability = CONFIG_ROUTELOOM_CAPABILITY;
  // Device nonce seeds the session transcript; hardware RNG makes every
  // boot's handshake unique even if the same host nonce recurs.
  bridge_config.device_nonce =
      (static_cast<std::uint64_t>(esp_random()) << 32U) | esp_random();

  static routeloom::usb::UsbBridge bridge(bridge_config, stream);

  EspNowRuntimeConfig config{};
  config.node.network = CONFIG_ROUTELOOM_NETWORK_ID;
  config.node.node = CONFIG_ROUTELOOM_NODE_ID;
  config.node.message_session = message_session;
  // Origin generation must rise every boot so peers discard the previous
  // incarnation's route state. It is derived from the persisted monotonic
  // boot session, mapped into 1..0xFFFF (0 is the "unset" sentinel).
  config.node.route_generation = static_cast<std::uint16_t>(
      ((message_session - 1U) % 0xFFFFU) + 1U);
  config.channel = CONFIG_ROUTELOOM_CHANNEL;
  config.max_tx_power_qdbm = CONFIG_ROUTELOOM_TX_POWER_QDBM;

  // The bridge is the node's observer: mesh deliveries and diagnostics are
  // reported to the host as DataFromMesh/Delivery/Diag frames.
  static EspNowRuntime runtime(config, security, bridge);
  status = runtime.initialize();
  if (!status) fail(status.detail);
  bridge.set_mesh(&runtime.node());

  if (CONFIG_ROUTELOOM_PEER_NODE_ID != 0) {
    MacAddress mac{};
    if (!parse_mac(CONFIG_ROUTELOOM_PEER_MAC, mac)) {
      fail("invalid peer MAC");
    }
    status =
        runtime.register_neighbor(CONFIG_ROUTELOOM_PEER_NODE_ID, mac, 1);
    if (!status) fail(status.detail);
  }

#if CONFIG_ROUTELOOM_DISCOVERY
  // Autonomous discovery (issue #3): the RLD1 bootstrap lane plus the
  // portable NeighborDiscovery engine, attached to the runtime's
  // DiscoveryPort. Dev-PSK possession authentication only — EXPERIMENTAL.
  // The USB bridge path is unaffected: bridge stays the NodeObserver and the
  // single-threaded pump loop drives the engine via runtime.poll_once().
  routeloom::MacAddress self_mac{};
  status = runtime.local_mac(self_mac);
  if (!status) fail(status.detail);
  routeloom::DiscoveryConfig discovery_config{};
  discovery_config.node = config.node.node;
  discovery_config.mac = self_mac;
  discovery_config.network = config.node.network;
  // The 4-byte hint is a discovery filter only, never membership evidence.
  discovery_config.network_hint =
      static_cast<std::uint32_t>(config.node.network);
  discovery_config.capability_bits = CONFIG_ROUTELOOM_CAPABILITY;
  routeloom::espnow::EspNowAutonomyPolicy autonomy_policy{};
#if CONFIG_ROUTELOOM_DISCOVERY_MEMBER
  autonomy_policy.self_member = true;
#else
  autonomy_policy.self_member = false;
#endif
#if CONFIG_ROUTELOOM_DISCOVERY_AUTO_APPROVE
  autonomy_policy.auto_approve = true;
#else
  autonomy_policy.auto_approve = false;
#endif
#if CONFIG_ROUTELOOM_DISCOVERY_INITIATE
  autonomy_policy.initiate = true;
#else
  autonomy_policy.initiate = false;
#endif
  static routeloom::espnow::EspNowAutonomy autonomy(
      discovery_config, autonomy_policy, runtime, security, kTag);
  status = autonomy.start();
  if (!status) fail(status.detail);
  ESP_LOGW(kTag,
           "EXPERIMENTAL discovery active: dev-PSK possession proof is not "
           "a production identity");
#endif

  status = runtime.start();
  if (!status) fail(status.detail);

  if (security.security_profile() != routeloom::SecurityProfile::Production) {
    ESP_LOGW(
        kTag,
        "EXPERIMENTAL bridge started; development PSK is not a production "
        "identity profile");
  }

  // Single-threaded pump: app_main owns serial RX, the bridge's periodic
  // work (handshake/credit/partial-frame timeouts, TX pump) and the runtime
  // event drain, so no extra task can interleave bridge polls.
  static std::array<std::uint8_t, 512> rx{};
  for (;;) {
    const int received = usb_serial_jtag_read_bytes(
        rx.data(), rx.size(), pdMS_TO_TICKS(0));
    if (received > 0) {
      bridge.on_bytes(
          ByteView{rx.data(), static_cast<std::size_t>(received)},
          monotonic_now_ms());
    }
    bridge.poll(monotonic_now_ms());
    runtime.poll_once();
    vTaskDelay(pdMS_TO_TICKS(2));
  }
}
