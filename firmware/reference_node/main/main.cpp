#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/psk_security.hpp"
#include "sdkconfig.h"

namespace {
constexpr char kTag[] = "RouteLoomRef";

using routeloom::ByteView;
using routeloom::DeliveryResult;
using routeloom::MessageId;
using routeloom::MessageKey;
using routeloom::NodeId;
using routeloom::NodeObserver;
using routeloom::Status;
using routeloom::StatusCode;
using routeloom::espnow::DevelopmentPskSecurityProvider;
using routeloom::espnow::EspNowRuntime;
using routeloom::espnow::EspNowRuntimeConfig;
using routeloom::espnow::MacAddress;
using routeloom::espnow::NvsCounterStore;

class LogObserver final : public NodeObserver {
 public:
  void on_message(const MessageKey& key, const NodeId source,
                  const ByteView payload) noexcept override {
    ESP_LOGI(kTag, "message origin=%llu session=%lu sequence=%llu bytes=%u",
             static_cast<unsigned long long>(source),
             static_cast<unsigned long>(key.id.session),
             static_cast<unsigned long long>(key.id.sequence),
             static_cast<unsigned>(payload.size));
  }

  void on_delivery(const DeliveryResult& result) noexcept override {
    ESP_LOGI(kTag, "delivery session=%lu sequence=%llu state=%u reason=%s",
             static_cast<unsigned long>(result.id.session),
             static_cast<unsigned long long>(result.id.sequence),
             static_cast<unsigned>(result.state), result.reason);
  }

  void on_diagnostic(const char* reason, const NodeId peer,
                     const MessageId* message) noexcept override {
    ESP_LOGW(kTag, "diagnostic reason=%s peer=%llu message=%s", reason,
             static_cast<unsigned long long>(peer),
             message == nullptr ? "none" : "present");
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
  if (std::sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x", &values[0],
                  &values[1], &values[2], &values[3], &values[4],
                  &values[5]) != 6) {
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

  static LogObserver observer;
  EspNowRuntimeConfig config{};
  config.node.network = CONFIG_ROUTELOOM_NETWORK_ID;
  config.node.node = CONFIG_ROUTELOOM_NODE_ID;
  config.node.message_session = message_session;
  config.channel = CONFIG_ROUTELOOM_CHANNEL;
  config.max_tx_power_qdbm = CONFIG_ROUTELOOM_TX_POWER_QDBM;

  static EspNowRuntime runtime(config, security, observer);
  status = runtime.initialize();
  if (!status) fail(status.detail);

  if (CONFIG_ROUTELOOM_PEER_NODE_ID != 0) {
    MacAddress mac{};
    if (!parse_mac(CONFIG_ROUTELOOM_PEER_MAC, mac)) {
      fail("invalid peer MAC");
    }
    status =
        runtime.register_neighbor(CONFIG_ROUTELOOM_PEER_NODE_ID, mac, 1);
    if (!status) fail(status.detail);
  }

  status = runtime.start_task();
  if (!status) fail(status.detail);
  ESP_LOGW(
      kTag,
      "EXPERIMENTAL CORE_FIXED_250 started; development PSK is not a "
      "production identity profile");
}
