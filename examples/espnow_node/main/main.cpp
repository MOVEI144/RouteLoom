#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "esp_err.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/nvs_boot_session.hpp"
#include "routeloom/nvs_legacy_purge.hpp"
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/owner_pump.hpp"
#else
#include "routeloom/psk_security.hpp"
#endif

namespace {
constexpr char kTag[] = "RouteLoomNode";

using routeloom::ByteView;
using routeloom::DeliveryResult;
using routeloom::MessageId;
using routeloom::MessageKey;
using routeloom::NodeId;
using routeloom::NodeObserver;
using routeloom::Status;
using routeloom::StatusCode;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
using routeloom::espnow::EspNowSecurityOwner;
using routeloom::espnow::EspOwnerEntropy;
using routeloom::espnow::Sdkv1Stores;
#else
using routeloom::espnow::DevelopmentPskSecurityProvider;
#endif
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

[[maybe_unused]] int hex_value(const char value) noexcept {
  if (value >= '0' && value <= '9') return value - '0';
  const char lower =
      static_cast<char>(std::tolower(static_cast<unsigned char>(value)));
  if (lower >= 'a' && lower <= 'f') return lower - 'a' + 10;
  return -1;
}

template <std::size_t Size>
[[maybe_unused]] bool parse_hex(const char* text,
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

[[maybe_unused]] bool parse_mac(const char* text, MacAddress& mac) noexcept {
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

#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
routeloom::MonotonicMs monotonic_now_ms() noexcept {
  return static_cast<routeloom::MonotonicMs>(esp_timer_get_time() / 1000);
}
#endif

}  // namespace

extern "C" void app_main(void) {
  // Identity, nonce reservations, replay state and message sessions live in
  // NVS. Never erase it automatically after a version/capacity error: that
  // would silently turn a recoverable storage problem into key/counter
  // rollback.
  const esp_err_t nvs_error = nvs_flash_init();
  if (nvs_error != ESP_OK) {
    ESP_LOGE(kTag,
             "NVS init failed (%s); automatic erase is disabled, explicit "
             "recovery is required",
             esp_err_to_name(nvs_error));
    fail("NVS initialization failed");
  }

  // The boot session (default "nvs" partition) advances before any
  // per-peer security state is touched: that state lives in its own
  // partition (issue #37, sdk-v1/05 §4 D2-a), so exhausting it can never
  // block this write. Every boot — even one that fails below — consumes a
  // session, which keeps TX epochs strictly fresh.
  std::uint32_t message_session = 0;
  auto status = next_boot_session(message_session);
  if (!status) fail(status.detail);

  const esp_err_t sec_nvs_error =
      nvs_flash_init_partition(routeloom::espnow::kSecurityNvsPartition);
  if (sec_nvs_error != ESP_OK) {
    ESP_LOGE(kTag,
             "security NVS partition '%s' init failed (%s); automatic erase "
             "is disabled: flash the partition table (partitions.csv) and "
             "erase NVS explicitly",
             routeloom::espnow::kSecurityNvsPartition,
             esp_err_to_name(sec_nvs_error));
    fail("security NVS initialization failed");
  }
#if CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM
  status = routeloom::reserve_dev_group_boot_session(message_session, message_session);
  if (!status) fail(status.detail);
#endif
  if (routeloom::espnow::nvs_namespace_in_use(NVS_DEFAULT_PART_NAME,
                                              "rlcounter") ||
      routeloom::espnow::nvs_namespace_in_use(NVS_DEFAULT_PART_NAME,
                                              "rlreplay")) {
    ESP_LOGW(kTag,
             "legacy rlcounter/rlreplay state in the default NVS partition "
             "is orphaned (pre-rlsec layout); an explicit NVS erase reclaims "
             "it");
  }
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  status = routeloom::espnow::refuse_legacy_boot_after_migration();
  if (!status) fail(status.detail);
  std::uint32_t peer_capacity = 0;
  status = routeloom::espnow::nvs_partition_peer_capacity(
      routeloom::espnow::kSecurityNvsPartition,
      routeloom::espnow::kNodeMaxPersistedPeers, peer_capacity);
  if (!status) fail(status.detail);

  static NvsCounterStore counter_store;
  status = counter_store.open("rlcounter",
                              routeloom::espnow::kSecurityNvsPartition);
  if (!status) fail(status.detail);

  std::array<std::uint8_t,
             DevelopmentPskSecurityProvider::kMasterKeySize>
      key{};
  if (!parse_hex(CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX, key)) {
    fail("invalid development key");
  }
  static DevelopmentPskSecurityProvider security;
  routeloom::espnow::PeerStateConfig peer_state{};
  peer_state.replay_namespace = "rlreplay";
  peer_state.partition = routeloom::espnow::kSecurityNvsPartition;
  // TX link/end epochs below are the boot session: records of older epochs
  // are dead and swept (witness first); a session at or below the witness
  // fails closed here.
  peer_state.tx_epoch = message_session;
  peer_state.max_persisted_peers = peer_capacity;
  status = security.initialize(key, counter_store, peer_state);
  if (!status) fail(status.detail);
  routeloom::espnow::log_peer_state(kTag, security,
                                    routeloom::espnow::kSecurityNvsPartition);
  routeloom::SecurityProvider& session_security = security;
#else
  // Owner profile (G-SEC P4 §8.4): the SDK v1 stores feed the shared
  // security owner; the dev-PSK path above is compiled out. An unopenable
  // store fails boot — without stores the coordinator could never join,
  // so continuing would run a dead node.
  static Sdkv1Stores sdkv1_stores(routeloom::sdkv1::kResumeNodeSlots);
  status = sdkv1_stores.open(routeloom::espnow::kSecurityNvsPartition);
  if (!status) fail(status.detail);
  status = sdkv1_stores.initialize();
  if (!status) {
    ESP_LOGE(kTag, "sdkv1 stores init: %s", status.detail);
  }
  sdkv1_stores.log_state(kTag);
  static EspOwnerEntropy entropy;
  static EspNowSecurityOwner owner;
  EspNowSecurityOwner::Config owner_config{};
  owner_config.local_node = CONFIG_ROUTELOOM_NODE_ID;
  // Pre-radio station MAC from eFuse: no custom MAC is ever set, so this
  // is the address the runtime will read back after Wi-Fi init.
  if (esp_read_mac(owner_config.local_mac.data(), ESP_MAC_WIFI_STA) != ESP_OK) {
    fail("station MAC unreadable");
  }
  owner_config.joiner.node = owner_config.local_node;
  owner_config.joiner.mac = owner_config.local_mac;
  owner_config.log_tag = kTag;
  status = owner.begin(sdkv1_stores, entropy, owner_config);
  if (!status) fail(status.detail);
  routeloom::SecurityProvider& session_security = owner.session_provider();
#endif

  static LogObserver observer;
  EspNowRuntimeConfig config{};
  config.node.network = CONFIG_ROUTELOOM_NETWORK_ID;
  config.node.node = CONFIG_ROUTELOOM_NODE_ID;
  config.node.message_session = message_session;
  // Explicit durable boot token (G-SEC P4 §9.1): identical to the compat
  // init for the legacy provider, explicit-nonzero for session providers.
  config.node.boot_session = message_session;
  // Telemetry observations carry the same persisted per-boot incarnation —
  // never the zero "unset".
  config.node.boot_incarnation = message_session;
  // Origin generation must rise every boot so peers discard the previous
  // incarnation's route state. It is derived from the persisted monotonic
  // boot session itself (Wire v2: 32-bit, never wraps in a device lifetime;
  // the session is already >= 1, 0 stays the "unset" sentinel).
  config.node.route_generation = message_session;
  // Replay epochs must advance with every boot: the persisted floor rejects
  // anything at-or-below the newest seen epoch, so a boot that reuses the
  // previous epoch can never re-establish a lost replay window. The boot
  // session is already the persisted monotonic counter, mapped into the
  // non-zero epoch space.
  config.node.link_epoch = config.node.route_generation;
  config.node.end_epoch = config.node.route_generation;
#if CONFIG_ROUTELOOM_ROUTE_GATEWAY_SCOPED
  // Gateway-scoped routing profile (docs/design/sdk-v1/routing-scale.md,
  // issue #41). A violating lease would only surface at boot as
  // ROUTE_LIFETIME_BELOW_REFRESH_BOUND; refuse the build instead.
  static_assert(CONFIG_ROUTELOOM_ROUTE_GATEWAY_1 != 0,
                "ROUTELOOM_ROUTE_GATEWAY_1 must name the site gateway");
  static_assert(CONFIG_ROUTELOOM_ROUTE_GATEWAY_2 != CONFIG_ROUTELOOM_ROUTE_GATEWAY_1,
                "ROUTELOOM_ROUTE_GATEWAY_2 must differ from GATEWAY_1");
  static_assert(routeloom::scoped_lifetime_sufficient(
                    static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_PERIOD_MS),
                    static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_LIFETIME_MS),
                    routeloom::kScopedDefaultRefreshTicks),
                "ROUTELOOM_ROUTE_LIFETIME_MS below (2 * 6 + 2) * ROUTELOOM_ROUTE_PERIOD_MS");
  config.node.route_gateways[0] =
      static_cast<routeloom::NodeId>(CONFIG_ROUTELOOM_ROUTE_GATEWAY_1);
  config.node.route_gateways[1] =
      static_cast<routeloom::NodeId>(CONFIG_ROUTELOOM_ROUTE_GATEWAY_2);
  config.node.route_advertisement_period_ms =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_PERIOD_MS);
  config.node.route_lifetime_ms =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_ROUTE_LIFETIME_MS);
  ESP_LOGI(kTag,
           "routing profile: gateway-scoped gateways=0x%" PRIx64 ",0x%" PRIx64
           " tick=%" PRIu32 "ms lease=%" PRIu32 "ms",
           config.node.route_gateways[0], config.node.route_gateways[1],
           config.node.route_advertisement_period_ms, config.node.route_lifetime_ms);
#endif
  config.channel = CONFIG_ROUTELOOM_CHANNEL;
  config.max_tx_power_qdbm = CONFIG_ROUTELOOM_TX_POWER_QDBM;
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  std::fill(key.begin(), key.end(), 0);
#endif

  static EspNowRuntime runtime(config, session_security, observer);
  status = runtime.initialize();
  if (!status) fail(status.detail);

#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
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

  // The development PSK profile is pinned to SecurityProfile::Development;
  // this firmware can never report itself as production-secure.
  if (security.security_profile() != routeloom::SecurityProfile::Production) {
    ESP_LOGW(
        kTag,
        "EXPERIMENTAL CORE_FIXED_250 started; development PSK is not a "
        "production identity profile");
  }
#else
  // Owner profile: entropy draws only exist post-radio-up, so the owner
  // boots here — boot() arms its cookie sealer from ready entropy and
  // the node start stays deferred to ApplyMemberConfig. The
  // single-threaded pump owns the event drain and the owner poll.
  status = entropy.begin();
  if (!status) fail(status.detail);
  status = owner.attach_runtime(runtime);
  if (!status) fail(status.detail);
  status = owner.boot(message_session, /*rlboot_prepared=*/true,
                      /*usb_direct=*/false, monotonic_now_ms());
  if (!status) fail(status.detail);
  ESP_LOGI(kTag, "security owner started; node start deferred to membership");
  for (;;) {
    runtime.poll_once();
    owner.poll(monotonic_now_ms());
    runtime.wait_for_event(routeloom::kOwnerPollPeriodMs);
  }
#endif
}
