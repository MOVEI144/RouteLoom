#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "sdkconfig.h"
#if CONFIG_ROUTELOOM_DISCOVERY
#include "routeloom/espnow_autonomy.hpp"
#endif
#include "routeloom/espnow_power.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/power.hpp"
#include "routeloom/psk_security.hpp"

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
using routeloom::espnow::EspNowPowerPort;
using routeloom::espnow::EspNowRuntime;
using routeloom::espnow::EspNowRuntimeConfig;
using routeloom::espnow::MacAddress;
using routeloom::espnow::NvsCounterStore;
using routeloom::espnow::NvsSleepStorage;

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

#if CONFIG_ROUTELOOM_DEEP_SLEEP

// RTC slow-memory marker: written right before esp_deep_sleep_start and
// cleared on boot. Lost on a full power cut — exactly the cases that must
// not be classified as a sleep resume.
RTC_DATA_ATTR std::uint32_t s_sleep_marker = 0;
constexpr std::uint32_t kSleepMarkerValue = 0x524c5057;  // "RLPW"

class LogPowerEvents final : public routeloom::PowerEvents {
 public:
  void on_transition(const routeloom::PowerState from,
                     const routeloom::PowerState to,
                     const char* reason) noexcept override {
    ESP_LOGI(kTag, "power %s -> %s (%s)", routeloom::power_state_name(from),
             routeloom::power_state_name(to), reason);
  }
  void on_pending_result(const routeloom::PendingDeliveryRecord& record,
                         const routeloom::StatusCode result) noexcept override {
    ESP_LOGI(kTag, "pending %lu/%llu -> %u",
             static_cast<unsigned long>(record.original_id.session),
             static_cast<unsigned long long>(record.original_id.sequence),
             static_cast<unsigned>(result));
  }
  void on_diagnostic(const char* reason) noexcept override {
    ESP_LOGW(kTag, "power diagnostic: %s", reason);
  }
};

routeloom::ResetCause classify_boot() noexcept {
  // esp_sleep_get_wakeup_causes() returns a *bitmap* of esp_sleep_source_t
  // values — on a non-sleep reset it reports BIT(ESP_SLEEP_WAKEUP_UNDEFINED),
  // which is nonzero. Mask the UNDEFINED bit before treating the bitmap as
  // evidence of a real sleep wakeup so brownout/watchdog resets are not
  // misclassified as deep-sleep resumes.
  const std::uint32_t wakeup =
      esp_sleep_get_wakeup_causes() & ~(1U << ESP_SLEEP_WAKEUP_UNDEFINED);
  const esp_reset_reason_t reason = esp_reset_reason();
  const bool marked = s_sleep_marker == kSleepMarkerValue;
  s_sleep_marker = 0;
  if (marked && (reason == ESP_RST_DEEPSLEEP || wakeup != 0U)) {
    return routeloom::ResetCause::DeepSleepWake;
  }
  if (reason == ESP_RST_POWERON || reason == ESP_RST_BROWNOUT ||
      reason == ESP_RST_UNKNOWN) {
    return routeloom::ResetCause::ColdBoot;
  }
  return routeloom::ResetCause::OtherReset;
}

routeloom::MonotonicMs monotonic_now_ms() noexcept {
  return static_cast<routeloom::MonotonicMs>(esp_timer_get_time() / 1000);
}

#endif  // CONFIG_ROUTELOOM_DEEP_SLEEP

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
  // Origin generation must rise every boot so peers discard the previous
  // incarnation's route state. It is derived from the persisted monotonic
  // boot session, mapped into 1..0xFFFF (0 is the "unset" sentinel).
  config.node.route_generation = static_cast<std::uint16_t>(
      ((message_session - 1U) % 0xFFFFU) + 1U);
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

#if CONFIG_ROUTELOOM_DISCOVERY
  // Autonomous discovery (issue #3): the RLD1 bootstrap lane plus the
  // portable NeighborDiscovery engine, attached to the runtime's
  // DiscoveryPort. Dev-PSK possession authentication only — EXPERIMENTAL.
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

#if CONFIG_ROUTELOOM_DEEP_SLEEP
  static NvsSleepStorage sleep_storage(counter_store);
  static EspNowPowerPort power_port(runtime);
  static LogPowerEvents power_events;
  routeloom::PowerConfig power_config{};
  static routeloom::PowerCoordinator coordinator(
      power_config, runtime.node(), power_port, sleep_storage, power_events);

  // Cold boot vs deep-sleep resume are distinct coordinator inputs. Elapsed
  // time across sleep is reported unknown until a trusted RTC interval is
  // wired, so durable pendings park as TIME_UNCERTAIN instead of resending.
  status = coordinator.begin(classify_boot(), routeloom::ElapsedInterval{0, 0, false},
                             monotonic_now_ms());
  if (!status) fail(status.detail);
  runtime.mark_started();

  routeloom::SleepRequest request{};
  request.pending_policy = routeloom::SleepWorkPolicy::Fail;
  request.wake.wake_after_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
  bool prepared = false;
  const std::int64_t prepare_at_us =
      esp_timer_get_time() +
      static_cast<std::int64_t>(CONFIG_ROUTELOOM_SLEEP_AFTER_MS) * 1000LL;
  const std::int64_t stop_at_us = prepare_at_us + 30000000LL;
  // Single-threaded pump: the runtime task is not started so app_main owns
  // both the event drain and the coordinator poll.
  while (coordinator.state() != routeloom::PowerState::Sleeping &&
         esp_timer_get_time() < stop_at_us) {
    runtime.poll_once();
    coordinator.poll(monotonic_now_ms());
    if (!prepared && coordinator.state() == routeloom::PowerState::Running &&
        esp_timer_get_time() >= prepare_at_us) {
      status = coordinator.sleep_prepare(request, monotonic_now_ms());
      if (!status) fail(status.detail);
      prepared = true;
    }
    if (coordinator.state() == routeloom::PowerState::ReadyToSleep) {
      s_sleep_marker = kSleepMarkerValue;
      status =
          coordinator.sleep_enter(coordinator.ticket(), monotonic_now_ms());
      if (!status) fail(status.detail);
    }
    vTaskDelay(pdMS_TO_TICKS(2));
  }
  if (coordinator.state() != routeloom::PowerState::Sleeping) {
    fail("sleep deadline exceeded");
  }
#else
  status = runtime.start_task();
  if (!status) fail(status.detail);
#endif
  // The development PSK profile is pinned to SecurityProfile::Development;
  // this firmware can never report itself as production-secure.
  if (security.security_profile() != routeloom::SecurityProfile::Production) {
    ESP_LOGW(
        kTag,
        "EXPERIMENTAL CORE_FIXED_250 started; development PSK is not a "
        "production identity profile");
  }
}
