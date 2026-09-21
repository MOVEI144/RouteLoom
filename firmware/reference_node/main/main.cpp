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
#if CONFIG_ROUTELOOM_DISCOVERY || CONFIG_ROUTELOOM_CONFIG
#include "routeloom/espnow_autonomy.hpp"
#endif
#if CONFIG_ROUTELOOM_MIGRATION
#include "routeloom/espnow_migration.hpp"
#include "routeloom/nvs_ledger_store.hpp"
#endif
#if CONFIG_ROUTELOOM_CONFIG
#include "routeloom/config.hpp"
#include "routeloom/config_cose.hpp"
#include "routeloom/config_dev.hpp"
#include "routeloom/config_wire.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/nvs_config_store.hpp"
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

routeloom::MonotonicMs monotonic_now_ms() noexcept {
  return static_cast<routeloom::MonotonicMs>(esp_timer_get_time() / 1000);
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

#endif  // CONFIG_ROUTELOOM_DEEP_SLEEP

#if CONFIG_ROUTELOOM_CONFIG

// Reference desired-state provider for the SDK namespace (04 §4.2). Applies
// the committed snapshot: diagnostics_level (field 1) drives esp_log level
// immediately; discovery_enabled (2) / relay_allowed (3) are committed
// durably and surfaced through accessors the runtime consults — the live
// enforcement hooks are the deferred integration step, never claimed here.
// apply/restore are idempotent and complete on the next poll (async token);
// read_active returns the persisted blob so the journal's readback
// verification proves durability, not a log string or a RAM echo.
class RefNodeConfigProvider final : public routeloom::ConfigProvider {
 public:
  // Persist the active snapshot so it survives reboot alongside the journal.
  // The NVS namespace is stashed: every provider instance owns ONE config
  // namespace, so persist()/read_active() must use the namespace it was
  // opened with — never a shared "active" blob that a second namespace's
  // apply could overwrite.
  Status open(const char* name_space) noexcept {
    if (name_space == nullptr ||
        std::strlen(name_space) >= sizeof(namespace_)) {
      return Status::error(StatusCode::InvalidArgument,
                           "config values namespace invalid");
    }
    std::memcpy(namespace_, name_space, std::strlen(name_space) + 1);
    nvs_handle_t handle = 0;
    if (nvs_open(namespace_, NVS_READWRITE, &handle) != ESP_OK) {
      return Status::error(StatusCode::StorageFailure, "config values nvs_open");
    }
    std::size_t actual = sizeof(active_.bytes);
    const esp_err_t error = nvs_get_blob(handle, "active", active_.bytes.data(), &actual);
    nvs_close(handle);
    if (error == ESP_OK && actual <= active_.bytes.size()) {
      active_.size = actual;
    }
    return Status::success();
  }
  Status validate(const std::uint16_t, const std::uint16_t,
                  const ByteView) noexcept override {
    return Status::success();
  }
  Status prepare(const std::uint16_t, const std::uint16_t,
                 const ByteView) noexcept override {
    return Status::success();
  }
  Status apply(const std::uint16_t, const ByteView next,
               routeloom::OperationToken& token) noexcept override {
    if (next.size > pending_.bytes.size()) {
      return Status::error(StatusCode::NoCapacity, "config snapshot oversized");
    }
    pending_.size = next.size;
    std::memcpy(pending_.bytes.data(), next.data, next.size);
    token = routeloom::OperationToken{++token_id_};
    commit_done_ = false;
    return Status::success();
  }
  Status restore(const std::uint16_t, const ByteView snapshot,
                 routeloom::OperationToken& token) noexcept override {
    if (snapshot.size > pending_.bytes.size()) {
      return Status::error(StatusCode::NoCapacity, "config snapshot oversized");
    }
    pending_.size = snapshot.size;
    std::memcpy(pending_.bytes.data(), snapshot.data, snapshot.size);
    token = routeloom::OperationToken{++token_id_};
    commit_done_ = false;
    return Status::success();
  }
  Status poll(const routeloom::OperationToken token, bool& done,
              Status& outcome) noexcept override {
    done = false;
    outcome = Status::success();
    if (token.value != token_id_) {
      return Status::error(StatusCode::NotFound, "config token unknown");
    }
    // The terminal outcome is the persist result: a commit that could not
    // land in NVS is reported as a failure (the journal then restores or
    // quarantines) — never claimed as applied.
    if (!commit_done_) {
      outcome = commit_pending();
      if (!outcome) {
        done = true;
        return Status::success();
      }
      commit_done_ = true;
      drain_deadline_ms_ = esp_log_timestamp() + kDrainBoundMs;
    }
    // Honest drain (01 §1.6): a relay-off commit stays APPLYING while
    // accepted transit work is still in flight — completing early would
    // claim quiescence that does not exist. Bounded: work that outlives
    // the bound is reported as applied-with-residue, not hung on.
    if (node_ != nullptr && !relay_allowed_ &&
        node_->transit_in_flight() > 0 &&
        esp_log_timestamp() < drain_deadline_ms_) {
      done = false;
      return Status::success();
    }
    done = true;
    return Status::success();
  }
  Status read_active(const std::uint16_t, const routeloom::MutableByteView target,
                     std::size_t& out_size) noexcept override {
    // The readback input is the persisted blob, not the RAM copy: the
    // journal's VERIFYING step must prove the snapshot is durable, not
    // merely staged in RAM.
    nvs_handle_t handle = 0;
    if (nvs_open(namespace_, NVS_READONLY, &handle) != ESP_OK) {
      return Status::error(StatusCode::StorageFailure, "config readback nvs_open");
    }
    std::size_t actual = target.size;
    const esp_err_t error = nvs_get_blob(handle, "active", target.data, &actual);
    nvs_close(handle);
    if (error != ESP_OK) {
      return Status::error(StatusCode::StorageFailure, "config readback failed");
    }
    out_size = actual;
    return Status::success();
  }

  bool discovery_enabled() const noexcept { return discovery_enabled_; }
  bool relay_allowed() const noexcept { return relay_allowed_; }
  // Live relay gate (01-forwarding §policy): config commits apply the flag
  // to the running node — disabling stops NEW transit admission only;
  // accepted work drains on its original deadlines.
  void attach_node(routeloom::MeshNode* node) noexcept {
    node_ = node;
    if (node_ != nullptr) node_->set_relay_enabled(relay_allowed_);
  }

 private:
  // A snapshot becomes "active" only once it is durable: persist the
  // pending image FIRST, then update the RAM copy and apply live fields.
  // A failed write leaves active_ == the last durable image and reports
  // the failure — the RAM copy never runs ahead of flash.
  Status commit_pending() noexcept {
    const Status persisted = persist();
    if (!persisted) return persisted;
    active_.size = pending_.size;
    std::memcpy(active_.bytes.data(), pending_.bytes.data(), pending_.size);
    apply_fields();
    return Status::success();
  }
  // Writes the PENDING image (the candidate for activation) under this
  // provider's own namespace — the caller decides activation on success.
  Status persist() noexcept {
    nvs_handle_t handle = 0;
    if (nvs_open(namespace_, NVS_READWRITE, &handle) != ESP_OK) {
      return Status::error(StatusCode::StorageFailure, "config persist nvs_open");
    }
    esp_err_t error =
        nvs_set_blob(handle, "active", pending_.bytes.data(), pending_.size);
    if (error == ESP_OK) error = nvs_commit(handle);
    nvs_close(handle);
    return error == ESP_OK
               ? Status::success()
               : Status::error(StatusCode::StorageFailure, "config persist commit");
  }
  // Decode the committed TLV and drive the effects the node can apply.
  void apply_fields() noexcept {
    routeloom::endpoint::ConfigField fields[routeloom::endpoint::kConfigFieldCountMax]{};
    std::uint16_t count = 0;
    if (!routeloom::config_tlv_decode(active_.view(), fields,
                                    routeloom::endpoint::kConfigFieldCountMax,
                                    count)
             .ok()) {
      return;
    }
    for (std::uint16_t i = 0; i < count; ++i) {
      switch (fields[i].field_id) {
        case 1:  // diagnostics_level u8 0..2 -> esp_log level
          esp_log_level_set("*", static_cast<esp_log_level_t>(fields[i].value[0] + 1));
          break;
        case 2:
          discovery_enabled_ = fields[i].value[0] != 0;
          break;
        case 3:
          relay_allowed_ = fields[i].value[0] != 0;
          if (node_ != nullptr) {
            node_->set_relay_enabled(relay_allowed_);
            if (!relay_allowed_) {
              // Honest drain reporting (01 §1.6): the commit is durable and
              // withdrawal is advertised, but accepted transit keeps
              // draining on its own deadlines — log the residue instead of
              // implying the pipes are already empty.
              const std::size_t draining = node_->transit_in_flight();
              if (draining > 0) {
                ESP_LOGW(kTag, "relay off: %u transit records draining",
                         static_cast<unsigned>(draining));
              }
            }
          }
          break;
        default:
          break;
      }
    }
  }

  routeloom::ByteBuffer<routeloom::endpoint::kConfigSnapshotMax> active_{};
  routeloom::ByteBuffer<routeloom::endpoint::kConfigSnapshotMax> pending_{};
  char namespace_[16]{};
  std::uint64_t token_id_{0};
  bool discovery_enabled_{true};
  bool relay_allowed_{true};
  routeloom::MeshNode* node_{nullptr};
  // Drain accounting for a relay-off commit: the operation reports done
  // only when in-flight transit has drained or the bound elapsed.
  bool commit_done_{false};
  std::uint32_t drain_deadline_ms_{0};
  static constexpr std::uint32_t kDrainBoundMs = 30000;
};

// Maintenance/admission boundary for a mesh-only reference node (04 §4.8):
// this profile's only management path is the mesh itself — there is no
// independent admin path (no USB host, no serial console on the data plane).
// A change that disables discovery, disables relay or changes the migration
// policy can therefore remove the node's own reachability, so the gate
// refuses it outright. A build that gains an independent path would pass a
// different flag; success is never claimed by dropping in-flight DATA.
class RefNodeMaintenanceGate final : public routeloom::ConfigMaintenanceGate {
 public:
  explicit RefNodeMaintenanceGate(const bool independent_admin_path) noexcept
      : independent_admin_path_(independent_admin_path) {}
  Status check(const routeloom::ConfigMaintenanceCheck& request) noexcept override {
    if (!independent_admin_path_ &&
        (request.discovery_disabling || request.relay_disabling ||
         request.migration_changing)) {
      return Status::error(StatusCode::AuthorizationFailed,
                          "config would remove the only management path");
    }
    return Status::success();
  }

 private:
  bool independent_admin_path_{false};
};

#endif  // CONFIG_ROUTELOOM_CONFIG

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
  if (!status) fail(status.detail);

#if CONFIG_ROUTELOOM_MIGRATION
  // Channel migration (issue #5): durable plan/commit/active state plus the
  // dev-PSK commit verifier. The plan store opens BEFORE the runtime so the
  // committed channel can reconcile the boot channel — a committed plan
  // never restores a channel by itself, it only picks the channel the radio
  // starts on, and restart() still runs the participant's resume checks.
  static routeloom::espnow::NvsPlanStore plan_store;
  status = plan_store.open("rlplan");
  if (!status) fail(status.detail);
  std::uint8_t boot_channel = 0;
  const bool have_boot_channel = plan_store.boot_channel(boot_channel).ok();
#endif

  std::uint32_t message_session = 0;
  status = next_boot_session(message_session);
  if (!status) fail(status.detail);

  static LogObserver observer;
  EspNowRuntimeConfig config{};
  config.node.network = CONFIG_ROUTELOOM_NETWORK_ID;
  config.node.node = CONFIG_ROUTELOOM_NODE_ID;
  config.node.message_session = message_session;
  // Telemetry observations carry the same persisted per-boot incarnation as
  // the config journal (cross-cutting §4.2) — never the zero "unset".
  config.node.boot_incarnation = message_session;
  // Origin generation must rise every boot so peers discard the previous
  // incarnation's route state. It is derived from the persisted monotonic
  // boot session, mapped into 1..0xFFFF (0 is the "unset" sentinel).
  config.node.route_generation = static_cast<std::uint16_t>(
      ((message_session - 1U) % 0xFFFFU) + 1U);
  config.channel = CONFIG_ROUTELOOM_CHANNEL;
#if CONFIG_ROUTELOOM_MIGRATION
  if (have_boot_channel) {
    ESP_LOGW(kTag, "migration boot channel %u overrides static %u",
             static_cast<unsigned>(boot_channel),
             static_cast<unsigned>(config.channel));
    config.channel = boot_channel;
  }
#endif
  config.max_tx_power_qdbm = CONFIG_ROUTELOOM_TX_POWER_QDBM;

#if CONFIG_ROUTELOOM_MIGRATION
  routeloom::espnow::EspNowMigrationConfig migration_config{};
  const bool self_authority =
#if CONFIG_ROUTELOOM_MIGRATION_SELF_AUTHORITY
      true;
#else
      false;
#endif
  migration_config.mode = CONFIG_ROUTELOOM_MIGRATION == 1
                              ? routeloom::MigrationMode::Observe
                              : routeloom::MigrationMode::Manual;
  migration_config.authority_role = self_authority;
  migration_config.agent.authority_role = self_authority;
  migration_config.agent.participant.node = config.node.node;
  migration_config.agent.participant.network = config.node.network;
  migration_config.agent.participant.authority =
      self_authority ? config.node.node
                     : static_cast<NodeId>(CONFIG_ROUTELOOM_MIGRATION_AUTHORITY);
  migration_config.agent.participant.home_channel = config.channel;
  migration_config.agent.self_rediscovery_capable = true;
  // Measurement inputs are deployment parameters, not firmware guesses.
  migration_config.agent.measurements.management_rtt_p99_ms =
      CONFIG_ROUTELOOM_MIGRATION_RTT_P99_MS;
  migration_config.agent.measurements.control_delivery_bound_ms =
      CONFIG_ROUTELOOM_MIGRATION_DELIVERY_BOUND_MS;
  migration_config.agent.measurements.required_transfer_ms =
      CONFIG_ROUTELOOM_MIGRATION_TRANSFER_BOUND_MS;
  migration_config.agent.measurements.measured_switch_bound_ms =
      CONFIG_ROUTELOOM_MIGRATION_SWITCH_BOUND_MS;
  migration_config.coordinator.node = config.node.node;
  migration_config.coordinator.home_channel = config.channel;
  // Commit evidence derives from the same dev-PSK master key, domain
  // separated inside the verifier — Development profile only.
  static routeloom::espnow::DevPskCommitVerifier commit_verifier;
  status = commit_verifier.initialize(key);
  if (!status) fail(status.detail);
#endif

#if CONFIG_ROUTELOOM_CONFIG
  // Derive the dev permit key BEFORE the link master key is wiped below:
  // config_dev_key = SHA256("RouteLoom/config-dev/v1" || master_key). The
  // host mirror derives the same bytes — never the raw link key — so config
  // auth is a distinct, domain-separated secret.
  constexpr char kConfigDevDomain[] = "RouteLoom/config-dev/v1";
  static routeloom::ScopeDigest config_dev_key{};
  {
    std::array<std::uint8_t, 64> config_key_material{};
    std::memcpy(config_key_material.data(), kConfigDevDomain,
                sizeof(kConfigDevDomain) - 1);
    std::memcpy(config_key_material.data() + sizeof(kConfigDevDomain) - 1,
                key.data(), key.size());
    routeloom::sha256(
        ByteView{config_key_material.data(),
                 sizeof(kConfigDevDomain) - 1 + key.size()},
        config_dev_key);
  }
#endif
  std::fill(key.begin(), key.end(), 0);

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

#if CONFIG_ROUTELOOM_MIGRATION
  // Channel migration (issue #5): participant + coordinator over the
  // authenticated control-object lane, with durable plan/commit/active
  // records in "rlplan". The authority role needs a durable authority ledger
  // (operation ids + audit anchor) before it may issue.
  static routeloom::espnow::NvsLedgerStore authority_ledger;
  if (self_authority) {
    status = authority_ledger.open("rlmauth");
    if (!status) fail(status.detail);
  }
  static routeloom::espnow::EspNowMigration migration(
      migration_config, runtime, plan_store, commit_verifier,
      self_authority ? &authority_ledger : nullptr);
  status = migration.start();
  if (!status) fail(status.detail);
  ESP_LOGW(kTag,
           "EXPERIMENTAL migration lane active (mode=%d): dev-PSK commit "
           "evidence is not a production identity",
           CONFIG_ROUTELOOM_MIGRATION);
#endif

#if CONFIG_ROUTELOOM_CONFIG
  // Remote-config target (P5): durable NVS-backed ConfigJournal + a
  // dev-profile permit verifier, exposed to the routed end-protected lane
  // through ConfigTarget. The dev key is domain-separated from the link
  // master key so permit auth never reuses the link secret directly.
  static routeloom::espnow::NvsConfigStore config_store;
  status = config_store.open("rlcfg");
  if (!status) {
    // Not fatal: the journal's own initialize() will report the storage
    // fault; the node stays up degraded rather than halting the mesh.
    ESP_LOGE(kTag, "config store open failed: %s", status.detail);
  }
  static RefNodeConfigProvider config_provider;
  status = config_provider.open("rlcfgv");
  if (!status) {
    ESP_LOGE(kTag, "config provider open failed: %s", status.detail);
  }
  static RefNodeMaintenanceGate config_gate(/*independent_admin_path=*/false);
  static routeloom::ConfigRateLimiter config_limiter;
  static routeloom::espnow::EspNowEntropySource config_entropy;
  // The domain-separated dev permit key was derived above, before the link
  // master key was wiped (SHA256("RouteLoom/config-dev/v1" || master_key)).
#if CONFIG_ROUTELOOM_CONFIG_PROFILE == 1
  // RLCP1_COSE_ESP256 (m1-completion/03-signing.md): the single provisioned
  // authority P-256 key. The verifier accepts ONLY the fixed COSE_Sign1
  // shape — a dev-HMAC permit is rejected by profile, never by fallback.
  static routeloom::CoseEsp256AuthorityVerifier config_verifier;
  {
    std::array<std::uint8_t, routeloom::kCosePublicKeySize> pubkey{};
    if (!parse_hex(CONFIG_ROUTELOOM_CONFIG_COSE_KEY_HEX, pubkey)) {
      fail("invalid COSE authority key hex");
    }
    config_verifier.provision(
        static_cast<std::uint64_t>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY),
        ByteView{pubkey.data(), pubkey.size()});
    if (!config_verifier.ready()) {
      fail("COSE authority key is not a valid P-256 point");
    }
    std::fill(pubkey.begin(), pubkey.end(), 0);
  }
  ESP_LOGW(kTag, "config profile: RLCP1_COSE_ESP256 (asymmetric permit)");
#else
  static routeloom::DevConfigAuthorityVerifier config_verifier(
      ByteView{config_dev_key.data(), config_dev_key.size()});
#endif
  routeloom::ConfigJournalConfig journal_config{};
  journal_config.network = CONFIG_ROUTELOOM_NETWORK_ID;
  journal_config.target = static_cast<NodeId>(CONFIG_ROUTELOOM_NODE_ID);
  journal_config.config_namespace = routeloom::endpoint::kConfigNamespaceSdk;
  journal_config.boot_incarnation = message_session;
  journal_config.authorized_issuer =
      static_cast<NodeId>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY);
  journal_config.authority_generation =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY_GENERATION);
  static routeloom::ConfigJournal config_journal(
      journal_config, config_store, config_verifier, config_entropy,
      config_limiter, &config_provider, /*validator=*/nullptr, &config_gate);
  status = config_journal.initialize(monotonic_now_ms());
  if (!status) {
    // Journal impairment is NOT a node-fatal condition (04 §4.7, 06 §6.3):
    // halting here would take down mesh routing/discovery for the whole
    // network, while the impaired journal can still serve honest answers.
    // The journal is attached anyway — an initialized-but-impaired journal
    // adopts its surviving record as a known value, refuses new intake
    // with RecoveryRequired/quarantined verdicts, and still answers status
    // queries; an uninitialized one reports "not initialized". Either way
    // the wire outcome is honest and the node keeps routing.
    //
    // Recovery is deliberately NOT implicit: §6.3 requires authorized
    // recovery evidence from the authority or redeployment. This profile
    // wires no recovery verb — ConfigJournal::recover() stays an explicit
    // operator/host call (exercised by tests), so the field path is
    // re-provisioning/redeploy, never an unattended self-reset.
    ESP_LOGE(kTag,
             "config journal init failed: %s — running degraded "
             "(routing continues, config intake refuses)",
             status.detail);
  }
  static routeloom::MeshConfigPort config_port(runtime.node());
  static routeloom::ConfigTarget config_target(config_port);
  status = config_target.add_journal(
      routeloom::endpoint::kConfigNamespaceSdk, config_journal);
  if (!status) fail(status.detail);
  runtime.node().set_config_sink(&config_target);
  // The committed config image drives the live relay gate from now on
  // (field 3 relay_allowed); attach after the sink so the gate reflects the
  // durable snapshot, not just the compile-time default.
  config_provider.attach_node(&runtime.node());
#if CONFIG_ROUTELOOM_CONFIG_PROFILE == 1
  ESP_LOGW(kTag,
           "config target active (RLCP1_COSE_ESP256 asymmetric permit — "
           "verification is real but not production-qualified)");
#else
  ESP_LOGW(kTag,
           "EXPERIMENTAL config target active (dev HMAC permit profile, not "
           "a production identity)");
#endif
  // §6.8 flash-write accounting: the NVS adapter counts committed journal
  // writes; logged here so bench runs can read the boot-time baseline.
  const auto cfg_writes = config_store.write_stats();
  ESP_LOGI(kTag, "config store writes=%llu bytes=%llu",
           static_cast<unsigned long long>(cfg_writes.commits),
           static_cast<unsigned long long>(cfg_writes.bytes));
#endif

#if CONFIG_ROUTELOOM_TELEMETRY_REMOTE
  // Bench surface (02-telemetry §4.2): answer routed Diagnostic(48)
  // telemetry queries. Local collection is unconditional; this is only the
  // remote-answer opt-in.
  runtime.node().set_telemetry_remote(true);
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
      // The marker claims "sleep in progress" only while sleep_enter runs:
      // a return — failure or an unexpected non-sleep success — must not
      // leave it armed for the reset path to misread as a sleep cycle.
      s_sleep_marker = 0;
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
