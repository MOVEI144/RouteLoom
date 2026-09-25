#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_sleep.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "nvs.h"
#include "nvs_flash.h"
#include "routeloom/nvs_boot_session.hpp"
#include "routeloom/nvs_legacy_purge.hpp"
#include "sdkconfig.h"
#if CONFIG_ROUTELOOM_DISCOVERY || CONFIG_ROUTELOOM_CONFIG
#include "routeloom/espnow_autonomy.hpp"
#endif
#if CONFIG_ROUTELOOM_DISCOVERY
#include "routeloom/espnow_scope_provider.hpp"
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
#include "routeloom/nvs_security_floor.hpp"
#endif
#if CONFIG_ROUTELOOM_TRUST_STORE
#include "routeloom/device_credential.hpp"
#include "routeloom/nvs_cred_store.hpp"
#include "routeloom/nvs_trust_store.hpp"
#include "routeloom/trust_view.hpp"
#endif
#include "routeloom/espnow_power.hpp"
#include "routeloom/espnow_runtime.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_session_rtc.hpp"
#include "routeloom/fail_policy.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/power.hpp"
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#include "routeloom/espnow_sdkv1_entropy.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/owner_pump.hpp"
#else
#include "routeloom/psk_security.hpp"
#endif
#include "routeloom/secure_clear.hpp"

namespace {
constexpr char kTag[] = "RouteLoomRef";

// NVS codec state uses CPU-only reads and writes, so C5 Owner profiles
// keep it in LP SRAM while HP SRAM remains available to radio traffic.
#if (CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC || \
     CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM) && \
    CONFIG_IDF_TARGET_ESP32C5
#define ROUTELOOM_OWNER_C5_LP RTC_DATA_ATTR
#else
#define ROUTELOOM_OWNER_C5_LP
#endif

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
#else
using routeloom::espnow::DevelopmentPskSecurityProvider;
#endif
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
    // Unknown-epoch group traffic is the backstop pull trigger for a
    // missed rotation Wake (records only; the owner polls the flag).
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    if (owner_ != nullptr && reason != nullptr &&
        std::strcmp(reason, "GROUP_KEY_RETIRED") == 0) {
      owner_->note_group_key_retired();
    }
#endif
  }
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  void bind_owner(EspNowSecurityOwner* owner) noexcept { owner_ = owner; }

 private:
  EspNowSecurityOwner* owner_{nullptr};
#endif
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

// .rtc_noinit is the only RAM the boot path never re-initializes, so it is
// what actually survives esp_restart and the deep-sleep wake used below
// (.rtc.data is re-copied from the image on every non-deep-sleep reset).
// Power-on leaves it garbage, so a magic word tells a real streak from
// random RAM. The streak drives routeloom::fail_action — backoff restarts
// first, a long deep sleep once the fault proves persistent. It clears
// only on a stability proof — the runtime task starting on the always-on
// build, an actually-entered coordinated sleep (the port's pre-sleep
// hook) on the DEEP_SLEEP build — or on power-on, never mid-boot: a fault
// late in the awake window must keep the count. The routeloom
// fail_streak_* calls are its only writers.
RTC_NOINIT_ATTR routeloom::FailStreak s_fail;

[[noreturn]] void fail(const char* detail) {
  const std::uint32_t streak = routeloom::fail_streak_consume(s_fail);
  const routeloom::FailAction action = routeloom::fail_action(streak);
  if (action.deep_sleep) {
    // Persistent fault: every further restart is one more NVS session write
    // with no recovery evidence. Stop the radio first — sleeping with the
    // Wi-Fi driver live is the contract violation enter_sleep() guards
    // against — then halt at deep-sleep current; the streak survives in
    // .rtc_noinit so each timer wake keeps the same bounded cadence. The
    // marker stays clear: this is a fault halt, not a coordinated sleep,
    // so the DEEP_SLEEP profile's classify_boot() reports the wake as
    // OtherReset rather than a resume.
    const bool wake_armed = esp_sleep_enable_timer_wakeup(
        static_cast<std::uint64_t>(action.delay_ms) * 1000ULL) == ESP_OK;
    ESP_LOGE(kTag, "fatal: %s (streak=%lu, deep sleep %lu ms%s)", detail,
             static_cast<unsigned long>(streak + 1U),
             static_cast<unsigned long>(action.delay_ms),
             wake_armed ? "" : "; wake timer arm FAILED");
    (void)esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(100));  // let the fatal line reach the UART
    esp_deep_sleep_start();
  }
  ESP_LOGE(kTag, "fatal: %s (streak=%lu, restart in %lu ms)", detail,
           static_cast<unsigned long>(streak + 1U),
           static_cast<unsigned long>(action.delay_ms));
  vTaskDelay(pdMS_TO_TICKS(action.delay_ms));
  esp_restart();
}

// Used by the CONFIG and DEEP_SLEEP opt-in paths only; in a default build it
// has no caller, so it is marked maybe_unused rather than deleted.
[[maybe_unused]] routeloom::MonotonicMs monotonic_now_ms() noexcept {
  return static_cast<routeloom::MonotonicMs>(esp_timer_get_time() / 1000);
}

#if CONFIG_ROUTELOOM_DEEP_SLEEP

// RTC slow-memory marker: written right before esp_deep_sleep_start and
// cleared on boot. Lost on a full power cut — exactly the cases that must
// not be classified as a sleep resume. The programmed timer duration rides
// alongside so the wake can prove a trusted slept-time lower bound (P4
// §9.3); it is one-shot — a reset without a new sleep must not reuse it.
RTC_DATA_ATTR std::uint32_t s_sleep_marker = 0;
RTC_DATA_ATTR std::uint32_t s_sleep_programmed_ms = 0;
constexpr std::uint32_t kSleepMarkerValue = 0x524c5057;  // "RLPW"

#if CONFIG_ROUTELOOM_DEEP_SLEEP && CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
// Owner sleep tail (P4 §9.3, V1-F07): the retained session image in RTC
// slow memory, the only RAM surviving deep sleep. Zero after any
// non-sleep reset (re-copied from the image) — decode refuses those, so
// no validity claim rides on the backing itself.
RTC_DATA_ATTR std::array<std::uint8_t, routeloom::sdkv1::kRtcSessionRecordSize>
    s_rtc_session{};
// The consumed image waits here until the parent binds; the always-on
// security Owner does not reserve this space in gateway HP SRAM.
RTC_DATA_ATTR routeloom::sdkv1::RtcSessionImage s_rtc_hold{};
#endif

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

// The boot-fault streak's only stability proof in this profile: an
// actually-entered coordinated sleep. The port fires the hook after the
// Wi-Fi driver is stopped, immediately before esp_deep_sleep_start() —
// every fallible step of the awake window (boot, drain, image commit,
// wake configuration) is already behind it, so a persistent late-boot
// fault keeps the count and escalates to the bounded halt instead of
// re-arming the fast restart every ~40 s cycle.
class FailStreakClearOnSleep final : public routeloom::espnow::PreSleepHook {
 public:
  void on_pre_sleep() noexcept override {
    routeloom::fail_streak_pre_sleep(s_fail);
  }
};

routeloom::ResetCause classify_boot(bool& marked) noexcept {
  const esp_reset_reason_t reason = esp_reset_reason();
  marked = s_sleep_marker == kSleepMarkerValue;
  s_sleep_marker = 0;
  if (routeloom::trusted_deep_sleep_reset(reason == ESP_RST_DEEPSLEEP, marked)) {
    return routeloom::ResetCause::DeepSleepWake;
  }
  if (reason == ESP_RST_POWERON || reason == ESP_RST_BROWNOUT ||
      reason == ESP_RST_UNKNOWN) {
    return routeloom::ResetCause::ColdBoot;
  }
  return routeloom::ResetCause::OtherReset;
}

// A marked timer wake proves the wake source, not an elapsed-time upper
// bound: RTC slow-clock drift and time spent rebooting are not bounded by
// the programmed duration. Park durable pendings TIME_UNCERTAIN until an
// independently bounded elapsed interval is available.
routeloom::ElapsedInterval classify_wake_elapsed(const routeloom::ResetCause cause,
                                                 const bool marked) noexcept {
  const std::uint32_t programmed = s_sleep_programmed_ms;
  s_sleep_programmed_ms = 0;
  return routeloom::classify_sleep_elapsed(
      cause == routeloom::ResetCause::DeepSleepWake,
      esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_TIMER, marked,
      programmed, /*trusted_upper_ms=*/0);
}

#endif  // CONFIG_ROUTELOOM_DEEP_SLEEP

#if CONFIG_ROUTELOOM_CONFIG

// Reference desired-state provider for the SDK namespace (04 §4.2). Applies
// the committed snapshot: diagnostics_level (field 1) drives esp_log level
// immediately; discovery_enabled (2) / relay_allowed (3) are committed
// durably and surfaced through accessors the runtime consults — the live
// enforcement hooks are the deferred integration step, never claimed here.
// apply/restore are idempotent and complete on the next poll (async token).
// restore stages the baseline bytes verbatim (the readback proves the
// signed bytes) while application always drives the EFFECTIVE values — a
// snapshot that omits a field resets that effect to the schema default,
// so a sparse restore cannot leave a stale live value behind (§5.5).
// read_active re-reads the persisted blob AND verifies the live effects
// (relay gate, applied log level); discovery/migration ride unverified,
// so validate_recovery refuses baselines that change them.
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
    // Fail closed on bytes this schema cannot express — the staged image
    // stays verbatim (the readback proves the signed baseline bytes);
    // omission-to-default expansion happens at apply time, not here.
    routeloom::ConfigSdkEffective effective{};
    const Status expressible =
        routeloom::config_sdk_effective_values(snapshot, effective);
    if (!expressible) return expressible;
    if (snapshot.size > pending_.bytes.size()) {
      return Status::error(StatusCode::NoCapacity, "config snapshot oversized");
    }
    pending_.size = snapshot.size;
    std::memcpy(pending_.bytes.data(), snapshot.data, snapshot.size);
    token = routeloom::OperationToken{++token_id_};
    commit_done_ = false;
    return Status::success();
  }
  Status validate_recovery(const std::uint16_t, const std::uint16_t,
                           const ByteView baseline) noexcept override {
    // Recovery capability (§5.5): diagnostics and relay are proven through
    // live verification, but discovery has value accessors only and
    // migration is unconnected — a baseline that CHANGES an unverified
    // field is Unsupported. Unchanged values ride along in the blob
    // without claiming a live effect that does not exist.
    if (node_ == nullptr) {
      return Status::error(StatusCode::Unsupported,
                           "config recovery needs the live node");
    }
    routeloom::ConfigSdkEffective want{};
    Status status = routeloom::config_sdk_effective_values(baseline, want);
    if (!status) return status;
    routeloom::ConfigSdkEffective have{};
    status = routeloom::config_sdk_effective_values(active_.view(), have);
    if (!status) return status;
    if (want.values[1] != have.values[1] || want.values[3] != have.values[3]) {
      return Status::error(StatusCode::Unsupported,
                           "config recovery changes an unverified field");
    }
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
      drain_start_ms_ = esp_log_timestamp();
    }
    // Honest drain (01 §1.6): a relay-off commit stays APPLYING while
    // accepted transit work is still in flight — completing early would
    // claim quiescence that does not exist. The bound is elapsed-time
    // arithmetic (wrap-safe). On expiry the commit is still a success —
    // the relay gate IS applied — but the residue is surfaced as an
    // explicit warning rather than silently folded into the verdict; the
    // stranded frames resolve under their own per-frame deadlines.
    const bool draining =
        node_ != nullptr && !relay_allowed_ && node_->transit_in_flight() > 0;
    if (draining &&
        esp_log_timestamp() - drain_start_ms_ < kDrainBoundMs) {
      done = false;
      return Status::success();
    }
    if (draining) {
      ESP_LOGW(kTag, "relay-off commit applied with transit residue: "
                     "frames drain under their own deadlines");
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
    if (error == ESP_ERR_NVS_NOT_FOUND) {
      // Never configured: the empty initial baseline, not a fault. The
      // factory gate treats this as at-baseline; anything else unreadable
      // fails closed.
      out_size = 0;
      return Status::success();
    }
    if (error != ESP_OK) {
      return Status::error(StatusCode::StorageFailure, "config readback failed");
    }
    out_size = actual;
    // Live verification (§5.5): durable bytes alone never prove the
    // effects applied. The relay gate compares against the node's live
    // state; diagnostics compares against the level this provider last
    // applied (unknown until the first commit — a reboot proves nothing
    // until the boot restore re-applies). Discovery/migration ride
    // unverified: validate_recovery refuses baselines that change them.
    routeloom::ConfigSdkEffective effective{};
    const Status expressible = routeloom::config_sdk_effective_values(
        routeloom::ByteView{target.data, out_size}, effective);
    if (!expressible) return expressible;
    if (effective.values[0] != applied_diag_) {
      return Status::error(StatusCode::IntegrityError,
                           "config readback diagnostics not applied");
    }
    if (node_ == nullptr ||
        node_->relay_enabled() != (effective.values[2] != 0)) {
      return Status::error(StatusCode::IntegrityError,
                           "config readback relay gate diverged");
    }
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
  // Application is always over the EFFECTIVE values (04 §4.2): a snapshot
  // that omits a field resets that effect to the schema default, so a
  // sparse restore cannot leave a stale live value behind (§5.5).
  void apply_fields() noexcept {
    routeloom::ConfigSdkEffective effective{};
    if (!routeloom::config_sdk_effective_values(active_.view(), effective).ok()) {
      return;
    }
    // diagnostics_level u8 0..2 -> esp_log level; the applied level is
    // recorded for the readback's live verification.
    applied_diag_ = effective.values[0];
    esp_log_level_set("*", static_cast<esp_log_level_t>(effective.values[0] + 1));
    discovery_enabled_ = effective.values[1] != 0;
    relay_allowed_ = effective.values[2] != 0;
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
    // Field 4 (migration_policy) commits durably but stays unenforced —
    // no effect exists to drive (deferred integration, never claimed).
  }

  routeloom::ByteBuffer<routeloom::endpoint::kConfigSnapshotMax> active_{};
  routeloom::ByteBuffer<routeloom::endpoint::kConfigSnapshotMax> pending_{};
  char namespace_[16]{};
  std::uint64_t token_id_{0};
  bool discovery_enabled_{true};
  bool relay_allowed_{true};
  // Last diagnostics level apply_fields drove (0..2); unknown until the
  // first commit, so a reboot proves nothing until the boot restore
  // re-applies. Written only on the commit path — never staged state.
  std::uint8_t applied_diag_{0xFF};
  routeloom::MeshNode* node_{nullptr};
  // Drain accounting for a relay-off commit: the operation reports done
  // only when in-flight transit has drained or the bound elapsed.
  bool commit_done_{false};
  std::uint32_t drain_start_ms_{0};
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
  // A matching magic is the only thing that distinguishes a streak that
  // survived esp_restart from power-on garbage in .rtc_noinit.
  routeloom::fail_streak_boot(s_fail);
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
  auto status = routeloom::next_boot_session(message_session);
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

  // SDK v1 stores (sdk-v1/05 §5): the `rlsec` namespaces rlident/rlsite/
  // rlrevo/rlres behind the dual-slot discipline. Impairment is never
  // node-fatal and never triggers an erase: a quarantined/uncertain store
  // is reported and its consumers fail closed (the maintenance console
  // refuses, the join FSM of P3-4 will treat it as unprovisioned), while
  // the node keeps routing.
  static ROUTELOOM_OWNER_C5_LP routeloom::espnow::Sdkv1Stores sdkv1_stores(
      routeloom::sdkv1::kResumeNodeSlots);
  status = sdkv1_stores.open(routeloom::espnow::kSecurityNvsPartition);
  if (!status) {
#if CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE || !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
    // A factory console without NVS provisions nothing, and the security
    // owner cannot join without stores — continuing would run a dead node.
    fail(status.detail);
#else
    ESP_LOGE(kTag, "sdkv1 stores open failed: %s", status.detail);
#endif
  } else {
    const routeloom::Status sdkv1_status = sdkv1_stores.initialize();
    if (!sdkv1_status) {
      ESP_LOGE(kTag, "sdkv1 stores init: %s", sdkv1_status.detail);
    }
    sdkv1_stores.log_state(kTag);
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
#if CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
    // Member boot binds the already advanced token to the adopted RLS1.
    status = routeloom::reconcile_boot_session(sdkv1_stores.site(), message_session);
    if (!status) fail(status.detail);
#endif
#if CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM && !CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE
    status = routeloom::reserve_dev_group_boot_session(message_session, message_session);
    if (!status) fail(status.detail);
#endif
#endif
  }
#if CONFIG_ROUTELOOM_MAINTENANCE_CONSOLE
  // Factory maintenance console (sdk-v1/07 §6): runs pre-RF and owns the
  // device from here — no radio, no mesh. Returns only when the USB
  // console itself cannot be set up.
  status = routeloom::espnow::run_maintenance_console(sdkv1_stores);
  fail(status.detail);
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
  // Owner profile (G-SEC P4 §8.4): the shared security owner runs over
  // the sdkv1 stores above; the dev-PSK path is compiled out. The owner
  // boots after radio-up (entropy + attach + boot below); the node start
  // stays deferred to ApplyMemberConfig.
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
#if CONFIG_ROUTELOOM_DEEP_SLEEP && CONFIG_ROUTELOOM_SECURITY_MODE_MEMBER_EDHOC
  status = owner.begin(sdkv1_stores, entropy, owner_config, &s_rtc_hold);
#else
  status = owner.begin(sdkv1_stores, entropy, owner_config);
#endif
  if (!status) fail(status.detail);
  routeloom::SecurityProvider& session_security = owner.session_provider();
#endif

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

#if CONFIG_ROUTELOOM_TRUST_STORE
  // Production trust stores (sdk-completion/04-provisioning-lifecycle.md
  // §4.2.2/§4.4): the RLT1 trust image ("rltrust" t0/t1) and the RLC1
  // device credential ("rlcred" d0/d1) are validated at boot before the
  // config verifier below is exposed. Impairment is never node-fatal and
  // never triggers an erase or reformat: a quarantined/uncertain store
  // leaves the TrustView verifier !ready() (fail closed — permit intake
  // refuses) and the node keeps routing degraded, the same posture as the
  // config journal's impairment rule. There is NO install verb and no
  // manufactured provisioning flow in this firmware yet — first install
  // of these namespaces is a physical/deployment act owned by the host
  // tooling workstream (routeloom-provision).
  static routeloom::espnow::NvsTrustStore trust_store_storage;
  auto trust_status = trust_store_storage.open("rltrust");
  if (!trust_status) {
    ESP_LOGE(kTag, "trust store open failed: %s", trust_status.detail);
  }
  static routeloom::espnow::NvsCredStore cred_store_storage;
  auto cred_status = cred_store_storage.open("rlcred");
  if (!cred_status) {
    ESP_LOGE(kTag, "credential store open failed: %s", cred_status.detail);
  }
  static routeloom::TrustStore trust_store(trust_store_storage);
  static routeloom::DeviceCredentialStore credential_store(
      cred_store_storage);
  trust_status = trust_store.initialize();
  if (!trust_status) {
    ESP_LOGE(kTag, "trust store init: %s", trust_status.detail);
  }
  cred_status = credential_store.initialize();
  if (!cred_status) {
    ESP_LOGE(kTag, "credential store init: %s", cred_status.detail);
  }
  if (trust_store.quarantined() || credential_store.quarantined()) {
    ESP_LOGE(kTag,
             "REPROVISION_REQUIRED: trust/credential store quarantined — "
             "recovery is an explicit operator act, never an implicit reset");
  } else if (trust_store.uncertain() || credential_store.uncertain()) {
    ESP_LOGE(kTag,
             "REPROVISION_REQUIRED: trust/credential sibling state unproven "
             "— possibly-stale state is refused until recover()");
  }
  ESP_LOGI(kTag,
           "trust store: epoch=%lu gen_floor=%lu anchors=%u keys=%u "
           "revocations=%u flags=0x%02x active=%d uncertain=%d quarantined=%d",
           static_cast<unsigned long>(trust_store.store_epoch()),
           static_cast<unsigned long>(trust_store.min_authority_generation()),
           static_cast<unsigned>(trust_store.image().anchor_count),
           static_cast<unsigned>(trust_store.image().key_count),
           static_cast<unsigned>(trust_store.image().revocation_count),
           static_cast<unsigned>(trust_store.flags()),
           trust_store.has_active() ? 1 : 0,
           trust_store.uncertain() ? 1 : 0,
           trust_store.quarantined() ? 1 : 0);
  if (credential_store.has_active()) {
    const routeloom::DeviceCredential& credential =
        credential_store.credential();
    ESP_LOGI(kTag,
             "credential: node=%llu key_location=%u status=%u grant=%uB "
             "generation_base=%lu",
             static_cast<unsigned long long>(credential.node_id),
             static_cast<unsigned>(credential.key_location),
             static_cast<unsigned>(credential.cred_status),
             static_cast<unsigned>(credential.grant.size),
             static_cast<unsigned long>(credential.generation_base_session));
    // §4.8 epoch-window check: when (session - generation_base_session)
    // reaches the 0xFFF0 threshold the next boots would wrap the u16 wire
    // epoch under peer floors that can never accept it — the design's
    // REPROVISION_REQUIRED wedge, reported as a diagnostic (the dev link
    // profile still brings the mesh up; the production credential epoch
    // has no consumer wired yet).
    std::uint16_t credential_epoch = 0;
    const routeloom::Status epoch_status =
        routeloom::credential_epoch_for_session(
            message_session, credential.generation_base_session,
            credential_epoch);
    if (!epoch_status) {
      ESP_LOGE(kTag,
               "REPROVISION_REQUIRED: credential epoch window — %s "
               "(session=%lu base=%lu)",
               epoch_status.detail,
               static_cast<unsigned long>(message_session),
               static_cast<unsigned long>(
                   credential.generation_base_session));
    }
  } else {
    ESP_LOGI(kTag,
             "credential: none provisioned (uncertain=%d quarantined=%d)",
             credential_store.uncertain() ? 1 : 0,
             credential_store.quarantined() ? 1 : 0);
  }
  // §4.8: the provisioned NetworkId carries the deployment generation in
  // the upper 32 bits. Wire v1 encodes only the low 32 (wire.cpp rejects
  // >u32), so the radio/mesh identity is the low half; the FULL u64 binds
  // inside the permit AAD/journal below. Building SecurityContexts from
  // the provisioned u64 rather than the wire field is the
  // membership/endpoint workstream and is deliberately NOT wired here.
  const routeloom::NetworkId provisioned_network =
      trust_store.has_active()
          ? (trust_store.network() & 0xFFFFFFFFULL)
          : static_cast<routeloom::NetworkId>(CONFIG_ROUTELOOM_NETWORK_ID);
  if (trust_store.has_active() &&
      provisioned_network !=
          static_cast<routeloom::NetworkId>(CONFIG_ROUTELOOM_NETWORK_ID)) {
    ESP_LOGW(kTag,
             "trust image network low32 0x%08lx overrides static 0x%08x",
             static_cast<unsigned long>(provisioned_network),
             static_cast<unsigned>(CONFIG_ROUTELOOM_NETWORK_ID));
  }
  // §4.9 wear instrumentation: committed-write counters, same WriteStats
  // shape as the config-journal adapter (logged here as the boot
  // baseline; nothing below commits to these stores yet).
  const auto trust_writes = trust_store_storage.write_stats();
  const auto cred_writes = cred_store_storage.write_stats();
  ESP_LOGI(kTag, "store writes: trust=%llu/%lluB cred=%llu/%lluB",
           static_cast<unsigned long long>(trust_writes.commits),
           static_cast<unsigned long long>(trust_writes.bytes),
           static_cast<unsigned long long>(cred_writes.commits),
           static_cast<unsigned long long>(cred_writes.bytes));
#endif

  static LogObserver observer;
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  observer.bind_owner(&owner);
#endif
  EspNowRuntimeConfig config{};
#if CONFIG_ROUTELOOM_TRUST_STORE
  // The committed trust image owns the deployment's network identity;
  // only the low 32 bits are wire-visible on Wire v1 (see above).
  config.node.network = provisioned_network;
#else
  config.node.network = CONFIG_ROUTELOOM_NETWORK_ID;
#endif
  config.node.node = CONFIG_ROUTELOOM_NODE_ID;
  config.node.message_session = message_session;
  // Explicit durable boot token (G-SEC P4 §9.1): identical to the compat
  // init for the legacy provider, explicit-nonzero for session providers.
  config.node.boot_session = message_session;
  // Telemetry observations carry the same persisted per-boot incarnation as
  // the config journal (cross-cutting §4.2) — never the zero "unset".
  config.node.boot_incarnation = message_session;
  // Origin generation must rise every boot so peers discard the previous
  // incarnation's route state. It is derived from the persisted monotonic
  // boot session itself (Wire v2: 32-bit, never wraps in a device lifetime;
  // the session is already >= 1, 0 stays the "unset" sentinel).
  config.node.route_generation = message_session;
  // Replay epochs must advance with every boot: the persisted floor rejects
  // anything at-or-below the newest seen epoch, so a boot that reuses the
  // previous epoch can never re-establish a lost replay window (replay.cpp
  // REPLAY_STATE_LOST wedge). The boot session is already the persisted
  // monotonic counter, mapped into the non-zero epoch space.
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
#if CONFIG_ROUTELOOM_ROUTE_BROADCAST
  // P5-2 broadcast opt-in (routing-scale.md section 8): default off.
  config.node.route_broadcast = true;
  ESP_LOGI(kTag, "routing profile: route broadcast opt-in enabled");
#endif
  ESP_LOGI(kTag,
           "routing profile: gateway-scoped gateways=0x%" PRIx64 ",0x%" PRIx64
           " tick=%" PRIu32 "ms lease=%" PRIu32 "ms",
           config.node.route_gateways[0], config.node.route_gateways[1],
           config.node.route_advertisement_period_ms, config.node.route_lifetime_ms);
#endif
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

#if CONFIG_ROUTELOOM_CONFIG && !CONFIG_ROUTELOOM_TRUST_STORE
  // Derive the dev permit key BEFORE the link master key is wiped below:
  // config_dev_key = SHA256("RouteLoom/config-dev/v1" || master_key). The
  // host mirror derives the same bytes — never the raw link key — so config
  // auth is a distinct, domain-separated secret. Not derived under the
  // trust-store profile: the dev path is compiled out of that build.
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
    routeloom::secure_clear(config_key_material);
  }
#endif
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  routeloom::secure_clear(key);
#endif

  static EspNowRuntime runtime(config, session_security, observer);
  status = runtime.initialize();
  if (!status) fail(status.detail);

#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  // Owner profile: boot after radio-up — entropy.begin() draws post-RF
  // randomness, then boot() arms the cookie sealer from it. The node
  // start stays deferred to ApplyMemberConfig (member) or adopt_dev
  // (dev, below).
  status = entropy.begin();
  if (!status) fail(status.detail);
  status = owner.attach_runtime(runtime);
  if (!status) fail(status.detail);
#if CONFIG_ROUTELOOM_SECURITY_MODE_DEV_RAM
  // Dev route (P4 §10.1): adoption without joining. The reserved dev
  // boot (message_session) plus the static PSK/network/node/channel
  // arm the dev-resume engine through the coordinator; pairwise
  // sessions and group send/receive serve from here on.
  routeloom::keys::Secret dev_psk{};
  if (!parse_hex(CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX, dev_psk)) {
    fail("invalid development key");
  }
  EspNowSecurityOwner::DevConfig dev_config{};
  dev_config.psk = dev_psk;
  routeloom::secure_clear(dev_psk);
  dev_config.network = static_cast<routeloom::NetworkId>(CONFIG_ROUTELOOM_NETWORK_ID);
  dev_config.node = CONFIG_ROUTELOOM_NODE_ID;
  dev_config.channel = static_cast<std::uint8_t>(CONFIG_ROUTELOOM_CHANNEL);
  dev_config.boot = message_session;
  dev_config.role = routeloom::sdkv1::kMemberRoleEndpoint | routeloom::sdkv1::kMemberRoleRelay;
  status = owner.adopt_dev(dev_config, monotonic_now_ms());
  if (!status) fail(status.detail);
#else
  status = owner.boot(message_session, /*rlboot_prepared=*/true,
                      /*usb_direct=*/false, monotonic_now_ms());
  if (!status) fail(status.detail);
#endif
#endif

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
#endif

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
#if CONFIG_ROUTELOOM_DISCOVERY_SCOPE != 0
  // Discovery Scope Key (issue #14): the dev-profile provider derives
  // per-generation keys from the configured base key. A scoped mode whose
  // key cannot install fails boot — never a silent Off downgrade.
  static routeloom::espnow::DevScopeProvider scope_provider(
      routeloom::ScopeRef{CONFIG_ROUTELOOM_DISCOVERY_SCOPE_REF});
  std::array<std::uint8_t, routeloom::kScopeKeyBytes> scope_key{};
  if (!parse_hex(CONFIG_ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX, scope_key)) {
    fail("invalid ROUTELOOM_DISCOVERY_SCOPE_KEY_HEX");
  }
  status = scope_provider.install(
      routeloom::ByteView{scope_key.data(), scope_key.size()},
      CONFIG_ROUTELOOM_DISCOVERY_SCOPE_GENERATION, 0);
  routeloom::secure_clear(scope_key);
  if (!status) fail(status.detail);
  discovery_config.scope_mode =
      static_cast<routeloom::ScopeMode>(CONFIG_ROUTELOOM_DISCOVERY_SCOPE);
  discovery_config.scope_provider = &scope_provider;
  discovery_config.scope = scope_provider.ref();
#endif
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
  // Wired vs host-only: this node executes inbound verified commits and runs
  // surveys/cutover; nothing local mints a plan — MigrationAuthority::
  // commit_plan() has no firmware/USB caller today and is exercised by host
  // tests only.
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
  // The RLF1 security floor bounds every protected counter the journal
  // and the trust store mint (04 §4.7). It is NEVER auto-created: a
  // missing floor means managed re-provisioning has not run, so the
  // journal below initializes impaired and privileged intake refuses.
  static routeloom::espnow::NvsSecurityFloorStore config_floor_store;
  status = config_floor_store.open("rlfloor",
                                   routeloom::espnow::kSecurityNvsPartition);
  if (!status) {
    ESP_LOGE(kTag, "security floor open failed: %s", status.detail);
  }
  static routeloom::SecurityFloorStore config_floor(config_floor_store);
  status = config_floor.initialize();
  if (!status) {
    ESP_LOGE(kTag,
             "security floor unavailable: %s — config intake refuses until "
             "managed re-provisioning installs one",
             status.detail);
  }
  static RefNodeMaintenanceGate config_gate(/*independent_admin_path=*/false);
  static routeloom::ConfigRateLimiter config_limiter;
  static routeloom::espnow::EspNowEntropySource config_entropy;
#if CONFIG_ROUTELOOM_TRUST_STORE
  // Production provenance (04-provisioning §4.4 step 5): the verifier
  // resolves authority key records from the committed RLT1 trust image —
  // the store is the ONLY accepted key source in this build. The Kconfig
  // static COSE key and the dev-HMAC path are compiled out; a production
  // policy never accepts a dev envelope (enforced by profile selection,
  // never by trying both). An absent/quarantined/uncertain store leaves
  // the view !ready() — fail closed, intake refused, routing continues.
  // require_authority() pins the configured authority id so ready()
  // additionally reports whether THE deployment's authority resolves an
  // active key — the generation itself floats with rotation under the
  // combined RLT1/RLF1 floor (the floor's G leads across updates).
  trust_store.attach_floor(&config_floor);
  static routeloom::TrustView config_verifier(trust_store);
  config_verifier.attach_floor(&config_floor);
  config_verifier.require_authority(
      static_cast<std::uint64_t>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY));
  ESP_LOGW(kTag,
           "config profile: trust-store RLCP1_COSE_ESP256 (verifier %s)",
           config_verifier.ready()
               ? "ready"
               : "NOT READY — store unprovisioned/impaired");
#elif CONFIG_ROUTELOOM_CONFIG_PROFILE == 1
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
    routeloom::secure_clear(pubkey);
  }
  ESP_LOGW(kTag, "config profile: RLCP1_COSE_ESP256 (asymmetric permit)");
#else
  // The domain-separated dev permit key was derived above, before the link
  // master key was wiped (SHA256("RouteLoom/config-dev/v1" || master_key)).
  static routeloom::DevConfigAuthorityVerifier config_verifier(
      ByteView{config_dev_key.data(), config_dev_key.size()});
#endif
  routeloom::ConfigJournalConfig journal_config{};
#if CONFIG_ROUTELOOM_TRUST_STORE
  // §4.8: the RCC1 network field and the permit AAD bind the FULL u64
  // NetworkId — the provisioned value (deployment-generation upper bits
  // included) when an image is committed. With no active image the
  // verifier is !ready() regardless, so the Kconfig low32 fallback only
  // fills the journal's own record fields while intake stays refused.
  journal_config.network =
      trust_store.has_active()
          ? trust_store.network()
          : static_cast<routeloom::NetworkId>(CONFIG_ROUTELOOM_NETWORK_ID);
#else
  journal_config.network = CONFIG_ROUTELOOM_NETWORK_ID;
#endif
  journal_config.target = static_cast<NodeId>(CONFIG_ROUTELOOM_NODE_ID);
  journal_config.config_namespace = routeloom::endpoint::kConfigNamespaceSdk;
  journal_config.boot_incarnation = message_session;
  journal_config.authorized_issuer =
      static_cast<NodeId>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY);
  journal_config.authority_generation =
      static_cast<std::uint32_t>(CONFIG_ROUTELOOM_CONFIG_AUTHORITY_GENERATION);
  static routeloom::ConfigJournal config_journal(
      journal_config, config_store, config_floor, config_verifier,
      config_entropy, config_limiter, &config_provider,
      /*validator=*/nullptr, &config_gate);
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
    // recovery evidence from the authority. The impaired journal still
    // answers kind-4 recovery objects through config_target's single
    // assembler (a signed RCR2 intent naming the floor's exact next
    // counters plus the baseline to re-apply), so an authorized
    // routeloomctl `config-recover` reaches it over the mesh; no
    // unsigned shortcut into the ceremony exists.
    ESP_LOGE(kTag,
             "config journal init failed: %s — running degraded "
             "(routing continues, config intake refuses)",
             status.detail);
  }
  static routeloom::MeshConfigPort config_port(runtime.node());
  static routeloom::ConfigTarget config_target(config_port, config_limiter);
  status = config_target.add_journal(
      routeloom::endpoint::kConfigNamespaceSdk, config_journal);
  if (!status) fail(status.detail);
#if CONFIG_ROUTELOOM_TRUST_STORE
  // Kind-5 trust-manifest intake and the trust-status query answer from
  // the same store the TrustView verifier reads: root-signed RTM1 images
  // update the verifier's key set in-band, governed by signatures and the
  // security floor — never by transport claims.
  config_target.attach_trust_store(trust_store, config_floor);
#endif
  runtime.node().set_config_sink(&config_target);
#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  // Authority lane (G-SEC P5): subtype-9 carriers and kind-7 objects route
  // to the Owner's mesh endpoint before the config path sees them.
  config_target.attach_authority(owner.authority_demux());
#endif
  // The committed config image drives the live relay gate from now on
  // (field 3 relay_allowed); attach after the sink so the gate reflects the
  // durable snapshot, not just the compile-time default.
  config_provider.attach_node(&runtime.node());
#if CONFIG_ROUTELOOM_TRUST_STORE
  ESP_LOGW(kTag,
           "config target active (trust-store RLCP1_COSE_ESP256 — "
           "production path EXPERIMENTAL: kind-5 install + trust-status "
           "receipt wired, not production-qualified)");
#elif CONFIG_ROUTELOOM_CONFIG_PROFILE == 1
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

#if !CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  // Owner profile: the runtime task is not started (the node starts on
  // ApplyMemberConfig), so app_main owns the event drain and the owner
  // poll single-threaded.
  ESP_LOGI(kTag, "security owner started; node start deferred to membership");
#if CONFIG_ROUTELOOM_DEEP_SLEEP
  // Owner sleep tail (P4 §9.3, V1-F07): one-shot wake evidence for the
  // restore below. The marker/programmed reads clear the RTC cells, so
  // a reset without a new sleep never reuses them.
  bool owner_boot_marked = false;
  const routeloom::ResetCause owner_boot_cause = classify_boot(owner_boot_marked);
  const std::uint32_t owner_programmed_ms = s_sleep_programmed_ms;
  s_sleep_programmed_ms = 0;
  const bool owner_deep_wake = owner_boot_cause == routeloom::ResetCause::DeepSleepWake;
  const bool owner_timer_wake = esp_sleep_get_wakeup_cause() == ESP_SLEEP_WAKEUP_TIMER;
  routeloom::sdkv1::BufferRtcSessionPort owner_rtc_port(
      routeloom::MutableByteView{s_rtc_session.data(), s_rtc_session.size()});
  static routeloom::espnow::EspNowPowerPort owner_power_port(runtime);
  static FailStreakClearOnSleep owner_streak_clear;
  owner_power_port.set_pre_sleep_hook(&owner_streak_clear);
  bool owner_restore_settled = false;
  bool owner_sleep_parked = false;
  const std::int64_t owner_prepare_at_us =
      esp_timer_get_time() +
      static_cast<std::int64_t>(CONFIG_ROUTELOOM_SLEEP_AFTER_MS) * 1000LL;
  const std::int64_t owner_stop_at_us = owner_prepare_at_us + 30000000LL;
#endif
  // Boot complete — the pump loop below is the node's main loop.
  routeloom::fail_streak_runtime_started(s_fail);
  for (;;) {
    runtime.poll_once();
    owner.poll(monotonic_now_ms());
#if CONFIG_ROUTELOOM_DEEP_SLEEP
    // Warm restore: retried while the parent re-binds (Busy) with a
    // freshly bounded elapsed upper bound each round; terminal (warm or
    // refused) settles once and a refusal resumes cold.
    if (!owner_restore_settled) {
      const routeloom::MonotonicMs awake_ms = monotonic_now_ms();
      const std::uint32_t awake32 =
          awake_ms > 0xFFFFFFFFULL ? 0xFFFFFFFFU : static_cast<std::uint32_t>(awake_ms);
      const std::uint32_t elapsed = routeloom::bound_sleep_elapsed_upper_ms(
          owner_deep_wake, owner_timer_wake, owner_boot_marked, owner_programmed_ms,
          awake32);
      const routeloom::Status restored = owner.coordinator().restore_sleep_image(
          owner_rtc_port, message_session, elapsed, owner_deep_wake, owner_boot_marked);
      if (restored.code != routeloom::StatusCode::Busy) {
        owner_restore_settled = true;
        if (restored) {
          ESP_LOGI(kTag, "sleep restore: warm (elapsed bound %lu ms)",
                   static_cast<unsigned long>(elapsed));
        } else {
          ESP_LOGW(kTag, "sleep restore refused (%s): cold resume", restored.detail);
        }
      }
    }
    // Sleep entry: park the security leg, save the retained image over
    // the live parent binding, then configure the timer wake and enter
    // deep sleep through the shared power port (radio stop + pre-sleep
    // hook). Busy re-pumps against the drain deadline; a save refusal
    // without an image sleeps cold with the marker clear. The Owner
    // admits sleep only after node deliveries, group holds and radio
    // work have drained as well as its security workspace. At the drain
    // deadline, pending application results are settled before teardown.
    if (esp_timer_get_time() >= owner_prepare_at_us) {
      if (!owner_sleep_parked) {
        if (owner.prepare_sleep(monotonic_now_ms(),
                                esp_timer_get_time() >= owner_stop_at_us)) {
          owner_sleep_parked = true;
        }
      }
      if (owner_sleep_parked) {
        routeloom::NodeId parent = routeloom::kInvalidNodeId;
        routeloom::MacAddress parent_mac{};
        routeloom::BindingId parent_binding{routeloom::kInvalidBindingId};
        routeloom::Status saved =
            routeloom::Status::error(routeloom::StatusCode::NotFound, "no parent link");
        if (runtime.node().sleep_work_pending()) {
          saved = routeloom::Status::error(routeloom::StatusCode::Busy,
                                          "node has sleep work");
        } else if (owner.coordinator().first_live_peer(routeloom::SecurityScope::Link, parent) &&
            owner.discovery() != nullptr &&
            owner.discovery()->binding_of(parent, parent_binding) &&
            owner.discovery()->mac_of(parent, parent_mac)) {
          saved = owner.coordinator().save_sleep_image(
              owner_rtc_port, parent, parent_mac, parent_binding.value,
              monotonic_now_ms());
        }
        if (saved.code == routeloom::StatusCode::Busy) {
          // New work landed after the park: unpark and keep pumping.
          owner_sleep_parked = false;
          (void)owner.wake(monotonic_now_ms());
        } else {
          if (saved) {
            s_sleep_marker = kSleepMarkerValue;
            s_sleep_programmed_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
          }
          routeloom::WakePlan plan{};
          plan.wake_after_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
          if (!owner_power_port.configure_wake(plan)) fail("owner sleep wakeup refused");
          (void)owner_power_port.enter_sleep();
          // enter_sleep does not return on silicon; a return means no
          // sleep happened — never leave the marker armed for the reset
          // path to misread as a sleep cycle.
          s_sleep_marker = 0;
          s_sleep_programmed_ms = 0;
          fail("owner sleep entry returned");
        }
      }
    }
#endif
    runtime.wait_for_event(routeloom::kOwnerPollPeriodMs);
  }
#elif CONFIG_ROUTELOOM_DEEP_SLEEP
  // Wired: PowerCoordinator driven single-threaded (no runtime task), two-
  // slot NVS sleep image, RTC-marker + wake-cause classification, timer wake
  // via esp_deep_sleep_start. The timer cause is recorded, but no trusted
  // upper bound on elapsed time exists yet, so pendings park TIME_UNCERTAIN.
  // Not wired (host/port only): GPIO wake mask and bounded
  // rediscovery — EspNowPowerPort::start_discovery reports Unsupported, so
  // an unconfirmed resume ends RESUME_UNCONFIRMED/DISCOVERY_REQUIRED
  // instead of fabricating rediscovery.
  // Sleep images are system state and stay in the default partition
  // (sdk-v1/05 §5.1); only per-peer security state lives in rlsec.
  static NvsCounterStore sleep_store;
  status = sleep_store.open("rlsleep");
  if (!status) fail(status.detail);
  static NvsSleepStorage sleep_storage(sleep_store);
  static EspNowPowerPort power_port(runtime);
  static LogPowerEvents power_events;
  static FailStreakClearOnSleep streak_clear;
  power_port.set_pre_sleep_hook(&streak_clear);
  routeloom::PowerConfig power_config{};
  static routeloom::PowerCoordinator coordinator(
      power_config, runtime.node(), power_port, sleep_storage, power_events);

  // Cold boot vs deep-sleep resume are distinct coordinator inputs. The
  // The timer cause alone cannot bound elapsed time, so durable pendings
  // park TIME_UNCERTAIN until an independent elapsed-time source exists.
  bool boot_marked = false;
  const routeloom::ResetCause boot_cause = classify_boot(boot_marked);
  status = coordinator.begin(boot_cause, classify_wake_elapsed(boot_cause, boot_marked),
                             monotonic_now_ms());
  if (!status) fail(status.detail);
  runtime.mark_started();
  // The streak decision at this event is to hold: the pump loop below
  // still runs fallible work (drain, image commit, wake configuration,
  // sleep_enter) and fail() must see the retained count. This profile's
  // only clear is FailStreakClearOnSleep, fired at the point of no return
  // inside enter_sleep().
  routeloom::fail_streak_mark_started(s_fail);

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
      s_sleep_programmed_ms = CONFIG_ROUTELOOM_SLEEP_DURATION_MS;
      status =
          coordinator.sleep_enter(coordinator.ticket(), monotonic_now_ms());
      // The marker claims "sleep in progress" only while sleep_enter runs:
      // a return — failure or an unexpected non-sleep success — must not
      // leave it armed for the reset path to misread as a sleep cycle.
      s_sleep_marker = 0;
      s_sleep_programmed_ms = 0;
      if (!status) fail(status.detail);
    }
    runtime.wait_for_event(routeloom::kOwnerPollPeriodMs);
  }
  if (coordinator.state() != routeloom::PowerState::Sleeping) {
    fail("sleep deadline exceeded");
  }
#else
  status = runtime.start_task();
  if (!status) fail(status.detail);
  // Boot complete — the runtime task is the node's main loop.
  routeloom::fail_streak_runtime_started(s_fail);
#endif
#if CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE
  // The development PSK profile is pinned to SecurityProfile::Development;
  // this firmware can never report itself as production-secure.
  if (security.security_profile() != routeloom::SecurityProfile::Production) {
    ESP_LOGW(
        kTag,
        "EXPERIMENTAL CORE_FIXED_250 started; development PSK is not a "
        "production identity profile");
  }
#endif
}
