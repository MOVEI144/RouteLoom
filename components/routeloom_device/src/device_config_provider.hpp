#pragma once

// SDK-namespace config provider and maintenance gate of a remote-config
// target (04-remote-config), used by device_config.cpp.

#include <cstdint>
#include <cstring>

#include "esp_log.h"
#include "nvs.h"
#include "routeloom/config.hpp"
#include "routeloom/node.hpp"
#include "routeloom/rlcw1.hpp"

namespace routeloom {

// Shared desired-state provider for the SDK namespace (04 §4.2). Applies
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
class DeviceConfigProvider final : public ConfigProvider {
 public:
  // Persist the active snapshot so it survives reboot alongside the journal.
  // The NVS namespace is stashed: every provider instance owns ONE config
  // namespace, so persist()/read_active() must use the namespace it was
  // opened with — never a shared "active" blob that a second namespace's
  // apply could overwrite.
  Status open(const char* name_space, const char* log_tag) noexcept {
    tag_ = log_tag;
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
               OperationToken& token) noexcept override {
    if (next.size > pending_.bytes.size()) {
      return Status::error(StatusCode::NoCapacity, "config snapshot oversized");
    }
    pending_.size = next.size;
    std::memcpy(pending_.bytes.data(), next.data, next.size);
    token = OperationToken{++token_id_};
    commit_done_ = false;
    return Status::success();
  }
  Status restore(const std::uint16_t, const ByteView snapshot,
                 OperationToken& token) noexcept override {
    // Fail closed on bytes this schema cannot express — the staged image
    // stays verbatim (the readback proves the signed baseline bytes);
    // omission-to-default expansion happens at apply time, not here.
    ConfigSdkEffective effective{};
    const Status expressible = config_sdk_effective_values(snapshot, effective);
    if (!expressible) return expressible;
    if (snapshot.size > pending_.bytes.size()) {
      return Status::error(StatusCode::NoCapacity, "config snapshot oversized");
    }
    pending_.size = snapshot.size;
    std::memcpy(pending_.bytes.data(), snapshot.data, snapshot.size);
    token = OperationToken{++token_id_};
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
    ConfigSdkEffective want{};
    Status status = config_sdk_effective_values(baseline, want);
    if (!status) return status;
    ConfigSdkEffective have{};
    status = config_sdk_effective_values(active_.view(), have);
    if (!status) return status;
    if (want.values[1] != have.values[1] || want.values[3] != have.values[3]) {
      return Status::error(StatusCode::Unsupported,
                           "config recovery changes an unverified field");
    }
    return Status::success();
  }
  Status poll(const OperationToken token, bool& done,
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
      ESP_LOGW(tag_, "relay-off commit applied with transit residue: "
                     "frames drain under their own deadlines");
    }
    done = true;
    return Status::success();
  }
  Status read_active(const std::uint16_t, const MutableByteView target,
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
    ConfigSdkEffective effective{};
    const Status expressible = config_sdk_effective_values(
        ByteView{target.data, out_size}, effective);
    if (!expressible) return expressible;
    if (effective.values[0] != applied_diag_) {
      return Status::error(StatusCode::IntegrityError,
                           "config readback diagnostics not applied");
    }
    if (node_ == nullptr ||
        node_->relay_enabled() != relay_expected(effective.values[2] != 0)) {
      return Status::error(StatusCode::IntegrityError,
                           "config readback relay gate diverged");
    }
    return Status::success();
  }

  bool discovery_enabled() const noexcept { return discovery_enabled_; }
  bool relay_allowed() const noexcept { return relay_allowed_; }
  // Live relay gate (01-forwarding §policy): config commits apply the flag
  // to the running node — disabling stops NEW transit admission only;
  // accepted work drains on its original deadlines. The adopted role
  // bounds the gate — config may withdraw relay from a relay member, never
  // grant it to an endpoint.
  void attach_node(MeshNode* node) noexcept {
    node_ = node;
    if (node_ != nullptr) node_->set_relay_enabled(relay_expected(relay_allowed_));
  }
  // Membership adoption rebuilds the MeshNode and re-enables relay by
  // role; the committed relay_allowed=false must hold across that.
  void sync_relay() noexcept {
    if (node_ != nullptr && !relay_allowed_ && node_->relay_enabled()) {
      node_->set_relay_enabled(false);
    }
  }

 private:
  bool relay_expected(const bool allowed) const noexcept {
    if (node_ == nullptr) return allowed;
    return allowed && (node_->local_role() & (sdkv1::kMemberRoleRelay |
                                              sdkv1::kMemberRoleGateway)) != 0;
  }
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
    ConfigSdkEffective effective{};
    if (!config_sdk_effective_values(active_.view(), effective).ok()) {
      return;
    }
    // diagnostics_level u8 0..2 -> esp_log level; the applied level is
    // recorded for the readback's live verification.
    applied_diag_ = effective.values[0];
    esp_log_level_set("*", static_cast<esp_log_level_t>(effective.values[0] + 1));
    discovery_enabled_ = effective.values[1] != 0;
    relay_allowed_ = effective.values[2] != 0;
    if (node_ != nullptr) {
      node_->set_relay_enabled(relay_expected(relay_allowed_));
      if (!relay_allowed_) {
        // Honest drain reporting (01 §1.6): the commit is durable and
        // withdrawal is advertised, but accepted transit keeps
        // draining on its own deadlines — log the residue instead of
        // implying the pipes are already empty.
        const std::size_t draining = node_->transit_in_flight();
        if (draining > 0) {
          ESP_LOGW(tag_, "relay off: %u transit records draining",
                   static_cast<unsigned>(draining));
        }
      }
    }
    // Field 4 (migration_policy) commits durably but stays unenforced —
    // no effect exists to drive (deferred integration, never claimed).
  }

  ByteBuffer<endpoint::kConfigSnapshotMax> active_{};
  ByteBuffer<endpoint::kConfigSnapshotMax> pending_{};
  char namespace_[16]{};
  const char* tag_{"RouteLoomNode"};
  std::uint64_t token_id_{0};
  bool discovery_enabled_{true};
  bool relay_allowed_{true};
  // Last diagnostics level apply_fields drove (0..2); unknown until the
  // first commit, so a reboot proves nothing until the boot restore
  // re-applies. Written only on the commit path — never staged state.
  std::uint8_t applied_diag_{0xFF};
  MeshNode* node_{nullptr};
  // Drain accounting for a relay-off commit: the operation reports done
  // only when in-flight transit has drained or the bound elapsed.
  bool commit_done_{false};
  std::uint32_t drain_start_ms_{0};
  static constexpr std::uint32_t kDrainBoundMs = 30000;
};

// Maintenance/admission boundary for a mesh-only node (04 §4.8):
// this profile's only management path is the mesh itself — there is no
// independent admin path (no USB host, no serial console on the data plane).
// A change that disables discovery, disables relay or changes the migration
// policy can therefore remove the node's own reachability, so the gate
// refuses it outright. A build that gains an independent path would pass a
// different flag; success is never claimed by dropping in-flight DATA.
class DeviceMaintenanceGate final : public ConfigMaintenanceGate {
 public:
  explicit DeviceMaintenanceGate(const bool independent_admin_path) noexcept
      : independent_admin_path_(independent_admin_path) {}
  Status check(const ConfigMaintenanceCheck& request) noexcept override {
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

}  // namespace routeloom
