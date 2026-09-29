// Manual channel plan of a Member node (V2-08, issue #5 manual). Every
// member runs the migration participant over the durable "rlplan" records;
// the USB gateway is also the site's plan authority, admitting SAK-signed
// plans from the host (HostOps 0x68) into its "rlmauth" ledger. Both verify
// with the adopted site's SAK (SiteCommitVerifier), so the USB session
// authenticates the host but never the plan. The stored plan channel is
// the operating channel the coordinator adopts at boot, and each verified
// plan switch moves the coordinator with the radio.

#include "routeloom/device.hpp"

#if ROUTELOOM_DEVICE_MIGRATION

#include <optional>

#include "esp_log.h"
#include "routeloom/espnow_migration.hpp"
#include "routeloom/espnow_sdkv1.hpp"
#include "routeloom/espnow_security_owner.hpp"
#include "routeloom/nvs_ledger_store.hpp"
#include "routeloom/sdkv1_security_coordinator.hpp"
#include "routeloom/site_signed.hpp"
#include "routeloom/usb_bridge.hpp"

namespace routeloom {

struct DeviceChannelPlan final : usb::UsbBridge::ChannelPlanUsbSink {
  espnow::NvsPlanStore plan_store;
  espnow::NvsLedgerStore ledger_store;
  SiteCommitVerifier verifier;
  espnow::EspNowMigration* migration{nullptr};
  PlanMeasurements measurements{};
  MigrationMode mode{MigrationMode::Manual};
  bool authority{false};
  bool tried{false};
  std::uint8_t noted_channel{0};
  std::uint32_t noted_generation{0};

  Status start(espnow::EspNowRuntime& runtime, const sdkv1::SiteRecord& site,
               const bool gateway) noexcept {
    Status status = verifier.provision(site);
    if (!status) return status;
    const NodeId self = runtime.node().node_id();
    const bool authority_role = gateway && mode == MigrationMode::Manual;
    espnow::EspNowMigrationConfig config{};
    config.mode = mode;
    config.authority_role = authority_role;
    config.agent.authority_role = authority_role;
    // The site signs as its site id over the full site network; the first
    // site gateway carries the Authority on the wire (1-hop TimeSync source,
    // READY/RESULT destination).
    config.agent.participant.node = self;
    config.agent.participant.network = site.network;
    config.agent.participant.authority = site.site_id;
    config.agent.participant.home_channel = runtime.committed_channel();
    config.agent.authority_peer = gateway ? self : site.gateways[0];
    config.agent.self_rediscovery_capable = true;
    config.agent.measurements = measurements;
    config.coordinator.node = self;
    config.coordinator.home_channel = runtime.committed_channel();
    if (authority_role) {
      status = ledger_store.open("rlmauth");
      if (!status) return status;
    }
    // Kept apart from the plan state so it stays zero-initialized (.bss):
    // the plan state's vtables would pull all of it into .data.
    static std::optional<espnow::EspNowMigration> storage;
    storage.emplace(config, runtime, plan_store, verifier,
                    authority_role ? &ledger_store : nullptr);
    status = storage->start();
    if (!status) {
      storage.reset();
      return status;
    }
    migration = &*storage;
    authority = authority_role;
    return Status::success();
  }

  Status offer(const usb::ChannelPlanRequest& request, const MonotonicMs now_ms) noexcept {
    MigrationPlan plan{};
    Status status = plan_decode(request.blob, plan);
    if (!status) return status;
    const Digest256 plan_hash = plan_digest(request.blob);
    AuthorityOperation operation{};
    operation.network = plan.network;
    operation.authority = plan.authority;
    operation.generation = plan.authority_generation;
    operation.sequence = plan.operation_sequence;
    operation.kind = AuthorityOperationKind::ChannelMigration;
    operation.previous_state_hash = plan.previous_state_hash;
    operation.operation_hash = bind_operation_payload(
        AuthorityOperationKind::ChannelMigration, ByteView{plan_hash.data(), plan_hash.size()});
    // No recovery snapshot rides the offer: a signed snapshot is itself
    // commit evidence and would bypass the READY gate. The gateway ledger's
    // state after a plan is the plan hash.
    VerifiedAuthorityPlan verified{};
    return migration->agent().offer_plan(plan, request.blob, operation, request.commit_signature,
                                         plan_hash, ByteView{}, ByteView{},
                                         /*is_rollback=*/false, now_ms, verified);
  }

  static usb::ConfigOpsResult result_for(const Status& status) noexcept {
    switch (status.code) {
      case StatusCode::Ok:
        return usb::ConfigOpsResult::Ok;
      case StatusCode::InvalidState:
      case StatusCode::Busy:
      case StatusCode::WouldBlock:
      case StatusCode::NoCapacity:
        return usb::ConfigOpsResult::Busy;
      case StatusCode::AuthenticationFailed:
      case StatusCode::AuthorizationFailed:
        return usb::ConfigOpsResult::Denied;
      case StatusCode::InvalidArgument:
      case StatusCode::IntegrityError:
      case StatusCode::Conflict:
      case StatusCode::ClockUncertain:
      case StatusCode::ProtocolError:
        return usb::ConfigOpsResult::Invalid;
      default:
        return usb::ConfigOpsResult::Indeterminate;
    }
  }

  Status channel_plan(const ByteView inner, const MutableByteView reply, std::size_t& written,
                      const MonotonicMs now_ms) noexcept override {
    usb::ChannelPlanRequest request{};
    Status status = usb::decode_channel_plan(inner, request);
    if (!status) return status;
    usb::ChannelPlanReport report{};
    handle(request, report, now_ms);
    return usb::encode_channel_plan_report(report, reply, written);
  }

  void handle(const usb::ChannelPlanRequest& request, usb::ChannelPlanReport& report,
              const MonotonicMs now_ms) noexcept {
    Status status = Status::success();
    if (migration == nullptr || !authority) {
      // Before adoption the node has no site key to verify with.
      status = Status::error(StatusCode::InvalidState, "plan authority not ready");
    } else if (request.action == usb::ChannelPlanAction::Offer) {
      status = offer(request, now_ms);
    } else if (request.action == usb::ChannelPlanAction::Release) {
      status = request.plan_hash == migration->agent().issued_plan_hash()
                   ? migration->agent().release_commit(now_ms)
                   : Status::error(StatusCode::Conflict, "not the offered plan");
    }
    report = usb::ChannelPlanReport{};
    report.result = static_cast<std::uint16_t>(result_for(status));
    report.detail = static_cast<std::uint8_t>(status.code);
    report.gateway_now_ms = now_ms;
    if (migration == nullptr) return;
    const MigrationAgent& agent = migration->agent();
    const MigrationParticipant& participant = agent.participant();
    report.phase = static_cast<std::uint8_t>(participant.phase());
    report.active_channel = participant.active_channel();
    report.active_epoch = participant.active_epoch().value;
    const std::size_t ready = agent.ready_count();
    report.ready = static_cast<std::uint8_t>(ready > 0xFF ? 0xFF : ready);
    report.released = agent.commit_released();
    const MonotonicMs cooldown = migration->authority().cooldown_until();
    const MonotonicMs remaining = cooldown > now_ms ? cooldown - now_ms : 0;
    report.cooldown_ms = static_cast<std::uint32_t>(remaining > 0xFFFFFFFFU ? 0xFFFFFFFFU
                                                                             : remaining);
    if (const SingleAuthority* ledger = migration->ledger()) {
      report.ledger_sequence = ledger->state().applied_sequence;
      report.ledger_state = ledger->state().state_hash;
    }
    report.offered_plan = agent.issued_plan_hash();
  }
};

Status Device::begin_channel_plan(const DeviceConfig& config) noexcept {
  static DeviceChannelPlan plan;
  plan.mode = config.channel_plan == 1 ? MigrationMode::Observe : MigrationMode::Manual;
  plan.measurements.management_rtt_p99_ms = config.plan_rtt_p99_ms;
  plan.measurements.control_delivery_bound_ms = config.plan_delivery_bound_ms;
  plan.measurements.required_transfer_ms = config.plan_transfer_bound_ms;
  plan.measurements.measured_switch_bound_ms = config.plan_switch_bound_ms;
  Status status = plan.plan_store.open("rlplan");
  if (!status) return status;
  // A committed plan owns the channel across reboots: the member adopts
  // its site on the plan's channel, never back on the SitePackage one.
  std::uint8_t channel = 0;
  if (plan.plan_store.boot_channel(channel).ok()) {
    ESP_LOGW(tag_, "channel plan: operating channel %u from the stored plan",
             static_cast<unsigned>(channel));
    owner_->coordinator().set_plan_channel(channel);
  }
  channel_plan_ = &plan;
#if ROUTELOOM_PROFILE_HAS_GATEWAY
  if (bridge_ != nullptr && plan.mode == MigrationMode::Manual &&
      (config.usb_capability & usb::kCapChannelPlanV1) != 0) {
    status = bridge_->attach_channel_plan(plan);
  }
#endif
  return status;
}

void Device::poll_channel_plan(const MonotonicMs now_ms) noexcept {
  static_cast<void>(now_ms);
  DeviceChannelPlan& plan = *channel_plan_;
  if (plan.migration == nullptr) {
    // The site key, the adopted NodeId and the operating channel exist only
    // once the member node runs. A failed start leaves plans off this boot.
    if (plan.tried || !runtime_->node().started() ||
        owner_->coordinator().mode() != sdkv1::CoordinatorMode::Member ||
        !stores_->site().has_site()) {
      return;
    }
    plan.tried = true;
    const sdkv1::SiteRecord& site = stores_->site().site();
    // One plan authority per site: the first site gateway, which every
    // member takes as its TimeSync source.
    const bool gateway = role_ == profile::Role::Gateway &&
                         (site.role & sdkv1::kMemberRoleGateway) != 0 &&
                         site.gateways[0] == runtime_->node().node_id();
    const Status status = plan.start(*runtime_, site, gateway);
    if (!status) ESP_LOGE(tag_, "channel plan start failed: %s", status.detail);
    return;
  }
  // Outside Member mode the Owner owns the channel (a re-join scans); the
  // re-adoption returns the radio to the plan channel itself.
  const bool member = owner_->coordinator().mode() == sdkv1::CoordinatorMode::Member;
  plan.migration->agent().hold_reconcile(!member);
  // A verified plan switch moved the radio: the coordinator follows it once
  // the operation settled on the plan's channel.
  if (!member || runtime_->radio_operation_busy()) return;
  const MigrationParticipant& participant = plan.migration->agent().participant();
  const std::uint8_t channel = runtime_->committed_channel();
  const std::uint32_t generation = runtime_->radio_generation().value;
  if (participant.active_epoch().value == 0 || participant.active_channel() != channel ||
      (channel == plan.noted_channel && generation == plan.noted_generation)) {
    return;
  }
  if (owner_->coordinator().note_plan_cutover(channel, generation)) {
    plan.noted_channel = channel;
    plan.noted_generation = generation;
  }
}

}  // namespace routeloom

#endif  // ROUTELOOM_DEVICE_MIGRATION
