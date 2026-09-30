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
  // Stranded member search: no bound neighbour since `isolated_since`;
  // `search_channel` is the candidate the radio holds (0 = none) until
  // `dwell_until`.
  MonotonicMs isolated_since{0};
  MonotonicMs dwell_until{0};
  std::uint8_t search_channel{0};
  std::uint8_t search_next{0};

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
      MigrationAgent& agent = migration->agent();
      if (request.plan_hash != agent.issued_plan_hash()) {
        status = Status::error(StatusCode::Conflict, "not the offered plan");
      } else {
        for (std::size_t i = 0; i < request.required_count; ++i) {
          ParticipantReadiness ready{};
          if (!agent.readiness_of(request.required[i], ready) || !ready.ready ||
              ready.plan_hash != request.plan_hash) {
            status = Status::error(StatusCode::WouldBlock, "REQUIRED_SET_NOT_READY");
            break;
          }
        }
        if (status) status = agent.release_commit(now_ms);
      }
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
  if (member) search_stranded(plan, now_ms);
  plan.migration->agent().hold_reconcile(!member || plan.search_channel != 0);
  // A verified plan switch (or a stranded search) moved the radio: the
  // coordinator follows it once the operation settled.
  if (!member || runtime_->radio_operation_busy()) return;
  const MigrationParticipant& participant = plan.migration->agent().participant();
  const std::uint8_t channel = runtime_->committed_channel();
  const std::uint32_t generation = runtime_->radio_generation().value;
  const bool followed = plan.search_channel != 0 ? plan.search_channel == channel
                                                 : participant.active_epoch().value != 0 &&
                                                       participant.active_channel() == channel;
  if (!followed || (channel == plan.noted_channel && generation == plan.noted_generation)) {
    return;
  }
  if (owner_->coordinator().note_plan_cutover(channel, generation)) {
    plan.noted_channel = channel;
    plan.noted_generation = generation;
    // A searched candidate is heard at once, not after the ramped
    // rediscovery backoff of the channel it left.
    NeighborDiscovery* discovery = owner_->discovery();
    if (plan.search_channel != 0 && discovery != nullptr) discovery->rearm_repair();
  }
}

// A member that missed a plan switch (or holds a plan the site has since
// replaced) hears no bound neighbour on its channel. After
// kStrandedDetectMs it listens in turn on the bounded candidates: the
// SitePackage channel, its active plan channel and the latest plan's
// channels. It stays where a neighbour binds (the member handshake
// authenticates the site; an unauthenticated frame never binds) and asks
// the site for its newest signed plan there; a newer commit replaces the
// stored plan through the participant's verifier. The site authority
// never moves.
void Device::search_stranded(DeviceChannelPlan& plan, const MonotonicMs now_ms) noexcept {
  constexpr MonotonicMs kStrandedDetectMs = 15000;
  constexpr MonotonicMs kCandidateDwellMs = 15000;
  MigrationAgent& agent = plan.migration->agent();
  const MigrationParticipant& participant = agent.participant();
  NodeId bound[1]{};
  const bool live = runtime_->migration_peers(bound, 1) != 0;
  // A plan in flight owns the radio; a commit waiting for a clock sample
  // while nothing is heard does not.
  const bool plan_owns_radio =
      participant.in_progress() &&
      !(participant.phase() == ParticipantPhase::Committed && !participant.clock_valid());
  if (plan.authority || plan_owns_radio || runtime_->radio_operation_busy()) {
    plan.isolated_since = 0;
    return;
  }
  if (live) {
    plan.isolated_since = 0;
    if (plan.search_channel == 0) return;
    if (participant.active_channel() == plan.search_channel) {
      ESP_LOGW(tag_, "channel plan: rejoined the site on channel %u (epoch %lu)",
               static_cast<unsigned>(plan.search_channel),
               static_cast<unsigned long>(participant.active_epoch().value));
      plan.search_channel = 0;
      return;
    }
    agent.request_newest_state(now_ms);
    return;
  }
  if (plan.isolated_since == 0) {
    plan.isolated_since = now_ms;
    return;
  }
  if (now_ms - plan.isolated_since < kStrandedDetectMs || now_ms < plan.dwell_until) return;
  std::uint8_t candidates[3]{};
  std::uint8_t count = 0;
  const auto add = [&](const std::uint8_t channel) {
    if (channel == 0 || count == 3) return;
    for (std::uint8_t i = 0; i < count; ++i) {
      if (candidates[i] == channel) return;
    }
    candidates[count++] = channel;
  };
  add(stores_->site().site().channel);
  add(participant.active_channel());
  if (const MigrationPlan* pending = participant.pending_plan()) {
    add(pending->new_channel);
    add(pending->old_channel);
  }
  if (count < 2) return;  // no plan: the site channel is the only one
  const std::uint8_t channel = candidates[plan.search_next % count];
  plan.search_next = static_cast<std::uint8_t>((plan.search_next + 1) % count);
  plan.dwell_until = now_ms + kCandidateDwellMs;
  if (channel == runtime_->committed_channel()) {
    if (plan.search_channel != 0) plan.search_channel = channel;
    return;
  }
  RadioOperation op{};
  op.kind = RadioOperationKind::ChannelCutover;
  op.deadline_ms = now_ms + migration_const::kGuardFloorMs * 20U;
  op.constraints.channel = channel;
  op.constraints.outage_permitted = true;
  if (runtime_->request_radio_operation(op) == kInvalidOperationToken) return;
  plan.search_channel = channel;
  ESP_LOGW(tag_, "channel plan: no bound neighbour, listening on channel %u",
           static_cast<unsigned>(channel));
}

}  // namespace routeloom

#endif  // ROUTELOOM_DEVICE_MIGRATION
