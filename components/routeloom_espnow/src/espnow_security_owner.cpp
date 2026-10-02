#include "routeloom/espnow_security_owner.hpp"

#include <cstdio>

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "routeloom/psa_edhoc_aead.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom::espnow {

// The P6 lifecycle is CPU-only state. Member builds with RTC capacity keep
// it outside the main radio/USB SRAM bank (on C5 only outside the gateway
// role, whose LP RAM already holds the Owner).
#if CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32S3 || \
    (CONFIG_IDF_TARGET_ESP32C5 && !CONFIG_ROUTELOOM_ROLE_GATEWAY)
RTC_DATA_ATTR
#endif
alignas(sdkv1::MembershipLifecycle)
std::array<std::uint8_t, sizeof(sdkv1::MembershipLifecycle)>
    EspNowSecurityOwner::lifecycle_box_{};
bool EspNowSecurityOwner::lifecycle_box_in_use_{false};

namespace {

constexpr std::uint32_t kTuneDeadlineMs = 3000;
constexpr int kApplyCutoverRetries = 3;
// A GROUP_KEY_RETIRED diagnostic turns into at most one pull per window;
// the channel's own bucket (1/min) paces the wire below this.
constexpr MonotonicMs kRetiredPullWindowMs = 10000;

}  // namespace

EspNowSecurityOwner::~EspNowSecurityOwner() noexcept {
  if (authority_live_) {
    mesh_sink()->~AuthorityMeshSink();
    if (gateway_role()) {
      gateway()->~AuthorityGateway();
    } else {
      endpoint()->~AuthorityEndpoint();
    }
    mesh_port()->~MeshConfigPort();
    authority_live_ = false;
  }
  if (discovery_live_) {
    discovery()->~NeighborDiscovery();
    discovery_live_ = false;
  }
  if (lifecycle_live_) {
    lifecycle().~MembershipLifecycle();
    secure_clear(lifecycle_box_);
    lifecycle_live_ = false;
    lifecycle_box_in_use_ = false;
  }
  if (coordinator_live_) {
    coordinator().~SecurityCoordinator();
    coordinator_live_ = false;
  }
  if (begun_) {
    verifier().~StoreCredentialVerifier();
    sealer().~HmacJoinCookie();
    begun_ = false;
  }
}

sdkv1::MembershipLifecycle& EspNowSecurityOwner::lifecycle() noexcept {
  return *reinterpret_cast<sdkv1::MembershipLifecycle*>(lifecycle_box_.data());
}

// --- P6 lifecycle ports -----------------------------------------------------

Status EspNowSecurityOwner::LifecycleAuthorityPort::authority_send(
    const std::uint8_t authority_type, const ByteView body) noexcept {
  EspNowSecurityOwner& owner = owner_;
  if (authority_type < 5 || authority_type > 7 || body.data == nullptr ||
      body.size == 0 || body.size > owner.authority_tx_staged_[0].body.size()) {
    return Status::error(StatusCode::InvalidArgument, "p6 authority body");
  }
  if (!owner.coordinator_live_ ||
      owner.coordinator().authority_snapshot().state != sdkv1::AuthoritySnapshot::State::Ready) {
    return Status::error(StatusCode::WouldBlock, "p6 authority not ready");
  }
  for (AuthorityTxStage& slot : owner.authority_tx_staged_) {
    if (slot.used) continue;
    std::memcpy(slot.body.data(), body.data, body.size);
    slot.type = authority_type;
    slot.size = body.size;
    slot.used = true;
    return Status::success();
  }
  return Status::error(StatusCode::WouldBlock, "p6 authority queue full");
}

bool EspNowSecurityOwner::LifecycleAuthorityPort::authority_tx_settled() noexcept {
  EspNowSecurityOwner& owner = owner_;
  for (const AuthorityTxStage& slot : owner.authority_tx_staged_) {
    if (slot.used) return false;
  }
  if (!owner.coordinator_live_ || !owner.authority_live_) return true;
  // Below Ready there is nothing to drain: a down channel never holds
  // the cutover switch (no re-establishment waits here).
  const sdkv1::AuthoritySnapshot snap = owner.coordinator().authority_snapshot();
  if (snap.state != sdkv1::AuthoritySnapshot::State::Ready) return true;
  if (snap.busy) return false;
  if (owner.gateway_role()) return !owner.usb_tx_pending_;
  return owner.endpoint()->quiescent();
}

Status EspNowSecurityOwner::LifecyclePeerPort::peer_send(const NodeId peer, const FrameType carrier,
                                                         const ByteView body) noexcept {
  EspNowSecurityOwner& owner = owner_;
  if (owner.runtime_ == nullptr || !owner.coordinator_live_ || body.data == nullptr ||
      body.size == 0 || body.size > owner.peer_tx_staged_[0].body.size()) {
    return Status::error(StatusCode::InvalidArgument, "p6 peer send");
  }
  std::uint32_t generation = 0, role = 0;
  if (!owner.coordinator().authenticated_link(peer, owner.adopted_network_, generation, role)) {
    return Status::error(StatusCode::AuthorizationFailed, "p6 peer unauthenticated");
  }
  std::uint32_t binding = 0;
  if (!owner.runtime_->p6_link_binding(peer, binding)) {
    return Status::error(StatusCode::AuthorizationFailed, "p6 peer binding absent");
  }
  for (PeerTxStage& slot : owner.peer_tx_staged_) {
    if (slot.used) continue;
    std::memcpy(slot.body.data(), body.data, body.size);
    slot.peer = peer;
    slot.carrier = carrier;
    slot.size = body.size;
    slot.binding = binding;
    slot.used = true;
    return Status::success();
  }
  return Status::error(StatusCode::WouldBlock, "p6 peer queue full");
}

Status EspNowSecurityOwner::LifecycleRuntimePort::enforce_revocation(
    const sdkv1::RevocationSet& set, const std::uint32_t site_epoch,
    const MonotonicMs now_ms) noexcept {
  EspNowSecurityOwner& owner = owner_;
  if (owner.stores_ == nullptr || !owner.coordinator_live_) {
    return Status::error(StatusCode::InvalidState, "enforce before wiring");
  }
  // Enforcement never waits for a live notice transfer: the RRS1
  // predicate retires sessions and routes now, and the matching
  // authority down transfers cancel with them (no notice may extend a
  // revoked peer's mesh lifetime). The revoked device still learns
  // its removal over the ZT recovery path (04 §6.3).
  // The P4 bank, pending handshakes and Discovery bindings retire before
  // any durable resume sweep. The route withdrawal also closes queued
  // sends to revoked peers. The RLP2 resume sweep itself belongs to the
  // lifecycle's Sweep step (the single sweep path) and runs next.
  std::uint32_t retired_old = 0;
  std::uint32_t retired_links = 0;
  const Status sessions = owner.coordinator().revoke_member_sessions(
      set, site_epoch, now_ms, &retired_old, &retired_links);
  if (!sessions) return sessions;
  if (owner.gateway_role() && owner.authority_live_) {
    for (std::size_t i = 0; i < set.count; ++i) {
      if (set.entries[i].readmit_gk_epoch != 0 &&
          (retired_old & (std::uint32_t{1} << i)) == 0) continue;
      owner.gateway()->cancel_down_to(set.entries[i].node_id);
    }
  }
  if (owner.runtime_ != nullptr) {
    for (std::size_t i = 0; i < set.count; ++i) {
      if (set.entries[i].readmit_gk_epoch != 0 &&
          (retired_links & (std::uint32_t{1} << i)) == 0) continue;
      owner.runtime_->node().revoke_routes(set.entries[i].node_id, now_ms);
    }
  }
  return Status::success();
}

Status EspNowSecurityOwner::LifecycleRuntimePort::remove_member_runtime() noexcept {
  EspNowSecurityOwner& owner = owner_;
  // The journal already holds the signed removal intent. Stop every
  // member key scope before erasing storage; a reboot replays this step
  // before the coordinator can adopt a member again.
  if (owner.runtime_ != nullptr) {
    const PauseReason prior = owner.runtime_->node().pause_reason();
    if (prior != PauseReason::None && prior != PauseReason::Cutover) {
      (void)owner.runtime_->node().clear_pause(prior);
    }
    (void)owner.runtime_->node().set_pause(PauseReason::Cutover, pause::kAll);
    (void)owner.runtime_->node().set_relay_enabled(false);
  }
  if (owner.discovery_live_) {
    owner.discovery()->membership().revoke();
  }
  if (owner.coordinator_live_ && !owner.removal_pending_) {
    sdkv1::CoordinatorEvent stop{};
    stop.kind = sdkv1::CoordinatorEventKind::StopForLifecycle;
    stop.now = owner.runtime_ != nullptr ? owner.runtime_->now_ms() : 0;
    const Status halted = owner.coordinator().step(stop);
    if (!halted) return halted;
  }
  owner.removal_pending_ = true;
  for (PeerTxStage& slot : owner.peer_tx_staged_) {
    secure_clear(slot.body);
    slot = PeerTxStage{};
  }
  for (AuthorityTxStage& slot : owner.authority_tx_staged_) {
    secure_clear(slot.body);
    slot = AuthorityTxStage{};
  }
  // The RLP2 resume clear belongs to the lifecycle's Resume step (the
  // single sweep path) and runs next.
  return Status::success();
}

Status EspNowSecurityOwner::LifecycleRuntimePort::erase_site_trust() noexcept {
  EspNowSecurityOwner& owner = owner_;
  if (!owner.coordinator_live_ || owner.stores_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "trust erasure before wiring");
  }
  const Status policy = owner.stores_->proxy_policy().erase();
  if (!policy) return policy;
  // The journaled removal (Holdoff, then the UnassignedReady watermark)
  // is the one record of a removal. A recovery join that found the
  // removal wrote RLV1 Blocked first so traffic stayed stopped until the
  // journal held the intent; left standing it would refuse the readmit
  // that the notice path allows after the same holdoff.
  if (owner.stores_->local_revocation().has_record()) {
    const Status cleared = owner.stores_->local_revocation().clear();
    if (!cleared) return cleared;
  }
  // RLS1 is erased by the lifecycle's Site step next, RLI1 stays
  // (device-level per 04 §6.4), and this step wipes the site-bound
  // intake policy and the RAM view (GK scope + discovery membership).
  return owner.coordinator().wipe_site_trust();
}

Status EspNowSecurityOwner::LifecycleRuntimePort::retire_network() noexcept {
  // Cutover retirement: member traffic halts like a removal, but the
  // stores (old + staged site) stay for the switch to commit.
  return remove_member_runtime();
}

bool EspNowSecurityOwner::LifecycleRuntimePort::route_state_snapshot(
    const sdkv1::GrantRouteState& query, sdkv1::GrantRouteState& report,
    const MonotonicMs now_ms) noexcept {
  EspNowSecurityOwner& owner = owner_;
  report = sdkv1::GrantRouteState{};
  report.head = query.head;
  report.mode = 1;
  report.status = 1;
  report.query_id = query.query_id;
  report.boot = owner.boot_witness_;
  // Unavailable unless every input below checks out; the Host treats
  // it as an unroutable target, never as evidence.
  if (owner.runtime_ == nullptr || !owner.coordinator_live_ || owner.stores_ == nullptr ||
      !owner.stores_->site().has_site() || owner.adopted_network_ == 0) {
    return true;
  }
  const sdkv1::SiteRecord& site = owner.stores_->site().site();
  const NodeId self = owner.self_node();
  for (std::uint8_t i = 0; i < site.gateway_count; ++i) {
    const NodeId gateway = site.gateways[i];
    if (gateway == kInvalidNodeId) continue;
    if (gateway == self) {
      // This node is the root: no parent, an unexpiring self route.
      report.status = 0;
      report.root = self;
      report.parent = 0;
      report.valid_for_ms = 0xFFFFFFFFU;
      return true;
    }
  }
  for (std::uint8_t i = 0; i < site.gateway_count; ++i) {
    const NodeId gateway = site.gateways[i];
    if (gateway == kInvalidNodeId || gateway == self) continue;
    const RouteSelection selection = owner.runtime_->node().routes().best(gateway);
    if (!selection.valid || selection.next_hop == kInvalidNodeId) continue;
    std::uint32_t generation = 0, role = 0;
    if (!owner.coordinator().authenticated_link(selection.next_hop, owner.adopted_network_,
                                                generation, role)) {
      continue;
    }
    const MonotonicMs expires =
        owner.runtime_->node().routes().selection_expires_at(gateway);
    const std::uint64_t remaining = expires > now_ms ? expires - now_ms : 0;
    report.status = 0;
    report.root = gateway;
    report.parent = selection.next_hop;
    // Change detector over the committed selection: any parent,
    // sequence or metric move flips it (collisions only delay a
    // re-query, never forge a route).
    const std::uint64_t mixed = selection.next_hop ^ (selection.next_hop >> 32U);
    report.route_stamp = static_cast<std::uint32_t>(mixed) ^
                         selection.sequence * 0x9E3779B1U ^ selection.metric;
    report.valid_for_ms =
        remaining > 0xFFFFFFFFU ? 0xFFFFFFFFU : static_cast<std::uint32_t>(remaining);
    return true;
  }
  return true;
}

Status EspNowSecurityOwner::LifecycleRuntimePort::install_site_trust(
    const sdkv1::SiteRecord& next) noexcept {
  (void)next;
  EspNowSecurityOwner& owner = owner_;
  if (owner.stores_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "trust install before wiring");
  }
  // The new site trust IS the staged RLS1 the lifecycle commits itself;
  // the RAM view (GK scope, discovery) adopts it at the post-reboot
  // re-adoption, not here. This step verifies the staged record the
  // lifecycle handed over matches the committed store.
  if (!owner.stores_->site().has_site()) {
    return Status::error(StatusCode::InvalidState, "no staged site to install");
  }
  return Status::success();
}

void EspNowSecurityOwner::LifecycleObjectSink::on_rrs_object(
    const NodeId peer, const ByteView object, const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  EspNowSecurityOwner& owner = owner_;
  // Latest-wins staging for the poll feed: gossip duplicates, so keeping
  // the newest completion is always at least as good. Never dispatches
  // here (the lifecycle holds its guard).
  if (object.data == nullptr || object.size == 0 ||
      object.size > owner.completed_object_.size()) {
    return;
  }
  std::memcpy(owner.completed_object_.data(), object.data, object.size);
  owner.completed_object_size_ = object.size;
  owner.completed_object_peer_ = peer;
  owner.completed_object_valid_ = true;
}

void EspNowSecurityOwner::LifecycleObserver::on_lifecycle_event(
    const sdkv1::LifecycleEvent& event, const MonotonicMs now_ms) noexcept {
  EspNowSecurityOwner& owner = owner_;
  owner.lifecycle_journal_.on_lifecycle_event(event, now_ms);
  owner.emit_lifecycle_diagnostic(event);
  const char* tag = owner.config_.log_tag;
  switch (event.kind) {
    case sdkv1::LifecycleEventKind::RrsApplied:
      ESP_LOGI(tag, "p6: RRS1 applied rs_epoch=%lu", static_cast<unsigned long>(event.epoch));
      break;
    case sdkv1::LifecycleEventKind::RrsRejected:
      ESP_LOGW(tag, "p6: RRS1 rejected rs_epoch=%lu detail=%lu",
               static_cast<unsigned long>(event.epoch), static_cast<unsigned long>(event.detail));
      break;
    case sdkv1::LifecycleEventKind::SelfRevoked:
      ESP_LOGW(tag, "p6: self rejected by RRS1 rs_epoch=%lu — recovery join next",
               static_cast<unsigned long>(event.epoch));
      break;
    case sdkv1::LifecycleEventKind::RecoveryStarted:
      ESP_LOGI(tag, "p6: recovery started reason=%lu", static_cast<unsigned long>(event.detail));
      break;
    case sdkv1::LifecycleEventKind::RecoveryFinished:
      ESP_LOGI(tag, "p6: recovery finished rs_epoch=%lu", static_cast<unsigned long>(event.epoch));
      break;
    case sdkv1::LifecycleEventKind::GossipStalled:
      ESP_LOGW(tag, "p6: gossip stalled peer=%llu rs_epoch=%lu",
               static_cast<unsigned long long>(event.peer), static_cast<unsigned long>(event.epoch));
      break;
    case sdkv1::LifecycleEventKind::StorageBlocked:
      ESP_LOGE(tag, "p6: STORAGE BLOCKED reason=%lu", static_cast<unsigned long>(event.detail));
      break;
  }
}

sdkv1::HmacJoinCookie& EspNowSecurityOwner::sealer() noexcept {
  return *reinterpret_cast<sdkv1::HmacJoinCookie*>(sealer_box_.data());
}

sdkv1::StoreCredentialVerifier& EspNowSecurityOwner::verifier() noexcept {
  return *reinterpret_cast<sdkv1::StoreCredentialVerifier*>(verifier_box_.data());
}

sdkv1::SecurityCoordinator& EspNowSecurityOwner::coordinator() noexcept {
  return *reinterpret_cast<sdkv1::SecurityCoordinator*>(coordinator_box_.data());
}

SecurityProvider& EspNowSecurityOwner::session_provider() noexcept {
  return coordinator().session_provider();
}

bool EspNowSecurityOwner::dev_adopted() const noexcept {
  if (!coordinator_live_) return false;
  const auto& coordinator =
      *reinterpret_cast<const sdkv1::SecurityCoordinator*>(coordinator_box_.data());
  return coordinator.mode() == sdkv1::CoordinatorMode::Dev;
}

NeighborDiscovery* EspNowSecurityOwner::discovery() noexcept {
  if (!discovery_live_) return nullptr;
  return reinterpret_cast<NeighborDiscovery*>(discovery_box_.data());
}

MeshConfigPort* EspNowSecurityOwner::mesh_port() noexcept {
  if (!authority_live_) return nullptr;
  return reinterpret_cast<MeshConfigPort*>(mesh_port_box_.data());
}

sdkv1::AuthorityEndpoint* EspNowSecurityOwner::endpoint() noexcept {
  if (!authority_live_ || gateway_role()) return nullptr;
  return reinterpret_cast<sdkv1::AuthorityEndpoint*>(transport_box_.endpoint.data());
}

sdkv1::AuthorityGateway* EspNowSecurityOwner::gateway() noexcept {
  if (!authority_live_ || !gateway_role()) return nullptr;
  return reinterpret_cast<sdkv1::AuthorityGateway*>(transport_box_.gateway.data());
}

sdkv1::AuthorityMeshSink* EspNowSecurityOwner::mesh_sink() noexcept {
  if (!authority_live_) return nullptr;
  return reinterpret_cast<sdkv1::AuthorityMeshSink*>(mesh_sink_box_.data());
}

NodeId EspNowSecurityOwner::self_node() const noexcept {
  return adopted_node_ != kInvalidNodeId ? adopted_node_ : config_.local_node;
}

sdkv1::AuthorityMeshDemux* EspNowSecurityOwner::authority_demux() noexcept {
  if (!authority_live_) return nullptr;
  return gateway_role() ? static_cast<sdkv1::AuthorityMeshDemux*>(gateway())
                        : static_cast<sdkv1::AuthorityMeshDemux*>(endpoint());
}

ConfigEndpointSink* EspNowSecurityOwner::authority_mesh_sink() noexcept {
  return mesh_sink();
}

const sdkv1::LifecycleJournal& EspNowSecurityOwner::lifecycle_journal() const noexcept {
  return lifecycle_journal_;
}

void EspNowSecurityOwner::emit_lifecycle_diagnostic(
    const sdkv1::LifecycleEvent& event) noexcept {
  if (bridge() == nullptr) return;
  // Stable vocabulary, numeric fields only — the PC greps these from its
  // event ring. Self-scoped events carry kInvalidNodeId like the mesh's
  // own self diagnostics; peer-scoped ones name the peer.
  char text[64]{};
  const char* format = nullptr;
  switch (event.kind) {
    case sdkv1::LifecycleEventKind::RrsApplied:
      format = "RRS_APPLIED:epoch=%lu";
      break;
    case sdkv1::LifecycleEventKind::RrsRejected:
      format = "RRS_REJECTED:epoch=%lu:detail=%lu";
      break;
    case sdkv1::LifecycleEventKind::SelfRevoked:
      format = "SELF_REVOKED:epoch=%lu";
      break;
    case sdkv1::LifecycleEventKind::RecoveryStarted:
      format = "RECOVERY_STARTED:reason=%lu";
      break;
    case sdkv1::LifecycleEventKind::RecoveryFinished:
      format = "RECOVERY_FINISHED:epoch=%lu";
      break;
    case sdkv1::LifecycleEventKind::GossipStalled:
      format = "GOSSIP_STALLED:epoch=%lu";
      break;
    case sdkv1::LifecycleEventKind::StorageBlocked:
      format = "STORAGE_BLOCKED:reason=%lu";
      break;
  }
  if (format == nullptr) return;
  if (event.kind == sdkv1::LifecycleEventKind::RrsRejected) {
    std::snprintf(text, sizeof(text), format,
                  static_cast<unsigned long>(event.epoch),
                  static_cast<unsigned long>(event.detail));
  } else {
    const std::uint32_t value =
        (event.kind == sdkv1::LifecycleEventKind::RecoveryStarted ||
         event.kind == sdkv1::LifecycleEventKind::StorageBlocked)
            ? event.detail
            : event.epoch;
    std::snprintf(text, sizeof(text), format,
                  static_cast<unsigned long>(value));
  }
  const bool peer_scoped =
      event.kind == sdkv1::LifecycleEventKind::GossipStalled ||
      event.kind == sdkv1::LifecycleEventKind::SelfRevoked;
  bridge()->on_diagnostic(text, peer_scoped ? event.peer : kInvalidNodeId, nullptr);
}

void EspNowSecurityOwner::emit_recovery_diagnostic(const std::uint8_t reason) noexcept {
  if (bridge() == nullptr) return;
  char text[64]{};
  std::snprintf(text, sizeof(text), "RECOVERY_REQUIRED:reason=%u",
                static_cast<unsigned>(reason));
  bridge()->on_diagnostic(text, kInvalidNodeId, nullptr);
}

Status EspNowSecurityOwner::begin(Sdkv1Stores& stores, EspOwnerEntropy& entropy,
                                  const Config& config,
                                  sdkv1::RtcSessionImage* sleep_image) noexcept {
  if (begun_) return Status::error(StatusCode::AlreadyExists, "owner already begun");
  if (lifecycle_box_in_use_)
    return Status::error(StatusCode::Busy, "lifecycle owner already active");
  if (config.local_node == kInvalidNodeId || config.local_node == kBroadcastNodeId ||
      config.local_mac == routeloom::MacAddress{}) {
    return Status::error(StatusCode::InvalidArgument, "owner identity");
  }
  constexpr std::uint32_t kRoleBits =
      sdkv1::kMemberRoleEndpoint | sdkv1::kMemberRoleRelay | sdkv1::kMemberRoleGateway;
  if (!profile::role_fits(config.role) ||
      (profile::kRoleFixed && config.role != profile::kRole) ||
      (config.joiner.capability & kRoleBits & ~profile::role_mask(config.role)) != 0 ||
      (config.joiner.requested_role & ~profile::role_mask(config.role)) != 0 ||
      (stores.site().has_site() &&
       (stores.site().site().role & ~profile::role_mask(config.role)) != 0)) {
    return Status::error(StatusCode::Unsupported, "RESOURCE_PROFILE_ROLE_MISMATCH");
  }
  // The sealer is constructed UNKEYED here: begin() runs before the
  // radio is up (the runtime constructor needs the provider view first),
  // and the cookie key must be drawn only after the radio entropy source
  // is ready (G-SEC P4 §8.4) — boot() arms it once entropy.begin() has
  // run. seal() refuses until then; nothing seals before boot.
  config_ = config;
  stores_ = &stores;
  entropy_ = &entropy;
  new (sealer_box_.data()) sdkv1::HmacJoinCookie();
  new (verifier_box_.data()) sdkv1::StoreCredentialVerifier(stores_->identity(), stores_->site());
  sdkv1::SecurityCoordinator::Deps deps{};
  deps.identity = &stores_->identity();
  deps.site = &stores_->site();
  deps.revocations = &stores_->revocation();
  deps.local_revocation = &stores_->local_revocation();
  deps.resume_storage = &stores_->resume2();
  deps.sleep_image = sleep_image;
  deps.entropy = entropy_;
  deps.rld1 = this;
  deps.mesh = this;
  deps.usb = this;
  deps.verifier = &verifier();
  deps.bank_aead = psa_session_aead_gcm();
  deps.join_aead = psa_edhoc_aead_ccm();
  deps.crypto_aead = *psa_aead_gcm();
  deps.proxy_sealer = &sealer();
  deps.authority_sink = this;
  deps.local_mac = config_.local_mac;
  deps.local_node = config_.local_node;
  deps.joiner_config = config_.joiner;
  deps.allowed_role = config_.role;
  new (coordinator_box_.data()) sdkv1::SecurityCoordinator(deps);
  coordinator_live_ = true;
  // The P6 membership lifecycle beside the coordinator: same stores and
  // RLX1 journal. Self is the RLI1
  // node id when provisioned, else the Kconfig identity (which becomes
  // the RLI1 id at provisioning — a mismatch blocks, never corrupts).
  sdkv1::LifecycleConfig lifecycle_config{};
  lifecycle_config.self = stores_->identity().has_identity()
                              ? stores_->identity().identity().node_id
                              : config_.local_node;
  lifecycle_config.profile =
      gateway_role() ? sdkv1::LifecycleProfile::Gateway : sdkv1::LifecycleProfile::Node;
  lifecycle_config.enabled_features = kCapRrsGossipV1;
  sdkv1::LifecyclePorts lifecycle_ports{lifecycle_authority_, lifecycle_peer_, lifecycle_runtime_,
                                        *entropy_, lifecycle_sink_, &lifecycle_observer_};
  new (lifecycle_box_.data())
      sdkv1::MembershipLifecycle(lifecycle_config, stores_->identity(), stores_->site(),
                                 stores_->revocation(), stores_->resume_cache(), lifecycle_ports,
                                 sdkv1::default_es256_verifier(), &stores_->lifecycle());
  lifecycle_live_ = true;
  lifecycle_box_in_use_ = true;
  begun_ = true;
  observer_store_ = EspNowDiscoveryObserver(config_.log_tag, runtime_);
  ESP_LOGI(config_.log_tag, "security owner ready (node 0x%llx)",
           static_cast<unsigned long long>(config_.local_node));
  return Status::success();
}

Status EspNowSecurityOwner::attach_runtime(EspNowRuntime& runtime) noexcept {
  if (!begun_) return Status::error(StatusCode::InvalidState, "owner not begun");
  if (runtime_ != nullptr) {
    return Status::error(StatusCode::AlreadyExists, "runtime already attached");
  }
  const Status status = runtime.attach_bootstrap_sink(*this);
  if (!status) return status;
  runtime_ = &runtime;
  runtime.set_rrs_chunk_sink(this);
  observer_store_ = EspNowDiscoveryObserver(config_.log_tag, runtime_);
  return Status::success();
}

Status EspNowSecurityOwner::attach_usb(usb::UsbBridge& bridge) noexcept {
  if (!profile::kGateway) {
    return Status::error(StatusCode::Unsupported, "USB bridge needs a gateway profile");
  }
  if (!begun_) return Status::error(StatusCode::InvalidState, "owner not begun");
  if (bridge_ != nullptr) {
    return Status::error(StatusCode::AlreadyExists, "usb already attached");
  }
  const Status status = bridge.attach_security_owner(*this);
  if (!status) return status;
  bridge_ = &bridge;
  return Status::success();
}

Status EspNowSecurityOwner::boot(const std::uint32_t rlboot_witness, const bool rlboot_prepared,
                                 const bool usb_direct, const MonotonicMs now_ms) noexcept {
  if (!begun_ || booted_) {
    return Status::error(StatusCode::InvalidState, "owner boot state");
  }
  if (runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "runtime not attached");
  }
  if (!rlboot_prepared || rlboot_witness == 0) {
    return Status::error(StatusCode::InvalidArgument, "boot witness unavailable");
  }
  // Arm the ZT OFFER cookie sealer from post-radio-up entropy (boot runs
  // after entropy.begin() in main): boot-RAM-only, so a reboot
  // invalidates every outstanding cookie. Unbegun entropy fails the boot
  // — an unkeyed coordinator must never run.
  std::array<std::uint8_t, 32> cookie_key{};
  Status key_status = entropy_->fill(MutableByteView{cookie_key.data(), cookie_key.size()});
  if (!key_status) return key_status;
  key_status = sealer().install_key(cookie_key);
  secure_clear(cookie_key.data(), cookie_key.size());
  if (!key_status) return key_status;
  // The lifecycle boots first (journal before member): a leftover
  // Removing/Holdoff intent from before the reboot runs to completion
  // before the coordinator may adopt anything.
  // A factory-fresh device (healthy empty site store, no journal record)
  // has nothing to adopt: booting the lifecycle now parks it in
  // StorageBlocked, which refuses the first MemberReady. It boots on that
  // first adoption instead, the path a reboot would take.
  const sdkv1::SiteStoreHealth site_health = stores_->site().health();
  const sdkv1::LifecycleStore& lifecycle_store = stores_->lifecycle();
  const bool factory_fresh =
      site_health.initialized && !site_health.has_site && !site_health.quarantined &&
      !site_health.uncertain && site_health.unsupported_mask == 0 &&
      site_health.read_error_mask == 0 && !site_health.active_load_failed &&
      !lifecycle_store.has_record() && !lifecycle_store.quarantined() &&
      !lifecycle_store.uncertain();
  sdkv1::LifecycleSnapshot boot_snap{};
  if (!factory_fresh) {
    const Status lifecycle_boot =
        lifecycle().dispatch(sdkv1::LifecycleInput::Boot(rlboot_prepared), now_ms);
    if (!lifecycle_boot) return lifecycle_boot;
    lifecycle_booted_ = true;
    boot_snap = lifecycle().snapshot();
  }
  // The RLX1 UnassignedReady watermark hands to the Joiner: a
  // post-removal Allow for an older generation of the same site refuses
  // (04 §6.4). Anything else clears the watermark.
  const sdkv1::LifecycleStore& journal = stores_->lifecycle();
  if (journal.has_record() &&
      journal.record().mode == sdkv1::LifecycleMode::UnassignedReady) {
    coordinator().set_removal_watermark(journal.record().site_id, journal.record().generation);
  } else {
    coordinator().set_removal_watermark(0, 0);
  }
  // A member rebooting mid-cutover replays its journal as Prepared:
  // the strike suppression must be live before the first poll.
  cutover_intent_ = boot_snap.phase == sdkv1::LifecyclePhase::Prepared ||
                    boot_snap.phase == sdkv1::LifecyclePhase::Switching;
  coordinator().set_cutover_intent(cutover_intent_);
  if (boot_snap.phase == sdkv1::LifecyclePhase::Removing ||
      boot_snap.phase == sdkv1::LifecyclePhase::Holdoff) {
    removal_pending_ = true;
    boot_witness_ = rlboot_witness;
    booted_ = true;
    ESP_LOGW(config_.log_tag, "boot: journal holds removal intent — erasure runs first");
    return Status::success();
  }
  // The authority transport needs the runtime (mesh port over the node)
  // and, on gateways, the bridge (USB lane + local direct port): both
  // attach before boot. Port attach precedes the Boot step so the first
  // adoption can start its channel immediately.
  if (gateway_role() && bridge() == nullptr) {
    return Status::error(StatusCode::InvalidState, "gateway without usb bridge");
  }
  new (mesh_port_box_.data()) MeshConfigPort(runtime_->node());
  authority_live_ = true;  // the accessors below (and the dtor) go live here
  if (gateway_role()) {
    new (transport_box_.gateway.data())
        sdkv1::AuthorityGateway(*mesh_port(), *this, *this, config_.local_node);
    new (mesh_sink_box_.data()) sdkv1::AuthorityMeshSink(*gateway());
    direct_port_.bind(this);
    Status authority_status = coordinator().attach_authority_port(direct_port_);
    if (!authority_status) return authority_status;
    authority_status = bridge()->attach_authority(*this);
    if (!authority_status) return authority_status;
  } else {
    new (transport_box_.endpoint.data())
        sdkv1::AuthorityEndpoint(*mesh_port(), config_.local_node);
    new (mesh_sink_box_.data()) sdkv1::AuthorityMeshSink(*endpoint());
    const Status authority_status = coordinator().attach_authority_port(*endpoint());
    if (!authority_status) return authority_status;
  }
  // The stored intake policy of this site applies before the proxy starts.
  if (stores_->site().has_site()) {
    const std::uint64_t site_id = stores_->site().site().site_id;
    sdkv1::ProxyPolicyRecord policy{};
    bool found = false;
    const Status loaded = stores_->proxy_policy().load(site_id, policy, found);
    coordinator().set_proxy_policy(site_id, loaded && (!found || policy.zero_touch_open));
  }
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Boot;
  event.now = now_ms;
  event.boot_witness = rlboot_witness;
  event.boot_prepared = rlboot_prepared;
  event.usb_direct = usb_direct;
  event.local_leave_completed = boot_snap.phase == sdkv1::LifecyclePhase::UnassignedReady &&
                               journal.has_record() &&
                               journal.record().mode == sdkv1::LifecycleMode::LeftReady;
  const Status status = coordinator().step(event);
  if (!status) return status;
  boot_witness_ = rlboot_witness;
  booted_ = true;
  ESP_LOGI(config_.log_tag, "booted (%s)", usb_direct ? "usb-direct" : "radio");
  return Status::success();
}

Status EspNowSecurityOwner::adopt_dev(const DevConfig& config,
                                        const MonotonicMs now_ms) noexcept {
  if (!begun_) return Status::error(StatusCode::InvalidState, "owner not begun");
  if (runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "runtime not attached");
  }
  if (booted_) {
    return Status::error(StatusCode::InvalidState, "owner already running");
  }
  // The dev route has no cutover: the static channel must already match
  // the radio (firmware boots the runtime on it). The coordinator
  // re-validates the rest (network/node/boot/role/PSK shapes).
  if (config.channel == 0 || runtime_->committed_channel() != config.channel) {
    return Status::error(StatusCode::InvalidArgument, "dev channel");
  }
  sdkv1::CoordinatorDevConfig adopted{};
  adopted.psk = config.psk;
  adopted.network = config.network;
  adopted.node = config.node;
  adopted.boot = config.boot;
  adopted.role = config.role;
  adopted.channel = config.channel;
  adopted.route_gateway_count = config.route_gateway_count;
  adopted.group_root_count = config.group_root_count;
  for (std::size_t i = 0; i < config.route_gateway_count &&
                          i < adopted.route_gateways.size(); ++i) {
    adopted.route_gateways[i] = config.route_gateways[i];
  }
  for (std::size_t i = 0; i < config.group_root_count &&
                          i < adopted.group_roots.size(); ++i) {
    adopted.group_roots[i] = config.group_roots[i];
  }
  const Status status = coordinator().adopt_dev(adopted, now_ms);
  secure_clear(adopted.psk);
  if (!status) return status;
  // A parked Recovery (ReportRecovery pending) is a failed adopt, not a
  // running dev node: fail loudly like a refused boot.
  if (coordinator().mode() == sdkv1::CoordinatorMode::Recovery) {
    return Status::error(StatusCode::RecoveryRequired, "dev adopt failed");
  }
  booted_ = true;  // the pump now drives the dev-armed coordinator
  security_profile_ = SecurityProfile::Development;
  ESP_LOGI(config_.log_tag, "dev adopted (node 0x%llx, boot %lu)",
           static_cast<unsigned long long>(config.node),
           static_cast<unsigned long>(config.boot));
  return Status::success();
}

void EspNowSecurityOwner::poll(const MonotonicMs now_ms) noexcept {
  if (!booted_) return;
  const std::uint64_t start_us = EspNowRuntime::now_us();
  poll_steps(now_ms);
  if (runtime_ != nullptr) {
    runtime_->note_security_busy_us(EspNowRuntime::now_us() - start_us);
  }
}

void EspNowSecurityOwner::poll_steps(const MonotonicMs now_ms) noexcept {
  poll_lifecycle(now_ms);
  if (removal_pending_) return;  // erasure owns the device until the reboot
  // RRS enforcement changes the handshake's signed local epoch and cancels
  // its pending flights. Finish the bounded local apply before starting a
  // fresh member discovery exchange, so its m1 can still accept m2.
  if (lifecycle_live_ && lifecycle_booted_ &&
      lifecycle().snapshot().phase == sdkv1::LifecyclePhase::ApplyingRrs) return;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Poll;
  event.now = now_ms;
  (void)coordinator().step(event);
  if (coordinator().mode() == sdkv1::CoordinatorMode::ZeroTouch) {
    static unsigned logged_join_state = 255;
    static unsigned logged_mode = 255;
    static unsigned logged_error = 255;
    const auto snapshot = coordinator().snapshot();
    const unsigned state = static_cast<unsigned>(snapshot.joiner);
    const unsigned mode = static_cast<unsigned>(snapshot.mode);
    const unsigned error = static_cast<unsigned>(snapshot.joiner_last_error);
    if (state != logged_join_state || mode != logged_mode || error != logged_error) {
      ESP_LOGI(config_.log_tag, "join mode=%u state=%u error=%u", mode, state, error);
      logged_join_state = state;
      logged_mode = mode;
      logged_error = error;
    }
  }
#if CONFIG_ROUTELOOM_TRACE
  if (coordinator().mode() == sdkv1::CoordinatorMode::Member) {
    static MonotonicMs last_member_trace = 0;
    if (now_ms >= last_member_trace + 5000) {
      last_member_trace = now_ms;
      const auto snap = coordinator().snapshot();
      const auto counts = coordinator().counters();
      const auto* disc = discovery();
      ESP_LOGI(config_.log_tag,
               "member state=%u links=%lu ends=%lu end_evict=%lu authority=%u/%u confirm=%u "
               "demux_drop=%lu",
               static_cast<unsigned>(snap.membership),
               static_cast<unsigned long>(snap.link_sessions),
               static_cast<unsigned long>(snap.end_sessions),
               static_cast<unsigned long>(snap.end_evictions),
               static_cast<unsigned>(snap.authority_started),
               static_cast<unsigned>(snap.authority_ready),
               static_cast<unsigned>(snap.join_confirmed),
               static_cast<unsigned long>(counts.demux_drops));
      ESP_LOGI(config_.log_tag,
               "member handshake starts=%lu requests=%lu rejected=%lu send_fail=%lu established=%lu failed=%lu last_error=%u active=%u",
               static_cast<unsigned long>(counts.member_starts),
               static_cast<unsigned long>(counts.link_requests),
               static_cast<unsigned long>(counts.link_request_failures),
               static_cast<unsigned long>(counts.link_send_failures),
               static_cast<unsigned long>(counts.link_established),
               static_cast<unsigned long>(counts.link_failed),
               static_cast<unsigned>(counts.link_last_error),
               static_cast<unsigned>(!snap.engine_quiescent));
      ESP_LOGI(config_.log_tag,
               "member end send_fail=%lu established=%lu failed=%lu last_error=%u",
               static_cast<unsigned long>(counts.end_send_failures),
               static_cast<unsigned long>(counts.end_established),
               static_cast<unsigned long>(counts.end_failed),
               static_cast<unsigned>(counts.end_last_error));
      const auto authority = coordinator().authority_snapshot();
      ESP_LOGI(config_.log_tag,
               "authority state=%u tx_sent=%llu tx_failed=%llu rx_accepted=%llu rx_rejected=%llu pull=%u busy=%u backoff_s=%lu",
               static_cast<unsigned>(authority.state),
               static_cast<unsigned long long>(authority.tx_sent),
               static_cast<unsigned long long>(authority.tx_failed),
               static_cast<unsigned long long>(authority.rx_accepted),
               static_cast<unsigned long long>(authority.rx_rejected),
               static_cast<unsigned>(authority.pull_pending),
               static_cast<unsigned>(authority.busy),
               static_cast<unsigned long>(authority.backoff_s));
      if (gateway_role() && gateway() != nullptr) {
        const auto& relay = gateway()->counters();
        ESP_LOGI(config_.log_tag,
                 "authority relay rx_carrier=%lu rx_manifest=%lu rx_chunk=%lu up=%lu blocked=%lu denied=%lu timeout=%lu",
                 static_cast<unsigned long>(relay.rx_carriers),
                 static_cast<unsigned long>(relay.rx_manifests),
                 static_cast<unsigned long>(relay.rx_chunks),
                 static_cast<unsigned long>(relay.up_fragments),
                 static_cast<unsigned long>(relay.up_blocked),
                 static_cast<unsigned long>(relay.denied),
                 static_cast<unsigned long>(relay.timeouts));
      } else if (endpoint() != nullptr) {
        const auto& mesh = endpoint()->counters();
        ESP_LOGI(config_.log_tag,
                 "authority mesh tx_carrier=%lu queued=%lu shed=%lu rx_carrier=%lu denied=%lu timeout=%lu",
                 static_cast<unsigned long>(mesh.tx_carriers),
                 static_cast<unsigned long>(mesh.mesh_queued),
                 static_cast<unsigned long>(mesh.mesh_shed),
                 static_cast<unsigned long>(mesh.rx_carriers),
                 static_cast<unsigned long>(mesh.rx_denied),
                 static_cast<unsigned long>(mesh.tx_timeouts));
      }
      if (mesh_sink() != nullptr) {
        ESP_LOGI(config_.log_tag, "authority jobs accepted=%lu failed=%lu last=%s",
                 static_cast<unsigned long>(mesh_sink()->jobs_accepted()),
                 static_cast<unsigned long>(mesh_sink()->jobs_failed()),
                 mesh_sink()->last_failure_reason());
      }
      if (disc != nullptr) {
        const auto stats = disc->stats();
        ESP_LOGI(config_.log_tag,
                 "member discovery rx=%lu offer_tx=%lu offer_rx=%lu auth=%lu kind_reject=%lu capacity=%lu send_fail=%lu",
                 static_cast<unsigned long>(stats.discovers_rx),
                 static_cast<unsigned long>(stats.offers_tx),
                 static_cast<unsigned long>(stats.offers_rx),
                 static_cast<unsigned long>(stats.auths_completed),
                 static_cast<unsigned long>(stats.kind_rejects),
                 static_cast<unsigned long>(stats.peer_capacity),
                 static_cast<unsigned long>(stats.send_failures));
        const auto scope = disc->scope_stats();
        ESP_LOGI(config_.log_tag,
                 "member scope raw=%lu accepted=%lu mac_reject=%lu hint=%lu generation=%lu key_unavailable=%lu budget=%lu",
                 static_cast<unsigned long>(scope.raw_rx),
                 static_cast<unsigned long>(scope.scope_accepted),
                 static_cast<unsigned long>(scope.mac_rejected),
                 static_cast<unsigned long>(scope.hint_mismatch),
                 static_cast<unsigned long>(scope.unknown_generation),
                 static_cast<unsigned long>(scope.key_unavailable),
                 static_cast<unsigned long>(scope.budget_dropped));
      }
    }
  }
#endif
  drive_authority(now_ms);
  poll_tune(now_ms);
  drain_actions(now_ms);
  if (discovery_live_ && runtime_ != nullptr && stores_ != nullptr &&
      stores_->site().has_site() &&
      coordinator().mode() == sdkv1::CoordinatorMode::Member) {
    const sdkv1::SiteRecord& site = stores_->site().site();
    bool routed = false;
    for (std::uint8_t i = 0; i < site.gateway_count; ++i) {
      const NodeId gateway = site.gateways[i];
      if (gateway == kInvalidNodeId) continue;
      if (gateway == self_node()) {
        routed = true;
        break;
      }
      const RouteSelection selection = runtime_->node().routes().best(gateway);
      std::uint32_t generation = 0, role = 0;
      if (selection.valid && selection.next_hop != kInvalidNodeId &&
          coordinator().authenticated_link(selection.next_hop, adopted_network_,
                                            generation, role)) {
        routed = true;
        break;
      }
    }
    discovery()->set_gateway_route_missing(site.gateway_count != 0 && !routed, now_ms);
  } else if (discovery_live_) {
    discovery()->set_gateway_route_missing(false, now_ms);
  }
}

// --- P6 lifecycle pump --------------------------------------------------------

void EspNowSecurityOwner::on_rrs_frame(const NodeId peer, const FrameType type,
                                       const ByteView body, const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!lifecycle_live_ || body.data == nullptr || body.size == 0 ||
      body.size > gossip_staged_[0].body.size()) {
    return;
  }
  if (type != FrameType::Control && type != FrameType::ControlObject) return;
  for (GossipStage& slot : gossip_staged_) {
    if (slot.used) continue;
    std::uint32_t generation = 0, role = 0;
    if (!coordinator_live_ || !coordinator().authenticated_link(peer, adopted_network_, generation, role))
      return;
    std::uint32_t binding = 0;
    if (runtime_ == nullptr || !runtime_->p6_link_binding(peer, binding)) return;
    std::memcpy(slot.body.data(), body.data, body.size);
    slot.body_size = body.size;
    slot.peer = peer;
    slot.carrier = type;
    slot.generation = generation;
    slot.role = role;
    slot.binding = binding;
    slot.used = true;
    return;
  }
  ++gossip_dropped_;
}

bool EspNowSecurityOwner::claim_rrs_chunk(const NodeId peer, const FrameType carrier,
                                          const ByteView body, const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!lifecycle_live_ || body.data == nullptr || body.size == 0 ||
      body.size > gossip_staged_[0].body.size()) {
    return false;
  }
  std::uint32_t binding = 0;
  if (runtime_ == nullptr || !runtime_->p6_link_binding(peer, binding) ||
      !lifecycle().owns_rrs_chunk(peer, binding, carrier, body)) return false;
  for (GossipStage& slot : gossip_staged_) {
    if (slot.used) continue;
    std::uint32_t generation = 0, role = 0;
    if (!coordinator_live_ || !coordinator().authenticated_link(peer, adopted_network_, generation, role))
      return true;
    std::memcpy(slot.body.data(), body.data, body.size);
    slot.body_size = body.size;
    slot.peer = peer;
    slot.carrier = carrier;
    slot.generation = generation;
    slot.role = role;
    slot.binding = binding;
    slot.used = true;
    return true;
  }
  ++gossip_dropped_;
  return true;  // claimed but unstaged: a retry, never migration's
}

void EspNowSecurityOwner::poll_lifecycle(const MonotonicMs now_ms) noexcept {
  if (!lifecycle_live_ || !lifecycle_booted_) return;
  sync_lifecycle_peers(now_ms);
  feed_lifecycle_inputs(now_ms);
  drain_authority_tx(now_ms);
  (void)lifecycle().dispatch(sdkv1::LifecycleInput::Poll(), now_ms);
  drain_authority_tx(now_ms);
  drain_peer_tx();
  drain_lifecycle_actions(now_ms);
  // Prepared/Switching members must keep old-group comms through the
  // commit window — the coordinator suppresses refresh strikes on the
  // newer-generation evidence that is expected mid-cutover.
  const auto phase = lifecycle().snapshot().phase;
  const bool intent = phase == sdkv1::LifecyclePhase::Prepared ||
                      phase == sdkv1::LifecyclePhase::Switching;
  if (intent != cutover_intent_) {
    cutover_intent_ = intent;
    coordinator().set_cutover_intent(intent);
  }
}

void EspNowSecurityOwner::sync_lifecycle_peers(const MonotonicMs now_ms) noexcept {
  if (runtime_ == nullptr || !coordinator_live_ || adopted_network_ == 0) return;
  // PeerBound acceptance depends on the stamp and on the lifecycle's
  // phase, adoption and revocation set; a change in any of them (or in
  // the radio generation) re-sends every stamp, otherwise only changed
  // stamps are sent.
  const sdkv1::LifecycleSnapshot life = lifecycle().snapshot();
  LifecycleGate gate{};
  gate.network = adopted_network_;
  gate.lifecycle_network = life.adopted_network;
  gate.radio_generation = runtime_->radio_generation().value;
  gate.site_commit_seq = life.site_commit_seq;
  gate.own_generation = life.own_generation;
  gate.rs_epoch = life.applied_rs_epoch;
  gate.phase = life.phase;
  const bool gate_changed = !(gate == lifecycle_gate_);
  lifecycle_gate_ = gate;
  std::array<LifecyclePeer, EspNowRuntime::kPeerCapacity> current{};
  std::size_t count = 0;
  runtime_->for_each_peer([&](const NodeId peer, const MacAddress&,
                              const RouteMetric, const bool) noexcept {
    if (peer == self_node() || count >= current.size()) return;
    std::uint32_t generation = 0, role = 0;
    if (!coordinator().authenticated_link(peer, adopted_network_, generation, role) ||
        role == 0 || role > 0xFF) return;
    std::uint32_t binding = 0;
    if (!runtime_->p6_link_binding(peer, binding)) return;
    LifecyclePeer entry{peer, generation, binding};
    const LifecyclePeer* prior = nullptr;
    for (const LifecyclePeer& known : lifecycle_peers_) {
      if (known.peer == peer) { prior = &known; break; }
    }
    if (gate_changed || prior == nullptr || prior->generation != generation ||
        prior->binding != binding) {
      sdkv1::PeerCredentialStamp stamp{};
      stamp.peer = peer;
      stamp.network = adopted_network_;
      stamp.assignment_generation = generation;
      stamp.role = static_cast<std::uint8_t>(role);
      stamp.binding_incarnation = binding;
      if (!lifecycle().dispatch(sdkv1::LifecycleInput::PeerBound(stamp), now_ms)) {
        entry.generation = 0;  // refused (table full): retry on the next sync
      }
    }
    current[count++] = entry;
  });
  for (const LifecyclePeer& prior : lifecycle_peers_) {
    if (prior.peer == kInvalidNodeId) continue;
    bool still_bound = false;
    for (std::size_t i = 0; i < count; ++i) {
      if (current[i].peer == prior.peer) { still_bound = true; break; }
    }
    if (!still_bound) {
      (void)lifecycle().dispatch(sdkv1::LifecycleInput::PeerGone(prior.peer), now_ms);
    }
  }
  lifecycle_peers_ = current;
}

void EspNowSecurityOwner::on_verified_authority(const std::uint8_t type,
                                                const ByteView plaintext) noexcept {
  if (((type < 5 || type > 7) && type != sdkv1::kAuthorityTypeProxyPolicy) ||
      plaintext.data == nullptr ||
      plaintext.size <= sdkv1::kAuthorityBodyHeadSize ||
      plaintext.size > authority_rx_staged_[0].body.size()) return;
  for (AuthorityRxStage& slot : authority_rx_staged_) {
    if (slot.used) continue;
    std::memcpy(slot.body.data(), plaintext.data, plaintext.size);
    slot.type = type;
    slot.size = plaintext.size;
    slot.used = true;
    return;
  }
}

// ProxyPolicySet (#176): durable before applied, applied before
// acknowledged. The ACK always names the generation now stored, so the
// site counts a proxy applied only for what survives a power cut.
void EspNowSecurityOwner::apply_proxy_policy(const ByteView tail) noexcept {
  sdkv1::ProxyPolicySet set{};
  if (!sdkv1::proxy_policy_set_decode(tail, set)) return;  // malformed: no ACK
  const std::uint64_t site_id = stores_->site().site().site_id;
  sdkv1::ProxyPolicyStore store = stores_->proxy_policy();
  sdkv1::ProxyPolicyRecord stored{};
  bool has = false;
  const Status loaded = store.load(site_id, stored, has);
  bool write = false;
  sdkv1::ProxyPolicyStatus status =
      loaded ? sdkv1::proxy_policy_decide(has ? &stored : nullptr, set, write)
             : sdkv1::ProxyPolicyStatus::StorageFailed;
  if (!loaded) coordinator().set_proxy_policy(site_id, false);
  if (write) {
    sdkv1::ProxyPolicyRecord record{};
    record.site_id = site_id;
    record.generation = set.generation;
    record.zero_touch_open = set.zero_touch_open;
    record.content = set.content;
    record.expected = set.expected;
    const Status committed = store.commit(record);
    const Status readback = store.load(site_id, stored, has);
    if (!readback) coordinator().set_proxy_policy(site_id, false);
    if (!committed || !readback) status = sdkv1::ProxyPolicyStatus::StorageFailed;
  }
  if (status == sdkv1::ProxyPolicyStatus::Applied && has) {
    coordinator().set_proxy_policy(site_id, stored.zero_touch_open, &stored.expected, runtime_->now_ms());
  }
  std::array<std::uint8_t, sdkv1::kProxyPolicyAckSize> ack{};
  if (!sdkv1::proxy_policy_ack_encode(status, has ? stored.generation : 0, ack)) return;
  for (AuthorityTxStage& slot : authority_tx_staged_) {
    if (slot.used) continue;
    std::memcpy(slot.body.data(), ack.data(), ack.size());
    slot.type = sdkv1::kAuthorityTypeProxyPolicy;
    slot.size = ack.size();
    slot.used = true;
    return;
  }
  // A full queue drops the ACK: the site resends and gets it next time.
}

void EspNowSecurityOwner::drain_authority_tx(const MonotonicMs now_ms) noexcept {
  for (AuthorityTxStage& slot : authority_tx_staged_) {
    if (!slot.used) continue;
    const Status sent = coordinator().send_authority_typed(
        slot.type, ByteView{slot.body.data(), slot.size}, now_ms);
    if (!sent) {
      // Transient refusals (mode churn, a channel still coming up) must not
      // kill the staged send: the lifecycle already counted it as emitted
      // when it staged, so dropping here loses the receipt forever. Keep
      // the slot and retry on the next poll — removal clears it regardless.
      break;
    }
    secure_clear(slot.body);
    slot = AuthorityTxStage{};
  }
}

void EspNowSecurityOwner::drain_peer_tx() noexcept {
  if (runtime_ == nullptr) return;
  for (PeerTxStage& slot : peer_tx_staged_) {
    if (!slot.used) continue;
    std::uint32_t generation = 0, role = 0;
    if (!coordinator().authenticated_link(slot.peer, adopted_network_, generation, role)) {
      secure_clear(slot.body);
      slot = PeerTxStage{};
      continue;
    }
    std::uint32_t binding = 0;
    if (!runtime_->p6_link_binding(slot.peer, binding) || binding != slot.binding) {
      secure_clear(slot.body);
      slot = PeerTxStage{};
      continue;
    }
    const Status sent = runtime_->p6_send(slot.peer, slot.carrier,
                                          ByteView{slot.body.data(), slot.size});
    if (!sent && (sent.code == StatusCode::WouldBlock || sent.code == StatusCode::Busy)) break;
    secure_clear(slot.body);
    slot = PeerTxStage{};
  }
}

void EspNowSecurityOwner::feed_lifecycle_inputs(const MonotonicMs now_ms) noexcept {
  // Gossip feeds only while adopted: the stamp needs the adopted network
  // and role, and the lifecycle ignores peer control while unadopted.
  if (adopted_network_ != 0 && adopted_role_ != 0) {
    for (AuthorityRxStage& slot : authority_rx_staged_) {
      if (!slot.used) continue;
      sdkv1::AuthorityBodyHead head{};
      const bool valid = sdkv1::authority_head_decode(
          ByteView{slot.body.data(), sdkv1::kAuthorityBodyHeadSize}, head).ok();
      if (valid && stores_ != nullptr && stores_->site().has_site() &&
          head.op == 1 && head.generation == stores_->site().site().assignment_generation &&
          stores_->site().site().network == adopted_network_) {
        sdkv1::PeerCredentialStamp stamp{};
        stamp.network = adopted_network_;
        stamp.peer = stores_->site().site().gateway_count != 0
                         ? stores_->site().site().gateways[0] : kInvalidNodeId;
        stamp.assignment_generation = head.generation;
        const ByteView tail{slot.body.data() + sdkv1::kAuthorityBodyHeadSize,
                            slot.size - sdkv1::kAuthorityBodyHeadSize};
        if (slot.type == sdkv1::kAuthorityTypeProxyPolicy) {
          apply_proxy_policy(tail);
        } else {
          (void)lifecycle().dispatch(sdkv1::LifecycleInput::Authority(stamp, slot.type, tail),
                                     now_ms);
        }
      }
      secure_clear(slot.body);
      slot = AuthorityRxStage{};
    }
    for (GossipStage& slot : gossip_staged_) {
      if (!slot.used) continue;
      slot.used = false;
      sdkv1::PeerCredentialStamp stamp{};
      stamp.peer = slot.peer;
      stamp.network = adopted_network_;
      std::uint32_t generation = 0, role = 0;
      if (coordinator().authenticated_link(slot.peer, adopted_network_, generation, role) &&
          generation == slot.generation && role == slot.role) {
        std::uint32_t binding = 0;
        if (!runtime_->p6_link_binding(slot.peer, binding) || binding != slot.binding) {
          secure_clear(slot.body);
          continue;
        }
        stamp.role = role;
        stamp.assignment_generation = generation;
        stamp.binding_incarnation = binding;
        (void)lifecycle().dispatch(
            sdkv1::LifecycleInput::PeerControl(
                stamp, slot.carrier, ByteView{slot.body.data(), slot.body_size}),
            now_ms);
      }
      secure_clear(slot.body);
    }
    if (completed_object_valid_) {
      completed_object_valid_ = false;
      (void)lifecycle().dispatch(
          sdkv1::LifecycleInput::Completed(
              completed_object_peer_,
              ByteView{completed_object_.data(), completed_object_size_}),
          now_ms);
    }
  } else {
    for (AuthorityRxStage& slot : authority_rx_staged_) {
      secure_clear(slot.body);
      slot = AuthorityRxStage{};
    }
    for (GossipStage& slot : gossip_staged_) slot.used = false;
    completed_object_valid_ = false;
  }
}

void EspNowSecurityOwner::drain_lifecycle_actions(const MonotonicMs now_ms) noexcept {
  for (int i = 0; i < 4; ++i) {
    sdkv1::LifecycleAction action{};
    if (!lifecycle().take_action(action)) break;
    switch (action.tag) {
      case sdkv1::LifecycleActionTag::RecoveryRequired:
      case sdkv1::LifecycleActionTag::StartRecoveryJoin:
        on_lifecycle_recovery(action, now_ms);
        break;
      case sdkv1::LifecycleActionTag::RestartUnassigned:
        if (action.reason == sdkv1::LifecycleActionReason::LocalLeave) {
          reboot_for_lifecycle("p6 local leave done — rebooting unassigned", true);
        }
        ESP_LOGW(config_.log_tag, "p6: removal holdoff done — rebooting unassigned");
        reboot_for_lifecycle("p6 restart-unassigned");
        break;
      case sdkv1::LifecycleActionTag::AdoptNetwork: {
        if (stores_ == nullptr ||
            stores_->site().commit_seq() != action.expected_site_commit_seq) {
          // The stores moved under the decision: the action stays pending
          // and retries next poll instead of adopting a stale switch.
          ESP_LOGW(config_.log_tag, "p6: adopt raced a store commit — retaking");
          break;
        }
        // A cold boot from Switching rolls the signed intent forward
        // before the coordinator has a Member binding. Reboot once from
        // the now-committed RLS1; the next boot has no Switching action.
        if (action.reason == sdkv1::LifecycleActionReason::ResumeSwitch &&
            adopted_network_ == 0 && adopted_role_ == 0 &&
            stores_->site().site().network == action.network &&
            stores_->lifecycle().record().mode == sdkv1::LifecycleMode::Idle) {
          reboot_for_lifecycle("p6 resume-switch adoption");
          break;
        }
        // A live cutover reboots exactly once; the clean boot completes
        // the action after it re-adopts from the committed stores — never
        // a second reboot on the same durable state.
        switch (sdkv1::adopt_network_disposition(
            action.network, adopted_network_, adopted_role_,
            coordinator_live_ && runtime_ != nullptr && runtime_->node().started() &&
                coordinator().mode() == sdkv1::CoordinatorMode::Member,
            runtime_ != nullptr &&
                runtime_->committed_channel() ==
                    coordinator().operating_channel(stores_->site().site().channel))) {
          case sdkv1::AdoptNetworkDisposition::Complete:
            ESP_LOGW(config_.log_tag, "p6: network 0x%llx adopted — completing",
                     static_cast<unsigned long long>(action.network));
            (void)lifecycle().dispatch(
                sdkv1::LifecycleInput::ActionDone(action.token, Status::success()), now_ms);
            break;
          case sdkv1::AdoptNetworkDisposition::WaitForAdoption:
            // The adoption is in flight (or failed and awaits
            // maintenance): the action stays pending for a retake.
            break;
          case sdkv1::AdoptNetworkDisposition::RebootToAdopt:
            ESP_LOGW(config_.log_tag, "p6: adopting network 0x%llx — rebooting",
                     static_cast<unsigned long long>(action.network));
            reboot_for_lifecycle("p6 adopt-network");
            break;
        }
        break;
      }
      case sdkv1::LifecycleActionTag::None:
        break;
    }
  }
}

void EspNowSecurityOwner::on_lifecycle_recovery(const sdkv1::LifecycleAction& action,
                                                const MonotonicMs now_ms) noexcept {
  // A self-rejecting RRS1 (or a link-failure verdict, issue #139)
  // re-proves the retained membership over a zero-touch join instead of
  // dropping it.
  if (lifecycle_recovery_token_ != 0) return;  // one recovery at a time
  if (stores_ == nullptr || stores_->site().commit_seq() != action.expected_site_commit_seq) {
    return;  // stale decision: the action stays pending for a retake
  }
  const Status started = coordinator().start_recovery_join(now_ms);
  if (!started) {
    // Not in Member mode (a recovery is already running, or removal
    // landed first): leave the action pending — completion arrives with
    // the Joiner's verdict, or not at all when removal wins.
    return;
  }
  lifecycle_recovery_token_ = action.token;
  ESP_LOGW(config_.log_tag, "p6: recovery join started reason=%u",
           static_cast<unsigned>(action.reason));
}

void EspNowSecurityOwner::complete_lifecycle_recovery(const bool reprovisioned,
                                                      const MonotonicMs now_ms) noexcept {
  if (lifecycle_recovery_token_ == 0 || !lifecycle_live_) return;
  const std::uint64_t token = lifecycle_recovery_token_;
  lifecycle_recovery_token_ = 0;
  (void)lifecycle().dispatch(sdkv1::LifecycleInput::ActionDone(token, Status::success()), now_ms);
  (void)lifecycle().dispatch(sdkv1::LifecycleInput::Recovery(reprovisioned), now_ms);
}

Status EspNowSecurityOwner::local_leave(const MonotonicMs now_ms) noexcept {
  if (!booted_ || !lifecycle_live_ || !lifecycle_booted_ || runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "LEAVE_NOT_MEMBER");
  }
  if (runtime_->node().in_external_callback()) {
    return Status::error(StatusCode::Busy, "owner leave in callback");
  }
  const Status status = lifecycle().dispatch(sdkv1::LifecycleInput::LocalLeave(), now_ms);
  if (!status) return status;
  // The intent is durable: nothing queued may leave under the old site.
  (void)runtime_->node().cancel_all("CANCELLED_LEAVE");
  // Stop admission and dispatch before returning, including the runtime
  // pass that precedes the lifecycle's next erasure step.
  (void)lifecycle_runtime_.remove_member_runtime();
  return Status::success();
}

Status EspNowSecurityOwner::request_join(const MonotonicMs now_ms) noexcept {
  if (!booted_ || !coordinator_live_ || removal_pending_) {
    return Status::error(StatusCode::InvalidState, "JOIN_NOT_AVAILABLE");
  }
  return coordinator().request_join(now_ms);
}

Status EspNowSecurityOwner::apply_join_policy(const sdkv1::JoinerConfig& policy,
                                              const std::uint32_t holdoff_ms) noexcept {
  if (!coordinator_live_) return Status::error(StatusCode::InvalidState, "owner not begun");
  const Status status = coordinator().apply_join_policy(policy, holdoff_ms);
  if (!status) return status;
  if (lifecycle_live_) lifecycle().set_holdoff_ms(holdoff_ms);
  return Status::success();
}

[[noreturn]] void EspNowSecurityOwner::reboot_for_lifecycle(const char* reason,
                                                            const bool leave) noexcept {
  if (restart_hook_ != nullptr) restart_hook_(restart_ctx_, leave);
  ESP_LOGE(config_.log_tag, "p6: %s (clean reboot, not a fault)", reason);
  vTaskDelay(pdMS_TO_TICKS(100));  // let the line reach the UART
  esp_restart();
  for (;;) {
  }  // unreachable: esp_restart never returns
}

void EspNowSecurityOwner::drive_authority(const MonotonicMs now_ms) noexcept {
  if (!authority_live_) return;
  if (gateway_role()) {
    gateway()->poll(now_ms);  // local downs deliver via on_local_down
    // The direct port stages exactly one completion per accepted send
    // (the port contract); it cannot feed the coordinator from inside
    // try_send, so the completion waits here for the next poll.
    if (usb_tx_pending_) {
      usb_tx_pending_ = false;
      sdkv1::CoordinatorEvent out{};
      out.kind = sdkv1::CoordinatorEventKind::AuthorityTx;
      out.now = now_ms;
      out.auth_token = usb_tx_.token;
      out.auth_delivered = usb_tx_.delivered;
      (void)coordinator().step(out);
    }
  } else {
    endpoint()->poll(now_ms);
    sdkv1::AuthorityRxCarrier rx{};
    if (endpoint()->take_rx(rx)) {
      sdkv1::CoordinatorEvent in{};
      in.kind = sdkv1::CoordinatorEventKind::AuthorityRx;
      in.now = now_ms;
      in.auth_kind = rx.kind;
      in.auth_bytes = rx.bytes;
      in.auth_writable = rx.writable;
      (void)coordinator().step(in);
    }
    sdkv1::AuthorityTxResult done{};
    while (endpoint()->take_tx_result(done)) {
      sdkv1::CoordinatorEvent out{};
      out.kind = sdkv1::CoordinatorEventKind::AuthorityTx;
      out.now = now_ms;
      out.auth_token = done.token;
      out.auth_delivered = done.delivered;
      (void)coordinator().step(out);
    }
  }
  // USB session edges drive the USB-bound channel: down arrives through
  // the bridge sinks; up is an edge the bridge never announces, so the
  // poll watches for it.
  if (bridge() != nullptr) {
    const bool active = bridge()->state() == usb::SessionState::Active;
    if (active && !usb_session_active_) {
      sdkv1::CoordinatorEvent up{};
      up.kind = sdkv1::CoordinatorEventKind::UsbSessionUp;
      up.now = now_ms;
      (void)coordinator().step(up);
    }
    usb_session_active_ = active;
  }
  // A retired GK observed on the air pulls the current one (throttled;
  // the backstop for a missed rotation Wake).
  if (group_key_retired_ && now_ms - last_pull_ms_ >= kRetiredPullWindowMs) {
    group_key_retired_ = false;
    last_pull_ms_ = now_ms;
    sdkv1::CoordinatorEvent pull{};
    pull.kind = sdkv1::CoordinatorEventKind::RequestPull;
    pull.now = now_ms;
    pull.pull_reason = 1;  // UnknownNewerEpoch
    (void)coordinator().step(pull);
  }
}

Status EspNowSecurityOwner::prepare_sleep(const MonotonicMs now_ms,
                                         const bool drain_deadline) noexcept {
  if (!booted_ || runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "owner not booted");
  }
  MeshNode& node = runtime_->node();
  if (node.in_external_callback() || (!drain_deadline && node.sleep_work_pending())) {
    return Status::error(StatusCode::Busy, "node has sleep work");
  }
  // Drain first: a pending action (tune/member/discovery) is owed work,
  // not sleep permission. The coordinator re-checks the slot anyway.
  poll_tune(now_ms);
  drain_actions(now_ms);
  if (!drain_deadline && node.sleep_work_pending()) {
    return Status::error(StatusCode::Busy, "node has sleep work");
  }
  const Status drained = node.set_draining(true);
  if (!drained) return drained;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::PrepareSleep;
  event.now = now_ms;
  const Status parked = coordinator().step(event);
  if (!parked) {
    (void)node.set_draining(false);
    return parked;
  }
  if (drain_deadline) {
    // The Owner path has no delivery image; report Fail dispositions
    // before tearing down radio work at the deadline.
    const Status settled = node.settle_failed_sleep_work();
    if (!settled) {
      (void)wake(now_ms);
      return settled;
    }
  } else {
    const Status quiet = node.quiesce_for_sleep();
    if (!quiet) {
      (void)wake(now_ms);
      return quiet;
    }
  }
  if (node.sleep_work_pending()) {
    (void)wake(now_ms);
    return Status::error(StatusCode::Busy, "node has sleep work");
  }
  return Status::success();
}

Status EspNowSecurityOwner::wake(const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  if (runtime_ != nullptr && runtime_->node().in_external_callback()) {
    return Status::error(StatusCode::Busy, "owner wake in callback");
  }
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Wake;
  event.now = now_ms;
  const Status awakened = coordinator().step(event);
  if (awakened && runtime_ != nullptr) (void)runtime_->node().set_draining(false);
  return awakened;
}

void EspNowSecurityOwner::on_bootstrap_rld1(const sdkv1::JoinRxMeta& meta,
                                            const std::uint32_t radio_generation,
                                            const ByteView frame,
                                            const MonotonicMs received_ms) noexcept {
  if (!booted_) return;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Rld1Rx;
  event.now = received_ms;
  event.rld1_meta = meta;
  event.rld1_frame = frame;
  event.radio_generation = radio_generation;
  (void)coordinator().step(event);
}

Status EspNowSecurityOwner::join_down(const NodeId to_proxy, const sdkv1::RelayObject& object,
                                      const ByteView raw_object,
                                      const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  const NodeId self =
      adopted_node_ != kInvalidNodeId ? adopted_node_ : config_.local_node;
  // A member gateway can host its own mesh join proxy. Both that proxy's
  // relay and a direct USB join name `self`; only the boot-witness-bound
  // LocalJoin token enters the direct lane. Other self-proxy downs go to
  // the gateway relay, which validates its live exchange and full token.
  if (to_proxy == self &&
      sdkv1::local_join_token_matches(sdkv1::relay_token_of(object.header),
                                       boot_witness_, local_join_relay_id_)) {
    const sdkv1::RelayHeader& header = object.header;
    if (header.dir != sdkv1::RelayDirection::Down || header.proxy != self ||
        header.joiner_mac != config_.local_mac) {
      return Status::error(StatusCode::InvalidArgument, "local join mismatch");
    }
    if (header.state == sdkv1::RelayState::Abort) {
      // Abort-via-down: the attempt dies like on session loss.
      local_join_relay_id_ = 0;
      sdkv1::CoordinatorEvent abort{};
      abort.kind = sdkv1::CoordinatorEventKind::UsbSessionDown;
      abort.now = now_ms;
      (void)coordinator().step(abort);
      return Status::success();
    }
    sdkv1::CoordinatorEvent down{};
    down.kind = sdkv1::CoordinatorEventKind::UsbLocalDown;
    down.now = now_ms;
    down.usb_phase = header.phase;
    down.usb_step = header.step;
    down.usb_body = object.message;
    return coordinator().step(down);
  }
  sdkv1::CoordinatorEvent down{};
  down.kind = sdkv1::CoordinatorEventKind::UsbRelayDown;
  down.now = now_ms;
  down.usb_proxy = to_proxy;
  down.usb_object = raw_object;
  return coordinator().step(down);
}

Status EspNowSecurityOwner::join_abort(const NodeId proxy, const sdkv1::RelayToken token,
                                       const std::uint8_t reason,
                                       const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  const NodeId self =
      adopted_node_ != kInvalidNodeId ? adopted_node_ : config_.local_node;
  if (proxy == self &&
      sdkv1::local_join_token_matches(token, boot_witness_, local_join_relay_id_)) {
    // The host is aborting our own LocalJoin attempt.
    local_join_relay_id_ = 0;
    sdkv1::CoordinatorEvent abort{};
    abort.kind = sdkv1::CoordinatorEventKind::UsbSessionDown;
    abort.now = now_ms;
    (void)coordinator().step(abort);
    return Status::success();
  }
  sdkv1::CoordinatorEvent abort{};
  abort.kind = sdkv1::CoordinatorEventKind::UsbRelayAbort;
  abort.now = now_ms;
  abort.usb_proxy = proxy;
  abort.usb_relay_id = token.relay_id;
  abort.usb_gateway_epoch = token.gateway_epoch;
  abort.usb_proxy_epoch = token.proxy_epoch;
  abort.usb_reason = reason;
  return coordinator().step(abort);
}

void EspNowSecurityOwner::join_session_down(const MonotonicMs now_ms) noexcept {
  local_join_relay_id_ = 0;
  if (!booted_) return;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::UsbSessionDown;
  event.now = now_ms;
  (void)coordinator().step(event);
}

Status EspNowSecurityOwner::authority_down(const NodeId device,
                                           const usb::AuthorityFragment& fragment,
                                           bool& complete,
                                           const MonotonicMs now_ms) noexcept {
  complete = false;
  if (!booted_ || !authority_live_ || !gateway_role()) {
    return Status::error(StatusCode::InvalidState, "authority lane not live");
  }
  // Self-addressed downs reassemble in the relay slots like any device;
  // the pump delivers them to the local channel instead of the mesh.
  (void)device;
  return gateway()->authority_down(fragment.device, fragment, complete, now_ms);
}

Status EspNowSecurityOwner::site_state_set(const usb::SiteStateSet& set,
                                           usb::SiteStateReport& report,
                                           const MonotonicMs now_ms) noexcept {
  if (!booted_ || !authority_live_ || !gateway_role()) {
    return Status::error(StatusCode::InvalidState, "authority lane not live");
  }
  std::uint32_t current = 0;
  std::uint32_t next = 0;
  const bool valid = coordinator().group_epochs(current, next);
  report.local_state_valid = valid;
  report.local_current = current;
  report.local_next = next;
  if (set.action == usb::SiteStateAction::WakeLocal) {
    // The host asks the gateway to (re)open its own channel: the local
    // equivalent of a Wake carrier (content-free, 8 bytes). The client
    // coalesces rapid wakes itself.
    static const std::uint8_t kWake[8] = {0};
    sdkv1::CoordinatorEvent wake{};
    wake.kind = sdkv1::CoordinatorEventKind::AuthorityRx;
    wake.now = now_ms;
    wake.auth_kind = sdkv1::AuthorityCarrierKind::Wake;
    wake.auth_bytes = ByteView{kWake, sizeof(kWake)};
    (void)coordinator().step(wake);
  } else if (valid && set.gk_epoch_hint != 0 && set.gk_epoch_hint != current &&
             set.gk_epoch_hint != next) {
    // The host's GK view matches neither of ours: ask for the current
    // one (the channel bucket paces the wire).
    sdkv1::CoordinatorEvent pull{};
    pull.kind = sdkv1::CoordinatorEventKind::RequestPull;
    pull.now = now_ms;
    pull.pull_reason = 1;  // UnknownNewerEpoch
    (void)coordinator().step(pull);
  }
  // Site/rs hints are the host's view of durable floors the device never
  // re-reads mid-boot; the GK hint above is the only acting one.
  return Status::success();
}

void EspNowSecurityOwner::authority_session_down(const MonotonicMs now_ms) noexcept {
  usb_tx_pending_ = false;
  if (authority_live_ && gateway_role()) gateway()->drop_all();
  if (!booted_) return;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::UsbSessionDown;
  event.now = now_ms;
  (void)coordinator().step(event);
}

bool EspNowSecurityOwner::send_up(const usb::AuthorityFragment& fragment) noexcept {
  if (bridge() == nullptr) return false;
  return bridge()->send_authority_up(fragment).ok();
}

void EspNowSecurityOwner::on_local_down(const sdkv1::AuthorityCarrierKind kind,
                                        const MutableByteView bytes) noexcept {
  if (!booted_) return;  // poll context; bytes borrow the relay slot
  sdkv1::CoordinatorEvent in{};
  in.kind = sdkv1::CoordinatorEventKind::AuthorityRx;
  in.now = runtime_ != nullptr ? runtime_->now_ms() : 0;
  in.auth_kind = kind;
  in.auth_bytes = ByteView{bytes.data, bytes.size};
  in.auth_writable = bytes;
  (void)coordinator().step(in);
}

bool EspNowSecurityOwner::DirectUsbAuthorityPort::try_send(
    const NodeId gateway, const sdkv1::AuthorityCarrierKind kind, const ByteView carrier,
    std::uint64_t& token) noexcept {
  token = 0;
  if (owner_ == nullptr || owner_->bridge() == nullptr) return false;
  if (owner_->bridge()->state() != usb::SessionState::Active) return false;
  if (owner_->usb_tx_pending_) return false;  // one completion at a time
  if (!sdkv1::authority_carrier_kind_valid(static_cast<std::uint8_t>(kind)) ||
      !sdkv1::authority_carrier_length_valid(kind, carrier.size) ||
      (carrier.size != 0 && carrier.data == nullptr)) {
    return false;
  }
  if (++owner_->usb_transfer_ == 0) owner_->usb_transfer_ = 1;
  // One carrier is at most 3 fragments (960 B data each). A refusal past
  // the first leaves a host-side partial the host's reassembly window
  // expires; the channel's Tick retries the whole carrier under a fresh
  // token, so the partial never merges with the retry.
  constexpr std::size_t kFragData = 960;
  std::size_t offset = 0;
  while (offset < carrier.size) {
    const std::size_t length =
        carrier.size - offset > kFragData ? kFragData : carrier.size - offset;
    usb::AuthorityFragment fragment{};
    fragment.device = owner_->self_node();
    fragment.transfer_id = owner_->usb_transfer_;
    fragment.kind = kind;
    fragment.hops = 0;  // direct: never touched the mesh
    fragment.total = static_cast<std::uint16_t>(carrier.size);
    fragment.offset = static_cast<std::uint16_t>(offset);
    fragment.data = ByteView{carrier.data + offset, length};
    (void)gateway;  // the USB leg needs no route address
    if (!owner_->bridge()->send_authority_up(fragment)) return false;
    offset += length;
  }
  token = owner_->usb_transfer_;
  owner_->usb_tx_ = sdkv1::AuthorityTxResult{token, true};
  owner_->usb_tx_pending_ = true;
  return true;
}

Status EspNowSecurityOwner::send_rld1(const routeloom::MacAddress& destination,
                                      const ByteView frame) noexcept {
  if (runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "runtime not attached");
  }
  return runtime_->send_rld1(destination, frame);
}

Status EspNowSecurityOwner::send_bootstrap(const NodeId destination, const FrameType type,
                                           const ByteView payload, const std::uint32_t lifetime_ms,
                                           const MonotonicMs now_ms, MessageId& id) noexcept {
  if (runtime_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "runtime not attached");
  }
  const Status sent = runtime_->node().send_bootstrap(destination, type, payload,
                                                      lifetime_ms, now_ms, id);
#if CONFIG_ESP_CONSOLE_USB_SERIAL_JTAG
  if (!sent.ok()) {
    ESP_LOGW(config_.log_tag, "end bootstrap tx peer=%u type=%u code=%u detail=%s",
             static_cast<unsigned>(destination), static_cast<unsigned>(type),
             static_cast<unsigned>(sent.code), sent.detail);
  }
#endif
  return sent;
}

Status EspNowSecurityOwner::send_local_join_up(const sdkv1::JoinAuthPhase phase,
                                               const std::uint8_t step,
                                               const ByteView message) noexcept {
  if (bridge() == nullptr) {
    return Status::error(StatusCode::InvalidState, "usb not attached");
  }
  if (local_join_relay_id_ == 0) {
    std::uint32_t id = 0;
    const Status drawn = entropy_->fill(
        MutableByteView{reinterpret_cast<std::uint8_t*>(&id), sizeof(id)});
    if (!drawn) return drawn;
    local_join_relay_id_ = id != 0 ? id : 1;  // nonzero within the session
  }
  const NodeId self =
      adopted_node_ != kInvalidNodeId ? adopted_node_ : config_.local_node;
  sdkv1::RelayObject up{};
  up.header.dir = sdkv1::RelayDirection::Up;
  up.header.relay_id = local_join_relay_id_;
  up.header.proxy = self;
  up.header.joiner_mac = config_.local_mac;
  up.header.phase = phase;
  up.header.step = step;
  up.header.state = sdkv1::RelayState::Continue;
  const sdkv1::RelayToken token =
      sdkv1::local_join_token(boot_witness_, local_join_relay_id_);
  up.header.gateway_epoch = token.gateway_epoch;
  up.header.proxy_epoch = token.proxy_epoch;
  up.message = message;
  std::array<std::uint8_t, sdkv1::kRelayObjectMax> encoded{};
  std::size_t written = 0;
  const Status status = sdkv1::relay_object_encode(
      up, MutableByteView{encoded.data(), encoded.size()}, written);
  if (!status) return status;
  const Status sent = bridge()->relay_up(self, 0, ByteView{encoded.data(), written});
  if (!sent) {
    ESP_LOGW(config_.log_tag, "local join up step=%u failed: %s",
             static_cast<unsigned>(step), sent.detail);
  } else {
    ESP_LOGI(config_.log_tag, "local join up step=%u queued (%lu bytes)",
             static_cast<unsigned>(step), static_cast<unsigned long>(written));
  }
  return sent;
}

Status EspNowSecurityOwner::send_relay_up_to_host(const NodeId proxy, const std::uint8_t hops,
                                                  const ByteView object) noexcept {
  if (bridge() == nullptr) {
    // No host: the gateway engine sheds with authority_unreachable.
    return Status::error(StatusCode::InvalidState, "usb not attached");
  }
  return bridge()->relay_up(proxy, hops, object);
}

Status EspNowSecurityOwner::send_relay_abort_to_host(
    const NodeId proxy, const sdkv1::RelayToken token,
    const sdkv1::RelayAbortReason reason) noexcept {
  if (bridge() == nullptr) {
    return Status::error(StatusCode::InvalidState, "usb not attached");
  }
  return bridge()->relay_abort(proxy, token, reason);
}

SecurityProfile EspNowSecurityOwner::security_profile() const noexcept {
  // The selected profile survives recovery; membership is not qualification.
  // MemberEdhoc remains Candidate until all production gates are met.
  return security_profile_;
}

bool EspNowSecurityOwner::binds_scope() const noexcept {
  // Vacuously true: member discovery never runs PROVE/CONFIRM (proofs are
  // engine-minted), so no transcript binding is needed — but Required
  // refuses to start without the flag, and the GK scope binds
  // DISCOVER/OFFER through the scope provider instead.
  return true;
}

Status EspNowSecurityOwner::cookie_seal(const CookieMaterial& material, AuthTag& out) noexcept {
  const sdkv1::MemberCookie* cookie = coordinator().member_cookie();
  if (cookie == nullptr) {
    return Status::error(StatusCode::InvalidState, "member cookie not live");
  }
  if (material.time_bucket > UINT64_MAX / sdkv1::MemberCookie::kBucketMs) {
    return Status::error(StatusCode::InvalidArgument, "cookie bucket overflow");
  }
  return cookie->seal(material.requester_mac, material.requester_nonce, material.network,
                      material.time_bucket * sdkv1::MemberCookie::kBucketMs, out);
}

Status EspNowSecurityOwner::cookie_verify(const CookieMaterial& material,
                                          const AuthTag& tag) noexcept {
  const sdkv1::MemberCookie* cookie = coordinator().member_cookie();
  if (cookie == nullptr) {
    return Status::error(StatusCode::InvalidState, "member cookie not live");
  }
  if (material.time_bucket > UINT64_MAX / sdkv1::MemberCookie::kBucketMs) {
    return Status::error(StatusCode::InvalidArgument, "cookie bucket overflow");
  }
  return cookie->verify(material.requester_mac, material.requester_nonce, material.network,
                        ByteView{tag.data(), tag.size()},
                        material.time_bucket * sdkv1::MemberCookie::kBucketMs);
}

Status EspNowSecurityOwner::attest(const autonomy::AuthPhase, const AuthTranscript&,
                                   AuthTag&) noexcept {
  return Status::error(StatusCode::Unsupported, "member proofs are engine-minted");
}

Status EspNowSecurityOwner::verify(const autonomy::AuthPhase, const AuthTranscript&,
                                   const AuthTag&) noexcept {
  return Status::error(StatusCode::Unsupported, "member proofs are engine-minted");
}

Status EspNowSecurityOwner::issue_proof(const AuthTranscript&, const NodeId, const AuthTag&,
                                        AuthenticatedPeerProof&) noexcept {
  return Status::error(StatusCode::Unsupported, "member proofs are engine-minted");
}

void EspNowSecurityOwner::drain_actions(const MonotonicMs now_ms) noexcept {
  for (;;) {
    sdkv1::CoordinatorAction action{};
    if (!coordinator().take_action(action).ok()) return;
    switch (action.kind) {
      case sdkv1::CoordinatorActionKind::TuneChannel:
        on_tune_channel(action.tune, now_ms);
        break;
      case sdkv1::CoordinatorActionKind::ApplyMemberConfig:
        on_member_config(action.member, now_ms);
        break;
      case sdkv1::CoordinatorActionKind::StartMemberDiscovery:
        on_start_discovery(now_ms);
        break;
      case sdkv1::CoordinatorActionKind::ReportRemoval:
        ESP_LOGE(config_.log_tag,
                 "membership removed (site 0x%llx gen %lu): traffic stopped, "
                 "cleanup rides maintenance",
                 static_cast<unsigned long long>(action.removal.site_id),
                 static_cast<unsigned long>(action.removal.generation));
        runtime_->node().set_relay_enabled(false);
        // The verified notice also drives the journaled erasure: the
        // lifecycle re-verifies the COSE itself and runs Removing (full
        // cleanup) → Holdoff → UnassignedReady → reboot. A recovery join
        // that lands here found the removal instead of reprovisioning.
        if (lifecycle_live_ && lifecycle_booted_) {
          (void)lifecycle().dispatch(
              sdkv1::LifecycleInput::RemovalRequired(ByteView{action.removal.object.data(),
                                                              action.removal.object.size()}),
              now_ms);
          complete_lifecycle_recovery(false, now_ms);
        }
        break;
      case sdkv1::CoordinatorActionKind::ReportRecovery:
        ESP_LOGE(config_.log_tag, "membership recovery required (reason %u): see maintenance",
                 static_cast<unsigned>(action.recovery));
        lifecycle_journal_.note_recovery_reported(
            static_cast<std::uint8_t>(action.recovery), now_ms);
        emit_recovery_diagnostic(static_cast<std::uint8_t>(action.recovery));
        // A recovery join that lands here did not reprovision: the
        // lifecycle decides the next step (retry or maintenance).
        if (lifecycle_live_ && lifecycle_booted_) complete_lifecycle_recovery(false, now_ms);
        break;
      case sdkv1::CoordinatorActionKind::None:
        break;
    }
  }
}

void EspNowSecurityOwner::on_tune_channel(const sdkv1::CoordinatorTune& tune,
                                          const MonotonicMs now_ms) noexcept {
  if (tune_.active) {
    // Unreachable: the Joiner waits for ChannelReady before the next
    // tune. Drop defensively rather than misattribute completions.
    ESP_LOGW(config_.log_tag, "tune dropped: another tune outstanding");
    return;
  }
  // The join PHY rides the radio's existing rate selection (LR250 peers
  // stay LR250); the cutover only moves the channel.
  (void)tune.phy;
  const Status requested = request_cutover(tune.channel, tune.token, now_ms);
  if (!requested) {
    ESP_LOGW(config_.log_tag, "tune request failed: %s", requested.detail);
    report_tune(Tune{tune.token, kInvalidOperationToken, tune.channel, true},
                StatusCode::RadioFailure, now_ms);
  }
}

void EspNowSecurityOwner::on_member_config(const sdkv1::CoordinatorMemberConfig& member,
                                           const MonotonicMs now_ms) noexcept {
  NodeConfig node = runtime_->node().config();
  // RLT1's mesh header carries the site's low 32-bit network id. The
  // full 64-bit value (high word = site epoch) remains in adopted_network_
  // for membership, authority and cryptographic binding.
  node.network = static_cast<std::uint32_t>(member.network);
  node.node = member.node;
  node.message_session = member.message_session;
  node.boot_session = member.boot_session;
  node.link_epoch = member.link_epoch;
  node.end_epoch = member.end_epoch;
  node.boot_incarnation = member.boot_incarnation;
  node.route_gateways.fill(kInvalidNodeId);
  node.group_roots.fill(kInvalidNodeId);
  const bool dev_mode =
      coordinator().mode() == sdkv1::CoordinatorMode::Dev;
  if (dev_mode) {
    // Dev adoption carries both lists explicitly from the board config;
    // nothing is remapped.
    for (std::size_t i = 0; i < member.route_gateway_count &&
                            i < node.route_gateways.size(); ++i) {
      node.route_gateways[i] = member.route_gateways[i];
    }
    for (std::size_t i = 0; i < member.group_root_count &&
                            i < node.group_roots.size(); ++i) {
      node.group_roots[i] = member.group_roots[i];
    }
  } else if (config_.flat_group_routing) {
    // Member flat group tree (dev-flow §6.1): the verified SitePackage
    // gateway list is the root set; routing policy stays flat.
    for (std::size_t i = 0; i < member.route_gateway_count &&
                            i < node.group_roots.size(); ++i) {
      node.group_roots[i] = member.route_gateways[i];
    }
  } else {
    for (std::size_t i = 0; i < member.route_gateway_count &&
                            i < node.route_gateways.size(); ++i) {
      node.route_gateways[i] = member.route_gateways[i];
    }
  }
  const std::uint8_t operating = member.channel;
  Status status = runtime_->adopt_member_node(node);
  bool same = false;
  if (!status && status.code == StatusCode::InvalidState && runtime_->node().started()) {
    const NodeConfig& live = runtime_->node().config();
    // The mesh header holds only the low network word. The retained full
    // site epoch must match too before a running node can be reused. The
    // radio channel is not part of the identity: a joiner scan hop in
    // flight when the re-adopt lands leaves it off-channel, and the
    // apply path moves it back below instead of failing the adopt.
    same = adopted_network_ == member.network && live.network == node.network &&
           live.node == node.node && live.message_session == node.message_session &&
           live.boot_session == node.boot_session && live.link_epoch == node.link_epoch &&
           live.end_epoch == node.end_epoch && live.boot_incarnation == node.boot_incarnation &&
           live.route_gateways == node.route_gateways &&
           live.group_roots == node.group_roots &&
           runtime_->node().local_role() == member.role;
  }
  if (!status && !same) {
    // A re-issued membership for another network (a cutover straggler
    // back over ZT, 04 §7): the mesh node and discovery cannot
    // re-adopt live, so reboot once like AdoptNetwork — the clean
    // boot re-adopts from the committed (reissued) stores and the
    // lifecycle cuts the stale Prepared stage there. Never a second
    // reboot on the same durable state: post-reboot the node starts
    // fresh and the adopt below succeeds.
    if (status.code == StatusCode::InvalidState && runtime_->node().started() &&
        adopted_network_ != 0 && adopted_role_ != 0 && member.network != adopted_network_ &&
        stores_ != nullptr && stores_->site().has_site() &&
        stores_->site().site().network == member.network) {
      reboot_for_lifecycle("member re-adopt");
    }
    ESP_LOGE(config_.log_tag, "member node adopt failed: %s", status.detail);
    report_tune(Tune{0, kInvalidOperationToken, operating, true},
                StatusCode::RadioFailure, runtime_->now_ms());
    return;
  }
  adopted_node_ = member.node;
  adopted_network_ = member.network;
  adopted_role_ = member.role;
  // The adopted config may have made this bridge a group root for the
  // first time — attach_group() ran before membership existed, so the
  // Hello bitmap never advertised it. The bit is bound into the
  // authenticated HelloAck: re-evaluate it here, which drains a live
  // session behind a sealed error so the host's re-hello observes the
  // restored capability (the authority lane resyncs and a pending
  // JoinConfirm is retransmitted across the bounce).
  if (bridge() != nullptr) {
    (void)bridge()->refresh_group_capability(now_ms);
  }
  // The lifecycle needs the verified package RS target at fresh adoption;
  // boot re-adoption carries zero and uses its durable floor.
  if (lifecycle_live_ && stores_ != nullptr) {
    // First adoption of a factory-fresh device: the lifecycle boots on the
    // committed site now, then takes the package RS target like any adoption.
    if (!lifecycle_booted_ &&
        lifecycle().dispatch(sdkv1::LifecycleInput::Boot(true), now_ms)) {
      lifecycle_booted_ = true;
    }
    if (lifecycle_booted_) {
      (void)lifecycle().dispatch(
          sdkv1::LifecycleInput::MemberReady(stores_->site().commit_seq(),
                                             member.rs_epoch_to_fetch), now_ms);
      complete_lifecycle_recovery(true, now_ms);
    }
  }
  // Adoption binds the authority transport's self id (self-downs deliver
  // locally and self-addressed mesh sends refuse from here on).
  if (authority_live_) {
    if (gateway_role()) {
      gateway()->set_self(member.node);
    } else {
      endpoint()->set_self(member.node);
    }
  }
  if (same && runtime_->committed_channel() == operating) {
    // Re-proved membership on a running node still owes the coordinator
    // ChannelReady; a second runtime start would incorrectly fail.
    sdkv1::CoordinatorEvent ready{};
    ready.kind = sdkv1::CoordinatorEventKind::ChannelReady;
    ready.now = runtime_->now_ms();
    ready.channel_result = StatusCode::Ok;
    ready.channel = operating;
    ready.channel_generation = runtime_->radio_generation().value;
    (void)coordinator().step(ready);
    return;
  }
  if (same) {
    // The node config is already live but the radio is off the operating
    // channel (a joiner scan hop was in flight when the re-adopt
    // landed). Move it back like the apply path; the token-0 completion
    // skips the runtime start because the node is already running.
    apply_retries_ = kApplyCutoverRetries;
    apply_channel_ = operating;
    status = request_cutover(operating, 0, runtime_->now_ms());
    if (!status) {
      ESP_LOGE(config_.log_tag, "member channel move failed: %s", status.detail);
      report_tune(Tune{0, kInvalidOperationToken, operating, true},
                  StatusCode::RadioFailure, runtime_->now_ms());
    }
    return;
  }
  // MeshNode gates bootstrap transit on the adopted Relay/Gateway role.
  // Enabling relay alone leaves its local role at zero and rejects routed
  // session handshakes with BOOTSTRAP_TRANSIT_ROLE.
  runtime_->node().set_local_role(member.role);
  // The gossip sink rides the member node: a fresh adopt placement-news
  // the node after reconstruction. Without it P6 frames reject.
  (void)runtime_->node().set_rrs_sink(this);
  runtime_->node().set_bootstrap_sink(&coordinator());
  // Endpoint-only members must not advertise transit routes.
  runtime_->node().set_relay_enabled(
      (member.role & (sdkv1::kMemberRoleRelay | sdkv1::kMemberRoleGateway)) != 0);
  // The radio may still sit on the join channel: move it to the adopted
  // operating channel before the node starts (no member traffic flows
  // during the move). Already there → start immediately.
  if (operating == runtime_->committed_channel()) {
    report_tune(Tune{0, kInvalidOperationToken, operating, true}, StatusCode::Ok,
                runtime_->now_ms());
    return;
  }
  apply_retries_ = kApplyCutoverRetries;
  apply_channel_ = operating;
  status = request_cutover(operating, 0, runtime_->now_ms());
  if (!status) {
    ESP_LOGE(config_.log_tag, "member channel move failed: %s", status.detail);
    report_tune(Tune{0, kInvalidOperationToken, operating, true},
                StatusCode::RadioFailure, runtime_->now_ms());
  }
}

void EspNowSecurityOwner::on_start_discovery(const MonotonicMs now_ms) noexcept {
  if (discovery_live_) {
    discovery()->rearm_repair();
    return;
  }
  // The dev route adopts static config, never an RLS1: the discovery
  // config gate below (engine mode + valid adoption) is the check there.
  if (!dev_adopted() && !stores_->site().has_site()) {
    ESP_LOGE(config_.log_tag, "member discovery without adopted site");
    return;
  }
  DiscoveryConfig config{};
  const Status prepared = coordinator().member_discovery_config(config);
  if (!prepared) {
    ESP_LOGE(config_.log_tag, "member discovery config failed: %s", prepared.detail);
    return;
  }
  auto* engine = new (discovery_box_.data()) NeighborDiscovery(config, *runtime_, *this,
                                                         coordinator().membership_hooks(),
                                                         *entropy_, observer_store_);
  discovery_live_ = true;
  Status status = engine->start(now_ms);
  if (!status) {
    if (status.code == StatusCode::RecoveryRequired) {
      // The adopted membership exists but cannot be proven yet (e.g. a
      // cross-network re-adopt whose RRS1 floor set never landed). A dead
      // stop here strands the node forever — re-prove over the zero-touch
      // join, whose reissue re-delivers the floor set out-of-band.
      engine->~NeighborDiscovery();
      discovery_live_ = false;
      secure_clear(discovery_box_);
      if (coordinator().start_recovery_join(now_ms)) return;
    }
    abort_discovery_start(now_ms, false);
    return;
  }
  status = coordinator().attach_discovery(*engine);
  if (!status) {
    abort_discovery_start(now_ms, false);
    return;
  }
  status = runtime_->attach_autonomy(*engine);
  if (!status) {
    abort_discovery_start(now_ms, true);
    return;
  }
  engine->set_member_handshake_mode(true);
  status = engine->begin_discovery(now_ms);
  if (!status) {
    abort_discovery_start(now_ms, true);
    return;
  }
  ESP_LOGI(config_.log_tag, "member discovery started");
}

void EspNowSecurityOwner::abort_discovery_start(const MonotonicMs now_ms,
                                                const bool attached) noexcept {
  // Attached ports may retain the discovery pointer. Keep the object alive
  // until runtime teardown, while revoking all session keys and radio work.
  if (!attached && discovery_live_) {
    discovery()->~NeighborDiscovery();
    discovery_live_ = false;
    secure_clear(discovery_box_);
  }
  sdkv1::CoordinatorEvent stop{};
  stop.kind = sdkv1::CoordinatorEventKind::Stop;
  stop.now = now_ms;
  (void)coordinator().step(stop);
  runtime_->stop();
}

void EspNowSecurityOwner::poll_tune(const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  if (!tune_.active) return;
  OperationResult result{};
  if (!runtime_->radio_operation_result(tune_.op, result)) {
    // Evidence expired before a terminal outcome: call it unknown.
    const Tune done = tune_;
    tune_ = Tune{};
    report_tune(done, StatusCode::DriverResultUnknown, runtime_->now_ms());
    return;
  }
  if (result.outcome == OperationOutcome::Pending) return;
  const Tune done = tune_;
  tune_ = Tune{};
  switch (result.outcome) {
    case OperationOutcome::Applied:
      report_tune(done, StatusCode::Ok, runtime_->now_ms());
      break;
    case OperationOutcome::Rejected:
      report_tune(done, StatusCode::AuthorizationFailed, runtime_->now_ms());
      break;
    case OperationOutcome::Failed:
      report_tune(done, StatusCode::RadioFailure, runtime_->now_ms());
      break;
    case OperationOutcome::Indeterminate:
    case OperationOutcome::Pending:
      report_tune(done, StatusCode::DriverResultUnknown, runtime_->now_ms());
      break;
  }
}

void EspNowSecurityOwner::report_tune(const Tune& tune, const StatusCode result_code,
                                      const MonotonicMs now_ms) noexcept {
  StatusCode reported = result_code;
  if (tune.coord_token == 0) {
    // The ApplyMemberConfig channel move: start the node, then report
    // the firmware's apply-time ChannelReady. On a failed move with
    // retries left, re-request instead of reporting.
    if (reported == StatusCode::Ok && runtime_->committed_channel() != tune.channel) {
      reported = StatusCode::RadioFailure;
    }
    if (reported != StatusCode::Ok && apply_retries_ > 0 && apply_channel_ != 0) {
      --apply_retries_;
      const Status retry = request_cutover(apply_channel_, 0, now_ms);
      if (retry) return;
      ESP_LOGW(config_.log_tag, "member channel retry failed: %s", retry.detail);
    }
    apply_retries_ = 0;
    apply_channel_ = 0;
    if (reported == StatusCode::Ok && !runtime_->node().started()) {
      // A same-config re-apply only moved the radio: the node is already
      // running and a second start would fail for no gain.
      const Status started = runtime_->start();
      if (!started) {
        ESP_LOGE(config_.log_tag, "member node start failed: %s", started.detail);
        reported = started.code;
      }
    }
  }
  // Report reality, not the request: the coordinator gates RLD1 on the
  // observed (channel, generation), so a failed move must not claim the
  // target.
  sdkv1::CoordinatorEvent ready{};
  ready.kind = sdkv1::CoordinatorEventKind::ChannelReady;
  ready.now = now_ms;
  ready.channel_token = tune.coord_token;
  ready.channel_result = reported;
  ready.channel = runtime_->committed_channel();
  ready.channel_generation = runtime_->radio_generation().value;
  (void)coordinator().step(ready);
}

Status EspNowSecurityOwner::request_cutover(const std::uint8_t channel,
                                            const std::uint32_t coord_token,
                                            const MonotonicMs now_ms) noexcept {
  RadioOperation op{};
  op.kind = RadioOperationKind::ChannelCutover;
  op.deadline_ms = now_ms + kTuneDeadlineMs;
  op.constraints.channel = channel;
  op.constraints.outage_permitted = true;
  const OperationToken token = runtime_->request_radio_operation(op);
  if (token == kInvalidOperationToken) {
    return Status::error(StatusCode::RadioFailure, "cutover not accepted");
  }
  tune_.coord_token = coord_token;
  tune_.op = token;
  tune_.channel = channel;
  tune_.active = true;
  return Status::success();
}

}  // namespace routeloom::espnow
