#include "routeloom/espnow_security_owner.hpp"

#include "esp_attr.h"
#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "routeloom/secure_clear.hpp"

namespace routeloom::espnow {

// The P6 lifecycle is CPU-only state. Member builds with RTC capacity keep
// it outside the main radio/USB SRAM bank.
#if CONFIG_IDF_TARGET_ESP32C3 || CONFIG_IDF_TARGET_ESP32S3 || \
    (CONFIG_IDF_TARGET_ESP32C5 && defined(ROUTELOOM_REFERENCE_IMAGE))
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
    if (config_.gateway) {
      mesh_sink()->~AuthorityMeshSink();
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
  // The P4 bank, pending handshakes and Discovery bindings retire before
  // any durable resume sweep. The route withdrawal also closes queued
  // sends to revoked peers.
  const Status sessions = owner.coordinator().revoke_member_sessions(set, site_epoch, now_ms);
  if (!sessions) return sessions;
  if (owner.runtime_ != nullptr) {
    for (std::size_t i = 0; i < set.count; ++i) {
      owner.runtime_->node().revoke_routes(set.entries[i].node_id, now_ms);
    }
  }
  if (owner.p4_sweep_network_ != set.network || owner.p4_sweep_rs_epoch_ != set.rs_epoch) {
    owner.p4_sweep_network_ = set.network;
    owner.p4_sweep_rs_epoch_ = set.rs_epoch;
    owner.p4_sweep_cursor_ = 0;
  }
  sdkv1::ResumeSlotStorage2& storage = owner.stores_->resume2();
  const bool gateway = storage.slot_count() ==
      sdkv1::kResume2GatewayLinkQuota + sdkv1::kResume2GatewayEndQuota;
  sdkv1::ResumeCache2 cache(storage,
                            gateway ? sdkv1::kResume2GatewayLinkQuota
                                    : sdkv1::kResume2NodeLinkQuota,
                            gateway ? sdkv1::kResume2GatewayEndQuota
                                    : sdkv1::kResume2NodeEndQuota);
  sdkv1::ResumeContext context{};
  context.network = set.network;
  context.revocations = &set;
  bool done = false;
  const Status swept = cache.sweep_revoked(context, owner.p4_sweep_cursor_, done);
  if (!swept) return swept;
  return done ? Status::success() : Status::error(StatusCode::WouldBlock, "p4 resume sweep");
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
  sdkv1::ResumeSlotStorage2& storage = owner.stores_->resume2();
  const bool gateway = storage.slot_count() ==
      sdkv1::kResume2GatewayLinkQuota + sdkv1::kResume2GatewayEndQuota;
  sdkv1::ResumeCache2 cache(storage,
                            gateway ? sdkv1::kResume2GatewayLinkQuota
                                    : sdkv1::kResume2NodeLinkQuota,
                            gateway ? sdkv1::kResume2GatewayEndQuota
                                    : sdkv1::kResume2NodeEndQuota);
  bool done = false;
  const Status cleared = cache.clear_step(owner.p4_clear_cursor_, done);
  if (!cleared) return cleared;
  return done ? Status::success() : Status::error(StatusCode::WouldBlock, "p4 resume clear");
}

Status EspNowSecurityOwner::LifecycleRuntimePort::erase_site_trust() noexcept {
  EspNowSecurityOwner& owner = owner_;
  if (!owner.coordinator_live_) {
    return Status::error(StatusCode::InvalidState, "trust erasure before wiring");
  }
  // The site trust on this path is the RLS1 SiteCert verified against
  // the RLI1 anchors (no separate derived blobs exist in production):
  // RLS1 itself is erased by the lifecycle's Site step next, RLI1 stays
  // (device-level per 04 §6.4), and this step wipes the RAM view (GK
  // scope + discovery membership) and verifies it is gone.
  return owner.coordinator().wipe_site_trust();
}

Status EspNowSecurityOwner::LifecycleRuntimePort::retire_network() noexcept {
  // Cutover retirement: member traffic halts like a removal, but the
  // stores (old + staged site) stay for the switch to commit.
  return remove_member_runtime();
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
  (void)now_ms;
  EspNowSecurityOwner& owner = owner_;
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

NeighborDiscovery* EspNowSecurityOwner::discovery() noexcept {
  if (!discovery_live_) return nullptr;
  return reinterpret_cast<NeighborDiscovery*>(discovery_box_.data());
}

MeshConfigPort* EspNowSecurityOwner::mesh_port() noexcept {
  if (!authority_live_) return nullptr;
  return reinterpret_cast<MeshConfigPort*>(mesh_port_box_.data());
}

sdkv1::AuthorityEndpoint* EspNowSecurityOwner::endpoint() noexcept {
  if (!authority_live_ || config_.gateway) return nullptr;
  return reinterpret_cast<sdkv1::AuthorityEndpoint*>(transport_box_.endpoint.data());
}

sdkv1::AuthorityGateway* EspNowSecurityOwner::gateway() noexcept {
  if (!authority_live_ || !config_.gateway) return nullptr;
  return reinterpret_cast<sdkv1::AuthorityGateway*>(transport_box_.gateway.data());
}

sdkv1::AuthorityMeshSink* EspNowSecurityOwner::mesh_sink() noexcept {
  if (!authority_live_ || !config_.gateway) return nullptr;
  return reinterpret_cast<sdkv1::AuthorityMeshSink*>(mesh_sink_box_.data());
}

NodeId EspNowSecurityOwner::self_node() const noexcept {
  return adopted_node_ != kInvalidNodeId ? adopted_node_ : config_.local_node;
}

sdkv1::AuthorityMeshDemux* EspNowSecurityOwner::authority_demux() noexcept {
  if (!authority_live_) return nullptr;
  return config_.gateway ? static_cast<sdkv1::AuthorityMeshDemux*>(gateway())
                         : static_cast<sdkv1::AuthorityMeshDemux*>(endpoint());
}

ConfigEndpointSink* EspNowSecurityOwner::authority_mesh_sink() noexcept {
  return mesh_sink();
}

Status EspNowSecurityOwner::begin(Sdkv1Stores& stores, EspOwnerEntropy& entropy,
                                  const Config& config) noexcept {
  if (begun_) return Status::error(StatusCode::AlreadyExists, "owner already begun");
  if (lifecycle_box_in_use_)
    return Status::error(StatusCode::Busy, "lifecycle owner already active");
  if (config.local_node == kInvalidNodeId || config.local_node == kBroadcastNodeId ||
      config.local_mac == routeloom::MacAddress{}) {
    return Status::error(StatusCode::InvalidArgument, "owner identity");
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
  deps.entropy = entropy_;
  deps.rld1 = this;
  deps.mesh = this;
  deps.usb = this;
  deps.verifier = &verifier();
  deps.bank_aead = psa_session_aead_gcm();
  deps.crypto_aead = *psa_aead_gcm();
  deps.proxy_sealer = &sealer();
  deps.authority_sink = this;
  deps.local_mac = config_.local_mac;
  deps.local_node = config_.local_node;
  deps.joiner_config = config_.joiner;
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
  lifecycle_config.profile = config_.gateway ? sdkv1::LifecycleProfile::Gateway
                                                       : sdkv1::LifecycleProfile::Node;
  lifecycle_config.enabled_features = kCapRrsGossipV1;
  sdkv1::LifecyclePorts lifecycle_ports{lifecycle_authority_, lifecycle_peer_, lifecycle_runtime_,
                                        *entropy_, lifecycle_sink_, &lifecycle_observer_};
  new (lifecycle_box_.data())
      sdkv1::MembershipLifecycle(lifecycle_config, stores_->identity(), stores_->site(),
                                 stores_->revocation(), stores_->resume(), lifecycle_ports,
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
  const Status lifecycle_boot =
      lifecycle().dispatch(sdkv1::LifecycleInput::Boot(rlboot_prepared), now_ms);
  if (!lifecycle_boot) return lifecycle_boot;
  lifecycle_booted_ = true;
  const sdkv1::LifecycleSnapshot boot_snap = lifecycle().snapshot();
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
  if (config_.gateway && bridge_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "gateway without usb bridge");
  }
  new (mesh_port_box_.data()) MeshConfigPort(runtime_->node());
  authority_live_ = true;  // the accessors below (and the dtor) go live here
  if (config_.gateway) {
    new (transport_box_.gateway.data())
        sdkv1::AuthorityGateway(*mesh_port(), *this, *this, config_.local_node);
    new (mesh_sink_box_.data()) sdkv1::AuthorityMeshSink(*gateway());
    direct_port_.bind(this);
    Status authority_status = coordinator().attach_authority_port(direct_port_);
    if (!authority_status) return authority_status;
    authority_status = bridge_->attach_authority(*this);
    if (!authority_status) return authority_status;
  } else {
    new (transport_box_.endpoint.data())
        sdkv1::AuthorityEndpoint(*mesh_port(), config_.local_node);
    const Status authority_status = coordinator().attach_authority_port(*endpoint());
    if (!authority_status) return authority_status;
  }
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Boot;
  event.now = now_ms;
  event.boot_witness = rlboot_witness;
  event.boot_prepared = rlboot_prepared;
  event.usb_direct = usb_direct;
  const Status status = coordinator().step(event);
  if (!status) return status;
  boot_witness_ = rlboot_witness;
  booted_ = true;
  ESP_LOGI(config_.log_tag, "booted (%s)", usb_direct ? "usb-direct" : "radio");
  return Status::success();
}

void EspNowSecurityOwner::poll(const MonotonicMs now_ms) noexcept {
  if (!booted_) return;
  poll_lifecycle(now_ms);
  if (removal_pending_) return;  // erasure owns the device until the reboot
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Poll;
  event.now = now_ms;
  (void)coordinator().step(event);
  drive_authority(now_ms);
  poll_tune(now_ms);
  drain_actions(now_ms);
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
}

void EspNowSecurityOwner::sync_lifecycle_peers(const MonotonicMs now_ms) noexcept {
  if (runtime_ == nullptr || !coordinator_live_ || adopted_network_ == 0) return;
  std::array<NodeId, EspNowRuntime::kPeerCapacity> current{};
  std::size_t count = 0;
  runtime_->for_each_peer([&](const NodeId peer, const MacAddress&,
                              const RouteMetric, const bool) noexcept {
    if (peer == self_node() || count >= current.size()) return;
    std::uint32_t generation = 0, role = 0;
    if (!coordinator().authenticated_link(peer, adopted_network_, generation, role) ||
        role == 0 || role > 0xFF) return;
    std::uint32_t binding = 0;
    if (!runtime_->p6_link_binding(peer, binding)) return;
    sdkv1::PeerCredentialStamp stamp{};
    stamp.peer = peer;
    stamp.network = adopted_network_;
    stamp.assignment_generation = generation;
    stamp.role = static_cast<std::uint8_t>(role);
    stamp.binding_incarnation = binding;
    (void)lifecycle().dispatch(sdkv1::LifecycleInput::PeerBound(stamp), now_ms);
    current[count++] = peer;
  });
  for (const NodeId prior : lifecycle_peers_) {
    if (prior == kInvalidNodeId) continue;
    bool still_bound = false;
    for (std::size_t i = 0; i < count; ++i) {
      if (current[i] == prior) { still_bound = true; break; }
    }
    if (!still_bound) {
      (void)lifecycle().dispatch(sdkv1::LifecycleInput::PeerGone(prior), now_ms);
    }
  }
  lifecycle_peers_ = current;
}

void EspNowSecurityOwner::on_verified_authority(const std::uint8_t type,
                                                const ByteView plaintext) noexcept {
  if (type < 5 || type > 7 || plaintext.data == nullptr ||
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

void EspNowSecurityOwner::drain_authority_tx(const MonotonicMs now_ms) noexcept {
  for (AuthorityTxStage& slot : authority_tx_staged_) {
    if (!slot.used) continue;
    const Status sent = coordinator().send_authority_typed(
        slot.type, ByteView{slot.body.data(), slot.size}, now_ms);
    if (!sent) {
      if (sent.code != StatusCode::Busy) {
        secure_clear(slot.body);
        slot = AuthorityTxStage{};
      }
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
        (void)lifecycle().dispatch(
            sdkv1::LifecycleInput::Authority(
                stamp, slot.type,
                ByteView{slot.body.data() + sdkv1::kAuthorityBodyHeadSize,
                         slot.size - sdkv1::kAuthorityBodyHeadSize}),
            now_ms);
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
        ESP_LOGW(config_.log_tag, "p6: removal holdoff done — rebooting unassigned");
        reboot_for_lifecycle("p6 restart-unassigned");
        break;
      case sdkv1::LifecycleActionTag::AdoptNetwork:
        if (stores_ == nullptr ||
            stores_->site().commit_seq() != action.expected_site_commit_seq) {
          // The stores moved under the decision: the action stays pending
          // and retries next poll instead of adopting a stale switch.
          ESP_LOGW(config_.log_tag, "p6: adopt raced a store commit — retaking");
          break;
        }
        ESP_LOGW(config_.log_tag, "p6: adopting network 0x%llx — rebooting",
                 static_cast<unsigned long long>(action.network));
        reboot_for_lifecycle("p6 adopt-network");
        break;
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

[[noreturn]] void EspNowSecurityOwner::reboot_for_lifecycle(const char* reason) noexcept {
  ESP_LOGE(config_.log_tag, "p6: %s (clean reboot, not a fault)", reason);
  vTaskDelay(pdMS_TO_TICKS(100));  // let the line reach the UART
  esp_restart();
  for (;;) {
  }  // unreachable: esp_restart never returns
}

void EspNowSecurityOwner::drive_authority(const MonotonicMs now_ms) noexcept {
  if (!authority_live_) return;
  if (config_.gateway) {
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
  if (bridge_ != nullptr) {
    const bool active = bridge_->state() == usb::SessionState::Active;
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

Status EspNowSecurityOwner::prepare_sleep(const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  // Drain first: a pending action (tune/member/discovery) is owed work,
  // not sleep permission. The coordinator re-checks the slot anyway.
  poll_tune(now_ms);
  drain_actions(now_ms);
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::PrepareSleep;
  event.now = now_ms;
  return coordinator().step(event);
}

Status EspNowSecurityOwner::wake(const MonotonicMs now_ms) noexcept {
  if (!booted_) return Status::error(StatusCode::InvalidState, "owner not booted");
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::Wake;
  event.now = now_ms;
  return coordinator().step(event);
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
  if (to_proxy == self) {
    // LocalJoin (§8.2): exact match only — Down to self, our relay id,
    // our radio MAC. Anything else is refused, never forwarded.
    const sdkv1::RelayHeader& header = object.header;
    if (header.dir != sdkv1::RelayDirection::Down || header.proxy != self ||
        !sdkv1::local_join_token_matches(sdkv1::relay_token_of(header),
                                         boot_witness_, local_join_relay_id_) ||
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
  if (!booted_ || !authority_live_ || !config_.gateway) {
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
  if (!booted_ || !authority_live_ || !config_.gateway) {
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
  if (authority_live_ && config_.gateway) gateway()->drop_all();
  if (!booted_) return;
  sdkv1::CoordinatorEvent event{};
  event.kind = sdkv1::CoordinatorEventKind::UsbSessionDown;
  event.now = now_ms;
  (void)coordinator().step(event);
}

bool EspNowSecurityOwner::send_up(const usb::AuthorityFragment& fragment) noexcept {
  if (bridge_ == nullptr) return false;
  return bridge_->send_authority_up(fragment).ok();
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
  if (owner_ == nullptr || owner_->bridge_ == nullptr) return false;
  if (owner_->bridge_->state() != usb::SessionState::Active) return false;
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
    if (!owner_->bridge_->send_authority_up(fragment)) return false;
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
  return runtime_->node().send_bootstrap(destination, type, payload, lifetime_ms, now_ms, id);
}

Status EspNowSecurityOwner::send_local_join_up(const sdkv1::JoinAuthPhase phase,
                                               const std::uint8_t step,
                                               const ByteView message) noexcept {
  if (bridge_ == nullptr) {
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
  return bridge_->relay_up(self, 0, ByteView{encoded.data(), written});
}

Status EspNowSecurityOwner::send_relay_up_to_host(const NodeId proxy, const std::uint8_t hops,
                                                  const ByteView object) noexcept {
  if (bridge_ == nullptr) {
    // No host: the gateway engine sheds with authority_unreachable.
    return Status::error(StatusCode::InvalidState, "usb not attached");
  }
  return bridge_->relay_up(proxy, hops, object);
}

Status EspNowSecurityOwner::send_relay_abort_to_host(
    const NodeId proxy, const sdkv1::RelayToken token,
    const sdkv1::RelayAbortReason reason) noexcept {
  if (bridge_ == nullptr) {
    return Status::error(StatusCode::InvalidState, "usb not attached");
  }
  return bridge_->relay_abort(proxy, token, reason);
}

SecurityProfile EspNowSecurityOwner::security_profile() const noexcept {
  // EXPERIMENTAL until P8 declares production (§15): the node surfaces
  // SECURITY_PROFILE_EXPERIMENTAL and nothing claims production status.
  return SecurityProfile::Development;
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
  adopted_node_ = member.node;
  adopted_network_ = member.network;
  adopted_role_ = member.role;
  // The adoption re-proves the stores for the lifecycle (first adopt and
  // every recovery re-adopt): the RLS1 commit_seq the coordinator saw,
  // with no package fetch target yet (a P4 adapter handoff to come —
  // acquisition meanwhile runs off the stored set plus gossip).
  if (lifecycle_live_ && lifecycle_booted_ && stores_ != nullptr) {
    (void)lifecycle().dispatch(
        sdkv1::LifecycleInput::MemberReady(stores_->site().commit_seq(), 0), now_ms);
    complete_lifecycle_recovery(true, now_ms);
  }
  // Adoption binds the authority transport's self id (self-downs deliver
  // locally and self-addressed mesh sends refuse from here on).
  if (authority_live_) {
    if (config_.gateway) {
      gateway()->set_self(member.node);
    } else {
      endpoint()->set_self(member.node);
    }
  }
  NodeConfig node = runtime_->node().config();
  node.network = member.network;
  node.node = member.node;
  node.message_session = member.message_session;
  node.boot_session = member.boot_session;
  node.link_epoch = member.link_epoch;
  node.end_epoch = member.end_epoch;
  node.boot_incarnation = member.boot_incarnation;
  node.route_gateways.fill(kInvalidNodeId);
  for (std::size_t i = 0; i < member.route_gateway_count && i < node.route_gateways.size(); ++i) {
    node.route_gateways[i] = member.route_gateways[i];
  }
  const std::uint8_t operating = stores_->site().has_site()
                                     ? stores_->site().site().channel
                                     : runtime_->committed_channel();
  Status status = runtime_->adopt_member_node(node);
  if (!status && status.code != StatusCode::InvalidState) {
    ESP_LOGE(config_.log_tag, "member node adopt failed: %s", status.detail);
    report_tune(Tune{0, kInvalidOperationToken, operating, true},
                StatusCode::RadioFailure, runtime_->now_ms());
    return;
  }
  // The gossip sink rides the member node: a fresh adopt placement-news
  // the node (install), a recovery re-adopt refuses the rebuild (the
  // running node already matches — re-assert and return). Idempotent
  // either way; without it P6 frames honestly reject.
  (void)runtime_->node().set_rrs_sink(this);
  if (!status) return;
  runtime_->node().set_bootstrap_sink(&coordinator());
  // Relay duties are role-gated (unknown role 0 never transits).
  runtime_->node().set_relay_enabled(member.role != 0);
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
  if (discovery_live_) return;
  if (!stores_->site().has_site()) {
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
    ESP_LOGE(config_.log_tag, "member discovery start failed: %s", status.detail);
    abort_discovery_start(now_ms, false);
    return;
  }
  status = coordinator().attach_discovery(*engine);
  if (!status) {
    ESP_LOGE(config_.log_tag, "discovery attach failed: %s", status.detail);
    abort_discovery_start(now_ms, false);
    return;
  }
  status = runtime_->attach_autonomy(*engine);
  if (!status) {
    ESP_LOGE(config_.log_tag, "autonomy attach failed: %s", status.detail);
    abort_discovery_start(now_ms, true);
    return;
  }
  engine->set_member_handshake_mode(true);
  status = engine->begin_discovery(now_ms);
  if (!status) {
    ESP_LOGE(config_.log_tag, "member begin_discovery failed: %s", status.detail);
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
    if (reported == StatusCode::Ok) {
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
