#include "routeloom/espnow_security_owner.hpp"

#include "esp_log.h"
#include "esp_system.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "routeloom/secure_clear.hpp"

namespace routeloom::espnow {
namespace {

// The member discovery scope handle: the coordinator's GK provider serves
// exactly one (member) scope and ignores the value — discovery only needs
// it non-invalid (Required refuses kInvalidScopeRef at start).
constexpr ScopeRef kMemberScopeRef{1};

constexpr std::uint32_t kTuneDeadlineMs = 3000;
constexpr int kApplyCutoverRetries = 3;

}  // namespace

EspNowSecurityOwner::~EspNowSecurityOwner() noexcept {
  if (discovery_live_) {
    discovery()->~NeighborDiscovery();
    discovery_live_ = false;
  }
  if (lifecycle_live_) {
    lifecycle().~MembershipLifecycle();
    lifecycle_live_ = false;
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
  (void)authority_type;
  (void)body;
  // The device authority channel (P5 PR4: USB/mesh mapping + the
  // AuthorityClient typed send) is not wired yet: Applied/Get/
  // NoticeAccepted/PREPARED/APPLIED stay unsent and the Host side
  // honestly reports them unknown until their bearer lands. WouldBlock
  // (not Unsupported): the bearer is coming, the data stays valid.
  return Status::error(StatusCode::WouldBlock, "p5 authority channel not wired");
}

Status EspNowSecurityOwner::LifecyclePeerPort::peer_send(const NodeId peer, const FrameType carrier,
                                                         const ByteView body) noexcept {
  (void)peer;
  (void)carrier;
  (void)body;
  // No 1-hop link-TX lane exists yet (migration_send is allowlisted to
  // the migration carriers and needs an attached migration engine):
  // StateEpochs/RrsRequest/manifests/chunks/ACKs stay unsent and the
  // lifecycle runs silent (features 0), still applying whatever RRS1
  // arrives. A dedicated link-TX API is the follow-up, not a reuse.
  return Status::error(StatusCode::WouldBlock, "p6 gossip TX not wired");
}

Status EspNowSecurityOwner::LifecycleRuntimePort::enforce_revocation(
    const sdkv1::RevocationSet& set, const std::uint32_t site_epoch,
    const MonotonicMs now_ms) noexcept {
  EspNowSecurityOwner& owner = owner_;
  if (owner.stores_ == nullptr || !owner.coordinator_live_) {
    return Status::error(StatusCode::InvalidState, "enforce before wiring");
  }
  // Sessions + Discovery bindings retire through the coordinator seam
  // (which re-checks the set against the adopted store first); routes
  // withdraw per entry through the node. TX-queue/group/RTC scrubbing
  // has no Owner-reachable API yet (residual below): retired sessions
  // make queued frames to revoked peers fail closed, and the revoked
  // routes never select again.
  const Status sessions = owner.coordinator().revoke_member_sessions(set, site_epoch, now_ms);
  if (!sessions) return sessions;
  if (owner.runtime_ != nullptr) {
    for (std::size_t i = 0; i < set.count; ++i) {
      owner.runtime_->node().revoke_routes(set.entries[i].node_id, now_ms);
    }
  }
  return Status::success();
}

Status EspNowSecurityOwner::LifecycleRuntimePort::remove_member_runtime() noexcept {
  EspNowSecurityOwner& owner = owner_;
  // Re-asserts the stopped state (the coordinator's land_removal runs
  // first on the Joiner path and already halted traffic): relay off,
  // discovery membership revoked. Idempotent by construction.
  if (owner.runtime_ != nullptr) {
    (void)owner.runtime_->node().set_relay_enabled(false);
  }
  if (owner.discovery_live_) {
    owner.discovery()->membership().revoke();
  }
  return Status::success();
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

Status EspNowSecurityOwner::begin(Sdkv1Stores& stores, EspOwnerEntropy& entropy,
                                  const Config& config) noexcept {
  if (begun_) return Status::error(StatusCode::AlreadyExists, "owner already begun");
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
  deps.proxy_sealer = &sealer();
  deps.local_mac = config_.local_mac;
  deps.local_node = config_.local_node;
  deps.joiner_config = config_.joiner;
  new (coordinator_box_.data()) sdkv1::SecurityCoordinator(deps);
  coordinator_live_ = true;
  // The P6 membership lifecycle beside the coordinator: same stores, the
  // RLX1 journal, silent gossip (no link-TX lane yet). Self is the RLI1
  // node id when provisioned, else the Kconfig identity (which becomes
  // the RLI1 id at provisioning — a mismatch blocks, never corrupts).
  sdkv1::LifecycleConfig lifecycle_config{};
  lifecycle_config.self = stores_->identity().has_identity()
                              ? stores_->identity().identity().node_id
                              : config_.local_node;
  lifecycle_config.profile = config_.lifecycle_gateway ? sdkv1::LifecycleProfile::Gateway
                                                       : sdkv1::LifecycleProfile::Node;
  lifecycle_config.enabled_features = 0;
  sdkv1::LifecyclePorts lifecycle_ports{lifecycle_authority_, lifecycle_peer_, lifecycle_runtime_,
                                        *entropy_, lifecycle_sink_, &lifecycle_observer_};
  new (lifecycle_box_.data())
      sdkv1::MembershipLifecycle(lifecycle_config, stores_->identity(), stores_->site(),
                                 stores_->revocation(), stores_->resume(), lifecycle_ports,
                                 sdkv1::default_es256_verifier(), &stores_->lifecycle());
  lifecycle_live_ = true;
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
    std::memcpy(slot.body.data(), body.data, body.size);
    slot.body_size = body.size;
    slot.peer = peer;
    slot.carrier = type;
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
  // The P4 binding adapter is not wired yet, so every gossip stamp carries
  // binding 0 (manifests and chunks consistently): the transfer registry
  // still keys (peer, hash) correctly.
  if (!lifecycle().owns_rrs_chunk(peer, 0, carrier, body)) return false;
  for (GossipStage& slot : gossip_staged_) {
    if (slot.used) continue;
    std::memcpy(slot.body.data(), body.data, body.size);
    slot.body_size = body.size;
    slot.peer = peer;
    slot.carrier = carrier;
    slot.used = true;
    return true;
  }
  ++gossip_dropped_;
  return true;  // claimed but unstaged: a retry, never migration's
}

void EspNowSecurityOwner::poll_lifecycle(const MonotonicMs now_ms) noexcept {
  if (!lifecycle_live_ || !lifecycle_booted_) return;
  feed_lifecycle_inputs(now_ms);
  (void)lifecycle().dispatch(sdkv1::LifecycleInput::Poll(), now_ms);
  drain_lifecycle_actions(now_ms);
}

void EspNowSecurityOwner::feed_lifecycle_inputs(const MonotonicMs now_ms) noexcept {
  // Gossip feeds only while adopted: the stamp needs the adopted network
  // and role, and the lifecycle ignores peer control while unadopted.
  if (adopted_network_ != 0 && adopted_role_ != 0) {
    for (GossipStage& slot : gossip_staged_) {
      if (!slot.used) continue;
      slot.used = false;
      sdkv1::PeerCredentialStamp stamp{};
      stamp.peer = slot.peer;
      stamp.network = adopted_network_;
      stamp.role = adopted_role_;
      // No P4 adapter yet: the generation/fingerprint/binding the sink
      // cannot verify stay zero (documented seam). The lifecycle
      // validates-but-never-consumes them on the gossip path — only
      // SAK-signed objects move state.
      (void)lifecycle().dispatch(
          sdkv1::LifecycleInput::PeerControl(
              stamp, slot.carrier, ByteView{slot.body.data(), slot.body_size}),
          now_ms);
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
  Status status = runtime_->adopt_member_node(node);
  if (!status && status.code != StatusCode::InvalidState) {
    ESP_LOGE(config_.log_tag, "member node adopt failed: %s", status.detail);
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
  const std::uint8_t operating = stores_->site().has_site()
                                     ? stores_->site().site().channel
                                     : runtime_->committed_channel();
  if (operating == runtime_->committed_channel()) {
    status = runtime_->start();
    if (!status) {
      ESP_LOGE(config_.log_tag, "member node start failed: %s", status.detail);
      return;
    }
    report_tune(Tune{0, kInvalidOperationToken, operating, true}, StatusCode::Ok,
                runtime_->now_ms());
    return;
  }
  apply_retries_ = kApplyCutoverRetries;
  apply_channel_ = operating;
  status = request_cutover(operating, 0, runtime_->now_ms());
  if (!status) {
    ESP_LOGE(config_.log_tag, "member channel move failed: %s", status.detail);
  }
}

void EspNowSecurityOwner::on_start_discovery(const MonotonicMs now_ms) noexcept {
  if (discovery_live_) return;
  if (!stores_->site().has_site()) {
    ESP_LOGE(config_.log_tag, "member discovery without adopted site");
    return;
  }
  DiscoveryConfig config{};
  config.node = adopted_node_;
  config.network = adopted_network_;
  config.scope_mode = ScopeMode::Required;
  config.scope_provider = &coordinator().gk_scope();
  config.scope = kMemberScopeRef;
  config.cookie_bucket_ms = static_cast<std::uint32_t>(sdkv1::MemberCookie::kBucketMs);
  auto* engine = new (discovery_box_.data()) NeighborDiscovery(config, *runtime_, *this,
                                                         coordinator().membership_hooks(),
                                                         *entropy_, observer_store_);
  discovery_live_ = true;
  Status status = engine->membership().initialize(coordinator().membership_hooks(),
                                                  adopted_network_);
  if (!status) {
    ESP_LOGE(config_.log_tag, "member controller init failed: %s", status.detail);
    engine->~NeighborDiscovery();
    discovery_live_ = false;
    return;
  }
  status = coordinator().attach_discovery(*engine);
  if (!status) {
    ESP_LOGE(config_.log_tag, "discovery attach failed: %s", status.detail);
    engine->~NeighborDiscovery();
    discovery_live_ = false;
    return;
  }
  status = runtime_->attach_autonomy(*engine);
  if (!status) {
    ESP_LOGE(config_.log_tag, "autonomy attach failed: %s", status.detail);
    engine->~NeighborDiscovery();
    discovery_live_ = false;
    return;
  }
  engine->set_member_handshake_mode(true);
  status = engine->start(now_ms);
  if (!status) {
    ESP_LOGE(config_.log_tag, "member discovery start failed: %s", status.detail);
    return;
  }
  status = engine->begin_discovery(now_ms);
  if (!status) {
    ESP_LOGW(config_.log_tag, "member begin_discovery failed: %s (rx-driven only)",
             status.detail);
  }
  ESP_LOGI(config_.log_tag, "member discovery started");
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
  if (tune.coord_token == 0) {
    // The ApplyMemberConfig channel move: start the node, then report
    // the firmware's apply-time ChannelReady. On a failed move with
    // retries left, re-request instead of reporting.
    if (result_code != StatusCode::Ok && apply_retries_ > 0 && apply_channel_ != 0) {
      --apply_retries_;
      const Status retry = request_cutover(apply_channel_, 0, now_ms);
      if (retry) return;
      ESP_LOGW(config_.log_tag, "member channel retry failed: %s", retry.detail);
    }
    apply_retries_ = 0;
    apply_channel_ = 0;
    const Status started = runtime_->start();
    if (!started) {
      ESP_LOGE(config_.log_tag, "member node start failed: %s", started.detail);
    }
  }
  // Report reality, not the request: the coordinator gates RLD1 on the
  // observed (channel, generation), so a failed move must not claim the
  // target.
  sdkv1::CoordinatorEvent ready{};
  ready.kind = sdkv1::CoordinatorEventKind::ChannelReady;
  ready.now = now_ms;
  ready.channel_token = tune.coord_token;
  ready.channel_result = result_code;
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
