#include "routeloom/sdkv1_security_coordinator.hpp"

#include <cassert>
#include <cstring>
#include <new>

#include "routeloom/discovery_scope.hpp"  // hmac_sha256
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_ead.hpp"  // join_org_hint/join_site_hint
#include "routeloom/sdkv1_session_wire.hpp"  // own RLD1 capability word
#include "routeloom/secure_clear.hpp"

namespace routeloom::sdkv1 {
namespace {

bool deps_ready(const SecurityCoordinator::Deps& deps) noexcept {
  // Discovery stays nullable: it attaches late (adoption precedes
  // discovery start) — every discovery use below guards for null.
  return deps.identity != nullptr && deps.site != nullptr && deps.revocations != nullptr &&
         deps.local_revocation != nullptr && deps.resume_storage != nullptr &&
         deps.entropy != nullptr &&
         deps.rld1 != nullptr && deps.mesh != nullptr && deps.usb != nullptr &&
         deps.verifier != nullptr && deps.proxy_sealer != nullptr &&
         deps.bank_aead.seal != nullptr && deps.bank_aead.open != nullptr &&
         deps.crypto_aead.seal != nullptr && deps.crypto_aead.open != nullptr &&
         deps.local_mac != MacAddress{} && deps.local_node != kInvalidNodeId &&
         deps.local_node != kBroadcastNodeId;
}

bool entropy_fill(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
  auto* entropy = static_cast<EntropySource*>(ctx);
  if (entropy == nullptr || out == nullptr) return false;
  return entropy->fill(MutableByteView{out, size}).ok();
}

void sat_inc(std::uint32_t& value) noexcept {
  if (value < 0xFFFFFFFFU) ++value;
}

}  // namespace

SecurityCoordinator::SecurityCoordinator(const Deps& deps) noexcept
    : deps_(deps),
      hooks_(*deps.identity, *deps.site, *deps.revocations, *deps.local_revocation, this, this),
      bank_sink_(bank_),
      pairwise_provider_(bank_),
      group_keys_(*deps_.site),
      group_provider_(group_keys_, pairwise_provider_, deps_.crypto_aead, deps_.local_node,
                      deps_.revocations),
      provider_mux_(pairwise_provider_, group_provider_),
      sleep_guard_(provider_mux_, pairwise_provider_),
      member_scope_(group_keys_, kMemberScopeRef) {
  // Fresh: no workspace side constructed, but the member small side is
  // (the channel view works from construction).
  // Boot builds the Joiner, the adoption swaps it for the member engine;
  // the adoption also starts the GK state and wants the authority channel.
  create_small();
  authority_env_.bind(deps_.entropy);
  if (deps_.sleep_image != nullptr) {
    secure_clear(deps_.sleep_image, sizeof(*deps_.sleep_image));
  }
}

SecurityCoordinator::~SecurityCoordinator() noexcept {
  if (mode_ == CoordinatorMode::Dev) {
    destroy_dev();
  } else {
    destroy_small();
  }
  destroy_workspace();
  if (deps_.sleep_image != nullptr) {
    secure_clear(deps_.sleep_image, sizeof(*deps_.sleep_image));
  }
}

SecurityCoordinator::MemberSmallSide::MemberSmallSide(
    const routeloom::AeadGcm& aead, AuthorityPort& port, AuthorityObserver& observer,
    rlres1::Environment& rlres1_env, GroupKeyState* group) noexcept
    : authority(aead, port, observer, rlres1_env, group) {}

SecurityCoordinator::DevSide::DevSide(const RevocationStore& revocations,
                                       const LocalRevocationStore& local_revocation,
                                       const AuthenticatedPeerView* peers) noexcept
    : hooks(revocations, local_revocation, peers) {}

SecurityCoordinator::DevSide::~DevSide() noexcept {
  if (group_live) {
    group().DevGroupProvider::~DevGroupProvider();
    group_live = false;
  }
  sender.clear();
  scope.wipe();
  hooks.wipe();
}

DevGroupProvider& SecurityCoordinator::DevSide::group() noexcept {
  return *reinterpret_cast<DevGroupProvider*>(group_box.data());
}

void SecurityCoordinator::destroy_small() noexcept {
  sides_.small.~MemberSmallSide();
  secure_clear(&sides_, sizeof(sides_));
}

void SecurityCoordinator::create_small() noexcept {
  new (&sides_.small) MemberSmallSide(deps_.crypto_aead, authority_port_, *this, authority_env_,
                                      &group_keys_);
}

void SecurityCoordinator::create_dev() noexcept {
  new (&sides_.dev)
      DevSide(*deps_.revocations, *deps_.local_revocation, this);
}

void SecurityCoordinator::destroy_dev() noexcept {
  sides_.dev.~DevSide();
  secure_clear(&sides_, sizeof(sides_));
}

DevGroupProvider& SecurityCoordinator::dev_group() noexcept { return dev().group(); }

bool SecurityCoordinator::SessionProviderMux::ready() const noexcept {
  return pairwise_.ready() && group().ready();
}

SecurityProfile SecurityCoordinator::SessionProviderMux::security_profile() const noexcept {
  return group().security_profile();
}

Status SecurityCoordinator::SessionProviderMux::tx_epoch(const SecurityScope scope, const NodeId peer,
                                                         std::uint32_t& epoch) noexcept {
  return is_group(scope) ? group().tx_epoch(scope, peer, epoch)
                         : pairwise_.tx_epoch(scope, peer, epoch);
}

Status SecurityCoordinator::SessionProviderMux::current_rx_epoch(const SecurityScope scope,
                                                                 const NodeId peer,
                                                                 std::uint32_t& epoch) const
    noexcept {
  return is_group(scope) ? group().current_rx_epoch(scope, peer, epoch)
                         : pairwise_.current_rx_epoch(scope, peer, epoch);
}

ContextState SecurityCoordinator::SessionProviderMux::context_state(const SecurityScope scope,
                                                                    const NodeId peer) const
    noexcept {
  return is_group(scope) ? group().context_state(scope, peer)
                         : pairwise_.context_state(scope, peer);
}

Status SecurityCoordinator::SessionProviderMux::tx_group_link_epochs(std::uint32_t& boot,
                                                                     std::uint32_t& g) noexcept {
  return group().tx_group_link_epochs(boot, g);
}

bool SecurityCoordinator::SessionProviderMux::accepts_group_epoch(const std::uint32_t g) const
    noexcept {
  return group().accepts_group_epoch(g);
}

bool SecurityCoordinator::SessionProviderMux::group_promotion_pending() const noexcept {
  return group().group_promotion_pending();
}

Status SecurityCoordinator::SessionProviderMux::next_counter(const SecurityContext& context,
                                                             std::uint64_t& counter) noexcept {
  return is_group(context.scope) ? group().next_counter(context, counter)
                                 : pairwise_.next_counter(context, counter);
}

Status SecurityCoordinator::SessionProviderMux::seal(
    const SecurityContext& context, const std::uint64_t counter, const ByteView aad,
    const ByteView plaintext, const MutableByteView ciphertext,
    std::array<std::uint8_t, kAeadTagSize>& tag) noexcept {
  return is_group(context.scope)
             ? group().seal(context, counter, aad, plaintext, ciphertext, tag)
             : pairwise_.seal(context, counter, aad, plaintext, ciphertext, tag);
}

Status SecurityCoordinator::SessionProviderMux::open(
    const SecurityContext& context, const std::uint64_t counter, const ByteView aad,
    const ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
    const MutableByteView plaintext) noexcept {
  return is_group(context.scope)
             ? group().open(context, counter, aad, ciphertext, tag, plaintext)
             : pairwise_.open(context, counter, aad, ciphertext, tag, plaintext);
}

SecurityCoordinator::MemberEngine::MemberEngine(
    ResumeSlotStorage2& resume, GatewaySessionBank& bank, BankSessionSink<32, 128>& sink,
    HandshakeMembershipView& membership, SessionCredentialVerifier& verifier,
    EntropySource& entropy, ZtRld1Port& rld1, ZtRelayPort& relay, JoinCookieSealer& sealer,
    const JoinProxyConfig& proxy_config, const JoinRelayGatewayConfig& gateway_config) noexcept
    : resume_cache(resume,
                   resume.slot_count() == kResume2GatewayLinkQuota + kResume2GatewayEndQuota
                       ? kResume2GatewayLinkQuota : kResume2NodeLinkQuota,
                   resume.slot_count() == kResume2GatewayLinkQuota + kResume2GatewayEndQuota
                       ? kResume2GatewayEndQuota : kResume2NodeEndQuota),
      engine(resume_cache, sink, member_cookie, membership, verifier, &entropy_fill, &entropy),
      demands(bank, engine),
      proxy(proxy_config, rld1, relay, sealer, entropy),
      gateway(gateway_config, relay) {}

void SecurityCoordinator::destroy_workspace() noexcept {
  if (mode_ == CoordinatorMode::ZeroTouch) {
    ws_.joiner.~Joiner();
  } else if (has_member_engine()) {
    // The engine's cross-references (cookie, cache, sink) die with the
    // workspace; outside references (bank, stores, ports) stay valid.
    // The wipe below also clears demux cookies and slot bytes (and the
    // dev PSK dies with the dev-armed engine here).
    ws_.member.~MemberEngine();
  } else {
    return;
  }
  secure_clear(&ws_, sizeof(ws_));
}

void SecurityCoordinator::create_joiner() noexcept {
  new (&ws_.joiner) Joiner(deps_.joiner_config, *deps_.identity, *deps_.site, *deps_.entropy,
                           *deps_.rld1, joiner_observer_);
  ws_.joiner.set_commit_policy(this);
}

void SecurityCoordinator::create_member() noexcept {
  // Relay service identities (#116 §3.2): both incarnations are the
  // adopted rlboot witness — committed durable, nonzero, distinct per
  // boot. The hints come from the adopted stores (OFFERs must name this
  // site or joiners filter them out); a missing SiteCA anchor fails the
  // proxy closed (org_hint 0 → invalid) rather than naming another site.
  JoinProxyConfig proxy_config{};
  proxy_config.node = adopted_.node;
  proxy_config.mac = deps_.local_mac;
  proxy_config.network_low32 = static_cast<std::uint32_t>(adopted_.network);
  proxy_config.site_hint = join_site_hint(deps_.site->site().site_id);
  const IdentityRecord& identity = deps_.identity->identity();
  for (std::uint8_t i = 0; i < identity.anchor_count; ++i) {
    const IdentityAnchor& anchor = identity.anchors[i];
    if (anchor.kind == AnchorKind::SiteCa && anchor.status == AnchorStatus::Active) {
      proxy_config.org_hint = join_org_hint(anchor.pubkey);
      break;
    }
  }
  proxy_config.proxy_epoch = adopted_.boot_session;
  proxy_config.gateway = kInvalidNodeId;
  for (std::size_t i = 0; i < adopted_.route_gateway_count; ++i) {
    const NodeId candidate = adopted_.route_gateways[i];
    if (candidate != kInvalidNodeId && candidate != kBroadcastNodeId &&
        candidate != adopted_.node) {
      proxy_config.gateway = candidate;
      break;
    }
  }
  if (proxy_config.gateway == kInvalidNodeId || proxy_config.gateway == kBroadcastNodeId) {
    // No remote gateway (lone gateway site, or an empty list): relay to
    // the co-located engine through the direction-demuxed loopback. The
    // local engine answers unreachable_retry when hostless — the standard
    // #116 mechanism, and proxy diversity routes joins around us.
    proxy_config.gateway = adopted_.node;
    proxy_config.colocated_gateway = true;
  }
  JoinRelayGatewayConfig gateway_config{};
  gateway_config.node = adopted_.node;
  gateway_config.gateway_epoch = adopted_.boot_session;
  new (&ws_.member) MemberEngine(*deps_.resume_storage, bank_, bank_sink_, *this, *deps_.verifier,
                                 *deps_.entropy, *deps_.rld1, *this, *deps_.proxy_sealer,
                                 proxy_config, gateway_config);
  ws_.member.gateway.set_host_sink(this);
}

Status SecurityCoordinator::step(const CoordinatorEvent& event) noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
  if (mode_ != CoordinatorMode::Fresh && event.now < last_now_) {
    return Status::error(StatusCode::TimeUncertain, "coordinator clock regressed");
  }
  in_port_ = true;
  last_now_ = event.now;
  Status status = Status::success();
  switch (event.kind) {
    case CoordinatorEventKind::Boot:
      status = on_boot(event);
      break;
    case CoordinatorEventKind::Poll:
      status = on_poll(event.now);
      break;
    case CoordinatorEventKind::Rld1Rx:
      status = on_rld1_rx(event);
      break;
    case CoordinatorEventKind::UsbLocalDown:
    case CoordinatorEventKind::UsbRelayDown:
    case CoordinatorEventKind::UsbRelayAbort:
    case CoordinatorEventKind::UsbSessionDown:
      status = on_usb(event);
      break;
    case CoordinatorEventKind::UsbSessionUp:
      status = on_usb_session_up(event.now);
      break;
    case CoordinatorEventKind::AuthorityRx:
      status = on_authority_rx(event);
      break;
    case CoordinatorEventKind::AuthorityTx:
      status = on_authority_tx(event);
      break;
    case CoordinatorEventKind::RequestPull:
      status = on_request_pull(event);
      break;
    case CoordinatorEventKind::ChannelReady:
      status = on_channel_ready(event);
      break;
    case CoordinatorEventKind::PrepareSleep:
      status = on_prepare_sleep(event.now);
      break;
    case CoordinatorEventKind::Wake:
      status = on_wake(event.now);
      break;
    case CoordinatorEventKind::Stop:
      status = on_stop(event.now);
      break;
    case CoordinatorEventKind::StopForLifecycle:
      status = on_stop(event.now, true);
      break;
  }
  in_port_ = false;
  return status;
}

Status SecurityCoordinator::adopt_dev(const CoordinatorDevConfig& config,
                                     const MonotonicMs now) noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
  if (mode_ != CoordinatorMode::Fresh) {
    return Status::error(StatusCode::InvalidState, "coordinator already running");
  }
  if (!deps_ready(deps_)) return Status::error(StatusCode::InvalidState, "coordinator deps");
  last_now_ = now;
  in_port_ = true;
  const Status status = install_dev_config(config, now);
  in_port_ = false;
  return status;
}

Status SecurityCoordinator::take_action(CoordinatorAction& out) noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
  if (!action_pending_) return Status::error(StatusCode::NotFound, "no coordinator action");
  out = action_;
  action_ = CoordinatorAction{};
  action_pending_ = false;
  return Status::success();
}

CoordinatorSnapshot SecurityCoordinator::snapshot() const noexcept {
  CoordinatorSnapshot out{};
  out.mode = mode_;
  out.membership = deps_.discovery != nullptr ? deps_.discovery->membership().state()
                                              : MembershipState::Unprovisioned;
  out.sleeping = sleeping_;
  out.action_pending = action_pending_;
  // Only the live workspace side is readable: the union holds nothing in
  // Fresh/Removed/Recovery.
  if (mode_ == CoordinatorMode::ZeroTouch) {
    out.joiner = joiner().snapshot().state;
  }
  if (has_member_engine()) {
    out.engine_quiescent = member().engine.quiescent();
    out.resume_link_slots = static_cast<std::uint16_t>(member().resume_cache.link_quota());
    out.resume_end_slots = static_cast<std::uint16_t>(member().resume_cache.end_quota());
  }
  out.link_sessions = static_cast<std::uint32_t>(bank_.live_count(SecurityScope::Link));
  out.end_sessions = static_cast<std::uint32_t>(bank_.live_count(SecurityScope::EndToEnd));
  out.demands = bank_.demand_count();
  // The dev route has no authority channel (the small side is dead in
  // Dev): report the same unstarted view a fresh channel snapshots.
  if (mode_ == CoordinatorMode::Dev) {
    out.authority_started = false;
    out.authority_ready = false;
    out.authority_busy = false;
  } else {
    const AuthoritySnapshot auth = small().authority.snapshot();
    out.authority_started = auth.started;
    out.authority_ready = auth.state == AuthoritySnapshot::State::Ready;
    out.authority_busy = auth.busy;
  }
  out.join_confirmed = join_confirmed_;
  out.refresh_strikes = refresh_strikes_;
  return out;
}

Status SecurityCoordinator::member_discovery_config(DiscoveryConfig& out) noexcept {
  out = DiscoveryConfig{};
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
  if (!has_member_engine() || !member_valid_) {
    return Status::error(StatusCode::InvalidState, "member discovery unavailable");
  }
  out.node = adopted_.node;
  out.mac = deps_.local_mac;
  out.network = adopted_.network;
  out.network_hint = static_cast<std::uint32_t>(adopted_.network);
  if (mode_ == CoordinatorMode::Dev) {
    // Dev-only bit, no member bits: the engine refuses any member/dev
    // mix as Unsupported (never a downgrade), and the Required dev
    // scope filters DISCOVER/OFFER to the same PSK before that.
    out.capability_bits = kRld1CapDevRamSessionV1;
    out.scope_mode = ScopeMode::Required;
    out.scope_provider = &dev().scope;
    out.scope = kDevScopeRef;
  } else {
    out.capability_bits = kRld1CapMemberEdhocV1 | kRld1CapMemberResumeV1;
    out.scope_mode = ScopeMode::Required;
    out.scope_provider = &member_scope_;
    out.scope = kMemberScopeRef;
  }
  out.cookie_bucket_ms = static_cast<std::uint32_t>(MemberCookie::kBucketMs);
  return Status::success();
}

MonotonicMs SecurityCoordinator::next_deadline(const MonotonicMs now) const noexcept {
  if (sleeping_ || mode_ == CoordinatorMode::Fresh) return kJoinNoDeadline;
  MonotonicMs deadline = kJoinNoDeadline;
  const auto sooner = [&](const MonotonicMs candidate) {
    if (candidate != kJoinNoDeadline && (deadline == kJoinNoDeadline || candidate < deadline)) {
      deadline = candidate;
    }
  };
  if (action_pending_) return now;
  for (const auto& staged : staged_) {
    if (staged.used) return now;
  }
  if (mode_ == CoordinatorMode::ZeroTouch) sooner(joiner().next_deadline());
  if (has_member_engine()) {
    // The engine and the bank publish no deadline: while either has work
    // the firmware must keep polling, else the demux expiries rule.
    if (!member().engine.quiescent() || bank_.demand_count() != 0) return now;
    for (const auto& entry : member().demux) {
      if (entry.used) sooner(entry.expires_at);
    }
    if (mode_ == CoordinatorMode::Member) {
      // A pending GK promote and the authority channel join the schedule.
      if (group_keys_.promotion_pending()) return now;
      if (authority_wanted_ && !small().authority.snapshot().started) {
        const MonotonicMs retry = last_authority_start_ > kJoinNoDeadline - 1000
                                      ? kJoinNoDeadline
                                      : last_authority_start_ + 1000;
        sooner(retry);
      } else {
        sooner(small().authority.next_deadline());
      }
    }
  }
  if (removal_holdoff_armed_) sooner(removal_holdoff_at_);
  return deadline;
}

bool SecurityCoordinator::quiescent() const noexcept {
  // Inside an outer call the answer is always false (P4 §2.2); a staged
  // frame is work even when the workspace naps; a pending action is work
  // for the firmware, not for sleep permission — PrepareSleep checks the
  // slot separately.
  if (in_port_) return false;
  return quiescent_locked();
}

bool SecurityCoordinator::member_work_pending() const noexcept {
  if (!member().engine.quiescent() || bank_.demand_count() != 0) return true;
  for (const auto& entry : member().demux) {
    if (!entry.used) continue;
    // A completed member leg (installed_link cleared its start) only
    // routes late duplicates — the engine already dropped the exchange,
    // so it never blocks sleep. Joiner/proxy legs always count as work.
    if (entry.owner == DemuxOwner::Member && !entry.has_start) continue;
    return true;
  }
  return false;
}

bool SecurityCoordinator::quiescent_locked() const noexcept {
  if (tune_outstanding_ != 0 || member_apply_pending_) return false;
  for (const auto& staged : staged_) {
    if (staged.used) return false;
  }
  if (sleeping_) return true;
  if (mode_ == CoordinatorMode::ZeroTouch) return joiner().quiescent();
  if (has_member_engine()) {
    // Completed member legs only route late duplicates (never sleep
    // work); Joiner/proxy legs always count — see member_work_pending.
    if (member_work_pending()) return false;
    if (mode_ != CoordinatorMode::Member) return true;
    // A pending GK promote (a durable flash write) holds sleep off; the
    // authority channel naps with the device instead — staged bytes, a
    // handshake or backoff resume on Wake, and deep sleep closes the
    // channel (PR5). Gating sleep on channel idleness would wedge a
    // device whose host is away.
    if (group_keys_.promotion_pending()) return false;
    return true;
  }
  return true;
}

Status SecurityCoordinator::on_boot(const CoordinatorEvent& event) noexcept {
  if (mode_ != CoordinatorMode::Fresh) {
    return Status::error(StatusCode::InvalidState, "coordinator already booted");
  }
  if (!deps_ready(deps_)) return Status::error(StatusCode::InvalidState, "coordinator deps");
  if (!event.boot_prepared) {
    return Status::error(StatusCode::InvalidArgument, "coordinator boot unprepared");
  }
  boot_witness_ = event.boot_witness;
  channel_ = 0;  // the first TuneChannel (or the firmware's operating
                 // channel, once adopted) sets it; until then RLD1 RX drops
  radio_generation_ = event.radio_generation;
  usb_direct_ = event.usb_direct;
  // A standing removal record restarts its 10-minute RAM holdoff on every
  // boot — the Cleaned commit time does not survive the reboot.
  if (deps_.local_revocation->has_record()) {
    removal_holdoff_armed_ = true;
    removal_holdoff_at_ = event.now + kRemovalHoldoffMs;
  }
  sat_inc(counters_.boots);
  // Every boot runs the Joiner's boot/store check — it is the classifier
  // of record (healthy adoption without radio, recovery_only re-issue,
  // RecoveryRequired when the stores cannot proceed). The firmware picks
  // the transport by attachment: USB (direct) or radio scan.
  JoinBootInput boot{};
  boot.boot_witness = event.boot_witness;
  boot.prepared = true;
  boot.removal_watermark_site_id = removal_watermark_site_id_;
  boot.removal_watermark_generation = removal_watermark_generation_;
  mode_ = CoordinatorMode::ZeroTouch;  // tags the workspace for destroy below
  create_joiner();
  const Status started = event.usb_direct ? joiner().start_direct(boot, *this, event.now)
                                          : joiner().start(boot, event.now);
  if (!started) {
    destroy_workspace();
    mode_ = CoordinatorMode::Recovery;
    CoordinatorAction action{};
    action.kind = CoordinatorActionKind::ReportRecovery;
    action.recovery = JoinRecoveryReason::MembershipInvalid;
    emit_action(action);
    return Status::success();
  }
  return Status::success();
}

Status SecurityCoordinator::on_poll(const MonotonicMs now) noexcept {
  if (mode_ == CoordinatorMode::Fresh) {
    return Status::error(StatusCode::InvalidState, "coordinator not booted");
  }
  if (sleeping_) return Status::success();
  if (mode_ == CoordinatorMode::ZeroTouch) {
    drain_joiner(now);
    maybe_abandon_refresh(now);
    return Status::success();
  }
  if (!has_member_engine()) return Status::success();
  if (member_apply_pending_) return Status::success();
  // Start discovery only after the firmware has reported a successful
  // member radio/node apply and the single action slot is free.
  if (!discovery_started_ && !action_pending_) {
    CoordinatorAction start{};
    start.kind = CoordinatorActionKind::StartMemberDiscovery;
    emit_action(start);
    discovery_started_ = true;
  }
  // Member poll order: staged RX first (it may complete exchanges),
  // then discovery starts, demands, the engine, and housekeeping.
  // Partial assemblies older than the exchange timeout are dropped so a
  // lost chunk cannot wedge a slot (TX slots evict on the next load).
  drain_staged(now);
  sweep_demux(now);
  (void)member().link_rx.expire(now, HandshakeEngine::kLinkTimeoutMs);
  (void)member().end_rx.expire(now, HandshakeEngine::kLinkTimeoutMs);
  // Eagerly take every parked discovery start into the demux table:
  // initiator legs request immediately, responder legs wait for m1/R1.
  // Taking consumes the discovery leg, so the table space check runs
  // first — a full table leaves the start parked for the next poll.
  for (;;) {
    if (deps_.discovery == nullptr) break;  // discovery starts after Apply
    std::size_t free = 0;
    for (const auto& slot : member().demux) {
      if (!slot.used) ++free;
    }
    if (free == 0) break;
    NeighborDiscovery::MemberStartRequest start{};
    if (!deps_.discovery->take_member_start(start, now).ok()) break;
    if (start.peer == kInvalidNodeId || start.peer == adopted_.node) continue;
    // Sleep re-confirmation (P4 §9.3, V1-F07): while a restore image is
    // held for this initiator peer at the retained radio MAC, the
    // accepted OFFER re-confirms the parent WITHOUT the engine —
    // restore installs the retained (peer-authenticated) session, and a
    // fresh handshake would install over the bank slot restore needs. No
    // demux leg is held: nothing routes for a confirmed parent. The
    // parent generation is revocation-vetted first (a revoked parent
    // must not even bind); any refusal falls through to the normal
    // engine path below, whose fresh session then stands while restore
    // reports occupied (cold resume).
    if (start.initiator && restore_holding_ && deps_.sleep_image != nullptr &&
        start.peer == deps_.sleep_image->contexts[0].entry.peer &&
        start.peer_mac == deps_.sleep_image->parent_mac &&
        !revoked(start.peer, deps_.sleep_image->contexts[0].entry.peer_generation) &&
        deps_.discovery->confirm_sleep_parent(start, now).ok()) {
      continue;
    }
    // One member leg per peer MAC: the engine refuses per-peer duplicates
    // anyway, and a second leg would alias the demux key. A simultaneous
    // open resolves to the first leg; mutual auth still succeeds. A
    // completed leg (installed_link cleared its start) only routes late
    // duplicates of the old exchange — a new exchange never matches it,
    // so it must not block the re-handshake (sleep wake, rekey).
    bool leg_live = false;
    for (const auto& slot : member().demux) {
      if (slot.used && slot.owner == DemuxOwner::Member && slot.has_start &&
          slot.mac == start.peer_mac) {
        leg_live = true;
        break;
      }
    }
    if (leg_live) continue;
    DemuxEntry* entry = claim_demux(start.peer_mac, 0, DemuxOwner::Member, now);
    if (entry == nullptr) break;
    entry->peer = start.peer;
    entry->has_start = true;
    entry->initiator = start.initiator;
    entry->carrier = start.carrier;
    // The Owner stamps what discovery cannot know: the adopted full64,
    // self, and the peer ends (direction-aware).
    entry->carrier.network = adopted_.network;
    if (start.initiator) {
      entry->carrier.node_i = adopted_.node;
      entry->carrier.node_r = start.peer;
    } else {
      entry->carrier.node_i = start.peer;
      entry->carrier.node_r = adopted_.node;
    }
    entry->expires_at = start.expires_at_ms;
    if (start.initiator) {
      // Pair with discovery's reservation, then request the exchange.
      std::uint32_t token = NeighborDiscovery::kMemberHandshakeNone;
      ScopeDigest carrier_digest{};
      keys::link_carrier_digest(entry->carrier, carrier_digest);
      if (!deps_.discovery
               ->begin_member_handshake(start.peer, start.peer_mac, carrier_digest, now, token)
               .ok()) {
        entry->used = false;
        continue;
      }
      entry->discovery_token = token;
      HandshakeRequest req{};
      req.scope = SecurityScope::Link;
      req.peer = start.peer;
      req.reason = HandshakeReason::Initial;
      // The minted proof names this reservation: without it discovery
      // cannot match the completion and the link never binds.
      req.elevation_token = token;
      req.mac_i = deps_.local_mac;
      req.mac_r = start.peer_mac;
      req.carrier = entry->carrier;
      if (!member().engine.request(req, now).ok()) {
        deps_.discovery->cancel_member_handshake(token);
        entry->used = false;
        continue;
      }
    }
  }
  drain_demands(now);
  drain_engine_results(now);
  drive_engine(now);
  if (mode_ == CoordinatorMode::Member) {
    // Join service, stale-GK watch and authority channel are Member-only:
    // the dev route has no proxy, no GK and no channel to drive.
    member().proxy.poll(now);
    if (member().gateway_active) member().gateway.poll(now);
    watch_linkless(now);   // stale-GK evidence accrues toward a refresh
    drive_authority(now);  // GK tick/promote, channel tick, deferred start
  }
  if (removal_holdoff_armed_ && now >= removal_holdoff_at_) {
    removal_holdoff_armed_ = false;
    hooks_.set_holdoff_elapsed(true);
  }
  return Status::success();
}

void SecurityCoordinator::sweep_demux(const MonotonicMs now) noexcept {
  assert(has_member_engine());
  for (auto& entry : member().demux) {
    if (!entry.used || now < entry.expires_at) continue;
    if (entry.discovery_token != NeighborDiscovery::kMemberHandshakeNone &&
        deps_.discovery != nullptr) {
      deps_.discovery->cancel_member_handshake(entry.discovery_token);
    }
    entry = DemuxEntry{};
  }
}

SecurityCoordinator::DemuxEntry* SecurityCoordinator::find_demux(
    const MacAddress& mac, const std::uint32_t object_id) noexcept {
  assert(has_member_engine());
  for (auto& entry : member().demux) {
    if (entry.used && entry.mac == mac && entry.object_id == object_id) return &entry;
  }
  return nullptr;
}

SecurityCoordinator::DemuxEntry* SecurityCoordinator::claim_demux(
    const MacAddress& mac, const std::uint32_t object_id, const DemuxOwner owner,
    const MonotonicMs now) noexcept {
  assert(has_member_engine());
  DemuxEntry* free = nullptr;
  for (auto& entry : member().demux) {
    if (!entry.used) {
      if (free == nullptr) free = &entry;
      continue;
    }
    if (entry.mac == mac && entry.object_id == object_id) {
      // Same exchange, same owner: refresh. Same exchange, another
      // owner: the cooperation is ambiguous — drop (no steal).
      if (entry.owner != owner) return nullptr;
      entry.expires_at = now + kDemuxHoldMs;
      return &entry;
    }
  }
  if (free == nullptr) return nullptr;
  free->used = true;
  free->mac = mac;
  free->peer = kInvalidNodeId;
  free->object_id = object_id;
  free->owner = owner;
  free->expires_at = now + kDemuxHoldMs;
  free->has_start = false;
  free->initiator = false;
  free->carrier = keys::LinkCarrier{};
  free->discovery_token = NeighborDiscovery::kMemberHandshakeNone;
  free->txn = {};
  return free;
}

Status SecurityCoordinator::on_rld1_rx(const CoordinatorEvent& event) noexcept {
  if (mode_ != CoordinatorMode::ZeroTouch && !has_member_engine()) {
    return Status::success();  // Fresh/Removed/Recovery: no RLD1 owner lives
  }
  if (sleeping_) return Status::success();
  if (has_member_engine() && member_apply_pending_) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  if (event.radio_generation != radio_generation_) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  // Observed channel and destination first: a frame for another MAC or an
  // unexpected channel never reaches an owner.
  if (channel_ != 0 && event.rld1_meta.channel != channel_) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  autonomy::Rld1Envelope env{};
  if (!autonomy::rld1_decode(event.rld1_frame, env).ok()) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  const bool to_us = event.rld1_meta.destination == deps_.local_mac;
  const bool to_broadcast = event.rld1_meta.destination == MacAddress{} ||
                            event.rld1_meta.destination ==
                                MacAddress{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};
  if (!to_us && !to_broadcast) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  // Discover/Offer split by body version: ZT v3 to the Joiner (ZT mode
  // only), member scope to discovery (member mode only).
  if (env.kind == FrameType::Discover || env.kind == FrameType::Offer) {
    if (zt_rld1_frame(env)) {
      if (mode_ != CoordinatorMode::ZeroTouch) {
        sat_inc(counters_.demux_drops);
        return Status::success();
      }
      return joiner().on_rld1_rx(event.rld1_meta, event.rld1_frame, event.now);
    }
    if (!has_member_engine()) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    DiscoveryRxMetadata observed{};
    observed.source = event.rld1_meta.source;
    observed.destination = event.rld1_meta.destination;
    if (deps_.discovery != nullptr) {
      deps_.discovery->on_rld1_rx(observed, event.rld1_frame, event.now);
    }
    return Status::success();
  }
  if (env.kind != FrameType::BootstrapAuth && env.kind != FrameType::BootstrapChunk &&
      env.kind != FrameType::BootstrapReply) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  if (!to_us) {  // Auth/Chunks/Replies are unicast-only on RLD1
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  // Joiner validates its own exchange, including pre-m2 RelayStatus; no
  // member demux exists while its workspace union arm is active.
  if (!has_member_engine()) {
    return joiner().on_rld1_rx(event.rld1_meta, event.rld1_frame, event.now);
  }
  // Auth/Chunk/Reply: exact (MAC, object id) owner match, else the
  // new-exchange admission below. The object id is the transaction's
  // first 4 bytes on every carrier.
  std::uint32_t object_id = 0;
  if (env.kind == FrameType::BootstrapChunk || env.kind == FrameType::BootstrapReply) {
    // The owner key (bytes 2..5) is only parsed from a full header: a
    // short body must not claim a demux leg on garbage bytes.
    if (env.body_size < kJoinChunkHeaderSize) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    object_id = (static_cast<std::uint32_t>(env.body[2]) << 24U) |
                (static_cast<std::uint32_t>(env.body[3]) << 16U) |
                (static_cast<std::uint32_t>(env.body[4]) << 8U) | env.body[5];
  } else {
    object_id = join_rld1_object_id(env.transaction_nonce);
  }
  DemuxEntry* hit = find_demux(event.rld1_meta.source, object_id);
  if (hit != nullptr) {
    if (hit->owner == DemuxOwner::Joiner) {
      if (mode_ != CoordinatorMode::ZeroTouch) {
        sat_inc(counters_.demux_drops);
        return Status::success();
      }
      return joiner().on_rld1_rx(event.rld1_meta, event.rld1_frame, event.now);
    }
    if (hit->owner == DemuxOwner::Proxy) {
      if (mode_ != CoordinatorMode::Member) {
        sat_inc(counters_.demux_drops);
        return Status::success();
      }
      const std::int16_t rssi = event.rld1_meta.rssi;
      const std::int8_t rssi8 =
          rssi < -128 ? -128 : (rssi > 127 ? 127 : static_cast<std::int8_t>(rssi));
      member().proxy.on_rld1_rx(event.rld1_meta.source, event.rld1_meta.destination, rssi8,
                        event.rld1_frame, event.now);
      return Status::success();
    }
    return demux_member_frame(env, hit, event.now);
  }
  // New exchange. An engine-mode Auth single frame with a parked
  // responder start (same peer MAC) binds to it; anything else follows
  // the mode default: ZT Joiner while unprovisioned, proxy admission
  // while member, drop while dev (no join service there).
  if (has_member_engine()) {
    for (auto& entry : member().demux) {
      if (entry.used && entry.owner == DemuxOwner::Member && entry.has_start &&
          !entry.initiator && entry.mac == event.rld1_meta.source) {
        // The initiator's txn now keys the leg, and every answer echoes
        // the same nonce back.
        entry.object_id = object_id;
        entry.txn = env.transaction_nonce;
        return demux_member_frame(env, &entry, event.now);
      }
    }
    if (mode_ != CoordinatorMode::Member) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    // The proxy owns one bounded exchange and verifies the OFFER cookie
    // before admitting it. Unknown pre-cookie frames must not occupy the
    // member demux table, or a small flood could block real handshakes.
    if (env.kind == FrameType::BootstrapReply &&
        member().proxy.state() != JoinProxy::State::Relaying) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    const std::int16_t rssi = event.rld1_meta.rssi;
    const std::int8_t rssi8 =
        rssi < -128 ? -128 : (rssi > 127 ? 127 : static_cast<std::int8_t>(rssi));
    member().proxy.on_rld1_rx(event.rld1_meta.source, event.rld1_meta.destination, rssi8,
                      event.rld1_frame, event.now);
    return Status::success();
  }
  if (env.kind == FrameType::BootstrapReply) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  DemuxEntry* joiner_entry =
      claim_demux(event.rld1_meta.source, object_id, DemuxOwner::Joiner, event.now);
  if (joiner_entry == nullptr) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  return joiner().on_rld1_rx(event.rld1_meta, event.rld1_frame, event.now);
}

void SecurityCoordinator::ensure_responder_token(DemuxEntry& entry,
                                                   const MonotonicMs now) noexcept {
  if (!entry.has_start || entry.initiator ||
      entry.discovery_token != NeighborDiscovery::kMemberHandshakeNone ||
      deps_.discovery == nullptr) {
    return;
  }
  std::uint32_t token = NeighborDiscovery::kMemberHandshakeNone;
  ScopeDigest carrier_digest{};
  keys::link_carrier_digest(entry.carrier, carrier_digest);
  if (deps_.discovery->begin_member_handshake(entry.peer, entry.mac, carrier_digest, now, token)
          .ok()) {
    entry.discovery_token = token;
  }
}

Status SecurityCoordinator::demux_member_frame(const autonomy::Rld1Envelope& env,
                                               DemuxEntry* entry, const MonotonicMs now) noexcept {
  if (entry == nullptr || !entry->used || !has_member_engine()) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  entry->expires_at = now + kDemuxHoldMs;
  const ByteView body{env.body.data(), env.body_size};
  // Replies advance our link TX slot when the exchange matches; anything
  // else on this leg drops.
  if (env.kind == FrameType::BootstrapReply) {
    JoinReply reply{};
    if (!join_reply_decode(JoinCarrier::Rld1, body, reply).ok() ||
        reply.lane != ObjectLane::JoinRelay) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    (void)member().link_tx.on_reply(reply, now);
    return Status::success();
  }
  if (env.kind == FrameType::BootstrapChunk) {
    JoinChunk chunk{};
    if (!join_chunk_decode(JoinCarrier::Rld1, body, chunk).ok()) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    // Chunks carry no lane bit on RLD1 (end objects never ride it); the
    // decode already refused foreign subs.
    const JoinObjectSlot::Accepted accepted = member().link_rx.accept(JoinCarrier::Rld1, chunk, now);
    if (accepted.send_reply) {
      std::array<std::uint8_t, kJoinReplySize> body{};
      std::size_t written = 0;
      if (join_reply_encode(JoinCarrier::Rld1, accepted.reply,
                              MutableByteView{body.data(), body.size()}, written)
              .ok() &&
          written <= autonomy::kRld1MaxBody) {
        autonomy::Rld1Envelope reply_env{};
        reply_env.kind = FrameType::BootstrapReply;
        reply_env.network_hint = static_cast<std::uint32_t>(adopted_.network);
        reply_env.claimed_node = adopted_.node;
        reply_env.transaction_nonce = entry->txn;
        std::memcpy(reply_env.body.data(), body.data(), written);
        reply_env.body_size = written;
        autonomy::Rld1Encoded frame{};
        if (autonomy::rld1_encode(reply_env, frame).ok()) {
          (void)deps_.rld1->send_rld1(entry->mac, frame.view());
        }
      }
    }
    if (accepted.outcome != JoinObjectSlot::Outcome::Complete) {
      if (accepted.outcome == JoinObjectSlot::Outcome::Rejected ||
          accepted.outcome == JoinObjectSlot::Outcome::Busy) {
        sat_inc(counters_.demux_drops);
      }
      return Status::success();
    }
    JoinAuthObject object{};
    if (!join_object_decode(member().link_rx.assembled(), object).ok() ||
        object.phase == JoinAuthPhase::RelayStatus) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    // Same first-message cookie rule as the single-frame path: a large
    // m1/R1 may legitimately arrive chunked (the cookie rides inside the
    // object), but it must still echo the OFFER cookie.
    if (object.step == 1 && !object.cookie_present) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    if (object.step == 1 && object.phase == JoinAuthPhase::Resume &&
        !member().budgets.admit_link_resume(now)) {
      sat_inc(counters_.demux_drops);
      return Status::success();
    }
    ensure_responder_token(*entry, now);
    HandshakeRx rx{};
    rx.scope = SecurityScope::Link;
    rx.phase = static_cast<std::uint8_t>(object.phase);
    rx.step = object.step;
    rx.claimed_peer = entry->peer;
    rx.elevation_token = entry->discovery_token;
    rx.src_mac = entry->mac;
    rx.dst_mac = deps_.local_mac;
    rx.carrier = entry->carrier;
    if (object.cookie_present) {
      rx.cookie = ByteView{object.cookie.data(), object.cookie.size()};
    }
    (void)member().engine.on_message(rx, object.message, now);
    return Status::success();
  }
  // Single-frame step: the join-lane object codec, then the engine. The
  // engine re-verifies the cookie against the parked carrier, the network
  // binding and the capability floor — the demux only routes.
  JoinAuthObject object{};
  if (!join_object_decode(body, object).ok() || object.phase == JoinAuthPhase::RelayStatus) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  if ((object.step == 1) && !object.cookie_present) {
    // First messages always echo the OFFER cookie (EDHOC-m1 and RLRES1-R1
    // alike); a missing cookie never reaches the engine.
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  // Link resume starts admit 1/s; EDHOC sits behind the engine's own
  // ECC gap instead of this bucket.
  if (object.step == 1 && object.phase == JoinAuthPhase::Resume &&
      !member().budgets.admit_link_resume(now)) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  ensure_responder_token(*entry, now);
  HandshakeRx rx{};
  rx.scope = SecurityScope::Link;
  rx.phase = static_cast<std::uint8_t>(object.phase);
  rx.step = object.step;
  rx.claimed_peer = entry->peer;
  rx.elevation_token = entry->discovery_token;
  rx.src_mac = entry->mac;
  rx.dst_mac = deps_.local_mac;
  rx.carrier = entry->carrier;
  if (object.cookie_present) {
    rx.cookie = ByteView{object.cookie.data(), object.cookie.size()};
  }
  (void)member().engine.on_message(rx, object.message, now);
  // The assembly is consumed: free the slot for the next exchange's
  // chunks (a second chunked handshake in this boot would otherwise
  // find it Busy). Late duplicates still answer Complete from the
  // retained token.
  member().link_rx.release_assembled();
  return Status::success();
}

void SecurityCoordinator::drain_demands(const MonotonicMs now) noexcept {
  // End demands request inline; link demands stage for discovery pairing.
  (void)member().demands.poll(now);
  for (;;) {
    SessionDemand demand{};
    if (!member().demands.take_link_demand(demand).ok()) break;
    // Pair with a live taken start for the same peer: the engine needs
    // the frozen carrier only discovery can supply.
    DemuxEntry* leg = nullptr;
    for (auto& entry : member().demux) {
      if (entry.used && entry.owner == DemuxOwner::Member && entry.has_start &&
          entry.peer == demand.peer && entry.initiator) {
        leg = &entry;
        break;
      }
    }
    if (leg == nullptr) {
      // No carrier yet: keep the demand in the bank (re-recorded) so a
      // later discovery round can pair it. The bank merges per peer.
      bank_.note_demand(demand.scope, demand.peer);
      continue;
    }
    HandshakeRequest req{};
    req.scope = SecurityScope::Link;
    req.peer = demand.peer;
    req.reason = HandshakeReason::Initial;
    // Pairs the minted proof with discovery's reservation (None when the
    // leg was never reserved: the session still installs, elevation is
    // skipped for it).
    req.elevation_token = leg->discovery_token;
    req.mac_i = deps_.local_mac;
    req.mac_r = leg->mac;
    req.carrier = leg->carrier;
    if (!member().engine.request(req, now).ok()) {
      bank_.note_demand(demand.scope, demand.peer);
      continue;
    }
    if (leg->discovery_token == NeighborDiscovery::kMemberHandshakeNone &&
        deps_.discovery != nullptr) {
      std::uint32_t token = NeighborDiscovery::kMemberHandshakeNone;
      ScopeDigest carrier_digest{};
      keys::link_carrier_digest(leg->carrier, carrier_digest);
      if (deps_.discovery
              ->begin_member_handshake(demand.peer, leg->mac, carrier_digest, now, token)
              .ok()) {
        leg->discovery_token = token;
      }
    }
  }
}

void SecurityCoordinator::drain_engine_results(const MonotonicMs now) noexcept {
  for (;;) {
    HandshakeResult result{};
    if (!member().engine.take_result(result).ok()) break;
    if (result.event == HandshakeEvent::Send) {
      if (emit_send(result, now).ok()) {
        (void)member().engine.accept_send(result.token, result.phase, result.step);
      }
    } else if (result.event == HandshakeEvent::Established && result.has_proof &&
               result.scope == SecurityScope::Link) {
      (void)installed_link(result, now);
      if (mode_ == CoordinatorMode::Member) note_link_established();
    } else if (result.event == HandshakeEvent::Failed && result.scope == SecurityScope::Link) {
      // Tear down the leg: the next discovery round or demand re-drives.
      for (auto& entry : member().demux) {
        if (entry.used && entry.owner == DemuxOwner::Member && entry.peer == result.peer) {
          if (entry.discovery_token != NeighborDiscovery::kMemberHandshakeNone &&
              deps_.discovery != nullptr) {
            deps_.discovery->cancel_member_handshake(entry.discovery_token);
          }
          entry = DemuxEntry{};
        }
      }
      // Stale-GK strikes are Member-only: dev has no GK to refresh.
      if (mode_ == CoordinatorMode::Member) note_link_failed();
    }
  }
}

Status SecurityCoordinator::drive_engine(const MonotonicMs now) noexcept {
  // The engine refuses Busy while a result pends: the poll legs always
  // drain first, so a refusal here only means a Send raced us — the next
  // poll picks it up.
  (void)member().engine.poll(now);
  (void)bank_.tick(now);
  drain_engine_results(now);
  return Status::success();
}

Status SecurityCoordinator::emit_send(const HandshakeResult& result,
                                      const MonotonicMs now) noexcept {
  if (result.scope == SecurityScope::Link) return emit_link_send(result, now);
  return emit_end_send(result, now);
}

Status SecurityCoordinator::emit_link_send(const HandshakeResult& result,
                                           const MonotonicMs now) noexcept {
  // The leg holds the peer MAC, the frozen carrier (cookie source) and
  // the transaction id (drawn on our first send, echoed after). Only a
  // live (start-carrying) leg answers: a completed leg for the same peer
  // names the old exchange, and sending on it would key the peer's demux
  // to an id it no longer routes.
  DemuxEntry* leg = nullptr;
  for (auto& entry : member().demux) {
    if (entry.used && entry.owner == DemuxOwner::Member && entry.has_start &&
        entry.peer == result.peer) {
      leg = &entry;
      break;
    }
  }
  if (leg == nullptr) return Status::error(StatusCode::NotFound, "no link leg");
  if (leg->object_id == 0) {
    std::array<std::uint8_t, 16> txn{};
    if (!entropy_fill(deps_.entropy, txn.data(), txn.size())) {
      return Status::error(StatusCode::InternalError, "no entropy");
    }
    std::uint32_t id = join_rld1_object_id(txn);
    if (id == 0) id = 1;  // nonzero: 0 keys "not yet bound" in the table
    // Alias check: another leg of ours must not share (mac, id).
    for (const auto& other : member().demux) {
      if (other.used && &other != leg && other.mac == leg->mac && other.object_id == id) {
        return Status::error(StatusCode::Busy, "link id alias");
      }
    }
    leg->object_id = id;
    leg->txn = txn;
  }
  const ByteView message{result.message.data(), result.message_size};
  JoinAuthObject object{};
  object.phase = static_cast<JoinAuthPhase>(result.phase);
  object.step = result.step;
  if (result.cookie_attach) {
    object.cookie_present = true;
    object.cookie = leg->carrier.cookie;
  }
  object.message = message;
  const std::size_t encoded_size = join_object_encoded_size(object);
  // Single-frame when it fits the RLD1 body, chunked (join lane) above.
  if (encoded_size <= join_single_frame_max(JoinCarrier::Rld1)) {
    std::array<std::uint8_t, kJoinObjectMax> body{};
    std::size_t written = 0;
    if (!join_object_encode(object, MutableByteView{body.data(), body.size()}, written).ok()) {
      return Status::error(StatusCode::ProtocolError, "link object encode");
    }
    autonomy::Rld1Envelope env{};
    env.kind = FrameType::BootstrapAuth;
    env.network_hint = static_cast<std::uint32_t>(adopted_.network);
    env.claimed_node = adopted_.node;
    env.transaction_nonce = leg->txn;
    env.capability_bits = 0;  // Auth bodies carry no capability claim
    if (written > env.body.size()) {
      return Status::error(StatusCode::ProtocolError, "link object body");
    }
    std::memcpy(env.body.data(), body.data(), written);
    env.body_size = written;
    autonomy::Rld1Encoded frame{};
    if (!autonomy::rld1_encode(env, frame).ok()) {
      return Status::error(StatusCode::ProtocolError, "link rld1 encode");
    }
    return deps_.rld1->send_rld1(leg->mac, frame.view());
  }
  // The slot holds the full object encoding (cookie included): the peer
  // assembles these bytes and decodes them as a JoinAuthObject.
  std::array<std::uint8_t, kJoinObjectMax> full{};
  std::size_t full_size = 0;
  if (!join_object_encode(object, MutableByteView{full.data(), full.size()}, full_size).ok()) {
    return Status::error(StatusCode::ProtocolError, "link object encode");
  }
  JoinObjectSlot& slot = member().link_tx;
  // Same occupant (an engine retransmit while chunks are unconfirmed):
  // re-emit the due chunks without resetting the receiver's progress.
  // Anything else loads, evicting a dead exchange's object if any.
  const bool same = slot.mode() == JoinObjectSlot::Mode::Sending &&
                    slot.phase() == object.phase && slot.step() == object.step &&
                    slot.id() == leg->object_id && slot.lane() == ObjectLane::JoinRelay;
  if (!same && !slot.load(JoinCarrier::Rld1, object.phase, object.step, leg->object_id, 0, 0,
                           ByteView{full.data(), full_size}, now)
                    .ok()) {
    return Status::error(StatusCode::ProtocolError, "link tx load");
  }
  // Emit the unconfirmed chunks now; replies advance the slot via
  // demux_member_frame, and the engine's retransmit re-drives the rest.
  const std::uint16_t pending = slot.pending_mask();
  bool accepted = true;
  for (std::size_t i = 0; i < slot.chunk_total(); ++i) {
    if ((pending & static_cast<std::uint16_t>(1U << i)) == 0) continue;
    JoinChunk chunk{};
    if (!slot.chunk_at(i, chunk).ok()) {
      accepted = false;
      break;
    }
    std::array<std::uint8_t, autonomy::kRld1MaxBody> body{};
    std::size_t written = 0;
    if (!join_chunk_encode(JoinCarrier::Rld1, chunk,
                           MutableByteView{body.data(), body.size()}, written)
             .ok()) {
      accepted = false;
      break;
    }
    autonomy::Rld1Envelope env{};
    env.kind = FrameType::BootstrapChunk;
    env.network_hint = static_cast<std::uint32_t>(adopted_.network);
    env.claimed_node = adopted_.node;
    env.transaction_nonce = leg->txn;
    if (written > env.body.size()) {
      accepted = false;
      break;
    }
    std::memcpy(env.body.data(), body.data(), written);
    env.body_size = written;
    autonomy::Rld1Encoded frame{};
    if (!autonomy::rld1_encode(env, frame).ok()) {
      accepted = false;
      break;
    }
    if (!deps_.rld1->send_rld1(leg->mac, frame.view()).ok()) accepted = false;
  }
  slot.note_sent(now);
  return accepted ? Status::success()
                  : Status::error(StatusCode::NoCapacity, "link transport full");
}

Status SecurityCoordinator::installed_link(const HandshakeResult& result,
                                           const MonotonicMs now) noexcept {
  (void)now;
  for (auto& entry : member().demux) {
    if (entry.used && entry.owner == DemuxOwner::Member && entry.peer == result.peer) {
      if (entry.discovery_token != NeighborDiscovery::kMemberHandshakeNone &&
          deps_.discovery != nullptr) {
        deps_.discovery->complete_handshake(entry.discovery_token, result.proof, last_now_);
        entry.discovery_token = NeighborDiscovery::kMemberHandshakeNone;
      }
      // The leg stays until expiry so late duplicates route instead of
      // re-opening; the engine already dropped the completed exchange.
      entry.has_start = false;
    }
  }
  return Status::success();
}

Status SecurityCoordinator::emit_end_send(const HandshakeResult& result,
                                          const MonotonicMs now) noexcept {
  // End objects ride the mesh bootstrap lane: a single type-3 frame when
  // the envelope fits, else end-lane chunks (id = exchange id) with
  // type-6 replies. Type 4 never carries an end object.
  const std::uint32_t exchange = result.exchange_id;
  if (exchange == 0) {
    return Status::error(StatusCode::ProtocolError, "end exchange id missing");
  }
  EndObject object{};
  object.phase = static_cast<JoinAuthPhase>(result.phase);
  object.step = result.step;
  object.exchange_id = exchange;
  object.profile = mode_ == CoordinatorMode::Dev ? kEndProfileDev : kEndProfileMember;
  object.message = ByteView{result.message.data(), result.message_size};
  std::array<std::uint8_t, kEndObjectMax> encoded{};
  std::size_t encoded_size = 0;
  if (!end_object_encode(object, MutableByteView{encoded.data(), encoded.size()}, encoded_size)
           .ok()) {
    return Status::error(StatusCode::ProtocolError, "end object encode");
  }
  MessageId id{};
  if (encoded_size <= kMaxApplicationPayload) {
    return deps_.mesh->send_bootstrap(result.peer, FrameType::BootstrapAuth,
                                      ByteView{encoded.data(), encoded_size},
                                      HandshakeEngine::kLinkTimeoutMs, now, id);
  }
  JoinObjectSlot& slot = member().end_tx;
  // Same retransmit rule as the link slot: a repeated Send for the
  // occupant re-emits due chunks, anything else loads (evicting).
  const bool same = slot.mode() == JoinObjectSlot::Mode::Sending &&
                    slot.phase() == object.phase && slot.step() == object.step &&
                    slot.id() == exchange && slot.lane() == ObjectLane::EndSession;
  if (!same && !slot.load(JoinCarrier::WireRelay, object.phase, object.step, exchange, 0, 0,
                           ByteView{encoded.data(), encoded_size}, now, ObjectLane::EndSession)
                    .ok()) {
    return Status::error(StatusCode::ProtocolError, "end tx load");
  }
  const std::uint16_t pending = slot.pending_mask();
  bool accepted = true;
  for (std::size_t i = 0; i < slot.chunk_total(); ++i) {
    if ((pending & static_cast<std::uint16_t>(1U << i)) == 0) continue;
    JoinChunk chunk{};
    if (!slot.chunk_at(i, chunk).ok()) {
      accepted = false;
      break;
    }
    std::array<std::uint8_t, kMaxApplicationPayload> body{};
    std::size_t written = 0;
    if (!join_chunk_encode(JoinCarrier::WireRelay, chunk,
                           MutableByteView{body.data(), body.size()}, written)
             .ok()) {
      accepted = false;
      break;
    }
    if (!deps_.mesh->send_bootstrap(result.peer, FrameType::BootstrapChunk,
                                    ByteView{body.data(), written},
                                    HandshakeEngine::kLinkTimeoutMs, now, id).ok()) {
      accepted = false;
    }
  }
  slot.note_sent(now);
  return accepted ? Status::success()
                  : Status::error(StatusCode::NoCapacity, "end transport full");
}

Status SecurityCoordinator::on_frame(const BootstrapMeta& meta, const FrameType type,
                                     ByteView payload, const MonotonicMs now_ms) noexcept {
  // Node RX context: stage only. Sending from inside the Node's receive
  // callback would re-enter the Node — Poll drains the queue instead.
  for (auto& slot : staged_) {
    if (slot.used) continue;
    if (payload.size > slot.payload.size()) {
      sat_inc(counters_.staged_drops);
      return Status::success();
    }
    slot.used = true;
    slot.meta = meta;
    slot.type = type;
    if (payload.size > 0) std::memcpy(slot.payload.data(), payload.data, payload.size);
    slot.payload_size = payload.size;
    slot.now = now_ms;
    return Status::success();
  }
  sat_inc(counters_.staged_drops);
  return Status::success();
}

void SecurityCoordinator::drain_staged(const MonotonicMs now) noexcept {
  for (auto& slot : staged_) {
    if (!slot.used) continue;
    slot.used = false;
    handle_bootstrap_frame(slot, now);
  }
}

void SecurityCoordinator::handle_bootstrap_frame(const StagedFrame& frame,
                                                 const MonotonicMs now) noexcept {
  if (!has_member_engine()) {
    sat_inc(counters_.staged_drops);
    return;
  }
  // Join-relay lanes are Member-only: a dev node runs no proxy/gateway,
  // so anything but the end-session lane drops here.
  const bool member_mode = mode_ == CoordinatorMode::Member;
  const ByteView payload{frame.payload.data(), frame.payload_size};
  switch (frame.type) {
    case FrameType::BootstrapAuth: {
      // Lane routing peek (P4 §7.3): byte 1 is the relay dir (1/2) or the
      // end phase (4/5) — never both. The decoders re-validate fully.
      if (payload.size < 2) {
        sat_inc(counters_.staged_drops);
        return;
      }
      if (payload.data[1] == static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage) ||
          payload.data[1] == static_cast<std::uint8_t>(JoinAuthPhase::Resume)) {
        handle_end_single(frame.meta, payload, now);
        return;
      }
      if (!member_mode) {
        sat_inc(counters_.staged_drops);
        return;
      }
      member().proxy.on_relay_rx(frame.meta.origin, frame.type, payload, now);
      if (member().gateway_active) {
        const std::uint8_t hops =
            frame.meta.hop_remaining > kDefaultHopLimit
                ? 0
                : static_cast<std::uint8_t>(kDefaultHopLimit - frame.meta.hop_remaining);
        member().gateway.on_relay_rx(frame.meta.origin, hops, frame.type, payload, now);
      }
      return;
    }
    case FrameType::MembershipResult:
      // Join-relay Final/Abort only: proxy first (its admission drops
      // foreign frames before any assembly), then the gateway.
      if (!member_mode) {
        sat_inc(counters_.staged_drops);
        return;
      }
      member().proxy.on_relay_rx(frame.meta.origin, frame.type, payload, now);
      if (member().gateway_active) {
        const std::uint8_t hops =
            frame.meta.hop_remaining > kDefaultHopLimit
                ? 0
                : static_cast<std::uint8_t>(kDefaultHopLimit - frame.meta.hop_remaining);
        member().gateway.on_relay_rx(frame.meta.origin, hops, frame.type, payload, now);
      }
      return;
    case FrameType::BootstrapChunk:
    case FrameType::BootstrapReply: {
      // Chunk/reply routing by the lane bit: end-lane subs assemble in
      // the end slot, join-lane subs go proxy-then-gateway. Both relay
      // engines re-check the lane before touching their slots.
      if (payload.size < 2) {
        sat_inc(counters_.demux_drops);
        return;
      }
      if ((payload.data[1] & kEndSubLaneBit) != 0) {
        if (frame.type == FrameType::BootstrapChunk) {
          handle_end_chunk(frame.meta, payload, now);
        } else {
          JoinReply reply{};
          if (join_reply_decode(JoinCarrier::WireRelay, payload, reply).ok() &&
              reply.lane == ObjectLane::EndSession) {
            (void)member().end_tx.on_reply(reply, now);
          } else {
            sat_inc(counters_.demux_drops);
          }
        }
        return;
      }
      if (!member_mode) {
        sat_inc(counters_.staged_drops);
        return;
      }
      member().proxy.on_relay_rx(frame.meta.origin, frame.type, payload, now);
      if (member().gateway_active) {
        const std::uint8_t hops =
            frame.meta.hop_remaining > kDefaultHopLimit
                ? 0
                : static_cast<std::uint8_t>(kDefaultHopLimit - frame.meta.hop_remaining);
        member().gateway.on_relay_rx(frame.meta.origin, hops, frame.type, payload, now);
      }
      return;
    }
    default:
      sat_inc(counters_.staged_drops);
      return;
  }
}

void SecurityCoordinator::handle_end_single(const BootstrapMeta& meta, ByteView payload,
                                            const MonotonicMs now) noexcept {
  EndObject object{};
  if (!end_single_frame_decode(FrameType::BootstrapAuth, payload, object).ok()) {
    sat_inc(counters_.demux_drops);
    return;
  }
  if (object.profile !=
      (mode_ == CoordinatorMode::Dev ? kEndProfileDev : kEndProfileMember)) {
    sat_inc(counters_.demux_drops);
    return;
  }
  // End resume starts admit 10/s burst 4; EDHOC sits behind the engine's
  // ECC gap. The origin stays a claim until the engine verifies it.
  if (object.step == 1 && object.phase == JoinAuthPhase::Resume &&
      !member().budgets.admit_end_resume(now)) {
    sat_inc(counters_.demux_drops);
    return;
  }
  HandshakeRx rx{};
  rx.scope = SecurityScope::EndToEnd;
  rx.phase = static_cast<std::uint8_t>(object.phase);
  rx.step = object.step;
  rx.claimed_peer = meta.origin;
  rx.exchange_id = object.exchange_id;
  (void)member().engine.on_message(rx, object.message, now);
}

void SecurityCoordinator::handle_end_chunk(const BootstrapMeta& meta, ByteView payload,
                                           const MonotonicMs now) noexcept {
  JoinChunk chunk{};
  if (!join_chunk_decode(JoinCarrier::WireRelay, payload, chunk).ok() ||
      chunk.lane != ObjectLane::EndSession) {
    sat_inc(counters_.demux_drops);
    return;
  }
  const JoinObjectSlot::Accepted accepted = member().end_rx.accept(JoinCarrier::WireRelay, chunk, now);
  if (accepted.send_reply) {
    std::array<std::uint8_t, kWireRelayReplySize> body{};
    std::size_t written = 0;
    MessageId id{};
    if (join_reply_encode(JoinCarrier::WireRelay, accepted.reply,
                          MutableByteView{body.data(), body.size()}, written)
            .ok()) {
      (void)deps_.mesh->send_bootstrap(meta.origin, FrameType::BootstrapReply,
                                       ByteView{body.data(), written},
                                       HandshakeEngine::kLinkTimeoutMs, now, id);
    }
  }
  if (accepted.outcome != JoinObjectSlot::Outcome::Complete) {
    if (accepted.outcome == JoinObjectSlot::Outcome::Rejected ||
        accepted.outcome == JoinObjectSlot::Outcome::Busy) {
      sat_inc(counters_.demux_drops);
    }
    return;
  }
  handle_end_single(meta, member().end_rx.assembled(), now);
  // Consumed: free the slot for the next end exchange (same Busy wedge
  // as the link slot above).
  member().end_rx.release_assembled();
}

// --- Sink/port interfaces (owned contexts, never re-entered) -------------------------------
// send_direct/relay_up/relay_abort/send_relay run inside the Coordinator's
// own step (Joiner/proxy/gateway calls made from Poll); on_frame runs in
// the Node's RX path and only stages.

Status SecurityCoordinator::send_direct(const JoinAuthPhase phase, const std::uint8_t step,
                                        const ByteView message) noexcept {
  return deps_.usb->send_local_join_up(phase, step, message);
}

bool SecurityCoordinator::check(const SiteRecord& prepared, const MonotonicMs now) noexcept {
  (void)now;
  // The RLV1 read-only veto: a commit that would resurrect a removed
  // membership is refused before any flash write. No record: allowed.
  const bool holdoff_elapsed = !removal_holdoff_armed_;
  return deps_.local_revocation->check_join(prepared.site_id, prepared.assignment_generation,
                                            holdoff_elapsed)
      .ok();
}

Status SecurityCoordinator::relay_up(const NodeId proxy, const std::uint8_t hops,
                                     const ByteView object) noexcept {
  return deps_.usb->send_relay_up_to_host(proxy, hops, object);
}

Status SecurityCoordinator::relay_abort(const NodeId proxy, const RelayToken token,
                                        const RelayAbortReason reason) noexcept {
  return deps_.usb->send_relay_abort_to_host(proxy, token, reason);
}

Status SecurityCoordinator::send_relay(const NodeId destination, const FrameType type,
                                       const ByteView payload) noexcept {
  if (mode_ != CoordinatorMode::Member) {
    return Status::error(StatusCode::InvalidState, "relay outside member");
  }
  const NodeId self = member_valid_ ? adopted_.node : deps_.local_node;
  if (destination == self || destination == deps_.local_node) {
    // Proxy and gateway on one device: loop back without touching the
    // radio. Both engines re-check direction, so feeding both is safe —
    // the foreign one drops via its own admission.
    member().proxy.on_relay_rx(self, type, payload, last_now_);
    if (member().gateway_active) member().gateway.on_relay_rx(self, 0, type, payload, last_now_);
    return Status::success();
  }
  MessageId id{};
  return deps_.mesh->send_bootstrap(destination, type, payload, HandshakeEngine::kLinkTimeoutMs,
                                    last_now_, id);
}

// --- Engine evidence views -----------------------------------------------------------------
// Read fresh at every entry and every commit; false/closed on anything
// unprovable.

bool SecurityCoordinator::local(HandshakeLocal& out) const noexcept {
  out = HandshakeLocal{};
  if (mode_ != CoordinatorMode::Member || !member_valid_) return false;
  if (!deps_.site->has_site() || !deps_.identity->has_identity()) return false;
  const SiteRecord& site = deps_.site->site();
  const IdentityRecord& identity = deps_.identity->identity();
  if (site.network != adopted_.network || identity.node_id != adopted_.node) return false;
  if (site.member_cert.size == 0) return false;  // validated stores carry it
  out.self = adopted_.node;
  out.network = adopted_.network;
  out.site_id = site.site_id;
  out.site_epoch = static_cast<std::uint32_t>(site.network >> 32);
  out.rs_epoch = site.rs_epoch_floor;
  out.gk_epoch = site.gk_epoch_current;
  out.generation = site.assignment_generation;
  out.role = site.role;
  out.caps = kRld1CapMemberEdhocV1 | kRld1CapMemberResumeV1;  // production pair, no DevRam
  out.boot = adopted_.boot_session;
  ScopeDigest digest{};
  sha256(site.member_cert.view(), digest);
  std::memcpy(out.local_cert_id.data(), digest.data(), out.local_cert_id.size());
  return true;
}

bool SecurityCoordinator::revoked(const NodeId peer, const std::uint32_t generation) const noexcept {
  // The shared Owner gate (P4 §10.1): the dev-armed engine consults this
  // at R1/R3 time with generation 0, exactly like the member engine. The
  // RLV1 record itself is enforced by the hooks + mode, not here.
  if (!has_member_engine() || !member_valid_) return false;
  if (!deps_.revocations->has_set()) return false;  // no set: nothing revoked
  const std::uint32_t site_epoch = static_cast<std::uint32_t>(adopted_.network >> 32);
  return deps_.revocations->rejects(peer, generation, site_epoch);
}

bool SecurityCoordinator::authenticated(const NodeId peer, const NetworkId network,
                                        std::uint32_t& generation,
                                        std::uint32_t& role) const noexcept {
  generation = 0;
  role = 0;
  // Only a live bank entry counts: the bank is RAM-only (empty before the
  // first install, wiped on site change), so a hit proves a completed
  // authentication of this boot. Caches, the shared GK and RLP names fail.
  // In Dev mode the hit proves "same PSK" (generation 0, policy role).
  if (!has_member_engine() || !member_valid_) return false;
  if (network != adopted_.network) return false;
  if (bank_.peer_summary(SecurityScope::Link, peer, generation, role)) return true;
  return bank_.peer_summary(SecurityScope::EndToEnd, peer, generation, role);
}

bool SecurityCoordinator::authenticated_link(const NodeId peer, const NetworkId network,
                                             std::uint32_t& generation,
                                             std::uint32_t& role) const noexcept {
  generation = 0;
  role = 0;
  return mode_ == CoordinatorMode::Member && member_valid_ &&
         network == adopted_.network &&
         bank_.peer_summary(SecurityScope::Link, peer, generation, role);
}

bool SecurityCoordinator::boot_witness_ok(const std::uint32_t witness) const noexcept {
  // A stored membership newer than the rlboot counter is implausible; a
  // zero witness never authenticates.
  return witness != 0 && witness <= boot_witness_;
}

// --- USB / channel / sleep legs --------------------------------------------------------------

Status SecurityCoordinator::on_usb(const CoordinatorEvent& event) noexcept {
  // Every down leg returns queue admission synchronously; the USB bridge
  // maps it to the 0x63 verdict. Sleeping still answers (refused): the
  // host must not block on a parked device.
  if (sleeping_) return Status::error(StatusCode::Busy, "coordinator sleeping");
  switch (event.kind) {
    case CoordinatorEventKind::UsbLocalDown: {
      // One LocalJoin down message for the direct run (the USB 0x61 body
      // after the adapter unwraps it).
      if (mode_ != CoordinatorMode::ZeroTouch || !usb_direct_) {
        sat_inc(counters_.usb_drops);
        return Status::error(StatusCode::InvalidState, "no direct attempt");
      }
      const Status fed =
          joiner().on_direct_message(event.usb_phase, event.usb_step, event.usb_body, event.now);
      if (!fed.ok()) sat_inc(counters_.usb_drops);
      return fed;
    }
    case CoordinatorEventKind::UsbRelayDown: {
      // USB 0x61 for a mesh proxy: queue admission only, never device
      // commit.
      if (mode_ != CoordinatorMode::Member || !member().gateway_active) {
        sat_inc(counters_.usb_drops);
        return Status::error(StatusCode::InvalidState, "no gateway here");
      }
      const Status admitted =
          member().gateway.host_down(event.usb_proxy, event.usb_object, event.now);
      if (!admitted.ok()) sat_inc(counters_.usb_drops);
      return admitted;
    }
    case CoordinatorEventKind::UsbRelayAbort: {
      // USB 0x62 (only HostAborted arrives from the host; anything else
      // the adapter already refused). Unknown tokens answer NotFound.
      if (mode_ != CoordinatorMode::Member || !member().gateway_active) {
        sat_inc(counters_.usb_drops);
        return Status::error(StatusCode::InvalidState, "no gateway here");
      }
      if (event.usb_reason != static_cast<std::uint8_t>(RelayAbortReason::HostAborted)) {
        sat_inc(counters_.usb_drops);
        return Status::error(StatusCode::InvalidArgument, "host abort reason");
      }
      RelayToken token{};
      token.gateway_epoch = event.usb_gateway_epoch;
      token.proxy_epoch = event.usb_proxy_epoch;
      token.relay_id = event.usb_relay_id;
      const Status aborted = member().gateway.host_abort(event.usb_proxy, token, event.now);
      if (!aborted.ok()) sat_inc(counters_.usb_drops);
      return aborted;
    }
    case CoordinatorEventKind::UsbSessionDown: {
      // USB disconnect: USB-bound state drops, never reused. A direct
      // join run dies with its transport; the firmware re-boots (radio)
      // or stops from the Stopped snapshot. Gateway relays abort
      // themselves: the USB port refuses their ups from here on. The
      // authority channel suspends with the session (only USB-gateway
      // builds see this event, and their channel rides USB directly);
      // UsbSessionUp restarts it.
      if (mode_ == CoordinatorMode::ZeroTouch && usb_direct_) {
        (void)joiner().stop(event.now);
      }
      suspend_authority();
      return Status::success();
    }
    default:
      return Status::error(StatusCode::InvalidArgument, "not a usb event");
  }
}

Status SecurityCoordinator::on_channel_ready(const CoordinatorEvent& event) noexcept {
  if (tune_outstanding_ != 0) {
    if (event.channel_token != tune_outstanding_) return Status::success();  // stale
    tune_outstanding_ = 0;
    channel_ = event.channel;
    radio_generation_ = event.channel_generation;
    if (mode_ != CoordinatorMode::ZeroTouch) return Status::success();
    const Status result = event.channel_result == StatusCode::Ok
                              ? Status::success()
                              : Status::error(event.channel_result, "tune failed");
    return joiner().on_channel_ready(event.channel_token, result, event.now);
  }
  // The first member report proves the node and radio reached the adopted
  // operating channel. Discovery cannot start on the join channel. The
  // dev route reports the same token-0 apply completion (already on its
  // static channel, so the move is a no-op there).
  if (!has_member_engine() || !member_apply_pending_ || event.channel_token != 0) {
    return Status::success();
  }
  member_apply_pending_ = false;
  if (event.channel_result != StatusCode::Ok || event.channel != channel_) {
    stop_traffic();
    destroy_workspace();
    // Leaving Dev rebuilds the small side (stop_traffic above destroyed
    // the dev side); everywhere else it never left.
    if (mode_ == CoordinatorMode::Dev) create_small();
    mode_ = CoordinatorMode::Recovery;
    CoordinatorAction recovery{};
    recovery.kind = CoordinatorActionKind::ReportRecovery;
    recovery.recovery = JoinRecoveryReason::RadioFailure;
    emit_action(recovery);
    return Status::success();
  }
  channel_ = event.channel;
  radio_generation_ = event.channel_generation;
  return Status::success();
}

Status SecurityCoordinator::on_prepare_sleep(const MonotonicMs now) noexcept {
  (void)now;
  // Busy while the firmware still owes a take_action or the workspace has
  // work; else park until the caller saves or aborts the image.
  if (action_pending_ || !quiescent_locked()) {
    return Status::error(StatusCode::Busy, "coordinator has work");
  }
  sleeping_ = true;
  sat_inc(counters_.sleep_parks);
  return Status::success();
}

Status SecurityCoordinator::on_wake(const MonotonicMs now) noexcept {
  (void)now;
  sleeping_ = false;
  // The retained image (if any was saved) is stale from here on: the
  // firmware invalidates the port on the abort path, and a retained-wake
  // continuation runs on live bank counters — never on write-ahead.
  sleep_guard_.disarm();
  return Status::success();
}

bool SecurityCoordinator::first_live_peer(const SecurityScope scope, NodeId& peer) const noexcept {
  return bank_.first_live_peer(scope, peer);
}

Status SecurityCoordinator::save_sleep_image(RtcSessionPort& port, const NodeId parent,
                                             const MacAddress& parent_mac,
                                             const std::uint32_t parent_binding,
                                             const MonotonicMs now) noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entered");
  if (deps_.sleep_image == nullptr) {
    return Status::error(StatusCode::Unsupported, "sleep image storage unavailable");
  }
  if (mode_ != CoordinatorMode::Member || !member_valid_) {
    return Status::error(StatusCode::InvalidState, "sleep save without adoption");
  }
  if (!sleeping_) {
    return Status::error(StatusCode::InvalidState, "sleep save without park");
  }
  if (now < last_now_) {
    return Status::error(StatusCode::TimeUncertain, "coordinator clock regressed");
  }
  // The park is stale the moment new work lands: an untaken action, an
  // outstanding tune, a staged end frame, a fresh bank demand, or a live
  // handshake leg aborts the attempt — the firmware wakes and retries.
  if (action_pending_ || tune_outstanding_ != 0 || member_apply_pending_ ||
      member_work_pending()) {
    return Status::error(StatusCode::Busy, "coordinator has work");
  }
  for (const auto& staged : staged_) {
    if (staged.used) return Status::error(StatusCode::Busy, "coordinator has work");
  }
  if (parent == kInvalidNodeId || parent == kBroadcastNodeId || parent_binding == 0 ||
      parent_mac == MacAddress{} || parent_mac == discovery_const::kBroadcastMac) {
    return Status::error(StatusCode::InvalidArgument, "sleep save parent shape");
  }
  if (!deps_.site->has_site() || !deps_.identity->has_identity()) {
    return Status::error(StatusCode::InvalidState, "sleep save without membership");
  }
  const Status ticked = bank_.tick(now);
  if (!ticked) return ticked;
  last_now_ = now;
  RtcSessionImage image{};
  image.source_boot = boot_witness_;
  const SiteRecord& site = deps_.site->site();
  image.network = site.network;
  image.local_generation = site.assignment_generation;
  image.site_commit = deps_.site->commit_seq();
  image.gk_epoch = site.gk_epoch_current;
  image.rs_floor = site.rs_epoch_floor;
  const IdentityRecord& identity = deps_.identity->identity();
  for (std::size_t i = 0; i < image.kid_digest.size(); ++i) {
    image.kid_digest[i] = identity.kid[i];
  }
  image.parent_mac = parent_mac;
  image.parent_binding = parent_binding;
  const Status link =
      bank_.export_sleep_entry(SecurityScope::Link, parent, image.contexts[0].entry);
  if (!link) {
    secure_clear(&image, sizeof(image));
    return link;
  }
  image.contexts[0].scope = SecurityScope::Link;
  image.count = 1;
  NodeId end_peer = kInvalidNodeId;
  if (bank_.first_live_peer(SecurityScope::EndToEnd, end_peer) &&
      bank_.export_sleep_entry(SecurityScope::EndToEnd, end_peer, image.contexts[1].entry).ok()) {
    image.contexts[1].scope = SecurityScope::EndToEnd;
    image.count = 2;
  }
  std::array<std::uint8_t, kRtcSessionRecordSize> encoded{};
  const Status shaped =
      encode_rtc_session(image, MutableByteView{encoded.data(), encoded.size()});
  if (!shaped) {
    secure_clear(&image, sizeof(image));
    secure_clear(encoded);
    return shaped;
  }
  const Status written = port.write(ByteView{encoded.data(), encoded.size()});
  secure_clear(encoded);
  if (!written) {
    secure_clear(&image, sizeof(image));
    return written;
  }
  // A save supersedes the restore the guard still tracks (sleep, wake,
  // sleep in one boot): re-arm over the fresh image so the next issue
  // compares against what the port now holds. A re-arm failure retires
  // the saved entries — their counters must never TX without write-ahead.
  if (sleep_guard_.armed()) {
    sleep_guard_.disarm();
    // The guard borrows its image from caller-stable storage: re-home
    // the fresh image in the held slot (the disarm above wiped the armed
    // image it replaces) before re-arming over it.
    *deps_.sleep_image = image;
    const Status rearmed = sleep_guard_.arm(port, *deps_.sleep_image);
    if (!rearmed) {
      for (std::size_t i = 0; i < image.count; ++i) {
        (void)bank_.retire(image.contexts[i].scope, image.contexts[i].entry.peer);
      }
      // The refused image is not armed: leave no key material behind.
      secure_clear(deps_.sleep_image, sizeof(*deps_.sleep_image));
    }
    secure_clear(&image, sizeof(image));
    return rearmed;
  }
  secure_clear(&image, sizeof(image));
  return Status::success();
}

Status SecurityCoordinator::fail_restore(const Status& status) noexcept {
  if (deps_.sleep_image != nullptr) {
    secure_clear(deps_.sleep_image, sizeof(*deps_.sleep_image));
  }
  restore_holding_ = false;
  restore_failed_ = true;
  restore_error_ = status;
  return status;
}

Status SecurityCoordinator::restore_sleep_image(RtcSessionPort& port, const std::uint32_t next_boot,
                                                const std::uint32_t trusted_elapsed_ms,
                                                const bool deep_sleep,
                                                const bool sleep_marker) noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entered");
  if (restore_done_) return Status::success();
  if (restore_failed_) return restore_error_;
  if (deps_.sleep_image == nullptr) {
    return Status::error(StatusCode::Unsupported, "sleep image storage unavailable");
  }
  if (mode_ != CoordinatorMode::Member || !member_valid_ || sleeping_) {
    return Status::error(StatusCode::Busy, "sleep restore not ready");
  }
  if (next_boot != boot_witness_) {
    return fail_restore(Status::error(StatusCode::InvalidArgument, "sleep restore boot mismatch"));
  }
  if (!restore_holding_) {
    RtcWakeCheck wake{};
    wake.deep_sleep = deep_sleep;
    wake.sleep_marker = sleep_marker;
    wake.trusted_elapsed_ms = trusted_elapsed_ms;
    wake.next_boot = next_boot;
    wake.network = adopted_.network;
    if (deps_.site->has_site() && deps_.identity->has_identity()) {
      const SiteRecord& site = deps_.site->site();
      wake.local_generation = site.assignment_generation;
      wake.site_commit = deps_.site->commit_seq();
      wake.gk_epoch = site.gk_epoch_current;
      wake.rs_floor = site.rs_epoch_floor;
      const IdentityRecord& identity = deps_.identity->identity();
      for (std::size_t i = 0; i < wake.kid_digest.size(); ++i) {
        wake.kid_digest[i] = identity.kid[i];
      }
    }
    // Without a durable membership (dev adoption) the check stays zeroed:
    // zeros can never match a member image's nonzero generation/commit,
    // so dev always resumes cold through RLRES1 instead.
    const Status consumed = consume_rtc_session(port, wake, *deps_.sleep_image);
    if (!consumed) return fail_restore(consumed);
    restore_holding_ = true;
    restore_elapsed_ms_ = trusted_elapsed_ms;
  }
  // The wake evidence is per-boot, but the elapsed bound grows while the
  // parent re-binds: re-apply positive deltas so the installed image is
  // always deducted to the latest bound. A delta that outlives any held
  // context fails the restore instead of installing an over-credited one.
  if (trusted_elapsed_ms > restore_elapsed_ms_) {
    const std::uint32_t delta = trusted_elapsed_ms - restore_elapsed_ms_;
    for (std::size_t i = 0; i < deps_.sleep_image->count; ++i) {
      SessionBankEntry& entry = deps_.sleep_image->contexts[i].entry;
      if (delta >= entry.remaining_ms) {
        return fail_restore(
            Status::error(StatusCode::IntegrityError, "sleep restore elapsed"));
      }
      entry.remaining_ms -= delta;
    }
    restore_elapsed_ms_ = trusted_elapsed_ms;
  }
  // The parent must have re-bound post-wake with the same radio MAC the
  // image names: a context without its radio peer is never sendable.
  const NodeId parent = deps_.sleep_image->contexts[0].entry.peer;
  NeighborDiscovery* const discovery = deps_.discovery;
  MacAddress observed{};
  BindingId live{kInvalidBindingId};
  if (discovery == nullptr || !discovery->binding_of(parent, live) ||
      !discovery->mac_of(parent, observed)) {
    return Status::error(StatusCode::Busy, "sleep restore parent unbound");
  }
  if (!rtc_parent_warm_ok(*deps_.sleep_image, observed, true)) {
    return fail_restore(
        Status::error(StatusCode::AuthorizationFailed, "sleep restore parent changed"));
  }
  // The adoption must still hold locally (RLV1, floors, store health)
  // and neither restored peer may have been revoked since.
  MembershipState local_state = MembershipState::Unprovisioned;
  const Status local_status = hooks_.local_state(adopted_.network, local_state);
  if (!local_status || local_state != MembershipState::Member) {
    return fail_restore(
        Status::error(StatusCode::AuthorizationFailed, "sleep restore membership lost"));
  }
  for (std::size_t i = 0; i < deps_.sleep_image->count; ++i) {
    const SessionBankEntry& entry = deps_.sleep_image->contexts[i].entry;
    if (revoked(entry.peer, entry.peer_generation)) {
      return fail_restore(
          Status::error(StatusCode::AuthorizationFailed, "sleep restore peer revoked"));
    }
  }
  const Status link =
      bank_.restore_entry(SecurityScope::Link, parent, deps_.sleep_image->contexts[0].entry);
  if (!link) return fail_restore(link);  // occupied: a newer context stands; resume instead
  if (deps_.sleep_image->count == 2) {
    // Best-effort: the end leg resumes through demand when the slot is
    // taken or stale — the warm link is unaffected.
    (void)bank_.restore_entry(SecurityScope::EndToEnd, deps_.sleep_image->contexts[1].entry.peer,
                              deps_.sleep_image->contexts[1].entry);
  }
  // Re-base the image to this boot before the guard commits it: the wake
  // chain proves "no boot skipped" (source + 1 == next), and the armed
  // port image is this boot's commit — a power cut without a second save
  // then consumes it on the next wake instead of failing the chain.
  deps_.sleep_image->source_boot = boot_witness_;
  const Status armed = sleep_guard_.arm(port, *deps_.sleep_image);
  const std::uint8_t restored_count = deps_.sleep_image->count;
  const NodeId end_peer =
      restored_count == 2 ? deps_.sleep_image->contexts[1].entry.peer : kInvalidNodeId;
  // The armed image stays: the guard borrows this slot from here on and
  // wipes it on disarm. The hold itself is over either way.
  restore_holding_ = false;
  if (!armed) {
    // Installed but unwritable: undo the install — restored counters
    // must never TX without write-ahead — and resume instead.
    (void)bank_.retire(SecurityScope::Link, parent);
    if (restored_count == 2) (void)bank_.retire(SecurityScope::EndToEnd, end_peer);
    return fail_restore(armed);
  }
  restore_done_ = true;
  return Status::success();
}

Status SecurityCoordinator::on_stop(const MonotonicMs now,
                                     const bool defer_resume_clear) noexcept {
  (void)now;
  if (has_member_engine()) {
    // stop_traffic reads the state; unattached (pre-Start) relays stop
    // as revoked.
    if (deps_.discovery != nullptr) {
      deps_.discovery->membership() = MembershipController{};
    }
    stop_traffic(!defer_resume_clear);
  }
  suspend_authority();
  {
    // Full stop: the GK state parks (counters and windows stay in RAM
    // for the boot; the next adoption rebinds or keeps the binding).
    GroupKeyState::Input stop{};
    stop.op = GroupKeyState::Op::Stop;
    (void)group_keys_.advance(stop, now);
  }
  destroy_workspace();  // wipes the live side (joiner or member)
  // Leaving Dev rebuilds the small side (stop_traffic above destroyed
  // the dev side); everywhere else it never left.
  if (mode_ == CoordinatorMode::Dev) create_small();
  for (auto& slot : staged_) slot = StagedFrame{};
  action_ = CoordinatorAction{};
  action_pending_ = false;
  authority_wanted_ = false;
  join_confirmed_ = false;
  refresh_active_ = false;
  refresh_strikes_ = 0;
  last_unknown_generation_ = 0;
  adopted_ = CoordinatorMemberConfig{};
  member_valid_ = false;
  tune_outstanding_ = 0;
  channel_ = 0;
  sleeping_ = false;
  usb_direct_ = false;
  discovery_started_ = false;
  member_apply_pending_ = false;
  hooks_.set_holdoff_elapsed(false);
  removal_holdoff_armed_ = false;
  // Restore is per-boot: a stopped coordinator forgets the held image
  // and any terminal verdict with it.
  if (deps_.sleep_image != nullptr) {
    secure_clear(deps_.sleep_image, sizeof(*deps_.sleep_image));
  }
  restore_holding_ = false;
  restore_done_ = false;
  restore_failed_ = false;
  restore_elapsed_ms_ = 0;
  restore_error_ = Status{StatusCode::Ok, "ok"};
  mode_ = CoordinatorMode::Fresh;
  return Status::success();
}

// --- Authority channel (G-SEC P5) ----------------------------------------------------------------

Status SecurityCoordinator::send_authority_typed(const std::uint8_t type,
                                                 const ByteView body,
                                                 const MonotonicMs now) noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
  if (mode_ != CoordinatorMode::Member || !member_valid_ || sleeping_) {
    return Status::error(StatusCode::InvalidState, "authority outside active member");
  }
  if (now < last_now_) return Status::error(StatusCode::TimeUncertain, "coordinator clock regressed");
  in_port_ = true;
  AuthorityInput input{};
  input.kind = AuthorityInputKind::SendTyped;
  input.typed.type = type;
  input.typed.body = body;
  const Status status = small().authority.advance(input, now);
  if (status) last_now_ = now;
  in_port_ = false;
  return status;
}

namespace {

constexpr std::uint8_t kRefreshStrikesMax = 3;
constexpr MonotonicMs kRefreshAbandonMs = 300000;   // 5 min without MemberReady
constexpr MonotonicMs kRefreshCooldownMs = 600000;  // 10 min after an abandoned refresh
constexpr MonotonicMs kAuthorityStartRetryMs = 1000;

}  // namespace

Status SecurityCoordinator::on_authority_rx(const CoordinatorEvent& event) noexcept {
  if (mode_ != CoordinatorMode::Member || sleeping_) return Status::success();
  if (!small().authority.snapshot().started) return Status::success();  // stale carrier
  AuthorityInput in{};
  in.kind = AuthorityInputKind::RxCarrier;
  in.rx.kind = event.auth_kind;
  in.rx.bytes = event.auth_bytes;
  in.rx.writable = event.auth_writable;
  return small().authority.advance(in, event.now);
}

Status SecurityCoordinator::on_authority_tx(const CoordinatorEvent& event) noexcept {
  if (mode_ != CoordinatorMode::Member || sleeping_) return Status::success();
  if (!small().authority.snapshot().started) return Status::success();
  AuthorityInput in{};
  in.kind = AuthorityInputKind::TxResult;
  in.tx.token = event.auth_token;
  in.tx.delivered = event.auth_delivered;
  return small().authority.advance(in, event.now);
}

Status SecurityCoordinator::on_request_pull(const CoordinatorEvent& event) noexcept {
  if (mode_ != CoordinatorMode::Member || sleeping_) return Status::success();
  if (!small().authority.snapshot().started) {
    // Not started yet: the adoption pull covers the first sync; a later
    // want restarts the channel and pulls then.
    authority_wanted_ = true;
    return Status::success();
  }
  if (event.pull_reason < 1 || event.pull_reason > 3) {
    return Status::error(StatusCode::InvalidArgument, "pull reason");
  }
  AuthorityInput in{};
  in.kind = AuthorityInputKind::RequestPull;
  in.pull.reason = static_cast<PullReason>(event.pull_reason);
  return small().authority.advance(in, event.now);
}

Status SecurityCoordinator::on_usb_session_up(const MonotonicMs now) noexcept {
  if (mode_ != CoordinatorMode::Member || sleeping_) return Status::success();
  // A gateway's own channel rides the USB session directly: it suspended
  // on the way down and restarts now. Mesh devices never see this event.
  authority_wanted_ = true;
  drive_authority(now);
  return Status::success();
}

bool SecurityCoordinator::build_authority_start(AuthorityStart& out) const noexcept {
  out = AuthorityStart{};
  if (!member_valid_ || deps_.site == nullptr || !deps_.site->has_site()) return false;
  const SiteRecord& site = deps_.site->site();
  // The carrier route address: the first listed route gateway that is not
  // us; ourselves when we are the only (gateway) route. The client
  // re-checks the binding against the durable record; fail fast here.
  NodeId gateway = kInvalidNodeId;
  for (std::size_t i = 0; i < adopted_.route_gateway_count; ++i) {
    const NodeId candidate = adopted_.route_gateways[i];
    if (candidate != kInvalidNodeId && candidate != kBroadcastNodeId &&
        candidate != adopted_.node) {
      gateway = candidate;
      break;
    }
  }
  if (gateway == kInvalidNodeId) {
    for (std::uint8_t i = 0; i < site.gateway_count; ++i) {
      if (site.gateways[i] == adopted_.node) gateway = adopted_.node;
    }
    if (gateway == kInvalidNodeId) return false;
  }
  bool listed = false;
  for (std::uint8_t i = 0; i < site.gateway_count; ++i) listed = listed || site.gateways[i] == gateway;
  if (!listed) return false;
  out.network = site.network;
  out.self = adopted_.node;
  out.site_id = site.site_id;
  out.gateway = gateway;
  out.dams = site.dams;
  out.generation = site.assignment_generation;
  out.epochs.site_epoch = static_cast<std::uint32_t>(site.network >> 32);
  out.epochs.rs_epoch = site.rs_epoch_floor;
  out.epochs.gk_epoch = site.gk_epoch_current;
  sha256(ByteView{site.member_cert.bytes.data(), site.member_cert.size},
         out.member_cert_hash);
  out.boot = adopted_.boot_session;
  out.gk_current = site.gk_epoch_current;
  out.gk_next = site.gk_epoch_next;
  return true;
}

void SecurityCoordinator::suspend_authority() noexcept {
  // No channel exists in Dev (see snapshot): suspending is a no-op there.
  if (mode_ == CoordinatorMode::Dev) return;
  if (!small().authority.snapshot().started) return;
  AuthorityInput in{};
  in.kind = AuthorityInputKind::Suspend;
  (void)small().authority.advance(in, last_now_);
}

void SecurityCoordinator::drive_authority(const MonotonicMs now) noexcept {
  if (mode_ != CoordinatorMode::Member) return;
  // The GK tick first: a promote the provider armed completes before the
  // channel answers anything above it. A blocked store refuses here and
  // the provider/users see it; the channel keeps reporting honestly.
  GroupKeyState::Input tick{};
  tick.op = GroupKeyState::Op::Tick;
  (void)group_keys_.advance(tick, now);
  AuthorityInput poll{};
  poll.kind = AuthorityInputKind::Tick;
  (void)small().authority.advance(poll, now);
  if (authority_wanted_ && !small().authority.snapshot().started &&
      now - last_authority_start_ >= kAuthorityStartRetryMs) {
    last_authority_start_ = now;
    AuthorityStart start{};
    if (!build_authority_start(start)) return;
    AuthorityInput begin{};
    begin.kind = AuthorityInputKind::Start;
    begin.start = start;
    if (!small().authority.advance(begin, now)) return;
    // The first sync rides the new channel immediately (one Pull; the
    // client's own bucket paces any more).
    AuthorityInput pull{};
    pull.kind = AuthorityInputKind::RequestPull;
    pull.pull.reason = PullReason::BootReconnectSync;
    (void)small().authority.advance(pull, now);
  }
}

void SecurityCoordinator::on_event(const AuthorityEvent& event) noexcept {
  // Channel context: count, never drive (no advance from the callback).
  switch (event.kind) {
    case AuthorityEvent::Kind::ChannelReady:
      sat_inc(counters_.authority_ready);
      break;
    case AuthorityEvent::Kind::ChannelLost:
      sat_inc(counters_.authority_lost);
      break;
    case AuthorityEvent::Kind::JoinConfirmAck:
      sat_inc(counters_.authority_confirmed);
      join_confirmed_ = true;
      break;
    case AuthorityEvent::Kind::UpdateReceived:
      sat_inc(counters_.authority_updates);
      break;
    case AuthorityEvent::Kind::ActivateReceived:
      sat_inc(counters_.authority_activates);
      break;
    case AuthorityEvent::Kind::Passthrough:
      sat_inc(counters_.authority_passthrough);
      if (deps_.authority_sink != nullptr && event.envelope_type >= 5 &&
          event.envelope_type <= 7) {
        deps_.authority_sink->on_verified_authority(event.envelope_type, event.passthrough);
      }
      break;
  }
}

// --- Stale-GK refresh (P5 §7.4) -------------------------------------------------------------------
// A member whose GK fell behind cannot pass Member discovery at all: the
// neighbors silently drop its DISCOVERs. Evidence accrues only while no
// usable link exists — a lone node with quiet neighbors never refreshes
// on linklessness alone. Three strikes (failed re-establishes and
// discovery rounds that observed unknown generations) tear the member
// engine down around the retained RLS1 and re-verify the same site over
// the ZT lane; ordinary DATA admission has no engine to admit through
// while the refresh runs. A refresh that cannot re-verify abandons back
// to the retained membership instead of wedging in ZeroTouch.

void SecurityCoordinator::note_link_established() noexcept { refresh_strikes_ = 0; }

void SecurityCoordinator::note_link_failed() noexcept {
  if (mode_ != CoordinatorMode::Member || !discovery_started_) return;
  if (bank_.live_count(SecurityScope::Link) != 0) return;  // per-peer flake
  if (refresh_strikes_ < kRefreshStrikesMax) ++refresh_strikes_;
}

void SecurityCoordinator::watch_linkless(const MonotonicMs now) noexcept {
  if (mode_ != CoordinatorMode::Member || !discovery_started_) return;
  if (bank_.live_count(SecurityScope::Link) != 0) {
    refresh_strikes_ = 0;
    if (deps_.discovery != nullptr) {
      last_unknown_generation_ = deps_.discovery->scope_stats().unknown_generation;
    }
    return;
  }
  // Link failures can arrive while draining engine results. Keep that
  // workspace live until the member poll reaches this boundary.
  if (refresh_strikes_ >= kRefreshStrikesMax) {
    start_refresh(now);
    return;
  }
  if (deps_.discovery == nullptr) return;
  const std::uint32_t unknown = deps_.discovery->scope_stats().unknown_generation;
  if (unknown != last_unknown_generation_) {
    // Fresh unknown-generation observations while linkless: one strike
    // per poll at most (a flood still counts once).
    last_unknown_generation_ = unknown;
    if (refresh_strikes_ < kRefreshStrikesMax) ++refresh_strikes_;
    if (refresh_strikes_ >= kRefreshStrikesMax) start_refresh(now);
  }
}

void SecurityCoordinator::start_refresh(const MonotonicMs now) noexcept {
  if (mode_ != CoordinatorMode::Member || refresh_active_) return;
  if (now < refresh_cooldown_until_) {
    refresh_strikes_ = 0;  // cooling down: the evidence waits
    return;
  }
  // The channel suspends (its DAMS copy wipes); the GK state stays live
  // so counters and replay windows survive the engine swap. RLS1 is
  // retained untouched — the refresh only re-verifies it.
  suspend_authority();
  authority_wanted_ = true;
  destroy_workspace();
  create_joiner();
  const JoinBootInput boot{boot_witness_, true, JoinBootMode::VerifyExistingMembership};
  const Status started =
      usb_direct_ ? joiner().start_direct(boot, *this, now) : joiner().start(boot, now);
  if (!started) {
    // No refresh leg possible: stay a member (the engine is already
    // gone, but the stores, bank and GK state are intact and the next
    // strikes re-arm from zero).
    destroy_workspace();
    create_member();
    mode_ = CoordinatorMode::Member;
    refresh_strikes_ = 0;
    refresh_cooldown_until_ = now > kJoinNoDeadline - kRefreshCooldownMs
                                  ? kJoinNoDeadline
                                  : now + kRefreshCooldownMs;
    return;
  }
  mode_ = CoordinatorMode::ZeroTouch;
  refresh_active_ = true;
  refresh_start_ = now;
  refresh_strikes_ = 0;
  sat_inc(counters_.refreshes);
}

void SecurityCoordinator::maybe_abandon_refresh(const MonotonicMs now) noexcept {
  if (!refresh_active_ || mode_ != CoordinatorMode::ZeroTouch) return;
  if (now - refresh_start_ < kRefreshAbandonMs) return;
  // Five minutes without MemberReady: re-verification is impossible
  // (host down, out of range, attacker-triggered). A healthy retained
  // membership re-adopts instead of wedging in ZeroTouch; an impaired
  // store stays with the joiner (it heals or reports RecoveryRequired).
  const SiteStoreHealth health = deps_.site->health();
  const bool healthy = deps_.site->has_site() && health.unsupported_mask == 0 &&
                       health.read_error_mask == 0 && !health.active_load_failed &&
                       !health.quarantined && !health.uncertain;
  if (!healthy) return;
  refresh_active_ = false;
  refresh_cooldown_until_ = now > kJoinNoDeadline - kRefreshCooldownMs
                                ? kJoinNoDeadline
                                : now + kRefreshCooldownMs;
  (void)adopt_boot_rls1(now);
}

// --- MemberReady adoption --------------------------------------------------------------------

Status SecurityCoordinator::adopt_member(const JoinAction& ready, const MonotonicMs now) noexcept {
  if (mode_ != CoordinatorMode::ZeroTouch) {
    return Status::error(StatusCode::InvalidState, "member ready outside zt");
  }
  // Preserve the verified package's RS target through member config adoption.
  return adopt_boot_rls1(now, ready.rs_epoch_to_fetch);
}

Status SecurityCoordinator::adopt_boot_rls1(const MonotonicMs now,
                                            const std::uint32_t rs_epoch_to_fetch) noexcept {
  const auto to_recovery = [&](const JoinRecoveryReason reason) {
    destroy_workspace();  // Recovery holds no workspace side
    mode_ = CoordinatorMode::Recovery;
    CoordinatorAction action{};
    action.kind = CoordinatorActionKind::ReportRecovery;
    action.recovery = reason;
    emit_action(action);
  };
  if (!deps_.site->has_site() || !deps_.identity->has_identity()) {
    to_recovery(JoinRecoveryReason::MembershipInvalid);
    return Status::success();
  }
  const SiteRecord& site = deps_.site->site();
  const IdentityRecord& identity = deps_.identity->identity();
  if (!boot_witness_ok(site.boot_witness)) {
    to_recovery(JoinRecoveryReason::BootWitnessMismatch);
    return Status::success();
  }
  if (identity.node_id == kInvalidNodeId || identity.node_id == kBroadcastNodeId ||
      site.network == 0 || (site.network & 0xFFFFFFFFU) == 0) {
    to_recovery(JoinRecoveryReason::MembershipInvalid);
    return Status::success();
  }
  return install_member_config(site, identity, site.boot_witness, now, rs_epoch_to_fetch);
}

Status SecurityCoordinator::install_member_config(const SiteRecord& site,
                                                  const IdentityRecord& identity,
                                                  const std::uint32_t boot_session,
                                                  const MonotonicMs now,
                                                  const std::uint32_t rs_epoch_to_fetch) noexcept {
  if (boot_session == 0) return Status::error(StatusCode::InvalidArgument, "zero boot session");
  CoordinatorMemberConfig cfg{};
  cfg.network = site.network;
  cfg.rs_epoch_to_fetch = rs_epoch_to_fetch;
  cfg.node = identity.node_id;
  cfg.channel = site.channel;
  // The message session names this boot on the mesh: entropy-drawn when
  // the RNG answers, else the rlboot witness (durable, nonzero, distinct
  // per boot). The node refuses 0 either way.
  std::uint32_t session = 0;
  if (!entropy_fill(deps_.entropy, reinterpret_cast<std::uint8_t*>(&session), sizeof(session)) ||
      session == 0) {
    session = boot_session;
  }
  cfg.message_session = session;
  cfg.boot_session = boot_session;
  cfg.link_epoch = 1;  // configured defaults; the session provider stamps
  cfg.end_epoch = 1;   // the live per-peer epochs over these
  std::uint64_t incarnation = 0;
  if (!entropy_fill(deps_.entropy, reinterpret_cast<std::uint8_t*>(&incarnation),
                    sizeof(incarnation))) {
    incarnation = 0;  // unset: hosts treat boot attribution as unknown
  }
  cfg.boot_incarnation = incarnation;
  cfg.role = site.role;
  for (std::size_t i = 0; i < site.gateway_count && i < cfg.route_gateways.size(); ++i) {
    cfg.route_gateways[cfg.route_gateway_count++] = site.gateways[i];
  }
  // Member state goes live before the engine configures: configure()
  // refreshes its local view through local(), which reads adopted_ in
  // Member mode. The Ready joiner is destroyed (wiped) first; every
  // failure leg below destroys the half-built member side and parks in
  // Recovery instead.
  adopted_ = cfg;
  member_valid_ = true;
  destroy_workspace();
  create_member();
  mode_ = CoordinatorMode::Member;
  GatewaySessionBank::LocalView local{};
  local.self = cfg.node;
  local.network = cfg.network;
  local.gk_epoch = site.gk_epoch_current;
  GatewaySessionBank::RandomSource random{};
  random.fn = &entropy_fill;
  random.ctx = deps_.entropy;
  Status banked = bank_.configured() ? bank_.reset_membership(local, now)
                                     : bank_.configure(local, deps_.bank_aead, random, now);
  if (!banked.ok()) {
    member_valid_ = false;
    destroy_workspace();
    mode_ = CoordinatorMode::Recovery;
    CoordinatorAction action{};
    action.kind = CoordinatorActionKind::ReportRecovery;
    action.recovery = JoinRecoveryReason::StorageFailure;
    emit_action(action);
    return Status::success();
  }
  if (!member().member_cookie.configured()) {
    if (!member().member_cookie.configure(&entropy_fill, deps_.entropy).ok()) {
      member_valid_ = false;
      destroy_workspace();
      mode_ = CoordinatorMode::Recovery;
      CoordinatorAction action{};
      action.kind = CoordinatorActionKind::ReportRecovery;
      action.recovery = JoinRecoveryReason::StorageFailure;
      emit_action(action);
      return Status::success();
    }
  }
  if (!member().engine.configure(now).ok()) {
    member_valid_ = false;
    destroy_workspace();
    mode_ = CoordinatorMode::Recovery;
    CoordinatorAction action{};
    action.kind = CoordinatorActionKind::ReportRecovery;
    action.recovery = JoinRecoveryReason::MembershipInvalid;
    emit_action(action);
    return Status::success();
  }
  // The group provider transmits as the adopted node from here on. The
  // GK state binds the adopted record — kept across a same-site refresh
  // (counters and replay windows survive), rebound on a new adoption.
  group_provider_.set_self(cfg.node);
  if (!group_keys_.ready()) {
    GroupKeyState::Input stop{};
    stop.op = GroupKeyState::Op::Stop;
    (void)group_keys_.advance(stop, now);
    GroupKeyState::Input start{};
    start.op = GroupKeyState::Op::Start;
    start.boot = boot_session;
    start.generation = site.assignment_generation;
    if (!group_keys_.advance(start, now).ok()) {
      member_valid_ = false;
      destroy_workspace();
      mode_ = CoordinatorMode::Recovery;
      CoordinatorAction action{};
      action.kind = CoordinatorActionKind::ReportRecovery;
      action.recovery = JoinRecoveryReason::StorageFailure;
      emit_action(action);
      return Status::success();
    }
  }
  // A new adoption wants a fresh channel (the JoinConfirm goes out on
  // first Ready) and clears the refresh evidence.
  authority_wanted_ = true;
  join_confirmed_ = false;
  refresh_active_ = false;
  refresh_strikes_ = 0;
  // The discovery's controller is initialized by the firmware at
  // StartMemberDiscovery (discovery attaches after adoption); the
  // proxy/gateway below carry their own membership state.
  // Relay duties are role-gated: endpoint-only members never OFFER. The
  // authority path is self when we are the gateway, else the mesh gateway
  // list (a hint — the proxy's own timeouts enforce reality).
  member().proxy.set_membership(MembershipState::Member, now);
  member().proxy.set_policy((site.role & (kMemberRoleRelay | kMemberRoleGateway)) != 0);
  member().gateway_active = (site.role & kMemberRoleGateway) != 0;
  if (member().gateway_active) {
    member().proxy.set_authority(true, 0, now);
    member().gateway.set_membership(MembershipState::Member);
  } else if (cfg.route_gateway_count > 0) {
    member().proxy.set_authority(true, 1, now);
    member().gateway.set_membership(MembershipState::Unprovisioned);
  } else {
    member().proxy.set_authority(false, 0, now);
    member().gateway.set_membership(MembershipState::Unprovisioned);
  }
  channel_ = site.channel;  // the operating channel gates RLD1 RX
  discovery_started_ = false;
  member_apply_pending_ = true;
  sat_inc(counters_.member_adoptions);
  emit_member_action();
  return Status::success();
}

void SecurityCoordinator::emit_member_action() noexcept {
  CoordinatorAction action{};
  action.kind = CoordinatorActionKind::ApplyMemberConfig;
  action.member = adopted_;
  emit_action(action);
}

void SecurityCoordinator::abandon_dev_adoption(JoinRecoveryReason reason) noexcept {
  // The member side exists (create_member ran); stop_traffic scrubs the
  // bank and destroys the partially adopted dev side, then the workspace
  // dies and the coordinator parks in Recovery like a failed member
  // adoption — with the small side rebuilt, as every non-Dev mode has it.
  stop_traffic();
  destroy_workspace();
  mode_ = CoordinatorMode::Recovery;
  create_small();
  CoordinatorAction action{};
  action.kind = CoordinatorActionKind::ReportRecovery;
  action.recovery = reason;
  emit_action(action);
}

Status SecurityCoordinator::install_dev_config(const CoordinatorDevConfig& config,
                                               const MonotonicMs now) noexcept {
  if (config.network == 0 || config.node == kInvalidNodeId ||
      config.node == kBroadcastNodeId || config.node == 0 || config.boot == 0 ||
      config.channel == 0 || config.role == 0) {
    return Status::error(StatusCode::InvalidArgument, "dev config");
  }
  bool psk_zero = true;
  for (const std::uint8_t byte : config.psk) {
    if (byte != 0) psk_zero = false;
  }
  if (psk_zero) return Status::error(StatusCode::InvalidArgument, "dev psk");
  if (mode_ == CoordinatorMode::Dev) {
    return Status::error(StatusCode::InvalidState, "dev already adopted");
  }
  CoordinatorMemberConfig cfg{};
  cfg.network = config.network;
  cfg.node = config.node;
  cfg.channel = config.channel;
  // Both sessions are the reserved durable boot: it rises every boot, so
  // a reboot never reuses a group key epoch (P4 §10.1).
  cfg.message_session = config.boot;
  cfg.boot_session = config.boot;
  cfg.link_epoch = 1;
  cfg.end_epoch = 1;
  cfg.boot_incarnation = 0;  // unknown on the dev route (telemetry only)
  cfg.role = config.role;
  adopted_ = cfg;
  member_valid_ = true;
  destroy_workspace();
  create_member();
  destroy_small();
  create_dev();
  mode_ = CoordinatorMode::Dev;
  sat_inc(counters_.boots);
  GatewaySessionBank::LocalView local{};
  local.self = cfg.node;
  local.network = cfg.network;
  local.gk_epoch = 1;  // fixed dev epoch (P4 §10.1): the engine attests
                       // created_gk 1 and the bank enforces created+2
  GatewaySessionBank::RandomSource random{};
  random.fn = &entropy_fill;
  random.ctx = deps_.entropy;
  const Status banked = bank_.configured() ? bank_.reset_membership(local, now)
                                           : bank_.configure(local, deps_.bank_aead, random, now);
  if (!banked.ok()) {
    abandon_dev_adoption(JoinRecoveryReason::StorageFailure);
    return Status::success();
  }
  if (!member().member_cookie.configure(&entropy_fill, deps_.entropy).ok()) {
    abandon_dev_adoption(JoinRecoveryReason::StorageFailure);
    return Status::success();
  }
  DevResumePolicy policy{};
  policy.psk = config.psk;
  policy.network = config.network;
  policy.self = config.node;
  policy.role = config.role;
  policy.boot = config.boot;
  if (!member().engine.configure_dev(policy, now).ok()) {
    abandon_dev_adoption(JoinRecoveryReason::MembershipInvalid);
    return Status::success();
  }
  // The group side binds only after the pairwise side stands: a failed
  // adopt leaves no half-adopted provider behind (stop_traffic in the
  // abandon path scrubs whatever bound so far). A boot at or below the
  // consumed high-water refuses: the rebuilt sender cannot remember an
  // earlier adoption's counter space on its own.
  if (config.boot <= dev_boot_seen_) {
    abandon_dev_adoption(JoinRecoveryReason::StorageFailure);
    return Status::success();
  }
  if (!dev().sender.configure(config.psk, config.network, config.node, config.boot).ok()) {
    abandon_dev_adoption(JoinRecoveryReason::StorageFailure);
    return Status::success();
  }
  dev_boot_seen_ = config.boot;
  new (dev().group_box.data())
      DevGroupProvider(dev().sender, config.psk, config.network, deps_.bank_aead, config.node);
  dev().group_live = true;
  provider_mux_.set_dev_group(&dev_group());
  provider_mux_.set_dev(true);
  if (!dev().scope.adopt(config.psk, config.network).ok()) {
    abandon_dev_adoption(JoinRecoveryReason::StorageFailure);
    return Status::success();
  }
  if (!dev().hooks.adopt(config.network, config.node, config.role).ok()) {
    abandon_dev_adoption(JoinRecoveryReason::MembershipInvalid);
    return Status::success();
  }
  // No proxy/gateway/authority in dev: the workspace side stays
  // Unprovisioned and the poll never drives it. Relay duties are
  // role-gated by the firmware from the adopted config, like member.
  channel_ = config.channel;  // the operating channel gates RLD1 RX
  discovery_started_ = false;
  member_apply_pending_ = true;
  sat_inc(counters_.dev_adoptions);
  emit_member_action();
  return Status::success();
}

// --- Joiner legs -------------------------------------------------------------------------------

void SecurityCoordinator::drain_joiner(const MonotonicMs now) noexcept {
  (void)joiner().poll(now);
  for (;;) {
    JoinAction action{};
    if (!joiner().take_action(action).ok()) break;
    on_joiner_action(action, now);
  }
}

void SecurityCoordinator::on_joiner_action(const JoinAction& action, const MonotonicMs now) noexcept {
  switch (action.kind) {
    case JoinActionKind::ChangeChannel: {
      // Retune order for the firmware; the completion comes back as
      // ChannelReady with the same token. The token never rests at 0.
      ++tune_token_;
      if (tune_token_ == 0) ++tune_token_;
      tune_outstanding_ = tune_token_;
      CoordinatorAction tune{};
      tune.kind = CoordinatorActionKind::TuneChannel;
      tune.tune.token = tune_token_;
      tune.tune.channel = action.channel;
      tune.tune.phy = action.phy;
      emit_action(tune);
      return;
    }
    case JoinActionKind::MemberReady:
      refresh_active_ = false;  // re-verified (or silently adopted)
      (void)adopt_member(action, now);
      return;
    case JoinActionKind::RemovalRequired:
      refresh_active_ = false;
      (void)land_removal(action.removal,
                         ByteView{action.removal_object.data(), action.removal_object.size()},
                         now);
      return;
    case JoinActionKind::RecoveryRequired: {
      refresh_active_ = false;
      destroy_workspace();
      mode_ = CoordinatorMode::Recovery;
      CoordinatorAction recovery{};
      recovery.kind = CoordinatorActionKind::ReportRecovery;
      recovery.recovery = action.recovery_reason;
      emit_action(recovery);
      return;
    }
    case JoinActionKind::None:
      return;
  }
}

void SecurityCoordinator::emit_action(const CoordinatorAction& action) noexcept {
  action_ = action;
  action_pending_ = true;
}

// --- Removal -------------------------------------------------------------------------------------

Status SecurityCoordinator::land_removal(const RemovalNotice& notice,
                                        const ByteView removal_object,
                                        const MonotonicMs now) noexcept {
  if (mode_ != CoordinatorMode::ZeroTouch && mode_ != CoordinatorMode::Member) {
    return Status::error(StatusCode::InvalidState, "removal without workspace");
  }
  if (!deps_.site->has_site() || !deps_.identity->has_identity()) {
    return Status::error(StatusCode::InvalidState, "removal without membership");
  }
  const SiteRecord& site = deps_.site->site();
  const IdentityRecord& identity = deps_.identity->identity();
  // The Joiner verified the notice against the stored membership; the
  // landing re-checks the naming before anything durable moves.
  if (notice.site_id != site.site_id || notice.node_id != identity.node_id ||
      notice.generation < site.assignment_generation) {
    return Status::error(StatusCode::InvalidArgument, "foreign removal notice");
  }
  LocalRevocationRecord record{};
  record.state = LocalRevocationState::Blocked;
  record.cause = LocalRevocationCause::Notice;
  record.local_node = identity.node_id;
  record.site_id = site.site_id;
  record.network = site.network;
  record.removed_generation = notice.generation;
  record.rs_epoch_floor = notice.rs_epoch;
  record.site_epoch_floor = static_cast<std::uint32_t>(site.network >> 32);
  ByteBuffer<kRemovalNoticePayloadSize> payload{};
  if (removal_notice_payload_encode(notice, payload).ok() && payload.size > 0) {
    ScopeDigest digest{};
    sha256(payload.view(), digest);
    record.evidence_digest = digest;
  }
  record.rls_commit_seq = deps_.site->commit_seq();
  record.boot_witness = boot_witness_;
  // Traffic stops even when the evidence commit fails — the verified
  // notice is authoritative. The commit status returns to the firmware;
  // the tombstone cleanup + commit_cleaned ride maintenance (PR5).
  const Status committed = deps_.local_revocation->commit_blocked(record);
  if (deps_.discovery != nullptr) deps_.discovery->membership().revoke();
  if (mode_ == CoordinatorMode::Member) stop_traffic();
  destroy_workspace();  // Removed holds no workspace side
  for (auto& slot : staged_) slot = StagedFrame{};
  removal_holdoff_armed_ = true;
  removal_holdoff_at_ = now + kRemovalHoldoffMs;
  mode_ = CoordinatorMode::Removed;
  sat_inc(counters_.removals);
  CoordinatorAction report{};
  report.kind = CoordinatorActionKind::ReportRemoval;
  report.removal.site_id = site.site_id;
  report.removal.generation = notice.generation;
  report.removal.notice = notice;
  if (removal_object.data != nullptr && removal_object.size == report.removal.object.size()) {
    std::memcpy(report.removal.object.data(), removal_object.data, removal_object.size);
  }
  emit_action(report);
  return committed;
}

void SecurityCoordinator::stop_traffic(const bool clear_resume) noexcept {
  // Member workspace is live; the caller destroys (wipes) it after. The
  // bank and the GK scope live outside the union, so they are scrubbed
  // here: bank clear does not depend on new entropy, and proxy/gateway leave
  // Member (aborting relays, freeing slots) before the wipe. In Dev the
  // dev side dies here instead of the small side (the dev-armed engine,
  // with its PSK policy, dies with the workspace below); the mux drops
  // its dev group pointer before the storage goes.
  (void)member().engine.cancel_all();
  bank_.clear();
  sleep_guard_.disarm();
  provider_mux_.set_dev(false);
  provider_mux_.set_dev_group(nullptr);
  if (mode_ == CoordinatorMode::Dev) {
    destroy_dev();
  } else {
    if (deps_.sleep_image != nullptr) {
      secure_clear(deps_.sleep_image, sizeof(*deps_.sleep_image));
    }
  }
  restore_holding_ = false;
  restore_done_ = false;
  restore_failed_ = false;
  restore_error_ = Status::success();
  if (clear_resume) (void)member().resume_cache.clear_all();
  (void)member().member_cookie.configure(&entropy_fill, deps_.entropy);  // rotate; old cookies die
  // Verified removal ends the channel (its DAMS copy wipes with it) and
  // parks the GK state: no group TX/RX, no scope tags from here on.
  suspend_authority();
  authority_wanted_ = false;
  join_confirmed_ = false;
  {
    GroupKeyState::Input stop{};
    stop.op = GroupKeyState::Op::Stop;
    (void)group_keys_.advance(stop, last_now_);
  }
  const MembershipState state = deps_.discovery != nullptr
                                    ? deps_.discovery->membership().state()
                                    : MembershipState::Revoked;
  member().proxy.set_membership(state, last_now_);
  member().gateway.set_membership(state);
  member().gateway_active = false;
  member_valid_ = false;
}

// --- P6 lifecycle connection points --------------------------------------------------------

Status SecurityCoordinator::start_recovery_join(const MonotonicMs now) noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
  if (mode_ != CoordinatorMode::Member || !member_valid_) {
    return Status::error(StatusCode::InvalidState, "recovery join outside member");
  }
  if (now < last_now_) return Status::error(StatusCode::TimeUncertain, "coordinator clock regressed");
  if (!deps_.site->has_site() || !deps_.identity->has_identity()) {
    return Status::error(StatusCode::InvalidState, "recovery join without membership");
  }
  in_port_ = true;
  last_now_ = now;
  // Traffic halts and member secrets scrub, but the stores stay: the
  // Joiner re-proves the retained membership (or lands its removal).
  // Staged member frames die with the engine — they must never feed a
  // post-recovery workspace.
  stop_traffic();
  destroy_workspace();
  for (auto& slot : staged_) slot = StagedFrame{};
  mode_ = CoordinatorMode::ZeroTouch;  // tags the workspace for destroy below
  create_joiner();
  JoinBootInput boot{};
  boot.boot_witness = boot_witness_;
  boot.prepared = true;
  boot.mode = JoinBootMode::VerifyExistingMembership;
  boot.removal_watermark_site_id = removal_watermark_site_id_;
  boot.removal_watermark_generation = removal_watermark_generation_;
  const Status started =
      usb_direct_ ? joiner().start_direct(boot, *this, now) : joiner().start(boot, now);
  if (!started) {
    destroy_workspace();
    mode_ = CoordinatorMode::Recovery;
    CoordinatorAction action{};
    action.kind = CoordinatorActionKind::ReportRecovery;
    action.recovery = JoinRecoveryReason::MembershipInvalid;
    emit_action(action);
  }
  in_port_ = false;
  return Status::success();
}

Status SecurityCoordinator::wipe_site_trust() noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
  GroupKeyState::Input stop{};
  stop.op = GroupKeyState::Op::Stop;
  (void)group_keys_.advance(stop, last_now_);
  if (deps_.discovery != nullptr) deps_.discovery->membership().revoke();
  if (group_keys_.ready()) return Status::error(StatusCode::InternalError, "gk survived wipe");
  return Status::success();
}

Status SecurityCoordinator::revoke_member_sessions(const RevocationSet& set,
                                                   const std::uint32_t site_epoch,
                                                   const MonotonicMs now) noexcept {
  (void)site_epoch;
  (void)now;
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
  if (mode_ != CoordinatorMode::Member) return Status::success();
  // The set must be the adopted one: the lifecycle commits before
  // enforcing, so anything else is a wiring bug — refuse instead of
  // retiring sessions for a set the store never adopted.
  if (!member_valid_ || !deps_.revocations->has_set() ||
      deps_.revocations->set().site_id != set.site_id ||
      deps_.revocations->set().network != set.network ||
      deps_.revocations->rs_epoch() != set.rs_epoch) {
    return Status::error(StatusCode::InvalidArgument, "revoke set mismatch");
  }
  (void)member().engine.cancel_all();
  for (std::size_t i = 0; i < set.count; ++i) {
    const NodeId peer = set.entries[i].node_id;
    if (peer == kInvalidNodeId || peer == kBroadcastNodeId) continue;
    (void)bank_.retire_all(peer);
    if (deps_.discovery != nullptr) (void)deps_.discovery->revoke_peer(peer);
  }
  return Status::success();
}

}  // namespace routeloom::sdkv1
