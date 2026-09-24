#include "routeloom/sdkv1_security_coordinator.hpp"

#include <cstring>
#include <new>

#include "routeloom/discovery_scope.hpp"  // hmac_sha256
#include "routeloom/rlcw1.hpp"
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
      session_provider_(bank_) {
  // Fresh: no workspace side constructed. Boot builds the Joiner, the
  // adoption swaps it for the member engine.
}

SecurityCoordinator::~SecurityCoordinator() noexcept { destroy_workspace(); }

SecurityCoordinator::MemberEngine::MemberEngine(
    ResumeSlotStorage2& resume, GatewaySessionBank& bank, BankSessionSink<32, 128>& sink,
    HandshakeMembershipView& membership, SessionCredentialVerifier& verifier,
    EntropySource& entropy, ZtRld1Port& rld1, ZtRelayPort& relay, JoinCookieSealer& sealer,
    const NodeId node, const MacAddress mac) noexcept
    : resume_cache(resume, kResume2NodeLinkQuota, kResume2NodeEndQuota),
      engine(resume_cache, sink, member_cookie, membership, verifier, &entropy_fill, &entropy),
      demands(bank, engine),
      proxy([&] {
        JoinProxyConfig config{};
        config.node = node;
        config.mac = mac;
        return config;
      }(),
            rld1, relay, sealer, entropy),
      gateway([&] {
        JoinRelayGatewayConfig config{};
        config.node = node;
        return config;
      }(),
              relay) {}

void SecurityCoordinator::destroy_workspace() noexcept {
  if (mode_ == CoordinatorMode::ZeroTouch) {
    ws_.joiner.~Joiner();
  } else if (mode_ == CoordinatorMode::Member) {
    // The engine's cross-references (cookie, cache, sink) die with the
    // workspace; outside references (bank, stores, ports) stay valid.
    // The wipe below also clears demux cookies and slot bytes.
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
  new (&ws_.member) MemberEngine(*deps_.resume_storage, bank_, bank_sink_, *this, *deps_.verifier,
                                 *deps_.entropy, *deps_.rld1, *this, *deps_.proxy_sealer,
                                 deps_.local_node, deps_.local_mac);
  ws_.member.gateway.set_host_sink(this);
}

Status SecurityCoordinator::step(const CoordinatorEvent& event) noexcept {
  if (in_port_) return Status::error(StatusCode::Busy, "coordinator re-entry");
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
  }
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
  if (mode_ == CoordinatorMode::Member) {
    out.engine_quiescent = member().engine.quiescent();
  }
  out.link_sessions = static_cast<std::uint32_t>(bank_.live_count(SecurityScope::Link));
  out.end_sessions = static_cast<std::uint32_t>(bank_.live_count(SecurityScope::EndToEnd));
  out.demands = bank_.demand_count();
  return out;
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
  if (mode_ == CoordinatorMode::Member) {
    // The engine and the bank publish no deadline: while either has work
    // the firmware must keep polling, else the demux expiries rule.
    if (!member().engine.quiescent() || bank_.demand_count() != 0) return now;
    for (const auto& entry : member().demux) {
      if (entry.used) sooner(entry.expires_at);
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

bool SecurityCoordinator::quiescent_locked() const noexcept {
  for (const auto& staged : staged_) {
    if (staged.used) return false;
  }
  if (sleeping_) return true;
  if (mode_ == CoordinatorMode::ZeroTouch) return joiner().quiescent();
  if (mode_ == CoordinatorMode::Member) {
    if (!member().engine.quiescent() || bank_.demand_count() != 0) return false;
    for (const auto& entry : member().demux) {
      if (entry.used) return false;
    }
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
  const JoinBootInput boot{event.boot_witness, true};
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
    return Status::success();
  }
  if (mode_ != CoordinatorMode::Member) return Status::success();
  // The GK scope is adopted with the member config; StartMemberDiscovery
  // follows ApplyMemberConfig through the single action slot (the
  // !action_pending_ guard keeps the order: the firmware takes the config
  // first, then starts discovery with the Required GK scope).
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
    // One member leg per peer MAC: the engine refuses per-peer duplicates
    // anyway, and a second leg would alias the demux key. A simultaneous
    // open resolves to the first leg; mutual auth still succeeds.
    bool leg_live = false;
    for (const auto& slot : member().demux) {
      if (slot.used && slot.owner == DemuxOwner::Member && slot.mac == start.peer_mac) {
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
      if (!deps_.discovery
               ->begin_member_handshake(start.peer, start.peer_mac, now, token)
               .ok()) {
        entry->used = false;
        continue;
      }
      entry->discovery_token = token;
      HandshakeRequest req{};
      req.scope = SecurityScope::Link;
      req.peer = start.peer;
      req.reason = HandshakeReason::Initial;
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
  member().proxy.poll(now);
  if (member().gateway_active) member().gateway.poll(now);
  if (removal_holdoff_armed_ && now >= removal_holdoff_at_) {
    removal_holdoff_armed_ = false;
    hooks_.set_holdoff_elapsed(true);
  }
  return Status::success();
}

void SecurityCoordinator::sweep_demux(const MonotonicMs now) noexcept {
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
  for (auto& entry : member().demux) {
    if (entry.used && entry.mac == mac && entry.object_id == object_id) return &entry;
  }
  return nullptr;
}

SecurityCoordinator::DemuxEntry* SecurityCoordinator::claim_demux(
    const MacAddress& mac, const std::uint32_t object_id, const DemuxOwner owner,
    const MonotonicMs now) noexcept {
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
  if (mode_ != CoordinatorMode::ZeroTouch && mode_ != CoordinatorMode::Member) {
    return Status::success();  // Fresh/Removed/Recovery: no RLD1 owner lives
  }
  if (sleeping_) return Status::success();
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
    if (mode_ != CoordinatorMode::Member) {
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
  // New exchange. A member-mode Auth single frame with a parked
  // responder start (same peer MAC) binds to it; anything else follows
  // the mode default: ZT Joiner while unprovisioned, proxy admission
  // while member. Replies never open an exchange.
  if (env.kind == FrameType::BootstrapReply) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  if (mode_ == CoordinatorMode::Member) {
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
    // Proxy admission is stateless-cookie-checked inside the proxy; claim
    // the demux leg so the exchange routes stably, and let the proxy's
    // own gates drop what is not for it.
    DemuxEntry* proxy_entry =
        claim_demux(event.rld1_meta.source, object_id, DemuxOwner::Proxy, event.now);
    if (proxy_entry == nullptr) {
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
  DemuxEntry* joiner_entry =
      claim_demux(event.rld1_meta.source, object_id, DemuxOwner::Joiner, event.now);
  if (joiner_entry == nullptr) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  return joiner().on_rld1_rx(event.rld1_meta, event.rld1_frame, event.now);
}

Status SecurityCoordinator::demux_member_frame(const autonomy::Rld1Envelope& env,
                                               DemuxEntry* entry, const MonotonicMs now) noexcept {
  if (entry == nullptr || !entry->used || mode_ != CoordinatorMode::Member) {
    sat_inc(counters_.demux_drops);
    return Status::success();
  }
  entry->expires_at = now + kDemuxHoldMs;
  const ByteView body{env.body.data(), env.body_size};
  // Replies advance our link TX slot when the exchange matches; anything
  // else on this leg drops.
  if (env.kind == FrameType::BootstrapReply) {
    JoinReply reply{};
    if (!join_reply_decode(body, reply).ok() || reply.lane != ObjectLane::JoinRelay) {
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
      if (join_reply_encode(accepted.reply, MutableByteView{body.data(), body.size()}, written)
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
    HandshakeRx rx{};
    rx.scope = SecurityScope::Link;
    rx.phase = static_cast<std::uint8_t>(object.phase);
    rx.step = object.step;
    rx.claimed_peer = entry->peer;
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
  HandshakeRx rx{};
  rx.scope = SecurityScope::Link;
  rx.phase = static_cast<std::uint8_t>(object.phase);
  rx.step = object.step;
  rx.claimed_peer = entry->peer;
  rx.src_mac = entry->mac;
  rx.dst_mac = deps_.local_mac;
  rx.carrier = entry->carrier;
  if (object.cookie_present) {
    rx.cookie = ByteView{object.cookie.data(), object.cookie.size()};
  }
  (void)member().engine.on_message(rx, object.message, now);
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
      if (deps_.discovery->begin_member_handshake(demand.peer, leg->mac, now, token).ok()) {
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
      (void)emit_send(result, now);
    } else if (result.event == HandshakeEvent::Established && result.has_proof &&
               result.scope == SecurityScope::Link) {
      (void)installed_link(result, now);
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
  // the transaction id (drawn on our first send, echoed after).
  DemuxEntry* leg = nullptr;
  for (auto& entry : member().demux) {
    if (entry.used && entry.owner == DemuxOwner::Member && entry.peer == result.peer) {
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
  if (!same && !slot.load(JoinCarrier::Rld1, object.phase, object.step, leg->object_id,
                           ByteView{full.data(), full_size}, now)
                    .ok()) {
    return Status::error(StatusCode::ProtocolError, "link tx load");
  }
  // Emit the unconfirmed chunks now; replies advance the slot via
  // demux_member_frame, and the engine's retransmit re-drives the rest.
  const std::uint16_t pending = slot.pending_mask();
  for (std::size_t i = 0; i < slot.chunk_total(); ++i) {
    if ((pending & static_cast<std::uint16_t>(1U << i)) == 0) continue;
    JoinChunk chunk{};
    if (!slot.chunk_at(i, chunk).ok()) break;
    std::array<std::uint8_t, autonomy::kRld1MaxBody> body{};
    std::size_t written = 0;
    if (!join_chunk_encode(JoinCarrier::Rld1, chunk,
                           MutableByteView{body.data(), body.size()}, written)
             .ok()) {
      break;
    }
    autonomy::Rld1Envelope env{};
    env.kind = FrameType::BootstrapChunk;
    env.network_hint = static_cast<std::uint32_t>(adopted_.network);
    env.claimed_node = adopted_.node;
    env.transaction_nonce = leg->txn;
    if (written > env.body.size()) break;
    std::memcpy(env.body.data(), body.data(), written);
    env.body_size = written;
    autonomy::Rld1Encoded frame{};
    if (!autonomy::rld1_encode(env, frame).ok()) break;
    (void)deps_.rld1->send_rld1(leg->mac, frame.view());
  }
  slot.note_sent(now);
  return Status::success();
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
  std::uint32_t exchange = result.token;
  if (exchange == 0) exchange = 1;  // nonzero: 0 is never a valid exchange
  EndObject object{};
  object.phase = static_cast<JoinAuthPhase>(result.phase);
  object.step = result.step;
  object.exchange_id = exchange;
  object.profile = kEndProfileMember;
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
  if (!same && !slot.load(JoinCarrier::WireRelay, object.phase, object.step, exchange,
                           ByteView{encoded.data(), encoded_size}, now, ObjectLane::EndSession)
                    .ok()) {
    return Status::error(StatusCode::ProtocolError, "end tx load");
  }
  const std::uint16_t pending = slot.pending_mask();
  for (std::size_t i = 0; i < slot.chunk_total(); ++i) {
    if ((pending & static_cast<std::uint16_t>(1U << i)) == 0) continue;
    JoinChunk chunk{};
    if (!slot.chunk_at(i, chunk).ok()) break;
    std::array<std::uint8_t, kMaxApplicationPayload> body{};
    std::size_t written = 0;
    if (!join_chunk_encode(JoinCarrier::WireRelay, chunk,
                           MutableByteView{body.data(), body.size()}, written)
             .ok()) {
      break;
    }
    (void)deps_.mesh->send_bootstrap(result.peer, FrameType::BootstrapChunk,
                                     ByteView{body.data(), written},
                                     HandshakeEngine::kLinkTimeoutMs, now, id);
  }
  slot.note_sent(now);
  return Status::success();
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
  if (mode_ != CoordinatorMode::Member) {
    sat_inc(counters_.staged_drops);
    return;
  }
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
          if (join_reply_decode(payload, reply).ok() &&
              reply.lane == ObjectLane::EndSession) {
            (void)member().end_tx.on_reply(reply, now);
          } else {
            sat_inc(counters_.demux_drops);
          }
        }
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
    std::array<std::uint8_t, kJoinReplySize> body{};
    std::size_t written = 0;
    MessageId id{};
    if (join_reply_encode(accepted.reply, MutableByteView{body.data(), body.size()}, written)
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

Status SecurityCoordinator::relay_abort(const NodeId proxy, const std::uint32_t relay_id,
                                        const RelayAbortReason reason) noexcept {
  return deps_.usb->send_relay_abort_to_host(proxy, relay_id, reason);
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
  if (mode_ != CoordinatorMode::Member || !member_valid_) return false;
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
  if (mode_ != CoordinatorMode::Member || !member_valid_) return false;
  if (network != adopted_.network) return false;
  if (bank_.peer_summary(SecurityScope::Link, peer, generation, role)) return true;
  return bank_.peer_summary(SecurityScope::EndToEnd, peer, generation, role);
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
      // the adapter already refused). Unknown relays answer NotFound —
      // the host then aborts via 0x61 with an Abort header.
      if (mode_ != CoordinatorMode::Member || !member().gateway_active) {
        sat_inc(counters_.usb_drops);
        return Status::error(StatusCode::InvalidState, "no gateway here");
      }
      if (event.usb_reason != static_cast<std::uint8_t>(RelayAbortReason::HostAborted)) {
        sat_inc(counters_.usb_drops);
        return Status::error(StatusCode::InvalidArgument, "host abort reason");
      }
      const Status aborted =
          member().gateway.host_abort(event.usb_proxy, event.usb_relay_id, event.now);
      if (!aborted.ok()) sat_inc(counters_.usb_drops);
      return aborted;
    }
    case CoordinatorEventKind::UsbSessionDown: {
      // USB disconnect: USB-bound state drops, never reused. A direct
      // join run dies with its transport; the firmware re-boots (radio)
      // or stops from the Stopped snapshot. Gateway relays abort
      // themselves: the USB port refuses their ups from here on.
      if (mode_ == CoordinatorMode::ZeroTouch && usb_direct_) {
        (void)joiner().stop(event.now);
      }
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
  // No tune outstanding: in member mode this is the firmware's apply-time
  // report (it owns the radio and retuned while applying the member
  // config); anywhere else it is stale.
  if (mode_ != CoordinatorMode::Member) return Status::success();
  channel_ = event.channel;
  radio_generation_ = event.channel_generation;
  return Status::success();
}

Status SecurityCoordinator::on_prepare_sleep(const MonotonicMs now) noexcept {
  (void)now;
  // Busy while the firmware still owes a take_action or the workspace has
  // work; else park. Sleep images are PR5 — Poll simply naps.
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
  return Status::success();
}

Status SecurityCoordinator::on_stop(const MonotonicMs now) noexcept {
  (void)now;
  if (mode_ == CoordinatorMode::Member) {
    // stop_traffic reads the state; unattached (pre-Start) relays stop
    // as revoked.
    if (deps_.discovery != nullptr) {
      deps_.discovery->membership() = MembershipController{};
    }
    stop_traffic();
  }
  destroy_workspace();  // wipes the live side (joiner or member)
  for (auto& slot : staged_) slot = StagedFrame{};
  action_ = CoordinatorAction{};
  action_pending_ = false;
  adopted_ = CoordinatorMemberConfig{};
  member_valid_ = false;
  tune_outstanding_ = 0;
  channel_ = 0;
  sleeping_ = false;
  usb_direct_ = false;
  discovery_started_ = false;
  hooks_.set_holdoff_elapsed(false);
  removal_holdoff_armed_ = false;
  mode_ = CoordinatorMode::Fresh;
  return Status::success();
}

// --- MemberReady adoption --------------------------------------------------------------------

Status SecurityCoordinator::adopt_member(const JoinAction& ready, const MonotonicMs now) noexcept {
  if (mode_ != CoordinatorMode::ZeroTouch) {
    return Status::error(StatusCode::InvalidState, "member ready outside zt");
  }
  // joined_now vs silent adoption share the tail: the stores are
  // re-resolved either way. rs_epoch_to_fetch (the fresh-join RS package
  // target) has no PR4 consumer — the RS fetch rides maintenance (PR5).
  (void)ready;
  return adopt_boot_rls1(now);
}

Status SecurityCoordinator::adopt_boot_rls1(const MonotonicMs now) noexcept {
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
  return install_member_config(site, identity, site.boot_witness, now);
}

Status SecurityCoordinator::install_member_config(const SiteRecord& site,
                                                  const IdentityRecord& identity,
                                                  const std::uint32_t boot_session,
                                                  const MonotonicMs now) noexcept {
  if (boot_session == 0) return Status::error(StatusCode::InvalidArgument, "zero boot session");
  CoordinatorMemberConfig cfg{};
  cfg.network = site.network;
  cfg.node = identity.node_id;
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
  gk_scope_.adopt(site.gk_current.data(), site.gk_epoch_current);
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
      (void)adopt_member(action, now);
      return;
    case JoinActionKind::RemovalRequired:
      (void)land_removal(action.removal, now);
      return;
    case JoinActionKind::RecoveryRequired: {
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

Status SecurityCoordinator::land_removal(const RemovalNotice& notice, const MonotonicMs now) noexcept {
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
  emit_action(report);
  return committed;
}

void SecurityCoordinator::stop_traffic() noexcept {
  // Member workspace is live; the caller destroys (wipes) it after. The
  // bank and the GK scope live outside the union, so they are scrubbed
  // here: the bank re-bind wipes every key, and the proxy/gateway leave
  // Member (aborting relays, freeing slots) before the wipe.
  (void)member().engine.cancel_all();
  if (bank_.configured() && member_valid_) {
    GatewaySessionBank::LocalView local{};
    local.self = adopted_.node;
    local.network = adopted_.network;
    if (deps_.site->has_site()) {
      local.gk_epoch = deps_.site->site().gk_epoch_current;
    }
    (void)bank_.reset_membership(local, last_now_);
  }
  (void)member().resume_cache.clear_all();
  (void)member().member_cookie.configure(&entropy_fill, deps_.entropy);  // rotate; old cookies die
  gk_scope_.wipe();
  const MembershipState state = deps_.discovery != nullptr
                                    ? deps_.discovery->membership().state()
                                    : MembershipState::Revoked;
  member().proxy.set_membership(state, last_now_);
  member().gateway.set_membership(state);
  member().gateway_active = false;
  member_valid_ = false;
}

// --- GK-backed discovery scope -----------------------------------------------------------------
// One live generation (P4 keeps no overlap): accepted == current, and the
// tag refuses anything else without leaking key material.

void SecurityCoordinator::GkScopeProvider::adopt(const std::uint8_t gk[32],
                                                 const std::uint32_t generation) noexcept {
  if (gk == nullptr || generation == 0) {
    wipe();
    return;
  }
  std::memcpy(gk_.data(), gk, gk_.size());
  generation_ = generation;
  active_ = true;
}

void SecurityCoordinator::GkScopeProvider::wipe() noexcept {
  secure_clear(gk_);
  generation_ = 0;
  active_ = false;
}

bool SecurityCoordinator::GkScopeProvider::current_generation(const ScopeRef scope,
                                                              std::uint32_t& out) noexcept {
  (void)scope;  // one member scope; the firmware binds the handle
  if (!active_) return false;
  out = generation_;
  return true;
}

bool SecurityCoordinator::GkScopeProvider::accepted_generation(const ScopeRef scope,
                                                               const std::uint32_t generation,
                                                               const MonotonicMs now_ms) noexcept {
  (void)scope;
  (void)now_ms;
  return active_ && generation != 0 && generation == generation_;
}

Status SecurityCoordinator::GkScopeProvider::scope_tag(const ScopeRef scope,
                                                       const std::uint32_t generation,
                                                       const ByteView input, ScopeTag& out) noexcept {
  out = ScopeTag{};
  if (!accepted_generation(scope, generation, 0)) {
    return Status::error(StatusCode::AuthenticationFailed, "scope generation not accepted");
  }
  ScopeDigest digest{};
  hmac_sha256(ByteView{gk_.data(), gk_.size()}, input, digest);
  std::memcpy(out.data(), digest.data(), out.size());  // left 128 bits
  return Status::success();
}

}  // namespace routeloom::sdkv1
