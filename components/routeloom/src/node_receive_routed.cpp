#include "node_internal.hpp"

namespace routeloom {

// Service=21 (scope-gateway-config 03 §3.3/§3.4): the terminal payload is
// end-verified and handed to the installed GatewayDelivery component — the
// node layer never interprets it. Relays treat it exactly like protected
// transit: dedup + bounded forward + hop ACK referencing type 21. A node
// without the endpoint drops at the terminal with an explicit diagnostic —
// retries then expire into an honest timeout, never a DATA-style success.
void MeshNode::handle_routed(const wire::LinkOpenedFrame& frame, const NodeId peer,
                             const RxBinding& rx,
                             const MonotonicMs now_ms) noexcept {
  const MessageKey key{frame.header.origin, frame.header.message};
  // The routed lane is shared by Service (21) and the config types (22/49/
  // 50/51): dedup is keyed on the frame's own type so a manifest, a chunk
  // and a Control query from the same origin never alias one another.
  const FrameType type = frame.header.type;

  // Frame-level dedup: a frame re-received on the same round only re-ACKs.
  // A resubmission on a NEW round reaches the component again — its own
  // dedup table decides PENDING/stored-receipt/CONFLICT. A transit record
  // that already reported a failure re-emits the retained evidence instead.
  if (auto* duplicate = find_dedup(key, type, frame.header.delivery_round)) {
    if (duplicate->forwarded) {
      TransitFailureReason conflict = TransitFailureReason::DuplicatePath;
      bool conflicted = false;
      if (frame.header.destination != duplicate->ref_destination) {
        conflicted = true;
        conflict = TransitFailureReason::MessageConflict;
      } else if (frame.header.previous_hop != duplicate->upstream_peer) {
        conflicted = true;
      }
      if (!conflicted && duplicate->has_fingerprint) {
        std::array<std::uint8_t, 32> incoming{};
        conflicted = wire::transit_fingerprint(frame, incoming).ok() &&
                     incoming != duplicate->evidence.fingerprint;
        if (conflicted) conflict = TransitFailureReason::MessageConflict;
      }
      if (conflicted) {
        emit_transit_refusal(frame, conflict, rx, now_ms);
        observer_.on_diagnostic("ROUTED_DEDUP_CONFLICT", peer,
                                &frame.header.message);
        return;
      }
    }
    if (duplicate->failure_reported) {
      replay_retained_failure(*duplicate, type, rx, now_ms);
      return;
    }
    if (!rx.valid) {
      refuse_without_binding(peer, frame.header, "REACK_NO_BINDING", now_ms);
      return;
    }
    AdmissionReservation reply{};
    if (!reserve_rx_reply(rx, /*needs_control_slot=*/true, 1, now_ms,
                          reply) ||
        !queue_hop_accept(frame.header, reply.txn, now_ms)) {
      reply.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    reply.committed = true;
    return;
  }

  if (frame.header.destination == config_.node) {
    wire::PlainFrame plain{};
    const auto status = wire::open_end(frame, config_.node, security_, plain);
    if (!status) {
      note_end_rx_refusal(status, frame, peer);
      return;
    }
    if (!rx.valid) {
      refuse_without_binding(peer, frame.header, "ADMISSION_NO_BINDING",
                             now_ms);
      return;
    }
    if ((frame.header.flags & wire::kFlagEndProtected) != 0) {
      observer_.on_verified_contact(frame.header.origin, now_ms);
    }
    if (wire::is_extension_type(type)) {
      // No extension type is implemented in this build: an authenticated
      // refusal with a reason, before any acceptance (no HOP_ACCEPT, no
      // dedup record), so the origin fails fast instead of timing out.
      emit_transit_refusal(frame, TransitFailureReason::Unsupported, rx, now_ms);
      observer_.on_diagnostic("EXTENSION_UNSUPPORTED", peer, &frame.header.message);
      return;
    }
    // Terminal routed probes: the ACK pool slot, the control lane, a
    // transaction, the component event slot when a component will take the
    // payload, and the transaction deadline — all read-only, all first.
    const bool needs_event =
        (type == FrameType::Service && gateway_sink_ != nullptr) ||
        (type != FrameType::Service && type != FrameType::Diagnostic &&
         type != FrameType::AppResult && config_sink_ != nullptr);
    MonotonicMs txn_deadline = 0;
    if (scheduler_.free_slots() < 1 || !scheduler_.control_slot_available() ||
        !txn_slot_available() ||
        (needs_event && !component_payload_event_available()) ||
        !txn_deadline_for(frame.header.remaining_deadline_ms, now_ms,
                          txn_deadline)) {
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("ROUTED_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    AdmissionReservation res{};
    res.node = this;
    ReplyLeaseToken use{kInvalidReplyLeaseToken};
    if (reply_peer_port_ == nullptr ||
        !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) {
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("ROUTED_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    res.use = use;
    if (!begin_txn(use, txn_deadline, res.txn)) {
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("ROUTED_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    // Terminal routed delivery is born Resolved (sdk-completion/02 §2.6): the
    // component's own dedup is the second layer — the node record's residual
    // duty is re-ACK of same-round retries only, so it stays evictable.
    auto* entry = allocate_dedup(key, type, frame.header.delivery_round,
                                 DedupPhase::Resolved, peer,
                                 frame.header.remaining_deadline_ms, now_ms);
    if (entry == nullptr) {
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    res.dedup = entry;
    if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    res.committed = true;
    entry->delivered = true;
    if (type == FrameType::Service) {
      if (gateway_sink_ != nullptr) {
        publish_component_event(ComponentEventTarget::ServicePayload, peer,
                                res.txn, txn_deadline, &plain, nullptr, false,
                                nullptr);
      } else {
        observer_.on_diagnostic("SERVICE_NO_ENDPOINT", peer, &frame.header.message);
      }
    } else if (type == FrameType::Diagnostic) {
      handle_diagnostic(plain, peer, now_ms);
    } else if (type == FrameType::AppResult) {
      // sdk-completion/01: RESULT/STATUS resolve origin-side APPLIED waits,
      // QUERY/RESULT_ACK answer from/consume terminal result records.
      handle_app_result(plain, peer, now_ms);
    } else {
      // Control/ControlObject/ObjectChunk/ObjectAck: the config endpoint
      // owns the terminal payload. A node without one reports it honestly —
      // the origin's retries expire into a timeout, never a false success.
      if (config_sink_ != nullptr) {
        publish_component_event(ComponentEventTarget::ConfigFrame, peer,
                                res.txn, txn_deadline, &plain, nullptr, false,
                                nullptr);
      } else {
        observer_.on_diagnostic("CONFIG_NO_ENDPOINT", peer, &frame.header.message);
      }
    }
    return;
  }

  // Transit: bounded admission, forward the still-protected bytes, then
  // ACK — a relay never interprets a routed payload terminally.
  if (!transit_permitted()) {
    ++transit_refused_;
    emit_transit_refusal(frame, TransitFailureReason::RelayDisabled, rx, now_ms);
    observer_.on_diagnostic("ROUTED_TRANSIT_RELAY_DISABLED", peer,
                            &frame.header.message);
    return;
  }
  MonotonicMs txn_deadline = 0;
  if (!txn_deadline_for(frame.header.remaining_deadline_ms, now_ms,
                        txn_deadline)) {
    ++transit_refused_;
    emit_transit_refusal(frame, TransitFailureReason::Deadline, rx, now_ms);
    observer_.on_diagnostic("ROUTED_TRANSIT_DEADLINE_SPENT", peer,
                            &frame.header.message);
    return;
  }
  if (!rx.valid) {
    ++transit_refused_;
    refuse_without_binding(peer, frame.header, "TRANSIT_NO_BINDING", now_ms);
    return;
  }
  const auto route = routes_.best(frame.header.destination);
  if (!route.valid || route.next_hop == peer) {
    emit_transit_refusal(frame, TransitFailureReason::NoRoute, rx, now_ms);
    observer_.on_diagnostic("ROUTED_TRANSIT_NO_ROUTE", peer, &frame.header.message);
    return;
  }
  const AdmitVerdict admit =
      scheduler_.check(config_.node, /*scope=*/peer, frame.header.origin, 2);
  if (admit != AdmitVerdict::Admitted ||
      !scheduler_.control_slot_available() || !txn_slot_available()) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    emit_busy_or_drop(peer, frame.header, busy_reason_for(admit), rx, now_ms);
    observer_.on_diagnostic("ROUTED_TRANSIT_DENIED", peer, &frame.header.message);
    return;
  }
  AdmissionReservation res{};
  res.node = this;
  ReplyLeaseToken use{kInvalidReplyLeaseToken};
  if (reply_peer_port_ == nullptr ||
      !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    observer_.on_diagnostic("ROUTED_TRANSIT_DENIED", peer, &frame.header.message);
    return;
  }
  res.use = use;
  if (!begin_txn(use, txn_deadline, res.txn)) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    observer_.on_diagnostic("ROUTED_TRANSIT_DENIED", peer, &frame.header.message);
    return;
  }
  auto* entry = allocate_dedup(key, type, frame.header.delivery_round,
                               DedupPhase::Live, peer,
                               frame.header.remaining_deadline_ms, now_ms);
  if (entry == nullptr) {
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    return;
  }
  res.dedup = entry;
  if (!queue_forward(frame, route.next_hop, res.txn, now_ms)) {
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    observer_.on_diagnostic("ROUTED_TRANSIT_RESERVATION_FAILED", peer,
                            &frame.header.message);
    return;
  }
  entry->forwarded = true;
  entry->upstream_peer = frame.header.previous_hop;
  entry->downstream_peer = route.next_hop;
  entry->ref_destination = frame.header.destination;
  entry->has_fingerprint =
      wire::transit_fingerprint(frame, entry->evidence.fingerprint).ok();
  if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
    // The forward stays committed; the sender's retry dedups and re-ACKs.
    res.committed = true;
    observer_.on_diagnostic("ROUTED_TRANSIT_ACK_FULL", peer, &frame.header.message);
    return;
  }
  res.committed = true;
}

void MeshNode::handle_bootstrap(const wire::LinkOpenedFrame& frame, const NodeId peer,
                                const RxBinding& rx, const MonotonicMs now_ms) noexcept {
  // The routed bootstrap lane (G-SEC P4 §7.4): join-relay and member
  // end-session objects, link-authenticated per hop, never end-protected.
  // receive_impl only routes link-only frames here; the origin below is an
  // unverified CLAIM carried over an authenticated previous hop.
  const MessageKey key{frame.header.origin, frame.header.message};
  const FrameType type = frame.header.type;
  if (reserved_node_id(frame.header.destination)) {
    observer_.on_diagnostic("BOOTSTRAP_SCOPE_REJECTED", peer, &frame.header.message);
    return;
  }

  // Frame-level dedup, keyed on the origin's MessageId like the routed
  // lane: a same-round retry re-ACKs, a conflicting re-submission refuses.
  if (auto* duplicate = find_dedup(key, type, frame.header.delivery_round)) {
    if (duplicate->forwarded) {
      TransitFailureReason conflict = TransitFailureReason::DuplicatePath;
      bool conflicted = false;
      if (frame.header.destination != duplicate->ref_destination) {
        conflicted = true;
        conflict = TransitFailureReason::MessageConflict;
      } else if (frame.header.previous_hop != duplicate->upstream_peer) {
        conflicted = true;
      }
      if (!conflicted && duplicate->has_fingerprint) {
        std::array<std::uint8_t, 32> incoming{};
        conflicted = wire::transit_fingerprint(frame, incoming).ok() &&
                     incoming != duplicate->evidence.fingerprint;
        if (conflicted) conflict = TransitFailureReason::MessageConflict;
      }
      if (conflicted) {
        emit_transit_refusal(frame, conflict, rx, now_ms);
        observer_.on_diagnostic("BOOTSTRAP_DEDUP_CONFLICT", peer, &frame.header.message);
        return;
      }
    }
    if (duplicate->failure_reported) {
      replay_retained_failure(*duplicate, type, rx, now_ms);
      return;
    }
    if (!rx.valid) {
      refuse_without_binding(peer, frame.header, "REACK_NO_BINDING", now_ms);
      return;
    }
    AdmissionReservation reply{};
    if (!reserve_rx_reply(rx, /*needs_control_slot=*/true, 1, now_ms,
                          reply) ||
        !queue_hop_accept(frame.header, reply.txn, now_ms)) {
      reply.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    reply.committed = true;
    return;
  }

  if (frame.header.destination == config_.node) {
    if (frame.header.payload_length > kMaxApplicationPayload) {
      observer_.on_diagnostic("BOOTSTRAP_PAYLOAD_REJECTED", peer, &frame.header.message);
      return;
    }
    if (!rx.valid) {
      refuse_without_binding(peer, frame.header, "ADMISSION_NO_BINDING", now_ms);
      return;
    }
    MonotonicMs txn_deadline = 0;
    if (scheduler_.free_slots() < 1 || !scheduler_.control_slot_available() ||
        !txn_slot_available() ||
        !txn_deadline_for(frame.header.remaining_deadline_ms, now_ms,
                          txn_deadline)) {
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("BOOTSTRAP_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    AdmissionReservation res{};
    res.node = this;
    ReplyLeaseToken use{kInvalidReplyLeaseToken};
    if (reply_peer_port_ == nullptr ||
        !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) {
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    res.use = use;
    if (!begin_txn(use, txn_deadline, res.txn)) {
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    auto* entry = allocate_dedup(key, type, frame.header.delivery_round,
                                 DedupPhase::Resolved, peer,
                                 frame.header.remaining_deadline_ms, now_ms);
    if (entry == nullptr) {
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    res.dedup = entry;
    if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    res.committed = true;
    entry->delivered = true;
    if (bootstrap_sink_ != nullptr) {
      sdkv1::BootstrapMeta meta{};
      meta.origin = frame.header.origin;
      meta.destination = frame.header.destination;
      meta.id = frame.header.message;
      meta.previous_hop = peer;
      meta.hop_remaining = frame.header.hop_remaining;
      meta.remaining_deadline_ms = frame.header.remaining_deadline_ms;
      ExternalCallbackScope scope(in_external_callback_);
      (void)bootstrap_sink_->on_frame(
          meta, type,
          ByteView{frame.protected_payload.data(), frame.header.payload_length}, now_ms);
    } else {
      observer_.on_diagnostic("BOOTSTRAP_NO_ENDPOINT", peer, &frame.header.message);
    }
    return;
  }

  // Transit: the relay holds no end session — it forwards the still
  // link-protected bytes untouched and never interprets the payload.
  if (!transit_permitted()) {
    ++transit_refused_;
    emit_transit_refusal(frame, TransitFailureReason::RelayDisabled, rx, now_ms);
    observer_.on_diagnostic("BOOTSTRAP_TRANSIT_RELAY_DISABLED", peer,
                            &frame.header.message);
    return;
  }
  // A bare Endpoint never forwards handshake traffic (P4 §7.4): only an
  // adopted Relay or Gateway role does.
  if ((local_role_ & (sdkv1::kMemberRoleRelay | sdkv1::kMemberRoleGateway)) == 0) {
    ++transit_refused_;
    emit_transit_refusal(frame, TransitFailureReason::RelayDisabled, rx, now_ms);
    observer_.on_diagnostic("BOOTSTRAP_TRANSIT_ROLE", peer, &frame.header.message);
    return;
  }
  // No inbound TTL check here: like the routed lane, the hop budget is
  // enforced once, at forward emission (wire::forward refuses hops <= 1
  // for every lane) — an inbound hops==0 transit frame is unemittable by
  // any honest encoder, so a second check would be unreachable.
  MonotonicMs txn_deadline = 0;
  if (!txn_deadline_for(frame.header.remaining_deadline_ms, now_ms,
                        txn_deadline)) {
    ++transit_refused_;
    emit_transit_refusal(frame, TransitFailureReason::Deadline, rx, now_ms);
    observer_.on_diagnostic("BOOTSTRAP_TRANSIT_DEADLINE_SPENT", peer,
                            &frame.header.message);
    return;
  }
  if (!rx.valid) {
    ++transit_refused_;
    refuse_without_binding(peer, frame.header, "TRANSIT_NO_BINDING", now_ms);
    return;
  }
  const auto route = routes_.best(frame.header.destination);
  if (!route.valid || route.next_hop == peer) {
    emit_transit_refusal(frame, TransitFailureReason::NoRoute, rx, now_ms);
    observer_.on_diagnostic("BOOTSTRAP_TRANSIT_NO_ROUTE", peer, &frame.header.message);
    return;
  }
  const AdmitVerdict admit =
      scheduler_.check(config_.node, /*scope=*/peer, frame.header.origin, 2);
  if (admit != AdmitVerdict::Admitted ||
      !scheduler_.control_slot_available() || !txn_slot_available()) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    emit_busy_or_drop(peer, frame.header, busy_reason_for(admit), rx, now_ms);
    observer_.on_diagnostic("BOOTSTRAP_TRANSIT_DENIED", peer, &frame.header.message);
    return;
  }
  AdmissionReservation res{};
  res.node = this;
  ReplyLeaseToken use{kInvalidReplyLeaseToken};
  if (reply_peer_port_ == nullptr ||
      !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    return;
  }
  res.use = use;
  if (!begin_txn(use, txn_deadline, res.txn)) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    return;
  }
  auto* entry = allocate_dedup(key, type, frame.header.delivery_round,
                               DedupPhase::Live, peer,
                               frame.header.remaining_deadline_ms, now_ms);
  if (entry == nullptr) {
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    return;
  }
  res.dedup = entry;
  if (!queue_forward(frame, route.next_hop, res.txn, now_ms)) {
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    observer_.on_diagnostic("BOOTSTRAP_TRANSIT_RESERVATION_FAILED", peer,
                            &frame.header.message);
    return;
  }
  entry->forwarded = true;
  entry->upstream_peer = frame.header.previous_hop;
  entry->downstream_peer = route.next_hop;
  entry->ref_destination = frame.header.destination;
  entry->has_fingerprint =
      wire::transit_fingerprint(frame, entry->evidence.fingerprint).ok();
  if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
    // The forward stays committed; the sender's retry dedups and re-ACKs.
    res.committed = true;
    observer_.on_diagnostic("BOOTSTRAP_TRANSIT_ACK_FULL", peer, &frame.header.message);
    return;
  }
  res.committed = true;
}

void MeshNode::handle_busy(const wire::LinkOpenedFrame& frame, const NodeId peer,
                           const RxBinding& rx,
                           const MonotonicMs now_ms) noexcept {
  // BUSY is link-scoped feedback to the previous hop only: it must be
  // addressed to us, must NOT be end-protected — a relay cannot end-sign
  // toward the origin — and must originate AT the peer: a forwarded BUSY
  // carrying a third party's origin is not our link's feedback.
  if (frame.header.destination != config_.node ||
      frame.header.origin != peer ||
      (frame.header.flags & wire::kFlagEndProtected) != 0) {
    observer_.on_diagnostic("BUSY_SCOPE_REJECTED", peer, &frame.header.message);
    return;
  }
  autonomy::BusyPayload payload{};
  const auto status = autonomy::busy_decode(
      ByteView{frame.protected_payload.data(), frame.header.payload_length}, payload);
  if (!status) {
    observer_.on_diagnostic("BUSY_PAYLOAD_REJECTED", peer, &frame.header.message);
    return;
  }
  ReplyBinding current{};
  if (!rx.valid || reply_peer_port_ == nullptr ||
      !reply_peer_port_->snapshot_binding(peer, current) ||
      current != rx.binding) {
    ++busy_stats_.busy_unmatched;
    observer_.on_diagnostic("BUSY_UNMATCHED", peer, &frame.header.message);
    return;
  }
  auto* neighbor = find_neighbor(peer);
  if (neighbor != nullptr) {
    // A well-formed authenticated BUSY proves the peer implements the
    // payload — mark it capable for our emit path. The grant is bounded:
    // direct proof refreshes the same validity window a capabilities
    // exchange would install. It proves exactly the busy payload, so it
    // installs exactly that permission — never a broadcast grant.
    neighbor->busy_capable = true;
    neighbor->cap_features = kCapBusyV1;
    neighbor->cap_valid_until_ms = now_ms + kCapabilitiesValidityMs;
    // The feedback sequence orders load feedback per peer: a stale or
    // replayed BUSY must never re-arm a deferral (03 §5). RFC 1982 serial
    // arithmetic — a plain <= would wedge the sequence forever after the
    // u32 wraps.
    if (neighbor->feedback_seen &&
        static_cast<std::int32_t>(payload.feedback_sequence.value -
                                  neighbor->last_feedback_seq) <= 0) {
      ++busy_stats_.busy_stale;
      observer_.on_diagnostic("BUSY_STALE_FEEDBACK", peer, &frame.header.message);
      return;
    }
    neighbor->feedback_seen = true;
    neighbor->last_feedback_seq = payload.feedback_sequence.value;
  }
  // The contract clamps the requested wait into [20, 1000] ms — too small
  // becomes a retransmit storm, too large a permanent stop.
  const std::uint32_t retry_ms = std::max(
      kBusyRetryAfterMinMs, std::min(payload.retry_after_ms, kBusyRetryAfterMaxMs));

  ++busy_stats_.busy_received;
  if (payload.subtype == autonomy::BusySubtype::PressureHint) {
    // Post-acceptance pressure: accepted work is never cancelled; the
    // window steps down one notch as the slow-down response (03 §5).
    if (neighbor != nullptr) {
      // A zero-pressure hint carries no busy claim — it must not throttle
      // either. Only real pressure steps the window down and re-arms the
      // busy picture (03 §5, §6.2, §7).
      if (payload.pressure != 0) {
        if (neighbor->tx_window > kPeerWindowMin) --neighbor->tx_window;
        neighbor->window_accepts = 0;
        if (!neighbor->busy_active) {
          neighbor->busy_active = true;
          neighbor->busy_since_ms = now_ms;
        }
        neighbor->last_busy_feedback_ms = now_ms;
      }
      neighbor->last_pressure = payload.pressure;
    }
    return;
  }

  // Reject: only a BUSY matching a pending (peer, MessageId, round) inside
  // its live exchange may act on our job — a BUSY for unknown or finished
  // work is counted and ignored. Like HOP_ACCEPT, the match also pins the
  // submitted binding: post-rebind feedback defers nothing.
  auto binding_matches = [&](const TxJob& job) {
    if (!job.submitted_binding_set || !rx.valid) return false;
    return job.submitted_binding == rx.binding.id &&
           job.submitted_generation == rx.binding.generation &&
           job.submitted_rx_context == rx.binding.rx_context_id;
  };
  auto* awaiting = awaiting_hop_.find([&](const AwaitingHop& value) {
    return value.job.peer == peer &&
           value.job.ack.accepted_type == payload.referenced_type &&
           value.job.ack.key.origin == payload.referenced_origin &&
           value.job.ack.key.id.session == payload.referenced_session &&
           value.job.ack.key.id.sequence == payload.referenced_sequence &&
           value.job.ack.round == payload.referenced_round &&
           binding_matches(value.job);
  });
  if (awaiting != nullptr) {
    // A repeat BUSY for an already-deferred exchange spends one unit of the
    // bounded readmission budget — fresh feedback sequences alone must not
    // be able to pin a job indefinitely (03 §5).
    if (awaiting->busy_deferred &&
        ++awaiting->job.busy_readmissions >= kBusyReadmissionsMax) {
      TxJob job = awaiting->job;
      awaiting_hop_.release(awaiting);
      fail_job(job, "BUSY_BUDGET_EXHAUSTED", now_ms);
    } else {
      awaiting->busy_deferred = true;
      awaiting->expires_at_ms = now_ms + retry_ms;
      obs_count(awaiting->job, &ObservationBucket::busy_deferrals, now_ms);
    }
  } else if (physical_.active && physical_.job.peer == peer &&
             physical_.job.ack.accepted_type == payload.referenced_type &&
             physical_.job.ack.key.origin == payload.referenced_origin &&
             physical_.job.ack.key.id.session == payload.referenced_session &&
             physical_.job.ack.key.id.sequence == payload.referenced_sequence &&
             physical_.job.ack.round == payload.referenced_round &&
             binding_matches(physical_.job)) {
    // The frame is still with the driver: the deferral applies when the TX
    // result lands, keeping BUSY vs RF-loss accounting separate.
    physical_.busy_deferred = true;
    physical_.busy_retry_ms = retry_ms;
    obs_count(physical_.job, &ObservationBucket::busy_deferrals, now_ms);
  } else {
    ++busy_stats_.busy_unmatched;
    observer_.on_diagnostic("BUSY_UNMATCHED", peer, &frame.header.message);
    return;
  }
  // An authenticated BUSY collapses the peer window to its minimum and
  // resets the accept streak (03 §5).
  if (neighbor != nullptr) {
    neighbor->tx_window = kPeerWindowMin;
    neighbor->window_accepts = 0;
    // A matched deferral is evidence we cannot inject toward this peer:
    // it sustains the severe-busy clock while fresh feedback keeps
    // arriving (03 §7) — still only a hint, never a metric input.
    if (!neighbor->busy_active) {
      neighbor->busy_active = true;
      neighbor->busy_since_ms = now_ms;
    }
    neighbor->last_busy_feedback_ms = now_ms;
    neighbor->last_pressure = payload.pressure;
  }
}

void MeshNode::handle_end_receipt(const wire::LinkOpenedFrame& frame, const NodeId peer,
                                  const RxBinding& rx,
                                  const MonotonicMs now_ms) noexcept {
  const MessageKey frame_key{frame.header.origin, frame.header.message};
  if (auto* duplicate = find_dedup(frame_key, FrameType::EndReceipt,
                                   frame.header.delivery_round)) {
    if (duplicate->forwarded) {
      // Same conflict discipline as DATA/routed transit: a divergent
      // retransmission is never blindly re-ACKed (01 §dedup conflicts).
      TransitFailureReason conflict = TransitFailureReason::DuplicatePath;
      bool conflicted = false;
      if (frame.header.destination != duplicate->ref_destination) {
        conflicted = true;
        conflict = TransitFailureReason::MessageConflict;
      } else if (frame.header.previous_hop != duplicate->upstream_peer) {
        conflicted = true;
      }
      if (!conflicted && duplicate->has_fingerprint) {
        std::array<std::uint8_t, 32> incoming{};
        conflicted = wire::transit_fingerprint(frame, incoming).ok() &&
                     incoming != duplicate->evidence.fingerprint;
        if (conflicted) conflict = TransitFailureReason::MessageConflict;
      }
      if (conflicted) {
        emit_transit_refusal(frame, conflict, rx, now_ms);
        observer_.on_diagnostic("RECEIPT_DEDUP_CONFLICT", peer,
                                &frame.header.message);
        return;
      }
      if (duplicate->failure_reported) {
        replay_retained_failure(*duplicate, FrameType::EndReceipt, rx, now_ms);
        return;
      }
    }
    if (!rx.valid) {
      refuse_without_binding(peer, frame.header, "REACK_NO_BINDING", now_ms);
      return;
    }
    AdmissionReservation reply{};
    if (!reserve_rx_reply(rx, /*needs_control_slot=*/true, 1, now_ms,
                          reply) ||
        !queue_hop_accept(frame.header, reply.txn, now_ms)) {
      reply.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    reply.committed = true;
    return;
  }

  if (frame.header.destination != config_.node) {
    // Relay-off admits no NEW transit work on any lane — the receipt frame
    // gets the same honest refusal as DATA (01 §policy).
    if (!transit_permitted()) {
      ++transit_refused_;
      emit_transit_refusal(frame, TransitFailureReason::RelayDisabled, rx,
                           now_ms);
      observer_.on_diagnostic("RECEIPT_TRANSIT_RELAY_DISABLED", peer,
                              &frame.header.message);
      return;
    }
    MonotonicMs txn_deadline = 0;
    if (!txn_deadline_for(frame.header.remaining_deadline_ms, now_ms,
                          txn_deadline)) {
      ++transit_refused_;
      emit_transit_refusal(frame, TransitFailureReason::Deadline, rx, now_ms);
      observer_.on_diagnostic("RECEIPT_TRANSIT_DEADLINE_SPENT", peer,
                              &frame.header.message);
      return;
    }
    if (!rx.valid) {
      ++transit_refused_;
      refuse_without_binding(peer, frame.header, "TRANSIT_NO_BINDING", now_ms);
      return;
    }
    const auto route = routes_.best(frame.header.destination);
    if (!route.valid || route.next_hop == peer) {
      observer_.on_diagnostic("RECEIPT_TRANSIT_NO_ROUTE", peer, &frame.header.message);
      return;
    }
    const AdmitVerdict admit =
        scheduler_.check(config_.node, peer, frame.header.origin, 2);
    if (admit != AdmitVerdict::Admitted ||
        !scheduler_.control_slot_available() || !txn_slot_available()) {
      saturating_inc(scheduler_.stats_.admissions_rejected);
      emit_busy_or_drop(peer, frame.header, busy_reason_for(admit), rx, now_ms);
      observer_.on_diagnostic("RECEIPT_TRANSIT_DENIED", peer,
                              &frame.header.message);
      return;
    }
    AdmissionReservation res{};
    res.node = this;
    ReplyLeaseToken use{kInvalidReplyLeaseToken};
    if (reply_peer_port_ == nullptr ||
        !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) {
      saturating_inc(scheduler_.stats_.admissions_rejected);
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("RECEIPT_TRANSIT_DENIED", peer,
                              &frame.header.message);
      return;
    }
    res.use = use;
    if (!begin_txn(use, txn_deadline, res.txn)) {
      saturating_inc(scheduler_.stats_.admissions_rejected);
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("RECEIPT_TRANSIT_DENIED", peer,
                              &frame.header.message);
      return;
    }
    auto* entry = allocate_dedup(frame_key, FrameType::EndReceipt,
                                 frame.header.delivery_round, DedupPhase::Live,
                                 peer, frame.header.remaining_deadline_ms,
                                 now_ms);
    if (entry == nullptr) {
      // Was silently lossy — sdk-completion/02 §2.8: the refusal is counted +
      // diagnosed inside allocate_dedup and the relay gets an honest BUSY.
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    res.dedup = entry;
    // Forward first: a failed reservation must not leave a false ACK behind.
    if (!queue_forward(frame, route.next_hop, res.txn, now_ms)) {
      return;
    }
    entry->forwarded = true;
    // Same correlation retention as DATA/routed transit — a post-
    // acceptance failure can be reported to the exact upstream peer.
    entry->upstream_peer = frame.header.previous_hop;
    entry->downstream_peer = route.next_hop;
    entry->ref_destination = frame.header.destination;
    entry->has_fingerprint =
        wire::transit_fingerprint(frame, entry->evidence.fingerprint).ok();
    // Accepted work stays committed when the ACK cannot be queued — the
    // sender's retry hits the dedup and re-ACKs.
    if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
      res.committed = true;
      return;
    }
    res.committed = true;
    return;
  }

  wire::PlainFrame plain{};
  const auto status = wire::open_end(frame, config_.node, security_, plain);
  if (!status) {
    note_end_rx_refusal(status, frame, peer);
    return;
  }
  MessageKey original{};
  std::uint8_t round = 0;
  const auto parse = decode_receipt_payload(ByteView{plain.payload.data(), plain.payload_size},
                                            original, round);
  if (!parse || original.origin != config_.node || original.id != frame.header.message) {
    observer_.on_diagnostic("INVALID_END_RECEIPT", peer, &frame.header.message);
    return;
  }
  if (!rx.valid) {
    refuse_without_binding(peer, frame.header, "ADMISSION_NO_BINDING",
                           now_ms);
    return;
  }
  if ((frame.header.flags & wire::kFlagEndProtected) != 0) {
    observer_.on_verified_contact(frame.header.origin, now_ms);
  }
  MonotonicMs txn_deadline = 0;
  if (scheduler_.free_slots() < 1 || !scheduler_.control_slot_available() ||
      !txn_slot_available() ||
      !txn_deadline_for(frame.header.remaining_deadline_ms, now_ms,
                        txn_deadline)) {
    return;
  }
  // Receipt consumed at the origin (sdk-completion/02 §2.6): born Resolved —
  // the residual duty is re-ACK of retried receipts while the delivery turns
  // terminal, so the record stays evictable under the transit class.
  AdmissionReservation res{};
  res.node = this;
  ReplyLeaseToken use{kInvalidReplyLeaseToken};
  if (reply_peer_port_ == nullptr ||
      !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) {
    return;
  }
  res.use = use;
  if (!begin_txn(use, txn_deadline, res.txn)) {
    return;
  }
  auto* entry = allocate_dedup(frame_key, FrameType::EndReceipt, frame.header.delivery_round,
                               DedupPhase::Resolved, peer,
                               frame.header.remaining_deadline_ms, now_ms);
  if (entry == nullptr) {
    // Was silently lossy — counted + diagnosed inside allocate_dedup; the
    // relay's bounded retry recovers, or an honest BUSY heads upstream.
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    return;
  }
  res.dedup = entry;
  if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
    return;
  }
  res.committed = true;
  entry->delivered = true;
  if (auto* delivery = find_delivery(original.id)) {
    if (delivery->options.delivery == DeliveryClass::Applied) {
      // APPLIED (01 §1.3): END_RECEIPT is SDK-acceptance evidence only — the
      // delivery keeps waiting for the application verdict. The receipt must
      // come from the delivery's own bound destination.
      if (delivery->destination != frame.header.origin) {
        observer_.on_diagnostic("APPLIED_RECEIPT_MISMATCH", peer,
                                &frame.header.message);
      } else if (delivery->state == DeliveryState::WaitingForEndReceipt &&
                 delivery->app_phase == 0) {
        delivery->app_phase = 1;
        delivery->next_round_at_ms =
            std::min(delivery->expires_at_ms,
                     now_ms + applied_window_ms(delivery->options.hop_limit,
                                                config_.hop_accept_timeout_ms));
        set_delivery_state(*delivery, DeliveryState::WaitingForEndReceipt,
                           "APP_RESULT_PENDING");
      }
      // A receipt for an already-committed/expired APPLIED delivery is
      // idempotent — dedup-suppressed per round, ignored otherwise.
    } else if (delivery->state != DeliveryState::Delivered) {
      // Delivered is absorbing: a late receipt is verified evidence that may
      // still promote Failed/Expired/Indeterminate, but it must never
      // re-fire a terminal verdict (e.g. a BestEffort TX_MAC_DONE) — a
      // second on_delivery for the same id would double-count completion.
      set_delivery_state(*delivery, DeliveryState::Delivered, "END_RECEIVED");
    }
  }
  (void)round;
}

}  // namespace routeloom
