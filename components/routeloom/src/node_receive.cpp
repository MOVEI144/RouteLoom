#include "node_internal.hpp"

namespace routeloom {

void MeshNode::finish_hop_accept(TxJob& job, const bool rtt_sampled,
                                 const std::uint32_t rtt_ms,
                                 const MonotonicMs now_ms) noexcept {
  obs_hop_result(job, true, now_ms);
  if (auto* bucket = job_bucket(job, now_ms)) {
    ++bucket->current.hop_accepts;
    if (rtt_sampled) {
      ++bucket->current.hop_rtt_samples;
      ewma_add(bucket->current.hop_rtt_us_ewma, rtt_ms * 1000u,
               bucket->current.hop_rtt_samples);
    }
    bucket->current.present = true;
    if (bucket->current.first_sample_ms == 0) {
      bucket->current.first_sample_ms = now_ms;
    }
    bucket->current.last_sample_ms = now_ms;
  }
  if (auto* neighbor = find_neighbor(job.peer)) {
    if (rtt_sampled) {
      ++neighbor->hop_rtt_samples;
      ewma_add(neighbor->hop_rtt_ewma_ms, rtt_ms,
               neighbor->hop_rtt_samples);
    }
    // An authenticated accept clears sustained busy and advances the
    // peer window, regardless of whether it precedes MAC completion.
    neighbor->busy_active = false;
    neighbor->busy_since_ms = 0;
    neighbor->last_busy_feedback_ms = 0;
    if (neighbor->window_accepts < kWindowGrowAccepts) {
      ++neighbor->window_accepts;
    }
    if (neighbor->window_accepts >= kWindowGrowAccepts &&
        neighbor->tx_window < kPeerWindowMax) {
      ++neighbor->tx_window;
      neighbor->window_accepts = 0;
    }
  }
  complete_job(job, true, now_ms);
}

void MeshNode::handle_hop_accept(const wire::PlainFrame& frame, const NodeId peer,
                                 const RxBinding& rx,
                                 const MonotonicMs now_ms) noexcept {
  AckKey key{};
  const auto status = decode_ack_payload(ByteView{frame.payload.data(), frame.payload_size}, key);
  if (!status) {
    observer_.on_diagnostic(status.detail, peer, nullptr);
    return;
  }
  // Binding-pinned match (design-q116 §6.2): beyond peer + ACK key, the
  // accept's authenticated RX binding id/generation must equal the binding
  // pinned at submit — an accept that arrives after a rebind resolves
  // nothing. The RX context is a membership check (valid implies a nonzero
  // epoch in the static context); session providers pin distinct contexts.
  auto* awaiting = awaiting_hop_.find([&](const AwaitingHop& value) {
    if (!(value.job.peer == peer &&
          value.job.ack.accepted_type == key.accepted_type &&
          value.job.ack.key == key.key && value.job.ack.round == key.round)) {
      return false;
    }
    if (!value.job.submitted_binding_set || !rx.valid) return false;
    return value.job.submitted_binding == rx.binding.id &&
           value.job.submitted_generation == rx.binding.generation &&
           value.job.submitted_rx_context == rx.binding.rx_context_id;
  });
  if (awaiting == nullptr) {
    auto& in_flight = physical_;
    const auto& job = in_flight.job;
    if (in_flight.active && job.requires_hop_accept && job.peer == peer &&
        job.ack.accepted_type == key.accepted_type && job.ack.key == key.key &&
        job.ack.round == key.round && job.submitted_binding_set && rx.valid &&
        job.submitted_binding == rx.binding.id &&
        job.submitted_generation == rx.binding.generation &&
        job.submitted_rx_context == rx.binding.rx_context_id) {
      in_flight.early_hop_accept = true;
      return;
    }
    observer_.on_diagnostic("UNMATCHED_HOP_ACCEPT", peer, &key.key.id);
    return;
  }
  TxJob job = awaiting->job;
  const bool was_deferred = awaiting->busy_deferred;
  const MonotonicMs sent_at_ms = awaiting->sent_at_ms;
  awaiting_hop_.release(awaiting);
  // HOP_ACCEPT round trip, MAC-accept -> authenticated accept. Only a live
  // exchange measures the path — a BUSY deferral's wait is peer-directed
  // and must never enter the adaptive RTO average (radio.md §8). The match
  // key carries no attempt discriminator, so after a retransmission an
  // accept may answer an earlier attempt and `now - sent_at_ms` would
  // learn a too-short RTT against the wrong baseline: retransmitted
  // exchanges resolve normally but cannot feed RTO adaptation.
  const bool rtt_sampled = !was_deferred && job.physical_attempts <= 1 &&
                           now_ms >= sent_at_ms;
  const std::uint32_t rtt_ms =
      rtt_sampled ? static_cast<std::uint32_t>(now_ms - sent_at_ms) : 0;
  finish_hop_accept(job, rtt_sampled, rtt_ms, now_ms);
}

void MeshNode::handle_data(const wire::LinkOpenedFrame& frame, const NodeId peer,
                           const RxBinding& rx,
                           const MonotonicMs now_ms) noexcept {
  const MessageKey key{frame.header.origin, frame.header.message};

  // END_RECEIPT loss may cause a later E2E round with the same logical Message ID.
  // A terminal recipient must acknowledge the new round without applying the payload twice.
  if (frame.header.destination == config_.node) {
    auto* terminal = dedup_.find([&](const DedupEntry& value) {
      return value.key == key && value.type == FrameType::Data &&
             value.phase == DedupPhase::Terminal && value.delivered;
    });
    if (terminal != nullptr) {
      // Cross-round refresh (sdk-completion/02 §2.6): re-ACK + re-emit the
      // receipt on a short reply reservation, retention extends only to the
      // new round's horizon + terminal slack and can NEVER pass the
      // first-seen hard cap — duplicates do not extend retention
      // (crash-time §4).
      terminal->expires_at_ms =
          std::max(terminal->expires_at_ms,
                   dedup_expiry_for(DedupPhase::Terminal,
                                    frame.header.remaining_deadline_ms,
                                    terminal->first_seen_ms, now_ms));
      if (!rx.valid) {
        refuse_without_binding(peer, frame.header, "RECEIPT_NO_BINDING",
                               now_ms);
        return;
      }
      AdmissionReservation reply{};
      if (!reserve_rx_reply(rx, /*needs_control_slot=*/true, 2, now_ms,
                            reply)) {
        reply.rollback();
        emit_busy_or_drop(peer, frame.header,
                          static_cast<std::uint8_t>(
                              autonomy::BusyReason::QueueFull),
                          rx, now_ms);
        return;
      }
      if (!queue_hop_accept(frame.header, reply.txn, now_ms)) {
        reply.rollback();
        emit_busy_or_drop(peer, frame.header,
                          static_cast<std::uint8_t>(
                              autonomy::BusyReason::QueueFull),
                          rx, now_ms);
        return;
      }
      reply.committed = true;  // the ACK joined; the receipt stays best-effort
      if (queue_end_receipt(frame.header, reply.txn, now_ms, terminal) &&
          frame.header.delivery == DeliveryClass::Applied) {
        // APPLIED (01 §1.5): a new-round retransmission replays the stored
        // verdict — the endpoint is never invoked twice for one MessageKey.
        if (auto* record = find_applied(key)) {
          emit_applied_result(*record, now_ms);
        }
      }
      return;
    }
  }

  if (auto* duplicate = find_dedup(key, FrameType::Data, frame.header.delivery_round)) {
    // Transit-record consistency (01 §4.3): a same-key frame on the same
    // round must present the same destination and the same upstream parent,
    // and — when we retained one — the same end-protected fingerprint.
    // A mismatch is a conflicted retransmission: report it, never ACK it.
    if (duplicate->forwarded) {
      // Destination/identity divergence is a message conflict; a different
      // upstream parent alone is a duplicate path (01 §dedup conflicts).
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
        observer_.on_diagnostic("TRANSIT_DEDUP_CONFLICT", peer,
                                &frame.header.message);
        return;
      }
    }
    // A transit record that already reported a failure re-emits that
    // retained evidence verbatim — never a blind re-ACK of a dead job,
    // never a re-originated claim under our own identity (01 §policy).
    if (duplicate->failure_reported) {
      replay_retained_failure(*duplicate, frame.header.type, rx, now_ms);
      return;
    }
    // Duplicate re-ACK (+ terminal receipt) on its own short reply
    // transaction — the original forward is never duplicated. Unaffordable
    // re-ACKs degrade to BUSY-or-drop; the sender's retry covers the gap.
    if (!rx.valid) {
      refuse_without_binding(peer, frame.header, "REACK_NO_BINDING", now_ms);
      return;
    }
    const bool want_receipt =
        duplicate->delivered && frame.header.destination == config_.node;
    AdmissionReservation reply{};
    if (!reserve_rx_reply(rx, /*needs_control_slot=*/true,
                          want_receipt ? 2 : 1, now_ms, reply)) {
      reply.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    if (!queue_hop_accept(frame.header, reply.txn, now_ms)) {
      reply.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    reply.committed = true;  // the ACK joined; the receipt stays best-effort
    if (want_receipt &&
        queue_end_receipt(frame.header, reply.txn, now_ms, duplicate) &&
        frame.header.delivery == DeliveryClass::Applied) {
      if (auto* record = find_applied(key)) {
        emit_applied_result(*record, now_ms);
      }
    }
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
    // Terminal admission probes (design-q116 §8.1 — all read-only): the ACK
    // + receipt pool slots, the control lane, a transaction, the APPLIED
    // result slot when a fresh one is needed, and the transaction deadline.
    // Nothing is spent until every probe agrees.
    MonotonicMs txn_deadline = 0;
    const bool need_applied = frame.header.delivery == DeliveryClass::Applied &&
                              find_applied(key) == nullptr;
    // APPLIED (01 §1.4/§1.6): a full result pool refuses with its own
    // capacity accounting — the most specific cause wins the diagnostic.
    if (need_applied && !applied_slot_available(now_ms)) {
      ++applied_stats_.refusals_capacity;
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("APPLIED_NO_RESULT_SLOT", peer,
                              &frame.header.message);
      return;
    }
    if (scheduler_.free_slots() < 2 || !scheduler_.control_slot_available() ||
        !scheduler_.origin_slot_available(config_.node) ||
        !txn_slot_available() ||
        !txn_deadline_for(frame.header.remaining_deadline_ms, now_ms,
                          txn_deadline)) {
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("ADMISSION_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    // Lease first: fully rollbackable, so a later refusal leaves no victim.
    AdmissionReservation res{};
    res.node = this;
    if (reply_peer_port_ == nullptr) {
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("ADMISSION_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    ReplyLeaseToken use{kInvalidReplyLeaseToken};
    if (!reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) {
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("ADMISSION_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    res.use = use;
    if (!begin_txn(use, txn_deadline, res.txn)) {
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      observer_.on_diagnostic("ADMISSION_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    // APPLIED (01 §1.4): the result record is part of admission — accepted
    // work must always have a place to store its verdict. An existing
    // record covers re-admission after the dedup record expired while the
    // result was still held.
    AppliedRecord* applied = nullptr;
    bool applied_new = false;
    if (frame.header.delivery == DeliveryClass::Applied) {
      applied = find_applied(key);
      if (applied == nullptr) {
        applied = allocate_applied(
            frame.header, ByteView{plain.payload.data(), plain.payload_size}, now_ms);
        if (applied == nullptr) {
          res.rollback();
          emit_busy_or_drop(peer, frame.header,
                            static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                            rx, now_ms);
          observer_.on_diagnostic("APPLIED_NO_RESULT_SLOT", peer,
                                  &frame.header.message);
          return;
        }
        applied_new = true;
        res.applied = applied;
        res.applied_new = true;
      }
    }
    // Terminal admission (sdk-completion/02 §2.3b): the delivered-DATA pin —
    // never evictable, bounded by the transit reserve. A refusal is already
    // counted + diagnosed inside allocate_dedup (DEDUP_OVERFLOW /
    // DEDUP_TERMINAL_RESERVE); the sender still gets an honest BUSY/drop.
    auto* entry = allocate_dedup(key, FrameType::Data, frame.header.delivery_round,
                                 DedupPhase::Terminal, peer,
                                 frame.header.remaining_deadline_ms, now_ms);
    if (entry == nullptr) {
      // Bounded dedup exhaustion is a capacity failure: the sender gets a
      // pre-acceptance BUSY (when a reply slot is affordable) instead of a
      // silent black hole.
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    res.dedup = entry;
    if (!queue_end_receipt(frame.header, res.txn, now_ms, entry)) {
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
      TxJob dropped{};
      if (scheduler_.drop_one_if(
              [&](const TxJob& job) { return job.txn == res.txn; },
              dropped)) {
        finish_txn_work(dropped.txn);
      }
      res.rollback();
      emit_busy_or_drop(peer, frame.header,
                        static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                        rx, now_ms);
      return;
    }
    res.committed = true;
    entry->delivered = true;
    if (!routes_.best(frame.header.origin).valid) {
      request_route_discovery(frame.header.origin, now_ms);
    }
    if (applied != nullptr) {
      // END_RECEIPT is SDK-level acceptance evidence first (01 §1.3); the
      // application verdict follows as its own APP_RESULT RESULT frame.
      dispatch_applied(frame.header, ByteView{plain.payload.data(), plain.payload_size},
                       *applied, applied_new, now_ms);
    } else {
      // open_end above is the origin proof (wire.hpp): this delivery is
      // origin-verified under the header's end_epoch. The evidence rides
      // the callback — group deliveries take the default forward instead
      // (group-key verification is not an origin END proof).
      DeliveryAssurance assurance{};
      assurance.origin_verified = true;
      assurance.site_epoch = frame.header.end_epoch;
      observer_.on_message(key, frame.header.origin,
                           ByteView{plain.payload.data(), plain.payload_size},
                           assurance);
    }
    return;
  }

  // Relay policy gate (01-forwarding §policy): a disabled/draining relay
  // refuses NEW transit admission before any dedup/route work — accepted
  // frames already in flight drain on their own deadlines. Honest refusal:
  // the sender's bounded retries expire, never a fabricated accept.
  if (!transit_permitted()) {
    ++transit_refused_;
    emit_transit_refusal(frame, TransitFailureReason::RelayDisabled, rx, now_ms);
    observer_.on_diagnostic("TRANSIT_RELAY_DISABLED", peer, &frame.header.message);
    return;
  }
  // A frame whose driver-queue time already consumed its forwarding budget
  // is dead on arrival — refuse it honestly rather than queueing a job that
  // can only expire (01 §lifetime debit). The same computation yields the
  // transaction deadline: min(frame budget, admission + 1500 ms).
  MonotonicMs txn_deadline = 0;
  if (!txn_deadline_for(frame.header.remaining_deadline_ms, now_ms,
                        txn_deadline)) {
    ++transit_refused_;
    emit_transit_refusal(frame, TransitFailureReason::Deadline, rx, now_ms);
    observer_.on_diagnostic("TRANSIT_DEADLINE_SPENT", peer, &frame.header.message);
    return;
  }
  if (!rx.valid) {
    ++transit_refused_;
    refuse_without_binding(peer, frame.header, "TRANSIT_NO_BINDING", now_ms);
    return;
  }
  const auto route = routes_.best(frame.header.destination);
  if (!route.valid || route.next_hop == peer) {
    // A route problem, not a capacity problem: keep the legacy drop +
    // sender-timeout semantics (03 §5 — BUSY is for admission failure).
    emit_transit_refusal(frame, TransitFailureReason::NoRoute, rx, now_ms);
    observer_.on_diagnostic("TRANSIT_NO_ROUTE", peer, &frame.header.message);
    return;
  }
  // Pre-admission check for the transit reservation (forward job + its
  // HOP_ACCEPT). A capacity refusal is answered with a pre-acceptance BUSY
  // when a reply slot is affordable.
  const AdmitVerdict admit =
      scheduler_.check(config_.node, /*scope=*/peer, frame.header.origin, 2);
  if (admit != AdmitVerdict::Admitted ||
      !scheduler_.control_slot_available() || !txn_slot_available()) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    emit_busy_or_drop(peer, frame.header, busy_reason_for(admit), rx, now_ms);
    observer_.on_diagnostic("TRANSIT_ADMISSION_DENIED", peer, &frame.header.message);
    return;
  }
  // Lease before dedup: the only step with an irreplaceable victim (the
  // evicted record) runs last among the fallible mutations.
  AdmissionReservation res{};
  res.node = this;
  ReplyLeaseToken use{kInvalidReplyLeaseToken};
  if (reply_peer_port_ == nullptr ||
      !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    observer_.on_diagnostic("TRANSIT_ADMISSION_DENIED", peer, &frame.header.message);
    return;
  }
  res.use = use;
  if (!begin_txn(use, txn_deadline, res.txn)) {
    saturating_inc(scheduler_.stats_.admissions_rejected);
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    observer_.on_diagnostic("TRANSIT_ADMISSION_DENIED", peer, &frame.header.message);
    return;
  }
  // Transit admission (sdk-completion/02): Live record bounded by the
  // per-upstream cap and the expired->Resolved->Evidence eviction sweep.
  auto* entry = allocate_dedup(key, FrameType::Data, frame.header.delivery_round,
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
  // The forward is committed BEFORE its HOP_ACCEPT reply is queued: a failed
  // reservation must never leave a false "accepted" ACK on the wire next to
  // the BUSY refusal.
  if (!queue_forward(frame, route.next_hop, res.txn, now_ms)) {
    res.rollback();
    emit_busy_or_drop(peer, frame.header,
                      static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull),
                      rx, now_ms);
    observer_.on_diagnostic("TRANSIT_RESERVATION_FAILED", peer, &frame.header.message);
    return;
  }
  entry->forwarded = true;
  // Retain the upstream correlation + downstream/destination binding +
  // fingerprint so a later post-acceptance failure can report TransitFailure
  // to the exact peer that handed us the frame, and a received report can
  // be validated against the work we actually accepted — never broadcast,
  // never origin-claimed.
  entry->upstream_peer = frame.header.previous_hop;
  entry->downstream_peer = route.next_hop;
  entry->ref_destination = frame.header.destination;
  entry->has_fingerprint =
      wire::transit_fingerprint(frame, entry->evidence.fingerprint).ok();
  if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
    // The accepted forward stays committed — accepted work is never silently
    // dropped. The sender's retry hits the dedup and re-ACKs instead of
    // double-forwarding.
    res.committed = true;
    observer_.on_diagnostic("TRANSIT_ACK_QUEUE_FULL", peer, &frame.header.message);
    return;
  }
  res.committed = true;
}

Status MeshNode::on_radio_receive(const NodeId peer, const ByteView encoded,
                                  const RadioRxMetadata& metadata,
                                  const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  // V1 callers carry no observation provenance; every in-tree V1 path is a
  // test/sim shim, so evidence is marked InjectedTest rather than invented.
  RadioRxMetadataV2 v2{};
  v2.rssi_dbm = metadata.rssi_dbm;
  v2.rssi_valid = true;
  v2.provenance = ObservationProvenance::InjectedTest;
  receive_impl(peer, encoded, &v2, now_ms);
  return Status::success();
}

Status MeshNode::on_radio_receive(const NodeId peer, const ByteView encoded,
                                  const RadioRxMetadataV2& metadata,
                                  const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  receive_impl(peer, encoded, &metadata, now_ms);
  return Status::success();
}

void MeshNode::receive_impl(const NodeId peer, const ByteView encoded,
                            const RadioRxMetadataV2* const metadata,
                            const MonotonicMs now_ms) noexcept {
  if (!started_) return;
  last_clock_ms_ = now_ms;
  // Time already spent in the driver queue debits the frame's remaining
  // forwarding budget (01 §lifetime): admission must see the capture-time
  // deadline, not a freshly-inflated one. No metadata → no debit claim.
  std::uint32_t rx_age_ms = 0;
  if (metadata != nullptr && metadata->received_us != 0) {
    const MonotonicMs captured_ms =
        static_cast<MonotonicMs>(metadata->received_us / 1000ULL);
    if (captured_ms <= now_ms) {
      rx_age_ms = static_cast<std::uint32_t>(
          std::min<std::uint64_t>(now_ms - captured_ms, UINT32_MAX));
    }
  }
  rx_age_ms_ = rx_age_ms;
  // Any received frame — even one that fails decode — is radio activity and
  // must invalidate outstanding sleep tickets.
  ++work_generation_;
  if (config_.route_broadcast) {
    // Opt-in RX: a strict broadcast-route shape bypasses the pairwise
    // receive path for the dedicated GroupLink dispatch — which never feeds
    // telemetry, resume confirmation or link activity. Anything else falls
    // through to the ordinary path below, unchanged.
    wire::Header peek{};
    if (wire::peek_header(encoded, peek) && peek.next_hop == kBroadcastNodeId) {
      handle_broadcast_route(peer, encoded, metadata, now_ms);
      return;
    }
  }
  wire::LinkOpenedFrame frame{};
  auto status = wire::open_link(encoded, config_.node, security_, frame);
  if (!status) {
    note_rx_refusal(status, peer, nullptr);
    ++telemetry_event_drops_;  // unauthenticated bytes never reach telemetry
    return;
  }
  if (frame.header.network != config_.network || frame.header.previous_hop != peer) {
    observer_.on_diagnostic("LINK_IDENTITY_MISMATCH", peer, &frame.header.message);
    ++telemetry_event_drops_;
    return;
  }
  // Context changes are an Owner binding change. Apply them before this RX
  // can refresh telemetry, confirm a neighbor, admit work, or match feedback.
  const RxBinding rx =
      capture_rx_binding(peer, metadata, frame.header.link_epoch);
  if (rx.valid &&
      !reply_peer_port_->observe_authenticated_rx(rx.binding)) {
    observer_.on_diagnostic("RX_CONTEXT_CHANGED", peer,
                            &frame.header.message);
    return;
  }
  // Only authenticated, well-formed traffic from our network confirms a
  // resume: junk or foreign frames still count as work (ticket invalidation
  // above) but must never satisfy the saved-peer confirmation window.
  ++rx_generation_;
  // Link-auth + identity passed: the frame is attributable to `peer`, so its
  // RF metadata may feed the per-peer summary (02-telemetry §2.3) — but only
  // when the runtime revalidated the captured generations. Stale-identity
  // metadata is evidence about an OLD binding/channel and refreshes nothing.
  const bool identity_current =
      metadata != nullptr && metadata->identity_current;
  if (metadata != nullptr && identity_current &&
      telemetry_peers_.note_rx(peer, *metadata, metadata->provenance,
                               config_.boot_incarnation, now_ms) ==
          nullptr) {
    ++telemetry_event_drops_;  // table full: bounded loss, never a fake sample
  }
  // Same bar feeds the migration verify oracle: connectivity evidence only
  // counts when the capture happened under the current channel/radio
  // generation — a pre-switch frame is not proof of post-switch reachability.
  if (autonomy_sink_ != nullptr && identity_current) {
    ExternalCallbackScope scope(in_external_callback_);
    autonomy_sink_->note_link_activity(peer, now_ms);
  }
  // A link-authenticated DATA, SERVICE or END_RECEIPT without end-to-end
  // protection is never valid in normal operation: the link open only
  // proves the immediate peer, so an unprotected payload could be injected
  // or altered by any relay on the path. Drop it before any
  // deliver-or-forward decision; the wire codec itself still accepts such
  // frames for link-only control types. Service=21 additionally has no
  // plaintext encoding at all (05 §5.3).
  if ((frame.header.type == FrameType::Data ||
       frame.header.type == FrameType::Service ||
       frame.header.type == FrameType::EndReceipt ||
       frame.header.type == FrameType::AppResult ||
       frame.header.type == FrameType::GroupData ||
       wire::is_extension_type(frame.header.type)) &&
      (frame.header.flags & wire::kFlagEndProtected) == 0) {
    observer_.on_diagnostic("END_PROTECTION_REQUIRED", peer, &frame.header.message);
    return;
  }

  // Reply identity for this receive (issue #117): the Owner's captured RX
  // binding plus the link-authenticated epoch. Every admission and every
  // HOP_ACCEPT/BUSY match below rechecks it; invalid input earns no reply
  // and no dispatch.
  switch (frame.header.type) {
    case FrameType::Data:
      handle_data(frame, peer, rx, now_ms);
      break;
    case FrameType::BootstrapAuth:
    case FrameType::MembershipResult:
    case FrameType::BootstrapChunk:
    case FrameType::BootstrapReply:
      // Routed bootstrap (P4 §7.4): link-only by construction — an
      // end-protected frame on this lane is a scope violation, never a
      // decodable alternative.
      if ((frame.header.flags & wire::kFlagEndProtected) != 0) {
        observer_.on_diagnostic("BOOTSTRAP_SCOPE_REJECTED", peer,
                                &frame.header.message);
      } else {
        handle_bootstrap(frame, peer, rx, now_ms);
      }
      break;
    case FrameType::Service:
      handle_routed(frame, peer, rx, now_ms);
      break;
    case FrameType::Control: {
      // Control (22) is routed config traffic only in this tree — it must
      // be end-protected like Service — except the P6 gossip bodies below,
      // which are the only link-scoped plaintext form. Anything else
      // unprotected is always rejected.
      const bool routed = (frame.header.flags & wire::kFlagEndProtected) != 0;
      const ByteView control_body{frame.protected_payload.data(), frame.header.payload_length};
      auto is_p6_body = [&]() noexcept {
        if (control_body.data == nullptr) return false;
        if (control_body.size == sdkv1::kStateEpochsSize &&
            control_body.data[0] == sdkv1::kRrsControlVersion &&
            control_body.data[1] == sdkv1::kRrsSubStateEpochs) {
          return true;
        }
        return control_body.size == sdkv1::kRrsRequestSize &&
               control_body.data[0] == sdkv1::kRrsControlVersion &&
               control_body.data[1] == sdkv1::kRrsSubRequest;
      };
      if (routed) {
        handle_routed(frame, peer, rx, now_ms);
      } else if (rrs_sink_ != nullptr && frame.header.destination == config_.node &&
                 is_p6_body()) {
        // P6 gossip (04 §4): link-authenticated 1-hop StateEpochs /
        // RrsRequest, self-addressed, exact shapes only. No general
        // link-only Control is opened by this branch. The sink
        // re-validates against the verified binding and the SAK.
        ExternalCallbackScope scope(in_external_callback_);
        rrs_sink_->on_rrs_frame(peer, frame.header.type, control_body, now_ms);
      } else if (rrs_sink_ == nullptr && frame.header.destination == config_.node &&
                 is_p6_body()) {
        // P6-shaped but unwired (the PR A state): rejected honestly, never
        // mistaken for end-authorized control.
        observer_.on_diagnostic("P6_NOT_WIRED", peer, &frame.header.message);
      } else {
        observer_.on_diagnostic("END_PROTECTION_REQUIRED", peer, &frame.header.message);
      }
      break;
    }
    case FrameType::EndReceipt:
      handle_end_receipt(frame, peer, rx, now_ms);
      break;
    case FrameType::AppResult:
      // sdk-completion/01: APP_RESULT rides the routed end-protected lane —
      // transit dedup/forwards it, terminals dispatch the body subtype.
      handle_routed(frame, peer, rx, now_ms);
      break;
    case FrameType::GroupData:
      handle_group_data(frame, peer, now_ms);
      break;
    case FrameType::HopAccept:
    case FrameType::RouteUpdate:
    case FrameType::SeqnoRequest:
    case FrameType::RouteRequest:
    case FrameType::GroupReport: {
      wire::PlainFrame plain{};
      status = wire::open_end(frame, config_.node, security_, plain);
      if (!status) {
        note_end_rx_refusal(status, frame, peer);
        return;
      }
      if (frame.header.type == FrameType::HopAccept) {
        handle_hop_accept(plain, peer, rx, now_ms);
      } else if (frame.header.type == FrameType::RouteUpdate) {
        handle_route_update(plain, peer, now_ms);
      } else if (frame.header.type == FrameType::RouteRequest) {
        handle_route_request(plain, peer, now_ms);
      } else if (frame.header.type == FrameType::GroupReport) {
        handle_group_report(plain, peer, now_ms);
      } else {
        handle_seqno_request(plain, peer, now_ms);
      }
      break;
    }
    case FrameType::Diagnostic:
      // 02-telemetry §4.2: dispatch on the outer protection class first.
      // End-protected diagnostics ride the routed lane (dedup/forward/
      // terminal); link-only subtypes are hop-1 local handling only.
      if ((frame.header.flags & wire::kFlagEndProtected) != 0) {
        handle_routed(frame, peer, rx, now_ms);
      } else if (frame.header.destination == config_.node) {
        handle_diagnostic_link(peer, frame, rx, now_ms);
      } else {
        observer_.on_diagnostic("DIAGNOSTIC_SCOPE_REJECTED", peer,
                                &frame.header.message);
      }
      break;
    case FrameType::Busy:
      // Link-scoped congestion feedback (03-congestion.md §5): strictly
      // 1-hop, bound to the immediate peer, never end-protected.
      handle_busy(frame, peer, rx, now_ms);
      break;
    case FrameType::NeighborProbe:
    case FrameType::NeighborResult:
    case FrameType::TimeSync:
    case FrameType::ChannelNotice:
      // Link-scoped autonomy control (02-discovery.md §3, migration
      // transport 04-channel-migration.md §5-§9): strictly 1-hop, bound to
      // the immediate peer, never end-protected. The sink re-validates
      // against the verified binding/phase — open_link alone is not
      // evidence (06 §3.1), and migration objects still face the real
      // signature verifier before they can move any state.
      if (autonomy_sink_ != nullptr && frame.header.destination == config_.node &&
          (frame.header.flags & wire::kFlagEndProtected) == 0) {
        ExternalCallbackScope scope(in_external_callback_);
        autonomy_sink_->on_autonomy_frame(
            peer, frame.header.type,
            ByteView{frame.protected_payload.data(), frame.header.payload_length},
            now_ms, now_ms - rx_age_ms);
      } else {
        observer_.on_diagnostic("AUTONOMY_FRAME_REJECTED", peer,
                                &frame.header.message);
      }
      break;
    case FrameType::ControlObject:
    case FrameType::ObjectChunk:
    case FrameType::ObjectAck: {
      auto is_rrs_manifest = [&]() noexcept {
        if (frame.header.payload_length != autonomy::kControlObjectPayloadSize) return false;
        autonomy::ControlObjectPayload manifest{};
        if (!autonomy::control_object_decode(
                ByteView{frame.protected_payload.data(), frame.header.payload_length},
                manifest)) {
          return false;
        }
        return manifest.kind == autonomy::ControlObjectKind::RevocationSet;
      };
      if ((frame.header.flags & wire::kFlagEndProtected) != 0) {
        // End-protected routed object traffic: the ConfigPermit (kind 3)
        // class rides the same manifest/chunk/ack carriers as migration
        // but multi-hop, end-authenticated to the terminal. The node layer
        // dedups/forwards/opens-end; the config sink still faces the real
        // permit verifier — routing never grants authority.
        handle_routed(frame, peer, rx, now_ms);
      } else if (frame.header.type == FrameType::ControlObject &&
                 frame.header.destination == config_.node && is_rrs_manifest()) {
        // P6 kind-6 (RevocationSet) manifest: routed to the gossip sink,
        // never fanned to the migration engine. Chunks/ACKs carry no kind
        // and stay on the autonomy lane; the Owner demuxes them by hash.
        if (rrs_sink_ != nullptr) {
          ExternalCallbackScope scope(in_external_callback_);
          rrs_sink_->on_rrs_frame(
              peer, frame.header.type,
              ByteView{frame.protected_payload.data(), frame.header.payload_length}, now_ms);
        } else {
          observer_.on_diagnostic("P6_NOT_WIRED", peer, &frame.header.message);
        }
      } else if (autonomy_sink_ != nullptr && frame.header.destination == config_.node) {
        // Link-scoped autonomous objects (migration kinds 1/2): strictly
        // 1-hop, bound to the immediate peer, never end-protected.
        ExternalCallbackScope scope(in_external_callback_);
        autonomy_sink_->on_autonomy_frame(
            peer, frame.header.type,
            ByteView{frame.protected_payload.data(), frame.header.payload_length},
            now_ms, now_ms - rx_age_ms);
      } else {
        observer_.on_diagnostic("AUTONOMY_FRAME_REJECTED", peer,
                                &frame.header.message);
      }
      break;
    }
    default:
      if (wire::is_extension_type(frame.header.type)) {
        // End-to-end extension types (64..95, incl. AppObject 64-66):
        // relays forward the body unread on the routed lane; the terminal
        // answers UNSUPPORTED (handle_routed).
        handle_routed(frame, peer, rx, now_ms);
      } else {
        observer_.on_diagnostic("FRAME_TYPE_UNSUPPORTED_IN_CORE_FIXED_250", peer,
                                &frame.header.message);
      }
      break;
  }
}

}  // namespace routeloom
