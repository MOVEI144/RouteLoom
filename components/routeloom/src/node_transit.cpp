#include "node_internal.hpp"

namespace routeloom {

// ---------------------------------------------------------------------------
// TransitFailure (01-forwarding §policy, 04 §4.2): bounded one-hop failure
// evidence for accepted transit work. Reports are link-only hop-1 BestEffort
// addressed to the retained upstream peer; they are dedup'd on
// reference+phase+reason, never ACKed, and never spawn further reports.
// ---------------------------------------------------------------------------

void MeshNode::map_transit_reason(const char* reason,
                                  TransitFailurePhase& phase,
                                  TransitFailureReason& out) noexcept {
  phase = TransitFailurePhase::FailedPostAcceptance;
  if (std::strcmp(reason, "DEADLINE_EXPIRED") == 0) {
    out = TransitFailureReason::Deadline;
  } else if (std::strcmp(reason, "NO_ROUTE") == 0) {
    out = TransitFailureReason::NoRoute;
  } else if (std::strcmp(reason, "DRIVER_RESULT_UNKNOWN") == 0) {
    // The radio never proved the outcome — honest unknown, not a failure.
    phase = TransitFailurePhase::OutcomeUnknown;
    out = TransitFailureReason::CallbackUnknown;
  } else {
    // Budget/queue/MAC exhaustion: the accepted work was retried to its
    // bound and still failed — proven local failure.
    out = TransitFailureReason::RetryExhausted;
  }
}

Status MeshNode::emit_transit_failure(const NodeId upstream,
                                      const TransitFailure& report,
                                      const TxnHandle txn,
                                      const MonotonicMs now_ms) noexcept {
  if (upstream == kInvalidNodeId || upstream == kBroadcastNodeId ||
      upstream == config_.node || report.report_id == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid report target");
  }
  // Bounded emission (forwarding §1.4): at most two reports per upstream
  // peer per second — a flapping upstream cannot turn our failure evidence
  // into a diagnostic flood. Excess reports are counted drops, not queued.
  DiagBudget* budget = diag_budget(upstream, now_ms);
  if (budget == nullptr ||
      budget->window_used >= kTransitFailurePerWindow) {
    ++telemetry_event_drops_;
    return Status::error(StatusCode::WouldBlock, "report budget spent");
  }
  ++budget->window_used;
  std::array<std::uint8_t, kTransitFailureBodySize> body{};
  if (!transit_failure_encode(report, MutableByteView{body.data(), body.size()})) {
    ++telemetry_event_drops_;
    return Status::error(StatusCode::InternalError, "report encode failed");
  }
  TxJob job{};
  job.form = JobForm::Plain;
  // Diagnostic owner: a report's own failure must never recursively spawn
  // another report — fail_job drops it silently by design.
  job.owner = JobOwner::Diagnostic;
  job.peer = upstream;
  job.requires_hop_accept = false;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kControlLifetimeMs;
  job.plain.header.type = FrameType::Diagnostic;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = upstream;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = upstream;
  job.plain.header.message =
      MessageId{config_.message_session, next_control_sequence_++};
  job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
  job.plain.header.original_lifetime_ms = kControlLifetimeMs;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  std::memcpy(job.plain.payload.data(), body.data(), body.size());
  job.plain.payload_size = body.size();
  job.txn = txn;
  Status status = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  if (!status) {
    // A report that cannot be queued is a counted loss, never a spin.
    ++telemetry_event_drops_;
    return status;
  }
  join_txn(txn);
  return Status::success();
}

void MeshNode::emit_transit_refusal(const wire::LinkOpenedFrame& frame,
                                    const TransitFailureReason reason,
                                    const RxBinding& rx,
                                    const MonotonicMs now_ms) noexcept {
  // Pre-acceptance refusal: no retained record — the fingerprint is computed
  // from the received frame so the report still pins the exact operation.
  if (!rx.valid) {
    refuse_without_binding(frame.header.previous_hop, frame.header,
                           "REFUSAL_NO_BINDING", now_ms);
    return;
  }
  TransitFailure report{};
  report.ref_origin = frame.header.origin;
  report.ref_session = frame.header.message.session;
  report.ref_sequence = frame.header.message.sequence;
  report.ref_destination = frame.header.destination;
  report.ref_type = static_cast<std::uint8_t>(frame.header.type);
  report.ref_round = frame.header.delivery_round;
  report.phase = TransitFailurePhase::RefusedPreAcceptance;
  report.reason = reason;
  report.claimed_reporter = config_.node;
  // Report-ID exhaustion is a counted stop, never a recycled identifier.
  if (next_failure_report_id_ == UINT32_MAX) {
    ++telemetry_event_drops_;
    return;
  }
  report.report_id = next_failure_report_id_++;
  if (!wire::transit_fingerprint(frame, report.fingerprint).ok()) return;
  AdmissionReservation reply{};
  if (!reserve_rx_reply(rx, false, 1, now_ms, reply)) {
    ++telemetry_event_drops_;
    return;
  }
  if (emit_transit_failure(frame.header.previous_hop, report, reply.txn,
                           now_ms)) {
    reply.committed = true;
  }
}

void MeshNode::replay_retained_failure(DedupEntry& duplicate,
                                       const FrameType type,
                                       const RxBinding& rx,
                                       const MonotonicMs now_ms) noexcept {
  // Replay bound: a duplicate storm cannot turn one retained failure into
  // unbounded re-emissions — capped count with minimum spacing (01 §replay).
  if (duplicate.failure_replays >= kMaxFailureReplays ||
      (duplicate.last_replay_ms != 0 &&
       now_ms - duplicate.last_replay_ms < kFailureReplayMinIntervalMs)) {
    ++telemetry_event_drops_;
    return;
  }
  if (!rx.valid) {
    ++telemetry_event_drops_;
    return;
  }
  TransitFailure reemit{};
  reemit.ref_origin = duplicate.key.origin;
  reemit.ref_session = duplicate.key.id.session;
  reemit.ref_sequence = duplicate.key.id.sequence;
  reemit.ref_destination = duplicate.ref_destination;
  reemit.ref_type = static_cast<std::uint8_t>(type);
  reemit.ref_round = duplicate.round;
  reemit.phase =
      static_cast<TransitFailurePhase>(duplicate.reported_phase);
  reemit.reason =
      static_cast<TransitFailureReason>(duplicate.reported_reason);
  // Verbatim: the ORIGINAL claimed reporter and report_id — re-originating
  // under our own identity would fabricate provenance.
  reemit.claimed_reporter = duplicate.reported_reporter;
  reemit.report_id = duplicate.reported_id;
  reemit.fingerprint = duplicate.evidence.fingerprint;
  AdmissionReservation reply{};
  if (!reserve_rx_reply(rx, false, 1, now_ms, reply)) {
    ++telemetry_event_drops_;
    return;
  }
  if (emit_transit_failure(duplicate.upstream_peer, reemit, reply.txn,
                           now_ms)) {
    reply.committed = true;
    ++duplicate.failure_replays;
    duplicate.last_replay_ms = now_ms;
  }
}

void MeshNode::report_transit_failure(const TxJob& job, const char* reason,
                                      const MonotonicMs now_ms) noexcept {
  // Only jobs whose accepted work we retained (dedup entry with upstream +
  // fingerprint) produce a report — link-local control jobs (BUSY emits
  // with owner Transit) have no record and exit here.
  auto* entry = dedup_.find([&](const DedupEntry& value) {
    return value.key == job.ack.key && value.type == job.ack.accepted_type &&
           value.round == job.ack.round && value.forwarded;
  });
  if (entry == nullptr || !entry->has_fingerprint ||
      entry->upstream_peer == kInvalidNodeId) {
    return;
  }
  TransitFailure report{};
  report.ref_origin = job.ack.key.origin;
  report.ref_session = job.ack.key.id.session;
  report.ref_sequence = job.ack.key.id.sequence;
  report.ref_destination = job.forwarded.header.destination;
  report.ref_type = static_cast<std::uint8_t>(job.ack.accepted_type);
  report.ref_round = job.ack.round;
  map_transit_reason(reason, report.phase, report.reason);
  report.claimed_reporter = config_.node;
  if (next_failure_report_id_ == UINT32_MAX) {
    ++telemetry_event_drops_;
    return;
  }
  report.report_id = next_failure_report_id_++;
  report.fingerprint = entry->evidence.fingerprint;
  // Retain the evidence for verbatim re-emission if the sender retries onto
  // the same dedup record — a re-ACK would falsely claim the job is alive.
  entry->failure_reported = true;
  entry->reported_phase = static_cast<std::uint8_t>(report.phase);
  entry->reported_reason = static_cast<std::uint8_t>(report.reason);
  entry->reported_reporter = report.claimed_reporter;
  entry->reported_id = report.report_id;
  // Post-acceptance failure retained: the record demotes to the Evidence
  // class (sdk-completion/02 §2.6) — still evictable, after all Resolved.
  mark_dedup_evidence(*entry);
  // The report reserves a fresh short transaction on the upstream's current
  // mapping: when the mapping is gone or the pool is spent, the retained
  // evidence above keeps the failure provable without sending anything.
  AdmissionReservation reply{};
  if (!reserve_short_reply(entry->upstream_peer, false, 1, now_ms, reply)) {
    ++telemetry_event_drops_;
    return;
  }
  if (emit_transit_failure(entry->upstream_peer, report, reply.txn, now_ms)) {
    reply.committed = true;
  }
}

void MeshNode::handle_transit_failure_report(const NodeId peer,
                                             const TransitFailure& report,
                                             const MonotonicMs now_ms) noexcept {
  // Dedup on reference+phase+reason: a fresh report_id must not restart the
  // exchange for an already-processed failure (04 §4.2). A live identical
  // entry is counted silence regardless of provenance.
  TransitFailureSeen* free_slot = nullptr;
  for (auto& seen : transit_failure_seen_) {
    const bool live = seen.expires_at_ms > now_ms;
    if (live && seen.key.origin == report.ref_origin &&
        seen.key.id.session == report.ref_session &&
        seen.key.id.sequence == report.ref_sequence &&
        seen.type == static_cast<FrameType>(report.ref_type) &&
        seen.round == report.ref_round &&
        seen.phase == static_cast<std::uint8_t>(report.phase) &&
        seen.reason == static_cast<std::uint8_t>(report.reason)) {
      return;  // already processed — counted silence
    }
    if (!live) free_slot = &seen;
    if (free_slot == nullptr && seen.expires_at_ms == 0) free_slot = &seen;
  }

  // Validate BEFORE allocating suppression state (01 §evidence): the report
  // is only meaningful when it references transit work we actually accepted —
  // it must come from the downstream peer we forwarded to, reference the
  // destination we forwarded toward, and carry the fingerprint of the bytes
  // we accepted. A fabricated reference suppresses nothing.
  const MessageKey ref_key{report.ref_origin,
                           MessageId{report.ref_session, report.ref_sequence}};
  auto* entry = dedup_.find([&](const DedupEntry& value) {
    return value.key == ref_key &&
           value.type == static_cast<FrameType>(report.ref_type) &&
           value.round == report.ref_round && value.forwarded;
  });
  if (entry == nullptr || entry->upstream_peer == kInvalidNodeId ||
      entry->downstream_peer != peer ||
      entry->ref_destination != report.ref_destination) {
    // References work we never accepted or never forwarded via this peer —
    // drop without allocating seen state.
    ++telemetry_event_drops_;
    return;
  }
  // The report must arrive under the SAME binding generation the attempt
  // was submitted in — a rebind invalidates the correlation (the old peer
  // identity cannot vouch for work attempted under a new binding).
  if (entry->downstream_binding != BindingGeneration{0}) {
    const auto* ds = telemetry_peers_.find(peer);
    if (ds == nullptr || !ds->occupied ||
        ds->binding != entry->downstream_binding) {
      ++telemetry_event_drops_;
      return;
    }
  }
  if (entry->has_fingerprint &&
      entry->evidence.fingerprint != report.fingerprint) {
    // The peer reported bytes we never forwarded — unverified claim,
    // propagate nothing and count the anomaly.
    ++telemetry_event_drops_;
    return;
  }

  if (free_slot == nullptr) {
    ++telemetry_event_drops_;
    return;
  }
  free_slot->key = ref_key;
  free_slot->type = static_cast<FrameType>(report.ref_type);
  free_slot->round = report.ref_round;
  free_slot->phase = static_cast<std::uint8_t>(report.phase);
  free_slot->reason = static_cast<std::uint8_t>(report.reason);
  // The seen-record never outlives the transit record it references
  // (sdk-completion/02 §2.3c) — a flat 60 s would pin report suppression
  // past the evidence's own retention.
  free_slot->expires_at_ms = entry->expires_at_ms;

  // Record the downstream-reported outcome on the retained record: a
  // re-received upstream duplicate replays this evidence VERBATIM (claimed
  // reporter and report_id preserved) instead of a blind re-ACK of work the
  // downstream already declared dead (01 §replay).
  entry->failure_reported = true;
  entry->reported_phase = static_cast<std::uint8_t>(report.phase);
  entry->reported_reason = static_cast<std::uint8_t>(report.reason);
  entry->reported_reporter = report.claimed_reporter;
  entry->reported_id = report.report_id;
  mark_dedup_evidence(*entry);

  // Propagate toward our upstream with the claimed reporter preserved
  // verbatim (unverified — we authenticated only `peer`). The fingerprint
  // is re-stamped from our retained record, never trusted from the wire.
  // The relay emission reserves its own short transaction on the upstream's
  // current mapping; the retained evidence above keeps the failure
  // provable when the reservation is unaffordable.
  TransitFailure onward = report;
  onward.fingerprint = entry->evidence.fingerprint;
  AdmissionReservation relay{};
  if (!reserve_short_reply(entry->upstream_peer, /*needs_control_slot=*/false,
                           1, now_ms, relay)) {
    ++telemetry_event_drops_;
    return;
  }
  if (emit_transit_failure(entry->upstream_peer, onward, relay.txn, now_ms)) {
    relay.committed = true;
  }
}

}  // namespace routeloom
