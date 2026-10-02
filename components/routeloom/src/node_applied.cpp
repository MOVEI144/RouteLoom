#include "node_internal.hpp"

namespace routeloom {

// --- APPLIED delivery (sdk-completion/01-applied-delivery.md) -----------------

std::uint32_t MeshNode::applied_window_ms(const std::uint8_t hop_limit,
                                          const std::uint32_t hop_timeout_ms) noexcept {
  // Same hop-scaled window the END_RECEIPT retry path uses — a RESULT/QUERY
  // answer has a comparable round trip.
  return static_cast<std::uint32_t>(std::max<std::uint64_t>(
      kMinimumEndToEndRetryMs,
      std::min<std::uint64_t>(std::numeric_limits<std::uint32_t>::max(),
                              static_cast<std::uint64_t>(hop_limit) *
                                  hop_timeout_ms * 2U)));
}

MeshNode::AppliedRecord* MeshNode::find_applied(const MessageKey& key) noexcept {
  return applied_records_.find(
      [&](const AppliedRecord& record) { return record.key == key; });
}

const MeshNode::AppliedRecord* MeshNode::find_applied(const MessageKey& key) const noexcept {
  return applied_records_.find(
      [&](const AppliedRecord& record) { return record.key == key; });
}

MeshNode::AppliedRecord* MeshNode::allocate_applied(
    const wire::Header& data, const ByteView body, const MonotonicMs now_ms) noexcept {
  auto* record = applied_records_.allocate();
  if (record == nullptr) {
    // Reclaim expired records first, then the oldest ACKed one — its only
    // residual duty is dedup answers and the origin already proved it
    // received the verdict (01 §1.7). Unacked in-window records are never
    // evicted into a lost verdict.
    while (auto* expired = applied_records_.find([&](const AppliedRecord& value) {
             return value.expires_at_ms <= now_ms;
           })) {
      ++applied_stats_.expired;
      applied_records_.release(expired);
    }
    record = applied_records_.allocate();
  }
  if (record == nullptr) {
    AppliedRecord* oldest_acked = nullptr;
    applied_records_.for_each([&](AppliedRecord& value) {
      if (value.acked && (oldest_acked == nullptr ||
                          value.expires_at_ms < oldest_acked->expires_at_ms)) {
        oldest_acked = &value;
      }
    });
    if (oldest_acked != nullptr) {
      ++applied_stats_.evicted;
      applied_records_.release(oldest_acked);
      record = applied_records_.allocate();
    }
  }
  if (record == nullptr) {
    ++applied_stats_.refusals_capacity;
    return nullptr;
  }
  *record = AppliedRecord{};
  record->key = MessageKey{data.origin, data.message};
  endpoint::applied_request_digest(
      data.network, data.origin, data.destination, data.message.session,
      data.message.sequence, data.delivery, data.original_lifetime_ms, body,
      record->request_digest);
  record->expires_at_ms = now_ms + kAppliedResultHoldMs;
  record->emit_deadline_ms = static_cast<MonotonicMs>(std::min<std::uint64_t>(
      static_cast<std::uint64_t>(now_ms) + kAppliedResultHoldMs,
      static_cast<std::uint64_t>(now_ms) + data.remaining_deadline_ms +
          kAppliedLateResultMs));
  return record;
}

void MeshNode::dispatch_applied(const wire::Header& data, const ByteView body,
                                AppliedRecord& record, const bool fresh,
                                const MonotonicMs now_ms) noexcept {
  if (!fresh) {
    // A re-delivered key answers from the stored verdict — the endpoint is
    // never invoked twice (01 §1.5). A digest mismatch means the origin
    // reused the MessageKey for different bytes: the committed result still
    // answers, the conflict is counted.
    std::array<std::uint8_t, 32> digest{};
    endpoint::applied_request_digest(
        data.network, data.origin, data.destination, data.message.session,
        data.message.sequence, data.delivery, data.original_lifetime_ms, body,
        digest);
    if (digest != record.request_digest) {
      ++applied_stats_.mismatched;
      observer_.on_diagnostic("APPLIED_KEY_CONFLICT", data.previous_hop,
                              &data.message);
    }
    (void)emit_applied_result(record, now_ms);
    return;
  }

  endpoint::AppResultOutcome outcome = endpoint::AppResultOutcome::Failure;
  std::uint32_t code = 0;
  ByteView result_data{};
  bool dispatched = false;
  // Hoisted to function scope: result_data ByteViews below alias these
  // objects, and the memcpy into record.result_data runs after the block.
  ExecutionLease current{};
  AppliedReply reply{};
  if (body.size < endpoint::kAppliedLeaseBytes) {
    code = static_cast<std::uint32_t>(endpoint::AppResultRefusal::MalformedRequest);
    ++applied_stats_.refusals_malformed;
  } else {
    current = applied_lease();
    bool lease_zero = true;
    for (std::size_t i = 0; i < endpoint::kAppliedLeaseBytes; ++i) {
      if (body.data[i] != 0) lease_zero = false;
    }
    if (lease_zero || !constant_time_equal(
                          ByteView{body.data, endpoint::kAppliedLeaseBytes},
                          ByteView{current.data(), current.size()})) {
      // Stale/absent lease: refused without running the endpoint; the result
      // carries the CURRENT lease so the origin can retry once correctly.
      code = static_cast<std::uint32_t>(endpoint::AppResultRefusal::StaleLease);
      ++applied_stats_.refusals_stale_lease;
      result_data = ByteView{current.data(), current.size()};
    } else if (applied_sink_ == nullptr) {
      code = static_cast<std::uint32_t>(endpoint::AppResultRefusal::NoEndpoint);
      ++applied_stats_.refusals_no_endpoint;
    } else if (open_applied_tickets(now_ms) >= kAppliedTicketMax) {
      // Every ticket is still open: refuse before the endpoint runs, so it
      // never holds more than kAppliedTicketMax at once.
      code = static_cast<std::uint32_t>(endpoint::AppResultRefusal::Capacity);
      ++applied_stats_.refusals_capacity;
    } else {
      reply = AppliedReply{};
      if (++next_applied_ticket_ == 0) ++next_applied_ticket_;
      const AppliedRequest request{record.key, data.origin,
                                   ByteView{body.data + endpoint::kAppliedLeaseBytes,
                                            body.size - endpoint::kAppliedLeaseBytes},
                                   data.remaining_deadline_ms,
                                   (static_cast<std::uint64_t>(config_.message_session) << 32) |
                                       next_applied_ticket_};
      {
        ExternalCallbackScope scope(in_external_callback_);
        applied_sink_->on_applied_request(request, reply);
      }
      dispatched = true;
      ++applied_stats_.requests_dispatched;
      if (reply.deferred) {
        // No verdict yet: nothing is committed or sent until
        // complete_applied(); a QUERY meanwhile answers Pending, and Expired
        // once the request deadline passed.
        record.ticket = next_applied_ticket_;
        record.emit_deadline_ms = now_ms + data.remaining_deadline_ms;
        return;
      }
      outcome = reply.outcome;
      code = reply.code;
      if (reply.size > endpoint::kAppResultDataMax ||
          code >= endpoint::kAppResultSdkCodeBase) {
        // Endpoint contract violation: oversize data or a code inside the
        // SDK-reserved band is rewritten to an honest InternalError — app
        // bytes can never impersonate an SDK refusal (01 §1.2).
        outcome = endpoint::AppResultOutcome::Failure;
        code = static_cast<std::uint32_t>(endpoint::AppResultRefusal::InternalError);
      } else {
        result_data = ByteView{reply.data.data(), reply.size};
      }
    }
  }
  (void)dispatched;
  record.outcome = static_cast<std::uint8_t>(outcome);
  record.application_code = code;
  record.result_size = static_cast<std::uint8_t>(result_data.size);
  if (result_data.size > 0) {
    std::memcpy(record.result_data.data(), result_data.data, result_data.size);
  }
  ++applied_stats_.results_committed;
  (void)emit_applied_result(record, now_ms);
}

std::size_t MeshNode::open_applied_tickets(const MonotonicMs now_ms) const noexcept {
  // A ticket past its request deadline can no longer complete.
  std::size_t open = 0;
  applied_records_.for_each([&](const AppliedRecord& record) {
    if (record.ticket != 0 && now_ms < record.emit_deadline_ms) ++open;
  });
  return open;
}

Status MeshNode::complete_applied(const std::uint64_t ticket, const AppliedReply& reply,
                                  const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(*this);
  last_clock_ms_ = now_ms;
  if (static_cast<std::uint32_t>(ticket) == 0 || reply.deferred ||
      reply.size > endpoint::kAppResultDataMax ||
      reply.code >= endpoint::kAppResultSdkCodeBase) {
    return Status::error(StatusCode::InvalidArgument, "invalid applied reply");
  }
  // The high half binds the ticket to this boot's message session.
  const auto serial = static_cast<std::uint32_t>(ticket);
  auto* record = (ticket >> 32) != config_.message_session
      ? nullptr
      : applied_records_.find(
            [&](const AppliedRecord& value) { return value.ticket == serial; });
  if (record == nullptr) return Status::error(StatusCode::NotFound, "APPLIED_TICKET_UNKNOWN");
  if (now_ms >= record->emit_deadline_ms) {
    return Status::error(StatusCode::Expired, "APPLIED_TICKET_EXPIRED");
  }
  ++work_generation_;
  record->ticket = 0;
  record->emit_deadline_ms =
      std::min(record->expires_at_ms, record->emit_deadline_ms + kAppliedLateResultMs);
  record->outcome = static_cast<std::uint8_t>(reply.outcome);
  record->application_code = reply.code;
  record->result_size = reply.size;
  if (reply.size > 0) std::memcpy(record->result_data.data(), reply.data.data(), reply.size);
  ++applied_stats_.results_committed;
  (void)emit_applied_result(*record, now_ms);
  return Status::success();
}

Status MeshNode::emit_applied_result(AppliedRecord& record,
                                     const MonotonicMs now_ms) noexcept {
  if (record.ticket != 0) {
    // A deferred verdict does not exist yet; replays and QUERYs wait for it.
    return Status::error(StatusCode::WouldBlock, "APPLIED_PENDING");
  }
  if (record.emits >= kAppliedMaxEmits || now_ms >= record.emit_deadline_ms ||
      now_ms < record.next_emit_ms) {
    ++applied_stats_.result_emits_suppressed;
    return Status::error(StatusCode::WouldBlock, "APPLIED_EMIT_BUDGET");
  }
  endpoint::AppResultBody body{};
  body.head.subtype = endpoint::AppResultSubtype::Result;
  body.head.outcome = record.outcome;
  body.head.network = static_cast<std::uint32_t>(config_.network);
  body.head.original_origin = record.key.origin;
  body.head.original_session = record.key.id.session;
  body.head.original_sequence = record.key.id.sequence;
  body.head.original_destination = config_.node;
  body.head.request_digest = record.request_digest;
  body.application_code = record.application_code;
  body.data_size = record.result_size;
  if (record.result_size > 0) {
    std::memcpy(body.data.data(), record.result_data.data(), record.result_size);
  }
  endpoint::EncodedServicePayload encoded{};
  auto status = endpoint::app_result_encode(body, encoded);
  if (!status) return status;
  // The RESULT's wire identity echoes the request's MessageId (the
  // END_RECEIPT precedent); the emit index rides delivery_round so each
  // bounded retransmission is a distinct frame at dedup, ≤3 total.
  const auto lifetime = static_cast<std::uint32_t>(std::min<std::uint64_t>(
      std::numeric_limits<std::uint32_t>::max(),
      static_cast<std::uint64_t>(record.emit_deadline_ms - now_ms)));
  status = queue_typed_job(FrameType::AppResult, JobOwner::Applied, record.key.id,
                           record.key.origin, encoded.view(), record.emits,
                           lifetime, Priority::Management, now_ms);
  if (!status) {
    ++applied_stats_.result_emits_suppressed;
    return status;
  }
  ++record.emits;
  ++applied_stats_.results_emitted;
  record.next_emit_ms =
      now_ms + applied_window_ms(kDefaultHopLimit, config_.hop_accept_timeout_ms);
  return Status::success();
}

void MeshNode::emit_app_status(const NodeId origin, const MessageKey& key,
                               const std::array<std::uint8_t, 32>& request_digest,
                               const endpoint::AppResultStatusCode code,
                               const std::uint64_t nonce,
                               const std::uint32_t lifetime_ms,
                               const MonotonicMs now_ms) noexcept {
  endpoint::AppResultStatus body{};
  body.head.subtype = endpoint::AppResultSubtype::Status;
  body.head.outcome = static_cast<std::uint8_t>(code);
  body.head.network = static_cast<std::uint32_t>(config_.network);
  body.head.original_origin = key.origin;
  body.head.original_session = key.id.session;
  body.head.original_sequence = key.id.sequence;
  body.head.original_destination = config_.node;
  body.head.request_digest = request_digest;
  body.query_nonce = nonce;
  endpoint::EncodedServicePayload encoded{};
  if (!endpoint::app_result_status_encode(body, encoded)) {
    ++applied_stats_.result_emits_suppressed;
    return;
  }
  const MessageId id{config_.message_session, next_control_sequence_++};
  const auto status =
      queue_typed_job(FrameType::AppResult, JobOwner::Applied, id, origin,
                      encoded.view(), 0, std::max<std::uint32_t>(lifetime_ms, 1),
                      Priority::Management, now_ms);
  if (status) {
    ++applied_stats_.status_sent;
  } else {
    ++applied_stats_.result_emits_suppressed;
  }
}

void MeshNode::emit_app_result_ack(const NodeId terminal,
                                   const endpoint::AppResultHead& head,
                                   const ByteView canonical_result_body,
                                   const MonotonicMs now_ms) noexcept {
  endpoint::AppResultAck ack{};
  ack.head.subtype = endpoint::AppResultSubtype::ResultAck;
  ack.head.outcome = 0;
  ack.head.network = static_cast<std::uint32_t>(config_.network);
  ack.head.original_origin = head.original_origin;
  ack.head.original_session = head.original_session;
  ack.head.original_sequence = head.original_sequence;
  ack.head.original_destination = head.original_destination;
  ack.head.request_digest = head.request_digest;
  endpoint::applied_result_digest(canonical_result_body, ack.result_digest);
  endpoint::EncodedServicePayload encoded{};
  if (!endpoint::app_result_ack_encode(ack, encoded)) return;
  const MessageId id{config_.message_session, next_control_sequence_++};
  // An ACK asserts receipt of that RESULT only — it never asserts
  // re-processing and never gets an ACK itself (01 §1.3).
  (void)queue_typed_job(FrameType::AppResult, JobOwner::Applied, id, terminal,
                        encoded.view(), 0, kControlLifetimeMs * 4,
                        Priority::Management, now_ms);
}

Status MeshNode::emit_app_query(Delivery& delivery, const MonotonicMs now_ms) noexcept {
  endpoint::AppResultQuery query{};
  query.head.subtype = endpoint::AppResultSubtype::Query;
  query.head.outcome = 0;
  query.head.network = static_cast<std::uint32_t>(config_.network);
  query.head.original_origin = config_.node;
  query.head.original_session = delivery.id.session;
  query.head.original_sequence = delivery.id.sequence;
  query.head.original_destination = delivery.destination;
  endpoint::applied_request_digest(
      config_.network, config_.node, delivery.destination, delivery.id.session,
      delivery.id.sequence, DeliveryClass::Applied, delivery.options.lifetime_ms,
      ByteView{delivery.payload.data(), delivery.payload_size},
      query.head.request_digest);
  query.query_nonce = delivery.app_query_nonce;
  endpoint::EncodedServicePayload encoded{};
  if (!endpoint::app_result_query_encode(query, encoded)) {
    return Status::error(StatusCode::InvalidArgument, "applied query encode failed");
  }
  const auto lifetime = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(delivery.expires_at_ms - now_ms,
                              std::numeric_limits<std::uint32_t>::max()));
  const MessageId id{config_.message_session, next_control_sequence_++};
  const auto status =
      queue_typed_job(FrameType::AppResult, JobOwner::Applied, id,
                      delivery.destination, encoded.view(), 0, lifetime,
                      Priority::Management, now_ms);
  if (status) ++applied_stats_.queries_sent;
  return status;
}

bool MeshNode::applied_answer_gate(const NodeId peer, const MonotonicMs now_ms) noexcept {
  auto* budget = diag_budget(peer, now_ms);
  if (budget == nullptr) return false;
  if (budget->last_applied_ms != 0 &&
      now_ms - budget->last_applied_ms < kAppliedAnswerMinIntervalMs) {
    return false;
  }
  budget->last_applied_ms = now_ms;
  return true;
}

void MeshNode::handle_app_result(const wire::PlainFrame& frame, const NodeId peer,
                                 const MonotonicMs now_ms) noexcept {
  const ByteView body{frame.payload.data(), frame.payload_size};
  const auto malformed = [&]() noexcept {
    ++applied_stats_.malformed;
    observer_.on_diagnostic("APPLIED_RESULT_MALFORMED", peer, &frame.header.message);
  };
  const auto mismatched = [&](const char* reason) noexcept {
    ++applied_stats_.mismatched;
    observer_.on_diagnostic(reason, peer, &frame.header.message);
  };
  if (body.size < 2 || body.data == nullptr) {
    malformed();
    return;
  }
  const std::uint32_t network32 = static_cast<std::uint32_t>(frame.header.network);
  switch (static_cast<endpoint::AppResultSubtype>(body.data[1])) {
    case endpoint::AppResultSubtype::Result: {
      endpoint::AppResultBody result{};
      if (!endpoint::app_result_decode(body, result)) {
        malformed();
        return;
      }
      const auto& head = result.head;
      // A RESULT must be issued by the request's bound destination and name
      // us as its origin — relays and unrelated nodes can never produce one.
      if (head.network != network32 || head.original_origin != config_.node ||
          head.original_destination != frame.header.origin) {
        mismatched("APPLIED_RESULT_MISMATCH");
        return;
      }
      // The result is end-verified: always acknowledge so the terminal's
      // emit budget stops. The ACK asserts receipt, never re-processing.
      emit_app_result_ack(frame.header.origin, head, body, now_ms);
      auto* delivery = find_delivery(
          MessageId{head.original_session, head.original_sequence});
      if (delivery == nullptr ||
          delivery->options.delivery != DeliveryClass::Applied ||
          delivery->destination != frame.header.origin ||
          delivery->state == DeliveryState::Accepted ||
          delivery->state == DeliveryState::Queued ||
          delivery->state == DeliveryState::WaitingForRoute ||
          delivery->state == DeliveryState::CancelledBeforeTx) {
        mismatched("APPLIED_RESULT_ORPHAN");
        return;
      }
      std::array<std::uint8_t, 32> digest{};
      endpoint::applied_request_digest(
          config_.network, config_.node, delivery->destination,
          delivery->id.session, delivery->id.sequence, DeliveryClass::Applied,
          delivery->options.lifetime_ms,
          ByteView{delivery->payload.data(), delivery->payload_size}, digest);
      if (digest != head.request_digest) {
        mismatched("APPLIED_RESULT_MISMATCH");
        return;
      }
      if (delivery->applied_present) {
        // Idempotent replay: the same verdict re-ACKs; a DIFFERENT verdict
        // under the same binding is a conflict — the first committed
        // outcome is never overwritten (01 §1.5).
        const bool same =
            delivery->applied_outcome == head.outcome &&
            delivery->applied_code == result.application_code &&
            delivery->applied_result_size == result.data_size &&
            (result.data_size == 0 ||
             std::memcmp(delivery->applied_result.data(), result.data.data(),
                         result.data_size) == 0);
        if (!same) mismatched("APPLIED_RESULT_CONFLICT");
        return;
      }
      delivery->applied_present = true;
      delivery->applied_outcome = head.outcome;
      delivery->applied_code = result.application_code;
      delivery->applied_result_size = static_cast<std::uint8_t>(result.data_size);
      if (result.data_size > 0) {
        std::memcpy(delivery->applied_result.data(), result.data.data(),
                    result.data_size);
      }
      ++applied_stats_.results_accepted;
      AppliedResultView view{};
      view.present = true;
      view.outcome = static_cast<endpoint::AppResultOutcome>(head.outcome);
      view.code = result.application_code;
      view.size = static_cast<std::uint8_t>(result.data_size);
      if (result.data_size > 0) {
        std::memcpy(view.data.data(), result.data.data(), result.data_size);
      }
      if (sleep_terminal(delivery->state)) {
        // Late evidence is stored and surfaced but never flips the terminal
        // verdict (01 §1.3).
        delivery->applied_late = true;
        view.late = true;
        ++applied_stats_.results_late;
        if (std::strcmp(delivery->reason, "APP_RESULT_TIMEOUT") == 0) {
          delivery->reason = "APP_RESULT_LATE";
        }
      } else if (head.outcome ==
                 static_cast<std::uint8_t>(endpoint::AppResultOutcome::Success)) {
        set_delivery_state(*delivery, DeliveryState::Delivered, "APP_APPLIED");
      } else {
        set_delivery_state(*delivery, DeliveryState::Failed, "APP_REJECTED");
      }
      observer_.on_applied_result(MessageKey{config_.node, delivery->id}, view);
      return;
    }
    case endpoint::AppResultSubtype::Query: {
      endpoint::AppResultQuery query{};
      if (!endpoint::app_result_query_decode(body, query)) {
        malformed();
        return;
      }
      const auto& head = query.head;
      // A QUERY must come from the request's origin and ask about work
      // destined to us.
      if (head.network != network32 || head.original_destination != config_.node ||
          head.original_origin != frame.header.origin) {
        mismatched("APPLIED_QUERY_MISMATCH");
        return;
      }
      ++applied_stats_.queries_received;
      const MessageKey req_key{head.original_origin,
                               MessageId{head.original_session,
                                         head.original_sequence}};
      auto* record = find_applied(req_key);
      if (record == nullptr) {
        if (!applied_answer_gate(frame.header.origin, now_ms)) {
          ++applied_stats_.result_emits_suppressed;
          return;
        }
        emit_app_status(frame.header.origin, req_key, head.request_digest,
                        endpoint::AppResultStatusCode::NotRetained,
                        query.query_nonce, frame.header.remaining_deadline_ms,
                        now_ms);
        return;
      }
      if (record->request_digest != head.request_digest) {
        mismatched("APPLIED_QUERY_MISMATCH");
        return;
      }
      if (now_ms >= record->emit_deadline_ms) {
        if (applied_answer_gate(frame.header.origin, now_ms)) {
          emit_app_status(frame.header.origin, req_key, head.request_digest,
                          endpoint::AppResultStatusCode::Expired,
                          query.query_nonce, frame.header.remaining_deadline_ms,
                          now_ms);
        }
        return;
      }
      if (record->ticket != 0) {
        if (applied_answer_gate(frame.header.origin, now_ms)) {
          emit_app_status(frame.header.origin, req_key, head.request_digest,
                          endpoint::AppResultStatusCode::Pending, query.query_nonce,
                          frame.header.remaining_deadline_ms, now_ms);
        }
        return;
      }
      // The stored verdict answers the query — the endpoint is never rerun.
      (void)emit_applied_result(*record, now_ms);
      return;
    }
    case endpoint::AppResultSubtype::ResultAck: {
      endpoint::AppResultAck ack{};
      if (!endpoint::app_result_ack_decode(body, ack)) {
        malformed();
        return;
      }
      const auto& head = ack.head;
      if (head.network != network32 || head.original_destination != config_.node ||
          head.original_origin != frame.header.origin) {
        mismatched("APPLIED_ACK_MISMATCH");
        return;
      }
      auto* record = find_applied(
          MessageKey{head.original_origin,
                     MessageId{head.original_session, head.original_sequence}});
      if (record == nullptr) return;  // expired: stale evidence, not an error
      if (record->request_digest != head.request_digest) {
        mismatched("APPLIED_ACK_MISMATCH");
        return;
      }
      // Recompute the canonical RESULT bytes from the stored record — the
      // ACK's result_digest must match the exact committed body (01 §1.2).
      endpoint::AppResultBody stored{};
      stored.head.subtype = endpoint::AppResultSubtype::Result;
      stored.head.outcome = record->outcome;
      stored.head.network = network32;
      stored.head.original_origin = record->key.origin;
      stored.head.original_session = record->key.id.session;
      stored.head.original_sequence = record->key.id.sequence;
      stored.head.original_destination = config_.node;
      stored.head.request_digest = record->request_digest;
      stored.application_code = record->application_code;
      stored.data_size = record->result_size;
      if (record->result_size > 0) {
        std::memcpy(stored.data.data(), record->result_data.data(), record->result_size);
      }
      endpoint::EncodedServicePayload canonical{};
      if (!endpoint::app_result_encode(stored, canonical)) return;
      std::array<std::uint8_t, 32> expected{};
      endpoint::applied_result_digest(canonical.view(), expected);
      if (!constant_time_equal(ByteView{expected.data(), expected.size()},
                               ByteView{ack.result_digest.data(),
                                        ack.result_digest.size()})) {
        mismatched("APPLIED_ACK_MISMATCH");
        return;
      }
      record->acked = true;
      ++applied_stats_.result_acks;
      return;
    }
    case endpoint::AppResultSubtype::Status: {
      endpoint::AppResultStatus status_body{};
      if (!endpoint::app_result_status_decode(body, status_body)) {
        malformed();
        return;
      }
      const auto& head = status_body.head;
      if (head.network != network32 || head.original_origin != config_.node ||
          head.original_destination != frame.header.origin) {
        mismatched("APPLIED_STATUS_MISMATCH");
        return;
      }
      ++applied_stats_.statuses_received;
      auto* delivery = find_delivery(
          MessageId{head.original_session, head.original_sequence});
      if (delivery == nullptr ||
          delivery->options.delivery != DeliveryClass::Applied ||
          delivery->destination != frame.header.origin) {
        mismatched("APPLIED_STATUS_ORPHAN");
        return;
      }
      // A STATUS only ever answers OUR latest QUERY — an unmatched nonce is
      // not evidence about this delivery (01 §1.3).
      if (delivery->app_queries == 0 ||
          status_body.query_nonce != delivery->app_query_nonce) {
        mismatched("APPLIED_STATUS_UNMATCHED");
        return;
      }
      if (sleep_terminal(delivery->state)) return;
      switch (static_cast<endpoint::AppResultStatusCode>(head.outcome)) {
        case endpoint::AppResultStatusCode::Pending:
          // Still executing at the terminal: keep waiting inside the deadline.
          delivery->next_round_at_ms = std::min(
              delivery->expires_at_ms,
              now_ms + applied_window_ms(delivery->options.hop_limit,
                                         config_.hop_accept_timeout_ms));
          break;
        case endpoint::AppResultStatusCode::Indeterminate:
          set_delivery_state(*delivery, DeliveryState::Indeterminate,
                             "APP_RESULT_INDETERMINATE");
          break;
        case endpoint::AppResultStatusCode::Expired:
          set_delivery_state(*delivery, DeliveryState::Indeterminate,
                             "APP_RESULT_EXPIRED");
          break;
        case endpoint::AppResultStatusCode::NotRetained:
          set_delivery_state(*delivery, DeliveryState::Indeterminate,
                             "APP_RESULT_NOT_RETAINED");
          break;
      }
      return;
    }
  }
  malformed();
}

void MeshNode::process_applied(const MonotonicMs now_ms) noexcept {
  // Retention expiry: after the hold the record is gone and a QUERY answers
  // NotRetained honestly (01 §1.6).
  while (auto* expired = applied_records_.find(
             [&](const AppliedRecord& value) { return value.expires_at_ms <= now_ms; })) {
    ++applied_stats_.expired;
    applied_records_.release(expired);
  }
  // Emit retries: an unacked committed result retransmits inside its window
  // and emit budget; dedup/QUERY replays share the same counters.
  applied_records_.for_each([&](AppliedRecord& record) {
    note_deadline(record.expires_at_ms);
    if (record.ticket == 0 && !record.acked && record.emits < kAppliedMaxEmits &&
        now_ms < record.emit_deadline_ms) {
      note_deadline(record.emit_deadline_ms);
      if (now_ms < record.next_emit_ms) note_deadline(record.next_emit_ms);
    }
    if (record.ticket == 0 && !record.acked && record.emits < kAppliedMaxEmits &&
        now_ms >= record.next_emit_ms && now_ms < record.emit_deadline_ms) {
      (void)emit_applied_result(record, now_ms);
      if (!record.acked && record.emits < kAppliedMaxEmits) {
        if (record.next_emit_ms > now_ms)
          note_deadline(record.next_emit_ms);
        else
          note_timer(now_ms, 2);
      }
    }
  });
}

}  // namespace routeloom
