#include "node_internal.hpp"

namespace routeloom {

Status MeshNode::send(const NodeId destination, const ByteView payload,
                      const SendOptions& options, const MonotonicMs now_ms,
                      MessageId& id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  last_clock_ms_ = now_ms;
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  // Any application TX intent is activity: it must invalidate an outstanding
  // sleep ticket even when the request itself is rejected below.
  ++work_generation_;
  if (paused(pause::kAppAdmission)) {
    return Status::error(StatusCode::InvalidState,
                         sleep_draining_ ? "NODE_DRAINING" : "NODE_PAUSED");
  }
  if (destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kMaxApplicationPayload || (payload.size > 0 && payload.data == nullptr) ||
      options.lifetime_ms == 0 ||
      options.lifetime_ms > kMaxMessageLifetimeMs || options.hop_limit == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid send request");
  }
  if (options.delivery == DeliveryClass::Applied) {
    // APPLIED requires the destination's execution lease — the parameter
    // only exists on send_applied; there is no silent downgrade path.
    return Status::error(StatusCode::Unsupported,
                         "APPLIED sends require send_applied()");
  }
  if (options.ordered &&
      (options.delivery != DeliveryClass::Reliable || options.persist_across_sleep)) {
    // Ordering is proven by the predecessor's END_RECEIPT (RELIABLE only);
    // the sleep image does not carry the predecessor link.
    return Status::error(StatusCode::InvalidArgument, "ORDERED_REQUIRES_RELIABLE");
  }
  return enqueue_delivery(
      MessageId{config_.message_session, next_message_sequence_}, destination,
      payload, options, now_ms, id);
}

Status MeshNode::send_applied(const NodeId destination, const ByteView payload,
                              const ExecutionLease& lease, const SendOptions& options,
                              const MonotonicMs now_ms, MessageId& id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  last_clock_ms_ = now_ms;
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  ++work_generation_;
  if (paused(pause::kAppAdmission)) {
    return Status::error(StatusCode::InvalidState,
                         sleep_draining_ ? "NODE_DRAINING" : "NODE_PAUSED");
  }
  if (destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kAppliedUserPayloadMax ||
      (payload.size > 0 && payload.data == nullptr) ||
      options.lifetime_ms == 0 ||
      options.lifetime_ms > kMaxMessageLifetimeMs || options.hop_limit == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid applied send request");
  }
  if (options.delivery != DeliveryClass::Applied || options.ordered) {
    return Status::error(StatusCode::InvalidArgument,
                         "send_applied requires DeliveryClass::Applied");
  }
  if (options.persist_across_sleep) {
    return Status::error(StatusCode::Unsupported,
                         "APPLIED sleep persistence is not implemented");
  }
  // The wire body is `execution_lease || user_payload` (01 §1.2); the lease
  // is verified by the destination against its own incarnation, never trusted.
  std::array<std::uint8_t, kMaxApplicationPayload> body{};
  std::memcpy(body.data(), lease.data(), lease.size());
  if (payload.size > 0) std::memcpy(body.data() + lease.size(), payload.data, payload.size);
  return enqueue_delivery(
      MessageId{config_.message_session, next_message_sequence_}, destination,
      ByteView{body.data(), lease.size() + payload.size}, options, now_ms, id);
}

ExecutionLease MeshNode::applied_lease() const noexcept {
  // message_session u32 | boot_session u32 | boot_incarnation u64 (P4 §9.1):
  // the lease tracks the destination's boot, not its E2E crypto epoch — an
  // E2E rekey or route change leaves it unchanged, a destination reboot
  // changes it. The session is validated nonzero, so a computed lease is
  // never all-zero and all-zero on the wire is always "no assertion" and
  // refuses (01 §1.2).
  ExecutionLease lease{};
  ByteWriter writer(MutableByteView{lease.data(), lease.size()});
  (void)writer.write_u32(config_.message_session);
  (void)writer.write_u32(config_.boot_session);
  (void)writer.write_u64(config_.boot_incarnation);
  return lease;
}

bool MeshNode::applied_result(const MessageId& id, AppliedResultView& out) const noexcept {
  const auto* delivery = find_delivery(id);
  if (delivery == nullptr || !delivery->applied_present) {
    out = AppliedResultView{};
    return false;
  }
  out.present = true;
  out.late = delivery->applied_late;
  out.outcome = static_cast<endpoint::AppResultOutcome>(delivery->applied_outcome);
  out.code = delivery->applied_code;
  out.size = delivery->applied_result_size;
  std::memcpy(out.data.data(), delivery->applied_result.data(), out.size);
  return true;
}

Status MeshNode::resume_delivery(const MessageId& id, const NodeId destination,
                                 const ByteView payload, const SendOptions& options,
                                 const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  ++work_generation_;
  if (paused(pause::kAppAdmission)) {
    return Status::error(StatusCode::InvalidState,
                         sleep_draining_ ? "NODE_DRAINING" : "NODE_PAUSED");
  }
  if (destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kMaxApplicationPayload || (payload.size > 0 && payload.data == nullptr) ||
      options.lifetime_ms == 0 ||
      options.lifetime_ms > kMaxMessageLifetimeMs || options.hop_limit == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid send request");
  }
  if (options.delivery == DeliveryClass::Applied) {
    // Resume of APPLIED work is deferred (sdk-completion/01 §1.10): the
    // request's lease/digest bookkeeping does not survive a real sleep.
    return Status::error(StatusCode::Unsupported,
                         "APPLIED resume is not implemented");
  }
  if (auto* existing = find_delivery(id)) {
    if (!sleep_terminal(existing->state)) {
      return Status::error(StatusCode::AlreadyExists, "delivery id already live");
    }
    // The terminal record is this delivery's previous incarnation
    // (SLEEP_SAVED in the in-process model): replace it so resume keeps the
    // same logical id instead of failing on the stale slot.
    deliveries_.release(existing);
  }
  MessageId out{};
  return enqueue_delivery(id, destination, payload, options, now_ms, out);
}

bool MeshNode::sleep_terminal(const DeliveryState state) noexcept {
  switch (state) {
    case DeliveryState::Empty:
    case DeliveryState::Delivered:
    case DeliveryState::Failed:
    case DeliveryState::Expired:
    case DeliveryState::CancelledBeforeTx:
    case DeliveryState::Indeterminate:
      return true;
    default:
      return false;
  }
}

Status MeshNode::enqueue_delivery(const MessageId& id, const NodeId destination,
                                  const ByteView payload, const SendOptions& options,
                                  const MonotonicMs now_ms, MessageId& out) noexcept {
  auto* record = deliveries_.allocate();
  if (record == nullptr) {
    // Terminal entries are history, not live work: evict the oldest one
    // before reporting the table full so sends are not wedged forever.
    Delivery* oldest_terminal = nullptr;
    deliveries_.for_each([&](Delivery& delivery) {
      switch (delivery.state) {
        case DeliveryState::Delivered:
        case DeliveryState::Failed:
        case DeliveryState::Expired:
        case DeliveryState::CancelledBeforeTx:
        case DeliveryState::Indeterminate:
          if (oldest_terminal == nullptr ||
              delivery.created_at_ms < oldest_terminal->created_at_ms) {
            oldest_terminal = &delivery;
          }
          break;
        default:
          break;
      }
    });
    if (oldest_terminal != nullptr) {
      // Class-(a) terminal eviction (sdk-completion/02 §2.3a): the result
      // becomes unqueryable — a real history loss, so it is counted and
      // diagnosed, never silent. Live deliveries are never evicted.
      const MessageId evicted_id = oldest_terminal->id;
      deliveries_.release(oldest_terminal);
      saturating_inc(dedup_stats_.delivery_terminal_evicted);
      observer_.on_diagnostic("DELIVERY_HISTORY_EVICTED", kInvalidNodeId,
                              &evicted_id);
      record = deliveries_.allocate();
    }
    if (record == nullptr) {
      return Status::error(StatusCode::NoCapacity, "delivery table full");
    }
  }
  record->id = id;
  // Keep the sequence space disjoint: a later send() must never reissue a
  // logical id that a resumed delivery still owns.
  if (id.session == config_.message_session && id.sequence >= next_message_sequence_ &&
      id.sequence != UINT64_MAX) {
    next_message_sequence_ = id.sequence + 1;
  }
  record->destination = destination;
  record->options = options;
  record->payload_size = payload.size;
  if (payload.size > 0) std::memcpy(record->payload.data(), payload.data, payload.size);
  record->created_at_ms = now_ms;
  record->expires_at_ms = now_ms + options.lifetime_ms;
  record->round = 0;
  set_delivery_state(*record, DeliveryState::Accepted, "TX_ACCEPTED");
  out = record->id;

  if (options.ordered) {
    // Per-source ordering (group-delivery.md §6): the newest earlier ordered
    // delivery to the same destination that may still reach it is this
    // one's predecessor. Delivered is proof of arrival; an undelivered one
    // can still arrive until its own deadline, so that deadline bounds the
    // wait (a CancelledBeforeTx predecessor never left and never blocks).
    const Delivery* predecessor = nullptr;
    deliveries_.for_each([&](const Delivery& other) {
      if (&other == record || !other.options.ordered ||
          other.destination != destination ||
          other.state == DeliveryState::Delivered ||
          other.state == DeliveryState::CancelledBeforeTx ||
          now_ms >= other.expires_at_ms) {
        return;
      }
      if (predecessor == nullptr || other.created_at_ms > predecessor->created_at_ms ||
          (other.created_at_ms == predecessor->created_at_ms &&
           other.id.sequence > predecessor->id.sequence)) {
        predecessor = &other;
      }
    });
    if (predecessor != nullptr) {
      record->order_after = predecessor->id;
      record->order_hold_until_ms = predecessor->expires_at_ms;
      record->order_wait = true;
      record->next_round_at_ms = now_ms;
      set_delivery_state(*record, DeliveryState::WaitingForRoute, "ORDER_WAIT");
      return Status::success();
    }
  }

  const auto status = queue_origin_data(*record, now_ms);
  if (!status) {
    if (status.code == StatusCode::NoRoute || status.code == StatusCode::WouldBlock) {
      set_delivery_state(*record, DeliveryState::WaitingForRoute, status.detail);
      record->next_round_at_ms = now_ms + 50;
      return Status::success();
    }
    deliveries_.release(record);
    return status;
  }
  return Status::success();
}

Status MeshNode::cancel(const MessageId& id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  auto* record = find_delivery(id);
  if (record == nullptr) return Status::error(StatusCode::NotFound, "delivery not found");
  switch (record->state) {
    case DeliveryState::Accepted:
    case DeliveryState::WaitingForRoute:
    case DeliveryState::Queued:
      set_delivery_state(*record, DeliveryState::CancelledBeforeTx, "CANCELLED_BEFORE_TX");
      return Status::success();
    case DeliveryState::WaitingForMac:
    case DeliveryState::WaitingForHopAccept:
    case DeliveryState::WaitingForEndReceipt:
      set_delivery_state(*record, DeliveryState::Indeterminate, "CANCEL_AFTER_TX_INDETERMINATE");
      return Status::success();
    default:
      return Status::error(StatusCode::InvalidState, "delivery is already terminal");
  }
}

DeliveryResult MeshNode::delivery(const MessageId& id) const noexcept {
  const auto* record = find_delivery(id);
  return record == nullptr ? DeliveryResult{id, DeliveryState::Empty, "NOT_FOUND"}
                           : DeliveryResult{id, record->state, record->reason};
}

Status MeshNode::queue_origin_data(Delivery& delivery, const MonotonicMs now_ms) noexcept {
  if (now_ms >= delivery.expires_at_ms) {
    return Status::error(StatusCode::Expired, "DEADLINE_EXPIRED");
  }
  const auto route = routes_.best(delivery.destination);
  if (!route.valid || find_neighbor(route.next_hop) == nullptr) {
    // Scoped profile: non-gateway destinations outside our subtree are
    // found on demand (routing-scale.md §4); the delivery waits for it.
    request_route_discovery(delivery.destination, now_ms);
    return Status::error(StatusCode::NoRoute, "NO_ROUTE");
  }
  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = JobOwner::OriginDelivery;
  job.peer = route.next_hop;
  job.requires_hop_accept = delivery.options.delivery == DeliveryClass::Reliable ||
                            delivery.options.delivery == DeliveryClass::Applied;
  job.max_attempts = config_.max_link_attempts;
  job.deadline_ms = delivery.expires_at_ms;
  job.ack = AckKey{FrameType::Data, MessageKey{config_.node, delivery.id}, delivery.round};
  job.plain.header.type = FrameType::Data;
  // Application DATA is always end-to-end protected: no code path may queue a
  // plaintext DATA frame (receivers reject it with END_PROTECTION_REQUIRED).
  job.plain.header.flags = wire::kFlagEndProtected;
  job.plain.header.delivery = delivery.options.delivery;
  job.plain.header.delivery_round = delivery.round;
  job.plain.header.hop_remaining = delivery.options.hop_limit;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = delivery.destination;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = route.next_hop;
  job.plain.header.message = delivery.id;
  job.plain.header.remaining_deadline_ms = static_cast<std::uint32_t>(delivery.expires_at_ms - now_ms);
  job.plain.header.original_lifetime_ms = delivery.options.lifetime_ms;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  job.plain.payload_size = delivery.payload_size;
  if (delivery.payload_size > 0) {
    std::memcpy(job.plain.payload.data(), delivery.payload.data(), delivery.payload_size);
  }
  job.priority = delivery.options.priority;
  const auto queued = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  if (!queued) return queued;
  set_delivery_state(delivery, DeliveryState::Queued, "QUEUED");
  return Status::success();
}

Status MeshNode::queue_forward(const wire::LinkOpenedFrame& frame, const NodeId next_hop,
                               const TxnHandle txn,
                               const MonotonicMs now_ms) noexcept {
  TxJob job{};
  job.set_forwarded(frame);
  job.owner = JobOwner::Transit;
  job.peer = next_hop;
  job.requires_hop_accept = true;
  job.max_attempts = config_.max_link_attempts;
  // The forwarding budget is the frame's remaining deadline MINUS the time
  // it already spent queued in the driver — a saturating debit, never a
  // freshly-inflated lifetime (01 §lifetime). The transaction deadline
  // bounds local work on top via work_deadline; the wire keeps this budget.
  const std::uint32_t remaining =
      frame.header.remaining_deadline_ms > rx_age_ms_
          ? frame.header.remaining_deadline_ms - rx_age_ms_
          : 0;
  job.deadline_ms = now_ms + remaining;
  job.ack = AckKey{frame.header.type,
                   MessageKey{frame.header.origin, frame.header.message},
                   frame.header.delivery_round};
  job.txn = txn;
  Status status = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  if (status) join_txn(txn);
  return status;
}

void MeshNode::join_txn(const TxnHandle handle) noexcept {
  if (handle == kInvalidTxnHandle || handle.slot >= txn_slots_.size()) return;
  TxnSlot& slot = txn_slots_[handle.slot];
  if (slot.state != TxnState::Free && slot.serial == handle.serial &&
      slot.work_refs < UINT8_MAX) {
    ++slot.work_refs;
  }
}

Status MeshNode::encode_ack_payload(const AckKey& key,
                                    std::array<std::uint8_t, kMaxApplicationPayload>& payload,
                                    std::size_t& size) noexcept {
  ByteWriter writer(MutableByteView{payload.data(), payload.size()});
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u8(static_cast<std::uint8_t>(key.accepted_type)));
  RL_WRITE(writer.write_u64(key.key.origin));
  RL_WRITE(writer.write_u32(key.key.id.session));
  RL_WRITE(writer.write_u64(key.key.id.sequence));
  RL_WRITE(writer.write_u8(key.round));
#undef RL_WRITE
  size = writer.size();
  return Status::success();
}

Status MeshNode::decode_ack_payload(const ByteView payload, AckKey& key) noexcept {
  ByteReader reader(payload);
  std::uint8_t type = 0;
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u8(type));
  RL_READ(reader.read_u64(key.key.origin));
  RL_READ(reader.read_u32(key.key.id.session));
  RL_READ(reader.read_u64(key.key.id.sequence));
  RL_READ(reader.read_u8(key.round));
#undef RL_READ
  const bool known_type = type == static_cast<std::uint8_t>(FrameType::Data) ||
      type == static_cast<std::uint8_t>(FrameType::EndReceipt) ||
      type == static_cast<std::uint8_t>(FrameType::BootstrapAuth) ||
      type == static_cast<std::uint8_t>(FrameType::MembershipResult) ||
      type == static_cast<std::uint8_t>(FrameType::BootstrapChunk) ||
      type == static_cast<std::uint8_t>(FrameType::BootstrapReply) ||
      type == static_cast<std::uint8_t>(FrameType::Service) ||
      type == static_cast<std::uint8_t>(FrameType::Control) ||
      type == static_cast<std::uint8_t>(FrameType::ControlObject) ||
      type == static_cast<std::uint8_t>(FrameType::ObjectChunk) ||
      type == static_cast<std::uint8_t>(FrameType::ObjectAck) ||
      type == static_cast<std::uint8_t>(FrameType::RouteUpdate) ||
      type == static_cast<std::uint8_t>(FrameType::SeqnoRequest) ||
      type == static_cast<std::uint8_t>(FrameType::Diagnostic) ||
      type == static_cast<std::uint8_t>(FrameType::AppResult);
  if (reader.remaining() != 0 || !known_type) {
    return Status::error(StatusCode::ProtocolError, "invalid hop accept payload");
  }
  key.accepted_type = static_cast<FrameType>(type);
  return Status::success();
}

Status MeshNode::queue_hop_accept(const wire::Header& accepted,
                                  const TxnHandle txn,
                                  const MonotonicMs now_ms) noexcept {
  TxJob job{};
  job.form = JobForm::Plain;
  job.peer = accepted.previous_hop;
  job.requires_hop_accept = false;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kControlLifetimeMs;
  job.txn = txn;
  job.plain.header.type = FrameType::HopAccept;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.delivery_round = accepted.delivery_round;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = accepted.previous_hop;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = accepted.previous_hop;
  job.plain.header.message = accepted.message;
  job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
  job.plain.header.original_lifetime_ms = kControlLifetimeMs;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  job.ack = AckKey{accepted.type, MessageKey{accepted.origin, accepted.message},
                   accepted.delivery_round};
  auto status = encode_ack_payload(job.ack, job.plain.payload, job.plain.payload_size);
  if (!status) return status;
  status = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  if (status) join_txn(txn);
  return status;
}

Status MeshNode::encode_receipt_payload(
    const wire::Header& data, std::array<std::uint8_t, kMaxApplicationPayload>& payload,
    std::size_t& size) noexcept {
  ByteWriter writer(MutableByteView{payload.data(), payload.size()});
  Status status;
#define RL_WRITE(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE(writer.write_u64(data.origin));
  RL_WRITE(writer.write_u64(data.destination));
  RL_WRITE(writer.write_u32(data.message.session));
  RL_WRITE(writer.write_u64(data.message.sequence));
  RL_WRITE(writer.write_u8(data.delivery_round));
  RL_WRITE(writer.write_u8(0));
#undef RL_WRITE
  size = writer.size();
  return Status::success();
}

Status MeshNode::decode_receipt_payload(const ByteView payload, MessageKey& key,
                                        std::uint8_t& round) noexcept {
  ByteReader reader(payload);
  NodeId original_destination = 0;
  std::uint8_t result = 0;
  Status status;
#define RL_READ(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ(reader.read_u64(key.origin));
  RL_READ(reader.read_u64(original_destination));
  RL_READ(reader.read_u32(key.id.session));
  RL_READ(reader.read_u64(key.id.sequence));
  RL_READ(reader.read_u8(round));
  RL_READ(reader.read_u8(result));
#undef RL_READ
  if (reader.remaining() != 0 || result != 0) {
    return Status::error(StatusCode::ProtocolError, "invalid end receipt payload");
  }
  return original_destination == kInvalidNodeId
             ? Status::error(StatusCode::ProtocolError, "invalid receipt destination")
             : Status::success();
}

Status MeshNode::queue_end_receipt(const wire::Header& data,
                                   const TxnHandle txn,
                                   const MonotonicMs now_ms,
                                   DedupEntry* carrier) noexcept {
  const auto route = routes_.best(data.origin);
  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = JobOwner::Transit;
  // A missing route leaves the receipt queued under the transaction's
  // deadline. Dispatch resolves the route again before sending it.
  job.peer = route.valid ? route.next_hop : kInvalidNodeId;
  job.requires_hop_accept = true;
  job.max_attempts = config_.max_link_attempts;
  job.deadline_ms = now_ms + data.remaining_deadline_ms;
  job.plain.header.type = FrameType::EndReceipt;
  job.plain.header.flags = wire::kFlagEndProtected;
  job.plain.header.delivery = DeliveryClass::Reliable;
  job.plain.header.delivery_round = data.delivery_round;
  // The receipt gets its own full hop budget — the DATA's remainder is often
  // 1 at the end of a long path, which would strand the return trip.
  job.plain.header.hop_remaining = kDefaultHopLimit;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = data.origin;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = route.next_hop;
  job.plain.header.message = data.message;
  job.plain.header.remaining_deadline_ms = data.remaining_deadline_ms;
  job.plain.header.original_lifetime_ms = data.original_lifetime_ms;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  // Known wire ambiguity: the ack key is {our node id, the ORIGIN's
  // MessageId, round}. Two origins that mint the same (session, sequence)
  // produce identical keys for receipts to different destinations; a
  // HOP_ACCEPT then matches the first awaiting entry and ends the
  // sibling's link wait early. Bounded — dedup pins, emit budgets, and
  // end-to-end retries are unaffected.
  job.ack = AckKey{FrameType::EndReceipt, MessageKey{config_.node, data.message},
                   data.delivery_round};
  auto status = encode_receipt_payload(data, job.plain.payload, job.plain.payload_size);
  if (!status) return status;
  // Seal the End envelope eagerly so re-emissions can replay it: a
  // same-round duplicate DATA re-queues a receipt that must be
  // byte-identical, or a transit relay's dedup fingerprint would read the
  // reissue as a conflict and the origin would never see it. The pin lives
  // on the carrier dedup record's evidence block — a terminal record never
  // carries a transit fingerprint, so the block is free — keyed to the
  // round it was minted for; a different round is a different receipt and
  // seals fresh. The has_fingerprint gate keeps an overlaid transit
  // fingerprint from ever being read as a pin.
  std::uint64_t end_counter = 0;
  std::uint32_t end_epoch = 0;
  bool pinned = false;
  if (carrier != nullptr && !carrier->has_fingerprint &&
      carrier->evidence.receipt.sealed &&
      carrier->evidence.receipt.round == data.delivery_round) {
    end_counter = carrier->evidence.receipt.end_counter;
    end_epoch = carrier->evidence.receipt.end_epoch;
    job.plain.header.original_lifetime_ms =
        carrier->evidence.receipt.original_lifetime_ms;
    job.plain.header.remaining_deadline_ms =
        std::min(job.plain.header.remaining_deadline_ms,
                 job.plain.header.original_lifetime_ms);
    pinned = true;
  }
  wire::LinkOpenedFrame sealed{};
  if (wire::seal_end(job.plain, security_, sealed, end_counter, end_epoch,
                     pinned).ok()) {
    // Sealed rides dispatch's retry_local path: per-hop retries re-wrap the
    // same end ciphertext, exactly like an origin DATA job's first seal.
    job.set_forwarded(sealed);
    job.form = JobForm::Sealed;
    if (carrier != nullptr && !pinned) {
      // Begin the pin member's lifetime over the evidence block — the
      // transit fingerprint never lives on a terminal record (and a
      // pathological same-key carrier loses it deliberately here).
      carrier->has_fingerprint = false;
      auto* pin = ::new (static_cast<void*>(&carrier->evidence.receipt))
          DedupEntry::DedupEvidence::ReceiptPin{};
      pin->end_counter = end_counter;
      pin->end_epoch = end_epoch;
      pin->original_lifetime_ms = job.plain.header.original_lifetime_ms;
      pin->round = data.delivery_round;
      pin->sealed = true;
    }
  }
  // A failed eager seal (no end context yet, pinned epoch retired) leaves
  // the job Plain: dispatch's encode_job mints a fresh envelope there,
  // which is the pre-pin behaviour and stays deadline-bounded.
  // The receipt's own deadline is the terminal frame budget; the
  // transaction deadline bounds local work on top via work_deadline.
  job.txn = txn;
  status = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  if (status) join_txn(txn);
  return status;
}

MeshNode::TxJob MeshNode::link_control_job(const FrameType type, const NodeId neighbor,
                                           const std::uint32_t lifetime_ms,
                                           const MonotonicMs now_ms) noexcept {
  // One-hop, link-protected, best-effort route-control frame bound to the
  // receiving neighbor (ROUTE_UPDATE / SEQNO_REQUEST / ROUTE_REQUEST).
  TxJob job{};
  job.form = JobForm::Plain;
  job.peer = neighbor;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + lifetime_ms;
  job.plain.header.type = type;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = neighbor;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = neighbor;
  job.plain.header.message = MessageId{config_.message_session, next_control_sequence_++};
  job.plain.header.remaining_deadline_ms = lifetime_ms;
  job.plain.header.original_lifetime_ms = lifetime_ms;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  return job;
}

// --- Service=21 carrier (scope-gateway-config 03 §3.3, 05 §5.3) ------------------
// A dedicated end-protected terminal lane beside DATA: hop-level ACK
// references type 21, relays forward the protected payload untouched, and
// completion is owned by the GatewayDelivery component — never borrowed
// from END_RECEIPT or implied by Node-DATA success.

Status MeshNode::send_service(const NodeId destination, const ByteView payload,
                              const std::uint32_t lifetime_ms,
                              const MonotonicMs now_ms, MessageId& id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  return send_service_impl(destination, payload, lifetime_ms, Priority::Normal,
                           now_ms, id);
}

Status MeshNode::send_service(const NodeId destination, const ByteView payload,
                              const std::uint32_t lifetime_ms, const Priority priority,
                              const MonotonicMs now_ms, MessageId& id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  return send_service_impl(destination, payload, lifetime_ms, priority, now_ms, id);
}

Status MeshNode::send_service_impl(const NodeId destination, const ByteView payload,
                                   const std::uint32_t lifetime_ms, const Priority priority,
                                   const MonotonicMs now_ms, MessageId& id) noexcept {
  last_clock_ms_ = now_ms;
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  ++work_generation_;
  if (paused(pause::kAppAdmission)) {
    return Status::error(StatusCode::InvalidState,
                         sleep_draining_ ? "NODE_DRAINING" : "NODE_PAUSED");
  }
  if (destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kMaxApplicationPayload || (payload.size > 0 && payload.data == nullptr) ||
      lifetime_ms == 0 ||
      lifetime_ms > kMaxMessageLifetimeMs) {
    return Status::error(StatusCode::InvalidArgument, "invalid service send");
  }
  id = MessageId{config_.message_session, next_message_sequence_++};
  return queue_typed_job(FrameType::Service, JobOwner::GatewayService, id,
                         destination, payload, /*round=*/0, lifetime_ms,
                         priority, now_ms);
}

Status MeshNode::resend_service(const MessageId& id, const NodeId destination,
                                const ByteView payload, const std::uint8_t round,
                                const std::uint32_t lifetime_ms,
                                const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  last_clock_ms_ = now_ms;
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  ++work_generation_;
  if (paused(pause::kAppAdmission)) {
    return Status::error(StatusCode::InvalidState,
                         sleep_draining_ ? "NODE_DRAINING" : "NODE_PAUSED");
  }
  if (id.sequence == 0 || destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kMaxApplicationPayload || (payload.size > 0 && payload.data == nullptr) ||
      lifetime_ms == 0 ||
      lifetime_ms > kMaxMessageLifetimeMs) {
    return Status::error(StatusCode::InvalidArgument, "invalid service resend");
  }
  return queue_typed_job(FrameType::Service, JobOwner::GatewayService, id,
                         destination, payload, round, lifetime_ms,
                         Priority::Normal, now_ms);
}

Status MeshNode::send_typed(const FrameType type, const NodeId destination,
                            const ByteView payload, const std::uint32_t lifetime_ms,
                            const MonotonicMs now_ms, MessageId& id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  last_clock_ms_ = now_ms;
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  ++work_generation_;
  if (paused(pause::kAppAdmission)) {
    return Status::error(StatusCode::InvalidState,
                         sleep_draining_ ? "NODE_DRAINING" : "NODE_PAUSED");
  }
  // This lane exists for the routed end-protected config types only. The
  // link-scoped autonomy forms of the object types must NOT be sent here
  // (they keep their own MigrationWirePort path), and Service stays on
  // send_service.
  const bool config_type = type == FrameType::Control ||
      type == FrameType::ControlObject || type == FrameType::ObjectChunk ||
      type == FrameType::ObjectAck;
  if (!config_type || destination == kInvalidNodeId || destination == config_.node ||
      payload.size > kMaxApplicationPayload || (payload.size > 0 && payload.data == nullptr) ||
      lifetime_ms == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid typed send");
  }
  id = MessageId{config_.message_session, next_message_sequence_++};
  return queue_typed_job(type, JobOwner::Config, id, destination, payload,
                         /*round=*/0, lifetime_ms, Priority::Normal, now_ms);
}

Status MeshNode::send_bootstrap(const NodeId destination, const FrameType type,
                                const ByteView payload, const std::uint32_t lifetime_ms,
                                const MonotonicMs now_ms, MessageId& id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  last_clock_ms_ = now_ms;
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  ++work_generation_;
  if (paused(pause::kAppAdmission)) {
    return Status::error(StatusCode::InvalidState,
                         sleep_draining_ ? "NODE_DRAINING" : "NODE_PAUSED");
  }
  const bool bootstrap_type = type == FrameType::BootstrapAuth ||
      type == FrameType::MembershipResult || type == FrameType::BootstrapChunk ||
      type == FrameType::BootstrapReply;
  if (!bootstrap_type || destination == kInvalidNodeId || destination == config_.node ||
      reserved_node_id(destination) || payload.size > kMaxApplicationPayload ||
      (payload.size > 0 && payload.data == nullptr) || lifetime_ms == 0 ||
      lifetime_ms > kMaxMessageLifetimeMs) {
    return Status::error(StatusCode::InvalidArgument, "invalid bootstrap send");
  }
  // The lane's own slice of the pool, computed live (P4 §7.4): 8 jobs
  // total, 2 per next hop. The route lookup below names the peer, so the
  // per-peer check runs against the resolved next hop, not the destination.
  if (scheduler_.count_owner(JobOwner::Bootstrap) >= kBootstrapJobsMax) {
    return Status::error(StatusCode::NoCapacity, "BOOTSTRAP_LANE_FULL");
  }
  const auto route = routes_.best(destination);
  if (!route.valid || find_neighbor(route.next_hop) == nullptr) {
    request_route_discovery(destination, now_ms);  // scoped profile only
    return Status::error(StatusCode::NoRoute, "NO_ROUTE");
  }
  if (scheduler_.count_owner_peer(JobOwner::Bootstrap, route.next_hop) >=
      kBootstrapJobsPerPeer) {
    return Status::error(StatusCode::NoCapacity, "BOOTSTRAP_PEER_FULL");
  }
  id = MessageId{config_.message_session, next_message_sequence_++};
  return queue_typed_job(type, JobOwner::Bootstrap, id, destination, payload,
                         /*round=*/0, lifetime_ms, Priority::Normal, now_ms,
                         /*end_protected=*/false);
}

Status MeshNode::queue_typed_job(const FrameType type, const JobOwner owner,
                                 const MessageId& id, const NodeId destination,
                                 const ByteView payload, const std::uint8_t round,
                                 const std::uint32_t lifetime_ms,
                                 const Priority priority,
                                 const MonotonicMs now_ms, const bool end_protected) noexcept {
  const auto route = routes_.best(destination);
  if (!route.valid || find_neighbor(route.next_hop) == nullptr) {
    request_route_discovery(destination, now_ms);  // scoped profile only
    return Status::error(StatusCode::NoRoute, "NO_ROUTE");
  }
  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = owner;
  job.peer = route.next_hop;
  // 03 §3.3: link authentication + bounded hop acceptance on every hop,
  // including the terminal gateway and the receipt's return path.
  job.requires_hop_accept = true;
  job.max_attempts = config_.max_link_attempts;
  job.deadline_ms = now_ms + lifetime_ms;
  job.ack = AckKey{type, MessageKey{config_.node, id}, round};
  job.plain.header.type = type;
  // §5.3: every Service payload is link AND end protected — the plaintext
  // path does not exist for this type (receivers drop it). Only the
  // bootstrap lane (P4 §7.4) sends link-only, so a relay forwards it
  // while holding no end session.
  job.plain.header.flags = end_protected ? wire::kFlagEndProtected : 0;
  job.plain.header.delivery = DeliveryClass::Reliable;
  job.plain.header.delivery_round = round;
  job.plain.header.hop_remaining = kDefaultHopLimit;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = destination;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = route.next_hop;
  job.plain.header.message = id;
  job.plain.header.remaining_deadline_ms = lifetime_ms;
  job.plain.header.original_lifetime_ms = lifetime_ms;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  job.plain.payload_size = payload.size;
  if (payload.size > 0) {
    std::memcpy(job.plain.payload.data(), payload.data, payload.size);
  }
  // The component picks the class: gateway outcomes (Descriptor/Receipt/
  // Pending/Reject) ride Management as receipt-class traffic, Query/Submit
  // stay Normal app traffic.
  job.priority = priority;
  if (owner == JobOwner::GatewayService || owner == JobOwner::Config) {
    // The completion event slot is held at send time (design-q116 §8.3):
    // when the queue cannot promise the completion, the send is Busy and
    // nothing is queued — the completion can never be silently lost.
    if (!component_payload_event_available()) {
      return Status::error(StatusCode::Busy, "COMPONENT_EVENT_FULL");
    }
  }
  AdmissionReservation reply{};
  if (owner == JobOwner::Applied || owner == JobOwner::Diagnostic) {
    // APPLIED answers and diagnostic replies are replies, not origin
    // traffic: each emission holds its own short reply transaction on the
    // destination's current mapping. Unaffordable emissions fail here and
    // are counted at the call site — never queued unprotected.
    if (!reserve_short_reply(destination, /*needs_control_slot=*/false, 1,
                             now_ms, reply)) {
      return Status::error(StatusCode::WouldBlock, "REPLY_UNAFFORDABLE");
    }
    job.txn = reply.txn;
  }
  Status status = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  if (!status) return status;
  if (owner == JobOwner::GatewayService || owner == JobOwner::Config) {
    ++component_jobs_outstanding_;
  }
  if (owner == JobOwner::Applied || owner == JobOwner::Diagnostic) {
    join_txn(reply.txn);
    reply.committed = true;
  }
  return Status::success();
}

}  // namespace routeloom
