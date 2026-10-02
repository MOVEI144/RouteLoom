#include "node_internal.hpp"

namespace routeloom {

// ---------------------------------------------------------------------------
// ExpectedReply admission transactions (issue #117)
// ---------------------------------------------------------------------------

MeshNode::AdmissionReservation::~AdmissionReservation() noexcept {
  rollback();
}

void MeshNode::AdmissionReservation::rollback() noexcept {
  if (committed || node == nullptr) return;
  // Reverse-order rollback of an uncommitted reservation. Records release
  // exactly; the lease use and the transaction slot recycle only while no
  // successfully enqueued job references them yet — a post-probe enqueue
  // failure is impossible single-threaded, but accepted work must never
  // lose its transaction if one ever did.
  if (dedup != nullptr) {
    node->dedup_.release(dedup);
    dedup = nullptr;
  }
  if (applied != nullptr && applied_new) {
    node->applied_records_.release(applied);
    applied = nullptr;
    applied_new = false;
  }
  if (txn != kInvalidTxnHandle) {
    const TxnSlot* slot = node->resolve_txn(txn);
    if (slot != nullptr && slot->work_refs == 0) {
      if (node->reply_peer_port_ != nullptr &&
          use != kInvalidReplyLeaseToken) {
        (void)node->reply_peer_port_->release(use);
      }
      // resolve_txn success implies a live slot at txn.slot.
      TxnSlot& live = node->txn_slots_[txn.slot];
      live.state = TxnState::Free;
      live.use = kInvalidReplyLeaseToken;
      live.deadline_ms = 0;
      live.work_refs = 0;
    }
    txn = kInvalidTxnHandle;
    use = kInvalidReplyLeaseToken;
  } else if (use != kInvalidReplyLeaseToken) {
    if (node->reply_peer_port_ != nullptr) {
      (void)node->reply_peer_port_->release(use);
    }
    use = kInvalidReplyLeaseToken;
  }
  node = nullptr;
}

RxBinding MeshNode::capture_rx_binding(
    const NodeId peer, const RadioRxMetadataV2* metadata,
    const std::uint32_t link_epoch) const noexcept {
  RxBinding rx{};
  if (reply_peer_port_ == nullptr || metadata == nullptr) return rx;
  if (peer == kInvalidNodeId || metadata->binding == kInvalidBindingId ||
      metadata->binding_generation == BindingGeneration{0} ||
      link_epoch == 0) {
    return rx;
  }
  rx.binding.peer = peer;
  rx.binding.id = metadata->binding;
  rx.binding.generation = metadata->binding_generation;
  rx.binding.rx_context_id = link_epoch;
  rx.valid = true;
  return rx;
}

bool MeshNode::txn_deadline_for(const std::uint32_t remaining_deadline_ms,
                                const MonotonicMs now_ms,
                                MonotonicMs& out) const noexcept {
  out = 0;
  // A frame whose driver-queue time already consumed its budget is dead on
  // arrival — it is refused, never admitted with a zero deadline.
  if (remaining_deadline_ms <= rx_age_ms_) return false;
  const std::uint64_t budget =
      static_cast<std::uint64_t>(remaining_deadline_ms - rx_age_ms_);
  if (now_ms > UINT64_MAX - budget) return false;
  if (now_ms > UINT64_MAX - kReplyLeaseTtlMs) return false;
  const MonotonicMs frame_deadline = now_ms + budget;
  const MonotonicMs horizon = now_ms + kReplyLeaseTtlMs;
  out = frame_deadline < horizon ? frame_deadline : horizon;
  return out > now_ms;
}

bool MeshNode::txn_slot_available() const noexcept {
  for (const auto& slot : txn_slots_) {
    if (slot.state != TxnState::Free || slot.retired) continue;
    std::uint32_t ignored = 0;
    if (next_use_serial(slot.serial, ignored)) return true;
  }
  return false;
}

Status MeshNode::begin_txn(const ReplyLeaseToken use,
                           const MonotonicMs deadline_ms,
                           TxnHandle& out) noexcept {
  out = kInvalidTxnHandle;
  bool retired_seen = false;
  for (std::size_t i = 0; i < txn_slots_.size(); ++i) {
    TxnSlot& slot = txn_slots_[i];
    if (slot.state != TxnState::Free) continue;
    if (slot.retired) {
      retired_seen = true;
      continue;
    }
    std::uint32_t serial = 0;
    if (!next_use_serial(slot.serial, serial)) {
      slot.retired = true;
      retired_seen = true;
      continue;
    }
    slot.serial = serial;
    slot.use = use;
    slot.deadline_ms = deadline_ms;
    slot.work_refs = 0;
    slot.state = TxnState::Committed;
    out.slot = static_cast<std::uint32_t>(i);
    out.serial = serial;
    return Status::success();
  }
  return Status::error(retired_seen ? StatusCode::CounterExhausted
                                    : StatusCode::NoCapacity,
                       retired_seen ? "transaction serials exhausted"
                                    : "8 transactions live");
}

const MeshNode::TxnSlot* MeshNode::resolve_txn(
    const TxnHandle handle) const noexcept {
  if (handle.slot >= txn_slots_.size()) return nullptr;
  const TxnSlot& slot = txn_slots_[handle.slot];
  if (slot.state == TxnState::Free || slot.serial != handle.serial) {
    return nullptr;
  }
  return &slot;
}

void MeshNode::finish_txn_work(const TxnHandle handle) noexcept {
  if (handle.slot >= txn_slots_.size()) return;
  TxnSlot& slot = txn_slots_[handle.slot];
  if (slot.state == TxnState::Free || slot.serial != handle.serial) return;
  if (slot.work_refs > 0) --slot.work_refs;
  if (slot.work_refs != 0) return;
  // Last reference — live or Closing: release the lease use and recycle
  // the slot at once; nothing lingers until a timer.
  if (reply_peer_port_ != nullptr &&
      slot.use != kInvalidReplyLeaseToken) {
    (void)reply_peer_port_->release(slot.use);
  }
  slot.state = TxnState::Free;
  slot.use = kInvalidReplyLeaseToken;
  slot.deadline_ms = 0;
}

MonotonicMs MeshNode::work_deadline(const TxJob& job) const noexcept {
  if (job.txn == kInvalidTxnHandle) return job.deadline_ms;
  const TxnSlot* slot = resolve_txn(job.txn);
  if (slot == nullptr) {
    // A live job always references a live transaction; a stale handle is a
    // bug — fail closed so the job can never transmit past its account.
    return 0;
  }
  return job.deadline_ms < slot->deadline_ms ? job.deadline_ms
                                             : slot->deadline_ms;
}

bool MeshNode::applied_slot_available(const MonotonicMs now_ms) noexcept {
  // Read-only: a free slot, or one allocate_applied() may reclaim — an
  // expired record or an ACKed one (the origin holds its verdict, 01 §1.7).
  // An unacked in-window record is never reclaimed, so a full pool of them
  // refuses and the origin retries.
  if (applied_records_.size() < applied_records_.capacity()) return true;
  bool reclaimable = false;
  applied_records_.for_each([&](const AppliedRecord& value) {
    if (value.expires_at_ms <= now_ms || value.acked) reclaimable = true;
  });
  return reclaimable;
}

bool MeshNode::component_event_available() const noexcept {
  for (const auto& slot : event_slots_) {
    if (slot.state != EventState::Free || slot.retired) continue;
    std::uint32_t ignored = 0;
    if (next_use_serial(slot.serial, ignored)) return true;
  }
  return false;
}

bool MeshNode::component_payload_event_available() const noexcept {
  if (!component_event_available()) return false;
  return component_events_pending() + component_jobs_outstanding_ <
         kComponentEventsMax;
}

bool MeshNode::component_target_pending(
    const ComponentEventTarget target) const noexcept {
  for (const auto& slot : event_slots_) {
    if (slot.state != EventState::Free && slot.event.target == target) {
      return true;
    }
  }
  return false;
}

void MeshNode::publish_component_event(
    const ComponentEventTarget target, const NodeId peer, const TxnHandle txn,
    const MonotonicMs deadline_ms, const wire::PlainFrame* frame,
    const MessageId* job_id, const bool job_accepted,
    const char* job_reason) noexcept {
  for (std::size_t i = 0; i < event_slots_.size(); ++i) {
    EventSlot& slot = event_slots_[i];
    if (slot.state != EventState::Free || slot.retired) continue;
    std::uint32_t serial = 0;
    if (!next_use_serial(slot.serial, serial)) {
      slot.retired = true;
      continue;
    }
    slot.serial = serial;
    slot.event = ComponentEvent{};
    slot.event.handle.slot = static_cast<std::uint32_t>(i);
    slot.event.handle.serial = serial;
    slot.event.target = target;
    slot.event.peer = peer;
    slot.event.txn = txn;
    slot.event.deadline_ms = deadline_ms;
    if (frame != nullptr) {
      slot.event.frame = *frame;
      // Terminal components inherit the budget after time in the driver queue.
      const auto remaining = frame->header.remaining_deadline_ms;
      slot.event.frame.header.remaining_deadline_ms =
          remaining > rx_age_ms_ ? remaining - rx_age_ms_ : 0;
    }
    if (job_id != nullptr) slot.event.job_id = *job_id;
    slot.event.job_accepted = job_accepted;
    slot.event.job_reason = job_reason;
    slot.state = EventState::Queued;
    if (txn != kInvalidTxnHandle) {
      if (txn.slot < txn_slots_.size()) {
        TxnSlot& live = txn_slots_[txn.slot];
        if (live.state != TxnState::Free && live.serial == txn.serial &&
            live.work_refs < UINT8_MAX) {
          ++live.work_refs;
        }
      }
    }
    return;
  }
  // Unreachable: every publisher probes component_event_available first.
  observer_.on_diagnostic("COMPONENT_EVENT_LOST", peer, job_id);
}

void MeshNode::sweep_transactions(const MonotonicMs now_ms) noexcept {
  if (!started_) return;
  if (now_ms < last_clock_ms_) return;  // uncertain clock: no time-based close
  for (std::size_t i = 0; i < txn_slots_.size(); ++i) {
    TxnSlot& slot = txn_slots_[i];
    if (slot.state == TxnState::Free) continue;
    const TxnHandle handle{static_cast<std::uint32_t>(i), slot.serial};
    const char* reason = "TXN_EXPIRED";
    bool close = now_ms >= slot.deadline_ms;
    if (!close) {
      if (reply_peer_port_ == nullptr) {
        close = true;
      } else {
        const Status valid =
            reply_peer_port_->validate(slot.use, now_ms);
        if (valid.code == StatusCode::Expired ||
            valid.code == StatusCode::Conflict ||
            valid.code == StatusCode::NotFound) {
          close = true;
          reason = valid.code == StatusCode::Expired ? "TXN_EXPIRED"
                                                     : "TXN_REVOKED";
        }
      }
    }
    if (!close) {
      note_deadline(slot.deadline_ms);
      continue;
    }
    if (slot.state == TxnState::Committed) slot.state = TxnState::Closing;
    // Unstarted scheduler jobs terminate through the ordinary failure path
    // so a dead forward still reports its TransitFailure evidence.
    TxJob dropped{};
    while (scheduler_.drop_one_if(
        [&](const TxJob& job) { return job.txn == handle; }, dropped)) {
      fail_job(dropped, reason, now_ms);
    }
    // Awaiting exchanges terminate instead of waiting out their RTO: the
    // transaction no longer pays for airtime.
    while (auto* awaiting = awaiting_hop_.find(
               [&](const AwaitingHop& value) {
                 return value.job.txn == handle;
               })) {
      TxJob job = awaiting->job;
      awaiting_hop_.release(awaiting);
      fail_job(job, reason, now_ms);
    }
    // Untaken component events never start past the deadline; Taken ones
    // finish at the Owner's complete.
    for (auto& event : event_slots_) {
      if (event.state == EventState::Queued && event.event.txn == handle) {
        event.state = EventState::Free;
        finish_txn_work(handle);
      }
    }
    // In-flight physical work resolves through its result: a retry past the
    // deadline fails there (work_deadline), a completion finishes there.
    if (slot.work_refs == 0) {
      if (reply_peer_port_ != nullptr &&
          slot.use != kInvalidReplyLeaseToken) {
        (void)reply_peer_port_->release(slot.use);
      }
      slot.state = TxnState::Free;
      slot.use = kInvalidReplyLeaseToken;
      slot.deadline_ms = 0;
    }
  }
}

void MeshNode::terminate_all_txn_work() noexcept {
  // Sleep quiesce: every transaction work item finishes silently — no
  // failure reports, no component wakeups — then every use releases.
  TxJob dropped{};
  while (scheduler_.drop_one_if(
      [&](const TxJob& job) { return job.txn != kInvalidTxnHandle; },
      dropped)) {
    finish_txn_work(dropped.txn);
  }
  if (physical_.active && physical_.job.txn != kInvalidTxnHandle) {
    finish_txn_work(physical_.job.txn);
  }
  awaiting_hop_.for_each([&](const AwaitingHop& value) {
    finish_txn_work(value.job.txn);
  });
  for (auto& event : event_slots_) {
    if (event.state != EventState::Free) {
      const TxnHandle txn = event.event.txn;
      event.state = EventState::Free;
      finish_txn_work(txn);
    }
  }
  for (auto& slot : txn_slots_) {
    if (slot.state == TxnState::Free) continue;
    if (reply_peer_port_ != nullptr &&
        slot.use != kInvalidReplyLeaseToken) {
      (void)reply_peer_port_->release(slot.use);
    }
    slot.state = TxnState::Free;
    slot.use = kInvalidReplyLeaseToken;
    slot.deadline_ms = 0;
    slot.work_refs = 0;
  }
}

Status MeshNode::reserve_short_reply(const NodeId peer,
                                     const bool needs_control_slot,
                                     const std::size_t pool_slots,
                                     const MonotonicMs now_ms,
                                     AdmissionReservation& out) noexcept {
  // Fresh stack object from the caller; field-wise init (the type is
  // intentionally non-assignable). Early failures below roll back through
  // the destructor.
  out.node = this;
  out.txn = kInvalidTxnHandle;
  out.use = kInvalidReplyLeaseToken;
  out.dedup = nullptr;
  out.applied = nullptr;
  out.applied_new = false;
  out.committed = false;
  if (reply_peer_port_ == nullptr) {
    return Status::error(StatusCode::Unsupported, "no reply port");
  }
  if (now_ms < last_clock_ms_) {
    return Status::error(StatusCode::TimeUncertain, "clock regressed");
  }
  if (needs_control_slot && !scheduler_.control_slot_available()) {
    return Status::error(StatusCode::WouldBlock, "CONTROL_LANE_FULL");
  }
  if (scheduler_.free_slots() < pool_slots) {
    return Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
  }
  if (!txn_slot_available()) {
    return Status::error(StatusCode::NoCapacity, "8 transactions live");
  }
  ReplyBinding snapshot{};
  Status status = reply_peer_port_->snapshot_binding(peer, snapshot);
  if (!status) return status;
  if (now_ms > UINT64_MAX - kReplyLeaseTtlMs) {
    return Status::error(StatusCode::CounterExhausted, "ttl unrepresentable");
  }
  ReplyLeaseToken use{kInvalidReplyLeaseToken};
  status = reply_peer_port_->acquire(snapshot, now_ms + kReplyLeaseTtlMs,
                                     now_ms, use);
  if (!status) return status;
  out.use = use;
  status = begin_txn(use, now_ms + kReplyLeaseTtlMs, out.txn);
  return status;
}

Status MeshNode::reserve_rx_reply(const RxBinding& rx,
                                     const bool needs_control_slot,
                                     const std::size_t pool_slots,
                                     const MonotonicMs now_ms,
                                     AdmissionReservation& out) noexcept {
  return reserve_rx_reply(rx, needs_control_slot, pool_slots, now_ms, out, UINT64_MAX);
}

Status MeshNode::reserve_rx_reply(const RxBinding& rx,
                                     const bool needs_control_slot,
                                     const std::size_t pool_slots,
                                     const MonotonicMs now_ms,
                                     AdmissionReservation& out,
                                     const MonotonicMs deadline_ms) noexcept {
  out.node = this;
  out.txn = kInvalidTxnHandle;
  out.use = kInvalidReplyLeaseToken;
  out.dedup = nullptr;
  out.applied = nullptr;
  out.applied_new = false;
  out.committed = false;
  if (!rx.valid || reply_peer_port_ == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "no rx binding");
  }
  if (now_ms < last_clock_ms_) {
    return Status::error(StatusCode::TimeUncertain, "clock regressed");
  }
  if (needs_control_slot && !scheduler_.control_slot_available()) {
    return Status::error(StatusCode::WouldBlock, "CONTROL_LANE_FULL");
  }
  if (scheduler_.free_slots() < pool_slots) {
    return Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
  }
  if (!txn_slot_available()) {
    return Status::error(StatusCode::NoCapacity, "8 transactions live");
  }
  if (now_ms > UINT64_MAX - kReplyLeaseTtlMs) {
    return Status::error(StatusCode::CounterExhausted, "ttl unrepresentable");
  }
  const MonotonicMs deadline = std::min(now_ms + kReplyLeaseTtlMs, deadline_ms);
  ReplyLeaseToken use{kInvalidReplyLeaseToken};
  Status status = reply_peer_port_->acquire(rx.binding,
                                            deadline,
                                            now_ms, use);
  if (!status) return status;
  out.use = use;
  status = begin_txn(use, deadline, out.txn);
  return status;
}

void MeshNode::refuse_without_binding(const NodeId peer,
                                      const wire::Header& header,
                                      const char* reason,
                                      const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  // Binding-less input earns no reply at all — not even a BUSY, which would
  // need a lease itself. The drop is counted where unsent replies land.
  ++busy_stats_.busy_send_failed;
  observer_.on_diagnostic(reason, peer, &header.message);
}

Status MeshNode::take_component_event(ComponentEvent& out) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  out = ComponentEvent{};
  for (auto& slot : event_slots_) {
    if (slot.state != EventState::Queued) continue;
    slot.state = EventState::Taken;
    out = slot.event;
    return Status::success();
  }
  return Status::error(StatusCode::NotFound, "no component event queued");
}

Status MeshNode::complete_component_event(
    const ComponentEventHandle handle) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  if (handle.slot >= event_slots_.size()) {
    return Status::error(StatusCode::NotFound, "unknown component event");
  }
  EventSlot& slot = event_slots_[handle.slot];
  if (slot.state != EventState::Taken || slot.serial != handle.serial) {
    return Status::error(StatusCode::NotFound, "unknown component event");
  }
  const TxnHandle txn = slot.event.txn;
  slot.state = EventState::Free;
  finish_txn_work(txn);
  return Status::success();
}

std::size_t MeshNode::component_events_pending() const noexcept {
  std::size_t count = 0;
  for (const auto& slot : event_slots_) {
    if (slot.state != EventState::Free) ++count;
  }
  return count;
}

std::size_t MeshNode::txn_in_flight() const noexcept {
  std::size_t count = 0;
  for (const auto& slot : txn_slots_) {
    if (slot.state != TxnState::Free) ++count;
  }
  return count;
}

void MeshNode::readmit_after_busy(TxJob& job, const MonotonicMs now_ms) noexcept {
  // The original deadline is preserved across deferrals (03 §5) — a BUSY
  // never buys extra lifetime.
  if (now_ms >= work_deadline(job)) {
    fail_job(job, "DEADLINE_EXPIRED", now_ms);
    return;
  }
  // BUSY re-admissions are bounded by busy_readmissions_max=4 and the
  // combined physical-attempt budget=6; neither is reset by peer/rate
  // changes.
  if (job.busy_readmissions >= kBusyReadmissionsMax ||
      job.physical_attempts >= kCombinedPhysicalAttemptsMax) {
    fail_job(job, "BUSY_BUDGET_EXHAUSTED", now_ms);
    return;
  }
  ++job.busy_readmissions;
  ++busy_stats_.busy_readmitted;
  // A fresh link counter for the re-admission — anti-replay never reuses
  // the frame captured before the deferral.
  job.encoded_tag = 0;
  TxJob pending = std::move(job);
  if (!scheduler_.enqueue(std::move(pending), config_.node, now_ms)) {
    fail_job(pending, "READMIT_QUEUE_FULL", now_ms);
  }
}

std::size_t MeshNode::peer_inflight(const NodeId peer) const noexcept {
  // In-flight hop exchanges to a peer = live (non-deferred) awaiting slots.
  // BUSY-deferred entries hold a bounded memory slot but are NOT in flight.
  std::size_t count = 0;
  awaiting_hop_.for_each([&](const AwaitingHop& value) {
    if (value.job.peer == peer && !value.busy_deferred) ++count;
  });
  return count;
}

std::uint8_t MeshNode::peer_window(const NodeId peer) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr) return kPeerWindowMin;
  if (neighbor->tx_window < kPeerWindowMin) return kPeerWindowMin;
  if (neighbor->tx_window > kPeerWindowMax) return kPeerWindowMax;
  return neighbor->tx_window;
}

std::uint32_t MeshNode::effective_hop_timeout_ms(
    const NodeId peer) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  // Unmeasured peers keep the configured initial RTO (radio.md §8); a
  // measured peer adapts inside the clamped band. The sample count, not the
  // EWMA value, gates adaptation — an honestly measured ~0 ms round trip
  // still clamps to the floor.
  if (neighbor == nullptr || neighbor->hop_rtt_samples == 0) {
    return config_.hop_accept_timeout_ms;
  }
  const std::uint64_t scaled =
      static_cast<std::uint64_t>(neighbor->hop_rtt_ewma_ms) * kLinkRtoMargin;
  return static_cast<std::uint32_t>(std::min<std::uint64_t>(
      kLinkRtoMaxMs, std::max<std::uint64_t>(kLinkRtoMinMs, scaled)));
}

MonotonicMs MeshNode::link_retry_not_before_ms(
    const TxJob& job, const MonotonicMs now_ms) noexcept {
  const auto* neighbor = find_neighbor(job.peer);
  const bool congested = neighbor != nullptr && neighbor->busy_active;
  const std::uint32_t bound =
      congested
          ? kLinkRetryJitterCongestedMaxMs - kLinkRetryJitterCongestedMinMs + 1
          : kLinkRetryJitterNormalMaxMs + 1;
  // Deterministic spread, same convention as the route-advertisement jitter
  // (~node.cpp:3834): node id decorrelates peers, the counter decorrelates
  // successive retries — no RNG needed.
  const std::uint32_t offset = static_cast<std::uint32_t>(
      (config_.node * 31ULL + ++retry_jitter_counter_ * 7ULL) % bound);
  const std::uint32_t jitter =
      congested ? kLinkRetryJitterCongestedMinMs + offset : offset;
  // A retry delayed past its own deadline never gets its last attempt.
  // Transaction jobs use the effective deadline: no attempt is scheduled
  // past the transaction close.
  return std::min(now_ms + jitter, work_deadline(job));
}

bool MeshNode::tx_admitted_now(const TxJob& job) const noexcept {
  // Only jobs that enter the HOP_ACCEPT exchange consume window slots.
  // Both bounds apply BEFORE the send: the peer window and the global
  // awaiting table — discovering the global cap after the frame is already
  // on the air would waste a transmission and duplicate a delivery.
  if (!job.requires_hop_accept) return true;
  if (awaiting_hop_.size() >= kAwaitingHopCapacity) return false;
  return peer_inflight(job.peer) < peer_window(job.peer);
}

}  // namespace routeloom
