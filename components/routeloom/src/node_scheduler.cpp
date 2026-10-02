#include "node_internal.hpp"

namespace routeloom {

// --- TxScheduler (03-congestion.md §4) -----------------------------------------

bool MeshNode::TxScheduler::control_job(const TxJob& job) noexcept {
  // The reserved lane carries only locally generated required control
  // responses (HOP_ACCEPT replies and pre-admission BUSY). Self-declared
  // urgent/control traffic from the wire can never enter it (03 §4).
  return job.form == JobForm::Plain &&
         (job.plain.header.type == FrameType::HopAccept ||
          job.plain.header.type == FrameType::Busy);
}

SchedClass MeshNode::TxScheduler::classify(const TxJob& job) noexcept {
  // Group delivery (group-delivery.md §5): copies and confirmations ride the
  // group message's own priority class — an Urgent alarm overtakes display
  // updates at every hop, and neither is charged to the management domain
  // (confirmations of accepted work belong to that work, radio.md §14).
  const FrameType group_type =
      job.form == JobForm::Forwarded ? job.forwarded.header.type : job.plain.header.type;
  if (group_type == FrameType::GroupData || group_type == FrameType::GroupReport) {
    switch (job.priority) {
      case Priority::Urgent:
        return SchedClass::Urgent;
      case Priority::Management:
        return SchedClass::Management;
      case Priority::Bulk:
        return SchedClass::Bulk;
      case Priority::Normal:
        return SchedClass::Normal;
    }
    return SchedClass::Normal;
  }
  if (group_type == FrameType::AppObjectStart || group_type == FrameType::AppObjectChunk ||
      group_type == FrameType::AppObjectAck) return SchedClass::Bulk;
  if (job.form == JobForm::Forwarded) {
    // Transit traffic keeps its lane across hops: receipts and application
    // results ride management; everything else follows the header's
    // traffic hint (wire.hpp byte 9), which can ask for Bulk or Urgent but
    // never Management.
    if (job.forwarded.header.type == FrameType::EndReceipt ||
        job.forwarded.header.type == FrameType::AppResult) {
      return SchedClass::Management;
    }
    switch (job.forwarded.header.traffic & wire::kTrafficPriorityMask) {
      case wire::kTrafficBulk:
        return SchedClass::Bulk;
      case wire::kTrafficUrgent:
        return SchedClass::Urgent;
      default:
        return SchedClass::Normal;
    }
  }
  switch (job.plain.header.type) {
    case FrameType::AppObjectStart:
    case FrameType::AppObjectChunk:
    case FrameType::AppObjectAck:
      return SchedClass::Bulk;
    case FrameType::Data:
    case FrameType::Service:
      // Service=21 payloads classify like application DATA by priority —
      // gateway outcomes ride Management (receipt-class) while Query/Submit
      // stay Normal app traffic. Transit keeps its lane via the Forwarded
      // branch above.
      switch (job.priority) {
        case Priority::Urgent:
          return SchedClass::Urgent;
        case Priority::Management:
          return SchedClass::Management;
        case Priority::Bulk:
          return SchedClass::Bulk;
        case Priority::Normal:
          return SchedClass::Normal;
      }
      return SchedClass::Normal;
    case FrameType::EndReceipt:
    case FrameType::AppResult:
      // APP_RESULT traffic is receipt-class management work (01 §1.6): it
      // must not starve behind bulk DATA or confirmations stop flowing.
      return SchedClass::Management;
    case FrameType::RouteUpdate:
    case FrameType::SeqnoRequest:
    case FrameType::RouteRequest:
      // Route maintenance (advertise/withdraw/repair probes) rides the
      // management class: it must keep flowing under a data flood or the
      // congestion itself can never be repaired (03 §8). It stays out of
      // the reserved control lane and never preempts DATA in the DRR.
      return SchedClass::Management;
    default:
      return SchedClass::Normal;
  }
}

AirtimeDomain MeshNode::TxScheduler::airtime_domain(const TxJob& job) noexcept {
  if (control_job(job)) return AirtimeDomain::Ack;
  return classify(job) == SchedClass::Management ? AirtimeDomain::Control
                                               : AirtimeDomain::Work;
}

void MeshNode::TxScheduler::flow_key(const TxJob& job, const NodeId self,
                                     NodeId& scope, NodeId& origin,
                                     NodeId& destination) noexcept {
  if (job.form == JobForm::Forwarded) {
    // The verified sender scope is the link-authenticated previous hop —
    // the claimed origin is not end-verified at a relay, so the SCOPE (not
    // the origin) bounds spoofed floods; the origin cap is a second bound.
    scope = job.forwarded.header.previous_hop;
    origin = job.forwarded.header.origin;
    destination = job.forwarded.header.destination;
  } else {
    scope = self;
    origin = job.plain.header.origin;
    destination = job.plain.header.destination;
  }
}

void MeshNode::TxScheduler::charge_cost(TxJob& job) noexcept {
  // Estimated TX cost = expected encoded length in bytes. This profile is
  // single-rate, so frame length is the cost unit (03 §4: charge estimated
  // TX cost by length/rate, not frame count). The pinned fixed cost stands
  // for the MAC header + preamble + MAC ACK every frame occupies (radio.md
  // §9 — body bytes alone undercharge a frame by ~70-105B of air time).
  std::uint64_t cost = wire::kHeaderSize + kAeadTagSize + kTxFrameFixedCostBytes;
  if (job.form != JobForm::Plain) {
    cost += job.forwarded.protected_payload_size;
  } else {
    cost += job.plain.payload_size;
    if ((job.plain.header.flags & wire::kFlagEndProtected) != 0) {
      cost += kAeadTagSize;
    }
  }
  job.tx_cost = static_cast<std::uint32_t>(cost);
}

std::size_t MeshNode::TxScheduler::origin_count(const NodeId origin) const noexcept {
  std::size_t count = 0;
  pool_.for_each([&](const TxJob& job) {
    if (job.form == JobForm::Plain &&
        (job.plain.header.type == FrameType::RouteUpdate ||
         job.plain.header.type == FrameType::SeqnoRequest ||
         job.plain.header.type == FrameType::RouteRequest)) return;
    const NodeId value = job.form == JobForm::Forwarded
                             ? job.forwarded.header.origin
                             : job.plain.header.origin;
    if (value == origin) ++count;
  });
  return count;
}

std::size_t MeshNode::TxScheduler::scope_count(const NodeId scope) const noexcept {
  std::size_t count = 0;
  pool_.for_each([&](const TxJob& job) {
    if (job.form == JobForm::Forwarded &&
        job.forwarded.header.previous_hop == scope) {
      ++count;
    }
  });
  return count;
}

AdmitVerdict MeshNode::TxScheduler::check(const NodeId self, const NodeId scope,
                                          const NodeId origin,
                                          const std::size_t slots_needed) const noexcept {
  // New received work must leave room for its responses and two route
  // maintenance jobs; otherwise a DATA flood can prevent route repair.
  if (free_slots() < slots_needed + kControlReserveSlots + kRouteReserveSlots) {
    return AdmitVerdict::PoolFull;
  }
  if (origin_count(origin) >= kMaxJobsPerOrigin) return AdmitVerdict::OriginLimited;
  if (scope != self && scope_count(scope) >= kMaxJobsPerScope) {
    return AdmitVerdict::ScopeLimited;
  }
  return AdmitVerdict::Admitted;
}

Status MeshNode::TxScheduler::enqueue(TxJob&& job, const NodeId self,
                                      const MonotonicMs now_ms) noexcept {
  if (used_ >= kTxQueueCapacity) {
    ++stats_.admissions_rejected;
    return Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
  }
  if (control_job(job)) {
    if (control_.count >= kControlLaneCapacity) {
      ++stats_.admissions_rejected;
      return Status::error(StatusCode::WouldBlock, "CONTROL_LANE_FULL");
    }
    TxJob* slot = pool_.allocate();
    if (slot == nullptr) {  // defensive: used_ and the pool cannot diverge
      ++stats_.admissions_rejected;
      return Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
    }
    *slot = std::move(job);
    charge_cost(*slot);
    slot->enqueued_at_ms = now_ms;
    slot->flow_next = nullptr;
    control_.push_back(slot);
    ++used_;
    return Status::success();
  }

  NodeId scope = kInvalidNodeId;
  NodeId origin = kInvalidNodeId;
  NodeId destination = kInvalidNodeId;
  flow_key(job, self, scope, origin, destination);
  const SchedClass cls = classify(job);
  const FrameType type = job.form == JobForm::Forwarded
                             ? job.forwarded.header.type : job.plain.header.type;
  const bool route_maintenance = job.form == JobForm::Plain &&
      (type == FrameType::RouteUpdate || type == FrameType::SeqnoRequest ||
       type == FrameType::RouteRequest);
  // Required work already accepted under check() keeps its slot; only new
  // unreserved jobs may be refused to preserve route and ACK capacity.
  if (job.txn == kInvalidTxnHandle && job.attempts == 0 &&
      job.physical_attempts == 0 &&
      free_slots() <= kControlReserveSlots + (route_maintenance ? 0 : kRouteReserveSlots)) {
    ++stats_.admissions_rejected;
    return Status::error(StatusCode::WouldBlock, "TX_QUEUE_RESERVED");
  }
  // >=80% watermark: new bulk admission is explicitly rejected/delayed —
  // already-accepted work is never evicted to make room (03 §4).
  if (cls == SchedClass::Bulk && bulk_suspended()) {
    ++stats_.bulk_suspended;
    ++stats_.admissions_rejected;
    return Status::error(StatusCode::Congested, "BULK_SUSPENDED_AT_WATERMARK");
  }
  // Global pool bound + per-origin/per-neighbor caps resist spoofed floods.
  if (data_class(cls) && job.attempts == 0 && job.physical_attempts == 0) {
    if (origin_count(origin) >= kMaxJobsPerOrigin) {
      ++stats_.admissions_rejected;
      return Status::error(StatusCode::Congested, "ORIGIN_QUEUE_CAP");
    }
    if (scope != self && scope_count(scope) >= kMaxJobsPerScope) {
      ++stats_.admissions_rejected;
      return Status::error(StatusCode::Congested, "SCOPE_QUEUE_CAP");
    }
  }
  FlowDesc* flow = flows_.find([&](const FlowDesc& value) {
    return value.sched_class == cls && value.scope == scope &&
           value.origin == origin && value.destination == destination;
  });
  if (flow == nullptr) {
    flow = flows_.allocate();
    if (flow != nullptr) {
      flow->sched_class = cls;
      flow->scope = scope;
      flow->origin = origin;
      flow->destination = destination;
    } else {
      // Descriptor table full: merge into the bounded per-class overflow
      // bucket — never a new unbounded queue (03 §4).
      flow = overflow_flow(cls);
      ++stats_.flow_overflow_merged;
    }
  }
  TxJob* slot = pool_.allocate();
  if (slot == nullptr) {  // defensive: the capacity check above holds
    ++stats_.admissions_rejected;
    return Status::error(StatusCode::WouldBlock, "TX_QUEUE_FULL");
  }
  *slot = std::move(job);
  charge_cost(*slot);
  slot->enqueued_at_ms = now_ms;
  slot->flow_next = nullptr;
  const bool was_empty = flow->jobs.empty();
  flow->jobs.push_back(slot);
  if (was_empty && !flow->in_rr) {
    (void)rr_[class_index(cls)].push(flow);
    flow->in_rr = true;
  }
  ++used_;
  return Status::success();
}

MeshNode::TxJob* MeshNode::TxScheduler::select(const MonotonicMs now_ms,
                                               const MeshNode& node) noexcept {
  if (selected_ != nullptr) return nullptr;
  // Reserved control lane first: a required ACK/BUSY response never waits
  // behind bulk DATA (03 §4) and is never held by the pause mask — it is
  // exactly the control a pause must keep alive (01 §3.3). A control job
  // carrying a retry-jitter hold defers to the next select pass, same as a
  // window-blocked flow.
  if (control_.head != nullptr && control_.head->not_before_ms <= now_ms) {
    TxJob* job = control_.pop_front();
    selected_ = job;
    selected_control_ = true;
    selected_flow_ = nullptr;
    return job;
  }
  // DataDispatch paused (survey visit, migration/cutover): all remaining
  // candidates are data-class flows — nothing else may transmit.
  if (node.paused(pause::kDataDispatch)) return nullptr;
  // DRR across the four classes, charged by estimated TX cost. Inside a
  // class the per-flow round-robin keeps a light sender from being pinned
  // behind one big continuous flow.
  bool foreground_checked = false;
  bool foreground_ready = false;
  for (std::size_t round = 0; round < kMaxSelectRounds; ++round) {
    bool any = false;
    for (std::size_t offset = 0; offset < kSchedClassCount; ++offset) {
      const std::size_t ci = (cursor_ + offset) % kSchedClassCount;
      FixedQueue<FlowDesc*, kRrCapacity>& ring = rr_[ci];
      if (ring.empty()) continue;
      any = true;
      deficit_[ci] = std::min<std::int32_t>(
          deficit_[ci] +
              kQuantumUnit *
                  static_cast<std::int32_t>(
                      sched_class_weight(static_cast<SchedClass>(ci))),
          kDeficitCap);
      const std::size_t flow_count = ring.size();
      for (std::size_t f = 0; f < flow_count; ++f) {
        FlowDesc* flow = nullptr;
        (void)ring.pop(flow);
        flow->in_rr = false;
        TxJob* head = flow->jobs.head;
        if (head == nullptr) {
          // Defensive: an empty flow is never supposed to sit in the ring.
          if (!flow->overflow) flows_.release(flow);
          continue;
        }
        const auto& header = head->form == JobForm::Plain ? head->plain.header : head->forwarded.header;
        const bool object = header.type == FrameType::AppObjectStart ||
                            header.type == FrameType::AppObjectChunk || header.type == FrameType::AppObjectAck;
        if (object && !foreground_checked) {
          // AppObject uses spare airtime: a ready foreground flow gets the
          // next physical frame even when the DRR cursor points at Bulk.
          // A blocked peer must not hold up unrelated object transfers.
          const auto ready = [&](const FlowDesc& candidate) noexcept {
            const auto* job = candidate.jobs.head;
            return candidate.sched_class != SchedClass::Bulk && job != nullptr &&
                   job->not_before_ms <= now_ms && node.tx_admitted_now(*job);
          };
          foreground_ready = flows_.find(ready) != nullptr;
          for (const auto& candidate : overflow_) foreground_ready |= ready(candidate);
          foreground_checked = true;
        }
        if (head->not_before_ms > now_ms ||
            (object && (now_ms < node.object_send_after_ms_ || foreground_ready))) {
          // Link-retry jitter hold (radio.md §8): the job waits for its
          // decorrelation delay — skipped like a window-blocked head and
          // revisited on a later pass.
          flow->in_rr = true;
          (void)ring.push(flow);
          continue;
        }
        if (!node.tx_admitted_now(*head)) {
          // Peer window full: the job waits, it is not dropped. Count the
          // block once per episode — the select loop may revisit this same
          // flow up to kMaxSelectRounds times in a single pass.
          if (!head->window_block_counted) {
            ++stats_.window_limited;
            head->window_block_counted = true;
          }
          flow->in_rr = true;
          (void)ring.push(flow);
          continue;
        }
        head->window_block_counted = false;
        if (static_cast<std::int32_t>(head->tx_cost) > deficit_[ci]) {
          flow->in_rr = true;
          (void)ring.push(flow);
          continue;
        }
        deficit_[ci] -= static_cast<std::int32_t>(head->tx_cost);
        (void)flow->jobs.pop_front();
        if (!flow->jobs.empty()) {
          flow->in_rr = true;
          (void)ring.push(flow);
        }
        selected_flow_ = flow;
        selected_ = head;
        selected_control_ = false;
        cursor_ = (ci + 1) % kSchedClassCount;
        return head;
      }
    }
    if (!any) return nullptr;
  }
  return nullptr;
}

void MeshNode::TxScheduler::unlink(TxJob* job) noexcept {
  auto unlink_from = [&](JobList& list) {
    TxJob* previous = nullptr;
    for (TxJob* cursor = list.head; cursor != nullptr;
         cursor = cursor->flow_next) {
      if (cursor == job) {
        if (previous == nullptr) {
          list.head = cursor->flow_next;
        } else {
          previous->flow_next = cursor->flow_next;
        }
        if (list.tail == cursor) list.tail = previous;
        cursor->flow_next = nullptr;
        --list.count;
        return true;
      }
      previous = cursor;
    }
    return false;
  };
  if (unlink_from(control_)) return;
  bool done = false;
  flows_.for_each([&](FlowDesc& flow) {
    if (!done && unlink_from(flow.jobs)) done = true;
  });
  if (!done) {
    for (auto& overflow : overflow_) {
      if (unlink_from(overflow.jobs)) break;
    }
  }
}

void MeshNode::TxScheduler::take_selected(TxJob& out) noexcept {
  if (selected_ == nullptr) {
    out = TxJob{};
    return;
  }
  out = std::move(*selected_);
  pool_.release(selected_);
  --used_;
  // A drained dedicated flow descriptor is freed here; the shared overflow
  // bucket is permanent and never released.
  if (selected_flow_ != nullptr && selected_flow_->jobs.empty() &&
      !selected_flow_->overflow) {
    flows_.release(selected_flow_);
  }
  selected_ = nullptr;
  selected_flow_ = nullptr;
  selected_control_ = false;
}

void MeshNode::TxScheduler::requeue_selected() noexcept {
  if (selected_ == nullptr) return;
  if (selected_control_) {
    control_.push_front(selected_);
  } else {
    selected_flow_->jobs.push_front(selected_);
    if (!selected_flow_->in_rr) {
      (void)rr_[class_index(selected_flow_->sched_class)].push(selected_flow_);
      selected_flow_->in_rr = true;
    }
  }
  selected_ = nullptr;
  selected_flow_ = nullptr;
  selected_control_ = false;
}

void MeshNode::TxScheduler::defer_selected() noexcept {
  if (selected_ == nullptr) return;
  if (selected_control_) {
    control_.push_back(selected_);
  } else {
    // Refund the deficit charged at selection: a route-deferred job never
    // transmitted, so its class must not carry the spent quantum into the
    // next round (Bulk with quantum 64 would otherwise stay penalised).
    const std::size_t ci = class_index(selected_flow_->sched_class);
    deficit_[ci] = std::min(
        deficit_[ci] + static_cast<std::int32_t>(selected_->tx_cost),
        kDeficitCap);
    selected_flow_->jobs.push_back(selected_);
    if (!selected_flow_->in_rr) {
      (void)rr_[class_index(selected_flow_->sched_class)].push(selected_flow_);
      selected_flow_->in_rr = true;
    }
  }
  selected_ = nullptr;
  selected_flow_ = nullptr;
  selected_control_ = false;
}

void MeshNode::TxScheduler::clear() noexcept {
  pool_.clear();
  flows_.clear();
  for (FlowDesc& flow : overflow_) flow = FlowDesc{};
  for (auto& ring : rr_) ring.clear();
  control_ = JobList{};
  deficit_.fill(0);
  used_ = 0;
  cursor_ = 0;
  selected_ = nullptr;
  selected_flow_ = nullptr;
  selected_control_ = false;
}

}  // namespace routeloom
