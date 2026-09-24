#include "routeloom/node.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <limits>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/bootstrap_transport.hpp"
#include "routeloom/byte_io.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_revocation.hpp"

namespace routeloom {
namespace {

constexpr std::uint32_t kControlLifetimeMs = 1000;
constexpr std::uint32_t kMinimumEndToEndRetryMs = 250;
// ROUTE_UPDATE record: destination(8) + origin generation(4) + sequence(2) + metric(2)
constexpr std::size_t kRouteRecordBytes = 16;
// ROUTE_UPDATE payload = 1-byte count + N records; the 128-byte payload caps
// N at floor((128 - 1) / kRouteRecordBytes) = 7.
constexpr std::size_t kMaxRouteRecordsPerFrame =
    (kMaxApplicationPayload - 1) / kRouteRecordBytes;
constexpr std::uint32_t kSeqnoRequestLifetimeMs = 2000;
constexpr std::uint32_t kSeqnoRequestCooldownMs = 2000;
constexpr std::uint32_t kSeqnoRequestMaxCooldownMs = 30000;
constexpr std::size_t kSeqnoMaxInflight = 4;
constexpr std::uint32_t kSeqnoStateDwellMs = 30000;
constexpr std::uint8_t kSeqnoRequestMaxTtl = kDefaultHopLimit;
constexpr std::size_t kSeqnoRequestPayloadBytes = 8 + 8 + 2 + 4 + 1;
// Triggered updates: at most one full-neighbor burst per min-interval, each
// burst delayed by a small deterministic jitter.
constexpr std::uint32_t kTriggeredUpdateMinIntervalMs = 1000;
constexpr std::uint32_t kTriggeredJitterMs = 64;

// Saturating u64 counter bump (sdk-completion/02 §2.4): a counter that would
// exceed UINT64_MAX pins — unreachable within a boot, never wrapping.
void saturating_inc(std::uint64_t& counter) noexcept {
  if (counter != UINT64_MAX) ++counter;
}

// Saturating u64 add for the airtime ledger — same pin-on-overflow rule.
void saturating_add(std::uint64_t& counter, const std::uint64_t delta) noexcept {
  counter = UINT64_MAX - counter < delta ? UINT64_MAX : counter + delta;
}

// Map a scheduler admission verdict onto a BUSY reason (03 §5). The reason
// is derived from the verdict — a BUSY that was never transmitted is never
// reported as sent.
std::uint8_t busy_reason_for(const AdmitVerdict verdict) noexcept {
  switch (verdict) {
    case AdmitVerdict::ScopeLimited:
    case AdmitVerdict::OriginLimited:
      return static_cast<std::uint8_t>(autonomy::BusyReason::RateLimited);
    default:
      return static_cast<std::uint8_t>(autonomy::BusyReason::QueueFull);
  }
}

}  // namespace

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
  if (job.form == JobForm::Forwarded) {
    // Transit traffic keeps its lane across hops: receipts and application
    // results ride management, everything else is normal.
    return (job.forwarded.header.type == FrameType::EndReceipt ||
            job.forwarded.header.type == FrameType::AppResult)
               ? SchedClass::Management
               : SchedClass::Normal;
  }
  switch (job.plain.header.type) {
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
  if (job.form == JobForm::Forwarded) {
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
  // Non-control admission leaves kControlReserveSlots for the responses
  // (BUSY / HOP_ACCEPT) a saturated node still owes its peers.
  if (free_slots() < slots_needed + kControlReserveSlots) {
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
  // >=80% watermark: new bulk admission is explicitly rejected/delayed —
  // already-accepted work is never evicted to make room (03 §4).
  if (cls == SchedClass::Bulk && bulk_suspended()) {
    ++stats_.bulk_suspended;
    ++stats_.admissions_rejected;
    return Status::error(StatusCode::Congested, "BULK_SUSPENDED_AT_WATERMARK");
  }
  // Global pool bound + per-origin/per-neighbor caps resist spoofed floods.
  if (data_class(cls)) {
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
        if (head->not_before_ms > now_ms) {
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

MeshNode::MeshNode(const NodeConfig& config, RadioPort& radio, SecurityProvider& security,
                   NodeObserver& observer) noexcept
    : config_(config),
      radio_(radio),
      security_(security),
      observer_(observer, in_external_callback_) {
  // The one compat init for the APPLIED boot lease (P4 §9.1): an unset
  // boot_session rides message_session. Session-type providers must pass
  // an explicit nonzero value — the Owner refuses 0 there.
  if (config_.boot_session == 0) config_.boot_session = config_.message_session;
  routes_.set_self(config.node);  // improvement-hold jitter identity (03 §7)
  // Feasibility state must outlive every lease that could still carry a
  // stale advertisement to us (routing-scale.md §8, RFC 8966 §3.7.3).
  routes_.set_tombstone_dwell(config.route_lifetime_ms);
}

Status MeshNode::validate_config() const noexcept {
  // Node ids at or above kGroupAddressBase name groups (group.hpp), never a
  // device — kBroadcastNodeId is the ALL group address.
  if (config_.network == 0 || config_.network > UINT32_MAX ||
      reserved_node_id(config_.node) ||
      config_.message_session == 0 || config_.route_generation == 0 ||
      config_.route_advertisement_period_ms == 0 ||
      config_.route_lifetime_ms <= config_.route_advertisement_period_ms ||
      config_.hop_accept_timeout_ms < kLinkRtoMinMs ||
      config_.callback_watchdog_ms == 0 ||
      config_.max_link_attempts == 0 || config_.max_end_to_end_rounds == 0 ||
      // rf_attempts_max is a pinned contract value (03 §5), not a tunable:
      // a config above it would silently exceed the RF-loss retry budget.
      config_.max_link_attempts > kRfAttemptsMax) {
    return Status::error(StatusCode::InvalidArgument, "invalid node configuration");
  }
  // Gateway-scoped profile (routing-scale.md §5): reserved ids are never a
  // gateway, and the lease must cover two per-link refresh cycles plus the
  // margin — otherwise tree routes would expire before their refresh lands,
  // which is exactly the flap of issue #41. Rejected, never just reported.
  for (const NodeId gateway : config_.route_gateways) {
    if (gateway != kInvalidNodeId && reserved_node_id(gateway)) {
      return Status::error(StatusCode::InvalidArgument, "invalid route gateway");
    }
  }
  if (gateway_scoped() &&
      !scoped_lifetime_sufficient(config_.route_advertisement_period_ms,
                                  config_.route_lifetime_ms,
                                  config_.route_refresh_ticks)) {
    return Status::error(StatusCode::InvalidArgument,
                         "ROUTE_LIFETIME_BELOW_REFRESH_BOUND");
  }
  return Status::success();
}

Status MeshNode::start(const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (started_) return Status::error(StatusCode::AlreadyExists, "node already started");
  const auto status = validate_config();
  if (!status) return status;
  if (!security_.ready()) {
    return Status::error(StatusCode::InvalidState, "security provider is not ready");
  }
  if (reply_peer_port_ == nullptr) {
    // Issue #117: every admission reserves a protected reply binding, so a
    // node without an Owner lease port cannot admit anything — refuse the
    // start explicitly instead of running half-enforced.
    return Status::error(StatusCode::InvalidState, "reply peer port not attached");
  }
  started_ = true;
  next_route_advertisement_ms_ = now_ms;
  // §14 control budget starts full at boot; the bucket is a spec-envelope
  // capability, not measured capacity.
  control_budget_last_ms_ = now_ms;
  group_budget_last_ms_ = now_ms;
  // A development-profile provider is allowed to run but is always surfaced
  // as EXPERIMENTAL; nothing in this node claims production security status.
  if (security_.security_profile() != SecurityProfile::Production) {
    observer_.on_diagnostic("SECURITY_PROFILE_EXPERIMENTAL", kInvalidNodeId, nullptr);
  }
  // Lease safety under metric churn (sdk-completion/03 §3.8, D4-06): a full
  // flat-profile table needs ceil(capacity / routes-per-page) advertisement
  // periods to be refreshed through the rotating cursor (a page carries the
  // self record plus kRouteUpdateMaxRecords - 1 routes). A lifetime shorter
  // than that bound lets tail routes expire before their refresh lands —
  // surfaced once as a diagnostic; whether it is a defect depends on how
  // large the table actually grows, so it is not a boot failure. The
  // gateway-scoped profile has its own, enforced bound (validate_config).
  if (!gateway_scoped() &&
      !flat_lifetime_sufficient(config_.route_advertisement_period_ms,
                                config_.route_lifetime_ms, kMaxRouteEntries)) {
    observer_.on_diagnostic("ROUTE_REFRESH_BOUND_EXCEEDED", kInvalidNodeId,
                            nullptr);
  }
  if (gateway_scoped()) {
    // Deterministic per-node tick offset so a site powered up together does
    // not refresh every tree link in the same instant.
    next_route_advertisement_ms_ =
        now_ms + (config_.node * 2654435761ULL) % config_.route_advertisement_period_ms;
  }
  return Status::success();
}

MeshNode::Neighbor* MeshNode::find_neighbor(const NodeId node) noexcept {
  return neighbors_.find([&](const Neighbor& value) { return value.node == node; });
}

const MeshNode::Neighbor* MeshNode::find_neighbor(const NodeId node) const noexcept {
  return neighbors_.find([&](const Neighbor& value) { return value.node == node; });
}

Status MeshNode::add_neighbor(const NodeId neighbor, const RouteMetric link_metric,
                              const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_ || neighbor == kInvalidNodeId || neighbor == config_.node || link_metric == 0 ||
      link_metric == kInfiniteRouteMetric) {
    return Status::error(StatusCode::InvalidArgument, "invalid neighbor");
  }
  auto* record = find_neighbor(neighbor);
  if (record == nullptr) {
    record = neighbors_.allocate();
    if (record == nullptr) {
      // Tombstoned records only remember a departed peer's last-seen
      // generation — soft state. Reclaim one before refusing, or churn
      // through more than the table capacity in distinct peers permanently
      // exhausts the pool (issue #20).
      record = neighbors_.find(
          [](const Neighbor& value) { return !value.active; });
      if (record != nullptr) {
        // A different identity inherits this slot: the per-peer feedback
        // ordering state is anti-replay continuity for THAT peer only and
        // must not transfer.
        record->last_feedback_seq = kNoFeedbackSeq;
        record->feedback_seen = false;
      }
    }
    if (record == nullptr) {
      return Status::error(StatusCode::NoCapacity, "neighbor table full");
    }
    record->generation = 0;  // last-seen origin generation; survives re-adds
  }
  record->node = neighbor;
  record->metric = link_metric;      // nominal — measurements adjust around it
  record->link_cost = link_metric;   // effective cost starts at nominal
  record->consecutive_failures = 0;
  // Re-adding a peer is a new observation epoch: drop the load aggregates
  // (keep the feedback ordering state — anti-replay must not reset).
  record->exchange_work = 0;
  record->exchange_accepts = 0;
  record->exchange_window_ms = 0;
  record->queue_sojourn_ewma_ms = 0;
  record->sojourn_samples = 0;
  record->last_sojourn_ms = 0;
  record->sojourn_window_ms = 0;
  record->hop_rtt_ewma_ms = 0;
  record->hop_rtt_samples = 0;
  record->busy_active = false;
  record->busy_since_ms = 0;
  record->last_busy_feedback_ms = 0;
  record->last_pressure = 0;
  // The congestion window is load state, not identity: a re-added peer
  // restarts at the initial window rather than inheriting a collapsed one.
  record->tx_window = kPeerWindowInitial;
  record->window_accepts = 0;
  record->busy_capable = false;
  record->cap_valid_until_ms = 0;
  record->cap_node_boot = 0;
  record->last_cap_exchange_ms = 0;
  // Tree roles are re-learned from the peer's own advertisements.
  record->child_until_ms = 0;
  record->interest_until_ms = 0;
  record->last_pull_answer_ms = 0;
  record->pull_target = kInvalidNodeId;
  record->pull_answer_pending = false;
  record->active = true;
  // Direct route to the neighbor itself, seeded at the last-seen generation
  // (0 for a brand-new peer); it upgrades as soon as its self record arrives.
  const RouteAdvertisement direct{neighbor, record->generation, 0, 0};
  auto result = routes_.consider(direct, neighbor, link_metric, now_ms,
                                 config_.route_lifetime_ms);
  if (result == RouteUpdateResult::NoCapacity && routes_.reclaim_tombstone()) {
    // A tombstone only remembers a dead destination's feasibility state —
    // soft state. Under saturation a direct-neighbor admission preempts the
    // oldest one (issue #50, same tradeoff as the neighbor-table reclaim
    // under issue #20); a learned-route flood still sees NoCapacity.
    result = routes_.consider(direct, neighbor, link_metric, now_ms,
                              config_.route_lifetime_ms);
  }
  if (result == RouteUpdateResult::NoCapacity) {
    record->active = false;
    return Status::error(StatusCode::NoCapacity, "route table full");
  }
  ++config_revision_;
  // Flat profile: a new neighbor gets the next dump right away. The scoped
  // profile keeps its tick grid (a new neighbor pulls what it needs, and a
  // reset grid would re-phase every tree link).
  if (!gateway_scoped()) next_route_advertisement_ms_ = now_ms;
  return Status::success();
}

Status MeshNode::remove_neighbor(const NodeId neighbor, const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  auto* record = find_neighbor(neighbor);
  if (record == nullptr) return Status::error(StatusCode::NotFound, "neighbor not found");
  record->active = false;
  routes_.invalidate_next_hop(neighbor, now_ms);
  routes_.clear_next_hop_busy(neighbor);  // drop stale busy state too
  ++self_route_sequence_;
  ++config_revision_;
  trigger_route_advertisement(now_ms);
  return Status::success();
}

MeshNode::Delivery* MeshNode::find_delivery(const MessageId& id) noexcept {
  return deliveries_.find([&](const Delivery& value) { return value.id == id; });
}

const MeshNode::Delivery* MeshNode::find_delivery(const MessageId& id) const noexcept {
  return deliveries_.find([&](const Delivery& value) { return value.id == id; });
}

MeshNode::DedupEntry* MeshNode::find_dedup(const MessageKey& key, const FrameType type,
                                           const std::uint8_t round) noexcept {
  return dedup_.find([&](const DedupEntry& value) {
    return value.key == key && value.type == type && value.round == round;
  });
}

const MeshNode::DedupEntry* MeshNode::find_dedup(const MessageKey& key,
                                               const FrameType type,
                                               const std::uint8_t round) const noexcept {
  return dedup_.find([&](const DedupEntry& value) {
    return value.key == key && value.type == type && value.round == round;
  });
}

std::size_t MeshNode::count_transit_upstream(const NodeId upstream) const noexcept {
  // The per-previous-hop bound covers every non-terminal record the peer
  // injected — transit forwards AND terminal-side Resolved births. Terminal
  // pins are bounded by the reserve instead (02 §2.5).
  std::size_t count = 0;
  dedup_.for_each([&](const DedupEntry& value) {
    if (value.phase != DedupPhase::Terminal && value.upstream_peer == upstream) {
      ++count;
    }
  });
  return count;
}

MonotonicMs MeshNode::dedup_expiry_for(const DedupPhase phase,
                                       const std::uint32_t deadline_remaining_ms,
                                       const MonotonicMs first_seen_ms,
                                       const MonotonicMs now_ms) const noexcept {
  // horizon = now + (remaining_deadline - rx_age): the latest instant a
  // legitimate retry of this round can arrive (02 §2.2). The path-length
  // factor is already spent by the frame's own deadline arithmetic.
  // A frame claiming more than the origin lifetime ceiling cannot come from
  // a conformant origin (issue #55): retention is sized on the ceiling, so
  // the claim buys no longer residency than a max-lifetime message.
  const std::uint32_t claimed = std::min(deadline_remaining_ms, kMaxMessageLifetimeMs);
  const std::uint32_t remaining = claimed > rx_age_ms_ ? claimed - rx_age_ms_ : 0;
  const MonotonicMs horizon = now_ms + remaining;
  const MonotonicMs slack =
      phase == DedupPhase::Terminal ? kTerminalSlackMs : kTransitSlackMs;
  const MonotonicMs duty = horizon + slack;
  const MonotonicMs cap = first_seen_ms + kDedupHardCapMs;
  return std::min(cap, duty);
}

bool MeshNode::evict_dedup_for_admission(const MonotonicMs now_ms) noexcept {
  // Phase-ordered victim selection (02 §2.5): an already-expired record is a
  // normal expiry release, never a forced eviction; then earliest-expiry
  // Resolved (residual duty only: re-ACK + late-report relay), then oldest
  // Evidence (verbatim replay material). Live and Terminal are skipped —
  // evicting one would orphan accepted work or break the exactly-once pin.
  if (auto* expired = dedup_.find(
          [&](const DedupEntry& value) { return value.expires_at_ms <= now_ms; })) {
    dedup_.release(expired);
    saturating_inc(dedup_stats_.expired);
    return true;
  }
  DedupEntry* victim = nullptr;
  dedup_.for_each([&](DedupEntry& value) {
    if (value.phase == DedupPhase::Resolved &&
        (victim == nullptr || value.expires_at_ms < victim->expires_at_ms)) {
      victim = &value;
    }
  });
  if (victim == nullptr) {
    dedup_.for_each([&](DedupEntry& value) {
      if (value.phase == DedupPhase::Evidence &&
          (victim == nullptr || value.first_seen_ms < victim->first_seen_ms)) {
        victim = &value;
      }
    });
  }
  if (victim == nullptr) return false;  // all-Live/Terminal: honest overflow
  release_dedup_victim(*victim);
  return true;
}

bool MeshNode::evict_dedup_for_upstream(const NodeId upstream,
                                        const MonotonicMs now_ms) noexcept {
  // Per-upstream bound (02 §2.5, #39): the bound limits how much of the pool
  // one previous hop may occupy — it is not a rate limit. At the bound the
  // upstream recycles its OWN evictable records in the global phase order
  // (expired -> earliest-expiry Resolved -> oldest Evidence), so a busy but
  // honest upstream is throttled by its live work, not by the retention of
  // exchanges that already finished. Other upstreams' records and every
  // Live/Terminal record are untouched; the refusal remains when all of its
  // records are Live.
  const auto mine = [upstream](const DedupEntry& value) {
    return value.phase != DedupPhase::Terminal && value.upstream_peer == upstream;
  };
  if (auto* expired = dedup_.find([&](const DedupEntry& value) {
        return mine(value) && value.expires_at_ms <= now_ms;
      })) {
    dedup_.release(expired);
    saturating_inc(dedup_stats_.expired);
    return true;
  }
  DedupEntry* victim = nullptr;
  dedup_.for_each([&](DedupEntry& value) {
    if (mine(value) && value.phase == DedupPhase::Resolved &&
        (victim == nullptr || value.expires_at_ms < victim->expires_at_ms)) {
      victim = &value;
    }
  });
  if (victim == nullptr) {
    dedup_.for_each([&](DedupEntry& value) {
      if (mine(value) && value.phase == DedupPhase::Evidence &&
          (victim == nullptr || value.first_seen_ms < victim->first_seen_ms)) {
        victim = &value;
      }
    });
  }
  if (victim == nullptr) return false;  // every record it holds is Live
  release_dedup_victim(*victim);
  return true;
}

void MeshNode::release_dedup_victim(DedupEntry& victim) noexcept {
  // A forced eviction is always counted + diagnosed (02 §2.8): the possible
  // consequence (one extra re-forward of a late duplicate, or loss of the
  // verbatim failure replay) is never silent.
  const MessageId victim_id = victim.key.id;
  const NodeId victim_peer = victim.upstream_peer;
  const bool was_resolved = victim.phase == DedupPhase::Resolved;
  dedup_.release(&victim);
  saturating_inc(was_resolved ? dedup_stats_.evicted_resolved
                              : dedup_stats_.evicted_evidence);
  observer_.on_diagnostic(was_resolved ? "DEDUP_EVICTED_RESOLVED"
                                       : "DEDUP_EVICTED_EVIDENCE",
                          victim_peer, &victim_id);
}

std::size_t MeshNode::count_terminal_pins() const noexcept {
  std::size_t count = 0;
  dedup_.for_each([&](const DedupEntry& value) {
    if (value.phase == DedupPhase::Terminal) ++count;
  });
  return count;
}

MeshNode::DedupEntry* MeshNode::allocate_dedup(
    const MessageKey& key, const FrameType type, const std::uint8_t round,
    const DedupPhase phase, const NodeId upstream,
    const std::uint32_t deadline_remaining_ms, const MonotonicMs now_ms) noexcept {
  if (auto* existing = find_dedup(key, type, round)) return existing;

  // Class admission gates (02 §2.5) run BEFORE touching the pool: terminal
  // pins may never reach into the transit reserve, and one previous-hop peer
  // may not monopolize retained non-terminal state.
  //
  // The reserve bounds the number of PINS (02 §2.10 "Terminal pins >= N"),
  // not the pool size: a pool crowded with evictable Resolved/Evidence
  // transit records must not refuse delivery to this node's own application
  // while the sweep below could reclaim one of them (#39 collateral refusal).
  if (phase == DedupPhase::Terminal && count_terminal_pins() >= kDedupTerminalPinMax) {
    saturating_inc(dedup_stats_.refused_terminal_reserve);
    observer_.on_diagnostic("DEDUP_TERMINAL_RESERVE", upstream, &key.id);
    return nullptr;
  }
  if (phase != DedupPhase::Terminal &&
      count_transit_upstream(upstream) >= kDedupPerUpstreamMax &&
      !evict_dedup_for_upstream(upstream, now_ms)) {
    saturating_inc(dedup_stats_.refused_upstream_cap);
    observer_.on_diagnostic("DEDUP_UPSTREAM_CAP", upstream, &key.id);
    return nullptr;
  }

  auto* entry = dedup_.allocate();
  if (entry == nullptr) {
    if (!evict_dedup_for_admission(now_ms)) {
      // True overflow: only Live/Terminal records remain. Refusal pressure
      // becomes BUSY backpressure at the call site — never dedup weakening.
      saturating_inc(dedup_stats_.refused_pool_full);
      observer_.on_diagnostic("DEDUP_OVERFLOW", upstream, &key.id);
      return nullptr;
    }
    entry = dedup_.allocate();
    if (entry == nullptr) {
      // Unreachable: the sweep just freed a slot. Counted, never silent.
      saturating_inc(dedup_stats_.refused_pool_full);
      observer_.on_diagnostic("DEDUP_OVERFLOW", upstream, &key.id);
      return nullptr;
    }
  }
  entry->key = key;
  entry->type = type;
  entry->round = round;
  entry->phase = phase;
  entry->first_seen_ms = now_ms;
  entry->expires_at_ms =
      dedup_expiry_for(phase, deadline_remaining_ms, now_ms, now_ms);
  // The upstream correlation is admission-time state: it feeds the per-peer
  // cap above and the TransitFailure replay path for forwarded records.
  entry->upstream_peer = upstream;
  saturating_inc(phase == DedupPhase::Terminal ? dedup_stats_.admitted_terminal
                                             : dedup_stats_.admitted_transit);
  return entry;
}

void MeshNode::resolve_dedup_for_job(const TxJob& job) noexcept {
  // Only forwarded jobs carry a retained transit record (job.ack mirrors the
  // forwarded frame's identity); locally originated Transit-owner emissions
  // (our END_RECEIPT, BUSY) never match a dedup key.
  if (job.form != JobForm::Forwarded) return;
  if (auto* entry = find_dedup(job.ack.key, job.ack.accepted_type, job.ack.round);
      entry != nullptr && entry->phase == DedupPhase::Live) {
    // The hop-accept resolved the exchange: residual duty is re-ACK of
    // upstream duplicates plus propagating a late downstream report (02 §2.6).
    entry->phase = DedupPhase::Resolved;
  }
}

void MeshNode::mark_dedup_evidence(DedupEntry& entry) noexcept {
  if (entry.phase == DedupPhase::Evidence) return;
  // Residency bound (02 §2.3c): at most kEvidenceCap Evidence records. At the
  // cap the oldest existing evidence is force-reclaimed — a counted, bounded
  // loss of verbatim-replay material, never an unbounded table.
  std::size_t evidence = 0;
  DedupEntry* oldest = nullptr;
  dedup_.for_each([&](DedupEntry& value) {
    if (&value == &entry || value.phase != DedupPhase::Evidence) return;
    ++evidence;
    if (oldest == nullptr || value.first_seen_ms < oldest->first_seen_ms) {
      oldest = &value;
    }
  });
  if (evidence >= kEvidenceCap && oldest != nullptr) {
    const MessageId victim_id = oldest->key.id;
    const NodeId victim_peer = oldest->upstream_peer;
    dedup_.release(oldest);
    saturating_inc(dedup_stats_.evicted_evidence);
    observer_.on_diagnostic("DEDUP_EVICTED_EVIDENCE", victim_peer, &victim_id);
  }
  entry.phase = DedupPhase::Evidence;
}

void MeshNode::set_delivery_state(Delivery& delivery, const DeliveryState state,
                                  const char* reason) noexcept {
  if (delivery.state == state && delivery.reason == reason) return;
  delivery.state = state;
  delivery.reason = reason;
  // Final-result observation (03 §3): END_RECEIPT/expiry/failure/
  // indeterminate are recorded as separate counters.
  switch (state) {
    case DeliveryState::Delivered:
    case DeliveryState::Failed:
    case DeliveryState::Expired:
    case DeliveryState::Indeterminate:
      obs_final(delivery, state, last_clock_ms_);
      break;
    default:
      break;
  }
  observer_.on_delivery(DeliveryResult{delivery.id, state, reason});
}

Status MeshNode::set_pause(const PauseReason reason,
                           const std::uint8_t mask) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (reason == PauseReason::None || reason == PauseReason::SleepDrain) {
    return Status::error(StatusCode::InvalidArgument, "invalid pause reason");
  }
  if (pause_reason_ != PauseReason::None && pause_reason_ != reason) {
    // A second operational pause would need priority/stacking rules the
    // contract does not define: refuse it explicitly instead.
    return Status::error(StatusCode::Conflict, "PAUSE_REASON_ACTIVE");
  }
  pause_reason_ = reason;
  pause_mask_ |= mask;
  return Status::success();
}

Status MeshNode::clear_pause(const PauseReason reason) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (reason == PauseReason::None || reason == PauseReason::SleepDrain) {
    return Status::error(StatusCode::InvalidArgument, "invalid pause reason");
  }
  if (pause_reason_ != reason) {
    return Status::error(StatusCode::InvalidState, "pause reason not active");
  }
  pause_reason_ = PauseReason::None;
  pause_mask_ = 0;
  return Status::success();
}

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
                                   const MonotonicMs now_ms) noexcept {
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

Status MeshNode::queue_route_update(const NodeId neighbor,
                                    const MonotonicMs now_ms) noexcept {
  TxJob job = link_control_job(FrameType::RouteUpdate, neighbor, kControlLifetimeMs,
                               now_ms);

  ByteWriter writer(MutableByteView{job.plain.payload.data(), job.plain.payload.size()});
  auto status = writer.write_u8(0);  // patched after records are appended
  if (!status) return status;
  std::uint8_t count = 0;
  auto append = [&](const NodeId destination, const RouteGeneration generation,
                    const RouteSequence sequence, const RouteMetric metric) -> bool {
    if (count >= kMaxRouteRecordsPerFrame) return false;
    if (writer.write_u64(destination) && writer.write_u32(generation) &&
        writer.write_u16(sequence) && writer.write_u16(metric)) {
      ++count;
      return true;
    }
    return false;
  };
  append(config_.node, config_.route_generation, self_route_sequence_, 0);
  // A frame holds at most kMaxRouteRecordsPerFrame records. Rotate a
  // per-neighbor cursor through the selected routes so a full dump spans
  // successive updates instead of permanently starving the tail entries.
  auto* neighbor_record = find_neighbor(neighbor);
  const std::size_t skip =
      neighbor_record != nullptr ? neighbor_record->route_cursor : 0;
  std::size_t index = 0;
  std::size_t advertised_count = 0;
  bool writer_full = false;
  routes_.for_each_selected([&](const RouteSelection& selection) {
    if (selection.destination == config_.node) return;
    if (index++ < skip || writer_full) return;
    // Relay-off withdrawal (01 §policy): a node that refuses transit must
    // not keep advertising itself as a viable path — every selected route
    // is retracted at infinity so neighbors stop sending us transit work.
    const RouteMetric advertised =
        (!relay_enabled_ || selection.next_hop == neighbor)
            ? kInfiniteRouteMetric
            : selection.metric;
    if (!append(selection.destination, selection.generation, selection.sequence,
                advertised)) {
      writer_full = true;
      return;
    }
    ++advertised_count;
    // FD is refreshed only when a finite advertisement actually leaves; a
    // split-horizon retraction (infinity) must not touch feasibility state.
    if (advertised != kInfiniteRouteMetric) routes_.mark_advertised(selection.destination);
  });
  if (neighbor_record != nullptr) {
    const std::size_t next = skip + advertised_count;
    neighbor_record->route_cursor =
        static_cast<std::uint8_t>(next >= index ? 0 : next);
  }
  // Retractions: destinations that lost their last feasible route are
  // advertised as infinity so neighbors withdraw promptly instead of waiting
  // out the lease (RFC 8966 §3.7.2). The record budget bounds the burst.
  routes_.for_each_lost([&](const RouteTable::LostRoute& lost) {
    if (writer_full || lost.destination == config_.node) return;
    if (!append(lost.destination, lost.generation, lost.sequence,
                kInfiniteRouteMetric)) {
      writer_full = true;
    }
  });
  job.plain.payload[0] = count;
  job.plain.payload_size = writer.size();
  return scheduler_.enqueue(std::move(job), config_.node, now_ms);
}

Status MeshNode::queue_seqno_request(const NodeId peer, const NodeId requester,
                                         const NodeId destination,
                                         const RouteSequence requested_sequence,
                                         const std::uint32_t request_id,
                                         const std::uint8_t ttl,
                                         const MonotonicMs now_ms) noexcept {
  if (ttl == 0 || peer == kInvalidNodeId || destination == kInvalidNodeId ||
      requester == kInvalidNodeId) {
    return Status::error(StatusCode::InvalidArgument, "invalid sequence request");
  }
  TxJob job = link_control_job(FrameType::SeqnoRequest, peer, kSeqnoRequestLifetimeMs,
                               now_ms);

  ByteWriter writer(MutableByteView{job.plain.payload.data(), job.plain.payload.size()});
  Status status;
#define RL_WRITE_SEQNO(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE_SEQNO(writer.write_u64(requester));
  RL_WRITE_SEQNO(writer.write_u64(destination));
  RL_WRITE_SEQNO(writer.write_u16(requested_sequence));
  RL_WRITE_SEQNO(writer.write_u32(request_id));
  RL_WRITE_SEQNO(writer.write_u8(ttl));
#undef RL_WRITE_SEQNO
  job.plain.payload_size = writer.size();
  return scheduler_.enqueue(std::move(job), config_.node, now_ms);
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

// --- BUSY emission (03-congestion.md §5) ----------------------------------------

std::uint32_t MeshNode::busy_retry_hint() const noexcept {
  // Occupancy-scaled retry hint, kept inside the contract clamp interval.
  const std::uint32_t hint =
      kBusyRetryAfterMinMs + scheduler_.occupancy_percent() * 4;
  return std::min(hint, kBusyRetryAfterMaxMs);
}

Status MeshNode::queue_busy(const NodeId peer, const wire::Header& rejected,
                            const std::uint8_t reason, const TxnHandle txn,
                            const MonotonicMs now_ms) noexcept {
  autonomy::BusyPayload payload{};
  payload.subtype = autonomy::BusySubtype::Reject;
  payload.reason = static_cast<autonomy::BusyReason>(reason);
  payload.referenced_type = rejected.type;
  payload.referenced_origin = rejected.origin;
  payload.referenced_session = rejected.message.session;
  payload.referenced_sequence = rejected.message.sequence;
  payload.referenced_round = rejected.delivery_round;
  // binding generation belongs to the radio Owner's binding table, which is
  // not wired into the portable core yet — 0 means "no binding context".
  payload.feedback_sequence = FeedbackSequence{next_feedback_sequence_++};
  payload.retry_after_ms = busy_retry_hint();
  payload.pressure = static_cast<std::uint8_t>(
      std::min<std::uint32_t>(255, scheduler_.occupancy_percent() * 255 / 100));
  autonomy::EncodedPayload encoded{};
  auto status = autonomy::busy_encode(payload, encoded);
  if (!status) return status;

  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = JobOwner::Transit;
  job.peer = peer;
  job.requires_hop_accept = false;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kControlLifetimeMs;
  job.plain.header.type = FrameType::Busy;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = peer;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = peer;
  job.plain.header.message =
      MessageId{config_.message_session, next_control_sequence_++};
  job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
  job.plain.header.original_lifetime_ms = kControlLifetimeMs;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  std::memcpy(job.plain.payload.data(), encoded.bytes.data(), encoded.size);
  job.plain.payload_size = encoded.size;
  job.txn = txn;
  status = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  if (status) join_txn(txn);
  return status;
}

void MeshNode::emit_busy_or_drop(const NodeId peer, const wire::Header& rejected,
                                 const std::uint8_t reason, const RxBinding& rx,
                                 const MonotonicMs now_ms) noexcept {
  const auto* neighbor = find_neighbor(peer);
  // Never emit the new payload toward a peer that has not proven or been
  // configured for BUSY (03 §5; the D4-09 legacy fallback is the sender's
  // own timeout). A BUSY itself needs a reply slot: without one the frame
  // is dropped and counted, never fabricated.
  if (neighbor == nullptr || !neighbor->busy_capable ||
      neighbor->cap_valid_until_ms <= now_ms ||
      scheduler_.free_slots() < 1) {
    ++busy_stats_.busy_send_failed;
    return;
  }
  if (!rx.valid) {
    refuse_without_binding(peer, rejected, "BUSY_NO_BINDING", now_ms);
    return;
  }
  // The BUSY rides its own short reply reservation on the receive's
  // evidence — when the lease itself is unaffordable the refusal degrades
  // to the counted local drop the sender's timeout already covers.
  AdmissionReservation reply{};
  if (!reserve_rx_reply(rx, true, 1, now_ms, reply)) {
    ++busy_stats_.busy_send_failed;
    return;
  }
  if (queue_busy(peer, rejected, reason, reply.txn, now_ms)) {
    reply.committed = true;
    ++busy_stats_.busy_sent;
  } else {
    ++busy_stats_.busy_send_failed;
  }
}

Status MeshNode::encode_job(TxJob& job, const MonotonicMs now_ms) noexcept {
  // tx_encoded_ still holds this job's sealed frame (the driver refused it
  // and nothing else was sealed since): hand the same bytes over again.
  if (job.encoded_tag != 0 && job.encoded_tag == tx_encoded_tag_) return Status::success();
  job.encoded_tag = 0;
  if (now_ms >= job.deadline_ms) {
    if (job.session_deferred) {
      // The job waited for a provider-owned session that never became
      // usable (sdk-v1/03 §9): say so instead of a generic expiry.
      if (session_stats_.tx_unavailable != UINT32_MAX) ++session_stats_.tx_unavailable;
      return Status::error(StatusCode::Expired, "SESSION_UNAVAILABLE");
    }
    return Status::error(StatusCode::Expired, "JOB_EXPIRED");
  }
  const auto remaining = static_cast<std::uint32_t>(job.deadline_ms - now_ms);
  // Sealing overwrites the shared buffer: whichever job it held loses its
  // encoding (tags never repeat within a job's lifetime).
  tx_encoded_tag_ = 0;
  Status status;
  if (job.form == JobForm::Plain) {
    job.plain.header.previous_hop = config_.node;
    job.plain.header.next_hop = job.peer;
    job.plain.header.remaining_deadline_ms = std::min(job.plain.header.remaining_deadline_ms,
                                                      remaining);
    status = wire::encode_new(job.plain, security_, tx_encoded_);
  } else {
    status = wire::forward(job.forwarded, config_.node, job.peer, config_.link_epoch,
                           remaining, security_, tx_encoded_);
  }
  if (status) {
    if (++last_encoded_tag_ == 0) last_encoded_tag_ = 1;
    tx_encoded_tag_ = last_encoded_tag_;
    job.encoded_tag = last_encoded_tag_;
    job.session_deferred = false;
  }
  return status;
}

bool MeshNode::defer_for_session(TxJob& job) noexcept {
  // encode refused with AuthRequired. Which context is missing? The link to
  // the next hop first, then the end layer a fresh frame would seal (a
  // forwarded frame's end layer is already sealed by its origin).
  NodeId subject = job.peer;
  ContextState state = security_.context_state(SecurityScope::Link, job.peer);
  if (context_usable(state) && job.form == JobForm::Plain &&
      (job.plain.header.flags & wire::kFlagEndProtected) != 0) {
    const SecurityContext end = wire::end_context(job.plain.header);
    subject = end.receiver;
    state = security_.context_state(end.scope, end.receiver);
  }
  // Every involved context is usable: the refusal is an ordinary
  // authentication failure and the job fails exactly as before.
  if (context_usable(state)) return false;
  if (!job.session_deferred) {
    // Once per job: the provider already knows (it answered None or
    // Establishing) and owns establishment (the handshake engine, P4-2);
    // the node only holds the frame, deadline-bounded, without spending a
    // counter on it.
    job.session_deferred = true;
    if (session_stats_.tx_deferred != UINT32_MAX) ++session_stats_.tx_deferred;
    observer_.on_diagnostic(
        state == ContextState::None ? "SESSION_REQUIRED" : "SESSION_PENDING",
        subject, &job.ack.key.id);
  }
  return true;
}

void MeshNode::note_rx_refusal(const Status& status, const NodeId peer,
                               const MessageId* message) noexcept {
  // Receive-side refusals keep the provider's detail as the diagnostic; an
  // unknown context (AuthRequired, sdk-v1/03 §9) is additionally counted —
  // it is never a replay and never falls back to another key.
  if (status.code == StatusCode::AuthRequired &&
      session_stats_.rx_auth_required != UINT32_MAX) {
    ++session_stats_.rx_auth_required;
  }
  observer_.on_diagnostic(status.detail, peer, message);
}

void MeshNode::dispatch_next(const MonotonicMs now_ms) noexcept {
  if (physical_.active) {
    if (now_ms - physical_.submitted_at_ms >= config_.callback_watchdog_ms) {
      TxJob job = physical_.job;
      physical_ = PhysicalInflight{};
      observer_.on_diagnostic("DRIVER_RESULT_UNKNOWN", job.peer, &job.ack.key.id);
      // Callback-uncertain results are accounted separately from RF loss
      // and BUSY — the job still retries within its bounded attempt budget.
      obs_count(job, &ObservationBucket::unknown_results, now_ms);
      // §3.3 evidence gate: an Unknown resolution taints the peer's metric
      // window — it may worsen but never improve until the next roll.
      if (Neighbor* neighbor = find_neighbor(job.peer)) {
        neighbor->metric_window_dirty = true;
      }
      // No driver observation will ever land for this attempt — release
      // its bucket pin here or the evidence could never be reclaimed.
      if (auto* bucket = job_bucket(job, now_ms);
          bucket != nullptr && bucket->pending_completions != 0) {
        --bucket->pending_completions;
      }
      (void)radio_.recover();
      retry_or_fail(job, "DRIVER_RESULT_UNKNOWN", now_ms);
    }
    return;
  }

  std::size_t route_defers = 0;
  while (TxJob* queued = scheduler_.select(now_ms, *this)) {
    if (queued->owner == JobOwner::OriginDelivery) {
      auto* delivery = find_delivery(queued->ack.key.id);
      // A queued retry for an already-terminal delivery is stale work:
      // dispatching it would burn airtime on a duplicate the receiver's
      // dedup pin suppresses anyway, and its outcome must never touch the
      // settled verdict. Delivered/Indeterminate are terminal too.
      if (delivery == nullptr || sleep_terminal(delivery->state)) {
        TxJob discarded{};
        scheduler_.take_selected(discarded);
        // The slot `queued` points at is released above: diagnose from the
        // taken job, not the dead slot.
        observer_.on_diagnostic("STALE_JOB_DROPPED", discarded.peer,
                                &discarded.ack.key.id);
        continue;
      }
    } else if (queued->owner == JobOwner::Group &&
               group_origin_job_stale(*queued)) {
      // A queued retry for an already-settled group origin: same rule as
      // above — never dispatch airtime for a verdict that already landed.
      TxJob discarded{};
      scheduler_.take_selected(discarded);
      observer_.on_diagnostic("STALE_JOB_DROPPED", discarded.peer,
                              &discarded.ack.key.id);
      continue;
    }
    // Combined physical-attempt budget (03 §5): a job that already consumed
    // its six transmissions fails here instead of occupying the driver.
    if (queued->physical_attempts >= kCombinedPhysicalAttemptsMax) {
      TxJob exhausted{};
      scheduler_.take_selected(exhausted);
      fail_job(exhausted, "ATTEMPT_BUDGET_EXHAUSTED", now_ms);
      continue;
    }
    // Route re-verification (03 §7): the route reserved at enqueue is
    // re-checked against the LIVE selected snapshot before the driver sees
    // the frame. A switched route retargets the job under the SAME
    // MessageId, original deadline and consumed round; a destination with
    // no feasible route holds the job (deadline-bounded) instead of
    // launching it on a next hop the table no longer selects — a frame
    // sent down an infeasible route can close a forwarding loop (D4-02).
    NodeId routed = kInvalidNodeId;
    if (queued->form == JobForm::Forwarded &&
        queued->forwarded.header.type != FrameType::GroupData) {
      // Group copies target a tree child chosen at round start; their
      // destination is a group address, never a unicast route.
      routed = queued->forwarded.header.destination;
    } else if (queued->form == JobForm::Plain &&
               (queued->plain.header.type == FrameType::Data ||
                queued->plain.header.type == FrameType::Service ||
                queued->plain.header.type == FrameType::EndReceipt)) {
      routed = queued->plain.header.destination;
    }
    if (routed != kInvalidNodeId) {
      const auto live = routes_.best(routed);
      if (!live.valid || find_neighbor(live.next_hop) == nullptr) {
        if (queued->form == JobForm::Plain &&
            queued->plain.header.type == FrameType::EndReceipt &&
            queued->peer == kInvalidNodeId) {
          TxJob failed{};
          scheduler_.take_selected(failed);
          fail_job(failed, "NO_RETURN_ROUTE", now_ms);
          continue;
        }
        if (now_ms >= work_deadline(*queued)) {
          TxJob stale{};
          scheduler_.take_selected(stale);
          fail_job(stale, "NO_ROUTE", now_ms);
          continue;
        }
        scheduler_.defer_selected();
        // A queue of only route-blocked jobs must not spin this pass; the
        // bound lets each job be re-checked on a later poll.
        if (++route_defers >= kTxQueueCapacity) return;
        continue;
      }
      if (live.next_hop != queued->peer) {
        queued->peer = live.next_hop;
        queued->encoded_tag = 0;  // re-stamp next_hop at encode
      }
    }
    if (next_physical_token_ == 0) {
      TxJob exhausted{};
      scheduler_.take_selected(exhausted);
      fail_job(exhausted, "TX_TOKEN_EXHAUSTED", now_ms);
      continue;
    }
    if (queued->txn != kInvalidTxnHandle) {
      // Admission work re-validates its lease use immediately before the
      // send (design-q116 §6.3): a use the Owner revoked or retired since
      // admission must never reach the air on a recycled binding.
      if (reply_peer_port_ == nullptr) {
        TxJob revoked{};
        scheduler_.take_selected(revoked);
        fail_job(revoked, "TXN_NO_PORT", now_ms);
        continue;
      }
      const TxnSlot* slot = resolve_txn(queued->txn);
      if (slot == nullptr) {
        // A live job always references a live transaction — a stale handle
        // fails closed instead of transmitting off-account.
        TxJob revoked{};
        scheduler_.take_selected(revoked);
        fail_job(revoked, "TXN_REVOKED", now_ms);
        continue;
      }
      const Status lease = reply_peer_port_->validate(slot->use, now_ms);
      if (lease.code == StatusCode::TimeUncertain) {
        // A regressed clock stops new TX this pass; the sweep already
        // suspended time-based closes, and callbacks still drain.
        scheduler_.requeue_selected();
        return;
      }
      if (!lease) {
        TxJob revoked{};
        scheduler_.take_selected(revoked);
        fail_job(revoked,
                 lease.code == StatusCode::Expired ? "TXN_EXPIRED"
                                                   : "TXN_REVOKED",
                 now_ms);
        continue;
      }
      if (now_ms >= work_deadline(*queued)) {
        TxJob expired{};
        scheduler_.take_selected(expired);
        fail_job(expired, "TXN_EXPIRED", now_ms);
        continue;
      }
    }
    auto status = encode_job(*queued, now_ms);
    if (!status) {
      if (status.code == StatusCode::AuthRequired && defer_for_session(*queued)) {
        // No session with the peer yet (sdk-v1/03 §9): hold the job like a
        // route-blocked one; its deadline still bounds the wait.
        scheduler_.defer_selected();
        if (++route_defers >= kTxQueueCapacity) return;
        continue;
      }
      TxJob failed{};
      scheduler_.take_selected(failed);
      fail_job(failed, status.detail, now_ms);
      continue;
    }
    if (queued->requires_hop_accept && reply_peer_port_ != nullptr) {
      // ACK-awaiting TX pins the submitted binding (design-q116 §6.2): the
      // snapshot, the encode above and the bound send below are one serial
      // operation, so the HOP_ACCEPT match later compares like with like.
      ReplyBinding snapshot{};
      status = reply_peer_port_->snapshot_binding(queued->peer, snapshot);
      if (!status) {
        TxJob unbound{};
        scheduler_.take_selected(unbound);
        retry_or_fail(unbound, status.detail, now_ms);
        continue;
      }
      queued->submitted_binding = snapshot.id;
      queued->submitted_generation = snapshot.generation;
      queued->submitted_rx_context = snapshot.rx_context_id;
      queued->submitted_binding_set = true;
    }
    std::uint64_t token = 0;
    (void)mint_physical_token(next_physical_token_, token);
    if (reply_peer_port_ != nullptr && queued->requires_hop_accept &&
        queued->submitted_binding_set) {
      ReplyBinding submitted{};
      submitted.peer = queued->peer;
      submitted.id = queued->submitted_binding;
      submitted.generation = queued->submitted_generation;
      submitted.rx_context_id = queued->submitted_rx_context;
      status = reply_peer_port_->send_bound(submitted, token,
                                            tx_encoded_.view());
    } else if (reply_peer_port_ != nullptr &&
               queued->txn != kInvalidTxnHandle &&
               resolve_txn(queued->txn) != nullptr) {
      // Lease-protected reply without a hop exchange (HOP_ACCEPT, BUSY,
      // refusals, receipts that need no accept): the Owner rechecks the use
      // against the live mapping, then submits.
      const TxnSlot* slot = resolve_txn(queued->txn);
      status = reply_peer_port_->send_reply(slot->use, token,
                                            tx_encoded_.view(), now_ms);
    } else {
      status = radio_.send(queued->peer, token, tx_encoded_.view());
    }
    if (status.code == StatusCode::WouldBlock || status.code == StatusCode::Busy) {
      // The driver could not take the frame: no attempt was made. Restore
      // the job at the head of its lane and stop dispatching this pass.
      scheduler_.requeue_selected();
      return;
    }
    TxJob submitted{};
    scheduler_.take_selected(submitted);
    if (!status) {
      retry_or_fail(submitted, status.detail, now_ms);
      continue;
    }
    ++submitted.physical_attempts;
    obs_tx_submitted(submitted, token, now_ms);
    physical_.job = std::move(submitted);
    physical_.token = token;
    physical_.submitted_at_ms = now_ms;
    physical_.active = true;
    if (physical_.job.owner == JobOwner::Transit) {
      // Bind the retained transit record to the attempt actually
      // submitted — dispatch may have retargeted next_hop after admission
      // (route repair), so the stored downstream/binding must reflect the
      // real attempt, not the enqueue-time route. The job's ack key holds
      // the transit record's identity; forwarded jobs keep no plain
      // header.
      if (auto* entry = find_dedup(physical_.job.ack.key,
                                   physical_.job.ack.accepted_type,
                                   physical_.job.ack.round)) {
        entry->downstream_peer = physical_.job.peer;
        entry->downstream_binding = BindingGeneration{0};
        if (const auto* s = telemetry_peers_.find(physical_.job.peer);
            s != nullptr && s->occupied) {
          entry->downstream_binding = s->binding;
        }
      }
    }
    if (physical_.job.owner == JobOwner::OriginDelivery) {
      if (auto* delivery = find_delivery(physical_.job.ack.key.id)) {
        set_delivery_state(*delivery, DeliveryState::WaitingForMac, "TX_MAC_PENDING");
      }
    }
    return;
  }
}

Status MeshNode::on_radio_tx_result(const std::uint64_t token, const bool success,
                                    const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  last_clock_ms_ = now_ms;
  ++work_generation_;
  if (!physical_.active || physical_.token != token) {
    observer_.on_diagnostic("STALE_TX_CALLBACK", kInvalidNodeId, nullptr);
    return Status::success();
  }
  TxJob job = physical_.job;
  const bool busy_deferred = physical_.busy_deferred;
  const std::uint32_t busy_retry_ms = physical_.busy_retry_ms;
  // Driver service time is recorded ONLY by note_radio_tx from the
  // runtime's own submitted/completed timestamps — a second measurement
  // here would double-record and inflate it with Owner/RX backlog (03 §3).
  physical_ = PhysicalInflight{};
  // The attempt resolved: release the bucket pin its submission took.
  // (Driver-side note_radio_tx never touches pins — raw-lane completions
  // must not consume a pin belonging to an in-flight job under the same
  // observation key.)
  if (auto* bucket = job_bucket(job, now_ms);
      bucket != nullptr && bucket->pending_completions != 0) {
    --bucket->pending_completions;
  }
  auto* neighbor = find_neighbor(job.peer);
  if (!success) {
    if (neighbor != nullptr && neighbor->consecutive_failures < UINT8_MAX) {
      ++neighbor->consecutive_failures;
      if (neighbor->consecutive_failures >= 2) {
        routes_.invalidate_next_hop(job.peer, now_ms);
        trigger_route_advertisement(now_ms);
      }
    }
    obs_count(job, &ObservationBucket::rf_failures, now_ms);
    retry_or_fail(job, "MAC_SEND_FAILED", now_ms);
    return Status::success();
  }
  if (neighbor != nullptr) neighbor->consecutive_failures = 0;
  if (!job.requires_hop_accept) {
    complete_job(job, false, now_ms);
    return Status::success();
  }
  auto* awaiting = awaiting_hop_.allocate();
  if (awaiting == nullptr) {
    // A full hop-wait table is a capacity shortfall, not RF loss (issue
    // #50): defer without consuming the retry budget. The frame did reach
    // the air so physical_attempts stays counted; tx_admitted_now re-gates
    // capacity before the next send.
    if (now_ms >= work_deadline(job)) {
      fail_job(job, "DEADLINE_EXPIRED", now_ms);
      return Status::success();
    }
    observer_.on_diagnostic("HOP_WAIT_TABLE_FULL", job.peer, &job.ack.key.id);
    job.encoded_tag = 0;
    TxJob pending = std::move(job);
    if (!scheduler_.enqueue(std::move(pending), config_.node, now_ms)) {
      fail_job(pending, "TX_QUEUE_FULL", now_ms);
    }
    return Status::success();
  }
  awaiting->job = std::move(job);
  // An authenticated BUSY that arrived while the frame was with the driver
  // takes effect now: the exchange is deferred, not retried as RF loss.
  awaiting->busy_deferred = busy_deferred;
  awaiting->sent_at_ms = now_ms;
  awaiting->expires_at_ms =
      now_ms + (busy_deferred
                    ? busy_retry_ms
                    : effective_hop_timeout_ms(awaiting->job.peer));
  if (awaiting->job.owner == JobOwner::OriginDelivery) {
    if (auto* delivery = find_delivery(awaiting->job.ack.key.id);
        delivery != nullptr && !sleep_terminal(delivery->state)) {
      // A receipt/RESULT may have settled the verdict while this frame was
      // with the driver — the hop-accept wait of its stale job must not
      // demote a terminal state.
      set_delivery_state(*delivery, DeliveryState::WaitingForHopAccept, "HOP_ACCEPT_PENDING");
    }
  }
  return Status::success();
}

void MeshNode::complete_job(TxJob& job, const bool hop_accepted,
                            const MonotonicMs now_ms) noexcept {
  // The transaction work item ends here — before any component effect, so
  // the lease releases exactly once however this fans out.
  finish_txn_work(job.txn);
  if (job.owner == JobOwner::Group) {
    group_job_done(job, true, now_ms);
    return;
  }
  if (job.owner == JobOwner::GatewayService) {
    // The Service endpoint owns completion: the first authenticated
    // HOP_ACCEPT resolves the exchange; the component tracks the rest.
    // Deferred for the Owner's outside drive — never synchronously
    // mid-call. The slot was held at send time, so this cannot be lost.
    if (component_jobs_outstanding_ > 0) --component_jobs_outstanding_;
    if (gateway_sink_ != nullptr) {
      if (component_event_available()) {
        publish_component_event(ComponentEventTarget::ServiceJobDone, job.peer,
                                kInvalidTxnHandle, job.deadline_ms, nullptr,
                                &job.ack.key.id, true, "HOP_ACCEPTED");
      } else {
        observer_.on_diagnostic("COMPONENT_EVENT_LOST", job.peer,
                                &job.ack.key.id);
      }
    }
    return;
  }
  if (job.owner == JobOwner::Config) {
    if (component_jobs_outstanding_ > 0) --component_jobs_outstanding_;
    if (config_sink_ != nullptr) {
      if (component_event_available()) {
        publish_component_event(ComponentEventTarget::ConfigJobDone, job.peer,
                                kInvalidTxnHandle, job.deadline_ms, nullptr,
                                &job.ack.key.id, true, "HOP_ACCEPTED");
      } else {
        observer_.on_diagnostic("COMPONENT_EVENT_LOST", job.peer,
                                &job.ack.key.id);
      }
    }
    return;
  }
  (void)hop_accepted;
  if (job.owner == JobOwner::Transit) {
    // sdk-completion/02 §2.6: a completed forward demotes its dedup record to
    // residual re-ACK/report-relay duty — Resolved is the evictable class.
    resolve_dedup_for_job(job);
    return;
  }
  if (job.owner != JobOwner::OriginDelivery) return;
  auto* delivery = find_delivery(job.ack.key.id);
  if (delivery == nullptr) return;
  if (job.plain.header.type != FrameType::Data) return;
  if (delivery->options.delivery == DeliveryClass::BestEffort) {
    // Same stale-job rule as below: a BestEffort frame that was still in
    // flight when its delivery settled (e.g. SLEEP_SAVED) must not overwrite
    // the settled verdict with a late TX_MAC_DONE.
    if (sleep_terminal(delivery->state)) {
      return;
    }
    set_delivery_state(*delivery, DeliveryState::Delivered, "TX_MAC_DONE");
    return;
  }
  // A verified RESULT/END_RECEIPT may have resolved the delivery while its
  // DATA job was still completing — for EVERY class the receipt wait must
  // never demote a terminal verdict (sdk-completion/01 §1.3).
  if (sleep_terminal(delivery->state)) {
    return;
  }
  delivery->next_round_at_ms = std::min(
      delivery->expires_at_ms,
      now_ms + applied_window_ms(delivery->options.hop_limit,
                                 config_.hop_accept_timeout_ms));
  set_delivery_state(*delivery, DeliveryState::WaitingForEndReceipt, "END_RECEIPT_PENDING");
}

void MeshNode::fail_job(TxJob& job, const char* reason,
                        const MonotonicMs now_ms) noexcept {
  // Terminate the transaction work item first: the failure report below
  // reserves a fresh short transaction, which must see the freed capacity.
  finish_txn_work(job.txn);
  if (job.owner == JobOwner::Group) {
    (void)reason;
    group_job_done(job, false, now_ms);
    return;
  }
  if (job.owner == JobOwner::GatewayService) {
    // Deferred completion, same held slot as the success path.
    if (component_jobs_outstanding_ > 0) --component_jobs_outstanding_;
    if (gateway_sink_ != nullptr) {
      if (component_event_available()) {
        publish_component_event(ComponentEventTarget::ServiceJobDone, job.peer,
                                kInvalidTxnHandle, job.deadline_ms, nullptr,
                                &job.ack.key.id, false, reason);
      } else {
        observer_.on_diagnostic("COMPONENT_EVENT_LOST", job.peer,
                                &job.ack.key.id);
      }
    }
    return;
  }
  if (job.owner == JobOwner::Config) {
    if (component_jobs_outstanding_ > 0) --component_jobs_outstanding_;
    if (config_sink_ != nullptr) {
      if (component_event_available()) {
        publish_component_event(ComponentEventTarget::ConfigJobDone, job.peer,
                                kInvalidTxnHandle, job.deadline_ms, nullptr,
                                &job.ack.key.id, false, reason);
      } else {
        observer_.on_diagnostic("COMPONENT_EVENT_LOST", job.peer,
                                &job.ack.key.id);
      }
    }
    return;
  }
  // Accepted transit work that failed post-acceptance reports a bounded
  // TransitFailure to its retained upstream — BUSY is pre-acceptance only
  // and must never retract an earlier HOP_ACCEPT.
  if (job.owner == JobOwner::Transit) {
    report_transit_failure(job, reason, now_ms);
    return;
  }
  if (job.owner != JobOwner::OriginDelivery) return;
  auto* delivery = find_delivery(job.ack.key.id);
  if (delivery == nullptr) return;
  // A stale DATA job (queued/dispatched before the verdict landed — e.g. a
  // retry round in flight when a late END_RECEIPT resolved the delivery)
  // must never demote a terminal verdict: Delivered cannot fall back to
  // WaitingForRoute/Failed on evidence that predates the resolution.
  if (sleep_terminal(delivery->state)) {
    return;
  }
  // APPLIED: a stale DATA job failure must not cancel a result wait already
  // in progress, and must never demote a stored verdict (01 §1.5).
  if (delivery->options.delivery == DeliveryClass::Applied &&
      delivery->app_phase != 0) {
    return;
  }
  if ((delivery->options.delivery == DeliveryClass::Reliable ||
       delivery->options.delivery == DeliveryClass::Applied) &&
      now_ms < delivery->expires_at_ms &&
      static_cast<std::uint8_t>(delivery->round + 1U) < config_.max_end_to_end_rounds) {
    ++delivery->round;
    delivery->next_round_at_ms = now_ms + 50;
    set_delivery_state(*delivery, DeliveryState::WaitingForRoute, reason);
    return;
  }
  if (delivery->options.delivery == DeliveryClass::Applied) {
    // Rounds exhausted on a transmitted request — the destination may have
    // executed it; Indeterminate is the honest verdict (01 §1.9).
    set_delivery_state(*delivery, DeliveryState::Indeterminate, "APP_RESULT_TIMEOUT");
    return;
  }
  set_delivery_state(*delivery, DeliveryState::Failed, reason);
}

void MeshNode::retry_or_fail(TxJob& job, const char* reason,
                             const MonotonicMs now_ms) noexcept {
  if (group_origin_job_stale(job)) {
    // Settled while in flight: drop instead of re-queueing — a retry must
    // not resurrect a terminal origin verdict.
    observer_.on_diagnostic("STALE_JOB_DROPPED", job.peer, &job.ack.key.id);
    return;
  }
  if (now_ms >= work_deadline(job)) {
    fail_job(job, "DEADLINE_EXPIRED", now_ms);
    return;
  }
  ++job.attempts;
  if (job.attempts < job.max_attempts &&
      job.physical_attempts < kCombinedPhysicalAttemptsMax) {
    // Each SDK retry receives a fresh link counter. Reusing a captured frame would
    // make strict anti-replay incompatible with reliable delivery.
    job.encoded_tag = 0;
    // Link-retry decorrelation (radio.md §8): the re-queued job is not
    // select-eligible until the jittered delay elapses.
    job.not_before_ms = link_retry_not_before_ms(job, now_ms);
    TxJob pending = std::move(job);
    if (!scheduler_.enqueue(std::move(pending), config_.node, now_ms)) {
      fail_job(pending, "TX_QUEUE_FULL", now_ms);
    }
    return;
  }
  fail_job(job, reason, now_ms);
}

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
  // Strictly the free-slot case: reclaim paths destroy records, so the
  // probe admits only what the mutating call can take without reclaiming.
  // Expired records sweep independently in process_applied; a refused
  // admission retries honestly instead of losing another record's verdict.
  if (applied_records_.size() < applied_records_.capacity()) return true;
  bool reclaimable = false;
  applied_records_.for_each([&](const AppliedRecord& value) {
    if (value.expires_at_ms <= now_ms || value.acked) reclaimable = true;
  });
  (void)reclaimable;
  return false;
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
    if (frame != nullptr) slot.event.frame = *frame;
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
    if (!close) continue;
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
  ReplyLeaseToken use{kInvalidReplyLeaseToken};
  Status status = reply_peer_port_->acquire(rx.binding,
                                            now_ms + kReplyLeaseTtlMs,
                                            now_ms, use);
  if (!status) return status;
  out.use = use;
  status = begin_txn(use, now_ms + kReplyLeaseTtlMs, out.txn);
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
    observer_.on_diagnostic("UNMATCHED_HOP_ACCEPT", peer, &key.key.id);
    return;
  }
  TxJob job = awaiting->job;
  const bool was_deferred = awaiting->busy_deferred;
  const MonotonicMs sent_at_ms = awaiting->sent_at_ms;
  awaiting_hop_.release(awaiting);
  obs_hop_result(job, true, now_ms);
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
  if (auto* neighbor = find_neighbor(peer)) {
    if (rtt_sampled) {
      ++neighbor->hop_rtt_samples;
      ewma_add(neighbor->hop_rtt_ewma_ms, rtt_ms,
               neighbor->hop_rtt_samples);
    }
    // An authenticated accept proves work gets through: it releases the
    // sustained-busy state that feeds the severe-busy repair path (03 §7).
    // A BUSY-deferred exchange that still completes does not break the
    // authenticated-accept streak — the accept is authoritative.
    neighbor->busy_active = false;
    neighbor->busy_since_ms = 0;
    neighbor->last_busy_feedback_ms = 0;
    if (neighbor->window_accepts < kWindowGrowAccepts) {
      ++neighbor->window_accepts;
    }
    // 8 consecutive authenticated accepts grow the window by one (03 §5).
    // Window growth is decoupled from memory-slot release on purpose.
    if (neighbor->window_accepts >= kWindowGrowAccepts &&
        neighbor->tx_window < kPeerWindowMax) {
      ++neighbor->tx_window;
      neighbor->window_accepts = 0;
    }
  }
  complete_job(job, true, now_ms);
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
      if (queue_end_receipt(frame.header, reply.txn, now_ms) &&
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
                     incoming != duplicate->fingerprint;
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
    if (want_receipt && queue_end_receipt(frame.header, reply.txn, now_ms) &&
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
      note_rx_refusal(status, peer, &frame.header.message);
      return;
    }
    if (!rx.valid) {
      refuse_without_binding(peer, frame.header, "ADMISSION_NO_BINDING",
                             now_ms);
      return;
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
    if (!queue_end_receipt(frame.header, res.txn, now_ms)) {
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
      observer_.on_message(key, frame.header.origin,
                           ByteView{plain.payload.data(), plain.payload_size});
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
      wire::transit_fingerprint(frame, entry->fingerprint).ok();
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
                     incoming != duplicate->fingerprint;
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
      note_rx_refusal(status, peer, &frame.header.message);
      return;
    }
    if (!rx.valid) {
      refuse_without_binding(peer, frame.header, "ADMISSION_NO_BINDING",
                             now_ms);
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
      wire::transit_fingerprint(frame, entry->fingerprint).ok();
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
                     incoming != duplicate->fingerprint;
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
    if (!rx.valid) return;
    AdmissionReservation reply{};
    if (reserve_rx_reply(rx, true, 1, now_ms, reply) &&
        queue_hop_accept(frame.header, reply.txn, now_ms)) reply.committed = true;
    return;
  }

  if (frame.header.destination == config_.node) {
    if (frame.header.payload_length > kMaxApplicationPayload) {
      observer_.on_diagnostic("BOOTSTRAP_PAYLOAD_REJECTED", peer, &frame.header.message);
      return;
    }
    MonotonicMs txn_deadline = 0;
    if (!rx.valid || scheduler_.free_slots() < 1 ||
        !scheduler_.control_slot_available() || !txn_slot_available() ||
        !txn_deadline_for(frame.header.remaining_deadline_ms, now_ms, txn_deadline)) {
      observer_.on_diagnostic("BOOTSTRAP_NO_ACK_SLOT", peer, &frame.header.message);
      return;
    }
    AdmissionReservation res{};
    res.node = this;
    ReplyLeaseToken use{kInvalidReplyLeaseToken};
    if (reply_peer_port_ == nullptr ||
        !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) return;
    res.use = use;
    if (!begin_txn(use, txn_deadline, res.txn)) return;
    auto* entry = allocate_dedup(key, type, frame.header.delivery_round,
                                 DedupPhase::Resolved, peer,
                                 frame.header.remaining_deadline_ms, now_ms);
    if (entry == nullptr) return;
    res.dedup = entry;
    if (!queue_hop_accept(frame.header, res.txn, now_ms)) return;
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
  if (frame.header.remaining_deadline_ms <= rx_age_ms_) {
    ++transit_refused_;
    emit_transit_refusal(frame, TransitFailureReason::Deadline, rx, now_ms);
    observer_.on_diagnostic("BOOTSTRAP_TRANSIT_DEADLINE_SPENT", peer,
                            &frame.header.message);
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
  MonotonicMs txn_deadline = 0;
  if (!rx.valid || admit != AdmitVerdict::Admitted ||
      !scheduler_.control_slot_available() || !txn_slot_available() ||
      !txn_deadline_for(frame.header.remaining_deadline_ms, now_ms, txn_deadline)) {
    emit_busy_or_drop(peer, frame.header, busy_reason_for(admit), rx, now_ms);
    return;
  }
  AdmissionReservation res{};
  res.node = this;
  ReplyLeaseToken use{kInvalidReplyLeaseToken};
  if (reply_peer_port_ == nullptr ||
      !reply_peer_port_->acquire(rx.binding, txn_deadline, now_ms, use)) return;
  res.use = use;
  if (!begin_txn(use, txn_deadline, res.txn)) return;
  auto* entry = allocate_dedup(key, type, frame.header.delivery_round,
                               DedupPhase::Live, peer,
                               frame.header.remaining_deadline_ms, now_ms);
  if (entry == nullptr) return;
  res.dedup = entry;
  if (!queue_forward(frame, route.next_hop, res.txn, now_ms)) return;
  entry->forwarded = true;
  entry->upstream_peer = frame.header.previous_hop;
  entry->downstream_peer = route.next_hop;
  entry->ref_destination = frame.header.destination;
  entry->has_fingerprint = wire::transit_fingerprint(frame, entry->fingerprint).ok();
  if (!queue_hop_accept(frame.header, res.txn, now_ms)) {
    res.committed = true;  // Forward owns the transaction even if ACK admission fails.
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
    // exchange would install.
    neighbor->busy_capable = true;
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
                     incoming != duplicate->fingerprint;
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
        wire::transit_fingerprint(frame, entry->fingerprint).ok();
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
    note_rx_refusal(status, peer, &frame.header.message);
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
    } else {
      reply = AppliedReply{};
      const AppliedRequest request{record.key, data.origin,
                                   ByteView{body.data + endpoint::kAppliedLeaseBytes,
                                            body.size - endpoint::kAppliedLeaseBytes},
                                   data.remaining_deadline_ms};
      {
        ExternalCallbackScope scope(in_external_callback_);
        applied_sink_->on_applied_request(request, reply);
      }
      dispatched = true;
      ++applied_stats_.requests_dispatched;
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

Status MeshNode::emit_applied_result(AppliedRecord& record,
                                     const MonotonicMs now_ms) noexcept {
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
    if (!record.acked && record.emits < kAppliedMaxEmits &&
        now_ms >= record.next_emit_ms && now_ms < record.emit_deadline_ms) {
      (void)emit_applied_result(record, now_ms);
    }
  });
}

void MeshNode::handle_route_update(const wire::PlainFrame& frame, const NodeId peer,
                                   const MonotonicMs now_ms) noexcept {
  auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || !neighbor->active) return;
  ByteReader reader(ByteView{frame.payload.data(), frame.payload_size});
  std::uint8_t count = 0;
  if (!reader.read_u8(count) || count > kMaxRouteRecordsPerFrame ||
      reader.remaining() != static_cast<std::size_t>(count) * kRouteRecordBytes) {
    observer_.on_diagnostic("INVALID_ROUTE_UPDATE", peer, &frame.header.message);
    return;
  }
  std::array<RouteAdvertisement, kMaxRouteRecordsPerFrame> records{};
  for (std::uint8_t i = 0; i < count; ++i) {
    if (!reader.read_u64(records[i].destination) ||
        !reader.read_u32(records[i].generation) ||
        !reader.read_u16(records[i].sequence) ||
        !reader.read_u16(records[i].metric)) {
      return;
    }
  }

  // Relay restart: the peer's self record (destination == peer) carries a
  // higher origin generation than we last saw. The restarted relay lost its
  // routing state, so every route learned from its previous incarnation is
  // stale. Drop via-peer candidates without hold-down — post-restart
  // advertisements are legitimate fresh state.
  bool restarted = false;
  for (std::uint8_t i = 0; i < count; ++i) {
    if (records[i].destination == peer && records[i].generation > neighbor->generation) {
      restarted = neighbor->generation != 0;
      neighbor->generation = records[i].generation;
    }
  }
  if (restarted) {
    routes_.invalidate_next_hop(peer, now_ms, false);
    // §3.7 identity reset: measurement gathered against the previous
    // incarnation is unattributable to this one.
    reset_neighbor_measurement(*neighbor);
    trigger_route_advertisement(now_ms);
    observer_.on_diagnostic("PEER_RESTARTED_ROUTES_FLUSHED", peer, nullptr);
  }
  // Scoped profile: tree-role inference (poisoned gateway record = the peer
  // routes to that gateway through us). Scheduling state only — route state
  // below still moves exclusively through consider().
  note_scoped_update(*neighbor, records.data(), count, now_ms);

  for (std::uint8_t i = 0; i < count; ++i) {
    const auto& advertisement = records[i];
    if (advertisement.destination == config_.node) continue;
    // Advertisements are considered against the CURRENT effective link
    // cost — the same cost update_link_cost applies to stored candidates,
    // so new and existing routes are built from one consistent state.
    const auto result = routes_.consider(advertisement, peer, neighbor->link_cost, now_ms,
                                         config_.route_lifetime_ms);
    if (result == RouteUpdateResult::Infeasible) {
      observer_.on_diagnostic("ROUTE_INFEASIBLE_SEQNO_NEEDED", peer, nullptr);
    } else if (result == RouteUpdateResult::StaleGeneration) {
      observer_.on_diagnostic("ROUTE_STALE_GENERATION", peer, nullptr);
    } else if (result == RouteUpdateResult::HeldDown) {
      observer_.on_diagnostic("ROUTE_HELD_DOWN", peer, nullptr);
    } else if (result != RouteUpdateResult::Accepted &&
               result != RouteUpdateResult::Updated &&
               result != RouteUpdateResult::Ignored) {
      observer_.on_diagnostic("ROUTE_UPDATE_REJECTED", peer, nullptr);
    }
  }
}

void MeshNode::handle_seqno_request(const wire::PlainFrame& frame, const NodeId peer,
                                        const MonotonicMs now_ms) noexcept {
  if (frame.payload_size != kSeqnoRequestPayloadBytes) {
    observer_.on_diagnostic("INVALID_SEQNO_REQUEST", peer, &frame.header.message);
    return;
  }
  ByteReader reader(ByteView{frame.payload.data(), frame.payload_size});
  NodeId requester = kInvalidNodeId;
  NodeId destination = kInvalidNodeId;
  RouteSequence requested_sequence = 0;
  std::uint32_t request_id = 0;
  std::uint8_t ttl = 0;
  if (!reader.read_u64(requester) || !reader.read_u64(destination) ||
      !reader.read_u16(requested_sequence) || !reader.read_u32(request_id) ||
      !reader.read_u8(ttl) || reader.remaining() != 0 || ttl == 0 ||
      ttl > kSeqnoRequestMaxTtl ||
      requester == kInvalidNodeId || destination == kInvalidNodeId) {
    observer_.on_diagnostic("INVALID_SEQNO_REQUEST", peer, &frame.header.message);
    return;
  }

  auto* seen = seqno_seen_.find([&](const SeqnoSeen& value) {
    return value.requester == requester && value.destination == destination &&
           value.request_id == request_id;
  });
  if (seen != nullptr) return;
  seen = seqno_seen_.allocate();
  if (seen == nullptr) {
    observer_.on_diagnostic("SEQNO_DEDUP_FULL", peer, &frame.header.message);
    return;
  }
  *seen = SeqnoSeen{requester, destination, request_id, now_ms + kSeqnoRequestLifetimeMs};
  // Scoped profile: the answer (a fresher sequence) must flow back along the
  // request's path, which is not necessarily a tree link — the previous hop
  // registers a short interest so triggered updates reach it, and an answer
  // from our own table is sent to it directly (routing-scale.md §3.3).
  Neighbor* requesting = gateway_scoped() ? find_neighbor(peer) : nullptr;
  if (requesting != nullptr) note_scoped_interest(*requesting, now_ms);

  if (destination == config_.node) {
    bool ambiguous = false;
    if (route_sequence_newer(requested_sequence, self_route_sequence_, ambiguous) ||
        ambiguous) {
      // RFC 8966 §3.8.1.2: an origin MUST NOT increase its sequence number by
      // more than 1 in reaction to a single seqno request. If one bump is not
      // enough, the requester's bounded retries converge instead.
      self_route_sequence_ = static_cast<RouteSequence>(self_route_sequence_ + 1U);
    }
    trigger_route_advertisement(now_ms);
    observer_.on_diagnostic("SEQNO_REQUEST_SATISFIED", peer, &frame.header.message);
    return;
  }

  if (ttl <= 1) return;
  // RFC 8966 §3.8.1.2: a node holding a route with a sequence at least as new
  // as the requested one answers from its own table instead of forwarding the
  // request toward the origin. Broadcast reaches the requester's path and
  // every other neighbor that may share the gap.
  const RouteSelection selected = routes_.best(destination);
  if (selected.valid) {
    bool ambiguous = false;
    const bool requested_newer =
        route_sequence_newer(requested_sequence, selected.sequence, ambiguous);
    if (!requested_newer && !ambiguous) {
      if (requesting != nullptr) {
        // Scoped profile: a generic trigger would only carry self + gateway
        // records; the requester needs THIS destination's record.
        requesting->pull_target = destination;
        requesting->pull_answer_pending = true;
      } else {
        trigger_route_advertisement(now_ms);
      }
      return;
    }
  }
  // One received request forwards along exactly one path (spec: a forwarder
  // must not branch). The selected route is preferred; an infeasible-but-live
  // candidate may carry it when feasibility blocks all forwarding.
  const NodeId next = routes_.request_next_hop(destination, 0, peer, requester);
  if (next == kInvalidNodeId || next == config_.node) {
    observer_.on_diagnostic("SEQNO_REQUEST_NO_PATH", peer, &frame.header.message);
    return;
  }
  (void)queue_seqno_request(next, requester, destination, requested_sequence,
                            request_id, static_cast<std::uint8_t>(ttl - 1U), now_ms);
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
       frame.header.type == FrameType::GroupData) &&
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
        note_rx_refusal(status, peer, &frame.header.message);
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
      observer_.on_diagnostic("FRAME_TYPE_UNSUPPORTED_IN_CORE_FIXED_250", peer,
                              &frame.header.message);
      break;
  }
}

void MeshNode::process_awaiting_hop(const MonotonicMs now_ms) noexcept {
  while (true) {
    auto* expired = awaiting_hop_.find(
        [&](const AwaitingHop& value) { return value.expires_at_ms <= now_ms; });
    if (expired == nullptr) break;
    TxJob job = expired->job;
    const bool deferred = expired->busy_deferred;
    awaiting_hop_.release(expired);
    if (deferred) {
      // BUSY deferral expiry re-admits the job under its BUSY readmission
      // budget — it is not an RF-loss retry (03 §5 separate accounting).
      readmit_after_busy(job, now_ms);
    } else {
      obs_hop_result(job, false, now_ms);
      // Hop-level timeout is its own counter — folded into rf_failures too,
      // but never reported under the wrong name (02 §counter identity).
      // Saturates with its flag set rather than wrapping silently.
      if (auto* bucket = job_bucket(job, now_ms)) {
        if (bucket->hop_timeouts != UINT32_MAX) {
          ++bucket->hop_timeouts;
        } else {
          bucket->saturation_mask |= kSatHopTimeouts;
        }
      }
      retry_or_fail(job, "HOP_ACCEPT_TIMEOUT", now_ms);
    }
  }
}

void MeshNode::process_delivery_timeouts(const MonotonicMs now_ms) noexcept {
  deliveries_.for_each([&](Delivery& delivery) {
    if (delivery.state == DeliveryState::Delivered || delivery.state == DeliveryState::Failed ||
        delivery.state == DeliveryState::Expired ||
        delivery.state == DeliveryState::CancelledBeforeTx ||
        delivery.state == DeliveryState::Indeterminate) {
      return;
    }
    if (now_ms >= delivery.expires_at_ms) {
      // APPLIED (01 §1.3): a transmitted APPLIED request may already have
      // executed at the destination — post-TX expiry is Indeterminate,
      // never the unproven Failed and never END_RECEIVED-promoted.
      if (delivery.options.delivery == DeliveryClass::Applied &&
          (delivery.state == DeliveryState::WaitingForMac ||
           delivery.state == DeliveryState::WaitingForHopAccept ||
           delivery.state == DeliveryState::WaitingForEndReceipt)) {
        set_delivery_state(delivery, DeliveryState::Indeterminate,
                           "APP_RESULT_TIMEOUT");
        return;
      }
      set_delivery_state(delivery, DeliveryState::Expired, "DEADLINE_EXPIRED");
      return;
    }
    // While retry rounds are paused (sleep drain or an operational pause),
    // the deliveries wait for their disposition instead of making new work.
    if (delivery.order_wait) {
      // Held behind its ordered predecessor: released once the predecessor
      // is Delivered (or gone as never-sent) or its deadline passed — the
      // head-of-line wait never outlives the predecessor's lifetime.
      const Delivery* predecessor = find_delivery(delivery.order_after);
      const bool settled =
          predecessor != nullptr &&
          (predecessor->state == DeliveryState::Delivered ||
           predecessor->state == DeliveryState::CancelledBeforeTx);
      if (!settled && now_ms < delivery.order_hold_until_ms) return;
      if (paused(pause::kRetryRounds)) return;
      delivery.order_wait = false;
      delivery.next_round_at_ms = now_ms;
    }
    if (!paused(pause::kRetryRounds) &&
        (delivery.state == DeliveryState::WaitingForRoute ||
         delivery.state == DeliveryState::WaitingForEndReceipt) &&
        now_ms >= delivery.next_round_at_ms) {
      if (delivery.state == DeliveryState::WaitingForEndReceipt) {
        if (delivery.options.delivery == DeliveryClass::Applied &&
            delivery.app_phase != 0) {
          // Application-pending window elapsed: bounded QUERY recovery
          // (<=kAppliedMaxQueries), then the delivery simply waits out its
          // deadline — a late RESULT still resolves it (01 §1.3).
          if (delivery.app_queries < kAppliedMaxQueries) {
            delivery.app_query_nonce = next_app_nonce_++;
            if (emit_app_query(delivery, now_ms)) {
              ++delivery.app_queries;
            }
            delivery.next_round_at_ms = std::min(
                delivery.expires_at_ms,
                now_ms + applied_window_ms(delivery.options.hop_limit,
                                           config_.hop_accept_timeout_ms));
          } else {
            delivery.next_round_at_ms = delivery.expires_at_ms;
          }
          return;
        }
        if (static_cast<std::uint8_t>(delivery.round + 1U) >=
            config_.max_end_to_end_rounds) {
          // For APPLIED the last round's DATA may have landed and executed —
          // Indeterminate, not the unproven Failed (01 §1.9).
          set_delivery_state(
              delivery,
              delivery.options.delivery == DeliveryClass::Applied
                  ? DeliveryState::Indeterminate
                  : DeliveryState::Failed,
              delivery.options.delivery == DeliveryClass::Applied
                  ? "APP_RESULT_TIMEOUT"
                  : "END_RECEIPT_TIMEOUT");
          return;
        }
        ++delivery.round;
      }
      const auto status = queue_origin_data(delivery, now_ms);
      if (!status) {
        delivery.next_round_at_ms = now_ms + 100;
        set_delivery_state(delivery, DeliveryState::WaitingForRoute, status.detail);
      }
    }
  });
}

void MeshNode::expire_dedup(const MonotonicMs now_ms) noexcept {
  while (true) {
    auto* expired = dedup_.find(
        [&](const DedupEntry& value) { return value.expires_at_ms <= now_ms; });
    if (expired == nullptr) break;
    dedup_.release(expired);
    saturating_inc(dedup_stats_.expired);
  }
}

std::int64_t MeshNode::control_budget_balance(const MonotonicMs now_ms) noexcept {
  if (now_ms > control_budget_last_ms_) {
    // Spec-envelope refill (1000µs/s == 1µs/ms). A balance that ran
    // negative through an over-capacity completion debit earns credit for
    // the whole interval, so elapsed clamps to the headroom to a FULL
    // bucket — not the capacity itself; credit beyond a full bucket is
    // unreachable anyway. The modular subtraction keeps room correct for
    // any negative balance.
    const std::uint64_t room =
        control_budget_tokens_us_ >=
                static_cast<std::int64_t>(kControlBudgetCapacityUs)
            ? 0
            : static_cast<std::uint64_t>(
                  static_cast<std::int64_t>(kControlBudgetCapacityUs)) -
                  static_cast<std::uint64_t>(control_budget_tokens_us_);
    const std::uint64_t elapsed = std::min<std::uint64_t>(
        now_ms - control_budget_last_ms_, room);
    control_budget_last_ms_ = now_ms;
    control_budget_tokens_us_ += static_cast<std::int64_t>(
        elapsed * kControlBudgetRefillUsPerS / 1000ULL);
  }
  return control_budget_tokens_us_;
}

MonotonicMs MeshNode::control_budget_wait_ms(const MonotonicMs now_ms) noexcept {
  // Emission demand = the calibrated per-frame air time: EWMA of measured
  // control-domain service, seeded at the pinned max-frame cost before any
  // sample exists. This keeps the bucket honest under the spec envelope
  // without charging a full worst-case frame the local driver never
  // actually burns. Demand is clamped to the bucket capacity: the refill
  // can never push the balance past one max frame's air time (§14 burst
  // >= 1 max frame), so a single over-capacity sample — driver service
  // including CCA backoff/retries — would otherwise defer against a
  // balance the bucket can never reach, silently stalling all management
  // emissions. The excess cost still arrives as the completion debit and
  // is repaid through the wait computed for the next emission (§8: a
  // normal route must never expire on this node's own budget wait).
  const std::int64_t demand = std::min<std::int64_t>(
      static_cast<std::int64_t>(control_service_ewma_us_),
      static_cast<std::int64_t>(kControlBudgetCapacityUs));
  const std::int64_t deficit = demand - control_budget_balance(now_ms);
  if (deficit <= 0) return 0;
  // deficit µs at the pinned refill rate -> ms, rounding up so the wait
  // lands affordable rather than one tick short.
  return (static_cast<std::uint64_t>(deficit) * 1000ULL +
          kControlBudgetRefillUsPerS - 1ULL) /
         kControlBudgetRefillUsPerS;
}

bool MeshNode::control_budget_refresh_fits(const MonotonicMs now_ms,
                                           const MonotonicMs wait_ms,
                                           const std::size_t fanout) noexcept {
  // Fan-out draw: every neighbor's refresh pulls the same bucket, so the
  // capacity decision prices `fanout` frames at the calibrated demand —
  // not just this emission — when bounding the wait inside the lease.
  const std::int64_t workload = static_cast<std::int64_t>(fanout) *
                                std::min<std::int64_t>(
                                    static_cast<std::int64_t>(control_service_ewma_us_),
                                    static_cast<std::int64_t>(kControlBudgetCapacityUs));
  const std::int64_t deficit = workload - control_budget_balance(now_ms);
  const std::uint64_t afford_ms =
      deficit <= 0 ? 0
                   : (static_cast<std::uint64_t>(deficit) * 1000ULL +
                      kControlBudgetRefillUsPerS - 1ULL) /
                         kControlBudgetRefillUsPerS;
  // Page count: the live route table's record pages each neighbor must
  // cycle through (the frame carries the self record plus entries). The
  // scoped profile spreads a whole upward cycle inside route_refresh_ticks
  // periods, so its refresh span is the tick count, not the page count.
  const std::uint64_t pages =
      gateway_scoped()
          ? config_.route_refresh_ticks
          : (static_cast<std::uint64_t>(routes_.size()) + kMaxRouteRecordsPerFrame) /
                kMaxRouteRecordsPerFrame;
  // 03 §8 refresh bound — pages*round_period + budget_wait + jitter +
  // loss_margin — against the ACTUAL lease the refresh must land inside.
  const std::uint64_t bound =
      pages * config_.route_advertisement_period_ms +
      std::max<std::uint64_t>(wait_ms, afford_ms) + kTriggeredJitterMs +
      config_.route_advertisement_period_ms;
  return config_.route_lifetime_ms > bound;
}

void MeshNode::note_control_budget_unsat() noexcept {
  saturating_inc(budget_stats_.control_budget_unsatisfiable);
  if (!control_budget_unsat_reported_) {
    control_budget_unsat_reported_ = true;
    observer_.on_diagnostic("CONTROL_BUDGET_UNSATISFIABLE", kInvalidNodeId,
                            nullptr);
  }
}

void MeshNode::schedule_route_advertisements(const MonotonicMs now_ms) noexcept {
  if (now_ms < next_route_advertisement_ms_ || scheduler_.full()) return;
  std::array<NodeId, kNeighborCapacity> active{};
  std::size_t count = 0;
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (neighbor.active && count < active.size()) active[count++] = neighbor.node;
  });
  if (count == 0) {
    next_route_advertisement_ms_ = now_ms + config_.route_advertisement_period_ms;
    return;
  }
  // §14 management airtime budget — calibrated profiles only. The
  // uncalibrated default profile never applies the spec-envelope refill
  // limit to route maintenance (radio.md §9/§14). When enabled, an
  // emission may only schedule while the bucket covers one frame's air
  // time; a needed deferral is allowed only while the §8 refresh bound
  // (fan-out × demand, live page count, actual lease) still fits —
  // otherwise the budget cannot sustain route maintenance for this
  // configuration: the emission goes out unfunded (a normal route must
  // never expire on this node's own budget wait) and the breach is
  // surfaced, never queued as a normal emission.
  if (config_.control_budget_gate_enabled) {
    const MonotonicMs wait_ms = control_budget_wait_ms(now_ms);
    if (wait_ms > 0) {
      if (control_budget_refresh_fits(now_ms, wait_ms, count)) {
        next_route_advertisement_ms_ = now_ms + wait_ms;
        return;
      }
      note_control_budget_unsat();
    } else {
      control_budget_unsat_reported_ = false;
    }
  }
  if (gateway_scoped()) {
    // One tick of the scoped profile: only the gateway-tree links that are
    // due this tick are refreshed (routing-scale.md §3.2).
    next_route_advertisement_ms_ = now_ms + config_.route_advertisement_period_ms;
    run_scoped_tick(now_ms);
    return;
  }
  const NodeId peer = active[route_neighbor_cursor_ % count];
  route_neighbor_cursor_ = (route_neighbor_cursor_ + 1) % count;
  (void)queue_route_update(peer, now_ms);
  auto interval = std::max<std::uint32_t>(
      50, config_.route_advertisement_period_ms / static_cast<std::uint32_t>(count));
  // >=50% queue watermark: background work shrinks to half rate (03 §4).
  if (scheduler_.background_reduced()) interval *= 2;
  next_route_advertisement_ms_ = now_ms + interval;
}

void MeshNode::expire_sequence_requests(const MonotonicMs now_ms) noexcept {
  while (true) {
    auto* expired = seqno_seen_.find(
        [&](const SeqnoSeen& value) { return value.expires_at_ms <= now_ms; });
    if (expired == nullptr) break;
    seqno_seen_.release(expired);
  }
  while (true) {
    auto* expired = seqno_state_.find(
        [&](const SeqnoState& value) { return value.expires_at_ms <= now_ms; });
    if (expired == nullptr) break;
    seqno_state_.release(expired);
  }
}

void MeshNode::schedule_sequence_requests(const MonotonicMs now_ms) noexcept {
  // Sequence requests are the repair path for infeasible destinations —
  // they must keep flowing under a data flood (03 §8). Bounded by the
  // global in-flight cap, linear backoff saturating at the max cooldown
  // and the queue admission check below; no watermark early-out.
  // Outstanding = requests sent inside the dedup window, still waiting for a
  // fresh advertisement. Bounded so a dead origin cannot pile up requests.
  std::size_t inflight = 0;
  seqno_state_.for_each([&](const SeqnoState& value) {
    if (value.last_sent_ms != 0 &&
        value.last_sent_ms + kSeqnoRequestLifetimeMs > now_ms) {
      ++inflight;
    }
  });

  routes_.for_each_sequence_request([&](const NodeId destination,
                                        const RouteSequence requested_sequence) {
    auto* state = seqno_state_.find(
        [&](const SeqnoState& value) { return value.destination == destination; });
    if (state == nullptr) {
      state = seqno_state_.allocate();
      if (state == nullptr) return;
      state->destination = destination;
      state->requested_sequence = requested_sequence;
      state->next_request_ms = now_ms;
    }
    state->expires_at_ms = now_ms + kSeqnoStateDwellMs;
    bool ambiguous = false;
    if (route_sequence_newer(requested_sequence, state->requested_sequence, ambiguous) ||
        ambiguous) {
      state->next_request_ms = now_ms;  // newer need: fresh retry window
      state->attempts = 0;
    }
    state->requested_sequence = requested_sequence;
    if (now_ms < state->next_request_ms || scheduler_.full()) return;
    // No retry cap (issue #50): a destination whose infeasible
    // advertisements keep renewing their lease would never see a fresh
    // sequence again if probing stopped — permanent unreachability with no
    // recovery path. Requests keep flowing on the bounded max-cooldown
    // cadence instead (per-destination rate still capped by backoff, the
    // in-flight cap and the dedup window).
    if (inflight >= kSeqnoMaxInflight) return;

    // Candidate rotation uses probe_cursor, not the saturating backoff
    // counter: a capped attempts would pin every later request to
    // hops[attempts % count] and starve the other candidates forever.
    const NodeId next = routes_.request_next_hop(destination, state->probe_cursor);
    if (next == kInvalidNodeId || next == config_.node) return;
    const std::uint32_t request_id = next_seqno_request_id_++;
    auto* seen = seqno_seen_.allocate();
    if (seen == nullptr) return;
    *seen = SeqnoSeen{config_.node, destination, request_id, now_ms + kSeqnoRequestLifetimeMs};
    if (queue_seqno_request(next, config_.node, destination, requested_sequence,
                            request_id, kDefaultHopLimit, now_ms)) {
      // Saturate, never wrap: attempts==0 would zero the backoff below and
      // turn the bounded cadence into a per-poll flood. The probe cursor is
      // deliberately NOT saturating — it wraps so candidate rotation keeps
      // cycling past the backoff cap.
      if (state->attempts != UINT8_MAX) ++state->attempts;
      ++state->probe_cursor;
      ++inflight;
      state->last_sent_ms = now_ms;
      // Linear backoff keeps retries bounded without a growing flood; the
      // >=50% queue watermark halves the probing rate on top (03 §4).
      const std::uint32_t factor = scheduler_.background_reduced() ? 2 : 1;
      state->next_request_ms = now_ms + std::min<std::uint32_t>(
          kSeqnoRequestMaxCooldownMs,
          kSeqnoRequestCooldownMs * state->attempts * factor);
      char detail[64];
      std::snprintf(detail, sizeof detail, "SEQNO_REQUEST_SENT dest=%llu seq=%u att=%u",
                    static_cast<unsigned long long>(destination), requested_sequence,
                    state->attempts);
      observer_.on_diagnostic(detail, next, nullptr);
    } else {
      seqno_seen_.release(seen);
    }
  });
}

void MeshNode::trigger_route_advertisement(const MonotonicMs now_ms) noexcept {
  // Generic triggers (neighbor loss, sequence bump, peer restart, relay
  // policy) change what every tree link must hear: in the scoped profile the
  // burst covers the parents (self record + dirty routes) and the children
  // and interested neighbors (self + gateway records).
  if (gateway_scoped()) scoped_trigger_all_ = true;
  arm_triggered_advertisement(now_ms);
}

void MeshNode::arm_triggered_advertisement(const MonotonicMs now_ms) noexcept {
  // Deterministic jitter decorrelates bursts across nodes without a RNG.
  const MonotonicMs jitter = (config_.node * 31ULL + ++trigger_counter_ * 7ULL) %
                             (kTriggeredJitterMs + 1ULL);
  const MonotonicMs earliest = std::max(now_ms, next_triggered_ms_) + jitter;
  if (!triggered_advertisement_ || earliest < triggered_at_ms_) {
    triggered_advertisement_ = true;
    triggered_at_ms_ = earliest;
  }
}

void MeshNode::run_triggered_advertisement(const MonotonicMs now_ms) noexcept {
  if (!triggered_advertisement_ || now_ms < triggered_at_ms_) return;
  // Same §14 gate as the periodic path — calibrated profiles only: an
  // unaffordable burst re-arms at its token wait, but only while the §8
  // refresh bound (fan-out × demand, page count, actual lease) can absorb
  // it; otherwise the burst goes out unfunded and the breach surfaces.
  if (config_.control_budget_gate_enabled) {
    const MonotonicMs wait_ms = control_budget_wait_ms(now_ms);
    if (wait_ms > 0) {
      std::size_t fanout = 0;
      neighbors_.for_each([&](const Neighbor& neighbor) {
        if (neighbor.active) ++fanout;
      });
      if (control_budget_refresh_fits(now_ms, wait_ms, fanout)) {
        triggered_at_ms_ = now_ms + wait_ms;
        return;  // stays armed
      }
      note_control_budget_unsat();
    } else {
      control_budget_unsat_reported_ = false;
    }
  }
  triggered_advertisement_ = false;
  // The gate charges affordability for ONE frame, then emits one
  // RouteUpdate per active neighbor: a multi-neighbor burst under-charges
  // up front, repaid as each completion debits its measured service (the
  // charge-at-completion model the rest of §14 runs on).
  // >=50% queue watermark: triggered bursts run at half rate (03 §4).
  next_triggered_ms_ = now_ms + kTriggeredUpdateMinIntervalMs *
                                   (scheduler_.background_reduced() ? 2 : 1);
  if (gateway_scoped()) {
    // Scoped burst: tree links and interested neighbors only — never the
    // flat all-neighbor dump (issue #41 burst of F frames per trigger).
    run_scoped_triggered(now_ms);
    return;
  }
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (!neighbor.active || scheduler_.full()) return;
    (void)queue_route_update(neighbor.node, now_ms);
  });
}

void MeshNode::scan_selection_changes(const MonotonicMs now_ms) noexcept {
  if (!gateway_scoped()) {
    routes_.for_each_selected_change(
        [&](const RouteSelection&) { trigger_route_advertisement(now_ms); },
        now_ms);
    return;
  }
  routes_.for_each_selected_change(
      [&](const RouteSelection& selection, const RouteSelection& previous) {
        note_scoped_change(selection, previous, now_ms);
      },
      now_ms);
}

Status MeshNode::poll(const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_) return Status::success();
  last_clock_ms_ = now_ms;
  // Expired/revoked admission transactions close before anything else may
  // transmit: no new TX leaves on a dead transaction (design-q116 §7.2).
  sweep_transactions(now_ms);
  routes_.expire(now_ms);
  // P3 (03 §6/§7): decay the per-peer observation windows, release stale
  // busy feedback at its TTL, refresh effective link costs and advance the
  // route-switch hysteresis before any selection change is advertised.
  refresh_neighbor_load(now_ms);
  expire_dedup(now_ms);
  expire_sequence_requests(now_ms);
  process_awaiting_hop(now_ms);
  process_delivery_timeouts(now_ms);
  // APPLIED terminal bookkeeping: result-record retention expiry and the
  // bounded RESULT emit retry pass (sdk-completion/01 §1.4/§1.6).
  process_applied(now_ms);
  // Group delivery (group-delivery.md): report deadlines, source rounds and
  // admission, ordered-hold release, retention expiry.
  process_group(now_ms);
  scan_selection_changes(now_ms);
  if (gateway_scoped()) expire_route_requests(now_ms);
  if (!paused(pause::kBackgroundWork)) {
    // Background work stops while paused/draining; in-flight queue entries
    // still dispatch below so the TX path can settle.
    run_triggered_advertisement(now_ms);
    schedule_sequence_requests(now_ms);
    schedule_route_advertisements(now_ms);
    if (gateway_scoped()) {
      // Scoped profile repair/bootstrap and on-demand paths (routing-scale
      // §3.3/§4): answers to pulls, pulls for a lost gateway route and
      // bounded discovery for waiting deliveries.
      flush_pull_answers(now_ms);
      schedule_parent_releases(now_ms);
      schedule_gateway_pulls(now_ms);
      schedule_route_discovery(now_ms);
    }
  }
  // The Service/config components are driven by the Owner outside node
  // calls (design-q116 §8.3): their poll() no longer runs here, and their
  // payloads/completions wait in the component event queue for take/complete.
  dispatch_next(now_ms);
  return Status::success();
}

// ---------------------------------------------------------------------------
// Congestion observation + stats surface (03 §3 groundwork for P3)
// ---------------------------------------------------------------------------

ObservationBucket* MeshNode::observation_bucket(
    const ObservationKey& key, const MonotonicMs now_ms) noexcept {
  auto* existing = observations_.find(
      [&](const ObservationBucket& value) { return value.key == key; });
  if (existing != nullptr) {
    // Window rotation (02 §2.4): a live bucket finalizes its current window
    // into `previous` every kObservationWindowMs — freshness is then judged
    // from contributing measurements, never from allocation age.
    if (now_ms - existing->window_start_ms >= kObservationWindowMs) {
      existing->previous = existing->current;
      existing->current = ObservationWindow{};
      existing->window_start_ms = now_ms;
    }
    existing->last_update_ms = now_ms;
    return existing;
  }
  auto* created = observations_.allocate();
  if (created == nullptr) {
    // Bounded reclaim (02 §bounded state): only a bucket whose evidence
    // validity has fully expired (kFeedbackTtlMs, not the shorter
    // aggregation window) AND that holds no pins or pending completions
    // may be released — live evidence and in-flight work are never
    // evicted into a silent counter reset.
    ObservationBucket* oldest_expired = nullptr;
    observations_.for_each([&](ObservationBucket& value) {
      if (value.pins != 0 || value.pending_completions != 0) return;
      if (now_ms - value.last_update_ms < kFeedbackTtlMs) return;
      if (oldest_expired == nullptr ||
          value.last_update_ms < oldest_expired->last_update_ms) {
        oldest_expired = &value;
      }
    });
    if (oldest_expired == nullptr ||
        !observations_.release(oldest_expired)) {
      ++busy_stats_.observation_overflow;  // bounded memory: overflow counts, never grows
      return nullptr;
    }
    created = observations_.allocate();
    if (created == nullptr) {
      ++busy_stats_.observation_overflow;
      return nullptr;
    }
  }
  created->key = key;
  created->window_start_ms = now_ms;
  created->last_update_ms = now_ms;
  return created;
}

ObservationBucket* MeshNode::observation_bucket(
    const NodeId peer, const std::uint8_t length_class,
    const MonotonicMs now_ms) noexcept {
  // Align submission-side accounting with the completion-side identity
  // (02 §2.3): one observation key spans the whole attempt, so a snapshot
  // can never report MAC successes against zero submissions. The peer's
  // current summary supplies the identity tuple; when none exists the
  // zero-generation key is the honest "unattributed" record.
  ObservationKey key{BindingGeneration{0}, ObservationDirection::Egress,
                     RadioGeneration{0}, ChannelEpoch{0}, length_class, peer};
  if (const auto* summary = telemetry_peers_.find(peer);
      summary != nullptr && !summary->stale) {
    key.binding = summary->binding;
    key.radio = summary->radio;
    key.channel = summary->channel;
  }
  return observation_bucket(key, now_ms);
}

void MeshNode::obs_tx_submitted(TxJob& job, const std::uint64_t token,
                                const MonotonicMs now_ms) noexcept {
  // One immutable observation identity per PHYSICAL ATTEMPT (02 §2.3):
  // every accepted submission re-stamps the key the runtime froze for
  // THIS token — a retry after a rebind/channel change must not inherit
  // the first attempt's identity. Only when the runtime did not stamp one
  // (host simulation harness) fall back to the peer summary.
  if (submit_identity_.valid && submit_identity_.token == token) {
    job.obs_key = submit_identity_.key;
    job.obs_key_set = true;
    submit_identity_.valid = false;
  } else if (!job.obs_key_set) {
    ObservationKey key{BindingGeneration{0}, ObservationDirection::Egress,
                       RadioGeneration{0}, ChannelEpoch{0},
                       frame_length_class(job.tx_cost), job.peer};
    if (const auto* summary = telemetry_peers_.find(job.peer);
        summary != nullptr && !summary->stale) {
      key.binding = summary->binding;
      key.radio = summary->radio;
      key.channel = summary->channel;
    }
    job.obs_key = key;
    job.obs_key_set = true;
  }
  auto* bucket = observation_bucket(job.obs_key, now_ms);
  if (bucket != nullptr) {
    ++bucket->tx_submitted;
    // The attempt pins its bucket until the completion-side observation
    // lands — in-flight work can never be reclaimed (02 §bounded state).
    if (bucket->pending_completions != UINT32_MAX) {
      ++bucket->pending_completions;
    }
    if (job.physical_attempts > 1) {
      // A re-submission after MAC failure/timeout is the only SDK-visible
      // retry the driver reports — never claimed as ESP-NOW-internal (02).
      // Saturates with its flag set rather than wrapping silently.
      if (bucket->sdk_retries != UINT32_MAX) {
        ++bucket->sdk_retries;
      } else {
        bucket->saturation_mask |= kSatSdkRetries;
      }
    }
    ++bucket->sojourn_samples;
    // Queue sojourn: enqueue -> handed to radio (03 §3). Lifetime EWMA
    // plus the current window's own measurement — window fields are what
    // snapshot freshness is judged against.
    ewma_add(bucket->queue_sojourn_ms_ewma, now_ms - job.enqueued_at_ms,
             bucket->sojourn_samples);
    ++bucket->current.queue_samples;
    ewma_add(bucket->current.queue_us_ewma,
             (now_ms - job.enqueued_at_ms) * 1000,
             bucket->current.queue_samples);
    ++bucket->current.tx_submitted;
    bucket->current.present = true;
    if (bucket->current.first_sample_ms == 0) {
      bucket->current.first_sample_ms = now_ms;
    }
    bucket->current.last_sample_ms = now_ms;
  }
  // Per-peer mirror (03 §6): the A->B queue picture and the exchange ratio
  // are per-next-hop, so the global bucket is mirrored into the neighbor
  // record even when the bounded bucket pool overflows.
  if (auto* neighbor = find_neighbor(job.peer)) {
    ++neighbor->sojourn_samples;
    ewma_add(neighbor->queue_sojourn_ewma_ms, now_ms - job.enqueued_at_ms,
             neighbor->sojourn_samples);
    neighbor->last_sojourn_ms = now_ms;
    neighbor->metric_sources |= Neighbor::kMetricSourceLocalSojourn;
    if (neighbor->sojourn_window_ms == 0) neighbor->sojourn_window_ms = now_ms;
    if (job.requires_hop_accept) {
      // Eligible attempt work for the exchange-cost ratio: every physical
      // submission counts, including submissions that later fail (§6.1).
      if (neighbor->exchange_window_ms == 0) neighbor->exchange_window_ms = now_ms;
      ++neighbor->exchange_work;
      neighbor->metric_sources |= Neighbor::kMetricSourceLocalExchange;
    }
  }
}

ObservationBucket* MeshNode::job_bucket(const TxJob& job,
                                        const MonotonicMs now_ms) noexcept {
  // The attempt's own stamped identity when it exists — never re-derive it
  // from a summary that may have re-bound mid-attempt (02 §2.3).
  if (job.obs_key_set) return observation_bucket(job.obs_key, now_ms);
  return observation_bucket(job.peer, frame_length_class(job.tx_cost), now_ms);
}

void MeshNode::obs_driver_service(const TxJob& job, const std::uint32_t service_us,
                                  const MonotonicMs now_ms) noexcept {
  auto* bucket = job_bucket(job, now_ms);
  if (bucket == nullptr) return;
  ++bucket->service_samples;
  // Driver service: driver acceptance -> TX callback (03 §3). May include
  // CCA/MAC retries — it is not airtime.
  ewma_add(bucket->driver_service_us_ewma, service_us, bucket->service_samples);
}

void MeshNode::obs_hop_result(const TxJob& job, const bool accepted,
                              const MonotonicMs now_ms) noexcept {
  auto* bucket = job_bucket(job, now_ms);
  if (bucket != nullptr) {
    if (accepted) {
      ++bucket->hop_accepted;
      // Hop exchange attempts until authenticated HOP_ACCEPT (03 §3), counted
      // by the physical attempt index that finally got through.
      const std::uint8_t index =
          job.physical_attempts == 0
              ? 0
              : static_cast<std::uint8_t>(job.physical_attempts - 1);
      ++bucket->accepted_at_attempt[std::min<std::uint8_t>(
          index, kCombinedPhysicalAttemptsMax - 1)];
    } else {
      ++bucket->rf_failures;  // HOP_ACCEPT timeout folds into RF-loss accounting
    }
  }
  if (accepted) {
    if (auto* neighbor = find_neighbor(job.peer)) {
      ++neighbor->exchange_accepts;  // authenticated-accept success (03 §6.1)
      neighbor->metric_sources |= Neighbor::kMetricSourceLocalExchange;
    }
  }
}

void MeshNode::obs_count(const TxJob& job,
                         std::uint64_t ObservationBucket::*counter,
                         const MonotonicMs now_ms) noexcept {
  auto* bucket = job_bucket(job, now_ms);
  if (bucket != nullptr) ++(bucket->*counter);
}

void MeshNode::obs_final(const Delivery& delivery, const DeliveryState state,
                         const MonotonicMs now_ms) noexcept {
  std::uint64_t ObservationBucket::*counter = nullptr;
  switch (state) {
    case DeliveryState::Delivered:
      // Only RELIABLE completion is an END_RECEIPT result; a BestEffort
      // "delivered" means TX_MAC_DONE and counts as a plain completion.
      counter = delivery.options.delivery == DeliveryClass::Reliable
                    ? &ObservationBucket::end_receipts
                    : &ObservationBucket::completions;
      break;
    case DeliveryState::Expired:
      counter = &ObservationBucket::expiries;
      break;
    case DeliveryState::Failed:
      counter = &ObservationBucket::failures;
      break;
    default:
      counter = &ObservationBucket::indeterminate;
      break;
  }
  // Final results aggregate under the default length class — a delivery has
  // no single on-air frame size.
  auto* bucket = observation_bucket(delivery.destination, 0, now_ms);
  if (bucket != nullptr) ++(bucket->*counter);
}

// ---------------------------------------------------------------------------
// M1 telemetry entry points (02-telemetry.md §2.3)
// ---------------------------------------------------------------------------

Status MeshNode::note_radio_tx(const RadioTxObservation& observation,
                               const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_ || observation.peer == kInvalidNodeId) return Status::success();
  const std::uint64_t service_us =
      observation.completed_us > observation.submitted_us
          ? observation.completed_us - observation.submitted_us
          : 0;
  if (service_us > 0) {
    // §14 airtime ledger: debit the measured driver service before any
    // bucket bookkeeping — the ledger is a fixed accumulator and must
    // record even when the bounded bucket pool cannot. A token that
    // matches the in-flight submission attributes to that job's domain;
    // anything else (raw lane, bootstrap, stale callback) lands in Misc.
    AirtimeDomain domain = AirtimeDomain::Misc;
    if (observation.token != 0 && physical_.active &&
        observation.token == physical_.token) {
      domain = TxScheduler::airtime_domain(physical_.job);
    }
    switch (domain) {
      case AirtimeDomain::Ack:
        saturating_add(budget_stats_.service_us_ack, service_us);
        break;
      case AirtimeDomain::Work:
        saturating_add(budget_stats_.service_us_work, service_us);
        break;
      case AirtimeDomain::Control:
        saturating_add(budget_stats_.service_us_control, service_us);
        // §14 charges the gated domain at completion: measured service
        // debits the bucket and may run it negative — the deficit is
        // repaid through the wait computed for the next management
        // emission, never by queueing on debt. The same sample calibrates
        // the demand the gate charges per emission.
        control_budget_balance(now_ms);
        control_budget_tokens_us_ -= static_cast<std::int64_t>(service_us);
        ++control_service_samples_;
        ewma_add(control_service_ewma_us_,
                 static_cast<std::uint32_t>(
                     std::min<std::uint64_t>(service_us, UINT32_MAX)),
                 control_service_samples_);
        break;
      case AirtimeDomain::Optimization:
        saturating_add(budget_stats_.service_us_optimization, service_us);
        break;
      case AirtimeDomain::Misc:
        saturating_add(budget_stats_.service_us_misc, service_us);
        break;
    }
  }
  auto* bucket = observation_bucket(
      ObservationKey{observation.binding_generation,
                     ObservationDirection::Egress, observation.radio_generation,
                     observation.channel_epoch, observation.frame_length_class,
                     observation.peer},
      now_ms);
  if (bucket == nullptr) {
    // observation_bucket already counted overflow
    return Status::success();
  }
  bucket->observer_boot = config_.boot_incarnation;
  switch (observation.outcome) {
    case RadioTxOutcome::Success:
      ++bucket->tx_mac_success;
      break;
    case RadioTxOutcome::Failure:
      ++bucket->tx_mac_fail;
      break;
    case RadioTxOutcome::Unknown:
      ++bucket->unknown_results;
      // §3.3 evidence gate: an Unknown resolution taints the peer's metric
      // window — it may worsen but never improve until the next roll.
      if (Neighbor* neighbor = find_neighbor(observation.peer)) {
        neighbor->metric_window_dirty = true;
      }
      break;
  }
  if (service_us > 0) {
    const std::uint32_t service_us32 = static_cast<std::uint32_t>(service_us);
    ++bucket->service_samples;
    ++bucket->current.driver_samples;
    ewma_add(bucket->driver_service_us_ewma, service_us32,
             bucket->service_samples);
    ewma_add(bucket->current.driver_us_ewma, service_us32,
             bucket->current.driver_samples);
  }
  bucket->current.present = true;
  bucket->current.sources |= static_cast<std::uint8_t>(
      1u << static_cast<unsigned>(observation.provenance));
  bucket->current.last_sample_ms = now_ms;
  if (bucket->current.first_sample_ms == 0) {
    bucket->current.first_sample_ms = now_ms;
  }
  return Status::success();
}

const PeerTelemetrySummary* MeshNode::telemetry_peer(const NodeId peer) const noexcept {
  return telemetry_peers_.find(peer);
}

const ObservationBucket* MeshNode::telemetry_bucket(
    const ObservationKey& key) const noexcept {
  return observations_.find(
      [&](const ObservationBucket& value) { return value.key == key; });
}

// ---------------------------------------------------------------------------
// D1c Diagnostic (48) dispatch (02-telemetry §4.2)
// ---------------------------------------------------------------------------

Status MeshNode::send_telemetry_query(const NodeId observer,
                                      const TelemetryQuery& query,
                                      const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "node not started");
  }
  if (observer == kInvalidNodeId || observer == kBroadcastNodeId ||
      observer == config_.node) {
    return Status::error(StatusCode::InvalidArgument, "invalid observer");
  }
  std::array<std::uint8_t, kTelemetryQueryBodySize> body{};
  const Status status =
      telemetry_query_encode(query, MutableByteView{body.data(), body.size()});
  if (!status) return status;
  // Bounded reply path: the query's own lifetime (capped at the 5 s design
  // bound) limits how long the exchange may occupy the routed lane.
  const MessageId id{config_.message_session, next_control_sequence_++};
  return queue_typed_job(FrameType::Diagnostic, JobOwner::Diagnostic, id,
                         observer, ByteView{body.data(), body.size()}, 0,
                         kTelemetryQueryLifetimeMs, Priority::Normal, now_ms);
}

Status MeshNode::send_capabilities_query(
    const NodeId peer,
    const std::array<std::uint8_t, kCapabilitiesNonceSize>& nonce,
    const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (!started_) {
    return Status::error(StatusCode::InvalidState, "node not started");
  }
  auto* const neighbor = find_neighbor(peer);
  if (peer == kInvalidNodeId || peer == kBroadcastNodeId ||
      peer == config_.node || neighbor == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "invalid peer");
  }
  // Renewal bound (04 §capabilities): a completed or granted exchange may
  // not be restarted for the same peer inside kCapQueryRenewalMs —
  // capability probing is bounded airtime, not a polling primitive.
  if (neighbor->last_cap_exchange_ms != 0 &&
      now_ms - neighbor->last_cap_exchange_ms < kCapQueryRenewalMs) {
    return Status::error(StatusCode::Busy, "capability query renewal bound");
  }
  // One outstanding query per peer; replies beyond their lifetime are
  // never matched (04 §capabilities).
  PendingCapQuery* free_slot = nullptr;
  for (auto& p : pending_caps_) {
    if (p.peer == kInvalidNodeId) {
      if (free_slot == nullptr) free_slot = &p;
      continue;
    }
    if (p.expires_at_ms <= now_ms) {
      if (free_slot == nullptr) free_slot = &p;
      continue;
    }
    if (p.peer == peer) {
      return Status::error(StatusCode::Busy, "capability query outstanding");
    }
  }
  if (free_slot == nullptr) {
    return Status::error(StatusCode::NoCapacity, "capability query table full");
  }
  CapabilitiesQuery query{};
  query.nonce = nonce;
  std::array<std::uint8_t, kCapabilitiesQueryBodySize> body{};
  Status status =
      capabilities_query_encode(query, MutableByteView{body.data(), body.size()});
  if (!status) return status;
  TxJob job{};
  job.form = JobForm::Plain;
  job.owner = JobOwner::Diagnostic;
  job.peer = peer;
  job.requires_hop_accept = false;
  job.max_attempts = 1;
  job.deadline_ms = now_ms + kControlLifetimeMs;
  job.plain.header.type = FrameType::Diagnostic;
  job.plain.header.delivery = DeliveryClass::BestEffort;
  job.plain.header.hop_remaining = 1;
  job.plain.header.network = config_.network;
  job.plain.header.origin = config_.node;
  job.plain.header.destination = peer;
  job.plain.header.previous_hop = config_.node;
  job.plain.header.next_hop = peer;
  job.plain.header.message =
      MessageId{config_.message_session, next_control_sequence_++};
  job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
  job.plain.header.original_lifetime_ms = kControlLifetimeMs;
  job.plain.header.link_epoch = config_.link_epoch;
  job.plain.header.end_epoch = config_.end_epoch;
  std::memcpy(job.plain.payload.data(), body.data(), body.size());
  job.plain.payload_size = body.size();
  if (!scheduler_.enqueue(std::move(job), config_.node, now_ms)) {
    return Status::error(StatusCode::NoCapacity, "tx queue full");
  }
  free_slot->peer = peer;
  free_slot->nonce = nonce;
  free_slot->expires_at_ms = now_ms + kCapQueryLifetimeMs;
  // Pin the peer's binding generation at query time: a reply that arrives
  // after a rebind is stale evidence and must not grant capability.
  if (const auto* summary = telemetry_peers_.find(peer);
      summary != nullptr && summary->occupied) {
    free_slot->binding = summary->binding;
  } else {
    free_slot->binding = BindingGeneration{0};
  }
  return Status::success();
}

Status MeshNode::queue_diagnostic_reply(const NodeId destination,
                                        const ByteView body,
                                        const std::uint32_t lifetime_ms,
                                        const MonotonicMs now_ms) noexcept {
  const MessageId id{config_.message_session, next_control_sequence_++};
  return queue_typed_job(FrameType::Diagnostic, JobOwner::Diagnostic, id,
                         destination, body, 0, lifetime_ms, Priority::Normal,
                         now_ms);
}

Status MeshNode::build_telemetry_snapshot(
    const TelemetryQuery& query, const MonotonicMs now_ms,
    TelemetrySnapshot& out, DiagnosticRejectReason& reject_reason) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  return build_telemetry_snapshot_impl(query, now_ms, out, reject_reason);
}

Status MeshNode::build_telemetry_snapshot_impl(
    const TelemetryQuery& query, const MonotonicMs now_ms,
    TelemetrySnapshot& out, DiagnosticRejectReason& reject_reason) noexcept {
  const PeerTelemetrySummary* summary = telemetry_peers_.find(query.peer);
  if (summary == nullptr) {
    reject_reason = DiagnosticRejectReason::NoPeer;
    return Status::error(StatusCode::NotFound, "no telemetry for peer");
  }
  if (summary->stale) {
    reject_reason = DiagnosticRejectReason::Stale;
    return Status::error(StatusCode::InvalidState, "telemetry stale");
  }

  // Freshness is judged ONLY from the measurements that contribute each
  // field group (02 §2.4): an unrelated recent frame can never relabel an
  // old RSSI aggregate as fresh, bookkeeping timestamps never freshen a
  // bucket, and a bound the contributing measurements cannot meet rejects
  // the whole snapshot as STALE instead of returning stale data with
  // cleared bits.
  const ObservationBucket* bucket = nullptr;
  if (query.length_class != kTelemetryPeerSummaryClass) {
    const ObservationKey key{summary->binding, query.direction,
                             summary->radio, summary->channel,
                             query.length_class, query.peer};
    bucket = telemetry_bucket(key);
  }
  // Contributing measurement stamps: RSSI group → last_rssi_ms; bucket
  // group → the current window's OLDEST contributing sample
  // (first_sample_ms — never last_update_ms bookkeeping, and never the
  // newest sample which would overstate freshness).
  MonotonicMs oldest_contributing = 0;
  const bool rssi_contributes = summary->rssi_present;
  const bool bucket_contributes =
      bucket != nullptr && bucket->current.present &&
      bucket->current.first_sample_ms != 0;
  if (rssi_contributes) oldest_contributing = summary->last_rssi_ms;
  if (bucket_contributes &&
      (oldest_contributing == 0 ||
       bucket->current.first_sample_ms < oldest_contributing)) {
    oldest_contributing = bucket->current.first_sample_ms;
  }
  const auto within_bound = [&](const MonotonicMs stamp) {
    return stamp != 0 && now_ms - stamp <= query.max_age_ms;
  };
  // A nonzero bound must be satisfiable by at least one contributing
  // measurement; max_age_ms == 0 means "no bound requested".
  if (query.max_age_ms != 0 &&
      !(rssi_contributes && within_bound(summary->last_rssi_ms)) &&
      !(bucket_contributes &&
        within_bound(bucket->current.first_sample_ms))) {
    reject_reason = DiagnosticRejectReason::Stale;
    return Status::error(StatusCode::Expired,
                         "no contributing measurement within bound");
  }

  out = TelemetrySnapshot{};
  out.request_id = query.request_id;
  out.observer = config_.node;
  out.observer_boot = config_.boot_incarnation;
  out.peer = query.peer;
  out.binding = summary->binding;
  out.radio = summary->radio;
  out.channel_epoch = summary->channel;
  out.channel = summary->channel_present ? summary->last_channel : 0;
  out.direction = query.direction;
  out.length_class = query.length_class;
  out.sampled_at_ms = oldest_contributing;
  // sample_age is the age of the OLDEST contributing measurement — a
  // conservative freshness claim that never rides on unrelated activity.
  out.sample_age_ms =
      oldest_contributing != 0 && now_ms > oldest_contributing
          ? static_cast<std::uint32_t>(now_ms - oldest_contributing)
          : 0;
  out.event_drops = static_cast<std::uint32_t>(
      std::min<std::uint64_t>(telemetry_event_drops_, UINT32_MAX));

  const bool rssi_fresh =
      summary->rssi_present &&
      (query.max_age_ms == 0 || within_bound(summary->last_rssi_ms));
  if (summary->rssi_present) {
    if (rssi_fresh) out.validity |= kTelemetryValidRssi;
    out.rssi_last = summary->rssi_last;
    out.rssi_min = summary->rssi_min;
    out.rssi_max = summary->rssi_max;
    out.rssi_ewma_q8_8 = summary->rssi_ewma_q8_8;
    out.rssi_samples = summary->rssi_samples;
    if (summary->rssi_saturated) out.saturation_mask |= kSatRssiSamples;
  }
  // Source bits reflect EVERY contributing group: the peer summary's own
  // provenance plus the detailed bucket's window source mask — an injected
  // TX measurement is never serialized as driver-derived evidence.
  out.validity |= summary->provenance == ObservationProvenance::LocalDriver
                      ? kTelemetrySourceLocalDriver
                      : kTelemetrySourceInjectedTest;
  if (bucket != nullptr) {
    const std::uint8_t src = bucket->current.sources;
    if (src & (1u << static_cast<unsigned>(ObservationProvenance::LocalDriver))) {
      out.validity |= kTelemetrySourceLocalDriver;
    }
    if (src & (1u << static_cast<unsigned>(ObservationProvenance::InjectedTest))) {
      out.validity |= kTelemetrySourceInjectedTest;
    }
  }
  if (summary->stale || (summary->rssi_present && !rssi_fresh)) {
    out.validity |= kTelemetryStale;
  }

  // A peer-summary-class query stops at the RSSI record; a bucket class
  // additionally fills the counters for that exact observation key.
  if (query.length_class != kTelemetryPeerSummaryClass) {
    if (bucket != nullptr) {
      const auto clamp = [](const std::uint64_t v) {
        return static_cast<std::uint32_t>(std::min<std::uint64_t>(v, UINT32_MAX));
      };
      // Lifetime counters are reported as lifetime values regardless of
      // freshness; the bucket-validity bit asserts a contributing sample
      // inside the requested bound — bookkeeping stamps never count.
      const bool bucket_fresh =
          query.max_age_ms == 0
              ? bucket_contributes
              : within_bound(bucket->current.first_sample_ms);
      if (bucket_fresh) out.validity |= kTelemetryValidBucket;
      out.window_ms = static_cast<std::uint32_t>(
          std::min<std::uint64_t>(now_ms - bucket->window_start_ms, UINT32_MAX));
      out.tx_submitted = clamp(bucket->tx_submitted);
      out.tx_mac_success = bucket->tx_mac_success;
      out.tx_mac_fail = bucket->tx_mac_fail;
      out.tx_unknown = clamp(bucket->unknown_results);
      out.sdk_retries = bucket->sdk_retries;
      out.hop_accepts = clamp(bucket->hop_accepted);
      out.hop_timeouts = bucket->hop_timeouts;
      out.busy = clamp(bucket->busy_deferrals);
      // Queue EWMA is a current-window measurement like the driver EWMA —
      // only reported when the window contributed queue samples.
      if (bucket->current.queue_samples > 0 && bucket_fresh) {
        out.queue_us_ewma = bucket->current.queue_us_ewma;
      }
      // The driver-service EWMA is only fresh evidence when the CURRENT
      // window actually contributed a driver measurement — a lifetime
      // aggregate freshened by an unrelated observation would misreport
      // stale data as current (02 §2.4).
      if (bucket->current.driver_samples > 0 && bucket_fresh) {
        out.validity |= kTelemetryValidDriverEwma;
        out.driver_us_ewma = bucket->current.driver_us_ewma;
      }
      // Same window-freshness rule for the HOP_ACCEPT RTT EWMA (radio.md §8).
      if (bucket->current.hop_rtt_samples > 0 && bucket_fresh) {
        out.validity |= kTelemetryValidHopRttEwma;
        out.hop_rtt_us_ewma = bucket->current.hop_rtt_us_ewma;
      }
      out.saturation_mask |= bucket->saturation_mask;
      if (bucket->stale || !bucket_fresh) out.validity |= kTelemetryStale;
      if (bucket->current.incomplete) out.validity |= kTelemetryWindowIncomplete;
    }
    // No matching bucket is not an error: the summary stands alone with the
    // bucket-validity bit clear (04 §4.2 — never invent a zero measurement).
  }
  return Status::success();
}

// CapabilitiesReply (04 §capabilities): advertises only what is wired AND
// currently permitted — forward_v1 requires the live relay gate, not just
// build support; permit_profiles lists only profiles with a ready endpoint.
MeshNode::DiagBudget* MeshNode::diag_budget(const NodeId peer,
                                            const MonotonicMs now_ms) noexcept {
  DiagBudget* free_slot = nullptr;
  DiagBudget* reclaimable = nullptr;
  for (auto& entry : diag_budget_) {
    if (entry.peer == peer) {
      // Single window-reset point: every pacing counter tied to this
      // window resets together — callers only test/increment, never
      // re-check the elapsed condition (it is already consumed here).
      if (now_ms - entry.window_start_ms >= kDiagBudgetWindowMs) {
        entry.window_start_ms = now_ms;
        entry.window_used = 0;
        entry.failure_window_used = 0;
      }
      return &entry;
    }
    if (entry.peer == kInvalidNodeId) {
      if (free_slot == nullptr) free_slot = &entry;
      continue;
    }
    // A slot whose every pacing restriction has expired carries no live
    // state — reclaiming it is not eviction, it is reuse of an entry that
    // enforces nothing. This bounds residency without ever losing live
    // pacing history.
    const bool expired =
        now_ms - entry.window_start_ms >= kDiagBudgetWindowMs &&
        (entry.last_cap_reply_ms == 0 ||
         now_ms - entry.last_cap_reply_ms >= kCapReplyMinIntervalMs) &&
        (entry.last_query_ms == 0 ||
         now_ms - entry.last_query_ms >= kDiagQueryMinIntervalMs);
    if (expired &&
        (reclaimable == nullptr ||
         entry.window_start_ms < reclaimable->window_start_ms)) {
      reclaimable = &entry;
    }
  }
  // A full table NEVER evicts a live budget — eviction would silently
  // reset that peer's pacing state. nullptr is a refusal: callers drop and
  // count, they do not admit unbounded work.
  if (free_slot == nullptr) free_slot = reclaimable;
  if (free_slot == nullptr) return nullptr;
  *free_slot = DiagBudget{};
  free_slot->peer = peer;
  free_slot->window_start_ms = now_ms;
  return free_slot;
}

CapabilitiesReply MeshNode::build_capabilities_reply(
    const std::array<std::uint8_t, kCapabilitiesNonceSize>& echo_nonce)
    const noexcept {
  CapabilitiesReply reply{};
  reply.echo_nonce = echo_nonce;
  reply.node_boot = config_.boot_incarnation;
  reply.features = kCapLocalTelemetryV1 | kCapTransitFailureV1 | kCapBusyV1;
  // forward_v1 additionally requires the live relay gate (04 §capabilities).
  if (transit_permitted()) reply.features |= kCapForwardV1;
  if (telemetry_remote_) reply.features |= kCapRemoteTelemetryV1;
  // Only the configured+ready verifier's bit — never every compiled profile.
  if (config_sink_ != nullptr) {
    ExternalCallbackScope scope(in_external_callback_);
    reply.permit_profiles = config_sink_->permit_profile_bits();
  }
  reply.valid_for_ms = kCapabilitiesValidityMs;
  return reply;
}

void MeshNode::handle_diagnostic(const wire::PlainFrame& frame,
                                 const NodeId peer,
                                 const MonotonicMs now_ms) noexcept {
  const ByteView body{frame.payload.data(), frame.payload_size};
  // Subtype dispatch happens on the end-verified body only — a malformed or
  // unversioned body is a drop, never a fallthrough to a link-only parser.
  if (body.size < kDiagnosticPrefixSize || body.data[0] != kDiagnosticBodyVersion ||
      body.data[2] != 0 || body.data[3] != 0) {
    observer_.on_diagnostic("DIAGNOSTIC_BODY_REJECTED", peer,
                            &frame.header.message);
    return;
  }
  const auto subtype = static_cast<DiagnosticSubtype>(body.data[1]);
  const auto origin = frame.header.origin;
  const std::uint32_t lifetime_ms = frame.header.remaining_deadline_ms;

  auto reply_reject = [&](const DiagnosticRejectReason reason,
                          const std::uint32_t request_id) {
    DiagnosticReject reject{};
    reject.request_id = request_id;
    reject.reason = reason;
    reject.observer = config_.node;
    std::array<std::uint8_t, kDiagnosticRejectBodySize> out{};
    if (!diagnostic_reject_encode(reject,
                                  MutableByteView{out.data(), out.size()})) {
      return;
    }
    if (!queue_diagnostic_reply(origin, ByteView{out.data(), out.size()},
                                lifetime_ms, now_ms)) {
      // A reject that cannot be queued is a counted loss, never a spin.
      ++telemetry_event_drops_;
    }
  };

  switch (subtype) {
    case DiagnosticSubtype::TelemetryQuery: {
      TelemetryQuery query{};
      if (!telemetry_query_decode(body, query).ok()) {
        observer_.on_diagnostic("DIAGNOSTIC_QUERY_REJECTED", peer,
                                &frame.header.message);
        return;
      }
      // Bounded intake: at most one telemetry query per origin per
      // interval — a requester cannot convert authenticated queries into
      // airtime floods (telemetry §2.7; queries are costly: 644 B/edge).
      // Budget-table exhaustion refuses rather than admitting untracked
      // work.
      DiagBudget* const qbudget = diag_budget(origin, now_ms);
      if (qbudget == nullptr ||
          (qbudget->last_query_ms != 0 &&
           now_ms - qbudget->last_query_ms < kDiagQueryMinIntervalMs)) {
        ++telemetry_event_drops_;
        return;
      }
      qbudget->last_query_ms = now_ms;
      if (!telemetry_remote_) {
        reply_reject(DiagnosticRejectReason::Denied, query.request_id);
        return;
      }
      TelemetrySnapshot snapshot{};
      DiagnosticRejectReason reason{};
      if (!build_telemetry_snapshot_impl(query, now_ms, snapshot, reason)) {
        reply_reject(reason, query.request_id);
        return;
      }
      std::array<std::uint8_t, kTelemetrySnapshotBodySize> out{};
      if (!telemetry_snapshot_encode(snapshot,
                                     MutableByteView{out.data(), out.size()})) {
        ++telemetry_event_drops_;
        return;
      }
      if (!queue_diagnostic_reply(origin, ByteView{out.data(), out.size()},
                                  lifetime_ms, now_ms)) {
        ++telemetry_event_drops_;
      }
      return;
    }
    case DiagnosticSubtype::TelemetrySnapshot:
    case DiagnosticSubtype::DiagnosticReject:
      if (diagnostic_sink_ != nullptr) {
        ExternalCallbackScope scope(in_external_callback_);
        diagnostic_sink_->on_diagnostic_body(origin, body, now_ms);
      } else {
        observer_.on_diagnostic("DIAGNOSTIC_NO_ENDPOINT", peer,
                                &frame.header.message);
      }
      return;
    default:
      // Unknown/unsupported subtype on an authenticated body: honest reject
      // when a request_id is present, otherwise a counted drop (04 §4.2).
      if (body.size >= 8) {
        std::uint32_t request_id = 0;
        for (int i = 0; i < 4; ++i) {
          request_id = (request_id << 8U) | body.data[4 + i];
        }
        reply_reject(DiagnosticRejectReason::Unsupported, request_id);
      } else {
        ++telemetry_event_drops_;
      }
      return;
  }
}

void MeshNode::handle_diagnostic_link(const NodeId peer,
                                      const wire::LinkOpenedFrame& frame,
                                      const RxBinding& rx,
                                      const MonotonicMs now_ms) noexcept {
  // Link-only Diagnostic subtypes (CapabilitiesQuery/Reply, TransitFailure):
  // link-authenticated hop-1 traffic — surfaced to the sink for correlation,
  // never forwarded and never answered on a routed lane.
  const ByteView body{frame.protected_payload.data(),
                      frame.header.payload_length};
  if (body.size < kDiagnosticPrefixSize ||
      body.data[0] != kDiagnosticBodyVersion) {
    observer_.on_diagnostic("DIAGNOSTIC_BODY_REJECTED", peer,
                            &frame.header.message);
    return;
  }
  const auto subtype = static_cast<DiagnosticSubtype>(body.data[1]);
  if (subtype == DiagnosticSubtype::TransitFailure) {
    // Bounded intake (01 §evidence): a peer cannot convert reports into
    // unbounded dedup/seen-table scans — at most kTransitFailurePerWindow
    // decodable bodies per peer per second.
    DiagBudget* budget = diag_budget(peer, now_ms);
    if (budget == nullptr ||
        budget->failure_window_used >= kTransitFailurePerWindow) {
      ++telemetry_event_drops_;
      return;
    }
    TransitFailure report{};
    if (transit_failure_decode(body, report).ok()) {
      ++budget->failure_window_used;
      // Node-internal correlation/propagation first; the sink still sees
      // the body so a host can surface upstream failure evidence.
      handle_transit_failure_report(peer, report, now_ms);
      if (diagnostic_sink_ != nullptr) {
        ExternalCallbackScope scope(in_external_callback_);
        diagnostic_sink_->on_diagnostic_body(peer, body, now_ms);
      }
    } else {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("TRANSIT_FAILURE_REJECTED", peer,
                              &frame.header.message);
    }
    return;
  }
  if (subtype == DiagnosticSubtype::CapabilitiesQuery) {
    CapabilitiesQuery query{};
    if (!capabilities_query_decode(body, query).ok()) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_QUERY_REJECTED", peer,
                              &frame.header.message);
      return;
    }
    // Bounded reply pacing: one capability reply per peer per second —
    // a querier cannot convert link-only probes into airtime floods.
    DiagBudget* budget = diag_budget(peer, now_ms);
    // last_*_ms == 0 means "never used": the first query is always admitted
    // even when the node clock starts near zero. A full budget table
    // refuses — unbounded replies are never emitted.
    if (budget == nullptr || (budget->last_cap_reply_ms != 0 &&
        now_ms - budget->last_cap_reply_ms < kCapReplyMinIntervalMs)) {
      ++telemetry_event_drops_;
      return;
    }
    CapabilitiesReply reply = build_capabilities_reply(query.nonce);
    std::array<std::uint8_t, kCapabilitiesReplyBodySize> out{};
    if (!capabilities_reply_encode(reply,
                                   MutableByteView{out.data(), out.size()})) {
      ++telemetry_event_drops_;
      return;
    }
    TxJob job{};
    job.form = JobForm::Plain;
    job.owner = JobOwner::Diagnostic;
    job.peer = peer;
    job.requires_hop_accept = false;
    job.max_attempts = 1;
    job.deadline_ms = now_ms + kControlLifetimeMs;
    job.plain.header.type = FrameType::Diagnostic;
    job.plain.header.delivery = DeliveryClass::BestEffort;
    job.plain.header.hop_remaining = 1;
    job.plain.header.network = config_.network;
    job.plain.header.origin = config_.node;
    job.plain.header.destination = peer;
    job.plain.header.previous_hop = config_.node;
    job.plain.header.next_hop = peer;
    job.plain.header.message =
        MessageId{config_.message_session, next_control_sequence_++};
    job.plain.header.remaining_deadline_ms = kControlLifetimeMs;
    job.plain.header.original_lifetime_ms = kControlLifetimeMs;
    job.plain.header.link_epoch = config_.link_epoch;
    job.plain.header.end_epoch = config_.end_epoch;
    std::memcpy(job.plain.payload.data(), out.data(), out.size());
    job.plain.payload_size = out.size();
    // Link-local replies hold a short transaction on the receive's
    // evidence, like every other reply — unaffordable answers are counted
    // drops, and only an actually queued answer spends the rate budget.
    AdmissionReservation res{};
    if (!rx.valid ||
        !reserve_rx_reply(rx, /*needs_control_slot=*/false, 1, now_ms,
                          res)) {
      ++telemetry_event_drops_;
      return;
    }
    job.txn = res.txn;
    if (scheduler_.enqueue(std::move(job), config_.node, now_ms)) {
      join_txn(res.txn);
      res.committed = true;
      budget->last_cap_reply_ms = now_ms;
    } else {
      ++telemetry_event_drops_;
    }
    return;
  }
  if (subtype == DiagnosticSubtype::CapabilitiesReply) {
    CapabilitiesReply reply{};
    if (!capabilities_reply_decode(body, reply).ok()) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_REPLY_REJECTED", peer,
                              &frame.header.message);
      return;
    }
    // The reply must echo a nonce from OUR outstanding query to this peer
    // (04 §capabilities): unsolicited or stale replies never grant
    // capability. Consume the pending entry on match.
    auto* pending = std::find_if(
        pending_caps_.begin(), pending_caps_.end(),
        [&](const PendingCapQuery& p) {
          return p.peer == peer && p.expires_at_ms > now_ms &&
                 p.nonce == reply.echo_nonce;
        });
    if (pending == pending_caps_.end()) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_REPLY_UNSOLICITED", peer,
                              &frame.header.message);
      return;
    }
    // The reply must answer under the SAME binding generation the query
    // was issued in — a post-rebind reply is stale evidence. A summary
    // already marked stale proves the rebind happened; binding 0 recorded
    // at query time means no binding was known, so the reply's own
    // (fresh) binding establishes the baseline rather than violating it.
    const auto* summary = telemetry_peers_.find(peer);
    const bool summary_current = summary != nullptr && !summary->stale;
    const BindingGeneration current_binding =
        summary_current ? summary->binding : BindingGeneration{0};
    const bool binding_violated =
        summary != nullptr && summary->stale
            ? true  // stale summary = a rebind happened after the query
            : pending->binding != BindingGeneration{0} &&
                  current_binding != pending->binding;
    // Consuming a pending entry — matched or not — still paces renewal:
    // otherwise a rejected reply would permit an immediate reprobe storm.
    if (auto* neighbor = find_neighbor(peer)) {
      neighbor->last_cap_exchange_ms = now_ms;
    }
    *pending = PendingCapQuery{};
    if (binding_violated) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_REPLY_STALE_BINDING", peer,
                              &frame.header.message);
      return;
    }
    // A reply must name a concrete responder boot — node_boot==0 means the
    // peer never initialized an incarnation, so the grant cannot be bound
    // to any identity (04 §capabilities).
    if (reply.node_boot == 0) {
      ++telemetry_event_drops_;
      observer_.on_diagnostic("DIAGNOSTIC_CAP_REPLY_NO_BOOT", peer,
                              &frame.header.message);
      return;
    }
    // The grant is bounded by the reply's own valid_for_ms under the
    // responder's boot identity — clamped to the protocol's validity bound
    // so a reply cannot mint an unbounded grant, and valid_for_ms==0 is
    // an explicit no-grant rather than a silent default (04 §capabilities).
    if (auto* neighbor = find_neighbor(peer)) {
      const std::uint32_t grant_ms =
          reply.valid_for_ms < kCapabilitiesValidityMs
              ? reply.valid_for_ms
              : kCapabilitiesValidityMs;
      neighbor->cap_node_boot = reply.node_boot;
      neighbor->cap_valid_until_ms = grant_ms != 0 ? now_ms + grant_ms : 0;
      neighbor->last_cap_exchange_ms = now_ms;
      neighbor->busy_capable =
          grant_ms != 0 && (reply.features & kCapBusyV1) != 0;
    }
    if (diagnostic_sink_ != nullptr) {
      ExternalCallbackScope scope(in_external_callback_);
      diagnostic_sink_->on_diagnostic_body(peer, body, now_ms);
    }
    return;
  }
  // Routed subtypes (TelemetryQuery/Snapshot/Reject) on the link-only lane
  // are a protocol violation: they lack end protection and can never be
  // authenticated as their claimed origin. Never feed them to a sink that
  // would resolve pending end-authenticated queries (04 §4.2).
  ++telemetry_event_drops_;
  observer_.on_diagnostic("DIAGNOSTIC_LINK_SCOPE_VIOLATION", peer,
                          &frame.header.message);
}

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
  reemit.fingerprint = duplicate.fingerprint;
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
  report.fingerprint = entry->fingerprint;
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
      entry->fingerprint != report.fingerprint) {
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
  onward.fingerprint = entry->fingerprint;
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

// ---------------------------------------------------------------------------
// P3 load coupling (03-congestion.md §6, §7)
// ---------------------------------------------------------------------------

void MeshNode::reset_neighbor_measurement(Neighbor& neighbor) noexcept {
  neighbor.exchange_work = 0;
  neighbor.exchange_accepts = 0;
  neighbor.exchange_window_ms = 0;
  neighbor.queue_sojourn_ewma_ms = 0;
  neighbor.sojourn_samples = 0;
  neighbor.last_sojourn_ms = 0;
  neighbor.sojourn_window_ms = 0;
  neighbor.hop_rtt_ewma_ms = 0;
  neighbor.hop_rtt_samples = 0;
  neighbor.metric_window_dirty = false;
  neighbor.metric_sources = 0;
  neighbor.last_cost_relax_ms = 0;
  neighbor.link_cost = neighbor.metric;
}

void MeshNode::refresh_link_cost(Neighbor& neighbor, const MonotonicMs now_ms) noexcept {
  // §6.1 base cost: the measured exchange ratio against the nominal. The
  // measured cost is in units of exchanges (attempt count per authenticated
  // accept), never driver microseconds — driver service time may already
  // contain MAC retries, so using it would double-count ETX. Below the
  // minimum sample count the nominal stands (no measured reference is ever
  // invented). A dirty window (sdk-completion/03 §3.3 — some attempt resolved
  // Unknown) may still count work toward worsening but must never let the
  // measured ratio improve the base off nominal.
  RouteMetric base = neighbor.metric;
  if (neighbor.exchange_accepts >= kExchangeMinAccepts) {
    const RouteMetric measured = measured_link_base(
        neighbor.metric, neighbor.exchange_work, neighbor.exchange_accepts);
    if (!neighbor.metric_window_dirty || measured >= base) base = measured;
  }
  // §6.2 queue penalty: ONLY our egress sojourn toward this peer, smoothed
  // over the observation window. A stale or absent sample reads as 0 — a
  // quiet queue is not congestion. The peer's own queue delay lives inside
  // its advertised metric and is never re-added here.
  const std::uint32_t queue_ms =
      neighbor.last_sojourn_ms != 0 &&
              now_ms - neighbor.last_sojourn_ms <= kObservationWindowMs
          ? neighbor.queue_sojourn_ewma_ms
          : 0;
  // §3.4 refusal-pressure floor: a saturated scheduler stops producing
  // sojourn samples exactly when congestion is worst, so pool occupancy is
  // folded in as penalty steps — same cap, max() not + (one congestion
  // reading, counted once). The floor engages only while refusals are
  // actually observed (§3.3 evidence): occupancy alone still produces
  // sojourn samples, so a merely-full pool must not inflate the metric.
  const bool refusal_pressure = refusal_floor_active(
      scheduler_.occupancy_percent(), last_refusal_ms_, now_ms);
  const std::uint32_t steps_r =
      refusal_pressure ? refusal_penalty_steps(scheduler_.occupancy_percent())
                       : 0;
  const std::uint32_t multiple =
      queue_ms != 0 || steps_r != 0
          ? (queue_penalty_steps(queue_ms) > steps_r
                 ? queue_penalty_steps(queue_ms)
                 : steps_r)
          : 0;
  const RouteMetric target = penalized_cost(base, multiple);
  // §3.4 asymmetric slew: worsening applies immediately; improvement is
  // time-gated to one relax step per observation window and suppressed
  // while the window is dirty (incomplete evidence never improves a cost).
  RouteMetric cost = neighbor.link_cost;
  if (target >= cost) {
    cost = target;
  } else if (!neighbor.metric_window_dirty &&
             now_ms - neighbor.last_cost_relax_ms >= kLinkCostRelaxWindowMs) {
    cost = relax_link_cost(cost, target, base);
    neighbor.last_cost_relax_ms = now_ms;
  }
  if (cost != neighbor.link_cost) {
    neighbor.link_cost = cost;
    // Recompute stored candidates from their advertised metrics; never
    // extends a lease, never deletes FD (03 §6.3).
    routes_.update_link_cost(neighbor.node, cost, now_ms);
  }
}

Status MeshNode::note_peer_stale(const NodeId peer) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  telemetry_peers_.mark_stale(peer);
  if (Neighbor* neighbor = find_neighbor(peer)) {
    reset_neighbor_measurement(*neighbor);
  }
  return Status::success();
}

Status MeshNode::set_autonomy_sink(AutonomyFrameSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  autonomy_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_gateway_sink(GatewayServiceSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  if (component_target_pending(ComponentEventTarget::ServicePayload) ||
      component_target_pending(ComponentEventTarget::ServiceJobDone)) {
    return Status::error(StatusCode::Busy, "component events pending");
  }
  gateway_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_config_sink(ConfigEndpointSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  if (component_target_pending(ComponentEventTarget::ConfigFrame) ||
      component_target_pending(ComponentEventTarget::ConfigJobDone)) {
    return Status::error(StatusCode::Busy, "component events pending");
  }
  config_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_diagnostic_sink(DiagnosticSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  diagnostic_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_applied_sink(AppliedEndpointSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  applied_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_telemetry_remote(const bool enabled) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  telemetry_remote_ = enabled;
  return Status::success();
}

Status MeshNode::set_draining(const bool draining) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  sleep_draining_ = draining;
  return Status::success();
}

Status MeshNode::set_relay_enabled(const bool enabled) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  const bool was = relay_enabled_;
  relay_enabled_ = enabled;
  if (started_ && was && !enabled) {
    // Prompt withdrawal: retract every route we advertised before neighbors
    // send more transit we would only refuse (01 §policy drain).
    trigger_route_advertisement(last_clock_ms_);
  }
  return Status::success();
}

void MeshNode::refresh_neighbor_load(const MonotonicMs now_ms) noexcept {
  // §3.4 refusal-pressure evidence: the floor engages on observed refusals,
  // not occupancy alone — a full-but-flowing pool still produces sojourn
  // samples. Track the scheduler's rejection counter once per refresh.
  if (scheduler_.stats_.admissions_rejected != last_admission_rejections_) {
    last_admission_rejections_ = scheduler_.stats_.admissions_rejected;
    last_refusal_ms_ = now_ms;
  }
  neighbors_.for_each([&](Neighbor& neighbor) {
    if (!neighbor.active) return;
    // Decaying observation window (03 §3): halve the exchange counters per
    // elapsed window — a bounded aggregate, never raw samples. The elapsed
    // count is computed, not iterated: the subtraction is modulo-2^64, so a
    // backwards or jumping clock would otherwise read as ~2^63 elapsed
    // windows and a per-window loop could never return. A u32 halves to
    // zero within 32 shifts, so the count saturates; advancing the anchor
    // by the full elapsed span lands it just under `now_ms` and the next
    // window rolls normally.
    if (neighbor.exchange_window_ms != 0) {
      const std::uint64_t elapsed_windows =
          (now_ms - neighbor.exchange_window_ms) / kObservationWindowMs;
      if (elapsed_windows != 0) {
        if (elapsed_windows >= 32) {
          neighbor.exchange_work = 0;
          neighbor.exchange_accepts = 0;
        } else {
          neighbor.exchange_work >>= static_cast<unsigned>(elapsed_windows);
          neighbor.exchange_accepts >>= static_cast<unsigned>(elapsed_windows);
        }
        neighbor.exchange_window_ms += kObservationWindowMs * elapsed_windows;
        // Window roll clears the dirty flag (§3.3): a bounded suppression of
        // metric improvement, never a latch.
        neighbor.metric_window_dirty = false;
      }
    }
    // The sojourn EWMA decays on its own window anchor (§3.4): sparse fresh
    // samples must not keep re-exposing a stale-inflated average — a quiet
    // queue after a burst converges within a few windows, not minutes. Same
    // computed-roll collapse as the exchange window above.
    if (neighbor.sojourn_window_ms != 0) {
      const std::uint64_t elapsed_windows =
          (now_ms - neighbor.sojourn_window_ms) / kObservationWindowMs;
      if (elapsed_windows != 0) {
        if (elapsed_windows >= 32) {
          neighbor.queue_sojourn_ewma_ms = 0;
        } else {
          neighbor.queue_sojourn_ewma_ms >>=
              static_cast<unsigned>(elapsed_windows);
        }
        neighbor.sojourn_window_ms += kObservationWindowMs * elapsed_windows;
      }
    }
    // Feedback TTL (03 §3/§5): sustained-busy survives only on fresh
    // authenticated feedback; silence past the TTL releases it so an old
    // self-report cannot hold a route away.
    if (neighbor.busy_active &&
        now_ms - neighbor.last_busy_feedback_ms > kFeedbackTtlMs) {
      neighbor.busy_active = false;
      neighbor.busy_since_ms = 0;
    }
    if (neighbor.busy_active) {
      routes_.note_next_hop_busy(neighbor.node, neighbor.busy_since_ms);
    } else {
      routes_.clear_next_hop_busy(neighbor.node);
    }
    refresh_link_cost(neighbor, now_ms);
  });
  // Route-switch hysteresis (03 §7): pending improvements commit here once
  // their hold elapsed, and committed selections that lost validity repair
  // immediately — load never admits an infeasible route.
  routes_.evaluate(now_ms);
}

RouteMetric MeshNode::peer_link_cost(const NodeId peer) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  return neighbor == nullptr ? kInfiniteRouteMetric : neighbor->link_cost;
}

MonotonicMs MeshNode::peer_busy_since(const NodeId peer) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  // A peer busy since t=0 reports its sustain start as 1 so the accessor's
  // "0 = not busy" contract stays unambiguous for diagnostics/tests.
  return neighbor == nullptr || !neighbor->busy_active
             ? MonotonicMs{0}
             : std::max<MonotonicMs>(1, neighbor->busy_since_ms);
}

Status MeshNode::note_peer_pressure(const NodeId peer, const std::uint8_t pressure,
                                    const std::uint32_t feedback_sequence,
                                    const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || !neighbor->active) return Status::success();
  // Same ordering rule as BUSY (03 §5): a stale or replayed feedback
  // sequence must never re-arm pressure. Serial arithmetic matches
  // handle_busy so the shared sequence space wraps identically.
  if (neighbor->feedback_seen &&
      static_cast<std::int32_t>(feedback_sequence -
                                neighbor->last_feedback_seq) <= 0) {
    ++busy_stats_.busy_stale;
    return Status::success();
  }
  neighbor->feedback_seen = true;
  neighbor->last_feedback_seq = feedback_sequence;
  neighbor->last_pressure = pressure;
  if (pressure != 0) {
    // Pressure only sustains the busy/queue picture (severe-busy repair);
    // it is a hint from a single peer — never a metric term (03 §6.2).
    if (!neighbor->busy_active) {
      neighbor->busy_active = true;
      neighbor->busy_since_ms = now_ms;
    }
    neighbor->last_busy_feedback_ms = now_ms;
  }
  return Status::success();
}

CongestionStats MeshNode::congestion_stats() const noexcept {
  CongestionStats merged = busy_stats_;
  merged += scheduler_.stats_;
  merged += budget_stats_;
  merged.queued = scheduler_.size();
  merged.control_queued = scheduler_.control_depth();
  merged.flows_active = scheduler_.flows_active();
  return merged;
}

std::uint8_t MeshNode::peer_tx_window(const NodeId peer) const noexcept {
  return peer_window(peer);
}

Status MeshNode::set_peer_busy_capable(const NodeId peer, const bool capable) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (auto* neighbor = find_neighbor(peer)) {
    neighbor->busy_capable = capable;
    // A host/configured grant carries the same bounded validity as an
    // exchange-derived one — it is refreshed, never permanent.
    neighbor->cap_valid_until_ms =
        capable ? last_clock_ms_ + kCapabilitiesValidityMs : 0;
  }
  return Status::success();
}

bool MeshNode::peer_busy_capable(const NodeId peer,
                                 const MonotonicMs now_ms) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  return neighbor != nullptr && neighbor->busy_capable &&
         neighbor->cap_valid_until_ms > now_ms;
}

}  // namespace routeloom
