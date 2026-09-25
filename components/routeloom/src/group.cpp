// Group delivery along the gateway tree (docs/design/sdk-v1/group-delivery.md).
//
// A configured route gateway (gateway-scoped profile, routing-scale.md) seals
// a GROUP_DATA message once under SecurityScope::Group and hands one
// link-wrapped copy to every tree child (MAC-acknowledged unicast, bounded
// link retries — no HOP_ACCEPT). Every node opens it (dedup and ordering are
// decided on the header before that), delivers it when it is a member, and
// forwards the same copy to its own children. Confirmation flows back up the
// same tree: each node sends ONE GROUP_REPORT to its parent per round once
// every child reported, failed, or the nested report deadline passed —
// delivered / non-member / missing counts for its whole subtree plus a
// bounded list of missing ids. The source then re-sends the message only
// into subtrees that are still incomplete (repair rounds), within the
// message lifetime.
//
// The tree is the routing tree: children are the neighbors whose committed
// route to a gateway goes through this node (Neighbor::child_until_ms, the
// poison-reverse evidence of route_scale.cpp), and "a child's subtree" is
// the set of destinations whose committed next hop is that child. Nothing
// here feeds the route table: group state is scheduling state only.

#include <algorithm>
#include <cstring>

#include "routeloom/group.hpp"
#include "routeloom/node.hpp"

namespace routeloom {
namespace {

constexpr std::uint32_t kGroupReportLifetimeMs = 1000;
// Tree state outlives the message deadline by this much so a straggling
// repair round still finds it.
constexpr std::uint32_t kGroupTreeSlackMs = 2000;
// Report resends answering a same-round duplicate from the parent.
constexpr std::uint8_t kGroupReportResendMax = 2;
// §14 estimation model (radio.md §9, congestion.hpp): encoded bytes plus the
// fixed MAC/preamble/MAC-ACK byte equivalent at 32 us per byte (LR 250k).
constexpr std::uint32_t kAirtimeUsPerByte = 32;

void saturating_inc(std::uint64_t& counter) noexcept {
  if (counter != UINT64_MAX) ++counter;
}

std::uint16_t saturating_add16(const std::uint16_t a, const std::uint32_t b) noexcept {
  const std::uint32_t sum = static_cast<std::uint32_t>(a) + b;
  return static_cast<std::uint16_t>(std::min<std::uint32_t>(sum, UINT16_MAX));
}

std::uint32_t frame_airtime_us(const std::size_t encoded_bytes) noexcept {
  return static_cast<std::uint32_t>((encoded_bytes + kTxFrameFixedCostBytes) *
                                    kAirtimeUsPerByte);
}

// Encoded GROUP_REPORT with no missing ids: header + head + link tag.
constexpr std::size_t kGroupReportMinEncoded =
    wire::kHeaderSize + kGroupReportFixedBytes + kAeadTagSize;

}  // namespace

// --- Membership ---------------------------------------------------------------------

Status MeshNode::set_group_membership(const GroupId* groups,
                                      const std::size_t count) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (count > kGroupMembershipMax || (count > 0 && groups == nullptr)) {
    return Status::error(StatusCode::InvalidArgument, "GROUP_MEMBERSHIP_TOO_MANY");
  }
  for (std::size_t i = 0; i < count; ++i) {
    if (groups[i] == 0 || groups[i] == kGroupAll) {
      return Status::error(StatusCode::InvalidArgument, "GROUP_ID_RESERVED");
    }
    for (std::size_t j = 0; j < i; ++j) {
      if (groups[j] == groups[i]) {
        return Status::error(StatusCode::InvalidArgument, "GROUP_ID_DUPLICATE");
      }
    }
  }
  group_membership_.fill(0);
  for (std::size_t i = 0; i < count; ++i) group_membership_[i] = groups[i];
  group_membership_count_ = count;
  return Status::success();
}

bool MeshNode::group_member(const GroupId group) const noexcept {
  if (group == kGroupAll) return true;
  if (group == 0) return false;
  for (std::size_t i = 0; i < group_membership_count_; ++i) {
    if (group_membership_[i] == group) return true;
  }
  return false;
}

std::size_t MeshNode::group_membership(GroupId* out, const std::size_t capacity) const noexcept {
  const std::size_t n = std::min(capacity, group_membership_count_);
  for (std::size_t i = 0; i < n && out != nullptr; ++i) out[i] = group_membership_[i];
  return group_membership_count_;
}

// --- Lookup / allocation ------------------------------------------------------------

MeshNode::GroupOrigin* MeshNode::find_group_origin(const MessageId& id) noexcept {
  return group_origins_.find([&](const GroupOrigin& value) { return value.id == id; });
}

const MeshNode::GroupOrigin* MeshNode::find_group_origin(const MessageId& id) const noexcept {
  return group_origins_.find([&](const GroupOrigin& value) { return value.id == id; });
}

MeshNode::GroupOrigin* MeshNode::origin_of(const GroupTree& tree) noexcept {
  return group_origins_.find([&](const GroupOrigin& value) { return &value.tree == &tree; });
}

MeshNode::GroupTree* MeshNode::find_group_tree(const MessageKey& key) noexcept {
  if (key.origin == config_.node) {
    GroupOrigin* origin = find_group_origin(key.id);
    return origin != nullptr && origin->admitted ? &origin->tree : nullptr;
  }
  return group_trees_.find([&](const GroupTree& value) { return value.key == key; });
}

MeshNode::GroupTree* MeshNode::allocate_group_tree(const MonotonicMs now_ms) noexcept {
  if (GroupTree* fresh = group_trees_.allocate()) return fresh;
  // Full: reclaim in order expired -> settled (reported, every child
  // complete) -> reported-but-incomplete, oldest first. A tree still
  // collecting reports is never a victim.
  GroupTree* victim = nullptr;
  int victim_rank = 3;
  group_trees_.for_each([&](GroupTree& value) {
    int rank = 3;
    if (value.expires_at_ms <= now_ms) {
      rank = 0;
    } else if (!value.collecting && value.reported) {
      bool settled = true;
      for (std::size_t i = 0; i < value.child_count; ++i) {
        settled = settled && value.children[i].complete;
      }
      rank = settled ? 1 : 2;
    }
    if (rank < victim_rank ||
        (rank == victim_rank && victim != nullptr &&
         value.expires_at_ms < victim->expires_at_ms)) {
      victim = &value;
      victim_rank = rank;
    }
  });
  if (victim == nullptr || victim_rank >= 3) return nullptr;
  group_trees_.release(victim);
  return group_trees_.allocate();
}

// Read-only resolution of the stream a (source, session) frame maps to:
// the source's existing stream (its session current or newer), nullptr for
// a source with no stream yet or — with `stale` set — a session from the
// source's previous boot. Nothing is switched, drained or allocated here:
// a candidate commits only after the frame authenticates (issue #106).
MeshNode::GroupStream* MeshNode::group_stream_candidate(const NodeId source,
                                                      const std::uint32_t session,
                                                      bool& stale) noexcept {
  stale = false;
  GroupStream* stream =
      group_streams_.find([&](const GroupStream& value) { return value.source == source; });
  if (stream != nullptr && session < stream->session) {
    stale = true;
    return nullptr;
  }
  return stream;
}

// Commits the candidate after Group end authentication. A newer session
// means the source rebooted: its stream restarts, and messages still held
// from the old session are handed over now, in order — they can never be
// completed by the old session any more. A new source takes a fresh slot.
MeshNode::GroupStream* MeshNode::group_stream_commit(GroupStream* candidate,
                                                   const NodeId source,
                                                   const std::uint32_t session) noexcept {
  if (candidate != nullptr) {
    if (session <= candidate->session) return candidate;  // same or older: nothing to commit
    group_skip_to(*candidate, candidate->max_seq + 1U);
    candidate->session = session;
    candidate->max_seq = 0;
    candidate->seen = 0;
    candidate->next_seq = 0;
    return candidate;
  }
  GroupStream* stream = group_streams_.allocate();
  if (stream == nullptr) return nullptr;
  stream->source = source;
  stream->session = session;
  return stream;
}

bool MeshNode::group_seen(const GroupStream& stream, const std::uint32_t seq) noexcept {
  if (stream.max_seq == 0 || seq > stream.max_seq) return false;
  const std::uint32_t distance = stream.max_seq - seq;
  return distance < kGroupSeenWindow && ((stream.seen >> distance) & 1ULL) != 0;
}

void MeshNode::group_mark_seen(GroupStream& stream, const std::uint32_t seq) noexcept {
  if (stream.max_seq == 0) {
    stream.max_seq = seq;
    stream.seen = 1;
    return;
  }
  if (seq > stream.max_seq) {
    const std::uint32_t shift = seq - stream.max_seq;
    stream.seen = shift >= kGroupSeenWindow ? 0 : (stream.seen << shift);
    stream.seen |= 1ULL;
    stream.max_seq = seq;
    return;
  }
  const std::uint32_t distance = stream.max_seq - seq;
  if (distance < kGroupSeenWindow) stream.seen |= 1ULL << distance;
}

// --- Source API ---------------------------------------------------------------------

Status MeshNode::send_group(const GroupId group, const ByteView payload,
                            const GroupSendOptions& options, const MonotonicMs now_ms,
                            MessageId& id) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  last_clock_ms_ = now_ms;
  if (!started_) return Status::error(StatusCode::InvalidState, "node is not started");
  ++work_generation_;
  if (paused(pause::kAppAdmission)) {
    return Status::error(StatusCode::InvalidState,
                         sleep_draining_ ? "NODE_DRAINING" : "NODE_PAUSED");
  }
  // Group delivery rides the gateway tree: only a configured route gateway
  // of the gateway-scoped profile has one (group-delivery.md §4). The flat
  // profile has no tree and would degrade to a flood — explicitly refused.
  if (!gateway_scoped()) {
    return Status::error(StatusCode::Unsupported, "GROUP_REQUIRES_GATEWAY_SCOPED");
  }
  if (!is_route_gateway(config_.node)) {
    return Status::error(StatusCode::Unsupported, "GROUP_SOURCE_NOT_GATEWAY");
  }
  if (group == 0 || payload.size > kGroupPayloadMax ||
      (payload.size > 0 && payload.data == nullptr) || options.lifetime_ms == 0 ||
      options.lifetime_ms > kMaxMessageLifetimeMs || options.hop_limit == 0 ||
      options.hop_limit == UINT8_MAX ||
      static_cast<std::uint8_t>(options.priority) >
          static_cast<std::uint8_t>(Priority::Urgent)) {
    return Status::error(StatusCode::InvalidArgument, "invalid group send");
  }
  if (next_group_seq_ == 0) {
    return Status::error(StatusCode::CounterExhausted, "GROUP_STREAM_EXHAUSTED");
  }
  // Source table: Normal traffic keeps one slot free for an Urgent alarm;
  // terminal records are history and are reclaimed oldest first.
  std::size_t active = 0;
  group_origins_.for_each([&](const GroupOrigin& value) {
    if (!sleep_terminal(value.state)) ++active;
  });
  const bool urgent = options.priority == Priority::Urgent;
  if (active >= kGroupOriginCapacity || (!urgent && active + 1 >= kGroupOriginCapacity)) {
    return Status::error(StatusCode::WouldBlock, "GROUP_QUEUE_FULL");
  }
  GroupOrigin* origin = group_origins_.allocate();
  if (origin == nullptr) {
    GroupOrigin* oldest = nullptr;
    group_origins_.for_each([&](GroupOrigin& value) {
      if (sleep_terminal(value.state) &&
          (oldest == nullptr || value.created_at_ms < oldest->created_at_ms)) {
        oldest = &value;
      }
    });
    if (oldest == nullptr) {
      return Status::error(StatusCode::WouldBlock, "GROUP_QUEUE_FULL");
    }
    group_origins_.release(oldest);
    origin = group_origins_.allocate();
    if (origin == nullptr) {
      return Status::error(StatusCode::WouldBlock, "GROUP_QUEUE_FULL");
    }
  }

  const std::uint32_t seq = next_group_seq_;
  const MessageId message{config_.message_session, kGroupSequenceFlag | seq};
  wire::PlainFrame plain{};
  plain.header.type = FrameType::GroupData;
  plain.header.flags = wire::kFlagEndProtected;
  plain.header.delivery = DeliveryClass::Reliable;
  plain.header.delivery_round = 0;
  plain.header.hop_remaining = options.hop_limit;
  plain.header.network = config_.network;
  plain.header.origin = config_.node;
  plain.header.destination = group_address(group);
  plain.header.previous_hop = config_.node;
  plain.header.next_hop = config_.node;
  plain.header.message = message;
  plain.header.remaining_deadline_ms = options.lifetime_ms;
  plain.header.original_lifetime_ms = options.lifetime_ms;
  plain.header.link_epoch = config_.link_epoch;
  plain.header.end_epoch = config_.end_epoch;
  GroupDataHeader head{};
  head.ordered = options.ordered;
  head.priority = options.priority;
  auto status = encode_group_data(head, payload,
                                  MutableByteView{plain.payload.data(), plain.payload.size()},
                                  plain.payload_size);
  if (status) status = wire::seal_group(plain, config_.node, security_, origin->sealed);
  if (!status) {
    group_origins_.release(origin);
    return status;
  }
  ++next_group_seq_;
  origin->id = message;
  origin->group = group;
  origin->priority = options.priority;
  origin->state = DeliveryState::Queued;
  origin->reason = "GROUP_QUEUED";
  origin->created_at_ms = now_ms;
  origin->expires_at_ms = now_ms + options.lifetime_ms;
  origin->group_seq = seq;
  // Estimated air time per reached node: its data copy + its report.
  const std::size_t data_encoded = wire::kHeaderSize + plain.payload_size + 2 * kAeadTagSize;
  origin->node_cost_us =
      frame_airtime_us(data_encoded) + frame_airtime_us(kGroupReportMinEncoded);
  origin->tree.key = MessageKey{config_.node, message};
  origin->tree.group = group;
  origin->tree.parent = config_.node;
  origin->tree.priority = options.priority;
  origin->tree.origin = true;
  origin->summary.id = message;
  origin->summary.group = group;
  origin->summary.state = DeliveryState::Queued;
  origin->summary.reason = origin->reason;
  id = message;
  saturating_inc(group_stats_.sent);
  // Messages far behind the new stream number are retired so no receiver's
  // duplicate window can be outrun by a straggling repair round.
  group_origins_.for_each([&](GroupOrigin& value) {
    if (&value != origin && !sleep_terminal(value.state) &&
        value.group_seq + kGroupStaleSeqs <= seq) {
      group_origin_terminal(value, DeliveryState::Failed, "GROUP_SUPERSEDED");
    }
  });
  // Admitted copies leave on the next poll's dispatch, like every send().
  group_admit(now_ms);
  return Status::success();
}

GroupDeliveryResult MeshNode::group_delivery(const MessageId& id) const noexcept {
  const GroupOrigin* origin = find_group_origin(id);
  if (origin == nullptr) {
    GroupDeliveryResult missing{};
    missing.id = id;
    missing.reason = "NOT_FOUND";
    return missing;
  }
  return origin->summary;
}

// --- Budget -------------------------------------------------------------------------

std::int64_t MeshNode::group_budget_balance(const MonotonicMs now_ms) noexcept {
  if (now_ms > group_budget_last_ms_) {
    const std::uint64_t elapsed = now_ms - group_budget_last_ms_;
    group_budget_last_ms_ = now_ms;
    const std::int64_t refill = static_cast<std::int64_t>(
        std::min<std::uint64_t>(elapsed * config_.group_airtime_us_per_s / 1000ULL,
                                static_cast<std::uint64_t>(kGroupBudgetCapacityUs) * 2ULL));
    group_budget_tokens_us_ = std::min(group_budget_tokens_us_ + refill, kGroupBudgetCapacityUs);
  }
  return group_budget_tokens_us_;
}

std::uint16_t MeshNode::group_expected_nodes() const noexcept {
  // Destinations the source's route table reaches through a neighbor: every
  // one of them is some tree child's subtree member (routing-scale.md §3).
  std::uint32_t count = 0;
  routes_.for_each_selected([&](const RouteSelection& selection) {
    if (!selection.valid || selection.destination == config_.node ||
        is_route_gateway(selection.destination) ||
        reserved_node_id(selection.destination)) {
      return;
    }
    const Neighbor* next = find_neighbor(selection.next_hop);
    if (next != nullptr && next->active) ++count;
  });
  return static_cast<std::uint16_t>(std::min<std::uint32_t>(count, UINT16_MAX));
}

void MeshNode::group_admit(const MonotonicMs now_ms) noexcept {
  if (paused(pause::kRetryRounds)) return;
  // One round-0 propagation at a time (Urgent excepted): a burst queues at
  // the source instead of stacking copies in every relay's TX pool.
  bool in_flight = false;
  group_origins_.for_each([&](const GroupOrigin& value) {
    if (value.admitted && value.tree.round == 0 && value.tree.collecting &&
        value.priority != Priority::Urgent) {
      in_flight = true;
    }
  });
  while (true) {
    GroupOrigin* next = nullptr;
    group_origins_.for_each([&](GroupOrigin& value) {
      if (value.admitted || value.state != DeliveryState::Queued) return;
      if (value.priority != Priority::Urgent && in_flight) return;
      const bool better =
          next == nullptr ||
          (value.priority == Priority::Urgent && next->priority != Priority::Urgent) ||
          ((value.priority == Priority::Urgent) == (next->priority == Priority::Urgent) &&
           value.group_seq < next->group_seq);
      if (better) next = &value;
    });
    if (next == nullptr) return;
    const std::uint16_t known = group_expected_nodes();
    const std::uint16_t expected = std::max<std::uint16_t>(1, known);
    const std::int64_t cost = static_cast<std::int64_t>(expected) * next->node_cost_us;
    if (next->priority != Priority::Urgent && config_.group_airtime_us_per_s != 0 &&
        group_budget_balance(now_ms) < std::min(cost, kGroupBudgetCapacityUs)) {
      // Waits for tokens; the lifetime keeps running (an unsent message
      // expires as GROUP_NOT_SENT). Counted once per message.
      if (!next->budget_waiting) {
        next->budget_waiting = true;
        saturating_inc(group_stats_.budget_deferrals);
        next->reason = "GROUP_BUDGET_WAIT";
        next->summary.reason = next->reason;
      }
      return;
    }
    (void)group_budget_balance(now_ms);
    group_budget_tokens_us_ -= cost;
    // Urgent may run the bucket into debt, but never unboundedly.
    group_budget_tokens_us_ = std::max(group_budget_tokens_us_, -kGroupBudgetCapacityUs);
    next->admitted = true;
    next->budget_waiting = false;
    next->expected_nodes = known;
    next->state = DeliveryState::WaitingForEndReceipt;
    next->reason = "GROUP_ROUND_PENDING";
    next->summary.state = next->state;
    next->summary.reason = next->reason;
    next->sealed.header.delivery_round = 0;
    next->sealed.header.remaining_deadline_ms =
        static_cast<std::uint32_t>(next->expires_at_ms > now_ms ? next->expires_at_ms - now_ms : 0);
    next->tree.expires_at_ms = next->expires_at_ms;
    saturating_inc(group_stats_.rounds_started);
    if (next->priority != Priority::Urgent) in_flight = true;
    group_begin_round(next->tree, next->sealed, config_.node, true, now_ms);
  }
}

// --- Tree rounds --------------------------------------------------------------------

std::uint16_t MeshNode::group_routed_subtree(const NodeId child, NodeId* ids,
                                             const std::size_t capacity,
                                             std::uint8_t& count) const noexcept {
  std::uint32_t total = 0;
  routes_.for_each_selected([&](const RouteSelection& selection) {
    if (!selection.valid || selection.next_hop != child || selection.destination == child ||
        selection.destination == config_.node || is_route_gateway(selection.destination) ||
        reserved_node_id(selection.destination)) {
      return;
    }
    ++total;
    if (ids != nullptr && count < capacity) ids[count++] = selection.destination;
  });
  return static_cast<std::uint16_t>(std::min<std::uint32_t>(total, UINT16_MAX));
}

bool MeshNode::queue_group_copy(const wire::LinkOpenedFrame& frame, const GroupTree& tree,
                                const NodeId child, const MonotonicMs now_ms) noexcept {
  TxJob job{};
  job.set_forwarded(frame);
  job.owner = JobOwner::Group;
  job.peer = child;
  // Per-hop reliability is the MAC acknowledgement plus bounded link
  // retries; the report is the end-to-end evidence (group-delivery.md §4).
  job.requires_hop_accept = false;
  job.max_attempts = config_.max_link_attempts;
  const std::uint32_t remaining =
      tree.origin ? frame.header.remaining_deadline_ms
                  : (frame.header.remaining_deadline_ms > rx_age_ms_
                         ? frame.header.remaining_deadline_ms - rx_age_ms_
                         : 0);
  if (remaining == 0) return false;
  job.deadline_ms = now_ms + remaining;
  job.ack = AckKey{FrameType::GroupData, tree.key,
                   static_cast<std::uint8_t>(frame.header.delivery_round & kGroupRoundMask)};
  job.priority = tree.priority;
  if (!scheduler_.enqueue(std::move(job), config_.node, now_ms)) return false;
  saturating_inc(group_stats_.copies_queued);
  return true;
}

void MeshNode::group_begin_round(GroupTree& tree, const wire::LinkOpenedFrame& frame,
                                 const NodeId parent, const bool force_all,
                                 const MonotonicMs now_ms) noexcept {
  tree.parent = parent;
  tree.round = static_cast<std::uint8_t>(frame.header.delivery_round & kGroupRoundMask);
  tree.collecting = true;
  tree.reported = false;
  tree.report_resends = 0;
  tree.missing_count = 0;
  tree.extra_missing = 0;
  tree.missing.fill(kInvalidNodeId);

  // Refresh the child set from the routing tree: drop entries that are no
  // longer children (their subtree is someone else's now), add new ones.
  std::size_t kept = 0;
  for (std::size_t i = 0; i < tree.child_count; ++i) {
    const GroupChild& entry = tree.children[i];
    if (entry.node != parent && entry.node != tree.key.origin &&
        neighbor_is_child(entry.node, now_ms)) {
      tree.children[kept++] = entry;
    }
  }
  for (std::size_t i = kept; i < tree.children.size(); ++i) tree.children[i] = GroupChild{};
  tree.child_count = static_cast<std::uint8_t>(kept);
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (!neighbor.active || neighbor.node == parent || neighbor.node == tree.key.origin ||
        !neighbor_is_child(neighbor.node, now_ms)) {
      return;
    }
    for (std::size_t i = 0; i < tree.child_count; ++i) {
      if (tree.children[i].node == neighbor.node) return;
    }
    if (tree.child_count < tree.children.size()) {
      tree.children[tree.child_count++].node = neighbor.node;
      return;
    }
    // More children than tracked: their subtrees are reported missing (with
    // ids) so the source sees the gap — never silently dropped.
    std::uint8_t count = tree.missing_count;
    if (count < tree.missing.size()) tree.missing[count++] = neighbor.node;
    const std::uint16_t below =
        group_routed_subtree(neighbor.node, tree.missing.data(), tree.missing.size(), count);
    tree.missing_count = count;
    tree.extra_missing = saturating_add16(tree.extra_missing, 1U + below);
    observer_.on_diagnostic("GROUP_CHILD_CAPACITY", neighbor.node, &tree.key.id);
  });

  // Forward the round copy to every child whose subtree is not known to be
  // complete. A relay that may not transit, or a copy whose hop budget is
  // spent, forwards nothing — those children are then reported missing.
  const bool can_forward =
      frame.header.hop_remaining > 1 && (tree.origin || transit_permitted());
  bool any_sent = false;
  for (std::size_t i = 0; i < tree.child_count; ++i) {
    GroupChild& entry = tree.children[i];
    entry.sent = false;
    entry.reported = false;
    entry.failed = false;
    if (force_all) entry.complete = false;
    if (entry.complete && !entry.not_child) {
      // A complete subtree whose size no longer matches what our routes
      // put behind the child has changed shape (nodes moved between
      // subtrees): its stored counts are stale, so it is asked again. This
      // keeps the per-subtree sums honest under tree churn.
      std::uint8_t none = 0;
      const std::uint32_t routed =
          1U + group_routed_subtree(entry.node, nullptr, 0, none);
      const std::uint32_t accounted =
          static_cast<std::uint32_t>(entry.delivered) + entry.nonmember + entry.missing;
      if (routed != accounted) entry.complete = false;
    }
    if (entry.complete || !can_forward) continue;
    if (queue_group_copy(frame, tree, entry.node, now_ms)) {
      entry.sent = true;
      any_sent = true;
    }
  }
  // Nested report deadline: children received hop_remaining - 1 and wait
  // that many levels minus one for their own subtree.
  const std::uint32_t levels =
      std::max<std::uint32_t>(1, static_cast<std::uint32_t>(frame.header.hop_remaining) - 1U);
  tree.deadline_ms = now_ms + static_cast<MonotonicMs>(levels) * kGroupLevelWaitMs;
  if (!any_sent) group_finalize(tree, now_ms);
}

bool MeshNode::group_round_resolved(const GroupTree& tree) const noexcept {
  for (std::size_t i = 0; i < tree.child_count; ++i) {
    const GroupChild& entry = tree.children[i];
    if (entry.sent && !entry.reported && !entry.failed) return false;
  }
  return true;
}

void MeshNode::group_build_report(const GroupTree& tree,
                                  GroupReportPayload& out) const noexcept {
  out = GroupReportPayload{};
  out.key = tree.key;
  out.round = tree.round;
  std::uint32_t delivered = tree.self_delivered ? 1U : 0U;
  std::uint32_t nonmember = tree.self_nonmember ? 1U : 0U;
  std::uint32_t missing = tree.extra_missing;
  std::uint8_t count = std::min<std::uint8_t>(tree.missing_count,
                                              static_cast<std::uint8_t>(out.missing.size()));
  for (std::size_t i = 0; i < count; ++i) out.missing[i] = tree.missing[i];
  for (std::size_t i = 0; i < tree.child_count; ++i) {
    const GroupChild& entry = tree.children[i];
    const bool fresh = entry.reported || (!entry.sent && entry.complete);
    if (fresh || entry.ever_reported) {
      // This round's report, a subtree already complete, or — for a child
      // that went silent this round — the last thing it told us (its ids
      // are not retained: the list is then marked truncated).
      delivered += entry.delivered;
      nonmember += entry.nonmember;
      missing += entry.missing;
      continue;
    }
    // Never reported: the child and everything routed through it.
    if (count < out.missing.size()) out.missing[count++] = entry.node;
    missing += 1U + group_routed_subtree(entry.node, out.missing.data(), out.missing.size(),
                                         count);
  }
  out.delivered = static_cast<std::uint16_t>(std::min<std::uint32_t>(delivered, UINT16_MAX));
  out.nonmember = static_cast<std::uint16_t>(std::min<std::uint32_t>(nonmember, UINT16_MAX));
  out.missing_total = static_cast<std::uint16_t>(std::min<std::uint32_t>(missing, UINT16_MAX));
  out.missing_count = std::min<std::uint8_t>(count, static_cast<std::uint8_t>(
                                                        std::min<std::uint32_t>(
                                                            out.missing_total, UINT8_MAX)));
  if (out.missing_total > out.missing_count) out.flags |= kGroupReportTruncated;
}

void MeshNode::group_finalize(GroupTree& tree, const MonotonicMs now_ms) noexcept {
  tree.collecting = false;
  if (tree.origin) {
    if (GroupOrigin* origin = origin_of(tree)) group_origin_round_done(*origin, now_ms);
    return;
  }
  GroupReportPayload report{};
  group_build_report(tree, report);
  if (queue_group_report(tree.parent, report, tree.priority, now_ms)) {
    saturating_inc(group_stats_.reports_sent);
  }
  tree.reported = true;
}

Status MeshNode::queue_group_report(const NodeId to, const GroupReportPayload& report,
                                    const Priority priority,
                                    const MonotonicMs now_ms) noexcept {
  if (to == kInvalidNodeId || to == config_.node) {
    return Status::error(StatusCode::InvalidArgument, "group report target");
  }
  TxJob job = link_control_job(FrameType::GroupReport, to, kGroupReportLifetimeMs, now_ms);
  job.owner = JobOwner::Group;
  job.max_attempts = config_.max_link_attempts;
  job.priority = priority;
  job.ack = AckKey{FrameType::GroupReport, report.key, report.round};
  auto status = encode_group_report(
      report, MutableByteView{job.plain.payload.data(), job.plain.payload.size()},
      job.plain.payload_size);
  if (!status) return status;
  return scheduler_.enqueue(std::move(job), config_.node, now_ms);
}

void MeshNode::group_origin_round_done(GroupOrigin& origin, const MonotonicMs now_ms) noexcept {
  GroupReportPayload aggregate{};
  group_build_report(origin.tree, aggregate);
  GroupDeliveryResult& summary = origin.summary;
  summary.rounds = static_cast<std::uint8_t>(origin.tree.round + 1U);
  summary.delivered = aggregate.delivered;
  summary.nonmember = aggregate.nonmember;
  summary.missing_total = aggregate.missing_total;
  summary.missing_count = aggregate.missing_count;
  summary.missing_truncated = (aggregate.flags & kGroupReportTruncated) != 0;
  summary.missing = aggregate.missing;
  const std::uint32_t accounted = static_cast<std::uint32_t>(aggregate.delivered) +
                                  aggregate.nonmember + aggregate.missing_total;
  origin.expected_nodes = std::max(origin.expected_nodes, group_expected_nodes());
  const std::uint16_t expected = origin.expected_nodes;
  summary.unaccounted =
      static_cast<std::uint16_t>(expected > accounted ? expected - accounted : 0U);
  // More accounted than the source has ever known: some subtree still
  // counts a node that moved elsewhere (stale per-child counts under tree
  // churn). Never reported as complete — the next round refreshes the tree.
  const bool overcounted = accounted > expected;
  if (accounted == 0 && expected == 0) {
    group_origin_terminal(origin, DeliveryState::Failed, "GROUP_NO_TREE");
    return;
  }
  if (summary.missing_total == 0 && summary.unaccounted == 0 && !overcounted) {
    group_origin_terminal(origin, DeliveryState::Delivered, "GROUP_COMPLETE");
    return;
  }
  const bool rounds_left = origin.tree.round + 1U < kGroupMaxRounds;
  if (rounds_left && now_ms + kGroupRepairGapMs < origin.expires_at_ms) {
    // Repair: the next round re-sends only into incomplete subtrees. When
    // the counts do not add up to the nodes the source knows (a node no
    // report accounted for, or one counted twice after moving between
    // subtrees), stored per-child counts cannot be trusted: that round is
    // a REFRESH round and every relay re-asks every child.
    origin.next_round_at_ms = now_ms + kGroupRepairGapMs;
    origin.force_all = summary.unaccounted != 0 || overcounted;
    origin.reason = "GROUP_REPAIR_PENDING";
    summary.state = origin.state;
    summary.reason = origin.reason;
    observer_.on_group_delivery(summary);
    return;
  }
  group_origin_terminal(origin, DeliveryState::Failed, "GROUP_INCOMPLETE");
}

void MeshNode::group_origin_terminal(GroupOrigin& origin, const DeliveryState state,
                                     const char* reason) noexcept {
  origin.state = state;
  origin.reason = reason;
  origin.tree.collecting = false;
  origin.summary.state = state;
  origin.summary.reason = reason;
  observer_.on_group_delivery(origin.summary);
}

// --- Receive path -------------------------------------------------------------------

void MeshNode::handle_group_data(const wire::LinkOpenedFrame& frame, const NodeId peer,
                                 const MonotonicMs now_ms) noexcept {
  const wire::Header& header = frame.header;
  if (!gateway_scoped()) {
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic("GROUP_REQUIRES_GATEWAY_SCOPED", peer, &header.message);
    return;
  }
  // Only a configured gateway sources group traffic (the tree is rooted at
  // it); the group stream number rides the authenticated MessageId.
  if ((header.flags & wire::kFlagEndProtected) == 0 ||
      !is_group_address(header.destination) || !is_route_gateway(header.origin) ||
      header.origin == config_.node || !is_group_sequence(header.message.sequence) ||
      header.delivery != DeliveryClass::Reliable) {
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic("GROUP_FRAME_REJECTED", peer, &header.message);
    return;
  }
  // A cached tree or seen bit is not evidence that a retired GK is still
  // authorized. Check before either short-circuit can forward a repair.
  if (!security_.accepts_group_epoch(header.end_epoch)) {
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic("GROUP_KEY_RETIRED", peer, &header.message);
    return;
  }
  if (security_.revoked_group_sender(header.origin) ||
      security_.revoked_group_sender(header.previous_hop)) {
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic("GROUP_SENDER_REVOKED", peer, &header.message);
    return;
  }
  const MessageKey key{header.origin, header.message};
  const std::uint8_t round = static_cast<std::uint8_t>(header.delivery_round & kGroupRoundMask);
  const bool refresh = (header.delivery_round & kGroupRoundRefresh) != 0;
  // Resolve the stream candidate read-only: a newer session or a new
  // source commits — session switch, held-message drain, dedup window —
  // only after the Group end layer and the payload authenticate (issue
  // #106). A stale session is the source's previous boot and is refused
  // outright; a new source is refused when no stream slot is free.
  bool stale = false;
  GroupStream* stream = group_stream_candidate(header.origin, header.message.session, stale);
  if (stale || (stream == nullptr && group_streams_.size() >= group_streams_.capacity())) {
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic(stale ? "GROUP_STALE_SESSION" : "GROUP_STREAM_CAPACITY", peer,
                            &header.message);
    return;
  }
  const std::uint32_t seq = group_stream_seq(header.message.sequence);

  if (GroupTree* tree = find_group_tree(key)) {
    saturating_inc(group_stats_.duplicates);
    if (round > tree->round) {
      // A repair round (possibly from a new parent after a tree change):
      // follow its sender and forward into our incomplete subtrees.
      tree->expires_at_ms = std::max(
          tree->expires_at_ms, now_ms + header.remaining_deadline_ms + kGroupTreeSlackMs);
      group_begin_round(*tree, frame, peer, refresh, now_ms);
      return;
    }
    GroupReportPayload report{};
    if (peer != tree->parent) {
      // Someone else also treats us as its child: we follow the first
      // sender of this round, so this one must not count us (no double
      // counting when child flags lag a parent change).
      report.key = key;
      report.round = round;
      report.flags = kGroupReportNotChild;
      if (queue_group_report(peer, report, tree->priority, now_ms)) {
        saturating_inc(group_stats_.not_child_sent);
      }
      return;
    }
    if (round == tree->round && tree->reported &&
        tree->report_resends < kGroupReportResendMax) {
      ++tree->report_resends;
      group_build_report(*tree, report);
      if (queue_group_report(peer, report, tree->priority, now_ms)) {
        saturating_inc(group_stats_.reports_sent);
      }
    }
    return;
  }

  // A candidate session — a new source, or the source's newer boot — has
  // no committed dedup state to test (the commit below resets it), so its
  // copy always opens. For the committed session, anything the duplicate
  // window can no longer tell apart is dropped, never re-delivered.
  const bool new_session = stream == nullptr || header.message.session != stream->session;
  if (!new_session && stream->max_seq != 0 && seq + kGroupSeenWindow <= stream->max_seq) {
    // Older than the duplicate window: whether it was delivered can no
    // longer be told — dropped, never re-delivered.
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic("GROUP_TOO_OLD", peer, &header.message);
    return;
  }
  const GroupId group = group_of_address(header.destination);
  const bool member = group_member(group);
  Priority priority = Priority::Normal;
  if (!new_session && group_seen(*stream, seq)) {
    // Received before, tree state since reclaimed: rebuild it without
    // opening or delivering again (exactly once).
    saturating_inc(group_stats_.duplicates);
  } else {
    wire::PlainFrame plain{};
    const auto status = wire::open_group(frame, security_, plain);
    if (!status) {
      if (status.code == StatusCode::Busy && security_.group_promotion_pending()) {
        // The frame authenticated under the staged next GK but the
        // durable promote is still outstanding: hold the sealed bytes
        // (one slot) and retry after the Owner's promote instead of
        // dropping onto the repair round. Nothing was committed above,
        // so the retry is a clean re-entry.
        if (!group_promote_hold_.used) {
          group_promote_hold_.used = true;
          group_promote_hold_.frame = frame;
          group_promote_hold_.peer = peer;
          group_promote_hold_.held_at_ms = now_ms;
          saturating_inc(group_stats_.promote_holds);
          return;
        }
        saturating_inc(group_stats_.promote_drops);
      }
      saturating_inc(group_stats_.open_failures);
      note_rx_refusal(status, peer, &header.message);
      return;
    }
    GroupDataHeader head{};
    ByteView app{};
    const auto parsed =
        decode_group_data(ByteView{plain.payload.data(), plain.payload_size}, head, app);
    if (!parsed) {
      saturating_inc(group_stats_.rejected);
      observer_.on_diagnostic(parsed.detail, peer, &header.message);
      return;
    }
    priority = head.priority;
    // Authenticated and well-formed: the candidate commits now — a newer
    // session restarts the stream, a new source takes its slot.
    stream = group_stream_commit(stream, header.origin, header.message.session);
    if (stream == nullptr) {  // defensive: capacity was checked above
      saturating_inc(group_stats_.rejected);
      observer_.on_diagnostic("GROUP_STREAM_CAPACITY", peer, &header.message);
      return;
    }
    saturating_inc(group_stats_.received);
    group_mark_seen(*stream, seq);
    const std::uint32_t remaining =
        header.remaining_deadline_ms > rx_age_ms_ ? header.remaining_deadline_ms - rx_age_ms_
                                                  : 0;
    GroupMessageInfo info{};
    info.key = key;
    info.group = group;
    info.group_seq = seq;
    info.priority = head.priority;
    info.ordered = head.ordered;
    group_accept(*stream, info, app, member, remaining, now_ms, header.end_epoch, peer);
  }

  GroupTree* tree = allocate_group_tree(now_ms);
  if (tree == nullptr) {
    // No tree slot (every tracked message is still collecting): confirm
    // ourselves and report our whole subtree missing so the source repairs
    // it in a later round — the copy is not forwarded untracked.
    saturating_inc(group_stats_.state_refusals);
    observer_.on_diagnostic("GROUP_STATE_CAPACITY", peer, &header.message);
    GroupTree scratch{};
    scratch.key = key;
    scratch.round = round;
    scratch.self_delivered = member;
    scratch.self_nonmember = !member;
    neighbors_.for_each([&](const Neighbor& neighbor) {
      if (!neighbor.active || neighbor.node == peer || neighbor.node == key.origin ||
          !neighbor_is_child(neighbor.node, now_ms)) {
        return;
      }
      std::uint8_t count = scratch.missing_count;
      if (count < scratch.missing.size()) scratch.missing[count++] = neighbor.node;
      const std::uint16_t below = group_routed_subtree(neighbor.node, scratch.missing.data(),
                                                       scratch.missing.size(), count);
      scratch.missing_count = count;
      scratch.extra_missing = saturating_add16(scratch.extra_missing, 1U + below);
    });
    GroupReportPayload report{};
    group_build_report(scratch, report);
    if (queue_group_report(peer, report, priority, now_ms)) {
      saturating_inc(group_stats_.reports_sent);
    }
    return;
  }
  tree->key = key;
  tree->group = group;
  tree->priority = priority;
  tree->self_delivered = member;
  tree->self_nonmember = !member;
  tree->expires_at_ms = now_ms + header.remaining_deadline_ms + kGroupTreeSlackMs;
  group_begin_round(*tree, frame, peer, refresh, now_ms);
}

void MeshNode::handle_group_report(const wire::PlainFrame& frame, const NodeId peer,
                                   const MonotonicMs now_ms) noexcept {
  if (!gateway_scoped()) {
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic("GROUP_REQUIRES_GATEWAY_SCOPED", peer, &frame.header.message);
    return;
  }
  // Link-only, one hop, from the reporting child itself.
  if (frame.header.flags != 0 || frame.header.origin != peer ||
      frame.header.destination != config_.node) {
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic("GROUP_REPORT_REJECTED", peer, &frame.header.message);
    return;
  }
  GroupReportPayload report{};
  const auto status =
      decode_group_report(ByteView{frame.payload.data(), frame.payload_size}, report);
  if (!status) {
    saturating_inc(group_stats_.rejected);
    observer_.on_diagnostic(status.detail, peer, &frame.header.message);
    return;
  }
  saturating_inc(group_stats_.reports_received);
  GroupTree* tree = find_group_tree(report.key);
  GroupChild* entry = nullptr;
  if (tree != nullptr) {
    for (std::size_t i = 0; i < tree->child_count; ++i) {
      if (tree->children[i].node == peer) entry = &tree->children[i];
    }
  }
  if (entry == nullptr) {
    saturating_inc(group_stats_.reports_unmatched);
    return;
  }
  if (entry->ever_reported && report.round < entry->report_round) return;  // older news
  entry->report_round = report.round;
  entry->ever_reported = true;
  if ((report.flags & kGroupReportNotChild) != 0) {
    entry->delivered = 0;
    entry->nonmember = 0;
    entry->missing = 0;
    entry->complete = true;
    entry->not_child = true;
  } else {
    entry->delivered = report.delivered;
    entry->nonmember = report.nonmember;
    entry->missing = report.missing_total;
    entry->complete = report.missing_total == 0;
    entry->not_child = false;
  }
  if (report.round != tree->round || !tree->collecting || !entry->sent || entry->reported) {
    // A late or unsolicited report only refreshes the child's counts for
    // the next round (a complete child is then not re-sent).
    return;
  }
  entry->reported = true;
  for (std::size_t i = 0; i < report.missing_count; ++i) {
    if (tree->missing_count >= tree->missing.size()) break;
    tree->missing[tree->missing_count++] = report.missing[i];
  }
  if (group_round_resolved(*tree)) group_finalize(*tree, now_ms);
}

bool MeshNode::group_origin_job_stale(const TxJob& job) const noexcept {
  if (job.owner != JobOwner::Group) return false;
  if (security_.revoked_group_sender(job.ack.key.origin) ||
      security_.revoked_group_sender(job.peer)) return true;
  const GroupTree* tree = group_trees_.find(
      [&](const GroupTree& value) { return value.key == job.ack.key; });
  if (tree == nullptr && job.ack.key.origin != config_.node) return true;
  if (tree != nullptr && security_.revoked_group_sender(tree->parent)) return true;
  if (job.ack.accepted_type == FrameType::GroupData &&
      job.form == JobForm::Forwarded &&
      !security_.accepts_group_epoch(job.forwarded.header.end_epoch)) return true;
  if (job.ack.key.origin != config_.node) return false;
  // Eviction only releases terminal records (send_group reclaims settled
  // history oldest-first), so a missing self-origin record means the origin
  // settled and its history was evicted: the leftover job is stale either
  // way — dispatching or retrying it would resurrect a terminal verdict.
  const GroupOrigin* origin = find_group_origin(job.ack.key.id);
  return origin == nullptr || sleep_terminal(origin->state);
}

void MeshNode::group_job_done(const TxJob& job, const bool success,
                              const MonotonicMs now_ms) noexcept {
  // A copy/report that resolved after its own origin settled (sleep
  // disposition, expiry): it must neither revive the verdict nor finalize a
  // round on its behalf.
  if (group_origin_job_stale(job)) return;
  if (job.ack.accepted_type != FrameType::GroupData) return;  // reports: fire and forget
  if (!success) saturating_inc(group_stats_.copies_failed);
  GroupTree* tree = find_group_tree(job.ack.key);
  if (tree == nullptr || job.ack.round != tree->round) return;
  for (std::size_t i = 0; i < tree->child_count; ++i) {
    GroupChild& entry = tree->children[i];
    if (entry.node != job.peer || !entry.sent) continue;
    if (!success) {
      // No MAC ACK after the bounded link retries: the child is missing for
      // this round; do not wait out the deadline for it.
      entry.failed = true;
      if (tree->collecting && group_round_resolved(*tree)) group_finalize(*tree, now_ms);
    }
    return;
  }
}

// --- Ordering and application hand-off (group-delivery.md §6) -----------------------

void MeshNode::group_deliver_app(const GroupMessageInfo& info, const ByteView app) noexcept {
  if (security_.revoked_group_sender(info.key.origin)) return;
  saturating_inc(group_stats_.delivered);
  if (info.late) saturating_inc(group_stats_.late);
  observer_.on_group_message(info, app);
}

void MeshNode::group_accept(GroupStream& stream, const GroupMessageInfo& info,
                            const ByteView app, const bool member,
                            const std::uint32_t remaining_ms,
                            const MonotonicMs now_ms,
                            const std::uint32_t gk_epoch,
                            const NodeId previous_hop) noexcept {
  const std::uint32_t seq = info.group_seq;
  if (stream.next_seq == 0) stream.next_seq = seq;  // first message of this session
  // Keep the cursor inside the duplicate window: anything older than the
  // window can no longer be told apart and is skipped.
  if (stream.max_seq >= kGroupSeenWindow && stream.next_seq + kGroupSeenWindow <= stream.max_seq) {
    group_skip_to(stream, stream.max_seq - kGroupSeenWindow + 1U);
  }
  if (!info.ordered || seq < stream.next_seq) {
    // Unordered traffic (alarms) is never held; an ordered message whose
    // slot was already skipped is delivered, flagged late.
    if (member) {
      GroupMessageInfo out = info;
      out.late = info.ordered && seq < stream.next_seq;
      group_deliver_app(out, app);
    }
    group_drain(stream);
    return;
  }
  if (seq == stream.next_seq) {
    if (member) group_deliver_app(info, app);
    ++stream.next_seq;
    group_drain(stream);
    return;
  }
  // A gap before this ordered message: hold it (members only — for a
  // non-member the slot is simply seen and drains past).
  if (!member) return;
  GroupHold* hold = group_holds_.allocate();
  if (hold == nullptr) {
    // Hold pool full: release the oldest held message now (skipping its
    // gap) rather than refusing or dropping this one.
    std::uint32_t oldest = UINT32_MAX;
    group_holds_.for_each([&](const GroupHold& value) {
      if (value.info.key.origin == stream.source && value.info.group_seq < oldest) {
        oldest = value.info.group_seq;
      }
    });
    if (oldest != UINT32_MAX) {
      group_skip_to(stream, oldest);
    } else {
      // Every hold belongs to another source: release that stream's oldest.
      GroupHold* victim = nullptr;
      group_holds_.for_each([&](GroupHold& value) {
        if (victim == nullptr || value.release_at_ms < victim->release_at_ms) victim = &value;
      });
      if (victim != nullptr) {
        GroupStream* other = group_streams_.find([&](const GroupStream& value) {
          return value.source == victim->info.key.origin;
        });
        if (other != nullptr) group_skip_to(*other, victim->info.group_seq);
      }
    }
    if (seq == stream.next_seq) {
      group_deliver_app(info, app);
      ++stream.next_seq;
      group_drain(stream);
      return;
    }
    if (seq < stream.next_seq) {
      GroupMessageInfo out = info;
      out.late = true;
      group_deliver_app(out, app);
      return;
    }
    hold = group_holds_.allocate();
    if (hold == nullptr) {  // defensive: a slot was just released
      GroupMessageInfo out = info;
      group_deliver_app(out, app);
      return;
    }
  }
  saturating_inc(group_stats_.held);
  hold->info = info;
  hold->previous_hop = previous_hop;
  hold->gk_epoch = gk_epoch;
  hold->release_at_ms = now_ms + std::min(remaining_ms, kGroupOrderMaxHoldMs);
  hold->size = static_cast<std::uint8_t>(std::min(app.size, hold->payload.size()));
  if (hold->size > 0) std::memcpy(hold->payload.data(), app.data, hold->size);
}

void MeshNode::group_drain(GroupStream& stream) noexcept {
  while (stream.next_seq != 0 && group_seen(stream, stream.next_seq)) {
    const std::uint32_t seq = stream.next_seq;
    GroupHold* hold = group_holds_.find([&](const GroupHold& value) {
      return value.info.key.origin == stream.source &&
             value.info.key.id.session == stream.session && value.info.group_seq == seq;
    });
    if (hold != nullptr) {
      const GroupMessageInfo info = hold->info;
      const bool live = security_.accepts_group_epoch(hold->gk_epoch) &&
                        !security_.revoked_group_sender(hold->previous_hop);
      std::array<std::uint8_t, kGroupPayloadMax> payload{};
      const std::uint8_t size = hold->size;
      std::memcpy(payload.data(), hold->payload.data(), size);
      group_holds_.release(hold);
      if (live) group_deliver_app(info, ByteView{payload.data(), size});
    }
    ++stream.next_seq;
  }
}

void MeshNode::group_skip_to(GroupStream& stream, const std::uint32_t target) noexcept {
  // Deliver every held message of this stream below `target` in stream
  // order, then move the cursor to `target` and drain.
  while (true) {
    GroupHold* lowest = nullptr;
    group_holds_.for_each([&](GroupHold& value) {
      if (value.info.key.origin == stream.source && value.info.group_seq < target &&
          (lowest == nullptr || value.info.group_seq < lowest->info.group_seq)) {
        lowest = &value;
      }
    });
    if (lowest == nullptr) break;
    if (stream.next_seq != 0 && lowest->info.group_seq > stream.next_seq) {
      group_stats_.gaps_skipped += lowest->info.group_seq - stream.next_seq;
    }
    const GroupMessageInfo info = lowest->info;
    const bool live = security_.accepts_group_epoch(lowest->gk_epoch) &&
                      !security_.revoked_group_sender(lowest->previous_hop);
    std::array<std::uint8_t, kGroupPayloadMax> payload{};
    const std::uint8_t size = lowest->size;
    std::memcpy(payload.data(), lowest->payload.data(), size);
    group_holds_.release(lowest);
    stream.next_seq = info.group_seq + 1U;
    if (live) group_deliver_app(info, ByteView{payload.data(), size});
  }
  if (stream.next_seq != 0 && target > stream.next_seq) {
    group_stats_.gaps_skipped += target - stream.next_seq;
  }
  if (stream.next_seq == 0 || target > stream.next_seq) stream.next_seq = target;
  group_drain(stream);
}

// --- Sleep settlement ---------------------------------------------------------------
bool MeshNode::settle_one_sleep_group_origin(
    const SleepWorkPolicy fallback) noexcept {
  GroupOrigin* target = group_origins_.find(
      [](const GroupOrigin& origin) { return !sleep_terminal(origin.state); });
  if (target == nullptr) return false;
  if (fallback == SleepWorkPolicy::Defer) {
    group_origin_terminal(*target, DeliveryState::Indeterminate,
                          "SLEEP_DEFERRED");
  } else {
    group_origin_terminal(*target, DeliveryState::Failed,
                          fallback == SleepWorkPolicy::Save
                              ? "SLEEP_GROUP_NOT_PERSISTED"
                              : "SLEEP_DRAIN");
  }
  return true;
}

SleepHoldRelease MeshNode::release_one_group_hold_for_sleep() noexcept {
  // Stable pick across streams: lowest (group_seq, source); pool order
  // breaks remaining ties.
  GroupHold* target = nullptr;
  group_holds_.for_each([&](GroupHold& hold) {
    if (target == nullptr ||
        hold.info.group_seq < target->info.group_seq ||
        (hold.info.group_seq == target->info.group_seq &&
         hold.info.key.origin < target->info.key.origin)) {
      target = &hold;
    }
  });
  if (target == nullptr) return SleepHoldRelease::NonePending;
  GroupStream* stream = group_streams_.find([&](const GroupStream& value) {
    return value.source == target->info.key.origin &&
           value.session == target->info.key.id.session;
  });
  if (stream == nullptr) {
    // Holds only exist with a stream: keep every hold and let the sleep
    // attempt abort instead of dropping payload silently.
    const NodeId peer = target->info.key.origin;
    const MessageId message = target->info.key.id;
    observer_.on_diagnostic("GROUP_HOLD_STREAM_MISSING", peer, &message);
    return SleepHoldRelease::StreamInvariant;
  }
  const std::uint32_t seq = target->info.group_seq;
  if (stream->next_seq != 0 && seq > stream->next_seq) {
    group_stats_.gaps_skipped += seq - stream->next_seq;
  }
  GroupMessageInfo info = target->info;
  const std::uint32_t gk_epoch = target->gk_epoch;
  const NodeId previous_hop = target->previous_hop;
  // A hold the cursor already passed (defensive — the release always takes
  // the lowest held seq) reads as late, exactly like group_accept.
  if (stream->next_seq != 0 && seq < stream->next_seq) info.late = true;
  std::array<std::uint8_t, kGroupPayloadMax> payload{};
  const std::uint8_t size = target->size;
  std::memcpy(payload.data(), target->payload.data(), size);
  group_holds_.release(target);
  if (stream->next_seq == 0 || seq >= stream->next_seq) {
    stream->next_seq = seq + 1U;
  }
  // Exactly one hand-off: the trailing group_drain() that group_skip_to runs
  // is deliberately NOT run, so this call releases exactly one message.
  if (security_.accepts_group_epoch(gk_epoch) &&
      !security_.revoked_group_sender(previous_hop))
    group_deliver_app(info, ByteView{payload.data(), size});
  return SleepHoldRelease::Released;
}

// quiesced() counts only group work that can still progress while draining:
// a round collecting reports (the source's own tree or a relay/receiver
// tree) may still resolve and queue its report. Queued origins and
// scheduled repair rounds are masked by the drain pause bits — a repair is
// a retry round (kRetryRounds), settled exactly like a paused unicast
// end-to-end retry: it does not run during drain and the unfinished origin
// is settled by the Fail/Save/Defer dispositions instead.
bool MeshNode::group_radio_pending() const noexcept {
  bool pending = false;
  group_trees_.for_each(
      [&](const GroupTree& tree) { pending = pending || tree.collecting; });
  group_origins_.for_each([&](const GroupOrigin& origin) {
    pending = pending || origin.tree.collecting;
  });
  return pending;
}

// --- poll() driver ------------------------------------------------------------------

void MeshNode::process_group(const MonotonicMs now_ms) noexcept {
  while (GroupHold* hold = group_holds_.find([&](const GroupHold& value) {
           return security_.revoked_group_sender(value.info.key.origin) ||
                  security_.revoked_group_sender(value.previous_hop);
         })) group_holds_.release(hold);
  while (GroupTree* tree = group_trees_.find([&](const GroupTree& value) {
           return security_.revoked_group_sender(value.key.origin) ||
                  security_.revoked_group_sender(value.parent);
         })) group_trees_.release(tree);
  // A frame held for a GK promote retries once the promote settles
  // (landed or failed); a promote that never settles expires the hold.
  if (group_promote_hold_.used && !security_.group_promotion_pending()) {
    const wire::LinkOpenedFrame frame = group_promote_hold_.frame;
    const NodeId peer = group_promote_hold_.peer;
    group_promote_hold_ = GroupPromoteHold{};
    handle_group_data(frame, peer, now_ms);
  } else if (group_promote_hold_.used &&
             now_ms - group_promote_hold_.held_at_ms > kGroupPromoteHoldMs) {
    group_promote_hold_ = GroupPromoteHold{};
    saturating_inc(group_stats_.promote_drops);
    saturating_inc(group_stats_.open_failures);
  }
  // Relay/receiver trees: report deadlines, then retention.
  group_trees_.for_each([&](GroupTree& tree) {
    if (tree.collecting && now_ms >= tree.deadline_ms) group_finalize(tree, now_ms);
  });
  group_trees_.for_each([&](GroupTree& tree) {
    if (!tree.collecting && tree.expires_at_ms <= now_ms) group_trees_.release(&tree);
  });
  // Ordered holds past their bound: skip the gap in front of them.
  while (true) {
    GroupHold* due = nullptr;
    group_holds_.for_each([&](GroupHold& value) {
      if (value.release_at_ms <= now_ms &&
          (due == nullptr || value.release_at_ms < due->release_at_ms)) {
        due = &value;
      }
    });
    if (due == nullptr) break;
    GroupStream* stream = group_streams_.find(
        [&](const GroupStream& value) { return value.source == due->info.key.origin; });
    if (stream == nullptr) {
      group_holds_.release(due);
      continue;
    }
    group_skip_to(*stream, due->info.group_seq);
  }
  // Source: round deadlines, repair rounds, expiry, admission.
  group_origins_.for_each([&](GroupOrigin& origin) {
    if (sleep_terminal(origin.state)) return;
    if (origin.admitted && !security_.accepts_group_epoch(origin.sealed.header.end_epoch)) {
      group_origin_terminal(origin, DeliveryState::Failed, "GROUP_KEY_RETIRED");
      return;
    }
    if (origin.tree.collecting && now_ms >= origin.tree.deadline_ms) {
      group_finalize(origin.tree, now_ms);
    }
    if (sleep_terminal(origin.state)) return;
    if (now_ms >= origin.expires_at_ms) {
      if (!origin.admitted) {
        group_origin_terminal(origin, DeliveryState::Expired, "GROUP_NOT_SENT");
      } else {
        group_origin_terminal(origin, DeliveryState::Failed, "GROUP_INCOMPLETE");
      }
      return;
    }
    if (origin.admitted && !origin.tree.collecting && origin.next_round_at_ms != 0 &&
        now_ms >= origin.next_round_at_ms && !paused(pause::kRetryRounds)) {
      const bool force = origin.force_all;
      // Repairs spend the same airtime bucket as new messages: a non-urgent
      // repair waits for tokens (its lifetime keeps running), so the group
      // lane's air time stays inside capacity + rate x window even when
      // tree churn forces refresh rounds. Urgent repairs are debited only.
      const std::uint32_t repaired =
          force ? std::max<std::uint32_t>(origin.expected_nodes, origin.summary.missing_total)
                : origin.summary.missing_total;
      const std::int64_t repair_cost =
          static_cast<std::int64_t>(std::max<std::uint32_t>(1, repaired)) * origin.node_cost_us;
      if (origin.priority != Priority::Urgent && config_.group_airtime_us_per_s != 0 &&
          group_budget_balance(now_ms) < std::min(repair_cost, kGroupBudgetCapacityUs)) {
        origin.next_round_at_ms = now_ms + kGroupRepairGapMs;
        if (!origin.budget_waiting) {
          origin.budget_waiting = true;
          saturating_inc(group_stats_.budget_deferrals);
        }
        return;
      }
      origin.next_round_at_ms = 0;
      origin.budget_waiting = false;
      origin.force_all = false;
      // A refresh round (tree accounting inconsistent) carries the REFRESH
      // bit so every relay re-asks every child, not just incomplete ones.
      origin.sealed.header.delivery_round = static_cast<std::uint8_t>(
          ((origin.tree.round + 1U) & kGroupRoundMask) | (force ? kGroupRoundRefresh : 0U));
      origin.sealed.header.remaining_deadline_ms =
          static_cast<std::uint32_t>(origin.expires_at_ms - now_ms);
      // A refresh round re-walks the whole tree and is charged as such.
      (void)group_budget_balance(now_ms);
      group_budget_tokens_us_ -= repair_cost;
      group_budget_tokens_us_ = std::max(group_budget_tokens_us_, -kGroupBudgetCapacityUs);
      saturating_inc(group_stats_.rounds_started);
      saturating_inc(group_stats_.repair_rounds);
      origin.reason = "GROUP_REPAIRING";
      origin.summary.reason = origin.reason;
      group_begin_round(origin.tree, origin.sealed, config_.node, force, now_ms);
    }
  });
  group_admit(now_ms);
}

}  // namespace routeloom
