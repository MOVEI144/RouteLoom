// Gateway-scoped routing profile (docs/design/sdk-v1/routing-scale.md).
//
// The Babel-derived route table (routing.hpp) is unchanged: every record this
// file emits leaves only after mark_advertised(), and every record it
// receives enters only through RouteTable::consider(). What changes is WHO
// hears WHICH record and WHEN:
//   * gateway routes + self record: down the gateway tree (parent -> child)
//     once per route_refresh_ticks periods, triggered on change;
//   * the subtree's routes: up the tree (child -> parent), same cadence;
//   * everything else: on demand (ROUTE_REQUEST Discover/Reply) along the
//     tree, bounded by TTL, dedup, a forward budget and backoff.
// Restricting the audience of an advertisement is indistinguishable from
// losing it on the air, which Babel's feasibility condition already
// tolerates — loop-freedom does not depend on the schedule (§8).

#include <algorithm>

#include "routeloom/byte_io.hpp"
#include "routeloom/node.hpp"
#include "routeloom/route_request.hpp"

namespace routeloom {
namespace {

constexpr std::uint32_t kScopedUpdateLifetimeMs = 1000;
// Upward pages admitted per tick per parent: a hub's full cycle (at most
// ceil(kMaxRouteEntries / 5) = 26 pages) always fits inside the six ticks of
// the default cycle without monopolising the 32-slot TX pool.
constexpr std::size_t kScopedMaxUpFramesPerTick = 6;
// Non-tree neighbors hear our self + gateway records once per this many
// refresh cycles (backup/improvement discovery), one neighbor at a time.
constexpr std::uint32_t kScopedOtherCycles = 4;
// Pull (Neighbor ROUTE_REQUEST) backoff while a gateway route is missing.
constexpr std::uint32_t kPullBaseMs = 1000;
constexpr std::uint32_t kPullMaxMs = 32000;
constexpr std::uint32_t kPullAnswerGapMs = 500;
// On-demand discovery: linear backoff per destination, state dropped after
// the last need plus this dwell.
constexpr std::uint32_t kDiscoveryBaseMs = 2000;
constexpr std::uint32_t kDiscoveryMaxMs = 30000;
constexpr std::uint32_t kDiscoveryDwellMs = 30000;
// Dedup + reverse-path pointer retention for multi-hop kinds.
constexpr std::uint32_t kRouteRequestSeenMs = 5000;
constexpr std::uint32_t kRouteRequestLifetimeMs = 2000;
// Discover forwarding budget per node.
constexpr std::uint32_t kRouteRequestWindowMs = 1000;
constexpr std::uint32_t kRouteRequestForwardsPerWindow = 8;
// Interest (pull / sequence request) lasts this many advertisement periods.
constexpr MonotonicMs kScopedInterestPeriods = 2;
// Delay before a former parent is told we left (see defer_parent_release).
constexpr MonotonicMs kScopedReleaseDelayMs = 3000;
// Unknown-GK broadcast hints surface at most this often: the key pull they
// trigger is the Owner's bounded work, not per-frame work.
constexpr MonotonicMs kBroadcastGkHintGapMs = 60000;

void saturating_inc(std::uint64_t& counter) noexcept {
  if (counter != UINT64_MAX) ++counter;
}

bool reserved_node(const NodeId node) noexcept {
  return node == kInvalidNodeId || node == kBroadcastNodeId;
}

}  // namespace

// Broadcast records are validated as a whole before the caller can install
// any route. A GK tag alone does not establish a pairwise sender identity.
namespace {
bool valid_broadcast_records(const BroadcastRouteRecord* records, const std::size_t count,
                             const NodeId sender) noexcept {
  if (records == nullptr || count == 0 || count > kBroadcastRouteMaxRecords ||
      reserved_node(sender) || records[0].route.destination != sender ||
      records[0].route.metric != 0 || records[0].via != kInvalidNodeId) return false;
  for (std::size_t i = 0; i < count; ++i) {
    const auto& record = records[i];
    const auto& route = record.route;
    if (reserved_node(route.destination) || route.generation == 0 ||
        (i != 0 && (route.metric == 0 ||
                     (route.metric == kInfiniteRouteMetric
                          ? record.via != kInvalidNodeId
                          : reserved_node(record.via) || record.via == sender ||
                                record.via == route.destination)))) return false;
    for (std::size_t j = 0; j < i; ++j) {
      if (records[j].route.destination == route.destination) return false;
    }
  }
  return true;
}
}  // namespace

Status encode_broadcast_route_update(const BroadcastRouteRecord* records,
                                     const std::size_t count, const NodeId sender,
                                     const MutableByteView out, std::size_t& written) noexcept {
  written = 0;
  if (!valid_broadcast_records(records, count, sender)) {
    return Status::error(StatusCode::InvalidArgument, "broadcast route records");
  }
  ByteWriter writer(out);
  auto status = writer.write_u8(1);
  if (status) status = writer.write_u8(0);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(count));
  if (status) status = writer.write_u8(0);
  for (std::size_t i = 0; status && i < count; ++i) {
    const auto& record = records[i];
    status = writer.write_u64(record.route.destination);
    if (status) status = writer.write_u32(record.route.generation);
    if (status) status = writer.write_u16(record.route.sequence);
    if (status) status = writer.write_u16(record.route.metric);
    if (status) status = writer.write_u64(record.via);
  }
  if (status) written = writer.size();
  return status;
}

Status decode_broadcast_route_update(
    const ByteView input, const NodeId sender,
    std::array<BroadcastRouteRecord, kBroadcastRouteMaxRecords>& records,
    std::size_t& count) noexcept {
  count = 0;
  if (input.data == nullptr || input.size < 28 || input.data[0] != 1 ||
      input.data[1] != 0 || input.data[3] != 0 || input.data[2] == 0 ||
      input.data[2] > kBroadcastRouteMaxRecords ||
      input.size != 4U + 24U * input.data[2]) {
    return Status::error(StatusCode::ProtocolError, "broadcast route length/head");
  }
  std::array<BroadcastRouteRecord, kBroadcastRouteMaxRecords> decoded{};
  ByteReader reader(input);
  std::uint8_t head = 0;
  for (int i = 0; i < 4; ++i) {
    auto status = reader.read_u8(head);
    if (!status) return status;
  }
  for (std::size_t i = 0; i < input.data[2]; ++i) {
    auto& record = decoded[i];
    auto status = reader.read_u64(record.route.destination);
    if (status) status = reader.read_u32(record.route.generation);
    if (status) status = reader.read_u16(record.route.sequence);
    if (status) status = reader.read_u16(record.route.metric);
    if (status) status = reader.read_u64(record.via);
    if (!status) return status;
  }
  if (!valid_broadcast_records(decoded.data(), input.data[2], sender)) {
    return Status::error(StatusCode::ProtocolError, "broadcast route records");
  }
  records = decoded;
  count = input.data[2];
  return Status::success();
}

RouteMetric project_broadcast_route_metric(const BroadcastRouteRecord& record,
                                           const NodeId receiver) noexcept {
  return record.via == receiver ? kInfiniteRouteMetric : record.route.metric;
}

// --- ROUTE_REQUEST payload codec ------------------------------------------------

Status encode_route_request(const RouteRequestPayload& payload, const MutableByteView out,
                            std::size_t& written) noexcept {
  written = 0;
  ByteWriter writer(out);
  Status status;
#define RL_WRITE_RR(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE_RR(writer.write_u8(static_cast<std::uint8_t>(payload.kind)));
  RL_WRITE_RR(writer.write_u8(payload.ttl));
  RL_WRITE_RR(writer.write_u64(payload.requester));
  RL_WRITE_RR(writer.write_u64(payload.target));
  RL_WRITE_RR(writer.write_u32(payload.request_id));
  RL_WRITE_RR(writer.write_u64(payload.record.destination));
  RL_WRITE_RR(writer.write_u32(payload.record.generation));
  RL_WRITE_RR(writer.write_u16(payload.record.sequence));
  RL_WRITE_RR(writer.write_u16(payload.record.metric));
#undef RL_WRITE_RR
  written = writer.size();
  return Status::success();
}

Status decode_route_request(const ByteView input, RouteRequestPayload& payload) noexcept {
  if (input.size != kRouteRequestPayloadBytes) {
    return Status::error(StatusCode::ProtocolError, "route request length");
  }
  ByteReader reader(input);
  std::uint8_t kind = 0;
  RouteRequestPayload decoded{};
  Status status;
#define RL_READ_RR(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_READ_RR(reader.read_u8(kind));
  RL_READ_RR(reader.read_u8(decoded.ttl));
  RL_READ_RR(reader.read_u64(decoded.requester));
  RL_READ_RR(reader.read_u64(decoded.target));
  RL_READ_RR(reader.read_u32(decoded.request_id));
  RL_READ_RR(reader.read_u64(decoded.record.destination));
  RL_READ_RR(reader.read_u32(decoded.record.generation));
  RL_READ_RR(reader.read_u16(decoded.record.sequence));
  RL_READ_RR(reader.read_u16(decoded.record.metric));
#undef RL_READ_RR
  if (kind < static_cast<std::uint8_t>(RouteRequestKind::Neighbor) ||
      kind > static_cast<std::uint8_t>(RouteRequestKind::Reply)) {
    return Status::error(StatusCode::ProtocolError, "route request kind");
  }
  decoded.kind = static_cast<RouteRequestKind>(kind);
  if (decoded.ttl == 0 || decoded.ttl > kRouteRequestMaxTtl ||
      (decoded.kind == RouteRequestKind::Neighbor && decoded.ttl != 1)) {
    return Status::error(StatusCode::ProtocolError, "route request ttl");
  }
  if (reserved_node(decoded.requester) || reserved_node(decoded.target) ||
      decoded.requester == decoded.target) {
    return Status::error(StatusCode::ProtocolError, "route request node");
  }
  const NodeId bound = decoded.kind == RouteRequestKind::Reply ? decoded.target
                                                               : decoded.requester;
  if (decoded.record.destination != bound) {
    return Status::error(StatusCode::ProtocolError, "route request record");
  }
  payload = decoded;
  return Status::success();
}

// --- Profile predicates ---------------------------------------------------------

bool MeshNode::gateway_scoped() const noexcept {
  for (const NodeId gateway : config_.route_gateways) {
    if (gateway != kInvalidNodeId) return true;
  }
  return false;
}

bool MeshNode::is_route_gateway(const NodeId destination) const noexcept {
  if (destination == kInvalidNodeId) return false;
  for (const NodeId gateway : config_.route_gateways) {
    if (gateway == destination) return true;
  }
  return false;
}

bool MeshNode::neighbor_is_child(const NodeId neighbor, const MonotonicMs now_ms) const noexcept {
  const auto* record = find_neighbor(neighbor);
  return record != nullptr && record->active && record->child_until_ms > now_ms;
}

bool MeshNode::scoped_child(const NodeId neighbor) const noexcept {
  return gateway_scoped() && neighbor_is_child(neighbor, last_clock_ms_);
}

NodeId MeshNode::scoped_uplink(const NodeId exclude) const noexcept {
  for (const NodeId gateway : config_.route_gateways) {
    if (gateway == kInvalidNodeId || gateway == config_.node) continue;
    const auto selection = routes_.best(gateway);
    if (!selection.valid || selection.next_hop == exclude) continue;
    const auto* record = find_neighbor(selection.next_hop);
    if (record != nullptr && record->active) return selection.next_hop;
  }
  return kInvalidNodeId;
}

std::uint32_t MeshNode::scoped_link_phase(const NodeId neighbor) const noexcept {
  // Deterministic per-(node, link) phase inside the refresh cycle: a node's
  // tree links are refreshed on different ticks instead of in one burst.
  const std::uint32_t ticks = std::max<std::uint32_t>(1, config_.route_refresh_ticks);
  const std::uint64_t mixed =
      (config_.node ^ (neighbor * 0x9E3779B97F4A7C15ULL)) * 0xBF58476D1CE4E5B9ULL;
  return static_cast<std::uint32_t>((mixed >> 29) % ticks);
}

bool MeshNode::upward_eligible(const RouteSelection& selection, const NodeId parent,
                               const MonotonicMs now_ms) const noexcept {
  // Upward records are the routes whose committed next hop is one of our
  // children: exactly our subtree (children and their descendants).
  // Generation-0 placeholders (see scoped_record) are never announced.
  return selection.valid && selection.generation != 0 &&
         selection.destination != config_.node &&
         !is_route_gateway(selection.destination) && selection.next_hop != parent &&
         neighbor_is_child(selection.next_hop, now_ms);
}

// --- Change tracking --------------------------------------------------------------

void MeshNode::note_scoped_change(const RouteSelection& selection,
                                  const RouteSelection& previous,
                                  const MonotonicMs now_ms) noexcept {
  const NodeId destination = selection.valid ? selection.destination : previous.destination;
  if (destination == kInvalidNodeId || destination == config_.node) return;
  if (is_route_gateway(destination)) {
    // Gateway route moved (next hop, sequence, metric or validity): the
    // children and interested neighbors hear it; a parent change also
    // restarts the upward cycle toward the new parent (run_scoped_triggered).
    scoped_down_dirty_ = true;
    arm_triggered_advertisement(now_ms);
    return;
  }
  // Upward-relevant: the route is (or was) part of our subtree, or our
  // parent still holds a finite record from us that must now be corrected.
  const bool relevant = (selection.valid && neighbor_is_child(selection.next_hop, now_ms)) ||
                        (previous.valid && neighbor_is_child(previous.next_hop, now_ms)) ||
                        routes_.announced_up(destination);
  if (!relevant) return;
  mark_scoped_dirty(destination, now_ms);
}

void MeshNode::mark_scoped_dirty(const NodeId destination, const MonotonicMs now_ms) noexcept {
  bool present = false;
  for (std::size_t i = 0; i < scoped_dirty_count_; ++i) present |= scoped_dirty_[i] == destination;
  if (!present) {
    if (scoped_dirty_count_ < scoped_dirty_.size()) {
      scoped_dirty_[scoped_dirty_count_++] = destination;
    } else {
      scoped_dirty_overflow_ = true;  // falls back to a full upward sweep
    }
  }
  arm_triggered_advertisement(now_ms);
}

void MeshNode::note_scoped_update(Neighbor& neighbor, const RouteAdvertisement* records,
                                  const std::size_t count, const MonotonicMs now_ms) noexcept {
  if (!gateway_scoped()) return;
  // Poison reverse makes the tree visible without a wire flag: a neighbor
  // whose committed next hop toward a gateway is us advertises that gateway
  // back to us at infinity. A neighbor that lost its gateway route also
  // sends infinity — treating it as a child is the useful answer (it gets
  // our downward refresh). A finite gateway record means "not via you".
  bool poisoned = false;
  bool finite = false;
  for (std::size_t i = 0; i < count; ++i) {
    const auto& record = records[i];
    if (!is_route_gateway(record.destination) || record.destination == neighbor.node) continue;
    if (record.metric == kInfiniteRouteMetric) {
      poisoned = true;
    } else {
      finite = true;
    }
  }
  const bool was_child = neighbor.child_until_ms > now_ms;
  if (poisoned) {
    neighbor.child_until_ms = now_ms + config_.route_lifetime_ms;
    if (!was_child) {
      // A new child: it and the subtree we already reach through it travel
      // upward now, not at our next cycle — a returning child's routes may
      // not change our selections at all (the scan would stay silent) while
      // our parent dropped them when the child left. The child gets our
      // self + gateway records right away (answered from poll() like a pull).
      const NodeId child = neighbor.node;
      mark_scoped_dirty(child, now_ms);
      routes_.for_each_selected([&](const RouteSelection& selection) {
        if (selection.next_hop == child && selection.destination != child) {
          mark_scoped_dirty(selection.destination, now_ms);
        }
      });
      if (!neighbor.pull_answer_pending) neighbor.pull_target = kInvalidNodeId;
      neighbor.pull_answer_pending = true;
    }
  } else if (finite) {
    neighbor.child_until_ms = 0;
    if (was_child) {
      // The subtree behind this neighbor moved to another parent. Retract
      // what we announced upward for it while our own (still working) route
      // keeps carrying traffic, instead of letting the ancestors' copies
      // decay into a black-holing cascade one lease later.
      const NodeId former = neighbor.node;
      routes_.for_each_selected([&](const RouteSelection& selection) {
        if (selection.next_hop == former && routes_.announced_up(selection.destination)) {
          mark_scoped_dirty(selection.destination, now_ms);
        }
      });
    }
  }
}

// --- Frame construction -----------------------------------------------------------

bool MeshNode::scoped_record(const NodeId destination, const NodeId receiver,
                             RouteAdvertisement& record) noexcept {
  const auto selection = routes_.best(destination);
  if (selection.valid && selection.generation == 0) {
    // A direct route seeded by add_neighbor() before the peer's own self
    // record arrived: its source generation is unknown, so it stays a local
    // placeholder. Advertising it would plant generation-0 state that the
    // real generation later resets network-wide.
    return false;
  }
  if (selection.valid) {
    // Same rules as the flat dump: split horizon with poison reverse toward
    // the next hop, relay-off withdraws everything, and FD is tightened
    // before a finite record leaves (routing.md §10).
    const RouteMetric metric =
        (!relay_enabled_ || selection.next_hop == receiver) ? kInfiniteRouteMetric
                                                            : selection.metric;
    record = RouteAdvertisement{destination, selection.generation, selection.sequence, metric};
    if (metric != kInfiniteRouteMetric) routes_.mark_advertised(destination);
    return true;
  }
  RouteTable::LostRoute lost{};
  if (routes_.lost_route(destination, lost)) {
    record = RouteAdvertisement{destination, lost.generation, lost.sequence,
                                kInfiniteRouteMetric};
    return true;
  }
  return false;
}

std::size_t MeshNode::append_scoped_base(RouteAdvertisement* records,
                                         const NodeId receiver) noexcept {
  std::size_t count = 0;
  records[count++] = RouteAdvertisement{config_.node, config_.route_generation,
                                        self_route_sequence_, 0};
  for (std::size_t i = 0; i < config_.route_gateways.size(); ++i) {
    const NodeId gateway = config_.route_gateways[i];
    if (gateway == kInvalidNodeId || gateway == config_.node) continue;
    bool duplicate = false;
    for (std::size_t j = 0; j < i; ++j) duplicate |= config_.route_gateways[j] == gateway;
    if (duplicate) continue;
    RouteAdvertisement record{};
    if (scoped_record(gateway, receiver, record)) records[count++] = record;
  }
  return count;
}

Status MeshNode::enqueue_route_records(const NodeId neighbor,
                                       const RouteAdvertisement* records,
                                       const std::size_t count,
                                       const MonotonicMs now_ms) noexcept {
  if (count == 0 || count > kRouteUpdateMaxRecords) {
    return Status::error(StatusCode::InvalidArgument, "route record count");
  }
  TxJob job = link_control_job(FrameType::RouteUpdate, neighbor, kScopedUpdateLifetimeMs,
                               now_ms);
  ByteWriter writer(MutableByteView{job.plain.payload.data(), job.plain.payload.size()});
  Status status = writer.write_u8(static_cast<std::uint8_t>(count));
  for (std::size_t i = 0; status && i < count; ++i) {
    status = writer.write_u64(records[i].destination);
    if (status) status = writer.write_u32(records[i].generation);
    if (status) status = writer.write_u16(records[i].sequence);
    if (status) status = writer.write_u16(records[i].metric);
  }
  if (!status) return status;
  job.plain.payload_size = writer.size();
  return scheduler_.enqueue(std::move(job), config_.node, now_ms);
}

Status MeshNode::queue_scoped_update(const NodeId neighbor, const NodeId extra,
                                     const MonotonicMs now_ms) noexcept {
  std::array<RouteAdvertisement, kRouteUpdateMaxRecords> records{};
  std::size_t count = append_scoped_base(records.data(), neighbor);
  if (extra != kInvalidNodeId && extra != config_.node && !is_route_gateway(extra) &&
      count < records.size()) {
    RouteAdvertisement record{};
    if (scoped_record(extra, neighbor, record)) records[count++] = record;
  }
  return enqueue_route_records(neighbor, records.data(), count, now_ms);
}

bool MeshNode::broadcast_tx_ready() noexcept {
  std::uint32_t boot = 0;
  std::uint32_t g = 0;
  // A side-effect-free snapshot: the provider draws no counter for it, so
  // asking per batch cannot burn the GroupLink counter space.
  return security_.tx_group_link_epochs(boot, g).ok() && boot != 0 && g != 0;
}

bool MeshNode::build_broadcast_records(BroadcastRouteRecord* records,
                                       std::size_t& count) noexcept {
  count = 0;
  if (records == nullptr) return false;
  records[count++] = BroadcastRouteRecord{
      RouteAdvertisement{config_.node, config_.route_generation, self_route_sequence_, 0},
      kInvalidNodeId};
  for (std::size_t i = 0; i < config_.route_gateways.size(); ++i) {
    const NodeId gateway = config_.route_gateways[i];
    if (gateway == kInvalidNodeId || gateway == config_.node) continue;
    bool duplicate = false;
    for (std::size_t j = 0; j < i; ++j) duplicate |= config_.route_gateways[j] == gateway;
    if (duplicate) continue;
    // The broadcast must carry the same base the unicast would — never a
    // silently shortened one. (Unreachable with four gateways or fewer.)
    if (count >= kBroadcastRouteMaxRecords) return false;
    const auto selection = routes_.best(gateway);
    if (selection.valid && selection.generation == 0) continue;  // placeholder: see scoped_record
    if (!selection.valid) {
      RouteTable::LostRoute lost{};
      if (!routes_.lost_route(gateway, lost)) continue;
      records[count++] = BroadcastRouteRecord{
          RouteAdvertisement{gateway, lost.generation, lost.sequence, kInfiniteRouteMetric},
          kInvalidNodeId};
      continue;
    }
    if (!relay_enabled_) {
      // Relay-off withdrawal (01 §policy): infinity to every listener. via
      // stays invalid — no single next hop is poisoned, everybody is.
      records[count++] = BroadcastRouteRecord{
          RouteAdvertisement{gateway, selection.generation, selection.sequence,
                             kInfiniteRouteMetric},
          kInvalidNodeId};
      continue;
    }
    // A gateway on a direct link has no third-node via: only unicast can
    // poison that next hop without starving another listener, so the whole
    // batch falls back to unicast.
    if (selection.next_hop == gateway) return false;
    records[count++] = BroadcastRouteRecord{
        RouteAdvertisement{gateway, selection.generation, selection.sequence,
                           selection.metric},
        selection.next_hop};
    routes_.mark_advertised(gateway);
  }
  return true;
}

Status MeshNode::queue_broadcast_route_update(const MonotonicMs now_ms) noexcept {
  std::array<BroadcastRouteRecord, kBroadcastRouteMaxRecords> records{};
  std::size_t count = 0;
  if (!build_broadcast_records(records.data(), count)) {
    return Status::error(StatusCode::InvalidState, "route broadcast not buildable");
  }
  TxJob job = link_control_job(FrameType::RouteUpdate, kBroadcastNodeId,
                               kScopedUpdateLifetimeMs, now_ms);
  std::size_t written = 0;
  const auto status = encode_broadcast_route_update(
      records.data(), count, config_.node,
      MutableByteView{job.plain.payload.data(), job.plain.payload.size()}, written);
  if (!status) return status;
  job.plain.payload_size = written;
  return scheduler_.enqueue(std::move(job), config_.node, now_ms);
}

bool MeshNode::emit_downward_batch(const NodeId* targets, const std::size_t count,
                                   const MonotonicMs now_ms) noexcept {
  if (targets == nullptr) return true;
  std::array<NodeId, kNeighborCapacity> eligible{};
  std::size_t eligible_count = 0;
  std::array<NodeId, kNeighborCapacity> others{};
  std::size_t other_count = 0;
  // Both call sites pass at most kNeighborCapacity targets.
  for (std::size_t i = 0; i < count; ++i) {
    if (config_.route_broadcast && peer_broadcast_eligible(targets[i], now_ms)) {
      eligible[eligible_count++] = targets[i];
    } else {
      others[other_count++] = targets[i];
    }
  }
  // One broadcast replaces two or more eligible unicasts; a lone eligible
  // target keeps unicast — a broadcast to one listener saves nothing. Any
  // failure (no GK, unbuildable records, full queue) falls back to the
  // plain unicast loop below, exactly as without the opt-in.
  if (eligible_count >= 2 && broadcast_tx_ready() &&
      queue_broadcast_route_update(now_ms)) {
    saturating_inc(route_scale_stats_.broadcast_frames);
    for (std::size_t i = 0; i < other_count; ++i) {
      if (scheduler_.full()) return false;
      if (queue_scoped_update(others[i], kInvalidNodeId, now_ms)) {
        saturating_inc(route_scale_stats_.downward_frames);
      }
    }
    return true;
  }
  for (std::size_t i = 0; i < count; ++i) {
    if (scheduler_.full()) return false;
    if (queue_scoped_update(targets[i], kInvalidNodeId, now_ms)) {
      saturating_inc(route_scale_stats_.downward_frames);
    }
  }
  return true;
}

std::size_t MeshNode::emit_upward(UpwardCycle& cycle, const std::size_t max_frames,
                                  const MonotonicMs now_ms) noexcept {
  std::size_t frames = 0;
  while (cycle.active && frames < max_frames && !scheduler_.full()) {
    std::array<RouteAdvertisement, kRouteUpdateMaxRecords> records{};
    std::size_t count = append_scoped_base(records.data(), cycle.parent);
    const std::size_t base = count;
    std::size_t index = 0;
    std::size_t taken = 0;
    bool more = false;
    // Stable pool order; a table change mid-cycle can shift one record past
    // the cursor, which the two-cycle lease absorbs (routing-scale.md §5).
    routes_.for_each_selected([&](const RouteSelection& selection) {
      if (!upward_eligible(selection, cycle.parent, now_ms)) return;
      if (index++ < cycle.cursor) return;
      if (count >= records.size()) {
        more = true;
        return;
      }
      records[count++] = RouteAdvertisement{
          selection.destination, selection.generation, selection.sequence,
          relay_enabled_ ? selection.metric : kInfiniteRouteMetric};
      ++taken;
    });
    // FD tightens before the finite records leave (for_each_selected is a
    // read-only walk, so the marks follow it).
    for (std::size_t i = base; i < count; ++i) {
      const bool finite = records[i].metric != kInfiniteRouteMetric;
      if (finite) routes_.mark_advertised(records[i].destination);
      routes_.set_announced_up(records[i].destination, finite);
    }
    if (!enqueue_route_records(cycle.parent, records.data(), count, now_ms)) break;
    saturating_inc(route_scale_stats_.upward_frames);
    cycle.cursor += taken;
    ++frames;
    if (!more) cycle.active = false;
  }
  return frames;
}

bool MeshNode::upward_change_record(const NodeId destination, const NodeId parent,
                                    const MonotonicMs now_ms,
                                    RouteAdvertisement& record) noexcept {
  const auto selection = routes_.best(destination);
  if (upward_eligible(selection, parent, now_ms)) {
    // Still (or newly) in our subtree: the current route, FD first.
    record = RouteAdvertisement{destination, selection.generation, selection.sequence,
                                relay_enabled_ ? selection.metric : kInfiniteRouteMetric};
    const bool finite = record.metric != kInfiniteRouteMetric;
    if (finite) routes_.mark_advertised(destination);
    routes_.set_announced_up(destination, finite);
    return true;
  }
  if (!routes_.announced_up(destination)) return false;
  // Left our subtree or lost: retract what the parent holds from us. A
  // retraction of a route we still use is legal (infinity only ever removes
  // a candidate) and keeps the ancestors from routing into a stale branch.
  if (selection.valid) {
    record = RouteAdvertisement{destination, selection.generation, selection.sequence,
                                kInfiniteRouteMetric};
  } else {
    RouteTable::LostRoute lost{};
    if (!routes_.lost_route(destination, lost)) {
      routes_.set_announced_up(destination, false);
      return false;
    }
    record = RouteAdvertisement{destination, lost.generation, lost.sequence,
                                kInfiniteRouteMetric};
  }
  routes_.set_announced_up(destination, false);
  return true;
}

void MeshNode::emit_upward_dirty(const NodeId parent, const MonotonicMs now_ms) noexcept {
  std::size_t next = 0;
  do {
    if (scheduler_.full()) return;
    std::array<RouteAdvertisement, kRouteUpdateMaxRecords> records{};
    std::size_t count = append_scoped_base(records.data(), parent);
    while (next < scoped_dirty_count_ && count < records.size()) {
      RouteAdvertisement record{};
      if (upward_change_record(scoped_dirty_[next], parent, now_ms, record)) {
        records[count++] = record;
      }
      ++next;
    }
    if (!enqueue_route_records(parent, records.data(), count, now_ms)) return;
    saturating_inc(route_scale_stats_.upward_frames);
  } while (next < scoped_dirty_count_);
}

void MeshNode::emit_upward_retractions(const NodeId parent, const MonotonicMs now_ms) noexcept {
  // Overflow fallback for emit_upward_dirty: sweep every destination we
  // announced upward that is no longer in our subtree (lost routes reach the
  // dirty list through the selection scan and decay if it overflowed).
  std::array<RouteAdvertisement, kRouteUpdateMaxRecords> records{};
  std::size_t count = append_scoped_base(records.data(), parent);
  const std::size_t base = count;
  bool full = false;
  routes_.for_each_selected([&](const RouteSelection& selection) {
    if (full || !routes_.announced_up(selection.destination) ||
        upward_eligible(selection, parent, now_ms)) {
      return;
    }
    if (count == records.size()) {
      if (scheduler_.full() || !enqueue_route_records(parent, records.data(), count, now_ms)) {
        full = true;
        return;
      }
      saturating_inc(route_scale_stats_.upward_frames);
      count = append_scoped_base(records.data(), parent);
    }
    records[count++] = RouteAdvertisement{selection.destination, selection.generation,
                                          selection.sequence, kInfiniteRouteMetric};
    routes_.set_announced_up(selection.destination, false);
  });
  if (!full && count > base && !scheduler_.full() &&
      enqueue_route_records(parent, records.data(), count, now_ms)) {
    saturating_inc(route_scale_stats_.upward_frames);
  }
}

// --- Periodic and triggered schedules --------------------------------------------

void MeshNode::note_scoped_interest(Neighbor& neighbor, const MonotonicMs now_ms) const noexcept {
  // Short-lived: long enough for a pending answer (a route we are about to
  // learn, a fresher sequence) to be pushed, short enough that a bootstrap
  // pull does not turn every neighbor into a push target for a whole lease.
  neighbor.interest_until_ms = now_ms + kScopedInterestPeriods *
                                            static_cast<MonotonicMs>(
                                                config_.route_advertisement_period_ms);
}

void MeshNode::defer_parent_release(const std::size_t index, const NodeId old_parent,
                                    const MonotonicMs now_ms) noexcept {
  // The former parent learns it lost a child only after the new parent had
  // time to carry our subtree upward: the retraction the former parent then
  // sends races a route that is already there, not one still in flight.
  if (old_parent == kInvalidNodeId || index >= release_parent_.size()) return;
  if (release_parent_[index] != kInvalidNodeId && release_parent_[index] != old_parent) {
    release_parent(release_parent_[index], now_ms);  // an older notice is due now
  }
  release_parent_[index] = old_parent;
  release_at_ms_[index] = now_ms + kScopedReleaseDelayMs;
}

void MeshNode::schedule_parent_releases(const MonotonicMs now_ms) noexcept {
  for (std::size_t i = 0; i < release_parent_.size(); ++i) {
    if (release_parent_[i] == kInvalidNodeId || now_ms < release_at_ms_[i]) continue;
    const NodeId old_parent = release_parent_[i];
    release_parent_[i] = kInvalidNodeId;
    // Back with the same parent in the meantime: nothing to release.
    if (old_parent == upward_[i].parent) continue;
    release_parent(old_parent, now_ms);
  }
}

void MeshNode::release_parent(const NodeId old_parent, const MonotonicMs now_ms) noexcept {
  // The previous parent learns at once that we no longer route through it
  // (our gateway record toward it is finite again), so it stops treating us
  // as a child instead of refreshing us for a whole lease.
  if (old_parent == kInvalidNodeId || scheduler_.full()) return;
  const auto* record = find_neighbor(old_parent);
  if (record == nullptr || !record->active) return;
  if (queue_scoped_update(old_parent, kInvalidNodeId, now_ms)) {
    saturating_inc(route_scale_stats_.other_frames);
  }
}

void MeshNode::run_scoped_tick(const MonotonicMs now_ms) noexcept {
  const std::uint32_t ticks = std::max<std::uint32_t>(1, config_.route_refresh_ticks);
  ++scoped_tick_;
  std::array<NodeId, kMaxRouteGateways> parents{};
  std::size_t parent_count = 0;
  for (std::size_t i = 0; i < config_.route_gateways.size(); ++i) {
    const NodeId gateway = config_.route_gateways[i];
    UpwardCycle& cycle = upward_[i];
    if (gateway == kInvalidNodeId || gateway == config_.node) {
      cycle = UpwardCycle{};
      continue;
    }
    const auto selection = routes_.best(gateway);
    const auto* record = selection.valid ? find_neighbor(selection.next_hop) : nullptr;
    if (record == nullptr || !record->active) {
      cycle = UpwardCycle{};
      continue;
    }
    const NodeId parent = selection.next_hop;
    bool duplicate = false;
    for (std::size_t j = 0; j < parent_count; ++j) duplicate |= parents[j] == parent;
    if (duplicate) {
      cycle = UpwardCycle{};  // the first gateway's cycle already covers it
      continue;
    }
    parents[parent_count++] = parent;
    if (cycle.parent != parent) {
      defer_parent_release(i, cycle.parent, now_ms);
      cycle = UpwardCycle{parent, 0, true};
    } else if ((scoped_tick_ + scoped_link_phase(parent)) % ticks == 0) {
      cycle.cursor = 0;
      cycle.active = true;
    }
    if (cycle.active) emit_upward(cycle, kScopedMaxUpFramesPerTick, now_ms);
  }
  auto is_parent = [&](const NodeId node) {
    for (std::size_t j = 0; j < parent_count; ++j) {
      if (parents[j] == node) return true;
    }
    return false;
  };
  // Children: one downward refresh per cycle, on the link's own phase.
  std::array<NodeId, kNeighborCapacity> due{};
  std::size_t due_count = 0;
  std::array<NodeId, kNeighborCapacity> others{};
  std::size_t other_count = 0;
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (!neighbor.active || is_parent(neighbor.node)) return;
    if (neighbor.child_until_ms > now_ms) {
      if ((scoped_tick_ + scoped_link_phase(neighbor.node)) % ticks == 0) {
        due[due_count++] = neighbor.node;
      }
    } else {
      others[other_count++] = neighbor.node;
    }
  });
  // Due children share one broadcast when two or more are eligible;
  // anything else keeps its unicast (P5-2 batching, routing-scale.md §8).
  if (!emit_downward_batch(due.data(), due_count, now_ms)) return;
  // Slow rotation over non-tree neighbors: keeps a backup candidate and lets
  // a better parent be found without refreshing every link every cycle.
  if (other_count != 0 &&
      (scoped_tick_ + scoped_link_phase(config_.node)) % (ticks * kScopedOtherCycles) == 0 &&
      !scheduler_.full()) {
    const NodeId peer = others[scoped_other_cursor_++ % other_count];
    if (queue_scoped_update(peer, kInvalidNodeId, now_ms)) {
      saturating_inc(route_scale_stats_.other_frames);
    }
  }
}

void MeshNode::run_scoped_triggered(const MonotonicMs now_ms) noexcept {
  const bool all = scoped_trigger_all_;
  const bool up = all || scoped_dirty_count_ != 0 || scoped_dirty_overflow_;
  const bool down = all || scoped_down_dirty_;
  std::array<NodeId, kMaxRouteGateways> parents{};
  std::size_t parent_count = 0;
  for (std::size_t i = 0; i < config_.route_gateways.size(); ++i) {
    const NodeId gateway = config_.route_gateways[i];
    UpwardCycle& cycle = upward_[i];
    if (gateway == kInvalidNodeId || gateway == config_.node) continue;
    const auto selection = routes_.best(gateway);
    const auto* record = selection.valid ? find_neighbor(selection.next_hop) : nullptr;
    if (record == nullptr || !record->active) {
      cycle = UpwardCycle{};
      continue;
    }
    const NodeId parent = selection.next_hop;
    bool duplicate = false;
    for (std::size_t j = 0; j < parent_count; ++j) duplicate |= parents[j] == parent;
    if (duplicate) continue;
    parents[parent_count++] = parent;
    if (cycle.parent != parent || scoped_dirty_overflow_) {
      // New parent (or too many changes to list): the whole subtree goes up
      // now, so downward reachability follows the tree without waiting for
      // the next periodic cycle.
      if (cycle.parent != parent) defer_parent_release(i, cycle.parent, now_ms);
      cycle = UpwardCycle{parent, 0, true};
      emit_upward(cycle, kScopedMaxUpFramesPerTick, now_ms);
      if (scoped_dirty_overflow_) emit_upward_retractions(parent, now_ms);
    } else if (up) {
      emit_upward_dirty(parent, now_ms);
    }
  }
  if (down) {
    std::array<NodeId, kNeighborCapacity> targets{};
    std::size_t target_count = 0;
    neighbors_.for_each([&](const Neighbor& neighbor) {
      if (!neighbor.active) return;
      for (std::size_t j = 0; j < parent_count; ++j) {
        if (parents[j] == neighbor.node) return;
      }
      if (neighbor.child_until_ms > now_ms || neighbor.interest_until_ms > now_ms) {
        targets[target_count++] = neighbor.node;
      }
    });
    // Triggered downward batch: same batching rule as the periodic tick
    // (one broadcast for two-plus eligible targets, unicast otherwise). A
    // mid-batch full scheduler still clears the dirty flags below — a
    // re-armed trigger, not a stuck one, carries the loss (as before).
    (void)emit_downward_batch(targets.data(), target_count, now_ms);
  }
  scoped_dirty_count_ = 0;
  scoped_dirty_overflow_ = false;
  scoped_down_dirty_ = false;
  scoped_trigger_all_ = false;
}

// --- Pull (1-hop ROUTE_REQUEST): bootstrap and repair ----------------------------

void MeshNode::schedule_gateway_pulls(const MonotonicMs now_ms) noexcept {
  for (std::size_t i = 0; i < config_.route_gateways.size(); ++i) {
    const NodeId gateway = config_.route_gateways[i];
    if (gateway == kInvalidNodeId || gateway == config_.node) continue;
    bool duplicate = false;
    for (std::size_t j = 0; j < i; ++j) duplicate |= config_.route_gateways[j] == gateway;
    if (duplicate) continue;
    const auto selection = routes_.best(gateway);
    // A generation-0 route is only the add_neighbor() placeholder of a
    // gateway next door: pull its real self record too.
    if (selection.valid && selection.generation != 0) {
      pull_attempts_[i] = 0;
      pull_next_ms_[i] = 0;
      continue;
    }
    if (now_ms < pull_next_ms_[i] || scheduler_.full()) continue;
    const RouteRequestPayload payload{
        RouteRequestKind::Neighbor, 1, config_.node, gateway, next_route_request_id_++,
        RouteAdvertisement{config_.node, config_.route_generation, self_route_sequence_, 0}};
    std::size_t neighbors = 0;
    neighbors_.for_each([&](const Neighbor& neighbor) {
      if (!neighbor.active) return;
      ++neighbors;
      if (scheduler_.full()) return;
      if (queue_route_request(neighbor.node, payload, now_ms)) {
        saturating_inc(route_scale_stats_.pulls_sent);
      }
    });
    if (neighbors == 0) {
      pull_next_ms_[i] = now_ms + kPullBaseMs;  // nobody to ask yet: no attempt spent
      continue;
    }
    if (pull_attempts_[i] != UINT8_MAX) ++pull_attempts_[i];
    const std::uint32_t shift = std::min<std::uint32_t>(pull_attempts_[i] - 1U, 5U);
    const std::uint32_t backoff = std::min<std::uint32_t>(kPullMaxMs, kPullBaseMs << shift);
    // Deterministic spread so a partitioned neighborhood does not re-pull in
    // lockstep.
    pull_next_ms_[i] = now_ms + backoff + (config_.node * 37ULL) % 250ULL;
  }
}

void MeshNode::flush_pull_answers(const MonotonicMs now_ms) noexcept {
  std::array<NodeId, kNeighborCapacity> answer{};
  std::array<NodeId, kNeighborCapacity> target{};
  std::size_t count = 0;
  neighbors_.for_each([&](Neighbor& neighbor) {
    if (!neighbor.active || !neighbor.pull_answer_pending) return;
    if (neighbor.last_pull_answer_ms != 0 &&
        now_ms - neighbor.last_pull_answer_ms < kPullAnswerGapMs) {
      return;  // coalesced: stays pending until the gap passes
    }
    neighbor.pull_answer_pending = false;
    const NodeId wanted = neighbor.pull_target;
    // Nothing useful to say yet: the interest mark makes the triggered
    // update carry the route to this neighbor as soon as we learn it.
    // (kInvalidNodeId = a plain self + gateway refresh for a new child.)
    if (wanted != kInvalidNodeId && wanted != config_.node &&
        !routes_.best(wanted).valid) {
      return;
    }
    neighbor.last_pull_answer_ms = now_ms;
    answer[count] = neighbor.node;
    target[count++] = wanted;
  });
  for (std::size_t i = 0; i < count; ++i) {
    if (scheduler_.full()) return;
    if (queue_scoped_update(answer[i], target[i], now_ms)) {
      saturating_inc(route_scale_stats_.pull_answers);
    }
  }
}

// --- On-demand discovery (Discover / Reply) --------------------------------------

void MeshNode::request_route_discovery(const NodeId destination,
                                       const MonotonicMs now_ms) noexcept {
  if (!gateway_scoped() || reserved_node(destination) || destination == config_.node ||
      is_route_gateway(destination) || routes_.best(destination).valid) {
    return;
  }
  if (auto* state = discoveries_.find(
          [&](const DiscoveryState& value) { return value.target == destination; })) {
    state->expires_at_ms = now_ms + kDiscoveryDwellMs;  // still needed
    return;
  }
  auto* state = discoveries_.allocate();
  if (state == nullptr) {
    saturating_inc(route_scale_stats_.route_requests_dropped);
    return;  // bounded: the delivery keeps waiting and asks again later
  }
  *state = DiscoveryState{destination, now_ms, now_ms + kDiscoveryDwellMs, 0};
  saturating_inc(route_scale_stats_.discoveries_started);
}

void MeshNode::schedule_route_discovery(const MonotonicMs now_ms) noexcept {
  while (auto* done = discoveries_.find([&](const DiscoveryState& value) {
           return value.expires_at_ms <= now_ms || routes_.best(value.target).valid;
         })) {
    if (routes_.best(done->target).valid) {
      saturating_inc(route_scale_stats_.discoveries_resolved);
    }
    discoveries_.release(done);
  }
  discoveries_.for_each([&](DiscoveryState& state) {
    if (now_ms < state.next_request_ms || scheduler_.full()) return;
    if (state.attempts != UINT8_MAX) ++state.attempts;
    state.next_request_ms =
        now_ms + std::min<std::uint32_t>(kDiscoveryMaxMs, kDiscoveryBaseMs * state.attempts);
    // Toward the gateway: the tree root (or the first ancestor that holds
    // the target in its subtree) turns the request down toward the target.
    // A node without an uplink (the gateway itself) cannot discover — its
    // table already holds every subtree route.
    const NodeId next = scoped_uplink(kInvalidNodeId);
    if (next == kInvalidNodeId) return;
    const std::uint32_t request_id = next_route_request_id_++;
    auto* seen = route_request_seen_.allocate();
    if (seen == nullptr) return;
    *seen = RouteRequestSeen{config_.node, request_id,
                             static_cast<std::uint8_t>(RouteRequestKind::Discover),
                             kInvalidNodeId, now_ms + kRouteRequestSeenMs};
    const RouteRequestPayload payload{
        RouteRequestKind::Discover, kRouteRequestMaxTtl, config_.node, state.target,
        request_id,
        RouteAdvertisement{config_.node, config_.route_generation, self_route_sequence_, 0}};
    if (queue_route_request(next, payload, now_ms)) {
      saturating_inc(route_scale_stats_.discovery_requests_sent);
    } else {
      route_request_seen_.release(seen);
    }
  });
}

void MeshNode::expire_route_requests(const MonotonicMs now_ms) noexcept {
  while (auto* expired = route_request_seen_.find(
             [&](const RouteRequestSeen& value) { return value.expires_at_ms <= now_ms; })) {
    route_request_seen_.release(expired);
  }
}

bool MeshNode::route_request_forward_budget(const MonotonicMs now_ms) noexcept {
  if (now_ms - route_request_window_ms_ >= kRouteRequestWindowMs) {
    route_request_window_ms_ = now_ms;
    route_request_window_count_ = 0;
  }
  if (route_request_window_count_ >= kRouteRequestForwardsPerWindow) return false;
  ++route_request_window_count_;
  return true;
}

Status MeshNode::queue_route_request(const NodeId peer, const RouteRequestPayload& payload,
                                     const MonotonicMs now_ms) noexcept {
  TxJob job = link_control_job(FrameType::RouteRequest, peer, kRouteRequestLifetimeMs, now_ms);
  std::size_t written = 0;
  const auto status = encode_route_request(
      payload, MutableByteView{job.plain.payload.data(), job.plain.payload.size()}, written);
  if (!status) return status;
  job.plain.payload_size = written;
  return scheduler_.enqueue(std::move(job), config_.node, now_ms);
}

void MeshNode::handle_route_request(const wire::PlainFrame& frame, const NodeId peer,
                                    const MonotonicMs now_ms) noexcept {
  auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || !neighbor->active) return;
  if (!gateway_scoped()) {
    // The flat profile never emits ROUTE_REQUEST; a stray one is ignored.
    observer_.on_diagnostic("ROUTE_REQUEST_UNSUPPORTED", peer, &frame.header.message);
    return;
  }
  RouteRequestPayload request{};
  if (!decode_route_request(ByteView{frame.payload.data(), frame.payload_size}, request)) {
    saturating_inc(route_scale_stats_.route_requests_dropped);
    observer_.on_diagnostic("INVALID_ROUTE_REQUEST", peer, &frame.header.message);
    return;
  }
  // The embedded record is an ordinary advertisement from `peer`: the same
  // feasibility / generation / hold-down rules as a ROUTE_UPDATE record.
  auto consider_record = [&](const RouteAdvertisement& record) {
    if (record.destination == config_.node) return;
    const auto result = routes_.consider(record, peer, neighbor->link_cost, now_ms,
                                         config_.route_lifetime_ms);
    if (result == RouteUpdateResult::Infeasible) {
      observer_.on_diagnostic("ROUTE_INFEASIBLE_SEQNO_NEEDED", peer, nullptr);
    }
  };

  if (request.kind == RouteRequestKind::Neighbor) {
    if (request.requester != peer) {
      saturating_inc(route_scale_stats_.route_requests_dropped);
      observer_.on_diagnostic("INVALID_ROUTE_REQUEST", peer, &frame.header.message);
      return;
    }
    consider_record(request.record);
    note_scoped_interest(*neighbor, now_ms);
    neighbor->pull_target = request.target;
    neighbor->pull_answer_pending = true;  // answered from poll(), coalesced
    return;
  }

  const auto kind = static_cast<std::uint8_t>(request.kind);
  if (request.requester == config_.node && request.kind == RouteRequestKind::Discover) {
    saturating_inc(route_scale_stats_.route_requests_dropped);  // our own, looped back
    return;
  }
  if (route_request_seen_.find([&](const RouteRequestSeen& value) {
        return value.requester == request.requester && value.request_id == request.request_id &&
               value.kind == kind;
      }) != nullptr) {
    saturating_inc(route_scale_stats_.route_requests_dropped);  // one forward per request
    return;
  }
  auto* seen = route_request_seen_.allocate();
  if (seen == nullptr) {
    saturating_inc(route_scale_stats_.route_requests_dropped);
    observer_.on_diagnostic("ROUTE_REQUEST_DEDUP_FULL", peer, &frame.header.message);
    return;
  }
  *seen = RouteRequestSeen{request.requester, request.request_id, kind, peer,
                           now_ms + kRouteRequestSeenMs};
  consider_record(request.record);
  // Capture selection changes before this path's own mark_advertised() can
  // sync the advertised snapshot ahead of the poll scan.
  scan_selection_changes(now_ms);

  if (request.kind == RouteRequestKind::Discover) {
    if (request.target == config_.node) {
      // The target answers with its own self record; the reply retraces the
      // request hop by hop via the reverse-path pointers.
      const RouteRequestPayload reply{
          RouteRequestKind::Reply, kRouteRequestMaxTtl, request.requester, config_.node,
          request.request_id,
          RouteAdvertisement{config_.node, config_.route_generation, self_route_sequence_, 0}};
      if (queue_route_request(peer, reply, now_ms)) {
        saturating_inc(route_scale_stats_.discovery_replies_sent);
      }
      return;
    }
    if (request.ttl <= 1 || !route_request_forward_budget(now_ms)) {
      saturating_inc(route_scale_stats_.route_requests_dropped);
      return;
    }
    // Down toward the target once some ancestor holds it in its subtree,
    // otherwise further up the gateway tree. Never back to the sender.
    const auto toward = routes_.best(request.target);
    const NodeId next = (toward.valid && toward.next_hop != peer) ? toward.next_hop
                                                                  : scoped_uplink(peer);
    if (next == kInvalidNodeId) {
      saturating_inc(route_scale_stats_.route_requests_dropped);
      observer_.on_diagnostic("ROUTE_REQUEST_NO_PATH", peer, &frame.header.message);
      return;
    }
    RouteRequestPayload forward = request;
    forward.ttl = static_cast<std::uint8_t>(request.ttl - 1U);
    // Our own route to the requester, advertised to `next` (a retraction
    // when we hold none — the receiver then simply has no reverse route).
    if (!scoped_record(request.requester, next, forward.record)) {
      forward.record = RouteAdvertisement{request.requester, request.record.generation,
                                          request.record.sequence, kInfiniteRouteMetric};
    }
    if (queue_route_request(next, forward, now_ms)) {
      saturating_inc(route_scale_stats_.discovery_requests_forwarded);
    }
    return;
  }

  // Reply.
  if (request.requester == config_.node) return;  // route installed above
  const auto* pointer = route_request_seen_.find([&](const RouteRequestSeen& value) {
    return value.requester == request.requester && value.request_id == request.request_id &&
           value.kind == static_cast<std::uint8_t>(RouteRequestKind::Discover);
  });
  if (pointer == nullptr || pointer->previous_hop == kInvalidNodeId || request.ttl <= 1) {
    saturating_inc(route_scale_stats_.route_requests_dropped);
    return;
  }
  const NodeId back = pointer->previous_hop;
  RouteRequestPayload forward = request;
  forward.ttl = static_cast<std::uint8_t>(request.ttl - 1U);
  if (!scoped_record(request.target, back, forward.record) ||
      forward.record.metric == kInfiniteRouteMetric) {
    // No feasible route to pass on (consider() flagged the sequence need).
    saturating_inc(route_scale_stats_.route_requests_dropped);
    observer_.on_diagnostic("ROUTE_REPLY_NO_ROUTE", peer, &frame.header.message);
    return;
  }
  if (queue_route_request(back, forward, now_ms)) {
    saturating_inc(route_scale_stats_.discovery_replies_forwarded);
  }
}

// --- P5-2 broadcast route advertisements (routing-scale.md §8) -------------------

void MeshNode::handle_broadcast_route(const NodeId peer, const ByteView encoded,
                                      const RadioRxMetadataV2* const metadata,
                                      const MonotonicMs now_ms) noexcept {
  // The strict shape was peeked by the caller; re-derive it here (no crypto)
  // so every gate below reads the same bytes the open will authenticate.
  wire::Header claimed{};
  if (!wire::peek_header(encoded, claimed) || claimed.next_hop != kBroadcastNodeId) {
    return;
  }
  // Sender gates BEFORE the GroupLink open: the attributed transmitter must
  // be the claimed origin (observed MAC), an active neighbor (REACHABLE in
  // the core: admitted, never removed), under a usable pairwise Link
  // context and — when the runtime carries binding evidence — a current
  // binding. None of this proves identity; it only refuses to spend a group
  // open on senders the pairwise layer does not vouch for.
  const auto* neighbor = find_neighbor(claimed.origin);
  if (claimed.origin != peer || neighbor == nullptr || !neighbor->active ||
      !context_usable(security_.context_state(SecurityScope::Link, claimed.origin)) ||
      (metadata != nullptr && !metadata->identity_current)) {
    observer_.on_diagnostic("BROADCAST_ROUTE_SENDER_REJECTED", peer, nullptr);
    return;
  }
  wire::LinkOpenedFrame frame{};
  const auto opened = wire::open_link(encoded, config_.node, security_, frame,
                                      /*allow_broadcast_route=*/true);
  if (!opened) {
    note_rx_refusal(opened, peer, nullptr);
    ++telemetry_event_drops_;
    return;
  }
  // An unknown GK generation is a hint, not evidence: the Owner pulls the
  // key, at most once a minute however often the hint repeats.
  if (!security_.accepts_group_epoch(frame.header.end_epoch)) {
    if (last_broadcast_gk_hint_ms_ != 0 &&
        now_ms - last_broadcast_gk_hint_ms_ < kBroadcastGkHintGapMs) {
      return;
    }
    last_broadcast_gk_hint_ms_ = now_ms;
    observer_.on_diagnostic("BROADCAST_UNKNOWN_GK", peer, &frame.header.message);
    return;
  }
  // The frame is link-only (no end tag): the whole payload authenticates
  // under the GroupLink tag above and decodes only as one valid unit.
  std::array<BroadcastRouteRecord, kBroadcastRouteMaxRecords> records{};
  std::size_t count = 0;
  if (!decode_broadcast_route_update(
          ByteView{frame.protected_payload.data(), frame.header.payload_length},
          frame.header.origin, records, count)) {
    observer_.on_diagnostic("BROADCAST_ROUTE_REJECTED", peer, &frame.header.message);
    return;
  }
  // Per-receiver poison projection, then the single shared route entry —
  // the same feasibility/generation/hold-down rules as unicast. Grants,
  // telemetry, resume confirmation and link activity never move here: a
  // group tag proves no pairwise identity.
  std::array<RouteAdvertisement, kBroadcastRouteMaxRecords> projected{};
  for (std::size_t i = 0; i < count; ++i) {
    projected[i] = records[i].route;
    projected[i].metric = project_broadcast_route_metric(records[i], config_.node);
  }
  apply_route_records(projected.data(), count, frame.header.origin, now_ms);
}

}  // namespace routeloom
