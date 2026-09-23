// MeshNode node-status accessors (node_status.hpp). Kept out of node.cpp on
// purpose: these are read-only projections of the neighbor, route and
// telemetry tables and must never mutate delivery/dedup/routing state.

#include <cstdint>

#include "routeloom/node.hpp"

namespace routeloom {

namespace {

constexpr bool listable(const NodeId node, const NodeId self) noexcept {
  return node != kInvalidNodeId && node != kBroadcastNodeId && node != self;
}

}  // namespace

bool MeshNode::node_status(const NodeId node, const MonotonicMs now_ms,
                           NodeStatus& out) const noexcept {
  static_assert(kNeighborCapacity + kMaxRouteEntries <= kNodeStatusTrackCapacity,
                "node status track capacity must cover every listable node");
  if (!listable(node, config_.node)) return false;
  const Neighbor* neighbor = find_neighbor(node);
  if (neighbor == nullptr && !routes_.knows(node)) return false;

  out = NodeStatus{};
  out.node = node;
  if (neighbor != nullptr) {
    out.flags |= kNodeStatusNeighbor;
    if (neighbor->active) {
      out.flags |= kNodeStatusNeighborActive;
      out.link_cost = neighbor->link_cost;
    }
  }
  const RouteSelection selection = routes_.best(node);
  if (selection.valid) {
    out.flags |= kNodeStatusReachable;
    out.route_metric = selection.metric;
    out.next_hop = selection.next_hop;
    if (selection.next_hop == node) out.flags |= kNodeStatusDirect;
  }
  // RF evidence exists only for immediate transmitters that passed link
  // authentication (telemetry §2.3); multi-hop nodes stay "not heard".
  if (const PeerTelemetrySummary* summary = telemetry_peers_.find(node)) {
    if (summary->last_sample_ms <= now_ms) {
      const std::uint64_t age = now_ms - summary->last_sample_ms;
      out.heard_age_ms = age > UINT32_MAX ? UINT32_MAX : static_cast<std::uint32_t>(age);
      out.flags |= kNodeStatusHeardValid;
    }
    if (summary->rssi_present) {
      out.flags |= kNodeStatusRssiValid;
      out.rssi_last_dbm = summary->rssi_last;
      out.rssi_ewma_q8_8 = summary->rssi_ewma_q8_8;
    }
    if (summary->stale) out.flags |= kNodeStatusTelemetryStale;
  }
  return true;
}

std::size_t MeshNode::node_status_page(const NodeId after, NodeStatus* const out,
                                       const std::size_t capacity,
                                       const MonotonicMs now_ms,
                                       bool& more) const noexcept {
  more = false;
  if (out == nullptr) return 0;
  // Smallest listable id strictly greater than `cursor` across the union of
  // neighbor records and route destinations; kInvalidNodeId when none. A
  // selection scan per slot keeps this allocation-free: O(capacity * (32 +
  // 128)) comparisons, bounded by the page size the caller chose.
  const auto next_after = [&](const NodeId cursor) {
    NodeId best = kInvalidNodeId;
    const auto consider = [&](const NodeId candidate) {
      if (!listable(candidate, config_.node) || candidate <= cursor) return;
      if (best == kInvalidNodeId || candidate < best) best = candidate;
    };
    neighbors_.for_each([&](const Neighbor& neighbor) { consider(neighbor.node); });
    routes_.for_each_destination(consider);
    return best;
  };
  std::size_t count = 0;
  NodeId cursor = after;
  while (count < capacity) {
    const NodeId next = next_after(cursor);
    if (next == kInvalidNodeId) return count;
    if (node_status(next, now_ms, out[count])) ++count;
    cursor = next;
  }
  more = next_after(cursor) != kInvalidNodeId;
  return count;
}

}  // namespace routeloom
