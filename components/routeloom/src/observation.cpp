// Read-only observation fills (observation.hpp) and the MeshNode route-detail
// accessors. Kept beside node_status.cpp: pure projections of the neighbor,
// route, dedup and scheduler tables — no selection, lease, advertisement or
// delivery state is touched here.

#include "routeloom/observation.hpp"

#include <cstdint>

#include "routeloom/node.hpp"

namespace routeloom {

namespace {

constexpr bool listable(const NodeId node, const NodeId self) noexcept {
  return node != kInvalidNodeId && node != kBroadcastNodeId && node != self;
}

constexpr std::uint32_t kU32Max = UINT32_MAX;

std::uint32_t saturate_u32(const std::uint64_t value) noexcept {
  return value > kU32Max ? kU32Max : static_cast<std::uint32_t>(value);
}

std::uint16_t saturate_u16(const std::size_t value) noexcept {
  return value > UINT16_MAX ? UINT16_MAX : static_cast<std::uint16_t>(value);
}

// The dedup counters pin at UINT64_MAX individually; their sum must pin at
// UINT32_MAX for the wire, never wrap through it.
std::uint32_t saturate_sum_u32(const std::uint64_t a, const std::uint64_t b,
                               const std::uint64_t c) noexcept {
  const std::uint64_t parts[3] = {a, b, c};
  std::uint64_t acc = 0;
  for (const std::uint64_t part : parts) {
    if (part > kU32Max - acc) return kU32Max;
    acc += part;
  }
  return static_cast<std::uint32_t>(acc);
}

// FNV-1a over fixed-size integers (portable across node builds: the digest
// is a same-boot change cookie, never persisted or compared across builds).
class Digest {
 public:
  void add_u64(const std::uint64_t v) noexcept {
    for (int i = 7; i >= 0; --i) add_u8(static_cast<std::uint8_t>(v >> (i * 8)));
  }
  void add_u32(const std::uint32_t v) noexcept {
    for (int i = 3; i >= 0; --i) add_u8(static_cast<std::uint8_t>(v >> (i * 8)));
  }
  void add_u16(const std::uint16_t v) noexcept {
    add_u8(static_cast<std::uint8_t>(v >> 8));
    add_u8(static_cast<std::uint8_t>(v & 0xFFU));
  }
  void add_u8(const std::uint8_t v) noexcept {
    hash_ ^= v;
    hash_ *= 16777619U;
  }
  std::uint32_t finish() const noexcept { return hash_; }

 private:
  std::uint32_t hash_{2166136261U};
};

}  // namespace

bool MeshNode::route_detail(const NodeId destination, const MonotonicMs now_ms,
                            RouteDetailEntry& out) const noexcept {
  out = RouteDetailEntry{};
  if (!listable(destination, config_.node) || !routes_.knows(destination)) {
    return false;
  }
  out.destination = destination;
  const RouteSelection selection = routes_.best(destination);
  if (selection.valid) {
    out.next_hop = selection.next_hop;
    out.generation = selection.generation;
    out.sequence = selection.sequence;
    out.metric = selection.metric;
    out.valid = true;
    MonotonicMs remaining = 0;
    // A valid selection always names a live candidate; a miss here means
    // the table changed under a non-const caller — report 0, not a guess.
    out.remaining_ms = routes_.selection_remaining(destination, now_ms, remaining)
                           ? saturate_u32(remaining)
                           : 0;
    return true;
  }
  // Remembered but unselected (lost/tombstoned): carry the retraction
  // identity when the table still holds it, so the host can tell "lost"
  // from "never known" without re-pulling the whole table.
  RouteTable::LostRoute lost{};
  if (routes_.lost_route(destination, lost)) {
    out.generation = lost.generation;
    out.sequence = lost.sequence;
  }
  return true;
}

std::size_t MeshNode::route_detail_page(const NodeId after, RouteDetailEntry* const out,
                                        const std::size_t capacity,
                                        const MonotonicMs now_ms, bool& more) const noexcept {
  more = false;
  if (out == nullptr) return 0;
  // Same cursor idiom as node_status_page: smallest listable destination
  // strictly greater than the cursor, one selection scan per slot —
  // O(capacity * kMaxRouteEntries), bounded by the caller's page size.
  const auto next_after = [&](const NodeId cursor) {
    NodeId best = kInvalidNodeId;
    routes_.for_each_destination([&](const NodeId candidate) {
      if (!listable(candidate, config_.node) || candidate <= cursor) return;
      if (best == kInvalidNodeId || candidate < best) best = candidate;
    });
    return best;
  };
  std::size_t count = 0;
  NodeId cursor = after;
  while (count < capacity) {
    const NodeId next = next_after(cursor);
    if (next == kInvalidNodeId) return count;
    if (route_detail(next, now_ms, out[count])) ++count;
    cursor = next;
  }
  more = next_after(cursor) != kInvalidNodeId;
  return count;
}

std::size_t MeshNode::dedup_terminal_pins() const noexcept {
  std::size_t pins = 0;
  dedup_.for_each([&](const DedupEntry& entry) {
    if (entry.phase == DedupPhase::Terminal) ++pins;
  });
  return pins;
}

void fill_observation_system(const std::uint64_t boot_id, const MonotonicMs now_ms,
                             const SystemHealthPort& port, const std::uint8_t power_mode,
                             const std::uint8_t coord_mode, const std::uint8_t sec_profile,
                             ObservationSystem& out) noexcept {
  out = ObservationSystem{};
  out.boot_id = boot_id;
  out.uptime_ms = now_ms;  // tree-wide monotonic clock starts at boot
  out.heap_free_bytes = port.heap_free_bytes();
  out.heap_min_bytes = port.heap_min_bytes();
  out.heap_largest_bytes = port.heap_largest_bytes();
  out.reset_code = port.reset_code();
  out.power_mode = power_mode;
  out.coord_mode = coord_mode;
  out.sec_profile = sec_profile;
}

void observation_counts(const MeshNode& node, const MonotonicMs now_ms,
                        std::uint16_t& neighbor_active, std::uint16_t& neighbor_total,
                        std::uint16_t& route_reachable, std::uint16_t& route_total) noexcept {
  neighbor_active = neighbor_total = route_reachable = route_total = 0;
  // Neighbor flags come from the same projection nodes.list serves, so the
  // counts can never disagree with a paginated listing.
  std::size_t active = 0, total = 0, reachable = 0;
  NodeId cursor = kInvalidNodeId;
  bool more = true;
  while (more) {
    NodeStatus page[kObservationRoutesPageMax];
    const std::size_t n = node.node_status_page(cursor, page, sizeof(page) / sizeof(page[0]),
                                                now_ms, more);
    if (n == 0) break;
    for (std::size_t i = 0; i < n; ++i) {
      if ((page[i].flags & kNodeStatusNeighbor) != 0) ++total;
      if (page[i].neighbor_active()) ++active;
      if (page[i].reachable()) ++reachable;
    }
    cursor = page[n - 1].node;
  }
  std::size_t remembered = 0;
  const NodeId self = node.node_id();
  node.routes().for_each_destination([&](const NodeId candidate) {
    if (listable(candidate, self)) ++remembered;
  });
  neighbor_active = saturate_u16(active);
  neighbor_total = saturate_u16(total);
  route_reachable = saturate_u16(reachable);
  route_total = saturate_u16(remembered);
}

void fill_observation_tables(const MeshNode& node, const MonotonicMs now_ms,
                             const std::uint16_t link_sessions, const std::uint16_t link_cap,
                             const std::uint16_t end_sessions, const std::uint16_t end_cap,
                             ObservationTables& out) noexcept {
  out = ObservationTables{};
  observation_counts(node, now_ms, out.neighbor_active, out.neighbor_total,
                     out.route_reachable, out.route_total);
  out.link_sessions = link_sessions;
  out.link_cap = link_cap;
  out.end_sessions = end_sessions;
  out.end_cap = end_cap;
  out.dedup_resident = saturate_u16(node.dedup_resident());
  out.dedup_terminal = saturate_u16(node.dedup_terminal_pins());
  out.dedup_cap = saturate_u16(kDedupCapacity);
  const std::size_t tx_cap = MeshNode::tx_queue_capacity();
  const std::size_t tx_free = node.tx_free_slots();
  const std::size_t tx_used = tx_free >= tx_cap ? 0 : tx_cap - tx_free;
  out.tx_cap = tx_cap > UINT8_MAX ? UINT8_MAX : static_cast<std::uint8_t>(tx_cap);
  out.tx_used = tx_used > UINT8_MAX ? UINT8_MAX : static_cast<std::uint8_t>(tx_used);
  out.group_trees =
      node.group_trees_in_use() > UINT8_MAX ? UINT8_MAX
                                            : static_cast<std::uint8_t>(node.group_trees_in_use());
  out.group_origins = node.group_origins_in_use() > UINT8_MAX
                          ? UINT8_MAX
                          : static_cast<std::uint8_t>(node.group_origins_in_use());
  const DedupStats& dedup = node.dedup_stats();
  out.dedup_refused = saturate_sum_u32(dedup.refused_pool_full, dedup.refused_terminal_reserve,
                                       dedup.refused_upstream_cap);
  out.dedup_evicted = saturate_sum_u32(dedup.evicted_resolved, dedup.evicted_evidence,
                                       dedup.delivery_terminal_evicted);
}

std::uint32_t observation_route_digest(const MeshNode& node, const MonotonicMs now_ms) noexcept {
  Digest digest{};
  NodeId cursor = kInvalidNodeId;
  bool more = true;
  while (more) {
    RouteDetailEntry page[kObservationRoutesPageMax];
    const std::size_t n =
        node.route_detail_page(cursor, page, sizeof(page) / sizeof(page[0]), now_ms, more);
    if (n == 0) break;
    for (std::size_t i = 0; i < n; ++i) {
      digest.add_u64(page[i].destination);
      digest.add_u64(page[i].next_hop);
      digest.add_u32(page[i].generation);
      digest.add_u16(page[i].sequence);
      digest.add_u16(page[i].metric);
      digest.add_u8(page[i].valid ? 1 : 0);
    }
    cursor = page[n - 1].destination;
  }
  return digest.finish();
}

std::uint32_t observation_neighbor_digest(const MeshNode& node,
                                          const MonotonicMs now_ms) noexcept {
  Digest digest{};
  NodeId cursor = kInvalidNodeId;
  bool more = true;
  while (more) {
    NodeStatus page[kObservationRoutesPageMax];
    const std::size_t n = node.node_status_page(cursor, page, sizeof(page) / sizeof(page[0]),
                                                now_ms, more);
    if (n == 0) break;
    // Active-neighbor id set only: RSSI ages and metrics move every second
    // and must not look like structural change.
    for (std::size_t i = 0; i < n; ++i) {
      if (page[i].neighbor_active()) digest.add_u64(page[i].node);
    }
    cursor = page[n - 1].node;
  }
  return digest.finish();
}

void fill_observation_summary(const MeshNode& node, const MonotonicMs now_ms,
                              const std::uint32_t milestone_gen,
                              ObservationSummary& out) noexcept {
  out = ObservationSummary{};
  out.neighbor_digest = observation_neighbor_digest(node, now_ms);
  out.route_digest = observation_route_digest(node, now_ms);
  observation_counts(node, now_ms, out.neighbor_active, out.neighbor_total,
                     out.route_reachable, out.route_total);
  out.milestone_gen = milestone_gen;
}

std::uint32_t observation_milestones_key(const JoinMilestones& milestones) noexcept {
  std::uint32_t key = kObservationFnv1a32Offset;
  key = observation_fnv1a32_step(key, milestones.mode);
  key = observation_fnv1a32_step(key, milestones.membership);
  key = observation_fnv1a32_step(key, milestones.joiner_state);
  key = observation_fnv1a32_step(key, milestones.flags);
  for (int i = 3; i >= 0; --i) {
    key = observation_fnv1a32_step(key, static_cast<std::uint8_t>(milestones.attempts >> (i * 8)));
  }
  return key;
}

}  // namespace routeloom
