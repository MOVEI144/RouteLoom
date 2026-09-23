#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/fixed_containers.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

using RouteMetric = std::uint16_t;
using RouteSequence = std::uint16_t;
using RouteGeneration = std::uint32_t;

constexpr RouteMetric kInfiniteRouteMetric = UINT16_MAX;
constexpr std::size_t kMaxRouteEntries = 128;
constexpr std::size_t kRouteCandidatesPerDestination = 3;
// Feasibility state (FD + last seen origin generation) is kept in the entry as
// a tombstone after the last candidate is gone, so a re-advertised stale route
// cannot pass feasibility. The tombstone is GC'd only after this dwell.
constexpr std::uint32_t kRouteTombstoneDwellMs = 60000;
// A just-failed next hop cannot be re-selected until this hold-down passes.
constexpr std::uint32_t kRouteHoldDownMs = 500;

// --- Load-aware switching discipline (03-congestion.md §7, D4-04) -------------
// Queue effects react immediately; route IMPROVEMENT works on a seconds
// timescale so a single load sample never flaps the mesh. All values are the
// contract pins from contracts.json congestion.*.
// An alternative must be >=20% and >=1 cost better than the committed route,
// sustained for the whole improvement hold, before a switch commits.
constexpr std::uint32_t kImprovementHoldMs = 10000;     // improvement_hold_ms
constexpr std::uint32_t kSwitchHoldMs = 5000;           // switch_hold_ms
// Sustained authenticated BUSY on the committed next hop for at least this
// long permits a faster local repair to a fresh feasible alternative — still
// damped by the post-switch hold.
constexpr std::uint32_t kSevereBusyMs = 2000;           // severe_busy_ms
// Pure metric-improvement advertisements are spaced at least this far apart
// per destination; withdrawals/expiry are never delayed by this gap.
constexpr std::uint32_t kImprovementAdGapMs = 2000;     // improvement_advertisement_gap_ms
// Node-id derived dispersion added to the improvement hold so a fleet does
// not evaluate the same switch at the same instant (03 §7).
constexpr std::uint32_t kImprovementJitterMs = 2000;
// Bound on remembered per-next-hop busy state (one per neighbor).
constexpr std::size_t kBusyLinkCapacity = 32;

struct RouteAdvertisement {
  NodeId destination{kInvalidNodeId};
  RouteGeneration generation{0};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
};

struct RouteCandidate {
  NodeId next_hop{kInvalidNodeId};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
  // The metric the next hop advertised (without our link cost). Feasibility
  // must be re-evaluated against the CURRENT feasible distance at select
  // time — FD only tightens, so a feasible flag snapshotted at consider()
  // can silently go stale and select a route that loops.
  RouteMetric advertised{kInfiniteRouteMetric};
  MonotonicMs learned_at_ms{0};
  MonotonicMs expires_at_ms{0};
  // Unexpired infeasible candidates are kept (lease-renewed) so a SeqNoRequest
  // can still ride them; they are never selected for DATA forwarding.
  bool feasible{false};
  bool valid{false};
};

struct RouteSelection {
  NodeId destination{kInvalidNodeId};
  NodeId next_hop{kInvalidNodeId};
  RouteGeneration generation{0};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
  bool valid{false};
};

enum class RouteUpdateResult : std::uint8_t {
  Accepted,
  Updated,
  Withdrawn,
  Infeasible,
  StaleGeneration,
  HeldDown,
  Ignored,
  NoCapacity,
};

bool route_sequence_newer(RouteSequence candidate, RouteSequence reference,
                          bool& ambiguous) noexcept;
// advertised + link cost, saturating to infinity. Callers must reject a zero
// link cost before calling (consider() ignores those advertisements).
RouteMetric route_metric_add(RouteMetric advertised, RouteMetric link_cost) noexcept;

// Babel-derived distance-vector table. Source key = (network implicit in the
// owning node, destination/origin NodeId, origin generation): an origin
// restart raises the generation and invalidates all prior feasibility state.
class RouteTable {
 public:
  RouteUpdateResult consider(const RouteAdvertisement& advertisement,
                             NodeId next_hop,
                             RouteMetric link_metric,
                             MonotonicMs now_ms,
                             MonotonicMs lifetime_ms) noexcept;

  bool withdraw(NodeId destination, NodeId next_hop, MonotonicMs now_ms) noexcept;
  // Drops every candidate learned via `next_hop`. hold=true (link failure,
  // withdrawal) applies the hold-down; hold=false is for a peer restart —
  // its previous-incarnation state is stale but fresh ads must not be held.
  void invalidate_next_hop(NodeId next_hop, MonotonicMs now_ms, bool hold = true) noexcept;
  void expire(MonotonicMs now_ms) noexcept;
  // Capacity preemption for direct-neighbor admission (issue #50): releases
  // the entry with the smallest armed tombstone_expires_at_ms, dropping its
  // feasibility state early. Returns false when nothing is armed — normal
  // GC still waits out the full dwell and live entries are never victims.
  bool reclaim_tombstone() noexcept;

  // --- Load coupling (03-congestion.md §6.3, §7) ------------------------------
  // Identity used for the improvement-hold jitter; set once at boot.
  void set_self(NodeId self) noexcept { self_id_ = self; }
  // Recomputes every candidate learned via `next_hop` from its STORED
  // advertised metric plus the new link cost (saturating). Leases are never
  // touched (metric_changes_refresh_advertisement_lease = false), FD is
  // never deleted, and a withdrawn/infeasible candidate is never revived —
  // load can only raise or lower the metric of routes feasibility already
  // permits. `now_ms` is the observation epoch; returns true when any
  // candidate was touched. cost == 0 is refused: only self-origin distance
  // is zero (03 §6.2).
  bool update_link_cost(NodeId next_hop, RouteMetric cost, MonotonicMs now_ms) noexcept;
  // Reports sustained authenticated-busy pressure observed on `next_hop`
  // (since_ms = when the sustain began — 0 is a legitimate timestamp, the
  // BusyLink's existence is the busy state). Feeds ONLY the severe-busy
  // fast-repair path — a peer's self-report is a hint and never changes a
  // metric by itself (03 §6.2, §7).
  void note_next_hop_busy(NodeId next_hop, MonotonicMs since_ms) noexcept;
  void clear_next_hop_busy(NodeId next_hop) noexcept;
  // Advances the switching discipline: commits pending improvements whose
  // hold elapsed, repairs committed selections that lost validity, and
  // tracks newly qualifying alternatives. Driven by the owner's poll plus
  // every mutating table operation.
  void evaluate(MonotonicMs now_ms) noexcept;

  RouteSelection best(NodeId destination) const noexcept;
  bool mark_advertised(NodeId destination) noexcept;
  bool needs_sequence_request(NodeId destination) const noexcept;
  RouteSequence requested_sequence(NodeId destination) const noexcept;
  // Next hop toward `destination` for a SeqNoRequest: the selected route when
  // one exists, otherwise an infeasible-but-live candidate. `attempt` rotates
  // through candidates so retries can try a different path.
  NodeId request_next_hop(NodeId destination, std::size_t attempt,
                          NodeId exclude_a = kInvalidNodeId,
                          NodeId exclude_b = kInvalidNodeId) const noexcept;

  template <typename Fn>
  void for_each_sequence_request(Fn fn) const noexcept {
    entries_.for_each([&](const Entry& entry) {
      if (!entry.sequence_request_needed) return;
      const RouteSequence requested = entry.feasible.valid
          ? static_cast<RouteSequence>(entry.feasible.sequence + 1U)
          : static_cast<RouteSequence>(1U);
      fn(entry.destination, requested);
    });
  }

  std::size_t size() const noexcept;

  template <typename Fn>
  void for_each_selected(Fn fn) const noexcept {
    entries_.for_each([&](const Entry& entry) {
      const auto selection = select(entry);
      if (selection.valid) fn(selection);
    });
  }

  struct LostRoute {
    NodeId destination{kInvalidNodeId};
    RouteGeneration generation{0};
    RouteSequence sequence{0};
  };

  // Fires for each remembered destination that currently has no feasible
  // selection (lost candidates and/or an armed tombstone). Used to emit
  // retractions so neighbors withdraw promptly instead of waiting for the
  // full lease expiry.
  template <typename Fn>
  void for_each_lost(Fn fn) const noexcept {
    entries_.for_each([&](const Entry& entry) {
      if (select(entry).valid) return;
      if (!has_candidates(entry) && entry.tombstone_expires_at_ms == 0) return;
      fn(LostRoute{entry.destination, entry.generation,
                   entry.feasible.valid ? entry.feasible.sequence
                                        : static_cast<RouteSequence>(0)});
    });
  }

  // Fires for each entry whose selected route changed since the last call
  // (including selection becoming invalid). Used for triggered updates.
  // A pure metric improvement (same next hop and sequence, lower metric) is
  // rate-limited to one triggered advertisement per improvement_advertisement_gap_ms
  // (03 §8): a suppressed improvement keeps last_selected stale so it fires
  // once the gap has passed — or is silently covered when a periodic
  // advertisement carries it first (mark_advertised syncs last_selected).
  template <typename Fn>
  void for_each_selected_change(Fn fn, MonotonicMs now_ms) noexcept {
    entries_.for_each([&](Entry& entry) {
      const auto selection = select(entry);
      const bool changed = selection.valid != entry.last_selected.valid ||
          (selection.valid &&
           (selection.next_hop != entry.last_selected.next_hop ||
            selection.sequence != entry.last_selected.sequence ||
            selection.metric != entry.last_selected.metric));
      if (!changed) return;
      const bool pure_improvement =
          selection.valid && entry.last_selected.valid &&
          selection.next_hop == entry.last_selected.next_hop &&
          selection.sequence == entry.last_selected.sequence &&
          selection.metric < entry.last_selected.metric;
      if (pure_improvement && entry.improvement_ad_ms != 0 &&
          now_ms - entry.improvement_ad_ms < kImprovementAdGapMs) {
        return;
      }
      if (pure_improvement) entry.improvement_ad_ms = now_ms;
      entry.last_selected = selection;
      fn(selection);
    });
  }

 private:
  struct FeasibleDistance {
    RouteSequence sequence{0};
    RouteMetric metric{kInfiniteRouteMetric};
    bool valid{false};
  };

  struct Entry {
    NodeId destination{kInvalidNodeId};
    RouteGeneration generation{0};
    FeasibleDistance feasible{};
    std::array<RouteCandidate, kRouteCandidatesPerDestination> candidates{};
    RouteSelection last_selected{};
    NodeId hold_next_hop{kInvalidNodeId};
    MonotonicMs hold_until_ms{0};
    MonotonicMs tombstone_expires_at_ms{0};
    bool sequence_request_needed{false};
    // Committed next hop (03 §7): the selection DATA forwarding, the
    // advertised metric and FD updates are all generated from. It moves only
    // through the hysteresis rules in evaluate_entry — never on a bare
    // metric comparison — and load can never commit an infeasible route.
    NodeId committed_next_hop{kInvalidNodeId};
    // Pending improvement: the qualifying alternative and when its
    // continuous-better streak began.
    NodeId improvement_next_hop{kInvalidNodeId};
    MonotonicMs improvement_since_ms{0};
    // Post-switch damping: no further voluntary switch commits before this.
    MonotonicMs switch_hold_until_ms{0};
    // Last triggered pure-improvement advertisement for this destination.
    MonotonicMs improvement_ad_ms{0};
  };

  // Per-next-hop sustained-busy input (03 §7 severe-busy path).
  struct BusyLink {
    NodeId next_hop{kInvalidNodeId};
    MonotonicMs since_ms{0};
  };

  Entry* find_or_allocate(NodeId destination) noexcept;
  const Entry* find(NodeId destination) const noexcept;
  static bool feasible(const Entry& entry, RouteSequence sequence,
                       RouteMetric metric) noexcept;
  static RouteSelection select(const Entry& entry) noexcept;
  static RouteCandidate* candidate_slot(Entry& entry, NodeId next_hop) noexcept;
  static bool has_candidates(const Entry& entry) noexcept;
  static void arm_tombstone(Entry& entry, MonotonicMs now_ms) noexcept;
  // The candidate via `hop` when it is still selectable (valid, flagged
  // feasible, finite metric and — re-checked — feasible against the CURRENT
  // feasible distance). kInvalidNodeId always yields nullptr.
  static const RouteCandidate* selectable(const Entry& entry, NodeId hop) noexcept;
  // Best selectable candidate; `exclude` skips one next hop (severe-busy
  // repair looks for a fresh alternative beside the busy committed hop).
  static const RouteCandidate* best_candidate(const Entry& entry,
                                              NodeId exclude) noexcept;
  void evaluate_entry(Entry& entry, MonotonicMs now_ms) noexcept;
  const BusyLink* busy_link(NodeId next_hop) const noexcept;
  std::uint32_t improvement_jitter(NodeId destination) const noexcept;

  FixedPool<Entry, kMaxRouteEntries> entries_{};
  FixedPool<BusyLink, kBusyLinkCapacity> busy_links_{};
  NodeId self_id_{kInvalidNodeId};
};

}  // namespace routeloom
