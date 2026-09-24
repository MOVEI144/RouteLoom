#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <type_traits>

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

// --- Gateway-scoped routing profile (docs/design/sdk-v1/routing-scale.md) ------
// Up to this many gateway destinations may be configured per site. Every node
// keeps a proactive route to each of them; other destinations are learned
// only along the gateway tree (upward) or on demand (ROUTE_REQUEST).
// Four since G-SEC P4 PR3, matching the RLS1 gateway list.
constexpr std::size_t kMaxRouteGateways = 4;
// ROUTE_UPDATE framing (Wire v2): count(1) + N x 16-byte records inside the
// 128-byte payload -> N <= 7; the sender's self record always takes one slot.
constexpr std::size_t kRouteUpdateRecordBytes = 16;
constexpr std::size_t kRouteUpdateMaxRecords =
    (kMaxApplicationPayload - 1) / kRouteUpdateRecordBytes;
static_assert(kRouteUpdateMaxRecords == 7, "Wire v2 ROUTE_UPDATE carries 7 records");
// Default per-link refresh cadence in advertisement periods (ticks): with the
// product period of 5 s every gateway-tree link is refreshed every 30 s.
constexpr std::uint8_t kScopedDefaultRefreshTicks = 6;
// Lease margin (ticks) on top of two refresh cycles: one refresh may be lost
// outright and the next may land up to a tick late (pacing / budget deferral)
// without the route expiring.
constexpr std::uint32_t kScopedLeaseMarginTicks = 2;

// Gateway-scoped lease rule (routing-scale.md §5): every tree-link record is
// re-sent once per `refresh_ticks` periods (the upward pages of one cycle are
// spread inside that cycle), so the lease must cover two cycles plus margin:
//   lifetime >= (2 * refresh_ticks + kScopedLeaseMarginTicks) * period.
constexpr bool scoped_lifetime_sufficient(const std::uint32_t period_ms,
                                          const std::uint32_t lifetime_ms,
                                          const std::uint32_t refresh_ticks) noexcept {
  return period_ms != 0 && refresh_ticks != 0 &&
         static_cast<std::uint64_t>(lifetime_ms) >=
             (2ULL * refresh_ticks + kScopedLeaseMarginTicks) * period_ms;
}

// Flat-profile lease rule for `destinations` selected routes: every neighbor
// receives one page per period and a page carries kRouteUpdateMaxRecords - 1
// routes beside the self record, so the lease must exceed the full page
// rotation plus one period of margin (issue #41).
constexpr std::uint64_t flat_refresh_pages(const std::uint64_t destinations) noexcept {
  return destinations == 0
             ? 1
             : (destinations + (kRouteUpdateMaxRecords - 1) - 1) /
                   (kRouteUpdateMaxRecords - 1);
}
constexpr bool flat_lifetime_sufficient(const std::uint32_t period_ms,
                                        const std::uint32_t lifetime_ms,
                                        const std::uint64_t destinations) noexcept {
  return period_ms != 0 &&
         static_cast<std::uint64_t>(lifetime_ms) >
             (flat_refresh_pages(destinations) + 1ULL) * period_ms;
}

// Product profile pin (routing-scale.md §5). tools/check_review_contracts.py
// re-derives the same rule from docs/reference/radio-defaults.json
// routing.gateway_scoped and checks these constants against it.
constexpr std::uint32_t kScopedProductPeriodMs = 5000;
constexpr std::uint32_t kScopedProductLifetimeMs = 90000;
static_assert(scoped_lifetime_sufficient(kScopedProductPeriodMs,
                                         kScopedProductLifetimeMs,
                                         kScopedDefaultRefreshTicks),
              "product gateway-scoped lease must cover two refresh cycles + margin");

struct RouteAdvertisement {
  NodeId destination{kInvalidNodeId};
  RouteGeneration generation{0};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
};

// Route records are laid out largest-alignment first (no interior padding):
// the table holds kMaxRouteEntries x kRouteCandidatesPerDestination of these
// in static RAM (docs/design/sdk-v1/ram-budget.md).
struct RouteCandidate {
  NodeId next_hop{kInvalidNodeId};
  MonotonicMs learned_at_ms{0};
  MonotonicMs expires_at_ms{0};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
  // The metric the next hop advertised (without our link cost). Feasibility
  // must be re-evaluated against the CURRENT feasible distance at select
  // time — FD only tightens, so a feasible flag snapshotted at consider()
  // can silently go stale and select a route that loops.
  RouteMetric advertised{kInfiniteRouteMetric};
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
  // Scoped-profile scheduling flag (see Entry::announced_up). Pure
  // bookkeeping: selection, feasibility and leases never read it.
  void set_announced_up(NodeId destination, bool announced) noexcept;
  bool announced_up(NodeId destination) const noexcept;
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

  // Read-only destination walk for the node status surface (node_status.hpp):
  // every remembered destination — selected, lost or tombstoned. `fn` gets
  // the destination id only; best() answers its current selection.
  template <typename Fn>
  void for_each_destination(Fn fn) const noexcept {
    entries_.for_each([&](const Entry& entry) { fn(entry.destination); });
  }
  bool knows(NodeId destination) const noexcept { return find(destination) != nullptr; }

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
  // Retraction data for one destination (same rule as for_each_lost).
  bool lost_route(NodeId destination, LostRoute& out) const noexcept;

  // Tombstone dwell (feasibility-state GC). Never shorter than the default
  // dwell and never shorter than the route lease: a source entry must outlive
  // every candidate that could still be advertised to us (RFC 8966 §3.7.3),
  // or a stale route could pass feasibility against a freshly reset FD.
  void set_tombstone_dwell(std::uint32_t lifetime_ms) noexcept {
    tombstone_dwell_ms_ = lifetime_ms > kRouteTombstoneDwellMs ? lifetime_ms
                                                               : kRouteTombstoneDwellMs;
  }
  std::uint32_t tombstone_dwell_ms() const noexcept { return tombstone_dwell_ms_; }

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
      const RouteSelection previous = entry.last_selected;
      entry.last_selected = selection;
      // Callers may also take the previous snapshot: the gateway-scoped
      // profile needs the old next hop to route a retraction upward.
      if constexpr (std::is_invocable_v<Fn&, const RouteSelection&,
                                        const RouteSelection&>) {
        fn(selection, previous);
      } else {
        fn(selection);
      }
    });
  }

 private:
  struct FeasibleDistance {
    RouteSequence sequence{0};
    RouteMetric metric{kInfiniteRouteMetric};
    bool valid{false};
  };

  // 8-byte members first, then the 4/2/1-byte tail (ram-budget.md): 216 B
  // per entry instead of 256 B (LP64 and RISC-V/Xtensa).
  struct Entry {
    NodeId destination{kInvalidNodeId};
    std::array<RouteCandidate, kRouteCandidatesPerDestination> candidates{};
    RouteSelection last_selected{};
    NodeId hold_next_hop{kInvalidNodeId};
    MonotonicMs hold_until_ms{0};
    MonotonicMs tombstone_expires_at_ms{0};
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
    RouteGeneration generation{0};
    FeasibleDistance feasible{};
    bool sequence_request_needed{false};
    // Gateway-scoped profile bookkeeping (never a routing input): a finite
    // record for this destination went to our parent and has not been
    // retracted since — leaving the subtree must send a retraction upward.
    bool announced_up{false};
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
  void arm_tombstone(Entry& entry, MonotonicMs now_ms) const noexcept;
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
  std::uint32_t tombstone_dwell_ms_{kRouteTombstoneDwellMs};
};

}  // namespace routeloom
