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
using RouteGeneration = std::uint16_t;

constexpr RouteMetric kInfiniteRouteMetric = UINT16_MAX;
constexpr std::size_t kMaxRouteEntries = 128;
constexpr std::size_t kRouteCandidatesPerDestination = 3;
// Feasibility state (FD + last seen origin generation) is kept in the entry as
// a tombstone after the last candidate is gone, so a re-advertised stale route
// cannot pass feasibility. The tombstone is GC'd only after this dwell.
constexpr std::uint32_t kRouteTombstoneDwellMs = 60000;
// A just-failed next hop cannot be re-selected until this hold-down passes.
constexpr std::uint32_t kRouteHoldDownMs = 500;

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
  template <typename Fn>
  void for_each_selected_change(Fn fn) noexcept {
    entries_.for_each([&](Entry& entry) {
      const auto selection = select(entry);
      const bool changed = selection.valid != entry.last_selected.valid ||
          (selection.valid &&
           (selection.next_hop != entry.last_selected.next_hop ||
            selection.sequence != entry.last_selected.sequence ||
            selection.metric != entry.last_selected.metric));
      if (changed) {
        entry.last_selected = selection;
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
  };

  Entry* find_or_allocate(NodeId destination) noexcept;
  const Entry* find(NodeId destination) const noexcept;
  static bool feasible(const Entry& entry, RouteSequence sequence,
                       RouteMetric metric) noexcept;
  static RouteSelection select(const Entry& entry) noexcept;
  static RouteCandidate* candidate_slot(Entry& entry, NodeId next_hop) noexcept;
  static bool has_candidates(const Entry& entry) noexcept;
  static void arm_tombstone(Entry& entry, MonotonicMs now_ms) noexcept;

  FixedPool<Entry, kMaxRouteEntries> entries_{};
};

}  // namespace routeloom
