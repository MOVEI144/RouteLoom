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

constexpr RouteMetric kInfiniteRouteMetric = UINT16_MAX;
constexpr std::size_t kMaxRouteEntries = 128;
constexpr std::size_t kRouteCandidatesPerDestination = 3;

struct RouteAdvertisement {
  NodeId destination{kInvalidNodeId};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
};

struct RouteCandidate {
  NodeId next_hop{kInvalidNodeId};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
  MonotonicMs learned_at_ms{0};
  MonotonicMs expires_at_ms{0};
  bool valid{false};
};

struct RouteSelection {
  NodeId destination{kInvalidNodeId};
  NodeId next_hop{kInvalidNodeId};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
  bool valid{false};
};

enum class RouteUpdateResult : std::uint8_t {
  Accepted,
  Updated,
  Withdrawn,
  Infeasible,
  Ignored,
  NoCapacity,
};

bool route_sequence_newer(RouteSequence candidate, RouteSequence reference,
                          bool& ambiguous) noexcept;
RouteMetric route_metric_add(RouteMetric left, RouteMetric right) noexcept;

class RouteTable {
 public:
  RouteUpdateResult consider(const RouteAdvertisement& advertisement,
                             NodeId next_hop,
                             RouteMetric link_metric,
                             MonotonicMs now_ms,
                             MonotonicMs lifetime_ms) noexcept;

  bool withdraw(NodeId destination, NodeId next_hop) noexcept;
  void invalidate_next_hop(NodeId next_hop) noexcept;
  void expire(MonotonicMs now_ms) noexcept;

  RouteSelection best(NodeId destination) const noexcept;
  bool mark_advertised(NodeId destination) noexcept;
  bool needs_sequence_request(NodeId destination) const noexcept;
  RouteSequence requested_sequence(NodeId destination) const noexcept;

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

 private:
  struct FeasibleDistance {
    RouteSequence sequence{0};
    RouteMetric metric{kInfiniteRouteMetric};
    bool valid{false};
  };

  struct Entry {
    NodeId destination{kInvalidNodeId};
    FeasibleDistance feasible{};
    std::array<RouteCandidate, kRouteCandidatesPerDestination> candidates{};
    bool sequence_request_needed{false};
  };

  Entry* find_or_allocate(NodeId destination) noexcept;
  const Entry* find(NodeId destination) const noexcept;
  static bool feasible(const Entry& entry, RouteSequence sequence,
                       RouteMetric metric) noexcept;
  static RouteSelection select(const Entry& entry) noexcept;
  static RouteCandidate* candidate_slot(Entry& entry, NodeId next_hop) noexcept;

  FixedPool<Entry, kMaxRouteEntries> entries_{};
};

}  // namespace routeloom
