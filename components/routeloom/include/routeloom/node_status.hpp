#pragma once

// Per-node link/route status surface (node_status_v1). Two portable pieces:
//
//   * NodeStatus — one bounded, allocation-free record describing what THIS
//     node currently knows about a remote node: whether it is an (active)
//     direct neighbor, the effective link cost and RSSI evidence for that
//     link, when it was last heard, and whether a feasible route to it is
//     selected (metric + next hop). MeshNode fills these from its existing
//     neighbor, route and telemetry tables (node_status.cpp) — no new
//     measurement is invented here.
//   * NodeStatusMonitor — a bounded level-triggered diff tracker that turns
//     successive snapshots into join/leave/route-change events. It holds
//     only a sorted baseline of "interesting" nodes (active neighbor or
//     reachable) and never allocates.
//
// Clock domain: every age in this header is a DURATION measured on the
// device's monotonic clock at snapshot time (`heard_age_ms = now -
// last_heard`). Absolute device timestamps never leave the device through
// this surface, so a host maps an age onto its own clock by subtracting it
// from its own receive time (see docs/spec/host.md §9).

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/routing.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// NodeStatus::flags bits. Bit 7 is reserved and always zero on the wire.
constexpr std::uint8_t kNodeStatusNeighbor = 1u << 0;        // a neighbor record exists (active or departed)
constexpr std::uint8_t kNodeStatusNeighborActive = 1u << 1;  // admitted direct neighbor right now
constexpr std::uint8_t kNodeStatusReachable = 1u << 2;       // a feasible route is selected
constexpr std::uint8_t kNodeStatusDirect = 1u << 3;          // selected next hop is the node itself
constexpr std::uint8_t kNodeStatusRssiValid = 1u << 4;       // rssi_* carry a real measurement
constexpr std::uint8_t kNodeStatusHeardValid = 1u << 5;      // heard_age_ms carries a real observation
constexpr std::uint8_t kNodeStatusTelemetryStale = 1u << 6;  // RF evidence predates the current link identity
constexpr std::uint8_t kNodeStatusFlagsMask = 0x7Fu;

struct NodeStatus {
  NodeId node{kInvalidNodeId};
  std::uint8_t flags{0};
  // Last and EWMA (signed Q8.8) RSSI of frames authenticated from this node
  // as the immediate transmitter. Meaningful only with kNodeStatusRssiValid.
  std::int8_t rssi_last_dbm{0};
  std::int16_t rssi_ewma_q8_8{0};
  // Effective link cost fed to routing (kInfiniteRouteMetric when the node
  // is not an active neighbor).
  RouteMetric link_cost{kInfiniteRouteMetric};
  // Selected route metric and next hop (infinite / invalid when unreachable).
  RouteMetric route_metric{kInfiniteRouteMetric};
  NodeId next_hop{kInvalidNodeId};
  // Device-monotonic age of the last authenticated frame from this node as
  // the immediate transmitter; saturates at UINT32_MAX. Meaningful only with
  // kNodeStatusHeardValid (multi-hop nodes are never "heard" directly).
  std::uint32_t heard_age_ms{0};

  bool neighbor_active() const noexcept { return (flags & kNodeStatusNeighborActive) != 0; }
  bool reachable() const noexcept { return (flags & kNodeStatusReachable) != 0; }
  // A node worth tracking for join/leave: it is an active neighbor or the
  // mesh can currently route to it.
  bool interesting() const noexcept { return neighbor_active() || reachable(); }
};

// Page bound shared by the USB page codec and the monitor's scan buffer.
constexpr std::size_t kNodeStatusPageMax = 16;
// Upper bound on distinct nodes a MeshNode can report: every route-table
// destination plus every neighbor record (a neighbor always seeds a direct
// route, so the true union is smaller).
constexpr std::size_t kNodeStatusTrackCapacity = kMaxRouteEntries + 32;

enum class NodeEventKind : std::uint8_t {
  NeighborUp = 1,    // node became an active direct neighbor
  NeighborDown = 2,  // node stopped being an active direct neighbor
  RouteUp = 3,       // a feasible route to the node is selected (joined)
  RouteDown = 4,     // no feasible route remains (left)
  RouteChanged = 5,  // still reachable, but the selected next hop moved
};

struct NodeEvent {
  std::uint32_t sequence{0};  // 1-based per arm(); a gap means lost events
  NodeEventKind kind{NodeEventKind::RouteUp};
  NodeStatus status{};  // the node's status as observed when the event fired
};

// Bounded level-triggered diff tracker. Usage (single-threaded):
//   arm(source, now)            — silent baseline := current interesting set
//   poll(source, now, max, emit) — emits at most `max` events; `emit`
//                                  returns false to refuse (queue full) and
//                                  the refused transition is retried on the
//                                  next poll (the baseline advances per
//                                  accepted event only).
// A flap that starts and ends between two polls is not reported — the
// monitor reports state changes, not every radio blip; hosts resync the
// full table through paginated queries.
//
// `Source` must provide:
//   std::size_t node_status_page(NodeId after, NodeStatus* out,
//                                std::size_t capacity, MonotonicMs now,
//                                bool& more) const noexcept;
// returning nodes with id > after in strictly ascending id order.
class NodeStatusMonitor {
 public:
  static constexpr std::size_t kCapacity = kNodeStatusTrackCapacity;
  static constexpr std::size_t kScanPage = 8;

  bool armed() const noexcept { return armed_; }
  std::size_t tracked() const noexcept { return size_; }
  std::uint32_t last_sequence() const noexcept { return sequence_; }
  // Interesting nodes that could not be tracked because the baseline was
  // full (unreachable by construction for a MeshNode source; kept honest).
  std::uint64_t overflow() const noexcept { return overflow_; }

  void disarm() noexcept {
    armed_ = false;
    size_ = 0;
    sequence_ = 0;
  }

  template <typename Source>
  void arm(const Source& source, const MonotonicMs now_ms) noexcept {
    size_ = 0;
    sequence_ = 0;
    armed_ = true;
    NodeId cursor = kInvalidNodeId;
    bool more = true;
    while (more) {
      const std::size_t n =
          source.node_status_page(cursor, scan_.data(), scan_.size(), now_ms, more);
      if (n == 0) break;
      for (std::size_t i = 0; i < n; ++i) {
        if (scan_[i].interesting() && !append(scan_[i])) ++overflow_;
      }
      cursor = scan_[n - 1].node;
    }
  }

  // Returns the number of events accepted by `emit`.
  template <typename Source, typename Emit>
  std::size_t poll(const Source& source, const MonotonicMs now_ms,
                   const std::size_t max_events, Emit&& emit) noexcept {
    if (!armed_ || max_events == 0) return 0;
    std::size_t emitted = 0;
    bool stop = false;
    // Offers one event; false stops the whole pass (budget or refusal).
    auto offer = [&](const NodeEventKind kind, const NodeStatus& status) {
      if (stop || emitted >= max_events) {
        stop = true;
        return false;
      }
      NodeEvent event{};
      event.sequence = sequence_ + 1U;
      event.kind = kind;
      event.status = status;
      if (!emit(event)) {
        stop = true;
        return false;
      }
      ++sequence_;
      ++emitted;
      return true;
    };
    std::size_t index = 0;  // baseline cursor (sorted ascending)
    NodeId cursor = kInvalidNodeId;
    bool more = true;
    while (more && !stop) {
      const std::size_t n =
          source.node_status_page(cursor, scan_.data(), scan_.size(), now_ms, more);
      if (n == 0) break;
      for (std::size_t i = 0; i < n && !stop; ++i) {
        const NodeStatus& current = scan_[i];
        // Baseline nodes below the scan position vanished from the source.
        while (!stop && index < size_ && baseline_[index].node < current.node) {
          if (settle(index, gone(baseline_[index].node), offer)) continue;
          ++index;
        }
        if (stop) break;
        if (index < size_ && baseline_[index].node == current.node) {
          if (!settle(index, current, offer)) ++index;
          continue;
        }
        if (!current.interesting()) continue;
        // New interesting node: insert an all-down baseline, then settle.
        if (!insert(index, current.node)) {
          ++overflow_;
          continue;
        }
        if (!settle(index, current, offer)) ++index;
      }
      cursor = scan_[n - 1].node;
    }
    // Everything left in the baseline past the last scanned id is gone.
    while (!stop && index < size_) {
      if (settle(index, gone(baseline_[index].node), offer)) continue;
      ++index;
    }
    return emitted;
  }

 private:
  struct Tracked {
    NodeId node{kInvalidNodeId};
    NodeId next_hop{kInvalidNodeId};
    bool neighbor_active{false};
    bool reachable{false};
  };

  static NodeStatus gone(const NodeId node) noexcept {
    NodeStatus status{};
    status.node = node;
    return status;
  }

  // Emits the transitions separating baseline_[index] from `current`, in a
  // fixed order (neighbor, then route), advancing the baseline per accepted
  // event. Returns true when the entry was erased (nothing left to track).
  template <typename Offer>
  bool settle(const std::size_t index, const NodeStatus& current, Offer& offer) noexcept {
    Tracked& entry = baseline_[index];
    if (entry.neighbor_active != current.neighbor_active()) {
      if (!offer(current.neighbor_active() ? NodeEventKind::NeighborUp
                                           : NodeEventKind::NeighborDown,
                 current)) {
        return false;
      }
      entry.neighbor_active = current.neighbor_active();
    }
    if (entry.reachable != current.reachable()) {
      if (!offer(current.reachable() ? NodeEventKind::RouteUp : NodeEventKind::RouteDown,
                 current)) {
        return false;
      }
      entry.reachable = current.reachable();
      entry.next_hop = current.reachable() ? current.next_hop : kInvalidNodeId;
    } else if (entry.reachable && entry.next_hop != current.next_hop) {
      if (!offer(NodeEventKind::RouteChanged, current)) return false;
      entry.next_hop = current.next_hop;
    }
    if (!entry.neighbor_active && !entry.reachable) {
      erase(index);
      return true;
    }
    return false;
  }

  bool append(const NodeStatus& status) noexcept {
    if (size_ >= kCapacity) return false;
    Tracked& entry = baseline_[size_++];
    entry.node = status.node;
    entry.neighbor_active = status.neighbor_active();
    entry.reachable = status.reachable();
    entry.next_hop = status.reachable() ? status.next_hop : kInvalidNodeId;
    return true;
  }

  bool insert(const std::size_t index, const NodeId node) noexcept {
    if (size_ >= kCapacity) return false;
    for (std::size_t i = size_; i > index; --i) baseline_[i] = baseline_[i - 1];
    baseline_[index] = Tracked{};
    baseline_[index].node = node;
    ++size_;
    return true;
  }

  void erase(const std::size_t index) noexcept {
    for (std::size_t i = index; i + 1 < size_; ++i) baseline_[i] = baseline_[i + 1];
    --size_;
    baseline_[size_] = Tracked{};
  }

  std::array<Tracked, kCapacity> baseline_{};
  std::size_t size_{0};
  std::array<NodeStatus, kScanPage> scan_{};
  std::uint32_t sequence_{0};
  std::uint64_t overflow_{0};
  bool armed_{false};
};

}  // namespace routeloom
