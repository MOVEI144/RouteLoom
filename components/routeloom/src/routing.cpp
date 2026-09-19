#include "routeloom/routing.hpp"

#include <algorithm>

namespace routeloom {

bool route_sequence_newer(const RouteSequence candidate, const RouteSequence reference,
                          bool& ambiguous) noexcept {
  const auto delta = static_cast<RouteSequence>(candidate - reference);
  ambiguous = delta == 0x8000U;
  return delta != 0 && delta < 0x8000U;
}

RouteMetric route_metric_add(const RouteMetric left, const RouteMetric right) noexcept {
  if (right == 0 || left == kInfiniteRouteMetric || right == kInfiniteRouteMetric) {
    return kInfiniteRouteMetric;
  }
  const std::uint32_t sum = static_cast<std::uint32_t>(left) + right;
  return sum >= kInfiniteRouteMetric ? kInfiniteRouteMetric
                                     : static_cast<RouteMetric>(sum);
}

RouteTable::Entry* RouteTable::find_or_allocate(const NodeId destination) noexcept {
  if (destination == kInvalidNodeId) return nullptr;
  if (auto* entry = entries_.find([&](const Entry& value) {
        return value.destination == destination;
      })) {
    return entry;
  }
  auto* entry = entries_.allocate();
  if (entry != nullptr) entry->destination = destination;
  return entry;
}

const RouteTable::Entry* RouteTable::find(const NodeId destination) const noexcept {
  return entries_.find([&](const Entry& value) { return value.destination == destination; });
}

bool RouteTable::feasible(const Entry& entry, const RouteSequence sequence,
                        const RouteMetric metric) noexcept {
  if (!entry.feasible.valid) return metric != kInfiniteRouteMetric;
  bool ambiguous = false;
  if (route_sequence_newer(sequence, entry.feasible.sequence, ambiguous)) return true;
  if (ambiguous) return false;
  return sequence == entry.feasible.sequence && metric < entry.feasible.metric;
}

bool RouteTable::has_candidates(const Entry& entry) noexcept {
  for (const auto& candidate : entry.candidates) {
    if (candidate.valid) return true;
  }
  return false;
}

void RouteTable::arm_tombstone(Entry& entry, const MonotonicMs now_ms) noexcept {
  if (!has_candidates(entry) && entry.tombstone_expires_at_ms == 0) {
    entry.tombstone_expires_at_ms = now_ms + kRouteTombstoneDwellMs;
  }
}

RouteCandidate* RouteTable::candidate_slot(Entry& entry, const NodeId next_hop) noexcept {
  for (auto& candidate : entry.candidates) {
    if (candidate.valid && candidate.next_hop == next_hop) return &candidate;
  }
  for (auto& candidate : entry.candidates) {
    if (!candidate.valid) return &candidate;
  }
  // All slots taken: evict an infeasible candidate first, then the worst
  // sequence/metric — never a feasible route while an infeasible one remains.
  for (auto& candidate : entry.candidates) {
    if (!candidate.feasible) return &candidate;
  }
  auto* worst = &entry.candidates[0];
  for (auto& candidate : entry.candidates) {
    bool ambiguous = false;
    const bool candidate_newer = route_sequence_newer(candidate.sequence, worst->sequence, ambiguous);
    if (!candidate_newer && (candidate.sequence != worst->sequence || candidate.metric > worst->metric)) {
      worst = &candidate;
    }
  }
  return worst;
}

RouteSelection RouteTable::select(const Entry& entry) noexcept {
  const RouteCandidate* selected = nullptr;
  for (const auto& candidate : entry.candidates) {
    if (!candidate.valid || !candidate.feasible ||
        candidate.metric == kInfiniteRouteMetric) continue;
    if (selected == nullptr) {
      selected = &candidate;
      continue;
    }
    bool ambiguous = false;
    if (route_sequence_newer(candidate.sequence, selected->sequence, ambiguous)) {
      selected = &candidate;
    } else if (!ambiguous && candidate.sequence == selected->sequence &&
               candidate.metric < selected->metric) {
      selected = &candidate;
    }
  }
  if (selected == nullptr) return RouteSelection{};
  return RouteSelection{entry.destination, selected->next_hop, entry.generation,
                        selected->sequence, selected->metric, true};
}

RouteUpdateResult RouteTable::consider(const RouteAdvertisement& advertisement,
                                       const NodeId next_hop,
                                       const RouteMetric link_metric,
                                       const MonotonicMs now_ms,
                                       const MonotonicMs lifetime_ms) noexcept {
  if (advertisement.destination == kInvalidNodeId || next_hop == kInvalidNodeId ||
      link_metric == 0 || lifetime_ms == 0) {
    return RouteUpdateResult::Ignored;
  }
  auto* entry = find_or_allocate(advertisement.destination);
  if (entry == nullptr) return RouteUpdateResult::NoCapacity;

  // Generation ordering is a plain comparison (no serial wrap): an origin
  // generation must be persisted monotonic per boot; a wrap is a profile
  // violation. Higher generation = the origin restarted, so all feasibility
  // state from the previous incarnation is stale.
  if (advertisement.generation < entry->generation) {
    return RouteUpdateResult::StaleGeneration;
  }
  if (advertisement.generation > entry->generation) {
    entry->generation = advertisement.generation;
    entry->feasible = FeasibleDistance{};
    for (auto& candidate : entry->candidates) candidate = RouteCandidate{};
    entry->last_selected = RouteSelection{};
    entry->hold_next_hop = kInvalidNodeId;
    entry->hold_until_ms = 0;
    entry->tombstone_expires_at_ms = 0;
    entry->sequence_request_needed = false;
  }

  if (advertisement.metric == kInfiniteRouteMetric) {
    return withdraw(advertisement.destination, next_hop, now_ms)
               ? RouteUpdateResult::Withdrawn
               : RouteUpdateResult::Ignored;
  }

  // Hold-down: a just-failed next hop is not re-learned until the hold passes.
  if (next_hop == entry->hold_next_hop && now_ms < entry->hold_until_ms) {
    return RouteUpdateResult::HeldDown;
  }

  const RouteMetric total = route_metric_add(advertisement.metric, link_metric);
  // Feasibility compares the advertised metric with FD — never the
  // link-cost-added total (spec §10). The selected route's own refresh
  // (advertised metric < our advertised FD metric) must stay feasible.
  const bool is_feasible =
      total != kInfiniteRouteMetric &&
      feasible(*entry, advertisement.sequence, advertisement.metric);

  auto* candidate = candidate_slot(*entry, next_hop);
  if (candidate == nullptr) return RouteUpdateResult::NoCapacity;
  const bool existed = candidate->valid && candidate->next_hop == next_hop;
  // Infeasible candidates are recorded too (lease renewed): they carry
  // SeqNoRequests and become selectable again on a newer sequence.
  *candidate = RouteCandidate{next_hop, advertisement.sequence, total, now_ms,
                              now_ms + lifetime_ms, is_feasible, true};
  entry->tombstone_expires_at_ms = 0;
  if (is_feasible) {
    entry->sequence_request_needed = false;
    return existed ? RouteUpdateResult::Updated : RouteUpdateResult::Accepted;
  }
  // An infeasible alternate is harmless while a feasible selected route still exists.
  // Request a newer origin sequence only when feasibility prevents all forwarding.
  entry->sequence_request_needed = !select(*entry).valid;
  return RouteUpdateResult::Infeasible;
}

bool RouteTable::withdraw(const NodeId destination, const NodeId next_hop,
                          const MonotonicMs now_ms) noexcept {
  auto* entry = entries_.find([&](const Entry& value) { return value.destination == destination; });
  if (entry == nullptr) return false;
  bool removed = false;
  for (auto& candidate : entry->candidates) {
    if (candidate.valid && candidate.next_hop == next_hop) {
      // A retraction keeps the (now infeasible) candidate until its lease
      // expires — it may still carry a SeqNoRequest toward the origin.
      candidate.feasible = false;
      candidate.metric = kInfiniteRouteMetric;
      removed = true;
    }
  }
  if (removed) {
    // The withdrawn next hop just reported failure: hold it down briefly so it
    // is not instantly re-selected on the next advertisement.
    entry->hold_next_hop = next_hop;
    entry->hold_until_ms = now_ms + kRouteHoldDownMs;
    if (!select(*entry).valid) entry->sequence_request_needed = true;
    arm_tombstone(*entry, now_ms);
  }
  return removed;
}

void RouteTable::invalidate_next_hop(const NodeId next_hop,
                                     const MonotonicMs now_ms,
                                     const bool hold) noexcept {
  entries_.for_each([&](Entry& entry) {
    bool removed = false;
    for (auto& candidate : entry.candidates) {
      if (candidate.valid && candidate.next_hop == next_hop) {
        candidate = RouteCandidate{};
        removed = true;
      }
    }
    if (removed) {
      if (hold) {
        entry.hold_next_hop = next_hop;
        entry.hold_until_ms = now_ms + kRouteHoldDownMs;
      }
      if (!select(entry).valid) entry.sequence_request_needed = true;
      arm_tombstone(entry, now_ms);
    }
  });
}

void RouteTable::expire(const MonotonicMs now_ms) noexcept {
  while (true) {
    auto* dead = entries_.find([&](const Entry& entry) {
      return entry.tombstone_expires_at_ms != 0 &&
             entry.tombstone_expires_at_ms <= now_ms;
    });
    if (dead == nullptr) break;
    entries_.release(dead);
  }
  entries_.for_each([&](Entry& entry) {
    bool removed = false;
    for (auto& candidate : entry.candidates) {
      if (candidate.valid && candidate.expires_at_ms <= now_ms) {
        candidate = RouteCandidate{};
        removed = true;
      }
    }
    if (removed && !select(entry).valid) entry.sequence_request_needed = true;
    // Lease expiry means the peer went silent, not that it failed: no hold-down.
    arm_tombstone(entry, now_ms);
  });
}

RouteSelection RouteTable::best(const NodeId destination) const noexcept {
  const auto* entry = find(destination);
  return entry == nullptr ? RouteSelection{} : select(*entry);
}

bool RouteTable::mark_advertised(const NodeId destination) noexcept {
  auto* entry = entries_.find([&](const Entry& value) { return value.destination == destination; });
  if (entry == nullptr) return false;
  const auto selected = select(*entry);
  if (!selected.valid) return false;
  // FD is updated only just before a finite advertisement actually leaves, per
  // spec: newer sequence -> advertised metric; same sequence -> min(old, new).
  if (!entry->feasible.valid) {
    entry->feasible = FeasibleDistance{selected.sequence, selected.metric, true};
    return true;
  }
  bool ambiguous = false;
  if (route_sequence_newer(selected.sequence, entry->feasible.sequence, ambiguous) ||
      (!ambiguous && selected.sequence == entry->feasible.sequence &&
       selected.metric < entry->feasible.metric)) {
    entry->feasible.sequence = selected.sequence;
    entry->feasible.metric = selected.metric;
  }
  return true;
}

bool RouteTable::needs_sequence_request(const NodeId destination) const noexcept {
  const auto* entry = find(destination);
  return entry != nullptr && entry->sequence_request_needed;
}

RouteSequence RouteTable::requested_sequence(const NodeId destination) const noexcept {
  const auto* entry = find(destination);
  if (entry == nullptr || !entry->sequence_request_needed) return 0;
  return entry->feasible.valid
      ? static_cast<RouteSequence>(entry->feasible.sequence + 1U)
      : static_cast<RouteSequence>(1U);
}

NodeId RouteTable::request_next_hop(const NodeId destination, const std::size_t attempt,
                                    const NodeId exclude_a,
                                    const NodeId exclude_b) const noexcept {
  const auto* entry = find(destination);
  if (entry == nullptr) return kInvalidNodeId;
  const auto selected = select(*entry);
  if (selected.valid && selected.next_hop != exclude_a && selected.next_hop != exclude_b) {
    return selected.next_hop;
  }
  std::array<NodeId, kRouteCandidatesPerDestination> hops{};
  std::size_t count = 0;
  for (const auto& candidate : entry->candidates) {
    if (candidate.valid && candidate.next_hop != exclude_a && candidate.next_hop != exclude_b) {
      hops[count++] = candidate.next_hop;
    }
  }
  return count != 0 ? hops[attempt % count] : kInvalidNodeId;
}

std::size_t RouteTable::size() const noexcept { return entries_.size(); }

}  // namespace routeloom
