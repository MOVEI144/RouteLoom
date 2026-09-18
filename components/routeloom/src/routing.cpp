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

RouteCandidate* RouteTable::candidate_slot(Entry& entry, const NodeId next_hop) noexcept {
  for (auto& candidate : entry.candidates) {
    if (candidate.valid && candidate.next_hop == next_hop) return &candidate;
  }
  for (auto& candidate : entry.candidates) {
    if (!candidate.valid) return &candidate;
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
    if (!candidate.valid || candidate.metric == kInfiniteRouteMetric) continue;
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
  return RouteSelection{entry.destination, selected->next_hop, selected->sequence,
                        selected->metric, true};
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

  if (advertisement.metric == kInfiniteRouteMetric) {
    return withdraw(advertisement.destination, next_hop) ? RouteUpdateResult::Withdrawn
                                                         : RouteUpdateResult::Ignored;
  }

  const RouteMetric total = route_metric_add(advertisement.metric, link_metric);
  if (total == kInfiniteRouteMetric || !feasible(*entry, advertisement.sequence, total)) {
    // An infeasible alternate is harmless while a feasible selected route still exists.
    // Request a newer origin sequence only when feasibility prevents all forwarding.
    entry->sequence_request_needed = !select(*entry).valid;
    return RouteUpdateResult::Infeasible;
  }

  auto* candidate = candidate_slot(*entry, next_hop);
  if (candidate == nullptr) return RouteUpdateResult::NoCapacity;
  const bool existed = candidate->valid && candidate->next_hop == next_hop;
  *candidate = RouteCandidate{next_hop, advertisement.sequence, total, now_ms,
                              now_ms + lifetime_ms, true};
  entry->sequence_request_needed = false;
  return existed ? RouteUpdateResult::Updated : RouteUpdateResult::Accepted;
}

bool RouteTable::withdraw(const NodeId destination, const NodeId next_hop) noexcept {
  auto* entry = entries_.find([&](const Entry& value) { return value.destination == destination; });
  if (entry == nullptr) return false;
  bool removed = false;
  for (auto& candidate : entry->candidates) {
    if (candidate.valid && candidate.next_hop == next_hop) {
      candidate = RouteCandidate{};
      removed = true;
    }
  }
  if (removed && !select(*entry).valid) entry->sequence_request_needed = true;
  return removed;
}

void RouteTable::invalidate_next_hop(const NodeId next_hop) noexcept {
  entries_.for_each([&](Entry& entry) {
    bool removed = false;
    for (auto& candidate : entry.candidates) {
      if (candidate.valid && candidate.next_hop == next_hop) {
        candidate = RouteCandidate{};
        removed = true;
      }
    }
    if (removed && !select(entry).valid) entry.sequence_request_needed = true;
  });
}

void RouteTable::expire(const MonotonicMs now_ms) noexcept {
  entries_.for_each([&](Entry& entry) {
    bool removed = false;
    for (auto& candidate : entry.candidates) {
      if (candidate.valid && candidate.expires_at_ms <= now_ms) {
        candidate = RouteCandidate{};
        removed = true;
      }
    }
    if (removed && !select(entry).valid) entry.sequence_request_needed = true;
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

std::size_t RouteTable::size() const noexcept { return entries_.size(); }

}  // namespace routeloom
