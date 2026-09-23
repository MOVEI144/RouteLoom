#include "routeloom/routing.hpp"

#include <algorithm>

namespace routeloom {

bool route_sequence_newer(const RouteSequence candidate, const RouteSequence reference,
                          bool& ambiguous) noexcept {
  const auto delta = static_cast<RouteSequence>(candidate - reference);
  ambiguous = delta == 0x8000U;
  return delta != 0 && delta < 0x8000U;
}

RouteMetric route_metric_add(const RouteMetric advertised,
                             const RouteMetric link_cost) noexcept {
  if (advertised == kInfiniteRouteMetric || link_cost == kInfiniteRouteMetric) {
    return kInfiniteRouteMetric;
  }
  const std::uint32_t sum = static_cast<std::uint32_t>(advertised) + link_cost;
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
  // Re-evaluate against the current FD: the stored flag may be stale-true
  // after mark_advertised tightened it.
  for (auto& candidate : entry.candidates) {
    if (!candidate.feasible ||
        !feasible(entry, candidate.sequence, candidate.advertised)) {
      return &candidate;
    }
  }
  // Everything is feasible: evict the worst sequence/metric, but prefer a
  // non-committed victim — evicting the committed hop and re-learning it on
  // the next advertisement would look exactly like a route flap.
  auto* worst = &entry.candidates[0];
  for (auto& candidate : entry.candidates) {
    const bool candidate_committed = candidate.next_hop == entry.committed_next_hop;
    const bool worst_committed = worst->next_hop == entry.committed_next_hop;
    if (candidate_committed && !worst_committed) continue;
    if (!candidate_committed && worst_committed) {
      worst = &candidate;
      continue;
    }
    bool ambiguous = false;
    const bool candidate_newer = route_sequence_newer(candidate.sequence, worst->sequence, ambiguous);
    if (!candidate_newer && (candidate.sequence != worst->sequence || candidate.metric > worst->metric)) {
      worst = &candidate;
    }
  }
  return worst;
}

const RouteCandidate* RouteTable::selectable(const Entry& entry,
                                             const NodeId hop) noexcept {
  if (hop == kInvalidNodeId) return nullptr;
  for (const auto& candidate : entry.candidates) {
    // Feasibility is re-evaluated against the CURRENT feasible distance, not
    // just the flag latched at consider(): mark_advertised only tightens FD,
    // so a stale-true flag would otherwise pick a route that loops back.
    if (candidate.valid && candidate.next_hop == hop && candidate.feasible &&
        candidate.metric != kInfiniteRouteMetric &&
        feasible(entry, candidate.sequence, candidate.advertised)) {
      return &candidate;
    }
  }
  return nullptr;
}

const RouteCandidate* RouteTable::best_candidate(const Entry& entry,
                                                 const NodeId exclude) noexcept {
  const RouteCandidate* selected = nullptr;
  for (const auto& candidate : entry.candidates) {
    if (candidate.next_hop == exclude) continue;
    // Same live feasibility re-evaluation as selectable().
    if (!candidate.valid || !candidate.feasible ||
        candidate.metric == kInfiniteRouteMetric ||
        !feasible(entry, candidate.sequence, candidate.advertised)) {
      continue;
    }
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
  return selected;
}

RouteSelection RouteTable::select(const Entry& entry) noexcept {
  // The committed next hop wins while it stays selectable: load-driven
  // alternatives move the selection only through evaluate_entry's
  // hysteresis, never through a bare metric comparison (03 §7, D4-03).
  // Recovery is immediate — a committed hop that lost validity falls
  // through to the best remaining feasible candidate without any hold.
  const RouteCandidate* chosen = selectable(entry, entry.committed_next_hop);
  if (chosen == nullptr) chosen = best_candidate(entry, kInvalidNodeId);
  if (chosen == nullptr) return RouteSelection{};
  return RouteSelection{entry.destination, chosen->next_hop, entry.generation,
                        chosen->sequence, chosen->metric, true};
}

const RouteTable::BusyLink* RouteTable::busy_link(const NodeId next_hop) const noexcept {
  return busy_links_.find(
      [&](const BusyLink& value) { return value.next_hop == next_hop; });
}

std::uint32_t RouteTable::improvement_jitter(const NodeId destination) const noexcept {
  // Deterministic per-(node, destination) dispersion so a fleet evaluating
  // the same congestion does not switch in lockstep (03 §7).
  return static_cast<std::uint32_t>(
      (self_id_ * 31ULL + destination * 17ULL) % (kImprovementJitterMs + 1ULL));
}

void RouteTable::evaluate_entry(Entry& entry, const MonotonicMs now_ms) noexcept {
  const RouteCandidate* committed = selectable(entry, entry.committed_next_hop);
  if (committed == nullptr) {
    // No committed route, or the committed hop just lost validity (expired,
    // withdrawn, FD-tightened): repair commits the raw best immediately —
    // the improvement hold never applies to failure recovery (03 §7). The
    // post-switch hold applies only when this REPLACES a previously
    // committed hop: without it the just-abandoned hop or a third candidate
    // could win the route back on the next evaluation. Arming it on the
    // very first acquisition would pin a suboptimal first commit and
    // starve the improvement path instead.
    const bool was_committed = entry.committed_next_hop != kInvalidNodeId;
    const RouteCandidate* raw = best_candidate(entry, kInvalidNodeId);
    entry.committed_next_hop = raw != nullptr ? raw->next_hop : kInvalidNodeId;
    if (raw != nullptr && was_committed) {
      entry.switch_hold_until_ms = now_ms + kSwitchHoldMs;
    }
    entry.improvement_next_hop = kInvalidNodeId;
    return;
  }

  // Severe-busy fast repair: sustained authenticated BUSY on the committed
  // hop for at least severe_busy_ms permits switching to a fresh feasible
  // alternative without waiting out the improvement hold. The post-switch
  // hold still damps it, and an alternative that is itself severely busy is
  // never a repair target.
  const BusyLink* busy = busy_link(committed->next_hop);
  if (busy != nullptr && now_ms - busy->since_ms >= kSevereBusyMs) {
    const RouteCandidate* alt = best_candidate(entry, committed->next_hop);
    if (alt != nullptr && now_ms >= entry.switch_hold_until_ms) {
      const BusyLink* alt_busy = busy_link(alt->next_hop);
      if (alt_busy == nullptr ||
          now_ms - alt_busy->since_ms < kSevereBusyMs) {
        entry.committed_next_hop = alt->next_hop;
        entry.switch_hold_until_ms = now_ms + kSwitchHoldMs;
        entry.improvement_next_hop = kInvalidNodeId;
      }
    }
    return;
  }

  const RouteCandidate* raw = best_candidate(entry, kInvalidNodeId);
  if (raw == nullptr || raw->next_hop == committed->next_hop) {
    // The committed hop is (still) the best — no improvement pending.
    entry.improvement_next_hop = kInvalidNodeId;
    return;
  }
  // A strictly newer origin sequence is freshness, not a load improvement:
  // it commits promptly like a repair. (raw can never carry an OLDER
  // sequence here — then the committed hop would be best_candidate itself.)
  bool ambiguous = false;
  if (route_sequence_newer(raw->sequence, committed->sequence, ambiguous) || ambiguous) {
    entry.committed_next_hop = raw->next_hop;
    entry.switch_hold_until_ms = now_ms + kSwitchHoldMs;
    entry.improvement_next_hop = kInvalidNodeId;
    return;
  }
  // Topology-fresh improvement: a strictly better ADVERTISED distance is new
  // routing information, not a load measurement — it commits promptly so the
  // advertised snapshot (and the FD it tightens) never lags behind what we
  // know. Only alternatives whose edge comes PURELY from our local link-cost
  // adjustments wait out the improvement hold — that is the D4-04 timescale
  // separation, and it keeps the stale-feasibility counterexample closed.
  // The post-switch hold still damps it: right after a repair the old hop
  // must not win its route back inside switch_hold_ms.
  if (raw->advertised < committed->advertised) {
    if (now_ms >= entry.switch_hold_until_ms) {
      entry.committed_next_hop = raw->next_hop;
      entry.switch_hold_until_ms = now_ms + kSwitchHoldMs;
      entry.improvement_next_hop = kInvalidNodeId;
    }
    return;
  }
  // Improvement gate (contracts improvement_fraction = 0.2 and >=1 cost):
  // raw.metric <= committed.metric * 0.8, evaluated in wide integer math.
  const bool improvement =
      static_cast<std::uint32_t>(raw->metric) * 5U <=
          static_cast<std::uint32_t>(committed->metric) * 4U &&
      committed->metric - raw->metric >= 1;
  if (!improvement) {
    entry.improvement_next_hop = kInvalidNodeId;
    return;
  }
  if (entry.improvement_next_hop != raw->next_hop) {
    // New streak: the alternative must stay the qualifying best for the
    // whole jittered improvement hold before the switch commits.
    entry.improvement_next_hop = raw->next_hop;
    entry.improvement_since_ms = now_ms;
    return;
  }
  const std::uint64_t hold =
      kImprovementHoldMs + improvement_jitter(entry.destination);
  if (now_ms - entry.improvement_since_ms >= hold &&
      now_ms >= entry.switch_hold_until_ms) {
    entry.committed_next_hop = raw->next_hop;
    entry.switch_hold_until_ms = now_ms + kSwitchHoldMs;
    entry.improvement_next_hop = kInvalidNodeId;
  }
}

void RouteTable::evaluate(const MonotonicMs now_ms) noexcept {
  entries_.for_each([&](Entry& entry) { evaluate_entry(entry, now_ms); });
}

bool RouteTable::update_link_cost(const NodeId next_hop, const RouteMetric cost,
                                  const MonotonicMs now_ms) noexcept {
  // §6.3 safety: candidates are recomputed from their STORED advertised
  // metrics; leases (learned/expires) are never touched, FD is never
  // deleted, and withdrawn candidates (advertised = infinity) stay infinite.
  // cost == 0 is refused — a zero-cost link is never introduced (§6.2).
  if (next_hop == kInvalidNodeId || cost == 0) return false;
  bool touched = false;
  entries_.for_each([&](Entry& entry) {
    bool changed = false;
    for (auto& candidate : entry.candidates) {
      if (!candidate.valid || candidate.next_hop != next_hop) continue;
      candidate.metric = route_metric_add(candidate.advertised, cost);
      // Same rule as consider(): feasibility compares the advertised metric
      // with the CURRENT FD; the link-cost total only gates finiteness.
      candidate.feasible =
          candidate.metric != kInfiniteRouteMetric &&
          feasible(entry, candidate.sequence, candidate.advertised);
      changed = true;
    }
    if (changed) {
      evaluate_entry(entry, now_ms);
      touched = true;
    }
  });
  return touched;
}

void RouteTable::note_next_hop_busy(const NodeId next_hop,
                                    const MonotonicMs since_ms) noexcept {
  if (next_hop == kInvalidNodeId) return;
  auto* link = busy_links_.find(
      [&](const BusyLink& value) { return value.next_hop == next_hop; });
  if (link == nullptr) {
    link = busy_links_.allocate();
    if (link == nullptr) return;  // bounded: a dropped report is a lost hint
    link->next_hop = next_hop;
  }
  link->since_ms = since_ms;
}

void RouteTable::clear_next_hop_busy(const NodeId next_hop) noexcept {
  auto* link = busy_links_.find(
      [&](const BusyLink& value) { return value.next_hop == next_hop; });
  if (link != nullptr) busy_links_.release(link);
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
  // A retraction for a destination we never heard of must not allocate a
  // table slot that GC would never collect.
  Entry* entry = advertisement.metric == kInfiniteRouteMetric
                     ? const_cast<Entry*>(find(advertisement.destination))
                     : find_or_allocate(advertisement.destination);
  if (entry == nullptr) {
    return advertisement.metric == kInfiniteRouteMetric
               ? RouteUpdateResult::Ignored
               : RouteUpdateResult::NoCapacity;
  }

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
    // A new origin incarnation invalidates every committed/pending switch
    // decision made against the previous one's state.
    entry->committed_next_hop = kInvalidNodeId;
    entry->improvement_next_hop = kInvalidNodeId;
    entry->switch_hold_until_ms = 0;
    entry->improvement_ad_ms = 0;
  }

  // Retractions pass the generation check above (a stale-generation withdraw
  // must not kill a fresh route), then withdraw marks the candidate infeasible,
  // holds the failed hop down and arms the tombstone for GC.
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
  *candidate = RouteCandidate{next_hop, advertisement.sequence, total,
                              advertisement.metric, now_ms,
                              now_ms + lifetime_ms, is_feasible, true};
  entry->tombstone_expires_at_ms = 0;
  if (is_feasible) {
    entry->sequence_request_needed = false;
    evaluate_entry(*entry, now_ms);
    return existed ? RouteUpdateResult::Updated : RouteUpdateResult::Accepted;
  }
  // An infeasible alternate is harmless while a feasible selected route still exists.
  // Request a newer origin sequence only when feasibility prevents all forwarding.
  entry->sequence_request_needed = !select(*entry).valid;
  evaluate_entry(*entry, now_ms);
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
      // expires — it may still carry a SeqNoRequest toward the origin. The
      // advertised metric is cleared too so a later load-cost refresh can
      // never resurrect the withdrawal (03 §6.3).
      candidate.feasible = false;
      candidate.metric = kInfiniteRouteMetric;
      candidate.advertised = kInfiniteRouteMetric;
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
    evaluate_entry(*entry, now_ms);
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
      } else if (entry.hold_next_hop == next_hop) {
        // A restarted relay's previous-incarnation state is stale but fresh
        // advertisements must not be held down by the earlier failure.
        entry.hold_next_hop = kInvalidNodeId;
        entry.hold_until_ms = 0;
      }
      if (!select(entry).valid) entry.sequence_request_needed = true;
      arm_tombstone(entry, now_ms);
      evaluate_entry(entry, now_ms);
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
    if (removed) evaluate_entry(entry, now_ms);
  });
}

bool RouteTable::reclaim_tombstone() noexcept {
  // Only the oldest ARMED tombstone is eligible: evicting anything younger
  // would trade bounded FD memory for faster capacity churn, and a live
  // entry (no tombstone armed) is never a victim — collect first, release
  // after the pool scan per the for_each contract.
  Entry* oldest = nullptr;
  entries_.for_each([&](Entry& entry) {
    if (entry.tombstone_expires_at_ms == 0) return;
    if (oldest == nullptr ||
        entry.tombstone_expires_at_ms < oldest->tombstone_expires_at_ms) {
      oldest = &entry;
    }
  });
  return entries_.release(oldest);
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
    entry->last_selected = selected;  // same snapshot the wire just carried
    return true;
  }
  bool ambiguous = false;
  if (route_sequence_newer(selected.sequence, entry->feasible.sequence, ambiguous) ||
      (!ambiguous && selected.sequence == entry->feasible.sequence &&
       selected.metric < entry->feasible.metric)) {
    entry->feasible.sequence = selected.sequence;
    entry->feasible.metric = selected.metric;
  }
  // The selection state that just went on the wire — DATA forwarding,
  // advertisements and FD all derive from this same snapshot (03 §6.3).
  entry->last_selected = selected;
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
