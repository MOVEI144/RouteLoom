#include "node_internal.hpp"

namespace routeloom {

Status MeshNode::queue_route_update(const NodeId neighbor,
                                    const MonotonicMs now_ms) noexcept {
  TxJob job = link_control_job(FrameType::RouteUpdate, neighbor, kControlLifetimeMs,
                               now_ms);

  ByteWriter writer(MutableByteView{job.plain.payload.data(), job.plain.payload.size()});
  auto status = writer.write_u8(0);  // patched after records are appended
  if (!status) return status;
  std::uint8_t count = 0;
  auto append = [&](const NodeId destination, const RouteGeneration generation,
                    const RouteSequence sequence, const RouteMetric metric) -> bool {
    if (count >= kMaxRouteRecordsPerFrame) return false;
    if (writer.write_u64(destination) && writer.write_u32(generation) &&
        writer.write_u16(sequence) && writer.write_u16(metric)) {
      ++count;
      return true;
    }
    return false;
  };
  append(config_.node, config_.route_generation, self_route_sequence_, 0);
  // Flat group tree (dev-flow §6.3): group-root records lead every update —
  // the per-root child lease in the receiver is only as fresh as its last
  // poisoned/finite root record, so roots must not wait for the rotating
  // sweep. The same split-horizon poison applies; a duplicate from the dump
  // below is idempotent.
  if (!gateway_scoped()) {
    for (const NodeId root : config_.group_roots) {
      if (root == kInvalidNodeId || root == config_.node) continue;
      const RouteSelection selected = routes_.best(root);
      if (selected.valid) {
        // Same rules as scoped_record(): a generation-0 placeholder (a
        // direct-neighbor seed before the peer's own record) is never
        // advertised; otherwise split-horizon poison applies.
        if (selected.generation == 0) continue;
        append(root, selected.generation, selected.sequence,
               (!relay_enabled_ || selected.next_hop == neighbor) ? kInfiniteRouteMetric
                                                                  : selected.metric);
        continue;
      }
      // A lost root route still announces at infinity (same rule as the
      // scoped tree): the parent's child lease for us stays useful — we get
      // its downward refresh instead of dropping off the group tree.
      RouteTable::LostRoute lost{};
      if (routes_.lost_route(root, lost)) {
        append(root, lost.generation, lost.sequence, kInfiniteRouteMetric);
      }
    }
  }
  // A frame holds at most kMaxRouteRecordsPerFrame records. Rotate a
  // per-neighbor cursor through the selected routes so a full dump spans
  // successive updates instead of permanently starving the tail entries.
  auto* neighbor_record = find_neighbor(neighbor);
  const std::size_t skip =
      neighbor_record != nullptr ? neighbor_record->route_cursor : 0;
  std::size_t index = 0;
  std::size_t advertised_count = 0;
  std::array<NodeId, kMaxRouteRecordsPerFrame> finite_records{};
  std::size_t finite_count = 0;
  bool writer_full = false;
  routes_.for_each_selected([&](const RouteSelection& selection) {
    if (selection.destination == config_.node) return;
    if (index++ < skip || writer_full) return;
    // Relay-off withdrawal (01 §policy): a node that refuses transit must
    // not keep advertising itself as a viable path — every selected route
    // is retracted at infinity so neighbors stop sending us transit work.
    const RouteMetric advertised =
        (!relay_enabled_ || selection.next_hop == neighbor)
            ? kInfiniteRouteMetric
            : selection.metric;
    if (!append(selection.destination, selection.generation, selection.sequence,
                advertised)) {
      writer_full = true;
      return;
    }
    ++advertised_count;
    // FD is refreshed only when a finite advertisement actually leaves; a
    // split-horizon retraction (infinity) must not touch feasibility state.
    if (advertised != kInfiniteRouteMetric) finite_records[finite_count++] = selection.destination;
  });
  const std::size_t next = skip + advertised_count;
  const std::uint8_t next_cursor = static_cast<std::uint8_t>(next >= index ? 0 : next);
  // Retractions: destinations that lost their last feasible route are
  // advertised as infinity so neighbors withdraw promptly instead of waiting
  // out the lease (RFC 8966 §3.7.2). The record budget bounds the burst.
  routes_.for_each_lost([&](const RouteTable::LostRoute& lost) {
    if (writer_full || lost.destination == config_.node) return;
    if (!append(lost.destination, lost.generation, lost.sequence,
                kInfiniteRouteMetric)) {
      writer_full = true;
    }
  });
  job.plain.payload[0] = count;
  job.plain.payload_size = writer.size();
  status = scheduler_.enqueue(std::move(job), config_.node, now_ms);
  // Failed admission cannot advance the advertisement cursor or FD: the
  // route was never queued and the next update must retry the same page.
  if (status) {
    if (neighbor_record != nullptr) neighbor_record->route_cursor = next_cursor;
    for (std::size_t i = 0; i < finite_count; ++i) {
      routes_.mark_advertised(finite_records[i]);
    }
  }
  return status;
}

Status MeshNode::queue_seqno_request(const NodeId peer, const NodeId requester,
                                         const NodeId destination,
                                         const RouteSequence requested_sequence,
                                         const std::uint32_t request_id,
                                         const std::uint8_t ttl,
                                         const MonotonicMs now_ms) noexcept {
  if (ttl == 0 || peer == kInvalidNodeId || destination == kInvalidNodeId ||
      requester == kInvalidNodeId) {
    return Status::error(StatusCode::InvalidArgument, "invalid sequence request");
  }
  TxJob job = link_control_job(FrameType::SeqnoRequest, peer, kSeqnoRequestLifetimeMs,
                               now_ms);

  ByteWriter writer(MutableByteView{job.plain.payload.data(), job.plain.payload.size()});
  Status status;
#define RL_WRITE_SEQNO(expr) do { status = (expr); if (!status) return status; } while (false)
  RL_WRITE_SEQNO(writer.write_u64(requester));
  RL_WRITE_SEQNO(writer.write_u64(destination));
  RL_WRITE_SEQNO(writer.write_u16(requested_sequence));
  RL_WRITE_SEQNO(writer.write_u32(request_id));
  RL_WRITE_SEQNO(writer.write_u8(ttl));
#undef RL_WRITE_SEQNO
  job.plain.payload_size = writer.size();
  return scheduler_.enqueue(std::move(job), config_.node, now_ms);
}

void MeshNode::handle_route_update(const wire::PlainFrame& frame, const NodeId peer,
                                   const MonotonicMs now_ms) noexcept {
  const auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || !neighbor->active) return;
  ByteReader reader(ByteView{frame.payload.data(), frame.payload_size});
  std::uint8_t count = 0;
  if (!reader.read_u8(count) || count > kMaxRouteRecordsPerFrame ||
      reader.remaining() != static_cast<std::size_t>(count) * kRouteRecordBytes) {
    observer_.on_diagnostic("INVALID_ROUTE_UPDATE", peer, &frame.header.message);
    return;
  }
  std::array<RouteAdvertisement, kMaxRouteRecordsPerFrame> records{};
  for (std::uint8_t i = 0; i < count; ++i) {
    if (!reader.read_u64(records[i].destination) ||
        !reader.read_u32(records[i].generation) ||
        !reader.read_u16(records[i].sequence) ||
        !reader.read_u16(records[i].metric)) {
      return;
    }
  }
  apply_route_records(records.data(), count, peer, now_ms, true);
}

void MeshNode::apply_route_records(const RouteAdvertisement* records,
                                   const std::size_t count, const NodeId peer,
                                   const MonotonicMs now_ms,
                                   const bool pairwise_authenticated) noexcept {
  auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || !neighbor->active || records == nullptr) return;

  // Relay restart: the peer's self record (destination == peer) carries a
  // higher origin generation than we last saw. The restarted relay lost its
  // routing state, so every route learned from its previous incarnation is
  // stale. Drop via-peer candidates without hold-down — post-restart
  // advertisements are legitimate fresh state.
  bool restarted = false;
  for (std::size_t i = 0; i < count; ++i) {
    if (records[i].destination == peer && records[i].generation > neighbor->generation) {
      restarted = neighbor->generation != 0;
      neighbor->generation = records[i].generation;
    }
  }
  if (restarted) {
    routes_.invalidate_next_hop(peer, now_ms, false);
    // Only pairwise authentication can retire per-peer measurement. A
    // GroupLink frame may update route generation but proves no peer boot.
    if (pairwise_authenticated) reset_neighbor_measurement(*neighbor);
    // The restarted peer's previous-incarnation group child evidence is
    // stale too: its next hops toward the group roots may differ. (Flat
    // profile only — under scoped this storage is the tree-role arm, which
    // keeps its own lease lifecycle.)
    if (!gateway_scoped()) neighbor->tree.group_child_until_ms.fill(0);
    trigger_route_advertisement(now_ms);
    observer_.on_diagnostic("PEER_RESTARTED_ROUTES_FLUSHED", peer, nullptr);
  }
  // Scoped profile: tree-role inference (poisoned gateway record = the peer
  // routes to that gateway through us). Scheduling state only — route state
  // below still moves exclusively through consider().
  note_scoped_update(*neighbor, records, count, now_ms);
  // Flat profile: per-root child leases (poisoned group-root record = the
  // peer's committed next hop toward that root is us).
  note_flat_group_update(*neighbor, records, count, now_ms);

  for (std::size_t i = 0; i < count; ++i) {
    const auto& advertisement = records[i];
    if (advertisement.destination == config_.node) continue;
    // Advertisements are considered against the CURRENT effective link
    // cost — the same cost update_link_cost applies to stored candidates,
    // so new and existing routes are built from one consistent state.
    const auto result = routes_.consider(advertisement, peer, neighbor->link_cost, now_ms,
                                         config_.route_lifetime_ms);
    if (result == RouteUpdateResult::Infeasible) {
      observer_.on_diagnostic("ROUTE_INFEASIBLE_SEQNO_NEEDED", peer, nullptr);
    } else if (result == RouteUpdateResult::StaleGeneration) {
      observer_.on_diagnostic("ROUTE_STALE_GENERATION", peer, nullptr);
    } else if (result == RouteUpdateResult::HeldDown) {
      observer_.on_diagnostic("ROUTE_HELD_DOWN", peer, nullptr);
    } else if (result != RouteUpdateResult::Accepted &&
               result != RouteUpdateResult::Updated &&
               result != RouteUpdateResult::Ignored) {
      observer_.on_diagnostic("ROUTE_UPDATE_REJECTED", peer, nullptr);
    }
  }
}

void MeshNode::handle_seqno_request(const wire::PlainFrame& frame, const NodeId peer,
                                        const MonotonicMs now_ms) noexcept {
  if (frame.payload_size != kSeqnoRequestPayloadBytes) {
    observer_.on_diagnostic("INVALID_SEQNO_REQUEST", peer, &frame.header.message);
    return;
  }
  ByteReader reader(ByteView{frame.payload.data(), frame.payload_size});
  NodeId requester = kInvalidNodeId;
  NodeId destination = kInvalidNodeId;
  RouteSequence requested_sequence = 0;
  std::uint32_t request_id = 0;
  std::uint8_t ttl = 0;
  if (!reader.read_u64(requester) || !reader.read_u64(destination) ||
      !reader.read_u16(requested_sequence) || !reader.read_u32(request_id) ||
      !reader.read_u8(ttl) || reader.remaining() != 0 || ttl == 0 ||
      ttl > kSeqnoRequestMaxTtl ||
      requester == kInvalidNodeId || destination == kInvalidNodeId) {
    observer_.on_diagnostic("INVALID_SEQNO_REQUEST", peer, &frame.header.message);
    return;
  }

  auto* seen = seqno_seen_.find([&](const SeqnoSeen& value) {
    return value.requester == requester && value.destination == destination &&
           value.request_id == request_id;
  });
  if (seen != nullptr) return;
  seen = seqno_seen_.allocate();
  if (seen == nullptr) {
    observer_.on_diagnostic("SEQNO_DEDUP_FULL", peer, &frame.header.message);
    return;
  }
  *seen = SeqnoSeen{requester, destination, request_id, now_ms + kSeqnoRequestLifetimeMs};
  // Scoped profile: the answer (a fresher sequence) must flow back along the
  // request's path, which is not necessarily a tree link — the previous hop
  // registers a short interest so triggered updates reach it, and an answer
  // from our own table is sent to it directly (routing-scale.md §3.3).
  Neighbor* requesting = gateway_scoped() ? find_neighbor(peer) : nullptr;
  if (requesting != nullptr) note_scoped_interest(*requesting, now_ms);

  if (destination == config_.node) {
    bool ambiguous = false;
    if (route_sequence_newer(requested_sequence, self_route_sequence_, ambiguous) ||
        ambiguous) {
      // RFC 8966 §3.8.1.2: an origin MUST NOT increase its sequence number by
      // more than 1 in reaction to a single seqno request. If one bump is not
      // enough, the requester's bounded retries converge instead.
      self_route_sequence_ = static_cast<RouteSequence>(self_route_sequence_ + 1U);
    }
    trigger_route_advertisement(now_ms);
    observer_.on_diagnostic("SEQNO_REQUEST_SATISFIED", peer, &frame.header.message);
    return;
  }

  if (ttl <= 1) return;
  // RFC 8966 §3.8.1.2: a node holding a route with a sequence at least as new
  // as the requested one answers from its own table instead of forwarding the
  // request toward the origin. Broadcast reaches the requester's path and
  // every other neighbor that may share the gap.
  const RouteSelection selected = routes_.best(destination);
  if (selected.valid) {
    bool ambiguous = false;
    const bool requested_newer =
        route_sequence_newer(requested_sequence, selected.sequence, ambiguous);
    if (!requested_newer && !ambiguous) {
      if (requesting != nullptr) {
        // Scoped profile: a generic trigger would only carry self + gateway
        // records; the requester needs THIS destination's record.
        requesting->tree.scoped.pull_target = destination;
        requesting->pull_answer_pending = true;
      } else {
        trigger_route_advertisement(now_ms);
      }
      return;
    }
  }
  // One received request forwards along exactly one path (spec: a forwarder
  // must not branch). The selected route is preferred; an infeasible-but-live
  // candidate may carry it when feasibility blocks all forwarding.
  const NodeId next = routes_.request_next_hop(destination, 0, peer, requester);
  if (next == kInvalidNodeId || next == config_.node) {
    observer_.on_diagnostic("SEQNO_REQUEST_NO_PATH", peer, &frame.header.message);
    return;
  }
  (void)queue_seqno_request(next, requester, destination, requested_sequence,
                            request_id, static_cast<std::uint8_t>(ttl - 1U), now_ms);
}

std::int64_t MeshNode::control_budget_balance(const MonotonicMs now_ms) noexcept {
  if (now_ms > control_budget_last_ms_) {
    // Spec-envelope refill (1000µs/s == 1µs/ms). A balance that ran
    // negative through an over-capacity completion debit earns credit for
    // the whole interval, so elapsed clamps to the headroom to a FULL
    // bucket — not the capacity itself; credit beyond a full bucket is
    // unreachable anyway. The modular subtraction keeps room correct for
    // any negative balance.
    const std::uint64_t room =
        control_budget_tokens_us_ >=
                static_cast<std::int64_t>(kControlBudgetCapacityUs)
            ? 0
            : static_cast<std::uint64_t>(
                  static_cast<std::int64_t>(kControlBudgetCapacityUs)) -
                  static_cast<std::uint64_t>(control_budget_tokens_us_);
    const std::uint64_t elapsed = std::min<std::uint64_t>(
        now_ms - control_budget_last_ms_, room);
    control_budget_last_ms_ = now_ms;
    control_budget_tokens_us_ += static_cast<std::int64_t>(
        elapsed * kControlBudgetRefillUsPerS / 1000ULL);
  }
  return control_budget_tokens_us_;
}

MonotonicMs MeshNode::control_budget_wait_ms(const MonotonicMs now_ms) noexcept {
  // Emission demand = the calibrated per-frame air time: EWMA of measured
  // control-domain service, seeded at the pinned max-frame cost before any
  // sample exists. This keeps the bucket honest under the spec envelope
  // without charging a full worst-case frame the local driver never
  // actually burns. Demand is clamped to the bucket capacity: the refill
  // can never push the balance past one max frame's air time (§14 burst
  // >= 1 max frame), so a single over-capacity sample — driver service
  // including CCA backoff/retries — would otherwise defer against a
  // balance the bucket can never reach, silently stalling all management
  // emissions. The excess cost still arrives as the completion debit and
  // is repaid through the wait computed for the next emission (§8: a
  // normal route must never expire on this node's own budget wait).
  const std::int64_t demand = std::min<std::int64_t>(
      static_cast<std::int64_t>(control_service_ewma_us_),
      static_cast<std::int64_t>(kControlBudgetCapacityUs));
  const std::int64_t deficit = demand - control_budget_balance(now_ms);
  if (deficit <= 0) return 0;
  // deficit µs at the pinned refill rate -> ms, rounding up so the wait
  // lands affordable rather than one tick short.
  return (static_cast<std::uint64_t>(deficit) * 1000ULL +
          kControlBudgetRefillUsPerS - 1ULL) /
         kControlBudgetRefillUsPerS;
}

bool MeshNode::control_budget_refresh_fits(const MonotonicMs now_ms,
                                           const MonotonicMs wait_ms,
                                           const std::size_t fanout) noexcept {
  // Fan-out draw: every neighbor's refresh pulls the same bucket, so the
  // capacity decision prices `fanout` frames at the calibrated demand —
  // not just this emission — when bounding the wait inside the lease.
  const std::int64_t workload = static_cast<std::int64_t>(fanout) *
                                std::min<std::int64_t>(
                                    static_cast<std::int64_t>(control_service_ewma_us_),
                                    static_cast<std::int64_t>(kControlBudgetCapacityUs));
  const std::int64_t deficit = workload - control_budget_balance(now_ms);
  const std::uint64_t afford_ms =
      deficit <= 0 ? 0
                   : (static_cast<std::uint64_t>(deficit) * 1000ULL +
                      kControlBudgetRefillUsPerS - 1ULL) /
                         kControlBudgetRefillUsPerS;
  // Page count: the live route table's record pages each neighbor must
  // cycle through (the frame carries the self record plus entries). The
  // scoped profile spreads a whole upward cycle inside route_refresh_ticks
  // periods, so its refresh span is the tick count, not the page count.
  const std::uint64_t pages =
      gateway_scoped()
          ? config_.route_refresh_ticks
          : (static_cast<std::uint64_t>(routes_.size()) + kMaxRouteRecordsPerFrame) /
                kMaxRouteRecordsPerFrame;
  // 03 §8 refresh bound — pages*round_period + budget_wait + jitter +
  // loss_margin — against the ACTUAL lease the refresh must land inside.
  const std::uint64_t bound =
      pages * config_.route_advertisement_period_ms +
      std::max<std::uint64_t>(wait_ms, afford_ms) + kTriggeredJitterMs +
      config_.route_advertisement_period_ms;
  return config_.route_lifetime_ms > bound;
}

void MeshNode::note_control_budget_unsat() noexcept {
  saturating_inc(budget_stats_.control_budget_unsatisfiable);
  if (!control_budget_unsat_reported_) {
    control_budget_unsat_reported_ = true;
    observer_.on_diagnostic("CONTROL_BUDGET_UNSATISFIABLE", kInvalidNodeId,
                            nullptr);
  }
}

void MeshNode::schedule_route_advertisements(const MonotonicMs now_ms) noexcept {
  if (now_ms < next_route_advertisement_ms_ || scheduler_.full()) return;
  std::array<NodeId, kNeighborCapacity> active{};
  std::size_t count = 0;
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (neighbor.active && count < active.size()) active[count++] = neighbor.node;
  });
  if (count == 0) {
    next_route_advertisement_ms_ = now_ms + config_.route_advertisement_period_ms;
    return;
  }
  // §14 management airtime budget — calibrated profiles only. The
  // uncalibrated default profile never applies the spec-envelope refill
  // limit to route maintenance (radio.md §9/§14). When enabled, an
  // emission may only schedule while the bucket covers one frame's air
  // time; a needed deferral is allowed only while the §8 refresh bound
  // (fan-out × demand, live page count, actual lease) still fits —
  // otherwise the budget cannot sustain route maintenance for this
  // configuration: the emission goes out unfunded (a normal route must
  // never expire on this node's own budget wait) and the breach is
  // surfaced, never queued as a normal emission.
  if (config_.control_budget_gate_enabled) {
    const MonotonicMs wait_ms = control_budget_wait_ms(now_ms);
    if (wait_ms > 0) {
      if (control_budget_refresh_fits(now_ms, wait_ms, count)) {
        next_route_advertisement_ms_ = now_ms + wait_ms;
        return;
      }
      note_control_budget_unsat();
    } else {
      control_budget_unsat_reported_ = false;
    }
  }
  if (gateway_scoped()) {
    // One tick of the scoped profile: only the gateway-tree links that are
    // due this tick are refreshed (routing-scale.md §3.2).
    next_route_advertisement_ms_ = now_ms + config_.route_advertisement_period_ms;
    run_scoped_tick(now_ms);
    return;
  }
  const NodeId peer = active[route_neighbor_cursor_ % count];
  route_neighbor_cursor_ = (route_neighbor_cursor_ + 1) % count;
  const auto status = queue_route_update(peer, now_ms);
  if (!status) {
    // Retry the same neighbor and page; an admission refusal is not a
    // route refresh and must not consume a full lease interval.
    route_neighbor_cursor_ = (route_neighbor_cursor_ + count - 1) % count;
    next_route_advertisement_ms_ = now_ms + 50;
    return;
  }
  const auto interval = std::max<std::uint32_t>(
      50, config_.route_advertisement_period_ms / static_cast<std::uint32_t>(count));
  // Lease renewal cannot be halved at the DATA watermark: with a 15s
  // flat lease, one lost update after a 10s interval expires the route.
  next_route_advertisement_ms_ = now_ms + interval;
}

void MeshNode::expire_sequence_requests(const MonotonicMs now_ms) noexcept {
  saturating_add(work_stats_.expiry_slots_scanned,
                 seqno_seen_.capacity() + seqno_state_.capacity());
  seqno_seen_.erase_if(
      [&](const SeqnoSeen& value) { return value.expires_at_ms <= now_ms; });
  seqno_state_.erase_if(
      [&](const SeqnoState& value) { return value.expires_at_ms <= now_ms; });
}

void MeshNode::schedule_sequence_requests(const MonotonicMs now_ms) noexcept {
  // Sequence requests are the repair path for infeasible destinations —
  // they must keep flowing under a data flood (03 §8). Bounded by the
  // global in-flight cap, linear backoff saturating at the max cooldown
  // and the queue admission check below; no watermark early-out.
  // Outstanding = requests sent inside the dedup window, still waiting for a
  // fresh advertisement. Bounded so a dead origin cannot pile up requests.
  std::size_t inflight = 0;
  seqno_state_.for_each([&](const SeqnoState& value) {
    if (value.last_sent_ms != 0 &&
        value.last_sent_ms + kSeqnoRequestLifetimeMs > now_ms) {
      ++inflight;
    }
  });

  routes_.for_each_sequence_request([&](const NodeId destination,
                                        const RouteSequence requested_sequence) {
    auto* state = seqno_state_.find(
        [&](const SeqnoState& value) { return value.destination == destination; });
    if (state == nullptr) {
      state = seqno_state_.allocate();
      if (state == nullptr) return;
      state->destination = destination;
      state->requested_sequence = requested_sequence;
      state->next_request_ms = now_ms;
    }
    state->expires_at_ms = now_ms + kSeqnoStateDwellMs;
    bool ambiguous = false;
    if (route_sequence_newer(requested_sequence, state->requested_sequence, ambiguous) ||
        ambiguous) {
      state->next_request_ms = now_ms;  // newer need: fresh retry window
      state->attempts = 0;
    }
    state->requested_sequence = requested_sequence;
    if (now_ms < state->next_request_ms || scheduler_.full()) return;
    // No retry cap (issue #50): a destination whose infeasible
    // advertisements keep renewing their lease would never see a fresh
    // sequence again if probing stopped — permanent unreachability with no
    // recovery path. Requests keep flowing on the bounded max-cooldown
    // cadence instead (per-destination rate still capped by backoff, the
    // in-flight cap and the dedup window).
    if (inflight >= kSeqnoMaxInflight) return;

    // Candidate rotation uses probe_cursor, not the saturating backoff
    // counter: a capped attempts would pin every later request to
    // hops[attempts % count] and starve the other candidates forever.
    const NodeId next = routes_.request_next_hop(destination, state->probe_cursor);
    if (next == kInvalidNodeId || next == config_.node) return;
    const std::uint32_t request_id = next_seqno_request_id_++;
    auto* seen = seqno_seen_.allocate();
    if (seen == nullptr) return;
    *seen = SeqnoSeen{config_.node, destination, request_id, now_ms + kSeqnoRequestLifetimeMs};
    if (queue_seqno_request(next, config_.node, destination, requested_sequence,
                            request_id, kDefaultHopLimit, now_ms)) {
      // Saturate, never wrap: attempts==0 would zero the backoff below and
      // turn the bounded cadence into a per-poll flood. The probe cursor is
      // deliberately NOT saturating — it wraps so candidate rotation keeps
      // cycling past the backoff cap.
      if (state->attempts != UINT8_MAX) ++state->attempts;
      ++state->probe_cursor;
      ++inflight;
      state->last_sent_ms = now_ms;
      // Linear backoff keeps retries bounded without a growing flood; the
      // >=50% queue watermark halves the probing rate on top (03 §4).
      const std::uint32_t factor = scheduler_.background_reduced() ? 2 : 1;
      state->next_request_ms = now_ms + std::min<std::uint32_t>(
          kSeqnoRequestMaxCooldownMs,
          kSeqnoRequestCooldownMs * state->attempts * factor);
      char detail[64];
      std::snprintf(detail, sizeof detail, "SEQNO_REQUEST_SENT dest=%llu seq=%u att=%u",
                    static_cast<unsigned long long>(destination), requested_sequence,
                    state->attempts);
      observer_.on_diagnostic(detail, next, nullptr);
    } else {
      seqno_seen_.release(seen);
    }
  });
}

void MeshNode::trigger_route_advertisement(const MonotonicMs now_ms) noexcept {
  // Generic triggers (neighbor loss, sequence bump, peer restart, relay
  // policy) change what every tree link must hear: in the scoped profile the
  // burst covers the parents (self record + dirty routes) and the children
  // and interested neighbors (self + gateway records).
  if (gateway_scoped()) scoped_trigger_all_ = true;
  arm_triggered_advertisement(now_ms);
}

void MeshNode::arm_triggered_advertisement(const MonotonicMs now_ms) noexcept {
  // Deterministic jitter decorrelates bursts across nodes without a RNG.
  const MonotonicMs jitter = (config_.node * 31ULL + ++trigger_counter_ * 7ULL) %
                             (kTriggeredJitterMs + 1ULL);
  const MonotonicMs earliest = std::max(now_ms, next_triggered_ms_) + jitter;
  if (!triggered_advertisement_ || earliest < triggered_at_ms_) {
    triggered_advertisement_ = true;
    triggered_at_ms_ = earliest;
  }
}

void MeshNode::run_triggered_advertisement(const MonotonicMs now_ms) noexcept {
  if (!triggered_advertisement_ || now_ms < triggered_at_ms_) return;
  // Same §14 gate as the periodic path — calibrated profiles only: an
  // unaffordable burst re-arms at its token wait, but only while the §8
  // refresh bound (fan-out × demand, page count, actual lease) can absorb
  // it; otherwise the burst goes out unfunded and the breach surfaces.
  if (config_.control_budget_gate_enabled) {
    const MonotonicMs wait_ms = control_budget_wait_ms(now_ms);
    if (wait_ms > 0) {
      std::size_t fanout = 0;
      neighbors_.for_each([&](const Neighbor& neighbor) {
        if (neighbor.active) ++fanout;
      });
      if (control_budget_refresh_fits(now_ms, wait_ms, fanout)) {
        triggered_at_ms_ = now_ms + wait_ms;
        return;  // stays armed
      }
      note_control_budget_unsat();
    } else {
      control_budget_unsat_reported_ = false;
    }
  }
  triggered_advertisement_ = false;
  // The gate charges affordability for ONE frame, then emits one
  // RouteUpdate per active neighbor: a multi-neighbor burst under-charges
  // up front, repaid as each completion debits its measured service (the
  // charge-at-completion model the rest of §14 runs on).
  // >=50% queue watermark: triggered bursts run at half rate (03 §4).
  next_triggered_ms_ = now_ms + kTriggeredUpdateMinIntervalMs *
                                   (scheduler_.background_reduced() ? 2 : 1);
  if (gateway_scoped()) {
    // Scoped burst: tree links and interested neighbors only — never the
    // flat all-neighbor dump (issue #41 burst of F frames per trigger).
    run_scoped_triggered(now_ms);
    return;
  }
  bool retry = false;
  neighbors_.for_each([&](const Neighbor& neighbor) {
    if (!neighbor.active) return;
    if (scheduler_.full() || !queue_route_update(neighbor.node, now_ms)) retry = true;
  });
  if (retry) {
    // The triggered update is still owed to at least one neighbor.
    // Duplicate refreshes are harmless; losing a withdrawal is not.
    triggered_advertisement_ = true;
    triggered_at_ms_ = std::max(now_ms + 50, next_triggered_ms_);
  }
}

void MeshNode::scan_selection_changes(const MonotonicMs now_ms) noexcept {
  if (!gateway_scoped()) {
    routes_.for_each_selected_change(
        [&](const RouteSelection&) { trigger_route_advertisement(now_ms); },
        now_ms);
    return;
  }
  routes_.for_each_selected_change(
      [&](const RouteSelection& selection, const RouteSelection& previous) {
        note_scoped_change(selection, previous, now_ms);
      },
      now_ms);
}

}  // namespace routeloom
