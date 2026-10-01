#include "node_internal.hpp"

namespace routeloom {

// ---------------------------------------------------------------------------
// P3 load coupling (03-congestion.md §6, §7)
// ---------------------------------------------------------------------------

void MeshNode::reset_neighbor_measurement(Neighbor& neighbor) noexcept {
  neighbor.exchange_work = 0;
  neighbor.exchange_accepts = 0;
  neighbor.exchange_window_ms = 0;
  neighbor.queue_sojourn_ewma_ms = 0;
  neighbor.sojourn_samples = 0;
  neighbor.last_sojourn_ms = 0;
  neighbor.sojourn_window_ms = 0;
  neighbor.hop_rtt_ewma_ms = 0;
  neighbor.hop_rtt_samples = 0;
  neighbor.metric_window_dirty = false;
  neighbor.metric_sources = 0;
  neighbor.last_cost_relax_ms = 0;
  neighbor.link_cost = neighbor.metric;
}

void MeshNode::refresh_link_cost(Neighbor& neighbor, const MonotonicMs now_ms) noexcept {
  // §6.1 base cost: the measured exchange ratio against the nominal. The
  // measured cost is in units of exchanges (attempt count per authenticated
  // accept), never driver microseconds — driver service time may already
  // contain MAC retries, so using it would double-count ETX. Below the
  // minimum sample count the nominal stands (no measured reference is ever
  // invented). A dirty window (sdk-completion/03 §3.3 — some attempt resolved
  // Unknown) may still count work toward worsening but must never let the
  // measured ratio improve the base off nominal.
  // Submission work precedes its authenticated accept. Exclude the latest
  // unresolved attempt of each exchange, but retain settled failure work
  // even when other exchanges toward this peer remain in flight.
  std::uint32_t pending_work = 0;
  if (physical_.active && physical_.job.requires_hop_accept &&
      physical_.job.peer == neighbor.node) {
    pending_work = 1;
  }
  awaiting_hop_.for_each([&](const AwaitingHop& value) {
    if (value.job.peer == neighbor.node) ++pending_work;
  });
  const bool exchange_pending = pending_work != 0;
  const std::uint32_t settled_work =
      neighbor.exchange_work > pending_work ? neighbor.exchange_work - pending_work : 0;
  RouteMetric base = neighbor.metric;
  if (neighbor.exchange_accepts >= kExchangeMinAccepts) {
    const RouteMetric measured = measured_link_base(
        neighbor.metric, settled_work, neighbor.exchange_accepts);
    if (!neighbor.metric_window_dirty || measured >= base) base = measured;
  }
  // §6.2 queue penalty: ONLY our egress sojourn toward this peer, smoothed
  // over the observation window. A stale or absent sample reads as 0 — a
  // quiet queue is not congestion. The peer's own queue delay lives inside
  // its advertised metric and is never re-added here.
  const std::uint32_t queue_ms =
      neighbor.last_sojourn_ms != 0 &&
              now_ms - neighbor.last_sojourn_ms <= kObservationWindowMs
          ? neighbor.queue_sojourn_ewma_ms
          : 0;
  // §3.4 refusal-pressure floor: a saturated scheduler stops producing
  // sojourn samples exactly when congestion is worst, so pool occupancy is
  // folded in as penalty steps — same cap, max() not + (one congestion
  // reading, counted once). The floor engages only while refusals are
  // actually observed (§3.3 evidence): occupancy alone still produces
  // sojourn samples, so a merely-full pool must not inflate the metric.
  const bool refusal_pressure = refusal_floor_active(
      scheduler_.occupancy_percent(), last_refusal_ms_, now_ms);
  const std::uint32_t steps_r =
      refusal_pressure ? refusal_penalty_steps(scheduler_.occupancy_percent())
                       : 0;
  const std::uint32_t multiple =
      queue_ms != 0 || steps_r != 0
          ? (queue_penalty_steps(queue_ms) > steps_r
                 ? queue_penalty_steps(queue_ms)
                 : steps_r)
          : 0;
  const RouteMetric target = penalized_cost(base, multiple);
  // §3.4 asymmetric slew: worsening applies immediately; improvement is
  // time-gated to one relax step per observation window and suppressed
  // while the window is dirty (incomplete evidence never improves a cost).
  RouteMetric cost = neighbor.link_cost;
  if (target >= cost) {
    cost = target;
  } else if (!exchange_pending && !neighbor.metric_window_dirty &&
             now_ms - neighbor.last_cost_relax_ms >= kLinkCostRelaxWindowMs) {
    cost = relax_link_cost(cost, target, base);
    neighbor.last_cost_relax_ms = now_ms;
  }
  if (cost != neighbor.link_cost) {
    neighbor.link_cost = cost;
    // Recompute stored candidates from their advertised metrics; never
    // extends a lease, never deletes FD (03 §6.3).
    routes_.update_link_cost(neighbor.node, cost, now_ms);
  }
}

Status MeshNode::note_peer_stale(const NodeId peer) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  telemetry_peers_.mark_stale(peer);
  if (Neighbor* neighbor = find_neighbor(peer)) {
    reset_neighbor_measurement(*neighbor);
    neighbor->cap_features = 0;
    neighbor->busy_capable = false;
    neighbor->cap_valid_until_ms = 0;
  }
  return Status::success();
}

void MeshNode::refresh_neighbor_load(const MonotonicMs now_ms) noexcept {
  // §3.4 refusal-pressure evidence: the floor engages on observed refusals,
  // not occupancy alone — a full-but-flowing pool still produces sojourn
  // samples. Track the scheduler's rejection counter once per refresh.
  if (scheduler_.stats_.admissions_rejected != last_admission_rejections_) {
    last_admission_rejections_ = scheduler_.stats_.admissions_rejected;
    last_refusal_ms_ = now_ms;
  }
  neighbors_.for_each([&](Neighbor& neighbor) {
    if (!neighbor.active) return;
    // Decaying observation window (03 §3): halve the exchange counters per
    // elapsed window — a bounded aggregate, never raw samples. The elapsed
    // count is computed, not iterated: the subtraction is modulo-2^64, so a
    // backwards or jumping clock would otherwise read as ~2^63 elapsed
    // windows and a per-window loop could never return. A u32 halves to
    // zero within 32 shifts, so the count saturates; advancing the anchor
    // by the full elapsed span lands it just under `now_ms` and the next
    // window rolls normally.
    if (neighbor.exchange_window_ms != 0) {
      const std::uint64_t elapsed_windows =
          (now_ms - neighbor.exchange_window_ms) / kObservationWindowMs;
      if (elapsed_windows != 0) {
        if (elapsed_windows >= 32) {
          neighbor.exchange_work = 0;
          neighbor.exchange_accepts = 0;
        } else {
          neighbor.exchange_work >>= static_cast<unsigned>(elapsed_windows);
          neighbor.exchange_accepts >>= static_cast<unsigned>(elapsed_windows);
        }
        neighbor.exchange_window_ms += kObservationWindowMs * elapsed_windows;
        // Window roll clears the dirty flag (§3.3): a bounded suppression of
        // metric improvement, never a latch.
        neighbor.metric_window_dirty = false;
      }
    }
    // The sojourn EWMA decays on its own window anchor (§3.4): sparse fresh
    // samples must not keep re-exposing a stale-inflated average — a quiet
    // queue after a burst converges within a few windows, not minutes. Same
    // computed-roll collapse as the exchange window above.
    if (neighbor.sojourn_window_ms != 0) {
      const std::uint64_t elapsed_windows =
          (now_ms - neighbor.sojourn_window_ms) / kObservationWindowMs;
      if (elapsed_windows != 0) {
        if (elapsed_windows >= 32) {
          neighbor.queue_sojourn_ewma_ms = 0;
        } else {
          neighbor.queue_sojourn_ewma_ms >>=
              static_cast<unsigned>(elapsed_windows);
        }
        neighbor.sojourn_window_ms += kObservationWindowMs * elapsed_windows;
      }
    }
    // Feedback TTL (03 §3/§5): sustained-busy survives only on fresh
    // authenticated feedback; silence past the TTL releases it so an old
    // self-report cannot hold a route away.
    if (neighbor.busy_active &&
        now_ms - neighbor.last_busy_feedback_ms > kFeedbackTtlMs) {
      neighbor.busy_active = false;
      neighbor.busy_since_ms = 0;
    }
    if (neighbor.busy_active) {
      routes_.note_next_hop_busy(neighbor.node, neighbor.busy_since_ms);
    } else {
      routes_.clear_next_hop_busy(neighbor.node);
    }
    refresh_link_cost(neighbor, now_ms);
  });
  // Route-switch hysteresis (03 §7): pending improvements commit here once
  // their hold elapsed, and committed selections that lost validity repair
  // immediately — load never admits an infeasible route.
  routes_.evaluate(now_ms);
}

RouteMetric MeshNode::peer_link_cost(const NodeId peer) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  return neighbor == nullptr ? kInfiniteRouteMetric : neighbor->link_cost;
}

MonotonicMs MeshNode::peer_busy_since(const NodeId peer) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  // A peer busy since t=0 reports its sustain start as 1 so the accessor's
  // "0 = not busy" contract stays unambiguous for diagnostics/tests.
  return neighbor == nullptr || !neighbor->busy_active
             ? MonotonicMs{0}
             : std::max<MonotonicMs>(1, neighbor->busy_since_ms);
}

Status MeshNode::note_peer_pressure(const NodeId peer, const std::uint8_t pressure,
                                    const std::uint32_t feedback_sequence,
                                    const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  auto* neighbor = find_neighbor(peer);
  if (neighbor == nullptr || !neighbor->active) return Status::success();
  // Same ordering rule as BUSY (03 §5): a stale or replayed feedback
  // sequence must never re-arm pressure. Serial arithmetic matches
  // handle_busy so the shared sequence space wraps identically.
  if (neighbor->feedback_seen &&
      static_cast<std::int32_t>(feedback_sequence -
                                neighbor->last_feedback_seq) <= 0) {
    ++busy_stats_.busy_stale;
    return Status::success();
  }
  neighbor->feedback_seen = true;
  neighbor->last_feedback_seq = feedback_sequence;
  neighbor->last_pressure = pressure;
  if (pressure != 0) {
    // Pressure only sustains the busy/queue picture (severe-busy repair);
    // it is a hint from a single peer — never a metric term (03 §6.2).
    if (!neighbor->busy_active) {
      neighbor->busy_active = true;
      neighbor->busy_since_ms = now_ms;
    }
    neighbor->last_busy_feedback_ms = now_ms;
  }
  return Status::success();
}

CongestionStats MeshNode::congestion_stats() const noexcept {
  CongestionStats merged = busy_stats_;
  merged += scheduler_.stats_;
  merged += budget_stats_;
  merged.queued = scheduler_.size();
  merged.control_queued = scheduler_.control_depth();
  merged.flows_active = scheduler_.flows_active();
  return merged;
}

std::uint8_t MeshNode::peer_tx_window(const NodeId peer) const noexcept {
  return peer_window(peer);
}

Status MeshNode::set_peer_busy_capable(const NodeId peer, const bool capable) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(in_call_);
  if (auto* neighbor = find_neighbor(peer)) {
    neighbor->busy_capable = capable;
    // A host/configured grant carries the same bounded validity as an
    // exchange-derived one — it is refreshed, never permanent — and it
    // names exactly the busy permission, like a BUSY proof.
    neighbor->cap_features = capable ? static_cast<std::uint32_t>(kCapBusyV1) : 0u;
    neighbor->cap_valid_until_ms =
        capable ? last_clock_ms_ + kCapabilitiesValidityMs : 0;
  }
  return Status::success();
}

bool MeshNode::peer_busy_capable(const NodeId peer,
                                 const MonotonicMs now_ms) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  return neighbor != nullptr && neighbor->busy_capable &&
         neighbor->cap_valid_until_ms > now_ms;
}

bool MeshNode::peer_broadcast_eligible(const NodeId peer,
                                       const MonotonicMs now_ms) const noexcept {
  const auto* neighbor = find_neighbor(peer);
  // Same liveness rule as the busy gate (an unexpired nonce-bound grant),
  // plus the broadcast bit and a usable pairwise Link context — the grant
  // alone never authorizes a broadcast to a peer we cannot reach pairwise.
  return neighbor != nullptr && neighbor->active &&
         (neighbor->cap_features & kCapRouteBroadcastV1) != 0 &&
         neighbor->cap_valid_until_ms > now_ms &&
         context_usable(security_.context_state(SecurityScope::Link, peer));
}

}  // namespace routeloom
