#include "node_internal.hpp"

namespace routeloom {

MeshNode::MeshNode(const NodeConfig& config, RadioPort& radio, SecurityProvider& security,
                   NodeObserver& observer) noexcept
    : config_(config),
      radio_(radio),
      security_(security),
      observer_(observer, in_external_callback_) {
  // The one compat init for the APPLIED boot lease (P4 §9.1): an unset
  // boot_session rides message_session. Session-type providers must pass
  // an explicit nonzero value — the Owner refuses 0 there.
  if (config_.boot_session == 0) config_.boot_session = config_.message_session;
  routes_.set_self(config.node);  // improvement-hold jitter identity (03 §7)
  // Feasibility state must outlive every lease that could still carry a
  // stale advertisement to us (routing-scale.md §8, RFC 8966 §3.7.3).
  routes_.set_tombstone_dwell(config.route_lifetime_ms);
}

Status MeshNode::validate_config() const noexcept {
  // Node ids at or above kGroupAddressBase name groups (group.hpp), never a
  // device — kBroadcastNodeId is the ALL group address.
  if (config_.network == 0 || config_.network > UINT32_MAX ||
      reserved_node_id(config_.node) ||
      config_.message_session == 0 || config_.route_generation == 0 ||
      config_.route_advertisement_period_ms == 0 ||
      config_.route_lifetime_ms <= config_.route_advertisement_period_ms ||
      config_.hop_accept_timeout_ms < kLinkRtoMinMs ||
      config_.callback_watchdog_ms == 0 ||
      config_.max_link_attempts == 0 || config_.max_end_to_end_rounds == 0 ||
      // rf_attempts_max is a pinned contract value (03 §5), not a tunable:
      // a config above it would silently exceed the RF-loss retry budget.
      config_.max_link_attempts > kRfAttemptsMax) {
    return Status::error(StatusCode::InvalidArgument, "invalid node configuration");
  }
  // Gateway-scoped profile (routing-scale.md §5): reserved ids are never a
  // gateway, and the lease must cover two per-link refresh cycles plus the
  // margin — otherwise tree routes would expire before their refresh lands,
  // which is exactly the flap of issue #41. Rejected, never just reported.
  for (const NodeId gateway : config_.route_gateways) {
    if (gateway != kInvalidNodeId && reserved_node_id(gateway)) {
      return Status::error(StatusCode::InvalidArgument, "invalid route gateway");
    }
  }
  bool has_group_root = false;
  for (const NodeId root : config_.group_roots) {
    if (root != kInvalidNodeId && reserved_node_id(root)) {
      return Status::error(StatusCode::InvalidArgument, "invalid group root");
    }
    has_group_root |= root != kInvalidNodeId;
  }
  // Roots and routing policy are separate knobs but never ambiguous: a flat
  // group tree may not coexist with a configured gateway-scoped profile.
  if (has_group_root && gateway_scoped()) {
    return Status::error(StatusCode::InvalidArgument, "GROUP_ROOTS_WITH_GATEWAYS");
  }
  if (config_.route_broadcast && !gateway_scoped()) {
    return Status::error(StatusCode::Unsupported, "BROADCAST_REQUIRES_SCOPED_ROUTES");
  }
  // Scoped opt-in is wired: batched GroupLink advertisements to live
  // grant holders, unicast everywhere else (routing-scale.md §8). Flat
  // full-table broadcast stays unsupported — see above.
  if (gateway_scoped() &&
      !scoped_lifetime_sufficient(config_.route_advertisement_period_ms,
                                  config_.route_lifetime_ms,
                                  config_.route_refresh_ticks)) {
    return Status::error(StatusCode::InvalidArgument,
                         "ROUTE_LIFETIME_BELOW_REFRESH_BOUND");
  }
  return Status::success();
}

Status MeshNode::start(const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(*this);
  if (started_) return Status::error(StatusCode::AlreadyExists, "node already started");
  const auto status = validate_config();
  if (!status) return status;
  if (!security_.ready()) {
    return Status::error(StatusCode::InvalidState, "security provider is not ready");
  }
  if (reply_peer_port_ == nullptr) {
    // Issue #117: every admission reserves a protected reply binding, so a
    // node without an Owner lease port cannot admit anything — refuse the
    // start explicitly instead of running half-enforced.
    return Status::error(StatusCode::InvalidState, "reply peer port not attached");
  }
  started_ = true;
  next_route_advertisement_ms_ = now_ms;
  // §14 control budget starts full at boot; the bucket is a spec-envelope
  // capability, not measured capacity.
  control_budget_last_ms_ = now_ms;
  group_budget_last_ms_ = now_ms;
  // A development-profile provider is allowed to run but is always surfaced
  // as EXPERIMENTAL; nothing in this node claims production security status.
  if (security_.security_profile() != SecurityProfile::Production) {
    observer_.on_diagnostic("SECURITY_PROFILE_EXPERIMENTAL", kInvalidNodeId, nullptr);
  }
  // Lease safety under metric churn (sdk-completion/03 §3.8, D4-06): a full
  // flat-profile table needs ceil(capacity / routes-per-page) advertisement
  // periods to be refreshed through the rotating cursor (a page carries the
  // self record plus kRouteUpdateMaxRecords - 1 routes). A lifetime shorter
  // than that bound lets tail routes expire before their refresh lands —
  // surfaced once as a diagnostic; whether it is a defect depends on how
  // large the table actually grows, so it is not a boot failure. The
  // gateway-scoped profile has its own, enforced bound (validate_config).
  if (!gateway_scoped() &&
      !flat_lifetime_sufficient(config_.route_advertisement_period_ms,
                                config_.route_lifetime_ms, kMaxRouteEntries)) {
    observer_.on_diagnostic("ROUTE_REFRESH_BOUND_EXCEEDED", kInvalidNodeId,
                            nullptr);
  }
  if (gateway_scoped()) {
    // Deterministic per-node tick offset so a site powered up together does
    // not refresh every tree link in the same instant.
    next_route_advertisement_ms_ =
        now_ms + (config_.node * 2654435761ULL) % config_.route_advertisement_period_ms;
  }
  return Status::success();
}

MeshNode::Neighbor* MeshNode::find_neighbor(const NodeId node) noexcept {
  return neighbors_.find([&](const Neighbor& value) { return value.node == node; });
}

const MeshNode::Neighbor* MeshNode::find_neighbor(const NodeId node) const noexcept {
  return neighbors_.find([&](const Neighbor& value) { return value.node == node; });
}

Status MeshNode::add_neighbor(const NodeId neighbor, const RouteMetric link_metric,
                              const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(*this);
  if (!started_ || neighbor == kInvalidNodeId || neighbor == config_.node || link_metric == 0 ||
      link_metric == kInfiniteRouteMetric) {
    return Status::error(StatusCode::InvalidArgument, "invalid neighbor");
  }
  auto* record = find_neighbor(neighbor);
  if (record == nullptr) {
    record = neighbors_.allocate();
    if (record == nullptr) {
      // Tombstoned records only remember a departed peer's last-seen
      // generation — soft state. Reclaim one before refusing, or churn
      // through more than the table capacity in distinct peers permanently
      // exhausts the pool (issue #20).
      record = neighbors_.find(
          [](const Neighbor& value) { return !value.active; });
      if (record != nullptr) {
        // A different identity inherits this slot: the per-peer feedback
        // ordering state is anti-replay continuity for THAT peer only and
        // must not transfer.
        record->last_feedback_seq = kNoFeedbackSeq;
        record->feedback_seen = false;
      }
    }
    if (record == nullptr) {
      return Status::error(StatusCode::NoCapacity, "neighbor table full");
    }
    record->generation = 0;  // last-seen origin generation; survives re-adds
  }
  record->node = neighbor;
  record->metric = link_metric;      // nominal — measurements adjust around it
  record->link_cost = link_metric;   // effective cost starts at nominal
  record->consecutive_failures = 0;
  // Re-adding a peer is a new observation epoch: drop the load aggregates
  // (keep the feedback ordering state — anti-replay must not reset).
  record->exchange_work = 0;
  record->exchange_accepts = 0;
  record->exchange_window_ms = 0;
  record->queue_sojourn_ewma_ms = 0;
  record->sojourn_samples = 0;
  record->last_sojourn_ms = 0;
  record->sojourn_window_ms = 0;
  record->hop_rtt_ewma_ms = 0;
  record->hop_rtt_samples = 0;
  record->busy_active = false;
  record->busy_since_ms = 0;
  record->last_busy_feedback_ms = 0;
  record->last_pressure = 0;
  // The congestion window is load state, not identity: a re-added peer
  // restarts at the initial window rather than inheriting a collapsed one.
  record->tx_window = kPeerWindowInitial;
  record->window_accepts = 0;
  record->busy_capable = false;
  record->cap_features = 0;
  record->cap_valid_until_ms = 0;
  record->cap_node_boot = 0;
  record->last_cap_exchange_ms = 0;
  // Tree roles are re-learned from the peer's own advertisements. Both
  // profile arms share this storage and every member's idle value is zero
  // (kInvalidNodeId == 0), so one reset serves either profile.
  record->tree = Neighbor::TreeRoles{};
  // A fresh binding must exchange the current self/gateway records even
  // when an old indirect gateway route suppresses the bootstrap pull.
  record->pull_answer_pending = gateway_scoped();
  record->active = true;
  // Direct route to the neighbor itself, seeded at the last-seen generation
  // (0 for a brand-new peer); it upgrades as soon as its self record arrives.
  const RouteAdvertisement direct{neighbor, record->generation, 0, 0};
  auto result = routes_.consider(direct, neighbor, link_metric, now_ms,
                                 config_.route_lifetime_ms);
  if (result == RouteUpdateResult::NoCapacity && routes_.reclaim_tombstone()) {
    // A tombstone only remembers a dead destination's feasibility state —
    // soft state. Under saturation a direct-neighbor admission preempts the
    // oldest one (issue #50, same tradeoff as the neighbor-table reclaim
    // under issue #20); a learned-route flood still sees NoCapacity.
    result = routes_.consider(direct, neighbor, link_metric, now_ms,
                              config_.route_lifetime_ms);
  }
  if (result == RouteUpdateResult::NoCapacity) {
    record->active = false;
    return Status::error(StatusCode::NoCapacity, "route table full");
  }
  ++config_revision_;
  // Flat profile: a new neighbor gets the next dump right away. The scoped
  // profile keeps its tick grid (a new neighbor pulls what it needs, and a
  // reset grid would re-phase every tree link).
  if (!gateway_scoped()) next_route_advertisement_ms_ = now_ms;
  return Status::success();
}

void MeshNode::drop_neighbor_locked(Neighbor& record, const NodeId neighbor,
                                   const MonotonicMs now_ms) noexcept {
  record.active = false;
  routes_.invalidate_next_hop(neighbor, now_ms);
  routes_.clear_next_hop_busy(neighbor);  // drop stale busy state too
  ++self_route_sequence_;
  ++config_revision_;
  trigger_route_advertisement(now_ms);
}

Status MeshNode::remove_neighbor(const NodeId neighbor, const MonotonicMs now_ms) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(*this);
  auto* record = find_neighbor(neighbor);
  if (record == nullptr) return Status::error(StatusCode::NotFound, "neighbor not found");
  drop_neighbor_locked(*record, neighbor, now_ms);
  return Status::success();
}

MeshNode::Delivery* MeshNode::find_delivery(const MessageId& id) noexcept {
  return deliveries_.find([&](const Delivery& value) { return value.id == id; });
}

const MeshNode::Delivery* MeshNode::find_delivery(const MessageId& id) const noexcept {
  return deliveries_.find([&](const Delivery& value) { return value.id == id; });
}

MeshNode::DedupEntry* MeshNode::find_dedup(const MessageKey& key, const FrameType type,
                                           const std::uint8_t round) noexcept {
  return dedup_.find([&](const DedupEntry& value) {
    return value.key == key && value.type == type && value.round == round;
  });
}

const MeshNode::DedupEntry* MeshNode::find_dedup(const MessageKey& key,
                                               const FrameType type,
                                               const std::uint8_t round) const noexcept {
  return dedup_.find([&](const DedupEntry& value) {
    return value.key == key && value.type == type && value.round == round;
  });
}

std::size_t MeshNode::count_transit_upstream(const NodeId upstream) const noexcept {
  // The per-previous-hop bound covers every non-terminal record the peer
  // injected — transit forwards AND terminal-side Resolved births. Terminal
  // pins are bounded by the reserve instead (02 §2.5).
  std::size_t count = 0;
  dedup_.for_each([&](const DedupEntry& value) {
    if (value.phase != DedupPhase::Terminal && value.upstream_peer == upstream) {
      ++count;
    }
  });
  return count;
}

MonotonicMs MeshNode::dedup_expiry_for(const DedupPhase phase,
                                       const std::uint32_t deadline_remaining_ms,
                                       const MonotonicMs first_seen_ms,
                                       const MonotonicMs now_ms) const noexcept {
  // horizon = now + (remaining_deadline - rx_age): the latest instant a
  // legitimate retry of this round can arrive (02 §2.2). The path-length
  // factor is already spent by the frame's own deadline arithmetic.
  // A frame claiming more than the origin lifetime ceiling cannot come from
  // a conformant origin (issue #55): retention is sized on the ceiling, so
  // the claim buys no longer residency than a max-lifetime message.
  const std::uint32_t claimed = std::min(deadline_remaining_ms, kMaxMessageLifetimeMs);
  const std::uint32_t remaining = claimed > rx_age_ms_ ? claimed - rx_age_ms_ : 0;
  const MonotonicMs horizon = now_ms + remaining;
  const MonotonicMs slack =
      phase == DedupPhase::Terminal ? kTerminalSlackMs : kTransitSlackMs;
  const MonotonicMs duty = horizon + slack;
  const MonotonicMs cap = first_seen_ms + kDedupHardCapMs;
  return std::min(cap, duty);
}

bool MeshNode::evict_dedup_for_admission(const MonotonicMs now_ms) noexcept {
  // Phase-ordered victim selection (02 §2.5): an already-expired record is a
  // normal expiry release, never a forced eviction; then earliest-expiry
  // Resolved (residual duty only: re-ACK + late-report relay), then oldest
  // Evidence (verbatim replay material). Live and Terminal are skipped —
  // evicting one would orphan accepted work or break the exactly-once pin.
  if (auto* expired = dedup_.find(
          [&](const DedupEntry& value) { return value.expires_at_ms <= now_ms; })) {
    dedup_.release(expired);
    saturating_inc(dedup_stats_.expired);
    return true;
  }
  DedupEntry* victim = nullptr;
  dedup_.for_each([&](DedupEntry& value) {
    if (value.phase == DedupPhase::Resolved &&
        (victim == nullptr || value.expires_at_ms < victim->expires_at_ms)) {
      victim = &value;
    }
  });
  if (victim == nullptr) {
    dedup_.for_each([&](DedupEntry& value) {
      if (value.phase == DedupPhase::Evidence &&
          (victim == nullptr || value.first_seen_ms < victim->first_seen_ms)) {
        victim = &value;
      }
    });
  }
  if (victim == nullptr) return false;  // all-Live/Terminal: honest overflow
  release_dedup_victim(*victim);
  return true;
}

bool MeshNode::evict_dedup_for_upstream(const NodeId upstream,
                                        const MonotonicMs now_ms) noexcept {
  // Per-upstream bound (02 §2.5, #39): the bound limits how much of the pool
  // one previous hop may occupy — it is not a rate limit. At the bound the
  // upstream recycles its OWN evictable records in the global phase order
  // (expired -> earliest-expiry Resolved -> oldest Evidence), so a busy but
  // honest upstream is throttled by its live work, not by the retention of
  // exchanges that already finished. Other upstreams' records and every
  // Live/Terminal record are untouched; the refusal remains when all of its
  // records are Live.
  const auto mine = [upstream](const DedupEntry& value) {
    return value.phase != DedupPhase::Terminal && value.upstream_peer == upstream;
  };
  if (auto* expired = dedup_.find([&](const DedupEntry& value) {
        return mine(value) && value.expires_at_ms <= now_ms;
      })) {
    dedup_.release(expired);
    saturating_inc(dedup_stats_.expired);
    return true;
  }
  DedupEntry* victim = nullptr;
  dedup_.for_each([&](DedupEntry& value) {
    if (mine(value) && value.phase == DedupPhase::Resolved &&
        (victim == nullptr || value.expires_at_ms < victim->expires_at_ms)) {
      victim = &value;
    }
  });
  if (victim == nullptr) {
    dedup_.for_each([&](DedupEntry& value) {
      if (mine(value) && value.phase == DedupPhase::Evidence &&
          (victim == nullptr || value.first_seen_ms < victim->first_seen_ms)) {
        victim = &value;
      }
    });
  }
  if (victim == nullptr) return false;  // every record it holds is Live
  release_dedup_victim(*victim);
  return true;
}

void MeshNode::release_dedup_victim(DedupEntry& victim) noexcept {
  // A forced eviction is always counted + diagnosed (02 §2.8): the possible
  // consequence (one extra re-forward of a late duplicate, or loss of the
  // verbatim failure replay) is never silent.
  const MessageId victim_id = victim.key.id;
  const NodeId victim_peer = victim.upstream_peer;
  const bool was_resolved = victim.phase == DedupPhase::Resolved;
  dedup_.release(&victim);
  saturating_inc(was_resolved ? dedup_stats_.evicted_resolved
                              : dedup_stats_.evicted_evidence);
  observer_.on_diagnostic(was_resolved ? "DEDUP_EVICTED_RESOLVED"
                                       : "DEDUP_EVICTED_EVIDENCE",
                          victim_peer, &victim_id);
}

std::size_t MeshNode::count_terminal_pins() const noexcept {
  std::size_t count = 0;
  dedup_.for_each([&](const DedupEntry& value) {
    if (value.phase == DedupPhase::Terminal) ++count;
  });
  return count;
}

MeshNode::DedupEntry* MeshNode::allocate_dedup(
    const MessageKey& key, const FrameType type, const std::uint8_t round,
    const DedupPhase phase, const NodeId upstream,
    const std::uint32_t deadline_remaining_ms, const MonotonicMs now_ms) noexcept {
  if (auto* existing = find_dedup(key, type, round)) return existing;

  // Class admission gates (02 §2.5) run BEFORE touching the pool: terminal
  // pins may never reach into the transit reserve, and one previous-hop peer
  // may not monopolize retained non-terminal state.
  //
  // The reserve bounds the number of PINS (02 §2.10 "Terminal pins >= N"),
  // not the pool size: a pool crowded with evictable Resolved/Evidence
  // transit records must not refuse delivery to this node's own application
  // while the sweep below could reclaim one of them (#39 collateral refusal).
  if (phase == DedupPhase::Terminal && count_terminal_pins() >= kDedupTerminalPinMax) {
    saturating_inc(dedup_stats_.refused_terminal_reserve);
    observer_.on_diagnostic("DEDUP_TERMINAL_RESERVE", upstream, &key.id);
    return nullptr;
  }
  if (phase != DedupPhase::Terminal &&
      count_transit_upstream(upstream) >= kDedupPerUpstreamMax &&
      !evict_dedup_for_upstream(upstream, now_ms)) {
    saturating_inc(dedup_stats_.refused_upstream_cap);
    observer_.on_diagnostic("DEDUP_UPSTREAM_CAP", upstream, &key.id);
    return nullptr;
  }

  auto* entry = dedup_.allocate();
  if (entry == nullptr) {
    if (!evict_dedup_for_admission(now_ms)) {
      // True overflow: only Live/Terminal records remain. Refusal pressure
      // becomes BUSY backpressure at the call site — never dedup weakening.
      saturating_inc(dedup_stats_.refused_pool_full);
      observer_.on_diagnostic("DEDUP_OVERFLOW", upstream, &key.id);
      return nullptr;
    }
    entry = dedup_.allocate();
    if (entry == nullptr) {
      // Unreachable: the sweep just freed a slot. Counted, never silent.
      saturating_inc(dedup_stats_.refused_pool_full);
      observer_.on_diagnostic("DEDUP_OVERFLOW", upstream, &key.id);
      return nullptr;
    }
  }
  entry->key = key;
  entry->type = type;
  entry->round = round;
  entry->phase = phase;
  entry->first_seen_ms = now_ms;
  entry->expires_at_ms =
      dedup_expiry_for(phase, deadline_remaining_ms, now_ms, now_ms);
  // The upstream correlation is admission-time state: it feeds the per-peer
  // cap above and the TransitFailure replay path for forwarded records.
  entry->upstream_peer = upstream;
  saturating_inc(phase == DedupPhase::Terminal ? dedup_stats_.admitted_terminal
                                             : dedup_stats_.admitted_transit);
  return entry;
}

void MeshNode::resolve_dedup_for_job(const TxJob& job) noexcept {
  // Only forwarded jobs carry a retained transit record (job.ack mirrors the
  // forwarded frame's identity); locally originated Transit-owner emissions
  // (our END_RECEIPT, BUSY) never match a dedup key.
  if (job.form != JobForm::Forwarded) return;
  if (auto* entry = find_dedup(job.ack.key, job.ack.accepted_type, job.ack.round);
      entry != nullptr && entry->phase == DedupPhase::Live) {
    // The hop-accept resolved the exchange: residual duty is re-ACK of
    // upstream duplicates plus propagating a late downstream report (02 §2.6).
    entry->phase = DedupPhase::Resolved;
  }
}

void MeshNode::mark_dedup_evidence(DedupEntry& entry) noexcept {
  if (entry.phase == DedupPhase::Evidence) return;
  // Residency bound (02 §2.3c): at most kEvidenceCap Evidence records. At the
  // cap the oldest existing evidence is force-reclaimed — a counted, bounded
  // loss of verbatim-replay material, never an unbounded table.
  std::size_t evidence = 0;
  DedupEntry* oldest = nullptr;
  dedup_.for_each([&](DedupEntry& value) {
    if (&value == &entry || value.phase != DedupPhase::Evidence) return;
    ++evidence;
    if (oldest == nullptr || value.first_seen_ms < oldest->first_seen_ms) {
      oldest = &value;
    }
  });
  if (evidence >= kEvidenceCap && oldest != nullptr) {
    const MessageId victim_id = oldest->key.id;
    const NodeId victim_peer = oldest->upstream_peer;
    dedup_.release(oldest);
    saturating_inc(dedup_stats_.evicted_evidence);
    observer_.on_diagnostic("DEDUP_EVICTED_EVIDENCE", victim_peer, &victim_id);
  }
  entry.phase = DedupPhase::Evidence;
}

void MeshNode::set_delivery_state(Delivery& delivery, const DeliveryState state,
                                  const char* reason) noexcept {
  if (delivery.state == state && delivery.reason == reason) return;
  delivery.state = state;
  delivery.reason = reason;
  if (state == DeliveryState::WaitingForMac) delivery.transmitted = true;
  // Final-result observation (03 §3): END_RECEIPT/expiry/failure/
  // indeterminate are recorded as separate counters.
  switch (state) {
    case DeliveryState::Delivered:
    case DeliveryState::Failed:
    case DeliveryState::Expired:
    case DeliveryState::Indeterminate:
      obs_final(delivery, state, last_clock_ms_);
      break;
    default:
      break;
  }
  observer_.on_delivery(DeliveryResult{delivery.id, state, reason});
}

Status MeshNode::set_pause(const PauseReason reason,
                           const std::uint8_t mask) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(*this);
  if (reason == PauseReason::None || reason == PauseReason::SleepDrain) {
    return Status::error(StatusCode::InvalidArgument, "invalid pause reason");
  }
  if (pause_reason_ != PauseReason::None && pause_reason_ != reason) {
    // A second operational pause would need priority/stacking rules the
    // contract does not define: refuse it explicitly instead.
    return Status::error(StatusCode::Conflict, "PAUSE_REASON_ACTIVE");
  }
  pause_reason_ = reason;
  pause_mask_ |= mask;
  return Status::success();
}

Status MeshNode::clear_pause(const PauseReason reason) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(*this);
  if (reason == PauseReason::None || reason == PauseReason::SleepDrain) {
    return Status::error(StatusCode::InvalidArgument, "invalid pause reason");
  }
  if (pause_reason_ != reason) {
    return Status::error(StatusCode::InvalidState, "pause reason not active");
  }
  pause_reason_ = PauseReason::None;
  pause_mask_ = 0;
  return Status::success();
}

Status MeshNode::set_autonomy_sink(AutonomyFrameSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  autonomy_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_gateway_sink(GatewayServiceSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  if (component_target_pending(ComponentEventTarget::ServicePayload) ||
      component_target_pending(ComponentEventTarget::ServiceJobDone)) {
    return Status::error(StatusCode::Busy, "component events pending");
  }
  gateway_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_config_sink(ConfigEndpointSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  if (component_target_pending(ComponentEventTarget::ConfigFrame) ||
      component_target_pending(ComponentEventTarget::ConfigJobDone)) {
    return Status::error(StatusCode::Busy, "component events pending");
  }
  config_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_diagnostic_sink(DiagnosticSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  diagnostic_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_applied_sink(AppliedEndpointSink* sink) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  applied_sink_ = sink;
  return Status::success();
}

Status MeshNode::set_telemetry_remote(const bool enabled) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  telemetry_remote_ = enabled;
  return Status::success();
}

Status MeshNode::set_observation_remote(const bool enabled) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  observation_remote_ = enabled;
  return Status::success();
}

Status MeshNode::set_observation_source(const ObservationSource* source) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  observation_source_ = source;
  return Status::success();
}

Status MeshNode::set_draining(const bool draining) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  next_poll_ms_ = 0;
  sleep_draining_ = draining;
  return Status::success();
}

Status MeshNode::settle_failed_sleep_work() noexcept {
  if (in_call_ || in_external_callback_ || !sleep_draining_) {
    return Status::error(StatusCode::Busy, "sleep settlement unavailable");
  }
  while (settle_one_sleep_delivery(
      SleepWorkPolicy::Fail, [](const MessageId&) noexcept { return false; })) {}
  while (settle_one_sleep_group_origin(SleepWorkPolicy::Fail)) {}
  while (true) {
    const SleepHoldRelease released = release_one_group_hold_for_sleep();
    if (released == SleepHoldRelease::NonePending) break;
    if (released == SleepHoldRelease::StreamInvariant) {
      return Status::error(StatusCode::InvalidState, "group hold stream missing");
    }
  }
  const Status quiet = quiesce_for_sleep();
  if (!quiet) return quiet;
  if (sleep_work_pending()) {
    return Status::error(StatusCode::Busy, "node has sleep work");
  }
  return Status::success();
}

Status MeshNode::set_relay_enabled(const bool enabled) noexcept {
  if (in_call_) return Status::error(StatusCode::Busy, "reentrant call");
  NodeGuard guard(*this);
  const bool was = relay_enabled_;
  relay_enabled_ = enabled;
  if (started_ && was && !enabled) {
    // Prompt withdrawal: retract every route we advertised before neighbors
    // send more transit we would only refuse (01 §policy drain).
    trigger_route_advertisement(last_clock_ms_);
  }
  return Status::success();
}

void MeshNode::revoke_routes(const NodeId peer, const MonotonicMs now_ms) noexcept {
  if (in_call_) return;  // enforcement is retried on the next RRS apply
  NodeGuard guard(*this);
  if (peer == kInvalidNodeId || peer == kBroadcastNodeId) return;
  // Route updates are plain frames gated only on the neighbor record, so
  // scrubbing the table is not enough: the neighbor itself goes inactive
  // (its re-advertisements are then ignored, not re-learned). It heals
  // through the normal handshake path — which the RRS gate refuses until
  // the peer re-authenticates under a newer generation.
  if (auto* record = find_neighbor(peer); record != nullptr) {
    drop_neighbor_locked(*record, peer, now_ms);
  } else {
    routes_.invalidate_next_hop(peer, now_ms, true);
  }
  // A deferred application completion belongs to the revoked source.
  // Keep terminal dedup, but drop its ticket: late completion cannot publish
  // a verdict under a later membership binding.
  while (auto* pending = applied_records_.find([&](const AppliedRecord& value) {
           return value.ticket != 0 && value.key.origin == peer;
         })) applied_records_.release(pending);
  const RouteSelection selected = routes_.best(peer);
  if (selected.valid) (void)routes_.withdraw(peer, selected.next_hop, now_ms);
  routes_.evaluate(now_ms);
  // A route withdrawal alone leaves admitted work alive. Drop queued and
  // awaiting work involving the revoked identity before another dispatch
  // can select it under a repaired route or an overlapping session.
  const auto involves_peer = [&](const TxJob& job) noexcept {
    if (job.owner == JobOwner::Group) {
      const GroupTree* tree = group_trees_.find(
          [&](const GroupTree& value) { return value.key == job.ack.key; });
      if (tree != nullptr && tree->parent == peer) return true;
    }
    return job.peer == peer || job.plain.header.origin == peer ||
           job.plain.header.destination == peer || job.ack.key.origin == peer;
  };
  TxJob dropped{};
  while (scheduler_.drop_one_if(involves_peer, dropped)) {
    fail_job(dropped, "REVOKED_PEER", now_ms, true);
  }
  while (auto* awaiting = awaiting_hop_.find(
             [&](const AwaitingHop& value) { return involves_peer(value.job); })) {
    TxJob job = awaiting->job;
    awaiting_hop_.release(awaiting);
    fail_job(job, "REVOKED_PEER", now_ms, true);
  }
  if (group_promote_hold_.used &&
      (group_promote_hold_.peer == peer || group_promote_hold_.frame.header.origin == peer)) {
    group_promote_hold_ = GroupPromoteHold{};
  }
  while (GroupHold* hold = group_holds_.find([&](const GroupHold& value) {
           return value.info.key.origin == peer || value.previous_hop == peer;
         })) group_holds_.release(hold);
  while (GroupTree* tree = group_trees_.find([&](const GroupTree& value) {
           return value.key.origin == peer || value.parent == peer;
         })) group_trees_.release(tree);
}

}  // namespace routeloom
