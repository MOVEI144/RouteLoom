#include "routeloom/channel_plan.hpp"

namespace routeloom {
namespace {

constexpr Status reject(const StatusCode code, const char* detail) noexcept {
  return Status::error(code, detail);
}

// Integer "candidate improves worst cost by >=25%": cand*4 <= cur*3.
// kInfiniteRouteMetric participates naturally: an infinite current cost is
// improved by any finite candidate; an infinite candidate never improves.
constexpr bool improved_quarter(const RouteMetric candidate,
                                const RouteMetric current) noexcept {
  return static_cast<std::uint64_t>(candidate) * 4U <=
         static_cast<std::uint64_t>(current) * 3U;
}

}  // namespace

// --- ChannelCoordinator ------------------------------------------------------------

ChannelCoordinator::ChannelCoordinator(
    const ChannelCoordinatorConfig& config) noexcept
    : config_(config) {}

Status ChannelCoordinator::set_mode(const MigrationMode mode) noexcept {
  switch (mode) {
    case MigrationMode::Disabled:
    case MigrationMode::Observe:
    case MigrationMode::Manual:
      mode_ = mode;
      return Status::success();
    case MigrationMode::AutoGuarded:
      // P6 stub gate (D5-01, 04 §10): automatic guarded migration is an
      // opt-in feature after qualification, never enabled by this design.
      return reject(StatusCode::Unsupported, "AUTOGUARDED_UNIMPLEMENTED");
  }
  return reject(StatusCode::InvalidArgument, "unknown migration mode");
}

Status ChannelCoordinator::set_home_channel(const std::uint8_t channel) noexcept {
  if (channel == 0 || channel > 13) {
    return reject(StatusCode::InvalidArgument, "invalid home channel");
  }
  config_.home_channel = channel;
  return Status::success();
}

// --- observation windows ------------------------------------------------------------

void ChannelCoordinator::advance_windows(const MonotonicMs now_ms) noexcept {
  const std::uint64_t index = now_ms / config_.bad_window_ms;
  if (window_index_ == kWindowUninitialized) {
    window_index_ = index;
    window_.reset();
    return;
  }
  while (window_index_ < index) {
    finalize_window(window_);
    ++window_index_;
    window_.reset();
  }
}

void ChannelCoordinator::finalize_window(const WindowState& window) noexcept {
  ++stats_.windows_finalized;
  last_window_unobserved_ = window.observations == 0;
  if (window.observations == 0) ++stats_.unobserved_windows;
  if (window.qualifying) {
    ++stats_.bad_windows;
    ++consecutive_bad_;
    for (std::size_t i = 0; i < window.observer_count; ++i) {
      const NodeId observer = window.observers[i];
      bool known = false;
      for (std::size_t j = 0; j < streak_observer_count_; ++j) {
        if (streak_observers_[j] == observer) {
          known = true;
          break;
        }
      }
      if (!known && streak_observer_count_ < streak_observers_.size()) {
        streak_observers_[streak_observer_count_++] = observer;
      }
    }
    streak_critical_ = streak_critical_ || window.critical;
    return;
  }
  // A good or unobserved window breaks the consecutive-bad streak.
  consecutive_bad_ = 0;
  streak_observer_count_ = 0;
  streak_critical_ = false;
}

void ChannelCoordinator::note_health_evidence(const HealthEvidence& evidence,
                                              const MonotonicMs now_ms) noexcept {
  if (mode_ == MigrationMode::Disabled) return;
  advance_windows(now_ms);
  if (!evidence.authenticated) {
    // Unauthenticated/self-reported degradation is diagnostic-only: it must
    // never move the whole mesh (04 §2).
    ++stats_.unauthenticated_ignored;
    return;
  }
  WindowState& window = current_window();
  ++window.observations;
  if (evidence.delivery_impaired || evidence.critical_link_impaired) {
    window.qualifying = true;
    window.critical = window.critical || evidence.critical_link_impaired;
    if (evidence.observer != kInvalidNodeId) {
      bool known = false;
      for (std::size_t i = 0; i < window.observer_count; ++i) {
        if (window.observers[i] == evidence.observer) {
          known = true;
          break;
        }
      }
      if (!known && window.observer_count < window.observers.size()) {
        window.observers[window.observer_count++] = evidence.observer;
      }
    }
  }
  // evidence.rssi_low is deliberately ignored for qualification: a low RSSI
  // alone never triggers a whole-mesh move (04 §2). It only counts as an
  // observation above.
}

// --- participants / candidate intersection -------------------------------------------

ChannelCoordinator::Participant* ChannelCoordinator::find_participant(
    const NodeId node) noexcept {
  return participants_.find(
      [&](const Participant& p) { return p.node == node; });
}

const ChannelCoordinator::Participant* ChannelCoordinator::find_participant(
    const NodeId node) const noexcept {
  return participants_.find(
      [&](const Participant& p) { return p.node == node; });
}

Status ChannelCoordinator::note_participant(
    const ParticipantCapability& capability) noexcept {
  if (capability.node == kInvalidNodeId ||
      capability.node == config_.node) {
    return reject(StatusCode::InvalidArgument, "invalid participant");
  }
  Participant* record = find_participant(capability.node);
  if (record == nullptr) {
    record = participants_.allocate();
    if (record == nullptr) {
      return reject(StatusCode::NoCapacity, "participant table full");
    }
    record->node = capability.node;
  }
  record->channel_mask = capability.channel_mask;
  record->migration_capable = capability.migration_capable;
  record->required = capability.required;
  legacy_block_ = false;
  participants_.for_each([&](const Participant& p) {
    if (p.required && !p.migration_capable) legacy_block_ = true;
  });
  return Status::success();
}

Status ChannelCoordinator::remove_participant(const NodeId node) noexcept {
  Participant* record = find_participant(node);
  if (record == nullptr) {
    return reject(StatusCode::NotFound, "participant unknown");
  }
  participants_.release(record);
  legacy_block_ = false;
  participants_.for_each([&](const Participant& p) {
    if (p.required && !p.migration_capable) legacy_block_ = true;
  });
  return Status::success();
}

std::uint32_t ChannelCoordinator::effective_mask() const noexcept {
  std::uint32_t mask = config_.candidate_mask & migration_const::kChannelMaskAll24;
  participants_.for_each([&](const Participant& p) {
    if (p.migration_capable) mask &= p.channel_mask;
    // A legacy participant narrows nothing here: it blocks the whole
    // proposal via legacy_block_ instead of faking a per-channel vote.
  });
  return mask;
}

std::size_t ChannelCoordinator::candidates(std::uint8_t* out,
                                           const std::size_t capacity) const noexcept {
  const std::uint32_t mask = effective_mask();
  std::size_t count = 0;
  for (std::uint8_t ch = 1; ch <= 13 && count < capacity; ++ch) {
    if (ch == config_.home_channel) continue;  // surveying home is pointless
    if ((mask & (1u << (ch - 1))) == 0) continue;
    if (out != nullptr) out[count] = ch;
    ++count;
  }
  return count;
}

bool ChannelCoordinator::candidate_permitted(const std::uint8_t channel) const noexcept {
  if (channel == 0 || channel == config_.home_channel) return false;
  return (effective_mask() & (1u << (channel - 1))) != 0;
}

// --- assess -------------------------------------------------------------------------

ChannelAssessment ChannelCoordinator::assess(const MonotonicMs now_ms) noexcept {
  advance_windows(now_ms);
  ChannelAssessment out{};
  out.consecutive_bad_windows = consecutive_bad_;
  out.independent_observers =
      static_cast<std::uint32_t>(streak_observer_count_);
  out.critical_link_impaired = streak_critical_;
  out.legacy_participant_block = legacy_block_;
  out.candidate_count = candidates(out.candidates.data(), out.candidates.size());

  if (mode_ == MigrationMode::Disabled) {
    out.verdict = AssessVerdict::Disabled;
    return out;
  }
  const bool all_bad = all_bad_reported_ && suppressed_epoch_ == evidence_epoch_;
  out.placement_review_advised = all_bad;
  if (consecutive_bad_ < config_.bad_windows_required) {
    out.verdict = AssessVerdict::Stable;
    // Sparse observation is not evidence of health: an unobserved window
    // earns a small bounded probe, never a survey (04 §2).
    out.probe_recommended = last_window_unobserved_;
    return out;
  }
  if (all_bad) {
    // Every candidate already screened bad on fresh evidence: report
    // load-limit/placement review instead of looping migrations (04 §4).
    out.verdict = AssessVerdict::Stable;
    return out;
  }
  const bool independent =
      streak_observer_count_ >= migration_const::kIndependentObserversRequired ||
      streak_critical_;
  if (!independent) {
    out.verdict = AssessVerdict::InsufficientEvidence;
    out.probe_recommended = true;
    return out;
  }
  out.verdict = AssessVerdict::SurveyProposed;
  return out;
}

// --- absences / leases ------------------------------------------------------------------

ChannelCoordinator::Absence* ChannelCoordinator::find_absence(
    const NodeId node, const std::uint32_t lease_id) noexcept {
  return absences_.find([&](const Absence& a) {
    return a.node == node && a.lease_id == lease_id;
  });
}

bool ChannelCoordinator::cut_absent(const std::uint16_t protected_cut_id,
                                    const MonotonicMs at_ms,
                                    const std::uint32_t ignore_lease) const noexcept {
  if (protected_cut_id == 0) return false;
  bool absent = false;
  absences_.for_each([&](const Absence& a) {
    // ignore_lease excludes only lease-owned records; externally noticed
    // absences (lease_id 0) always count.
    const bool ignored = ignore_lease != 0 && a.lease_id == ignore_lease;
    if (!ignored && a.protected_cut_id == protected_cut_id &&
        a.until_ms > at_ms) {
      absent = true;
    }
  });
  return absent;
}

bool ChannelCoordinator::node_absent(const NodeId node,
                                     const MonotonicMs now_ms) const noexcept {
  bool absent = false;
  absences_.for_each([&](const Absence& a) {
    if (a.node == node && a.until_ms > now_ms) absent = true;
  });
  return absent;
}

Status ChannelCoordinator::note_absence(const NodeId node,
                                        const std::uint16_t protected_cut_id,
                                        const MonotonicMs until_ms,
                                        const MonotonicMs now_ms) noexcept {
  if (node == kInvalidNodeId || until_ms <= now_ms) {
    return reject(StatusCode::InvalidArgument, "invalid absence notice");
  }
  Absence* record = find_absence(node, 0);
  if (record == nullptr) {
    record = absences_.allocate();
    if (record == nullptr) {
      return reject(StatusCode::NoCapacity, "absence table full");
    }
    record->node = node;
    record->lease_id = 0;
  }
  record->protected_cut_id = protected_cut_id;
  record->until_ms = until_ms;
  return Status::success();
}

ChannelCoordinator::PairVisit* ChannelCoordinator::pair_record(
    const NodeId a, const NodeId b, const bool create) noexcept {
  PairVisit* record = pair_visits_.find([&](const PairVisit& p) {
    return (p.a == a && p.b == b) || (p.a == b && p.b == a);
  });
  if (record == nullptr && create) {
    record = pair_visits_.allocate();
    if (record != nullptr) {
      record->a = a;
      record->b = b;
      record->last_end_ms = 0;
    }
  }
  return record;
}

bool ChannelCoordinator::lease_of(const std::uint32_t lease_id,
                                  SurveyLease& out) const noexcept {
  const SurveyLease* lease = leases_.find(
      [&](const SurveyLease& l) { return l.lease_id == lease_id; });
  if (lease == nullptr) return false;
  out = *lease;
  return true;
}

Status ChannelCoordinator::request_survey_lease(const SurveyRequest& request,
                                                const MonotonicMs now_ms,
                                                SurveyLease& out) noexcept {
  // Mode gate (04 §1/§3): Observe never moves the radio — a proposal is a
  // judgment, not an executable lease. AutoGuarded never reaches here.
  if (mode_ == MigrationMode::Disabled) {
    ++stats_.lease_rejects;
    return reject(StatusCode::InvalidState, "MIGRATION_DISABLED");
  }
  if (mode_ == MigrationMode::Observe) {
    ++stats_.lease_rejects;
    return reject(StatusCode::Unsupported, "OBSERVE_MODE_NO_RADIO_CHANGE");
  }
  if (legacy_block_) {
    // A required participant without migration capability blocks the survey
    // under the same safety conditions as the plan (D5-09).
    ++stats_.lease_rejects;
    return reject(StatusCode::LegacyParticipant, "LEGACY_REQUIRED_PARTICIPANT");
  }
  if (request.peer == kInvalidNodeId || request.peer == config_.node) {
    ++stats_.lease_rejects;
    return reject(StatusCode::InvalidArgument, "invalid survey peer");
  }
  if (!candidate_permitted(request.channel)) {
    ++stats_.lease_rejects;
    return reject(StatusCode::InvalidArgument, "channel outside candidate set");
  }
  if (request.duration_ms == 0 ||
      request.duration_ms > config_.survey_visit_max_ms) {
    ++stats_.lease_rejects;
    return reject(StatusCode::InvalidArgument, "SURVEY_DURATION_BOUND");
  }
  if (request.begin_ms < now_ms) {
    ++stats_.lease_rejects;
    return reject(StatusCode::InvalidArgument, "survey begin in the past");
  }
  if (request.mapping.uncertainty_ms > config_.clock_uncertainty_max_ms) {
    ++stats_.lease_rejects;
    return reject(StatusCode::ClockUncertain, "CLOCK_UNCERTAIN");
  }
  if (request.exchanges_per_direction == 0 ||
      request.exchanges_per_direction > config_.exchange_max_per_direction) {
    ++stats_.lease_rejects;
    return reject(StatusCode::InvalidArgument, "SURVEY_EXCHANGE_BOUND");
  }
  if (request.absence_notify_count > request.absence_notify.size()) {
    ++stats_.lease_rejects;
    return reject(StatusCode::InvalidArgument, "absence notify overflow");
  }
  // Revisit gap (04 §3): the same node is not re-visited within 30s. Both
  // ends are checked — a peer already away cannot be surveyed, and our own
  // last visit end bounds the next one.
  if (last_visit_end_ != 0 &&
      request.begin_ms < last_visit_end_ + config_.survey_gap_min_ms) {
    ++stats_.lease_rejects;
    return reject(StatusCode::WouldBlock, "SURVEY_REVISIT_GAP");
  }
  PairVisit* pair = pair_record(config_.node, request.peer, true);
  if (pair == nullptr) {
    ++stats_.lease_rejects;
    return reject(StatusCode::NoCapacity, "pair table full");
  }
  if (pair->last_end_ms != 0 &&
      request.begin_ms < pair->last_end_ms + config_.survey_gap_min_ms) {
    ++stats_.lease_rejects;
    return reject(StatusCode::WouldBlock, "SURVEY_PAIR_REVISIT_GAP");
  }
  if (node_absent(config_.node, request.begin_ms) ||
      node_absent(request.peer, request.begin_ms)) {
    ++stats_.lease_rejects;
    return reject(StatusCode::Conflict, "SURVEY_END_ALREADY_ABSENT");
  }
  // Protected cuts must not be simultaneously absent (04 §3): a second
  // absence on the same cut overlapping this visit is refused.
  if (cut_absent(request.protected_cut_id, request.begin_ms, 0)) {
    ++stats_.lease_rejects;
    ++stats_.protected_cut_conflicts;
    return reject(StatusCode::Conflict, "PROTECTED_CUT_SIMULTANEOUS_ABSENCE");
  }
  if (request.cut_without_alternative && !request.outage_permitted) {
    // An unpermissioned outage on a cut with no alternative is refused —
    // and the failure is named, never hidden behind a zero-outage claim.
    ++stats_.lease_rejects;
    return reject(StatusCode::SurveyRequiresOutagePermission,
                  "SURVEY_REQUIRES_OUTAGE_PERMISSION");
  }

  SurveyLease* lease = leases_.allocate();
  if (lease == nullptr) {
    ++stats_.lease_rejects;
    return reject(StatusCode::NoCapacity, "lease table full");
  }
  *lease = SurveyLease{};
  lease->lease_id = next_lease_id_++;
  lease->initiator = config_.node;
  lease->peer = request.peer;
  lease->channel = request.channel;
  lease->home_channel = config_.home_channel;
  lease->begin_ms = request.begin_ms;
  lease->end_ms = request.begin_ms + request.duration_ms;
  lease->mapping = request.mapping;
  lease->exchanges_per_direction_max = request.exchanges_per_direction;
  lease->samples_target_per_direction = config_.samples_per_direction;
  lease->outage_permitted = request.outage_permitted;
  lease->protected_cut_id = request.protected_cut_id;
  // Single radio: the whole visit is a home-channel outage. Never claimed
  // to be zero.
  lease->home_outage_ms = request.duration_ms;
  for (std::size_t i = 0; i < request.absence_notify_count; ++i) {
    lease->absence_notify[i] = request.absence_notify[i];
  }
  lease->absence_notify_count = request.absence_notify_count;

  // Both ends are absent for the lease window; the protected cut records
  // the absence so a second simultaneous cut is refused above.
  const NodeId ends[2] = {config_.node, request.peer};
  for (const NodeId end : ends) {
    Absence* absence = absences_.allocate();
    if (absence == nullptr) {
      leases_.release(lease);
      ++stats_.lease_rejects;
      return reject(StatusCode::NoCapacity, "absence table full");
    }
    absence->node = end;
    absence->protected_cut_id = request.protected_cut_id;
    absence->until_ms = lease->end_ms;
    absence->lease_id = lease->lease_id;
  }
  last_visit_end_ = lease->end_ms;
  pair->last_end_ms = lease->end_ms;
  ChannelEvidence* evidence = evidence_for(request.channel);
  if (evidence != nullptr) {
    ++evidence->visits;
    evidence->last_update_ms = now_ms;
  }
  ++stats_.leases_issued;
  out = *lease;
  return Status::success();
}

Status ChannelCoordinator::complete_survey(const std::uint32_t lease_id,
                                           const MonotonicMs now_ms) noexcept {
  SurveyLease* lease = leases_.find(
      [&](const SurveyLease& l) { return l.lease_id == lease_id; });
  if (lease == nullptr) {
    return reject(StatusCode::NotFound, "lease unknown or already closed");
  }
  (void)now_ms;
  const std::uint32_t id = lease->lease_id;
  leases_.release(lease);
  // Release exactly this lease's absence records; external notices stay.
  while (true) {
    Absence* absence = absences_.find(
        [&](const Absence& a) { return a.lease_id == id; });
    if (absence == nullptr) break;
    absences_.release(absence);
  }
  return Status::success();
}

Status ChannelCoordinator::note_survey_sample(
    const std::uint32_t lease_id, const SurveyDirection direction,
    const bool success, const MonotonicMs now_ms) noexcept {
  SurveyLease* lease = leases_.find(
      [&](const SurveyLease& l) { return l.lease_id == lease_id; });
  if (lease == nullptr) {
    return reject(StatusCode::NotFound, "lease unknown or closed");
  }
  const std::size_t di = survey_direction_index(direction);
  if (lease->exchanges_used[di] >= lease->exchanges_per_direction_max) {
    // The 4-per-direction visit budget is a hard bound (04 §3); exceeding it
    // is refused, never silently absorbed.
    ++stats_.exchange_budget_rejects;
    return reject(StatusCode::NoCapacity, "SURVEY_EXCHANGE_BUDGET");
  }
  ++lease->exchanges_used[di];
  ChannelEvidence* evidence = evidence_for(lease->channel);
  if (evidence != nullptr) {
    ++evidence->attempts[di];
    if (success) ++evidence->successes[di];
    evidence->last_update_ms = now_ms;
  }
  ++evidence_epoch_;  // fresh screening evidence clears all-bad suppression
  return Status::success();
}

ChannelEvidence* ChannelCoordinator::evidence_for(
    const std::uint8_t channel) noexcept {
  for (auto& record : evidence_) {
    if (record.used && record.channel == channel) return &record;
  }
  for (auto& record : evidence_) {
    if (!record.used) {
      record.used = true;
      record.channel = channel;
      return &record;
    }
  }
  return nullptr;
}

const ChannelEvidence* ChannelCoordinator::evidence_for(
    const std::uint8_t channel) const noexcept {
  for (const auto& record : evidence_) {
    if (record.used && record.channel == channel) return &record;
  }
  return nullptr;
}

bool ChannelCoordinator::screening_evidence(const std::uint8_t channel,
                                            ChannelEvidence& out) const noexcept {
  const ChannelEvidence* record = evidence_for(channel);
  if (record == nullptr) return false;
  out = *record;
  return true;
}

bool ChannelCoordinator::screening_passed(const std::uint8_t channel) const noexcept {
  const ChannelEvidence* record = evidence_for(channel);
  if (record == nullptr) return false;
  for (std::size_t d = 0; d < kSurveyDirectionCount; ++d) {
    if (record->attempts[d] < config_.samples_per_direction) return false;
    if (record->successes[d] < config_.screening_successes) return false;
  }
  return true;
}

// --- candidate adoption ------------------------------------------------------------------

AdoptionDecision ChannelCoordinator::evaluate_candidate(
    const CandidateReport& report) const noexcept {
  AdoptionDecision decision{};
  decision.channel = report.channel;
  if (!candidate_permitted(report.channel)) {
    decision.verdict = AdoptionVerdict::Reject;
    decision.reason = StatusCode::InvalidArgument;
    return decision;
  }
  if (report.route_count == 0 || report.route_count > report.routes.size()) {
    decision.verdict = AdoptionVerdict::InsufficientEvidence;
    return decision;
  }
  RouteMetric worst_current = 0;
  RouteMetric worst_candidate = 0;
  bool requirement_newly_met = false;
  for (std::size_t i = 0; i < report.route_count; ++i) {
    const CriticalRouteReport& route = report.routes[i];
    if (!route.measured) {
      // Unknown stays unknown: unmeasured edges are never treated as
      // passable, and a sleeping endpoint is not "confirmed" (04 §4).
      decision.verdict = AdoptionVerdict::InsufficientEvidence;
      return decision;
    }
    if (!route.reaches_authority) {
      // The candidate graph must carry protected endpoints to the
      // designated Gateway/Authority before any cost is compared (04 §4).
      decision.verdict = AdoptionVerdict::Reject;
      decision.reason = StatusCode::NoRoute;
      return decision;
    }
    if (route.current_worst > worst_current) worst_current = route.current_worst;
    if (route.candidate_worst > worst_candidate) {
      worst_candidate = route.candidate_worst;
    }
    if (!route.requirement_met_current && route.requirement_met_candidate) {
      requirement_newly_met = true;
    }
  }
  if (requirement_newly_met || improved_quarter(worst_candidate, worst_current)) {
    decision.verdict = AdoptionVerdict::Adopt;
    return decision;
  }
  decision.verdict = AdoptionVerdict::Reject;
  decision.reason = StatusCode::NoFeasibleAlternative;
  return decision;
}

AdoptionDecision ChannelCoordinator::evaluate_candidates(
    const CandidateReport* reports, const std::size_t count,
    const MonotonicMs now_ms) noexcept {
  (void)now_ms;
  AdoptionDecision decision{};
  bool saw_insufficient = false;
  std::size_t evaluated = 0;
  for (std::size_t i = 0; i < count; ++i) {
    const AdoptionDecision single = evaluate_candidate(reports[i]);
    if (single.verdict == AdoptionVerdict::Adopt) {
      all_bad_reported_ = false;
      return single;
    }
    if (single.verdict == AdoptionVerdict::Reject) ++evaluated;
    if (single.verdict == AdoptionVerdict::InsufficientEvidence) {
      saw_insufficient = true;
    }
  }
  if (evaluated > 0 && !saw_insufficient) {
    // All evaluated candidates rejected: report load-limit/placement review
    // and suppress further survey proposals until fresh screening evidence
    // arrives — migration is not retried for its own sake (04 §4, D5-08).
    decision.verdict = AdoptionVerdict::NoViableCandidate;
    decision.reason = StatusCode::NoFeasibleAlternative;
    decision.placement_review_advised = true;
    all_bad_reported_ = true;
    suppressed_epoch_ = evidence_epoch_;
    return decision;
  }
  decision.verdict = AdoptionVerdict::InsufficientEvidence;
  return decision;
}

bool ChannelCoordinator::all_candidates_bad() const noexcept {
  return all_bad_reported_ && suppressed_epoch_ == evidence_epoch_;
}

// --- periodic ------------------------------------------------------------------------------

void ChannelCoordinator::expire_leases(const MonotonicMs now_ms) noexcept {
  while (true) {
    SurveyLease* lease = leases_.find(
        [&](const SurveyLease& l) { return l.end_ms <= now_ms; });
    if (lease == nullptr) break;
    const std::uint32_t id = lease->lease_id;
    leases_.release(lease);
    while (true) {
      Absence* absence = absences_.find(
          [&](const Absence& a) { return a.lease_id == id; });
      if (absence == nullptr) break;
      absences_.release(absence);
    }
  }
}

void ChannelCoordinator::expire_absences(const MonotonicMs now_ms) noexcept {
  while (true) {
    Absence* absence = absences_.find(
        [&](const Absence& a) { return a.until_ms <= now_ms; });
    if (absence == nullptr) break;
    absences_.release(absence);
  }
}

void ChannelCoordinator::poll(const MonotonicMs now_ms) noexcept {
  advance_windows(now_ms);
  expire_leases(now_ms);
  expire_absences(now_ms);
}

// --- ChannelOperationRunner -------------------------------------------------------------------

ChannelOperationRunner::ChannelOperationRunner(
    ChannelPort& port, const ChannelOpsConfig& config) noexcept
    : port_(port),
      config_(config),
      home_channel_(config.home_channel),
      committed_channel_(config.home_channel) {}

Status ChannelOperationRunner::set_home_channel(
    const std::uint8_t channel) noexcept {
  if (channel < config_.channel_min || channel > config_.channel_max ||
      busy()) {
    return reject(StatusCode::InvalidState, "cannot move home while busy");
  }
  home_channel_ = channel;
  committed_channel_ = channel;
  return Status::success();
}

OperationToken ChannelOperationRunner::issue(const OperationOutcome outcome,
                                             const StatusCode reason,
                                             const MonotonicMs now_ms) noexcept {
  OperationResult result{};
  result.token = OperationToken{next_token_++};
  result.outcome = outcome;
  result.reason = reason;
  result.expires_at_ms = now_ms + config_.evidence_retention_ms;
  if (evidence_.full()) {
    OperationResult dropped{};
    (void)evidence_.pop(dropped);
  }
  (void)evidence_.push(result);
  return result.token;
}

void ChannelOperationRunner::record(const OperationOutcome outcome,
                                    const StatusCode reason,
                                    const MonotonicMs now_ms) noexcept {
  OperationResult result{};
  result.token = active_token_;
  result.outcome = outcome;
  result.reason = reason;
  result.expires_at_ms = now_ms + config_.evidence_retention_ms;
  if (evidence_.full()) {
    OperationResult dropped{};
    (void)evidence_.pop(dropped);
  }
  (void)evidence_.push(result);
  active_token_ = kInvalidOperationToken;
  active_ = RadioOperation{};
  phase_ = Phase::Idle;
}

OperationToken ChannelOperationRunner::request(const RadioOperation& op,
                                               const MonotonicMs now_ms) noexcept {
  // P4 implements the bounded survey visit and the verified switch
  // primitive; discovery visits and sleep preparation are not this runner's
  // contract.
  if (op.kind != RadioOperationKind::SurveyVisit &&
      op.kind != RadioOperationKind::ChannelCutover) {
    return issue(OperationOutcome::Rejected, StatusCode::Unsupported, now_ms);
  }
  if (busy()) {
    // The arbiter serializes radio configuration: one operation at a time.
    return issue(OperationOutcome::Rejected, StatusCode::Busy, now_ms);
  }
  const std::uint8_t channel = op.constraints.channel;
  if (channel < config_.channel_min || channel > config_.channel_max) {
    return issue(OperationOutcome::Rejected, StatusCode::InvalidArgument, now_ms);
  }
  if (!op.constraints.outage_permitted) {
    // Every switch is a bounded home-channel RX outage on a single radio;
    // without an explicit grant the operation is refused — never silently
    // executed or claimed to be outage-free (04 §3).
    return issue(OperationOutcome::Rejected,
                 StatusCode::SurveyRequiresOutagePermission, now_ms);
  }
  if (op.kind == RadioOperationKind::SurveyVisit &&
      (op.constraints.max_duration_ms == 0 ||
       op.constraints.max_duration_ms > config_.visit_hard_cap_ms)) {
    return issue(OperationOutcome::Rejected, StatusCode::InvalidArgument, now_ms);
  }
  if (op.deadline_ms != 0 && now_ms >= op.deadline_ms) {
    return issue(OperationOutcome::Rejected, StatusCode::Expired, now_ms);
  }
  active_ = op;
  active_token_ = OperationToken{next_token_++};
  phase_ = Phase::WaitDrain;
  const MonotonicMs budget_end = now_ms + config_.drain_budget_ms;
  drain_deadline_ms_ =
      op.deadline_ms != 0 && op.deadline_ms < budget_end ? op.deadline_ms
                                                         : budget_end;
  return active_token_;
}

Status ChannelOperationRunner::apply_channel(const std::uint8_t target) noexcept {
  const Status set = port_.set_channel(target);
  if (!set) return set;  // driver refused: known not applied -> FAILED
  std::uint8_t observed = 0;
  const Status readback = port_.readback_channel(observed);
  if (!readback || observed != target) {
    // The switch may or may not have taken effect: this is the uncertain
    // boundary, never reported as success or as a clean failure.
    return reject(StatusCode::DriverResultUnknown, "CHANNEL_READBACK_FAILED");
  }
  const Status peers = port_.reapply_peer_radio();
  if (!peers) {
    // Channel verified but peer rates could not be re-applied: partial side
    // effect, not a clean failure.
    return reject(StatusCode::DriverResultUnknown, "PEER_RATE_REAPPLY_FAILED");
  }
  port_.committed_channel(target);
  committed_channel_ = target;
  ++generation_.value;
  return Status::success();
}

void ChannelOperationRunner::fail_or_unknown(const Status& cause,
                                             const MonotonicMs now_ms) noexcept {
  if (cause.code != StatusCode::DriverResultUnknown) {
    // set_channel refused: nothing was applied.
    record(OperationOutcome::Failed, cause.code, now_ms);
    return;
  }
  // Post-set uncertainty: attempt a verified restore to home so the failure
  // is KNOWN (FAILED), and only report INDETERMINATE when the restore
  // itself cannot be verified.
  if (apply_channel(home_channel_).ok()) {
    record(OperationOutcome::Failed, cause.code, now_ms);
  } else {
    record(OperationOutcome::Indeterminate, StatusCode::DriverResultUnknown,
           now_ms);
  }
}

void ChannelOperationRunner::poll(const MonotonicMs now_ms) noexcept {
  switch (phase_) {
    case Phase::Idle:
      break;
    case Phase::WaitDrain: {
      if (!port_.tx_quiesced()) {
        if (now_ms < drain_deadline_ms_) break;
        // Drain deadline: fence the straggler so its missed callback
        // resolves as unknown — never fabricated success/failure (X-02) —
        // then proceed on the fenced boundary.
        port_.fence_pending_tx();
        if (active_.deadline_ms != 0 && now_ms >= active_.deadline_ms) {
          record(OperationOutcome::Failed, StatusCode::Expired, now_ms);
          break;
        }
      }
      const Status applied = apply_channel(active_.constraints.channel);
      if (!applied) {
        fail_or_unknown(applied, now_ms);
        break;
      }
      if (active_.kind == RadioOperationKind::SurveyVisit) {
        phase_ = Phase::VisitDwell;
        visit_end_ms_ = now_ms + active_.constraints.max_duration_ms;
      } else {
        // ChannelCutover: the verified channel becomes the new home.
        home_channel_ = active_.constraints.channel;
        record(OperationOutcome::Applied, StatusCode::Ok, now_ms);
      }
      break;
    }
    case Phase::VisitDwell: {
      if (now_ms < visit_end_ms_) break;
      // Return-to-home is part of the bounded visit: APPLIED only after the
      // home channel is readback-verified again.
      const Status restored = apply_channel(home_channel_);
      if (restored.ok()) {
        record(OperationOutcome::Applied, StatusCode::Ok, now_ms);
      } else if (restored.code != StatusCode::DriverResultUnknown) {
        // The return was refused; the radio is known to still be off-home.
        record(OperationOutcome::Failed, restored.code, now_ms);
      } else {
        record(OperationOutcome::Indeterminate,
               StatusCode::DriverResultUnknown, now_ms);
      }
      break;
    }
  }
  // Evidence retention.
  while (!evidence_.empty()) {
    const OperationResult* front = evidence_.front();
    if (front == nullptr || front->expires_at_ms > now_ms) break;
    OperationResult dropped{};
    (void)evidence_.pop(dropped);
  }
}

bool ChannelOperationRunner::result(const OperationToken token,
                                    OperationResult& out) const noexcept {
  if (token == active_token_) {
    out = OperationResult{token, OperationOutcome::Pending, StatusCode::Ok,
                          0};
    return true;
  }
  // FixedQueue has no index access; scan a copy by popping it.
  FixedQueue<OperationResult, migration_const::kOperationEvidence> copy =
      evidence_;
  OperationResult item{};
  while (copy.pop(item)) {
    if (item.token == token) {
      out = item;
      return true;
    }
  }
  return false;
}

}  // namespace routeloom
