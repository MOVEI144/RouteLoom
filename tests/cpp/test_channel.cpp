// P4 channel Observe + bounded-survey tests (docs/design/autonomous-mesh/
// 04-channel-migration.md §2-§4, contracts.json migration.*) plus the P6
// explainable AutoGuarded precondition gate (§1/§10, D5-01). Covers the
// observe->survey judgment, candidate intersection, SurveyLease bounds, the
// serialized channel-operation runner against a scripted ChannelPort, the
// single-radio visit model and the PauseMask. Scenario ids from
// scenarios.json are noted where they map (D5-08/D5-09/D5-10, X-02).
// Plan/commit/cutover/recovery (P5) is out of scope here.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <vector>

#include "routeloom/channel_plan.hpp"
#include "routeloom/node.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

#include "test_autonomy.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                          \
  do {                                                                       \
    if (!(expr)) {                                                           \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,   \
                   #expr);                                                   \
      ++failures;                                                            \
    }                                                                        \
  } while (false)
#define CHECK_OK(expr)                                                       \
  do {                                                                       \
    const auto _status = (expr);                                             \
    if (!_status.ok()) {                                                     \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,       \
                   __LINE__, #expr, _status.detail);                         \
      ++failures;                                                            \
    }                                                                        \
  } while (false)

using namespace routeloom;
using routeloom_test::CapturingObserver;
using routeloom_test::FakeRadioPort;
using routeloom_test::SimReplyPort;
using routeloom_test::SimWorld;
using routeloom_test::TestSecurity;

constexpr MonotonicMs kW0 = 1000;        // inside window 0
constexpr MonotonicMs kW1 = 31000;       // inside window 1
constexpr MonotonicMs kW2 = 61000;       // inside window 2

ChannelCoordinatorConfig coord_config(NodeId self = 1, std::uint8_t home = 1) {
  ChannelCoordinatorConfig config{};
  config.node = self;
  config.home_channel = home;
  return config;
}

HealthEvidence impaired(NodeId observer) {
  HealthEvidence e{};
  e.observer = observer;
  e.delivery_impaired = true;
  return e;
}

SurveyRequest survey_req(NodeId peer, std::uint8_t channel,
                         MonotonicMs begin) {
  SurveyRequest req{};
  req.peer = peer;
  req.channel = channel;
  req.begin_ms = begin;
  req.duration_ms = 150;
  req.mapping.uncertainty_ms = 10;
  req.exchanges_per_direction = 4;
  req.outage_permitted = true;
  return req;
}

// --- observe -> survey judgment (04 §2) ------------------------------------------

void test_window_tracking() {
  ChannelCoordinator c(coord_config());
  CHECK_OK(c.set_mode(MigrationMode::Manual));
  // One bad window is never enough for a survey proposal.
  c.note_health_evidence(impaired(7), kW0);
  c.note_health_evidence(impaired(8), kW0 + 10);
  ChannelAssessment a1 = c.assess(kW1);
  CHECK(a1.verdict == AssessVerdict::Stable);
  CHECK(a1.consecutive_bad_windows == 1);
  // A second consecutive bad window with two independent observation
  // points proposes a bounded survey.
  c.note_health_evidence(impaired(7), kW1);
  ChannelAssessment a2 = c.assess(kW2);
  CHECK(a2.verdict == AssessVerdict::SurveyProposed);
  CHECK(a2.consecutive_bad_windows == 2);
  CHECK(a2.independent_observers == 2);
}

void test_independence_requirement() {
  ChannelCoordinator c(coord_config());
  // Two consecutive bad windows but a single observation point: the
  // judgment stays InsufficientEvidence and asks for a small probe —
  // one node crying wolf never moves the mesh (04 §2).
  c.note_health_evidence(impaired(7), kW0);
  c.note_health_evidence(impaired(7), kW1);
  ChannelAssessment a = c.assess(kW2);
  CHECK(a.verdict == AssessVerdict::InsufficientEvidence);
  CHECK(a.probe_recommended);
  // A protected critical link impaired satisfies the alternative branch
  // even with a single observer.
  ChannelCoordinator c2(coord_config());
  HealthEvidence critical{};
  critical.observer = 7;
  critical.critical_link_impaired = true;
  c2.note_health_evidence(critical, kW0);
  c2.note_health_evidence(impaired(7), kW1);
  ChannelAssessment b = c2.assess(kW2);
  CHECK(b.verdict == AssessVerdict::SurveyProposed);
  CHECK(b.critical_link_impaired);
}

void test_rssi_only_never_triggers() {
  ChannelCoordinator c(coord_config());
  // 04 §2: RSSI alone never migrates the mesh.
  HealthEvidence rssi{};
  rssi.observer = 7;
  rssi.rssi_low = true;
  c.note_health_evidence(rssi, kW0);
  c.note_health_evidence(rssi, kW1);
  c.note_health_evidence(rssi, kW2);
  ChannelAssessment a = c.assess(kW2 + 30000);
  CHECK(a.verdict == AssessVerdict::Stable);
  CHECK(a.consecutive_bad_windows == 0);
}

void test_unauthenticated_ignored() {
  ChannelCoordinator c(coord_config());
  HealthEvidence hostile = impaired(7);
  hostile.authenticated = false;
  c.note_health_evidence(hostile, kW0);
  c.note_health_evidence(hostile, kW1);
  ChannelAssessment a = c.assess(kW2);
  CHECK(a.consecutive_bad_windows == 0);
  CHECK(c.stats().unauthenticated_ignored == 2);
  CHECK(a.verdict != AssessVerdict::SurveyProposed);
}

void test_mode_gates() {
  ChannelCoordinator c(coord_config());
  // AutoGuarded goes through the explainable gate: a bare request carries
  // no evidence, so the refusal names the first unmet precondition —
  // the verified authority path — never a blanket Unsupported.
  const Status blocked = c.set_mode(MigrationMode::AutoGuarded);
  CHECK(!blocked.ok());
  CHECK(blocked.code == StatusCode::NoRoute);
  CHECK(c.mode() == MigrationMode::Observe);
  // Disabled produces no judgment at all.
  CHECK_OK(c.set_mode(MigrationMode::Disabled));
  c.note_health_evidence(impaired(7), kW0);
  c.note_health_evidence(impaired(8), kW1);
  ChannelAssessment a = c.assess(kW2);
  CHECK(a.verdict == AssessVerdict::Disabled);
  // Observed-only mode must not change radio behavior: lease issue is
  // refused even though the proposal machinery ran.
  CHECK_OK(c.set_mode(MigrationMode::Observe));
  SurveyLease lease{};
  CHECK(c.request_survey_lease(survey_req(2, 6, kW2 + 10), kW2, lease).code ==
        StatusCode::Unsupported);
}

// --- candidate set / participants (04 §2, D5-09) -------------------------------------

void test_candidate_intersection() {
  ChannelCoordinator c(coord_config());
  std::uint8_t out[8]{};
  // No participants registered: approved profile set minus home.
  CHECK(c.candidates(out, 8) == 2);
  CHECK(out[0] == 6 && out[1] == 11);
  // Participant capability narrows the set (intersection).
  ParticipantCapability p{};
  p.node = 2;
  p.migration_capable = true;
  p.required = true;
  p.channel_mask = (1u << 5) | (1u << 10);  // {6,11}
  CHECK_OK(c.note_participant(p));
  CHECK(c.candidates(out, 8) == 2);
  ParticipantCapability narrow{};
  narrow.node = 3;
  narrow.migration_capable = true;
  narrow.channel_mask = 1u << 10;  // {11}
  CHECK_OK(c.note_participant(narrow));
  CHECK(c.candidates(out, 8) == 1 && out[0] == 11);
  // A required legacy participant does not narrow — it blocks (D5-09).
  ParticipantCapability legacy{};
  legacy.node = 4;
  legacy.migration_capable = false;
  legacy.required = true;
  legacy.channel_mask = migration_const::kChannelMaskAll24;
  CHECK_OK(c.note_participant(legacy));
  CHECK(c.legacy_participant_block());
  ChannelAssessment a = c.assess(kW0);
  CHECK(a.legacy_participant_block);
  SurveyLease lease{};
  CHECK_OK(c.set_mode(MigrationMode::Manual));
  CHECK(c.request_survey_lease(survey_req(2, 11, kW1), kW0, lease).code ==
        StatusCode::LegacyParticipant);
  // Non-required legacy (e.g. a peripheral leaf) does not block.
  ChannelCoordinator c2(coord_config());
  legacy.required = false;
  CHECK_OK(c2.note_participant(legacy));
  CHECK(!c2.legacy_participant_block());
}

// --- SurveyLease bounds (04 §3) -----------------------------------------------------

void test_lease_bounds() {
  ChannelCoordinator c(coord_config());
  CHECK_OK(c.set_mode(MigrationMode::Manual));
  SurveyLease lease{};

  SurveyRequest bad = survey_req(2, 6, kW0 + 100);
  bad.duration_ms = 201;
  CHECK(c.request_survey_lease(bad, kW0, lease).code == StatusCode::InvalidArgument);

  bad = survey_req(2, 6, kW0 + 100);
  bad.mapping.uncertainty_ms = 21;  // > clock_uncertainty_max_ms (D5-03 territory)
  CHECK(c.request_survey_lease(bad, kW0, lease).code == StatusCode::ClockUncertain);

  bad = survey_req(2, 6, kW0 + 100);
  bad.exchanges_per_direction = 5;  // > 4/visit
  CHECK(c.request_survey_lease(bad, kW0, lease).code == StatusCode::InvalidArgument);

  bad = survey_req(2, 2, kW0 + 100);  // channel outside candidates
  CHECK(c.request_survey_lease(bad, kW0, lease).code == StatusCode::InvalidArgument);

  bad = survey_req(2, 6, kW0 - 10);  // begin in the past
  CHECK(c.request_survey_lease(bad, kW0, lease).code == StatusCode::InvalidArgument);

  // A cut without an alternative requires explicit outage permission —
  // and the refusal is named, never hidden (04 §3).
  bad = survey_req(2, 6, kW0 + 100);
  bad.cut_without_alternative = true;
  bad.outage_permitted = false;
  CHECK(c.request_survey_lease(bad, kW0, lease).code ==
        StatusCode::SurveyRequiresOutagePermission);

  // Happy path: all lease contract fields are recorded; a single-radio
  // visit is always a home outage of the full duration, never zero.
  SurveyRequest good = survey_req(2, 6, kW0 + 100);
  good.absence_notify[0] = 9;
  good.absence_notify[1] = 10;
  good.absence_notify_count = 2;
  CHECK_OK(c.request_survey_lease(good, kW0, lease));
  CHECK(lease.initiator == 1 && lease.peer == 2);
  CHECK(lease.channel == 6 && lease.home_channel == 1);
  CHECK(lease.end_ms == kW0 + 250);  // return-to-home bound
  CHECK(lease.home_outage_ms == 150);
  CHECK(lease.absence_notify_count == 2);
  CHECK(lease.samples_target_per_direction == 20);
  CHECK(lease.exchanges_per_direction_max == 4);
}

void test_revisit_gap() {
  ChannelCoordinator c(coord_config());
  CHECK_OK(c.set_mode(MigrationMode::Manual));
  SurveyLease lease{};
  CHECK_OK(c.request_survey_lease(survey_req(2, 6, kW0 + 100), kW0, lease));
  // Same node re-visited inside the 30s gap is refused (04 §3).
  SurveyRequest again = survey_req(2, 6, kW0 + 250 + 1000);
  CHECK(c.request_survey_lease(again, kW0 + 250, lease).code ==
        StatusCode::WouldBlock);
  // After the gap the pair may visit again.
  SurveyRequest later = survey_req(2, 6, kW0 + 250 + 31000);
  CHECK_OK(c.request_survey_lease(later, kW0 + 250 + 30000, lease));
}

void test_scheduled_absence() {
  ChannelCoordinator c(coord_config());
  CHECK_OK(c.set_mode(MigrationMode::Manual));
  // An authenticated scheduled-absence notice marks the peer away; a lease
  // whose end is already absent is refused (04 §3).
  CHECK_OK(c.note_absence(2, 0, kW0 + 500, kW0));
  CHECK(c.node_absent(2, kW0 + 100));
  CHECK(!c.node_absent(2, kW0 + 600));
  SurveyLease lease{};
  CHECK(c.request_survey_lease(survey_req(2, 6, kW0 + 100), kW0, lease).code ==
        StatusCode::Conflict);
  // A lease on a protected cut blocks a second simultaneous absence on the
  // same cut (04 §3). The next request begins after our own revisit gap so
  // the cut conflict — not the gap — is the refusing rule.
  ChannelCoordinator c2(coord_config());
  CHECK_OK(c2.set_mode(MigrationMode::Manual));
  SurveyRequest first = survey_req(2, 6, kW0 + 100);  // ends kW0+250
  first.protected_cut_id = 7;
  CHECK_OK(c2.request_survey_lease(first, kW0, lease));
  CHECK_OK(c2.note_absence(9, 7, kW0 + 40000, kW0));  // same cut, overlapping
  SurveyRequest second = survey_req(3, 11, kW0 + 31000);
  second.protected_cut_id = 7;
  CHECK(c2.request_survey_lease(second, kW0 + 31000, lease).code ==
        StatusCode::Conflict);
  // A different cut is unaffected.
  SurveyRequest third = survey_req(3, 11, kW0 + 31000);
  third.protected_cut_id = 8;
  CHECK_OK(c2.request_survey_lease(third, kW0 + 31000, lease));
}

// --- screening evidence (04 §3) ------------------------------------------------------

void test_sample_accounting() {
  ChannelCoordinator c(coord_config());
  CHECK_OK(c.set_mode(MigrationMode::Manual));
  // Five visits at the 4-exchange/direction budget accumulate the 20-sample
  // screening target; 19/20 is screening, never a reliability proof.
  MonotonicMs begin = kW0 + 100;
  for (int visit = 0; visit < 5; ++visit) {
    SurveyLease lease{};
    CHECK_OK(c.request_survey_lease(survey_req(2, 6, begin), begin - 100, lease));
    for (int i = 0; i < 4; ++i) {
      const bool success = !(visit == 0 && i == 0);  // exactly one failure
      CHECK_OK(c.note_survey_sample(lease.lease_id,
                                    SurveyDirection::InitiatorToPeer, success,
                                    begin + 10));
      CHECK_OK(c.note_survey_sample(lease.lease_id,
                                    SurveyDirection::PeerToInitiator, success,
                                    begin + 10));
    }
    // The per-direction visit budget is a hard bound.
    CHECK(c.note_survey_sample(lease.lease_id, SurveyDirection::InitiatorToPeer,
                               true, begin + 10)
              .code == StatusCode::NoCapacity);
    CHECK_OK(c.complete_survey(lease.lease_id, begin + 200));
    begin += 31000;
  }
  ChannelEvidence ev{};
  CHECK(c.screening_evidence(6, ev));
  CHECK(ev.attempts[0] == 20 && ev.attempts[1] == 20);
  CHECK(ev.successes[0] == 19 && ev.successes[1] == 19);
  CHECK(ev.visits == 5);
  CHECK(c.screening_passed(6));
  CHECK(!c.screening_passed(11));
}

// --- AutoGuarded gate (04 §1/§10, D5-01; P6) ----------------------------------------

AutoGuardedEvidence full_evidence(const MonotonicMs at) {
  AutoGuardedEvidence e{};
  e.asserted_at_ms = at;
  e.authority_configured = true;
  e.authority_available = true;
  e.verifier_ready = true;
  e.authority_path_verified = true;
  e.required_count = 2;
  e.clock_valid = true;
  e.clock_uncertainty_ms = 10;
  e.clock_uncertainty_max_ms = migration_const::kClockUncertaintyMaxMs;
  e.recovery_plan_present = true;
  e.survey_evidence_known = true;
  e.survey_evidence_fresh = true;
  return e;
}

void test_autoguarded_gate_evaluator() {
  // A full pass is explicit: every condition satisfied, nothing inferred.
  AutoGuardedVerdict v = evaluate_autoguarded(full_evidence(kW0));
  CHECK(v.permitted);
  CHECK(v.satisfied_mask == kAutoGuardedAllMask);
  CHECK(v.unmet_mask() == 0);

  // Empty evidence: nothing asserts itself; every condition is unmet and
  // the refusal is explainable — first in evaluation order, stable detail.
  const AutoGuardedVerdict none =
      evaluate_autoguarded(AutoGuardedEvidence{});
  CHECK(!none.permitted);
  CHECK(none.first_unmet == AutoGuardedCondition::VerifiedAuthorityPath);
  CHECK(none.reason == StatusCode::NoRoute);
  // An empty required set and no latched cooldown genuinely satisfy those
  // conditions — the gate still blocks on authority path, clock, recovery
  // plan and survey evidence.
  CHECK(none.unmet_mask() ==
        (autoguarded_condition_bit(AutoGuardedCondition::VerifiedAuthorityPath) |
         autoguarded_condition_bit(AutoGuardedCondition::ClockBounded) |
         autoguarded_condition_bit(AutoGuardedCondition::RecoveryPlanPresent) |
         autoguarded_condition_bit(
             AutoGuardedCondition::SurveyEvidenceFresh)));

  AutoGuardedEvidence e{};
  e = full_evidence(kW0);
  e.authority_available = false;
  v = evaluate_autoguarded(e);
  CHECK(!v.permitted);
  CHECK(v.first_unmet == AutoGuardedCondition::VerifiedAuthorityPath);
  CHECK(v.reason == StatusCode::NoRoute);

  e = full_evidence(kW0);
  e.required_unobserved = 1;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::RequiredSetObserved);
  CHECK(v.reason == StatusCode::WouldBlock);

  e = full_evidence(kW0);
  e.required_not_ready = 1;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::RequiredSetReady);
  CHECK(v.reason == StatusCode::WouldBlock);

  e = full_evidence(kW0);
  e.required_legacy_present = true;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::NoLegacyRequired);
  CHECK(v.reason == StatusCode::LegacyParticipant);

  // Unknown time is never zero-uncertainty: an unarmed clock fails the
  // bound check, and an armed-but-wide clock fails it too.
  e = full_evidence(kW0);
  e.clock_valid = false;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::ClockBounded);
  CHECK(v.reason == StatusCode::ClockUncertain);
  e = full_evidence(kW0);
  e.clock_uncertainty_ms = e.clock_uncertainty_max_ms + 1;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::ClockBounded);
  CHECK(v.reason == StatusCode::ClockUncertain);

  e = full_evidence(kW0);
  e.cooldown_active = true;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::CooldownClear);
  CHECK(v.reason == StatusCode::Busy);

  e = full_evidence(kW0);
  e.recovery_plan_present = false;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::RecoveryPlanPresent);
  CHECK(v.reason == StatusCode::PlanNotCommitted);

  e = full_evidence(kW0);
  e.survey_evidence_known = false;
  e.survey_evidence_fresh = false;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::SurveyEvidenceFresh);
  CHECK(v.reason == StatusCode::Expired);

  // All unmet conditions are reported, not just the first.
  e = full_evidence(kW0);
  e.clock_valid = false;
  e.cooldown_active = true;
  v = evaluate_autoguarded(e);
  CHECK(v.first_unmet == AutoGuardedCondition::ClockBounded);
  CHECK(!v.satisfied(AutoGuardedCondition::ClockBounded));
  CHECK(!v.satisfied(AutoGuardedCondition::CooldownClear));
  CHECK(v.satisfied(AutoGuardedCondition::VerifiedAuthorityPath));
  CHECK(v.satisfied(AutoGuardedCondition::SurveyEvidenceFresh));

  // The survey-refresh mask exempts only survey freshness — reported but
  // not gating — while every other condition still blocks.
  e = full_evidence(kW0);
  e.survey_evidence_fresh = false;
  v = evaluate_autoguarded(e, kAutoguardedSurveyGateMask);
  CHECK(v.permitted);
  CHECK(!v.satisfied(AutoGuardedCondition::SurveyEvidenceFresh));
  e.cooldown_active = true;
  v = evaluate_autoguarded(e, kAutoguardedSurveyGateMask);
  CHECK(!v.permitted);
  CHECK(v.first_unmet == AutoGuardedCondition::CooldownClear);
}

// Feed the five bounded visits that accumulate passing 19/20 screening on
// `channel`; returns the timestamp of the last recorded sample.
MonotonicMs survey_pass_five(ChannelCoordinator& c, const MonotonicMs begin0,
                             const std::uint8_t channel) {
  MonotonicMs begin = begin0;
  MonotonicMs last = begin0;
  for (int visit = 0; visit < 5; ++visit) {
    SurveyLease lease{};
    CHECK_OK(c.request_survey_lease(survey_req(2, channel, begin),
                                    begin - 100, lease));
    for (int i = 0; i < 4; ++i) {
      const bool success = !(visit == 0 && i == 0);  // exactly one failure
      CHECK_OK(c.note_survey_sample(lease.lease_id,
                                    SurveyDirection::InitiatorToPeer, success,
                                    begin + 10));
      CHECK_OK(c.note_survey_sample(lease.lease_id,
                                    SurveyDirection::PeerToInitiator, success,
                                    begin + 10));
    }
    CHECK_OK(c.complete_survey(lease.lease_id, begin + 200));
    last = begin + 10;
    begin += 31000;
  }
  return last;
}

void test_autoguarded_gate_coordinator() {
  // No screening records: the coordinator recomputes its own condition —
  // a caller-asserted "fresh" never substitutes for real survey evidence.
  ChannelCoordinator c(coord_config());
  AutoGuardedVerdict v = c.request_autoguarded(full_evidence(kW0), kW0);
  CHECK(!v.permitted);
  CHECK(v.first_unmet == AutoGuardedCondition::SurveyEvidenceFresh);
  CHECK(v.reason == StatusCode::Expired);
  CHECK(c.mode() == MigrationMode::Observe);  // failure changes nothing

  // A required legacy participant blocks via coordinator-owned truth even
  // when the caller does not claim one (D5-09).
  ChannelCoordinator c2(coord_config());
  ParticipantCapability legacy{};
  legacy.node = 4;
  legacy.migration_capable = false;
  legacy.required = true;
  legacy.channel_mask = migration_const::kChannelMaskAll24;
  CHECK_OK(c2.note_participant(legacy));
  v = c2.request_autoguarded(full_evidence(kW0), kW0);
  CHECK(!v.permitted);
  CHECK(v.first_unmet == AutoGuardedCondition::NoLegacyRequired);
  CHECK(v.reason == StatusCode::LegacyParticipant);

  // A future-stamped snapshot is as stale as an aged one.
  v = c2.evaluate_autoguarded(full_evidence(kW0 + 1000), kW0);
  CHECK(!v.permitted);
  CHECK(v.reason == StatusCode::Expired);

  // Real passing screening, then an explicit opt-in request: the full
  // pass latches the mode and stores the evidence snapshot.
  CHECK_OK(c.set_mode(MigrationMode::Manual));
  const MonotonicMs last_sample = survey_pass_five(c, kW0 + 100, 6);
  const MonotonicMs gate_now = last_sample + 1000;
  v = c.request_autoguarded(full_evidence(gate_now), gate_now);
  CHECK(v.permitted);
  CHECK(v.satisfied_mask == kAutoGuardedAllMask);
  CHECK(c.mode() == MigrationMode::AutoGuarded);

  // In AutoGuarded a bounded visit issues — the live re-gate (survey
  // freshness exempt, everything else enforced) passes on fresh evidence.
  SurveyLease lease{};
  const MonotonicMs op_now = gate_now + 60000;
  CHECK_OK(c.request_survey_lease(survey_req(2, 6, op_now + 100), op_now,
                                  lease));

  // Past the evidence bound the stored snapshot vouches for nothing: the
  // automatic operation refuses with the explainable Expired verdict while
  // the mode itself is unchanged — refusal, never silent execution.
  const MonotonicMs stale_now =
      gate_now + kAutoguardedEvidenceMaxAgeMs + 1;
  CHECK(c.request_survey_lease(survey_req(2, 6, stale_now + 100), stale_now,
                               lease)
            .code == StatusCode::Expired);
  CHECK(c.mode() == MigrationMode::AutoGuarded);
}

// --- candidate adoption (04 §4, D5-08) ----------------------------------------------

CandidateReport report(std::uint8_t channel, RouteMetric cur,
                       RouteMetric cand) {
  CandidateReport r{};
  r.channel = channel;
  r.route_count = 1;
  r.routes[0].protected_endpoint = 50;
  r.routes[0].current_worst = cur;
  r.routes[0].candidate_worst = cand;
  r.routes[0].measured = true;
  r.routes[0].reaches_authority = true;
  return r;
}

void test_candidate_adoption() {
  ChannelCoordinator c(coord_config());
  // >=25% worst-cost improvement adopts.
  CandidateReport good = report(6, 100, 75);
  CHECK(c.evaluate_candidate(good).verdict == AdoptionVerdict::Adopt);
  // 10% improvement is not enough (04 §4).
  CandidateReport weak = report(6, 100, 90);
  AdoptionDecision weak_d = c.evaluate_candidate(weak);
  CHECK(weak_d.verdict == AdoptionVerdict::Reject);
  CHECK(weak_d.reason == StatusCode::NoFeasibleAlternative);
  // A requirement the current channel fails but the candidate meets adopts.
  CandidateReport met = report(6, 100, 90);
  met.routes[0].requirement_met_current = false;
  met.routes[0].requirement_met_candidate = true;
  CHECK(c.evaluate_candidate(met).verdict == AdoptionVerdict::Adopt);
  // Unmeasured edges are never passable: unknown stays unknown.
  CandidateReport unmeasured = report(6, 100, 50);
  unmeasured.routes[0].measured = false;
  CHECK(c.evaluate_candidate(unmeasured).verdict ==
        AdoptionVerdict::InsufficientEvidence);
  // Protected endpoints must reach the designated Gateway/Authority first.
  CandidateReport noreach = report(6, 100, 50);
  noreach.routes[0].reaches_authority = false;
  AdoptionDecision nr = c.evaluate_candidate(noreach);
  CHECK(nr.verdict == AdoptionVerdict::Reject);
  CHECK(nr.reason == StatusCode::NoRoute);
}

void test_all_candidates_bad_suppression() {
  // D5-08: every candidate bad -> report load-limit/placement review and
  // do not keep proposing migration for its own sake.
  ChannelCoordinator c(coord_config());
  CandidateReport bad6 = report(6, 100, 400);
  CandidateReport bad11 = report(11, 100, 500);
  const CandidateReport batch[2] = {bad6, bad11};
  AdoptionDecision d = c.evaluate_candidates(batch, 2, kW0);
  CHECK(d.verdict == AdoptionVerdict::NoViableCandidate);
  CHECK(d.placement_review_advised);
  CHECK(c.all_candidates_bad());
  // Fresh bad windows are suppressed while the all-bad evidence is fresh.
  c.note_health_evidence(impaired(7), kW0);
  c.note_health_evidence(impaired(8), kW1);
  ChannelAssessment a = c.assess(kW2);
  CHECK(a.verdict == AssessVerdict::Stable);
  CHECK(a.placement_review_advised);
  // New screening evidence reopens the judgment (no permanent latch).
  CHECK_OK(c.set_mode(MigrationMode::Manual));
  SurveyLease lease{};
  CHECK_OK(c.request_survey_lease(survey_req(2, 6, kW2 + 100), kW2, lease));
  CHECK_OK(c.note_survey_sample(lease.lease_id, SurveyDirection::InitiatorToPeer,
                                true, kW2 + 110));
  ChannelCoordinator c3(coord_config());
  c3.note_health_evidence(impaired(7), kW0);
  c3.note_health_evidence(impaired(8), kW1);
  CHECK(c3.assess(kW2).verdict == AssessVerdict::SurveyProposed);
}

// --- single-radio visit model (04 §3, D5-10) -----------------------------------------

void test_single_radio_visit_model() {
  // The fake models one radio: while parked on a survey channel it cannot
  // receive on home — and the return path restores reception.
  FakeRadioPort radio;
  TestSecurity security;
  CapturingObserver observer;
  NodeConfig config{};
  config.network = 1;
  config.node = 1;
  config.message_session = 10;
  SimReplyPort port(radio, config.node, config.link_epoch);
  MeshNode node(config, radio, security, observer);
  CHECK_OK(node.set_reply_peer_port(&port));
  radio.set_home_channel(1);
  CHECK_OK(node.start(0));
  const std::array<std::uint8_t, 4> junk{{1, 2, 3, 4}};
  const ByteView frame{junk.data(), junk.size()};
  const RadioRxMetadata meta{-60};

  radio.visit_channel(6, 100);  // visiting 6 until t=100
  CHECK(radio.current_channel(50) == 6);
  // Home RX is physically impossible while visiting (D5-10 oracle).
  CHECK(!radio.inject_rx(1, 2, frame, meta, 50, node));
  CHECK(radio.missed_rx == 1);
  // The visit channel still receives.
  CHECK(radio.inject_rx(6, 2, frame, meta, 50, node));
  // The bounded visit ends: home reception returns.
  CHECK(radio.current_channel(150) == 1);
  CHECK(radio.inject_rx(1, 2, frame, meta, 150, node));
  radio.visit_channel(11, 400);
  radio.return_home();
  CHECK(radio.current_channel(200) == 1);
}

// --- ChannelOperationRunner (04 §3/§8, D5-10, X-02) -----------------------------------

class FakeChannelPort final : public ChannelPort {
 public:
  bool tx_quiesced() const noexcept override { return quiesced; }
  Status set_channel(std::uint8_t ch) noexcept override {
    ++set_calls;
    if (set_calls == set_fail_at || set_calls >= set_fail_from) {
      return Status::error(StatusCode::RadioFailure, "scripted set failure");
    }
    channel = ch;
    return Status::success();
  }
  Status readback_channel(std::uint8_t& out) noexcept override {
    ++readback_calls;
    if (readback_calls == readback_fail_at) {
      return Status::error(StatusCode::RadioFailure, "scripted readback failure");
    }
    out = readback_calls == readback_wrong_at ? wrong_channel : channel;
    return Status::success();
  }
  Status reapply_peer_radio() noexcept override {
    ++reapply_calls;
    if (reapply_calls == reapply_fail_at) {
      return Status::error(StatusCode::RadioFailure, "scripted reapply failure");
    }
    return Status::success();
  }
  void fence_pending_tx() noexcept override { ++fence_calls; }
  void committed_channel(std::uint8_t ch) noexcept override {
    ++committed_calls;
    committed = ch;
  }

  bool quiesced{true};
  std::uint8_t channel{1};
  std::uint8_t wrong_channel{9};
  std::uint8_t committed{0};
  int set_calls{0};
  int readback_calls{0};
  int reapply_calls{0};
  int fence_calls{0};
  int committed_calls{0};
  int set_fail_at{0};
  int set_fail_from{std::numeric_limits<int>::max()};
  int readback_fail_at{0};
  int readback_wrong_at{0};
  int reapply_fail_at{0};
};

ChannelOpsConfig ops_config() {
  ChannelOpsConfig ops{};
  ops.home_channel = 1;
  ops.channel_min = 1;
  ops.channel_max = 13;
  ops.visit_hard_cap_ms = 200;
  ops.drain_budget_ms = 1000;
  ops.evidence_retention_ms = 60000;
  return ops;
}

RadioOperation cutover(std::uint8_t channel) {
  RadioOperation op{};
  op.kind = RadioOperationKind::ChannelCutover;
  op.constraints.channel = channel;
  op.constraints.outage_permitted = true;
  return op;
}

RadioOperation visit(std::uint8_t channel, std::uint32_t duration) {
  RadioOperation op{};
  op.kind = RadioOperationKind::SurveyVisit;
  op.constraints.channel = channel;
  op.constraints.max_duration_ms = duration;
  op.constraints.outage_permitted = true;
  return op;
}

OperationResult outcome(ChannelOperationRunner& runner, OperationToken token) {
  OperationResult r{};
  const bool found = runner.result(token, r);
  CHECK(found);
  return r;
}

void test_runner_rejects() {
  FakeChannelPort port;
  ChannelOperationRunner runner(port, ops_config());
  // P4 supports SurveyVisit + the verified switch primitive only.
  RadioOperation disc{};
  disc.kind = RadioOperationKind::DiscoveryVisit;
  OperationResult r = outcome(runner, runner.request(disc, 0));
  CHECK(r.outcome == OperationOutcome::Rejected);
  CHECK(r.reason == StatusCode::Unsupported);
  // No outage grant -> named refusal, never a silent zero-outage switch.
  RadioOperation denied = visit(6, 150);
  denied.constraints.outage_permitted = false;
  r = outcome(runner, runner.request(denied, 0));
  CHECK(r.outcome == OperationOutcome::Rejected);
  CHECK(r.reason == StatusCode::SurveyRequiresOutagePermission);
  // Bounds: channel range and the 200ms visit cap.
  r = outcome(runner, runner.request(cutover(14), 0));
  CHECK(r.outcome == OperationOutcome::Rejected);
  r = outcome(runner, runner.request(visit(6, 201), 0));
  CHECK(r.outcome == OperationOutcome::Rejected);
  // The arbiter serializes: a second op while busy is refused.
  (void)runner.request(visit(6, 100), 0);
  r = outcome(runner, runner.request(cutover(11), 10));
  CHECK(r.outcome == OperationOutcome::Rejected);
  CHECK(r.reason == StatusCode::Busy);
}

void test_runner_verified_apply() {
  FakeChannelPort port;
  ChannelOperationRunner runner(port, ops_config());
  // Cutover: drain-check -> set -> readback -> peer re-apply -> generation
  // bump -> APPLIED, and the verified channel becomes home.
  const RadioGeneration before = runner.radio_generation();
  const OperationToken token = runner.request(cutover(11), 0);
  runner.poll(10);
  OperationResult r = outcome(runner, token);
  CHECK(r.outcome == OperationOutcome::Applied);
  CHECK(port.set_calls == 1 && port.readback_calls == 1);
  CHECK(port.reapply_calls == 1 && port.committed == 11);
  CHECK(runner.radio_generation().value == before.value + 1);
  CHECK(runner.home_channel() == 11);
}

void test_runner_visit_returns_home() {
  FakeChannelPort port;
  ChannelOperationRunner runner(port, ops_config());
  const OperationToken token = runner.request(visit(6, 150), 0);
  runner.poll(10);
  CHECK(runner.visiting());        // off-channel dwell: home unreceivable
  CHECK(port.committed == 6);
  CHECK(outcome(runner, token).outcome == OperationOutcome::Pending);
  runner.poll(100);                // still inside the bounded visit
  CHECK(runner.visiting());
  runner.poll(200);                // duration exhausted -> verified return
  CHECK(!runner.visiting());
  CHECK(outcome(runner, token).outcome == OperationOutcome::Applied);
  CHECK(port.committed == 1);      // back home, readback-verified
  CHECK(port.set_calls == 2);
  CHECK(runner.radio_generation().value == 2);
}

void test_runner_fail_and_indeterminate() {
  {  // set_channel refused: known not applied -> FAILED, nothing committed.
    FakeChannelPort port;
    port.set_fail_from = 1;
    ChannelOperationRunner runner(port, ops_config());
    const OperationToken token = runner.request(cutover(6), 0);
    runner.poll(10);
    CHECK(outcome(runner, token).outcome == OperationOutcome::Failed);
    CHECK(port.committed_calls == 0);
    CHECK(runner.radio_generation().value == 0);
  }
  {  // Readback mismatch, restore verifies home -> FAILED (known state).
    FakeChannelPort port;
    port.readback_wrong_at = 1;
    ChannelOperationRunner runner(port, ops_config());
    const OperationToken token = runner.request(cutover(6), 0);
    runner.poll(10);
    CHECK(outcome(runner, token).outcome == OperationOutcome::Failed);
    CHECK(port.committed == 1);  // restored and re-verified home
  }
  {  // Readback mismatch AND restore refused -> INDETERMINATE, never
     // merged with success or failure.
    FakeChannelPort port;
    port.readback_wrong_at = 1;
    port.set_fail_from = 2;
    ChannelOperationRunner runner(port, ops_config());
    const OperationToken token = runner.request(cutover(6), 0);
    runner.poll(10);
    const OperationResult r = outcome(runner, token);
    CHECK(r.outcome == OperationOutcome::Indeterminate);
    CHECK(r.reason == StatusCode::DriverResultUnknown);
  }
  {  // Peer rate re-apply fails after a verified switch: the channel DID
     // change, so this is not a clean failure — restore -> FAILED.
    FakeChannelPort port;
    port.reapply_fail_at = 1;
    ChannelOperationRunner runner(port, ops_config());
    const OperationToken token = runner.request(cutover(6), 0);
    runner.poll(10);
    CHECK(outcome(runner, token).outcome == OperationOutcome::Failed);
    CHECK(port.committed == 1);
  }
}

void test_runner_visit_return_retries() {
  {  // A refused return leaves the radio KNOWN off-home: the runner stays
     // in the dwell and retries on the next poll — a transient refusal is
     // absorbed and the visit still lands APPLIED, verified home.
    FakeChannelPort port;
    port.set_fail_at = 2;  // the first return attempt is refused once
    ChannelOperationRunner runner(port, ops_config());
    const OperationToken token = runner.request(visit(6, 100), 0);
    runner.poll(10);
    CHECK(runner.visiting());
    runner.poll(200);   // dwell over; the first return is refused
    CHECK(runner.visiting());  // retry armed, still off-home
    CHECK(outcome(runner, token).outcome == OperationOutcome::Pending);
    runner.poll(201);   // bounded retry: verified return home
    CHECK(!runner.visiting());
    CHECK(outcome(runner, token).outcome == OperationOutcome::Applied);
    CHECK(port.committed == 1);
  }
  {  // Every return refused: the bounded budget exhausts to FAILED —
     // verified still off-home, never a silent park and never a loop.
    FakeChannelPort port;
    port.set_fail_from = 2;
    ChannelOperationRunner runner(port, ops_config());
    const OperationToken token = runner.request(visit(6, 100), 0);
    runner.poll(10);
    runner.poll(200);  // return attempt 1 refused
    runner.poll(201);  // attempt 2 refused
    runner.poll(202);  // attempt 3 refused -> budget exhausted -> FAILED
    const OperationResult r = outcome(runner, token);
    CHECK(r.outcome == OperationOutcome::Failed);
    CHECK(!runner.busy());
    CHECK(port.set_calls == 4);  // visit apply + 3 bounded return attempts
  }
  {  // A return whose readback lies is the uncertain boundary: INDETERMINATE
     // at once — a retry cannot make an unknown side effect more known.
    FakeChannelPort port;
    port.readback_wrong_at = 2;  // the return's readback lies
    ChannelOperationRunner runner(port, ops_config());
    const OperationToken token = runner.request(visit(6, 100), 0);
    runner.poll(10);
    runner.poll(200);
    const OperationResult r = outcome(runner, token);
    CHECK(r.outcome == OperationOutcome::Indeterminate);
    CHECK(r.reason == StatusCode::DriverResultUnknown);
    CHECK(!runner.visiting());
    CHECK(port.set_calls == 2);  // no retry on the unknown boundary
  }
}

void test_runner_drain_fence() {
  // D5-10/X-02: a pending TX straggler is fenced — its missed callback
  // resolves as unknown, never fabricated — then the apply proceeds.
  FakeChannelPort port;
  port.quiesced = false;
  ChannelOperationRunner runner(port, ops_config());
  const OperationToken token = runner.request(visit(6, 100), 0);
  runner.poll(500);
  CHECK(outcome(runner, token).outcome == OperationOutcome::Pending);
  CHECK(port.set_calls == 0);
  runner.poll(1000);  // drain budget exhausted -> fence -> apply
  CHECK(port.fence_calls == 1);
  CHECK(runner.visiting());
  // An op whose overall deadline lands inside the drain fails explicitly.
  FakeChannelPort port2;
  port2.quiesced = false;
  ChannelOperationRunner runner2(port2, ops_config());
  RadioOperation op = visit(6, 100);
  op.deadline_ms = 500;
  const OperationToken token2 = runner2.request(op, 0);
  runner2.poll(500);
  CHECK(outcome(runner2, token2).outcome == OperationOutcome::Failed);
  CHECK(outcome(runner2, token2).reason == StatusCode::Expired);
}

// --- PauseMask (01 §3.3) ---------------------------------------------------------------

void test_pause_mask_keeps_control_flowing() {
  SimWorld world;
  world.add(1);
  world.add(2);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.run(4000);  // let the direct route converge before pausing
  const std::array<std::uint8_t, 4> payload{{5, 6, 7, 8}};
  const std::size_t sights_before = world.net.sights.size();

  // Queue bulk DATA on node 1, then pause DATA dispatch + app admission:
  // the reserved control lane must still flow (01 §3.3).
  MessageId paused_id{};
  CHECK_OK(world.at(1)->send(2, ByteView{payload.data(), payload.size()},
                             SendOptions{}, world.now, paused_id));
  CHECK_OK(world.at(1)->set_pause(PauseReason::SurveyVisit,
                                  pause::kDataDispatch | pause::kAppAdmission));
  // New admission is refused while paused.
  MessageId refused{};
  CHECK(world.at(1)->send(2, ByteView{payload.data(), payload.size()},
                          SendOptions{}, world.now, refused)
            .code == StatusCode::InvalidState);
  // Node 2 (unpaused) sends DATA to node 1: node 1's HOP_ACCEPT reply rides
  // the reserved control lane even though its bulk DATA is held.
  MessageId id2{};
  CHECK_OK(world.at(2)->send(1, ByteView{payload.data(), payload.size()},
                             SendOptions{}, world.now, id2));
  world.run(1500);
  bool accept_from_1 = false;
  bool data_from_1 = false;
  for (std::size_t i = sights_before; i < world.net.sights.size(); ++i) {
    const auto& sight = world.net.sights[i];
    if (sight.from == 1 && sight.type == FrameType::HopAccept) {
      accept_from_1 = true;
    }
    if (sight.from == 1 && sight.type == FrameType::Data) data_from_1 = true;
  }
  // The wire-level oracle: node 1 answered the required accept through the
  // reserved lane while zero DATA frames left its queue.
  CHECK(accept_from_1);
  CHECK(!data_from_1);
  const DeliveryState s1 = world.at(1)->delivery(paused_id).state;
  CHECK(s1 != DeliveryState::Delivered && s1 != DeliveryState::Failed);
  // Clearing the pause resumes the queued work.
  CHECK_OK(world.at(1)->clear_pause(PauseReason::SurveyVisit));
  world.run(2000);
  CHECK(world.obs(2)->messages.size() == 1);
  CHECK(world.at(1)->delivery(paused_id).state == DeliveryState::Delivered);
}

void test_pause_reason_conflicts() {
  SimWorld world;
  world.add(1);
  CHECK_OK(world.at(1)->set_pause(PauseReason::MigrationPrepare, pause::kAll));
  // A second operational reason refuses instead of silently stacking.
  CHECK(world.at(1)->set_pause(PauseReason::Cutover, pause::kAll).code ==
        StatusCode::Conflict);
  // The same reason may extend its mask.
  CHECK_OK(world.at(1)->set_pause(PauseReason::MigrationPrepare,
                                  pause::kBackgroundWork));
  CHECK(world.at(1)->clear_pause(PauseReason::Cutover).code ==
        StatusCode::InvalidState);
  CHECK_OK(world.at(1)->clear_pause(PauseReason::MigrationPrepare));
  CHECK(world.at(1)->pause_reason() == PauseReason::None);
  // set_draining keeps its exact legacy semantics on top of the mask.
  world.at(1)->set_draining(true);
  CHECK(world.at(1)->draining());
  CHECK(world.at(1)->paused(pause::kAppAdmission));
  const std::array<std::uint8_t, 2> payload{{1, 2}};
  MessageId id{};
  CHECK(world.at(1)->send(2, ByteView{payload.data(), payload.size()},
                          SendOptions{}, world.now, id)
            .code == StatusCode::InvalidState);
  world.at(1)->set_draining(false);
  CHECK(!world.at(1)->draining());
}

}  // namespace

int main() {
  test_window_tracking();
  test_independence_requirement();
  test_rssi_only_never_triggers();
  test_unauthenticated_ignored();
  test_mode_gates();
  test_candidate_intersection();
  test_lease_bounds();
  test_revisit_gap();
  test_scheduled_absence();
  test_sample_accounting();
  test_autoguarded_gate_evaluator();
  test_autoguarded_gate_coordinator();
  test_candidate_adoption();
  test_all_candidates_bad_suppression();
  test_single_radio_visit_model();
  test_runner_rejects();
  test_runner_verified_apply();
  test_runner_visit_returns_home();
  test_runner_visit_return_retries();
  test_runner_fail_and_indeterminate();
  test_runner_drain_fence();
  test_pause_mask_keeps_control_flowing();
  test_pause_reason_conflicts();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom channel observe/survey tests passed");
  return 0;
}
