#pragma once

// Portable channel observe + bounded-survey core for the autonomous-mesh
// profile (docs/design/autonomous-mesh/04-channel-migration.md §2-§4,
// contracts.json migration.*). This phase implements ONLY:
//   - the Disabled/Observe/Manual mode state machine (AutoGuarded is a stub
//     gate returning Unsupported — P6),
//   - observation-window judgment: 30s windows, 2 consecutive bad windows
//     plus >=2 independent observation points or an impaired protected
//     critical link before a survey is proposed,
//   - the SurveyLease contract and bounded single-radio visit accounting,
//   - screening evidence (19/20) — never a reliability proof,
//   - candidate adoption evaluation (path-to-Authority first, >=25% worst-
//     cost improvement or a newly met requirement),
//   - the serialized channel-operation runner the radio Owner executes
//     (drain -> explicit set_channel -> readback -> peer rate re-apply ->
//     generation bump -> APPLIED/FAILED/INDETERMINATE).
//
// It does NOT implement plan storage/commit/cutover/recovery (P5) and never
// touches a radio driver: all switching goes through ChannelPort, all time
// through an injected monotonic now_ms.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Pinned parameters (contracts.json migration.*) ----------------------------

namespace migration_const {
constexpr std::uint32_t kBadWindowMs = 30000;          // bad_window_ms
constexpr std::uint32_t kBadWindowsRequired = 2;       // bad_windows_required
constexpr std::uint32_t kIndependentObserversRequired = 2;  // 04 §2
constexpr std::uint32_t kSurveyVisitMaxMs = 200;       // survey_visit_max_ms
constexpr std::uint32_t kSurveyGapMinMs = 30000;       // survey_gap_min_ms
constexpr std::uint8_t kSurveyExchangeMaxPerDirection = 4;   // per visit
constexpr std::uint8_t kSurveySamplesPerDirection = 20;      // screening target
constexpr std::uint8_t kScreeningSuccesses = 19;             // screening_successes
constexpr std::uint32_t kClockUncertaintyMaxMs = 20;   // clock_uncertainty_max_ms
constexpr std::uint32_t kPathImprovementPercent = 25;  // path_improvement_fraction
constexpr std::size_t kMaxCandidates = 4;              // {1,6,11} + slack
constexpr std::size_t kMaxParticipants = 32;
constexpr std::size_t kMaxObservers = 8;               // distinct ids per streak
constexpr std::size_t kMaxAbsenceNotices = 8;          // peers told of a visit
constexpr std::size_t kMaxAbsences = 8;                // tracked absences
constexpr std::size_t kMaxLeases = 4;                  // outstanding survey leases
constexpr std::size_t kMaxPairRecords = 8;             // revisit-gap records
constexpr std::size_t kMaxCriticalRoutes = 8;          // protected endpoints/report
constexpr std::size_t kOperationEvidence = 8;          // retained op results
constexpr std::uint32_t kCandidateMaskDefault =
    (1u << 0) | (1u << 5) | (1u << 10);                // channels {1,6,11}
constexpr std::uint32_t kChannelMaskAll24 = 0x3fffu;   // channels 1..13
}  // namespace migration_const

// --- Modes (04 §1 D5-01) ---------------------------------------------------------

// The four contract modes. AutoGuarded exists in the enum but is a P6 stub:
// selecting it returns Unsupported and never changes behavior.
enum class MigrationMode : std::uint8_t {
  Disabled = 0,
  Observe = 1,
  Manual = 2,
  AutoGuarded = 3,
};

// --- Observe -> survey judgment (04 §2) -----------------------------------------

// One observation point's classified evidence for the current 30s window.
// The caller classifies — this core never trusts raw counters:
//   - `authenticated=false` evidence NEVER counts (unauthenticated reports
//     and self-reports must not move the mesh, 04 §2),
//   - `rssi_low` alone is never sufficient — a low RSSI must not trigger a
//     whole-mesh migration (04 §2),
//   - qualifying evidence is delivery/link impairment or an impaired
//     protected critical link.
struct HealthEvidence {
  NodeId observer{kInvalidNodeId};     // independent observation point id
  bool authenticated{true};
  bool rssi_low{false};
  bool delivery_impaired{false};
  bool critical_link_impaired{false};  // protected critical link impaired
};

enum class AssessVerdict : std::uint8_t {
  Disabled = 0,              // mode Disabled: the coordinator produces no judgment
  Stable = 1,                // no sustained qualifying degradation
  InsufficientEvidence = 2,  // bad windows but too few independent points -> small probe
  SurveyProposed = 3,        // threshold met: bounded survey is justified
};

struct ChannelAssessment {
  AssessVerdict verdict{AssessVerdict::Stable};
  StatusCode reason{StatusCode::Ok};
  bool probe_recommended{false};          // too few points -> small probe (04 §2)
  bool legacy_participant_block{false};   // required legacy participant present
  bool placement_review_advised{false};   // all candidates screened bad (04 §4)
  std::uint32_t consecutive_bad_windows{0};
  std::uint32_t independent_observers{0};
  bool critical_link_impaired{false};
  // Candidate channels = approved RF profile set ∩ participant capability,
  // home channel excluded. Empty when migration is pointless/blocked.
  std::array<std::uint8_t, migration_const::kMaxCandidates> candidates{};
  std::size_t candidate_count{0};
};

// --- Participants / candidate set ------------------------------------------------

// Per-participant capability used to intersect the candidate set
// (04 §2: approved-RF-profile allowed set ∩ participant capability). A required
// participant without migration support blocks the whole proposal —
// it is never silently classed as deferred-sleep (D5-09).
struct ParticipantCapability {
  NodeId node{kInvalidNodeId};
  std::uint32_t channel_mask{0};       // bit (ch-1) for usable 2.4GHz channels
  bool migration_capable{false};
  bool required{false};                // member of the protected/required set
};

// --- SurveyLease (04 §3) ------------------------------------------------------------

// Common monotonic-time mapping between the two visit ends. A remote
// timestamp is never compared to local time without this mapping and its
// uncertainty; above clock_uncertainty_max_ms the lease is refused
// (CLOCK_UNCERTAIN).
struct ClockMapping {
  std::int64_t peer_offset_ms{0};        // peer monotonic - local monotonic estimate
  std::uint32_t uncertainty_ms{0};
};

enum class SurveyDirection : std::uint8_t {
  InitiatorToPeer = 0,
  PeerToInitiator = 1,
};
constexpr std::size_t kSurveyDirectionCount = 2;
constexpr std::size_t survey_direction_index(const SurveyDirection value) noexcept {
  return static_cast<std::size_t>(value);
}

// What the requester asserts about the link that will be cut during the
// visit. A cut without an alternative requires an explicit bounded outage
// permission — without it the request fails SURVEY_REQUIRES_OUTAGE_PERMISSION
// and the result never claims a zero-outage survey.
struct SurveyRequest {
  NodeId peer{kInvalidNodeId};             // the other end of the survey
  std::uint8_t channel{0};                 // candidate channel to visit
  MonotonicMs begin_ms{0};                 // planned visit start
  std::uint32_t duration_ms{0};            // <= kSurveyVisitMaxMs
  ClockMapping mapping{};
  std::uint8_t exchanges_per_direction{0}; // <= kSurveyExchangeMaxPerDirection
  bool outage_permitted{false};
  bool cut_without_alternative{false};
  std::uint16_t protected_cut_id{0};       // 0 = no protected cut
  // Direct peers that lose the link while we are away: each gets an
  // authenticated scheduled-absence notice (04 §3). Caller-supplied; the
  // coordinator records and bounds the list.
  std::array<NodeId, migration_const::kMaxAbsenceNotices> absence_notify{};
  std::size_t absence_notify_count{0};
};

// The bounded single-radio visit contract. Both ends, the candidate channel,
// the LR250 rate (fixed by the profile — no per-channel rate claims), the
// bounded duration, the common time mapping + uncertainty, the return-to-home
// deadline, the packet budget and the revisit gap are recorded here. The
// visit IS a home-channel outage for its whole duration (single radio):
// `home_outage_ms` always equals the duration — zero-outage is never claimed.
struct SurveyLease {
  std::uint32_t lease_id{0};
  NodeId initiator{kInvalidNodeId};
  NodeId peer{kInvalidNodeId};
  std::uint8_t channel{0};
  std::uint8_t home_channel{0};
  MonotonicMs begin_ms{0};
  MonotonicMs end_ms{0};              // = begin + duration: return-to-home bound
  ClockMapping mapping{};
  std::uint8_t exchanges_per_direction_max{0};
  std::uint8_t samples_target_per_direction{0};
  bool outage_permitted{false};
  std::uint16_t protected_cut_id{0};
  MonotonicMs home_outage_ms{0};      // == duration; never zero while visiting
  std::array<NodeId, migration_const::kMaxAbsenceNotices> absence_notify{};
  std::size_t absence_notify_count{0};
  // Per-direction exchange counters consumed by note_survey_sample; bounded
  // by exchanges_per_direction_max.
  std::uint8_t exchanges_used[kSurveyDirectionCount]{};
};

// Per-candidate screening evidence: visit/sample aggregates, never raw
// traces. "19/20" is candidate screening evidence — it is NOT a 99.9%
// reliability proof and is never reported as one (04 §3).
struct ChannelEvidence {
  std::uint8_t channel{0};
  std::uint16_t attempts[kSurveyDirectionCount]{};
  std::uint16_t successes[kSurveyDirectionCount]{};
  std::uint16_t visits{0};
  MonotonicMs last_update_ms{0};
  bool used{false};
};

// --- Candidate adoption (04 §4) ------------------------------------------------------

// One protected endpoint's measured comparison on a candidate. Unmeasured
// routes stay `measured=false` — an unmeasured edge is never treated as
// passable, and sleeping/unobserved endpoints are "unknown", never
// "confirmed connected on the candidate" (04 §4).
struct CriticalRouteReport {
  NodeId protected_endpoint{kInvalidNodeId};
  RouteMetric current_worst{kInfiniteRouteMetric};    // measured on home
  RouteMetric candidate_worst{kInfiniteRouteMetric};  // measured on candidate
  bool measured{false};
  bool reaches_authority{false};       // candidate path to designated GW/Authority
  bool requirement_met_current{true};
  bool requirement_met_candidate{false};
};

struct CandidateReport {
  std::uint8_t channel{0};
  std::array<CriticalRouteReport, migration_const::kMaxCriticalRoutes> routes{};
  std::size_t route_count{0};
};

enum class AdoptionVerdict : std::uint8_t {
  Adopt = 0,
  Reject = 1,
  InsufficientEvidence = 2,
  NoViableCandidate = 3,  // every evaluated candidate rejected -> report, don't loop
};

struct AdoptionDecision {
  AdoptionVerdict verdict{AdoptionVerdict::InsufficientEvidence};
  StatusCode reason{StatusCode::Ok};
  std::uint8_t channel{0};
  bool placement_review_advised{false};  // load-limit/placement review (04 §4)
};

// --- The coordinator ---------------------------------------------------------------

struct ChannelCoordinatorConfig {
  NodeId node{kInvalidNodeId};
  std::uint8_t home_channel{1};
  std::uint32_t candidate_mask{migration_const::kCandidateMaskDefault};
  std::uint32_t bad_window_ms{migration_const::kBadWindowMs};
  std::uint32_t bad_windows_required{migration_const::kBadWindowsRequired};
  std::uint32_t survey_gap_min_ms{migration_const::kSurveyGapMinMs};
  std::uint32_t survey_visit_max_ms{migration_const::kSurveyVisitMaxMs};
  std::uint32_t clock_uncertainty_max_ms{migration_const::kClockUncertaintyMaxMs};
  std::uint8_t exchange_max_per_direction{migration_const::kSurveyExchangeMaxPerDirection};
  std::uint8_t samples_per_direction{migration_const::kSurveySamplesPerDirection};
  std::uint8_t screening_successes{migration_const::kScreeningSuccesses};
};

struct ChannelCoordinatorStats {
  std::uint32_t windows_finalized{0};
  std::uint32_t bad_windows{0};
  std::uint32_t unobserved_windows{0};
  std::uint32_t unauthenticated_ignored{0};
  std::uint32_t leases_issued{0};
  std::uint32_t lease_rejects{0};
  std::uint32_t exchange_budget_rejects{0};
  std::uint32_t protected_cut_conflicts{0};
};

// Observe + bounded-survey planner. One instance per (node, network, radio).
// Not thread-safe: the radio Owner serializes calls. In Observe mode this
// never produces an executable lease — the radio behavior does not change.
class ChannelCoordinator {
 public:
  explicit ChannelCoordinator(const ChannelCoordinatorConfig& config) noexcept;

  // Mode transitions (04 §1). Disabled/Observe/Manual are selectable;
  // AutoGuarded is the P6 stub gate and always returns Unsupported.
  Status set_mode(MigrationMode mode) noexcept;
  MigrationMode mode() const noexcept { return mode_; }
  Status set_home_channel(std::uint8_t channel) noexcept;

  // --- observation input -----------------------------------------------------
  // Feed classified per-window evidence; unauthenticated input is counted
  // and discarded. Window finalization is driven by poll()/assess().
  void note_health_evidence(const HealthEvidence& evidence,
                            MonotonicMs now_ms) noexcept;

  // Participant capability bookkeeping for the candidate intersection.
  Status note_participant(const ParticipantCapability& capability) noexcept;
  Status remove_participant(NodeId node) noexcept;

  // The current observe->survey judgment. Finalizes completed windows first.
  ChannelAssessment assess(MonotonicMs now_ms) noexcept;

  // Candidate channels approved for survey (intersection minus home).
  std::size_t candidates(std::uint8_t* out, std::size_t capacity) const noexcept;
  bool candidate_permitted(std::uint8_t channel) const noexcept;
  bool legacy_participant_block() const noexcept { return legacy_block_; }

  // --- SurveyLease ------------------------------------------------------------
  // Issue a bounded visit lease. Manual mode only — Observe may propose but
  // never moves the radio; Disabled refuses everything. All §3 bounds are
  // enforced here: duration cap, uncertainty cap, exchange budget, the 30s
  // revisit gap, protected-cut exclusivity and outage permission.
  Status request_survey_lease(const SurveyRequest& request, MonotonicMs now_ms,
                              SurveyLease& out) noexcept;
  // Close a lease at/after its return-to-home bound (idempotent).
  Status complete_survey(std::uint32_t lease_id, MonotonicMs now_ms) noexcept;
  // An authenticated scheduled-absence notice received for another node
  // (e.g. the survey counterpart announces its own visit). Protected cuts
  // must not be simultaneously absent.
  Status note_absence(NodeId node, std::uint16_t protected_cut_id,
                      MonotonicMs until_ms, MonotonicMs now_ms) noexcept;
  bool node_absent(NodeId node, MonotonicMs now_ms) const noexcept;

  // Record one survey exchange sample against an open lease, bounded by the
  // lease's per-direction exchange budget.
  Status note_survey_sample(std::uint32_t lease_id, SurveyDirection direction,
                            bool success, MonotonicMs now_ms) noexcept;

  // Per-candidate screening evidence. screening_passed() is true only when
  // every direction reached samples_per_direction attempts with at least
  // screening_successes successes — and even then it is candidate screening,
  // never a reliability proof.
  bool screening_evidence(std::uint8_t channel, ChannelEvidence& out) const noexcept;
  bool screening_passed(std::uint8_t channel) const noexcept;

  // --- candidate adoption -------------------------------------------------------
  // Evaluate one candidate's measured route reports (04 §4): every required
  // route must be measured and must reach the designated Gateway/Authority;
  // adoption needs a >=25% improvement in the worst critical-route cost or a
  // requirement the current channel fails that the candidate meets.
  AdoptionDecision evaluate_candidate(const CandidateReport& report) const noexcept;
  // Evaluate a batch; the first Adopt wins. When every candidate is
  // rejected the verdict is NoViableCandidate, load-limit/placement review
  // is advised and further survey proposals are suppressed until new
  // screening evidence arrives (no migration loop, 04 §4).
  AdoptionDecision evaluate_candidates(const CandidateReport* reports,
                                       std::size_t count,
                                       MonotonicMs now_ms) noexcept;
  // True while an all-candidates-bad verdict is still fresh (no new
  // screening evidence since).
  bool all_candidates_bad() const noexcept;

  // Window finalization, lease/absence expiry.
  void poll(MonotonicMs now_ms) noexcept;

  const ChannelCoordinatorStats& stats() const noexcept { return stats_; }
  std::uint32_t consecutive_bad_windows() const noexcept { return consecutive_bad_; }
  std::size_t active_leases() const noexcept { return leases_.size(); }
  bool lease_of(std::uint32_t lease_id, SurveyLease& out) const noexcept;

 private:
  static constexpr std::uint64_t kWindowUninitialized = ~0ULL;

  struct WindowState {
    std::array<NodeId, migration_const::kMaxObservers> observers{};
    std::size_t observer_count{0};
    std::uint32_t observations{0};
    bool qualifying{false};
    bool critical{false};
    void reset() noexcept { *this = WindowState{}; }
  };

  struct Participant {
    NodeId node{kInvalidNodeId};
    std::uint32_t channel_mask{0};
    bool migration_capable{false};
    bool required{false};
  };

  struct Absence {
    NodeId node{kInvalidNodeId};
    std::uint16_t protected_cut_id{0};
    MonotonicMs until_ms{0};
    std::uint32_t lease_id{0};  // 0 = external notice
  };

  struct PairVisit {
    NodeId a{kInvalidNodeId};
    NodeId b{kInvalidNodeId};
    MonotonicMs last_end_ms{0};
  };

  void advance_windows(MonotonicMs now_ms) noexcept;
  void finalize_window(const WindowState& window) noexcept;
  WindowState& current_window() noexcept { return window_; }
  std::uint32_t effective_mask() const noexcept;
  Participant* find_participant(NodeId node) noexcept;
  const Participant* find_participant(NodeId node) const noexcept;
  ChannelEvidence* evidence_for(std::uint8_t channel) noexcept;
  const ChannelEvidence* evidence_for(std::uint8_t channel) const noexcept;
  Absence* find_absence(NodeId node, std::uint32_t lease_id) noexcept;
  bool cut_absent(std::uint16_t protected_cut_id, MonotonicMs at_ms,
                  std::uint32_t ignore_lease) const noexcept;
  PairVisit* pair_record(NodeId a, NodeId b, bool create) noexcept;
  void expire_leases(MonotonicMs now_ms) noexcept;
  void expire_absences(MonotonicMs now_ms) noexcept;

  ChannelCoordinatorConfig config_{};
  MigrationMode mode_{MigrationMode::Observe};
  ChannelCoordinatorStats stats_{};
  std::uint64_t window_index_{kWindowUninitialized};
  WindowState window_{};
  std::uint32_t consecutive_bad_{0};
  // Independent observation points accumulated across the current bad
  // streak; cleared when a good/unobserved window breaks it.
  std::array<NodeId, migration_const::kMaxObservers> streak_observers_{};
  std::size_t streak_observer_count_{0};
  bool streak_critical_{false};
  bool last_window_unobserved_{false};
  FixedPool<Participant, migration_const::kMaxParticipants> participants_{};
  bool legacy_block_{false};
  FixedPool<SurveyLease, migration_const::kMaxLeases> leases_{};
  FixedPool<Absence, migration_const::kMaxAbsences> absences_{};
  FixedPool<PairVisit, migration_const::kMaxPairRecords> pair_visits_{};
  std::array<ChannelEvidence, migration_const::kMaxCandidates> evidence_{};
  std::uint32_t next_lease_id_{1};
  MonotonicMs last_visit_end_{0};
  // All-candidates-bad suppression (04 §4): latched when every evaluated
  // candidate rejected; released when new screening evidence arrives
  // (note_survey_sample bumps evidence_epoch_).
  bool all_bad_reported_{false};
  std::uint32_t evidence_epoch_{0};
  std::uint32_t suppressed_epoch_{0};
};

// --- Channel operation runner (04 §3, §8; P0 arbiter contract) ----------------------

// The driver surface the radio Owner implements. Ordering is owned by
// ChannelOperationRunner; a port must never reorder these steps.
class ChannelPort {
 public:
  virtual ~ChannelPort() = default;
  // True when no TX completion can still be in flight with the driver.
  virtual bool tx_quiesced() const noexcept = 0;
  // Explicit channel switch. Must NOT be called directly by applications —
  // the runner is the only caller.
  virtual Status set_channel(std::uint8_t channel) noexcept = 0;
  // Read the driver channel back; the apply is verified, never assumed.
  virtual Status readback_channel(std::uint8_t& channel) noexcept = 0;
  // Re-apply per-peer radio settings (LR250 on every registered peer,
  // broadcast included) after a verified switch. Peer channel follows the
  // current-channel-zero policy and needs no rewrite (04 §8).
  virtual Status reapply_peer_radio() noexcept = 0;
  // Fence an outstanding TX whose completion may never arrive: it resolves
  // as unknown (watchdog), never as a fabricated success or failure (X-02).
  virtual void fence_pending_tx() noexcept = 0;
  // Record the verified channel as committed state — only after readback.
  virtual void committed_channel(std::uint8_t channel) noexcept = 0;
};

struct ChannelOpsConfig {
  std::uint8_t home_channel{1};
  std::uint8_t channel_min{1};
  std::uint8_t channel_max{13};
  std::uint32_t visit_hard_cap_ms{migration_const::kSurveyVisitMaxMs};
  std::uint32_t drain_budget_ms{1000};       // callback-fence bound
  std::uint32_t evidence_retention_ms{60000};
};

// Serialized radio-operation executor (01 §3.3, 04 §3/§8). One operation at
// a time; every apply is set_channel -> readback verify -> peer rate
// re-apply -> committed_channel -> RadioGeneration bump, in that order. A
// SurveyVisit additionally dwells off-channel and always returns home
// inside its bounded duration; APPLIED for a visit means the return was
// readback-verified. Result semantics follow the P0 contract:
//   REJECTED      - refused before any side effect,
//   FAILED        - started, known not to have taken effect (verified home),
//   INDETERMINATE - side effects unknown (a restore could not be verified);
//                   never merged with success or failure.
class ChannelOperationRunner {
 public:
  ChannelOperationRunner(ChannelPort& port, const ChannelOpsConfig& config) noexcept;

  // Submit an operation. Always returns a fresh token; pre-rejected
  // requests are recorded as REJECTED results against it.
  OperationToken request(const RadioOperation& op, MonotonicMs now_ms) noexcept;
  // Advance the serialized operation: drain wait -> apply -> visit dwell ->
  // return home. Drives nothing while Idle.
  void poll(MonotonicMs now_ms) noexcept;
  bool result(OperationToken token, OperationResult& out) const noexcept;
  bool busy() const noexcept { return phase_ != Phase::Idle; }
  // In the off-channel dwell: the home channel is physically unreceivable
  // (single radio). The Owner gates home-bound TX on this.
  bool visiting() const noexcept { return phase_ == Phase::VisitDwell; }
  std::uint8_t home_channel() const noexcept { return home_channel_; }
  std::uint8_t committed_channel() const noexcept { return committed_channel_; }
  // Bumped on every verified switch; stale callbacks from a previous
  // configuration are detectable against it (X-02).
  RadioGeneration radio_generation() const noexcept { return generation_; }
  Status set_home_channel(std::uint8_t channel) noexcept;

 private:
  enum class Phase : std::uint8_t { Idle = 0, WaitDrain = 1, VisitDwell = 2 };

  // set -> readback -> reapply -> commit -> generation bump. On a post-set
  // failure the port state is uncertain; the caller decides restore.
  Status apply_channel(std::uint8_t target) noexcept;
  // After a failed apply, attempt a verified return to the home channel.
  // Restored -> FAILED (known not in effect); unrestored -> INDETERMINATE.
  void fail_or_unknown(const Status& cause, MonotonicMs now_ms) noexcept;
  void record(OperationOutcome outcome, StatusCode reason,
              MonotonicMs now_ms) noexcept;
  OperationToken issue(OperationOutcome outcome, StatusCode reason,
                       MonotonicMs now_ms) noexcept;

  ChannelPort& port_;
  ChannelOpsConfig config_{};
  Phase phase_{Phase::Idle};
  RadioOperation active_{};
  OperationToken active_token_{kInvalidOperationToken};
  MonotonicMs drain_deadline_ms_{0};
  MonotonicMs visit_end_ms_{0};
  std::uint8_t home_channel_{1};
  std::uint8_t committed_channel_{1};
  RadioGeneration generation_{};
  std::uint64_t next_token_{1};
  FixedQueue<OperationResult, migration_const::kOperationEvidence> evidence_{};
};

}  // namespace routeloom
