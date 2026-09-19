#pragma once

// Portable channel-migration engine: plan object, verified-commit binding,
// the participant plan state machine, clock/cutover discipline and the
// helper/scout recovery schedule (docs/design/autonomous-mesh/
// 04-channel-migration.md §5-§10, contracts.json migration.*).
//
// This phase (P5a) is ESP-free portable logic. It NEVER claims an atomic
// all-node cutover, never performs a unilateral rollback and never claims a
// zero-outage switch. Safety = verified-commit monotonicity; liveness holds
// only under the explicit loss/clock/coverage/transfer assumptions the plan
// carries (04 §9.3). The radio Owner + driver wiring is P5b: all switching
// goes through the injected ChannelOperationRunner, all persistence through
// PlanStorage, all authority cryptography through CommitSignatureVerifier.
//
// Contract invariants encoded here:
//   - A stored plan blob is PREPARED only; a blob alone NEVER switches.
//   - A verified Authority commit that references the blob hash is the only
//     path to COMMITTED; VerifiedAuthorityPlan cannot be fabricated because
//     the sole issuing path runs a real signature verification.
//   - committed_epoch / active_epoch / visit_channel are distinct; epochs
//     never rewind, and the channel is never restored unconditionally from
//     a sleep image — the verified plan always wins.
//   - Rollback is just another plan: it needs a NEW authority operation and
//     a NEW channel epoch. There is no unilateral-rollback entry point.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/authority.hpp"
#include "routeloom/autonomy.hpp"
#include "routeloom/channel_plan.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Pinned plan/commit/recovery parameters (contracts.json migration.*) -----

namespace migration_const {
constexpr std::uint32_t kPrepareTimeoutMs = 30000;       // prepare_timeout_ms
constexpr std::uint32_t kCommitLeadFloorMs = 5000;       // commit_lead_floor_ms
constexpr std::uint32_t kCommitLeadRttMultiplier = 4;    // commit_lead_rtt_multiplier
constexpr std::uint32_t kGuardFloorMs = 100;             // guard_floor_ms
constexpr std::uint32_t kGuardUncertaintyMultiplier = 4; // guard_uncertainty_multiplier
constexpr std::uint32_t kVerifyMs = 30000;               // verify_ms
constexpr std::uint32_t kHelperVisitPeriodMs = 5000;     // helper_visit_period_ms
constexpr std::uint32_t kHelperDwellMs = 800;            // helper_old_channel_dwell_ms
constexpr std::uint32_t kHelperBudgetMs = 180000;        // helper_total_budget_ms
constexpr std::uint32_t kCooldownMs = 600000;            // cooldown_ms
constexpr std::uint8_t kAutomaticRollbacksMax = 1;       // automatic_rollbacks_per_plan_max
constexpr std::size_t kMaxHelpers = 8;                   // helper set bound
constexpr std::size_t kPlanBlobMax = 384;                // encoded plan bound
constexpr std::size_t kSnapshotMax = 544;                // encoded snapshot bound
constexpr std::size_t kCommitRecordSize = 224;           // durable commit record (v2)
constexpr std::size_t kActiveRecordSize = 56;            // durable active record
constexpr std::size_t kMaxCommitSignature = 64;          // signature evidence bound
}  // namespace migration_const

// --- The plan object (04 §6) ---------------------------------------------------

// The committed recovery schedule carried INSIDE the plan (04 §9.2): the
// helper set, the old-channel visit period/dwell, the bounded window and
// the transferable management-object bound. A helper visit is a bounded
// migration-time outage budget, distinct from the 200ms survey cap.
struct HelperSchedule {
  std::array<NodeId, migration_const::kMaxHelpers> helpers{};
  std::size_t helper_count{0};
  std::uint32_t visit_period_ms{0};     // e.g. 5000
  std::uint32_t dwell_ms{0};            // e.g. 800
  MonotonicMs window_begin_ms{0};       // authority-domain schedule start
  MonotonicMs window_end_ms{0};         // authority-domain budget bound
  std::uint16_t object_bytes_max{0};    // transferable management object bound
  bool present{false};                  // requires_recovery_plan gate input
};

// The channel-migration plan. The switch-time reference is the Authority
// boot/session plus a monotonic-clock mapping — never UTC (04 §6). All
// fields are bound into the blob digest; the Authority operation references
// that digest, so the operation digest transitively binds every field.
struct MigrationPlan {
  NetworkId network{0};
  NodeId authority{kInvalidNodeId};
  std::uint32_t authority_generation{0};
  std::uint64_t operation_sequence{0};
  Digest256 previous_state_hash{};
  ChannelEpoch old_epoch{};
  ChannelEpoch new_epoch{};
  std::uint8_t old_channel{0};
  std::uint8_t new_channel{0};
  std::uint32_t participant_capability_mask{0};
  Digest256 required_participant_digest{};
  Digest256 candidate_evidence_digest{};
  std::uint64_t authority_session{0};
  MonotonicMs switch_reference_ms{0};   // authority-domain monotonic
  ClockMapping mapping{};               // authority->local clock mapping
  MonotonicMs expiry_ms{0};             // authority-domain validity bound
  std::uint32_t guard_ms{0};
  HelperSchedule recovery{};
  std::uint32_t protected_services_mask{0};
  std::uint32_t max_outage_ms{0};
};

// Canonical plan-blob codec. The byte layout is internal to the plan object
// (carried as a ControlObject payload); it is deterministic so the blob
// digest is stable. plan_digest is a deterministic binding like
// bind_operation_payload — NOT a cryptographic hash; a production security
// profile replaces it with the negotiated suite hash over the same bytes.
constexpr std::uint8_t kMigrationPlanVersion = 1;
Status plan_encode(const MigrationPlan& plan, MutableByteView target,
                   std::size_t& out_size) noexcept;
Status plan_decode(ByteView encoded, MigrationPlan& out) noexcept;
Digest256 plan_digest(ByteView encoded_plan) noexcept;

// --- Clock / timing bounds (04 §8) ----------------------------------------------

// guard = max(100ms, 4*uncertainty + measured_switch_bound). The measured
// bound is a deployment input — never assumed.
constexpr std::uint32_t required_guard_ms(
    const std::uint32_t uncertainty_ms,
    const std::uint32_t measured_switch_bound_ms) noexcept {
  const std::uint64_t scaled =
      static_cast<std::uint64_t>(migration_const::kGuardUncertaintyMultiplier) *
          uncertainty_ms +
      measured_switch_bound_ms;
  return scaled > migration_const::kGuardFloorMs
             ? static_cast<std::uint32_t>(scaled)
             : migration_const::kGuardFloorMs;
}

// COMMIT distribution lead = max(5s, 4*management_RTT_P99,
// control_budget_delivery_bound). "5s is always enough" is never assumed
// (04 §8): the largest bound wins.
constexpr std::uint32_t required_commit_lead_ms(
    const std::uint32_t management_rtt_p99_ms,
    const std::uint32_t control_delivery_bound_ms) noexcept {
  const std::uint64_t scaled =
      static_cast<std::uint64_t>(migration_const::kCommitLeadRttMultiplier) *
      management_rtt_p99_ms;
  std::uint64_t lead = migration_const::kCommitLeadFloorMs;
  if (scaled > lead) lead = scaled;
  if (control_delivery_bound_ms > lead) lead = control_delivery_bound_ms;
  return static_cast<std::uint32_t>(lead);
}

// Conditional recovery bound (04 §9.3): recovery is claimable only while a
// helper edge remains on old or new channel, responses arrive inside the
// visit count, the transfer fits and clock error stays bounded.
//   H * ((loss_windows + 1) * visit_period + transfer_bound) + margin
// H is the maximum edge count a recovery wave crosses — deliberately NOT
// tied to the DATA hop limit.
constexpr std::uint64_t recovery_bound_ms(const std::uint32_t hops,
                                          const std::uint32_t loss_windows,
                                          const std::uint32_t visit_period_ms,
                                          const std::uint32_t transfer_bound_ms,
                                          const std::uint32_t margin_ms) noexcept {
  return static_cast<std::uint64_t>(hops) *
             ((static_cast<std::uint64_t>(loss_windows) + 1ULL) *
                  visit_period_ms +
              transfer_bound_ms) +
         margin_ms;
}

// --- Verified-commit binding (04 §5) ---------------------------------------------

// The authority-signature verification surface. An implementation MUST run
// a real cryptographic check (signature/MAC over the canonical commit
// binding) plus identity policy — an unconditional Ok is a contract
// violation, and neither a fixed `cryptographic_signature_verified=true`
// pass nor the non-crypto bind_operation_payload() is a substitute (04 §5).
// A production deployment installs the qualified profile provider; a
// development deployment installs an explicitly EXPERIMENTAL provider and
// the result is surfaced as such (never advertised as production).
class CommitSignatureVerifier {
 public:
  virtual ~CommitSignatureVerifier() = default;
  virtual bool ready() const noexcept = 0;
  // Deliberately Development by default so a provider cannot claim
  // production assurance by omission.
  virtual SecurityProfile security_profile() const noexcept {
    return SecurityProfile::Development;
  }
  // Verify the authority signature over (operation fields, plan_hash,
  // new_epoch) — the committed epoch is part of the signed input so the
  // evidence's epoch field cannot be rewritten without breaking the MAC.
  virtual Status verify_commit(const AuthorityOperation& operation,
                               const Digest256& plan_hash,
                               ChannelEpoch new_epoch,
                               ByteView signature) noexcept = 0;
  // Verify the authority signature over a recovery snapshot body. Signed
  // recovery material keeps verifying while the authority is stopped —
  // verification is local cryptography, not an authority round-trip.
  virtual Status verify_snapshot(ByteView snapshot, ByteView signature) noexcept = 0;
};

// Proof that one specific (operation, plan blob hash, epoch) triple passed
// real verification + scope policy. Only MigrationAuthority can mint a
// valid instance — the constructor surface cannot fabricate one, so a
// "verified" flag arriving from anywhere else is simply false.
class VerifiedAuthorityPlan {
 public:
  VerifiedAuthorityPlan() = default;
  bool valid() const noexcept { return valid_; }
  const Digest256& plan_hash() const noexcept { return plan_hash_; }
  const Digest256& operation_hash() const noexcept { return operation_hash_; }
  std::uint64_t sequence() const noexcept { return sequence_; }
  ChannelEpoch new_epoch() const noexcept { return new_epoch_; }
  // True when the verifying provider is EXPERIMENTAL (development profile):
  // the commit is real but is never a production-qualification claim.
  bool experimental() const noexcept { return experimental_; }

 private:
  friend class MigrationAuthority;
  static VerifiedAuthorityPlan issue(const Digest256& plan_hash,
                                     const AuthorityOperation& operation,
                                     ChannelEpoch new_epoch,
                                     bool experimental) noexcept {
    VerifiedAuthorityPlan out{};
    out.plan_hash_ = plan_hash;
    out.operation_hash_ = operation.operation_hash;
    out.sequence_ = operation.sequence;
    out.new_epoch_ = new_epoch;
    out.experimental_ = experimental;
    out.valid_ = true;
    return out;
  }

  Digest256 plan_hash_{};
  Digest256 operation_hash_{};
  std::uint64_t sequence_{0};
  ChannelEpoch new_epoch_{};
  bool experimental_{false};
  bool valid_{false};
};

struct MigrationAuthorityConfig {
  NetworkId network{0};
  NodeId authority{kInvalidNodeId};
  std::uint32_t cooldown_ms{migration_const::kCooldownMs};
  std::uint8_t automatic_rollbacks_max{migration_const::kAutomaticRollbacksMax};
};

// The single explicit Authority side (04 §5). A gateway gains no approval
// right by being a gateway; only this configured identity issues verified
// commits. `ledger` may be nullptr for a participant-side verify-only
// instance — it can re-verify signatures and snapshots but can never mint
// a new ledger commit.
class MigrationAuthority {
 public:
  MigrationAuthority(const MigrationAuthorityConfig& config,
                     CommitSignatureVerifier& verifier,
                     SingleAuthority* ledger) noexcept;

  // Issuer path: verify the authority's signature evidence with the real
  // verifier, ledger-commit the operation (the ledger's cryptographic flag
  // is fed ONLY by the verification result — never a constant), then mint
  // the VerifiedAuthorityPlan participants will accept.
  //   - plan_digest(blob) must equal the hash the operation binds,
  //   - the operation kind must be ChannelMigration, scope must match,
  //   - a stopped authority issues NO new commits (D5-04),
  //   - a rollback commit additionally needs a fresh epoch and consumes the
  //     single automatic-rollback credit of the last failed plan.
  Status commit_plan(const MigrationPlan& plan, ByteView plan_blob,
                     const AuthorityOperation& operation,
                     ByteView signature,
                     const Digest256& resulting_state_hash,
                     bool is_rollback, MonotonicMs now_ms,
                     VerifiedAuthorityPlan& out) noexcept;

  // Participant-side re-verification of received commit evidence: the same
  // real signature check plus network/authority/kind/digest binding policy.
  // Works while the authority is unreachable — signed material stays
  // distributable (D5-04).
  Status verify_commit(const AuthorityOperation& operation,
                       const Digest256& plan_hash, ChannelEpoch new_epoch,
                       ByteView signature, VerifiedAuthorityPlan& out) noexcept;

  // Signed recovery-snapshot check (04 §9.2). Same rule: real verification
  // only; a stopped authority does not block already-signed material.
  Status verify_snapshot(ByteView snapshot, ByteView signature) noexcept;

  // Mark the authority stopped/available. While stopped: no NEW commits;
  // already-committed plans and signed recovery material keep executing.
  void set_available(bool available) noexcept { available_ = available; }
  bool available() const noexcept { return available_; }
  // True only when the installed verifier is a real ready implementation —
  // the AutoGuarded gate's "verified authority path" needs actual signature
  // verification, not just an object that exists.
  bool verifier_ready() const noexcept { return verifier_.ready(); }

  // Terminal outcome feed: latches the inter-plan cooldown and grants the
  // failed plan its single automatic-rollback credit (04 §10).
  void note_plan_terminal(bool succeeded, MonotonicMs now_ms) noexcept;
  bool cooldown_active(MonotonicMs now_ms) const noexcept {
    return now_ms < cooldown_until_ms_;
  }
  MonotonicMs cooldown_until() const noexcept { return cooldown_until_ms_; }
  ChannelEpoch last_committed_epoch() const noexcept { return last_epoch_; }
  bool experimental_provider() const noexcept {
    return verifier_.security_profile() != SecurityProfile::Production;
  }

 private:
  Status check_scope(const AuthorityOperation& operation,
                     const Digest256& plan_hash) const noexcept;

  MigrationAuthorityConfig config_{};
  CommitSignatureVerifier& verifier_;
  SingleAuthority* ledger_;
  bool available_{true};
  MonotonicMs cooldown_until_ms_{0};
  std::uint8_t rollback_credit_{0};
  ChannelEpoch last_epoch_{};
};

// --- Participant-set gating (04 §7, D5-09) ----------------------------------------

// What the coordinator knows about one required-set member at COMMIT time.
// READY is accepted evidence of storage + capability + clock + drain budget
// + a recovery procedure — never a bare "it answered once".
struct ParticipantReadiness {
  NodeId node{kInvalidNodeId};
  Digest256 plan_hash{};             // plan the READY report was bound to
  bool required{false};
  bool answered{false};              // responded inside the prepare window
  bool ready{false};                 // full READY evidence accepted
  bool migration_capable{true};
  bool sleep_lease_valid{false};     // valid availability lease held
  bool rediscovery_capable{false};   // reachable via the recovery schedule
};

struct RequiredSetVerdict {
  bool commit_permitted{false};
  StatusCode reason{StatusCode::Ok};
  NodeId blocker{kInvalidNodeId};
  std::size_t ready_count{0};
  std::size_t deferred_count{0};     // sleep-deferred set (lease+rediscovery)
};

// Required set = awake relays/gateway, cuts serving protected connectivity
// and a path to the Authority. An UNANSWERED required node is never
// conveniently reclassed as asleep: only a valid availability lease AND
// rediscovery capability earn the deferred set. A legacy required node
// blocks auto migration outright (D5-09); a deferred set with no committed
// recovery schedule also blocks (requires_recovery_plan).
RequiredSetVerdict evaluate_required_set(
    const ParticipantReadiness* participants, std::size_t count,
    bool recovery_schedule_present) noexcept;

// --- Durable plan storage (04 §6) -------------------------------------------------

// Power-cut-safe persistence for the participant side. Three distinct
// durable things (04 §6/D5-06):
//   - hash-addressed plan blobs (stored+readback-verified = PREPARED only),
//   - the commit record (verified commit evidence -> COMMITTED),
//   - the active record (written only after driver apply + readback).
// Implementations must tolerate power loss at any boundary, never fabricate
// a record that was not committed, and never erase/reformat on error.
class PlanStorage {
 public:
  virtual ~PlanStorage() = default;
  // Hash-addressed blob region. write then read must return identical bytes.
  virtual Status write_blob(const Digest256& hash, ByteView blob) noexcept = 0;
  virtual Status read_blob(const Digest256& hash, MutableByteView target,
                           std::size_t& out_size) noexcept = 0;
  virtual Status drop_blob(const Digest256& hash) noexcept = 0;
  // The durable commit record (kCommitRecordSize bytes).
  virtual Status write_commit_record(ByteView record) noexcept = 0;
  virtual Status read_commit_record(MutableByteView target,
                                    std::size_t& out_size) noexcept = 0;
  // The durable active record (kActiveRecordSize bytes).
  virtual Status write_active_record(ByteView record) noexcept = 0;
  virtual Status read_active_record(MutableByteView target,
                                    std::size_t& out_size) noexcept = 0;
};

// What a participant durably commits: the verified operation, the blob hash
// it references, the new channel epoch and — when the commit arrived through
// signed commit evidence — the authority signature that minted it. Keeping
// the signature lets a helper re-emit verified commit evidence to stranded
// nodes after a restart instead of silently losing that serving capability
// (04 §9.2). A record adopted from a recovery snapshot carries no commit
// signature: the snapshot signature signs different bytes and is never
// relabelled as commit evidence.
struct CommitRecord {
  AuthorityOperation operation{};
  Digest256 plan_hash{};
  ChannelEpoch new_epoch{};
  std::array<std::uint8_t, migration_const::kMaxCommitSignature> signature{};
  std::uint8_t signature_size{0};
  bool present{false};
};

// What a participant durably applies: written only after the driver switch
// readback verifies. Losing it after apply re-applies idempotently from the
// stored commit (04 §6); it never downgrades an epoch.
struct ActiveRecord {
  ChannelEpoch epoch{};
  std::uint8_t channel{0};
  Digest256 plan_hash{};
  bool present{false};
};

Status commit_record_encode(const CommitRecord& record, MutableByteView target,
                            std::size_t& out_size) noexcept;
Status commit_record_decode(ByteView encoded, CommitRecord& out) noexcept;
Status active_record_encode(const ActiveRecord& record, MutableByteView target,
                            std::size_t& out_size) noexcept;
Status active_record_decode(ByteView encoded, ActiveRecord& out) noexcept;

// --- Signed recovery snapshot (04 §9.2) ---------------------------------------------

// The signed material a helper carries to stranded nodes: the latest commit
// evidence plus the full plan blob, so a node that skipped multiple epochs
// always converges on the NEWEST signed state — it never chases only the
// previous generation (D5-07).
struct RecoverySnapshot {
  AuthorityOperation operation{};
  Digest256 plan_hash{};
  std::array<std::uint8_t, migration_const::kPlanBlobMax> plan_blob{};
  std::size_t plan_blob_size{0};
};

constexpr std::uint8_t kRecoverySnapshotVersion = 1;
Status snapshot_encode(const RecoverySnapshot& snapshot, MutableByteView target,
                       std::size_t& out_size) noexcept;
Status snapshot_decode(ByteView encoded, RecoverySnapshot& out) noexcept;

// --- The participant engine (04 §7-§9) ----------------------------------------------

// Plan lifecycle states (04 §7). ASSESS/SURVEY are bookkeeping owned by the
// ChannelCoordinator; the engine records them so the full §7 machine is
// represented. ABORTED is reachable only pre-commit; RECOVERY_REQUIRED is
// the terminal state when the explicit recovery assumptions break.
enum class ParticipantPhase : std::uint8_t {
  Stable = 0,
  Assess = 1,
  Survey = 2,
  Preparing = 3,
  Committed = 4,
  Switching = 5,
  Verifying = 6,
  Recovering = 7,
  Aborted = 8,
  RecoveryRequired = 9,
};

// Deployment measurements the caller must supply — the engine never guesses
// them (04 §8). Unknown bounds stay unknown; a plan that cannot fit is
// rejected rather than silently shrunk.
struct PlanMeasurements {
  std::uint32_t management_rtt_p99_ms{0};
  std::uint32_t control_delivery_bound_ms{0};
  std::uint32_t required_transfer_ms{0};      // prepare-phase transfer need
  std::uint32_t measured_switch_bound_ms{0};  // local switch bound, measured
};

struct MigrationParticipantConfig {
  NodeId node{kInvalidNodeId};
  NetworkId network{0};
  NodeId authority{kInvalidNodeId};            // the single explicit Authority
  std::uint8_t home_channel{1};
  std::uint32_t prepare_timeout_ms{migration_const::kPrepareTimeoutMs};
  std::uint32_t verify_ms{migration_const::kVerifyMs};
  std::uint32_t clock_uncertainty_max_ms{migration_const::kClockUncertaintyMaxMs};
  std::uint32_t cooldown_ms{migration_const::kCooldownMs};
};

// Owner wiring points the portable engine drives. P5b maps them to the
// pause mask, scheduler and observation stores; the engine owns the ORDER.
class MigrationHooks {
 public:
  virtual ~MigrationHooks() = default;
  // DATA admission/intake hold. Set before the drain begins; cleared only
  // after the switch readback verifies (or after a verified home restore).
  // The reserved control lane is never held (pause mask semantics, 04 §8).
  virtual void hold_data(bool held) noexcept = 0;
  // Observation/clock generation update after a verified switch so stale
  // pre-cutover mappings/observations cannot be attributed to the new
  // configuration (X-02). Called BEFORE hold_data(false).
  virtual void note_cutover_generation(std::uint32_t radio_generation) noexcept = 0;
  // Helper visit boundary on the OLD channel (bookkeeping only; the visit
  // itself runs through the runner). A helper never becomes a permanent
  // second channel (04 §9.2).
  virtual void helper_visit(bool active, std::uint8_t old_channel) noexcept = 0;
};

struct MigrationStats {
  std::uint32_t plans_prepared{0};
  std::uint32_t plans_rejected{0};
  std::uint32_t commits{0};
  std::uint32_t commit_rejects{0};
  std::uint32_t cutovers_applied{0};
  std::uint32_t aborts{0};
  std::uint32_t snapshots_accepted{0};
  std::uint32_t snapshots_rejected{0};
  std::uint32_t helper_visits{0};
  std::uint32_t recovery_required{0};
  std::uint32_t blob_refetches{0};
  std::uint32_t verify_passed{0};   // VERIFY closed on real link evidence
  std::uint32_t verify_failed{0};   // VERIFY window expired with no traffic
};

// One participant's plan state machine. Not thread-safe: the radio Owner
// serializes calls. Drives the §7 machine, the §8 clock/cutover discipline
// and the §9 helper/scout recovery schedule.
class MigrationParticipant {
 public:
  MigrationParticipant(const MigrationParticipantConfig& config,
                       PlanStorage& storage, MigrationAuthority& authority,
                       ChannelOperationRunner& runner,
                       MigrationHooks* hooks) noexcept;

  ParticipantPhase phase() const noexcept { return phase_; }
  ChannelEpoch committed_epoch() const noexcept { return committed_epoch_; }
  ChannelEpoch active_epoch() const noexcept { return active_epoch_; }
  std::uint8_t active_channel() const noexcept { return active_channel_; }
  bool clock_valid() const noexcept { return clock_valid_; }
  // The armed mapping's uncertainty. An unarmed clock reports ABOVE the
  // configured bound, never zero — unknown time is not "zero error"
  // (unknown_time_is_zero=false), so the AutoGuarded clock gate fails on it.
  std::uint32_t clock_uncertainty_ms() const noexcept {
    return clock_valid_ ? clock_mapping_.uncertainty_ms
                        : config_.clock_uncertainty_max_ms + 1;
  }
  // The plan-terminal cooldown latch (04 §10) this participant holds.
  bool cooldown_active(MonotonicMs now_ms) const noexcept {
    return now_ms < cooldown_until_ms_;
  }
  // The armed authority mapping — meaningful only while clock_valid().
  // Used to form a survey lease with the authority as the survey peer.
  const ClockMapping& clock_mapping() const noexcept {
    return clock_mapping_;
  }
  // True while a plan is between PREPARING and VERIFYING: concurrent key
  // rotation, firmware update and authority identity change are excluded
  // (04 §6/D5-05). Advisory — the Owner enforces the exclusion.
  bool in_progress() const noexcept;
  const MigrationStats& stats() const noexcept { return stats_; }
  const MigrationPlan* pending_plan() const noexcept {
    return plan_known_ ? &pending_plan_ : nullptr;
  }
  // Digest of the currently held plan blob (valid while plan_known_). The
  // Owner uses it to label READY/result reports without re-digesting.
  const Digest256& pending_hash() const noexcept { return pending_hash_; }
  // Local-time switch instant of the held plan (0 when no clock is armed).
  // Report/notice emission only — the engine's own timing is unchanged.
  MonotonicMs pending_switch_local() const noexcept {
    if (!plan_known_ || !clock_valid_) return 0;
    return to_local(pending_plan_.switch_reference_ms);
  }

  // --- §7 prefix bookkeeping --------------------------------------------------
  Status note_assess() noexcept;       // Stable -> Assess
  Status note_survey_begin() noexcept; // Assess -> Survey
  Status note_survey_end() noexcept;   // Survey -> Stable

  // --- plan lifecycle ----------------------------------------------------------
  // Storage step 1 (04 §6): decode + validate the plan, store the blob
  // hash-addressed, readback-verify it — PREPARED only. Rejects: wrong
  // network/authority, non-monotonic epoch, channel mismatch, uncertainty
  // over 20ms, guard below the bound, insufficient COMMIT lead, a required
  // management transfer that cannot fit the prepare window, cooldown.
  Status prepare(ByteView plan_blob, const PlanMeasurements& measurements,
                 MonotonicMs now_ms) noexcept;

  // Storage step 3 (04 §6): verified commit evidence + the stored blob ->
  // COMMITTED. VerifiedAuthorityPlan is the only accepted evidence — a blob
  // alone never switches, and a forged/mismatched commit is refused (D5-01).
  // The received operation must be the one the token was minted for. In
  // Stable (commit-before-blob) the record is stored and the node enters
  // Recovering to refetch the blob — never fabricating config (04 §6).
  Status commit(const VerifiedAuthorityPlan& verified,
                const AuthorityOperation& operation,
                MonotonicMs now_ms) noexcept;
  // Same as commit() but also persists the authority signature on the
  // durable commit record so this node can re-emit verified commit evidence
  // to stranded peers after a restart (04 §9.2 helper duty). A signature
  // over the bound limit is refused outright.
  Status commit(const VerifiedAuthorityPlan& verified,
                const AuthorityOperation& operation, ByteView signature,
                MonotonicMs now_ms) noexcept;
  // Convenience: run the real verifier on received commit evidence
  // (operation + the plan hash and new epoch it references), then commit()
  // only when it mints a valid VerifiedAuthorityPlan. The accepted
  // signature is persisted with the commit record.
  Status note_commit_evidence(const AuthorityOperation& operation,
                              const Digest256& plan_hash, ChannelEpoch new_epoch,
                              ByteView signature, MonotonicMs now_ms) noexcept;

  // A fresh authenticated clock sample (TimeSync). Uncertainty over the 20ms
  // bound refuses and never re-arms the clock; after a restart only a FRESH
  // sample re-arms it — a stored monotonic mapping is never reused (D5-03).
  Status note_clock(const ClockMapping& mapping, MonotonicMs now_ms) noexcept;

  // --- recovery (04 §9) ---------------------------------------------------------
  // A stranded node adopts signed recovery material: real signature verify,
  // digest binding, epoch monotonicity, then store blob + commit and apply
  // (apply-on-resume). A newer snapshot always wins over stored state; a
  // stale/forged one is refused (D5-02/D5-07).
  Status adopt_snapshot(ByteView snapshot, ByteView signature,
                        MonotonicMs now_ms) noexcept;
  // This node is named in the committed plan's helper set.
  bool helper_role() const noexcept;
  // The next old-channel visit window in LOCAL time (helper duty and
  // stranded-listen share the schedule). False when the committed recovery
  // budget is exhausted — after that a helper never visits again (no
  // permanent second channel, 04 §9.2).
  bool next_helper_window(MonotonicMs now_ms, MonotonicMs& begin_ms,
                          MonotonicMs& end_ms) const noexcept;
  // The plan's helper budget in local time (0 = none/unknown).
  MonotonicMs recovery_window_end_local() const noexcept;
  // An explicit recovery-assumption violation: response latency beyond the
  // dwell, loss assumption broken, all helpers lost or a persistent
  // partition (04 §9.3). Terminal for this plan.
  void note_recovery_violation(MonotonicMs now_ms) noexcept;
  // Post-switch verify failure: the node could not confirm on the new
  // channel inside the window -> stranded recovery (never unilateral
  // rollback).
  void note_verify_failure() noexcept;
  // Connectivity evidence during VERIFY (04 §10): any link-authenticated
  // frame received on the new channel proves the cutover landed on a live
  // channel and closes VERIFY early. The window is NOT a blind timer —
  // reaching the deadline with zero evidence is a verify failure.
  void note_link_activity(MonotonicMs now_ms) noexcept;
  // Whether the explicit assumptions (04 §9.3) could even hold for this
  // plan: the recovery bound must fit inside the committed helper budget.
  bool recovery_assumptions_satisfiable(std::uint32_t hops,
                                        std::uint32_t loss_windows,
                                        std::uint32_t transfer_bound_ms,
                                        std::uint32_t margin_ms) const noexcept;

  // --- driver-facing ------------------------------------------------------------
  // Advance: prepare deadline -> ABORTED (pre-commit only); committed
  // switch time -> the ordered cutover (DATA hold -> deadline-preserving
  // drain -> TX fence -> set_channel -> readback -> peer reapply ->
  // generation update -> DATA resume) through the runner; verify window ->
  // STABLE; helper windows -> bounded old-channel visits; recovery budget
  // exhaustion -> RECOVERY_REQUIRED.
  void poll(MonotonicMs now_ms) noexcept;

  // Cold/resume path (D5-03/D5-06): load durable commit + active records.
  // A commit record whose blob is missing enters Recovering to refetch —
  // never fabricating the missing config. A commit with no active record
  // re-applies idempotently once the clock re-arms. The channel is NEVER
  // restored unconditionally from a sleep image; the verified plan wins.
  Status resume(MonotonicMs now_ms) noexcept;

 private:
  enum class CutoverStep : std::uint8_t {
    None = 0,
    Requested = 1,
    InFlight = 2,
  };

  MonotonicMs to_local(MonotonicMs authority_ms) const noexcept;
  MonotonicMs switch_time_local() const noexcept;
  Status store_blob_verified(const Digest256& hash, ByteView blob) noexcept;
  Status store_commit_record(const CommitRecord& record) noexcept;
  Status store_active_record(const ActiveRecord& record) noexcept;
  Status validate_plan(const MigrationPlan& plan, const PlanMeasurements& m,
                       MonotonicMs now_ms) const noexcept;
  // Structural legality only — no epoch/base identity, no now-relative
  // feasibility. Applied on every adoption path, including committed-blob
  // refetch and signed-snapshot catch-up.
  Status check_plan_structure(const MigrationPlan& plan) const noexcept;
  // Measurement- and now-relative feasibility (guard bound, transfer
  // budget, commit lead). Skipped only where a post-commit path cannot
  // evaluate it — never skipped on the initial PREPARE.
  Status validate_plan_feasibility(const MigrationPlan& plan,
                                   const PlanMeasurements& m,
                                   MonotonicMs now_ms) const noexcept;
  // stranded_on_old: the verified commit is held but unapplied and the node
  // is known to still be on the old channel — one bounded re-follow is
  // allowed; otherwise recovery waits for signed material.
  void enter_recovering(bool stranded_on_old) noexcept;
  void latch_cooldown(MonotonicMs now_ms) noexcept;
  void begin_cutover(MonotonicMs now_ms) noexcept;
  void finish_cutover_applied(MonotonicMs now_ms) noexcept;
  void poll_helper(MonotonicMs now_ms) noexcept;

  MigrationParticipantConfig config_{};
  PlanStorage& storage_;
  MigrationAuthority& authority_;
  ChannelOperationRunner& runner_;
  MigrationHooks* hooks_{nullptr};

  ParticipantPhase phase_{ParticipantPhase::Stable};
  MigrationPlan pending_plan_{};
  bool plan_known_{false};
  Digest256 pending_hash_{};
  // The plan hash the stored commit record references; set whenever a
  // commit lands so a later blob is accepted only under that digest.
  Digest256 commit_plan_hash_{};
  // Working authority->local mapping (from the verified plan or a fresh
  // note_clock sample). A stored pre-restart mapping is never re-armed.
  ClockMapping clock_mapping_{};
  MonotonicMs prepare_deadline_ms_{0};
  MonotonicMs verify_deadline_ms_{0};
  MonotonicMs cooldown_until_ms_{0};
  ChannelEpoch committed_epoch_{};
  ChannelEpoch active_epoch_{};
  std::uint8_t active_channel_{0};
  bool clock_valid_{false};
  bool awaiting_blob_{false};
  CutoverStep cutover_{CutoverStep::None};
  OperationToken cutover_token_{kInvalidOperationToken};
  bool data_held_{false};
  // Helper duty bookkeeping: last consumed visit index on the committed
  // schedule (sentinel = none) and whether a visit is in flight. A helper
  // never persists a second channel.
  std::size_t helper_index_{static_cast<std::size_t>(-1)};
  bool helper_visit_active_{false};
  OperationToken helper_token_{kInvalidOperationToken};
  // One bounded re-follow of a held commit after a failed cutover left the
  // node verifiably on the old channel. `available` is a one-shot budget so
  // a failing driver can never loop the retry (04 §9.1).
  bool recovery_retry_pending_{false};
  bool recovery_retry_available_{true};
  MigrationStats stats_{};
};

}  // namespace routeloom
