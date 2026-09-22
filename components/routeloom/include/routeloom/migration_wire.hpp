#pragma once

// Wire-level transport + owner glue for channel-migration plan distribution
// (docs/design/autonomous-mesh/04-channel-migration.md §5-§9; P5b). Builds
// on the frozen Wire v1 frame types — nothing here adds or changes a frame
// type or byte on the wire:
//
//   - ControlObject (49)  manifest of an authenticated object,
//   - ObjectChunk   (50)  fixed chunks of that object,
//   - ObjectAck     (51)  receiver progress/completion report,
//   - ChannelNotice (24)  scheduled-absence / switch notices,
//   - TimeSync      (23)  authority clock samples (fresh-clock re-arm, D5-03).
//
// Authenticated objects (<= kMigrationObjectMax here; the wire budget allows
// 2048B) carry the plan PREPARE/COMMIT material both directions:
//
//   authority -> participant (ControlObjectKind::ChannelPlan):
//       PlanBlob        = msg 1 | plan blob (a blob alone never switches)
//       CommitEvidence  = msg 2 | verified (operation, plan_hash, epoch, sig)
//       SnapshotRequest = msg 5 | stranded-node request (helper serve path)
//   participant -> authority (ControlObjectKind::ChannelPlan):
//       ReadyReport     = msg 3 | plan_hash | epoch | status | flags
//       ResultReport    = msg 4 | plan_hash | epoch | outcome
//   helper -> stranded   (ControlObjectKind::RecoverySnapshot):
//       signed snapshot = u16 sig_len | signature | snapshot body
//
// Every commit-executing path still goes through MigrationParticipant's real
// verifier — transport NEVER grants trust; a forged CommitEvidence or
// snapshot is rejected exactly like a forged local call (D5-01).

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/channel_plan.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/migration.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

namespace migration_wire_const {
// Migration objects stay well under the 2048B wire budget; 1024B covers the
// largest (signed snapshot ~600B) with headroom and bounds reassembly RAM.
constexpr std::size_t kMigrationObjectMax = 1024;
constexpr std::size_t kChunkDataMax =
    kMaxApplicationPayload - autonomy::kObjectChunkHeaderSize;  // 90
constexpr std::size_t kInboundSlots = 2;    // concurrent reassemblies
constexpr std::size_t kOutboundSlots = 3;   // concurrent transfers
constexpr std::size_t kDeliveredLog = 4;    // re-ack dedup ring
constexpr std::size_t kPendingSends = 24;   // agent work queue
constexpr std::size_t kReadinessCapacity = 16;
constexpr std::size_t kResultCapacity = 16;
constexpr std::size_t kRequiredCapacity = 8;
constexpr std::size_t kInlineObjectMax = 64;  // small object content inline
constexpr std::size_t kCommitEvidenceBodyMax =
    93 + 32 + 4 + 2 + migration_const::kMaxCommitSignature;
constexpr std::size_t kCommitEvidenceObjectMax = 1 + kCommitEvidenceBodyMax;
constexpr std::uint32_t kAckTimeoutMs = 2000;
constexpr std::uint8_t kSendAttemptsMax = 3;
constexpr std::uint32_t kInboundExpiryMs = 15000;
constexpr std::uint32_t kPendingTtlMs = 60000;
constexpr std::size_t kPumpFramesPerPoll = 4;
constexpr std::uint32_t kDefaultTimesyncPeriodMs = 5000;
constexpr std::uint32_t kDefaultTimesyncUncertaintyMs = 4;
// Bounded ChannelCutover retries within one committed-vs-active divergence
// episode; exhaustion is the RECOVERY_REQUIRED diagnosis boundary (04 §9).
constexpr std::uint8_t kChannelReconcileAttempts = 3;
}  // namespace migration_wire_const

// --- Message kinds inside ChannelPlan objects ---------------------------------
enum class PlanMessage : std::uint8_t {
  PlanBlob = 1,
  CommitEvidence = 2,
  ReadyReport = 3,
  ResultReport = 4,
  SnapshotRequest = 5,
};

enum class ReadyStatus : std::uint8_t {
  Ready = 1,
  NotReady = 2,
  DeferredSleep = 3,
};

enum class ResultOutcome : std::uint8_t {
  Applied = 1,
  Aborted = 2,
  Recovering = 3,
  RecoveryRequired = 4,
};

// CommitEvidence body: operation fields | plan_hash | new_epoch |
// sig_len u16 | signature.
struct CommitEvidence {
  AuthorityOperation operation{};
  Digest256 plan_hash{};
  ChannelEpoch new_epoch{};
  std::array<std::uint8_t, migration_const::kMaxCommitSignature> signature{};
  std::uint8_t signature_size{0};
};
Status commit_evidence_encode(const CommitEvidence& evidence,
                              MutableByteView target,
                              std::size_t& out_size) noexcept;
Status commit_evidence_decode(ByteView encoded, CommitEvidence& out) noexcept;

// ReadyReport flags: capability/lease evidence for the required-set gate
// (04 §7). Ready means storage accepted + clock + drain budget verified —
// never a bare "answered once".
struct ReadyReport {
  Digest256 plan_hash{};
  ChannelEpoch new_epoch{};
  ReadyStatus status{ReadyStatus::NotReady};
  bool migration_capable{false};
  bool sleep_lease_valid{false};
  bool rediscovery_capable{false};
  bool storage_ok{false};
  bool clock_ok{false};
  bool drain_ok{false};
};
Status ready_report_encode(const ReadyReport& report, MutableByteView target,
                           std::size_t& out_size) noexcept;
Status ready_report_decode(ByteView encoded, ReadyReport& out) noexcept;

struct ResultReport {
  Digest256 plan_hash{};
  ChannelEpoch epoch{};
  ResultOutcome outcome{ResultOutcome::Aborted};
};
Status result_report_encode(const ResultReport& report, MutableByteView target,
                            std::size_t& out_size) noexcept;
Status result_report_decode(ByteView encoded, ResultReport& out) noexcept;

// Stranded-node request carried to a helper during its old-channel visit.
// plan_hash all-zero = "serve your newest signed state" (D5-07: convergence
// is always on the NEWEST commit, never the previous generation).
struct SnapshotRequest {
  ChannelEpoch known_epoch{};
  Digest256 plan_hash{};
};
Status snapshot_request_encode(const SnapshotRequest& request,
                               MutableByteView target,
                               std::size_t& out_size) noexcept;
Status snapshot_request_decode(ByteView encoded, SnapshotRequest& out) noexcept;

// RecoverySnapshot-kind object wrapper: u16 sig_len | signature | snapshot
// body (snapshot_encode output). The signature is verified by the engine
// over the body — the wrapper is transport framing only.
Status signed_snapshot_wrap(ByteView snapshot_body, ByteView signature,
                            MutableByteView target,
                            std::size_t& out_size) noexcept;
Status signed_snapshot_unwrap(ByteView object, ByteView& snapshot_body,
                              ByteView& signature) noexcept;

// Canonical commit-signing input shared by portable tests and the ESP
// development verifier: "RLCMT1" | operation fields | plan_hash | new_epoch.
// The epoch is part of the signed input so an evidence's epoch field can
// never be rewritten without invalidating the MAC — a forged epoch would
// otherwise wedge a participant's committed_epoch ahead of any real plan.
constexpr std::size_t kCommitSigningInputSize = 6 + 93 + 32 + 4;
Status commit_signing_input(const AuthorityOperation& operation,
                            const Digest256& plan_hash, ChannelEpoch new_epoch,
                            MutableByteView target,
                            std::size_t& out_size) noexcept;

// --- Owner surfaces ------------------------------------------------------------

// Bounded authenticated-payload TX + peer-set enumeration the transport
// needs from the radio Owner. Every send is a sealed Wire v1 frame on the
// existing link scope — no new crypto, no new frame types.
class MigrationWirePort {
 public:
  virtual ~MigrationWirePort() = default;
  // One autonomy payload inside one link-sealed frame to a verified peer.
  // WouldBlock while a serialized channel operation owns the radio —
  // except during the off-channel dwell, where visit-marked control is the
  // whole point of the visit.
  virtual Status migration_send(NodeId peer, FrameType type,
                                ByteView payload) noexcept = 0;
  // Verified 1-hop control peers (driver-registered; autonomy peers must
  // additionally hold a Bound/Reachable record).
  virtual std::size_t migration_peers(NodeId* out,
                                      std::size_t capacity) const noexcept = 0;
};

// Reassembled-object delivery into the agent.
class MigrationObjectSink {
 public:
  virtual ~MigrationObjectSink() = default;
  virtual void on_object(NodeId peer, autonomy::ControlObjectKind kind,
                         ByteView object, MonotonicMs now_ms) noexcept = 0;
};

// Which channel context the exchange may currently transmit on.
enum class ExchangeChannel : std::uint8_t {
  Home = 0,    // committed channel — all traffic
  Visit = 2,   // off-channel dwell — visit-marked traffic only
  Blocked = 3  // serialized op owns the radio — nothing transmits
};

struct PlanExchangeConfig {
  std::uint32_t ack_timeout_ms{migration_wire_const::kAckTimeoutMs};
  std::uint8_t send_attempts_max{migration_wire_const::kSendAttemptsMax};
  std::uint32_t inbound_expiry_ms{migration_wire_const::kInboundExpiryMs};
};

// Bounded authenticated-object transport: manifest + in-order chunks + ack,
// resend-on-timeout (never an infinite loop), re-ack dedup on re-delivery.
// Not thread-safe; the Owner serializes. All state is fixed — a dropped or
// exhausted transfer surfaces as an outcome, never as heap growth.
class PlanExchange {
 public:
  PlanExchange(const PlanExchangeConfig& config, MigrationWirePort& wire,
               MigrationObjectSink& sink) noexcept;

  void on_manifest(NodeId peer, const autonomy::ControlObjectPayload& manifest,
                   MonotonicMs now_ms) noexcept;
  void on_chunk(NodeId peer, const autonomy::ObjectChunkPayload& chunk,
                MonotonicMs now_ms) noexcept;
  void on_ack(NodeId peer, const autonomy::ObjectAckPayload& ack,
              MonotonicMs now_ms) noexcept;

  // Queue one object for transfer; content is copied. `visit_channel`
  // restricts the transfer to the off-channel dwell (helper serves); a
  // normal transfer never transmits during a visit. NoCapacity when every
  // transfer slot is busy — the caller may retry later.
  Status publish(NodeId dest, autonomy::ControlObjectKind kind,
                 ByteView content, MonotonicMs now_ms,
                 bool visit_channel = false) noexcept;

  void poll(MonotonicMs now_ms, ExchangeChannel channel) noexcept;

  std::uint8_t outbound_busy() const noexcept;
  std::uint32_t objects_delivered() const noexcept { return delivered_count_; }
  std::uint32_t transfers_failed() const noexcept { return failed_count_; }

 private:
  struct Inbound {
    bool used{false};
    NodeId peer{kInvalidNodeId};
    autonomy::ControlObjectKind kind{autonomy::ControlObjectKind::ChannelPlan};
    autonomy::ObjectHash hash{};
    std::uint16_t total_len{0};
    std::uint16_t received{0};
    MonotonicMs deadline_ms{0};
    std::array<std::uint8_t, migration_wire_const::kMigrationObjectMax> data{};
  };
  struct Outbound {
    bool used{false};
    NodeId dest{kInvalidNodeId};
    autonomy::ControlObjectKind kind{autonomy::ControlObjectKind::ChannelPlan};
    autonomy::ObjectHash hash{};
    std::uint16_t total_len{0};
    std::uint16_t sent{0};
    std::uint8_t attempts{0};
    bool manifest_sent{false};
    bool visit_channel{false};
    MonotonicMs ack_deadline_ms{0};
    std::array<std::uint8_t, migration_wire_const::kMigrationObjectMax> data{};
  };

  Inbound* find_inbound(NodeId peer, const autonomy::ObjectHash& hash) noexcept;
  Outbound* find_outbound(NodeId dest,
                          const autonomy::ObjectHash& hash) noexcept;
  void send_ack(NodeId peer, const autonomy::ObjectHash& hash,
                std::uint16_t received_len,
                autonomy::ObjectAckStatus status) noexcept;
  void complete_inbound(Inbound& slot, MonotonicMs now_ms) noexcept;
  bool delivered_before(const autonomy::ObjectHash& hash) const noexcept;
  void note_delivered(const autonomy::ObjectHash& hash) noexcept;

  PlanExchangeConfig config_{};
  MigrationWirePort& wire_;
  MigrationObjectSink& sink_;
  std::array<Inbound, migration_wire_const::kInboundSlots> inbound_{};
  std::array<Outbound, migration_wire_const::kOutboundSlots> outbound_{};
  std::array<autonomy::ObjectHash, migration_wire_const::kDeliveredLog>
      delivered_{};
  std::size_t delivered_next_{0};
  std::uint32_t delivered_count_{0};
  std::uint32_t failed_count_{0};
};

// --- Agent-facing runtime sink ---------------------------------------------------

// Migration-scoped ingress/poll surface the radio Owner routes to after
// link authentication + identity checks (MeshNode -> AutonomyFrameSink ->
// here). Implemented by MigrationAgent.
class MigrationFrameSink {
 public:
  virtual ~MigrationFrameSink() = default;
  virtual void on_migration_frame(NodeId peer, FrameType type,
                                  ByteView payload,
                                  MonotonicMs now_ms) noexcept = 0;
  virtual void poll(MonotonicMs now_ms) noexcept = 0;
  // Any link-authenticated frame receipt is connectivity evidence. The
  // Owner reports it so VERIFY closes on real traffic instead of a blind
  // timer (04 §10). Default no-op keeps non-migration sinks unaffected.
  virtual void note_link_activity(NodeId peer, MonotonicMs now_ms) noexcept {
    (void)peer;
    (void)now_ms;
  }
};

// What the agent needs from its Owner beyond the wire port: the DATA pause
// (mask semantics — the control lane is never held), the radio generation
// surface and a diagnostics tap.
class MigrationOwnerPort {
 public:
  virtual ~MigrationOwnerPort() = default;
  virtual void hold_data(bool held) noexcept = 0;
  virtual void note_radio_generation(std::uint32_t radio_generation) noexcept = 0;
  virtual void on_migration_event(const char* reason,
                                  NodeId peer) noexcept = 0;
};

struct MigrationAgentConfig {
  MigrationParticipantConfig participant{};
  PlanMeasurements measurements{};
  bool authority_role{false};
  // Required-set membership this authority gates commits on (04 §7).
  std::array<NodeId, migration_wire_const::kRequiredCapacity> required{};
  std::size_t required_count{0};
  // Self-reported readiness inputs for ReadyReport flags.
  bool self_sleep_lease_valid{false};
  bool self_rediscovery_capable{true};
  std::uint32_t timesync_period_ms{
      migration_wire_const::kDefaultTimesyncPeriodMs};  // 0 disables
  std::uint32_t timesync_uncertainty_ms{
      migration_wire_const::kDefaultTimesyncUncertaintyMs};
  std::uint32_t snapshot_request_period_ms{
      migration_const::kHelperVisitPeriodMs};
  std::uint32_t rx_clock_slack_ms{2};  // added to every received sample
  std::uint32_t terminal_margin_ms{5000};
};

// Participant + (optional) authority wiring over the authenticated object
// transport. One instance per node. Drives MigrationParticipant (engine),
// ChannelCoordinator (bookkeeping/notices) and MigrationAuthority (issuer
// path) through the wire port; the Owner supplies storage, verifier and the
// serialized runner.
class MigrationAgent final : public MigrationFrameSink,
                             public MigrationObjectSink,
                             private MigrationHooks {
 public:
  MigrationAgent(const MigrationAgentConfig& config, MigrationWirePort& wire,
                 MigrationOwnerPort& owner, PlanStorage& storage,
                 MigrationAuthority& authority,
                 ChannelOperationRunner& runner,
                 ChannelCoordinator* coordinator) noexcept;

  // MigrationFrameSink
  void on_migration_frame(NodeId peer, FrameType type, ByteView payload,
                          MonotonicMs now_ms) noexcept override;
  void poll(MonotonicMs now_ms) noexcept override;
  void note_link_activity(NodeId peer, MonotonicMs now_ms) noexcept override;

  // Cold/resume entry: load durable records via the engine. Afterwards the
  // poll loop continuously reconciles the runner's committed channel with
  // the engine's active record — whether the divergence came from an
  // unavailable boot-time read or a mid-run stranded radio — through a
  // real verified ChannelCutover, never a bare assignment.
  Status resume(MonotonicMs now_ms) noexcept;

  // --- authority (Manual) issuance -------------------------------------------
  // Ledger-commit the plan through the real MigrationAuthority path, then
  // distribute the plan blob (PREPARE) plus the signed recovery snapshot to
  // every currently bound peer. Commit evidence is HELD until
  // release_commit() — the READY collection gate stays explicit (04 §7).
  // `snapshot_body`/`snapshot_signature` may be empty to skip snapshot
  // distribution; when present the body must decode to (operation, plan
  // blob) consistent material or the offer is refused.
  Status offer_plan(const MigrationPlan& plan, ByteView plan_blob,
                    const AuthorityOperation& operation,
                    ByteView commit_signature,
                    const Digest256& resulting_state_hash,
                    ByteView snapshot_body, ByteView snapshot_signature,
                    bool is_rollback, MonotonicMs now_ms,
                    VerifiedAuthorityPlan& out) noexcept;
  // Release the held commit evidence to bound peers and arm terminal
  // accounting. Requires a prior successful offer_plan.
  Status release_commit(MonotonicMs now_ms) noexcept;
  // Required-set gate over collected READY reports (04 §7/D5-09).
  RequiredSetVerdict readiness_verdict() const noexcept;
  bool readiness_of(NodeId node, ParticipantReadiness& out) const noexcept;

  // --- AutoGuarded gate (P6) ---------------------------------------------------
  // Compose the evidence this agent can prove — authority configured/
  // available/verifier-ready, authority reachability via the readiness set
  // or a held verified commit, required-set accounting (unanswered is never
  // silently "asleep", 04 §7), participant clock/cooldown — over the
  // caller-asserted deployment fields (recovery-plan commitment, extra
  // path evidence) and run the single shared gate. `evidence` fields the
  // agent measures are overwritten; caller-asserted fields can only widen
  // (they are trusted deployment inputs, same discipline as
  // PlanMeasurements).
  AutoGuardedVerdict evaluate_autoguarded(AutoGuardedEvidence evidence,
                                          MonotonicMs now_ms) const noexcept;
  // Opt-in AutoGuarded request: forwards the composed evidence to the
  // coordinator's gate. The verdict is always returned — a refusal names
  // every unmet condition instead of reporting Unsupported.
  AutoGuardedVerdict request_autoguarded(const AutoGuardedEvidence& evidence,
                                         MonotonicMs now_ms) noexcept;

  // --- Manual survey -----------------------------------------------------------
  // Bounded survey visit through the coordinator lease + serialized runner:
  // emits authenticated scheduled-absence notices to the lease's notify set
  // BEFORE the visit, then runs a SurveyVisit op. Manual mode only.
  Status request_survey(const SurveyRequest& request, MonotonicMs now_ms,
                        OperationToken& out) noexcept;

  MigrationParticipant& participant() noexcept { return participant_; }
  const MigrationParticipant& participant() const noexcept {
    return participant_;
  }
  ChannelCoordinator* coordinator() noexcept { return coordinator_; }
  bool serving() const noexcept { return serving_; }
  std::size_t pending_sends() const noexcept { return pending_.size(); }
  PlanExchange& exchange() noexcept { return exchange_; }

 private:
  enum class PendingTag : std::uint8_t {
    Inline = 0,         // inline_body holds the complete object content
    ServeSnapshot = 1,  // materialize commit evidence + blob (+ snapshot)
    DistributeBlob = 2,
    DistributeEvidence = 3,
    DistributeSnapshot = 4,
  };
  struct PendingSend {
    NodeId dest{kInvalidNodeId};
    PendingTag tag{PendingTag::Inline};
    autonomy::ControlObjectKind kind{autonomy::ControlObjectKind::ChannelPlan};
    MonotonicMs deadline_ms{0};
    bool visit_channel{false};
    std::array<std::uint8_t, migration_wire_const::kInlineObjectMax>
        inline_body{};
    std::uint8_t inline_size{0};
  };
  struct ResultEntry {
    bool used{false};
    NodeId node{kInvalidNodeId};
    Digest256 plan_hash{};
    ChannelEpoch epoch{};
    ResultOutcome outcome{ResultOutcome::Aborted};
  };

  // MigrationObjectSink
  void on_object(NodeId peer, autonomy::ControlObjectKind kind,
                 ByteView object, MonotonicMs now_ms) noexcept override;
  // MigrationHooks
  void hold_data(bool held) noexcept override;
  void note_cutover_generation(std::uint32_t radio_generation) noexcept
      override;
  void helper_visit(bool active, std::uint8_t old_channel) noexcept override;

  void on_phase_transition(ParticipantPhase from, ParticipantPhase to,
                           MonotonicMs now_ms) noexcept;
  void enqueue_pending(const PendingSend& send) noexcept;
  void queue_inline(NodeId dest, autonomy::ControlObjectKind kind,
                    ByteView content, MonotonicMs deadline_ms,
                    bool visit_channel) noexcept;
  void emit_notice(NodeId dest, autonomy::AbsenceReason reason,
                   ChannelEpoch epoch, std::uint32_t starts_in_ms,
                   std::uint32_t duration_ms,
                   std::uint16_t protected_cut_id) noexcept;
  void emit_notice_all(autonomy::AbsenceReason reason, ChannelEpoch epoch,
                       std::uint32_t starts_in_ms, std::uint32_t duration_ms,
                       std::uint16_t protected_cut_id) noexcept;
  void emit_ready_report(const Digest256& plan_hash, ChannelEpoch epoch,
                         ReadyStatus status,
                         MonotonicMs now_ms) noexcept;
  void emit_result_report(ResultOutcome outcome,
                          MonotonicMs now_ms) noexcept;
  void pump_pending(MonotonicMs now_ms) noexcept;
  void materialize_serve(NodeId dest, MonotonicMs now_ms) noexcept;
  void distribute(PendingTag tag, MonotonicMs deadline_ms) noexcept;
  ExchangeChannel channel_context() const noexcept;
  void record_readiness(NodeId peer, const ReadyReport& report) noexcept;
  void record_result(NodeId peer, const ResultReport& report) noexcept;
  void check_terminal(MonotonicMs now_ms) noexcept;
  // Fill the AutoGuardedEvidence fields this agent can measure/verify;
  // caller-asserted fields are only ever widened (never cleared).
  void compose_autoguarded(AutoGuardedEvidence& evidence,
                           MonotonicMs now_ms) const noexcept;
  // AutoGuarded-mode survey: on a SurveyProposed assessment, build the
  // bounded request (authority as survey peer — the only end we hold an
  // armed clock mapping for) and submit it. The coordinator re-gates the
  // stored evidence snapshot itself; a refusal just skips this tick.
  void auto_survey(const ChannelAssessment& assessment,
                   MonotonicMs now_ms) noexcept;

  MigrationAgentConfig config_{};
  MigrationWirePort& wire_;
  MigrationOwnerPort& owner_;
  PlanStorage& storage_;
  MigrationAuthority& authority_;
  ChannelOperationRunner& runner_;
  ChannelCoordinator* coordinator_{nullptr};
  MigrationParticipant participant_;
  PlanExchange exchange_;

  ParticipantPhase last_phase_{ParticipantPhase::Stable};
  // Last emitted coordinator assessment verdict — ASSESS_* owner events fire
  // on change only, never per-poll spam.
  AssessVerdict last_assess_verdict_{AssessVerdict::Stable};
  bool serving_{false};
  OperationToken reconcile_token_{kInvalidOperationToken};
  bool reconcile_pending_op_{false};
  // Per-divergence-episode bookkeeping for the live committed-vs-active
  // reconcile: failed ops so far, plus the exhaustion latch — both reset
  // the moment the channels agree again.
  std::uint8_t reconcile_attempts_{0};
  bool reconcile_exhausted_{false};
  bool survey_pending_{false};
  OperationToken survey_token_{kInvalidOperationToken};
  std::uint32_t survey_lease_id_{0};
  // AutoGuarded survey notes are latched per proposal streak — one owner
  // event per skip/refuse reason, cleared on issue or verdict change.
  bool autosurvey_noted_{false};
  MonotonicMs next_snapshot_request_ms_{0};
  MonotonicMs next_timesync_ms_{0};
  std::uint32_t timesync_sequence_{0};

  // Authority-side issued plan material (single in-flight plan).
  bool issued_{false};
  bool commit_released_{false};
  bool terminal_armed_{false};
  bool issued_recovery_present_{false};
  Digest256 issued_plan_hash_{};
  ChannelEpoch issued_epoch_{};
  MonotonicMs issued_switch_local_ms_{0};
  MonotonicMs terminal_deadline_ms_{0};
  std::array<std::uint8_t, migration_const::kPlanBlobMax> issued_blob_{};
  std::size_t issued_blob_size_{0};
  std::array<std::uint8_t,
             migration_wire_const::kCommitEvidenceObjectMax>
      issued_evidence_{};
  std::size_t issued_evidence_size_{0};
  std::array<std::uint8_t, migration_const::kSnapshotMax + 68>
      issued_snapshot_{};
  std::size_t issued_snapshot_size_{0};

  // RAM cache of the newest verified signed snapshot object (serving aid —
  // durability is the commit record + blob, not this cache).
  bool cached_snapshot_valid_{false};
  ChannelEpoch cached_snapshot_epoch_{};
  std::array<std::uint8_t, migration_const::kSnapshotMax + 68>
      cached_snapshot_{};
  std::size_t cached_snapshot_size_{0};

  FixedQueue<PendingSend, migration_wire_const::kPendingSends> pending_{};
  FixedPool<ParticipantReadiness, migration_wire_const::kReadinessCapacity>
      readiness_{};
  std::array<ResultEntry, migration_wire_const::kResultCapacity> results_{};
};

}  // namespace routeloom
