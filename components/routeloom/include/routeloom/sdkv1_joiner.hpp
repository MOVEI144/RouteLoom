#pragma once

// SDK v1 zero-touch join FSM (docs/design/sdk-v1/02-zero-touch-join.md §10,
// §11; design P3-4; plan P3-4 PR 3). The portable device side of joining:
// scan/observe overlapped sites, run one EDHOC exchange at a time through
// the candidate table (sdkv1_join_candidates.hpp) and the handshake driver
// (sdkv1_join_handshake.hpp), and durably commit the verified RLS1 — or
// avoid the site without writing anything.
//
// The single Owner serializes all calls and performs every action: radio
// tuning (ChangeChannel), membership adoption (MemberReady), removal
// handoff (RemovalRequired) and recovery (RecoveryRequired). The Joiner
// never touches MeshNode, the radio, NVS or the MembershipController
// itself; it only owns one ZtJoinerLink over the injected ZtRld1Port.
//
// Re-entrancy contract (design §3.1): every mutating entry is guarded, so a
// call made from a port/observer/storage callback returns Busy and changes
// nothing; the Owner re-feeds its own bounded queue after the outer call
// returns. The internal link observer only updates the fixed candidate
// table, copies one complete down message into the 960 B mailbox and sets
// hint/failure flags — it never drives the session or the link.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/admission.hpp"  // MembershipState
#include "routeloom/edhoc.hpp"      // AeadCcm
#include "routeloom/sdkv1_ead.hpp"  // RemovalNotice
#include "routeloom/sdkv1_join_candidates.hpp"
#include "routeloom/sdkv1_join_handshake.hpp"
#include "routeloom/sdkv1_join_relay.hpp"
#include "routeloom/sdkv1_records.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// --- Radio profile -----------------------------------------------------------------------
// Regional channel limits are the Owner's job; the Joiner only tunes inside
// the configured scan set on the fixed join PHY.
enum class JoinPhy : std::uint8_t { Lr250 = 0 };

struct JoinerConfig {
  NodeId node{kInvalidNodeId};
  MacAddress mac{};
  std::uint32_t fw_version{0};
  // JoinRequest capability bits (same positions as the MemberCert role
  // bits); a granted relay/gateway role the hardware cannot run is
  // refused before commit.
  std::uint32_t capability{0};
  std::uint8_t requested_role{0};  // nonzero known role bits, within capability
  // Scan channels 1..14, unique, at most 3. Default {1,6,11}.
  std::array<std::uint8_t, kJoinScanChannelMax> scan_channels{{1, 6, 11}};
  std::uint8_t scan_channel_count{3};
  // bit n set -> channel n usable on this hardware (1..14).
  std::uint16_t usable_channel_mask{0xFFFE};
};

// --- Boot input ------------------------------------------------------------------------------
// The Owner reads, repairs and durably writes rlboot before start and hands
// the witness over; the Joiner issues no boot counter and takes no wall
// clock. A preferred former membership is RAM-only and derived from the
// stored RLS1. A completed RLX1 removal supplies a durable generation
// watermark through the Owner's boot gate.
enum class JoinBootMode : std::uint8_t { Normal = 0, VerifyExistingMembership = 1 };

struct JoinBootInput {
  std::uint32_t boot_witness{0};
  bool prepared{false};
  // Query the authority without dropping a healthy retained membership.
  JoinBootMode mode{JoinBootMode::Normal};
  // Both zero unless a verified RLX1 watermark names the last removed site.
  std::uint64_t removal_watermark_site_id{0};
  std::uint32_t removal_watermark_generation{0};
};

// --- Radio input ------------------------------------------------------------------------------
// Observed (not self-reported) frame metadata. `frame` is valid during the
// call only.
struct JoinRxMeta {
  MacAddress source{};
  MacAddress destination{};
  std::uint8_t channel{0};
  std::int16_t rssi{0};
};

// --- Actions (single slot; take before the driver advances) -------------------------
enum class JoinActionKind : std::uint8_t {
  None = 0,
  ChangeChannel,
  MemberReady,
  RemovalRequired,
  RecoveryRequired,
};

enum class JoinRecoveryReason : std::uint8_t {
  None = 0,
  UnknownSchema,       // a slot holds an unknown record schema: never recovered over
  SeqExhausted,        // commit_seq floor is u32 max: never wrapped
  StorageFailure,      // persistent read/write failure after the bounded retries
  BootWitnessMismatch,  // stored membership is newer than the rlboot witness
  MembershipInvalid,   // stored bytes do not authenticate for this device
  AssignmentRegressed,  // a re-issue regresses the retained membership
  TokenExhausted,       // the channel token would wrap: tuning stops
};

struct JoinAction {
  JoinActionKind kind{JoinActionKind::None};
  // ChangeChannel: retune, then report completion with the same token.
  std::uint32_t channel_token{0};
  std::uint8_t channel{0};
  JoinPhy phy{JoinPhy::Lr250};
  // MemberReady: re-resolve the store and adopt the membership (the Owner
  // starts RLT1, Member scope, links/routes and JoinConfirm). No keys.
  std::uint32_t commit_seq{0};
  bool joined_now{false};  // false when an existing membership was adopted
  std::uint32_t rs_epoch_to_fetch{0};  // fresh joins: the package target; else 0
  // RemovalRequired: a notice verified against the stored membership, for
  // the removal coordinator. The Joiner already stopped traffic.
  RemovalNotice removal{};
  std::array<std::uint8_t, kRemovalNoticeObjectSize> removal_object{};
  std::uint64_t removal_site_id{0};
  std::uint32_t removal_generation{0};
  // RecoveryRequired: external diagnosis/recovery; nothing is auto-erased.
  JoinRecoveryReason recovery_reason{JoinRecoveryReason::None};
};

// --- Observer ------------------------------------------------------------------------------------
// State transitions, attempt begin/end, authenticated verdicts and store
// failures. Values only: no secrets, tickets, raw EAD or certificates.
enum class JoinState : std::uint8_t {
  Stopped = 0,
  BootCheck,
  ScanTune,
  WaitChannel,
  ScanWindow,
  Select,
  RefreshWindow,
  SendM1,
  WaitM2,
  SendM3,
  WaitM4,
  Decided,
  Commit,
  Reconcile,
  Backoff,
  Ready,
  Removed,
  RecoveryRequired,
};

// Saturating fixed counters (reason-split, no dynamic strings).
struct JoinCounters {
  std::uint32_t attempts{0};
  std::uint32_t m1_sent{0};
  std::uint32_t m2_ok{0};
  std::uint32_t m4_ok{0};
  std::uint32_t allows{0};
  std::uint32_t denies{0};
  std::uint32_t pendings{0};
  std::uint32_t busies{0};
  std::uint32_t removals{0};
  std::uint32_t malformed{0};
  std::uint32_t auth_failures{0};
  std::uint32_t transient_failures{0};
  std::uint32_t timeouts{0};
  std::uint32_t store_failures{0};
  std::uint32_t link_failures{0};
  std::uint32_t rx_dropped{0};
  std::uint32_t stale_events{0};
  // No re-entry counter: a re-entered call returns Busy without changing
  // anything, not even diagnostics.
};

enum class JoinEventKind : std::uint8_t {
  StateChanged = 0,
  AttemptStarted,
  AttemptFinished,
  StoreFailure,
};

struct JoinEvent {
  JoinEventKind kind{JoinEventKind::StateChanged};
  JoinState from{JoinState::Stopped};
  JoinState to{JoinState::Stopped};
  JoinCandidateKey key{};  // AttemptStarted/AttemptFinished
  MacAddress proxy{};      // AttemptStarted
  JoinAttemptOutcome outcome{JoinAttemptOutcome::Pending};  // AttemptFinished
  bool authenticated{false};               // AttemptFinished: from an authenticated m4
  StatusCode store_error{StatusCode::Ok};  // StoreFailure
  JoinCounters counters{};
};

class JoinObserver {
 public:
  virtual ~JoinObserver() = default;
  virtual void on_event(const JoinEvent& event) noexcept = 0;
};

class NullJoinObserver final : public JoinObserver {
 public:
  void on_event(const JoinEvent&) noexcept override {}
};

// --- Snapshot ------------------------------------------------------------------------------------
struct JoinSnapshot {
  JoinState state{JoinState::Stopped};
  MembershipState membership{MembershipState::Unprovisioned};
  bool action_pending{false};
  JoinActionKind pending_action{JoinActionKind::None};
  std::uint8_t channel{0};
  std::uint32_t channel_token{0};
  bool clock_uncertain{false};
  StatusCode last_error{StatusCode::Ok};
  JoinCounters counters{};
  JoinCandidatesStats candidates{};
  JoinAttemptStats handshake{};
};

// --- The FSM ---------------------------------------------------------------------------------------
class Joiner final {
 public:
  Joiner(const JoinerConfig& config, IdentityStore& identity, SiteStore& site,
         EntropySource& entropy, ZtRld1Port& port, JoinObserver& observer,
         const edhoc::AeadCcm* aead = nullptr) noexcept;
  ~Joiner();
  Joiner(const Joiner&) = delete;
  Joiner& operator=(const Joiner&) = delete;

  // Starts from Stopped only; the next poll runs the boot/store check.
  // Refuses an unprepared boot witness or an invalid scan-channel set.
  Status start(const JoinBootInput& boot, MonotonicMs now) noexcept;
  // Completion of the pending ChangeChannel token (sync radios report it
  // from a separate call after consuming the action). Stale tokens from an
  // older tune are ignored and counted, never applied.
  Status on_channel_ready(std::uint32_t token, Status result, MonotonicMs now) noexcept;
  // One observed RLD1 frame with its radio metadata; gated (destination,
  // channel, nonce, proxy, phase/step) before it reaches the link.
  Status on_rld1_rx(const JoinRxMeta& meta, ByteView frame, MonotonicMs now) noexcept;
  // Drives timers and the link, advances at most one heavy step.
  Status poll(MonotonicMs now) noexcept;
  // Takes the pending control action (NotFound when empty).
  Status take_action(JoinAction& out) noexcept;
  // Drops radio/session/uncommitted state and invalidates the channel
  // generation. Stored RLS1 and the avoid table survive.
  Status stop(MonotonicMs now) noexcept;

  JoinSnapshot snapshot() const noexcept;
  // Earliest time poll() has work; last-seen now when work is immediate,
  // kJoinNoDeadline when nothing is scheduled.
  MonotonicMs next_deadline() const noexcept;
  // True only with no in-flight work of this component (false inside any
  // outer call). Not a whole-device sleep permission.
  bool quiescent() const noexcept;

 private:
  class LinkObserver final : public ZtJoinerObserver {
   public:
    explicit LinkObserver(Joiner& owner) noexcept : owner_(owner) {}
    void on_offer(const ZtOfferView& offer) noexcept override;
    void on_message(JoinAuthPhase phase, std::uint8_t step, ByteView message) noexcept override;
    void on_relay_status(RelayStatusCode status, std::uint32_t retry_after_ms) noexcept override;
    void on_link_failure(const char* reason) noexcept override;

   private:
    Joiner& owner_;
  };

  enum class RefreshPhase : std::uint8_t { RateWait = 0, Collect };

  // Monotonic-clock gate: a regression aborts the in-flight attempt,
  // parks the FSM in Stopped and latches until stop() opens a new clock
  // domain (reboot semantics). Never feeds regressed time to the tables.
  bool clock_ok(MonotonicMs now) noexcept;
  Status enter_boot_check(MonotonicMs now) noexcept;
  Status drive(MonotonicMs now) noexcept;
  Status drive_scan_tune(MonotonicMs now) noexcept;
  Status drive_scan_window(MonotonicMs now) noexcept;
  Status drive_select(MonotonicMs now) noexcept;
  Status drive_refresh(MonotonicMs now) noexcept;
  Status drive_send_m1(MonotonicMs now) noexcept;
  Status drive_wait_m2(MonotonicMs now) noexcept;
  Status drive_send_m3(MonotonicMs now) noexcept;
  Status drive_wait_m4(MonotonicMs now) noexcept;
  Status drive_decided(MonotonicMs now) noexcept;
  Status drive_commit(MonotonicMs now) noexcept;
  Status drive_reconcile(MonotonicMs now) noexcept;
  Status drive_backoff(MonotonicMs now) noexcept;
  Status drive_wait_channel(MonotonicMs now) noexcept;

  void set_state(JoinState next) noexcept;
  void set_projection(MembershipState next) noexcept;
  void emit(JoinEventKind kind) noexcept;
  bool emit_action(const JoinAction& action) noexcept;
  // Ends the radio/session leg of an attempt; maps the outcome onto the
  // table's live attempt (when one is in flight) and returns to Select.
  void finish_attempt(JoinAttemptOutcome outcome,
                      std::uint32_t retry_after_s, MonotonicMs now) noexcept;
  void teardown_attempt() noexcept;
  void clear_mailbox() noexcept;
  void start_scan() noexcept;
  bool open_scan_window(MonotonicMs now) noexcept;
  void tune_failed(MonotonicMs now) noexcept;
  void begin_refresh() noexcept;
  void recovery_required(JoinRecoveryReason reason) noexcept;
  void reconcile_enter(bool authorized, MonotonicMs now) noexcept;
  void wipe_expectation() noexcept;
  bool matches_expectation(const SiteRecord& site) noexcept;
  bool recovery_match(const JoinCandidateKey& key) const noexcept;
  // Full re-verification of an adopted RLS1 before it may drive anything.
  bool verify_adopted(const SiteRecord& site, const IdentityRecord& identity) noexcept;
  bool below_removal_watermark(const SiteRecord& site) const noexcept;
  bool retain_membership(const SiteRecord& site, const IdentityRecord& identity) noexcept;
  static MonotonicMs sat_add(MonotonicMs a, std::uint64_t delta) noexcept;
  static void sat_inc(std::uint32_t& counter) noexcept;
  static bool step_expected(JoinState state, JoinAuthPhase phase, std::uint8_t step) noexcept;

  JoinerConfig config_{};
  IdentityStore& identity_;
  SiteStore& site_;
  EntropySource& entropy_;
  JoinObserver& observer_;
  const edhoc::AeadCcm* aead_{nullptr};
  LinkObserver link_observer_;
  ZtJoinerLink link_;
  JoinCandidates candidates_;
  JoinHandshake handshake_;

  JoinState state_{JoinState::Stopped};
  MembershipState projection_{MembershipState::Unprovisioned};
  MonotonicMs last_now_{0};
  bool clock_uncertain_{false};
  bool in_call_{false};

  std::uint32_t boot_witness_{0};
  std::uint64_t removal_watermark_site_id_{0};
  std::uint32_t removal_watermark_generation_{0};
  std::uint32_t retained_floor_{0};  // adopted rs_epoch_floor, kept on same-site recovery
  std::uint8_t channel_{0};          // last tuned channel, 0 = untuned
  std::uint8_t channel_target_{0};   // tune in flight
  std::uint32_t channel_token_{0};
  bool channel_waiting_{false};
  bool tune_is_refresh_{false};
  MonotonicMs channel_deadline_{0};
  MonotonicMs window_deadline_{0};
  RefreshPhase refresh_phase_{RefreshPhase::RateWait};

  JoinCandidateKey attempt_key_{};
  MacAddress attempt_proxy_{};
  std::uint8_t attempt_hops_{kZtHopsUnknown};
  JoinCandidate* attempt_record_{nullptr};
  JoinAttempt attempt_{};
  ZtOfferView refresh_offer_{};
  bool refresh_offer_valid_{false};
  std::int16_t refresh_rssi_{0};

  // Single 960 B RX/TX workspace (§9): the mailbox or the compose buffer,
  // never both — the session call returns and the staged copy moves on
  // before the bytes are reused.
  std::array<std::uint8_t, kJoinMessageMax> msg_{};
  std::size_t msg_len_{0};
  bool mailbox_valid_{false};
  JoinAuthPhase mailbox_phase_{JoinAuthPhase::EdhocMessage};
  std::uint8_t mailbox_step_{0};
  bool hint_valid_{false};
  RelayStatusCode hint_status_{RelayStatusCode::Queued};
  std::uint32_t hint_retry_ms_{0};
  bool link_failed_{false};
  JoinRxMeta last_rx_{};

  JoinAction action_{};
  bool action_pending_{false};

  MonotonicMs t2_deadline_{0};
  MonotonicMs t4_deadline_{0};
  MonotonicMs overall_deadline_{0};
  MonotonicMs last_m1_ms_{0};
  JoinDecided decided_{};
  bool decided_valid_{false};

  struct CommitExpectation {
    bool valid{false};
    std::uint32_t rs_epoch_to_fetch{0};
    Digest256 fingerprint{};
  };
  CommitExpectation commit_expect_{};
  Digest256 retained_fingerprint_{};
  bool retained_fingerprint_valid_{false};
  bool reconcile_authorized_{false};
  MonotonicMs backoff_deadline_{0};
  std::uint8_t reconcile_retries_{0};
  MonotonicMs reconcile_deadline_{0};

  // Recovery joins attempt the known site only; the store also refuses a
  // site change while a membership is adopted.
  bool recovery_only_{false};
  bool verify_existing_{false};
  JoinCandidateKey recovery_key_{};
  std::uint64_t recovery_site_id_{0};

  JoinMembershipEvidence evidence_{};
  bool evidence_valid_{false};
  StatusCode last_error_{StatusCode::Ok};
  JoinCounters counters_{};
  JoinEvent event_{};
};

static_assert(sizeof(Joiner) <= 12288, "Joiner must stay within the 12 KiB LP64 budget");

}  // namespace routeloom::sdkv1
