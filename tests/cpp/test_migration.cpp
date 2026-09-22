// P5a portable channel-migration tests (docs/design/autonomous-mesh/
// 04-channel-migration.md §5-§10, contracts.json migration.*). Covers the
// plan object + verified-commit storage order, the participant state
// machine, clock/cutover discipline, helper/scout recovery, the single-
// authority issuer and rollback/cooldown. Scenario ids from scenarios.json
// are noted where they map (D5-01..D5-07, D5-09, X-02). ESP driver wiring
// is P5b — every side effect goes through fakes.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "routeloom/authority.hpp"
#include "routeloom/migration.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

#include "test_ledger.hpp"
#include "test_security.hpp"

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
using routeloom_test::FaultyLedgerStorage;
using routeloom_test::mix;

constexpr NetworkId kNet = 7;
constexpr NodeId kAuthority = 9;
constexpr NodeId kSelf = 2;

// --- deterministic test "crypto" ------------------------------------------------
// A real check inside the test crypto model: the signature is a keyed
// deterministic MAC over (operation fields, plan hash) / snapshot bytes.
// Forging bytes fails verification — this is NOT a pass-through.

Digest256 sign_commit(const AuthorityOperation& op, const Digest256& plan_hash,
                      const ChannelEpoch new_epoch) {
  std::uint64_t lanes[4] = {0xA17B9C4D2E3F0112ULL, 0x5A5A5A5A5A5A5A5AULL,
                            0x123456789ABCDEF0ULL, 0x0FEDCBA987654321ULL};
  lanes[0] = mix(lanes[0], op.network);
  lanes[0] = mix(lanes[0], op.authority);
  lanes[0] = mix(lanes[0], op.generation);
  lanes[0] = mix(lanes[0], op.sequence);
  lanes[0] = mix(lanes[0], static_cast<std::uint8_t>(op.kind));
  lanes[0] = mix(lanes[0], new_epoch.value);
  for (const std::uint8_t b : op.previous_state_hash) lanes[1] = mix(lanes[1], b);
  for (const std::uint8_t b : op.operation_hash) lanes[2] = mix(lanes[2], b);
  for (const std::uint8_t b : plan_hash) lanes[3] = mix(lanes[3], b);
  Digest256 out{};
  for (int lane = 0; lane < 4; ++lane) {
    for (int byte = 0; byte < 8; ++byte) {
      out[lane * 8 + byte] =
          static_cast<std::uint8_t>(lanes[lane] >> (56 - byte * 8));
    }
  }
  return out;
}

Digest256 sign_snapshot(ByteView snapshot) {
  std::uint64_t lanes[4] = {0xDEADBEEFCAFEF00DULL, 0x243F6A8885A308D3ULL,
                            0x452821E638D01377ULL, 0xBF58476D1CE4E5B9ULL};
  for (std::size_t i = 0; i < snapshot.size; ++i) {
    lanes[i % 4] = mix(lanes[i % 4], snapshot.data[i]);
  }
  Digest256 out{};
  for (int lane = 0; lane < 4; ++lane) {
    for (int byte = 0; byte < 8; ++byte) {
      out[lane * 8 + byte] =
          static_cast<std::uint8_t>(lanes[lane] >> (56 - byte * 8));
    }
  }
  return out;
}

class TestCommitVerifier final : public CommitSignatureVerifier {
 public:
  bool ready() const noexcept override { return ready_; }
  SecurityProfile security_profile() const noexcept override {
    return profile_;  // Development by default: EXPERIMENTAL, never production
  }
  Status verify_commit(const AuthorityOperation& operation,
                       const Digest256& plan_hash, const ChannelEpoch new_epoch,
                       ByteView signature) noexcept override {
    ++commit_checks;
    if (fail_next_) {
      fail_next_ = false;
      return Status::error(StatusCode::AuthenticationFailed, "scripted reject");
    }
    const Digest256 expected = sign_commit(operation, plan_hash, new_epoch);
    if (signature.size != expected.size() ||
        std::memcmp(signature.data, expected.data(), expected.size()) != 0) {
      return Status::error(StatusCode::AuthenticationFailed, "bad signature");
    }
    return Status::success();
  }
  Status verify_snapshot(ByteView snapshot, ByteView signature) noexcept override {
    ++snapshot_checks;
    const Digest256 expected = sign_snapshot(snapshot);
    if (signature.size != expected.size() ||
        std::memcmp(signature.data, expected.data(), expected.size()) != 0) {
      return Status::error(StatusCode::AuthenticationFailed, "bad signature");
    }
    return Status::success();
  }

  bool ready_{true};
  SecurityProfile profile_{SecurityProfile::Development};
  bool fail_next_{false};
  int commit_checks{0};
  int snapshot_checks{0};
};

// --- in-memory plan storage with fault injection ---------------------------------

class MemoryPlanStorage final : public PlanStorage {
 public:
  Status write_blob(const Digest256& hash, const ByteView blob) noexcept override {
    if (fail_writes) {
      return Status::error(StatusCode::StorageFailure, "injected write failure");
    }
    Blob* slot = find(hash);
    if (slot == nullptr) {
      slot = find_free();
      if (slot == nullptr) {
        return Status::error(StatusCode::NoCapacity, "blob slots full");
      }
      slot->hash = hash;
      slot->used = true;
    }
    if (blob.size > slot->data.size()) {
      return Status::error(StatusCode::NoCapacity, "blob too large");
    }
    std::memcpy(slot->data.data(), blob.data, blob.size);
    slot->size = blob.size;
    return Status::success();
  }
  Status read_blob(const Digest256& hash, const MutableByteView target,
                   std::size_t& out_size) noexcept override {
    const Blob* slot = find(hash);
    if (slot == nullptr) {
      return Status::error(StatusCode::NotFound, "blob absent");
    }
    if (target.size < slot->size) {
      return Status::error(StatusCode::NoCapacity, "read buffer too small");
    }
    std::memcpy(target.data, slot->data.data(), slot->size);
    out_size = slot->size;
    return Status::success();
  }
  Status drop_blob(const Digest256& hash) noexcept override {
    Blob* slot = find(hash);
    if (slot == nullptr) return Status::error(StatusCode::NotFound, "blob absent");
    *slot = Blob{};
    return Status::success();
  }
  Status write_commit_record(const ByteView record) noexcept override {
    if (fail_writes) {
      return Status::error(StatusCode::StorageFailure, "injected write failure");
    }
    if (record.size > commit_.size()) {
      return Status::error(StatusCode::NoCapacity, "commit record too large");
    }
    std::memcpy(commit_.data(), record.data, record.size);
    commit_size_ = record.size;
    return Status::success();
  }
  Status read_commit_record(const MutableByteView target,
                            std::size_t& out_size) noexcept override {
    if (commit_size_ == 0) {
      return Status::error(StatusCode::NotFound, "no commit record");
    }
    std::memcpy(target.data, commit_.data(), commit_size_);
    out_size = commit_size_;
    return Status::success();
  }
  Status write_active_record(const ByteView record) noexcept override {
    if (fail_writes || fail_active_writes) {
      return Status::error(StatusCode::StorageFailure, "injected write failure");
    }
    if (record.size > active_.size()) {
      return Status::error(StatusCode::NoCapacity, "active record too large");
    }
    std::memcpy(active_.data(), record.data, record.size);
    active_size_ = record.size;
    return Status::success();
  }
  Status read_active_record(const MutableByteView target,
                            std::size_t& out_size) noexcept override {
    if (active_size_ == 0) {
      return Status::error(StatusCode::NotFound, "no active record");
    }
    std::memcpy(target.data, active_.data(), active_size_);
    out_size = active_size_;
    return Status::success();
  }

  void erase_blob(const Digest256& hash) { (void)drop_blob(hash); }
  void erase_commit() { commit_size_ = 0; }
  void erase_active() { active_size_ = 0; }

  bool fail_writes{false};
  bool fail_active_writes{false};

 private:
  struct Blob {
    bool used{false};
    Digest256 hash{};
    std::array<std::uint8_t, migration_const::kPlanBlobMax> data{};
    std::size_t size{0};
  };
  Blob* find(const Digest256& hash) noexcept {
    for (auto& slot : blobs_) {
      if (slot.used && slot.hash == hash) return &slot;
    }
    return nullptr;
  }
  Blob* find_free() noexcept {
    for (auto& slot : blobs_) {
      if (!slot.used) return &slot;
    }
    return nullptr;
  }
  std::array<Blob, 2> blobs_{};
  std::array<std::uint8_t, migration_const::kCommitRecordSize> commit_{};
  std::size_t commit_size_{0};
  std::array<std::uint8_t, migration_const::kActiveRecordSize> active_{};
  std::size_t active_size_{0};
};

// --- scripted channel port + recording hooks --------------------------------------

class FakeChannelPort final : public ChannelPort {
 public:
  explicit FakeChannelPort(std::vector<std::string>& log) : log_(log) {}
  bool tx_quiesced() const noexcept override { return quiesced; }
  Status set_channel(std::uint8_t ch) noexcept override {
    log_.push_back("set:" + std::to_string(ch));
    ++set_calls;
    if (set_always_fail || set_calls >= set_fail_from) {
      return Status::error(StatusCode::RadioFailure, "scripted set failure");
    }
    channel = ch;
    return Status::success();
  }
  Status readback_channel(std::uint8_t& out) noexcept override {
    log_.push_back("readback");
    ++readback_calls;
    if (always_wrong_readback) {
      out = static_cast<std::uint8_t>(channel + 1);
      return Status::success();
    }
    out = channel;
    return Status::success();
  }
  Status reapply_peer_radio() noexcept override {
    log_.push_back("reapply");
    ++reapply_calls;
    if (reapply_fail) {
      return Status::error(StatusCode::RadioFailure, "scripted reapply failure");
    }
    return Status::success();
  }
  void fence_pending_tx() noexcept override {
    log_.push_back("fence");
    ++fence_calls;
    quiesced = true;  // fenced: no completion can still arrive
  }
  void committed_channel(std::uint8_t ch) noexcept override {
    log_.push_back("commit:" + std::to_string(ch));
    ++committed_calls;
    committed = ch;
  }

  std::vector<std::string>& log_;
  bool quiesced{true};
  bool always_wrong_readback{false};
  bool reapply_fail{false};
  bool set_always_fail{false};
  int set_fail_from{std::numeric_limits<int>::max()};
  std::uint8_t channel{1};
  std::uint8_t committed{0};
  int set_calls{0};
  int readback_calls{0};
  int reapply_calls{0};
  int fence_calls{0};
  int committed_calls{0};
};

class RecordingHooks final : public MigrationHooks {
 public:
  explicit RecordingHooks(std::vector<std::string>& log) : log_(log) {}
  void hold_data(bool held) noexcept override {
    log_.push_back(held ? "hold+" : "hold-");
    data_held = held;
  }
  void note_cutover_generation(std::uint32_t generation) noexcept override {
    log_.push_back("gen:" + std::to_string(generation));
    generations.push_back(generation);
  }
  void helper_visit(bool active, std::uint8_t old_channel) noexcept override {
    log_.push_back(active ? "helper+:" + std::to_string(old_channel)
                          : "helper-:" + std::to_string(old_channel));
    helper_active = active;
  }

  std::vector<std::string>& log_;
  std::vector<std::uint32_t> generations;
  bool data_held{false};
  bool helper_active{false};
};

// --- rig -----------------------------------------------------------------------------

constexpr MonotonicMs kNow = 1000;

struct Rig {
  Rig() {
    ledger.initialize();
    participant_config.node = kSelf;
    participant_config.network = kNet;
    participant_config.authority = kAuthority;
    participant_config.home_channel = 1;
    ops.home_channel = 1;
    ops.visit_hard_cap_ms = 1000;  // must cover the 800ms helper dwell
    ops.drain_budget_ms = 100;
  }

  // A valid plan: epoch `epoch` moves channel old->new at `switch_ref`
  // (authority domain; tests use identity mapping so it equals local time).
  MigrationPlan plan(std::uint32_t epoch, std::uint8_t old_ch,
                     std::uint8_t new_ch, MonotonicMs switch_ref,
                     std::uint64_t sequence) {
    MigrationPlan p{};
    p.network = kNet;
    p.authority = kAuthority;
    p.authority_generation = 1;
    p.operation_sequence = sequence;
    p.old_epoch = ChannelEpoch{epoch - 1};
    p.new_epoch = ChannelEpoch{epoch};
    p.old_channel = old_ch;
    p.new_channel = new_ch;
    p.participant_capability_mask = migration_const::kChannelMaskAll24;
    p.authority_session = 42;
    p.switch_reference_ms = switch_ref;
    p.mapping.peer_offset_ms = 0;   // identity mapping for the test world
    p.mapping.uncertainty_ms = 10;  // <= 20ms bound
    p.guard_ms = required_guard_ms(10, 50);
    p.expiry_ms = switch_ref + p.guard_ms + 120000;
    p.recovery.present = true;
    p.recovery.helpers[0] = 3;   // helper set never includes kSelf by
    p.recovery.helpers[1] = 4;   // default: tests opt in explicitly
    p.recovery.helper_count = 2;
    p.recovery.visit_period_ms = migration_const::kHelperVisitPeriodMs;
    p.recovery.dwell_ms = migration_const::kHelperDwellMs;
    p.recovery.window_begin_ms = switch_ref;
    p.recovery.window_end_ms =
        switch_ref + migration_const::kHelperBudgetMs;
    p.recovery.object_bytes_max = migration_const::kSnapshotMax;
    p.protected_services_mask = 1;
    p.max_outage_ms = 500;
    return p;
  }

  ByteView encode(const MigrationPlan& p, std::array<std::uint8_t, 512>& buf,
                  std::size_t& size) {
    const Status s = plan_encode(
        p, MutableByteView{buf.data(), buf.size()}, size);
    CHECK(s.ok());
    return ByteView{buf.data(), size};
  }

  AuthorityOperation operation(const MigrationPlan& p,
                               const Digest256& plan_hash,
                               const Digest256& previous_state_hash) {
    AuthorityOperation op{};
    op.network = kNet;
    op.authority = kAuthority;
    op.generation = p.authority_generation;
    op.sequence = p.operation_sequence;
    op.kind = AuthorityOperationKind::ChannelMigration;
    op.previous_state_hash = previous_state_hash;
    op.operation_hash = bind_operation_payload(
        AuthorityOperationKind::ChannelMigration,
        ByteView{plan_hash.data(), plan_hash.size()});
    return op;
  }

  PlanMeasurements measurements() {
    PlanMeasurements m{};
    m.management_rtt_p99_ms = 100;
    m.control_delivery_bound_ms = 0;
    m.required_transfer_ms = 1000;
    m.measured_switch_bound_ms = 50;
    return m;
  }

  FaultyLedgerStorage ledger_storage;
  SingleAuthority ledger{kNet, kAuthority, ledger_storage};
  TestCommitVerifier verifier;
  MigrationAuthorityConfig authority_config{kNet, kAuthority};
  // Issuer-side instance (holds the ledger) and a participant-side
  // verify-only instance (no ledger: it can never mint commits).
  std::vector<std::string> log;
  MemoryPlanStorage storage;
  FakeChannelPort port{log};
  ChannelOpsConfig ops;
  RecordingHooks hooks{log};
  MigrationParticipantConfig participant_config;

  MigrationAuthority issuer() {
    return MigrationAuthority(authority_config, verifier, &ledger);
  }
  MigrationAuthority verifier_only() {
    return MigrationAuthority(authority_config, verifier, nullptr);
  }
};

// Drive one full happy-path migration on `participant` starting at `now`.
void drive_full_migration(MigrationParticipant& participant,
                          ChannelOperationRunner& runner, Rig& rig,
                          const MigrationPlan& plan, ByteView blob,
                          const Digest256& plan_hash,
                          const AuthorityOperation& op,
                          MonotonicMs now) {
  CHECK_OK(participant.prepare(blob, rig.measurements(), now));
  CHECK(participant.phase() == ParticipantPhase::Preparing);
  // The signed plan's embedded mapping never arms the clock (issue #38):
  // only a fresh authenticated TimeSync does — identity mapping here.
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, now + 5));
  VerifiedAuthorityPlan token{};
  const Digest256 sig = sign_commit(op, plan_hash, plan.new_epoch);
  CHECK_OK(rig.verifier_only().verify_commit(
      op, plan_hash, plan.new_epoch,
      ByteView{sig.data(), sig.size()}, token));
  CHECK(token.valid() && token.experimental());  // dev profile = EXPERIMENTAL
  CHECK_OK(participant.commit(token, op, now + 10));
  CHECK(participant.phase() == ParticipantPhase::Committed);
  // Switch time (identity mapping) -> hold -> runner apply -> resume.
  participant.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  participant.poll(plan.switch_reference_ms + 2);
  CHECK(participant.phase() == ParticipantPhase::Verifying);
  // VERIFY closes on authenticated link activity on the new channel,
  // not on the timer alone.
  participant.note_link_activity(plan.switch_reference_ms + 3);
  CHECK(participant.phase() == ParticipantPhase::Stable);
}

// --- §6 storage order + verified commit (D5-01, D5-06) --------------------------------

void test_blob_alone_never_switches() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  CHECK(participant.phase() == ParticipantPhase::Preparing);
  // The plan's embedded mapping is stored but NEVER armed (issue #38).
  CHECK(!participant.clock_valid());
  // Scheduled switch time passes with no commit: nothing moves (D5-01).
  participant.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  participant.poll(plan.switch_reference_ms + 2);
  CHECK(rig.port.set_calls == 0);
  CHECK(rig.port.committed_calls == 0);
  CHECK(participant.active_channel() == 1);
  CHECK(participant.phase() == ParticipantPhase::Preparing);
  // Prepare deadline expiry -> ABORTED, active config kept.
  participant.poll(kNow + 30001);
  CHECK(participant.phase() == ParticipantPhase::Aborted);
  CHECK(participant.stats().aborts == 1);
  CHECK(participant.active_channel() == 1);
}

void test_commit_without_blob_refetches() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  // Verified commit arrives before any blob: the record is stored and the
  // node enters recovery to REFETCH — never fabricating config (04 §6).
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow));
  CHECK(participant.phase() == ParticipantPhase::Recovering);
  CHECK(participant.committed_epoch() == plan.new_epoch);
  participant.poll(kNow + 100);
  runner.poll(kNow + 100);
  CHECK(rig.port.set_calls == 0);  // no blob -> no switch
  // A blob whose digest does not match the commit is refused.
  MigrationPlan other = rig.plan(2, 1, 11, 7500, 2);
  std::array<std::uint8_t, 512> buf2{};
  std::size_t size2 = 0;
  const ByteView wrong = rig.encode(other, buf2, size2);
  CHECK(participant.prepare(wrong, rig.measurements(), kNow + 200).code ==
        StatusCode::IntegrityError);
  // The referenced blob completes the stored commit -> Committed -> follow.
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow + 200));
  CHECK(participant.phase() == ParticipantPhase::Committed);
  // The timed switch waits on an authenticated clock, never on the plan's
  // embedded mapping — arm, then the committed plan follows its schedule.
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 300));
  participant.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  participant.poll(plan.switch_reference_ms + 2);
  CHECK(participant.phase() == ParticipantPhase::Verifying);
  CHECK(rig.port.committed == 6);
}

void test_verified_plan_only() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));

  // A default-constructed token is not proof of anything.
  VerifiedAuthorityPlan forged{};
  CHECK(!forged.valid());
  CHECK(participant.commit(forged, op, kNow + 10).code ==
        StatusCode::AuthenticationFailed);
  CHECK(participant.phase() == ParticipantPhase::Preparing);

  // Forged signature bytes fail the REAL verification — no commit.
  Digest256 bad_sig{};
  bad_sig[0] = 0xEE;
  CHECK(participant.note_commit_evidence(
            op, hash, plan.new_epoch, ByteView{bad_sig.data(), bad_sig.size()},
            kNow + 10)
            .code == StatusCode::AuthenticationFailed);
  CHECK(participant.phase() == ParticipantPhase::Preparing);
  CHECK(participant.stats().commit_rejects == 2);

  // Signature over the WRONG blob hash also fails (binding is checked).
  Digest256 wrong_hash{};
  wrong_hash[0] = 0xAA;
  AuthorityOperation bound_wrong = rig.operation(plan, wrong_hash, Digest256{});
  const Digest256 sig_wrong = sign_commit(bound_wrong, wrong_hash, plan.new_epoch);
  CHECK(participant.note_commit_evidence(
            bound_wrong, wrong_hash, plan.new_epoch,
            ByteView{sig_wrong.data(), sig_wrong.size()}, kNow + 10)
            .code == StatusCode::IntegrityError);
  CHECK(participant.phase() == ParticipantPhase::Preparing);

  // The real commit evidence is accepted — and the verifier ran (no fixed
  // boolean pass: verify_commit actually checked the MAC).
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow + 10));
  CHECK(rig.verifier.commit_checks >= 3);
  CHECK(participant.phase() == ParticipantPhase::Committed);
  CHECK(participant.committed_epoch() == plan.new_epoch);
  CHECK(participant.active_epoch() != plan.new_epoch);  // not applied yet
}

// --- §7 participant-set gating (D5-09) ---------------------------------------------------

void test_required_set_gating() {
  // READY required set -> permitted.
  ParticipantReadiness set[4]{};
  set[0].node = 3; set[0].required = true; set[0].answered = true;
  set[0].ready = true;
  set[1].node = 4; set[1].required = true; set[1].answered = true;
  set[1].ready = true;
  RequiredSetVerdict v = evaluate_required_set(set, 2, true);
  CHECK(v.commit_permitted && v.ready_count == 2);

  // Answered but not READY -> blocked.
  set[1].ready = false;
  v = evaluate_required_set(set, 2, true);
  CHECK(!v.commit_permitted && v.blocker == 4);
  CHECK(v.reason == StatusCode::WouldBlock);

  // Unanswered is never conveniently asleep: no lease -> blocked.
  set[1].answered = false;
  v = evaluate_required_set(set, 2, true);
  CHECK(!v.commit_permitted && v.blocker == 4);

  // Valid availability lease + rediscovery -> deferred set, permitted only
  // when the plan carries a committed recovery schedule.
  set[1].sleep_lease_valid = true;
  set[1].rediscovery_capable = true;
  v = evaluate_required_set(set, 2, true);
  CHECK(v.commit_permitted && v.deferred_count == 1);
  v = evaluate_required_set(set, 2, false);
  CHECK(!v.commit_permitted);  // requires_recovery_plan
  CHECK(v.reason == StatusCode::PlanNotCommitted);

  // A required legacy participant blocks outright — never reclassed.
  set[1].migration_capable = false;
  v = evaluate_required_set(set, 2, true);
  CHECK(!v.commit_permitted);
  CHECK(v.reason == StatusCode::LegacyParticipant);

  // Non-required legacy nodes do not block.
  ParticipantReadiness mixed[2]{};
  mixed[0].node = 3; mixed[0].required = true; mixed[0].answered = true;
  mixed[0].ready = true;
  mixed[1].node = 5; mixed[1].required = false;
  mixed[1].migration_capable = false;
  v = evaluate_required_set(mixed, 2, true);
  CHECK(v.commit_permitted);
}

void test_assess_survey_bookkeeping() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  CHECK_OK(participant.note_assess());
  CHECK(participant.phase() == ParticipantPhase::Assess);
  CHECK(participant.note_survey_end().code == StatusCode::InvalidState);
  CHECK_OK(participant.note_survey_begin());
  CHECK(participant.phase() == ParticipantPhase::Survey);
  CHECK_OK(participant.note_survey_end());
  CHECK(participant.phase() == ParticipantPhase::Stable);
  CHECK(participant.note_survey_begin().code == StatusCode::InvalidState);
}

// --- §8 clock + timing bounds ------------------------------------------------------------

void test_timing_bounds() {
  // Lead = max(5s, 4*RTT_P99, delivery bound): never "5s always enough".
  CHECK(required_commit_lead_ms(0, 0) == 5000);
  CHECK(required_commit_lead_ms(2000, 0) == 8000);
  CHECK(required_commit_lead_ms(100, 9000) == 9000);
  // Guard = max(100ms, 4*uncertainty + measured bound).
  CHECK(required_guard_ms(20, 0) == 100);
  CHECK(required_guard_ms(20, 30) == 110);
  // Recovery bound formula: H * ((loss+1)*period + transfer) + margin.
  CHECK(recovery_bound_ms(2, 1, 5000, 300, 1000) ==
        2 * (2 * 5000 + 300) + 1000);

  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  // Arm once so the now-relative COMMIT-lead check below is exercised — an
  // unarmed node skips it by design (authority time cannot be mapped).
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow));
  PlanMeasurements m = rig.measurements();
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;

  // Clock uncertainty over 20ms -> CLOCK_UNCERTAIN, never armed.
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  plan.mapping.uncertainty_ms = 21;
  ByteView blob = rig.encode(plan, buf, size);
  CHECK(participant.prepare(blob, m, kNow).code == StatusCode::ClockUncertain);
  CHECK(participant.phase() == ParticipantPhase::Stable);

  // Guard below the computed bound -> rejected.
  plan = rig.plan(1, 1, 6, 7500, 1);
  plan.guard_ms = 50;
  blob = rig.encode(plan, buf, size);
  CHECK(participant.prepare(blob, m, kNow).code == StatusCode::InvalidArgument);

  // Required management transfer cannot fit the standard 30s window ->
  // rejected, not squeezed.
  plan = rig.plan(1, 1, 6, 7500, 1);
  blob = rig.encode(plan, buf, size);
  PlanMeasurements heavy = m;
  heavy.required_transfer_ms = 31000;
  CHECK(participant.prepare(blob, heavy, kNow).code ==
        StatusCode::InvalidArgument);

  // Switch time too close for the computed commit lead -> rejected.
  plan = rig.plan(1, 1, 6, kNow + m.required_transfer_ms + 4999, 1);
  blob = rig.encode(plan, buf, size);
  CHECK(participant.prepare(blob, m, kNow).code == StatusCode::InvalidArgument);

  // Non-monotonic epoch -> rejected; epochs never rewind.
  plan = rig.plan(0, 1, 6, 7500, 1);  // new_epoch == committed (0)
  blob = rig.encode(plan, buf, size);
  CHECK(participant.prepare(blob, m, kNow).code == StatusCode::Conflict);

  // Wrong network/authority scope -> rejected.
  plan = rig.plan(1, 1, 6, 7500, 1);
  plan.authority = 77;
  blob = rig.encode(plan, buf, size);
  CHECK(participant.prepare(blob, m, kNow).code ==
        StatusCode::AuthorizationFailed);
}

// --- §8 cutover ordering (D5-05, X-02) -----------------------------------------------------

void test_cutover_sequence_order() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  drive_full_migration(participant, runner, rig, plan, blob, hash, op, kNow);
  CHECK(rig.port.committed == 6);
  CHECK(participant.active_channel() == 6);
  CHECK(participant.active_epoch() == plan.new_epoch);
  // Strict ordering: DATA hold -> set -> readback -> peer reapply ->
  // committed -> generation update -> DATA resume (04 §8).
  const std::vector<std::string> expected{
      "hold+", "set:6", "readback", "reapply", "commit:6", "gen:1", "hold-"};
  CHECK(rig.log == expected);
  CHECK(!rig.hooks.data_held);
}

void test_cutover_fence_and_late_callback() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  rig.ops.drain_budget_ms = 100;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  plan.guard_ms = 500;  // op deadline 8000, drain deadline 7600
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow + 10));
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 20));
  rig.port.quiesced = false;  // a TX completion is still in flight
  participant.poll(plan.switch_reference_ms + 1);
  CHECK(participant.phase() == ParticipantPhase::Switching);
  runner.poll(plan.switch_reference_ms + 1);  // drain wait (deadline +101)
  CHECK(rig.port.set_calls == 0);
  // Drain deadline (request time + 100ms budget): the straggler is fenced —
  // a late callback resolves as unknown, never fabricated success/failure
  // (X-02).
  runner.poll(plan.switch_reference_ms + 102);
  participant.poll(plan.switch_reference_ms + 102);
  CHECK(rig.port.fence_calls == 1);
  CHECK(participant.phase() == ParticipantPhase::Verifying);
  const std::vector<std::string> expected{"hold+", "fence",   "set:6",
                                        "readback", "reapply", "commit:6",
                                        "gen:1",  "hold-"};
  CHECK(rig.log == expected);
}

void test_cutover_indeterminate_and_failed() {
  {  // Readback mismatch AND restore unverifiable -> INDETERMINATE ->
     // RECOVERY_REQUIRED (channel state unknown; never assumed).
    Rig rig{};
    rig.ops.visit_hard_cap_ms = 1000;
    ChannelOperationRunner runner(rig.port, rig.ops);
    MigrationAuthority verify = rig.verifier_only();
    MigrationParticipant participant(rig.participant_config, rig.storage,
                                     verify, runner, &rig.hooks);
    MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
    std::array<std::uint8_t, 512> buf{};
    std::size_t size = 0;
    const ByteView blob = rig.encode(plan, buf, size);
    const Digest256 hash = plan_digest(blob);
    const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
    CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
    const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
    CHECK_OK(participant.note_commit_evidence(
        op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow));
    CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 10));
    rig.port.always_wrong_readback = true;
    participant.poll(plan.switch_reference_ms + 1);
    runner.poll(plan.switch_reference_ms + 1);
    participant.poll(plan.switch_reference_ms + 2);
    CHECK(participant.phase() == ParticipantPhase::RecoveryRequired);
    CHECK(participant.stats().recovery_required == 1);
    CHECK(!rig.hooks.data_held);
  }
  {  // set_channel refused: verified still on old channel -> RECOVERING,
     // one bounded re-follow of the held commit.
    Rig rig{};
    rig.ops.visit_hard_cap_ms = 1000;
    ChannelOperationRunner runner(rig.port, rig.ops);
    MigrationAuthority verify = rig.verifier_only();
    MigrationParticipant participant(rig.participant_config, rig.storage,
                                     verify, runner, &rig.hooks);
    MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
    std::array<std::uint8_t, 512> buf{};
    std::size_t size = 0;
    const ByteView blob = rig.encode(plan, buf, size);
    const Digest256 hash = plan_digest(blob);
    const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
    CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
    const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
    CHECK_OK(participant.note_commit_evidence(
        op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow));
    CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 10));
    rig.port.set_fail_from = 1;
    participant.poll(plan.switch_reference_ms + 1);
    runner.poll(plan.switch_reference_ms + 1);
    participant.poll(plan.switch_reference_ms + 2);
    CHECK(participant.phase() == ParticipantPhase::Recovering);
    // Recovering with the verified commit held: one re-follow attempt.
    rig.port.set_fail_from = 3;
    participant.poll(plan.switch_reference_ms + 3);
    runner.poll(plan.switch_reference_ms + 3);
    participant.poll(plan.switch_reference_ms + 4);
    CHECK(participant.phase() == ParticipantPhase::Verifying);
    CHECK(rig.port.committed == 6);
  }
}

// --- §9 helper schedule + recovery ----------------------------------------------------------

void test_helper_visit_schedule_and_budget() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;  // 800ms dwell must fit the cap
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  plan.recovery.helpers[0] = kSelf;  // this node IS a designated helper
  plan.recovery.helper_count = 2;
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  drive_full_migration(participant, runner, rig, plan, blob, hash, op, kNow);
  CHECK(participant.helper_role());  // node 2 is named in the helper set

  // Helper visits the OLD channel on the committed schedule: 5s period,
  // 800ms dwell, inside the 180s budget (04 §9.2). Windows at
  // 7500/12500/17500/22500 -> four visits consumed in the first 16s after
  // the switch (the first is issued during VERIFYING, which is allowed).
  for (MonotonicMs t = plan.switch_reference_ms;
       t < plan.switch_reference_ms + 16000; t += 100) {
    participant.poll(t);
    runner.poll(t);
  }
  CHECK(participant.stats().helper_visits == 4);
  // Every visit ended back on the new home channel — never a second domain.
  CHECK(rig.port.channel == 6);
  // Schedule reporting in local time: the next unexpired window.
  MonotonicMs begin = 0, end = 0;
  CHECK(participant.next_helper_window(plan.switch_reference_ms + 16000,
                                       begin, end));
  CHECK(begin == plan.switch_reference_ms + 20000 &&
        end == plan.switch_reference_ms + 20800);

  // Budget exhaustion: no visit past the committed window, and the helper
  // never becomes a permanent second channel.
  const MonotonicMs budget_end =
      plan.switch_reference_ms + migration_const::kHelperBudgetMs;
  for (MonotonicMs t = budget_end - 4000; t < budget_end + 10000; t += 100) {
    participant.poll(t);
    runner.poll(t);
  }
  CHECK(!participant.next_helper_window(budget_end + 1, begin, end));
  CHECK(rig.port.channel == 6);  // home = new channel; nothing parks on 1
  CHECK(participant.phase() == ParticipantPhase::Stable);
}

void test_verify_deadline_without_activity_recovers() {
  // 04 §10: VERIFY closes on authenticated link activity. A window that
  // expires with zero evidence is a verify FAILURE -> stranded-side
  // recovery, and crucially NOT a unilateral rollback to the old channel.
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow));
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 10));
  participant.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  participant.poll(plan.switch_reference_ms + 2);
  CHECK(participant.phase() == ParticipantPhase::Verifying);

  // Activity BEFORE Verifying is not evidence: the oracle only counts
  // frames observed while the verify window is open.
  // (note_link_activity is a no-op outside Verifying — asserted below by
  // the stats staying zero until the real call.)
  const MonotonicMs deadline = plan.switch_reference_ms + 2 +
                               rig.participant_config.verify_ms;
  participant.poll(deadline);
  CHECK(participant.phase() == ParticipantPhase::Recovering);
  CHECK(participant.stats().verify_failed == 1);
  CHECK(participant.stats().verify_passed == 0);
  // No unilateral rollback: the radio stays on the committed channel and
  // no second set_channel ran — only a new signed plan or helper rescue
  // may move the node.
  CHECK(rig.port.committed == 6);
  CHECK(rig.port.set_calls == 1);

  // Recovery is not a re-follow of the same commit (already applied):
  // polling onward keeps Recovering until the helper budget lapses.
  participant.poll(deadline + 5000);
  runner.poll(deadline + 5000);
  CHECK(participant.phase() == ParticipantPhase::Recovering);
}

void test_verify_activity_after_stable_is_ignored() {
  // A stale activity notification once the phase already closed must not
  // bump verify stats or reopen anything.
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow));
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 10));
  participant.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  participant.poll(plan.switch_reference_ms + 2);
  CHECK(participant.phase() == ParticipantPhase::Verifying);
  participant.note_link_activity(plan.switch_reference_ms + 3);
  CHECK(participant.phase() == ParticipantPhase::Stable);
  CHECK(participant.stats().verify_passed == 1);
  // Duplicate/late evidence after Stable is absorbed, not double-counted.
  participant.note_link_activity(plan.switch_reference_ms + 10);
  CHECK(participant.stats().verify_passed == 1);
  CHECK(participant.phase() == ParticipantPhase::Stable);
}

void test_stranded_node_recovery_via_snapshot() {
  // D5-02: a node that missed COMMIT stays on the old channel; a helper's
  // signed snapshot (latest commit + plan blob) brings it along.
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant stranded(rig.participant_config, rig.storage,
                                verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});

  RecoverySnapshot snap{};
  snap.operation = op;
  snap.plan_hash = hash;
  std::memcpy(snap.plan_blob.data(), blob.data, blob.size);
  snap.plan_blob_size = blob.size;
  std::array<std::uint8_t, migration_const::kSnapshotMax> snap_buf{};
  std::size_t snap_size = 0;
  CHECK_OK(snapshot_encode(snap, MutableByteView{snap_buf.data(),
                                               snap_buf.size()},
                           snap_size));
  const ByteView snap_bytes{snap_buf.data(), snap_size};

  // Forged snapshot: rejected, nothing moves.
  Digest256 bad_sig{};
  bad_sig[0] = 0x77;
  CHECK(stranded.adopt_snapshot(snap_bytes,
                                ByteView{bad_sig.data(), bad_sig.size()},
                                kNow)
            .code == StatusCode::AuthenticationFailed);
  CHECK(stranded.phase() == ParticipantPhase::Stable);

  // Tampered snapshot body signed by an attacker who can MAC the tampered
  // bytes but not the real key material — inside the test crypto model the
  // signature verifies, so rejection must come from the digest binding:
  // operation -> plan_hash -> blob must be self-consistent.
  std::array<std::uint8_t, migration_const::kSnapshotMax> tampered = snap_buf;
  tampered[snap_size - 1] ^= 0xFF;
  const Digest256 tam_sig =
      sign_snapshot(ByteView{tampered.data(), snap_size});
  CHECK(stranded.adopt_snapshot(
            ByteView{tampered.data(), snap_size},
            ByteView{tam_sig.data(), tam_sig.size()}, kNow)
            .code == StatusCode::IntegrityError);

  // Valid signed snapshot: store blob + commit -> Committed -> follow.
  const Digest256 sig = sign_snapshot(snap_bytes);
  CHECK_OK(stranded.adopt_snapshot(
      snap_bytes, ByteView{sig.data(), sig.size()}, kNow + 5000));
  CHECK(stranded.phase() == ParticipantPhase::Committed);
  CHECK(stranded.committed_epoch() == plan.new_epoch);
  // Snapshot adoption arms NO clock (issue #38, D5-03): the committed
  // node waits unarmed — honestly no timed switch — until a fresh
  // authenticated TimeSync.
  CHECK(!stranded.clock_valid());
  stranded.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  stranded.poll(plan.switch_reference_ms + 2);
  CHECK(rig.port.set_calls == 0);
  CHECK(stranded.phase() == ParticipantPhase::Committed);
  CHECK_OK(stranded.note_clock(ClockMapping{0, 10},
                               plan.switch_reference_ms + 3));
  stranded.poll(plan.switch_reference_ms + 4);
  runner.poll(plan.switch_reference_ms + 4);
  stranded.poll(plan.switch_reference_ms + 5);
  CHECK(stranded.phase() == ParticipantPhase::Verifying);
  CHECK(rig.port.committed == 6);

  // The same snapshot replayed after adoption is stale — epochs never
  // rewind.
  CHECK(stranded.adopt_snapshot(snap_bytes,
                                ByteView{sig.data(), sig.size()},
                                plan.switch_reference_ms + 10)
            .code == StatusCode::Conflict);
}

void test_recovery_bound_gate() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  // Bound must fit inside the committed 180s helper budget (04 §9.3).
  CHECK(participant.recovery_assumptions_satisfiable(3, 2, 500, 1000));
  CHECK(!participant.recovery_assumptions_satisfiable(50, 4, 5000, 1000));
}

void test_recovery_budget_exhaustion_required() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow));
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 10));
  // The cutover fails verifiably (driver always refuses): stranded on the
  // old channel with the commit held -> RECOVERING, one bounded re-follow.
  rig.port.set_always_fail = true;
  participant.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  participant.poll(plan.switch_reference_ms + 2);
  CHECK(participant.phase() == ParticipantPhase::Recovering);
  // The single re-follow also fails: no retry loop, just recovery waiting.
  participant.poll(plan.switch_reference_ms + 3);
  runner.poll(plan.switch_reference_ms + 3);
  participant.poll(plan.switch_reference_ms + 4);
  CHECK(participant.phase() == ParticipantPhase::Recovering);
  participant.poll(plan.switch_reference_ms + 5);
  runner.poll(plan.switch_reference_ms + 5);
  participant.poll(plan.switch_reference_ms + 6);
  CHECK(participant.phase() == ParticipantPhase::Recovering);
  // The committed helper budget lapses without rescue (04 §9.3): the
  // strong recovery SLO is over -> RECOVERY_REQUIRED, terminal.
  const MonotonicMs end =
      plan.switch_reference_ms + migration_const::kHelperBudgetMs;
  participant.poll(end + 1);
  CHECK(participant.phase() == ParticipantPhase::RecoveryRequired);
  CHECK(participant.stats().recovery_required == 1);
  participant.poll(end + 1000);
  CHECK(participant.phase() == ParticipantPhase::RecoveryRequired);
}

// --- resume / restart (D5-03, D5-06) ---------------------------------------------------------

void test_resume_committed_apply_on_resume() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow));

  // Cold restart after COMMIT but before the switch: the stored monotonic
  // mapping is NEVER reused — the clock stays disarmed, so no timed switch
  // happens until a fresh authenticated sample re-arms it (D5-03).
  FakeChannelPort port2{rig.log};
  ChannelOperationRunner runner2(port2, rig.ops);
  MigrationParticipant resumed(rig.participant_config, rig.storage,
                               verify, runner2, &rig.hooks);
  CHECK_OK(resumed.resume(plan.switch_reference_ms + 5));
  CHECK(resumed.phase() == ParticipantPhase::Committed);
  CHECK(!resumed.clock_valid());
  resumed.poll(plan.switch_reference_ms + 100);
  runner2.poll(plan.switch_reference_ms + 100);
  CHECK(port2.set_calls == 0);  // no blind switch without a clock
  ClockMapping fresh{};
  fresh.uncertainty_ms = 10;
  CHECK_OK(resumed.note_clock(fresh, plan.switch_reference_ms + 100));
  resumed.poll(plan.switch_reference_ms + 101);
  runner2.poll(plan.switch_reference_ms + 101);
  resumed.poll(plan.switch_reference_ms + 102);
  CHECK(resumed.phase() == ParticipantPhase::Verifying);
  CHECK(port2.committed == 6);  // apply-on-resume via the verified commit

  // An over-bound clock sample must not arm the clock (D5-03).
  FakeChannelPort port3{rig.log};
  ChannelOperationRunner runner3(port3, rig.ops);
  MigrationParticipant resumed2(rig.participant_config, rig.storage,
                                verify, runner3, &rig.hooks);
  CHECK_OK(resumed2.resume(plan.switch_reference_ms + 200));
  ClockMapping bad{};
  bad.uncertainty_ms = 25;
  CHECK(resumed2.note_clock(bad, plan.switch_reference_ms + 200).code ==
        StatusCode::ClockUncertain);
  CHECK(!resumed2.clock_valid());
}

void test_resume_missing_blob_and_active_loss() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  drive_full_migration(participant, runner, rig, plan, blob, hash, op, kNow);
  CHECK(participant.active_channel() == 6);

  // Case A: commit record references a blob that is gone -> Recovering
  // (refetch/quarantine), never fabricating config.
  {
    Rig rig2{};
    rig2.ops.visit_hard_cap_ms = 1000;
    ChannelOperationRunner r2(rig2.port, rig2.ops);
    MigrationAuthority v2 = rig2.verifier_only();
    MigrationParticipant p2(rig2.participant_config, rig2.storage,
                            v2, r2, &rig2.hooks);
    CHECK_OK(p2.prepare(blob, rig2.measurements(), kNow));
    const Digest256 sig2 = sign_commit(op, hash, plan.new_epoch);
    CHECK_OK(p2.note_commit_evidence(
        op, hash, plan.new_epoch, ByteView{sig2.data(), sig2.size()}, kNow));
    rig2.storage.erase_blob(hash);
    MigrationParticipant p2r(rig2.participant_config, rig2.storage,
                             v2, r2, &rig2.hooks);
    CHECK_OK(p2r.resume(kNow + 50));
    CHECK(p2r.phase() == ParticipantPhase::Recovering);
    CHECK(p2r.stats().blob_refetches == 1);
    // Refetching the referenced blob completes the stored commit.
    CHECK_OK(p2r.prepare(blob, rig2.measurements(), kNow + 100));
    CHECK(p2r.phase() == ParticipantPhase::Committed);
  }

  // Case B: driver applied, then ONLY the active record was lost -> the
  // stored commit re-applies idempotently; the epoch never downgrades.
  {
    Rig rig3{};
    rig3.ops.visit_hard_cap_ms = 1000;
    ChannelOperationRunner r3(rig3.port, rig3.ops);
    MigrationAuthority v3 = rig3.verifier_only();
    MigrationParticipant p3(rig3.participant_config, rig3.storage,
                            v3, r3, &rig3.hooks);
    drive_full_migration(p3, r3, rig3, plan, blob, hash, op, kNow);
    rig3.storage.erase_active();
    MigrationParticipant p3r(rig3.participant_config, rig3.storage,
                             v3, r3, &rig3.hooks);
    // Re-apply must happen inside the plan's signed validity window
    // (expiry = switch + guard + 120s): resume well inside it.
    CHECK_OK(p3r.resume(kNow + 50000));
    CHECK(p3r.phase() == ParticipantPhase::Committed);  // re-apply pending
    CHECK(p3r.committed_epoch() == plan.new_epoch);
    ClockMapping fresh{};
    fresh.uncertainty_ms = 10;
    CHECK_OK(p3r.note_clock(fresh, kNow + 50000));
    p3r.poll(kNow + 50001);
    r3.poll(kNow + 50001);
    p3r.poll(kNow + 50002);
    CHECK(p3r.phase() == ParticipantPhase::Verifying);
    CHECK(p3r.active_epoch() == plan.new_epoch);  // idempotent, not rewound
    CHECK(rig3.port.committed == 6);
  }
}

// --- issuer: cooldown / rollback / authority stop (04 §5, §10; D5-04) ----------------

void test_issuer_commit_and_cooldown() {
  Rig rig{};
  MigrationAuthority issuer = rig.issuer();
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  VerifiedAuthorityPlan token{};

  // A VALIDLY-SIGNED but degenerate plan is refused at the issuer: the
  // same structural bar as every adoption path (D5-02 — no bypass for
  // the authority itself). old==new channel and an expiry that precedes
  // the guarded switch both fail before the ledger is touched.
  MigrationPlan degenerate = rig.plan(9, 1, 1, 7500, 1);
  std::array<std::uint8_t, 512> bufd{};
  std::size_t dsize = 0;
  const ByteView dblob = rig.encode(degenerate, bufd, dsize);
  const Digest256 dhash = plan_digest(dblob);
  const AuthorityOperation dop = rig.operation(degenerate, dhash, Digest256{});
  const Digest256 dsig = sign_commit(dop, dhash, degenerate.new_epoch);
  CHECK(issuer.commit_plan(degenerate, dblob, dop,
                           ByteView{dsig.data(), dsig.size()}, dhash, false,
                           kNow, token)
            .code == StatusCode::InvalidArgument);
  CHECK(!token.valid());
  MigrationPlan expired = rig.plan(9, 1, 6, 7500, 1);
  expired.expiry_ms = expired.switch_reference_ms;  // no room for guard
  std::array<std::uint8_t, 512> bufe{};
  std::size_t esize = 0;
  const ByteView eblob = rig.encode(expired, bufe, esize);
  const Digest256 ehash = plan_digest(eblob);
  const AuthorityOperation eop = rig.operation(expired, ehash, Digest256{});
  const Digest256 esig = sign_commit(eop, ehash, expired.new_epoch);
  CHECK(issuer.commit_plan(expired, eblob, eop,
                           ByteView{esig.data(), esig.size()}, ehash, false,
                           kNow, token)
            .code == StatusCode::InvalidArgument);
  CHECK(rig.ledger.state().applied_sequence == 0);  // nothing committed

  CHECK_OK(issuer.commit_plan(plan, blob, op,
                              ByteView{sig.data(), sig.size()}, hash, false,
                              kNow, token));
  CHECK(token.valid());
  CHECK(token.plan_hash() == hash);
  CHECK(issuer.last_committed_epoch() == plan.new_epoch);
  CHECK(rig.ledger.state().applied_sequence == 1);
  CHECK(rig.verifier.commit_checks == 1);  // real check ran, no fixed pass

  // A second normal plan inside the cooldown window is refused.
  issuer.note_plan_terminal(true, kNow + 40000);
  MigrationPlan plan2 = rig.plan(2, 6, 11, 80000, 2);
  std::array<std::uint8_t, 512> buf2{};
  std::size_t size2 = 0;
  const ByteView blob2 = rig.encode(plan2, buf2, size2);
  const Digest256 hash2 = plan_digest(blob2);
  AuthorityOperation op2 = rig.operation(plan2, hash2, hash);
  const Digest256 sig2 = sign_commit(op2, hash2, plan2.new_epoch);
  CHECK(issuer.commit_plan(plan2, blob2, op2,
                           ByteView{sig2.data(), sig2.size()}, hash2, false,
                           kNow + 41000, token)
            .code == StatusCode::Busy);
  // After the 600s cooldown the next plan commits.
  CHECK_OK(issuer.commit_plan(plan2, blob2, op2,
                              ByteView{sig2.data(), sig2.size()}, hash2, false,
                              kNow + 40000 + 600001, token));
}

void test_rollback_requires_new_epoch_and_credit() {
  Rig rig{};
  MigrationAuthority issuer = rig.issuer();
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  VerifiedAuthorityPlan token{};
  CHECK_OK(issuer.commit_plan(plan, blob, op,
                              ByteView{sig.data(), sig.size()}, hash, false,
                              kNow, token));

  // Rollback before the plan terminally fails: no credit -> refused. There
  // is no unilateral path.
  MigrationPlan back = rig.plan(2, 6, 1, 60000, 2);
  std::array<std::uint8_t, 512> buf2{};
  std::size_t size2 = 0;
  const ByteView blob2 = rig.encode(back, buf2, size2);
  const Digest256 hash2 = plan_digest(blob2);
  AuthorityOperation op2 = rig.operation(back, hash2, hash);
  const Digest256 sig2 = sign_commit(op2, hash2, back.new_epoch);
  CHECK(issuer.commit_plan(back, blob2, op2,
                           ByteView{sig2.data(), sig2.size()}, hash2, true,
                           kNow + 1000, token)
            .code == StatusCode::InvalidState);

  // Plan failed -> exactly ONE automatic rollback credit, needing a new
  // authority operation AND a new channel epoch.
  issuer.note_plan_terminal(false, kNow + 40000);
  CHECK_OK(issuer.commit_plan(back, blob2, op2,
                              ByteView{sig2.data(), sig2.size()}, hash2, true,
                              kNow + 41000, token));
  // A second automatic rollback for the same failed plan is refused;
  // cooldown + diagnostics follow (04 §10).
  MigrationPlan back2 = rig.plan(3, 1, 6, 90000, 3);
  std::array<std::uint8_t, 512> buf3{};
  std::size_t size3 = 0;
  const ByteView blob3 = rig.encode(back2, buf3, size3);
  const Digest256 hash3 = plan_digest(blob3);
  AuthorityOperation op3 = rig.operation(back2, hash3, hash2);
  const Digest256 sig3 = sign_commit(op3, hash3, back2.new_epoch);
  CHECK(issuer.commit_plan(back2, blob3, op3,
                           ByteView{sig3.data(), sig3.size()}, hash3, true,
                           kNow + 42000, token)
            .code == StatusCode::InvalidState);

  // A rollback that does not advance the epoch is rejected regardless.
  Rig rig4{};
  MigrationAuthority issuer4 = rig4.issuer();
  CHECK_OK(issuer4.commit_plan(plan, blob, op,
                               ByteView{sig.data(), sig.size()}, hash, false,
                               kNow, token));
  issuer4.note_plan_terminal(false, kNow + 40000);
  MigrationPlan same_epoch = rig4.plan(1, 6, 1, 60000, 2);
  std::array<std::uint8_t, 512> buf4{};
  std::size_t size4 = 0;
  const ByteView blob4 = rig4.encode(same_epoch, buf4, size4);
  const Digest256 hash4 = plan_digest(blob4);
  AuthorityOperation op4 = rig4.operation(same_epoch, hash4, hash);
  const Digest256 sig4 = sign_commit(op4, hash4, same_epoch.new_epoch);
  CHECK(issuer4.commit_plan(same_epoch, blob4, op4,
                            ByteView{sig4.data(), sig4.size()}, hash4, true,
                            kNow + 41000, token)
            .code == StatusCode::Conflict);  // EPOCH_NOT_MONOTONIC
}

void test_authority_stopped() {
  Rig rig{};
  MigrationAuthority issuer = rig.issuer();
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  VerifiedAuthorityPlan token{};
  CHECK_OK(issuer.commit_plan(plan, blob, op,
                              ByteView{sig.data(), sig.size()}, hash, false,
                              kNow, token));

  // Authority stopped: NO new commits (D5-04). A failed issue clears its
  // out-token — use scratch tokens so the valid one survives.
  issuer.set_available(false);
  MigrationPlan plan2 = rig.plan(2, 6, 11, 80000, 2);
  std::array<std::uint8_t, 512> buf2{};
  std::size_t size2 = 0;
  const ByteView blob2 = rig.encode(plan2, buf2, size2);
  const Digest256 hash2 = plan_digest(blob2);
  AuthorityOperation op2 = rig.operation(plan2, hash2, hash);
  const Digest256 sig2 = sign_commit(op2, hash2, plan2.new_epoch);
  VerifiedAuthorityPlan scratch{};
  CHECK(issuer.commit_plan(plan2, blob2, op2,
                           ByteView{sig2.data(), sig2.size()}, hash2, false,
                           kNow + 1000, scratch)
            .code == StatusCode::ApprovalRequired);
  CHECK(!scratch.valid());

  // But signed material still verifies: a participant-side verify-only
  // instance accepts the already-issued commit — and the committed plan
  // keeps executing to cutover.
  MigrationAuthority verify = rig.verifier_only();
  verify.set_available(false);  // verifier-side authority also down
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  CHECK_OK(participant.commit(token, op, kNow + 10));
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 20));
  participant.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  participant.poll(plan.switch_reference_ms + 2);
  CHECK(participant.phase() == ParticipantPhase::Verifying);
  CHECK(rig.port.committed == 6);

  // A verify-only instance (no ledger) can never mint a commit even when
  // everything else is well-formed — a gateway gains no approval right.
  MigrationAuthority noledger = rig.verifier_only();
  CHECK(noledger.commit_plan(plan, blob, op,
                             ByteView{sig.data(), sig.size()}, hash, false,
                             kNow, scratch)
            .code == StatusCode::InvalidState);

  // An unavailable verifier means NO verified plan at all.
  Rig rig5{};
  MigrationAuthority dead = rig5.issuer();
  rig5.verifier.ready_ = false;
  CHECK(dead.commit_plan(plan, blob, op,
                         ByteView{sig.data(), sig.size()}, hash, false,
                         kNow, scratch)
            .code == StatusCode::AuthProfileUnavailable);
}

void test_participant_cooldown_after_abort() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  participant.poll(kNow + 30001);  // prepare timeout -> Aborted
  CHECK(participant.phase() == ParticipantPhase::Aborted);
  // A new plan inside the 600s cooldown is refused — failures never
  // ping-pong (04 §10). Same epoch-1 shape: the aborted plan never
  // committed, so the fresh plan still starts from epoch 0. The switch
  // reference stays comfortably in the future so the commit-lead gate
  // is not the thing being exercised.
  MigrationPlan plan2 = rig.plan(1, 1, 11, kNow + 800000, 1);
  std::array<std::uint8_t, 512> buf2{};
  std::size_t size2 = 0;
  const ByteView blob2 = rig.encode(plan2, buf2, size2);
  CHECK(participant.prepare(blob2, rig.measurements(), kNow + 60000).code ==
        StatusCode::Busy);
  CHECK_OK(participant.prepare(blob2, rig.measurements(),
                               kNow + 30001 + 600001));
}

void test_in_progress_excludes_concurrent_ops() {
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  CHECK(!participant.in_progress());
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  CHECK(participant.in_progress());  // key rotation / OTA / authority change excluded
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow));
  CHECK(participant.in_progress());
}

// --- #38: the clock is armed only by authenticated TimeSync -------------------------

void test_plan_blob_never_arms_clock() {
  // Issue #38 defect 1: the mapping inside the signed plan is the issuer's
  // clock — adopting it armed every receiver to the AUTHORITY's offset.
  // prepare() stores the blob only; a fresh authenticated TimeSync is the
  // sole arming path (D5-03).
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  CHECK(!participant.clock_valid());  // blob stored, clock unarmed
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow + 10));
  CHECK(participant.phase() == ParticipantPhase::Committed);
  // The scheduled instant passes with no authenticated clock: honestly no
  // switch — previously the plan's mapping would have (mis)timed it.
  participant.poll(plan.switch_reference_ms + 1);
  runner.poll(plan.switch_reference_ms + 1);
  participant.poll(plan.switch_reference_ms + 2);
  CHECK(rig.port.set_calls == 0);
  CHECK(participant.phase() == ParticipantPhase::Committed);
  // A fresh authority TimeSync arms the clock and the committed plan
  // follows its schedule.
  CHECK_OK(participant.note_clock(ClockMapping{0, 10},
                                  plan.switch_reference_ms + 3));
  participant.poll(plan.switch_reference_ms + 4);
  runner.poll(plan.switch_reference_ms + 4);
  participant.poll(plan.switch_reference_ms + 5);
  CHECK(participant.phase() == ParticipantPhase::Verifying);
  CHECK(rig.port.committed == 6);
}

void test_expired_plan_demotes_committed() {
  // Issue #38 defect 3: plan.expiry_ms was never checked at runtime — an
  // expired commit could still cut over. An armed node past the signed
  // validity bound now demotes to recovery instead of switching.
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow + 10));
  CHECK_OK(participant.note_clock(ClockMapping{0, 10}, kNow + 20));
  CHECK(participant.phase() == ParticipantPhase::Committed);
  // Past the signed expiry: no cutover — the node demotes to recovery.
  participant.poll(plan.expiry_ms + 1);
  runner.poll(plan.expiry_ms + 1);
  participant.poll(plan.expiry_ms + 2);
  CHECK(rig.port.set_calls == 0);
  CHECK(participant.phase() == ParticipantPhase::Recovering);
  // And once the committed helper budget lapses without rescue, the
  // terminal recovery violation lands (04 §9.3).
  participant.poll(plan.switch_reference_ms +
                   migration_const::kHelperBudgetMs + 1);
  CHECK(participant.phase() == ParticipantPhase::RecoveryRequired);
  CHECK(participant.stats().recovery_required == 1);
}

void test_unarmed_committed_wedge_bound() {
  // Issue #38 defect 4: an unarmed Committed node could hold a verified
  // plan forever. The derived bound — Committed entry +
  // (expiry - switch_reference) + guard — demotes it to scout recovery
  // instead (04 §9.2).
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  MigrationPlan plan = rig.plan(1, 1, 6, 7500, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  CHECK_OK(participant.prepare(blob, rig.measurements(), kNow));
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow + 10));
  CHECK(participant.phase() == ParticipantPhase::Committed);
  CHECK(!participant.clock_valid());
  const MonotonicMs bound = kNow + 10 +
                            (plan.expiry_ms - plan.switch_reference_ms) +
                            plan.guard_ms;
  // Inside the bound: Committed, unarmed, honestly nothing cut.
  participant.poll(bound - 1);
  CHECK(participant.phase() == ParticipantPhase::Committed);
  CHECK(rig.port.set_calls == 0);
  // Bound lapsed with no authenticated clock -> scout recovery.
  participant.poll(bound);
  CHECK(participant.phase() == ParticipantPhase::Recovering);
  CHECK(rig.port.set_calls == 0);
}

void test_armed_commit_lead_and_unarmed_skip() {
  // The COMMIT-lead feasibility check runs through the node's OWN armed
  // mapping in the authority domain — a node whose monotonic clock sits
  // far behind the authority's evaluates the same plan honestly. Under
  // the old design the plan's embedded mapping WAS everyone's mapping.
  Rig rig{};
  rig.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner(rig.port, rig.ops);
  MigrationAuthority verify = rig.verifier_only();
  MigrationParticipant participant(rig.participant_config, rig.storage,
                                   verify, runner, &rig.hooks);
  // Authority clock 60s ahead of this node's monotonic clock.
  CHECK_OK(participant.note_clock(ClockMapping{60000, 10}, kNow));
  const PlanMeasurements m = rig.measurements();
  // need = required_transfer (1s) + commit lead (5s) = 6s.
  const MonotonicMs now_auth = kNow + 60000;  // this node maps to here
  // Inside the lead in the AUTHORITY domain -> refused. plan.mapping
  // (identity) would have accepted this — wrong clock, wrong answer.
  MigrationPlan tight = rig.plan(1, 1, 6, now_auth + 5999, 1);
  std::array<std::uint8_t, 512> buf2{};
  std::size_t size2 = 0;
  const ByteView tight_blob = rig.encode(tight, buf2, size2);
  CHECK(participant.prepare(tight_blob, m, kNow).code ==
        StatusCode::InvalidArgument);
  CHECK(participant.phase() == ParticipantPhase::Stable);
  // Comfortably past the lead in the AUTHORITY domain -> accepted.
  MigrationPlan plan = rig.plan(1, 1, 6, now_auth + 30000, 1);
  std::array<std::uint8_t, 512> buf{};
  std::size_t size = 0;
  const ByteView blob = rig.encode(plan, buf, size);
  CHECK_OK(participant.prepare(blob, m, kNow));
  // The armed node then follows the switch at its own mapped local
  // instant: switch_local = (now_auth + 30000) - 60000.
  const Digest256 hash = plan_digest(blob);
  const AuthorityOperation op = rig.operation(plan, hash, Digest256{});
  const Digest256 sig = sign_commit(op, hash, plan.new_epoch);
  CHECK_OK(participant.note_commit_evidence(
      op, hash, plan.new_epoch, ByteView{sig.data(), sig.size()}, kNow + 10));
  const MonotonicMs switch_local = now_auth + 30000 - 60000;
  participant.poll(switch_local + 1);
  runner.poll(switch_local + 1);
  participant.poll(switch_local + 2);
  CHECK(participant.phase() == ParticipantPhase::Verifying);
  CHECK(rig.port.committed == 6);

  // An UNARMED node cannot compute the lead at all — the check is skipped
  // and the stored-blob path proceeds (bounded by plan expiry instead).
  Rig rig2{};
  rig2.ops.visit_hard_cap_ms = 1000;
  ChannelOperationRunner runner2(rig2.port, rig2.ops);
  MigrationAuthority verify2 = rig2.verifier_only();
  MigrationParticipant cold(rig2.participant_config, rig2.storage, verify2,
                            runner2, &rig2.hooks);
  CHECK_OK(cold.prepare(tight_blob, m, kNow));
  CHECK(cold.phase() == ParticipantPhase::Preparing);
}

}  // namespace

int main() {
  test_blob_alone_never_switches();
  test_commit_without_blob_refetches();
  test_verified_plan_only();
  test_required_set_gating();
  test_assess_survey_bookkeeping();
  test_timing_bounds();
  test_cutover_sequence_order();
  test_cutover_fence_and_late_callback();
  test_cutover_indeterminate_and_failed();
  test_helper_visit_schedule_and_budget();
  test_verify_deadline_without_activity_recovers();
  test_verify_activity_after_stable_is_ignored();
  test_stranded_node_recovery_via_snapshot();
  test_recovery_bound_gate();
  test_recovery_budget_exhaustion_required();
  test_resume_committed_apply_on_resume();
  test_resume_missing_blob_and_active_loss();
  test_issuer_commit_and_cooldown();
  test_rollback_requires_new_epoch_and_credit();
  test_authority_stopped();
  test_participant_cooldown_after_abort();
  test_in_progress_excludes_concurrent_ops();
  test_plan_blob_never_arms_clock();
  test_expired_plan_demotes_committed();
  test_unarmed_committed_wedge_bound();
  test_armed_commit_lead_and_unarmed_skip();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom channel-migration tests passed");
  return 0;
}
