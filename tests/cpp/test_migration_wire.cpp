// P5b migration transport/agent tests (docs/design/autonomous-mesh/
// 04-channel-migration.md §5-§9, contracts.json migration.*). Covers the
// object-content codecs, the bounded manifest/chunk/ack exchange and the
// MigrationAgent loop: PREPARE/READY/COMMIT in both directions, forged and
// unsigned evidence rejection, stale epochs, snapshot serving, durable
// commit-signature re-emission and restart reconcile. Every side effect
// goes through fakes; no Wire v1 bytes change — the exchange reuses the
// frozen control-object codecs.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <limits>
#include <string>
#include <vector>

#include "routeloom/authority.hpp"
#include "routeloom/autonomy_wire.hpp"
#include "routeloom/migration.hpp"
#include "routeloom/migration_wire.hpp"
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
constexpr NodeId kPeer = 3;
constexpr MonotonicMs kNow = 1000;

// --- deterministic test "crypto" (same model as test_migration.cpp) ---------

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
  bool ready() const noexcept override { return true; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  Status verify_commit(const AuthorityOperation& operation,
                       const Digest256& plan_hash, const ChannelEpoch new_epoch,
                       ByteView signature) noexcept override {
    const Digest256 expected = sign_commit(operation, plan_hash, new_epoch);
    if (signature.size != expected.size() ||
        std::memcmp(signature.data, expected.data(), expected.size()) != 0) {
      return Status::error(StatusCode::AuthenticationFailed, "bad signature");
    }
    return Status::success();
  }
  Status verify_snapshot(ByteView snapshot,
                         ByteView signature) noexcept override {
    const Digest256 expected = sign_snapshot(snapshot);
    if (signature.size != expected.size() ||
        std::memcmp(signature.data, expected.data(), expected.size()) != 0) {
      return Status::error(StatusCode::AuthenticationFailed, "bad signature");
    }
    return Status::success();
  }
};

class MemoryPlanStorage final : public PlanStorage {
 public:
  Status write_blob(const Digest256& hash,
                    const ByteView blob) noexcept override {
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
    if (slot == nullptr) return Status::error(StatusCode::NotFound, "absent");
    *slot = Blob{};
    return Status::success();
  }
  Status write_commit_record(const ByteView record) noexcept override {
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

class FakeChannelPort final : public ChannelPort {
 public:
  bool tx_quiesced() const noexcept override { return quiesced; }
  Status set_channel(std::uint8_t ch) noexcept override {
    ++set_calls;
    if (set_fail) {
      return Status::error(StatusCode::RadioFailure, "scripted set failure");
    }
    channel = ch;
    return Status::success();
  }
  Status readback_channel(std::uint8_t& out) noexcept override {
    if (wrong_readback) {
      out = static_cast<std::uint8_t>(channel + 1);
      return Status::success();
    }
    out = channel;
    return Status::success();
  }
  Status reapply_peer_radio() noexcept override {
    ++reapply_calls;
    return Status::success();
  }
  void fence_pending_tx() noexcept override { quiesced = true; }
  void committed_channel(std::uint8_t ch) noexcept override {
    committed = ch;
  }

  bool quiesced{true};
  bool set_fail{false};
  bool wrong_readback{false};
  std::uint8_t channel{1};
  std::uint8_t committed{0};
  int set_calls{0};
  int reapply_calls{0};
};

// --- fake wire port + bus ------------------------------------------------------

struct Captured {
  NodeId from{kInvalidNodeId};
  NodeId dest{kInvalidNodeId};
  FrameType type{FrameType::Data};
  std::array<std::uint8_t, kMaxApplicationPayload> data{};
  std::size_t size{0};
};

class FakeWirePort final : public MigrationWirePort {
 public:
  explicit FakeWirePort(NodeId self) : self_(self) {}
  Status migration_send(NodeId peer, FrameType type,
                        ByteView payload) noexcept override {
    if (block_sends) {
      return Status::error(StatusCode::WouldBlock, "scripted block");
    }
    if (payload.size > kMaxApplicationPayload) {
      return Status::error(StatusCode::InvalidArgument, "payload bound");
    }
    Captured frame{};
    frame.from = self_;
    frame.dest = peer;
    frame.type = type;
    frame.size = payload.size;
    std::memcpy(frame.data.data(), payload.data, payload.size);
    sent.push_back(frame);
    return Status::success();
  }
  std::size_t migration_peers(NodeId* out,
                              std::size_t capacity) const noexcept override {
    std::size_t count = 0;
    for (const NodeId peer : peers) {
      if (count >= capacity) break;
      out[count++] = peer;
    }
    return count;
  }

  NodeId self_;
  std::deque<Captured> sent;
  std::vector<NodeId> peers;
  bool block_sends{false};
};

// Deliver one captured frame to a sink the way the authenticated receive
// path would: MeshNode already opened + identity-checked the Wire frame;
// the migration sink sees (peer, type, payload).
void deliver(MigrationFrameSink& sink, const Captured& frame,
             MonotonicMs now_ms) {
  sink.on_migration_frame(frame.from, frame.type,
                          ByteView{frame.data.data(), frame.size}, now_ms);
}

// Push every captured frame from `source_wire` into `sink` the way the
// authenticated receive path would, then drop nothing else.
void flush_wire(FakeWirePort& source_wire, MigrationFrameSink& sink,
                MonotonicMs now_ms) {
  while (!source_wire.sent.empty()) {
    const Captured frame = source_wire.sent.front();
    source_wire.sent.pop_front();
    deliver(sink, frame, now_ms);
  }
}

class CollectingSink final : public MigrationObjectSink {
 public:
  void on_object(NodeId peer, autonomy::ControlObjectKind kind,
                 ByteView object, MonotonicMs now_ms) noexcept override {
    (void)now_ms;
    last_peer = peer;
    last_kind = kind;
    last_size = object.size;
    objects.push_back(std::vector<std::uint8_t>(object.data,
                                                object.data + object.size));
  }
  NodeId last_peer{kInvalidNodeId};
  autonomy::ControlObjectKind last_kind{
      autonomy::ControlObjectKind::ChannelPlan};
  std::size_t last_size{0};
  std::vector<std::vector<std::uint8_t>> objects;
};

class RecordingOwner final : public MigrationOwnerPort {
 public:
  void hold_data(bool held) noexcept override {
    held ? ++holds : ++releases;
    data_held = held;
  }
  void note_radio_generation(std::uint32_t generation) noexcept override {
    generations.push_back(generation);
  }
  void on_migration_event(const char* reason, NodeId peer) noexcept override {
    events.emplace_back(reason == nullptr ? "" : reason);
    (void)peer;
  }
  bool has_event(const char* needle) const {
    for (const auto& event : events) {
      if (event.find(needle) != std::string::npos) return true;
    }
    return false;
  }

  int holds{0};
  int releases{0};
  bool data_held{false};
  std::vector<std::uint32_t> generations;
  std::vector<std::string> events;
};

// --- agent rig ------------------------------------------------------------------


struct AgentRig {
  AgentRig(NodeId self, bool authority_role, ChannelCoordinator& coordinator)
      : wire(self),
        runner(port, ops),
        authority(authority_role
                      ? MigrationAuthority{MigrationAuthorityConfig{kNet,
                                                                   kAuthority},
                                           verifier, &ledger}
                      : MigrationAuthority{MigrationAuthorityConfig{kNet,
                                                                   kAuthority},
                                           verifier, nullptr}),
        agent(make_config(self, authority_role), wire, owner, storage,
              authority, runner, &coordinator) {
    (void)ledger.initialize();
  }

  static MigrationAgentConfig make_config(NodeId self, bool authority_role) {
    MigrationAgentConfig config{};
    config.participant.node = self;
    config.participant.network = kNet;
    config.participant.authority = kAuthority;
    config.participant.home_channel = 1;
    config.authority_role = authority_role;
    config.measurements.management_rtt_p99_ms = 100;
    config.measurements.control_delivery_bound_ms = 0;
    config.measurements.required_transfer_ms = 1000;
    config.measurements.measured_switch_bound_ms = 50;
    config.self_rediscovery_capable = true;
    config.timesync_period_ms = 5000;
    config.timesync_uncertainty_ms = 4;
    config.snapshot_request_period_ms = 500;
    if (authority_role) {
      config.required[0] = kSelf;  // the participant is the required set
      config.required_count = 1;
    }
    return config;
  }

  FakeWirePort wire;
  FakeChannelPort port;
  ChannelOpsConfig ops = [] {
    ChannelOpsConfig c{};
    c.home_channel = 1;
    c.visit_hard_cap_ms = migration_const::kHelperDwellMs;
    c.drain_budget_ms = 100;
    return c;
  }();
  ChannelOperationRunner runner;
  RecordingOwner owner;
  MemoryPlanStorage storage;
  FaultyLedgerStorage ledger_storage;
  SingleAuthority ledger{kNet, kAuthority, ledger_storage};
  TestCommitVerifier verifier;
  MigrationAuthority authority;
  MigrationAgent agent;
};

ChannelCoordinatorConfig coordinator_config(NodeId self) {
  ChannelCoordinatorConfig config{};
  config.node = self;
  config.home_channel = 1;
  return config;
}

MigrationPlan make_plan(std::uint32_t epoch, std::uint8_t old_ch,
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
  p.mapping.peer_offset_ms = 0;
  p.mapping.uncertainty_ms = 10;
  p.guard_ms = required_guard_ms(10, 50);
  p.expiry_ms = switch_ref + p.guard_ms + 120000;
  p.recovery.present = true;
  p.recovery.helpers[0] = 5;
  p.recovery.helper_count = 1;
  p.recovery.visit_period_ms = migration_const::kHelperVisitPeriodMs;
  p.recovery.dwell_ms = migration_const::kHelperDwellMs;
  p.recovery.window_begin_ms = switch_ref;
  p.recovery.window_end_ms = switch_ref + migration_const::kHelperBudgetMs;
  p.recovery.object_bytes_max = migration_const::kSnapshotMax;
  p.protected_services_mask = 1;
  p.max_outage_ms = 500;
  return p;
}

AuthorityOperation make_operation(const MigrationPlan& p,
                                  const Digest256& plan_hash) {
  AuthorityOperation op{};
  op.network = kNet;
  op.authority = kAuthority;
  op.generation = p.authority_generation;
  op.sequence = p.operation_sequence;
  op.kind = AuthorityOperationKind::ChannelMigration;
  op.previous_state_hash = Digest256{};
  op.operation_hash = bind_operation_payload(
      AuthorityOperationKind::ChannelMigration,
      ByteView{plan_hash.data(), plan_hash.size()});
  return op;
}

// Two-agent world: one authority-role agent (kAuthority) and one
// participant (kSelf) on a frame-level bus. pump() advances both agents,
// their serialized runners and the frame delivery exactly once.
struct AgentWorld {
  AgentWorld() {
    auth.wire.peers = {kSelf};
    part.wire.peers = {kAuthority};
    (void)auth.agent.resume(0);
    (void)part.agent.resume(0);
  }

  ChannelCoordinator coord_auth{coordinator_config(kAuthority)};
  ChannelCoordinator coord_part{coordinator_config(kSelf)};
  AgentRig auth{kAuthority, true, coord_auth};
  AgentRig part{kSelf, false, coord_part};

  void pump(MonotonicMs now) {
    auth.agent.poll(now);
    part.agent.poll(now);
    while (!auth.wire.sent.empty()) {
      const Captured frame = auth.wire.sent.front();
      auth.wire.sent.pop_front();
      if (frame.dest == kSelf) deliver(part.agent, frame, now);
    }
    while (!part.wire.sent.empty()) {
      const Captured frame = part.wire.sent.front();
      part.wire.sent.pop_front();
      if (frame.dest == kAuthority) deliver(auth.agent, frame, now);
    }
    auth.runner.poll(now);
    part.runner.poll(now);
  }
  void pump_n(MonotonicMs& now, int rounds, std::uint32_t step_ms = 5) {
    for (int i = 0; i < rounds; ++i) {
      pump(now);
      now += step_ms;
    }
  }
};

struct IssuedPlan {
  MigrationPlan plan{};
  std::array<std::uint8_t, migration_const::kPlanBlobMax> blob{};
  std::size_t blob_size{0};
  Digest256 plan_hash{};
  AuthorityOperation operation{};
  Digest256 signature{};
  std::array<std::uint8_t, migration_const::kSnapshotMax> snap{};
  std::size_t snap_size{0};
  Digest256 snap_sig{};
};

IssuedPlan issue_plan(std::uint32_t epoch, MonotonicMs switch_ref,
                      std::uint64_t sequence) {
  IssuedPlan issued{};
  issued.plan = make_plan(epoch, 1, 6, switch_ref, sequence);
  CHECK_OK(plan_encode(
      issued.plan, MutableByteView{issued.blob.data(), issued.blob.size()},
      issued.blob_size));
  issued.plan_hash =
      plan_digest(ByteView{issued.blob.data(), issued.blob_size});
  issued.operation = make_operation(issued.plan, issued.plan_hash);
  issued.signature = sign_commit(issued.operation, issued.plan_hash, issued.plan.new_epoch);
  RecoverySnapshot snapshot{};
  snapshot.operation = issued.operation;
  snapshot.plan_hash = issued.plan_hash;
  std::memcpy(snapshot.plan_blob.data(), issued.blob.data(),
              issued.blob_size);
  snapshot.plan_blob_size = issued.blob_size;
  CHECK_OK(snapshot_encode(
      snapshot, MutableByteView{issued.snap.data(), issued.snap.size()},
      issued.snap_size));
  issued.snap_sig =
      sign_snapshot(ByteView{issued.snap.data(), issued.snap_size});
  return issued;
}

// Drive one full authority->participant migration over the exchange loop:
// offer_plan (PREPARE) -> READY report -> release_commit (COMMIT) ->
// scheduled cutover -> VERIFY -> Applied result report -> terminal latch.
void test_agent_full_migration() {
  AgentWorld world;
  MonotonicMs now = kNow;
  // Epoch 1: a fresh participant sits at committed_epoch 0, so the plan's
  // old_epoch (epoch-1) must be 0 and old_channel the configured home 1 —
  // anything else is a genuine PLAN_BASE_MISMATCH.
  const IssuedPlan issued = issue_plan(1, now + 30000, 1);
  const Digest256 state_hash = sign_snapshot(ByteView{issued.blob.data(), 8});

  // Offer WITHOUT the recovery snapshot: the READY gate is exercised
  // cleanly (a distributed snapshot IS verified commit material — a node
  // adopting it commits early by design, which would skip the READY round).
  VerifiedAuthorityPlan token{};
  CHECK_OK(world.auth.agent.offer_plan(
      issued.plan, ByteView{issued.blob.data(), issued.blob_size},
      issued.operation, ByteView{issued.signature.data(), issued.signature.size()},
      state_hash, ByteView{}, ByteView{}, false, now, token));
  CHECK(token.valid() && token.experimental());
  CHECK(world.auth.agent.serving() == false);

  // PREPARE distribution + READY collection.
  world.pump_n(now, 30);
  CHECK(world.part.agent.participant().phase() == ParticipantPhase::Preparing);
  ParticipantReadiness readiness{};
  CHECK(world.auth.agent.readiness_of(kSelf, readiness));
  CHECK(readiness.ready);
  const RequiredSetVerdict verdict = world.auth.agent.readiness_verdict();
  CHECK(verdict.commit_permitted);

  // COMMIT release -> verified evidence -> participant commits durably.
  CHECK_OK(world.auth.agent.release_commit(now));
  world.pump_n(now, 30);
  CHECK(world.part.agent.participant().phase() == ParticipantPhase::Committed);
  CHECK(world.part.agent.participant().committed_epoch().value == 1);
  // The authority's own participant also committed.
  CHECK(world.auth.agent.participant().phase() == ParticipantPhase::Committed);
  // The commit record persisted the authority signature (04 §9.2 serving).
  std::array<std::uint8_t, migration_const::kCommitRecordSize> raw{};
  std::size_t raw_size = 0;
  CHECK_OK(world.part.storage.read_commit_record(
      MutableByteView{raw.data(), raw.size()}, raw_size));
  CommitRecord record{};
  CHECK_OK(commit_record_decode(ByteView{raw.data(), raw_size}, record));
  CHECK(record.present && record.signature_size == issued.signature.size());
  CHECK(std::memcmp(record.signature.data(), issued.signature.data(),
                    issued.signature.size()) == 0);

  // Scheduled cutover: jump to the switch instant, drive the ordered
  // hold -> drain -> fence -> set -> readback -> reapply -> commit.
  now = issued.plan.switch_reference_ms + 1;
  world.pump(now);
  world.pump(now + 1);
  CHECK(world.part.port.committed == 6);
  CHECK(world.part.runner.committed_channel() == 6);
  CHECK(world.part.agent.participant().phase() == ParticipantPhase::Verifying);
  CHECK(world.part.owner.holds >= 1 && world.part.owner.releases >= 1);
  CHECK(!world.part.owner.generations.empty());

  // Verify closes on authenticated link activity on the new channel
  // (any authenticated frame from a peer), not on the timer alone.
  world.pump_n(now, 10);
  world.part.agent.note_link_activity(kAuthority, now + 2);
  CHECK(world.part.agent.participant().phase() == ParticipantPhase::Stable);
  CHECK(world.part.agent.participant().stats().verify_passed == 1);
  CHECK(world.part.owner.has_event("VERIFY_PASSED"));
  now += 30000 + 5000;
  world.pump_n(now, 10);
  CHECK(world.part.agent.participant().active_epoch().value == 1);
  CHECK(world.auth.authority.cooldown_until() > now);
}

// A CommitEvidence object with a wrong signature must be rejected by the
// real verifier inside the engine — transport delivery grants no trust.
void test_agent_forged_commit_evidence() {
  AgentWorld world;
  MonotonicMs now = kNow;
  const IssuedPlan issued = issue_plan(1, now + 30000, 11);

  // Blob first so the participant is Preparing (clean reject assertion).
  std::array<std::uint8_t, migration_const::kPlanBlobMax + 1> blob_msg{};
  blob_msg[0] = static_cast<std::uint8_t>(PlanMessage::PlanBlob);
  std::memcpy(blob_msg.data() + 1, issued.blob.data(), issued.blob_size);
  CollectingSink scratch_sink{};
  FakeWirePort scratch_wire{kAuthority};
  PlanExchange scratch{PlanExchangeConfig{}, scratch_wire, scratch_sink};
  CHECK_OK(scratch.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                           ByteView{blob_msg.data(), issued.blob_size + 1},
                           now));
  for (int round = 0; round < 12; ++round) {
    scratch.poll(now, ExchangeChannel::Home);
    flush_wire(scratch_wire, world.part.agent, now);
    world.part.agent.poll(now);
    now += 5;
  }
  CHECK(world.part.agent.participant().phase() == ParticipantPhase::Preparing);

  // Forged evidence: real operation fields, garbage signature.
  CommitEvidence forged{};
  forged.operation = issued.operation;
  forged.plan_hash = issued.plan_hash;
  forged.new_epoch = issued.plan.new_epoch;
  forged.signature.fill(0xAAU);
  forged.signature_size = 32;
  std::array<std::uint8_t, migration_wire_const::kCommitEvidenceObjectMax>
      forged_msg{};
  forged_msg[0] = static_cast<std::uint8_t>(PlanMessage::CommitEvidence);
  std::size_t forged_size = 0;
  CHECK_OK(commit_evidence_encode(
      forged,
      MutableByteView{forged_msg.data() + 1, forged_msg.size() - 1},
      forged_size));
  CHECK_OK(scratch.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                           ByteView{forged_msg.data(), forged_size + 1}, now));
  for (int round = 0; round < 12; ++round) {
    scratch.poll(now, ExchangeChannel::Home);
    flush_wire(scratch_wire, world.part.agent, now);
    world.part.agent.poll(now);
    now += 5;
  }
  CHECK(world.part.owner.has_event("COMMIT_EVIDENCE_REJECTED"));
  CHECK(world.part.agent.participant().phase() == ParticipantPhase::Preparing);
  CHECK(world.part.agent.participant().committed_epoch().value == 0);
}

// A self-declared plan from the wrong authority never reaches PREPARED —
// the engine re-validates scope inside on_object.
void test_agent_wrong_authority_blob() {
  AgentWorld world;
  MonotonicMs now = kNow;
  MigrationPlan bad_plan = make_plan(1, 1, 6, now + 30000, 11);
  bad_plan.authority = kPeer;  // not the configured Authority
  std::array<std::uint8_t, migration_const::kPlanBlobMax> blob{};
  std::size_t blob_size = 0;
  CHECK_OK(plan_encode(bad_plan, MutableByteView{blob.data(), blob.size()},
                       blob_size));
  std::array<std::uint8_t, migration_const::kPlanBlobMax + 1> msg{};
  msg[0] = static_cast<std::uint8_t>(PlanMessage::PlanBlob);
  std::memcpy(msg.data() + 1, blob.data(), blob_size);
  CollectingSink scratch_sink{};
  FakeWirePort scratch_wire{kAuthority};
  PlanExchange scratch{PlanExchangeConfig{}, scratch_wire, scratch_sink};
  CHECK_OK(scratch.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                           ByteView{msg.data(), blob_size + 1}, now));
  for (int round = 0; round < 12; ++round) {
    scratch.poll(now, ExchangeChannel::Home);
    flush_wire(scratch_wire, world.part.agent, now);
    world.part.agent.poll(now);
    now += 5;
  }
  CHECK(world.part.agent.participant().phase() != ParticipantPhase::Preparing);
  CHECK(world.part.agent.participant().pending_plan() == nullptr);
  // The NotReady report still reaches the authority's readiness table.
  for (int round = 0; round < 12; ++round) {
    world.part.agent.poll(now);
    while (!world.part.wire.sent.empty()) {
      const Captured frame = world.part.wire.sent.front();
      world.part.wire.sent.pop_front();
      if (frame.dest == kAuthority) deliver(world.auth.agent, frame, now);
    }
    now += 5;
  }
  ParticipantReadiness readiness{};
  CHECK(world.auth.agent.readiness_of(kSelf, readiness));
  CHECK(readiness.answered && !readiness.ready);
}

// Validly-signed evidence for a STALE epoch is rejected on monotonicity —
// the signature check passing does not override epoch order (D5-02).
void test_agent_stale_epoch_evidence() {
  AgentWorld world;
  MonotonicMs now = kNow;
  const IssuedPlan issued = issue_plan(1, now + 30000, 1);
  VerifiedAuthorityPlan token{};
  CHECK_OK(world.auth.agent.offer_plan(
      issued.plan, ByteView{issued.blob.data(), issued.blob_size},
      issued.operation,
      ByteView{issued.signature.data(), issued.signature.size()},
      Digest256{}, ByteView{}, ByteView{}, false, now, token));
  world.pump_n(now, 30);
  CHECK_OK(world.auth.agent.release_commit(now));
  world.pump_n(now, 30);
  CHECK(world.part.agent.participant().committed_epoch().value == 1);

  // Complete the scheduled cutover so the participant is Stable: from there
  // the monotonic guard (COMMIT_STALE) is what refuses the replay.
  now = issued.plan.switch_reference_ms + 1;
  world.pump(now);
  world.pump(now + 1);
  world.part.agent.note_link_activity(kAuthority, now + 3);
  now += 30000 + 5000;
  world.pump_n(now, 10);
  CHECK(world.part.agent.participant().phase() == ParticipantPhase::Stable);

  // Same-epoch evidence for a DIFFERENT plan, correctly signed: rejected,
  // and the committed epoch does not regress.
  const IssuedPlan stale = issue_plan(1, now + 60000, 2);
  CommitEvidence evidence{};
  evidence.operation = stale.operation;
  evidence.plan_hash = stale.plan_hash;
  evidence.new_epoch = stale.plan.new_epoch;
  std::memcpy(evidence.signature.data(), stale.signature.data(), 32);
  evidence.signature_size = 32;
  std::array<std::uint8_t, migration_wire_const::kCommitEvidenceObjectMax>
      msg{};
  msg[0] = static_cast<std::uint8_t>(PlanMessage::CommitEvidence);
  std::size_t size = 0;
  CHECK_OK(commit_evidence_encode(
      evidence, MutableByteView{msg.data() + 1, msg.size() - 1}, size));
  CollectingSink scratch_sink{};
  FakeWirePort scratch_wire{kAuthority};
  PlanExchange scratch{PlanExchangeConfig{}, scratch_wire, scratch_sink};
  CHECK_OK(scratch.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                           ByteView{msg.data(), size + 1}, now));
  for (int round = 0; round < 12; ++round) {
    scratch.poll(now, ExchangeChannel::Home);
    flush_wire(scratch_wire, world.part.agent, now);
    world.part.agent.poll(now);
    now += 5;
  }
  CHECK(world.part.owner.has_event("COMMIT_EVIDENCE_REJECTED"));
  CHECK(world.part.agent.participant().committed_epoch().value == 1);
}

// The authority's periodic TimeSync re-arms the participant's clock after
// restart; samples from any other source are valid traffic but never clock
// evidence (D5-03).
void test_agent_timesync_rearm() {
  AgentWorld world;
  CHECK(!world.part.agent.participant().clock_valid());
  MonotonicMs now = kNow;

  // A sample from a non-authority node must NOT arm the clock — valid wire
  // traffic, never clock evidence (D5-03).
  autonomy::TimeSyncPayload foreign{};
  foreign.source = kPeer;
  foreign.sequence = 77;
  foreign.reference_ms = now + 900000;
  foreign.uncertainty_ms = 4;
  autonomy::EncodedPayload payload{};
  CHECK_OK(autonomy::time_sync_encode(foreign, payload));
  world.part.agent.on_migration_frame(kPeer, FrameType::TimeSync,
                                      payload.view(), now);
  CHECK(!world.part.agent.participant().clock_valid());

  // An over-uncertainty sample — even from the authority — is refused and
  // never re-arms a cold clock (20ms bound, 04 §8).
  autonomy::TimeSyncPayload sloppy{};
  sloppy.source = kAuthority;
  sloppy.sequence = 99;
  sloppy.reference_ms = now + 42;
  sloppy.uncertainty_ms = 100;  // + slack exceeds the bound
  CHECK_OK(autonomy::time_sync_encode(sloppy, payload));
  world.part.agent.on_migration_frame(kAuthority, FrameType::TimeSync,
                                      payload.view(), now);
  CHECK(!world.part.agent.participant().clock_valid());

  // The authority's periodic in-bounds sample re-arms it. (First emission
  // is scheduled timesync_period_ms after resume.)
  now = 5000;
  world.pump(now);
  CHECK(world.part.agent.participant().clock_valid());
}

// A helper serves its durably committed state to a stranded node: the
// persisted commit signature is re-emitted as CommitEvidence and the blob
// follows — the stranded node converges on the NEWEST signed state (D5-07).
void test_agent_snapshot_serving() {
  AgentWorld world;
  MonotonicMs now = kNow;
  const IssuedPlan issued = issue_plan(1, now + 30000, 1);
  VerifiedAuthorityPlan token{};
  CHECK_OK(world.auth.agent.offer_plan(
      issued.plan, ByteView{issued.blob.data(), issued.blob_size},
      issued.operation,
      ByteView{issued.signature.data(), issued.signature.size()},
      Digest256{}, ByteView{}, ByteView{}, false, now, token));
  world.pump_n(now, 30);
  CHECK_OK(world.auth.agent.release_commit(now));
  world.pump_n(now, 30);
  CHECK(world.part.agent.participant().committed_epoch().value == 1);

  // The stranded node asks for the newest signed state (all-zero hash).
  ChannelCoordinator coord_stranded{coordinator_config(kPeer)};
  AgentRig stranded(kPeer, false, coord_stranded);
  stranded.wire.peers = {kSelf};
  (void)stranded.agent.resume(now);

  SnapshotRequest request{};
  request.known_epoch = ChannelEpoch{0};  // knows nothing
  std::array<std::uint8_t, migration_wire_const::kInlineObjectMax> msg{};
  msg[0] = static_cast<std::uint8_t>(PlanMessage::SnapshotRequest);
  std::size_t size = 0;
  CHECK_OK(snapshot_request_encode(
      request, MutableByteView{msg.data() + 1, msg.size() - 1}, size));
  CollectingSink scratch_sink{};
  FakeWirePort scratch_wire{kPeer};
  PlanExchange scratch{PlanExchangeConfig{}, scratch_wire, scratch_sink};
  CHECK_OK(scratch.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                           ByteView{msg.data(), size + 1}, now));
  for (int round = 0; round < 12; ++round) {
    scratch.poll(now, ExchangeChannel::Home);
    flush_wire(scratch_wire, world.part.agent, now);
    world.part.agent.poll(now);
    now += 5;
  }
  // The serve goes to the requester: commit evidence + blob (Home context).
  for (int round = 0; round < 40; ++round) {
    world.part.agent.poll(now);
    while (!world.part.wire.sent.empty()) {
      const Captured frame = world.part.wire.sent.front();
      world.part.wire.sent.pop_front();
      if (frame.dest == kPeer) deliver(stranded.agent, frame, now);
      if (frame.dest == kAuthority) deliver(world.auth.agent, frame, now);
    }
    stranded.agent.poll(now);
    now += 5;
  }
  // Commit-before-blob recovery: evidence arrives first -> Recovering;
  // the served blob then completes the committed state.
  CHECK(stranded.agent.participant().committed_epoch().value == 1);
  CHECK(stranded.agent.participant().phase() == ParticipantPhase::Committed ||
        stranded.agent.participant().phase() == ParticipantPhase::Recovering);
}

// Resume reconcile: a durable active record on a different channel triggers
// one verified ChannelCutover through the runner — never a bare assignment.
void test_agent_resume_reconcile() {
  AgentWorld world;
  // Durably: committed+applied epoch 1 on channel 6 (blob present so the
  // resume can prove it); physically on 1.
  const IssuedPlan issued = issue_plan(1, 60000, 1);
  CHECK_OK(world.part.storage.write_blob(
      issued.plan_hash, ByteView{issued.blob.data(), issued.blob_size}));
  CommitRecord commit{};
  commit.operation = issued.operation;
  commit.plan_hash = issued.plan_hash;
  commit.new_epoch = issued.plan.new_epoch;
  std::memcpy(commit.signature.data(), issued.signature.data(), 32);
  commit.signature_size = 32;
  commit.present = true;
  std::array<std::uint8_t, migration_const::kCommitRecordSize> raw{};
  std::size_t raw_size = 0;
  CHECK_OK(commit_record_encode(commit, MutableByteView{raw.data(), raw.size()},
                                raw_size));
  CHECK_OK(world.part.storage.write_commit_record(
      ByteView{raw.data(), raw_size}));
  ActiveRecord active{};
  active.epoch = issued.plan.new_epoch;
  active.channel = 6;
  active.plan_hash = issued.plan_hash;
  active.present = true;
  std::array<std::uint8_t, migration_const::kActiveRecordSize> araw{};
  CHECK_OK(active_record_encode(
      active, MutableByteView{araw.data(), araw.size()}, raw_size));
  CHECK_OK(world.part.storage.write_active_record(
      ByteView{araw.data(), raw_size}));

  MonotonicMs now = kNow;
  CHECK_OK(world.part.agent.resume(now));
  // Reconcile queued: runner picks it up over bounded polls.
  for (int round = 0; round < 20 && world.part.runner.committed_channel() != 6;
       ++round) {
    world.part.agent.poll(now);
    world.part.runner.poll(now);
    now += 5;
  }
  CHECK(world.part.runner.committed_channel() == 6);
  CHECK(world.part.port.committed == 6);
}

// Live channel reconcile (04 §9.2): a committed-vs-active divergence that
// appears MID-RUN — e.g. a visit return that failed and left the radio
// behind — is converged by a bounded verified ChannelCutover, not only at
// resume time.
void test_agent_live_reconcile() {
  AgentWorld world;
  MonotonicMs now = kNow;
  // Radio committed on 6 while the durable record says 1 — the state a
  // stranded visit return leaves behind.
  CHECK_OK(world.part.runner.set_home_channel(6));
  for (int round = 0;
       round < 20 && world.part.runner.committed_channel() != 1; ++round) {
    world.part.agent.poll(now);
    world.part.runner.poll(now);
    now += 5;
  }
  CHECK(world.part.runner.committed_channel() == 1);
  CHECK(world.part.port.committed == 1);
  CHECK(world.part.port.channel == 1);
  CHECK(!world.part.owner.has_event("RESUME_CHANNEL_DIVERGED"));
  CHECK(world.part.agent.participant().phase() == ParticipantPhase::Stable);
}

// A permanently refusing driver exhausts the bounded reconcile budget:
// one RESUME_CHANNEL_DIVERGED event, then the terminal RECOVERY_REQUIRED
// diagnosis — never a silent park and never an unbounded retry loop.
void test_agent_reconcile_exhaustion_required() {
  AgentWorld world;
  MonotonicMs now = kNow;
  CHECK_OK(world.part.runner.set_home_channel(6));
  world.part.port.set_fail = true;  // every re-apply is refused
  for (int round = 0; round < 20; ++round) {
    world.part.agent.poll(now);
    world.part.runner.poll(now);
    now += 5;
  }
  CHECK(world.part.agent.participant().phase() ==
        ParticipantPhase::RecoveryRequired);
  CHECK(world.part.agent.participant().stats().recovery_required == 1);
  int diverged_events = 0;
  for (const auto& event : world.part.owner.events) {
    if (event.find("RESUME_CHANNEL_DIVERGED") != std::string::npos) {
      ++diverged_events;
    }
  }
  CHECK(diverged_events == 1);
  // Latched for the episode: further polls issue no more radio ops.
  const int calls_at_exhaustion = world.part.port.set_calls;
  for (int round = 0; round < 10; ++round) {
    world.part.agent.poll(now);
    world.part.runner.poll(now);
    now += 5;
  }
  CHECK(world.part.port.set_calls == calls_at_exhaustion);
}

void test_agent_release_requires_offer() {
  AgentWorld world;
  CHECK(world.auth.agent.release_commit(kNow).code ==
        StatusCode::InvalidState);
  // offer_plan on a non-authority agent is refused before any distribution.
  const IssuedPlan issued = issue_plan(1, kNow + 30000, 1);
  VerifiedAuthorityPlan token{};
  CHECK(world.part.agent
            .offer_plan(issued.plan,
                        ByteView{issued.blob.data(), issued.blob_size},
                        issued.operation,
                        ByteView{issued.signature.data(), 32}, Digest256{},
                        ByteView{}, ByteView{}, false, kNow, token)
            .code == StatusCode::InvalidState);
  CHECK(world.part.wire.sent.empty());

  // A snapshot that does not bind THIS operation/blob is refused outright
  // (ledger commits run first — this offer mints op seq 1 then rejects the
  // mismatched snapshot; the op is consumed but nothing is distributed).
  IssuedPlan other = issue_plan(2, kNow + 90000, 2);
  VerifiedAuthorityPlan rejected{};
  CHECK(world.auth.agent
            .offer_plan(issued.plan,
                        ByteView{issued.blob.data(), issued.blob_size},
                        issued.operation,
                        ByteView{issued.signature.data(), 32}, Digest256{},
                        ByteView{other.snap.data(), other.snap_size},
                        ByteView{other.snap_sig.data(), 32}, false, kNow,
                        rejected)
            .code == StatusCode::IntegrityError);
}

// The bounded pending queue drops the NEW send and reports it — never an
// unbounded grow, never a silent drop of older work.
void test_agent_pending_bounded() {
  AgentWorld world;
  MonotonicMs now = kNow;
  CollectingSink scratch_sink{};
  FakeWirePort scratch_wire{kPeer};
  PlanExchange scratch{PlanExchangeConfig{}, scratch_wire, scratch_sink};
  // Distinct SnapshotRequest objects (dedup is by object hash) beyond the
  // pending capacity. Interleave publish/pump/deliver: the exchange's own
  // outbound slots are the tighter bound otherwise.
  for (std::size_t i = 0;
       i < migration_wire_const::kPendingSends + 4; ++i) {
    SnapshotRequest request{};
    request.known_epoch = ChannelEpoch{static_cast<std::uint32_t>(i + 1)};
    std::array<std::uint8_t, migration_wire_const::kInlineObjectMax> msg{};
    msg[0] = static_cast<std::uint8_t>(PlanMessage::SnapshotRequest);
    std::size_t size = 0;
    CHECK_OK(snapshot_request_encode(
        request, MutableByteView{msg.data() + 1, msg.size() - 1}, size));
    CHECK_OK(scratch.publish(
        kSelf, autonomy::ControlObjectKind::ChannelPlan,
        ByteView{msg.data(), size + 1}, now));
    // Poll THEN drain every round — the manifest goes out on the first
    // poll, its chunk on the next; gating on sent.empty() would stop after
    // the manifest and never complete the object.
    for (int round = 0; round < 8; ++round) {
      scratch.poll(now, ExchangeChannel::Home);
      flush_wire(scratch_wire, world.part.agent, now);
      now += 2;
    }
    // Free the outbound slot for the next object (ack path is out of scope
    // for the sender here — a stale slot would block the next publish).
    autonomy::ObjectHash hash = plan_digest(
        ByteView{msg.data(), size + 1});
    autonomy::ObjectAckPayload ack{};
    ack.object_hash = hash;
    ack.received_len = static_cast<std::uint16_t>(size + 1);
    ack.status = autonomy::ObjectAckStatus::Ok;
    scratch.on_ack(kSelf, ack, now);
  }
  CHECK(world.part.agent.pending_sends() ==
        migration_wire_const::kPendingSends);
  CHECK(world.part.owner.has_event("PENDING_SEND_DROPPED"));
}

// Stopped authority: no NEW commit may issue, but already-signed recovery
// material keeps verifying at participants (D5-04).
void test_agent_authority_stopped() {
  AgentWorld world;
  world.auth.authority.set_available(false);
  const IssuedPlan issued = issue_plan(1, kNow + 30000, 1);
  VerifiedAuthorityPlan token{};
  CHECK(!world.auth.agent
             .offer_plan(issued.plan,
                         ByteView{issued.blob.data(), issued.blob_size},
                         issued.operation,
                         ByteView{issued.signature.data(), 32}, Digest256{},
                         ByteView{}, ByteView{}, false, kNow, token)
             .ok());
  // Pre-signed commit evidence still verifies through the participant-side
  // authority (verification is local cryptography, not a round trip).
  VerifiedAuthorityPlan verified{};
  CHECK_OK(world.part.authority.verify_commit(
      issued.operation, issued.plan_hash, issued.plan.new_epoch,
      ByteView{issued.signature.data(), 32}, verified));
  CHECK(verified.valid());
}


// --- codecs ----------------------------------------------------------------------

void test_codecs_roundtrip() {
  std::array<std::uint8_t, 256> buf{};
  std::size_t size = 0;

  const MigrationPlan plan =
      make_plan(7, 1, 6, 20000, 11);
  std::array<std::uint8_t, migration_const::kPlanBlobMax> blob{};
  std::size_t blob_size = 0;
  CHECK_OK(plan_encode(plan, MutableByteView{blob.data(), blob.size()},
                       blob_size));
  const Digest256 plan_hash =
      plan_digest(ByteView{blob.data(), blob_size});
  const AuthorityOperation op = make_operation(plan, plan_hash);

  CommitEvidence evidence{};
  evidence.operation = op;
  evidence.plan_hash = plan_hash;
  evidence.new_epoch = plan.new_epoch;
  const Digest256 sig = sign_commit(op, plan_hash, plan.new_epoch);
  std::memcpy(evidence.signature.data(), sig.data(), sig.size());
  evidence.signature_size = static_cast<std::uint8_t>(sig.size());
  CHECK_OK(commit_evidence_encode(
      evidence, MutableByteView{buf.data(), buf.size()}, size));
  CommitEvidence decoded{};
  CHECK_OK(commit_evidence_decode(ByteView{buf.data(), size}, decoded));
  CHECK(decoded.operation.sequence == op.sequence);
  CHECK(decoded.operation.authority == op.authority);
  CHECK(decoded.plan_hash == plan_hash);
  CHECK(decoded.new_epoch.value == plan.new_epoch.value);
  CHECK(decoded.signature_size == sig.size());
  CHECK(std::memcmp(decoded.signature.data(), sig.data(), sig.size()) == 0);

  ReadyReport report{};
  report.plan_hash = plan_hash;
  report.new_epoch = plan.new_epoch;
  report.status = ReadyStatus::Ready;
  report.migration_capable = true;
  report.clock_ok = true;
  report.storage_ok = true;
  report.drain_ok = true;
  CHECK_OK(ready_report_encode(report, MutableByteView{buf.data(), buf.size()},
                               size));
  ReadyReport report_out{};
  CHECK_OK(ready_report_decode(ByteView{buf.data(), size}, report_out));
  CHECK(report_out.status == ReadyStatus::Ready);
  CHECK(report_out.migration_capable && report_out.clock_ok &&
        report_out.storage_ok && report_out.drain_ok);
  CHECK(!report_out.sleep_lease_valid);

  ResultReport result{};
  result.plan_hash = plan_hash;
  result.epoch = plan.new_epoch;
  result.outcome = ResultOutcome::Applied;
  CHECK_OK(result_report_encode(
      result, MutableByteView{buf.data(), buf.size()}, size));
  ResultReport result_out{};
  CHECK_OK(result_report_decode(ByteView{buf.data(), size}, result_out));
  CHECK(result_out.outcome == ResultOutcome::Applied);
  CHECK(result_out.plan_hash == plan_hash);

  SnapshotRequest request{};
  request.known_epoch = ChannelEpoch{4};
  request.plan_hash = plan_hash;
  CHECK_OK(snapshot_request_encode(
      request, MutableByteView{buf.data(), buf.size()}, size));
  SnapshotRequest request_out{};
  CHECK_OK(snapshot_request_decode(ByteView{buf.data(), size}, request_out));
  CHECK(request_out.known_epoch.value == 4);
  CHECK(request_out.plan_hash == plan_hash);

  // Signed snapshot wrapper round trip.
  RecoverySnapshot snapshot{};
  snapshot.operation = op;
  snapshot.plan_hash = plan_hash;
  std::memcpy(snapshot.plan_blob.data(), blob.data(), blob_size);
  snapshot.plan_blob_size = blob_size;
  std::array<std::uint8_t, migration_const::kSnapshotMax> snap_buf{};
  std::size_t snap_size = 0;
  CHECK_OK(snapshot_encode(
      snapshot, MutableByteView{snap_buf.data(), snap_buf.size()}, snap_size));
  const Digest256 snap_sig =
      sign_snapshot(ByteView{snap_buf.data(), snap_size});
  std::array<std::uint8_t, migration_const::kSnapshotMax + 68> wrap_buf{};
  std::size_t wrap_size = 0;
  CHECK_OK(signed_snapshot_wrap(
      ByteView{snap_buf.data(), snap_size},
      ByteView{snap_sig.data(), snap_sig.size()},
      MutableByteView{wrap_buf.data(), wrap_buf.size()}, wrap_size));
  ByteView body{}, signature{};
  CHECK_OK(
      signed_snapshot_unwrap(ByteView{wrap_buf.data(), wrap_size}, body,
                             signature));
  CHECK(body.size == snap_size);
  CHECK(std::memcmp(body.data, snap_buf.data(), snap_size) == 0);
  CHECK(signature.size == snap_sig.size());
  CHECK(std::memcmp(signature.data, snap_sig.data(), snap_sig.size()) == 0);
}

void test_codecs_reject_malformed() {
  std::array<std::uint8_t, 256> buf{};
  std::size_t size = 0;
  const MigrationPlan plan = make_plan(7, 1, 6, 20000, 11);
  std::array<std::uint8_t, migration_const::kPlanBlobMax> blob{};
  std::size_t blob_size = 0;
  CHECK_OK(plan_encode(plan, MutableByteView{blob.data(), blob.size()},
                       blob_size));
  const Digest256 plan_hash = plan_digest(ByteView{blob.data(), blob_size});
  const AuthorityOperation op = make_operation(plan, plan_hash);

  CommitEvidence evidence{};
  evidence.operation = op;
  evidence.plan_hash = plan_hash;
  evidence.new_epoch = plan.new_epoch;
  const Digest256 sig = sign_commit(op, plan_hash, plan.new_epoch);
  std::memcpy(evidence.signature.data(), sig.data(), sig.size());
  evidence.signature_size = static_cast<std::uint8_t>(sig.size());
  CHECK_OK(commit_evidence_encode(
      evidence, MutableByteView{buf.data(), buf.size()}, size));

  CommitEvidence out{};
  // Truncated body.
  CHECK(!commit_evidence_decode(ByteView{buf.data(), size - 1}, out).ok());
  // Trailing garbage.
  CHECK(!commit_evidence_decode(ByteView{buf.data(), size + 1}, out).ok());
  // sig_len zero inside the stream: encode a hand-mutated copy.
  std::array<std::uint8_t, 256> mutated = buf;
  mutated[size - sig.size() - 1] = 0;  // low byte of sig_len -> 0
  mutated[size - sig.size() - 2] = 0;
  CHECK(!commit_evidence_decode(
            ByteView{mutated.data(), size - sig.size()}, out)
            .ok());
  // Oversized declared signature.
  CommitEvidence bad = evidence;
  bad.signature_size = migration_const::kMaxCommitSignature + 1;
  CHECK(!commit_evidence_encode(bad, MutableByteView{buf.data(), buf.size()},
                                size)
             .ok());

  // Ready/Result status and outcome outside the enum are rejected.
  ReadyReport report{};
  report.plan_hash = plan_hash;
  report.status = ReadyStatus::Ready;
  CHECK_OK(ready_report_encode(report, MutableByteView{buf.data(), buf.size()},
                               size));
  mutated = buf;
  mutated[size - 2] = 0;  // status byte -> 0
  ReadyReport report_out{};
  CHECK(!ready_report_decode(ByteView{mutated.data(), size}, report_out).ok());
  mutated = buf;
  mutated[size - 2] = 9;  // unknown status
  CHECK(!ready_report_decode(ByteView{mutated.data(), size}, report_out).ok());

  ResultReport result{};
  result.plan_hash = plan_hash;
  result.outcome = ResultOutcome::Applied;
  CHECK_OK(result_report_encode(
      result, MutableByteView{buf.data(), buf.size()}, size));
  mutated = buf;
  mutated[size - 1] = 0;
  ResultReport result_out{};
  CHECK(
      !result_report_decode(ByteView{mutated.data(), size}, result_out).ok());

  // Snapshot wrapper bounds: zero signature, oversized signature, empty body.
  ByteView body{}, signature{};
  CHECK(!signed_snapshot_wrap(ByteView{buf.data(), 4}, ByteView{buf.data(), 0},
                              MutableByteView{buf.data(), buf.size()}, size)
             .ok());
  std::array<std::uint8_t, migration_const::kMaxCommitSignature + 1>
      oversize{};
  CHECK(!signed_snapshot_wrap(
            ByteView{buf.data(), 4},
            ByteView{oversize.data(), oversize.size()},
            MutableByteView{buf.data(), buf.size()}, size)
             .ok());
  CHECK(!signed_snapshot_wrap(ByteView{}, ByteView{sig.data(), sig.size()},
                              MutableByteView{buf.data(), buf.size()}, size)
             .ok());
  CHECK(!signed_snapshot_unwrap(ByteView{buf.data(), 2}, body, signature)
             .ok());
}

void test_signing_input_layout() {
  const MigrationPlan plan = make_plan(7, 1, 6, 20000, 11);
  std::array<std::uint8_t, migration_const::kPlanBlobMax> blob{};
  std::size_t blob_size = 0;
  CHECK_OK(plan_encode(plan, MutableByteView{blob.data(), blob.size()},
                       blob_size));
  const Digest256 plan_hash = plan_digest(ByteView{blob.data(), blob_size});
  const AuthorityOperation op = make_operation(plan, plan_hash);
  std::array<std::uint8_t, kCommitSigningInputSize> input{};
  std::size_t size = 0;
  CHECK_OK(commit_signing_input(
      op, plan_hash, plan.new_epoch,
      MutableByteView{input.data(), input.size()}, size));
  CHECK(size == kCommitSigningInputSize);
  CHECK(std::memcmp(input.data(), "RLCMT1", 6) == 0);
  // The input binds operation fields + plan hash + epoch; any field
  // change must change the signed bytes.
  AuthorityOperation other = op;
  other.sequence = op.sequence + 1;
  std::array<std::uint8_t, kCommitSigningInputSize> input2{};
  std::size_t size2 = 0;
  CHECK_OK(commit_signing_input(
      other, plan_hash, plan.new_epoch,
      MutableByteView{input2.data(), input2.size()}, size2));
  CHECK(std::memcmp(input.data(), input2.data(), size) != 0);
  Digest256 other_hash = plan_hash;
  other_hash[0] ^= 0xFFU;
  CHECK_OK(commit_signing_input(
      op, other_hash, plan.new_epoch,
      MutableByteView{input2.data(), input2.size()}, size2));
  CHECK(std::memcmp(input.data(), input2.data(), size) != 0);
}

// --- PlanExchange ------------------------------------------------------------------

struct ExchangePair {
  FakeWirePort wire_a{kAuthority};
  FakeWirePort wire_b{kSelf};
  CollectingSink sink_a;
  CollectingSink sink_b;
  PlanExchange a{PlanExchangeConfig{}, wire_a, sink_a};
  PlanExchange b{PlanExchangeConfig{}, wire_b, sink_b};
};

// Move every frame from `from_wire` into `to` as manifest/chunk/ack.
void relay(FakeWirePort& from_wire, PlanExchange& to, MonotonicMs now_ms) {
  while (!from_wire.sent.empty()) {
    const Captured frame = from_wire.sent.front();
    from_wire.sent.pop_front();
    autonomy::EncodedPayload payload{};
    std::memcpy(payload.bytes.data(), frame.data.data(), frame.size);
    payload.size = frame.size;
    switch (frame.type) {
      case FrameType::ControlObject: {
        autonomy::ControlObjectPayload manifest{};
        CHECK_OK(control_object_decode(payload.view(), manifest));
        to.on_manifest(frame.from, manifest, now_ms);
        break;
      }
      case FrameType::ObjectChunk: {
        autonomy::ObjectChunkPayload chunk{};
        CHECK_OK(object_chunk_decode(payload.view(), chunk));
        to.on_chunk(frame.from, chunk, now_ms);
        break;
      }
      case FrameType::ObjectAck: {
        autonomy::ObjectAckPayload ack{};
        CHECK_OK(object_ack_decode(payload.view(), ack));
        to.on_ack(frame.from, ack, now_ms);
        break;
      }
      default:
        CHECK(false);
        break;
    }
  }
}

void test_exchange_happy_path() {
  ExchangePair pair{};
  const std::array<std::uint8_t, 200> content = [] {
    std::array<std::uint8_t, 200> c{};
    for (std::size_t i = 0; i < c.size(); ++i) c[i] = static_cast<std::uint8_t>(i);
    return c;
  }();
  CHECK_OK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                          ByteView{content.data(), content.size()}, kNow));
  MonotonicMs now = kNow;
  for (int round = 0; round < 12 && pair.sink_b.objects.empty(); ++round) {
    pair.a.poll(now, ExchangeChannel::Home);
    relay(pair.wire_a, pair.b, now);
    relay(pair.wire_b, pair.a, now);  // acks back
    now += 5;
  }
  CHECK(pair.sink_b.objects.size() == 1);
  if (!pair.sink_b.objects.empty()) {
    CHECK(pair.sink_b.objects[0].size() == content.size());
    CHECK(std::memcmp(pair.sink_b.objects[0].data(), content.data(),
                      content.size()) == 0);
  }
  CHECK(pair.sink_b.last_peer == kAuthority);
  // Ok ack frees the outbound slot.
  CHECK(pair.a.outbound_busy() == 0);
  CHECK(pair.b.objects_delivered() == 1);
}

void test_exchange_chunk_loss_resend() {
  ExchangePair pair{};
  const std::array<std::uint8_t, 200> content = [] {
    std::array<std::uint8_t, 200> c{};
    for (std::size_t i = 0; i < c.size(); ++i) c[i] = static_cast<std::uint8_t>(i + 3);
    return c;
  }();
  CHECK_OK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                          ByteView{content.data(), content.size()}, kNow));
  MonotonicMs now = kNow;
  bool dropped = false;
  for (int round = 0; round < 30 && pair.sink_b.objects.empty(); ++round) {
    pair.a.poll(now, ExchangeChannel::Home);
    // Drop exactly one chunk on the floor; the receiver's Incomplete ack
    // restarts the bounded whole-object resend.
    if (!dropped) {
      for (auto it = pair.wire_a.sent.begin(); it != pair.wire_a.sent.end();
           ++it) {
        if (it->type == FrameType::ObjectChunk) {
          pair.wire_a.sent.erase(it);
          dropped = true;
          break;
        }
      }
    }
    relay(pair.wire_a, pair.b, now);
    relay(pair.wire_b, pair.a, now);
    now += 5;
  }
  CHECK(dropped);
  CHECK(pair.sink_b.objects.size() == 1);
  CHECK(pair.b.transfers_failed() == 0);
}

void test_exchange_forged_content() {
  ExchangePair pair{};
  const std::array<std::uint8_t, 64> content = [] {
    std::array<std::uint8_t, 64> c{};
    c.fill(0xABU);
    return c;
  }();
  CHECK_OK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                          ByteView{content.data(), content.size()}, kNow));
  MonotonicMs now = kNow;
  // Pump until a chunk is actually on the wire (the manifest goes first),
  // then corrupt its bytes: the receiver's digest check must fail the
  // object and never deliver it to the sink.
  bool corrupted = false;
  for (int round = 0; round < 12; ++round) {
    pair.a.poll(now, ExchangeChannel::Home);
    for (auto& frame : pair.wire_a.sent) {
      if (frame.type == FrameType::ObjectChunk && !corrupted) {
        frame.data[40] ^= 0xFFU;  // inside the chunk data region
        corrupted = true;
      }
    }
    relay(pair.wire_a, pair.b, now);
    relay(pair.wire_b, pair.a, now);
    now += 5;
    if (corrupted && pair.a.outbound_busy() == 0) break;
  }
  CHECK(corrupted);
  CHECK(pair.sink_b.objects.empty());
  CHECK(pair.b.objects_delivered() == 0);
  // The Failed ack retires the sender's transfer.
  CHECK(pair.a.transfers_failed() >= 1 || pair.a.outbound_busy() == 0);
}

void test_exchange_bounded_and_expiry() {
  ExchangePair pair{};
  const std::array<std::uint8_t, 16> content{};
  // Outbound slots are bounded at kOutboundSlots.
  for (std::size_t i = 0; i < migration_wire_const::kOutboundSlots; ++i) {
    CHECK_OK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                            ByteView{content.data(), content.size() - i},
                            kNow));
  }
  CHECK(pair.a.outbound_busy() ==
        migration_wire_const::kOutboundSlots);
  // A fourth DISTINCT object (the dedup key is the content hash) overflows.
  std::array<std::uint8_t, 16> fourth{};
  fourth.fill(0x99U);
  CHECK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                       ByteView{fourth.data(), fourth.size()}, kNow)
            .code == StatusCode::NoCapacity);
  // Oversized content never enters a slot.
  std::array<std::uint8_t, migration_wire_const::kMigrationObjectMax + 1>
      huge{};
  CHECK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                       ByteView{huge.data(), huge.size()}, kNow)
            .code == StatusCode::InvalidArgument);

  // A manifest beyond the object bound is acked Failed, not buffered.
  autonomy::ControlObjectPayload manifest{};
  manifest.total_len =
      static_cast<std::uint16_t>(migration_wire_const::kMigrationObjectMax + 1);
  manifest.object_hash.fill(0x11U);
  pair.b.on_manifest(kAuthority, manifest, kNow);
  CHECK(!pair.wire_b.sent.empty());
  const Captured& nack = pair.wire_b.sent.back();
  CHECK(nack.type == FrameType::ObjectAck);
  autonomy::EncodedPayload ack_payload{};
  std::memcpy(ack_payload.bytes.data(), nack.data.data(), nack.size);
  ack_payload.size = nack.size;
  autonomy::ObjectAckPayload ack{};
  CHECK_OK(object_ack_decode(ack_payload.view(), ack));
  CHECK(ack.status == autonomy::ObjectAckStatus::Failed);
  pair.wire_b.sent.clear();

  // An inbound reassembly that stalls expires instead of pinning the slot.
  manifest.total_len = 100;
  pair.b.on_manifest(kAuthority, manifest, kNow);
  autonomy::ObjectChunkPayload chunk{};
  chunk.object_hash = manifest.object_hash;
  chunk.offset = 0;
  chunk.data_size = 10;
  pair.b.on_chunk(kAuthority, chunk, kNow);
  pair.b.poll(kNow + migration_wire_const::kInboundExpiryMs + 1,
              ExchangeChannel::Home);
  // Slot freed: a fresh manifest for the same hash re-opens cleanly.
  pair.b.on_manifest(kAuthority, manifest,
                     kNow + migration_wire_const::kInboundExpiryMs + 2);
  CHECK(pair.sink_b.objects.empty());
}

void test_exchange_channel_gating() {
  ExchangePair pair{};
  // Distinct payloads — publish dedups on the object hash, so identical
  // content would collapse both transfers into one slot.
  std::array<std::uint8_t, 30> home_content{};
  std::array<std::uint8_t, 30> visit_content{};
  visit_content.fill(0x77U);
  CHECK_OK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                          ByteView{home_content.data(), home_content.size()},
                          kNow, false));
  CHECK_OK(pair.a.publish(kSelf, autonomy::ControlObjectKind::RecoverySnapshot,
                          ByteView{visit_content.data(), visit_content.size()},
                          kNow, true));
  // Blocked: the serialized op owns the radio — nothing transmits.
  pair.a.poll(kNow, ExchangeChannel::Blocked);
  CHECK(pair.wire_a.sent.empty());
  // And a blocked stretch does NOT burn resend attempts: the ack deadline
  // freezes so an overdue deadline defers instead of retrying.
  pair.a.poll(kNow + 60000, ExchangeChannel::Blocked);
  CHECK(pair.wire_a.sent.empty());
  CHECK(pair.a.transfers_failed() == 0);
  // Visit: only the visit-marked transfer may transmit.
  pair.a.poll(kNow + 60005, ExchangeChannel::Visit);
  bool saw_normal = false;
  bool saw_visit = false;
  for (const auto& frame : pair.wire_a.sent) {
    if (frame.type == FrameType::ControlObject) {
      autonomy::EncodedPayload payload{};
      std::memcpy(payload.bytes.data(), frame.data.data(), frame.size);
      payload.size = frame.size;
      autonomy::ControlObjectPayload manifest{};
      CHECK_OK(control_object_decode(payload.view(), manifest));
      if (manifest.kind == autonomy::ControlObjectKind::RecoverySnapshot) {
        saw_visit = true;
      } else {
        saw_normal = true;
      }
    }
  }
  CHECK(saw_visit);
  CHECK(!saw_normal);
  pair.wire_a.sent.clear();
  // Home: the normal transfer proceeds.
  pair.a.poll(kNow + 60010, ExchangeChannel::Home);
  CHECK(!pair.wire_a.sent.empty());
}

void test_exchange_ack_timeout_bounded() {
  ExchangePair pair{};
  const std::array<std::uint8_t, 30> content{};
  CHECK_OK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                          ByteView{content.data(), content.size()}, kNow));
  MonotonicMs now = kNow;
  // Push all chunks out, then never ack: bounded resends exhaust and the
  // transfer fails — never an infinite retry loop.
  for (int round = 0; round < 40 && pair.a.transfers_failed() == 0; ++round) {
    pair.a.poll(now, ExchangeChannel::Home);
    pair.wire_a.sent.clear();  // drop everything: peer is gone
    now += migration_wire_const::kAckTimeoutMs + 100;
  }
  CHECK(pair.a.transfers_failed() == 1);
  CHECK(pair.a.outbound_busy() == 0);
}

void test_exchange_duplicate_delivery() {
  ExchangePair pair{};
  const std::array<std::uint8_t, 30> content = [] {
    std::array<std::uint8_t, 30> c{};
    c.fill(0x55U);
    return c;
  }();
  CHECK_OK(pair.a.publish(kSelf, autonomy::ControlObjectKind::ChannelPlan,
                          ByteView{content.data(), content.size()}, kNow));
  MonotonicMs now = kNow;
  for (int round = 0; round < 12 && pair.sink_b.objects.empty(); ++round) {
    pair.a.poll(now, ExchangeChannel::Home);
    relay(pair.wire_a, pair.b, now);
    relay(pair.wire_b, pair.a, now);
    now += 5;
  }
  CHECK(pair.sink_b.objects.size() == 1);
  // Re-serve the same object: re-acknowledged Ok but NOT re-dispatched to
  // the semantic layer.
  autonomy::ObjectHash hash = plan_digest(ByteView{content.data(), content.size()});
  autonomy::ControlObjectPayload manifest{};
  manifest.total_len = static_cast<std::uint16_t>(content.size());
  manifest.object_hash = hash;
  pair.b.on_manifest(kAuthority, manifest, now);
  CHECK(pair.sink_b.objects.size() == 1);
  CHECK(!pair.wire_b.sent.empty());
  const Captured& dup = pair.wire_b.sent.back();
  CHECK(dup.type == FrameType::ObjectAck);
  autonomy::EncodedPayload payload{};
  std::memcpy(payload.bytes.data(), dup.data.data(), dup.size);
  payload.size = dup.size;
  autonomy::ObjectAckPayload ack{};
  CHECK_OK(object_ack_decode(payload.view(), ack));
  CHECK(ack.status == autonomy::ObjectAckStatus::Ok);
}

}  // namespace

int main() {
  test_codecs_roundtrip();
  test_codecs_reject_malformed();
  test_signing_input_layout();
  test_exchange_happy_path();
  test_exchange_chunk_loss_resend();
  test_exchange_forged_content();
  test_exchange_bounded_and_expiry();
  test_exchange_channel_gating();
  test_exchange_ack_timeout_bounded();
  test_exchange_duplicate_delivery();
  test_agent_full_migration();
  test_agent_forged_commit_evidence();
  test_agent_wrong_authority_blob();
  test_agent_stale_epoch_evidence();
  test_agent_timesync_rearm();
  test_agent_snapshot_serving();
  test_agent_resume_reconcile();
  test_agent_live_reconcile();
  test_agent_reconcile_exhaustion_required();
  test_agent_release_requires_offer();
  test_agent_pending_bounded();
  test_agent_authority_stopped();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom migration-wire tests passed");
  return 0;
}
