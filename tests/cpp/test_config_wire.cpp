// Routed config-wire tests (05-wire-api.md §5.5/§5.6): the dev-profile
// permit signer/verifier and the ConfigTarget/ConfigGateway endpoints driven
// back-to-back over a loopback ConfigWirePort. The challenge -> sign ->
// manifest/chunk -> ack -> apply path runs the REAL ConfigJournal — object
// assembly feeds submit_permit, so the wire test exercises verify/dedup/
// admission/decide end to end. Transport success is still never a verdict:
// the assertions read the journal's own revision/phase afterwards.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>

#include "routeloom/config.hpp"
#include "routeloom/config_dev.hpp"
#include "routeloom/config_wire.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/wire.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                            \
  do {                                                                         \
    if (!(expr)) {                                                             \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,     \
                   #expr);                                                     \
      ++failures;                                                              \
    }                                                                          \
  } while (false)
#define CHECK_OK(expr)                                                         \
  do {                                                                         \
    const auto _status = (expr);                                               \
    if (!_status.ok()) {                                                       \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,         \
                   __LINE__, #expr, _status.detail);                           \
      ++failures;                                                              \
    }                                                                          \
  } while (false)

using namespace routeloom;
using endpoint::ConfigCommand;
using endpoint::ConfigField;
using endpoint::ConfigFieldType;
using endpoint::ConfigPhase;
using endpoint::ConfigReason;

constexpr NetworkId kNet = 7;
constexpr NodeId kAuthority = 42;
constexpr NodeId kTarget = 0x1234;
constexpr NodeId kGateway = 0x9ABC;
constexpr std::uint64_t kBoot = 0xB007;
constexpr std::size_t kJournalSlot = kConfigJournalSlotBytes;

// Dev permit key shared by the issuer signer and the target verifier.
constexpr std::array<std::uint8_t, 16> kDevKey = {0xD0, 0xE1, 0xF2, 0x03,
                                                  0x14, 0x25, 0x36, 0x47,
                                                  0x58, 0x69, 0x7A, 0x8B,
                                                  0x9C, 0xAD, 0xBE, 0x0F};
ByteView dev_key() { return ByteView{kDevKey.data(), kDevKey.size()}; }

// --- Fakes -------------------------------------------------------------------

class CountingEntropy final : public EntropySource {
 public:
  Status fill(const MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) {
      out.data[i] = static_cast<std::uint8_t>(counter_ + i);
    }
    counter_ = static_cast<std::uint8_t>(counter_ + out.size + 1U);
    return Status::success();
  }
  std::uint8_t counter_{0x31};
};

class FakeJournalStorage final : public ConfigJournalStorage {
 public:
  Status read(const std::uint8_t slot, const MutableByteView target) noexcept override {
    if (slot >= kConfigJournalSlots || target.size != kJournalSlot) {
      return Status::error(StatusCode::InvalidArgument, "bad journal read");
    }
    std::memcpy(target.data, slots_[slot].data(), kJournalSlot);
    return Status::success();
  }
  Status write(const std::uint8_t slot, const ByteView data) noexcept override {
    if (slot >= kConfigJournalSlots || data.size == 0 ||
        data.size > kJournalSlot) {
      return Status::error(StatusCode::InvalidArgument, "bad journal write");
    }
    std::memcpy(slots_[slot].data(), data.data, data.size);
    return Status::success();
  }
  std::array<std::uint8_t, kJournalSlot> slots_[kConfigJournalSlots]{};
};

// Desired-state provider that completes apply/restore after one poll and
// commits pending -> active (readback input).
class FakeProvider final : public ConfigProvider {
 public:
  Status validate(const std::uint16_t, const std::uint16_t,
                  const ByteView) noexcept override {
    ++validate_calls;
    return Status::success();
  }
  Status prepare(const std::uint16_t, const std::uint16_t,
                 const ByteView) noexcept override {
    ++prepare_calls;
    return Status::success();
  }
  Status apply(const std::uint16_t, const ByteView next,
               OperationToken& token) noexcept override {
    ++apply_calls;
    pending_.size = next.size;
    std::memcpy(pending_.bytes.data(), next.data, next.size);
    token = OperationToken{++token_id_};
    return Status::success();
  }
  Status restore(const std::uint16_t, const ByteView snapshot,
                 OperationToken& token) noexcept override {
    ++restore_calls;
    pending_.size = snapshot.size;
    std::memcpy(pending_.bytes.data(), snapshot.data, snapshot.size);
    token = OperationToken{++token_id_};
    return Status::success();
  }
  Status poll(const OperationToken token, bool& done,
              Status& outcome) noexcept override {
    done = false;
    outcome = Status::success();
    if (token.value != token_id_) {
      return Status::error(StatusCode::NotFound, "unknown token");
    }
    done = true;
    active_.size = pending_.size;
    std::memcpy(active_.bytes.data(), pending_.bytes.data(), pending_.size);
    return Status::success();
  }
  Status read_active(const std::uint16_t, const MutableByteView target,
                     std::size_t& out_size) noexcept override {
    if (active_.size > target.size) {
      return Status::error(StatusCode::NoCapacity, "read buffer small");
    }
    std::memcpy(target.data, active_.bytes.data(), active_.size);
    out_size = active_.size;
    return Status::success();
  }
  ByteBuffer<endpoint::kConfigSnapshotMax> active_{};
  ByteBuffer<endpoint::kConfigSnapshotMax> pending_{};
  std::uint64_t token_id_{0};
  int validate_calls{0}, prepare_calls{0}, apply_calls{0}, restore_calls{0};
};

class PermitAllGate final : public ConfigMaintenanceGate {
 public:
  Status check(const ConfigMaintenanceCheck& request) noexcept override {
    ++calls;
    last = request;
    return result;
  }
  Status result = Status::success();
  ConfigMaintenanceCheck last{};
  int calls{0};
};

class PermissiveValidator final : public ConfigSchemaValidator {
 public:
  Status validate_field(const ConfigField&) const noexcept override {
    return Status::success();
  }
};

// Loopback port: config_send only ENQUEUES a verified PlainFrame; flush()
// delivers it to the bound peer sink on a later call — the asynchronous
// delivery the real routed lane provides (a reply can never arrive inside
// the send that produced it, so the sender's pending state is already set).
// `drop` makes every send "succeed" yet deliver nothing: the no-route /
// timeout case.
class LoopbackPort final : public ConfigWirePort {
 public:
  static constexpr std::size_t kQueueMax = 64;
  LoopbackPort(const NodeId self, ConfigEndpointSink*& peer_slot) noexcept
      : self_(self), peer_slot_(peer_slot) {}
  Status config_send(const NodeId dest, const FrameType type,
                     const ByteView payload, const MonotonicMs now_ms) noexcept {
    (void)now_ms;
    ++sent;
    if (drop || dest != peer_dest_ || count_ >= kQueueMax) {
      ++skipped;
      return Status::success();  // accepted locally, never delivered
    }
    Pending& p = queue_[count_++];
    p.dest = dest;
    p.type = type;
    p.payload_size = payload.size;
    std::memcpy(p.payload.data(), payload.data, payload.size);
    return Status::success();
  }
  // Deliver every queued frame to the peer sink, in enqueue order (a manifest
  // always precedes its chunks).
  void flush(const MonotonicMs now_ms) noexcept {
    const std::size_t n = count_;
    count_ = 0;  // re-entrant sends enqueue behind the batch being drained
    for (std::size_t i = 0; i < n; ++i) {
      const Pending& p = queue_[i];
      if (peer_slot_ == nullptr) continue;
      ++delivered;
      wire::PlainFrame frame{};
      frame.header.type = p.type;
      frame.header.origin = self_;
      frame.header.destination = p.dest;
      frame.payload_size = p.payload_size;
      std::memcpy(frame.payload.data(), p.payload.data(), p.payload_size);
      peer_slot_->on_config_frame(self_, frame, now_ms);
    }
  }
  NodeId peer_dest_{kInvalidNodeId};
  bool drop{false};
  int sent{0};
  int delivered{0};
  int skipped{0};

 private:
  struct Pending {
    NodeId dest{kInvalidNodeId};
    FrameType type{FrameType::Data};
    std::array<std::uint8_t, kMaxApplicationPayload> payload{};
    std::size_t payload_size{0};
  };
  NodeId self_;
  ConfigEndpointSink*& peer_slot_;
  std::array<Pending, kQueueMax> queue_{};
  std::size_t count_{0};
};

// Records every gateway -> host reply.
class RecordingHost final : public ConfigHostSink {
 public:
  void on_config_reply(const std::uint64_t request, const std::uint8_t sub,
                       const ConfigOpsResult result, const NodeId target,
                       const ByteView body, const MonotonicMs) noexcept override {
    ++calls;
    last_request = request;
    last_sub = sub;
    last_result = result;
    last_target = target;
    last_body.size = body.size;
    std::memcpy(last_body.bytes.data(), body.data, body.size);
  }
  int calls{0};
  std::uint64_t last_request{0};
  std::uint8_t last_sub{0};
  ConfigOpsResult last_result{ConfigOpsResult::Invalid};
  NodeId last_target{kInvalidNodeId};
  ByteBuffer<kMaxApplicationPayload> last_body{};
};

// --- Rig --------------------------------------------------------------------

struct TargetRig {
  ConfigJournalConfig config{};
  FakeJournalStorage storage{};
  DevConfigAuthorityVerifier verifier{dev_key()};
  CountingEntropy entropy{};
  ConfigRateLimiter rate{};
  FakeProvider provider{};
  PermitAllGate gate{};
  PermissiveValidator validator{};
  std::unique_ptr<ConfigJournal> journal{};

  explicit TargetRig(const std::uint64_t boot = kBoot) {
    config.network = kNet;
    config.target = kTarget;
    config.config_namespace = endpoint::kConfigNamespaceSdk;
    config.schema = 1;
    config.boot_incarnation = boot;
    config.authorized_issuer = kAuthority;
    config.authority_generation = 1;
    config.challenge_valid_ms = kConfigChallengeMaxMs;
    journal = std::make_unique<ConfigJournal>(config, storage, verifier, entropy,
                                            rate, &provider, nullptr, &gate);
  }
};

// --- Dev permit profile ------------------------------------------------------

ConfigField sdk_bool(const std::uint16_t id, const bool value) {
  ConfigField field{};
  field.field_id = id;
  field.type = ConfigFieldType::Bool;
  field.value_size = 1;
  field.value[0] = value ? 1 : 0;
  return field;
}

// A valid command for (net,target,ns) at `expected_revision`. `next` and the
// two snapshot hashes are derived exactly the way the journal re-derives
// them — config_patch_apply over the base snapshot — so the signed hashes
// match the target's own recomputation.
ConfigCommand make_command(const endpoint::ControlChallenge& challenge,
                           const std::uint64_t expected_revision,
                           const ConfigField* patch, const std::uint16_t count,
                           const ByteView base_snapshot) {
  ConfigCommand command{};
  command.config_namespace = endpoint::kConfigNamespaceSdk;
  command.schema = 1;
  command.network = kNet;
  command.target = kTarget;
  command.authority = kAuthority;
  command.authority_generation = 1;
  command.authority_sequence = 1;
  command.operation_id = {0xA5, 1, 2, 3, 4, 5, 6, 7,
                          8, 9, 10, 11, 12, 13, 14, 15};
  command.expected_revision = expected_revision;
  command.next_revision = expected_revision + 1;
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  const Status applied =
      config_patch_apply(base_snapshot, patch, count, next, changed);
  CHECK_OK(applied);
  CHECK(changed);
  CHECK_OK(config_snapshot_hash(endpoint::kConfigNamespaceSdk, 1, base_snapshot,
                                command.base_snapshot_hash));
  CHECK_OK(config_snapshot_hash(endpoint::kConfigNamespaceSdk, 1, next.view(),
                                command.next_snapshot_hash));
  command.target_boot = challenge.target_boot;
  command.challenge_nonce = challenge.challenge_nonce;
  command.apply_within_ms = challenge.valid_for_ms;
  command.field_count = count;
  for (std::uint16_t i = 0; i < count; ++i) command.fields[i] = patch[i];
  return command;
}

void test_dev_permit_roundtrip() {
  DevConfigPermitSigner signer(dev_key());
  DevConfigAuthorityVerifier verifier(dev_key());
  CHECK(signer.ready() && verifier.ready());
  CHECK(signer.security_profile() == SecurityProfile::Development);
  CHECK(verifier.security_profile() == SecurityProfile::Development);

  endpoint::ControlChallenge challenge{};
  challenge.target_boot = kBoot;
  challenge.challenge_nonce = {1, 2, 3, 4, 5, 6, 7, 8,
                             9, 10, 11, 12, 13, 14, 15, 16};
  challenge.valid_for_ms = 1000;
  const ConfigField fields[] = {sdk_bool(2, true)};
  ByteBuffer<endpoint::kConfigSnapshotMax> base{};
  ConfigCommand command = make_command(challenge, 0, fields, 1, base.view());
  endpoint::EncodedConfigCommand canonical{};
  CHECK_OK(endpoint::config_command_encode(command, canonical));
  ByteBuffer<kConfigPermitObjectMax> permit{};
  CHECK_OK(signer.sign(command, canonical.view(), permit));

  ConfigPermitContext context{};
  context.network = kNet;
  context.target = kTarget;
  context.config_namespace = endpoint::kConfigNamespaceSdk;
  context.authorized_issuer = kAuthority;
  context.authority_generation = 1;
  endpoint::EncodedConfigCommand payload{};
  bool verified = false;
  CHECK_OK(verifier.verify_permit(context, permit.view(), payload, verified));
  CHECK(verified);
  CHECK(payload.size == canonical.size);
  CHECK(std::memcmp(payload.bytes.data(), canonical.bytes.data(),
                    canonical.size) == 0);

  // Wrong verifier key -> denied, not an error.
  const std::array<std::uint8_t, 16> wrong_key = {9, 9, 9, 9, 9, 9, 9, 9,
                                                9, 9, 9, 9, 9, 9, 9, 9};
  DevConfigAuthorityVerifier bad_verifier(
      ByteView{wrong_key.data(), wrong_key.size()});
  verified = true;
  payload.size = 0;
  CHECK_OK(
      bad_verifier.verify_permit(context, permit.view(), payload, verified));
  CHECK(!verified);

  // A different target's context -> the aad binding fails -> denied.
  ConfigPermitContext other = context;
  other.target = 0x7777;
  verified = true;
  CHECK_OK(verifier.verify_permit(other, permit.view(), payload, verified));
  CHECK(!verified);

  // The configured authority must match the command's claimed authority.
  ConfigPermitContext wrong_issuer = context;
  wrong_issuer.authorized_issuer = 0x99;
  verified = true;
  CHECK_OK(verifier.verify_permit(wrong_issuer, permit.view(), payload,
                                  verified));
  CHECK(!verified);

  // Tamper with the tag -> denied.
  ByteBuffer<kConfigPermitObjectMax> tampered = permit;
  tampered.bytes[tampered.size - 1] ^= 0xFF;
  verified = true;
  CHECK_OK(verifier.verify_permit(context, tampered.view(), payload, verified));
  CHECK(!verified);

  // Truncated envelope -> malformed (error), not denied.
  verified = true;
  const Status trunc = verifier.verify_permit(
      context, ByteView{permit.bytes.data(), kConfigDevPermitMin - 1}, payload,
      verified);
  CHECK(!trunc.ok());
}

// --- Wire round trips ---------------------------------------------------------

// Advance both endpoints one bounded step: each poll() may enqueue more
// outbound work, then both queues flush into the peer (the deferred routed
// delivery). Manifests always precede their chunks within one batch.
void pump(ConfigGateway& gateway, ConfigTarget& target, LoopbackPort& gw_port,
          LoopbackPort& tgt_port, MonotonicMs& now_ms, const int rounds = 8) {
  for (int i = 0; i < rounds; ++i) {
    now_ms += 10;
    gateway.poll(now_ms);
    target.poll(now_ms);
    gw_port.flush(now_ms);
    tgt_port.flush(now_ms);
  }
}

void test_challenge_status_wire() {
  MonotonicMs now_ms = 1000;
  ConfigEndpointSink* gw_peer = nullptr;   // bound to target below
  ConfigEndpointSink* tgt_peer = nullptr;  // bound to gateway below
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  gw_port.peer_dest_ = kTarget;
  tgt_port.peer_dest_ = kGateway;

  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now_ms));
  ConfigTarget target(tgt_port);
  CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
  RecordingHost host{};
  ConfigGateway gateway(gw_port, host);
  tgt_peer = &target;
  gw_peer = &gateway;

  // Challenge.
  const std::array<std::uint8_t, 16> client_nonce = {1, 1, 1, 1, 1, 1, 1, 1,
                                                   1, 1, 1, 1, 1, 1, 1, 1};
  CHECK_OK(gateway.submit_challenge(0xC0, kTarget, endpoint::kConfigNamespaceSdk,
                                    1, client_nonce, now_ms));
  pump(gateway, target, gw_port, tgt_port, now_ms);
  CHECK(host.calls == 1);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  CHECK(host.last_sub == 0x23);
  CHECK(host.last_target == kTarget);
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(host.last_body.view(), challenge));
  CHECK(challenge.target_boot == kBoot);
  CHECK(challenge.client_nonce == client_nonce);  // the query's nonce echoed

  // A second query while one is outstanding reports Busy (admission, not a
  // wire failure); the outstanding one still resolves normally.
  CHECK_OK(gateway.submit_challenge(0xC1, kTarget, endpoint::kConfigNamespaceSdk,
                                    1, client_nonce, now_ms));
  const Status busy =
      gateway.submit_challenge(0xC2, kTarget, endpoint::kConfigNamespaceSdk, 1,
                               client_nonce, now_ms);
  CHECK(!busy.ok());
  pump(gateway, target, gw_port, tgt_port, now_ms);
  CHECK(host.calls == 2);
  CHECK(host.last_result == ConfigOpsResult::Ok);

  // A status query for an operation the target never saw gets no reply — the
  // gateway reports the honest Indeterminate at the deadline, not success.
  const std::array<std::uint8_t, 16> unknown_opid = {0xAA, 1, 2, 3, 4, 5, 6, 7,
                                                   8, 9, 10, 11, 12, 13, 14, 15};
  CHECK_OK(gateway.submit_status_query(0xC3, kTarget,
                                       endpoint::kConfigNamespaceSdk,
                                       unknown_opid, now_ms));
  for (int i = 0; i < 400; ++i) {
    now_ms += 10;
    gateway.poll(now_ms);
    target.poll(now_ms);
    gw_port.flush(now_ms);
    tgt_port.flush(now_ms);
  }
  // Timeout, not success — the target never answered inside the window.
  CHECK(host.last_result == ConfigOpsResult::Timeout);
}

// The full chain: challenge -> build RCC1 -> dev-sign -> object transfer ->
// journal verify/decide -> status shows the new revision.
void test_permit_transfer_e2e() {
  MonotonicMs now_ms = 2000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  gw_port.peer_dest_ = kTarget;
  tgt_port.peer_dest_ = kGateway;

  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now_ms));
  ConfigTarget target(tgt_port);
  CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
  RecordingHost host{};
  ConfigGateway gateway(gw_port, host);
  tgt_peer = &target;
  gw_peer = &gateway;

  // 1. Challenge over the wire.
  const std::array<std::uint8_t, 16> client_nonce = {2, 2, 2, 2, 2, 2, 2, 2,
                                                   2, 2, 2, 2, 2, 2, 2, 2};
  CHECK_OK(gateway.submit_challenge(0xD0, kTarget, endpoint::kConfigNamespaceSdk,
                                    1, client_nonce, now_ms));
  pump(gateway, target, gw_port, tgt_port, now_ms);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(host.last_body.view(), challenge));

  // 2. Build + sign the permit the issuer would produce.
  const ConfigField fields[] = {sdk_bool(2, true)};
  ByteBuffer<endpoint::kConfigSnapshotMax> base{};
  ConfigCommand command = make_command(challenge, challenge.revision, fields, 1,
                                       base.view());
  DevConfigPermitSigner signer(dev_key());
  endpoint::EncodedConfigCommand canonical{};
  CHECK_OK(endpoint::config_command_encode(command, canonical));
  ByteBuffer<kConfigPermitObjectMax> permit{};
  CHECK_OK(signer.sign(command, canonical.view(), permit));

  // 3. Transfer the object. The journal assembles + submits it internally;
  //    the Ok ack means "assembled", proven by the journal revision after.
  CHECK_OK(gateway.submit_permit(0xD1, kTarget, permit.view(), now_ms));
  pump(gateway, target, gw_port, tgt_port, now_ms, 40);
  CHECK(host.calls >= 2);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  CHECK(host.last_sub == 0x21);
  CHECK(target.object_acks() >= 1);

  // The journal must have actually decided (revision 1, provider applied).
  CHECK(rig.journal->decision_revision() == 1);
  CHECK(rig.provider.apply_calls >= 1);

  // 4. A status query for the permit's own operation id returns the committed
  //    revision to the host (the journal knows the record it just created).
  CHECK_OK(gateway.submit_status_query(0xD2, kTarget,
                                       endpoint::kConfigNamespaceSdk,
                                       command.operation_id, now_ms));
  pump(gateway, target, gw_port, tgt_port, now_ms);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  endpoint::ControlStatus status{};
  CHECK_OK(endpoint::control_status_decode(host.last_body.view(), status));
  CHECK(status.decision_revision == 1);
}

// An undelivered query resolves honestly at its deadline as Indeterminate.
void test_query_timeout() {
  MonotonicMs now_ms = 3000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  gw_port.peer_dest_ = kTarget;
  gw_port.drop = true;  // black hole: sends succeed, nothing arrives
  RecordingHost host{};
  ConfigGateway gateway(gw_port, host);
  (void)tgt_peer;

  const std::array<std::uint8_t, 16> nonce = {3, 3, 3, 3, 3, 3, 3, 3,
                                              3, 3, 3, 3, 3, 3, 3, 3};
  CHECK_OK(gateway.submit_challenge(0xE0, kTarget, endpoint::kConfigNamespaceSdk,
                                    1, nonce, now_ms));
  for (int i = 0; i < 400; ++i) {
    now_ms += 10;
    gateway.poll(now_ms);
  }
  CHECK(host.calls == 1);
  // Query deadline is reported as Timeout — the honest non-Ok terminal state.
  CHECK(host.last_result == ConfigOpsResult::Timeout);
}

}  // namespace

int main() {
  test_dev_permit_roundtrip();
  test_challenge_status_wire();
  test_permit_transfer_e2e();
  test_query_timeout();
  if (failures == 0) {
    std::printf("config_wire tests OK\n");
    return 0;
  }
  std::fprintf(stderr, "%d config_wire check(s) failed\n", failures);
  return 1;
}
