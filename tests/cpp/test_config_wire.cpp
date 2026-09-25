// Routed config-wire tests (05-wire-api.md §5.5/§5.6): the dev-profile
// permit signer/verifier and the ConfigTarget/ConfigGateway endpoints driven
// back-to-back over a loopback ConfigWirePort. The challenge -> sign ->
// manifest/chunk -> ack -> apply path runs the REAL ConfigJournal — the
// target's single assembler feeds submit_permit/submit_recovery/
// trust_manifest_accept by kind, so the wire test exercises verify/dedup/
// admission/decide end to end. Transport success is still never a verdict:
// the assertions read the journal's (or trust store's) own state afterwards.

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
#include "routeloom/sdkv1_authority_transport.hpp"
#include "routeloom/security_floor.hpp"
#include "routeloom/trust_manifest.hpp"
#include "routeloom/trust_store.hpp"
#include "routeloom/wire.hpp"

#include "test_provisioning.hpp"

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
using routeloom_test::FaultyTrustStorage;
using routeloom_test::sign_digest_low_s;
using routeloom_test::test_image;
using routeloom_test::test_key_record;
using routeloom_test::test_keypair;
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

class FakeFloorStore final : public SecurityFloorStorage {
 public:
  Status read(const MutableByteView target) noexcept override {
    if (target.size != kSecurityFloorBlobBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad floor read");
    }
    if (!provisioned) {
      return Status::error(StatusCode::NotFound, "floor missing");
    }
    std::memcpy(target.data, blob_.data(), kSecurityFloorBlobBytes);
    return Status::success();
  }
  Status write(const ByteView data) noexcept override {
    if (data.size != kSecurityFloorBlobBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad floor write");
    }
    std::memcpy(blob_.data(), data.data, data.size);
    provisioned = true;
    return Status::success();
  }
  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob_{};
  bool provisioned{false};
};

void seed_floor(FakeFloorStore& storage, const std::uint64_t network,
                const std::uint64_t target, const std::uint16_t ns,
                const std::uint16_t schema) {
  SecurityFloorState state{};
  state.network = network;
  state.target = target;
  state.namespace_count = 1;
  state.entries[0].config_namespace = ns;
  state.entries[0].schema = schema;
  SecurityFloorStore floor(storage);
  CHECK_OK(floor.provision_seed(state));
}

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

// Records the last ObjectAck delivered to a sink (target-side ack observe).
class RecordingAckSink final : public ConfigEndpointSink {
 public:
  void on_config_frame(const NodeId, const wire::PlainFrame& frame,
                       const MonotonicMs) noexcept override {
    if (frame.header.type != FrameType::ObjectAck) return;
    autonomy::ObjectAckPayload ack{};
    if (autonomy::object_ack_decode(
            ByteView{frame.payload.data(), frame.payload_size}, ack)) {
      ++acks;
      last_status = ack.status;
      last_received = ack.received_len;
    }
  }
  void on_config_job_done(const MessageId&, bool, const char*,
                          const MonotonicMs) noexcept override {}
  void poll(const MonotonicMs) noexcept override {}
  int acks{0};
  autonomy::ObjectAckStatus last_status{autonomy::ObjectAckStatus::Ok};
  std::uint16_t last_received{0};
};

// A terminal-side PlainFrame as the routed lane would deliver it.
wire::PlainFrame object_frame(const NodeId origin, const FrameType type,
                              const ByteView payload) {
  wire::PlainFrame frame{};
  frame.header.type = type;
  frame.header.origin = origin;
  frame.header.destination = kTarget;
  frame.payload_size = payload.size;
  std::memcpy(frame.payload.data(), payload.data, payload.size);
  return frame;
}

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
    if (body.size > 0) {
      std::memcpy(last_body.bytes.data(), body.data, body.size);
    }
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
  FakeFloorStore floor_storage{};
  DevConfigAuthorityVerifier verifier{dev_key()};
  CountingEntropy entropy{};
  ConfigRateLimiter rate{};
  FakeProvider provider{};
  PermitAllGate gate{};
  PermissiveValidator validator{};
  std::unique_ptr<SecurityFloorStore> floor{};
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
    seed_floor(floor_storage, config.network, config.target,
               config.config_namespace, config.schema);
    floor = std::make_unique<SecurityFloorStore>(floor_storage);
    CHECK_OK(floor->initialize());
    journal = std::make_unique<ConfigJournal>(config, storage, *floor, verifier,
                                            entropy, rate, &provider, nullptr,
                                            &gate);
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

// Test-only dev envelope minter (the device carries no issuance path —
// the production issuer is the Rust host). Mirrors the envelope byte
// layout via the public tag helper.
void dev_wrap_permit(const ConfigCommand& command, const ByteView canonical,
                     ByteBuffer<kConfigPermitObjectMax>& permit) {
  ByteBuffer<kConfigPermitAadSize> aad{};
  CHECK_OK(config_permit_aad(command.network, command.target,
                           command.config_namespace, aad));
  std::array<std::uint8_t, kConfigDevPermitTagSize> tag{};
  CHECK_OK(config_dev_permit_tag(dev_key(), aad.view(), canonical, tag));
  CHECK(aad.size + canonical.size + tag.size() <= permit.bytes.size());
  std::memcpy(permit.bytes.data(), aad.bytes.data(), aad.size);
  std::memcpy(permit.bytes.data() + aad.size, canonical.data, canonical.size);
  std::memcpy(permit.bytes.data() + aad.size + canonical.size, tag.data(),
              tag.size());
  permit.size = aad.size + canonical.size + tag.size();
}

void test_dev_permit_roundtrip() {
  DevConfigAuthorityVerifier verifier(dev_key());
  CHECK(verifier.ready());
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
  dev_wrap_permit(command, canonical.view(), permit);

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

// Argument and capacity failures carry distinct status codes: malformed
// arguments are InvalidArgument, an oversized aggregate is NoCapacity
// (the staged ByteWriter overflow code the streamed path replaced).
void test_dev_permit_tag_status_codes() {
  std::array<std::uint8_t, kConfigDevPermitTagSize> tag{};
  std::array<std::uint8_t, kConfigPermitAadSize> aad{};
  const ByteView key = dev_key();
  const ByteView canonical{reinterpret_cast<const std::uint8_t*>("x"), 1};

  const ByteView aad_view{aad.data(), aad.size()};
  Status status =
      config_dev_permit_tag(ByteView{}, aad_view, canonical, tag);
  CHECK(status.code == StatusCode::InvalidArgument);
  status = config_dev_permit_tag(key, ByteView{aad.data(), 1}, canonical, tag);
  CHECK(status.code == StatusCode::InvalidArgument);
  status = config_dev_permit_tag(key, aad_view, ByteView{}, tag);
  CHECK(status.code == StatusCode::InvalidArgument);

  std::array<std::uint8_t, kConfigPermitObjectMax> huge{};
  const ByteView oversized{huge.data(), huge.size()};
  status = config_dev_permit_tag(key, aad_view, oversized, tag);
  CHECK(status.code == StatusCode::NoCapacity);
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
  ConfigTarget target(tgt_port, rig.rate);
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
  ConfigTarget target(tgt_port, rig.rate);
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
  endpoint::EncodedConfigCommand canonical{};
  CHECK_OK(endpoint::config_command_encode(command, canonical));
  ByteBuffer<kConfigPermitObjectMax> permit{};
  dev_wrap_permit(command, canonical.view(), permit);

  // 3. Transfer the object. The target assembles it, the journal submits;
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

// A duplicate manifest carrying the live object's hash but a DIFFERENT
// declared length is a conflict — it must be Failed, not re-acked as
// progress against a byte count the reassembly never accepted.
void test_manifest_duplicate_total_len_conflict() {
  MonotonicMs now_ms = 4000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  tgt_port.peer_dest_ = kGateway;

  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now_ms));
  ConfigTarget target(tgt_port, rig.rate);
  CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
  RecordingAckSink sink{};
  gw_peer = &sink;

  const std::array<std::uint8_t, 8> obj{{1, 2, 3, 4, 5, 6, 7, 8}};
  autonomy::ControlObjectPayload manifest{};
  manifest.subtype = autonomy::ControlObjectSubtype::Manifest;
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  manifest.total_len = static_cast<std::uint16_t>(obj.size());
  sha256(ByteView{obj.data(), obj.size()}, manifest.object_hash);
  autonomy::EncodedPayload encoded{};
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));

  // First manifest opens the intake: the ack is Incomplete, slot held.
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(sink.acks == 1);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Incomplete);
  CHECK(target.object_active());

  // Same object hash, different declared length → conflict answer Failed.
  manifest.total_len = 64;
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(sink.acks == 2);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
  CHECK(target.object_active());  // the live intake is untouched

  // A byte-consistent duplicate still re-acks as Incomplete — only the
  // length-mismatched variant is a conflict.
  manifest.total_len = static_cast<std::uint16_t>(obj.size());
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(sink.acks == 3);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Incomplete);
}

// An end-authenticated reply that does not echo THIS query's client_nonce /
// operation_id (or its namespace) is a foreign frame — it must never
// complete the outstanding query.
void test_query_reply_echo_binding() {
  MonotonicMs now_ms = 5000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  gw_port.peer_dest_ = kTarget;
  tgt_port.peer_dest_ = kGateway;
  RecordingHost host{};
  ConfigGateway gateway(gw_port, host);
  (void)tgt_peer;

  const std::array<std::uint8_t, 16> client_nonce = {9, 9, 9, 9, 9, 9, 9, 9,
                                                   9, 9, 9, 9, 9, 9, 9, 9};
  CHECK_OK(gateway.submit_challenge(0xF0, kTarget, endpoint::kConfigNamespaceSdk,
                                    1, client_nonce, now_ms));
  gw_port.flush(now_ms);   // the query goes out; nothing answers it yet

  endpoint::ControlChallenge forged{};
  forged.config_namespace = endpoint::kConfigNamespaceSdk;
  forged.schema = 1;
  forged.target_boot = 9;
  forged.revision = 1;
  forged.valid_for_ms = 60000;
  forged.challenge_nonce.fill(0x33);
  forged.active_hash.fill(0x44);
  endpoint::EncodedServicePayload enc{};

  // Right origin, right subtype, valid encoding — WRONG nonce echo.
  forged.client_nonce.fill(0x77);
  CHECK_OK(endpoint::control_challenge_encode(forged, enc));
  gateway.on_config_frame(kTarget, object_frame(kTarget, FrameType::Control,
                                                enc.view()),
                          now_ms);
  CHECK(host.calls == 0);
  CHECK(gateway.query_active());

  // Right nonce echo but a different namespace — still foreign.
  forged.client_nonce = client_nonce;
  forged.config_namespace = 0x8000;   // a different registered namespace
  CHECK_OK(endpoint::control_challenge_encode(forged, enc));
  gateway.on_config_frame(kTarget, object_frame(kTarget, FrameType::Control,
                                                enc.view()),
                          now_ms);
  CHECK(host.calls == 0);
  CHECK(gateway.query_active());

  // The query outlives the forgeries and resolves honestly at its deadline.
  for (int i = 0; i < 400; ++i) {
    now_ms += 10;
    gateway.poll(now_ms);
  }
  CHECK(host.calls == 1);
  CHECK(host.last_result == ConfigOpsResult::Timeout);

  // Status query: a reply echoing a different operation_id never completes.
  const std::array<std::uint8_t, 16> operation_id = {0xA1, 1, 2, 3, 4, 5, 6, 7,
                                                   8, 9, 10, 11, 12, 13, 14, 15};
  CHECK_OK(gateway.submit_status_query(0xF1, kTarget,
                                       endpoint::kConfigNamespaceSdk,
                                       operation_id, now_ms));
  gw_port.flush(now_ms);
  endpoint::ControlStatus status{};
  status.config_namespace = endpoint::kConfigNamespaceSdk;
  status.operation_id.fill(0x99);    // not the queried operation id
  status.phase = ConfigPhase::Active;
  status.reason = ConfigReason::Ok;
  CHECK_OK(endpoint::control_status_encode(status, enc));
  gateway.on_config_frame(kTarget, object_frame(kTarget, FrameType::Control,
                                                enc.view()),
                          now_ms);
  CHECK(host.calls == 1);            // still only the timeout report
  CHECK(gateway.query_active());

  // The correctly echoed reply DOES complete — binding, not silence.
  status.operation_id = operation_id;
  CHECK_OK(endpoint::control_status_encode(status, enc));
  gateway.on_config_frame(kTarget, object_frame(kTarget, FrameType::Control,
                                                enc.view()),
                          now_ms);
  CHECK(host.calls == 2);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  CHECK(!gateway.query_active());
}

// --- Kind-5 trust rig ---------------------------------------------------------

constexpr std::uint64_t kRootId = 0x100;

struct TrustRig {
  FaultyTrustStorage storage{};
  std::unique_ptr<TrustStore> store{};
  routeloom_test::TestKeyPair root = test_keypair(0x11);

  // Provision an epoch-1 image (root anchor active, one active config key)
  // on the journal's own floor — the real shared-floor topology.
  void provision(TargetRig& rig) {
    store = std::make_unique<TrustStore>(storage);
    CHECK_OK(store->initialize());
    TrustImage base = test_image(1, kNet, root, kRootId);
    base.keys[0] = test_key_record(kAuthority, 1, test_keypair(0x33).pub,
                                   TrustKeyStatus::Active);
    base.key_count = 1;
    CHECK_OK(store->commit_image(base));
    store->attach_floor(rig.floor.get());
  }

  // A real root-signed RTM1 for `image` (the RootSigner path: RLT1 body,
  // Sig_structure under the committed network's AAD, low-S signature).
  void make_manifest(const TrustImage& image,
                     ByteBuffer<kTrustManifestObjectMax>& out) {
    ByteBuffer<kTrustImageContentMax> content{};
    CHECK_OK(trust_image_body_encode(image, content));
    ByteBuffer<kTrustManifestProtectedSize> protected_bytes{};
    CHECK_OK(trust_manifest_protected(kRootId, protected_bytes));
    ByteBuffer<kTrustManifestAadSize> aad{};
    CHECK_OK(trust_manifest_aad(image.network, aad));
    ByteBuffer<kTrustManifestSigMax> sig_structure{};
    CHECK_OK(trust_manifest_sig_structure(protected_bytes.view(), aad.view(),
                                          content.view(), sig_structure));
    Digest256 digest{};
    sha256(sig_structure.view(), digest);
    std::array<std::uint8_t, 64> signature{};
    CHECK(sign_digest_low_s(root.priv, digest, signature));
    CHECK_OK(trust_manifest_assemble(content.view(), kRootId,
                                     ByteView{signature.data(), signature.size()},
                                     out));
  }

  TrustImage next_image(const std::uint32_t epoch) {
    TrustImage next = test_image(epoch, kNet, root, kRootId);
    next.keys[0] = test_key_record(kAuthority, 1, test_keypair(0x33).pub,
                                   TrustKeyStatus::Active);
    next.key_count = 1;
    next.min_authority_generation = 2;
    return next;
  }
};

// Deliver `object` as `kind` straight into a target (direct injection;
// acks flush to the sink). Returns the terminal ack status.
autonomy::ObjectAckStatus deliver_direct(ConfigTarget& target,
                                         LoopbackPort& port,
                                         RecordingAckSink& sink,
                                         const NodeId origin,
                                         const autonomy::ControlObjectKind kind,
                                         const ByteView object,
                                         MonotonicMs& t) {
  autonomy::ControlObjectPayload manifest{};
  manifest.subtype = autonomy::ControlObjectSubtype::Manifest;
  manifest.kind = kind;
  manifest.total_len = static_cast<std::uint16_t>(object.size);
  sha256(object, manifest.object_hash);
  autonomy::EncodedPayload encoded{};
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(origin, object_frame(origin, FrameType::ControlObject,
                                              encoded.view()),
                         t);
  port.flush(t);
  if (sink.last_status == autonomy::ObjectAckStatus::Failed) {
    return sink.last_status;
  }
  for (std::uint16_t offset = 0; offset < object.size;
       offset = static_cast<std::uint16_t>(offset + 90)) {
    autonomy::ObjectChunkPayload chunk{};
    chunk.subtype = autonomy::ObjectChunkSubtype::Chunk;
    chunk.object_hash = manifest.object_hash;
    chunk.offset = offset;
    chunk.data_size = static_cast<std::uint16_t>(
        object.size - offset < 90 ? object.size - offset : 90);
    std::memcpy(chunk.data.data(), object.data + offset, chunk.data_size);
    CHECK_OK(autonomy::object_chunk_encode(chunk, encoded));
    t += 10;
    target.on_config_frame(origin, object_frame(origin, FrameType::ObjectChunk,
                                                encoded.view()),
                           t);
    port.flush(t);
    if (sink.last_status == autonomy::ObjectAckStatus::Failed) {
      return sink.last_status;
    }
  }
  return sink.last_status;
}

// The pinned (origin, kind, hash, total_len) tuple, the kind caps, unknown
// kinds, and the no-extension deadline — direct target injection.
void test_single_assembler_discipline() {
  MonotonicMs now_ms = 6000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort tgt_port(kTarget, gw_peer);
  tgt_port.peer_dest_ = kGateway;
  (void)tgt_peer;

  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now_ms));
  ConfigTarget target(tgt_port, rig.rate);
  CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
  RecordingAckSink sink{};
  gw_peer = &sink;
  autonomy::EncodedPayload encoded{};

  // Kind 3 over the 1024 B permit cap is denied without an ack (the
  // carrier itself allows 2048 — the KIND cap refuses).
  autonomy::ControlObjectPayload manifest{};
  manifest.subtype = autonomy::ControlObjectSubtype::Manifest;
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  manifest.total_len = kConfigPermitObjectMax + 1;
  manifest.object_hash[0] = 1;
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(target.control_denied() == 1);
  CHECK(sink.acks == 0);

  // Unknown kind 6 never decodes — denied without an ack. Migration kind
  // 1 decodes but never routes here — denied the same way.
  manifest.kind = static_cast<autonomy::ControlObjectKind>(6);
  manifest.total_len = 64;
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  manifest.kind = autonomy::ControlObjectKind::ChannelPlan;
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(target.control_denied() == 3);
  CHECK(sink.acks == 0);

  // Kind 5 without an attached trust store is a KNOWN kind the node cannot
  // serve: Failed-acked, not silently denied.
  manifest.kind = autonomy::ControlObjectKind::TrustManifest;
  manifest.total_len = static_cast<std::uint16_t>(kConfigTrustObjectMax);
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(sink.acks == 1);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
  CHECK(!target.object_active());

  // Open a kind-3 assembly; everything off-tuple refuses against it.
  const std::array<std::uint8_t, 8> obj{{1, 2, 3, 4, 5, 6, 7, 8}};
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  manifest.total_len = static_cast<std::uint16_t>(obj.size());
  sha256(ByteView{obj.data(), obj.size()}, manifest.object_hash);
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Incomplete);
  CHECK(target.object_active());

  // Same hash, different kind (kind 4) → Failed; the live assembly stands.
  autonomy::ControlObjectPayload other = manifest;
  other.kind = autonomy::ControlObjectKind::ConfigRecovery;
  CHECK_OK(autonomy::control_object_encode(other, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
  CHECK(target.object_active());

  // Same tuple, different origin → Failed (origin is pinned too).
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kAuthority, object_frame(kAuthority,
                                                  FrameType::ControlObject,
                                                  encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
  autonomy::ObjectChunkPayload chunk{};
  chunk.subtype = autonomy::ObjectChunkSubtype::Chunk;
  chunk.object_hash = manifest.object_hash;
  chunk.offset = 0;
  chunk.data_size = static_cast<std::uint16_t>(obj.size());
  std::memcpy(chunk.data.data(), obj.data(), obj.size());
  CHECK_OK(autonomy::object_chunk_encode(chunk, encoded));
  const std::uint32_t denied_before = target.control_denied();
  target.on_config_frame(kAuthority, object_frame(kAuthority,
                                                  FrameType::ObjectChunk,
                                                  encoded.view()),
                         now_ms);
  tgt_port.flush(now_ms);
  CHECK(target.control_denied() == denied_before + 1);  // no ack for it
  CHECK(target.object_active());

  // A byte-consistent duplicate re-acks Incomplete — but does NOT extend
  // the deadline: a chunk past the ORIGINAL 10 s still fails.
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ControlObject,
                                                encoded.view()),
                         now_ms + 9990);
  tgt_port.flush(now_ms + 9990);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Incomplete);
  CHECK(target.object_active());
  CHECK_OK(autonomy::object_chunk_encode(chunk, encoded));
  target.on_config_frame(kGateway, object_frame(kGateway, FrameType::ObjectChunk,
                                                encoded.view()),
                         now_ms + kConfigReassemblyTimeoutMs + 1);
  tgt_port.flush(now_ms + kConfigReassemblyTimeoutMs + 1);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
  CHECK(!target.object_active());
}

// Kind-5 end to end: a real root-signed RTM1 rides the gateway trust slot
// to the target, the store advances, and the host learns nothing but
// transport success (epoch proof is a separate TrustStatus query).
void test_kind5_trust_delivery_e2e() {
  MonotonicMs now_ms = 7000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  gw_port.peer_dest_ = kTarget;
  tgt_port.peer_dest_ = kGateway;

  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now_ms));
  TrustRig trust{};
  trust.provision(rig);
  ConfigTarget target(tgt_port, rig.rate);
  CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
  target.attach_trust_store(*trust.store, *rig.floor);
  RecordingHost host{};
  ConfigGateway gateway(gw_port, host);
  tgt_peer = &target;
  gw_peer = &gateway;

  ByteBuffer<kTrustManifestObjectMax> object{};
  trust.make_manifest(trust.next_image(2), object);
  CHECK(object.size > 0 && object.size <= kConfigTrustObjectMax);
  CHECK_OK(gateway.submit_trust(0xE5, kTarget, object.view(), now_ms));
  CHECK(gateway.trust_transfer_active());
  pump(gateway, target, gw_port, tgt_port, now_ms, 40);
  CHECK(host.calls == 1);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  CHECK(host.last_sub == 0x25);
  CHECK(host.last_target == kTarget);
  CHECK(!gateway.trust_transfer_active());
  // The store really advanced — transport Ok never implies it alone.
  CHECK(trust.store->store_epoch() == 2);
  CHECK(trust.store->min_authority_generation() == 2);
  SecurityFloorState floor_state{};
  CHECK_OK(rig.floor->read(floor_state));
  CHECK(floor_state.trust_epoch_floor == 2);

  // Without the trust connection the same object is refused (Denied, and
  // the store it never reached stays put).
  MonotonicMs t2 = 8000;
  TargetRig rig2{};
  CHECK_OK(rig2.journal->initialize(t2));
  TrustRig trust2{};
  trust2.provision(rig2);
  ConfigEndpointSink* gw_peer2 = nullptr;
  ConfigEndpointSink* tgt_peer2 = nullptr;
  LoopbackPort gw_port2(kGateway, tgt_peer2);
  LoopbackPort tgt_port2(kTarget, gw_peer2);
  gw_port2.peer_dest_ = kTarget;
  tgt_port2.peer_dest_ = kGateway;
  ConfigTarget target2(tgt_port2, rig2.rate);
  CHECK_OK(target2.add_journal(endpoint::kConfigNamespaceSdk, *rig2.journal));
  RecordingHost host2{};
  ConfigGateway gateway2(gw_port2, host2);
  tgt_peer2 = &target2;
  gw_peer2 = &gateway2;
  ByteBuffer<kTrustManifestObjectMax> object2{};
  trust2.make_manifest(trust2.next_image(2), object2);
  CHECK_OK(gateway2.submit_trust(0xE6, kTarget, object2.view(), t2));
  pump(gateway2, target2, gw_port2, tgt_port2, t2, 40);
  CHECK(host2.calls == 1);
  CHECK(host2.last_result == ConfigOpsResult::Denied);
  CHECK(host2.last_sub == 0x25);
  CHECK(trust2.store->store_epoch() == 1);
}

// The kind-5 verify shares the device's expensive-verify budget with the
// permit/recovery submits: back-to-back completions refuse, and a FAILED
// verify charges the budget exactly like a success.
void test_trust_verify_shares_budget() {
  MonotonicMs now_ms = 9000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort tgt_port(kTarget, gw_peer);
  tgt_port.peer_dest_ = kGateway;
  (void)tgt_peer;

  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now_ms));
  TrustRig trust{};
  trust.provision(rig);
  ConfigTarget target(tgt_port, rig.rate);
  CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
  target.attach_trust_store(*trust.store, *rig.floor);
  RecordingAckSink sink{};
  gw_peer = &sink;

  ByteBuffer<kTrustManifestObjectMax> object{};
  trust.make_manifest(trust.next_image(2), object);
  // First completion consumes the token and installs epoch 2.
  CHECK(deliver_direct(target, tgt_port, sink, kGateway,
                       autonomy::ControlObjectKind::TrustManifest,
                       object.view(), now_ms) ==
        autonomy::ObjectAckStatus::Ok);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Ok);
  CHECK(trust.store->store_epoch() == 2);
  // Immediate redelivery: the budget is spent — Failed, store untouched.
  CHECK(deliver_direct(target, tgt_port, sink, kGateway,
                       autonomy::ControlObjectKind::TrustManifest,
                       object.view(), now_ms) ==
        autonomy::ObjectAckStatus::Failed);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
  // Past the 5 s window the duplicate succeeds without a flash write.
  now_ms += ConfigRateLimiter::kExpensiveVerifyIntervalMs + 10;
  target.poll(now_ms);
  CHECK(deliver_direct(target, tgt_port, sink, kGateway,
                       autonomy::ControlObjectKind::TrustManifest,
                       object.view(), now_ms) ==
        autonomy::ObjectAckStatus::Ok);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Ok);
  CHECK(trust.store->store_epoch() == 2);

  // A garbage object on a fresh token reaches the verifier, fails, and
  // CHARGES the budget: the good redelivery right after still refuses.
  now_ms += ConfigRateLimiter::kExpensiveVerifyIntervalMs + 10;
  target.poll(now_ms);
  std::array<std::uint8_t, 128> garbage{};
  garbage.fill(0x5A);
  CHECK(deliver_direct(target, tgt_port, sink, kGateway,
                       autonomy::ControlObjectKind::TrustManifest,
                       ByteView{garbage.data(), garbage.size()},
                       now_ms) == autonomy::ObjectAckStatus::Failed);
  CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
  CHECK(trust.store->store_epoch() == 2);
  CHECK(deliver_direct(target, tgt_port, sink, kGateway,
                       autonomy::ControlObjectKind::TrustManifest,
                       object.view(), now_ms) ==
        autonomy::ObjectAckStatus::Failed);
  // And the budget recovers: past the window the good object lands again.
  now_ms += ConfigRateLimiter::kExpensiveVerifyIntervalMs + 10;
  target.poll(now_ms);
  CHECK(deliver_direct(target, tgt_port, sink, kGateway,
                       autonomy::ControlObjectKind::TrustManifest,
                       object.view(), now_ms) ==
        autonomy::ObjectAckStatus::Ok);
}

// TrustStatus query end to end, plus the nonce/network binding: a reply
// naming any other network is foreign, never this query's completion.
void test_trust_status_query_wire() {
  MonotonicMs now_ms = 10000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  gw_port.peer_dest_ = kTarget;
  tgt_port.peer_dest_ = kGateway;

  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now_ms));
  TrustRig trust{};
  trust.provision(rig);
  ConfigTarget target(tgt_port, rig.rate);
  CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
  target.attach_trust_store(*trust.store, *rig.floor);
  RecordingHost host{};
  ConfigGateway gateway(gw_port, host);
  tgt_peer = &target;
  gw_peer = &gateway;

  const std::array<std::uint8_t, 16> nonce = {5, 5, 5, 5, 1, 2, 3, 4,
                                              5, 6, 7, 8, 9, 10, 11, 12};
  CHECK_OK(gateway.submit_trust_status_query(0xF5, kTarget, kNet, nonce,
                                             now_ms));
  pump(gateway, target, gw_port, tgt_port, now_ms);
  CHECK(host.calls == 1);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  CHECK(host.last_sub == 0x26);
  endpoint::TrustStatus status{};
  CHECK_OK(endpoint::trust_status_decode(host.last_body.view(), status));
  CHECK(status.nonce_echo == nonce);
  CHECK(status.network == kNet);
  CHECK(status.store_epoch == 1);
  CHECK(status.min_authority_generation == 1);
  CHECK(status.anchor_count == 1);
  CHECK(status.key_count == 1);
  CHECK(status.revocation_count == 0);
  CHECK(status.flags == endpoint::kTrustStatusFlagHasActive);
  Digest256 zero{};
  CHECK(status.image_fingerprint != zero);

  // Forged bindings never complete: wrong network, then wrong nonce echo.
  CHECK_OK(gateway.submit_trust_status_query(0xF6, kTarget, kNet, nonce,
                                             now_ms));
  gw_port.flush(now_ms);
  endpoint::TrustStatus forged{};
  forged.nonce_echo = nonce;
  forged.network = kNet + 1;  // foreign deployment
  forged.store_epoch = 9;
  endpoint::EncodedServicePayload enc{};
  CHECK_OK(endpoint::trust_status_encode(forged, enc));
  gateway.on_config_frame(kTarget, object_frame(kTarget, FrameType::Control,
                                                enc.view()),
                          now_ms);
  CHECK(host.calls == 1);
  CHECK(gateway.query_active());
  forged.network = kNet;
  forged.nonce_echo.fill(0x77);  // wrong echo
  CHECK_OK(endpoint::trust_status_encode(forged, enc));
  gateway.on_config_frame(kTarget, object_frame(kTarget, FrameType::Control,
                                                enc.view()),
                          now_ms);
  CHECK(host.calls == 1);
  CHECK(gateway.query_active());
  // The honest reply still completes — binding, not silence.
  pump(gateway, target, gw_port, tgt_port, now_ms);
  CHECK(host.calls == 2);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  CHECK(host.last_sub == 0x26);
}

// RecoveryInfo query end to end: the baseline (J/R, version, profile,
// survivor) the host signs the next recovery against.
void test_recovery_info_query_wire() {
  MonotonicMs now_ms = 11000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  gw_port.peer_dest_ = kTarget;
  tgt_port.peer_dest_ = kGateway;

  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now_ms));
  ConfigTarget target(tgt_port, rig.rate);
  CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
  RecordingHost host{};
  ConfigGateway gateway(gw_port, host);
  tgt_peer = &target;
  gw_peer = &gateway;

  const std::array<std::uint8_t, 16> nonce = {6, 6, 6, 6, 1, 2, 3, 4,
                                              5, 6, 7, 8, 9, 10, 11, 12};
  CHECK_OK(gateway.submit_recovery_info_query(0xF7, kTarget, kNet,
                                              endpoint::kConfigNamespaceSdk,
                                              nonce, now_ms));
  pump(gateway, target, gw_port, tgt_port, now_ms);
  CHECK(host.calls == 1);
  CHECK(host.last_result == ConfigOpsResult::Ok);
  CHECK(host.last_sub == 0x27);
  endpoint::RecoveryInfo info{};
  CHECK_OK(endpoint::recovery_info_decode(host.last_body.view(), info));
  CHECK(info.config_namespace == endpoint::kConfigNamespaceSdk);
  CHECK(info.schema == 1);
  CHECK(info.nonce_echo == nonce);
  CHECK(info.network == kNet);
  CHECK(info.store_floor == 0 && info.decision_floor == 0);  // fresh rig
  CHECK(info.flags == 0);  // healthy, and no adopted survivor yet
  CHECK(info.recovery_version == kRecoveryWireVersion);
  CHECK(info.profile_bits == 1u << 0);  // dev profile bit, verifier ready

  // A reply for another namespace or network never completes the query.
  CHECK_OK(gateway.submit_recovery_info_query(0xF8, kTarget, kNet,
                                              endpoint::kConfigNamespaceSdk,
                                              nonce, now_ms));
  gw_port.flush(now_ms);
  endpoint::RecoveryInfo forged{};
  forged.config_namespace = endpoint::kConfigNamespaceSdk;
  forged.schema = 1;
  forged.nonce_echo = nonce;
  forged.network = kNet + 1;
  forged.recovery_version = 1;
  endpoint::EncodedServicePayload enc{};
  CHECK_OK(endpoint::recovery_info_encode(forged, enc));
  gateway.on_config_frame(kTarget, object_frame(kTarget, FrameType::Control,
                                                enc.view()),
                          now_ms);
  CHECK(host.calls == 1);
  CHECK(gateway.query_active());
  pump(gateway, target, gw_port, tgt_port, now_ms);
  CHECK(host.calls == 2);
  CHECK(host.last_result == ConfigOpsResult::Ok);
}

// All three kinds share one bounded staging slot; the object kind fixes
// the cap, while the reply keeps the submitted HostOps subcommand.
void test_transfer_slot_shared() {
  MonotonicMs now_ms = 12000;
  ConfigEndpointSink* gw_peer = nullptr;
  ConfigEndpointSink* tgt_peer = nullptr;
  LoopbackPort gw_port(kGateway, tgt_peer);
  LoopbackPort tgt_port(kTarget, gw_peer);
  gw_port.peer_dest_ = kTarget;
  (void)tgt_peer;
  RecordingHost host{};
  ConfigGateway gateway(gw_port, host);

  std::array<std::uint8_t, 100> permit{};
  permit.fill(0xA1);
  std::array<std::uint8_t, 100> recovery{};
  recovery.fill(0xB2);
  std::array<std::uint8_t, 1500> manifest{};
  manifest.fill(0xC3);
  CHECK_OK(gateway.submit_permit(0xE1, kTarget,
                                 ByteView{permit.data(), permit.size()},
                                 now_ms));
  CHECK(gateway.transfer_active());
  CHECK(!gateway.submit_recovery(0xE2, kTarget,
                                 ByteView{recovery.data(), recovery.size()},
                                 now_ms).ok());
  CHECK(!gateway.submit_trust(0xE4, kTarget,
                              ByteView{manifest.data(), manifest.size()},
                              now_ms)
             .ok());

  // Each ack resolves ONLY its own slot, under its own sub.
  const auto ack_for = [&](const ByteView object, const std::uint64_t req,
                           const std::uint8_t sub) {
    autonomy::ObjectAckPayload ack{};
    ack.subtype = autonomy::ObjectAckSubtype::Ack;
    sha256(object, ack.object_hash);
    ack.received_len = static_cast<std::uint16_t>(object.size);
    ack.status = autonomy::ObjectAckStatus::Ok;
    autonomy::EncodedPayload enc{};
    CHECK_OK(autonomy::object_ack_encode(ack, enc));
    gateway.on_config_frame(kTarget, object_frame(kTarget, FrameType::ObjectAck,
                                                  enc.view()),
                            now_ms);
    CHECK(host.last_request == req);
    CHECK(host.last_sub == sub);
    CHECK(host.last_result == ConfigOpsResult::Ok);
  };
  ack_for(ByteView{permit.data(), permit.size()}, 0xE1, 0x21);
  CHECK(!gateway.transfer_active());
  CHECK_OK(gateway.submit_recovery(0xE2, kTarget,
                                   ByteView{recovery.data(), recovery.size()},
                                   now_ms));
  ack_for(ByteView{recovery.data(), recovery.size()}, 0xE2, 0x24);
  CHECK(!gateway.recovery_transfer_active());
  CHECK_OK(gateway.submit_trust(0xE3, kTarget,
                                ByteView{manifest.data(), manifest.size()},
                                now_ms));
  CHECK(gateway.trust_transfer_active());
  ack_for(ByteView{manifest.data(), manifest.size()}, 0xE3, 0x25);
  CHECK(!gateway.trust_transfer_active());
  CHECK(host.calls == 3);

  // And the 1024 B slots still refuse what only the trust slot can stage.
  CHECK(!gateway
             .submit_permit(0xE5, kTarget,
                            ByteView{manifest.data(), manifest.size()}, now_ms)
             .ok());
  CHECK(!gateway
             .submit_recovery(0xE6, kTarget,
                              ByteView{manifest.data(), manifest.size()}, now_ms)
             .ok());
}

void test_authority_config_hash_conflict() {
  constexpr MonotonicMs now = 1000;
  TargetRig rig{};
  CHECK_OK(rig.journal->initialize(now));
  ConfigEndpointSink* peer = nullptr;
  LoopbackPort port(kTarget, peer);
  port.peer_dest_ = kGateway;
  RecordingAckSink sink{};
  peer = &sink;
  autonomy::ControlObjectPayload manifest{};
  manifest.subtype = autonomy::ControlObjectSubtype::Manifest;
  manifest.total_len = 500;
  manifest.object_hash[0] = 0xA5;
  autonomy::EncodedPayload encoded{};

  {
    ConfigTarget target(port, rig.rate);
    CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
    sdkv1::AuthorityEndpoint authority(port, kTarget);
    target.attach_authority(&authority);
    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    CHECK_OK(autonomy::control_object_encode(manifest, encoded));
    target.on_config_frame(kGateway,
                           object_frame(kGateway, FrameType::ControlObject, encoded.view()), now);
    port.flush(now);
    CHECK(target.object_active());
    CHECK(sink.last_status == autonomy::ObjectAckStatus::Incomplete);

    manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
    CHECK_OK(autonomy::control_object_encode(manifest, encoded));
    target.on_config_frame(kGateway,
                           object_frame(kGateway, FrameType::ControlObject, encoded.view()), now);
    port.flush(now);
    CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
    CHECK(target.object_active());
    CHECK(!authority.claim_transfer(kGateway, manifest.object_hash));
  }
  {
    ConfigTarget target(port, rig.rate);
    CHECK_OK(target.add_journal(endpoint::kConfigNamespaceSdk, *rig.journal));
    sdkv1::AuthorityEndpoint authority(port, kTarget);
    target.attach_authority(&authority);
    manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
    CHECK_OK(autonomy::control_object_encode(manifest, encoded));
    target.on_config_frame(kGateway,
                           object_frame(kGateway, FrameType::ControlObject, encoded.view()), now);
    port.flush(now);
    CHECK(sink.last_status == autonomy::ObjectAckStatus::Incomplete);
    CHECK(authority.claim_transfer(kGateway, manifest.object_hash));

    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    CHECK_OK(autonomy::control_object_encode(manifest, encoded));
    target.on_config_frame(kGateway,
                           object_frame(kGateway, FrameType::ControlObject, encoded.view()), now);
    port.flush(now);
    CHECK(sink.last_status == autonomy::ObjectAckStatus::Failed);
    CHECK(!target.object_active());
    CHECK(authority.claim_transfer(kGateway, manifest.object_hash));
  }
}

void test_gateway_authority_relay_with_config_attached() {
  class AuthorityHost final : public sdkv1::AuthorityHostSink {
   public:
    bool send_up(const usb::AuthorityFragment& fragment) noexcept override {
      ++sent;
      device = fragment.device;
      kind = fragment.kind;
      size = fragment.data.size;
      return true;
    }
    int sent{0};
    NodeId device{kInvalidNodeId};
    sdkv1::AuthorityCarrierKind kind{sdkv1::AuthorityCarrierKind::Envelope};
    std::size_t size{0};
  } authority_host;
  class LocalSink final : public sdkv1::AuthorityLocalSink {
   public:
    void on_local_down(sdkv1::AuthorityCarrierKind, MutableByteView) noexcept override {}
  } local;
  ConfigEndpointSink* peer = nullptr;
  LoopbackPort port(kGateway, peer);
  RecordingHost config_host{};
  ConfigGateway config(port, config_host);
  sdkv1::AuthorityGateway authority(port, authority_host, local, kGateway);
  config.attach_authority(&authority);

  const std::array<std::uint8_t, 8> wake{};
  std::array<std::uint8_t, kMaxApplicationPayload> encoded{};
  std::size_t written = 0;
  CHECK_OK(sdkv1::authority_carrier_encode(
      sdkv1::AuthorityCarrierKind::Wake, 0, ByteView{wake.data(), wake.size()},
      MutableByteView{encoded.data(), encoded.size()}, written));
  config.on_config_frame(kTarget,
                         object_frame(kTarget, FrameType::Control,
                                      ByteView{encoded.data(), written}),
                         1000);
  authority.poll(1001);
  CHECK(authority_host.sent == 1);
  CHECK(authority_host.device == kTarget);
  CHECK(authority_host.kind == sdkv1::AuthorityCarrierKind::Wake);
  CHECK(authority_host.size == wake.size());
  CHECK(config_host.calls == 0);
}

}  // namespace

int main() {
  test_dev_permit_roundtrip();
  test_challenge_status_wire();
  test_permit_transfer_e2e();
  test_query_timeout();
  test_manifest_duplicate_total_len_conflict();
  test_query_reply_echo_binding();
  test_dev_permit_tag_status_codes();
  test_single_assembler_discipline();
  test_authority_config_hash_conflict();
  test_gateway_authority_relay_with_config_attached();
  test_kind5_trust_delivery_e2e();
  test_trust_verify_shares_budget();
  test_trust_status_query_wire();
  test_recovery_info_query_wire();
  test_transfer_slot_shared();
  if (failures == 0) {
    std::printf("config_wire tests OK\n");
    return 0;
  }
  std::fprintf(stderr, "%d config_wire check(s) failed\n", failures);
  return 1;
}
