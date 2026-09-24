// Small Remote Config portable-core tests: the C01-C14 acceptance cases
// (06-acceptance.md), issuer commit-order/resume behaviour, the dual-slot
// journal power-loss matrix, reassembly bounds and the schema/TLV layer —
// all through the real code paths with storage/provider/verifier fakes.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>

#include "routeloom/authority.hpp"
#include "routeloom/config.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/endpoint_wire.hpp"

#include "test_ledger.hpp"  // FaultyLedgerStorage for the issuer's ledger

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
constexpr std::uint64_t kBoot = 0xB007;
constexpr std::size_t kJournalSlot = kConfigJournalSlotBytes;   // 4096
constexpr std::size_t kOutboxSlot = kConfigOutboxRecordBytes;   // 2048

// --- Fakes ----------------------------------------------------------------------

// Deterministic nonzero entropy (monotonic byte stream).
class CountingEntropy final : public EntropySource {
 public:
  Status fill(const MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) {
      out.data[i] = static_cast<std::uint8_t>(counter_ + i);
    }
    counter_ = static_cast<std::uint8_t>(counter_ + out.size + 1U);
    return Status::success();
  }
  std::uint8_t counter_{0x11};
};

// Two 4096-byte slots, byte-granular cut/drop injection, read errors.
class FakeJournalStorage final : public ConfigJournalStorage {
 public:
  Status read(const std::uint8_t slot, const MutableByteView target) noexcept override {
    if (slot >= kConfigJournalSlots || target.size != kJournalSlot) {
      return Status::error(StatusCode::InvalidArgument, "bad journal read");
    }
    if (read_error) {
      return Status::error(StatusCode::StorageFailure, "injected read error");
    }
    std::memcpy(target.data, slots_[slot].data(), kJournalSlot);
    return Status::success();
  }
  Status write(const std::uint8_t slot, const ByteView data) noexcept override {
    if (slot >= kConfigJournalSlots || data.size == 0 || data.size > kJournalSlot) {
      return Status::error(StatusCode::InvalidArgument, "bad journal write");
    }
    const std::size_t call = write_calls++;
    if (call == cut_call) {
      const std::size_t landed = cut_bytes < data.size ? cut_bytes : data.size;
      std::memcpy(slots_[slot].data(), data.data, landed);
      return Status::error(StatusCode::StorageFailure, "power cut mid write");
    }
    if (call == drop_call) {
      return Status::error(StatusCode::StorageFailure, "power lost before write");
    }
    std::memcpy(slots_[slot].data(), data.data, data.size);
    return Status::success();
  }
  void corrupt(const std::uint8_t slot, const std::size_t offset) {
    slots_[slot][offset] ^= 0xFFU;
  }
  void fill(const std::uint8_t slot, const std::uint8_t value) { slots_[slot].fill(value); }

  std::array<std::array<std::uint8_t, kJournalSlot>, kConfigJournalSlots> slots_{};
  std::size_t write_calls{0};
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  std::size_t drop_call{std::numeric_limits<std::size_t>::max()};
  bool read_error{false};
};

// Four 2048-byte issuer outbox slots.
class FakeOutboxStorage final : public ConfigOutboxStorage {
 public:
  Status read(const std::uint8_t slot, const MutableByteView target) noexcept override {
    if (slot >= kConfigIssuerOutboxSlots || target.size != kOutboxSlot) {
      return Status::error(StatusCode::InvalidArgument, "bad outbox read");
    }
    std::memcpy(target.data, slots_[slot].data(), kOutboxSlot);
    return Status::success();
  }
  Status write(const std::uint8_t slot, const ByteView data) noexcept override {
    if (slot >= kConfigIssuerOutboxSlots || data.size == 0 || data.size > kOutboxSlot) {
      return Status::error(StatusCode::InvalidArgument, "bad outbox write");
    }
    last_write_size = data.size;
    const std::size_t call = write_calls++;
    if (call == cut_call) {
      const std::size_t landed = cut_bytes < data.size ? cut_bytes : data.size;
      std::memcpy(slots_[slot].data(), data.data, landed);
      return Status::error(StatusCode::StorageFailure, "power cut mid write");
    }
    if (call == drop_call) {
      return Status::error(StatusCode::StorageFailure, "power lost before write");
    }
    std::memcpy(slots_[slot].data(), data.data, data.size);
    return Status::success();
  }
  std::array<std::array<std::uint8_t, kOutboxSlot>, kConfigIssuerOutboxSlots> slots_{};
  std::size_t write_calls{0};
  std::size_t last_write_size{0};
  std::size_t cut_call{std::numeric_limits<std::size_t>::max()};
  std::size_t cut_bytes{0};
  std::size_t drop_call{std::numeric_limits<std::size_t>::max()};
};

// The test permit envelope (development profile — never advertised as
// production): AAD(32B) || canonical RCC1 || tag(16B) where
// tag = SHA256("RouteLoom/config-permit-test/v1\0" || aad || canonical)[0:16].
// The verifier recomputes the tag in constant time — a real cryptographic
// check over the whole envelope, not a key-name claim.
constexpr char kTestPermitDomain[] = "RouteLoom/config-permit-test/v1";
constexpr std::size_t kPermitAadSize = kConfigPermitAadSize;
constexpr std::size_t kPermitTagSize = 16;

void test_permit_tag(const ByteView aad, const ByteView canonical,
                     std::array<std::uint8_t, kPermitTagSize>& out) {
  Sha256 hash{};
  hash.update(ByteView{reinterpret_cast<const std::uint8_t*>(kTestPermitDomain),
                       sizeof(kTestPermitDomain)});
  hash.update(aad);
  hash.update(canonical);
  Digest256 digest{};
  hash.finish(digest);
  std::memcpy(out.data(), digest.data(), kPermitTagSize);
}

// The test recovery envelope: recovery_aad(46B) || canonical RCR1 || tag(16B)
// under its own domain — a kind-4 object can never verify as a kind-3
// permit, mirroring the dev profile's separate domains.
constexpr char kTestRecoveryDomain[] = "RouteLoom/config-recover-test/v1";
constexpr std::size_t kRecoveryAadSize = kConfigRecoveryAadSize;

void test_recovery_tag(const ByteView aad, const ByteView canonical,
                       std::array<std::uint8_t, kPermitTagSize>& out) {
  Sha256 hash{};
  hash.update(ByteView{reinterpret_cast<const std::uint8_t*>(kTestRecoveryDomain),
                       sizeof(kTestRecoveryDomain)});
  hash.update(aad);
  hash.update(canonical);
  Digest256 digest{};
  hash.finish(digest);
  std::memcpy(out.data(), digest.data(), kPermitTagSize);
}

class FakePermitSigner final : public ConfigPermitSigner {
 public:
  bool ready() const noexcept override { return ready_; }
  Status sign(const ConfigCommand& command, const ByteView canonical,
              ByteBuffer<kConfigPermitObjectMax>& permit) noexcept override {
    ++sign_calls;
    if (fail_next) {
      fail_next = false;
      return Status::error(StatusCode::InternalError, "injected sign failure");
    }
    ByteBuffer<kConfigPermitAadSize> aad{};
    Status status =
        config_permit_aad(command.network, command.target, command.config_namespace, aad);
    if (!status) return status;
    if (aad.size + canonical.size + kPermitTagSize > permit.bytes.size()) {
      return Status::error(StatusCode::NoCapacity, "permit oversize");
    }
    std::memcpy(permit.bytes.data(), aad.bytes.data(), aad.size);
    std::memcpy(permit.bytes.data() + aad.size, canonical.data, canonical.size);
    std::array<std::uint8_t, kPermitTagSize> tag{};
    test_permit_tag(aad.view(), canonical, tag);
    std::memcpy(permit.bytes.data() + aad.size + canonical.size, tag.data(), tag.size());
    permit.size = aad.size + canonical.size + kPermitTagSize;
    return Status::success();
  }
  Status sign_recovery(const endpoint::ConfigRecoveryCommand& command,
                       const ByteView canonical,
                       ByteBuffer<kConfigPermitObjectMax>& permit) noexcept override {
    ++sign_calls;
    if (fail_next) {
      fail_next = false;
      return Status::error(StatusCode::InternalError, "injected sign failure");
    }
    ByteBuffer<kRecoveryAadSize> aad{};
    Status status = config_recovery_aad(command.network, command.target,
                                        command.config_namespace, aad);
    if (!status) return status;
    if (aad.size + canonical.size + kPermitTagSize > permit.bytes.size()) {
      return Status::error(StatusCode::NoCapacity, "recovery object oversize");
    }
    std::memcpy(permit.bytes.data(), aad.bytes.data(), aad.size);
    std::memcpy(permit.bytes.data() + aad.size, canonical.data, canonical.size);
    std::array<std::uint8_t, kPermitTagSize> tag{};
    test_recovery_tag(aad.view(), canonical, tag);
    std::memcpy(permit.bytes.data() + aad.size + canonical.size, tag.data(), tag.size());
    permit.size = aad.size + canonical.size + kPermitTagSize;
    return Status::success();
  }
  bool ready_{true};
  bool fail_next{false};
  std::size_t sign_calls{0};
};

class FakeVerifier final : public ConfigAuthorityVerifier {
 public:
  bool ready() const noexcept override { return true; }
  // Tests that need the expensive-verify intake gate set this flag — the
  // dev-profile default stays cheap (03-signing §3.3).
  bool expensive{false};
  bool verify_is_expensive() const noexcept override { return expensive; }
  Status verify_permit(const ConfigPermitContext& context, const ByteView permit,
                       endpoint::EncodedConfigCommand& payload,
                       bool& verified) noexcept override {
    verified = false;
    ++verify_calls;
    if (permit.size < kPermitAadSize + endpoint::kRcc1HeaderSize + kPermitTagSize ||
        permit.size > kConfigPermitObjectMax) {
      return Status::error(StatusCode::ProtocolError, "permit envelope malformed");
    }
    ByteBuffer<kConfigPermitAadSize> aad{};
    Status status =
        config_permit_aad(context.network, context.target, context.config_namespace, aad);
    if (!status) return status;
    if (!constant_time_equal(ByteView{permit.data, kPermitAadSize}, aad.view())) {
      return Status::success();  // wrong scope binding -> verified=false
    }
    const ByteView canonical{permit.data + kPermitAadSize,
                             permit.size - kPermitAadSize - kPermitTagSize};
    std::array<std::uint8_t, kPermitTagSize> tag{};
    test_permit_tag(aad.view(), canonical, tag);
    if (!constant_time_equal(
            ByteView{tag.data(), tag.size()},
            ByteView{permit.data + permit.size - kPermitTagSize, kPermitTagSize})) {
      return Status::success();  // signature mismatch -> verified=false
    }
    // The verified payload is only the canonical command; all identity
    // policy beyond the envelope is the journal's own check.
    status = endpoint::config_command_decode(canonical, decoded_);
    if (!status) return status;
    payload.size = canonical.size;
    std::memcpy(payload.bytes.data(), canonical.data, canonical.size);
    verified = true;
    return Status::success();
  }
  // The kind-4 recovery envelope: recovery-domain aad || RCR1 || tag16 —
  // fixed 138 B. Same contract as verify_permit; the test profile resolves
  // every generation, so the countersign resolvability check always passes.
  Status verify_recovery(const ConfigPermitContext& context, const ByteView object,
                         endpoint::EncodedRecoveryCommand& payload,
                         bool& verified) noexcept override {
    verified = false;
    ++verify_calls;
    if (object.size != kRecoveryAadSize + endpoint::kRcr1Size + kPermitTagSize) {
      return Status::error(StatusCode::ProtocolError,
                           "recovery envelope malformed");
    }
    ByteBuffer<kRecoveryAadSize> aad{};
    Status status = config_recovery_aad(context.network, context.target,
                                        context.config_namespace, aad);
    if (!status) return status;
    if (!constant_time_equal(ByteView{object.data, kRecoveryAadSize}, aad.view())) {
      return Status::success();  // wrong scope binding -> verified=false
    }
    const ByteView canonical{object.data + kRecoveryAadSize, endpoint::kRcr1Size};
    std::array<std::uint8_t, kPermitTagSize> tag{};
    test_recovery_tag(aad.view(), canonical, tag);
    if (!constant_time_equal(
            ByteView{tag.data(), tag.size()},
            ByteView{object.data + object.size - kPermitTagSize, kPermitTagSize})) {
      return Status::success();  // signature mismatch -> verified=false
    }
    status = endpoint::config_recovery_decode(canonical, decoded_recovery_);
    if (!status) return status;
    payload.size = canonical.size;
    std::memcpy(payload.bytes.data(), canonical.data, canonical.size);
    verified = true;
    return Status::success();
  }
  endpoint::ConfigCommand decoded_{};
  endpoint::ConfigRecoveryCommand decoded_recovery_{};
  std::size_t verify_calls{0};
};

// Desired-state provider fake: validate/prepare are side-effect-free,
// apply/restore complete after `polls_to_complete` polls, then commit the
// pending snapshot to the "active" image. read_active returns the actual
// committed bytes (readback verification).
class FakeProvider final : public ConfigProvider {
 public:
  Status validate(const std::uint16_t, const std::uint16_t,
                  const ByteView) noexcept override {
    ++validate_calls;
    return validate_result;
  }
  Status prepare(const std::uint16_t, const std::uint16_t,
                 const ByteView) noexcept override {
    ++prepare_calls;
    return prepare_result;
  }
  Status apply(const std::uint16_t, const ByteView next,
               OperationToken& token) noexcept override {
    ++apply_calls;
    if (!apply_result.ok()) return apply_result;
    pending_.size = next.size;
    std::memcpy(pending_.bytes.data(), next.data, next.size);
    polls_left_ = polls_to_complete;
    token = OperationToken{++token_id_};
    if (partial_apply) active_.size = 0;  // simulate a half-applied write
    return Status::success();
  }
  Status restore(const std::uint16_t, const ByteView snapshot,
                 OperationToken& token) noexcept override {
    ++restore_calls;
    if (!restore_result.ok()) return restore_result;
    pending_.size = snapshot.size;
    std::memcpy(pending_.bytes.data(), snapshot.data, snapshot.size);
    polls_left_ = polls_to_complete;
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
    if (--polls_left_ > 0) return Status::success();
    done = true;
    if (fail_polls > 0) {
      --fail_polls;
      outcome = Status::error(StatusCode::DriverResultUnknown, "apply failed");
      return Status::success();
    }
    active_ = pending_;
    outcome = Status::success();
    return Status::success();
  }
  Status read_active(const std::uint16_t, const MutableByteView target,
                     std::size_t& out_size) noexcept override {
    if (corrupt_reads > 0) {
      --corrupt_reads;
      out_size = 3;
      std::memcpy(target.data, "bad", 3);
      return Status::success();
    }
    if (active_.size > target.size) {
      return Status::error(StatusCode::NoCapacity, "read buffer small");
    }
    std::memcpy(target.data, active_.bytes.data(), active_.size);
    out_size = active_.size;
    return Status::success();
  }
  ByteBuffer<endpoint::kConfigSnapshotMax> active_{};
  ByteBuffer<endpoint::kConfigSnapshotMax> pending_{};
  int polls_to_complete{1};
  int polls_left_{0};
  std::uint64_t token_id_{0};
  Status validate_result = Status::success();
  Status prepare_result = Status::success();
  Status apply_result = Status::success();
  Status restore_result = Status::success();
  int fail_polls{0};
  bool partial_apply{false};
  int corrupt_reads{0};
  int validate_calls{0}, prepare_calls{0}, apply_calls{0}, restore_calls{0};
};

class FakeMaintenanceGate final : public ConfigMaintenanceGate {
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

// --- Helpers --------------------------------------------------------------------

// Shared test-wide state so operation ids and signed blobs stay unique.
std::uint8_t op_counter_ = 1;
FakePermitSigner signer_;
ByteBuffer<kConfigPermitObjectMax> last_permit_{};
ConfigCommand last_command_{};

ConfigField sdk_bool(const std::uint16_t id, const bool value) {
  ConfigField field{};
  field.field_id = id;
  field.type = ConfigFieldType::Bool;
  field.value_size = 1;
  field.value[0] = value ? 1 : 0;
  return field;
}

ConfigField sdk_u8(const std::uint16_t id, const std::uint8_t value) {
  ConfigField field{};
  field.field_id = id;
  field.type = ConfigFieldType::U8;
  field.value_size = 1;
  field.value[0] = value;
  return field;
}

// Build + encode + sign a permit for `command` (all fields set by caller).
void build_permit(FakePermitSigner& signer, const ConfigCommand& command,
                  ByteBuffer<kConfigPermitObjectMax>& permit) {
  endpoint::EncodedConfigCommand canonical{};
  CHECK_OK(endpoint::config_command_encode(command, canonical));
  CHECK_OK(signer.sign(command, canonical.view(), permit));
}

struct TargetRig {
  ConfigJournalConfig config{};
  FakeJournalStorage storage{};
  FakeVerifier verifier{};
  CountingEntropy entropy{};
  ConfigRateLimiter rate{};
  FakeProvider provider{};
  FakeMaintenanceGate gate{};
  PermissiveValidator validator{};
  std::unique_ptr<ConfigJournal> journal{};

  explicit TargetRig(const std::uint64_t boot = kBoot, const bool with_gate = true)
      : gate_installed_(with_gate) {
    config.network = kNet;
    config.target = kTarget;
    config.config_namespace = endpoint::kConfigNamespaceSdk;
    config.schema = 1;
    config.boot_incarnation = boot;
    config.authorized_issuer = kAuthority;
    config.authority_generation = 1;
    config.challenge_valid_ms = kConfigChallengeMaxMs;
    journal = std::make_unique<ConfigJournal>(
        config, storage, verifier, entropy, rate, &provider, nullptr,
        with_gate ? &gate : nullptr);
  }
  void boot(const MonotonicMs now_ms) {
    journal = std::make_unique<ConfigJournal>(
        config, storage, verifier, entropy, rate, &provider, nullptr,
        gate_installed_ ? &gate : nullptr);
    boot_status_ = journal->initialize(now_ms);
  }
  bool gate_installed_{true};
  Status boot_status_ = Status::success();
};

// Build a command bound to `challenge` (the caller picked the challenge),
// sign it and submit. Returns the submit Status; the permit stays in
// last_permit_ / last_command_ like drive_update.
Status submit_bound(TargetRig& rig, const endpoint::ControlChallenge& challenge,
                    const ConfigField* patch, const std::uint16_t patch_count,
                    const MonotonicMs now_ms, const std::uint64_t expected_revision,
                    const ByteView base_snapshot, ConfigVerdict& verdict,
                    const std::uint32_t apply_within_ms = 0,
                    ConfigCommand* command_out = nullptr) {
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  Status status =
      config_patch_apply(base_snapshot, patch, patch_count, next, changed);
  if (!status) return status;
  Digest256 base_hash{}, next_hash{};
  status = config_snapshot_hash(rig.config.config_namespace, rig.config.schema,
                                base_snapshot, base_hash);
  if (!status) return status;
  status = config_snapshot_hash(rig.config.config_namespace, rig.config.schema,
                                next.view(), next_hash);
  if (!status) return status;

  ConfigCommand command{};
  command.config_namespace = rig.config.config_namespace;
  command.schema = rig.config.schema;
  command.network = rig.config.network;
  command.target = rig.config.target;
  command.authority = rig.config.authorized_issuer;
  command.authority_generation = rig.config.authority_generation;
  command.authority_sequence = 1;  // issuer ledger sequence — not the CAS input
  command.operation_id = {0xA0, 1, 2, 3, 4, 5, 6, 7,
                          static_cast<std::uint8_t>(expected_revision + 1), 9, 10, 11,
                          12, 13, 14, 15};
  command.operation_id[1] = static_cast<std::uint8_t>(op_counter_++);
  command.expected_revision = expected_revision;
  command.next_revision = expected_revision + 1;
  command.base_snapshot_hash = base_hash;
  command.next_snapshot_hash = next_hash;
  command.target_boot = rig.config.boot_incarnation;
  command.challenge_nonce = challenge.challenge_nonce;
  command.apply_within_ms =
      apply_within_ms != 0 ? apply_within_ms : challenge.valid_for_ms;
  command.field_count = patch_count;
  for (std::uint16_t i = 0; i < patch_count; ++i) command.fields[i] = patch[i];
  if (command_out != nullptr) *command_out = command;

  ByteBuffer<kConfigPermitObjectMax> permit{};
  build_permit(signer_, command, permit);
  last_permit_ = permit;
  last_command_ = command;
  return rig.journal->submit_permit(permit.view(), now_ms, true, verdict);
}

// Drive one end-to-end update against a rig: challenge -> command -> sign ->
// submit. Returns the submit Status and fills the verdict. `patch` fields
// must already be sorted+valid.
Status drive_update(TargetRig& rig, const ConfigField* patch,
                    const std::uint16_t patch_count, MonotonicMs& now_ms,
                    const std::uint64_t expected_revision,
                    const ByteView base_snapshot, ConfigVerdict& verdict,
                    ConfigCommand* command_out = nullptr) {
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = rig.config.config_namespace;
  query.schema = rig.config.schema;
  query.client_nonce = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, 5, 6};
  endpoint::EncodedServicePayload encoded{};
  Status status = rig.journal->handle_challenge_query(query, now_ms, encoded);
  if (!status) return status;
  endpoint::ControlChallenge challenge{};
  status = endpoint::control_challenge_decode(encoded.view(), challenge);
  if (!status) return status;
  return submit_bound(rig, challenge, patch, patch_count, now_ms,
                      expected_revision, base_snapshot, verdict, 0, command_out);
}

void drain(TargetRig& rig, MonotonicMs& now_ms, const int polls = 6) {
  for (int i = 0; i < polls; ++i) rig.journal->poll(now_ms += 10);
}

// --- Unit tests: TLV / snapshot hash / patch merge -------------------------------

void test_tlv_layer() {
  // Round-trip: sorted fields encode then decode identically.
  const ConfigField fields[] = {sdk_u8(1, 2), sdk_bool(2, true), sdk_bool(3, false)};
  ByteBuffer<endpoint::kConfigSnapshotMax> tlv{};
  CHECK_OK(config_tlv_encode(fields, 3, tlv));
  ConfigField decoded[endpoint::kConfigFieldCountMax]{};
  std::uint16_t count = 0;
  CHECK_OK(config_tlv_decode(tlv.view(), decoded, endpoint::kConfigFieldCountMax, count));
  CHECK(count == 3);
  CHECK(decoded[0].field_id == 1 && decoded[0].value[0] == 2);
  CHECK(decoded[1].field_id == 2 && decoded[1].value[0] == 1);
  CHECK(decoded[2].field_id == 3 && decoded[2].value[0] == 0);

  // Unsorted / duplicate ids are rejected on encode.
  const ConfigField unsorted[] = {sdk_u8(3, 0), sdk_u8(1, 0)};
  ByteBuffer<endpoint::kConfigSnapshotMax> scratch{};
  CHECK(config_tlv_encode(unsorted, 2, scratch).code == StatusCode::InvalidArgument);
  const ConfigField dup[] = {sdk_u8(2, 0), sdk_u8(2, 1)};
  CHECK(config_tlv_encode(dup, 2, scratch).code == StatusCode::InvalidArgument);

  // Hand-built malformed TLV: wrong-length u8, unknown type, trailing junk.
  const std::uint8_t bad_len[] = {0, 1, 2, 0, 4, 0, 0, 0, 0, 0};
  CHECK(config_tlv_decode(ByteView{bad_len, sizeof(bad_len)}, decoded,
                          endpoint::kConfigFieldCountMax, count)
            .code == StatusCode::ProtocolError);
  const std::uint8_t bad_type[] = {0, 1, 9, 0, 1, 0};
  CHECK(config_tlv_decode(ByteView{bad_type, sizeof(bad_type)}, decoded,
                          endpoint::kConfigFieldCountMax, count)
            .code == StatusCode::ProtocolError);
  const std::uint8_t trailing[] = {0, 1, 2, 0, 1, 7, 0};
  CHECK(config_tlv_decode(ByteView{trailing, sizeof(trailing)}, decoded,
                          endpoint::kConfigFieldCountMax, count)
            .code == StatusCode::ProtocolError);
}

void test_snapshot_hash_domain() {
  // The §5.4 formula: SHA256(domain\0 || ns u16 || schema u16 || snapshot).
  const ConfigField fields[] = {sdk_u8(1, 1)};
  ByteBuffer<endpoint::kConfigSnapshotMax> tlv{};
  CHECK_OK(config_tlv_encode(fields, 1, tlv));
  Digest256 hash{};
  CHECK_OK(config_snapshot_hash(1, 1, tlv.view(), hash));

  ByteBuffer<endpoint::kConfigSnapshotInputMax> input{};
  CHECK_OK(endpoint::config_snapshot_hash_input(1, 1, tlv.view(), input));
  Digest256 expected{};
  sha256(input.view(), expected);
  CHECK(hash == expected);
  // Different namespace or schema changes the hash.
  Digest256 other{};
  CHECK_OK(config_snapshot_hash(1, 2, tlv.view(), other));
  CHECK(!(hash == other));
  CHECK_OK(config_snapshot_hash(0x8000, 1, tlv.view(), other));
  CHECK(!(hash == other));
}

void test_patch_merge() {
  const ConfigField base[] = {sdk_u8(1, 0), sdk_bool(2, true), sdk_u8(4, 0)};
  ByteBuffer<endpoint::kConfigSnapshotMax> base_tlv{};
  CHECK_OK(config_tlv_encode(base, 3, base_tlv));
  // Patch overwrites id 2 and adds id 3; id 1 and 4 retained, order stays.
  const ConfigField patch[] = {sdk_bool(2, false), sdk_bool(3, true)};
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  CHECK_OK(config_patch_apply(base_tlv.view(), patch, 2, next, changed));
  CHECK(changed);
  ConfigField merged[endpoint::kConfigFieldCountMax]{};
  std::uint16_t count = 0;
  CHECK_OK(config_tlv_decode(next.view(), merged, endpoint::kConfigFieldCountMax, count));
  CHECK(count == 4);
  CHECK(merged[0].field_id == 1 && merged[0].value[0] == 0);
  CHECK(merged[1].field_id == 2 && merged[1].value[0] == 0);
  CHECK(merged[2].field_id == 3 && merged[2].value[0] == 1);
  CHECK(merged[3].field_id == 4 && merged[3].value[0] == 0);

  // Same-value patch -> changed=false (NO_CHANGE path).
  const ConfigField noop[] = {sdk_bool(2, true)};
  CHECK_OK(config_patch_apply(base_tlv.view(), noop, 1, next, changed));
  CHECK(!changed);
  // There is no deletion or null/type conversion in the contract: a patch
  // cannot remove a field, only overwrite with a same-id field.
  const ConfigField typed[] = {{2, ConfigFieldType::U32, {0, 0, 0, 0}, 4}};
  CHECK_OK(config_patch_apply(base_tlv.view(), typed, 1, next, changed));
  CHECK_OK(config_tlv_decode(next.view(), merged, endpoint::kConfigFieldCountMax, count));
  CHECK(merged[1].field_id == 2 && merged[1].type == ConfigFieldType::U32);
}

void test_namespace_table() {
  ConfigNamespaceTable table{};
  CHECK(table.size() == 1);
  CHECK(table.find(1) != nullptr);
  CHECK(table.find(0x8000) == nullptr);
  // App namespaces require an explicit validator — a namespace without
  // schema rules can never silently accept values.
  CHECK(table.register_namespace(ConfigNamespaceEntry{0x8000, 1, nullptr, nullptr})
            .code == StatusCode::InvalidArgument);
  PermissiveValidator validator;
  CHECK_OK(table.register_namespace(ConfigNamespaceEntry{0x8000, 1, &validator, nullptr}));
  CHECK(table.size() == 2);
  CHECK_OK(table.register_namespace(ConfigNamespaceEntry{0x8001, 1, &validator, nullptr}));
  CHECK_OK(table.register_namespace(ConfigNamespaceEntry{0x8002, 1, &validator, nullptr}));
  CHECK(table.register_namespace(ConfigNamespaceEntry{0x8003, 1, &validator, nullptr})
            .code == StatusCode::NoCapacity);
  // Invalid namespace ids (0, 2, 0xffff) are rejected outright.
  CHECK(table.register_namespace(ConfigNamespaceEntry{2, 1, &validator, nullptr})
            .code == StatusCode::InvalidArgument);
  CHECK(table.register_namespace(ConfigNamespaceEntry{0xffff, 1, &validator, nullptr})
            .code == StatusCode::InvalidArgument);
}

void test_rate_limiter() {
  ConfigRateLimiter limiter{};
  CHECK(limiter.consume(0));    // sustained token
  CHECK(limiter.consume(0));    // burst token
  CHECK(!limiter.consume(0));   // capacity exhausted
  CHECK(!limiter.consume(30000));
  CHECK(limiter.consume(60000));
  CHECK(!limiter.consume(60000));
}

void test_sdk_field_rules() {
  CHECK_OK(config_sdk_field_validate(sdk_u8(1, 2)));
  CHECK(config_sdk_field_validate(sdk_u8(1, 3)).code == StatusCode::InvalidArgument);
  CHECK_OK(config_sdk_field_validate(sdk_bool(2, true)));
  CHECK_OK(config_sdk_field_validate(sdk_bool(3, false)));
  CHECK_OK(config_sdk_field_validate(sdk_u8(4, 2)));
  CHECK(config_sdk_field_validate(sdk_u8(4, 3)).code == StatusCode::InvalidArgument);
  CHECK(config_sdk_field_validate(sdk_u8(5, 0)).code == StatusCode::Unsupported);
  // A bool typed as u8 is a type mismatch, not a value problem.
  ConfigField wrong_type = sdk_bool(2, true);
  wrong_type.type = ConfigFieldType::U8;
  CHECK(config_sdk_field_validate(wrong_type).code == StatusCode::InvalidArgument);
}

// --- C01: basic valid flow --------------------------------------------------------

void test_c01_basic_flow() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1), sdk_bool(2, true)};
  ConfigVerdict verdict{};
  const ByteView empty{};
  CHECK_OK(drive_update(rig, patch, 2, now_ms, 0, empty, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 1);
  CHECK(rig.journal->active_revision() == 1);
  CHECK(rig.journal->stats().applies == 1);
  CHECK(rig.provider.active_.size == rig.journal->active_snapshot().size);
  CHECK(std::memcmp(rig.provider.active_.bytes.data(), rig.journal->active_snapshot().data,
                    rig.provider.active_.size) == 0);

  // The applied snapshot decodes to the merged field set.
  ConfigField fields[endpoint::kConfigFieldCountMax]{};
  std::uint16_t count = 0;
  CHECK_OK(config_tlv_decode(rig.journal->active_snapshot(), fields,
                             endpoint::kConfigFieldCountMax, count));
  CHECK(count == 2 && fields[0].field_id == 1 && fields[0].value[0] == 1);

  // StatusQuery returns the stored ACTIVE result for the operation id.
  endpoint::ControlStatusQuery sq{};
  sq.config_namespace = 1;
  sq.operation_id = last_command_.operation_id;
  endpoint::EncodedServicePayload reply{};
  CHECK_OK(rig.journal->handle_status_query(sq, now_ms, reply));
  endpoint::ControlStatus status{};
  CHECK_OK(endpoint::control_status_decode(reply.view(), status));
  CHECK(status.phase == ConfigPhase::Active);
  CHECK(status.decision_revision == 1 && status.active_revision == 1);

  // NO_CHANGE patch is refused before any decision: no revision, no write.
  const std::size_t writes_before = rig.storage.write_calls;
  const ConfigField same[] = {sdk_u8(1, 1)};
  CHECK(drive_update(rig, same, 1, now_ms += 100, 1, rig.journal->active_snapshot(),
                     verdict)
            .code == StatusCode::AlreadyExists);
  CHECK(verdict.reason == ConfigReason::NoChange);
  CHECK(rig.journal->decision_revision() == 1);
  CHECK(rig.storage.write_calls == writes_before);
}

// --- C02: CAS conflict -------------------------------------------------------------

void test_c02_cas_conflict() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->decision_revision() == 1);

  // Stale: expected 0 while the journal is at 1.
  CHECK(drive_update(rig, patch, 1, now_ms += 100, 0, ByteView{}, verdict).code ==
        StatusCode::Conflict);
  CHECK(verdict.reason == ConfigReason::StaleRevision);
  CHECK(rig.journal->stats().stale_revision == 1);
  // From the future is also a CAS failure (no silent skip).
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK(drive_update(rig, patch2, 1, now_ms += 100, 5,
                     rig.journal->active_snapshot(), verdict)
            .code == StatusCode::Conflict);
  CHECK(verdict.reason == ConfigReason::StaleRevision);
  // Base-hash mismatch (a permit built against the wrong base).
  ConfigCommand command = last_command_;
  command.expected_revision = 1;
  command.next_revision = 2;
  command.base_snapshot_hash = Digest256{};
  command.operation_id = {0xB0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  ByteBuffer<kConfigPermitObjectMax> permit{};
  build_permit(signer_, command, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::Conflict);
  CHECK(verdict.reason == ConfigReason::BaseHashMismatch);
  CHECK(rig.journal->decision_revision() == 1);
}

// --- C03: global sequence holes across targets --------------------------------------

void test_c03_sequence_holes() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);

  // The next operation's authority_sequence jumped (the issuer served
  // other targets in between): only the per-target revision is the CAS.
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = 1;
  query.schema = 1;
  query.client_nonce = {7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(rig.journal->handle_challenge_query(query, now_ms += 61000, encoded));
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
  CHECK(challenge.revision == 1);

  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(config_patch_apply(rig.journal->active_snapshot(), patch2, 1, next, changed));
  Digest256 next_hash{};
  CHECK_OK(config_snapshot_hash(1, 1, next.view(), next_hash));
  ConfigCommand command = last_command_;
  command.operation_id = {0xC0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  command.authority_sequence = 42;  // a hole vs the previous sequence 1
  command.expected_revision = 1;
  command.next_revision = 2;
  command.base_snapshot_hash = challenge.active_hash;
  command.next_snapshot_hash = next_hash;
  command.challenge_nonce = challenge.challenge_nonce;
  command.fields[0] = patch2[0];
  command.field_count = 1;
  ByteBuffer<kConfigPermitObjectMax> permit{};
  build_permit(signer_, command, permit);
  CHECK_OK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 2);
}

// --- C04: authorization boundary -----------------------------------------------------

// Expensive-verifier intake limiter (03-signing §3.3): one verification
// start per 5 s, burst 1, charged before any signature work — a flood of
// well-formed-but-invalid permits cannot monopolize the Owner.
void test_c04_verify_intake_limit() {
  TargetRig rig;
  rig.verifier.expensive = true;  // simulate an ECC-class verifier
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  // The first expensive verification consumes the single intake token.
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));

  // A second permit inside the window is refused CAPACITY before ANY
  // signature work — intake refusal is not a denial and spends no revision.
  ByteBuffer<kConfigPermitObjectMax> forged = last_permit_;
  forged.bytes[40] ^= 0xFFU;
  const std::size_t calls = rig.verifier.verify_calls;
  CHECK(rig.journal->submit_permit(forged.view(), now_ms + 1000, true, verdict)
            .code == StatusCode::Busy);
  CHECK(verdict.reason == ConfigReason::Capacity);
  CHECK(rig.journal->stats().verify_intake_refusals == 1);
  CHECK(rig.verifier.verify_calls == calls);  // no signature work ran

  // After the window the same forged permit reaches the verifier and is
  // honestly denied — the limiter gates intake, never the verdict itself.
  CHECK(rig.journal->submit_permit(forged.view(), now_ms + 7000, true, verdict)
            .code == StatusCode::AuthenticationFailed);
  CHECK(rig.verifier.verify_calls == calls + 1);
}

// The intake gate is device-global (03-signing §3.3): two journals sharing
// the embedder's limiter share ONE verification budget — a second journal
// cannot mint its own burst.
void test_c04_verify_intake_shared() {
  TargetRig rig;
  rig.verifier.expensive = true;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));

  // A second journal on the SAME rate limiter — the embedder's device-wide
  // budget object.
  FakeJournalStorage storage_b{};
  ConfigJournalConfig config_b = rig.config;
  config_b.config_namespace = endpoint::kConfigNamespaceSdk;  // any namespace
  ConfigJournal journal_b(config_b, storage_b, rig.verifier, rig.entropy,
                          rig.rate, nullptr, nullptr, nullptr);
  CHECK_OK(journal_b.initialize(now_ms));

  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  const std::size_t calls = rig.verifier.verify_calls;

  // Journal B's first-ever expensive permit is refused inside the window —
  // the token journal A spent is the device's only token.
  ByteBuffer<kConfigPermitObjectMax> forged = last_permit_;
  forged.bytes[40] ^= 0xFFU;
  CHECK(journal_b.submit_permit(forged.view(), now_ms + 1000, true, verdict)
            .code == StatusCode::Busy);
  CHECK(verdict.reason == ConfigReason::Capacity);
  CHECK(rig.verifier.verify_calls == calls);  // still no signature work

  // Past the window journal B DOES get served — the budget is shared, not
  // per-journal stranded.
  CHECK(journal_b.submit_permit(forged.view(), now_ms + 7000, true, verdict)
            .code == StatusCode::AuthenticationFailed);
  CHECK(rig.verifier.verify_calls == calls + 1);
}

void test_c04_authorization() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  const std::uint64_t rev = rig.journal->decision_revision();

  // Forged permit: one flipped byte fails the signature check.
  ByteBuffer<kConfigPermitObjectMax> forged = last_permit_;
  forged.bytes[40] ^= 0xFFU;
  CHECK(rig.journal->submit_permit(forged.view(), now_ms, true, verdict).code ==
        StatusCode::AuthenticationFailed);
  CHECK(verdict.reason == ConfigReason::AuthorityDenied);

  // A properly signed permit for the WRONG issuer id still dies at the
  // journal's own identity check — a signature alone never grants scope.
  ConfigCommand wrong = last_command_;
  wrong.operation_id = {0xD0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  wrong.authority = 0x7777;  // not the authorized issuer
  ByteBuffer<kConfigPermitObjectMax> permit{};
  build_permit(signer_, wrong, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::AuthorizationFailed);
  CHECK(verdict.reason == ConfigReason::AuthorityDenied);

  // Wrong target id: the permit AAD binds network+target+namespace, so the
  // envelope itself fails verification — the command is never even judged.
  wrong = last_command_;
  wrong.operation_id = {0xD1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  wrong.target = 0x9999;
  permit.clear();
  build_permit(signer_, wrong, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::AuthenticationFailed);

  // Wrong authority generation.
  wrong = last_command_;
  wrong.operation_id = {0xD2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  wrong.authority_generation = 9;
  permit.clear();
  build_permit(signer_, wrong, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::AuthorizationFailed);

  // Wrong namespace (a valid codec namespace, just not this journal's).
  wrong = last_command_;
  wrong.operation_id = {0xD3, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  wrong.config_namespace = 0x8000;
  permit.clear();
  build_permit(signer_, wrong, permit);
  // The AAD covers the journal's own namespace, so the envelope verifies
  // only if the command's namespace matches the journal's — both fail.
  CHECK(!rig.journal->submit_permit(permit.view(), now_ms, true, verdict).ok());
  CHECK(rig.journal->decision_revision() == rev);
}

// --- C05: challenge expiry / boot change / clock uncertainty -------------------------

void test_c05_challenge_bounds() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};

  // Expired: challenge issued at t0, submitted past valid_for.
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->decision_revision() == 1);

  // Build a second op against a challenge issued at now, submit late.
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = 1;
  query.schema = 1;
  query.client_nonce = {7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(rig.journal->handle_challenge_query(query, now_ms, encoded));
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(config_patch_apply(rig.journal->active_snapshot(), patch2, 1, next, changed));
  Digest256 next_hash{};
  CHECK_OK(config_snapshot_hash(1, 1, next.view(), next_hash));
  ConfigCommand command = last_command_;
  command.operation_id = {0xE0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  command.expected_revision = 1;
  command.next_revision = 2;
  command.base_snapshot_hash = challenge.active_hash;
  command.next_snapshot_hash = next_hash;
  command.challenge_nonce = challenge.challenge_nonce;
  command.target_boot = challenge.target_boot;
  command.apply_within_ms = challenge.valid_for_ms;
  command.fields[0] = patch2[0];
  command.field_count = 1;
  ByteBuffer<kConfigPermitObjectMax> permit{};
  build_permit(signer_, command, permit);
  const MonotonicMs late = now_ms + challenge.valid_for_ms + 1;
  CHECK(rig.journal->submit_permit(permit.view(), late, true, verdict).code ==
        StatusCode::Expired);
  CHECK(verdict.reason == ConfigReason::Deadline);

  // Clock uncertainty: the elapsed time cannot be proven -> no new apply.
  CHECK(rig.journal->submit_permit(permit.view(), now_ms + 100, false, verdict).code ==
        StatusCode::Expired);
  CHECK(verdict.reason == ConfigReason::Deadline);

  // Boot-incarnation mismatch: a permit bound to a different boot dies.
  ConfigCommand wrong_boot = command;
  wrong_boot.operation_id = {0xE1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  wrong_boot.target_boot = rig.config.boot_incarnation + 1;
  permit.clear();
  build_permit(signer_, wrong_boot, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms + 200, true, verdict).code ==
        StatusCode::AuthorizationFailed);

  // A re-issued challenge gets a NEW nonce; the old permit cannot rebind.
  CHECK_OK(rig.journal->handle_challenge_query(query, now_ms + 300, encoded));
  endpoint::ControlChallenge fresh{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), fresh));
  CHECK(!(fresh.challenge_nonce == challenge.challenge_nonce));
  wrong_boot = command;  // still carries the OLD nonce
  wrong_boot.operation_id = {0xE2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  permit.clear();
  build_permit(signer_, wrong_boot, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms + 400, true, verdict).code ==
        StatusCode::AuthorizationFailed);
  CHECK(rig.journal->decision_revision() == 1);
}

// --- C06: write/commit/readback fault injection at the DECIDED boundary ----------------

void test_c06_fault_injection_decided() {
  // Prepare a rig at revision 1 (one applied update = 3 committed records).
  for (std::size_t cut_bytes = 0; cut_bytes <= 2200; cut_bytes += 97) {
    for (const bool seal_phase : {false, true}) {
      TargetRig rig;
      MonotonicMs now_ms = 1000;
      CHECK_OK(rig.journal->initialize(now_ms));
      const ConfigField patch[] = {sdk_u8(1, 1)};
      ConfigVerdict verdict{};
      CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
      drain(rig, now_ms);
      CHECK(rig.journal->phase() == ConfigPhase::Active);

      // The next update's first journal write is DECIDED (write 0 = pending,
      // write 1 = seal, then readback). Cut inside it.
      rig.storage.cut_call = rig.storage.write_calls + (seal_phase ? 1 : 0);
      rig.storage.cut_bytes = cut_bytes;
      const ConfigField patch2[] = {sdk_u8(1, 2)};
      const Status submitted =
          drive_update(rig, patch2, 1, now_ms += 61000, 1,
                       rig.journal->active_snapshot(), verdict);
      CHECK(submitted.code == StatusCode::StorageFailure);
      CHECK(verdict.reason == ConfigReason::StorageFailure);

      // Reboot: the torn record is either discarded (pending) or marks the
      // sibling uncertain — revision 2 is never silently confirmed ACTIVE.
      rig.boot(now_ms += 10);
      drain(rig, now_ms);
      CHECK(rig.journal->decision_revision() <= 2);
      CHECK(rig.journal->active_revision() == 1);
      if (rig.boot_status_.ok()) {
        // Clean outcomes: back at the old ACTIVE record, or the committed
        // DECIDED resolved to INTERRUPTED — never ACTIVE-with-revision-2.
        const bool old_active = rig.journal->phase() == ConfigPhase::Active &&
                                rig.journal->decision_revision() == 1;
        const bool interrupted = rig.journal->phase() == ConfigPhase::Interrupted &&
                                 rig.journal->decision_revision() == 2;
        CHECK(old_active || interrupted);
      } else {
        CHECK(rig.journal->uncertain());
      }
    }
  }

  // Drop the DECIDED seal write entirely: pending record discarded, clean.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField patch[] = {sdk_u8(1, 1)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    rig.storage.drop_call = rig.storage.write_calls + 1;
    const ConfigField patch2[] = {sdk_u8(1, 2)};
    CHECK(!drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict)
               .ok());
    rig.boot(now_ms += 10);
    CHECK_OK(rig.boot_status_);
    drain(rig, now_ms);
    CHECK(rig.journal->decision_revision() == 1);
  }

  // DECIDED committed, then the deferred APPLY_INTENT write is dropped in
  // poll: the committed DECIDED record IS durable — boot resolves it to
  // INTERRUPTED (challenge dead across the boot), revision consumed.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField patch[] = {sdk_u8(1, 1)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    // Drop the APPLY_INTENT pending write — it runs inside poll(), not
    // inside submit (the RX path only ever commits DECIDED).
    rig.storage.drop_call = rig.storage.write_calls + 2;
    const ConfigField patch2[] = {sdk_u8(1, 2)};
    const Status submitted =
        drive_update(rig, patch2, 1, now_ms += 61000, 1,
                     rig.journal->active_snapshot(), verdict);
    CHECK(submitted.ok());  // DECIDED is durable; the intent write defers
    rig.journal->poll(now_ms += 10);  // intent write dropped -> stays pending
    rig.boot(now_ms += 10);
    CHECK_OK(rig.boot_status_);
    drain(rig, now_ms);
    // DECIDED committed, APPLY_INTENT dropped: the revision stays consumed
    // and the operation is recorded interrupted — never applied.
    CHECK(rig.journal->decision_revision() == 2);
    CHECK(rig.journal->phase() == ConfigPhase::Interrupted);
    CHECK(rig.journal->active_revision() == 1);
    endpoint::ControlStatusQuery sq{};
    sq.config_namespace = 1;
    sq.operation_id = last_command_.operation_id;
    endpoint::EncodedServicePayload reply{};
    CHECK_OK(rig.journal->handle_status_query(sq, now_ms, reply));
    endpoint::ControlStatus status{};
    CHECK_OK(endpoint::control_status_decode(reply.view(), status));
    CHECK(status.phase == ConfigPhase::Interrupted);
    CHECK(status.reason == ConfigReason::Deadline);
  }
}

// --- C07: power loss between APPLY_INTENT and ACTIVE -----------------------------------

void test_c07_apply_window_power_loss() {
  // Interrupted restore path: APPLY_INTENT durable, apply never finished.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField patch[] = {sdk_u8(1, 1)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    const std::size_t snapshot_size = rig.journal->active_snapshot().size;

    const ConfigField patch2[] = {sdk_u8(1, 2)};
    rig.provider.partial_apply = true;  // simulate a half-applied write
    CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                          rig.journal->active_snapshot(), verdict));
    // Land APPLY_INTENT and kick the apply (both deferred out of submit):
    // the apply token is outstanding and the provider's active is partial.
    rig.journal->poll(now_ms += 10);
    rig.config.boot_incarnation = kBoot + 1;
    rig.boot(now_ms += 10);  // "power loss": new journal on the same storage
    CHECK_OK(rig.boot_status_);
    CHECK(rig.provider.active_.size == 0);  // partial, never claimed
    drain(rig, now_ms);
    CHECK(rig.journal->phase() == ConfigPhase::Interrupted);
    CHECK(rig.journal->decision_revision() == 2);  // revision stays consumed
    CHECK(rig.journal->active_revision() == 1);
    // The previous confirmed snapshot was restored and read back.
    CHECK(rig.provider.active_.size == snapshot_size);
    endpoint::ControlStatusQuery sq{};
    sq.config_namespace = 1;
    sq.operation_id = last_command_.operation_id;
    endpoint::EncodedServicePayload reply{};
    CHECK_OK(rig.journal->handle_status_query(sq, now_ms, reply));
    endpoint::ControlStatus status{};
    CHECK_OK(endpoint::control_status_decode(reply.view(), status));
    CHECK(status.reason == ConfigReason::ApplyInterrupted);
  }

  // Restore failure at boot -> QUARANTINED, not "maybe applied".
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField patch[] = {sdk_u8(1, 1)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    const ConfigField patch2[] = {sdk_u8(1, 2)};
    CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                          rig.journal->active_snapshot(), verdict));
    rig.journal->poll(now_ms += 10);  // land APPLY_INTENT + kick the apply
    rig.provider.restore_result =
        Status::error(StatusCode::StorageFailure, "restore dead");
    rig.config.boot_incarnation = kBoot + 1;
    rig.boot(now_ms += 10);
    CHECK_OK(rig.boot_status_);
    drain(rig, now_ms);
    CHECK(rig.journal->phase() == ConfigPhase::Quarantined);
    CHECK(rig.journal->quarantined());
  }
}

// --- C08: restart after ACTIVE is continuation only -------------------------------------

void test_c08_active_continuation() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  const std::size_t snapshot_size = rig.journal->active_snapshot().size;
  const std::size_t writes = rig.storage.write_calls;

  rig.config.boot_incarnation = kBoot + 1;
  rig.boot(now_ms += 10);
  CHECK_OK(rig.boot_status_);
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 1);
  CHECK(rig.journal->active_revision() == 1);
  // Continuation restored the confirmed snapshot once — no new journal
  // record was written and the operation was not re-executed as a command.
  CHECK(rig.storage.write_calls == writes);
  CHECK(rig.provider.restore_calls == 1);
  CHECK(rig.provider.apply_calls == 1);  // no re-apply happened
  CHECK(rig.provider.active_.size == snapshot_size);
}

// --- C09: one-slot and both-slot corruption --------------------------------------------

void test_c09_slot_corruption() {
  // One slot lost: survivor is a known value; intake refuses until an
  // authorized recovery re-establishes a fresh generation.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField patch[] = {sdk_u8(1, 1)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    rig.storage.corrupt(0, 100);  // the ACTIVE record's slot
    rig.boot(now_ms += 10);
    CHECK(!rig.boot_status_.ok());
    CHECK(rig.journal->uncertain());
    const ConfigField patch2[] = {sdk_u8(1, 2)};
    CHECK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                       rig.journal->active_snapshot(), verdict)
              .code == StatusCode::RecoveryRequired);
    // A permit submission reports the verdict-level refusal too.
    CHECK(rig.journal->submit_permit(last_permit_.view(), now_ms, true, verdict)
              .code == StatusCode::RecoveryRequired);
    CHECK(verdict.reason == ConfigReason::RecoveryRequired);
    // Authorized recovery re-opens intake without regressing the floor.
    CHECK_OK(rig.journal->recover(10, now_ms, false));
    CHECK(!rig.journal->uncertain());
    // The adopted survivor is INTERRUPTED: its prev-restore was scheduled
    // by recover() and must settle before intake re-opens.
    drain(rig, now_ms);
    CHECK(rig.journal->phase() == ConfigPhase::Interrupted);
    CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                          rig.journal->active_snapshot(), verdict));
    drain(rig, now_ms);
    CHECK(rig.journal->phase() == ConfigPhase::Active);
  }

  // Both slots lost: quarantine, no auto-reset to revision 0.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField patch[] = {sdk_u8(1, 1)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    rig.storage.corrupt(0, 100);
    rig.storage.corrupt(1, 200);
    rig.boot(now_ms += 10);
    CHECK(!rig.boot_status_.ok());
    CHECK(rig.journal->quarantined());
    // Intake is closed; recovery requires a generation above the floor.
    ConfigVerdict v{};
    CHECK(rig.journal->submit_permit(last_permit_.view(), now_ms, true, v).code ==
          StatusCode::IntegrityError);
    CHECK(rig.journal->recover(0, now_ms, false).code == StatusCode::InvalidArgument);
    // With no verifiable survivor, a plain recover() must NOT fabricate a
    // base — the journal stays quarantined (04 §4.7: never an automatic
    // return to revision 0).
    CHECK(rig.journal->recover(11, now_ms, false).code ==
          StatusCode::RecoveryRequired);
    CHECK(rig.journal->quarantined());
    // Only an explicit re-provision attestation may establish the base.
    CHECK_OK(rig.journal->recover(11, now_ms, true));
    CHECK(!rig.journal->quarantined());
    CHECK(rig.journal->phase() == ConfigPhase::Idle);
  }
}

// --- C10: object reassembly corruption ---------------------------------------------------

void test_c10_reassembly() {
  // Produce a real signed permit to chunk.
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  const ByteBuffer<kConfigPermitObjectMax> permit = last_permit_;

  const auto send_chunks = [&](TargetRig& r, const ByteBuffer<kConfigPermitObjectMax>& obj,
                               const std::uint16_t chunk_size, MonotonicMs& t) {
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    manifest.total_len = static_cast<std::uint16_t>(obj.size);
    sha256(obj.view(), manifest.object_hash);
    Status last = r.journal->note_object_manifest(manifest, t);
    for (std::uint16_t offset = 0; offset < obj.size && last.ok();
         offset = static_cast<std::uint16_t>(offset + chunk_size)) {
      autonomy::ObjectChunkPayload chunk{};
      chunk.object_hash = manifest.object_hash;
      chunk.offset = offset;
      chunk.data_size = static_cast<std::uint16_t>(
          obj.size - offset < chunk_size ? obj.size - offset : chunk_size);
      std::memcpy(chunk.data.data(), obj.bytes.data() + offset, chunk.data_size);
      t += 10;
      last = r.journal->note_object_chunk(chunk, t);
    }
    return last;
  };
  // Same flow but the manifest digest is taken from a DIFFERENT object —
  // used to deliver corrupted bytes under an honest manifest.
  auto send_chunks_as = [&](TargetRig& r, const ByteBuffer<kConfigPermitObjectMax>& obj,
                            const ByteBuffer<kConfigPermitObjectMax>& hashed,
                            const std::uint16_t chunk_size, MonotonicMs& t) {
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    manifest.total_len = static_cast<std::uint16_t>(obj.size);
    sha256(hashed.view(), manifest.object_hash);
    Status last = r.journal->note_object_manifest(manifest, t);
    for (std::uint16_t offset = 0; offset < obj.size && last.ok();
         offset = static_cast<std::uint16_t>(offset + chunk_size)) {
      autonomy::ObjectChunkPayload chunk{};
      chunk.object_hash = manifest.object_hash;
      chunk.offset = offset;
      chunk.data_size = static_cast<std::uint16_t>(
          obj.size - offset < chunk_size ? obj.size - offset : chunk_size);
      std::memcpy(chunk.data.data(), obj.bytes.data() + offset, chunk.data_size);
      t += 10;
      last = r.journal->note_object_chunk(chunk, t);
    }
    return last;
  };

  // A complete, intact object submits the permit and applies — here the
  // permit is rebound to rig's freshly issued challenge.
  {
    endpoint::ControlChallengeQuery query{};
    query.config_namespace = 1;
    query.schema = 1;
  query.client_nonce = {7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
    endpoint::EncodedServicePayload encoded{};
    now_ms += 61000;
    CHECK_OK(rig.journal->handle_challenge_query(query, now_ms, encoded));
    endpoint::ControlChallenge challenge{};
    CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
    ByteBuffer<endpoint::kConfigSnapshotMax> next{};
    bool changed = false;
    const ConfigField patch2[] = {sdk_u8(1, 2)};
    CHECK_OK(config_patch_apply(rig.journal->active_snapshot(), patch2, 1, next, changed));
    Digest256 next_hash{};
    CHECK_OK(config_snapshot_hash(1, 1, next.view(), next_hash));
    ConfigCommand command = last_command_;
    command.operation_id = {0xF0, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
    command.expected_revision = 1;
    command.next_revision = 2;
    command.base_snapshot_hash = challenge.active_hash;
    command.next_snapshot_hash = next_hash;
    command.challenge_nonce = challenge.challenge_nonce;
    command.fields[0] = patch2[0];
    command.field_count = 1;
    ByteBuffer<kConfigPermitObjectMax> signed_permit{};
    build_permit(signer_, command, signed_permit);
    CHECK_OK(send_chunks(rig, signed_permit, 64, now_ms));
    drain(rig, now_ms);
    CHECK(rig.journal->phase() == ConfigPhase::Active);
    CHECK(rig.journal->decision_revision() == 2);
  }

  // Corrupted object bytes fail the manifest digest — never applied.
  {
    TargetRig rig3;
    MonotonicMs t = 5000;
    CHECK_OK(rig3.journal->initialize(t));
    ByteBuffer<kConfigPermitObjectMax> bad = permit;
    bad.bytes[50] ^= 0xFFU;
    // Honest manifest (digest of the ORIGINAL bytes) + corrupted content:
    // the reassembly digest check must reject the object before submit.
    CHECK(send_chunks_as(rig3, bad, permit, 64, t).code ==
          StatusCode::IntegrityError);
    CHECK(rig3.journal->stats().reassembly_rejects == 1);
    CHECK(rig3.journal->decision_revision() == 0);
  }

  // Duplicate offset with different bytes poisons the assembly.
  {
    TargetRig rig3;
    MonotonicMs t = 5000;
    CHECK_OK(rig3.journal->initialize(t));
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    manifest.total_len = static_cast<std::uint16_t>(permit.size);
    sha256(permit.view(), manifest.object_hash);
    CHECK_OK(rig3.journal->note_object_manifest(manifest, t));
    autonomy::ObjectChunkPayload chunk{};
    chunk.object_hash = manifest.object_hash;
    chunk.offset = 0;
    chunk.data_size = 32;
    std::memcpy(chunk.data.data(), permit.bytes.data(), 32);
    CHECK_OK(rig3.journal->note_object_chunk(chunk, t));
    chunk.data[10] ^= 0xFFU;  // same offset, different bytes
    CHECK(rig3.journal->note_object_chunk(chunk, t + 10).code == StatusCode::Conflict);
  }

  // Missing manifest -> chunk is an error; oversized object -> rejected.
  {
    TargetRig rig3;
    MonotonicMs t = 5000;
    CHECK_OK(rig3.journal->initialize(t));
    autonomy::ObjectChunkPayload chunk{};
    CHECK(rig3.journal->note_object_chunk(chunk, t).code == StatusCode::InvalidState);
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::ChannelPlan;  // wrong kind
    manifest.total_len = 64;
    manifest.object_hash[0] = 1;
    CHECK(rig3.journal->note_object_manifest(manifest, t).code ==
          StatusCode::ProtocolError);
    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    manifest.total_len = kConfigPermitObjectMax + 1;
    CHECK(rig3.journal->note_object_manifest(manifest, t).code ==
          StatusCode::ProtocolError);
  }

  // Reassembly timeout: a chunk arriving past 10 s resets the assembly.
  {
    TargetRig rig3;
    MonotonicMs t = 5000;
    CHECK_OK(rig3.journal->initialize(t));
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    manifest.total_len = static_cast<std::uint16_t>(permit.size);
    sha256(permit.view(), manifest.object_hash);
    CHECK_OK(rig3.journal->note_object_manifest(manifest, t));
    autonomy::ObjectChunkPayload chunk{};
    chunk.object_hash = manifest.object_hash;
    chunk.offset = 0;
    chunk.data_size = 32;
    std::memcpy(chunk.data.data(), permit.bytes.data(), 32);
    CHECK_OK(rig3.journal->note_object_chunk(chunk, t + 10));
    CHECK(rig3.journal->note_object_chunk(chunk, t + kConfigReassemblyTimeoutMs + 1)
              .code == StatusCode::Expired);
  }
}

// --- C11: schema boundaries ---------------------------------------------------------------

void test_c11_schema_boundaries() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));

  // Unknown field id 5 is a valid TLV field but not in the SDK schema.
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = 1;
  query.schema = 1;
  query.client_nonce = {7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(rig.journal->handle_challenge_query(query, now_ms, encoded));
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
  const ConfigField bad_field[] = {sdk_u8(5, 0)};
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  CHECK_OK(config_patch_apply(ByteView{}, bad_field, 1, next, changed));
  Digest256 next_hash{};
  CHECK_OK(config_snapshot_hash(1, 1, next.view(), next_hash));
  ConfigCommand command{};
  command.config_namespace = 1;
  command.schema = 1;
  command.network = kNet;
  command.target = kTarget;
  command.authority = kAuthority;
  command.authority_generation = 1;
  command.authority_sequence = 1;
  command.operation_id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xF5};
  command.expected_revision = 0;
  command.next_revision = 1;
  command.base_snapshot_hash = challenge.active_hash;
  command.next_snapshot_hash = next_hash;
  command.target_boot = kBoot;
  command.challenge_nonce = challenge.challenge_nonce;
  command.apply_within_ms = challenge.valid_for_ms;
  command.field_count = 1;
  command.fields[0] = bad_field[0];
  ByteBuffer<kConfigPermitObjectMax> permit{};
  build_permit(signer_, command, permit);
  ConfigVerdict verdict{};
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::Unsupported);
  CHECK(verdict.reason == ConfigReason::InvalidPatch);
  CHECK(rig.journal->decision_revision() == 0);

  // Out-of-range SDK value (u8 field 1 = 3) is rejected the same way.
  command.operation_id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xF6};
  command.fields[0] = sdk_u8(1, 3);
  const ConfigField range_patch[] = {sdk_u8(1, 3)};
  CHECK_OK(config_patch_apply(ByteView{}, range_patch, 1, next, changed));
  CHECK_OK(config_snapshot_hash(1, 1, next.view(), next_hash));
  command.next_snapshot_hash = next_hash;
  permit.clear();
  build_permit(signer_, command, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::InvalidArgument);
  CHECK(verdict.reason == ConfigReason::InvalidPatch);

  // Schema version mismatch in the command is an authorization failure.
  command.operation_id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0xF7};
  command.fields[0] = sdk_u8(1, 1);
  command.schema = 2;
  CHECK_OK(config_patch_apply(ByteView{}, command.fields.data(), 1, next, changed));
  CHECK_OK(config_snapshot_hash(1, 2, next.view(), next_hash));
  command.next_snapshot_hash = next_hash;
  permit.clear();
  build_permit(signer_, command, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::AuthorizationFailed);

  // The merged snapshot can never exceed 16 fields / 512 bytes: a 16-field
  // base plus a new field id overflows and is rejected as an invalid patch.
  ConfigField many[endpoint::kConfigFieldCountMax]{};
  for (std::uint16_t i = 0; i < endpoint::kConfigFieldCountMax; ++i) {
    many[i] = sdk_u8(static_cast<std::uint16_t>(i + 1), 0);
  }
  ByteBuffer<endpoint::kConfigSnapshotMax> many_tlv{};
  CHECK_OK(config_tlv_encode(many, endpoint::kConfigFieldCountMax, many_tlv));
  const ConfigField seventeenth[] = {sdk_u8(17, 1)};
  ByteBuffer<endpoint::kConfigSnapshotMax> overflow{};
  CHECK(config_patch_apply(many_tlv.view(), seventeenth, 1, overflow, changed).code ==
        StatusCode::InvalidArgument);
}

// --- C12: relay-off unsafe-path refusal ------------------------------------------------------

void test_c12_maintenance_boundary() {
  // With a gate installed, relay-off consults it; a Busy gate maps to
  // MAINTENANCE_BUSY and nothing is decided.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField relay_on[] = {sdk_bool(3, true)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, relay_on, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    CHECK(rig.gate.calls == 0);  // enabling needs no gate

    rig.gate.result = Status::error(StatusCode::Busy, "channel migration in progress");
    const ConfigField relay_off[] = {sdk_bool(3, false)};
    CHECK(drive_update(rig, relay_off, 1, now_ms += 61000, 1,
                       rig.journal->active_snapshot(), verdict)
              .code == StatusCode::Busy);
    CHECK(verdict.reason == ConfigReason::MaintenanceBusy);
    CHECK(rig.gate.calls == 1);
    CHECK(rig.gate.last.relay_disabling);
    CHECK(rig.journal->decision_revision() == 1);
    CHECK(rig.journal->stats().maintenance_refusals == 1);

    // A refusing gate denies outright; an allowing gate admits the change.
    rig.gate.result =
        Status::error(StatusCode::AuthorizationFailed, "only admin path");
    CHECK(drive_update(rig, relay_off, 1, now_ms += 61000, 1,
                       rig.journal->active_snapshot(), verdict)
              .code == StatusCode::AuthorizationFailed);
    CHECK(verdict.reason == ConfigReason::AuthorityDenied);
    rig.gate.result = Status::success();
    CHECK_OK(drive_update(rig, relay_off, 1, now_ms += 61000, 1,
                          rig.journal->active_snapshot(), verdict));
    drain(rig, now_ms);
    CHECK(rig.journal->phase() == ConfigPhase::Active);
    CHECK(rig.journal->decision_revision() == 2);
  }

  // With no gate installed, a management-path-removing change is refused by
  // default — the initial profile never drops the only admin path.
  {
    TargetRig rig(kBoot, false);
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField relay_on[] = {sdk_bool(3, true)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, relay_on, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    const ConfigField relay_off[] = {sdk_bool(3, false)};
    CHECK(drive_update(rig, relay_off, 1, now_ms += 61000, 1,
                       rig.journal->active_snapshot(), verdict)
              .code == StatusCode::AuthorizationFailed);
    CHECK(verdict.reason == ConfigReason::AuthorityDenied);
    CHECK(rig.journal->decision_revision() == 1);
  }

  // Discovery-off also routes through the gate.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField disc_on[] = {sdk_bool(2, true)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, disc_on, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    rig.gate.result = Status::error(StatusCode::AuthorizationFailed, "no return path");
    const ConfigField disc_off[] = {sdk_bool(2, false)};
    CHECK(drive_update(rig, disc_off, 1, now_ms += 61000, 1,
                       rig.journal->active_snapshot(), verdict)
              .code == StatusCode::AuthorizationFailed);
    CHECK(rig.gate.last.discovery_disabling);
  }
}

// --- C13: result record bounds and retention ---------------------------------------------------

void test_c13_result_records() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  ConfigVerdict verdict{};
  ConfigField patch[1] = {sdk_u8(1, 0)};

  // The acceptance budget (1/min + burst 1) bounds accepted updates to at
  // most 7 inside the 300 s retention window, so the 8-record table is a
  // storage bound, never an intake constraint: the table can never grow
  // past 8 and expired records are the only ones evicted.
  for (int i = 0; i < 8; ++i) {
    patch[0] = sdk_u8(1, static_cast<std::uint8_t>((i + 1) % 3));
    CHECK_OK(drive_update(rig, patch, 1, now_ms, static_cast<std::uint64_t>(i),
                          rig.journal->active_snapshot(), verdict));
    drain(rig, now_ms);
    CHECK(rig.journal->phase() == ConfigPhase::Active);
    now_ms += 60000;
    CHECK(rig.journal->result_records() <= 8);
  }
  CHECK(rig.journal->decision_revision() == 8);

  // A duplicate (same opid + same canonical digest) returns the stored
  // verdict: no decision, no flash write, no new record.
  const ByteBuffer<kConfigPermitObjectMax> saved_permit = last_permit_;
  const ConfigCommand saved_command = last_command_;
  const std::size_t writes = rig.storage.write_calls;
  CHECK_OK(rig.journal->submit_permit(saved_permit.view(), now_ms, true, verdict));
  CHECK(verdict.phase == ConfigPhase::Active);
  CHECK(verdict.reason == ConfigReason::Ok);
  CHECK(rig.storage.write_calls == writes);

  // Same operation id with different content is a CONFLICT, never a re-run.
  ConfigCommand variant = saved_command;
  variant.fields[0] = sdk_u8(1, 0);
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  CHECK_OK(config_patch_apply(rig.journal->active_snapshot(), variant.fields.data(), 1,
                              next, changed));
  Digest256 next_hash{};
  CHECK_OK(config_snapshot_hash(1, 1, next.view(), next_hash));
  variant.next_snapshot_hash = next_hash;
  ByteBuffer<kConfigPermitObjectMax> permit{};
  build_permit(signer_, variant, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::Conflict);
  CHECK(rig.journal->stats().conflicts >= 1);

  // Retention is measured from first completion and is NOT extended by
  // duplicate delivery: still served inside the window, RESULT_EXPIRED
  // past it (never a silent re-execution). The record was written when
  // op 8 completed — one 60 s acceptance tick before `now_ms`.
  const MonotonicMs stored_at = now_ms - 60000;
  CHECK_OK(rig.journal->submit_permit(saved_permit.view(), stored_at + 299000, true,
                                    verdict));
  CHECK(verdict.phase == ConfigPhase::Active);
  CHECK(rig.journal->submit_permit(saved_permit.view(), stored_at + 300500, true,
                                   verdict)
            .code == StatusCode::NotFound);
  CHECK(verdict.reason == ConfigReason::ResultExpired);

  // Expired records free their slot for new operations (op 8 left field 1
  // at 2, so this patch must differ to be a real change).
  patch[0] = sdk_u8(1, 0);
  now_ms = stored_at + 300500;
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 8,
                        rig.journal->active_snapshot(), verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 9);
  CHECK(rig.journal->result_records() <= 8);
}

// --- C14: maintenance conflict + stale permit arrival ---------------------------------------------

void test_c14_stale_and_busy() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);

  // A permit minted for the old revision arrives late -> STALE, no apply.
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = 1;
  query.schema = 1;
  query.client_nonce = {7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  endpoint::EncodedServicePayload encoded{};
  now_ms += 100;
  CHECK_OK(rig.journal->handle_challenge_query(query, now_ms, encoded));
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
  ConfigCommand stale = last_command_;  // expected_revision 0, next 1
  stale.operation_id = {0xC4, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  stale.challenge_nonce = challenge.challenge_nonce;
  stale.target_boot = challenge.target_boot;
  ByteBuffer<kConfigPermitObjectMax> permit{};
  build_permit(signer_, stale, permit);
  CHECK(rig.journal->submit_permit(permit.view(), now_ms, true, verdict).code ==
        StatusCode::Conflict);
  CHECK(verdict.reason == ConfigReason::StaleRevision);

  // Maintenance conflict: while a transaction is between DECIDED and its
  // terminal record, a second operation is refused BUSY — never queued.
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);  // apply token outstanding
  ConfigCommand second = last_command_;
  second.operation_id = {0xC5, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  ByteBuffer<kConfigPermitObjectMax> permit2{};
  build_permit(signer_, second, permit2);
  CHECK(rig.journal->submit_permit(permit2.view(), now_ms, true, verdict).code ==
        StatusCode::Busy);
  // And the in-flight operation still completes to ACTIVE.
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 2);
}

// --- Issuer-side flows -----------------------------------------------------------------

struct IssuerRig {
  static ConfigIssuerConfig make_config() {
    ConfigIssuerConfig config{};
    config.network = kNet;
    config.authority = kAuthority;
    config.safety_margin_ms = 200;
    return config;
  }

  ConfigIssuerConfig config{make_config()};
  routeloom_test::FaultyLedgerStorage ledger_storage{};
  SingleAuthority ledger{kNet, kAuthority, ledger_storage};
  FakeOutboxStorage outbox{};
  FakePermitSigner signer{};
  CountingEntropy entropy{};
  ConfigIssuer issuer{config, ledger, outbox, signer, entropy};

  void boot() { CHECK_OK(ledger.initialize()); }
};

endpoint::ControlChallenge fake_challenge(const std::uint64_t revision,
                                          const ByteView active_snapshot,
                                          const MonotonicMs /*now*/) {
  endpoint::ControlChallenge challenge{};
  challenge.config_namespace = 1;
  challenge.schema = 1;
  challenge.target_boot = kBoot;
  challenge.challenge_nonce = {0x5A, 1, 2, 3, 4, 5, 6, 7,
                               8,    9, 10, 11, 12, 13, 14, 15};
  challenge.revision = revision;
  CHECK_OK(config_snapshot_hash(1, 1, active_snapshot, challenge.active_hash));
  challenge.valid_for_ms = 30000;
  return challenge;
}

void test_issuer_commit_order() {
  IssuerRig rig;
  rig.boot();
  CHECK_OK(rig.issuer.initialize());
  const MonotonicMs now_ms = 1000;
  CHECK_OK(rig.issuer.note_challenge(fake_challenge(0, ByteView{}, now_ms), kTarget,
                                     now_ms));

  const ConfigField patch[] = {sdk_u8(1, 1)};
  IssuedOperation op{};
  CHECK_OK(rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms + 10, op));
  CHECK(op.issued);
  // The ledger committed exactly once, at sequence 1, with the REAL
  // SHA-256 operation hash — bind_operation_payload is never involved.
  CHECK(rig.ledger.state().applied_sequence == 1);
  Digest256 expected_hash{};
  sha256(op.canonical.view(), expected_hash);
  CHECK(rig.ledger.last_operation_hash() == expected_hash);

  // The signed permit retransmits byte-identically every time.
  ByteBuffer<kConfigPermitObjectMax> p1{}, p2{};
  CHECK_OK(rig.issuer.signed_permit(op.slot, p1));
  CHECK_OK(rig.issuer.signed_permit(op.slot, p2));
  CHECK(p1.size == p2.size);
  CHECK(std::memcmp(p1.bytes.data(), p2.bytes.data(), p1.size) == 0);
  CHECK(p1.size == op.permit.size);
  CHECK(std::memcmp(p1.bytes.data(), op.permit.bytes.data(), p1.size) == 0);

  // The canonical command inside the permit decodes and binds the op.
  endpoint::ConfigCommand decoded{};
  const ByteView canonical{p1.bytes.data() + kPermitAadSize,
                           p1.size - kPermitAadSize - kPermitTagSize};
  CHECK_OK(endpoint::config_command_decode(canonical, decoded));
  CHECK(decoded.expected_revision == 0 && decoded.next_revision == 1);
  CHECK(decoded.authority_sequence == 1);
  CHECK(decoded.target == kTarget && decoded.network == kNet);
}

void test_issuer_no_change_and_budget() {
  IssuerRig rig;
  rig.boot();
  CHECK_OK(rig.issuer.initialize());
  const MonotonicMs now_ms = 1000;
  // Build a base snapshot the challenge commits to.
  const ConfigField base[] = {sdk_u8(1, 1)};
  ByteBuffer<endpoint::kConfigSnapshotMax> base_tlv{};
  CHECK_OK(config_tlv_encode(base, 1, base_tlv));
  CHECK_OK(rig.issuer.note_challenge(fake_challenge(3, base_tlv.view(), now_ms),
                                     kTarget, now_ms));

  // NO_CHANGE: same-value patch decides before signing — no ledger write,
  // no outbox write, no flash, no revision.
  const std::size_t ledger_writes = rig.ledger_storage.write_calls;
  const std::size_t outbox_writes = rig.outbox.write_calls;
  const ConfigField noop[] = {sdk_u8(1, 1)};
  IssuedOperation op{};
  CHECK_OK(rig.issuer.propose(kTarget, 1, 1, base_tlv.view(), noop, 1, 0,
                              now_ms + 10, op));
  CHECK(op.no_change);
  CHECK(!op.issued);
  CHECK(rig.ledger_storage.write_calls == ledger_writes);
  CHECK(rig.outbox.write_calls == outbox_writes);
  CHECK(rig.ledger.state().applied_sequence == 0);
  CHECK(rig.signer.sign_calls == 0);

  // Challenge budget: apply_within is the remaining lifetime minus the
  // conservative safety margin — never the full challenge window.
  const ConfigField patch[] = {sdk_u8(1, 2)};
  CHECK_OK(rig.issuer.propose(kTarget, 1, 1, base_tlv.view(), patch, 1, 0,
                              now_ms + 29000, op));
  CHECK(op.issued);
  endpoint::ConfigCommand decoded{};
  CHECK_OK(endpoint::config_command_decode(op.canonical.view(), decoded));
  CHECK(decoded.apply_within_ms == 30000 - 29000 - 200);
  // Inside the remaining window but past the margin -> refused.
  CHECK(rig.issuer.propose(kTarget, 1, 1, base_tlv.view(), patch, 1, 0,
                           now_ms + 29900, op)
            .code == StatusCode::Expired);
  // A caller budget larger than the remaining window is refused, not
  // silently clamped past the challenge lifetime.
  CHECK(rig.issuer.propose(kTarget, 1, 1, base_tlv.view(), patch, 1, 60000,
                           now_ms + 10, op)
            .code == StatusCode::Expired);
}

void test_issuer_resume_after_power_loss() {
  // Case A: outbox persisted + ledger committed, signing never completed.
  {
    IssuerRig rig;
    rig.boot();
    CHECK_OK(rig.issuer.initialize());
    const MonotonicMs now_ms = 1000;
    CHECK_OK(rig.issuer.note_challenge(fake_challenge(0, ByteView{}, now_ms), kTarget,
                                       now_ms));
    rig.signer.fail_next = true;  // power loss lands right at the sign step
    const ConfigField patch[] = {sdk_u8(1, 1)};
    IssuedOperation op{};
    CHECK(rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms, op)
              .code == StatusCode::InternalError);
    CHECK(rig.ledger.state().applied_sequence == 1);  // commit DID land
    // Resume: the pending entry sees the commit already landed, then signs.
    ConfigIssuer resumed(rig.config, rig.ledger, rig.outbox, rig.signer,
                         rig.entropy);
    CHECK_OK(resumed.initialize());
    CHECK(resumed.signed_count() == 1);
    CHECK(resumed.pending_count() == 0);
    ByteBuffer<kConfigPermitObjectMax> permit{};
    CHECK_OK(resumed.signed_permit(0, permit));
    endpoint::ConfigCommand decoded{};
    CHECK_OK(endpoint::config_command_decode(
        ByteView{permit.bytes.data() + kPermitAadSize, permit.size - kPermitAadSize - 16}, decoded));
    CHECK(decoded.authority_sequence == 1);  // same command, same blob
  }

  // Case B: outbox persisted but the ledger commit itself was cut.
  {
    IssuerRig rig;
    rig.boot();
    CHECK_OK(rig.issuer.initialize());
    const MonotonicMs now_ms = 1000;
    CHECK_OK(rig.issuer.note_challenge(fake_challenge(0, ByteView{}, now_ms), kTarget,
                                       now_ms));
    // Cut the ledger's FIRST commit write (call 0 = pending phase).
    rig.ledger_storage.cut_call = 0;
    rig.ledger_storage.cut_bytes = 40;
    const ConfigField patch[] = {sdk_u8(1, 1)};
    IssuedOperation op{};
    CHECK(!rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms, op)
               .ok());
    CHECK(rig.ledger.state().applied_sequence == 0);
    ConfigIssuer resumed(rig.config, rig.ledger, rig.outbox, rig.signer,
                         rig.entropy);
    CHECK_OK(resumed.initialize());
    CHECK(resumed.signed_count() == 1);
    CHECK(rig.ledger.state().applied_sequence == 1);
  }
}

void test_issuer_outbox_bounds() {
  IssuerRig rig;
  rig.boot();
  CHECK_OK(rig.issuer.initialize());
  const MonotonicMs now_ms = 1000;
  CHECK_OK(rig.issuer.note_challenge(fake_challenge(0, ByteView{}, now_ms), kTarget,
                                     now_ms));
  // Force every sign to fail once: each propose leaves a committed-but-
  // unsigned pending entry, until the outbox (4) fills.
  const ConfigField patch[] = {sdk_u8(1, 1)};
  for (int i = 0; i < 4; ++i) {
    rig.signer.fail_next = true;
    // Each failure leaves the ledger one sequence ahead; the next propose
    // mints the next sequence.
    IssuedOperation op{};
    CHECK(rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms, op)
              .code == StatusCode::InternalError);
  }
  IssuedOperation op{};
  CHECK(rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms, op)
            .code == StatusCode::NoCapacity);
  // Resume finishes all four. Each entry's own commit DID land, but
  // applied has moved past it and no sibling holds its sequence — that
  // makes the "this entry consumed the sequence" claim unprovable (an
  // outside ledger consumer could hold it), so every entry is re-minted
  // under a fresh sequence and committed again rather than signing a
  // canonical whose commit cannot be proven.
  ConfigIssuer resumed(rig.config, rig.ledger, rig.outbox, rig.signer,
                       rig.entropy);
  CHECK_OK(resumed.initialize());
  CHECK(resumed.signed_count() == 4);
  CHECK(rig.ledger.state().applied_sequence == 8);
}

// --- Apply-path failure -> restore -> INTERRUPTED ------------------------------------------

void test_apply_failure_restores() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  const std::size_t prev_size = rig.journal->active_snapshot().size;

  rig.provider.fail_polls = 1;  // apply fails once; the restore still completes
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict));
  drain(rig, now_ms);
  // The apply failure restored the previous snapshot and the operation is
  // recorded APPLY_INTERRUPTED — the revision stays consumed.
  CHECK(rig.journal->phase() == ConfigPhase::Interrupted);
  CHECK(rig.journal->decision_revision() == 2);
  CHECK(rig.journal->active_revision() == 1);
  CHECK(rig.provider.active_.size == prev_size);
  CHECK(rig.provider.restore_calls == 1);

  // Readback mismatch (verify failed) also restores + interrupts.
  TargetRig rig2;
  MonotonicMs t2 = 1000;
  CHECK_OK(rig2.journal->initialize(t2));
  CHECK_OK(drive_update(rig2, patch, 1, t2, 0, ByteView{}, verdict));
  drain(rig2, t2);
  rig2.provider.corrupt_reads = 1;  // only the post-apply readback lies
  CHECK_OK(drive_update(rig2, patch2, 1, t2 += 61000, 1,
                        rig2.journal->active_snapshot(), verdict));
  drain(rig2, t2);
  CHECK(rig2.journal->phase() == ConfigPhase::Interrupted);
  CHECK(rig2.provider.restore_calls == 1);
}

// --- Storage contract: records fit the slots, no whole-board erase ---------------------------

void test_storage_contract() {
  FakeJournalStorage storage;
  FakeVerifier verifier;
  CountingEntropy entropy;
  ConfigRateLimiter rate;
  FakeProvider provider;
  ConfigJournalConfig config{};
  config.network = kNet;
  config.target = kTarget;
  config.boot_incarnation = kBoot;
  config.authorized_issuer = kAuthority;
  config.authority_generation = 1;
  ConfigJournal journal(config, storage, verifier, entropy, rate, &provider,
                        nullptr, nullptr);
  MonotonicMs now_ms = 1000;
  CHECK_OK(journal.initialize(now_ms));
  // Invalid identities are refused up front.
  ConfigJournalConfig bad = config;
  bad.challenge_valid_ms = kConfigChallengeMaxMs + 1;
  ConfigJournal journal_bad(bad, storage, verifier, entropy, rate, &provider,
                            nullptr, nullptr);
  CHECK(journal_bad.initialize(now_ms).code == StatusCode::InvalidArgument);
  bad = config;
  bad.boot_incarnation = 0;
  ConfigJournal journal_bad2(bad, storage, verifier, entropy, rate, &provider,
                             nullptr, nullptr);
  CHECK(journal_bad2.initialize(now_ms).code == StatusCode::InvalidArgument);
}

// --- Recovery / floor / deferred-intent regressions ---------------------------------------

// The generation/revision floors must advance on every committed record:
// recover() may never re-mint a generation this boot already consumed,
// nor roll a decided revision back (06 §6.3).
void test_floor_advance_on_commit() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  // Apply fails AND the restore fails -> QUARANTINED record committed.
  rig.provider.apply_result =
      Status::error(StatusCode::StorageFailure, "apply dead");
  rig.provider.restore_result =
      Status::error(StatusCode::StorageFailure, "restore dead");
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->quarantined());
  // Generations 1..3 (DECIDED, APPLY_INTENT, QUARANTINED) are all consumed
  // this boot — recovery must start above them, not above a stale floor.
  CHECK(rig.journal->recover(2, now_ms, false).code == StatusCode::InvalidArgument);
  CHECK(rig.journal->recover(3, now_ms, false).code == StatusCode::InvalidArgument);
  CHECK_OK(rig.journal->recover(4, now_ms, false));
  CHECK(!rig.journal->quarantined());
  // The decided revision was adopted — never rolled back to a lower base.
  CHECK(rig.journal->decision_revision() == 1);
}

// An ACTIVE survivor stays ACTIVE across recovery: losing the sibling
// slot's evidence does not roll the target back to a previous snapshot.
void test_active_survivor_recover() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  const std::size_t active_size = rig.journal->active_snapshot().size;

  // Corrupt the NON-ACTIVE sibling slot (the stale APPLY_INTENT record).
  rig.storage.corrupt(1, 200);
  rig.boot(now_ms += 10);
  CHECK(!rig.boot_status_.ok());
  CHECK(rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);

  CHECK_OK(rig.journal->recover(4, now_ms, false));
  CHECK(!rig.journal->uncertain());
  // The survivor is adopted as ACTIVE with its confirmed snapshot — the
  // recover() code used to degrade it to INTERRUPTED and roll back.
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 1);
  CHECK(rig.journal->active_revision() == 1);
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.provider.active_.size == active_size);
}

// A terminal write dropped on the boot-resolution path is retried by
// poll() — the durable record must not stay APPLY_INTENT forever.
void test_boot_terminal_persist_retry() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  // Land update 2's APPLY_INTENT with the apply kicked but never finished.
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict));
  rig.journal->poll(now_ms += 10);
  // Boot: the APPLY_INTENT survivor restores prev; the terminal
  // INTERRUPTED write is then dropped — it must retry, not vanish.
  rig.storage.drop_call = rig.storage.write_calls;  // next write = finish w0
  rig.boot(now_ms += 10);
  CHECK_OK(rig.boot_status_);
  // One poll: restore kicks AND completes -> the terminal write is dropped.
  rig.journal->poll(now_ms += 10);
  CHECK(rig.journal->phase() == ConfigPhase::ApplyIntent);  // not terminal yet
  rig.journal->poll(now_ms += 10);  // retry lands the INTERRUPTED record
  CHECK(rig.journal->phase() == ConfigPhase::Interrupted);
  // Prove durability: a subsequent boot reads the INTERRUPTED record.
  rig.boot(now_ms += 10);
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Interrupted);
  CHECK(rig.journal->decision_revision() == 2);
}

// One requester's challenge churn must never kill another requester's
// outstanding challenge; a full table refuses Busy rather than evicting.
void test_challenge_churn() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));

  // The "admin" requester holds the first slot.
  endpoint::ControlChallengeQuery admin_q{};
  admin_q.config_namespace = 1;
  admin_q.schema = 1;
  admin_q.client_nonce = {0xAA, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(rig.journal->handle_challenge_query(admin_q, now_ms, encoded));
  endpoint::ControlChallenge admin_challenge{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), admin_challenge));

  // Three other requesters fill the remaining slots.
  for (std::uint8_t i = 0; i < 3; ++i) {
    endpoint::ControlChallengeQuery q{};
    q.config_namespace = 1;
    q.schema = 1;
    q.client_nonce = {0xB0, i, i, i, i, i, i, i, i, i, i, i, i, i, i, i};
    endpoint::EncodedServicePayload out{};
    CHECK_OK(rig.journal->handle_challenge_query(q, now_ms += 5, out));
  }
  // Table full: a fifth DISTINCT requester is refused Busy — outstanding
  // challenges are never evicted by churn.
  endpoint::ControlChallengeQuery extra{};
  extra.config_namespace = 1;
  extra.schema = 1;
  extra.client_nonce = {0xC0, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9};
  endpoint::EncodedServicePayload out{};
  CHECK(rig.journal->handle_challenge_query(extra, now_ms += 5, out).code ==
        StatusCode::Busy);
  // The admin's re-query refreshes its OWN slot only — and its permit
  // bound to the refreshed challenge still validates.
  CHECK_OK(rig.journal->handle_challenge_query(admin_q, now_ms += 5, encoded));
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), admin_challenge));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(submit_bound(rig, admin_challenge, patch, 1, now_ms, 0, ByteView{},
                        verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 1);
}

// submit_permit returns right after DECIDED: no APPLY_INTENT write and no
// provider apply on the radio RX path — both land inside poll().
void test_deferred_intent() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  CHECK(rig.provider.apply_calls == 0);  // apply never ran on the RX path
  CHECK(rig.journal->phase() == ConfigPhase::Decided);
  CHECK(rig.journal->stats().accepted == 1);
  const std::size_t writes = rig.storage.write_calls;
  rig.journal->poll(now_ms += 10);  // APPLY_INTENT write + apply kick
  CHECK(rig.provider.apply_calls == 1);
  CHECK(rig.journal->phase() == ConfigPhase::Applying);
  CHECK(rig.storage.write_calls == writes + 2);  // pending + seal only
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);

  // The apply-window deadline is re-checked at the true apply time: a
  // first poll past the window ends INTERRUPTED — never applied late.
  TargetRig rig2;
  MonotonicMs t = 1000;
  CHECK_OK(rig2.journal->initialize(t));
  endpoint::ControlChallengeQuery q{};
  q.config_namespace = 1;
  q.schema = 1;
  q.client_nonce = {7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(rig2.journal->handle_challenge_query(q, t, encoded));
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
  ConfigVerdict v2{};
  CHECK_OK(submit_bound(rig2, challenge, patch, 1, t, 0, ByteView{}, v2,
                        100 /* apply_within_ms */));
  rig2.journal->poll(t + 200);  // past the window at the true apply time
  CHECK(rig2.journal->phase() == ConfigPhase::Interrupted);
  CHECK(rig2.provider.apply_calls == 0);  // the apply never started
}

// A DECIDED write fault returns the acceptance token — the refusal
// consumed nothing, so the budget is not burned by storage faults.
void test_storage_failure_refunds_budget() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);

  // Second update inside the same 60 s window: drop its DECIDED write.
  rig.storage.drop_call = rig.storage.write_calls;  // DECIDED pending write
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK(drive_update(rig, patch2, 1, now_ms, 1,
                     rig.journal->active_snapshot(), verdict)
            .code == StatusCode::StorageFailure);
  CHECK(rig.journal->stats().storage_failures == 1);

  // A third update in the same window would exceed the 2/60 s budget if
  // the failed DECIDED had burned its token — it must still be admitted.
  const ConfigField patch3[] = {sdk_u8(1, 0)};
  CHECK_OK(drive_update(rig, patch3, 1, now_ms, 1,
                        rig.journal->active_snapshot(), verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 2);
}

// While storage is unproven every intake path refuses — challenges,
// manifests and chunks included, not just submit_permit.
void test_uncertain_intake_refused() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  rig.storage.corrupt(1, 200);  // lose the non-ACTIVE sibling
  rig.boot(now_ms += 10);
  CHECK(rig.journal->uncertain());

  endpoint::ControlChallengeQuery q{};
  q.config_namespace = 1;
  q.schema = 1;
  q.client_nonce = {7, 7, 7, 7, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  endpoint::EncodedServicePayload encoded{};
  CHECK(rig.journal->handle_challenge_query(q, now_ms, encoded).code ==
        StatusCode::RecoveryRequired);
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  manifest.total_len = 64;
  manifest.object_hash[0] = 1;
  CHECK(rig.journal->note_object_manifest(manifest, now_ms).code ==
        StatusCode::RecoveryRequired);
  autonomy::ObjectChunkPayload chunk{};
  CHECK(rig.journal->note_object_chunk(chunk, now_ms).code ==
        StatusCode::RecoveryRequired);
}

// A committed-seal record that fails structural validation is noise: it
// must NOT bound the recovery floor (bitrot could otherwise mint an
// arbitrary floor and wedge recovery forever).
void test_floor_corrupt_structural() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  // Damage the ACTIVE record's reserved byte (offset 21): the record
  // parses but fails semantic validation — Corrupt WITHOUT floor proof.
  rig.storage.corrupt(0, 21);
  rig.boot(now_ms += 10);
  CHECK(rig.journal->uncertain());
  // The floor came only from the valid sibling (generation 2): the
  // corrupt record's gen-3 claim cannot wedge recovery.
  CHECK_OK(rig.journal->recover(3, now_ms, false));
  CHECK(!rig.journal->uncertain());
}

// Corrupt-but-present evidence is never "fresh": erased + corrupt slots
// quarantine; a foreign record reports its identity mismatch — neither
// may silently adopt an empty base.
void test_fresh_vs_impaired() {
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    rig.storage.fill(0, 0xA5);  // undecodable garbage, not erased
    rig.boot(now_ms);
    CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
    CHECK(rig.journal->quarantined());
  }
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    const ConfigField patch[] = {sdk_u8(1, 1)};
    ConfigVerdict verdict{};
    CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
    drain(rig, now_ms);
    // Same durable bytes, journal configured for a different network.
    TargetRig foreign;
    foreign.config.network = kNet + 1;
    foreign.storage.slots_ = rig.storage.slots_;
    foreign.boot(now_ms += 10);
    CHECK(foreign.boot_status_.code == StatusCode::Conflict);
  }
}

// The revision pair is codec-enforced end to end: a permit can never
// carry next_revision != expected_revision + 1 to validate_command.
void test_revision_pair_contract() {
  ConfigCommand command{};
  command.config_namespace = 1;
  command.schema = 1;
  command.network = kNet;
  command.target = kTarget;
  command.authority = kAuthority;
  command.authority_generation = 1;
  command.authority_sequence = 1;
  command.operation_id = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  command.expected_revision = 5;
  command.next_revision = 7;  // != expected + 1
  command.base_snapshot_hash[0] = 1;
  command.next_snapshot_hash[0] = 2;
  command.target_boot = kBoot;
  command.challenge_nonce = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  command.apply_within_ms = 1000;
  command.field_count = 1;
  command.fields[0] = sdk_u8(1, 1);
  endpoint::EncodedConfigCommand canonical{};
  CHECK(endpoint::config_command_encode(command, canonical).code ==
        StatusCode::InvalidArgument);
}

// A duplicate manifest with a different total_len contradicts the
// assembly in progress — a protocol conflict, never re-ACKed.
void test_manifest_length_conflict() {
  TargetRig rig;
  MonotonicMs t = 1000;
  CHECK_OK(rig.journal->initialize(t));
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  manifest.total_len = 64;
  manifest.object_hash[0] = 0xAB;
  CHECK_OK(rig.journal->note_object_manifest(manifest, t));
  manifest.total_len = 128;  // same object hash, different declared length
  CHECK(rig.journal->note_object_manifest(manifest, t).code ==
        StatusCode::Conflict);
}

// RESULT_EXPIRED is the wire answer — the Status4 response is emitted,
// not dropped behind an error Status.
void test_status_result_expired() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  const ConfigCommand op1 = last_command_;
  // A later operation supersedes op1 as the durable record — the status
  // query then falls through to op1's (now expired) result record.
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict));
  drain(rig, now_ms);
  endpoint::ControlStatusQuery sq{};
  sq.config_namespace = 1;
  sq.operation_id = op1.operation_id;
  endpoint::EncodedServicePayload reply{};
  CHECK_OK(rig.journal->handle_status_query(sq, now_ms + kConfigResultHoldMs + 1,
                                            reply));
  endpoint::ControlStatus status{};
  CHECK_OK(endpoint::control_status_decode(reply.view(), status));
  CHECK(status.phase == ConfigPhase::Idle);
  CHECK(status.reason == ConfigReason::ResultExpired);
}

// A CRC-failed SIGNED outbox entry is impaired — never a free slot: its
// signature may already have been consumed.
void test_impaired_outbox_slot() {
  IssuerRig rig;
  rig.boot();
  CHECK_OK(rig.issuer.initialize());
  const MonotonicMs now_ms = 1000;
  CHECK_OK(rig.issuer.note_challenge(fake_challenge(0, ByteView{}, now_ms),
                                     kTarget, now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  IssuedOperation op{};
  CHECK_OK(rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms,
                              op));
  CHECK(op.issued);
  CHECK(op.slot == 0);
  // Corrupt the signed record's payload (past the 24-byte header): the
  // record parses under a committed seal but fails CRC.
  rig.outbox.slots_[0][40] ^= 0xFFU;
  // A new propose must skip the impaired slot — never reuse it.
  IssuedOperation op2{};
  CHECK_OK(rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms,
                              op2));
  CHECK(op2.issued);
  CHECK(op2.slot == 1);
  // Resume reports the impairment instead of silently freeing the slot.
  const auto snapshot = rig.outbox.slots_[0];
  ConfigIssuer resumed(rig.config, rig.ledger, rig.outbox, rig.signer,
                       rig.entropy);
  CHECK(!resumed.initialize().ok());
  CHECK(rig.outbox.slots_[0] == snapshot);  // never cleared or overwritten
}

// Unique holder of a consumed sequence is unprovable: resume re-mints the
// operation under a fresh sequence and commits it, rather than signing a
// canonical whose ledger commit cannot be proven.
void test_issuer_remint_sequence() {
  IssuerRig rig;
  rig.boot();
  CHECK_OK(rig.issuer.initialize());
  const MonotonicMs now_ms = 1000;
  CHECK_OK(rig.issuer.note_challenge(fake_challenge(0, ByteView{}, now_ms),
                                     kTarget, now_ms));
  // Power cut inside the ledger commit: the PENDING outbox entry (seq 1)
  // persisted, but its commit never landed.
  rig.ledger_storage.cut_call = 0;
  rig.ledger_storage.cut_bytes = 40;
  const ConfigField patch[] = {sdk_u8(1, 1)};
  IssuedOperation op{};
  CHECK(!rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms, op)
             .ok());
  CHECK(rig.ledger.state().applied_sequence == 0);
  // An outside consumer then takes sequences 1 and 2 — the ledger's
  // global sequence is shared, config ops are not its only commits.
  for (int i = 0; i < 2; ++i) {
    AuthorityOperation external{};
    Digest256 hash{};
    sha256(ByteView{reinterpret_cast<const std::uint8_t*>("ext"), 3}, hash);
    CHECK_OK(rig.ledger.build_operation(
        AuthorityOperationKind::MembershipApproval, hash, external));
    CHECK_OK(rig.ledger.apply_membership_approval(external, hash, true));
  }
  CHECK(rig.ledger.state().applied_sequence == 2);
  // Resume: whether the entry's own commit landed is unprovable — it is
  // re-minted to sequence 3, committed, then signed.
  ConfigIssuer resumed(rig.config, rig.ledger, rig.outbox, rig.signer,
                       rig.entropy);
  CHECK_OK(resumed.initialize());
  CHECK(resumed.signed_count() == 1);
  CHECK(rig.ledger.state().applied_sequence == 3);
  ByteBuffer<kConfigPermitObjectMax> permit{};
  CHECK_OK(resumed.signed_permit(0, permit));
  endpoint::ConfigCommand decoded{};
  CHECK_OK(endpoint::config_command_decode(
      ByteView{permit.bytes.data() + kPermitAadSize,
               permit.size - kPermitAadSize - kPermitTagSize},
      decoded));
  CHECK(decoded.authority_sequence == 3);
}

// Superseded outbox entries are tombstoned with a short pending-seal
// header — not a full 2048-byte erase (the §6.8 flash budget counts writes).
void test_outbox_tombstone_size() {
  IssuerRig rig;
  rig.boot();
  CHECK_OK(rig.issuer.initialize());
  const MonotonicMs now_ms = 1000;
  CHECK_OK(rig.issuer.note_challenge(fake_challenge(0, ByteView{}, now_ms),
                                     kTarget, now_ms));
  rig.ledger_storage.cut_call = 0;
  rig.ledger_storage.cut_bytes = 40;
  const ConfigField patch[] = {sdk_u8(1, 1)};
  IssuedOperation op{};
  CHECK(!rig.issuer.propose(kTarget, 1, 1, ByteView{}, patch, 1, 0, now_ms, op)
             .ok());
  // An outside consumer takes sequence 1: the pending entry is provably
  // superseded and gets tombstoned on resume.
  AuthorityOperation external{};
  Digest256 hash{};
  sha256(ByteView{reinterpret_cast<const std::uint8_t*>("ext"), 3}, hash);
  CHECK_OK(rig.ledger.build_operation(AuthorityOperationKind::MembershipApproval,
                                      hash, external));
  CHECK_OK(rig.ledger.apply_membership_approval(external, hash, true));
  ConfigIssuer resumed(rig.config, rig.ledger, rig.outbox, rig.signer,
                       rig.entropy);
  const Status status = resumed.initialize();
  CHECK(status.code == StatusCode::Conflict);  // superseded, honestly reported
  CHECK(resumed.signed_count() == 0);
  CHECK(resumed.pending_count() == 0);
  CHECK(rig.outbox.last_write_size <= 32);
}

// --- R-series: the dedicated recovery lane (Issue #51) -------------------------
//
// A signed kind-4 RCR1 object is the ONLY intake an impaired journal still
// serves. StoreRecover attests a fresh store generation for a quarantined/
// uncertain journal; AuthorityGeneration countersigns the next trust
// generation (03-signing trust update) on a proven one. Everything else —
// bad signatures, stale generations, replays, wrong lanes — stays fail-closed.

// Build + encode + sign an RCR1 recovery object bound to `rig`'s identity.
// `authority_generation` is the generation the COMMAND claims — the journal
// only accepts the one it currently pins.
void build_recovery(FakePermitSigner& signer, const TargetRig& rig,
                    const endpoint::ConfigRecoveryClass cls,
                    const std::uint8_t attest,
                    const std::uint32_t new_store_generation,
                    const std::uint32_t new_authority_generation,
                    const std::uint8_t opid_tag,
                    const std::uint32_t authority_generation,
                    ByteBuffer<kConfigPermitObjectMax>& object,
                    endpoint::ConfigRecoveryCommand* command_out = nullptr) {
  endpoint::ConfigRecoveryCommand command{};
  command.recovery_class = cls;
  command.attest = attest;
  command.config_namespace = rig.config.config_namespace;
  command.schema = rig.config.schema;
  command.network = rig.config.network;
  command.target = rig.config.target;
  command.authority = rig.config.authorized_issuer;
  command.authority_generation = authority_generation;
  command.authority_sequence = 90 + opid_tag;
  command.operation_id = {0xC0, opid_tag, 2, 3, 4, 5, 6, 7,
                          8,    9,        10, 11, 12, 13, 14, 15};
  command.new_store_generation = new_store_generation;
  command.new_authority_generation = new_authority_generation;
  if (command_out != nullptr) *command_out = command;
  endpoint::EncodedRecoveryCommand canonical{};
  CHECK_OK(endpoint::config_recovery_encode(command, canonical));
  CHECK_OK(signer.sign_recovery(command, canonical.view(), object));
}

// Feed `object` through the kind-4 manifest/chunk lane in `chunk_size` pieces.
Status send_recovery_chunks(TargetRig& rig,
                            const ByteBuffer<kConfigPermitObjectMax>& object,
                            const std::uint16_t chunk_size, MonotonicMs& t) {
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::ConfigRecovery;
  manifest.total_len = static_cast<std::uint16_t>(object.size);
  sha256(object.view(), manifest.object_hash);
  Status last = rig.journal->note_recovery_manifest(manifest, t);
  for (std::uint16_t offset = 0; offset < object.size && last.ok();
       offset = static_cast<std::uint16_t>(offset + chunk_size)) {
    autonomy::ObjectChunkPayload chunk{};
    chunk.object_hash = manifest.object_hash;
    chunk.offset = offset;
    chunk.data_size = static_cast<std::uint16_t>(
        object.size - offset < chunk_size ? object.size - offset : chunk_size);
    std::memcpy(chunk.data.data(), object.bytes.data() + offset, chunk.data_size);
    t += 10;
    last = rig.journal->note_recovery_chunk(chunk, t);
  }
  return last;
}

// R01: both journal slots lost -> quarantine -> a signed StoreRecover object
// (attest=reprovision) restores intake and a normal permit applies after.
void test_r01_quarantine_store_recovery() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);

  // Total loss: both slot images unreadable -> next boot quarantines.
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms + 100);
  CHECK(rig.journal->quarantined());

  // Ordinary intake stays closed (quarantine -> InvalidState); the
  // recovery lane does not.
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  manifest.total_len = 64;
  manifest.object_hash[0] = 1;
  CHECK(rig.journal->note_object_manifest(manifest, now_ms + 110).code ==
        StatusCode::InvalidState);

  // No verifiable record survives: attest=adopt must fail closed — only an
  // explicit re-provisioning attestation mints the new generation.
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestAdopt, 500, 0, 1,
                 rig.config.authority_generation, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms + 130, verdict).code ==
        StatusCode::RecoveryRequired);
  CHECK(rig.journal->quarantined());

  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestReprovision, 500, 0, 2,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 140, verdict));
  CHECK(verdict.reason == ConfigReason::Ok);
  CHECK(!rig.journal->quarantined());
  CHECK(!rig.journal->uncertain());
  // Both slots now carry the same verifiable record under generation 500.
  CHECK(std::memcmp(rig.storage.slots_[0].data(), rig.storage.slots_[1].data(),
                    64) == 0);

  // Intake is re-established: a bound permit flows through the normal path.
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 200,
                        rig.journal->decision_revision(),
                        rig.journal->active_snapshot(), verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// R02: one-slot bitrot -> uncertain -> StoreRecover (attest=adopt) heals the
// journal; the surviving record is adopted under the new store generation.
void test_r02_uncertain_store_recovery() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  const std::uint64_t proven_revision = rig.journal->decision_revision();

  // Bitrot in one slot only -> boot lands uncertain.
  rig.storage.corrupt(1, 128);
  rig.boot(now_ms + 100);
  CHECK(rig.journal->uncertain());
  CHECK(rig.journal->decision_revision() == proven_revision);  // survivor kept

  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestAdopt, 600, 0, 3,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 150, verdict));
  CHECK(verdict.reason == ConfigReason::Ok);
  CHECK(!rig.journal->uncertain());
  // The proven revision floor carried over — pre-loss permits cannot replay.
  CHECK(rig.journal->decision_revision() >= proven_revision);
}

// R03: signature/binding/scope rejections on the recovery lane.
void test_r03_recovery_rejections() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms);
  CHECK(rig.journal->quarantined());
  ConfigVerdict verdict{};

  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestReprovision, 500, 0, 4,
                 rig.config.authority_generation, object);

  // Tampered signature byte -> unverified, denied.
  ByteBuffer<kConfigPermitObjectMax> bad = object;
  bad.bytes[bad.size - 1] ^= 0xFFU;
  CHECK(rig.journal->submit_recovery(bad.view(), now_ms + 10, verdict).code ==
        StatusCode::AuthenticationFailed);
  CHECK(verdict.reason == ConfigReason::AuthorityDenied);
  CHECK(rig.journal->quarantined());

  // Tampered AAD scope byte -> unverified, denied.
  bad = object;
  bad.bytes[kRecoveryAadSize - 1] ^= 0xFFU;
  CHECK(rig.journal->submit_recovery(bad.view(), now_ms + 20, verdict).code ==
        StatusCode::AuthenticationFailed);

  // A permit-shaped envelope through the recovery lane: kind-3 bytes are
  // never reinterpreted as recovery — the aad domain differs.
  const ConfigField patch[] = {sdk_u8(1, 2)};
  CHECK(!rig.journal->submit_permit(object.view(), now_ms + 30, true, verdict)
             .ok());

  // Signed under a generation the journal does not pin -> scope denied.
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestReprovision, 500, 0, 5,
                 rig.config.authority_generation + 7, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms + 40, verdict).code ==
        StatusCode::AuthorizationFailed);
  CHECK(verdict.reason == ConfigReason::AuthorityDenied);
  CHECK(rig.journal->quarantined());
  static_cast<void>(patch);
}

// R04: replay protection — same op+same digest is idempotent, same op+
// different digest is conflict, a generation at/below the floor is refused.
void test_r04_recovery_replay_floor() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms);
  ConfigVerdict verdict{};

  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestReprovision, 500, 0, 6,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 10, verdict));
  // Same operation id + same bytes -> recorded verdict, never re-applied.
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 20, verdict));
  CHECK(verdict.reason == ConfigReason::Ok);

  // Same operation id + different content -> CONFLICT.
  ByteBuffer<kConfigPermitObjectMax> conflicting{};
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestReprovision, 700, 0, 6,
                 rig.config.authority_generation, conflicting);
  // Same opid tag (6) produces the same operation id with different content.
  CHECK(rig.journal->submit_recovery(conflicting.view(), now_ms + 30, verdict)
            .code == StatusCode::Conflict);

  // A fresh recovery naming the consumed generation or below is refused:
  // the proven floor moved to 500.
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestReprovision, 500, 0, 7,
                 rig.config.authority_generation, object);
  rig.storage.fill(0, 0xEE);  // re-impair so class admission passes
  rig.boot(now_ms + 40);
  // The rebuilt journal proves the 500-generation record; a replay at 500
  // sits at/below the floor the journal already consumed.
  CHECK(rig.journal->uncertain());
  CHECK(rig.journal->submit_recovery(object.view(), now_ms + 50, verdict)
            .code == StatusCode::InvalidArgument);
}

// R05: the 03-signing trust update — a countersigned AuthorityGeneration
// object durably installs the new pin; permits under it apply only after.
void test_r05_trust_update() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->authority_generation() == 1);

  // A permit signed under the new generation is rejected BEFORE the trust
  // update — the journal still pins generation 1.
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = rig.config.config_namespace;
  query.schema = rig.config.schema;
  query.client_nonce = {1, 1, 1, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(rig.journal->handle_challenge_query(query, now_ms + 10, encoded));
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
  ConfigCommand command = last_command_;
  command.operation_id = {0xD0, 1, 2, 3, 4, 5, 6, 7,
                          8,    9, 10, 11, 12, 13, 14, 15};
  command.challenge_nonce = challenge.challenge_nonce;
  command.authority_generation = 3;  // signed under the NEW generation
  ByteBuffer<kConfigPermitObjectMax> early_permit{};
  build_permit(signer_, command, early_permit);
  CHECK(rig.journal->submit_permit(early_permit.view(), now_ms + 20, true, verdict)
            .code == StatusCode::AuthorizationFailed);
  CHECK(verdict.reason == ConfigReason::AuthorityDenied);

  // The countersigned trust update installs generation 3 durably.
  ByteBuffer<kConfigPermitObjectMax> update{};
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::AuthorityGeneration,
                 0, 0, 3, 8, rig.config.authority_generation, update);
  CHECK_OK(rig.journal->submit_recovery(update.view(), now_ms + 30, verdict));
  CHECK(verdict.reason == ConfigReason::Ok);
  CHECK(rig.journal->authority_generation() == 3);

  // The very permit that was rejected now applies under the new pin (a
  // fresh acceptance-budget window — the trust update consumed one).
  now_ms += 61000;
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  CHECK_OK(config_patch_apply(rig.journal->active_snapshot(), patch2, 1, next, changed));
  Digest256 next_hash{};
  CHECK_OK(config_snapshot_hash(1, 1, next.view(), next_hash));
  endpoint::ControlChallengeQuery query2 = query;
  query2.client_nonce = {2, 2, 2, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14};
  CHECK_OK(rig.journal->handle_challenge_query(query2, now_ms, encoded));
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
  command.operation_id = {0xD1, 1, 2, 3, 4, 5, 6, 7,
                          8,    9, 10, 11, 12, 13, 14, 15};
  command.challenge_nonce = challenge.challenge_nonce;
  command.expected_revision = rig.journal->decision_revision();
  command.next_revision = command.expected_revision + 1;
  command.base_snapshot_hash = challenge.active_hash;
  command.next_snapshot_hash = next_hash;
  command.fields[0] = patch2[0];
  command.field_count = 1;
  ByteBuffer<kConfigPermitObjectMax> new_permit{};
  build_permit(signer_, command, new_permit);
  CHECK_OK(rig.journal->submit_permit(new_permit.view(), now_ms + 10, true, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);

  // The pin is durable: a reboot re-adopts generation 3, not the
  // build-time 1 — and permits under the OLD generation are now stale.
  now_ms += 200;
  rig.boot(now_ms);
  CHECK(rig.journal->authority_generation() == 3);
  CHECK(!rig.journal->quarantined() && !rig.journal->uncertain());
  drain(rig, now_ms);  // finish the boot-time restore re-assert
  ByteBuffer<kConfigPermitObjectMax> old_permit{};
  command.operation_id = {0xD2, 1, 2, 3, 4, 5, 6, 7,
                          8,    9, 10, 11, 12, 13, 14, 15};
  command.authority_generation = 1;
  build_permit(signer_, command, old_permit);
  CHECK(rig.journal->submit_permit(old_permit.view(), now_ms + 10, true, verdict)
            .code == StatusCode::AuthorizationFailed);
}

// R06: trust-update admission rules — the class only runs on a proven,
// idle journal and only ever advances the generation.
void test_r06_trust_update_admission() {
  // On an IMPAIRED journal the countersign is refused: the journal must
  // re-prove its store via StoreRecover first.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    rig.storage.fill(0, 0xEE);
    rig.storage.fill(1, 0xEE);
    rig.boot(now_ms);
    CHECK(rig.journal->quarantined());
    ByteBuffer<kConfigPermitObjectMax> update{};
    build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::AuthorityGeneration,
                   0, 0, 3, 9, rig.config.authority_generation, update);
    ConfigVerdict verdict{};
    CHECK(rig.journal->submit_recovery(update.view(), now_ms + 10, verdict).code ==
          StatusCode::InvalidState);
    CHECK(verdict.reason == ConfigReason::RecoveryRequired);
    CHECK(rig.journal->authority_generation() == 1);
  }

  // On a proven journal, a non-advancing transition is stale/replay — and
  // a StoreRecover on a proven journal is out of place.
  {
    TargetRig rig;
    MonotonicMs now_ms = 1000;
    CHECK_OK(rig.journal->initialize(now_ms));
    ConfigVerdict verdict{};
    ByteBuffer<kConfigPermitObjectMax> update{};
    build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::AuthorityGeneration,
                   0, 0, 1, 10, rig.config.authority_generation, update);
    CHECK(rig.journal->submit_recovery(update.view(), now_ms + 10, verdict).code ==
          StatusCode::InvalidArgument);
    build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                   endpoint::kRcr1AttestReprovision, 500, 0, 11,
                   rig.config.authority_generation, update);
    CHECK(rig.journal->submit_recovery(update.view(), now_ms + 20, verdict).code ==
          StatusCode::InvalidState);
    CHECK(verdict.reason == ConfigReason::Unsupported);
    CHECK(rig.journal->authority_generation() == 1);
  }
}

// R07: the kind-4 reassembly lane stays open impaired; kind-3 stays shut.
void test_r07_recovery_lane_reassembly() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms);
  CHECK(rig.journal->quarantined());

  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::ConfigRecoveryClass::StoreRecover,
                 endpoint::kRcr1AttestReprovision, 500, 0, 12,
                 rig.config.authority_generation, object);
  CHECK_OK(send_recovery_chunks(rig, object, 32, now_ms));
  CHECK(!rig.journal->quarantined());

  // Kind-4 manifest discipline on a fresh impaired journal: wrong-kind and
  // oversized manifests reject; digest-mismatched content fails integrity.
  TargetRig rig2;
  MonotonicMs t = 5000;
  rig2.storage.fill(0, 0xEE);
  rig2.storage.fill(1, 0xEE);
  rig2.boot(t);
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;  // wrong lane kind
  manifest.total_len = 64;
  manifest.object_hash[0] = 1;
  CHECK(rig2.journal->note_recovery_manifest(manifest, t).code ==
        StatusCode::ProtocolError);
  manifest.kind = autonomy::ControlObjectKind::ConfigRecovery;
  manifest.total_len = kConfigPermitObjectMax + 1;
  CHECK(rig2.journal->note_recovery_manifest(manifest, t).code ==
        StatusCode::ProtocolError);

  // Honest manifest + corrupted bytes: the digest check rejects before
  // submit_recovery ever sees the object.
  manifest.total_len = static_cast<std::uint16_t>(object.size);
  sha256(object.view(), manifest.object_hash);
  CHECK_OK(rig2.journal->note_recovery_manifest(manifest, t));
  autonomy::ObjectChunkPayload chunk{};
  chunk.object_hash = manifest.object_hash;
  chunk.offset = 0;
  chunk.data_size = 64;
  std::memcpy(chunk.data.data(), object.bytes.data(), 64);
  chunk.data[10] ^= 0xFFU;  // corrupted under an honest manifest
  t += 10;
  CHECK_OK(rig2.journal->note_recovery_chunk(chunk, t));
  chunk.offset = 64;
  chunk.data_size = static_cast<std::uint16_t>(object.size - 64);
  std::memcpy(chunk.data.data(), object.bytes.data() + 64, chunk.data_size);
  t += 10;
  CHECK(rig2.journal->note_recovery_chunk(chunk, t).code ==
        StatusCode::IntegrityError);
  CHECK(rig2.journal->quarantined());

  // The kind-3 lane stays shut through all of it (quarantine -> InvalidState).
  CHECK(rig2.journal->note_object_manifest(manifest, t).code ==
        StatusCode::InvalidState);
}

// R08: the issuer mints a recovery object end-to-end — commit order,
// kind-tagged outbox, signed_object lane selection.
void test_r08_issuer_issue_recovery() {
  IssuerRig rig;
  rig.boot();
  CHECK_OK(rig.issuer.initialize());
  const MonotonicMs now_ms = 1000;

  IssuedRecovery out{};
  CHECK_OK(rig.issuer.issue_recovery(
      kTarget, 1, 1, endpoint::ConfigRecoveryClass::StoreRecover,
      endpoint::kRcr1AttestReprovision, 500, 0, out));
  CHECK(out.issued);
  CHECK(rig.ledger.state().applied_sequence == 1);
  // The outbox entry is kind-tagged RCR1 — signed_object reports the lane.
  std::uint8_t kind = 0xFF;
  ByteBuffer<kConfigPermitObjectMax> object{};
  CHECK_OK(rig.issuer.signed_object(out.slot, kind, object));
  CHECK(kind == kOutboxKindRecovery);
  CHECK(object.size == kRecoveryAadSize + endpoint::kRcr1Size + kPermitTagSize);

  // The signed object delivers recovery to a quarantined target journal.
  TargetRig target;
  target.storage.fill(0, 0xEE);
  target.storage.fill(1, 0xEE);
  target.boot(now_ms + 10);
  ConfigVerdict verdict{};
  CHECK_OK(target.journal->submit_recovery(object.view(), now_ms + 20, verdict));
  CHECK(verdict.reason == ConfigReason::Ok);
  CHECK(!target.journal->quarantined());

  // The trust-update class mints through the same path.
  IssuedRecovery trust{};
  CHECK_OK(rig.issuer.issue_recovery(
      kTarget, 1, 1, endpoint::ConfigRecoveryClass::AuthorityGeneration,
      0, 0, 3, trust));
  CHECK(trust.issued);
  CHECK(rig.ledger.state().applied_sequence == 2);
  endpoint::ConfigRecoveryCommand decoded{};
  ByteBuffer<kConfigPermitObjectMax> trust_object{};
  CHECK_OK(rig.issuer.signed_object(trust.slot, kind, trust_object));
  const ByteView canonical{trust_object.bytes.data() + kRecoveryAadSize,
                           endpoint::kRcr1Size};
  CHECK_OK(endpoint::config_recovery_decode(canonical, decoded));
  CHECK(decoded.recovery_class == endpoint::ConfigRecoveryClass::AuthorityGeneration);
  CHECK(decoded.new_authority_generation == 3);
  CHECK(decoded.authority_sequence == 2);

  // A recovery entry survives an issuer reboot: resume_pending re-decodes
  // the RCR1 kind and the signed object retransmits byte-identically.
  IssuerRig rig2;
  rig2.boot();
  CHECK_OK(rig2.issuer.initialize());
  rig2.signer.fail_next = true;
  IssuedRecovery pending{};
  CHECK(rig2.issuer.issue_recovery(
                kTarget, 1, 1, endpoint::ConfigRecoveryClass::StoreRecover,
                endpoint::kRcr1AttestReprovision, 500, 0, pending)
            .code == StatusCode::InternalError);
  ConfigIssuer resumed(rig2.config, rig2.ledger, rig2.outbox, rig2.signer,
                       rig2.entropy);
  CHECK_OK(resumed.initialize());
  CHECK(resumed.signed_count() == 1);
  ByteBuffer<kConfigPermitObjectMax> resumed_object{};
  CHECK_OK(resumed.signed_object(pending.slot, kind, resumed_object));
  CHECK(kind == kOutboxKindRecovery);
  CHECK(resumed_object.size > 0);
}

}  // namespace

int main() {
  // Schema / TLV / hash layer.
  test_tlv_layer();
  test_snapshot_hash_domain();
  test_patch_merge();
  test_namespace_table();
  test_rate_limiter();
  test_sdk_field_rules();
  // C01-C14.
  test_c01_basic_flow();
  test_c02_cas_conflict();
  test_c03_sequence_holes();
  test_c04_verify_intake_limit();
  test_c04_verify_intake_shared();
  test_c04_authorization();
  test_c05_challenge_bounds();
  test_c06_fault_injection_decided();
  test_c07_apply_window_power_loss();
  test_c08_active_continuation();
  test_c09_slot_corruption();
  test_c10_reassembly();
  test_c11_schema_boundaries();
  test_c12_maintenance_boundary();
  test_c13_result_records();
  test_c14_stale_and_busy();
  // Issuer side.
  test_issuer_commit_order();
  test_issuer_no_change_and_budget();
  test_issuer_resume_after_power_loss();
  test_issuer_outbox_bounds();
  // Provider apply/verify failure -> restore semantics.
  test_apply_failure_restores();
  test_storage_contract();
  // Recovery/floor/deferred-intent regressions.
  test_floor_advance_on_commit();
  test_active_survivor_recover();
  test_boot_terminal_persist_retry();
  test_challenge_churn();
  test_deferred_intent();
  test_storage_failure_refunds_budget();
  test_uncertain_intake_refused();
  test_floor_corrupt_structural();
  test_fresh_vs_impaired();
  test_revision_pair_contract();
  test_manifest_length_conflict();
  test_status_result_expired();
  test_impaired_outbox_slot();
  test_issuer_remint_sequence();
  test_outbox_tombstone_size();
  // Issue #51: dedicated kind-4 recovery lane + trust update.
  test_r01_quarantine_store_recovery();
  test_r02_uncertain_store_recovery();
  test_r03_recovery_rejections();
  test_r04_recovery_replay_floor();
  test_r05_trust_update();
  test_r06_trust_update_admission();
  test_r07_recovery_lane_reassembly();
  test_r08_issuer_issue_recovery();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom remote-config tests passed");
  return 0;
}
