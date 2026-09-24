// Small Remote Config portable-core tests: the C01-C14 acceptance cases
// (06-acceptance.md), the RLF1 floor reservation rules, the R-series
// recovery-lane cases, the dual-slot journal power-loss matrix,
// reassembly bounds and the schema/TLV layer — all through the real
// code paths with storage/provider/verifier fakes. (Issuance lives in
// the Rust host; its commit order is covered by the host test suite.)

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/authority.hpp"
#include "routeloom/config.hpp"
#include "routeloom/config_cose.hpp"
#include "routeloom/config_dev.hpp"
#include "routeloom/config_wire.hpp"
#include "routeloom/crc32.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/trust_manifest.hpp"
#include "routeloom/trust_store.hpp"
#include "routeloom/trust_view.hpp"
#include "routeloom/wire.hpp"
#include "test_ledger.hpp"
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

// One 136-byte RLF1 floor image with loss/corruption injection. Reads fail
// until provisioned — a missing floor is never an empty one.
class FakeFloorStore final : public SecurityFloorStorage {
 public:
  Status read(const MutableByteView target) noexcept override {
    if (target.size != kSecurityFloorBlobBytes) {
      return Status::error(StatusCode::InvalidArgument, "bad floor read");
    }
    if (read_error) {
      return Status::error(StatusCode::StorageFailure, "injected floor read error");
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
    ++write_calls;
    if (fail_writes) {
      return Status::error(StatusCode::StorageFailure, "injected floor write error");
    }
    if (torn_write) {
      // The write faults after landing a torn prefix with one flipped
      // byte — the readback must catch it and the cache must not follow.
      // (The flip matters: a clean prefix of an advance that only moves
      // J/R could otherwise be byte-identical to the old image.)
      const std::size_t landed = data.size / 2;
      std::memcpy(blob_.data(), data.data, landed);
      blob_[10] ^= 0xFFU;
      provisioned = true;
      return Status::error(StatusCode::StorageFailure, "torn floor write");
    }
    std::memcpy(blob_.data(), data.data, data.size);
    provisioned = true;
    return Status::success();
  }
  void wipe() {
    blob_.fill(0);
    provisioned = false;
  }
  void corrupt(const std::size_t offset) { blob_[offset] ^= 0xFFU; }

  std::array<std::uint8_t, kSecurityFloorBlobBytes> blob_{};
  bool provisioned{false};
  bool read_error{false};
  bool fail_writes{false};
  bool torn_write{false};
  std::size_t write_calls{0};
};

// Seed `storage` with a floor for (network, target) carrying one namespace
// entry at (J, R). Aborts on failure — the fake cannot fail unprompted.
void seed_floor(FakeFloorStore& storage, const std::uint64_t network,
                const std::uint64_t target, const std::uint16_t ns,
                const std::uint16_t schema, const std::uint32_t j,
                const std::uint64_t r, const std::uint8_t flags = 0) {
  SecurityFloorState state{};
  state.network = network;
  state.target = target;
  state.namespace_count = 1;
  state.flags = flags;
  state.entries[0].config_namespace = ns;
  state.entries[0].schema = schema;
  state.entries[0].store_floor = j;
  state.entries[0].decision_floor = r;
  SecurityFloorStore floor(storage);
  CHECK_OK(floor.provision_seed(state));
}

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

// The test recovery envelope: recovery_aad(46B) || canonical RCR2 || tag(16B)
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

// Test-only envelope minter (the device carries no issuance path — the
// production issuer is the Rust host). Plain struct, no interface.
class FakePermitSigner {
 public:
  Status sign(const ConfigCommand& command, const ByteView canonical,
              ByteBuffer<kConfigPermitObjectMax>& permit) noexcept {
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
  Status sign_recovery(const endpoint::ConfigRecoveryIntent& intent,
                       const ByteView canonical,
                       ByteBuffer<kConfigPermitObjectMax>& permit) noexcept {
    ByteBuffer<kRecoveryAadSize> aad{};
    Status status = config_recovery_aad(intent.network, intent.target,
                                        intent.config_namespace, aad);
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
  // The kind-4 recovery envelope: recovery-domain aad || RCR2(112..624) ||
  // tag16. Same contract as verify_permit; the test profile resolves
  // every generation, so the countersign resolvability check always passes.
  Status verify_recovery(const ConfigPermitContext& context, const ByteView object,
                         endpoint::EncodedRecoveryIntent& payload,
                         bool& verified) noexcept override {
    verified = false;
    ++verify_calls;
    if (object.size < kRecoveryAadSize + endpoint::kRcr2HeaderSize + kPermitTagSize ||
        object.size > kConfigPermitObjectMax) {
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
    const ByteView canonical{object.data + kRecoveryAadSize,
                             object.size - kRecoveryAadSize - kPermitTagSize};
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
  endpoint::ConfigRecoveryIntent decoded_recovery_{};
  std::size_t verify_calls{0};
};

// Desired-state provider fake: validate/prepare are side-effect-free,
// apply/restore complete after `polls_to_complete` polls, then commit the
// pending snapshot to the durable ("active") image and — unless frozen —
// to the live-effects image. read_active returns the durable bytes after
// proving the live image still matches them (readback verification);
// legacy tests that seed only `active_` skip the live check.
class FakeProvider final : public ConfigProvider {
 public:
  // Seed both images at once: the provider's durable and live state agree.
  void seed(const ByteView image) noexcept {
    active_.size = image.size;
    std::memcpy(active_.bytes.data(), image.data, image.size);
    live_ = active_;
    live_explicit_ = true;
  }
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
  Status validate_recovery(const std::uint16_t, const std::uint16_t,
                           const ByteView) noexcept override {
    ++validate_recovery_calls;
    return validate_recovery_result;
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
    if (!freeze_live) live_ = pending_;  // a frozen live image stays stale
    live_explicit_ = true;
    outcome = Status::success();
    return Status::success();
  }
  Status read_active(const std::uint16_t, const MutableByteView target,
                     std::size_t& out_size) noexcept override {
    if (fail_reads > 0) {
      --fail_reads;
      return Status::error(StatusCode::StorageFailure, "readback failed");
    }
    if (corrupt_reads > 0) {
      --corrupt_reads;
      out_size = 3;
      std::memcpy(target.data, "bad", 3);
      return Status::success();
    }
    if (live_explicit_ && (live_.size != active_.size ||
                           std::memcmp(live_.bytes.data(), active_.bytes.data(),
                                       active_.size) != 0)) {
      return Status::error(StatusCode::IntegrityError, "live image diverged");
    }
    if (active_.size > target.size) {
      return Status::error(StatusCode::NoCapacity, "read buffer small");
    }
    std::memcpy(target.data, active_.bytes.data(), active_.size);
    out_size = active_.size;
    return Status::success();
  }
  ByteBuffer<endpoint::kConfigSnapshotMax> active_{};
  ByteBuffer<endpoint::kConfigSnapshotMax> live_{};
  bool live_explicit_{false};
  ByteBuffer<endpoint::kConfigSnapshotMax> pending_{};
  int polls_to_complete{1};
  int polls_left_{0};
  std::uint64_t token_id_{0};
  Status validate_result = Status::success();
  Status prepare_result = Status::success();
  Status validate_recovery_result = Status::success();
  Status apply_result = Status::success();
  Status restore_result = Status::success();
  int fail_polls{0};
  int fail_reads{0};
  bool freeze_live{false};
  bool partial_apply{false};
  int corrupt_reads{0};
  int validate_calls{0}, prepare_calls{0}, apply_calls{0}, restore_calls{0};
  int validate_recovery_calls{0};
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

// Test-only dev-authority key (16 B). T04 signs with the PRODUCTION dev
// envelope helpers and verifies through the REAL DevConfigAuthorityVerifier
// (§9.1: security acceptance runs the real verifier, never verified=true).
constexpr std::uint8_t kDevKeyBytes[] = {
    't', '0', '4', '-', 'd', 'e', 'v', '-', 'k', 'e', 'y', '-', '0', '0', '0', '1'};

struct TargetRig {
  ConfigJournalConfig config{};
  FakeJournalStorage storage{};
  FakeFloorStore floor_storage{};
  FakeVerifier verifier{};
  DevConfigAuthorityVerifier dev_verifier{ByteView{kDevKeyBytes, sizeof(kDevKeyBytes)}};
  CoseEsp256AuthorityVerifier cose_verifier{};
  CountingEntropy entropy{};
  ConfigRateLimiter rate{};
  FakeProvider provider{};
  FakeMaintenanceGate gate{};
  PermissiveValidator validator{};
  std::unique_ptr<SecurityFloorStore> floor{};
  std::unique_ptr<ConfigJournal> journal{};

  explicit TargetRig(const std::uint64_t boot = kBoot, const bool with_gate = true,
                     const bool with_dev = false, const bool with_cose = false)
      : gate_installed_(with_gate),
        dev_installed_(with_dev),
        cose_installed_(with_cose) {
    config.network = kNet;
    config.target = kTarget;
    config.config_namespace = endpoint::kConfigNamespaceSdk;
    config.schema = 1;
    config.boot_incarnation = boot;
    config.authorized_issuer = kAuthority;
    config.authority_generation = 1;
    config.challenge_valid_ms = kConfigChallengeMaxMs;
    // A fresh deployment ships a provisioned floor at J=R=0; tests that
    // need an impaired floor wipe or corrupt it after construction.
    seed_floor(floor_storage, config.network, config.target,
               config.config_namespace, config.schema, 0, 0);
    floor = std::make_unique<SecurityFloorStore>(floor_storage);
    CHECK_OK(floor->initialize());
    ConfigAuthorityVerifier& active_verifier = select_verifier(with_dev, with_cose);
    journal = std::make_unique<ConfigJournal>(
        config, storage, *floor, active_verifier, entropy, rate, &provider, nullptr,
        with_gate ? &gate : nullptr);
  }
  void boot(const MonotonicMs now_ms) {
    // A reboot re-reads the floor from storage (fresh cache, same bytes);
    // when the floor is gone the journal init below fails the same way.
    floor = std::make_unique<SecurityFloorStore>(floor_storage);
    floor_status_ = floor->initialize();
    ConfigAuthorityVerifier& active_verifier =
        select_verifier(dev_installed_, cose_installed_);
    journal = std::make_unique<ConfigJournal>(
        config, storage, *floor, active_verifier, entropy, rate, &provider, nullptr,
        gate_installed_ ? &gate : nullptr);
    boot_status_ = journal->initialize(now_ms);
  }
  // Current floors for the rig's namespace (aborts when unreadable).
  std::uint32_t floor_j() {
    SecurityFloorState state{};
    CHECK_OK(floor->read(state));
    const SecurityFloorEntry* entry =
        SecurityFloorStore::entry_for(state, config.config_namespace);
    CHECK(entry != nullptr);
    return entry->store_floor;
  }
  std::uint64_t floor_r() {
    SecurityFloorState state{};
    CHECK_OK(floor->read(state));
    const SecurityFloorEntry* entry =
        SecurityFloorStore::entry_for(state, config.config_namespace);
    CHECK(entry != nullptr);
    return entry->decision_floor;
  }
  bool gate_installed_{true};
  bool dev_installed_{false};
  bool cose_installed_{false};

 private:
  ConfigAuthorityVerifier& select_verifier(const bool with_dev, const bool with_cose) {
    if (with_cose) return cose_verifier;
    if (with_dev) return dev_verifier;
    return verifier;
  }

 public:
  Status boot_status_ = Status::success();
  Status floor_status_ = Status::success();
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

// Build + encode + sign an RCR2 recovery object bound to `rig`'s identity.
// `hash_basis` is hashed into snapshot_hash — the baseline itself for
// Reprovision, the expected survivor for AdoptKnown (which carries no
// bytes); pass anything else to forge a hash mismatch.
// `authority_generation` is the generation the INTENT claims — the journal
// only accepts the one it currently pins.
void build_recovery(FakePermitSigner& signer, const TargetRig& rig,
                    const std::uint8_t mode,
                    const std::uint32_t new_store_generation,
                    const std::uint64_t new_revision,
                    const ByteView hash_basis,
                    const ByteView baseline,
                    const std::uint8_t opid_tag,
                    const std::uint32_t authority_generation,
                    ByteBuffer<kConfigPermitObjectMax>& object,
                    endpoint::ConfigRecoveryIntent* intent_out = nullptr) {
  endpoint::ConfigRecoveryIntent intent{};
  intent.mode = mode;
  intent.config_namespace = rig.config.config_namespace;
  intent.schema = rig.config.schema;
  intent.network = rig.config.network;
  intent.target = rig.config.target;
  intent.authority = rig.config.authorized_issuer;
  intent.authority_generation = authority_generation;
  intent.authority_sequence = 90 + opid_tag;
  intent.operation_id = {0xC0, opid_tag, 2, 3, 4, 5, 6, 7,
                         8,    9,        10, 11, 12, 13, 14, 15};
  intent.new_store_generation = new_store_generation;
  intent.new_revision = new_revision;
  CHECK_OK(config_snapshot_hash(rig.config.config_namespace, rig.config.schema,
                                hash_basis, intent.snapshot_hash));
  if (mode == endpoint::kRcr2ModeReprovision) {
    intent.baseline.size = baseline.size;
    if (baseline.size > 0) {
      std::memcpy(intent.baseline.bytes.data(), baseline.data, baseline.size);
    }
  }
  if (intent_out != nullptr) *intent_out = intent;
  endpoint::EncodedRecoveryIntent canonical{};
  CHECK_OK(endpoint::config_recovery_encode(intent, canonical));
  CHECK_OK(signer.sign_recovery(intent, canonical.view(), object));
}

// Encode SDK fields into canonical snapshot bytes for recovery baselines.
ByteBuffer<endpoint::kConfigSnapshotMax> snapshot_of(const ConfigField* fields,
                                                     const std::uint16_t count) {
  ByteBuffer<endpoint::kConfigSnapshotMax> out{};
  CHECK_OK(config_tlv_encode(fields, count, out));
  return out;
}

// Build + encode + sign an RCR2 object with the PRODUCTION dev-envelope
// helpers (same shape as build_recovery, real HMAC). T04's acceptance
// evidence runs through this, never through verified=true.
void build_dev_recovery(const TargetRig& rig, const std::uint8_t mode,
                        const std::uint32_t new_store_generation,
                        const std::uint64_t new_revision,
                        const ByteView hash_basis, const ByteView baseline,
                        const std::uint8_t opid_tag,
                        ByteBuffer<kConfigPermitObjectMax>& object) {
  endpoint::ConfigRecoveryIntent intent{};
  intent.mode = mode;
  intent.config_namespace = rig.config.config_namespace;
  intent.schema = rig.config.schema;
  intent.network = rig.config.network;
  intent.target = rig.config.target;
  intent.authority = rig.config.authorized_issuer;
  intent.authority_generation = rig.config.authority_generation;
  intent.authority_sequence = 90 + opid_tag;
  intent.operation_id = {0xD0, opid_tag, 2, 3, 4, 5, 6, 7,
                         8,    9,        10, 11, 12, 13, 14, 15};
  intent.new_store_generation = new_store_generation;
  intent.new_revision = new_revision;
  CHECK_OK(config_snapshot_hash(rig.config.config_namespace, rig.config.schema,
                                hash_basis, intent.snapshot_hash));
  if (mode == endpoint::kRcr2ModeReprovision) {
    intent.baseline.size = baseline.size;
    if (baseline.size > 0) {
      std::memcpy(intent.baseline.bytes.data(), baseline.data, baseline.size);
    }
  }
  endpoint::EncodedRecoveryIntent canonical{};
  CHECK_OK(endpoint::config_recovery_encode(intent, canonical));
  ByteBuffer<kConfigRecoveryAadSize> aad{};
  CHECK_OK(config_recovery_aad(intent.network, intent.target,
                               intent.config_namespace, aad));
  std::array<std::uint8_t, kConfigDevPermitTagSize> tag{};
  CHECK_OK(config_dev_recovery_tag(
      ByteView{kDevKeyBytes, sizeof(kDevKeyBytes)}, aad.view(),
      canonical.view(), tag));
  object.clear();
  CHECK(aad.size + canonical.size + tag.size() <= object.bytes.size());
  std::memcpy(object.bytes.data(), aad.bytes.data(), aad.size);
  std::memcpy(object.bytes.data() + aad.size, canonical.bytes.data(),
              canonical.size);
  std::memcpy(object.bytes.data() + aad.size + canonical.size, tag.data(),
              tag.size());
  object.size = aad.size + canonical.size + tag.size();
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
  FakeFloorStore floor_b{};
  seed_floor(floor_b, rig.config.network, rig.config.target,
             endpoint::kConfigNamespaceSdk, rig.config.schema, 0, 0);
  SecurityFloorStore floor_store_b(floor_b);
  CHECK_OK(floor_store_b.initialize());
  ConfigJournalConfig config_b = rig.config;
  config_b.config_namespace = endpoint::kConfigNamespaceSdk;  // any namespace
  ConfigJournal journal_b(config_b, storage_b, floor_store_b, rig.verifier,
                          rig.entropy, rig.rate, nullptr, nullptr, nullptr);
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

  // Drop the DECIDED seal write entirely: the floor still spent its J/R,
  // so a reboot cannot prove the surviving record is the latest one.
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
    CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
    CHECK(rig.journal->uncertain());
    CHECK(rig.journal->decision_revision() == 1);
  }

  // DECIDED committed, then the deferred APPLY_INTENT write is dropped in
  // poll: the committed DECIDED record is a known value, but the floor
  // spent one more J, so boot cannot prove whether APPLY_INTENT landed.
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
    CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
    CHECK(rig.journal->uncertain());
    // The known DECIDED record cannot be reported as an interruption
    // without resolving the missing floor generation.
    CHECK(rig.journal->decision_revision() == 2);
    CHECK(rig.journal->phase() == ConfigPhase::Decided);
    CHECK(rig.journal->active_revision() == 1);
    endpoint::ControlChallengeQuery query{};
    endpoint::EncodedServicePayload reply{};
    CHECK(!rig.journal->handle_challenge_query(query, now_ms, reply).ok());
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
    // Authorized recovery re-opens intake without regressing the floor —
    // it must name the floor's exact next (J 3 -> 4, R 1 -> 2). AdoptKnown
    // binds the surviving APPLY_INTENT's confirmed (prev) snapshot.
    ByteBuffer<kConfigPermitObjectMax> object{};
    build_recovery(signer_, rig, endpoint::kRcr2ModeAdoptKnown, 4, 2,
                   rig.journal->active_snapshot(), ByteView{}, 31,
                   rig.config.authority_generation, object);
    CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
    CHECK(rig.journal->uncertain());  // isolated until the readback proves it
    drain(rig, now_ms);
    CHECK(!rig.journal->uncertain());
    CHECK(rig.journal->phase() == ConfigPhase::Active);
    CHECK(rig.journal->decision_revision() == 2);
    CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 2,
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
    // Intake is closed; recovery requires the floor's exact next.
    ConfigVerdict v{};
    CHECK(rig.journal->submit_permit(last_permit_.view(), now_ms, true, v).code ==
          StatusCode::IntegrityError);
    const ConfigField baseline_fields[] = {sdk_u8(1, 1)};
    const auto baseline = snapshot_of(baseline_fields, 1);
    ByteBuffer<kConfigPermitObjectMax> object{};
    // A generation at/below the floor is refused: only the current
    // recovery can land.
    build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 3, 2,
                   baseline.view(), baseline.view(), 32,
                   rig.config.authority_generation, object);
    CHECK(rig.journal->submit_recovery(object.view(), now_ms, v).code ==
          StatusCode::InvalidArgument);
    // With no verifiable survivor, adopt-known must NOT fabricate a base
    // — the journal stays quarantined (04 §4.7: never an automatic
    // return to revision 0).
    build_recovery(signer_, rig, endpoint::kRcr2ModeAdoptKnown, 4, 2, ByteView{},
                   ByteView{}, 33, rig.config.authority_generation, object);
    CHECK(rig.journal->submit_recovery(object.view(), now_ms, v).code ==
          StatusCode::RecoveryRequired);
    CHECK(rig.journal->quarantined());
    // A generation that is not the floor's next is refused even in
    // reprovision mode — only the current recovery can land.
    build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 11, 2,
                   baseline.view(), baseline.view(), 34,
                   rig.config.authority_generation, object);
    CHECK(rig.journal->submit_recovery(object.view(), now_ms, v).code ==
          StatusCode::InvalidArgument);
    CHECK(rig.journal->quarantined());
    // Only an explicit reprovisioning baseline may establish the base.
    build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 4, 2,
                   baseline.view(), baseline.view(), 35,
                   rig.config.authority_generation, object);
    CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, v));
    drain(rig, now_ms);
    CHECK(!rig.journal->quarantined());
    CHECK(rig.journal->phase() == ConfigPhase::Active);
    CHECK(rig.journal->decision_revision() == 2);
  }
}

// --- Target-driven object intake -----------------------------------------------------
// Assembly lives in ConfigTarget now: these tests feed manifest/chunk frames
// through a real target bound to the rig's journal and observe the ObjectAck
// stream (Ok = dispatched, Failed = refused) plus the journal's own state.
// The journal's note_*_manifest gates are still asserted directly.

// Captures everything a ConfigTarget sends: ObjectAcks (intake) and Control
// replies (queries).
class AckPort final : public ConfigWirePort {
 public:
  Status config_send(const NodeId, const FrameType type, const ByteView payload,
                     const MonotonicMs) noexcept override {
    ++sent;
    if (type == FrameType::ObjectAck) {
      autonomy::ObjectAckPayload ack{};
      if (autonomy::object_ack_decode(payload, ack)) {
        ++acks;
        last_status = ack.status;
        last_received = ack.received_len;
      }
    }
    return Status::success();
  }
  int sent{0};
  int acks{0};
  autonomy::ObjectAckStatus last_status{autonomy::ObjectAckStatus::Ok};
  std::uint16_t last_received{0};
};

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

void send_manifest(ConfigTarget& target, const NodeId origin,
                   const autonomy::ControlObjectPayload& manifest,
                   const MonotonicMs now_ms) {
  autonomy::EncodedPayload encoded{};
  CHECK_OK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(origin,
                         object_frame(origin, FrameType::ControlObject,
                                      encoded.view()),
                         now_ms);
}

void send_chunk(ConfigTarget& target, const NodeId origin,
                const autonomy::ObjectChunkPayload& chunk,
                const MonotonicMs now_ms) {
  autonomy::EncodedPayload encoded{};
  CHECK_OK(autonomy::object_chunk_encode(chunk, encoded));
  target.on_config_frame(origin,
                         object_frame(origin, FrameType::ObjectChunk,
                                      encoded.view()),
                         now_ms);
}

// Deliver `object` as `kind` in chunk_size pieces; returns the terminal ack.
// `hash_override` names a different manifest digest (corruption tests).
autonomy::ObjectAckStatus deliver_object(
    ConfigTarget& target, AckPort& port, const NodeId origin,
    const autonomy::ControlObjectKind kind, const ByteView object,
    const std::uint16_t chunk_size, MonotonicMs& t,
    const ByteView hash_override = ByteView{}) {
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = kind;
  manifest.total_len = static_cast<std::uint16_t>(object.size);
  if (hash_override.size == manifest.object_hash.size()) {
    std::memcpy(manifest.object_hash.data(), hash_override.data,
                hash_override.size);
  } else {
    sha256(object, manifest.object_hash);
  }
  send_manifest(target, origin, manifest, t);
  if (port.last_status == autonomy::ObjectAckStatus::Failed) {
    return port.last_status;
  }
  for (std::uint16_t offset = 0; offset < object.size;
       offset = static_cast<std::uint16_t>(offset + chunk_size)) {
    autonomy::ObjectChunkPayload chunk{};
    std::memcpy(chunk.object_hash.data(), manifest.object_hash.data(),
                manifest.object_hash.size());
    chunk.offset = offset;
    chunk.data_size = static_cast<std::uint16_t>(object.size - offset < chunk_size
                                                     ? object.size - offset
                                                     : chunk_size);
    std::memcpy(chunk.data.data(), object.data + offset, chunk.data_size);
    t += 10;
    send_chunk(target, origin, chunk, t);
    if (port.last_status == autonomy::ObjectAckStatus::Failed) {
      return port.last_status;
    }
  }
  return port.last_status;
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
  AckPort port;
  ConfigTarget target(port, rig.rate);
  CHECK_OK(target.add_journal(1, *rig.journal));

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
    CHECK(deliver_object(target, port, kAuthority,
                         autonomy::ControlObjectKind::ConfigPermit,
                         signed_permit.view(), 64,
                         now_ms) == autonomy::ObjectAckStatus::Ok);
    drain(rig, now_ms);
    CHECK(rig.journal->phase() == ConfigPhase::Active);
    CHECK(rig.journal->decision_revision() == 2);
  }

  // Corrupted object bytes fail the manifest digest — never applied.
  {
    TargetRig rig3;
    MonotonicMs t = 5000;
    CHECK_OK(rig3.journal->initialize(t));
    AckPort port3;
    ConfigTarget target3(port3, rig3.rate);
    CHECK_OK(target3.add_journal(1, *rig3.journal));
    ByteBuffer<kConfigPermitObjectMax> bad = permit;
    bad.bytes[50] ^= 0xFFU;
    // Honest manifest (digest of the ORIGINAL bytes) + corrupted content:
    // the assembly digest check must reject the object before submit.
    Digest256 honest{};
    sha256(permit.view(), honest);
    CHECK(deliver_object(target3, port3, kAuthority,
                         autonomy::ControlObjectKind::ConfigPermit, bad.view(),
                         64, t,
                         ByteView{honest.data(),
                                  honest.size()}) == autonomy::ObjectAckStatus::Failed);
    CHECK(!target3.object_active());
    CHECK(rig3.journal->decision_revision() == 0);
  }

  // Duplicate offset with different bytes poisons the assembly.
  {
    TargetRig rig3;
    MonotonicMs t = 5000;
    CHECK_OK(rig3.journal->initialize(t));
    AckPort port3;
    ConfigTarget target3(port3, rig3.rate);
    CHECK_OK(target3.add_journal(1, *rig3.journal));
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    manifest.total_len = static_cast<std::uint16_t>(permit.size);
    sha256(permit.view(), manifest.object_hash);
    send_manifest(target3, kAuthority, manifest, t);
    CHECK(port3.last_status == autonomy::ObjectAckStatus::Incomplete);
    autonomy::ObjectChunkPayload chunk{};
    chunk.object_hash = manifest.object_hash;
    chunk.offset = 0;
    chunk.data_size = 32;
    std::memcpy(chunk.data.data(), permit.bytes.data(), 32);
    send_chunk(target3, kAuthority, chunk, t);
    CHECK(port3.last_status == autonomy::ObjectAckStatus::Incomplete);
    chunk.data[10] ^= 0xFFU;  // same offset, different bytes
    send_chunk(target3, kAuthority, chunk, t + 10);
    CHECK(port3.last_status == autonomy::ObjectAckStatus::Failed);
    CHECK(!target3.object_active());
  }

  // Missing manifest -> chunk denied; the journal gate still refuses a
  // wrong kind and an oversized object directly.
  {
    TargetRig rig3;
    MonotonicMs t = 5000;
    CHECK_OK(rig3.journal->initialize(t));
    AckPort port3;
    ConfigTarget target3(port3, rig3.rate);
    CHECK_OK(target3.add_journal(1, *rig3.journal));
    autonomy::ObjectChunkPayload chunk{};
    send_chunk(target3, kAuthority, chunk, t);
    CHECK(target3.control_denied() == 1);
    CHECK(port3.acks == 0);  // denied, never acked
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

  // Reassembly timeout: a chunk arriving past 10 s fails the assembly.
  {
    TargetRig rig3;
    MonotonicMs t = 5000;
    CHECK_OK(rig3.journal->initialize(t));
    AckPort port3;
    ConfigTarget target3(port3, rig3.rate);
    CHECK_OK(target3.add_journal(1, *rig3.journal));
    autonomy::ControlObjectPayload manifest{};
    manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
    manifest.total_len = static_cast<std::uint16_t>(permit.size);
    sha256(permit.view(), manifest.object_hash);
    send_manifest(target3, kAuthority, manifest, t);
    autonomy::ObjectChunkPayload chunk{};
    chunk.object_hash = manifest.object_hash;
    chunk.offset = 0;
    chunk.data_size = 32;
    std::memcpy(chunk.data.data(), permit.bytes.data(), 32);
    send_chunk(target3, kAuthority, chunk, t + 10);
    CHECK(port3.last_status == autonomy::ObjectAckStatus::Incomplete);
    send_chunk(target3, kAuthority, chunk, t + kConfigReassemblyTimeoutMs + 1);
    CHECK(port3.last_status == autonomy::ObjectAckStatus::Failed);
    CHECK(!target3.object_active());
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
  FakeFloorStore floor_storage;
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
  seed_floor(floor_storage, config.network, config.target,
             config.config_namespace, config.schema, 0, 0);
  SecurityFloorStore floor(floor_storage);
  CHECK_OK(floor.initialize());
  ConfigJournal journal(config, storage, floor, verifier, entropy, rate,
                        &provider, nullptr, nullptr);
  MonotonicMs now_ms = 1000;
  CHECK_OK(journal.initialize(now_ms));
  // Invalid identities are refused up front.
  ConfigJournalConfig bad = config;
  bad.challenge_valid_ms = kConfigChallengeMaxMs + 1;
  ConfigJournal journal_bad(bad, storage, floor, verifier, entropy, rate,
                            &provider, nullptr, nullptr);
  CHECK(journal_bad.initialize(now_ms).code == StatusCode::InvalidArgument);
  bad = config;
  bad.boot_incarnation = 0;
  ConfigJournal journal_bad2(bad, storage, floor, verifier, entropy, rate,
                             &provider, nullptr, nullptr);
  CHECK(journal_bad2.initialize(now_ms).code == StatusCode::InvalidArgument);
}

// --- Recovery / floor / deferred-intent regressions ---------------------------------------

// The generation/revision floors must advance on every committed record:
// A recovery may never re-mint counters this boot already consumed,
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
  rig.provider.apply_result = Status::success();
  rig.provider.restore_result = Status::success();
  // Generations 1..3 (DECIDED, APPLY_INTENT, QUARANTINED) are all consumed
  // this boot — recovery must start above them, not above a stale floor.
  const ConfigField baseline_fields[] = {sdk_u8(1, 1)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 2, 2,
                 baseline.view(), baseline.view(), 36,
                 rig.config.authority_generation, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidArgument);
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 3, 2,
                 baseline.view(), baseline.view(), 37,
                 rig.config.authority_generation, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidArgument);
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 4, 2,
                 baseline.view(), baseline.view(), 38,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  // The completed revision advances past the proven floor — never rolled
  // back to a lower base.
  CHECK(rig.journal->decision_revision() == 2);
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

  // AdoptKnown re-proves the ACTIVE survivor: no rollback to prev.
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeAdoptKnown, 4, 2,
                 rig.journal->active_snapshot(), ByteView{}, 39,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(!rig.journal->uncertain());
  // The survivor completes as ACTIVE with its confirmed snapshot — the
  // old recovery code used to degrade it to INTERRUPTED and roll back.
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 2);
  CHECK(rig.journal->active_revision() == 2);
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
  // The target cannot reserve kind 3 on the impaired journal either: the
  // manifest is Failed-acked, and a chunk for nothing is denied.
  AckPort port;
  ConfigTarget target(port, rig.rate);
  CHECK_OK(target.add_journal(1, *rig.journal));
  send_manifest(target, kAuthority, manifest, now_ms);
  CHECK(port.last_status == autonomy::ObjectAckStatus::Failed);
  CHECK(!target.object_active());
  autonomy::ObjectChunkPayload chunk{};
  send_chunk(target, kAuthority, chunk, now_ms);
  CHECK(target.control_denied() == 1);
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
  // The corrupt record's gen-3 claim bounds nothing: recovery names the
  // floor's exact next (J 3 -> 4, R 1 -> 2), never the bitrot's claim.
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeAdoptKnown, 3, 2,
                 rig.journal->active_snapshot(), ByteView{}, 40,
                 rig.config.authority_generation, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidArgument);
  build_recovery(signer_, rig, endpoint::kRcr2ModeAdoptKnown, 4, 2,
                 rig.journal->active_snapshot(), ByteView{}, 41,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
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
// assembly in progress — Failed-acked, never re-ACKed as progress.
void test_manifest_length_conflict() {
  TargetRig rig;
  MonotonicMs t = 1000;
  CHECK_OK(rig.journal->initialize(t));
  AckPort port;
  ConfigTarget target(port, rig.rate);
  CHECK_OK(target.add_journal(1, *rig.journal));
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  manifest.total_len = 64;
  manifest.object_hash[0] = 0xAB;
  send_manifest(target, kAuthority, manifest, t);
  CHECK(port.last_status == autonomy::ObjectAckStatus::Incomplete);
  CHECK(target.object_active());
  manifest.total_len = 128;  // same object hash, different declared length
  send_manifest(target, kAuthority, manifest, t);
  CHECK(port.last_status == autonomy::ObjectAckStatus::Failed);
  // The live assembly survives the contradiction — only its own bytes
  // complete or poison it.
  CHECK(target.object_active());
}

// A journal that becomes impaired invalidates an in-progress NORMAL permit
// assembly (the submit it feeds could never succeed), while a kind-4
// assembly on the same target stays servable.
void test_quarantine_invalidates_permit_assembly() {
  TargetRig rig;
  MonotonicMs t = 1000;
  CHECK_OK(rig.journal->initialize(t));
  AckPort port;
  ConfigTarget target(port, rig.rate);
  CHECK_OK(target.add_journal(1, *rig.journal));

  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  manifest.total_len = 64;
  manifest.object_hash[0] = 0xAB;
  send_manifest(target, kAuthority, manifest, t);
  CHECK(port.last_status == autonomy::ObjectAckStatus::Incomplete);
  CHECK(target.object_active());

  // Spend the live floor's store axis (no reboot): the next submit finds
  // no nameable generation — CounterExhausted — and the live state wedges
  // into quarantine.
  SecurityFloorState current{};
  CHECK_OK(rig.floor->read(current));
  SecurityFloorState spent = current;
  spent.entries[0].store_floor = 0xFFFFFFFFU;
  CHECK_OK(rig.floor->advance(current, spent));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK(drive_update(rig, patch, 1, t += 10, 0, ByteView{}, verdict).code ==
        StatusCode::CounterExhausted);
  CHECK(rig.journal->quarantined());

  // The target's poll drops the doomed permit assembly; a chunk for it is
  // denied and a fresh kind-3 manifest cannot reserve.
  target.poll(t += 10);
  CHECK(!target.object_active());
  autonomy::ObjectChunkPayload chunk{};
  std::memcpy(chunk.object_hash.data(), manifest.object_hash.data(),
              manifest.object_hash.size());
  send_chunk(target, kAuthority, chunk, t);
  CHECK(target.control_denied() == 1);
  send_manifest(target, kAuthority, manifest, t);
  CHECK(port.last_status == autonomy::ObjectAckStatus::Failed);

  // Kind 4 on the same impaired journal still reserves: recovery stays
  // reachable while normal intake is shut.
  manifest.kind = autonomy::ControlObjectKind::ConfigRecovery;
  send_manifest(target, kAuthority, manifest, t);
  CHECK(port.last_status == autonomy::ObjectAckStatus::Incomplete);
  CHECK(target.object_active());
  target.poll(t += 10);  // impairment does not drop kind-4 assemblies
  CHECK(target.object_active());
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


// --- R-series: the dedicated recovery lane (Issue #51) -------------------------
//
// A signed kind-4 RCR2 recovery intent is the ONLY intake an impaired
// journal still serves: it names the floor's exact-next counters and the
// baseline to re-apply. Everything else — bad signatures, stale counters,
// replays, wrong lanes — stays fail-closed.

// (build_recovery/snapshot_of are defined above drain(); used from C09 on.)

// Feed `object` through the kind-4 intake in `chunk_size` pieces.
autonomy::ObjectAckStatus send_recovery_chunks(
    ConfigTarget& target, AckPort& port,
    const ByteBuffer<kConfigPermitObjectMax>& object,
    const std::uint16_t chunk_size, MonotonicMs& t) {
  return deliver_object(target, port, kAuthority,
                        autonomy::ControlObjectKind::ConfigRecovery,
                        object.view(), chunk_size, t);
}

// R01: both journal slots lost -> quarantine -> a signed Reprovision intent
// re-applies its baseline and restores intake; a normal permit applies after.
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

  // No verifiable record survives: adopt-known must fail closed — a mere
  // signed attestation adopts nothing. Both intents name the floor's
  // exact next (J 3 -> 4, R 1 -> 2).
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeAdoptKnown, 4, 2, ByteView{},
                 ByteView{}, 1, rig.config.authority_generation, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms + 130, verdict).code ==
        StatusCode::RecoveryRequired);
  CHECK(rig.journal->quarantined());

  // Reprovision carries the complete new baseline: intent persists, the
  // restore proves it, the completion twins re-open intake.
  const ConfigField baseline_fields[] = {sdk_u8(1, 1), sdk_bool(2, true),
                                         sdk_bool(3, true), sdk_u8(4, 0)};
  const auto baseline = snapshot_of(baseline_fields, 4);
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 4, 2,
                 baseline.view(), baseline.view(), 2,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 140, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);
  CHECK(rig.journal->quarantined());  // isolated until the readback proves it
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(!rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 2);
  CHECK(rig.journal->active_snapshot().size == baseline.size);
  // Both slots now carry the same completion record (intent J=4, complete J=5).
  CHECK(std::memcmp(rig.storage.slots_[0].data(), rig.storage.slots_[1].data(),
                    64) == 0);

  // Intake is re-established: a bound permit flows through the normal path.
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000,
                        rig.journal->decision_revision(),
                        rig.journal->active_snapshot(), verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// R02: one-slot bitrot -> uncertain -> AdoptKnown re-proves the survivor
// and heals the journal; the completed revision advances past the proven
// floor, so pre-loss permits cannot replay.
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

  // AdoptKnown binds the survivor's confirmed snapshot by hash: the
  // re-apply re-proves it through the provider readback.
  ByteBuffer<kConfigPermitObjectMax> object{};
  const ByteView survivor = rig.journal->active_snapshot();
  build_recovery(signer_, rig, endpoint::kRcr2ModeAdoptKnown, 4, 2, survivor,
                 ByteView{}, 3, rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 150, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);
  drain(rig, now_ms);
  CHECK(!rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == proven_revision + 1);
  CHECK(rig.journal->active_snapshot().size == survivor.size);
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

  // The counters never matter here: every case below fails before the
  // floor checks (exact-next J=1/R=1 on the fresh floor would apply).
  const ConfigField baseline_fields[] = {sdk_u8(1, 1)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 500, 7,
                 baseline.view(), baseline.view(), 4,
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
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 500, 7,
                 baseline.view(), baseline.view(), 5,
                 rig.config.authority_generation + 7, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms + 40, verdict).code ==
        StatusCode::AuthorizationFailed);
  CHECK(verdict.reason == ConfigReason::AuthorityDenied);
  CHECK(rig.journal->quarantined());
  static_cast<void>(patch);
}

// R04: replay protection — same op+same digest is idempotent, same op+
// different digest is conflict, counters at/below the floor are refused.
void test_r04_recovery_replay_floor() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms);
  ConfigVerdict verdict{};

  const ConfigField baseline_fields[] = {sdk_u8(1, 1)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 1, 1,
                 baseline.view(), baseline.view(), 6,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 10, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);
  // Same operation id + same bytes while in flight -> progress, never a
  // second ceremony.
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 15, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);

  // Same operation id + different content -> CONFLICT.
  ByteBuffer<kConfigPermitObjectMax> conflicting{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 700, 9,
                 baseline.view(), baseline.view(), 6,
                 rig.config.authority_generation, conflicting);
  // Same opid tag (6) produces the same operation id with different content.
  CHECK(rig.journal->submit_recovery(conflicting.view(), now_ms + 30, verdict)
            .code == StatusCode::Conflict);

  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  // The lane closes once healed: even the completed operation's own
  // bytes are refused here (completion is answered on the status lane).
  CHECK(rig.journal->submit_recovery(object.view(), now_ms + 35, verdict)
            .code == StatusCode::InvalidState);

  // A fresh recovery that does not name the floor's exact next is
  // refused: the floor moved to J=2/R=1, so only J=3/R=2 could land now.
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 1, 1,
                 baseline.view(), baseline.view(), 7,
                 rig.config.authority_generation, object);
  rig.storage.fill(0, 0xEE);  // re-impair so the lane stays admissible
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms + 40);
  CHECK(rig.journal->quarantined());
  CHECK(rig.journal->submit_recovery(object.view(), now_ms + 50, verdict)
            .code == StatusCode::InvalidArgument);
}

// R07: the kind-4 reassembly lane stays open impaired; kind-3 stays shut.
void test_r07_recovery_lane_reassembly() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms);
  CHECK(rig.journal->quarantined());

  const ConfigField baseline_fields[] = {sdk_u8(1, 1)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 1, 1,
                 baseline.view(), baseline.view(), 12,
                 rig.config.authority_generation, object);
  AckPort port;
  ConfigTarget target(port, rig.rate);
  CHECK_OK(target.add_journal(1, *rig.journal));
  CHECK(send_recovery_chunks(target, port, object, 32, now_ms) ==
        autonomy::ObjectAckStatus::Ok);
  CHECK(!target.object_active());
  // Assembly completed — not CONFIG_ACTIVE: the ceremony still has to
  // prove the baseline before intake re-opens.
  CHECK(rig.journal->quarantined());
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());

  // Manifest discipline on a fresh impaired journal: a permit manifest is
  // refused (that lane is closed while impaired) and an oversized
  // recovery manifest is malformed; digest-mismatched content fails
  // integrity.
  TargetRig rig2;
  MonotonicMs t = 5000;
  rig2.storage.fill(0, 0xEE);
  rig2.storage.fill(1, 0xEE);
  rig2.boot(t);
  AckPort port2;
  ConfigTarget target2(port2, rig2.rate);
  CHECK_OK(target2.add_journal(1, *rig2.journal));
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;  // lane closed impaired
  manifest.total_len = 64;
  manifest.object_hash[0] = 1;
  CHECK(rig2.journal->note_object_manifest(manifest, t).code ==
        StatusCode::InvalidState);
  manifest.kind = autonomy::ControlObjectKind::ConfigRecovery;
  manifest.total_len = kConfigPermitObjectMax + 1;
  CHECK(rig2.journal->note_object_manifest(manifest, t).code ==
        StatusCode::ProtocolError);

  // Honest manifest + corrupted bytes: the digest check rejects before
  // submit_recovery ever sees the object.
  manifest.total_len = static_cast<std::uint16_t>(object.size);
  sha256(object.view(), manifest.object_hash);
  send_manifest(target2, kAuthority, manifest, t);
  CHECK(port2.last_status == autonomy::ObjectAckStatus::Incomplete);
  autonomy::ObjectChunkPayload chunk{};
  chunk.object_hash = manifest.object_hash;
  chunk.offset = 0;
  chunk.data_size = 64;
  std::memcpy(chunk.data.data(), object.bytes.data(), 64);
  chunk.data[10] ^= 0xFFU;  // corrupted under an honest manifest
  t += 10;
  send_chunk(target2, kAuthority, chunk, t);
  CHECK(port2.last_status == autonomy::ObjectAckStatus::Incomplete);
  // The remainder in bounded pieces: the digest check rejects at
  // completion, before submit_recovery ever sees the object.
  std::size_t sent = 64;
  while (sent < object.size) {
    const std::size_t piece =
        object.size - sent > 64 ? 64 : object.size - sent;
    chunk.offset = static_cast<std::uint16_t>(sent);
    chunk.data_size = static_cast<std::uint16_t>(piece);
    std::memcpy(chunk.data.data(), object.bytes.data() + sent, piece);
    t += 10;
    send_chunk(target2, kAuthority, chunk, t);
    sent += piece;
  }
  CHECK(port2.last_status == autonomy::ObjectAckStatus::Failed);
  CHECK(!target2.object_active());
  CHECK(rig2.journal->quarantined());

  // The kind-3 lane stays shut through all of it (quarantine -> InvalidState).
  manifest.kind = autonomy::ControlObjectKind::ConfigPermit;
  CHECK(rig2.journal->note_object_manifest(manifest, t).code ==
        StatusCode::InvalidState);
}

// --- RecoveryInfo (subtype 7/8): the read-only recovery baseline ----------------

void test_recovery_info_healthy() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);

  endpoint::RecoveryInfoQuery query{};
  query.config_namespace = 1;
  query.nonce = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(rig.journal->handle_recovery_info_query(query, now_ms, encoded));
  endpoint::RecoveryInfo info{};
  CHECK_OK(endpoint::recovery_info_decode(encoded.view(), info));
  CHECK(info.config_namespace == 1);
  CHECK(info.schema == 1);
  CHECK(info.nonce_echo == query.nonce);
  CHECK(info.network == kNet);
  // One update persists three records (DECIDED/INTENT/ACTIVE) under one
  // decision: the reply names the floor's exact-next authority, not the
  // journal's memory of it.
  CHECK(info.store_floor == rig.floor_j());
  CHECK(info.decision_floor == rig.floor_r());
  CHECK(info.store_floor == 3 && info.decision_floor == 1);
  CHECK(info.flags == endpoint::kRecoveryInfoFlagSurvivorKnown);
  CHECK(info.snapshot_hash == rig.journal->active_hash());
  CHECK(info.recovery_version == kRecoveryWireVersion);
  CHECK(info.profile_bits == 0);  // FakeVerifier advertises no profile bit

  // Namespace mismatch and uninitialized journals refuse.
  query.config_namespace = 0x8000;
  CHECK(rig.journal->handle_recovery_info_query(query, now_ms, encoded).code ==
        StatusCode::Unsupported);
  TargetRig fresh;
  query.config_namespace = 1;
  CHECK(fresh.journal->handle_recovery_info_query(query, now_ms, encoded).code ==
        StatusCode::InvalidState);
}

void test_recovery_info_impaired() {
  // Quarantined, no survivor: impairment is explicit, the baseline is
  // explicit unknown — but J/R still serve (the floor is a separate
  // store and it is alive).
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms += 10);
  CHECK(rig.journal->quarantined());

  endpoint::RecoveryInfoQuery query{};
  query.config_namespace = 1;
  query.nonce = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(rig.journal->handle_recovery_info_query(query, now_ms, encoded));
  endpoint::RecoveryInfo info{};
  CHECK_OK(endpoint::recovery_info_decode(encoded.view(), info));
  CHECK(info.flags == (endpoint::kRecoveryInfoFlagImpaired |
                       endpoint::kRecoveryInfoFlagQuarantined));
  CHECK(info.store_floor == 3 && info.decision_floor == 1);
  Digest256 zero{};
  CHECK(info.snapshot_hash == zero);  // explicit unknown, never a guess
  CHECK(info.recovery_version == kRecoveryWireVersion);

  // Uncertain with a known-value survivor: the hash serves with the
  // impairment flags — the accept path (not this advisory reply) decides
  // whether the survivor is adoptable.
  TargetRig rig2;
  now_ms = 2000;
  CHECK_OK(rig2.journal->initialize(now_ms));
  CHECK_OK(drive_update(rig2, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig2, now_ms);
  rig2.storage.corrupt(1, 200);  // lose the non-ACTIVE sibling
  rig2.boot(now_ms += 10);
  CHECK(rig2.journal->uncertain());
  CHECK_OK(rig2.journal->handle_recovery_info_query(query, now_ms, encoded));
  CHECK_OK(endpoint::recovery_info_decode(encoded.view(), info));
  CHECK(info.flags == (endpoint::kRecoveryInfoFlagImpaired |
                       endpoint::kRecoveryInfoFlagUncertain |
                       endpoint::kRecoveryInfoFlagSurvivorKnown));
  CHECK(info.snapshot_hash == rig2.journal->active_hash());
}

void test_recovery_info_floor_dead() {
  // The floor cannot name J/R (a failed commit left it unusable): the
  // journal refuses rather than report zeros the host would sign against.
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  rig.floor_storage.fail_writes = true;
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK(!drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict).ok());
  rig.floor_storage.fail_writes = false;

  endpoint::RecoveryInfoQuery query{};
  query.config_namespace = 1;
  query.nonce = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  endpoint::EncodedServicePayload encoded{};
  CHECK(rig.journal->handle_recovery_info_query(query, now_ms, encoded).code ==
        StatusCode::RecoveryRequired);
}

// --- F-series: the RLF1 security floor -----------------------------------------
//
// The floor reserves every store generation (and every decision revision)
// BEFORE the journal record that consumes it; a failed journal write
// consumes the reservation. The tests below pin the reservation order,
// the gap rule, the missing/corrupt-floor intake stop, the save-order
// check, exhaustion, and the record-kind migration.

// Recompute a journal slot's trailing CRC32 after surgical byte edits.
void refix_journal_crc(FakeJournalStorage& storage, const std::uint8_t slot) {
  auto& image = storage.slots_[slot];
  const std::size_t len =
      (static_cast<std::size_t>(image[6]) << 8) | image[7];
  const std::uint32_t crc =
      crc32_iso_hdlc(ByteView{image.data(), len - 4});
  image[len - 4] = static_cast<std::uint8_t>((crc >> 24) & 0xFFU);
  image[len - 3] = static_cast<std::uint8_t>((crc >> 16) & 0xFFU);
  image[len - 2] = static_cast<std::uint8_t>((crc >> 8) & 0xFFU);
  image[len - 1] = static_cast<std::uint8_t>(crc & 0xFFU);
}

// Every commit reserves first: DECIDED moves J and R, later phases of the
// same transaction move J and hold R.
void test_floor_reserve_on_commit() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  CHECK(rig.floor_j() == 1);
  CHECK(rig.floor_r() == 1);
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.floor_j() == 3);
  CHECK(rig.floor_r() == 1);
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict));
  CHECK(rig.floor_j() == 4);
  CHECK(rig.floor_r() == 2);
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.floor_j() == 6);
  CHECK(rig.floor_r() == 2);
}

// A failed journal write consumes its floor reservation: the retry mints
// the NEXT generation, never the dropped one.
void test_floor_gap_consumed() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  rig.storage.drop_call = 0;  // the DECIDED write never lands
  CHECK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict).code ==
        StatusCode::StorageFailure);
  CHECK(rig.floor_j() == 1);  // reserved, then dropped: consumed
  CHECK(rig.floor_r() == 1);
  rig.storage.drop_call = std::numeric_limits<std::size_t>::max();
  CHECK_OK(drive_update(rig, patch, 1, now_ms += 61000, 0, ByteView{},
                        verdict));
  CHECK(rig.floor_j() == 2);  // the gap is skipped, never reused
  CHECK(rig.floor_r() == 1);
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 1);
}

void test_floor_ahead_of_standard_record_parks_on_boot() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField first[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, first, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.floor_j() == 3 && rig.floor_r() == 1);
  const auto completed_id = last_command_.operation_id;

  const ConfigField second[] = {sdk_u8(1, 2)};
  rig.storage.drop_call = rig.storage.write_calls;
  CHECK(drive_update(rig, second, 1, now_ms += 61000, 1,
                     rig.journal->active_snapshot(), verdict)
            .code == StatusCode::StorageFailure);
  CHECK(rig.floor_j() == 4 && rig.floor_r() == 2);
  rig.storage.drop_call = std::numeric_limits<std::size_t>::max();
  rig.boot(now_ms += 10);
  CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
  CHECK(rig.journal->uncertain());
  endpoint::ControlChallengeQuery query{};
  endpoint::EncodedServicePayload reply{};
  CHECK(!rig.journal->handle_challenge_query(query, now_ms, reply).ok());
  endpoint::ControlStatusQuery status_query{};
  status_query.config_namespace = rig.config.config_namespace;
  status_query.operation_id = completed_id;
  CHECK_OK(rig.journal->handle_status_query(status_query, now_ms, reply));
  endpoint::ControlStatus status{};
  CHECK_OK(endpoint::control_status_decode(reply.view(), status));
  CHECK(status.phase == ConfigPhase::Quarantined);
  CHECK(status.reason == ConfigReason::RecoveryRequired);
}

// A missing floor stops ALL privileged intake — and it is never
// auto-created: only managed re-provisioning restores service.
void test_floor_missing_stops_intake() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  rig.floor_storage.wipe();
  rig.boot(now_ms += 10);
  CHECK(rig.boot_status_.code == StatusCode::RecoveryRequired);
  CHECK(!rig.journal->initialized());
  ConfigVerdict verdict{};
  CHECK(rig.journal->submit_permit(last_permit_.view(), now_ms, true, verdict)
            .code == StatusCode::InvalidState);
  endpoint::ControlChallengeQuery query{};
  endpoint::EncodedServicePayload encoded{};
  CHECK(rig.journal->handle_challenge_query(query, now_ms, encoded).code ==
        StatusCode::InvalidState);
  endpoint::ControlStatusQuery status_query{};
  CHECK(rig.journal->handle_status_query(status_query, now_ms, encoded).code ==
        StatusCode::InvalidState);
  CHECK(rig.journal->submit_recovery(last_permit_.view(), now_ms, verdict)
            .code == StatusCode::InvalidState);
  // Managed re-provisioning installs the floor; the journal serves again.
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 0, 0);
  rig.boot(now_ms += 10);
  CHECK_OK(rig.boot_status_);
  const ConfigField patch[] = {sdk_u8(1, 1)};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
}

// A torn floor write invalidates the cache: intake stops until a refresh
// re-proves the bytes — and a refresh cannot heal durable garbage, only
// managed re-provisioning can.
void test_floor_torn_write_invalidates() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  rig.floor_storage.torn_write = true;
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                     rig.journal->active_snapshot(), verdict)
            .code == StatusCode::StorageFailure);
  CHECK(!rig.floor->usable());
  SecurityFloorState state{};
  CHECK(rig.floor->read(state).code == StatusCode::RecoveryRequired);
  // Intake now refuses: the reservation path cannot prove its floors.
  CHECK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                     rig.journal->active_snapshot(), verdict)
            .code == StatusCode::RecoveryRequired);
  // The torn image is durable: refresh re-reads the same garbage.
  rig.floor_storage.torn_write = false;
  CHECK(rig.floor->refresh().code == StatusCode::IntegrityError);
  // Managed re-provisioning at the true counters restores service.
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 3, 1);
  CHECK_OK(rig.floor->refresh());
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// A journal newer than its floor proves the save order was violated (or
// the floor was mis-seeded): stop, never mint from unknown counters.
void test_floor_order_violation() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 0, 0);
  rig.boot(now_ms += 10);
  CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
  CHECK(rig.journal->quarantined());
  // No recovery can mint: below the journal is spent, and the floor's
  // next (1) is below the journal too.
  const ConfigField baseline_fields[] = {sdk_u8(1, 1)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 1, 1,
                 baseline.view(), baseline.view(), 42,
                 rig.config.authority_generation, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidArgument);
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 4, 1,
                 baseline.view(), baseline.view(), 43,
                 rig.config.authority_generation, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidArgument);
  // Managed fix: re-provision the floor at the true counters, reboot.
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 3, 1);
  rig.boot(now_ms += 10);
  CHECK_OK(rig.boot_status_);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  drain(rig, now_ms);
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict));
}

// Fresh journal slots with a floor that names consumed counters are a
// total journal loss, never a fresh deployment: quarantine, and recover
// from the floor's J/R.
void test_floor_ahead_fresh_quarantines() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  // Total journal loss with the slots reading back erased (the corrupt-
  // both shape quarantines too, but through the corruption rule — R01).
  rig.storage.fill(0, 0xFF);
  rig.storage.fill(1, 0xFF);
  rig.boot(now_ms + 100);
  CHECK(rig.boot_status_.code == StatusCode::RecoveryRequired);
  CHECK(rig.journal->quarantined());
  // The floor survived the journal: J=3, R=1 still name the next recovery.
  CHECK(rig.floor_j() == 3);
  CHECK(rig.floor_r() == 1);
  // Recovery at the floor's exact next lands (reprovision: no
  // survivor to adopt).
  const ConfigField baseline_fields[] = {sdk_u8(1, 1)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 4, 2,
                 baseline.view(), baseline.view(), 21,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms + 200, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// A spent store axis wedges honestly: the op fails CounterExhausted, the
// journal quarantines, and no retry loop spins on poll().
void test_store_exhausted() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  // Spend the remaining axis in this boot; after a reboot a floor ahead
  // of the journal is unproven history and correctly parks the journal.
  SecurityFloorState current{};
  CHECK_OK(rig.floor->read(current));
  SecurityFloorState spent = current;
  spent.entries[0].store_floor = 0xFFFFFFFFU;
  CHECK_OK(rig.floor->advance(current, spent));
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                     rig.journal->active_snapshot(), verdict)
            .code == StatusCode::CounterExhausted);
  CHECK(verdict.reason == ConfigReason::RecoveryRequired);
  CHECK(rig.journal->quarantined());
  rig.journal->poll(now_ms += 10);
  CHECK(rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Quarantined);
  // Recovery cannot mint past the spent axis either: the headroom check
  // fires before exact-next, whatever the intent names.
  const ConfigField baseline_fields[] = {sdk_u8(1, 1)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeReprovision, 7, 2,
                 baseline.view(), baseline.view(), 44,
                 rig.config.authority_generation, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::CounterExhausted);
}

// Format-1 journal images (reserved byte 0) still decode as Standard
// records, so healthy pre-floor journals migrate.
void test_floor_record_kind_legacy() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  // The ACTIVE record sits in slot 0; downgrade its format to 1.
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  rig.storage.slots_[0][4] = 0;
  rig.storage.slots_[0][5] = 1;
  refix_journal_crc(rig.storage, 0);
  rig.boot(now_ms += 10);
  CHECK_OK(rig.boot_status_);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 1);
  drain(rig, now_ms);
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  CHECK_OK(drive_update(rig, patch2, 1, now_ms += 61000, 1,
                        rig.journal->active_snapshot(), verdict));
}

// Same-generation twins must agree on the whole encoded content: a twin
// pair differing only in issuer metadata is ambiguous, never adopted.
void test_floor_twins_full_content() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  CHECK_OK(rig.journal->initialize(now_ms));
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  rig.storage.corrupt(1, 200);
  rig.boot(now_ms += 10);
  CHECK(rig.journal->uncertain());
  // Complete a recovery so both slots carry identical ACTIVE twins
  // (intent J=4, complete J=5); then flip one byte of slot 0's
  // issuer_generation (offset 44) and repair the CRC so the record
  // parses but disagrees with its twin.
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_recovery(signer_, rig, endpoint::kRcr2ModeAdoptKnown, 4, 2,
                 rig.journal->active_snapshot(), ByteView{}, 45,
                 rig.config.authority_generation, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  rig.storage.corrupt(0, 44);
  refix_journal_crc(rig.storage, 0);
  rig.boot(now_ms += 10);
  CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
  CHECK(rig.journal->uncertain());
}


}  // namespace

// --- T04 + power table (§5.4-§5.6): the RCR2 ceremony under a REAL -------
// verifier. Every intent below is dev-signed with the production envelope
// helpers and verified by DevConfigAuthorityVerifier — never verified=true
// (§9.1). The setups seed directly the state one applied update plus total
// journal loss leaves (floor J=3/R=1, provider holding the old 6 B
// snapshot, both slots destroyed) — R01 proves the same shape end to end.

// Seed the T04 post-loss state: floor (3,1), provider durable+live on the
// old 6 B snapshot, both journal slots destroyed. Boots quarantined.
void t04_seed_loss(TargetRig& rig, MonotonicMs& now_ms) {
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 3, 1);
  const ConfigField old_fields[] = {sdk_u8(1, 1)};
  const auto old_snapshot = snapshot_of(old_fields, 1);
  CHECK(old_snapshot.size == 6);
  rig.provider.seed(old_snapshot.view());
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms);
  CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
  CHECK(rig.journal->quarantined());
}

std::array<std::uint8_t, 16> dev_opid(const std::uint8_t tag) {
  return {0xD0, tag, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
}

endpoint::ControlStatus query_status(TargetRig& rig,
                                     const std::array<std::uint8_t, 16>& opid,
                                     const MonotonicMs now_ms) {
  endpoint::ControlStatusQuery query{};
  query.config_namespace = 1;
  query.operation_id = opid;
  endpoint::EncodedServicePayload reply{};
  CHECK_OK(rig.journal->handle_status_query(query, now_ms, reply));
  endpoint::ControlStatus status{};
  CHECK_OK(endpoint::control_status_decode(reply.view(), status));
  return status;
}

// T04a: a different complete baseline re-provisions the wiped journal —
// isolated until the readback proves it, then journal bytes/hash plus
// provider durable AND live all match the baseline.
void test_t04_reprovision_success() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  CHECK(rig.provider.validate_recovery_calls == 0);

  const ConfigField baseline_fields[] = {sdk_u8(1, 2), sdk_bool(2, true),
                                         sdk_bool(3, true), sdk_u8(4, 0)};
  const auto baseline = snapshot_of(baseline_fields, 4);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 1, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);
  CHECK(rig.journal->quarantined());  // isolated until complete
  CHECK(rig.provider.validate_recovery_calls == 1);  // capability probed
  // Never Active/Ok before the completion twins land.
  const endpoint::ControlStatus progress =
      query_status(rig, dev_opid(1), now_ms);
  CHECK(progress.phase != ConfigPhase::Active);
  CHECK(progress.reason == ConfigReason::InProgress);

  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(!rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 2);
  CHECK(rig.journal->active_revision() == 2);
  const ByteView active = rig.journal->active_snapshot();
  CHECK(active.size == baseline.size);
  CHECK(std::memcmp(active.data, baseline.bytes.data(), active.size) == 0);
  Digest256 expect_hash{};
  CHECK_OK(config_snapshot_hash(rig.config.config_namespace, rig.config.schema,
                                baseline.view(), expect_hash));
  CHECK(rig.journal->active_hash() == expect_hash);
  CHECK(rig.provider.active_.size == baseline.size);
  CHECK(std::memcmp(rig.provider.active_.bytes.data(), baseline.bytes.data(),
                    baseline.size) == 0);
  CHECK(rig.provider.live_.size == baseline.size);
  CHECK(std::memcmp(rig.provider.live_.bytes.data(), baseline.bytes.data(),
                    baseline.size) == 0);
  const endpoint::ControlStatus done = query_status(rig, dev_opid(1), now_ms);
  CHECK(done.phase == ConfigPhase::Active);
  CHECK(done.reason == ConfigReason::Ok);
  CHECK(done.active_hash == expect_hash);
}

// T04b: the schema-allows-empty baseline restores clean — no old live
// value survives the re-apply.
void test_t04_reprovision_empty() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);

  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2, ByteView{},
                     ByteView{}, 2, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->active_snapshot().size == 0);
  Digest256 expect_hash{};
  CHECK_OK(config_snapshot_hash(rig.config.config_namespace, rig.config.schema,
                                ByteView{}, expect_hash));
  CHECK(rig.journal->active_hash() == expect_hash);
  // The old 6 B live image is gone from both provider images.
  CHECK(rig.provider.active_.size == 0);
  CHECK(rig.provider.live_.size == 0);
}

// Transplant one applied update's history onto a dev rig: valid records
// need a writer, so drive it on a sibling rig and move the storage
// image, floor and provider state over. Loses the non-ACTIVE sibling —
// boots uncertain with a proven ACTIVE survivor.
void t04_seed_uncertain_survivor(TargetRig& rig, MonotonicMs& now_ms) {
  const ConfigField patch[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  TargetRig donor;
  CHECK_OK(donor.journal->initialize(now_ms));
  CHECK_OK(drive_update(donor, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(donor, now_ms);
  rig.storage.slots_ = donor.storage.slots_;
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 3, 1);
  rig.provider.seed(donor.provider.active_.view());
  rig.storage.corrupt(1, 200);  // lose the non-ACTIVE sibling
  rig.boot(now_ms += 100);
  CHECK(rig.journal->uncertain());
}

// T04c: a mere signed attestation adopts nothing; a bound survivor adopts.
void test_t04_adopt_known() {
  // No survivor: AdoptKnown refuses, the journal stays quarantined.
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeAdoptKnown, 4, 2, ByteView{},
                     ByteView{}, 3, object);
  ConfigVerdict verdict{};
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::RecoveryRequired);
  CHECK(rig.journal->quarantined());

  // A wrong hash against a real survivor refuses as Conflict, never a
  // partial adoption.
  TargetRig rig2(kBoot, true, true);
  t04_seed_uncertain_survivor(rig2, now_ms);
  const ConfigField wrong_fields[] = {sdk_u8(1, 2)};
  const auto wrong = snapshot_of(wrong_fields, 1);
  build_dev_recovery(rig2, endpoint::kRcr2ModeAdoptKnown, 4, 2, wrong.view(),
                     ByteView{}, 4, object);
  CHECK(rig2.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::Conflict);
  CHECK(rig2.journal->uncertain());

  // The bound survivor adopts and completes.
  build_dev_recovery(rig2, endpoint::kRcr2ModeAdoptKnown, 4, 2,
                     rig2.journal->active_snapshot(), ByteView{}, 5, object);
  CHECK_OK(rig2.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig2, now_ms);
  CHECK(!rig2.journal->uncertain());
  CHECK(rig2.journal->phase() == ConfigPhase::Active);
  CHECK(rig2.journal->active_snapshot().size == 6);
}

// T04d: provider fault injections during the ceremony — a delayed restore
// still completes; a partial change, a readback failure and a byte
// mismatch all land terminal failures and stay impaired.
void test_t04_provider_faults() {
  const ConfigField baseline_fields[] = {sdk_u8(1, 2), sdk_bool(2, true),
                                         sdk_bool(3, true), sdk_u8(4, 0)};
  const auto baseline = snapshot_of(baseline_fields, 4);

  // Delayed restore: three polls to commit, still completes.
  {
    TargetRig rig(kBoot, true, true);
    MonotonicMs now_ms = 1000;
    t04_seed_loss(rig, now_ms);
    rig.provider.polls_to_complete = 3;
    ByteBuffer<kConfigPermitObjectMax> object{};
    build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                       baseline.view(), baseline.view(), 6, object);
    ConfigVerdict verdict{};
    CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
    rig.journal->poll(now_ms += 10);
    rig.journal->poll(now_ms += 10);
    CHECK(rig.journal->quarantined());  // restore still running
    drain(rig, now_ms);
    CHECK(!rig.journal->quarantined());
    CHECK(rig.journal->phase() == ConfigPhase::Active);
  }

  // Partial change: durable advances, live stays stale — the readback
  // catches it, the failure is terminal, isolation continues.
  {
    TargetRig rig(kBoot, true, true);
    MonotonicMs now_ms = 1000;
    t04_seed_loss(rig, now_ms);
    rig.provider.freeze_live = true;
    ByteBuffer<kConfigPermitObjectMax> object{};
    build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                       baseline.view(), baseline.view(), 7, object);
    ConfigVerdict verdict{};
    CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
    drain(rig, now_ms);
    CHECK(rig.journal->quarantined());
    CHECK(rig.journal->phase() == ConfigPhase::Interrupted);
    const endpoint::ControlStatus failed = query_status(rig, dev_opid(7), now_ms);
    CHECK(failed.phase == ConfigPhase::Interrupted);
    CHECK(failed.reason == ConfigReason::StorageFailure);
  }

  // Readback failure at proof time: same terminal shape.
  {
    TargetRig rig(kBoot, true, true);
    MonotonicMs now_ms = 1000;
    t04_seed_loss(rig, now_ms);
    ByteBuffer<kConfigPermitObjectMax> object{};
    build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                       baseline.view(), baseline.view(), 8, object);
    ConfigVerdict verdict{};
    CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
    rig.provider.fail_reads = 1;  // the maintenance-base read already passed
    drain(rig, now_ms);
    CHECK(rig.journal->quarantined());
    const endpoint::ControlStatus failed = query_status(rig, dev_opid(8), now_ms);
    CHECK(failed.phase == ConfigPhase::Interrupted);
    CHECK(failed.reason == ConfigReason::StorageFailure);
  }

  // Byte mismatch: the read succeeds but differs — VerifyFailed.
  {
    TargetRig rig(kBoot, true, true);
    MonotonicMs now_ms = 1000;
    t04_seed_loss(rig, now_ms);
    ByteBuffer<kConfigPermitObjectMax> object{};
    build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                       baseline.view(), baseline.view(), 9, object);
    ConfigVerdict verdict{};
    CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
    rig.provider.corrupt_reads = 1;  // poison the proof read only
    drain(rig, now_ms);
    CHECK(rig.journal->quarantined());
    const endpoint::ControlStatus failed = query_status(rig, dev_opid(9), now_ms);
    CHECK(failed.phase == ConfigPhase::Interrupted);
    CHECK(failed.reason == ConfigReason::VerifyFailed);
  }
}

// Power row 1 (§5.6): floor saved, intent not — the counters are consumed,
// the old object is refused, a fresh authorization on the new floor lands.
void test_power_floor_saved_intent_not() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  const ConfigField baseline_fields[] = {sdk_u8(1, 2)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 10, object);
  // Drop the intent's seal write: the pending image is discardable, the
  // floor reservation (J=4/R=2) stands.
  rig.storage.drop_call = rig.storage.write_calls + 1;
  ConfigVerdict verdict{};
  CHECK(!rig.journal->submit_recovery(object.view(), now_ms, verdict).ok());
  CHECK(rig.journal->quarantined());
  CHECK(rig.floor_j() == 4);
  CHECK(rig.floor_r() == 2);
  rig.boot(now_ms += 100);
  CHECK(rig.journal->quarantined());  // pending intent + lost slots: no resume
  // The old authorization is spent — only the new floor's exact next lands.
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidArgument);
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 5, 3,
                     baseline.view(), baseline.view(), 11, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// Power row 2 (§5.6): durable intent, restore never started — the boot
// resumes the SAME baseline idempotently, no new authorization.
void test_power_intent_resume() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  const ConfigField baseline_fields[] = {sdk_u8(1, 2), sdk_bool(3, true)};
  const auto baseline = snapshot_of(baseline_fields, 2);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 12, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  CHECK(rig.provider.restore_calls == 0);
  rig.boot(now_ms += 100);  // cut before the first poll: restore never ran
  CHECK_OK(rig.boot_status_);
  // New intake stays Busy until the resumed restore proves the provider;
  // the recovery lane itself is closed while the adopt is healthy.
  endpoint::ControlChallengeQuery challenge{};
  challenge.config_namespace = 1;
  endpoint::EncodedServicePayload encoded{};
  CHECK(rig.journal->handle_challenge_query(challenge, now_ms, encoded).code ==
        StatusCode::Busy);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidState);
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 2);
  CHECK(rig.journal->active_snapshot().size == baseline.size);
  CHECK(rig.provider.live_.size == baseline.size);
  const endpoint::ControlStatus done = query_status(rig, dev_opid(12), now_ms);
  CHECK(done.phase == ConfigPhase::Active);
  CHECK(done.reason == ConfigReason::Ok);
}

// Power row 2b (§5.6): restore interrupted mid-flight — same idempotent
// resume, the partial provider write is re-applied wholesale.
void test_power_restore_midflight_resume() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  rig.provider.polls_to_complete = 3;
  const ConfigField baseline_fields[] = {sdk_u8(1, 2)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 13, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  rig.journal->poll(now_ms += 10);  // restore starts...
  rig.journal->poll(now_ms += 10);  // ...but never commits
  CHECK(rig.journal->quarantined());
  rig.boot(now_ms += 100);  // cut mid-restore
  CHECK_OK(rig.boot_status_);
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.provider.active_.size == baseline.size);
  CHECK(rig.provider.live_.size == baseline.size);
}

// Power row 4 (§5.6): provider done, readback pending — the resume never
// assumes success. It restores and readback-verifies even when the
// provider already holds the baseline, and re-applies wholesale when the
// provider diverged.
void test_power_resume_reverifies() {
  const ConfigField baseline_fields[] = {sdk_u8(1, 2)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ConfigVerdict verdict{};

  // Provider already complete: the restore still runs, then the readback
  // proof completes the ceremony.
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 18, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  CHECK(rig.provider.restore_calls == 0);
  rig.provider.seed(baseline.view());  // provider finished before the cut
  rig.boot(now_ms += 100);
  CHECK_OK(rig.boot_status_);
  drain(rig, now_ms);
  CHECK(rig.provider.restore_calls >= 1);  // no success assumption
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->active_snapshot().size == baseline.size);

  // Provider diverged: the same durable intent re-applies the baseline.
  TargetRig rig2(kBoot, true, true);
  t04_seed_loss(rig2, now_ms);
  build_dev_recovery(rig2, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 19, object);
  CHECK_OK(rig2.journal->submit_recovery(object.view(), now_ms, verdict));
  const ConfigField garbage_fields[] = {sdk_u8(9, 9)};
  const auto garbage = snapshot_of(garbage_fields, 1);
  rig2.provider.seed(garbage.view());
  rig2.boot(now_ms += 100);
  CHECK_OK(rig2.boot_status_);
  drain(rig2, now_ms);
  CHECK(rig2.journal->phase() == ConfigPhase::Active);
  CHECK(rig2.provider.live_.size == baseline.size);
  CHECK(std::memcmp(rig2.provider.live_.bytes.data(), baseline.bytes.data(),
                    baseline.size) == 0);
  CHECK(rig2.provider.active_.size == baseline.size);
}

// Power row 3 (§5.6): the readback fails — a terminal failure record
// lands, isolation continues, the next boot does NOT retry the spent
// authorization; a fresh one supersedes it.
void test_power_verify_failure_terminal() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  rig.provider.freeze_live = true;
  const ConfigField baseline_fields[] = {sdk_u8(1, 2)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 14, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Interrupted);
  // Intent J=4 plus the failure record J=5 are both consumed.
  CHECK(rig.floor_j() == 5);
  rig.boot(now_ms += 100);
  CHECK(rig.boot_status_.code == StatusCode::RecoveryRequired);
  CHECK(rig.journal->uncertain());  // failed intent: terminal, never resumed
  CHECK(!rig.journal->quarantined());
  // The spent authorization answers its terminal record, never Active/Ok.
  const endpoint::ControlStatus failed = query_status(rig, dev_opid(14), now_ms);
  CHECK(failed.phase == ConfigPhase::Interrupted);
  CHECK(failed.reason == ConfigReason::StorageFailure);
  // A fresh authorization supersedes (J=6/R=3 on the live floor).
  rig.provider.freeze_live = false;
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 6, 3,
                     baseline.view(), baseline.view(), 15, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(!rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// Power row 4 (§5.6): complete reserved, completion never written — the
// floor moved past the intent, so the boot parks uncertain without
// resuming; a fresh authorization recovers. Both slots stay valid here,
// isolating the ceremony-gap rule from the sibling-loss rules.
void test_power_complete_reserved_unwritten() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_uncertain_survivor(rig, now_ms);
  const ConfigField baseline_fields[] = {sdk_u8(1, 2)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 16, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  // Slots now [ACTIVE gen 3, intent gen 4], both valid: the complete's
  // floor reservation (J=5) lands, then both twin writes die.
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 5, 2);
  rig.boot(now_ms += 100);
  CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
  CHECK(rig.journal->uncertain());
  // No autonomous resume from the stale intent: new intake (not Busy)
  // and no restore running.
  CHECK(rig.provider.restore_calls == 0);
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 6, 3,
                     baseline.view(), baseline.view(), 17, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(!rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// Power row 5 (§5.6) over destroyed flash: a lone intent the floor moved
// past is spent — the boot parks uncertain even though the intent record
// itself is intact; only a fresh exact-next authorization resumes.
void test_power_spent_intent_parks() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  const ConfigField baseline_fields[] = {sdk_u8(1, 2)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 20, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  // Slots are [destroyed, intent J=4]: the complete's floor reservation
  // (J=5) lands, then both twin writes die.
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 5, 2);
  rig.boot(now_ms += 100);
  CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
  CHECK(rig.journal->uncertain());
  CHECK(rig.provider.restore_calls == 0);  // spent: no autonomous resume
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 6, 3,
                     baseline.view(), baseline.view(), 21, object);
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(!rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->active_snapshot().size == baseline.size);
}

// Power row 5 (§5.6): a lone completion — the boot re-verifies the
// provider and lands the identical twin before intake re-opens, with no
// new authorization.
void test_power_lone_complete_mirror() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  const ConfigField baseline_fields[] = {sdk_u8(1, 2), sdk_bool(2, true)};
  const auto baseline = snapshot_of(baseline_fields, 2);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 18, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  rig.journal->poll(now_ms += 10);  // the restore starts (no journal writes)
  // Cut the second twin's seal: slot 1 completes, slot 0 stays pending.
  rig.storage.drop_call = rig.storage.write_calls + 3;
  rig.journal->poll(now_ms += 10);  // commit + readback + partial twins
  CHECK(rig.journal->quarantined());  // completion not durable yet
  rig.boot(now_ms += 100);  // cut between the twin writes
  CHECK_OK(rig.boot_status_);
  drain(rig, now_ms);  // mirror leg: re-verify + land the twin
  CHECK(!rig.journal->quarantined());
  CHECK(!rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(std::memcmp(rig.storage.slots_[0].data(), rig.storage.slots_[1].data(),
                    64) == 0);
  const endpoint::ControlStatus done = query_status(rig, dev_opid(18), now_ms);
  CHECK(done.phase == ConfigPhase::Active);
  CHECK(done.reason == ConfigReason::Ok);
}

// Power row 6 (§5.6): twins durable, reply never sent — the boot
// re-confirms the provider, the same opid answers Active/Ok, and a
// re-received object runs no extra restore.
void test_power_twins_no_reply() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  const ConfigField baseline_fields[] = {sdk_u8(1, 2)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 19, object);
  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  const int restores = rig.provider.restore_calls;
  rig.boot(now_ms += 100);  // cut after the twins, before any reply
  CHECK_OK(rig.boot_status_);
  drain(rig, now_ms);  // reconfirmation restore, no new ceremony
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.provider.restore_calls == restores + 1);
  const endpoint::ControlStatus done = query_status(rig, dev_opid(19), now_ms);
  CHECK(done.phase == ConfigPhase::Active);
  CHECK(done.reason == ConfigReason::Ok);
  // Re-receiving the spent object refuses without touching the provider.
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidState);
  CHECK(rig.provider.restore_calls == restores + 1);
}

// Power row 7 (§5.6): the floor cannot be read — initialization fails
// and every intake refuses as uninitialized.
void test_power_floor_unreadable() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  rig.floor_storage.read_error = true;
  rig.boot(now_ms += 100);
  CHECK(!rig.boot_status_.ok());
  CHECK(!rig.journal->initialized());
  ConfigVerdict verdict{};
  const ConfigField patch[] = {sdk_u8(1, 2)};
  CHECK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict).code ==
        StatusCode::InvalidState);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2, ByteView{},
                     ByteView{}, 20, object);
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::InvalidState);
  endpoint::ControlChallengeQuery challenge{};
  endpoint::EncodedServicePayload encoded{};
  CHECK(rig.journal->handle_challenge_query(challenge, now_ms, encoded).code ==
        StatusCode::InvalidState);
  endpoint::ControlStatusQuery query{};
  CHECK(rig.journal->handle_status_query(query, now_ms, encoded).code ==
        StatusCode::InvalidState);
}

// Power row 8 (§5.6: empty floor) is test_floor_missing_stops_intake —
// initialization fails, all intake refuses, managed re-provisioning
// recovers. No duplicate here.

// SDK effective values (04 §4.2): omissions fill with the schema defaults;
// unknown ids fail closed — no silent defaulting into an effect.
void test_sdk_effective_values() {
  ConfigSdkEffective eff{};
  CHECK_OK(config_sdk_effective_values(ByteView{}, eff));
  CHECK(eff.values[0] == 2 && eff.values[1] == 1 && eff.values[2] == 1 &&
        eff.values[3] == 0);
  const ConfigField partial[] = {sdk_u8(1, 0)};
  const auto partial_snap = snapshot_of(partial, 1);
  CHECK_OK(config_sdk_effective_values(partial_snap.view(), eff));
  CHECK(eff.values[0] == 0 && eff.values[1] == 1 && eff.values[2] == 1 &&
        eff.values[3] == 0);
  const ConfigField full[] = {sdk_u8(1, 0), sdk_bool(2, false),
                              sdk_bool(3, false), sdk_u8(4, 2)};
  const auto full_snap = snapshot_of(full, 4);
  CHECK_OK(config_sdk_effective_values(full_snap.view(), eff));
  CHECK(eff.values[0] == 0 && eff.values[1] == 0 && eff.values[2] == 0 &&
        eff.values[3] == 2);
  const ConfigField unknown[] = {sdk_u8(5, 0)};
  const auto unknown_snap = snapshot_of(unknown, 1);
  CHECK(config_sdk_effective_values(unknown_snap.view(), eff).code ==
        StatusCode::Unsupported);
  const ConfigField bad_range[] = {sdk_u8(1, 3)};
  const auto bad_range_snap = snapshot_of(bad_range, 1);
  CHECK(config_sdk_effective_values(bad_range_snap.view(), eff).code ==
        StatusCode::InvalidArgument);
  ConfigField wrong_type = sdk_bool(2, true);
  wrong_type.type = ConfigFieldType::U8;
  const auto wrong_type_snap = snapshot_of(&wrong_type, 1);
  CHECK(config_sdk_effective_values(wrong_type_snap.view(), eff).code ==
        StatusCode::InvalidArgument);
  // Wire-order violations fail at decode, before any defaulting.
  const std::uint8_t unsorted[] = {0x02, 0x00, 0x01, 0x01, 0x00, 0x00,
                                   0x01, 0x00, 0x02, 0x01, 0x00, 0x02};
  CHECK(config_sdk_effective_values(ByteView{unsorted, sizeof(unsorted)}, eff)
            .code == StatusCode::ProtocolError);
  const std::uint8_t duplicate[] = {0x01, 0x00, 0x02, 0x01, 0x00, 0x02,
                                    0x01, 0x00, 0x02, 0x01, 0x00, 0x01};
  CHECK(config_sdk_effective_values(ByteView{duplicate, sizeof(duplicate)}, eff)
            .code == StatusCode::ProtocolError);
  const std::uint8_t truncated[] = {0x01, 0x00, 0x02, 0x01, 0x00};
  CHECK(config_sdk_effective_values(ByteView{truncated, sizeof(truncated)}, eff)
            .code == StatusCode::ProtocolError);
}

// Factory gate (04 §4.2): a provisioned-zero floor with no journal history
// and a stranger's provider blob restores the initial baseline behind the
// boot gate instead of adopting the blob — intake opens only after the
// readback proves it, and nothing is ever decided for the repair.
void test_factory_gate_stale_provider() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  const ConfigField stale_fields[] = {sdk_u8(1, 0)};
  const auto stale = snapshot_of(stale_fields, 1);
  rig.provider.seed(stale.view());
  rig.boot(now_ms);
  CHECK_OK(rig.boot_status_);
  ConfigVerdict verdict{};
  const ConfigField patch[] = {sdk_u8(1, 1)};
  CHECK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict).code ==
        StatusCode::Busy);
  CHECK(rig.provider.restore_calls == 0);  // restore starts in maintenance
  drain(rig, now_ms);
  CHECK(rig.provider.restore_calls == 1);
  CHECK(rig.provider.active_.size == 0);  // initial baseline restored
  CHECK(rig.floor_j() == 0);
  CHECK(rig.floor_r() == 0);
  CHECK(rig.journal->phase() == ConfigPhase::Idle);  // repair decides nothing
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
  drain(rig, now_ms);
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// Factory gate, unreadable provider: privileged intake stops until managed
// re-provisioning — the journal never opens on unknown provider state.
void test_factory_gate_unreadable_provider() {
  TargetRig rig;
  MonotonicMs now_ms = 1000;
  rig.provider.fail_reads = 1;  // the factory probe read fails
  rig.boot(now_ms);
  CHECK(rig.boot_status_.code == StatusCode::RecoveryRequired);
  CHECK(!rig.journal->initialized());
  endpoint::ControlChallengeQuery query{};
  endpoint::EncodedServicePayload encoded{};
  CHECK(rig.journal->handle_challenge_query(query, now_ms, encoded).code ==
        StatusCode::InvalidState);
  // Managed re-provisioning: a readable provider opens the journal again.
  rig.boot(now_ms += 10);
  CHECK_OK(rig.boot_status_);
  ConfigVerdict verdict{};
  const ConfigField patch[] = {sdk_u8(1, 1)};
  CHECK_OK(drive_update(rig, patch, 1, now_ms, 0, ByteView{}, verdict));
}

// Capability refusal (§5.5): validate_recovery answers Unsupported before
// the floor reservation — the journal stays quarantined, the counters are
// unconsumed, and the SAME authorization lands once the provider can prove it.
void test_recovery_unsupported_baseline() {
  TargetRig rig(kBoot, true, true);
  MonotonicMs now_ms = 1000;
  t04_seed_loss(rig, now_ms);
  rig.provider.validate_recovery_result =
      Status::error(StatusCode::Unsupported, "unverified field change");
  const ConfigField baseline_fields[] = {sdk_u8(1, 2)};
  const auto baseline = snapshot_of(baseline_fields, 1);
  ByteBuffer<kConfigPermitObjectMax> object{};
  build_dev_recovery(rig, endpoint::kRcr2ModeReprovision, 4, 2,
                     baseline.view(), baseline.view(), 22, object);
  ConfigVerdict verdict{};
  CHECK(rig.journal->submit_recovery(object.view(), now_ms, verdict).code ==
        StatusCode::Unsupported);
  CHECK(rig.provider.validate_recovery_calls == 1);
  CHECK(rig.journal->quarantined());
  CHECK(rig.floor_j() == 3);  // unconsumed: the authorization survives
  CHECK(rig.floor_r() == 1);
  rig.provider.validate_recovery_result = Status::success();
  CHECK_OK(rig.journal->submit_recovery(object.view(), now_ms, verdict));
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
}

// --- Signed golden vectors: Rust-issued objects through C++ verifiers ---------
// The checked-in objects under protocol/config-signed-golden are the
// cross-language contract (§9.1: the main interop proof is the Rust
// issuer's signatures verifying under C++ micro-ecc/TrustView). The Rust
// suite re-issues every vector byte-identically; here the SAME bytes are
// decoded and verified through the production Dev/COSE/TrustView
// verifiers, and the two reprovision objects run the full recovery
// ceremony on a real ConfigJournal. Every asserted field below is a
// fixture pinned by the Rust issuer (authority 0x42, generation 1,
// network 0xAAAA, target 0x99) — a mismatch is a wire break, not drift.

struct SignedGolden {
  std::string name;
  std::string profile;
  std::uint8_t kind{0};
  std::uint8_t mode{0};
  std::uint64_t authority{0};
  std::uint32_t authority_generation{0};
  std::uint64_t authority_sequence{0};
  std::array<std::uint8_t, 16> operation_id{};
  std::array<std::uint8_t, 32> dev_key{};
  std::vector<std::uint8_t> canonical;
  std::vector<std::uint8_t> object;
};

// The vectors are flat one-key-per-line JSON (quoted strings or bare
// numbers), the same shape the endpoint-vector reader takes.
std::map<std::string, std::string> read_flat_json(const std::string& path) {
  std::map<std::string, std::string> out;
  std::ifstream file(path);
  CHECK(file.good());
  std::string line;
  while (std::getline(file, line)) {
    const std::size_t key_begin = line.find('"');
    if (key_begin == std::string::npos) continue;
    const std::size_t key_end = line.find('"', key_begin + 1);
    if (key_end == std::string::npos) continue;
    const std::size_t colon = line.find(':', key_end + 1);
    if (colon == std::string::npos) continue;
    std::size_t value_begin = line.find_first_not_of(" \t", colon + 1);
    if (value_begin == std::string::npos) continue;
    std::string value;
    if (line[value_begin] == '"') {
      const std::size_t value_end = line.find('"', value_begin + 1);
      if (value_end == std::string::npos) continue;
      value = line.substr(value_begin + 1, value_end - value_begin - 1);
    } else {
      const std::size_t value_end = line.find_first_of(", \t}", value_begin);
      value = line.substr(value_begin, value_end - value_begin);
    }
    out.emplace(line.substr(key_begin + 1, key_end - key_begin - 1), value);
  }
  return out;
}

std::uint8_t golden_nibble(const char c) {
  if (c >= '0' && c <= '9') return static_cast<std::uint8_t>(c - '0');
  if (c >= 'a' && c <= 'f') return static_cast<std::uint8_t>(c - 'a' + 10);
  return static_cast<std::uint8_t>(c - 'A' + 10);
}

std::vector<std::uint8_t> golden_unhex(const std::string& hex) {
  CHECK(hex.size() % 2 == 0);
  std::vector<std::uint8_t> out(hex.size() / 2);
  for (std::size_t i = 0; i < out.size(); ++i) {
    out[i] = static_cast<std::uint8_t>(golden_nibble(hex[2 * i]) * 16 +
                                        golden_nibble(hex[2 * i + 1]));
  }
  return out;
}

SignedGolden load_signed_golden(const char* name) {
  const std::string path =
      std::string(ROUTELOOM_CONFIG_SIGNED_GOLDEN_DIR) + "/" + name + ".json";
  const std::map<std::string, std::string> json = read_flat_json(path);
  SignedGolden golden;
  golden.name = json.at("name");
  golden.profile = json.at("profile");
  golden.kind = static_cast<std::uint8_t>(std::stoul(json.at("kind")));
  golden.mode = static_cast<std::uint8_t>(std::stoul(json.at("mode")));
  golden.authority = std::stoull(json.at("authority"));
  golden.authority_generation =
      static_cast<std::uint32_t>(std::stoul(json.at("authority_generation")));
  golden.authority_sequence = std::stoull(json.at("authority_sequence"));
  CHECK(json.at("network") == "43690");  // 0xAAAA, pinned by the issuer
  CHECK(json.at("target") == "153");     // 0x99
  CHECK(json.at("config_namespace") == "1");
  CHECK(json.at("schema") == "1");
  CHECK(json.at("codec") == "config_signed_object");
  CHECK(json.at("expect") == "ok");
  const std::vector<std::uint8_t> opid = golden_unhex(json.at("operation_id_hex"));
  CHECK(opid.size() == golden.operation_id.size());
  std::memcpy(golden.operation_id.data(), opid.data(), opid.size());
  const std::vector<std::uint8_t> key = golden_unhex(json.at("dev_key_hex"));
  CHECK(key.size() == golden.dev_key.size());
  std::memcpy(golden.dev_key.data(), key.data(), key.size());
  golden.canonical = golden_unhex(json.at("canonical_hex"));
  golden.object = golden_unhex(json.at("object_hex"));
  return golden;
}

ConfigPermitContext golden_context() {
  ConfigPermitContext context{};
  context.network = 0xAAAA;
  context.target = 0x99;
  context.config_namespace = 1;
  context.authorized_issuer = 0x42;
  context.authority_generation = 1;
  return context;
}

// The Rust test COSE authority key (config.rs cose_signer(): authority
// 0x42, scalar [0x5E; 32]); the public half is derived here with the
// same micro-ecc the verifier runs — no key bytes are pinned twice.
routeloom_test::TestKeyPair golden_cose_key() {
  return routeloom_test::test_keypair(0x5E);
}

void check_golden_permit_fields(const SignedGolden& golden,
                                const std::uint8_t opid_tag) {
  CHECK(golden.kind == 3);
  CHECK(golden.profile == "dev-hmac-sha256-16" ||
        golden.profile == "rlcp1-cose-esp256");
  CHECK(golden.authority == 0x42);
  CHECK(golden.authority_generation == 1);
  CHECK(golden.authority_sequence == 9);
  std::array<std::uint8_t, 16> expect_opid{};
  expect_opid.fill(opid_tag);
  CHECK(golden.operation_id == expect_opid);
  // The fixture behind the vector: challenge (boot 7, nonce [D2; 16],
  // revision 4 over {f1:u8=1}) noted at t=1000, proposed at t=1100 with
  // patch {f1:u8=2} and the whole remaining budget (30000-100-100).
  endpoint::ConfigCommand command{};
  CHECK_OK(endpoint::config_command_decode(
      ByteView{golden.canonical.data(), golden.canonical.size()}, command));
  CHECK(command.config_namespace == 1);
  CHECK(command.schema == 1);
  CHECK(command.network == 0xAAAA);
  CHECK(command.target == 0x99);
  CHECK(command.authority == 0x42);
  CHECK(command.authority_generation == 1);
  CHECK(command.authority_sequence == 9);
  CHECK(command.operation_id == expect_opid);
  CHECK(command.expected_revision == 4);
  CHECK(command.next_revision == 5);
  CHECK(command.target_boot == 7);
  std::array<std::uint8_t, 16> expect_nonce{};
  expect_nonce.fill(0xD2);
  CHECK(command.challenge_nonce == expect_nonce);
  CHECK(command.apply_within_ms == 29800);
  CHECK(command.field_count == 1);
  CHECK(command.fields[0].field_id == 1);
  CHECK(command.fields[0].type == endpoint::ConfigFieldType::U8);
  CHECK(command.fields[0].value_size == 1);
  CHECK(command.fields[0].value[0] == 2);
}

void check_golden_recovery_fields(const SignedGolden& golden,
                                  const std::uint8_t opid_tag) {
  CHECK(golden.kind == 4);
  CHECK(golden.profile == "dev-hmac-sha256-16" ||
        golden.profile == "rlcp1-cose-esp256");
  CHECK(golden.authority == 0x42);
  CHECK(golden.authority_generation == 1);
  std::array<std::uint8_t, 16> expect_opid{};
  expect_opid.fill(opid_tag);
  CHECK(golden.operation_id == expect_opid);
  // Both recovery vectors attest the exact-next floor (J=4, R=8); adopt
  // binds the proven survivor [AB; 32] by hash alone, reprovision
  // carries {f1:u8=2} (raw TLV 00 01 02 00 01 02).
  endpoint::ConfigRecoveryIntent intent{};
  CHECK_OK(endpoint::config_recovery_decode(
      ByteView{golden.canonical.data(), golden.canonical.size()}, intent));
  CHECK(intent.config_namespace == 1);
  CHECK(intent.schema == 1);
  CHECK(intent.network == 0xAAAA);
  CHECK(intent.target == 0x99);
  CHECK(intent.authority == 0x42);
  CHECK(intent.authority_generation == 1);
  CHECK(intent.new_store_generation == 4);
  CHECK(intent.new_revision == 8);
  if (golden.mode == endpoint::kRcr2ModeAdoptKnown) {
    CHECK(golden.authority_sequence == 10);
    CHECK(intent.authority_sequence == 10);
    CHECK(intent.mode == endpoint::kRcr2ModeAdoptKnown);
    CHECK(intent.baseline.size == 0);
    std::array<std::uint8_t, 32> expect_hash{};
    expect_hash.fill(0xAB);
    CHECK(intent.snapshot_hash == expect_hash);
  } else {
    CHECK(golden.mode == endpoint::kRcr2ModeReprovision);
    CHECK(golden.authority_sequence == 11);
    CHECK(intent.authority_sequence == 11);
    CHECK(intent.mode == endpoint::kRcr2ModeReprovision);
    const std::uint8_t expect_baseline[] = {0x00, 0x01, 0x02, 0x00, 0x01, 0x02};
    CHECK(intent.baseline.size == sizeof(expect_baseline));
    CHECK(std::memcmp(intent.baseline.bytes.data(), expect_baseline,
                      sizeof(expect_baseline)) == 0);
    // The signed hash is the baseline's own domain hash — recomputed
    // here by the C++ production hasher, so this CHECK compares the two
    // languages' hashes over the same bytes.
    Digest256 expect_hash{};
    CHECK_OK(config_snapshot_hash(1, 1, intent.baseline.view(), expect_hash));
    CHECK(intent.snapshot_hash == expect_hash);
  }
}

// T07/T08 consume leg: every Rust-signed vector decodes to its pinned
// fixture and verifies under the matching production verifier — dev
// HMAC, static COSE, and a TrustView resolving the COSE key from a live
// store. The verified payload must equal the canonical byte for byte.
void test_signed_golden_verify() {
  const ConfigPermitContext context = golden_context();
  const routeloom_test::TestKeyPair cose_key = golden_cose_key();

  const SignedGolden dev_permit = load_signed_golden("dev_permit");
  const SignedGolden cose_permit = load_signed_golden("cose_permit");
  check_golden_permit_fields(dev_permit, 0x51);
  check_golden_permit_fields(cose_permit, 0x54);

  const SignedGolden dev_adopt = load_signed_golden("dev_recovery_adopt");
  const SignedGolden cose_adopt = load_signed_golden("cose_recovery_adopt");
  check_golden_recovery_fields(dev_adopt, 0x52);
  check_golden_recovery_fields(cose_adopt, 0x55);

  const SignedGolden dev_reprovision =
      load_signed_golden("dev_recovery_reprovision");
  const SignedGolden cose_reprovision =
      load_signed_golden("cose_recovery_reprovision");
  check_golden_recovery_fields(dev_reprovision, 0x53);
  check_golden_recovery_fields(cose_reprovision, 0x56);

  // Same issuer inputs under both profiles bind the same hashes.
  endpoint::ConfigCommand dev_command{}, cose_command{};
  CHECK_OK(endpoint::config_command_decode(
      ByteView{dev_permit.canonical.data(), dev_permit.canonical.size()},
      dev_command));
  CHECK_OK(endpoint::config_command_decode(
      ByteView{cose_permit.canonical.data(), cose_permit.canonical.size()},
      cose_command));
  CHECK(dev_command.base_snapshot_hash == cose_command.base_snapshot_hash);
  CHECK(dev_command.next_snapshot_hash == cose_command.next_snapshot_hash);
  endpoint::ConfigRecoveryIntent dev_intent{}, cose_intent{};
  CHECK_OK(endpoint::config_recovery_decode(
      ByteView{dev_reprovision.canonical.data(), dev_reprovision.canonical.size()},
      dev_intent));
  CHECK_OK(endpoint::config_recovery_decode(
      ByteView{cose_reprovision.canonical.data(), cose_reprovision.canonical.size()},
      cose_intent));
  CHECK(dev_intent.snapshot_hash == cose_intent.snapshot_hash);

  // Dev profile through the production HMAC verifier.
  DevConfigAuthorityVerifier dev_verifier(
      ByteView{dev_permit.dev_key.data(), dev_permit.dev_key.size()});
  endpoint::EncodedConfigCommand permit_payload{};
  bool verified = false;
  CHECK_OK(dev_verifier.verify_permit(
      context, ByteView{dev_permit.object.data(), dev_permit.object.size()},
      permit_payload, verified));
  CHECK(verified);
  CHECK(permit_payload.size == dev_permit.canonical.size());
  CHECK(std::memcmp(permit_payload.bytes.data(), dev_permit.canonical.data(),
                    permit_payload.size) == 0);
  endpoint::EncodedRecoveryIntent recovery_payload{};
  for (const SignedGolden* golden : {&dev_adopt, &dev_reprovision}) {
    verified = false;
    recovery_payload.clear();
    CHECK_OK(dev_verifier.verify_recovery(
        context, ByteView{golden->object.data(), golden->object.size()},
        recovery_payload, verified));
    CHECK(verified);
    CHECK(recovery_payload.size == golden->canonical.size());
    CHECK(std::memcmp(recovery_payload.bytes.data(), golden->canonical.data(),
                      recovery_payload.size) == 0);
  }

  // COSE profile through the static production verifier.
  CoseEsp256AuthorityVerifier cose_verifier;
  cose_verifier.provision(
      0x42, ByteView{cose_key.pub.data(), cose_key.pub.size()});
  CHECK(cose_verifier.ready());
  verified = false;
  permit_payload.clear();
  CHECK_OK(cose_verifier.verify_permit(
      context, ByteView{cose_permit.object.data(), cose_permit.object.size()},
      permit_payload, verified));
  CHECK(verified);
  CHECK(permit_payload.size == cose_permit.canonical.size());
  CHECK(std::memcmp(permit_payload.bytes.data(), cose_permit.canonical.data(),
                    permit_payload.size) == 0);
  for (const SignedGolden* golden : {&cose_adopt, &cose_reprovision}) {
    verified = false;
    recovery_payload.clear();
    CHECK_OK(cose_verifier.verify_recovery(
        context, ByteView{golden->object.data(), golden->object.size()},
        recovery_payload, verified));
    CHECK(verified);
    CHECK(recovery_payload.size == golden->canonical.size());
    CHECK(std::memcmp(recovery_payload.bytes.data(), golden->canonical.data(),
                      recovery_payload.size) == 0);
  }

  // And through a TrustView resolving the same key live from a store —
  // the §9.1 Rust-signer-to-TrustView leg. (The manifest delivery path
  // itself is T02's; here the store is the key-resolution vehicle.)
  routeloom_test::FaultyTrustStorage trust_storage;
  TrustStore trust_store(trust_storage);
  CHECK_OK(trust_store.initialize());
  TrustImage image = routeloom_test::test_image(
      1, 0xAAAA, routeloom_test::test_keypair(0x11), 0x100);
  image.keys[0] = routeloom_test::test_key_record(
      0x42, 1, cose_key.pub, TrustKeyStatus::Active);
  image.key_count = 1;
  CHECK_OK(trust_store.commit_image(image));
  TrustView view(trust_store);
  CHECK(view.ready());
  verified = false;
  permit_payload.clear();
  CHECK_OK(view.verify_permit(
      context, ByteView{cose_permit.object.data(), cose_permit.object.size()},
      permit_payload, verified));
  CHECK(verified);
  CHECK(permit_payload.size == cose_permit.canonical.size());
  for (const SignedGolden* golden : {&cose_adopt, &cose_reprovision}) {
    verified = false;
    recovery_payload.clear();
    CHECK_OK(view.verify_recovery(
        context, ByteView{golden->object.data(), golden->object.size()},
        recovery_payload, verified));
    CHECK(verified);
    CHECK(recovery_payload.size == golden->canonical.size());
    CHECK(std::memcmp(recovery_payload.bytes.data(), golden->canonical.data(),
                      recovery_payload.size) == 0);
  }
}

// Deliver one Rust-signed reprovision vector through a real ConfigJournal:
// the rig is retargeted at the golden context (the envelopes bind
// 0xAAAA/0x99/0x42/gen-1), seeded into the post-loss state the vectors
// attest (floor J=3/R=7, old 6 B provider snapshot, both slots
// destroyed), then must recover to Active on {f1:u8=2} and stay there
// across a reboot.
void golden_reprovision_delivery(const SignedGolden& golden, const bool with_cose,
                                 const routeloom_test::TestKeyPair& cose_key) {
  TargetRig rig(kBoot, true, !with_cose, with_cose);
  if (with_cose) {
    rig.cose_verifier.provision(
        0x42, ByteView{cose_key.pub.data(), cose_key.pub.size()});
  } else {
    rig.dev_verifier = DevConfigAuthorityVerifier(
        ByteView{golden.dev_key.data(), golden.dev_key.size()});
  }
  rig.config.network = 0xAAAA;
  rig.config.target = 0x99;
  rig.config.authorized_issuer = 0x42;
  rig.config.authority_generation = 1;
  MonotonicMs now_ms = 1000;
  seed_floor(rig.floor_storage, rig.config.network, rig.config.target,
             rig.config.config_namespace, rig.config.schema, 3, 7);
  const ConfigField old_fields[] = {sdk_u8(1, 1)};
  const auto old_snapshot = snapshot_of(old_fields, 1);
  rig.provider.seed(old_snapshot.view());
  rig.storage.fill(0, 0xEE);
  rig.storage.fill(1, 0xEE);
  rig.boot(now_ms);
  CHECK(rig.boot_status_.code == StatusCode::IntegrityError);
  CHECK(rig.journal->quarantined());

  ConfigVerdict verdict{};
  CHECK_OK(rig.journal->submit_recovery(
      ByteView{golden.object.data(), golden.object.size()}, now_ms, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);
  CHECK(rig.journal->quarantined());  // isolated until the readback proves it
  drain(rig, now_ms);
  CHECK(!rig.journal->quarantined());
  CHECK(!rig.journal->uncertain());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->decision_revision() == 8);
  CHECK(rig.journal->active_revision() == 8);
  // The attested reservation (J=4/R=8) plus the completion record (J=5).
  CHECK(rig.floor_j() == 5);
  CHECK(rig.floor_r() == 8);
  const std::uint8_t expect_baseline[] = {0x00, 0x01, 0x02, 0x00, 0x01, 0x02};
  const ByteView active = rig.journal->active_snapshot();
  CHECK(active.size == sizeof(expect_baseline));
  CHECK(std::memcmp(active.data, expect_baseline, sizeof(expect_baseline)) == 0);
  Digest256 expect_hash{};
  CHECK_OK(config_snapshot_hash(rig.config.config_namespace, rig.config.schema,
                                active, expect_hash));
  CHECK(rig.journal->active_hash() == expect_hash);
  CHECK(rig.provider.active_.size == sizeof(expect_baseline));
  CHECK(std::memcmp(rig.provider.active_.bytes.data(), expect_baseline,
                    sizeof(expect_baseline)) == 0);
  CHECK(rig.provider.live_.size == sizeof(expect_baseline));
  CHECK(std::memcmp(rig.provider.live_.bytes.data(), expect_baseline,
                    sizeof(expect_baseline)) == 0);

  // The recovery survives a reboot: same storage, fresh RAM, still Active
  // on the reprovisioned baseline.
  rig.boot(now_ms += 1000);
  CHECK_OK(rig.boot_status_);
  CHECK(!rig.journal->quarantined());
  CHECK(rig.journal->phase() == ConfigPhase::Active);
  CHECK(rig.journal->active_revision() == 8);
  const ByteView durable = rig.journal->active_snapshot();
  CHECK(durable.size == sizeof(expect_baseline));
  CHECK(std::memcmp(durable.data, expect_baseline, sizeof(expect_baseline)) == 0);
  CHECK(rig.journal->active_hash() == expect_hash);
}

void test_signed_golden_delivery() {
  const routeloom_test::TestKeyPair cose_key = golden_cose_key();
  golden_reprovision_delivery(load_signed_golden("dev_recovery_reprovision"),
                              false, cose_key);
  golden_reprovision_delivery(load_signed_golden("cose_recovery_reprovision"),
                              true, cose_key);
}

// --- T06: disaster generation migration ---------------------------------------
// The real SingleAuthority ledger is destroyed and rebuilt, quarantines,
// refuses the old generation, and recovers under a new one; the
// post-recover (generation, sequence) state feeds every later issuance —
// no test-side pin is ever swapped (§9.2 T06). The existing target, a
// TrustView deployment still holding only the old key, rejects the new
// generation until a signed root RTM1 lands; after the update plus a
// restart it accepts the new generation and rejects the old key. All
// crypto is real: ledger state machine, P-256 envelopes, trust-store
// commits, journal, floor and provider.

const routeloom_test::TestKeyPair kT06Root = routeloom_test::test_keypair(0x11);
const routeloom_test::TestKeyPair kT06AuthG = routeloom_test::test_keypair(0x33);
const routeloom_test::TestKeyPair kT06AuthGPrime = routeloom_test::test_keypair(0x34);

std::array<std::uint8_t, 16> t06_opid(const std::uint8_t tag) {
  std::array<std::uint8_t, 16> opid{};
  opid.fill(0x60);
  opid[0] = 0x61;
  opid[1] = tag;
  return opid;
}

// The COSE envelope both T06 lanes share (mirrors make_permit in the
// trust-view tests): byte-exact protected header {1:-9, 4:bstr8(kid)},
// Sig_structure over the lane's own AAD, deterministic low-S ECDSA.
Status t06_cose_sign(const ByteView canonical, const ByteView aad,
                     const std::uint64_t kid,
                     const std::array<std::uint8_t, 32>& priv,
                     ByteBuffer<kConfigPermitObjectMax>& out) {
  out.clear();
  ByteBuffer<13> protected_bytes{};
  ByteWriter prot(protected_bytes.writable());
  Status status = prot.write_u8(0xA2);  // map(2)
  if (status) status = prot.write_u8(0x01);
  if (status) status = prot.write_u8(0x28);  // -9 (ESP256)
  if (status) status = prot.write_u8(0x04);
  if (status) status = prot.write_u8(0x48);  // bstr(8)
  if (status) status = prot.write_u64(kid);
  if (!status) return status;
  protected_bytes.size = prot.size();
  ByteBuffer<kCosePermitMax + 64> sig_structure{};
  status = cose_sig_structure(protected_bytes.view(), aad, canonical,
                              sig_structure);
  if (!status) return status;
  ScopeDigest digest{};
  sha256(sig_structure.view(), digest);
  std::array<std::uint8_t, 64> signature{};
  if (!routeloom_test::sign_digest_low_s(priv, digest, signature)) {
    return Status::error(StatusCode::InternalError, "t06 sign failed");
  }
  ByteWriter writer(out.writable());
  status = writer.write_u8(0xD2);  // tag 18
  if (status) status = writer.write_u8(0x84);  // array(4)
  if (status) {
    status = routeloom_test::cbor_put_bstr(writer, protected_bytes.view());
  }
  if (status) status = writer.write_u8(0xA0);  // empty unprotected map
  if (status) status = routeloom_test::cbor_put_bstr(writer, canonical);
  if (status) {
    status = routeloom_test::cbor_put_bstr(
        writer, ByteView{signature.data(), signature.size()});
  }
  if (!status) return status;
  out.size = writer.size();
  return Status::success();
}

Status t06_make_permit(const ConfigCommand& command,
                       const std::array<std::uint8_t, 32>& priv,
                       ByteBuffer<kConfigPermitObjectMax>& out) {
  endpoint::EncodedConfigCommand canonical{};
  Status status = endpoint::config_command_encode(command, canonical);
  if (!status) return status;
  ByteBuffer<kConfigPermitAadSize> aad{};
  status = config_permit_aad(command.network, command.target,
                             command.config_namespace, aad);
  if (!status) return status;
  return t06_cose_sign(canonical.view(), aad.view(), command.authority, priv,
                       out);
}

Status t06_make_recovery(const endpoint::ConfigRecoveryIntent& intent,
                         const std::array<std::uint8_t, 32>& priv,
                         ByteBuffer<kConfigPermitObjectMax>& out) {
  endpoint::EncodedRecoveryIntent canonical{};
  Status status = endpoint::config_recovery_encode(intent, canonical);
  if (!status) return status;
  ByteBuffer<kConfigRecoveryAadSize> aad{};
  status = config_recovery_aad(intent.network, intent.target,
                               intent.config_namespace, aad);
  if (!status) return status;
  return t06_cose_sign(canonical.view(), aad.view(), intent.authority, priv,
                       out);
}

// The RootSigner path (mirrors make_manifest in the trust-manifest
// tests): RLT1 body, committed-network AAD, assembled manifest.
void t06_make_manifest(const TrustImage& image, const std::uint64_t root_id,
                       const std::array<std::uint8_t, 32>& priv,
                       ByteBuffer<kTrustManifestObjectMax>& out) {
  ByteBuffer<kTrustImageContentMax> content{};
  CHECK_OK(trust_image_body_encode(image, content));
  ByteBuffer<kTrustManifestProtectedSize> protected_bytes{};
  CHECK_OK(trust_manifest_protected(root_id, protected_bytes));
  ByteBuffer<kTrustManifestAadSize> aad{};
  CHECK_OK(trust_manifest_aad(image.network, aad));
  ByteBuffer<kTrustManifestSigMax> sig_structure{};
  CHECK_OK(trust_manifest_sig_structure(protected_bytes.view(), aad.view(),
                                        content.view(), sig_structure));
  ScopeDigest digest{};
  sha256(sig_structure.view(), digest);
  std::array<std::uint8_t, 64> signature{};
  CHECK(routeloom_test::sign_digest_low_s(priv, digest, signature));
  CHECK_OK(trust_manifest_assemble(content.view(), root_id,
                                   ByteView{signature.data(), signature.size()},
                                   out));
}

// A TrustView-backed target: real SecurityFloorStore, TrustStore,
// TrustView (floor-attached, as trust-managed deployments run) and
// ConfigJournal over storage fakes. restart() destroys every RAM object
// and rebuilds from the same storages — nothing re-seeded, never
// re-pinned (the configured generation pin is set once at deployment).
struct T06Target {
  ConfigJournalConfig config{};
  FakeJournalStorage storage{};
  FakeFloorStore floor_storage{};
  routeloom_test::FaultyTrustStorage trust_storage{};
  CountingEntropy entropy{};
  ConfigRateLimiter rate{};
  FakeProvider provider{};
  FakeMaintenanceGate gate{};
  std::unique_ptr<SecurityFloorStore> floor;
  std::unique_ptr<TrustStore> trust;
  std::unique_ptr<TrustView> view;
  std::unique_ptr<ConfigJournal> journal{};
  Status boot_status_ = Status::success();

  T06Target() {
    config.network = kNet;
    config.target = kTarget;
    config.config_namespace = endpoint::kConfigNamespaceSdk;
    config.schema = 1;
    config.boot_incarnation = kBoot;
    config.authorized_issuer = kAuthority;
    config.authority_generation = 1;
    config.challenge_valid_ms = kConfigChallengeMaxMs;
    seed_floor(floor_storage, config.network, config.target,
               config.config_namespace, config.schema, 0, 0);
    build(1000);
  }
  void build(const MonotonicMs now_ms) {
    floor = std::make_unique<SecurityFloorStore>(floor_storage);
    CHECK_OK(floor->initialize());
    trust = std::make_unique<TrustStore>(trust_storage);
    CHECK_OK(trust->initialize());
    view = std::make_unique<TrustView>(*trust);
    view->attach_floor(floor.get());
    journal = std::make_unique<ConfigJournal>(config, storage, *floor, *view,
                                              entropy, rate, &provider, nullptr,
                                              &gate);
    boot_status_ = journal->initialize(now_ms);
  }
  void restart(const MonotonicMs now_ms) {
    journal.reset();
    view.reset();
    trust.reset();
    floor.reset();
    build(now_ms);
  }
  std::uint32_t floor_j() {
    SecurityFloorState state{};
    CHECK_OK(floor->read(state));
    const SecurityFloorEntry* entry =
        SecurityFloorStore::entry_for(state, config.config_namespace);
    CHECK(entry != nullptr);
    return entry->store_floor;
  }
  std::uint64_t floor_r() {
    SecurityFloorState state{};
    CHECK_OK(floor->read(state));
    const SecurityFloorEntry* entry =
        SecurityFloorStore::entry_for(state, config.config_namespace);
    CHECK(entry != nullptr);
    return entry->decision_floor;
  }
  void drain(MonotonicMs& now_ms, const int polls = 8) {
    for (int i = 0; i < polls; ++i) journal->poll(now_ms += 10);
  }
};

void t06_provision_trust(T06Target& target) {
  TrustImage image =
      routeloom_test::test_image(1, kNet, kT06Root, 0x100);
  image.keys[0] = routeloom_test::test_key_record(
      kAuthority, 1, kT06AuthG.pub, TrustKeyStatus::Active);
  image.key_count = 1;
  CHECK_OK(target.trust->commit_image(image));
}

// Intake is limited to one P-256 verify start per 5 s and two accepts
// per 60 s device-wide; the ceremony spans realistic time so every
// submit is admitted. Challenges are queried fresh at each step, so the
// jumps never expire one.
void t06_expiry_gap(MonotonicMs& now_ms) { now_ms += 61000; }

Digest256 t06_digest(const ByteView bytes) {
  ScopeDigest digest{};
  sha256(bytes, digest);
  Digest256 out{};
  std::memcpy(out.data(), digest.data(), out.size());
  return out;
}

// Reserve one ledger operation binding the approved content bytes; the
// returned (generation, sequence) is what the signed object must bind.
// The commit lands after signing, binding the finished envelope.
AuthorityOperation t06_issue_op(SingleAuthority& authority,
                                const ByteView content) {
  AuthorityOperation op{};
  CHECK_OK(authority.build_operation(AuthorityOperationKind::RemoteConfig,
                                     t06_digest(content), op));
  return op;
}

void t06_commit_op(SingleAuthority& authority, const AuthorityOperation& op,
                   const ByteView envelope) {
  CHECK_OK(authority.apply_remote_config(op, t06_digest(envelope), true));
}

// Challenge -> ledger-built command -> COSE sign -> ledger commit ->
// submit. The command's (generation, sequence) always come from the
// live ledger handover, never from a test constant.
Status t06_drive_permit(T06Target& target, SingleAuthority& authority,
                        const ConfigField* patch, const std::uint16_t patch_count,
                        const std::array<std::uint8_t, 32>& auth_priv,
                        const std::uint64_t expected_revision,
                        const ByteView base_snapshot, MonotonicMs& now_ms,
                        ConfigVerdict& verdict, const std::uint8_t opid_tag,
                        ConfigCommand* command_out = nullptr) {
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = target.config.config_namespace;
  query.schema = target.config.schema;
  query.client_nonce = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2, 3, 4, opid_tag, 6};
  endpoint::EncodedServicePayload encoded{};
  Status status =
      target.journal->handle_challenge_query(query, now_ms, encoded);
  if (!status) return status;
  endpoint::ControlChallenge challenge{};
  status = endpoint::control_challenge_decode(encoded.view(), challenge);
  if (!status) return status;
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  status = config_patch_apply(base_snapshot, patch, patch_count, next, changed);
  if (!status) return status;
  Digest256 base_hash{}, next_hash{};
  status = config_snapshot_hash(target.config.config_namespace,
                                target.config.schema, base_snapshot, base_hash);
  if (!status) return status;
  status = config_snapshot_hash(target.config.config_namespace,
                                target.config.schema, next.view(), next_hash);
  if (!status) return status;
  ByteBuffer<endpoint::kConfigSnapshotMax> patch_tlv{};
  status = config_tlv_encode(patch, patch_count, patch_tlv);
  if (!status) return status;
  const AuthorityOperation op = t06_issue_op(authority, patch_tlv.view());

  ConfigCommand command{};
  command.config_namespace = target.config.config_namespace;
  command.schema = target.config.schema;
  command.network = target.config.network;
  command.target = target.config.target;
  command.authority = target.config.authorized_issuer;
  command.authority_generation = op.generation;
  command.authority_sequence = op.sequence;
  command.operation_id = t06_opid(opid_tag);
  command.expected_revision = expected_revision;
  command.next_revision = expected_revision + 1;
  command.base_snapshot_hash = base_hash;
  command.next_snapshot_hash = next_hash;
  command.target_boot = target.config.boot_incarnation;
  command.challenge_nonce = challenge.challenge_nonce;
  command.apply_within_ms = challenge.valid_for_ms;
  command.field_count = patch_count;
  for (std::uint16_t i = 0; i < patch_count; ++i) command.fields[i] = patch[i];
  if (command_out != nullptr) *command_out = command;

  ByteBuffer<kConfigPermitObjectMax> permit{};
  status = t06_make_permit(command, auth_priv, permit);
  if (!status) return status;
  t06_commit_op(authority, op, permit.view());
  return target.journal->submit_permit(permit.view(), now_ms, true, verdict);
}

// T06 core: the authority ledger's real disaster — both slots
// destroyed, rebuild quarantines, old-generation issuance refuses,
// operator recover(2) — then the existing target migrates: it rejects
// the new generation while un-updated, takes the signed root RTM1, and
// after a restart accepts the new generation and rejects the old key.
// The journal's configured pin is never touched after deployment.
void test_t06_disaster_generation_migration() {
  routeloom_test::FaultyLedgerStorage ledger_storage;
  SingleAuthority authority(kNet, kAuthority, ledger_storage);
  CHECK_OK(authority.initialize());
  for (std::uint64_t seq = 1; seq <= 2; ++seq) {
    AuthorityOperation history{};
    Digest256 content{};
    content[0] = static_cast<std::uint8_t>(seq);
    CHECK_OK(authority.build_operation(AuthorityOperationKind::RemoteConfig,
                                       content, history));
    CHECK(history.generation == 1);
    CHECK(history.sequence == seq);
    Digest256 state{};
    state[0] = static_cast<std::uint8_t>(0xA0 + seq);
    CHECK_OK(authority.apply_remote_config(history, state, true));
  }

  T06Target target;
  MonotonicMs now_ms = 10000;
  CHECK_OK(target.boot_status_);
  t06_provision_trust(target);
  CHECK(target.trust->store_epoch() == 1);
  CHECK(target.view->ready());

  // Pre-disaster: a gen-1 permit applies end to end (ledger seq 3).
  const ConfigField patch1[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  ConfigCommand issued{};
  CHECK_OK(t06_drive_permit(target, authority, patch1, 1, kT06AuthG.priv, 0,
                            ByteView{}, now_ms, verdict, 1, &issued));
  CHECK(issued.authority_generation == 1);
  CHECK(issued.authority_sequence == 3);
  target.drain(now_ms);
  CHECK(target.journal->phase() == ConfigPhase::Active);
  CHECK(target.journal->decision_revision() == 1);
  const ConfigField expect1_fields[] = {sdk_u8(1, 1)};
  const auto expect1 = snapshot_of(expect1_fields, 1);
  CHECK(target.journal->active_snapshot().size == expect1.size);
  CHECK(std::memcmp(target.journal->active_snapshot().data,
                    expect1.bytes.data(), expect1.size) == 0);

  t06_expiry_gap(now_ms);
  // DISASTER: both ledger slots destroyed; the rebuild quarantines and
  // old-generation issuance refuses — nothing silently resets to 0.
  ledger_storage.fill(0, 0xEE);
  ledger_storage.fill(1, 0xEE);
  SingleAuthority rebuilt(kNet, kAuthority, ledger_storage);
  CHECK(rebuilt.initialize().code == StatusCode::IntegrityError);
  CHECK(rebuilt.quarantined());
  AuthorityOperation blocked{};
  Digest256 blocked_content{};
  CHECK(rebuilt.build_operation(AuthorityOperationKind::RemoteConfig,
                                blocked_content, blocked)
            .code == StatusCode::IntegrityError);
  // Explicit operator recovery under the new generation. The RTM1 needs
  // no commit from the destroyed ledger — the root signs the rotation.
  CHECK_OK(rebuilt.recover(2));
  CHECK(!rebuilt.quarantined());
  CHECK(rebuilt.state().generation == 2);
  CHECK(rebuilt.state().applied_sequence == 0);

  // The un-updated target rejects the new generation: the ledger-handed
  // (gen 2, seq 1) signs fine, but the target resolves no key for it.
  const ConfigField patch2[] = {sdk_u8(1, 2)};
  ConfigCommand gprime{};
  CHECK(t06_drive_permit(target, rebuilt, patch2, 1, kT06AuthGPrime.priv, 1,
                         target.journal->active_snapshot(), now_ms, verdict, 2,
                         &gprime)
            .code == StatusCode::AuthenticationFailed);
  CHECK(gprime.authority_generation == 2);
  CHECK(gprime.authority_sequence == 1);
  CHECK(verdict.reason == ConfigReason::AuthorityDenied);
  CHECK(target.journal->phase() == ConfigPhase::Active);
  CHECK(target.journal->decision_revision() == 1);

  t06_expiry_gap(now_ms);
  // Root rotation lands: epoch 2 retires the old key, activates the new
  // one and raises the generation floor — through the real manifest
  // path against the shared RLF1 floor.
  TrustImage rotated = routeloom_test::test_image(2, kNet, kT06Root, 0x100);
  rotated.min_authority_generation = 2;
  rotated.keys[0] = routeloom_test::test_key_record(
      kAuthority, 1, kT06AuthG.pub, TrustKeyStatus::Retired);
  rotated.keys[1] = routeloom_test::test_key_record(
      kAuthority, 2, kT06AuthGPrime.pub, TrustKeyStatus::Active);
  rotated.key_count = 2;
  ByteBuffer<kTrustManifestObjectMax> manifest{};
  t06_make_manifest(rotated, 0x100, kT06Root.priv, manifest);
  CHECK_OK(
      trust_manifest_accept(*target.trust, manifest.view(), *target.floor));
  CHECK(target.trust->store_epoch() == 2);

  // Restart: all RAM destroyed, rebuilt from storage. The journal is
  // still Active on the old revision, trust is at epoch 2, and the
  // deployed pin is untouched — the floor decides now. The boot restore
  // re-proves the provider before intake re-opens.
  target.restart(now_ms += 1000);
  CHECK_OK(target.boot_status_);
  CHECK(target.journal->phase() == ConfigPhase::Active);
  CHECK(target.journal->decision_revision() == 1);
  CHECK(target.config.authority_generation == 1);
  CHECK(target.view->effective_generation_floor() == 2);
  target.drain(now_ms);

  t06_expiry_gap(now_ms);
  // The new generation applies after update + restart (ledger seq 2 —
  // the rejected attempt's sequence stayed spent, never reused).
  ConfigCommand gprime2{};
  CHECK_OK(t06_drive_permit(target, rebuilt, patch2, 1, kT06AuthGPrime.priv, 1,
                            target.journal->active_snapshot(), now_ms, verdict,
                            3, &gprime2));
  CHECK(gprime2.authority_generation == 2);
  CHECK(gprime2.authority_sequence == 2);
  target.drain(now_ms);
  CHECK(target.journal->phase() == ConfigPhase::Active);
  CHECK(target.journal->decision_revision() == 2);
  const ConfigField expect2_fields[] = {sdk_u8(1, 2)};
  const auto expect2 = snapshot_of(expect2_fields, 1);
  CHECK(target.journal->active_snapshot().size == expect2.size);
  CHECK(std::memcmp(target.journal->active_snapshot().data,
                    expect2.bytes.data(), expect2.size) == 0);

  t06_expiry_gap(now_ms);
  // The old key is dead: a correctly-bound gen-1 leftover — fresh
  // challenge, fresh opid, only the generation/key stale — is rejected
  // at signature resolution, before any CAS check could run.
  endpoint::ControlChallengeQuery query{};
  query.config_namespace = target.config.config_namespace;
  query.schema = target.config.schema;
  query.client_nonce = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
  endpoint::EncodedServicePayload encoded{};
  CHECK_OK(target.journal->handle_challenge_query(query, now_ms, encoded));
  endpoint::ControlChallenge challenge{};
  CHECK_OK(endpoint::control_challenge_decode(encoded.view(), challenge));
  const ConfigField patch_old[] = {sdk_u8(1, 0)};
  ByteBuffer<endpoint::kConfigSnapshotMax> next{};
  bool changed = false;
  CHECK_OK(config_patch_apply(target.journal->active_snapshot(), patch_old, 1,
                              next, changed));
  CHECK(changed);
  Digest256 base_hash{}, next_hash{};
  CHECK_OK(config_snapshot_hash(target.config.config_namespace,
                                target.config.schema,
                                target.journal->active_snapshot(), base_hash));
  CHECK_OK(config_snapshot_hash(target.config.config_namespace,
                                target.config.schema, next.view(), next_hash));
  ConfigCommand leftover{};
  leftover.config_namespace = target.config.config_namespace;
  leftover.schema = target.config.schema;
  leftover.network = target.config.network;
  leftover.target = target.config.target;
  leftover.authority = target.config.authorized_issuer;
  leftover.authority_generation = 1;
  leftover.authority_sequence = 3;  // the pre-disaster permit's values
  leftover.operation_id = t06_opid(4);
  leftover.expected_revision = 2;
  leftover.next_revision = 3;
  leftover.base_snapshot_hash = base_hash;
  leftover.next_snapshot_hash = next_hash;
  leftover.target_boot = target.config.boot_incarnation;
  leftover.challenge_nonce = challenge.challenge_nonce;
  leftover.apply_within_ms = challenge.valid_for_ms;
  leftover.field_count = 1;
  leftover.fields[0] = patch_old[0];
  ByteBuffer<kConfigPermitObjectMax> leftover_permit{};
  CHECK_OK(t06_make_permit(leftover, kT06AuthG.priv, leftover_permit));
  CHECK(target.journal->submit_permit(leftover_permit.view(), now_ms, true,
                                      verdict)
            .code == StatusCode::AuthenticationFailed);
  CHECK(verdict.reason == ConfigReason::AuthorityDenied);
  CHECK(target.journal->decision_revision() == 2);
}

// T06 double-loss variant: the target journal is fully destroyed in the
// same disaster. Recovery runs RTM1 -> RCR2 -> RCC1 in order: the
// rotation first (the recovery verifies under the new key), then a
// reprovision carrying the operator baseline at the RecoveryInfo's
// advertised exact-next, then the normal lane proves the generation.
void test_t06_double_loss_rtm1_rcr2_rcc1() {
  routeloom_test::FaultyLedgerStorage ledger_storage;
  SingleAuthority authority(kNet, kAuthority, ledger_storage);
  CHECK_OK(authority.initialize());
  for (std::uint64_t seq = 1; seq <= 2; ++seq) {
    AuthorityOperation history{};
    Digest256 content{};
    content[0] = static_cast<std::uint8_t>(seq);
    CHECK_OK(authority.build_operation(AuthorityOperationKind::RemoteConfig,
                                       content, history));
    Digest256 state{};
    state[0] = static_cast<std::uint8_t>(0xA0 + seq);
    CHECK_OK(authority.apply_remote_config(history, state, true));
  }

  T06Target target;
  MonotonicMs now_ms = 20000;
  CHECK_OK(target.boot_status_);
  t06_provision_trust(target);
  const ConfigField patch1[] = {sdk_u8(1, 1)};
  ConfigVerdict verdict{};
  CHECK_OK(t06_drive_permit(target, authority, patch1, 1, kT06AuthG.priv, 0,
                            ByteView{}, now_ms, verdict, 5));
  target.drain(now_ms);
  CHECK(target.journal->phase() == ConfigPhase::Active);
  CHECK(target.journal->decision_revision() == 1);

  t06_expiry_gap(now_ms);
  // DOUBLE DISASTER: journal slots and ledger slots all destroyed. The
  // floor, the trust image and the provider backing survive — each on
  // its own store.
  target.storage.fill(0, 0xEE);
  target.storage.fill(1, 0xEE);
  ledger_storage.fill(0, 0xEE);
  ledger_storage.fill(1, 0xEE);
  target.restart(now_ms);
  CHECK(target.boot_status_.code == StatusCode::IntegrityError);
  CHECK(target.journal->quarantined());
  CHECK(target.trust->store_epoch() == 1);  // rotation not yet delivered
  SingleAuthority rebuilt(kNet, kAuthority, ledger_storage);
  CHECK(rebuilt.initialize().code == StatusCode::IntegrityError);
  CHECK(rebuilt.quarantined());
  CHECK_OK(rebuilt.recover(2));
  CHECK(rebuilt.state().generation == 2);

  // RTM1 first: epoch 2 activates the key the recovery verifies under.
  TrustImage rotated = routeloom_test::test_image(2, kNet, kT06Root, 0x100);
  rotated.min_authority_generation = 2;
  rotated.keys[0] = routeloom_test::test_key_record(
      kAuthority, 1, kT06AuthG.pub, TrustKeyStatus::Retired);
  rotated.keys[1] = routeloom_test::test_key_record(
      kAuthority, 2, kT06AuthGPrime.pub, TrustKeyStatus::Active);
  rotated.key_count = 2;
  ByteBuffer<kTrustManifestObjectMax> manifest{};
  t06_make_manifest(rotated, 0x100, kT06Root.priv, manifest);
  CHECK_OK(
      trust_manifest_accept(*target.trust, manifest.view(), *target.floor));
  CHECK(target.trust->store_epoch() == 2);

  // The operator reads RecoveryInfo: it reports the current floors,
  // and the recovery must name one past each (the floor's exact next).
  endpoint::RecoveryInfoQuery info_query{};
  info_query.config_namespace = target.config.config_namespace;
  info_query.nonce.fill(0x71);
  endpoint::EncodedServicePayload info_reply{};
  CHECK_OK(target.journal->handle_recovery_info_query(info_query, now_ms,
                                                      info_reply));
  endpoint::RecoveryInfo info{};
  CHECK_OK(endpoint::recovery_info_decode(info_reply.view(), info));
  CHECK(info.nonce_echo == info_query.nonce);
  CHECK(info.store_floor == target.floor_j());
  CHECK(info.decision_floor == target.floor_r());
  const std::uint32_t exact_j = info.store_floor + 1;
  const std::uint64_t exact_r = info.decision_floor + 1;

  // RCR2 reprovision under the recovered ledger state.
  const ConfigField baseline_fields[] = {sdk_u8(1, 2), sdk_bool(2, true)};
  const auto baseline = snapshot_of(baseline_fields, 2);
  const AuthorityOperation rop = t06_issue_op(rebuilt, baseline.view());
  CHECK(rop.generation == 2);
  CHECK(rop.sequence == 1);
  endpoint::ConfigRecoveryIntent intent{};
  intent.mode = endpoint::kRcr2ModeReprovision;
  intent.config_namespace = target.config.config_namespace;
  intent.schema = target.config.schema;
  intent.network = target.config.network;
  intent.target = target.config.target;
  intent.authority = target.config.authorized_issuer;
  intent.authority_generation = rop.generation;
  intent.authority_sequence = rop.sequence;
  intent.operation_id = t06_opid(6);
  intent.new_store_generation = exact_j;
  intent.new_revision = exact_r;
  CHECK_OK(config_snapshot_hash(target.config.config_namespace,
                                target.config.schema, baseline.view(),
                                intent.snapshot_hash));
  intent.baseline.size = baseline.size;
  std::memcpy(intent.baseline.bytes.data(), baseline.bytes.data(),
              baseline.size);
  ByteBuffer<kConfigPermitObjectMax> object{};
  CHECK_OK(t06_make_recovery(intent, kT06AuthGPrime.priv, object));
  t06_commit_op(rebuilt, rop, object.view());
  CHECK_OK(target.journal->submit_recovery(object.view(), now_ms, verdict));
  CHECK(verdict.reason == ConfigReason::InProgress);
  CHECK(target.journal->quarantined());
  target.drain(now_ms);
  CHECK(!target.journal->quarantined());
  CHECK(target.journal->phase() == ConfigPhase::Active);
  CHECK(target.journal->decision_revision() == exact_r);
  CHECK(target.journal->active_snapshot().size == baseline.size);
  CHECK(std::memcmp(target.journal->active_snapshot().data,
                    baseline.bytes.data(), baseline.size) == 0);

  // Durability across a restart, then the normal lane proves the new
  // generation on top of the recovered baseline.
  target.restart(now_ms += 1000);
  CHECK_OK(target.boot_status_);
  CHECK(target.journal->phase() == ConfigPhase::Active);
  CHECK(target.journal->decision_revision() == exact_r);
  target.drain(now_ms);
  t06_expiry_gap(now_ms);
  const ConfigField patch3[] = {sdk_bool(3, true)};
  ConfigCommand proved{};
  CHECK_OK(t06_drive_permit(target, rebuilt, patch3, 1, kT06AuthGPrime.priv,
                            exact_r,
                            target.journal->active_snapshot(), now_ms, verdict,
                            7, &proved));
  CHECK(proved.authority_generation == 2);
  CHECK(proved.authority_sequence == 2);
  target.drain(now_ms);
  CHECK(target.journal->phase() == ConfigPhase::Active);
  CHECK(target.journal->decision_revision() == exact_r + 1);
}

int main() {
  // Schema / TLV / hash layer.
  test_tlv_layer();
  test_snapshot_hash_domain();
  test_patch_merge();
  test_namespace_table();
  test_rate_limiter();
  test_sdk_field_rules();
  test_sdk_effective_values();
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
  test_quarantine_invalidates_permit_assembly();
  test_status_result_expired();
  // Issue #51: dedicated kind-4 recovery lane.
  test_r01_quarantine_store_recovery();
  test_r02_uncertain_store_recovery();
  test_r03_recovery_rejections();
  test_r04_recovery_replay_floor();
  test_r07_recovery_lane_reassembly();
  test_recovery_info_healthy();
  test_recovery_info_impaired();
  test_recovery_info_floor_dead();
  // RLF1 security floor.
  test_floor_reserve_on_commit();
  test_floor_gap_consumed();
  test_floor_ahead_of_standard_record_parks_on_boot();
  test_floor_missing_stops_intake();
  test_floor_torn_write_invalidates();
  test_floor_order_violation();
  test_floor_ahead_fresh_quarantines();
  test_store_exhausted();
  test_floor_record_kind_legacy();
  test_floor_twins_full_content();
  // T04 + §5.6 power table: the RCR2 ceremony under the real dev verifier.
  test_t04_reprovision_success();
  test_t04_reprovision_empty();
  test_t04_adopt_known();
  test_t04_provider_faults();
  test_power_floor_saved_intent_not();
  test_power_intent_resume();
  test_power_restore_midflight_resume();
  test_power_resume_reverifies();
  test_power_verify_failure_terminal();
  test_power_complete_reserved_unwritten();
  test_power_spent_intent_parks();
  test_power_lone_complete_mirror();
  test_power_twins_no_reply();
  test_power_floor_unreadable();
  test_factory_gate_stale_provider();
  test_factory_gate_unreadable_provider();
  test_recovery_unsupported_baseline();
  test_signed_golden_verify();
  test_signed_golden_delivery();
  test_t06_disaster_generation_migration();
  test_t06_double_loss_rtm1_rcr2_rcc1();
  if (failures != 0) {
    std::fprintf(stderr, "%d test checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom remote-config tests passed");
  return 0;
}
