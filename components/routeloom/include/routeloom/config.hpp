#pragma once

// Small Remote Config portable core (issue #17;
// docs/design/scope-gateway-config/04-remote-config.md +
// 05-wire-api.md §5.4/§5.5, contracts.json config.*, 06-acceptance.md).
// Implements the P4 "Config portable" layer on top of the endpoint_wire
// codecs (P0):
//   - the schema/TLV layer: sorted typed TLV snapshots, patch -> next-
//     snapshot merge, the §5.4 snapshot hash and the SDK ns=1/schema=1
//     field rules,
//   (the issuer side — canonical construction, the durable outbox and the
//   commit order — lives in the Rust host, never on the device: this unit
//   is the target/verifier side only),
//   - the target side: ConfigChallenge issuance (nonce128, boot
//     incarnation, local monotonic expiry <= 30 s), the per-(Network,
//     target, namespace) ConfigJournal phase machine
//     IDLE->...->ACTIVE(+INTERRUPTED/QUARANTINED), CAS on
//     expected_revision, STALE_REVISION/CONFLICT/duplicate-id semantics,
//     dual-slot journal persistence with the RLF1 floor reservation before
//     and write->commit->readback after every phase advance, the §6.3
//     one-slot-loss rule, result records 8x300 s, one active transaction,
//     the 1/min+burst1 acceptance budget and the kind-3 permit
//     reassembly bound,
//   - the provider contract: side-effect-free validate/prepare, idempotent
//     async apply/restore via completion tokens, readback verification,
//     restore-failure -> QUARANTINED, no whole-board erase,
//   - the maintenance/admission boundary for management-path-removing
//     changes (relay off, discovery off, migration policy).
//
// Everything is portable: storage is an interface (the NVS adapter is a
// later phase), time is an injected monotonic now_ms, entropy comes from
// the existing EntropySource. The permit signature is the trust contract
// "issuer committed, then signed": it is verified through a
// ConfigAuthorityVerifier that MUST run a real cryptographic check — the
// production COSE_Sign1 provider lands with #10, and neither a key name
// nor bind_operation_payload() (documented non-crypto) may fabricate
// verified=true.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/autonomy.hpp"
#include "routeloom/autonomy_wire.hpp"
#include "routeloom/authority.hpp"
#include "routeloom/discovery.hpp"  // EntropySource
#include "routeloom/endpoint_wire.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/security.hpp"
#include "routeloom/security_floor.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// --- Bounds (contracts.json config.*) -----------------------------------------
constexpr std::size_t kConfigJournalSlotBytes = 4096;     // slot_bytes
constexpr std::uint8_t kConfigJournalSlots = 2;           // slots_per_namespace
constexpr std::size_t kConfigNamespaceLimit = 4;          // namespace_max
constexpr std::size_t kConfigResultRecords = 8;           // records
constexpr std::uint32_t kConfigResultHoldMs = 300000;     // result_hold_ms
constexpr std::uint32_t kConfigChallengeMaxMs = 30000;    // challenge_max_ms
constexpr std::uint32_t kConfigReassemblyTimeoutMs = 10000;  // reassembly_timeout_ms
constexpr std::size_t kConfigPermitObjectMax = 1024;      // object_max
constexpr std::size_t kConfigPermitEncodedMax = 774;      // permit_encoded_max
constexpr std::uint32_t kConfigAcceptPerMinute = 1;       // accepted_per_minute
constexpr std::uint32_t kConfigAcceptBurst = 1;           // burst
constexpr std::uint32_t kConfigAcceptWindowMs = 60000;
// §6.3 math convention (the gateway's 20/min+burst8 admits 28/60 s): the
// sustained rate plus the burst allowance, so config admits 2 per 60 s.
constexpr std::uint32_t kConfigAcceptCapacity =
    kConfigAcceptPerMinute + kConfigAcceptBurst;
// Outstanding challenges per journal (implementation bound — no contract
// constant pins it). Keyed by requester client_nonce so one requester's
// re-query refreshes only its own slot; a full table refuses rather than
// evicting another requester's in-flight challenge.
constexpr std::size_t kConfigChallengeSlots = 4;

// --- Schema / TLV layer ---------------------------------------------------------

// Parse a complete sorted TLV snapshot (bare field sequence, no envelope).
// Same rules as the RCC1 patch codec: strict ascending field ids, known
// types, exact lengths, <=16 fields, value <=96 B, no trailing bytes.
Status config_tlv_decode(ByteView tlv, endpoint::ConfigField* fields,
                         std::uint16_t capacity, std::uint16_t& count) noexcept;

// Serialize already-sorted, already-valid fields into snapshot TLV bytes.
Status config_tlv_encode(const endpoint::ConfigField* fields, std::uint16_t count,
                         ByteBuffer<endpoint::kConfigSnapshotMax>& out) noexcept;

// Snapshot hash (05 §5.4): SHA256("RouteLoom/config-snapshot/v1" || NUL ||
// namespace u16 || schema u16 || complete_sorted_TLV_snapshot).
Status config_snapshot_hash(std::uint16_t config_namespace, std::uint16_t schema,
                            ByteView snapshot_tlv, Digest256& out) noexcept;

// Merge a validated patch onto a base snapshot: patch fields overwrite the
// same id, others are retained; output stays strictly ascending. Sets
// `changed=false` when the merged result equals the base (the issuer's
// NO_CHANGE check before signing; the target's before DECIDED).
Status config_patch_apply(ByteView base_tlv, const endpoint::ConfigField* patch,
                          std::uint16_t patch_count,
                          ByteBuffer<endpoint::kConfigSnapshotMax>& next,
                          bool& changed) noexcept;

// §5.4 external_aad: "RouteLoom/config-permit/v1" || NUL || Network u64 ||
// target u64 || namespace u16. Both permit profiles (production COSE and
// dev/test) bind this exact byte string.
inline constexpr char kConfigPermitDomain[] = "RouteLoom/config-permit/v1";
constexpr std::size_t kConfigPermitAadSize = sizeof(kConfigPermitDomain) + 8 + 8 + 2;
Status config_permit_aad(NetworkId network, NodeId target, std::uint16_t config_namespace,
                         ByteBuffer<kConfigPermitAadSize>& out) noexcept;

// The recovery-object external_aad (04 §4.7, 06 §6.3): a domain separate
// from the permit aad so a kind-4 recovery envelope can never verify as a
// kind-3 permit (and vice versa) under any profile.
inline constexpr char kConfigRecoveryDomain[] = "RouteLoom/config-recover/v1";
constexpr std::size_t kConfigRecoveryAadSize =
    sizeof(kConfigRecoveryDomain) + 8 + 8 + 2;
Status config_recovery_aad(NetworkId network, NodeId target,
                           std::uint16_t config_namespace,
                           ByteBuffer<kConfigRecoveryAadSize>& out) noexcept;

// SDK namespace=1 / schema=1 field rules (04 §4.2): field 1 diagnostics_level
// u8 0..2, field 2 discovery_enabled bool, field 3 relay_allowed bool,
// field 4 migration_policy u8 0..2. Unknown ids/types are rejected.
Status config_sdk_field_validate(const endpoint::ConfigField& field) noexcept;

// Per-namespace schema validation for application namespaces. Registered
// with the namespace; SDK ns=1 uses config_sdk_field_validate instead.
class ConfigSchemaValidator {
 public:
  virtual ~ConfigSchemaValidator() = default;
  virtual Status validate_field(const endpoint::ConfigField& field) const noexcept = 0;
};

class ConfigProvider;  // defined below — entries may pre-attach a provider

// Registered-namespaces set (04 §4.2): default is the single SDK namespace;
// up to kConfigNamespaceLimit entries; app namespaces are 0x8000..0xfffe and
// must be explicitly registered.
struct ConfigNamespaceEntry {
  std::uint16_t config_namespace{endpoint::kConfigNamespaceSdk};
  std::uint16_t schema{1};
  const ConfigSchemaValidator* validator{nullptr};  // null -> SDK rules (ns 1 only)
  ConfigProvider* provider{nullptr};
};

class ConfigNamespaceTable {
 public:
  ConfigNamespaceTable() noexcept;  // pre-registers SDK ns=1/schema=1
  Status register_namespace(const ConfigNamespaceEntry& entry) noexcept;
  const ConfigNamespaceEntry* find(std::uint16_t config_namespace) const noexcept;
  std::size_t size() const noexcept { return size_; }

 private:
  std::array<ConfigNamespaceEntry, kConfigNamespaceLimit> entries_{};
  std::size_t size_{0};
};

// --- Boundary interfaces ---------------------------------------------------------

// Everything the permit verification binds (05 §5.4 external_aad plus the
// target's authorization policy from 04 §4.3).
struct ConfigPermitContext {
  NetworkId network{0};
  NodeId target{kInvalidNodeId};
  std::uint16_t config_namespace{0};
  NodeId authorized_issuer{kInvalidNodeId};   // the single allowed authority id
  std::uint32_t authority_generation{0};      // the permitted authority generation
};

// The authority-signature verification surface for config permits. An
// implementation MUST run a real cryptographic check over the whole permit
// (production: COSE_Sign1/ES256 with the §5.4 external_aad, landing with
// #10) plus the identity policy in `context`. An unconditional Ok/verified
// is a contract violation, and neither a fixed `verified=true` nor
// bind_operation_payload() is a substitute (04 §4.3). Development
// providers stay EXPERIMENTAL and are surfaced as such.
class ConfigAuthorityVerifier {
 public:
  virtual ~ConfigAuthorityVerifier() = default;
  virtual bool ready() const noexcept = 0;
  virtual SecurityProfile security_profile() const noexcept {
    return SecurityProfile::Development;
  }
  // CapabilitiesReply permit_profiles wire bit (04 §capabilities): the ONE
  // bit this verifier represents — bit0 dev-HMAC, bit1 RLCP1_COSE_ESP256.
  // 0 = not advertiseable. Only a ready() verifier's bit is advertised.
  virtual std::uint32_t permit_profile_bit() const noexcept { return 0; }
  // True when a verification attempt is expensive enough to warrant the
  // pre-verification intake limiter (03-signing §3.3): asymmetric ECC
  // verification on the radio Owner must be bounded independently of the
  // post-verification acceptance budget. Cheap profiles (HMAC) return false.
  virtual bool verify_is_expensive() const noexcept { return false; }
  // Verify `permit` (profile-defined envelope) against `context`. On
  // success `payload` receives the canonical RCC1 bytes the permit signs;
  // `verified` is set false whenever the signature, the binding or the
  // identity policy fails — a false verdict is not necessarily an error
  // return (errors are for malformed envelopes/provider faults).
  virtual Status verify_permit(const ConfigPermitContext& context, ByteView permit,
                               endpoint::EncodedConfigCommand& payload,
                               bool& verified) noexcept = 0;
  // The same contract for a kind-4 recovery object (RCR1 payload, the
  // recovery-domain external_aad — never the permit aad). Authority
  // generation changes are root-authorized trust updates (RTM1), never
  // recovery commands. The default refuses — a profile without a recovery
  // envelope must fail closed, never silently accept.
  virtual Status verify_recovery(const ConfigPermitContext& context,
                                 ByteView object,
                                 endpoint::EncodedRecoveryCommand& payload,
                                 bool& verified) noexcept {
    (void)context;
    (void)object;
    (void)payload;
    verified = false;
    return Status::error(StatusCode::Unsupported,
                       "config recovery profile unsupported");
  }
};

// Per-namespace dual-slot journal persistence. read() fills the whole
// 4096-byte slot image; write() lands a record of <=4096 bytes.
// Implementations must tolerate power loss at any byte boundary and must
// never erase or reformat storage on error.
class ConfigJournalStorage {
 public:
  virtual ~ConfigJournalStorage() = default;
  virtual Status read(std::uint8_t slot, MutableByteView target) noexcept = 0;
  virtual Status write(std::uint8_t slot, ByteView data) noexcept = 0;
};

// The desired-state provider contract (04 §4.6). validate/prepare are
// side-effect-free; apply/restore are idempotent operations toward a
// desired/confirmed snapshot returning an async completion token — they
// never block the radio task. read_active returns the real active values;
// log strings are never proof of success. Providers with irreversible
// effects must not be registered.
class ConfigProvider {
 public:
  virtual ~ConfigProvider() = default;
  virtual Status validate(std::uint16_t config_namespace, std::uint16_t schema,
                          ByteView next_snapshot) noexcept = 0;
  virtual Status prepare(std::uint16_t config_namespace, std::uint16_t schema,
                         ByteView next_snapshot) noexcept = 0;
  virtual Status apply(std::uint16_t config_namespace, ByteView next_snapshot,
                       OperationToken& token) noexcept = 0;
  virtual Status restore(std::uint16_t config_namespace, ByteView snapshot,
                         OperationToken& token) noexcept = 0;
  // Poll a completion token: done=true carries the terminal Status.
  virtual Status poll(OperationToken token, bool& done, Status& outcome) noexcept = 0;
  // The actually-active snapshot bytes (readback verification input).
  virtual Status read_active(std::uint16_t config_namespace, MutableByteView target,
                             std::size_t& out_size) noexcept = 0;
};

// The maintenance/admission boundary (04 §4.8): consulted before DECIDED
// whenever a change would disable discovery, disable relay or change the
// migration policy — the operations that can remove management
// reachability. The gate re-confirms drain schedule, dependent endpoints,
// a management return path and stop permission against live maintenance
// state (channel migration/sleep in progress -> Busy). The initial profile
// refuses a change that removes the only admin path; success is never
// claimed by dropping in-flight DATA.
struct ConfigMaintenanceCheck {
  std::uint16_t config_namespace{0};
  NodeId target{kInvalidNodeId};
  bool discovery_disabling{false};
  bool relay_disabling{false};
  bool migration_changing{false};
  MonotonicMs now_ms{0};
};

class ConfigMaintenanceGate {
 public:
  virtual ~ConfigMaintenanceGate() = default;
  virtual Status check(const ConfigMaintenanceCheck& request) noexcept = 0;
};

// --- Acceptance budget ------------------------------------------------------------

// New-update acceptance budget: 1/min sustained + burst 1 = at most 2
// accepted updates in any 60 s window (the §6.3 rate+burst convention).
// Duplicates, refusals and status queries consume nothing.
class ConfigRateLimiter {
 public:
  bool consume(MonotonicMs now_ms) noexcept {
    if (now_ms > last_ms_) {
      const std::uint64_t refill =
          ((now_ms - last_ms_) * kConfigAcceptPerMinute) / kConfigAcceptWindowMs;
      if (refill > 0) {
        const std::uint64_t tokens = tokens_ + refill;
        tokens_ = tokens > kConfigAcceptCapacity
                      ? kConfigAcceptCapacity
                      : static_cast<std::uint32_t>(tokens);
        last_ms_ = now_ms;
      }
    }
    if (tokens_ == 0) return false;
    --tokens_;
    return true;
  }

  // Return one token after a spend that produced nothing — a DECIDED write
  // that faulted persisted no record, so the refusal consumes no budget
  // (duplicates, refusals and status queries consume nothing).
  void refund() noexcept {
    if (tokens_ < kConfigAcceptCapacity) ++tokens_;
  }

  // Device-global expensive-verification intake gate (03-signing §3.3):
  // one verification START per 5 s across ALL attached journals — charged
  // before any signature work so invalid-but-well-formed permits cannot
  // monopolize the Owner. The embedder owns this object and shares it
  // between journals, which is what makes the bound device-wide.
  bool consume_expensive_verify(const MonotonicMs now_ms) noexcept {
    if (!verify_token_ &&
        now_ms - last_verify_refill_ms_ >= kExpensiveVerifyIntervalMs) {
      verify_token_ = true;
      last_verify_refill_ms_ = now_ms;
    } else if (verify_token_ && last_verify_refill_ms_ == 0) {
      last_verify_refill_ms_ = now_ms;  // anchor the first window
    }
    if (!verify_token_) return false;
    verify_token_ = false;
    last_verify_refill_ms_ = now_ms;
    return true;
  }
  static constexpr std::uint32_t kExpensiveVerifyIntervalMs = 5000;

 private:
  std::uint32_t tokens_{kConfigAcceptCapacity};
  MonotonicMs last_ms_{0};
  MonotonicMs last_verify_refill_ms_{0};
  bool verify_token_{true};
};

// --- Target-side pieces ------------------------------------------------------------

// The reply a journal produces for one submitted operation: what the
// Status4 payload carries (opid is the submitter's own). Phase IDLE +
// reason is a pre-acceptance refusal — never ACTIVE (05 §5.5).
struct ConfigVerdict {
  endpoint::ConfigPhase phase{endpoint::ConfigPhase::Idle};
  endpoint::ConfigReason reason{endpoint::ConfigReason::Ok};
  std::uint64_t decision_revision{0};
  std::uint64_t active_revision{0};
  Digest256 active_hash{};
};

// Coarse C-Status mapping for the config-local reason table (05 §5.5 keeps
// the u16 detail; C Status maps onto existing names).
StatusCode config_reason_status(endpoint::ConfigReason reason) noexcept;

struct ConfigJournalConfig {
  NetworkId network{0};
  NodeId target{kInvalidNodeId};
  std::uint16_t config_namespace{endpoint::kConfigNamespaceSdk};
  std::uint16_t schema{1};
  std::uint64_t boot_incarnation{0};               // nonzero, fresh per boot
  NodeId authorized_issuer{kInvalidNodeId};        // the single allowed authority
  std::uint32_t authority_generation{0};           // the permitted generation
  std::uint32_t challenge_valid_ms{kConfigChallengeMaxMs};  // <= 30 s
};

struct ConfigStats {
  std::uint32_t challenges_issued{0};
  std::uint32_t permits_verified{0};
  std::uint32_t permits_denied{0};
  std::uint32_t accepted{0};
  std::uint32_t rate_refusals{0};
  // Pre-verification intake refusals (03-signing §3.3): expensive permits
  // rejected before any signature work — charged even on failure.
  std::uint32_t verify_intake_refusals{0};
  std::uint32_t stale_revision{0};
  std::uint32_t conflicts{0};
  std::uint32_t no_change{0};
  std::uint32_t storage_failures{0};
  std::uint32_t applies{0};
  std::uint32_t restores{0};
  std::uint32_t interrupted{0};
  std::uint32_t quarantine_events{0};
  std::uint32_t reassembly_rejects{0};
  std::uint32_t maintenance_refusals{0};
};

// The durable record's kind (journal format 2 header byte): a recovery
// intent and its completion carry the same phase values as a normal
// transaction's DECIDED/ACTIVE would, but boot must resume them through
// the recovery ceremony — never through the normal continuation.
enum class ConfigRecordKind : std::uint8_t {
  Standard = 0,
  RecoveryIntent = 1,
  RecoveryComplete = 2,
};

// One (Network, target, namespace) ConfigJournal: the phase machine, the
// dual-slot durable record, the challenge issuer, the permit reassembly
// bound and the result history. Not thread-safe — the Owner serializes
// calls; provider calls never block the radio task (async tokens).
//
// Every durable phase advance reserves its store generation (and, for
// decisions, its revision) in the RLF1 security floor BEFORE the journal
// record is written; a failed journal write consumes the reservation —
// generations are never reused. The floor is a constructor dependency:
// without a usable floor the journal refuses privileged intake.
class ConfigJournal {
 public:
  ConfigJournal(const ConfigJournalConfig& config, ConfigJournalStorage& storage,
                SecurityFloorStore& floor, ConfigAuthorityVerifier& verifier,
                EntropySource& entropy, ConfigRateLimiter& rate_limiter,
                ConfigProvider* provider, const ConfigSchemaValidator* validator,
                ConfigMaintenanceGate* gate) noexcept;

  // Boot recovery: verify both slots against the security floor, adopt the
  // newest verifiable record and resolve its phase (04 §4.7 + 06 §6.3):
  //   - record ACTIVE        -> restore the confirmed snapshot (continuation
  //                             of decided config, not a new command run),
  //   - DECIDED pre-intent   -> keep the consumed revision, mark INTERRUPTED
  //                             (challenge is dead across the boot change),
  //   - APPLY_INTENT..VERIFY -> idempotent restore of the previous confirmed
  //                             snapshot, record APPLY_INTERRUPTED;
  //                             unrestorable -> QUARANTINED,
  //   - one slot lost        -> the survivor is a "known value" only:
  //                             CONFIG_STORAGE_UNCERTAIN, no update intake,
  //   - both slots lost      -> no auto reset to revision 0; quarantine —
  //                             the floor's J/R name the next recovery, and
  //                             explicit recovery/re-provisioning is required,
  //   - journal newer than the floor -> the save order was violated (or the
  //                             floor was lost and mis-seeded): stop, never
  //                             mint from unknown counters.
  Status initialize(MonotonicMs now_ms) noexcept;

  // Control22 handlers. The challenge carries a fresh nonce128, this boot
  // incarnation, the current decision revision and the active hash with a
  // local monotonic expiry <= kConfigChallengeMaxMs — never a wall-clock
  // lifetime.
  Status handle_challenge_query(const endpoint::ControlChallengeQuery& query,
                                MonotonicMs now_ms,
                                endpoint::EncodedServicePayload& out) noexcept;
  Status handle_status_query(const endpoint::ControlStatusQuery& query,
                             MonotonicMs now_ms,
                             endpoint::EncodedServicePayload& out) noexcept;

  // Kind-3 permit object ingress (05 §5.5): manifest first, bounded chunks,
  // 10 s reassembly, digest verified before the permit is submitted. An
  // object ACK Ok means assembly completed — never CONFIG_ACTIVE.
  Status note_object_manifest(const autonomy::ControlObjectPayload& manifest,
                              MonotonicMs now_ms) noexcept;
  Status note_object_chunk(const autonomy::ObjectChunkPayload& chunk,
                           MonotonicMs now_ms) noexcept;

  // Verify -> dedup -> admission -> validate -> PREPARED -> DECIDED ->
  // APPLY_INTENT -> apply-start. Returns the Status for the caller plus the
  // wire-level verdict (phase/reason) the Status4 reply should carry.
  // `clock_known=false` reports elapsed-time uncertainty: no new config is
  // applied when the challenge elapsed cannot be proven (04 §4.4).
  Status submit_permit(ByteView permit, MonotonicMs now_ms, bool clock_known,
                       ConfigVerdict& verdict) noexcept;

  // The dedicated kind-4 recovery lane (04 §4.7, 06 §6.3): the ONLY intake
  // that stays open while the journal is quarantined or uncertain — a
  // signed recovery command is the evidence an impaired journal accepts.
  // Same manifest/chunk/10 s reassembly/digest discipline as kind-3, on a
  // separate slot; completion dispatches to submit_recovery, never
  // submit_permit.
  Status note_recovery_manifest(const autonomy::ControlObjectPayload& manifest,
                                MonotonicMs now_ms) noexcept;
  Status note_recovery_chunk(const autonomy::ObjectChunkPayload& chunk,
                             MonotonicMs now_ms) noexcept;

  // Verify -> dedup -> dispatch on a signed RCR1 StoreRecover command
  // (impaired journals only): attests a fresh store generation and runs
  // the recover() ceremony under the signed attest. Authority generation
  // changes arrive as root-authorized trust updates (RTM1), never here.
  // Signature verification, the generation/revision floors and the
  // result-record dedup apply; every failure stays fail-closed.
  Status submit_recovery(ByteView object, MonotonicMs now_ms,
                         ConfigVerdict& verdict) noexcept;

  // Drives the async provider completion (APPLYING/VERIFYING/restore), the
  // reassembly timeout and result-record expiry.
  void poll(MonotonicMs now_ms) noexcept;

  // Explicit operator recovery from STORAGE_UNCERTAIN or quarantine:
  // attests a fresh store generation and re-establishes intake. The
  // surviving "known value" (if any) is adopted under the new generation;
  // the proven revision floor is never regressed, so pre-loss permits can
  // never re-validate. Never invoked implicitly. When NO verifiable record
  // survives, adopting a base would silently fabricate state — an
  // undelegated authority decision — so recovery stays impaired unless
  // `reprovision` explicitly attests this is a re-provisioning under a
  // fresh trust generation (04 §4.7: total loss requires re-provisioning,
  // never an automatic return to revision 0). The flag is unnecessary
  // whenever a survivor exists; the survivor is adopted as-is either way.
  Status recover(std::uint32_t new_store_generation, MonotonicMs now_ms,
                 bool reprovision) noexcept;

  endpoint::ConfigPhase phase() const noexcept { return phase_; }
  std::uint64_t decision_revision() const noexcept { return decision_revision_; }
  std::uint64_t active_revision() const noexcept { return active_revision_; }
  const Digest256& active_hash() const noexcept { return active_hash_; }
  ByteView active_snapshot() const noexcept { return active_snapshot_.view(); }
  bool initialized() const noexcept { return initialized_; }
  // The RLF1 floor this journal reserves from (targets also serve it to
  // recovery queries; the reference is stable for the journal's life).
  SecurityFloorStore& floor() noexcept { return floor_; }
  // Capability advertisement (04 §capabilities): the configured verifier's
  // wire bit when it is provisioned, 0 otherwise — an unready profile is
  // never advertised.
  std::uint32_t permit_profile_bits() const noexcept {
    return verifier_.ready() ? verifier_.permit_profile_bit() : 0;
  }
  bool uncertain() const noexcept { return uncertain_; }
  bool quarantined() const noexcept { return quarantined_; }
  // The authority generation this journal accepts: the configured pin
  // (a root-authorized trust update moves it; the adopted durable
  // record's generation carries it across boots).
  std::uint32_t authority_generation() const noexcept {
    return authority_generation_;
  }
  // True while an operation is between DECIDED and its terminal record:
  // maintenance/other radio operations consult this for exclusivity.
  bool in_progress() const noexcept { return txn_.active; }
  const ConfigStats& stats() const noexcept { return stats_; }
  std::size_t result_records() const noexcept {
    std::size_t used = 0;
    for (const ResultRecord& record : results_) {
      if (record.used) ++used;
    }
    return used;
  }

 private:
  enum class SlotContent : std::uint8_t {
    Empty,
    Pending,
    Corrupt,
    Unsupported,
    Foreign,
    Valid,
  };

  struct JournalRecord {
    std::uint32_t store_generation{0};
    endpoint::ConfigPhase phase{endpoint::ConfigPhase::Idle};
    endpoint::ConfigReason reason{endpoint::ConfigReason::Ok};
    ConfigRecordKind kind{ConfigRecordKind::Standard};
    NetworkId network{0};
    NodeId target{kInvalidNodeId};
    std::uint16_t config_namespace{0};
    std::uint16_t schema{0};
    NodeId issuer{kInvalidNodeId};
    std::uint32_t issuer_generation{0};
    std::uint64_t authority_sequence{0};
    std::array<std::uint8_t, 16> operation_id{};
    Digest256 command_digest{};
    std::uint64_t decision_revision{0};
    std::uint64_t active_revision{0};
    std::uint64_t target_boot{0};
    std::uint32_t apply_within_ms{0};
    ByteBuffer<endpoint::kConfigSnapshotMax> prev_snapshot{};
    ByteBuffer<endpoint::kConfigSnapshotMax> next_snapshot{};
    ByteBuffer<kConfigPermitObjectMax> permit{};
  };

  struct ResultRecord {
    bool used{false};
    std::array<std::uint8_t, 16> operation_id{};
    Digest256 command_digest{};
    endpoint::ConfigPhase phase{endpoint::ConfigPhase::Idle};
    endpoint::ConfigReason reason{endpoint::ConfigReason::Ok};
    std::uint64_t decision_revision{0};
    std::uint64_t active_revision{0};
    Digest256 active_hash{};
    MonotonicMs stored_ms{0};
  };

  struct Transaction {
    bool active{false};
    bool applying{false};   // provider.apply token outstanding
    bool restoring{false};  // provider.restore token outstanding
    bool pending_persist{false};  // terminal record write deferred by a storage fault
    bool intent_pending{false};   // APPLY_INTENT persist + apply deferred to poll()
    endpoint::ConfigPhase pending_phase{endpoint::ConfigPhase::Idle};
    endpoint::ConfigReason pending_reason{endpoint::ConfigReason::Ok};
    MonotonicMs challenge_issued_ms{0};  // issue time of the consumed challenge
    endpoint::ConfigCommand command{};
    endpoint::EncodedConfigCommand canonical{};
    Digest256 command_digest{};
    ByteBuffer<kConfigPermitObjectMax> permit{};
    ByteBuffer<endpoint::kConfigSnapshotMax> prev_snapshot{};
    ByteBuffer<endpoint::kConfigSnapshotMax> next_snapshot{};
    Digest256 next_hash{};
    OperationToken token{kInvalidOperationToken};
    endpoint::ConfigReason fail_reason{endpoint::ConfigReason::ApplyInterrupted};
  };

  // Boot-time restore bookkeeping (resolve_recovered): the provider's
  // restore token is async, so poll() completes the resolution.
  struct Boot {
    bool restore_pending{false};
    bool restore_started{false};
    // ResolveInterrupted: persist INTERRUPTED (or QUARANTINED) after the
    // restore settles. Reconfirm: nothing persists on success.
    bool resolve{false};
    endpoint::ConfigReason interrupt_reason{endpoint::ConfigReason::ApplyInterrupted};
    ByteBuffer<endpoint::kConfigSnapshotMax> restore_snapshot{};
    OperationToken token{kInvalidOperationToken};
  };

  struct Challenge {
    bool outstanding{false};
    std::array<std::uint8_t, 16> client_nonce{};
    std::array<std::uint8_t, 16> nonce{};
    std::uint16_t schema{0};
    MonotonicMs issued_ms{0};
    std::uint32_t valid_for_ms{0};
  };

  struct Reassembly {
    bool active{false};
    autonomy::ControlObjectPayload manifest{};
    std::array<std::uint8_t, kConfigPermitObjectMax> buffer{};
    std::array<std::uint8_t, kConfigPermitObjectMax / 8> received{};
    std::size_t received_count{0};
    MonotonicMs started_ms{0};
  };

  Status store_record(const JournalRecord& record) noexcept;
  // Reserve the next store generation (and the transaction's decision
  // revision, if higher than the floor) in the RLF1 floor BEFORE the
  // journal record is written. On success `reserved_j` names the
  // generation the record MUST carry; a later journal-store failure
  // consumes it — the RAM counters follow the reservation either way.
  Status reserve_generation(const Transaction& txn, std::uint32_t& reserved_j) noexcept;
  Status persist_phase(endpoint::ConfigPhase phase, endpoint::ConfigReason reason,
                       const Transaction& txn) noexcept;
  Status decode_slot(std::uint8_t slot, JournalRecord& record,
                     SlotContent& content, bool& committed_fields) noexcept;
  Status adopt_record(const JournalRecord& record) noexcept;
  Status resolve_recovered(MonotonicMs now_ms) noexcept;
  Status start_restore(Transaction& txn, endpoint::ConfigReason reason) noexcept;
  Status finish_transaction(Transaction& txn, endpoint::ConfigPhase phase,
                            endpoint::ConfigReason reason) noexcept;
  // Wedge the live state honestly when the floor is spent: no record can
  // ever commit again, so intake stops and status reports quarantine.
  void quarantine_ram() noexcept;
  Transaction& boot_txn() noexcept;  // fills boot_txn_; callers take it by ref
  Status record_result(const Transaction& txn, endpoint::ConfigPhase phase,
                       endpoint::ConfigReason reason, MonotonicMs now_ms) noexcept;
  bool find_result(const std::array<std::uint8_t, 16>& operation_id,
                   const ResultRecord*& out) noexcept;
  void fill_verdict(ConfigVerdict& verdict, endpoint::ConfigPhase phase,
                    endpoint::ConfigReason reason) const noexcept;
  Status validate_command(const endpoint::ConfigCommand& command,
                          const Digest256& digest, MonotonicMs now_ms,
                          bool clock_known, ConfigVerdict& verdict) noexcept;
  Status reassemble_complete(MonotonicMs now_ms) noexcept;
  // The recovery lane's own completion path.
  Status recovery_reassemble_complete(MonotonicMs now_ms) noexcept;
  // Result-record write for the recovery lane (same dedup table as permit
  // outcomes so a replayed recovery answers with its verdict).
  Status record_recovery_result(const endpoint::ConfigRecoveryCommand& command,
                                const Digest256& digest, endpoint::ConfigPhase phase,
                                endpoint::ConfigReason reason,
                                MonotonicMs now_ms) noexcept;
  // The outstanding challenge carrying `nonce`, or nullptr — the permit
  // binds the nonce, so any live slot may satisfy it.
  const Challenge* find_challenge(const std::array<std::uint8_t, 16>& nonce) const noexcept;

  ConfigJournalConfig config_{};
  ConfigJournalStorage& storage_;
  SecurityFloorStore& floor_;
  ConfigAuthorityVerifier& verifier_;
  EntropySource& entropy_;
  ConfigRateLimiter& rate_limiter_;
  ConfigProvider* provider_;
  const ConfigSchemaValidator* validator_;
  ConfigMaintenanceGate* gate_;

  endpoint::ConfigPhase phase_{endpoint::ConfigPhase::Idle};
  std::uint64_t decision_revision_{0};
  std::uint64_t active_revision_{0};
  Digest256 active_hash_{};
  ByteBuffer<endpoint::kConfigSnapshotMax> active_snapshot_{};
  std::uint32_t store_generation_{0};
  // The accepted authority generation — config_.authority_generation until
  // an adopted record or a countersigned update advances it. Durable via
  // the journal record's issuer_generation field, which always holds the
  // pin in force when that record committed.
  std::uint32_t authority_generation_{0};
  std::uint32_t proven_floor_{0};      // highest store gen any committed seal proved
  std::uint64_t revision_floor_{0};    // highest decision revision proved this boot
  std::uint8_t active_slot_{0};
  bool has_active_{false};
  bool initialized_{false};
  bool uncertain_{false};
  bool quarantined_{false};

  std::array<Challenge, kConfigChallengeSlots> challenges_{};
  Transaction txn_{};
  Boot boot_{};
  Reassembly reassembly_{};
  Reassembly recovery_reassembly_{};  // kind-4 lane — stays open impaired
  JournalRecord durable_{};          // newest persisted record (mirrors storage)
  std::array<ResultRecord, kConfigResultRecords> results_{};
  MonotonicMs last_now_ms_{0};
  ConfigStats stats_{};

  // Big transient work areas live in the object, not the stack: the journal
  // is statically allocated by the runtime, so member scratch costs .bss
  // once instead of pushing multi-KB frames onto task stacks (observed:
  // ESP32-C3 main-task stack protection fault during initialize(), then on
  // the submit/poll path — ~12 KB of frames against the 8 KB task stack).
  std::array<JournalRecord, kConfigJournalSlots> parsed_{};
  std::array<std::uint8_t, kConfigJournalSlotBytes> scratch_a_{};
  std::array<std::uint8_t, kConfigJournalSlotBytes> scratch_b_{};
  // Submit-path scratch: submit_permit decodes canonical/command and builds
  // the transaction in submit_txn_, then commits it to txn_ in one shot —
  // early returns never leave a half-built transaction active. The permit
  // patch merge and the maintenance-boundary decode get their own field
  // scratch so no two live buffers ever alias.
  Transaction submit_txn_{};
  JournalRecord record_scratch_{};  // persist_phase/recover record staging
  std::array<endpoint::ConfigField, endpoint::kConfigFieldCountMax> merge_a_{};
  std::array<endpoint::ConfigField, endpoint::kConfigFieldCountMax> merge_b_{};
  std::array<endpoint::ConfigField, endpoint::kConfigFieldCountMax> fields_a_{};
  std::array<endpoint::ConfigField, endpoint::kConfigFieldCountMax> fields_b_{};
  // Poll/recovery-path scratch: boot_txn() fills boot_txn_ once per use and
  // callers pass it to finish_transaction by reference; readback_ holds the
  // provider read_active bytes for the restore/verify comparisons.
  Transaction boot_txn_{};
  std::array<std::uint8_t, endpoint::kConfigSnapshotMax> readback_{};
  // Recovery-submit scratch (member .bss like the submit path): the
  // verified RCR1 canonical and its decoded command.
  endpoint::EncodedRecoveryCommand recovery_canonical_{};
  endpoint::ConfigRecoveryCommand recovery_command_{};
};

}  // namespace routeloom
