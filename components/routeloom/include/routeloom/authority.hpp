#pragma once

#include <array>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

using Digest256 = std::array<std::uint8_t, 32>;

struct AuthorityRecord {
  NetworkId network{0};
  NodeId authority{kInvalidNodeId};
  std::uint32_t generation{0};
  std::uint64_t applied_sequence{0};
  Digest256 state_hash{};
};

enum class AuthorityOperationKind : std::uint8_t {
  Generic = 0,
  RemoteConfig = 1,
  MembershipApproval = 2,
  MembershipRevocation = 3,
  // Verified channel-migration plan commit (04-channel-migration.md §5-§6):
  // operation_hash binds the plan blob digest, so the ledger reference
  // transitively binds every plan field.
  ChannelMigration = 4,
};

struct AuthorityOperation {
  NetworkId network{0};
  NodeId authority{kInvalidNodeId};
  std::uint32_t generation{0};
  std::uint64_t sequence{0};
  AuthorityOperationKind kind{AuthorityOperationKind::Generic};
  Digest256 previous_state_hash{};
  Digest256 operation_hash{};
};

// Deterministically binds an operation kind and payload into
// AuthorityOperation::operation_hash for ledger wiring and tests. NOT a
// cryptographic digest: a production security profile replaces it with the
// negotiated suite hash over the canonical operation encoding.
Digest256 bind_operation_payload(AuthorityOperationKind kind, ByteView payload) noexcept;

// Raw two-slot persistence for the authority ledger. Each slot holds exactly
// kAuthorityLedgerRecordSize bytes. Implementations must tolerate power loss
// at any byte boundary and must never erase or reformat storage on error.
class LedgerStorage {
 public:
  virtual ~LedgerStorage() = default;
  virtual Status read(std::uint8_t slot, MutableByteView target) noexcept = 0;
  virtual Status write(std::uint8_t slot, ByteView data) noexcept = 0;
};

constexpr std::uint8_t kAuthorityLedgerSlots = 2;
constexpr std::uint32_t kAuthorityLedgerSchemaVersion = 1;
constexpr std::size_t kAuthorityLedgerRecordSize = 156;

class SingleAuthority {
 public:
  SingleAuthority(NetworkId network, NodeId authority, LedgerStorage& storage) noexcept;

  // Verifies both ledger slots and restores the highest committed revision.
  // A half-written or unparseable slot is ignored while the other slot is
  // usable; if no committed record survives, the authority enters quarantine
  // (IntegrityError) instead of silently resetting to revision 0.
  Status initialize() noexcept;

  Status validate(const AuthorityOperation& operation,
                  bool cryptographic_signature_verified) const noexcept;
  Status commit(const AuthorityOperation& operation,
                const Digest256& resulting_state_hash,
                bool cryptographic_signature_verified) noexcept;

  // Narrow ledger integration points for control-plane consumers. Each
  // requires the matching AuthorityOperation::kind; payloads bind through
  // operation_hash (see bind_operation_payload).
  Status apply_remote_config(const AuthorityOperation& operation,
                             const Digest256& resulting_state_hash,
                             bool cryptographic_signature_verified) noexcept;
  Status apply_membership_approval(const AuthorityOperation& operation,
                                   const Digest256& resulting_state_hash,
                                   bool cryptographic_signature_verified) noexcept;
  Status apply_membership_revocation(const AuthorityOperation& operation,
                                     const Digest256& resulting_state_hash,
                                     bool cryptographic_signature_verified) noexcept;

  // Explicit operator recovery from quarantine: writes a fresh genesis record
  // under `new_generation`, which must exceed every generation any committed
  // (or committed-but-CRC-damaged) record proved this boot — so pre-loss
  // operations can never re-validate. The operator attests the generation is
  // fresh for (network, authority); after total media loss no ledger data
  // survives to bound it, so the attestation is the safety mechanism.
  // Never invoked implicitly; storage errors never trigger erase or reformat.
  Status recover(std::uint32_t new_generation) noexcept;

  const AuthorityRecord& state() const noexcept { return state_; }
  bool quarantined() const noexcept { return quarantined_; }
  // The operation_hash of the newest committed record. Remote-config
  // resume uses it to tell "our commit already landed before the power
  // loss" from "a different operation took the sequence".
  const Digest256& last_operation_hash() const noexcept {
    return last_operation_hash_;
  }
  // Build the next AuthorityOperation against the current ledger state:
  // generation + sequence = applied_sequence+1 + the state-hash chain link.
  // The caller supplies the real operation_hash (e.g. SHA-256 over the
  // canonical operation bytes) — never bind_operation_payload() in a
  // production trust path.
  Status build_operation(AuthorityOperationKind kind, const Digest256& operation_hash,
                         AuthorityOperation& out) const noexcept;
  // Committed ledger revision; while quarantined, the highest structurally
  // valid revision seen so operators can tell state was lost, not absent.
  std::uint64_t revision() const noexcept { return revision_; }

 private:
  Status commit_typed(AuthorityOperationKind expected,
                      const AuthorityOperation& operation,
                      const Digest256& resulting_state_hash,
                      bool cryptographic_signature_verified) noexcept;
  Status store_record(std::uint8_t slot, const AuthorityRecord& record,
                      std::uint64_t revision, const Digest256& previous_state_hash,
                      const Digest256& operation_hash) noexcept;

  NetworkId network_{0};
  NodeId authority_{kInvalidNodeId};
  LedgerStorage& storage_;
  AuthorityRecord state_{};
  Digest256 last_operation_hash_{};
  std::uint64_t revision_{0};
  std::uint64_t recovery_floor_{0};
  // Highest authority generation proven by any committed record this boot —
  // including committed-seal records whose CRC failed (their fields still
  // bound how far the ledger advanced). Recovery must start above it.
  std::uint32_t max_generation_seen_{1};
  std::array<StatusCode, kAuthorityLedgerSlots> slot_reserved_{};
  std::uint8_t active_slot_{0};
  bool has_active_{false};
  bool initialized_{false};
  bool quarantined_{false};
};

}  // namespace routeloom
