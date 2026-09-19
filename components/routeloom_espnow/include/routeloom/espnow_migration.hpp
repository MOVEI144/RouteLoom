#pragma once

// ESP-NOW-side bundle for the P5b migration execution path
// (docs/design/autonomous-mesh/04-channel-migration.md §5-§9). Three pieces:
//
//   - DevPskCommitVerifier: CommitSignatureVerifier over the SAME development
//     master key as DevelopmentPskSecurityProvider, domain-separated by HMAC
//     derivation. EXPERIMENTAL — SecurityProfile::Development; the commit
//     evidence is a real HMAC-SHA256 check, never a stubbed pass, but it is
//     shared-key material and is never advertised as production identity.
//   - NvsPlanStore: PlanStorage over NVS — two bounded hash-addressed blob
//     slots plus fixed commit/active record keys. Power-cut-safe at the NVS
//     commit boundary; CRC integrity lives in the record codecs.
//   - EspNowMigration: MigrationOwnerPort glue binding the portable
//     MigrationAgent to EspNowRuntime (wire port, channel runner, pause
//     mask) plus the optional SingleAuthority ledger for the issuer role.

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>

#include "nvs.h"
#include "routeloom/authority.hpp"
#include "routeloom/migration.hpp"
#include "routeloom/migration_wire.hpp"
#include "routeloom/espnow_runtime.hpp"

namespace routeloom::espnow {

// EXPERIMENTAL development commit verifier (G-SEC production signing is
// still pending — this is the explicit Development profile, surfaced as
// such). Derives a dedicated key:
//     key = HMAC-SHA256(master_key, "RouteLoom migration commit v1")
// and verifies commit evidence as HMAC-SHA256 over the canonical signing
// input (migration_wire commit_signing_input). Real cryptographic check;
// shared-key semantics only.
class DevPskCommitVerifier final : public CommitSignatureVerifier {
 public:
  DevPskCommitVerifier() = default;
  ~DevPskCommitVerifier() override;

  DevPskCommitVerifier(const DevPskCommitVerifier&) = delete;
  DevPskCommitVerifier& operator=(const DevPskCommitVerifier&) = delete;

  // Derives the domain-separated key. PSA crypto must be initialized — the
  // security provider's initialize() already does that on this runtime.
  Status initialize(const std::array<std::uint8_t, 32>& master_key) noexcept;

  bool ready() const noexcept override { return ready_; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  Status verify_commit(const AuthorityOperation& operation,
                       const Digest256& plan_hash,
                       ByteView signature) noexcept override;
  Status verify_snapshot(ByteView snapshot,
                         ByteView signature) noexcept override;

  // Issuer side (authority role only): produce the MAC a peer will verify.
  Status sign_commit(const AuthorityOperation& operation,
                     const Digest256& plan_hash, ChannelEpoch new_epoch,
                     std::array<std::uint8_t, 32>& out) noexcept;
  Status sign_snapshot(ByteView snapshot_body,
                       std::array<std::uint8_t, 32>& out) noexcept;

 private:
  Status mac(ByteView input, std::array<std::uint8_t, 32>& out) noexcept;
  Status check(ByteView input, ByteView signature) noexcept;

  std::array<std::uint8_t, 32> key_{};
  bool ready_{false};
};

// PlanStorage over NVS. Keys in one namespace:
//   "commit"  — the single durable commit record (kCommitRecordSize bound),
//   "active"  — the durable active record (kActiveRecordSize bound),
//   "pb0"/"pb1" — two hash-addressed plan-blob slots
//                 (magic | sequence | hash | len | blob).
// A torn or wrong-size blob read reports failure — the engine refetches
// rather than trusting truncated bytes. No path erases or reformats flash;
// a failed write is reported, never repaired silently.
class NvsPlanStore final : public PlanStorage {
 public:
  NvsPlanStore() = default;
  ~NvsPlanStore() override;

  NvsPlanStore(const NvsPlanStore&) = delete;
  NvsPlanStore& operator=(const NvsPlanStore&) = delete;

  Status open(const char* name_space) noexcept;
  void close() noexcept;

  Status write_blob(const Digest256& hash, ByteView blob) noexcept override;
  Status read_blob(const Digest256& hash, MutableByteView target,
                   std::size_t& out_size) noexcept override;
  Status drop_blob(const Digest256& hash) noexcept override;
  Status write_commit_record(ByteView record) noexcept override;
  Status read_commit_record(MutableByteView target,
                            std::size_t& out_size) noexcept override;
  Status write_active_record(ByteView record) noexcept override;
  Status read_active_record(MutableByteView target,
                            std::size_t& out_size) noexcept override;

  // Boot-time helper: the newest applied channel record, if any. Firmware
  // reads this BEFORE wifi init so the node boots onto its committed
  // channel (apply-on-resume without a post-boot switch). This is the
  // durable post-readback record — never a bare sleep image (D5-06).
  Status boot_channel(std::uint8_t& channel) noexcept;

 private:
  static constexpr std::uint32_t kBlobMagic = 0x524C4231U;  // "RLB1"
  static constexpr std::size_t kBlobSlots = 2;
  // magic u32 | sequence u32 | hash 32 | len u16 | blob
  static constexpr std::size_t kBlobRecordSize =
      4 + 4 + 32 + 2 + migration_const::kPlanBlobMax;

  Status read_blob_slot(std::uint8_t slot, Digest256& hash, std::uint32_t& seq,
                        MutableByteView blob, std::size_t& blob_size) noexcept;
  Status write_blob_slot(std::uint8_t slot, std::uint32_t seq,
                         const Digest256& hash, ByteView blob) noexcept;
  Status read_key(const char* key, MutableByteView target,
                  std::size_t& out_size) noexcept;
  Status write_key(const char* key, ByteView data) noexcept;

  nvs_handle_t handle_{0};
  bool open_{false};
};

struct EspNowMigrationConfig {
  MigrationAgentConfig agent{};
  MigrationMode mode{MigrationMode::Observe};
  bool authority_role{false};
  ChannelCoordinatorConfig coordinator{};
};

// Owns the authority-side objects (verifier-provided) and the agent; the
// Owner hooks: DATA pause via the pause mask (Cutover reason — the reserved
// control lane stays open), generation surfacing, diagnostics.
class EspNowMigration final : public MigrationOwnerPort {
 public:
  // `ledger_storage` is required iff config.authority_role — the issuer
  // needs the durable SingleAuthority ledger. A participant passes nullptr.
  EspNowMigration(const EspNowMigrationConfig& config,
                  EspNowRuntime& runtime, PlanStorage& plan_storage,
                  CommitSignatureVerifier& verifier,
                  LedgerStorage* ledger_storage) noexcept;

  // Sets the coordinator mode, restores the authority ledger (issuer only),
  // attaches the agent sink to the runtime (raising the runner visit cap to
  // the committed helper dwell) and runs the engine's resume path.
  Status start() noexcept;

  MigrationAgent& agent() noexcept { return agent_; }
  MigrationAuthority& authority() noexcept { return authority_; }
  ChannelCoordinator& coordinator() noexcept { return coordinator_; }
  bool authority_ready() const noexcept {
    return !config_.authority_role ||
           (ledger_.has_value() && !ledger_->quarantined());
  }

  // MigrationOwnerPort
  void hold_data(bool held) noexcept override;
  void note_radio_generation(std::uint32_t radio_generation) noexcept
      override;
  void on_migration_event(const char* reason, NodeId peer) noexcept override;

 private:
  EspNowMigrationConfig config_{};
  EspNowRuntime& runtime_;
  std::optional<SingleAuthority> ledger_;
  MigrationAuthority authority_;
  ChannelCoordinator coordinator_;
  MigrationAgent agent_;
  std::uint32_t last_radio_generation_{0};
};

}  // namespace routeloom::espnow
