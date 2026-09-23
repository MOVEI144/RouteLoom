#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "routeloom/counter_store.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/group_replay.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/nvs_replay_store.hpp"
#include "routeloom/peer_state.hpp"
#include "routeloom/replay.hpp"
#include "routeloom/security.hpp"

namespace routeloom::espnow {

// Persisted-peer caps (issue #37, sdk-v1/05 §4 D2-c and §5.2). A persisted
// peer is worst case kPeerStateEntriesPerPeer (20) NVS entries; the caps keep
// that within 80% of the security partition, which tools/nvs_budget.py checks
// against every firmware partition table. Firmware also clamps them to what
// the mounted partition can hold (nvs_partition_peer_capacity).
inline constexpr std::uint32_t kNodeMaxPersistedPeers = 64;      // 64 KiB rlsec
inline constexpr std::uint32_t kGatewayMaxPersistedPeers = 128;  // 128 KiB rlsec

// Where and how the development provider persists per-peer state.
struct PeerStateConfig {
  // NVS namespace of the replay floors/windows (opened by the provider).
  const char* replay_namespace{"rlreplay"};
  // NVS partition label of that namespace; nullptr selects the default
  // "nvs". The counter store passed to initialize() is opened by the caller
  // and should live in the same partition.
  const char* partition{nullptr};
  // Lowest TX epoch this node uses until the next initialize(): the boot
  // session (link/end epochs are derived from it). TX counter records of
  // older epochs are swept at initialize() (05 §4 D2-b). Must be non-zero.
  std::uint32_t tx_epoch{0};
  // Cap on persisted peers (both scopes); new peers beyond it are refused
  // with PEER_STATE_CAPACITY, existing peers are unaffected.
  std::uint32_t max_persisted_peers{kNodeMaxPersistedPeers};
};

// Development baseline for CORE_FIXED_250. It supplies real AES-GCM, durable
// counters and replay state, but a shared master key is not a production device
// identity system. Replace it with the qualified EDHOC/RPK provider before a
// secure production release. security_profile() is pinned to Development.
class DevelopmentPskSecurityProvider final : public SecurityProvider {
 public:
  static constexpr std::size_t kMasterKeySize = 32;
  // Flash-wear budget (issues #30/#57, crash-time-resources.md §7):
  // - TX: kTxContextCapacity live leases; an evicted lease parks its
  //   unissued block remainder in a checkpoint cache (compact, RAM only),
  //   so re-creating it within kParkedLeaseCapacity further contexts costs
  //   no block commit.
  // - RX: kRxContextCapacity live replay windows. The window is RAM-only
  //   behind a persisted ceiling (ReplayGuard), so an eviction tightens the
  //   ceiling (<= 1 commit) and the reopen's next accept re-reserves
  //   (<= 1 commit). Sized so a gateway's link + end contexts stay resident.
  static constexpr std::size_t kTxContextCapacity = 32;
  static constexpr std::size_t kParkedLeaseCapacity = 64;
  static constexpr std::size_t kRxContextCapacity = 64;

  DevelopmentPskSecurityProvider() = default;
  ~DevelopmentPskSecurityProvider() override;

  // Fails closed (Conflict, TX_EPOCH_AT_OR_BELOW_SWEEP_WITNESS) when
  // config.tx_epoch is at or below the persisted sweep witness — the boot
  // session went backwards relative to erased TX records — and when the
  // witness or the replay namespace cannot be opened. A failed sweep or peer
  // census is NOT fatal: see peer_state_stats()/counter_sweep_status().
  Status initialize(const std::array<std::uint8_t, kMasterKeySize>& master_key,
                    NvsCounterStore& counter_store,
                    const PeerStateConfig& config) noexcept;
  void close() noexcept;

  bool ready() const noexcept override { return ready_; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  // Replay-state diagnostics: rejects caused by fingerprint-mismatched
  // records — the u32 slot-collision signature (see ReplayGuard).
  std::uint32_t foreign_fingerprint_rejects() const noexcept {
    return replay_guard_.foreign_fingerprint_rejects();
  }
  // Bounded peer state (#37): record counts against the caps, capacity and
  // witness refusals, and the report of the boot-time TX record sweep.
  PeerStateStats peer_state_stats() const noexcept;
  Status counter_sweep_status() const noexcept {
    return counters_.sweep_status();
  }
  Status replay_census_status() const noexcept {
    return replay_bounds_.count_status();
  }
  // SecurityScope::Group receive state (group-delivery.md §7): RAM-only,
  // bounded (GroupReplayTable::kCapacity group senders), never
  // persisted — it adds no per-peer NVS records (#37).
  const GroupReplayTable& group_replay() const noexcept { return group_replay_; }
  Status next_counter(const SecurityContext& context,
                      std::uint64_t& counter) noexcept override;
  Status seal(const SecurityContext& context, std::uint64_t counter,
              ByteView aad, ByteView plaintext, MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override;
  Status open(const SecurityContext& context, std::uint64_t counter,
              ByteView aad, ByteView ciphertext,
              const std::array<std::uint8_t, kAeadTagSize>& tag,
              MutableByteView plaintext) noexcept override;

 private:
  struct TxContext {
    SecurityContext context{};
    std::uint64_t fingerprint{0};
    std::optional<CounterLease> lease{};
    // LRU stamp: evicted first when the bounded context pool fills.
    std::uint64_t use_stamp{0};
  };

  struct RxContext {
    SecurityContext context{};
    ReplayGuard::Window window{};
    std::uint64_t use_stamp{0};
  };

  static bool same_context(const SecurityContext& left,
                           const SecurityContext& right) noexcept;
  Status derive_key(const SecurityContext& context,
                    std::array<std::uint8_t, 32>& key) const noexcept;
  static void make_nonce(const SecurityContext& context, std::uint64_t counter,
                         std::array<std::uint8_t, 12>& nonce) noexcept;
  TxContext* tx_context(const SecurityContext& context) noexcept;
  Status rx_context(const SecurityContext& context, RxContext*& result) noexcept;

  std::array<std::uint8_t, kMasterKeySize> master_key_{};
  // TX leases commit through the bounded decorator: witness gate + cap.
  BoundedCounterStore counters_{};
  NvsReplayStore replay_store_{};
  // RX floors/windows: capped, never deleted.
  BoundedReplayStore replay_bounds_{};
  ReplayGuard replay_guard_{replay_bounds_};
  bool ready_{false};
  FixedPool<TxContext, kTxContextCapacity> tx_contexts_{};
  CounterCheckpointCache<kParkedLeaseCapacity> parked_leases_{};
  FixedPool<RxContext, kRxContextCapacity> rx_contexts_{};
  GroupReplayTable group_replay_{};
  std::uint64_t context_stamp_{0};
};

// Boot log of the bounded peer state (#37): counts against the caps, the TX
// sweep report, sweep/census failures and the NVS usage of `partition`.
// Never silent — a degraded census or sweep is logged as an error.
void log_peer_state(const char* tag,
                    const DevelopmentPskSecurityProvider& security,
                    const char* partition) noexcept;

}  // namespace routeloom::espnow
