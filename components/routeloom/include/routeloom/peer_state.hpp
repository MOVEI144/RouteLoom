#pragma once

#include <cstddef>
#include <cstdint>

#include "routeloom/counter_store.hpp"
#include "routeloom/replay.hpp"
#include "routeloom/status.hpp"

// Bounded persistent per-peer security state for the development PSK
// profile (issue #37; docs/design/sdk-v1/05-nvs-state-37.md §4, plan P0-2).
//
// The development profile has no handshake: a context key is a pure function
// of (PSK, scope, network, sender, receiver, epoch). Two deletion rules
// follow from that (05 §2):
//
// - C1, TX counter records. A record may be dropped only if its key can never
//   be used again. TX keys are bound to this node's own epoch (the boot
//   session, monotonic), so a record whose key_epoch is below the current TX
//   epoch is dead — PROVIDED the node can never go back to that epoch. The
//   sweep therefore first commits a monotonic witness (the largest epoch it
//   is about to drop) and only then erases; afterwards every commit at or
//   below the witness is refused. Because a lease must commit a reservation
//   block before it issues a single counter (CounterLease::reserve_block),
//   refusing the commit refuses every counter under a dropped key.
// - C2, RX replay floors/windows. Dropping a floor or window lets a captured
//   frame under the same (still valid) key be accepted again, and forcing the
//   peer onto a newer epoch would wedge an idle but live peer until it
//   reboots (there is no in-band way to make it re-key). Nothing here ever
//   deletes RX state (05 §4 D2-d); growth is bounded instead: a NEW peer
//   pair's floor is refused once the cap is reached (D2-c), existing peers
//   keep working, and every refusal is counted.
//
// The production profile (05 §3) removes per-peer persistent state
// altogether; this file is only the interim mitigation.
namespace routeloom {

// Status detail of a refused NEW peer state (TX counter record or RX replay
// floor) once the per-peer cap is reached. Node diagnostics surface it.
inline constexpr char kPeerStateCapacityDetail[] = "PEER_STATE_CAPACITY";
// Status detail of a TX commit (or an open) at or below the sweep witness:
// that epoch's counter records may have been erased, so its keys are dead.
inline constexpr char kTxEpochWitnessDetail[] = "TX_EPOCH_AT_OR_BELOW_SWEEP_WITNESS";

// --- NVS entry budget (ESP-IDF NVS format v2) -------------------------------
// Mirrored by tools/nvs_budget.py, which CI checks against every firmware
// partition table (05 §5.3, V1-N07).
inline constexpr std::uint32_t kNvsEntryBytes = 32;
inline constexpr std::uint32_t kNvsEntriesPerPage = 126;
// A blob costs one index entry, one chunk header and its 32-byte data spans.
constexpr std::uint32_t nvs_blob_entries(const std::size_t bytes) noexcept {
  return 2U + static_cast<std::uint32_t>((bytes + kNvsEntryBytes - 1U) /
                                         kNvsEntryBytes);
}
// One persisted peer = Link + EndToEnd scope, each with a TX counter record,
// an RX floor and an RX window (05 section 1: at most ~20 entries per peer).
inline constexpr std::uint32_t kPeerStateEntriesPerPeer =
    2U * (nvs_blob_entries(sizeof(CounterRecord)) +
          nvs_blob_entries(sizeof(ReplayFloorRecord)) +
          nvs_blob_entries(sizeof(ReplayWindowRecord)));
static_assert(kPeerStateEntriesPerPeer == 20, "sdk-v1/05 entry budget per peer");
// Two namespace entries plus the u32 sweep witness.
inline constexpr std::uint32_t kPeerStateFixedEntries = 3;
// Share of the usable entries (one page is kept free for NVS GC) the capped
// peer state may claim; the rest absorbs page fragmentation and rewrites.
inline constexpr std::uint32_t kPeerStateBudgetPercent = 80;

// Largest peer count whose worst-case records fit the budget of an NVS
// partition with `total_entries` entries (nvs_get_stats().total_entries).
constexpr std::uint32_t max_persisted_peers_for_entries(
    const std::uint32_t total_entries) noexcept {
  const std::uint64_t usable =
      total_entries > kNvsEntriesPerPage ? total_entries - kNvsEntriesPerPage
                                         : 0U;
  const std::uint64_t budget = usable * kPeerStateBudgetPercent / 100U;
  return budget > kPeerStateFixedEntries
             ? static_cast<std::uint32_t>((budget - kPeerStateFixedEntries) /
                                          kPeerStateEntriesPerPeer)
             : 0U;
}

struct PeerStateLimits {
  std::uint32_t max_counter_records{0};  // TX: one per (scope, receiver)
  std::uint32_t max_replay_peers{0};     // RX: one floor(+window) per (scope, sender)
};

// A persisted peer spans both scopes, so each record kind gets two slots.
constexpr PeerStateLimits peer_state_limits(
    const std::uint32_t max_persisted_peers) noexcept {
  const std::uint32_t slots =
      max_persisted_peers > 0x7FFFFFFFU ? 0xFFFFFFFFU : 2U * max_persisted_peers;
  return PeerStateLimits{slots, slots};
}

// Enumeration callback of the inventories below.
class SlotVisitor {
 public:
  virtual ~SlotVisitor() = default;
  // Returns false to stop the enumeration early.
  virtual bool visit(std::uint32_t slot) noexcept = 0;
};

// A CounterStore whose records can be enumerated and erased, plus the durable
// sweep witness. The NVS adapter and host doubles implement it.
class CounterInventory : public CounterStore {
 public:
  // Visits every persisted counter slot once (never the witness). The
  // visitor may load() records while the enumeration runs, but must not
  // commit or erase.
  virtual Status for_each_slot(SlotVisitor& visitor) noexcept = 0;
  // Durably removes one record; an absent record is success.
  virtual Status erase(std::uint32_t slot) noexcept = 0;
  virtual Status load_witness(std::uint32_t& witness, bool& found) noexcept = 0;
  // Must be durable before it returns success (erasures depend on it).
  virtual Status commit_witness(std::uint32_t witness) noexcept = 0;
};

// A ReplayStore whose floor records can be enumerated (counting only; RX
// state is never erased, see the file comment).
class ReplayInventory : public ReplayStore {
 public:
  virtual Status for_each_floor_slot(SlotVisitor& visitor) noexcept = 0;
};

struct CounterSweepReport {
  std::uint32_t erased{0};               // dead records removed (C1)
  std::uint32_t retained_current{0};     // key_epoch == TX epoch
  std::uint32_t retained_future{0};      // key_epoch > TX epoch: regression evidence
  std::uint32_t retained_unreadable{0};  // corrupt / foreign layout: kept, fail closed
  std::uint32_t passes{0};
};

// CounterStore decorator: sweeps dead TX records at open (05 §4 D2-b),
// enforces the witness on every commit and caps the record count (D2-c).
class BoundedCounterStore final : public CounterStore {
 public:
  // `tx_epoch` is the lowest epoch any lease will use until the next open —
  // the boot session. Refuses (Conflict, kTxEpochWitnessDetail) an epoch at
  // or below a persisted witness: some of its records may have been erased,
  // so reusing it could reuse (key, counter) pairs. A witness that cannot be
  // read fails the open (StorageFailure/IntegrityError). A failed sweep does
  // NOT fail the open: records stay (safe), sweep_status() says why, and new
  // records are refused if the count could not be established.
  Status open(CounterInventory& inner, std::uint32_t max_records,
              std::uint32_t tx_epoch) noexcept;
  void close() noexcept;
  bool is_open() const noexcept { return inner_ != nullptr; }

  Status load(std::uint32_t slot, CounterRecord& record,
              bool& found) noexcept override;
  Status commit(std::uint32_t slot, const CounterRecord& record) noexcept override;

  std::uint32_t records() const noexcept { return records_; }
  std::uint32_t max_records() const noexcept { return max_records_; }
  bool records_known() const noexcept { return records_known_; }
  bool witness_present() const noexcept { return witness_found_; }
  std::uint32_t witness() const noexcept { return witness_; }
  std::uint32_t capacity_rejects() const noexcept { return capacity_rejects_; }
  std::uint32_t witness_rejects() const noexcept { return witness_rejects_; }
  const CounterSweepReport& sweep_report() const noexcept { return report_; }
  Status sweep_status() const noexcept { return sweep_status_; }

 private:
  Status sweep() noexcept;

  CounterInventory* inner_{nullptr};
  std::uint32_t max_records_{0};
  std::uint32_t tx_epoch_{0};
  std::uint32_t witness_{0};
  bool witness_found_{false};
  std::uint32_t records_{0};
  bool records_known_{false};
  std::uint32_t capacity_rejects_{0};
  std::uint32_t witness_rejects_{0};
  CounterSweepReport report_{};
  Status sweep_status_{};
};

// ReplayStore decorator: caps the number of persisted peer pairs (floor
// slots). Never deletes anything. A window may only be written next to its
// pair's floor (ReplayGuard always ratchets the floor first), so windows are
// bounded by the same cap.
class BoundedReplayStore final : public ReplayStore {
 public:
  // Counts the persisted floors. A failed count does not fail the open:
  // existing peers keep working and new peers are refused.
  Status open(ReplayInventory& inner, std::uint32_t max_peers) noexcept;
  void close() noexcept;
  bool is_open() const noexcept { return inner_ != nullptr; }

  Status load_window(std::uint32_t slot, ReplayWindowRecord& record,
                     bool& found) noexcept override;
  Status commit_window(std::uint32_t slot,
                       const ReplayWindowRecord& record) noexcept override;
  Status load_floor(std::uint32_t slot, ReplayFloorRecord& record,
                    bool& found) noexcept override;
  Status commit_floor(std::uint32_t slot,
                      const ReplayFloorRecord& record) noexcept override;

  std::uint32_t peers() const noexcept { return peers_; }
  std::uint32_t max_peers() const noexcept { return max_peers_; }
  bool peers_known() const noexcept { return peers_known_; }
  std::uint32_t capacity_rejects() const noexcept { return capacity_rejects_; }
  Status count_status() const noexcept { return count_status_; }

 private:
  ReplayInventory* inner_{nullptr};
  std::uint32_t max_peers_{0};
  std::uint32_t peers_{0};
  bool peers_known_{false};
  std::uint32_t capacity_rejects_{0};
  Status count_status_{};
};

// Aggregate for providers and firmware logs.
struct PeerStateStats {
  std::uint32_t counter_records{0};
  std::uint32_t counter_capacity{0};
  std::uint32_t replay_peers{0};
  std::uint32_t replay_capacity{0};
  std::uint32_t capacity_rejects{0};  // TX + RX refusals (PEER_STATE_CAPACITY)
  std::uint32_t witness_rejects{0};
  std::uint32_t witness{0};
  bool witness_present{false};
  bool counts_known{false};
  CounterSweepReport sweep{};
};

}  // namespace routeloom
