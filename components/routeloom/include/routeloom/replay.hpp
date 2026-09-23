#pragma once

#include <cstdint>

#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

// Persisted receive-side anti-replay state for SecurityProvider
// implementations. Two record kinds are stored per peer:
//
// - ReplayWindowRecord: a reservation high-water ("accepted ceiling") for
//   one exact SecurityContext (scope + network + sender + receiver + epoch).
//   The 64-bit sliding window itself lives in RAM only (Window); the store
//   holds a ceiling that is always at or above every counter the window has
//   accepted. It is committed only when the live maximum crosses the
//   persisted ceiling, and then reserves `reservation_ahead` counters beyond
//   it — one flash commit per reservation step instead of one per frame
//   (issue #30), mirroring the TX counter lease.
// - ReplayFloorRecord: a monotonic epoch floor per peer pair (the same tuple
//   without the epoch). It is what makes "do not accept old epochs after
//   replay-state loss" enforceable: without it, a stale epoch is
//   indistinguishable from a brand-new context.
//
// Conservative loss semantics (reject-or-rehandshake):
// - After a restart (or any reopen without the RAM window) every counter at
//   or below the persisted ceiling is treated as already accepted. At most
//   `reservation_ahead` fresh counters plus the out-of-order stragglers of
//   the lost RAM bitmap are rejected; senders continue with new counters.
//   A counter above the ceiling can never have been accepted, because
//   accept() commits the raised ceiling BEFORE reporting success.
// - A context epoch below the persisted floor is always rejected.
// - A missing window record at the current floor epoch means the persisted
//   replay state was lost mid-epoch; the context is rejected until the peer
//   re-handshakes onto a newer epoch.
// - Corrupt or fingerprint-mismatched records are integrity errors, never a
//   reason to silently re-initialize a window.
// - A failed commit rolls the in-memory state back; the frame is not
//   accepted.
// - A completely missing floor is a cold start and adopts the incoming
//   epoch: with no persisted reference at all, first boot and total wipe
//   cannot be told apart without a trusted monotonic store (see
//   docs/spec/security.md and crash-time-resources.md).
namespace routeloom {

struct ReplayWindowRecord {  // 40 bytes, fixed layout, no padding
  std::uint64_t context_fingerprint{0};
  // Reservation high-water: every counter <= accepted_ceiling may already
  // have been accepted and is rejected after the RAM window is lost. It only
  // ever sits at or above the live maximum (see ReplayGuard::accept).
  // A pre-reservation record (layout 0) stored its maximum accepted counter
  // at this offset; reading that as a ceiling is exactly as conservative.
  std::uint64_t accepted_ceiling{0};
  std::uint64_t legacy_bitmap{0};  // layout 0 only; written as 0, never read
  std::uint32_t generation{0};
  std::uint8_t initialized{0};
  std::uint8_t layout{0};  // kReplayRecordLayout, or 0 for a legacy record
  std::uint8_t reserved[6]{};
  std::uint32_t crc{0};  // crc32_iso_hdlc over the preceding bytes
};
static_assert(sizeof(ReplayWindowRecord) == 40, "replay window layout");

// Default reservation step for the persisted accepted ceiling: one window
// commit per 64 counters advanced (the width of the RAM window). The price
// of a larger step is paid only after an unclean restart: up to this many
// fresh counters from each peer are rejected once.
constexpr std::uint32_t kReplayReservationAhead = 64;

struct ReplayFloorRecord {  // 24 bytes, fixed layout, no padding
  std::uint64_t peer_fingerprint{0};
  std::uint32_t generation{0};
  std::uint32_t minimum_epoch{0};
  std::uint8_t initialized{0};
  std::uint8_t layout{0};  // kReplayRecordLayout; v1 (u16 epoch) records read 0
  std::uint8_t reserved[2]{};
  std::uint32_t crc{0};  // crc32_iso_hdlc over the preceding bytes
};
static_assert(sizeof(ReplayFloorRecord) == 24, "replay floor layout");
// Wire v2 floor (32-bit minimum epoch). A v1 floor (u16 epoch, layout byte
// 0) is refused as corrupt — fail closed, never reinterpreted. Window
// records written by this code carry the same value (ceiling format); a
// layout-0 window is the older per-frame format and is read conservatively,
// any other layout is refused as corrupt.
constexpr std::uint8_t kReplayRecordLayout = 2;

// Persistent backing for replay records (NVS on device, test doubles on
// host). Implementations must report commit success only once the record is
// durable; an acknowledged-but-lost commit cannot be detected later and is
// an explicit store contract violation.
class ReplayStore {
 public:
  virtual ~ReplayStore() = default;
  virtual Status load_window(std::uint32_t slot, ReplayWindowRecord& record,
                             bool& found) noexcept = 0;
  virtual Status commit_window(std::uint32_t slot,
                               const ReplayWindowRecord& record) noexcept = 0;
  virtual Status load_floor(std::uint32_t slot, ReplayFloorRecord& record,
                            bool& found) noexcept = 0;
  virtual Status commit_floor(std::uint32_t slot,
                              const ReplayFloorRecord& record) noexcept = 0;
};

// Stable fingerprints bind persisted state to a security context. The peer
// fingerprint omits the epoch so the floor survives key-epoch changes; it
// must never be used to key counter material.
std::uint64_t replay_context_fingerprint(const SecurityContext& context) noexcept;
std::uint64_t replay_peer_fingerprint(const SecurityContext& context) noexcept;

class ReplayGuard {
 public:
  // reservation_ahead: how far past the live maximum each ceiling commit
  // reserves. 0 commits on every advance of the maximum (the pre-#30 cost).
  explicit ReplayGuard(
      ReplayStore& store,
      std::uint32_t reservation_ahead = kReplayReservationAhead) noexcept
      : store_(store), reservation_ahead_(reservation_ahead) {}

  // In-memory per-context replay state. Obtained from open_context and
  // threaded through accept(); the caller owns the storage and must keep at
  // most one open Window per context (a second one is refused at its next
  // commit, see accept()).
  struct Window {
    // Last record this window durably committed or loaded (initialized == 0
    // until the first accept of a fresh context commits a ceiling).
    ReplayWindowRecord record{};
    // Live sliding window, RAM only. Meaningful when `live`; reopened from
    // the store it starts at the persisted ceiling with every bit set, i.e.
    // everything at or below the ceiling counts as already accepted.
    std::uint64_t maximum_counter{0};
    std::uint64_t bitmap{0};
    bool live{false};
    std::uint32_t slot{0};
    // The context epoch this window was opened for. Windows share one
    // persisted slot per peer pair, so accept() re-checks this against the
    // floor: a stale in-memory window must never overwrite the live record.
    std::uint32_t epoch{0};
    bool open{false};
    // Peer-pair fingerprint of the owning context; lets accept() validate
    // the persisted floor is still THIS pair's record, not just any blob.
    std::uint64_t peer_fingerprint{0};
  };

  // window_slot is the per-(context, epoch) fingerprint; floor_slot is the
  // epoch-free peer-pair fingerprint. Persisted windows and counter leases
  // live at floor_slot so epoch advances re-key one record in place —
  // storage stays O(peers) regardless of how many epochs a peer burns
  // through (otherwise every boot would leak a record in NVS).
  // The u32 fold is a public, keyless computation: an insider who can pick
  // a NodeId can manufacture a targeted slot collision deterministically.
  // On the counter side a foreign record at the same slot wedges the lease
  // with Conflict (permanent TX failure to that destination); on the
  // replay side the colliding records cross-claim each other's state.
  // G-SEC identity design must derive these slots under a secret salt so
  // collision targeting requires the credential, not just the algorithm.
  static std::uint32_t window_slot(const SecurityContext& context) noexcept;
  static std::uint32_t floor_slot(const SecurityContext& context) noexcept;

  // Loads the persisted window for `context` and enforces the peer epoch
  // floor. Every failure is safe-side (see file comment).
  Status open_context(const SecurityContext& context, Window& window) noexcept;

  // Re-validates only the peer epoch floor. Callers that cache a Window must
  // run this on every frame: the floor may have advanced after the window
  // was opened (peer re-handshake), making the cached epoch stale.
  Status check_floor(const SecurityContext& context) noexcept;

  // Sliding-window accept against the RAM window. When the new maximum
  // exceeds the persisted ceiling, a raised ceiling (maximum +
  // reservation_ahead) is committed BEFORE success is reported; a failed
  // commit leaves the in-memory window untouched so the frame is never
  // treated as accepted. Frames at or below the ceiling (including
  // out-of-order ones inside the 64-bit window) cost no flash write.
  Status accept(Window& window, std::uint64_t counter) noexcept;

  // Retires a window the caller is about to drop while the process keeps
  // running (cache eviction, clean shutdown). If the persisted ceiling is
  // above the live maximum, it is lowered to the live maximum — still at or
  // above every counter accepted — so a later reopen rejects only the
  // out-of-order stragglers instead of up to reservation_ahead fresh
  // counters. At most one commit; the window is closed either way. A failed
  // or skipped tighten is safe (the higher ceiling simply stays).
  Status close_context(Window& window) noexcept;

  // Rejects caused by fingerprint-mismatched persisted records — the
  // observable signature of two peer pairs folded onto one u32 slot (or
  // foreign replay state at the slot), a permanent mutual-reject fault that
  // otherwise has no diagnostic.
  std::uint32_t foreign_fingerprint_rejects() const noexcept {
    return foreign_fingerprint_rejects_;
  }

 private:
  Status floor_state(const SecurityContext& context, ReplayFloorRecord& floor,
                     bool& found) noexcept;
  Status ratchet_floor(const SecurityContext& context,
                       const ReplayFloorRecord& floor, bool found) noexcept;
  Status check_window_floor(const Window& window) noexcept;
  Status commit_ceiling(Window& window, std::uint64_t ceiling) noexcept;

  ReplayStore& store_;
  std::uint32_t reservation_ahead_{kReplayReservationAhead};
  std::uint32_t foreign_fingerprint_rejects_{0};
};

}  // namespace routeloom
