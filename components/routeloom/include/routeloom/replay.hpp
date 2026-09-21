#pragma once

#include <cstdint>

#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

// Persisted receive-side anti-replay state for SecurityProvider
// implementations. Two record kinds are stored per peer:
//
// - ReplayWindowRecord: the sliding 64-bit counter window for one exact
//   SecurityContext (scope + network + sender + receiver + epoch).
// - ReplayFloorRecord: a monotonic epoch floor per peer pair (the same tuple
//   without the epoch). It is what makes "do not accept old epochs after
//   replay-state loss" enforceable: without it, a stale epoch is
//   indistinguishable from a brand-new context.
//
// Conservative loss semantics (reject-or-rehandshake):
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
  std::uint64_t maximum_counter{0};
  std::uint64_t bitmap{0};
  std::uint32_t generation{0};
  std::uint8_t initialized{0};
  std::uint8_t reserved[7]{};
  std::uint32_t crc{0};  // crc32_iso_hdlc over the preceding bytes
};
static_assert(sizeof(ReplayWindowRecord) == 40, "replay window layout");

struct ReplayFloorRecord {  // 24 bytes, fixed layout, no padding
  std::uint64_t peer_fingerprint{0};
  std::uint32_t generation{0};
  std::uint16_t minimum_epoch{0};
  std::uint8_t initialized{0};
  std::uint8_t reserved[5]{};
  std::uint32_t crc{0};  // crc32_iso_hdlc over the preceding bytes
};
static_assert(sizeof(ReplayFloorRecord) == 24, "replay floor layout");

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
  explicit ReplayGuard(ReplayStore& store) noexcept : store_(store) {}

  // In-memory per-context replay state. Obtained from open_context and
  // threaded through accept(); the caller owns the storage.
  struct Window {
    ReplayWindowRecord record{};
    std::uint32_t slot{0};
    // The context epoch this window was opened for. Windows share one
    // persisted slot per peer pair, so accept() re-checks this against the
    // floor: a stale in-memory window must never overwrite the live record.
    std::uint16_t epoch{0};
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
  static std::uint32_t window_slot(const SecurityContext& context) noexcept;
  static std::uint32_t floor_slot(const SecurityContext& context) noexcept;

  // Loads the persisted window for `context` and enforces the peer epoch
  // floor. Every failure is safe-side (see file comment).
  Status open_context(const SecurityContext& context, Window& window) noexcept;

  // Re-validates only the peer epoch floor. Callers that cache a Window must
  // run this on every frame: the floor may have advanced after the window
  // was opened (peer re-handshake), making the cached epoch stale.
  Status check_floor(const SecurityContext& context) noexcept;

  // Sliding-window accept. Persists the updated window before reporting
  // success; a failed commit rolls the in-memory window back so the frame
  // is never treated as accepted.
  Status accept(Window& window, std::uint64_t counter) noexcept;

 private:
  Status floor_state(const SecurityContext& context, ReplayFloorRecord& floor,
                     bool& found) noexcept;
  Status ratchet_floor(const SecurityContext& context,
                       const ReplayFloorRecord& floor, bool found) noexcept;

  ReplayStore& store_;
};

}  // namespace routeloom
