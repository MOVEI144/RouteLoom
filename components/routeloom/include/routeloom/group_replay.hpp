#pragma once

// Bounded, RAM-only receive replay state for SecurityScope::Group contexts
// (docs/design/sdk-v1/group-delivery.md §7, sdk-v1/03 §6.2/§6.5).
//
// One entry per (network, sender, context receiver). The wire layer uses one
// site-group context per sender (receiver = kBroadcastNodeId; the destination
// group is authenticated in the end AAD), so a site needs one entry per group
// SENDER however many groups it uses. Each entry holds the sender's current
// epoch plus a 64-counter sliding window. Rules:
//   * a lower epoch than the entry's is refused (a previous sender boot);
//   * a higher epoch restarts the window (the sender rebooted: new key);
//   * inside one epoch a counter is accepted once — above the window
//     maximum it slides the window, below the window it is refused;
//   * a NEW (sender, context) pair when the table is full is REFUSED and
//     counted, never admitted by evicting another: eviction would re-open
//     the evicted pair to replay (sdk-v1/03 §6.2).
// Nothing is persisted, so no per-peer NVS state is added (#37): after a
// receiver reboot a frame captured under a still-current sender epoch can be
// accepted once more. That is the documented group-key limit (03 §6.5);
// group payloads are idempotent state notifications, and the node's own
// per-source stream window deduplicates within a boot.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

class GroupReplayTable {
 public:
  static constexpr std::size_t kCapacity = 16;
  static constexpr std::uint32_t kWindow = 64;

  // Accept-once check for an AUTHENTICATED group frame (call only after the
  // AEAD tag verified). Only SecurityScope::Group contexts are accepted.
  Status accept(const SecurityContext& context, std::uint64_t counter) noexcept;

  std::size_t size() const noexcept;
  std::uint32_t replays() const noexcept { return replays_; }
  std::uint32_t stale_epochs() const noexcept { return stale_epochs_; }
  std::uint32_t capacity_refusals() const noexcept { return capacity_refusals_; }
  void clear() noexcept;

 private:
  struct Entry {
    NetworkId network{0};
    NodeId sender{kInvalidNodeId};
    NodeId group{kInvalidNodeId};
    std::uint32_t epoch{0};
    std::uint64_t maximum{0};
    std::uint64_t bitmap{0};  // bit i: counter maximum - i accepted
    bool used{false};
  };
  std::array<Entry, kCapacity> entries_{};
  std::uint32_t replays_{0};
  std::uint32_t stale_epochs_{0};
  std::uint32_t capacity_refusals_{0};
};

}  // namespace routeloom
