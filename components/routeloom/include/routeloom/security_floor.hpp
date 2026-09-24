// The RLF1 security floor (04 §4.7): one small integrity-sealed record that
// survives the loss of the journal AND the trust slots it bounds. Every
// protected counter — the trust epoch floor E, the authority-generation
// floor G, each namespace's journal store floor J and decision floor R —
// is reserved here BEFORE the record that consumes it is written, so a
// power cut can only leave a consumed gap, never a reused value. The
// journal and the trust store read the floor at boot and refuse intake
// when it is missing, corrupt, or behind their own records; there is no
// silent re-creation (a lost floor is re-provisioned through the explicit
// managed path, never inferred from the stores it is supposed to bound).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/authority.hpp"
#include "routeloom/byte_io.hpp"
#include "routeloom/status.hpp"

namespace routeloom {

// --- RLF1 record layout (fixed 136 B) ---------------------------------------
//   0   u32  magic "RLF1"
//   4   u16  format | u16 blob_len (136)
//   8   u64  network | u64 target
//   24  u32  trust_epoch_floor (E) | u32 min_authority_generation (G)
//   32  u8[32] last committed RTM1 original hash (zero only before the
//              first managed trust install)
//   64  u8   namespace_count | u8 flags (bit0 = trust-managed) | u16 reserved=0
//   68  4 x (u16 ns | u16 schema | u32 store floor J | u64 decision floor R)
//   132 u32  crc32 over bytes [0, 132)
constexpr std::uint32_t kSecurityFloorMagic = 0x524C4631U;  // "RLF1"
constexpr std::uint16_t kSecurityFloorFormat = 1;
constexpr std::size_t kSecurityFloorBlobBytes = 136;
constexpr std::size_t kSecurityFloorMaxNamespaces = 4;
// The trust store is root-managed on this device: generation policy comes
// from the committed RLT1 image bounded below by E/G, never from a fixed
// configured pin.
constexpr std::uint8_t kSecurityFloorTrustManaged = 0x01;

struct SecurityFloorEntry {
  std::uint16_t config_namespace{0};
  std::uint16_t schema{0};
  std::uint32_t store_floor{0};     // J: next journal record uses J + 1
  std::uint64_t decision_floor{0};  // R: next decision uses at least R + 1
};

struct SecurityFloorState {
  NetworkId network{0};
  NodeId target{kInvalidNodeId};
  std::uint32_t trust_epoch_floor{0};
  std::uint32_t min_authority_generation{0};
  Digest256 last_manifest_hash{};
  std::uint8_t namespace_count{0};
  std::uint8_t flags{0};
  std::array<SecurityFloorEntry, kSecurityFloorMaxNamespaces> entries{};
};

// Single-blob persistence for the floor record. read() fills the whole
// 136 B image; write() replaces it atomically (NVS blob set + commit) and
// must return an error unless the bytes provably landed.
class SecurityFloorStorage {
 public:
  virtual ~SecurityFloorStorage() = default;
  virtual Status read(MutableByteView target) noexcept = 0;
  virtual Status write(ByteView data) noexcept = 0;
};

Status security_floor_encode(const SecurityFloorState& state,
                             MutableByteView out) noexcept;
Status security_floor_decode(ByteView blob, SecurityFloorState& out) noexcept;

// The floor is Owner-serialized (the same single-threaded Owner that drives
// the journal and the trust store) — no internal locking. The validated
// image is cached in RAM; any failed write or readback invalidates the
// cache and stops privileged intake until refresh() re-proves the bytes.
class SecurityFloorStore {
 public:
  explicit SecurityFloorStore(SecurityFloorStorage& storage) noexcept
      : storage_(storage) {}

  // Read and validate the provisioned floor. A missing, torn or
  // regressed image fails — the floor is never auto-created, because a
  // re-invented floor would unbind exactly the counters it must bound.
  Status initialize() noexcept;
  bool usable() const noexcept { return usable_; }
  // Re-read the stored image after a failure (write/readback error left
  // the cache invalid). Intake stays stopped until this succeeds.
  Status refresh() noexcept;
  // The validated cached image. Fails while the floor is unusable.
  Status read(SecurityFloorState& out) const noexcept;

  // Move floors forward: `expected` must equal the cached image (the
  // caller proves it decided against current floors), `next` keeps the
  // identity, the namespace table and the flags, and never lowers E, G,
  // J or R. Encode -> write -> readback, then the cache follows. A
  // next == expected call is a no-op success (idempotent resume replays
  // the reservation they already hold).
  Status advance(const SecurityFloorState& expected,
                 const SecurityFloorState& next) noexcept;

  // Explicit provisioning / managed re-provisioning: installs `state`
  // wholesale (encode -> write -> readback). The ONLY path that creates
  // or lowers a floor — normal operation and boot never call it.
  Status provision_seed(const SecurityFloorState& state) noexcept;

  static const SecurityFloorEntry* entry_for(const SecurityFloorState& state,
                                             std::uint16_t config_namespace) noexcept;
  static SecurityFloorEntry* entry_for_mut(SecurityFloorState& state,
                                           std::uint16_t config_namespace) noexcept;

 private:
  Status commit(const SecurityFloorState& state) noexcept;

  SecurityFloorStorage& storage_;
  SecurityFloorState cached_{};
  bool usable_{false};
};

}  // namespace routeloom
