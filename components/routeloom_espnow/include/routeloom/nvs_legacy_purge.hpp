#pragma once

// NVS-backed LegacyPurgePort for the physical `security legacy-state`
// console verb (G-SEC P4 §10.2): enumerates the exact legacy peer-record
// shapes (`rlcounter:c%08x`, `rlreplay:f/r%08x`) in the rlsec partition
// and commits the `rldev/migration` RAM-only marker. Erase never touches
// anything outside those two namespaces and shapes — cmax, witnesses,
// boot_hi, RLI1/RLS1/RLT1/RRS1/RLV1/RLP and config records all survive.
// Single-threaded on the maintenance console task (radio never runs in
// that boot, so `stopped` is structural). No heap, no exceptions.

#include <cstddef>

#include "routeloom/sdkv1_legacy_purge.hpp"
#include "routeloom/status.hpp"

namespace routeloom::espnow {

// The durable "RAM-only migrated" marker (P4 §10.2): NVS u32 fixed value
// `0x52414D31` ("RAM1"). Any other value, type or read failure is not a
// marker — the port reports it instead of guessing.
inline constexpr std::uint32_t kLegacyMigrationMagic = 0x52414D31;

// A migrated device must never restart the persistent legacy provider in
// this firmware image. Called before any legacy counter/replay store opens.
Status refuse_legacy_boot_after_migration() noexcept;

class NvsLegacyPurgePort final : public sdkv1::LegacyPurgePort {
 public:
  NvsLegacyPurgePort() noexcept = default;

  NvsLegacyPurgePort(const NvsLegacyPurgePort&) = delete;
  NvsLegacyPurgePort& operator=(const NvsLegacyPurgePort&) = delete;

  Status migration(bool& present) noexcept override;
  Status commit_migration() noexcept override;
  // Restartable cursor enumeration over rlcounter then rlreplay (a zero
  // cursor opens a new pass). Each call re-finds the NVS iterator and
  // skips to the effective ordinal, so an erase committed between calls
  // never invalidates iteration; erases already done in this pass shift
  // later ordinals down and are compensated. Returned names stay valid
  // through the next call or erase, whichever comes first.
  Status next(std::size_t& cursor, sdkv1::LegacyKey& key, bool& found) noexcept override;
  // Erases one enumerated key (namespace + shape re-checked; anything
  // outside the legacy peer shapes is refused). An already-gone key is
  // success — retries stay idempotent.
  Status erase(const sdkv1::LegacyKey& key) noexcept override;

 private:
  std::size_t pass_erases_{0};  // legacy erases in the current enumeration
  char space_[16]{};
  char key_[16]{};
};

}  // namespace routeloom::espnow
