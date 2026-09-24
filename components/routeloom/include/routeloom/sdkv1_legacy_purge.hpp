#pragma once

#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"

namespace routeloom::sdkv1 {

// Physical-maintenance-only purge of the three obsolete peer record shapes.
// The caller must first check the full maintenance-domain fingerprint and
// stop/drain radio, USB and Node; this port never makes that authorization.
struct LegacyKey {
  const char* name_space{nullptr};
  const char* key{nullptr};
};

class LegacyPurgePort {
 public:
  virtual ~LegacyPurgePort() = default;
  // migration is a durable RAM1 marker; unknown schema/type must fail.
  virtual Status migration(bool& present) noexcept = 0;
  virtual Status commit_migration() noexcept = 0;
  // cursor starts at zero for every new enumeration. Names remain valid
  // through erase(); enumeration must have finite length.
  virtual Status next(std::size_t& cursor, LegacyKey& key, bool& found) noexcept = 0;
  virtual Status erase(const LegacyKey& key) noexcept = 0;
};

struct LegacyPurgeResult {
  std::uint32_t erased{0};
  std::uint32_t remaining{0};
};

bool is_legacy_peer_key(const LegacyKey& key) noexcept;
// One pass deletes at most 16 records. Caller repeats until remaining==0.
// A failure returns without claiming completion; retries are idempotent.
Status purge_legacy_state(LegacyPurgePort& port, bool stopped, bool ram_only_build,
                          LegacyPurgeResult& result) noexcept;

}  // namespace routeloom::sdkv1
