#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

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

// Physical-maintenance console for the purge (P4 §10.2): the portable logic
// behind the firmware's `security legacy-state` verb. The firmware runner
// feeds one line at a time over an exclusive maintenance boot (never the
// mesh/USB remote command path) and stops/drains radio, USB and Node first;
// `stopped` carries that fact per line. `domain` is the full expected
// maintenance-domain fingerprint (sdkv1_dev_session); the runner computes it
// from the PSK/site and this class compares bytes exactly, never printing it.
//
// Protocol (one line in, one line out; tokens split on exactly one space):
//   status                                    -> OK legacy=<n> marker=<0|1>
//   purge --domain <32hex> --confirm          -> OK erased=<e> remaining=<r>
// Failures are `ERR <token>`: `domain` (no match, malformed included),
// `busy` (radio not stopped), `refused` (legacy build), `store` (port
// failure), `invalid_argument`. Every refusal leaves the store untouched.
// process_line returns Ok whenever a response line was produced; only a
// short response buffer is a caller bug. Responses are NUL-terminated with
// size excluding the NUL.
class LegacyStateConsole {
 public:
  static constexpr std::size_t kResponseMax = 96;
  LegacyStateConsole(LegacyPurgePort& port, const std::array<std::uint8_t, 16>& domain,
                     bool ram_only_build) noexcept;

  LegacyStateConsole(const LegacyStateConsole&) = delete;
  LegacyStateConsole& operator=(const LegacyStateConsole&) = delete;

  Status process_line(ByteView line, bool stopped, char* response,
                      std::size_t response_capacity, std::size_t& response_size) noexcept;

 private:
  LegacyPurgePort& port_;
  std::array<std::uint8_t, 16> domain_{};
  bool ram_only_{false};
};

}  // namespace routeloom::sdkv1
