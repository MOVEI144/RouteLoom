#pragma once

#include <cstdint>

#include "nvs.h"
#include "routeloom/config.hpp"

namespace routeloom::espnow {

// ConfigJournalStorage over NVS blobs (keys "j0"/"j1"). One instance backs
// ONE (network, target, namespace) journal: the caller opens a distinct NVS
// namespace per config namespace (e.g. "rlcj1".."rlcj4").
//
// Power-loss / corruption contract (04-remote-config.md §4.7):
//   - a missing blob reads back as a uniformly-erased image, which the
//     journal's is_erased() classifies as an Empty (never-written) slot;
//   - a blob that EXISTS but reads back uniformly erased/zeroed (or
//     zero-length) is a torn/anomalous write — reported corrupt, never
//     Empty, so presence evidence can't silently reset to revision 0;
//   - a blob larger than the slot, or a read fault, is reported as corrupt /
//     StorageFailure — never silently reset to a "known" revision 0;
//   - the variable-length record lands as a blob of exactly data.size; the
//     unread tail of the 4096-byte slot reads back 0xFF (erased), matching
//     what the journal wrote only up to record_len;
//   - nvs_flash_erase is never called and a failed write is reported, never
//     repaired by reformatting.
class NvsConfigStore final : public ConfigJournalStorage {
 public:
  // Committed-write accounting for the §6.8 flash-write measurement: every
  // successful write() counts one NVS commit and its blob byte length.
  struct WriteStats {
    std::uint64_t commits{0};
    std::uint64_t bytes{0};
  };

  NvsConfigStore() = default;
  ~NvsConfigStore() override;

  NvsConfigStore(const NvsConfigStore&) = delete;
  NvsConfigStore& operator=(const NvsConfigStore&) = delete;

  Status open(const char* name_space) noexcept;
  void close() noexcept;

  Status read(std::uint8_t slot, MutableByteView target) noexcept override;
  Status write(std::uint8_t slot, ByteView data) noexcept override;

  WriteStats write_stats() const noexcept { return stats_; }

 private:
  nvs_handle_t handle_{0};
  bool open_{false};
  WriteStats stats_{};
};

}  // namespace routeloom::espnow
