#pragma once

#include <cstdint>

#include "nvs.h"
#include "routeloom/trust_store.hpp"

namespace routeloom::espnow {

// TrustStoreStorage over NVS blobs (keys "t0"/"t1", namespace "rltrust";
// 04-provisioning-lifecycle.md §4.2.2/§4.3.1). One instance backs the ONE
// dual-slot RLT1 trust store for this node.
//
// Power-loss / corruption contract (mirrors NvsConfigStore semantics):
//   - a missing blob reads back as a uniformly-erased slot image, which
//     the store's classifier sees as Empty (never written);
//   - a blob that EXISTS but reads back uniformly erased/zeroed (or
//     zero-length) is a torn/anomalous write — reported corrupt, never
//     Empty, so presence evidence can't silently reset the store to a
//     fresh unprovisioned state;
//   - a blob larger than the slot, or a read fault, is reported as
//     corrupt / StorageFailure — never silently "fixed";
//   - the variable-length record lands as a blob of exactly data.size;
//     the unread tail of the 2048-byte slot reads back 0xFF (erased),
//     matching what the store wrote only up to used_len;
//   - nvs_flash_erase is never called and a failed write is reported,
//     never repaired by reformatting. Recovery is the store's explicit
//     recover() — an operator act, never an implicit reset.
class NvsTrustStore final : public TrustStoreStorage {
 public:
  // Committed-write accounting for the §4.9 flash-wear budget: every
  // successful write() counts one NVS commit and its blob byte length.
  struct WriteStats {
    std::uint64_t commits{0};
    std::uint64_t bytes{0};
  };

  NvsTrustStore() = default;
  ~NvsTrustStore() override;

  NvsTrustStore(const NvsTrustStore&) = delete;
  NvsTrustStore& operator=(const NvsTrustStore&) = delete;

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
