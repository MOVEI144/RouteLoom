#pragma once

#include <cstdint>

#include "nvs.h"
#include "routeloom/device_credential.hpp"

namespace routeloom::espnow {

// CredentialStorage over NVS blobs (keys "d0"/"d1", namespace "rlcred";
// 04-provisioning-lifecycle.md §4.2.2/§4.3.2). One instance backs the ONE
// dual-slot RLC1 device-credential record for this node.
//
// Same power-loss / corruption contract as NvsTrustStore/NvsConfigStore:
//   - a missing blob reads back as a uniformly-erased slot image, which
//     the store's classifier sees as Empty (no credential provisioned);
//   - a blob that EXISTS but reads back uniformly erased/zeroed (or
//     zero-length) is a torn/anomalous write — reported corrupt, never
//     Empty;
//   - a blob larger than the slot, or a read fault, is reported as
//     corrupt / StorageFailure;
//   - the variable-length record lands as a blob of exactly data.size;
//     the unread tail of the 1024-byte slot reads back 0xFF (erased);
//   - nvs_flash_erase is never called and a failed write is reported,
//     never repaired by reformatting. Recovery is the store's explicit
//     recover() — an operator act, never an implicit reset.
class NvsCredStore final : public CredentialStorage {
 public:
  // Committed-write accounting for the §4.9 flash-wear budget: every
  // successful write() counts one NVS commit and its blob byte length.
  struct WriteStats {
    std::uint64_t commits{0};
    std::uint64_t bytes{0};
  };

  NvsCredStore() = default;
  ~NvsCredStore() override;

  NvsCredStore(const NvsCredStore&) = delete;
  NvsCredStore& operator=(const NvsCredStore&) = delete;

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
