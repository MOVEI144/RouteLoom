#pragma once

#include <cstddef>
#include <cstdint>

#include "nvs.h"
#include "routeloom/security_floor.hpp"

namespace routeloom::espnow {

// SecurityFloorStorage over one NVS blob (key "state"). One instance backs
// the device's whole RLF1 floor record: the caller opens a dedicated NVS
// namespace (e.g. "rlfloor") in the kSecurityNvsPartition partition.
//
// Floor contract (04-remote-config.md §4.7):
//   - a missing blob is NOT an empty floor — read() reports NotFound so the
//     portable store stops privileged intake until managed re-provisioning
//     installs a floor (a floor must never be inferred from the stores it
//     is supposed to bound);
//   - a blob of the wrong size, or a read fault, is StorageFailure — never
//     a silent reset;
//   - write() is blob set + commit; it reports unless the bytes landed.
class NvsSecurityFloorStore final : public SecurityFloorStorage {
 public:
  NvsSecurityFloorStore() = default;
  ~NvsSecurityFloorStore() override;

  NvsSecurityFloorStore(const NvsSecurityFloorStore&) = delete;
  NvsSecurityFloorStore& operator=(const NvsSecurityFloorStore&) = delete;

  // `partition == nullptr` opens the default NVS partition; pass
  // kSecurityNvsPartition for the security partition.
  Status open(const char* name_space, const char* partition) noexcept;
  void close() noexcept;

  Status read(MutableByteView target) noexcept override;
  Status write(ByteView data) noexcept override;

 private:
  nvs_handle_t handle_{0};
  bool open_{false};
};

}  // namespace routeloom::espnow
