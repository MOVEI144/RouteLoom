#pragma once

#include <cstdint>

#include "nvs.h"
#include "routeloom/authority.hpp"

namespace routeloom::espnow {

// Two-slot LedgerStorage over NVS blobs (keys "lg0"/"lg1"). A missing blob
// reads back as erased bytes; a blob whose size differs from the record size
// reads back as a fixed non-erased pattern so the ledger treats the slot as
// unusable instead of trusting a truncated record. No path erases or
// reformats flash: nvs_flash_erase is never called and a failed write is
// reported, never repaired silently.
class NvsLedgerStore final : public LedgerStorage {
 public:
  NvsLedgerStore() = default;
  ~NvsLedgerStore() override;

  NvsLedgerStore(const NvsLedgerStore&) = delete;
  NvsLedgerStore& operator=(const NvsLedgerStore&) = delete;

  Status open(const char* name_space) noexcept;
  void close() noexcept;

  Status read(std::uint8_t slot, MutableByteView target) noexcept override;
  Status write(std::uint8_t slot, ByteView data) noexcept override;

 private:
  nvs_handle_t handle_{0};
  bool open_{false};
};

}  // namespace routeloom::espnow
