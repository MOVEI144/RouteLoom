#pragma once

// Flash layout PT-4M-v2 (v2 design §8.4) and the image identity. The
// bootloader and partition table cannot change by OTA, so every image checks
// the flashed table before NVS or RF is touched and refuses to start on any
// other layout or on a flash smaller than 4 MB.

#include <cstdint>

#include "routeloom/status.hpp"

namespace routeloom::espnow {

inline constexpr char kPartitionLayoutId[] = "PT-4M-v2";
inline constexpr std::uint32_t kMinFlashBytes = 0x400000;

struct PartitionRow {
  const char* label;
  std::uint32_t offset;
  std::uint32_t size;
};

// Must equal every app's partitions.csv (checked by tools/nvs_budget.py).
inline constexpr PartitionRow kPt4mV2[] = {
    {"nvs", 0x9000, 0x6000},
    {"phy_init", 0xF000, 0x1000},
    {"otadata", 0x10000, 0x2000},
    {"rlcfg", 0x12000, 0x6000},
    {"rlkeys", 0x18000, 0x3000},
    {"rlsec", 0x20000, 0x20000},
    {"ota_0", 0x40000, 0x1D0000},
    {"ota_1", 0x210000, 0x1D0000},
    {"coredump", 0x3E0000, 0x10000},
};

// Embedded in the app image so tools and logs can tell which SDK, layout and
// storage generation it was built for. storage_epoch counts on-flash storage
// generations that need a full erase to cross.
struct ImageInfo {
  char magic[8];
  char sdk_version[16];
  char partition_id[12];
  std::uint32_t storage_epoch;
};
extern const ImageInfo kImageInfo;

// Logs the image identity, then checks the physical flash size and every
// PT-4M-v2 row (label, offset, size). On mismatch it logs the reason and
// returns an error; the caller must stop before starting RF.
Status verify_flash_layout() noexcept;

// Confirms the running image to the rollback bootloader. Call once, after
// the owner and runtime are running. No-op for an image flashed by esptool.
void mark_app_valid() noexcept;

}  // namespace routeloom::espnow
