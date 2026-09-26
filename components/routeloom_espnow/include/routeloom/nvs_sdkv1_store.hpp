#pragma once

#include <cstdint>

#include "nvs.h"
#include "routeloom/sdkv1_blob_storage.hpp"

namespace routeloom::espnow {

// One NVS namespace of the `rlsec` partition as a sdkv1::BlobNamespace —
// the ESP-IDF half of the SDK v1 store adapter (docs/design/sdk-v1/05 §5,
// 08 P7-1). The slot/key mapping and the read-back contract (missing key =
// erased, present-but-erased = corrupt, oversize = corrupt, no implicit
// erase) live in the portable sdkv1_blob_storage and are host-tested
// against a fake NVS; this class only forwards to nvs_get_blob /
// nvs_set_blob + nvs_commit.
//
// Wiring (the partition must already be mounted with
// nvs_flash_init_partition(kSecurityNvsPartition)):
//
//   NvsBlobNamespace ident;
//   ident.open(kSecurityNvsPartition, sdkv1::kIdentityNamespace);
//   auto storage = sdkv1::BlobRecordSlotStorage::identity(ident);
//   sdkv1::IdentityStore store(storage);   // ~1.3 KiB: keep it off the
//   store.initialize();                    // task stack (static or owner)
//
// and likewise kSiteNamespace + ::site, kRevocationNamespace +
// ::revocation, kResume2Namespace + BlobResumeSlotStorage2(ns,
// sdkv1::kResumeNodeSlots or kResumeGatewaySlots). Opening a missing
// namespace READWRITE creates it immediately; nothing here erases a key.
class NvsBlobNamespace final : public sdkv1::BlobNamespace {
 public:
  // Committed-write accounting for the flash-wear budget (05 §6).
  struct WriteStats {
    std::uint64_t commits{0};
    std::uint64_t bytes{0};
  };

  // Most recent native NVS failure: `op` tags the call ("open",
  // "blob_size", "blob_read", "blob_write", "commit") and `native` is the
  // esp_err_t it returned. Sticky — successes and benign absence probes
  // never clear it — so a later read still explains the earlier fault.
  // `op == nullptr` (with ESP_OK) until the first failure.
  struct NvsLastError {
    const char* op{nullptr};
    esp_err_t native{ESP_OK};
  };

  NvsBlobNamespace() = default;
  ~NvsBlobNamespace() override;

  NvsBlobNamespace(const NvsBlobNamespace&) = delete;
  NvsBlobNamespace& operator=(const NvsBlobNamespace&) = delete;

  // `partition` nullptr selects the default "nvs" partition (bench only;
  // the SDK v1 records belong in kSecurityNvsPartition). The labels are
  // snapshotted on entry so even a failed open stays attributable.
  Status open(const char* partition, const char* name_space) noexcept;
  void close() noexcept;
  bool is_open() const noexcept { return open_; }

  Status blob_size(const char* key, std::size_t& size, bool& found) noexcept override;
  Status blob_read(const char* key, MutableByteView target,
                   std::size_t& read_len) noexcept override;
  Status blob_write(const char* key, ByteView data) noexcept override;

  WriteStats write_stats() const noexcept { return stats_; }
  NvsLastError last_error() const noexcept { return last_; }
  // Snapshotted open() labels ("", "" until the first open call).
  const char* partition() const noexcept { return partition_; }
  const char* name_space() const noexcept { return space_; }

 private:
  // Records the failure for last_error() and maps it to StorageFailure,
  // spelling capacity refuses apart from generic faults so the remedy
  // (free space vs investigate) stays visible in the detail alone.
  Status note_error(const char* op, esp_err_t error, const char* failed_detail,
                    const char* nospace_detail) noexcept;

  nvs_handle_t handle_{0};
  bool open_{false};
  WriteStats stats_{};
  NvsLastError last_{};
  // NVS labels are at most 15 chars + NUL each.
  char partition_[16]{};
  char space_[16]{};
};

}  // namespace routeloom::espnow
