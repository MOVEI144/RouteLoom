#pragma once

// Storage ports of the SDK v1 stores (sdkv1_store.hpp) over a key/blob
// namespace — the portable half of the `rlsec` NVS adapter
// (docs/design/sdk-v1/05 §5, 08 P1-3 follow-up / P7-1). The ESP-IDF
// adapter (routeloom_espnow nvs_sdkv1_store) implements BlobNamespace with
// nvs_open_from_partition("rlsec", …); host tests implement it with a fake
// NVS. Keeping the slot/blob mapping here means the read-back contract is
// exercised by host tests instead of only compiled for the device.
//
// NVS layout (partition `rlsec`, 05 §5.1):
//   rlident  i0 / i1        RLI1 twin pair        (blob ≤ 664 B, slot 1024 B)
//   rlsite   s0 / s1        RLS1 A/B pair         (blob ≤ 712 B, slot 1024 B)
//   rlrevo   r0 / r1        RRS1 storage record   (blob ≤ 640 B, slot 640 B)
//   rlres    s00…s15        RLP1 slots, node      (blob = 84 B)
//            s000…s159      RLP1 slots, gateway   (3 digits once count > 100)
//
// Read-back contract (identical to NvsTrustStore / NvsCredStore):
//   - a MISSING key reads as a uniformly erased (0xFF) slot image — the
//     store's "never written" (Empty);
//   - a blob that EXISTS but reads back uniformly erased/zeroed (including a
//     zero-length blob) is a torn/anomalous write, reported with a fixed
//     non-erased pattern so the store quarantines instead of adopting an
//     "absent" sibling;
//   - a blob larger than the slot, or whose read length disagrees with its
//     reported size, is reported with the same non-erased pattern;
//   - the record lands as a blob of exactly data.size bytes; the unread tail
//     of the slot view reads 0xFF, matching what the store wrote;
//   - backend errors surface as StorageFailure; nothing here erases, resets
//     or reformats (recovery is the stores' explicit recover()).
// RLP1 slots have no seal: any size other than 84 B reads as the non-erased
// pattern, which fails the CRC and is treated as an empty slot (the only
// consequence of a torn resume slot is one full EDHOC, 05 §3.2).
//
// Heap-free, no statics; one BlobRecordSlotStorage/BlobResumeSlotStorage
// is two pointers and a size, so wiring the four stores costs no RAM beyond
// the stores' own scratch buffers.

#include <cstddef>
#include <cstdint>

#include "routeloom/sdkv1_store.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::sdkv1 {

// Namespaces of the `rlsec` partition (05 §5.1). NVS limits namespace and
// key names to 15 characters.
inline constexpr char kIdentityNamespace[] = "rlident";
inline constexpr char kSiteNamespace[] = "rlsite";
inline constexpr char kRevocationNamespace[] = "rlrevo";
inline constexpr char kResumeNamespace[] = "rlres";

inline constexpr char kIdentityKey0[] = "i0";
inline constexpr char kIdentityKey1[] = "i1";
inline constexpr char kSiteKey0[] = "s0";
inline constexpr char kSiteKey1[] = "s1";
inline constexpr char kRevocationKey0[] = "r0";
inline constexpr char kRevocationKey1[] = "r1";

// Resume-cache slot counts (05 §3.2 / §5.1): a node keeps 16 slots, a
// gateway 160. Key names are fixed per slot so NVS usage never grows with
// the number of peers.
constexpr std::size_t kResumeNodeSlots = 16;
constexpr std::size_t kResumeGatewaySlots = 160;
constexpr std::size_t kResumeSlotsMax = 999;
constexpr std::size_t kResumeKeyBytes = 5;  // "s" + up to 3 digits + NUL

// Fill pattern for a present-but-unusable blob (same value the NVS
// trust/credential adapters use).
constexpr std::uint8_t kBlobCorruptFill = 0xA5U;

// One key/blob namespace. Every call is synchronous; write() returns only
// after the value is durable (nvs_set_blob + nvs_commit).
class BlobNamespace {
 public:
  virtual ~BlobNamespace() = default;
  // Stored length of `key`; found=false (and success) when the key is
  // missing. Any other failure is StorageFailure.
  virtual Status blob_size(const char* key, std::size_t& size, bool& found) noexcept = 0;
  // Read the whole blob into target (target.size is its reported size);
  // read_len receives the length actually read.
  virtual Status blob_read(const char* key, MutableByteView target,
                           std::size_t& read_len) noexcept = 0;
  virtual Status blob_write(const char* key, ByteView data) noexcept = 0;
};

// The read-back contract above for one key into a slot view of
// target.size bytes (the blob must fit the view).
Status read_blob_slot(BlobNamespace& blobs, const char* key, MutableByteView target) noexcept;

// RecordSlotStorage (IdentityStore / SiteStore / RevocationStore) over the
// two keys of one namespace. `slot_bytes` is the store's slot view size
// (kIdentitySlotBytes / kSiteSlotBytes / kRevocationSlotBytes); reads
// with any other view size and writes larger than it are refused.
class BlobRecordSlotStorage final : public RecordSlotStorage {
 public:
  BlobRecordSlotStorage(BlobNamespace& blobs, const char* key0, const char* key1,
                        std::size_t slot_bytes) noexcept
      : blobs_(blobs), keys_{key0, key1}, slot_bytes_(slot_bytes) {}

  Status read(std::uint8_t slot, MutableByteView target) noexcept override;
  Status write(std::uint8_t slot, ByteView data) noexcept override;

  // The fixed layouts above.
  static BlobRecordSlotStorage identity(BlobNamespace& blobs) noexcept;
  static BlobRecordSlotStorage site(BlobNamespace& blobs) noexcept;
  static BlobRecordSlotStorage revocation(BlobNamespace& blobs) noexcept;

 private:
  BlobNamespace& blobs_;
  const char* keys_[2];
  std::size_t slot_bytes_;
};

// ResumeSlotStorage (ResumeCache) over "s%02u" (count ≤ 100) or "s%03u"
// keys. A slot count of 0 or above kResumeSlotsMax makes every call fail
// with InvalidArgument (slot_count() then reports 0).
class BlobResumeSlotStorage final : public ResumeSlotStorage {
 public:
  BlobResumeSlotStorage(BlobNamespace& blobs, std::size_t slot_count) noexcept
      : blobs_(blobs),
        slot_count_(slot_count > 0 && slot_count <= kResumeSlotsMax ? slot_count : 0) {}

  std::size_t slot_count() const noexcept override { return slot_count_; }
  Status read(std::size_t index, MutableByteView target) noexcept override;
  Status write(std::size_t index, ByteView data) noexcept override;

  // Key of slot `index` for a cache of `slot_count` slots.
  static Status slot_key(std::size_t index, std::size_t slot_count,
                         char (&key)[kResumeKeyBytes]) noexcept;

 private:
  BlobNamespace& blobs_;
  std::size_t slot_count_;
};

}  // namespace routeloom::sdkv1
