#include "routeloom/sdkv1_blob_storage.hpp"

#include <cstring>

namespace routeloom::sdkv1 {
namespace {

constexpr std::uint8_t kErasedFill = 0xFFU;

bool uniform(const std::uint8_t* data, const std::size_t size, const std::uint8_t value) noexcept {
  for (std::size_t i = 0; i < size; ++i) {
    if (data[i] != value) return false;
  }
  return true;
}

}  // namespace

Status read_blob_slot(BlobNamespace& blobs, const char* key, const MutableByteView target) noexcept {
  if (key == nullptr || target.data == nullptr || target.size == 0) {
    return Status::error(StatusCode::InvalidArgument, "blob slot read arguments");
  }
  std::size_t actual = 0;
  bool found = false;
  Status status = blobs.blob_size(key, actual, found);
  if (!status) return status;
  if (!found) {
    // Never written: the uniformly erased image the stores classify Empty.
    std::memset(target.data, kErasedFill, target.size);
    return Status::success();
  }
  if (actual > target.size) {
    // Cannot fit the slot: unusable, not erased.
    std::memset(target.data, kBlobCorruptFill, target.size);
    return Status::success();
  }
  std::size_t read_len = actual;
  if (actual > 0) {
    status = blobs.blob_read(key, MutableByteView{target.data, actual}, read_len);
    if (!status) return status;
  }
  if (read_len != actual) {
    std::memset(target.data, kBlobCorruptFill, target.size);
    return Status::success();
  }
  // The store wrote only used_len bytes; the rest of the view is the
  // erased flash it never touched.
  if (actual < target.size) {
    std::memset(target.data + actual, kErasedFill, target.size - actual);
  }
  // A present blob that reads uniformly erased or zeroed (or is empty) is
  // evidence of a torn/anomalous write, never proof of absence: only a
  // missing key may classify Empty.
  const std::uint8_t first = target.data[0];
  if ((first == kErasedFill || first == 0x00U) && uniform(target.data, target.size, first)) {
    std::memset(target.data, kBlobCorruptFill, target.size);
  }
  return Status::success();
}

// --- BlobRecordSlotStorage -------------------------------------------------------

Status BlobRecordSlotStorage::read(const std::uint8_t slot, const MutableByteView target) noexcept {
  if (slot >= SealedSlotPair::kSlots || target.data == nullptr || target.size != slot_bytes_) {
    return Status::error(StatusCode::InvalidArgument, "record slot read arguments");
  }
  return read_blob_slot(blobs_, keys_[slot], target);
}

Status BlobRecordSlotStorage::write(const std::uint8_t slot, const ByteView data) noexcept {
  if (slot >= SealedSlotPair::kSlots || data.data == nullptr || data.size == 0 ||
      data.size > slot_bytes_) {
    return Status::error(StatusCode::InvalidArgument, "record slot write arguments");
  }
  return blobs_.blob_write(keys_[slot], data);
}

Status BlobRecordSlotStorage::erase(const std::uint8_t slot) noexcept {
  if (slot >= SealedSlotPair::kSlots) {
    return Status::error(StatusCode::InvalidArgument, "record slot erase arguments");
  }
  return blobs_.blob_erase(keys_[slot]);
}

BlobRecordSlotStorage BlobRecordSlotStorage::identity(BlobNamespace& blobs) noexcept {
  return BlobRecordSlotStorage(blobs, kIdentityKey0, kIdentityKey1, kIdentitySlotBytes);
}

BlobRecordSlotStorage BlobRecordSlotStorage::site(BlobNamespace& blobs) noexcept {
  return BlobRecordSlotStorage(blobs, kSiteKey0, kSiteKey1, kSiteSlotBytes);
}

BlobRecordSlotStorage BlobRecordSlotStorage::revocation(BlobNamespace& blobs) noexcept {
  return BlobRecordSlotStorage(blobs, kRevocationKey0, kRevocationKey1, kRevocationSlotBytes);
}

BlobRecordSlotStorage BlobRecordSlotStorage::local_revocation(BlobNamespace& blobs) noexcept {
  return BlobRecordSlotStorage(blobs, kLocalRevocationKey0, kLocalRevocationKey1,
                               kLocalRevocationSlotBytes);
}

BlobRecordSlotStorage BlobRecordSlotStorage::lifecycle(BlobNamespace& blobs) noexcept {
  return BlobRecordSlotStorage(blobs, kLifecycleKey0, kLifecycleKey1, kLifecycleSlotBytes);
}

// --- BlobResumeSlotStorage2 ------------------------------------------------------

Status BlobResumeSlotStorage2::slot_key(const std::size_t index, const std::size_t slot_count,
                                       char (&key)[kResumeKeyBytes]) noexcept {
  if (slot_count == 0 || slot_count > kResumeSlotsMax || index >= slot_count) {
    return Status::error(StatusCode::InvalidArgument, "resume slot index");
  }
  // Hand-rolled decimal (no snprintf: keeps the size_t formatting free of
  // 32/64-bit format-width differences).
  const std::size_t digits = slot_count <= 100 ? 2 : 3;
  key[0] = 's';
  std::size_t value = index;
  for (std::size_t i = digits; i > 0; --i) {
    key[i] = static_cast<char>('0' + static_cast<int>(value % 10U));
    value /= 10U;
  }
  key[digits + 1] = '\0';
  return Status::success();
}

Status BlobResumeSlotStorage2::read(const std::size_t index, const MutableByteView target) noexcept {
  if (target.data == nullptr || target.size != kResume2SlotBytes) {
    return Status::error(StatusCode::InvalidArgument, "resume2 slot read arguments");
  }
  char key[kResumeKeyBytes]{};
  const Status status = slot_key(index, slot_count_, key);
  if (!status) return status;
  std::size_t actual = 0;
  bool found = false;
  const Status size_status = blobs_.blob_size(key, actual, found);
  if (!size_status) return size_status;
  if (found && actual != kResume2SlotBytes) {
    std::memset(target.data, kBlobCorruptFill, target.size);
    return Status::success();
  }
  return read_blob_slot(blobs_, key, target);
}

Status BlobResumeSlotStorage2::write(const std::size_t index, const ByteView data) noexcept {
  if (data.data == nullptr || data.size != kResume2SlotBytes) {
    return Status::error(StatusCode::InvalidArgument, "resume2 slot write arguments");
  }
  char key[kResumeKeyBytes]{};
  const Status status = slot_key(index, slot_count_, key);
  if (!status) return status;
  return blobs_.blob_write(key, data);
}

}  // namespace routeloom::sdkv1
