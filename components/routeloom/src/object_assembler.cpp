#include "routeloom/object_assembler.hpp"

#include <cstring>

#include "routeloom/discovery_scope.hpp"
#include "routeloom/secure_clear.hpp"

namespace routeloom {

Status ObjectAssembler::begin(MutableByteView storage, MutableByteView bitmap,
                              std::uint16_t total, std::uint16_t cell,
                              MonotonicMs deadline_ms) noexcept {
  if (active()) return Status::error(StatusCode::Busy, "assembly active");
  if (total == 0 || cell == 0 || storage.data == nullptr || bitmap.data == nullptr ||
      storage.size < total || bitmap.size < ((total + cell - 1U) / cell + 7U) / 8U) {
    return Status::error(StatusCode::InvalidArgument, "assembly bounds");
  }
  storage_ = storage;
  bitmap_ = bitmap;
  total_ = total;
  cell_ = cell;
  received_ = 0;
  deadline_ms_ = deadline_ms;
  std::memset(bitmap_.data, 0, bitmap_.size);
  return Status::success();
}

Status ObjectAssembler::insert(std::uint16_t offset, ByteView data,
                               MonotonicMs now_ms) noexcept {
  if (!active()) return Status::error(StatusCode::InvalidState, "assembly inactive");
  if (expired(now_ms)) return Status::error(StatusCode::Expired, "assembly expired");
  if (data.data == nullptr || data.size == 0 || offset >= total_ ||
      data.size > static_cast<std::size_t>(total_ - offset) ||
      (cell_ != 1 && (offset % cell_ != 0 ||
       data.size != static_cast<std::size_t>(total_ - offset < cell_ ? total_ - offset : cell_)))) {
    return Status::error(StatusCode::InvalidArgument, "assembly grid");
  }
  // Validate every overlap before mutating: a conflict leaves progress intact.
  for (std::size_t i = 0; i < data.size; ++i) {
    const std::size_t at = offset + i;
    const std::size_t bit = at / cell_;
    if ((bitmap_.data[bit / 8] & (1U << (bit % 8))) != 0 &&
        storage_.data[at] != data.data[i]) {
      return Status::error(StatusCode::Conflict, "assembly conflict");
    }
  }
  if (cell_ != 1) {
    const std::size_t bit = offset / cell_;
    if ((bitmap_.data[bit / 8] & (1U << (bit % 8))) == 0) {
      std::memcpy(storage_.data + offset, data.data, data.size);
      bitmap_.data[bit / 8] |= static_cast<std::uint8_t>(1U << (bit % 8));
      received_ = static_cast<std::uint16_t>(received_ + data.size);
    }
  } else {
    for (std::size_t i = 0; i < data.size; ++i) {
      const std::size_t at = offset + i;
      const std::uint8_t mask = static_cast<std::uint8_t>(1U << (at % 8));
      if ((bitmap_.data[at / 8] & mask) == 0) {
        storage_.data[at] = data.data[i];
        bitmap_.data[at / 8] |= mask;
        ++received_;
      }
    }
  }
  return Status::success();
}

Status ObjectAssembler::verify(ByteView digest) const noexcept {
  if (!complete()) return Status::error(StatusCode::InvalidState, "assembly incomplete");
  if (digest.data == nullptr || (digest.size != 16 && digest.size != 32)) {
    return Status::error(StatusCode::InvalidArgument, "assembly digest length");
  }
  ScopeDigest actual{};
  sha256(data(), actual);
  std::uint8_t diff = 0;
  for (std::size_t i = 0; i < digest.size; ++i) diff |= actual[i] ^ digest.data[i];
  secure_clear(actual);
  return diff == 0 ? Status::success() : Status::error(StatusCode::IntegrityError,
                                                     "assembly digest mismatch");
}

void ObjectAssembler::reset() noexcept {
  if (storage_.data != nullptr && total_ != 0) std::memset(storage_.data, 0, total_);
  if (bitmap_.data != nullptr) std::memset(bitmap_.data, 0, bitmap_.size);
  storage_ = {};
  bitmap_ = {};
  total_ = cell_ = received_ = 0;
  deadline_ms_ = 0;
}

}  // namespace routeloom
