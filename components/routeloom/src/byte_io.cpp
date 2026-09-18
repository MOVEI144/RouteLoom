#include "routeloom/byte_io.hpp"

namespace routeloom {

Status ByteWriter::reserve(const std::size_t count) const noexcept {
  if (target_.data == nullptr || offset_ > target_.size || count > target_.size - offset_) {
    return Status::error(StatusCode::NoCapacity, "byte writer overflow");
  }
  return Status::success();
}

Status ByteWriter::write_u8(const std::uint8_t value) noexcept {
  const auto status = reserve(1);
  if (!status) return status;
  target_.data[offset_++] = value;
  return Status::success();
}

Status ByteWriter::write_u16(const std::uint16_t value) noexcept {
  const auto status = reserve(2);
  if (!status) return status;
  target_.data[offset_++] = static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  target_.data[offset_++] = static_cast<std::uint8_t>(value & 0xFFU);
  return Status::success();
}

Status ByteWriter::write_u32(const std::uint32_t value) noexcept {
  const auto status = reserve(4);
  if (!status) return status;
  for (int shift = 24; shift >= 0; shift -= 8) {
    target_.data[offset_++] = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
  }
  return Status::success();
}

Status ByteWriter::write_u64(const std::uint64_t value) noexcept {
  const auto status = reserve(8);
  if (!status) return status;
  for (int shift = 56; shift >= 0; shift -= 8) {
    target_.data[offset_++] = static_cast<std::uint8_t>((value >> shift) & 0xFFU);
  }
  return Status::success();
}

Status ByteWriter::write_bytes(const ByteView value) noexcept {
  if (value.size > 0 && value.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "null byte source");
  }
  const auto status = reserve(value.size);
  if (!status) return status;
  if (value.size > 0) std::memcpy(target_.data + offset_, value.data, value.size);
  offset_ += value.size;
  return Status::success();
}

Status ByteReader::require(const std::size_t count) const noexcept {
  if (source_.data == nullptr || offset_ > source_.size || count > source_.size - offset_) {
    return Status::error(StatusCode::ProtocolError, "truncated input");
  }
  return Status::success();
}

Status ByteReader::read_u8(std::uint8_t& value) noexcept {
  const auto status = require(1);
  if (!status) return status;
  value = source_.data[offset_++];
  return Status::success();
}

Status ByteReader::read_u16(std::uint16_t& value) noexcept {
  const auto status = require(2);
  if (!status) return status;
  value = static_cast<std::uint16_t>((static_cast<std::uint16_t>(source_.data[offset_]) << 8U) |
                                     source_.data[offset_ + 1]);
  offset_ += 2;
  return Status::success();
}

Status ByteReader::read_u32(std::uint32_t& value) noexcept {
  const auto status = require(4);
  if (!status) return status;
  value = 0;
  for (int i = 0; i < 4; ++i) value = (value << 8U) | source_.data[offset_++];
  return Status::success();
}

Status ByteReader::read_u64(std::uint64_t& value) noexcept {
  const auto status = require(8);
  if (!status) return status;
  value = 0;
  for (int i = 0; i < 8; ++i) value = (value << 8U) | source_.data[offset_++];
  return Status::success();
}

Status ByteReader::read_bytes(const MutableByteView target) noexcept {
  if (target.size > 0 && target.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "null byte destination");
  }
  const auto status = require(target.size);
  if (!status) return status;
  if (target.size > 0) std::memcpy(target.data, source_.data + offset_, target.size);
  offset_ += target.size;
  return Status::success();
}

}  // namespace routeloom
