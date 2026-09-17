#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

class ByteWriter {
 public:
  explicit ByteWriter(MutableByteView target) : target_(target) {}

  Status write_u8(std::uint8_t value) noexcept;
  Status write_u16(std::uint16_t value) noexcept;
  Status write_u32(std::uint32_t value) noexcept;
  Status write_u64(std::uint64_t value) noexcept;
  Status write_bytes(ByteView value) noexcept;

  std::size_t size() const noexcept { return offset_; }

 private:
  Status reserve(std::size_t count) const noexcept;
  MutableByteView target_{};
  std::size_t offset_{0};
};

class ByteReader {
 public:
  explicit ByteReader(ByteView source) : source_(source) {}

  Status read_u8(std::uint8_t& value) noexcept;
  Status read_u16(std::uint16_t& value) noexcept;
  Status read_u32(std::uint32_t& value) noexcept;
  Status read_u64(std::uint64_t& value) noexcept;
  Status read_bytes(MutableByteView target) noexcept;

  std::size_t remaining() const noexcept { return source_.size - offset_; }
  std::size_t consumed() const noexcept { return offset_; }

 private:
  Status require(std::size_t count) const noexcept;
  ByteView source_{};
  std::size_t offset_{0};
};

}  // namespace routeloom
