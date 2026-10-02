#pragma once

#include <array>
#include "routeloom/types.hpp"
#include "routeloom/status.hpp"

namespace routeloom::object_wire {
constexpr std::size_t kMaxBytes = 4096;
constexpr std::size_t kChunkBytes = 121;
constexpr std::size_t kMaxChunks = (kMaxBytes + kChunkBytes - 1) / kChunkBytes;
constexpr std::uint8_t kVersion = 1;
// START carries the absolute transfer's remaining lifetime separately from
// each routed frame's <=4 s TTL. Retries never extend receiver admission.
constexpr std::size_t kStartBytes = 31;
constexpr std::size_t kChunkHeadBytes = 7;
constexpr std::size_t kAckBytes = 15;
using ObjectId = std::uint32_t;
using Digest = std::array<std::uint8_t, 16>;
enum class AckStatus : std::uint8_t {
  Incomplete = 0, Complete = 1, Busy = 2, NoBuffer = 3, Conflict = 4,
  Expired = 5, Cancelled = 6, Unsupported = 7, Failed = 8
};
struct Start {
  ObjectId id{0};
  std::uint16_t total{0};
  std::uint8_t chunks{0};
  std::uint16_t app_tag{0};
  std::uint8_t encoding{0};
  Digest digest{};
  std::uint32_t lifetime_ms{30000};
};
struct Chunk {
  ObjectId id{0};
  std::uint8_t index{0};
  ByteView data{};
};
struct Ack {
  ObjectId id{0};
  AckStatus status{AckStatus::Incomplete};
  std::uint8_t missing{0};
  std::uint64_t bitmap{0};
};
Status encode(const Start& value, MutableByteView out, std::size_t& size) noexcept;
Status encode(const Chunk& value, MutableByteView out, std::size_t& size) noexcept;
Status encode(const Ack& value, MutableByteView out, std::size_t& size) noexcept;
Status decode(ByteView in, Start& value) noexcept;
Status decode(ByteView in, Chunk& value) noexcept;
Status decode(ByteView in, Ack& value) noexcept;
}  // namespace routeloom::object_wire
