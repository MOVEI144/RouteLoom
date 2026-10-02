#include "routeloom/app_object_wire.hpp"
#include "routeloom/byte_io.hpp"

namespace routeloom::object_wire {
namespace {
Status invalid() noexcept { return Status::error(StatusCode::ProtocolError, "object wire bounds"); }
bool valid(const Start& v) noexcept {
  return v.id != 0 && v.total > 0 && v.total <= kMaxBytes &&
         v.chunks == (v.total + kChunkBytes - 1) / kChunkBytes &&
         v.lifetime_ms > 0 && v.lifetime_ms <= 120000;
}
bool valid(const Chunk& v) noexcept {
  return v.id != 0 && v.index < kMaxChunks && v.data.data != nullptr &&
         v.data.size > 0 && v.data.size <= kChunkBytes;
}
bool valid(const Ack& v) noexcept {
  return v.id != 0 && static_cast<unsigned>(v.status) <= static_cast<unsigned>(AckStatus::Failed) &&
         v.missing <= kMaxChunks && (v.bitmap >> kMaxChunks) == 0;
}
}
Status encode(const Start& v, MutableByteView out, std::size_t& size) noexcept {
  size = 0;
  if (!valid(v) || out.data == nullptr || out.size < kStartBytes) return invalid();
  ByteWriter w(out);
  (void)w.write_u8(kVersion); (void)w.write_u32(v.id); (void)w.write_u16(v.total);
  (void)w.write_u8(v.chunks); (void)w.write_u16(v.app_tag); (void)w.write_u8(v.encoding);
  (void)w.write_bytes({v.digest.data(), v.digest.size()}); (void)w.write_u32(v.lifetime_ms);
  size = w.size(); return Status::success();
}
Status encode(const Chunk& v, MutableByteView out, std::size_t& size) noexcept {
  size = 0;
  if (!valid(v) || out.data == nullptr || out.size < kChunkHeadBytes + v.data.size) return invalid();
  ByteWriter w(out);
  (void)w.write_u8(kVersion); (void)w.write_u32(v.id); (void)w.write_u8(v.index);
  (void)w.write_u8(static_cast<std::uint8_t>(v.data.size)); (void)w.write_bytes(v.data);
  size = w.size(); return Status::success();
}
Status encode(const Ack& v, MutableByteView out, std::size_t& size) noexcept {
  size = 0;
  if (!valid(v) || out.data == nullptr || out.size < kAckBytes) return invalid();
  ByteWriter w(out);
  (void)w.write_u8(kVersion); (void)w.write_u32(v.id);
  (void)w.write_u8(static_cast<std::uint8_t>(v.status)); (void)w.write_u8(v.missing);
  (void)w.write_u64(v.bitmap); size = w.size(); return Status::success();
}
Status decode(ByteView in, Start& v) noexcept {
  if (in.data == nullptr || in.size != kStartBytes) return invalid();
  ByteReader r(in); std::uint8_t version = 0; Start result{};
  (void)r.read_u8(version); (void)r.read_u32(result.id); (void)r.read_u16(result.total);
  (void)r.read_u8(result.chunks); (void)r.read_u16(result.app_tag); (void)r.read_u8(result.encoding);
  (void)r.read_bytes({result.digest.data(), result.digest.size()}); (void)r.read_u32(result.lifetime_ms);
  if (version != kVersion || !valid(result)) return invalid();
  v = result; return Status::success();
}
Status decode(ByteView in, Chunk& v) noexcept {
  if (in.data == nullptr || in.size <= kChunkHeadBytes || in.size > kChunkHeadBytes + kChunkBytes) return invalid();
  ByteReader r(in); std::uint8_t version = 0, length = 0; Chunk result{};
  (void)r.read_u8(version); (void)r.read_u32(result.id); (void)r.read_u8(result.index);
  (void)r.read_u8(length); result.data = {in.data + kChunkHeadBytes, in.size - kChunkHeadBytes};
  if (version != kVersion || length != result.data.size || !valid(result)) return invalid();
  v = result; return Status::success();
}
Status decode(ByteView in, Ack& v) noexcept {
  if (in.data == nullptr || in.size != kAckBytes) return invalid();
  ByteReader r(in); std::uint8_t version = 0, status = 0; Ack result{};
  (void)r.read_u8(version); (void)r.read_u32(result.id); (void)r.read_u8(status);
  result.status = static_cast<AckStatus>(status); (void)r.read_u8(result.missing);
  (void)r.read_u64(result.bitmap);
  if (version != kVersion || !valid(result)) return invalid();
  v = result; return Status::success();
}
}  // namespace routeloom::object_wire
