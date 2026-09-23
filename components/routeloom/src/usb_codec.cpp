#include "routeloom/usb_codec.hpp"

#include <cstring>

#include "routeloom/byte_io.hpp"
#include "routeloom/crc32.hpp"

namespace routeloom::usb {

Status cobs_encode(const ByteView input, const MutableByteView out,
                   std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "null cobs output");
  }
  if (input.size > 0 && input.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "null cobs input");
  }
  // Worst case is input.size + input.size/254 + 1 code bytes.
  if (out.size < input.size + input.size / 254 + 1) {
    return Status::error(StatusCode::NoCapacity, "cobs output too small");
  }
  std::size_t code_index = 0;
  std::size_t length = 1;  // reserve slot for the first code byte
  std::uint8_t code = 1;
  for (std::size_t i = 0; i < input.size; ++i) {
    const std::uint8_t byte = input.data[i];
    if (byte == 0) {
      out.data[code_index] = code;
      code_index = length++;
      code = 1;
    } else {
      out.data[length++] = byte;
      ++code;
      if (code == 0xFF) {
        out.data[code_index] = code;
        code_index = length++;
        code = 1;
      }
    }
  }
  out.data[code_index] = code;
  written = length;
  return Status::success();
}

Status cobs_decode(const ByteView input, const MutableByteView out,
                   std::size_t& written) noexcept {
  written = 0;
  if (out.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "null cobs output");
  }
  if (input.size > 0 && input.data == nullptr) {
    return Status::error(StatusCode::InvalidArgument, "null cobs input");
  }
  // Encoded COBS data never contains a 0x00 byte anywhere (the delimiter is
  // stripped by the caller), so a zero inside the segment is malformed input.
  if (input.size > 0 &&
      std::memchr(input.data, 0, input.size) != nullptr) {
    return Status::error(StatusCode::ProtocolError, "INVALID_COBS");
  }
  std::size_t index = 0;
  while (index < input.size) {
    const std::uint8_t code = input.data[index];
    if (code == 0) {
      return Status::error(StatusCode::ProtocolError, "INVALID_COBS");
    }
    ++index;
    const std::size_t next = index + static_cast<std::size_t>(code) - 1;
    if (next > input.size) {
      return Status::error(StatusCode::ProtocolError, "INVALID_COBS");
    }
    const std::size_t chunk = next - index;
    // The implicit zero is only emitted when this block is non-final, so it
    // must only be charged against the output when it will actually be
    // written — otherwise an exactly-full decode is falsely rejected.
    const bool implicit_zero = (code != 0xFF && next < input.size);
    if (written + chunk + (implicit_zero ? 1U : 0U) > out.size) {
      return Status::error(StatusCode::NoCapacity, "cobs decode overflow");
    }
    // memmove: an in-place decode (out aliases input) copies each chunk to
    // an offset at or before its source.
    if (chunk > 0) std::memmove(out.data + written, input.data + index, chunk);
    written += chunk;
    index = next;
    if (implicit_zero) {
      out.data[written++] = 0;
    }
  }
  return Status::success();
}

Status encode_frame(const FrameKind kind, const std::uint16_t flags,
                    const std::uint64_t session, const std::uint64_t request,
                    const ByteView body, const MutableByteView scratch,
                    const MutableByteView out,
                    std::size_t& written) noexcept {
  written = 0;
  if (body.size > kMaxBodySize || body.size > 0xFFFFU) {
    return Status::error(StatusCode::InvalidArgument, "FRAME_TOO_LARGE");
  }
  // The caller owns the decoded-staging buffer so this frame path carries
  // no multi-KB stack buffer on the (bounded) calling task.
  const std::size_t decoded_need = kHeaderSize + body.size + kCrcSize;
  if (out.data == nullptr || out.size < encoded_frame_bound(decoded_need)) {
    return Status::error(StatusCode::NoCapacity, "frame output too small");
  }
  if (scratch.data == nullptr || scratch.size < decoded_need) {
    return Status::error(StatusCode::NoCapacity, "frame scratch too small");
  }
  ByteWriter writer(MutableByteView{scratch.data, decoded_need});
  Status status = writer.write_u32(kMagic);
  if (status) status = writer.write_u8(kProtocolVersion);
  if (status) status = writer.write_u8(static_cast<std::uint8_t>(kind));
  if (status) status = writer.write_u16(flags);
  if (status) status = writer.write_u64(session);
  if (status) status = writer.write_u64(request);
  if (status) status = writer.write_u16(static_cast<std::uint16_t>(body.size));
  if (status) status = writer.write_bytes(body);
  if (!status) return status;
  const std::uint32_t crc = crc32_iso_hdlc(ByteView{scratch.data, writer.size()});
  status = writer.write_u32(crc);
  if (!status) return status;
  std::size_t encoded = 0;
  status = cobs_encode(ByteView{scratch.data, writer.size()}, out, encoded);
  if (!status) return status;
  out.data[encoded++] = 0;  // delimiter
  written = encoded;
  return Status::success();
}

Status decode_frame(const ByteView decoded, UsbFrame& out) noexcept {
  if (decoded.size < kHeaderSize + kCrcSize) {
    return Status::error(StatusCode::ProtocolError, "FRAME_TOO_SHORT");
  }
  if (decoded.size > kMaxDecodedFrame) {
    return Status::error(StatusCode::ProtocolError, "FRAME_TOO_LARGE");
  }
  ByteReader reader(decoded);
  std::uint32_t magic = 0;
  Status status = reader.read_u32(magic);
  if (!status || magic != kMagic) {
    return Status::error(StatusCode::ProtocolError, "INVALID_MAGIC");
  }
  std::uint8_t version = 0;
  (void)reader.read_u8(version);
  if (version != kProtocolVersion) {
    return Status::error(StatusCode::Unsupported, "UNSUPPORTED_VERSION");
  }
  std::uint8_t kind = 0;
  (void)reader.read_u8(kind);
  switch (static_cast<FrameKind>(kind)) {
    case FrameKind::Hello:
    case FrameKind::HelloAck:
    case FrameKind::DataToMesh:
    case FrameKind::DataFromMesh:
    case FrameKind::DeliveryEvent:
    case FrameKind::HostOps:
    case FrameKind::Credit:
    case FrameKind::Diagnostic:
    case FrameKind::Error:
    case FrameKind::KeepAlive:
      break;
    default:
      return Status::error(StatusCode::ProtocolError, "UNKNOWN_KIND");
  }
  std::uint16_t flags = 0;
  std::uint64_t session = 0;
  std::uint64_t request = 0;
  std::uint16_t body_len = 0;
  (void)reader.read_u16(flags);
  (void)reader.read_u64(session);
  (void)reader.read_u64(request);
  (void)reader.read_u16(body_len);
  if (decoded.size != kHeaderSize + body_len + kCrcSize) {
    return Status::error(StatusCode::ProtocolError, "INVALID_LENGTH");
  }
  const std::uint32_t expected =
      crc32_iso_hdlc(ByteView{decoded.data, decoded.size - kCrcSize});
  std::uint32_t actual = 0;
  const std::size_t crc_offset = decoded.size - kCrcSize;
  for (std::size_t i = 0; i < kCrcSize; ++i) {
    actual = (actual << 8U) | decoded.data[crc_offset + i];
  }
  if (expected != actual) {
    return Status::error(StatusCode::IntegrityError, "CRC_MISMATCH");
  }
  out.kind = static_cast<FrameKind>(kind);
  out.flags = flags;
  out.session = session;
  out.request = request;
  out.body = ByteView{decoded.data + kHeaderSize, body_len};
  return Status::success();
}

void StreamDecoder::push(const ByteView input, const MonotonicMs now_ms) noexcept {
  if (input.size > 0 && input.data == nullptr) {
    sink_.on_stream_error(
        Status::error(StatusCode::InvalidArgument, "null stream input"));
    return;
  }
  for (std::size_t i = 0; i < input.size; ++i) {
    const std::uint8_t byte = input.data[i];
    last_byte_ms_ = now_ms;
    if (byte == 0) {
      if (discarding_) {
        discarding_ = false;  // bounded discard ends at the delimiter; resync
      } else if (pending_size_ > 0) {
        finish_segment();
      }
      continue;
    }
    if (discarding_) continue;
    if (pending_size_ >= pending_.size()) {
      pending_size_ = 0;
      discarding_ = true;
      sink_.on_stream_error(
          Status::error(StatusCode::ProtocolError, "FRAME_TOO_LARGE"));
      continue;
    }
    pending_[pending_size_++] = byte;
  }
}

void StreamDecoder::finish_segment() noexcept {
  // Decoded in place: the segment is consumed here, so the decoded frame
  // (at most kMaxDecodedFrame bytes, as before) overwrites its own encoding
  // instead of needing a second multi-KB buffer (ram-budget.md).
  std::size_t decoded_size = 0;
  Status status = cobs_decode(
      ByteView{pending_.data(), pending_size_},
      MutableByteView{pending_.data(), kMaxDecodedFrame}, decoded_size);
  pending_size_ = 0;
  if (!status) {
    sink_.on_stream_error(status);
    return;
  }
  UsbFrame frame{};
  status = decode_frame(ByteView{pending_.data(), decoded_size}, frame);
  if (!status) {
    sink_.on_stream_error(status);
    return;
  }
  sink_.on_frame(frame);
}

void StreamDecoder::poll(const MonotonicMs now_ms) noexcept {
  if (pending_size_ == 0 && !discarding_) return;
  if (now_ms - last_byte_ms_ >= kPartialFrameTimeoutMs) {
    const bool had_partial = pending_size_ > 0;
    pending_size_ = 0;
    discarding_ = false;
    if (had_partial) {
      sink_.on_stream_error(
          Status::error(StatusCode::ProtocolError, "PARTIAL_FRAME_TIMEOUT"));
    }
  }
}

void StreamDecoder::reset() noexcept {
  pending_size_ = 0;
  discarding_ = false;
}

}  // namespace routeloom::usb
