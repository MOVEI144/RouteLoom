#pragma once

// USB/serial framing for the RouteLoom device bridge. Byte-identical to
// host/routeloom-protocol (v0.1 implementation profile, not a frozen ABI):
//
//   decoded = MAGIC(4) "RLU1" || version(1) || kind(1) || flags(2 BE)
//             || session(8 BE) || request(8 BE) || body_len(2 BE) || body
//             || crc32(4 BE)
//   wire    = COBS(decoded) || 0x00 delimiter
//
// CRC is CRC-32/ISO-HDLC (routeloom::crc32) over the decoded bytes before the
// CRC field, appended big-endian. CRC is integrity only, never authentication.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::usb {

constexpr std::size_t kHeaderSize = 26;  // magic + version + kind + flags + session + request + body_len
constexpr std::size_t kCrcSize = 4;
constexpr std::size_t kMaxDecodedFrame = 4096;
constexpr std::size_t kMaxBodySize = kMaxDecodedFrame - kHeaderSize - kCrcSize;
// Conservative upper bound: n + floor(n/254) + 2 including the delimiter.
constexpr std::size_t kMaxEncodedFrame = kMaxDecodedFrame + (kMaxDecodedFrame / 254) + 2;
// Encoded bytes buffered between delimiters before a frame is declared
// overlength and the decoder enters bounded discard until the next delimiter.
constexpr std::size_t kMaxPendingEncoded = kMaxDecodedFrame + 64;
constexpr MonotonicMs kPartialFrameTimeoutMs = 1000;

constexpr std::uint32_t kMagic = 0x524C5531U;  // "RLU1"
constexpr std::uint8_t kProtocolVersion = 1;

enum class FrameKind : std::uint8_t {
  Hello = 1,
  HelloAck = 2,
  DataToMesh = 16,
  DataFromMesh = 17,
  DeliveryEvent = 18,
  Credit = 32,
  Diagnostic = 33,
  Error = 34,
  KeepAlive = 35,
};

// CONTROL-reservation kinds (spec section 4): session setup, credit,
// keepalive and error reporting. DataFromMesh/DeliveryEvent/Diagnostic are
// ordinary traffic and require credit.
constexpr bool is_control_kind(const FrameKind kind) noexcept {
  return kind == FrameKind::Hello || kind == FrameKind::HelloAck ||
         kind == FrameKind::Credit || kind == FrameKind::KeepAlive ||
         kind == FrameKind::Error;
}

struct UsbFrame {
  FrameKind kind{FrameKind::KeepAlive};
  std::uint16_t flags{0};
  std::uint64_t session{0};
  std::uint64_t request{0};
  ByteView body{};  // view into caller-owned storage; valid only for the call
};

// COBS encode/decode matching host/routeloom-protocol cobs_encode/cobs_decode
// exactly. Output excludes the 0x00 delimiter.
Status cobs_encode(ByteView input, MutableByteView out, std::size_t& written) noexcept;
Status cobs_decode(ByteView input, MutableByteView out, std::size_t& written) noexcept;

// Encodes one full wire frame (header + body + CRC, COBS, delimiter).
Status encode_frame(FrameKind kind, std::uint16_t flags, std::uint64_t session,
                    std::uint64_t request, ByteView body, MutableByteView out,
                    std::size_t& written) noexcept;

// Validates and splits one decoded (post-COBS) buffer. `out.body` aliases
// `decoded`. Checks magic, version, kind, exact body_len and CRC.
Status decode_frame(ByteView decoded, UsbFrame& out) noexcept;

// Receives fully decoded frames and decode failures. `frame.body` is valid
// only for the duration of on_frame.
class UsbFrameSink {
 public:
  virtual ~UsbFrameSink() = default;
  virtual void on_frame(const UsbFrame& frame) noexcept = 0;
  virtual void on_stream_error(Status status) noexcept = 0;
};

// Push-style byte stream decoder. Buffers encoded bytes between 0 delimiters,
// decodes at each delimiter, bounds the pending buffer, discards overlength
// segments until the next delimiter (resync), and drops partial frames after
// kPartialFrameTimeoutMs without a new byte.
class StreamDecoder {
 public:
  explicit StreamDecoder(UsbFrameSink& sink) noexcept : sink_(sink) {}

  void push(ByteView input, MonotonicMs now_ms) noexcept;
  // Call periodically; drops a partial frame that stalled past the timeout.
  void poll(MonotonicMs now_ms) noexcept;
  void reset() noexcept;

  std::size_t pending() const noexcept { return pending_size_; }
  bool discarding() const noexcept { return discarding_; }

 private:
  void finish_segment() noexcept;

  UsbFrameSink& sink_;
  std::array<std::uint8_t, kMaxPendingEncoded> pending_{};
  std::array<std::uint8_t, kMaxDecodedFrame> decoded_{};
  std::size_t pending_size_{0};
  MonotonicMs last_byte_ms_{0};
  bool discarding_{false};
};

// Session-direction cumulative grant accounting (spec section 3). Mirrors
// CumulativeCredit in host/routeloom-protocol: a grant is a cumulative
// ceiling, not a delta; max wins; duplicates never add; regression is
// rejected. Consume once per frame before the first byte of its write;
// partial-write continuation must not re-charge.
class CumulativeCredit {
 public:
  CumulativeCredit() noexcept = default;
  explicit CumulativeCredit(std::uint64_t session) noexcept : session_(session) {}

  void reset(std::uint64_t session) noexcept {
    session_ = session;
    grant_frames_ = grant_bytes_ = consumed_frames_ = consumed_bytes_ = 0;
  }

  Status update(std::uint64_t session, std::uint64_t grant_frames,
                std::uint64_t grant_bytes) noexcept {
    if (session != session_) {
      return Status::error(StatusCode::ProtocolError, "CREDIT_SESSION_MISMATCH");
    }
    if (grant_frames < grant_frames_ || grant_bytes < grant_bytes_) {
      return Status::error(StatusCode::ProtocolError, "CREDIT_REGRESSION");
    }
    grant_frames_ = grant_frames;
    grant_bytes_ = grant_bytes;
    return Status::success();
  }

  // Charges 1 frame + `decoded_len` bytes (full decoded protected frame length
  // including CRC, excluding COBS and delimiter). WouldBlock when either axis
  // is exhausted; nothing is consumed on failure.
  Status consume(std::uint64_t decoded_len) noexcept {
    // Saturating comparisons: raw addition could wrap past UINT64_MAX and
    // pass the check, so never let consumed exceed grant by wrap-around.
    if (consumed_frames_ >= grant_frames_ || consumed_bytes_ > grant_bytes_ ||
        decoded_len > grant_bytes_ - consumed_bytes_) {
      return Status::error(StatusCode::WouldBlock, "CREDIT_EXHAUSTED");
    }
    ++consumed_frames_;
    consumed_bytes_ += decoded_len;
    return Status::success();
  }

  std::uint64_t session() const noexcept { return session_; }
  std::uint64_t grant_frames() const noexcept { return grant_frames_; }
  std::uint64_t grant_bytes() const noexcept { return grant_bytes_; }
  std::uint64_t consumed_frames() const noexcept { return consumed_frames_; }
  std::uint64_t consumed_bytes() const noexcept { return consumed_bytes_; }
  std::uint64_t available_frames() const noexcept {
    return grant_frames_ - consumed_frames_;
  }
  std::uint64_t available_bytes() const noexcept {
    return grant_bytes_ - consumed_bytes_;
  }

 private:
  std::uint64_t session_{0};
  std::uint64_t grant_frames_{0};
  std::uint64_t grant_bytes_{0};
  std::uint64_t consumed_frames_{0};
  std::uint64_t consumed_bytes_{0};
};

}  // namespace routeloom::usb
