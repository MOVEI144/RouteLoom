// USB device-bridge tests: codec edge cases, cumulative credit, the dev-auth
// session state machine, zero-credit control reservation, idempotency and a
// full replay of the shared protocol/usb-golden vectors produced by the Rust
// routeloom-protocol generator (byte-level C++/Rust interop evidence).

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <new>
#include <sstream>
#include <string>
#include <vector>

#include "routeloom/byte_io.hpp"
#include "routeloom/node.hpp"
#include "routeloom/usb_bridge.hpp"
#include "routeloom/usb_codec.hpp"
#include "routeloom/usb_session.hpp"
#include "routeloom/version.h"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using namespace routeloom::usb;
using routeloom_test::TestSecurity;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimReplyPort;
using routeloom_test::sim_rx_metadata;

#ifndef ROUTELOOM_USB_GOLDEN_DIR
#define ROUTELOOM_USB_GOLDEN_DIR "protocol/usb-golden"
#endif

const std::uint8_t kSecret[] = "routeloom-dev-secret";  // 20 bytes w/o NUL
constexpr std::size_t kSecretLen = 20;

ByteView secret_view() { return ByteView{kSecret, kSecretLen}; }

// ---------------------------------------------------------------- utilities

class FakeStream final : public ByteStream {
 public:
  std::deque<std::uint8_t> out;
  std::size_t max_write{static_cast<std::size_t>(-1)};
  bool fail{false};

  Status write(const ByteView data, std::size_t& written) noexcept override {
    written = 0;
    if (fail) return Status::error(StatusCode::DriverResultUnknown, "stream dead");
    const std::size_t count = std::min(data.size, max_write);
    for (std::size_t i = 0; i < count; ++i) out.push_back(data.data[i]);
    written = count;
    return Status::success();
  }

  std::vector<std::uint8_t> take() {
    std::vector<std::uint8_t> bytes(out.begin(), out.end());
    out.clear();
    return bytes;
  }
};

struct DecodedRecord {
  UsbFrame frame{};
  std::vector<std::uint8_t> body;
};

class CollectSink final : public UsbFrameSink {
 public:
  std::vector<DecodedRecord> frames;
  std::vector<Status> errors;

  void on_frame(const UsbFrame& frame) noexcept override {
    DecodedRecord record{};
    record.frame = frame;
    record.body.assign(frame.body.data, frame.body.data + frame.body.size);
    record.frame.body = ByteView{record.body.data(), record.body.size()};
    frames.push_back(std::move(record));
  }
  void on_stream_error(const Status status) noexcept override {
    errors.push_back(status);
  }
};

std::vector<std::uint8_t> encode(FrameKind kind, std::uint16_t flags,
                                 std::uint64_t session, std::uint64_t request,
                                 ByteView body) {
  std::array<std::uint8_t, kMaxDecodedFrame> scratch{};
  std::array<std::uint8_t, kMaxEncodedFrame> out{};
  std::size_t written = 0;
  const Status status =
      encode_frame(kind, flags, session, request, body,
                   MutableByteView{scratch.data(), scratch.size()},
                   MutableByteView{out.data(), out.size()}, written);
  if (!status) return {};
  return std::vector<std::uint8_t>(out.begin(), out.begin() + written);
}

// ------------------------------------------------------------------- codec

std::uint64_t rng_state = 0xC0B5ULL;
std::uint64_t next_random() {
  rng_state += 0x9e3779b97f4a7c15ULL;
  std::uint64_t z = rng_state;
  z = (z ^ (z >> 30U)) * 0xbf58476d1ce4e5b9ULL;
  z = (z ^ (z >> 27U)) * 0x94d049bb133111ebULL;
  return z ^ (z >> 31U);
}

void test_cobs() {
  std::array<std::uint8_t, 700> input{};
  std::array<std::uint8_t, 800> encoded{};
  std::array<std::uint8_t, 700> decoded{};
  for (const std::size_t size : {0U, 1U, 2U, 253U, 254U, 255U, 508U, 600U}) {
    for (std::size_t i = 0; i < size; ++i) {
      input[i] = static_cast<std::uint8_t>(next_random());
    }
    std::size_t enc = 0, dec = 0;
    CHECK_OK(cobs_encode(ByteView{input.data(), size},
                         MutableByteView{encoded.data(), encoded.size()}, enc));
    CHECK(enc <= size + size / 254 + 1);
    for (std::size_t i = 0; i < enc; ++i) CHECK(encoded[i] != 0);
    CHECK_OK(cobs_decode(ByteView{encoded.data(), enc},
                         MutableByteView{decoded.data(), decoded.size()}, dec));
    CHECK(dec == size);
    CHECK(size == 0 || std::memcmp(input.data(), decoded.data(), size) == 0);
  }
  // All-zero input exercises the code restart path.
  std::memset(input.data(), 0, 10);
  std::size_t enc = 0, dec = 0;
  CHECK_OK(cobs_encode(ByteView{input.data(), 10},
                       MutableByteView{encoded.data(), encoded.size()}, enc));
  CHECK_OK(cobs_decode(ByteView{encoded.data(), enc},
                       MutableByteView{decoded.data(), decoded.size()}, dec));
  CHECK(dec == 10 && std::memcmp(input.data(), decoded.data(), 10) == 0);
}

void test_cobs_exact_capacity() {
  // An output buffer filled to the last byte by a final non-0xFF block must
  // decode: the implicit zero is only emitted between blocks, so reserving
  // space for it at end-of-input falsely rejected exactly-full frames.
  std::vector<std::uint8_t> input(kMaxDecodedFrame);
  for (std::size_t i = 0; i < input.size(); ++i) {
    input[i] = static_cast<std::uint8_t>((i * 31U) ^ 0x5AU);
  }
  std::vector<std::uint8_t> encoded(kMaxEncodedFrame);
  std::size_t enc = 0;
  CHECK_OK(cobs_encode(ByteView{input.data(), input.size()},
                       MutableByteView{encoded.data(), encoded.size()}, enc));
  std::vector<std::uint8_t> decoded(kMaxDecodedFrame);
  std::size_t dec = 0;
  CHECK_OK(cobs_decode(ByteView{encoded.data(), enc},
                       MutableByteView{decoded.data(), decoded.size()}, dec));
  CHECK(dec == input.size());
  CHECK(std::memcmp(input.data(), decoded.data(), dec) == 0);

  // A zero byte inside a COBS segment is malformed (the delimiter is
  // stripped by the stream layer before decode).
  const std::array<std::uint8_t, 4> with_zero{{0x03, 0xAA, 0x00, 0x01}};
  CHECK(cobs_decode(ByteView{with_zero.data(), with_zero.size()},
                    MutableByteView{decoded.data(), decoded.size()}, dec)
            .code == StatusCode::ProtocolError);

  // Null non-empty input is rejected, not dereferenced.
  CHECK(cobs_decode(ByteView{nullptr, 4},
                    MutableByteView{decoded.data(), decoded.size()}, dec)
            .code == StatusCode::InvalidArgument);
}

// The stream decoder decodes each segment in place (one buffer, not two).
// In-place and out-of-place decodes must agree byte for byte, including the
// 0xFF block and implicit-zero paths and the exactly-full 4096-byte frame.
void test_cobs_decode_in_place() {
  for (const std::size_t size :
       {std::size_t{0}, std::size_t{1}, std::size_t{2}, std::size_t{253},
        std::size_t{254}, std::size_t{255}, std::size_t{508}, std::size_t{1000},
        kMaxDecodedFrame}) {
    for (const int pattern : {0, 1, 2}) {
      std::vector<std::uint8_t> input(size);
      for (std::size_t i = 0; i < size; ++i) {
        input[i] = pattern == 0 ? static_cast<std::uint8_t>(next_random())
                   : pattern == 1 ? static_cast<std::uint8_t>(i % 3 == 0 ? 0 : i)
                                  : static_cast<std::uint8_t>(0xA5);
      }
      std::vector<std::uint8_t> buffer(kMaxEncodedFrame);
      std::size_t enc = 0;
      CHECK_OK(cobs_encode(ByteView{input.data(), input.size()},
                           MutableByteView{buffer.data(), buffer.size()}, enc));
      std::vector<std::uint8_t> separate(kMaxDecodedFrame);
      std::size_t dec_separate = 0;
      CHECK_OK(cobs_decode(ByteView{buffer.data(), enc},
                           MutableByteView{separate.data(), separate.size()},
                           dec_separate));
      std::size_t dec_in_place = 0;
      CHECK_OK(cobs_decode(ByteView{buffer.data(), enc},
                           MutableByteView{buffer.data(), kMaxDecodedFrame},
                           dec_in_place));
      CHECK(dec_in_place == size && dec_separate == size);
      CHECK(size == 0 || std::memcmp(buffer.data(), input.data(), size) == 0);
    }
  }
}

// encode_frame needs only encoded_frame_bound(decoded) bytes of output — the
// bridge stages its TX frame in a buffer sized for its largest body, not a
// 4 KB frame — and refuses anything smaller without writing past it.
void test_encode_frame_bounded_output() {
  CHECK(encoded_frame_bound(kMaxDecodedFrame) == kMaxEncodedFrame);
  std::vector<std::uint8_t> body(1048);
  for (std::size_t i = 0; i < body.size(); ++i) {
    body[i] = static_cast<std::uint8_t>(i % 5 == 0 ? 0 : 0xFF - i);
  }
  const std::size_t decoded = kHeaderSize + body.size() + kCrcSize;
  std::vector<std::uint8_t> scratch(decoded);
  std::vector<std::uint8_t> tight(encoded_frame_bound(decoded));
  std::size_t written = 0;
  CHECK_OK(encode_frame(FrameKind::DataFromMesh, 0, 7, 9,
                        ByteView{body.data(), body.size()},
                        MutableByteView{scratch.data(), scratch.size()},
                        MutableByteView{tight.data(), tight.size()}, written));
  const std::vector<std::uint8_t> reference = encode(
      FrameKind::DataFromMesh, 0, 7, 9, ByteView{body.data(), body.size()});
  CHECK(!reference.empty() && written == reference.size() &&
        std::memcmp(tight.data(), reference.data(), written) == 0);
  CHECK(encode_frame(FrameKind::DataFromMesh, 0, 7, 9,
                     ByteView{body.data(), body.size()},
                     MutableByteView{scratch.data(), scratch.size()},
                     MutableByteView{tight.data(), tight.size() - 1}, written)
            .code == StatusCode::NoCapacity);
}

void test_encode_frame_inplace() {
  std::array<std::uint8_t, 1048> body{};
  std::array<std::uint8_t, kHeaderSize + 1048 + kCrcSize> scratch{};
  std::array<std::uint8_t, kMaxEncodedFrame> wire{};
  for (const std::size_t size : {0U, 1U, 253U, 254U, 255U, 960U, 1024U, 1048U}) {
    for (const bool all_zero : {false, true}) {
      for (std::size_t i = 0; i < size; ++i) {
        body[i] = all_zero ? 0 : static_cast<std::uint8_t>(i * 37U + 3U);
      }
      std::copy_n(body.begin(), size, scratch.begin());
      const std::size_t decoded = kHeaderSize + size + kCrcSize;
      std::size_t written = 0;
      CHECK_OK(encode_frame_inplace(
          FrameKind::DataFromMesh, 0x1234, 7, 9,
          MutableByteView{scratch.data(), decoded}, size,
          MutableByteView{wire.data(), encoded_frame_bound(decoded)}, written));
      const auto reference = encode(FrameKind::DataFromMesh, 0x1234, 7, 9,
                                    ByteView{body.data(), size});
      CHECK(written == reference.size());
      CHECK(std::memcmp(wire.data(), reference.data(), written) == 0);
    }
  }
  std::size_t written = 99;
  CHECK(encode_frame_inplace(FrameKind::DataFromMesh, 0, 0, 0,
                             MutableByteView{scratch.data(), scratch.size() - 1},
                             body.size(), MutableByteView{wire.data(), wire.size()}, written)
            .code == StatusCode::NoCapacity);
  CHECK(written == 0);
  CHECK(encode_frame_inplace(FrameKind::DataFromMesh, 0, 0, 0,
                             MutableByteView{scratch.data(), scratch.size()},
                             body.size(), MutableByteView{wire.data(), 1}, written)
            .code == StatusCode::NoCapacity);
  CHECK(written == 0);
}

void test_frame_max_body_boundary() {
  // kMaxBodySize = 4066 → decoded frame exactly kMaxDecodedFrame (4096):
  // the stream decoder must accept it (the phantom-zero bug rejected it).
  CollectSink sink;
  StreamDecoder decoder(sink);
  std::vector<std::uint8_t> body(kMaxBodySize);
  for (std::size_t i = 0; i < body.size(); ++i) {
    body[i] = static_cast<std::uint8_t>(i * 17U);
  }
  const auto wire = encode(FrameKind::DataToMesh, 0, 1, 2,
                           ByteView{body.data(), body.size()});
  CHECK(!wire.empty());
  decoder.push(ByteView{wire.data(), wire.size()}, 0);
  CHECK(sink.frames.size() == 1);
  CHECK(sink.frames[0].frame.body.size == kMaxBodySize);
  CHECK(sink.errors.empty());

  // One byte over the limit is rejected by encode, not truncated.
  std::array<std::uint8_t, kMaxDecodedFrame> scratch{};
  std::array<std::uint8_t, kMaxEncodedFrame> out{};
  std::size_t written = 0;
  CHECK(encode_frame(FrameKind::DataToMesh, 0, 1, 2,
                     ByteView{body.data(), kMaxBodySize + 1},
                     MutableByteView{scratch.data(), scratch.size()},
                     MutableByteView{out.data(), out.size()}, written)
            .code == StatusCode::InvalidArgument);

  // An undersized scratch is rejected honestly, never truncated into.
  std::array<std::uint8_t, 64> small_scratch{};
  CHECK(encode_frame(FrameKind::DataToMesh, 0, 1, 2,
                     ByteView{body.data(), 128},
                     MutableByteView{small_scratch.data(), small_scratch.size()},
                     MutableByteView{out.data(), out.size()}, written)
            .code == StatusCode::NoCapacity);
}

void test_frame_codec() {
  CollectSink sink;
  StreamDecoder decoder(sink);

  const std::array<std::uint8_t, 5> body{{0, 1, 2, 0, 3}};
  const auto wire = encode(FrameKind::DataToMesh, 7, 11, 12,
                           ByteView{body.data(), body.size()});
  CHECK(!wire.empty());
  CHECK(wire.back() == 0);
  // One byte at a time must not change the decode.
  for (const std::uint8_t byte : wire) decoder.push(ByteView{&byte, 1}, 0);
  CHECK(sink.frames.size() == 1);
  CHECK(sink.errors.empty());
  const UsbFrame& frame = sink.frames[0].frame;
  CHECK(frame.kind == FrameKind::DataToMesh && frame.flags == 7 &&
        frame.session == 11 && frame.request == 12 && frame.body.size == 5);
  CHECK(std::memcmp(frame.body.data, body.data(), 5) == 0);

  // Corrupt byte inside a frame -> error event, stream resyncs.
  auto corrupt = wire;
  corrupt[corrupt.size() / 2] ^= 1;
  decoder.push(ByteView{corrupt.data(), corrupt.size()}, 1);
  CHECK(!sink.errors.empty());
  CHECK(sink.frames.size() == 1);
  decoder.push(ByteView{wire.data(), wire.size()}, 2);
  CHECK(sink.frames.size() == 2);

  // Garbage (boot-log noise) ends at a delimiter: the segment fails to
  // decode, an error is reported, and the next frame resyncs cleanly.
  const std::array<std::uint8_t, 4> noise{{'b', 'o', 'o', 't'}};
  const std::array<std::uint8_t, 1> delim{{0}};
  decoder.push(ByteView{noise.data(), noise.size()}, 3);
  decoder.push(ByteView{delim.data(), delim.size()}, 3);
  decoder.push(ByteView{wire.data(), wire.size()}, 3);
  CHECK(sink.frames.size() == 3);

  // Overlength segment: bounded discard until the next delimiter, then resync.
  std::vector<std::uint8_t> flood(kMaxPendingEncoded + 16, 0x55);
  decoder.push(ByteView{flood.data(), flood.size()}, 4);
  CHECK(decoder.discarding());
  decoder.push(ByteView{delim.data(), delim.size()}, 4);
  CHECK(!decoder.discarding());
  decoder.push(ByteView{wire.data(), wire.size()}, 5);
  CHECK(sink.frames.size() == 4);
  CHECK(!decoder.discarding());

  // Partial frame is discarded after the 1000ms timeout; next frame decodes.
  const std::size_t half = wire.size() / 2;
  decoder.push(ByteView{wire.data(), half}, 6);
  CHECK(decoder.pending() == half);
  decoder.poll(6 + kPartialFrameTimeoutMs - 1);
  CHECK(decoder.pending() == half);
  const std::size_t errors_before = sink.errors.size();
  decoder.poll(6 + kPartialFrameTimeoutMs + 1);
  CHECK(decoder.pending() == 0);
  CHECK(sink.errors.size() > errors_before);
  decoder.push(ByteView{wire.data(), wire.size()}, 7 + kPartialFrameTimeoutMs);
  CHECK(sink.frames.size() == 5);
}

void test_credit() {
  CumulativeCredit credit(9);
  CHECK(credit.update(8, 4, 400).code == StatusCode::ProtocolError);
  CHECK_OK(credit.update(9, 4, 400));
  CHECK_OK(credit.update(9, 4, 400));  // duplicate grant never adds
  // Stale (reordered, smaller) notices are absorbed per-axis max — no error,
  // no shrink (usb-protocol.md §3, shared golden tx_grant_stale/zero/mixed).
  CHECK_OK(credit.update(9, 3, 400));
  CHECK(credit.grant_frames() == 4 && credit.grant_bytes() == 400);
  CHECK_OK(credit.update(9, 4, 300));
  CHECK(credit.grant_frames() == 4 && credit.grant_bytes() == 400);
  CHECK_OK(credit.update(9, 0, 0));
  CHECK(credit.grant_frames() == 4 && credit.grant_bytes() == 400);
  // Partially-stale: a higher frames axis still advances while bytes keeps
  // the earlier maximum.
  CHECK_OK(credit.update(9, 6, 100));
  CHECK(credit.grant_frames() == 6 && credit.grant_bytes() == 400);
  CHECK_OK(credit.consume(100));
  CHECK_OK(credit.consume(100));
  CHECK_OK(credit.consume(100));
  CHECK_OK(credit.consume(100));
  CHECK(credit.consume(1).code == StatusCode::WouldBlock);
  CHECK(credit.consumed_frames() == 4 && credit.consumed_bytes() == 400);
  // Bytes axis is enforced independently.
  CumulativeCredit small(1);
  CHECK_OK(small.update(1, 3, 100));
  CHECK(small.consume(101).code == StatusCode::WouldBlock);
  CHECK(small.consumed_frames() == 0);
  // Saturating accounting: a consume that would wrap `consumed + len` past
  // UINT64_MAX must still compare against the grant, not pass by wrap-around.
  CumulativeCredit wrap(1);
  CHECK_OK(wrap.update(1, 10, UINT64_MAX));
  CHECK_OK(wrap.consume(UINT64_MAX - 5));
  CHECK(wrap.consume(10).code == StatusCode::WouldBlock);
  CHECK(wrap.consumed_bytes() == UINT64_MAX - 5);
  // Session change resets accounting.
  credit.reset(10);
  CHECK(credit.grant_frames() == 0 && credit.consumed_frames() == 0);
}

// ------------------------------------------------------------------ session

SessionTranscript golden_transcript(std::uint32_t capability = 0x3 | kCapHostOpsV1) {
  SessionTranscript t{};
  t.host_nonce = 0x0102030405060708ULL;
  t.device_nonce = 0xA0B0C0D0E0F00102ULL;
  t.version = 2;
  t.node = 1;
  t.boot_id = 0x000000B0071D0001ULL;
  t.network = 7;
  t.capability = capability;
  const char* principal = "host-operator";
  t.principal_len = 13;
  std::memcpy(t.principal.data(), principal, t.principal_len);
  return t;
}

SessionProof golden_proof(std::uint32_t capability = 0x3 | kCapHostOpsV1) {
  const SessionTranscript transcript = golden_transcript(capability);
  std::array<std::uint8_t, kTranscriptSize> encoded{};
  std::size_t size = 0;
  if (!encode_transcript(transcript,
                         MutableByteView{encoded.data(), encoded.size()}, size)) {
    return SessionProof{};
  }
  return derive_session_proof(secret_view(), ByteView{encoded.data(), size});
}

void test_session_mac() {
  // Anchors are pinned by protocol/usb-golden/session.json (test_golden_session);
  // here: direction keys differ and every frame-tag input is covered.
  const SessionProof proof = golden_proof();
  CHECK(proof.key_h2d != proof.key_d2h);

  const std::array<std::uint8_t, 4> inner{{1, 2, 3, 4}};
  std::array<std::uint8_t, 64> sealed{};
  std::size_t sealed_size = 0;
  CHECK_OK(seal_body(proof.key_h2d, kDirHostToDevice, 0, FrameKind::KeepAlive, 0, 9,
                     ByteView{inner.data(), inner.size()},
                     MutableByteView{sealed.data(), sealed.size()}, sealed_size));
  CHECK(sealed_size == kProtectedBodyOverhead + inner.size());
  UsbFrame frame{};
  frame.kind = FrameKind::KeepAlive;
  frame.request = 9;
  frame.body = ByteView{sealed.data(), sealed_size};
  std::uint64_t counter = 99;
  ByteView opened{};
  CHECK_OK(open_body(proof.key_h2d, kDirHostToDevice, frame, counter, opened));
  CHECK(counter == 0 && opened.size == inner.size());
  // Wrong direction, tampered tag and tampered inner all fail.
  CHECK(open_body(proof.key_d2h, kDirDeviceToHost, frame, counter, opened).code ==
        StatusCode::AuthenticationFailed);
  sealed[10] ^= 1;
  frame.body = ByteView{sealed.data(), sealed_size};
  CHECK(open_body(proof.key_h2d, kDirHostToDevice, frame, counter, opened).code ==
        StatusCode::AuthenticationFailed);
  // The other direction's key never opens a frame, even with the right byte.
  sealed[10] ^= 1;
  frame.body = ByteView{sealed.data(), sealed_size};
  CHECK(open_body(proof.key_d2h, kDirHostToDevice, frame, counter, opened).code ==
        StatusCode::AuthenticationFailed);
  // A rewritten offered version range (downgrade) or another secret changes
  // every session value.
  SessionTranscript narrowed = golden_transcript();
  narrowed.max_version = 1;
  std::array<std::uint8_t, kTranscriptSize> encoded{};
  std::size_t size = 0;
  CHECK_OK(encode_transcript(narrowed, MutableByteView{encoded.data(), encoded.size()}, size));
  const SessionProof downgraded =
      derive_session_proof(secret_view(), ByteView{encoded.data(), size});
  CHECK(downgraded.auth_tag != proof.auth_tag && downgraded.key_h2d != proof.key_h2d);
  SessionTranscript other_network = golden_transcript();
  other_network.network |= 1ULL << 32U;
  CHECK_OK(encode_transcript(other_network,
                             MutableByteView{encoded.data(), encoded.size()}, size));
  const SessionProof network_bound =
      derive_session_proof(secret_view(), ByteView{encoded.data(), size});
  CHECK(network_bound.hello_tag != proof.hello_tag);
  const std::array<std::uint8_t, 3> other{{'b', 'a', 'd'}};
  const SessionProof wrong = derive_session_proof(ByteView{other.data(), other.size()},
                                                  ByteView{encoded.data(), size});
  CHECK(wrong.hello_tag != network_bound.hello_tag);
  // The last 64-bit counter cannot be sealed: incrementing it would reuse
  // counter zero in the same session.
  sealed_size = 99;
  CHECK(!seal_body(proof.key_h2d, kDirHostToDevice, UINT64_MAX,
                   FrameKind::KeepAlive, 0, 9, ByteView{},
                   MutableByteView{sealed.data(), sealed.size()}, sealed_size).ok());
  CHECK(sealed_size == 0);
}

void test_session_material_clears_on_destruction() {
  alignas(SessionProof) std::array<std::uint8_t, sizeof(SessionProof)> proof_storage{};
  auto* proof = new (proof_storage.data()) SessionProof(golden_proof());
  CHECK(std::any_of(proof->key_h2d.begin(), proof->key_h2d.end(),
                    [](std::uint8_t byte) { return byte != 0; }));
  proof->~SessionProof();
  const auto proof_key = proof_storage.begin() + offsetof(SessionProof, key_h2d);
  CHECK(std::all_of(proof_key, proof_key + usb::kSessionKeySize,
                    [](std::uint8_t byte) { return byte == 0; }));

  alignas(SessionKeys) std::array<std::uint8_t, sizeof(SessionKeys)> keys_storage{};
  auto* keys = new (keys_storage.data()) SessionKeys{};
  keys->key_h2d.fill(0xa5);
  keys->~SessionKeys();
  const auto session_key = keys_storage.begin() + offsetof(SessionKeys, key_h2d);
  CHECK(std::all_of(session_key, session_key + usb::kSessionKeySize,
                    [](std::uint8_t byte) { return byte == 0; }));

  alignas(Sha256) std::array<std::uint8_t, sizeof(Sha256)> hash_storage{};
  auto* hash = new (hash_storage.data()) Sha256{};
  const std::array<std::uint8_t, 3> key_material{{'k', 'e', 'y'}};
  hash->update(ByteView{key_material.data(), key_material.size()});
  hash->~Sha256();
  CHECK(std::all_of(hash_storage.begin(), hash_storage.end(),
                    [](std::uint8_t byte) { return byte == 0; }));
}

void test_idempotency() {
  const SessionTag hash{};
  constexpr std::uint64_t s1 = 0x51, s2 = 0x52;
  IdempotencyRecord* record = nullptr;
  const auto submit = [&](IdempotencyTable& table, std::uint64_t key,
                          std::uint64_t session, MonotonicMs now) {
    return table.submit(key, hash, session, now, record);
  };
  IdempotencyTable full;
  std::array<IdempotencyRecord*, IdempotencyTable::kCapacity> rows{};
  for (std::uint64_t key = 0; key < rows.size(); ++key) {
    CHECK(submit(full, 100 + key, s1, 5000 + key) == IdempotencyResult::Accepted);
    rows[key] = record;
    record->accepted = true;
    record->message_session = 77;
    record->message_sequence = key;
  }
  CHECK(submit(full, 200, s1, 6000) == IdempotencyResult::NoCapacity);
  CHECK(submit(full, 200, s1, 24ULL * 3600 * 1000 + 6000) ==
        IdempotencyResult::NoCapacity);
  CHECK(full.find_message(77, 3) == rows[3] && full.find_message(78, 3) == nullptr);
  rows[3]->settled = true;
  rows[1]->settled = true;
  CHECK(full.next_unreported(s1) == rows[1] && full.next_unreported(s2) == nullptr);
  CHECK(submit(full, 200, s1, 6001) == IdempotencyResult::NoCapacity);
  rows[3]->reported = true;
  rows[1]->reported = true;
  // Replaying the oldest outcome must not make a newer terminal the victim.
  CHECK(submit(full, 101, s1, 6002) == IdempotencyResult::Existing);
  CHECK(submit(full, 200, s1, 6003) == IdempotencyResult::Accepted);
  CHECK(record == rows[1]);
  CHECK(submit(full, 101, s1, 6004) == IdempotencyResult::ResultExpired);
  CHECK(submit(full, 99, s1, 6004) == IdempotencyResult::ResultExpired);
  CHECK(submit(full, 100, s1, 6004) == IdempotencyResult::Existing);
  SessionTag other{};
  other[0] = 1;
  CHECK(full.submit(100, other, s1, 6004, record) ==
        IdempotencyResult::Conflict);

  // Retry reservations use the same bound and never steal an owed request.
  CHECK(submit(full, 100, s1, 6004) == IdempotencyResult::Existing);
  record->request = 40;
  CHECK(full.repeat(record, 41));
  CHECK(record->request == 41 && rows[0]->request == 40);
  CHECK(!full.repeat(record, 42));
  CHECK(record->request == 41 && full.size() == IdempotencyTable::kCapacity);
  record->settled = true;
  record->reported = true;

  // A new HostLink incarnation has an independent floor and key space.
  CHECK(submit(full, 101, s2, 6005) == IdempotencyResult::Accepted);
  CHECK(record->usb_session == s2);
  CHECK(submit(full, 300, s2, 6006) == IdempotencyResult::NoCapacity);

  // Sustained traffic reclaims terminals without losing its floor. Each
  // new incarnation may start its monotonic keys at a fresh random base.
  IdempotencyTable stream;
  MonotonicMs now = 10000;
  for (std::uint64_t session = 1; session <= 6; ++session) {
    for (std::uint64_t key = 1000; key < 2100; ++key) {
      CHECK(submit(stream, key, session, ++now) == IdempotencyResult::Accepted);
      record->settled = true;
      record->reported = true;
    }
    CHECK(stream.size() == IdempotencyTable::kCapacity);
    CHECK(submit(stream, 999, session, ++now) == IdempotencyResult::ResultExpired);
    CHECK(submit(stream, 1000, session, ++now) == IdempotencyResult::ResultExpired);
    CHECK(submit(stream, 2099, session, ++now) == IdempotencyResult::Existing);
  }
}

// -------------------------------------------------------- loopback bridge

struct HostDriver {
  SessionProof proof{};
  std::uint64_t h2d_counter{0};
  std::uint64_t session{0};

  std::vector<std::uint8_t> plain(FrameKind kind, std::uint16_t flags,
                                  std::uint64_t request, ByteView body) {
    return encode(kind, flags, 0, request, body);
  }
  std::vector<std::uint8_t> sealed(FrameKind kind, std::uint64_t request,
                                   ByteView inner) {
    std::array<std::uint8_t, 1200> body{};
    std::size_t body_size = 0;
    if (!seal_body(proof.key_h2d, kDirHostToDevice, h2d_counter, kind, 0, request,
                   inner, MutableByteView{body.data(), body.size()}, body_size)) {
      return {};
    }
    ++h2d_counter;
    return encode(kind, 0, session, request, ByteView{body.data(), body_size});
  }
};

struct World {
  FakeStream stream;
  std::vector<std::uint8_t> secret{kSecret, kSecret + kSecretLen};
  UsbBridge bridge;
  SimNetwork net;
  TestSecurity sec1, sec2;
  CapturingObserver obs2;
  SimRadio r1, r2;
  SimReplyPort p1, p2;
  MeshNode n1, n2;
  CollectSink device_sink;
  StreamDecoder device_decoder;

  explicit World(bool scoped = false)
      : bridge(config(), stream),
        r1(net, 1), r2(net, 2),
        p1(r1, 1, node_config(1, 7001, scoped).link_epoch),
        p2(r2, 2, node_config(2, 2002, scoped).link_epoch),
        n1(node_config(1, 7001, scoped), r1, sec1, bridge),
        n2(node_config(2, 2002, scoped), r2, sec2, obs2),
        device_decoder(device_sink) {
    (void)n1.set_reply_peer_port(&p1);
    (void)n2.set_reply_peer_port(&p2);
    bridge.set_mesh(&n1);
    net.register_node(1, &n1);
    net.register_node(2, &n2);
    net.register_reply_port(1, &p1);
    net.register_reply_port(2, &p2);
    net.connect(1, 2);
    n1.start(0);
    n2.start(0);
    n1.add_neighbor(2, 1, 0);
    n2.add_neighbor(1, 1, 0);
  }

  UsbBridge::Config config() {
    UsbBridge::Config cfg{};
    cfg.secret = ByteView{secret.data(), secret.size()};
    cfg.node = 1;
    cfg.network = 7;
    cfg.boot_id = 0xB0071D0001ULL;
    cfg.capability = 0x3 | kCapHostOpsV1;
    cfg.device_nonce = 0xA0B0C0D0E0F00102ULL;
    return cfg;
  }
  static NodeConfig node_config(NodeId node, std::uint32_t session, bool scoped = false) {
    NodeConfig cfg{};
    cfg.network = 7;
    cfg.node = node;
    cfg.message_session = session;
    cfg.boot_incarnation = session;  // firmware wires the same NVS counter
    if (scoped) {
      // Gateway-scoped profile, node 1 (the bridge node) the route gateway:
      // the only profile group delivery runs on.
      cfg.route_gateways = {1, kInvalidNodeId};
      cfg.route_advertisement_period_ms = 500;
      cfg.route_lifetime_ms = 9000;
      cfg.route_refresh_ticks = kScopedDefaultRefreshTicks;
    }
    return cfg;
  }

  // Pumps both mesh nodes, the radio and the bridge; returns the device
  // bytes the bridge emitted meanwhile.
  std::vector<std::uint8_t> run_mesh(MonotonicMs& now, const MonotonicMs ms) {
    std::vector<std::uint8_t> out;
    const MonotonicMs end = now + ms;
    for (; now < end; now += 5) {
      n1.poll(now);
      n2.poll(now);
      net.flush(now);
      bridge.poll(now);
      const auto bytes = stream.take();
      out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
  }

  void feed(const std::vector<std::uint8_t>& wire, MonotonicMs now) {
    bridge.on_bytes(ByteView{wire.data(), wire.size()}, now);
  }
  std::vector<std::uint8_t> drain_raw(MonotonicMs now) {
    for (int i = 0; i < 16; ++i) bridge.poll(now);
    return stream.take();
  }
  void drain(MonotonicMs now) {
    // Anything the device emitted lands in the sink for inspection.
    const auto bytes = drain_raw(now);
    if (!bytes.empty()) device_decoder.push(ByteView{bytes.data(), bytes.size()}, now);
  }
};

std::uint16_t read_u16(const std::uint8_t* p) {
  return static_cast<std::uint16_t>((p[0] << 8U) | p[1]);
}

std::uint32_t read_u32(const std::uint8_t* p) {
  return (static_cast<std::uint32_t>(p[0]) << 24U) |
         (static_cast<std::uint32_t>(p[1]) << 16U) |
         (static_cast<std::uint32_t>(p[2]) << 8U) | p[3];
}

std::uint64_t read_u64(const std::uint8_t* p) {
  std::uint64_t v = 0;
  for (int i = 0; i < 8; ++i) v = (v << 8U) | p[i];
  return v;
}

void write_u64(std::uint8_t* p, std::uint64_t v) {
  for (int i = 7; i >= 0; --i) {
    p[i] = static_cast<std::uint8_t>(v & 0xFFU);
    v >>= 8U;
  }
}

// Performs HELLO/AUTH/ACTIVE against the bridge using the shared dev-session
// helpers. Returns the negotiated session id (0 on failure).
std::uint64_t host_handshake(World& world, HostDriver& host, MonotonicMs& now,
                             std::uint64_t host_nonce, std::uint64_t request_base) {
  std::array<std::uint8_t, 64> hello_body{};
  write_u64(hello_body.data(), host_nonce);
  hello_body[8] = 2;
  hello_body[9] = 2;
  const char* principal = "host-operator";
  hello_body[10] = 13;
  std::memcpy(hello_body.data() + 11, principal, 13);
  world.feed(host.plain(FrameKind::Hello, 0, request_base,
                        ByteView{hello_body.data(), 24}), now);
  world.drain(now);
  now += 200;
  if (world.device_sink.frames.size() != 1) return 0;
  const auto& ack = world.device_sink.frames.back().frame;
  if (ack.kind != FrameKind::HelloAck || ack.body.size != 53) return 0;
  // Copy the body out: clearing the sink would invalidate the ByteView.
  std::array<std::uint8_t, 64> ack_body{};
  std::memcpy(ack_body.data(), ack.body.data, ack.body.size);
  world.device_sink.frames.clear();

  SessionTranscript transcript{};
  transcript.host_nonce = host_nonce;
  transcript.device_nonce = read_u64(ack_body.data());
  transcript.version = ack_body[8];
  transcript.node = read_u64(ack_body.data() + 9);
  transcript.boot_id = read_u64(ack_body.data() + 17);
  transcript.network = read_u64(ack_body.data() + 25);
  transcript.capability = read_u32(ack_body.data() + 33);
  transcript.principal_len = 13;
  std::memcpy(transcript.principal.data(), principal, 13);
  std::array<std::uint8_t, kTranscriptSize> encoded{};
  std::size_t size = 0;
  if (!encode_transcript(transcript,
                         MutableByteView{encoded.data(), encoded.size()}, size)) {
    return 0;
  }
  host.proof = derive_session_proof(secret_view(), ByteView{encoded.data(), size});
  host.session = host.proof.session_id;

  // Verify the device's hello tag before authenticating.
  if (std::memcmp(ack_body.data() + 37, host.proof.hello_tag.data(), kTagSize) != 0) {
    return 0;
  }
  world.feed(host.plain(FrameKind::Hello, kFlagAuth, request_base + 1,
                        ByteView{host.proof.auth_tag.data(), kTagSize}), now);
  world.drain(now);
  now += 200;
  if (world.device_sink.frames.size() != 2) return 0;  // auth_ok + rx grant
  const auto& auth_ok = world.device_sink.frames[0].frame;
  if (auth_ok.kind != FrameKind::HelloAck || (auth_ok.flags & kFlagAuth) == 0 ||
      auth_ok.body.size != 24) {
    return 0;
  }
  if (std::memcmp(auth_ok.body.data, host.proof.auth_ok_tag.data(), kTagSize) != 0 ||
      read_u64(auth_ok.body.data + kTagSize) != host.session) {
    return 0;
  }
  const auto& grant = world.device_sink.frames[1].frame;
  if (grant.kind != FrameKind::Credit || grant.session != host.session) return 0;
  std::uint64_t counter = 0;
  ByteView inner{};
  if (!open_body(host.proof.key_d2h, kDirDeviceToHost, grant, counter, inner) ||
      counter != 0 || inner.size != 17 || inner.data[0] != kCreditGrant) {
    return 0;
  }
  world.device_sink.frames.clear();
  return host.session;
}

void test_bridge_auth_reserves_initial_grant() {
  World world;
  HostDriver host;
  MonotonicMs now = 10;
  std::array<std::uint8_t, 24> hello{};
  write_u64(hello.data(), 0x1234);
  hello[8] = 2;
  hello[9] = 2;
  hello[10] = 13;
  std::memcpy(hello.data() + 11, "host-operator", 13);
  world.feed(host.plain(FrameKind::Hello, 0, 1, ByteView{hello.data(), hello.size()}), now);
  world.drain(now);
  CHECK(world.device_sink.frames.size() == 1);
  if (world.device_sink.frames.size() != 1) return;
  const UsbFrame ack = world.device_sink.frames[0].frame;
  SessionTranscript transcript{};
  transcript.host_nonce = 0x1234;
  transcript.device_nonce = read_u64(ack.body.data);
  transcript.node = read_u64(ack.body.data + 9);
  transcript.boot_id = read_u64(ack.body.data + 17);
  transcript.network = read_u64(ack.body.data + 25);
  transcript.capability = read_u32(ack.body.data + 33);
  transcript.principal_len = 13;
  std::memcpy(transcript.principal.data(), "host-operator", 13);
  std::array<std::uint8_t, kTranscriptSize> encoded{};
  std::size_t size = 0;
  CHECK_OK(encode_transcript(transcript, MutableByteView{encoded.data(), encoded.size()}, size));
  const SessionProof proof = derive_session_proof(secret_view(), ByteView{encoded.data(), size});
  world.device_sink.frames.clear();

  // Malformed AUTHs can fill the pre-auth control queue before a valid AUTH.
  for (int i = 0; i < 3; ++i) {
    world.feed(host.plain(FrameKind::Hello, kFlagAuth, 2 + i,
                          ByteView{nullptr, 0}), now);
  }
  world.feed(host.plain(FrameKind::Hello, kFlagAuth, 5,
                        ByteView{proof.auth_tag.data(), proof.auth_tag.size()}), now);
  world.drain(now);
  bool saw_auth_ok = false;
  bool saw_grant = false;
  for (const auto& record : world.device_sink.frames) {
    saw_auth_ok |= record.frame.kind == FrameKind::HelloAck &&
                   (record.frame.flags & kFlagAuth) != 0;
    saw_grant |= record.frame.kind == FrameKind::Credit;
  }
  CHECK(saw_auth_ok && saw_grant);
}

std::vector<std::uint8_t> grant_body(std::uint64_t frames, std::uint64_t bytes) {
  std::vector<std::uint8_t> inner(17, 0);
  inner[0] = kCreditGrant;
  write_u64(inner.data() + 1, frames);
  write_u64(inner.data() + 9, bytes);
  return inner;
}

void test_bridge_optional_capabilities_need_attachment() {
  FakeStream stream;
  UsbBridge::Config cfg{};
  cfg.capability = 0x3 | kCapHostOpsV1 | kCapGatewayEndpointV1 | kCapConfigEndpointV1 |
                   kCapM1DiagnosticsV1 | kCapNodeStatusV1 | kCapGroupDeliveryV1 |
                   kCapJoinRelayV1 | kCapJoinRelayV2 | kCapAuthorityChannelV1 |
                   kCapObservationV1 | kCapRxAssuranceV1;
  UsbBridge bridge(cfg, stream);
  CHECK(bridge.capability() == (0x3 | kCapHostOpsV1));
}

void test_bridge_session_lifecycle() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(world.bridge.state() == SessionState::Disconnected);
  const std::uint64_t session = host_handshake(world, host, now, 0x1111, 10);
  CHECK(session != 0);
  CHECK(world.bridge.state() == SessionState::Active);

  // No device->host grant yet: a mesh event queues but cannot send.
  const std::array<std::uint8_t, 3> msg{{9, 9, 9}};
  world.bridge.on_message(MessageKey{2, MessageId{2002, 1}}, 2,
                          ByteView{msg.data(), msg.size()});
  world.drain(now);
  // Zero credit: the mesh event stays queued; only CONTROL frames
  // (bounded credit queries) may leave under the reservation.
  for (const auto& record : world.device_sink.frames) {
    CHECK(record.frame.kind == FrameKind::Credit);
  }
  CHECK(world.bridge.stats().credit_denied > 0);

  // The stall ladder emits bounded credit queries then CONNECTION_STALLED.
  for (int i = 0; i < 20; ++i) {
    now += 100;
    world.drain(now);
  }
  std::size_t queries = 0;
  bool stalled_error = false;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind == FrameKind::Credit) ++queries;
    if (record.frame.kind == FrameKind::Error) {
      std::uint64_t counter = 0;
      ByteView opened{};
      // Error inner body: code u16 || request u64 || rlen u8 || reason.
      if (open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter,
                    opened) &&
          opened.size > 2 &&
          opened.data[1] == static_cast<std::uint8_t>(UsbErrorCode::ConnectionStalled)) {
        stalled_error = true;
      }
    }
  }
  CHECK(queries == 3);           // bounded: 500ms spacing, max 3
  CHECK(stalled_error);
  CHECK(world.bridge.connection_stalled());
  world.device_sink.frames.clear();

  // A fresh cumulative grant un-stalls the pending frame; it is charged once.
  world.feed(host.sealed(FrameKind::Credit, 20, ByteView{grant_body(4, 4096).data(), 17}), now);
  world.drain(now);
  CHECK(!world.bridge.connection_stalled());
  bool got_mesh_frame = false;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind == FrameKind::DataFromMesh) {
      got_mesh_frame = true;
      std::uint64_t counter = 0;
      ByteView inner{};
      CHECK_OK(open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter, inner));
      CHECK(inner.size == 20 + 3);
      CHECK(read_u64(inner.data) == 2);
    }
  }
  CHECK(got_mesh_frame);
  CHECK(world.bridge.tx_credit().consumed_frames() == 1);
  world.device_sink.frames.clear();

  // Stale-session frame (valid tag, wrong session id) is dropped silently.
  const std::uint64_t wrong_session = session ^ 0xFFULL;
  std::array<std::uint8_t, 64> stale_body{};
  std::size_t stale_body_size = 0;
  CHECK_OK(seal_body(host.proof.key_h2d, kDirHostToDevice, host.h2d_counter,
                     FrameKind::KeepAlive, 0, 21, ByteView{},
                     MutableByteView{stale_body.data(), stale_body.size()},
                     stale_body_size));
  const auto stale_frame = encode(FrameKind::KeepAlive, 0, wrong_session, 21,
                                  ByteView{stale_body.data(), stale_body_size});
  world.feed(stale_frame, now);
  world.drain(now);
  CHECK(world.bridge.stats().stale_session == 1);
  CHECK(world.device_sink.frames.empty());

  // Replay: same wire bytes twice; the second copy must be rejected.
  const auto keep = host.sealed(FrameKind::KeepAlive, 22, ByteView{});
  world.feed(keep, now);
  world.drain(now);
  world.feed(keep, now);
  world.drain(now);
  CHECK(world.bridge.stats().replay_rejected == 1);
  world.device_sink.frames.clear();

  // Reconnect: a fresh HELLO tears down and builds a new session.
  HostDriver host2;
  const std::uint64_t session2 = host_handshake(world, host2, now, 0x2222, 30);
  CHECK(session2 != 0 && session2 != session);
  // The old session's frames are now stale.
  world.feed(keep, now);
  world.drain(now);
  CHECK(world.device_sink.frames.empty());
}

// Stale/duplicate cumulative grants add no credit (usb-protocol.md §3):
// they must not reset the bounded zero-credit recovery ladder. A host that
// keeps sending (0,0) notices must still hit the 3-query cap and
// CONNECTION_STALLED instead of a query every poll interval forever.
void test_bridge_stale_grant_keeps_stall_ladder() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x4444, 10) != 0);

  // A mesh event queued with zero tx credit starts the recovery ladder.
  const std::array<std::uint8_t, 3> msg{{5, 5, 5}};
  world.bridge.on_message(MessageKey{2, MessageId{4004, 1}}, 2,
                          ByteView{msg.data(), msg.size()});

  std::vector<MonotonicMs> query_times;
  std::uint64_t request = 60;
  bool stalled_error = false;
  for (int i = 0; i < 40; ++i) {
    now += 100;
    world.drain(now);
    for (const auto& record : world.device_sink.frames) {
      if (record.frame.kind == FrameKind::Credit) query_times.push_back(now);
      if (record.frame.kind == FrameKind::Error) {
        std::uint64_t counter = 0;
        ByteView opened{};
        if (open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter,
                      opened) &&
            opened.size > 2 &&
            opened.data[1] ==
                static_cast<std::uint8_t>(UsbErrorCode::ConnectionStalled)) {
          stalled_error = true;
        }
      }
    }
    world.device_sink.frames.clear();
    // No-op cumulative grant: absorbed by update(), ceiling unchanged.
    const auto noop = grant_body(0, 0);
    world.feed(host.sealed(FrameKind::Credit, request++,
                           ByteView{noop.data(), noop.size()}), now);
  }
  CHECK(query_times.size() == 3);  // bounded cap reached despite no-op grants
  for (std::size_t i = 1; i < query_times.size(); ++i) {
    CHECK(query_times[i] - query_times[i - 1] >= 500);  // 500ms query spacing
  }
  CHECK(stalled_error);
  CHECK(world.bridge.connection_stalled());
}

// Single-axis and below-threshold grants must not clear the recovery ladder:
// a host raising only the frame ceiling (1,0),(2,0),... while a pending DATA
// still lacks byte credit produces no forward progress, so queries must keep
// their 500ms spacing and reach CONNECTION_STALLED. The ladder is released
// only when the pending frame actually consumes credit on the wire.
void test_bridge_partial_grant_keeps_stall_ladder() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x5555, 10) != 0);

  // A mesh event queued with zero tx credit starts the recovery ladder.
  const std::array<std::uint8_t, 3> msg{{7, 7, 7}};
  world.bridge.on_message(MessageKey{2, MessageId{5005, 1}}, 2,
                          ByteView{msg.data(), msg.size()});

  std::vector<MonotonicMs> query_times;
  std::uint64_t request = 60;
  bool stalled_error = false;
  for (int i = 0; i < 40; ++i) {
    now += 100;
    world.drain(now);
    for (const auto& record : world.device_sink.frames) {
      if (record.frame.kind == FrameKind::Credit) query_times.push_back(now);
      if (record.frame.kind == FrameKind::Error) {
        std::uint64_t counter = 0;
        ByteView opened{};
        if (open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter,
                      opened) &&
            opened.size > 2 &&
            opened.data[1] ==
                static_cast<std::uint8_t>(UsbErrorCode::ConnectionStalled)) {
          stalled_error = true;
        }
      }
    }
    world.device_sink.frames.clear();
    // Frame-axis-only growth; on i==20 also a bytes grant far below the
    // pending frame's decoded length — neither can send it.
    const auto grant = grant_body(static_cast<std::uint64_t>(i + 1),
                                  i == 20 ? 8 : 0);
    world.feed(host.sealed(FrameKind::Credit, request++,
                           ByteView{grant.data(), grant.size()}), now);
  }
  CHECK(query_times.size() == 3);  // bounded cap reached despite rising grants
  for (std::size_t i = 1; i < query_times.size(); ++i) {
    CHECK(query_times[i] - query_times[i - 1] >= 500);  // 500ms query spacing
  }
  CHECK(stalled_error);
  CHECK(world.bridge.connection_stalled());

  // A grant covering the pending frame lets it consume credit — the ladder
  // clears on actual forward progress, not on the grant notice itself.
  world.feed(host.sealed(FrameKind::Credit, request++,
                         ByteView{grant_body(64, 4096).data(), 17}), now);
  world.drain(now);
  CHECK(!world.bridge.connection_stalled());
  bool got_mesh_frame = false;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind == FrameKind::DataFromMesh) got_mesh_frame = true;
  }
  CHECK(got_mesh_frame);
  CHECK(world.bridge.tx_credit().consumed_frames() == 1);
}

// Late nonce binding (issue #34): firmware seeds device_nonce after
// radio-up entropy via the setter; the value must reach the HelloAck wire
// unchanged (attempt counter is still zero at the first HELLO).
void test_bridge_set_device_nonce() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  world.bridge.set_device_nonce(0x1122334455667788ULL);
  std::array<std::uint8_t, 64> hello_body{};
  write_u64(hello_body.data(), 0x9999);
  hello_body[8] = 2;
  hello_body[9] = 2;
  const char* principal = "host-operator";
  hello_body[10] = 13;
  std::memcpy(hello_body.data() + 11, principal, 13);
  world.feed(host.plain(FrameKind::Hello, 0, 50,
                        ByteView{hello_body.data(), 24}), now);
  world.drain(now);
  CHECK(world.device_sink.frames.size() == 1);
  const auto& ack = world.device_sink.frames.back().frame;
  CHECK(ack.kind == FrameKind::HelloAck && ack.body.size == 53);
  CHECK(read_u64(ack.body.data) == 0x1122334455667788ULL);
}

void test_bridge_idempotent_send() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x3333, 40) != 0);

  const auto grant = grant_body(8, 8192);
  world.feed(host.sealed(FrameKind::Credit, 41, ByteView{grant.data(), grant.size()}), now);
  world.drain(now);

  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  std::array<std::uint8_t, 40> inner{};
  write_u64(inner.data(), 7);  // host-chosen idempotency key
  write_u64(inner.data() + 8, 2);
  std::memcpy(inner.data() + 16, payload.data(), payload.size());
  const auto send = host.sealed(FrameKind::DataToMesh, 42,
                                ByteView{inner.data(), 16 + payload.size()});
  world.feed(send, now);
  world.drain(now);
  std::size_t accepted = 0;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind == FrameKind::DeliveryEvent) ++accepted;
  }
  CHECK(accepted >= 1);  // Accepted (+Queued) command receipts
  world.device_sink.frames.clear();

  // Same key + same payload (fresh request id): cached result replayed.
  const std::uint64_t counter_before = host.h2d_counter;
  const auto replay = host.sealed(FrameKind::DataToMesh, 43,
                                  ByteView{inner.data(), 16 + payload.size()});
  CHECK(host.h2d_counter == counter_before + 1);
  world.feed(replay, now);
  world.drain(now);
  bool idempotent_replay = false;
  for (const auto& record : world.device_sink.frames) {
    std::uint64_t counter = 0;
    ByteView opened{};
    if (record.frame.kind != FrameKind::DeliveryEvent) continue;
    CHECK_OK(open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter, opened));
    if (opened.size == 24 && read_u16(opened.data + 21) == ROUTELOOM_REASON_IDEMPOTENT_REPLAY &&
        opened.data[23] == 0) {
      idempotent_replay = true;
    }
  }
  CHECK(idempotent_replay);
  world.device_sink.frames.clear();

  // Same key, different payload -> CONFLICT.
  std::array<std::uint8_t, 40> changed{};
  write_u64(changed.data(), 7);  // same idempotency key
  write_u64(changed.data() + 8, 2);
  const std::array<std::uint8_t, 4> other{{9, 9, 9, 9}};
  std::memcpy(changed.data() + 16, other.data(), other.size());
  world.feed(host.sealed(FrameKind::DataToMesh, 44,
                         ByteView{changed.data(), 16 + other.size()}), now);
  world.drain(now);
  bool conflict = false;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind == FrameKind::Error) {
      std::uint64_t counter = 0;
      ByteView opened{};
      if (open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter,
                    opened) &&
          opened.size > 2 &&
          opened.data[1] == static_cast<std::uint8_t>(UsbErrorCode::Conflict)) {
        conflict = true;
      }
    }
  }
  CHECK(conflict);
}

// Every legal frame in one RX credit window receives its explicit refusal,
// even when all eight replies contend for the four CONTROL slots.
void test_bridge_expired_burst() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x3388, 40) != 0);
  world.bridge.set_mesh(nullptr);
  std::array<std::uint8_t, 17> body{};
  write_u64(body.data() + 8, 2);
  for (std::uint64_t key = 100; key < 117; ++key) {
    write_u64(body.data(), key);
    world.feed(host.sealed(FrameKind::DataToMesh, key,
                          ByteView{body.data(), body.size()}), now);
    now += 1000;
    world.drain(now);
  }
  world.device_sink.frames.clear();
  write_u64(body.data(), 100);
  for (std::uint64_t request = 200; request < 208; ++request) {
    world.feed(host.sealed(FrameKind::DataToMesh, request,
                          ByteView{body.data(), body.size()}), now);
  }
  for (int i = 0; i < 20; ++i) {
    now += 100;
    world.drain(now);
  }
  std::array<unsigned, 8> replies{};
  for (const auto& frame : world.device_sink.frames) {
    if (frame.frame.kind != FrameKind::Error) continue;
    std::uint64_t counter = 0;
    ByteView inner{};
    CHECK_OK(open_body(host.proof.key_d2h, kDirDeviceToHost, frame.frame, counter, inner));
    if (inner.size < 13) continue;
    const auto request = read_u64(inner.data + 2);
    if (request < 200 || request >= 208) continue;
    CHECK(read_u16(inner.data + 10) == ROUTELOOM_REASON_RESULT_EXPIRED);
    ++replies[request - 200];
  }
  for (const auto replies_for_request : replies) CHECK(replies_for_request == 1);
}

void test_bridge_partial_write() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x4444, 50) != 0);
  const auto grant = grant_body(4, 8192);
  world.feed(host.sealed(FrameKind::Credit, 51, ByteView{grant.data(), grant.size()}), now);
  world.drain(now);
  world.device_sink.frames.clear();
  world.stream.max_write = 5;  // every write call trickles 5 bytes

  const std::array<std::uint8_t, 6> msg{{1, 1, 1, 1, 1, 1}};
  world.bridge.on_message(MessageKey{2, MessageId{2002, 7}}, 2,
                          ByteView{msg.data(), msg.size()});
  const std::uint64_t frames_before = world.bridge.tx_credit().consumed_frames();
  for (int i = 0; i < 200 && world.device_sink.frames.empty(); ++i) {
    world.drain(now);
  }
  CHECK(!world.device_sink.frames.empty());
  // The frame took many partial writes but was charged exactly once.
  CHECK(world.bridge.tx_credit().consumed_frames() == frames_before + 1);
  world.stream.max_write = static_cast<std::size_t>(-1);
}

// ---------------------------------------------------- M1 diagnostics (D1d)

// Collects the first HostOps 0x31 reply the device emits: opens the sealed
// frame, verifies the inner head, returns payload offset or 0.
std::size_t diag_reply_at(const HostDriver& host, const CollectSink& sink,
                          std::array<std::uint8_t, 256>& body,
                          std::uint16_t& result) {
  for (const auto& record : sink.frames) {
    if (record.frame.kind != FrameKind::HostOps) continue;
    std::uint64_t counter = 0;
    ByteView opened{};
    if (!open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter,
                   opened)) {
      continue;
    }
    if (opened.size < 4 || opened.data[0] != kHostOpsSchema ||
        opened.data[1] != static_cast<std::uint8_t>(HostOpsSub::DiagnosticResponse)) {
      continue;
    }
    const std::size_t payload_len =
        (static_cast<std::size_t>(opened.data[2]) << 8U) | opened.data[3];
    if (opened.size != 4 + payload_len || payload_len < 12) continue;
    result = (static_cast<std::uint16_t>(opened.data[4]) << 8U) | opened.data[5];
    const std::size_t n = payload_len - 12;
    std::memcpy(body.data(), opened.data + 4 + 12, n);
    body[n] = 0;
    return n;
  }
  return 0;
}

// Builds a sealed 0x30 DiagnosticRequest: inner = schema|sub|len16|
// observer:u64|body.
std::vector<std::uint8_t> diag_request(HostDriver& host, std::uint64_t request,
                                       NodeId observer, ByteView body) {
  std::vector<std::uint8_t> inner(4 + 8 + body.size, 0);
  inner[0] = kHostOpsSchema;
  inner[1] = static_cast<std::uint8_t>(HostOpsSub::DiagnosticRequest);
  inner[2] = static_cast<std::uint8_t>((8 + body.size) >> 8U);
  inner[3] = static_cast<std::uint8_t>(8 + body.size);
  write_u64(inner.data() + 4, observer);
  std::memcpy(inner.data() + 12, body.data, body.size);
  return host.sealed(FrameKind::HostOps, request,
                     ByteView{inner.data(), inner.size()});
}

struct ObservedDiag {
  std::string reason;
  std::uint64_t boot{0};
  std::uint32_t seq{0};
  std::uint64_t dropped{0};
};

// Opens every Diagnostic frame in the sink: inner = peer(8) || flags(1) ||
// reason_len(1) || reason || boot(8) || seq(4) || dropped_total(8).
std::vector<ObservedDiag> collect_diagnostics(const HostDriver& host,
                                              const CollectSink& sink) {
  std::vector<ObservedDiag> out;
  for (const auto& record : sink.frames) {
    if (record.frame.kind != FrameKind::Diagnostic) continue;
    std::uint64_t counter = 0;
    ByteView opened{};
    if (!open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter,
                   opened)) {
      continue;
    }
    CHECK(opened.size >= 10);
    if (opened.size < 10) continue;
    CHECK((opened.data[8] & kDiagFlagHasAccounting) != 0);
    const std::size_t rlen = opened.data[9];
    const std::size_t tail = 10 + rlen;
    CHECK(opened.size == tail + 20);
    if (opened.size != tail + 20) continue;
    ObservedDiag diag;
    diag.reason.assign(reinterpret_cast<const char*>(opened.data + 10), rlen);
    diag.boot = read_u64(opened.data + tail);
    diag.seq = read_u32(opened.data + tail + 8);
    diag.dropped = read_u64(opened.data + tail + 12);
    out.push_back(diag);
  }
  return out;
}

void test_bridge_diagnostic_loss_accounting() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0xD1A6, 80) != 0);
  // No device→host credit yet: 9 diagnostics overfill the 8-slot data
  // queue and the 9th is a counted diagnostic drop, never silent.
  for (int i = 0; i < 9; ++i) {
    char reason[16];
    std::snprintf(reason, sizeof reason, "EVT%d", i);
    world.bridge.on_diagnostic(reason, 2, nullptr);
  }
  CHECK(world.bridge.stats().diagnostics_dropped == 1);
  // Grant credit and drain: the 8 queued diagnostics arrive stamped with
  // (boot, seq, dropped_total).
  const auto grant = grant_body(32, 65536);
  world.feed(host.sealed(FrameKind::Credit, 81,
                         ByteView{grant.data(), grant.size()}),
             now);
  world.drain(now);
  const auto first = collect_diagnostics(host, world.device_sink);
  // Seqs are relative: node start already emitted diagnostics before the
  // handshake drained them; what matters is consecutiveness + stamping.
  CHECK(first.size() == 8);
  for (std::size_t i = 0; i < first.size(); ++i) {
    if (i > 0) CHECK(first[i].seq == first[i - 1].seq + 1);
    CHECK(first[i].dropped == 0);
    CHECK(first[i].boot == 0xB0071D0001ULL);
  }
  // The next diagnostic first emits the loss marker, then itself: the PC
  // sees the gap (the dropped 9th fill) bracketed by an explicit marker.
  world.device_sink.frames.clear();
  world.bridge.on_diagnostic("EVT9", 2, nullptr);
  world.drain(now);
  const auto second = collect_diagnostics(host, world.device_sink);
  CHECK(second.size() == 2);
  if (second.size() == 2 && first.size() == 8) {
    const std::uint32_t base = first.back().seq;
    CHECK(second[0].reason == "DIAG_LOSS");
    CHECK(second[0].seq == base + 2);  // base+1 was the dropped fill
    CHECK(second[0].dropped == 1);
    CHECK(second[1].reason == "EVT9");
    CHECK(second[1].seq == base + 3);
    CHECK(second[1].dropped == 1);
  }
  CHECK(world.bridge.stats().diagnostics_dropped == 1);
}

void test_bridge_diagnostics() {
  World world;
  // Diagnostics must be attached BEFORE the handshake so bit5 lands in the
  // authenticated capability transcript.
  CHECK_OK(world.bridge.attach_diagnostics());
  world.n2.set_telemetry_remote(true);
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x5555, 60) != 0);
  const auto grant = grant_body(16, 32768);
  world.feed(host.sealed(FrameKind::Credit, 61,
                         ByteView{grant.data(), grant.size()}), now);
  world.drain(now);
  world.device_sink.frames.clear();

  auto pump_mesh = [&](int rounds) {
    for (int i = 0; i < rounds; ++i) {
      world.n1.poll(now);
      world.n2.poll(now);
      world.net.flush(now);
      world.drain(now);
      now += 5;
    }
  };

  // 1) Local CapabilitiesQuery (subtype 1, nonce16 + reserved4 = 24 B).
  {
    CapabilitiesQuery cap_query{};
    for (std::size_t i = 0; i < cap_query.nonce.size(); ++i) {
      cap_query.nonce[i] = static_cast<std::uint8_t>(0xA0 + i);
    }
    std::array<std::uint8_t, kCapabilitiesQueryBodySize> query{};
    CHECK_OK(capabilities_query_encode(
        cap_query, MutableByteView{query.data(), query.size()}));
    world.feed(diag_request(host, 62, /*observer=*/1,
                            ByteView{query.data(), query.size()}), now);
    pump_mesh(8);
    std::array<std::uint8_t, 256> body{};
    std::uint16_t result = 0xFFFF;
    const std::size_t n = diag_reply_at(host, world.device_sink, body, result);
    CHECK(n == kCapabilitiesReplyBodySize);
    CHECK(result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
    if (n == kCapabilitiesReplyBodySize) {
      CapabilitiesReply reply{};
      CHECK_OK(capabilities_reply_decode(ByteView{body.data(), n}, reply));
      CHECK(reply.echo_nonce == cap_query.nonce);  // echoed verbatim
      CHECK(reply.node_boot == 7001);               // n1 boot_incarnation
      CHECK((reply.features & kCapLocalTelemetryV1) != 0);
      CHECK((reply.features & kCapForwardV1) != 0);   // relay on + started
      CHECK((reply.features & kCapRemoteTelemetryV1) == 0);  // n1 not opted in
      CHECK((reply.features & kCapTransitFailureV1) != 0);
      CHECK(reply.valid_for_ms == kCapabilitiesValidityMs);
      world.device_sink.frames.clear();
    }
  }

  // 2) Local TelemetryQuery — seed n1's summary for peer 2 with real RX
  //    traffic first (the sim injects V1 -> honest InjectedTest provenance).
  {
    SendOptions opts{};
    MessageId id{};
    const std::array<std::uint8_t, 4> msg{{9, 9, 9, 9}};
    CHECK_OK(world.n2.send(1, ByteView{msg.data(), msg.size()}, opts, now, id));
    pump_mesh(20);

    TelemetryQuery query{};
    query.request_id = 0x1234;
    query.peer = 2;
    query.length_class = kTelemetryPeerSummaryClass;
    std::array<std::uint8_t, kTelemetryQueryBodySize> qbody{};
    CHECK_OK(telemetry_query_encode(
        query, MutableByteView{qbody.data(), qbody.size()}));
    world.feed(diag_request(host, 63, /*observer=*/1,
                            ByteView{qbody.data(), qbody.size()}), now);
    pump_mesh(8);
    std::array<std::uint8_t, 256> body{};
    std::uint16_t result = 0xFFFF;
    const std::size_t n = diag_reply_at(host, world.device_sink, body, result);
    CHECK(n == kTelemetrySnapshotBodySize);
    CHECK(result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
    if (n == kTelemetrySnapshotBodySize) {
      TelemetrySnapshot snap{};
      CHECK_OK(telemetry_snapshot_decode(ByteView{body.data(), n}, snap));
      CHECK(snap.request_id == 0x1234 && snap.observer == 1 && snap.peer == 2);
      CHECK((snap.validity & kTelemetrySourceInjectedTest) != 0);
      world.device_sink.frames.clear();
    }
  }

  // 3) Remote TelemetryQuery: observer=2 crosses the routed lane — the
  //    reply lands on the bridge's DiagnosticSink and resolves the pending
  //    slot under the SAME usb request id.
  {
    TelemetryQuery query{};
    query.request_id = 0xBEEF;
    query.peer = 1;
    query.length_class = kTelemetryPeerSummaryClass;
    std::array<std::uint8_t, kTelemetryQueryBodySize> qbody{};
    CHECK_OK(telemetry_query_encode(
        query, MutableByteView{qbody.data(), qbody.size()}));
    world.feed(diag_request(host, 64, /*observer=*/2,
                            ByteView{qbody.data(), qbody.size()}), now);
    pump_mesh(40);
    std::array<std::uint8_t, 256> body{};
    std::uint16_t result = 0xFFFF;
    const std::size_t n = diag_reply_at(host, world.device_sink, body, result);
    CHECK(n == kTelemetrySnapshotBodySize);
    CHECK(result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
    if (n == kTelemetrySnapshotBodySize) {
      TelemetrySnapshot snap{};
      CHECK_OK(telemetry_snapshot_decode(ByteView{body.data(), n}, snap));
      // The bridge mints the mesh correlation id — the host-supplied
      // 0xBEEF is never forwarded, so a replayed request cannot collide
      // with a live slot (04 §USB correlation).
      CHECK(snap.request_id != 0xBEEF && snap.request_id != 0 &&
            snap.observer == 2 && snap.peer == 1);
      world.device_sink.frames.clear();
    }
  }

  // 4) A remote observer with no route gets an immediate honest NoRoute —
  //    never a pending slot that can only expire.
  {
    TelemetryQuery query{};
    query.request_id = 0x77;
    query.peer = 1;
    query.length_class = kTelemetryPeerSummaryClass;
    std::array<std::uint8_t, kTelemetryQueryBodySize> qbody{};
    CHECK_OK(telemetry_query_encode(
        query, MutableByteView{qbody.data(), qbody.size()}));
    world.feed(diag_request(host, 65, /*observer=*/99,
                            ByteView{qbody.data(), qbody.size()}), now);
    pump_mesh(8);
    std::array<std::uint8_t, 256> body{};
    std::uint16_t result = 0xFFFF;
    diag_reply_at(host, world.device_sink, body, result);
    CHECK(result == static_cast<std::uint16_t>(ConfigOpsResult::NoRoute));
    world.device_sink.frames.clear();
  }

  // 5) Malformed body (short prefix) -> Invalid, not a crash.
  {
    const std::array<std::uint8_t, 2> bad{{1, 3}};
    world.feed(diag_request(host, 66, /*observer=*/1,
                            ByteView{bad.data(), bad.size()}), now);
    pump_mesh(8);
    // 2-byte body fails decode_diagnostic_request's min bound entirely ->
    // ProtocolError Error frame, not a 0x31.
    std::array<std::uint8_t, 256> body{};
    std::uint16_t result = 0xFFFF;
    diag_reply_at(host, world.device_sink, body, result);
    CHECK(result == 0xFFFF);
    world.device_sink.frames.clear();
  }
}

// ------------------------------------------------ node status (node_status_v1)

// Opens every HostOps frame in the sink and returns the inners whose sub
// matches, in wire order, with their frame request ids.
struct OpenedOps {
  std::uint64_t request{0};
  std::vector<std::uint8_t> inner;
};

std::vector<OpenedOps> host_ops_inners(const HostDriver& host,
                                       const CollectSink& sink,
                                       const HostOpsSub sub) {
  std::vector<OpenedOps> out;
  for (const auto& record : sink.frames) {
    if (record.frame.kind != FrameKind::HostOps) continue;
    std::uint64_t counter = 0;
    ByteView opened{};
    if (!open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter,
                   opened)) {
      continue;
    }
    if (opened.size < 2 || opened.data[1] != static_cast<std::uint8_t>(sub)) continue;
    out.push_back(OpenedOps{record.frame.request,
                            std::vector<std::uint8_t>(opened.data, opened.data + opened.size)});
  }
  return out;
}

std::vector<std::uint8_t> node_status_request(HostDriver& host, std::uint64_t request,
                                              NodeId after, std::uint8_t max_entries,
                                              std::uint8_t flags) {
  NodeStatusQuery query{};
  query.after = after;
  query.max_entries = max_entries;
  query.flags = flags;
  std::array<std::uint8_t, kGatewayInnerHeadSize + kNodeStatusQueryPayload> inner{};
  std::size_t n = 0;
  if (!encode_node_status_query(query, MutableByteView{inner.data(), inner.size()}, n)) {
    return {};
  }
  return host.sealed(FrameKind::HostOps, request, ByteView{inner.data(), n});
}

std::vector<NodeEvent> node_events(const HostDriver& host, const CollectSink& sink) {
  std::vector<NodeEvent> events;
  for (const auto& opened : host_ops_inners(host, sink, HostOpsSub::NodeEvent)) {
    NodeEvent event{};
    CHECK(opened.request == 0);  // unsolicited
    CHECK_OK(decode_node_event(ByteView{opened.inner.data(), opened.inner.size()}, event));
    events.push_back(event);
  }
  return events;
}

void test_bridge_node_status() {
  // 1) Not attached: the query is answered honestly Unsupported, and a
  //    malformed query is a ProtocolError Error frame, never a page.
  {
    World world;
    HostDriver host;
    MonotonicMs now = 0;
    CHECK(host_handshake(world, host, now, 0x6161, 70) != 0);
    const auto grant = grant_body(16, 32768);
    world.feed(host.sealed(FrameKind::Credit, 71, ByteView{grant.data(), grant.size()}), now);
    world.drain(now);
    world.device_sink.frames.clear();
    world.feed(node_status_request(host, 72, 0, 16, kNodeStatusQuerySubscribe), now);
    world.drain(now);
    const auto pages = host_ops_inners(host, world.device_sink, HostOpsSub::NodeStatusPage);
    CHECK(pages.size() == 1);
    if (pages.size() == 1) {
      NodeStatusPageHeader header{};
      ByteView entries{};
      CHECK(pages[0].request == 72);
      CHECK_OK(decode_node_status_page(
          ByteView{pages[0].inner.data(), pages[0].inner.size()}, header, entries));
      CHECK(header.result == static_cast<std::uint16_t>(ConfigOpsResult::Unsupported));
      CHECK(header.count == 0 && header.flags == 0);
    }
    CHECK(!world.bridge.node_status_armed());
    world.device_sink.frames.clear();
    // max_entries 0 is malformed.
    std::array<std::uint8_t, 14> bad{{1, 0x40, 0, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    world.feed(host.sealed(FrameKind::HostOps, 73, ByteView{bad.data(), bad.size()}), now);
    world.drain(now);
    bool error = false;
    for (const auto& record : world.device_sink.frames) {
      error = error || record.frame.kind == FrameKind::Error;
    }
    CHECK(error);
    CHECK(host_ops_inners(host, world.device_sink, HostOpsSub::NodeStatusPage).empty());
    // 0x41/0x42 from the host are direction violations.
    std::array<std::uint8_t, 4> wrong{{1, 0x42, 0, 0}};
    world.device_sink.frames.clear();
    world.feed(host.sealed(FrameKind::HostOps, 74, ByteView{wrong.data(), wrong.size()}), now);
    world.drain(now);
    error = false;
    for (const auto& record : world.device_sink.frames) {
      error = error || record.frame.kind == FrameKind::Error;
    }
    CHECK(error);
  }

  // 2) Attached: paging, arming, bounded event bursts, session scoping.
  World world;
  CHECK_OK(world.bridge.attach_node_status());
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x6262, 80) != 0);
  const auto grant = grant_body(256, 1u << 20);
  world.feed(host.sealed(FrameKind::Credit, 81, ByteView{grant.data(), grant.size()}), now);
  world.drain(now);
  world.device_sink.frames.clear();
  for (NodeId id = 10; id < 30; ++id) CHECK_OK(world.n1.add_neighbor(id, 2, now));

  // Walk everything in pages of 8 without subscribing.
  std::vector<NodeId> walked;
  NodeId cursor = 0;
  std::uint64_t request = 82;
  for (int page = 0; page < 8; ++page) {
    world.device_sink.frames.clear();
    world.feed(node_status_request(host, request, cursor, 8, 0), now);
    world.drain(now);
    const auto pages = host_ops_inners(host, world.device_sink, HostOpsSub::NodeStatusPage);
    CHECK(pages.size() == 1);
    if (pages.size() != 1) break;
    CHECK(pages[0].request == request);
    ++request;
    NodeStatusPageHeader header{};
    ByteView entries{};
    CHECK_OK(decode_node_status_page(
        ByteView{pages[0].inner.data(), pages[0].inner.size()}, header, entries));
    CHECK((header.flags & kNodeStatusPageArmed) == 0);
    for (std::size_t i = 0; i < header.count; ++i) {
      NodeStatus entry{};
      CHECK_OK(decode_node_status_entry(
          ByteView{entries.data + i * kNodeStatusEntrySize, kNodeStatusEntrySize}, entry));
      CHECK(entry.neighbor_active() && entry.reachable() &&
            (entry.flags & kNodeStatusDirect) != 0);
      walked.push_back(entry.node);
    }
    cursor = header.next_after;
    if ((header.flags & kNodeStatusPageMore) == 0) break;
  }
  std::vector<NodeId> expected{2};
  for (NodeId id = 10; id < 30; ++id) expected.push_back(id);
  CHECK(walked == expected);

  // Unarmed: mesh changes produce no events.
  world.device_sink.frames.clear();
  CHECK_OK(world.n1.remove_neighbor(10, now));
  now += 1000;
  world.drain(now);
  CHECK(node_events(host, world.device_sink).empty());

  // Arm with a one-entry page: the page reports ARMED and event_seq 0.
  world.device_sink.frames.clear();
  world.feed(node_status_request(host, request++, 0, 1, kNodeStatusQuerySubscribe), now);
  world.drain(now);
  CHECK(world.bridge.node_status_armed());
  {
    const auto pages = host_ops_inners(host, world.device_sink, HostOpsSub::NodeStatusPage);
    CHECK(pages.size() == 1);
    if (!pages.empty()) {
      NodeStatusPageHeader header{};
      ByteView entries{};
      CHECK_OK(decode_node_status_page(
          ByteView{pages[0].inner.data(), pages[0].inner.size()}, header, entries));
      CHECK(header.count == 1 && (header.flags & kNodeStatusPageArmed) != 0 &&
            (header.flags & kNodeStatusPageMore) != 0 && header.event_seq == 0);
    }
  }

  // Leave: NeighborDown + RouteDown for node 11.
  world.device_sink.frames.clear();
  CHECK_OK(world.n1.remove_neighbor(11, now));
  now += 300;
  world.drain(now);
  auto events = node_events(host, world.device_sink);
  CHECK(events.size() == 2);
  if (events.size() == 2) {
    CHECK(events[0].sequence == 1 && events[0].kind == NodeEventKind::NeighborDown);
    CHECK(events[1].sequence == 2 && events[1].kind == NodeEventKind::RouteDown);
    CHECK(events[0].status.node == 11 && !events[1].status.reachable());
  }

  // A burst of joins drains kNodeEventBurst events per monitor pass, in
  // contiguous sequence order, without ever dropping one.
  world.device_sink.frames.clear();
  for (NodeId id = 100; id < 106; ++id) CHECK_OK(world.n1.add_neighbor(id, 3, now));
  now += 300;
  world.drain(now);
  CHECK(node_events(host, world.device_sink).size() == 4);
  for (int i = 0; i < 4; ++i) {
    now += 300;
    world.drain(now);
  }
  events = node_events(host, world.device_sink);
  CHECK(events.size() == 12);
  for (std::size_t i = 0; i < events.size(); ++i) {
    CHECK(events[i].sequence == 3 + i);
    CHECK(events[i].kind == (i % 2 == 0 ? NodeEventKind::NeighborUp : NodeEventKind::RouteUp));
    CHECK(events[i].status.node == 100 + i / 2);
    CHECK(events[i].status.link_cost == 3);
  }
  CHECK(world.bridge.stats().node_events == 14);

  // A resync page reports the sequence the device reached.
  world.device_sink.frames.clear();
  world.feed(node_status_request(host, request++, 0, 16, 0), now);
  world.drain(now);
  {
    const auto pages = host_ops_inners(host, world.device_sink, HostOpsSub::NodeStatusPage);
    CHECK(pages.size() == 1);
    if (!pages.empty()) {
      NodeStatusPageHeader header{};
      ByteView entries{};
      CHECK_OK(decode_node_status_page(
          ByteView{pages[0].inner.data(), pages[0].inner.size()}, header, entries));
      CHECK(header.event_seq == 14 && header.count == 16);
    }
  }

  // A new session starts silent: the baseline belonged to the old one.
  world.device_sink.frames.clear();
  HostDriver second;
  CHECK(host_handshake(world, second, now, 0x6363, 90) != 0);
  CHECK(!world.bridge.node_status_armed());
  world.feed(second.sealed(FrameKind::Credit, 91, ByteView{grant.data(), grant.size()}), now);
  CHECK_OK(world.n1.remove_neighbor(12, now));
  now += 1000;
  world.drain(now);
  CHECK(node_events(second, world.device_sink).empty());
}

// ------------------------------------------------- observation (0x70-0x72)

class TestObservationSource final : public ObservationSource {
 public:
  explicit TestObservationSource(const MeshNode& mesh) : mesh_(mesh) {}

  JoinMilestones milestones{};
  bool fail_fills{false};

  bool fill_system(MonotonicMs now_ms, ObservationSystem& out) const noexcept override {
    if (fail_fills) return false;
    fill_observation_system(0xB0071D0001ULL, now_ms, port_, kPowerRunning,
                            kCoordModeDev, kProfileDevRam, out);
    return true;
  }
  bool fill_tables(MonotonicMs now_ms, ObservationTables& out) const noexcept override {
    if (fail_fills) return false;
    fill_observation_tables(mesh_, now_ms, 0, 32, 0, 128, out);
    return true;
  }
  bool fill_milestones(MonotonicMs, JoinMilestones& out) const noexcept override {
    if (fail_fills) return false;
    out = milestones;
    return true;
  }
  bool fill_summary(MonotonicMs now_ms, ObservationSummary& out) const noexcept override {
    if (fail_fills) return false;
    fill_observation_summary(mesh_, now_ms, 0, out);
    return true;
  }
  std::size_t route_detail_page(NodeId after, RouteDetailEntry* out, std::size_t capacity,
                                MonotonicMs now_ms, bool& more) const noexcept override {
    if (fail_fills) {
      more = false;
      return 0;
    }
    return mesh_.route_detail_page(after, out, capacity, now_ms, more);
  }
  bool route_detail_exact(NodeId destination, MonotonicMs now_ms,
                          RouteDetailEntry& out) const noexcept override {
    if (fail_fills) return false;
    return mesh_.route_detail(destination, now_ms, out);
  }
  std::size_t neighbor_detail_page(NodeId after, NeighborDetailEntry* out, std::size_t capacity,
                                   MonotonicMs now_ms, bool& more) const noexcept override {
    if (fail_fills) {
      more = false;
      return 0;
    }
    return ::routeloom::neighbor_detail_page(mesh_, discovery_, after, out, capacity, now_ms,
                                             more);
  }
  bool neighbor_detail_exact(NodeId peer, MonotonicMs now_ms,
                             NeighborDetailEntry& out) const noexcept override {
    if (fail_fills) return false;
    return ::routeloom::neighbor_detail_exact(mesh_, discovery_, peer, now_ms, out);
  }

 private:
  const MeshNode& mesh_;
  const NeighborDiscovery* discovery_{nullptr};
  NullSystemHealthPort port_;
};

std::vector<std::uint8_t> observation_request(HostDriver& host, std::uint64_t request,
                                              ObservationSection section, NodeId after,
                                              std::uint8_t max_entries, std::uint8_t flags) {
  ObservationQuery query{};
  query.section = section;
  query.after = after;
  query.max_entries = max_entries;
  query.flags = flags;
  std::array<std::uint8_t, kGatewayInnerHeadSize + kObservationQueryPayload> inner{};
  std::size_t n = 0;
  if (!encode_observation_query(query, MutableByteView{inner.data(), inner.size()}, n)) {
    return {};
  }
  return host.sealed(FrameKind::HostOps, request, ByteView{inner.data(), n});
}

std::vector<ObservationEvent> observation_events(const HostDriver& host, const CollectSink& sink) {
  std::vector<ObservationEvent> events;
  for (const auto& opened : host_ops_inners(host, sink, HostOpsSub::ObservationEvent)) {
    ObservationEvent event{};
    CHECK(opened.request == 0);  // unsolicited
    CHECK_OK(decode_observation_event(ByteView{opened.inner.data(), opened.inner.size()}, event));
    events.push_back(event);
  }
  return events;
}

void test_bridge_observation() {
  // 1) Not attached: Unsupported pages, malformed queries are Error frames,
  //    and 0x71/0x72 from the host are direction violations.
  {
    World world;
    HostDriver host;
    MonotonicMs now = 0;
    CHECK(host_handshake(world, host, now, 0x7171, 70) != 0);
    const auto grant = grant_body(16, 32768);
    world.feed(host.sealed(FrameKind::Credit, 71, ByteView{grant.data(), grant.size()}), now);
    world.drain(now);
    world.device_sink.frames.clear();
    world.feed(observation_request(host, 72, ObservationSection::System, 0, 8, 0), now);
    world.drain(now);
    const auto pages = host_ops_inners(host, world.device_sink, HostOpsSub::ObservationPage);
    CHECK(pages.size() == 1);
    if (pages.size() == 1) {
      ObservationPageHeader header{};
      ByteView body{};
      CHECK(pages[0].request == 72);
      CHECK_OK(decode_observation_page(
          ByteView{pages[0].inner.data(), pages[0].inner.size()}, header, body));
      CHECK(header.result == static_cast<std::uint16_t>(ConfigOpsResult::Unsupported));
      CHECK(header.section == ObservationSection::System);
      CHECK(header.count == 0 && body.size == 0);
    }
    CHECK(!world.bridge.observation_armed());
    world.device_sink.frames.clear();
    // Section 9 is malformed.
    std::array<std::uint8_t, 16> bad{{1, 0x70, 0, 12, 9, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
    world.feed(host.sealed(FrameKind::HostOps, 73, ByteView{bad.data(), bad.size()}), now);
    world.drain(now);
    bool error = false;
    for (const auto& record : world.device_sink.frames) {
      error = error || record.frame.kind == FrameKind::Error;
    }
    CHECK(error);
    CHECK(host_ops_inners(host, world.device_sink, HostOpsSub::ObservationPage).empty());
    std::array<std::uint8_t, 4> wrong{{1, 0x72, 0, 0}};
    world.device_sink.frames.clear();
    world.feed(host.sealed(FrameKind::HostOps, 74, ByteView{wrong.data(), wrong.size()}), now);
    world.drain(now);
    error = false;
    for (const auto& record : world.device_sink.frames) {
      error = error || record.frame.kind == FrameKind::Error;
    }
    CHECK(error);
  }

  // 2) Attached: every section serves, pages walk, events flow on change.
  World world;
  TestObservationSource source(world.n1);
  CHECK_OK(world.bridge.attach_observation(source));
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x7272, 80) != 0);
  const auto grant = grant_body(256, 1u << 20);
  world.feed(host.sealed(FrameKind::Credit, 81, ByteView{grant.data(), grant.size()}), now);
  world.drain(now);
  world.device_sink.frames.clear();
  for (NodeId id = 10; id < 13; ++id) CHECK_OK(world.n1.add_neighbor(id, 2, now));
  std::uint64_t request = 82;

  // The decoded body borrows the opened inners; copy it out before the
  // inners vector dies with this lambda's scope. Each query advances the
  // clock one control-refill step: every answer carries an rx-grant control
  // frame, and the bridge's TX token bucket (burst 4, 1 per 100 ms) would
  // otherwise head-of-line-block the data queue behind an unemittable
  // grant — the same pacing the node-status test gets from its now += 1000.
  const auto query_page = [&](ObservationSection section, NodeId after, std::uint8_t max,
                              std::uint8_t flags, ObservationPageHeader& header,
                              std::vector<std::uint8_t>& body_bytes) {
    now += 100;
    world.device_sink.frames.clear();
    world.feed(observation_request(host, request++, section, after, max, flags), now);
    world.drain(now);
    const auto pages = host_ops_inners(host, world.device_sink, HostOpsSub::ObservationPage);
    CHECK(pages.size() == 1);
    if (pages.size() != 1) return false;
    ByteView inner_body{};
    CHECK_OK(decode_observation_page(
        ByteView{pages[0].inner.data(), pages[0].inner.size()}, header, inner_body));
    body_bytes.assign(inner_body.data, inner_body.data + inner_body.size);
    return true;
  };
  const auto body_view = [](const std::vector<std::uint8_t>& bytes) {
    return ByteView{bytes.data(), bytes.size()};
  };

  // System singleton: boot lease, uptime, unknown heap on the null port.
  {
    ObservationPageHeader header{};
    std::vector<std::uint8_t> body_bytes{};
    CHECK(query_page(ObservationSection::System, 0, 8, 0, header, body_bytes));
    CHECK(header.result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
    CHECK(header.count == 1 && header.revision == 0);
    CHECK(header.boot_id == 0xB0071D0001ULL);
    ObservationSystem system{};
    CHECK_OK(decode_observation_system(body_view(body_bytes), system));
    CHECK(system.uptime_ms == now);
    CHECK(system.heap_free_bytes == kHeapBytesUnknown);
    CHECK(system.reset_code == kResetUnknown);
    CHECK(system.power_mode == kPowerRunning);
    CHECK(system.coord_mode == kCoordModeDev);
  }

  // Tables singleton: counts agree with the node behind the bridge.
  {
    ObservationPageHeader header{};
    std::vector<std::uint8_t> body_bytes{};
    CHECK(query_page(ObservationSection::Tables, 0, 8, 0, header, body_bytes));
    ObservationTables tables{};
    CHECK_OK(decode_observation_tables(body_view(body_bytes), tables));
    CHECK(tables.neighbor_active == 4);  // node 2 plus 10..12
    CHECK(tables.neighbor_total == 4);
    CHECK(tables.route_total == 4);
    CHECK(tables.link_cap == 32 && tables.end_cap == 128);
    CHECK(tables.dedup_cap == kDedupCapacity);
    CHECK(tables.tx_cap == MeshNode::tx_queue_capacity());
  }

  // Milestones singleton: the canned record round-trips; the all-unknown
  // tuple packs to zero, so the generation starts at 0.
  {
    ObservationPageHeader header{};
    std::vector<std::uint8_t> body_bytes{};
    CHECK(query_page(ObservationSection::Milestones, 0, 8, 0, header, body_bytes));
    CHECK(header.revision == 0);
    JoinMilestones milestones{};
    CHECK_OK(decode_observation_milestones(body_view(body_bytes), milestones));
    CHECK(milestones.flags == 0);
    CHECK(milestones.join_started_age_ms == kMilestoneAgeUnknown);
  }

  // Summary singleton: digests plus counts; revision is the route digest.
  std::uint32_t route_digest = 0;
  std::uint32_t neighbor_digest = 0;
  {
    ObservationPageHeader header{};
    std::vector<std::uint8_t> body_bytes{};
    CHECK(query_page(ObservationSection::Summary, 0, 8, 0, header, body_bytes));
    ObservationSummary summary{};
    CHECK_OK(decode_observation_summary(body_view(body_bytes), summary));
    CHECK(summary.neighbor_active == 4);
    CHECK(summary.route_total == 4);
    CHECK(summary.milestone_gen == 0);
    CHECK(header.revision == summary.route_digest);
    route_digest = summary.route_digest;
    neighbor_digest = summary.neighbor_digest;
  }

  // Routes pages walk the table ascending with MORE; revision matches.
  {
    std::vector<NodeId> walked;
    NodeId cursor = 0;
    for (int page = 0; page < 4; ++page) {
      ObservationPageHeader header{};
      std::vector<std::uint8_t> body_bytes{};
      CHECK(query_page(ObservationSection::Routes, cursor, 2, 0, header, body_bytes));
      CHECK(header.revision == route_digest);
      const ByteView body = body_view(body_bytes);
      for (std::size_t i = 0; i < header.count; ++i) {
        RouteDetailEntry entry{};
        CHECK_OK(decode_observation_route_entry(
            ByteView{body.data + i * kObservationRouteEntrySize, kObservationRouteEntrySize},
            entry));
        CHECK(walked.empty() || entry.destination > walked.back());
        CHECK(entry.valid && entry.next_hop == entry.destination);
        CHECK(entry.remaining_ms > 0);
        walked.push_back(entry.destination);
      }
      cursor = header.next_after;
      if ((header.flags & kObservationPageMore) == 0) break;
    }
    CHECK((walked == std::vector<NodeId>{2, 10, 11, 12}));
  }

  // EXACT: one destination, present or honestly absent.
  {
    ObservationPageHeader header{};
    std::vector<std::uint8_t> body_bytes{};
    CHECK(query_page(ObservationSection::Routes, 11, 8, kObservationQueryExact, header, body_bytes));
    CHECK(header.count == 1 && (header.flags & kObservationPageMore) == 0);
    RouteDetailEntry entry{};
    CHECK_OK(decode_observation_route_entry(body_view(body_bytes), entry));
    CHECK(entry.destination == 11 && entry.valid);
    CHECK(query_page(ObservationSection::Routes, 99, 8, kObservationQueryExact, header, body_bytes));
    CHECK(header.result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
    CHECK(header.count == 0 && (header.flags & kObservationPageMore) == 0);
  }

  // Neighbors pages walk the neighbor table ascending with MORE; revision
  // is the neighbor digest; without discovery, phase/lease read unknown.
  {
    std::vector<NodeId> walked;
    NodeId cursor = 0;
    for (int page = 0; page < 4; ++page) {
      ObservationPageHeader header{};
      std::vector<std::uint8_t> body_bytes{};
      CHECK(query_page(ObservationSection::Neighbors, cursor, 2, 0, header, body_bytes));
      CHECK(header.revision == neighbor_digest);
      const ByteView body = body_view(body_bytes);
      for (std::size_t i = 0; i < header.count; ++i) {
        NeighborDetailEntry entry{};
        CHECK_OK(decode_observation_neighbor_entry(
            ByteView{body.data + i * kObservationNeighborEntrySize, kObservationNeighborEntrySize},
            entry));
        CHECK(walked.empty() || entry.peer > walked.back());
        CHECK((entry.flags & kNeighborActive) != 0);
        CHECK(entry.link_cost != kInfiniteRouteMetric);
        CHECK(entry.phase == kNeighborPhaseUnknown);
        CHECK(entry.lease_remaining_ms == kNeighborAgeUnknown);
        walked.push_back(entry.peer);
      }
      cursor = header.next_after;
      if ((header.flags & kObservationPageMore) == 0) break;
    }
    CHECK((walked == std::vector<NodeId>{2, 10, 11, 12}));
  }

  // EXACT: one neighbor, present or honestly absent.
  {
    ObservationPageHeader header{};
    std::vector<std::uint8_t> body_bytes{};
    CHECK(query_page(ObservationSection::Neighbors, 11, 8, kObservationQueryExact, header,
                     body_bytes));
    CHECK(header.count == 1 && (header.flags & kObservationPageMore) == 0);
    NeighborDetailEntry entry{};
    CHECK_OK(decode_observation_neighbor_entry(body_view(body_bytes), entry));
    CHECK(entry.peer == 11);
    CHECK((entry.flags & kNeighborActive) != 0);
    CHECK(query_page(ObservationSection::Neighbors, 99, 8, kObservationQueryExact, header,
                     body_bytes));
    CHECK(header.result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
    CHECK(header.count == 0 && (header.flags & kObservationPageMore) == 0);
  }

  // A failing source answers Indeterminate, never a fabricated page.
  {
    source.fail_fills = true;
    ObservationPageHeader header{};
    std::vector<std::uint8_t> body_bytes{};
    CHECK(query_page(ObservationSection::Tables, 0, 8, 0, header, body_bytes));
    CHECK(header.result == static_cast<std::uint16_t>(ConfigOpsResult::Indeterminate));
    CHECK(header.count == 0 && body_bytes.empty());
    source.fail_fills = false;
  }

  // Subscribe, then change the topology: one 0x72 names both moved halves.
  CHECK(!world.bridge.observation_armed());
  {
    ObservationPageHeader header{};
    std::vector<std::uint8_t> body_bytes{};
    CHECK(query_page(ObservationSection::Routes, 0, 8, kObservationQuerySubscribe, header, body_bytes));
    CHECK((header.flags & kObservationPageArmed) != 0);
  }
  CHECK(world.bridge.observation_armed());
  world.device_sink.frames.clear();
  CHECK_OK(world.n1.add_neighbor(20, 2, now));
  now += 300;
  world.drain(now);
  {
    const auto events = observation_events(host, world.device_sink);
    CHECK(events.size() == 1);
    if (events.size() == 1) {
      CHECK(events[0].sequence == 1);
      CHECK(events[0].kind == kObservationEventTopology);
      CHECK(events[0].mask ==
            (kObservationEventMaskNeighbors | kObservationEventMaskRoutes));
      CHECK(events[0].boot_id == 0xB0071D0001ULL);
    }
  }

  // A milestone flip emits kind 2 with the bumped generation (sequence 2:
  // the topology event above was sequence 1 — the sink is the emission
  // count now that the bridge keeps no 0x72 counters).
  world.device_sink.frames.clear();
  source.milestones.mode = kCoordModeMember;
  source.milestones.flags = kMilestoneAdopted;
  source.milestones.attempts = 1;
  now += 300;
  world.drain(now);
  {
    const auto events = observation_events(host, world.device_sink);
    CHECK(events.size() == 1);
    if (events.size() == 1) {
      CHECK(events[0].sequence == 2);
      CHECK(events[0].kind == kObservationEventMilestone);
      CHECK(events[0].revision == 1);
    }
  }

  // A new session starts silent: the subscription belonged to the old one.
  world.device_sink.frames.clear();
  HostDriver second;
  CHECK(host_handshake(world, second, now, 0x7373, 100) != 0);
  CHECK(!world.bridge.observation_armed());
  world.feed(second.sealed(FrameKind::Credit, 101, ByteView{grant.data(), grant.size()}), now);
  CHECK_OK(world.n1.remove_neighbor(20, now));
  now += 1000;
  world.drain(now);
  CHECK(observation_events(second, world.device_sink).empty());
}

// Remote observation over the 0x30 tunnel: the gateway forwards the
// subtype-7 query to the observer and relays the subtype-8 answer under
// the SAME usb request id (the mesh correlation id stays bridge-minted
// and opaque to the host).
void test_bridge_remote_observation() {
  World world;
  CHECK_OK(world.bridge.attach_diagnostics());
  TestObservationSource source_n2(world.n2);
  CHECK_OK(world.n2.set_observation_source(&source_n2));
  CHECK_OK(world.n2.set_observation_remote(true));
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x0B52, 90) != 0);
  const auto grant = grant_body(256, 1u << 20);
  world.feed(host.sealed(FrameKind::Credit, 91,
                         ByteView{grant.data(), grant.size()}),
             now);
  world.drain(now);
  world.device_sink.frames.clear();

  auto pump_mesh = [&](int rounds) {
    for (int i = 0; i < rounds; ++i) {
      world.n1.poll(now);
      world.n2.poll(now);
      world.net.flush(now);
      world.drain(now);
      now += 5;
    }
  };

  // 1) Remote summary query: observer=2 answers from its wired source.
  {
    RemoteObservationQuery query{};
    query.request_id = 0xBEEF;
    query.section = ObservationSection::Summary;
    query.max_entries = 1;
    std::array<std::uint8_t, kRemoteObservationQueryBodySize> qbody{};
    CHECK_OK(remote_observation_query_encode(
        query, MutableByteView{qbody.data(), qbody.size()}));
    world.feed(diag_request(host, 92, /*observer=*/2,
                            ByteView{qbody.data(), qbody.size()}),
               now);
    pump_mesh(60);
    std::array<std::uint8_t, 256> body{};
    std::uint16_t result = 0xFFFF;
    const std::size_t n = diag_reply_at(host, world.device_sink, body, result);
    CHECK(result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
    CHECK(n >= kRemoteObservationSnapshotHeadSize);
    if (n >= kRemoteObservationSnapshotHeadSize) {
      RemoteObservationSnapshot snap{};
      CHECK_OK(remote_observation_snapshot_decode(ByteView{body.data(), n}, snap));
      CHECK(snap.request_id != 0xBEEF && snap.request_id != 0);
      CHECK(snap.observer == 2);
      CHECK(snap.section == ObservationSection::Summary && snap.count == 1);
      ObservationSummary summary{};
      CHECK_OK(decode_observation_summary(
          ByteView{snap.body.data(), snap.body_size}, summary));
      CHECK(snap.revision == summary.route_digest);
      world.device_sink.frames.clear();
    }
  }

  // 2) Opt-in off: n2 without the remote flag answers Denied (policy,
  // not silence) — the host sees the same reason space end to end.
  {
    CHECK_OK(world.n2.set_observation_remote(false));
    RemoteObservationQuery query{};
    query.request_id = 0xDEAD;
    query.section = ObservationSection::System;
    query.max_entries = 1;
    std::array<std::uint8_t, kRemoteObservationQueryBodySize> qbody{};
    CHECK_OK(remote_observation_query_encode(
        query, MutableByteView{qbody.data(), qbody.size()}));
    world.feed(diag_request(host, 93, /*observer=*/2,
                            ByteView{qbody.data(), qbody.size()}),
               now);
    pump_mesh(60);
    std::array<std::uint8_t, 256> body{};
    std::uint16_t result = 0xFFFF;
    const std::size_t n = diag_reply_at(host, world.device_sink, body, result);
    CHECK(result == static_cast<std::uint16_t>(ConfigOpsResult::Ok));
    CHECK(n == kDiagnosticRejectBodySize);
    if (n == kDiagnosticRejectBodySize) {
      DiagnosticReject rej{};
      CHECK_OK(diagnostic_reject_decode(ByteView{body.data(), n}, rej));
      CHECK(rej.reason == DiagnosticRejectReason::Denied && rej.observer == 2);
      world.device_sink.frames.clear();
    }
  }

  // 3) A remote observer with no route gets an immediate honest NoRoute.
  {
    RemoteObservationQuery query{};
    query.request_id = 0x77;
    query.section = ObservationSection::System;
    query.max_entries = 1;
    std::array<std::uint8_t, kRemoteObservationQueryBodySize> qbody{};
    CHECK_OK(remote_observation_query_encode(
        query, MutableByteView{qbody.data(), qbody.size()}));
    world.feed(diag_request(host, 94, /*observer=*/99,
                            ByteView{qbody.data(), qbody.size()}),
               now);
    pump_mesh(8);
    std::array<std::uint8_t, 256> body{};
    std::uint16_t result = 0xFFFF;
    diag_reply_at(host, world.device_sink, body, result);
    CHECK(result == static_cast<std::uint16_t>(ConfigOpsResult::NoRoute));
    world.device_sink.frames.clear();
  }
}

struct EvidenceObserver final : NodeObserver {
  std::vector<DeliveryAssurance> evidence;
  void on_message(const MessageKey&, NodeId, ByteView) noexcept override {}
  void on_message(const MessageKey&, NodeId, ByteView,
                  const DeliveryAssurance& assurance) noexcept override {
    evidence.push_back(assurance);
  }
  void on_delivery(const DeliveryResult&) noexcept override {}
  void on_diagnostic(const char*, NodeId, const MessageId*) noexcept override {}
};

void test_node_delivery_carries_assurance() {
  // A bound-destination delivery arrives with the open_end verdict: the
  // origin is verified under the sender's stamped end_epoch.
  SimNetwork net;
  TestSecurity sec1, sec2;
  CapturingObserver obs1;
  EvidenceObserver obs2;
  SimRadio r1(net, 1), r2(net, 2);
  SimReplyPort p1(r1, 1, 1), p2(r2, 2, 1);
  MeshNode n1(World::node_config(1, 7001), r1, sec1, obs1);
  MeshNode n2(World::node_config(2, 2002), r2, sec2, obs2);
  (void)n1.set_reply_peer_port(&p1);
  (void)n2.set_reply_peer_port(&p2);
  net.register_node(1, &n1);
  net.register_node(2, &n2);
  net.register_reply_port(1, &p1);
  net.register_reply_port(2, &p2);
  net.connect(1, 2);
  MonotonicMs now = 0;
  n1.start(now);
  n2.start(now);
  n1.add_neighbor(2, 1, now);
  n2.add_neighbor(1, 1, now);
  auto tick = [&] {
    n1.poll(now);
    n2.poll(now);
    net.flush(now);
  };
  for (int i = 0; i < 20; ++i) {
    now += 5;
    tick();
  }
  const std::array<std::uint8_t, 3> msg{{7, 7, 7}};
  MessageId id{};
  CHECK_OK(n1.send(2, ByteView{msg.data(), msg.size()}, SendOptions{}, now, id));
  for (int step = 0; step < 200 && obs2.evidence.empty(); ++step) {
    now += 5;
    tick();
  }
  CHECK(obs2.evidence.size() == 1);
  if (!obs2.evidence.empty()) {
    CHECK(obs2.evidence[0].origin_verified);
    CHECK(obs2.evidence[0].site_epoch == 1);  // default stamped end_epoch
  }
}

// Unseals the first DataFromMesh in the sink into body/flags; false when
// none is present.
bool first_ingress(const HostDriver& host, CollectSink& sink,
                   std::vector<std::uint8_t>& body, std::uint16_t& flags) {
  for (const auto& record : sink.frames) {
    if (record.frame.kind != FrameKind::DataFromMesh) continue;
    std::uint64_t counter = 0;
    ByteView inner{};
    if (!open_body(host.proof.key_d2h, kDirDeviceToHost, record.frame, counter,
                   inner)) {
      return false;
    }
    flags = record.frame.flags;
    body.assign(inner.data, inner.data + inner.size);
    return true;
  }
  return false;
}

void test_bridge_rx_assurance() {
  // 1) No profile: 0x08 answers Unsupported and evidence deliveries stay
  // legacy (no flag, no tail).
  {
    World world;
    HostDriver host;
    MonotonicMs now = 0;
    CHECK(host_handshake(world, host, now, 0xA881, 100) != 0);
    const auto grant = grant_body(256, 1u << 20);
    world.feed(host.sealed(FrameKind::Credit, 101,
                           ByteView{grant.data(), grant.size()}),
               now);
    world.drain(now);
    world.device_sink.frames.clear();
    const std::array<std::uint8_t, 2> enable{{1, 0x08}};
    world.feed(host.sealed(FrameKind::HostOps, 102,
                           ByteView{enable.data(), enable.size()}),
               now);
    world.drain(now);
    const auto replies =
        host_ops_inners(host, world.device_sink, HostOpsSub::RxAssuranceEnable);
    CHECK(replies.size() == 1);
    if (replies.size() == 1) {
      RxAssuranceResponse response{};
      CHECK_OK(decode_rx_assurance_response(
          ByteView{replies[0].inner.data(), replies[0].inner.size()},
          response));
      CHECK(response.result == HostOpsResult::Unsupported);
    }
    CHECK(!world.bridge.rx_assurance_enabled());
    world.device_sink.frames.clear();
    const std::array<std::uint8_t, 3> msg{{9, 9, 9}};
    DeliveryAssurance assurance{};
    assurance.origin_verified = true;
    assurance.site_epoch = 7;
    world.bridge.on_message(MessageKey{2, MessageId{2002, 1}}, 2,
                            ByteView{msg.data(), msg.size()}, assurance);
    world.drain(now);
    std::vector<std::uint8_t> body;
    std::uint16_t flags = 0xFFFF;
    CHECK(first_ingress(host, world.device_sink, body, flags));
    CHECK(flags == 0);
    CHECK(body.size() == 20 + 3);
  }

  // 2) With a profile: 0x08 enables, evidence deliveries are flagged +
  // tailed, and the proving-nothing form stays legacy.
  {
    World world;
    HostDriver host;
    MonotonicMs now = 0;
    CHECK_OK(world.bridge.set_rx_assurance_profile(kProfileLegacyFixture));
    CHECK(host_handshake(world, host, now, 0xA882, 110) != 0);
    const auto grant = grant_body(256, 1u << 20);
    world.feed(host.sealed(FrameKind::Credit, 111,
                           ByteView{grant.data(), grant.size()}),
               now);
    world.drain(now);
    world.device_sink.frames.clear();
    const std::array<std::uint8_t, 2> enable{{1, 0x08}};
    world.feed(host.sealed(FrameKind::HostOps, 112,
                           ByteView{enable.data(), enable.size()}),
               now);
    world.drain(now);
    const auto replies =
        host_ops_inners(host, world.device_sink, HostOpsSub::RxAssuranceEnable);
    CHECK(replies.size() == 1);
    if (replies.size() == 1) {
      RxAssuranceResponse response{};
      CHECK_OK(decode_rx_assurance_response(
          ByteView{replies[0].inner.data(), replies[0].inner.size()},
          response));
      CHECK(response.result == HostOpsResult::Ok);
    }
    CHECK(world.bridge.rx_assurance_enabled());
    world.device_sink.frames.clear();
    const std::array<std::uint8_t, 3> msg{{9, 9, 9}};
    DeliveryAssurance assurance{};
    assurance.origin_verified = true;
    assurance.site_epoch = 7;
    world.bridge.on_message(MessageKey{2, MessageId{2002, 1}}, 2,
                            ByteView{msg.data(), msg.size()}, assurance);
    world.drain(now);
    std::vector<std::uint8_t> body;
    std::uint16_t flags = 0;
    CHECK(first_ingress(host, world.device_sink, body, flags));
    CHECK((flags & kFlagIngressAssurance) != 0);
    CHECK(body.size() == 20 + 3 + kIngressAssuranceTailSize);
    if (body.size() == 20 + 3 + kIngressAssuranceTailSize) {
      IngressAssurance tail{};
      CHECK_OK(decode_ingress_assurance_tail(
          ByteView{body.data() + 20 + 3, kIngressAssuranceTailSize}, tail));
      CHECK(tail.verified);
      CHECK(tail.profile == kProfileLegacyFixture);
      CHECK(tail.site_epoch == 7);
      world.device_sink.frames.clear();
    }
    // The 3-arg form (group default-forward path) stays legacy even
    // inside an enabled session.
    world.bridge.on_message(MessageKey{2, MessageId{2002, 2}}, 2,
                            ByteView{msg.data(), msg.size()});
    world.drain(now);
    CHECK(first_ingress(host, world.device_sink, body, flags));
    CHECK(flags == 0);
    CHECK(body.size() == 20 + 3);
    world.device_sink.frames.clear();
    // An unverified verdict is reported honestly, not dropped.
    DeliveryAssurance denied{};
    denied.origin_verified = false;
    denied.site_epoch = 9;
    world.bridge.on_message(MessageKey{2, MessageId{2002, 3}}, 2,
                            ByteView{msg.data(), msg.size()}, denied);
    world.drain(now);
    CHECK(first_ingress(host, world.device_sink, body, flags));
    CHECK((flags & kFlagIngressAssurance) != 0);
    if (body.size() == 20 + 3 + kIngressAssuranceTailSize) {
      IngressAssurance tail{};
      CHECK_OK(decode_ingress_assurance_tail(
          ByteView{body.data() + 20 + 3, kIngressAssuranceTailSize}, tail));
      CHECK(!tail.verified);
      CHECK(tail.site_epoch == 9);
    }
  }

  // 3) Validation: a bad profile id is refused, a malformed 0x08 is a
  // ProtocolError (never an enable), and the tail codec fails closed.
  {
    World world;
    CHECK(!world.bridge.set_rx_assurance_profile(4).ok());
    HostDriver host;
    MonotonicMs now = 0;
    CHECK(host_handshake(world, host, now, 0xA883, 120) != 0);
    const std::array<std::uint8_t, 3> bad{{1, 0x08, 0xFF}};
    world.feed(host.sealed(FrameKind::HostOps, 121,
                           ByteView{bad.data(), bad.size()}),
               now);
    world.drain(now);
    bool error = false;
    for (const auto& record : world.device_sink.frames) {
      error = error || record.frame.kind == FrameKind::Error;
    }
    CHECK(error);
    CHECK(!world.bridge.rx_assurance_enabled());

    IngressAssurance tail{};
    tail.verified = true;
    tail.profile = kProfileMemberEdhoc;
    tail.site_epoch = 0xA5A5A5A5;
    std::array<std::uint8_t, kIngressAssuranceTailSize> encoded{};
    CHECK_OK(encode_ingress_assurance_tail(
        tail, MutableByteView{encoded.data(), encoded.size()}));
    IngressAssurance back{};
    CHECK_OK(decode_ingress_assurance_tail(
        ByteView{encoded.data(), encoded.size()}, back));
    CHECK(back.verified && back.profile == kProfileMemberEdhoc &&
          back.site_epoch == 0xA5A5A5A5);
    // Stray flag bit, reserved byte, unknown profile, short tail.
    std::array<std::uint8_t, kIngressAssuranceTailSize> mutated = encoded;
    mutated[0] = 0x02;
    CHECK(!decode_ingress_assurance_tail(
              ByteView{mutated.data(), mutated.size()}, back)
              .ok());
    mutated = encoded;
    mutated[3] = 0x01;
    CHECK(!decode_ingress_assurance_tail(
              ByteView{mutated.data(), mutated.size()}, back)
              .ok());
    mutated = encoded;
    mutated[2] = 0x04;
    CHECK(!decode_ingress_assurance_tail(
              ByteView{mutated.data(), mutated.size()}, back)
              .ok());
    CHECK(!decode_ingress_assurance_tail(
              ByteView{encoded.data(), encoded.size() - 1}, back)
              .ok());
    IngressAssurance over{};
    over.profile = 4;
    CHECK(!encode_ingress_assurance_tail(
              over, MutableByteView{encoded.data(), encoded.size()})
              .ok());
  }

  // 4) Reconnect drops the enable (a new session re-enables) but keeps
  // the boot-scoped profile id.
  {
    World world;
    HostDriver host;
    MonotonicMs now = 0;
    CHECK_OK(world.bridge.set_rx_assurance_profile(kProfileDevRam));
    CHECK(host_handshake(world, host, now, 0xA884, 130) != 0);
    const auto grant = grant_body(256, 1u << 20);
    world.feed(host.sealed(FrameKind::Credit, 131,
                           ByteView{grant.data(), grant.size()}),
               now);
    world.drain(now);
    world.device_sink.frames.clear();
    const std::array<std::uint8_t, 2> enable{{1, 0x08}};
    world.feed(host.sealed(FrameKind::HostOps, 132,
                           ByteView{enable.data(), enable.size()}),
               now);
    world.drain(now);
    CHECK(world.bridge.rx_assurance_enabled());
    world.device_sink.frames.clear();
    HostDriver host2;
    CHECK(host_handshake(world, host2, now, 0xA885, 140) != 0);
    CHECK(!world.bridge.rx_assurance_enabled());
    world.feed(host2.sealed(FrameKind::Credit, 141,
                            ByteView{grant.data(), grant.size()}),
               now);
    world.drain(now);
    world.device_sink.frames.clear();
    world.feed(host2.sealed(FrameKind::HostOps, 142,
                            ByteView{enable.data(), enable.size()}),
               now);
    world.drain(now);
    const auto replies = host_ops_inners(host2, world.device_sink,
                                         HostOpsSub::RxAssuranceEnable);
    CHECK(replies.size() == 1);
    if (replies.size() == 1) {
      RxAssuranceResponse response{};
      CHECK_OK(decode_rx_assurance_response(
          ByteView{replies[0].inner.data(), replies[0].inner.size()},
          response));
      CHECK(response.result == HostOpsResult::Ok);
    }
    CHECK(world.bridge.rx_assurance_enabled());
  }
}

// ------------------------------------------------------------- golden files

using Fields = std::map<std::string, std::string>;

Fields parse_flat_json(const std::string& text) {
  Fields fields;
  std::size_t pos = 0;
  while (pos < text.size()) {
    const std::size_t key_begin = text.find('"', pos);
    if (key_begin == std::string::npos) break;
    const std::size_t key_end = text.find('"', key_begin + 1);
    if (key_end == std::string::npos) break;
    const std::size_t colon = text.find(':', key_end + 1);
    if (colon == std::string::npos) break;
    std::size_t cursor = colon + 1;
    while (cursor < text.size() && std::isspace(static_cast<unsigned char>(text[cursor]))) ++cursor;
    std::string value;
    if (cursor < text.size() && text[cursor] == '"') {
      const std::size_t value_end = text.find('"', cursor + 1);
      if (value_end == std::string::npos) break;
      value = text.substr(cursor + 1, value_end - cursor - 1);
      pos = value_end + 1;
    } else {
      std::size_t value_end = cursor;
      while (value_end < text.size() &&
             (std::isdigit(static_cast<unsigned char>(text[value_end])) || text[value_end] == '-')) {
        ++value_end;
      }
      value = text.substr(cursor, value_end - cursor);
      pos = value_end;
    }
    fields[text.substr(key_begin + 1, key_end - key_begin - 1)] = value;
  }
  return fields;
}

std::uint64_t field_u64(const Fields& fields, const char* key) {
  const auto it = fields.find(key);
  if (it == fields.end() || it->second.empty()) return 0;
  return std::strtoull(it->second.c_str(), nullptr, 10);
}

int hex_value(const char c) {
  if (c >= '0' && c <= '9') return c - '0';
  if (c >= 'a' && c <= 'f') return c - 'a' + 10;
  if (c >= 'A' && c <= 'F') return c - 'A' + 10;
  return -1;
}

bool hex_decode(const std::string& hex, std::vector<std::uint8_t>& out) {
  if (hex.size() % 2 != 0) return false;
  out.clear();
  for (std::size_t i = 0; i < hex.size(); i += 2) {
    const int high = hex_value(hex[i]);
    const int low = hex_value(hex[i + 1]);
    if (high < 0 || low < 0) return false;
    out.push_back(static_cast<std::uint8_t>(high * 16 + low));
  }
  return true;
}

std::string read_file(const std::filesystem::path& path) {
  std::ifstream input(path, std::ios::binary);
  std::ostringstream contents;
  contents << input.rdbuf();
  return contents.str();
}

void test_golden_session() {
  const std::filesystem::path root(ROUTELOOM_USB_GOLDEN_DIR);
  const Fields session = parse_flat_json(read_file(root / "session.json"));
  CHECK(!session.empty());
  std::vector<std::uint8_t> secret;
  CHECK(hex_decode(session.at("secret_hex"), secret));
  // The C++ session construction must derive identical proof material.
  const SessionProof proof = golden_proof();
  CHECK(proof.session_id == field_u64(session, "session_id"));
  std::vector<std::uint8_t> key;
  CHECK(hex_decode(session.at("key_h2d_hex"), key));
  CHECK(key == std::vector<std::uint8_t>(proof.key_h2d.begin(), proof.key_h2d.end()));
  CHECK(hex_decode(session.at("key_d2h_hex"), key));
  CHECK(key == std::vector<std::uint8_t>(proof.key_d2h.begin(), proof.key_d2h.end()));

  World world;
  MonotonicMs now = 0;

  std::vector<std::filesystem::path> steps;
  for (const auto& entry : std::filesystem::directory_iterator(root / "frames")) {
    if (entry.path().extension() == ".json") steps.push_back(entry.path());
  }
  std::sort(steps.begin(), steps.end());
  CHECK(steps.size() >= 10);

  std::vector<std::uint8_t> expected_out;
  std::vector<std::uint8_t> produced;
  bool injected_mesh = false;
  for (const auto& path : steps) {
    const Fields vector = parse_flat_json(read_file(path));
    const std::string name = vector.count("name") ? vector.at("name") : "";
    const std::string direction = vector.count("direction") ? vector.at("direction") : "";
    std::vector<std::uint8_t> wire;
    CHECK(hex_decode(vector.at("wire_hex"), wire));
    if (direction == "d2h") {
      if (name == "data_from_mesh" && !injected_mesh) {
        // Inject the mesh delivery that makes the bridge emit this frame.
        injected_mesh = true;
        const std::array<std::uint8_t, 8> payload{{'m','e','s','h','-','u','p','!'}};
        MessageId id{};
        CHECK_OK(world.n2.send(1, ByteView{payload.data(), payload.size()},
                               SendOptions{}, now, id));
        // The boot-time route advertisement rides the management class and
        // may take the first dispatch turn; poll until the DATA is on air.
        bool on_air = false;
        for (int i = 0; i < 4 && !on_air; ++i) {
          world.n2.poll(now);
          world.net.flush(now);
          for (const auto& s : world.net.sights) {
            on_air = on_air || s.type == FrameType::Data;
          }
        }
      }
      expected_out.insert(expected_out.end(), wire.begin(), wire.end());
    } else {
      world.feed(wire, now);
    }
    const auto emitted = world.drain_raw(now);
    produced.insert(produced.end(), emitted.begin(), emitted.end());
    now += 200;
  }
  CHECK(produced == expected_out);
  if (produced != expected_out) {
    std::fprintf(stderr, "golden mismatch: produced %zu bytes, expected %zu\n",
                 produced.size(), expected_out.size());
    const std::size_t common = std::min(produced.size(), expected_out.size());
    for (std::size_t i = 0; i < common; ++i) {
      if (produced[i] != expected_out[i]) {
        std::fprintf(stderr, "first divergence at byte %zu: %02x != %02x\n", i,
                     produced[i], expected_out[i]);
        break;
      }
    }
  }
  CHECK(world.bridge.stats().rx_errors == 0);
  CHECK(world.bridge.stats().auth_failures == 0);
  CHECK(world.bridge.stats().replay_rejected == 0);
  CHECK(world.bridge.stats().stale_session == 0);
  CHECK(world.bridge.state() == SessionState::Disconnected);  // close drained
}

// protocol/usb-golden/node-status: the same replay discipline for the
// node_status_v1 family. The device advertises CAP_NODE_STATUS_V1; right
// before the first event vector the mesh loses neighbor 2, and the device's
// 250 ms monitor pass must emit exactly the golden NeighborDown/RouteDown
// frames (compared on the concatenated stream, like the session replay).
void test_golden_node_status() {
  const std::filesystem::path root =
      std::filesystem::path(ROUTELOOM_USB_GOLDEN_DIR) / "node-status";
  const Fields session = parse_flat_json(read_file(root / "session.json"));
  CHECK(!session.empty());
  const std::uint32_t capability = 0x3 | kCapHostOpsV1 | kCapNodeStatusV1;
  CHECK(field_u64(session, "capability") == capability);
  const SessionProof proof = golden_proof(capability);
  CHECK(proof.session_id == field_u64(session, "session_id"));
  std::vector<std::uint8_t> key;
  CHECK(hex_decode(session.at("key_h2d_hex"), key));
  CHECK(key == std::vector<std::uint8_t>(proof.key_h2d.begin(), proof.key_h2d.end()));
  CHECK(hex_decode(session.at("key_d2h_hex"), key));
  CHECK(key == std::vector<std::uint8_t>(proof.key_d2h.begin(), proof.key_d2h.end()));

  World world;
  CHECK_OK(world.bridge.attach_node_status());
  MonotonicMs now = 0;
  std::vector<std::filesystem::path> steps;
  for (const auto& entry : std::filesystem::directory_iterator(root / "frames")) {
    if (entry.path().extension() == ".json") steps.push_back(entry.path());
  }
  std::sort(steps.begin(), steps.end());
  CHECK(steps.size() >= 12);

  std::vector<std::uint8_t> expected_out;
  std::vector<std::uint8_t> produced;
  bool removed = false;
  for (const auto& path : steps) {
    const Fields vector = parse_flat_json(read_file(path));
    const std::string name = vector.count("name") ? vector.at("name") : "";
    const std::string direction = vector.count("direction") ? vector.at("direction") : "";
    std::vector<std::uint8_t> wire;
    CHECK(hex_decode(vector.at("wire_hex"), wire));
    if (direction == "d2h") {
      if (name.rfind("node_event_", 0) == 0 && !removed) {
        removed = true;
        CHECK_OK(world.n1.remove_neighbor(2, now));
      }
      expected_out.insert(expected_out.end(), wire.begin(), wire.end());
    } else {
      world.feed(wire, now);
    }
    const auto emitted = world.drain_raw(now);
    produced.insert(produced.end(), emitted.begin(), emitted.end());
    now += 200;
  }
  CHECK(removed);
  CHECK(produced == expected_out);
  if (produced != expected_out) {
    std::fprintf(stderr, "node-status golden mismatch: produced %zu bytes, expected %zu\n",
                 produced.size(), expected_out.size());
    const std::size_t common = std::min(produced.size(), expected_out.size());
    for (std::size_t i = 0; i < common; ++i) {
      if (produced[i] != expected_out[i]) {
        std::fprintf(stderr, "first divergence at byte %zu: %02x != %02x\n", i,
                     produced[i], expected_out[i]);
        break;
      }
    }
  }
  CHECK(world.bridge.stats().rx_errors == 0);
  CHECK(world.bridge.stats().auth_failures == 0);
  CHECK(world.bridge.stats().node_events == 2);
  CHECK(world.bridge.state() == SessionState::Disconnected);
}

// protocol/usb-golden/group-ops: the same replay discipline for the
// group_delivery_v1 family. The device advertises CAP_GROUP_DELIVERY_V1 on a
// gateway-scoped two-node mesh; the admitted status is emitted synchronously,
// and the FINAL status must come out of the mesh pump that runs right
// before its golden step — under the GROUP_SEND's request id.
void test_golden_group_ops() {
  const std::filesystem::path root =
      std::filesystem::path(ROUTELOOM_USB_GOLDEN_DIR) / "group-ops";
  const Fields session = parse_flat_json(read_file(root / "session.json"));
  CHECK(!session.empty());
  const std::uint32_t capability = 0x3 | kCapHostOpsV1 | kCapGroupDeliveryV1;
  CHECK(field_u64(session, "capability") == capability);
  const SessionProof proof = golden_proof(capability);
  CHECK(proof.session_id == field_u64(session, "session_id"));

  World world(/*scoped=*/true);
  CHECK_OK(world.bridge.attach_group());
  MonotonicMs now = 0;
  // Before the host connects: node 2 adopts gateway 1 as its tree parent.
  const auto warmup = world.run_mesh(now, 8000);
  (void)warmup;  // bridge output before the session opens is not part of the replay
  CHECK(world.n1.scoped_child(2));
  std::vector<std::filesystem::path> steps;
  for (const auto& entry : std::filesystem::directory_iterator(root / "frames")) {
    if (entry.path().extension() == ".json") steps.push_back(entry.path());
  }
  std::sort(steps.begin(), steps.end());
  CHECK(steps.size() >= 14);

  std::vector<std::uint8_t> expected_out;
  std::vector<std::uint8_t> produced;
  bool pumped = false;
  for (const auto& path : steps) {
    const Fields vector = parse_flat_json(read_file(path));
    const std::string name = vector.count("name") ? vector.at("name") : "";
    const std::string direction = vector.count("direction") ? vector.at("direction") : "";
    std::vector<std::uint8_t> wire;
    CHECK(hex_decode(vector.at("wire_hex"), wire));
    if (direction == "d2h") {
      if (name == "group_status_final") {
        pumped = true;
        const auto emitted = world.run_mesh(now, 1000);
        produced.insert(produced.end(), emitted.begin(), emitted.end());
      }
      expected_out.insert(expected_out.end(), wire.begin(), wire.end());
    } else {
      world.feed(wire, now);
    }
    const auto emitted = world.drain_raw(now);
    produced.insert(produced.end(), emitted.begin(), emitted.end());
    now += 200;
  }
  CHECK(pumped);
  CHECK(produced == expected_out);
  if (produced != expected_out) {
    std::fprintf(stderr, "group-ops golden mismatch: produced %zu bytes, expected %zu\n",
                 produced.size(), expected_out.size());
    const std::size_t common = std::min(produced.size(), expected_out.size());
    for (std::size_t i = 0; i < common; ++i) {
      if (produced[i] != expected_out[i]) {
        std::fprintf(stderr, "first divergence at byte %zu: %02x != %02x\n", i,
                     produced[i], expected_out[i]);
        break;
      }
    }
  }
  CHECK(world.obs2.group_messages.size() == 1);
  CHECK(world.n1.group_stats().sent == 1);
  CHECK(world.bridge.stats().rx_errors == 0);
  CHECK(world.bridge.stats().auth_failures == 0);
  CHECK(world.bridge.state() == SessionState::Disconnected);
}

// --- join_relay_v2 (SDK v1 zero-touch join, 02 §7.2/§7.4, #116) ----------------

struct RecordedWire {
  NodeId to{kInvalidNodeId};
  FrameType type{FrameType::Data};
  std::vector<std::uint8_t> payload;
};

class RecordingRelayPort final : public sdkv1::ZtRelayPort {
 public:
  Status send_relay(const NodeId destination, const FrameType type,
                    const ByteView payload) noexcept override {
    frames.push_back(RecordedWire{destination, type,
                                  std::vector<std::uint8_t>(payload.data, payload.data + payload.size)});
    return Status::success();
  }
  std::vector<RecordedWire> frames;
};

std::vector<std::uint8_t> sealed_inner(HostDriver& host, const std::uint64_t request,
                                       const std::vector<std::uint8_t>& inner) {
  return host.sealed(FrameKind::HostOps, request, ByteView{inner.data(), inner.size()});
}

std::vector<std::uint8_t> join_down_inner(const NodeId proxy, const std::uint32_t relay_id,
                                          const std::size_t message_size) {
  sdkv1::RelayObject object{};
  object.header.dir = sdkv1::RelayDirection::Down;
  object.header.relay_id = relay_id;
  object.header.proxy = proxy;
  object.header.joiner_mac = MacAddress{{2, 0, 0, 0, 0x12, 0x34}};
  object.header.step = 2;
  object.header.gateway_epoch = 7;
  object.header.proxy_epoch = 3;
  std::vector<std::uint8_t> message(message_size, 0x5A);
  object.message = ByteView{message.data(), message.size()};
  std::vector<std::uint8_t> bytes(sdkv1::kJoinObjectMax);
  std::size_t written = 0;
  CHECK_OK(sdkv1::relay_object_encode(object, MutableByteView{bytes.data(), bytes.size()}, written));
  JoinRelayDown down{};
  down.to_proxy = proxy;
  down.object = ByteView{bytes.data(), written};
  std::vector<std::uint8_t> inner(kGatewayInnerHeadSize + kJoinRelayDownMaxPayload);
  std::size_t size = 0;
  CHECK_OK(encode_join_relay_down(down, MutableByteView{inner.data(), inner.size()}, size));
  inner.resize(size);
  return inner;
}

void test_bridge_join_relay() {
  // One message ceiling bounds every carrier (sdk-v1/02 §7.4): the largest
  // 0x60/0x61 body fits the bridge's 1024 B TX item.
  static_assert(kGatewayInnerHeadSize + kJoinRelayUpMaxPayload <= 1024, "0x60 fits a TX item");
  static_assert(kGatewayInnerHeadSize + kJoinRelayDownMaxPayload <= 1024, "0x61 fits a TX item");
  // 1) Not attached: 0x61/0x62 are answered Unsupported (V1-H08); malformed
  //    bodies and device-only subcommands are ProtocolError frames.
  {
    World world;
    HostDriver host;
    MonotonicMs now = 0;
    CHECK(host_handshake(world, host, now, 0x6a6a, 90) != 0);
    const auto grant = grant_body(16, 32768);
    world.feed(host.sealed(FrameKind::Credit, 91, ByteView{grant.data(), grant.size()}), now);
    world.drain(now);
    world.device_sink.frames.clear();
    RecordingRelayPort bad_wire;
    sdkv1::JoinRelayGatewayConfig bad_config{};
    bad_config.node = 1;  // an unset service epoch must not advertise relay support
    sdkv1::JoinRelayGateway bad_gateway(bad_config, bad_wire);
    CHECK(world.bridge.attach_join_relay(bad_gateway).code == StatusCode::InvalidArgument);
    const std::uint8_t sample = 1;
    CHECK(world.bridge.relay_up(2, 1, ByteView{&sample, 1}).code == StatusCode::InvalidState);
    world.feed(sealed_inner(host, 92, join_down_inner(2, 77, 40)), now);
    world.drain(now);
    const auto results = host_ops_inners(host, world.device_sink, HostOpsSub::JoinRelayResult);
    CHECK(results.size() == 1);
    if (results.size() == 1) {
      JoinRelayResult result{};
      CHECK_OK(decode_join_relay_result(ByteView{results[0].inner.data(), results[0].inner.size()},
                                        result));
      CHECK(results[0].request == 92);
      CHECK(result.result == static_cast<std::uint16_t>(ConfigOpsResult::Unsupported));
      CHECK(result.proxy == 2 && result.relay_id == 77);
      CHECK(result.gateway_epoch == 7 && result.proxy_epoch == 3);
    }
    std::uint64_t request = 93;
    for (const std::vector<std::uint8_t>& bad :
         {std::vector<std::uint8_t>{2, 0x61, 0, 1, 0},             // truncated
          std::vector<std::uint8_t>{1, 0x61, 0, 1, 0},             // schema 1 join rejected
          std::vector<std::uint8_t>{2, 0x60, 0, 0},                // device -> host only
          std::vector<std::uint8_t>{2, 0x63, 0, 0}}) {             // device -> host only
      world.device_sink.frames.clear();
      now += 500;  // control-frame token bucket (Error frames are rate limited)
      world.feed(sealed_inner(host, request++, bad), now);
      world.drain(now);
      bool error = false;
      for (const auto& record : world.device_sink.frames) {
        error = error || record.frame.kind == FrameKind::Error;
      }
      CHECK(error);
    }
  }
  // 2) Attached but no session: the gateway's host sink refuses, so the
  //    gateway answers the proxy authority_unreachable (07 §7).
  {
    World world;
    RecordingRelayPort wire;
    sdkv1::JoinRelayGatewayConfig invalid_config{};
    invalid_config.node = 1;
    sdkv1::JoinRelayGateway invalid_gateway(invalid_config, wire);
    CHECK(world.bridge.attach_join_relay(invalid_gateway).code == StatusCode::InvalidArgument);
    sdkv1::JoinRelayGatewayConfig config{};
    config.node = 1;
    config.gateway_epoch = 7;
    sdkv1::JoinRelayGateway gateway(config, wire);
    gateway.set_membership(MembershipState::Member);
    CHECK_OK(world.bridge.attach_join_relay(gateway));
    const std::uint8_t message[3] = {1, 2, 3};
    CHECK(!world.bridge.relay_up(2, 1, ByteView{message, 3}).ok());
    sdkv1::RelayObject up{};
    up.header.relay_id = 5;
    up.header.proxy = 2;
    up.header.joiner_mac = MacAddress{{2, 0, 0, 0, 0x12, 0x34}};
    up.header.joiner_rssi_dbm = -50;
    up.header.gateway_epoch = 7;
    up.header.proxy_epoch = 3;
    up.message = ByteView{message, 3};
    std::array<std::uint8_t, 64> bytes{};
    std::size_t written = 0;
    CHECK_OK(sdkv1::relay_object_encode(up, MutableByteView{bytes.data(), bytes.size()}, written));
    gateway.on_relay_rx(2, 1, FrameType::BootstrapAuth, ByteView{bytes.data(), written}, 0);
    CHECK(wire.frames.size() == 1);
    if (wire.frames.size() == 1) {
      sdkv1::RelayObject answer{};
      CHECK_OK(sdkv1::relay_single_frame_decode(
          wire.frames[0].type, ByteView{wire.frames[0].payload.data(), wire.frames[0].payload.size()},
          answer));
      CHECK(answer.header.state == sdkv1::RelayState::Abort);
      CHECK(answer.abort.status == sdkv1::RelayStatusCode::AuthorityUnreachable);
    }
  }
}

// protocol/usb-golden/join-relay-v2: the join_relay_v2 family replayed
// through a real UsbBridge with an attached JoinRelayGateway. The proxy's
// Wire frames are injected right before the device steps they cause; the
// gateway's own Wire output toward the proxy is checked against the host's
// objects.
void test_golden_join_relay() {
  const std::filesystem::path root =
      std::filesystem::path(ROUTELOOM_USB_GOLDEN_DIR) / "join-relay-v2";
  const Fields session = parse_flat_json(read_file(root / "session.json"));
  CHECK(!session.empty());
  const std::uint32_t capability = 0x3 | kCapHostOpsV1 | kCapJoinRelayV2;
  CHECK(field_u64(session, "capability") == capability);
  const SessionProof proof = golden_proof(capability);
  CHECK(proof.session_id == field_u64(session, "session_id"));

  World world;
  RecordingRelayPort wire;
  // The gateway epoch is read from the scenario's own m1 up object, so the
  // test never hardcodes the generator's token.
  std::uint32_t gateway_epoch = 0;
  {
    std::vector<std::filesystem::path> scan;
    for (const auto& entry : std::filesystem::directory_iterator(root / "frames")) {
      if (entry.path().extension() == ".json") scan.push_back(entry.path());
    }
    for (const auto& path : scan) {
      const Fields vector = parse_flat_json(read_file(path));
      if (vector.count("name") == 0 || vector.at("name") != "join_relay_up_m1") continue;
      std::vector<std::uint8_t> inner;
      CHECK(hex_decode(vector.at("inner_hex"), inner));
      JoinRelayUp up{};
      CHECK_OK(decode_join_relay_up(ByteView{inner.data(), inner.size()}, up));
      sdkv1::RelayObject object{};
      CHECK_OK(sdkv1::relay_object_decode(up.object, object));
      gateway_epoch = object.header.gateway_epoch;
    }
  }
  CHECK(gateway_epoch != 0);
  sdkv1::JoinRelayGatewayConfig config{};
  config.node = 1;
  config.gateway_epoch = gateway_epoch;
  sdkv1::JoinRelayGateway gateway(config, wire);
  gateway.set_membership(MembershipState::Member);
  CHECK_OK(world.bridge.attach_join_relay(gateway));
  MonotonicMs now = 0;
  std::vector<std::filesystem::path> steps;
  for (const auto& entry : std::filesystem::directory_iterator(root / "frames")) {
    if (entry.path().extension() == ".json") steps.push_back(entry.path());
  }
  std::sort(steps.begin(), steps.end());
  CHECK(steps.size() >= 19);

  const auto up_object = [](const std::vector<std::uint8_t>& inner, std::vector<std::uint8_t>& out) {
    JoinRelayUp up{};
    CHECK_OK(decode_join_relay_up(ByteView{inner.data(), inner.size()}, up));
    CHECK(up.gateway == 1 && up.from_proxy == 2 && up.hops == 3);
    out.assign(up.object.data, up.object.data + up.object.size);
  };
  std::vector<std::uint8_t> m1_object;
  std::vector<std::uint8_t> m1_r2_object;
  std::vector<std::vector<std::uint8_t>> down_objects;
  std::vector<std::uint8_t> expected_out;
  std::vector<std::uint8_t> produced;
  for (const auto& path : steps) {
    const Fields vector = parse_flat_json(read_file(path));
    const std::string name = vector.count("name") ? vector.at("name") : "";
    const std::string direction = vector.count("direction") ? vector.at("direction") : "";
    std::vector<std::uint8_t> wire_bytes;
    std::vector<std::uint8_t> inner;
    CHECK(hex_decode(vector.at("wire_hex"), wire_bytes));
    CHECK(hex_decode(vector.at("inner_hex"), inner));
    if (direction == "d2h") {
      if (name == "join_relay_up_m1") {
        up_object(inner, m1_object);
        gateway.on_relay_rx(2, 3, FrameType::BootstrapAuth,
                            ByteView{m1_object.data(), m1_object.size()}, now);
      } else if (name == "join_relay_up_m1_r2") {
        up_object(inner, m1_r2_object);
        gateway.on_relay_rx(2, 3, FrameType::BootstrapAuth,
                            ByteView{m1_r2_object.data(), m1_r2_object.size()}, now);
      } else if (name == "join_relay_up_m3") {
        std::vector<std::uint8_t> object;
        up_object(inner, object);
        sdkv1::RelayObject decoded{};
        CHECK_OK(sdkv1::relay_object_decode(ByteView{object.data(), object.size()}, decoded));
        sdkv1::JoinObjectSlot sender{};
        CHECK_OK(sender.load(sdkv1::JoinCarrier::WireRelay, decoded.header.phase,
                             decoded.header.step, decoded.header.relay_id,
                             decoded.header.gateway_epoch, decoded.header.proxy_epoch,
                             ByteView{object.data(), object.size()}, now));
        CHECK(sender.chunk_total() == 4);
        for (std::size_t i = 0; i < sender.chunk_total(); ++i) {
          sdkv1::JoinChunk chunk{};
          CHECK_OK(sender.chunk_at(i, chunk));
          std::array<std::uint8_t, kMaxApplicationPayload> payload{};
          std::size_t size = 0;
          CHECK_OK(sdkv1::join_chunk_encode(sdkv1::JoinCarrier::WireRelay, chunk,
                                            MutableByteView{payload.data(), payload.size()}, size));
          gateway.on_relay_rx(2, 3, FrameType::BootstrapChunk, ByteView{payload.data(), size}, now);
        }
      } else if (name == "join_relay_proxy_abort") {
        JoinRelayAbort notice{};
        CHECK_OK(decode_join_relay_abort(ByteView{inner.data(), inner.size()}, notice));
        CHECK(!m1_r2_object.empty());
        sdkv1::RelayObject m1{};
        CHECK_OK(sdkv1::relay_object_decode(ByteView{m1_r2_object.data(), m1_r2_object.size()}, m1));
        sdkv1::RelayObject abort{};
        abort.header = m1.header;
        abort.header.relay_id = notice.relay_id;
        abort.header.gateway_epoch = notice.gateway_epoch;
        abort.header.proxy_epoch = notice.proxy_epoch;
        abort.header.state = sdkv1::RelayState::Abort;
        abort.abort.status = sdkv1::RelayStatusCode::Aborted;
        std::array<std::uint8_t, 64> bytes{};
        std::size_t size = 0;
        CHECK_OK(sdkv1::relay_object_encode(abort, MutableByteView{bytes.data(), bytes.size()}, size));
        gateway.on_relay_rx(2, 3, FrameType::BootstrapAuth, ByteView{bytes.data(), size}, now);
      }
      expected_out.insert(expected_out.end(), wire_bytes.begin(), wire_bytes.end());
    } else {
      if (name.rfind("join_relay_down_", 0) == 0) {
        JoinRelayDown down{};
        CHECK_OK(decode_join_relay_down(ByteView{inner.data(), inner.size()}, down));
        down_objects.emplace_back(down.object.data, down.object.data + down.object.size);
      }
      world.feed(wire_bytes, now);
    }
    const auto emitted = world.drain_raw(now);
    produced.insert(produced.end(), emitted.begin(), emitted.end());
    now += 200;
  }
  CHECK(produced == expected_out);
  if (produced != expected_out) {
    std::fprintf(stderr, "join-relay golden mismatch: produced %zu bytes, expected %zu\n",
                 produced.size(), expected_out.size());
    const std::size_t common = std::min(produced.size(), expected_out.size());
    for (std::size_t i = 0; i < common; ++i) {
      if (produced[i] != expected_out[i]) {
        std::fprintf(stderr, "first divergence at byte %zu: %02x != %02x\n", i,
                     produced[i], expected_out[i]);
        break;
      }
    }
  }
  // The gateway's Wire side: 4 chunks for m2 to proxy 2, receipts for the 4
  // m3 chunks, 4 chunks for m4 — each down object reassembles to the host's —
  // then one abort object: the host_abort lands while m4 is still
  // SendingFinal, so the live relay is finished with a Wire abort (#116 §4.4).
  CHECK(down_objects.size() == 2);
  sdkv1::RelayObject m1_check{};
  CHECK_OK(sdkv1::relay_object_decode(ByteView{m1_object.data(), m1_object.size()}, m1_check));
  std::size_t down_index = 0;
  sdkv1::JoinObjectSlot receiver{};
  std::size_t receipts = 0;
  std::size_t wire_aborts = 0;
  for (const RecordedWire& frame : wire.frames) {
    CHECK(frame.to == 2);
    if (frame.type == FrameType::BootstrapReply) {
      ++receipts;
      continue;
    }
    if (frame.type == FrameType::MembershipResult) {
      sdkv1::RelayObject abort{};
      CHECK_OK(sdkv1::relay_object_decode(
          ByteView{frame.payload.data(), frame.payload.size()}, abort));
      CHECK(abort.header.dir == sdkv1::RelayDirection::Down);
      CHECK(abort.header.state == sdkv1::RelayState::Abort);
      CHECK(abort.abort.status == sdkv1::RelayStatusCode::Aborted);
      CHECK(sdkv1::relay_token_equal(sdkv1::relay_token_of(abort.header),
                                     sdkv1::relay_token_of(m1_check.header)));
      ++wire_aborts;
      continue;
    }
    CHECK(frame.type == FrameType::BootstrapChunk);
    sdkv1::JoinChunk chunk{};
    CHECK_OK(sdkv1::join_chunk_decode(sdkv1::JoinCarrier::WireRelay,
                                      ByteView{frame.payload.data(), frame.payload.size()}, chunk));
    const auto accepted = receiver.accept(sdkv1::JoinCarrier::WireRelay, chunk, 0);
    if (accepted.outcome == sdkv1::JoinObjectSlot::Outcome::Complete && down_index < 2) {
      const ByteView assembled = receiver.assembled();
      CHECK(std::vector<std::uint8_t>(assembled.data, assembled.data + assembled.size) ==
            down_objects[down_index]);
      ++down_index;
      receiver.release_assembled();
    }
  }
  CHECK(down_index == 2);
  CHECK(receipts == 4);
  CHECK(wire_aborts == 1);
  CHECK(gateway.stats().up_objects == 3 && gateway.stats().down_objects == 2);
  CHECK(gateway.stats().host_aborts == 1);
  CHECK(gateway.stats().proxy_aborts == 1);
  CHECK(world.bridge.stats().rx_errors == 0);
  CHECK(world.bridge.stats().auth_failures == 0);
  CHECK(world.bridge.state() == SessionState::Disconnected);
}

// protocol/usb-golden/join-relay-v2/{valid,invalid}: the 0x60-0x63 inners
// (schema 2, generated by tools/gen_sdkv1_join_relay_v2_vectors.py) decode
// to the listed fields and re-encode byte-for-byte; invalid inners are
// refused.
void test_golden_join_relay_codec() {
  const std::filesystem::path root =
      std::filesystem::path(ROUTELOOM_USB_GOLDEN_DIR) / "join-relay-v2";
  std::vector<std::filesystem::path> valid;
  for (const auto& entry : std::filesystem::directory_iterator(root / "valid")) {
    if (entry.path().extension() == ".json") valid.push_back(entry.path());
  }
  std::vector<std::filesystem::path> invalid;
  for (const auto& entry : std::filesystem::directory_iterator(root / "invalid")) {
    if (entry.path().extension() == ".json") invalid.push_back(entry.path());
  }
  std::sort(valid.begin(), valid.end());
  std::sort(invalid.begin(), invalid.end());
  CHECK(valid.size() >= 12);
  CHECK(invalid.size() >= 20);
  for (const auto& path : valid) {
    const Fields f = parse_flat_json(read_file(path));
    std::vector<std::uint8_t> inner;
    CHECK(hex_decode(f.at("inner_hex"), inner));
    const std::string& codec = f.at("codec");
    std::vector<std::uint8_t> out(2048);
    std::size_t written = 0;
    if (codec == "join_usb_up") {
      JoinRelayUp up{};
      CHECK_OK(decode_join_relay_up(ByteView{inner.data(), inner.size()}, up));
      CHECK(up.gateway == field_u64(f, "gateway"));
      CHECK(up.from_proxy == field_u64(f, "from_proxy"));
      CHECK(up.hops == field_u64(f, "hops"));
      std::vector<std::uint8_t> object;
      CHECK(hex_decode(f.at("object_hex"), object));
      CHECK(std::vector<std::uint8_t>(up.object.data, up.object.data + up.object.size) == object);
      CHECK_OK(encode_join_relay_up(up, MutableByteView{out.data(), out.size()}, written));
    } else if (codec == "join_usb_down") {
      JoinRelayDown down{};
      CHECK_OK(decode_join_relay_down(ByteView{inner.data(), inner.size()}, down));
      CHECK(down.to_proxy == field_u64(f, "to_proxy"));
      std::vector<std::uint8_t> object;
      CHECK(hex_decode(f.at("object_hex"), object));
      CHECK(std::vector<std::uint8_t>(down.object.data, down.object.data + down.object.size) ==
            object);
      CHECK_OK(encode_join_relay_down(down, MutableByteView{out.data(), out.size()}, written));
    } else if (codec == "join_usb_abort") {
      JoinRelayAbort abort{};
      CHECK_OK(decode_join_relay_abort(ByteView{inner.data(), inner.size()}, abort));
      CHECK(abort.proxy == field_u64(f, "proxy"));
      CHECK(abort.relay_id == field_u64(f, "relay_id"));
      CHECK(abort.gateway_epoch == field_u64(f, "gateway_epoch"));
      CHECK(abort.proxy_epoch == field_u64(f, "proxy_epoch"));
      CHECK(abort.reason == field_u64(f, "reason"));
      CHECK_OK(encode_join_relay_abort(abort, MutableByteView{out.data(), out.size()}, written));
    } else if (codec == "join_usb_result") {
      JoinRelayResult result{};
      CHECK_OK(decode_join_relay_result(ByteView{inner.data(), inner.size()}, result));
      CHECK(result.result == field_u64(f, "result"));
      CHECK(result.proxy == field_u64(f, "proxy"));
      CHECK(result.relay_id == field_u64(f, "relay_id"));
      CHECK(result.gateway_epoch == field_u64(f, "gateway_epoch"));
      CHECK(result.proxy_epoch == field_u64(f, "proxy_epoch"));
      CHECK_OK(
          encode_join_relay_result(result, MutableByteView{out.data(), out.size()}, written));
    } else {
      CHECK(!"unknown usb join codec");
      continue;
    }
    CHECK(std::vector<std::uint8_t>(out.data(), out.data() + written) == inner);
  }
  for (const auto& path : invalid) {
    const Fields f = parse_flat_json(read_file(path));
    std::vector<std::uint8_t> encoded;
    CHECK(hex_decode(f.at("encoded_hex"), encoded));
    const ByteView input{encoded.data(), encoded.size()};
    const std::string& codec = f.at("codec");
    if (codec == "join_usb_up") {
      JoinRelayUp up{};
      CHECK(!decode_join_relay_up(input, up).ok());
    } else if (codec == "join_usb_down") {
      JoinRelayDown down{};
      CHECK(!decode_join_relay_down(input, down).ok());
    } else if (codec == "join_usb_abort") {
      JoinRelayAbort abort{};
      CHECK(!decode_join_relay_abort(input, abort).ok());
    } else if (codec == "join_usb_result") {
      JoinRelayResult result{};
      CHECK(!decode_join_relay_result(input, result).ok());
    } else {
      CHECK(!"unknown usb join codec");
    }
  }
}

}  // namespace

int main() {
  test_cobs();
  test_cobs_exact_capacity();
  test_cobs_decode_in_place();
  test_encode_frame_bounded_output();
  test_encode_frame_inplace();
  test_frame_max_body_boundary();
  test_frame_codec();
  test_credit();
  test_session_mac();
  test_session_material_clears_on_destruction();
  test_idempotency();
  test_bridge_optional_capabilities_need_attachment();
  test_bridge_session_lifecycle();
  test_bridge_auth_reserves_initial_grant();
  test_bridge_stale_grant_keeps_stall_ladder();
  test_bridge_partial_grant_keeps_stall_ladder();
  test_bridge_set_device_nonce();
  test_bridge_idempotent_send();
  test_bridge_expired_burst();
  test_bridge_partial_write();
  test_bridge_diagnostic_loss_accounting();
  test_bridge_diagnostics();
  test_bridge_node_status();
  test_bridge_observation();
  test_bridge_remote_observation();
  test_node_delivery_carries_assurance();
  test_bridge_rx_assurance();
  test_golden_session();
  test_golden_node_status();
  test_golden_group_ops();
  test_bridge_join_relay();
  test_golden_join_relay();
  test_golden_join_relay_codec();
  if (failures != 0) {
    std::fprintf(stderr, "%d usb checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom USB bridge tests passed");
  return 0;
}
