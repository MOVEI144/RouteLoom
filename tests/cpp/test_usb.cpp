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
#include <sstream>
#include <string>
#include <vector>

#include "routeloom/byte_io.hpp"
#include "routeloom/node.hpp"
#include "routeloom/usb_bridge.hpp"
#include "routeloom/usb_codec.hpp"
#include "routeloom/usb_session.hpp"

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
  std::array<std::uint8_t, kMaxEncodedFrame> out{};
  std::size_t written = 0;
  const Status status =
      encode_frame(kind, flags, session, request, body,
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
  CHECK(credit.update(9, 3, 400).code == StatusCode::ProtocolError);
  CHECK(credit.update(9, 4, 300).code == StatusCode::ProtocolError);
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
  // Session change resets accounting.
  credit.reset(10);
  CHECK(credit.grant_frames() == 0 && credit.consumed_frames() == 0);
}

// ------------------------------------------------------------------ session

SessionTranscript golden_transcript() {
  SessionTranscript t{};
  t.host_nonce = 0x0102030405060708ULL;
  t.device_nonce = 0xA0B0C0D0E0F00102ULL;
  t.version = 1;
  t.node = 1;
  t.boot_id = 0x000000B0071D0001ULL;
  t.network = 7;
  t.capability = 3;
  const char* principal = "host-operator";
  t.principal_len = 13;
  std::memcpy(t.principal.data(), principal, t.principal_len);
  return t;
}

SessionProof golden_proof() {
  const SessionTranscript transcript = golden_transcript();
  std::array<std::uint8_t, kTranscriptSize> encoded{};
  std::size_t size = 0;
  if (!encode_transcript(transcript,
                         MutableByteView{encoded.data(), encoded.size()}, size)) {
    return SessionProof{};
  }
  return derive_session_proof(secret_view(), ByteView{encoded.data(), size});
}

void test_session_mac() {
  const SessionProof proof = golden_proof();
  // Anchor values generated by the Rust dev_session port (session.json).
  CHECK(proof.session_id == 9570924496059420596ULL);
  const std::array<std::uint8_t, 16> expected_key{
      0x1c, 0x8e, 0x3f, 0xde, 0x26, 0x72, 0xd2, 0x8c,
      0x64, 0x09, 0x16, 0x82, 0xb2, 0xcc, 0x44, 0x8c};
  CHECK(proof.key == expected_key);

  const std::array<std::uint8_t, 4> inner{{1, 2, 3, 4}};
  std::array<std::uint8_t, 64> sealed{};
  std::size_t sealed_size = 0;
  CHECK_OK(seal_body(proof.key, kDirHostToDevice, 0, FrameKind::KeepAlive, 0, 9,
                     ByteView{inner.data(), inner.size()},
                     MutableByteView{sealed.data(), sealed.size()}, sealed_size));
  CHECK(sealed_size == kProtectedBodyOverhead + inner.size());
  UsbFrame frame{};
  frame.kind = FrameKind::KeepAlive;
  frame.request = 9;
  frame.body = ByteView{sealed.data(), sealed_size};
  std::uint64_t counter = 99;
  ByteView opened{};
  CHECK_OK(open_body(proof.key, kDirHostToDevice, frame, counter, opened));
  CHECK(counter == 0 && opened.size == inner.size());
  // Wrong direction, tampered tag and tampered inner all fail.
  CHECK(open_body(proof.key, kDirDeviceToHost, frame, counter, opened).code ==
        StatusCode::AuthenticationFailed);
  sealed[10] ^= 1;
  frame.body = ByteView{sealed.data(), sealed_size};
  CHECK(open_body(proof.key, kDirHostToDevice, frame, counter, opened).code ==
        StatusCode::AuthenticationFailed);
}

void test_idempotency() {
  IdempotencyTable table;
  const std::array<std::uint8_t, 4> principal{{'h', 'o', 's', 't'}};
  const std::array<std::uint8_t, 2> a{{1, 2}}, b{{1, 3}};
  IdempotencyRecord* record = nullptr;
  CHECK(table.submit(ByteView{principal.data(), principal.size()}, 7, 16, 42,
                     payload_hash(ByteView{a.data(), a.size()}),
                     record) == IdempotencyResult::Accepted);
  CHECK(record != nullptr);
  CHECK(table.submit(ByteView{principal.data(), principal.size()}, 7, 16, 42,
                     payload_hash(ByteView{a.data(), a.size()}),
                     record) == IdempotencyResult::Existing);
  CHECK(table.submit(ByteView{principal.data(), principal.size()}, 7, 16, 42,
                     payload_hash(ByteView{b.data(), b.size()}),
                     record) == IdempotencyResult::Conflict);
  // Different scope members are different identities.
  CHECK(table.submit(ByteView{principal.data(), principal.size()}, 8, 16, 42,
                     payload_hash(ByteView{a.data(), a.size()}),
                     record) == IdempotencyResult::Accepted);
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
    if (!seal_body(proof.key, kDirHostToDevice, h2d_counter, kind, 0, request,
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
  MeshNode n1, n2;
  CollectSink device_sink;
  StreamDecoder device_decoder;

  World()
      : bridge(config(), stream),
        r1(net, 1), r2(net, 2),
        n1(node_config(1, 7001), r1, sec1, bridge),
        n2(node_config(2, 2002), r2, sec2, obs2),
        device_decoder(device_sink) {
    bridge.set_mesh(&n1);
    net.register_node(1, &n1);
    net.register_node(2, &n2);
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
    cfg.capability = 3;
    cfg.device_nonce = 0xA0B0C0D0E0F00102ULL;
    return cfg;
  }
  static NodeConfig node_config(NodeId node, std::uint32_t session) {
    NodeConfig cfg{};
    cfg.network = 7;
    cfg.node = node;
    cfg.message_session = session;
    return cfg;
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
  hello_body[8] = 1;
  hello_body[9] = 1;
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
  if (std::memcmp(ack_body.data() + 37, host.proof.hello_tag.data(), kDevTagSize) != 0) {
    return 0;
  }
  world.feed(host.plain(FrameKind::Hello, kFlagAuth, request_base + 1,
                        ByteView{host.proof.auth_tag.data(), kDevTagSize}), now);
  world.drain(now);
  now += 200;
  if (world.device_sink.frames.size() != 2) return 0;  // auth_ok + rx grant
  const auto& auth_ok = world.device_sink.frames[0].frame;
  if (auth_ok.kind != FrameKind::HelloAck || (auth_ok.flags & kFlagAuth) == 0 ||
      auth_ok.body.size != 24) {
    return 0;
  }
  if (std::memcmp(auth_ok.body.data, host.proof.auth_ok_tag.data(), kDevTagSize) != 0 ||
      read_u64(auth_ok.body.data + kDevTagSize) != host.session) {
    return 0;
  }
  const auto& grant = world.device_sink.frames[1].frame;
  if (grant.kind != FrameKind::Credit || grant.session != host.session) return 0;
  std::uint64_t counter = 0;
  ByteView inner{};
  if (!open_body(host.proof.key, kDirDeviceToHost, grant, counter, inner) ||
      counter != 0 || inner.size != 17 || inner.data[0] != kCreditGrant) {
    return 0;
  }
  world.device_sink.frames.clear();
  return host.session;
}

std::vector<std::uint8_t> grant_body(std::uint64_t frames, std::uint64_t bytes) {
  std::vector<std::uint8_t> inner(17, 0);
  inner[0] = kCreditGrant;
  write_u64(inner.data() + 1, frames);
  write_u64(inner.data() + 9, bytes);
  return inner;
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
      if (open_body(host.proof.key, kDirDeviceToHost, record.frame, counter,
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
      CHECK_OK(open_body(host.proof.key, kDirDeviceToHost, record.frame, counter, inner));
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
  CHECK_OK(seal_body(host.proof.key, kDirHostToDevice, host.h2d_counter,
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

void test_bridge_idempotent_send() {
  World world;
  HostDriver host;
  MonotonicMs now = 0;
  CHECK(host_handshake(world, host, now, 0x3333, 40) != 0);

  const auto grant = grant_body(8, 8192);
  world.feed(host.sealed(FrameKind::Credit, 41, ByteView{grant.data(), grant.size()}), now);
  world.drain(now);

  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  std::array<std::uint8_t, 32> inner{};
  write_u64(inner.data(), 2);
  std::memcpy(inner.data() + 8, payload.data(), payload.size());
  const auto send = host.sealed(FrameKind::DataToMesh, 42,
                                ByteView{inner.data(), 8 + payload.size()});
  world.feed(send, now);
  world.drain(now);
  std::size_t accepted = 0;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind == FrameKind::DeliveryEvent) ++accepted;
  }
  CHECK(accepted >= 1);  // Accepted (+Queued) command receipts
  world.device_sink.frames.clear();

  // Same identity + same payload: cached result replayed, no second send.
  const std::uint64_t counter_before = host.h2d_counter;
  const auto replay = host.sealed(FrameKind::DataToMesh, 42,
                                  ByteView{inner.data(), 8 + payload.size()});
  CHECK(host.h2d_counter == counter_before + 1);
  world.feed(replay, now);
  world.drain(now);
  bool idempotent_replay = false;
  for (const auto& record : world.device_sink.frames) {
    std::uint64_t counter = 0;
    ByteView opened{};
    if (record.frame.kind != FrameKind::DeliveryEvent) continue;
    CHECK_OK(open_body(host.proof.key, kDirDeviceToHost, record.frame, counter, opened));
    if (opened.size > 22 &&
        std::memcmp(opened.data + 22, "IDEMPOTENT_REPLAY", 17) == 0) {
      idempotent_replay = true;
    }
  }
  CHECK(idempotent_replay);
  world.device_sink.frames.clear();

  // Same key, different payload -> CONFLICT.
  std::array<std::uint8_t, 32> changed{};
  write_u64(changed.data(), 2);
  const std::array<std::uint8_t, 4> other{{9, 9, 9, 9}};
  std::memcpy(changed.data() + 8, other.data(), other.size());
  world.feed(host.sealed(FrameKind::DataToMesh, 42,
                         ByteView{changed.data(), 8 + other.size()}), now);
  world.drain(now);
  bool conflict = false;
  for (const auto& record : world.device_sink.frames) {
    if (record.frame.kind == FrameKind::Error) {
      std::uint64_t counter = 0;
      ByteView opened{};
      if (open_body(host.proof.key, kDirDeviceToHost, record.frame, counter,
                    opened) &&
          opened.size > 2 &&
          opened.data[1] == static_cast<std::uint8_t>(UsbErrorCode::Conflict)) {
        conflict = true;
      }
    }
  }
  CHECK(conflict);
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
  CHECK(hex_decode(session.at("session_key_hex"), key));
  CHECK(key == std::vector<std::uint8_t>(proof.key.begin(), proof.key.end()));

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
        world.n2.poll(now);
        world.net.flush(now);
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

}  // namespace

int main() {
  test_cobs();
  test_frame_codec();
  test_credit();
  test_session_mac();
  test_idempotency();
  test_bridge_session_lifecycle();
  test_bridge_idempotent_send();
  test_bridge_partial_write();
  test_golden_session();
  if (failures != 0) {
    std::fprintf(stderr, "%d usb checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom USB bridge tests passed");
  return 0;
}
