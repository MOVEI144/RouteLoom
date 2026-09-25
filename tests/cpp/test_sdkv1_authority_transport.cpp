// Authority-channel mesh transport tests (G-SEC P5 PR4): the
// Control-22/sub-9 carrier codec, the device endpoint, the two-slot
// gateway relay, and the ConfigTarget demux hook.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/config.hpp"
#include "routeloom/config_wire.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/sdkv1_authority.hpp"
#include "routeloom/sdkv1_authority_transport.hpp"

static_assert(sizeof(routeloom::sdkv1::AuthorityEndpoint) <= 4512,
              "authority endpoint keeps only chunk receipt bits");
static_assert(sizeof(routeloom::sdkv1::AuthorityGateway) <= 4384,
              "authority relay keeps only chunk receipt bits");
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/usb_host_ops.hpp"
#include "routeloom/wire.hpp"

namespace {

using namespace routeloom;
using namespace routeloom::sdkv1;

int failures = 0;
#define CHECK(expr)                                                  \
  do {                                                               \
    if (!(expr)) {                                                   \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__,      \
                   __LINE__, #expr);                                 \
      ++failures;                                                    \
    }                                                                \
  } while (false)

constexpr NodeId kDevice = 0x1111;
constexpr NodeId kGateway = 0x2222;

std::vector<std::uint8_t> pattern(const std::size_t n, const std::uint8_t seed = 0x40) {
  std::vector<std::uint8_t> out(n);
  for (std::size_t i = 0; i < n; ++i) out[i] = static_cast<std::uint8_t>(seed + i);
  return out;
}

// Records every config_send; the test decodes and answers manually.
class RecordingPort final : public ConfigWirePort {
 public:
  struct Sent {
    NodeId dest{kInvalidNodeId};
    FrameType type{FrameType::Data};
    MonotonicMs now{0};
    std::vector<std::uint8_t> payload;
  };
  Status config_send(const NodeId dest, const FrameType type, const ByteView payload,
                     const MonotonicMs now) noexcept override {
    ++sends;
    Sent sent;
    sent.dest = dest;
    sent.type = type;
    sent.now = now;
    sent.payload.assign(payload.data, payload.data + payload.size);
    queue.push_back(sent);
    return Status::success();
  }
  int sends{0};
  std::vector<Sent> queue;
};

// Loopback between two ConfigTargets (the asynchronous delivery of the
// routed lane: a reply never arrives inside the send that produced it).
class LoopbackPort final : public ConfigWirePort {
 public:
  LoopbackPort(const NodeId self, ConfigEndpointSink*& peer) noexcept
      : self_(self), peer_(peer) {}
  Status config_send(const NodeId dest, const FrameType type, const ByteView payload,
                     const MonotonicMs) noexcept override {
    ++sends;
    if (drop) return Status::success();
    Pending pending{};
    pending.dest = dest;
    pending.type = type;
    pending.size = payload.size;
    std::memcpy(pending.bytes.data(), payload.data, payload.size);
    queue.push_back(pending);
    return Status::success();
  }
  void flush(const MonotonicMs now) noexcept {
    auto batch = queue;
    queue.clear();
    for (const auto& pending : batch) {
      if (peer_ == nullptr) continue;
      ++delivered;
      wire::PlainFrame frame{};
      frame.header.type = pending.type;
      frame.header.origin = self_;
      frame.header.destination = pending.dest;
      frame.payload_size = pending.size;
      std::memcpy(frame.payload.data(), pending.bytes.data(), pending.size);
      peer_->on_config_frame(self_, frame, now);
    }
  }
  bool drop{false};
  int sends{0};
  int delivered{0};

 private:
  struct Pending {
    NodeId dest{kInvalidNodeId};
    FrameType type{FrameType::Data};
    std::array<std::uint8_t, kMaxApplicationPayload> bytes{};
    std::size_t size{0};
  };
  NodeId self_;
  ConfigEndpointSink*& peer_;
  std::vector<Pending> queue;
};

class RecordingLocalSink final : public AuthorityLocalSink {
 public:
  struct Down {
    AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
    std::vector<std::uint8_t> bytes;
  };
  void on_local_down(AuthorityCarrierKind kind, MutableByteView bytes) noexcept override {
    Down down;
    down.kind = kind;
    down.bytes.assign(bytes.data, bytes.data + bytes.size);
    downs.push_back(down);
  }
  std::vector<Down> downs;
};

class RecordingHostSink final : public AuthorityHostSink {
 public:
  struct Up {
    NodeId device{kInvalidNodeId};
    std::uint32_t transfer_id{0};
    AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
    std::uint8_t hops{0};
    std::uint16_t total{0};
    std::uint16_t offset{0};
    std::vector<std::uint8_t> data;
  };
  bool send_up(const usb::AuthorityFragment& fragment) noexcept override {
    if (refuse) return false;
    Up up;
    up.device = fragment.device;
    up.transfer_id = fragment.transfer_id;
    up.kind = fragment.kind;
    up.hops = fragment.hops;
    up.total = fragment.total;
    up.offset = fragment.offset;
    up.data.assign(fragment.data.data, fragment.data.data + fragment.data.size);
    ups.push_back(up);
    return true;
  }
  bool refuse{false};
  std::vector<Up> ups;
};

wire::PlainFrame terminal_frame(const NodeId origin, const NodeId dest, const FrameType type,
                                const ByteView payload) {
  wire::PlainFrame frame{};
  frame.header.type = type;
  frame.header.origin = origin;
  frame.header.destination = dest;
  frame.payload_size = payload.size;
  std::memcpy(frame.payload.data(), payload.data, payload.size);
  return frame;
}

void test_carrier_codec() {
  for (const auto kind :
       {AuthorityCarrierKind::R1, AuthorityCarrierKind::R2, AuthorityCarrierKind::R3,
        AuthorityCarrierKind::Envelope, AuthorityCarrierKind::Wake}) {
    const std::size_t body_size = kind == AuthorityCarrierKind::R1      ? 60
                                  : kind == AuthorityCarrierKind::R2    ? 52
                                  : kind == AuthorityCarrierKind::R3    ? 16
                                  : kind == AuthorityCarrierKind::Wake ? 8
                                                                        : 120;
    const auto body = pattern(body_size);
    const std::uint32_t exchange =
        (kind == AuthorityCarrierKind::Envelope || kind == AuthorityCarrierKind::Wake)
            ? 0
            : 0x12345678;
    std::array<std::uint8_t, kMaxApplicationPayload> encoded{};
    std::size_t written = 0;
    CHECK(authority_carrier_encode(kind, exchange, ByteView{body.data(), body.size()},
                                   MutableByteView{encoded.data(), encoded.size()},
                                   written));
    CHECK(written == kAuthorityCarrierHeadSize + body_size);
    AuthorityCarrierKind back_kind{AuthorityCarrierKind::Envelope};
    std::uint32_t back_exchange = 0;
    ByteView back_body{};
    CHECK(authority_carrier_decode(ByteView{encoded.data(), written}, back_kind,
                                   back_exchange, back_body));
    CHECK(back_kind == kind);
    CHECK(back_exchange == exchange);
    CHECK(back_body.size == body_size &&
          std::memcmp(back_body.data, body.data(), body_size) == 0);
  }
  // Length pins per kind.
  CHECK(authority_carrier_length_valid(AuthorityCarrierKind::R1, 60));
  CHECK(authority_carrier_length_valid(AuthorityCarrierKind::R1, 109));
  CHECK(!authority_carrier_length_valid(AuthorityCarrierKind::R1, 59));
  CHECK(!authority_carrier_length_valid(AuthorityCarrierKind::R1, 110));
  CHECK(authority_carrier_length_valid(AuthorityCarrierKind::R2, 52));
  CHECK(authority_carrier_length_valid(AuthorityCarrierKind::R2, 12));
  CHECK(!authority_carrier_length_valid(AuthorityCarrierKind::R2, 51));
  CHECK(authority_carrier_length_valid(AuthorityCarrierKind::R3, 16));
  CHECK(!authority_carrier_length_valid(AuthorityCarrierKind::R3, 15));
  CHECK(authority_carrier_length_valid(AuthorityCarrierKind::Envelope, 28));
  CHECK(authority_carrier_length_valid(AuthorityCarrierKind::Envelope, 2048));
  CHECK(!authority_carrier_length_valid(AuthorityCarrierKind::Envelope, 27));
  CHECK(!authority_carrier_length_valid(AuthorityCarrierKind::Envelope, 2049));
  CHECK(authority_carrier_length_valid(AuthorityCarrierKind::Wake, 8));
  CHECK(!authority_carrier_length_valid(AuthorityCarrierKind::Wake, 7));
  // Encode refuses a body above the carrier frame and a wrong token rule.
  const auto big = pattern(121);
  std::array<std::uint8_t, kMaxApplicationPayload> encoded{};
  std::size_t written = 0;
  CHECK(!authority_carrier_encode(AuthorityCarrierKind::Envelope, 0,
                                  ByteView{big.data(), big.size()},
                                  MutableByteView{encoded.data(), encoded.size()},
                                  written));
  const auto r1 = pattern(60);
  CHECK(!authority_carrier_encode(AuthorityCarrierKind::R1, 0,
                                  ByteView{r1.data(), r1.size()},
                                  MutableByteView{encoded.data(), encoded.size()},
                                  written));
  const auto wake = pattern(8);
  CHECK(!authority_carrier_encode(AuthorityCarrierKind::Wake, 7,
                                  ByteView{wake.data(), wake.size()},
                                  MutableByteView{encoded.data(), encoded.size()},
                                  written));
  // Decode refuses a bad head and a mis-sized body.
  std::array<std::uint8_t, 16> bad{2, kAuthorityControlSubtype, 5, 0, 0, 0, 0, 0,
                                   1, 2, 3, 4, 5, 6, 7, 8};
  AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
  std::uint32_t exchange = 0;
  ByteView body{};
  CHECK(!authority_carrier_decode(ByteView{bad.data(), bad.size()}, kind, exchange, body));
  bad[0] = 1;
  bad[1] = 5;  // the trust-status subtype is not a carrier
  CHECK(!authority_carrier_decode(ByteView{bad.data(), bad.size()}, kind, exchange, body));
  bad[1] = kAuthorityControlSubtype;
  bad[2] = 6;
  CHECK(!authority_carrier_decode(ByteView{bad.data(), bad.size()}, kind, exchange, body));
  bad[2] = 5;
  bad[3] = 1;
  CHECK(!authority_carrier_decode(ByteView{bad.data(), bad.size()}, kind, exchange, body));
  bad[3] = 0;
  bad[7] = 9;  // Wake must carry a zero token
  CHECK(!authority_carrier_decode(ByteView{bad.data(), bad.size()}, kind, exchange, body));
}

void test_endpoint_small_carrier() {
  RecordingPort port;
  AuthorityEndpoint endpoint(port, kDevice);
  const auto r1 = pattern(60);
  std::uint64_t token = 0;
  CHECK(endpoint.try_send(kGateway, AuthorityCarrierKind::R1,
                          ByteView{r1.data(), r1.size()}, token));
  CHECK(token != 0);
  // One transfer at a time: the second send refuses without spending.
  std::uint64_t token2 = 0;
  CHECK(!endpoint.try_send(kGateway, AuthorityCarrierKind::R1,
                           ByteView{r1.data(), r1.size()}, token2));
  CHECK(token2 == 0);
  AuthorityTxResult early{};
  CHECK(!endpoint.take_tx_result(early));  // staged, not sent yet
  endpoint.poll(1000);
  CHECK(port.sends == 1);
  CHECK(port.queue.size() == 1);
  CHECK(port.queue[0].dest == kGateway);
  CHECK(port.queue[0].type == FrameType::Control);
  CHECK(port.queue[0].now == 1000);
  AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
  std::uint32_t exchange = 0;
  ByteView body{};
  CHECK(authority_carrier_decode(
      ByteView{port.queue[0].payload.data(), port.queue[0].payload.size()}, kind,
      exchange, body));
  CHECK(kind == AuthorityCarrierKind::R1);
  CHECK(exchange != 0);
  CHECK(body.size == r1.size() && std::memcmp(body.data, r1.data(), r1.size()) == 0);
  AuthorityTxResult result{};
  CHECK(endpoint.take_tx_result(result));
  CHECK(result.token == token);
  CHECK(result.delivered);
  CHECK(!endpoint.take_tx_result(result));
  CHECK(endpoint.quiescent());
  // Self and invalid destinations never stage.
  CHECK(!endpoint.try_send(kDevice, AuthorityCarrierKind::R1,
                           ByteView{r1.data(), r1.size()}, token2));
  CHECK(!endpoint.try_send(kInvalidNodeId, AuthorityCarrierKind::R1,
                           ByteView{r1.data(), r1.size()}, token2));
}

void test_endpoint_object_round_trip() {
  ConfigEndpointSink* device_peer = nullptr;
  ConfigEndpointSink* gateway_peer = nullptr;
  LoopbackPort device_port(kDevice, device_peer);
  LoopbackPort gateway_port(kGateway, gateway_peer);
  ConfigRateLimiter device_limiter;
  ConfigRateLimiter gateway_limiter;
  ConfigTarget device_target(device_port, device_limiter);
  ConfigTarget gateway_target(gateway_port, gateway_limiter);
  AuthorityEndpoint device(device_port, kDevice);
  AuthorityEndpoint gateway(gateway_port, kGateway);
  device_target.attach_authority(&device);
  gateway_target.attach_authority(&gateway);
  device_peer = &gateway_target;  // device sends reach the gateway target
  gateway_peer = &device_target;  // gateway sends reach the device target

  const auto envelope = pattern(1500);
  std::uint64_t token = 0;
  CHECK(device.try_send(kGateway, AuthorityCarrierKind::Envelope,
                        ByteView{envelope.data(), envelope.size()}, token));
  MonotonicMs now = 1000;
  for (int i = 0; i < 40; ++i) {
    device.poll(now);
    gateway.poll(now);
    device_port.flush(now);
    gateway_port.flush(now);
    now += 100;
  }
  AuthorityRxCarrier rx{};
  CHECK(gateway.take_rx(rx));
  CHECK(rx.kind == AuthorityCarrierKind::Envelope);
  CHECK(rx.bytes.size == envelope.size() &&
        std::memcmp(rx.bytes.data, envelope.data(), envelope.size()) == 0);
  CHECK(!gateway.take_rx(rx));
  AuthorityTxResult result{};
  CHECK(device.take_tx_result(result));
  CHECK(result.token == token);
  CHECK(result.delivered);
  CHECK(device.quiescent());
  CHECK(gateway.quiescent());
}

void test_endpoint_object_timeout() {
  ConfigEndpointSink* peer = nullptr;
  LoopbackPort port(kDevice, peer);
  ConfigRateLimiter limiter;
  ConfigTarget target(port, limiter);
  AuthorityEndpoint endpoint(port, kDevice);
  target.attach_authority(&endpoint);
  port.drop = true;  // nothing is ever delivered: no acks come back
  const auto envelope = pattern(300);
  std::uint64_t token = 0;
  CHECK(endpoint.try_send(kGateway, AuthorityCarrierKind::Envelope,
                          ByteView{envelope.data(), envelope.size()}, token));
  MonotonicMs now = 1000;
  for (int i = 0; i < 6; ++i) {
    endpoint.poll(now);
    port.flush(now);
    now += 500;
  }
  // Five resend rounds exhaust the per-chunk budget well before 15 s.
  AuthorityTxResult result{};
  CHECK(endpoint.take_tx_result(result));
  CHECK(result.token == token);
  CHECK(!result.delivered);
  CHECK(endpoint.quiescent());
  CHECK(endpoint.counters().tx_timeouts == 1);
}

void test_endpoint_rx_rules() {
  RecordingPort port;
  AuthorityEndpoint endpoint(port, kDevice);
  // A carrier from self is a reflection: dropped, never delivered.
  const auto r1 = pattern(60);
  std::array<std::uint8_t, kMaxApplicationPayload> frame{};
  std::size_t written = 0;
  CHECK(authority_carrier_encode(AuthorityCarrierKind::R1, 0xABCD,
                                 ByteView{r1.data(), r1.size()},
                                 MutableByteView{frame.data(), frame.size()},
                                 written));
  endpoint.on_control(kDevice, ByteView{frame.data(), written}, 1000);
  AuthorityRxCarrier rx{};
  CHECK(!endpoint.take_rx(rx));
  CHECK(endpoint.counters().rx_denied == 1);
  // A good carrier lands; a second one waits (no overwrite) until taken.
  endpoint.on_control(kGateway, ByteView{frame.data(), written}, 1000);
  endpoint.on_control(kGateway, ByteView{frame.data(), written}, 1000);
  CHECK(endpoint.take_rx(rx));
  CHECK(rx.kind == AuthorityCarrierKind::R1 && rx.bytes.size == 60);
  CHECK(!endpoint.take_rx(rx));
  // A kind-7 object with a lying hash fails at completion with a Failed ack.
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
  manifest.total_len = 200;
  for (std::size_t i = 0; i < manifest.object_hash.size(); ++i)
    manifest.object_hash[i] = static_cast<std::uint8_t>(i + 1);
  endpoint.on_manifest(kGateway, manifest, 2000);
  autonomy::ObjectChunkPayload chunk{};
  chunk.object_hash = manifest.object_hash;
  chunk.offset = 0;
  chunk.data_size = 90;
  for (std::size_t i = 0; i < 90; ++i) chunk.data[i] = static_cast<std::uint8_t>(i);
  endpoint.on_chunk(kGateway, chunk, 2000);
  chunk.offset = 90;
  chunk.data_size = 90;
  endpoint.on_chunk(kGateway, chunk, 2000);
  chunk.offset = 180;
  chunk.data_size = 20;
  endpoint.on_chunk(kGateway, chunk, 2000);
  CHECK(!endpoint.take_rx(rx));  // hash mismatch: nothing completes
  CHECK(port.sends == 4);        // Incomplete x3 then Failed
  autonomy::ObjectAckPayload ack{};
  const auto& last = port.queue.back();
  CHECK(last.type == FrameType::ObjectAck);
  CHECK(autonomy::object_ack_decode(
      ByteView{last.payload.data(), last.payload.size()}, ack));
  CHECK(ack.status == autonomy::ObjectAckStatus::Failed);
  // A conflicting duplicate poisons the next assembly.
  manifest.total_len = 100;
  endpoint.on_manifest(kGateway, manifest, 3000);
  chunk.offset = 0;
  chunk.data_size = 90;
  endpoint.on_chunk(kGateway, chunk, 3000);
  chunk.data[0] ^= 0xFF;
  endpoint.on_chunk(kGateway, chunk, 3000);
  CHECK(!endpoint.take_rx(rx));
  CHECK(autonomy::object_ack_decode(
      ByteView{port.queue.back().payload.data(), port.queue.back().payload.size()}, ack));
  CHECK(ack.status == autonomy::ObjectAckStatus::Failed);
  // Claim routing: subtype 9 and kind 7 only, live hashes only.
  CHECK(endpoint.claim_control(kAuthorityControlSubtype));
  CHECK(!endpoint.claim_control(5));
  CHECK(endpoint.claim_kind(autonomy::ControlObjectKind::AuthorityEnvelope));
  CHECK(!endpoint.claim_kind(autonomy::ControlObjectKind::TrustManifest));
  autonomy::ObjectHash foreign{};
  foreign[0] = 0xEE;
  CHECK(!endpoint.claim_transfer(kGateway, foreign));
  CHECK(endpoint.quiescent());
}

void test_object_chunks_require_contiguous_grid() {
  RecordingPort port;
  AuthorityEndpoint endpoint(port, kDevice);
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
  manifest.total_len = 200;
  manifest.object_hash[0] = 0xA5;
  autonomy::ObjectChunkPayload chunk{};
  chunk.object_hash = manifest.object_hash;
  chunk.data_size = 90;
  chunk.offset = 90;  // A count of 90 is not a contiguous ACK from zero.
  endpoint.on_manifest(kGateway, manifest, 1000);
  endpoint.on_chunk(kGateway, chunk, 1000);
  autonomy::ObjectAckPayload ack{};
  CHECK(autonomy::object_ack_decode(
      ByteView{port.queue.back().payload.data(), port.queue.back().payload.size()}, ack));
  CHECK(ack.status == autonomy::ObjectAckStatus::Failed);
  CHECK(endpoint.quiescent());

  RecordingHostSink host;
  RecordingLocalSink local;
  AuthorityGateway gateway(port, host, local, kGateway);
  gateway.on_manifest(kDevice, manifest, 2000);
  chunk.offset = 1;  // A full-sized chunk must start on the 90 B grid.
  gateway.on_chunk(kDevice, chunk, 2000);
  CHECK(autonomy::object_ack_decode(
      ByteView{port.queue.back().payload.data(), port.queue.back().payload.size()}, ack));
  CHECK(ack.status == autonomy::ObjectAckStatus::Failed);
  CHECK(gateway.quiescent());
}

void test_object_ack_requires_sent_progress() {
  RecordingPort port;
  AuthorityEndpoint endpoint(port, kDevice);
  const auto envelope = pattern(300);
  std::uint64_t token = 0;
  CHECK(endpoint.try_send(kGateway, AuthorityCarrierKind::Envelope,
                          ByteView{envelope.data(), envelope.size()}, token));
  endpoint.poll(1000);  // manifest and the first 90 B only
  autonomy::ControlObjectPayload manifest{};
  CHECK(autonomy::control_object_decode(
      ByteView{port.queue[0].payload.data(), port.queue[0].payload.size()}, manifest));
  autonomy::ObjectAckPayload ack{};
  ack.object_hash = manifest.object_hash;
  ack.status = autonomy::ObjectAckStatus::Ok;
  ack.received_len = manifest.total_len;
  endpoint.on_ack(kGateway, ack, 1000);
  AuthorityTxResult result{};
  CHECK(!endpoint.take_tx_result(result));
  ack.status = autonomy::ObjectAckStatus::Incomplete;
  ack.received_len = 1;  // an off-grid ACK must not steer the next chunk
  endpoint.on_ack(kGateway, ack, 1000);
  endpoint.poll(1500);
  autonomy::ObjectChunkPayload chunk{};
  CHECK(autonomy::object_chunk_decode(
      ByteView{port.queue.back().payload.data(), port.queue.back().payload.size()}, chunk));
  CHECK(chunk.offset == 0);
}

void test_small_carrier_does_not_claim_old_object_hash() {
  RecordingPort port;
  AuthorityEndpoint endpoint(port, kDevice);
  const auto envelope = pattern(300);
  std::uint64_t token = 0;
  CHECK(endpoint.try_send(kGateway, AuthorityCarrierKind::Envelope,
                          ByteView{envelope.data(), envelope.size()}, token));
  endpoint.poll(1000);
  autonomy::ControlObjectPayload manifest{};
  CHECK(autonomy::control_object_decode(
      ByteView{port.queue[0].payload.data(), port.queue[0].payload.size()}, manifest));
  endpoint.poll(17000);  // the object transfer times out
  AuthorityTxResult result{};
  CHECK(endpoint.take_tx_result(result));
  CHECK(!result.delivered);
  const auto r1 = pattern(60);
  CHECK(endpoint.try_send(kGateway, AuthorityCarrierKind::R1,
                          ByteView{r1.data(), r1.size()}, token));
  CHECK(!endpoint.claim_transfer(kGateway, manifest.object_hash));
  endpoint.poll(17001);
  CHECK(port.queue.back().type == FrameType::Control);
}

void test_gateway_up_path() {
  RecordingPort port;
  RecordingHostSink host;
  RecordingLocalSink local;
  AuthorityGateway gateway(port, host, local, kGateway);
  // One mesh carrier becomes one 0x64 fragment on poll.
  const auto r1 = pattern(60);
  std::array<std::uint8_t, kMaxApplicationPayload> frame{};
  std::size_t written = 0;
  CHECK(authority_carrier_encode(AuthorityCarrierKind::R1, 0x11,
                                 ByteView{r1.data(), r1.size()},
                                 MutableByteView{frame.data(), frame.size()},
                                 written));
  gateway.on_control(kDevice, ByteView{frame.data(), written}, 1000);
  CHECK(!gateway.quiescent());
  gateway.poll(1000);
  CHECK(host.ups.size() == 1);
  CHECK(host.ups[0].device == kDevice);
  CHECK(host.ups[0].transfer_id != 0);
  CHECK(host.ups[0].kind == AuthorityCarrierKind::R1);
  CHECK(host.ups[0].hops == 1);
  CHECK(host.ups[0].total == 60);
  CHECK(host.ups[0].offset == 0);
  CHECK(host.ups[0].data.size() == 60 &&
        std::memcmp(host.ups[0].data.data(), r1.data(), r1.size()) == 0);
  CHECK(gateway.quiescent());
  // A 2048 B mesh object becomes three 0x64 fragments (960/960/128).
  const auto big = pattern(2048, 0x90);
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
  manifest.total_len = 2048;
  // The manifest hash is the sha256 of the bytes; compute it inline.
  {
    ScopeDigest hash{};
    sha256(ByteView{big.data(), big.size()}, hash);
    for (std::size_t i = 0; i < 32; ++i) manifest.object_hash[i] = hash[i];
  }
  gateway.on_manifest(kDevice, manifest, 2000);
  for (std::uint16_t offset = 0; offset < 2048; offset += 90) {
    autonomy::ObjectChunkPayload chunk{};
    chunk.object_hash = manifest.object_hash;
    chunk.offset = offset;
    chunk.data_size = static_cast<std::uint16_t>(offset + 90 <= 2048 ? 90 : 2048 - offset);
    std::memcpy(chunk.data.data(), big.data() + offset, chunk.data_size);
    gateway.on_chunk(kDevice, chunk, 2000);
  }
  const std::size_t ups_before = host.ups.size();
  gateway.poll(2000);
  CHECK(host.ups.size() == ups_before + 3);
  CHECK(host.ups[ups_before].total == 2048);
  CHECK(host.ups[ups_before].offset == 0);
  CHECK(host.ups[ups_before].data.size() == 960);
  CHECK(host.ups[ups_before + 1].offset == 960);
  CHECK(host.ups[ups_before + 1].data.size() == 960);
  CHECK(host.ups[ups_before + 2].offset == 1920);
  CHECK(host.ups[ups_before + 2].data.size() == 128);
  std::vector<std::uint8_t> joined;
  for (std::size_t i = ups_before; i < host.ups.size(); ++i)
    joined.insert(joined.end(), host.ups[i].data.begin(), host.ups[i].data.end());
  CHECK(joined.size() == big.size() &&
        std::memcmp(joined.data(), big.data(), big.size()) == 0);
  CHECK(gateway.quiescent());
}

void test_gateway_down_path() {
  RecordingPort port;
  RecordingHostSink host;
  RecordingLocalSink local;
  AuthorityGateway gateway(port, host, local, kGateway);
  // A small R2 down becomes one mesh carrier with the USB token as the
  // exchange id.
  const auto r2 = pattern(52, 0x70);
  usb::AuthorityFragment fragment{};
  fragment.device = kDevice;
  fragment.transfer_id = 0xA11CE;
  fragment.kind = AuthorityCarrierKind::R2;
  fragment.hops = 0;
  fragment.total = 52;
  fragment.offset = 0;
  fragment.data = ByteView{r2.data(), r2.size()};
  bool complete = false;
  CHECK(gateway.authority_down(kDevice, fragment, complete, 1000));
  CHECK(complete);  // single-fragment object
  gateway.poll(1000);
  CHECK(port.sends == 1);
  CHECK(port.queue[0].dest == kDevice);
  CHECK(port.queue[0].type == FrameType::Control);
  CHECK(port.queue[0].now == 1000);
  AuthorityCarrierKind kind{AuthorityCarrierKind::Envelope};
  std::uint32_t exchange = 0;
  ByteView body{};
  CHECK(authority_carrier_decode(
      ByteView{port.queue[0].payload.data(), port.queue[0].payload.size()}, kind,
      exchange, body));
  CHECK(kind == AuthorityCarrierKind::R2);
  CHECK(exchange == fragment.transfer_id);
  CHECK(body.size == r2.size() && std::memcmp(body.data, r2.data(), r2.size()) == 0);
  CHECK(gateway.quiescent());
  // A three-fragment envelope down becomes a kind-7 mesh transfer.
  const auto envelope = pattern(1500, 0x20);
  port.queue.clear();
  for (const std::uint16_t offset : {0, 960}) {
    fragment.transfer_id = 0xBEEF;
    fragment.kind = AuthorityCarrierKind::Envelope;
    fragment.total = 1500;
    fragment.offset = offset;
    const std::size_t length = offset == 0 ? 960 : 540;
    fragment.data = ByteView{envelope.data() + offset, length};
    complete = false;
    CHECK(gateway.authority_down(kDevice, fragment, complete, 2000));
    CHECK(!complete || offset != 0);
  }
  CHECK(complete);
  gateway.poll(2000);
  CHECK(port.sends >= 2);  // manifest + first chunk
  CHECK(port.queue[0].type == FrameType::ControlObject);
  autonomy::ControlObjectPayload manifest{};
  CHECK(autonomy::control_object_decode(
      ByteView{port.queue[0].payload.data(), port.queue[0].payload.size()},
      manifest));
  CHECK(manifest.kind == autonomy::ControlObjectKind::AuthorityEnvelope);
  CHECK(manifest.total_len == 1500);
  CHECK(port.queue[1].type == FrameType::ObjectChunk);
  autonomy::ObjectAckPayload premature{};
  premature.object_hash = manifest.object_hash;
  premature.status = autonomy::ObjectAckStatus::Ok;
  premature.received_len = manifest.total_len;
  gateway.on_ack(kDevice, premature, 2000);
  CHECK(!gateway.quiescent());
  premature.status = autonomy::ObjectAckStatus::Incomplete;
  premature.received_len = 1;
  gateway.on_ack(kDevice, premature, 2000);
  gateway.poll(2500);
  autonomy::ObjectChunkPayload retry{};
  CHECK(autonomy::object_chunk_decode(
      ByteView{port.queue.back().payload.data(), port.queue.back().payload.size()}, retry));
  CHECK(retry.offset == 0);
  // Rewriting the token's bytes mid-transfer is a Conflict, not a merge.
  fragment.transfer_id = 0xCAFE;
  fragment.total = 1500;
  fragment.offset = 0;
  const auto first = pattern(960, 0x01);
  fragment.data = ByteView{first.data(), first.size()};
  CHECK(gateway.authority_down(kDevice, fragment, complete, 3000));
  CHECK(!complete);
  auto tampered = first;
  tampered[0] ^= 0xFF;
  fragment.data = ByteView{tampered.data(), tampered.size()};
  CHECK(!gateway.authority_down(kDevice, fragment, complete, 3000));
  // A zero-token down never stages.
  fragment.device = kDevice;
  fragment.transfer_id = 0;
  CHECK(!gateway.authority_down(kDevice, fragment, complete, 3000));
}

void test_gateway_self_down() {
  RecordingPort port;
  RecordingHostSink host;
  RecordingLocalSink local;
  AuthorityGateway gateway(port, host, local, kGateway);
  // Self-addressed downs reassemble in a slot and deliver to the local
  // client on poll — never back onto the mesh.
  const auto envelope = pattern(1500, 0x33);
  usb::AuthorityFragment fragment{};
  fragment.device = kGateway;
  fragment.transfer_id = 0x5E1F;
  fragment.kind = AuthorityCarrierKind::Envelope;
  fragment.hops = 0;
  fragment.total = 1500;
  fragment.offset = 0;
  fragment.data = ByteView{envelope.data(), 960};
  bool complete = false;
  CHECK(gateway.authority_down(kGateway, fragment, complete, 1000));
  CHECK(!complete);
  fragment.offset = 960;
  fragment.data = ByteView{envelope.data() + 960, 540};
  CHECK(gateway.authority_down(kGateway, fragment, complete, 1000));
  CHECK(complete);
  CHECK(local.downs.empty());  // delivery happens on poll, not in RX
  gateway.poll(1000);
  CHECK(local.downs.size() == 1);
  CHECK(local.downs[0].kind == AuthorityCarrierKind::Envelope);
  CHECK(local.downs[0].bytes.size() == envelope.size() &&
        std::memcmp(local.downs[0].bytes.data(), envelope.data(), envelope.size()) == 0);
  CHECK(port.sends == 0);  // nothing looped onto the mesh
  CHECK(gateway.quiescent());

  // The Owner has one verified-message staging slot. Two completed local
  // downs remain ordered across polls so neither authenticated body is lost.
  const auto first = pattern(1500, 0x51);
  const auto second = pattern(1500, 0x81);
  const auto stage = [&](const std::vector<std::uint8_t>& body,
                         const std::uint32_t transfer) {
    fragment.kind = AuthorityCarrierKind::Envelope;
    fragment.total = 1500;
    fragment.transfer_id = transfer;
    fragment.offset = 0;
    fragment.data = ByteView{body.data(), 960};
    CHECK(gateway.authority_down(kGateway, fragment, complete, 2000));
    CHECK(!complete);
    fragment.offset = 960;
    fragment.data = ByteView{body.data() + 960, 540};
    CHECK(gateway.authority_down(kGateway, fragment, complete, 2000));
    CHECK(complete);
  };
  stage(first, 0x5E20);
  stage(second, 0x5E21);
  gateway.poll(2000);
  CHECK(local.downs.size() == 2);
  if (local.downs.size() >= 2) CHECK(local.downs[1].bytes == first);
  gateway.poll(2001);
  CHECK(local.downs.size() == 3);
  if (local.downs.size() >= 3) CHECK(local.downs[2].bytes == second);
  CHECK(gateway.quiescent());
}

void test_gateway_slot_exhaustion() {
  RecordingPort port;
  RecordingHostSink host;
  RecordingLocalSink local;
  AuthorityGateway gateway(port, host, local, kGateway);
  const auto r1 = pattern(60);
  std::array<std::uint8_t, kMaxApplicationPayload> frame{};
  std::size_t written = 0;
  CHECK(authority_carrier_encode(AuthorityCarrierKind::R1, 0x11,
                                 ByteView{r1.data(), r1.size()},
                                 MutableByteView{frame.data(), frame.size()},
                                 written));
  // Two slots: two carriers hold; the third is denied, never evicted.
  gateway.on_control(kDevice, ByteView{frame.data(), written}, 1000);
  gateway.on_control(0x3333, ByteView{frame.data(), written}, 1000);
  gateway.on_control(0x4444, ByteView{frame.data(), written}, 1000);
  CHECK(gateway.counters().denied == 1);
  CHECK(!gateway.quiescent());
  // A down also refuses Busy while both slots are live.
  usb::AuthorityFragment fragment{};
  fragment.device = kDevice;
  fragment.transfer_id = 0x1234;
  fragment.kind = AuthorityCarrierKind::R2;
  fragment.total = 52;
  const auto r2 = pattern(52);
  fragment.data = ByteView{r2.data(), r2.size()};
  bool complete = false;
  const Status busy = gateway.authority_down(kDevice, fragment, complete, 1000);
  CHECK(!busy && busy.code == StatusCode::Busy);
  // Draining one slot frees it for the down.
  gateway.poll(1000);
  CHECK(host.ups.size() == 2);
  CHECK(gateway.authority_down(kDevice, fragment, complete, 1100));
  // USB session death drops everything, honestly idle afterwards.
  CHECK(!gateway.quiescent());
  gateway.drop_all();
  CHECK(gateway.quiescent());
}

void test_gateway_direct_down_rejects_noncanonical_fragments() {
  RecordingPort port;
  RecordingHostSink host;
  RecordingLocalSink local;
  AuthorityGateway gateway(port, host, local, kGateway);
  const auto bytes = pattern(960);
  usb::AuthorityFragment fragment{};
  fragment.device = kDevice;
  fragment.transfer_id = 7;
  fragment.kind = AuthorityCarrierKind::Envelope;
  fragment.total = 2049;
  fragment.data = ByteView{bytes.data(), bytes.size()};
  bool complete = false;
  CHECK(!gateway.authority_down(kDevice, fragment, complete, 1000));
  CHECK(gateway.quiescent());
  fragment.total = 1500;
  fragment.data = ByteView{bytes.data(), 959};
  CHECK(!gateway.authority_down(kDevice, fragment, complete, 1000));
  CHECK(gateway.quiescent());
  fragment.data = ByteView{bytes.data(), bytes.size()};
  fragment.offset = 1;
  CHECK(!gateway.authority_down(kDevice, fragment, complete, 1000));
  CHECK(gateway.quiescent());
  fragment.offset = 0;
  fragment.device = kBroadcastNodeId;
  CHECK(!gateway.authority_down(kBroadcastNodeId, fragment, complete, 1000));
  CHECK(gateway.quiescent());
}

void test_config_target_authority_hook() {
  RecordingPort port;
  ConfigRateLimiter limiter;
  ConfigTarget target(port, limiter);
  AuthorityEndpoint endpoint(port, kGateway);
  // Without the demux attached, subtype 9 is denied like any unknown.
  const auto wake = pattern(8);
  std::array<std::uint8_t, kMaxApplicationPayload> frame{};
  std::size_t written = 0;
  CHECK(authority_carrier_encode(AuthorityCarrierKind::Wake, 0,
                                 ByteView{wake.data(), wake.size()},
                                 MutableByteView{frame.data(), frame.size()},
                                 written));
  const std::uint32_t denied_before = target.control_denied();
  target.on_config_frame(kDevice,
                         terminal_frame(kDevice, kGateway, FrameType::Control,
                                        ByteView{frame.data(), written}),
                         1000);
  CHECK(target.control_denied() == denied_before + 1);
  // Attached: the carrier reaches the endpoint, a config subtype still
  // takes the config path (denied here for lack of a journal).
  target.attach_authority(&endpoint);
  target.on_config_frame(kDevice,
                         terminal_frame(kDevice, kGateway, FrameType::Control,
                                        ByteView{frame.data(), written}),
                         1000);
  AuthorityRxCarrier rx{};
  CHECK(endpoint.take_rx(rx));
  CHECK(rx.kind == AuthorityCarrierKind::Wake && rx.bytes.size == 8);
  CHECK(target.control_denied() == denied_before + 1);  // no new deny
  // A kind-7 manifest routes to the endpoint and is acked Incomplete.
  const auto envelope = pattern(500, 0x55);
  ScopeDigest hash{};
  sha256(ByteView{envelope.data(), envelope.size()}, hash);
  autonomy::ControlObjectPayload manifest{};
  manifest.kind = autonomy::ControlObjectKind::AuthorityEnvelope;
  manifest.total_len = 500;
  for (std::size_t i = 0; i < 32; ++i) manifest.object_hash[i] = hash[i];
  autonomy::EncodedPayload encoded{};
  CHECK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kDevice,
                         terminal_frame(kDevice, kGateway, FrameType::ControlObject,
                                        encoded.view()),
                         2000);
  CHECK(port.sends == 1);
  CHECK(port.queue[0].type == FrameType::ObjectAck);
  // A config chunk from a different end-authenticated origin may carry the
  // same hash. It must stay on the config path rather than enter this
  // authority assembly.
  autonomy::ObjectChunkPayload chunk{};
  chunk.object_hash = manifest.object_hash;
  chunk.offset = 0;
  chunk.data_size = 90;
  std::memcpy(chunk.data.data(), envelope.data(), chunk.data_size);
  CHECK(autonomy::object_chunk_encode(chunk, encoded));
  const std::uint32_t authority_denied = endpoint.counters().rx_denied;
  target.on_config_frame(0x3333,
                         terminal_frame(0x3333, kGateway, FrameType::ObjectChunk,
                                        encoded.view()),
                         2100);
  CHECK(target.control_denied() == denied_before + 2);
  CHECK(endpoint.counters().rx_denied == authority_denied);
  CHECK(port.sends == 1);
  target.on_config_frame(kDevice,
                         terminal_frame(kDevice, kGateway, FrameType::ObjectChunk,
                                        encoded.view()),
                         2200);
  CHECK(port.sends == 2);
  // A kind-5 manifest still takes the config path (no trust store here).
  manifest.kind = autonomy::ControlObjectKind::TrustManifest;
  CHECK(autonomy::control_object_encode(manifest, encoded));
  target.on_config_frame(kDevice,
                         terminal_frame(kDevice, kGateway, FrameType::ControlObject,
                                        encoded.view()),
                         2000);
  CHECK(endpoint.counters().rx_denied == 0);
  // Detaching restores deny-and-drop for subtype 9.
  target.attach_authority(nullptr);
  target.on_config_frame(kDevice,
                         terminal_frame(kDevice, kGateway, FrameType::Control,
                                        ByteView{frame.data(), written}),
                         3000);
  CHECK(target.control_denied() == denied_before + 3);
}

}  // namespace

int main() {
  test_carrier_codec();
  test_endpoint_small_carrier();
  test_endpoint_object_round_trip();
  test_endpoint_object_timeout();
  test_endpoint_rx_rules();
  test_object_chunks_require_contiguous_grid();
  test_object_ack_requires_sent_progress();
  test_small_carrier_does_not_claim_old_object_hash();
  test_gateway_up_path();
  test_gateway_down_path();
  test_gateway_self_down();
  test_gateway_slot_exhaustion();
  test_gateway_direct_down_rejects_noncanonical_fragments();
  test_config_target_authority_hook();
  if (failures != 0) {
    std::fprintf(stderr, "%d authority-transport checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom authority-transport tests passed");
  return 0;
}
