// Fuzz target: SDK v1 zero-touch join transport (plan P3-1/P3-2) —
// components/routeloom/src/sdkv1_join_transport.cpp and sdkv1_join_relay.cpp.
//
// Codec half: every decoder sees the raw input (RLD1 DISCOVER/OFFER v3
// frames, BootstrapAuth phase 4-6 objects, chunks and replies on both
// carriers, relay objects, the USB 0x60-0x63 bodies). A successful decode
// is re-encoded and must reproduce the input (one encoding per value); a
// decoded view must stay inside the input.
//
// Engine half: the input is also read as a script of length-prefixed frames
// (u16 length | frame). Selector bit 0 of the first byte picks the carrier:
// RLD1 frames go to a JoinProxy and a ZtJoinerLink, Wire relay frames
// (u8 FrameType | payload) to a JoinRelayGateway and a JoinProxy, with the
// clock advancing between frames so every timeout path runs. The engines
// must never crash, never hold more than their bounded slots and never hand
// the host an object that fails to decode.
//
// Seeds: tests/fuzz/corpus/sdkv1_join, written by
// tools/gen_sdkv1_join_transport_vectors.py from the shared golden vectors.

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "routeloom/bootstrap_transport.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/sdkv1_join_relay.hpp"
#include "routeloom/sdkv1_join_transport.hpp"
#include "routeloom/usb_host_ops.hpp"

#include "fuzz_driver.hpp"

namespace {

using namespace routeloom;
using namespace routeloom::sdkv1;

void require_same(const ByteView encoded, const ByteView input) {
  if (encoded.size != input.size ||
      (input.size != 0 && std::memcmp(encoded.data, input.data, input.size) != 0)) {
    std::abort();  // decode accepted a non-canonical encoding
  }
}

bool inside(const ByteView part, const ByteView whole) {
  if (part.size == 0) return true;
  return part.data >= whole.data && part.data + part.size <= whole.data + whole.size;
}

class FixedEntropy final : public EntropySource {
 public:
  Status fill(const MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) out.data[i] = next_++;
    return Status::success();
  }

 private:
  std::uint8_t next_{1};
};

class NullRadio final : public ZtRld1Port {
 public:
  Status send_rld1(const MacAddress&, const ByteView frame) noexcept override {
    autonomy::Rld1Envelope env{};
    if (!autonomy::rld1_decode(frame, env).ok()) std::abort();  // engines emit valid RLD1
    return Status::success();
  }
};

class NullWire final : public ZtRelayPort {
 public:
  Status send_relay(NodeId, const FrameType, const ByteView payload) noexcept override {
    if (payload.size > kMaxApplicationPayload) std::abort();  // one Wire payload at most
    return Status::success();
  }
};

class CheckingHost final : public JoinRelayHostSink {
 public:
  Status relay_up(const NodeId proxy, std::uint8_t, const ByteView object) noexcept override {
    RelayObject decoded{};
    if (!relay_object_decode(object, decoded).ok() || decoded.header.proxy != proxy ||
        decoded.header.dir != RelayDirection::Up) {
      std::abort();
    }
    return Status::success();
  }
  Status relay_abort(NodeId, RelayToken, RelayAbortReason) noexcept override {
    return Status::success();
  }
};

class NullObserver final : public ZtJoinerObserver {
 public:
  void on_offer(const ZtOfferView&) noexcept override {}
  void on_message(JoinAuthPhase, std::uint8_t, const ByteView message) noexcept override {
    if (message.size == 0 || message.size > kJoinMessageMax) std::abort();
  }
  void on_relay_status(RelayStatusCode, std::uint32_t) noexcept override {}
  void on_link_failure(const char*) noexcept override {}
};

void codecs(const ByteView input) {
  std::array<std::uint8_t, 2048> out{};
  std::size_t written = 0;
  const MutableByteView sink{out.data(), out.size()};

  autonomy::Rld1Envelope env{};
  ZtDiscoverBody discover{};
  if (zt_discover_frame_decode(input, env, discover).ok()) {
    autonomy::Rld1Encoded again{};
    if (!zt_discover_frame_encode(env.claimed_node, env.transaction_nonce, discover, again).ok()) {
      std::abort();
    }
    require_same(again.view(), input);
  }
  ZtOfferBody offer{};
  if (zt_offer_frame_decode(input, env, offer).ok()) {
    autonomy::Rld1Encoded again{};
    if (!zt_offer_frame_encode(env.claimed_node, env.network_hint, env.transaction_nonce, offer,
                               again)
             .ok()) {
      std::abort();
    }
    require_same(again.view(), input);
  }
  if (autonomy::rld1_decode(input, env).ok() && zt_rld1_frame(env)) {
    for (const MembershipState state :
         {MembershipState::Discovering, MembershipState::Authenticating, MembershipState::Member}) {
      (void)zt_admit_rld1(state, AdmissionDirection::Rx, env);
      (void)zt_admit_rld1(state, AdmissionDirection::Tx, env);
    }
  }

  JoinAuthObject object{};
  if (join_object_decode(input, object).ok()) {
    if (!inside(object.message, input)) std::abort();
    if (!join_object_encode(object, sink, written).ok()) std::abort();
    require_same(ByteView{out.data(), written}, input);
  }
  for (const JoinCarrier carrier : {JoinCarrier::Rld1, JoinCarrier::WireRelay}) {
    JoinChunk chunk{};
    if (join_chunk_decode(carrier, input, chunk).ok()) {
      if (!inside(chunk.data, input)) std::abort();
      if (!join_chunk_encode(carrier, chunk, sink, written).ok()) std::abort();
      require_same(ByteView{out.data(), written}, input);
      JoinObjectSlot slot{};
      const JoinObjectSlot::Accepted accepted = slot.accept(carrier, chunk, 0);
      if (accepted.outcome != JoinObjectSlot::Outcome::Progress &&
          accepted.outcome != JoinObjectSlot::Outcome::Complete) {
        std::abort();  // a well-formed chunk always starts an empty slot
      }
    }
  }
  for (const JoinCarrier carrier : {JoinCarrier::Rld1, JoinCarrier::WireRelay}) {
    JoinReply reply{};
    if (join_reply_decode(carrier, input, reply).ok()) {
      if (!join_reply_encode(carrier, reply, sink, written).ok()) std::abort();
      require_same(ByteView{out.data(), written}, input);
    }
  }
  // P4 §7.3: the routed end-session object shares the chunk carriers but
  // never an assembly — the lane bit in the sub byte selects it.
  EndObject end{};
  if (end_object_decode(input, end).ok()) {
    if (!inside(end.message, input)) std::abort();
    if (!end_object_encode(end, sink, written).ok()) std::abort();
    require_same(ByteView{out.data(), written}, input);
    EndObject single{};
    (void)end_single_frame_decode(FrameType::BootstrapAuth, input, single);
    if (end_single_frame_decode(FrameType::MembershipResult, input, single).ok()) {
      std::abort();  // type 4 never carries an end object
    }
  }
  RelayObject relay{};
  if (relay_object_decode(input, relay).ok()) {
    if (!inside(relay.message, input)) std::abort();
    if (!relay_object_encode(relay, sink, written).ok()) std::abort();
    require_same(ByteView{out.data(), written}, input);
    RelayObject single{};
    (void)relay_single_frame_decode(relay_single_frame_type(relay.header), input, single);
  }
  EpochQuery query{};
  if (epoch_query_decode(input, query).ok()) {
    if (!epoch_query_encode(query, sink, written).ok()) std::abort();
    require_same(ByteView{out.data(), written}, input);
  }
  EpochReply epoch_reply{};
  if (epoch_reply_decode(input, epoch_reply).ok()) {
    if (!epoch_reply_encode(epoch_reply, sink, written).ok()) std::abort();
    require_same(ByteView{out.data(), written}, input);
  }
  (void)classify_wire_relay(input);

  usb::JoinRelayUp up{};
  if (usb::decode_join_relay_up(input, up).ok()) {
    if (!inside(up.object, input) || !usb::encode_join_relay_up(up, sink, written).ok()) {
      std::abort();
    }
    require_same(ByteView{out.data(), written}, input);
  }
  usb::JoinRelayDown down{};
  if (usb::decode_join_relay_down(input, down).ok()) {
    if (!inside(down.object, input) || !usb::encode_join_relay_down(down, sink, written).ok()) {
      std::abort();
    }
    require_same(ByteView{out.data(), written}, input);
  }
  usb::JoinRelayAbort abort_body{};
  if (usb::decode_join_relay_abort(input, abort_body).ok()) {
    if (!usb::encode_join_relay_abort(abort_body, sink, written).ok()) std::abort();
    require_same(ByteView{out.data(), written}, input);
  }
  usb::JoinRelayResult result{};
  if (usb::decode_join_relay_result(input, result).ok()) {
    if (!usb::encode_join_relay_result(result, sink, written).ok()) std::abort();
    require_same(ByteView{out.data(), written}, input);
  }
}

constexpr NodeId kGateway = 0x00A1000000000001;
constexpr NodeId kProxy = 0x00A1000000000777;
constexpr MacAddress kProxyMac{{0x02, 0, 0, 0, 0x07, 0x77}};
constexpr MacAddress kDeviceMac{{0x02, 0, 0, 0, 0x12, 0x34}};
constexpr MacAddress kBroadcast{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};

void engines(const ByteView input) {
  if (input.size < 1) return;
  NullRadio radio;
  NullWire wire;
  FixedEntropy entropy;
  std::array<std::uint8_t, 32> key{};
  HmacJoinCookie cookie(key);
  JoinProxyConfig proxy_config{};
  proxy_config.node = kProxy;
  proxy_config.mac = kProxyMac;
  proxy_config.network_low32 = 0x0A1B2C3D;
  proxy_config.gateway = kGateway;
  proxy_config.proxy_epoch = 3;
  JoinProxy proxy(proxy_config, radio, wire, cookie, entropy);
  proxy.set_membership(MembershipState::Member, 0);
  proxy.set_policy(true);
  proxy.set_authority(true, 2, 0);
  JoinRelayGatewayConfig gateway_config{};
  gateway_config.node = kGateway;
  gateway_config.gateway_epoch = 7;
  JoinRelayGateway gateway(gateway_config, wire);
  gateway.set_membership(MembershipState::Member);
  CheckingHost host;
  gateway.set_host_sink(&host);
  NullObserver observer;
  ZtJoinerConfig joiner_config{};
  joiner_config.node = 0x00A1000000001234;
  joiner_config.mac = kDeviceMac;
  ZtJoinerLink joiner(joiner_config, radio, entropy, observer);
  joiner.set_membership(MembershipState::Authenticating);

  const bool wire_script = (input.data[0] & 1U) != 0;
  MonotonicMs now = 0;
  std::size_t pos = 1;
  while (pos + 2 <= input.size) {
    const std::size_t length =
        (static_cast<std::size_t>(input.data[pos]) << 8U) | input.data[pos + 1];
    pos += 2;
    if (length > input.size - pos) break;
    const ByteView frame{input.data + pos, length};
    pos += length;
    now += 1 + (length & 0x3FFU) * 7;  // lets assemblies, cookies and relays time out
    if (wire_script) {
      if (frame.size < 1) continue;
      const auto type = static_cast<FrameType>(frame.data[0]);
      const ByteView payload{frame.data + 1, frame.size - 1};
      gateway.on_relay_rx(kProxy, 2, type, payload, now);
      proxy.on_relay_rx(kGateway, type, payload, now);
      RelayObject object{};
      if (relay_object_decode(payload, object).ok() && object.header.dir == RelayDirection::Down) {
        (void)gateway.host_down(object.header.proxy, payload, now);
      }
    } else {
      proxy.on_rld1_rx(kDeviceMac, (length & 1U) != 0 ? kBroadcast : kProxyMac, -60, frame, now);
      joiner.on_rld1_rx(kProxyMac, kDeviceMac, frame, now);
    }
    proxy.poll(now);
    gateway.poll(now);
    joiner.poll(now);
    if (gateway.slots_in_use() > JoinRelayGateway::kSlots) std::abort();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size > 4096) return 0;
  const ByteView input{data, size};
  codecs(input);
  engines(input);
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
