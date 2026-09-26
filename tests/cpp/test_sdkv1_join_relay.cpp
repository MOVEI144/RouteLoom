// SDK v1 zero-touch join transport engines (plan P3-1/P3-2) end to end in a
// host simulation: an unassigned device (ZtJoinerLink) reaches a fake Site
// Authority through a member proxy (JoinProxy, RLD1 <-> Wire relay) and a
// gateway (JoinRelayGateway, Wire relay <-> host sink). The Wire relay is a
// direct port here (the harness reports 3 mesh hops); MeshNode routing of
// FrameTypes 3-6 is the owner's wiring and not simulated.
//
// Acceptance covered: V1-J02 (multi-hop relay, proxy slot released after the
// final object), V1-J10 (proxy busy / authority unreachable: hints only, no
// state change on the device), V1-J11 (pre-auth flood: one relay per proxy,
// one m1 per 2 s, cookie before any memory, bounded OFFER queue — the "member
// DATA keeps flowing" half needs the MeshNode wiring and is not claimed).

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <functional>
#include <string>
#include <vector>

#include "routeloom/discovery.hpp"
#include "routeloom/sdkv1_join_relay.hpp"

namespace {

int failures = 0;
std::string current;
#define CHECK(expr)                                                                  \
  do {                                                                               \
    if (!(expr)) {                                                                   \
      std::fprintf(stderr, "CHECK failed %s:%d [%s]: %s\n", __FILE__, __LINE__,      \
                   current.c_str(), #expr);                                          \
      ++failures;                                                                    \
    }                                                                                \
  } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;
using Bytes = std::vector<std::uint8_t>;

constexpr NodeId kGateway = 0x00A1000000000001;
constexpr NodeId kProxy = 0x00A1000000000777;
constexpr NodeId kDevice = 0x00A1000000001234;
constexpr std::uint32_t kNetworkLow32 = 0x0A1B2C3D;
constexpr std::uint32_t kOrgHint = 0x6F726721;
constexpr std::uint32_t kSiteHint = 0x51734242;
constexpr MacAddress kProxyMac{{0x02, 0, 0, 0, 0x07, 0x77}};
constexpr MacAddress kBroadcast{{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}};
constexpr std::uint32_t kGatewayEpoch = 7;
constexpr std::uint32_t kProxyEpoch = 3;

MacAddress device_mac(const std::uint8_t index) { return MacAddress{{0x02, 0, 0, 0, 0x12, index}}; }

Bytes filler(const std::size_t size, const std::uint8_t seed) {
  Bytes out(size);
  for (std::size_t i = 0; i < size; ++i) out[i] = static_cast<std::uint8_t>(seed + i * 31U);
  return out;
}

ByteView view(const Bytes& bytes) { return ByteView{bytes.data(), bytes.size()}; }

class CounterEntropy final : public EntropySource {
 public:
  explicit CounterEntropy(const std::uint8_t seed) : next_(seed) {}
  Status fill(const MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) out.data[i] = next_++;
    return Status::success();
  }

 private:
  std::uint8_t next_{0};
};

struct RadioFrame {
  MacAddress from{};
  MacAddress to{};
  Bytes bytes;
};

struct WireFrame {
  NodeId from{kInvalidNodeId};
  NodeId to{kInvalidNodeId};
  FrameType type{FrameType::Data};
  Bytes payload;
};

class RadioPort final : public ZtRld1Port {
 public:
  RadioPort(std::deque<RadioFrame>& air, const MacAddress& self) : air_(air), self_(self) {}
  Status send_rld1(const MacAddress& destination, const ByteView frame) noexcept override {
    if (refuse) return Status::error(StatusCode::NoRoute, "radio unavailable");
    air_.push_back(RadioFrame{self_, destination, Bytes(frame.data, frame.data + frame.size)});
    return Status::success();
  }
  bool refuse{false};

 private:
  std::deque<RadioFrame>& air_;
  MacAddress self_;
};

class WirePort final : public ZtRelayPort {
 public:
  WirePort(std::deque<WireFrame>& mesh, const NodeId self) : mesh_(mesh), self_(self) {}
  Status send_relay(const NodeId destination, const FrameType type,
                    const ByteView payload) noexcept override {
    if (refuse) return Status::error(StatusCode::NoRoute, "no route");
    mesh_.push_back(WireFrame{self_, destination, type, Bytes(payload.data, payload.data + payload.size)});
    return Status::success();
  }
  bool refuse{false};

 private:
  std::deque<WireFrame>& mesh_;
  NodeId self_;
};

struct DeviceObserver final : ZtJoinerObserver {
  void on_offer(const ZtOfferView& offer) noexcept override { offers.push_back(offer); }
  void on_message(const JoinAuthPhase phase, const std::uint8_t step,
                  const ByteView message) noexcept override {
    messages.push_back({phase, step, Bytes(message.data, message.data + message.size)});
    if (respond) respond(messages.back());
  }
  void on_relay_status(const RelayStatusCode status, const std::uint32_t retry) noexcept override {
    statuses.push_back({status, retry});
  }
  void on_link_failure(const char* reason) noexcept override { failures_seen.push_back(reason); }

  struct Message {
    JoinAuthPhase phase;
    std::uint8_t step;
    Bytes bytes;
  };
  std::vector<ZtOfferView> offers;
  std::vector<Message> messages;
  std::vector<std::pair<RelayStatusCode, std::uint32_t>> statuses;
  std::vector<std::string> failures_seen;
  // Optional hook run inside on_message to verify the callback contract.
  std::function<void(const Message&)> respond;
};

// The host side of 0x60/0x62: records what the gateway hands up.
struct FakeAuthority final : JoinRelayHostSink {
  Status relay_up(const NodeId proxy, const std::uint8_t hops, const ByteView object) noexcept override {
    if (refuse) return Status::error(StatusCode::NoCapacity, "host queue full");
    ups.push_back({proxy, hops, Bytes(object.data, object.data + object.size)});
    if (on_up) on_up(ups.back());  // reentry must be refused
    return Status::success();
  }
  Status relay_abort(const NodeId proxy, const RelayToken token,
                     const RelayAbortReason reason) noexcept override {
    aborts.push_back({proxy, token, reason});
    if (on_abort) on_abort(aborts.back());  // reentry must be refused
    return Status::success();
  }
  struct Up {
    NodeId proxy;
    std::uint8_t hops;
    Bytes object;
  };
  struct Abort {
    NodeId proxy;
    RelayToken token;
    RelayAbortReason reason;
  };
  std::vector<Up> ups;
  std::vector<Abort> aborts;
  bool refuse{false};
  // Optional hooks run inside the callbacks (the gateway must refuse
  // reentry from them; the recorded copy stays valid).
  std::function<void(const Up&)> on_up;
  std::function<void(const Abort&)> on_abort;
};

Bytes down_object(const RelayHeader& up, const std::uint8_t step, const RelayState state,
                  const Bytes& message) {
  RelayObject object{};
  object.header = up;
  object.header.dir = RelayDirection::Down;
  object.header.step = step;
  object.header.state = state;
  object.header.joiner_rssi_dbm = 0;
  object.message = view(message);
  Bytes out(kJoinObjectMax);
  std::size_t written = 0;
  CHECK(relay_object_encode(object, MutableByteView{out.data(), out.size()}, written).ok());
  out.resize(written);
  return out;
}

Bytes abort_object(const RelayHeader& up, const RelayStatusCode status, const std::uint32_t retry) {
  RelayObject object{};
  object.header = up;
  object.header.dir = RelayDirection::Down;
  object.header.state = RelayState::Abort;
  object.header.joiner_rssi_dbm = 0;
  object.abort.status = status;
  object.abort.retry_after_ms = retry;
  Bytes out(kRelayHeaderSize + kRelayAbortBodySize);
  std::size_t written = 0;
  CHECK(relay_object_encode(object, MutableByteView{out.data(), out.size()}, written).ok());
  return out;
}

RelayObject parse_up(const Bytes& bytes) {
  RelayObject object{};
  CHECK(relay_object_decode(view(bytes), object).ok());
  return object;
}

// One device, one proxy, one gateway, one authority.
struct World {
  explicit World(const std::size_t devices = 1)
      : proxy_radio(air, kProxyMac),
        proxy_wire(mesh, kProxy),
        gateway_wire(mesh, kGateway),
        cookie_sealer(cookie_key()),
        proxy_entropy(0x40),
        proxy(proxy_config(), proxy_radio, proxy_wire, cookie_sealer, proxy_entropy),
        gateway(gateway_config(), gateway_wire) {
    for (std::size_t i = 0; i < devices; ++i) {
      radios.emplace_back(new RadioPort(air, device_mac(static_cast<std::uint8_t>(i))));
      entropies.emplace_back(new CounterEntropy(static_cast<std::uint8_t>(0x10 + 0x20 * i)));
      observers.emplace_back(new DeviceObserver());
      ZtJoinerConfig config{};
      config.node = kDevice + i;
      config.mac = device_mac(static_cast<std::uint8_t>(i));
      config.org_hint = kOrgHint;
      links.emplace_back(new ZtJoinerLink(config, *radios.back(), *entropies.back(),
                                          *observers.back()));
      links.back()->set_membership(MembershipState::Discovering);
    }
    proxy.set_membership(MembershipState::Member, 0);
    proxy.set_policy(true);
    proxy.set_authority(true, 3, 0);
    gateway.set_membership(MembershipState::Member);
    gateway.set_host_sink(&authority);
  }
  ~World() {
    for (auto* p : links) delete p;
    for (auto* p : observers) delete p;
    for (auto* p : entropies) delete p;
    for (auto* p : radios) delete p;
  }
  World(const World&) = delete;
  World& operator=(const World&) = delete;

  static std::array<std::uint8_t, 32> cookie_key() {
    std::array<std::uint8_t, 32> key{};
    for (std::size_t i = 0; i < key.size(); ++i) key[i] = static_cast<std::uint8_t>(0xA0 + i);
    return key;
  }
  static JoinProxyConfig proxy_config() {
    JoinProxyConfig config{};
    config.node = kProxy;
    config.mac = kProxyMac;
    config.network_low32 = kNetworkLow32;
    config.org_hint = kOrgHint;
    config.site_hint = kSiteHint;
    config.gateway = kGateway;
    config.proxy_epoch = kProxyEpoch;
    return config;
  }
  static JoinRelayGatewayConfig gateway_config() {
    JoinRelayGatewayConfig config{};
    config.node = kGateway;
    config.gateway_epoch = kGatewayEpoch;
    return config;
  }

  // Deliver everything in flight (subject to the filters), then poll.
  void pump(const std::size_t rounds = 64) {
    for (std::size_t round = 0; round < rounds && (!air.empty() || !mesh.empty()); ++round) {
      std::deque<RadioFrame> radio;
      radio.swap(air);
      if (reverse_radio) std::reverse(radio.begin(), radio.end());
      for (const RadioFrame& frame : radio) {
        ++radio_frames;
        if (drop_radio && drop_radio(frame)) continue;
        const ByteView bytes = view(frame.bytes);
        if (frame.from != kProxyMac && (frame.to == kProxyMac || frame.to == kBroadcast)) {
          proxy.on_rld1_rx(frame.from, frame.to, -61, bytes, now);
        }
        for (std::size_t i = 0; i < links.size(); ++i) {
          const MacAddress mac = device_mac(static_cast<std::uint8_t>(i));
          if (frame.from != mac && (frame.to == mac || frame.to == kBroadcast)) {
            links[i]->on_rld1_rx(frame.from, frame.to, bytes, now);
          }
        }
      }
      std::deque<WireFrame> wire;
      wire.swap(mesh);
      for (const WireFrame& frame : wire) {
        ++wire_frames;
        if (drop_wire && drop_wire(frame)) continue;
        if (frame.to == kGateway) {
          gateway.on_relay_rx(frame.from, 3, frame.type, view(frame.payload), now);
        } else if (frame.to == kProxy) {
          proxy.on_relay_rx(frame.from, frame.type, view(frame.payload), now);
        }
      }
    }
  }
  void advance(const MonotonicMs ms, const MonotonicMs step = 50) {
    for (MonotonicMs t = 0; t < ms; t += step) {
      now += step;
      proxy.poll(now);
      gateway.poll(now);
      for (auto* link : links) link->poll(now);
      pump();
    }
  }

  // Discover + connect device `i` to the proxy.
  bool connect(const std::size_t i = 0) {
    ZtDiscoverBody body{};
    body.org_hint = kOrgHint;
    observers[i]->offers.clear();
    if (!links[i]->discover(body, now)) return false;
    pump();
    advance(400);  // OFFER slot (<= 320 ms)
    if (observers[i]->offers.empty()) return false;
    links[i]->set_membership(MembershipState::Authenticating);
    return links[i]->connect(observers[i]->offers.back()).ok();
  }

  std::deque<RadioFrame> air;
  std::deque<WireFrame> mesh;
  RadioPort proxy_radio;
  WirePort proxy_wire;
  WirePort gateway_wire;
  HmacJoinCookie cookie_sealer;
  CounterEntropy proxy_entropy;
  JoinProxy proxy;
  JoinRelayGateway gateway;
  FakeAuthority authority;
  std::vector<RadioPort*> radios;
  std::vector<CounterEntropy*> entropies;
  std::vector<DeviceObserver*> observers;
  std::vector<ZtJoinerLink*> links;
  MonotonicMs now{1000};
  bool reverse_radio{false};
  std::function<bool(const RadioFrame&)> drop_radio;
  std::function<bool(const WireFrame&)> drop_wire;
  std::size_t radio_frames{0};
  std::size_t wire_frames{0};
};

// The Site Authority side of the test: answer the last up object.
Bytes answer(World& world, const std::uint8_t step, const RelayState state, const Bytes& message) {
  CHECK(!world.authority.ups.empty());
  const RelayObject up = parse_up(world.authority.ups.back().object);
  const Bytes down = down_object(up.header, step, state, message);
  CHECK(world.gateway.host_down(kProxy, view(down), world.now).ok());
  return down;
}

bool message_is(const DeviceObserver::Message& m, const std::uint8_t step, const Bytes& bytes) {
  return m.phase == JoinAuthPhase::EdhocMessage && m.step == step && m.bytes == bytes;
}

// --- scenarios ------------------------------------------------------------------------

void run_exchange(World& world, const Bytes& m1, const Bytes& m2, const Bytes& m3,
                  const Bytes& m4) {
  DeviceObserver& device = *world.observers[0];
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(m1), world.now).ok());
  world.pump();
  CHECK(world.proxy.state() == JoinProxy::State::Relaying);
  CHECK(world.authority.ups.size() == 1);
  const RelayObject up1 = parse_up(world.authority.ups[0].object);
  CHECK(world.authority.ups[0].proxy == kProxy && world.authority.ups[0].hops == 3);
  CHECK(up1.header.step == 1 && up1.header.phase == JoinAuthPhase::EdhocMessage);
  CHECK(up1.header.joiner_mac == device_mac(0) && up1.header.joiner_rssi_dbm == -61);
  CHECK(Bytes(up1.message.data, up1.message.data + up1.message.size) == m1);

  answer(world, 2, RelayState::Continue, m2);
  world.pump();
  world.advance(3000);
  CHECK(device.messages.size() == 1 && message_is(device.messages[0], 2, m2));

  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(m3), world.now).ok());
  world.pump();
  world.advance(3000);
  CHECK(world.authority.ups.size() == 2);
  const RelayObject up3 = parse_up(world.authority.ups[1].object);
  CHECK(up3.header.step == 3 && up3.header.relay_id == up1.header.relay_id);
  CHECK(Bytes(up3.message.data, up3.message.data + up3.message.size) == m3);

  answer(world, 4, RelayState::Final, m4);
  world.pump();
  world.advance(3000);
  CHECK(device.messages.size() == 2 && message_is(device.messages[1], 4, m4));
  // 02 §7.3: the final down object releases the proxy slot.
  CHECK(world.proxy.state() == JoinProxy::State::Idle);
  CHECK(world.proxy.stats().relays_completed == 1);
  CHECK(world.gateway.slots_in_use() <= JoinRelayGateway::kSlots);
  CHECK(device.statuses.empty() && device.failures_seen.empty());
  CHECK(world.authority.aborts.empty());
}

void test_happy_path() {
  current = "happy_path (V1-J02)";
  World world;
  CHECK(world.connect());
  const ZtOfferView& offer = world.observers[0]->offers.back();
  CHECK(offer.proxy == kProxy && offer.network_low32 == kNetworkLow32);
  CHECK(offer.body.site_hint == kSiteHint && offer.body.authority_hops == 3);
  CHECK((offer.body.flags & kZtOfferAuthorityReachable) != 0);
  run_exchange(world, filler(59, 1), filler(372, 2), filler(404, 3), filler(353, 4));
  // Every exchanged object stayed within its budget: m2/m3/m4 took 4 RLD1
  // chunks and 4 Wire chunks each.
  CHECK(world.proxy.stats().up_objects == 2 && world.proxy.stats().down_objects == 2);
  CHECK(world.gateway.stats().up_objects == 2 && world.gateway.stats().down_objects == 2);
  CHECK(world.proxy.stats().retransmissions == 0);
  // After the relay the proxy offers again.
  CHECK(world.connect());
}

void test_loss_and_reorder() {
  current = "loss_and_reorder";
  World world;
  CHECK(world.connect());
  // Reverse every RLD1 batch (chunks arrive out of order) and drop the
  // first transmission of selected chunks and replies on both carriers.
  world.reverse_radio = true;
  int radio_drops = 0;
  world.drop_radio = [&radio_drops](const RadioFrame& frame) {
    autonomy::Rld1Envelope env{};
    if (!autonomy::rld1_decode(ByteView{frame.bytes.data(), frame.bytes.size()}, env)) return false;
    const bool droppable = env.kind == FrameType::BootstrapChunk || env.kind == FrameType::BootstrapReply;
    if (droppable && radio_drops < 3 && (env.body[7] == 106 || env.kind == FrameType::BootstrapReply)) {
      ++radio_drops;
      return true;
    }
    return false;
  };
  int wire_drops = 0;
  world.drop_wire = [&wire_drops](const WireFrame& frame) {
    if (frame.type == FrameType::BootstrapChunk && wire_drops < 2 && frame.payload[7] == 110) {
      ++wire_drops;
      return true;
    }
    return frame.type == FrameType::BootstrapReply && wire_drops == 2 && ++wire_drops == 3;
  };
  run_exchange(world, filler(59, 5), filler(372, 6), filler(404, 7), filler(353, 8));
  CHECK(radio_drops == 3 && wire_drops >= 2);
  CHECK(world.proxy.stats().retransmissions + world.gateway.stats().retransmissions +
            world.links[0]->stats().retransmissions >
        0);
}

void test_resume_chunked_opening() {
  current = "resume_chunked_opening";
  World world;
  CHECK(world.connect());
  // R1 with a 48-byte ticket and the cookie: 131 B, two RLD1 chunks. Chunk
  // 1 alone cannot open a relay (no cookie yet); chunk 0 can.
  world.reverse_radio = true;
  const Bytes r1 = filler(109, 9);
  CHECK(world.links[0]->send(JoinAuthPhase::Resume, 1, view(r1), world.now).ok());
  world.pump();
  CHECK(world.proxy.stats().frames_rejected >= 1);
  world.reverse_radio = false;
  world.advance(1000);
  CHECK(world.authority.ups.size() == 1);
  const RelayObject up = parse_up(world.authority.ups[0].object);
  CHECK(up.header.phase == JoinAuthPhase::Resume && up.header.step == 1);
  CHECK(Bytes(up.message.data, up.message.data + up.message.size) == r1);
  const Bytes r2 = filler(52, 10);
  answer(world, 2, RelayState::Final, r2);
  world.pump();
  CHECK(world.observers[0]->messages.size() == 1);
  CHECK(world.observers[0]->messages[0].phase == JoinAuthPhase::Resume);
  CHECK(world.proxy.state() == JoinProxy::State::Idle);
}

void test_unreachable_and_busy() {
  current = "unreachable_and_busy (V1-J10)";
  {
    // No path to the authority: DISCOVERs get no OFFER.
    World world;
    world.proxy.set_authority(false, kZtHopsUnknown, world.now);
    CHECK(!world.connect());
    CHECK(world.proxy.stats().offers_suppressed >= 1);
  }
  {
    // The gateway has no host (Site Authority down): the relay is refused
    // with authority_unreachable, which reaches the device as a hint only.
    World world;
    CHECK(world.connect());
    world.gateway.set_host_sink(nullptr);
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    DeviceObserver& device = *world.observers[0];
    CHECK(device.statuses.size() == 1);
    CHECK(device.statuses[0].first == RelayStatusCode::AuthorityUnreachable);
    CHECK(device.statuses[0].second == 5000);
    CHECK(device.messages.empty());
    CHECK(world.proxy.state() == JoinProxy::State::Idle);
    CHECK(world.gateway.stats().host_unavailable == 1);
    CHECK(world.links[0]->connected());  // a hint never ends the attempt by itself
  }
  {
    // The authority cancels before m2: host_abort ends the relay and the
    // device sees RelayStatus(aborted), then re-discovers.
    World world;
    CHECK(world.connect());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    const RelayObject up = parse_up(world.authority.ups.back().object);
    CHECK(world.gateway.host_abort(kProxy, relay_token_of(up.header), world.now).ok());
    world.pump();
    CHECK(world.observers[0]->statuses.size() == 1);
    CHECK(world.observers[0]->statuses[0].first == RelayStatusCode::Aborted);
    CHECK(world.proxy.state() == JoinProxy::State::Idle);
  }
  {
    // A second device while the proxy relays: RelayStatus(busy).
    World world(2);
    CHECK(world.connect(0));
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    CHECK(world.proxy.state() == JoinProxy::State::Relaying);
    // Device 1 gets no OFFER while the proxy relays (the m1-with-cookie
    // busy path is covered by test_flood).
    CHECK(!world.connect(1));
    CHECK(world.proxy.stats().offers_suppressed >= 1);
    CHECK(world.proxy.state() == JoinProxy::State::Relaying);
  }
}

void test_flood() {
  current = "flood (V1-J11)";
  World world(6);
  // Six devices discover at once: the proxy holds at most 4 pending OFFERs.
  for (std::size_t i = 0; i < 6; ++i) {
    ZtDiscoverBody body{};
    body.org_hint = kOrgHint;
    CHECK(world.links[i]->discover(body, world.now).ok());
  }
  world.pump();
  CHECK(world.proxy.stats().discovers_rx == 6);
  CHECK(world.proxy.stats().offers_suppressed == 2);
  world.advance(400);
  std::size_t offered = 0;
  for (auto* observer : world.observers) offered += observer->offers.size();
  CHECK(offered == 4);
  // All four send m1: exactly one relay starts, the others hear busy.
  for (std::size_t i = 0; i < 6; ++i) {
    if (world.observers[i]->offers.empty()) continue;
    world.links[i]->set_membership(MembershipState::Authenticating);
    CHECK(world.links[i]->connect(world.observers[i]->offers.back()).ok());
    CHECK(world.links[i]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
  }
  world.pump();
  CHECK(world.proxy.stats().relays_started == 1);
  CHECK(world.proxy.stats().busy_replies == 3);
  CHECK(world.authority.ups.size() == 1);
  std::size_t busy = 0;
  for (auto* observer : world.observers) {
    for (const auto& status : observer->statuses) busy += status.first == RelayStatusCode::Busy;
  }
  CHECK(busy == 3);
  // A forged m1 (no valid cookie) never opens anything or costs memory.
  JoinAuthObject forged{};
  forged.phase = JoinAuthPhase::EdhocMessage;
  forged.step = 1;
  forged.cookie_present = true;
  const Bytes m1 = filler(59, 3);
  forged.message = view(m1);
  Bytes object(128);
  std::size_t written = 0;
  CHECK(join_object_encode(forged, MutableByteView{object.data(), object.size()}, written).ok());
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::BootstrapAuth;
  env.claimed_node = kDevice + 9;
  env.transaction_nonce = JoinNonce{{9, 9, 9}};
  std::memcpy(env.body.data(), object.data(), written);
  env.body_size = written;
  autonomy::Rld1Encoded frame{};
  CHECK(autonomy::rld1_encode(env, frame).ok());
  const std::uint32_t cookie_rejects = world.proxy.stats().cookie_rejects;
  world.proxy.on_rld1_rx(device_mac(9), kProxyMac, -50, frame.view(), world.now);
  CHECK(world.proxy.stats().cookie_rejects == cookie_rejects + 1);
  CHECK(world.proxy.stats().relays_started == 1);
}

void test_rate_limit() {
  current = "rate_limit";
  World world(2);
  CHECK(world.connect(0));
  CHECK(world.connect(1));
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  world.pump();
  CHECK(world.proxy.state() == JoinProxy::State::Relaying);
  // The first relay ends quickly (deny as an EDHOC error, single frame, final)...
  answer(world, 5, RelayState::Final, filler(31, 2));
  world.pump();
  CHECK(world.proxy.state() == JoinProxy::State::Idle);
  // ...but a new m1 inside the 2 s budget is still refused with a wait hint.
  CHECK(world.links[1]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 3)), world.now).ok());
  world.pump();
  CHECK(world.proxy.stats().rate_limited == 1);
  CHECK(!world.observers[1]->statuses.empty());
  CHECK(world.observers[1]->statuses.back().first == RelayStatusCode::Busy);
  CHECK(world.observers[1]->statuses.back().second > 0 &&
        world.observers[1]->statuses.back().second <= 2000);
}

void test_timeouts() {
  current = "timeouts";
  {
    // The device goes silent after m2: 5 s later the proxy aborts both ways.
    World world;
    CHECK(world.connect());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    answer(world, 2, RelayState::Continue, filler(372, 2));
    world.pump();
    world.advance(4800);
    CHECK(world.proxy.state() == JoinProxy::State::Relaying);
    world.advance(400);
    CHECK(world.proxy.state() == JoinProxy::State::Idle);
    CHECK(world.authority.aborts.size() == 1);
    CHECK(world.authority.aborts[0].reason == RelayAbortReason::ProxyAborted);
    CHECK(!world.observers[0]->statuses.empty());
    CHECK(world.observers[0]->statuses.back().first == RelayStatusCode::Aborted);
  }
  {
    // The authority never answers: the 20 s relay cap ends it.
    World world;
    CHECK(world.connect());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    world.advance(19000);
    CHECK(world.proxy.state() == JoinProxy::State::Relaying);
    world.advance(1500);
    CHECK(world.proxy.state() == JoinProxy::State::Idle);
    CHECK(world.authority.aborts.size() == 1);
  }
  {
    // The proxy never confirms a chunked down object: the gateway gives up
    // after its send budget and tells the host.
    World world;
    CHECK(world.connect());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    world.drop_wire = [](const WireFrame& frame) { return frame.to == kProxy; };
    answer(world, 2, RelayState::Continue, filler(372, 2));
    world.advance(3000);
    CHECK(world.gateway.stats().delivery_failed == 1);
    CHECK(!world.authority.aborts.empty());
    CHECK(world.authority.aborts.back().reason == RelayAbortReason::DeliveryFailed);
    CHECK(world.gateway.slots_in_use() == 0);
  }
  {
    // A chunked up object never completes at the gateway: expired.
    World world;
    CHECK(world.connect());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    answer(world, 2, RelayState::Continue, filler(372, 2));
    world.pump();
    world.advance(1000);
    // Only chunk 0 of m3 reaches the gateway (the proxy's own abort after
    // its send budget is lost too), so the gateway's 3 s assembly expires.
    world.drop_wire = [](const WireFrame& frame) {
      const bool first_chunk = frame.type == FrameType::BootstrapChunk &&
                               frame.payload[6] == 0 && frame.payload[7] == 0;
      return frame.to == kGateway && !first_chunk;
    };
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(filler(404, 3)), world.now)
              .ok());
    world.advance(4000);
    CHECK(world.gateway.stats().expired >= 1);
    bool expired = false;
    for (const auto& abort : world.authority.aborts) {
      expired = expired || abort.reason == RelayAbortReason::GatewayExpired;
    }
    CHECK(expired);
  }
}

void test_host_abort_and_revocation() {
  current = "host_abort_and_revocation";
  {
    World world;
    CHECK(world.connect());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    const RelayObject up = parse_up(world.authority.ups.back().object);
    RelayToken unknown = relay_token_of(up.header);
    unknown.relay_id += 1;
    CHECK(world.gateway.host_abort(kProxy, unknown, world.now).code == StatusCode::NotFound);
    CHECK(world.gateway.host_abort(kProxy, relay_token_of(up.header), world.now).ok());
    world.pump();
    CHECK(world.proxy.state() == JoinProxy::State::Idle);
    CHECK(world.observers[0]->statuses.back().first == RelayStatusCode::Aborted);
    CHECK(world.gateway.host_abort(kProxy, relay_token_of(up.header), world.now).code ==
          StatusCode::NotFound);
  }
  {
    // host_down argument checks.
    World world;
    CHECK(world.connect());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    const RelayObject up = parse_up(world.authority.ups.back().object);
    const Bytes down = down_object(up.header, 2, RelayState::Continue, filler(20, 1));
    CHECK(world.gateway.host_down(kProxy + 1, view(down), world.now).code ==
          StatusCode::InvalidArgument);
    Bytes truncated = down;
    truncated.resize(10);
    CHECK(!world.gateway.host_down(kProxy, view(truncated), world.now).ok());
    // A down Abort through host_down is refused: cancel with host_abort.
    const Bytes abort = abort_object(up.header, RelayStatusCode::Aborted, 0);
    CHECK(world.gateway.host_down(kProxy, view(abort), world.now).code ==
          StatusCode::ProtocolError);
    // An unknown token is NotFound without touching the Wire port ...
    RelayToken unknown = relay_token_of(up.header);
    unknown.relay_id += 1;
    RelayObject foreign{};
    foreign.header = up.header;
    foreign.header.dir = RelayDirection::Down;
    foreign.header.relay_id = unknown.relay_id;
    foreign.header.step = 2;
    foreign.header.joiner_rssi_dbm = 0;
    const Bytes foreign_msg = filler(20, 1);
    foreign.message = view(foreign_msg);
    Bytes foreign_bytes(kJoinObjectMax);
    std::size_t foreign_written = 0;
    CHECK(relay_object_encode(foreign, MutableByteView{foreign_bytes.data(), foreign_bytes.size()},
                              foreign_written)
              .ok());
    foreign_bytes.resize(foreign_written);
    world.gateway_wire.refuse = true;
    CHECK(world.gateway.host_down(kProxy, view(foreign_bytes), world.now).code ==
          StatusCode::NotFound);
    // ... while a refused port fails a known single frame without changing it.
    CHECK(world.gateway.host_down(kProxy, view(down), world.now).code == StatusCode::NoRoute);
    world.gateway_wire.refuse = false;
    CHECK(world.gateway.host_down(kProxy, view(down), world.now).ok());
    world.gateway.set_membership(MembershipState::Revoked);
    CHECK(world.gateway.host_down(kProxy, view(down), world.now).code ==
          StatusCode::InvalidState);
  }
  {
    // The proxy's own membership ends mid-relay: it stops relaying and
    // offering (02 §7.3 last row).
    World world;
    CHECK(world.connect());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    world.proxy.set_membership(MembershipState::Revoked, world.now);
    CHECK(world.proxy.state() == JoinProxy::State::Idle);
    world.pump();
    CHECK(!world.connect());
  }
}

void test_gateway_slots() {
  current = "gateway_slots";
  // Three proxies push chunked step-1 up objects at once; the gateway holds
  // two assemblies and the third completes once a slot frees (its proxy
  // retransmits).
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  gateway.set_membership(MembershipState::Member);
  FakeAuthority authority;
  gateway.set_host_sink(&authority);
  std::vector<Bytes> objects;
  std::vector<JoinObjectSlot> senders(3);
  for (std::size_t p = 0; p < 3; ++p) {
    RelayObject object{};
    object.header.relay_id = static_cast<std::uint32_t>(100 + p);
    object.header.proxy = kProxy + p;
    object.header.joiner_mac = device_mac(static_cast<std::uint8_t>(p));
    object.header.step = 1;
    object.header.joiner_rssi_dbm = -40;
    object.header.gateway_epoch = kGatewayEpoch;
    object.header.proxy_epoch = kProxyEpoch;
    const Bytes message = filler(300, static_cast<std::uint8_t>(p));
    object.message = view(message);
    Bytes encoded(kJoinObjectMax);
    std::size_t written = 0;
    CHECK(relay_object_encode(object, MutableByteView{encoded.data(), encoded.size()}, written).ok());
    encoded.resize(written);
    objects.push_back(encoded);
    CHECK(senders[p]
              .load(JoinCarrier::WireRelay, JoinAuthPhase::EdhocMessage, 1,
                    object.header.relay_id, kGatewayEpoch, kProxyEpoch,
                    view(objects.back()), 0)
              .ok());
  }
  const auto send_chunk = [&](const std::size_t p, const std::size_t i) {
    JoinChunk chunk{};
    CHECK(senders[p].chunk_at(i, chunk).ok());
    std::array<std::uint8_t, kMaxApplicationPayload> body{};
    std::size_t size = 0;
    CHECK(join_chunk_encode(JoinCarrier::WireRelay, chunk, MutableByteView{body.data(), body.size()},
                            size)
              .ok());
    gateway.on_relay_rx(kProxy + p, 2, FrameType::BootstrapChunk, ByteView{body.data(), size}, 10);
  };
  send_chunk(0, 0);
  send_chunk(1, 0);
  send_chunk(2, 0);  // no slot
  CHECK(gateway.stats().slot_busy == 1);
  for (std::size_t i = 1; i < senders[0].chunk_total(); ++i) send_chunk(0, i);
  CHECK(authority.ups.size() == 1 && authority.ups[0].object == objects[0]);
  // Proxy 2 retransmits: the delivered assembly freed its slot, so it opens.
  for (std::size_t i = 0; i < senders[2].chunk_total(); ++i) send_chunk(2, i);
  CHECK(authority.ups.size() == 2 && authority.ups[1].object == objects[2]);
  CHECK(authority.ups[1].hops == 2);
  // A spoofed origin (the object names another proxy) is refused.
  send_chunk(1, 1);
  const std::size_t before = authority.ups.size();
  JoinChunk chunk{};
  CHECK(senders[1].chunk_at(2, chunk).ok());
  std::array<std::uint8_t, kMaxApplicationPayload> body{};
  std::size_t size = 0;
  CHECK(join_chunk_encode(JoinCarrier::WireRelay, chunk, MutableByteView{body.data(), body.size()},
                          size)
            .ok());
  gateway.on_relay_rx(kProxy + 7, 2, FrameType::BootstrapChunk, ByteView{body.data(), size}, 11);
  CHECK(authority.ups.size() == before);
}

void test_joiner_filters() {
  current = "joiner_filters";
  World world;
  ZtDiscoverBody body{};
  body.org_hint = kOrgHint;
  CHECK(world.links[0]->discover(body, world.now).ok());
  // An OFFER for another organization, another nonce, or to another MAC is ignored.
  ZtOfferBody offer{};
  offer.org_hint = kOrgHint ^ 1;
  autonomy::Rld1Encoded frame{};
  CHECK(zt_offer_frame_encode(kProxy, kNetworkLow32, world.links[0]->nonce(), offer, frame).ok());
  world.links[0]->on_rld1_rx(kProxyMac, device_mac(0), frame.view(), world.now);
  offer.org_hint = kOrgHint;
  CHECK(zt_offer_frame_encode(kProxy, kNetworkLow32, JoinNonce{{1}}, offer, frame).ok());
  world.links[0]->on_rld1_rx(kProxyMac, device_mac(0), frame.view(), world.now);
  CHECK(zt_offer_frame_encode(kProxy, kNetworkLow32, world.links[0]->nonce(), offer, frame).ok());
  world.links[0]->on_rld1_rx(kProxyMac, device_mac(5), frame.view(), world.now);
  CHECK(world.observers[0]->offers.empty());
  CHECK(world.links[0]->stats().offers_ignored == 3);
  world.links[0]->on_rld1_rx(kProxyMac, device_mac(0), frame.view(), world.now);
  CHECK(world.observers[0]->offers.size() == 1);
  // Sending before connect is refused; a down step is not an up message.
  CHECK(!world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(10, 1)), world.now).ok());
  world.links[0]->set_membership(MembershipState::Authenticating);
  CHECK(world.links[0]->connect(world.observers[0]->offers[0]).ok());
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 2, view(filler(10, 1)), world.now).code ==
        StatusCode::InvalidArgument);
  // A BootstrapAuth from a different MAC with the same nonce is rejected.
  JoinAuthObject status{};
  status.phase = JoinAuthPhase::RelayStatus;
  status.relay_status = RelayStatusCode::Busy;
  std::array<std::uint8_t, kRelayStatusObjectSize> bytes{};
  std::size_t written = 0;
  CHECK(join_object_encode(status, MutableByteView{bytes.data(), bytes.size()}, written).ok());
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::BootstrapAuth;
  env.network_hint = kNetworkLow32;
  env.claimed_node = kProxy;
  env.transaction_nonce = world.links[0]->nonce();
  std::memcpy(env.body.data(), bytes.data(), written);
  env.body_size = written;
  CHECK(autonomy::rld1_encode(env, frame).ok());
  world.links[0]->on_rld1_rx(MacAddress{{2, 9, 9, 9, 9, 9}}, device_mac(0), frame.view(), world.now);
  CHECK(world.observers[0]->statuses.empty());
  world.links[0]->on_rld1_rx(kProxyMac, device_mac(0), frame.view(), world.now);
  CHECK(world.observers[0]->statuses.size() == 1);
  // The joiner's up object fails after its send budget when nobody answers.
  world.links[0]->set_membership(MembershipState::Authenticating);
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(filler(300, 1)), world.now).ok());
  world.air.clear();
  for (int i = 0; i < 10; ++i) {
    world.now += 500;
    world.links[0]->poll(world.now);
    world.air.clear();
  }
  CHECK(world.observers[0]->failures_seen.size() == 1);
}

void test_cookie_expiry() {
  current = "cookie_expiry";
  World world;
  CHECK(world.connect());
  // Two cookie buckets later the OFFER's cookie is stale.
  world.now += 4100;
  world.proxy.poll(world.now);
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  world.pump();
  CHECK(world.proxy.stats().cookie_rejects == 1);
  CHECK(world.proxy.state() == JoinProxy::State::Idle);
}

void test_deferred_send_after_on_message() {
  current = "deferred_send_after_on_message";
  World world;
  CHECK(world.connect());
  const Bytes m1 = filler(59, 1);
  const Bytes m2 = filler(372, 2);
  const Bytes m3 = filler(404, 3);
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(m1), world.now).ok());
  world.pump();
  answer(world, 2, RelayState::Continue, m2);
  world.pump();
  CHECK(world.observers[0]->messages.size() == 1);
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(m3), world.now).ok());
  world.pump();
  CHECK(world.authority.ups.size() == 2);
  if (world.authority.ups.size() == 2) {
    const RelayObject up3 = parse_up(world.authority.ups[1].object);
    CHECK(Bytes(up3.message.data, up3.message.data + up3.message.size) == m3);
  }
}

void test_down_duplicate_keeps_sending() {
  current = "down_duplicate_keeps_sending";
  {
    // Chunked m2: its Complete receipt is lost once and m3's chunks are
    // held back, so the proxy retransmits m2 while the joiner is still
    // Sending m3. The duplicate must re-earn its Complete reply through
    // the completed-key memory without releasing the m3 send.
    World world;
    CHECK(world.connect());
    const Bytes m1 = filler(59, 1);
    const Bytes m2 = filler(372, 2);
    const Bytes m3 = filler(404, 3);
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(m1), world.now).ok());
    world.pump();
    bool receipt_dropped = false;
    world.drop_radio = [&](const RadioFrame& frame) {
      autonomy::Rld1Envelope env{};
      if (!autonomy::rld1_decode(view(frame.bytes), env)) return false;
      // The device's Complete receipt of m2 is lost once.
      if (frame.from == device_mac(0) && env.kind == FrameType::BootstrapReply &&
          env.body[1] == join_sub(JoinAuthPhase::EdhocMessage, 2) &&
          env.body[8] == static_cast<std::uint8_t>(JoinReplyStatus::Complete) &&
          !receipt_dropped) {
        receipt_dropped = true;
        return true;
      }
      // m3's chunks stay lost until the proxy's m2 retransmission went out.
      return frame.from == device_mac(0) && env.kind == FrameType::BootstrapChunk &&
             env.body[1] == join_sub(JoinAuthPhase::EdhocMessage, 3) &&
             world.proxy.stats().retransmissions == 0;
    };
    answer(world, 2, RelayState::Continue, m2);
    world.pump();
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(m3), world.now).ok());
    world.pump();
    world.advance(3000);
    CHECK(receipt_dropped);
    CHECK(world.proxy.stats().retransmissions > 0);  // the m2 chunks came again
    CHECK(world.observers[0]->messages.size() == 1 &&
          message_is(world.observers[0]->messages[0], 2, m2));
    CHECK(world.authority.ups.size() == 2);
    if (world.authority.ups.size() == 2) {
      const RelayObject up3 = parse_up(world.authority.ups[1].object);
      CHECK(up3.header.step == 3);
      CHECK(Bytes(up3.message.data, up3.message.data + up3.message.size) == m3);
    }
    CHECK(world.links[0]->stats().retransmissions > 0);
    CHECK(world.observers[0]->failures_seen.empty());
  }
  {
    // Single-frame m2: no receipt exists to lose, so the duplicate is a
    // raw replay of the captured frame — it must not re-fire on_message
    // nor release the m3 send started after the callback.
    World world;
    CHECK(world.connect());
    const Bytes m3 = filler(404, 3);
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now)
              .ok());
    world.pump();
    Bytes m2_frame;
    bool replayed = false;
    world.drop_radio = [&](const RadioFrame& frame) {
      autonomy::Rld1Envelope env{};
      if (!autonomy::rld1_decode(view(frame.bytes), env)) return false;
      if (frame.to == device_mac(0) && env.kind == FrameType::BootstrapAuth &&
          env.body_size >= 3 &&
          env.body[1] == static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage) &&
          env.body[2] == 2 && m2_frame.empty()) {
        m2_frame = frame.bytes;  // capture m2 for a link-layer replay
        return false;
      }
      // m3's chunks stay lost until the replay has been injected.
      return frame.from == device_mac(0) && env.kind == FrameType::BootstrapChunk &&
             env.body[1] == join_sub(JoinAuthPhase::EdhocMessage, 3) && !replayed;
    };
    answer(world, 2, RelayState::Continue, filler(80, 2));
    world.pump();
    CHECK(!m2_frame.empty());
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(m3), world.now).ok());
    world.pump();
    world.links[0]->on_rld1_rx(kProxyMac, device_mac(0), view(m2_frame), world.now);
    CHECK(world.observers[0]->messages.size() == 1);
    CHECK(world.links[0]->slot().mode() == JoinObjectSlot::Mode::Sending);
    replayed = true;
    world.advance(2000);
    CHECK(world.authority.ups.size() == 2);
    if (world.authority.ups.size() == 2) {
      const RelayObject up3 = parse_up(world.authority.ups[1].object);
      CHECK(Bytes(up3.message.data, up3.message.data + up3.message.size) == m3);
    }
    CHECK(world.links[0]->stats().retransmissions > 0);
    CHECK(world.observers[0]->failures_seen.empty());
  }
  {
    // A whole stale object re-assembled from stray chunks (the completed
    // key already belongs to m4) must not re-fire on_message either.
    World world;
    CHECK(world.connect());
    const Bytes m1 = filler(59, 1);
    const Bytes m2 = filler(372, 2);
    const Bytes m3 = filler(404, 3);
    const Bytes m4 = filler(353, 4);
    std::vector<Bytes> m2_chunks;
    world.drop_radio = [&m2_chunks](const RadioFrame& frame) {
      autonomy::Rld1Envelope env{};
      if (frame.from == kProxyMac && autonomy::rld1_decode(view(frame.bytes), env) &&
          env.kind == FrameType::BootstrapChunk &&
          env.body[1] == join_sub(JoinAuthPhase::EdhocMessage, 2)) {
        m2_chunks.push_back(frame.bytes);  // tap only, nothing dropped
      }
      return false;
    };
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(m1), world.now).ok());
    world.pump();
    answer(world, 2, RelayState::Continue, m2);
    world.pump();
    CHECK(m2_chunks.size() == 4);
    CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(m3), world.now).ok());
    world.pump();
    answer(world, 4, RelayState::Final, m4);
    world.pump();
    CHECK(world.observers[0]->messages.size() == 2);
    for (const Bytes& chunk : m2_chunks) {
      world.links[0]->on_rld1_rx(kProxyMac, device_mac(0), view(chunk), world.now);
    }
    CHECK(world.observers[0]->messages.size() == 2);
    CHECK(world.links[0]->slot().mode() == JoinObjectSlot::Mode::Idle);
  }
}

// A complete single-frame up object (Continue or Abort) from kProxy.
Bytes up_frame(const std::uint32_t relay_id, const std::uint8_t step, const RelayState state,
               const NodeId proxy = kProxy) {
  RelayObject object{};
  object.header.relay_id = relay_id;
  object.header.proxy = proxy;
  object.header.joiner_mac = device_mac(0);
  object.header.step = step;
  object.header.state = state;
  object.header.joiner_rssi_dbm = -40;
  object.header.gateway_epoch = kGatewayEpoch;
  object.header.proxy_epoch = kProxyEpoch;
  const Bytes message = state == RelayState::Abort ? Bytes{} : filler(40, step);
  object.message = view(message);
  if (state == RelayState::Abort) object.abort.status = RelayStatusCode::Aborted;
  Bytes out(kJoinObjectMax);
  std::size_t written = 0;
  CHECK(relay_object_encode(object, MutableByteView{out.data(), out.size()}, written).ok());
  out.resize(written);
  return out;
}

void test_colocated_gateway_proxy_down() {
  current = "colocated_gateway_proxy_down";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kProxy);
  FakeAuthority authority;
  JoinRelayGatewayConfig config{};
  config.node = kProxy;
  config.gateway_epoch = kGatewayEpoch;
  const Bytes m1 = up_frame(73, 1, RelayState::Continue, kProxy);
  {
    JoinRelayGateway ordinary(config, port);
    CHECK(ordinary.set_membership(MembershipState::Member).ok());
    CHECK(ordinary.set_host_sink(&authority).ok());
    CHECK(ordinary.on_relay_rx(kProxy, 0, FrameType::BootstrapAuth, view(m1), 100).ok());
    CHECK(authority.ups.empty());
  }
  config.colocated_proxy = true;
  JoinRelayGateway colocated(config, port);
  CHECK(colocated.set_membership(MembershipState::Member).ok());
  CHECK(colocated.set_host_sink(&authority).ok());
  CHECK(colocated.on_relay_rx(kProxy, 0, FrameType::BootstrapAuth, view(m1), 100).ok());
  CHECK(authority.ups.size() == 1);
  if (authority.ups.empty()) return;
  const Bytes m2 = down_object(parse_up(authority.ups.back().object).header, 2,
                               RelayState::Continue, filler(20, 2));
  CHECK(colocated.host_down(kProxy, view(m2), 101).ok());
  CHECK(mesh.size() == 1 && mesh.front().to == kProxy);
}

void test_busy_inside_relay_up() {
  current = "busy_inside_relay_up";
  // Sink callbacks must not re-enter the gateway: mutating calls inside
  // relay_up return Busy (or are ignored) and change nothing. The same
  // host_down after the callback is the #113 scenario: the chunked down
  // object keeps its retransmission state and reaches the device.
  World world;
  CHECK(world.connect());
  const Bytes m1 = filler(300, 1);  // chunked all the way to the gateway
  const Bytes m2 = filler(372, 2);  // chunked down to the proxy
  const Bytes m3 = filler(404, 3);
  FakeAuthority other;  // set_host_sink inside the callback must be ignored
  int answered = 0;
  Bytes down;
  world.authority.on_up = [&](const FakeAuthority::Up& up) {
    if (answered++ != 0) return;
    const RelayObject object = parse_up(up.object);
    down = down_object(object.header, 2, RelayState::Continue, m2);
    CHECK(world.gateway.host_down(kProxy, view(down), world.now).code == StatusCode::Busy);
    CHECK(world.gateway.host_abort(kProxy, relay_token_of(object.header), world.now).code ==
          StatusCode::Busy);
    world.gateway.set_membership(MembershipState::Unprovisioned);  // ignored
    world.gateway.set_host_sink(&other);                         // ignored
    world.gateway.poll(world.now);                               // ignored
    // A frame fed inside the callback is not processed at all.
    const std::uint32_t rejected = world.gateway.stats().frames_rejected;
    world.gateway.on_relay_rx(kProxy, 3, FrameType::BootstrapAuth,
                              view(up_frame(999, 1, RelayState::Continue)), world.now);
    CHECK(world.gateway.stats().frames_rejected == rejected);
  };
  // Lose exactly the offset-0 Wire chunk of the down object once.
  int dropped = 0;
  world.drop_wire = [&dropped](const WireFrame& frame) {
    if (frame.from != kGateway || frame.to != kProxy || dropped != 0 ||
        frame.type != FrameType::BootstrapChunk || frame.payload[6] != 0 ||
        frame.payload[7] != 0) {
      return false;
    }
    ++dropped;
    return true;
  };
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(m1), world.now).ok());
  world.pump();
  CHECK(answered == 1 && !down.empty());
  CHECK(world.authority.ups.size() == 1);
  CHECK(world.gateway.stats().down_objects == 0);  // nothing changed inside
  CHECK(world.gateway.stats().host_aborts == 0);
  CHECK(world.gateway.host_down(kProxy, view(down), world.now).ok());  // works now
  world.advance(3000);
  CHECK(dropped == 1);
  CHECK(world.gateway.stats().retransmissions > 0);
  CHECK(world.observers[0]->messages.size() == 1 &&
        message_is(world.observers[0]->messages[0], 2, m2));
  CHECK(world.authority.aborts.empty());
  // The sink was never replaced: the next stage still reaches authority.
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(m3), world.now).ok());
  world.pump();
  CHECK(world.authority.ups.size() == 2);
  CHECK(other.ups.empty() && other.aborts.empty());
}

void test_busy_inside_relay_abort() {
  current = "busy_inside_relay_abort";
  // relay_abort (GatewayExpired and ProxyAborted): mutating calls inside
  // the callback are refused and ignored. After it returns, the ended
  // relay is unknown to host_abort and the freed slot takes a new
  // operation.
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  gateway.set_membership(MembershipState::Member);
  FakeAuthority authority;
  gateway.set_host_sink(&authority);
  const auto token = [](const std::uint32_t relay_id) {
    RelayToken token{};
    token.gateway_epoch = kGatewayEpoch;
    token.proxy_epoch = kProxyEpoch;
    token.relay_id = relay_id;
    return token;
  };
  std::vector<Bytes> objects;
  std::vector<JoinObjectSlot> senders(2);
  const auto make_up = [&](const std::size_t i, const NodeId proxy, const std::uint32_t relay_id,
                           const std::uint8_t step) {
    RelayObject object{};
    object.header.relay_id = relay_id;
    object.header.proxy = proxy;
    object.header.joiner_mac = device_mac(0);
    object.header.step = step;
    object.header.joiner_rssi_dbm = -40;
    object.header.gateway_epoch = kGatewayEpoch;
    object.header.proxy_epoch = kProxyEpoch;
    const Bytes message = filler(300, static_cast<std::uint8_t>(i));
    object.message = view(message);
    Bytes encoded(kJoinObjectMax);
    std::size_t written = 0;
    CHECK(relay_object_encode(object, MutableByteView{encoded.data(), encoded.size()}, written)
              .ok());
    encoded.resize(written);
    objects.push_back(encoded);
    CHECK(senders[i]
              .load(JoinCarrier::WireRelay, JoinAuthPhase::EdhocMessage, step, relay_id,
                    kGatewayEpoch, kProxyEpoch, view(objects.back()), 0)
              .ok());
  };
  const auto send_chunk = [&](const NodeId proxy, const std::size_t i, const std::size_t c,
                              const MonotonicMs now) {
    JoinChunk chunk{};
    CHECK(senders[i].chunk_at(c, chunk).ok());
    std::array<std::uint8_t, kMaxApplicationPayload> body{};
    std::size_t size = 0;
    CHECK(join_chunk_encode(JoinCarrier::WireRelay, chunk, MutableByteView{body.data(), body.size()},
                            size)
              .ok());
    gateway.on_relay_rx(proxy, 2, FrameType::BootstrapChunk, ByteView{body.data(), size}, now);
  };
  // Two live exchanges (m1 delivered, m3 assembly started) expire in one pass.
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(100, 1, RelayState::Continue)), 10);
  gateway.on_relay_rx(kProxy + 1, 2, FrameType::BootstrapAuth,
                      view(up_frame(200, 1, RelayState::Continue, kProxy + 1)), 20);
  CHECK(authority.ups.size() == 2);
  const Bytes m2_a = down_object(parse_up(authority.ups[0].object).header, 2,
                                 RelayState::Continue, filler(20, 1));
  const Bytes m2_b = down_object(parse_up(authority.ups[1].object).header, 2,
                                 RelayState::Continue, filler(20, 2));
  CHECK(gateway.host_down(kProxy, view(m2_a), 21).ok());
  CHECK(gateway.host_down(kProxy + 1, view(m2_b), 22).ok());
  make_up(0, kProxy + 1, 200, 3);  // relay B stage 3 (partial: expires in the same pass)
  make_up(1, kProxy, 100, 3);      // relay A stage 3 (partial: expires first)
  send_chunk(kProxy, 1, 0, 30);
  send_chunk(kProxy + 1, 0, 0, 40);
  CHECK(gateway.slots_in_use() == 2);
  bool handled = false;
  authority.on_abort = [&](const FakeAuthority::Abort& abort) {
    if (abort.reason != RelayAbortReason::GatewayExpired || handled) return;
    handled = true;
    CHECK(abort.proxy == kProxy && abort.token.relay_id == 100);
    RelayHeader header{};
    header.relay_id = 300;
    header.proxy = kProxy;
    header.joiner_mac = device_mac(0);
    header.gateway_epoch = kGatewayEpoch;
    header.proxy_epoch = kProxyEpoch;
    const Bytes down = down_object(header, 2, RelayState::Continue, filler(300, 9));
    CHECK(gateway.host_down(kProxy, view(down), 3040).code == StatusCode::Busy);
    CHECK(gateway.host_abort(kProxy, token(100), 3040).code == StatusCode::Busy);
    gateway.set_membership(MembershipState::Unprovisioned);  // ignored
    gateway.set_host_sink(nullptr);                        // ignored
    // Relay B expires at this same instant: a nested poll must notify
    // nothing, free nothing, and count nothing.
    const JoinRelayGatewayStats before = gateway.stats();
    gateway.poll(3040);  // ignored
    CHECK(authority.aborts.size() == 1);
    CHECK(gateway.slots_in_use() == 1);  // A is already finished; B is untouched
    CHECK(gateway.stats().expired == before.expired);
    CHECK(gateway.stats().proxy_aborts == before.proxy_aborts);
  };
  gateway.poll(3040);  // expires A (callback above), then B in the same pass
  CHECK(handled);
  CHECK(authority.aborts.size() == 2);  // B's expiry ran after the callback
  CHECK(gateway.stats().expired == 2);
  CHECK(gateway.stats().down_objects == 2);  // the callback changed nothing
  CHECK(gateway.slots_in_use() == 0);
  // After the callback: the ended relays are unknown to host_abort, and a
  // freed slot takes a new operation (membership was never cleared).
  CHECK(gateway.host_abort(kProxy, token(100), 3041).code == StatusCode::NotFound);
  CHECK(gateway.host_abort(kProxy + 1, token(200), 3041).code == StatusCode::NotFound);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(300, 1, RelayState::Continue)), 3042);
  const RelayObject opened = parse_up(authority.ups.back().object);
  const Bytes down = down_object(opened.header, 2, RelayState::Continue, filler(300, 9));
  CHECK(gateway.host_down(kProxy, view(down), 3043).ok());
  CHECK(gateway.slots_in_use() == 1);
  // The ProxyAborted callback applies the same reentry rules, and the
  // ignored set_host_sink(nullptr) proves the sink is still attached.
  int proxy_calls = 0;
  authority.on_abort = [&](const FakeAuthority::Abort& abort) {
    if (abort.reason != RelayAbortReason::ProxyAborted || proxy_calls++ != 0) return;
    CHECK(abort.proxy == kProxy + 2 && abort.token.relay_id == 400);
    CHECK(gateway.host_down(kProxy, view(down), 3050).code == StatusCode::Busy);
    CHECK(gateway.host_abort(kProxy + 2, token(400), 3050).code == StatusCode::Busy);
  };
  gateway.on_relay_rx(kProxy + 2, 2, FrameType::BootstrapAuth,
                      view(up_frame(400, 1, RelayState::Continue, kProxy + 2)), 3045);
  CHECK(authority.ups.size() == 4);
  gateway.on_relay_rx(kProxy + 2, 2, FrameType::BootstrapAuth,
                      view(up_frame(400, 1, RelayState::Abort, kProxy + 2)), 3050);
  CHECK(proxy_calls == 1);
  CHECK(authority.aborts.size() == 3);  // the sink was never detached
  CHECK(gateway.host_abort(kProxy, token(300), 3051).ok());
}

void test_delivery_failed_callback_busy() {
  current = "delivery_failed_callback_busy";
  // relay_abort(DeliveryFailed) at the retransmit cap: the callback must
  // not re-enter — a host_down inside it is Busy, and the post-callback
  // free must not erase an operation that starts afterwards.
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  gateway.set_membership(MembershipState::Member);
  FakeAuthority authority;
  gateway.set_host_sink(&authority);
  const auto token = [](const std::uint32_t relay_id) {
    RelayToken token{};
    token.gateway_epoch = kGatewayEpoch;
    token.proxy_epoch = kProxyEpoch;
    token.relay_id = relay_id;
    return token;
  };
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(500, 1, RelayState::Continue)), 5);
  const RelayObject opened = parse_up(authority.ups.back().object);
  const Bytes down = down_object(opened.header, 2, RelayState::Continue, filler(300, 9));
  CHECK(gateway.host_down(kProxy, view(down), 10).ok());  // sends_ = 1
  CHECK(gateway.slots_in_use() == 1);
  // The proxy never answers: poll hits the retransmit cap.
  int calls = 0;
  authority.on_abort = [&](const FakeAuthority::Abort& abort) {
    if (abort.reason != RelayAbortReason::DeliveryFailed || calls++ != 0) return;
    CHECK(abort.proxy == kProxy && abort.token.relay_id == 500);
    CHECK(gateway.slots_in_use() == 0);  // finished (wiped) before the callback
    CHECK(gateway.host_down(kProxy, view(down), 2010).code == StatusCode::Busy);
    CHECK(gateway.host_abort(kProxy, token(500), 2010).code == StatusCode::Busy);
    gateway.set_membership(MembershipState::Unprovisioned);  // ignored
    gateway.poll(2010);                                    // ignored
    CHECK(gateway.slots_in_use() == 0);
  };
  gateway.poll(510);   // resend -> sends_ = 2
  gateway.poll(1010);  // resend -> sends_ = 3
  gateway.poll(1510);  // resend -> sends_ = 4
  CHECK(calls == 0 && gateway.stats().delivery_failed == 0);
  gateway.poll(2010);  // sends_ >= max_sends -> DeliveryFailed
  CHECK(calls == 1 && authority.aborts.size() == 1);
  CHECK(gateway.stats().delivery_failed == 1);
  CHECK(gateway.stats().down_objects == 1);  // the callback changed nothing
  CHECK(gateway.slots_in_use() == 0);
  // After the callback the relay is terminated: its key never reopens, but
  // a newer key from the same proxy starts a fresh exchange.
  CHECK(gateway.host_abort(kProxy, token(500), 2020).code == StatusCode::NotFound);
  CHECK(gateway.host_down(kProxy, view(down), 2020).code == StatusCode::Expired);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(501, 1, RelayState::Continue)), 2030);
  const RelayObject reopened = parse_up(authority.ups.back().object);
  const Bytes down2 = down_object(reopened.header, 2, RelayState::Continue, filler(300, 9));
  CHECK(gateway.host_down(kProxy, view(down2), 2040).ok());
  CHECK(gateway.slots_in_use() == 1);
}

void test_q116_stage_and_terminal_dedup() {
  current = "q116_stage_and_terminal_dedup (Q116-01/Q116-03)";
  // #116: a duplicate up stage must not displace the down object being sent,
  // and a duplicate ProxyAborted must notify the host only once.
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  gateway.set_membership(MembershipState::Member);
  FakeAuthority authority;
  gateway.set_host_sink(&authority);
  RelayHeader up_header{};
  up_header.dir = RelayDirection::Up;
  up_header.relay_id = 7;
  up_header.proxy = kProxy;
  up_header.joiner_mac = device_mac(0);
  up_header.phase = JoinAuthPhase::EdhocMessage;
  up_header.step = 1;
  up_header.state = RelayState::Continue;
  up_header.joiner_rssi_dbm = -40;
  up_header.gateway_epoch = kGatewayEpoch;
  up_header.proxy_epoch = kProxyEpoch;
  RelayObject up_object{};
  up_object.header = up_header;
  const Bytes m1 = filler(40, 1);
  up_object.message = view(m1);
  Bytes up_bytes(kJoinObjectMax);
  std::size_t written = 0;
  CHECK(relay_object_encode(up_object, MutableByteView{up_bytes.data(), up_bytes.size()}, written)
            .ok());
  up_bytes.resize(written);
  gateway.on_relay_rx(kProxy, 3, FrameType::BootstrapAuth, view(up_bytes), 1000);
  CHECK(authority.ups.size() == 1);
  const Bytes down = down_object(up_header, 2, RelayState::Continue, filler(200, 2));
  CHECK(down.size() > kMaxApplicationPayload);  // chunked down, held in a slot
  CHECK(gateway.host_down(kProxy, view(down), 1100).ok());
  CHECK(gateway.slots_in_use() == 1);
  // A retransmitted m1 (Complete receipt was lost) must neither free the
  // down slot nor reach the host a second time.
  gateway.on_relay_rx(kProxy, 3, FrameType::BootstrapAuth, view(up_bytes), 1200);
  CHECK(authority.ups.size() == 1);
  CHECK(gateway.slots_in_use() == 1);
  // The down object is still retransmitted until the proxy confirms it.
  const std::size_t wire_before = mesh.size();
  gateway.poll(1700);
  CHECK(gateway.stats().retransmissions > 0);
  CHECK(mesh.size() > wire_before);
  // A duplicate ProxyAborted for the live key notifies only once.
  RelayObject abort{};
  abort.header = up_header;
  abort.header.state = RelayState::Abort;
  abort.abort.status = RelayStatusCode::Aborted;
  Bytes abort_bytes(kJoinObjectMax);
  CHECK(relay_object_encode(abort, MutableByteView{abort_bytes.data(), abort_bytes.size()}, written)
            .ok());
  abort_bytes.resize(written);
  gateway.on_relay_rx(kProxy, 3, FrameType::BootstrapAuth, view(abort_bytes), 1800);
  gateway.on_relay_rx(kProxy, 3, FrameType::BootstrapAuth, view(abort_bytes), 1900);
  CHECK(authority.aborts.size() == 1);
  CHECK(authority.aborts[0].reason == RelayAbortReason::ProxyAborted);
  CHECK(authority.aborts[0].token.relay_id == 7);
  CHECK(relay_token_equal(authority.aborts[0].token, relay_token_of(up_header)));
}

void test_q116_proxy_old_up_keeps_down() {
  current = "q116_proxy_old_up_keeps_down";
  World world;
  CHECK(world.connect());
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  const Bytes old_m1 = world.air.front().bytes;
  world.pump();
  CHECK(world.authority.ups.size() == 1);
  world.drop_radio = [](const RadioFrame& frame) {
    autonomy::Rld1Envelope env{};
    return frame.from == device_mac(0) && autonomy::rld1_decode(view(frame.bytes), env).ok() &&
           env.kind == FrameType::BootstrapReply;
  };
  answer(world, 2, RelayState::Continue, filler(372, 2));
  world.pump();
  CHECK(world.proxy.slot().mode() == JoinObjectSlot::Mode::Sending);
  world.proxy.on_rld1_rx(device_mac(0), kProxyMac, -61, view(old_m1), world.now);
  CHECK(world.proxy.slot().mode() == JoinObjectSlot::Mode::Sending);
  CHECK(world.proxy.stats().up_objects == 1);
  CHECK(world.authority.ups.size() == 1);
  world.drop_radio = {};
  world.advance(1000);
  CHECK(world.proxy.stats().retransmissions > 0);
  CHECK(world.observers[0]->messages.size() == 1);
}

void test_q116_gateway_stage_and_abort_identity() {
  current = "q116_gateway_stage_and_abort_identity";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  FakeAuthority authority;
  CHECK(gateway.set_membership(MembershipState::Member).ok());
  CHECK(gateway.set_host_sink(&authority).ok());
  const Bytes m1 = up_frame(31, 1, RelayState::Continue);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(m1), 100);
  CHECK(authority.ups.size() == 1);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(31, 3, RelayState::Continue)), 101);
  CHECK(authority.ups.size() == 1);
  RelayObject wrong_abort{};
  wrong_abort.header = parse_up(m1).header;
  wrong_abort.header.joiner_mac = device_mac(9);
  wrong_abort.header.state = RelayState::Abort;
  wrong_abort.abort.status = RelayStatusCode::Aborted;
  Bytes encoded(kRelayHeaderSize + kRelayAbortBodySize);
  std::size_t written = 0;
  CHECK(relay_object_encode(wrong_abort, MutableByteView{encoded.data(), encoded.size()},
                            written).ok());
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(encoded), 102);
  CHECK(authority.aborts.empty());
  const Bytes m2 = down_object(parse_up(m1).header, 2, RelayState::Continue, filler(20, 2));
  CHECK(gateway.host_down(kProxy, view(m2), 103).ok());
}

void test_q116_invalid_complete_does_not_poison_floor() {
  current = "q116_invalid_complete_does_not_poison_floor";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  FakeAuthority authority;
  CHECK(gateway.set_membership(MembershipState::Member).ok());
  CHECK(gateway.set_host_sink(&authority).ok());
  Bytes invalid = up_frame(41, 1, RelayState::Continue);
  invalid.resize(kRelayObjectMax + 1, 0xA5);
  JoinObjectSlot sender;
  CHECK(sender.load(JoinCarrier::WireRelay, JoinAuthPhase::EdhocMessage, 1, 41,
                    kGatewayEpoch, kProxyEpoch, view(invalid), 100).ok());
  for (std::size_t i = 0; i < sender.chunk_total(); ++i) {
    JoinChunk chunk{};
    CHECK(sender.chunk_at(i, chunk).ok());
    std::array<std::uint8_t, kMaxApplicationPayload> encoded{};
    std::size_t written = 0;
    CHECK(join_chunk_encode(JoinCarrier::WireRelay, chunk,
                            MutableByteView{encoded.data(), encoded.size()}, written).ok());
    gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapChunk,
                        ByteView{encoded.data(), written}, 100 + i);
  }
  CHECK(authority.ups.empty());
  for (const WireFrame& frame : mesh) {
    if (frame.type != FrameType::BootstrapReply) continue;
    JoinReply reply{};
    CHECK(join_reply_decode(JoinCarrier::WireRelay, view(frame.payload), reply).ok());
    CHECK(reply.status != JoinReplyStatus::Complete);
  }
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(41, 1, RelayState::Continue)), 200);
  CHECK(authority.ups.size() == 1);
}

void test_q116_proxy_old_down_keeps_up() {
  current = "q116_proxy_old_down_keeps_up";
  World world;
  CHECK(world.connect());
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  world.pump();
  answer(world, 2, RelayState::Continue, filler(80, 2));
  CHECK(!world.mesh.empty());
  const WireFrame old_m2 = world.mesh.front();
  world.pump();
  CHECK(world.observers[0]->messages.size() == 1);
  world.drop_wire = [](const WireFrame& frame) {
    return frame.from == kProxy && frame.to == kGateway &&
           frame.type == FrameType::BootstrapChunk;
  };
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 3, view(filler(404, 3)), world.now).ok());
  world.pump();
  CHECK(world.proxy.slot().mode() == JoinObjectSlot::Mode::Sending);
  world.proxy.on_relay_rx(kGateway, old_m2.type, view(old_m2.payload), world.now);
  CHECK(world.proxy.slot().mode() == JoinObjectSlot::Mode::Sending);
  CHECK(world.observers[0]->messages.size() == 1);
  world.drop_wire = {};
  world.advance(1000);
  CHECK(world.authority.ups.size() == 2);
}

void test_q116_late_query_reply() {
  current = "q116_late_query_reply";
  World world;
  ZtDiscoverBody body{};
  body.org_hint = kOrgHint;
  CHECK(world.links[0]->discover(body, world.now).ok());
  const RadioFrame discover = world.air.front();
  CHECK(world.proxy.on_rld1_rx(discover.from, discover.to, -50, view(discover.bytes),
                                world.now).ok());
  CHECK(!world.mesh.empty());
  EpochQuery query{};
  CHECK(epoch_query_decode(view(world.mesh.front().payload), query).ok());
  EpochReply reply{};
  reply.gateway_epoch = kGatewayEpoch;
  reply.authority_ready = true;
  reply.nonce = query.nonce;
  std::array<std::uint8_t, kEpochReplySize> encoded{};
  std::size_t written = 0;
  CHECK(epoch_reply_encode(reply, MutableByteView{encoded.data(), encoded.size()}, written).ok());
  CHECK(world.proxy.on_relay_rx(kGateway, FrameType::BootstrapAuth,
                                ByteView{encoded.data(), written}, world.now + 2100).ok());
  CHECK(world.proxy.stats().epoch_replies_rx == 0);
}

void test_q116_host_abort_no_route_terminates() {
  current = "q116_host_abort_no_route_terminates";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  FakeAuthority authority;
  CHECK(gateway.set_membership(MembershipState::Member).ok());
  CHECK(gateway.set_host_sink(&authority).ok());
  const Bytes m1 = up_frame(51, 1, RelayState::Continue);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(m1), 100);
  const RelayToken token = relay_token_of(parse_up(m1).header);
  port.refuse = true;
  CHECK(gateway.host_abort(kProxy, token, 101).code == StatusCode::NoRoute);
  CHECK(gateway.host_abort(kProxy, token, 102).code == StatusCode::NotFound);
  const Bytes m2 = down_object(parse_up(m1).header, 2, RelayState::Continue, filler(20, 2));
  CHECK(gateway.host_down(kProxy, view(m2), 103).code == StatusCode::Expired);
}

void test_q116_proxy_single_up_port_failure() {
  current = "q116_proxy_single_up_port_failure";
  World world;
  CHECK(world.connect());
  world.proxy_wire.refuse = true;
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  world.pump();
  CHECK(world.proxy.state() == JoinProxy::State::Idle);
  CHECK(world.authority.ups.empty());
  CHECK(!world.observers[0]->statuses.empty());
  if (!world.observers[0]->statuses.empty()) {
    CHECK(world.observers[0]->statuses.back().first == RelayStatusCode::AuthorityUnreachable);
  }
}

void test_q116_proxy_single_down_port_failure() {
  current = "q116_proxy_single_down_port_failure";
  World world;
  CHECK(world.connect());
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  world.pump();
  CHECK(world.authority.ups.size() == 1);
  world.proxy_radio.refuse = true;
  answer(world, 2, RelayState::Continue, filler(20, 2));
  world.pump();
  CHECK(world.proxy.state() == JoinProxy::State::Idle);
  CHECK(world.authority.aborts.size() == 1);
  if (!world.authority.aborts.empty())
    CHECK(world.authority.aborts[0].reason == RelayAbortReason::ProxyAborted);
}

void test_q116_invalid_config() {
  current = "q116_invalid_config";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig gateway_config{};
  gateway_config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(gateway_config, port);
  CHECK(gateway.set_membership(MembershipState::Member).code == StatusCode::InvalidArgument);
  std::deque<RadioFrame> air;
  RadioPort radio(air, kProxyMac);
  CounterEntropy entropy(1);
  HmacJoinCookie cookie(World::cookie_key());
  JoinProxyConfig proxy_config = World::proxy_config();
  proxy_config.gateway = kInvalidNodeId;
  JoinProxy proxy(proxy_config, radio, port, cookie, entropy);
  CHECK(proxy.set_policy(true).code == StatusCode::InvalidArgument);
}

void test_q116_deadline_without_poll() {
  current = "q116_deadline_without_poll";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  FakeAuthority authority;
  CHECK(gateway.set_membership(MembershipState::Member).ok());
  CHECK(gateway.set_host_sink(&authority).ok());
  const Bytes m1 = up_frame(61, 1, RelayState::Continue);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(m1), 100);
  const Bytes m2 = down_object(parse_up(m1).header, 2, RelayState::Continue, filler(20, 2));
  CHECK(gateway.host_down(kProxy, view(m2), 20100).code == StatusCode::Expired);
  CHECK(mesh.empty());
  CHECK(authority.aborts.size() == 1);
  if (!authority.aborts.empty())
    CHECK(authority.aborts[0].reason == RelayAbortReason::GatewayExpired);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(61, 3, RelayState::Continue)), 20101);
  CHECK(authority.ups.size() == 1);
}

void test_q116_offer_deadline_overflow() {
  current = "q116_offer_deadline_overflow";
  World world;
  world.now = ~MonotonicMs{0} - 10;
  ZtDiscoverBody body{};
  body.org_hint = kOrgHint;
  CHECK(world.links[0]->discover(body, world.now).ok());
  const RadioFrame discover = world.air.front();
  CHECK(world.proxy.on_rld1_rx(discover.from, discover.to, -50, view(discover.bytes),
                                world.now).ok());
  CHECK(world.proxy.poll(world.now).ok());
  CHECK(world.proxy.stats().offers_tx == 0);
}

void test_q116_joiner_link_callback_busy() {
  current = "q116_joiner_link_callback_busy";
  World world;
  CHECK(world.connect());
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  world.pump();
  int callbacks = 0;
  world.observers[0]->respond = [&](const DeviceObserver::Message& message) {
    if (message.step != 2) return;
    ++callbacks;
    const std::uint32_t before = world.links[0]->stats().objects_tx;
    CHECK(world.links[0]
              ->send(JoinAuthPhase::EdhocMessage, 3, view(filler(404, 3)), world.now)
              .code == StatusCode::Busy);
    CHECK(world.links[0]->close().code == StatusCode::Busy);
    CHECK(world.links[0]->set_membership(MembershipState::Unprovisioned).code ==
          StatusCode::Busy);
    CHECK(world.links[0]->connect(world.observers[0]->offers.back()).code == StatusCode::Busy);
    ZtDiscoverBody discover{};
    discover.org_hint = kOrgHint;
    CHECK(world.links[0]->discover(discover, world.now).code == StatusCode::Busy);
    CHECK(world.links[0]->poll(world.now).code == StatusCode::Busy);
    CHECK(world.links[0]
              ->on_rld1_rx(kProxyMac, device_mac(0), ByteView{}, world.now)
              .code == StatusCode::Busy);
    CHECK(world.links[0]->stats().objects_tx == before);
  };
  answer(world, 2, RelayState::Continue, filler(372, 2));
  world.pump();
  CHECK(callbacks == 1);
  CHECK(world.links[0]->connected());
}

void test_q116_oversized_rld1_stage_keeps_down() {
  current = "q116_oversized_rld1_stage_keeps_down";
  World world;
  CHECK(world.connect());
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  world.pump();
  world.drop_radio = [](const RadioFrame& frame) {
    autonomy::Rld1Envelope env{};
    return frame.from == device_mac(0) && autonomy::rld1_decode(view(frame.bytes), env).ok() &&
           env.kind == FrameType::BootstrapReply;
  };
  answer(world, 2, RelayState::Continue, filler(372, 2));
  world.pump();
  CHECK(world.proxy.slot().mode() == JoinObjectSlot::Mode::Sending);
  std::array<std::uint8_t, kRld1JoinChunkData> prefix{};
  prefix[0] = autonomy::kPayloadVersion;
  prefix[1] = static_cast<std::uint8_t>(JoinAuthPhase::EdhocMessage);
  prefix[2] = 3;
  JoinChunk chunk{};
  chunk.phase = JoinAuthPhase::EdhocMessage;
  chunk.step = 3;
  chunk.id = join_rld1_object_id(world.links[0]->nonce());
  chunk.total = static_cast<std::uint16_t>(kJoinObjectHeadSize + kJoinMessageMax + 1);
  chunk.data = ByteView{prefix.data(), prefix.size()};
  std::array<std::uint8_t, autonomy::kRld1MaxBody> body{};
  std::size_t size = 0;
  CHECK(join_chunk_encode(JoinCarrier::Rld1, chunk,
                          MutableByteView{body.data(), body.size()}, size).ok());
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::BootstrapChunk;
  env.claimed_node = kDevice;
  env.transaction_nonce = world.links[0]->nonce();
  std::memcpy(env.body.data(), body.data(), size);
  env.body_size = size;
  autonomy::Rld1Encoded frame{};
  CHECK(autonomy::rld1_encode(env, frame).ok());
  world.proxy.on_rld1_rx(device_mac(0), kProxyMac, -61, frame.view(), world.now);
  CHECK(world.proxy.slot().mode() == JoinObjectSlot::Mode::Sending);
}

void test_q116_supersede_with_full_active_table() {
  current = "q116_supersede_with_full_active_table";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  FakeAuthority authority;
  CHECK(gateway.set_membership(MembershipState::Member).ok());
  CHECK(gateway.set_host_sink(&authority).ok());
  for (std::size_t i = 0; i < JoinRelayGateway::kActiveRelays; ++i) {
    const NodeId proxy = kProxy + i;
    gateway.on_relay_rx(proxy, 2, FrameType::BootstrapAuth,
                        view(up_frame(1, 1, RelayState::Continue, proxy)), 100 + i);
  }
  CHECK(authority.ups.size() == JoinRelayGateway::kActiveRelays);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(2, 1, RelayState::Continue)), 200);
  CHECK(authority.ups.size() == JoinRelayGateway::kActiveRelays + 1);
  CHECK(authority.aborts.size() == 1);
  if (!authority.aborts.empty()) CHECK(authority.aborts[0].reason == RelayAbortReason::Superseded);
}

void test_q116_floor_capacity_and_gateway_restart() {
  current = "q116_floor_capacity_and_gateway_restart";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  FakeAuthority authority;
  CHECK(gateway.set_membership(MembershipState::Member).ok());
  CHECK(gateway.set_host_sink(&authority).ok());
  for (std::size_t i = 0; i < JoinRelayGateway::kProxyFloors; ++i) {
    const NodeId proxy = kProxy + i;
    gateway.on_relay_rx(proxy, 2, FrameType::BootstrapAuth,
                        view(up_frame(1, 1, RelayState::Abort, proxy)), 100 + i);
  }
  CHECK(authority.aborts.empty());
  const NodeId extra = kProxy + JoinRelayGateway::kProxyFloors;
  const Bytes m1 = up_frame(1, 1, RelayState::Continue, extra);
  gateway.on_relay_rx(extra, 2, FrameType::BootstrapAuth, view(m1), 300);
  CHECK(authority.ups.empty());
  config.gateway_epoch = kGatewayEpoch + 1;
  JoinRelayGateway restarted(config, port);
  CHECK(restarted.set_membership(MembershipState::Member).ok());
  CHECK(restarted.set_host_sink(&authority).ok());
  restarted.on_relay_rx(extra, 2, FrameType::BootstrapAuth, view(m1), 301);
  CHECK(authority.ups.empty());
  Bytes fresh = m1;
  fresh[27] = static_cast<std::uint8_t>(kGatewayEpoch + 1);
  restarted.on_relay_rx(extra, 2, FrameType::BootstrapAuth, view(fresh), 302);
  CHECK(authority.ups.size() == 1);
}

void test_q116_sink_detach_terminates_exchange() {
  current = "q116_sink_detach_terminates_exchange";
  World world;
  CHECK(world.connect());
  CHECK(world.links[0]->send(JoinAuthPhase::EdhocMessage, 1, view(filler(59, 1)), world.now).ok());
  world.pump();
  CHECK(world.authority.ups.size() == 1);
  const Bytes old_up = world.authority.ups.front().object;
  CHECK(world.gateway.set_host_sink(nullptr).ok());
  world.pump();
  CHECK(world.proxy.state() == JoinProxy::State::Idle);
  CHECK(world.gateway.set_host_sink(&world.authority).ok());
  world.gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(old_up), world.now);
  CHECK(world.authority.ups.size() == 1);
  CHECK(world.authority.aborts.empty());
  const Bytes fresh = up_frame(2, 1, RelayState::Continue);
  world.gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(fresh), world.now);
  CHECK(world.authority.ups.size() == 2);
}

void test_q116_proxy_restart_token() {
  current = "q116_proxy_restart_token";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  FakeAuthority authority;
  CHECK(gateway.set_membership(MembershipState::Member).ok());
  CHECK(gateway.set_host_sink(&authority).ok());
  const Bytes old_m1 = up_frame(1, 1, RelayState::Continue);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(old_m1), 100);
  Bytes fresh_m1 = old_m1;
  fresh_m1[19] = 9;  // the restarted proxy observes a different joiner MAC
  fresh_m1[31] = static_cast<std::uint8_t>(kProxyEpoch + 1);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(fresh_m1), 101);
  CHECK(authority.ups.size() == 2);
  CHECK(authority.aborts.size() == 1);
  if (!authority.aborts.empty()) CHECK(authority.aborts[0].reason == RelayAbortReason::Superseded);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth, view(old_m1), 102);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      view(up_frame(1, 1, RelayState::Abort)), 103);
  CHECK(authority.ups.size() == 2);
  CHECK(authority.aborts.size() == 1);
  const Bytes old_m2 = down_object(parse_up(old_m1).header, 2, RelayState::Continue,
                                   filler(20, 2));
  CHECK(gateway.host_down(kProxy, view(old_m2), 104).code == StatusCode::Expired);
  const Bytes fresh_m2 = down_object(parse_up(fresh_m1).header, 2, RelayState::Continue,
                                     filler(20, 3));
  CHECK(gateway.host_down(kProxy, view(fresh_m2), 105).ok());
}

void test_q116_epoch_query_rate() {
  current = "q116_epoch_query_rate";
  std::deque<WireFrame> mesh;
  WirePort port(mesh, kGateway);
  JoinRelayGatewayConfig config{};
  config.node = kGateway;
  config.gateway_epoch = kGatewayEpoch;
  JoinRelayGateway gateway(config, port);
  CHECK(gateway.set_membership(MembershipState::Member).ok());
  EpochQuery query{};
  query.nonce[0] = 1;
  std::array<std::uint8_t, kEpochQuerySize> encoded{};
  std::size_t written = 0;
  CHECK(epoch_query_encode(query, MutableByteView{encoded.data(), encoded.size()}, written).ok());
  for (int i = 0; i < 20; ++i)
    gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                        ByteView{encoded.data(), written}, 1000);
  CHECK(mesh.size() == 4);
  CHECK(gateway.slots_in_use() == 0);
  gateway.on_relay_rx(kProxy, 2, FrameType::BootstrapAuth,
                      ByteView{encoded.data(), written}, 1100);
  CHECK(mesh.size() == 5);
}

}  // namespace

void test_q116_size_budgets() {
  current = "q116_size_budgets";
  // #116 §4.1: the RelayBook stays bounded on every target.
  CHECK(sizeof(JoinRelayGateway) <= 6656);
  CHECK(sizeof(JoinProxy) <= 1792);
  CHECK(sizeof(JoinObjectSlot) <= 1120);
  std::printf("q116 sizes: gateway=%zu proxy=%zu slot=%zu\n", sizeof(JoinRelayGateway),
              sizeof(JoinProxy), sizeof(JoinObjectSlot));
}

int main() {
  test_happy_path();
  test_loss_and_reorder();
  test_resume_chunked_opening();
  test_unreachable_and_busy();
  test_flood();
  test_rate_limit();
  test_timeouts();
  test_host_abort_and_revocation();
  test_gateway_slots();
  test_joiner_filters();
  test_cookie_expiry();
  test_deferred_send_after_on_message();
  test_down_duplicate_keeps_sending();
  test_busy_inside_relay_up();
  test_busy_inside_relay_abort();
  test_delivery_failed_callback_busy();
  test_q116_stage_and_terminal_dedup();
  test_colocated_gateway_proxy_down();
  test_q116_proxy_old_up_keeps_down();
  test_q116_gateway_stage_and_abort_identity();
  test_q116_invalid_complete_does_not_poison_floor();
  test_q116_proxy_old_down_keeps_up();
  test_q116_late_query_reply();
  test_q116_host_abort_no_route_terminates();
  test_q116_proxy_single_up_port_failure();
  test_q116_proxy_single_down_port_failure();
  test_q116_invalid_config();
  test_q116_deadline_without_poll();
  test_q116_offer_deadline_overflow();
  test_q116_joiner_link_callback_busy();
  test_q116_oversized_rld1_stage_keeps_down();
  test_q116_supersede_with_full_active_table();
  test_q116_floor_capacity_and_gateway_restart();
  test_q116_sink_detach_terminates_exchange();
  test_q116_proxy_restart_token();
  test_q116_epoch_query_rate();
  test_q116_size_budgets();
  if (failures != 0) {
    std::fprintf(stderr, "%d sdkv1 join relay check(s) failed\n", failures);
    return 1;
  }
  std::puts("routeloom_sdkv1_join_relay_tests: ok");
  return 0;
}
