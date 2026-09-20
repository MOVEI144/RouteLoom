// P1a portable neighbor-discovery tests: the full RLD1 exchange between two
// portable engines over a synchronous fake medium, each rejection path, lease
// lifecycle, capacity, conflict and storm control. Scenario ids from
// docs/design/autonomous-mesh/scenarios.json are noted where they map.

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

#include "test_autonomy.hpp"
#include "test_security.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                          \
  do {                                                                       \
    if (!(expr)) {                                                           \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__,   \
                   #expr);                                                   \
      ++failures;                                                            \
    }                                                                        \
  } while (false)
#define CHECK_OK(expr)                                                       \
  do {                                                                       \
    const auto _status = (expr);                                             \
    if (!_status.ok()) {                                                     \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,       \
                   __LINE__, #expr, _status.detail);                         \
      ++failures;                                                            \
    }                                                                        \
  } while (false)

using namespace routeloom;
using routeloom_test::ScriptedEntropy;
using routeloom_test::TestSecurity;

MacAddress mac_of(const std::uint8_t tail) {
  return MacAddress{0x02, 0x00, 0x00, 0x00, 0x00, tail};
}

// Deterministic entropy adapter with a forceable next fill so suppression
// rolls and slot picks are test-controllable.
class TestEntropy final : public EntropySource {
 public:
  explicit TestEntropy(const std::uint64_t seed) : impl_(seed) {}
  Status fill(const MutableByteView out) noexcept override {
    if (forced_) {
      forced_ = false;
      std::uint64_t v = forced_value_;
      for (std::size_t i = 0; i < out.size; ++i) {
        out.data[i] = static_cast<std::uint8_t>(v & 0xff);
        v >>= 8;
      }
      return Status::success();
    }
    return impl_.fill(out);
  }
  void force_next(const std::uint64_t value) {
    forced_ = true;
    forced_value_ = value;
  }

 private:
  ScriptedEntropy impl_;
  bool forced_{false};
  std::uint64_t forced_value_{0};
};

class TestHooks final : public MembershipHooks {
 public:
  bool local_member(NetworkId) const noexcept override { return is_member; }
  bool known_member(const NodeId peer, NetworkId) const noexcept override {
    return peer_members.count(peer) != 0;
  }
  bool approve_join(NodeId, NetworkId) noexcept override { return approve; }

  bool is_member{false};
  std::set<NodeId> peer_members;
  bool approve{true};
};

class TestObserver final : public DiscoveryObserver {
 public:
  void on_discovery_event(const char* reason, const NodeId peer) noexcept override {
    events.emplace_back(reason, peer);
  }
  bool has(const char* prefix) const {
    for (const auto& e : events) {
      if (e.first.rfind(prefix, 0) == 0) return true;
    }
    return false;
  }
  std::vector<std::pair<std::string, NodeId>> events;
};

struct DiscMedium;
struct Unit;

// Recording + synchronously-delivering port. Delivery happens inside send();
// the medium stamps its shared `now`.
class TestPort final : public DiscoveryPort {
 public:
  struct Sent {
    MacAddress dest{};
    bool wire{false};
    FrameType kind{FrameType::Discover};
    MonotonicMs at{0};
    std::vector<std::uint8_t> bytes;
  };

  TestPort(DiscMedium& medium, const MacAddress self) : medium_(&medium), self_(self) {}

  Status send_rld1(const MacAddress& dest, const ByteView encoded) noexcept override;
  Status send_wire(BindingId, const MacAddress& dest, const FrameType type,
                   const ByteView payload) noexcept override;

  std::size_t count_kind(const FrameType kind) const {
    std::size_t n = 0;
    for (const auto& s : sent) {
      if (!s.wire && s.kind == kind) ++n;
    }
    return n;
  }
  std::size_t count_wire(const FrameType kind) const {
    std::size_t n = 0;
    for (const auto& s : sent) {
      if (s.wire && s.kind == kind) ++n;
    }
    return n;
  }
  std::vector<MonotonicMs> times_of(FrameType kind, bool wire) const {
    std::vector<MonotonicMs> out;
    for (const auto& s : sent) {
      if (s.wire == wire && s.kind == kind) out.push_back(s.at);
    }
    return out;
  }

  std::vector<Sent> sent;

 private:
  DiscMedium* medium_;
  MacAddress self_;
};

struct DiscMedium {
  MonotonicMs now{0};
  bool drop_rld1{false};
  bool drop_wire{false};
  std::vector<Unit*> units;
  // Directed link cuts: (src,dest) pairs that never receive traffic.
  std::vector<std::pair<MacAddress, MacAddress>> blocked;

  bool link_open(const MacAddress& src, const MacAddress& dest) const {
    for (const auto& p : blocked) {
      if (p.first == src && p.second == dest) return false;
    }
    return true;
  }
  void block(const MacAddress& src, const MacAddress& dest) {
    blocked.emplace_back(src, dest);
  }
  void deliver_rld1(const MacAddress& src, const MacAddress& dest,
                    const ByteView bytes);
  void deliver_wire(const MacAddress& src, const MacAddress& dest,
                    const FrameType type, const ByteView payload);
};

// One discovery node: security, authenticator, hooks, entropy, port, engine.
struct Unit {
  Unit(DiscMedium& medium, const NodeId id, const std::uint8_t mac_tail,
       const NetworkId network, const std::uint32_t hint, const bool member)
      : mac(mac_of(mac_tail)),
        node(id),
        auth(security, 1),
        entropy(1000 + id),
        port(medium, mac),
        engine(make_config(id, mac, network, hint), port, auth, hooks, entropy,
               observer) {
    hooks.is_member = member;
    medium.units.push_back(this);
  }

  static DiscoveryConfig make_config(const NodeId id, const MacAddress& mac,
                                     const NetworkId network,
                                     const std::uint32_t hint) {
    DiscoveryConfig config{};
    config.node = id;
    config.mac = mac;
    config.network = network;
    config.network_hint = hint;
    config.capability_bits = 1;
    config.probe_timeout_ms = 200;
    return config;
  }

  MacAddress mac;
  NodeId node;
  TestSecurity security;
  DevPskAuthenticator auth;
  TestHooks hooks;
  TestEntropy entropy;
  TestObserver observer;
  TestPort port;
  NeighborDiscovery engine;
};

Status TestPort::send_rld1(const MacAddress& dest, const ByteView encoded) noexcept {
  const FrameType kind = encoded.size > 5
                             ? static_cast<FrameType>(encoded.data[5])
                             : FrameType::Diagnostic;
  sent.push_back(Sent{dest, false, kind, medium_->now,
                      std::vector<std::uint8_t>(encoded.data,
                                                encoded.data + encoded.size)});
  medium_->deliver_rld1(self_, dest, encoded);
  return Status::success();
}

Status TestPort::send_wire(BindingId, const MacAddress& dest, const FrameType type,
                           const ByteView payload) noexcept {
  sent.push_back(Sent{dest, true, type, medium_->now,
                      std::vector<std::uint8_t>(payload.data,
                                                payload.data + payload.size)});
  medium_->deliver_wire(self_, dest, type, payload);
  return Status::success();
}

void DiscMedium::deliver_rld1(const MacAddress& src, const MacAddress& dest,
                              const ByteView bytes) {
  if (drop_rld1) return;
  for (auto* u : units) {
    if (u->mac == src) continue;
    if (dest == discovery_const::kBroadcastMac || u->mac == dest) {
      if (!link_open(src, u->mac)) continue;
      u->engine.on_rld1_rx(src, bytes, now);
    }
  }
}

void DiscMedium::deliver_wire(const MacAddress& src, const MacAddress& dest,
                              const FrameType type, const ByteView payload) {
  if (drop_wire) return;
  for (auto* u : units) {
    if (u->mac == dest && link_open(src, u->mac)) {
      u->engine.on_wire_rx(src, type, payload, now);
    }
  }
}

struct DiscWorld {
  DiscMedium medium;
  std::vector<std::unique_ptr<Unit>> units;

  Unit& add(const NodeId id, const std::uint8_t mac_tail, const bool member,
            const std::uint32_t hint = 0xC0FFEE, const NetworkId network = 7) {
    units.push_back(
        std::make_unique<Unit>(medium, id, mac_tail, network, hint, member));
    return *units.back();
  }
  void start_all() {
    for (auto& u : units) CHECK_OK(u->engine.start(medium.now));
  }
  void run(const MonotonicMs duration_ms, const MonotonicMs step = 5) {
    const MonotonicMs end = medium.now + duration_ms;
    for (; medium.now < end; medium.now += step) {
      for (auto& u : units) u->engine.poll(medium.now);
    }
  }
};

// Build an RLD1 frame of an arbitrary (even forbidden) kind by patching a
// valid encoded DISCOVER — the encoder rightfully refuses these kinds, but
// tests need hostile bytes on the wire.
std::vector<std::uint8_t> forged_envelope(const std::uint8_t kind,
                                          const NodeId claimed,
                                          const std::array<std::uint8_t, 16>& nonce,
                                          const ByteView body) {
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::Discover;
  env.network_hint = 0xC0FFEE;
  env.claimed_node = claimed;
  env.transaction_nonce = nonce;
  if (body.size > env.body.size()) return {};
  std::memcpy(env.body.data(), body.data, body.size);
  env.body_size = body.size;
  autonomy::Rld1Encoded enc{};
  if (!autonomy::rld1_encode(env, enc)) return {};
  std::vector<std::uint8_t> bytes(enc.bytes.begin(), enc.bytes.begin() + enc.size);
  bytes[5] = kind;  // kind field offset in the 44-byte header
  return bytes;
}

// A legitimate kind-3 envelope carrying a BootstrapAuth body (for crafting
// PROVE/CONFIRM/FINISH with chosen body bytes).
std::vector<std::uint8_t> auth_envelope(const autonomy::AuthPhase phase,
                                      const NodeId claimed,
                                      const std::array<std::uint8_t, 16>& nonce,
                                      const ByteView body) {
  autonomy::BootstrapAuthBody auth{};
  auth.phase = phase;
  if (body.size > auth.body.size()) return {};
  std::memcpy(auth.body.data(), body.data, body.size);
  auth.body_size = body.size;
  autonomy::EncodedPayload payload{};
  if (!autonomy::bootstrap_auth_encode(auth, payload)) return {};
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::BootstrapAuth;
  env.network_hint = 0xC0FFEE;
  env.claimed_node = claimed;
  env.transaction_nonce = nonce;
  std::memcpy(env.body.data(), payload.bytes.data(), payload.size);
  env.body_size = payload.size;
  autonomy::Rld1Encoded enc{};
  if (!autonomy::rld1_encode(env, enc)) return {};
  return std::vector<std::uint8_t>(enc.bytes.begin(), enc.bytes.begin() + enc.size);
}

// Extract the transaction nonce out of a captured DISCOVER/OFFER frame.
std::array<std::uint8_t, 16> nonce_of(const std::vector<std::uint8_t>& frame) {
  std::array<std::uint8_t, 16> nonce{};
  if (frame.size() >= 40) std::copy_n(frame.begin() + 24, 16, nonce.begin());
  return nonce;
}

void run_exchange(DiscWorld& world, Unit& a) {
  CHECK_OK(a.engine.begin_discovery(world.medium.now));
  world.run(3000);
}

// --- Tests ----------------------------------------------------------------------

// Byte-level pin of the emitted DISCOVER envelope (02 §4 layout, golden-style).
void test_rld1_envelope_bytes() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  world.add(2, 0xB2, /*member=*/true);
  world.start_all();
  CHECK_OK(a.engine.begin_discovery(0));

  CHECK(a.port.count_kind(FrameType::Discover) == 1);
  const auto& bytes = a.port.sent.front().bytes;
  CHECK(bytes.size() == autonomy::kRld1HeaderSize);  // empty body
  const auto u32 = [&](const std::size_t off) {
    return (static_cast<std::uint32_t>(bytes[off]) << 24U) |
           (static_cast<std::uint32_t>(bytes[off + 1]) << 16U) |
           (static_cast<std::uint32_t>(bytes[off + 2]) << 8U) |
           static_cast<std::uint32_t>(bytes[off + 3]);
  };
  const auto u64 = [&](const std::size_t off) {
    std::uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v = (v << 8U) | bytes[off + i];
    return v;
  };
  CHECK(u32(0) == 0x524c4431);           // "RLD1"
  CHECK(bytes[4] == 1);                  // version
  CHECK(bytes[5] == 1);                  // kind = Discover
  CHECK(u32(6) >> 16U == autonomy::kRld1HeaderSize);
  CHECK((u32(6) & 0xffffU) == bytes.size());  // total_len
  CHECK(bytes[10] == 0 && bytes[11] == 0);    // flags u16
  CHECK(u32(12) == 0xC0FFEE);            // network hint
  CHECK(u64(16) == 1);                   // claimed node
  CHECK(u32(40) == 1);                   // capability bits
  // Round-trip through the pinned codec.
  autonomy::Rld1Envelope back{};
  CHECK_OK(autonomy::rld1_decode(
      ByteView{bytes.data(), bytes.size()}, back));
  CHECK(back.kind == FrameType::Discover && back.claimed_node == 1);
}

// The full member<->member exchange: DISCOVER -> OFFER -> PROVE -> CONFIRM ->
// FINISH -> probe/result -> REACHABLE (D3-01, D3-11).
void test_member_member_exchange() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();

  run_exchange(world, a);

  NeighborPhase phase{};
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);
  CHECK(b.engine.phase_of(a.mac, phase) && phase == NeighborPhase::Reachable);
  CHECK(a.engine.data_permitted(b.mac));
  CHECK(b.engine.data_permitted(a.node));

  // Members stay Member through the whole exchange (06 §2.1: no demotion).
  CHECK(a.engine.membership().state() == MembershipState::Member);
  CHECK(b.engine.membership().state() == MembershipState::Member);

  CHECK(a.port.count_kind(FrameType::Discover) >= 1);
  CHECK(b.port.count_kind(FrameType::Offer) >= 1);
  CHECK(a.port.count_kind(FrameType::BootstrapAuth) >= 2);  // PROVE + FINISH
  CHECK(b.port.count_kind(FrameType::BootstrapAuth) >= 1);  // CONFIRM
  CHECK(a.port.count_wire(FrameType::NeighborProbe) >= 1);
  CHECK(b.port.count_wire(FrameType::NeighborResult) >= 1);

  BindingId binding{};
  CHECK(a.engine.binding_of(2, binding) && binding != kInvalidBindingId);
  CHECK(b.engine.binding_of(1, binding) && binding != kInvalidBindingId);
  CHECK(a.engine.stats().auths_completed == 1);
  CHECK(b.engine.stats().auths_completed == 1);
}

// New-node join: device auth alone is not membership; pending commit blocks
// DATA; the dev approval hook commits -> Member + REACHABLE (D3-02, D3-12).
void test_new_node_join() {
  DiscWorld world;
  Unit& a = world.add(9, 0xA9, /*member=*/false);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  b.hooks.peer_members.insert(9);
  a.hooks.peer_members.insert(2);
  a.hooks.approve = false;  // authority absent -> bounded hold, never auto-ok
  world.start_all();

  run_exchange(world, a);

  CHECK(a.engine.membership().state() ==
        MembershipState::AuthorizedPendingCommit);
  NeighborPhase phase{};
  CHECK(a.engine.phase_of(b.mac, phase));
  CHECK(phase != NeighborPhase::Reachable);
  CHECK(!a.engine.data_permitted(b.mac));
  CHECK(!b.engine.data_permitted(a.node));
  CHECK(a.engine.stats().auths_completed == 1);  // auth done, member not yet

  a.hooks.approve = true;  // admission result arrives
  world.run(3000);
  CHECK(a.engine.membership().state() == MembershipState::Member);
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);
  CHECK(a.engine.data_permitted(b.mac));
}

// Forbidden kinds on RLD1 are rejected at the single classification point,
// never falling back into the Wire parser (D3-13).
void test_rld1_kind_rejects() {
  DiscWorld world;
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  world.start_all();
  const MacAddress attacker = mac_of(0x77);
  const std::array<std::uint8_t, 16> nonce{};

  for (const std::uint8_t kind : {4, 7, 16, 99}) {  // Result/Query/DATA/unknown
    const auto bytes = forged_envelope(kind, 9, nonce, ByteView{nullptr, 0});
    CHECK(!bytes.empty());
    b.engine.on_rld1_rx(attacker, ByteView{bytes.data(), bytes.size()},
                        world.medium.now);
  }
  CHECK(b.engine.stats().kind_rejects == 4);
  CHECK(b.engine.candidate_count() == 0);
}

// Foreign and replayed cookies are rejected before the transcript check; a
// cookie issued for a different nonce/MAC cannot open the exchange (02 §5).
void test_cookie_rejects() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();

  // Drive only B's side so A never sends its real PROVE: B creates the
  // candidate and emits its OFFER, then we inject a forged PROVE.
  CHECK_OK(a.engine.begin_discovery(world.medium.now));  // DISCOVER -> B
  world.medium.now += 400;  // past every possible offer slot
  b.engine.poll(world.medium.now);
  CHECK(b.engine.candidate_count() == 1);
  CHECK(b.port.count_kind(FrameType::Offer) == 1);

  const std::array<std::uint8_t, 16> nonce = nonce_of(a.port.sent.front().bytes);
  CHECK((nonce != std::array<std::uint8_t, 16>{}));

  // Foreign cookie: garbage echo + garbage tag, correct nonce/MAC.
  std::array<std::uint8_t, 32> prove_body{};
  for (std::size_t i = 0; i < prove_body.size(); ++i) prove_body[i] = 0xAB;
  const auto forged = auth_envelope(autonomy::AuthPhase::Prove, 1, nonce,
                                    ByteView{prove_body.data(), prove_body.size()});
  CHECK(!forged.empty());
  b.engine.on_rld1_rx(a.mac, ByteView{forged.data(), forged.size()},
                      world.medium.now);
  CHECK(b.engine.stats().cookie_rejects == 1);
  CHECK(b.observer.has("COOKIE_REJECT"));
  CHECK(b.engine.candidate_count() == 0);  // reject releases the transaction

  // Same forged PROVE again: no live transaction, silently ignored.
  b.engine.on_rld1_rx(a.mac, ByteView{forged.data(), forged.size()},
                      world.medium.now);
  CHECK(b.engine.stats().cookie_rejects == 1);

  // Replayed cookie: capture the cookie B just issued, start a fresh
  // transaction (new nonce -> different sealed cookie) and replay the old
  // cookie — the material check must reject it.
  std::array<std::uint8_t, 16> old_cookie{};
  for (const auto& s : b.port.sent) {
    if (!s.wire && s.kind == FrameType::Offer) {
      autonomy::Rld1Envelope env{};
      CHECK_OK(autonomy::rld1_decode(
          ByteView{s.bytes.data(), s.bytes.size()}, env));
      std::copy_n(env.body.begin() + 4, 16, old_cookie.begin());
    }
  }
  CHECK((old_cookie != std::array<std::uint8_t, 16>{}));

  std::array<std::uint8_t, 16> nonce2{};
  nonce2[15] = 0x77;  // any nonce != the one the cookie was sealed for
  world.medium.now += 500;  // past the 400ms density window: always answered
  const auto discover2 = forged_envelope(
      static_cast<std::uint8_t>(FrameType::Discover), 1, nonce2,
      ByteView{nullptr, 0});
  b.engine.on_rld1_rx(a.mac, ByteView{discover2.data(), discover2.size()},
                      world.medium.now);
  world.medium.now += 400;
  b.engine.poll(world.medium.now);
  CHECK(b.engine.candidate_count() == 1);
  CHECK(b.port.count_kind(FrameType::Offer) == 2);

  std::array<std::uint8_t, 32> replay_body{};
  std::copy(old_cookie.begin(), old_cookie.end(), replay_body.begin());
  const auto replay = auth_envelope(
      autonomy::AuthPhase::Prove, 1, nonce2,
      ByteView{replay_body.data(), replay_body.size()});
  CHECK(!replay.empty());
  b.engine.on_rld1_rx(a.mac, ByteView{replay.data(), replay.size()},
                      world.medium.now);
  CHECK(b.engine.stats().cookie_rejects == 2);
  CHECK(b.port.count_kind(FrameType::BootstrapAuth) == 0);  // never CONFIRMed
}

// DATA is gated until REACHABLE + verified membership; unknown MACs on the
// Wire lane are rejected outright (06 §3.1, §4.3).
void test_data_gate() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();

  // Unknown MAC on the Wire lane: rejected before anything else.
  const std::uint8_t junk[8] = {0};
  b.engine.on_wire_rx(mac_of(0x66), FrameType::Data,
                      ByteView{junk, sizeof(junk)}, world.medium.now);
  CHECK(b.engine.stats().kind_rejects == 1);
  CHECK(b.observer.has("KIND_REJECT"));  // unknown MAC: rejected outright

  // Full exchange while the Wire lane is cut: everything binds but probes
  // never land, so the record stays BOUND — never REACHABLE.
  world.medium.drop_wire = true;
  CHECK_OK(a.engine.begin_discovery(world.medium.now));
  CHECK(!a.engine.data_permitted(b.mac));  // no record yet
  world.run(1500);
  NeighborPhase phase{};
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Bound);
  CHECK(!a.engine.data_permitted(b.mac));
  const std::uint32_t rejects = a.engine.stats().kind_rejects;
  a.engine.on_wire_rx(b.mac, FrameType::Data, ByteView{junk, sizeof(junk)},
                      world.medium.now);
  CHECK(a.engine.stats().kind_rejects == rejects + 1);
  CHECK(a.observer.has("DATA_REJECT"));

  // Restore the lane: probes land, REACHABLE unlocks DATA.
  world.medium.drop_wire = false;
  world.run(1500);
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);
  CHECK(a.engine.data_permitted(b.mac));
}

// Candidate table (16) and transient peer slots (3) are hard bounds; pressure
// is reported as PEER_CAPACITY, never a silent drop (D3-04, D3-05).
void test_capacity() {
  DiscWorld world;
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  world.start_all();

  for (std::uint8_t i = 0; i < 18; ++i) {
    b.entropy.force_next(0);  // roll == 0 -> never suppressed
    const auto bytes =
        forged_envelope(static_cast<std::uint8_t>(FrameType::Discover),
                        100 + i, std::array<std::uint8_t, 16>{},
                        ByteView{nullptr, 0});
    b.engine.on_rld1_rx(mac_of(static_cast<std::uint8_t>(0x10 + i)),
                        ByteView{bytes.data(), bytes.size()}, world.medium.now);
  }
  CHECK(b.engine.candidate_count() == 16);
  CHECK(b.engine.stats().peer_capacity >= 2);   // parked + table-full
  CHECK(b.observer.has("PEER_CAPACITY"));
  world.run(400);
  // At most 3 transient slots -> at most 3 offers in flight.
  CHECK(b.port.count_kind(FrameType::Offer) <= 3);
  // 18 discovers produced 16 bounded records — no unbounded growth.
  CHECK(b.engine.stats().discovers_rx == 18);
}

// Density suppression: observed discover density lowers the response
// probability but never reaches zero (02 §6, D3-04).
void test_density_suppression() {
  DiscWorld world;
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  world.start_all();
  for (std::uint8_t i = 0; i < 8; ++i) {
    b.entropy.force_next(1);  // roll 1 % (density+1) != 0 -> suppressed
    const auto bytes =
        forged_envelope(static_cast<std::uint8_t>(FrameType::Discover),
                        100 + i, std::array<std::uint8_t, 16>{},
                        ByteView{nullptr, 0});
    b.engine.on_rld1_rx(mac_of(static_cast<std::uint8_t>(0x30 + i)),
                        ByteView{bytes.data(), bytes.size()}, world.medium.now);
  }
  CHECK(b.engine.stats().discovers_rx == 8);
  CHECK(b.engine.stats().suppressed_offers == 7);  // first always answered
  CHECK(b.engine.candidate_count() == 1);
}

// Lease expiry demotes to STALE — the binding record survives, only the
// usability is withdrawn (02 §9).
void test_lease_expiry() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();
  run_exchange(world, a);

  NeighborPhase phase{};
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);

  // Silence the peer: probes go unanswered, the 30s lease lapses.
  world.medium.drop_wire = true;
  world.run(31000);
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Stale);
  CHECK(a.engine.neighbor_count() == 1);  // demoted, not deleted
  CHECK(!a.engine.data_permitted(b.mac));
  // The verified mapping still resolves so re-confirmation probes can find
  // the peer; only data traffic is gated off.
  NodeId resolved = kInvalidNodeId;
  CHECK(a.engine.node_of(b.mac, resolved) && resolved == 2);
  CHECK(a.engine.stats().stale_expirations >= 1);
}

// Same NodeId appearing on a new MAC while the old binding is alive must be
// quarantined, not overwritten (02 §8, D3-03).
void test_mac_change_conflict() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();
  run_exchange(world, a);

  NeighborPhase phase{};
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);

  // A second radio claiming NodeId 2 on a different MAC. Cut clone<->B so the
  // only possible responder is A (otherwise the clone might bind to B).
  Unit& clone = world.add(2, 0xC3, /*member=*/true);
  clone.hooks.peer_members.insert(1);
  world.medium.block(clone.mac, b.mac);
  world.medium.block(b.mac, clone.mac);
  CHECK_OK(clone.engine.start(world.medium.now));
  run_exchange(world, clone);

  CHECK(a.engine.phase_of(clone.mac, phase) &&
        phase == NeighborPhase::Conflict);
  CHECK(a.observer.has("BINDING_CONFLICT"));
  CHECK(a.engine.stats().conflicts >= 1);
  // A quarantined record never resolves: neither MAC->node nor node->binding
  // may attribute the conflicted radio.
  NodeId resolved = kInvalidNodeId;
  BindingId binding = kInvalidBindingId;
  CHECK(!a.engine.node_of(clone.mac, resolved));
  // The original binding is untouched and still usable.
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);
  CHECK(a.engine.data_permitted(b.mac));
  CHECK(a.engine.node_of(b.mac, resolved) && resolved == 2);
  CHECK(a.engine.binding_of(2, binding) && binding != kInvalidBindingId);
}

// Simultaneous open: both nodes discover at once; the verified lower NodeId
// keeps the requester role and exactly one exchange converges (02 §3, D3-07).
void test_simultaneous_open() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);  // lower NodeId wins
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();

  CHECK_OK(a.engine.begin_discovery(world.medium.now));
  CHECK_OK(b.engine.begin_discovery(world.medium.now));
  world.run(4000);

  NeighborPhase phase{};
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);
  CHECK(b.engine.phase_of(a.mac, phase) && phase == NeighborPhase::Reachable);
  CHECK(a.engine.neighbor_count() == 1);
  CHECK(b.engine.neighbor_count() == 1);
  // Exactly one auth exchange completed per side — no duplicate bindings.
  CHECK(a.engine.stats().auths_completed == 1);
  CHECK(b.engine.stats().auths_completed == 1);
}

// Requester storm control: a second handshake start waits out the 1/s burst-1
// token; a concurrent begin is refused (02 §6).
void test_handshake_rate_limit() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  Unit& c = world.add(3, 0xC4, /*member=*/true);
  a.hooks.peer_members.insert(2);
  a.hooks.peer_members.insert(3);
  b.hooks.peer_members.insert(1);
  c.hooks.peer_members.insert(1);
  world.start_all();

  CHECK_OK(a.engine.begin_discovery(world.medium.now));
  CHECK(a.engine.begin_discovery(world.medium.now).code ==
        StatusCode::WouldBlock);  // one exchange at a time
  world.run(700);  // first exchange completes well inside the 1s token window
  NeighborPhase phase{};
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);
  const auto proves = a.port.times_of(FrameType::BootstrapAuth, false);
  CHECK(proves.size() >= 1);
  const MonotonicMs first_prove = proves.front();

  // A second exchange inside the same 1s window: its PROVE must wait for the
  // handshake-start token (1/s, burst 1).
  CHECK_OK(a.engine.begin_discovery(world.medium.now));
  world.run(3000);
  const auto all = a.port.times_of(FrameType::BootstrapAuth, false);
  CHECK(all.size() >= 3);  // PROVE+FINISH of #1, PROVE (+FINISH) of #2
  // The second PROVE (kind 3, phase Prove=1) is >= 1s after the first.
  std::vector<MonotonicMs> prove_times;
  for (const auto& s : a.port.sent) {
    if (!s.wire && s.kind == FrameType::BootstrapAuth && s.bytes.size() > 45 &&
        s.bytes[45] == 1) {
      prove_times.push_back(s.at);
    }
  }
  CHECK(prove_times.size() >= 2);
  CHECK(prove_times[1] >= first_prove + 1000);
  (void)c;
}

// A revoked node emits nothing and answers nothing (06 §4.2, D3-15).
void test_revoked_silent() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();

  b.engine.membership().revoke();
  CHECK(b.engine.membership().state() == MembershipState::Revoked);
  const std::size_t sent_before = b.port.sent.size();
  CHECK_OK(a.engine.begin_discovery(world.medium.now));
  world.run(1000);
  CHECK(b.port.sent.size() == sent_before);        // no OFFER, nothing
  CHECK(b.engine.candidate_count() == 0);          // RX fully gated
  CHECK(b.engine.stats().kind_rejects >= 1);
  // The peer cannot be rejoined over the radio path.
  CHECK(b.engine.begin_discovery(world.medium.now).code ==
        StatusCode::AuthorizationFailed);
}

// The production profile is honestly unavailable — every operation reports
// AUTH_PROFILE_UNAVAILABLE instead of stubbing security (02 §5).
void test_production_unavailable() {
  UnavailableAuthenticator auth;
  CookieMaterial material{};
  AuthTag tag{};
  AuthTranscript transcript{};
  CHECK(auth.security_profile() == SecurityProfile::Production);
  CHECK(auth.cookie_seal(material, tag).code ==
        StatusCode::AuthProfileUnavailable);
  CHECK(auth.cookie_verify(material, tag).code ==
        StatusCode::AuthProfileUnavailable);
  CHECK(auth.attest(autonomy::AuthPhase::Prove, transcript, tag).code ==
        StatusCode::AuthProfileUnavailable);
  CHECK(auth.verify(autonomy::AuthPhase::Prove, transcript, tag).code ==
        StatusCode::AuthProfileUnavailable);
  CHECK(std::strcmp(status_code_name(StatusCode::AuthProfileUnavailable),
                    "AUTH_PROFILE_UNAVAILABLE") == 0);
}

// Craft a BootstrapChunk envelope: body = ver u8 | subtype u8 | txn u32 |
// offset u16 | total u16 | data.
std::vector<std::uint8_t> chunk_envelope(
    const NodeId claimed, const std::array<std::uint8_t, 16>& nonce,
    const std::uint32_t txn, const std::uint16_t offset,
    const std::uint16_t total, const ByteView data) {
  std::array<std::uint8_t, 10 + autonomy::kRld1MaxBody> body{};
  auto put32 = [&](const std::size_t at, const std::uint32_t v) {
    body[at] = static_cast<std::uint8_t>(v >> 24U);
    body[at + 1] = static_cast<std::uint8_t>(v >> 16U);
    body[at + 2] = static_cast<std::uint8_t>(v >> 8U);
    body[at + 3] = static_cast<std::uint8_t>(v);
  };
  auto put16 = [&](const std::size_t at, const std::uint16_t v) {
    body[at] = static_cast<std::uint8_t>(v >> 8U);
    body[at + 1] = static_cast<std::uint8_t>(v);
  };
  body[0] = 1;
  body[1] = 1;
  put32(2, txn);
  put16(6, offset);
  put16(8, total);
  if (data.size > autonomy::kRld1MaxBody - 10) return {};
  std::memcpy(body.data() + 10, data.data, data.size);
  return forged_envelope(static_cast<std::uint8_t>(FrameType::BootstrapChunk),
                         claimed, nonce,
                         ByteView{body.data(), 10 + data.size});
}

// Bounded reassembly: RLD1 chunks may carry BootstrapAuth only, require a live
// transaction, and re-check admission on the completed inner object (06 §3.2).
void test_fragment_reassembly() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();

  CHECK_OK(a.engine.begin_discovery(world.medium.now));
  world.medium.now += 400;
  b.engine.poll(world.medium.now);
  CHECK(b.engine.candidate_count() == 1);
  const std::array<std::uint8_t, 16> nonce = nonce_of(a.port.sent.front().bytes);

  // Real cookie echo + garbage prove tag, encoded as a BootstrapAuth payload
  // and split across two chunks.
  autonomy::BootstrapAuthBody auth{};
  auth.phase = autonomy::AuthPhase::Prove;
  const std::vector<std::uint8_t>& offer =
      b.port.sent.back().bytes;  // OFFER body[4..20] = cookie
  autonomy::Rld1Envelope offer_env{};
  CHECK_OK(autonomy::rld1_decode(
      ByteView{offer.data(), offer.size()}, offer_env));
  std::memcpy(auth.body.data(), offer_env.body.data() + 4, 16);
  for (std::size_t i = 16; i < 32; ++i) auth.body[i] = 0x5A;  // bad tag
  auth.body_size = 32;
  autonomy::EncodedPayload payload{};
  CHECK_OK(autonomy::bootstrap_auth_encode(auth, payload));
  CHECK(payload.size == 36);

  const std::uint32_t txn = 0xABCD;
  const auto c1 = chunk_envelope(1, nonce, txn, 0, 36,
                                 ByteView{payload.bytes.data(), 20});
  const auto c2 = chunk_envelope(1, nonce, txn, 20, 36,
                                 ByteView{payload.bytes.data() + 20, 16});
  b.engine.on_rld1_rx(a.mac, ByteView{c1.data(), c1.size()}, world.medium.now);
  CHECK(b.engine.stats().auth_tag_rejects == 0);  // nothing dispatched yet
  b.engine.on_rld1_rx(a.mac, ByteView{c2.data(), c2.size()}, world.medium.now);
  // The reassembled PROVE ran the cookie check (passed) and failed the tag:
  // evidence the inner dispatch happened on the completed object.
  CHECK(b.engine.stats().auth_tag_rejects == 1);
  CHECK(b.observer.has("AUTH_FAILED"));
  // Each chunk produced a control reply on kind 6.
  CHECK(b.port.count_kind(FrameType::BootstrapReply) == 2);
}

// Fragment rejection paths: no live transaction, oversize object, out-of-order
// delivery, undecodable inner object, and the 4-slot assembly bound.
void test_fragment_rejects() {
  DiscWorld world;
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  world.start_all();
  const MacAddress peer = mac_of(0x71);
  const std::array<std::uint8_t, 16> nonce{};

  // No live transaction owns this nonce -> rejected, no slot consumed.
  const std::uint8_t data[4] = {1, 2, 3, 4};
  auto c = chunk_envelope(7, nonce, 1, 0, 8, ByteView{data, 4});
  b.engine.on_rld1_rx(peer, ByteView{c.data(), c.size()}, world.medium.now);
  CHECK(b.engine.stats().kind_rejects == 1);

  // Oversize total (>1024) and out-of-order offsets are rejected/NAKed.
  auto big = chunk_envelope(7, nonce, 1, 0, 2000, ByteView{data, 4});
  b.engine.on_rld1_rx(peer, ByteView{big.data(), big.size()}, world.medium.now);
  CHECK(b.engine.stats().kind_rejects == 2);

  // Give the peer a live transaction, then deliver out-of-order.
  const auto disc = forged_envelope(
      static_cast<std::uint8_t>(FrameType::Discover), 7,
      std::array<std::uint8_t, 16>{}, ByteView{nullptr, 0});
  b.engine.on_rld1_rx(peer, ByteView{disc.data(), disc.size()},
                      world.medium.now);
  CHECK(b.engine.candidate_count() == 1);
  auto ooo = chunk_envelope(7, std::array<std::uint8_t, 16>{}, 9, 8, 20,
                            ByteView{data, 4});
  const std::size_t replies = b.port.count_kind(FrameType::BootstrapReply);
  b.engine.on_rld1_rx(peer, ByteView{ooo.data(), ooo.size()}, world.medium.now);
  CHECK(b.port.count_kind(FrameType::BootstrapReply) == replies + 1);

  // Garbage inner object: reassembly completes but decode fails -> reject.
  std::array<std::uint8_t, 8> garbage{};
  std::memset(garbage.data(), 0xFF, garbage.size());
  auto g1 = chunk_envelope(7, std::array<std::uint8_t, 16>{}, 10, 0, 8,
                           ByteView{garbage.data(), 8});
  const std::uint32_t rejects = b.engine.stats().kind_rejects;
  b.engine.on_rld1_rx(peer, ByteView{g1.data(), g1.size()}, world.medium.now);
  CHECK(b.engine.stats().kind_rejects == rejects + 1);

  // Assembly bound: 4 slots. Five live transactions each opening one chunk
  // exhausts them — the fifth is reported as PEER_CAPACITY.
  const std::uint32_t capacity = b.engine.stats().peer_capacity;
  for (std::uint8_t i = 0; i < 5; ++i) {
    b.entropy.force_next(0);  // never suppressed
    std::array<std::uint8_t, 16> n{};
    n[15] = static_cast<std::uint8_t>(0x40 + i);
    const MacAddress mac = mac_of(static_cast<std::uint8_t>(0x80 + i));
    const auto d = forged_envelope(
        static_cast<std::uint8_t>(FrameType::Discover), 50 + i, n,
        ByteView{nullptr, 0});
    b.engine.on_rld1_rx(mac, ByteView{d.data(), d.size()}, world.medium.now);
    const auto k = chunk_envelope(50 + i, n, 77, 0, 20, ByteView{data, 4});
    b.engine.on_rld1_rx(mac, ByteView{k.data(), k.size()}, world.medium.now);
  }
  CHECK(b.engine.stats().peer_capacity > capacity);
}

// A FINISH for a released or never-opened transaction is ignored — it can
// never resurrect a dead exchange (06 §2.2).
void test_stale_finish() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();

  // FINISH with no live transaction at all.
  std::array<std::uint8_t, 16> tag{};
  const auto fin = auth_envelope(autonomy::AuthPhase::Finish, 1,
                                 std::array<std::uint8_t, 16>{},
                                 ByteView{tag.data(), 16});
  b.engine.on_rld1_rx(a.mac, ByteView{fin.data(), fin.size()},
                      world.medium.now);
  CHECK(b.engine.candidate_count() == 0);
  CHECK(!b.observer.has("BOUND"));

  // Same for a CONFIRM with no live outbound at the requester side.
  a.engine.on_rld1_rx(b.mac, ByteView{fin.data(), fin.size()},
                      world.medium.now);
  CHECK(a.engine.stats().auths_completed == 0);
}

// Owner controls: planned suspension demotes to STALE on wake; revocation
// makes the binding unusable while the record survives (02 §9).
void test_suspend_revoke() {
  DiscWorld world;
  Unit& a = world.add(1, 0xA1, /*member=*/true);
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();
  run_exchange(world, a);
  NeighborPhase phase{};
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);

  // Planned absence: Suspended until the given instant, then Stale.
  CHECK_OK(a.engine.suspend_peer(2, world.medium.now + 10000));
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Suspended);
  CHECK(!a.engine.data_permitted(b.mac));
  world.run(11000);
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Stale);

  // Revocation: record survives, binding unusable, RX rejected, and the
  // dead mapping no longer resolves for sends or lease attribution.
  CHECK_OK(a.engine.revoke_peer(2));
  CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Revoked);
  CHECK(a.engine.neighbor_count() == 1);
  NodeId resolved = kInvalidNodeId;
  BindingId binding = kInvalidBindingId;
  CHECK(!a.engine.node_of(b.mac, resolved));
  CHECK(!a.engine.binding_of(2, binding));
  const std::uint32_t rejects = a.engine.stats().kind_rejects;
  const std::uint8_t junk[8] = {0};
  a.engine.on_wire_rx(b.mac, FrameType::NeighborProbe,
                      ByteView{junk, sizeof(junk)}, world.medium.now);
  CHECK(a.engine.stats().kind_rejects == rejects + 1);
  CHECK(a.engine.revoke_peer(9).code == StatusCode::NotFound);
}

// Candidate TTL: an unanswered candidate expires at 5s and frees its slot.
void test_candidate_ttl() {
  DiscWorld world;
  Unit& b = world.add(2, 0xB2, /*member=*/true);
  world.start_all();
  const auto bytes =
      forged_envelope(static_cast<std::uint8_t>(FrameType::Discover), 55,
                      std::array<std::uint8_t, 16>{}, ByteView{nullptr, 0});
  b.engine.on_rld1_rx(mac_of(0x51), ByteView{bytes.data(), bytes.size()},
                      world.medium.now);
  CHECK(b.engine.candidate_count() == 1);
  NeighborPhase phase{};
  CHECK(b.engine.phase_of(mac_of(0x51), phase) &&
        phase == NeighborPhase::Candidate);
  world.run(5100);
  CHECK(b.engine.candidate_count() == 0);
  CHECK(!b.engine.phase_of(mac_of(0x51), phase));
}

}  // namespace

int main() {
  test_rld1_envelope_bytes();
  test_member_member_exchange();
  test_new_node_join();
  test_rld1_kind_rejects();
  test_cookie_rejects();
  test_data_gate();
  test_capacity();
  test_density_suppression();
  test_lease_expiry();
  test_mac_change_conflict();
  test_simultaneous_open();
  test_handshake_rate_limit();
  test_revoked_silent();
  test_production_unavailable();
  test_fragment_reassembly();
  test_fragment_rejects();
  test_stale_finish();
  test_suspend_revoke();
  test_candidate_ttl();

  if (failures != 0) {
    std::fprintf(stderr, "%d discovery checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom discovery tests passed");
  return 0;
}
