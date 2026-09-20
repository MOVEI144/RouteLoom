// Discovery Scope Key tests (docs/design/scope-gateway-config/
// 02-discovery-scope.md, cases.json S01-S11): scoped DiscoverV2/OfferV2
// lanes over the real RLD1 exchange, generation windows, dedup, migration
// modes, observed-MAC binding and the auth-transcript scope_binding. S12 is
// the hardware case and stays out of the portable suite.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/discovery_scope.hpp"
#include "routeloom/endpoint_wire.hpp"
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
using routeloom::endpoint::ScopeClass;

constexpr NetworkId kNetwork = 7;
constexpr std::uint32_t kHint = 0xC0FFEE;
constexpr std::uint32_t kGen = 1;

MacAddress mac_of(const std::uint8_t tail) {
  return MacAddress{0x02, 0x00, 0x00, 0x00, 0x00, tail};
}

// Deterministic dev/test scope provider: holds the raw key internally and
// never exposes it — callers only see the opaque ScopeRef and generations.
// Different seeds model different scopes. Marked EXPERIMENTAL by the
// interface default (production adapters are a later phase).
class TestScopeProvider final : public DiscoveryScopeProvider {
 public:
  explicit TestScopeProvider(const std::uint8_t seed) { base_key_.fill(seed); }
  const ScopeRef ref{ScopeRef{42}};
  ScopeKeyRing ring{};
  bool key_available{true};
  std::uint32_t tag_calls{0};

  Status install(const std::uint32_t generation, const MonotonicMs now_ms) {
    const Status status = ring.install(generation, now_ms);
    if (status) keys_[generation] = key_for(generation);
    return status;
  }
  Status rotate(const std::uint32_t generation, const MonotonicMs now_ms) {
    const Status status = ring.rotate(generation, now_ms);
    if (!status) return status;
    keys_[generation] = key_for(generation);
    std::uint32_t current = 0;
    ring.current(current);
    for (auto it = keys_.begin(); it != keys_.end();) {
      if (it->first != current && it->first != ring.previous()) {
        it = keys_.erase(it);
      } else {
        ++it;
      }
    }
    return status;
  }

  bool current_generation(const ScopeRef scope, std::uint32_t& out) noexcept override {
    if (scope != ref || !key_available) return false;
    return ring.current(out);
  }
  bool accepted_generation(const ScopeRef scope, const std::uint32_t generation,
                           const MonotonicMs now_ms) noexcept override {
    return scope == ref && key_available && ring.accepted(generation, now_ms);
  }
  Status scope_tag(const ScopeRef scope, const std::uint32_t generation,
                   const ByteView input, ScopeTag& out) noexcept override {
    if (scope != ref || !key_available) {
      return Status::error(StatusCode::AuthProfileUnavailable, "scope key unavailable");
    }
    const auto it = keys_.find(generation);
    if (it == keys_.end()) {
      return Status::error(StatusCode::NotFound, "unknown scope generation");
    }
    ++tag_calls;
    ScopeDigest mac{};
    hmac_sha256(ByteView{it->second.data(), it->second.size()}, input, mac);
    std::memcpy(out.data(), mac.data(), out.size());
    return Status::success();
  }

 private:
  std::array<std::uint8_t, kScopeKeyBytes> base_key_{};
  std::map<std::uint32_t, std::array<std::uint8_t, kScopeKeyBytes>> keys_{};
  // Each generation owns distinct key material; tests derive deterministically.
  std::array<std::uint8_t, kScopeKeyBytes> key_for(const std::uint32_t generation) const {
    std::array<std::uint8_t, kScopeKeyBytes> key = base_key_;
    key[0] ^= static_cast<std::uint8_t>(generation >> 24U);
    key[1] ^= static_cast<std::uint8_t>(generation >> 16U);
    key[2] ^= static_cast<std::uint8_t>(generation >> 8U);
    key[3] ^= static_cast<std::uint8_t>(generation);
    return key;
  }
};

// An authenticator that predates scope_binding: structurally identical to
// the dev profile but cannot fold the binding into the tag (S11).
class LegacyAuthenticator final : public NeighborAuthenticator {
 public:
  explicit LegacyAuthenticator(SecurityProvider& provider) : impl_(provider, 1) {}
  SecurityProfile security_profile() const noexcept override {
    return impl_.security_profile();
  }
  bool binds_scope() const noexcept override { return false; }
  Status cookie_seal(const CookieMaterial& m, AuthTag& t) noexcept override {
    return impl_.cookie_seal(m, t);
  }
  Status cookie_verify(const CookieMaterial& m, const AuthTag& t) noexcept override {
    return impl_.cookie_verify(m, t);
  }
  Status attest(const autonomy::AuthPhase p, const AuthTranscript& t,
                AuthTag& o) noexcept override {
    return impl_.attest(p, t, o);
  }
  Status verify(const autonomy::AuthPhase p, const AuthTranscript& t,
                const AuthTag& g) noexcept override {
    return impl_.verify(p, t, g);
  }
  Status issue_proof(const AuthTranscript& t, const NodeId self,
                     const AuthTag& closing,
                     AuthenticatedPeerProof& out) noexcept override {
    return impl_.issue_proof(t, self, closing, out);
  }

 private:
  DevPskAuthenticator impl_;
};

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
  routeloom_test::ScriptedEntropy impl_;
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

struct ScopeMedium;
struct ScopeUnit;

class ScopePort final : public DiscoveryPort {
 public:
  struct Sent {
    MacAddress dest{};
    bool wire{false};
    FrameType kind{FrameType::Discover};
    MonotonicMs at{0};
    std::vector<std::uint8_t> bytes;
  };
  ScopePort(ScopeMedium& medium, const MacAddress self) : medium_(&medium), self_(self) {}
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
  std::vector<Sent> sent;

 private:
  ScopeMedium* medium_;
  MacAddress self_;
};

struct ScopeMedium {
  MonotonicMs now{0};
  bool drop_rld1{false};
  bool drop_wire{false};
  std::vector<ScopeUnit*> units;
  void deliver_rld1(const MacAddress& src, const MacAddress& dest,
                    const ByteView bytes);
  void deliver_wire(const MacAddress& src, const MacAddress& dest,
                    const FrameType type, const ByteView payload);
};

struct ScopeUnit {
  ScopeUnit(ScopeMedium& medium, const NodeId id, const std::uint8_t mac_tail,
            const bool member, const ScopeMode mode, const std::uint8_t scope_seed,
            const ScopeClass scope_class = ScopeClass::Member,
            const MonotonicMs migration_until_ms = 0,
            const NetworkId network = kNetwork, const std::uint32_t hint = kHint)
      : mac(mac_of(mac_tail)),
        node(id),
        scope_provider(scope_seed),
        auth(security, 1),
        entropy(3000 + id),
        port(medium, mac),
        engine(make_config(id, mac, network, hint, mode,
                           scope_seed != 0 ? &scope_provider : nullptr,
                           scope_provider.ref, scope_class, migration_until_ms),
               port, auth, hooks, entropy, observer) {
    hooks.is_member = member;
    if (scope_seed != 0) {
      const Status status = scope_provider.install(kGen, 0);
      if (!status) {
        std::fprintf(stderr, "scope install failed: %s\n", status.detail);
        ++failures;
      }
    }
    medium.units.push_back(this);
  }

  static DiscoveryConfig make_config(const NodeId id, const MacAddress& mac,
                                     const NetworkId network,
                                     const std::uint32_t hint,
                                     const ScopeMode mode,
                                     DiscoveryScopeProvider* provider,
                                     const ScopeRef scope,
                                     const ScopeClass scope_class,
                                     const MonotonicMs migration_until_ms) {
    DiscoveryConfig config{};
    config.node = id;
    config.mac = mac;
    config.network = network;
    config.network_hint = hint;
    config.capability_bits = 1;
    config.probe_timeout_ms = 200;
    config.scope_mode = mode;
    config.scope_provider = provider;
    config.scope = scope;
    config.scope_class = scope_class;
    config.migration_until_ms = migration_until_ms;
    return config;
  }

  MacAddress mac;
  NodeId node;
  routeloom_test::TestSecurity security;
  TestScopeProvider scope_provider;
  DevPskAuthenticator auth;
  TestHooks hooks;
  TestEntropy entropy;
  TestObserver observer;
  ScopePort port;
  NeighborDiscovery engine;
};

Status ScopePort::send_rld1(const MacAddress& dest, const ByteView encoded) noexcept {
  const FrameType kind = encoded.size > 5
                             ? static_cast<FrameType>(encoded.data[5])
                             : FrameType::Diagnostic;
  sent.push_back(Sent{dest, false, kind, medium_->now,
                      std::vector<std::uint8_t>(encoded.data,
                                                encoded.data + encoded.size)});
  medium_->deliver_rld1(self_, dest, encoded);
  return Status::success();
}

Status ScopePort::send_wire(BindingId, const MacAddress& dest,
                            const FrameType type, const ByteView payload) noexcept {
  sent.push_back(Sent{dest, true, type, medium_->now,
                      std::vector<std::uint8_t>(payload.data,
                                                payload.data + payload.size)});
  medium_->deliver_wire(self_, dest, type, payload);
  return Status::success();
}

void ScopeMedium::deliver_rld1(const MacAddress& src, const MacAddress& dest,
                               const ByteView bytes) {
  if (drop_rld1) return;
  for (auto* u : units) {
    if (u->mac == src) continue;
    if (dest == discovery_const::kBroadcastMac || u->mac == dest) {
      u->engine.on_rld1_rx(DiscoveryRxMetadata{src, dest}, bytes, now);
    }
  }
}

void ScopeMedium::deliver_wire(const MacAddress& src, const MacAddress& dest,
                               const FrameType type, const ByteView payload) {
  if (drop_wire) return;
  for (auto* u : units) {
    if (u->mac == dest) {
      u->engine.on_wire_rx(src, type, payload, now);
    }
  }
}

struct ScopeWorld {
  ScopeMedium medium;
  std::vector<std::unique_ptr<ScopeUnit>> units;

  ScopeUnit& add(const NodeId id, const std::uint8_t mac_tail, const bool member,
                 const ScopeMode mode, const std::uint8_t scope_seed,
                 const ScopeClass scope_class = ScopeClass::Member,
                 const MonotonicMs migration_until_ms = 0,
                 const NetworkId network = kNetwork) {
    units.push_back(std::make_unique<ScopeUnit>(medium, id, mac_tail, member, mode,
                                              scope_seed, scope_class,
                                              migration_until_ms, network));
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

// --- Frame builders (rogue/attacker traffic uses the same pinned codecs) ------

std::vector<std::uint8_t> scoped_discover_frame(
    TestScopeProvider& provider, const std::uint32_t generation,
    const ScopeClass scope_class, const NetworkId network, const NodeId node,
    const MacAddress& source, const std::array<std::uint8_t, 16>& nonce,
    const std::uint32_t caps = 1) {
  std::uint32_t hint = 0;
  if (!scope_hint(provider, provider.ref, generation, scope_class, network,
                  hint)) {
    return {};
  }
  endpoint::Rld1DiscoverBodyV2 body{};
  body.scope_class = scope_class;
  body.generation = generation;
  endpoint::EncodedScopeBody encoded_body{};
  if (!endpoint::scope_discover_body_encode(body, encoded_body)) return {};
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::Discover;
  env.network_hint = hint;
  env.claimed_node = node;
  env.transaction_nonce = nonce;
  env.capability_bits = caps;
  std::memcpy(env.body.data(), encoded_body.bytes.data(), encoded_body.size);
  env.body_size = encoded_body.size;
  autonomy::Rld1Encoded pass{};
  if (!autonomy::rld1_encode(env, pass)) return {};
  ByteBuffer<endpoint::kScopeDiscoverMacInputSize> input{};
  if (!endpoint::scope_discover_mac_input(
          network, source, discovery_const::kBroadcastMac,
          ByteView{pass.bytes.data(), autonomy::kRld1HeaderSize},
          ByteView{pass.bytes.data() + autonomy::kRld1HeaderSize, 8}, input)) {
    return {};
  }
  ScopeTag tag{};
  if (!provider.scope_tag(provider.ref, generation, input.view(), tag)) {
    return {};
  }
  std::memcpy(env.body.data() + 8, tag.data(), tag.size());
  autonomy::Rld1Encoded encoded{};
  if (!autonomy::rld1_encode(env, encoded)) return {};
  return std::vector<std::uint8_t>(encoded.bytes.begin(),
                                 encoded.bytes.begin() + encoded.size);
}

std::vector<std::uint8_t> legacy_discover_frame(
    const NodeId node, const std::uint32_t hint,
    const std::array<std::uint8_t, 16>& nonce) {
  autonomy::Rld1Envelope env{};
  env.kind = FrameType::Discover;
  env.network_hint = hint;
  env.claimed_node = node;
  env.transaction_nonce = nonce;
  env.capability_bits = 1;
  env.body_size = 0;
  autonomy::Rld1Encoded encoded{};
  if (!autonomy::rld1_encode(env, encoded)) return {};
  return std::vector<std::uint8_t>(encoded.bytes.begin(),
                                 encoded.bytes.begin() + encoded.size);
}

void run_exchange(ScopeWorld& world, ScopeUnit& a) {
  CHECK_OK(a.engine.begin_discovery(world.medium.now));
  world.run(3000);
}

// --- S01: wrong-scope responder storm consumes zero in-scope resources ---------
void test_s01_wrong_scope_flood() {
  ScopeWorld world;
  ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
  world.start_all();
  TestScopeProvider rogue(0x99);
  CHECK_OK(rogue.install(kGen, 0));

  // 100 well-formed DiscoverV2 frames signed under a foreign scope key.
  for (std::uint8_t i = 0; i < 100; ++i) {
    std::array<std::uint8_t, 16> nonce{};
    nonce[15] = i;
    const auto frame = scoped_discover_frame(rogue, kGen, ScopeClass::Member,
                                             kNetwork, 100 + i,
                                             mac_of(static_cast<std::uint8_t>(i + 1)),
                                             nonce);
    CHECK(!frame.empty());
    b.engine.on_rld1_rx({mac_of(static_cast<std::uint8_t>(i + 1)),
                         discovery_const::kBroadcastMac},
                        ByteView{frame.data(), frame.size()}, world.medium.now);
  }
  world.run(500);

  const ScopeStats& ss = b.engine.scope_stats();
  CHECK(ss.raw_rx == 100);
  CHECK(ss.budget_dropped == 84);          // raw burst 16, rate-limited rest
  CHECK(ss.hint_mismatch == 16);           // foreign key -> foreign hint space
  CHECK(ss.scope_accepted == 0);
  CHECK(ss.mac_rejected == 0);             // all died at the cheap hint step
  CHECK(b.engine.candidate_count() == 0);
  CHECK(b.port.count_kind(FrameType::Offer) == 0);
  CHECK(b.engine.stats().auths_completed == 0);
  CHECK(b.engine.neighbor_count() == 0);

  // Same-scope hint but corrupted tag: passes the hint filter, dies at MAC.
  for (std::uint8_t i = 0; i < 4; ++i) {
    std::array<std::uint8_t, 16> nonce{};
    nonce[15] = static_cast<std::uint8_t>(0x80 + i);
    auto frame = scoped_discover_frame(b.scope_provider, kGen, ScopeClass::Member,
                                       kNetwork, 200 + i,
                                       mac_of(static_cast<std::uint8_t>(0x90 + i)),
                                       nonce);
    CHECK(!frame.empty());
    frame[60] ^= 0xFF;  // corrupt one tag byte (tag occupies bytes 52..67)
    b.engine.on_rld1_rx({mac_of(static_cast<std::uint8_t>(0x90 + i)),
                         discovery_const::kBroadcastMac},
                        ByteView{frame.data(), frame.size()}, world.medium.now);
    b.engine.poll(world.medium.now);  // drain <=2 MACs per poll
  }
  world.run(200);
  CHECK(b.engine.scope_stats().mac_rejected == 4);
  CHECK(b.engine.candidate_count() == 0);
  CHECK(b.port.count_kind(FrameType::Offer) == 0);
}

// --- S02: Required silently drops missing/wrong/unknown-generation tags --------
void test_s02_required_drops() {
  ScopeWorld world;
  ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
  world.start_all();
  const MacAddress peer = mac_of(0x44);

  // Missing tag: legacy empty-body DISCOVER is a tag-less frame in Required.
  const auto legacy = legacy_discover_frame(9, kHint, {});
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{legacy.data(), legacy.size()}, world.medium.now);
  CHECK(b.engine.scope_stats().mac_rejected == 1);

  // Unknown generation: gen=99 frame — generation gate precedes hint/MAC.
  auto wrong_gen = scoped_discover_frame(b.scope_provider, kGen,
                                         ScopeClass::Member, kNetwork, 9, peer, {});
  CHECK(!wrong_gen.empty());
  wrong_gen[48] = 0; wrong_gen[49] = 0; wrong_gen[50] = 0; wrong_gen[51] = 99;
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{wrong_gen.data(), wrong_gen.size()},
                      world.medium.now);
  CHECK(b.engine.scope_stats().unknown_generation == 1);

  // Wrong tag: valid hint, corrupted MAC — dropped in the verify drain.
  auto bad_tag = scoped_discover_frame(b.scope_provider, kGen, ScopeClass::Member,
                                       kNetwork, 9, peer, {});
  CHECK(!bad_tag.empty());
  bad_tag[55] ^= 0x01;
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{bad_tag.data(), bad_tag.size()}, world.medium.now);
  b.engine.poll(world.medium.now);

  CHECK(b.engine.scope_stats().mac_rejected == 2);
  CHECK(b.engine.candidate_count() == 0);
  CHECK(b.port.count_kind(FrameType::Offer) == 0);
  CHECK(b.engine.stats().auths_completed == 0);
  // Silent drops only — no per-source error frame is ever emitted (02 §2.7).
  CHECK(b.port.sent.empty());
}

// --- S03: a scope match is a filter, never membership or a proof --------------
void test_s03_scope_match_not_membership() {
  ScopeWorld world;
  ScopeUnit& b = world.add(2, 0xB2, /*member=*/false, ScopeMode::Required, 0x11);
  world.start_all();
  const MacAddress peer = mac_of(0x44);
  const auto frame = scoped_discover_frame(b.scope_provider, kGen,
                                           ScopeClass::Member, kNetwork, 9,
                                           peer, {});
  CHECK(!frame.empty());
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{frame.data(), frame.size()}, world.medium.now);
  b.engine.poll(world.medium.now);
  world.run(500);

  CHECK(b.engine.scope_stats().scope_accepted == 1);
  CHECK(b.engine.candidate_count() == 1);
  CHECK(b.port.count_kind(FrameType::Offer) == 1);
  // The filter admitted the exchange, but no proof/membership was minted —
  // with no PROVE in flight the controller relaxes back to Discovering; only
  // the unchanged auth/membership pipeline can produce Member (02 §2.3).
  CHECK(b.engine.stats().auths_completed == 0);
  CHECK(b.engine.neighbor_count() == 0);
  CHECK(b.engine.membership().state() != MembershipState::Member);
  CHECK(b.engine.membership().state() == MembershipState::Discovering);
}

// --- S04: dedup duplicate / conflict / bounded capacity ------------------------
void test_s04_dedup() {
  ScopeWorld world;
  ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
  world.start_all();
  const MacAddress peer = mac_of(0x44);
  std::array<std::uint8_t, 16> nonce{};
  nonce[15] = 7;

  const auto frame = scoped_discover_frame(b.scope_provider, kGen,
                                           ScopeClass::Member, kNetwork, 9,
                                           peer, nonce);
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{frame.data(), frame.size()}, world.medium.now);
  b.engine.poll(world.medium.now);
  CHECK(b.engine.scope_stats().scope_accepted == 1);

  // Re-reception of the identical bytes: counted once, no second offer.
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{frame.data(), frame.size()}, world.medium.now);
  b.engine.poll(world.medium.now);
  CHECK(b.engine.scope_stats().duplicate == 1);
  CHECK(b.engine.candidate_count() == 1);
  world.run(500);
  CHECK(b.port.count_kind(FrameType::Offer) == 1);

  // Same dedup key (mac, nonce, class, gen) but different content: conflict.
  const auto conflict = scoped_discover_frame(b.scope_provider, kGen,
                                              ScopeClass::Member, kNetwork, 55,
                                              peer, nonce);
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{conflict.data(), conflict.size()},
                      world.medium.now);
  b.engine.poll(world.medium.now);
  CHECK(b.engine.scope_stats().dedup_conflict == 1);
  CHECK(b.engine.candidate_count() == 1);

  // Capacity: 33 distinct keys overflow the 32-record table.
  for (std::uint8_t i = 0; i < 33; ++i) {
    std::array<std::uint8_t, 16> n{};
    n[14] = 0xA0;
    n[15] = i;
    const auto f = scoped_discover_frame(b.scope_provider, kGen,
                                         ScopeClass::Member, kNetwork, 100 + i,
                                         mac_of(static_cast<std::uint8_t>(0x60 + i)),
                                         n);
    world.medium.now += 40;  // keep the 32/s raw budget replenished
    b.engine.on_rld1_rx({mac_of(static_cast<std::uint8_t>(0x60 + i)),
                         discovery_const::kBroadcastMac},
                        ByteView{f.data(), f.size()}, world.medium.now);
    b.engine.poll(world.medium.now);
  }
  CHECK(b.engine.scope_stats().dedup_full >= 1);
}

// --- S05: current/previous overlap boundaries, never extended -------------------
void test_s05_generation_window() {
  // Ring contract: previous accepted exactly 1800s from demotion.
  ScopeKeyRing ring{};
  CHECK_OK(ring.install(1, 0));
  CHECK_OK(ring.rotate(2, 1000));
  std::uint32_t gen = 0;
  CHECK(ring.current(gen) && gen == 2);
  CHECK(ring.accepted(1, 1000 + 1799999));
  CHECK(!ring.accepted(1, 1000 + 1800000));  // boundary is exclusive
  CHECK_OK(ring.rotate(3, 2000));            // gen1 must now be gone entirely
  CHECK(ring.current(gen) && gen == 3);
  CHECK(ring.previous() == 2);
  CHECK(!ring.accepted(1, 2000));
  CHECK(ring.accepted(2, 2000));
  CHECK(ring.rotate(3, 3000).code == StatusCode::InvalidArgument);   // no reuse
  CHECK(ring.rotate(0, 3000).code == StatusCode::InvalidArgument);   // no zero
  CHECK(ring.install(4, 3000).code == StatusCode::InvalidState);     // one scope
  ring.drop_previous();  // restart with unprovable elapsed time
  CHECK(!ring.accepted(2, 2000));

  // Engine level: a gen1 frame inside the window verifies; past it, the same
  // signed frame is an unknown_generation drop — the window never extends.
  ScopeWorld world;
  ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
  world.start_all();
  CHECK_OK(b.scope_provider.rotate(2, world.medium.now));
  const MacAddress peer = mac_of(0x44);

  world.medium.now += 1700000;  // inside the 1800s overlap
  std::array<std::uint8_t, 16> n1{};
  n1[15] = 1;
  const auto f1 = scoped_discover_frame(b.scope_provider, 1, ScopeClass::Member,
                                        kNetwork, 9, peer, n1);
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{f1.data(), f1.size()}, world.medium.now);
  b.engine.poll(world.medium.now);
  CHECK(b.engine.scope_stats().scope_accepted == 1);

  world.medium.now += 200000;  // now 1900s past demotion -> outside overlap
  std::array<std::uint8_t, 16> n2{};
  n2[15] = 2;
  const auto f2 = scoped_discover_frame(b.scope_provider, 1, ScopeClass::Member,
                                        kNetwork, 9, peer, n2);
  b.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                      ByteView{f2.data(), f2.size()}, world.medium.now);
  CHECK(b.engine.scope_stats().unknown_generation == 1);
  CHECK(b.engine.candidate_count() == 1);  // only the first was admitted
}

// --- S06: Required key loss stops discovery — never falls back ------------------
void test_s06_required_key_loss() {
  ScopeWorld world;
  ScopeUnit& a = world.add(1, 0xA1, /*member=*/true, ScopeMode::Required, 0x11);
  ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
  world.start_all();

  a.scope_provider.key_available = false;
  CHECK(a.engine.begin_discovery(world.medium.now).code ==
        StatusCode::AuthProfileUnavailable);
  CHECK(a.engine.scope_stats().key_unavailable >= 1);
  CHECK(a.port.sent.empty());                    // nothing advertised
  CHECK(a.engine.scope_stats().legacy_used == 0);  // no OpenLegacy downgrade

  // Responder side: inbound frames die too — including legacy (no fallback).
  b.scope_provider.key_available = false;
  const auto scoped = scoped_discover_frame(b.scope_provider, kGen,
                                            ScopeClass::Member, kNetwork, 9,
                                            mac_of(0x44), {});
  b.engine.on_rld1_rx({mac_of(0x44), discovery_const::kBroadcastMac},
                      ByteView{scoped.data(), scoped.size()}, world.medium.now);
  const auto legacy = legacy_discover_frame(9, kHint, {});
  b.engine.on_rld1_rx({mac_of(0x44), discovery_const::kBroadcastMac},
                      ByteView{legacy.data(), legacy.size()}, world.medium.now);
  b.engine.poll(world.medium.now);
  CHECK(b.engine.candidate_count() == 0);
  CHECK(b.port.count_kind(FrameType::Offer) == 0);
  CHECK(b.engine.scope_stats().legacy_used == 0);
}

// --- S07: raw flood cannot starve the DATA/ACK lane ------------------------------
void test_s07_flood_preserves_data_lane() {
  ScopeWorld world;
  ScopeUnit& a = world.add(1, 0xA1, /*member=*/true, ScopeMode::Required, 0x11);
  ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
  a.hooks.peer_members.insert(2);
  b.hooks.peer_members.insert(1);
  world.start_all();
  run_exchange(world, a);
  CHECK(a.engine.data_permitted(b.mac));
  CHECK(b.engine.data_permitted(a.mac));

  TestScopeProvider rogue(0x77);
  CHECK_OK(rogue.install(kGen, 0));
  // Valid-hint frames first: 10 consume budget, 8 fit the verify queue, the
  // last 2 overflow it (bounded pending work).
  for (std::uint8_t i = 0; i < 10; ++i) {
    std::array<std::uint8_t, 16> nonce{};
    nonce[15] = i;
    auto frame = scoped_discover_frame(b.scope_provider, kGen,
                                       ScopeClass::Member, kNetwork, 200 + i,
                                       mac_of(static_cast<std::uint8_t>(i + 1)),
                                       nonce);
    frame[60] ^= 0xFF;  // corrupt tag: queued, then dropped at verify
    b.engine.on_rld1_rx({mac_of(static_cast<std::uint8_t>(i + 1)),
                         discovery_const::kBroadcastMac},
                        ByteView{frame.data(), frame.size()}, world.medium.now);
  }
  // Then 100 wrong-scope frames in the same instant: the burst budget admits
  // 6 more (16 - 10 already spent) and rate-drops the rest.
  for (std::uint8_t i = 0; i < 100; ++i) {
    std::array<std::uint8_t, 16> nonce{};
    nonce[15] = static_cast<std::uint8_t>(0x40 + i);
    const auto frame = scoped_discover_frame(rogue, kGen, ScopeClass::Member,
                                             kNetwork, 200 + i,
                                             mac_of(static_cast<std::uint8_t>(i + 1)),
                                             nonce);
    b.engine.on_rld1_rx({mac_of(static_cast<std::uint8_t>(i + 1)),
                         discovery_const::kBroadcastMac},
                        ByteView{frame.data(), frame.size()}, world.medium.now);
  }
  // The wire lane is untouched by the flood: a probe still round-trips.
  a.engine.poll(world.medium.now);
  const std::size_t results_before = b.port.sent.size();
  autonomy::NeighborProbePayload probe{};
  BindingId binding{};
  CHECK(a.engine.binding_of(2, binding));
  probe.binding_generation = BindingGeneration{1};
  probe.probe_sequence = 9001;
  probe.sent_ms = world.medium.now;
  autonomy::EncodedPayload payload{};
  CHECK_OK(autonomy::neighbor_probe_encode(probe, payload));
  b.engine.on_wire_rx(a.mac, FrameType::NeighborProbe, payload.view(),
                      world.medium.now);
  CHECK(b.port.sent.size() > results_before);
  CHECK(b.engine.data_permitted(a.mac));

  b.engine.poll(world.medium.now);  // drains at most 2 queued MACs
  CHECK(b.engine.scope_stats().raw_rx >= 110);
  CHECK(b.engine.scope_stats().budget_dropped >= 94);
  CHECK(b.engine.candidate_count() == 0);
  CHECK(b.engine.stats().auths_completed == 1);  // only the real exchange
}

// --- S08: mode compatibility matrix ----------------------------------------------
void test_s08_mode_matrix() {
  // Required <-> Required: scoped v2 exchange completes end to end.
  {
    ScopeWorld world;
    ScopeUnit& a = world.add(1, 0xA1, /*member=*/true, ScopeMode::Required, 0x11);
    ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
    a.hooks.peer_members.insert(2);
    b.hooks.peer_members.insert(1);
    world.start_all();
    run_exchange(world, a);
    NeighborPhase phase{};
    CHECK(a.engine.phase_of(b.mac, phase) && phase == NeighborPhase::Reachable);
    CHECK(b.engine.phase_of(a.mac, phase) && phase == NeighborPhase::Reachable);
    CHECK(a.engine.stats().auths_completed == 1);
    CHECK(b.engine.stats().auths_completed == 1);
    CHECK(a.engine.scope_stats().scope_accepted >= 1);   // verified offer
    CHECK(b.engine.scope_stats().scope_accepted >= 1);   // verified discover
    CHECK(b.engine.scope_stats().legacy_used == 0);
  }

  // OpenLegacy requester vs Required responder: silent drop, no exchange.
  {
    ScopeWorld world;
    ScopeUnit& a = world.add(1, 0xA1, /*member=*/true, ScopeMode::OpenLegacy, 0);
    ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
    world.start_all();
    CHECK_OK(a.engine.begin_discovery(world.medium.now));
    world.run(1500);
    CHECK(b.engine.candidate_count() == 0);
    CHECK(b.port.count_kind(FrameType::Offer) == 0);
    CHECK(b.engine.scope_stats().mac_rejected >= 1);
    CHECK(b.engine.scope_stats().legacy_used == 0);
    CHECK(a.engine.stats().auths_completed == 0);
  }

  // OpenLegacy requester vs OptionalMigration responder inside the window:
  // the bounded legacy lane completes the exchange on both ends.
  {
    ScopeWorld world;
    ScopeUnit& a = world.add(1, 0xA1, /*member=*/true, ScopeMode::OpenLegacy, 0);
    ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::OptionalMigration,
                             0x11, ScopeClass::Member,
                             /*migration_until_ms=*/3600000);
    a.hooks.peer_members.insert(2);
    b.hooks.peer_members.insert(1);
    world.start_all();
    run_exchange(world, a);
    CHECK(a.engine.stats().auths_completed == 1);
    CHECK(b.engine.stats().auths_completed == 1);
    CHECK(b.engine.scope_stats().legacy_used >= 1);
    NeighborPhase phase{};
    CHECK(b.engine.phase_of(a.mac, phase) && phase == NeighborPhase::Reachable);
  }

  // OptionalMigration requester vs Required responder: scoped lane works.
  {
    ScopeWorld world;
    ScopeUnit& a = world.add(1, 0xA1, /*member=*/true, ScopeMode::OptionalMigration,
                             0x11, ScopeClass::Member, 3600000);
    ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
    a.hooks.peer_members.insert(2);
    b.hooks.peer_members.insert(1);
    world.start_all();
    run_exchange(world, a);
    CHECK(a.engine.stats().auths_completed == 1);
    CHECK(b.engine.stats().auths_completed == 1);
    CHECK(a.engine.scope_stats().legacy_used == 0);  // scoped won first try
  }

  // OptionalMigration with no proven window is Required-like for legacy.
  {
    ScopeWorld world;
    ScopeUnit& a = world.add(1, 0xA1, /*member=*/true, ScopeMode::OpenLegacy, 0);
    ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::OptionalMigration,
                             0x11, ScopeClass::Member, /*until=*/0);
    world.start_all();
    CHECK_OK(a.engine.begin_discovery(world.medium.now));
    world.run(1500);
    CHECK(b.engine.candidate_count() == 0);
    CHECK(b.engine.scope_stats().legacy_used == 0);
    CHECK(b.engine.scope_stats().mac_rejected >= 1);
  }
}

// --- S09: observed-MAC/network/capability binding ---------------------------------
void test_s09_observed_mac_binding() {
  ScopeWorld world;
  ScopeUnit& b = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11);
  world.start_all();
  const MacAddress honest = mac_of(0x44);
  const auto good = scoped_discover_frame(b.scope_provider, kGen,
                                          ScopeClass::Member, kNetwork, 9,
                                          honest, {});
  CHECK(!good.empty());

  // Spoofed observed source: the tag binds the RX-metadata MAC, so the same
  // bytes from another address fail verification.
  b.engine.on_rld1_rx({mac_of(0xEE), discovery_const::kBroadcastMac},
                      ByteView{good.data(), good.size()}, world.medium.now);
  b.engine.poll(world.medium.now);
  CHECK(b.engine.scope_stats().mac_rejected == 1);
  CHECK(b.engine.candidate_count() == 0);

  // Unicast destination: DISCOVER is broadcast-only in scoped modes.
  b.engine.on_rld1_rx({honest, b.mac},
                      ByteView{good.data(), good.size()}, world.medium.now);
  CHECK(b.engine.scope_stats().mac_rejected == 2);

  // Different Network: the hint domain binds the full-width NetworkId.
  const auto foreign_net = scoped_discover_frame(b.scope_provider, kGen,
                                                 ScopeClass::Member, 88, 9,
                                                 honest, {});
  b.engine.on_rld1_rx({honest, discovery_const::kBroadcastMac},
                      ByteView{foreign_net.data(), foreign_net.size()},
                      world.medium.now);
  CHECK(b.engine.scope_stats().hint_mismatch >= 1);

  // Capability-bit alteration: inside the tagged header — the MAC catches it.
  auto tampered = scoped_discover_frame(b.scope_provider, kGen,
                                        ScopeClass::Member, kNetwork, 9,
                                        honest, {});
  tampered[40] ^= 0x01;  // capability bits live at header offset 40
  b.engine.on_rld1_rx({honest, discovery_const::kBroadcastMac},
                      ByteView{tampered.data(), tampered.size()},
                      world.medium.now);
  b.engine.poll(world.medium.now);
  CHECK(b.engine.scope_stats().mac_rejected == 3);
  CHECK(b.engine.candidate_count() == 0);
}

// --- S10: Member vs Commissioning separation; Network 0 ---------------------------
void test_s10_class_separation() {
  // Broad Commissioning discovery is never valid on Network 0.
  {
    ScopeWorld world;
    ScopeUnit& c = world.add(3, 0xC3, /*member=*/true, ScopeMode::Required, 0x11,
                             ScopeClass::Commissioning, 0, /*network=*/0);
    CHECK(c.engine.start(world.medium.now).code == StatusCode::NetworkRequired);
  }

  // Member-class frames never wake a Commissioning responder (and back).
  {
    ScopeWorld world;
    ScopeUnit& m = world.add(1, 0xA1, /*member=*/true, ScopeMode::Required, 0x11,
                             ScopeClass::Member);
    ScopeUnit& c = world.add(2, 0xB2, /*member=*/true, ScopeMode::Required, 0x11,
                             ScopeClass::Commissioning);
    world.start_all();
    const MacAddress peer = mac_of(0x44);
    const auto member_frame = scoped_discover_frame(
        m.scope_provider, kGen, ScopeClass::Member, kNetwork, 9, peer, {});
    c.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                        ByteView{member_frame.data(), member_frame.size()},
                        world.medium.now);
    c.engine.poll(world.medium.now);
    CHECK(c.engine.scope_stats().hint_mismatch == 1);
    CHECK(c.engine.scope_stats().scope_accepted == 0);
    CHECK(c.engine.candidate_count() == 0);

    const auto comm_frame = scoped_discover_frame(
        c.scope_provider, kGen, ScopeClass::Commissioning, kNetwork, 9, peer, {});
    m.engine.on_rld1_rx({peer, discovery_const::kBroadcastMac},
                        ByteView{comm_frame.data(), comm_frame.size()},
                        world.medium.now);
    m.engine.poll(world.medium.now);
    CHECK(m.engine.scope_stats().hint_mismatch == 1);
    CHECK(m.engine.candidate_count() == 0);
  }
}

// --- S11: an auth provider that cannot bind scope makes Required unusable ---------
void test_s11_old_provider_unusable() {
  ScopeWorld world;
  // Build a Required engine over an authenticator that predates the binding.
  routeloom_test::TestSecurity security;
  LegacyAuthenticator auth(security);
  TestHooks hooks;
  TestEntropy entropy(7);
  TestObserver observer;
  TestScopeProvider provider(0x11);
  CHECK_OK(provider.install(kGen, 0));
  hooks.is_member = true;
  ScopePort port(world.medium, mac_of(0xB2));
  DiscoveryConfig config = ScopeUnit::make_config(
      2, mac_of(0xB2), kNetwork, kHint, ScopeMode::Required, &provider,
      provider.ref, ScopeClass::Member, 0);
  NeighborDiscovery engine(config, port, auth, hooks, entropy, observer);
  CHECK(engine.start(world.medium.now).code ==
        StatusCode::AuthProfileUnavailable);
}

}  // namespace

int main() {
  test_s01_wrong_scope_flood();
  test_s02_required_drops();
  test_s03_scope_match_not_membership();
  test_s04_dedup();
  test_s05_generation_window();
  test_s06_required_key_loss();
  test_s07_flood_preserves_data_lane();
  test_s08_mode_matrix();
  test_s09_observed_mac_binding();
  test_s10_class_separation();
  test_s11_old_provider_unusable();

  if (failures != 0) {
    std::fprintf(stderr, "%d scope checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom scope tests passed");
  return 0;
}
