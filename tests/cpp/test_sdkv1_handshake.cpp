// Member handshake engine (G-SEC P4 §5-§7, PR2): two real engines over a
// synchronous harness — full link EDHOC with method-0 signatures and
// issued MemberCerts, resume round-trips, the cookie/binding/caps gates,
// re-entry (P4-C01), cancel/timeout, simultaneous open, the min-GK rule,
// revocation at commit, and discovery elevation with the minted proof.
// Key agreement is proven by seal/open round-trips in both directions;
// message sizes are asserted from the real encoders (§13.1).

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/discovery.hpp"
#include "routeloom/discovery_scope.hpp"  // sha256
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_handshake.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/session_bank.hpp"

#include "test_autonomy.hpp"
#include "test_sdkv1.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                        \
  do {                                                                     \
    if (!(expr)) {                                                         \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, \
                   #expr);                                                 \
      ++failures;                                                          \
    }                                                                      \
  } while (false)
#define CHECK_OK(expr)                                                     \
  do {                                                                     \
    const auto _status = (expr);                                           \
    if (!_status.ok()) {                                                   \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,      \
                   __LINE__, #expr, _status.detail);                       \
      ++failures;                                                          \
    }                                                                      \
  } while (false)

using namespace routeloom;
using namespace routeloom::sdkv1;
using sdkv1_test::FaultyResumeStorage2;

constexpr NodeId kNodeA = sdkv1_test::kNode;  // 0x00A1...1234 (device 0x54)
constexpr NodeId kNodeB = sdkv1_test::kPeer;  // 0x00A1...0777 (peer 0x56)
constexpr NetworkId kNet = sdkv1_test::kNetwork;
constexpr std::uint32_t kSiteEpoch = sdkv1_test::kSiteEpoch;
constexpr std::uint32_t kGk = 12;
constexpr std::uint32_t kRs = 14;
constexpr MonotonicMs kT0 = 1000;

MacAddress mac_of(const std::uint8_t tail) {
  return MacAddress{0x02, 0x00, 0x00, 0x00, 0x00, tail};
}

// --- Deterministic doubles ------------------------------------------------------

struct XorShift {
  std::uint64_t state{0x12345678};
  static bool fill(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
    auto& self = *static_cast<XorShift*>(ctx);
    if (out == nullptr) return false;
    for (std::size_t i = 0; i < size; ++i) {
      self.state ^= self.state << 13;
      self.state ^= self.state >> 7;
      self.state ^= self.state << 17;
      out[i] = static_cast<std::uint8_t>(self.state >> 56U);
    }
    return true;
  }
};

// Key-mixing test AEAD (NOT a cipher): the tag binds key, nonce, AAD and
// bytes, so a key disagreement fails the open — which is all the
// agreement check needs. Real-AEAD correctness is the bank's own test.
struct TestAead {
  static std::uint64_t mix(const std::uint64_t state, const std::uint64_t value) noexcept {
    return (state ^ (value + 0x9e3779b97f4a7c15ULL + (state << 6U) + (state >> 2U))) *
           0xbf58476d1ce4e5b9ULL;
  }
  static bool call(const std::uint8_t key[16], const std::uint8_t nonce[12], const ByteView aad,
                   const ByteView input, std::uint8_t* out, std::uint8_t tag[16],
                   const bool sealing) noexcept {
    std::uint64_t state = 0x7465737461656164ULL;
    for (int i = 0; i < 16; ++i) state = mix(state, key[i]);
    for (int i = 0; i < 12; ++i) state = mix(state, nonce[i]);
    for (std::size_t i = 0; i < aad.size; ++i) state = mix(state, aad.data[i]);
    const std::uint64_t keystream = state;
    for (std::size_t i = 0; i < input.size; ++i) {
      out[i] = input.data[i] ^ static_cast<std::uint8_t>(mix(keystream, i + 1) >> 56U);
    }
    std::uint64_t left = keystream, right = mix(keystream, 0x746167ULL);
    const ByteView tagged = sealing ? ByteView{out, input.size} : input;
    for (std::size_t i = 0; i < aad.size; ++i) left = mix(left, aad.data[i]);
    for (std::size_t i = 0; i < tagged.size; ++i) right = mix(right, tagged.data[i]);
    std::uint8_t expect[16];
    for (int i = 0; i < 8; ++i) {
      expect[i] = static_cast<std::uint8_t>(left >> (56 - i * 8));
      expect[8 + i] = static_cast<std::uint8_t>(right >> (56 - i * 8));
    }
    if (sealing) {
      std::memcpy(tag, expect, 16);
      return true;
    }
    std::uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= static_cast<std::uint8_t>(expect[i] ^ tag[i]);
    return diff == 0;
  }
  static bool seal(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView plaintext, std::uint8_t* out,
                   std::uint8_t tag[16]) noexcept {
    (void)ctx;
    return call(key, nonce, aad, plaintext, out, tag, true);
  }
  static bool open(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView ciphertext, const std::uint8_t tag[16],
                   std::uint8_t* out) noexcept {
    (void)ctx;
    std::uint8_t copy[16];
    std::memcpy(copy, tag, 16);
    return call(key, nonce, aad, ciphertext, out, copy, false);
  }
};

struct TestMembership final : public HandshakeMembershipView {
  bool local(HandshakeLocal& out) const noexcept override {
    if (!local_ok) return false;
    ++local_calls;
    if (change_on_local_call == local_calls) ++view.gk_epoch;
    if (reenter_engine != nullptr && reenter_request) {
      // P4-C01 probe: a mutating call from inside the callback.
      HandshakeRequest req{};
      req.scope = SecurityScope::Link;
      req.peer = view.self == kNodeA ? kNodeB : kNodeA;
      reenter_seen_busy =
          reenter_engine->request(req, 9999).code == StatusCode::Busy;
    }
    out = view;
    return true;
  }
  bool revoked(const NodeId peer, const std::uint32_t generation) const noexcept override {
    (void)generation;
    return revoked_peers.count(peer) != 0;
  }

  mutable HandshakeLocal view{};
  bool local_ok{true};
  mutable std::size_t local_calls{0};
  std::size_t change_on_local_call{0};
  std::set<NodeId> revoked_peers;
  // Re-entry probe wiring (mutable: the interface is const).
  HandshakeEngine* reenter_engine{nullptr};
  bool reenter_request{false};
  mutable bool reenter_seen_busy{false};
};

// Firmware-shaped verifier: real chain verification under the SAK plus
// the field checks, consulting the membership view for revocation.
struct TestVerifier final : public SessionCredentialVerifier {
  bool local_credential(LocalCredential& out) noexcept override {
    out = LocalCredential{};
    if (cert_size == 0 || cert_size > out.cred.size()) return false;
    std::memcpy(out.cred.data(), cert.data(), cert_size);
    out.cred_size = cert_size;
    out.privkey = privkey;
    return true;
  }
  bool verify_peer(const ByteView cert_bytes, const NodeId expected_node,
                   PeerCertClaims& out) noexcept override {
    out = PeerCertClaims{};
    CertClaims decoded{};
    bool verified = false;
    if (!cert_verify(cert_bytes, sak_pub, decoded, verified).ok() || !verified) return false;
    if (decoded.type != CertType::Member || decoded.subject != expected_node ||
        decoded.network != network || decoded.site_epoch != site_epoch || decoded.role == 0 ||
        (decoded.role & ~kMemberRoleMask) != 0 || decoded.assignment_generation == 0) {
      return false;
    }
    if (membership != nullptr && membership->revoked(decoded.subject, decoded.assignment_generation)) {
      return false;
    }
    out.node = decoded.subject;
    out.generation = decoded.assignment_generation;
    out.role = decoded.role;
    out.site_epoch = decoded.site_epoch;
    return true;
  }

  std::array<std::uint8_t, 256> cert{};
  std::size_t cert_size{0};
  std::array<std::uint8_t, 32> privkey{};
  P256PublicKey sak_pub{};
  NetworkId network{0};
  std::uint32_t site_epoch{0};
  TestMembership* membership{nullptr};
};

using TestBank = NodeSessionBank;

struct TestSink final : public HandshakeSessionSink {
  explicit TestSink(TestBank& bank) : bank(bank) {}
  Status install_verified(const ContextKeys& keys, const InstallAttestation& att) noexcept override {
    if (reenter_engine != nullptr && reenter_poll) {
      reenter_seen_busy = reenter_engine->poll(9999).code == StatusCode::Busy;
    }
    ++installs;
    last_created_gk = att.created_gk_epoch;
    return bank.install_verified(keys, att);
  }
  Status allocate_context_id(std::uint32_t& out) noexcept override {
    return bank.allocate_context_id(out);
  }
  bool context_id_live(const std::uint32_t id) const noexcept override {
    return bank.context_id_live(id);
  }

  TestBank& bank;
  std::size_t installs{0};
  std::uint32_t last_created_gk{0};
  HandshakeEngine* reenter_engine{nullptr};
  bool reenter_poll{false};
  bool reenter_seen_busy{false};
};

struct Side {
  Side(const NodeId self, const NodeId peer, const MacAddress& mac_self,
       const MacAddress& mac_peer, const routeloom_test::TestKeyPair& key,
       const ByteBuffer<kRlcw1CertMax>& member_cert, const std::uint32_t generation,
       const std::uint32_t role, const std::uint64_t rng_seed, const std::uint32_t gk_epoch,
       const bool gateway_cache = false)
      : self(self),
        peer(peer),
        mac_self(mac_self),
        mac_peer(mac_peer),
        storage(gateway_cache ? 160 : 16),
        cache(storage, gateway_cache ? 32 : kResume2NodeLinkQuota,
              gateway_cache ? 128 : kResume2NodeEndQuota),
        sink(bank),
        engine(cache, sink, cookie, membership, verifier, &XorShift::fill, &rng) {
    rng.state = rng_seed;
    const ByteView cert_view = member_cert.view();
    verifier.cert_size = cert_view.size;
    std::memcpy(verifier.cert.data(), cert_view.data, cert_view.size);
    verifier.privkey = key.priv;
    verifier.sak_pub = sdkv1_test::sak().pub;
    verifier.network = kNet;
    verifier.site_epoch = kSiteEpoch;
    verifier.membership = &membership;
    membership.view.self = self;
    membership.view.network = kNet;
    membership.view.site_id = sdkv1_test::kSiteId;
    membership.view.site_epoch = kSiteEpoch;
    membership.view.rs_epoch = kRs;
    membership.view.gk_epoch = gk_epoch;
    membership.view.generation = generation;
    membership.view.role = role;
    membership.view.caps = kRld1CapMemberEdhocV1 | kRld1CapMemberResumeV1;
    membership.view.boot = self == kNodeA ? 7 : 9;
    ScopeDigest digest{};
    sha256(cert_view, digest);
    std::memcpy(membership.view.local_cert_id.data(), digest.data(),
                membership.view.local_cert_id.size());
  }

  bool start() {
    AeadGcm port{&TestAead::seal, &TestAead::open, nullptr};
    TestBank::LocalView view{};
    view.self = self;
    view.network = kNet;
    view.gk_epoch = membership.view.gk_epoch;
    TestBank::RandomSource random{&XorShift::fill, &rng};
    if (!bank.configure(view, port, random, kT0).ok()) return false;
    if (!cookie.configure(&XorShift::fill, &rng).ok()) return false;
    return engine.configure(kT0).ok();
  }

  NodeId self{kInvalidNodeId};
  NodeId peer{kInvalidNodeId};
  MacAddress mac_self{};
  MacAddress mac_peer{};
  XorShift rng;
  FaultyResumeStorage2 storage;
  ResumeCache2 cache;
  TestBank bank;
  TestSink sink;
  MemberCookie cookie;
  TestMembership membership;
  TestVerifier verifier;
  HandshakeEngine engine;
};

ByteBuffer<kRlcw1CertMax> member_cert_for(const NodeId node, const P256PublicKey& pubkey,
                                         const std::uint32_t role,
                                         const std::uint32_t generation) {
  CertClaims claims{};
  claims.type = CertType::Member;
  claims.issuer = sdkv1_test::kSiteId;
  claims.subject = node;
  claims.pubkey = pubkey;
  claims.network = kNet;
  claims.role = role;
  claims.assignment_generation = generation;
  claims.site_epoch = kSiteEpoch;
  claims.serial = 4412;
  return sdkv1_test::issue(claims, sdkv1_test::sak());
}

// The frozen RLD1 exchange both sides agree on (P4 §5.2), with the
// responder-sealed cookie the initiator echoes.
struct FrozenLink {
  keys::LinkCarrier carrier{};
  std::array<std::uint8_t, 16> cookie{};
};

template <typename Initiator, typename Responder>
FrozenLink freeze_link(Initiator& initiator, Responder& responder, const MonotonicMs now,
                       const std::uint32_t caps_i, const std::uint32_t caps_r) {
  FrozenLink frozen{};
  frozen.carrier.network = kNet;
  frozen.carrier.node_i = initiator.self;
  frozen.carrier.node_r = responder.self;
  for (std::size_t i = 0; i < 16; ++i) {
    frozen.carrier.requester_nonce[i] = static_cast<std::uint8_t>(i);
    frozen.carrier.responder_nonce[i] = static_cast<std::uint8_t>(0x10 + i);
    frozen.carrier.scope_binding[i] = static_cast<std::uint8_t>(0xC0 + i);
    frozen.carrier.scope_binding[16 + i] = static_cast<std::uint8_t>(0xD0 + i);
  }
  frozen.carrier.capability_i = caps_i;
  frozen.carrier.capability_r = caps_r;
  CHECK_OK(responder.cookie.seal(initiator.mac_self, frozen.carrier.requester_nonce, kNet, now,
                                frozen.cookie));
  frozen.carrier.cookie = frozen.cookie;
  return frozen;
}

struct PumpResult {
  bool established_a{false};
  bool established_b{false};
  HandshakeResult est_a{};
  HandshakeResult est_b{};
  StatusCode failed_a{StatusCode::Ok};
  StatusCode failed_b{StatusCode::Ok};
  std::size_t m1_size{0}, m2_size{0}, m3_size{0}, m4_size{0};
  std::size_t r1_size{0}, r2_size{0}, r3_size{0};
};

// Delivers one Send result into the peer with owner-observed framing.
template <typename To, typename From>
Status deliver_to(To& to, const From& from, const HandshakeResult& send,
                  const FrozenLink& frozen, const MonotonicMs now) {
  HandshakeRx rx{};
  rx.scope = send.scope;
  rx.phase = send.phase;
  rx.step = send.step;
  rx.claimed_peer = from.self;
  std::array<std::uint8_t, 16> cookie = frozen.cookie;  // borrowed by rx below
  if (send.scope == SecurityScope::EndToEnd) {
    rx.exchange_id = send.exchange_id;  // routed envelope id, nonzero
  } else {
    rx.src_mac = from.mac_self;  // observed sender/receiver, always
    rx.dst_mac = to.mac_self;
    rx.carrier = frozen.carrier;
    if (send.cookie_attach) rx.cookie = ByteView{cookie.data(), cookie.size()};
  }
  return to.engine.on_message(rx, ByteView{send.message.data(), send.message_size}, now);
}

// Runs the exchange to completion: every Send is delivered immediately,
// time advances 50 ms per hop (well inside the cookie bucket and the
// retransmit/timer horizons, so no timer fires mid-exchange).
template <typename A, typename B>
PumpResult pump(A& a, B& b, const FrozenLink& frozen,
                  const MonotonicMs start = kT0) {
  PumpResult result{};
  MonotonicMs now = start;
  const auto note_send = [&](const HandshakeResult& send) {
    if (send.phase == 4 && send.step == 1) result.m1_size = send.message_size;
    if (send.phase == 4 && send.step == 2) result.m2_size = send.message_size;
    if (send.phase == 4 && send.step == 3) result.m3_size = send.message_size;
    if (send.phase == 4 && send.step == 4) result.m4_size = send.message_size;
    if (send.phase == 5 && send.step == 1) result.r1_size = send.message_size;
    if (send.phase == 5 && send.step == 2) result.r2_size = send.message_size;
    if (send.phase == 5 && send.step == 3) result.r3_size = send.message_size;
  };
  for (int round = 0; round < 12 && !(result.established_a && result.established_b); ++round) {
    bool progress = false;
    HandshakeResult out{};
    std::vector<HandshakeResult> sends_a, sends_b;
    while (a.engine.take_result(out).ok()) {
      progress = true;
      if (out.event == HandshakeEvent::Send) {
        sends_a.push_back(out);
      } else if (out.event == HandshakeEvent::Established) {
        result.established_a = true;
        result.est_a = out;
      } else if (out.event == HandshakeEvent::Failed) {
        result.failed_a = out.failure;
      }
    }
    while (b.engine.take_result(out).ok()) {
      progress = true;
      if (out.event == HandshakeEvent::Send) {
        sends_b.push_back(out);
      } else if (out.event == HandshakeEvent::Established) {
        result.established_b = true;
        result.est_b = out;
      } else if (out.event == HandshakeEvent::Failed) {
        result.failed_b = out.failure;
      }
    }
    for (const auto& send : sends_a) {
      note_send(send);
      now += 50;
      CHECK_OK(a.engine.accept_send(send.token, send.phase, send.step));
      CHECK_OK(deliver_to(b, a, send, frozen, now));
    }
    for (const auto& send : sends_b) {
      note_send(send);
      now += 50;
      CHECK_OK(b.engine.accept_send(send.token, send.phase, send.step));
      CHECK_OK(deliver_to(a, b, send, frozen, now));
    }
    if (!progress) break;
  }
  return result;
}

template <typename From, typename To>
bool roundtrip_ok(From& from, To& to, const HandshakeResult& est_from,
                  const HandshakeResult& est_to) {
  if (est_from.tx_context_id == 0 || est_from.tx_context_id != est_to.rx_context_id) return false;
  SecurityContext seal_ctx{};
  seal_ctx.scope = SecurityScope::Link;
  seal_ctx.network = kNet;
  seal_ctx.sender = from.self;
  seal_ctx.receiver = to.self;
  seal_ctx.epoch = est_from.tx_context_id;
  std::uint64_t counter = 0;
  if (!from.bank.next_counter(seal_ctx, counter).ok()) return false;
  const std::uint8_t aad[] = {0xAA, 0xBB};
  const std::uint8_t plain[] = {1, 2, 3, 4, 5};
  std::array<std::uint8_t, 5> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  if (!from.bank
           .seal(seal_ctx, counter, ByteView{aad, sizeof(aad)}, ByteView{plain, sizeof(plain)},
                 MutableByteView{cipher.data(), cipher.size()}, tag)
           .ok()) {
    return false;
  }
  SecurityContext open_ctx{};
  open_ctx.scope = SecurityScope::Link;
  open_ctx.network = kNet;
  open_ctx.sender = from.self;
  open_ctx.receiver = to.self;
  open_ctx.epoch = est_to.rx_context_id;
  std::array<std::uint8_t, 5> opened{};
  if (!to.bank
           .open(open_ctx, counter, ByteView{aad, sizeof(aad)},
                 ByteView{cipher.data(), cipher.size()}, tag,
                 MutableByteView{opened.data(), opened.size()})
           .ok()) {
    return false;
  }
  return opened[0] == 1 && opened[4] == 5;
}

constexpr std::uint32_t kCapsFull = kRld1CapMemberEdhocV1 | kRld1CapMemberResumeV1;
constexpr std::uint32_t kCapsEdhocOnly = kRld1CapMemberEdhocV1;

struct Pair {
  // Heap-held: a Side owns the engine/bank and is neither copyable nor movable.
  std::unique_ptr<Side> a;
  std::unique_ptr<Side> b;
  static Pair make(const std::uint32_t gk_a = kGk, const std::uint32_t gk_b = kGk,
                   const bool gateway_b = false) {
    const auto cert_a =
        member_cert_for(kNodeA, sdkv1_test::device_key().pub, kMemberRoleEndpoint, 3);
    const auto cert_b = member_cert_for(kNodeB, sdkv1_test::other_key().pub, kMemberRoleRelay, 1);
    Pair pair;
    pair.a.reset(new Side(kNodeA, kNodeB, mac_of(0x0A), mac_of(0x0B),
                          sdkv1_test::device_key(), cert_a, 3, kMemberRoleEndpoint, 0xA1, gk_a));
    pair.b.reset(new Side(kNodeB, kNodeA, mac_of(0x0B), mac_of(0x0A), sdkv1_test::other_key(),
                          cert_b, 1, kMemberRoleRelay, 0xB2, gk_b, gateway_b));
    CHECK(pair.a->start());
    CHECK(pair.b->start());
    return pair;
  }
};

// --- Dev-resume sides (P4 §10.1, PR6 wiring) -----------------------------------
// Same engine/bank/cookie shape as Side, but armed with a DevResumePolicy
// instead of member credentials: the membership view answers no local
// evidence (local() must never even be called) and revocation only, the
// credential verifier is null (dev never runs EDHOC), and the bank sits
// at the fixed dev GK epoch 1.
struct DevMembership final : public HandshakeMembershipView {
  bool local(HandshakeLocal& out) const noexcept override {
    ++local_calls;
    (void)out;
    return false;
  }
  bool revoked(const NodeId peer, const std::uint32_t generation) const noexcept override {
    (void)generation;  // dev generations are always 0; the local gate decides
    return revoked_peers.count(peer) != 0;
  }
  mutable std::size_t local_calls{0};
  std::set<NodeId> revoked_peers;
};

struct NullVerifier final : public SessionCredentialVerifier {
  bool local_credential(LocalCredential& out) noexcept override {
    (void)out;
    return false;
  }
  bool verify_peer(const ByteView cert, const NodeId expected_node,
                   PeerCertClaims& out) noexcept override {
    (void)cert;
    (void)expected_node;
    (void)out;
    return false;
  }
};

struct DevSide {
  DevSide(const NodeId self, const NodeId peer, const MacAddress& mac_self,
          const MacAddress& mac_peer, const keys::Secret& psk, const std::uint64_t rng_seed)
      : self(self),
        peer(peer),
        mac_self(mac_self),
        mac_peer(mac_peer),
        storage(16),
        cache(storage, kResume2NodeLinkQuota, kResume2NodeEndQuota),
        sink(bank),
        engine(cache, sink, cookie, membership, verifier, &XorShift::fill, &rng) {
    rng.state = rng_seed;
    policy.psk = psk;
    policy.network = kNet;
    policy.self = self;
    policy.role = kMemberRoleEndpoint;
    policy.boot = 11;
  }

  bool start() {
    AeadGcm port{&TestAead::seal, &TestAead::open, nullptr};
    TestBank::LocalView view{};
    view.self = self;
    view.network = kNet;
    view.gk_epoch = 1;  // dev fixed epoch (P4 §10.1)
    TestBank::RandomSource random{&XorShift::fill, &rng};
    if (!bank.configure(view, port, random, kT0).ok()) return false;
    if (!cookie.configure(&XorShift::fill, &rng).ok()) return false;
    return engine.configure_dev(policy, kT0).ok();
  }

  NodeId self{kInvalidNodeId};
  NodeId peer{kInvalidNodeId};
  MacAddress mac_self{};
  MacAddress mac_peer{};
  XorShift rng;
  FaultyResumeStorage2 storage;
  ResumeCache2 cache;
  TestBank bank;
  TestSink sink;
  MemberCookie cookie;
  DevMembership membership;
  NullVerifier verifier;
  HandshakeEngine engine;
  DevResumePolicy policy{};
};

keys::Secret dev_psk(const std::uint8_t fill) {
  keys::Secret psk{};
  psk.fill(fill);
  return psk;
}

struct DevPair {
  std::unique_ptr<DevSide> a;
  std::unique_ptr<DevSide> b;
  static DevPair make(const keys::Secret& psk_a, const keys::Secret& psk_b) {
    DevPair pair;
    pair.a.reset(new DevSide(kNodeA, kNodeB, mac_of(0x0A), mac_of(0x0B), psk_a, 0xD1));
    pair.b.reset(new DevSide(kNodeB, kNodeA, mac_of(0x0B), mac_of(0x0A), psk_b, 0xD2));
    CHECK(pair.a->start());
    CHECK(pair.b->start());
    return pair;
  }
  static DevPair make() {
    const keys::Secret psk = dev_psk(0xA5);
    return make(psk, psk);
  }
};

constexpr std::uint32_t kCapsDev = kRld1CapDevRamSessionV1;

template <typename Initiator, typename Responder>
Status request_link(Initiator& initiator, Responder& responder, const FrozenLink& frozen,
                    const MonotonicMs now,
                    const HandshakeReason reason = HandshakeReason::Initial,
                    const std::uint32_t elevation_token = 0) {
  HandshakeRequest req{};
  req.scope = SecurityScope::Link;
  req.peer = responder.self;
  req.reason = reason;
  req.elevation_token = elevation_token;
  req.mac_i = initiator.mac_self;
  req.mac_r = responder.mac_self;
  req.carrier = frozen.carrier;
  return initiator.engine.request(req, now);
}

bool slot_for(Side& side, const NodeId peer, ResumeSlot2& slot) {
  ResumeContext context{};
  context.network = kNet;
  context.gk_epoch = side.membership.view.gk_epoch;
  context.revocations = nullptr;
  std::size_t index = 0;
  return side.cache.find_by_peer(ResumePurpose::Link, peer, context, slot, index).ok();
}

void test_link_edhoc_full() {
  Pair pair = Pair::make();
  const FrozenLink frozen =
      freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  const PumpResult result = pump(*pair.a, *pair.b, frozen);
  CHECK(result.established_a);
  CHECK(result.established_b);
  CHECK(result.failed_a == StatusCode::Ok);
  CHECK(result.failed_b == StatusCode::Ok);
  CHECK(result.est_a.role == HandshakeRole::Initiator);
  CHECK(result.est_b.role == HandshakeRole::Responder);
  CHECK(result.est_a.peer == kNodeB && result.est_b.peer == kNodeA);
  // Context ids cross: our TX is the peer's RX, all nonzero and distinct.
  CHECK(result.est_a.tx_context_id != 0 && result.est_a.rx_context_id != 0);
  CHECK(result.est_a.tx_context_id == result.est_b.rx_context_id);
  CHECK(result.est_a.rx_context_id == result.est_b.tx_context_id);
  CHECK(result.est_a.tx_context_id != result.est_a.rx_context_id);
  // Link establishment mints the discovery elevation proof on both ends.
  CHECK(result.est_a.has_proof && result.est_a.proof.valid());
  CHECK(result.est_b.has_proof && result.est_b.proof.valid());
  CHECK(result.est_a.proof.peer() == kNodeB);
  CHECK(result.est_b.proof.peer() == kNodeA);
  CHECK(pair.a->sink.installs == 1 && pair.b->sink.installs == 1);
  // The installed keys agree in both directions.
  CHECK(roundtrip_ok(*pair.a, *pair.b, result.est_a, result.est_b));
  CHECK(roundtrip_ok(*pair.b, *pair.a, result.est_b, result.est_a));
  // Both ends saved a resume slot for the peer.
  ResumeSlot2 slot_a{}, slot_b{};
  CHECK(slot_for(*pair.a, kNodeB, slot_a));
  CHECK(slot_for(*pair.b, kNodeA, slot_b));
  CHECK(slot_a.created_gk_epoch == kGk && slot_b.created_gk_epoch == kGk);
  // Real-encoder sizes (§13.1): every message fits the 960 B link object.
  std::printf("edhoc sizes: m1=%zu m2=%zu m3=%zu m4=%zu\n", result.m1_size, result.m2_size,
              result.m3_size, result.m4_size);
  CHECK(result.m1_size != 0 && result.m2_size != 0 && result.m3_size != 0 &&
        result.m4_size != 0);
  CHECK(result.m1_size <= 960 && result.m2_size <= 960 && result.m3_size <= 960 &&
        result.m4_size <= 960);
  CHECK(result.m1_size + 6 + 16 <= 116);  // object header + cookie, §13.1
}

void test_responder_waits_for_m4_admission() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult m1{}, m2{}, m3{}, m4{}, result{};
  CHECK_OK(pair.a->engine.take_result(m1));
  CHECK_OK(deliver_to(*pair.b, *pair.a, m1, frozen, kT0 + 50));
  CHECK_OK(pair.b->engine.take_result(m2));
  CHECK_OK(deliver_to(*pair.a, *pair.b, m2, frozen, kT0 + 100));
  CHECK_OK(pair.a->engine.take_result(m3));
  CHECK_OK(deliver_to(*pair.b, *pair.a, m3, frozen, kT0 + 150));
  CHECK_OK(pair.b->engine.take_result(m4));
  CHECK(m4.event == HandshakeEvent::Send && m4.phase == 4 && m4.step == 4);
  CHECK(pair.b->bank.live_count(SecurityScope::Link) == 0);
  CHECK(pair.b->engine.take_result(result).code == StatusCode::NotFound);
  CHECK_OK(pair.b->engine.poll(kT0 + 550));
  HandshakeResult retry{};
  CHECK_OK(pair.b->engine.take_result(retry));
  CHECK(retry.event == HandshakeEvent::Send && retry.step == 4 &&
        retry.message_size == m4.message_size);
  CHECK(pair.b->bank.live_count(SecurityScope::Link) == 0);
  CHECK_OK(pair.b->engine.accept_send(retry.token, retry.phase, retry.step));
  CHECK(pair.b->bank.live_count(SecurityScope::Link) == 1);
  CHECK_OK(pair.b->engine.take_result(result));
  CHECK(result.event == HandshakeEvent::Established);
}

void test_resume_after_edhoc() {
  Pair pair = Pair::make();
  FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  PumpResult first = pump(*pair.a, *pair.b, frozen);
  CHECK(first.established_a && first.established_b);
  // Reboot-like loss: the banks forget, the durable RLP slots survive.
  CHECK_OK(pair.a->bank.retire(SecurityScope::Link, kNodeB));
  CHECK_OK(pair.b->bank.retire(SecurityScope::Link, kNodeA));
  const MonotonicMs t1 = kT0 + 500;
  frozen = freeze_link(*pair.a, *pair.b, t1, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, t1));
  // Resume-first: the first flight is R1, not m1.
  HandshakeResult out{};
  CHECK_OK(pair.a->engine.take_result(out));
  CHECK(out.event == HandshakeEvent::Send && out.phase == 5 && out.step == 1);
  const std::size_t r1_size = out.message_size;
  CHECK_OK(deliver_to(*pair.b, *pair.a, out, frozen, t1 + 50));
  const PumpResult resumed = pump(*pair.a, *pair.b, frozen, t1 + 50);
  CHECK(resumed.established_a && resumed.established_b);
  CHECK(r1_size != 0 && resumed.r2_size != 0 && resumed.r3_size != 0);
  CHECK(resumed.m1_size == 0);  // no EDHOC ran
  CHECK(pair.a->sink.installs == 2 && pair.b->sink.installs == 2);
  CHECK(roundtrip_ok(*pair.a, *pair.b, resumed.est_a, resumed.est_b));
  CHECK(roundtrip_ok(*pair.b, *pair.a, resumed.est_b, resumed.est_a));
  CHECK(resumed.est_a.has_proof && resumed.est_b.has_proof);
  std::printf("resume sizes: r1=%zu r2=%zu r3=%zu\n", r1_size, resumed.r2_size,
              resumed.r3_size);
}

void test_gateway_resume_lookup_budget() {
  {
    Pair pair = Pair::make(kGk, kGk, true);
    const FrozenLink frozen = freeze_link(*pair.b, *pair.a, kT0, kCapsFull, kCapsFull);
    pair.b->storage.read_calls = 0;
    CHECK_OK(request_link(*pair.b, *pair.a, frozen, kT0));
    CHECK(pair.b->storage.read_calls <= 16);
    for (MonotonicMs now = kT0 + 1; now < kT0 + 8; ++now) {
      pair.b->storage.read_calls = 0;
      CHECK_OK(pair.b->engine.poll(now));
      CHECK(pair.b->storage.read_calls <= 16);
      HandshakeResult send{};
      if (pair.b->engine.take_result(send).ok()) {
        CHECK(send.event == HandshakeEvent::Send && send.phase == 4);
        break;
      }
    }
  }
  {
    Pair pair = Pair::make(kGk, kGk, true);
    FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
    CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
    const PumpResult first = pump(*pair.a, *pair.b, frozen);
    CHECK(first.established_a && first.established_b);
    pair.b->storage.slot(31) = pair.b->storage.slot(0);
    pair.b->storage.slot(0).fill(0xFF);
    CHECK_OK(pair.a->bank.retire(SecurityScope::Link, kNodeB));
    CHECK_OK(pair.b->bank.retire(SecurityScope::Link, kNodeA));
    const MonotonicMs t1 = kT0 + 500;
    frozen = freeze_link(*pair.a, *pair.b, t1, kCapsFull, kCapsFull);
    CHECK_OK(request_link(*pair.a, *pair.b, frozen, t1));
    HandshakeResult r1{};
    CHECK_OK(pair.a->engine.take_result(r1));
    CHECK(r1.phase == 5 && r1.step == 1);
    pair.b->storage.read_calls = 0;
    CHECK_OK(deliver_to(*pair.b, *pair.a, r1, frozen, t1 + 1));
    CHECK(pair.b->storage.read_calls <= 16);
    bool got_r2 = false;
    HandshakeResult r2{};
    for (MonotonicMs now = t1 + 2; now < t1 + 16 && !got_r2; ++now) {
      pair.b->storage.read_calls = 0;
      CHECK_OK(pair.b->engine.poll(now));
      CHECK(pair.b->storage.read_calls <= 16);
      if (pair.b->engine.take_result(r2).ok()) {
        got_r2 = r2.event == HandshakeEvent::Send && r2.phase == 5 && r2.step == 2;
      }
    }
    CHECK(got_r2);
    if (got_r2) {
      CHECK_OK(deliver_to(*pair.a, *pair.b, r2, frozen, t1 + 20));
      HandshakeResult r3{}, established{};
      CHECK_OK(pair.a->engine.take_result(r3));
      CHECK(r3.event == HandshakeEvent::Send && r3.step == 3);
      CHECK_OK(deliver_to(*pair.b, *pair.a, r3, frozen, t1 + 21));
      CHECK_OK(pair.b->engine.take_result(established));
      CHECK(established.event == HandshakeEvent::Established);
    }
  }
  {
    Pair pair = Pair::make(kGk, kGk, true);
    const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
    CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
    const PumpResult first = pump(*pair.a, *pair.b, frozen);
    CHECK(first.established_a && first.established_b);
    ResumeSlot2 slot{};
    CHECK(slot_for(*pair.b, kNodeA, slot));
    slot.purpose = ResumePurpose::End;
    CHECK_OK(resume2_slot_encode(slot, pair.b->storage.slot(159)));
    HandshakeRequest request{};
    request.scope = SecurityScope::EndToEnd;
    request.peer = kNodeA;
    request.reason = HandshakeReason::Initial;
    const MonotonicMs t1 = kT0 + 500;
    pair.b->storage.read_calls = 0;
    CHECK_OK(pair.b->engine.request(request, t1));
    CHECK(pair.b->storage.read_calls <= 16);
    bool sent_r1 = false;
    for (MonotonicMs now = t1 + 1; now < t1 + 12 && !sent_r1; ++now) {
      pair.b->storage.read_calls = 0;
      CHECK_OK(pair.b->engine.poll(now));
      CHECK(pair.b->storage.read_calls <= 16);
      HandshakeResult out{};
      if (pair.b->engine.take_result(out).ok()) {
        sent_r1 = out.event == HandshakeEvent::Send && out.phase == 5 && out.step == 1;
      }
    }
    CHECK(sent_r1);
  }
}

void test_routed_end_exchange() {
  Pair pair = Pair::make();
  HandshakeRequest request{};
  request.scope = SecurityScope::EndToEnd;
  request.peer = kNodeB;
  request.reason = HandshakeReason::Initial;
  const auto exchange = [&](const MonotonicMs start, const std::uint8_t expected_phase) {
    CHECK_OK(pair.a->engine.request(request, start));
    bool established_a = false, established_b = false;
    bool first_send = true;
    MonotonicMs now = start;
    for (int turn = 0; turn < 16 && !(established_a && established_b); ++turn) {
      bool progressed = false;
      for (Side* from : {pair.a.get(), pair.b.get()}) {
        Side* to = from == pair.a.get() ? pair.b.get() : pair.a.get();
        HandshakeResult out{};
        while (from->engine.take_result(out).ok()) {
          progressed = true;
          if (out.event == HandshakeEvent::Established) {
            if (from == pair.a.get()) established_a = true;
            else established_b = true;
            continue;
          }
          CHECK(out.event == HandshakeEvent::Send);
          if (out.event != HandshakeEvent::Send) continue;
          if (first_send) {
            CHECK(out.phase == expected_phase && out.step == 1);
            first_send = false;
          }
          CHECK_OK(from->engine.accept_send(out.token, out.phase, out.step));
          HandshakeRx rx{};
          rx.scope = SecurityScope::EndToEnd;
          rx.phase = out.phase;
          rx.step = out.step;
          rx.claimed_peer = from->self;
          rx.exchange_id = out.exchange_id;
          CHECK(rx.exchange_id != 0);
          now += 50;
          CHECK_OK(to->engine.on_message(rx, ByteView{out.message.data(), out.message_size}, now));
        }
      }
      if (!progressed) break;
    }
    CHECK(established_a && established_b);
  };
  exchange(kT0, 4);
  CHECK(pair.a->bank.live_count(SecurityScope::EndToEnd) == 1);
  CHECK(pair.b->bank.live_count(SecurityScope::EndToEnd) == 1);
  CHECK_OK(pair.a->bank.retire(SecurityScope::EndToEnd, kNodeB));
  CHECK_OK(pair.b->bank.retire(SecurityScope::EndToEnd, kNodeA));
  exchange(kT0 + 500, 5);
  CHECK(pair.a->bank.live_count(SecurityScope::EndToEnd) == 1);
  CHECK(pair.b->bank.live_count(SecurityScope::EndToEnd) == 1);
}

void test_resume_slot_replaced_before_commit() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  const PumpResult first = pump(*pair.a, *pair.b, frozen);
  CHECK(first.established_a && first.established_b);
  CHECK_OK(pair.a->bank.retire(SecurityScope::Link, kNodeB));
  CHECK_OK(pair.b->bank.retire(SecurityScope::Link, kNodeA));
  const MonotonicMs t1 = kT0 + 500;
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, t1));
  HandshakeResult r1{}, r2{};
  CHECK_OK(pair.a->engine.take_result(r1));
  CHECK(r1.phase == 5 && r1.step == 1);
  CHECK_OK(deliver_to(*pair.b, *pair.a, r1, frozen, t1 + 50));
  CHECK_OK(pair.b->engine.take_result(r2));
  CHECK(r2.phase == 5 && r2.step == 2);
  ResumeSlot2 replacement{};
  CHECK(slot_for(*pair.a, kNodeB, replacement));
  replacement.rms[0] ^= 0x5A;
  ++replacement.peer_generation;
  replacement.reserved_uses = 0;
  ResumeContext context{};
  context.network = kNet;
  context.gk_epoch = kGk;
  CHECK_OK(pair.a->cache.put(replacement, context));
  CHECK_OK(deliver_to(*pair.a, *pair.b, r2, frozen, t1 + 100));
  CHECK(pair.a->sink.installs == 1);
  HandshakeResult outcome{};
  CHECK_OK(pair.a->engine.take_result(outcome));
  CHECK(outcome.event == HandshakeEvent::Failed);
}

void test_pending_send_invalidated_by_membership_loss() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  pair.a->membership.local_ok = false;
  HandshakeResult result{};
  CHECK(!pair.a->engine.take_result(result).ok());
  CHECK(result.token == 0 && result.message_size == 0);
  CHECK(pair.a->engine.quiescent());
}

void test_local_epoch_floor_survives_reconfiguration() {
  Pair pair = Pair::make();
  HandshakeResult out{};
  pair.a->membership.view.gk_epoch = kGk - 1;
  CHECK(pair.a->engine.configure(kT0 + 1).code == StatusCode::Conflict);
  pair.a->membership.view.gk_epoch = kGk;
  pair.a->membership.view.gk_epoch = kGk - 1;
  CHECK(pair.a->engine.take_result(out).code == StatusCode::Conflict);
  CHECK(pair.a->engine.take_result(out).code == StatusCode::Conflict);
  pair.a->membership.local_ok = false;
  CHECK(!pair.a->engine.take_result(out).ok());
  pair.a->membership.local_ok = true;
  CHECK(pair.a->engine.take_result(out).code == StatusCode::Conflict);
  pair.a->membership.view.gk_epoch = kGk + 1;
  CHECK(pair.a->engine.take_result(out).code == StatusCode::Conflict);
  CHECK(pair.a->engine.take_result(out).code == StatusCode::NotFound);
}

void test_local_change_during_commit_cancels_result() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult m1{}, m2{}, m3{};
  CHECK_OK(pair.a->engine.take_result(m1));
  CHECK_OK(deliver_to(*pair.b, *pair.a, m1, frozen, kT0 + 50));
  CHECK_OK(pair.b->engine.take_result(m2));
  CHECK_OK(deliver_to(*pair.a, *pair.b, m2, frozen, kT0 + 100));
  CHECK_OK(pair.a->engine.take_result(m3));
  CHECK(m3.step == 3);
  CHECK_OK(deliver_to(*pair.b, *pair.a, m3, frozen, kT0 + 150));
  HandshakeResult m4{}, out{};
  CHECK_OK(pair.b->engine.take_result(m4));
  CHECK(m4.event == HandshakeEvent::Send && m4.step == 4);
  pair.b->membership.change_on_local_call = pair.b->membership.local_calls + 1;
  CHECK(!pair.b->engine.accept_send(m4.token, m4.phase, m4.step).ok());
  CHECK(pair.b->bank.live_count(SecurityScope::Link) == 0);
  CHECK(pair.b->engine.take_result(out).code == StatusCode::NotFound);
  CHECK(pair.b->engine.quiescent());
}

void test_reconfigure_does_not_reuse_exchange_token() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult old_send{}, new_send{};
  CHECK_OK(pair.a->engine.take_result(old_send));
  CHECK(old_send.event == HandshakeEvent::Send && old_send.token != 0);
  CHECK_OK(pair.a->engine.configure(kT0 + 500));
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0 + 500));
  CHECK_OK(pair.a->engine.take_result(new_send));
  CHECK(new_send.event == HandshakeEvent::Send && new_send.token != old_send.token);
}

void test_cookie_reject() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult send{};
  CHECK_OK(pair.a->engine.take_result(send));
  CHECK(send.event == HandshakeEvent::Send && send.cookie_attach);
  // A forged cookie dies before any responder state exists.
  HandshakeRx rx{};
  rx.scope = SecurityScope::Link;
  rx.phase = send.phase;
  rx.step = send.step;
  rx.claimed_peer = kNodeA;
  rx.src_mac = pair.a->mac_self;
  rx.dst_mac = pair.b->mac_self;
  rx.carrier = frozen.carrier;
  std::array<std::uint8_t, 16> forged = frozen.cookie;
  forged[0] ^= 0xFF;
  rx.cookie = ByteView{forged.data(), forged.size()};
  CHECK_OK(pair.b->engine.on_message(rx, ByteView{send.message.data(), send.message_size},
                                    kT0 + 50));
  HandshakeResult nothing{};
  CHECK(pair.b->engine.take_result(nothing).code == StatusCode::NotFound);
  CHECK(pair.b->engine.quiescent());
  CHECK(pair.b->sink.installs == 0);
  // The initiator retransmits into the void, then reports the timeout.
  CHECK(pair.a->engine.poll(kT0 + 8001).ok());
  HandshakeResult failed{};
  CHECK_OK(pair.a->engine.take_result(failed));
  CHECK(failed.event == HandshakeEvent::Failed && failed.failure == StatusCode::Expired);
}

void test_binding_reject() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult send{};
  CHECK_OK(pair.a->engine.take_result(send));
  const ByteView m1{send.message.data(), send.message_size};
  // The same m1 bytes from an unobserved MAC: the cookie (sealed for
  // the observed initiator MAC) already refuses them.
  HandshakeRx rx{};
  rx.scope = SecurityScope::Link;
  rx.phase = send.phase;
  rx.step = send.step;
  rx.claimed_peer = kNodeA;
  rx.src_mac = mac_of(0xFF);
  rx.dst_mac = pair.b->mac_self;
  rx.carrier = frozen.carrier;
  rx.cookie = ByteView{frozen.cookie.data(), frozen.cookie.size()};
  CHECK_OK(pair.b->engine.on_message(rx, m1, kT0 + 50));
  HandshakeResult nothing{};
  CHECK(pair.b->engine.take_result(nothing).code == StatusCode::NotFound);
  CHECK(pair.b->engine.quiescent());
  // Even with a cookie freshly sealed for the new MAC, the Intent gate
  // drops the bytes: they name the old carrier, not this one (P4 §5.2:
  // observed MACs feed the binding, never claimed ones).
  std::array<std::uint8_t, 16> fresh_cookie{};
  CHECK_OK(pair.b->cookie.seal(mac_of(0xFF), frozen.carrier.requester_nonce, kNet, kT0 + 50,
                              fresh_cookie));
  rx.carrier.cookie = fresh_cookie;
  rx.cookie = ByteView{fresh_cookie.data(), fresh_cookie.size()};
  CHECK_OK(pair.b->engine.on_message(rx, m1, kT0 + 60));
  CHECK(pair.b->engine.take_result(nothing).code == StatusCode::NotFound);
  CHECK(pair.b->engine.quiescent());
  CHECK(pair.b->sink.installs == 0);
}

void test_caps_unsupported() {
  Pair pair = Pair::make();
  // No mutual EDHOC floor: selection refuses before any frame exists.
  FrozenLink no_edhoc = freeze_link(*pair.a, *pair.b, kT0, 0, kCapsFull);
  CHECK(request_link(*pair.a, *pair.b, no_edhoc, kT0).code == StatusCode::Unsupported);
  FrozenLink peer_no_edhoc = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, 0);
  CHECK(request_link(*pair.a, *pair.b, peer_no_edhoc, kT0).code == StatusCode::Unsupported);
  // DevRam never mixes with the production profile.
  FrozenLink dev = freeze_link(*pair.a, *pair.b, kT0, kCapsFull | kRld1CapDevRamSessionV1,
                               kCapsFull);
  CHECK(request_link(*pair.a, *pair.b, dev, kT0).code == StatusCode::Unsupported);
  CHECK(pair.a->engine.quiescent());
  HandshakeResult nothing{};
  CHECK(pair.a->engine.take_result(nothing).code == StatusCode::NotFound);
}

void test_resume_skipped_without_bit25() {
  Pair pair = Pair::make();
  // Seed the cache with a full EDHOC first.
  FrozenLink full = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, full, kT0));
  const PumpResult first = pump(*pair.a, *pair.b, full);
  CHECK(first.established_a && first.established_b);
  CHECK_OK(pair.a->bank.retire(SecurityScope::Link, kNodeB));
  CHECK_OK(pair.b->bank.retire(SecurityScope::Link, kNodeA));
  // The peer's new OFFER drops the resume bit: same RMS, EDHOC anyway.
  // (The second EDHOC begin waits out the 2 s ECC gap via the queue.)
  const MonotonicMs t1 = kT0 + 500;
  FrozenLink edhoc_only = freeze_link(*pair.a, *pair.b, t1, kCapsFull, kCapsEdhocOnly);
  CHECK_OK(request_link(*pair.a, *pair.b, edhoc_only, t1));
  CHECK(pair.a->engine.poll(t1 + 2100).ok());
  HandshakeResult out{};
  CHECK_OK(pair.a->engine.take_result(out));
  CHECK(out.event == HandshakeEvent::Send && out.phase == 4 && out.step == 1);
}

void test_reentry_busy() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  // A mutating call from inside a membership callback sees Busy and
  // queues nothing: the outer request then emits exactly one Send.
  pair.a->membership.reenter_engine = &pair.a->engine;
  pair.a->membership.reenter_request = true;
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  CHECK(pair.a->membership.reenter_seen_busy);
  pair.a->membership.reenter_request = false;
  HandshakeResult first{}, second{};
  CHECK_OK(pair.a->engine.take_result(first));
  CHECK(first.event == HandshakeEvent::Send);
  CHECK(pair.a->engine.take_result(second).code == StatusCode::NotFound);
  // And from inside the install path during commit.
  pair.a->sink.reenter_engine = &pair.a->engine;
  pair.a->sink.reenter_poll = true;
  pair.b->sink.reenter_engine = &pair.b->engine;
  pair.b->sink.reenter_poll = true;
  CHECK_OK(deliver_to(*pair.b, *pair.a, first, frozen, kT0 + 50));
  const PumpResult result = pump(*pair.a, *pair.b, frozen, kT0 + 50);
  CHECK(result.established_a && result.established_b);
  CHECK(pair.a->sink.reenter_seen_busy || pair.b->sink.reenter_seen_busy);
  CHECK(roundtrip_ok(*pair.a, *pair.b, result.est_a, result.est_b));
}

void test_cancel_and_timeout() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult send{};
  CHECK_OK(pair.a->engine.take_result(send));
  CHECK_OK(pair.a->engine.cancel(kNodeB, HandshakeCancelReason::Shutdown));
  HandshakeResult nothing{};
  CHECK(pair.a->engine.take_result(nothing).code == StatusCode::NotFound);
  CHECK(pair.a->engine.quiescent());
  CHECK(pair.a->sink.installs == 0);
  // A fresh request after cancel works: cancel leaves no residue.
  // (The re-begin waits out the 2 s ECC gap via the queue.)
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0 + 100));
  CHECK(pair.a->engine.poll(kT0 + 2100).ok());
  const PumpResult result = pump(*pair.a, *pair.b, frozen, kT0 + 2100);
  CHECK(result.established_a && result.established_b);
  // Timeout without any delivery reports Expired, once.
  Pair pair2 = Pair::make();
  const FrozenLink frozen2 = freeze_link(*pair2.a, *pair2.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair2.a, *pair2.b, frozen2, kT0));
  CHECK_OK(pair2.a->engine.take_result(send));
  CHECK(pair2.a->engine.poll(kT0 + 8001).ok());
  HandshakeResult failed{};
  CHECK_OK(pair2.a->engine.take_result(failed));
  CHECK(failed.event == HandshakeEvent::Failed && failed.failure == StatusCode::Expired);
  CHECK(pair2.a->engine.take_result(nothing).code == StatusCode::NotFound);
  CHECK(pair2.a->engine.quiescent());
}

void test_simultaneous_open() {
  Pair pair = Pair::make();
  // Both sides initiate at once; kNodeB (0x777) is the smaller id and
  // stays initiator, kNodeA yields and answers as responder (P4 §5.5).
  CHECK(kNodeB < kNodeA);
  const FrozenLink frozen_ab = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  const FrozenLink frozen_ba = freeze_link(*pair.b, *pair.a, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen_ab, kT0));
  CHECK_OK(request_link(*pair.b, *pair.a, frozen_ba, kT0));
  HandshakeResult m1a{}, m1b{};
  CHECK_OK(pair.a->engine.take_result(m1a));
  CHECK_OK(pair.b->engine.take_result(m1b));
  // B drops A's m1 (B wins); A yields to B's m1 but must wait out
  // its own initiator begin's ECC gap, so the m1 parks first.
  CHECK_OK(deliver_to(*pair.b, *pair.a, m1a, frozen_ab, kT0 + 50));
  HandshakeResult nothing{};
  CHECK(pair.b->engine.take_result(nothing).code == StatusCode::NotFound);
  CHECK_OK(deliver_to(*pair.a, *pair.b, m1b, frozen_ba, kT0 + 100));
  CHECK(pair.a->engine.take_result(nothing).code == StatusCode::NotFound);
  CHECK(!pair.a->engine.quiescent());  // the parked m1 is live state
  CHECK(pair.a->engine.poll(kT0 + 2100).ok());
  const PumpResult result = pump(*pair.a, *pair.b, frozen_ba, kT0 + 2100);
  CHECK(result.established_a && result.established_b);
  CHECK(result.failed_a == StatusCode::Ok && result.failed_b == StatusCode::Ok);
  CHECK(result.est_a.role == HandshakeRole::Responder);
  CHECK(result.est_b.role == HandshakeRole::Initiator);
  CHECK(pair.a->sink.installs == 1 && pair.b->sink.installs == 1);
  CHECK(roundtrip_ok(*pair.a, *pair.b, result.est_a, result.est_b));
  CHECK(roundtrip_ok(*pair.b, *pair.a, result.est_b, result.est_a));
}

void test_min_gk_birthday() {
  // Responder one GK ahead (compatible): the new RMS/context birthday
  // is the smaller epoch (P4 §5.3).
  Pair pair = Pair::make(kGk, kGk + 1);
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  const PumpResult result = pump(*pair.a, *pair.b, frozen);
  CHECK(result.established_a && result.established_b);
  CHECK(pair.a->sink.last_created_gk == kGk);
  CHECK(pair.b->sink.last_created_gk == kGk);
  ResumeSlot2 slot_a{}, slot_b{};
  CHECK(slot_for(*pair.a, kNodeB, slot_a));
  CHECK(slot_for(*pair.b, kNodeA, slot_b));
  CHECK(slot_a.created_gk_epoch == kGk && slot_b.created_gk_epoch == kGk);
}

void test_revoke_before_commit() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult m1{};
  CHECK_OK(pair.a->engine.take_result(m1));
  CHECK_OK(deliver_to(*pair.b, *pair.a, m1, frozen, kT0 + 50));
  HandshakeResult m2{};
  CHECK_OK(pair.b->engine.take_result(m2));
  // Revoked after m1 but before the peer credential lands: the m3
  // credential check fails closed and nothing installs (V1-F02).
  pair.b->membership.revoked_peers.insert(kNodeA);
  CHECK_OK(deliver_to(*pair.a, *pair.b, m2, frozen, kT0 + 100));
  HandshakeResult m3{};
  CHECK_OK(pair.a->engine.take_result(m3));
  CHECK_OK(deliver_to(*pair.b, *pair.a, m3, frozen, kT0 + 150));
  HandshakeResult failed{};
  CHECK_OK(pair.b->engine.take_result(failed));
  CHECK(failed.event == HandshakeEvent::Failed &&
        failed.failure == StatusCode::AuthenticationFailed);
  CHECK(pair.b->sink.installs == 0 && pair.a->sink.installs == 0);
  CHECK(pair.a->engine.poll(kT0 + 9000).ok());
  HandshakeResult expired{};
  CHECK_OK(pair.a->engine.take_result(expired));
  CHECK(expired.event == HandshakeEvent::Failed && expired.failure == StatusCode::Expired);
}

void test_unknown_claimant_cannot_complete() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult m1{};
  CHECK_OK(pair.a->engine.take_result(m1));
  // Unattributed step-1: the responder answers, but the exchange can
  // never bind a peer, so both sides time out with nothing installed.
  HandshakeRx rx{};
  rx.scope = SecurityScope::Link;
  rx.phase = m1.phase;
  rx.step = m1.step;
  rx.claimed_peer = kInvalidNodeId;
  rx.src_mac = pair.a->mac_self;
  rx.dst_mac = pair.b->mac_self;
  rx.carrier = frozen.carrier;
  rx.cookie = ByteView{frozen.cookie.data(), frozen.cookie.size()};
  CHECK_OK(pair.b->engine.on_message(rx, ByteView{m1.message.data(), m1.message_size},
                                    kT0 + 50));
  const PumpResult result = pump(*pair.a, *pair.b, frozen, kT0 + 50);
  CHECK(!result.established_a && !result.established_b);
  CHECK(pair.a->engine.poll(kT0 + 9000).ok());
  CHECK(pair.b->engine.poll(kT0 + 9000).ok());
  HandshakeResult failed{};
  CHECK_OK(pair.a->engine.take_result(failed));
  CHECK(failed.failure == StatusCode::Expired);
  CHECK_OK(pair.b->engine.take_result(failed));
  CHECK(failed.failure == StatusCode::Expired);
  CHECK(pair.a->sink.installs == 0 && pair.b->sink.installs == 0);
}

// --- Discovery elevation (P4 §7.2) --------------------------------------------------

class ElevationPort final : public DiscoveryPort {
 public:
  Status send_rld1(const MacAddress&, ByteView) noexcept override { return Status::success(); }
  Status send_wire(BindingId, const MacAddress&, FrameType, ByteView) noexcept override {
    ++wire_sends;
    return Status::success();
  }
  std::size_t wire_sends{0};
};

class ElevationEntropy final : public EntropySource {
 public:
  Status fill(const MutableByteView out) noexcept override { return impl_.fill(out); }
  routeloom_test::ScriptedEntropy impl_{0xE1E7};
};

class ElevationHooks final : public MembershipHooks {
 public:
  bool local_member(NetworkId) const noexcept override { return is_member; }
  bool known_member(const NodeId peer, NetworkId) const noexcept override {
    return peer_members.count(peer) != 0;
  }
  bool approve_join(NodeId, NetworkId) noexcept override { return true; }
  bool is_member{true};
  std::set<NodeId> peer_members;
};

class ElevationObserver final : public DiscoveryObserver {
 public:
  void on_discovery_event(const char* reason, const NodeId peer) noexcept override {
    events.emplace_back(reason, peer);
  }
  bool has(const char* prefix) const {
    for (const auto& event : events) {
      if (event.first.rfind(prefix, 0) == 0) return true;
    }
    return false;
  }
  std::vector<std::pair<std::string, NodeId>> events;
};

struct ElevationRig {
  ElevationPort port;
  UnavailableAuthenticator auth;  // the member path needs no dev authenticator
  ElevationHooks hooks;
  ElevationEntropy entropy;
  ElevationObserver observer;
  NeighborDiscovery discovery;
  ElevationRig(const NodeId self, const MacAddress& mac)
      : discovery(config(self, mac), port, auth, hooks, entropy, observer) {
    hooks.peer_members.insert(self == kNodeA ? kNodeB : kNodeA);
  }

 private:
  static DiscoveryConfig config(const NodeId self, const MacAddress& mac) {
    DiscoveryConfig config{};
    config.node = self;
    config.mac = mac;
    config.network = kNet;
    config.capability_bits = kCapsFull;
    return config;
  }
};

void test_elevation() {
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  ScopeDigest carrier_digest{};
  keys::link_carrier_digest(frozen.carrier, carrier_digest);
  ElevationRig rig(kNodeA, pair.a->mac_self);
  CHECK_OK(rig.discovery.start(kT0));
  // Reserve first (the owner does this before driving the engine).
  std::uint32_t token = 0;
  CHECK_OK(rig.discovery.begin_member_handshake(kNodeB, pair.b->mac_self, carrier_digest,
                                                kT0, token));
  CHECK(token != NeighborDiscovery::kMemberHandshakeNone);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0, HandshakeReason::Initial, token));
  const PumpResult result = pump(*pair.a, *pair.b, frozen);
  CHECK(result.established_a);
  // Complete with the minted proof: Bound with a probe on the wire.
  CHECK_OK(rig.discovery.complete_handshake(token, result.est_a.proof, kT0 + 500));
  NeighborPhase phase = NeighborPhase::Candidate;
  CHECK(rig.discovery.phase_of(kNodeB, phase) && phase == NeighborPhase::Bound);
  CHECK(rig.observer.has("BOUND"));
  CHECK(rig.port.wire_sends != 0);  // the reachability probe
  // The token is single-use; the proof names exactly this peer/MAC/net.
  CHECK(rig.discovery.complete_handshake(token, result.est_a.proof, kT0 + 600).code ==
        StatusCode::NotFound);
  std::uint32_t next_token = 0;
  CHECK_OK(rig.discovery.begin_member_handshake(kNodeB, pair.b->mac_self, carrier_digest,
                                                kT0 + 700,
                                                next_token));
  CHECK(rig.discovery.complete_handshake(next_token, result.est_a.proof, kT0 + 800).code ==
        StatusCode::AuthenticationFailed);
  ElevationRig restarted(kNodeA, pair.a->mac_self);
  CHECK_OK(restarted.discovery.start(kT0));
  std::uint32_t restarted_token = 0;
  ScopeDigest next_carrier = carrier_digest;
  next_carrier[0] ^= 0x80;
  CHECK_OK(restarted.discovery.begin_member_handshake(kNodeB, pair.b->mac_self, next_carrier, kT0,
                                                      restarted_token));
  CHECK(restarted.discovery.complete_handshake(restarted_token, result.est_a.proof,
                                                kT0 + 100).code ==
        StatusCode::AuthenticationFailed);
  CHECK(result.est_a.proof.peer() == kNodeB);
  CHECK(result.est_a.proof.network() == kNet);
  CHECK(std::memcmp(result.est_a.proof.mac().data(), pair.b->mac_self.data(), 6) == 0);
}

void test_elevation_negatives() {
  ElevationRig rig(kNodeA, mac_of(0x0A));
  CHECK_OK(rig.discovery.start(kT0));
  ScopeDigest dummy_digest{};
  dummy_digest.fill(0xA5);
  std::uint32_t token = 0;
  CHECK_OK(rig.discovery.begin_member_handshake(kNodeB, mac_of(0x0B), dummy_digest,
                                                kT0, token));
  // An empty proof is refused and consumes the reservation.
  AuthenticatedPeerProof empty{};
  CHECK(!empty.valid());
  CHECK(rig.discovery.complete_handshake(token, empty, kT0 + 100).code ==
        StatusCode::AuthenticationFailed);
  CHECK(rig.discovery.complete_handshake(token, empty, kT0 + 100).code == StatusCode::NotFound);
  // Unknown tokens never elevate.
  CHECK(rig.discovery.complete_handshake(0xDEAD, empty, kT0 + 100).code == StatusCode::NotFound);
  // Cancel drops the reservation silently; unknown cancels are ignored.
  CHECK_OK(rig.discovery.begin_member_handshake(kNodeB, mac_of(0x0B), dummy_digest,
                                                kT0 + 100, token));
  rig.discovery.cancel_member_handshake(token);
  CHECK(rig.discovery.complete_handshake(token, empty, kT0 + 200).code == StatusCode::NotFound);
  rig.discovery.cancel_member_handshake(0xBEEF);
  // Four live reservations max.
  std::uint32_t tokens[4] = {0, 0, 0, 0};
  for (int i = 0; i < 4; ++i) {
    CHECK_OK(rig.discovery.begin_member_handshake(
        static_cast<NodeId>(0x00A1000000001000ULL + static_cast<std::uint64_t>(i)),
        mac_of(static_cast<std::uint8_t>(0x20 + i)), dummy_digest, kT0 + 200, tokens[i]));
  }
  std::uint32_t overflow = 0;
  CHECK(rig.discovery.begin_member_handshake(kNodeB, mac_of(0x0B), dummy_digest,
                                             kT0 + 200, overflow).code ==
        StatusCode::PeerCapacity);
  for (const std::uint32_t live : tokens) rig.discovery.cancel_member_handshake(live);
  // A start contradicting a bound record is a conflict, not a re-bind.
  Pair pair = Pair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  ScopeDigest carrier_digest{};
  keys::link_carrier_digest(frozen.carrier, carrier_digest);
  CHECK_OK(rig.discovery.begin_member_handshake(kNodeB, pair.b->mac_self, carrier_digest,
                                                kT0 + 300, token));
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0 + 300,
                        HandshakeReason::Initial, token));
  const PumpResult result = pump(*pair.a, *pair.b, frozen, kT0 + 300);
  CHECK(result.established_a);
  CHECK_OK(rig.discovery.complete_handshake(token, result.est_a.proof, kT0 + 800));
  std::uint32_t conflict = 0;
  CHECK(rig.discovery.begin_member_handshake(kNodeB, mac_of(0x0C), carrier_digest,
                                             kT0 + 800, conflict).code ==
        StatusCode::BindingConflict);
}

void test_bank_sink_forwarding() {
  TestBank bank{};
  XorShift rng{0x5EED};
  AeadGcm port{&TestAead::seal, &TestAead::open, nullptr};
  TestBank::LocalView view{};
  view.self = kNodeA;
  view.network = kNet;
  view.gk_epoch = kGk;
  CHECK_OK(bank.configure(view, port, TestBank::RandomSource{&XorShift::fill, &rng}, kT0));
  BankSessionSink<32, 8> sink(bank);
  ContextKeys keys{};
  keys.scope = SecurityScope::Link;
  keys.network = kNet;
  keys.peer = kNodeB;
  keys.tx_context_id = 0x1111;
  keys.rx_context_id = 0x2222;
  InstallAttestation att{};
  att.peer_role = kMemberRoleEndpoint;
  att.created_gk_epoch = kGk;
  CHECK_OK(sink.install_verified(keys, att));
  std::uint32_t id = 0;
  CHECK_OK(sink.allocate_context_id(id));
  CHECK(id != 0 && sink.context_id_live(0x2222) && !sink.context_id_live(id));
}

}  // namespace

void test_dev_link_resume() {
  // Two dev engines complete a PSK-rooted RLRES1 with no member evidence,
  // no EDHOC flight and no resume-store traffic, and the installed keys
  // agree in both directions.
  DevPair pair = DevPair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsDev, kCapsDev);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  const PumpResult result = pump(*pair.a, *pair.b, frozen);
  CHECK(result.established_a && result.established_b);
  CHECK(result.failed_a == StatusCode::Ok && result.failed_b == StatusCode::Ok);
  CHECK(result.est_a.tx_context_id == result.est_b.rx_context_id);
  CHECK(result.est_a.rx_context_id == result.est_b.tx_context_id);
  CHECK(result.est_a.has_proof && result.est_b.has_proof);
  CHECK(pair.a->sink.installs == 1 && pair.b->sink.installs == 1);
  CHECK(roundtrip_ok(*pair.a, *pair.b, result.est_a, result.est_b));
  CHECK(roundtrip_ok(*pair.b, *pair.a, result.est_b, result.est_a));
  CHECK(pair.a->storage.write_calls == 0 && pair.b->storage.write_calls == 0);
  CHECK(pair.a->storage.read_calls == 0 && pair.b->storage.read_calls == 0);
  CHECK(pair.a->membership.local_calls == 0 && pair.b->membership.local_calls == 0);
  // Dev summary shape (P4 §10.1): cert 0, generation 0, created_gk 1.
  SessionBankEntry entry{};
  CHECK_OK(pair.a->bank.export_entry(SecurityScope::Link, kNodeB, entry));
  CHECK(entry.peer_generation == 0 && entry.created_gk == 1);
  CHECK((entry.flags & TestBank::kFlagDevResume) != 0);
  const std::array<std::uint8_t, 8> zero_cert{};
  CHECK(entry.peer_cert_id == zero_cert);
  // The resume wire sizes are unchanged (R1 60 / R2 52 / R3 16).
  CHECK(result.r1_size == rlres1::kR1BaseSize);
  CHECK(result.r2_size == rlres1::kR2Size);
  CHECK(result.r3_size == rlres1::kR3Size);
  CHECK(result.m1_size == 0);  // no EDHOC flight on either side
}

void test_dev_churn_200_no_nvs() {
  // V1-N01 host shape: one initiator runs full exchanges against 200
  // distinct dev peers with zero resume-store reads or writes (#37 — no
  // c/f/r growth). Each peer answers from its own engine: the pair RMS
  // binds both node ids, so one responder cannot stand in for another.
  const keys::Secret psk = dev_psk(0xA5);
  DevSide initiator(kNodeA, kNodeB, mac_of(0x0A), mac_of(0x0B), psk, 0xD1);
  CHECK(initiator.start());
  std::size_t ok = 0;
  MonotonicMs now = kT0;
  for (std::uint32_t i = 0; i < 200; ++i) {
    const NodeId peer = 0x00A1000000010000ULL + i;
    DevSide responder(peer, kNodeA, mac_of(0x0B), mac_of(0x0A), psk, 0xE0 + i);
    CHECK(responder.start());
    // A fresh cookie per round: the seal only covers a ~4 s bucket.
    const FrozenLink frozen = freeze_link(initiator, responder, now, kCapsDev, kCapsDev);
    HandshakeRequest req{};
    req.scope = SecurityScope::Link;
    req.peer = peer;
    req.reason = HandshakeReason::Initial;
    req.mac_i = initiator.mac_self;
    req.mac_r = initiator.mac_peer;
    req.carrier = frozen.carrier;
    CHECK_OK(initiator.engine.request(req, now));
    const PumpResult round = pump(initiator, responder, frozen, now);
    if (round.established_a && round.established_b) ++ok;
    CHECK_OK(initiator.bank.retire_all(peer));
    CHECK_OK(responder.bank.retire_all(kNodeA));
    CHECK(responder.storage.write_calls == 0 && responder.storage.read_calls == 0);
    // Past the 8 s exchange deadline: the initiator's post-Established
    // R3Confirm resend duty ends through the natural poll lifecycle.
    now += 9000;
    CHECK_OK(initiator.engine.poll(now));
  }
  CHECK(ok == 200);
  CHECK(initiator.sink.installs == 200);
  CHECK(initiator.storage.write_calls == 0 && initiator.storage.read_calls == 0);
  CHECK(initiator.membership.local_calls == 0);
  CHECK(initiator.engine.quiescent());
}

void test_dev_end_resume() {
  // Same policy over the routed end scope: no carrier/MAC/cookie, the
  // exchange id rides the envelope, keys agree end to end.
  DevPair pair = DevPair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsDev, kCapsDev);
  HandshakeRequest req{};
  req.scope = SecurityScope::EndToEnd;
  req.peer = kNodeB;
  req.reason = HandshakeReason::Initial;
  CHECK_OK(pair.a->engine.request(req, kT0));
  const PumpResult result = pump(*pair.a, *pair.b, frozen);
  CHECK(result.established_a && result.established_b);
  CHECK(!result.est_a.has_proof && !result.est_b.has_proof);  // end: no discovery proof
  SecurityContext seal_ctx{};
  seal_ctx.scope = SecurityScope::EndToEnd;
  seal_ctx.network = kNet;
  seal_ctx.sender = kNodeA;
  seal_ctx.receiver = kNodeB;
  seal_ctx.epoch = result.est_a.tx_context_id;
  std::uint64_t counter = 0;
  CHECK_OK(pair.a->bank.next_counter(seal_ctx, counter));
  const std::uint8_t plain[] = {9, 8, 7};
  std::array<std::uint8_t, 3> cipher{};
  std::array<std::uint8_t, kAeadTagSize> tag{};
  CHECK_OK(pair.a->bank.seal(seal_ctx, counter, ByteView{}, ByteView{plain, 3},
                             MutableByteView{cipher.data(), cipher.size()}, tag));
  SecurityContext open_ctx = seal_ctx;
  open_ctx.epoch = result.est_b.rx_context_id;
  std::array<std::uint8_t, 3> opened{};
  CHECK_OK(pair.b->bank.open(open_ctx, counter, ByteView{},
                             ByteView{cipher.data(), cipher.size()}, tag,
                             MutableByteView{opened.data(), opened.size()}));
  CHECK(opened[0] == 9 && opened[2] == 7);
  CHECK(pair.a->storage.write_calls == 0 && pair.b->storage.write_calls == 0);
}

void test_dev_psk_mismatch_refuses() {
  // Different PSKs derive different RMS: the responder answers at most an
  // unauthenticated hint and the initiator fails WITHOUT an EDHOC
  // fallback (dev has no credentials to fall back to).
  DevPair pair = DevPair::make(dev_psk(0xA5), dev_psk(0x5A));
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsDev, kCapsDev);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  const PumpResult result = pump(*pair.a, *pair.b, frozen);
  CHECK(!result.established_a && !result.established_b);
  CHECK(result.failed_a == StatusCode::AuthenticationFailed);
  CHECK(pair.a->sink.installs == 0 && pair.b->sink.installs == 0);
  CHECK(pair.a->storage.write_calls == 0 && pair.b->storage.write_calls == 0);
  CHECK(result.m1_size == 0);  // the Failed came from RLRES1, not EDHOC
}

void test_dev_unknown_claimant_dropped() {
  // Dev lookup derives the RMS from (PSK, network, self, claimed peer):
  // an R1 without a claimed peer never resolves, never installs.
  DevPair pair = DevPair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsDev, kCapsDev);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  HandshakeResult send{};
  CHECK_OK(pair.a->engine.take_result(send));
  CHECK(send.event == HandshakeEvent::Send && send.phase == 5 && send.step == 1);
  CHECK_OK(pair.a->engine.accept_send(send.token, send.phase, send.step));
  HandshakeRx rx{};
  rx.scope = SecurityScope::Link;
  rx.phase = 5;
  rx.step = 1;
  rx.claimed_peer = kInvalidNodeId;
  rx.src_mac = pair.a->mac_self;
  rx.dst_mac = pair.b->mac_self;
  rx.carrier = frozen.carrier;
  std::array<std::uint8_t, 16> cookie = frozen.cookie;
  rx.cookie = ByteView{cookie.data(), cookie.size()};
  CHECK_OK(pair.b->engine.on_message(
      rx, ByteView{send.message.data(), send.message_size}, kT0 + 50));
  HandshakeResult answer{};
  if (pair.b->engine.take_result(answer).ok()) {
    CHECK(answer.event == HandshakeEvent::Send);  // at most a hint
  }
  CHECK(pair.b->sink.installs == 0);
  CHECK(pair.b->storage.write_calls == 0 && pair.b->storage.read_calls == 0);
}

void test_dev_caps_refused() {
  // Dev link legs need the DevRam bit on BOTH sides and no member bits:
  // any member/dev mix at selection time is Unsupported, never a quiet
  // downgrade to the old protocol.
  DevPair pair = DevPair::make();
  FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsDev, kCapsDev);
  frozen.carrier.capability_r = kCapsFull;
  CHECK(request_link(*pair.a, *pair.b, frozen, kT0).code == StatusCode::Unsupported);
  frozen.carrier.capability_i = kCapsFull;
  frozen.carrier.capability_r = kCapsDev;
  CHECK(request_link(*pair.a, *pair.b, frozen, kT0).code == StatusCode::Unsupported);
  frozen.carrier.capability_i = kCapsDev | kCapsFull;
  frozen.carrier.capability_r = kCapsDev;
  CHECK(request_link(*pair.a, *pair.b, frozen, kT0).code == StatusCode::Unsupported);
  // And a member engine refuses a dev-only peer the same way.
  Pair members = Pair::make();
  const FrozenLink dev_frozen =
      freeze_link(*members.a, *members.b, kT0, kCapsDev, kCapsDev);
  CHECK(request_link(*members.a, *members.b, dev_frozen, kT0).code ==
        StatusCode::Unsupported);
}

void test_dev_responder_caps_refused() {
  // A direct R1 may arrive without a local request(). Construct an R1
  // under the malformed carrier itself so its MAC remains valid: a
  // binding mismatch alone must not mask a missing responder caps gate.
  struct R1Env final : rlres1::Environment {
    std::uint8_t nonce{1};
    bool random(MutableByteView out) noexcept override {
      for (std::size_t i = 0; i < out.size; ++i) out.data[i] = nonce++;
      return true;
    }
    bool find_slot(keys::Purpose, const keys::ResumeId&, rlres1::Slot&) noexcept override {
      return false;
    }
    bool revoked(NodeId, std::uint32_t) noexcept override { return false; }
    bool allocate_context_id(keys::Purpose, NodeId, std::uint32_t& id) noexcept override {
      id = 0xCAFE;
      return true;
    }
    bool reserve_resume_use(keys::Purpose, const keys::ResumeId&) noexcept override {
      return true;
    }
  };
  constexpr std::array<std::uint32_t, 3> bad_caps{
      kCapsFull, kCapsDev | kCapsFull, 0};
  for (const auto caps : bad_caps) {
    DevPair pair = DevPair::make();
    const FrozenLink bad = freeze_link(*pair.a, *pair.b, kT0, caps, kCapsDev);
    R1Env env;
    rlres1::Engine raw;
    rlres1::Local local{};
    local.self = kNodeA;
    local.network = kNet;
    local.epochs.site_epoch = static_cast<std::uint32_t>(kNet >> 32);
    local.epochs.gk_epoch = 1;
    CHECK_OK(raw.configure(local, rlres1::Limits{}));
    rlres1::BeginRequest begin{};
    begin.slot.purpose = keys::Purpose::Link;
    begin.slot.peer = kNodeB;
    begin.slot.network = kNet;
    begin.slot.created_gk_epoch = 1;
    CHECK_OK(keys::dev_pair_rms(pair.a->policy.psk, kNet, kNodeA, kNodeB,
                                keys::Purpose::Link, begin.slot.secret));
    begin.carrier.kind = rlres1::Carrier::Kind::Link;
    begin.carrier.mac_i = pair.a->mac_self;
    begin.carrier.mac_r = pair.b->mac_self;
    keys::link_carrier_digest(bad.carrier, begin.carrier.carrier_digest);
    rlres1::Output r1{};
    raw.begin(begin, kT0, env, r1);
    CHECK(r1.action == rlres1::Action::Send);
    HandshakeRx rx{};
    rx.scope = SecurityScope::Link;
    rx.phase = 5;
    rx.step = 1;
    rx.claimed_peer = kNodeA;
    rx.src_mac = pair.a->mac_self;
    rx.dst_mac = pair.b->mac_self;
    rx.carrier = bad.carrier;
    rx.cookie = ByteView{bad.cookie.data(), bad.cookie.size()};
    CHECK_OK(pair.b->engine.on_message(
        rx, ByteView{r1.message.data(), r1.message_size}, kT0 + 50));
    HandshakeResult answer{};
    CHECK(pair.b->engine.take_result(answer).code == StatusCode::NotFound);
    CHECK(pair.b->engine.quiescent());
    CHECK(pair.b->sink.installs == 0);
  }
}

void test_member_responder_caps_refused() {
  // The direct R1 path must check the member hint pair even when its MAC
  // verifies under an existing RLP slot.
  struct R1Env final : rlres1::Environment {
    std::uint8_t nonce{1};
    bool random(MutableByteView out) noexcept override {
      for (std::size_t i = 0; i < out.size; ++i) out.data[i] = nonce++;
      return true;
    }
    bool find_slot(keys::Purpose, const keys::ResumeId&, rlres1::Slot&) noexcept override {
      return false;
    }
    bool revoked(NodeId, std::uint32_t) noexcept override { return false; }
    bool allocate_context_id(keys::Purpose, NodeId, std::uint32_t& id) noexcept override {
      id = 0xCAFE;
      return true;
    }
    bool reserve_resume_use(keys::Purpose, const keys::ResumeId&) noexcept override {
      return true;
    }
  };
  Pair pair = Pair::make();
  const FrozenLink good = freeze_link(*pair.a, *pair.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*pair.a, *pair.b, good, kT0));
  const PumpResult seeded = pump(*pair.a, *pair.b, good);
  CHECK(seeded.established_a && seeded.established_b);
  const bool quiescent_before = pair.b->engine.quiescent();
  ResumeSlot2 slot{};
  CHECK(slot_for(*pair.a, kNodeB, slot));
  const FrozenLink bad = freeze_link(*pair.a, *pair.b, kT0 + 500,
                                     kCapsFull | kCapsDev, kCapsFull);
  R1Env env;
  rlres1::Engine raw;
  rlres1::Local local{};
  local.self = kNodeA;
  local.network = kNet;
  local.site_id = sdkv1_test::kSiteId;
  local.epochs.site_epoch = kSiteEpoch;
  local.epochs.rs_epoch = kRs;
  local.epochs.gk_epoch = kGk;
  CHECK_OK(raw.configure(local, rlres1::Limits{}));
  rlres1::BeginRequest begin{};
  begin.slot.purpose = keys::Purpose::Link;
  begin.slot.peer = kNodeB;
  begin.slot.network = kNet;
  begin.slot.created_gk_epoch = slot.created_gk_epoch;
  begin.slot.peer_generation = slot.peer_generation;
  begin.slot.secret = slot.rms;
  begin.carrier.kind = rlres1::Carrier::Kind::Link;
  begin.carrier.mac_i = pair.a->mac_self;
  begin.carrier.mac_r = pair.b->mac_self;
  keys::link_carrier_digest(bad.carrier, begin.carrier.carrier_digest);
  rlres1::Output r1{};
  raw.begin(begin, kT0 + 500, env, r1);
  CHECK(r1.action == rlres1::Action::Send);
  HandshakeRx rx{};
  rx.scope = SecurityScope::Link;
  rx.phase = 5;
  rx.step = 1;
  rx.claimed_peer = kNodeA;
  rx.src_mac = pair.a->mac_self;
  rx.dst_mac = pair.b->mac_self;
  rx.carrier = bad.carrier;
  rx.cookie = ByteView{bad.cookie.data(), bad.cookie.size()};
  CHECK_OK(pair.b->engine.on_message(
      rx, ByteView{r1.message.data(), r1.message_size}, kT0 + 550));
  HandshakeResult answer{};
  CHECK(pair.b->engine.take_result(answer).code == StatusCode::NotFound);
  CHECK(pair.b->engine.quiescent() == quiescent_before);
}

void test_member_dev_mutual_refusal() {
  // V1-K10 host shape: a member initiator and a dev responder (and back)
  // never establish — neither side installs, and neither side answers in
  // the other's protocol.
  Pair members = Pair::make();
  DevPair devs = DevPair::make();
  // Member EDHOC m1 into a dev responder: the cookie (a DoS gate, not an
  // auth proof) verifies, then the m1 dies silently — no m2, no install.
  const FrozenLink m_frozen = freeze_link(*members.a, *devs.b, kT0, kCapsFull, kCapsFull);
  CHECK_OK(request_link(*members.a, *devs.b, m_frozen, kT0));
  const PumpResult m_result = pump(*members.a, *devs.b, m_frozen);
  CHECK(!m_result.established_a && !m_result.established_b);
  CHECK(m_result.m1_size != 0);  // the member really attempted EDHOC
  CHECK(m_result.m2_size == 0 && m_result.r2_size == 0);
  CHECK(members.a->sink.installs == 0 && devs.b->sink.installs == 0);
  // Dev R1 into a member responder: at most an unauthenticated hint, and
  // the dev initiator fails instead of falling back to EDHOC.
  const FrozenLink d_frozen = freeze_link(*devs.a, *members.b, kT0, kCapsDev, kCapsDev);
  CHECK_OK(request_link(*devs.a, *members.b, d_frozen, kT0));
  const PumpResult d_result = pump(*devs.a, *members.b, d_frozen);
  CHECK(!d_result.established_a && !d_result.established_b);
  CHECK(d_result.failed_a == StatusCode::Ok);
  CHECK_OK(devs.a->engine.poll(kT0 + 9000));
  HandshakeResult dev_timeout{};
  CHECK_OK(devs.a->engine.take_result(dev_timeout));
  CHECK(dev_timeout.event == HandshakeEvent::Failed &&
        dev_timeout.failure == StatusCode::AuthenticationFailed);
  CHECK(d_result.m1_size == 0 && d_result.r3_size == 0);
  CHECK(devs.a->sink.installs == 0 && members.b->sink.installs == 0);
  CHECK(members.b->engine.quiescent());  // the hint left no responder state
  CHECK(devs.a->storage.write_calls == 0 && members.b->storage.write_calls == 0);
}

void test_dev_revoked_peer_refuses() {
  // The local revocation gate runs before the install even with the right
  // PSK: a revoked initiator gets at most a hint, never a session.
  DevPair pair = DevPair::make();
  pair.b->membership.revoked_peers.insert(kNodeA);
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsDev, kCapsDev);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  const PumpResult result = pump(*pair.a, *pair.b, frozen);
  CHECK(!result.established_a && !result.established_b);
  CHECK(result.failed_a == StatusCode::AuthenticationFailed);
  CHECK(pair.a->sink.installs == 0 && pair.b->sink.installs == 0);
  CHECK(pair.a->storage.write_calls == 0 && pair.b->storage.write_calls == 0);
}

void test_dev_configure_busy_while_in_flight() {
  // Re-arming the policy mid-exchange is refused; once the exchange is
  // done and drained it is accepted again.
  DevPair pair = DevPair::make();
  const FrozenLink frozen = freeze_link(*pair.a, *pair.b, kT0, kCapsDev, kCapsDev);
  CHECK_OK(request_link(*pair.a, *pair.b, frozen, kT0));
  CHECK(pair.a->engine.configure_dev(pair.a->policy, kT0 + 50).code == StatusCode::Busy);
  const PumpResult result = pump(*pair.a, *pair.b, frozen);
  CHECK(result.established_a && result.established_b);
  // Past the 8 s exchange deadline: the post-Established R3Confirm duty
  // ends, the engine drains quiescent, and re-arming is accepted again.
  CHECK_OK(pair.a->engine.poll(kT0 + 9000));
  CHECK_OK(pair.a->engine.configure_dev(pair.a->policy, kT0 + 9000));
}

int main() {
  test_link_edhoc_full();
  test_responder_waits_for_m4_admission();
  test_resume_after_edhoc();
  test_gateway_resume_lookup_budget();
  test_routed_end_exchange();
  test_resume_slot_replaced_before_commit();
  test_pending_send_invalidated_by_membership_loss();
  test_local_epoch_floor_survives_reconfiguration();
  test_local_change_during_commit_cancels_result();
  test_reconfigure_does_not_reuse_exchange_token();
  test_cookie_reject();
  test_binding_reject();
  test_caps_unsupported();
  test_resume_skipped_without_bit25();
  test_reentry_busy();
  test_cancel_and_timeout();
  test_simultaneous_open();
  test_min_gk_birthday();
  test_revoke_before_commit();
  test_unknown_claimant_cannot_complete();
  test_elevation();
  test_elevation_negatives();
  test_bank_sink_forwarding();
  test_dev_link_resume();
  test_dev_churn_200_no_nvs();
  test_dev_end_resume();
  test_dev_psk_mismatch_refuses();
  test_dev_unknown_claimant_dropped();
  test_dev_caps_refused();
  test_dev_responder_caps_refused();
  test_member_responder_caps_refused();
  test_member_dev_mutual_refusal();
  test_dev_revoked_peer_refuses();
  test_dev_configure_busy_while_in_flight();
  if (failures == 0) {
    std::printf("sdkv1 handshake: all scenarios pass\n");
    return 0;
  }
  std::fprintf(stderr, "sdkv1 handshake: %d failures\n", failures);
  return 1;
}
