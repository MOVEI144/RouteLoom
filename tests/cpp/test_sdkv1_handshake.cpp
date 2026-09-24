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
       const std::uint32_t role, const std::uint64_t rng_seed, const std::uint32_t gk_epoch)
      : self(self),
        peer(peer),
        mac_self(mac_self),
        mac_peer(mac_peer),
        cache(storage, kResume2NodeLinkQuota, kResume2NodeEndQuota),
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
  FaultyResumeStorage2 storage{16};
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

FrozenLink freeze_link(Side& initiator, Side& responder, const MonotonicMs now,
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
Status deliver_to(Side& to, const Side& from, const HandshakeResult& send,
                  const FrozenLink& frozen, const MonotonicMs now) {
  HandshakeRx rx{};
  rx.scope = send.scope;
  rx.phase = send.phase;
  rx.step = send.step;
  rx.claimed_peer = from.self;
  rx.src_mac = from.mac_self;  // observed sender/receiver, always
  rx.dst_mac = to.mac_self;
  rx.carrier = frozen.carrier;
  std::array<std::uint8_t, 16> cookie = frozen.cookie;
  if (send.cookie_attach) rx.cookie = ByteView{cookie.data(), cookie.size()};
  return to.engine.on_message(rx, ByteView{send.message.data(), send.message_size}, now);
}

// Runs the exchange to completion: every Send is delivered immediately,
// time advances 50 ms per hop (well inside the cookie bucket and the
// retransmit/timer horizons, so no timer fires mid-exchange).
PumpResult pump(Side& a, Side& b, const FrozenLink& frozen,
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
      CHECK_OK(deliver_to(b, a, send, frozen, now));
    }
    for (const auto& send : sends_b) {
      note_send(send);
      now += 50;
      CHECK_OK(deliver_to(a, b, send, frozen, now));
    }
    if (!progress) break;
  }
  return result;
}

bool roundtrip_ok(Side& from, Side& to, const HandshakeResult& est_from,
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
  static Pair make(const std::uint32_t gk_a = kGk, const std::uint32_t gk_b = kGk) {
    const auto cert_a =
        member_cert_for(kNodeA, sdkv1_test::device_key().pub, kMemberRoleEndpoint, 3);
    const auto cert_b = member_cert_for(kNodeB, sdkv1_test::other_key().pub, kMemberRoleRelay, 1);
    Pair pair;
    pair.a.reset(new Side(kNodeA, kNodeB, mac_of(0x0A), mac_of(0x0B),
                          sdkv1_test::device_key(), cert_a, 3, kMemberRoleEndpoint, 0xA1, gk_a));
    pair.b.reset(new Side(kNodeB, kNodeA, mac_of(0x0B), mac_of(0x0A), sdkv1_test::other_key(),
                          cert_b, 1, kMemberRoleRelay, 0xB2, gk_b));
    CHECK(pair.a->start());
    CHECK(pair.b->start());
    return pair;
  }
};

Status request_link(Side& initiator, Side& responder, const FrozenLink& frozen,
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
  pair.b->membership.change_on_local_call = pair.b->membership.local_calls + 2;
  CHECK_OK(deliver_to(*pair.b, *pair.a, m3, frozen, kT0 + 150));
  HandshakeResult out{};
  CHECK(pair.b->engine.take_result(out).code == StatusCode::NotFound);
  CHECK(out.token == 0 && out.message_size == 0);
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

int main() {
  test_link_edhoc_full();
  test_resume_after_edhoc();
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
  if (failures == 0) {
    std::printf("sdkv1 handshake: all scenarios pass\n");
    return 0;
  }
  std::fprintf(stderr, "sdkv1 handshake: %d failures\n", failures);
  return 1;
}
