// RLRES1 resume state machine + attack suite (docs/design/sdk-v1/06-fast-rejoin.md
// §2, plan P1-5, acceptance V1-F02). Two standalone Engines talk through the
// test; every attack must be refused with its specific Reject reason and must
// never install a context. The clock is injected (`now` on every call).

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"

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

namespace keys = routeloom::keys;
using namespace routeloom::rlres1;  // NOLINT: test-local brevity
using routeloom::ByteView;
using routeloom::MutableByteView;
using routeloom::NodeId;
using Bytes = std::vector<std::uint8_t>;

constexpr NodeId kA = 0x101;
constexpr NodeId kB = 0x102;
constexpr NodeId kC = 0x103;
constexpr std::uint64_t kSite = 0x5100000000000042ull;
constexpr std::uint64_t kNetwork = (std::uint64_t{7} << 32) | 0x0A0B0C0Du;
constexpr std::uint64_t kOtherNetwork = (std::uint64_t{7} << 32) | 0x0E0E0E0Eu;

keys::Secret secret(std::uint8_t seed) {
  keys::Secret s{};
  for (std::size_t i = 0; i < s.size(); ++i) s[i] = static_cast<std::uint8_t>(seed + 7 * i);
  return s;
}

struct TestEnv final : Environment {
  std::uint64_t rng{0x9E3779B97F4A7C15ull};
  std::uint32_t next_cid{0x1000};
  bool entropy_ok{true};
  bool cid_ok{true};
  std::vector<Slot> slots;
  std::vector<std::pair<NodeId, std::uint32_t>> revoked_list;

  bool random(MutableByteView out) noexcept override {
    if (!entropy_ok) return false;
    for (std::size_t i = 0; i < out.size; ++i) {
      rng ^= rng << 13;
      rng ^= rng >> 7;
      rng ^= rng << 17;
      out.data[i] = static_cast<std::uint8_t>(rng);
    }
    return true;
  }
  bool find_slot(keys::Purpose purpose, const keys::ResumeId& rid, Slot& out) noexcept override {
    for (const auto& s : slots) {
      keys::ResumeId mine{};
      keys::resume_id(s.secret, s.purpose, mine);
      if (s.purpose == purpose && mine == rid) {
        out = s;
        return true;
      }
    }
    return false;
  }
  bool revoked(NodeId peer, std::uint32_t generation) noexcept override {
    for (const auto& r : revoked_list) {
      if (r.first == peer && generation < r.second) return true;
    }
    return false;
  }
  bool allocate_context_id(keys::Purpose, NodeId, std::uint32_t& cid) noexcept override {
    if (!cid_ok) return false;
    cid = next_cid++;
    return true;
  }
  bool reserve_resume_use(keys::Purpose, const keys::ResumeId&) noexcept override {
    ++reserves;
    return reserve_ok;
  }
  bool reserve_ok{true};
  unsigned reserves{0};
};

Carrier link_carrier() {
  Carrier c{};
  c.kind = Carrier::Kind::Link;
  c.mac_i = {0xA0, 0xB1, 0xC2, 0xD3, 0xE4, 0xF5};
  c.mac_r = {0x06, 0x17, 0x28, 0x39, 0x40, 0xAA};
  for (std::size_t i = 0; i < c.carrier_digest.size(); ++i) {
    c.carrier_digest[i] = static_cast<std::uint8_t>(0x77 + i);
  }
  return c;
}

Carrier routed(std::uint8_t hops) {
  Carrier c{};
  c.hops = hops;
  return c;
}

Epochs epochs(std::uint32_t rs, std::uint32_t gk) { return Epochs{7, rs, gk}; }

Limits generous() {
  Limits l{};
  l.responder_rate_per_s = 100;
  return l;
}

Bytes bytes(const Output& o) {
  return Bytes(o.message.begin(), o.message.begin() + static_cast<std::ptrdiff_t>(o.message_size));
}
ByteView view(const Bytes& b) { return ByteView{b.data(), b.size()}; }

// One node: engine + environment.
struct Node {
  Engine engine;
  TestEnv env;
  NodeId self;
  explicit Node(NodeId id, Epochs e = epochs(3, 12), Limits l = generous(),
                std::uint64_t network = kNetwork) : self(id) {
    CHECK(engine.configure(Local{id, network, kSite, e}, l).ok());
    env.rng ^= id * 0x100000001B3ull;
  }
};

// Mutual link slot between a and b with the same RMS.
void pair(Node& a, Node& b, keys::Purpose purpose = keys::Purpose::Link,
          std::uint32_t created = 12, std::uint8_t seed = 1) {
  a.env.slots.push_back(Slot{purpose, b.self, kNetwork, created, 1, secret(seed)});
  b.env.slots.push_back(Slot{purpose, a.self, kNetwork, created, 1, secret(seed)});
}

BeginRequest begin_req(const Node& from, NodeId peer, keys::Purpose purpose = keys::Purpose::Link) {
  BeginRequest r{};
  for (const auto& s : from.env.slots) {
    if (s.peer == peer && s.purpose == purpose) r.slot = s;
  }
  r.carrier = purpose == keys::Purpose::Link ? link_carrier() : routed(2);
  return r;
}

struct Transcript {
  Bytes r1, r2, r3;
  Output i_out, r_out;
};

// Full honest handshake a -> b at time t.
Transcript handshake(Node& a, Node& b, std::uint64_t t = 1000,
                     keys::Purpose purpose = keys::Purpose::Link) {
  Transcript tr;
  const Carrier carrier = purpose == keys::Purpose::Link ? link_carrier() : routed(2);
  Output o;
  a.engine.begin(begin_req(a, b.self, purpose), t, a.env, o);
  CHECK(o.action == Action::Send);
  tr.r1 = bytes(o);
  b.engine.on_r1(view(tr.r1), carrier, a.self, t + 5, b.env, o);
  CHECK(o.action == Action::Send && o.message_size == kR2Size);
  tr.r2 = bytes(o);
  a.engine.on_r2(b.self, purpose, view(tr.r2), t + 10, tr.i_out);
  CHECK(tr.i_out.action == Action::SendAndInstall);
  tr.r3 = bytes(tr.i_out);
  b.engine.on_r3(a.self, purpose, view(tr.r3), t + 15, tr.r_out);
  CHECK(tr.r_out.action == Action::Install);
  return tr;
}

void test_happy_path() {
  Node a(kA);
  Node b(kB, epochs(4, 13));
  pair(a, b);
  const Transcript tr = handshake(a, b);
  const Established& ei = tr.i_out.established;
  const Established& er = tr.r_out.established;
  CHECK(ei.tx.key == er.rx.key && ei.tx.iv == er.rx.iv);
  CHECK(ei.rx.key == er.tx.key && ei.rx.iv == er.tx.iv);
  CHECK(ei.tx.key != ei.rx.key);
  CHECK(ei.rx_context_id == er.tx_context_id && ei.tx_context_id == er.rx_context_id);
  CHECK(ei.peer == kB && er.peer == kA && ei.role == Role::Initiator && er.role == Role::Responder);
  CHECK(ei.local_rs_behind && !ei.peer_rs_behind);  // b has RRS1 epoch 4 > 3
  CHECK(er.peer_rs_behind && !er.local_rs_behind);
  CHECK(tr.r1.size() == kR1BaseSize && tr.r3.size() == kR3Size);
  CHECK(a.engine.initiator_in_flight() == 0 && b.engine.responder_in_flight() == 0);

  // A second resume with the same RMS yields fresh keys (new nonces).
  const Transcript again = handshake(a, b, 5000);
  CHECK(again.i_out.established.tx.key != ei.tx.key);

  // Routed purpose (E2E) with hops.
  Node c(kC);
  Node d(0x0001);
  pair(c, d, keys::Purpose::End, 12, 9);
  const Transcript e2e = handshake(c, d, 1000, keys::Purpose::End);
  CHECK(e2e.i_out.established.purpose == keys::Purpose::End);
}

// V1-F02: replay of each message never creates a context.
void test_replay() {
  Node a(kA);
  Node b(kB);
  pair(a, b);
  const Transcript tr = handshake(a, b);
  Output o;

  // R1 replay after completion: the bounded replay cache refuses it.
  b.engine.on_r1(view(tr.r1), link_carrier(), kA, 2000, b.env, o);
  CHECK(o.reject == Reject::ReplayedNonce && o.action == Action::None);
  // R2 / R3 replay after completion: no session expects them.
  a.engine.on_r2(kB, keys::Purpose::Link, view(tr.r2), 2000, o);
  CHECK(o.reject == Reject::NoSession && o.action == Action::None);
  b.engine.on_r3(kA, keys::Purpose::Link, view(tr.r3), 2000, o);
  CHECK(o.reject == Reject::NoSession && o.action == Action::None);

  // Old R2 into a fresh initiator session: mac_R covers the new nonce_I.
  a.engine.begin(begin_req(a, kB), 3000, a.env, o);
  const Bytes fresh_r1 = bytes(o);
  a.engine.on_r2(kB, keys::Purpose::Link, view(tr.r2), 3001, o);
  CHECK(o.reject == Reject::BadMac && o.action == Action::Fallback);
  CHECK(a.engine.initiator_in_flight() == 0);

  // Old R3 into a fresh responder session: mac_I3 covers the new TH.
  b.engine.on_r1(view(fresh_r1), link_carrier(), kA, 3002, b.env, o);
  CHECK(o.action == Action::Send);
  b.engine.on_r3(kA, keys::Purpose::Link, view(tr.r3), 3003, o);
  CHECK(o.reject == Reject::BadMac && o.action == Action::None);
  CHECK(b.engine.responder_in_flight() == 0);

  // Captured R1 replayed after the replay cache has rolled over: the
  // responder answers but stays in WAIT_R3 (context NOT active); without the
  // RMS the attacker cannot produce R3, so the session expires unused.
  for (std::size_t i = 0; i < kReplayCacheSize; ++i) {
    const Transcript filler = handshake(a, b, 10000 + 100 * i);
    (void)filler;
  }
  b.engine.on_r1(view(tr.r1), link_carrier(), kA, 20000, b.env, o);
  CHECK(o.action == Action::Send && o.message_size == kR2Size);
  CHECK(b.engine.responder_in_flight() == 1);
  ExpiredSession ex{};
  CHECK(!b.engine.next_expired(21000, ex));
  CHECK(b.engine.next_expired(21001, ex));
  CHECK(ex.role == Role::Responder && ex.peer == kA);
  CHECK(b.engine.responder_in_flight() == 0);
  // ...and a late R3 (any bytes) finds nothing.
  b.engine.on_r3(kA, keys::Purpose::Link, view(tr.r3), 21002, o);
  CHECK(o.reject == Reject::NoSession);
}

// V1-F02: missing R3 -> responder never installs; expires.
void test_missing_r3() {
  Node a(kA);
  Node b(kB);
  pair(a, b);
  Output o;
  a.engine.begin(begin_req(a, kB), 0, a.env, o);
  const Bytes r1 = bytes(o);
  b.engine.on_r1(view(r1), link_carrier(), kA, 10, b.env, o);
  CHECK(o.action == Action::Send);
  CHECK(b.engine.responder_in_flight() == 1);
  b.engine.on_r3(kA, keys::Purpose::Link, ByteView{nullptr, 0}, 1011, o);
  CHECK(o.reject == Reject::Timeout && o.action == Action::None);
  CHECK(b.engine.responder_in_flight() == 0);
  // Initiator times out too and falls back to full EDHOC.
  ExpiredSession ex{};
  CHECK(a.engine.next_expired(1001, ex) && ex.role == Role::Initiator && ex.peer == kB);
}

void test_reflection() {
  Node a(kA);
  Node b(kB);
  pair(a, b);
  Output o;
  a.engine.begin(begin_req(a, kB), 0, a.env, o);
  const Bytes r1 = bytes(o);
  // A's own R1 bounced back to A (A also serves link resumes with the same RMS).
  a.engine.on_r1(view(r1), link_carrier(), kB, 1, a.env, o);
  CHECK(o.reject == Reject::Reflection && o.action == Action::None);
  CHECK(a.engine.responder_in_flight() == 0);
  b.engine.on_r1(view(r1), link_carrier(), kA, 2, b.env, o);
  const Bytes r2 = bytes(o);
  // R2 reflected to its sender: B has no initiator session.
  b.engine.on_r2(kA, keys::Purpose::Link, view(r2), 3, o);
  CHECK(o.reject == Reject::NoSession);
  Output done;
  a.engine.on_r2(kB, keys::Purpose::Link, view(r2), 4, done);
  CHECK(done.action == Action::SendAndInstall);
  // R3 reflected to its sender: A has no responder session.
  a.engine.on_r3(kB, keys::Purpose::Link, view(bytes(done)), 5, o);
  CHECK(o.reject == Reject::NoSession);
}

void test_stale_epochs_and_generation() {
  Output o;
  {  // RMS lifetime: created_gk_epoch + 2 <= gk -> initiator refuses to resume.
    Node a(kA, epochs(3, 14));
    Node b(kB, epochs(3, 14));
    pair(a, b, keys::Purpose::Link, 12);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    CHECK(o.reject == Reject::SlotExpired && o.action == Action::None);
  }
  {  // Responder's view is newer: authenticated R1, then expired hint.
    Node a(kA, epochs(3, 13));
    Node b(kB, epochs(3, 14));
    pair(a, b, keys::Purpose::Link, 12);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::SlotExpired && o.action == Action::Send);
    CHECK(o.message_size == kR2HintSize && o.message[0] == 2);
    const Bytes hint = bytes(o);
    a.engine.on_r2(kB, keys::Purpose::Link, view(hint), 2, o);
    CHECK(o.reject == Reject::UnauthenticatedHint && o.action == Action::Fallback);
  }
  {  // Peer claims a GK epoch older than the RMS itself (rollback / capture).
    Node a(kA, epochs(3, 11));
    Node b(kB, epochs(3, 12));
    pair(a, b, keys::Purpose::Link, 12);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::StaleGkEpoch && o.action == Action::None);
  }
  {  // Peer >= 2 GK epochs ahead: we must pull the GK first.
    Node a(kA, epochs(3, 15));
    Node b(kB, epochs(3, 13));
    pair(a, b, keys::Purpose::Link, 14);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::FutureGkEpoch && o.action == Action::None);
  }
  {  // Stale R2 epochs (authenticated) -> initiator falls back.
    Node a(kA, epochs(3, 13));
    Node b(kB, epochs(3, 13));
    pair(a, b, keys::Purpose::Link, 12);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    const Bytes r2 = bytes(o);
    CHECK(a.engine.update_epochs(epochs(3, 15)).ok());  // a rotated twice meanwhile
    a.engine.on_r2(kB, keys::Purpose::Link, view(r2), 2, o);
    CHECK(o.reject == Reject::StaleGkEpoch && o.action == Action::Fallback);
  }
  {  // RRS1: peer generation revoked.
    Node a(kA);
    Node b(kB);
    pair(a, b);
    a.env.revoked_list.push_back({kB, 2});
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    CHECK(o.reject == Reject::PeerRevoked && o.action == Action::None);
    a.env.revoked_list.clear();
    b.env.revoked_list.push_back({kA, 2});
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::PeerRevoked && o.message_size == kR2HintSize && o.message[0] == 3);
    CHECK(b.engine.responder_in_flight() == 0);
  }
  {  // site_epoch mismatch inside an authentic R1 (peer holding the RMS but on
     // another site epoch): crafted with the primitives.
    Node b(kB);
    const keys::Secret rms = secret(1);
    b.env.slots.push_back(Slot{keys::Purpose::Link, kA, kNetwork, 12, 1, rms});
    R1 m{};
    m.purpose = keys::Purpose::Link;
    keys::resume_id(rms, m.purpose, m.rid);
    m.nonce_i[0] = 0x42;
    m.cid_i = 99;
    m.epochs = Epochs{6, 3, 12};
    std::array<std::uint8_t, kR1MaxSize> buf{};
    std::size_t n = 0;
    CHECK(encode_r1(m, MutableByteView{buf.data(), buf.size()}, n).ok());
    keys::Secret k_auth{};
    CHECK(keys::resume_auth_key(rms, m.purpose, kNetwork, kA, kB, k_auth).ok());
    routeloom::ScopeDigest binding{};
    const Carrier c = link_carrier();
    keys::resume_binding_link(c.mac_i, c.mac_r, c.carrier_digest, binding);
    CHECK(keys::resume_mac(ByteView{k_auth.data(), k_auth.size()}, keys::kLabelResumeR1,
                           ByteView{binding.data(), binding.size()}, ByteView{buf.data(), n - 16},
                           ByteView{}, m.mac)
              .ok());
    std::memcpy(buf.data() + n - 16, m.mac.data(), 16);
    b.engine.on_r1(ByteView{buf.data(), n}, c, kA, 1, b.env, o);
    CHECK(o.reject == Reject::SiteEpochMismatch && o.action == Action::None);
  }
}

void test_wrong_site() {
  Output o;
  {  // A device of the neighbouring site: B has no slot for its rid.
    Node a(kA);
    Node b(kB);
    a.env.slots.push_back(Slot{keys::Purpose::Link, kB, kNetwork, 12, 1, secret(50)});
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::UnknownResumptionId && o.message_size == kR2HintSize &&
          o.message[0] == 1);
    CHECK(b.engine.responder_in_flight() == 0);
  }
  {  // Slot left over from another network (site cutover): refused before MAC.
    Node a(kA);
    Node b(kB);
    pair(a, b);
    b.env.slots.back().network = kOtherNetwork;
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::WrongNetwork && o.action == Action::None);
    Node c(kC);
    c.env.slots.push_back(Slot{keys::Purpose::Link, kB, kOtherNetwork, 12, 1, secret(1)});
    c.engine.begin(begin_req(c, kB), 0, c.env, o);
    CHECK(o.reject == Reject::WrongNetwork);
  }
  {  // Same RMS but the two sides are on different networks: K_auth binds the
     // network, so the MAC cannot verify.
    Node a(kA, epochs(3, 12), generous(), kOtherNetwork);
    Node b(kB);
    a.env.slots.push_back(Slot{keys::Purpose::Link, kB, kOtherNetwork, 12, 1, secret(1)});
    b.env.slots.push_back(Slot{keys::Purpose::Link, kA, kNetwork, 12, 1, secret(1)});
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::BadMac && o.action == Action::None);
  }
  {  // Carrier says the sender is C, the slot belongs to A.
    Node a(kA);
    Node b(kB);
    pair(a, b);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kC, 1, b.env, o);
    CHECK(o.reject == Reject::PeerMismatch && o.action == Action::None);
    // Link binding: a different observed MAC pair breaks mac_I.
    Carrier moved = link_carrier();
    moved.mac_i[5] ^= 1;
    b.engine.on_r1(view(r1), moved, kA, 2, b.env, o);
    CHECK(o.reject == Reject::BadMac);
  }
}

void test_malformed_and_mutation() {
  Node a(kA);
  Node b(kB);
  pair(a, b);
  Output o;
  a.engine.begin(begin_req(a, kB), 0, a.env, o);
  const Bytes r1 = bytes(o);

  Bytes cut(r1.begin(), r1.end() - 1);
  b.engine.on_r1(view(cut), link_carrier(), kA, 1, b.env, o);
  CHECK(o.reject == Reject::Malformed && o.decode == keys::DecodeError::Truncated);
  Bytes big(r1);
  big.resize(200, 0);
  b.engine.on_r1(view(big), link_carrier(), kA, 1, b.env, o);
  CHECK(o.reject == Reject::Malformed && o.decode == keys::DecodeError::Oversized);
  b.engine.on_r1(ByteView{nullptr, 0}, link_carrier(), kA, 1, b.env, o);
  CHECK(o.reject == Reject::Malformed);

  // Any single-bit change anywhere in R1 never yields an authenticated R2.
  for (std::size_t i = 0; i < r1.size(); ++i) {
    for (int bit = 0; bit < 8; bit += 3) {
      Bytes m(r1);
      m[i] ^= static_cast<std::uint8_t>(1u << bit);
      b.engine.on_r1(view(m), link_carrier(), kA, 1, b.env, o);
      CHECK(!(o.action == Action::Send && o.message_size == kR2Size));
      CHECK(o.reject != Reject::None);
    }
  }
  CHECK(b.engine.responder_in_flight() == 0);

  // Genuine R1 -> R2; every single-bit change of R2 ends A's session without keys.
  b.engine.on_r1(view(r1), link_carrier(), kA, 2, b.env, o);
  const Bytes r2 = bytes(o);
  CHECK(r2.size() == kR2Size);
  for (std::size_t i = 0; i < r2.size(); ++i) {
    Node a2(kA);
    Node b2(kB);
    pair(a2, b2);
    Output p;
    a2.engine.begin(begin_req(a2, kB), 0, a2.env, p);
    const Bytes r1b = bytes(p);
    b2.engine.on_r1(view(r1b), link_carrier(), kA, 1, b2.env, p);
    Bytes m = bytes(p);
    m[i] ^= 0x10;
    a2.engine.on_r2(kB, keys::Purpose::Link, view(m), 2, p);
    CHECK(p.action != Action::SendAndInstall);
    CHECK(p.action == Action::Fallback);
    // Every single-bit change of R3 ends B's session without keys.
    Output q;
    a2.engine.begin(begin_req(a2, kB), 10, a2.env, q);
    const Bytes r1c = bytes(q);
    Node b3(kB);
    b3.env.slots = b2.env.slots;
    b3.engine.on_r1(view(r1c), link_carrier(), kA, 11, b3.env, q);
    const Bytes r2c = bytes(q);
    a2.engine.on_r2(kB, keys::Purpose::Link, view(r2c), 12, q);
    CHECK(q.action == Action::SendAndInstall);
    Bytes r3 = bytes(q);
    r3[i % r3.size()] ^= 0x01;
    b3.engine.on_r3(kA, keys::Purpose::Link, view(r3), 13, q);
    CHECK(q.reject == Reject::BadMac && q.action == Action::None);
  }

  {  // Truncated R2 and oversized R3 are Malformed and end the session.
    Node c(kA);
    Node d(kB);
    pair(c, d);
    Output p;
    c.engine.begin(begin_req(c, kB), 0, c.env, p);
    const Bytes r1d = bytes(p);
    d.engine.on_r1(view(r1d), link_carrier(), kA, 1, d.env, p);
    const Bytes r2d = bytes(p);
    Bytes short_r2(r2d.begin(), r2d.begin() + 40);
    c.engine.on_r2(kB, keys::Purpose::Link, view(short_r2), 2, p);
    CHECK(p.reject == Reject::Malformed && p.decode == keys::DecodeError::LengthMismatch &&
          p.action == Action::Fallback);
    Bytes long_r3(17, 0);
    d.engine.on_r3(kA, keys::Purpose::Link, view(long_r3), 3, p);
    CHECK(p.reject == Reject::Malformed && p.decode == keys::DecodeError::Oversized);
    CHECK(d.engine.responder_in_flight() == 0);
  }
}

void test_state_confusion() {
  Node a(kA);
  Node b(kB);
  pair(a, b);
  Output o;
  const Bytes junk_r2(kR2Size, 0);
  // R2 / R3 with no handshake at all.
  a.engine.on_r2(kB, keys::Purpose::Link, view(junk_r2), 0, o);
  CHECK(o.reject == Reject::NoSession);
  b.engine.on_r3(kA, keys::Purpose::Link, view(Bytes(16, 0)), 0, o);
  CHECK(o.reject == Reject::NoSession);

  a.engine.begin(begin_req(a, kB), 0, a.env, o);
  const Bytes r1 = bytes(o);
  // R3 before R2 exists at B.
  b.engine.on_r3(kA, keys::Purpose::Link, view(Bytes(16, 0)), 1, o);
  CHECK(o.reject == Reject::NoSession);
  // R2 for the wrong purpose or wrong peer does not touch the link session.
  a.engine.on_r2(kB, keys::Purpose::End, view(junk_r2), 1, o);
  CHECK(o.reject == Reject::NoSession);
  a.engine.on_r2(kC, keys::Purpose::Link, view(junk_r2), 1, o);
  CHECK(o.reject == Reject::NoSession);
  CHECK(a.engine.initiator_in_flight() == 1);
  // R3-shaped bytes offered as R1.
  b.engine.on_r1(view(Bytes(16, 1)), link_carrier(), kA, 1, b.env, o);
  CHECK(o.reject == Reject::Malformed && o.decode == keys::DecodeError::Truncated);
  // R1 delivered where R2 is expected: the initiator session ends (fallback).
  a.engine.on_r2(kB, keys::Purpose::Link, view(r1), 2, o);
  CHECK(o.reject == Reject::Malformed && o.action == Action::Fallback);
  CHECK(a.engine.initiator_in_flight() == 0);

  // R2 bytes delivered where R3 is expected.
  a.engine.begin(begin_req(a, kB), 10, a.env, o);
  const Bytes r1b = bytes(o);
  b.engine.on_r1(view(r1b), link_carrier(), kA, 11, b.env, o);
  const Bytes r2b = bytes(o);
  b.engine.on_r3(kA, keys::Purpose::Link, view(r2b), 12, o);
  CHECK(o.reject == Reject::Malformed && o.action == Action::None);
  // Duplicate R2 after completion.
  Output done;
  a.engine.on_r2(kB, keys::Purpose::Link, view(r2b), 13, done);
  CHECK(done.action == Action::SendAndInstall);
  a.engine.on_r2(kB, keys::Purpose::Link, view(r2b), 14, o);
  CHECK(o.reject == Reject::NoSession);
}

void test_downgrade() {
  Output o;
  {  // Forged unauthenticated hint: fallback only; the slot stays usable.
    Node a(kA);
    Node b(kB);
    pair(a, b);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    Bytes hint{3, 0, 0, 0};
    hint.insert(hint.end(), r1.begin() + 4, r1.begin() + 12);  // echo the public rid
    a.engine.on_r2(kB, keys::Purpose::Link, view(hint), 1, o);
    CHECK(o.reject == Reject::UnauthenticatedHint && o.action == Action::Fallback);
    const Transcript tr = handshake(a, b, 100);  // slot not invalidated
    CHECK(tr.i_out.action == Action::SendAndInstall);
    // A hint that echoes somebody else's rid.
    a.engine.begin(begin_req(a, kB), 200, a.env, o);
    Bytes other{1, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8};
    a.engine.on_r2(kB, keys::Purpose::Link, view(other), 201, o);
    CHECK(o.reject == Reject::HintMismatch && o.action == Action::Fallback);
  }
  {  // Flags (future features) are refused, not ignored.
    Node a(kA);
    Node b(kB);
    pair(a, b);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    Bytes r1 = bytes(o);
    r1[1] = 0x01;
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::Malformed && o.decode == keys::DecodeError::UnsupportedFlags);
    r1[1] = 0;
    b.engine.on_r1(view(r1), link_carrier(), kA, 2, b.env, o);
    Bytes r2 = bytes(o);
    r2[1] = 0x80;
    a.engine.on_r2(kB, keys::Purpose::Link, view(r2), 3, o);
    CHECK(o.reject == Reject::Malformed && o.decode == keys::DecodeError::UnsupportedFlags &&
          o.action == Action::Fallback);
  }
  {  // Authenticated status-0 R2 cut down to the 12-byte hint length.
    Node a(kA);
    Node b(kB);
    pair(a, b);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    const Bytes r2 = bytes(o);
    a.engine.on_r2(kB, keys::Purpose::Link, view(Bytes(r2.begin(), r2.begin() + 12)), 2, o);
    CHECK(o.reject == Reject::Malformed && o.decode == keys::DecodeError::LengthMismatch);
  }
  {  // Purpose rewrite (link -> end) over a routed carrier: rid is per purpose.
    Node a(kA);
    Node b(kB, epochs(3, 12), [] {
      Limits l = generous();
      l.responder_purposes = (1u << 1) | (1u << 2);
      return l;
    }());
    pair(a, b);
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    Bytes r1 = bytes(o);
    r1[0] = 2;
    b.engine.on_r1(view(r1), routed(1), kA, 1, b.env, o);
    CHECK(o.reject == Reject::UnknownResumptionId);
    // ...and over the link carrier the purpose/carrier mismatch is refused.
    b.engine.on_r1(view(r1), link_carrier(), kA, 2, b.env, o);
    CHECK(o.reject == Reject::PurposeNotServed);
  }
  {  // A device is never an authority / pending-join responder.
    Node a(kA);
    Node b(kB);
    a.env.slots.push_back(Slot{keys::Purpose::Authority, kSite, kNetwork, 0, 1, secret(3)});
    BeginRequest r{};
    r.slot = a.env.slots.back();
    r.carrier = routed(2);
    a.engine.begin(r, 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.engine.on_r1(view(r1), routed(2), kA, 1, b.env, o);
    CHECK(o.reject == Reject::PurposeNotServed);
  }
  {  // Pending-join without its ticket.
    Node a(kA);
    a.env.slots.push_back(Slot{keys::Purpose::PendingJoin, kSite, kNetwork, 0, 0, secret(4)});
    BeginRequest r{};
    r.slot = a.env.slots.back();
    r.carrier = routed(2);
    a.engine.begin(r, 0, a.env, o);
    CHECK(o.reject == Reject::InvalidRequest);
    const std::array<std::uint8_t, 8> ticket{1, 2, 3, 4, 5, 6, 7, 8};
    r.ticket = ByteView{ticket.data(), ticket.size()};
    a.engine.begin(r, 0, a.env, o);
    CHECK(o.action == Action::Send && o.message_size == kR1BaseSize + 1 + 8);
    Bytes stripped = bytes(o);
    stripped.erase(stripped.begin() + 44, stripped.begin() + 53);  // drop len+ticket
    Node host(0x0A0A, epochs(4, 12), [] {
      Limits l = generous();
      l.responder_purposes = 1u << 5;
      return l;
    }());
    host.env.slots.push_back(Slot{keys::Purpose::PendingJoin, kA, kNetwork, 0, 0, secret(4)});
    host.engine.on_r1(view(stripped), routed(2), kA, 1, host.env, o);
    CHECK(o.reject == Reject::Malformed && o.decode == keys::DecodeError::LengthMismatch);
  }
}

void test_exhaustion() {
  Output o;
  {  // Initiator table: bounded, never evicts, duplicates refused.
    Node a(kA);
    for (NodeId id = 0x200; id < 0x200 + kMaxInitiatorSessions + 1; ++id) {
      a.env.slots.push_back(Slot{keys::Purpose::Link, id, kNetwork, 12, 1, secret(static_cast<std::uint8_t>(id))});
    }
    for (std::size_t i = 0; i < kMaxInitiatorSessions; ++i) {
      a.engine.begin(begin_req(a, 0x200 + i), 0, a.env, o);
      CHECK(o.action == Action::Send);
    }
    a.engine.begin(begin_req(a, 0x200), 0, a.env, o);
    CHECK(o.reject == Reject::DuplicateSession);
    a.engine.begin(begin_req(a, 0x200 + kMaxInitiatorSessions), 0, a.env, o);
    CHECK(o.reject == Reject::TableFull);
    CHECK(a.engine.initiator_in_flight() == kMaxInitiatorSessions);
    ExpiredSession ex{};
    std::size_t expired = 0;
    while (a.engine.next_expired(5000, ex)) ++expired;
    CHECK(expired == kMaxInitiatorSessions);
    a.engine.begin(begin_req(a, 0x200 + kMaxInitiatorSessions), 5000, a.env, o);
    CHECK(o.action == Action::Send);
  }
  {  // Configured lower bound.
    Limits l = generous();
    l.max_initiator = 1;
    Node a(kA, epochs(3, 12), l);
    a.env.slots.push_back(Slot{keys::Purpose::Link, kB, kNetwork, 12, 1, secret(1)});
    a.env.slots.push_back(Slot{keys::Purpose::Link, kC, kNetwork, 12, 1, secret(2)});
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    a.engine.begin(begin_req(a, kC), 0, a.env, o);
    CHECK(o.reject == Reject::TableFull);
  }
  {  // Responder table: kMaxResponderSessions concurrent, then TableFull.
    Node b(kB);
    std::vector<Bytes> r1s;
    for (NodeId id = 0x300; id < 0x300 + kMaxResponderSessions + 1; ++id) {
      Node a(id);
      pair(a, b, keys::Purpose::Link, 12, static_cast<std::uint8_t>(id));
      a.engine.begin(begin_req(a, kB), 0, a.env, o);
      r1s.push_back(bytes(o));
    }
    for (std::size_t i = 0; i < kMaxResponderSessions; ++i) {
      b.engine.on_r1(view(r1s[i]), link_carrier(), 0x300 + i, 1, b.env, o);
      CHECK(o.action == Action::Send);
    }
    b.engine.on_r1(view(r1s.back()), link_carrier(), 0x300 + kMaxResponderSessions, 1, b.env, o);
    CHECK(o.reject == Reject::TableFull && o.action == Action::None);
    CHECK(b.engine.responder_in_flight() == kMaxResponderSessions);
  }
  {  // Admission rate: 1/s, burst 1.
    Limits l{};
    l.responder_rate_per_s = 1;
    l.responder_burst = 1;
    Node b(kB, epochs(3, 12), l);
    Node a1(0x401);
    Node a2(0x402);
    pair(a1, b, keys::Purpose::Link, 12, 11);
    pair(a2, b, keys::Purpose::Link, 12, 12);
    a1.engine.begin(begin_req(a1, kB), 0, a1.env, o);
    const Bytes r1a = bytes(o);
    a2.engine.begin(begin_req(a2, kB), 0, a2.env, o);
    const Bytes r1b = bytes(o);
    b.engine.on_r1(view(r1a), link_carrier(), 0x401, 100, b.env, o);
    CHECK(o.action == Action::Send);
    b.engine.on_r1(view(r1b), link_carrier(), 0x402, 600, b.env, o);
    CHECK(o.reject == Reject::RateLimited && o.action == Action::None);
    // The refused R1 is still in the replay cache: a fresh one is needed.
    a2.engine.abort(Role::Initiator, kB, keys::Purpose::Link);
    a2.engine.begin(begin_req(a2, kB), 1100, a2.env, o);
    const Bytes r1c = bytes(o);
    b.engine.on_r1(view(r1c), link_carrier(), 0x402, 1100, b.env, o);
    CHECK(o.action == Action::Send);
  }
  {  // Entropy / context-id unavailability fails closed.
    Node a(kA);
    Node b(kB);
    pair(a, b);
    a.env.entropy_ok = false;
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    CHECK(o.reject == Reject::EntropyUnavailable && a.engine.initiator_in_flight() == 0);
    a.env.entropy_ok = true;
    a.env.cid_ok = false;
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    CHECK(o.reject == Reject::ContextIdUnavailable && a.engine.initiator_in_flight() == 0);
    a.env.cid_ok = true;
    a.engine.begin(begin_req(a, kB), 0, a.env, o);
    const Bytes r1 = bytes(o);
    b.env.entropy_ok = false;
    b.engine.on_r1(view(r1), link_carrier(), kA, 1, b.env, o);
    CHECK(o.reject == Reject::EntropyUnavailable && b.engine.responder_in_flight() == 0);
  }
}

void test_timeouts() {
  Node a(kA);
  Node b(kB);
  pair(a, b, keys::Purpose::End, 12, 5);
  Output o;
  BeginRequest r = begin_req(a, kB, keys::Purpose::End);
  r.carrier = routed(3);  // deadline = 1000 + 3 x 300 ms
  a.engine.begin(r, 0, a.env, o);
  const Bytes r1 = bytes(o);
  b.engine.on_r1(view(r1), routed(3), kA, 100, b.env, o);
  const Bytes r2 = bytes(o);
  a.engine.on_r2(kB, keys::Purpose::End, view(r2), 1901, o);
  CHECK(o.reject == Reject::Timeout && o.action == Action::Fallback);

  a.engine.begin(r, 5000, a.env, o);
  const Bytes r1b = bytes(o);
  Node b2(kB);
  b2.env.slots = b.env.slots;
  b2.engine.on_r1(view(r1b), routed(3), kA, 5000, b2.env, o);
  const Bytes r2b = bytes(o);
  a.engine.on_r2(kB, keys::Purpose::End, view(r2b), 6900, o);  // exactly at the deadline
  CHECK(o.action == Action::SendAndInstall);
  const Bytes r3 = bytes(o);
  b2.engine.on_r3(kA, keys::Purpose::End, view(r3), 6901, o);
  CHECK(o.reject == Reject::Timeout && o.action == Action::None);
}

void test_simultaneous_open() {
  Node a(kA);
  Node b(kB);
  pair(a, b);
  Output o;
  a.engine.begin(begin_req(a, kB), 0, a.env, o);
  const Bytes r1a = bytes(o);
  b.engine.begin(begin_req(b, kA), 0, b.env, o);
  const Bytes r1b = bytes(o);
  // A (lower id) keeps its attempt and refuses B's.
  a.engine.on_r1(view(r1b), link_carrier(), kB, 1, a.env, o);
  CHECK(o.reject == Reject::SimultaneousOpen && o.action == Action::None);
  // B yields: answers A and drops its own initiator session.
  b.engine.on_r1(view(r1a), link_carrier(), kA, 1, b.env, o);
  CHECK(o.action == Action::Send && o.superseded_initiator);
  CHECK(b.engine.initiator_in_flight() == 0);
  const Bytes r2 = bytes(o);
  a.engine.on_r2(kB, keys::Purpose::Link, view(r2), 2, o);
  CHECK(o.action == Action::SendAndInstall);
  const Bytes r3 = bytes(o);
  b.engine.on_r3(kA, keys::Purpose::Link, view(r3), 3, o);
  CHECK(o.action == Action::Install);
}

void test_authority_and_pending() {
  // Device -> Site Authority over DAMS (purpose 4); node_R is the site_id.
  Node dev(kA, epochs(2, 10));
  Limits host_limits = generous();
  host_limits.responder_purposes = (1u << 4) | (1u << 5);
  Node host(0x0A0A, epochs(4, 12), host_limits);
  dev.env.slots.push_back(Slot{keys::Purpose::Authority, kSite, kNetwork, 0, 1, secret(3)});
  host.env.slots.push_back(Slot{keys::Purpose::Authority, kA, kNetwork, 0, 1, secret(3)});
  Output o;
  BeginRequest r{};
  r.slot = dev.env.slots.back();
  r.carrier = routed(4);
  dev.engine.begin(r, 0, dev.env, o);
  CHECK(o.action == Action::Send);
  const Bytes r1 = bytes(o);
  // A stale GK is exactly why a device calls the authority: not refused.
  host.engine.on_r1(view(r1), routed(4), kA, 1, host.env, o);
  CHECK(o.action == Action::Send);
  const Bytes r2 = bytes(o);
  Output di;
  dev.engine.on_r2(kSite, keys::Purpose::Authority, view(r2), 2, di);
  CHECK(di.action == Action::SendAndInstall && di.established.local_rs_behind);
  Output hi;
  host.engine.on_r3(kA, keys::Purpose::Authority, view(bytes(di)), 3, hi);
  CHECK(hi.action == Action::Install);
  CHECK(hi.established.rx.key == di.established.tx.key);
  // The device refuses an authority slot that names another site.
  r.slot.peer = kSite + 1;
  dev.engine.begin(r, 10, dev.env, o);
  CHECK(o.reject == Reject::PeerMismatch);
}

void test_configuration_and_counters() {
  Engine e;
  Output o;
  TestEnv env;
  e.begin(BeginRequest{}, 0, env, o);
  CHECK(o.reject == Reject::InvalidRequest);
  // site_epoch must match the network's upper 32 bits.
  CHECK(!e.configure(Local{kA, kNetwork, kSite, Epochs{6, 0, 0}}, Limits{}).ok());
  Limits bad{};
  bad.max_responder = kMaxResponderSessions + 1;
  CHECK(!e.configure(Local{kA, kNetwork, kSite, epochs(0, 0)}, bad).ok());
  CHECK(e.configure(Local{kA, kNetwork, kSite, epochs(0, 0)}, Limits{}).ok());
  CHECK(!e.update_epochs(Epochs{8, 0, 0}).ok());
  CHECK(e.update_epochs(epochs(1, 1)).ok());

  Node a(kA);
  Node b(kB);
  pair(a, b);
  a.engine.begin(begin_req(a, kB), 0, a.env, o);
  a.engine.abort_peer(kB);
  CHECK(a.engine.initiator_in_flight() == 0);
  a.engine.on_r2(kB, keys::Purpose::Link, view(Bytes(kR2Size, 0)), 1, o);
  CHECK(o.reject == Reject::NoSession);
  CHECK(a.engine.reject_count(Reject::NoSession) == 1);
  CHECK(std::strcmp(reject_name(Reject::ReplayedNonce), "replayed_nonce") == 0);

  // Output::clear zeroizes installed keys.
  const Transcript tr = handshake(a, b, 100);
  Output copy = tr.i_out;
  copy.clear();
  const std::array<std::uint8_t, 16> zero{};
  CHECK(copy.established.tx.key == zero && copy.message_size == 0);
}

void test_sizing() {
  // ESP32-C3 gateway floor (sdk-v1/ram-budget.md, 08 §6 Q8 update): one
  // engine instance is a few KiB and never static.
  std::printf("sizeof(rlres1::Engine) = %zu, sizeof(Output) = %zu\n", sizeof(Engine),
              sizeof(Output));
  CHECK(sizeof(Engine) <= 2304);
  CHECK(sizeof(Output) <= 384);
}

// P4 §6.2: the responder spends one RMS use per verified R1, and a spent
// budget answers Expired (full EDHOC) instead of UnknownId.
void test_reserve_hook() {
  Node a(kA);
  Node b(kB);
  pair(a, b);
  Output o;
  a.engine.begin(begin_req(a, kB), 1000, a.env, o);
  CHECK(o.action == Action::Send);
  const Bytes r1 = bytes(o);
  b.engine.on_r1(view(r1), link_carrier(), kA, 1005, b.env, o);
  CHECK(o.action == Action::Send && o.message_size == kR2Size);
  CHECK(b.env.reserves == 1);
  // A bad MAC never reaches the hook: no slot is verified, no use spent.
  Bytes forged = r1;
  forged[forged.size() - 1] ^= 0xFF;
  b.engine.on_r1(view(forged), link_carrier(), kA, 1006, b.env, o);
  CHECK(o.reject == Reject::BadMac);
  CHECK(b.env.reserves == 1);
  // An exhausted budget answers Expired so the initiator runs a full
  // EDHOC; the slot itself is left alone (no erase on hint).
  b.env.reserve_ok = false;
  a.engine.abort_peer(kB);  // drop the first in-flight attempt on both ends
  b.engine.abort_peer(kA);
  a.engine.begin(begin_req(a, kB), 2000, a.env, o);
  CHECK(o.action == Action::Send);
  const Bytes r1b = bytes(o);
  b.engine.on_r1(view(r1b), link_carrier(), kA, 2005, b.env, o);
  CHECK(o.action == Action::Send && o.message_size == kR2HintSize);
  CHECK(o.reject == Reject::ResumeBudgetExhausted);
  CHECK(o.message[0] == static_cast<std::uint8_t>(R2Status::Expired));
  CHECK(b.env.reserves == 2 && !b.env.slots.empty());
  CHECK(std::strcmp(reject_name(Reject::ResumeBudgetExhausted), "resume_budget_exhausted") == 0);
}

// P4 §6.2: epochs advance monotonically within a site.
void test_epoch_regression() {
  Engine e;
  Output o;
  TestEnv env;
  CHECK(e.configure(Local{kA, kNetwork, kSite, epochs(3, 12)}, Limits{}).ok());
  CHECK(e.update_epochs(epochs(4, 12)).ok());
  CHECK(e.update_epochs(epochs(4, 13)).ok());
  CHECK(!e.update_epochs(epochs(3, 13)).ok());  // RS regressed: refused
  CHECK(!e.update_epochs(epochs(4, 12)).ok());  // GK regressed: refused
  CHECK(!e.update_epochs(Epochs{8, 4, 13}).ok());  // site change: re-configure
}

void test_authority_self_name_collision() {
  // The site id lives in its own namespace: when it numerically equals the
  // device NodeId the authority handshake must still run (G-SEC P5 §4). The
  // pairwise self-handshake refusal is unaffected.
  constexpr NodeId kBoth = 0x42;
  Engine dev;
  TestEnv dev_env;
  CHECK(dev.configure(Local{kBoth, kNetwork, kBoth, epochs(2, 10)}, generous()).ok());
  Engine host;
  TestEnv host_env;
  Limits host_limits = generous();
  host_limits.responder_purposes = (1u << 4);
  CHECK(host.configure(Local{kBoth, kNetwork, kBoth, epochs(4, 12)}, host_limits).ok());
  const Slot dev_slot{keys::Purpose::Authority, kBoth, kNetwork, 0, 1, secret(3)};
  const Slot host_slot{keys::Purpose::Authority, kBoth, kNetwork, 0, 1, secret(3)};
  Output o;
  BeginRequest r{};
  r.slot = dev_slot;
  r.carrier = routed(4);
  dev.begin(r, 0, dev_env, o);
  CHECK(o.action == Action::Send);  // peer == site id == self: allowed
  const Bytes r1 = bytes(o);
  host_env.slots.push_back(host_slot);
  host.on_r1(view(r1), routed(4), kBoth, 1, host_env, o);
  CHECK(o.action == Action::Send && o.message_size == kR2Size);
  const Bytes r2 = bytes(o);
  Output di;
  dev.on_r2(kBoth, keys::Purpose::Authority, view(r2), 2, di);
  CHECK(di.action == Action::SendAndInstall);
  Output hi;
  host.on_r3(kBoth, keys::Purpose::Authority, view(bytes(di)), 3, hi);
  CHECK(hi.action == Action::Install);
  CHECK(hi.established.rx.key == di.established.tx.key);

  // Pairwise still refuses a handshake with itself.
  Node n(kA);
  n.env.slots.push_back(Slot{keys::Purpose::Link, kA, kNetwork, 12, 1, secret(9)});
  n.engine.begin(begin_req(n, kA), 10, n.env, o);
  CHECK(o.reject == Reject::InvalidRequest);
}

void test_clock_ceiling_overflow() {
  // Deadlines saturate instead of wrapping near UINT64_MAX, and the
  // responder token bucket refills instead of starving on a wrapped
  // elapsed*rate product.
  Node a(kA);
  Node b(kB);
  pair(a, b);
  Output o;
  constexpr routeloom::MonotonicMs kNearMax = UINT64_MAX - 10;
  a.engine.begin(begin_req(a, kB), kNearMax, a.env, o);
  CHECK(o.action == Action::Send);
  ExpiredSession expired{};
  CHECK(!a.engine.next_expired(UINT64_MAX, expired));
  CHECK(a.engine.initiator_in_flight() == 1);

  Limits throttled{};
  throttled.responder_rate_per_s = 32768;  // 2^15: elapsed 2^49 * rate == 2^64
  throttled.responder_burst = 1;
  Node c(kA);
  Node d(kB, epochs(3, 12), throttled);
  pair(c, d, keys::Purpose::End);
  c.engine.begin(begin_req(c, kB, keys::Purpose::End), 100, c.env, o);
  CHECK(o.action == Action::Send);
  const Bytes r1a = bytes(o);
  c.engine.abort(Role::Initiator, kB, keys::Purpose::End);
  d.engine.on_r1(view(r1a), routed(2), kA, 100, d.env, o);
  CHECK(o.action == Action::Send);  // consumes the single token
  d.engine.abort(Role::Responder, kA, keys::Purpose::End);
  c.engine.begin(begin_req(c, kB, keys::Purpose::End), 100, c.env, o);
  CHECK(o.action == Action::Send);
  const Bytes r1b = bytes(o);
  c.engine.abort(Role::Initiator, kB, keys::Purpose::End);
  d.engine.on_r1(view(r1b), routed(2), kA, 100, d.env, o);
  CHECK(o.reject == Reject::RateLimited);  // no time passed: empty bucket
  d.engine.abort(Role::Responder, kA, keys::Purpose::End);
  c.engine.begin(begin_req(c, kB, keys::Purpose::End), 100, c.env, o);
  CHECK(o.action == Action::Send);
  const Bytes r1c = bytes(o);
  c.engine.abort(Role::Initiator, kB, keys::Purpose::End);
  constexpr routeloom::MonotonicMs kWrap =
      100 + (std::uint64_t{1} << 49);  // elapsed*rate wraps to exactly 0
  d.engine.on_r1(view(r1c), routed(2), kA, kWrap, d.env, o);
  CHECK(o.action == Action::Send);  // refilled, not starved
}

}  // namespace

int main() {
  test_happy_path();
  test_replay();
  test_missing_r3();
  test_reflection();
  test_stale_epochs_and_generation();
  test_wrong_site();
  test_malformed_and_mutation();
  test_state_confusion();
  test_downgrade();
  test_exhaustion();
  test_timeouts();
  test_simultaneous_open();
  test_authority_and_pending();
  test_authority_self_name_collision();
  test_clock_ceiling_overflow();
  test_configuration_and_counters();
  test_reserve_hook();
  test_epoch_regression();
  test_sizing();
  if (failures != 0) {
    std::fprintf(stderr, "%d RLRES1 check(s) failed\n", failures);
    return 1;
  }
  std::printf("RLRES1 state machine + attack suite: all passed\n");
  return 0;
}
