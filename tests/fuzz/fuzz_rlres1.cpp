// Fuzz target: RLRES1 resume handshake (components/routeloom/src/rlres1.cpp,
// docs/design/sdk-v1/06-fast-rejoin.md §2, plan P1-5).
//
// The first byte selects a mode; the rest drives it:
//   0  codecs: decode R1/R2/R3/AuthorityEnvelope; an accepted input must
//      re-encode to exactly the same bytes (canonical, no slack).
//   1  raw R1 into a responder that holds the genuine slot.
//   2  raw R2 into an initiator waiting on its genuine R1.
//   3  raw R3 into a responder waiting in WAIT_R3.
//   4/5/6  mutation of the genuine R1/R2/R3: payload = length tweak, then
//          (offset, xor) pairs.
//   7  op script over two engines (begin / deliver / mutate / clock / abort).
// Invariants (abort on violation): an authenticated R2 / installed context
// only ever results from the byte-exact genuine message; a responder only
// installs keys its initiator derived; session tables never exceed their
// bounds. Deterministic: every input rebuilds both engines from fixed seeds.

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>

#include "routeloom/key_schedule.hpp"
#include "routeloom/rlres1.hpp"

#include "fuzz_driver.hpp"

namespace {

namespace keys = routeloom::keys;
namespace rl = routeloom::rlres1;
using routeloom::ByteView;
using routeloom::MutableByteView;
using routeloom::NodeId;

constexpr NodeId kA = 0x101;
constexpr NodeId kB = 0x102;
constexpr std::uint64_t kSite = 0x5100000000000042ull;
constexpr std::uint64_t kNetwork = (std::uint64_t{7} << 32) | 0x0A0B0C0Du;

struct Env final : rl::Environment {
  std::uint64_t rng;
  std::uint32_t cid;
  NodeId peer;
  keys::Secret rms{};
  explicit Env(std::uint64_t seed, NodeId p) : rng(seed), cid(static_cast<std::uint32_t>(seed) | 1u), peer(p) {
    for (std::size_t i = 0; i < rms.size(); ++i) rms[i] = static_cast<std::uint8_t>(1 + 17 * i);
  }
  bool random(MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) {
      rng ^= rng << 13;
      rng ^= rng >> 7;
      rng ^= rng << 17;
      out.data[i] = static_cast<std::uint8_t>(rng);
    }
    return true;
  }
  bool find_slot(keys::Purpose purpose, const keys::ResumeId& rid, rl::Slot& out) noexcept override {
    keys::ResumeId mine{};
    keys::resume_id(rms, keys::Purpose::Link, mine);
    if (purpose != keys::Purpose::Link || mine != rid) return false;
    out = slot();
    return true;
  }
  bool revoked(NodeId, std::uint32_t) noexcept override { return false; }
  bool allocate_context_id(keys::Purpose, NodeId, std::uint32_t& out) noexcept override {
    out = cid++;
    if (out == 0) out = cid++;
    return true;
  }
  bool reserve_resume_use(keys::Purpose, const keys::ResumeId&) noexcept override { return true; }
  rl::Slot slot() const noexcept { return rl::Slot{keys::Purpose::Link, peer, kNetwork, 12, 1, rms}; }
};

rl::Carrier carrier() {
  rl::Carrier c{};
  c.kind = rl::Carrier::Kind::Link;
  c.mac_i = {1, 2, 3, 4, 5, 6};
  c.mac_r = {7, 8, 9, 10, 11, 12};
  return c;
}

struct Side {
  rl::Engine engine;
  Env env;
  NodeId self;
  Side(NodeId id, NodeId peer) : env(0x9E3779B97F4A7C15ull ^ id, peer), self(id) {
    if (!engine.configure(rl::Local{id, kNetwork, kSite, rl::Epochs{7, 3, 12}}, rl::Limits{}).ok()) {
      std::abort();
    }
  }
  void begin(std::uint64_t now, rl::Output& out) {
    rl::BeginRequest r{};
    r.slot = env.slot();
    r.carrier = carrier();
    engine.begin(r, now, env, out);
  }
  void bounds() const {
    if (engine.initiator_in_flight() > rl::kMaxInitiatorSessions ||
        engine.responder_in_flight() > rl::kMaxResponderSessions) {
      std::abort();
    }
  }
};

bool eq(ByteView a, const std::uint8_t* b, std::size_t n) {
  return a.size == n && (n == 0 || std::memcmp(a.data, b, n) == 0);
}

void codecs(ByteView in) {
  std::array<std::uint8_t, rl::kMaxMessageSize> buf{};
  std::size_t n = 0;
  rl::R1 r1{};
  if (rl::decode_r1(in, r1) == keys::DecodeError::None) {
    if (!rl::encode_r1(r1, MutableByteView{buf.data(), buf.size()}, n).ok() || !eq(in, buf.data(), n)) {
      std::abort();
    }
  }
  rl::R2 r2{};
  if (rl::decode_r2(in, r2) == keys::DecodeError::None) {
    if (!rl::encode_r2(r2, MutableByteView{buf.data(), buf.size()}, n).ok() || !eq(in, buf.data(), n)) {
      std::abort();
    }
  }
  rl::Mac r3{};
  if (rl::decode_r3(in, r3) == keys::DecodeError::None && in.size != rl::kR3Size) std::abort();
  keys::AuthorityEnvelopeHeader h{};
  if (keys::authority_envelope_decode(in, h) == keys::DecodeError::None) {
    std::array<std::uint8_t, keys::kAuthorityEnvelopeHeaderSize> head{};
    if (!keys::authority_envelope_header_encode(h, head).ok() ||
        std::memcmp(head.data(), in.data, head.size()) != 0) {
      std::abort();
    }
  }
}

// Honest transcript up to the requested step; returns the genuine message.
struct Genuine {
  std::array<std::uint8_t, rl::kMaxMessageSize> r1{}, r2{}, r3{};
  std::size_t r1n{0}, r2n{0}, r3n{0};
};

void apply_mask(std::uint8_t* msg, std::size_t& n, ByteView mask) {
  // mask[0] tweaks the length (-4..+4, bounded by the buffer); every following
  // (offset, xor) pair flips bits at one position, so a single mutation
  // reaches any field of the genuine message instead of smearing byte 0.
  if (mask.size == 0) return;
  const int delta = static_cast<int>(mask.data[0] % 9) - 4;
  const long target = static_cast<long>(n) + delta;
  n = static_cast<std::size_t>(std::clamp<long>(target, 0, rl::kMaxMessageSize));
  for (std::size_t i = 1; i + 1 < mask.size && n != 0; i += 2) {
    msg[mask.data[i] % n] ^= mask.data[i + 1];
  }
}

void single(std::uint8_t mode, ByteView payload) {
  Side a(kA, kB);
  Side b(kB, kA);
  rl::Output o;
  Genuine g;
  a.begin(0, o);
  g.r1n = o.message_size;
  std::memcpy(g.r1.data(), o.message.data(), g.r1n);

  if (mode == 1 || mode == 4) {
    std::array<std::uint8_t, rl::kMaxMessageSize> m{};
    std::size_t n = std::min(payload.size, m.size());
    ByteView in = payload;
    if (mode == 4) {
      m = g.r1;
      n = g.r1n;
      apply_mask(m.data(), n, payload);
      in = ByteView{m.data(), n};
    }
    b.engine.on_r1(in, carrier(), kA, 1, b.env, o);
    if (o.action == rl::Action::Send && o.message_size == rl::kR2Size &&
        !eq(in, g.r1.data(), g.r1n)) {
      std::abort();  // authenticated R2 for a forged R1
    }
    b.bounds();
    return;
  }
  b.engine.on_r1(ByteView{g.r1.data(), g.r1n}, carrier(), kA, 1, b.env, o);
  if (o.action != rl::Action::Send || o.message_size != rl::kR2Size) std::abort();
  g.r2n = o.message_size;
  std::memcpy(g.r2.data(), o.message.data(), g.r2n);

  if (mode == 2 || mode == 5) {
    std::array<std::uint8_t, rl::kMaxMessageSize> m{};
    std::size_t n = std::min(payload.size, m.size());
    ByteView in = payload;
    if (mode == 5) {
      m = g.r2;
      n = g.r2n;
      apply_mask(m.data(), n, payload);
      in = ByteView{m.data(), n};
    }
    a.engine.on_r2(kB, keys::Purpose::Link, in, 2, o);
    if (o.action == rl::Action::SendAndInstall && !eq(in, g.r2.data(), g.r2n)) std::abort();
    if (o.action != rl::Action::SendAndInstall && o.action != rl::Action::Fallback) std::abort();
    a.bounds();
    return;
  }
  rl::Output ai;
  a.engine.on_r2(kB, keys::Purpose::Link, ByteView{g.r2.data(), g.r2n}, 2, ai);
  if (ai.action != rl::Action::SendAndInstall) std::abort();
  g.r3n = ai.message_size;
  std::memcpy(g.r3.data(), ai.message.data(), g.r3n);

  std::array<std::uint8_t, rl::kMaxMessageSize> m{};
  std::size_t n = std::min(payload.size, m.size());
  ByteView in = payload;
  if (mode == 6) {
    m = g.r3;
    n = g.r3n;
    apply_mask(m.data(), n, payload);
    in = ByteView{m.data(), n};
  }
  b.engine.on_r3(kA, keys::Purpose::Link, in, 3, o);
  if (o.action == rl::Action::Install) {
    if (!eq(in, g.r3.data(), g.r3n) || o.established.rx.key != ai.established.tx.key) std::abort();
  }
  b.bounds();
}

void script(ByteView p) {
  Side a(kA, kB);
  Side b(kB, kA);
  rl::Output out_a;
  rl::Output out_b;
  rl::Output o;
  std::uint64_t now = 0;
  // Keys either side derived as initiator (bounded list): a responder may
  // only ever install one of them.
  std::array<keys::TrafficKey, 16> a_tx{};
  std::array<keys::TrafficKey, 16> b_tx{};
  std::size_t na = 0;
  std::size_t nb = 0;
  auto remember = [](std::array<keys::TrafficKey, 16>& list, std::size_t& count,
                     const keys::TrafficKey& k) {
    list[count % list.size()] = k;
    ++count;
  };
  auto known = [](const std::array<keys::TrafficKey, 16>& list, std::size_t count,
                  const keys::TrafficKey& k) {
    for (std::size_t i = 0; i < std::min(count, list.size()); ++i) {
      if (list[i].key == k.key && list[i].iv == k.iv) return true;
    }
    return false;
  };
  auto msg = [](const rl::Output& x) { return ByteView{x.message.data(), x.message_size}; };

  std::size_t i = 0;
  while (i < p.size) {
    const std::uint8_t op = p.data[i++];
    const std::uint8_t arg = i < p.size ? p.data[i] : 0;
    switch (op % 12) {
      case 0: a.begin(now, out_a); break;
      case 1: b.begin(now, out_b); break;
      case 2:
        b.engine.on_r1(msg(out_a), carrier(), kA, now, b.env, o);
        if (o.action == rl::Action::Send) out_b = o;
        break;
      case 3:
        a.engine.on_r1(msg(out_b), carrier(), kB, now, a.env, o);
        if (o.action == rl::Action::Send) out_a = o;
        break;
      case 4:
        a.engine.on_r2(kB, keys::Purpose::Link, msg(out_b), now, o);
        if (o.action == rl::Action::SendAndInstall) {
          remember(a_tx, na, o.established.tx);
          out_a = o;
        }
        break;
      case 5:
        b.engine.on_r2(kA, keys::Purpose::Link, msg(out_a), now, o);
        if (o.action == rl::Action::SendAndInstall) {
          remember(b_tx, nb, o.established.tx);
          out_b = o;
        }
        break;
      case 6:
        b.engine.on_r3(kA, keys::Purpose::Link, msg(out_a), now, o);
        // Once the bounded list wrapped the check is skipped, never weakened.
        if (o.action == rl::Action::Install && na <= a_tx.size() &&
            !known(a_tx, na, o.established.rx)) {
          std::abort();
        }
        break;
      case 7:
        a.engine.on_r3(kB, keys::Purpose::Link, msg(out_b), now, o);
        // Once the bounded list wrapped the check is skipped, never weakened.
        if (o.action == rl::Action::Install && nb <= b_tx.size() &&
            !known(b_tx, nb, o.established.rx)) {
          std::abort();
        }
        break;
      case 8: {
        now += static_cast<std::uint64_t>(arg) * 10u;
        ++i;
        rl::ExpiredSession ex{};
        while (a.engine.next_expired(now, ex)) {}
        while (b.engine.next_expired(now, ex)) {}
        break;
      }
      case 9:
        if (out_a.message_size != 0) out_a.message[arg % out_a.message_size] ^= static_cast<std::uint8_t>(arg | 1u);
        ++i;
        break;
      case 10:
        if (out_b.message_size != 0) out_b.message[arg % out_b.message_size] ^= static_cast<std::uint8_t>(arg | 1u);
        ++i;
        break;
      default:
        if (arg & 1u) {
          a.engine.abort_peer(kB);
        } else {
          b.engine.abort_peer(kA);
        }
        ++i;
        break;
    }
    a.bounds();
    b.bounds();
  }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
  if (size == 0) return 0;
  const std::uint8_t mode = static_cast<std::uint8_t>(data[0] % 8);
  const ByteView payload{data + 1, size - 1};
  if (mode == 0) {
    codecs(payload);
  } else if (mode == 7) {
    script(payload);
  } else {
    single(mode, payload);
  }
  return 0;
}

ROUTELOOM_FUZZ_MAIN()
