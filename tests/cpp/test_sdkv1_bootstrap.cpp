// Routed member-session bootstrap (G-SEC P4 §7.3-§7.4, PR3): the end-object
// envelope edges beyond the golden file, the lane-separated chunk/reply
// sub namespace and slot isolation, the purpose-split responder budgets,
// the session-bank demand driver, and the MeshNode type-3..6 lane over a
// three-node simulated mesh (terminal/forward, role gate, TTL/deadline,
// lane caps, hop authentication vs origin claims, DATA continuity).

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "routeloom/bootstrap_transport.hpp"
#include "routeloom/node.hpp"
#include "routeloom/rlcw1.hpp"
#include "routeloom/sdkv1_handshake.hpp"
#include "routeloom/sdkv1_join_transport.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/session_bank.hpp"
#include "routeloom/wire.hpp"

#include "test_sdkv1.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

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
using routeloom_test::SimWorld;

constexpr NetworkId kNet = 1;
constexpr MonotonicMs kT0 = 1000;

// --- End envelope edges (beyond the golden vectors) -------------------------------

void test_end_object_edges() {
  // Empty message and oversized message refuse on encode.
  EndObject empty{};
  empty.phase = JoinAuthPhase::EdhocMessage;
  empty.step = 1;
  empty.exchange_id = 7;
  empty.profile = kEndProfileMember;
  empty.message = ByteView{};
  std::array<std::uint8_t, kEndObjectMax> out{};
  std::size_t written = 0;
  CHECK(!end_object_encode(empty, MutableByteView{out.data(), out.size()}, written).ok());
  std::array<std::uint8_t, kJoinMessageMax + 1> big{};
  EndObject oversized = empty;
  oversized.message = ByteView{big.data(), big.size()};
  CHECK(!end_object_encode(oversized, MutableByteView{out.data(), out.size()}, written).ok());
  // RelayStatus phase and EDHOC step 5 refuse both ways.
  EndObject status = empty;
  status.phase = JoinAuthPhase::RelayStatus;
  status.message = ByteView{big.data(), 1};
  CHECK(!end_object_encode(status, MutableByteView{out.data(), out.size()}, written).ok());
  EndObject step5 = empty;
  step5.step = 5;
  step5.message = ByteView{big.data(), 1};
  CHECK(!end_object_encode(step5, MutableByteView{out.data(), out.size()}, written).ok());
  // A short output buffer refuses without writing.
  std::array<std::uint8_t, 13> tiny{};
  CHECK(!end_object_encode(step5, MutableByteView{tiny.data(), tiny.size()}, written).ok() ||
        written == 0);
  EndObject good = empty;
  good.message = ByteView{big.data(), 1};
  CHECK(!end_object_encode(good, MutableByteView{tiny.data(), 2}, written).ok());
  CHECK(written == 0);
  // Type 4 is join-relay Final/Abort only: refused even for valid bytes.
  std::array<std::uint8_t, kEndObjectMax> encoded{};
  CHECK_OK(end_object_encode(good, MutableByteView{encoded.data(), encoded.size()}, written));
  EndObject decoded{};
  CHECK_OK(end_single_frame_decode(FrameType::BootstrapAuth,
                                   ByteView{encoded.data(), written}, decoded));
  CHECK(decoded.exchange_id == 7);
  CHECK(!end_single_frame_decode(FrameType::MembershipResult,
                                 ByteView{encoded.data(), written}, decoded)
             .ok());
  CHECK(!end_single_frame_decode(FrameType::BootstrapChunk,
                                 ByteView{encoded.data(), written}, decoded)
             .ok());
  CHECK(end_object_encoded_size(good) == written);
}

// --- Chunk/reply lane namespace -----------------------------------------------------

void test_chunk_lane_codec() {
  // The end sub namespace is exactly 0xC1..0xC4 and 0xD1..0xD3.
  for (const auto phase : {JoinAuthPhase::EdhocMessage, JoinAuthPhase::Resume}) {
    const std::uint8_t max_step = phase == JoinAuthPhase::EdhocMessage ? 4 : 3;
    for (std::uint8_t step = 1; step <= max_step; ++step) {
      const std::uint8_t sub = end_sub(phase, step);
      CHECK((sub & kEndSubLaneBit) != 0);
      ObjectLane lane{};
      JoinAuthPhase decoded_phase{};
      std::uint8_t decoded_step = 0;
      CHECK(object_sub_decode(sub, lane, decoded_phase, decoded_step));
      CHECK(lane == ObjectLane::EndSession);
      CHECK(decoded_phase == phase);
      CHECK(decoded_step == step);
    }
  }
  // The join namespace is untouched: legacy bytes decode to the join lane.
  for (const auto phase : {JoinAuthPhase::EdhocMessage, JoinAuthPhase::Resume}) {
    const std::uint8_t max_step = phase == JoinAuthPhase::EdhocMessage ? 5 : 3;
    for (std::uint8_t step = 1; step <= max_step; ++step) {
      const std::uint8_t sub = join_sub(phase, step);
      CHECK((sub & kEndSubLaneBit) == 0);
      ObjectLane lane{};
      JoinAuthPhase decoded_phase{};
      std::uint8_t decoded_step = 0;
      CHECK(object_sub_decode(sub, lane, decoded_phase, decoded_step));
      CHECK(lane == ObjectLane::JoinRelay);
      CHECK(decoded_phase == phase);
      CHECK(decoded_step == step);
    }
  }
  // Cross-lane aliases refuse: step 5 exists only on the join lane.
  {
    ObjectLane lane{};
    JoinAuthPhase phase{};
    std::uint8_t step = 0;
    CHECK(!object_sub_decode(0xC5, lane, phase, step));
    CHECK(!object_sub_decode(0xD4, lane, phase, step));
    CHECK(!object_sub_decode(0xE1, lane, phase, step));
    CHECK(!object_sub_decode(0x01, lane, phase, step));
    CHECK(object_sub_decode(0x45, lane, phase, step));  // join EDHOC step 5
    CHECK(lane == ObjectLane::JoinRelay && step == 5);
  }
  // Chunk round-trip carries the lane; the end lane never rides RLD1.
  // WireRelay v2 grid is 110 (18 B head with reserved-zero end epochs).
  std::array<std::uint8_t, 110> body{};
  for (std::size_t i = 0; i < body.size(); ++i) body[i] = static_cast<std::uint8_t>(i);
  JoinChunk chunk{};
  chunk.phase = JoinAuthPhase::EdhocMessage;
  chunk.step = 3;
  chunk.id = 0x12345678;
  chunk.offset = 0;
  chunk.total = 200;
  chunk.data = ByteView{body.data(), body.size()};
  chunk.lane = ObjectLane::EndSession;
  std::array<std::uint8_t, 128> wire{};
  std::size_t wire_written = 0;
  CHECK_OK(join_chunk_encode(JoinCarrier::WireRelay, chunk,
                             MutableByteView{wire.data(), wire.size()}, wire_written));
  CHECK(wire[1] == 0xC3);
  JoinChunk back{};
  CHECK_OK(join_chunk_decode(JoinCarrier::WireRelay, ByteView{wire.data(), wire_written}, back));
  CHECK(back.lane == ObjectLane::EndSession);
  CHECK(back.phase == JoinAuthPhase::EdhocMessage && back.step == 3);
  CHECK(back.id == chunk.id && back.total == chunk.total);
  CHECK(!join_chunk_encode(JoinCarrier::Rld1, chunk, MutableByteView{wire.data(), wire.size()},
                           wire_written)
             .ok());
  // A join chunk keeps the legacy sub byte-for-byte.
  JoinChunk legacy = chunk;
  legacy.lane = ObjectLane::JoinRelay;
  legacy.step = 5;
  legacy.data = ByteView{body.data(), 106};
  legacy.total = 200;
  legacy.offset = 0;
  // RLD1 grid is 106: rebuild a grid-aligned chunk for the legacy carrier.
  CHECK_OK(join_chunk_encode(JoinCarrier::Rld1, legacy,
                             MutableByteView{wire.data(), wire.size()}, wire_written));
  CHECK(wire[1] == 0x45);
  // Reply round-trip carries the lane too (v2 18 B Wire head).
  JoinReply reply{};
  reply.phase = JoinAuthPhase::Resume;
  reply.step = 2;
  reply.id = 99;
  reply.received = 110;
  reply.status = JoinReplyStatus::Progress;
  reply.lane = ObjectLane::EndSession;
  std::array<std::uint8_t, kWireRelayReplySize> reply_wire{};
  std::size_t reply_written = 0;
  CHECK_OK(join_reply_encode(JoinCarrier::WireRelay, reply,
                             MutableByteView{reply_wire.data(), reply_wire.size()}, reply_written));
  CHECK(reply_wire[1] == 0xD2);
  JoinReply reply_back{};
  CHECK_OK(join_reply_decode(JoinCarrier::WireRelay, ByteView{reply_wire.data(), reply_written},
                             reply_back));
  CHECK(reply_back.lane == ObjectLane::EndSession);
  CHECK(reply_back.received == 110);
}

void test_slot_lane_isolation() {
  // Same (carrier, id, phase, step), different lanes: two slots assemble
  // without aliasing, and cross-lane traffic is refused, not merged.
  std::array<std::uint8_t, 300> object{};
  for (std::size_t i = 0; i < object.size(); ++i) object[i] = static_cast<std::uint8_t>(i * 3 + 1);
  JoinObjectSlot join_slot;
  JoinObjectSlot end_slot;
  CHECK_OK(join_slot.load(JoinCarrier::WireRelay, JoinAuthPhase::EdhocMessage, 1, 0xA11CE, 7, 3,
                          ByteView{object.data(), object.size()}, kT0));
  CHECK_OK(end_slot.load(JoinCarrier::WireRelay, JoinAuthPhase::EdhocMessage, 1, 0xA11CE, 0, 0,
                         ByteView{object.data(), object.size()}, kT0,
                         ObjectLane::EndSession));
  CHECK(join_slot.lane() == ObjectLane::JoinRelay);
  CHECK(end_slot.lane() == ObjectLane::EndSession);
  // Outbound chunks differ only in the sub byte.
  JoinChunk join_first{};
  JoinChunk end_first{};
  CHECK_OK(join_slot.chunk_at(0, join_first));
  CHECK_OK(end_slot.chunk_at(0, end_first));
  CHECK(join_first.lane == ObjectLane::JoinRelay);
  CHECK(end_first.lane == ObjectLane::EndSession);
  std::array<std::uint8_t, 128> join_wire{};
  std::array<std::uint8_t, 128> end_wire{};
  std::size_t join_written = 0;
  std::size_t end_written = 0;
  CHECK_OK(join_chunk_encode(JoinCarrier::WireRelay, join_first,
                             MutableByteView{join_wire.data(), join_wire.size()}, join_written));
  CHECK_OK(join_chunk_encode(JoinCarrier::WireRelay, end_first,
                             MutableByteView{end_wire.data(), end_wire.size()}, end_written));
  CHECK(join_written == end_written);
  CHECK(join_wire[1] == 0x41 && end_wire[1] == 0xC1);
  // Same id/offset/total, then the lane's epoch bytes: the join lane's
  // service epochs vs the end lane's reserved zeros.
  CHECK(std::memcmp(join_wire.data() + 2, end_wire.data() + 2, 8) == 0);
  CHECK(join_wire[10] == 0 && join_wire[13] == 7 && end_wire[10] == 0 && end_wire[13] == 0);
  CHECK(std::memcmp(join_wire.data() + 18, end_wire.data() + 18, join_written - 18) == 0);
  // A join reply never advances the end lane's send, and vice versa.
  JoinReply join_complete{};
  join_complete.phase = JoinAuthPhase::EdhocMessage;
  join_complete.step = 1;
  join_complete.id = 0xA11CE;
  join_complete.gateway_epoch = 7;
  join_complete.proxy_epoch = 3;
  join_complete.received = static_cast<std::uint16_t>(object.size());
  join_complete.status = JoinReplyStatus::Complete;
  join_complete.lane = ObjectLane::JoinRelay;
  CHECK(end_slot.on_reply(join_complete, kT0) == JoinObjectSlot::ReplyOutcome::Ignored);
  JoinReply end_complete = join_complete;
  end_complete.lane = ObjectLane::EndSession;
  end_complete.gateway_epoch = 0;
  end_complete.proxy_epoch = 0;
  CHECK(join_slot.on_reply(end_complete, kT0) == JoinObjectSlot::ReplyOutcome::Ignored);
  CHECK(end_slot.on_reply(end_complete, kT0) == JoinObjectSlot::ReplyOutcome::Done);
  // ... and nonzero epochs never confirm the end lane's reserved-zero key.
  JoinReply end_wrong_epoch = end_complete;
  end_wrong_epoch.gateway_epoch = 7;
  CHECK(end_slot.on_reply(end_wrong_epoch, kT0) == JoinObjectSlot::ReplyOutcome::Ignored);
  // Inbound: an end chunk never joins a join-lane assembly.
  JoinObjectSlot inbound;
  JoinChunk join_chunk{};
  CHECK_OK(join_chunk_decode(JoinCarrier::WireRelay, ByteView{join_wire.data(), join_written},
                             join_chunk));
  const auto first = inbound.accept(JoinCarrier::WireRelay, join_chunk, kT0);
  CHECK(first.outcome == JoinObjectSlot::Outcome::Progress);
  CHECK(inbound.lane() == ObjectLane::JoinRelay);
  JoinChunk end_chunk{};
  CHECK_OK(
      join_chunk_decode(JoinCarrier::WireRelay, ByteView{end_wire.data(), end_written}, end_chunk));
  const auto crossed = inbound.accept(JoinCarrier::WireRelay, end_chunk, kT0);
  CHECK(crossed.outcome == JoinObjectSlot::Outcome::Busy);
  CHECK(!crossed.send_reply);
  // End-lane assembly completes on its own slot with end-lane replies.
  JoinObjectSlot end_inbound;
  JoinChunk c0 = end_chunk;
  const auto e0 = end_inbound.accept(JoinCarrier::WireRelay, c0, kT0);
  CHECK(e0.outcome == JoinObjectSlot::Outcome::Progress);
  CHECK(e0.reply.lane == ObjectLane::EndSession);
  for (std::size_t i = 1; i < 3; ++i) {
    JoinChunk ci{};
    // Rebuild the remaining chunks from the peer's sender side.
    JoinObjectSlot sender;
    CHECK_OK(sender.load(JoinCarrier::WireRelay, JoinAuthPhase::EdhocMessage, 1, 0xA11CE, 0, 0,
                         ByteView{object.data(), object.size()}, kT0, ObjectLane::EndSession));
    CHECK_OK(sender.chunk_at(i, ci));
    const auto accepted = end_inbound.accept(JoinCarrier::WireRelay, ci, kT0);
    if (i < 2) {
      CHECK(accepted.outcome == JoinObjectSlot::Outcome::Progress);
    } else {
      CHECK(accepted.outcome == JoinObjectSlot::Outcome::Complete);
      CHECK(accepted.reply.lane == ObjectLane::EndSession);
      CHECK(accepted.reply.status == JoinReplyStatus::Complete);
    }
  }
  CHECK(end_inbound.assembled().size == object.size());
  CHECK(std::memcmp(end_inbound.assembled().data, object.data(), object.size()) == 0);
  // End objects never load on the RLD1 carrier; EDHOC step 5 never loads
  // on the end lane.
  JoinObjectSlot bad;
  CHECK(!bad.load(JoinCarrier::Rld1, JoinAuthPhase::EdhocMessage, 1, 0xA11CE, 0, 0,
                  ByteView{object.data(), object.size()}, kT0, ObjectLane::EndSession)
             .ok());
  CHECK(!bad.load(JoinCarrier::WireRelay, JoinAuthPhase::EdhocMessage, 5, 0xA11CE, 0, 0,
                  ByteView{object.data(), object.size()}, kT0, ObjectLane::EndSession)
             .ok());
  // A WireRelay join-lane load without service epochs is refused (#116).
  CHECK(!bad.load(JoinCarrier::WireRelay, JoinAuthPhase::EdhocMessage, 1, 0xA11CE, 0, 0,
                  ByteView{object.data(), object.size()}, kT0, ObjectLane::JoinRelay)
             .ok());
}

// --- Responder rate budgets -------------------------------------------------------------

void test_bootstrap_budgets() {
  // Link resume: 1 start/s, no burst.
  {
    BootstrapBudgets budgets;
    CHECK(budgets.admit_link_resume(kT0));
    CHECK(!budgets.admit_link_resume(kT0));
    CHECK(!budgets.admit_link_resume(kT0 + 999));
    CHECK(budgets.admit_link_resume(kT0 + 1000));
    CHECK(!budgets.admit_link_resume(kT0 + 1000));
    // Idle time tops up to 1, never more.
    CHECK(budgets.admit_link_resume(kT0 + 10000));
    CHECK(!budgets.admit_link_resume(kT0 + 10000));
  }
  // End (gateway) resume: 10/s with a burst of 4.
  {
    BootstrapBudgets budgets;
    for (std::size_t i = 0; i < 4; ++i) CHECK(budgets.admit_end_resume(kT0));
    CHECK(!budgets.admit_end_resume(kT0));
    // 100 ms refills exactly one token.
    CHECK(!budgets.admit_end_resume(kT0 + 99));
    CHECK(budgets.admit_end_resume(kT0 + 100));
    CHECK(!budgets.admit_end_resume(kT0 + 100));
    // Idle time tops up to the burst, never past it.
    for (std::size_t i = 0; i < 4; ++i) CHECK(budgets.admit_end_resume(kT0 + 10000 + i));
    CHECK(!budgets.admit_end_resume(kT0 + 10003));
  }
  // The two buckets keep separate clocks and balances.
  {
    BootstrapBudgets budgets;
    CHECK(budgets.admit_link_resume(kT0));
    for (std::size_t i = 0; i < 4; ++i) CHECK(budgets.admit_end_resume(kT0));
    CHECK(!budgets.admit_end_resume(kT0));
    CHECK(budgets.admit_link_resume(kT0 + 1000));
    // +1000 refills the end bucket to its burst of 4; drain it fully.
    for (std::size_t i = 0; i < 4; ++i) CHECK(budgets.admit_end_resume(kT0 + 1000));
    CHECK(!budgets.admit_end_resume(kT0 + 1000));
    // A backwards clock grants nothing new and consumes nothing extra.
    CHECK(!budgets.admit_end_resume(kT0 + 500));
    CHECK(!budgets.admit_end_resume(kT0 + 1000));
    CHECK(budgets.admit_end_resume(kT0 + 1100));
  }
}

// --- Session demand driver ----------------------------------------------------------------
// Minimal engine doubles: the driver only needs request() to be attempted
// (a credential-less engine refuses InvalidState AFTER recording the
// exchange — the attempt itself is the observable forward).

struct DriverRng {
  std::uint64_t state{0x9E3779B9};
  static bool fill(void* ctx, std::uint8_t* out, const std::size_t size) noexcept {
    auto& self = *static_cast<DriverRng*>(ctx);
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

struct DriverAead {
  static bool seal(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView plaintext, std::uint8_t* out_ciphertext,
                   std::uint8_t out_tag[16]) noexcept {
    (void)ctx;
    (void)aad;
    if (out_ciphertext == nullptr || out_tag == nullptr) return false;
    for (std::size_t i = 0; i < plaintext.size; ++i) {
      out_ciphertext[i] =
          static_cast<std::uint8_t>(plaintext.data[i] ^ key[i % 16] ^ nonce[i % 12]);
    }
    for (std::size_t i = 0; i < 16; ++i) out_tag[i] = static_cast<std::uint8_t>(key[i] ^ nonce[i % 12]);
    return true;
  }
  static bool open(void* ctx, const std::uint8_t key[16], const std::uint8_t nonce[12],
                   const ByteView aad, const ByteView ciphertext, const std::uint8_t tag[16],
                   std::uint8_t* out_plaintext) noexcept {
    (void)ctx;
    (void)aad;
    if (out_plaintext == nullptr || tag == nullptr) return false;
    std::uint8_t expect[16];
    for (std::size_t i = 0; i < 16; ++i) expect[i] = static_cast<std::uint8_t>(key[i] ^ nonce[i % 12]);
    if (std::memcmp(expect, tag, 16) != 0) return false;
    for (std::size_t i = 0; i < ciphertext.size; ++i) {
      out_plaintext[i] =
          static_cast<std::uint8_t>(ciphertext.data[i] ^ key[i % 16] ^ nonce[i % 12]);
    }
    return true;
  }
};

struct DriverMembership final : public HandshakeMembershipView {
  bool local(HandshakeLocal& out) const noexcept override {
    if (!local_ok) return false;
    out = view;
    return true;
  }
  bool revoked(NodeId peer, std::uint32_t generation) const noexcept override {
    (void)peer;
    (void)generation;
    return false;
  }
  HandshakeLocal view{};
  bool local_ok{true};
};

struct DriverVerifier final : public SessionCredentialVerifier {
  bool local_credential(LocalCredential& out) noexcept override {
    (void)out;
    return false;  // credential-less: requests record, then refuse
  }
  bool verify_peer(ByteView cert, NodeId expected_node, PeerCertClaims& out) noexcept override {
    (void)cert;
    (void)expected_node;
    (void)out;
    return false;
  }
};

struct DriverHarness {
  DriverHarness()
      : cache(storage, kResume2NodeLinkQuota, kResume2NodeEndQuota),
        sink(bank),
        engine(cache, sink, cookie, membership, verifier, &DriverRng::fill, &rng),
        driver(bank, engine) {
    membership.view.self = kSelf;
    membership.view.network = kNet;
    membership.view.site_id = 0x5EED;
    membership.view.site_epoch = 0;
    membership.view.gk_epoch = 1;
    membership.view.generation = 3;
    membership.view.role = kMemberRoleEndpoint | kMemberRoleRelay;
    membership.view.caps = kRld1CapMemberEdhocV1 | kRld1CapMemberResumeV1;
    membership.view.boot = 7;
  }

  bool start() {
    const AeadGcm port{&DriverAead::seal, &DriverAead::open, nullptr};
    NodeSessionBank::LocalView view{};
    view.self = kSelf;
    view.network = kNet;
    view.gk_epoch = 1;
    const NodeSessionBank::RandomSource random{&DriverRng::fill, &rng};
    if (!bank.configure(view, port, random, kT0).ok()) return false;
    if (!cookie.configure(&DriverRng::fill, &rng).ok()) return false;
    return engine.configure(kT0).ok();
  }

  // Plants one establishment demand through the real bank path: a TX
  // epoch lookup with no session records demand and refuses AuthRequired.
  bool plant_demand(const SecurityScope scope, const NodeId peer) {
    std::uint32_t epoch = 0;
    return bank.tx_epoch(scope, peer, epoch).code == StatusCode::AuthRequired;
  }

  static constexpr NodeId kSelf = 0x51;
  DriverRng rng;
  sdkv1_test::FaultyResumeStorage2 storage{16};
  ResumeCache2 cache;
  NodeSessionBank bank;
  BankSessionSink<32, 8> sink;
  MemberCookie cookie;
  DriverMembership membership;
  DriverVerifier verifier;
  HandshakeEngine engine;
  BootstrapDemandDriver<32, 8> driver;
};

void test_demand_driver_end_forwarded() {
  DriverHarness h;
  CHECK(h.start());
  // Two end demands: both are forwarded to the engine (which records the
  // exchanges, then refuses for the missing credential — the attempt is
  // the driver's observable contract).
  CHECK(h.plant_demand(SecurityScope::EndToEnd, 0x61));
  CHECK(h.plant_demand(SecurityScope::EndToEnd, 0x62));
  CHECK(h.bank.demand_count() == 2);
  const Status status = h.driver.poll(kT0);
  CHECK(status.code == StatusCode::InvalidState);
  CHECK(h.bank.demand_count() == 0);
  CHECK(h.driver.pending_link_count() == 0);
  CHECK(!h.engine.quiescent());
  // Both exchanges are live in the engine: re-requesting either is Busy.
  for (const NodeId peer : {NodeId{0x61}, NodeId{0x62}}) {
    HandshakeRequest req{};
    req.scope = SecurityScope::EndToEnd;
    req.peer = peer;
    CHECK(h.engine.request(req, kT0).code == StatusCode::Busy);
  }
}

void test_demand_driver_link_staged() {
  DriverHarness h;
  CHECK(h.start());
  // Link demands carry no carrier: the driver stages them for the Owner
  // instead of requesting, merged per peer.
  CHECK(h.plant_demand(SecurityScope::Link, 0x61));
  CHECK(h.plant_demand(SecurityScope::Link, 0x61));
  CHECK(h.plant_demand(SecurityScope::Link, 0x62));
  CHECK_OK(h.driver.poll(kT0));
  CHECK(h.bank.demand_count() == 0);
  CHECK(h.driver.pending_link_count() == 2);
  CHECK(h.engine.quiescent());  // nothing requested without a carrier
  SessionDemand first{};
  SessionDemand second{};
  CHECK_OK(h.driver.take_link_demand(first));
  CHECK_OK(h.driver.take_link_demand(second));
  CHECK(first.scope == SecurityScope::Link && second.scope == SecurityScope::Link);
  CHECK(((first.peer == 0x61 && second.peer == 0x62) || (first.peer == 0x62 && second.peer == 0x61)));
  SessionDemand none{};
  CHECK(h.driver.take_link_demand(none).code == StatusCode::NotFound);
}

void test_demand_driver_pushback() {
  DriverHarness h;
  CHECK(h.start());
  // Fill the 8-slot link staging, then plant a 9th demand: the driver
  // pushes it back into the bank instead of dropping it.
  for (NodeId peer = 0x61; peer < 0x69; ++peer) CHECK(h.plant_demand(SecurityScope::Link, peer));
  CHECK_OK(h.driver.poll(kT0));
  CHECK(h.driver.pending_link_count() == 8);
  CHECK(h.plant_demand(SecurityScope::Link, 0x69));
  CHECK_OK(h.driver.poll(kT0));
  CHECK(h.driver.pending_link_count() == 8);
  CHECK(h.bank.demand_count() == 1);
  CHECK(h.bank.demand_pending(SecurityScope::Link, 0x69));
  // Draining the staging lets the next poll forward the pushed-back demand.
  for (std::size_t i = 0; i < 8; ++i) {
    SessionDemand dropped{};
    CHECK_OK(h.driver.take_link_demand(dropped));
  }
  CHECK_OK(h.driver.poll(kT0));
  CHECK(h.bank.demand_count() == 0);
  CHECK(h.driver.pending_link_count() == 1);
  SessionDemand last{};
  CHECK_OK(h.driver.take_link_demand(last));
  CHECK(last.peer == 0x69);
}

void test_demand_driver_first_error_drains_rest() {
  DriverHarness h;
  CHECK(h.start());
  // An engine refusal on the end demand must not strand the link demand
  // queued behind it: poll reports the first error after draining all.
  CHECK(h.plant_demand(SecurityScope::EndToEnd, 0x61));
  CHECK(h.plant_demand(SecurityScope::Link, 0x62));
  const Status status = h.driver.poll(kT0);
  CHECK(status.code == StatusCode::InvalidState);
  CHECK(h.bank.demand_count() == 0);
  CHECK(h.driver.pending_link_count() == 1);
  SessionDemand staged{};
  CHECK_OK(h.driver.take_link_demand(staged));
  CHECK(staged.peer == 0x62);
}

// --- MeshNode bootstrap lane (three-node sim) -----------------------------------------

struct BootstrapTap final : public BootstrapSink {
  Status on_frame(const BootstrapMeta& meta, const FrameType type, const ByteView payload,
                  const MonotonicMs now_ms) noexcept override {
    (void)now_ms;
    metas.push_back(meta);
    types.push_back(type);
    payloads.emplace_back(payload.data, payload.data + payload.size);
    return Status::success();
  }
  std::vector<BootstrapMeta> metas;
  std::vector<FrameType> types;
  std::vector<std::vector<std::uint8_t>> payloads;
};

wire::EncodedFrame craft_bootstrap(routeloom_test::TestSecurity& sec, const FrameType type,
                                   const NodeId origin, const NodeId destination,
                                   const NodeId previous_hop, const NodeId next_hop,
                                   const MessageId& id, const ByteView payload,
                                   const bool end_protected, const std::uint8_t hops,
                                   const std::uint32_t deadline_ms) {
  wire::Header h{};
  h.type = type;
  h.flags = end_protected ? wire::kFlagEndProtected : 0;
  h.delivery = DeliveryClass::Reliable;
  h.delivery_round = 0;
  h.hop_remaining = hops;
  h.network = kNet;
  h.origin = origin;
  h.destination = destination;
  h.previous_hop = previous_hop;
  h.next_hop = next_hop;  // the receiving node, not the final destination
  h.message = id;
  h.message = id;
  h.remaining_deadline_ms = deadline_ms;
  h.original_lifetime_ms = deadline_ms;
  h.link_epoch = 1;
  h.end_epoch = 1;
  wire::PlainFrame plain{};
  plain.header = h;
  plain.payload_size = payload.size;
  if (payload.size > 0) std::memcpy(plain.payload.data(), payload.data, payload.size);
  wire::EncodedFrame out{};
  CHECK_OK(wire::encode_new(plain, sec, out));
  return out;
}

void test_node_bootstrap_three_hop() {
  SimWorld w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  MeshNode* c = w.add(3);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  // Only the relay needs the forwarding role; endpoints terminate with
  // whatever role they carry (here: none).
  b->set_local_role(kMemberRoleRelay);
  BootstrapTap tap_a;
  BootstrapTap tap_b;
  BootstrapTap tap_c;
  a->set_bootstrap_sink(&tap_a);
  b->set_bootstrap_sink(&tap_b);
  c->set_bootstrap_sink(&tap_c);
  w.run(4000);  // let the 2-hop route form (~one adv hop per period)
  CHECK(w.at(1)->routes().best(3).valid);
  const std::vector<std::uint8_t> body{0xDE, 0xAD, 0xBE, 0xEF};
  MessageId id{};
  CHECK_OK(a->send_bootstrap(3, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                             4000, w.now, id));
  CHECK(id.sequence != 0);
  w.run(1500);
  // Terminal delivery at C only: the relay forwards without interpreting.
  CHECK(tap_c.metas.size() == 1);
  CHECK(tap_b.metas.empty());
  CHECK(tap_a.metas.empty());
  if (tap_c.metas.size() == 1) {
    CHECK(tap_c.types[0] == FrameType::BootstrapAuth);
    CHECK(tap_c.payloads[0] == body);
    // The meta keeps the previous hop's authentication fact separate from
    // the unverified origin claim.
    CHECK(tap_c.metas[0].origin == 1);
    CHECK(tap_c.metas[0].destination == 3);
    CHECK(tap_c.metas[0].previous_hop == 2);
    CHECK(tap_c.metas[0].id.session == id.session);
    CHECK(tap_c.metas[0].id.sequence == id.sequence);
  }
}

void test_node_bootstrap_role_gate() {
  SimWorld w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  MeshNode* c = w.add(3);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  // B carries no role: a bare endpoint never forwards handshake traffic.
  BootstrapTap tap_c;
  c->set_bootstrap_sink(&tap_c);
  w.run(4000);
  CHECK(w.at(1)->routes().best(3).valid);
  const std::vector<std::uint8_t> body{1, 2, 3};
  MessageId id{};
  CHECK_OK(a->send_bootstrap(3, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                             4000, w.now, id));
  w.run(1500);
  CHECK(tap_c.metas.empty());
  CHECK(w.obs(2)->has_diag("BOOTSTRAP_TRANSIT_ROLE"));
  // Adopting the Gateway role opens transit; Endpoint alone does not.
  b->set_local_role(kMemberRoleEndpoint);
  MessageId id2{};
  CHECK_OK(a->send_bootstrap(3, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                             4000, w.now, id2));
  w.run(1500);
  CHECK(tap_c.metas.empty());
  b->set_local_role(kMemberRoleGateway);
  MessageId id3{};
  CHECK_OK(a->send_bootstrap(3, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                             4000, w.now, id3));
  w.run(1500);
  CHECK(tap_c.metas.size() == 1);
}

void test_node_bootstrap_caps() {
  SimWorld w;
  MeshNode* a = w.add(1);
  w.add(2);
  w.add(3);
  w.add(4);
  w.add(5);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.link(1, 4, 1, 1);
  w.link(1, 5, 1, 1);
  w.run(3000);
  for (const NodeId peer : {NodeId{2}, NodeId{3}, NodeId{4}, NodeId{5}}) {
    CHECK(w.at(1)->routes().best(peer).valid);
  }
  // Two jobs per next hop: the third to the same peer refuses while the
  // first two are still queued (no run() between the sends).
  const std::vector<std::uint8_t> body{9};
  MessageId id{};
  CHECK_OK(a->send_bootstrap(2, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                             4000, w.now, id));
  CHECK_OK(a->send_bootstrap(2, FrameType::BootstrapChunk, ByteView{body.data(), body.size()},
                             4000, w.now, id));
  CHECK(a->send_bootstrap(2, FrameType::BootstrapReply, ByteView{body.data(), body.size()},
                          4000, w.now, id)
            .code == StatusCode::NoCapacity);
  // Fill the lane to 8 across four peers; the 9th refuses lane-full.
  for (const NodeId peer : {NodeId{3}, NodeId{4}, NodeId{5}}) {
    CHECK_OK(a->send_bootstrap(peer, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                               4000, w.now, id));
    CHECK_OK(a->send_bootstrap(peer, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                               4000, w.now, id));
  }
  CHECK(a->send_bootstrap(3, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                          4000, w.now, id)
            .code == StatusCode::NoCapacity);
  // Draining the queue frees the slice again.
  w.run(1500);
  CHECK_OK(a->send_bootstrap(2, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                             4000, w.now, id));
  // Shape errors refuse without consuming the lane.
  CHECK(a->send_bootstrap(2, FrameType::Service, ByteView{body.data(), body.size()}, 4000,
                          w.now, id)
            .code == StatusCode::InvalidArgument);
  CHECK(a->send_bootstrap(1, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                          4000, w.now, id)
            .code == StatusCode::InvalidArgument);
  CHECK(a->send_bootstrap(kBroadcastNodeId, FrameType::BootstrapAuth,
                          ByteView{body.data(), body.size()}, 4000, w.now, id)
            .code == StatusCode::InvalidArgument);
}

void test_node_bootstrap_rx_guards() {
  SimWorld w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  w.start_all();
  w.link(1, 2, 1, 1);
  BootstrapTap tap_b;
  b->set_bootstrap_sink(&tap_b);
  routeloom_test::TestSecurity scratch;
  const std::vector<std::uint8_t> body{0xAA, 0xBB};
  const ByteView view{body.data(), body.size()};
  // An end-protected frame on the bootstrap lane is a scope violation.
  {
    const wire::EncodedFrame frame =
        craft_bootstrap(scratch, FrameType::BootstrapAuth, 1, 2, 1, 2, MessageId{101, 1}, view,
                        /*end_protected=*/true, kDefaultHopLimit, 4000);
    b->on_radio_receive(1, frame.view(), RadioRxMetadata{-60}, w.now);
    CHECK(tap_b.metas.empty());
    CHECK(w.obs(2)->has_diag("BOOTSTRAP_SCOPE_REJECTED"));
  }
  // A group/broadcast destination never terminals or transits.
  {
    const wire::EncodedFrame frame =
        craft_bootstrap(scratch, FrameType::BootstrapAuth, 1, kBroadcastNodeId, 1, 2,
                        MessageId{101, 2}, view, false, kDefaultHopLimit, 4000);
    b->on_radio_receive(1, frame.view(), RadioRxMetadata{-60}, w.now);
    CHECK(tap_b.metas.empty());
    CHECK(w.obs(2)->diagnostics.back() == "BOOTSTRAP_SCOPE_REJECTED");
  }
  // A same-round retry re-ACKs without re-delivering to the sink.
  {
    const wire::EncodedFrame frame =
        craft_bootstrap(scratch, FrameType::BootstrapChunk, 1, 2, 1, 2, MessageId{101, 3}, view,
                        false, kDefaultHopLimit, 4000);
    const auto rx = sim_rx_metadata(w.reply_ports.at(2).get(), 1);
    b->on_radio_receive(1, frame.view(), rx, w.now);
    b->on_radio_receive(1, frame.view(), rx, w.now);
    CHECK(tap_b.metas.size() == 1);
    CHECK(tap_b.types.back() == FrameType::BootstrapChunk);
  }
  (void)a;
}

void test_node_bootstrap_transit_guards() {
  SimWorld w;
  w.add(1);
  MeshNode* b = w.add(2);
  w.add(3);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.run(4000);
  CHECK(w.at(2)->routes().best(3).valid);
  b->set_local_role(kMemberRoleRelay);  // reach the TTL/deadline checks
  routeloom_test::TestSecurity scratch;
  const std::vector<std::uint8_t> body{0xCC};
  const ByteView view{body.data(), body.size()};
  // TTL is enforced at forward emission (wire::forward, shared with the
  // routed lane): a one-hop bootstrap frame cannot transit, a two-hop one
  // forwards with the budget decremented.
  {
    const wire::EncodedFrame one = craft_bootstrap(
        scratch, FrameType::BootstrapAuth, 1, 3, 1, 2, MessageId{101, 11}, view, false, 1, 4000);
    wire::LinkOpenedFrame opened{};
    CHECK_OK(wire::open_link(one.view(), 2, scratch, opened));
    wire::EncodedFrame onward{};
    CHECK(wire::forward(opened, 2, 3, 1, 4000, scratch, onward).code ==
          StatusCode::Expired);
    const wire::EncodedFrame two = craft_bootstrap(
        scratch, FrameType::BootstrapAuth, 1, 3, 1, 2, MessageId{101, 12}, view, false, 2, 4000);
    wire::LinkOpenedFrame opened2{};
    CHECK_OK(wire::open_link(two.view(), 2, scratch, opened2));
    CHECK_OK(wire::forward(opened2, 2, 3, 1, 4000, scratch, onward));
    wire::LinkOpenedFrame at_next{};
    CHECK_OK(wire::open_link(onward.view(), 3, scratch, at_next));
    CHECK(at_next.header.hop_remaining == 1);
    CHECK(at_next.header.previous_hop == 2);
  }
  // A spent deadline refuses as well: the frame was captured 200 ms ago
  // with only 100 ms of forwarding budget left (encode_new never emits a
  // zero lifetime, so the age comes from the RX metadata).
  {
    const wire::EncodedFrame frame = craft_bootstrap(
        scratch, FrameType::BootstrapAuth, 1, 3, 1, 2, MessageId{101, 14}, view, false,
        kDefaultHopLimit, 100);
    RadioRxMetadataV2 aged = sim_rx_metadata(w.reply_ports.at(2).get(), 1);
    aged.received_us = (w.now - 200) * 1000U;
    b->on_radio_receive(1, frame.view(), aged, w.now);
    CHECK(w.obs(2)->has_diag("BOOTSTRAP_TRANSIT_DEADLINE_SPENT"));
  }
  // A live frame transits: C's sink sees the origin claim and the
  // forwarding previous hop.
  BootstrapTap tap_c;
  w.at(3)->set_bootstrap_sink(&tap_c);
  {
    const wire::EncodedFrame frame =
        craft_bootstrap(scratch, FrameType::MembershipResult, 1, 3, 1, 2, MessageId{101, 13},
                        view, false, kDefaultHopLimit, 4000);
    b->on_radio_receive(1, frame.view(), sim_rx_metadata(w.reply_ports.at(2).get(), 1), w.now);
    w.run(1500);
    CHECK(tap_c.metas.size() == 1);
    if (tap_c.metas.size() == 1) {
      CHECK(tap_c.types[0] == FrameType::MembershipResult);
      CHECK(tap_c.metas[0].origin == 1);
      CHECK(tap_c.metas[0].previous_hop == 2);
    }
  }
}

void test_node_bootstrap_no_sink_and_data_continuity() {
  SimWorld w;
  MeshNode* a = w.add(1);
  MeshNode* b = w.add(2);
  MeshNode* c = w.add(3);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  b->set_local_role(kMemberRoleRelay);
  // C has no bootstrap sink: the frame still hop-ACKs and terminates
  // honestly instead of failing closed into a stall.
  w.run(4000);
  CHECK(w.at(1)->routes().best(3).valid);
  const std::vector<std::uint8_t> body{7, 7, 7};
  MessageId id{};
  CHECK_OK(a->send_bootstrap(3, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                             4000, w.now, id));
  w.run(1500);
  CHECK(w.obs(3)->has_diag("BOOTSTRAP_NO_ENDPOINT"));
  // DATA keeps flowing while bootstrap traffic is in flight.
  BootstrapTap tap_c;
  c->set_bootstrap_sink(&tap_c);
  MessageId bootstrap_id{};
  CHECK_OK(a->send_bootstrap(3, FrameType::BootstrapAuth, ByteView{body.data(), body.size()},
                             4000, w.now, bootstrap_id));
  SendOptions options{};
  options.lifetime_ms = 4000;
  MessageId data_id{};
  const std::vector<std::uint8_t> data{1, 2, 3, 4};
  CHECK_OK(a->send(3, ByteView{data.data(), data.size()}, options, w.now, data_id));
  w.run(1500);
  CHECK(tap_c.metas.size() == 1);
  CHECK(w.obs(3)->messages.size() == 1);
  if (!w.obs(3)->messages.empty()) CHECK(w.obs(3)->messages[0] == data);
}

}  // namespace

int main() {
  test_end_object_edges();
  test_chunk_lane_codec();
  test_slot_lane_isolation();
  test_bootstrap_budgets();
  test_demand_driver_end_forwarded();
  test_demand_driver_link_staged();
  test_demand_driver_pushback();
  test_demand_driver_first_error_drains_rest();
  test_node_bootstrap_three_hop();
  test_node_bootstrap_role_gate();
  test_node_bootstrap_caps();
  test_node_bootstrap_rx_guards();
  test_node_bootstrap_transit_guards();
  test_node_bootstrap_no_sink_and_data_continuity();
  if (failures == 0) {
    std::printf("sdkv1 bootstrap: all tests passed\n");
    return 0;
  }
  std::printf("sdkv1 bootstrap: %d failures\n", failures);
  return 1;
}
