// Dedup capacity-class tests (sdk-completion/02-dedup-capacity.md, issue #9):
// phase-aware retention and phase-ordered eviction of the shared (profile-sized)
// dedup pool — Live/Resolved/Evidence/Terminal classes, the transit reserve
// and per-upstream bound, the first-seen hard cap, verbatim failure-evidence
// replay and its bounded loss on eviction, class-(a) delivery-history
// eviction, and honest saturation (BUSY/counted refusal) instead of dedup
// weakening.
//
// The dedup pool is private, so phases are proven by OBSERVABLE BEHAVIOR:
// eviction rank (Resolved before Evidence, Live/Terminal never), the
// re-ACK/replay emission on a re-received frame, the admission/refusal
// counters in dedup_stats(), and the diagnostic strings.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

#include "routeloom/byte_io.hpp"
#include "routeloom/node.hpp"
#include "routeloom/wire.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::TestSecurity;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimReplyPort;
using routeloom_test::sim_rx_metadata;
using routeloom_test::SimWorld;
using routeloom_test::FrameSight;

constexpr NetworkId kNet = 7;
const std::uint8_t kPayload[] = "dedup-test";

ByteView payload_view() { return ByteView{kPayload, sizeof(kPayload) - 1}; }

// Class bounds of the compiled resource profile (node.hpp, #39). The pool
// fills below are expressed in these constants; the Live-record counts they
// park are sized for the default relay profile (the hop-wait table holds 8).
constexpr std::size_t kCap = kDedupCapacity;
constexpr std::size_t kPins = kDedupTerminalPinMax;
constexpr std::size_t kReserve = kDedupTransitReserve;
constexpr std::size_t kUpCap = kDedupPerUpstreamMax;
constexpr std::size_t kHopWait = 8;  // MeshNode awaiting_hop_ capacity
static_assert(kDedupCapacity == kDedupCapacityRelay,
              "dedup fills are sized for the default relay profile");
static_assert(kPins + kReserve == kCap, "reserve splits the pool");

// ---------------------------------------------------------------- fixture

// Same small harness shape as the congestion tests: one interchangeable
// TestSecurity mints authenticated frames "from" any peer (link tags derive
// only from the wire context). Phantom peers are just NodeIds — injected
// frames arrive from them but they never exist as nodes, so replies to them
// fail transmission silently (control jobs carry JobOwner::None).
struct Harness {
  SimNetwork net;
  TestSecurity cipher;
  std::map<NodeId, std::unique_ptr<TestSecurity>> sec;
  std::map<NodeId, std::unique_ptr<CapturingObserver>> obs;
  std::map<NodeId, std::unique_ptr<SimRadio>> radio;
  std::map<NodeId, std::unique_ptr<SimReplyPort>> ports;
  std::map<NodeId, std::unique_ptr<MeshNode>> node;
  MonotonicMs now{0};

  MeshNode* add(NodeId id, std::uint32_t hop_timeout = 60,
                std::uint8_t attempts = 2) {
    NodeConfig cfg{};
    cfg.network = kNet;
    cfg.node = id;
    cfg.message_session = 100 + static_cast<std::uint32_t>(id);
    cfg.route_generation = 1;
    cfg.route_advertisement_period_ms = 30000;  // one boot ad, then quiet
    cfg.route_lifetime_ms = 60000;
    cfg.hop_accept_timeout_ms = hop_timeout;
    cfg.max_link_attempts = attempts;
    cfg.max_end_to_end_rounds = 3;
    sec[id] = std::make_unique<TestSecurity>();
    obs[id] = std::make_unique<CapturingObserver>();
    radio[id] = std::make_unique<SimRadio>(net, id);
    ports[id] = std::make_unique<SimReplyPort>(*radio[id], id, cfg.link_epoch);
    node[id] = std::make_unique<MeshNode>(cfg, *radio[id], *sec[id], *obs[id]);
    node[id]->set_reply_peer_port(ports[id].get());
    net.register_node(id, node[id].get());
    net.register_reply_port(id, ports[id].get());
    (void)node[id]->start(now);
    return node[id].get();
  }
  MeshNode* at(NodeId id) const { return node.at(id).get(); }
  CapturingObserver* observer(NodeId id) const { return obs.at(id).get(); }
  // A full link: radio path + routing neighbor entries both ways.
  void link(NodeId a, NodeId b) {
    net.connect(a, b);
    (void)node[a]->add_neighbor(b, 1, now);
    (void)node[b]->add_neighbor(a, 1, now);
  }
  // A one-way route without a radio path: `node_id` resolves `target` as a
  // next hop, but every transmission toward it fails at flush (no such node).
  void phantom_route(NodeId node_id, NodeId target) {
    (void)node[node_id]->add_neighbor(target, 1, now);
  }
  void step(NodeId id) {
    node[id]->poll(now);
    net.flush(now);
  }
  std::size_t sights(FrameType type, NodeId from, NodeId to) const {
    std::size_t count = 0;
    for (const auto& s : net.sights) {
      if (s.type == type && s.from == from && s.to == to) ++count;
    }
    return count;
  }
  std::size_t data_sights(std::uint64_t sequence, NodeId from, NodeId to) const {
    std::size_t count = 0;
    for (const auto& s : net.sights) {
      if (s.type == FrameType::Data && s.sequence == sequence &&
          s.from == from && s.to == to) {
        ++count;
      }
    }
    return count;
  }
};

// Index of the first diagnostic carrying `prefix` (for ordering assertions);
// -1 when absent.
long diag_index(const CapturingObserver* obs, const char* prefix) {
  for (std::size_t i = 0; i < obs->diagnostics.size(); ++i) {
    if (obs->diagnostics[i].rfind(prefix, 0) == 0) return static_cast<long>(i);
  }
  return -1;
}

// ------------------------------------------------------------ crafting

wire::Header mk_header(FrameType type, NodeId origin, NodeId destination,
                       NodeId previous, NodeId next, MessageId message,
                       std::uint8_t flags = 0, std::uint8_t round = 0,
                       std::uint32_t deadline_ms = 5000) {
  wire::Header h{};
  h.type = type;
  h.flags = flags;
  h.delivery = DeliveryClass::Reliable;
  h.delivery_round = round;
  h.hop_remaining = kDefaultHopLimit;
  h.network = kNet;
  h.origin = origin;
  h.destination = destination;
  h.previous_hop = previous;
  h.next_hop = next;
  h.message = message;
  h.remaining_deadline_ms = deadline_ms;
  h.original_lifetime_ms = deadline_ms;
  h.link_epoch = 1;
  h.end_epoch = 1;
  return h;
}

wire::EncodedFrame craft_frame(TestSecurity& cipher, const wire::Header& header,
                               ByteView payload) {
  wire::PlainFrame plain{};
  plain.header = header;
  plain.payload_size = payload.size;
  if (payload.size > 0) {
    std::memcpy(plain.payload.data(), payload.data, payload.size);
  }
  wire::EncodedFrame out{};
  CHECK_OK(wire::encode_new(plain, cipher, out));
  return out;
}

// End-protected transit DATA `prev` -> `relay` bound for `destination`.
wire::EncodedFrame craft_transit(TestSecurity& cipher, NodeId prev, NodeId relay,
                                 NodeId origin, NodeId destination,
                                 std::uint64_t seq, std::uint8_t round = 0,
                                 std::uint32_t deadline_ms = 5000) {
  return craft_frame(cipher,
                     mk_header(FrameType::Data, origin, destination, prev, relay,
                               MessageId{42, seq}, wire::kFlagEndProtected,
                               round, deadline_ms),
                     payload_view());
}

// End-protected terminal DATA `prev` -> `dest_node` (destination == dest_node).
wire::EncodedFrame craft_terminal(TestSecurity& cipher, NodeId prev,
                                  NodeId dest_node, NodeId origin,
                                  std::uint64_t seq, std::uint8_t round = 0,
                                  std::uint32_t deadline_ms = 5000) {
  return craft_frame(cipher,
                     mk_header(FrameType::Data, origin, dest_node, prev,
                               dest_node, MessageId{42, seq},
                               wire::kFlagEndProtected, round, deadline_ms),
                     payload_view());
}

// End-protected routed Service frame `prev` -> `next` (terminal or transit).
wire::EncodedFrame craft_service(TestSecurity& cipher, NodeId prev, NodeId next,
                                 NodeId origin, NodeId destination,
                                 std::uint64_t seq, std::uint8_t round = 0,
                                 std::uint32_t deadline_ms = 5000) {
  return craft_frame(cipher,
                     mk_header(FrameType::Service, origin, destination, prev,
                               next, MessageId{43, seq}, wire::kFlagEndProtected,
                               round, deadline_ms),
                     payload_view());
}

// End-protected END_RECEIPT `emitter` -> `origin_node` via `prev` -> `to`.
// Payload: u64 original_origin | u64 original_destination | u32 session |
// u64 sequence | u8 round | u8 result(0) — see encode_receipt_payload.
wire::EncodedFrame craft_receipt(TestSecurity& cipher, NodeId emitter,
                                 NodeId origin_node, NodeId prev, NodeId to,
                                 MessageId msg, std::uint8_t data_round = 0,
                                 std::uint8_t frame_round = 0,
                                 std::uint32_t deadline_ms = 5000) {
  std::array<std::uint8_t, 32> body{};
  ByteWriter w(MutableByteView{body.data(), body.size()});
  CHECK_OK(w.write_u64(origin_node));   // original DATA origin
  CHECK_OK(w.write_u64(emitter));       // original DATA destination (emitter)
  CHECK_OK(w.write_u32(msg.session));
  CHECK_OK(w.write_u64(msg.sequence));
  CHECK_OK(w.write_u8(data_round));
  CHECK_OK(w.write_u8(0));
  return craft_frame(cipher,
                     mk_header(FrameType::EndReceipt, emitter, origin_node, prev,
                               to, msg, wire::kFlagEndProtected, frame_round,
                               deadline_ms),
                     ByteView{body.data(), w.size()});
}

void inject(Harness& h, NodeId receiver, NodeId peer,
            const wire::EncodedFrame& frame) {
  h.at(receiver)->on_radio_receive(peer, frame.view(),
                                   sim_rx_metadata(h.ports.at(receiver).get(), peer),
                                   h.now);
}

void drive_terminal_receipt(Harness& h, NodeId terminal, NodeId source) {
  for (int i = 0; i < 40 && h.at(terminal)->txn_in_flight() != 0; ++i) {
    h.step(terminal);
    h.step(source);
    h.now += 5;
  }
  CHECK(h.at(terminal)->txn_in_flight() == 0);
}

// Drive a transit exchange P -> relay -> downstream to completion: steps the
// relay until the forward is on the air to `downstream` (queued HOP_ACCEPTs
// to phantom upstreams drain first — control lane beats data lane), then
// steps the downstream so its accept returns and the record resolves.
void drive_resolved(Harness& h, NodeId relay, NodeId downstream,
                    std::uint64_t seq) {
  for (int k = 0; k < 8 && h.data_sights(seq, relay, downstream) < 1; ++k) {
    h.step(relay);
  }
  h.step(downstream);
  h.step(relay);
}

// Drop predicate for evidence fills (SimNetwork::drop_frame is a plain
// function pointer — no captures — so the target pair lives in file state).
// Dropping the forwarded DATA on the air is deterministic RF loss toward a
// REAL neighbor: no phantom neighbors, no perpetual route-advertisement
// churn starving the diagnostic lane.
NodeId g_drop_from = kInvalidNodeId;
NodeId g_drop_to = kInvalidNodeId;
bool drop_data_frames(const SimNetwork::Pending& p) {
  if (p.from != g_drop_from || p.to != g_drop_to) return false;
  FrameSight s{};
  return routeloom_test::sight_frame(
             ByteView{p.frame.data(), p.frame.size()}, s) &&
         s.type == FrameType::Data;
}

// Drive a transit admission to post-acceptance failure (Evidence): the
// forward toward `downstream` (a real, linked, never-polled node) is dropped
// on the air twice, the attempt budget exhausts, and the retained evidence
// surfaces as a Diagnostic TransitFailure report toward the REAL `upstream`.
// That sight is the observable proof the evidence path ran; emission is
// bounded at two reports per upstream per 1 s window, so callers advance
// `now` past the window between records.
void drive_evidence(Harness& h, NodeId relay, NodeId upstream,
                    NodeId downstream, const wire::EncodedFrame& frame) {
  g_drop_from = relay;
  g_drop_to = downstream;
  h.net.drop_frame = drop_data_frames;
  // The previous fill's failures invalidated+held the route (500 ms); the
  // caller's window roll expired it — re-add restores the candidate.
  (void)h.at(relay)->add_neighbor(downstream, 1, h.now);
  const std::size_t before = h.sights(FrameType::Diagnostic, relay, upstream);
  inject(h, relay, upstream, frame);
  for (int k = 0;
       k < 16 && h.sights(FrameType::Diagnostic, relay, upstream) == before;
       ++k) {
    h.step(relay);
    // The second attempt waits out its link-retry jitter (radio.md §8,
    // <=20 ms): time must advance for the retry to become select-eligible.
    h.now += 8;
  }
  h.net.drop_frame = nullptr;
  g_drop_from = g_drop_to = kInvalidNodeId;
}

// Step `id` until `type` gains a sight toward `to` — dispatch can be
// interleaved by triggered route advertisements, so never count on a fixed
// number of polls for a single queued frame.
void step_until_sight(Harness& h, NodeId id, FrameType type, NodeId to,
                      std::size_t want) {
  for (int k = 0; k < 10 && h.sights(type, id, to) < want; ++k) h.step(id);
}

// ------------------------------------------------------------- tests

// §2.4/§2.6 births: transit admission counts as transit (born Live), terminal
// DATA delivery counts as terminal (born Terminal), routed-terminal delivery
// and origin-side receipt consumption are born Resolved — both count as
// transit admissions.
void test_birth_phases() {
  Harness h;
  MeshNode* r = h.add(1);
  (void)h.add(2);            // X: live downstream terminal
  (void)h.add(3);            // P: real upstream — ACKs to it land as sights
  (void)h.add(101);          // source for the terminal DATA/receipt exchange
  h.link(1, 2);
  h.link(1, 3);
  h.link(1, 101);
  const NodeId p = 3;

  // --- transit birth (Live): counters separate the classes.
  // NB: a faithful duplicate is the SAME wire bytes re-delivered (a fresh
  // encode_new carries a new end_counter -> different transit fingerprint ->
  // correctly diagnosed as TRANSIT_DEDUP_CONFLICT, not a dup).
  const auto f1 = craft_transit(h.cipher, p, 1, 500, 2, 1);
  inject(h, 1, p, f1);
  CHECK(r->dedup_stats().admitted_transit == 1);
  CHECK(r->dedup_stats().admitted_terminal == 0);
  // An immediate same-round duplicate re-ACKs without a second admission.
  inject(h, 1, p, f1);
  CHECK(r->dedup_stats().admitted_transit == 1);
  drive_resolved(h, 1, 2, 1);
  CHECK(h.data_sights(1, 1, 2) == 1);
  // After the hop-accept completes (Resolved) the record still suppresses the
  // dup — another re-ACK, never a second forward.
  inject(h, 1, p, f1);
  step_until_sight(h, 1, FrameType::HopAccept, p, 3);
  CHECK(h.data_sights(1, 1, 2) == 1);
  CHECK(h.sights(FrameType::HopAccept, 1, p) >= 2);
  CHECK(r->dedup_stats().admitted_transit == 1);

  // --- terminal birth: Terminal pin + exactly one on_message.
  const NodeId p2 = 101;
  inject(h, 1, p2, craft_terminal(h.cipher, p2, 1, p2, 7));
  CHECK(r->dedup_stats().admitted_terminal == 1);
  CHECK(h.observer(1)->messages.size() == 1);
  h.step(1);

  // --- routed terminal birth (Service -> no endpoint): Resolved class, which
  // counts as a transit admission.
  const auto fs = craft_service(h.cipher, p2, 1, 700, 1, 8);
  inject(h, 1, p2, fs);
  CHECK(r->dedup_stats().admitted_transit == 2);
  CHECK(h.observer(1)->has_diag("SERVICE_NO_ENDPOINT"));
  h.step(1);
  inject(h, 1, p2, fs);
  CHECK(r->dedup_stats().admitted_transit == 2);  // dup: re-ACK only

  // --- origin-side receipt consumption: born Resolved (transit class).
  const MessageId rid{42, 77};
  const auto fr = craft_receipt(h.cipher, /*emitter=*/2, /*origin_node=*/1,
                                p2, 1, rid);
  inject(h, 1, p2, fr);
  CHECK(r->dedup_stats().admitted_transit == 3);
  h.step(1);
  inject(h, 1, p2, fr);
  CHECK(r->dedup_stats().admitted_transit == 3);

  CHECK(r->dedup_stats().refused_pool_full == 0);
  CHECK(r->dedup_stats().refused_terminal_reserve == 0);
  CHECK(r->dedup_stats().refused_upstream_cap == 0);
  CHECK(r->dedup_stats().evicted_resolved == 0);
  CHECK(r->dedup_stats().evicted_evidence == 0);
}

// §2.5: with a mixed-phase pool at capacity, new transit admissions evict
// Resolved records first, then Evidence, and refuse outright once only
// Live/Terminal records remain — each step counted and diagnosed.
void test_eviction_order() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);  // live work never times out
  (void)h.add(2);                                  // X: live downstream
  (void)h.add(50);
  h.link(1, 2);
  h.link(1, 50);

  // 4 Resolved records (completed R -> X exchanges from phantom upstreams).
  // Long deadlines: retention must outlast the evidence fills' window rolls.
  for (std::uint64_t i = 0; i < 4; ++i) {
    const NodeId p = 100 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 600 + i, 2, 1 + i, 0, 30000));
    drive_resolved(h, 1, 2, 1 + i);
  }
  CHECK(r->dedup_stats().admitted_transit == 4);

  // 12 Evidence records: forwards toward X are dropped on the air (MAC
  // failure twice), exhaust the attempt budget -> post-acceptance failure
  // -> Evidence. The 1 s roll expires the previous fill's 500 ms route
  // hold (distinct phantom upstreams need no report-window roll); the
  // reports toward phantoms have no sights — the eviction order below is
  // the proof of the phase.
  for (std::uint64_t i = 0; i < 12; ++i) {
    const NodeId p = 60 + static_cast<NodeId>(i);
    drive_evidence(h, 1, p, 2,
                   craft_transit(h.cipher, p, 1, 610 + i, 2, 21 + i, 0, 30000));
    h.now += 1001;
  }
  CHECK(r->dedup_stats().admitted_transit == 16);

  // kCap - 16 terminal pins (inside the pin bound) -> pool full with zero
  // live transactions: each receipt exchange is settled before the next fill.
  static_assert(kCap - 16 <= kPins, "fill stays inside the pin bound");
  for (std::uint64_t i = 0; i < kCap - 16; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 100 + i));
    drive_terminal_receipt(h, 1, 50);
  }
  const DedupStats& stats = r->dedup_stats();
  CHECK(stats.admitted_terminal + stats.admitted_transit == kCap);

  // R-phase probes each evict the earliest-expiry Resolved record, then
  // are driven to failure so their transactions recycle and the pool
  // stays full for the next probe. The roll expires the route hold again.
  std::uint64_t prev_res = stats.evicted_resolved;
  std::uint64_t prev_ev = stats.evicted_evidence;
  for (std::uint64_t i = 0; i < 4; ++i) {
    const NodeId p = 140 + static_cast<NodeId>(i);
    drive_evidence(h, 1, p, 2, craft_transit(h.cipher, p, 1, 700 + i, 2, 41 + i));
    CHECK(stats.evicted_resolved == prev_res + 1);   // earliest-expiry Resolved
    CHECK(stats.evicted_evidence == prev_ev);        // Evidence untouched
    prev_res = stats.evicted_resolved;
    h.now += 1001;
  }
  // E-phase probes are transit admissions left undispatched (no steps, so
  // no dispatch): each evicts the oldest Evidence record while itself
  // staying Live. Two shared phantom upstreams keep the live binding
  // count inside the 3-binding budget.
  for (std::uint64_t i = 0; i < 4; ++i) {
    const NodeId p = 150 + static_cast<NodeId>(i % 2);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 710 + i, 2, 51 + i));
    CHECK(stats.evicted_resolved == prev_res);       // no Resolved left
    CHECK(stats.evicted_evidence == prev_ev + 1);    // Evidence next
    prev_ev = stats.evicted_evidence;
  }

  // Diagnostic ordering mirrors the eviction order.
  const long first_res = diag_index(h.observer(1), "DEDUP_EVICTED_RESOLVED");
  const long first_ev = diag_index(h.observer(1), "DEDUP_EVICTED_EVIDENCE");
  CHECK(first_res >= 0 && first_ev > first_res);
}

// §2.5/§2.10 refusal at lease capacity (issue #117): with all 8
// transactions live, a transit probe is refused with a diagnosed, counted
// drop — uniform across busy-capable and legacy peers, since the BUSY
// itself is unaffordable (Q117-14). Dedup still suppresses at capacity.
void test_full_pool_honest_refusal() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);   // X: live downstream
  (void)h.add(3);   // Q: busy-capable upstream
  (void)h.add(50);
  h.link(1, 2);
  h.link(1, 3);
  h.link(1, 50);
  r->set_peer_busy_capable(3, true);

  for (std::uint64_t i = 0; i < kPins; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 100 + i));
    drive_terminal_receipt(h, 1, 50);
  }
  // 8 parked Lives hold all 8 transactions (two shared phantom upstreams
  // stay inside the 3-binding budget).
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 130 + static_cast<NodeId>(i % 2);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 620 + i, 2, 31 + i));
    h.step(1);  // HOP_ACCEPT out (dropped at the phantom)
    h.step(1);  // forward delivered to X -> parks in awaiting, stays Live
  }
  CHECK(r->dedup_stats().admitted_terminal == kPins);
  CHECK(r->dedup_stats().admitted_transit == 8);

  // Busy-capable upstream: diagnosed refusal, counted drop, no BUSY.
  const std::size_t sights_before = h.net.sights.size();
  const auto failed_before = r->congestion_stats().busy_send_failed;
  inject(h, 1, 3, craft_transit(h.cipher, 3, 1, 700, 2, 41));
  CHECK(h.observer(1)->has_diag("TRANSIT_ADMISSION_DENIED"));
  CHECK(r->congestion_stats().busy_sent == 0);
  CHECK(r->congestion_stats().busy_send_failed == failed_before + 1);
  h.step(1);
  for (std::size_t i = sights_before; i < h.net.sights.size(); ++i) {
    CHECK(!(h.net.sights[i].type == FrameType::Busy &&
            h.net.sights[i].from == 1));
  }

  // Legacy (phantom) upstream: the same uniform counted drop.
  const NodeId legacy = 170;
  const auto failed_before2 = r->congestion_stats().busy_send_failed;
  inject(h, 1, legacy, craft_transit(h.cipher, legacy, 1, 701, 2, 42));
  CHECK(r->congestion_stats().busy_sent == 0);
  CHECK(r->congestion_stats().busy_send_failed == failed_before2 + 1);

  // Dedup still answers at capacity: the pinned terminal record suppresses a
  // re-received copy — no second admission, no second on_message — and the
  // same key on a NEW round is still suppressed by the round-agnostic pin.
  // (The duplicate's re-ACK is unaffordable too, so it drops silently.)
  const std::size_t msgs_before = h.observer(1)->messages.size();
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 100));
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 100, /*round=*/1));
  CHECK(h.observer(1)->messages.size() == msgs_before);
  CHECK(r->dedup_stats().admitted_terminal == kPins);
}

// §2.5 terminal reserve: pins may occupy at most kCap - kReserve slots; the
// last kReserve are unreachable by terminal admissions but remain open to
// transit.
void test_terminal_reserve() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);
  (void)h.add(50);
  h.link(1, 2);
  h.link(1, 50);

  for (std::uint64_t i = 0; i < kPins; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 100 + i));
    drive_terminal_receipt(h, 1, 50);
  }
  CHECK(r->dedup_stats().admitted_terminal == kPins);

  // Terminal #kPins+1 is refused by the reserve, not by pool capacity.
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 900));
  CHECK(r->dedup_stats().refused_terminal_reserve == 1);
  CHECK(r->dedup_stats().admitted_terminal == kPins);
  CHECK(h.observer(1)->has_diag("DEDUP_TERMINAL_RESERVE"));
  CHECK(h.observer(1)->messages.size() == kPins);

  // Transit traffic still admits into the reserve — up to the 8 live
  // transactions (two shared phantom upstreams stay in the binding budget).
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 130 + static_cast<NodeId>(i % 2);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 620 + i, 2, 31 + i));
    h.step(1);  // HOP_ACCEPT out (dropped at the phantom)
    h.step(1);  // forward delivered to X -> parks in awaiting, stays Live
  }
  CHECK(r->dedup_stats().admitted_transit == 8);

  // With all transactions live, transit honestly refuses (counted drop).
  const NodeId p_last = 160;
  inject(h, 1, p_last, craft_transit(h.cipher, p_last, 1, 720, 2, 61));
  CHECK(h.observer(1)->has_diag("TRANSIT_ADMISSION_DENIED"));

  // Free one transaction by letting X accept a parked forward, and the
  // reserve still refuses terminals (pins are maxed, pool has room).
  h.step(2);  // X dispatches its queued HOP_ACCEPT for a parked forward
  h.step(1);  // the accept lands: one forward resolves, its slot frees
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 901));
  CHECK(r->dedup_stats().refused_terminal_reserve == 2);
}

// #39: the reserve bounds the number of terminal PINS, not the pool size. A
// pool crowded with evictable (Resolved) transit records must not refuse
// delivery to this node's own application: the terminal admission reclaims
// a Resolved record through the normal sweep instead.
void test_terminal_admits_over_resolved_crowd() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);
  (void)h.add(50);
  h.link(1, 2);
  h.link(1, 50);

  // Resolved records from distinct phantom upstreams (the per-upstream bound
  // never fires), then pins up to a full pool.
  constexpr std::size_t kResolved = kReserve + 4;
  for (std::uint64_t i = 0; i < kResolved; ++i) {
    const NodeId p = 100 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 600 + i, 2, 1 + i));
    drive_resolved(h, 1, 2, 1 + i);
  }
  for (std::uint64_t i = 0; i < kCap - kResolved; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 100 + i));
    drive_terminal_receipt(h, 1, 50);
  }
  CHECK(r->dedup_resident() == kCap);
  CHECK(r->dedup_stats().refused_terminal_reserve == 0);

  // Pool full, pins below their bound: the next terminal evicts a Resolved
  // record (counted + diagnosed) and is delivered.
  const std::size_t msgs = h.observer(1)->messages.size();
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 900));
  CHECK(r->dedup_stats().refused_terminal_reserve == 0);
  CHECK(r->dedup_stats().refused_pool_full == 0);
  CHECK(r->dedup_stats().evicted_resolved == 1);
  CHECK(h.observer(1)->messages.size() == msgs + 1);
  CHECK(r->dedup_resident() == kCap);

  // Pins keep their own bound: fill the remaining pin headroom, then the
  // next terminal is refused by the reserve although Resolved records remain.
  const std::size_t pins = kCap - kResolved + 1;
  for (std::uint64_t i = 0; i < kPins - pins; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 901 + i));
    drive_terminal_receipt(h, 1, 50);
  }
  CHECK(r->dedup_stats().admitted_terminal == kPins);
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 990));
  CHECK(r->dedup_stats().refused_terminal_reserve == 1);
  CHECK(r->dedup_stats().admitted_terminal == kPins);
}

// §2.5 upstream bound (#39): one previous-hop peer occupies at most
// kDedupPerUpstreamMax non-terminal records. At the bound it recycles its OWN
// finished (Resolved) records — earliest expiry first — instead of being
// refused: the bound isolates upstreams from each other, it is not a
// throughput ceiling. Another upstream's records are never the victim, even
// when they would expire earlier.
void test_upstream_cap() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);
  (void)h.add(5);  // B: a real upstream so its re-ACKs land as sights
  h.link(1, 2);
  h.link(1, 5);
  const NodeId a = 100;
  const NodeId b = 5;

  // B's record has the EARLIEST expiry in the pool (500 ms deadline): a
  // global earliest-expiry sweep would pick it first.
  const auto fb = craft_transit(h.cipher, b, 1, 800, 2, 90, /*round=*/0,
                                /*deadline_ms=*/500);
  inject(h, 1, b, fb);
  drive_resolved(h, 1, 2, 90);

  // kUpCap completed exchanges from upstream A -> kUpCap Resolved records.
  for (std::uint64_t i = 0; i < kUpCap; ++i) {
    inject(h, 1, a, craft_transit(h.cipher, a, 1, 600 + i, 2, 1 + i));
    drive_resolved(h, 1, 2, 1 + i);
  }
  CHECK(r->dedup_stats().admitted_transit == kUpCap + 1);
  CHECK(r->dedup_resident() == kUpCap + 1);  // pool far from full

  // A's next transit is admitted by recycling A's earliest-expiry Resolved
  // record (counted + diagnosed) — never refused, never B's record.
  inject(h, 1, a, craft_transit(h.cipher, a, 1, 700, 2, 60));
  CHECK(r->dedup_stats().refused_upstream_cap == 0);
  CHECK(r->dedup_stats().evicted_resolved == 1);
  CHECK(h.observer(1)->has_diag("DEDUP_EVICTED_RESOLVED"));
  CHECK(r->dedup_stats().admitted_transit == kUpCap + 2);
  CHECK(r->dedup_resident() == kUpCap + 1);  // A still holds exactly kUpCap

  // The bound covers terminal-side Resolved births too: a Service delivery
  // from A recycles another of A's records.
  inject(h, 1, a, craft_service(h.cipher, a, 1, 701, 1, 61));
  CHECK(r->dedup_stats().refused_upstream_cap == 0);
  CHECK(r->dedup_stats().evicted_resolved == 2);
  CHECK(r->dedup_resident() == kUpCap + 1);

  // B's earlier-expiring record survived A's pressure: its duplicate is
  // still suppressed (re-ACK, no second admission, no second forward).
  const std::uint64_t admitted = r->dedup_stats().admitted_transit;
  const std::size_t acks = h.sights(FrameType::HopAccept, 1, b);
  const std::size_t fwd = h.data_sights(90, 1, 2);
  inject(h, 1, b, fb);
  step_until_sight(h, 1, FrameType::HopAccept, b, acks + 1);
  CHECK(r->dedup_stats().admitted_transit == admitted);
  CHECK(h.sights(FrameType::HopAccept, 1, b) == acks + 1);
  CHECK(h.data_sights(90, 1, 2) == fwd);

  // Live records are never recycled: the scheduler already bounds one
  // upstream's live forwards (per-scope 12 + hop-wait 8) below kUpCap, so
  // the refusal branch (DEDUP_UPSTREAM_CAP) is reachable only when every
  // record an upstream holds is Live — never by finished work.
  static_assert(12 + kHopWait < kUpCap,
                "relay profile: live forwards alone cannot hit the bound");
}

// §2.3c/§2.10: Evidence residency is bounded by kEvidenceCap — the
// oldest evidence is force-reclaimed; a retained record replays its
// TransitFailure verbatim while an evicted one admits the dup as fresh work.
void test_evidence_cap_and_replay() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000, /*attempts=*/2);
  (void)h.add(2);   // X: real downstream the forwards fail toward
  (void)h.add(5);   // real upstream — replies to it land as sights
  h.link(1, 2);
  h.link(1, 5);
  const NodeId up = 5;

  // Each fill: real upstream -> real downstream X whose DATA frames are
  // dropped on the air; the forward's MAC failures produce Evidence + a
  // TransitFailure report toward `up`. Reports are bounded at two per 1 s
  // diag window per peer, so `now` rolls the window between fills and the
  // report sight confirms Evidence formed. Max-lifetime (30 s) deadlines
  // keep the records alive across the ~27 s fill timeline.
  std::array<wire::EncodedFrame, kEvidenceCap + 1> frames{};
  auto make_evidence = [&](std::uint64_t i) {
    frames[i] = craft_transit(h.cipher, up, 1, 600 + i, 2, 1 + i,
                              /*round=*/0, kMaxMessageLifetimeMs);
    drive_evidence(h, 1, up, 2, frames[i]);
    h.now += 1001;
  };

  // kEvidenceCap records fit the cap; the next force-reclaims the oldest.
  for (std::uint64_t i = 0; i < kEvidenceCap; ++i) make_evidence(i);
  CHECK(r->dedup_stats().evicted_evidence == 0);
  make_evidence(kEvidenceCap);
  CHECK(r->dedup_stats().evicted_evidence == 1);
  CHECK(h.observer(1)->has_diag("DEDUP_EVICTED_EVIDENCE"));

  // A dup of the RETAINED record (i == kEvidenceCap — the same bytes again)
  // replays its retained evidence verbatim — a Diagnostic toward the
  // upstream, never a fresh blind re-ACK. (The 1 s diag window rolls first.)
  const std::uint64_t admitted_before = r->dedup_stats().admitted_transit;
  const std::size_t hops_before = h.sights(FrameType::HopAccept, 1, up);
  const std::size_t diags_before = h.sights(FrameType::Diagnostic, 1, up);
  h.now += 1001;
  inject(h, 1, up, frames[kEvidenceCap]);
  step_until_sight(h, 1, FrameType::Diagnostic, up, diags_before + 1);
  CHECK(r->dedup_stats().admitted_transit == admitted_before);
  CHECK(h.sights(FrameType::Diagnostic, 1, up) == diags_before + 1);
  CHECK(h.sights(FrameType::HopAccept, 1, up) == hops_before);

  // Replay bounding (01 §replay): >=1 s spacing and a 3-replay cap — the
  // record answers a spaced dup storm exactly three times, then stays quiet.
  for (std::size_t replay = 2; replay <= 3; ++replay) {
    h.now += 1001;
    inject(h, 1, up, frames[kEvidenceCap]);
    step_until_sight(h, 1, FrameType::Diagnostic, up, diags_before + replay);
    CHECK(h.sights(FrameType::Diagnostic, 1, up) == diags_before + replay);
  }
  h.now += 1001;
  inject(h, 1, up, frames[kEvidenceCap]);
  h.step(1);
  h.step(1);
  CHECK(h.sights(FrameType::Diagnostic, 1, up) == diags_before + 3);  // capped

  // A dup of the EVICTED record (i == 0 — the same wire bytes again) admits
  // as fresh work: a re-ACK first, then a NEW failure cycle. The route to X
  // was invalidated+held by the fills' drops — long expired; re-add restores
  // the candidate BEFORE the admission consults it.
  g_drop_from = 1;
  g_drop_to = 2;
  h.net.drop_frame = drop_data_frames;
  (void)r->add_neighbor(2, 1, h.now);
  inject(h, 1, up, frames[0]);
  CHECK(r->dedup_stats().admitted_transit == admitted_before + 1);
  step_until_sight(h, 1, FrameType::HopAccept, up, hops_before + 1);
  CHECK(h.sights(FrameType::HopAccept, 1, up) == hops_before + 1);
  for (int k = 0;
       k < 16 &&
       h.sights(FrameType::Diagnostic, 1, up) < diags_before + 4;
       ++k) {
    h.step(1);
    // Retries carry link-retry jitter (radio.md §8, <=20 ms): advance the
    // clock so each re-queued attempt becomes select-eligible.
    h.now += 8;
  }
  h.net.drop_frame = nullptr;
  g_drop_from = g_drop_to = kInvalidNodeId;
  CHECK(h.sights(FrameType::Diagnostic, 1, up) >= diags_before + 4);
}

// §2.5/§2.10: evicting a Resolved record loses nothing end-to-end — a late
// same-round duplicate is re-admitted and re-forwarded once, and the
// terminal's pin still suppresses the second application delivery.
void test_evicted_resolved_reforward() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  MeshNode* x = h.add(2);   // downstream terminal for the tracked exchanges
  (void)h.add(4);           // parking downstream for filler forwards
  (void)h.add(50);
  h.link(1, 2);
  h.link(1, 4);
  h.link(1, 50);
  const NodeId p = 100;

  // Two Resolved records up front: R1 with the EARLIER expiry (evicted
  // first), R2 the later one — so the probe's eviction and the re-admitted
  // dup's eviction are deterministic.
  const auto f1 = craft_transit(h.cipher, p, 1, 600, 2, 1, /*round=*/0,
                                /*deadline_ms=*/500);
  inject(h, 1, p, f1);
  drive_resolved(h, 1, 2, 1);
  CHECK(h.data_sights(1, 1, 2) == 1);
  inject(h, 1, p, craft_transit(h.cipher, p, 1, 601, 2, 2));
  drive_resolved(h, 1, 2, 2);

  // Fill to capacity: kPins terminal pins (the reserve bound), then 2
  // forwards parked in awaiting_hop_ toward node 4 (never polled -> they
  // stay Live and unevictable), then Resolved exchanges up to a full pool.
  // The parks share one phantom upstream: the probe (a second upstream)
  // and the dup (a third) must all fit the live 3-binding budget, and
  // their forwards share the 8-slot hop-wait table with the parks.
  constexpr std::size_t kLive = 2;
  constexpr std::size_t kLateResolved = kCap - kPins - kLive - 2;
  for (std::uint64_t i = 0; i < kPins; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 50, 100 + i));
    drive_terminal_receipt(h, 1, 50);
  }
  for (std::uint64_t i = 0; i < kLive; ++i) {
    inject(h, 1, 130, craft_transit(h.cipher, 130, 1, 620 + i, 4, 31 + i));
    step_until_sight(h, 1, FrameType::Data, 4, i + 1);
  }
  for (std::uint64_t i = 0; i < kLateResolved; ++i) {
    inject(h, 1, p,
           craft_transit(h.cipher, p, 1, 602 + i, 2, 3 + i));
    drive_resolved(h, 1, 2, 3 + i);
  }
  CHECK(r->dedup_stats().admitted_terminal +
            r->dedup_stats().admitted_transit == kCap);
  CHECK(x->dedup_stats().admitted_terminal == 2 + kLateResolved);
  CHECK(h.observer(2)->messages.size() == 2 + kLateResolved);

  // The probe evicts R1 — the earliest-expiry Resolved record. Its fresh
  // phantom upstream is the second live binding (parks hold the first).
  const NodeId probe = 131;
  inject(h, 1, probe, craft_transit(h.cipher, probe, 1, 700, 4, 41));
  CHECK(r->dedup_stats().evicted_resolved == 1);
  CHECK(h.observer(1)->has_diag("DEDUP_EVICTED_RESOLVED"));

  // The late same-round duplicate (the same wire bytes re-delivered) is
  // re-admitted — evicting the earliest remaining Resolved record — and
  // re-forwarded once; the downstream terminal pin suppresses the duplicate
  // delivery end-to-end.
  const std::uint64_t admitted_before = r->dedup_stats().admitted_transit;
  const std::size_t data_before = h.data_sights(1, 1, 2);
  inject(h, 1, p, f1);
  CHECK(r->dedup_stats().admitted_transit == admitted_before + 1);
  CHECK(r->dedup_stats().evicted_resolved == 2);
  for (int k = 0; k < 10 && h.data_sights(1, 1, 2) < data_before + 1; ++k) {
    h.step(1);
  }
  CHECK(h.data_sights(1, 1, 2) == data_before + 1);  // one extra transmission
  h.step(2);  // X answers the dup (re-ACK) without re-delivering
  // pins, not deliveries; the dup added no pin
  CHECK(h.observer(2)->messages.size() == 2 + kLateResolved);
  CHECK(x->dedup_stats().admitted_terminal == 2 + kLateResolved);
}

// §2.2/§2.6 retention: expiry is set at admission as
// min(first_seen + 60 s, horizon + phase_slack); duplicates never extend it,
// and a terminal re-receipt refreshes only up to the first-seen hard cap.
// Each bound is proven by suppression-before / fresh-admission-after.
void test_retention_bounds() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);
  (void)h.add(100);
  h.link(1, 2);
  h.link(1, 100);
  const NodeId p = 100;

  // --- transit slack: born-Live record with a 5 s deadline expires at
  // first_seen + 5000 + 5000 = +10000; a same-round dup never extends it.
  const auto f1 = craft_transit(h.cipher, p, 1, 500, 2, 1);
  inject(h, 1, p, f1);
  CHECK(r->dedup_stats().admitted_transit == 1);
  h.now = 9999;
  inject(h, 1, p, f1);                            // identical bytes: a real dup
  CHECK(r->dedup_stats().admitted_transit == 1);  // still resident: suppressed
  const std::uint64_t e0 = r->dedup_stats().expired;
  h.now = 10000;
  h.step(1);                                      // boundary: swept
  CHECK(r->dedup_stats().expired > e0);
  h.now = 10001;
  inject(h, 1, p, f1);
  CHECK(r->dedup_stats().admitted_transit == 2);  // expired: re-admitted fresh
  // (the re-admitted forward expires undispatched later — harmless leftovers)

  // --- terminal slack: a pin with a 5 s deadline lives to first_seen+35000.
  // (No mid-life dup here: a re-received terminal frame REFRESHES retention
  // toward the first-seen hard cap per §2.6 — that bound is proven below.)
  h.now = 20000;
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 7));
  CHECK(r->dedup_stats().admitted_terminal == 1);
  h.step(1);
  CHECK(h.observer(1)->messages.size() == 1);
  h.now = 54999;
  h.step(1);                                      // inside the pin's life
  const std::uint64_t e1 = r->dedup_stats().expired;
  h.now = 55000;
  h.step(1);
  CHECK(r->dedup_stats().expired == e1 + 1);      // swept at the boundary
  h.now = 55001;
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 7));
  CHECK(r->dedup_stats().admitted_terminal == 2);
  // Retention honestly ended: a post-expiry arrival is a new delivery.
  CHECK(h.observer(1)->messages.size() == 2);

  // --- first-seen hard cap: admitted at T with a 5 s deadline
  // (expiry T+35000); a new-round re-receipt at T+34000 refreshes to
  // min(T+60000, 34000+5000+30000) = T+60000 — never past the cap.
  h.now = 100000;
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 8));
  CHECK(r->dedup_stats().admitted_terminal == 3);
  h.step(1);
  const std::size_t msgs_before = h.observer(1)->messages.size();
  h.now = 134000;  // T+34000
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 8, /*round=*/1));
  CHECK(h.observer(1)->messages.size() == msgs_before);  // suppressed + refreshed
  h.now = 159999;  // T+59999 — inside the refreshed cap
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 8, /*round=*/1));
  CHECK(h.observer(1)->messages.size() == msgs_before);
  const std::uint64_t e2 = r->dedup_stats().expired;
  h.now = 160000;  // T+60000 — the first-seen hard cap
  h.step(1);
  CHECK(r->dedup_stats().expired > e2);
  // Without the cap the refresh would have held the record to T+69000 —
  // expiry at exactly T+60000 proves duplicates never extend retention.
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 8, /*round=*/1));
  CHECK(r->dedup_stats().admitted_terminal == 4);
  CHECK(h.observer(1)->messages.size() == msgs_before + 1);
}

// §2.5: the allocation-time sweep reclaims EXPIRED records before it evicts
// anything — when the pool is full of expirable records, every probe's
// admission frees exactly one expired record and evicted_* stays zero.
void test_expired_reclaim_beats_eviction() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);
  (void)h.add(50);
  h.link(1, 2);
  h.link(1, 50);

  // Pool composition (pins stay under kPins): 8 Resolved records with a
  // 500 ms deadline (expiry ~= first_seen + 5500), then kCap-16 terminal
  // pins (expiry ~= +30500), then 8 fresh Resolved records with a long
  // deadline (alive past the probe point). Total 8 + (kCap-16) + 8 = kCap
  // with zero live transactions; exactly the eight short-deadline Resolved
  // records expire in the next advance.
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 100 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 600 + i, 2, 1 + i, 0, 500));
    drive_resolved(h, 1, 2, 1 + i);
  }
  static_assert(kCap - 16 <= kPins, "fill stays inside the pin bound");
  for (std::uint64_t i = 0; i < kCap - 16; ++i) {
    inject(h, 1, 50,
           craft_terminal(h.cipher, 50, 1, 50, 100 + i, 0, 500));
    drive_terminal_receipt(h, 1, 50);
  }
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 110 + static_cast<NodeId>(i);
    inject(h, 1, p,
           craft_transit(h.cipher, p, 1, 620 + i, 2, 21 + i, 0, 30000));
    drive_resolved(h, 1, 2, 21 + i);
  }
  CHECK(r->dedup_stats().admitted_terminal +
            r->dedup_stats().admitted_transit == kCap);

  // Advance past the short Resolved expiry (+5500) but inside the terminal
  // slack (+30500) and the fresh records' horizon: eight records are
  // dead-but-resident, and no poll runs before the probes, so no sweep
  // eats them first. Each probe's admission reclaims exactly one expired
  // record (a counted expiry release, never a forced eviction) while the
  // probe itself stays Live and undispatched. Two shared phantom upstreams
  // keep the live binding count inside the 3-binding budget.
  h.now += 5600;
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 140 + static_cast<NodeId>(i % 2);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 700 + i, 2, 51 + i));
    CHECK(r->dedup_stats().expired == i + 1);
    CHECK(r->dedup_stats().evicted_resolved == 0);
    CHECK(r->dedup_stats().evicted_evidence == 0);
  }
  // All 8 transactions live now: the next probe honestly refuses with a
  // diagnosed, counted drop — the expired-reclaim path never runs, since
  // nothing expired remains anyway.
  const NodeId p_last = 160;
  inject(h, 1, p_last, craft_transit(h.cipher, p_last, 1, 720, 2, 61));
  CHECK(h.observer(1)->has_diag("TRANSIT_ADMISSION_DENIED"));
  CHECK(r->dedup_stats().expired == 8);
}

// §2.6 cross-round pin: an END_RECEIPT-loss retry arrives on round+1 — the
// pinned terminal record suppresses the application delivery, re-ACKs, and
// re-emits the receipt toward a routable origin. Footprint stays 1.
void test_cross_round_terminal_pin() {
  Harness h;
  MeshNode* t = h.add(11);  // terminal
  (void)h.add(10);          // O: real neighbor upstream/origin
  h.link(10, 11);

  inject(h, 11, 10, craft_terminal(h.cipher, 10, 11, 10, 5, /*round=*/0));
  CHECK(t->dedup_stats().admitted_terminal == 1);
  CHECK(h.observer(11)->messages.size() == 1);
  step_until_sight(h, 11, FrameType::EndReceipt, 10, 1);
  CHECK(h.sights(FrameType::HopAccept, 11, 10) == 1);
  CHECK(h.sights(FrameType::EndReceipt, 11, 10) == 1);

  // The receipt was "lost" at O (its consumption never matched a delivery) —
  // the origin retries the DATA on round 1.
  inject(h, 11, 10, craft_terminal(h.cipher, 10, 11, 10, 5, /*round=*/1));
  CHECK(t->dedup_stats().admitted_terminal == 1);   // footprint stays 1
  CHECK(h.observer(11)->messages.size() == 1);      // exactly-once holds
  step_until_sight(h, 11, FrameType::EndReceipt, 10, 2);
  CHECK(h.sights(FrameType::HopAccept, 11, 10) == 2);   // re-ACK
  CHECK(h.sights(FrameType::EndReceipt, 11, 10) == 2);  // receipt re-emitted
}

// §2.3a class-(a): the 8-slot origin delivery table evicts only TERMINAL
// records — all-live refuses the send; a terminal eviction is counted and
// diagnosed, and the evicted result is no longer queryable.
void test_delivery_table_terminal_eviction() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  SendOptions best{};
  best.delivery = DeliveryClass::BestEffort;

  std::array<MessageId, 8> ids{};
  for (auto& id : ids) CHECK_OK(a->send(2, payload_view(), best, h.now, id));
  // All eight live: the next send must be refused, never evict live work.
  MessageId extra{};
  const auto refused = a->send(2, payload_view(), best, h.now, extra);
  CHECK(!refused);
  CHECK(refused.code == StatusCode::NoCapacity);
  CHECK(a->dedup_stats().delivery_terminal_evicted == 0);

  // Complete all eight (best-effort resolves at TX success) -> terminal.
  // Dispatch can be interleaved by a triggered route advertisement, so loop
  // until the eighth lands rather than counting on one step per job.
  std::size_t delivered = 0;
  for (int k = 0; k < 20 && delivered < 8; ++k) {
    h.step(1);
    ++h.now;
    delivered = 0;
    for (const auto& id : ids) {
      if (a->delivery(id).state == DeliveryState::Delivered) ++delivered;
    }
  }
  CHECK(delivered == 8);

  // The ninth send evicts exactly one terminal record — counted + diagnosed,
  // and that result is no longer queryable.
  MessageId ninth{};
  CHECK_OK(a->send(2, payload_view(), best, h.now, ninth));
  CHECK(a->dedup_stats().delivery_terminal_evicted == 1);
  CHECK(h.observer(1)->has_diag("DELIVERY_HISTORY_EVICTED"));
  std::size_t empty = 0;
  for (const auto& id : ids) {
    if (a->delivery(id).state == DeliveryState::Empty) ++empty;
  }
  CHECK(empty == 1);
}

// §2.7/§2.10 continuous send below capacity: a sustained reliable stream
// through a relay never saturates dedup — every message delivered exactly
// once, counters account for every record, transit records expire on the
// short slack while terminal pins persist.
void test_continuous_send_below_capacity() {
  SimWorld w;
  w.network_id = kNet;
  MeshNode* o = w.add(1);
  MeshNode* r = w.add(2);
  MeshNode* t = w.add(3);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.run(4000);  // routes settle (O's reachability advertises through R)

  constexpr int kSends = 12;
  for (int i = 0; i < kSends; ++i) {
    MessageId id{};
    CHECK_OK(o->send(3, payload_view(), SendOptions{}, w.now, id));
    w.run(150);  // exchange + receipt complete well inside the pacing
  }
  CHECK(w.obs(3)->messages.size() == static_cast<std::size_t>(kSends));

  // Terminal: 12 pins, no refusal of any kind.
  CHECK(t->dedup_stats().admitted_terminal == static_cast<std::uint64_t>(kSends));
  CHECK(t->dedup_stats().refused_terminal_reserve == 0);
  CHECK(t->dedup_stats().refused_pool_full == 0);
  // Relay: two transit records per message (DATA forward + receipt forward),
  // resolved after completion; zero refusal/eviction.
  CHECK(r->dedup_stats().admitted_transit >= 2 * kSends);
  CHECK(r->dedup_stats().refused_pool_full == 0);
  CHECK(r->dedup_stats().refused_upstream_cap == 0);
  CHECK(r->dedup_stats().evicted_resolved == 0);
  CHECK(r->dedup_stats().evicted_evidence == 0);
  // Origin: receipts consumed born-Resolved; the 8-slot delivery table
  // recycled terminal history for sends past slot 8 (counted, never silent).
  CHECK(o->dedup_stats().admitted_transit >= kSends);
  CHECK(o->dedup_stats().delivery_terminal_evicted ==
            static_cast<std::uint64_t>(kSends - 8));
  CHECK(o->dedup_stats().refused_pool_full == 0);

  // Transit retention is the short slack: with 5 s deadlines the relay's
  // records die ~10 s after birth while the terminal pins (35 s) persist.
  const std::uint64_t transit_records = r->dedup_stats().admitted_transit;
  w.run(12000);
  CHECK(r->dedup_stats().expired >= transit_records);
  CHECK(t->dedup_stats().expired == 0);  // pins still holding
  CHECK(w.obs(3)->messages.size() == static_cast<std::size_t>(kSends));
}

// Issue #39 (a): the relay throughput ceiling. A 3-node line 1 - 2 - 3 with
// traffic both ways through relay 2 (3 = gateway: 1 -> 3 uplink, 3 -> 1
// downlink), 1.5 msg/s per source for 120 simulated seconds, Reliable with
// the default 5 s lifetime. The relay holds two transit records per message
// (DATA + END_RECEIPT forward) from each upstream; with the old flat 60 s
// retention that is 2 x 3 msg/s x 60 s = 360 records against a 64-slot pool
// (ceiling ~0.5 msg/s). Deadline-bound transit retention (~10 s) keeps the
// relay near 60 records and every class bound untouched: no refusal, no
// eviction, every message delivered exactly once.
void test_line_throughput_two_sources() {
  SimWorld w;
  w.network_id = kNet;
  MeshNode* a = w.add(1);
  MeshNode* r = w.add(2);
  MeshNode* g = w.add(3);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.run(4000);  // routes settle both ways
  CHECK(a->routes().best(3).valid);
  CHECK(g->routes().best(1).valid);

  constexpr std::uint64_t kPerSource = 180;  // 1.5 msg/s x 120 s
  const MonotonicMs start = w.now;
  std::uint64_t sent = 0;
  std::size_t refused_sends = 0;
  std::size_t peak_relay = 0;
  while (sent < kPerSource) {
    // Send k is due at start + k * 2000/3 ms (1.5 msg/s, no drift).
    if (w.now >= start + (sent * 2000) / 3) {
      MessageId id{};
      if (!a->send(3, payload_view(), SendOptions{}, w.now, id)) ++refused_sends;
      if (!g->send(1, payload_view(), SendOptions{}, w.now, id)) ++refused_sends;
      ++sent;
    }
    w.run(5);
    peak_relay = std::max(peak_relay, r->dedup_resident());
  }
  w.run(3000);  // drain the last exchanges
  CHECK(w.now - start >= 119000);
  CHECK(refused_sends == 0);

  // Exactly once, both directions.
  CHECK(w.obs(3)->messages.size() == kPerSource);
  CHECK(w.obs(1)->messages.size() == kPerSource);
  for (NodeId origin : {NodeId{1}, NodeId{3}}) {
    std::size_t delivered = 0;
    for (const auto& event : w.obs(origin)->delivery_events) {
      if (event.state == DeliveryState::Delivered) ++delivered;
    }
    CHECK(delivered == kPerSource);
  }
  // No class bound fired anywhere — the ceiling is gone, not hidden.
  for (NodeId id : {NodeId{1}, NodeId{2}, NodeId{3}}) {
    const DedupStats& s = w.at(id)->dedup_stats();
    CHECK(s.refused_pool_full == 0);
    CHECK(s.refused_terminal_reserve == 0);
    CHECK(s.refused_upstream_cap == 0);
    CHECK(s.evicted_resolved == 0);
    CHECK(s.evicted_evidence == 0);
    CHECK(!w.obs(id)->has_diag("DEDUP_OVERFLOW"));
    CHECK(!w.obs(id)->has_diag("DEDUP_UPSTREAM_CAP"));
    CHECK(!w.obs(id)->has_diag("DEDUP_TERMINAL_RESERVE"));
    CHECK(!w.obs(id)->has_diag("ADMISSION_NO_DEDUP_SLOT"));
  }
  // The relay forwarded a DATA and an END_RECEIPT per message and recycled
  // them by expiry: residency stayed far below the old flat-60 s demand.
  CHECK(r->dedup_stats().admitted_transit >= 4 * kPerSource);
  CHECK(r->dedup_stats().admitted_terminal == 0);
  CHECK(peak_relay < kCap);
  CHECK(peak_relay <= 2 * 3 * (5 + 5) + 8);  // 2 records x 3 msg/s x ~10 s
  std::printf("line throughput: relay peak residency %zu / %zu\n", peak_relay,
              kCap);
}

// §2.7/§2.10 above capacity: a sustained terminal flood saturates at exactly
// the kPins bound — every admission attempt is accounted (admitted or
// refused_terminal_reserve), dedup keeps suppressing re-received frames, and
// no counter is silently lost.
void test_terminal_flood_honest_saturation() {
  Harness h;
  MeshNode* t = h.add(1);
  const NodeId p = 50;
  (void)h.add(p);
  h.link(1, p);

  constexpr std::uint64_t kFlood = kPins + 14;
  for (std::uint64_t i = 0; i < kFlood; ++i) {
    inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 100 + i));
    drive_terminal_receipt(h, 1, p);
  }
  const DedupStats& s = t->dedup_stats();
  CHECK(s.admitted_terminal == kPins);
  CHECK(s.refused_terminal_reserve == kFlood - kPins);
  CHECK(h.observer(1)->messages.size() == kPins);

  // Re-received copies of ADMITTED frames still suppress at capacity — on the
  // original round and on a fresh round alike.
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 100));
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 100, /*round=*/1));
  CHECK(h.observer(1)->messages.size() == kPins);
  CHECK(s.admitted_terminal == kPins);
  CHECK(s.refused_terminal_reserve == kFlood - kPins);  // dups never consume

  // Re-received copies of REFUSED frames are refused again — each attempt is
  // an accounted admission decision (bounded retry pressure, never silent).
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 100 + kPins + 4));
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, p, 100 + kPins + 4));
  CHECK(s.refused_terminal_reserve == kFlood - kPins + 2);
  CHECK(s.admitted_terminal == kPins);
  CHECK(h.observer(1)->messages.size() == kPins);
  // Every unique admission decision is accounted.
  CHECK(s.admitted_terminal + s.refused_terminal_reserve == kFlood + 2);
}

// A fresh node's dedup surface starts at zero — every counter is a real
// saturating u64 wired to a real event.
void test_stats_baseline() {
  Harness h;
  MeshNode* r = h.add(1);
  const auto& s = r->dedup_stats();
  CHECK(s.admitted_terminal == 0 && s.admitted_transit == 0 &&
        s.refused_pool_full == 0 && s.refused_terminal_reserve == 0 &&
        s.refused_upstream_cap == 0 && s.evicted_resolved == 0 &&
        s.evicted_evidence == 0 && s.expired == 0 &&
        s.delivery_terminal_evicted == 0);
}

}  // namespace

int main() {
  test_birth_phases();
  test_eviction_order();
  test_full_pool_honest_refusal();
  test_terminal_reserve();
  test_terminal_admits_over_resolved_crowd();
  test_upstream_cap();
  test_evidence_cap_and_replay();
  test_evicted_resolved_reforward();
  test_retention_bounds();
  test_expired_reclaim_beats_eviction();
  test_cross_round_terminal_pin();
  test_delivery_table_terminal_eviction();
  test_continuous_send_below_capacity();
  test_line_throughput_two_sources();
  test_terminal_flood_honest_saturation();
  test_stats_baseline();
  if (failures == 0) {
    std::printf("RouteLoom dedup tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d dedup checks failed\n", failures);
  return 1;
}
