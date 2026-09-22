// Dedup capacity-class tests (sdk-completion/02-dedup-capacity.md, issue #9):
// phase-aware retention and phase-ordered eviction of the shared 64-slot
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
using routeloom_test::SimWorld;
using routeloom_test::FrameSight;

constexpr NetworkId kNet = 7;
const std::uint8_t kPayload[] = "dedup-test";

ByteView payload_view() { return ByteView{kPayload, sizeof(kPayload) - 1}; }

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
    node[id] = std::make_unique<MeshNode>(cfg, *radio[id], *sec[id], *obs[id]);
    net.register_node(id, node[id].get());
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
  h.at(receiver)->on_radio_receive(peer, frame.view(), RadioRxMetadata{-60},
                                   h.now);
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
  h.link(1, 2);
  h.link(1, 3);
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
  inject(h, 1, p2, craft_terminal(h.cipher, p2, 1, 600, 7));
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
  (void)h.add(5);                                  // U: real upstream for reports
  h.link(1, 2);
  h.link(1, 5);
  const NodeId up = 5;

  // 4 Resolved records (completed R -> X exchanges from phantom upstreams).
  for (std::uint64_t i = 0; i < 4; ++i) {
    const NodeId p = 100 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 600 + i, 2, 1 + i));
    drive_resolved(h, 1, 2, 1 + i);
  }
  CHECK(r->dedup_stats().admitted_transit == 4);

  // 4 Evidence records: forwards toward X are dropped on the air
  // (deterministic RF loss), exhaust the attempt budget -> post-acceptance
  // failure -> Evidence + a TransitFailure report toward the real upstream.
  // The report sight confirms the evidence phase; the 1 s/peer diag window
  // is rolled between fills so every report is emitted, not counted-dropped.
  for (std::uint64_t i = 0; i < 4; ++i) {
    drive_evidence(h, 1, up, 2,
                   craft_transit(h.cipher, up, 1, 610 + i, 2, 21 + i));
    h.now += 1001;
  }
  CHECK(r->dedup_stats().admitted_transit == 8);

  // 48 terminal pins -> pool 56, then 8 uncompleted forwards parked in
  // awaiting_hop_ (live records, scheduler drained) -> pool 64. The route to
  // X was invalidated+held by the evidence fills' drops — it has expired by
  // now, but the candidate needs re-seeding.
  for (std::uint64_t i = 0; i < 48; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 9000 + i, 100 + i));
    h.step(1);
  }
  (void)r->add_neighbor(2, 1, h.now);
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 130 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 620 + i, 2, 31 + i));
    h.step(1);  // HOP_ACCEPT out (dropped at the phantom)
    h.step(1);  // forward delivered to X -> parks in awaiting, stays Live
  }
  const DedupStats& stats = r->dedup_stats();
  CHECK(stats.admitted_terminal + stats.admitted_transit == 64);

  // Probes are transit admissions left undispatched: each forces exactly one
  // eviction while itself staying Live.
  std::uint64_t prev_res = stats.evicted_resolved;
  std::uint64_t prev_ev = stats.evicted_evidence;
  for (std::uint64_t i = 0; i < 4; ++i) {
    const NodeId p = 140 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 700 + i, 2, 41 + i));
    CHECK(stats.evicted_resolved == prev_res + 1);   // earliest-expiry Resolved
    CHECK(stats.evicted_evidence == prev_ev);        // Evidence untouched
    prev_res = stats.evicted_resolved;
  }
  for (std::uint64_t i = 0; i < 4; ++i) {
    const NodeId p = 150 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 710 + i, 2, 51 + i));
    CHECK(stats.evicted_resolved == prev_res);       // no Resolved left
    CHECK(stats.evicted_evidence == prev_ev + 1);    // Evidence next
    prev_ev = stats.evicted_evidence;
  }
  // All evictable records gone: pool = 48 Terminal + 16 Live. Honest refusal
  // — Live and Terminal records are never eviction victims.
  const NodeId p_last = 160;
  inject(h, 1, p_last, craft_transit(h.cipher, p_last, 1, 720, 2, 61));
  CHECK(stats.refused_pool_full == 1);

  // Diagnostic ordering mirrors the eviction order.
  const long first_res = diag_index(h.observer(1), "DEDUP_EVICTED_RESOLVED");
  const long first_ev = diag_index(h.observer(1), "DEDUP_EVICTED_EVIDENCE");
  const long first_ovf = diag_index(h.observer(1), "DEDUP_OVERFLOW");
  CHECK(first_res >= 0 && first_ev > first_res && first_ovf > first_ev);
}

// §2.5/§2.10 refusal on an all-Live/Terminal pool: BUSY toward a busy-capable
// peer, a counted drop toward a legacy peer, and dedup still working at
// capacity (a re-received terminal frame suppresses — on_message unchanged).
void test_full_pool_honest_refusal() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);   // X: live downstream
  (void)h.add(3);   // Q: busy-capable upstream
  h.link(1, 2);
  h.link(1, 3);
  r->set_peer_busy_capable(3, true);

  for (std::uint64_t i = 0; i < 56; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 9000 + i, 100 + i));
    h.step(1);
  }
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 130 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 620 + i, 2, 31 + i));
    h.step(1);
    h.step(1);
  }
  CHECK(r->dedup_stats().admitted_terminal == 56);
  CHECK(r->dedup_stats().admitted_transit == 8);

  // Busy-capable upstream: refusal emits a real BUSY through the control lane.
  const std::size_t sights_before = h.net.sights.size();
  inject(h, 1, 3, craft_transit(h.cipher, 3, 1, 700, 2, 41));
  CHECK(r->dedup_stats().refused_pool_full == 1);
  CHECK(r->congestion_stats().busy_sent == 1);
  h.step(1);
  bool busy_seen = false;
  for (std::size_t i = sights_before; i < h.net.sights.size(); ++i) {
    if (h.net.sights[i].type == FrameType::Busy && h.net.sights[i].from == 1 &&
        h.net.sights[i].to == 3) {
      busy_seen = true;
    }
  }
  CHECK(busy_seen);
  CHECK(h.observer(1)->has_diag("DEDUP_OVERFLOW"));

  // Legacy (phantom) upstream: counted drop, no BUSY emitted.
  const NodeId legacy = 170;
  const auto sent_before = r->congestion_stats().busy_sent;
  const auto failed_before = r->congestion_stats().busy_send_failed;
  inject(h, 1, legacy, craft_transit(h.cipher, legacy, 1, 701, 2, 42));
  CHECK(r->dedup_stats().refused_pool_full == 2);
  CHECK(r->congestion_stats().busy_sent == sent_before);
  CHECK(r->congestion_stats().busy_send_failed == failed_before + 1);

  // Dedup still answers at capacity: the pinned terminal record suppresses a
  // re-received copy — no second admission, no second on_message — and the
  // same key on a NEW round is still suppressed by the round-agnostic pin.
  const std::size_t msgs_before = h.observer(1)->messages.size();
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 9000, 100));
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 9000, 100, /*round=*/1));
  CHECK(h.observer(1)->messages.size() == msgs_before);
  CHECK(r->dedup_stats().admitted_terminal == 56);
}

// §2.5 terminal reserve: pins may occupy at most 64 - 8 = 56 slots; the last
// eight are unreachable by terminal admissions but remain open to transit.
void test_terminal_reserve() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);
  h.link(1, 2);

  for (std::uint64_t i = 0; i < 56; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 9000 + i, 100 + i));
    h.step(1);
  }
  CHECK(r->dedup_stats().admitted_terminal == 56);

  // Terminal #57 is refused by the reserve, not by pool capacity.
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 9999, 200));
  CHECK(r->dedup_stats().refused_terminal_reserve == 1);
  CHECK(r->dedup_stats().admitted_terminal == 56);
  CHECK(h.observer(1)->has_diag("DEDUP_TERMINAL_RESERVE"));
  CHECK(h.observer(1)->messages.size() == 56);

  // Transit traffic still admits into the reserve.
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 130 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 620 + i, 2, 31 + i));
    h.step(1);
    h.step(1);
  }
  CHECK(r->dedup_stats().admitted_transit == 8);

  // Pool now full of Live + Terminal only: transit honestly refuses too.
  const NodeId p_last = 160;
  inject(h, 1, p_last, craft_transit(h.cipher, p_last, 1, 720, 2, 61));
  CHECK(r->dedup_stats().refused_pool_full == 1);
  CHECK(h.observer(1)->has_diag("DEDUP_OVERFLOW"));
  // And the reserve still refuses terminals.
  inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 9998, 201));
  CHECK(r->dedup_stats().refused_terminal_reserve == 2);
}

// §2.5 upstream bound: at most kDedupPerUpstreamMax (24) non-terminal records
// per previous-hop peer — one flooding upstream cannot starve the others.
void test_upstream_cap() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);
  h.link(1, 2);
  const NodeId a = 100;
  const NodeId b = 101;

  // 24 completed exchanges from upstream A -> 24 Resolved records.
  for (std::uint64_t i = 0; i < 24; ++i) {
    inject(h, 1, a, craft_transit(h.cipher, a, 1, 600 + i, 2, 1 + i));
    drive_resolved(h, 1, 2, 1 + i);
  }
  CHECK(r->dedup_stats().admitted_transit == 24);

  // The 25th transit from A is refused by the dedup upstream bound — the
  // scheduler still has room, so the refusal is unambiguously dedup's.
  inject(h, 1, a, craft_transit(h.cipher, a, 1, 624, 2, 30));
  CHECK(r->dedup_stats().refused_upstream_cap == 1);
  CHECK(h.observer(1)->has_diag("DEDUP_UPSTREAM_CAP"));
  CHECK(r->dedup_stats().admitted_transit == 24);

  // The bound covers terminal-side Resolved births too: a Service delivery
  // from A is refused by the same cap (counted, diagnosed).
  inject(h, 1, a, craft_service(h.cipher, a, 1, 700, 1, 31));
  CHECK(r->dedup_stats().refused_upstream_cap == 2);

  // A second upstream admits immediately — the cap is per previous-hop.
  inject(h, 1, b, craft_transit(h.cipher, b, 1, 800, 2, 40));
  CHECK(r->dedup_stats().admitted_transit == 25);
  CHECK(r->dedup_stats().refused_upstream_cap == 2);
}

// §2.3c/§2.10: Evidence residency is bounded by kEvidenceCap (16) — the
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
  // report sight confirms Evidence formed. 60 s deadlines keep the records
  // alive across the ~17 s fill timeline.
  std::array<wire::EncodedFrame, 17> frames{};
  auto make_evidence = [&](std::uint64_t i) {
    frames[i] = craft_transit(h.cipher, up, 1, 600 + i, 2, 1 + i,
                              /*round=*/0, /*deadline_ms=*/60000);
    drive_evidence(h, 1, up, 2, frames[i]);
    h.now += 1001;
  };

  // 16 records fit the Evidence cap; the 17th force-reclaims the oldest.
  for (std::uint64_t i = 0; i < 16; ++i) make_evidence(i);
  CHECK(r->dedup_stats().evicted_evidence == 0);
  make_evidence(16);
  CHECK(r->dedup_stats().evicted_evidence == 1);
  CHECK(h.observer(1)->has_diag("DEDUP_EVICTED_EVIDENCE"));

  // A dup of the RETAINED record (i == 16 — the same wire bytes again)
  // replays its retained evidence verbatim — a Diagnostic toward the
  // upstream, never a fresh blind re-ACK. (The 1 s diag window rolls first.)
  const std::uint64_t admitted_before = r->dedup_stats().admitted_transit;
  const std::size_t hops_before = h.sights(FrameType::HopAccept, 1, up);
  const std::size_t diags_before = h.sights(FrameType::Diagnostic, 1, up);
  h.now += 1001;
  inject(h, 1, up, frames[16]);
  step_until_sight(h, 1, FrameType::Diagnostic, up, diags_before + 1);
  CHECK(r->dedup_stats().admitted_transit == admitted_before);
  CHECK(h.sights(FrameType::Diagnostic, 1, up) == diags_before + 1);
  CHECK(h.sights(FrameType::HopAccept, 1, up) == hops_before);

  // Replay bounding (01 §replay): >=1 s spacing and a 3-replay cap — the
  // record answers a spaced dup storm exactly three times, then stays quiet.
  for (std::size_t replay = 2; replay <= 3; ++replay) {
    h.now += 1001;
    inject(h, 1, up, frames[16]);
    step_until_sight(h, 1, FrameType::Diagnostic, up, diags_before + replay);
    CHECK(h.sights(FrameType::Diagnostic, 1, up) == diags_before + replay);
  }
  h.now += 1001;
  inject(h, 1, up, frames[16]);
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
  h.link(1, 2);
  h.link(1, 4);
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

  // Fill to capacity: 54 terminal pins (2 + 54 = 56, the reserve bound),
  // then 6 forwards parked in awaiting_hop_ toward node 4 (never polled ->
  // they stay Live and unevictable), then two more Resolved exchanges. Pool =
  // 4R + 54T + 6L = 64, and two awaiting slots stay free for the probe's and
  // the dup's forwards (a full table would force retry storms and extra
  // sights).
  for (std::uint64_t i = 0; i < 54; ++i) {
    inject(h, 1, 50, craft_terminal(h.cipher, 50, 1, 9000 + i, 100 + i));
    h.step(1);
  }
  for (std::uint64_t i = 0; i < 6; ++i) {
    const NodeId q = 130 + static_cast<NodeId>(i);
    inject(h, 1, q, craft_transit(h.cipher, q, 1, 620 + i, 4, 31 + i));
    step_until_sight(h, 1, FrameType::Data, 4, i + 1);
  }
  for (std::uint64_t i = 0; i < 2; ++i) {
    inject(h, 1, p,
           craft_transit(h.cipher, p, 1, 602 + i, 2, 3 + i));
    drive_resolved(h, 1, 2, 3 + i);
  }
  CHECK(r->dedup_stats().admitted_terminal +
            r->dedup_stats().admitted_transit == 64);
  CHECK(x->dedup_stats().admitted_terminal == 4);
  CHECK(h.observer(2)->messages.size() == 4);

  // The probe evicts R1 — the earliest-expiry Resolved record.
  const NodeId probe = 160;
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
  CHECK(h.observer(2)->messages.size() == 4);      // pins, not deliveries
  CHECK(x->dedup_stats().admitted_terminal == 4);  // the dup added no pin
}

// §2.2/§2.6 retention: expiry is set at admission as
// min(first_seen + 60 s, horizon + phase_slack); duplicates never extend it,
// and a terminal re-receipt refreshes only up to the first-seen hard cap.
// Each bound is proven by suppression-before / fresh-admission-after.
void test_retention_bounds() {
  Harness h;
  MeshNode* r = h.add(1, /*hop_timeout=*/60000);
  (void)h.add(2);
  h.link(1, 2);
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
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 600, 7));
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
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 600, 7));
  CHECK(r->dedup_stats().admitted_terminal == 2);
  // Retention honestly ended: a post-expiry arrival is a new delivery.
  CHECK(h.observer(1)->messages.size() == 2);

  // --- first-seen hard cap: admitted at T with a 5 s deadline
  // (expiry T+35000); a new-round re-receipt at T+34000 refreshes to
  // min(T+60000, 34000+5000+30000) = T+60000 — never past the cap.
  h.now = 100000;
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 610, 8));
  CHECK(r->dedup_stats().admitted_terminal == 3);
  h.step(1);
  const std::size_t msgs_before = h.observer(1)->messages.size();
  h.now = 134000;  // T+34000
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 610, 8, /*round=*/1));
  CHECK(h.observer(1)->messages.size() == msgs_before);  // suppressed + refreshed
  h.now = 159999;  // T+59999 — inside the refreshed cap
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 610, 8, /*round=*/1));
  CHECK(h.observer(1)->messages.size() == msgs_before);
  const std::uint64_t e2 = r->dedup_stats().expired;
  h.now = 160000;  // T+60000 — the first-seen hard cap
  h.step(1);
  CHECK(r->dedup_stats().expired > e2);
  // Without the cap the refresh would have held the record to T+69000 —
  // expiry at exactly T+60000 proves duplicates never extend retention.
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 610, 8, /*round=*/1));
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
  h.link(1, 2);

  // Pool composition (terminal pins cap at 64-8=56 total): 9 Resolved
  // records with a 500 ms deadline (expiry ~= first_seen + 5500), then 47
  // terminal pins (expiry ~= +30500), then 8 forwards parked in
  // awaiting_hop_ with an 8 s deadline (expiry ~= +13000 — ALIVE at the
  // probe point). Total 9 + 47 + 8 = 64, of which exactly the nine Resolved
  // records expire in the next advance.
  for (std::uint64_t i = 0; i < 9; ++i) {
    const NodeId p = 100 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 600 + i, 2, 1 + i, 0, 500));
    drive_resolved(h, 1, 2, 1 + i);
  }
  for (std::uint64_t i = 0; i < 47; ++i) {
    inject(h, 1, 50,
           craft_terminal(h.cipher, 50, 1, 9000 + i, 100 + i, 0, 500));
    h.step(1);
  }
  for (std::uint64_t i = 0; i < 8; ++i) {
    const NodeId p = 120 + static_cast<NodeId>(i);
    inject(h, 1, p,
           craft_transit(h.cipher, p, 1, 620 + i, 2, 21 + i, 0, 8000));
    step_until_sight(h, 1, FrameType::Data, 2, 10 + i);
  }
  CHECK(r->dedup_stats().admitted_terminal +
            r->dedup_stats().admitted_transit == 64);

  // Advance past the Resolved expiry (+5500) but inside the terminal slack
  // (+30500) and the live records' expiry (+13000): nine records are
  // dead-but-resident. NB: no poll — the probes' own allocation-time sweep
  // must do the reclaim.
  h.now += 5600;
  for (std::uint64_t i = 0; i < 9; ++i) {
    const NodeId p = 140 + static_cast<NodeId>(i);
    inject(h, 1, p, craft_transit(h.cipher, p, 1, 700 + i, 2, 51 + i));
    CHECK(r->dedup_stats().expired == i + 1);  // one lazy reclaim per probe
    CHECK(r->dedup_stats().evicted_resolved == 0);
    CHECK(r->dedup_stats().evicted_evidence == 0);
  }
  // Pool = 47 Terminal + 8 parked Live + 9 Live probes: the next probe
  // honestly refuses — nothing safe to reclaim or evict remains.
  const NodeId p_last = 160;
  inject(h, 1, p_last, craft_transit(h.cipher, p_last, 1, 720, 2, 61));
  CHECK(r->dedup_stats().refused_pool_full == 1);
  CHECK(h.observer(1)->has_diag("DEDUP_OVERFLOW"));
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

// §2.7/§2.10 above capacity: a sustained terminal flood saturates at exactly
// the 56-pin bound — every admission attempt is accounted (admitted or
// refused_terminal_reserve), dedup keeps suppressing re-received frames, and
// no counter is silently lost.
void test_terminal_flood_honest_saturation() {
  Harness h;
  MeshNode* t = h.add(1);
  const NodeId p = 50;

  constexpr std::uint64_t kFlood = 70;
  for (std::uint64_t i = 0; i < kFlood; ++i) {
    inject(h, 1, p, craft_terminal(h.cipher, p, 1, 9000 + i, 100 + i));
    h.step(1);
  }
  const DedupStats& s = t->dedup_stats();
  CHECK(s.admitted_terminal == 56);
  CHECK(s.refused_terminal_reserve == kFlood - 56);
  CHECK(h.observer(1)->messages.size() == 56);

  // Re-received copies of ADMITTED frames still suppress at capacity — on the
  // original round and on a fresh round alike.
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 9000, 100));
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 9000, 100, /*round=*/1));
  CHECK(h.observer(1)->messages.size() == 56);
  CHECK(s.admitted_terminal == 56);
  CHECK(s.refused_terminal_reserve == kFlood - 56);  // dups never consume

  // Re-received copies of REFUSED frames are refused again — each attempt is
  // an accounted admission decision (bounded retry pressure, never silent).
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 9000 + 60, 160));
  inject(h, 1, p, craft_terminal(h.cipher, p, 1, 9000 + 60, 160));
  CHECK(s.refused_terminal_reserve == kFlood - 56 + 2);
  CHECK(s.admitted_terminal == 56);
  CHECK(h.observer(1)->messages.size() == 56);
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
  test_upstream_cap();
  test_evidence_cap_and_replay();
  test_evicted_resolved_reforward();
  test_retention_bounds();
  test_expired_reclaim_beats_eviction();
  test_cross_round_terminal_pin();
  test_delivery_table_terminal_eviction();
  test_continuous_send_below_capacity();
  test_terminal_flood_honest_saturation();
  test_stats_baseline();
  if (failures == 0) {
    std::printf("RouteLoom dedup tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d dedup checks failed\n", failures);
  return 1;
}
