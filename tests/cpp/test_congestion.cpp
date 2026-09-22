// Autonomous-mesh P2 tests (issue #4): bounded congestion scheduler
// (DRR classes + reserved control lane + bounded flows), BUSY
// emit/dispatch/deferral semantics, peer windows, attempt budgets, queue
// watermarks and the observation groundwork.
//
// Scenario coverage notes reference docs/design/autonomous-mesh/scenarios.json
// (D4-xx) and 03-congestion.md §4/§5.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

#include "routeloom/autonomy_wire.hpp"
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
using routeloom_test::FrameSight;

constexpr NetworkId kNet = 7;
const std::uint8_t kPayload[] = "congestion-test";

ByteView payload_view() { return ByteView{kPayload, sizeof(kPayload) - 1}; }

// ---------------------------------------------------------------- fixture

// Small harness: deterministic TestSecurity instances are interchangeable
// (tags derive only from the wire context), so a single `cipher` can mint
// frames "from" any peer.
struct Harness {
  SimNetwork net;
  TestSecurity cipher;
  std::map<NodeId, std::unique_ptr<TestSecurity>> sec;
  std::map<NodeId, std::unique_ptr<CapturingObserver>> obs;
  std::map<NodeId, std::unique_ptr<SimRadio>> radio;
  std::map<NodeId, std::unique_ptr<MeshNode>> node;
  MonotonicMs now{0};

  MeshNode* add(NodeId id, std::uint8_t rounds = 3, std::uint8_t attempts = 2) {
    NodeConfig cfg{};
    cfg.network = kNet;
    cfg.node = id;
    cfg.message_session = 100 + static_cast<std::uint32_t>(id);
    cfg.route_generation = 1;
    cfg.route_advertisement_period_ms = 30000;  // one boot ad, then quiet
    cfg.route_lifetime_ms = 60000;
    cfg.hop_accept_timeout_ms = 60;
    cfg.max_link_attempts = attempts;
    cfg.max_end_to_end_rounds = rounds;
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
  void link(NodeId a, NodeId b) {
    net.connect(a, b);
    (void)node[a]->add_neighbor(b, 1, now);
    (void)node[b]->add_neighbor(a, 1, now);
  }
  // One dispatch opportunity for a single node + delivery of queued frames.
  void step(NodeId id) {
    node[id]->poll(now);
    net.flush(now);
  }
  std::size_t data_sights(std::uint64_t sequence) const {
    std::size_t count = 0;
    for (const auto& s : net.sights) {
      if (s.type == FrameType::Data && s.sequence == sequence) ++count;
    }
    return count;
  }
};

// ------------------------------------------------------------ crafting

wire::Header mk_header(FrameType type, NodeId origin, NodeId destination,
                       NodeId previous, NodeId next, MessageId message,
                       std::uint8_t flags = 0, std::uint8_t round = 0) {
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
  h.remaining_deadline_ms = 5000;
  h.original_lifetime_ms = 5000;
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

// A BUSY(20) frame `from` -> `to`. BUSY is link-scoped: never end-protected.
wire::EncodedFrame craft_busy(TestSecurity& cipher, NodeId from, NodeId to,
                              autonomy::BusyPayload& payload,
                              std::uint64_t wire_seq) {
  autonomy::EncodedPayload body{};
  CHECK_OK(autonomy::busy_encode(payload, body));
  return craft_frame(cipher,
                     mk_header(FrameType::Busy, from, to, from, to,
                               MessageId{777, wire_seq}),
                     body.view());
}

autonomy::BusyPayload busy_for(const MessageId& data_id, NodeId origin,
                               std::uint8_t round, std::uint32_t retry_ms,
                               std::uint32_t feedback_seq) {
  autonomy::BusyPayload payload{};
  payload.subtype = autonomy::BusySubtype::Reject;
  payload.reason = autonomy::BusyReason::QueueFull;
  payload.referenced_type = FrameType::Data;
  payload.referenced_origin = origin;
  payload.referenced_session = data_id.session;
  payload.referenced_sequence = data_id.sequence;
  payload.referenced_round = round;
  payload.retry_after_ms = retry_ms;
  payload.feedback_sequence = FeedbackSequence{feedback_seq};
  return payload;
}

// Authenticated HOP_ACCEPT `from` -> `to` acknowledging (type, origin, msg,
// round). Ack payload layout: u8 type | u64 origin | u32 session | u64 seq |
// u8 round (see MeshNode::encode_ack_payload).
wire::EncodedFrame craft_accept(TestSecurity& cipher, NodeId from, NodeId to,
                                FrameType accepted_type, NodeId origin,
                                const MessageId& msg, std::uint8_t round,
                                std::uint64_t wire_seq) {
  std::array<std::uint8_t, 32> body{};
  ByteWriter writer(MutableByteView{body.data(), body.size()});
  CHECK_OK(writer.write_u8(static_cast<std::uint8_t>(accepted_type)));
  CHECK_OK(writer.write_u64(origin));
  CHECK_OK(writer.write_u32(msg.session));
  CHECK_OK(writer.write_u64(msg.sequence));
  CHECK_OK(writer.write_u8(round));
  return craft_frame(cipher,
                     mk_header(FrameType::HopAccept, from, to, from, to,
                               MessageId{888, wire_seq}),
                     ByteView{body.data(), writer.size()});
}

// End-protected transit DATA `prev` -> `relay` bound for `destination` with a
// spoofable `origin` (relays never end-verify the claimed origin).
wire::EncodedFrame craft_transit(TestSecurity& cipher, NodeId prev, NodeId relay,
                                 NodeId origin, NodeId destination,
                                 std::uint64_t seq) {
  return craft_frame(cipher,
                     mk_header(FrameType::Data, origin, destination, prev, relay,
                               MessageId{42, seq}, wire::kFlagEndProtected),
                     payload_view());
}

void inject(Harness& h, NodeId receiver, NodeId peer,
            const wire::EncodedFrame& frame) {
  h.at(receiver)->on_radio_receive(peer, frame.view(), RadioRxMetadata{-60}, h.now);
}

// Step `id` until `expected` DATA transmissions of `seq` have been observed.
// Background jobs (the one boot-time route advertisement) may legitimately
// consume a dispatch turn, so callers must not assume one poll == one DATA.
void drive_tx(Harness& h, NodeId id, std::uint64_t seq, std::size_t expected,
              int max_steps = 16) {
  for (int k = 0; k < max_steps && h.data_sights(seq) < expected; ++k) {
    h.step(id);
    ++h.now;
  }
}

// ------------------------------------------------------------- tests

// D4-04: DRR fairness — weighted classes interleave by deficit; bulk is
// charged by estimated TX cost and is delayed but never starved.
void test_drr_fairness() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  SendOptions bulk{};
  bulk.delivery = DeliveryClass::BestEffort;
  bulk.priority = Priority::Bulk;
  SendOptions normal = bulk;
  normal.priority = Priority::Normal;
  SendOptions urgent = bulk;
  urgent.priority = Priority::Urgent;

  // Queue order is deliberately hostile: bulk first, urgent last.
  std::array<MessageId, 2> b_ids{};
  std::array<MessageId, 2> u_ids{};
  for (auto& id : b_ids) CHECK_OK(a->send(2, payload_view(), bulk, h.now, id));
  for (auto& id : u_ids) CHECK_OK(a->send(2, payload_view(), urgent, h.now, id));

  std::vector<std::uint64_t> order;
  for (int i = 0; i < 6 && order.size() < 4; ++i) {
    const std::size_t before = h.net.sights.size();
    h.step(1);
    for (std::size_t s = before; s < h.net.sights.size(); ++s) {
      if (h.net.sights[s].type == FrameType::Data) {
        order.push_back(h.net.sights[s].sequence);
      }
    }
    ++h.now;
  }
  CHECK(order.size() == 4);
  if (order.size() == 4) {
    // Urgent (weight 8) preempts earlier-queued bulk (weight 1).
    CHECK(order[0] == u_ids[0].sequence && order[1] == u_ids[1].sequence);
    CHECK(order[2] == b_ids[0].sequence && order[3] == b_ids[1].sequence);
  }

  // Normal-vs-bulk deficit share: normal jobs flow while bulk waits, but all
  // bulk work is eventually transmitted (no permanent starvation).
  Harness h2;
  MeshNode* a2 = h2.add(1);
  (void)h2.add(2);
  h2.link(1, 2);
  std::vector<std::uint64_t> n_seq, b_seq;
  for (int i = 0; i < 4; ++i) {
    MessageId id{};
    CHECK_OK(a2->send(2, payload_view(), normal, h2.now, id));
    n_seq.push_back(id.sequence);
    CHECK_OK(a2->send(2, payload_view(), bulk, h2.now, id));
    b_seq.push_back(id.sequence);
  }
  std::vector<std::uint64_t> sent;
  for (int i = 0; i < 20 && sent.size() < 8; ++i) {
    const std::size_t before = h2.net.sights.size();
    h2.step(1);
    for (std::size_t s = before; s < h2.net.sights.size(); ++s) {
      if (h2.net.sights[s].type == FrameType::Data) {
        sent.push_back(h2.net.sights[s].sequence);
      }
    }
    ++h2.now;
  }
  CHECK(sent.size() == 8);
  const auto is_bulk = [&](std::uint64_t seq) {
    return std::find(b_seq.begin(), b_seq.end(), seq) != b_seq.end();
  };
  // The first submission is normal-class and normal outruns bulk ~4:1.
  CHECK(!sent.empty() && !is_bulk(sent[0]));
  std::size_t early_bulk = 0;
  for (std::size_t i = 0; i < std::min<std::size_t>(sent.size(), 4); ++i) {
    if (is_bulk(sent[i])) ++early_bulk;
  }
  CHECK(early_bulk <= 1);  // bulk gets a share, not the head of the line
}

// D4-04: reserved control lane — locally generated required responses
// (HOP_ACCEPT) preempt queued data-class work; ordinary queued traffic never
// enters the lane.
void test_control_lane() {
  Harness h;
  MeshNode* a = h.add(1);
  MeshNode* b = h.add(2);
  h.link(1, 2);

  // B queues ordinary data work first — it must NOT jump the control lane.
  SendOptions best{};
  best.delivery = DeliveryClass::BestEffort;
  for (int i = 0; i < 2; ++i) {
    MessageId id{};
    CHECK_OK(b->send(1, payload_view(), best, h.now, id));
  }
  CHECK(b->congestion_stats().control_queued == 0);

  // A sends RELIABLE DATA; B accepts it, queueing a HOP_ACCEPT reply.
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  // DATA on air + delivered into B's receive path; the boot route
  // advertisement (management class) may legitimately take a turn first.
  drive_tx(h, 1, data.sequence, 1);
  CHECK(b->congestion_stats().control_queued == 1);  // the HOP_ACCEPT

  const std::size_t before = h.net.sights.size();
  h.step(2);
  // The first frame B emits is the control-lane HOP_ACCEPT, not its queued
  // data — required responses never wait behind bulk/normal work.
  bool first_is_accept = false;
  for (std::size_t i = before; i < h.net.sights.size(); ++i) {
    if (h.net.sights[i].from == 2) {
      first_is_accept = h.net.sights[i].type == FrameType::HopAccept;
      break;
    }
  }
  CHECK(first_is_accept);
}

// D4-04: bounded capacity — the per-origin cap rejects spoofed-flood
// admissions and the flow descriptor table stays bounded. The origin cap is
// exercised through crafted transit forwards (delivery slots are 8, below
// the 12-job origin cap, so self-sends cannot reach it).
// flow_overflow_merged is a by-construction fallback: descriptors are
// released with their last job, so live flows can never outnumber live jobs.
void test_flow_caps() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(3);
  (void)h.add(4);
  (void)h.add(6);
  h.link(1, 3);
  h.link(1, 4);
  h.link(1, 6);

  // 12 forwards claiming the SAME origin, alternating two sender scopes so
  // the per-origin cap (not the per-scope cap) is what trips.
  for (std::uint64_t i = 1; i <= 12; ++i) {
    const NodeId peer = (i % 2 == 0) ? 3 : 4;
    inject(h, 1, peer, craft_transit(h.cipher, peer, 1, 999, 6, i));
    h.step(1);  // drains the accept; the forward job accumulates
    ++h.now;
  }
  const NodeId peer = 3;
  inject(h, 1, peer, craft_transit(h.cipher, peer, 1, 999, 6, 13));
  CHECK(h.observer(1)->has_diag("TRANSIT_ADMISSION_DENIED"));
  CHECK(a->congestion_stats().busy_send_failed >= 1);  // legacy peer: counted drop
  CHECK(a->congestion_stats().flows_active <= kFlowDescriptorsMax);
  CHECK(a->congestion_stats().flow_overflow_merged == 0);
}

// D4-03/D4-08: BUSY emission on a real admission failure (per-sender scope
// cap) and dispatch of the Busy(20) frame back to the rejected peer.
void test_busy_emission() {
  Harness h;
  MeshNode* p = h.add(3);
  MeshNode* b = h.add(2);
  (void)h.add(4);  // Q: transit destination next-hop
  h.link(3, 2);
  h.link(2, 4);
  b->set_peer_busy_capable(3, true);

  // 12 transit DATA from P with distinct origins fill the per-scope cap.
  for (std::uint64_t i = 1; i <= 12; ++i) {
    inject(h, 2, 3, craft_transit(h.cipher, 3, 2, 1000 + i, 4, i));
    h.step(2);  // drains the HOP_ACCEPT so the control lane stays usable
    ++h.now;
  }
  const std::size_t sights_before = h.net.sights.size();
  inject(h, 2, 3, craft_transit(h.cipher, 3, 2, 2000, 4, 13));
  CHECK(b->congestion_stats().busy_sent == 1);

  h.step(2);  // BUSY leaves via the reserved control lane
  bool busy_seen = false;
  for (std::size_t i = sights_before; i < h.net.sights.size(); ++i) {
    if (h.net.sights[i].type == FrameType::Busy && h.net.sights[i].from == 2 &&
        h.net.sights[i].to == 3) {
      busy_seen = true;
    }
  }
  CHECK(busy_seen);
  CHECK(p->congestion_stats().busy_received == 1);
  // The BUSY references a job P never really sent — unmatched, never acted on.
  CHECK(p->congestion_stats().busy_unmatched == 1);
}

// D4-09: a peer that has not proven BUSY capability gets the legacy silent
// drop + counted failure — the payload is never emitted toward it.
void test_busy_legacy_peer() {
  Harness h;
  MeshNode* b = h.add(2);
  (void)h.add(3);
  (void)h.add(4);
  h.link(3, 2);
  h.link(2, 4);
  // NB: no set_peer_busy_capable — P is a legacy peer.

  for (std::uint64_t i = 1; i <= 12; ++i) {
    inject(h, 2, 3, craft_transit(h.cipher, 3, 2, 1000 + i, 4, i));
    h.step(2);
    ++h.now;
  }
  const std::size_t sights_before = h.net.sights.size();
  inject(h, 2, 3, craft_transit(h.cipher, 3, 2, 2000, 4, 13));
  CHECK(b->congestion_stats().busy_sent == 0);
  CHECK(b->congestion_stats().busy_send_failed >= 1);
  for (std::size_t i = sights_before; i < h.net.sights.size(); ++i) {
    CHECK(h.net.sights[i].type != FrameType::Busy);
  }
}

// D4-03/D4-08: an authenticated BUSY matching a pending (peer, MessageId,
// round) defers the exchange by the clamped retry_after, then re-admits the
// job for a fresh transmission — separate from RF-loss accounting.
void test_busy_deferral_readmission() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);

  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  // TX1 on air; job parks in awaiting-hop (B never answers)
  drive_tx(h, 1, data.sequence, 1);
  CHECK(h.data_sights(data.sequence) == 1);
  CHECK(a->peer_tx_window(2) == kPeerWindowInitial);

  auto busy = busy_for(data, 1, 0, 50, 1);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, busy, 1));
  CHECK(a->congestion_stats().busy_received == 1);
  CHECK(a->peer_tx_window(2) == kPeerWindowMin);  // window collapsed to 1

  h.now += 60;  // past the 50ms deferral
  drive_tx(h, 1, data.sequence, 2);
  CHECK(a->congestion_stats().busy_readmitted == 1);
  CHECK(h.data_sights(data.sequence) == 2);  // retransmitted after readmission
}

// D4-03: retry_after is clamped into [20, 1000] ms on receipt.
void test_busy_retry_clamp() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);

  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);

  // retry_after=1ms must clamp UP to 20ms: no early readmission.
  auto low = busy_for(data, 1, 0, 1, 1);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, low, 1));
  h.now += 19;
  h.step(1);
  CHECK(a->congestion_stats().busy_readmitted == 0);
  h.now += 2;  // now at +21 > +20 clamp floor
  drive_tx(h, 1, data.sequence, 2);
  CHECK(a->congestion_stats().busy_readmitted == 1);
  CHECK(h.data_sights(data.sequence) == 2);

  // retry_after=99999ms must clamp DOWN to 1000ms.
  auto high = busy_for(data, 1, 0, 99999, 2);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, high, 2));
  h.now += 999;
  h.step(1);
  CHECK(a->congestion_stats().busy_readmitted == 1);
  h.now += 2;  // +1001 > +1000 clamp ceiling
  drive_tx(h, 1, data.sequence, 3);
  CHECK(a->congestion_stats().busy_readmitted == 2);
  CHECK(h.data_sights(data.sequence) == 3);
}

// D4-03: stale/replayed feedback sequences are rejected per-peer.
void test_busy_stale_sequence() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);

  auto fresh = busy_for(data, 1, 0, 50, 7);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, fresh, 1));
  CHECK(a->congestion_stats().busy_received == 1);

  auto replay = busy_for(data, 1, 0, 50, 7);   // same sequence again
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, replay, 2));
  auto older = busy_for(data, 1, 0, 50, 3);   // and an older one
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, older, 3));
  CHECK(a->congestion_stats().busy_stale == 2);
  CHECK(a->congestion_stats().busy_received == 1);  // stale ones don't count
}

// D4-03: a BUSY for the wrong delivery round or from the wrong peer must not
// touch the pending exchange — it falls back to the RF-loss retry path.
void test_busy_wrong_round_and_peer() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  (void)h.add(3);
  h.link(1, 2);
  h.link(1, 3);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);

  auto wrong_round = busy_for(data, 1, /*round=*/1, 50, 1);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, wrong_round, 1));
  auto wrong_peer = busy_for(data, 1, 0, 50, 2);
  inject(h, 1, 3, craft_busy(h.cipher, 3, 1, wrong_peer, 2));
  CHECK(a->congestion_stats().busy_unmatched == 2);
  CHECK(a->congestion_stats().busy_readmitted == 0);

  // The exchange stays on the RF-loss track: HOP_ACCEPT timeout, retry #2.
  h.now += 70;
  drive_tx(h, 1, data.sequence, 2);
  CHECK(h.data_sights(data.sequence) == 2);
}

// D4-03: unauthenticated traffic never reaches the BUSY handler — a
// corrupted link tag fails open_link; a BUSY addressed elsewhere fails the
// scope check.
void test_busy_unauthenticated() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  (void)h.add(3);
  h.link(1, 2);
  h.link(1, 3);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);

  auto payload = busy_for(data, 1, 0, 50, 1);
  auto forged = craft_busy(h.cipher, 2, 1, payload, 1);
  forged.bytes[forged.size - 1] ^= 0xFF;  // break the link tag
  inject(h, 1, 2, forged);
  CHECK(a->congestion_stats().busy_received == 0);
  CHECK(!h.observer(1)->diagnostics.empty());

  // Valid auth but addressed to a different node: out of scope.
  auto offscope = craft_busy(h.cipher, 2, 3, payload, 2);
  // Re-mint addressed to us but with destination field pointing at node 3:
  // craft_busy sets destination=to; rebuild a proper scoped-miss frame.
  wire::PlainFrame plain{};
  plain.header = mk_header(FrameType::Busy, 2, 3, 2, 1, MessageId{777, 9});
  autonomy::EncodedPayload body{};
  CHECK_OK(autonomy::busy_encode(payload, body));
  plain.payload_size = body.size;
  std::memcpy(plain.payload.data(), body.bytes.data(), body.size);
  wire::EncodedFrame scoped{};
  CHECK_OK(wire::encode_new(plain, h.cipher, scoped));
  (void)offscope;
  inject(h, 1, 2, scoped);
  CHECK(a->congestion_stats().busy_received == 0);
  CHECK(h.observer(1)->has_diag("BUSY_SCOPE_REJECTED"));
}

// D4-08: the per-peer HOP_ACCEPT window collapses to 1 on an authenticated
// BUSY and regrows by one after 8 consecutive authenticated accepts. Memory
// slots and window are independent: accepts grow the window, not the pool.
void test_peer_window_shrink_grow() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  CHECK(a->peer_tx_window(2) == kPeerWindowInitial);  // 2

  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);
  auto busy = busy_for(data, 1, 0, 50, 1);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, busy, 1));
  CHECK(a->peer_tx_window(2) == kPeerWindowMin);  // 1

  // Complete the deferred exchange with an authenticated accept, then run 7
  // more exchanges: 8 consecutive accepts regrow the window by one.
  inject(h, 1, 2, craft_accept(h.cipher, 2, 1, FrameType::Data, 1, data, 0, 1));
  for (int i = 1; i < 8; ++i) {
    MessageId next{};
    CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, next));
    // Window is 1: other queued work may take the dispatch turn first, so
    // drive until this delivery is actually on the air before accepting it.
    drive_tx(h, 1, next.sequence, 1);
    CHECK(h.data_sights(next.sequence) == 1);
    inject(h, 1, 2,
           craft_accept(h.cipher, 2, 1, FrameType::Data, 1, next, 0,
                        static_cast<std::uint64_t>(i + 1)));
    ++h.now;
  }
  CHECK(a->peer_tx_window(2) == kPeerWindowInitial);
}

// D4-08: bounded attempt budgets — RF loss retries stop at max_link_attempts
// (2), BUSY readmissions at 4, and a BUSY never extends the original
// deadline. With max_end_to_end_rounds=1 the delivery fails terminally.
void test_attempt_budgets() {
  // RF-loss bound: exactly 2 transmissions, then terminal failure.
  Harness h;
  MeshNode* a = h.add(1, /*rounds=*/1, /*attempts=*/2);
  (void)h.add(2);
  h.link(1, 2);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);                                 // TX1
  h.now += 70;
  drive_tx(h, 1, data.sequence, 2);          // timeout -> retry -> TX2
  CHECK(h.data_sights(data.sequence) == 2);
  h.now += 70;
  h.step(1);                                 // attempts exhausted -> Failed
  CHECK(h.data_sights(data.sequence) == 2);
  CHECK(a->delivery(data).state == DeliveryState::Failed);

  // BUSY-readmission bound: 4 readmissions = 5 transmissions, then
  // BUSY_BUDGET_EXHAUSTED. Each deferral needs a fresh feedback sequence.
  Harness h2;
  MeshNode* a2 = h2.add(1, /*rounds=*/1, /*attempts=*/2);
  (void)h2.add(2);
  h2.link(1, 2);
  MessageId d2{};
  CHECK_OK(a2->send(2, payload_view(), SendOptions{}, h2.now, d2));
  drive_tx(h2, 1, d2.sequence, 1);           // TX1
  for (std::uint32_t i = 1; i <= 4; ++i) {
    auto busy = busy_for(d2, 1, 0, 50, i);
    inject(h2, 1, 2, craft_busy(h2.cipher, 2, 1, busy, i));
    h2.now += 60;
    drive_tx(h2, 1, d2.sequence, i + 1);     // readmitted -> next TX
    CHECK(h2.data_sights(d2.sequence) == i + 1);
  }
  // The 5th deferral exhausts busy_readmissions_max=4: terminal failure.
  auto last = busy_for(d2, 1, 0, 50, 5);
  inject(h2, 1, 2, craft_busy(h2.cipher, 2, 1, last, 5));
  h2.now += 60;
  h2.step(1);
  CHECK(h2.data_sights(d2.sequence) == 5);   // 1 + 4 readmissions, no 6th TX
  CHECK(a2->congestion_stats().busy_readmitted == 4);
  CHECK(a2->delivery(d2).state == DeliveryState::Failed);
}

// D4-04: queue watermarks — at >=80% pool occupancy new bulk admissions are
// explicitly rejected while higher classes are still admitted. The pool is
// filled with crafted transit forwards (delivery slots cap self-sends at 8).
void test_watermarks() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(3);
  (void)h.add(4);
  (void)h.add(5);
  (void)h.add(6);  // transit next-hop
  h.link(1, 3);
  h.link(1, 4);
  h.link(1, 5);
  h.link(1, 6);

  // 26 forwards accumulate; each step drains that frame's control-lane
  // accept. Cycling three sender scopes keeps every cap below its bound.
  for (std::uint64_t i = 1; i <= 26; ++i) {
    const NodeId peer = 3 + (i % 3);
    inject(h, 1, peer, craft_transit(h.cipher, peer, 1, 5000 + i, 6, i));
    h.step(1);
    ++h.now;
  }
  // 26 forwards + 1 boot-time route advertisement = 27/32 (84%) — the
  // bulk-stop watermark is active.
  CHECK(a->congestion_stats().queued == 27);

  SendOptions bulk{};
  bulk.delivery = DeliveryClass::BestEffort;
  bulk.priority = Priority::Bulk;
  MessageId id{};
  const auto refused = a->send(6, payload_view(), bulk, h.now, id);
  CHECK(!refused.ok());  // explicit rejection, not a silent queue
  CHECK(a->congestion_stats().bulk_suspended >= 1);

  // Non-bulk admission still works at the watermark (normal-class forward).
  inject(h, 1, 3, craft_transit(h.cipher, 3, 1, 7777, 6, 99));
  CHECK(a->congestion_stats().queued == 29);  // accept + forward admitted
}

// D4-10: BUSY never cancels accepted work. A deferred exchange that still
// receives its HOP_ACCEPT completes normally; a BUSY referencing finished
// work is unmatched and harmless; a PressureHint only steps the window down.
void test_busy_never_cancels() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);

  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);

  auto busy = busy_for(data, 1, 0, 50, 1);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, busy, 1));
  // The accept still lands: deferred does not mean cancelled.
  inject(h, 1, 2, craft_accept(h.cipher, 2, 1, FrameType::Data, 1, data, 0, 1));
  CHECK(a->delivery(data).state == DeliveryState::WaitingForEndReceipt);

  // A BUSY referencing the now-finished exchange is unmatched and harmless.
  auto late = busy_for(data, 1, 0, 50, 2);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, late, 2));
  CHECK(a->congestion_stats().busy_unmatched == 1);
  CHECK(a->delivery(data).state == DeliveryState::WaitingForEndReceipt);

  // PressureHint: slows us down (window -1) but never touches accepted work.
  autonomy::BusyPayload hint{};
  hint.subtype = autonomy::BusySubtype::PressureHint;
  hint.reason = autonomy::BusyReason::QueueFull;
  hint.feedback_sequence = FeedbackSequence{3};
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, hint, 3));
  CHECK(a->congestion_stats().busy_received == 3);
  CHECK(a->delivery(data).state == DeliveryState::WaitingForEndReceipt);
}

// D4-05 groundwork: observation buckets aggregate sojourn/service/hop/final
// counters per bounded key — no raw samples, no route-metric coupling yet.
void test_observation_buckets() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);
  auto busy = busy_for(data, 1, 0, 50, 1);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, busy, 1));
  h.now += 60;
  drive_tx(h, 1, data.sequence, 2);  // readmission TX

  std::size_t buckets = 0;
  std::uint64_t submitted = 0, deferrals = 0, service = 0;
  a->for_each_observation([&](const ObservationBucket& bucket) {
    ++buckets;
    submitted += bucket.tx_submitted;
    deferrals += bucket.busy_deferrals;
    service += bucket.service_samples;
  });
  CHECK(buckets >= 1);
  CHECK(submitted >= 2);       // TX1 + readmitted TX2
  CHECK(deferrals == 1);       // the BUSY deferral, separate from RF loss
  CHECK(service >= 2);         // driver accept -> TX callback samples
}

// D4-03: BUSY is link-scoped feedback — the claimed origin must BE the
// immediate peer, and an end-protected BUSY is out of scope entirely (a
// relay cannot end-sign toward the origin).
void test_busy_origin_mismatch() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  (void)h.add(3);
  h.link(1, 2);
  h.link(1, 3);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);

  auto busy = busy_for(data, 1, 0, 50, 1);
  autonomy::EncodedPayload body{};
  CHECK_OK(autonomy::busy_encode(busy, body));

  // origin=3 arriving over the link from peer 2: not this link's feedback.
  wire::EncodedFrame relayed = craft_frame(
      h.cipher,
      mk_header(FrameType::Busy, 3, 1, 2, 1, MessageId{777, 5}),
      body.view());
  inject(h, 1, 2, relayed);
  CHECK(a->congestion_stats().busy_received == 0);
  CHECK(h.observer(1)->has_diag("BUSY_SCOPE_REJECTED"));

  // End-protected BUSY from the peer itself: still out of scope.
  wire::EncodedFrame protected_busy = craft_frame(
      h.cipher,
      mk_header(FrameType::Busy, 2, 1, 2, 1, MessageId{777, 6},
                wire::kFlagEndProtected),
      body.view());
  inject(h, 1, 2, protected_busy);
  CHECK(a->congestion_stats().busy_received == 0);
  CHECK(a->peer_tx_window(2) == kPeerWindowInitial);  // never throttled
}

// D4-03/§6.2: a zero-pressure hint carries no busy claim — it must not
// throttle the window or establish a busy condition.
void test_busy_zero_pressure_hint() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);
  CHECK(a->peer_tx_window(2) == kPeerWindowInitial);

  autonomy::BusyPayload hint{};
  hint.subtype = autonomy::BusySubtype::PressureHint;
  hint.reason = autonomy::BusyReason::QueueFull;
  hint.pressure = 0;
  hint.feedback_sequence = FeedbackSequence{1};
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, hint, 1));
  CHECK(a->congestion_stats().busy_received == 1);
  CHECK(a->peer_tx_window(2) == kPeerWindowInitial);  // no throttle
  CHECK(a->peer_busy_since(2) == 0);                // no busy condition
}

// D4-03: feedback sequence ordering uses RFC 1982 serial arithmetic — a
// sequence that wraps past u32 max must still be accepted as fresher, and a
// genuinely older one rejected.
void test_busy_feedback_wrap() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);

  // Establish a sequence near the u32 wrap boundary.
  auto near_max = busy_for(data, 1, 0, 50, 0xFFFFFFFEu);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, near_max, 1));
  CHECK(a->congestion_stats().busy_received == 1);

  // Wrapped successor (diff = +3 mod 2^32): fresh, must be accepted.
  auto wrapped = busy_for(data, 1, 0, 50, 1);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, wrapped, 2));
  CHECK(a->congestion_stats().busy_received == 2);
  CHECK(a->congestion_stats().busy_stale == 0);

  // A sequence behind the boundary (diff negative): stale, rejected.
  auto older = busy_for(data, 1, 0, 50, 0xFFFFFFFDu);
  inject(h, 1, 2, craft_busy(h.cipher, 2, 1, older, 3));
  CHECK(a->congestion_stats().busy_received == 2);
  CHECK(a->congestion_stats().busy_stale == 1);
}

// Issue #50-2 invariant: when the 8-slot hop-wait table is full, a new
// exchange must defer at select and burn zero attempt budget — capacity is
// not RF loss. The blocked job transmits only after a slot frees. The
// blocked job is a transit forward (delivery slots are 8 too, so a ninth
// origin send() cannot even be created — a relay needs no delivery record).
void test_awaiting_full_defers_without_attempts() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  (void)h.add(5);  // transit source, a neighbor of the relay under test
  h.link(1, 2);
  h.link(1, 5);

  // Park then BUSY-defer all 8 awaiting slots: each filler transmits once,
  // then an authenticated BUSY(1000) holds the slot ~1s. Deferred slots are
  // not inflight, so the peer window (initial 2) never gates this setup.
  constexpr std::size_t kAwaitingSlots = 8;
  std::array<MessageId, kAwaitingSlots> ids{};
  for (std::size_t i = 0; i < ids.size(); ++i) {
    CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, ids[i]));
    drive_tx(h, 1, ids[i].sequence, 1);
    auto busy = busy_for(ids[i], 1, 0, 1000, static_cast<std::uint32_t>(i + 1));
    inject(h, 1, 2, craft_busy(h.cipher, 2, 1, busy, 100 + i));
  }
  CHECK(a->congestion_stats().busy_received == kAwaitingSlots);

  // The over-capacity job: transit DATA arriving from neighbor 5 bound for
  // direct peer 2. Every select defers it on the full table — zero
  // transmissions, i.e. zero attempts burned, while the wait itself must
  // not fail it.
  constexpr std::uint64_t kTransitSeq = 42;
  inject(h, 1, 5, craft_transit(h.cipher, 5, 1, 999, 2, kTransitSeq));
  for (int i = 0; i < 200; ++i) {  // ~200ms inside the deferral window
    h.step(1);
    ++h.now;
  }
  CHECK(h.data_sights(kTransitSeq) == 0);

  // Deferred fillers drain (~+1s plus hop-accept churn): the transit job
  // then transmits on its own budget — proof the capacity wait consumed
  // nothing.
  for (int i = 0; i < 3000 && h.data_sights(kTransitSeq) == 0; ++i) {
    h.step(1);
    ++h.now;
  }
  CHECK(h.data_sights(kTransitSeq) >= 1);
}

}  // namespace

int main() {
  test_drr_fairness();
  test_control_lane();
  test_flow_caps();
  test_busy_emission();
  test_busy_legacy_peer();
  test_busy_deferral_readmission();
  test_busy_retry_clamp();
  test_busy_stale_sequence();
  test_busy_wrong_round_and_peer();
  test_busy_unauthenticated();
  test_busy_origin_mismatch();
  test_busy_zero_pressure_hint();
  test_busy_feedback_wrap();
  test_peer_window_shrink_grow();
  test_awaiting_full_defers_without_attempts();
  test_attempt_budgets();
  test_watermarks();
  test_busy_never_cancels();
  test_observation_buckets();
  if (failures == 0) {
    std::printf("RouteLoom congestion tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d congestion checks failed\n", failures);
  return 1;
}
