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

  MeshNode* add(NodeId id, std::uint8_t rounds = 3, std::uint8_t attempts = 2,
                std::uint32_t adv_ms = 30000, std::uint32_t life_ms = 60000,
                bool budget_gate = false) {
    NodeConfig cfg{};
    cfg.network = kNet;
    cfg.node = id;
    cfg.message_session = 100 + static_cast<std::uint32_t>(id);
    cfg.route_generation = 1;
    cfg.route_advertisement_period_ms = adv_ms;  // default: one boot ad, then quiet
    cfg.route_lifetime_ms = life_ms;
    cfg.control_budget_gate_enabled = budget_gate;
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
// The retry path adds link-jitter (radio.md §8, <=20 ms) before a
// retransmission is select-eligible — the step budget must outlast it.
void drive_tx(Harness& h, NodeId id, std::uint64_t seq, std::size_t expected,
              int max_steps = 64) {
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

  // 14 forwards claiming the SAME origin, alternating two sender scopes so
  // the per-origin cap (not the per-scope cap) is what trips. Each step
  // drains the accept AND sends the next queued job inside the same flush
  // (TX-complete submits directly) — the peer window holds 2 forwards in
  // flight, so 14 admissions leave 12 pooled against the cap.
  for (std::uint64_t i = 1; i <= 14; ++i) {
    const NodeId peer = (i % 2 == 0) ? 3 : 4;
    inject(h, 1, peer, craft_transit(h.cipher, peer, 1, 999, 6, i));
    h.step(1);  // drains the accept; the forward job accumulates
    ++h.now;
  }
  const NodeId peer = 3;
  inject(h, 1, peer, craft_transit(h.cipher, peer, 1, 999, 6, 15));
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

  // 14 transit DATA from P with distinct origins fill the per-scope cap.
  // Each step drains the accept AND sends the next queued job inside the
  // same flush (TX-complete submits directly) — the peer window holds 2
  // forwards in flight, so 14 admissions leave 12 pooled against the cap.
  for (std::uint64_t i = 1; i <= 14; ++i) {
    inject(h, 2, 3, craft_transit(h.cipher, 3, 2, 1000 + i, 4, i));
    h.step(2);  // drains the HOP_ACCEPT so the control lane stays usable
    ++h.now;
  }
  const std::size_t sights_before = h.net.sights.size();
  inject(h, 2, 3, craft_transit(h.cipher, 3, 2, 2000, 4, 15));
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
  // NB: no set_peer_busy_capable — P is a legacy peer. Two forwards go
  // in flight under the peer window while each step drains the rest, so
  // 14 admissions leave the per-scope cap full.
  for (std::uint64_t i = 1; i <= 14; ++i) {
    inject(h, 2, 3, craft_transit(h.cipher, 3, 2, 1000 + i, 4, i));
    h.step(2);
    ++h.now;
  }
  const std::size_t sights_before = h.net.sights.size();
  inject(h, 2, 3, craft_transit(h.cipher, 3, 2, 2000, 4, 15));
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

  // 29 forwards accumulate; each step drains that frame's control-lane
  // accept AND sends the next queued job inside the same flush — the peer
  // window holds 2 forwards in flight (the boot advertisement is drained
  // too), leaving 27 pooled. Cycling three sender scopes keeps every cap
  // below its bound.
  for (std::uint64_t i = 1; i <= 29; ++i) {
    const NodeId peer = 3 + (i % 3);
    inject(h, 1, peer, craft_transit(h.cipher, peer, 1, 5000 + i, 6, i));
    h.step(1);
    ++h.now;
  }
  // 27 pooled forwards = 27/32 (84%) — the bulk-stop watermark is active.
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

// radio.md §8 (#45): per-peer link RTT EWMA replaces the fixed 60 ms
// hop-accept deadline — clamp(ewma*2, 20, 250). Scripted accepts at
// controlled delays populate the EWMA; a silent exchange then exposes the
// adapted deadline through its retry timing.
void test_adaptive_hop_timeout_shrinks() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);   // never polled: only our scripted accepts land
  h.link(1, 2);

  // Three ~10 ms accepts seed the per-peer EWMA (first sample seeds it).
  for (int s = 0; s < 3; ++s) {
    MessageId m{};
    CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, m));
    drive_tx(h, 1, m.sequence, 1);
    h.now += 10;
    inject(h, 1, 2, craft_accept(h.cipher, 2, 1, FrameType::Data, 1, m, 0,
                                 static_cast<std::uint64_t>(s + 1)));
  }
  // The previously dead window fields are now populated by the accept path
  // (the small DATA frame lands in frame-length class 2 once the #46
  // fixed per-frame charge is included).
  const ObservationKey key{BindingGeneration{0}, ObservationDirection::Egress,
                           RadioGeneration{0}, ChannelEpoch{0}, 2, 2};
  const ObservationBucket* bucket = a->telemetry_bucket(key);
  CHECK(bucket != nullptr);
  if (bucket == nullptr) return;
  CHECK(bucket->current.hop_rtt_samples == 3);
  CHECK(bucket->current.hop_accepts >= 3);
  CHECK(bucket->current.hop_rtt_us_ewma >= 9000 &&
        bucket->current.hop_rtt_us_ewma <= 12000);

  // ewma ~= 10 ms -> effective = clamp(20, 20, 250) = 20 ms: a silent
  // exchange now expires far inside the old fixed 60 ms.
  MessageId silent{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, silent));
  drive_tx(h, 1, silent.sequence, 1);
  h.now += 14;
  h.step(1);
  h.step(1);
  CHECK(h.data_sights(silent.sequence) == 1);  // ~+15 ms: still awaiting
  h.now += 35;
  drive_tx(h, 1, silent.sequence, 2);          // expired ~+20 -> retry TX2
  CHECK(h.data_sights(silent.sequence) == 2);
}

// Same mechanism upward: a measured RTT above half the base lifts the
// deadline past 60 ms, and a large EWMA caps it at the spec's 250 ms.
void test_adaptive_hop_timeout_expands_and_caps() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);

  for (int s = 0; s < 2; ++s) {
    MessageId m{};
    CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, m));
    drive_tx(h, 1, m.sequence, 1);
    h.now += 55;
    inject(h, 1, 2, craft_accept(h.cipher, 2, 1, FrameType::Data, 1, m, 0,
                                 static_cast<std::uint64_t>(s + 10)));
  }
  // ewma ~= 55 ms -> effective ~= 110 ms: the old 60 ms fixed timeout would
  // already have retried here.
  MessageId mid{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, mid));
  drive_tx(h, 1, mid.sequence, 1);
  h.now += 65;
  h.step(1);
  h.step(1);
  CHECK(h.data_sights(mid.sequence) == 1);
  h.now += 80;
  drive_tx(h, 1, mid.sequence, 2);
  CHECK(h.data_sights(mid.sequence) == 2);

  // Cap: feed samples just inside each successive effective deadline —
  // the EWMA climbs until clamp(ewma*2) saturates at 250 ms. Transit
  // forwards run the same awaiting/accept path without spending the
  // bounded delivery table.
  Harness h2;
  MeshNode* a2 = h2.add(1);
  (void)h2.add(2);
  (void)h2.add(3);
  h2.link(1, 2);
  h2.link(1, 3);
  const ObservationKey key{BindingGeneration{0}, ObservationDirection::Egress,
                           RadioGeneration{0}, ChannelEpoch{0}, 2, 3};
  for (int s = 0; s < 14; ++s) {
    const ObservationBucket* b = a2->telemetry_bucket(key);
    const std::uint32_t ewma_ms =
        b != nullptr ? b->current.hop_rtt_us_ewma / 1000 : 0;
    if (ewma_ms * 2 >= kLinkRtoMaxMs) break;
    const std::uint64_t seq = 500 + static_cast<std::uint64_t>(s);
    inject(h2, 1, 2,
           craft_transit(h2.cipher, 2, 1, 5000 + s, 3, seq));
    drive_tx(h2, 1, seq, 1);
    h2.now += ewma_ms == 0
                  ? 59
                  : std::min<std::uint32_t>(2 * ewma_ms, kLinkRtoMaxMs) - 10;
    inject(h2, 1, 3,
           craft_accept(h2.cipher, 3, 1, FrameType::Data, 5000 + s,
                        MessageId{42, seq}, 0, static_cast<std::uint64_t>(s + 20)));
  }
  const ObservationBucket* b = a2->telemetry_bucket(key);
  CHECK(b != nullptr && b->current.hop_rtt_us_ewma / 1000 * 2 >= kLinkRtoMaxMs);
  // A silent transit forward now expires at the 250 ms ceiling, not the
  // old 60 ms.
  const std::uint64_t capped_seq = 999;
  inject(h2, 1, 2, craft_transit(h2.cipher, 2, 1, 7000, 3, capped_seq));
  drive_tx(h2, 1, capped_seq, 1);
  h2.now += 245;
  h2.step(1);
  h2.step(1);
  CHECK(h2.data_sights(capped_seq) == 1);
  h2.now += 45;
  drive_tx(h2, 1, capped_seq, 2);
  CHECK(h2.data_sights(capped_seq) == 2);
}

// PR review (#45 follow-up): the HOP_ACCEPT match key carries no attempt
// discriminator, so a delayed accept landing after a retransmission may
// answer an earlier attempt — measuring `now - sent_at_ms` against the
// latest send would learn a too-short RTT. Retransmitted exchanges still
// resolve the accept but feed nothing into RTO adaptation.
void test_retransmitted_exchange_not_rtt_sampled() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);   // never polled: only our scripted accepts land
  h.link(1, 2);

  // First TX ~1 ms; the unmeasured peer waits the configured 60 ms.
  MessageId m{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, m));
  drive_tx(h, 1, m.sequence, 1);

  // Past the awaiting deadline: expiry re-queues the retry under jitter,
  // then the retransmission lands (portable repro: retry ~78 ms).
  h.now += 77;
  h.step(1);
  drive_tx(h, 1, m.sequence, 2);

  // The delayed accept for the first attempt arrives ~2 ms after the
  // retry went out — ambiguous, so it resolves without an RTT sample.
  h.now += 2;
  inject(h, 1, 2, craft_accept(h.cipher, 2, 1, FrameType::Data, 1, m, 0, 77));

  const ObservationKey key{BindingGeneration{0}, ObservationDirection::Egress,
                           RadioGeneration{0}, ChannelEpoch{0}, 2, 2};
  const ObservationBucket* bucket = a->telemetry_bucket(key);
  CHECK(bucket != nullptr);
  if (bucket == nullptr) return;
  CHECK(bucket->current.hop_accepts == 1);
  CHECK(bucket->current.hop_rtt_samples == 0);

  // RTO keeps the configured 60 ms: stepped in 1 ms ticks, the follow-up
  // delivery sees just one transmission inside that window — a collapsed
  // 20 ms RTO would have expired and re-sent (2 sights) before it ends.
  MessageId next{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, next));
  drive_tx(h, 1, next.sequence, 1);
  for (int t = 0; t < 50; ++t) {
    h.step(1);
    ++h.now;
  }
  CHECK(h.data_sights(next.sequence) == 1);
}

// radio.md §8 + 04 §4.2 (#45): the populated hop-RTT EWMA must carry its
// wire validity bit — a nonzero measurement flagged absent is discarded by
// receivers honoring the flag, and a class with no contributing samples
// reports zero with the bit clear.
void test_telemetry_hop_rtt_validity_bit() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);

  MessageId m{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, m));
  drive_tx(h, 1, m.sequence, 1);
  h.now += 10;
  inject(h, 1, 2, craft_accept(h.cipher, 2, 1, FrameType::Data, 1, m, 0, 1));

  TelemetryQuery query{};
  query.request_id = 7;
  query.peer = 2;
  query.direction = ObservationDirection::Egress;
  query.length_class = 2;  // small DATA + #46 fixed charge
  TelemetrySnapshot snap{};
  DiagnosticRejectReason reason{};
  CHECK_OK(a->build_telemetry_snapshot(query, h.now, snap, reason));
  CHECK((snap.validity & kTelemetryValidHopRttEwma) != 0);
  CHECK(snap.hop_rtt_us_ewma != 0);

  query.length_class = 1;
  TelemetrySnapshot empty{};
  CHECK_OK(a->build_telemetry_snapshot(query, h.now, empty, reason));
  CHECK((empty.validity & kTelemetryValidHopRttEwma) == 0);
  CHECK(empty.hop_rtt_us_ewma == 0);
}

// radio.md §8 (#45): a link retry is re-queued with jittered not_before —
// 0..20 ms normally, 20..100 ms while the peer reports busy — so a frozen
// clock can never trigger the retransmission.
void test_link_retry_jitter() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);
  h.now += 70;   // awaiting deadline crossed
  h.step(1);     // expiry processed -> retry re-queued with jitter
  // The deterministic first jitter on node 1 is nonzero (17 ms): at a
  // frozen clock the retry stays queued, unlike the old immediate path.
  h.step(1);
  h.step(1);
  CHECK(h.data_sights(data.sequence) == 1);
  h.now += 25;   // past the 20 ms bound -> eligible
  drive_tx(h, 1, data.sequence, 2);
  CHECK(h.data_sights(data.sequence) == 2);

  // Congested range: a matched BUSY Reject marks the peer busy, then a
  // timed-out retry is held back >=20 ms and <=100 ms.
  Harness h2;
  MeshNode* a2 = h2.add(1);
  (void)h2.add(2);
  h2.link(1, 2);
  MessageId busy_job{};
  CHECK_OK(a2->send(2, payload_view(), SendOptions{}, h2.now, busy_job));
  drive_tx(h2, 1, busy_job.sequence, 1);
  auto reject = busy_for(busy_job, 1, 0, 50, 1);
  inject(h2, 1, 2, craft_busy(h2.cipher, 2, 1, reject, 1));
  MessageId j2{};
  CHECK_OK(a2->send(2, payload_view(), SendOptions{}, h2.now, j2));
  drive_tx(h2, 1, j2.sequence, 1);
  h2.now += 70;
  h2.step(1);    // j2 expiry -> retry held 20..100 ms
  h2.now += 15;
  h2.step(1);
  h2.step(1);
  CHECK(h2.data_sights(j2.sequence) == 1);   // not_before >= +20
  h2.now += 100;                             // not_before <= +100
  drive_tx(h2, 1, j2.sequence, 2);
  CHECK(h2.data_sights(j2.sequence) == 2);
}

// radio.md §8 (#45): the adaptive floor is also the config floor — a
// hop_accept_timeout_ms below 20 ms can only violate the physical bound.
void test_hop_timeout_config_floor() {
  NodeConfig cfg{};
  cfg.network = kNet;
  cfg.node = 1;
  cfg.message_session = 101;
  cfg.route_generation = 1;
  cfg.route_advertisement_period_ms = 30000;
  cfg.route_lifetime_ms = 60000;
  cfg.max_link_attempts = 2;
  cfg.max_end_to_end_rounds = 3;
  SimNetwork net;
  TestSecurity cipher;
  CapturingObserver observer;
  SimRadio radio(net, 1);

  cfg.hop_accept_timeout_ms = kLinkRtoMinMs - 1;
  MeshNode low(cfg, radio, cipher, observer);
  CHECK(low.start(0).code == StatusCode::InvalidArgument);

  cfg.hop_accept_timeout_ms = kLinkRtoMinMs;
  MeshNode floor(cfg, radio, cipher, observer);
  CHECK_OK(floor.start(0));
}


// --- issue #46: transmission-budget accounting (radio.md §9/§14) -------------

std::size_t route_ads(const Harness& h, NodeId from) {
  std::size_t count = 0;
  for (const auto& s : h.net.sights) {
    if (s.type == FrameType::RouteUpdate && s.from == from) ++count;
  }
  return count;
}

// #46 fixed cost: the DRR charge includes the pinned per-frame fixed cost —
// a small body lands in the largest frame-length class where body-only
// accounting left it mid-sized (88 hdr + 16 tag + 96 fixed + 15 payload =
// 215B estimated; the pre-fix 119B sat in class 1).
void test_charge_fixed_cost() {
  Harness h;
  MeshNode* a = h.add(1);
  (void)h.add(2);
  h.link(1, 2);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);

  const ObservationKey large{BindingGeneration{0}, ObservationDirection::Egress,
                             RadioGeneration{0}, ChannelEpoch{0}, 2, 2};
  const ObservationBucket* bucket = a->telemetry_bucket(large);
  CHECK(bucket != nullptr);
  if (bucket != nullptr) CHECK(bucket->tx_submitted >= 2);  // boot ad + DATA
  // Submission-side class moves 1 -> 2 under the fixed charge (the obs-side
  // class-0 bucket from driver callbacks is unchanged and not asserted).
  const ObservationKey mid{BindingGeneration{0}, ObservationDirection::Egress,
                           RadioGeneration{0}, ChannelEpoch{0}, 1, 2};
  CHECK(a->telemetry_bucket(mid) == nullptr);
}

// #46 ledger: every completed TX debits its measured driver-service µs into
// a per-domain accumulator — the control lane charges the accepted work's
// own ACK domain, management class charges the gated control domain,
// scheduled DATA charges work, off-scheduler traffic lands in misc.
void test_airtime_ledger_domains() {
  Harness h;
  MeshNode* a = h.add(1);
  MeshNode* b = h.add(2);
  h.link(1, 2);
  MessageId data{};
  CHECK_OK(a->send(2, payload_view(), SendOptions{}, h.now, data));
  drive_tx(h, 1, data.sequence, 1);  // A's DATA delivered; B queues HOP_ACCEPT
  h.step(2);                       // B's control-lane HOP_ACCEPT completes
  h.step(2);                       // B's boot advertisement completes

  const CongestionStats sa = a->congestion_stats();
  CHECK(sa.service_us_work >= 50);     // scheduled DATA
  CHECK(sa.service_us_control >= 50);  // boot RouteUpdate (management class)
  const CongestionStats sb = b->congestion_stats();
  CHECK(sb.service_us_ack >= 50);      // control-lane HOP_ACCEPT
  CHECK(sb.service_us_control >= 50);  // B's own boot advertisement

  // An off-scheduler completion (no matching in-flight token) -> misc.
  RadioTxObservation raw{};
  raw.peer = 2;
  raw.submitted_us = 1000;
  raw.completed_us = 2000;
  raw.outcome = RadioTxOutcome::Success;
  raw.provenance = ObservationProvenance::LocalDriver;
  a->note_radio_tx(raw, h.now);
  CHECK(a->congestion_stats().service_us_misc == 1000);

  // An Unknown completion carries no measured service — nothing is debited.
  RadioTxObservation unknown = raw;
  unknown.completed_us = 0;
  unknown.outcome = RadioTxOutcome::Unknown;
  a->note_radio_tx(unknown, h.now);
  CHECK(a->congestion_stats().service_us_misc == 1000);
}

// #46 gate: the §14 management bucket gates emissions by air time — when the
// local balance cannot cover one frame's air time the advertisement
// stretches by the computed token wait instead of queueing on debt.
void test_control_budget_gate() {
  Harness h;
  h.net.service_us = 12000;  // every TX reports one full frame of driver service
  MeshNode* a = h.add(1, 3, 2, /*adv*/ 100, /*life*/ 60000, /*gate*/ true);
  (void)h.add(2);
  h.link(1, 2);

  // The boot ad emits immediately against the full 12000µs bucket; its
  // completion debits 12000µs of control-domain service (demand calibrates
  // to the same 12000µs, so the bucket is fully drained).
  h.step(1);
  CHECK(route_ads(h, 1) == 1);
  CHECK(a->congestion_stats().service_us_control >= 12000);

  // The next tick cannot cover one frame's air time: the ad stretches by
  // the computed token wait (~12s) rather than queueing on debt.
  h.now += 150;
  h.step(1);
  CHECK(route_ads(h, 1) == 1);
  h.now += 5000;
  h.step(1);
  CHECK(route_ads(h, 1) == 1);

  // Once the wait lands the bucket has refilled and the ad emits — the
  // periodic ad and the neighbor-add trigger both pass the refilled gate,
  // and TX-complete submits the second frame inside the same step.
  h.now += 7000;
  h.step(1);
  CHECK(route_ads(h, 1) == 3);
  CHECK(a->congestion_stats().service_us_control >= 24000);
}

// #46 unsatisfiable: when the §8 refresh bound cannot absorb the token
// wait inside the actual lease, the emission is unsatisfiable — surfaced
// and counted — but still sent: a normal route must never expire on this
// node's own budget wait (03 §8), so an unsatisfiable gate emits anyway
// rather than parking route maintenance.
void test_control_budget_unsatisfiable() {
  Harness h;
  h.net.service_us = 12000;  // one ad drains the whole 12000µs bucket
  MeshNode* a = h.add(1, 3, 2, /*adv*/ 100, /*life*/ 200, /*gate*/ true);
  (void)h.add(2);
  h.link(1, 2);

  // The boot ad emits against a full bucket, then debits all of it.
  h.step(1);
  CHECK(route_ads(h, 1) == 1);

  // The next tick needs ~11850µs of refill — a wait the 200ms lease
  // cannot absorb. The neighbor-add trigger is armed by then too, so
  // both emission paths report the breach (one diag per episode) and go
  // out unfunded: the burst takes the single in-flight TX slot and the
  // queued periodic frame follows as soon as it completes (same step).
  h.now += 150;
  h.step(1);
  CHECK(route_ads(h, 1) == 3);
  CHECK(a->congestion_stats().control_budget_unsatisfiable == 2);
  CHECK(h.observer(1)->has_diag("CONTROL_BUDGET_UNSATISFIABLE"));

  // Emissions keep flowing on schedule while the breach is open; the
  // counter records every unfunded emission.
  h.now += 500;
  h.step(1);
  CHECK(route_ads(h, 1) == 4);
  CHECK(a->congestion_stats().control_budget_unsatisfiable == 3);
}

// #46 livelock regression: a single control-domain completion reporting
// service ABOVE the bucket capacity (driver service incl. CCA backoff /
// retries, e.g. 20000µs > 12000µs) seeds demand past the reachable balance.
// Demand clamps to capacity so a full bucket always affords one emission;
// the excess debit is repaid through the wait for the next one — a normal
// route must never expire on this node's own budget wait (§8).
void test_control_budget_over_capacity_service() {
  Harness h;
  h.net.service_us = 20000;  // one frame burns more than the 12000µs bucket
  MeshNode* a = h.add(1, 3, 2, /*adv*/ 100, /*life*/ 60000, /*gate*/ true);
  (void)h.add(2);
  h.link(1, 2);

  // The boot ad emits against the full bucket; its completion debits
  // 20000µs (the balance runs negative) and seeds demand at 20000µs.
  h.step(1);
  CHECK(route_ads(h, 1) == 1);
  CHECK(a->congestion_stats().service_us_control >= 20000);

  // The next tick defers by the true debt (~19850µs ≈ 20s at 1000µs/s),
  // not forever: the gate never waits on a balance the refill cannot
  // reach, so the wait stays finite and well under the 60s lease — no
  // unsatisfiable, no silent stall.
  h.now += 150;
  h.step(1);
  CHECK(route_ads(h, 1) == 1);
  CHECK(a->congestion_stats().control_budget_unsatisfiable == 0);

  // Inside the wait the ad stays parked; once the debt is repaid the
  // emission lands (periodic + neighbor-add trigger, sent back to back in
  // the same step).
  h.now += 18500;
  h.step(1);
  CHECK(route_ads(h, 1) == 1);
  h.now += 2000;
  h.step(1);
  CHECK(route_ads(h, 1) == 3);
  CHECK(a->congestion_stats().service_us_control >= 40000);

  // Emissions keep flowing at the real airtime rate: the back-to-back
  // pair debited ~40000µs, so the next emission waits ~40s — inside the
  // 60s lease. Route maintenance survives on the node's own budget.
  h.now += 21000;
  h.step(1);
  CHECK(route_ads(h, 1) == 3);
  CHECK(a->congestion_stats().control_budget_unsatisfiable == 0);
  h.now += 20000;
  h.step(1);
  CHECK(route_ads(h, 1) >= 4);
  CHECK(a->congestion_stats().control_budget_unsatisfiable == 0);
}

// #46 review regression (P1): the UNCALIBRATED §14 bucket must not gate
// the default profile. Four nodes in a line — relays 2 and 3 each carry
// fan-out 2 — run the default 5000ms period / 15000ms lease with a
// measured-realistic 12000µs driver service per TX. Under the
// unconditional 1ms/s envelope the relay's fan-out refill starved route
// maintenance and the end-to-end route expired inside ~27s; with the
// gate off the route must survive sustained operation and no
// unsatisfiable event may be raised.
void test_control_budget_default_profile_ungated() {
  Harness h;
  h.net.service_us = 12000;  // measured-realistic full-frame service
  for (NodeId id = 1; id <= 4; ++id) {
    (void)h.add(id, 3, 2, /*adv*/ 5000, /*life*/ 15000);
  }
  h.link(1, 2);
  h.link(2, 3);
  h.link(3, 4);

  // Sustained operation across six leases: from the first checkpoint on,
  // 1's route to 4 through both relays must stay leased — not just at
  // startup.
  for (std::uint32_t t = 0; t <= 90000; t += 50) {
    h.now += 50;
    for (NodeId id = 1; id <= 4; ++id) h.step(id);
    if (t >= 30000 && t % 15000 == 0) {
      CHECK(h.at(1)->routes().best(4).valid);
    }
  }
  CHECK(h.at(1)->routes().best(4).valid);
  for (NodeId id = 1; id <= 4; ++id) {
    CHECK(h.at(id)->congestion_stats().control_budget_unsatisfiable == 0);
    CHECK(!h.observer(id)->has_diag("CONTROL_BUDGET_UNSATISFIABLE"));
  }
}

// Same default multi-adjacency configuration with the gate ENABLED: the
// §8 capacity decision reports the envelope budget cannot sustain the
// fan-out workload inside the actual lease — UNSATISFIABLE surfaces once
// per episode — yet the emissions still go out unfunded, so the route
// never expires on the nodes' own budget waits either.
void test_control_budget_default_profile_capacity_flag() {
  Harness h;
  h.net.service_us = 12000;
  for (NodeId id = 1; id <= 4; ++id) {
    (void)h.add(id, 3, 2, /*adv*/ 5000, /*life*/ 15000, /*gate*/ true);
  }
  h.link(1, 2);
  h.link(2, 3);
  h.link(3, 4);

  for (std::uint32_t t = 0; t <= 90000; t += 50) {
    h.now += 50;
    for (NodeId id = 1; id <= 4; ++id) h.step(id);
    if (t >= 30000 && t % 15000 == 0) {
      CHECK(h.at(1)->routes().best(4).valid);
    }
  }
  CHECK(h.at(1)->routes().best(4).valid);
  // The capacity decision fired on the relays: the fan-out workload
  // cannot be repaid inside the lease — counted and surfaced, while
  // route maintenance continued on unfunded emissions.
  CHECK(h.at(2)->congestion_stats().control_budget_unsatisfiable >= 1);
  CHECK(h.observer(2)->has_diag("CONTROL_BUDGET_UNSATISFIABLE"));
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
  test_adaptive_hop_timeout_shrinks();
  test_adaptive_hop_timeout_expands_and_caps();
  test_retransmitted_exchange_not_rtt_sampled();
  test_telemetry_hop_rtt_validity_bit();
  test_link_retry_jitter();
  test_hop_timeout_config_floor();
  test_charge_fixed_cost();
  test_airtime_ledger_domains();
  test_control_budget_gate();
  test_control_budget_unsatisfiable();
  test_control_budget_over_capacity_service();
  test_control_budget_default_profile_ungated();
  test_control_budget_default_profile_capacity_flag();
  if (failures == 0) {
    std::printf("RouteLoom congestion tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d congestion checks failed\n", failures);
  return 1;
}
