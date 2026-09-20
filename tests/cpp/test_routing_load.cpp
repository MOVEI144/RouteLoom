// Autonomous-mesh P3 tests (issue #4): load-aware safe route selection —
// measured exchange-cost link metrics, local queue-penalty ownership,
// lease-safe metric recomputation, the improvement/switch-hold hysteresis
// with deterministic jitter, severe-BUSY fast repair, ordered/TTL-bound
// feedback and the one-active-next-hop invariant.
//
// Scenario coverage notes reference docs/design/autonomous-mesh/scenarios.json
// (D4-xx) and 03-congestion.md §6/§7.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <map>
#include <memory>
#include <set>
#include <vector>

#include "routeloom/autonomy_wire.hpp"
#include "routeloom/congestion.hpp"
#include "routeloom/node.hpp"
#include "routeloom/routing.hpp"
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
const std::uint8_t kPayload[] = "load-test";

ByteView payload_view() { return ByteView{kPayload, sizeof(kPayload) - 1}; }

// Jitter the table derives for (self=1, destination=9): used to pin the
// improvement-hold edge deterministically.
constexpr std::uint32_t kJitter19 = (1U * 31U + 9U * 17U) % (2000U + 1U);  // 184

// ---------------------------------------------------------------- fixture

// Same small harness shape as the P2 congestion tests: one interchangeable
// cipher mints frames "from" any peer.
struct Harness {
  SimNetwork net;
  TestSecurity cipher;
  std::map<NodeId, std::unique_ptr<TestSecurity>> sec;
  std::map<NodeId, std::unique_ptr<CapturingObserver>> obs;
  std::map<NodeId, std::unique_ptr<SimRadio>> radio;
  std::map<NodeId, std::unique_ptr<MeshNode>> node;
  MonotonicMs now{0};

  MeshNode* add(NodeId id) {
    NodeConfig cfg{};
    cfg.network = kNet;
    cfg.node = id;
    cfg.message_session = 100 + static_cast<std::uint32_t>(id);
    cfg.route_generation = 1;
    cfg.route_advertisement_period_ms = 30000;  // one boot ad, then quiet
    cfg.route_lifetime_ms = 60000;
    cfg.hop_accept_timeout_ms = 60;
    cfg.max_link_attempts = 2;
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
  void link(NodeId a, NodeId b) {
    net.connect(a, b);
    (void)node[a]->add_neighbor(b, 1, now);
    (void)node[b]->add_neighbor(a, 1, now);
  }
  void step(NodeId id) {
    node[id]->poll(now);
    net.flush(now);
  }
};

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

// An authenticated BUSY frame `from` -> `to` carrying `payload`.
wire::EncodedFrame craft_busy(TestSecurity& cipher, NodeId from, NodeId to,
                              autonomy::BusyPayload& payload,
                              std::uint64_t wire_seq) {
  autonomy::EncodedPayload body{};
  CHECK_OK(autonomy::busy_encode(payload, body));
  return craft_frame(cipher,
                     mk_header(FrameType::Busy, from, to, from, to,
                               MessageId{888, wire_seq}),
                     body.view());
}

autonomy::BusyPayload pressure_hint(std::uint8_t pressure,
                                    std::uint32_t feedback_seq) {
  autonomy::BusyPayload payload{};
  payload.subtype = autonomy::BusySubtype::PressureHint;
  payload.reason = autonomy::BusyReason::QueueFull;
  payload.pressure = pressure;
  payload.feedback_sequence = FeedbackSequence{feedback_seq};
  return payload;
}

// A radio that drops the NEXT submitted frame at the driver level (the
// send() call itself succeeds; the failure arrives through on_radio_tx_result
// exactly like a real driver accept-then-fail).
class FlakyRadio final : public RadioPort {
 public:
  SimNetwork* net{nullptr};
  NodeId owner{0};
  bool fail_next{false};
  std::deque<std::uint64_t> failed;

  Status send(NodeId peer, std::uint64_t token, ByteView frame) noexcept override {
    if (fail_next) {
      fail_next = false;
      failed.push_back(token);
      return Status::success();
    }
    return net->enqueue(owner, peer, token, frame);
  }
  Status recover() noexcept override { return Status::success(); }
};

// -------------------------------------------------- pure cost math (D4-05)

void test_cost_helpers() {
  // measured base: b = clamp_positive(ceil(nominal * work / accepts)).
  CHECK(measured_link_base(0, 100, 50) == 1);       // floor: never 0
  CHECK(measured_link_base(10, 0, 0) == 10);        // no samples -> nominal
  CHECK(measured_link_base(10, 8, 8) == 10);        // ideal ratio -> nominal
  CHECK(measured_link_base(10, 16, 8) == 20);       // 2x exchange work -> 20
  CHECK(measured_link_base(10, 17, 8) == 22);       // ceil(21.25) = 22
  CHECK(measured_link_base(1, 101, 100) == 2);      // ceil(1.01) = 2
  CHECK(measured_link_base(kInfiniteRouteMetric, 10, 5) == kInfiniteRouteMetric);
  // Saturation, no wrap: 65534 * 100000 / 4 overflows u16 -> 65535 (inf),
  // never a small wrapped value that would make a bad link look fast.
  CHECK(measured_link_base(65534, 100000, 4) == kInfiniteRouteMetric);
  CHECK(measured_link_base(40000, 100, 1) == kInfiniteRouteMetric);

  // Queue penalty: p = b * min(4, ceil(max(0, Q-50)/50)); link = b + p.
  CHECK(queue_penalized_cost(10, 0) == 10);
  CHECK(queue_penalized_cost(10, 50) == 10);        // at target -> no penalty
  CHECK(queue_penalized_cost(10, 51) == 20);        // 1 step -> b*(1+1)
  CHECK(queue_penalized_cost(10, 100) == 20);
  CHECK(queue_penalized_cost(10, 101) == 30);       // 2 steps
  CHECK(queue_penalized_cost(10, 250) == 50);       // 4 steps (cap)
  CHECK(queue_penalized_cost(10, 100000) == 50);    // capped, not unbounded
  CHECK(queue_penalized_cost(0, 500) == 1);         // floor: never 0
  CHECK(queue_penalized_cost(kInfiniteRouteMetric, 100) == kInfiniteRouteMetric);
  CHECK(queue_penalized_cost(60000, 250) == kInfiniteRouteMetric);  // sat

  // Saturating route addition stays saturated instead of wrapping small.
  CHECK(route_metric_add(60000, 10000) == kInfiniteRouteMetric);
  CHECK(route_metric_add(60000, 5000) == 65000);
}

// ------------------------------- table: lease-safe recompute (D4-02/D4-05)

void test_update_link_cost_table() {
  RouteTable table;
  table.set_self(1);
  CHECK(table.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000) ==
        RouteUpdateResult::Accepted);
  CHECK(table.consider(RouteAdvertisement{9, 1, 100, 10}, 3, 10, 0, 60000) ==
        RouteUpdateResult::Accepted);
  auto best = table.best(9);
  CHECK(best.valid && best.next_hop == 2 && best.metric == 20);

  // Cost is recomputed from the STORED advertised metric, not accumulated.
  CHECK(table.update_link_cost(2, 30, 1));
  best = table.best(9);
  CHECK(best.next_hop == 2 && best.metric == 40);   // 10 + 30
  // via-3 (total 20) is a qualifying improvement (20*5 <= 40*4) — but the
  // committed hop holds until the jittered improvement hold elapses.
  table.evaluate(500);
  CHECK(table.best(9).next_hop == 2);

  // Zero-cost is refused: only self-origin distance may be 0 (03 §6.2).
  CHECK(!table.update_link_cost(2, 0, 2));
  CHECK(!table.update_link_cost(77, 5, 2));         // unknown hop
  CHECK(table.best(9).metric == 40);

  // Saturation path: a cost that pushes the total to infinity makes the
  // committed hop unselectable -> immediate repair (no hold on failure).
  CHECK(table.update_link_cost(2, 60000, 3));
  CHECK(table.best(9).next_hop == 2 && table.best(9).metric == 60010);
  CHECK(table.update_link_cost(2, kInfiniteRouteMetric, 4));
  best = table.best(9);
  CHECK(best.valid && best.next_hop == 3 && best.metric == 20);

  // Lease safety (metric_changes_refresh_advertisement_lease = false): a
  // cost update late in the lease does not renew the stored advertisement.
  RouteTable lease;
  lease.set_self(1);
  lease.consider(RouteAdvertisement{8, 1, 50, 5}, 4, 10, 0, 5000);
  CHECK(lease.update_link_cost(4, 7, 4900));        // touched, not renewed
  lease.expire(5001);
  CHECK(!lease.best(8).valid);
}

// ------------------- table: load never admits infeasible (D4-02/D4-08)

void test_load_never_admits_infeasible() {
  RouteTable table;
  table.set_self(1);
  table.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000);
  CHECK(table.mark_advertised(9));                  // FD := (seq 100, 20)
  // Same-sequence candidate advertising 30 >= FD 20 -> infeasible.
  CHECK(table.consider(RouteAdvertisement{9, 1, 100, 30}, 3, 1, 1, 60000) ==
        RouteUpdateResult::Infeasible);
  // Make the infeasible route the cheapest in the table: it must still not
  // be admitted — load can never relax feasibility (03 §6.3).
  CHECK(table.update_link_cost(3, 1, 2));
  auto best = table.best(9);
  CHECK(best.valid && best.next_hop == 2);
  // Even with the feasible route withdrawn, the lightly-loaded infeasible
  // route stays rejected (the stale-feasibility regression).
  CHECK(table.withdraw(9, 2, 3));
  CHECK(!table.best(9).valid);
}

// ---------------------------------- table: hysteresis (D4-01/D4-04/D4-07)

void test_improvement_hysteresis() {
  RouteTable table;
  table.set_self(1);
  table.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000);  // 20
  table.consider(RouteAdvertisement{9, 1, 100, 10}, 3, 10, 0, 60000);  // 20
  CHECK(table.best(9).next_hop == 2);

  // Exactly 20% better qualifies: 16*5 = 80 <= 20*4.
  CHECK(table.update_link_cost(3, 6, 10));
  table.evaluate(10);
  CHECK(table.best(9).next_hop == 2);               // streak just started
  // Below the threshold never commits: 17*5 = 85 > 80.
  RouteTable weak;
  weak.set_self(1);
  weak.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000);
  weak.consider(RouteAdvertisement{9, 1, 100, 10}, 3, 10, 0, 60000);
  weak.update_link_cost(3, 7, 10);                  // total 17, not qualifying
  weak.evaluate(60000);
  CHECK(weak.best(9).next_hop == 2);

  // The hold is improvement_hold_ms + jitter(self,dest) = 10000 + 184.
  table.evaluate(10 + 10000 + kJitter19 - 1);
  CHECK(table.best(9).next_hop == 2);               // one tick short
  table.evaluate(10 + 10000 + kJitter19);
  CHECK(table.best(9).next_hop == 3);               // committed

  // A qualifying alternative that is briefly best then worsens resets the
  // streak — the better state must be CONTINUOUS.
  RouteTable flappy;
  flappy.set_self(1);
  flappy.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000);
  flappy.consider(RouteAdvertisement{9, 1, 100, 10}, 3, 10, 0, 60000);
  flappy.update_link_cost(3, 6, 10);                // qualifies at t=10
  flappy.evaluate(5000);
  flappy.update_link_cost(3, 20, 6000);             // worse again: streak reset
  flappy.update_link_cost(3, 6, 7000);              // qualifies again at t=7000
  flappy.evaluate(7000 + 10000 + kJitter19 - 1);
  CHECK(flappy.best(9).next_hop == 2);              // hold restarted at 7000
  flappy.evaluate(7000 + 10000 + kJitter19);
  CHECK(flappy.best(9).next_hop == 3);
}

void test_severe_busy_and_switch_hold() {
  // D4-03/D4-07: sustained authenticated BUSY on the committed hop permits
  // repair without the improvement hold — still damped by switch_hold.
  RouteTable table;
  table.set_self(1);
  table.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000);  // 20
  table.consider(RouteAdvertisement{9, 1, 100, 20}, 3, 10, 0, 60000);  // 30
  CHECK(table.best(9).next_hop == 2);
  table.note_next_hop_busy(2, 1000);
  table.evaluate(1000 + kSevereBusyMs - 1);
  CHECK(table.best(9).next_hop == 2);               // not yet severe
  table.evaluate(1000 + kSevereBusyMs);
  CHECK(table.best(9).next_hop == 3);               // repaired, even though worse
  // Busy clears: via-2 has the strictly better advertised distance — a
  // topology-fresh improvement — but the 5s post-switch hold (armed at
  // t=3000) still damps the revert.
  table.clear_next_hop_busy(2);
  table.evaluate(3001);
  CHECK(table.best(9).next_hop == 3);
  table.evaluate(3000 + kSwitchHoldMs - 1);
  CHECK(table.best(9).next_hop == 3);
  table.evaluate(3000 + kSwitchHoldMs);
  CHECK(table.best(9).next_hop == 2);               // revert after the hold

  // A severely busy alternative is never a repair target.
  RouteTable both;
  both.set_self(1);
  both.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000);
  both.consider(RouteAdvertisement{9, 1, 100, 20}, 3, 10, 0, 60000);
  both.note_next_hop_busy(2, 1);
  both.note_next_hop_busy(3, 1);
  both.evaluate(5000);
  CHECK(both.best(9).next_hop == 2);

  // Switch hold: a severe-busy repair inside the post-switch window waits.
  RouteTable held;
  held.set_self(1);
  held.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000);
  // Topology-fresh improvement (advertised 1 < 10) commits promptly and
  // arms the 5s switch hold at t=100.
  held.consider(RouteAdvertisement{9, 1, 100, 1}, 3, 10, 100, 60000);
  CHECK(held.best(9).next_hop == 3);
  held.note_next_hop_busy(3, 1);                    // severe by t>=2001
  held.evaluate(2100);
  CHECK(held.best(9).next_hop == 3);                // held until t=5100
  held.evaluate(5100);
  CHECK(held.best(9).next_hop == 2);                // hold elapsed -> repair
}

// ----------------- table: triggered-ad gap on pure improvements (D4-06)

void test_improvement_ad_gap() {
  RouteTable table;
  table.set_self(1);
  table.consider(RouteAdvertisement{9, 1, 100, 10}, 2, 10, 0, 60000);
  int fired = 0;
  auto scan = [&](MonotonicMs now) {
    table.for_each_selected_change(
        [&](const RouteSelection&) { ++fired; }, now);
  };
  scan(0);
  CHECK(fired == 1);                                // new selection fires
  table.mark_advertised(9);                         // periodic ad carries it

  // First pure metric improvement fires immediately (no prior ad to space).
  table.update_link_cost(2, 5, 100);                // 20 -> 15
  scan(100);
  CHECK(fired == 2);
  // A second improvement inside the 2s gap is suppressed but not lost.
  table.update_link_cost(2, 4, 200);                // 15 -> 14
  scan(200);
  CHECK(fired == 2);
  scan(100 + kImprovementAdGapMs);                  // gap elapsed
  CHECK(fired == 3);
  // Worsening metrics and selection loss are never delayed by the gap.
  table.update_link_cost(2, 50, 2200);              // 14 -> 60
  scan(2200);
  CHECK(fired == 4);
}

// ----------------------- node: queue penalty ownership (D4-05)

void test_queue_penalty_ownership() {
  Harness h;
  MeshNode* a = h.add(1);
  h.add(2);
  h.add(3);
  h.link(1, 2);
  h.link(1, 3);
  // BestEffort sends toward 2, each sitting ~300ms in our egress queue
  // before dispatch — the EWMA converges to a >=4-step penalty. Batched so
  // the bounded delivery table (8) is never overflowed.
  SendOptions opts{};
  opts.delivery = DeliveryClass::BestEffort;
  for (int batch = 0; batch < 3; ++batch) {
    MessageId ids[8];
    for (int i = 0; i < 8; ++i) {
      CHECK_OK(a->send(2, payload_view(), opts, h.now, ids[i]));
    }
    h.now += 300;
    // The DRR scheduler drains only a few frames per poll — repeated polls
    // at the same clock each measure a ~300ms sojourn per job.
    for (int drain = 0; drain < 30; ++drain) {
      h.step(1);
      bool done = true;
      for (const auto& id : ids) {
        done &= a->delivery(id).state == DeliveryState::Delivered;
      }
      if (done) break;
    }
  }
  h.step(1);                                        // next poll applies the cost
  // base stays nominal 1 (<4 accepts); p = 1*4 -> cost 5.
  CHECK(a->peer_link_cost(2) == 5);
  // Ownership: only OUR egress toward 2 is penalized — the idle link to 3
  // is untouched, and nothing of 2's own queue leaks into our metric.
  CHECK(a->peer_link_cost(3) == 1);
  // The penalty decays with the observation window.
  h.now += 2001;
  h.step(1);
  CHECK(a->peer_link_cost(2) == 1);
}

// ----------------------- node: measured exchange ratio (D4-05)

void test_exchange_ratio_cost() {
  // D4-05: every-other physical attempt fails at the driver; the measured
  // ratio is eligible attempt work / authenticated accepts (2/1 here).
  SimNetwork net;
  TestSecurity sec1, sec2;
  CapturingObserver obs1, obs2;
  FlakyRadio radio1;
  SimRadio radio2(net, 2);
  radio1.net = &net;
  radio1.owner = 1;
  NodeConfig c1{};
  c1.network = kNet;
  c1.node = 1;
  c1.message_session = 101;
  c1.route_generation = 1;
  c1.route_advertisement_period_ms = 25000;   // no periodic ad inside the test
  c1.route_lifetime_ms = 600000;
  c1.hop_accept_timeout_ms = 60;
  c1.max_link_attempts = 2;
  c1.max_end_to_end_rounds = 3;
  NodeConfig c2 = c1;
  c2.node = 2;
  c2.message_session = 102;
  MeshNode a(c1, radio1, sec1, obs1);
  MeshNode b(c2, radio2, sec2, obs2);
  net.register_node(1, &a);
  net.register_node(2, &b);
  net.connect(1, 2);
  MonotonicMs now = 0;
  a.start(now);
  b.start(now);
  a.add_neighbor(2, 1, now);
  b.add_neighbor(1, 1, now);
  auto tick = [&] {
    a.poll(now);
    b.poll(now);
    while (!radio1.failed.empty()) {
      a.on_radio_tx_result(radio1.failed.front(), false, now);
      radio1.failed.pop_front();
    }
    net.flush(now);
  };
  // Drain the boot advertisements before arming failures so only DATA
  // submissions can consume them.
  for (int i = 0; i < 20; ++i) { now += 5; tick(); }

  for (int i = 0; i < 5; ++i) {
    MessageId m{};
    radio1.fail_next = true;   // first physical attempt of this delivery fails
    CHECK_OK(a.send(2, payload_view(), SendOptions{}, now, m));
    for (int step = 0; step < 200 && obs2.messages.size() <
         static_cast<std::size_t>(i + 1); ++step) {
      now += 5;
      tick();
    }
    CHECK(obs2.messages.size() == static_cast<std::size_t>(i + 1));
  }
  // After 4+ authenticated accepts the ratio applies: ceil(1 * 2/1) = 2.
  // Queue delay is negligible (5ms steps) so no penalty term interferes.
  CHECK(a.peer_link_cost(2) >= 2);
}

// ------------------ node: sustained egress load switches route (D4-01)

void test_sustained_load_switches_route() {
  SimWorld w;
  w.add(1, 1, 100, 3000);
  w.add(2, 1, 100, 3000);
  w.add(3, 1, 100, 3000);
  w.add(4, 1, 100, 3000);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.link(3, 4, 1, 1);
  w.run(2000);   // both arms learned; committed arm settles deterministically

  MeshNode* a = w.at(1);
  SendOptions opts{};
  opts.delivery = DeliveryClass::BestEffort;
  auto last_data_to = [&](std::uint64_t sequence) -> NodeId {
    NodeId to = kInvalidNodeId;
    for (const auto& s : w.net.sights) {
      if (s.type == FrameType::Data && s.from == 1 && s.sequence == sequence) {
        to = s.to;
      }
    }
    return to;
  };

  // Congest whichever relay is committed: a batch of sends every ~1.5s sits
  // ~300ms in our egress queue, keeping the sojourn EWMA hot for >10s.
  NodeId congested = kInvalidNodeId;
  {
    MessageId probe{};
    CHECK_OK(a->send(4, payload_view(), opts, w.now, probe));
    w.run(50);
    congested = last_data_to(probe.sequence);
    CHECK(congested == 2 || congested == 3);
  }
  const NodeId alternative = congested == 2 ? 3 : 2;
  std::uint64_t seq_early = 0, seq_late = 0;
  for (int i = 0; i < 60; ++i) {
    MessageId m{};
    if (a->send(4, payload_view(), opts, w.now, m).ok()) {
      // Early probe: any send inside ~2.4-4.8s of congestion — long before
      // the ~10s jittered hold can commit. Late probe: the last accepted
      // send, dispatched after the hold.
      if (i >= 8 && seq_early == 0) seq_early = m.sequence;
      if (i >= 50 && seq_late == 0) seq_late = m.sequence;
    }
    w.now += 300;
    a->poll(w.now);
    // The relays and destination are NOT congested: several dispatch passes
    // per step keep their queues drained and route leases fresh — the test
    // isolates OUR egress penalty from downstream starvation.
    for (int s = 0; s < 6; ++s) {
      w.at(2)->poll(w.now);
      w.at(3)->poll(w.now);
      w.at(4)->poll(w.now);
      w.net.flush(w.now);
    }
  }
  CHECK(seq_early != 0 && seq_late != 0);
  // Well before the ~10s jittered hold, DATA still took the committed arm.
  CHECK(last_data_to(seq_early) == congested);
  // After the hold, the feasible alternative carries new DATA.
  CHECK(last_data_to(seq_late) == alternative);
}

// ------------------ node: sustained BUSY fast repair + feedback (D4-03)

void test_sustained_busy_switches_route() {
  SimWorld w;
  w.network_id = kNet;
  w.add(1, 1, 100, 3000);
  w.add(2, 1, 100, 3000);
  w.add(3, 1, 100, 3000);
  w.add(4, 1, 100, 3000);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.link(3, 4, 1, 1);
  w.run(2000);

  MeshNode* a = w.at(1);
  TestSecurity cipher;
  SendOptions opts{};
  opts.delivery = DeliveryClass::BestEffort;
  auto last_data_to = [&](std::uint64_t sequence) -> NodeId {
    NodeId to = kInvalidNodeId;
    for (const auto& s : w.net.sights) {
      if (s.type == FrameType::Data && s.from == 1 && s.sequence == sequence) {
        to = s.to;
      }
    }
    return to;
  };
  MessageId probe{};
  CHECK_OK(a->send(4, payload_view(), opts, w.now, probe));
  w.run(50);
  const NodeId busy_peer = last_data_to(probe.sequence);
  CHECK(busy_peer == 2 || busy_peer == 3);
  const NodeId alternative = busy_peer == 2 ? 3 : 2;
  CHECK(a->peer_busy_since(busy_peer) == 0);

  // Ordered authenticated pressure hints sustain BUSY for >2s (one every
  // 400ms, increasing feedback sequence).
  std::uint64_t seq_before = 0, seq_after = 0;
  for (std::uint32_t i = 1; i <= 7; ++i) {
    auto hint = pressure_hint(200, i);
    auto frame = craft_busy(cipher, busy_peer, 1, hint, i);
    w.at(1)->on_radio_receive(busy_peer,
                              ByteView{frame.bytes.data(), frame.size},
                              RadioRxMetadata{-60}, w.now);
    if (i == 4) {   // ~1.6s sustained — below the severe threshold
      MessageId m{};
      CHECK_OK(a->send(4, payload_view(), opts, w.now, m));
      seq_before = m.sequence;
    }
    w.run(400);
  }
  CHECK(a->peer_busy_since(busy_peer) != 0);
  {
    MessageId m{};
    CHECK_OK(a->send(4, payload_view(), opts, w.now, m));
    seq_after = m.sequence;
    w.run(50);
  }
  // Severe-BUSY repair committed inside the 10s improvement hold would be
  // far too slow — the fast path already moved DATA to the fresh arm.
  CHECK(last_data_to(seq_before) == busy_peer);
  CHECK(last_data_to(seq_after) == alternative);

  // Feedback TTL: silence past 3s releases the sustained-busy state, and a
  // stale (replayed) feedback sequence is never honored.
  const auto stale_before = a->congestion_stats().busy_stale;
  auto stale = pressure_hint(200, 3);   // lower than the last accepted seq
  auto stale_frame = craft_busy(cipher, busy_peer, 1, stale, 100);
  w.at(1)->on_radio_receive(busy_peer,
                            ByteView{stale_frame.bytes.data(), stale_frame.size},
                            RadioRxMetadata{-60}, w.now);
  CHECK(a->congestion_stats().busy_stale == stale_before + 1);
  w.run(3500);
  CHECK(a->peer_busy_since(busy_peer) == 0);
}

// --------------- node: feedback ordering + TTL surface (D4-03)

void test_feedback_ordering_ttl() {
  Harness h;
  MeshNode* a = h.add(1);
  h.add(2);
  h.link(1, 2);
  a->note_peer_pressure(2, 200, 5, h.now);
  CHECK(a->peer_busy_since(2) != 0);
  a->note_peer_pressure(2, 200, 4, h.now);   // stale sequence -> rejected
  CHECK(a->congestion_stats().busy_stale == 1);
  a->note_peer_pressure(2, 200, 6, h.now);   // fresh -> accepted
  // Zero pressure carries no busy claim on an idle peer.
  a->note_peer_pressure(3, 0, 1, h.now);     // unknown peer -> ignored
  h.now += kFeedbackTtlMs + 1;
  h.step(1);
  CHECK(a->peer_busy_since(2) == 0);         // TTL released the busy state
}

// -------------------- node: one active next hop, no striping (D4-08)

void test_no_multipath() {
  SimWorld w;
  w.add(1, 1, 100, 3000);
  w.add(2, 1, 100, 3000);
  w.add(3, 1, 100, 3000);
  w.add(4, 1, 100, 3000);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.link(3, 4, 1, 1);
  w.run(2000);
  MeshNode* a = w.at(1);
  // Reliable sends retry whole rounds under the SAME MessageId — every
  // DATA sighting of one message from node 1 must use one next hop.
  std::map<std::uint64_t, std::set<NodeId>> hops_per_message;
  for (int i = 0; i < 3; ++i) {
    MessageId m{};
    CHECK_OK(a->send(4, payload_view(), SendOptions{}, w.now, m));
    w.run(1500);
    for (const auto& s : w.net.sights) {
      if (s.type == FrameType::Data && s.from == 1 &&
          s.sequence == m.sequence) {
        hops_per_message[m.sequence].insert(s.to);
      }
    }
  }
  CHECK(hops_per_message.size() == 3);
  for (const auto& [seq, hops] : hops_per_message) {
    (void)seq;
    CHECK(hops.size() == 1);   // never striped across the two arms
  }
}

}  // namespace

int main() {
  test_cost_helpers();
  test_update_link_cost_table();
  test_load_never_admits_infeasible();
  test_improvement_hysteresis();
  test_severe_busy_and_switch_hold();
  test_improvement_ad_gap();
  test_queue_penalty_ownership();
  test_exchange_ratio_cost();
  test_sustained_load_switches_route();
  test_sustained_busy_switches_route();
  test_feedback_ordering_ttl();
  test_no_multipath();
  if (failures == 0) {
    std::printf("RouteLoom load-routing tests passed\n");
    return 0;
  }
  std::fprintf(stderr, "%d load-routing checks failed\n", failures);
  return 1;
}
