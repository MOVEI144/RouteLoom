// G-ROUTE portable routing profile tests: line/diamond/ring delivery, relay
// and multi-link repair, restarts (origin generation), stale advertisement
// rejection, sequence wrap, partition/merge convergence, multiple origins,
// and the forwarding loop-freedom property. All deterministic — the sim is
// driven entirely by MonotonicMs, no real time.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <map>
#include <set>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/types.hpp"

#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::SimWorld;
using routeloom_test::FrameSight;

using Key = std::tuple<NodeId, std::uint32_t, std::uint64_t, std::uint8_t, std::uint8_t>;

Key sight_key(const FrameSight& s) {
  return std::make_tuple(s.origin, s.session, s.sequence, s.round,
                       static_cast<std::uint8_t>(s.type));
}

// Loop-freedom property over recorded frame sightings: within one message
// round, (a) no node forwards to more than one next hop, (b) no node receives
// the message twice, (c) no frame comes back to its origin, and (d) the
// hop-decremented sightings form a single consistent forwarding chain.
void check_no_forward_loops(const std::vector<FrameSight>& sights) {
  std::map<Key, std::vector<FrameSight>> by_key;
  for (const auto& s : sights) {
    if (s.type == FrameType::Data || s.type == FrameType::EndReceipt) {
      by_key[sight_key(s)].push_back(s);
    }
  }
  for (const auto& [key, hops] : by_key) {
    std::map<std::pair<NodeId, NodeId>, FrameSight> dedup;
    for (const auto& h : hops) dedup[{h.from, h.to}] = h;
    std::set<NodeId> receivers;
    for (const auto& [edge, h] : dedup) {
      CHECK(h.to != h.origin);  // a frame must never return to its origin
      receivers.insert(h.to);
    }
    // One sender -> one receiver per node: retries to the same peer are
    // dedup'd away, so any second distinct target is a forwarding branch.
    std::map<NodeId, std::set<NodeId>> targets;
    for (const auto& [edge, h] : dedup) targets[h.from].insert(h.to);
    for (const auto& [from, tos] : targets) CHECK(tos.size() == 1);
    for (const auto& to : receivers) {
      std::set<NodeId> sources;
      for (const auto& [edge, h] : dedup) if (h.to == to) sources.insert(h.from);
      CHECK(sources.size() <= 1);  // same message must not arrive twice
    }
    // Hop budget decreases exactly once per forwarding hop along the chain.
    std::vector<FrameSight> chain;
    for (const auto& [edge, h] : dedup) chain.push_back(h);
    std::sort(chain.begin(), chain.end(),
              [](const FrameSight& a, const FrameSight& b) {
                return a.hop_remaining > b.hop_remaining;
              });
    for (std::size_t i = 1; i < chain.size(); ++i) {
      CHECK(chain[i].hop_remaining + 1 == chain[i - 1].hop_remaining);
      CHECK(chain[i].from == chain[i - 1].to);
    }
  }
}

void make_line(SimWorld& w, int count, RouteMetric metric = 1) {
  for (int i = 1; i <= count; ++i) w.add(static_cast<NodeId>(i));
  w.start_all();
  for (int i = 1; i < count; ++i) w.link(i, i + 1, metric, metric);
}

void send_and_expect(SimWorld& w, NodeId from, NodeId to, MonotonicMs run_ms,
                     const char* tag) {
  const std::array<std::uint8_t, 4> payload{{1, 2, 3, 4}};
  SendOptions options{};
  options.lifetime_ms = 30000;
  MessageId id{};
  CHECK_OK(w.at(from)->send(to, ByteView{payload.data(), payload.size()}, options,
                           w.now, id));
  w.run(run_ms);
  CHECK(w.obs(to)->messages.size() >= 1);
  CHECK(w.at(from)->delivery(id).state == DeliveryState::Delivered);
  if (w.obs(to)->messages.empty() || w.at(from)->delivery(id).state != DeliveryState::Delivered) {
    std::fprintf(stderr, "  %s: delivery %llu->%llu failed (state=%d %s msgs=%zu)\n",
                 tag, static_cast<unsigned long long>(from),
                 static_cast<unsigned long long>(to),
                 static_cast<int>(w.at(from)->delivery(id).state),
                 w.at(from)->delivery(id).reason, w.obs(to)->messages.size());
  }
}

void test_line_delivery(int hops) {
  SimWorld w;
  make_line(w, hops + 1);
  w.run(2000 + 600 * hops);  // routes propagate ~one advertisement hop per period
  CHECK(w.at(1)->routes().best(static_cast<NodeId>(hops + 1)).valid);
  send_and_expect(w, 1, static_cast<NodeId>(hops + 1), 15000, "line");
  check_no_forward_loops(w.net.sights);
}

void test_diamond() {
  SimWorld w;
  for (NodeId id = 1; id <= 4; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1); w.link(2, 4, 1, 1);
  w.link(1, 3, 2, 2); w.link(3, 4, 2, 2);
  w.run(4000);
  CHECK(w.at(1)->routes().best(4).next_hop == 2);  // cheaper arm wins
  send_and_expect(w, 1, 4, 10000, "diamond");
  check_no_forward_loops(w.net.sights);
}

void test_ring() {
  SimWorld w;
  for (NodeId id = 1; id <= 6; ++id) w.add(id);
  w.start_all();
  for (NodeId id = 1; id <= 6; ++id) w.link(id, id % 6 + 1, 1, 1);
  w.run(5000);
  CHECK(w.at(1)->routes().best(4).valid);
  send_and_expect(w, 1, 4, 12000, "ring");
  send_and_expect(w, 4, 1, 12000, "ring-back");
  check_no_forward_loops(w.net.sights);
}

void test_relay_removal() {
  SimWorld w;
  for (NodeId id = 1; id <= 4; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1); w.link(2, 4, 1, 1);
  w.link(1, 3, 2, 2); w.link(3, 4, 2, 2);
  w.run(4000);
  CHECK(w.at(1)->routes().best(4).next_hop == 2);
  w.unlink(2, 4);  // relay 2 loses its uplink; 1 must repair via 3
  w.run(6000);
  CHECK(w.at(1)->routes().best(4).next_hop == 3);
  send_and_expect(w, 1, 4, 15000, "relay-removal");
  check_no_forward_loops(w.net.sights);
}

void test_multi_link_loss() {
  SimWorld w;
  for (NodeId id = 1; id <= 5; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1); w.link(1, 3, 2, 2);
  w.link(2, 4, 1, 1); w.link(3, 4, 2, 2);
  w.link(4, 5, 1, 1); w.link(3, 5, 3, 3);
  w.run(4000);
  CHECK(w.at(1)->routes().best(5).next_hop == 2);
  w.unlink(1, 2);  // simultaneous double link loss
  w.unlink(4, 5);
  w.run(8000);
  CHECK(w.at(1)->routes().best(5).next_hop == 3);
  send_and_expect(w, 1, 5, 15000, "multi-link-loss");
  check_no_forward_loops(w.net.sights);
}

void test_stale_advertisement_rejected() {
  RouteTable table;
  // Baseline: feasible route seq 100 metric 10 advertised -> FD=(100,10).
  CHECK(table.consider(RouteAdvertisement{9, 1, 100, 0}, 2, 10, 0, 5000) ==
        RouteUpdateResult::Accepted);
  CHECK(table.mark_advertised(9));
  // Older sequence: infeasible.
  CHECK(table.consider(RouteAdvertisement{9, 1, 99, 0}, 3, 5, 1, 5000) ==
        RouteUpdateResult::Infeasible);
  // Same sequence, advertised metric not strictly below FD: infeasible.
  CHECK(table.consider(RouteAdvertisement{9, 1, 100, 20}, 3, 5, 2, 5000) ==
        RouteUpdateResult::Infeasible);
  // Same sequence, strictly better advertised metric: feasible (the via-3
  // infeasible candidate is retained, so this reports Updated).
  CHECK(table.consider(RouteAdvertisement{9, 1, 100, 5}, 3, 5, 3, 5000) ==
        RouteUpdateResult::Updated);
  // Lower origin generation is always stale, even with a higher sequence.
  CHECK(table.consider(RouteAdvertisement{9, 0, 200, 0}, 4, 1, 4, 5000) ==
        RouteUpdateResult::StaleGeneration);
  // Higher generation resets the source: the same low sequence is now fresh.
  CHECK(table.consider(RouteAdvertisement{9, 2, 0, 0}, 4, 1, 5, 5000) ==
        RouteUpdateResult::Accepted);
  CHECK(table.best(9).next_hop == 4);
  CHECK(table.best(9).generation == 2);
  CHECK(table.mark_advertised(9));  // FD=(0,1) under generation 2
  // After the upgrade, generation-1 advertisements stay rejected.
  CHECK(table.consider(RouteAdvertisement{9, 1, 200, 0}, 2, 1, 6, 5000) ==
        RouteUpdateResult::StaleGeneration);

  // Tombstone: last candidate fails, but FD + generation must still reject a
  // stale re-advertisement instead of letting it look fresh.
  table.invalidate_next_hop(4, 10);
  CHECK(!table.best(9).valid);
  CHECK(table.needs_sequence_request(9));
  CHECK(table.consider(RouteAdvertisement{9, 2, 0, 50}, 5, 1, 11, 5000) ==
        RouteUpdateResult::Infeasible);  // seq 0 == FD seq 0, metric 50 not < FD 1
  // The infeasible via-5 candidate expires on its lease, then the tombstone
  // survives a documented dwell before the GC releases it.
  table.expire(5012);
  CHECK(table.size() == 1);  // candidate lease gone, tombstone armed
  table.expire(5012 + kRouteTombstoneDwellMs - 1);
  CHECK(table.size() == 1);  // dwell not yet elapsed
  table.expire(5012 + kRouteTombstoneDwellMs);
  CHECK(table.size() == 0);  // tombstone GC'd
  CHECK(table.consider(RouteAdvertisement{9, 2, 0, 50}, 5, 1, 70000, 5000) ==
        RouteUpdateResult::Accepted);  // FD gone with the tombstone
}

void test_sequence_wrap() {
  RouteTable table;
  CHECK(table.consider(RouteAdvertisement{9, 1, 0xFFFE, 0}, 2, 1, 0, 5000) ==
        RouteUpdateResult::Accepted);
  CHECK(table.mark_advertised(9));
  CHECK(table.consider(RouteAdvertisement{9, 1, 0xFFFF, 0}, 2, 1, 1, 5000) ==
        RouteUpdateResult::Updated);  // +1 still newer
  CHECK(table.mark_advertised(9));
  // Wrap: 0x0000 follows 0xFFFF in serial arithmetic.
  CHECK(table.consider(RouteAdvertisement{9, 1, 0, 0}, 2, 1, 2, 5000) ==
        RouteUpdateResult::Updated);
  CHECK(table.mark_advertised(9));
  CHECK(table.best(9).sequence == 0);
  // Behind the wrap: 0xFFFF is older than 0 -> infeasible.
  CHECK(table.consider(RouteAdvertisement{9, 1, 0xFFFF, 0}, 3, 1, 3, 5000) ==
        RouteUpdateResult::Infeasible);
  // Ambiguous half-wrap distance: rejected, needs resync.
  bool ambiguous = false;
  CHECK(!route_sequence_newer(0x8000, 0, ambiguous) && ambiguous);
  CHECK(table.consider(RouteAdvertisement{9, 1, 0x8000, 0}, 3, 1, 4, 5000) ==
        RouteUpdateResult::Infeasible);
}

void test_origin_restart() {
  SimWorld w;
  make_line(w, 4);
  w.run(4000);
  CHECK(w.at(1)->routes().best(4).valid);
  CHECK(w.at(3)->routes().best(4).generation == 1);

  // Origin 4 restarts: fresh node, higher persisted generation.
  w.remove_node(4);
  w.add(4, /*generation=*/2);
  w.at(4)->start(w.now);
  w.net.connect(3, 4);
  w.at(3)->add_neighbor(4, 1, w.now);
  w.at(4)->add_neighbor(3, 1, w.now);
  w.run(5000);

  // Neighbor detected the generation bump and flushed stale via-peer state.
  CHECK(w.obs(3)->has_diag("PEER_RESTARTED_ROUTES_FLUSHED"));
  CHECK(w.at(3)->routes().best(4).generation == 2);
  // Old-generation advertisements for 4 from the rest of the mesh are rejected.
  CHECK(w.obs(3)->has_diag("ROUTE_STALE_GENERATION"));
  send_and_expect(w, 1, 4, 15000, "origin-restart");
  check_no_forward_loops(w.net.sights);
}

void test_relay_restart() {
  SimWorld w;
  make_line(w, 4);
  w.run(4000);
  CHECK(w.at(1)->routes().best(4).valid);

  // Relay 3 restarts with a higher generation: its neighbors must flush every
  // route learned from its previous incarnation.
  w.remove_node(3);
  w.add(3, /*generation=*/2);
  w.at(3)->start(w.now);
  w.net.connect(2, 3); w.net.connect(3, 4);
  w.at(2)->add_neighbor(3, 1, w.now);
  w.at(4)->add_neighbor(3, 1, w.now);
  w.at(3)->add_neighbor(2, 1, w.now);
  w.at(3)->add_neighbor(4, 1, w.now);
  w.run(6000);

  CHECK(w.obs(2)->has_diag("PEER_RESTARTED_ROUTES_FLUSHED"));
  CHECK(w.at(2)->routes().best(4).valid);  // relearned through restarted 3
  send_and_expect(w, 1, 4, 15000, "relay-restart");
  check_no_forward_loops(w.net.sights);
}

void test_partition_merge() {
  SimWorld w;
  // Partition A: 1-2. Partition B: 3-4-5, where 5 restarts (gen 2) while cut off.
  w.add(1); w.add(2); w.add(3); w.add(4); w.add(5);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(3, 4, 1, 1); w.link(4, 5, 1, 1);
  w.run(4000);

  w.remove_node(5);
  w.add(5, /*generation=*/2);
  w.at(5)->start(w.now);
  w.net.connect(4, 5);
  w.at(4)->add_neighbor(5, 1, w.now);
  w.at(5)->add_neighbor(4, 1, w.now);
  w.run(3000);

  // Merge: the partitions join. Fresh advertisements converge without loops.
  w.link(2, 3, 1, 1);
  w.run(8000);
  CHECK(w.at(1)->routes().best(5).valid);
  CHECK(w.at(1)->routes().best(5).generation == 2);
  send_and_expect(w, 1, 5, 15000, "partition-merge");
  send_and_expect(w, 5, 1, 15000, "partition-merge-back");
  check_no_forward_loops(w.net.sights);
}

void test_multiple_origins_pinning() {
  SimWorld w;
  // Two gateways behind different arms: an explicit destination must never be
  // rerouted to the other gateway.
  for (NodeId id = 1; id <= 5; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1); w.link(2, 4, 1, 1);
  w.link(1, 3, 1, 1); w.link(3, 5, 1, 1);
  w.run(4000);
  CHECK(w.at(1)->routes().best(4).next_hop == 2);
  CHECK(w.at(1)->routes().best(5).next_hop == 3);

  const std::array<std::uint8_t, 4> p4{{4, 4, 4, 4}};
  const std::array<std::uint8_t, 4> p5{{5, 5, 5, 5}};
  SendOptions options{};
  options.lifetime_ms = 30000;
  MessageId id4{}, id5{};
  CHECK_OK(w.at(1)->send(4, ByteView{p4.data(), p4.size()}, options, w.now, id4));
  CHECK_OK(w.at(1)->send(5, ByteView{p5.data(), p5.size()}, options, w.now, id5));
  w.run(15000);
  CHECK(w.at(1)->delivery(id4).state == DeliveryState::Delivered);
  CHECK(w.at(1)->delivery(id5).state == DeliveryState::Delivered);
  // Gateway 4 received only the 4-bound payload, gateway 5 only the 5-bound.
  CHECK(w.obs(4)->messages.size() == 1);
  CHECK(w.obs(4)->messages[0] == std::vector<std::uint8_t>(p4.begin(), p4.end()));
  CHECK(w.obs(5)->messages.size() == 1);
  CHECK(w.obs(5)->messages[0] == std::vector<std::uint8_t>(p5.begin(), p5.end()));
  check_no_forward_loops(w.net.sights);
}

}  // namespace

int main() {
  test_line_delivery(1);
  test_line_delivery(3);
  test_line_delivery(5);
  test_line_delivery(10);
  test_diamond();
  test_ring();
  test_relay_removal();
  test_multi_link_loss();
  test_stale_advertisement_rejected();
  test_sequence_wrap();
  test_origin_restart();
  test_relay_restart();
  test_partition_merge();
  test_multiple_origins_pinning();
  if (failures != 0) {
    std::fprintf(stderr, "%d routing-sim checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom routing profile tests passed");
  return 0;
}
