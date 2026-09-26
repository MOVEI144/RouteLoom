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

#include "routeloom/byte_io.hpp"
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

void test_revoke_routes() {
  // P6 enforcement: revoking a peer drops every candidate via it and
  // the route to the peer itself; surviving destinations repair onto
  // other next hops, and the hold-down keeps the revoked arm from
  // being re-selected when it re-advertises.
  SimWorld w;
  for (NodeId id = 1; id <= 4; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1); w.link(2, 4, 1, 1);
  w.link(1, 3, 2, 2); w.link(3, 4, 2, 2);
  w.run(4000);
  CHECK(w.at(1)->routes().best(4).next_hop == 2);
  CHECK(w.at(1)->routes().best(2).valid);
  const std::array<std::uint8_t, 1> pending_payload{{0xA5}};
  SendOptions pending_options{};
  pending_options.lifetime_ms = 30000;
  MessageId pending{};
  CHECK_OK(w.at(1)->send(2, ByteView{pending_payload.data(), pending_payload.size()},
                         pending_options, w.now, pending));
  w.at(1)->revoke_routes(2, w.now);
  CHECK(w.at(1)->delivery(pending).state == DeliveryState::Failed);
  CHECK(!w.at(1)->routes().best(2).valid);
  // The revoked arm stays dead across advertisement waves (its updates
  // are ignored while the record is inactive); the destination repairs
  // onto the surviving arm and delivery follows.
  w.run(15000);
  CHECK(w.at(1)->routes().best(4).next_hop == 3);
  send_and_expect(w, 1, 4, 10000, "revoke-routes");
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

void test_relay_first_gateway_route(bool scoped) {
  // A member can bind the relay before that relay binds the gateway.
  // Gateway downlink must learn the member through the relay, not require
  // a direct gateway/member edge.
  SimWorld w;
  if (scoped) {
    w.configure = [](NodeConfig& config) {
      config.route_gateways[0] = 1;
      config.route_refresh_ticks = 2;
      config.route_lifetime_ms = 3000;
    };
  }
  for (NodeId id = 1; id <= 3; ++id) w.add(id);
  w.start_all();
  w.link(2, 3, 1, 1);
  w.run(2000);
  CHECK(!w.at(1)->routes().best(3).valid);
  w.link(1, 2, 1, 1);
  w.run(scoped ? 7000 : 4000);
  CHECK(w.at(1)->routes().best(3).next_hop == 2);
  send_and_expect(w, 1, 3, 10000, "relay-first downlink");
  check_no_forward_loops(w.net.sights);
}

void test_relay_first_three_hop_gateway_route(bool scoped) {
  // The member binds a relay before either relay can reach the gateway.
  // Advertisements must propagate across both relays without a direct edge.
  SimWorld w;
  if (scoped) {
    w.configure = [](NodeConfig& config) {
      config.route_gateways[0] = 1;
      config.route_refresh_ticks = 2;
      config.route_lifetime_ms = 3000;
    };
  }
  for (NodeId id = 1; id <= 4; ++id) w.add(id);
  w.start_all();
  w.link(3, 4, 1, 1);
  w.run(2000);
  CHECK(!w.at(1)->routes().best(4).valid);
  w.link(2, 3, 1, 1);
  w.run(2000);
  CHECK(!w.at(1)->routes().best(4).valid);
  w.link(1, 2, 1, 1);
  w.run(scoped ? 11000 : 7000);
  CHECK(w.at(1)->routes().best(4).next_hop == 2);
  CHECK(w.at(2)->routes().best(4).next_hop == 3);
  send_and_expect(w, 1, 4, 10000, "relay-first three-hop downlink");
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

void test_stale_feasible_candidate_not_selected() {
  // FD tightening after a candidate latched feasible (A->B->A loop review):
  // A hears B->G metric 3 (via B, total 4), then learns a direct G link at
  // cost 1 and advertises it, shrinking FD to (seq 7, metric 1). B's stored
  // candidate stays flagged feasible even though its advertised metric 3 is
  // now above FD. When A's direct link fails before B's update arrives, the
  // stale candidate must NOT be selected — selecting it closes the loop.
  RouteTable a;
  constexpr MonotonicMs T0 = 1000;
  constexpr MonotonicMs LIFE = 60000;
  CHECK(a.consider(RouteAdvertisement{7, 1, 7, 3}, 2, 1, T0, LIFE) ==
        RouteUpdateResult::Accepted);
  CHECK(a.consider(RouteAdvertisement{7, 1, 7, 0}, 7, 1, T0, LIFE) ==
        RouteUpdateResult::Accepted);
  CHECK(a.mark_advertised(7));  // FD(G) = (seq 7, metric 1)
  // The loop partner exists on B's side: B selects A for G.
  RouteTable b;
  CHECK(b.consider(RouteAdvertisement{7, 1, 7, 1}, 1, 1, T0, LIFE) ==
        RouteUpdateResult::Accepted);
  CHECK(b.best(7).valid && b.best(7).next_hop == 1);
  // A->G fails before B's updated advertisement reaches A.
  a.invalidate_next_hop(7, T0 + 1);
  const auto best = a.best(7);
  CHECK(!(best.valid && best.next_hop == 2));
  CHECK(!best.valid);
  CHECK(a.needs_sequence_request(7));
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

void test_retraction_propagates() {
  SimWorld w;
  // Line 1-2-3 with no alternate path. When 2-3 drops, 2 must promptly
  // advertise an infinity record for 3 so 1 withdraws — not wait out the
  // 1000ms route lifetime.
  for (NodeId id = 1; id <= 3; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.run(4000);
  CHECK(w.at(1)->routes().best(3).valid);

  w.unlink(2, 3);
  // One triggered-update cycle (≤ ~200ms of run time) must already withdraw
  // the route at 1; lease expiry alone would keep it valid for ~1000ms.
  w.run(400);
  CHECK(!w.at(1)->routes().best(3).valid);
}

void test_seqno_intermediate_answers() {
  SimWorld w;
  // Line 1-2-3. A seqno request reaching node 2 for destination 3 — which 2
  // already has a fresh route to — is answered from 2's own table instead of
  // being forwarded onward to the origin (RFC 8966 §3.8.1.2).
  for (NodeId id = 1; id <= 3; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.run(4000);
  CHECK(w.at(2)->routes().best(3).valid);

  // Craft a SeqNoRequest as node 1 would send it: requester=1, destination=3,
  // requested seq 0 (already satisfied by 2's route), ttl=2.
  std::array<std::uint8_t, 23> payload{};
  {
    ByteWriter writer(MutableByteView{payload.data(), payload.size()});
    CHECK_OK(writer.write_u64(1));   // requester
    CHECK_OK(writer.write_u64(3));   // destination
    CHECK_OK(writer.write_u16(0));   // requested sequence
    CHECK_OK(writer.write_u32(9));   // request id
    CHECK_OK(writer.write_u8(2));    // ttl
  }
  wire::PlainFrame plain{};
  plain.header.type = FrameType::SeqnoRequest;
  plain.header.delivery = DeliveryClass::BestEffort;
  plain.header.hop_remaining = 1;
  plain.header.network = 1;
  plain.header.origin = 1;
  plain.header.destination = 2;
  plain.header.previous_hop = 1;
  plain.header.next_hop = 2;
  plain.header.message = MessageId{101, 77};
  plain.header.remaining_deadline_ms = 60000;
  plain.header.original_lifetime_ms = 60000;
  plain.payload_size = payload.size();
  std::memcpy(plain.payload.data(), payload.data(), payload.size());
  wire::EncodedFrame encoded{};
  CHECK_OK(wire::encode_new(plain, *w.security[1], encoded));

  const std::size_t sights_before = w.net.sights.size();
  w.at(2)->on_radio_receive(1, encoded.view(), RadioRxMetadata{-60}, w.now);
  w.run(3000);
  // 2 answered with a route update toward its neighbors — and never relayed
  // a seqno request onward to 3.
  bool saw_update_to_1 = false;
  for (std::size_t i = sights_before; i < w.net.sights.size(); ++i) {
    const FrameSight& sight = w.net.sights[i];
    CHECK(sight.type != FrameType::SeqnoRequest);
    if (sight.type == FrameType::RouteUpdate && sight.to == 1) {
      saw_update_to_1 = true;
    }
  }
  CHECK(saw_update_to_1);
}

// Issue #50-1 helpers: drop every seqno request at the wire and count a
// node's SEQNO_REQUEST_SENT diagnostics (dropped frames leave no sightings,
// so the sender's own log is the probe signal).
bool drop_seqno_frames(const routeloom_test::SimNetwork::Pending& pending) {
  FrameSight sight{};
  return routeloom_test::sight_frame(
             ByteView{pending.frame.data(), pending.frame.size()}, sight) &&
         sight.type == FrameType::SeqnoRequest;
}

std::size_t seqno_sends(const routeloom_test::CapturingObserver& obs) {
  std::size_t count = 0;
  for (const auto& diag : obs.diagnostics) {
    if (diag.rfind("SEQNO_REQUEST_SENT", 0) == 0) ++count;
  }
  return count;
}

// Issue #50-1: a destination whose infeasible advertisements keep renewing
// their lease must keep being probed past the old 8-attempt cap — on the
// bounded max-cooldown cadence — or it stays permanently unreachable.
void test_seqno_retry_past_cap() {
  SimWorld w;
  // Triangle: node 1 holds the direct route to 3 and advertises it, so its
  // FD for 3 tightens to (seq S, metric 1). Node 2's advertisements of 3 at
  // the same sequence with metric 1 are never strictly better: once the 1-3
  // link dies they stay infeasible yet keep renewing the candidate lease —
  // the deadlock shape from issue #50.
  for (NodeId id = 1; id <= 3; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.link(1, 3, 1, 1);
  w.run(4000);
  CHECK(w.at(1)->routes().best(3).valid);
  CHECK(w.at(1)->routes().best(3).next_hop == 3);  // direct route selected

  // Wire-level death only — no remove_neighbor, so node 3's sequence stays
  // put and no organic repair can happen. Every seqno request is lost.
  w.net.disconnect(1, 3);
  w.net.drop_frame = drop_seqno_frames;
  w.run(2000);  // direct candidate invalidated; probing begins

  // The first ~56s after probing starts cover the old 8-attempt window
  // (linear backoff: gaps 2,4,...,16s then the 30s ceiling).
  w.run(90000);
  const std::size_t sends_early = seqno_sends(*w.obs(1));
  CHECK(sends_early >= 8);
  // Past the old cap the probes must NOT stop — but they ride the bounded
  // 30s cadence, never a flood: ~4-5 sends in the next two minutes.
  w.run(120000);
  const std::size_t late = seqno_sends(*w.obs(1)) - sends_early;
  CHECK(late >= 3);
  CHECK(late <= 8);

  // Repair lands the moment requests get through again: node 3 bumps its
  // sequence, the fresh advertisement is feasible, data delivers.
  w.net.drop_frame = nullptr;
  w.run(45000);
  CHECK(w.at(1)->routes().best(3).valid);
  CHECK(w.at(1)->routes().best(3).next_hop == 2);  // repaired via node 2
  send_and_expect(w, 1, 3, 15000, "seqno-post-cap-repair");
  check_no_forward_loops(w.net.sights);
}

// Injects a route update frame carrying a single record straight into a
// node's RX path — the portable equivalent of "keep feeding this node the
// advertisement" used by the issue-#50 review's portable repro.
std::uint64_t g_inject_message_seq = 1;
void inject_route_update(SimWorld& w, NodeId from, NodeId to, NodeId dest,
                         std::uint32_t generation, std::uint16_t sequence,
                         std::uint16_t metric) {
  // Wire v2 record: dest u64 | generation u32 | sequence u16 | metric u16.
  std::array<std::uint8_t, 17> payload{};
  {
    ByteWriter writer(MutableByteView{payload.data(), payload.size()});
    CHECK_OK(writer.write_u8(1));
    CHECK_OK(writer.write_u64(dest));
    CHECK_OK(writer.write_u32(generation));
    CHECK_OK(writer.write_u16(sequence));
    CHECK_OK(writer.write_u16(metric));
  }
  wire::PlainFrame plain{};
  plain.header.type = FrameType::RouteUpdate;
  plain.header.delivery = DeliveryClass::BestEffort;
  plain.header.hop_remaining = 1;
  plain.header.network = w.network_id;
  plain.header.origin = from;
  plain.header.destination = to;
  plain.header.previous_hop = from;
  plain.header.next_hop = to;
  plain.header.message = MessageId{static_cast<std::uint32_t>(900 + from),
                                   g_inject_message_seq++};
  plain.header.remaining_deadline_ms = 60000;
  plain.header.original_lifetime_ms = 60000;
  plain.payload_size = payload.size();
  std::memcpy(plain.payload.data(), payload.data(), payload.size());
  wire::EncodedFrame encoded{};
  CHECK_OK(wire::encode_new(plain, *w.security[from], encoded));
  w.at(to)->on_radio_receive(from, encoded.view(), RadioRxMetadata{-60}, w.now);
}

// Issue #50 review follow-up: the saturating backoff counter must not also
// drive next-hop candidate selection. Node 1's FD for 99 tightens to
// (seq 1, metric 1) once it advertises the injected metric-0 route; the
// via-2 / via-3 advertisements at seq 1 metric 1 are then never strictly
// better, so they stay infeasible alternates. Feeding those advertisements
// indefinitely keeps their candidate leases alive — the review's portable
// repro — and past the 255-attempt saturation the requests must still
// round-robin BOTH candidates instead of pinning hops[255 % 2] forever.
void test_seqno_probe_cursor_past_cap() {
  SimWorld w;
  for (NodeId id = 1; id <= 3; ++id) w.add(id, 1, 100, 10000);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.run(4000);

  // FD establishment: an injected feasible-looking advertisement from
  // peer 2 (adv metric 0) is selected and re-advertised at metric 1, so
  // node 1's FD for 99 becomes (seq 1, metric 1).
  inject_route_update(w, 2, 1, 99, 1, 1, 0);
  w.run(4000);
  CHECK(w.at(1)->routes().best(99).valid);
  CHECK(w.at(1)->routes().best(99).next_hop == 2);

  // Peer 3 joins as a second (infeasible) candidate, then peer 2's route is
  // retracted — every surviving candidate is now infeasible vs the FD and
  // seqno probing starts. Past the withdraw hold-down the finite
  // re-injection below brings via-2 back as an infeasible candidate.
  inject_route_update(w, 3, 1, 99, 1, 1, 1);
  inject_route_update(w, 2, 1, 99, 1, 1, kInfiniteRouteMetric);
  w.run(600, 2000);
  CHECK(w.at(1)->routes().needs_sequence_request(99));

  // Sends 1-16 ride the linear backoff (~240s total); every later send sits
  // on the 30s ceiling, so ~9e6 ms of sim time reaches ~300 sends — well
  // past the 255-attempt saturation. Nodes 2/3 have no route to 99, so the
  // requests never resolve and the deadlock persists.
  for (int chunk = 0; chunk < 1500; ++chunk) {
    w.run(6000, 2000);
    inject_route_update(w, 2, 1, 99, 1, 1, 1);
    inject_route_update(w, 3, 1, 99, 1, 1, 1);
  }

  const auto& diagnostics = w.obs(1)->diagnostics;
  const auto& peers = w.obs(1)->diagnostic_peers;
  std::size_t sends = 0;
  std::size_t post_cap_to_2 = 0;
  std::size_t post_cap_to_3 = 0;
  for (std::size_t i = 0; i < diagnostics.size(); ++i) {
    if (diagnostics[i].rfind("SEQNO_REQUEST_SENT", 0) != 0) continue;
    ++sends;
    if (sends > 255) {
      if (peers[i] == 2) ++post_cap_to_2;
      if (peers[i] == 3) ++post_cap_to_3;
    }
  }
  CHECK(sends >= 280);  // deadlock persists well past the saturation point
  // With selection driven by the saturated counter, every post-cap request
  // lands on the same candidate (255 % 2); the independent cursor must keep
  // both alternates in rotation.
  CHECK(post_cap_to_2 >= 10);
  CHECK(post_cap_to_3 >= 10);
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


// Issue #29 (Wire v2): route origin generations are 32-bit. A generation past
// the old u16 budget is a newer incarnation, and the v1 wrap value is stale.
void test_route_generation_past_u16_budget() {
  RouteTable table;
  CHECK(table.consider(RouteAdvertisement{9, 65535, 10, 0}, 2, 10, 0, 5000) ==
        RouteUpdateResult::Accepted);
  CHECK(table.mark_advertised(9));
  // One more boot: generation 65536 resets the source — fresh, not stale.
  CHECK(table.consider(RouteAdvertisement{9, 65536, 0, 0}, 3, 10, 1, 5000) ==
        RouteUpdateResult::Accepted);
  CHECK(table.best(9).generation == 65536);
  // What a v1 wrap (0xFFFF -> 1) would have advertised is now correctly old.
  CHECK(table.consider(RouteAdvertisement{9, 1, 500, 0}, 4, 1, 2, 5000) ==
        RouteUpdateResult::StaleGeneration);
  CHECK(table.best(9).generation == 65536);
}

// End to end: two nodes whose boot-derived epochs and route generation are
// far past 65,535 exchange reliable traffic over Wire v2 unchanged.
void test_delivery_with_large_epochs() {
  SimWorld w;
  w.link_epoch = 70001;
  w.end_epoch = 90001;
  w.add(1, /*generation=*/80000);
  w.link_epoch = 70002;
  w.end_epoch = 90002;
  w.add(2, /*generation=*/80000);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.run(400);
  send_and_expect(w, 1, 2, 4000, "large-epochs");
}

}  // namespace

int main() {
  test_relay_first_gateway_route(false);
  test_relay_first_gateway_route(true);
  test_relay_first_three_hop_gateway_route(false);
  test_relay_first_three_hop_gateway_route(true);
  test_line_delivery(1);
  test_line_delivery(3);
  test_line_delivery(5);
  test_line_delivery(10);
  test_revoke_routes();
  test_diamond();
  test_ring();
  test_relay_removal();
  test_multi_link_loss();
  test_stale_advertisement_rejected();
  test_route_generation_past_u16_budget();
  test_delivery_with_large_epochs();
  test_stale_feasible_candidate_not_selected();
  test_sequence_wrap();
  test_origin_restart();
  test_relay_restart();
  test_partition_merge();
  test_retraction_propagates();
  test_seqno_intermediate_answers();
  test_seqno_retry_past_cap();
  test_seqno_probe_cursor_past_cap();
  test_multiple_origins_pinning();
  if (failures != 0) {
    std::fprintf(stderr, "%d routing-sim checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom routing profile tests passed");
  return 0;
}
