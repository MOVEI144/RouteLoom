// Gateway-scoped routing profile (docs/design/sdk-v1/routing-scale.md,
// issue #41): ROUTE_REQUEST codec + golden payload parity, lease rules,
// tombstone dwell vs. lease, tree formation, repair, on-demand discovery,
// loop-freedom under churn, and the 100-node scale run with product timers
// (period 5 s, lifetime 90 s) — continuous gateway reachability, no flap,
// board-to-board discovery and a per-node airtime budget check.
//
// Usage: routeloom_routing_scale_tests [unit|scale]  (no argument: both)

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <map>
#include <set>
#include <sstream>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/route_request.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/types.hpp"

#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using routeloom_test::FrameSight;
using routeloom_test::SimWorld;

// §14 airtime model (radio.md §9/§14, congestion.hpp kTxFrameFixedCostBytes):
// encoded frame bytes plus the fixed MAC/LR-preamble/MAC-ACK byte-equivalent,
// at LR 250 kbps = 32 us per byte.
constexpr std::uint64_t kUsPerByte = 32;
constexpr std::uint64_t airtime_us(const routeloom_test::SimNetwork::TxTally& tally) {
  return (tally.bytes + tally.frames * kTxFrameFixedCostBytes) * kUsPerByte;
}

void scoped_profile(SimWorld& w, const NodeId gateway, const std::uint32_t period_ms,
                    const std::uint32_t lifetime_ms) {
  w.configure = [=](NodeConfig& config) {
    config.route_gateways = {gateway, kInvalidNodeId};
    config.route_advertisement_period_ms = period_ms;
    config.route_lifetime_ms = lifetime_ms;
    config.route_refresh_ticks = kScopedDefaultRefreshTicks;
  };
}

// Follows committed next hops for `destination` starting at `from`. Returns
// 1 when the chain reaches the destination, 0 when it hits a node without a
// route (a black hole — allowed transiently), -1 on a forwarding loop.
int follow_chain(const SimWorld& w, NodeId from, const NodeId destination,
                 std::size_t* hops = nullptr) {
  std::set<NodeId> visited;
  std::size_t count = 0;
  while (from != destination) {
    if (!visited.insert(from).second) return -1;
    const auto selection = w.at(from)->routes().best(destination);
    if (!selection.valid) return 0;
    from = selection.next_hop;
    ++count;
    if (w.nodes.count(from) == 0) return 0;
  }
  if (hops != nullptr) *hops = count;
  return 1;
}

// Failure aid: prints the next-hop chain from `from` toward `destination`.
void dump_chain(const SimWorld& w, NodeId from, const NodeId destination) {
  std::fprintf(stderr, "  chain %llu -> %llu at %llu ms:", static_cast<unsigned long long>(from),
               static_cast<unsigned long long>(destination),
               static_cast<unsigned long long>(w.now));
  for (int hop = 0; hop < 12 && from != destination; ++hop) {
    std::fprintf(stderr, " %llu", static_cast<unsigned long long>(from));
    const auto selection = w.at(from)->routes().best(destination);
    if (!selection.valid) {
      std::fprintf(stderr, " (no route)");
      break;
    }
    from = selection.next_hop;
  }
  std::fprintf(stderr, "\n");
}

bool send_data(SimWorld& w, const NodeId from, const NodeId to, MessageId& id,
               const std::uint32_t lifetime_ms = 20000) {
  const std::array<std::uint8_t, 4> payload{{0xB0, 0xA2, 0xD5, 0x01}};
  SendOptions options{};
  options.lifetime_ms = lifetime_ms;
  const auto status =
      w.at(from)->send(to, ByteView{payload.data(), payload.size()}, options, w.now, id);
  if (!status.ok()) {
    std::fprintf(stderr, "  send %llu->%llu refused: %s\n",
                 static_cast<unsigned long long>(from),
                 static_cast<unsigned long long>(to), status.detail);
  }
  return status.ok();
}

// Loop-freedom over recorded DATA sightings: within one message round no
// node forwards to two different next hops and no node receives it twice.
bool data_sights_loop_free(const std::vector<FrameSight>& sights) {
  using Key = std::tuple<NodeId, std::uint32_t, std::uint64_t, std::uint8_t>;
  std::map<Key, std::set<std::pair<NodeId, NodeId>>> edges;
  for (const auto& s : sights) {
    if (s.type != FrameType::Data) continue;
    edges[std::make_tuple(s.origin, s.session, s.sequence, s.round)].insert({s.from, s.to});
  }
  for (const auto& [key, set] : edges) {
    std::map<NodeId, std::set<NodeId>> out;
    std::map<NodeId, std::set<NodeId>> in;
    for (const auto& [from, to] : set) {
      if (to == std::get<0>(key)) return false;  // back at the origin
      out[from].insert(to);
      in[to].insert(from);
    }
    for (const auto& [node, targets] : out) {
      if (targets.size() != 1) return false;
    }
    for (const auto& [node, sources] : in) {
      if (sources.size() != 1) return false;
    }
  }
  return true;
}

// ----------------------------------------------------------------------------
// Unit: ROUTE_REQUEST payload codec
// ----------------------------------------------------------------------------

std::vector<std::uint8_t> from_hex(const std::string& hex) {
  std::vector<std::uint8_t> out;
  for (std::size_t i = 0; i + 1 < hex.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
  }
  return out;
}

// payload_hex of protocol/golden/valid/route_request.json (generated by the
// Rust gen_golden example from the same field values): C++ and Rust agree on
// the payload bytes, the shared golden harnesses on the framed bytes.
std::string golden_route_request_payload_hex() {
  std::ifstream input(std::string(ROUTELOOM_GOLDEN_DIR) + "/valid/route_request.json");
  std::stringstream contents;
  contents << input.rdbuf();
  const std::string text = contents.str();
  const std::string key = "\"payload_hex\": \"";
  const auto start = text.find(key);
  if (start == std::string::npos) return {};
  const auto end = text.find('"', start + key.size());
  return text.substr(start + key.size(), end - start - key.size());
}

void test_route_request_codec() {
  const RouteRequestPayload payload{RouteRequestKind::Discover, 10, 0x0102030405060708ULL,
                                    0x1112131415161718ULL, 0xA1B2C3D4U,
                                    RouteAdvertisement{0x0102030405060708ULL, 7, 0x0123, 0x0010}};
  std::array<std::uint8_t, kRouteRequestPayloadBytes> bytes{};
  std::size_t written = 0;
  CHECK_OK(encode_route_request(payload, MutableByteView{bytes.data(), bytes.size()}, written));
  CHECK(written == kRouteRequestPayloadBytes);
  const auto expected = from_hex(
      "020a"
      "0102030405060708"
      "1112131415161718"
      "a1b2c3d4"
      "0102030405060708"
      "00000007"
      "0123"
      "0010");
  CHECK(expected.size() == written);
  CHECK(std::memcmp(expected.data(), bytes.data(), expected.size()) == 0);
  // Cross-language parity with the shared golden vector.
  CHECK(from_hex(golden_route_request_payload_hex()) == expected);

  RouteRequestPayload decoded{};
  CHECK_OK(decode_route_request(ByteView{bytes.data(), written}, decoded));
  CHECK(decoded.kind == RouteRequestKind::Discover && decoded.ttl == 10);
  CHECK(decoded.requester == payload.requester && decoded.target == payload.target);
  CHECK(decoded.request_id == payload.request_id);
  CHECK(decoded.record.generation == 7 && decoded.record.sequence == 0x0123 &&
        decoded.record.metric == 0x0010);

  auto reject = [&](auto mutate) {
    auto copy = bytes;
    mutate(copy);
    RouteRequestPayload out{};
    return !decode_route_request(ByteView{copy.data(), copy.size()}, out).ok();
  };
  CHECK(reject([](auto& b) { b[0] = 0; }));   // kind 0
  CHECK(reject([](auto& b) { b[0] = 4; }));   // kind 4
  CHECK(reject([](auto& b) { b[1] = 0; }));   // ttl 0
  CHECK(reject([](auto& b) { b[1] = 11; }));  // ttl above the hop limit
  CHECK(reject([](auto& b) { b[0] = 1; }));   // Neighbor must carry ttl 1
  CHECK(reject([](auto& b) { b[0] = 3; }));   // Reply record must be the target's
  CHECK(reject([](auto& b) { std::memset(b.data() + 2, 0, 8); }));     // requester 0
  CHECK(reject([](auto& b) { std::memset(b.data() + 10, 0xFF, 8); }));  // broadcast target
  CHECK(reject([](auto& b) { std::memcpy(b.data() + 10, b.data() + 2, 8); }));  // self target
  {
    RouteRequestPayload out{};
    CHECK(!decode_route_request(ByteView{bytes.data(), written - 1}, out).ok());
    std::array<std::uint8_t, kRouteRequestPayloadBytes + 1> longer{};
    std::memcpy(longer.data(), bytes.data(), written);
    CHECK(!decode_route_request(ByteView{longer.data(), longer.size()}, out).ok());
  }
  // A valid Neighbor pull and a valid Reply decode.
  auto neighbor = bytes;
  neighbor[0] = 1;
  neighbor[1] = 1;
  RouteRequestPayload out{};
  CHECK_OK(decode_route_request(ByteView{neighbor.data(), neighbor.size()}, out));
  auto reply = bytes;
  reply[0] = 3;
  std::memcpy(reply.data() + 22, reply.data() + 10, 8);  // record = target
  CHECK_OK(decode_route_request(ByteView{reply.data(), reply.size()}, out));
}

// Broadcast route payload: parent poisons only its own gateway record while
// a different neighbor still sees a finite metric. Malformed input must not
// publish any records, including a valid prefix.
void test_broadcast_route_payload() {
  std::array<BroadcastRouteRecord, kBroadcastRouteMaxRecords> records{};
  records[0] = {{10, 7, 3, 0}, 0};
  records[1] = {{1, 8, 4, 5}, 20};
  std::array<std::uint8_t, kMaxApplicationPayload> bytes{};
  std::size_t written = 0;
  CHECK_OK(encode_broadcast_route_update(records.data(), 2, 10,
                                         MutableByteView{bytes.data(), bytes.size()}, written));
  CHECK(written == 52);
  CHECK(bytes[0] == 1 && bytes[1] == 0 && bytes[2] == 2 && bytes[3] == 0);
  const std::array<std::uint8_t, 24> second{{0, 0, 0, 0, 0, 0, 0, 1,
                                              0, 0, 0, 8, 0, 4, 0, 5,
                                              0, 0, 0, 0, 0, 0, 0, 20}};
  CHECK(std::memcmp(bytes.data() + 28, second.data(), second.size()) == 0);
  std::array<BroadcastRouteRecord, kBroadcastRouteMaxRecords> decoded{};
  std::size_t count = 0;
  CHECK_OK(decode_broadcast_route_update(ByteView{bytes.data(), written}, 10, decoded, count));
  CHECK(count == 2 && decoded[1].via == 20);
  CHECK(project_broadcast_route_metric(decoded[1], 20) == kInfiniteRouteMetric);
  CHECK(project_broadcast_route_metric(decoded[1], 30) == 5);
  auto bad = bytes;
  bad[2] = 1;  // no trailing records allowed
  CHECK(!decode_broadcast_route_update(ByteView{bad.data(), written}, 10, decoded, count).ok());
  CHECK(count == 0);
  bad = bytes;
  std::memset(bad.data() + 44, 0, 8);
  bad[51] = 10;  // a nonself route cannot point back to its sender
  CHECK(!decode_broadcast_route_update(ByteView{bad.data(), written}, 10, decoded, count).ok());
  CHECK(count == 0);
  bad = bytes;
  // Duplicate destination in the second record.
  std::memcpy(bad.data() + 28, bad.data() + 4, 8);
  CHECK(!decode_broadcast_route_update(ByteView{bad.data(), written}, 10, decoded, count).ok());
  CHECK(count == 0);
  CHECK(!decode_broadcast_route_update(ByteView{bytes.data(), written - 1}, 10,
                                       decoded, count).ok());
  CHECK(count == 0);
}

// ----------------------------------------------------------------------------
// Unit: lease rules and config enforcement
// ----------------------------------------------------------------------------

void test_lease_rules() {
  // Scoped: lifetime >= (2 * ticks + margin) * period.
  CHECK(scoped_lifetime_sufficient(5000, 90000, 6));
  CHECK(scoped_lifetime_sufficient(5000, 70000, 6));
  CHECK(!scoped_lifetime_sufficient(5000, 69999, 6));
  CHECK(!scoped_lifetime_sufficient(5000, 15000, 6));  // the old default flaps
  CHECK(!scoped_lifetime_sufficient(0, 90000, 6));
  CHECK(!scoped_lifetime_sufficient(5000, 90000, 0));
  // Flat: pages of six routes each (the self record takes the seventh slot).
  CHECK(flat_refresh_pages(0) == 1);
  CHECK(flat_refresh_pages(6) == 1);
  CHECK(flat_refresh_pages(7) == 2);
  CHECK(flat_refresh_pages(100) == 17);
  // Issue #41: with one period of margin, 5 s / 15 s sustains a single page
  // (6 destinations); 100 destinations need 17 pages, i.e. a lease > 90 s.
  CHECK(flat_lifetime_sufficient(5000, 15000, 6));
  CHECK(!flat_lifetime_sufficient(5000, 15000, 7));
  CHECK(!flat_lifetime_sufficient(5000, 15000, 100));
  CHECK(!flat_lifetime_sufficient(5000, 90000, 100));
  CHECK(flat_lifetime_sufficient(5000, 90001, 100));
}

void test_scoped_config_enforced() {
  {
    SimWorld w;
    scoped_profile(w, 1, 5000, 15000);  // flat default lifetime: rejected
    w.add(1);
    const auto status = w.at(1)->start(0);
    CHECK(!status.ok());
    CHECK(std::string(status.detail) == "ROUTE_LIFETIME_BELOW_REFRESH_BOUND");
  }
  {
    SimWorld w;
    scoped_profile(w, 1, 5000, kScopedProductLifetimeMs);
    w.add(1);
    CHECK_OK(w.at(1)->start(0));
    CHECK(w.at(1)->gateway_scoped());
    // The enforced bound replaces the flat-profile diagnostic.
    CHECK(!w.obs(1)->has_diag("ROUTE_REFRESH_BOUND_EXCEEDED"));
  }
  {
    SimWorld w;
    w.configure = [](NodeConfig& config) {
      config.route_gateways = {kBroadcastNodeId, kInvalidNodeId};
      config.route_lifetime_ms = kScopedProductLifetimeMs;
    };
    w.add(1);
    CHECK(!w.at(1)->start(0).ok());
  }
  {
    SimWorld w;  // flat profile keeps its (non-fatal) diagnostic
    w.add(1, 1, 5000, 15000);
    CHECK_OK(w.at(1)->start(0));
    CHECK(!w.at(1)->gateway_scoped());
    CHECK(w.obs(1)->has_diag("ROUTE_REFRESH_BOUND_EXCEEDED"));
  }
}

// ----------------------------------------------------------------------------
// Unit: RouteTable pieces the profile relies on
// ----------------------------------------------------------------------------

void test_tombstone_outlives_lease() {
  // A tombstone that dies before the neighbors' leases lets a stale,
  // older-sequence advertisement pass feasibility against a reset FD. The
  // dwell therefore follows the lease (RFC 8966 §3.7.3).
  auto run = [](const std::uint32_t dwell_for_lifetime) {
    RouteTable table;
    table.set_tombstone_dwell(dwell_for_lifetime);
    CHECK(table.consider(RouteAdvertisement{9, 1, 10, 0}, 2, 1, 0, 1000) ==
          RouteUpdateResult::Accepted);
    CHECK(table.mark_advertised(9));  // FD = (10, 1)
    table.expire(1000);               // lease gone -> tombstone armed
    CHECK(!table.best(9).valid);
    table.expire(70000);              // past the default 60 s dwell
    return table.consider(RouteAdvertisement{9, 1, 9, 0}, 3, 1, 70000, 1000);
  };
  CHECK(run(0) == RouteUpdateResult::Accepted);  // default dwell: stale route admitted
  CHECK(run(90000) == RouteUpdateResult::Infeasible);
  RouteTable table;
  table.set_tombstone_dwell(15000);
  CHECK(table.tombstone_dwell_ms() == kRouteTombstoneDwellMs);  // never below default
}

void test_lost_route_and_previous_selection() {
  RouteTable table;
  CHECK(table.consider(RouteAdvertisement{9, 3, 40, 5}, 2, 1, 0, 5000) ==
        RouteUpdateResult::Accepted);
  CHECK(table.mark_advertised(9));
  RouteTable::LostRoute lost{};
  CHECK(!table.lost_route(9, lost));  // still selected
  std::vector<std::pair<RouteSelection, RouteSelection>> seen;
  table.for_each_selected_change(
      [&](const RouteSelection& now, const RouteSelection& before) {
        seen.emplace_back(now, before);
      },
      1);
  CHECK(seen.empty());  // mark_advertised synced the snapshot
  CHECK(table.withdraw(9, 2, 2));
  table.for_each_selected_change(
      [&](const RouteSelection& now, const RouteSelection& before) {
        seen.emplace_back(now, before);
      },
      3);
  CHECK(seen.size() == 1);
  if (!seen.empty()) {
    CHECK(!seen[0].first.valid);
    CHECK(seen[0].second.valid && seen[0].second.next_hop == 2 &&
          seen[0].second.destination == 9);
  }
  CHECK(table.lost_route(9, lost));
  CHECK(lost.destination == 9 && lost.generation == 3 && lost.sequence == 40);
  CHECK(!table.lost_route(77, lost));
}

// ----------------------------------------------------------------------------
// Small scoped meshes (compressed timers: period 500 ms, lease 9 s)
// ----------------------------------------------------------------------------

constexpr std::uint32_t kFastPeriodMs = 500;
constexpr std::uint32_t kFastLifetimeMs = 9000;
static_assert(scoped_lifetime_sufficient(kFastPeriodMs, kFastLifetimeMs,
                                         kScopedDefaultRefreshTicks),
              "compressed test profile must satisfy the scoped lease rule");

void test_tree_formation_and_cadence() {
  SimWorld w;
  scoped_profile(w, 1, kFastPeriodMs, kFastLifetimeMs);
  for (NodeId id = 1; id <= 4; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.link(3, 4, 1, 1);
  w.run(6000);
  CHECK(w.at(2)->routes().best(1).valid && w.at(2)->routes().best(1).next_hop == 1);
  CHECK(w.at(4)->routes().best(1).valid && w.at(4)->routes().best(1).next_hop == 3);
  CHECK(w.at(1)->scoped_child(2));
  CHECK(w.at(2)->scoped_child(3));
  CHECK(w.at(3)->scoped_child(4));
  CHECK(!w.at(2)->scoped_child(1));
  CHECK(!w.at(4)->scoped_child(3));
  // Upward learning: the gateway reaches the far leaf through the tree...
  CHECK(w.at(1)->routes().best(4).valid && w.at(1)->routes().best(4).next_hop == 2);
  // ...but downward frames carry only self + gateway records, so a leaf
  // holds no route to its grandparent (no flat dump of the whole table).
  CHECK(!w.at(4)->routes().best(2).valid);

  // Steady-state cadence: one frame per tree link per cycle.
  const auto before = w.net.route_control_tx;
  const std::uint32_t cycle_ms = kFastPeriodMs * kScopedDefaultRefreshTicks;
  const std::uint32_t cycles = 20;
  w.run(cycle_ms * cycles - 5);
  auto frames = [&](const NodeId id) {
    const auto it = before.find(id);
    return w.net.route_control_tx[id].frames - (it == before.end() ? 0 : it->second.frames);
  };
  // Leaf 4: one upward frame per cycle (its only neighbor is its parent).
  CHECK(frames(4) >= cycles - 1 && frames(4) <= cycles + 1);
  // Gateway 1: one downward frame per cycle to its single child.
  CHECK(frames(1) >= cycles - 1 && frames(1) <= cycles + 1);
  // Relay 2: one up + one down per cycle.
  CHECK(frames(2) >= 2 * cycles - 2 && frames(2) <= 2 * cycles + 2);
  // Routes never lapsed during the window.
  CHECK(w.at(4)->routes().best(1).valid && w.at(1)->routes().best(4).valid);
}

void test_repair_after_parent_loss() {
  // Gateway 1; relays 2 and 3; 4 hangs off both relays and has child 5.
  SimWorld w;
  scoped_profile(w, 1, kFastPeriodMs, kFastLifetimeMs);
  for (NodeId id = 1; id <= 5; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.link(3, 4, 1, 1);
  w.link(4, 5, 1, 1);
  w.run(8000);
  const auto before = w.at(4)->routes().best(1);
  CHECK(before.valid && (before.next_hop == 2 || before.next_hop == 3));
  CHECK(follow_chain(w, 1, 5) == 1);
  const NodeId lost_parent = before.next_hop;
  const NodeId other = lost_parent == 2 ? 3 : 2;
  w.unlink(lost_parent, 4);
  w.run(6000);
  const auto after = w.at(4)->routes().best(1);
  CHECK(after.valid && after.next_hop == other);
  CHECK(w.at(5)->routes().best(1).valid);
  CHECK(follow_chain(w, 5, 1) == 1);
  CHECK(follow_chain(w, 1, 5) == 1);  // downward follows the new branch
  MessageId down{};
  MessageId up{};
  CHECK(send_data(w, 1, 5, down));
  CHECK(send_data(w, 5, 1, up));
  w.run(3000);
  CHECK(w.at(1)->delivery(down).state == DeliveryState::Delivered);
  CHECK(w.at(5)->delivery(up).state == DeliveryState::Delivered);
  CHECK(w.at(4)->route_scale_stats().pulls_sent + w.at(4)->route_scale_stats().upward_frames > 0);
  CHECK(data_sights_loop_free(w.net.sights));
}

// A better parent appears while the old parent still reaches the board: the
// board re-parents, the new parent carries the subtree upward at once, and
// the old parent — told after kScopedReleaseDelayMs — retracts what it had
// announced instead of letting the ancestors' copies decay one lease later.
// The gateway follows the new branch without ever losing its route.
void test_parent_switch_keeps_downward_reachability() {
  SimWorld w;
  scoped_profile(w, 1, kFastPeriodMs, kFastLifetimeMs);
  for (NodeId id = 1; id <= 5; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 3, 3);  // old parent 2: a costly uplink
  w.link(1, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.link(4, 5, 1, 1);
  w.run(6000);
  CHECK(w.at(4)->routes().best(1).next_hop == 2);
  CHECK(w.at(1)->routes().best(5).next_hop == 2);
  CHECK(w.at(2)->routes().announced_up(5));
  // A cheaper relay comes into range. 4 learns it from 3's slow rotation to
  // non-tree neighbors and re-parents (strictly better advertised metric).
  w.link(3, 4, 1, 1);
  int downward_breaks = 0;
  int loops = 0;
  MonotonicMs switched_at = 0;
  for (int step = 0; step < 6000 && (switched_at == 0 || w.now < switched_at + 5000); ++step) {
    w.run(0);
    if (switched_at == 0 && w.at(4)->routes().best(1).next_hop == 3) switched_at = w.now;
    const int chain = follow_chain(w, 1, 5);
    if (chain == 0) ++downward_breaks;
    if (chain < 0) ++loops;
  }
  CHECK(switched_at != 0);
  CHECK(w.at(3)->scoped_child(4));
  CHECK(!w.at(2)->scoped_child(4));
  // Retracted within the release delay (plus a triggered interval), well
  // before the old copies would have expired (lease 9 s).
  CHECK(!w.at(2)->routes().announced_up(5));
  CHECK(w.at(2)->routes().best(5).valid);  // the old path itself still works
  CHECK(w.at(1)->routes().best(5).next_hop == 3);
  CHECK(downward_breaks == 0);
  CHECK(loops == 0);
  MessageId down{};
  CHECK(send_data(w, 1, 5, down));
  w.run(2000);
  CHECK(w.at(1)->delivery(down).state == DeliveryState::Delivered);
}

void test_on_demand_discovery() {
  // Two branches under gateway 1: 4 - 2 - 1 - 3 - 5.
  SimWorld w;
  scoped_profile(w, 1, kFastPeriodMs, kFastLifetimeMs);
  for (NodeId id = 1; id <= 5; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(1, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.link(3, 5, 1, 1);
  w.run(6000);
  CHECK(!w.at(4)->routes().best(5).valid);  // not in 4's tree view
  MessageId id{};
  CHECK(send_data(w, 4, 5, id));
  w.run(3000);
  CHECK(w.at(4)->delivery(id).state == DeliveryState::Delivered);
  const auto& s4 = w.at(4)->route_scale_stats();
  CHECK(s4.discoveries_started == 1);
  CHECK(s4.discovery_requests_sent >= 1);
  CHECK(s4.discoveries_resolved == 1);
  CHECK(w.at(5)->route_scale_stats().discovery_replies_sent >= 1);
  CHECK(w.at(2)->route_scale_stats().discovery_requests_forwarded >= 1);
  CHECK(w.at(1)->route_scale_stats().discovery_requests_forwarded >= 1);
  CHECK(w.at(2)->route_scale_stats().discovery_replies_forwarded >= 1);
  // Both directions now hold feasible, loop-free chains.
  CHECK(follow_chain(w, 4, 5) == 1);
  CHECK(follow_chain(w, 5, 4) == 1);
  MessageId back{};
  CHECK(send_data(w, 5, 4, back));
  w.run(2000);
  CHECK(w.at(5)->delivery(back).state == DeliveryState::Delivered);
  CHECK(data_sights_loop_free(w.net.sights));
  // Discovered routes are a cache: unused, they lapse after one lease.
  w.run(kFastLifetimeMs + 2000);
  CHECK(!w.at(4)->routes().best(5).valid);
}

void test_flat_node_ignores_route_request() {
  // A scoped node whose gateway is unreachable pulls its neighbors; a flat
  // neighbor never answers and never acts on the frame.
  SimWorld w;
  w.configure = [](NodeConfig& config) {
    if (config.node == 1) {
      config.route_gateways = {99, kInvalidNodeId};
      config.route_advertisement_period_ms = kFastPeriodMs;
      config.route_lifetime_ms = kFastLifetimeMs;
    }
  };
  w.add(1);
  w.add(2, 1, 100, 1000);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.run(1500);
  CHECK(w.at(1)->route_scale_stats().pulls_sent >= 1);
  CHECK(w.obs(2)->has_diag("ROUTE_REQUEST_UNSUPPORTED"));
  CHECK(!w.at(2)->routes().best(99).valid);
}

// Loop-freedom under churn: 5x5 grid (8-neighborhood), gateway in a corner,
// deterministic link flaps; next-hop chains toward the gateway and toward
// every board from the gateway must never cycle, and DATA never loops.
void test_scoped_loop_freedom_under_churn() {
  SimWorld w;
  constexpr int kSide = 5;
  auto id = [](int x, int y) { return static_cast<NodeId>(1 + x * kSide + y); };
  const NodeId gateway = id(0, 0);
  scoped_profile(w, gateway, kFastPeriodMs, kFastLifetimeMs);
  for (int x = 0; x < kSide; ++x) {
    for (int y = 0; y < kSide; ++y) w.add(id(x, y));
  }
  w.start_all();
  std::vector<std::pair<NodeId, NodeId>> links;
  for (int x = 0; x < kSide; ++x) {
    for (int y = 0; y < kSide; ++y) {
      for (const auto& [dx, dy] : {std::pair{1, 0}, std::pair{0, 1}, std::pair{1, 1},
                                   std::pair{1, -1}}) {
        const int nx = x + dx;
        const int ny = y + dy;
        if (nx < 0 || ny < 0 || nx >= kSide || ny >= kSide) continue;
        w.link(id(x, y), id(nx, ny), 1, 1);
        links.emplace_back(id(x, y), id(nx, ny));
      }
    }
  }
  w.run(10000);
  std::uint64_t lcg = 0x5EED5EEDULL;
  auto next = [&]() {
    lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
    return static_cast<std::uint32_t>(lcg >> 33);
  };
  std::set<std::pair<NodeId, NodeId>> down;
  int loops = 0;
  for (int round = 0; round < 40; ++round) {
    // Flap one link (never more than 6 down at once), then send a little.
    const auto link = links[next() % links.size()];
    if (down.count(link) != 0) {
      w.net.connect(link.first, link.second);
      w.at(link.first)->add_neighbor(link.second, 1, w.now);
      w.at(link.second)->add_neighbor(link.first, 1, w.now);
      down.erase(link);
    } else if (down.size() < 6) {
      w.unlink(link.first, link.second);
      down.insert(link);
    }
    const NodeId board = id(static_cast<int>(1 + next() % (kSide - 1)),
                            static_cast<int>(next() % kSide));
    MessageId msg{};
    (void)send_data(w, board, gateway, msg, 5000);
    (void)send_data(w, gateway, board, msg, 5000);
    for (int step = 0; step < 20; ++step) {
      w.run(100);
      for (const auto& [node, ptr] : w.nodes) {
        if (node != gateway && follow_chain(w, node, gateway) < 0) ++loops;
        if (node != gateway && follow_chain(w, gateway, node) < 0) ++loops;
      }
    }
  }
  CHECK(loops == 0);
  CHECK(data_sights_loop_free(w.net.sights));
}

// ----------------------------------------------------------------------------
// Scale: 100 nodes, one gateway, product timers
// ----------------------------------------------------------------------------

RouteScaleStats sum_stats(const SimWorld& w) {
  RouteScaleStats sum{};
  for (const auto& [node, ptr] : w.nodes) {
    const auto& s = ptr->route_scale_stats();
    sum.upward_frames += s.upward_frames;
    sum.downward_frames += s.downward_frames;
    sum.other_frames += s.other_frames;
    sum.pull_answers += s.pull_answers;
    sum.pulls_sent += s.pulls_sent;
  }
  return sum;
}

void test_hundred_node_site() {
  constexpr int kSide = 10;
  constexpr std::uint32_t kPeriodMs = kScopedProductPeriodMs;      // 5 s
  constexpr std::uint32_t kLifetimeMs = kScopedProductLifetimeMs;  // 90 s
  constexpr routeloom::MonotonicMs kStepMs = 50;
  auto id = [](int x, int y) { return static_cast<NodeId>(1 + x * kSide + y); };
  const NodeId gateway = id(0, 4);  // gateway on an outer wall: depth 9

  SimWorld w;
  w.net.record_sights = false;  // bounded memory for the long run (issue #59)
  scoped_profile(w, gateway, kPeriodMs, kLifetimeMs);
  for (int x = 0; x < kSide; ++x) {
    for (int y = 0; y < kSide; ++y) w.add(id(x, y));
  }
  w.start_all();
  for (int x = 0; x < kSide; ++x) {
    for (int y = 0; y < kSide; ++y) {
      for (const auto& [dx, dy] : {std::pair{1, 0}, std::pair{0, 1}, std::pair{1, 1},
                                   std::pair{1, -1}}) {
        const int nx = x + dx;
        const int ny = y + dy;
        if (nx < 0 || ny < 0 || nx >= kSide || ny >= kSide) continue;
        w.link(id(x, y), id(nx, ny), 1, 1);
      }
    }
  }
  std::vector<NodeId> boards;
  for (const auto& [node, ptr] : w.nodes) {
    if (node != gateway) boards.push_back(node);
  }

  // --- Convergence ----------------------------------------------------------
  auto converged = [&]() {
    for (const NodeId board : boards) {
      if (follow_chain(w, board, gateway) != 1) return false;
      if (follow_chain(w, gateway, board) != 1) return false;
    }
    return true;
  };
  routeloom::MonotonicMs converged_at = 0;
  while (w.now <= 120000) {
    w.run(1000 - kStepMs, kStepMs);
    if (converged()) {
      converged_at = w.now;
      break;
    }
  }
  CHECK(converged_at != 0);
  {
    routeloom_test::SimNetwork::TxTally bootstrap{};
    for (const auto& [node, tally] : w.net.route_control_tx) {
      bootstrap.frames += tally.frames;
      bootstrap.bytes += tally.bytes;
    }
    std::fprintf(stderr, "  scale: converged at %llu ms after %llu route-control frames (%.1f s air)\n",
                 static_cast<unsigned long long>(converged_at),
                 static_cast<unsigned long long>(bootstrap.frames),
                 static_cast<double>(airtime_us(bootstrap)) / 1e6);
  }

  // --- Steady state: 4 minutes, continuous reachability, no loops ----------
  const auto tally_before = w.net.route_control_tx;
  const RouteScaleStats stats_before = sum_stats(w);
  const routeloom::MonotonicMs window_start = w.now;
  constexpr routeloom::MonotonicMs kWindowMs = 240000;
  std::size_t upward_lapses = 0;
  std::size_t downward_lapses = 0;
  std::size_t chain_failures = 0;
  std::size_t loops = 0;
  std::size_t max_depth = 0;
  const routeloom::MonotonicMs window_end = window_start + kWindowMs;
  std::size_t tick = 0;
  while (w.now < window_end) {
    w.run(0, kStepMs);  // exactly one step
    // Every step: every board holds a route to the gateway and the gateway
    // one to every board (the "no flap" property of issue #41).
    for (const NodeId board : boards) {
      if (!w.at(board)->routes().best(gateway).valid) ++upward_lapses;
      if (!w.at(gateway)->routes().best(board).valid) ++downward_lapses;
    }
    // Every second: the committed next-hop chains actually arrive.
    if (++tick % 20 == 0) {
      for (const NodeId board : boards) {
        std::size_t hops = 0;
        const int up = follow_chain(w, board, gateway, &hops);
        const int dn = follow_chain(w, gateway, board);
        if (up < 0 || dn < 0) ++loops;
        if (up != 1 || dn != 1) {
          if (++chain_failures <= 5) {
            dump_chain(w, up != 1 ? board : gateway, up != 1 ? gateway : board);
          }
        }
        max_depth = std::max(max_depth, hops);
      }
    }
  }
  CHECK(upward_lapses == 0);
  CHECK(downward_lapses == 0);
  CHECK(chain_failures == 0);
  CHECK(loops == 0);
  CHECK(max_depth <= kDefaultHopLimit);
  std::fprintf(stderr, "  scale: lapses up=%zu down=%zu chain=%zu loops=%zu max_depth=%zu\n",
               upward_lapses, downward_lapses, chain_failures, loops, max_depth);

  // --- Airtime against the §14 envelope --------------------------------------
  const double window_s = static_cast<double>(w.now - window_start) / 1000.0;
  double network_us_per_s = 0;
  double max_us_per_s = 0;
  double max_leaf_us_per_s = 0;
  NodeId max_node = kInvalidNodeId;
  std::size_t leaves = 0;
  std::uint64_t window_frames = 0;
  for (const auto& [node, ptr] : w.nodes) {
    routeloom_test::SimNetwork::TxTally delta = w.net.route_control_tx[node];
    const auto it = tally_before.find(node);
    if (it != tally_before.end()) {
      delta.frames -= it->second.frames;
      delta.bytes -= it->second.bytes;
    }
    window_frames += delta.frames;
    const double us_per_s = static_cast<double>(airtime_us(delta)) / window_s;
    network_us_per_s += us_per_s;
    if (us_per_s > max_us_per_s) {
      max_us_per_s = us_per_s;
      max_node = node;
    }
    bool has_child = false;
    for (const auto& [other, other_ptr] : w.nodes) has_child |= ptr->scoped_child(other);
    if (!has_child && node != gateway) {
      ++leaves;
      max_leaf_us_per_s = std::max(max_leaf_us_per_s, us_per_s);
    }
  }
  const double mean_us_per_s = network_us_per_s / static_cast<double>(w.nodes.size());
  const RouteScaleStats stats_after = sum_stats(w);
  std::fprintf(stderr,
               "  scale: window %.0f s, route-control frames=%llu (up=%llu down=%llu other=%llu "
               "pull=%llu answer=%llu)\n",
               window_s, static_cast<unsigned long long>(window_frames),
               static_cast<unsigned long long>(stats_after.upward_frames -
                                               stats_before.upward_frames),
               static_cast<unsigned long long>(stats_after.downward_frames -
                                               stats_before.downward_frames),
               static_cast<unsigned long long>(stats_after.other_frames -
                                               stats_before.other_frames),
               static_cast<unsigned long long>(stats_after.pulls_sent - stats_before.pulls_sent),
               static_cast<unsigned long long>(stats_after.pull_answers -
                                               stats_before.pull_answers));
  std::fprintf(stderr,
               "  scale: airtime network=%.0f us/s mean=%.0f us/s max=%.0f us/s (node %llu) "
               "max_leaf=%.0f us/s leaves=%zu\n",
               network_us_per_s, mean_us_per_s, max_us_per_s,
               static_cast<unsigned long long>(max_node), max_leaf_us_per_s, leaves);
  // radio.md §14 / radio-defaults.json scheduling: the 100 000 us/s network
  // management envelope, 1 000 us/s per node on average (100 design nodes),
  // every leaf board inside its own share, and no hotspot above 1 % of the
  // channel (hubs relay their subtree's upward pages — routing-scale.md §7).
  CHECK(network_us_per_s <= kControlBudgetNetworkUsPerS);
  CHECK(mean_us_per_s <= kControlBudgetRefillUsPerS);
  CHECK(leaves > 0 && max_leaf_us_per_s <= kControlBudgetRefillUsPerS);
  CHECK(max_us_per_s <= 10.0 * kControlBudgetRefillUsPerS);

  // --- Traffic: boards up to the gateway, gateway down to boards -----------
  constexpr routeloom::MonotonicMs kFineStepMs = 5;
  std::uint64_t lcg = 0xC0FFEEULL;
  auto pick = [&]() {
    lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
    return boards[static_cast<std::size_t>(lcg >> 33) % boards.size()];
  };
  std::vector<std::pair<NodeId, MessageId>> ups;
  std::vector<MessageId> downs;
  const std::size_t gateway_messages_before = w.obs(gateway)->messages.size();
  const routeloom::MonotonicMs traffic_start = w.now;
  std::set<NodeId> reporters;
  while (reporters.size() < 10) reporters.insert(pick());
  for (const NodeId board : reporters) {  // ten occupancy reports at once
    MessageId up{};
    if (send_data(w, board, gateway, up)) ups.emplace_back(board, up);
  }
  for (int i = 0; i < 6; ++i) {  // display updates (gateway delivery pool: 8)
    MessageId dn{};
    if (send_data(w, gateway, pick(), dn)) downs.push_back(dn);
  }
  CHECK(ups.size() == 10 && downs.size() == 6);
  // Mesh-time latency: every occupancy report lands at the gateway fast.
  routeloom::MonotonicMs all_up_at = 0;
  while (w.now < traffic_start + 3000) {
    w.run(0, kFineStepMs);
    if (all_up_at == 0 &&
        w.obs(gateway)->messages.size() >= gateway_messages_before + ups.size()) {
      all_up_at = w.now;
    }
  }
  for (const auto& [from, msg] : ups) {
    CHECK(w.at(from)->delivery(msg).state == DeliveryState::Delivered);
  }
  for (const auto& msg : downs) {
    CHECK(w.at(gateway)->delivery(msg).state == DeliveryState::Delivered);
  }
  CHECK(all_up_at != 0 && all_up_at - traffic_start <= 200);
  std::fprintf(stderr, "  scale: 10 upstream reports all at the gateway after %llu ms\n",
               static_cast<unsigned long long>(all_up_at - traffic_start));
  // The burst moved load-coupled link costs (nominal metric 1 quantizes a
  // 25 % work/accept ratio to a doubled cost), which may re-parent a board
  // between equal-cost relays. Downward reachability of the moved subtree is
  // then restored by the triggered upward path, not by lease expiry: bound it.
  const routeloom::MonotonicMs settle_start = w.now;
  while (!converged() && w.now < settle_start + 10000) w.run(0, kStepMs);
  CHECK(converged());
  CHECK(w.now - settle_start <= 5000);
  std::fprintf(stderr, "  scale: reachability settled %llu ms after the burst\n",
               static_cast<unsigned long long>(w.now - settle_start));

  // --- Board-to-board via on-demand discovery ------------------------------
  // Random pairs among boards within five hops of the gateway, so the tree
  // path (up to the common ancestor and down) stays inside the 10-hop limit.
  std::vector<NodeId> near;
  for (const NodeId board : boards) {
    std::size_t hops = 0;
    if (follow_chain(w, board, gateway, &hops) == 1 && hops <= 5) near.push_back(board);
  }
  int via_discovery = 0;
  for (int pair = 0; pair < 3; ++pair) {
    lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
    const NodeId a = near[static_cast<std::size_t>(lcg >> 33) % near.size()];
    lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
    NodeId c = near[static_cast<std::size_t>(lcg >> 33) % near.size()];
    if (c == a) c = near[(static_cast<std::size_t>(lcg >> 40) + 1) % near.size()];
    if (c == a) continue;
    const bool had_route = w.at(a)->routes().best(c).valid;
    const auto started = w.at(a)->route_scale_stats().discoveries_started;
    MessageId msg{};
    CHECK(send_data(w, a, c, msg));
    w.run(3000, kFineStepMs);
    const bool delivered = w.at(a)->delivery(msg).state == DeliveryState::Delivered;
    CHECK(delivered);
    if (!had_route) {
      CHECK(w.at(a)->route_scale_stats().discoveries_started == started + 1);
      via_discovery += delivered ? 1 : 0;
    }
    std::fprintf(stderr, "  scale: board %llu -> board %llu %s (%s)\n",
                 static_cast<unsigned long long>(a), static_cast<unsigned long long>(c),
                 delivered ? "delivered" : "FAILED",
                 had_route ? "route already known" : "via discovery");
  }
  CHECK(via_discovery >= 1);
  // Discovery never disturbs the tree: reachability holds afterwards.
  CHECK(converged());
  if (!converged()) {
    for (const NodeId board : boards) {
      if (follow_chain(w, board, gateway) != 1) dump_chain(w, board, gateway);
      if (follow_chain(w, gateway, board) != 1) dump_chain(w, gateway, board);
    }
  }
}

}  // namespace

int main(int argc, char** argv) {
  const std::string mode = argc > 1 ? argv[1] : "";
  if (mode.empty() || mode == "unit") {
    test_route_request_codec();
    test_broadcast_route_payload();
    test_lease_rules();
    test_scoped_config_enforced();
    test_tombstone_outlives_lease();
    test_lost_route_and_previous_selection();
    test_tree_formation_and_cadence();
    test_repair_after_parent_loss();
    test_parent_switch_keeps_downward_reachability();
    test_on_demand_discovery();
    test_flat_node_ignores_route_request();
    test_scoped_loop_freedom_under_churn();
  }
  if (mode.empty() || mode == "scale") {
    test_hundred_node_site();
  }
  if (failures != 0) {
    std::fprintf(stderr, "%d routing-scale checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom routing-scale tests passed");
  return 0;
}
