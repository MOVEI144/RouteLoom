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
    // P5-2: a flat all-destinations dump must not silently accept opt-in.
    SimWorld w;
    w.configure = [](NodeConfig& config) { config.route_broadcast = true; };
    w.add(1);
    const auto status = w.at(1)->start(0);
    CHECK(status.code == StatusCode::Unsupported);
    CHECK(std::string(status.detail) == "BROADCAST_REQUIRES_SCOPED_ROUTES");
  }
  {
    // P5-2: scoped opt-in starts — batched GroupLink advertisements to live
    // grant holders, unicast everywhere else. The default stays off.
    SimWorld w;
    scoped_profile(w, 1, 5000, kScopedProductLifetimeMs);
    const auto configure = w.configure;
    w.configure = [configure](NodeConfig& config) {
      configure(config);
      config.route_broadcast = true;
    };
    w.add(1);
    CHECK_OK(w.at(1)->start(0));
    CHECK(w.at(1)->gateway_scoped());
    SimWorld plain;
    scoped_profile(plain, 1, 5000, kScopedProductLifetimeMs);
    plain.add(1);
    CHECK_OK(plain.at(1)->start(0));
    std::array<std::uint8_t, kCapabilitiesNonceSize> nonce{};
    nonce.fill(0x11);
    CHECK((w.at(1)->build_capabilities_reply(nonce).features &
           kCapRouteBroadcastV1) != 0);
    CHECK((plain.at(1)->build_capabilities_reply(nonce).features &
           kCapRouteBroadcastV1) == 0);
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
    sum.broadcast_frames += s.broadcast_frames;
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

// ----------------------------------------------------------------------------
// P5-2 broadcast: grant lifecycle, batched TX, dedicated RX (V1-K08)
// ----------------------------------------------------------------------------

void broadcast_profile(SimWorld& w, const NodeId gateway) {
  scoped_profile(w, gateway, kFastPeriodMs, kFastLifetimeMs);
  const auto configure = w.configure;
  w.configure = [configure](NodeConfig& config) {
    configure(config);
    config.route_broadcast = true;
  };
}

// Owner-stand-in probing: every node in `probers` queries every neighbor.
// One deterministic nonzero nonce per (querier, peer); renewal/outstanding
// refusals are normal pacing, never failures.
//
// Two pacings shape the round. First, the node's per-origin queue (12)
// holds queries, replies and route jobs together: bursting all 8 queries
// at once leaves no room for the replies. Second, the sim dispatches one
// in-flight frame per poll, so an undrained round trickles over hundreds
// of ms — and any nonzero exchange latency collides with the 5 s renewal
// bound (the next round is then refused and its grants lapse). Batches of
// two with a full same-instant drain between them respect both, the way a
// real Owner paces its probes and real firmware completes a round in ms.
void probe_broadcast_grants(SimWorld& w, const std::set<NodeId>& probers,
                            std::uint64_t& lcg) {
  std::map<NodeId, std::vector<NodeId>> neighbors;
  std::size_t most = 0;
  for (const NodeId node : probers) {
    if (w.nodes.count(node) == 0) continue;
    for (const auto& [peer, ptr] : w.nodes) {
      if (peer != node && w.net.connected(node, peer)) {
        neighbors[node].push_back(peer);
      }
    }
    most = std::max(most, neighbors[node].size());
  }
  constexpr std::size_t kProbeBatch = 2;
  for (std::size_t base = 0; base < most; base += kProbeBatch) {
    for (const auto& [node, peers] : neighbors) {
      for (std::size_t k = 0; k < kProbeBatch && base + k < peers.size();
           ++k) {
        std::array<std::uint8_t, kCapabilitiesNonceSize> nonce{};
        for (auto& byte : nonce) {
          lcg = lcg * 6364136223846793005ULL + 1442695040888963407ULL;
          byte = static_cast<std::uint8_t>(lcg >> 33);
        }
        nonce[0] |= 0x01;  // the codec refuses an all-zero nonce
        (void)w.at(node)->send_capabilities_query(peers[base + k], nonce,
                                                  w.now);
      }
    }
    // ~2 frames per node per pass (poll dispatch + post-drain dispatch);
    // 8 passes drain a batch several times over, all at one `now`.
    for (int pass = 0; pass < 8; ++pass) {
      for (const auto& [node, ptr] : w.nodes) ptr->poll(w.now);
      w.net.flush(w.now);
    }
  }
}

bool saw_broadcast_update(const SimWorld& w, const NodeId from) {
  for (const auto& sight : w.net.sights) {
    if (sight.type == FrameType::RouteUpdate && sight.from == from &&
        sight.to == kBroadcastNodeId) {
      return true;
    }
  }
  return false;
}

// Seals an authentic broadcast RouteUpdate from `from` under its test GK.
bool seal_broadcast_frame(routeloom_test::TestSecurity& security,
                          const NetworkId network, const NodeId from,
                          const BroadcastRouteRecord* records,
                          const std::size_t count,
                          wire::EncodedFrame& encoded) {
  wire::PlainFrame frame{};
  frame.header.network = network;
  frame.header.type = FrameType::RouteUpdate;
  frame.header.origin = from;
  frame.header.previous_hop = from;
  frame.header.next_hop = kBroadcastNodeId;
  frame.header.destination = kBroadcastNodeId;
  frame.header.hop_remaining = 1;
  frame.header.delivery = DeliveryClass::BestEffort;
  frame.header.message = MessageId{100 + static_cast<std::uint32_t>(from), 1};
  frame.header.original_lifetime_ms = 1000;
  frame.header.remaining_deadline_ms = 1000;
  frame.header.link_epoch = 1;
  frame.header.end_epoch = 1;
  std::size_t written = 0;
  if (!encode_broadcast_route_update(
          records, count, from,
          MutableByteView{frame.payload.data(), frame.payload.size()},
          written)) {
    return false;
  }
  frame.payload_size = written;
  return wire::encode_new(frame, security, encoded).ok();
}

void test_broadcast_grant_lifecycle() {
  SimWorld w;
  broadcast_profile(w, 1);
  w.add(1);
  w.add(2);
  w.start_all();
  w.link(1, 2, 1, 1);
  CHECK(!w.at(1)->peer_broadcast_eligible(2, w.now));  // no grant yet
  std::uint64_t lcg = 0xBCA57;
  probe_broadcast_grants(w, {1, 2}, lcg);
  w.run(100);
  CHECK(w.at(1)->peer_broadcast_eligible(2, w.now));
  CHECK(w.at(2)->peer_broadcast_eligible(1, w.now));
  // A legacy peer answers without the bit: probed, but never eligible.
  const auto configure = w.configure;
  w.configure = [configure](NodeConfig& config) {
    configure(config);
    config.route_broadcast = false;
  };
  w.add(3);
  CHECK_OK(w.at(3)->start(w.now));
  w.link(1, 3, 1, 1);
  probe_broadcast_grants(w, {1}, lcg);
  w.run(100);
  CHECK(!w.at(1)->peer_broadcast_eligible(3, w.now));
  // A configured busy grant is exactly the busy permission, never broadcast.
  CHECK_OK(w.at(1)->set_peer_busy_capable(2, true));
  CHECK(w.at(1)->peer_busy_capable(2, w.now));
  CHECK(!w.at(1)->peer_broadcast_eligible(2, w.now));
  // Expiry returns every peer to unicast.
  w.run(6000);
  CHECK(!w.at(1)->peer_broadcast_eligible(2, w.now));
  CHECK(!w.at(2)->peer_broadcast_eligible(1, w.now));
  // A fresh probe re-arms; remove + re-add revokes immediately.
  probe_broadcast_grants(w, {1, 2}, lcg);
  w.run(100);
  CHECK(w.at(1)->peer_broadcast_eligible(2, w.now));
  w.unlink(1, 2);
  w.link(1, 2, 1, 1);
  CHECK(!w.at(1)->peer_broadcast_eligible(2, w.now));
  CHECK(!w.at(2)->peer_broadcast_eligible(1, w.now));
}

void test_broadcast_batches_downward_refresh() {
  // G(1) - A(5) - P(2) - C(3), C(4): P reaches the gateway via A, so its two
  // children share one broadcast refresh while live grants hold; G's single
  // child keeps unicast.
  SimWorld w;
  broadcast_profile(w, 1);
  for (NodeId id = 1; id <= 6; ++id) w.add(id);
  w.start_all();
  w.link(1, 5, 1, 1);
  w.link(5, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.link(2, 4, 1, 1);
  w.link(2, 6, 1, 1);  // spare leaf, removed later to force a trigger
  std::uint64_t lcg = 0xB0A7;
  const std::set<NodeId> probers{1, 2, 3, 4, 5, 6};
  probe_broadcast_grants(w, probers, lcg);
  w.run(3000);
  for (const NodeId board : {2, 3, 4, 5, 6}) {
    CHECK(follow_chain(w, board, 1) == 1);
    CHECK(follow_chain(w, 1, board) == 1);
  }
  CHECK(w.at(2)->scoped_child(3));
  CHECK(w.at(2)->scoped_child(4));
  // Removing the spare leaf triggers P's downward batch to both children.
  w.at(2)->remove_neighbor(6, w.now);
  w.at(6)->remove_neighbor(2, w.now);
  w.net.disconnect(2, 6);
  w.run(2000);
  CHECK(w.at(2)->route_scale_stats().broadcast_frames > 0);
  CHECK(saw_broadcast_update(w, 2));
  CHECK(w.at(1)->route_scale_stats().broadcast_frames == 0);  // one child: unicast
  CHECK(follow_chain(w, 3, 1) == 1);
  CHECK(follow_chain(w, 4, 1) == 1);
  // Expired grants fall back to unicast: no new broadcast, still converged.
  w.run(6000);
  CHECK(!w.at(2)->peer_broadcast_eligible(3, w.now));
  CHECK(!w.at(2)->peer_broadcast_eligible(4, w.now));
  const std::uint64_t broadcast_before =
      w.at(2)->route_scale_stats().broadcast_frames;
  const std::uint64_t downward_before =
      w.at(2)->route_scale_stats().downward_frames;
  w.unlink(2, 4);
  w.link(2, 4, 1, 1);
  w.run(3000);
  CHECK(w.at(2)->route_scale_stats().broadcast_frames == broadcast_before);
  CHECK(w.at(2)->route_scale_stats().downward_frames > downward_before);
  CHECK(follow_chain(w, 3, 1) == 1);
  CHECK(follow_chain(w, 4, 1) == 1);
}

void test_broadcast_direct_gateway_falls_back() {
  // G(1) - P(2) - C(3), C(4): P's gateway route is direct, so no broadcast
  // can carry it (no third-node via) — the batch stays unicast and the
  // tree still converges.
  SimWorld w;
  broadcast_profile(w, 1);
  for (NodeId id = 1; id <= 4; ++id) w.add(id);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.link(2, 4, 1, 1);
  std::uint64_t lcg = 0xD1EC7;
  probe_broadcast_grants(w, {1, 2, 3, 4}, lcg);
  w.run(3000);
  CHECK(w.at(2)->peer_broadcast_eligible(3, w.now));
  CHECK(w.at(2)->peer_broadcast_eligible(4, w.now));
  CHECK(w.at(2)->route_scale_stats().broadcast_frames == 0);
  CHECK(w.at(2)->route_scale_stats().downward_frames > 0);
  CHECK(!saw_broadcast_update(w, 2));
  for (const NodeId board : {2, 3, 4}) {
    CHECK(follow_chain(w, board, 1) == 1);
    CHECK(follow_chain(w, 1, board) == 1);
  }
}

std::size_t count_diag(const routeloom_test::CapturingObserver* obs, const char* reason) {
  std::size_t count = 0;
  for (const auto& d : obs->diagnostics) {
    if (d == reason) ++count;
  }
  return count;
}

void test_broadcast_rx_gates() {
  // S(4) advertises the gateway G(1) at metric 5 via P(2). P (the via) must
  // see infinity and take S as a child; X(3) must learn G via S.
  SimWorld w;
  broadcast_profile(w, 1);
  w.add(1);
  w.add(2);
  w.add(3);
  w.add(4);
  w.add(5);  // unknown sender: never linked
  w.start_all();
  w.link(2, 4, 1, 1);
  w.link(3, 4, 1, 1);
  auto seal_from = [&](const NodeId from, const RouteMetric metric,
                       wire::EncodedFrame& encoded) {
    BroadcastRouteRecord records[2]{};
    records[0].route = RouteAdvertisement{from, 1, 7, 0};
    records[0].via = kInvalidNodeId;
    records[1].route = RouteAdvertisement{1, 1, 3, metric};
    records[1].via = 2;
    return seal_broadcast_frame(*w.security[from], w.network_id, from, records, 2,
                               encoded);
  };
  auto rx_meta = [&](const NodeId node, const NodeId peer) {
    return routeloom_test::sim_rx_metadata(w.reply_ports[node].get(), peer);
  };
  wire::EncodedFrame p_frame{};
  CHECK(seal_from(4, 5, p_frame));
  const std::uint32_t rx_before = w.at(2)->rx_generation();
  const std::uint32_t work_before = w.at(2)->work_generation();
  CHECK_OK(w.at(2)->on_radio_receive(
      4, p_frame.view(), rx_meta(2, 4), w.now));
  CHECK(w.at(2)->rx_generation() == rx_before);  // no resume confirmation
  CHECK(w.at(2)->work_generation() == work_before + 1);  // sleep tickets die
  CHECK(!w.at(2)->peer_broadcast_eligible(4, w.now));  // no grant fabricated
  CHECK(w.at(2)->scoped_child(4));  // poisoned gateway record = child
  CHECK(!w.at(2)->routes().best(1).valid);  // via self projects infinity
  CHECK(w.at(2)->routes().best(4).valid);  // the self record still lands
  wire::EncodedFrame x_frame{};
  CHECK(seal_from(4, 5, x_frame));
  CHECK_OK(
      w.at(3)->on_radio_receive(4, x_frame.view(), rx_meta(3, 4), w.now));
  const auto via_s = w.at(3)->routes().best(1);
  CHECK(via_s.valid && via_s.next_hop == 4 && via_s.metric == 6);
  // Unknown sender: connected radio, no neighbor — rejected, route untouched.
  w.net.connect(3, 5);
  wire::EncodedFrame unknown{};
  CHECK(seal_from(5, 5, unknown));
  CHECK_OK(
      w.at(3)->on_radio_receive(5, unknown.view(), rx_meta(3, 5), w.now));
  CHECK(!w.at(3)->routes().best(5).valid);
  CHECK(w.obs(3)->has_diag("BROADCAST_ROUTE_SENDER_REJECTED"));
  // Attributed transmitter differs from the claimed origin: rejected.
  wire::EncodedFrame misattributed{};
  CHECK(seal_from(4, 5, misattributed));
  CHECK_OK(w.at(3)->on_radio_receive(
      2, misattributed.view(), rx_meta(3, 2), w.now));
  CHECK(w.at(3)->routes().best(1).metric == 6);  // unchanged
  // Stale binding evidence: rejected before the group open.
  wire::EncodedFrame stale{};
  CHECK(seal_from(4, 5, stale));
  auto stale_meta = rx_meta(3, 4);
  stale_meta.identity_current = false;
  CHECK_OK(w.at(3)->on_radio_receive(4, stale.view(), stale_meta, w.now));
  CHECK(w.at(3)->routes().best(1).metric == 6);  // unchanged
  // Legacy receiver: the ordinary path refuses the broadcast shape.
  const auto configure = w.configure;
  w.configure = [configure](NodeConfig& config) {
    configure(config);
    config.route_broadcast = false;
  };
  w.add(6);
  CHECK_OK(w.at(6)->start(w.now));
  w.link(4, 6, 1, 1);
  wire::EncodedFrame legacy{};
  CHECK(seal_from(4, 5, legacy));
  CHECK_OK(
      w.at(6)->on_radio_receive(4, legacy.view(), rx_meta(6, 4), w.now));
  CHECK(w.at(6)->routes().best(4).generation == 0);  // self record not applied
  CHECK(!w.at(6)->routes().best(1).valid);
  // Unknown GK: a rate-limited hint, never a route. The clock leaves 0
  // first: the 0-sentinel pacing (same convention as pull answers) only
  // engages once time has advanced.
  w.now = 1000;
  w.security[3]->set_accept_group_epoch(false);
  wire::EncodedFrame unknown_gk{};
  CHECK(seal_from(4, 2, unknown_gk));  // better metric — must not apply
  CHECK_OK(
      w.at(3)->on_radio_receive(4, unknown_gk.view(), rx_meta(3, 4), w.now));
  CHECK(w.at(3)->routes().best(1).metric == 6);  // unchanged
  CHECK(count_diag(w.obs(3), "BROADCAST_UNKNOWN_GK") == 1);
  wire::EncodedFrame unknown_gk2{};
  CHECK(seal_from(4, 2, unknown_gk2));
  CHECK_OK(
      w.at(3)->on_radio_receive(4, unknown_gk2.view(), rx_meta(3, 4), w.now));
  CHECK(count_diag(w.obs(3), "BROADCAST_UNKNOWN_GK") == 1);  // coalesced
  w.now += 61000;
  wire::EncodedFrame unknown_gk3{};
  CHECK(seal_from(4, 2, unknown_gk3));
  CHECK_OK(
      w.at(3)->on_radio_receive(4, unknown_gk3.view(), rx_meta(3, 4), w.now));
  CHECK(count_diag(w.obs(3), "BROADCAST_UNKNOWN_GK") == 2);
  // Bad tag: refused, and the failure pollutes no replay window.
  w.security[3]->set_accept_group_epoch(true);
  const std::uint64_t replays_before = w.security.at(3)->group_replays();
  wire::EncodedFrame tampered{};
  CHECK(seal_from(4, 2, tampered));
  tampered.bytes[tampered.size - 1] ^= 0xFF;
  CHECK_OK(
      w.at(3)->on_radio_receive(4, tampered.view(), rx_meta(3, 4), w.now));
  CHECK(w.at(3)->routes().best(1).metric == 6);  // unchanged
  CHECK(w.security.at(3)->group_replays() == replays_before);
  // Exact replay of accepted bytes: refused, applied exactly once.
  wire::EncodedFrame replay{};
  CHECK(seal_from(4, 2, replay));
  CHECK_OK(
      w.at(3)->on_radio_receive(4, replay.view(), rx_meta(3, 4), w.now));
  CHECK(w.at(3)->routes().best(1).metric == 3);  // 2 + link cost 1
  CHECK_OK(
      w.at(3)->on_radio_receive(4, replay.view(), rx_meta(3, 4), w.now));
  CHECK(w.at(3)->routes().best(1).metric == 3);  // unchanged
  CHECK(w.security.at(3)->group_replays() == replays_before + 1);
}

// A pairwise Link the provider reports unusable vetoes broadcast RX even
// with the sender admitted and the group tag valid.
class BroadcastLinkGateSecurity final : public SecurityProvider {
 public:
  explicit BroadcastLinkGateSecurity(routeloom_test::TestSecurity& inner) : inner_(inner) {}
  bool ready() const noexcept override { return true; }
  ContextState context_state(const SecurityScope scope,
                             const NodeId peer) const noexcept override {
    if (scope == SecurityScope::Link && peer == gated_peer_ && !link_up_) {
      return ContextState::None;
    }
    return inner_.context_state(scope, peer);
  }
  Status tx_group_link_epochs(std::uint32_t& boot, std::uint32_t& g) noexcept override {
    return inner_.tx_group_link_epochs(boot, g);
  }
  bool accepts_group_epoch(const std::uint32_t g) const noexcept override {
    return inner_.accepts_group_epoch(g);
  }
  Status next_counter(const SecurityContext& context,
                      std::uint64_t& counter) noexcept override {
    return inner_.next_counter(context, counter);
  }
  Status seal(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView plaintext,
              const MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    return inner_.seal(context, counter, aad, plaintext, ciphertext, tag);
  }
  Status open(const SecurityContext& context, const std::uint64_t counter,
              const ByteView aad, const ByteView ciphertext,
              const std::array<std::uint8_t, kAeadTagSize>& tag,
              const MutableByteView plaintext) noexcept override {
    return inner_.open(context, counter, aad, ciphertext, tag, plaintext);
  }
  void set_link_up(const bool up) noexcept { link_up_ = up; }

 private:
  routeloom_test::TestSecurity& inner_;
  NodeId gated_peer_{4};
  bool link_up_{false};
};

void test_broadcast_rx_requires_pairwise_link() {
  SimWorld w;
  broadcast_profile(w, 1);
  // Receiver 2 runs behind the gating provider; locals outlive the node.
  routeloom_test::TestSecurity inner;
  BroadcastLinkGateSecurity gated(inner);
  routeloom_test::CapturingObserver observer;
  routeloom_test::SimRadio radio(w.net, 2);
  NodeConfig config{};
  config.network = w.network_id;
  config.node = 2;
  config.message_session = 102;
  config.boot_incarnation = 0xB002;
  config.route_generation = 1;
  config.link_epoch = 1;
  config.end_epoch = 1;
  config.route_gateways = {1, kInvalidNodeId};
  config.route_advertisement_period_ms = kFastPeriodMs;
  config.route_lifetime_ms = kFastLifetimeMs;
  config.route_broadcast = true;
  routeloom_test::TestSecurity sender_security;
  routeloom_test::SimReplyPort reply_port(radio, 2, 1);
  MeshNode node(config, radio, gated, observer);
  node.set_reply_peer_port(&reply_port);
  CHECK_OK(node.start(0));
  CHECK_OK(node.add_neighbor(4, 1, 0));
  BroadcastRouteRecord records[1]{};
  records[0].route = RouteAdvertisement{4, 1, 7, 0};
  records[0].via = kInvalidNodeId;
  wire::EncodedFrame blocked{};
  CHECK(seal_broadcast_frame(sender_security, w.network_id, 4, records, 1, blocked));
  RadioRxMetadataV2 meta{};
  meta.identity_current = true;
  CHECK_OK(node.on_radio_receive(4, blocked.view(), meta, 0));
  CHECK(!node.routes().best(4).valid || node.routes().best(4).generation == 0);
  CHECK(count_diag(&observer, "BROADCAST_ROUTE_SENDER_REJECTED") == 1);
  gated.set_link_up(true);
  wire::EncodedFrame admitted{};
  CHECK(seal_broadcast_frame(sender_security, w.network_id, 4, records, 1, admitted));
  CHECK_OK(node.on_radio_receive(4, admitted.view(), meta, 0));
  CHECK(node.routes().best(4).valid);
  CHECK(node.routes().best(4).generation == 1);
  CHECK(count_diag(&observer, "BROADCAST_ROUTE_SENDER_REJECTED") == 1);
}

// Probes every 5 s (a grant never outlives its renewal) while running.
void run_with_probes(SimWorld& w, const std::set<NodeId>& probers,
                     std::uint64_t& lcg, MonotonicMs duration_ms,
                     MonotonicMs next_probe_ms) {
  const MonotonicMs end = w.now + duration_ms;
  while (w.now < end) {
    if (w.now >= next_probe_ms) {
      probe_broadcast_grants(w, probers, lcg);
      next_probe_ms += 5000;
    }
    w.run(0, 5);
  }
}

void test_broadcast_topologies() {
  std::uint64_t lcg = 0x70;
  // Self/parent/child: 1(G) - 2 - 3 with 2's uplink through 1 and 3 behind 2.
  {
    SimWorld w;
    broadcast_profile(w, 1);
    for (NodeId id = 1; id <= 3; ++id) w.add(id);
    w.start_all();
    w.link(1, 2, 1, 1);
    w.link(2, 3, 1, 1);
    const std::set<NodeId> probers{1, 2, 3};
    probe_broadcast_grants(w, probers, lcg);
    run_with_probes(w, probers, lcg, 4000, 5000);
    CHECK(follow_chain(w, 3, 1) == 1);
    CHECK(follow_chain(w, 1, 3) == 1);
    CHECK(w.at(1)->scoped_child(2));
    CHECK(w.at(2)->scoped_child(3));
    CHECK(!w.at(2)->scoped_child(1));
    // One child per node: nothing to batch, everything unicast.
    CHECK(sum_stats(w).broadcast_frames == 0);
  }
  // Diamond: two disjoint paths stay loop-free with broadcast on.
  {
    SimWorld w;
    broadcast_profile(w, 1);
    for (NodeId id = 1; id <= 4; ++id) w.add(id);
    w.start_all();
    w.link(1, 2, 1, 1);
    w.link(1, 3, 1, 1);
    w.link(2, 4, 1, 1);
    w.link(3, 4, 1, 1);
    const std::set<NodeId> probers{1, 2, 3, 4};
    probe_broadcast_grants(w, probers, lcg);
    run_with_probes(w, probers, lcg, 4000, 5000);
    for (const NodeId board : {2, 3, 4}) {
      CHECK(follow_chain(w, board, 1) == 1);
      CHECK(follow_chain(w, 1, board) == 1);
    }
    MessageId up{};
    MessageId down{};
    CHECK(send_data(w, 4, 1, up));
    CHECK(send_data(w, 1, 4, down));
    run_with_probes(w, probers, lcg, 2000, 10000);
    CHECK(w.at(4)->delivery(up).state == DeliveryState::Delivered);
    CHECK(w.at(1)->delivery(down).state == DeliveryState::Delivered);
    CHECK(data_sights_loop_free(w.net.sights));
  }
  // Ten hops: a line of ten converges end to end.
  {
    SimWorld w;
    broadcast_profile(w, 1);
    for (NodeId id = 1; id <= 10; ++id) w.add(id);
    w.start_all();
    for (NodeId id = 1; id <= 9; ++id) w.link(id, id + 1, 1, 1);
    std::set<NodeId> probers;
    for (NodeId id = 1; id <= 10; ++id) probers.insert(id);
    probe_broadcast_grants(w, probers, lcg);
    run_with_probes(w, probers, lcg, 8000, 5000);
    std::size_t hops = 0;
    CHECK(follow_chain(w, 10, 1, &hops) == 1);
    CHECK(hops == 9);
    CHECK(follow_chain(w, 1, 10) == 1);
    for (NodeId id = 2; id <= 10; ++id) {
      CHECK(follow_chain(w, id, 1) == 1);
      CHECK(follow_chain(w, 1, id) == 1);
    }
  }
  // Partition: the far half loses the gateway, then rejoins.
  {
    SimWorld w;
    broadcast_profile(w, 1);
    for (NodeId id = 1; id <= 4; ++id) w.add(id);
    w.start_all();
    w.link(1, 2, 1, 1);
    w.link(2, 3, 1, 1);
    w.link(3, 4, 1, 1);
    const std::set<NodeId> probers{1, 2, 3, 4};
    probe_broadcast_grants(w, probers, lcg);
    run_with_probes(w, probers, lcg, 4000, 5000);
    CHECK(follow_chain(w, 4, 1) == 1);
    w.unlink(2, 3);
    run_with_probes(w, probers, lcg, 10000, 10000);
    CHECK(!w.at(3)->routes().best(1).valid);
    CHECK(!w.at(4)->routes().best(1).valid);
    // Rejoin: the re-adds revoked the 2-3 grants, so let the renewal bound
    // pass, re-probe, and converge again with broadcast back on.
    w.link(2, 3, 1, 1);
    w.run(1000);
    probe_broadcast_grants(w, probers, lcg);
    w.run(4000);  // inside the fresh grant window (strict expiry bound)
    CHECK(w.at(2)->peer_broadcast_eligible(3, w.now));
    CHECK(follow_chain(w, 4, 1) == 1);
    CHECK(follow_chain(w, 1, 4) == 1);
  }
}

// ----------------------------------------------------------------------------
// Scale: 100 nodes x legacy/mixed/opt-in with the same seed
// ----------------------------------------------------------------------------

struct BcastModeResult {
  const char* name{""};
  MonotonicMs converged_at{0};
  std::size_t upward_lapses{0};
  std::size_t downward_lapses{0};
  std::size_t chain_failures{0};
  std::size_t loops{0};
  std::uint64_t route_frames{0};
  std::uint64_t route_bytes{0};
  std::uint64_t diag_frames{0};
  std::uint64_t diag_bytes{0};
  std::uint64_t broadcast_frames{0};
  std::uint64_t downward_frames{0};
  double window_s{0};
};

// mode 0 = legacy (all unicast), 1 = mixed (the x < 5 half opts in, the
// gateway side), 2 = all opt-in. Same topology, timers and probe seed;
// only the opt-in set differs. The mixed boundary is contiguous (a rollout
// pocket), not checkerboard: batching needs two opting-in children.
BcastModeResult run_bcast_mode(const int mode) {
  constexpr int kSide = 10;
  constexpr std::uint32_t kPeriodMs = kScopedProductPeriodMs;
  constexpr std::uint32_t kLifetimeMs = kScopedProductLifetimeMs;
  constexpr MonotonicMs kStepMs = 50;
  auto id = [](int x, int y) { return static_cast<NodeId>(1 + x * kSide + y); };
  const NodeId gateway = id(0, 4);

  SimWorld w;
  w.net.record_sights = false;
  scoped_profile(w, gateway, kPeriodMs, kLifetimeMs);
  const auto configure = w.configure;
  w.configure = [configure, mode](NodeConfig& config) {
    configure(config);
    const int x = static_cast<int>((config.node - 1) / kSide);
    if (mode == 2 || (mode == 1 && x < kSide / 2)) {
      config.route_broadcast = true;
    }
  };
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
  std::set<NodeId> probers;
  if (mode != 0) {
    for (const auto& [node, ptr] : w.nodes) {
      const int x = static_cast<int>((node - 1) / kSide);
      if (mode == 2 || x < kSide / 2) probers.insert(node);
    }
  }
  std::uint64_t lcg = 0xBCA57;  // same probe seed every mode
  BcastModeResult result{};
  result.name = mode == 0 ? "legacy" : mode == 1 ? "mixed" : "opt-in";

  std::vector<NodeId> boards;
  for (const auto& [node, ptr] : w.nodes) {
    if (node != gateway) boards.push_back(node);
  }
  auto converged = [&]() {
    for (const NodeId board : boards) {
      if (follow_chain(w, board, gateway) != 1) return false;
      if (follow_chain(w, gateway, board) != 1) return false;
    }
    return true;
  };
  // Probes ride 2.5 s off the 5 s tick grid so every grant covers its tick.
  MonotonicMs next_probe_ms = 2500;
  auto step = [&]() {
    if (!probers.empty() && w.now >= next_probe_ms) {
      probe_broadcast_grants(w, probers, lcg);
      next_probe_ms += 5000;
    }
    w.run(0, kStepMs);
  };
  std::size_t tick = 0;
  while (w.now <= 120000) {
    step();
    if (++tick % 20 == 0 && converged()) {
      result.converged_at = w.now;
      break;
    }
  }

  const auto tally_before = w.net.route_control_tx;
  const auto diag_before = w.net.tx_by_type;
  const RouteScaleStats stats_before = sum_stats(w);
  const MonotonicMs window_start = w.now;
  constexpr MonotonicMs kWindowMs = 60000;
  const MonotonicMs window_end = window_start + kWindowMs;
  tick = 0;
  while (w.now < window_end) {
    step();
    for (const NodeId board : boards) {
      if (!w.at(board)->routes().best(gateway).valid) ++result.upward_lapses;
      if (!w.at(gateway)->routes().best(board).valid) ++result.downward_lapses;
    }
    if (++tick % 20 == 0) {
      for (const NodeId board : boards) {
        const int up = follow_chain(w, board, gateway);
        const int dn = follow_chain(w, gateway, board);
        if (up < 0 || dn < 0) ++result.loops;
        if (up != 1 || dn != 1) ++result.chain_failures;
      }
    }
  }
  result.window_s = static_cast<double>(w.now - window_start) / 1000.0;
  for (const auto& [node, ptr] : w.nodes) {
    (void)ptr;
    routeloom_test::SimNetwork::TxTally delta = w.net.route_control_tx[node];
    const auto it = tally_before.find(node);
    if (it != tally_before.end()) {
      delta.frames -= it->second.frames;
      delta.bytes -= it->second.bytes;
    }
    result.route_frames += delta.frames;
    result.route_bytes += delta.bytes;
  }
  {
    routeloom_test::SimNetwork::TxTally delta =
        w.net.tx_by_type[FrameType::Diagnostic];
    const auto it = diag_before.find(FrameType::Diagnostic);
    if (it != diag_before.end()) {
      delta.frames -= it->second.frames;
      delta.bytes -= it->second.bytes;
    }
    result.diag_frames = delta.frames;
    result.diag_bytes = delta.bytes;
  }
  const RouteScaleStats stats_after = sum_stats(w);
  result.broadcast_frames =
      stats_after.broadcast_frames - stats_before.broadcast_frames;
  result.downward_frames =
      stats_after.downward_frames - stats_before.downward_frames;
  return result;
}

void test_broadcast_hundred_node_modes() {
  const BcastModeResult legacy = run_bcast_mode(0);
  const BcastModeResult mixed = run_bcast_mode(1);
  const BcastModeResult optin = run_bcast_mode(2);
  for (const auto* r : {&legacy, &mixed, &optin}) {
    CHECK(r->converged_at != 0);
    CHECK(r->upward_lapses == 0);
    CHECK(r->downward_lapses == 0);
    CHECK(r->chain_failures == 0);
    CHECK(r->loops == 0);
  }
  CHECK(legacy.broadcast_frames == 0);
  CHECK(mixed.broadcast_frames > 0);
  CHECK(optin.broadcast_frames > 0);
  // Batching replaces downward unicasts one-for-many: fewer route frames.
  CHECK(optin.route_frames < legacy.route_frames);
  for (const auto* r : {&legacy, &mixed, &optin}) {
    const routeloom_test::SimNetwork::TxTally route{r->route_frames,
                                                   r->route_bytes};
    const routeloom_test::SimNetwork::TxTally diag{r->diag_frames,
                                                  r->diag_bytes};
    const double route_us = static_cast<double>(airtime_us(route)) / r->window_s;
    const double diag_us = static_cast<double>(airtime_us(diag)) / r->window_s;
    std::fprintf(stderr,
                 "  bcast-100: %-7s converged=%6llu ms lapses=%zu/%zu chain=%zu loops=%zu "
                 "route=%llu frames (%7.0f us/s) cap=%llu frames (%7.0f us/s) "
                 "total=%7.0f us/s down_uni=%llu bcast=%llu\n",
                 r->name, static_cast<unsigned long long>(r->converged_at),
                 r->upward_lapses, r->downward_lapses, r->chain_failures,
                 r->loops, static_cast<unsigned long long>(r->route_frames),
                 route_us, static_cast<unsigned long long>(r->diag_frames),
                 diag_us, route_us + diag_us,
                 static_cast<unsigned long long>(r->downward_frames),
                 static_cast<unsigned long long>(r->broadcast_frames));
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
    test_broadcast_grant_lifecycle();
    test_broadcast_batches_downward_refresh();
    test_broadcast_direct_gateway_falls_back();
    test_broadcast_rx_gates();
    test_broadcast_rx_requires_pairwise_link();
    test_broadcast_topologies();
  }
  if (mode.empty() || mode == "scale") {
    test_hundred_node_site();
    test_broadcast_hundred_node_modes();
  }
  if (failures != 0) {
    std::fprintf(stderr, "%d routing-scale checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom routing-scale tests passed");
  return 0;
}
