// observation_v1 unit tests: the MeshNode route-detail accessors, the
// read-only fill helpers and digests, and the HostOps 0x70-0x72 codecs.
// Bridge integration lives in test_usb.cpp; coordinator milestone latches
// in test_sdkv1_security_coordinator.cpp.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "routeloom/discovery.hpp"
#include "routeloom/node.hpp"
#include "routeloom/observation.hpp"
#include "routeloom/usb_host_ops.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)

using namespace routeloom;
using namespace routeloom::usb;
using routeloom_test::SimWorld;

// --- fixture ----------------------------------------------------------------

void make_line(SimWorld& world) {
  // 1 -- 2 -- 3: node 1 hears 2 directly and reaches 3 through 2.
  world.add(1);
  world.add(2);
  world.add(3);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.link(2, 3, 1, 1);
  world.run(1500);
}

// --- route detail ------------------------------------------------------------

void test_route_detail_line_topology() {
  SimWorld world;
  make_line(world);
  const MeshNode& n1 = *world.at(1);

  RouteDetailEntry d2{};
  CHECK(n1.route_detail(2, world.now, d2));
  CHECK(d2.destination == 2);
  CHECK(d2.valid);
  CHECK(d2.next_hop == 2);
  const RouteSelection best2 = n1.routes().best(2);
  CHECK(best2.valid);
  CHECK(d2.generation == best2.generation);
  CHECK(d2.sequence == best2.sequence);
  CHECK(d2.metric == best2.metric);
  MonotonicMs remaining = 0;
  CHECK(n1.routes().selection_remaining(2, world.now, remaining));
  CHECK(d2.remaining_ms == remaining);
  CHECK(d2.remaining_ms > 0);
  CHECK(d2.remaining_ms <= 1000);

  RouteDetailEntry d3{};
  CHECK(n1.route_detail(3, world.now, d3));
  CHECK(d3.valid);
  CHECK(d3.next_hop == 2);
  CHECK(d3.metric == 2);

  RouteDetailEntry none{};
  CHECK(!n1.route_detail(1, world.now, none));    // self is not listable
  CHECK(!n1.route_detail(99, world.now, none));   // unknown destination
  CHECK(!n1.route_detail(kBroadcastNodeId, world.now, none));
}

void test_route_detail_page_walk() {
  SimWorld world;
  make_line(world);
  const MeshNode& n1 = *world.at(1);

  // One-entry pages walk the whole table in ascending order.
  std::vector<NodeId> seen;
  NodeId cursor = 0;
  bool more = true;
  while (more) {
    RouteDetailEntry page[1];
    const std::size_t n = n1.route_detail_page(cursor, page, 1, world.now, more);
    CHECK(n <= 1);
    if (n == 0) break;
    CHECK(seen.empty() || page[0].destination > seen.back());
    seen.push_back(page[0].destination);
    cursor = page[0].destination;
  }
  CHECK(seen.size() == 2);
  CHECK(seen[0] == 2 && seen[1] == 3);

  // A full page answers at once with no remainder.
  RouteDetailEntry full[8];
  more = true;
  const std::size_t n = n1.route_detail_page(0, full, 8, world.now, more);
  CHECK(n == 2 && !more);
  CHECK(full[0].destination == 2 && full[1].destination == 3);

  // Past the end: empty, no remainder.
  RouteDetailEntry empty[8];
  more = true;
  CHECK(n1.route_detail_page(3, empty, 8, world.now, more) == 0);
  CHECK(!more);
}

void test_observation_counts() {
  SimWorld world;
  make_line(world);
  const MeshNode& n1 = *world.at(1);
  std::uint16_t active = 0, total = 0, reachable = 0, remembered = 0;
  observation_counts(n1, world.now, active, total, reachable, remembered);
  CHECK(active == 1);
  CHECK(total == 1);
  CHECK(reachable == 2);
  CHECK(remembered == 2);
}

// --- neighbor detail ------------------------------------------------------------

void test_neighbor_detail_line_topology() {
  SimWorld world;
  make_line(world);
  const MeshNode& n1 = *world.at(1);

  // Node 1's neighbor table holds 2 only (3 is multi-hop, no neighbor
  // record) — with the discovery sidecar absent, phase/lease read unknown.
  NeighborDetailEntry page[8];
  bool more = true;
  const std::size_t n = neighbor_detail_page(n1, nullptr, 0, page, 8, world.now, more);
  CHECK(n == 1 && !more);
  CHECK(page[0].peer == 2);
  CHECK((page[0].flags & kNeighborActive) != 0);
  CHECK(page[0].link_cost == 1);
  CHECK(page[0].phase == kNeighborPhaseUnknown);
  CHECK(page[0].lease_remaining_ms == kNeighborAgeUnknown);
  // RSSI/heard mirror the node_status row (the sim delivers valid -60 dBm
  // evidence): the entry projects, never invents.
  NodeStatus row{};
  CHECK(n1.node_status_page(1, &row, 1, world.now, more) == 1);
  CHECK(row.node == 2);
  CHECK(((page[0].flags & kNeighborRssiValid) != 0) ==
        ((row.flags & kNodeStatusRssiValid) != 0));
  CHECK(((page[0].flags & kNeighborHeardValid) != 0) ==
        ((row.flags & kNodeStatusHeardValid) != 0));
  if ((row.flags & kNodeStatusRssiValid) != 0) {
    CHECK(page[0].rssi_last_dbm == row.rssi_last_dbm);
    CHECK(page[0].rssi_ewma_q8_8 == row.rssi_ewma_q8_8);
  } else {
    CHECK(page[0].rssi_last_dbm == 0);
    CHECK(page[0].rssi_ewma_q8_8 == 0);
  }
  if ((row.flags & kNodeStatusHeardValid) != 0) {
    CHECK(page[0].heard_age_ms == row.heard_age_ms);
  } else {
    CHECK(page[0].heard_age_ms == kNeighborAgeUnknown);
  }

  // Exact lookup: the direct neighbor resolves, the multi-hop peer and
  // self do not (they hold no neighbor record).
  NeighborDetailEntry exact{};
  CHECK(neighbor_detail_exact(n1, nullptr, 2, world.now, exact));
  CHECK(exact.peer == 2);
  CHECK(!neighbor_detail_exact(n1, nullptr, 3, world.now, exact));
  CHECK(!neighbor_detail_exact(n1, nullptr, 1, world.now, exact));
  CHECK(!neighbor_detail_exact(n1, nullptr, kBroadcastNodeId, world.now, exact));
}

void test_neighbor_detail_page_walk() {
  SimWorld world;
  world.add(1);
  for (NodeId id = 2; id <= 11; ++id) {
    world.add(id);
  }
  world.start_all();
  for (NodeId id = 2; id <= 11; ++id) {
    world.link(1, id, 1, 1);
  }
  world.run(1500);
  const MeshNode& n1 = *world.at(1);

  // Two-entry pages walk all ten neighbors ascending with `more` set
  // until the last page.
  std::vector<NodeId> seen;
  NodeId cursor = 0;
  bool more = true;
  while (more) {
    NeighborDetailEntry page[2];
    const std::size_t n = neighbor_detail_page(n1, nullptr, cursor, page, 2, world.now, more);
    CHECK(n <= 2);
    if (n == 0) break;
    for (std::size_t i = 0; i < n; ++i) {
      CHECK(seen.empty() || page[i].peer > seen.back());
      seen.push_back(page[i].peer);
    }
    cursor = page[n - 1].peer;
  }
  CHECK(seen.size() == 10);
  for (std::size_t i = 0; i < seen.size(); ++i) {
    CHECK(seen[i] == 2 + i);
  }
  NeighborDetailEntry empty[2];
  more = true;
  CHECK(neighbor_detail_page(n1, nullptr, 11, empty, 2, world.now, more) == 0);
  CHECK(!more);
}

void test_neighbor_phase_registry_pins_discovery_order() {
  // The observation phase registry is the discovery NeighborPhase shifted
  // by one (0 stays unknown): pin the wire assumption so an enum reorder
  // fails loudly instead of mislabeling rows.
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Candidate) == 0);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Authenticating) == 1);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Authenticated) == 2);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::ApprovalPending) == 3);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Bound) == 4);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Reachable) == 5);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Suspended) == 6);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Stale) == 7);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Conflict) == 8);
  CHECK(static_cast<std::uint8_t>(NeighborPhase::Revoked) == 9);
  CHECK(kNeighborPhaseReachable == 6);
}

// --- read-only proof ------------------------------------------------------------

struct SelectionSnapshot {
  NodeId dest{kInvalidNodeId};
  NodeId next_hop{kInvalidNodeId};
  RouteGeneration generation{0};
  RouteSequence sequence{0};
  RouteMetric metric{kInfiniteRouteMetric};
  bool valid{false};
};

std::vector<SelectionSnapshot> snapshot_selections(const MeshNode& node) {
  std::vector<SelectionSnapshot> out;
  node.routes().for_each_destination([&](const NodeId dest) {
    const RouteSelection best = node.routes().best(dest);
    out.push_back(SelectionSnapshot{dest, best.next_hop, best.generation,
                                    best.sequence, best.metric, best.valid});
  });
  return out;
}

void test_observation_reads_change_nothing() {
  SimWorld world;
  make_line(world);
  const MeshNode& n1 = *world.at(1);
  // The test node is non-const; the cast only reaches the mutating
  // advertisement-baseline drain below (production reads stay const).
  RouteTable& routes = const_cast<RouteTable&>(n1.routes());

  // Drain the advertisement baseline: from here on, any newly reported
  // selection change proves a read mutated routing state.
  std::size_t drained = 0;
  routes.for_each_selected_change(
      [&](const RouteSelection&, const RouteSelection&) { ++drained; }, world.now);

  const std::vector<SelectionSnapshot> before = snapshot_selections(n1);
  CHECK(!before.empty());
  const std::uint32_t route_digest_before = observation_route_digest(n1, world.now);
  const std::uint32_t neighbor_digest_before = observation_neighbor_digest(n1, world.now);

  // Every observation read the USB surface serves.
  for (int i = 0; i < 3; ++i) {
    NodeId cursor = 0;
    bool more = true;
    while (more) {
      RouteDetailEntry page[8];
      const std::size_t n = n1.route_detail_page(cursor, page, 8, world.now, more);
      if (n == 0) break;
      cursor = page[n - 1].destination;
    }
    RouteDetailEntry exact{};
    CHECK(n1.route_detail(3, world.now, exact));
    NodeId ncursor = 0;
    bool nmore = true;
    while (nmore) {
      NeighborDetailEntry npage[8];
      const std::size_t nn = neighbor_detail_page(n1, nullptr, ncursor, npage, 8, world.now, nmore);
      if (nn == 0) break;
      ncursor = npage[nn - 1].peer;
    }
    NeighborDetailEntry nexact{};
    CHECK(neighbor_detail_exact(n1, nullptr, 2, world.now, nexact));
    std::uint16_t a = 0, t = 0, r = 0, m = 0;
    observation_counts(n1, world.now, a, t, r, m);
    ObservationTables tables{};
    fill_observation_tables(n1, world.now, 0, 32, 0, 128, tables);
    ObservationSummary summary{};
    fill_observation_summary(n1, world.now, 0, summary);
    CHECK(n1.dedup_terminal_pins() <= n1.dedup_resident());
  }
  CHECK(observation_route_digest(n1, world.now) == route_digest_before);
  CHECK(observation_neighbor_digest(n1, world.now) == neighbor_digest_before);

  // No selection moved and the advertisement baseline stayed quiet.
  const std::vector<SelectionSnapshot> after = snapshot_selections(n1);
  CHECK(after.size() == before.size());
  for (std::size_t i = 0; i < before.size() && i < after.size(); ++i) {
    CHECK(after[i].dest == before[i].dest);
    CHECK(after[i].next_hop == before[i].next_hop);
    CHECK(after[i].generation == before[i].generation);
    CHECK(after[i].sequence == before[i].sequence);
    CHECK(after[i].metric == before[i].metric);
    CHECK(after[i].valid == before[i].valid);
  }
  std::size_t fresh_changes = 0;
  routes.for_each_selected_change(
      [&](const RouteSelection&, const RouteSelection&) { ++fresh_changes; }, world.now);
  CHECK(fresh_changes == 0);

  // Positive control: a real topology change IS detected by the same
  // instruments, so the quiet above is evidence, not a deaf detector. A
  // new neighbor seeds a direct route synchronously; the check runs
  // before any advertisement can sync the baseline first.
  world.add(4);
  world.at(4)->start(world.now);
  world.link(1, 4, 1, 1);
  std::size_t real_changes = 0;
  routes.for_each_selected_change(
      [&](const RouteSelection&, const RouteSelection&) { ++real_changes; }, world.now);
  CHECK(real_changes > 0);
  CHECK(observation_route_digest(n1, world.now) != route_digest_before);
  CHECK(observation_neighbor_digest(n1, world.now) != neighbor_digest_before);
}

void test_digests_track_structure_only() {
  SimWorld world;
  make_line(world);
  const MeshNode& n1 = *world.at(1);
  const std::uint32_t routes0 = observation_route_digest(n1, world.now);
  const std::uint32_t neighbors0 = observation_neighbor_digest(n1, world.now);
  // Time passing and traffic aging change no digest.
  world.run(500);
  CHECK(observation_route_digest(n1, world.now) == routes0);
  CHECK(observation_neighbor_digest(n1, world.now) == neighbors0);
  // A new neighbor moves the neighbor digest.
  world.add(4);
  world.at(4)->start(world.now);
  world.link(1, 4, 1, 1);
  world.run(500);
  CHECK(observation_neighbor_digest(n1, world.now) != neighbors0);
}

// --- fills --------------------------------------------------------------------

class FakeHealthPort final : public SystemHealthPort {
 public:
  std::uint32_t heap_free_bytes() const noexcept override { return 12345; }
  std::uint32_t heap_min_bytes() const noexcept override { return 12000; }
  std::uint32_t heap_largest_bytes() const noexcept override { return 8000; }
  std::uint8_t reset_code() const noexcept override { return kResetPowerOn; }
};

void test_fill_system() {
  ObservationSystem null_out{};
  const NullSystemHealthPort null_port{};
  fill_observation_system(0xB0071D0001ULL, 999, null_port, kPowerUnknown,
                          kCoordModeUnknown, kProfileUnknown, null_out);
  CHECK(null_out.boot_id == 0xB0071D0001ULL);
  CHECK(null_out.uptime_ms == 999);
  CHECK(null_out.heap_free_bytes == kHeapBytesUnknown);
  CHECK(null_out.heap_min_bytes == kHeapBytesUnknown);
  CHECK(null_out.heap_largest_bytes == kHeapBytesUnknown);
  CHECK(null_out.reset_code == kResetUnknown);

  ObservationSystem out{};
  const FakeHealthPort port{};
  fill_observation_system(7, 1000, port, kPowerRunning, kCoordModeMember,
                          kProfileMemberEdhoc, out);
  CHECK(out.boot_id == 7);
  CHECK(out.uptime_ms == 1000);
  CHECK(out.heap_free_bytes == 12345);
  CHECK(out.heap_min_bytes == 12000);
  CHECK(out.heap_largest_bytes == 8000);
  CHECK(out.reset_code == kResetPowerOn);
  CHECK(out.power_mode == kPowerRunning);
  CHECK(out.coord_mode == kCoordModeMember);
  CHECK(out.sec_profile == kProfileMemberEdhoc);
}

void test_fill_tables() {
  SimWorld world;
  make_line(world);
  const MeshNode& n1 = *world.at(1);
  ObservationTables out{};
  fill_observation_tables(n1, world.now, 3, 32, 5, 128, out);
  CHECK(out.neighbor_active == 1);
  CHECK(out.neighbor_total == 1);
  CHECK(out.route_reachable == 2);
  CHECK(out.route_total == 2);
  CHECK(out.link_sessions == 3);
  CHECK(out.link_cap == 32);
  CHECK(out.end_sessions == 5);
  CHECK(out.end_cap == 128);
  CHECK(out.dedup_cap == kDedupCapacity);
  CHECK(out.dedup_resident <= kDedupCapacity);
  CHECK(out.dedup_terminal <= out.dedup_resident);
  CHECK(out.tx_cap == MeshNode::tx_queue_capacity());
  CHECK(out.tx_used <= out.tx_cap);
}

// --- codecs ---------------------------------------------------------------------

void test_query_codec() {
  ObservationQuery query{};
  query.section = ObservationSection::Routes;
  query.max_entries = 8;
  query.flags = kObservationQuerySubscribe;
  query.after = 0x0102030405060708ULL;
  std::array<std::uint8_t, 64> buffer{};
  std::size_t written = 0;
  CHECK(encode_observation_query(query, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  CHECK(written == kGatewayInnerHeadSize + kObservationQueryPayload);
  ObservationQuery decoded{};
  CHECK(decode_observation_query(ByteView{buffer.data(), written}, decoded).ok());
  CHECK(decoded.section == ObservationSection::Routes);
  CHECK(decoded.max_entries == 8);
  CHECK(decoded.flags == kObservationQuerySubscribe);
  CHECK(decoded.after == 0x0102030405060708ULL);

  // EXACT names one destination on the routes section, one peer on the
  // neighbors section.
  ObservationQuery exact{};
  exact.section = ObservationSection::Routes;
  exact.flags = kObservationQueryExact;
  exact.after = 9;
  CHECK(encode_observation_query(exact, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  exact.section = ObservationSection::Neighbors;
  CHECK(encode_observation_query(exact, MutableByteView{buffer.data(), buffer.size()}, written).ok());

  // Rejects: unknown section, bad flags, EXACT off the paged sections,
  // EXACT with a zero cursor, all-ones cursor, out-of-range page size,
  // truncation.
  ObservationQuery bad = query;
  bad.section = static_cast<ObservationSection>(6);
  CHECK(!encode_observation_query(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = query;
  bad.flags = 0xFC;
  CHECK(!encode_observation_query(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = query;
  bad.section = ObservationSection::System;
  bad.flags = kObservationQueryExact;
  bad.after = 9;
  CHECK(!encode_observation_query(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = query;
  bad.flags = kObservationQueryExact;
  bad.after = 0;
  CHECK(!encode_observation_query(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = query;
  bad.max_entries = 0;
  CHECK(!encode_observation_query(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = query;
  bad.max_entries = kObservationRoutesPageMax + 1;
  CHECK(!encode_observation_query(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  std::array<std::uint8_t, 64> bad_buffer{};
  std::size_t bad_written = 0;
  CHECK(encode_observation_query(query, MutableByteView{bad_buffer.data(), bad_buffer.size()},
                                 bad_written)
            .ok());
  CHECK(!decode_observation_query(ByteView{bad_buffer.data(), bad_written - 1}, decoded).ok());
  // after=all-ones must be rejected on decode (encode allows the cursor
  // value only through raw bytes; craft by patching the cursor field).
  for (int i = 0; i < 8; ++i) bad_buffer[kGatewayInnerHeadSize + 4 + i] = 0xFF;
  CHECK(!decode_observation_query(ByteView{bad_buffer.data(), bad_written}, decoded).ok());
}

void test_singleton_codecs() {
  std::array<std::uint8_t, 64> buffer{};

  ObservationSystem system{};
  system.uptime_ms = 0xFFFFFFFFFFFFFFFFULL;
  system.heap_free_bytes = 1;
  system.heap_min_bytes = 2;
  system.heap_largest_bytes = 3;
  system.reset_code = kResetWatchdog;
  system.power_mode = kPowerDraining;
  system.coord_mode = kCoordModeZeroTouch;
  system.sec_profile = kProfileDevRam;
  CHECK(encode_observation_system(system, MutableByteView{buffer.data(), buffer.size()}).ok());
  ObservationSystem system_back{};
  CHECK(decode_observation_system(ByteView{buffer.data(), kObservationSystemBody}, system_back).ok());
  CHECK(system_back.uptime_ms == system.uptime_ms);
  CHECK(system_back.heap_free_bytes == 1);
  CHECK(system_back.reset_code == kResetWatchdog);
  CHECK(system_back.power_mode == kPowerDraining);
  CHECK(system_back.coord_mode == kCoordModeZeroTouch);
  CHECK(system_back.sec_profile == kProfileDevRam);
  CHECK(!decode_observation_system(ByteView{buffer.data(), kObservationSystemBody - 1}, system_back)
             .ok());

  ObservationTables tables{};
  tables.neighbor_active = 0xFFFF;
  tables.route_total = 128;
  tables.link_sessions = 32;
  tables.link_cap = 32;
  tables.dedup_resident = 96;
  tables.dedup_terminal = 7;
  tables.dedup_cap = 96;
  tables.tx_used = 31;
  tables.tx_cap = 32;
  tables.group_trees = 4;
  tables.group_origins = 3;
  tables.dedup_refused = 0xFFFFFFFFU;
  tables.dedup_evicted = 123;
  CHECK(encode_observation_tables(tables, MutableByteView{buffer.data(), buffer.size()}).ok());
  ObservationTables tables_back{};
  CHECK(decode_observation_tables(ByteView{buffer.data(), kObservationTablesBody}, tables_back).ok());
  CHECK(tables_back.neighbor_active == 0xFFFF);
  CHECK(tables_back.route_total == 128);
  CHECK(tables_back.dedup_terminal == 7);
  CHECK(tables_back.tx_used == 31);
  CHECK(tables_back.group_origins == 3);
  CHECK(tables_back.dedup_refused == 0xFFFFFFFFU);
  CHECK(!decode_observation_tables(ByteView{buffer.data(), kObservationTablesBody + 1}, tables_back)
             .ok());

  JoinMilestones milestones{};
  milestones.mode = kCoordModeMember;
  milestones.membership = kMembershipMember;
  milestones.joiner_state = kJoinerReady;
  milestones.flags = kMilestoneAdopted | kMilestoneConfirmed;
  milestones.attempts = 2;
  milestones.join_started_age_ms = 100;
  milestones.adopted_age_ms = 50;
  milestones.confirmed_age_ms = 10;
  milestones.adopted_node = 0x0A;
  CHECK(encode_observation_milestones(milestones, MutableByteView{buffer.data(), buffer.size()}).ok());
  JoinMilestones milestones_back{};
  CHECK(decode_observation_milestones(ByteView{buffer.data(), kObservationMilestonesBody},
                                      milestones_back)
            .ok());
  CHECK(milestones_back.mode == kCoordModeMember);
  CHECK(milestones_back.flags == (kMilestoneAdopted | kMilestoneConfirmed));
  CHECK(milestones_back.attempts == 2);
  CHECK(milestones_back.adopted_node == 0x0A);
  // Unknown flag bits are rejected, never masked away.
  buffer[3] = 0xFF;
  CHECK(!decode_observation_milestones(ByteView{buffer.data(), kObservationMilestonesBody},
                                       milestones_back)
             .ok());

  ObservationSummary summary{};
  summary.neighbor_digest = 0xA5A5A5A5U;
  summary.route_digest = 0x5A5A5A5AU;
  summary.neighbor_active = 3;
  summary.route_total = 40;
  summary.milestone_gen = 9;
  CHECK(encode_observation_summary(summary, MutableByteView{buffer.data(), buffer.size()}).ok());
  ObservationSummary summary_back{};
  CHECK(decode_observation_summary(ByteView{buffer.data(), kObservationSummaryBody}, summary_back)
            .ok());
  CHECK(summary_back.neighbor_digest == 0xA5A5A5A5U);
  CHECK(summary_back.route_digest == 0x5A5A5A5AU);
  CHECK(summary_back.milestone_gen == 9);
}

void test_route_entry_codec() {
  RouteDetailEntry entry{};
  entry.destination = 0x0102030405060708ULL;
  entry.next_hop = 0x0807060504030201ULL;
  entry.generation = 0xA5A5A5A5U;
  entry.sequence = 0x1234;
  entry.metric = 0x7FFF;
  entry.valid = true;
  entry.remaining_ms = 0xDEADBEEFU;
  std::array<std::uint8_t, kObservationRouteEntrySize> buffer{};
  CHECK(encode_observation_route_entry(entry, MutableByteView{buffer.data(), buffer.size()}).ok());
  RouteDetailEntry back{};
  CHECK(decode_observation_route_entry(ByteView{buffer.data(), buffer.size()}, back).ok());
  CHECK(back.destination == entry.destination);
  CHECK(back.next_hop == entry.next_hop);
  CHECK(back.generation == 0xA5A5A5A5U);
  CHECK(back.sequence == 0x1234);
  CHECK(back.metric == 0x7FFF);
  CHECK(back.valid);
  CHECK(back.remaining_ms == 0xDEADBEEFU);
  // flags > 1 and nonzero reserved are rejected.
  buffer[8 + 8 + 4 + 2 + 2] = 2;
  CHECK(!decode_observation_route_entry(ByteView{buffer.data(), buffer.size()}, back).ok());
  buffer[8 + 8 + 4 + 2 + 2] = 1;
  buffer[8 + 8 + 4 + 2 + 2 + 1] = 1;
  CHECK(!decode_observation_route_entry(ByteView{buffer.data(), buffer.size()}, back).ok());
}

void test_neighbor_entry_codec() {
  NeighborDetailEntry entry{};
  entry.peer = 0x0102030405060708ULL;
  entry.heard_age_ms = 4242;
  entry.lease_remaining_ms = 80000;
  entry.link_cost = 12;
  entry.rssi_ewma_q8_8 = static_cast<std::int16_t>(-70 * 256 + 128);
  entry.phase = kNeighborPhaseReachable;
  entry.flags = kNeighborActive | kNeighborRssiValid | kNeighborHeardValid;
  entry.rssi_last_dbm = -71;
  std::array<std::uint8_t, kObservationNeighborEntrySize> buffer{};
  CHECK(encode_observation_neighbor_entry(entry, MutableByteView{buffer.data(), buffer.size()})
            .ok());
  NeighborDetailEntry back{};
  CHECK(decode_observation_neighbor_entry(ByteView{buffer.data(), buffer.size()}, back).ok());
  CHECK(back.peer == entry.peer);
  CHECK(back.heard_age_ms == 4242);
  CHECK(back.lease_remaining_ms == 80000);
  CHECK(back.link_cost == 12);
  CHECK(back.rssi_ewma_q8_8 == static_cast<std::int16_t>(-70 * 256 + 128));
  CHECK(back.phase == kNeighborPhaseReachable);
  CHECK(back.flags == entry.flags);
  CHECK(back.rssi_last_dbm == -71);
  // Unknown flag bits and nonzero reserved are rejected; unknown phase
  // and sentinel ages round-trip (they are data, not errors).
  buffer[21] = 0xF8;
  CHECK(!decode_observation_neighbor_entry(ByteView{buffer.data(), buffer.size()}, back).ok());
  buffer[21] = entry.flags;
  buffer[23] = 1;
  CHECK(!decode_observation_neighbor_entry(ByteView{buffer.data(), buffer.size()}, back).ok());
  buffer[23] = 0;
  NeighborDetailEntry unknown{};
  unknown.peer = 9;
  CHECK(encode_observation_neighbor_entry(unknown, MutableByteView{buffer.data(), buffer.size()})
            .ok());
  CHECK(decode_observation_neighbor_entry(ByteView{buffer.data(), buffer.size()}, back).ok());
  CHECK(back.phase == kNeighborPhaseUnknown);
  CHECK(back.heard_age_ms == kNeighborAgeUnknown);
  CHECK(back.lease_remaining_ms == kNeighborAgeUnknown);
}

void test_page_codec() {
  std::array<std::uint8_t, kGatewayInnerHeadSize + kObservationPageMaxPayload> buffer{};
  // Singleton page round-trip.
  ObservationSystem system{};
  system.uptime_ms = 4242;
  std::array<std::uint8_t, kObservationSystemBody> body{};
  CHECK(encode_observation_system(system, MutableByteView{body.data(), body.size()}).ok());
  ObservationPageHeader header{};
  header.result = static_cast<std::uint16_t>(ConfigOpsResult::Ok);
  header.section = ObservationSection::System;
  header.flags = kObservationPageArmed;
  header.count = 1;
  header.boot_id = 0xB0071D0001ULL;
  header.revision = 0;
  header.next_after = 0;
  std::size_t written = 0;
  CHECK(encode_observation_page(header, ByteView{body.data(), body.size()}, 1,
                                MutableByteView{buffer.data(), buffer.size()}, written)
            .ok());
  ObservationPageHeader header_back{};
  ByteView body_back{};
  CHECK(decode_observation_page(ByteView{buffer.data(), written}, header_back, body_back).ok());
  CHECK(header_back.section == ObservationSection::System);
  CHECK(header_back.count == 1);
  CHECK(header_back.boot_id == 0xB0071D0001ULL);
  CHECK((header_back.flags & kObservationPageArmed) != 0);
  CHECK(body_back.size == kObservationSystemBody);

  // Routes page round-trip (ascending entries).
  RouteDetailEntry entries[2]{};
  entries[0].destination = 2;
  entries[0].next_hop = 2;
  entries[0].generation = 1;
  entries[0].valid = true;
  entries[0].remaining_ms = 500;
  entries[1].destination = 3;
  entries[1].next_hop = 2;
  entries[1].generation = 1;
  entries[1].valid = true;
  entries[1].remaining_ms = 400;
  std::array<std::uint8_t, 2 * kObservationRouteEntrySize> routes_body{};
  for (int i = 0; i < 2; ++i) {
    CHECK(encode_observation_route_entry(
              entries[i],
              MutableByteView{routes_body.data() + i * kObservationRouteEntrySize,
                              kObservationRouteEntrySize})
              .ok());
  }
  ObservationPageHeader routes_header{};
  routes_header.result = static_cast<std::uint16_t>(ConfigOpsResult::Ok);
  routes_header.section = ObservationSection::Routes;
  routes_header.flags = kObservationPageMore | kObservationPageArmed;
  routes_header.count = 2;
  routes_header.boot_id = 9;
  routes_header.revision = 0x11223344U;
  routes_header.next_after = 3;
  CHECK(encode_observation_page(routes_header, ByteView{routes_body.data(), routes_body.size()}, 2,
                                MutableByteView{buffer.data(), buffer.size()}, written)
            .ok());
  CHECK(decode_observation_page(ByteView{buffer.data(), written}, header_back, body_back).ok());
  CHECK(header_back.count == 2);
  CHECK(header_back.next_after == 3);
  CHECK(body_back.size == 2 * kObservationRouteEntrySize);

  // Neighbors page round-trip (ascending peers, same cursor rule).
  NeighborDetailEntry peers[2]{};
  peers[0].peer = 2;
  peers[0].link_cost = 1;
  peers[0].phase = kNeighborPhaseReachable;
  peers[0].flags = kNeighborActive | kNeighborHeardValid;
  peers[0].heard_age_ms = 120;
  peers[1].peer = 3;
  peers[1].link_cost = 2;
  std::array<std::uint8_t, 2 * kObservationNeighborEntrySize> neighbors_body{};
  for (int i = 0; i < 2; ++i) {
    CHECK(encode_observation_neighbor_entry(
              peers[i],
              MutableByteView{neighbors_body.data() + i * kObservationNeighborEntrySize,
                              kObservationNeighborEntrySize})
              .ok());
  }
  ObservationPageHeader neighbors_header{};
  neighbors_header.result = static_cast<std::uint16_t>(ConfigOpsResult::Ok);
  neighbors_header.section = ObservationSection::Neighbors;
  neighbors_header.count = 2;
  neighbors_header.boot_id = 9;
  neighbors_header.revision = 0xA5A5A5A5U;
  neighbors_header.next_after = 3;
  CHECK(encode_observation_page(neighbors_header,
                                ByteView{neighbors_body.data(), neighbors_body.size()}, 2,
                                MutableByteView{buffer.data(), buffer.size()}, written)
            .ok());
  CHECK(decode_observation_page(ByteView{buffer.data(), written}, header_back, body_back).ok());
  CHECK(header_back.count == 2);
  CHECK(header_back.next_after == 3);
  CHECK(body_back.size == 2 * kObservationNeighborEntrySize);
  ObservationPageHeader neighbors_bad_cursor = neighbors_header;
  neighbors_bad_cursor.next_after = 2;
  CHECK(!encode_observation_page(neighbors_bad_cursor,
                                 ByteView{neighbors_body.data(), neighbors_body.size()}, 2,
                                 MutableByteView{buffer.data(), buffer.size()}, written)
             .ok());

  // Rejects: count/body mismatch, non-ascending entries, wrong cursor,
  // singleton count != 1, non-Ok with entries.
  CHECK(!encode_observation_page(routes_header, ByteView{routes_body.data(), routes_body.size()},
                                 1, MutableByteView{buffer.data(), buffer.size()}, written)
             .ok());
  std::array<std::uint8_t, 2 * kObservationRouteEntrySize> swapped{};
  CHECK(encode_observation_route_entry(
            entries[1], MutableByteView{swapped.data(), kObservationRouteEntrySize})
            .ok());
  CHECK(encode_observation_route_entry(
            entries[0],
            MutableByteView{swapped.data() + kObservationRouteEntrySize, kObservationRouteEntrySize})
            .ok());
  CHECK(!encode_observation_page(routes_header, ByteView{swapped.data(), swapped.size()}, 2,
                                 MutableByteView{buffer.data(), buffer.size()}, written)
             .ok());
  ObservationPageHeader bad_cursor = routes_header;
  bad_cursor.next_after = 2;
  CHECK(!encode_observation_page(bad_cursor, ByteView{routes_body.data(), routes_body.size()}, 2,
                                 MutableByteView{buffer.data(), buffer.size()}, written)
             .ok());
  ObservationPageHeader bad_count = header;
  bad_count.count = 2;
  CHECK(!encode_observation_page(bad_count, ByteView{body.data(), body.size()}, 2,
                                 MutableByteView{buffer.data(), buffer.size()}, written)
             .ok());

  // Non-Ok pages carry count 0 and an empty body, any section.
  ObservationPageHeader unsupported{};
  unsupported.result = static_cast<std::uint16_t>(ConfigOpsResult::Unsupported);
  unsupported.section = ObservationSection::Tables;
  unsupported.boot_id = 9;
  unsupported.next_after = 0x77;
  CHECK(encode_observation_page(unsupported, ByteView{}, 0,
                                MutableByteView{buffer.data(), buffer.size()}, written)
            .ok());
  CHECK(decode_observation_page(ByteView{buffer.data(), written}, header_back, body_back).ok());
  CHECK(header_back.count == 0);
  CHECK(body_back.size == 0);
  CHECK(header_back.next_after == 0x77);
}

void test_event_codec() {
  std::array<std::uint8_t, kGatewayInnerHeadSize + kObservationEventPayload> buffer{};
  ObservationEvent event{};
  event.sequence = 41;
  event.kind = kObservationEventTopology;
  event.mask = kObservationEventMaskRoutes;
  event.boot_id = 0xB0071D0001ULL;
  event.revision = 0x11111111U;
  event.extra = 0x22222222U;
  std::size_t written = 0;
  CHECK(
      encode_observation_event(event, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  CHECK(written == kGatewayInnerHeadSize + kObservationEventPayload);
  ObservationEvent back{};
  CHECK(decode_observation_event(ByteView{buffer.data(), written}, back).ok());
  CHECK(back.sequence == 41);
  CHECK(back.kind == kObservationEventTopology);
  CHECK(back.mask == kObservationEventMaskRoutes);
  CHECK(back.revision == 0x11111111U);
  CHECK(back.extra == 0x22222222U);

  ObservationEvent milestone{};
  milestone.sequence = 1;
  milestone.kind = kObservationEventMilestone;
  milestone.boot_id = 5;
  milestone.revision = 3;
  CHECK(encode_observation_event(milestone, MutableByteView{buffer.data(), buffer.size()}, written)
            .ok());
  CHECK(decode_observation_event(ByteView{buffer.data(), written}, back).ok());
  CHECK(back.kind == kObservationEventMilestone);
  CHECK(back.mask == 0);

  // Rejects: zero sequence, unknown kind, milestone mask, bad topology mask.
  ObservationEvent bad = event;
  bad.sequence = 0;
  CHECK(!encode_observation_event(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = event;
  bad.kind = 3;
  CHECK(!encode_observation_event(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = milestone;
  bad.mask = 1;
  CHECK(!encode_observation_event(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
  bad = event;
  bad.mask = 0xFC;
  CHECK(!encode_observation_event(bad, MutableByteView{buffer.data(), buffer.size()}, written).ok());
}

bool hex_value(char c, std::uint8_t& out) {
  if (c >= '0' && c <= '9') {
    out = static_cast<std::uint8_t>(c - '0');
    return true;
  }
  if (c >= 'a' && c <= 'f') {
    out = static_cast<std::uint8_t>(c - 'a' + 10);
    return true;
  }
  return false;
}

std::vector<std::uint8_t> hex_decode(const char* hex) {
  std::vector<std::uint8_t> out;
  const std::size_t len = std::strlen(hex);
  for (std::size_t i = 0; i + 1 < len; i += 2) {
    std::uint8_t high = 0, low = 0;
    if (!hex_value(hex[i], high) || !hex_value(hex[i + 1], low)) return {};
    out.push_back(static_cast<std::uint8_t>(high * 16 + low));
  }
  return out;
}

void test_milestone_key() {
  // The zero tuple keys to the bridge's seed baseline (no gen bump on
  // first sight); any tuple field moves the key.
  JoinMilestones zero{};
  zero.mode = 0;
  zero.membership = 0;
  zero.joiner_state = 0;
  zero.flags = 0;
  zero.attempts = 0;
  CHECK(observation_milestones_key(zero) == kObservationMilestoneKeyZero);
  JoinMilestones moved = zero;
  moved.attempts = 1;
  CHECK(observation_milestones_key(moved) != kObservationMilestoneKeyZero);
  moved = zero;
  moved.mode = 1;
  CHECK(observation_milestones_key(moved) != kObservationMilestoneKeyZero);
  CHECK(observation_milestones_key(zero) == observation_milestones_key(zero));
}

// Fixed vectors: the same bytes are asserted in
// host/routeloom-protocol/src/observation.rs
// `fixed_vectors_match_device_encoder` — identical bytes must decode
// identically on both sides. Regenerate both from the encoder above.
void test_fixed_vectors() {
  const auto query =
      hex_decode("0170000c040108000000000000000000");
  ObservationQuery decoded_query{};
  CHECK(decode_observation_query(ByteView{query.data(), query.size()},
                                 decoded_query)
            .ok());
  CHECK(decoded_query.section == ObservationSection::Routes);
  CHECK(decoded_query.flags == kObservationQuerySubscribe);
  CHECK(decoded_query.max_entries == 8);
  CHECK(decoded_query.after == 0);

  const auto system_page = hex_decode(
      "01710036000000020100000000b0071d000100000000000000000000000000000000"
      "000010920000000100000002000000030302020200000000");
  ObservationPageHeader header{};
  ByteView body{};
  CHECK(decode_observation_page(
            ByteView{system_page.data(), system_page.size()}, header, body)
            .ok());
  CHECK(header.section == ObservationSection::System);
  CHECK(header.count == 1);
  CHECK(header.boot_id == 0xB0071D0001ULL);
  ObservationSystem system{};
  CHECK(decode_observation_system(body, system).ok());
  CHECK(system.uptime_ms == 4242);
  CHECK(system.reset_code == 3);

  const auto milestones_page = hex_decode(
      "0171003a000002000100000000b0071d000100000007000000000000000003050303"
      "0000000200000064000000320000000a000000000000000a00000000");
  CHECK(decode_observation_page(
            ByteView{milestones_page.data(), milestones_page.size()}, header,
            body)
            .ok());
  CHECK(header.section == ObservationSection::Milestones);
  CHECK(header.revision == 7);
  JoinMilestones milestones{};
  CHECK(decode_observation_milestones(body, milestones).ok());
  CHECK(milestones.mode == kCoordModeMember);
  CHECK(milestones.flags == (kMilestoneAdopted | kMilestoneConfirmed));
  CHECK(milestones.attempts == 2);
  CHECK(milestones.adopted_node == 0x0A);

  const auto routes_page = hex_decode(
      "017100560000040302000000000000000009112233440000000000000003"
      "0000000000000002000000000000000200000001000900010100000001f4"
      "000000000000000300000000000000020000000100070002010000000190");
  CHECK(decode_observation_page(
            ByteView{routes_page.data(), routes_page.size()}, header, body)
            .ok());
  CHECK(header.section == ObservationSection::Routes);
  CHECK(header.count == 2);
  CHECK(header.revision == 0x11223344U);
  CHECK(header.next_after == 3);
  RouteDetailEntry e0{};
  CHECK(decode_observation_route_entry(
            ByteView{body.data, kObservationRouteEntrySize}, e0)
            .ok());
  CHECK(e0.destination == 2 && e0.next_hop == 2);
  CHECK(e0.generation == 1 && e0.sequence == 9 && e0.metric == 1);
  CHECK(e0.valid && e0.remaining_ms == 500);

  const auto neighbors_page = hex_decode(
      "01710032000005000100000000b0071d0001a5a5a5a50000000000000002"
      "000000000000000200000078000138800001ba800605b900");
  CHECK(decode_observation_page(
            ByteView{neighbors_page.data(), neighbors_page.size()}, header,
            body)
            .ok());
  CHECK(header.section == ObservationSection::Neighbors);
  CHECK(header.count == 1);
  CHECK(header.revision == 0xA5A5A5A5U);
  CHECK(header.next_after == 2);
  NeighborDetailEntry n0{};
  CHECK(decode_observation_neighbor_entry(
            ByteView{body.data, kObservationNeighborEntrySize}, n0)
            .ok());
  CHECK(n0.peer == 2);
  CHECK(n0.heard_age_ms == 120 && n0.lease_remaining_ms == 80000);
  CHECK(n0.link_cost == 1 && n0.phase == kNeighborPhaseReachable);
  CHECK(n0.flags == (kNeighborActive | kNeighborHeardValid));
  CHECK(n0.rssi_last_dbm == -71);

  const auto event = hex_decode(
      "017200180000002901020000000000b0071d00011111111122222222");
  ObservationEvent decoded_event{};
  CHECK(decode_observation_event(ByteView{event.data(), event.size()},
                                 decoded_event)
            .ok());
  CHECK(decoded_event.sequence == 41);
  CHECK(decoded_event.kind == kObservationEventTopology);
  CHECK(decoded_event.mask == kObservationEventMaskRoutes);
}

}  // namespace

void test_reference_obs1_receipt() {
  routeloom::ObservationSystem system{};
  system.boot_id = 7;
  system.uptime_ms = 1234;
  system.heap_free_bytes = 4096;
  char response[512]{};
  std::size_t used = 0;
  CHECK(routeloom::format_observation_console_system(
      2, system, response, sizeof(response), used).ok());
  CHECK(used < sizeof(response));
  CHECK(std::strncmp(response, "OBS1 {", 6) == 0);
  CHECK(std::strstr(response, "\"observer_boot\":\"0000000000000007\"") != nullptr);
  CHECK(std::strstr(response, "\"uptime_ms\":1234") != nullptr);
  char small[8]{};
  CHECK(!routeloom::format_observation_console_system(
      2, system, small, sizeof(small), used).ok());
  CHECK(used == 0);
}

int main() {
  test_reference_obs1_receipt();
  test_route_detail_line_topology();
  test_route_detail_page_walk();
  test_neighbor_detail_line_topology();
  test_neighbor_detail_page_walk();
  test_neighbor_phase_registry_pins_discovery_order();
  test_observation_counts();
  test_observation_reads_change_nothing();
  test_digests_track_structure_only();
  test_fill_system();
  test_fill_tables();
  test_query_codec();
  test_singleton_codecs();
  test_route_entry_codec();
  test_neighbor_entry_codec();
  test_page_codec();
  test_event_codec();
  test_fixed_vectors();
  test_milestone_key();
  if (failures != 0) {
    std::fprintf(stderr, "observation tests: %d failures\n", failures);
    return 1;
  }
  std::printf("observation tests: all passed\n");
  return 0;
}
