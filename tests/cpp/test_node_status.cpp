// node_status_v1 unit tests: the MeshNode snapshot accessors, the bounded
// NodeStatusMonitor diff tracker and the HostOps 0x40-0x42 codecs. Bridge
// integration and the shared USB golden replay live in test_usb.cpp.

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <functional>
#include <map>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/node_status.hpp"
#include "routeloom/usb_host_ops.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr) do { if (!(expr)) { std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, #expr); ++failures; } } while (false)
#define CHECK_OK(expr) do { const auto _status = (expr); if (!_status.ok()) { std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__, __LINE__, #expr, _status.detail); ++failures; } } while (false)

using namespace routeloom;
using namespace routeloom::usb;
using routeloom_test::SimWorld;

// ------------------------------------------------------------ snapshot

void test_snapshot_line_topology() {
  // 1 -- 2 -- 3: node 1 hears 2 directly and reaches 3 through 2.
  SimWorld world;
  world.add(1);
  world.add(2);
  world.add(3);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.link(2, 3, 1, 1);
  world.run(1500);

  const MeshNode& n1 = *world.at(1);
  NodeStatus s2{};
  CHECK(n1.node_status(2, world.now, s2));
  CHECK(s2.node == 2);
  CHECK((s2.flags & kNodeStatusNeighbor) != 0);
  CHECK(s2.neighbor_active());
  CHECK(s2.reachable());
  CHECK((s2.flags & kNodeStatusDirect) != 0);
  CHECK(s2.next_hop == 2);
  CHECK(s2.link_cost == n1.peer_link_cost(2));
  CHECK(s2.route_metric == n1.routes().best(2).metric);
  // Route advertisements from 2 were link-authenticated at node 1: the sim
  // injects RSSI -60 through the V1 path (InjectedTest provenance).
  CHECK((s2.flags & kNodeStatusHeardValid) != 0);
  CHECK((s2.flags & kNodeStatusRssiValid) != 0);
  CHECK(s2.rssi_last_dbm == -60);
  CHECK(s2.rssi_ewma_q8_8 == -60 * 256);
  CHECK(s2.heard_age_ms < 1000);

  NodeStatus s3{};
  CHECK(n1.node_status(3, world.now, s3));
  CHECK(!s3.neighbor_active());
  CHECK((s3.flags & kNodeStatusNeighbor) == 0);
  CHECK(s3.reachable());
  CHECK((s3.flags & kNodeStatusDirect) == 0);
  CHECK(s3.next_hop == 2);
  CHECK(s3.route_metric == 2);
  CHECK(s3.link_cost == kInfiniteRouteMetric);
  // Never the immediate transmitter: no RF evidence is fabricated.
  CHECK((s3.flags & (kNodeStatusHeardValid | kNodeStatusRssiValid)) == 0);

  // Self, reserved and unknown ids are not listable.
  NodeStatus none{};
  CHECK(!n1.node_status(1, world.now, none));
  CHECK(!n1.node_status(kInvalidNodeId, world.now, none));
  CHECK(!n1.node_status(kBroadcastNodeId, world.now, none));
  CHECK(!n1.node_status(99, world.now, none));

  // The heard age is a duration on the same monotonic axis.
  NodeStatus later{};
  CHECK(n1.node_status(2, world.now + 5000, later));
  CHECK(later.heard_age_ms == s2.heard_age_ms + 5000);

  // Link loss: the neighbor record stays (departed), reachability ends.
  world.unlink(2, 3);
  world.unlink(1, 2);
  world.run(3000);
  NodeStatus gone{};
  CHECK(n1.node_status(2, world.now, gone));
  CHECK((gone.flags & kNodeStatusNeighbor) != 0);
  CHECK(!gone.neighbor_active());
  CHECK(!gone.reachable());
  CHECK(gone.next_hop == kInvalidNodeId);
  CHECK(gone.link_cost == kInfiniteRouteMetric);
}

void test_snapshot_pagination() {
  SimWorld world;
  MeshNode* n1 = world.add(1);
  world.start_all();
  // Insert out of order: pages must still come back strictly ascending.
  const std::array<NodeId, 20> ids{{900, 7, 300, 12, 5000, 44, 45, 2, 1000, 81,
                                    650, 3, 17, 18, 19, 20000, 77, 78, 1234, 555}};
  for (const NodeId id : ids) CHECK_OK(n1->add_neighbor(id, 2, world.now));
  std::vector<NodeId> expected(ids.begin(), ids.end());
  std::sort(expected.begin(), expected.end());

  for (const std::size_t page_size : {std::size_t{1}, std::size_t{3}, std::size_t{7},
                                      std::size_t{16}, std::size_t{20}}) {
    std::vector<NodeId> walked;
    NodeId cursor = kInvalidNodeId;
    bool more = true;
    std::array<NodeStatus, kNodeStatusPageMax + 4> page{};
    int guard = 0;
    while (more && guard++ < 64) {
      const std::size_t n = n1->node_status_page(cursor, page.data(), page_size,
                                                 world.now, more);
      CHECK(n <= page_size);
      if (n == 0) break;
      for (std::size_t i = 0; i < n; ++i) {
        CHECK(page[i].neighbor_active() && page[i].reachable());
        walked.push_back(page[i].node);
      }
      cursor = page[n - 1].node;
    }
    CHECK(walked == expected);
  }
  // Exact-fit last page reports no more; a zero-capacity probe reports more.
  bool more = true;
  std::array<NodeStatus, 20> all{};
  CHECK(n1->node_status_page(0, all.data(), all.size(), world.now, more) == 20);
  CHECK(!more);
  CHECK(n1->node_status_page(0, all.data(), 0, world.now, more) == 0);
  CHECK(more);
  CHECK(n1->node_status_page(20000, all.data(), all.size(), world.now, more) == 0);
  CHECK(!more);
  CHECK(n1->node_status_page(0, nullptr, 4, world.now, more) == 0);

  // A cursor survives churn: removing an already-listed node and adding a
  // new one behind the cursor never repeats or skips the rest.
  std::array<NodeStatus, 5> first{};
  CHECK(n1->node_status_page(0, first.data(), first.size(), world.now, more) == 5);
  CHECK(more);
  CHECK(!n1->add_neighbor(1, 1, world.now).ok());  // self is never listable
  CHECK_OK(n1->remove_neighbor(first[0].node, world.now));
  CHECK_OK(n1->add_neighbor(4, 2, world.now));  // lands before the cursor
  std::vector<NodeId> rest;
  NodeId cursor = first[4].node;
  more = true;
  while (more) {
    const std::size_t n = n1->node_status_page(cursor, all.data(), 4, world.now, more);
    if (n == 0) break;
    for (std::size_t i = 0; i < n; ++i) rest.push_back(all[i].node);
    cursor = all[n - 1].node;
  }
  CHECK(rest == std::vector<NodeId>(expected.begin() + 5, expected.end()));
}

// ------------------------------------------------------------ monitor

// Scriptable Source: a sorted map the test mutates between polls.
struct FakeSource {
  std::map<NodeId, NodeStatus> nodes;
  mutable int pages{0};

  void set(NodeId node, bool neighbor, bool reachable, NodeId next_hop = kInvalidNodeId) {
    NodeStatus s{};
    s.node = node;
    s.flags = static_cast<std::uint8_t>(
        (neighbor ? (kNodeStatusNeighbor | kNodeStatusNeighborActive) : 0U) |
        (reachable ? kNodeStatusReachable : 0U));
    s.next_hop = reachable ? (next_hop == kInvalidNodeId ? node : next_hop) : kInvalidNodeId;
    if (reachable && s.next_hop == node) s.flags |= kNodeStatusDirect;
    nodes[node] = s;
  }

  std::size_t node_status_page(NodeId after, NodeStatus* out, std::size_t capacity,
                               MonotonicMs, bool& more) const noexcept {
    ++pages;
    more = false;
    std::size_t n = 0;
    for (auto it = nodes.upper_bound(after); it != nodes.end(); ++it) {
      if (n == capacity) {
        more = true;
        break;
      }
      out[n++] = it->second;
    }
    return n;
  }
};

struct Recorder {
  std::vector<NodeEvent> events;
  std::size_t refuse_after{SIZE_MAX};
  bool operator()(const NodeEvent& event) {
    if (events.size() >= refuse_after) return false;
    events.push_back(event);
    return true;
  }
};

void test_monitor_diff() {
  FakeSource source;
  source.set(10, true, true);
  source.set(20, false, true, 10);
  source.set(30, false, false);  // known but uninteresting: never tracked
  NodeStatusMonitor monitor;
  Recorder rec;
  // Disarmed: nothing happens.
  CHECK(monitor.poll(source, 0, 8, std::ref(rec)) == 0);
  monitor.arm(source, 0);
  CHECK(monitor.armed());
  CHECK(monitor.tracked() == 2);
  CHECK(monitor.poll(source, 1, 8, std::ref(rec)) == 0);  // arm is silent
  CHECK(rec.events.empty());

  // Join: a new neighbor with a direct route -> NeighborUp then RouteUp.
  source.set(15, true, true);
  CHECK(monitor.poll(source, 2, 8, std::ref(rec)) == 2);
  CHECK(rec.events.size() == 2);
  CHECK(rec.events[0].kind == NodeEventKind::NeighborUp && rec.events[0].status.node == 15);
  CHECK(rec.events[1].kind == NodeEventKind::RouteUp && rec.events[1].status.node == 15);
  CHECK(rec.events[0].sequence == 1 && rec.events[1].sequence == 2);

  // Re-route: 20 now via 15 -> RouteChanged only.
  source.set(20, false, true, 15);
  CHECK(monitor.poll(source, 3, 8, std::ref(rec)) == 1);
  CHECK(rec.events.back().kind == NodeEventKind::RouteChanged);
  CHECK(rec.events.back().status.next_hop == 15);
  CHECK(rec.events.back().sequence == 3);

  // Leave: 10 vanishes from the source entirely, 20 becomes unreachable.
  source.nodes.erase(10);
  source.set(20, false, false);
  rec.events.clear();
  CHECK(monitor.poll(source, 4, 8, std::ref(rec)) == 3);
  CHECK(rec.events.size() == 3);
  CHECK(rec.events[0].kind == NodeEventKind::NeighborDown && rec.events[0].status.node == 10);
  CHECK(rec.events[1].kind == NodeEventKind::RouteDown && rec.events[1].status.node == 10);
  CHECK(!rec.events[1].status.reachable());
  CHECK(rec.events[2].kind == NodeEventKind::RouteDown && rec.events[2].status.node == 20);
  CHECK(monitor.tracked() == 1);  // only 15 remains interesting
  CHECK(monitor.last_sequence() == 6);

  // A flap that starts and ends between polls is not reported.
  source.set(20, false, true, 15);
  source.set(20, false, false);
  rec.events.clear();
  CHECK(monitor.poll(source, 5, 8, std::ref(rec)) == 0);

  // Re-arm restarts the sequence space and the baseline.
  monitor.arm(source, 6);
  CHECK(monitor.last_sequence() == 0 && monitor.tracked() == 1);
  monitor.disarm();
  CHECK(!monitor.armed() && monitor.tracked() == 0);
}

void test_monitor_backpressure() {
  FakeSource source;
  NodeStatusMonitor monitor;
  monitor.arm(source, 0);
  for (NodeId id = 1; id <= 5; ++id) source.set(id * 10, true, true);
  Recorder rec;
  // Budget 3: exactly three events, in id order, then the pass stops.
  CHECK(monitor.poll(source, 1, 3, std::ref(rec)) == 3);
  CHECK(rec.events.size() == 3);
  CHECK(rec.events[2].status.node == 20 && rec.events[2].kind == NodeEventKind::NeighborUp);
  // Refusal: the sink takes one more then refuses; nothing is lost, the
  // refused transition is offered again with the SAME sequence number.
  rec.refuse_after = 4;
  CHECK(monitor.poll(source, 2, 8, std::ref(rec)) == 1);
  CHECK(rec.events.back().sequence == 4);
  rec.refuse_after = SIZE_MAX;
  CHECK(monitor.poll(source, 3, 64, std::ref(rec)) == 6);
  CHECK(rec.events.size() == 10);
  for (std::size_t i = 0; i < rec.events.size(); ++i) {
    CHECK(rec.events[i].sequence == i + 1);  // contiguous, no gap, no dup
  }
  // Each node produced exactly NeighborUp then RouteUp.
  for (std::size_t i = 0; i < 10; i += 2) {
    CHECK(rec.events[i].kind == NodeEventKind::NeighborUp);
    CHECK(rec.events[i + 1].kind == NodeEventKind::RouteUp);
    CHECK(rec.events[i].status.node == rec.events[i + 1].status.node);
  }
  // A node that joins and is refused, then leaves before the retry, is
  // dropped from the baseline without any event.
  source.set(60, true, true);
  rec.refuse_after = rec.events.size();
  CHECK(monitor.poll(source, 4, 8, std::ref(rec)) == 0);
  CHECK(monitor.tracked() == 6);
  source.nodes.erase(60);
  rec.refuse_after = SIZE_MAX;
  CHECK(monitor.poll(source, 5, 8, std::ref(rec)) == 0);
  CHECK(monitor.tracked() == 5);
  CHECK(monitor.overflow() == 0);
}

void test_monitor_with_mesh() {
  SimWorld world;
  world.add(1);
  world.add(2);
  world.add(3);
  world.start_all();
  world.link(1, 2, 1, 1);
  world.run(500);
  NodeStatusMonitor monitor;
  monitor.arm(*world.at(1), world.now);
  CHECK(monitor.tracked() == 1);
  Recorder rec;
  world.link(2, 3, 1, 1);
  world.run(1500);
  CHECK(monitor.poll(*world.at(1), world.now, 8, std::ref(rec)) == 1);
  CHECK(rec.events.size() == 1);
  if (!rec.events.empty()) {
    CHECK(rec.events[0].kind == NodeEventKind::RouteUp);
    CHECK(rec.events[0].status.node == 3 && rec.events[0].status.next_hop == 2);
  }
  rec.events.clear();
  world.unlink(1, 2);
  world.run(3000);
  CHECK(monitor.poll(*world.at(1), world.now, 8, std::ref(rec)) == 3);
  bool down2 = false, lost2 = false, lost3 = false;
  for (const auto& e : rec.events) {
    down2 = down2 || (e.kind == NodeEventKind::NeighborDown && e.status.node == 2);
    lost2 = lost2 || (e.kind == NodeEventKind::RouteDown && e.status.node == 2);
    lost3 = lost3 || (e.kind == NodeEventKind::RouteDown && e.status.node == 3);
  }
  CHECK(down2 && lost2 && lost3);
  CHECK(monitor.tracked() == 0);
}

// ------------------------------------------------------------ codec

NodeStatus sample_entry(NodeId node, bool reachable) {
  NodeStatus s{};
  s.node = node;
  s.flags = kNodeStatusNeighbor | kNodeStatusNeighborActive | kNodeStatusRssiValid |
            kNodeStatusHeardValid;
  if (reachable) s.flags |= kNodeStatusReachable | kNodeStatusDirect;
  s.rssi_last_dbm = -71;
  s.rssi_ewma_q8_8 = -18000;
  s.link_cost = 3;
  s.route_metric = reachable ? 3 : kInfiniteRouteMetric;
  s.next_hop = reachable ? node : kInvalidNodeId;
  s.heard_age_ms = 1234;
  return s;
}

bool same(const NodeStatus& a, const NodeStatus& b) {
  return a.node == b.node && a.flags == b.flags && a.rssi_last_dbm == b.rssi_last_dbm &&
         a.rssi_ewma_q8_8 == b.rssi_ewma_q8_8 && a.link_cost == b.link_cost &&
         a.route_metric == b.route_metric && a.next_hop == b.next_hop &&
         a.heard_age_ms == b.heard_age_ms;
}

void test_codec_query() {
  std::array<std::uint8_t, 32> buf{};
  std::size_t n = 0;
  NodeStatusQuery q{};
  q.after = 0x0102030405060708ULL;
  q.max_entries = 16;
  q.flags = kNodeStatusQuerySubscribe;
  CHECK_OK(encode_node_status_query(q, MutableByteView{buf.data(), buf.size()}, n));
  CHECK(n == kGatewayInnerHeadSize + kNodeStatusQueryPayload);
  const std::array<std::uint8_t, 14> golden{{0x01, 0x40, 0x00, 0x0a, 0x01, 0x02, 0x03, 0x04,
                                             0x05, 0x06, 0x07, 0x08, 0x10, 0x01}};
  CHECK(std::memcmp(buf.data(), golden.data(), golden.size()) == 0);
  NodeStatusQuery back{};
  CHECK_OK(decode_node_status_query(ByteView{buf.data(), n}, back));
  CHECK(back.after == q.after && back.max_entries == 16 && back.flags == 1);

  auto rejects = [&](std::size_t index, std::uint8_t value) {
    std::array<std::uint8_t, 14> bad = golden;
    bad[index] = value;
    NodeStatusQuery out{};
    return !decode_node_status_query(ByteView{bad.data(), bad.size()}, out).ok();
  };
  CHECK(rejects(12, 0));     // max_entries 0
  CHECK(rejects(12, 17));    // above the page bound
  CHECK(rejects(13, 0x02));  // reserved flag bit
  CHECK(rejects(0, 2));      // schema
  CHECK(rejects(1, 0x41));   // wrong sub
  CHECK(rejects(3, 0x0b));   // payload_len mismatch
  std::array<std::uint8_t, 14> all_ones = golden;
  for (std::size_t i = 4; i < 12; ++i) all_ones[i] = 0xFF;
  NodeStatusQuery out{};
  CHECK(!decode_node_status_query(ByteView{all_ones.data(), all_ones.size()}, out).ok());
  CHECK(!decode_node_status_query(ByteView{golden.data(), 13}, out).ok());  // truncated
}

void test_codec_page_and_event() {
  std::array<NodeStatus, 3> entries{{sample_entry(5, true), sample_entry(9, false),
                                     sample_entry(700, true)}};
  NodeStatusPageHeader header{};
  header.result = 0;
  header.flags = kNodeStatusPageMore | kNodeStatusPageArmed;
  header.count = 3;
  header.next_after = 700;
  header.event_seq = 42;
  std::array<std::uint8_t, kGatewayInnerHeadSize + kNodeStatusPageMaxPayload + 8> buf{};
  std::size_t n = 0;
  CHECK_OK(encode_node_status_page(header, entries.data(), 3,
                                   MutableByteView{buf.data(), buf.size()}, n));
  CHECK(n == kGatewayInnerHeadSize + kNodeStatusPageFixed + 3 * kNodeStatusEntrySize);
  NodeStatusPageHeader h{};
  ByteView view{};
  CHECK_OK(decode_node_status_page(ByteView{buf.data(), n}, h, view));
  CHECK(h.count == 3 && h.flags == 3 && h.next_after == 700 && h.event_seq == 42);
  CHECK(view.size == 3 * kNodeStatusEntrySize);
  for (std::size_t i = 0; i < 3; ++i) {
    NodeStatus e{};
    CHECK_OK(decode_node_status_entry(
        ByteView{view.data + i * kNodeStatusEntrySize, kNodeStatusEntrySize}, e));
    CHECK(same(e, entries[i]));
  }
  // Exact entry layout (28 B, big-endian, signed fields two's complement).
  const std::array<std::uint8_t, 28> entry5{{0, 0, 0, 0, 0, 0, 0, 5, 0x3f, 0xb9, 0xb9, 0xb0,
                                             0, 3, 0, 3, 0, 0, 0, 0, 0, 0, 0, 5,
                                             0, 0, 0x04, 0xd2}};
  CHECK(std::memcmp(view.data, entry5.data(), entry5.size()) == 0);

  // Encoder refusals: unordered, count mismatch, entries on a failure.
  std::array<NodeStatus, 2> unordered{{sample_entry(9, true), sample_entry(5, true)}};
  NodeStatusPageHeader h2 = header;
  h2.count = 2;
  CHECK(!encode_node_status_page(h2, unordered.data(), 2,
                                 MutableByteView{buf.data(), buf.size()}, n).ok());
  CHECK(!encode_node_status_page(header, entries.data(), 2,
                                 MutableByteView{buf.data(), buf.size()}, n).ok());
  NodeStatusPageHeader failed{};
  failed.result = static_cast<std::uint16_t>(ConfigOpsResult::Unsupported);
  failed.count = 1;
  CHECK(!encode_node_status_page(failed, entries.data(), 1,
                                 MutableByteView{buf.data(), buf.size()}, n).ok());
  failed.count = 0;
  CHECK_OK(encode_node_status_page(failed, nullptr, 0,
                                   MutableByteView{buf.data(), buf.size()}, n));
  CHECK(n == kGatewayInnerHeadSize + kNodeStatusPageFixed);
  CHECK_OK(decode_node_status_page(ByteView{buf.data(), n}, h, view));
  CHECK(h.result == static_cast<std::uint16_t>(ConfigOpsResult::Unsupported));

  // Decoder refusals on a valid page mutated in place.
  CHECK_OK(encode_node_status_page(header, entries.data(), 3,
                                   MutableByteView{buf.data(), buf.size()}, n));
  auto rejects = [&](std::size_t offset, std::uint8_t value) {
    std::vector<std::uint8_t> bad(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
    bad[offset] = value;
    NodeStatusPageHeader hh{};
    ByteView vv{};
    return !decode_node_status_page(ByteView{bad.data(), bad.size()}, hh, vv).ok();
  };
  const std::size_t e0 = kGatewayInnerHeadSize + kNodeStatusPageFixed;
  CHECK(rejects(6, 0x04));             // unknown page flag
  CHECK(rejects(7, 2));                // count vs length
  CHECK(rejects(15, 0x01));            // next_after != last entry
  CHECK(rejects(e0 + 8, 0x80 | 0x3f)); // reserved entry flag bit
  CHECK(rejects(e0 + 7, 0));           // node id 0
  CHECK(rejects(e0 + 7, 9));           // duplicate id -> not strictly ascending
  CHECK(rejects(e0 + 23, 0));          // reachable entry without next hop
  CHECK(rejects(5, 99));               // result outside the ConfigOpsResult set
  std::vector<std::uint8_t> trailing(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(n));
  trailing.push_back(0);
  NodeStatusPageHeader hh{};
  ByteView vv{};
  CHECK(!decode_node_status_page(ByteView{trailing.data(), trailing.size()}, hh, vv).ok());

  // Events.
  NodeEvent event{};
  event.sequence = 7;
  event.kind = NodeEventKind::RouteDown;
  event.status = sample_entry(9, false);
  std::array<std::uint8_t, kGatewayInnerHeadSize + kNodeEventPayload> ebuf{};
  CHECK_OK(encode_node_event(event, MutableByteView{ebuf.data(), ebuf.size()}, n));
  CHECK(n == ebuf.size());
  CHECK(ebuf[0] == 1 && ebuf[1] == 0x42 && ebuf[3] == kNodeEventPayload);
  NodeEvent back{};
  CHECK_OK(decode_node_event(ByteView{ebuf.data(), n}, back));
  CHECK(back.sequence == 7 && back.kind == NodeEventKind::RouteDown && same(back.status, event.status));
  auto event_rejects = [&](std::size_t offset, std::uint8_t value) {
    auto bad = ebuf;
    bad[offset] = value;
    NodeEvent out{};
    return !decode_node_event(ByteView{bad.data(), bad.size()}, out).ok();
  };
  CHECK(event_rejects(8, 0));   // kind 0
  CHECK(event_rejects(8, 6));   // kind past RouteChanged
  CHECK(event_rejects(9, 1));   // reserved byte
  CHECK(event_rejects(7, 0));   // sequence 0 (7 -> 0)
  NodeEvent zero = event;
  zero.sequence = 0;
  CHECK(!encode_node_event(zero, MutableByteView{ebuf.data(), ebuf.size()}, n).ok());
}

}  // namespace

int main() {
  test_snapshot_line_topology();
  test_snapshot_pagination();
  test_monitor_diff();
  test_monitor_backpressure();
  test_monitor_with_mesh();
  test_codec_query();
  test_codec_page_and_event();
  if (failures != 0) {
    std::fprintf(stderr, "%d node status checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom node status tests passed");
  return 0;
}
