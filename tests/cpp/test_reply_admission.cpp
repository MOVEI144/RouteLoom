// ExpectedReply admission enforcement (issue #117, design-q116 §7-§8): the
// MeshNode side of the reply-lease contract against a simulated Owner port.
// A transit/terminal admission reserves one 1500 ms transaction plus one
// lease use before any ACK/forward/dispatch becomes visible; the transaction
// bounds local work (never the wire budget); callback re-entry is Busy with
// zero state change; component payloads wait for the Owner's outside drive.
//
// Q117-05/07/08/11/12/14 exercise the node integration.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <map>
#include <memory>
#include <vector>

#include "routeloom/node.hpp"
#include "routeloom/reply_peer_leases.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "test_security.hpp"
#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                      \
  do {                                                                   \
    if (!(expr)) {                                                       \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, \
                   #expr);                                               \
      ++failures;                                                        \
    }                                                                    \
  } while (false)

using namespace routeloom;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimReplyPort;
using routeloom_test::SimWorld;
using routeloom_test::TestSecurity;

constexpr NetworkId kNet = 7;
const std::uint8_t kPayload[] = "reply-admission";

ByteView payload_view() { return ByteView{kPayload, sizeof(kPayload) - 1}; }

wire::Header mk_header(FrameType type, NodeId origin, NodeId destination,
                       NodeId previous, NodeId next, MessageId message,
                       std::uint8_t flags = 0, std::uint8_t round = 0,
                       std::uint32_t deadline_ms = 5000) {
  wire::Header h{};
  h.type = type;
  h.flags = flags;
  h.delivery = DeliveryClass::Reliable;
  h.delivery_round = round;
  h.hop_remaining = 10;
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
  const Status status = wire::encode_new(plain, cipher, out);
  if (!status.ok()) {
    std::fprintf(stderr, "craft_frame failed: %s\n", status.detail);
    ++failures;
  }
  return out;
}

wire::EncodedFrame craft_transit(TestSecurity& cipher, NodeId prev, NodeId relay,
                                 NodeId origin, NodeId destination,
                                 std::uint64_t seq,
                                 std::uint32_t deadline_ms = 5000) {
  return craft_frame(cipher,
                     mk_header(FrameType::Data, origin, destination, prev, relay,
                               MessageId{42, seq}, wire::kFlagEndProtected, 0,
                               deadline_ms),
                     payload_view());
}

// Routed transit never parses the sealed payload before the admission
// probes, so an opaque body exercises the batch-reservation refusal.
wire::EncodedFrame craft_routed_transit(TestSecurity& cipher, NodeId prev,
                                        NodeId relay, NodeId origin,
                                        NodeId destination, std::uint64_t seq) {
  return craft_frame(cipher,
                     mk_header(FrameType::Service, origin, destination, prev,
                               relay, MessageId{43, seq},
                               wire::kFlagEndProtected),
                     payload_view());
}

wire::EncodedFrame craft_receipt_transit(TestSecurity& cipher, NodeId prev,
                                         NodeId relay, NodeId origin,
                                         NodeId destination,
                                         std::uint64_t seq) {
  return craft_frame(cipher,
                     mk_header(FrameType::EndReceipt, origin, destination, prev,
                               relay, MessageId{44, seq},
                               wire::kFlagEndProtected),
                     payload_view());
}

// Manual harness: per-node Owner ports plus V2 injection carrying the
// receiver's binding snapshot — the RX evidence the real runtime captures.
struct Harness {
  SimNetwork net;
  TestSecurity cipher;
  std::map<NodeId, std::unique_ptr<TestSecurity>> sec;
  std::map<NodeId, std::unique_ptr<CapturingObserver>> obs;
  std::map<NodeId, std::unique_ptr<SimRadio>> radio;
  std::map<NodeId, std::unique_ptr<SimReplyPort>> ports;
  std::map<NodeId, std::unique_ptr<MeshNode>> node;
  MonotonicMs now{0};

  MeshNode* add(NodeId id) {
    NodeConfig cfg{};
    cfg.network = kNet;
    cfg.node = id;
    cfg.message_session = 100 + static_cast<std::uint32_t>(id);
    cfg.route_generation = 1;
    cfg.link_epoch = 1;
    cfg.end_epoch = 1;
    cfg.route_advertisement_period_ms = 30000;
    cfg.route_lifetime_ms = 60000;
    cfg.hop_accept_timeout_ms = 60;
    cfg.max_link_attempts = 2;
    cfg.max_end_to_end_rounds = 3;
    sec[id] = std::make_unique<TestSecurity>();
    obs[id] = std::make_unique<CapturingObserver>();
    radio[id] = std::make_unique<SimRadio>(net, id);
    ports[id] = std::make_unique<SimReplyPort>(*radio[id], id, cfg.link_epoch);
    node[id] =
        std::make_unique<MeshNode>(cfg, *radio[id], *sec[id], *obs[id]);
    node[id]->set_reply_peer_port(ports[id].get());
    net.register_node(id, node[id].get());
    net.register_reply_port(id, ports[id].get());
    (void)node[id]->start(now);
    return node[id].get();
  }
  MeshNode* at(NodeId id) const { return node.at(id).get(); }
  SimReplyPort* port(NodeId id) const { return ports.at(id).get(); }
  CapturingObserver* observer(NodeId id) const { return obs.at(id).get(); }
  void link(NodeId a, NodeId b) {
    net.connect(a, b);
    (void)node[a]->add_neighbor(b, 1, now);
    (void)node[b]->add_neighbor(a, 1, now);
  }
  void poll_all() {
    for (auto& [id, n] : node) n->poll(now);
  }
  void run(MonotonicMs duration_ms, MonotonicMs step = 5) {
    const MonotonicMs end = now + duration_ms;
    for (; now <= end; now += step) {
      poll_all();
      net.flush(now);
    }
  }
};

void inject_v2(Harness& h, NodeId receiver, NodeId peer,
               const wire::EncodedFrame& frame) {
  RadioRxMetadataV2 meta{};
  meta.rssi_dbm = -60;
  meta.rssi_valid = true;
  meta.provenance = ObservationProvenance::InjectedTest;
  ReplyBinding binding{};
  if (h.port(receiver)->snapshot_binding(peer, binding).ok()) {
    meta.binding = binding.id;
    meta.binding_generation = binding.generation;
  }
  h.at(receiver)->on_radio_receive(peer, frame.view(), meta, h.now);
}

// block_send is a plain function pointer: the recording hook stages through
// a file-local buffer.
std::vector<std::uint8_t>& held_frame() {
  static std::vector<std::uint8_t> held;
  return held;
}

bool record_and_hold_relay_data(NodeId from, NodeId to, ByteView frame) {
  if (from == 2 && to == 3 && frame.size > 4 &&
      frame.data[4] == static_cast<std::uint8_t>(FrameType::Data) &&
      held_frame().empty()) {
    held_frame().assign(frame.data, frame.data + frame.size);
    return true;
  }
  return false;
}

std::uint32_t read_u32_be(const std::uint8_t* data) {
  return (static_cast<std::uint32_t>(data[0]) << 24) |
         (static_cast<std::uint32_t>(data[1]) << 16) |
         (static_cast<std::uint32_t>(data[2]) << 8) |
         static_cast<std::uint32_t>(data[3]);
}

std::size_t count_sights(const SimNetwork& net, FrameType type, NodeId from,
                         NodeId to) {
  std::size_t count = 0;
  for (const auto& sight : net.sights) {
    if (sight.type == type && sight.from == from && sight.to == to) ++count;
  }
  return count;
}

// Minimal Service sink: counts payloads/completions without parsing or
// calling back into the node — the Owner-side drive is what is tested.
class CountingServiceSink final : public GatewayServiceSink {
 public:
  void on_service_payload(NodeId, const wire::PlainFrame&,
                          MonotonicMs) noexcept override {
    ++payloads;
  }
  void on_service_job_done(const MessageId&, bool hop_accepted, const char*,
                           MonotonicMs) noexcept override {
    hop_accepted ? ++done_accepted : ++done_failed;
  }
  void poll(MonotonicMs) noexcept override {}
  std::size_t payloads{0};
  std::size_t done_accepted{0};
  std::size_t done_failed{0};
};

// Delegating Owner port: proves the node depends only on the ReplyPeerPort
// interface (Q117-13) — identical behavior behind a counting wrapper.
class CountingPort final : public ReplyPeerPort {
 public:
  explicit CountingPort(SimReplyPort& inner) noexcept : inner_(inner) {}
  Status acquire(ReplyBinding captured, MonotonicMs deadline, MonotonicMs now,
                 ReplyLeaseToken& out) noexcept override {
    ++acquires;
    return inner_.acquire(captured, deadline, now, out);
  }
  Status release(ReplyLeaseToken token) noexcept override {
    ++releases;
    return inner_.release(token);
  }
  Status validate(ReplyLeaseToken token,
                  MonotonicMs now) noexcept override {
    ++validations;
    return inner_.validate(token, now);
  }
  Status send_reply(ReplyLeaseToken token, std::uint64_t tx_token,
                    ByteView frame, MonotonicMs now) noexcept override {
    return inner_.send_reply(token, tx_token, frame, now);
  }
  Status snapshot_binding(NodeId peer,
                          ReplyBinding& out) noexcept override {
    return inner_.snapshot_binding(peer, out);
  }
  Status send_bound(ReplyBinding binding, std::uint64_t tx_token,
                    ByteView frame) noexcept override {
    return inner_.send_bound(binding, tx_token, frame);
  }
  std::size_t acquires{0};
  std::size_t validations{0};
  std::size_t releases{0};

 private:
  SimReplyPort& inner_;
};

// Q117-05: a held transit forward dies with its 1500 ms transaction even
// though the frame budget (5000 ms) is unspent — and the lease is released.
void test_forward_bounded_by_transaction_lifetime() {
  SimWorld w;
  (void)w.add(1);
  MeshNode* relay = w.add(2);
  (void)w.add(3);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.run(500);  // converge routes
  // Hold the relay->destination DATA leg: the forward stays queued, the
  // HOP_ACCEPT still flows, so the transaction alone bounds the work.
  w.net.block_send = [](NodeId from, NodeId to, ByteView frame) {
    return from == 2 && to == 3 && frame.size > 4 &&
           frame.data[4] == static_cast<std::uint8_t>(FrameType::Data);
  };
  // BestEffort at the origin: no end-to-end retry rounds, so exactly one
  // transit admission exists and the transaction alone bounds it.
  SendOptions options{};
  options.delivery = DeliveryClass::BestEffort;
  options.lifetime_ms = 5000;
  MessageId id{};
  CHECK(w.at(1)->send(3, payload_view(), options, w.now, id).ok());
  w.run(50);
  CHECK(relay->transit_in_flight() == 1);
  SimReplyPort* port = w.net.reply_port(2);
  CHECK(port != nullptr);
  CHECK(port->leases().live_use_count() == 1);
  // Just inside the transaction: the work is still live.
  const MonotonicMs admitted_at = w.now;
  while (w.now < admitted_at + 1399) w.run(10);
  CHECK(relay->transit_in_flight() == 1);
  CHECK(port->leases().live_use_count() == 1);
  // Past 1500 ms: the forward is terminated and the lease released, long
  // before the frame's own 5000 ms budget expires.
  while (w.now < admitted_at + 1501) w.run(10);
  CHECK(relay->transit_in_flight() == 0);
  CHECK(port->leases().live_use_count() == 0);
}

// Q117-05 (wire-budget pin): the 1500 ms transaction clamps local work only.
// A forward dispatched in time still carries (almost) the full frame budget.
void test_wire_budget_survives_transaction_clamp() {
  SimWorld w;
  (void)w.add(1);
  (void)w.add(2);
  (void)w.add(3);
  w.start_all();
  w.link(1, 2, 1, 1);
  w.link(2, 3, 1, 1);
  w.run(500);
  held_frame().clear();
  w.net.block_send = &record_and_hold_relay_data;
  SendOptions options{};
  options.delivery = DeliveryClass::Reliable;
  options.lifetime_ms = 5000;
  MessageId id{};
  CHECK(w.at(1)->send(3, payload_view(), options, w.now, id).ok());
  w.run(100);
  CHECK(!held_frame().empty());
  CHECK(held_frame().size() >= 64);
  if (held_frame().size() < 64) return;
  // Offset 60: remaining_deadline_ms (u32 BE). Dwell debits tens of ms at
  // most — a 1500 ms clamp leaking into the wire budget would read ~1400.
  const std::uint32_t remaining = read_u32_be(held_frame().data() + 60);
  CHECK(remaining > 4000);
}

// Q117-11: a send() issued from inside an observer callback is Busy and
// queues nothing.
struct ReentrantSendObserver final : NodeObserver {
  MeshNode* node{nullptr};
  Status send_status{Status::success()};
  std::size_t free_before{0};
  std::size_t free_after{0};
  std::size_t messages{0};
  void on_message(const MessageKey&, NodeId, ByteView) noexcept override {
    ++messages;
    free_before = node->tx_free_slots();
    SendOptions options{};
    MessageId id{};
    send_status = node->send(9, payload_view(), options, 0, id);
    free_after = node->tx_free_slots();
  }
  void on_delivery(const DeliveryResult&) noexcept override {}
  void on_diagnostic(const char*, NodeId, const MessageId*) noexcept override {}
};

void test_reentrant_send_is_busy() {
  SimNetwork net;
  TestSecurity cipher;
  TestSecurity sec;
  SimRadio radio(net, 2);
  SimReplyPort port(radio, 2, 1);
  ReentrantSendObserver observer;
  NodeConfig cfg{};
  cfg.network = kNet;
  cfg.node = 2;
  cfg.message_session = 102;
  cfg.route_generation = 1;
  cfg.link_epoch = 1;
  cfg.end_epoch = 1;
  MeshNode node(cfg, radio, sec, observer);
  observer.node = &node;
  node.set_reply_peer_port(&port);
  net.register_node(2, &node);
  CHECK(node.start(0).ok());
  (void)node.add_neighbor(1, 1, 0);
  (void)node.add_neighbor(9, 1, 0);  // the re-entrant send has a route
  const wire::EncodedFrame terminal = craft_frame(
      cipher, mk_header(FrameType::Data, 1, 2, 1, 2, MessageId{42, 7},
                        wire::kFlagEndProtected),
      payload_view());
  RadioRxMetadataV2 meta{};
  meta.rssi_valid = true;
  meta.provenance = ObservationProvenance::InjectedTest;
  ReplyBinding binding{};
  CHECK(port.snapshot_binding(1, binding).ok());
  meta.binding = binding.id;
  meta.binding_generation = binding.generation;
  node.on_radio_receive(1, terminal.view(), meta, 0);
  CHECK(observer.messages == 1);
  CHECK(observer.send_status.code == StatusCode::Busy);
  CHECK(observer.free_after == observer.free_before);
}

// Q117-11: a nested on_radio_receive from inside an observer callback is
// Busy and dispatches nothing.
struct ReentrantReceiveObserver final : NodeObserver {
  MeshNode* node{nullptr};
  const wire::EncodedFrame* nested{nullptr};
  RadioRxMetadataV2 nested_meta{};
  std::size_t messages{0};
  void on_message(const MessageKey&, NodeId, ByteView) noexcept override {
    ++messages;
    if (messages == 1 && nested != nullptr) {
      node->on_radio_receive(1, nested->view(), nested_meta, 0);
    }
  }
  void on_delivery(const DeliveryResult&) noexcept override {}
  void on_diagnostic(const char*, NodeId, const MessageId*) noexcept override {}
};

void test_reentrant_receive_is_busy() {
  SimNetwork net;
  TestSecurity cipher;
  TestSecurity sec;
  SimRadio radio(net, 2);
  SimReplyPort port(radio, 2, 1);
  ReentrantReceiveObserver observer;
  NodeConfig cfg{};
  cfg.network = kNet;
  cfg.node = 2;
  cfg.message_session = 102;
  cfg.route_generation = 1;
  cfg.link_epoch = 1;
  cfg.end_epoch = 1;
  MeshNode node(cfg, radio, sec, observer);
  observer.node = &node;
  node.set_reply_peer_port(&port);
  net.register_node(2, &node);
  CHECK(node.start(0).ok());
  (void)node.add_neighbor(1, 1, 0);
  const wire::EncodedFrame first = craft_frame(
      cipher, mk_header(FrameType::Data, 1, 2, 1, 2, MessageId{42, 7},
                        wire::kFlagEndProtected),
      payload_view());
  const wire::EncodedFrame second = craft_frame(
      cipher, mk_header(FrameType::Data, 1, 2, 1, 2, MessageId{42, 8},
                        wire::kFlagEndProtected),
      payload_view());
  RadioRxMetadataV2 meta{};
  meta.rssi_valid = true;
  meta.provenance = ObservationProvenance::InjectedTest;
  ReplyBinding binding{};
  CHECK(port.snapshot_binding(1, binding).ok());
  meta.binding = binding.id;
  meta.binding_generation = binding.generation;
  observer.nested = &second;
  observer.nested_meta = meta;
  node.on_radio_receive(1, first.view(), meta, 0);
  CHECK(observer.messages == 1);
}

// Q117-01/07: with three bindings pinned by held transit, a fourth upstream
// is refused with zero partial effect — no forward, no dedup record.
void test_fourth_binding_refused_without_side_effects() {
  Harness h;
  (void)h.add(1);
  MeshNode* relay = h.add(2);
  (void)h.add(3);
  h.link(1, 2);
  h.link(2, 3);
  h.run(50);  // converge routes
  h.net.block_send = [](NodeId from, NodeId, ByteView frame) {
    return from == 2 && frame.size > 4 &&
           frame.data[4] == static_cast<std::uint8_t>(FrameType::Data);
  };
  const DedupStats dedup_before = relay->dedup_stats();
  for (std::uint64_t i = 0; i < 3; ++i) {
    const NodeId upstream = static_cast<NodeId>(10 + i);
    inject_v2(h, 2, upstream,
              craft_transit(h.cipher, upstream, 2, 100 + i, 3, 500 + i));
    h.run(5);
  }
  CHECK(relay->transit_in_flight() == 3);
  CHECK(h.port(2)->leases().live_entry_count() == 3);
  CHECK(relay->dedup_stats().admitted_transit ==
        dedup_before.admitted_transit + 3);
  const std::uint64_t busy_dropped_before =
      relay->congestion_stats().busy_send_failed;
  inject_v2(h, 2, 11,
            craft_transit(h.cipher, 11, 2, 200, 3, 600));
  h.run(5);
  // Same-binding sharing also holds: upstream 11's second transaction shares
  // its entry instead of spending a fourth one.
  CHECK(relay->transit_in_flight() == 4);
  CHECK(h.port(2)->leases().live_entry_count() == 3);
  inject_v2(h, 2, 13,
            craft_transit(h.cipher, 13, 2, 201, 3, 601));
  h.run(5);
  CHECK(relay->transit_in_flight() == 4);
  CHECK(h.port(2)->leases().live_entry_count() == 3);
  CHECK(relay->dedup_stats().admitted_transit ==
        dedup_before.admitted_transit + 4);
  CHECK(relay->dedup_stats().evicted_resolved == 0);
  // The refusal is counted where an unsent BUSY lands when no reply slot is
  // affordable — and nothing was queued for the refused upstream.
  CHECK(relay->congestion_stats().busy_send_failed == busy_dropped_before + 1);
  // Q117-07/10: the failed batch left no transaction, no event, no queue.
  CHECK(relay->txn_in_flight() == 4);
  CHECK(relay->component_events_pending() == 0);
}

// Q117-08: with the 8-deep control lane full, DATA / routed / END_RECEIPT
// transit all refuse — zero forwards on any lane.
void test_control_lane_full_refuses_all_forwards() {
  Harness h;
  (void)h.add(1);
  MeshNode* relay = h.add(2);
  (void)h.add(3);
  (void)h.add(4);
  h.link(1, 2);
  h.link(2, 3);
  h.link(2, 4);
  h.run(50);  // converge routes
  // 8 undispatched transit admissions fill the control lane exactly.
  for (std::uint64_t i = 1; i <= 8; ++i) {
    inject_v2(h, 2, 1, craft_transit(h.cipher, 1, 2, 100 + i, 4, i));
  }
  CHECK(relay->dedup_stats().admitted_transit == 8);
  CHECK(relay->txn_in_flight() == 8);
  // Each lane's probe refuses; nothing is admitted, leased, or queued.
  inject_v2(h, 2, 1, craft_transit(h.cipher, 1, 2, 200, 4, 100));
  inject_v2(h, 2, 1, craft_routed_transit(h.cipher, 1, 2, 201, 4, 101));
  inject_v2(h, 2, 3, craft_receipt_transit(h.cipher, 3, 2, 3, 1, 102));
  CHECK(relay->dedup_stats().admitted_transit == 8);
  CHECK(relay->txn_in_flight() == 8);
  CHECK(h.observer(2)->has_diag("RECEIPT_TRANSIT_DENIED"));
  // Drain everything admitted: exactly the 8 fills forward, never a probe.
  h.run(500);
  CHECK(count_sights(h.net, FrameType::Data, 2, 4) == 8);
  CHECK(count_sights(h.net, FrameType::Service, 2, 4) == 0);
  CHECK(count_sights(h.net, FrameType::EndReceipt, 2, 1) == 0);
}

// Q117-08 (reverse): when the data budget is spent but the control lane is
// free, a refused probe queues no lone HOP_ACCEPT.
void test_data_bound_leaves_no_lone_ack() {
  Harness h;
  (void)h.add(1);
  MeshNode* relay = h.add(2);
  (void)h.add(4);  // never polled: forwards park, transactions stay live
  h.link(1, 2);
  h.link(2, 4);
  h.run(50);
  for (std::uint64_t i = 1; i <= 8; ++i) {
    inject_v2(h, 2, 1, craft_transit(h.cipher, 1, 2, 100 + i, 4, i));
    h.at(2)->poll(h.now);
    h.net.flush(h.now);  // accept drains; the forward parks downstream-less
    h.now += 5;
  }
  CHECK(relay->txn_in_flight() == 8);
  CHECK(relay->congestion_stats().control_queued == 0);
  inject_v2(h, 2, 1, craft_transit(h.cipher, 1, 2, 200, 4, 100));
  CHECK(relay->dedup_stats().admitted_transit == 8);
  CHECK(relay->txn_in_flight() == 8);
  CHECK(relay->congestion_stats().control_queued == 0);  // no lone ACK
  CHECK(h.observer(2)->has_diag("TRANSIT_ADMISSION_DENIED"));
}

// Q117-12: 8 outstanding component jobs close the payload-event window — a
// routed-terminal probe rolls back before spending transaction, lease,
// lane, or dedup — and the window reopens once the jobs complete.
void test_component_backpressure_rolls_back_routed() {
  Harness h;
  (void)h.add(1);
  MeshNode* relay = h.add(2);
  (void)h.add(4);
  h.link(1, 2);
  h.link(2, 4);
  h.run(50);
  CountingServiceSink sink;
  CHECK(relay->set_gateway_sink(&sink).ok());
  // 8 origin Service jobs hold all 8 completion slots without spending a
  // transaction (no polls yet, so nothing completes or publishes).
  for (int i = 0; i < 8; ++i) {
    MessageId id{};
    CHECK(relay->send_service(4, payload_view(), 5000, h.now, id).ok());
  }
  const DedupStats dedup_before = relay->dedup_stats();
  // Routed terminal to self: refused by the event probe alone — leases,
  // transactions, and the control lane all stand free.
  wire::Header header =
      mk_header(FrameType::Service, 1, 2, 1, 2, MessageId{43, 1},
                wire::kFlagEndProtected);
  inject_v2(h, 2, 1, craft_frame(h.cipher, header, payload_view()));
  CHECK(relay->dedup_stats().admitted_transit == dedup_before.admitted_transit);
  CHECK(relay->txn_in_flight() == 0);
  CHECK(relay->component_events_pending() == 0);
  CHECK(h.observer(2)->has_diag("ROUTED_NO_ACK_SLOT"));
  CHECK(sink.payloads == 0);
  // Drain: all 8 jobs complete (completions flow through the Owner pump),
  // the window reopens, and the same probe is admitted and delivered.
  h.run(500);
  CHECK(sink.done_accepted == 8);
  CHECK(relay->component_events_pending() == 0);
  inject_v2(h, 2, 1, craft_frame(h.cipher, header, payload_view()));
  h.run(50);
  CHECK(relay->dedup_stats().admitted_transit == dedup_before.admitted_transit + 1);
  CHECK(sink.payloads == 1);
}

// Q117-14: saturation is a counted drop, never a wedge — once downstream
// accepts free the budget, the sender's retry is admitted and delivered.
void test_saturation_drop_recovers_on_retry() {
  Harness h;
  (void)h.add(1);
  MeshNode* relay = h.add(2);
  MeshNode* downstream = h.add(4);
  h.link(1, 2);
  h.link(2, 4);
  h.run(50);
  for (std::uint64_t i = 1; i <= 8; ++i) {
    inject_v2(h, 2, 1, craft_transit(h.cipher, 1, 2, 100 + i, 4, i));
    h.at(2)->poll(h.now);
    h.net.flush(h.now);
    h.now += 5;
  }
  CHECK(relay->txn_in_flight() == 8);
  const auto failed_before = relay->congestion_stats().busy_send_failed;
  const auto probe = craft_transit(h.cipher, 1, 2, 200, 4, 100);
  inject_v2(h, 2, 1, probe);
  CHECK(h.observer(2)->has_diag("TRANSIT_ADMISSION_DENIED"));
  CHECK(relay->congestion_stats().busy_sent == 0);
  CHECK(relay->congestion_stats().busy_send_failed == failed_before + 1);
  // Downstream answers: every parked forward resolves and frees its slot.
  for (int i = 0; i < 20 && relay->txn_in_flight() != 0; ++i) {
    downstream->poll(h.now);
    h.net.flush(h.now);
    h.at(2)->poll(h.now);
    h.net.flush(h.now);
    h.now += 5;
  }
  CHECK(relay->txn_in_flight() == 0);
  // The retry (same bytes) is admitted and forwarded exactly once more.
  const std::size_t data_before = count_sights(h.net, FrameType::Data, 2, 4);
  inject_v2(h, 2, 1, probe);
  h.run(200);
  CHECK(relay->dedup_stats().admitted_transit == 9);
  CHECK(count_sights(h.net, FrameType::Data, 2, 4) == data_before + 1);
  CHECK(h.observer(4)->messages.size() == 9);
}

// Q117-13: the same scripted exchange behind a delegating Owner port admits,
// forwards, and resolves identically — the node depends on the port
// interface alone.
void test_owner_swap_identical_outcome() {
  struct Outcome {
    std::uint64_t admitted;
    std::size_t data_sights;
    std::size_t accept_sights;
    std::size_t delivered;
  };
  const auto scenario = [](bool wrap) {
    Harness h;
    (void)h.add(1);
    MeshNode* relay = h.add(2);
    (void)h.add(4);
    h.link(1, 2);
    h.link(2, 4);
    h.run(50);
    CountingPort* wrapper = nullptr;
    CountingPort owned(*h.port(2));
    if (wrap) {
      wrapper = &owned;
      CHECK(relay->set_reply_peer_port(wrapper).ok());
    }
    for (std::uint64_t i = 1; i <= 3; ++i) {
      inject_v2(h, 2, 1, craft_transit(h.cipher, 1, 2, 100 + i, 4, i));
      h.run(60);
    }
    Outcome out{relay->dedup_stats().admitted_transit,
                count_sights(h.net, FrameType::Data, 2, 4),
                count_sights(h.net, FrameType::HopAccept, 2, 1),
                h.observer(4)->messages.size()};
    if (wrap) {
      CHECK(wrapper->acquires == 3);
      CHECK(wrapper->releases == 3);
    }
    return out;
  };
  const Outcome plain = scenario(false);
  const Outcome wrapped = scenario(true);
  CHECK(plain.admitted == 3 && wrapped.admitted == 3);
  CHECK(plain.data_sights == wrapped.data_sights);
  CHECK(plain.accept_sights == wrapped.accept_sights);
  CHECK(plain.delivered == wrapped.delivered);
}

// Q117-06: a retired peer's mapping refuses bound traffic — the Service job
// never reaches the air and its failure is reported through the completion
// event, while a healthy peer's job still delivers.
void test_send_to_retired_peer_reports_failure() {
  Harness h;
  (void)h.add(1);
  MeshNode* relay = h.add(2);
  (void)h.add(3);
  (void)h.add(4);
  h.link(1, 2);
  h.link(2, 3);
  h.link(2, 4);
  h.run(50);
  CountingServiceSink sink;
  CHECK(relay->set_gateway_sink(&sink).ok());
  // Retire peer 3's driver record after the link lived: the mapping the
  // job would snapshot is gone.
  h.port(2)->retire_peer(3);
  MessageId stale_id{};
  CHECK(relay->send_service(3, payload_view(), 5000, h.now, stale_id).ok());
  MessageId healthy_id{};
  CHECK(relay->send_service(4, payload_view(), 5000, h.now, healthy_id).ok());
  h.run(1000);  // attempts exhaust on the retired mapping, delivery on 4
  CHECK(count_sights(h.net, FrameType::Service, 2, 3) == 0);
  CHECK(count_sights(h.net, FrameType::Service, 2, 4) >= 1);
  CHECK(sink.done_failed == 1);
  CHECK(sink.done_accepted == 1);
}

}  // namespace

int main() {
  test_forward_bounded_by_transaction_lifetime();
  test_wire_budget_survives_transaction_clamp();
  test_reentrant_send_is_busy();
  test_reentrant_receive_is_busy();
  test_fourth_binding_refused_without_side_effects();
  test_control_lane_full_refuses_all_forwards();
  test_data_bound_leaves_no_lone_ack();
  test_component_backpressure_rolls_back_routed();
  test_saturation_drop_recovers_on_retry();
  test_owner_swap_identical_outcome();
  test_send_to_retired_peer_reports_failure();
  if (failures != 0) {
    std::fprintf(stderr, "FAIL: %d checks failed\n", failures);
    return 1;
  }
  std::puts("PASS: test_reply_admission");
  return 0;
}
