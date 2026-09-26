// Bench application module tests (design-devflow.md §5): wire codec rejects
// and bounds, then the portable BenchApp driven through real MeshNode
// instances on the in-memory SimNetwork — echo, counters, rollcall, STATUS
// pages, bounded peer-send runs, constrained faults, and the reset rules
// (a replayed command after reset must not restart anything).

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <deque>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "routeloom/admission.hpp"
#include "routeloom/bench/app.hpp"
#include "routeloom/bench/protocol.hpp"
#include "routeloom/group.hpp"
#include "routeloom/node.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/types.hpp"

#include "test_sim.hpp"

namespace {

int failures = 0;
#define CHECK(expr)                                                        \
  do {                                                                     \
    if (!(expr)) {                                                         \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__, __LINE__, \
                   #expr);                                                 \
      ++failures;                                                          \
    }                                                                      \
  } while (false)
#define CHECK_OK(expr)                                                     \
  do {                                                                     \
    const auto _status = (expr);                                           \
    if (!_status.ok()) {                                                   \
      std::fprintf(stderr, "STATUS failed %s:%d: %s (%s)\n", __FILE__,     \
                   __LINE__, #expr, _status.detail);                       \
      ++failures;                                                          \
    }                                                                      \
  } while (false)

using namespace routeloom;
using namespace routeloom::bench;
using routeloom_test::CapturingObserver;
using routeloom_test::SimNetwork;
using routeloom_test::SimRadio;
using routeloom_test::SimReplyPort;
using routeloom_test::TestSecurity;

// The whole app state must stay inside the 2 KiB per-chip gate (§5.4).
static_assert(sizeof(BenchApp) <= 2048, "bench app exceeds the 2 KiB budget");

constexpr std::uint32_t kFastPeriodMs = 500;
constexpr std::uint32_t kFastLifetimeMs = 9000;
static_assert(scoped_lifetime_sufficient(kFastPeriodMs, kFastLifetimeMs,
                                         kScopedDefaultRefreshTicks),
              "fast test timers satisfy the scoped lease rule");

RunUuid make_run(std::uint8_t tag) {
  RunUuid run{};
  run[0] = 0x52;  // 'R'
  run[1] = 0x55;  // 'U'
  run[15] = tag;
  return run;
}

// ---------------------------------------------------------------------------
// Fakes + world
// ---------------------------------------------------------------------------

struct FakePlatform final : BenchPlatform {
  std::uint32_t heap_free{100000};
  std::uint32_t heap_min{90000};
  std::uint32_t heap_largest{60000};
  std::uint32_t stack_hwm{4096};
  std::uint8_t cause{1};
  std::uint32_t restarts{0};
  std::uint32_t heap_free_bytes() const noexcept override { return heap_free; }
  std::uint32_t heap_min_free_bytes() const noexcept override { return heap_min; }
  std::uint32_t heap_largest_free_bytes() const noexcept override {
    return heap_largest;
  }
  std::uint32_t stack_high_water_bytes() const noexcept override {
    return stack_hwm;
  }
  std::uint8_t reset_cause() const noexcept override { return cause; }
  void restart() noexcept override { ++restarts; }
};

struct FakeProbe final : BenchProbe {
  BenchProbeSample fixed{};
  void sample(BenchProbeSample& out) noexcept override { out = fixed; }
};

struct HostMessage;  // decoded host-observed bench message (defined below)

// Mesh world: node 1 is the host/gateway (CapturingObserver); ids >= 2 run
// the BenchApp. Scoped profile (gateway 1) so group rollcall is exercised
// over the real tree path.
struct BenchWorld {
  SimNetwork net;
  MonotonicMs now{0};
  std::uint32_t link_epoch{1};
  std::uint32_t end_epoch{1};
  std::map<NodeId, std::unique_ptr<TestSecurity>> security;
  std::map<NodeId, std::unique_ptr<CapturingObserver>> host_obs;
  std::map<NodeId, std::unique_ptr<FakePlatform>> platforms;
  std::map<NodeId, std::unique_ptr<FakeProbe>> probes;
  std::map<NodeId, std::unique_ptr<SimRadio>> radios;
  std::map<NodeId, std::unique_ptr<SimReplyPort>> reply_ports;
  std::map<NodeId, std::unique_ptr<BenchApp>> apps;
  std::map<NodeId, std::unique_ptr<MeshNode>> nodes;
  std::map<NodeId, std::uint32_t> peer_link_epochs;
  std::map<NodeId, std::uint64_t> boots;
  std::set<std::pair<NodeId, NodeId>> adjacency;
  // host_messages() snapshots live here so decoded pointers stay valid for
  // the rest of the test — deque never invalidates on push_back.
  std::deque<std::vector<HostMessage>> held_messages;

  void configure(NodeConfig& config) const {
    config.route_gateways = {1, kInvalidNodeId};
    config.route_advertisement_period_ms = kFastPeriodMs;
    config.route_lifetime_ms = kFastLifetimeMs;
    config.route_refresh_ticks = kScopedDefaultRefreshTicks;
  }

  MeshNode* add(NodeId id, bool bench) {
    NodeConfig config{};
    config.network = 1;
    config.node = id;
    config.message_session = 100 + static_cast<std::uint32_t>(id);
    if (boots.count(id) == 0) {
      boots[id] = 0xB000 + static_cast<std::uint32_t>(id);
    }
    config.boot_incarnation = boots[id];
    config.route_generation = 1;
    config.link_epoch = link_epoch;
    config.end_epoch = end_epoch;
    configure(config);
    security[id] = std::make_unique<TestSecurity>();
    radios[id] = std::make_unique<SimRadio>(net, id);
    reply_ports[id] =
        std::make_unique<SimReplyPort>(*radios[id], id, config.link_epoch);
    for (const auto& [other, epoch] : peer_link_epochs) {
      reply_ports[id]->set_rx_context(other, epoch);
      reply_ports[other]->set_rx_context(id, config.link_epoch);
    }
    peer_link_epochs[id] = config.link_epoch;
    if (bench) {
      BenchConfig bc{};
      bc.firmware_digest = 0xC0FFEE01;
      bc.app_version = 1;
      apps[id] = std::make_unique<BenchApp>(bc);
      platforms[id] = std::make_unique<FakePlatform>();
      probes[id] = std::make_unique<FakeProbe>();
      probes[id]->fixed.site_valid = true;
      probes[id]->fixed.site_id = 0x51;
      apps[id]->set_platform(platforms[id].get());
      apps[id]->set_probe(probes[id].get());
      nodes[id] = std::make_unique<MeshNode>(config, *radios[id],
                                             *security[id], *apps[id]);
      apps[id]->attach(*nodes[id], now);
    } else {
      host_obs[id] = std::make_unique<CapturingObserver>();
      nodes[id] = std::make_unique<MeshNode>(config, *radios[id],
                                             *security[id], *host_obs[id]);
    }
    nodes[id]->set_reply_peer_port(reply_ports[id].get());
    net.register_node(id, nodes[id].get());
    net.register_reply_port(id, reply_ports[id].get());
    return nodes[id].get();
  }

  MeshNode* at(NodeId id) const { return nodes.at(id).get(); }
  BenchApp* app(NodeId id) const { return apps.at(id).get(); }
  CapturingObserver* obs(NodeId id) const { return host_obs.at(id).get(); }
  FakePlatform* platform(NodeId id) const { return platforms.at(id).get(); }
  std::uint64_t boot(NodeId id) const { return boots.at(id); }

  void link(NodeId a, NodeId b) {
    const auto key = std::make_pair(std::min(a, b), std::max(a, b));
    adjacency.insert(key);
    net.connect(a, b);
    CHECK_OK(at(a)->add_neighbor(b, 1, now));
    CHECK_OK(at(b)->add_neighbor(a, 1, now));
  }

  void start_all() {
    for (auto& [id, node] : nodes) {
      const Status s = node->start(now);
      if (!s.ok()) {
        std::fprintf(stderr, "node %llu start failed: %s\n",
                     static_cast<unsigned long long>(id), s.detail);
        ++failures;
      }
    }
  }

  void run(MonotonicMs duration_ms, MonotonicMs step = 5) {
    const MonotonicMs end = now + duration_ms;
    for (; now <= end; now += step) {
      for (auto& [id, node] : nodes) node->poll(now);
      for (auto& [id, app] : apps) {
        if (nodes.count(id) != 0) app->poll(now);
      }
      net.flush(now);
    }
  }

  // Reset a bench node: same neighbours and epochs (the wire re-join is a
  // separate ticket's concern), a fresh boot incarnation. What must not
  // survive is any application state.
  void reset_bench(NodeId id) {
    net.unregister_node(id);
    nodes.erase(id);   // before apps.erase: the node observes the app
    apps.erase(id);
    ++boots[id];
    add(id, true);
    const Status s = at(id)->start(now);
    if (!s.ok()) {
      std::fprintf(stderr, "node %llu restart failed: %s\n",
                   static_cast<unsigned long long>(id), s.detail);
      ++failures;
    }
    // Re-add neighbours only after the restarted node is running.
    for (const auto& [a, b] : adjacency) {
      if (a == id || b == id) {
        const NodeId other = a == id ? b : a;
        if (nodes.count(other) != 0) {
          (void)at(id)->add_neighbor(other, 1, now);
          (void)at(other)->add_neighbor(id, 1, now);
        }
      }
    }
  }
};

// ---------------------------------------------------------------------------
// Wire helpers
// ---------------------------------------------------------------------------

template <typename Body>
std::vector<std::uint8_t> body_bytes(const Body& body) {
  std::array<std::uint8_t, 128> buf{};
  ByteWriter writer{MutableByteView{buf.data(), buf.size()}};
  CHECK_OK(encode(body, writer));
  return {buf.data(), buf.data() + writer.size()};
}

bool bench_send(BenchWorld& w, NodeId to, std::uint8_t opcode,
                const RunUuid& run, std::uint32_t seq, ByteView body,
                std::uint16_t flags = 0, NodeId from = 1) {
  std::array<std::uint8_t, kMaxMessage> wire{};
  std::size_t written = 0;
  const Status status = encode(opcode, flags, run, seq, body,
                               MutableByteView{wire.data(), wire.size()},
                               written);
  if (!status) {
    std::fprintf(stderr, "bench_send encode failed: %s\n", status.detail);
    return false;
  }
  SendOptions options{};
  options.delivery = DeliveryClass::Reliable;
  options.lifetime_ms = 5000;
  MessageId id{};
  const Status sent = w.at(from)->send(to, ByteView{wire.data(), written},
                                       options, w.now, id);
  if (!sent) {
    std::fprintf(stderr, "bench_send send failed: %s\n", sent.detail);
  }
  return sent.ok();
}

// A decoded bench message with the body copied out — the observer's byte
// storage moves as it grows, so nothing here may borrow it.
struct HostMessage {
  std::uint8_t opcode{0};
  std::uint16_t flags{0};
  RunUuid run{};
  std::uint32_t sequence{0};
  std::vector<std::uint8_t> body;
};

// Decode every application payload a host observer recorded. The snapshot is
// parked on the world's deque so pointers into it stay valid until teardown.
const std::vector<HostMessage>& host_messages(BenchWorld& w, NodeId host) {
  auto& out = w.held_messages.emplace_back();
  for (const auto& raw : w.obs(host)->messages) {
    Message msg{};
    if (decode(ByteView{raw.data(), raw.size()}, msg) == DecodeError::Ok) {
      out.push_back(HostMessage{msg.opcode, msg.flags, msg.run, msg.sequence,
                                {msg.body.data, msg.body.data + msg.body.size}});
    }
  }
  return out;
}

const HostMessage* last_opcode(const std::vector<HostMessage>& msgs,
                               std::uint8_t opcode) {
  for (auto it = msgs.rbegin(); it != msgs.rend(); ++it) {
    if (it->opcode == opcode) return &*it;
  }
  return nullptr;
}

std::vector<std::uint8_t> vec(const char* text) {
  return {reinterpret_cast<const std::uint8_t*>(text),
          reinterpret_cast<const std::uint8_t*>(text) + std::strlen(text)};
}

// Scoped two/three-node fixture: gateway host 1 + bench members.
void build(BenchWorld& w, int bench_count) {
  w.add(1, false);
  for (int i = 0; i < bench_count; ++i) w.add(static_cast<NodeId>(2 + i), true);
  w.start_all();
  // add_neighbor refuses before start(): link only once all nodes run.
  for (int i = 0; i < bench_count; ++i) w.link(1, static_cast<NodeId>(2 + i));
  w.run(8000);  // adverts run a few periods; the gateway tree is up
}

// ---------------------------------------------------------------------------
// Codec tests (pure — no mesh)
// ---------------------------------------------------------------------------

void test_codec_header_roundtrip() {
  const RunUuid run = make_run(7);
  std::array<std::uint8_t, kMaxMessage> wire{};
  std::size_t written = 0;
  const auto body = vec("ping");
  CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::EchoRequest), 0, run, 42,
                  ByteView{body.data(), body.size()},
                  MutableByteView{wire.data(), wire.size()}, written));
  CHECK(written == kHeaderSize + 4);
  Message msg{};
  CHECK(decode(ByteView{wire.data(), written}, msg) == DecodeError::Ok);
  CHECK(msg.opcode == static_cast<std::uint8_t>(Opcode::EchoRequest));
  CHECK(msg.flags == 0 && msg.run == run && msg.sequence == 42);
  CHECK(msg.body.size == 4 && std::memcmp(msg.body.data, "ping", 4) == 0);
}

void test_codec_rejects() {
  std::array<std::uint8_t, kMaxMessage> wire{};
  std::size_t written = 0;
  const RunUuid run = make_run(1);
  CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::CountOnly), 0, run, 1,
                  ByteView{}, MutableByteView{wire.data(), wire.size()},
                  written));
  Message msg{};
  CHECK(decode(ByteView{wire.data(), kHeaderSize - 1}, msg) ==
        DecodeError::Truncated);
  std::array<std::uint8_t, kMaxMessage> bad = wire;
  bad[0] = 'X';
  CHECK(decode(ByteView{bad.data(), written}, msg) == DecodeError::BadMagic);
  bad = wire;
  bad[4] = 9;  // version
  CHECK(decode(ByteView{bad.data(), written}, msg) ==
        DecodeError::UnsupportedVersion);
  bad = wire;
  bad[31] ^= 0xFF;  // corrupt the CRC field
  CHECK(decode(ByteView{bad.data(), written}, msg) == DecodeError::CrcMismatch);
  // Unknown opcode is still a well-formed message: the app layer rejects it.
  bad = wire;
  bad[5] = 0x77;
  CHECK(decode(ByteView{bad.data(), written}, msg) == DecodeError::Ok);
  CHECK(!opcode_known(msg.opcode));
  CHECK(opcode_known(static_cast<std::uint8_t>(Opcode::EchoRequest)));
  CHECK(opcode_is_reply(static_cast<std::uint8_t>(Opcode::Status)));
  CHECK(!opcode_is_reply(static_cast<std::uint8_t>(Opcode::StatusGet)));
}

void test_codec_encode_bounds() {
  std::array<std::uint8_t, kMaxMessage + 8> wire{};
  std::size_t written = 0;
  const RunUuid run = make_run(1);
  std::array<std::uint8_t, kMaxBody + 1> big{};
  CHECK(encode(static_cast<std::uint8_t>(Opcode::EchoRequest), 0, run, 1,
               ByteView{big.data(), big.size()},
               MutableByteView{wire.data(), wire.size()},
               written).code == StatusCode::InvalidArgument);
  CHECK(written == 0);
  // One byte short of a header-only message is refused without output.
  std::array<std::uint8_t, kHeaderSize> small{};
  CHECK(encode(static_cast<std::uint8_t>(Opcode::EchoRequest), 0, run, 1,
               ByteView{}, MutableByteView{small.data(), kHeaderSize - 1},
               written).code == StatusCode::NoCapacity);
  CHECK(written == 0);
}

void test_codec_bodies() {
  PeerSendStartBody start{};
  start.expected_boot = 0x1122334455667788ULL;
  start.destination = 3;
  start.sequence_begin = 10;
  start.count = 64;
  start.payload_len = 32;
  start.seed = 0xDEADBEEF;
  start.interval_ms = 250;
  start.ttl_ms = 2000;
  start.max_inflight = 4;
  const auto raw = body_bytes(start);
  CHECK(raw.size() == kPeerSendStartBodySize);
  PeerSendStartBody back{};
  ByteReader reader{ByteView{raw.data(), raw.size()}};
  CHECK(decode(reader, back));
  CHECK(back.expected_boot == start.expected_boot &&
        back.destination == 3 && back.count == 64 &&
        back.interval_ms == 250 && back.max_inflight == 4);
  // Trailing garbage is refused.
  std::vector<std::uint8_t> over = raw;
  over.push_back(0);
  ByteReader extra{ByteView{over.data(), over.size()}};
  CHECK(!decode(extra, back));

  CountStatusBody cs{};
  cs.state = 1;
  cs.unique_packets = 9;
  cs.unique_bytes = 123;
  cs.duplicates = 2;
  cs.crc_invalid = 1;
  cs.first_ms = 100;
  cs.last_ms = 200;
  cs.window_base = 33;
  cs.window = 0xFF00FF00AA55AA55ULL;
  const auto craw = body_bytes(cs);
  CHECK(craw.size() == kCountStatusBodySize);
  CountStatusBody csback{};
  ByteReader cr{ByteView{craw.data(), craw.size()}};
  CHECK(decode(cr, csback) && csback.window == cs.window &&
        csback.unique_packets == 9);

  FaultSetBody fs{};
  fs.expected_boot = 7;
  fs.fault = fault::kEchoDelay;
  fs.duration_ms = 5000;
  fs.param = 250;
  const auto fraw = body_bytes(fs);
  CHECK(fraw.size() == kFaultSetBodySize);
  FaultSetBody fback{};
  ByteReader fr{ByteView{fraw.data(), fraw.size()}};
  CHECK(decode(fr, fback) && fback.fault == fault::kEchoDelay &&
        fback.param == 250);

  ResetRequestBody rr{};
  rr.expected_boot = 0x99;
  rr.delay_ms = 150;
  const auto rraw = body_bytes(rr);
  CHECK(rraw.size() == kResetRequestBodySize);

  CapabilitiesBody caps{};
  caps.app_version = 1;
  caps.boot_incarnation = 0xB002;
  caps.opcode_count = 17;
  for (std::uint8_t i = 0; i < caps.opcode_count; ++i) caps.opcodes[i] = i + 1;
  const auto capraw = body_bytes(caps);
  CapabilitiesBody capback{};
  ByteReader capr{ByteView{capraw.data(), capraw.size()}};
  CHECK(decode(capr, capback) && capback.opcode_count == 17 &&
        capback.opcodes[16] == 17 && capback.max_unicast_body == kMaxBody);
}

// ---------------------------------------------------------------------------
// Application tests (sim mesh)
// ---------------------------------------------------------------------------

void test_announce_and_hello() {
  BenchWorld w;
  build(w, 1);
  // The join announce: one CAPABILITIES to the gateway without being asked.
  const auto msgs = host_messages(w, 1);
  const HostMessage* caps_msg = last_opcode(
      msgs, static_cast<std::uint8_t>(Opcode::Capabilities));
  CHECK(caps_msg != nullptr);
  CHECK(caps_msg->run == kNullRun);
  CapabilitiesBody caps{};
  ByteReader reader{ByteView{caps_msg->body.data(), caps_msg->body.size()}};
  CHECK(decode(reader, caps));
  CHECK(caps.boot_incarnation == w.boot(2) && caps.app_version == 1);
  CHECK(caps.run_slots == BenchApp::kRunSlots &&
        caps.reply_queue == BenchApp::kReplyQueueDepth &&
        caps.generator_max_inflight == BenchApp::kGeneratorMaxInflight);
  CHECK(caps.opcode_count == 17);
  CHECK(caps.firmware_digest == 0xC0FFEE01);

  // HELLO re-query returns the same record.
  const auto before = w.obs(1)->messages.size();
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::Hello), kNullRun,
                   1, ByteView{}));
  w.run(400);
  const auto after = host_messages(w, 1);
  CHECK(after.size() > before);
  const HostMessage* hello = last_opcode(
      after, static_cast<std::uint8_t>(Opcode::Capabilities));
  CHECK(hello != nullptr && hello->sequence == 1);
}

void test_echo_roundtrip_and_replies() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(1);
  const auto body = vec("roundtrip");
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest), run,
                   10, ByteView{body.data(), body.size()}));
  w.run(400);
  const auto msgs = host_messages(w, 1);
  const HostMessage* reply =
      last_opcode(msgs, static_cast<std::uint8_t>(Opcode::EchoReply));
  CHECK(reply != nullptr);
  CHECK(reply->run == run && reply->sequence == 10);
  CHECK((reply->flags & kFlagResponse) != 0);
  CHECK((reply->flags & (kFlagDuplicate | kFlagLate)) == 0);
  CHECK(reply->body.size() == body.size() &&
        std::memcmp(reply->body.data(), body.data(), body.size()) == 0);
  CHECK(w.app(2)->stats().echo_answered == 1);

  // A reply-flagged message never gets answered (no reply storms).
  const auto before = w.obs(1)->messages.size();
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoReply), run, 11,
                   ByteView{body.data(), body.size()}, kFlagResponse));
  w.run(400);
  CHECK(w.obs(1)->messages.size() == before);
  CHECK(w.app(2)->stats().responses_seen == 1);
  CHECK(w.app(2)->stats().echo_answered == 1);
}

void test_echo_duplicate_and_late() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(2);
  const auto body = vec("x");
  auto echo = [&](std::uint32_t seq) {
    HostMessage out{};
    CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest),
                     run, seq, ByteView{body.data(), body.size()}));
    w.run(300);
    const auto msgs = host_messages(w, 1);
    if (const HostMessage* m =
            last_opcode(msgs, static_cast<std::uint8_t>(Opcode::EchoReply))) {
      out = *m;
    }
    return out;
  };
  const HostMessage first = echo(100);
  CHECK((first.flags & kFlagDuplicate) == 0 && (first.flags & kFlagLate) == 0);
  const HostMessage dup = echo(100);
  CHECK((dup.flags & kFlagDuplicate) != 0);
  const HostMessage late = echo(10);  // 90 below the window base
  CHECK((late.flags & kFlagLate) != 0);
  const HostMessage fresh = echo(99);  // inside the window, unseen
  CHECK((fresh.flags & kFlagDuplicate) == 0 && (fresh.flags & kFlagLate) == 0);
}

void test_reply_queue_full() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(3);
  // Park every reply for a minute.
  FaultSetBody fault{};
  fault.expected_boot = w.boot(2);
  fault.fault = fault::kEchoDelay;
  fault.duration_ms = 60000;
  fault.param = 60000;
  const auto fraw = body_bytes(fault);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::FaultSet), run, 1,
                   ByteView{fraw.data(), fraw.size()}));
  w.run(300);
  const auto body = vec("q");
  for (std::uint32_t seq = 10; seq < 15; ++seq) {
    CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest),
                     run, seq, ByteView{body.data(), body.size()}));
    w.run(50);
  }
  // 4 parked + 1 overflow; the fifth still counted as answered then dropped.
  CHECK(w.app(2)->stats().reply_dropped == 1);
  CHECK(w.app(2)->stats().echo_answered == 5);
}

void test_counter_and_count_get() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(4);
  const auto body = vec("payload16bytes_____");
  for (std::uint32_t seq = 1; seq <= 3; ++seq) {
    CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::CountOnly), run,
                     seq, ByteView{body.data(), body.size()}));
  }
  w.run(400);
  // One duplicate (same seq), one CRC-corrupt copy.
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::CountOnly), run, 2,
                   ByteView{body.data(), body.size()}));
  std::array<std::uint8_t, kMaxMessage> bad{};
  std::size_t bad_n = 0;
  CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::CountOnly), 0, run, 4,
                  ByteView{body.data(), body.size()},
                  MutableByteView{bad.data(), bad.size()}, bad_n));
  bad[bad_n - 1] ^= 0xFF;  // flip a body byte: CRC no longer matches
  {
    SendOptions options{};
    MessageId id{};
    CHECK(w.at(1)
              ->send(2, ByteView{bad.data(), bad_n}, options, w.now, id)
              .ok());
  }
  w.run(400);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::CountGet), run, 0,
                   ByteView{}));
  w.run(400);
  const auto msgs = host_messages(w, 1);
  const HostMessage* status =
      last_opcode(msgs, static_cast<std::uint8_t>(Opcode::CountStatus));
  CHECK(status != nullptr && status->run == run);
  CountStatusBody cs{};
  ByteReader reader{ByteView{status->body.data(), status->body.size()}};
  CHECK(decode(reader, cs));
  CHECK(cs.state == 1 && cs.unique_packets == 3 &&
        cs.unique_bytes == 3 * body.size() && cs.duplicates == 1 &&
        cs.crc_invalid == 1);
  CHECK(cs.window_base == 3);  // the CRC-bad copy never marks the window
}

void test_run_capacity_and_retire() {
  BenchWorld w;
  build(w, 1);
  const auto body = vec("r");
  // Three runs: the third evicts the first into the tombstone ring.
  for (std::uint8_t tag = 1; tag <= 3; ++tag) {
    CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest),
                     make_run(tag), 1, ByteView{body.data(), body.size()}));
    w.run(200);
  }
  // The evicted run is late, not re-opened.
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest),
                   make_run(1), 2, ByteView{body.data(), body.size()}));
  w.run(400);
  const HostMessage* late =
      last_opcode(host_messages(w, 1),
                  static_cast<std::uint8_t>(Opcode::EchoReply));
  CHECK(late != nullptr && (late->flags & kFlagLate) != 0);
  CHECK(w.app(2)->stats().late_requests == 1);

  // A live run also retires after the idle bound.
  w.run(60000 + 5000);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest),
                   make_run(2), 2, ByteView{body.data(), body.size()}));
  w.run(400);
  const HostMessage* idle_late =
      last_opcode(host_messages(w, 1),
                  static_cast<std::uint8_t>(Opcode::EchoReply));
  CHECK(idle_late != nullptr && (idle_late->flags & kFlagLate) != 0);
  CHECK(w.app(2)->stats().late_requests >= 2);
}

void test_rollcall() {
  BenchWorld w;
  build(w, 2);
  const RunUuid run = make_run(9);
  auto rollcall = [&](std::uint32_t seq, std::uint8_t page) {
    std::vector<std::uint8_t> body;
    if (page != kRollcallNoPage) {
      body.push_back(page);
    }
    std::array<std::uint8_t, kMaxMessage> wire{};
    std::size_t written = 0;
    CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::Rollcall), 0, run, seq,
                    ByteView{body.data(), body.size()},
                    MutableByteView{wire.data(), wire.size()}, written));
    GroupSendOptions options{};
    options.lifetime_ms = 5000;
    MessageId id{};
    CHECK_OK(w.at(1)->send_group(kGroupAll, ByteView{wire.data(), written},
                                 options, w.now, id));
  };
  const auto before = w.obs(1)->messages.size();
  rollcall(1, kRollcallNoPage);
  w.run(2000);
  // First rollcall: both bench nodes answer page 0 individually.
  std::size_t statuses = 0;
  for (const auto& msg : host_messages(w, 1)) {
    if (msg.opcode == static_cast<std::uint8_t>(Opcode::Status)) ++statuses;
  }
  CHECK(statuses == 2);
  CHECK(w.app(2)->stats().status_sent >= 1 &&
        w.app(3)->stats().status_sent >= 1);

  // Second rollcall, unchanged state: no new individual status.
  const auto seen = w.obs(1)->messages.size();
  rollcall(2, kRollcallNoPage);
  w.run(2000);
  std::size_t extra = 0;
  for (std::size_t i = seen; i < w.obs(1)->messages.size(); ++i) {
    Message m{};
    if (decode(ByteView{w.obs(1)->messages[i].data(),
                        w.obs(1)->messages[i].size()},
               m) == DecodeError::Ok &&
        m.opcode == static_cast<std::uint8_t>(Opcode::Status)) {
      ++extra;
    }
  }
  CHECK(extra == 0);
  CHECK(w.obs(1)->messages.size() >= before);

  // A requested slice answers even when nothing changed.
  rollcall(3, status_page::kCounters);
  w.run(2000);
  const HostMessage* sliced = last_opcode(host_messages(w, 1),
                                      static_cast<std::uint8_t>(Opcode::Status));
  CHECK(sliced != nullptr && sliced->sequence == 3);
  ByteReader reader{ByteView{sliced->body.data(), sliced->body.size()}};
  std::uint16_t sample_seq = 0;
  std::uint64_t boot = 0;
  std::uint8_t page = 0;
  std::uint8_t count = 0;
  CHECK(reader.read_u16(sample_seq) && reader.read_u64(boot) &&
        reader.read_u8(page) && reader.read_u8(count));
  CHECK(page == status_page::kCounters && count == status_page::kCount);
  CHECK(boot == w.boot(2) || boot == w.boot(3));
}

void test_status_pages() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(5);
  for (std::uint8_t page = 0; page < status_page::kCount; ++page) {
    std::array<std::uint8_t, 1> body{page};
    CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::StatusGet), run,
                     10 + page, ByteView{body.data(), body.size()}));
    w.run(300);
  }
  // Out-of-range page returns a header-only page (fields empty).
  std::array<std::uint8_t, 1> bad_page{status_page::kCount};
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::StatusGet), run,
                   99, ByteView{bad_page.data(), bad_page.size()}));
  w.run(400);
  const auto msgs = host_messages(w, 1);
  std::map<std::uint8_t, HostMessage> pages;
  for (const auto& msg : msgs) {
    if (msg.opcode == static_cast<std::uint8_t>(Opcode::Status)) {
      ByteReader reader{ByteView{msg.body.data(), msg.body.size()}};
      std::uint16_t sample = 0;
      std::uint64_t boot = 0;
      std::uint8_t p = 0, pc = 0;
      if (reader.read_u16(sample) && reader.read_u64(boot) &&
          reader.read_u8(p) && reader.read_u8(pc)) {
        CHECK(boot == w.boot(2) && pc == status_page::kCount);
        pages[p] = msg;
      }
    }
  }
  CHECK(pages.count(status_page::kIdentity) == 1);
  CHECK(pages.count(status_page::kCounters) == 1);
  CHECK(pages.count(status_page::kGenerator) == 1);
  CHECK(pages.count(status_page::kResources) == 1);
  // Identity page fields: node id, digests, site id populated.
  {
    ByteReader fields{ByteView{pages[status_page::kIdentity].body.data(), pages[status_page::kIdentity].body.size()}};
    std::uint16_t sample_seq = 0;
    std::uint64_t boot = 0;
    std::uint8_t page = 0, count = 0;
    std::uint64_t node = 0;
    std::uint8_t proto = 0, appv = 0;
    std::uint32_t uptime = 0;
    std::uint8_t cause = 0;
    std::uint32_t fw = 0, cfg = 0;
    std::uint64_t site = 0;
    std::uint32_t kid = 0;
    CHECK(fields.read_u16(sample_seq) && fields.read_u64(boot) &&
          fields.read_u8(page) && fields.read_u8(count) &&
          fields.read_u64(node) && fields.read_u8(proto) &&
          fields.read_u8(appv) && fields.read_u32(uptime) &&
          fields.read_u8(cause) && fields.read_u32(fw) &&
          fields.read_u32(cfg) && fields.read_u64(site) &&
          fields.read_u32(kid));
    CHECK(node == 2 && proto == kProtocolVersion && appv == 1 &&
          fw == 0xC0FFEE01 && site == 0x51);
  }
  // status_page::kCount request produced a header-only page (or none): the
  // app must not crash or mis-encode.
  CHECK(w.app(2)->stats().status_sent >= status_page::kCount);
}

void test_peer_send_run() {
  BenchWorld w;
  build(w, 2);
  const RunUuid run = make_run(6);
  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 1000;
  start.count = 4;
  start.payload_len = 16;
  start.seed = 0xABCDEF;
  start.interval_ms = 50;
  start.ttl_ms = 2000;
  start.max_inflight = 1;
  const auto body = body_bytes(start);
  CHECK(body.size() <= kMaxCommandBody);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart), run,
                   1, ByteView{body.data(), body.size()}));
  w.run(5000);
  const auto msgs = host_messages(w, 1);
  const HostMessage* status = last_opcode(
      msgs, static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(status != nullptr && status->run == run && status->sequence == 1);
  PeerSendStatusBody ps{};
  ByteReader reader{ByteView{status->body.data(), status->body.size()}};
  CHECK(decode(reader, ps));
  // The ack only confirms acceptance — counters land on the generator page
  // once the bounded run closes.
  CHECK(ps.result == result::kStarted && ps.planned == 4);

  // The destination's run counted the four packets — collected separately.
  CHECK(bench_send(w, 3, static_cast<std::uint8_t>(Opcode::CountGet), run, 0,
                   ByteView{}));
  w.run(400);
  const HostMessage* count_msg = last_opcode(
      host_messages(w, 1),
      static_cast<std::uint8_t>(Opcode::CountStatus));
  CHECK(count_msg != nullptr);
  CountStatusBody cs{};
  ByteReader cr{ByteView{count_msg->body.data(), count_msg->body.size()}};
  CHECK(decode(cr, cs));
  CHECK(cs.unique_packets == 4 && cs.duplicates == 0);

  // Generator finished on its bound — a query on STATUS page 5 says so.
  std::array<std::uint8_t, 1> page{status_page::kGenerator};
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::StatusGet), run, 7,
                   ByteView{page.data(), page.size()}));
  w.run(300);
  const HostMessage* gen_page = last_opcode(host_messages(w, 1),
                                        static_cast<std::uint8_t>(Opcode::Status));
  CHECK(gen_page != nullptr);
  ByteReader gr{ByteView{gen_page->body.data(), gen_page->body.size()}};
  std::uint16_t sample_seq = 0;
  std::uint64_t gen_boot = 0;
  std::uint8_t gen_page_id = 0, gen_page_count = 0, gstate = 0;
  std::uint64_t commander = 0, destination = 0;
  RunUuid gen_run{};
  std::uint32_t seq_begin = 0;
  std::uint16_t planned = 0, submitted = 0, admitted = 0, delivered = 0;
  std::uint16_t failed = 0, unknown = 0, sent = 0;
  CHECK(gr.read_u16(sample_seq) && gr.read_u64(gen_boot) &&
        gr.read_u8(gen_page_id) && gr.read_u8(gen_page_count) &&
        gr.read_u8(gstate) && gr.read_u64(commander) &&
        gr.read_bytes(MutableByteView{gen_run.data(), gen_run.size()}) &&
        gr.read_u64(destination) && gr.read_u32(seq_begin) &&
        gr.read_u16(planned) && gr.read_u16(submitted) &&
        gr.read_u16(admitted) && gr.read_u16(delivered) &&
        gr.read_u16(failed) && gr.read_u16(unknown) && gr.read_u16(sent));
  CHECK(gen_page_id == status_page::kGenerator);
  CHECK(gstate == gen_state::kComplete);
  CHECK(commander == 1 && destination == 3 && gen_run == run);
  CHECK(planned == 4 && submitted == 4 && admitted == 4 && sent == 4);
  CHECK(delivered + unknown + failed == 4);
}

void test_peer_send_duplicate_and_stale() {
  BenchWorld w;
  build(w, 2);
  const RunUuid run = make_run(7);
  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 1;
  start.count = 2;
  start.payload_len = 8;
  start.interval_ms = 50;
  start.ttl_ms = 2000;
  const auto body = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart), run,
                   1, ByteView{body.data(), body.size()}));
  w.run(400);
  // Same command re-delivered (e.g. APPLIED retry): refused as duplicate.
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart), run,
                   1, ByteView{body.data(), body.size()}));
  w.run(400);
  const HostMessage* dup = last_opcode(host_messages(w, 1),
                                   static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(dup != nullptr && (dup->flags & kFlagDuplicate) != 0);
  PeerSendStatusBody ps{};
  ByteReader reader{ByteView{dup->body.data(), dup->body.size()}};
  CHECK(decode(reader, ps));
  CHECK(ps.result == result::kDuplicate);
  CHECK(w.app(2)->stats().duplicate_commands == 1);

  // A command minted against a different boot is stale, not a new run.
  const RunUuid run2 = make_run(8);
  start.expected_boot = w.boot(2) + 9;
  const auto body2 = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart),
                   run2, 1, ByteView{body2.data(), body2.size()}));
  w.run(400);
  const HostMessage* stale = last_opcode(host_messages(w, 1),
                                     static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(stale != nullptr && (stale->flags & kFlagLate) != 0);
  ByteReader sr{ByteView{stale->body.data(), stale->body.size()}};
  CHECK(decode(sr, ps) && ps.result == result::kStaleBoot);
  CHECK(w.app(2)->stats().stale_boot == 1);
}

void test_peer_send_unauthorized() {
  BenchWorld w;
  build(w, 2);
  const RunUuid run = make_run(10);
  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 1;
  start.count = 1;
  start.payload_len = 8;
  start.interval_ms = 10;
  start.ttl_ms = 2000;
  const auto body = body_bytes(start);
  // A member node is not the authorized controller — even though the mesh
  // auth proves it is a peer, it cannot drive control commands.
  const auto before = w.obs(1)->messages.size();
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart), run,
                   1, ByteView{body.data(), body.size()}, 0, 3));
  w.run(400);
  CHECK(w.app(2)->stats().unauthorized == 1);
  CHECK(w.obs(1)->messages.size() == before);  // no reply to a non-controller

  // And a group-carried START is refused the same way (group key != admin).
  std::array<std::uint8_t, kMaxMessage> wire{};
  std::size_t written = 0;
  CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::PeerSendStart), 0, run, 2,
                  ByteView{body.data(), body.size()},
                  MutableByteView{wire.data(), wire.size()}, written));
  GroupSendOptions options{};
  MessageId id{};
  CHECK_OK(w.at(1)->send_group(kGroupAll, ByteView{wire.data(), written},
                               options, w.now, id));
  w.run(400);
  CHECK(w.app(2)->stats().unauthorized == 2);
  CHECK(w.app(2)->stats().rx_dropped == 0);  // was dispatched, then refused
}

void test_reset_request() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(11);
  ResetRequestBody req{};
  req.expected_boot = w.boot(2);
  req.delay_ms = 100;
  const auto body = body_bytes(req);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::ResetRequest), run,
                   1, ByteView{body.data(), body.size()}));
  w.run(50);  // ACK is on the wire before the delay elapses
  const auto msgs = host_messages(w, 1);
  const HostMessage* ack = last_opcode(
      msgs, static_cast<std::uint8_t>(Opcode::ResetAck));
  CHECK(ack != nullptr);
  ResetAckBody ab{};
  ByteReader ar{ByteView{ack->body.data(), ack->body.size()}};
  CHECK(decode(ar, ab) && ab.accepted == 1);
  CHECK(w.platform(2)->restarts == 0);
  w.run(300);
  CHECK(w.platform(2)->restarts == 1);
  CHECK(w.app(2)->stats().resets_executed == 1);

  // Stale binding: a request for the wrong incarnation is refused.
  const RunUuid run2 = make_run(12);
  req.expected_boot = w.boot(2) + 5;
  const auto body2 = body_bytes(req);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::ResetRequest),
                   run2, 1, ByteView{body2.data(), body2.size()}));
  w.run(400);
  const HostMessage* stale_ack = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::ResetAck));
  CHECK(stale_ack != nullptr && (stale_ack->flags & kFlagLate) != 0);
  ByteReader sr{ByteView{stale_ack->body.data(), stale_ack->body.size()}};
  CHECK(decode(sr, ab) && ab.accepted == 0);
  CHECK(w.platform(2)->restarts == 1);  // unchanged
}

void test_source_reset_no_restart() {
  BenchWorld w;
  build(w, 2);
  const RunUuid run = make_run(13);
  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 1;
  start.count = 64;
  start.payload_len = 8;
  start.interval_ms = 500;  // slow enough to reset mid-run
  start.ttl_ms = 2000;
  const auto body = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart), run,
                   1, ByteView{body.data(), body.size()}));
  w.run(1200);  // ~2 packets out, run still active
  // Source resets externally: the bounded run dies with the app.
  w.reset_bench(2);
  w.run(2000);
  // The pre-reset command retransmitted against the NEW boot fails — the
  // new incarnation refuses it as stale rather than resuming the run.
  const RunUuid stale = run;
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart),
                   stale, 1, ByteView{body.data(), body.size()}));
  w.run(400);
  const HostMessage* reply = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(reply != nullptr);
  PeerSendStatusBody ps{};
  ByteReader reader{ByteView{reply->body.data(), reply->body.size()}};
  CHECK(decode(reader, ps));
  CHECK(ps.result == result::kStaleBoot);
  CHECK(ps.submitted == 0 && ps.delivered == 0);  // no silent resume
  CHECK(w.app(2)->stats().stale_boot == 1);
}

void test_destination_reset() {
  BenchWorld w;
  build(w, 2);
  const RunUuid run = make_run(14);
  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 1;
  start.count = 6;
  start.payload_len = 8;
  start.interval_ms = 400;  // slow enough that ~2 land before the reset
  start.ttl_ms = 2000;
  const auto body = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart), run,
                   1, ByteView{body.data(), body.size()}));
  w.run(800);  // a few packets already counted at node 3
  CHECK(bench_send(w, 3, static_cast<std::uint8_t>(Opcode::CountGet), run, 0,
                   ByteView{}));
  w.run(400);
  std::uint32_t before_reset_unique = 0;
  {
    const HostMessage* msg = last_opcode(
        host_messages(w, 1), static_cast<std::uint8_t>(Opcode::CountStatus));
    CHECK(msg != nullptr);
    if (msg != nullptr) {
      CountStatusBody cs{};
      ByteReader reader{ByteView{msg->body.data(), msg->body.size()}};
      if (decode(reader, cs)) before_reset_unique = cs.unique_packets;
    }
  }
  CHECK(before_reset_unique > 0 && before_reset_unique < 6);

  // Destination resets mid-run; remaining packets still arrive but the
  // destination's counting restarted — no phantom pre-reset history.
  w.reset_bench(3);
  w.run(4000);
  CHECK(bench_send(w, 3, static_cast<std::uint8_t>(Opcode::CountGet), run, 0,
                   ByteView{}));
  w.run(400);
  const HostMessage* msg = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::CountStatus));
  CHECK(msg != nullptr);
  CountStatusBody cs{};
  ByteReader reader{ByteView{msg->body.data(), msg->body.size()}};
  CHECK(decode(reader, cs));
  CHECK(cs.unique_packets < 6);  // restarted from zero, not continued
  CHECK(w.app(3)->stats().rx_total > 0);
}

void test_counter_reset() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(15);
  const auto body = vec("count");
  for (std::uint32_t seq = 1; seq <= 3; ++seq) {
    CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::CountOnly), run,
                     seq, ByteView{body.data(), body.size()}));
  }
  w.run(400);
  ExpectedBootBody reset{};
  reset.expected_boot = w.boot(2);
  const auto rbody = body_bytes(reset);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::CounterReset), run,
                   1, ByteView{rbody.data(), rbody.size()}));
  w.run(400);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::CountGet), run, 0,
                   ByteView{}));
  w.run(400);
  const HostMessage* msg = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::CountStatus));
  CHECK(msg != nullptr);
  CountStatusBody cs{};
  ByteReader reader{ByteView{msg->body.data(), msg->body.size()}};
  CHECK(decode(reader, cs));
  CHECK(cs.unique_packets == 0 && cs.unique_bytes == 0 && cs.duplicates == 0);
  // Only the run statistics cleared: the node itself stayed joined/alive.
  CHECK(w.at(2)->started());
}

void test_malformed_and_unknown() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(16);
  // Unknown opcode — well formed, refused by the app.
  CHECK(bench_send(w, 2, 0x77, run, 1, ByteView{}));
  // Garbage (not even the bench header) and a CRC-corrupt frame.
  {
    SendOptions options{};
    MessageId id{};
    const auto junk = vec("not-a-bench-frame-----------------------------");
    CHECK(w.at(1)
              ->send(2, ByteView{junk.data(), junk.size()}, options, w.now,
                     id)
              .ok());
    std::array<std::uint8_t, kMaxMessage> bad{};
    std::size_t n = 0;
    CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::EchoRequest), 0, run, 5,
                    ByteView{}, MutableByteView{bad.data(), bad.size()}, n));
    bad[kHeaderSize - 1] ^= 0xFF;
    CHECK(w.at(1)
              ->send(2, ByteView{bad.data(), n}, options, w.now, id)
              .ok());
  }
  w.run(500);
  const BenchStats& s = w.app(2)->stats();
  CHECK(s.unknown_opcode == 1);
  CHECK(s.malformed >= 1);
  CHECK(s.crc_invalid >= 1);
  // None of that produced replies.
  CHECK(s.echo_answered == 0);
}

void test_rx_queue_overflow() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(17);
  const auto body = vec("x");
  std::array<std::uint8_t, kMaxMessage> wire{};
  std::size_t n = 0;
  CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::CountOnly), 0, run, 1,
                  ByteView{body.data(), body.size()},
                  MutableByteView{wire.data(), wire.size()}, n));
  // Five observer callbacks land before the app ever polls — the contract
  // this queue exists for. The four-deep queue keeps four and counts the
  // fifth as dropped instead of growing or blocking the SDK callback.
  MessageKey key{};
  key.origin = 1;
  for (std::uint8_t i = 0; i < 5; ++i) {
    key.id.sequence = i;
    w.app(2)->on_message(key, 1, ByteView{wire.data(), n});
  }
  w.run(100);
  CHECK(w.app(2)->stats().rx_dropped == 1);
  CHECK(w.app(2)->stats().rx_total == 4);
}

void test_send_load_fault() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(18);
  FaultSetBody fault{};
  fault.expected_boot = w.boot(2);
  fault.fault = fault::kSendLoad;
  fault.duration_ms = 400;
  fault.param = 100;
  const auto body = body_bytes(fault);
  const auto before = w.obs(1)->messages.size();
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::FaultSet), run, 1,
                   ByteView{body.data(), body.size()}));
  w.run(800);
  const auto received = w.obs(1)->messages.size() - before;
  CHECK(received >= 3 && received <= 6);  // ~4 at 100 ms, bounded window
  CHECK(w.app(2)->stats().send_load_sent >= 3);
  // The fault auto-clears: nothing more after the duration.
  const auto settled = w.obs(1)->messages.size();
  w.run(800);
  CHECK(w.obs(1)->messages.size() == settled);
}

void test_fault_suppress_and_delay() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(19);
  const auto body = vec("e");
  FaultSetBody fault{};
  fault.expected_boot = w.boot(2);
  fault.fault = fault::kEchoSuppress;
  fault.duration_ms = 500;
  const auto fbody = body_bytes(fault);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::FaultSet), run, 1,
                   ByteView{fbody.data(), fbody.size()}));
  w.run(100);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest), run,
                   2, ByteView{body.data(), body.size()}));
  w.run(400);
  CHECK(w.app(2)->stats().echo_suppressed == 1);
  // After the fault window the same flow answers again.
  w.run(400);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest), run,
                   3, ByteView{body.data(), body.size()}));
  w.run(400);
  const HostMessage* reply = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::EchoReply));
  CHECK(reply != nullptr && reply->sequence == 3);
}

void test_peer_send_stop() {
  BenchWorld w;
  build(w, 2);
  const RunUuid run = make_run(20);
  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 1;
  start.count = 64;
  start.payload_len = 8;
  start.interval_ms = 1000;
  start.ttl_ms = 2000;
  const auto body = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart), run,
                   1, ByteView{body.data(), body.size()}));
  w.run(300);
  ExpectedBootBody stop{};
  stop.expected_boot = w.boot(2);
  const auto sbody = body_bytes(stop);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStop), run,
                   2, ByteView{sbody.data(), sbody.size()}));
  w.run(400);
  const HostMessage* msg = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(msg != nullptr);
  PeerSendStatusBody ps{};
  ByteReader reader{ByteView{msg->body.data(), msg->body.size()}};
  CHECK(decode(reader, ps));
  CHECK(ps.result == result::kStopped && ps.state == gen_state::kStopped);
  // Stopping a run that does not exist answers NotRunning, not a crash.
  const RunUuid run2 = make_run(21);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStop),
                   run2, 1, ByteView{sbody.data(), sbody.size()}));
  w.run(400);
  const HostMessage* nr = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  ByteReader nr_reader{ByteView{nr->body.data(), nr->body.size()}};
  CHECK(decode(nr_reader, ps) && ps.result == result::kNotRunning);
}

void test_configured_controller_and_digest() {
  BenchWorld w;
  w.add(1, false);
  w.add(2, true);
  w.add(3, false);
  BenchConfig configured{};
  configured.controller = 3;
  configured.firmware_digest = 0x12345678;
  configured.config_digest = 0x87654321;
  w.app(2)->configure(configured);
  w.start_all();
  w.link(1, 2);
  w.link(2, 3);
  w.run(8000);

  const RunUuid run = make_run(31);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::Hello), run,
                   1, ByteView{}, 0, 1));
  w.run(500);
  const HostMessage* caps_msg = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::Capabilities));
  CHECK(caps_msg != nullptr);
  if (caps_msg != nullptr) {
    CapabilitiesBody caps{};
    ByteReader reader{ByteView{caps_msg->body.data(), caps_msg->body.size()}};
    CHECK(decode(reader, caps));
    CHECK(caps.firmware_digest == configured.firmware_digest);
    CHECK(caps.config_digest == configured.config_digest);
  }

  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 1;
  start.count = 1;
  start.payload_len = 1;
  start.ttl_ms = 2000;
  const auto body = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart),
                   run, 2, ByteView{body.data(), body.size()}, 0, 1));
  w.run(400);
  CHECK(w.app(2)->stats().unauthorized == 1);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart),
                   run, 3, ByteView{body.data(), body.size()}, 0, 3));
  w.run(400);
  const HostMessage* accepted = last_opcode(
      host_messages(w, 3), static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(accepted != nullptr);
  if (accepted != nullptr) {
    PeerSendStatusBody status{};
    ByteReader reader{ByteView{accepted->body.data(), accepted->body.size()}};
    CHECK(decode(reader, status) && status.result == result::kStarted);
  }
}

void test_peer_send_status_query() {
  BenchWorld w;
  build(w, 2);
  const RunUuid run = make_run(32);
  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 10;
  start.count = 2;
  start.payload_len = 4;
  start.ttl_ms = 1000;
  const auto body = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart),
                   run, 1, ByteView{body.data(), body.size()}));
  w.run(3000);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStatus),
                   run, 2, ByteView{}));
  w.run(400);
  const HostMessage* answer = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(answer != nullptr && answer->sequence == 2);
  if (answer != nullptr && answer->sequence == 2) {
    PeerSendStatusBody status{};
    ByteReader reader{ByteView{answer->body.data(), answer->body.size()}};
    CHECK(decode(reader, status));
    CHECK(status.result == result::kQuery);
    CHECK(status.state == gen_state::kComplete && status.planned == 2);
  }
  const RunUuid other = make_run(33);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStatus),
                   other, 3, ByteView{}));
  w.run(400);
  answer = last_opcode(host_messages(w, 1),
                       static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(answer != nullptr && answer->sequence == 3);
  if (answer != nullptr && answer->sequence == 3) {
    PeerSendStatusBody status{};
    ByteReader reader{ByteView{answer->body.data(), answer->body.size()}};
    CHECK(decode(reader, status));
    CHECK(status.state == gen_state::kIdle && status.planned == 0);
  }
}

void test_reset_waits_for_ack_send() {
  BenchWorld w;
  w.add(1, false);
  w.add(2, true);
  w.start_all();  // No route back to the controller.
  ResetRequestBody req{};
  req.expected_boot = w.boot(2);
  req.delay_ms = 20;
  const auto body = body_bytes(req);
  std::array<std::uint8_t, kMaxMessage> wire{};
  std::size_t written = 0;
  CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::ResetRequest), 0,
                  make_run(34), 1, ByteView{body.data(), body.size()},
                  MutableByteView{wire.data(), wire.size()}, written));
  MessageKey key{};
  key.origin = 1;
  w.app(2)->on_message(key, 1, ByteView{wire.data(), written});
  w.app(2)->poll(0);
  w.app(2)->poll(100);
  CHECK(w.platform(2)->restarts == 0);
  w.link(1, 2);
  w.run(500);
  CHECK(w.platform(2)->restarts == 1);
}

void test_tombstone_counter_wrap() {
  BenchWorld w;
  build(w, 1);
  MessageKey key{};
  key.origin = 1;
  for (std::uint16_t i = 0; i < 258; ++i) {
    RunUuid run = make_run(static_cast<std::uint8_t>(i));
    run[14] = static_cast<std::uint8_t>(i >> 8);
    std::array<std::uint8_t, kMaxMessage> wire{};
    std::size_t written = 0;
    CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::CountOnly), 0, run, 1,
                    ByteView{}, MutableByteView{wire.data(), wire.size()},
                    written));
    w.app(2)->on_message(key, 1, ByteView{wire.data(), written});
    w.app(2)->poll(w.now);
    ++w.now;
  }
  RunUuid recent = make_run(255);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::CountGet),
                   recent, 1, ByteView{}));
  w.run(400);
  const HostMessage* answer = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::CountStatus));
  CHECK(answer != nullptr);
  if (answer != nullptr) {
    CountStatusBody count{};
    ByteReader reader{ByteView{answer->body.data(), answer->body.size()}};
    CHECK(decode(reader, count) && count.state == 2);
  }
}

void test_unrelated_deliveries_do_not_fill_generator_queue() {
  BenchWorld w;
  build(w, 1);
  DeliveryResult result{};
  result.id.session = 987;
  result.id.sequence = 1;
  result.state = DeliveryState::Delivered;
  w.app(2)->on_delivery(result);
  result.id.sequence = 2;
  w.app(2)->on_delivery(result);
  CHECK(w.app(2)->stats().delivery_events_dropped == 0);
}

void test_announce_after_membership() {
  BenchWorld w;
  w.add(1, false);
  w.add(2, true);
  w.probes[2]->fixed.participation_valid = true;
  w.probes[2]->fixed.membership =
      static_cast<std::uint8_t>(MembershipState::Unprovisioned);
  w.start_all();
  w.link(1, 2);
  w.run(1000);
  CHECK(last_opcode(host_messages(w, 1),
                    static_cast<std::uint8_t>(Opcode::Capabilities)) ==
        nullptr);
  w.probes[2]->fixed.membership =
      static_cast<std::uint8_t>(MembershipState::Member);
  w.run(1000);
  CHECK(last_opcode(host_messages(w, 1),
                    static_cast<std::uint8_t>(Opcode::Capabilities)) !=
        nullptr);
}

void test_group_hello_does_not_amplify() {
  BenchWorld w;
  build(w, 2);
  const auto before = w.obs(1)->messages.size();
  std::array<std::uint8_t, kMaxMessage> wire{};
  std::size_t written = 0;
  CHECK_OK(encode(static_cast<std::uint8_t>(Opcode::Hello), 0, make_run(35),
                  1, ByteView{}, MutableByteView{wire.data(), wire.size()},
                  written));
  GroupSendOptions options{};
  MessageId id{};
  CHECK_OK(w.at(1)->send_group(kGroupAll, ByteView{wire.data(), written},
                               options, w.now, id));
  w.run(1000);
  CHECK(w.obs(1)->messages.size() == before);
  CHECK(w.app(2)->stats().group_ignored >= 1);
}

void test_delayed_reply_expires_before_due() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(36);
  FaultSetBody fault{};
  fault.expected_boot = w.boot(2);
  fault.fault = fault::kEchoDelay;
  fault.duration_ms = 20000;
  fault.param = 10000;
  const auto fbody = body_bytes(fault);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::FaultSet), run,
                   1, ByteView{fbody.data(), fbody.size()}));
  w.run(100);
  for (std::uint32_t seq = 2; seq < 6; ++seq) {
    CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest),
                     run, seq, ByteView{}));
    w.run(100);
  }
  w.run(6000);
  CHECK(w.app(2)->stats().reply_dropped == 4);
}

void test_peer_send_rejects_impossible_bounds() {
  BenchWorld w;
  build(w, 2);
  PeerSendStartBody start{};
  start.expected_boot = w.boot(2);
  start.destination = 3;
  start.sequence_begin = 1;
  start.count = 2;
  start.payload_len = 1;
  start.ttl_ms = 1000;
  start.max_inflight = 0;
  auto body = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart),
                   make_run(37), 1, ByteView{body.data(), body.size()}));
  w.run(400);
  const HostMessage* reply = last_opcode(
      host_messages(w, 1), static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(reply != nullptr);
  if (reply != nullptr) {
    PeerSendStatusBody status{};
    ByteReader reader{ByteView{reply->body.data(), reply->body.size()}};
    CHECK(decode(reader, status) && status.result == result::kInvalid);
  }
  start.max_inflight = 1;
  start.sequence_begin = 0xffffffffu;
  body = body_bytes(start);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::PeerSendStart),
                   make_run(38), 1, ByteView{body.data(), body.size()}));
  w.run(400);
  reply = last_opcode(host_messages(w, 1),
                      static_cast<std::uint8_t>(Opcode::PeerSendStatus));
  CHECK(reply != nullptr);
  if (reply != nullptr) {
    PeerSendStatusBody status{};
    ByteReader reader{ByteView{reply->body.data(), reply->body.size()}};
    CHECK(decode(reader, status) && status.result == result::kInvalid);
  }
}

void test_fault_duration_bound_and_clear() {
  BenchWorld w;
  build(w, 1);
  const RunUuid run = make_run(39);
  FaultSetBody fault{};
  fault.expected_boot = w.boot(2);
  fault.fault = fault::kEchoSuppress;
  fault.duration_ms = BenchApp::kGeneratorMaxDurationMs + 1;
  auto body = body_bytes(fault);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::FaultSet), run,
                   1, ByteView{body.data(), body.size()}));
  w.run(200);
  CHECK(w.app(2)->stats().invalid_requests == 1);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest), run,
                   2, ByteView{}));
  w.run(200);
  CHECK(w.app(2)->stats().echo_suppressed == 0);

  fault.duration_ms = 10000;
  body = body_bytes(fault);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::FaultSet), run,
                   3, ByteView{body.data(), body.size()}));
  w.run(200);
  fault.fault = fault::kNone;
  fault.duration_ms = 0;
  body = body_bytes(fault);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::FaultSet), run,
                   4, ByteView{body.data(), body.size()}));
  w.run(200);
  CHECK(bench_send(w, 2, static_cast<std::uint8_t>(Opcode::EchoRequest), run,
                   5, ByteView{}));
  w.run(200);
  CHECK(w.app(2)->stats().echo_suppressed == 0);
}

// --- Shared golden vectors -------------------------------------------------
// protocol/bench-golden: the same flat "key": value JSON subset as
// test_usb.cpp. Positive vectors decode and re-encode byte-identically;
// negatives carry the named DecodeError verdict.

#ifndef ROUTELOOM_BENCH_GOLDEN_DIR
#define ROUTELOOM_BENCH_GOLDEN_DIR "protocol/bench-golden"
#endif

std::map<std::string, std::string> bench_flat_json(const std::string& text) {
  std::map<std::string, std::string> fields;
  std::size_t pos = 0;
  while (pos < text.size()) {
    const std::size_t key_begin = text.find('"', pos);
    if (key_begin == std::string::npos) break;
    const std::size_t key_end = text.find('"', key_begin + 1);
    const std::size_t colon = text.find(':', key_end + 1);
    std::size_t cursor = colon + 1;
    while (cursor < text.size() &&
           std::isspace(static_cast<unsigned char>(text[cursor]))) {
      ++cursor;
    }
    std::string value;
    if (cursor < text.size() && text[cursor] == '"') {
      const std::size_t value_end = text.find('"', cursor + 1);
      value = text.substr(cursor + 1, value_end - cursor - 1);
      pos = value_end + 1;
    } else {
      std::size_t value_end = cursor;
      while (value_end < text.size() &&
             (std::isdigit(static_cast<unsigned char>(text[value_end])))) {
        ++value_end;
      }
      value = text.substr(cursor, value_end - cursor);
      pos = value_end;
    }
    fields[text.substr(key_begin + 1, key_end - key_begin - 1)] = value;
  }
  return fields;
}

std::string bench_field(const std::map<std::string, std::string>& fields,
                        const char* key) {
  const auto it = fields.find(key);
  return it == fields.end() ? std::string() : it->second;
}

std::vector<std::uint8_t> bench_unhex(const std::string& text) {
  std::vector<std::uint8_t> out;
  out.reserve(text.size() / 2);
  for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
    out.push_back(static_cast<std::uint8_t>(
        std::stoul(text.substr(i, 2), nullptr, 16)));
  }
  return out;
}

std::string bench_read(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  return {std::istreambuf_iterator<char>(in),
          std::istreambuf_iterator<char>()};
}

void test_golden() {
  const std::filesystem::path root(ROUTELOOM_BENCH_GOLDEN_DIR);
  std::vector<std::filesystem::path> files;
  for (const auto& entry : std::filesystem::directory_iterator(root)) {
    if (entry.path().extension() == ".json") files.push_back(entry.path());
  }
  std::sort(files.begin(), files.end());
  CHECK(files.size() >= 20);

  std::size_t positive = 0;
  std::size_t negative = 0;
  for (const auto& path : files) {
    const auto fields = bench_flat_json(bench_read(path));
    const std::string name = bench_field(fields, "name");
    const std::string expect = bench_field(fields, "expect");
    const auto wire = bench_unhex(bench_field(fields, "wire_hex"));
    Message msg{};
    const DecodeError error =
        decode(ByteView{wire.data(), wire.size()}, msg);
    if (expect == "ok") {
      ++positive;
      CHECK(error == DecodeError::Ok);
      if (error != DecodeError::Ok) continue;
      CHECK(msg.opcode == std::stoul(bench_field(fields, "opcode")));
      CHECK(msg.flags == std::stoul(bench_field(fields, "flags")));
      CHECK(msg.sequence == std::stoul(bench_field(fields, "sequence")));
      const auto run = bench_unhex(bench_field(fields, "run_uuid_hex"));
      CHECK(run.size() == msg.run.size() &&
            std::memcmp(run.data(), msg.run.data(), run.size()) == 0);
      const auto body = bench_unhex(bench_field(fields, "body_hex"));
      CHECK(body.size() == msg.body.size &&
            (body.empty() ||
             std::memcmp(body.data(), msg.body.data, body.size()) == 0));
      if (opcode_known(msg.opcode)) {
        // Re-encoding must reproduce the wire bytes exactly.
        std::array<std::uint8_t, kMaxMessage> out{};
        std::size_t written = 0;
        CHECK_OK(encode(msg.opcode, msg.flags, msg.run, msg.sequence,
                        msg.body, MutableByteView{out.data(), out.size()},
                        written));
        CHECK(written == wire.size() &&
              std::memcmp(out.data(), wire.data(), wire.size()) == 0);
        if (opcode_is_reply(msg.opcode)) {
          CHECK((msg.flags & kFlagResponse) != 0);
        }
      } else {
        CHECK(name == "unknown_opcode");
      }
    } else {
      ++negative;
      const DecodeError wanted =
          expect == "truncated"          ? DecodeError::Truncated
          : expect == "bad_magic"        ? DecodeError::BadMagic
          : expect == "unsupported_version" ? DecodeError::UnsupportedVersion
                                         : DecodeError::CrcMismatch;
      CHECK(error == wanted);
    }
  }
  CHECK(positive >= 20 && negative >= 4);
}

}  // namespace

int main(int argc, char** argv) {
  const char* only = argc > 1 ? argv[1] : nullptr;
  auto run_test = [&](const char* name, void (*fn)()) {
    if (only == nullptr || std::string(name).find(only) != std::string::npos) {
      fn();
    }
  };
  run_test("codec_header_roundtrip", test_codec_header_roundtrip);
  run_test("codec_rejects", test_codec_rejects);
  run_test("codec_encode_bounds", test_codec_encode_bounds);
  run_test("codec_bodies", test_codec_bodies);
  run_test("echo_roundtrip_and_replies", test_echo_roundtrip_and_replies);
  run_test("announce_and_hello", test_announce_and_hello);
  run_test("echo_duplicate_and_late", test_echo_duplicate_and_late);
  run_test("reply_queue_full", test_reply_queue_full);
  run_test("counter_and_count_get", test_counter_and_count_get);
  run_test("run_capacity_and_retire", test_run_capacity_and_retire);
  run_test("rollcall", test_rollcall);
  run_test("status_pages", test_status_pages);
  run_test("peer_send_run", test_peer_send_run);
  run_test("peer_send_duplicate_and_stale", test_peer_send_duplicate_and_stale);
  run_test("peer_send_unauthorized", test_peer_send_unauthorized);
  run_test("reset_request", test_reset_request);
  run_test("source_reset_no_restart", test_source_reset_no_restart);
  run_test("destination_reset", test_destination_reset);
  run_test("counter_reset", test_counter_reset);
  run_test("malformed_and_unknown", test_malformed_and_unknown);
  run_test("rx_queue_overflow", test_rx_queue_overflow);
  run_test("send_load_fault", test_send_load_fault);
  run_test("fault_suppress_and_delay", test_fault_suppress_and_delay);
  run_test("peer_send_stop", test_peer_send_stop);
  run_test("configured_controller_and_digest", test_configured_controller_and_digest);
  run_test("peer_send_status_query", test_peer_send_status_query);
  run_test("reset_waits_for_ack_send", test_reset_waits_for_ack_send);
  run_test("tombstone_counter_wrap", test_tombstone_counter_wrap);
  run_test("unrelated_deliveries_do_not_fill_generator_queue",
           test_unrelated_deliveries_do_not_fill_generator_queue);
  run_test("announce_after_membership", test_announce_after_membership);
  run_test("group_hello_does_not_amplify", test_group_hello_does_not_amplify);
  run_test("delayed_reply_expires_before_due", test_delayed_reply_expires_before_due);
  run_test("peer_send_rejects_impossible_bounds", test_peer_send_rejects_impossible_bounds);
  run_test("fault_duration_bound_and_clear", test_fault_duration_bound_and_clear);
  run_test("golden", test_golden);
  if (failures != 0) {
    std::fprintf(stderr, "%d bench checks failed\n", failures);
    return 1;
  }
  std::puts("RouteLoom bench tests passed");
  return 0;
}
