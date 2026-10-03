// Host regression tests for the real ESP-NOW Owner's ExpectedReply lease
// wiring (issue #117, PR B): the actual espnow runtime translation unit,
// compiled against the in-tree ESP-IDF/FreeRTOS stand-ins and driven
// through its public API on a fake clock. Covers what the portable
// SimReplyPort tests cannot: port installation, static and autonomy binding
// lifetime, driver registration, callback attribution, and stop teardown.

#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/espnow_runtime.hpp"
#include "routeloom/autonomy_wire.hpp"
#include "routeloom/node.hpp"
#include "routeloom/owner_pump.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "esp_now.h"
#include "idf_stubs.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

namespace routeloom::espnow {
struct EspNowRuntimeTestAccess {
  static std::uint32_t hil_rx_frames(const EspNowRuntime& runtime) noexcept {
    return runtime.hil_rx_frames_;
  }
  static const NodeConfig& wire_config(const EspNowRuntime& runtime) noexcept {
    return runtime.config_.node;
  }
  static ReplyPeerPort& reply(EspNowRuntime& runtime) noexcept {
    return runtime.reply_port_;
  }
  static Status raw_send(EspNowRuntime& runtime, const MacAddress& mac) noexcept {
    const std::uint8_t frame = 0x42;
    return runtime.send_raw(mac, ByteView{&frame, 1});
  }
  static void fence(EspNowRuntime& runtime) noexcept { runtime.channel_fence_tx(); }
  static bool fenced(const EspNowRuntime& runtime) noexcept {
    return runtime.fenced_outstanding_;
  }
  static void set_release_pending(EspNowRuntime& runtime, NodeId peer) noexcept {
    if (auto* record = runtime.find_peer(peer)) record->release_pending = true;
  }
  static void release_peer(EspNowRuntime& runtime, NodeId peer) noexcept {
    if (auto* record = runtime.find_peer(peer)) {
      runtime.release_autonomy_peer(*record, runtime.now_ms());
    }
  }
  static bool peer_registered(EspNowRuntime& runtime, NodeId peer) noexcept {
    const auto* record = runtime.find_peer(peer);
    return record != nullptr && record->driver_registered;
  }
  static void make_driverless(EspNowRuntime& runtime, NodeId peer) noexcept {
    if (auto* record = runtime.find_peer(peer)) record->driver_registered = false;
  }
  static void mark_transient(EspNowRuntime& runtime, const MacAddress& mac) noexcept {
    runtime.transient_peers_[0].mac = mac;
    runtime.transient_peers_[0].used = true;
  }
  static bool release_transient(EspNowRuntime& runtime) noexcept {
    return runtime.release_transient_peer(runtime.transient_peers_[0],
                                          kInvalidNodeId);
  }
  static bool transient_used(EspNowRuntime& runtime) noexcept {
    return runtime.transient_peers_[0].used;
  }
  static std::size_t live_uses(const EspNowRuntime& runtime) noexcept {
    return runtime.reply_leases_.live_use_count();
  }
  static routeloom::Status observe_context(EspNowRuntime& runtime,
                                           NodeId peer,
                                           std::uint32_t epoch) noexcept {
    const auto* record = runtime.find_peer(peer);
    if (record == nullptr) {
      return routeloom::Status::error(routeloom::StatusCode::NotFound,
                                      "test peer absent");
    }
    return reply(runtime).observe_authenticated_rx(
        routeloom::ReplyBinding{peer, record->binding_id, record->binding,
                                epoch});
  }
};
}  // namespace routeloom::espnow

namespace {

int failures = 0;
#define CHECK(expr)                                                   \
  do {                                                                \
    if (!(expr)) {                                                    \
      std::fprintf(stderr, "CHECK failed %s:%d: %s\n", __FILE__,      \
                   __LINE__, #expr);                                  \
      ++failures;                                                     \
    }                                                                 \
  } while (false)

using routeloom::ByteView;
using routeloom::DeliveryState;
using routeloom::MessageId;
using routeloom::NodeId;
using routeloom::SendOptions;
using routeloom::espnow::EspNowRuntime;
using routeloom::espnow::EspNowRuntimeConfig;
using routeloom::espnow::EspNowRuntimeTestAccess;
using routeloom::espnow::MacAddress;
using routeloom_test::CapturingObserver;
using routeloom_test::TestSecurity;

constexpr NodeId kSelf = 1;
constexpr NodeId kPeer = 2;
// The stub's default station MAC (these tests never call set_mac).
const std::array<std::uint8_t, 6> kSelfMac{{0x02, 0x11, 0x22, 0x33, 0x44, 0x55}};
const std::array<std::uint8_t, 6> kBroadcast{{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}};

EspNowRuntimeConfig make_config() {
  EspNowRuntimeConfig config{};
  config.node.network = 0xA11CE;
  config.node.node = kSelf;
  config.node.message_session = 101;
  config.node.boot_incarnation = 0xB001;
  config.node.link_epoch = 1;
  config.node.end_epoch = 1;
  config.node.route_advertisement_period_ms = 100;
  config.node.route_lifetime_ms = 1000;
  config.channel = 6;
  config.max_tx_power_qdbm = 80;
  return config;
}

MacAddress peer_mac() {
  MacAddress mac{};
  const std::uint8_t bytes[6] = {0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x02};
  std::memcpy(mac.bytes.data(), bytes, sizeof(bytes));
  return mac;
}

MacAddress self_mac() {
  MacAddress mac{};
  const std::uint8_t bytes[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
  std::memcpy(mac.bytes.data(), bytes, sizeof(bytes));
  return mac;
}

// --- Real NeighborDiscovery engines bound to the real runtime --------------
// The §4-B/D regression needs the actual runtime surfaces the portable
// harness cannot reach: driver-peer release for a STALE binding, on-demand
// re-registration inside send_wire, and note_route_repair bridging a mesh
// demand into the discovery engine.

class MemberHooks final : public routeloom::MembershipHooks {
 public:
  bool local_member(routeloom::NetworkId) const noexcept override { return true; }
  bool known_member(routeloom::NodeId, routeloom::NetworkId) const noexcept override {
    return true;
  }
  bool approve_join(routeloom::NodeId, routeloom::NetworkId) noexcept override {
    return true;
  }
};

class SequenceEntropy final : public routeloom::EntropySource {
 public:
  explicit SequenceEntropy(const std::uint32_t seed) : state_(seed) {}
  routeloom::Status fill(const routeloom::MutableByteView out) noexcept override {
    for (std::size_t i = 0; i < out.size; ++i) {
      state_ = state_ * 1664525u + 1013904223u;
      out.data[i] = static_cast<std::uint8_t>(state_ >> 24U);
    }
    return routeloom::Status::success();
  }

 private:
  std::uint32_t state_;
};

routeloom::MacAddress core_mac(const MacAddress& mac) {
  routeloom::MacAddress out{};
  std::memcpy(out.data(), mac.bytes.data(), out.size());
  return out;
}

routeloom::DiscoveryConfig discovery_cfg(const NodeId node,
                                         const routeloom::MacAddress mac) {
  routeloom::DiscoveryConfig cfg{};
  cfg.node = node;
  cfg.mac = mac;
  cfg.network = make_config().node.network;
  cfg.network_hint = 0xC0FFEE;
  cfg.capability_bits = 1;
  cfg.probe_timeout_ms = 200;
  cfg.cold_start_jitter_max_ms = 0;
  cfg.backoff_min_ms = 50;
  cfg.backoff_initial_max_ms = 100;
  cfg.backoff_max_ms = 400;
  cfg.awake_lease_ms = 400;
  cfg.idle_refresh_ms = 60000;
  // Park the steady-state stale cadence: recovery must come from the
  // mesh's repair demand, not the background re-probe budget.
  cfg.stale_reprobe_ms = 60000;
  cfg.stale_reprobe_attempts = 60;
  return cfg;
}

// Peer-side radio port: RLD1 replies are injected straight into the
// runtime's RX queue; Wire-lane autonomy payloads are wrapped into a sealed
// one-hop frame first — the peer's own TX path builds the same shape.
class PeerAutonomyPort final : public routeloom::DiscoveryPort {
 public:
  PeerAutonomyPort(TestSecurity& security, const routeloom::MacAddress self,
                   const NodeId node, const routeloom::NetworkId network,
                   const NodeId host)
      : security_(security), self_(self), node_(node), network_(network),
        host_(host) {}

  routeloom::Status send_rld1(const routeloom::MacAddress&,
                              const ByteView encoded) noexcept override {
    if (paused_) return refused();
    if (!idf_stub::inject_rx(self_.data(), encoded.data, encoded.size)) {
      return refused();
    }
    return routeloom::Status::success();
  }

  routeloom::Status send_wire(routeloom::BindingId,
                              const routeloom::MacAddress&,
                              const routeloom::FrameType type,
                              const ByteView payload) noexcept override {
    if (paused_) return refused();
    routeloom::wire::PlainFrame frame{};
    frame.header.type = type;
    frame.header.delivery = routeloom::DeliveryClass::BestEffort;
    frame.header.hop_remaining = 1;
    frame.header.network = network_;
    frame.header.origin = node_;
    frame.header.destination = host_;
    frame.header.previous_hop = node_;
    frame.header.next_hop = host_;
    frame.header.message = MessageId{0xBEEF0001, ++sequence_};
    frame.header.remaining_deadline_ms = 500;
    frame.header.original_lifetime_ms = 500;
    frame.header.link_epoch = 1;
    frame.header.end_epoch = 1;
    frame.payload_size = payload.size;
    if (payload.size > 0) {
      std::memcpy(frame.payload.data(), payload.data, payload.size);
    }
    routeloom::wire::EncodedFrame encoded{};
    const routeloom::Status sealed =
        routeloom::wire::encode_new(frame, security_, encoded);
    if (!sealed) return sealed;
    if (!idf_stub::inject_rx(self_.data(), encoded.bytes.data(),
                            encoded.size)) {
      return refused();
    }
    return routeloom::Status::success();
  }

  // A partition: both TX directions stop delivering until cleared.
  bool paused_{false};

 private:
  static routeloom::Status refused() {
    return routeloom::Status::error(routeloom::StatusCode::WouldBlock,
                                    "radio cut");
  }

  TestSecurity& security_;
  routeloom::MacAddress self_{};
  NodeId node_;
  routeloom::NetworkId network_;
  NodeId host_;
  std::uint32_t sequence_{0};
};

class ReenteringSecurity final : public routeloom::SecurityProvider {
 public:
  EspNowRuntime* runtime{nullptr};
  mutable bool armed{false};
  mutable routeloom::Status nested_acquire{};
  mutable routeloom::Status nested_register{};
  std::uint32_t tx_context{1};
  std::uint32_t rx_context{1};
  bool ready() const noexcept override { return true; }
  routeloom::Status tx_epoch(routeloom::SecurityScope, NodeId,
                              std::uint32_t& epoch) noexcept override {
    epoch = tx_context;
    return routeloom::Status::success();
  }
  routeloom::Status current_rx_epoch(routeloom::SecurityScope scope, NodeId peer,
                                      std::uint32_t& epoch) const noexcept override {
    epoch = rx_context;
    if (armed && scope == routeloom::SecurityScope::Link &&
        peer == kPeer && runtime != nullptr) {
      armed = false;
      routeloom::ReplyLeaseToken token{};
      nested_acquire = EspNowRuntimeTestAccess::reply(*runtime).acquire(
          routeloom::ReplyBinding{kPeer, routeloom::BindingId{UINT32_MAX},
                                  routeloom::BindingGeneration{1}, epoch},
          1000, 0, token);
      nested_register = runtime->register_neighbor(kPeer, peer_mac(), 2);
    }
    return routeloom::Status::success();
  }
  routeloom::Status next_counter(const routeloom::SecurityContext& context,
                                 std::uint64_t& counter) noexcept override {
    return base_.next_counter(context, counter);
  }
  routeloom::Status seal(
      const routeloom::SecurityContext& context, std::uint64_t counter,
      ByteView aad, ByteView plain, routeloom::MutableByteView ciphertext,
      std::array<std::uint8_t, routeloom::kAeadTagSize>& tag) noexcept override {
    return base_.seal(context, counter, aad, plain, ciphertext, tag);
  }
  routeloom::Status open(
      const routeloom::SecurityContext& context, std::uint64_t counter,
      ByteView aad, ByteView ciphertext,
      const std::array<std::uint8_t, routeloom::kAeadTagSize>& tag,
      routeloom::MutableByteView plain) noexcept override {
    return base_.open(context, counter, aad, ciphertext, tag, plain);
  }
 private:
  TestSecurity base_;
};

void test_security_callback_cannot_reenter_owner_lease() {
  idf_stub::reset();
  ReenteringSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  security.runtime = &runtime;
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());
  security.armed = true;
  routeloom::ReplyBinding snapshot{};
  CHECK(EspNowRuntimeTestAccess::reply(runtime)
            .snapshot_binding(kPeer, snapshot)
            .ok());
  CHECK(security.nested_acquire.code == routeloom::StatusCode::Busy);
  CHECK(security.nested_register.code == routeloom::StatusCode::Busy);
  CHECK(EspNowRuntimeTestAccess::live_uses(runtime) == 0);
  runtime.stop();
}

void test_p6_binding_tracks_current_receive_context() {
  idf_stub::reset();
  ReenteringSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  std::uint32_t binding = 0;
  CHECK(runtime.p6_link_binding(kPeer, binding).ok());
  CHECK(binding == 1);
  security.rx_context = 2;
  CHECK(runtime.p6_link_binding(kPeer, binding).ok());
  CHECK(binding == 2);
  security.rx_context = 0;
  CHECK(runtime.p6_link_binding(kPeer, binding).code == routeloom::StatusCode::InvalidState);
  CHECK(binding == 0);
  runtime.stop();
}

// The runtime installs its lease port before node start: without it the
// node refuses to start ("reply peer port not attached") and no firmware
// admission can run at all.
void test_boot_installs_lease_port() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  runtime.stop();
}

class CapturingBootstrap final : public routeloom::espnow::BootstrapRld1Sink {
 public:
  void on_bootstrap_rld1(const routeloom::sdkv1::JoinRxMeta&,
                         std::uint32_t, ByteView, routeloom::MonotonicMs) noexcept override {
    ++received;
  }
  unsigned received{0};
};

void test_prestart_owner_pump() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CapturingBootstrap bootstrap;
  CHECK(runtime.attach_bootstrap_sink(bootstrap).ok());
  std::array<std::uint8_t, routeloom::autonomy::kRld1HeaderSize> rld1{};
  rld1[0] = 'R'; rld1[1] = 'L'; rld1[2] = 'D'; rld1[3] = '1';
  rld1[4] = routeloom::autonomy::kRld1Version;
  rld1[5] = static_cast<std::uint8_t>(routeloom::FrameType::Discover);
  rld1[6] = 0;
  rld1[7] = static_cast<std::uint8_t>(rld1.size());
  rld1[8] = 0;
  rld1[9] = static_cast<std::uint8_t>(rld1.size());
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), kBroadcast.data(), rld1.data(),
                            rld1.size()));
  runtime.poll_once();
  CHECK(bootstrap.received == 1);

  routeloom::RadioOperation move{};
  move.kind = routeloom::RadioOperationKind::ChannelCutover;
  move.deadline_ms = 3000;
  move.constraints.channel = 7;
  move.constraints.outage_permitted = true;
  const routeloom::OperationToken token = runtime.request_radio_operation(move);
  CHECK(token != routeloom::kInvalidOperationToken);
  routeloom::OperationResult result{};
  for (int i = 0; i < 10; ++i) {
    runtime.poll_once();
    CHECK(runtime.radio_operation_result(token, result));
    if (result.outcome != routeloom::OperationOutcome::Pending) break;
    idf_stub::advance_ms(1);
  }
  CHECK(result.outcome == routeloom::OperationOutcome::Applied);
  CHECK(runtime.committed_channel() == 7);
  runtime.stop();
}

struct CountingConfigSink final : routeloom::ConfigEndpointSink {
  unsigned frames{0};
  unsigned jobs{0};
  unsigned polls{0};
  bool last_hop_accepted{false};
  void on_config_frame(NodeId, const routeloom::wire::PlainFrame&,
                       routeloom::MonotonicMs) noexcept override {
    ++frames;
  }
  void on_config_job_done(const MessageId&, bool accepted, const char*,
                          routeloom::MonotonicMs) noexcept override {
    ++jobs;
    last_hop_accepted = accepted;
  }
  void poll(routeloom::MonotonicMs) noexcept override { ++polls; }
};

void test_owner_drives_config_component() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  CountingConfigSink sink;
  EspNowRuntimeConfig config = make_config();
  config.node.route_lifetime_ms = 60000;
  EspNowRuntime runtime(config, security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.node().set_config_sink(&sink).ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());

  routeloom::wire::PlainFrame plain{};
  plain.header.type = routeloom::FrameType::Control;
  plain.header.flags = routeloom::wire::kFlagEndProtected;
  plain.header.delivery = routeloom::DeliveryClass::Reliable;
  plain.header.hop_remaining = 1;
  plain.header.network = make_config().node.network;
  plain.header.origin = kPeer;
  plain.header.destination = kSelf;
  plain.header.previous_hop = kPeer;
  plain.header.next_hop = kSelf;
  plain.header.message = MessageId{202, 1};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 1;
  plain.header.end_epoch = 1;
  plain.payload[0] = 1;
  plain.payload_size = 1;
  routeloom::wire::EncodedFrame encoded{};
  CHECK(routeloom::wire::encode_new(plain, security, encoded).ok());
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), kSelfMac.data(), encoded.bytes.data(),
                            encoded.size));
  runtime.poll_once();
  CHECK(sink.frames == 1);
  CHECK(sink.polls == 1);

  // The same Owner drive must deliver outbound job completion as well.
  // No peer hop ACK is injected, so the bounded job fails honestly.
  for (unsigned sent = 0; sent < 9; ++sent) {
    MessageId job{};
    const routeloom::Status queued = runtime.node().send_typed(routeloom::FrameType::Control, kPeer,
                                    ByteView{plain.payload.data(), 1}, 1000,
                                    runtime.now_ms(), job);
    if (!queued) std::fprintf(stderr, "config send %u: %s\n", sent, queued.detail);
    CHECK(queued.ok());
    if (!queued) break;
    for (unsigned i = 0; i < 600 && sink.jobs <= sent; ++i) {
      idf_stub::advance_ms(5);
      runtime.poll_once();
      idf_stub::complete_send(true);
    }
    CHECK(sink.jobs == sent + 1);
    CHECK(runtime.node().component_events_pending() == 0);
  }
  CHECK(!sink.last_hop_accepted);
  runtime.stop();
}

// A radio that refills the event queue while the Owner drains it: every
// dequeue injects the next frame until kRefillTotal frames were offered.
struct RefillingRadio {
  static constexpr unsigned kRefillTotal = 200;
  TestSecurity* security{nullptr};
  unsigned injected{0};
  bool inject_next() {
    if (injected >= kRefillTotal) return false;
    routeloom::wire::PlainFrame plain{};
    plain.header.type = routeloom::FrameType::Data;
    plain.header.flags = routeloom::wire::kFlagEndProtected;
    plain.header.delivery = routeloom::DeliveryClass::BestEffort;
    plain.header.hop_remaining = 1;
    plain.header.network = make_config().node.network;
    plain.header.origin = kPeer;
    plain.header.destination = kSelf;
    plain.header.previous_hop = kPeer;
    plain.header.next_hop = kSelf;
    plain.header.message = MessageId{204, injected + 1};
    plain.header.remaining_deadline_ms = 5000;
    plain.header.original_lifetime_ms = 5000;
    plain.header.link_epoch = 1;
    plain.header.end_epoch = 1;
    plain.payload[0] = static_cast<std::uint8_t>(injected >> 8);
    plain.payload[1] = static_cast<std::uint8_t>(injected);
    plain.payload_size = 2;
    routeloom::wire::EncodedFrame encoded{};
    if (!routeloom::wire::encode_new(plain, *security, encoded).ok()) return false;
    if (!idf_stub::inject_rx(peer_mac().bytes.data(), kSelfMac.data(),
                             encoded.bytes.data(), encoded.size)) return false;
    ++injected;
    return true;
  }
  static void on_receive(void* self) { (void)static_cast<RefillingRadio*>(self)->inject_next(); }
};

// Records which refill frames reached the node, in order: each is either
// delivered or refused for lack of an ACK slot (the test sends no ACKs).
struct ArrivalObserver final : routeloom::NodeObserver {
  std::vector<std::uint64_t> arrivals;
  void on_message(const routeloom::MessageKey& key, NodeId,
                  ByteView) noexcept override {
    note(&key.id);
  }
  void on_delivery(const routeloom::DeliveryResult&) noexcept override {}
  void on_diagnostic(const char*, NodeId, const MessageId* id) noexcept override {
    note(id);
  }
  void note(const MessageId* id) {
    if (id != nullptr && id->session == 204) arrivals.push_back(id->sequence);
  }
};

// One pass drains at most kRxDrainPerPass events; the rest stays queued in
// FIFO order, none is lost, and the components still run every pass.
void test_rx_drain_is_bounded_per_pass() {
  idf_stub::reset();
  TestSecurity security;
  ArrivalObserver observer;
  CountingConfigSink sink;
  EspNowRuntimeConfig config = make_config();
  config.node.route_lifetime_ms = 60000;
  EspNowRuntime runtime(config, security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.node().set_config_sink(&sink).ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());

  RefillingRadio radio{};
  radio.security = &security;
  while (radio.injected < EspNowRuntime::kEventQueueCapacity && radio.inject_next()) {}
  CHECK(radio.injected == EspNowRuntime::kEventQueueCapacity);
  idf_stub::set_receive_hook(&RefillingRadio::on_receive, &radio);
  unsigned passes = 0;
  while (observer.arrivals.size() < RefillingRadio::kRefillTotal && passes < 50) {
    const std::size_t before = observer.arrivals.size();
    const unsigned polls_before = sink.polls;
    runtime.poll_once();
    ++passes;
    CHECK(observer.arrivals.size() - before <= EspNowRuntime::kRxDrainPerPass);
    CHECK(sink.polls == polls_before + 1);
  }
  idf_stub::set_receive_hook(nullptr, nullptr);
  CHECK(passes > 1);
  CHECK(observer.arrivals.size() == RefillingRadio::kRefillTotal);
  for (std::size_t i = 0; i < observer.arrivals.size(); ++i) {
    CHECK(observer.arrivals[i] == i + 1);
  }
  CHECK(runtime.owner_stats().polls == passes);
  CHECK(runtime.owner_stats().rx_queue_max == EspNowRuntime::kEventQueueCapacity);
  CHECK(runtime.owner_stats().empty_polls == 0);
  runtime.poll_once();
  CHECK(runtime.owner_stats().empty_polls == 1);
  runtime.stop();
}

void test_rx_queue_peak_during_drain() {
  idf_stub::reset();
  TestSecurity security;
  ArrivalObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  RefillingRadio radio{};
  radio.security = &security;
  CHECK(radio.inject_next());
  idf_stub::set_receive_hook(+[](void* context) {
    idf_stub::set_receive_hook(nullptr, nullptr);
    auto& source = *static_cast<RefillingRadio*>(context);
    while (source.injected <= EspNowRuntime::kEventQueueCapacity && source.inject_next()) {}
  }, &radio);
  runtime.poll_once();
  CHECK(runtime.owner_stats().rx_queue_max == EspNowRuntime::kEventQueueCapacity);
  runtime.stop();
}

// The Owner wait rounds up to whole ticks: a 2 ms wait under the 100 Hz
// stub tick blocks one tick instead of zero (a busy spin).
void test_owner_wait_rounds_up_to_a_tick() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  runtime.wait_for_event(0);
  CHECK(idf_stub::last_peek_ticks() == 1);
  runtime.wait_for_event(routeloom::kOwnerPollPeriodMs);
  CHECK(idf_stub::last_peek_ticks() == 1);
  runtime.wait_for_event(15);
  CHECK(idf_stub::last_peek_ticks() == 2);
  runtime.wait_for_event(UINT64_MAX / configTICK_RATE_HZ + 1);
  CHECK(idf_stub::last_peek_ticks() == UINT32_MAX - 1);
  runtime.stop();
}

void test_notification_keeps_external_and_racing_wakes() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  runtime.bind_wake_task(xTaskGetCurrentTaskHandle());
  // An external queue (post/USB/worker) is not visible to runtime's wait.
  runtime.notify_owner();
  runtime.wait_for_event(1000);
  CHECK(idf_stub::last_peek_ticks() == 0);
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  const auto inject = [](void*) {
    const std::uint8_t junk = 0;
    CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), &junk, 1));
  };
  idf_stub::set_notify_wait_hook(inject, nullptr);
  runtime.wait_for_event(1000);
  CHECK(idf_stub::last_peek_ticks() == 0);
  const auto empty = runtime.owner_stats().empty_polls;
  runtime.poll_once();
  CHECK(runtime.owner_stats().empty_polls == empty);
  runtime.stop();
}

void test_unknown_rx_does_not_wake_owner() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  runtime.bind_wake_task(xTaskGetCurrentTaskHandle());
  idf_stub::enable_notify_clock();
  const std::uint8_t junk = 0;
  for (unsigned i = 0; i < 1000; ++i) {
    CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), &junk, 1));
    runtime.wait_for_event(0);
  }
  const auto stats = idf_stub::notify_wait_stats();
  CHECK(stats.wakes == 0 && stats.blocks == 1000);
  CHECK(runtime.unknown_peer_rx() == 1000);
  runtime.stop();
}

void test_wake_budget_stops_radio_submissions() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize());
  CHECK(runtime.start());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1));
  CHECK(runtime.node().set_pause(routeloom::PauseReason::SurveyVisit,
                                 routeloom::pause::kBackgroundWork));
  const std::uint8_t frame = 42;
  runtime.set_radio_deadline(1000);
  idf_stub::set_now_us(999000);
  CHECK(EspNowRuntimeTestAccess::raw_send(runtime, peer_mac()));
  CHECK(idf_stub::complete_send(true));
  runtime.poll_once();
  const auto submissions = idf_stub::send_count();
  idf_stub::set_now_us(1000000);
  CHECK(EspNowRuntimeTestAccess::raw_send(runtime, peer_mac()).code ==
        routeloom::StatusCode::DiscoveryBudgetExhausted);
  CHECK(runtime.send(kPeer, 1, {&frame, 1}).code ==
        routeloom::StatusCode::DiscoveryBudgetExhausted);
  CHECK(idf_stub::send_count() == submissions);
  runtime.stop();
}

void test_idle_deadline_poll_equivalence() {
  std::uint32_t polls[2]{};
  std::vector<std::string> diagnostics[2];
  for (unsigned adaptive = 0; adaptive < 2; ++adaptive) {
    idf_stub::reset();
    TestSecurity security;
    CapturingObserver observer;
    EspNowRuntime runtime(make_config(), security, observer);
    CHECK(runtime.initialize().ok());
    CHECK(runtime.start().ok());
    routeloom::MonotonicMs now = 0;
    while (now <= 60000) {
      idf_stub::set_now_us(static_cast<std::int64_t>(now) * 1000);
      runtime.poll_once();
      const routeloom::MonotonicMs due = runtime.next_deadline(now);
      CHECK(due > now);
      if (adaptive != 0) {
        const auto stats = runtime.node().work_stats();
        CHECK(runtime.node().poll(now + 1));
        CHECK(runtime.node().work_stats().expiry_slots_scanned == stats.expiry_slots_scanned);
      }
      now = adaptive != 0 ? std::min(due, now + 1000) : now + 1;
    }
    polls[adaptive] = runtime.owner_stats().polls;
    CHECK(idf_stub::send_count() == 0);
    CHECK(observer.messages.empty());
    CHECK(observer.delivery_events.empty());
    diagnostics[adaptive] = observer.diagnostics;
    CHECK(observer.group_messages.empty());
    CHECK(observer.group_results.empty());
    CHECK(runtime.node().work_stats().expiry_slots_scanned == 0);
    runtime.stop();
  }
  CHECK(diagnostics[0] == diagnostics[1]);
  CHECK(polls[0] == 60001);
  CHECK(polls[1] == 601);
  std::printf("idle Owner polls: eager=%u deadline=%u\n", polls[0], polls[1]);
}

void test_active_deadline_noop() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize());
  CHECK(runtime.start());
  idf_stub::set_now_us(10000);
  SendOptions options{};
  options.lifetime_ms = 501;
  MessageId id{};
  CHECK(runtime.send_application(99, ByteView{}, options, id));
  runtime.poll_once();
  const auto due = runtime.node().next_deadline(10);
  CHECK(due > 12 && due <= 511);
  const auto scanned = runtime.node().work_stats().expiry_slots_scanned;
  CHECK(runtime.node().poll(11));
  CHECK(runtime.node().work_stats().expiry_slots_scanned == scanned);
  CHECK(runtime.node().next_deadline(11) == due);
  // A new application event invalidates the cached timer, even at the
  // same timestamp. A clock regression also forces a fresh pass.
  CHECK(runtime.send_application(98, ByteView{}, options, id));
  CHECK(runtime.node().next_deadline(10) == 10);
  CHECK(runtime.node().poll(10));
  CHECK(runtime.node().next_deadline(9) == 9);
  runtime.stop();
}

void test_owner_trace_includes_node_work() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  idf_stub::advance_ms(60000);
  runtime.poll_once();
  CHECK(idf_stub::log_contains("owner expiry_slots="));
  CHECK(idf_stub::log_contains("hop_accept_expired="));
  runtime.stop();
}

// Once a static peer's authenticated RX epoch is known, Reliable DATA reaches
// the driver and waits for its hop ACK. The absence of a remote ACK may still
// fail the delivery after the bounded retries.
void test_reliable_to_static_peer_uses_binding() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());

  const std::uint8_t payload[] = {0x10, 0x20, 0x30};
  MessageId id{};
  CHECK(runtime
            .send_application(kPeer, ByteView{payload, sizeof(payload)},
                              SendOptions{}, id)
            .ok());

  // send_application reports Accepted synchronously. The stub driver
  // completes MAC sends but supplies no hop ACK.
  const auto terminal = [](DeliveryState state) {
    return state == DeliveryState::Delivered ||
           state == DeliveryState::Failed ||
           state == DeliveryState::Expired ||
           state == DeliveryState::CancelledBeforeTx ||
           state == DeliveryState::Indeterminate;
  };
  for (unsigned i = 0;
       i < 6000 && (observer.delivery_events.empty() ||
                    !terminal(observer.delivery_events.back().state));
       ++i) {
    idf_stub::advance_ms(5);
    runtime.poll_once();
    // The stub driver completes every send successfully; the completion
    // lands on the event queue and resolves on the next poll — background
    // traffic cycles instead of wedging the reserved lane.
    idf_stub::complete_send(true);
  }
  CHECK(!observer.delivery_events.empty());
  bool waited_for_hop_ack = false;
  for (const auto& event : observer.delivery_events) {
    if (event.id == id && event.state == DeliveryState::WaitingForHopAccept) {
      waited_for_hop_ack = true;
      break;
    }
  }
  CHECK(waited_for_hop_ack);
  if (!observer.delivery_events.empty()) {
    const auto& result = observer.delivery_events.back();
    CHECK(result.id == id);
    CHECK(result.state == DeliveryState::Failed);
    CHECK(result.reason == nullptr ||
          std::strcmp(result.reason, "no live binding for peer") != 0);
  }
  runtime.stop();
}

void test_old_rx_epoch_cannot_acquire_current_binding() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());

  routeloom::wire::PlainFrame plain{};
  plain.header.type = routeloom::FrameType::Data;
  plain.header.flags = routeloom::wire::kFlagEndProtected;
  plain.header.delivery = routeloom::DeliveryClass::Reliable;
  plain.header.hop_remaining = 1;
  plain.header.network = make_config().node.network;
  plain.header.origin = kPeer;
  plain.header.destination = kSelf;
  plain.header.previous_hop = kPeer;
  plain.header.next_hop = kSelf;
  plain.header.message = MessageId{202, 1};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 2;
  plain.header.end_epoch = 1;
  plain.payload[0] = 0x42;
  plain.payload_size = 1;
  routeloom::wire::EncodedFrame encoded{};
  CHECK(routeloom::wire::encode_new(plain, security, encoded).ok());
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), kSelfMac.data(), encoded.bytes.data(),
                            encoded.size));
  runtime.poll_once();
  CHECK(observer.messages.size() == 1);
  routeloom::ReplyBinding current{};
  CHECK(EspNowRuntimeTestAccess::reply(runtime)
            .snapshot_binding(kPeer, current)
            .ok());
  CHECK(current.rx_context_id == 2);

  plain.header.message.sequence = 2;
  plain.header.link_epoch = 1;
  CHECK(routeloom::wire::encode_new(plain, security, encoded).ok());
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), kSelfMac.data(), encoded.bytes.data(),
                            encoded.size));
  runtime.poll_once();
  CHECK(observer.messages.size() == 1);
  runtime.stop();
}

void test_distinct_session_tx_and_rx_contexts() {
  idf_stub::reset();
  ReenteringSecurity security;
  security.tx_context = 22;
  security.rx_context = 11;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());

  routeloom::wire::PlainFrame plain{};
  plain.header.type = routeloom::FrameType::Data;
  plain.header.flags = routeloom::wire::kFlagEndProtected;
  plain.header.delivery = routeloom::DeliveryClass::Reliable;
  plain.header.hop_remaining = 1;
  plain.header.network = make_config().node.network;
  plain.header.origin = kPeer;
  plain.header.destination = kSelf;
  plain.header.previous_hop = kPeer;
  plain.header.next_hop = kSelf;
  plain.header.message = MessageId{203, 1};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 11;
  plain.header.end_epoch = 1;
  plain.payload[0] = 0x42;
  plain.payload_size = 1;
  TestSecurity peer_cipher;
  routeloom::wire::EncodedFrame encoded{};
  CHECK(routeloom::wire::encode_new(plain, peer_cipher, encoded).ok());
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), kSelfMac.data(), encoded.bytes.data(),
                            encoded.size));
  runtime.poll_once();
  CHECK(observer.messages.size() == 1);
  routeloom::ReplyBinding bound{};
  CHECK(EspNowRuntimeTestAccess::reply(runtime)
            .snapshot_binding(kPeer, bound)
            .ok());
  CHECK(bound.rx_context_id == 11);
  runtime.stop();
}

void test_stop_drains_node_reply_uses() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());
  routeloom::wire::PlainFrame plain{};
  plain.header.type = routeloom::FrameType::Data;
  plain.header.flags = routeloom::wire::kFlagEndProtected;
  plain.header.delivery = routeloom::DeliveryClass::Reliable;
  plain.header.hop_remaining = 1;
  plain.header.network = make_config().node.network;
  plain.header.origin = kPeer;
  plain.header.destination = kSelf;
  plain.header.previous_hop = kPeer;
  plain.header.next_hop = kSelf;
  plain.header.message = MessageId{202, 2};
  plain.header.remaining_deadline_ms = 5000;
  plain.header.original_lifetime_ms = 5000;
  plain.header.link_epoch = 1;
  plain.header.end_epoch = 1;
  plain.payload[0] = 0x42;
  plain.payload_size = 1;
  routeloom::wire::EncodedFrame encoded{};
  CHECK(routeloom::wire::encode_new(plain, security, encoded).ok());
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), kSelfMac.data(), encoded.bytes.data(),
                            encoded.size));
  runtime.poll_once();
  CHECK(runtime.node().txn_in_flight() == 1);
  CHECK(EspNowRuntimeTestAccess::live_uses(runtime) == 1);
  runtime.stop();
  CHECK(runtime.node().txn_in_flight() == 0);
  CHECK(EspNowRuntimeTestAccess::live_uses(runtime) == 0);
}

void test_stale_binding_keeps_reserved_reply_sendable() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());

  auto& port = EspNowRuntimeTestAccess::reply(runtime);
  routeloom::ReplyBinding binding{};
  CHECK(port.snapshot_binding(kPeer, binding).ok());
  CHECK(port.probe_acquire(binding, 1000, 0).ok());
  CHECK(EspNowRuntimeTestAccess::live_uses(runtime) == 0);
  routeloom::ReplyLeaseToken use{};
  CHECK(port.acquire(binding, 1000, 0, use).ok());
  EspNowRuntimeTestAccess::set_release_pending(runtime, kPeer);
  CHECK(port.probe_acquire(binding, 1000, 0).code == routeloom::StatusCode::Conflict);
  CHECK(EspNowRuntimeTestAccess::live_uses(runtime) == 1);
  CHECK(port.observe_authenticated_rx(binding).ok());
  const std::uint8_t frame = 0x42;
  CHECK(port.send_reply(use, 1, ByteView{&frame, 1}, 0).ok());
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  CHECK(port.release(use).ok());
  runtime.stop();
}

void test_driverless_authenticated_recovery() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());
  EspNowRuntimeTestAccess::make_driverless(runtime, kPeer);
  // A stale binding is still valid for authenticated Probe/Result RX even
  // when the send-side driver peer has been released.
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());
  CHECK(!EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 0).ok());
  runtime.stop();
}

// §4 B/D end-to-end over the real runtime: bind a real NeighborDiscovery
// engine to the runtime, partition the radio until the peer lapses Stale
// and the runtime releases its driver peer, then repair on mesh demand —
// the early probe must re-arm the physical peer and the authenticated
// Result must restore Reachable without a new exchange.
void test_stale_peer_probe_recovery_over_runtime() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());

  MemberHooks hooks_a;
  MemberHooks hooks_b;
  SequenceEntropy entropy_a(11);
  SequenceEntropy entropy_b(22);
  routeloom::NullDiscoveryObserver disc_observer;
  routeloom::DevPskAuthenticator auth_a(security, 1);
  TestSecurity peer_security;
  routeloom::DevPskAuthenticator auth_b(peer_security, 1);

  routeloom::NeighborDiscovery engine_a(
      discovery_cfg(kSelf, core_mac(self_mac())), runtime, auth_a, hooks_a,
      entropy_a, disc_observer);
  CHECK(runtime.attach_autonomy(engine_a).ok());
  CHECK(runtime.start().ok());

  PeerAutonomyPort port_b(peer_security, core_mac(peer_mac()), kPeer,
                          make_config().node.network, kSelf);
  routeloom::NeighborDiscovery engine_b(
      discovery_cfg(kPeer, core_mac(peer_mac())), port_b, auth_b, hooks_b,
      entropy_b, disc_observer);

  const routeloom::MonotonicMs t0 = runtime.now_ms();
  CHECK(engine_a.start(t0).ok());
  CHECK(engine_b.start(t0).ok());

  // Deliver one captured physical send to the peer engine. RLD1 envelopes
  // ride the bootstrap lane; everything else is a sealed wire-lane frame.
  bool cut = false;
  const auto ferry = [&] {
    idf_stub::TxFrame tx{};
    while (idf_stub::pop_tx(tx)) {
      if (cut) continue;
      const routeloom::MonotonicMs now = idf_stub::now_us() / 1000;
      const ByteView bytes{tx.bytes, tx.length};
      if (bytes.size >= 4 && std::memcmp(bytes.data, "RLD1", 4) == 0) {
        routeloom::MacAddress dest{};
        std::memcpy(dest.data(), tx.dest, dest.size());
        engine_b.on_rld1_rx(
            routeloom::DiscoveryRxMetadata{core_mac(self_mac()), dest}, bytes,
            now);
        continue;
      }
      routeloom::wire::LinkOpenedFrame opened{};
      if (!routeloom::wire::open_link(bytes, kPeer, peer_security, opened)
               .ok()) {
        continue;
      }
      engine_b.on_wire_rx(
          core_mac(self_mac()), opened.header.type,
          ByteView{opened.protected_payload.data(),
                   opened.protected_payload_size},
          now);
    }
  };
  const auto step = [&] {
    idf_stub::advance_ms(5);
    runtime.poll_once();
    idf_stub::complete_send(true);
    engine_b.poll(idf_stub::now_us() / 1000);
    ferry();
  };
  const auto phase_of = [](routeloom::NeighborDiscovery& engine,
                           const NodeId peer) {
    routeloom::NeighborPhase phase = routeloom::NeighborPhase::Candidate;
    engine.phase_of(peer, phase);
    return phase;
  };

  CHECK(engine_a.begin_discovery(t0).ok());
  bool bound = false;
  for (int i = 0; i < 4000 && !bound; ++i) {
    step();
    bound = phase_of(engine_a, kPeer) == routeloom::NeighborPhase::Reachable &&
            phase_of(engine_b, kSelf) == routeloom::NeighborPhase::Reachable;
  }
  CHECK(bound);
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  // Firmware leaves this mode armed while the Owner handles handshakes.
  engine_a.set_member_handshake_mode(true);

  // Partition both directions until the lease lapses Stale on both engines
  // and the runtime releases the physical driver peer (binding kept).
  cut = true;
  port_b.paused_ = true;
  bool stale = false;
  for (int i = 0; i < 4000 && !stale; ++i) {
    step();
    stale = phase_of(engine_a, kPeer) == routeloom::NeighborPhase::Stale &&
            phase_of(engine_b, kSelf) == routeloom::NeighborPhase::Stale;
  }
  CHECK(stale);
  CHECK(!EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));

  // The mesh loses its route through the peer: the demand must drive an
  // early probe through send_wire, which re-arms the driver peer on demand.
  cut = false;
  port_b.paused_ = false;
  runtime.note_route_repair(kPeer, runtime.now_ms());
  CHECK(engine_a.stats().repair_demands == 1);
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));

  bool recovered = false;
  for (int i = 0; i < 2000 && !recovered; ++i) {
    step();
    recovered =
        phase_of(engine_a, kPeer) == routeloom::NeighborPhase::Reachable &&
        phase_of(engine_b, kSelf) == routeloom::NeighborPhase::Reachable;
  }
  CHECK(recovered);
  CHECK(idf_stub::tx_drops() == 0);
  runtime.stop();
}

void test_driver_release_waits_for_use_and_callback() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());

  auto& port = EspNowRuntimeTestAccess::reply(runtime);
  routeloom::ReplyBinding binding{};
  CHECK(port.snapshot_binding(kPeer, binding).ok());
  routeloom::ReplyLeaseToken use{};
  CHECK(port.acquire(binding, 1000, 0, use).ok());
  EspNowRuntimeTestAccess::release_peer(runtime, kPeer);
  CHECK(idf_stub::del_peer_count() == 0);
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  CHECK(port.release(use).ok());
  const std::uint8_t frame = 0x42;
  CHECK(runtime.send(kPeer, 1, ByteView{&frame, 1}).ok());
  EspNowRuntimeTestAccess::release_peer(runtime, kPeer);
  CHECK(idf_stub::del_peer_count() == 0);
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  CHECK(idf_stub::complete_send(true));
  EspNowRuntimeTestAccess::release_peer(runtime, kPeer);
  CHECK(idf_stub::del_peer_count() == 1);
  CHECK(!EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  runtime.stop();
}

// A broadcast uses the Owner's reserved physical slot and the permanent
// driver peer, not a transient NodeId->MAC mapping or raw-send lane.
void test_route_broadcast_uses_reserved_radio_slot() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  const std::uint8_t frame = 0x42;
  CHECK(runtime.send(routeloom::kBroadcastNodeId, 1, ByteView{&frame, 1}).ok());
  CHECK(idf_stub::send_count() == 1);
  CHECK(idf_stub::last_send_to(routeloom::discovery_const::kBroadcastMac.data()));
  CHECK(runtime.send(routeloom::kBroadcastNodeId, 2, ByteView{&frame, 1}).code ==
        routeloom::StatusCode::WouldBlock);
  const auto airtime_before = runtime.node().congestion_stats().service_us_misc;
  idf_stub::advance_ms(2);
  CHECK(idf_stub::complete_send(true));
  runtime.poll_once();
  CHECK(runtime.node().congestion_stats().service_us_misc >= airtime_before + 2000);
  CHECK(runtime.node().telemetry_peer(routeloom::kBroadcastNodeId) == nullptr);
  CHECK(runtime.send(routeloom::kBroadcastNodeId, 2, ByteView{&frame, 1}).ok());
  CHECK(idf_stub::complete_send(false));
  runtime.stop();
}

void test_physical_tx_arbitrates_across_peers() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  MacAddress other = peer_mac();
  other.bytes[5] = 3;
  CHECK(runtime.register_neighbor(3, other, 1).ok());
  const std::uint8_t frame = 0x42;
  CHECK(runtime.send(kPeer, 1, ByteView{&frame, 1}).ok());
  CHECK(EspNowRuntimeTestAccess::raw_send(runtime, other).code ==
        routeloom::StatusCode::WouldBlock);
  CHECK(idf_stub::send_count() == 1);
  CHECK(idf_stub::complete_send(true));
  CHECK(EspNowRuntimeTestAccess::raw_send(runtime, other).ok());
  CHECK(runtime.send(kPeer, 2, ByteView{&frame, 1}).code ==
        routeloom::StatusCode::WouldBlock);
  CHECK(idf_stub::send_count() == 2);
  CHECK(idf_stub::complete_send(true));
  CHECK(runtime.send(kPeer, 2, ByteView{&frame, 1}).ok());
  CHECK(idf_stub::complete_send(true));
  runtime.stop();
}

void test_driver_delete_failure_keeps_slot_occupied() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());

  idf_stub::fail_del_peer(true);
  EspNowRuntimeTestAccess::release_peer(runtime, kPeer);
  CHECK(idf_stub::del_peer_count() == 1);
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  idf_stub::fail_del_peer(false);
  EspNowRuntimeTestAccess::release_peer(runtime, kPeer);
  CHECK(idf_stub::del_peer_count() == 2);
  CHECK(!EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  runtime.stop();
}

// Re-auth can leave transient bookkeeping beside a regular mapping for the
// same MAC. Releasing that bookkeeping must not delete the regular peer's
// physical ESP-NOW registration (C3 1->2->3 reset HIL, issue #169).
void test_transient_cleanup_keeps_regular_driver_peer() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  EspNowRuntimeTestAccess::mark_transient(runtime, peer_mac());
  const unsigned deletes_before = idf_stub::del_peer_count();
  CHECK(EspNowRuntimeTestAccess::release_transient(runtime));
  CHECK(!EspNowRuntimeTestAccess::transient_used(runtime));
  CHECK(idf_stub::del_peer_count() == deletes_before);
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  runtime.stop();
}

void test_failed_static_registration_does_not_claim_a_slot() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  idf_stub::fail_add_peer(true);
  CHECK(!runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  std::size_t occupied = 0;
  runtime.for_each_peer([&](NodeId, const MacAddress&, routeloom::RouteMetric,
                            bool) { ++occupied; });
  CHECK(occupied == 0);
  idf_stub::fail_add_peer(false);
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  runtime.stop();
}

void test_route_capacity_registration_rolls_back_driver_peer() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  auto& routes = const_cast<routeloom::RouteTable&>(runtime.node().routes());
  for (std::size_t i = 0; i < routeloom::kMaxRouteEntries; ++i) {
    const auto result = routes.consider(
        routeloom::RouteAdvertisement{1000 + i, 1, 1, 1}, kPeer, 1, 0,
        10000);
    CHECK(result == routeloom::RouteUpdateResult::Accepted);
  }
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).code ==
        routeloom::StatusCode::NoCapacity);
  CHECK(!EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  CHECK(idf_stub::del_peer_count() == 1);
  routes.expire(10001);
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  runtime.stop();
}

void test_failed_registration_delete_retries_before_slot_reuse() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  auto& routes = const_cast<routeloom::RouteTable&>(runtime.node().routes());
  for (std::size_t i = 0; i < routeloom::kMaxRouteEntries; ++i) {
    CHECK(routes.consider(
              routeloom::RouteAdvertisement{1000 + i, 1, 1, 1}, kPeer, 1, 0,
              10000) == routeloom::RouteUpdateResult::Accepted);
  }
  idf_stub::fail_del_peer(true);
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).code ==
        routeloom::StatusCode::RadioFailure);
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  routes.expire(10001);
  idf_stub::fail_del_peer(false);
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  CHECK(idf_stub::del_peer_count() == 2);
  runtime.stop();
}

void test_retired_binding_cannot_be_resurrected_by_registration() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());
  auto& port = EspNowRuntimeTestAccess::reply(runtime);
  routeloom::ReplyBinding old_binding{};
  CHECK(port.snapshot_binding(kPeer, old_binding).ok());
  routeloom::ReplyLeaseToken use{};
  CHECK(port.acquire(old_binding, 1000, 0, use).ok());

  EspNowRuntimeTestAccess::release_peer(runtime, kPeer);
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).code ==
        routeloom::StatusCode::Conflict);
  const std::uint8_t frame = 0x42;
  CHECK(port.send_reply(use, 1, ByteView{&frame, 1}, 0).code ==
        routeloom::StatusCode::Conflict);
  CHECK(port.release(use).ok());
  EspNowRuntimeTestAccess::release_peer(runtime, kPeer);
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  CHECK(EspNowRuntimeTestAccess::observe_context(runtime, kPeer, 1).ok());
  routeloom::ReplyBinding new_binding{};
  CHECK(port.snapshot_binding(kPeer, new_binding).ok());
  CHECK(new_binding.id != old_binding.id);
  runtime.stop();
}

void test_adopt_member_node_keeps_node_startable() {
  // Owner adoption (member now, dev next) reconstructs the node: the
  // #117 reply-lease port must be re-attached and adopted gateways must
  // run sufficient route timers, or node start refuses and the adopted
  // node never runs.
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntimeConfig config = make_config();
  EspNowRuntime runtime(config, security, observer);
  CHECK(runtime.initialize().ok());
  struct ConfigSink final : routeloom::ConfigEndpointSink {
    void on_config_frame(routeloom::NodeId, const routeloom::wire::PlainFrame&,
                         routeloom::MonotonicMs) noexcept override {}
    void on_config_job_done(const routeloom::MessageId&, bool, const char*,
                            routeloom::MonotonicMs) noexcept override {}
    void poll(routeloom::MonotonicMs) noexcept override {}
  } config_sink;
  struct ServiceSink final : routeloom::GatewayServiceSink {
    void on_service_payload(routeloom::NodeId, const routeloom::wire::PlainFrame&,
                            routeloom::MonotonicMs) noexcept override {}
    void on_service_job_done(const routeloom::MessageId&, bool, const char*,
                             routeloom::MonotonicMs) noexcept override {}
    void poll(routeloom::MonotonicMs) noexcept override {}
  } service_sink;
  struct DiagnosticReceiver final : routeloom::DiagnosticSink {
    void on_diagnostic_body(routeloom::NodeId, ByteView,
                            routeloom::MonotonicMs) noexcept override {}
  } diagnostic_sink;
  struct AppliedSink final : routeloom::AppliedEndpointSink {
    void on_applied_request(const routeloom::AppliedRequest&,
                            routeloom::AppliedReply& reply) noexcept override {
      reply.deferred = true;
    }
  } applied_sink;
  CHECK(runtime.node().set_config_sink(&config_sink).ok());
  CHECK(runtime.node().set_gateway_sink(&service_sink).ok());
  CHECK(runtime.node().set_diagnostic_sink(&diagnostic_sink).ok());
  CHECK(runtime.node().set_applied_sink(&applied_sink).ok());
  routeloom::NodeConfig adopted = config.node;
  adopted.node = 0x00A1000000001234ULL;
  adopted.network = 0x0A1B2C3DUL;
  adopted.message_session = 4242;
  adopted.boot_session = 4242;
  adopted.route_generation = 4242;
  adopted.route_gateways[0] = 0x00A1000000000001ULL;
  adopted.route_gateways[1] = 0x00A1000000000002ULL;
  CHECK(runtime.adopt_member_node(adopted).ok());
  CHECK(runtime.node().config_sink() == &config_sink);
  CHECK(runtime.node().gateway_sink() == &service_sink);
  CHECK(runtime.node().diagnostic_sink() == &diagnostic_sink);
  CHECK(runtime.node().applied_sink() == &applied_sink);
  // Probe/Result wire headers must use the installed identity, not the
  // firmware's pre-join static node/network after a reassigned join.
  CHECK(EspNowRuntimeTestAccess::wire_config(runtime).node == adopted.node);
  CHECK(EspNowRuntimeTestAccess::wire_config(runtime).network == adopted.network);
  CHECK(EspNowRuntimeTestAccess::wire_config(runtime).message_session ==
        adopted.message_session);
  // Adopted gateways run the product scoped timers (routing-scale.md §5):
  // the constructed flat defaults cannot satisfy the lease rule.
  CHECK(runtime.node().config().route_advertisement_period_ms ==
        routeloom::kScopedProductPeriodMs);
  CHECK(runtime.node().config().route_lifetime_ms ==
        routeloom::kScopedProductLifetimeMs);
  CHECK(runtime.start().ok());
  runtime.stop();
}

void test_adopt_member_node_keeps_sufficient_timers() {
  // Sufficient configured timers survive adoption untouched: only an
  // insufficient pair is raised to the product scoped values.
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntimeConfig config = make_config();
  config.node.route_advertisement_period_ms = 5000;
  config.node.route_lifetime_ms = 90000;
  EspNowRuntime runtime(config, security, observer);
  CHECK(runtime.initialize().ok());
  routeloom::NodeConfig adopted = config.node;
  adopted.node = 0x00A1000000001234ULL;
  adopted.network = 0x0A1B2C3DUL;
  adopted.message_session = 4242;
  adopted.boot_session = 4242;
  adopted.route_generation = 4242;
  CHECK(runtime.adopt_member_node(adopted).ok());
  CHECK(runtime.node().config().route_advertisement_period_ms == 5000);
  CHECK(runtime.node().config().route_lifetime_ms == 90000);
  CHECK(runtime.start().ok());
  runtime.stop();
}

std::uint8_t completion_macs[4][6] = {};
esp_now_send_status_t completion_status[4] = {};
int completion_count = 0;

void record_completion(const esp_now_send_info_t* info,
                       const esp_now_send_status_t status) noexcept {
  if (completion_count < 4 && info != nullptr && info->des_addr != nullptr) {
    std::memcpy(completion_macs[completion_count], info->des_addr, 6);
    completion_status[completion_count] = status;
  }
  ++completion_count;
}

// Multi-TX completion attribution (D04 mesh): two esp_now_send calls to
// different MACs, drained via take_tx like the mesh peer tick, then
// completed in order. Each completion must report its own destination —
// reporting the last destination twice leaks the runtime's per-MAC
// in-flight tracking into the TX callback quarantine and wedges that
// peer's link handshake (M4 WouldBlock until Expired).
void test_completions_attribute_in_send_order_after_take_tx() {
  idf_stub::reset();
  completion_count = 0;
  CHECK(esp_now_register_send_cb(&record_completion) == ESP_OK);
  const std::uint8_t mac_a[6] = {0x02, 0x00, 0x00, 0x00, 0xA1, 0x02};
  const std::uint8_t mac_b[6] = {0x02, 0x00, 0x00, 0x00, 0xA1, 0x03};
  const std::uint8_t body[4] = {0x52, 0x4C, 0x44, 0x31};
  CHECK(esp_now_send(mac_a, body, sizeof(body)) == ESP_OK);
  CHECK(esp_now_send(mac_b, body, sizeof(body)) == ESP_OK);
  idf_stub::TxFrame taken{};
  CHECK(idf_stub::take_tx(taken));
  CHECK(std::memcmp(taken.dest, mac_a, 6) == 0);
  CHECK(idf_stub::take_tx(taken));
  CHECK(std::memcmp(taken.dest, mac_b, 6) == 0);
  CHECK(!idf_stub::take_tx(taken));
  CHECK(idf_stub::complete_send(true));
  CHECK(idf_stub::complete_send(false));
  CHECK(!idf_stub::complete_send(true));
  CHECK(completion_count == 2);
  CHECK(std::memcmp(completion_macs[0], mac_a, 6) == 0);
  CHECK(completion_status[0] == ESP_NOW_SEND_SUCCESS);
  CHECK(std::memcmp(completion_macs[1], mac_b, 6) == 0);
  CHECK(completion_status[1] == ESP_NOW_SEND_FAIL);
  CHECK(esp_now_unregister_send_cb() == ESP_OK);
}

void test_cutover_fence_recovers_when_driver_omits_completion() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  const std::uint8_t frame = 0x42;
  CHECK(runtime.send(kPeer, 1, ByteView{&frame, 1}).ok());
  EspNowRuntimeTestAccess::fence(runtime);
  CHECK(EspNowRuntimeTestAccess::fenced(runtime));
  CHECK(EspNowRuntimeTestAccess::raw_send(runtime, peer_mac()).code ==
        routeloom::StatusCode::WouldBlock);
  idf_stub::advance_ms(4000);
  runtime.poll_once();
  CHECK(!EspNowRuntimeTestAccess::fenced(runtime));
  runtime.stop();
}

void test_hil_rx_diagnostics_are_owner_serialized() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());
  const std::uint8_t invalid_frame = 0;
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), &invalid_frame, 1));
  CHECK(EspNowRuntimeTestAccess::hil_rx_frames(runtime) == 0);
  runtime.poll_once();
  CHECK(EspNowRuntimeTestAccess::hil_rx_frames(runtime) == 1);
  runtime.stop();
}

}  // namespace

int main() {
  test_notification_keeps_external_and_racing_wakes();
  test_unknown_rx_does_not_wake_owner();
  test_wake_budget_stops_radio_submissions();
  test_idle_deadline_poll_equivalence();
  test_active_deadline_noop();
  test_hil_rx_diagnostics_are_owner_serialized();
  test_completions_attribute_in_send_order_after_take_tx();
  test_cutover_fence_recovers_when_driver_omits_completion();
  test_boot_installs_lease_port();
  test_prestart_owner_pump();
  test_owner_drives_config_component();
  test_rx_drain_is_bounded_per_pass();
  test_rx_queue_peak_during_drain();
  test_owner_wait_rounds_up_to_a_tick();
  test_owner_trace_includes_node_work();
  test_security_callback_cannot_reenter_owner_lease();
  test_p6_binding_tracks_current_receive_context();
  test_reliable_to_static_peer_uses_binding();
  test_old_rx_epoch_cannot_acquire_current_binding();
  test_distinct_session_tx_and_rx_contexts();
  test_stop_drains_node_reply_uses();
  test_stale_binding_keeps_reserved_reply_sendable();
  test_driverless_authenticated_recovery();
  test_stale_peer_probe_recovery_over_runtime();
  test_driver_release_waits_for_use_and_callback();
  test_route_broadcast_uses_reserved_radio_slot();
  test_physical_tx_arbitrates_across_peers();
  test_driver_delete_failure_keeps_slot_occupied();
  test_transient_cleanup_keeps_regular_driver_peer();
  test_failed_static_registration_does_not_claim_a_slot();
  test_route_capacity_registration_rolls_back_driver_peer();
  test_failed_registration_delete_retries_before_slot_reuse();
  test_retired_binding_cannot_be_resurrected_by_registration();
  test_adopt_member_node_keeps_node_startable();
  test_adopt_member_node_keeps_sufficient_timers();
  if (failures != 0) {
    std::fprintf(stderr, "test_espnow_runtime: %d failure(s)\n", failures);
    return 1;
  }
  std::puts("test_espnow_runtime: ok");
  return 0;
}
