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
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

#include "idf_stubs.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

namespace routeloom::espnow {
struct EspNowRuntimeTestAccess {
  static ReplyPeerPort& reply(EspNowRuntime& runtime) noexcept {
    return runtime.reply_port_;
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
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), rld1.data(), rld1.size()));
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
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), encoded.bytes.data(),
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
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), encoded.bytes.data(),
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
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), encoded.bytes.data(),
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
  CHECK(idf_stub::inject_rx(peer_mac().bytes.data(), encoded.bytes.data(),
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
  routeloom::ReplyLeaseToken use{};
  CHECK(port.acquire(binding, 1000, 0, use).ok());
  EspNowRuntimeTestAccess::set_release_pending(runtime, kPeer);
  CHECK(port.observe_authenticated_rx(binding).ok());
  const std::uint8_t frame = 0x42;
  CHECK(port.send_reply(use, 1, ByteView{&frame, 1}, 0).ok());
  CHECK(EspNowRuntimeTestAccess::peer_registered(runtime, kPeer));
  CHECK(port.release(use).ok());
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

}  // namespace

int main() {
  test_boot_installs_lease_port();
  test_prestart_owner_pump();
  test_security_callback_cannot_reenter_owner_lease();
  test_p6_binding_tracks_current_receive_context();
  test_reliable_to_static_peer_uses_binding();
  test_old_rx_epoch_cannot_acquire_current_binding();
  test_distinct_session_tx_and_rx_contexts();
  test_stop_drains_node_reply_uses();
  test_stale_binding_keeps_reserved_reply_sendable();
  test_driver_release_waits_for_use_and_callback();
  test_driver_delete_failure_keeps_slot_occupied();
  test_failed_static_registration_does_not_claim_a_slot();
  test_route_capacity_registration_rolls_back_driver_peer();
  test_failed_registration_delete_retries_before_slot_reuse();
  test_retired_binding_cannot_be_resurrected_by_registration();
  if (failures != 0) {
    std::fprintf(stderr, "test_espnow_runtime: %d failure(s)\n", failures);
    return 1;
  }
  std::puts("test_espnow_runtime: ok");
  return 0;
}
