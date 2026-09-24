// Host regression tests for the real ESP-NOW Owner's ExpectedReply lease
// wiring (issue #117, PR B): the actual espnow runtime translation unit,
// compiled against the in-tree ESP-IDF/FreeRTOS stand-ins and driven
// through its public API on a fake clock. Covers what the portable
// SimReplyPort tests cannot — the firmware Owner installs a lease port at
// construction (node start refuses without one) and refuses protected
// traffic for peers with no verified binding.

#include <cstdint>
#include <cstdio>
#include <cstring>

#include "routeloom/espnow_runtime.hpp"
#include "routeloom/node.hpp"
#include "routeloom/types.hpp"

#include "idf_stubs.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

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

// A statically registered peer has no discovery-verified binding, so an
// ACK-awaiting (Reliable) delivery to it must fail at the binding snapshot
// — never transmit unbound. Best-effort traffic is unaffected (no snapshot).
void test_reliable_to_unbound_peer_fails_at_snapshot() {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer;
  EspNowRuntime runtime(make_config(), security, observer);
  CHECK(runtime.initialize().ok());
  CHECK(runtime.start().ok());
  CHECK(runtime.register_neighbor(kPeer, peer_mac(), 1).ok());

  const std::uint8_t payload[] = {0x10, 0x20, 0x30};
  MessageId id{};
  CHECK(runtime
            .send_application(kPeer, ByteView{payload, sizeof(payload)},
                              SendOptions{}, id)
            .ok());

  // send_application reports Accepted synchronously; the refusal lands
  // later as a terminal verdict. Three end-to-end rounds, ~50 ms apart;
  // each round's job dies at the snapshot. Cap far beyond that so a
  // wedged pump fails loudly.
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
  if (!observer.delivery_events.empty()) {
    const auto& result = observer.delivery_events.back();
    CHECK(result.id == id);
    CHECK(result.state == DeliveryState::Failed);
    CHECK(result.reason != nullptr &&
          std::strcmp(result.reason, "no live binding for peer") == 0);
  }
  // The snapshot-failure reason proves the DATA job never transmitted;
  // only best-effort background traffic may have reached the stub driver.
  runtime.stop();
}

}  // namespace

int main() {
  test_boot_installs_lease_port();
  test_reliable_to_unbound_peer_fails_at_snapshot();
  if (failures != 0) {
    std::fprintf(stderr, "test_espnow_runtime: %d failure(s)\n", failures);
    return 1;
  }
  std::puts("test_espnow_runtime: ok");
  return 0;
}
