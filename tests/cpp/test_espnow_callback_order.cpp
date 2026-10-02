#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "routeloom/espnow_runtime.hpp"
#include "idf_stubs.hpp"
#include "test_security.hpp"
#include "test_sim.hpp"

using namespace routeloom;
using namespace routeloom_test;

namespace {
void check(bool ok) {
  if (!ok) std::abort();
}

constexpr std::array<std::uint8_t, 6> kPeerMac{2, 0xaa, 0xbb, 0xcc, 0xdd, 2};

NodeConfig node_config(NodeId id) {
  NodeConfig config{};
  config.network = 7;
  config.node = id;
  config.message_session = static_cast<std::uint32_t>(100 + id);
  config.boot_incarnation = static_cast<std::uint32_t>(200 + id);
  config.link_epoch = 1;
  config.end_epoch = 1;
  return config;
}

// Only the peer radio is fake; both ends execute the production MeshNode.
class PeerRadio final : public RadioPort {
 public:
  Status recover() noexcept override { return Status::success(); }
  Status send(NodeId, std::uint64_t token, ByteView frame) noexcept override {
    if (pending) return Status::error(StatusCode::WouldBlock, "peer TX pending");
    check(frame.size <= bytes.bytes.size());
    std::memcpy(bytes.bytes.data(), frame.data, frame.size);
    bytes.size = frame.size;
    tx_token = token;
    pending = true;
    return Status::success();
  }
  void drain(MeshNode& node, MonotonicMs now) {
    if (!pending) return;
    check(idf_stub::inject_rx(kPeerMac.data(), bytes.bytes.data(), bytes.size));
    pending = false;
    check(node.on_radio_tx_result(tx_token, true, now).ok());
  }
  ByteBuffer<280> bytes;
  std::uint64_t tx_token{0};
  bool pending{false};
};

enum class Order { CallbackFirst, RxFirst, BeforeReturn, Delayed };

struct Link {
  espnow::EspNowRuntime& runtime;
  MeshNode& peer;
  SimReplyPort& peer_reply;
  PeerRadio& radio;
  Order order;
  bool overflow{false};
  MonotonicMs callback_due{0};

  void transfer() {
    const auto now = runtime.now_ms();
    if (callback_due != 0 && now >= callback_due) {
      check(idf_stub::complete_send(true));
      callback_due = 0;
    }
    idf_stub::TxFrame frame{};
    if (!idf_stub::take_tx(frame)) return;
    if (overflow) {
      // A full RX queue must preserve the reserved completion. The lost
      // response is recovered by the normal Reliable retry, not re-injected.
      const std::uint8_t invalid = 0;
      for (std::size_t i = 0; i < espnow::EspNowRuntime::kEventQueueCapacity; ++i)
        check(idf_stub::inject_rx(kPeerMac.data(), &invalid, 1));
      overflow = false;
    }
    if (order == Order::CallbackFirst) check(idf_stub::complete_send(true));
    check(peer.on_radio_receive(1, {frame.bytes, frame.length},
                                sim_rx_metadata(&peer_reply, 1), now).ok());
    check(peer.poll(now).ok());
    radio.drain(peer, now);
    if (order == Order::Delayed) callback_due = now + 25;
    else if (order != Order::CallbackFirst) check(idf_stub::complete_send(true));
  }
  static void submitted(void* context) { static_cast<Link*>(context)->transfer(); }
};

void delivery(Order order, bool overflow) {
  idf_stub::reset();
  TestSecurity security;
  CapturingObserver observer, peer_observer;
  espnow::EspNowRuntimeConfig config{};
  config.node = node_config(1);
  config.channel = 6;
  config.max_tx_power_qdbm = 80;
  espnow::EspNowRuntime runtime(config, security, observer);
  check(runtime.initialize().ok());
  check(runtime.start().ok());
  espnow::MacAddress mac{};
  mac.bytes = kPeerMac;
  check(runtime.register_neighbor(2, mac, 1).ok());
  PeerRadio radio;
  SimReplyPort reply(radio, 2, 1);
  MeshNode peer(node_config(2), radio, security, peer_observer);
  check(peer.set_reply_peer_port(&reply).ok());
  check(peer.start(0).ok());
  check(peer.add_neighbor(1, 1, 0).ok());
  Link link{runtime, peer, reply, radio, order, overflow};
  if (order == Order::BeforeReturn) idf_stub::set_send_hook(&Link::submitted, &link);
  SendOptions options{};
  options.delivery = DeliveryClass::Reliable;
  options.lifetime_ms = 5000;
  const std::uint8_t payload = 42;
  // The 2 s source cadence matches the quiet H7R2 foundation. Repeat in
  // both directions and retain every terminal and duplicate observation.
  for (unsigned reverse = 0; reverse < 2; ++reverse) {
    auto& source = reverse == 0 ? observer : peer_observer;
    auto& destination = reverse == 0 ? peer_observer : observer;
    for (unsigned i = 0; i < 20; ++i) {
      MessageId id{};
      const auto now = runtime.now_ms();
      check((reverse == 0 ? runtime.send_application(2, {&payload, 1}, options, id)
                          : peer.send(1, {&payload, 1}, options, now, id)).ok());
      const auto until = now + 2000;
      while (runtime.now_ms() < until) {
        runtime.poll_once();
        if (order != Order::BeforeReturn) link.transfer();
        check(peer.poll(runtime.now_ms()).ok());
        radio.drain(peer, runtime.now_ms());
        idf_stub::advance_ms(1);
      }
      unsigned terminals = 0;
      for (const auto& event : source.delivery_events) {
        if (event.id != id || event.state < DeliveryState::Delivered) continue;
        check(event.state == DeliveryState::Delivered);
        ++terminals;
      }
      check(terminals == 1);
      check(destination.messages.size() == i + 1);
    }
  }
  check(idf_stub::tx_overruns() == 0);
  check(runtime.rx_dropped() == (overflow ? 1U : 0U));
  check(runtime.stale_tx_results() == 0);
  check(!runtime.tx_fence_active());
  idf_stub::set_send_hook(nullptr, nullptr);
  runtime.stop();
}
}  // namespace

int main() {
  for (const auto order : {Order::CallbackFirst, Order::RxFirst, Order::BeforeReturn,
                           Order::Delayed})
    delivery(order, false);
  delivery(Order::BeforeReturn, true);
  std::printf("ESP-NOW callback ordering: dedup=%zu, 20/20 both ways per scenario\n",
              kDedupCapacity);
}
