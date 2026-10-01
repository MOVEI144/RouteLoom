#include <array>
#include <cassert>
#include <cstring>
#include <memory>
#include <string>

#include "routeloom/app_object.hpp"
#include "routeloom/discovery_scope.hpp"
#include "test_sim.hpp"

using namespace routeloom;
namespace {
// Endpoint boundaries include one authenticated driver-queue handoff; radio
// delivery is covered by the Owner mesh scenarios.
class Security final : public SecurityProvider {
 public:
  bool ready() const noexcept override { return true; }
  Status tx_epoch(SecurityScope, NodeId, std::uint32_t& epoch) noexcept override {
    epoch = tx_context; return Status::success();
  }
  std::uint32_t tx_context{1};
  Status current_rx_epoch(SecurityScope, NodeId, std::uint32_t& epoch) const noexcept override {
    epoch = rx_context; return Status::success();
  }
  std::uint32_t rx_context{1};
  Status next_counter(const SecurityContext& c, std::uint64_t& n) noexcept override {
    return cipher.next_counter(c, n);
  }
  Status seal(const SecurityContext& c, std::uint64_t n, ByteView aad, ByteView in,
              MutableByteView out, std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override {
    return cipher.seal(c, n, aad, in, out, tag);
  }
  Status open(const SecurityContext& c, std::uint64_t n, ByteView aad, ByteView in,
              const std::array<std::uint8_t, kAeadTagSize>& tag, MutableByteView out) noexcept override {
    return cipher.open(c, n, aad, in, tag, out);
  }
 private:
  routeloom_test::TestSecurity cipher;
};
class Radio final : public RadioPort {
 public:
  Status send(NodeId, std::uint64_t, ByteView) noexcept override { return Status::error(StatusCode::Busy, "radio"); }
  Status recover() noexcept override { return Status::success(); }
};
class Observer final : public NodeObserver, public ObjectObserver {
 public:
  void on_message(const MessageKey&, NodeId, ByteView) noexcept override {}
  void on_delivery(const DeliveryResult&) noexcept override {}
  void on_diagnostic(const char*, NodeId, const MessageId*) noexcept override {}
  void on_object(const ObjectRxInfo&, ByteView) noexcept override { ++received; }
  void on_object_result(const ObjectResult& value) noexcept override { result = value; }
  ObjectResult result{};
  unsigned received{0};
};
struct Fixture {
  Radio radio;
  Security security;
  Observer observer;
  routeloom_test::SimReplyPort reply{radio, 1, 1};
  std::unique_ptr<MeshNode> node;
  std::unique_ptr<AppObject> object;
  std::array<std::uint8_t, 4096> storage{};
  Fixture() {
    NodeConfig config{}; config.node = 1; config.network = 7;
    config.message_session = 1; config.end_epoch = 1;
    node = std::make_unique<MeshNode>(config, radio, security, observer);
    object = std::make_unique<AppObject>(*node, security, observer);
    assert(object->attach());
    assert(node->set_reply_peer_port(&reply));
    assert(node->start(0));
    assert(node->add_neighbor(2, 1, 0));
  }
};
template<class T> wire::PlainFrame frame(FrameType type, const T& body) {
  wire::PlainFrame out{};
  out.header.type = type; out.header.flags = wire::kFlagEndProtected;
  out.header.origin = 2; out.header.destination = 1;
  out.header.message.session = 1; out.header.end_epoch = 1;
  out.header.original_lifetime_ms = 4000;
  out.header.remaining_deadline_ms = 3000;
  assert(object_wire::encode(body, {out.payload.data(), out.payload.size()}, out.payload_size));
  return out;
}
void loan_registration() {
  Fixture f;
  ObjectId id = 0;
  assert(f.object->send(2, {f.storage.data() + 1, 121}, {}, 0, id));
  assert(f.object->register_buffer({f.storage.data(), f.storage.size()}).code == StatusCode::Conflict);
  assert(f.object->cancel(id));
  f.object->poll(1);
  assert(f.object->register_buffer({f.storage.data(), f.storage.size()}));
}
void received_deadline() {
  for (const bool driver_queue : {false, true}) {
    Fixture f;
    assert(f.object->register_buffer({f.storage.data(), f.storage.size()}));
    const std::uint8_t byte = 0x93;
    object_wire::Start start{}; start.id = 1; start.total = 1; start.chunks = 1;
    start.lifetime_ms = 1500;
    ScopeDigest digest{}; sha256({&byte, 1}, digest);
    std::copy_n(digest.begin(), start.digest.size(), start.digest.begin());
    auto manifest = frame(FrameType::AppObjectStart, start);
    const MonotonicMs now = driver_queue ? 1001 : 1000;
    if (driver_queue) {
      manifest.header.network = 7;
      manifest.header.previous_hop = 2; manifest.header.next_hop = 1;
      manifest.header.message.sequence = 1;
      manifest.header.remaining_deadline_ms = 4000;
      wire::EncodedFrame encoded{};
      assert(wire::encode_new(manifest, f.security, encoded));
      auto metadata = routeloom_test::sim_rx_metadata(&f.reply, 2);
      metadata.received_us = 1000;
      assert(f.node->on_radio_receive(2, encoded.view(), metadata, now));
      ComponentEvent event{};
      assert(f.node->take_component_event(event));
      manifest = event.frame;
    }
    f.object->on_config_frame(2, manifest, now);
    const auto chunk = frame(FrameType::AppObjectChunk, object_wire::Chunk{1, 0, {&byte, 1}});
    // A 1000 ms delay in either queue leaves 500 ms of object lifetime.
    f.object->on_config_frame(2, chunk, now + 500);
    f.object->poll(now + 500);
    assert(f.observer.received == 0);
    assert(f.object->quiescent());
  }
}
void terminal_ack_guard() {
  for (int boundary : {0, 1, 2}) {
    Fixture f;
    ObjectId id = 0;
    assert(f.object->send(2, {f.storage.data(), 1}, {}, 0, id));
    f.object->poll(0); f.object->poll(1);
    auto ack = frame(FrameType::AppObjectAck, object_wire::Ack{id, object_wire::AckStatus::Incomplete, 0, 0});
    f.object->on_config_frame(2, ack, 2);
    f.object->poll(3); f.object->poll(500);
    if (boundary == 1) f.security.tx_context = 2;
    const MonotonicMs now = boundary == 2 ? 10002 : 501;
    ack = frame(FrameType::AppObjectAck, object_wire::Ack{id, object_wire::AckStatus::Complete, 1, 1});
    f.object->on_config_frame(2, ack, now);
    f.object->poll(now);
    const auto expected = boundary == 0 ? ObjectState::Delivered :
                          boundary == 1 ? ObjectState::Failed : ObjectState::Expired;
    assert(f.observer.result.state == expected);
    if (boundary == 1) assert(f.observer.result.reason == StatusCode::AuthRequired);
    if (boundary == 2) assert(f.observer.result.reason == StatusCode::Expired);
  }
}
void source_floor_capacity() {
  Fixture f;
  assert(f.object->register_buffer({f.storage.data(), f.storage.size()}));
  const std::uint8_t byte = 0x93;
  object_wire::Start start{}; start.id = 1; start.total = 1; start.chunks = 1;
  start.lifetime_ms = 2000;
  ScopeDigest digest{}; sha256({&byte, 1}, digest);
  std::copy_n(digest.begin(), start.digest.size(), start.digest.begin());
  MonotonicMs now = 0;
  const auto receive = [&](NodeId peer, ObjectId id, std::uint32_t boot) {
    start.id = id;
    auto manifest = frame(FrameType::AppObjectStart, start);
    auto chunk = frame(FrameType::AppObjectChunk, object_wire::Chunk{id, 0, {&byte, 1}});
    for (auto* wire_frame : {&manifest, &chunk}) {
      wire_frame->header.origin = peer;
      wire_frame->header.message.session = boot;
      wire_frame->header.end_epoch = f.security.rx_context;
      f.object->on_config_frame(peer, *wire_frame, now);
    }
    f.object->poll(now);
    // Completion records expire; live source floors must survive them.
    now += 32000;
    f.object->poll(now);
  };
  // Same low 32 bits, distinct full-width peer identities.
  for (std::size_t i = 0; i < profile::kEndSessions; ++i) {
    receive((static_cast<NodeId>(i + 1) << 32) | 2, 1, 2);
    assert(f.observer.received == i + 1);
  }
  const unsigned full = f.observer.received;
  receive((static_cast<NodeId>(profile::kEndSessions + 1) << 32) | 2, 1, 2);
  assert(f.observer.received == full);  // full: no live floor is evicted
  const NodeId first = (NodeId{1} << 32) | 2;
  receive(first, 1, 2);  // expired completion is not delivered again
  receive(first, 2, 1);  // an older boot cannot raise the ID floor
  assert(f.observer.received == full);
  receive(first, 2, 2);
  assert(f.observer.received == full + 1);
  ++f.security.rx_context;  // retired contexts free both identity and progress
  receive((static_cast<NodeId>(profile::kEndSessions + 1) << 32) | 2, 1, 2);
  assert(f.observer.received == full + 2);
}
}
int main(int argc, char** argv) {
  if (argc == 1 || std::string(argv[1]) == "loan") loan_registration();
  if (argc == 1 || std::string(argv[1]) == "deadline") received_deadline();
  if (argc == 1 || std::string(argv[1]) == "ack") terminal_ack_guard();
  if (argc == 1 || std::string(argv[1]) == "floor") source_floor_capacity();
}
