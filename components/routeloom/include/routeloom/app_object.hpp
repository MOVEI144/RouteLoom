#pragma once

#include "routeloom/app_object_wire.hpp"
#include "routeloom/object_assembler.hpp"
#include "routeloom/node.hpp"
#include "routeloom/profile.hpp"

#ifndef ROUTELOOM_APP_OBJECT_TRANSFER
#define ROUTELOOM_APP_OBJECT_TRANSFER 0
#endif
#ifndef ROUTELOOM_APP_OBJECT_RX_SLOTS
#define ROUTELOOM_APP_OBJECT_RX_SLOTS 2
#endif

namespace routeloom {
using ObjectId = object_wire::ObjectId;
struct ObjectOptions {
  std::uint32_t deadline_ms{30000};
  std::uint16_t app_tag{0};
  std::uint8_t content_encoding{0};
};
enum class ObjectState : std::uint8_t {
  Delivered = 1, Expired = 2, CancelledBeforeTx = 3,
  Indeterminate = 4, Failed = 5, Unsupported = 6
};
struct ObjectResult {
  ObjectId id{0};
  ObjectState state{ObjectState::Failed};
  StatusCode reason{StatusCode::Ok};
};
struct ObjectRxInfo {
  NodeId source{kInvalidNodeId};
  ObjectId id{0};
  std::uint32_t source_boot{0};
  std::uint32_t end_context{0};
  std::uint16_t app_tag{0};
  std::uint8_t content_encoding{0};
};
class ObjectObserver {
 public:
  virtual ~ObjectObserver() = default;
  virtual bool object_receive_ready() const noexcept { return true; }
  virtual std::size_t object_receive_slots() const noexcept { return ROUTELOOM_APP_OBJECT_RX_SLOTS; }
  virtual void on_object(const ObjectRxInfo&, ByteView) noexcept {}
  virtual void on_object_result(const ObjectResult&) noexcept {}
};

#if ROUTELOOM_APP_OBJECT_TRANSFER
// An optional endpoint on the existing typed, authenticated routed lane.
// One immutable TX loan, caller-provided RX buffers; no payload arena here.
// It delegates the config/authority lane to the previously installed sink.
// Keep the endpoint and registered buffers alive while installed on the node.
class AppObject final : public ConfigEndpointSink {
 public:
  AppObject(MeshNode& node, SecurityProvider& security, ObjectObserver& observer) noexcept;
  ~AppObject() override;
  Status attach() noexcept;
  Status register_buffer(MutableByteView buffer) noexcept;
  Status send(NodeId destination, ByteView data, const ObjectOptions& options,
              MonotonicMs now_ms, ObjectId& id) noexcept;
  Status cancel(ObjectId id) noexcept;
  void poll(MonotonicMs now_ms) noexcept override;
  bool accepts_extension(FrameType type) const noexcept override;
  void on_config_frame(NodeId peer, const wire::PlainFrame& frame,
                       MonotonicMs now_ms) noexcept override;
  void on_config_job_done(const MessageId& id, bool accepted, const char* reason,
                          MonotonicMs now_ms) noexcept override;
  std::uint32_t permit_profile_bits() const noexcept override;
  bool quiescent() const noexcept override;

 private:
  struct Key {
    NodeId peer{0};
    NetworkId network{0};
    NodeId self{0};
    std::uint32_t boot{0};
    std::uint32_t epoch{0};
    ObjectId id{0};
    std::uint32_t self_boot{0};
    bool operator==(const Key& other) const noexcept;
  };
  struct Rx {
    MutableByteView storage{};
    ObjectAssembler assembler{};
    std::array<std::uint8_t, 8> bitmap{};
    MonotonicMs progress_ms{0};
    // Reserved before admission and retained past the assembly deadline.
    std::uint8_t record{0};
  };
  struct Record {
    Key key{};
    object_wire::Digest digest{};
    MonotonicMs until_ms{0};
    std::uint64_t bitmap{0};
    std::uint16_t total{0};
    std::uint16_t app_tag{0};
    std::uint8_t chunks{0};
    std::uint8_t encoding{0};
    object_wire::AckStatus status{object_wire::AckStatus::Incomplete};
    bool used{false};
    bool ack_pending{false};
  };
  // A floor survives completion-record expiry until its crypto context is
  // retired. No live floor is evicted to admit a new source.
  struct Floor {
    std::uint32_t epoch{0};
    ObjectId highest{0};
    std::uint32_t boot{0};
  };
  struct Flight {
    MessageId job{};
    MonotonicMs sent_ms{0};
    std::uint8_t index{0};
    std::uint8_t sends{0};
    bool queued{false};
    bool used{false};
  };
  struct Tx {
    ByteView data{};
    NodeId destination{0};
    object_wire::Start start{};
    MonotonicMs deadline_ms{0};
    MonotonicMs progress_ms{0};
    MonotonicMs retry_after_ms{0};
    std::uint32_t tx_epoch{0};
    std::uint32_t rx_epoch{0};
    std::uint32_t destination_boot{0};
    std::uint32_t self_boot{0};
    NodeId self{0};
    NetworkId network{0};
    std::uint64_t acked{0};
    std::uint64_t emitted{0};
    // Keep at most one object frame ahead of a foreground exchange.
    std::array<Flight, 1> flight{};
    std::uint8_t busy_retries{0};
    bool active{false};
    bool manifest_acked{false};
    bool ever_sent{false};
  };
  Key key(const wire::PlainFrame& frame, ObjectId id) const noexcept;
  bool live(const Key& key) const noexcept;
  bool live_tx() noexcept;
  std::uint64_t bits(const Rx& rx) const noexcept;
  void start_rx(const wire::PlainFrame& frame, MonotonicMs now_ms) noexcept;
  void chunk_rx(const wire::PlainFrame& frame, MonotonicMs now_ms) noexcept;
  void ack_rx(const wire::PlainFrame& frame, MonotonicMs now_ms) noexcept;
  void queue_ack(NodeId peer, const object_wire::Ack& ack, MonotonicMs now_ms) noexcept;
  void finish_rx(Rx& rx, object_wire::AckStatus status) noexcept;
  void finish_tx(ObjectState state, StatusCode reason) noexcept;
  bool send_frame(FrameType type, NodeId peer, ByteView payload,
                  MonotonicMs now_ms, MessageId& id, std::uint32_t lifetime_ms = 4000) noexcept;
  void pump(MonotonicMs now_ms) noexcept;

  MeshNode& node_;
  SecurityProvider& security_;
  ObjectObserver& observer_;
  ConfigEndpointSink* fallback_{nullptr};
  std::array<Rx, ROUTELOOM_APP_OBJECT_RX_SLOTS> rx_{};
  // Completion metadata never retains a payload loan or evicts a live record.
  std::array<Record, 12> records_{};
  // Separate naturally aligned peer IDs avoid tail padding per floor.
  // Both arrays use the same index and retire together with the context.
  std::array<NodeId, profile::kEndSessions> floor_peers_{};
  std::array<Floor, profile::kEndSessions> floors_{};
  Tx tx_{};
  ObjectResult result_{};
  ObjectId next_id_{1};
  MonotonicMs send_after_ms_{0};
  bool result_ready_{false};
  bool in_call_{false};
};
#endif
}  // namespace routeloom
