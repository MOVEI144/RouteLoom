#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/fixed_containers.hpp"
#include "routeloom/routing.hpp"
#include "routeloom/security.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"
#include "routeloom/wire.hpp"

namespace routeloom {

struct NodeConfig {
  NetworkId network{0};
  NodeId node{kInvalidNodeId};
  std::uint32_t message_session{0};
  std::uint16_t link_epoch{1};
  std::uint16_t end_epoch{1};
  // Origin generation for this node's own route source. Must be persisted
  // monotonic and incremented on every boot; a restarted node advertises a
  // higher generation so peers discard its previous-incarnation route state.
  std::uint16_t route_generation{1};
  std::uint32_t route_advertisement_period_ms{5000};
  std::uint32_t route_lifetime_ms{15000};
  std::uint32_t hop_accept_timeout_ms{60};
  std::uint32_t callback_watchdog_ms{1000};
  std::uint8_t max_link_attempts{2};
  std::uint8_t max_end_to_end_rounds{3};
};

struct RadioRxMetadata {
  std::int8_t rssi_dbm{0};
};

class RadioPort {
 public:
  virtual ~RadioPort() = default;
  virtual Status send(NodeId peer, std::uint64_t token, ByteView frame) noexcept = 0;
  virtual Status recover() noexcept = 0;
};

class NodeObserver {
 public:
  virtual ~NodeObserver() = default;
  virtual void on_message(const MessageKey& key, NodeId source, ByteView payload) noexcept = 0;
  virtual void on_delivery(const DeliveryResult& result) noexcept = 0;
  virtual void on_diagnostic(const char* reason, NodeId peer, const MessageId* message) noexcept = 0;
};

class NullObserver final : public NodeObserver {
 public:
  void on_message(const MessageKey&, NodeId, ByteView) noexcept override {}
  void on_delivery(const DeliveryResult&) noexcept override {}
  void on_diagnostic(const char*, NodeId, const MessageId*) noexcept override {}
};

// Narrow sink for link-scoped autonomy control payloads (NeighborProbe /
// NeighborResult, docs/design/autonomous-mesh/02-discovery.md §3). The radio
// Owner installs one; a frame reaches it only after wire::open_link and the
// network/peer identity checks pass, so payload bytes are link-authenticated
// but NOT end-verified — the sink must still re-validate them (binding
// generation, neighbor phase) before acting.
class AutonomyFrameSink {
 public:
  virtual ~AutonomyFrameSink() = default;
  virtual void on_autonomy_frame(NodeId peer, FrameType type, ByteView payload,
                                 MonotonicMs now_ms) noexcept = 0;
};

// Policy applied by MeshNode::settle_for_sleep to deliveries that are not in a
// terminal state when the node drains for sleep.
enum class SleepWorkPolicy : std::uint8_t {
  Fail = 0,   // fail with an explicit reason
  Save = 1,   // persist unfinished deliveries into the sleep image
  Defer = 2,  // leave them; the result is unknown after real sleep
};

// Read-only view of a Delivery slot for the power coordinator.
struct DeliverySnapshot {
  MessageId id{};
  NodeId destination{kInvalidNodeId};
  SendOptions options{};
  DeliveryState state{DeliveryState::Empty};
  MonotonicMs expires_at_ms{0};
  ByteView payload{};
};

class MeshNode {
 public:
  MeshNode(const NodeConfig& config, RadioPort& radio, SecurityProvider& security,
           NodeObserver& observer) noexcept;

  Status start(MonotonicMs now_ms) noexcept;
  Status add_neighbor(NodeId neighbor, RouteMetric link_metric,
                      MonotonicMs now_ms) noexcept;
  Status remove_neighbor(NodeId neighbor, MonotonicMs now_ms) noexcept;

  Status send(NodeId destination, ByteView payload, const SendOptions& options,
              MonotonicMs now_ms, MessageId& id) noexcept;
  Status cancel(const MessageId& id) noexcept;
  DeliveryResult delivery(const MessageId& id) const noexcept;

  void poll(MonotonicMs now_ms) noexcept;
  void on_radio_receive(NodeId peer, ByteView frame, const RadioRxMetadata& metadata,
                        MonotonicMs now_ms) noexcept;
  // Install/clear the autonomy control sink (Owner wiring, nullptr disables).
  void set_autonomy_sink(AutonomyFrameSink* sink) noexcept { autonomy_sink_ = sink; }
  void on_radio_tx_result(std::uint64_t token, bool success,
                          MonotonicMs now_ms) noexcept;

  const RouteTable& routes() const noexcept { return routes_; }
  const NodeConfig& config() const noexcept { return config_; }
  NodeId node_id() const noexcept { return config_.node; }
  bool started() const noexcept { return started_; }

  // Sleep support. While draining, send() is rejected and background work
  // (route advertisements, sequence requests, retry rounds) stops; in-flight
  // queue entries still dispatch so the TX path can settle.
  void set_draining(bool draining) noexcept { draining_ = draining; }
  bool draining() const noexcept { return draining_; }
  // True when no radio-bound work remains: empty TX queue, no physical
  // in-flight frame and no job waiting for a hop accept.
  bool quiesced() const noexcept {
    return !physical_.active && tx_queue_.empty() && awaiting_hop_.size() == 0;
  }
  // Bumped on every send() call, received frame and TX-result callback: any
  // radio-visible activity. Used to invalidate outstanding sleep tickets.
  std::uint32_t work_generation() const noexcept { return work_generation_; }
  // Bumps only on inbound radio frames that pass link authentication and the
  // network/peer identity check — the signal the power coordinator uses to
  // confirm saved peers actually answered after a resume. Invalid frames, TX
  // callbacks and app sends do not count as peer confirmation.
  std::uint32_t rx_generation() const noexcept { return rx_generation_; }
  // Bumped on peer/config changes (neighbor add/remove).
  std::uint32_t config_revision() const noexcept { return config_revision_; }
  static constexpr std::size_t delivery_capacity() noexcept {
    return kDeliveryCapacity;
  }

  template <typename Fn>
  void for_each_delivery(Fn fn) const noexcept {
    deliveries_.for_each([&](const Delivery& delivery) {
      fn(DeliverySnapshot{delivery.id, delivery.destination, delivery.options,
                          delivery.state, delivery.expires_at_ms,
                          ByteView{delivery.payload.data(), delivery.payload_size}});
    });
  }

  // Phase 1 of the sleep settlement — read-only. Offers every non-terminal
  // durable delivery (or all non-terminal deliveries under SleepWorkPolicy::
  // Save) to `save` WITHOUT changing delivery state: until the durable image
  // is committed, live work must stay live so a persistence failure can abort
  // back to running with nothing lost.
  template <typename SaveFn>
  void snapshot_for_sleep(SleepWorkPolicy fallback, SaveFn&& save) noexcept {
    deliveries_.for_each([&](const Delivery& delivery) {
      if (sleep_terminal(delivery.state)) return;
      if (delivery.options.persist_across_sleep ||
          fallback == SleepWorkPolicy::Save) {
        save(DeliverySnapshot{delivery.id, delivery.destination, delivery.options,
                              delivery.state, delivery.expires_at_ms,
                              ByteView{delivery.payload.data(),
                                       delivery.payload_size}});
      }
    });
  }

  // Phase 2 — only after the durable image commit succeeded. `was_saved`
  // reports whether a delivery id landed in the committed image; those
  // deliveries become Indeterminate (outcome decided after resume). Everything
  // else follows `fallback`: a delivery that was eligible but not saved fails
  // explicitly — durable work is never dropped silently.
  template <typename WasSavedFn>
  void apply_sleep_dispositions(SleepWorkPolicy fallback,
                                WasSavedFn&& was_saved) noexcept {
    deliveries_.for_each([&](Delivery& delivery) {
      if (sleep_terminal(delivery.state)) return;
      const bool durable = delivery.options.persist_across_sleep;
      const bool eligible = durable || fallback == SleepWorkPolicy::Save;
      if (eligible && was_saved(delivery.id)) {
        set_delivery_state(delivery, DeliveryState::Indeterminate, "SLEEP_SAVED");
      } else if (fallback == SleepWorkPolicy::Defer && !durable) {
        set_delivery_state(delivery, DeliveryState::Indeterminate, "SLEEP_DEFERRED");
      } else {
        set_delivery_state(delivery, DeliveryState::Failed,
                           eligible ? "SLEEP_PERSIST_FULL" : "SLEEP_DRAIN");
      }
    });
  }

  // Re-injects a persisted delivery under its ORIGINAL logical message id so
  // the destination's terminal dedup still suppresses a payload it already
  // delivered when the end receipt was lost in sleep. Only the power
  // coordinator calls this; ordinary send() always allocates a fresh id.
  // Rejected when the id is already live or collides with argument checks.
  Status resume_delivery(const MessageId& id, NodeId destination, ByteView payload,
                         const SendOptions& options, MonotonicMs now_ms) noexcept;

  // Drops all queued/in-flight radio work after apply_sleep_dispositions ran.
  // A frame
  // already handed to the driver is reported unknown, never as sent.
  void quiesce_for_sleep() noexcept {
    if (physical_.active) {
      observer_.on_diagnostic("SLEEP_TX_INFLIGHT", physical_.job.peer,
                              &physical_.job.ack.key.id);
      physical_ = PhysicalInflight{};
    }
    tx_queue_.clear();
    awaiting_hop_.clear();
  }

 private:
  static constexpr std::size_t kNeighborCapacity = 32;
  static constexpr std::size_t kDeliveryCapacity = 8;
  static constexpr std::size_t kDedupCapacity = 64;
  static constexpr std::size_t kTxQueueCapacity = 32;
  static constexpr std::size_t kAwaitingHopCapacity = 8;
  static constexpr std::size_t kSeqnoSeenCapacity = 32;
  static constexpr std::size_t kSeqnoStateCapacity = 32;

  struct Neighbor {
    NodeId node{kInvalidNodeId};
    RouteMetric metric{1};
    RouteGeneration generation{0};  // last origin generation the peer self-advertised
    std::uint8_t consecutive_failures{0};
    std::uint8_t route_cursor{0};  // rotation cursor for periodic route dumps
    bool active{false};
  };

  struct SeqnoSeen {
    NodeId requester{kInvalidNodeId};
    NodeId destination{kInvalidNodeId};
    std::uint32_t request_id{0};
    MonotonicMs expires_at_ms{0};
  };

  // Per-destination request state. Survives dedup (seqno_seen_) expiry so the
  // retry cap and cooldown still apply after the seen-record is gone.
  struct SeqnoState {
    NodeId destination{kInvalidNodeId};
    RouteSequence requested_sequence{0};
    MonotonicMs next_request_ms{0};
    MonotonicMs last_sent_ms{0};
    MonotonicMs expires_at_ms{0};
    std::uint8_t attempts{0};
  };

  struct DedupEntry {
    MessageKey key{};
    FrameType type{FrameType::Data};
    std::uint8_t round{0};
    MonotonicMs expires_at_ms{0};
    bool delivered{false};
    bool forwarded{false};
  };

  struct Delivery {
    MessageId id{};
    NodeId destination{kInvalidNodeId};
    SendOptions options{};
    std::array<std::uint8_t, kMaxApplicationPayload> payload{};
    std::size_t payload_size{0};
    DeliveryState state{DeliveryState::Empty};
    MonotonicMs created_at_ms{0};
    MonotonicMs expires_at_ms{0};
    MonotonicMs next_round_at_ms{0};
    std::uint8_t round{0};
    const char* reason{"NONE"};
  };

  enum class JobForm : std::uint8_t { Plain, Forwarded };
  enum class JobOwner : std::uint8_t { None, OriginDelivery, Transit };

  struct AckKey {
    FrameType accepted_type{FrameType::Data};
    MessageKey key{};
    std::uint8_t round{0};
  };

  struct TxJob {
    JobForm form{JobForm::Plain};
    JobOwner owner{JobOwner::None};
    wire::PlainFrame plain{};
    wire::LinkOpenedFrame forwarded{};
    NodeId peer{kInvalidNodeId};
    AckKey ack{};
    bool requires_hop_accept{false};
    std::uint8_t attempts{0};
    std::uint8_t max_attempts{1};
    MonotonicMs deadline_ms{0};
    wire::EncodedFrame encoded{};
    bool encoded_valid{false};
  };

  struct PhysicalInflight {
    TxJob job{};
    std::uint64_t token{0};
    MonotonicMs submitted_at_ms{0};
    bool active{false};
  };

  struct AwaitingHop {
    TxJob job{};
    MonotonicMs expires_at_ms{0};
  };

  Status validate_config() const noexcept;
  Neighbor* find_neighbor(NodeId node) noexcept;
  const Neighbor* find_neighbor(NodeId node) const noexcept;
  Delivery* find_delivery(const MessageId& id) noexcept;
  const Delivery* find_delivery(const MessageId& id) const noexcept;
  DedupEntry* find_dedup(const MessageKey& key, FrameType type,
                         std::uint8_t round) noexcept;
  DedupEntry* allocate_dedup(const MessageKey& key, FrameType type,
                             std::uint8_t round, MonotonicMs expires_at_ms) noexcept;

  void set_delivery_state(Delivery& delivery, DeliveryState state,
                          const char* reason) noexcept;
  static bool sleep_terminal(DeliveryState state) noexcept;
  Status enqueue_delivery(const MessageId& id, NodeId destination, ByteView payload,
                          const SendOptions& options, MonotonicMs now_ms,
                          MessageId& out) noexcept;
  Status queue_origin_data(Delivery& delivery, MonotonicMs now_ms) noexcept;
  Status queue_forward(const wire::LinkOpenedFrame& frame, NodeId next_hop,
                       MonotonicMs now_ms) noexcept;
  Status queue_hop_accept(const wire::Header& accepted, MonotonicMs now_ms) noexcept;
  Status queue_end_receipt(const wire::Header& data, MonotonicMs now_ms) noexcept;
  Status queue_route_update(NodeId neighbor, MonotonicMs now_ms) noexcept;
  Status queue_seqno_request(NodeId peer, NodeId requester, NodeId destination,
                             RouteSequence requested_sequence, std::uint32_t request_id,
                             std::uint8_t ttl, MonotonicMs now_ms) noexcept;

  Status encode_job(TxJob& job, MonotonicMs now_ms) noexcept;
  void dispatch_next(MonotonicMs now_ms) noexcept;
  void complete_job(TxJob& job, bool hop_accepted, MonotonicMs now_ms) noexcept;
  void fail_job(TxJob& job, const char* reason, MonotonicMs now_ms) noexcept;
  void retry_or_fail(TxJob& job, const char* reason, MonotonicMs now_ms) noexcept;

  void handle_hop_accept(const wire::PlainFrame& frame, NodeId peer,
                         MonotonicMs now_ms) noexcept;
  void handle_data(const wire::LinkOpenedFrame& frame, NodeId peer,
                   MonotonicMs now_ms) noexcept;
  void handle_end_receipt(const wire::LinkOpenedFrame& frame, NodeId peer,
                          MonotonicMs now_ms) noexcept;
  void handle_route_update(const wire::PlainFrame& frame, NodeId peer,
                           MonotonicMs now_ms) noexcept;
  void handle_seqno_request(const wire::PlainFrame& frame, NodeId peer,
                            MonotonicMs now_ms) noexcept;

  void process_awaiting_hop(MonotonicMs now_ms) noexcept;
  void process_delivery_timeouts(MonotonicMs now_ms) noexcept;
  void expire_dedup(MonotonicMs now_ms) noexcept;
  void schedule_route_advertisements(MonotonicMs now_ms) noexcept;
  void schedule_sequence_requests(MonotonicMs now_ms) noexcept;
  void expire_sequence_requests(MonotonicMs now_ms) noexcept;
  // Triggered update: schedule a full-neighbor advertisement burst after a
  // deterministic jitter, bounded by a minimum interval between bursts so a
  // flap storm cannot flood the TX queue.
  void trigger_route_advertisement(MonotonicMs now_ms) noexcept;
  void run_triggered_advertisement(MonotonicMs now_ms) noexcept;

  static Status encode_ack_payload(const AckKey& key,
                                   std::array<std::uint8_t, kMaxApplicationPayload>& payload,
                                   std::size_t& size) noexcept;
  static Status decode_ack_payload(ByteView payload, AckKey& key) noexcept;
  static Status encode_receipt_payload(const wire::Header& data,
                                       std::array<std::uint8_t, kMaxApplicationPayload>& payload,
                                       std::size_t& size) noexcept;
  static Status decode_receipt_payload(ByteView payload, MessageKey& key,
                                       std::uint8_t& round) noexcept;

  NodeConfig config_{};
  RadioPort& radio_;
  SecurityProvider& security_;
  NodeObserver& observer_;
  RouteTable routes_{};
  AutonomyFrameSink* autonomy_sink_{nullptr};
  FixedPool<Neighbor, kNeighborCapacity> neighbors_{};
  FixedPool<Delivery, kDeliveryCapacity> deliveries_{};
  FixedPool<DedupEntry, kDedupCapacity> dedup_{};
  FixedPool<SeqnoSeen, kSeqnoSeenCapacity> seqno_seen_{};
  FixedPool<SeqnoState, kSeqnoStateCapacity> seqno_state_{};
  FixedQueue<TxJob, kTxQueueCapacity> tx_queue_{};
  FixedPool<AwaitingHop, kAwaitingHopCapacity> awaiting_hop_{};
  PhysicalInflight physical_{};
  std::uint64_t next_physical_token_{1};
  std::uint64_t next_message_sequence_{1};
  std::uint64_t next_control_sequence_{1};
  std::uint32_t next_seqno_request_id_{1};
  RouteSequence self_route_sequence_{1};
  MonotonicMs next_route_advertisement_ms_{0};
  std::size_t route_neighbor_cursor_{0};
  bool triggered_advertisement_{false};
  MonotonicMs triggered_at_ms_{0};
  MonotonicMs next_triggered_ms_{0};
  std::uint32_t trigger_counter_{0};
  std::uint32_t work_generation_{0};
  std::uint32_t rx_generation_{0};
  std::uint32_t config_revision_{0};
  bool started_{false};
  bool draining_{false};
};

}  // namespace routeloom
