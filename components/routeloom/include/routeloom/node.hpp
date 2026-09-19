#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/congestion.hpp"
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
// NeighborResult, docs/design/autonomous-mesh/02-discovery.md §3, plus the
// migration-control set TimeSync/ChannelNotice/ControlObject/ObjectChunk/
// ObjectAck, 04-channel-migration.md §5-§9). The radio Owner installs one; a
// frame reaches it only after wire::open_link and the network/peer identity
// checks pass, so payload bytes are link-authenticated but NOT end-verified
// — the sink must still re-validate them (binding generation, neighbor
// phase, authority signature verification) before acting.
class AutonomyFrameSink {
 public:
  virtual ~AutonomyFrameSink() = default;
  virtual void on_autonomy_frame(NodeId peer, FrameType type, ByteView payload,
                                 MonotonicMs now_ms) noexcept = 0;
};

// Pause contract (01-integration.md §3.3): narrower than blanket draining.
// A PauseReason names WHY traffic is held; the mask selects WHICH traffic is
// held so the control needed to coordinate a survey/cutover keeps flowing —
// plain set_draining(true) stops route/control work and would deadlock a
// migration that still needs its control lane.
enum class PauseReason : std::uint8_t {
  None = 0,
  SleepDrain = 1,       // reserved for the legacy set_draining path
  SurveyVisit = 2,      // bounded single-radio off-channel visit (04 §3)
  MigrationPrepare = 3, // plan distribution/coordination in flight (04 §7)
  Cutover = 4,          // committed switch executing (04 §8)
};

namespace pause {
// Mask bits over traffic categories. The reserved scheduler control lane
// (HOP_ACCEPT replies, pre-admission BUSY) is NEVER masked — it is exactly
// the control a pause must keep alive.
constexpr std::uint8_t kAppAdmission = 1u << 0;   // send()/resume_delivery()
constexpr std::uint8_t kDataDispatch = 1u << 1;   // non-control scheduler dispatch
constexpr std::uint8_t kBackgroundWork = 1u << 2; // route ads + seqno probing
constexpr std::uint8_t kRetryRounds = 1u << 3;    // origin end-to-end retries
constexpr std::uint8_t kAll =
    kAppAdmission | kDataDispatch | kBackgroundWork | kRetryRounds;
// What set_draining(true) has always meant: in-flight queue entries still
// dispatch, only new admission/background/retry work stops.
constexpr std::uint8_t kSleepDrainMask =
    kAppAdmission | kBackgroundWork | kRetryRounds;
// Off-channel visit: the home channel is physically unreceivable — nothing
// home-bound may run.
constexpr std::uint8_t kSurveyVisitMask = kAll;
// Migration/cutover: bulk DATA pauses while reserved control keeps flowing.
constexpr std::uint8_t kMigrationMask = kAll;
}  // namespace pause

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
  // queue entries still dispatch so the TX path can settle. Equivalent to a
  // pause with pause::kSleepDrainMask; composable with a set_pause mask.
  void set_draining(bool draining) noexcept { sleep_draining_ = draining; }
  bool draining() const noexcept { return sleep_draining_; }
  // Pause contract (01 §3.3): hold only the masked traffic categories so
  // migration/survey-critical control is not deadlocked by a blanket drain.
  // One operational reason is active at a time (SleepDrain is orthogonal and
  // owned by set_draining); the reserved control lane is never masked.
  Status set_pause(PauseReason reason, std::uint8_t mask) noexcept;
  Status clear_pause(PauseReason reason) noexcept;
  PauseReason pause_reason() const noexcept { return pause_reason_; }
  // Effective mask = active reason mask ∪ the sleep-drain bits.
  std::uint8_t pause_mask() const noexcept {
    return pause_mask_ | (sleep_draining_ ? pause::kSleepDrainMask : 0);
  }
  bool paused(std::uint8_t bits) const noexcept {
    return (pause_mask() & bits) != 0;
  }
  // True when no radio-bound work remains: empty TX queue, no physical
  // in-flight frame and no job waiting for a hop accept.
  bool quiesced() const noexcept {
    return !physical_.active && scheduler_.empty() && awaiting_hop_.size() == 0;
  }

  // --- Congestion control (03-congestion.md §4, §5) ----------------------------
  // Live scheduler/BUSY counters for tests, diagnostics and the P3 observer.
  CongestionStats congestion_stats() const noexcept;
  // Current per-peer in-flight window (1..4) used by the dispatch gate.
  std::uint8_t peer_tx_window(NodeId peer) const noexcept;
  // Marks a peer as implementing the Busy(20) feedback payload. Until
  // capability negotiation lands, BUSY replies are emitted only to peers
  // marked here or proven by a valid received BUSY (03 §5, scenario D4-09).
  void set_peer_busy_capable(NodeId peer, bool capable) noexcept;
  // Effective link cost currently fed to routing for `peer` (nominal base
  // adjusted by the measured exchange ratio and our egress queue penalty,
  // 03 §6). kInfiniteRouteMetric when the peer is unknown.
  RouteMetric peer_link_cost(NodeId peer) const noexcept;
  // Sustained-busy start time for `peer` (0 = not busy) — diagnostic/test
  // surface for the severe-busy fast-repair path (03 §7).
  MonotonicMs peer_busy_since(NodeId peer) const noexcept;
  // Authenticated neighbor pressure feedback (Busy.pressure field or
  // NeighborResult-derived, delivered by the link-authenticated ingress
  // path). Ordered per peer by the feedback sequence and honored only
  // inside its TTL; feeds ONLY the local busy/queue picture — a peer
  // self-report is a hint, never added to a route metric and never able
  // to admit an infeasible route (03 §6.2, D4-02).
  void note_peer_pressure(NodeId peer, std::uint8_t pressure,
                          std::uint32_t feedback_sequence,
                          MonotonicMs now_ms) noexcept;
  // Bounded observation aggregates (03 §3): EWMA + counters per key, never
  // raw samples. The global buckets feed diagnostics; the per-neighbor
  // mirrors drive the P3 route-metric coupling (03 §6).
  template <typename Fn>
  void for_each_observation(Fn fn) const noexcept {
    observations_.for_each(fn);
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
    scheduler_.clear();
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
  static constexpr std::uint32_t kNoFeedbackSeq = 0xFFFFFFFFu;

  struct Neighbor {
    NodeId node{kInvalidNodeId};
    RouteMetric metric{1};      // nominal link cost (add_neighbor input)
    RouteMetric link_cost{1};   // effective cost fed to RouteTable (03 §6)
    RouteGeneration generation{0};  // last origin generation the peer self-advertised
    std::uint8_t consecutive_failures{0};
    std::uint8_t route_cursor{0};  // rotation cursor for periodic route dumps
    // Congestion state (03-congestion.md §5): per-peer in-flight window and
    // the consecutive-authenticated-accept streak that grows it. A window is
    // NOT a memory-slot counter — freeing an awaiting slot never grows it.
    std::uint8_t tx_window{kPeerWindowInitial};
    std::uint8_t window_accepts{0};
    bool busy_capable{false};  // peer proved/configured for Busy(20) feedback
    // Highest feedback sequence accepted from this peer; stale/replayed
    // BUSY payloads are detected against it (FeedbackSequence ordering tag).
    // feedback_seen is separate so a first seq equal to the sentinel value
    // cannot disable ordering checks forever.
    std::uint32_t last_feedback_seq{kNoFeedbackSeq};
    bool feedback_seen{false};
    // Per-peer exchange measurement (03 §6.1): decaying-window counters of
    // eligible attempt work (every physical submission of a hop-accept
    // exchange — failures included) and authenticated accepts. Below
    // kExchangeMinAccepts the measured ratio is unused and cost stays
    // nominal.
    std::uint32_t exchange_work{0};
    std::uint32_t exchange_accepts{0};
    MonotonicMs exchange_window_ms{0};
    // Per-peer egress queue sojourn EWMA (03 §6.2): only OUR delay toward
    // this peer may penalize the link cost. Stale samples read as 0.
    std::uint32_t queue_sojourn_ewma_ms{0};
    std::uint32_t sojourn_samples{0};
    MonotonicMs last_sojourn_ms{0};
    // Sustained authenticated-busy feedback (03 §7 severe-busy): set while
    // matched BUSY deferrals or pressure hints keep arriving; cleared by an
    // authenticated accept or when feedback goes stale past its TTL. It is
    // a hint for the switch discipline, never a metric input. `busy_active`
    // is the state — busy_since_ms==0 is a legitimate timestamp (t=0), not
    // a "clear" sentinel.
    bool busy_active{false};
    MonotonicMs busy_since_ms{0};
    MonotonicMs last_busy_feedback_ms{0};
    std::uint8_t last_pressure{0};
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
    // RF-loss retry counter (03 §5 rf_attempts_max, per-job, never reset by
    // peer/rate changes) and the bound for it.
    std::uint8_t attempts{0};
    std::uint8_t max_attempts{1};
    MonotonicMs deadline_ms{0};
    wire::EncodedFrame encoded{};
    bool encoded_valid{false};
    // Scheduler metadata — assigned at admission, preserved across requeues.
    Priority priority{Priority::Normal};       // origin DATA class input
    std::uint32_t tx_cost{0};                  // estimated on-air bytes
    MonotonicMs enqueued_at_ms{0};             // queue-sojourn measurement base
    TxJob* flow_next{nullptr};                 // intrusive per-flow list link
    // Attempt budget accounting (contracts.json congestion.*).
    std::uint8_t busy_readmissions{0};
    std::uint8_t physical_attempts{0};
  };

  // Bounded TX scheduler (03-congestion.md §4): a single fixed pool of TxJob
  // slots shared by a small reserved control lane (ACK/required responses)
  // and four DRR classes charged by estimated TX cost, with per-flow
  // round-robin inside each class. No queue duplication — flows link pool
  // jobs intrusively and classes hold only descriptor pointers.
  class TxScheduler {
   public:
    TxScheduler() noexcept = default;

    // Admission decision for `slots_needed` additional non-control jobs from
    // (scope, origin). Pure check: reserves nothing, so the caller must
    // enqueue immediately after (single-threaded owner).
    AdmitVerdict check(NodeId self, NodeId scope, NodeId origin,
                       std::size_t slots_needed) const noexcept;
    Status enqueue(TxJob&& job, NodeId self, MonotonicMs now_ms) noexcept;
    // DRR pick of the next transmittable job (control lane first). A job
    // whose peer window is full is skipped for this pass, not dropped.
    // Returns nullptr when nothing is eligible.
    TxJob* select(MonotonicMs now_ms, const MeshNode& node) noexcept;
    void take_selected(TxJob& out) noexcept;
    // Put the selected job back at the head of its lane (driver rejected
    // the submission before any transmit attempt).
    void requeue_selected() noexcept;
    // Move the selected job to the TAIL of its lane: the dispatch-time
    // route re-check holds it (bounded by its original deadline) without
    // head-of-line blocking the rest of its flow (03 §7).
    void defer_selected() noexcept;
    void clear() noexcept;

    bool empty() const noexcept { return used_ == 0; }
    bool full() const noexcept { return used_ >= capacity(); }
    std::size_t size() const noexcept { return used_; }
    static constexpr std::size_t capacity() noexcept { return kTxQueueCapacity; }
    std::size_t free_slots() const noexcept { return capacity() - used_; }
    std::size_t control_depth() const noexcept { return control_.count; }
    std::size_t flows_active() const noexcept { return flows_.size(); }
    std::uint32_t occupancy_percent() const noexcept {
      return static_cast<std::uint32_t>(used_ * 100 / capacity());
    }
    // Queue watermarks (03 §4): >=50% shrink background probe/log work,
    // >=80% suspend bulk and improvement probes.
    bool background_reduced() const noexcept {
      return occupancy_percent() >= kQueueWatermarkBackgroundPercent;
    }
    bool bulk_suspended() const noexcept {
      return occupancy_percent() >= kQueueWatermarkStopPercent;
    }

    CongestionStats stats_{};

   private:
    // Intrusive FIFO of pool jobs; only pointers, never job copies.
    struct JobList {
      TxJob* head{nullptr};
      TxJob* tail{nullptr};
      std::size_t count{0};

      bool empty() const noexcept { return head == nullptr; }
      void push_back(TxJob* job) noexcept {
        job->flow_next = nullptr;
        if (tail != nullptr) tail->flow_next = job;
        tail = job;
        if (head == nullptr) head = job;
        ++count;
      }
      void push_front(TxJob* job) noexcept {
        job->flow_next = head;
        head = job;
        if (tail == nullptr) tail = job;
        ++count;
      }
      TxJob* pop_front() noexcept {
        TxJob* job = head;
        if (job != nullptr) {
          head = job->flow_next;
          if (head == nullptr) tail = nullptr;
          job->flow_next = nullptr;
          --count;
        }
        return job;
      }
    };

    // Flow key = (verified sender scope, origin, concrete destination) per
    // class. `overflow` marks the shared bounded bucket used when the 32
    // descriptor table is full — new admissions merge instead of failing.
    struct FlowDesc {
      JobList jobs{};
      NodeId scope{kInvalidNodeId};
      NodeId origin{kInvalidNodeId};
      NodeId destination{kInvalidNodeId};
      SchedClass sched_class{SchedClass::Normal};
      bool in_rr{false};
      bool overflow{false};
    };

    static bool control_job(const TxJob& job) noexcept;
    static SchedClass classify(const TxJob& job) noexcept;
    static void flow_key(const TxJob& job, NodeId self, NodeId& scope,
                         NodeId& origin, NodeId& destination) noexcept;
    static void charge_cost(TxJob& job) noexcept;
    static std::size_t class_index(SchedClass value) noexcept {
      return sched_class_index(value);
    }
    FlowDesc* overflow_flow(SchedClass value) noexcept {
      FlowDesc& flow = overflow_[class_index(value)];
      flow.sched_class = value;
      flow.overflow = true;
      return &flow;
    }
    std::size_t origin_count(NodeId origin) const noexcept;
    std::size_t scope_count(NodeId scope) const noexcept;
    static bool data_class(SchedClass value) noexcept {
      return value != SchedClass::Management;
    }

    static constexpr std::size_t kControlLaneCapacity = 8;
    static constexpr std::size_t kMaxJobsPerOrigin = 12;
    static constexpr std::size_t kMaxJobsPerScope = 12;
    // DRR: quantum per round per class = weight * 64 bytes of estimated
    // cost; a 250-byte bulk frame becomes affordable within a few rounds.
    static constexpr std::int32_t kQuantumUnit = 64;
    static constexpr std::int32_t kDeficitCap = 1024;
    static constexpr std::size_t kMaxSelectRounds = 8;
    static constexpr std::size_t kRrCapacity = kFlowDescriptorsMax + kSchedClassCount;

    FixedPool<TxJob, kTxQueueCapacity> pool_{};
    FixedPool<FlowDesc, kFlowDescriptorsMax> flows_{};
    std::array<FlowDesc, kSchedClassCount> overflow_{};
    JobList control_{};
    std::array<FixedQueue<FlowDesc*, kRrCapacity>, kSchedClassCount> rr_{};
    std::array<std::int32_t, kSchedClassCount> deficit_{};
    std::size_t used_{0};
    std::size_t cursor_{0};
    TxJob* selected_{nullptr};
    FlowDesc* selected_flow_{nullptr};
    bool selected_control_{false};
  };

  struct PhysicalInflight {
    TxJob job{};
    std::uint64_t token{0};
    MonotonicMs submitted_at_ms{0};
    bool active{false};
    // An authenticated BUSY arrived while the frame was with the driver:
    // the deferral is applied when the TX result lands (03 §5).
    bool busy_deferred{false};
    std::uint32_t busy_retry_ms{0};
  };

  struct AwaitingHop {
    TxJob job{};
    MonotonicMs expires_at_ms{0};
    // An authenticated BUSY deferred this exchange: on expiry the job is
    // re-admitted against its BUSY readmission budget instead of consuming
    // an RF-loss attempt (03 §5).
    bool busy_deferred{false};
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
  // BUSY emission (03 §5): pre-admission refusal for a NEW authenticated
  // inbound DATA — never for already HOP_ACCEPT-ed work. Emits only when the
  // peer is busy-capable and a reply slot is affordable; otherwise drops and
  // counts busy_send_failed so the sender's timeout path stays honest.
  Status queue_busy(NodeId peer, const wire::Header& rejected,
                    std::uint8_t reason, MonotonicMs now_ms) noexcept;
  void emit_busy_or_drop(NodeId peer, const wire::Header& rejected,
                         std::uint8_t reason, MonotonicMs now_ms) noexcept;
  Status queue_route_update(NodeId neighbor, MonotonicMs now_ms) noexcept;
  Status queue_seqno_request(NodeId peer, NodeId requester, NodeId destination,
                             RouteSequence requested_sequence, std::uint32_t request_id,
                             std::uint8_t ttl, MonotonicMs now_ms) noexcept;

  Status encode_job(TxJob& job, MonotonicMs now_ms) noexcept;
  void dispatch_next(MonotonicMs now_ms) noexcept;
  void complete_job(TxJob& job, bool hop_accepted, MonotonicMs now_ms) noexcept;
  void fail_job(TxJob& job, const char* reason, MonotonicMs now_ms) noexcept;
  void retry_or_fail(TxJob& job, const char* reason, MonotonicMs now_ms) noexcept;
  // Re-admit a BUSY-deferred job after its clamped retry_after wait, bounded
  // by busy_readmissions_max and the combined physical-attempt budget (03 §5).
  void readmit_after_busy(TxJob& job, MonotonicMs now_ms) noexcept;
  // Dispatch gate for the scheduler: a job that requires HOP_ACCEPT is
  // eligible only while the peer's in-flight count is below its window.
  bool tx_admitted_now(const TxJob& job) const noexcept;
  std::size_t peer_inflight(NodeId peer) const noexcept;
  std::uint8_t peer_window(NodeId peer) const noexcept;
  std::uint32_t busy_retry_hint() const noexcept;

  // P3 load coupling (03 §6/§7): per-neighbor observation decay, busy-TTL,
  // effective link-cost refresh and the route-switch hysteresis tick.
  void refresh_neighbor_load(MonotonicMs now_ms) noexcept;
  void refresh_link_cost(Neighbor& neighbor, MonotonicMs now_ms) noexcept;

  // Observation aggregation (03 §3): bounded buckets keyed by the contract
  // tuple. find-or-allocate returns nullptr only when the pool is exhausted.
  ObservationBucket* observation_bucket(std::uint8_t length_class,
                                        MonotonicMs now_ms) noexcept;
  void obs_tx_submitted(const TxJob& job, MonotonicMs now_ms) noexcept;
  void obs_driver_service(const TxJob& job, std::uint32_t service_us,
                          MonotonicMs now_ms) noexcept;
  void obs_hop_result(const TxJob& job, bool accepted, MonotonicMs now_ms) noexcept;
  void obs_count(const TxJob& job, std::uint64_t ObservationBucket::*counter,
                 MonotonicMs now_ms) noexcept;
  void obs_final(const Delivery& delivery, DeliveryState state,
                 MonotonicMs now_ms) noexcept;

  void handle_hop_accept(const wire::PlainFrame& frame, NodeId peer,
                         MonotonicMs now_ms) noexcept;
  void handle_data(const wire::LinkOpenedFrame& frame, NodeId peer,
                   MonotonicMs now_ms) noexcept;
  void handle_busy(const wire::LinkOpenedFrame& frame, NodeId peer,
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
  TxScheduler scheduler_{};
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
  // Node-global ordering tag stamped on emitted BUSY payloads; receivers
  // compare it per-peer to reject stale/replayed feedback (03 §5).
  std::uint32_t next_feedback_sequence_{1};
  // BUSY-side statistics; merged into congestion_stats() with the
  // scheduler's own counters.
  CongestionStats busy_stats_{};
  // Bounded observation buckets (03 §3 groundwork for P3).
  static constexpr std::size_t kObservationCapacity = 8;
  FixedPool<ObservationBucket, kObservationCapacity> observations_{};
  // Latest wall time seen on the event path; observation timestamps use it
  // where the call site (e.g. delivery-state transitions) has no clock.
  MonotonicMs last_clock_ms_{0};
  std::uint32_t work_generation_{0};
  std::uint32_t rx_generation_{0};
  std::uint32_t config_revision_{0};
  bool started_{false};
  bool sleep_draining_{false};
  PauseReason pause_reason_{PauseReason::None};
  std::uint8_t pause_mask_{0};
};

}  // namespace routeloom
