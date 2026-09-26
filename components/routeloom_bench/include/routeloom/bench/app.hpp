#pragma once

// Bench application module (design-devflow.md §5): the state machine behind
// firmware/bench_node, built only on the public SDK surface — MeshNode::send
// /send_group, NodeObserver callbacks, delivery results, group membership.
//
// Reentrancy discipline (node.hpp): NodeObserver callbacks only copy into
// the bounded queues below; every reply, generator send and control action
// runs on the owner's poll() — nothing calls back into the node mid-callback.
//
// Control commands (PEER_SEND_*, COUNTER_RESET, FAULT_SET, RESET_REQUEST) are
// accepted only from the authorized controller over end-protected unicast —
// the SDK marks every application DATA payload end-protected, so the check is
// the origin identity, never group membership. Each control body carries the
// target boot incarnation it was minted against so a replayed command after
// a reset refuses instead of restarting a bounded run.

#include <array>
#include <cstddef>
#include <cstdint>

#include "routeloom/bench/protocol.hpp"
#include "routeloom/byte_io.hpp"
#include "routeloom/node.hpp"
#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom::bench {

// Device resources the portable module cannot know — supplied by the small
// ESP-IDF port inside firmware/bench_node (design §5.1: no ESP dependencies
// in the portable half).
class BenchPlatform {
 public:
  virtual ~BenchPlatform() = default;
  virtual std::uint32_t heap_free_bytes() const noexcept = 0;
  virtual std::uint32_t heap_min_free_bytes() const noexcept = 0;
  virtual std::uint32_t heap_largest_free_bytes() const noexcept = 0;
  virtual std::uint32_t stack_high_water_bytes() const noexcept = 0;
  virtual std::uint8_t reset_cause() const noexcept = 0;
  // Restart after the already-armed delay elapses (poll context). A test
  // port records instead of restarting.
  virtual void restart() noexcept = 0;
};

// Read-only lifecycle/board observation (design §5.3). Today the firmware
// fills this from the public SecurityCoordinator snapshot + site store +
// node stats; the D02 board config and the planned D05 NodeHealth/
// LifecycleSnapshot contract plug in here — unpopulated fields stay at the
// zero "unknown" value.
struct BenchProbeSample {
  bool participation_valid{false};
  std::uint8_t mode{0};
  std::uint8_t membership{0};
  std::uint8_t joiner{0};
  std::uint8_t joiner_error{0};
  std::uint32_t joiner_observations{0};
  std::uint32_t radio_generation{0};
  std::uint8_t authority_flags{0};  // bit0 started, 1 ready, 2 busy, 3 join_confirmed
  std::uint8_t refresh_strikes{0};
  std::uint16_t link_sessions{0};
  std::uint16_t end_sessions{0};
  bool site_valid{false};
  std::uint64_t site_id{0};
  std::uint32_t gk_epoch_current{0};
  std::uint32_t gk_epoch_next{0};
  std::uint32_t assignment_generation{0};
  std::uint8_t role{0};
  std::uint8_t route_profile{0};  // 0 flat, 1 gateway-scoped
  NodeId gateway{kInvalidNodeId};
};

class BenchProbe {
 public:
  virtual ~BenchProbe() = default;
  virtual void sample(BenchProbeSample& out) noexcept = 0;
};

struct BenchConfig {
  // Authorized control origin (the site gateway); 0 means "no override —
  // authorize the node's first configured route gateway".
  NodeId controller{kInvalidNodeId};
  std::uint8_t app_version{1};
  std::uint32_t firmware_digest{0};
  // D02 BoardConfig digest — 0 until individual configuration lands.
  std::uint32_t config_digest{0};
};

// Application counters, surfaced on STATUS page 2 and asserted by tests.
struct BenchStats {
  std::uint32_t rx_total{0};          // application payloads accepted for dispatch
  std::uint32_t rx_dropped{0};        // bounded RX queue overflows
  std::uint32_t malformed{0};         // header decode failures (truncated/magic/version)
  std::uint32_t invalid_requests{0};  // known opcode, undecodable body or wrong channel
  std::uint32_t crc_invalid{0};       // body CRC mismatches
  std::uint32_t unknown_opcode{0};
  std::uint32_t responses_seen{0};    // kFlagResponse input — never answered
  std::uint32_t unauthorized{0};      // control from a non-controller origin or group
  std::uint32_t stale_boot{0};        // control/bound traffic for a previous incarnation
  std::uint32_t duplicate_commands{0};
  std::uint32_t late_requests{0};     // requests for retired/unknown runs
  std::uint32_t echo_answered{0};
  std::uint32_t echo_suppressed{0};
  std::uint32_t reply_dropped{0};     // reply queue saturation
  std::uint32_t reply_send_failed{0};
  std::uint32_t rollcalls{0};
  std::uint32_t status_sent{0};
  std::uint32_t group_ignored{0};     // non-rollcall group payloads
  std::uint32_t delivery_events_dropped{0};
  std::uint32_t resets_executed{0};
  std::uint32_t send_load_sent{0};    // packets emitted by the send-load fault
};

// STATUS page ids (design §5.3 categories, bounded per page).
namespace status_page {
inline constexpr std::uint8_t kIdentity = 0;       // ids, time, digests
inline constexpr std::uint8_t kParticipation = 1;  // coordinator/site snapshot
inline constexpr std::uint8_t kCounters = 2;       // BenchStats above
inline constexpr std::uint8_t kRun0 = 3;           // run table slot 0
inline constexpr std::uint8_t kRun1 = 4;           // run table slot 1
inline constexpr std::uint8_t kGenerator = 5;      // peer-send run state
inline constexpr std::uint8_t kResources = 6;      // platform + rollcall track
inline constexpr std::uint8_t kCount = 7;
}  // namespace status_page

class BenchApp final : public NodeObserver {
 public:
  // Bounds (design §5.4): reply queue 4, two tracked runs, one generator.
  static constexpr std::size_t kRxQueueDepth = 4;
  static constexpr std::size_t kReplyQueueDepth = 4;
  // One outstanding generator send consumes at most one delivery event; a
  // second slot would sit empty forever.
  static constexpr std::size_t kDeliveryEventDepth = 1;
  static constexpr std::size_t kRunSlots = 2;
  // Tombstone ring for just-evicted runs — deeper than the live slots so a
  // run displaced by two newer arrivals still reads as late, never reopened.
  static constexpr std::size_t kRetiredDepth = 3;
  // Command-replay window; cross-incarnation replays are refused by the
  // expected_boot check, so the log only covers in-incarnation replays.
  static constexpr std::size_t kCmdLogDepth = 2;
  static constexpr std::uint8_t kGeneratorMaxInflight = 1;
  static constexpr std::uint16_t kGeneratorMaxCount = 64;
  // A generator run lives at most this long regardless of pace (design
  // §5.2: 64 packets or 60 s, whichever first).
  static constexpr std::uint32_t kGeneratorMaxDurationMs = 60000;
  static constexpr std::uint32_t kMaxFaultDurationMs = 60000;
  // An echo/counter run with no traffic for this long retires to the
  // tombstone ring; further packets for it are late, never a restart.
  static constexpr std::uint32_t kRunIdleMs = 60000;
  static constexpr std::uint32_t kReplyTtlMs = 5000;
  // Backoff between send attempts for a parked reply (transient refusals).
  static constexpr std::uint32_t kReplyRetryMs = 100;
  static constexpr std::uint32_t kRollcallJitterMs = 200;

  explicit BenchApp(const BenchConfig& config) noexcept;

  // Apply the image/board settings after platform initialization, before
  // traffic starts. Firmware digests are unavailable during static init.
  void configure(const BenchConfig& config) noexcept { config_ = config; }

  // The node must outlive the app. Call before traffic; boot is read from
  // node.config() at use time so member adoption can re-bind it.
  void attach(MeshNode& node, MonotonicMs now_ms) noexcept;
  void set_platform(BenchPlatform* platform) noexcept { platform_ = platform; }
  void set_probe(BenchProbe* probe) noexcept { probe_ = probe; }

  // Owner-loop step: drain the bounded queues, run the generator, send due
  // replies, retire idle runs, fire an armed reset.
  void poll(MonotonicMs now_ms) noexcept;

  const BenchStats& stats() const noexcept { return stats_; }
  // Snapshot generation stamped on every STATUS page (§5.3): bumps on
  // structural state change so a host can detect an interrupted page scan.
  std::uint16_t status_version() const noexcept { return status_version_; }

  // Observer surface — copies only, never calls back into the node.
  void on_message(const MessageKey& key, NodeId source,
                  ByteView payload) noexcept override;
  void on_delivery(const DeliveryResult& result) noexcept override;
  void on_diagnostic(const char* reason, NodeId peer,
                     const MessageId* message) noexcept override;
  void on_group_message(const GroupMessageInfo& info,
                        ByteView payload) noexcept override;

 private:
  struct RxEntry {
    // The wire-level MessageId and group metadata are not needed by the app:
    // bench replies correlate on the bench header's run_uuid/sequence and
    // always answer the origin over unicast.
    NodeId origin{kInvalidNodeId};
    bool is_group{false};
    bool group_late{false};
    std::array<std::uint8_t, kMaxApplicationPayload> buf{};
    std::uint8_t len{0};
    bool used{false};
  };

  struct ReplyEntry {
    NodeId destination{kInvalidNodeId};
    MonotonicMs not_before{0};
    MonotonicMs expires_ms{0};
    std::array<std::uint8_t, kMaxApplicationPayload> buf{};
    std::uint8_t len{0};
    bool used{false};
    bool reset_ack{false};
  };

  struct DeliveryEvent {
    MessageId id{};
    DeliveryState state{DeliveryState::Empty};
    bool used{false};
  };

  // Per-run reception window and statistics (§5.2 counter/echo tracking).
  // window bit i marks sequence (window_base - i) seen; a sequence above the
  // base shifts the window, below base-63 is late.
  struct RunRecord {
    bool used{false};
    RunUuid uuid{};
    std::uint32_t window_base{0};
    std::uint64_t window{0};
    std::uint32_t unique_packets{0};
    std::uint32_t unique_bytes{0};
    std::uint32_t duplicates{0};
    std::uint32_t crc_invalid{0};
    std::uint32_t first_ms{0};
    std::uint32_t last_ms{0};
    MonotonicMs last_active{0};
  };

  struct Generator {
    bool active{false};
    std::uint8_t state{gen_state::kIdle};
    RunUuid uuid{};
    NodeId commander{kInvalidNodeId};
    NodeId destination{kInvalidNodeId};
    std::uint32_t sequence_begin{0};
    std::uint16_t count{0};
    std::uint16_t sent{0};
    std::uint8_t payload_len{0};
    std::uint32_t seed{0};
    std::uint32_t interval_ms{0};
    std::uint32_t ttl_ms{0};
    MonotonicMs next_due{0};
    MonotonicMs deadline_ms{0};
    bool inflight{false};
    MessageId inflight_id{};
    MonotonicMs inflight_deadline{0};
    // The destination boot incarnation this run is bound to (stamped into
    // every COUNT_ONLY); dest_reset latches when the destination reports
    // the run stale, i.e. it rebooted — further outcomes are unknown.
    std::uint64_t dest_boot{0};
    bool dest_reset{false};
    // Terminal SDK verdicts for the at-most-64 submitted sequences. A
    // delayed stale notice can correct exactly its own verdict once, even
    // if the generator has already finished or notices arrive out of order.
    std::uint64_t delivered_mask{0};
    std::uint64_t failed_mask{0};
    std::uint16_t submitted{0};
    std::uint16_t admitted{0};
    std::uint16_t delivered{0};
    std::uint16_t failed{0};
    std::uint16_t unknown{0};
    std::uint32_t first_ms{0};
    std::uint32_t last_ms{0};
  };

  struct RollcallTrack {
    RunUuid last_uuid{};
    std::uint32_t last_seq{0};
    std::uint32_t last_ms{0};
    std::uint32_t count{0};
    bool announced{false};
    std::uint16_t version_at_reply{0};
    bool pending{false};
    MonotonicMs not_before{0};
    NodeId reply_to{kInvalidNodeId};
    std::uint8_t page{kRollcallNoPage};
  };

  // Command dedup key (design §5.2): (origin, run_uuid, command_seq,
  // boot_incarnation). boot is stored explicitly so the quad is visible;
  // entries never outlive the incarnation that minted them anyway.
  struct CmdSeen {
    NodeId origin{kInvalidNodeId};
    RunUuid run{};
    std::uint32_t seq{0};
    std::uint32_t boot{0};  // low word of boot_incarnation
    bool used{false};
  };

  struct Faults {
    MonotonicMs echo_suppress_until{0};
    MonotonicMs echo_delay_until{0};
    std::uint32_t echo_delay_ms{0};
    // Bounded send-load fault: one COUNT_ONLY to the commander every
    // send_load_period_ms until send_load_until.
    MonotonicMs send_load_until{0};
    MonotonicMs send_load_next{0};
    NodeId send_load_to{kInvalidNodeId};
    std::uint32_t send_load_period_ms{0};
    std::uint32_t send_load_seq{0};
  };

  void enqueue_rx(NodeId origin, ByteView payload, bool is_group,
                  bool group_late) noexcept;
  void drain_rx(MonotonicMs now_ms) noexcept;
  void dispatch(const RxEntry& entry, const Message& msg,
                MonotonicMs now_ms) noexcept;
  void drain_delivery(MonotonicMs now_ms) noexcept;
  void drain_replies(MonotonicMs now_ms) noexcept;
  void drive_generator(MonotonicMs now_ms) noexcept;
  void drive_rollcall(MonotonicMs now_ms) noexcept;
  void drive_reset(MonotonicMs now_ms) noexcept;
  void drive_send_load(MonotonicMs now_ms) noexcept;
  void retire_idle_runs(MonotonicMs now_ms) noexcept;
  void maybe_announce(MonotonicMs now_ms) noexcept;

  bool authorized(NodeId origin) const noexcept;
  bool cmd_duplicate(NodeId origin, const RunUuid& run,
                     std::uint32_t seq) noexcept;

  void handle_echo(const RxEntry& entry, const Message& msg,
                   MonotonicMs now_ms) noexcept;
  void handle_count(const RxEntry& entry, const Message& msg,
                    MonotonicMs now_ms) noexcept;
  // A COUNT_STATUS reply that names the current or last generator run can
  // be the destination's stale-binding notice.
  void handle_count_status(const RxEntry& entry, const Message& msg,
                           MonotonicMs now_ms) noexcept;
  void handle_count_get(const RxEntry& entry, const Message& msg,
                        MonotonicMs now_ms) noexcept;
  void handle_rollcall(const RxEntry& entry, const Message& msg,
                       MonotonicMs now_ms) noexcept;
  void handle_status_get(const RxEntry& entry, const Message& msg,
                         MonotonicMs now_ms) noexcept;
  void handle_peer_send_start(const RxEntry& entry, const Message& msg,
                              MonotonicMs now_ms) noexcept;
  void handle_peer_send_stop(const RxEntry& entry, const Message& msg,
                             MonotonicMs now_ms) noexcept;
  void handle_peer_send_status(const RxEntry& entry, const Message& msg,
                               MonotonicMs now_ms) noexcept;
  void fill_generator_status(const RunUuid& run,
                             PeerSendStatusBody& reply) const noexcept;
  void handle_counter_reset(const RxEntry& entry, const Message& msg,
                            MonotonicMs now_ms) noexcept;
  void handle_fault_set(const RxEntry& entry, const Message& msg,
                        MonotonicMs now_ms) noexcept;
  void handle_reset_request(const RxEntry& entry, const Message& msg,
                            MonotonicMs now_ms) noexcept;

  bool enqueue_reply(NodeId destination, std::uint8_t opcode,
                     std::uint16_t flags, const RunUuid& run,
                     std::uint32_t sequence, ByteView body,
                     MonotonicMs not_before, MonotonicMs now_ms,
                     bool reset_ack = false) noexcept;
  RunRecord* find_run(const RunUuid& uuid) noexcept;
  const RunRecord* find_run(const RunUuid& uuid) const noexcept;
  RunRecord* open_run(const RunUuid& uuid, std::uint32_t seq,
                      MonotonicMs now_ms) noexcept;
  bool run_retired(const RunUuid& uuid) const noexcept;
  void tombstone(const RunUuid& uuid) noexcept;
  // Returns 0 fresh-bit-set, 1 duplicate (in-window seen), 2 late.
  std::uint8_t window_mark(RunRecord& run, std::uint32_t seq) noexcept;
  bool fault_active(MonotonicMs now_ms) const noexcept;
  void bump_version() noexcept { ++status_version_; }
  std::uint64_t boot_incarnation() const noexcept;
  void status_page_fields(std::uint8_t page, ByteWriter& out,
                          MonotonicMs now_ms) noexcept;
  void send_status(NodeId to, const RunUuid& run, std::uint32_t seq,
                   std::uint8_t page, MonotonicMs now_ms) noexcept;

  MeshNode* node_{nullptr};
  BenchPlatform* platform_{nullptr};
  BenchProbe* probe_{nullptr};
  BenchConfig config_{};
  MonotonicMs attached_ms_{0};
  bool announced_{false};
  std::uint16_t status_version_{0};
  std::uint8_t retired_count_{0};
  std::uint8_t cmd_cursor_{0};
  BenchStats stats_{};
  Generator generator_{};
  RollcallTrack rollcall_{};
  Faults faults_{};
  bool reset_armed_{false};
  bool reset_pending_{false};
  bool reset_ack_submitted_{false};
  bool reset_ack_result_pending_{false};
  std::uint32_t reset_delay_ms_{0};
  MonotonicMs reset_at_ms_{0};
  MessageId reset_ack_id_{};
  DeliveryState reset_ack_delivery_{DeliveryState::Empty};
  RxEntry rx_[kRxQueueDepth];
  ReplyEntry replies_[kReplyQueueDepth];
  DeliveryEvent deliveries_[kDeliveryEventDepth];
  RunRecord runs_[kRunSlots];
  RunUuid retired_[kRetiredDepth];
  CmdSeen cmd_log_[kCmdLogDepth];
};

}  // namespace routeloom::bench
