#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "esp_now.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "routeloom/autonomy_wire.hpp"
#include "routeloom/channel_plan.hpp"
#include "routeloom/discovery.hpp"
#include "routeloom/migration_wire.hpp"
#include "routeloom/node.hpp"

namespace routeloom::espnow {

struct MacAddress {
  std::array<std::uint8_t, 6> bytes{};

  friend bool operator==(const MacAddress& left, const MacAddress& right) noexcept {
    return left.bytes == right.bytes;
  }
};

struct EspNowRuntimeConfig {
  NodeConfig node{};
  std::uint8_t channel{1};
  std::array<char, 3> country{{'J', 'P', '\0'}};
  std::uint8_t country_first_channel{1};
  std::uint8_t country_channel_count{13};
  std::int8_t max_tx_power_qdbm{-128};  // Must be explicitly set by an approved deployment profile.
  std::uint32_t task_stack_bytes{8192};
  UBaseType_t task_priority{5};
  BaseType_t task_core{tskNO_AFFINITY};
};

// Radio Owner for the autonomous-mesh profile (01-integration §2-§3). Two
// strictly separated RX lanes exist after the single carrier classification:
//   - known-peer lane: verified Wire v1 traffic from peers_ (driver-registered
//     node mappings), drained into MeshNode as before;
//   - bootstrap lane: bounded RLD1-only queue feeding the attached
//     NeighborDiscovery engine; unknown-MAC non-RLD1 frames still drop.
// TX keeps one reserved completion slot for MeshNode work; bootstrap/
// autonomy sends never consume it — their send callbacks are accounted
// separately (01 §3.1).
class EspNowRuntime final : public RadioPort,
                            public DiscoveryPort,
                            public AutonomyFrameSink,
                            public MigrationWirePort {
 public:
  static constexpr std::size_t kPeerCapacity = 19;
  static constexpr std::size_t kEventQueueCapacity = 48;
  static constexpr std::size_t kBootstrapQueueCapacity = 8;
  // contracts.json peer_partition: broadcast 1 + regular 16 + transient 3
  // = driver maximum 20. The regular budget applies only while a discovery
  // engine is attached; without one all kPeerCapacity slots stay available
  // to the static register_neighbor path.
  static constexpr std::size_t kRegularPeerBudget =
      discovery_const::kRegularPeerSlots;
  static constexpr std::size_t kTransientPeerCapacity =
      discovery_const::kTransientPeerSlots;
  static constexpr std::int8_t kTxPowerUnset = -128;
  // The ESP-NOW send callback identifies a completion only by
  // (des_addr, status). To keep completions attributable, at most one
  // non-reserved autonomy send per MAC may be in flight, and the reserved
  // DATA slot is refused while a raw send targets the same MAC.
  static constexpr std::size_t kRawTxCapacity = 4;

  EspNowRuntime(const EspNowRuntimeConfig& config, SecurityProvider& security,
                NodeObserver& observer) noexcept;
  ~EspNowRuntime() override;

  EspNowRuntime(const EspNowRuntime&) = delete;
  EspNowRuntime& operator=(const EspNowRuntime&) = delete;

  Status initialize() noexcept;
  Status register_neighbor(NodeId node, const MacAddress& mac,
                           RouteMetric link_metric) noexcept;
  Status start() noexcept;
  Status start_task(const char* name = "routeloom") noexcept;
  void stop() noexcept;
  void poll_once() noexcept;

  // Attach the autonomy stack: `engine` must be constructed with this
  // runtime as its DiscoveryPort and must outlive the runtime. Installs the
  // autonomy sink on the node and registers the permanent broadcast driver
  // peer (LR250 applied). Optional — when never called the runtime behaves
  // exactly like the static-peer build.
  Status attach_autonomy(NeighborDiscovery& engine) noexcept;
  NeighborDiscovery* discovery() const noexcept { return discovery_; }

  // Observed station MAC, valid after initialize(); the discovery config and
  // auth transcript bind to this address.
  Status local_mac(routeloom::MacAddress& out) const noexcept;

  std::uint8_t channel() const noexcept { return config_.channel; }
  MonotonicMs now_ms() const noexcept;
  static std::uint64_t now_us() noexcept;
  // Iterate registered peer mappings (NodeId, MAC, link metric,
  // autonomy-managed flag) for the power coordinator's peer-cache capture.
  template <typename Fn>
  void for_each_peer(Fn fn) const noexcept {
    for (const auto& peer : peers_) {
      if (peer.used) fn(peer.node, peer.mac, peer.metric, peer.autonomy);
    }
  }
  // Marks the runtime as started when node bring-up was driven by a
  // PowerCoordinator resume path instead of start().
  void mark_started() noexcept { started_ = true; }

  Status send_application(NodeId destination, ByteView payload,
                          const SendOptions& options, MessageId& id) noexcept;
  DeliveryResult delivery(const MessageId& id) const noexcept { return node_.delivery(id); }
  MeshNode& node() noexcept { return node_; }

  // Autonomy-side diagnostic tap: discovery/migration engines surface
  // bounded reason strings through the SAME NodeObserver the mesh uses, so
  // they ride the existing device→host diagnostic frames (USB bridge).
  // Rate-limited downstream — event producers stay infrequent.
  void note_diagnostic(const char* reason, NodeId peer) noexcept;

  Status send(NodeId peer, std::uint64_t token, ByteView frame) noexcept override;
  Status recover() noexcept override;

  // --- DiscoveryPort (02-discovery.md §4) -------------------------------------
  // Bootstrap-lane TX. Unicast destinations occupy a bounded transient
  // driver peer; the broadcast address uses the permanent broadcast peer.
  // RLD1 carries only Discover/Offer/BootstrapAuth/BootstrapChunk/
  // BootstrapReply — never DATA.
  Status send_rld1(const routeloom::MacAddress& dest,
                   ByteView encoded) noexcept override;
  // Authenticated Wire-lane autonomy TX (NeighborProbe/NeighborResult only):
  // sealed under the link scope through the existing SecurityProvider and
  // sent to the verified binding's driver peer.
  Status send_wire(BindingId binding, const routeloom::MacAddress& dest,
                   FrameType type, ByteView payload) noexcept override;

  // --- AutonomyFrameSink --------------------------------------------------------
  // Wire-lane autonomy RX after MeshNode's open_link + identity checks.
  void on_autonomy_frame(NodeId peer, FrameType type, ByteView payload,
                         MonotonicMs now_ms) noexcept override;
  // Verify oracle (04 §10): forwards authenticated traffic to the migration
  // sink — but ONLY while no radio operation owns the channel. Frames
  // observed during a survey/helper visit or mid-cutover drain are
  // old-channel/stale traffic and can never prove new-channel connectivity.
  void note_link_activity(NodeId peer, MonotonicMs now_ms) noexcept override;

  // --- Migration transport (04 §5-§9, P5b) ---------------------------------------
  // Attach the migration sink (the EspNowMigration bundle's agent). While
  // attached, link-authenticated TimeSync/ChannelNotice/ControlObject/
  // ObjectChunk/ObjectAck payloads are routed to it, its poll() runs inside
  // poll_once(), and the runner's visit hard cap is raised to the committed
  // helper dwell (800ms) so old-channel serve visits fit — coordinator
  // survey leases keep enforcing the 200ms bound themselves.
  Status attach_migration(MigrationFrameSink& sink) noexcept;
  MigrationFrameSink* migration() const noexcept { return migration_; }

  // --- MigrationWirePort ---------------------------------------------------------
  // Sealed Wire v1 autonomy-payload TX to a verified peer (any registered
  // driver peer; autonomy-managed peers additionally require a Bound/
  // Reachable record). Blocked while a serialized channel operation owns
  // the radio EXCEPT during the off-channel dwell, where the helper-serve
  // traffic is the visit's whole purpose.
  Status migration_send(NodeId peer, FrameType type,
                        ByteView payload) noexcept override;
  std::size_t migration_peers(NodeId* out,
                              std::size_t capacity) const noexcept override;

  // The serialized channel-operation runner — the migration engine's only
  // path to the radio (04 §8).
  ChannelOperationRunner& channel_operations() noexcept {
    return channel_runner_;
  }

  // --- Radio operation arbiter (01 §3.3, 04 §3/§8) ------------------------------
  // The ONLY path that may switch the radio channel: applications and
  // feature code must never call esp_wifi_set_channel directly. One
  // operation is serialized at a time by the portable runner; the result
  // follows the P0 contract (APPLIED/REJECTED/FAILED/INDETERMINATE).
  OperationToken request_radio_operation(const RadioOperation& op) noexcept;
  bool radio_operation_result(OperationToken token,
                              OperationResult& out) const noexcept;
  bool radio_operation_busy() const noexcept;
  // Radio configuration generation: bumped on every verified switch so
  // stale TX completions cannot be attributed to a newer configuration.
  RadioGeneration radio_generation() const noexcept;
  // Completions that arrived after a config fence: accounted separately,
  // never merged with success or failure (X-02).
  std::uint32_t stale_tx_results() const noexcept { return stale_tx_results_; }
  // RX events dropped because a queue was full — load evidence (05 §5),
  // counted separately for the bootstrap lane and the normal lane.
  std::uint32_t bootstrap_rx_dropped() const noexcept {
    return bootstrap_rx_dropped_;
  }
  std::uint32_t rx_dropped() const noexcept { return rx_dropped_; }
  // Recovery-required visibility (02 §2.3): a fenced or quarantined MAC
  // stays unavailable until its owed callback arrives or recover()
  // rebuilds the driver — the host must be able to see that state.
  bool tx_fence_active() const noexcept { return fenced_outstanding_; }
  std::size_t quarantined_peers() const noexcept { return quarantined_count_; }

 private:
  enum class EventKind : std::uint8_t { Rx, Tx };
  // TX completion provenance (02-telemetry §2.2): which lane a send callback
  // belongs to. Stale/fenced completions are evidence under their ORIGINAL
  // generations — they resolve nothing in the node.
  enum class TxLane : std::uint8_t { Reserved, Raw, Stale };
  struct Event {
    EventKind kind{EventKind::Rx};
    NodeId peer{kInvalidNodeId};
    // The MAC the frame actually arrived from — resolved once at enqueue so
    // a later peer-table remap cannot reattribute the frame (TOCTOU).
    routeloom::MacAddress source{};
    std::uint64_t token{0};
    std::uint16_t length{0};
    std::int8_t rssi_dbm{0};
    bool success{false};
    // D1b observation fields: captured in the callback, attributed by the
    // generations recorded at submit time so a stale callback can never mint
    // evidence under a newer radio/channel identity.
    TxLane tx_lane{TxLane::Reserved};
    std::uint64_t observed_us{0};    // rx: enqueue stamp (esp_timer); tx: completed_us
    std::uint64_t submitted_us{0};   // tx only
    BindingGeneration binding{};
    RadioGeneration radio_generation{};
    ChannelEpoch channel_epoch{};
    std::uint8_t channel{0};
    std::uint8_t frame_length_class{0};
    bool rssi_valid{false};
    bool channel_valid{false};
    std::array<std::uint8_t, kMaxEspNowBody> data{};
  };
  // Bootstrap-lane record: self-contained RLD1 envelope + observed metadata.
  // No NodeId is resolved in the callback (01 §3.1). `destination` is the
  // observed des_addr so the scope filter can enforce DISCOVER-broadcast /
  // OFFER-unicast and bind the MAC input (02-discovery-scope §2.4).
  struct BootstrapEvent {
    routeloom::MacAddress source{};
    routeloom::MacAddress destination{};
    MonotonicMs received_ms{0};
    std::uint16_t length{0};
    std::int8_t rssi_dbm{0};
    std::array<std::uint8_t, autonomy::kRld1MaxTotal> data{};
  };
  struct Peer {
    NodeId node{kInvalidNodeId};
    MacAddress mac{};
    RouteMetric metric{1};
    bool used{false};
    bool driver_registered{false};
    // Set for slots owned by the discovery lease sync: they may be released
    // on phase transitions. Static register_neighbor entries are never
    // auto-released.
    bool autonomy{false};
    // Whether this peer was added to the MeshNode neighbor table at
    // REACHABLE (so a later release can undo exactly that).
    bool neighbor_added{false};
    // Discovery binding generation mirrored from the engine — the identity
    // epoch stamped on this peer's RX/TX observations (02 §2.4). 0 until
    // the first bound record resolves it.
    BindingGeneration binding{0};
  };
  // A driver peer held for an in-flight auth exchange — no NodeId exists yet
  // (the claimed id is unverified until the transcript verifies).
  struct TransientPeer {
    MacAddress mac{};
    bool used{false};
  };

  static void receive_callback(const esp_now_recv_info_t* info,
                               const std::uint8_t* data, int length) noexcept;
  static void send_callback(const esp_now_send_info_t* info,
                            esp_now_send_status_t status) noexcept;
  static void task_entry(void* argument) noexcept;
  // Cheap callback-side carrier check: full RLD1 magic+version, fixed header
  // length, total length consistency and the {1,2,3,5,6} kind allowlist.
  // Anything passing this goes to the bootstrap lane; a later full
  // rld1_decode failure in the worker is a REJECT, never a Wire fallback.
  static bool classify_bootstrap(const std::uint8_t* data, int length) noexcept;

  static EspNowRuntime* instance_;
  static portMUX_TYPE callback_lock_;

  Peer* find_peer(NodeId node) noexcept;
  const Peer* find_peer(NodeId node) const noexcept;
  Peer* find_peer(const std::uint8_t mac[6]) noexcept;
  const Peer* find_peer(const std::uint8_t mac[6]) const noexcept;
  TransientPeer* find_transient(const std::uint8_t mac[6]) noexcept;
  Status initialize_wifi() noexcept;
  Status initialize_espnow() noexcept;
  Status add_driver_peer(const MacAddress& mac) noexcept;
  Status register_driver_peer(Peer& peer) noexcept;
  Status register_broadcast_peer() noexcept;
  Status ensure_transient_peer(const MacAddress& mac) noexcept;
  Status promote_to_regular(NodeId node, const MacAddress& mac) noexcept;
  void release_driver_peer(const MacAddress& mac, NodeId node) noexcept;
  void release_autonomy_peer(Peer& peer, MonotonicMs now) noexcept;
  void reconcile_autonomy(MonotonicMs now) noexcept;
  Status send_raw(const MacAddress& mac, ByteView frame) noexcept;
  Status apply_lr250(const MacAddress& mac) noexcept;
  Status rebuild_driver() noexcept;

  // --- ChannelPort implementation (nested: the Owner's driver surface) ----------
  class OwnerChannelPort final : public routeloom::ChannelPort {
   public:
    explicit OwnerChannelPort(EspNowRuntime& owner) noexcept : owner_(owner) {}
    bool tx_quiesced() const noexcept override;
    Status set_channel(std::uint8_t channel) noexcept override;
    Status readback_channel(std::uint8_t& channel) noexcept override;
    Status reapply_peer_radio() noexcept override;
    void fence_pending_tx() noexcept override;
    void committed_channel(std::uint8_t channel) noexcept override;

   private:
    EspNowRuntime& owner_;
  };
  static ChannelOpsConfig ops_config_for(
      const EspNowRuntimeConfig& config) noexcept;
  bool channel_tx_quiesced() const noexcept;
  Status channel_set(std::uint8_t channel) noexcept;
  Status channel_readback(std::uint8_t& channel) noexcept;
  Status channel_reapply_peers() noexcept;
  void channel_fence_tx() noexcept;
  // Caller holds callback_lock_. Purges quarantine entries whose radio
  // generation is no longer current, then reports whether `mac` remains
  // quarantined (a callback is still owed for a retired send to it).
  bool tx_quarantined(const MacAddress& mac) noexcept;
  // Stage a TX completion event when event_queue_ refuses it. Caller holds
  // callback_lock_. Bounded; overflow is counted via telemetry_event_drops_.
  void stage_lost_tx(const Event& event) noexcept;
  void channel_committed(std::uint8_t channel) noexcept;

  void enqueue_rx(const esp_now_recv_info_t* info,
                  const std::uint8_t* data, int length) noexcept;
  void enqueue_tx(const esp_now_send_info_t* info,
                  esp_now_send_status_t status) noexcept;
  std::size_t regular_used() const noexcept;
  std::size_t regular_budget() const noexcept;

  EspNowRuntimeConfig config_{};
  SecurityProvider& security_;
  NodeObserver& observer_;
  MeshNode node_;
  std::array<Peer, kPeerCapacity> peers_{};
  std::array<TransientPeer, kTransientPeerCapacity> transient_peers_{};
  NeighborDiscovery* discovery_{nullptr};
  QueueHandle_t event_queue_{nullptr};
  QueueHandle_t bootstrap_queue_{nullptr};
  TaskHandle_t task_{nullptr};
  std::uint64_t pending_token_{0};
  NodeId pending_node_{kInvalidNodeId};
  MacAddress pending_mac_{};
  std::uint32_t pending_generation_{0};
  // Submit-time observation record for the reserved TX (02 §2.3): copied
  // into the completion event so attribution never re-reads live state.
  std::uint64_t pending_submitted_us_{0};
  BindingGeneration pending_binding_{0};
  ChannelEpoch pending_channel_epoch_{0};
  std::uint8_t pending_length_class_{0};
  // In-flight non-reserved (bootstrap/probe/migration) sends, one entry per
  // destination MAC. Entries retire on their completion callback or after
  // callback_watchdog_ms; while an entry exists both send_raw() to that MAC
  // and a reserved DATA send() to that MAC are refused.
  struct RawTx {
    MacAddress mac{};
    MonotonicMs sent_ms{0};
    // Submit-time observation record (same rule as the reserved lane).
    NodeId node{kInvalidNodeId};
    std::uint64_t submitted_us{0};
    BindingGeneration binding{0};
    RadioGeneration radio_generation{};
    ChannelEpoch channel_epoch{0};
    std::uint8_t length_class{0};
  };
  std::array<RawTx, kRawTxCapacity> raw_tx_{};
  std::size_t raw_tx_count_{0};
  // Watchdog-retired raw sends awaiting Unknown accounting on the poll task
  // (node state may only be touched there — never inside callback_lock_).
  std::array<RawTx, kRawTxCapacity> expired_tx_{};
  std::size_t expired_tx_count_{0};
  // A fenced TX whose completion may still arrive: new sends to the same MAC
  // are guarded until the stale callback lands or the guard window passes,
  // so an old callback can never satisfy a new send (X-02).
  MacAddress fenced_mac_{};
  // The fenced send's frozen submit record — its late callback reports as
  // Unknown evidence under these original generations (X-02).
  RawTx fenced_pending_{};
  bool fenced_outstanding_{false};
  // MAC quarantine (02 §2.3/X-02): a watchdog-retired send still owes the
  // driver a callback. While its radio generation is current the MAC stays
  // quarantined — a late callback consumes the marker as stale evidence and
  // can never resolve a replacement send to the same destination. Entries
  // clear on radio-generation change (proven quiescence barrier).
  static constexpr std::size_t kQuarantineCapacity = 4;
  std::array<RawTx, kQuarantineCapacity> quarantined_tx_{};
  std::size_t quarantined_count_{0};
  // TX completions that could not be enqueued onto event_queue_ are staged
  // here and drained on the next poll_once — an accepted submission must
  // resolve exactly once, never disappear into a queue overflow (02 §2.5).
  static constexpr std::size_t kLostTxCapacity = 4;
  std::array<Event, kLostTxCapacity> lost_tx_{};
  std::size_t lost_tx_count_{0};
  // Dedicated staging for the single outstanding RESERVED completion — it
  // resolves the node's job state and is never displaced by raw-lane
  // overflow (02 §2.5).
  Event lost_node_tx_{};
  bool lost_node_tx_valid_{false};
  std::uint32_t stale_tx_results_{0};
  OwnerChannelPort channel_port_;
  ChannelOperationRunner channel_runner_;
  MigrationFrameSink* migration_{nullptr};
  routeloom::MacAddress self_mac_{};
  std::uint64_t autonomy_sequence_{0};
  // Source MAC of the RX event currently being drained in poll_once — used
  // by on_autonomy_frame so the engine sees the observed MAC, not a
  // re-resolved peer-table value.
  routeloom::MacAddress rx_source_{};
  std::uint32_t bootstrap_rx_dropped_{0};
  std::uint32_t rx_dropped_{0};
  std::uint32_t autonomy_tx_ok_{0};
  std::uint32_t autonomy_tx_failed_{0};
  // Owner-side channel epoch: bumped on every readback-verified committed
  // channel (channel_committed). Distinct from the numeric channel — two
  // commits to the same channel still move the epoch.
  ChannelEpoch channel_epoch_{0};
  std::uint32_t telemetry_event_drops_{0};
  // Submit ms of the reserved TX — the poll-task callback watchdog so a
  // never-completing send cannot wedge pending_tx_ forever (02 §2.2).
  MonotonicMs pending_sent_ms_{0};
  bool pending_tx_{false};
  bool broadcast_peer_{false};
  bool wifi_initialized_{false};
  bool espnow_initialized_{false};
  bool started_{false};
};

}  // namespace routeloom::espnow
