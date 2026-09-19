#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "esp_now.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "routeloom/autonomy_wire.hpp"
#include "routeloom/discovery.hpp"
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
                            public AutonomyFrameSink {
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

 private:
  enum class EventKind : std::uint8_t { Rx, Tx };
  struct Event {
    EventKind kind{EventKind::Rx};
    NodeId peer{kInvalidNodeId};
    std::uint64_t token{0};
    std::uint16_t length{0};
    std::int8_t rssi_dbm{0};
    bool success{false};
    std::array<std::uint8_t, kMaxEspNowBody> data{};
  };
  // Bootstrap-lane record: self-contained RLD1 envelope + observed metadata.
  // No NodeId is resolved in the callback (01 §3.1).
  struct BootstrapEvent {
    routeloom::MacAddress source{};
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
  MacAddress pending_mac_{};
  routeloom::MacAddress self_mac_{};
  std::uint64_t autonomy_sequence_{0};
  std::uint32_t bootstrap_rx_dropped_{0};
  std::uint32_t autonomy_tx_ok_{0};
  std::uint32_t autonomy_tx_failed_{0};
  bool pending_tx_{false};
  bool broadcast_peer_{false};
  bool wifi_initialized_{false};
  bool espnow_initialized_{false};
  bool started_{false};
};

}  // namespace routeloom::espnow
