#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

#include "esp_now.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
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

class EspNowRuntime final : public RadioPort {
 public:
  static constexpr std::size_t kPeerCapacity = 19;
  static constexpr std::size_t kEventQueueCapacity = 48;
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

  std::uint8_t channel() const noexcept { return config_.channel; }
  // Iterate registered peer mappings (NodeId, MAC, link metric) for the
  // power coordinator's peer-cache capture.
  template <typename Fn>
  void for_each_peer(Fn fn) const noexcept {
    for (const auto& peer : peers_) {
      if (peer.used) fn(peer.node, peer.mac, peer.metric);
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
  struct Peer {
    NodeId node{kInvalidNodeId};
    MacAddress mac{};
    RouteMetric metric{1};
    bool used{false};
    bool driver_registered{false};
  };

  static void receive_callback(const esp_now_recv_info_t* info,
                               const std::uint8_t* data, int length) noexcept;
  static void send_callback(const esp_now_send_info_t* info,
                            esp_now_send_status_t status) noexcept;
  static void task_entry(void* argument) noexcept;

  static EspNowRuntime* instance_;
  static portMUX_TYPE callback_lock_;

  Peer* find_peer(NodeId node) noexcept;
  const Peer* find_peer(NodeId node) const noexcept;
  Peer* find_peer(const std::uint8_t mac[6]) noexcept;
  Status initialize_wifi() noexcept;
  Status initialize_espnow() noexcept;
  Status register_driver_peer(Peer& peer) noexcept;
  Status apply_lr250(const MacAddress& mac) noexcept;
  Status rebuild_driver() noexcept;
  void enqueue_rx(const esp_now_recv_info_t* info,
                  const std::uint8_t* data, int length) noexcept;
  void enqueue_tx(const esp_now_send_info_t* info,
                  esp_now_send_status_t status) noexcept;
  MonotonicMs now_ms() const noexcept;

  EspNowRuntimeConfig config_{};
  SecurityProvider& security_;
  NodeObserver& observer_;
  MeshNode node_;
  std::array<Peer, kPeerCapacity> peers_{};
  QueueHandle_t event_queue_{nullptr};
  TaskHandle_t task_{nullptr};
  std::uint64_t pending_token_{0};
  MacAddress pending_mac_{};
  bool pending_tx_{false};
  bool wifi_initialized_{false};
  bool espnow_initialized_{false};
  bool started_{false};
};

}  // namespace routeloom::espnow
