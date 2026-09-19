#include "routeloom/espnow_runtime.hpp"

#include <algorithm>
#include <cstring>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "routeloom/wire.hpp"

namespace routeloom::espnow {
namespace {
constexpr char kTag[] = "RouteLoom";
// Wire-lane autonomy control frames are 1-hop liveness exchanges; a short
// lifetime keeps a stale probe from circulating.
constexpr std::uint32_t kAutonomyWireLifetimeMs = 500;

Status esp_status(const esp_err_t error, const StatusCode code,
                  const char* detail) noexcept {
  return error == ESP_OK ? Status::success() : Status::error(code, detail);
}

Status esp_send_status(const esp_err_t error) noexcept {
  if (error == ESP_OK) return Status::success();
  if (error == ESP_ERR_ESPNOW_NO_MEM) {
    return Status::error(StatusCode::WouldBlock, "ESP-NOW NO_MEM");
  }
  if (error == ESP_ERR_ESPNOW_FULL) {
    return Status::error(StatusCode::NoCapacity, "ESP-NOW peer full");
  }
  if (error == ESP_ERR_ESPNOW_NOT_FOUND) {
    return Status::error(StatusCode::NotFound, "ESP-NOW peer not found");
  }
  if (error == ESP_ERR_ESPNOW_CHAN) {
    return Status::error(StatusCode::Conflict, "ESP-NOW channel mismatch");
  }
  return Status::error(StatusCode::RadioFailure, "esp_now_send failed");
}
}  // namespace

EspNowRuntime* EspNowRuntime::instance_ = nullptr;
portMUX_TYPE EspNowRuntime::callback_lock_ = portMUX_INITIALIZER_UNLOCKED;

ChannelOpsConfig EspNowRuntime::ops_config_for(
    const EspNowRuntimeConfig& config) noexcept {
  ChannelOpsConfig ops{};
  ops.home_channel = config.channel;
  ops.channel_min = config.country_first_channel;
  const std::uint32_t last =
      static_cast<std::uint32_t>(config.country_first_channel) +
      config.country_channel_count;
  ops.channel_max =
      static_cast<std::uint8_t>(last > 0 ? last - 1 : 13);
  ops.visit_hard_cap_ms = migration_const::kSurveyVisitMaxMs;
  ops.drain_budget_ms = config.node.callback_watchdog_ms;
  return ops;
}

EspNowRuntime::EspNowRuntime(const EspNowRuntimeConfig& config,
                             SecurityProvider& security,
                             NodeObserver& observer) noexcept
    : config_(config), security_(security), observer_(observer),
      node_(config.node, *this, security, observer),
      channel_port_(*this), channel_runner_(channel_port_, ops_config_for(config)) {}

EspNowRuntime::~EspNowRuntime() { stop(); }

MonotonicMs EspNowRuntime::now_ms() const noexcept {
  return static_cast<MonotonicMs>(esp_timer_get_time() / 1000);
}

EspNowRuntime::Peer* EspNowRuntime::find_peer(const NodeId node) noexcept {
  for (auto& peer : peers_) {
    if (peer.used && peer.node == node) {
      return &peer;
    }
  }
  return nullptr;
}

const EspNowRuntime::Peer* EspNowRuntime::find_peer(
    const NodeId node) const noexcept {
  for (auto& peer : peers_) {
    if (peer.used && peer.node == node) {
      return &peer;
    }
  }
  return nullptr;
}

EspNowRuntime::Peer* EspNowRuntime::find_peer(
    const std::uint8_t mac[6]) noexcept {
  if (mac == nullptr) {
    return nullptr;
  }
  for (auto& peer : peers_) {
    if (peer.used &&
        std::memcmp(peer.mac.bytes.data(), mac, peer.mac.bytes.size()) == 0) {
      return &peer;
    }
  }
  return nullptr;
}

const EspNowRuntime::Peer* EspNowRuntime::find_peer(
    const std::uint8_t mac[6]) const noexcept {
  if (mac == nullptr) {
    return nullptr;
  }
  for (const auto& peer : peers_) {
    if (peer.used &&
        std::memcmp(peer.mac.bytes.data(), mac, peer.mac.bytes.size()) == 0) {
      return &peer;
    }
  }
  return nullptr;
}

EspNowRuntime::TransientPeer* EspNowRuntime::find_transient(
    const std::uint8_t mac[6]) noexcept {
  if (mac == nullptr) {
    return nullptr;
  }
  for (auto& slot : transient_peers_) {
    if (slot.used &&
        std::memcmp(slot.mac.bytes.data(), mac, slot.mac.bytes.size()) == 0) {
      return &slot;
    }
  }
  return nullptr;
}

std::size_t EspNowRuntime::regular_used() const noexcept {
  std::size_t count = 0;
  for (const auto& peer : peers_) {
    if (peer.used) ++count;
  }
  return count;
}

std::size_t EspNowRuntime::regular_budget() const noexcept {
  // With discovery attached the contracts.json partition applies: 16 regular
  // + 3 transient + 1 broadcast = 20 driver peers. Detached, the full
  // peers_ capacity remains available to the static path.
  return discovery_ != nullptr ? kRegularPeerBudget : kPeerCapacity;
}

Status EspNowRuntime::initialize_wifi() noexcept {
  if (config_.channel < 1 || config_.channel > 13 ||
      config_.max_tx_power_qdbm == kTxPowerUnset) {
    return Status::error(StatusCode::InvalidArgument,
                         "approved channel and tx power are required");
  }
  esp_err_t error = esp_netif_init();
  if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
    return esp_status(error, StatusCode::RadioFailure,
                      "esp_netif_init failed");
  }
  error = esp_event_loop_create_default();
  if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
    return esp_status(error, StatusCode::RadioFailure,
                      "event loop init failed");
  }
  wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
  error = esp_wifi_init(&init);
  if (error != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure,
                      "esp_wifi_init failed");
  }
  wifi_initialized_ = true;
  if ((error = esp_wifi_set_storage(WIFI_STORAGE_RAM)) != ESP_OK ||
      (error = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure,
                      "Wi-Fi mode configuration failed");
  }
  wifi_country_t country{};
  country.cc[0] = config_.country[0];
  country.cc[1] = config_.country[1];
  country.cc[2] = '\0';
  country.schan = config_.country_first_channel;
  country.nchan = config_.country_channel_count;
  country.max_tx_power = config_.max_tx_power_qdbm;
  country.policy = WIFI_COUNTRY_POLICY_MANUAL;
  if ((error = esp_wifi_set_country(&country)) != ESP_OK ||
      (error = esp_wifi_set_protocol(
           WIFI_IF_STA, WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G |
                            WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR)) != ESP_OK ||
      (error = esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW20)) != ESP_OK ||
      (error = esp_wifi_start()) != ESP_OK ||
      (error = esp_wifi_set_channel(config_.channel,
                                    WIFI_SECOND_CHAN_NONE)) != ESP_OK ||
      (error = esp_wifi_set_max_tx_power(config_.max_tx_power_qdbm)) !=
          ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure,
                      "Wi-Fi LR startup failed");
  }
  error = esp_wifi_get_mac(WIFI_IF_STA, self_mac_.data());
  if (error != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure,
                      "reading station MAC failed");
  }
  return Status::success();
}

Status EspNowRuntime::apply_lr250(const MacAddress& mac) noexcept {
  esp_now_rate_config_t rate{};
  rate.phymode = WIFI_PHY_MODE_LR;
  rate.rate = WIFI_PHY_RATE_LORA_250K;
  rate.ersu = false;
  rate.dcm = false;
  return esp_status(esp_now_set_peer_rate_config(mac.bytes.data(), &rate),
                    StatusCode::RadioFailure, "setting LR250 failed");
}

Status EspNowRuntime::add_driver_peer(const MacAddress& mac) noexcept {
  esp_now_peer_info_t info{};
  std::memcpy(info.peer_addr, mac.bytes.data(), mac.bytes.size());
  // driver_peer_channel_policy "current-channel-zero" (contracts.json,
  // 04 §8): peers follow the interface channel so a verified channel switch
  // does not rewrite per-peer channel fields — LR250 is still re-applied to
  // every peer by channel_reapply_peers().
  info.channel = 0;
  info.ifidx = WIFI_IF_STA;
  info.encrypt = false;
  const esp_err_t error = esp_now_add_peer(&info);
  if (error != ESP_OK && error != ESP_ERR_ESPNOW_EXIST) {
    return esp_status(error,
                      error == ESP_ERR_ESPNOW_FULL
                          ? StatusCode::NoCapacity
                          : StatusCode::RadioFailure,
                      "esp_now_add_peer failed");
  }
  // LR250 on every (re)registration — including the broadcast peer (02 §7).
  const Status rate = apply_lr250(mac);
  if (!rate) {
    (void)esp_now_del_peer(mac.bytes.data());
    return rate;
  }
  return Status::success();
}

Status EspNowRuntime::register_driver_peer(Peer& peer) noexcept {
  if (peer.driver_registered) {
    return Status::success();
  }
  const Status status = add_driver_peer(peer.mac);
  if (!status) {
    return status;
  }
  peer.driver_registered = true;
  return Status::success();
}

Status EspNowRuntime::register_broadcast_peer() noexcept {
  if (broadcast_peer_) {
    return Status::success();
  }
  MacAddress mac{};
  mac.bytes = discovery_const::kBroadcastMac;
  const Status status = add_driver_peer(mac);
  if (!status) {
    return status;
  }
  broadcast_peer_ = true;
  return Status::success();
}

Status EspNowRuntime::initialize_espnow() noexcept {
  auto error = esp_now_init();
  if (error != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure,
                      "esp_now_init failed");
  }
  espnow_initialized_ = true;
  instance_ = this;
  if ((error = esp_now_register_recv_cb(
           &EspNowRuntime::receive_callback)) != ESP_OK ||
      (error = esp_now_register_send_cb(
           &EspNowRuntime::send_callback)) != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure,
                      "ESP-NOW callback registration failed");
  }
  for (auto& peer : peers_) {
    if (peer.used) {
      const auto status = register_driver_peer(peer);
      if (!status) {
        return status;
      }
    }
  }
  if (discovery_ != nullptr) {
    const Status status = register_broadcast_peer();
    if (!status) {
      return status;
    }
  }
  for (auto& slot : transient_peers_) {
    if (slot.used) {
      const Status status = add_driver_peer(slot.mac);
      if (!status) {
        return status;
      }
    }
  }
  return Status::success();
}

Status EspNowRuntime::initialize() noexcept {
  if (event_queue_ != nullptr) {
    return Status::error(StatusCode::AlreadyExists,
                         "runtime initialized");
  }
  if (!security_.ready()) {
    return Status::error(StatusCode::InvalidState,
                         "security provider not ready");
  }
  event_queue_ = xQueueCreate(kEventQueueCapacity, sizeof(Event));
  if (event_queue_ == nullptr) {
    return Status::error(StatusCode::NoCapacity,
                         "event queue allocation failed");
  }
  bootstrap_queue_ =
      xQueueCreate(kBootstrapQueueCapacity, sizeof(BootstrapEvent));
  if (bootstrap_queue_ == nullptr) {
    vQueueDelete(event_queue_);
    event_queue_ = nullptr;
    return Status::error(StatusCode::NoCapacity,
                         "bootstrap queue allocation failed");
  }
  auto status = initialize_wifi();
  if (status) {
    status = initialize_espnow();
  }
  if (!status) {
    stop();
    return status;
  }
  return Status::success();
}

Status EspNowRuntime::register_neighbor(
    const NodeId node, const MacAddress& mac,
    const RouteMetric link_metric) noexcept {
  if (node == kInvalidNodeId || node == config_.node.node ||
      link_metric == 0 || link_metric == kInfiniteRouteMetric) {
    return Status::error(StatusCode::InvalidArgument,
                         "invalid neighbor registration");
  }
  Peer* record = find_peer(node);
  if (record == nullptr) {
    if (regular_used() >= regular_budget()) {
      return Status::error(StatusCode::PeerCapacity,
                           "regular peer partition full");
    }
    for (auto& candidate : peers_) {
      if (!candidate.used) {
        record = &candidate;
        break;
      }
    }
  }
  if (record == nullptr) {
    return Status::error(StatusCode::NoCapacity, "peer mapping full");
  }
  if (record->used && !(record->mac == mac)) {
    return Status::error(StatusCode::Conflict,
                         "node already mapped to another MAC");
  }
  record->used = true;
  record->node = node;
  record->mac = mac;
  record->metric = link_metric;
  if (espnow_initialized_) {
    const auto status = register_driver_peer(*record);
    if (!status) {
      return status;
    }
  }
  if (started_) {
    return node_.add_neighbor(node, link_metric, now_ms());
  }
  return Status::success();
}

Status EspNowRuntime::attach_autonomy(NeighborDiscovery& engine) noexcept {
  if (discovery_ != nullptr) {
    return Status::error(StatusCode::AlreadyExists,
                         "autonomy engine already attached");
  }
  if (regular_used() > kRegularPeerBudget) {
    return Status::error(StatusCode::PeerCapacity,
                         "static peers exceed the regular partition");
  }
  discovery_ = &engine;
  node_.set_autonomy_sink(this);
  if (espnow_initialized_) {
    const Status status = register_broadcast_peer();
    if (!status) {
      discovery_ = nullptr;
      node_.set_autonomy_sink(nullptr);
      return status;
    }
  }
  return Status::success();
}

Status EspNowRuntime::local_mac(routeloom::MacAddress& out) const noexcept {
  if (!wifi_initialized_) {
    return Status::error(StatusCode::InvalidState,
                         "wifi not initialized");
  }
  out = self_mac_;
  return Status::success();
}

Status EspNowRuntime::start() noexcept {
  if (event_queue_ == nullptr || !espnow_initialized_) {
    return Status::error(StatusCode::InvalidState,
                         "runtime not initialized");
  }
  if (started_) {
    return Status::error(StatusCode::AlreadyExists,
                         "runtime started");
  }
  auto status = node_.start(now_ms());
  if (!status) {
    return status;
  }
  for (auto& peer : peers_) {
    if (!peer.used) {
      continue;
    }
    status = node_.add_neighbor(peer.node, peer.metric, now_ms());
    if (!status) {
      return status;
    }
    if (peer.autonomy) {
      // Restart path: the neighbor add here must be undoable by a later
      // autonomy release, so mirror the REACHABLE bookkeeping.
      peer.neighbor_added = true;
    }
  }
  started_ = true;
  return Status::success();
}

void EspNowRuntime::task_entry(void* argument) noexcept {
  auto* runtime = static_cast<EspNowRuntime*>(argument);
  while (runtime->started_) {
    runtime->poll_once();
    vTaskDelay(pdMS_TO_TICKS(2));
  }
  runtime->task_ = nullptr;
  vTaskDelete(nullptr);
}

Status EspNowRuntime::start_task(const char* name) noexcept {
  if (!started_) {
    const auto status = start();
    if (!status) {
      return status;
    }
  }
  if (task_ != nullptr) {
    return Status::error(StatusCode::AlreadyExists,
                         "runtime task exists");
  }
  const BaseType_t result = xTaskCreatePinnedToCore(
      &EspNowRuntime::task_entry, name == nullptr ? "routeloom" : name,
      config_.task_stack_bytes / sizeof(StackType_t), this,
      config_.task_priority, &task_, config_.task_core);
  return result == pdPASS
             ? Status::success()
             : Status::error(StatusCode::NoCapacity,
                             "runtime task allocation failed");
}

void EspNowRuntime::stop() noexcept {
  started_ = false;
  if (task_ != nullptr) {
    for (int i = 0; i < 50 && task_ != nullptr; ++i) {
      vTaskDelay(pdMS_TO_TICKS(1));
    }
  }
  portENTER_CRITICAL(&callback_lock_);
  if (instance_ == this) {
    instance_ = nullptr;
  }
  pending_tx_ = false;
  pending_token_ = 0;
  pending_generation_ = 0;
  fenced_outstanding_ = false;
  portEXIT_CRITICAL(&callback_lock_);
  if (espnow_initialized_) {
    (void)esp_now_unregister_recv_cb();
    (void)esp_now_unregister_send_cb();
    (void)esp_now_deinit();
    espnow_initialized_ = false;
  }
  for (auto& peer : peers_) {
    peer.driver_registered = false;
  }
  for (auto& slot : transient_peers_) {
    slot.used = false;
  }
  broadcast_peer_ = false;
  if (wifi_initialized_) {
    (void)esp_wifi_stop();
    (void)esp_wifi_deinit();
    wifi_initialized_ = false;
  }
  if (event_queue_ != nullptr) {
    vQueueDelete(event_queue_);
    event_queue_ = nullptr;
  }
  if (bootstrap_queue_ != nullptr) {
    vQueueDelete(bootstrap_queue_);
    bootstrap_queue_ = nullptr;
  }
}

void EspNowRuntime::poll_once() noexcept {
  if (!started_ || event_queue_ == nullptr) {
    return;
  }
  const MonotonicMs now = now_ms();
  Event event{};
  while (xQueueReceive(event_queue_, &event, 0) == pdTRUE) {
    if (event.kind == EventKind::Tx) {
      node_.on_radio_tx_result(event.token, event.success, now);
    } else {
      node_.on_radio_receive(
          event.peer, ByteView{event.data.data(), event.length},
          RadioRxMetadata{event.rssi_dbm}, now);
    }
  }
  if (discovery_ != nullptr && bootstrap_queue_ != nullptr) {
    BootstrapEvent rx{};
    while (xQueueReceive(bootstrap_queue_, &rx, 0) == pdTRUE) {
      discovery_->on_rld1_rx(
          rx.source, ByteView{rx.data.data(), rx.length}, rx.received_ms);
    }
    discovery_->poll(now);
    reconcile_autonomy(now);
  }
  // Serialized channel operations advance here: drain fence -> verified
  // apply -> bounded visit dwell -> verified return home (04 §3/§8).
  channel_runner_.poll(now);
  node_.poll(now);
}

Status EspNowRuntime::send_application(
    const NodeId destination, const ByteView payload,
    const SendOptions& options, MessageId& id) noexcept {
  if (!started_) {
    return Status::error(StatusCode::InvalidState,
                         "runtime not started");
  }
  return node_.send(destination, payload, options, now_ms(), id);
}

Status EspNowRuntime::send_raw(const MacAddress& mac,
                               const ByteView frame) noexcept {
  if (!espnow_initialized_) {
    return Status::error(StatusCode::InvalidState,
                         "ESP-NOW not initialized");
  }
  if (frame.data == nullptr || frame.size == 0 ||
      frame.size > ESP_NOW_MAX_DATA_LEN) {
    return Status::error(StatusCode::InvalidArgument,
                         "invalid ESP-NOW frame");
  }
  return esp_send_status(
      esp_now_send(mac.bytes.data(), frame.data, frame.size));
}

Status EspNowRuntime::send(const NodeId peer, const std::uint64_t token,
                           const ByteView frame) noexcept {
  if (channel_runner_.busy()) {
    // A serialized channel operation owns the radio: DATA submissions wait
    // rather than transmit against a stale configuration (04 §8).
    return Status::error(StatusCode::WouldBlock, "RADIO_OP_IN_PROGRESS");
  }
  const Peer* record = find_peer(peer);
  if (record == nullptr || !record->driver_registered) {
    return Status::error(StatusCode::NotFound,
                         "peer is not registered");
  }
  if (frame.data == nullptr || frame.size == 0 ||
      frame.size > ESP_NOW_MAX_DATA_LEN) {
    return Status::error(StatusCode::InvalidArgument,
                         "invalid ESP-NOW frame");
  }
  portENTER_CRITICAL(&callback_lock_);
  if (pending_tx_) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock,
                         "physical TX already in flight");
  }
  if (fenced_outstanding_) {
    if (now_ms() >= fenced_until_ms_) {
      fenced_outstanding_ = false;
    } else if (fenced_mac_ == record->mac) {
      // A fenced callback for this MAC may still be in flight: refuse the
      // new send so the old completion can never be attributed to it (X-02).
      portEXIT_CRITICAL(&callback_lock_);
      return Status::error(StatusCode::WouldBlock, "TX_FENCE_GUARD");
    }
  }
  pending_tx_ = true;
  pending_token_ = token;
  pending_mac_ = record->mac;
  pending_generation_ = channel_runner_.radio_generation().value;
  portEXIT_CRITICAL(&callback_lock_);
  const esp_err_t error =
      esp_now_send(record->mac.bytes.data(), frame.data, frame.size);
  if (error != ESP_OK) {
    portENTER_CRITICAL(&callback_lock_);
    pending_tx_ = false;
    pending_token_ = 0;
    portEXIT_CRITICAL(&callback_lock_);
    return esp_send_status(error);
  }
  return Status::success();
}

// --- DiscoveryPort -------------------------------------------------------------

Status EspNowRuntime::ensure_transient_peer(const MacAddress& mac) noexcept {
  if (find_transient(mac.bytes.data()) != nullptr) {
    return Status::success();
  }
  TransientPeer* slot = nullptr;
  for (auto& candidate : transient_peers_) {
    if (!candidate.used) {
      slot = &candidate;
      break;
    }
  }
  if (slot == nullptr) {
    return Status::error(StatusCode::PeerCapacity,
                         "transient peer partition full");
  }
  const Status status = add_driver_peer(mac);
  if (!status) {
    return status;
  }
  slot->mac = mac;
  slot->used = true;
  return Status::success();
}

Status EspNowRuntime::send_rld1(const routeloom::MacAddress& dest,
                                const ByteView encoded) noexcept {
  if (discovery_ == nullptr) {
    return Status::error(StatusCode::InvalidState,
                         "autonomy engine not attached");
  }
  if (encoded.data == nullptr || encoded.size == 0 ||
      encoded.size > autonomy::kRld1MaxTotal) {
    return Status::error(StatusCode::InvalidArgument,
                         "invalid RLD1 frame");
  }
  MacAddress mac{};
  mac.bytes = dest;
  Status status = Status::success();
  if (dest == discovery_const::kBroadcastMac) {
    status = register_broadcast_peer();
  } else {
    const Peer* record = find_peer(mac.bytes.data());
    if (record == nullptr || !record->driver_registered) {
      // Unicast bootstrap toward an unregistered MAC: hold one of the three
      // transient driver peers for the in-flight exchange (02 §7).
      status = ensure_transient_peer(mac);
    }
  }
  if (!status) {
    return status;
  }
  return send_raw(mac, encoded);
}

Status EspNowRuntime::send_wire(const BindingId binding,
                                const routeloom::MacAddress& dest,
                                const FrameType type,
                                const ByteView payload) noexcept {
  if (discovery_ == nullptr) {
    return Status::error(StatusCode::InvalidState,
                         "autonomy engine not attached");
  }
  if (channel_runner_.busy()) {
    // The authenticated home lane holds while the Owner runs a serialized
    // channel operation (04 §3/§8).
    return Status::error(StatusCode::WouldBlock, "RADIO_OP_IN_PROGRESS");
  }
  // Only post-BIND availability probes ride this path; the allowlist is
  // explicit so a future type cannot slip onto the wire lane unreviewed.
  if (type != FrameType::NeighborProbe && type != FrameType::NeighborResult) {
    return Status::error(StatusCode::InvalidArgument,
                         "type not allowed on the autonomy wire lane");
  }
  NodeId node = kInvalidNodeId;
  if (!discovery_->node_of(dest, node)) {
    return Status::error(StatusCode::NotFound,
                         "no bound record for destination");
  }
  BindingId current{};
  if (!discovery_->binding_of(node, current) || current != binding) {
    return Status::error(StatusCode::Conflict, "stale binding id");
  }
  MacAddress mac{};
  mac.bytes = dest;
  const Peer* record = find_peer(mac.bytes.data());
  if (record == nullptr) {
    // Binding exists but no regular driver peer yet: promote now. A full
    // partition surfaces PEER_CAPACITY to the engine — never a silent drop.
    const Status status = promote_to_regular(node, mac);
    if (!status) {
      return status;
    }
    record = find_peer(mac.bytes.data());
  } else if (record->node != node) {
    return Status::error(StatusCode::Conflict,
                         "mac bound to another node");
  }
  wire::PlainFrame frame{};
  frame.header.type = type;
  frame.header.delivery = DeliveryClass::BestEffort;
  frame.header.hop_remaining = 1;
  frame.header.network = config_.node.network;
  frame.header.origin = config_.node.node;
  frame.header.destination = node;
  frame.header.previous_hop = config_.node.node;
  frame.header.next_hop = node;
  frame.header.message =
      MessageId{config_.node.message_session, ++autonomy_sequence_};
  frame.header.remaining_deadline_ms = kAutonomyWireLifetimeMs;
  frame.header.original_lifetime_ms = kAutonomyWireLifetimeMs;
  frame.header.link_epoch = config_.node.link_epoch;
  frame.header.end_epoch = config_.node.end_epoch;
  if (payload.size > frame.payload.size()) {
    return Status::error(StatusCode::NoCapacity,
                         "autonomy payload exceeds wire budget");
  }
  if (payload.size > 0) {
    std::memcpy(frame.payload.data(), payload.data, payload.size);
  }
  frame.payload_size = payload.size;
  wire::EncodedFrame encoded{};
  // Link-scope seal via the existing provider — counters/AEAD stay inside
  // DevelopmentPskSecurityProvider; no new crypto primitive here.
  const Status status = wire::encode_new(frame, security_, encoded);
  if (!status) {
    return status;
  }
  return send_raw(mac, encoded.view());
}

void EspNowRuntime::on_autonomy_frame(const NodeId peer, const FrameType type,
                                      const ByteView payload,
                                      const MonotonicMs now_ms) noexcept {
  if (discovery_ == nullptr) {
    return;
  }
  const Peer* record = find_peer(peer);
  if (record == nullptr) {
    return;
  }
  discovery_->on_wire_rx(record->mac.bytes, type, payload, now_ms);
}

// --- Peer lease sync (02 §7, contracts peer_partition) ---------------------------

Status EspNowRuntime::promote_to_regular(const NodeId node,
                                         const MacAddress& mac) noexcept {
  Peer* record = find_peer(node);
  if (record == nullptr) {
    record = find_peer(mac.bytes.data());
  }
  if (record != nullptr) {
    if (record->node != node || !(record->mac == mac)) {
      return Status::error(StatusCode::Conflict,
                           "peer identity mismatch");
    }
    // An existing (e.g. statically configured) mapping stays owner-managed;
    // it satisfies the lease but is never auto-released.
    if (!record->driver_registered) {
      return register_driver_peer(*record);
    }
    return Status::success();
  }
  if (regular_used() >= regular_budget()) {
    return Status::error(StatusCode::PeerCapacity,
                         "regular peer partition full");
  }
  for (auto& candidate : peers_) {
    if (!candidate.used) {
      record = &candidate;
      break;
    }
  }
  if (record == nullptr) {
    return Status::error(StatusCode::PeerCapacity, "peer mapping full");
  }
  record->used = true;
  record->node = node;
  record->mac = mac;
  record->metric = 1;
  record->autonomy = true;
  record->neighbor_added = false;
  record->driver_registered = false;
  if (TransientPeer* slot = find_transient(mac.bytes.data())) {
    // The transient slot's driver registration moves to the regular peer;
    // only the bookkeeping is released.
    slot->used = false;
    record->driver_registered = true;
    return Status::success();
  }
  const Status status = register_driver_peer(*record);
  if (!status) {
    record->used = false;
    record->autonomy = false;
    return status;
  }
  return Status::success();
}

void EspNowRuntime::release_driver_peer(const MacAddress& mac,
                                        const NodeId node) noexcept {
  portENTER_CRITICAL(&callback_lock_);
  const bool inflight = pending_tx_ && pending_mac_ == mac;
  portEXIT_CRITICAL(&callback_lock_);
  if (inflight) {
    // Never silent: the delivery resolves as DRIVER_RESULT_UNKNOWN via the
    // node watchdog, or the driver completion still arrives and is consumed.
    observer_.on_diagnostic("PEER_TX_INFLIGHT_RELEASED", node, nullptr);
  }
  (void)esp_now_del_peer(mac.bytes.data());
}

void EspNowRuntime::release_autonomy_peer(Peer& peer,
                                          const MonotonicMs now) noexcept {
  if (peer.neighbor_added) {
    // Stale/suspended/evicted peers leave the routing neighbor table;
    // re-confirmation requires a fresh exchange (02 §9).
    (void)node_.remove_neighbor(peer.node, now);
    peer.neighbor_added = false;
  }
  if (peer.driver_registered) {
    release_driver_peer(peer.mac, peer.node);
    peer.driver_registered = false;
  }
  peer.used = false;
  peer.autonomy = false;
  peer.node = kInvalidNodeId;
}

void EspNowRuntime::reconcile_autonomy(const MonotonicMs now) noexcept {
  if (discovery_ == nullptr) {
    return;
  }
  // Transient slots mirror the engine's live candidates/exchanges.
  for (auto& slot : transient_peers_) {
    if (!slot.used) {
      continue;
    }
    NeighborPhase phase{};
    if (!discovery_->phase_of(slot.mac.bytes, phase)) {
      release_driver_peer(slot.mac, kInvalidNodeId);
      slot.used = false;
      continue;
    }
    switch (phase) {
      case NeighborPhase::Candidate:
      case NeighborPhase::Authenticating:
        break;  // in-flight exchange holds the transient slot
      case NeighborPhase::ApprovalPending:
      case NeighborPhase::Bound:
      case NeighborPhase::Reachable: {
        NodeId node = kInvalidNodeId;
        if (discovery_->node_of(slot.mac.bytes, node) &&
            promote_to_regular(node, slot.mac).ok()) {
          // promote_to_regular released the slot bookkeeping on success.
          break;
        }
        // peers_ partition full: do not park a bound peer in the transient
        // budget — release it and let wire sends surface PEER_CAPACITY.
        release_driver_peer(slot.mac, node);
        slot.used = false;
        break;
      }
      default:
        // Stale/Suspended/Conflict/Revoked: release the driver peer.
        release_driver_peer(slot.mac, kInvalidNodeId);
        slot.used = false;
        break;
    }
  }
  // Autonomy-managed regular peers mirror the engine's bound records.
  for (auto& peer : peers_) {
    if (!peer.used || !peer.autonomy) {
      continue;
    }
    NeighborPhase phase{};
    const bool known = discovery_->phase_of(peer.node, phase);
    if (known && (phase == NeighborPhase::ApprovalPending ||
                  phase == NeighborPhase::Bound ||
                  phase == NeighborPhase::Reachable)) {
      if (phase == NeighborPhase::Reachable && !peer.neighbor_added &&
          started_) {
        // REACHABLE is the only phase where policy-limited DATA may flow;
        // routing learns the link here (register_neighbor-equivalent).
        if (node_.add_neighbor(peer.node, peer.metric, now).ok()) {
          peer.neighbor_added = true;
        }
      }
      continue;
    }
    release_autonomy_peer(peer, now);
  }
}

Status EspNowRuntime::rebuild_driver() noexcept {
  if (espnow_initialized_) {
    (void)esp_now_unregister_recv_cb();
    (void)esp_now_unregister_send_cb();
    (void)esp_now_deinit();
    espnow_initialized_ = false;
  }
  for (auto& peer : peers_) {
    peer.driver_registered = false;
  }
  broadcast_peer_ = false;
  return initialize_espnow();
}

Status EspNowRuntime::recover() noexcept {
  portENTER_CRITICAL(&callback_lock_);
  pending_tx_ = false;
  pending_token_ = 0;
  portEXIT_CRITICAL(&callback_lock_);
  return rebuild_driver();
}

void EspNowRuntime::receive_callback(
    const esp_now_recv_info_t* info, const std::uint8_t* data,
    const int length) noexcept {
  if (instance_ != nullptr) {
    instance_->enqueue_rx(info, data, length);
  }
}

void EspNowRuntime::send_callback(
    const esp_now_send_info_t* info,
    const esp_now_send_status_t status) noexcept {
  if (instance_ != nullptr) {
    instance_->enqueue_tx(info, status);
  }
}

bool EspNowRuntime::classify_bootstrap(const std::uint8_t* data,
                                       const int length) noexcept {
  if (data == nullptr ||
      length < static_cast<int>(autonomy::kRld1HeaderSize) ||
      length > static_cast<int>(autonomy::kRld1MaxTotal)) {
    return false;
  }
  // "RLD1"
  if (data[0] != 0x52 || data[1] != 0x4c || data[2] != 0x44 ||
      data[3] != 0x31 || data[4] != autonomy::kRld1Version) {
    return false;
  }
  switch (static_cast<FrameType>(data[5])) {
    case FrameType::Discover:
    case FrameType::Offer:
    case FrameType::BootstrapAuth:
    case FrameType::BootstrapChunk:
    case FrameType::BootstrapReply:
      break;
    default:
      return false;
  }
  const auto read_u16 = [](const std::uint8_t* p) noexcept {
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(p[0]) << 8U) | p[1]);
  };
  const std::uint16_t header_len = read_u16(data + 6);
  const std::uint16_t total_len = read_u16(data + 8);
  const std::uint16_t flags = read_u16(data + 10);
  return header_len == autonomy::kRld1HeaderSize &&
         total_len == static_cast<std::uint16_t>(length) && flags == 0;
}

void EspNowRuntime::enqueue_rx(
    const esp_now_recv_info_t* info, const std::uint8_t* data,
    const int length) noexcept {
  if (event_queue_ == nullptr || info == nullptr ||
      info->src_addr == nullptr || data == nullptr || length <= 0 ||
      length > static_cast<int>(kMaxEspNowBody)) {
    return;
  }
  // Carrier classification precedes the peer table: RLD1 is recognized once
  // by its full magic+version and never reaches the Wire parser (06 §3.1).
  if (classify_bootstrap(data, length)) {
    if (bootstrap_queue_ == nullptr) {
      return;
    }
    BootstrapEvent event{};
    std::memcpy(event.source.data(), info->src_addr, event.source.size());
    event.received_ms = now_ms();
    event.length = static_cast<std::uint16_t>(length);
    event.rssi_dbm = info->rx_ctrl != nullptr ? info->rx_ctrl->rssi : 0;
    std::memcpy(event.data.data(), data, event.length);
    portENTER_CRITICAL(&callback_lock_);
    if (xQueueSend(bootstrap_queue_, &event, 0) != pdTRUE) {
      ++bootstrap_rx_dropped_;
    }
    portEXIT_CRITICAL(&callback_lock_);
    return;
  }
  Peer* peer = find_peer(info->src_addr);
  if (peer == nullptr) {
    return;
  }
  Event event{};
  event.kind = EventKind::Rx;
  event.peer = peer->node;
  event.length = static_cast<std::uint16_t>(length);
  event.rssi_dbm =
      info->rx_ctrl != nullptr ? info->rx_ctrl->rssi : 0;
  std::memcpy(event.data.data(), data, event.length);
  (void)xQueueSend(event_queue_, &event, 0);
}

void EspNowRuntime::enqueue_tx(
    const esp_now_send_info_t* info,
    const esp_now_send_status_t status) noexcept {
  if (event_queue_ == nullptr || info == nullptr ||
      info->des_addr == nullptr) {
    return;
  }
  Event event{};
  event.kind = EventKind::Tx;
  portENTER_CRITICAL(&callback_lock_);
  const bool pending_match =
      pending_tx_ && std::memcmp(pending_mac_.bytes.data(), info->des_addr,
                                 pending_mac_.bytes.size()) == 0;
  if (pending_match &&
      pending_generation_ != channel_runner_.radio_generation().value) {
    // Completion for a pre-switch configuration: it cannot resolve the
    // newer send — account separately, never as success or failure (X-02).
    ++stale_tx_results_;
    pending_tx_ = false;
    pending_token_ = 0;
    portEXIT_CRITICAL(&callback_lock_);
    return;
  }
  if (!pending_match) {
    if (fenced_outstanding_ &&
        std::memcmp(fenced_mac_.bytes.data(), info->des_addr,
                    fenced_mac_.bytes.size()) == 0) {
      // The fenced straggler arrived late: accounted separately and never
      // merged with a send that ran under the newer configuration (X-02).
      ++stale_tx_results_;
      fenced_outstanding_ = false;
      portEXIT_CRITICAL(&callback_lock_);
      return;
    }
    // Not the reserved node-TX completion: bootstrap/autonomy sends are
    // accounted here but never consume the reservation slot (01 §3.1).
    if (status == ESP_NOW_SEND_SUCCESS) {
      ++autonomy_tx_ok_;
    } else {
      ++autonomy_tx_failed_;
    }
    portEXIT_CRITICAL(&callback_lock_);
    return;
  }
  event.token = pending_token_;
  event.success = status == ESP_NOW_SEND_SUCCESS;
  pending_tx_ = false;
  pending_token_ = 0;
  portEXIT_CRITICAL(&callback_lock_);
  (void)xQueueSend(event_queue_, &event, 0);
}

// --- Radio operation arbiter + ChannelPort (04 §3/§8) ---------------------------

OperationToken EspNowRuntime::request_radio_operation(
    const RadioOperation& op) noexcept {
  // Policy rejections (unsupported kind, channel bounds, missing outage
  // permission) are recorded by the runner as REJECTED results; a driver
  // that is not up fails the apply as InvalidState -> FAILED. Either way
  // the token always resolves to evidence.
  return channel_runner_.request(op, now_ms());
}

bool EspNowRuntime::radio_operation_result(
    const OperationToken token, OperationResult& out) const noexcept {
  if (token == kInvalidOperationToken) {
    return false;
  }
  return channel_runner_.result(token, out);
}

bool EspNowRuntime::radio_operation_busy() const noexcept {
  return channel_runner_.busy();
}

RadioGeneration EspNowRuntime::radio_generation() const noexcept {
  return channel_runner_.radio_generation();
}

bool EspNowRuntime::channel_tx_quiesced() const noexcept {
  portENTER_CRITICAL(&callback_lock_);
  const bool quiesced = !pending_tx_;
  portEXIT_CRITICAL(&callback_lock_);
  return quiesced;
}

Status EspNowRuntime::channel_set(const std::uint8_t channel) noexcept {
  if (!wifi_initialized_) {
    return Status::error(StatusCode::InvalidState, "wifi not initialized");
  }
  return esp_status(
      esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE),
      StatusCode::RadioFailure, "esp_wifi_set_channel failed");
}

Status EspNowRuntime::channel_readback(std::uint8_t& channel) noexcept {
  if (!wifi_initialized_) {
    return Status::error(StatusCode::InvalidState, "wifi not initialized");
  }
  std::uint8_t primary = 0;
  wifi_second_chan_t second = WIFI_SECOND_CHAN_NONE;
  const esp_err_t error = esp_wifi_get_channel(&primary, &second);
  if (error != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure,
                      "esp_wifi_get_channel failed");
  }
  channel = primary;
  return Status::success();
}

Status EspNowRuntime::channel_reapply_peers() noexcept {
  if (!espnow_initialized_) {
    return Status::error(StatusCode::InvalidState,
                         "ESP-NOW not initialized");
  }
  // 04 §8 cutover list: after a verified channel switch every registered
  // peer gets its rate re-applied — broadcast and transient peers included.
  // Peer channel needs no rewrite under the current-channel-zero policy.
  for (const auto& peer : peers_) {
    if (!peer.used || !peer.driver_registered) continue;
    const Status status = apply_lr250(peer.mac);
    if (!status) return status;
  }
  for (const auto& slot : transient_peers_) {
    if (!slot.used) continue;
    const Status status = apply_lr250(slot.mac);
    if (!status) return status;
  }
  if (broadcast_peer_) {
    MacAddress mac{};
    mac.bytes = discovery_const::kBroadcastMac;
    const Status status = apply_lr250(mac);
    if (!status) return status;
  }
  return Status::success();
}

void EspNowRuntime::channel_fence_tx() noexcept {
  bool fenced = false;
  portENTER_CRITICAL(&callback_lock_);
  if (pending_tx_) {
    // The straggler keeps its own record: its late callback resolves as
    // unknown/stale — never as a fabricated success or failure (X-02).
    fenced_mac_ = pending_mac_;
    fenced_until_ms_ = now_ms() + config_.node.callback_watchdog_ms;
    fenced_outstanding_ = true;
    pending_tx_ = false;
    pending_token_ = 0;
    fenced = true;
  }
  portEXIT_CRITICAL(&callback_lock_);
  if (fenced) {
    observer_.on_diagnostic("OP_TX_FENCED", kInvalidNodeId, nullptr);
  }
}

void EspNowRuntime::channel_committed(const std::uint8_t channel) noexcept {
  // Only after readback-verified apply + peer re-apply: config_.channel is
  // never assigned alone (04 §8 forbids the bare assignment cutover).
  config_.channel = channel;
}

bool EspNowRuntime::OwnerChannelPort::tx_quiesced() const noexcept {
  return owner_.channel_tx_quiesced();
}

Status EspNowRuntime::OwnerChannelPort::set_channel(
    const std::uint8_t channel) noexcept {
  return owner_.channel_set(channel);
}

Status EspNowRuntime::OwnerChannelPort::readback_channel(
    std::uint8_t& channel) noexcept {
  return owner_.channel_readback(channel);
}

Status EspNowRuntime::OwnerChannelPort::reapply_peer_radio() noexcept {
  return owner_.channel_reapply_peers();
}

void EspNowRuntime::OwnerChannelPort::fence_pending_tx() noexcept {
  owner_.channel_fence_tx();
}

void EspNowRuntime::OwnerChannelPort::committed_channel(
    const std::uint8_t channel) noexcept {
  owner_.channel_committed(channel);
}

}  // namespace routeloom::espnow
