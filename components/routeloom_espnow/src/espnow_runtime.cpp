#include "routeloom/espnow_runtime.hpp"

#include <algorithm>
#include <cstring>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"

namespace routeloom::espnow {
namespace {
constexpr char kTag[] = "RouteLoom";

Status esp_status(const esp_err_t error, const StatusCode code,
                  const char* detail) noexcept {
  return error == ESP_OK ? Status::success() : Status::error(code, detail);
}
}  // namespace

EspNowRuntime* EspNowRuntime::instance_ = nullptr;
portMUX_TYPE EspNowRuntime::callback_lock_ = portMUX_INITIALIZER_UNLOCKED;

EspNowRuntime::EspNowRuntime(const EspNowRuntimeConfig& config,
                             SecurityProvider& security,
                             NodeObserver& observer) noexcept
    : config_(config), security_(security), observer_(observer),
      node_(config.node, *this, security, observer) {}

EspNowRuntime::~EspNowRuntime() { stop(); }

MonotonicMs EspNowRuntime::now_ms() const noexcept {
  return static_cast<MonotonicMs>(esp_timer_get_time() / 1000);
}

EspNowRuntime::Peer* EspNowRuntime::find_peer(const NodeId node) noexcept {
  for (auto& peer : peers_) if (peer.used && peer.node == node) return &peer;
  return nullptr;
}

const EspNowRuntime::Peer* EspNowRuntime::find_peer(const NodeId node) const noexcept {
  for (const auto& peer : peers_) if (peer.used && peer.node == node) return &peer;
  return nullptr;
}

EspNowRuntime::Peer* EspNowRuntime::find_peer(const std::uint8_t mac[6]) noexcept {
  if (mac == nullptr) return nullptr;
  for (auto& peer : peers_) {
    if (peer.used && std::memcmp(peer.mac.bytes.data(), mac, peer.mac.bytes.size()) == 0) return &peer;
  }
  return nullptr;
}

Status EspNowRuntime::initialize_wifi() noexcept {
  if (config_.channel < 1 || config_.channel > 13 ||
      config_.max_tx_power_qdbm == kTxPowerUnset) {
    return Status::error(StatusCode::InvalidArgument,
                         "approved channel and tx power are required");
  }
  esp_err_t error = esp_netif_init();
  if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
    return esp_status(error, StatusCode::RadioFailure, "esp_netif_init failed");
  }
  error = esp_event_loop_create_default();
  if (error != ESP_OK && error != ESP_ERR_INVALID_STATE) {
    return esp_status(error, StatusCode::RadioFailure, "event loop init failed");
  }
  wifi_init_config_t init = WIFI_INIT_CONFIG_DEFAULT();
  error = esp_wifi_init(&init);
  if (error != ESP_OK) return esp_status(error, StatusCode::RadioFailure, "esp_wifi_init failed");
  wifi_initialized_ = true;
  if ((error = esp_wifi_set_storage(WIFI_STORAGE_RAM)) != ESP_OK ||
      (error = esp_wifi_set_mode(WIFI_MODE_STA)) != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure, "Wi-Fi mode configuration failed");
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
      (error = esp_wifi_set_protocol(WIFI_IF_STA,
          WIFI_PROTOCOL_11B | WIFI_PROTOCOL_11G | WIFI_PROTOCOL_11N | WIFI_PROTOCOL_LR)) != ESP_OK ||
      (error = esp_wifi_set_bandwidth(WIFI_IF_STA, WIFI_BW_HT20)) != ESP_OK ||
      (error = esp_wifi_start()) != ESP_OK ||
      (error = esp_wifi_set_channel(config_.channel, WIFI_SECOND_CHAN_NONE)) != ESP_OK ||
      (error = esp_wifi_set_max_tx_power(config_.max_tx_power_qdbm)) != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure, "Wi-Fi LR startup failed");
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

Status EspNowRuntime::register_driver_peer(Peer& peer) noexcept {
  if (peer.driver_registered) return Status::success();
  esp_now_peer_info_t info{};
  std::memcpy(info.peer_addr, peer.mac.bytes.data(), peer.mac.bytes.size());
  info.channel = config_.channel;
  info.ifidx = WIFI_IF_STA;
  info.encrypt = false;
  esp_err_t error = esp_now_add_peer(&info);
  if (error != ESP_OK && error != ESP_ERR_ESPNOW_EXIST) {
    return esp_status(error,
                      error == ESP_ERR_ESPNOW_FULL ? StatusCode::NoCapacity
                                                  : StatusCode::RadioFailure,
                      "esp_now_add_peer failed");
  }
  peer.driver_registered = true;
  const auto rate = apply_lr250(peer.mac);
  if (!rate) {
    (void)esp_now_del_peer(peer.mac.bytes.data());
    peer.driver_registered = false;
    return rate;
  }
  return Status::success();
}

Status EspNowRuntime::initialize_espnow() noexcept {
  auto error = esp_now_init();
  if (error != ESP_OK) return esp_status(error, StatusCode::RadioFailure, "esp_now_init failed");
  espnow_initialized_ = true;
  instance_ = this;
  if ((error = esp_now_register_recv_cb(&EspNowRuntime::receive_callback)) != ESP_OK ||
      (error = esp_now_register_send_cb(&EspNowRuntime::send_callback)) != ESP_OK) {
    return esp_status(error, StatusCode::RadioFailure, "ESP-NOW callback registration failed");
  }
  for (auto& peer : peers_) {
    if (peer.used) {
      const auto status = register_driver_peer(peer);
      if (!status) return status;
    }
  }
  return Status::success();
}

Status EspNowRuntime::initialize() noexcept {
  if (event_queue_ != nullptr) return Status::error(StatusCode::AlreadyExists, "runtime initialized");
  if (!security_.ready()) return Status::error(StatusCode::InvalidState, "security provider not ready");
  event_queue_ = xQueueCreate(kEventQueueCapacity, sizeof(Event));
  if (event_queue_ == nullptr) return Status::error(StatusCode::NoCapacity, "event queue allocation failed");
  auto status = initialize_wifi();
  if (status) status = initialize_espnow();
  if (!status) {
    stop();
    return status;
  }
  return Status::success();
}

Status EspNowRuntime::register_neighbor(const NodeId node, const MacAddress& mac,
                                        const RouteMetric link_metric) noexcept {
  if (node == kInvalidNodeId || node == config_.node.node || link_metric == 0 ||
      link_metric == kInfiniteRouteMetric) {
    return Status::error(StatusCode::InvalidArgument, "invalid neighbor registration");
  }
  Peer* record = find_peer(node);
  if (record == nullptr) {
    for (auto& candidate : peers_) {
      if (!candidate.used) { record = &candidate; break; }
    }
  }
  if (record == nullptr) return Status::error(StatusCode::NoCapacity, "peer mapping full");
  if (record->used && !(record->mac == mac)) {
    return Status::error(StatusCode::Conflict, "node already mapped to another MAC");
  }
  record->used = true;
  record->node = node;
  record->mac = mac;
  record->metric = link_metric;
  if (espnow_initialized_) {
    const auto status = register_driver_peer(*record);
    if (!status) return status;
  }
  if (started_) return node_.add_neighbor(node, link_metric, now_ms());
  return Status::success();
}

Status EspNowRuntime::start() noexcept {
  if (event_queue_ == nullptr || !espnow_initialized_) {
    return Status::error(StatusCode::InvalidState, "runtime not initialized");
  }
  if (started_) return Status::error(StatusCode::AlreadyExists, "runtime started");
  auto status = node_.start(now_ms());
  if (!status) return status;
  for (const auto& peer : peers_) {
    if (!peer.used) continue;
    status = node_.add_neighbor(peer.node, peer.metric, now_ms());
    if (!status) return status;
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
    if (!status) return status;
  }
  if (task_ != nullptr) return Status::error(StatusCode::AlreadyExists, "runtime task exists");
  const BaseType_t result = xTaskCreatePinnedToCore(&EspNowRuntime::task_entry,
      name == nullptr ? "routeloom" : name, config_.task_stack_bytes / sizeof(StackType_t),
      this, config_.task_priority, &task_, config_.task_core);
  return result == pdPASS ? Status::success()
                          : Status::error(StatusCode::NoCapacity, "runtime task allocation failed");
}

void EspNowRuntime::stop() noexcept {
  started_ = false;
  if (task_ != nullptr) {
    for (int i = 0; i < 50 && task_ != nullptr; ++i) vTaskDelay(pdMS_TO_TICKS(1));
  }
  portENTER_CRITICAL(&callback_lock_);
  if (instance_ == this) instance_ = nullptr;
  pending_tx_ = false;
  pending_token_ = 0;
  portEXIT_CRITICAL(&callback_lock_);
  if (espnow_initialized_) {
    (void)esp_now_unregister_recv_cb();
    (void)esp_now_unregister_send_cb();
    (void)esp_now_deinit();
    espnow_initialized_ = false;
  }
  if (wifi_initialized_) {
    (void)esp_wifi_stop();
    (void)esp_wifi_deinit();
    wifi_initialized_ = false;
  }
  if (event_queue_ != nullptr) {
    vQueueDelete(event_queue_);
    event_queue_ = nullptr;
  }
}

void EspNowRuntime::poll_once() noexcept {
  if (!started_ || event_queue_ == nullptr) return;
  Event event{};
  while (xQueueReceive(event_queue_, &event, 0) == pdTRUE) {
    if (event.kind == EventKind::Tx) {
      node_.on_radio_tx_result(event.token, event.success, now_ms());
    } else {
      node_.on_radio_receive(event.peer, ByteView{event.data.data(), event.length},
                             RadioRxMetadata{event.rssi_dbm}, now_ms());
    }
  }
  node_.poll(now_ms());
}

Status EspNowRuntime::send_application(const NodeId destination, const ByteView payload,
                                       const SendOptions& options, MessageId& id) noexcept {
  if (!started_) return Status::error(StatusCode::InvalidState, "runtime not started");
  return node_.send(destination, payload, options, now_ms(), id);
}

Status EspNowRuntime::send(const NodeId peer, const std::uint64_t token,
                           const ByteView frame) noexcept {
  const Peer* record = find_peer(peer);
  if (record == nullptr || !record->driver_registered) {
    return Status::error(StatusCode::NotFound, "peer is not registered");
  }
  if (frame.data == nullptr || frame.size == 0 || frame.size > ESP_NOW_MAX_DATA_LEN) {
    return Status::error(StatusCode::InvalidArgument, "invalid ESP-NOW frame");
  }
  portENTER_CRITICAL(&callback_lock_);
  if (pending_tx_) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock, "physical TX already in flight");
  }
  pending_tx_ = true;
  pending_token_ = token;
  pending_mac_ = record->mac;
  portEXIT_CRITICAL(&callback_lock_);
  const esp_err_t error = esp_now_send(record->mac.bytes.data(), frame.data, frame.size);
  if (error != ESP_OK) {
    portENTER_CRITICAL(&callback_lock_);
    pending_tx_ = false;
    pending_token_ = 0;
    portEXIT_CRITICAL(&callback_lock_);
    if (error == ESP_ERR_ESPNOW_NO_MEM) return Status::error(StatusCode::WouldBlock, "ESP-NOW NO_MEM");
    if (error == ESP_ERR_ESPNOW_FULL) return Status::error(StatusCode::NoCapacity, "ESP-NOW peer full");
    if (error == ESP_ERR_ESPNOW_CHAN) return Status::error(StatusCode::Conflict, "ESP-NOW channel mismatch");
    return Status::error(StatusCode::RadioFailure, "esp_now_send failed");
  }
  return Status::success();
}

Status EspNowRuntime::rebuild_driver() noexcept {
  if (espnow_initialized_) {
    (void)esp_now_unregister_recv_cb();
    (void)esp_now_unregister_send_cb();
    (void)esp_now_deinit();
    espnow_initialized_ = false;
  }
  for (auto& peer : peers_) peer.driver_registered = false;
  return initialize_espnow();
}

Status EspNowRuntime::recover() noexcept {
  portENTER_CRITICAL(&callback_lock_);
  pending_tx_ = false;
  pending_token_ = 0;
  portEXIT_CRITICAL(&callback_lock_);
  return rebuild_driver();
}

void EspNowRuntime::receive_callback(const esp_now_recv_info_t* info,
                                     const std::uint8_t* data,
                                     const int length) noexcept {
  if (instance_ != nullptr) instance_->enqueue_rx(info, data, length);
}

void EspNowRuntime::send_callback(const esp_now_send_info_t* info,
                                  const esp_now_send_status_t status) noexcept {
  if (instance_ != nullptr) instance_->enqueue_tx(info, status);
}

void EspNowRuntime::enqueue_rx(const esp_now_recv_info_t* info,
                               const std::uint8_t* data, const int length) noexcept {
  if (event_queue_ == nullptr || info == nullptr || info->src_addr == nullptr ||
      data == nullptr || length <= 0 || length > static_cast<int>(kMaxEspNowBody)) return;
  Peer* peer = find_peer(info->src_addr);
  if (peer == nullptr) return;
  Event event{};
  event.kind = EventKind::Rx;
  event.peer = peer->node;
  event.length = static_cast<std::uint16_t>(length);
  event.rssi_dbm = info->rx_ctrl != nullptr ? info->rx_ctrl->rssi : 0;
  std::memcpy(event.data.data(), data, event.length);
  (void)xQueueSend(event_queue_, &event, 0);
}

void EspNowRuntime::enqueue_tx(const esp_now_send_info_t* info,
                               const esp_now_send_status_t status) noexcept {
  if (event_queue_ == nullptr || info == nullptr || info->des_addr == nullptr) return;
  Event event{};
  event.kind = EventKind::Tx;
  portENTER_CRITICAL(&callback_lock_);
  if (!pending_tx_ || std::memcmp(pending_mac_.bytes.data(), info->des_addr,
                                  pending_mac_.bytes.size()) != 0) {
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

}  // namespace routeloom::espnow
