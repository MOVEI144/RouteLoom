#include "routeloom/espnow_runtime.hpp"

#include <algorithm>
#include <cstring>
#include <new>

#include "esp_event.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "routeloom/wire.hpp"

namespace routeloom::espnow {
namespace {
[[maybe_unused]] constexpr char kTag[] = "RouteLoom";
// Wire-lane autonomy control frames are 1-hop liveness exchanges; a short
// lifetime keeps a stale probe from circulating.
constexpr std::uint32_t kAutonomyWireLifetimeMs = 500;
// poll_once runs every ~2ms: stack headroom is logged once a minute.
constexpr std::uint64_t kStackHwmLogIntervalMs = 60000;

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
      channel_port_(*this), reply_port_(*this),
      channel_runner_(channel_port_, ops_config_for(config)) {
  // Issue #117: every admission reserves a protected reply binding, and
  // node start refuses without a lease port — install it here, where no
  // transaction can be live yet so the attach cannot fail.
  (void)node_.set_reply_peer_port(&reply_port_);
}

EspNowRuntime::~EspNowRuntime() { stop(); }

MonotonicMs EspNowRuntime::now_ms() const noexcept {
  return static_cast<MonotonicMs>(esp_timer_get_time() / 1000);
}

std::uint64_t EspNowRuntime::now_us() noexcept {
  return static_cast<std::uint64_t>(esp_timer_get_time());
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
  // wifi_country_t::max_tx_power is in dBm — esp_wifi_set_max_tx_power maps
  // its qdBm argument into this field via a {power -> dBm} table (IDF v6.0.3
  // Wi-Fi API reference). The effective cap is re-applied below in qdBm.
  country.max_tx_power =
      static_cast<int8_t>(config_.max_tx_power_qdbm / 4);
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
  portENTER_CRITICAL(&callback_lock_);
  const bool registered = peer.driver_registered;
  portEXIT_CRITICAL(&callback_lock_);
  if (registered) {
    return Status::success();
  }
  const Status status = add_driver_peer(peer.mac);
  if (!status) {
    return status;
  }
  portENTER_CRITICAL(&callback_lock_);
  peer.driver_registered = true;
  portEXIT_CRITICAL(&callback_lock_);
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
  // Route advertisements also use this permanent peer when discovery is
  // absent. Register it once with the same radio-owner rate setup.
  const Status broadcast_status = register_broadcast_peer();
  if (!broadcast_status) return broadcast_status;
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
  // Radio-only init (G-SEC P4 §8.1): provider readiness gates the node
  // start (MeshNode::start refuses an unready provider), not the radio —
  // a member-mode device brings the radio up for its zero-touch join
  // while the session provider is still unconfigured, and the node
  // starts only after the adopted member config lands.
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
  if (reply_call_active_.load() || node_.in_external_callback()) {
    return Status::error(StatusCode::Busy, "reentrant owner call");
  }
  if (node == kInvalidNodeId || node == config_.node.node ||
      link_metric == 0 || link_metric == kInfiniteRouteMetric) {
    return Status::error(StatusCode::InvalidArgument,
                         "invalid neighbor registration");
  }
  // Peer-table mutation runs under callback_lock_ so the WiFi-task RX
  // callback never observes a torn (used, node, mac) triple.
  portENTER_CRITICAL(&callback_lock_);
  Peer* record = find_peer(node);
  if (record == nullptr) {
    if (regular_used() >= regular_budget()) {
      portEXIT_CRITICAL(&callback_lock_);
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
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::NoCapacity, "peer mapping full");
  }
  const bool newly_created = !record->used;
  const RouteMetric old_metric = record->metric;
  const bool old_release_pending = record->release_pending;
  if (record->binding_retired) {
    const bool cleanup = record->registration_failed && !record->autonomy &&
                         record->release_pending &&
                         record->mac == mac && record->node == node;
    portEXIT_CRITICAL(&callback_lock_);
    if (cleanup) {
      const Status released = release_driver_peer(mac, node);
      if (!released) return released;
      portENTER_CRITICAL(&callback_lock_);
      record->used = false;
      record->driver_registered = false;
      record->node = kInvalidNodeId;
      record->binding_id = kInvalidBindingId;
      record->binding = BindingGeneration{0};
      record->rx_context_id = 0;
      record->release_pending = false;
      record->binding_retired = false;
      record->registration_failed = false;
      portEXIT_CRITICAL(&callback_lock_);
      return register_neighbor(node, mac, link_metric);
    }
    return Status::error(StatusCode::Conflict,
                         "prior binding still draining");
  }
  if (record->used && !(record->mac == mac)) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::Conflict,
                         "node already mapped to another MAC");
  }
  if (newly_created) {
    if (next_static_binding_id_ < 0x80000000u) {
      portEXIT_CRITICAL(&callback_lock_);
      return Status::error(StatusCode::CounterExhausted,
                           "static binding ids exhausted");
    }
    record->binding_id = BindingId{next_static_binding_id_--};
    record->binding = BindingGeneration{1};
    record->rx_context_id = 0;
    record->autonomy = false;
    record->binding_retired = false;
    record->registration_failed = false;
  }
  record->used = true;
  record->node = node;
  record->mac = mac;
  record->metric = link_metric;
  // A new mapping cannot admit RX work until both driver registration and
  // the Node's route-neighbor insertion have succeeded.
  record->release_pending = true;
  portEXIT_CRITICAL(&callback_lock_);
  if (espnow_initialized_) {
    const auto status = register_driver_peer(*record);
    if (!status) {
      if (newly_created) {
        portENTER_CRITICAL(&callback_lock_);
        record->used = false;
        record->node = kInvalidNodeId;
        record->binding_id = kInvalidBindingId;
        record->binding = BindingGeneration{0};
        record->rx_context_id = 0;
        record->release_pending = false;
        record->registration_failed = false;
        portEXIT_CRITICAL(&callback_lock_);
      } else {
        portENTER_CRITICAL(&callback_lock_);
        record->metric = old_metric;
        record->release_pending = old_release_pending;
        portEXIT_CRITICAL(&callback_lock_);
      }
      return status;
    }
  }
  if (started_) {
    const Status status = node_.add_neighbor(node, link_metric, now_ms());
    if (!status) {
      if (newly_created) {
        const Status released = release_driver_peer(mac, node);
        portENTER_CRITICAL(&callback_lock_);
        if (released) {
          record->used = false;
          record->driver_registered = false;
          record->node = kInvalidNodeId;
          record->binding_id = kInvalidBindingId;
          record->binding = BindingGeneration{0};
          record->rx_context_id = 0;
          record->release_pending = false;
          record->registration_failed = false;
        } else {
          record->binding_retired = true;
          record->registration_failed = true;
        }
        portEXIT_CRITICAL(&callback_lock_);
        if (!released) return released;
      } else {
        portENTER_CRITICAL(&callback_lock_);
        record->metric = old_metric;
        record->release_pending = old_release_pending;
        portEXIT_CRITICAL(&callback_lock_);
      }
      return status;
    }
  }
  portENTER_CRITICAL(&callback_lock_);
  record->release_pending = false;
  portEXIT_CRITICAL(&callback_lock_);
  return Status::success();
}

Status EspNowRuntime::attach_bootstrap_sink(BootstrapRld1Sink& sink) noexcept {
  if (bootstrap_sink_ != nullptr) {
    return Status::error(StatusCode::AlreadyExists,
                         "bootstrap sink already attached");
  }
  bootstrap_sink_ = &sink;
  return Status::success();
}

Status EspNowRuntime::adopt_member_node(const routeloom::NodeConfig& adopted) noexcept {
  if (node_.started() || started_) {
    return Status::error(StatusCode::InvalidState,
                         "member config arrived after node start");
  }
  node_.~MeshNode();
  new (&node_) MeshNode(adopted, *this, security_, observer_);
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
    if (peer.autonomy) {
      // Autonomy-managed peers enter routing only at REACHABLE; anything
      // else is picked up (or released) by the next lease sync instead of
      // leaking a stale link into the neighbor table.
      NeighborPhase phase{};
      if (discovery_ == nullptr ||
          !discovery_->phase_of(peer.node, phase) ||
          phase != NeighborPhase::Reachable) {
        continue;
      }
    }
    status = node_.add_neighbor(peer.node, peer.metric, now_ms());
    if (!status) {
      return status;
    }
    if (peer.autonomy) {
      // Restart path: the neighbor add here must be undoable by a later
      // autonomy release, so mirror the REACHABLE bookkeeping.
      portENTER_CRITICAL(&callback_lock_);
      peer.neighbor_added = true;
      portEXIT_CRITICAL(&callback_lock_);
    }
  }
  started_ = true;
  return Status::success();
}

void EspNowRuntime::task_entry(void* argument) noexcept {
  auto* runtime = static_cast<EspNowRuntime*>(argument);
  // task_ has a single writer — this task: self-published first so a
  // stop() running on it recognizes the self-call, self-cleared before
  // the join flag drops so a joiner never observes a dangling handle.
  runtime->task_ = xTaskGetCurrentTaskHandle();
  while (runtime->started_) {
    runtime->poll_once();
    runtime->wait_for_event(kOwnerPollPeriodMs);
  }
  runtime->task_ = nullptr;
  // Released last: once task_running_ reads false, a joining stop() owns
  // the teardown and frees the queues this task was draining.
  runtime->task_running_ = false;
  vTaskDelete(nullptr);
}

Status EspNowRuntime::start_task(const char* name) noexcept {
  if (!started_) {
    const auto status = start();
    if (!status) {
      return status;
    }
  }
  // Liveness is claimed before the task exists: it may start on another
  // core (or preempt this one at a higher priority) in the window before
  // xTaskCreatePinnedToCore returns, and both stop()'s join and this
  // double-start guard must already see it. task_running_ is that flag;
  // task_ is left for the task itself to publish (single writer).
  bool expected = false;
  if (!task_running_.compare_exchange_strong(expected, true)) {
    return Status::error(StatusCode::AlreadyExists,
                         "runtime task exists");
  }
  const BaseType_t result = xTaskCreatePinnedToCore(
      &EspNowRuntime::task_entry, name == nullptr ? "routeloom" : name,
      config_.task_stack_bytes / sizeof(StackType_t), this,
      config_.task_priority, nullptr, config_.task_core);
  if (result != pdPASS) {
    task_running_ = false;
    return Status::error(StatusCode::NoCapacity,
                         "runtime task allocation failed");
  }
  return Status::success();
}

void EspNowRuntime::stop() noexcept {
  started_ = false;
  // Join before teardown: the poll task clears task_running_ only after
  // its in-flight poll_once() returns, and the queues it drains are
  // freed below. The wait covers the whole create→exit window, since
  // task_running_ is claimed before the task can run (start_task()).
  // Contract (header): single caller, never issued on the poll task — a
  // stop() reaching here from inside a poll_once observer callback
  // cannot wait on itself, so it skips the join and still tears the
  // queues down under the in-flight frame (configASSERT on the next
  // queue touch), the same hazard the pre-join code had.
  if (task_.load() != xTaskGetCurrentTaskHandle()) {
    constexpr TickType_t kWarnIntervalTicks = pdMS_TO_TICKS(5000);
    TickType_t waited_ticks = 0;
    while (task_running_.load()) {
      vTaskDelay(pdMS_TO_TICKS(1));
      if (++waited_ticks >= kWarnIntervalTicks) {
        waited_ticks = 0;
        ESP_LOGW(kTag, "runtime task still draining");
      }
    }
  }
  // The Owner worker is joined. Settle Node jobs while the lease port and
  // driver still exist, then retire any remaining Owner-held uses.
  (void)node_.quiesce_for_sleep();
  (void)reply_leases_.invalidate_all();
  portENTER_CRITICAL(&callback_lock_);
  if (instance_ == this) {
    instance_ = nullptr;
  }
  pending_tx_ = false;
  pending_token_ = 0;
  pending_node_ = kInvalidNodeId;
  pending_generation_ = 0;
  fenced_outstanding_ = false;
  raw_tx_count_ = 0;
  expired_tx_count_ = 0;
  quarantined_count_ = 0;
  quarantine_notice_count_ = 0;
  quarantine_recover_next_ms_ = 0;
  lost_tx_count_ = 0;
  lost_node_tx_valid_ = false;
  portEXIT_CRITICAL(&callback_lock_);
  if (espnow_initialized_) {
    (void)esp_now_unregister_recv_cb();
    (void)esp_now_unregister_send_cb();
    (void)esp_now_deinit();
    espnow_initialized_ = false;
  }
  portENTER_CRITICAL(&callback_lock_);
  for (auto& peer : peers_) {
    peer.driver_registered = false;
  }
  for (auto& slot : transient_peers_) {
    slot.used = false;
  }
  portEXIT_CRITICAL(&callback_lock_);
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
  if (event_queue_ == nullptr) {
    return;
  }
  const MonotonicMs now = now_ms();
  if (!started_) {
    // Join RLD1 and channel operations run before the member Node starts.
    // No ordinary Wire frame may enter an unstarted Node; discard that
    // bounded queue while the bootstrap owner receives its own lane.
    Event discarded{};
    for (std::size_t i = 0; i < kEventQueueCapacity &&
                            xQueueReceive(event_queue_, &discarded, 0) == pdTRUE; ++i) {}
    poll_bootstrap(now);
    channel_runner_.poll(now);
    return;
  }
  // Stack headroom of the CALLING task: poll_once is driven by the runtime
  // task (start_task) or by the app_main pump loops (bridge_node,
  // reference_node deep-sleep), so this one site covers whichever stack the
  // firmware drains events on. Rate-limited — this path runs every ~2ms.
  if (now - stack_hwm_log_ms_ >= kStackHwmLogIntervalMs) {
    stack_hwm_log_ms_ = now;
    ESP_LOGI(kTag, "stack hwm %s %lu B", pcTaskGetName(nullptr),
             static_cast<unsigned long>(uxTaskGetStackHighWaterMark(nullptr)));
  }
  Event event{};
  // The dedicated reserved-completion slot drains FIRST — it resolves the
  // node's outstanding job and is never displaced by raw traffic.
  {
    bool have = false;
    portENTER_CRITICAL(&callback_lock_);
    if (lost_node_tx_valid_) {
      event = lost_node_tx_;
      lost_node_tx_valid_ = false;
      have = true;
    }
    portEXIT_CRITICAL(&callback_lock_);
    if (have) {
      RadioTxObservation staged{};
      staged.peer = event.peer;
      staged.binding_generation = event.binding;
      staged.radio_generation = event.radio_generation;
      staged.channel_epoch = event.channel_epoch;
      staged.submitted_us = event.submitted_us;
      staged.completed_us = event.observed_us;
      staged.frame_length_class = event.frame_length_class;
      staged.outcome = event.success ? RadioTxOutcome::Success
                                     : RadioTxOutcome::Failure;
      staged.provenance = ObservationProvenance::LocalDriver;
      staged.token = event.token;
      if (event.peer != kBroadcastNodeId) node_.note_radio_tx(staged, now);
      node_.on_radio_tx_result(event.token, event.success, now);
    }
  }
  // Staged TX completions next: a queue-full callback already consumed its
  // pending record — delaying it would leave the node's job unresolved.
  for (;;) {
    portENTER_CRITICAL(&callback_lock_);
    if (lost_tx_count_ == 0) {
      portEXIT_CRITICAL(&callback_lock_);
      break;
    }
    event = lost_tx_[--lost_tx_count_];
    portEXIT_CRITICAL(&callback_lock_);
    RadioTxObservation staged{};
    staged.peer = event.peer;
    staged.binding_generation = event.binding;
    staged.radio_generation = event.radio_generation;
    staged.channel_epoch = event.channel_epoch;
    staged.submitted_us = event.submitted_us;
    staged.completed_us = event.observed_us;
    staged.frame_length_class = event.frame_length_class;
    staged.outcome = event.tx_lane == TxLane::Stale
                         ? RadioTxOutcome::Unknown
                         : (event.success ? RadioTxOutcome::Success
                                          : RadioTxOutcome::Failure);
    staged.provenance = ObservationProvenance::LocalDriver;
    staged.token = event.token;
    if (event.peer != kBroadcastNodeId) node_.note_radio_tx(staged, now);
    if (event.tx_lane == TxLane::Reserved) {
      node_.on_radio_tx_result(event.token, event.success, now);
    }
  }
  while (xQueueReceive(event_queue_, &event, 0) == pdTRUE) {
    if (event.kind == EventKind::Tx) {
      // Telemetry gets every completion lane; the node's job resolution only
      // ever sees the Reserved lane — raw/stale completions resolve nothing
      // (X-02, 02-telemetry §2.2).
      RadioTxObservation obs{};
      obs.peer = event.peer;
      obs.binding_generation = event.binding;
      obs.radio_generation = event.radio_generation;
      obs.channel_epoch = event.channel_epoch;
      obs.submitted_us = event.submitted_us;
      obs.completed_us = event.observed_us;
      obs.frame_length_class = event.frame_length_class;
      obs.outcome = event.tx_lane == TxLane::Stale
                        ? RadioTxOutcome::Unknown
                        : (event.success ? RadioTxOutcome::Success
                                         : RadioTxOutcome::Failure);
      obs.provenance = ObservationProvenance::LocalDriver;
      obs.token = event.token;
      if (event.peer != kBroadcastNodeId) node_.note_radio_tx(obs, now);
      if (event.tx_lane == TxLane::Reserved) {
        node_.on_radio_tx_result(event.token, event.success, now);
      }
    } else {
      RadioRxMetadataV2 meta{};
      meta.received_us = event.observed_us;
      meta.binding_generation = event.binding;
      meta.binding = event.binding_id;
      meta.radio_generation = event.radio_generation;
      meta.channel_epoch = event.channel_epoch;
      meta.rssi_dbm = event.rssi_dbm;
      meta.rssi_valid = event.rssi_valid;
      meta.channel = event.channel;
      meta.channel_valid = event.channel_valid;
      meta.provenance = ObservationProvenance::LocalDriver;
      // Revalidate the captured identity before dispatch (02 §2.2): an
      // event queued before a rebind or channel commit must not let its
      // stale generations read as current evidence — retire the summary
      // AND strip the metadata's freshness so it feeds neither the peer
      // telemetry summary nor the connectivity oracle.
      {
        bool identity_current = false;
        portENTER_CRITICAL(&callback_lock_);
        if (const Peer* record = find_peer(event.source.data())) {
          identity_current = record->binding == event.binding &&
              record->binding_id == event.binding_id;
        }
        identity_current = identity_current &&
            event.radio_generation == channel_runner_.radio_generation() &&
            event.channel_epoch == channel_epoch_;
        portEXIT_CRITICAL(&callback_lock_);
        meta.identity_current = identity_current;
        if (!identity_current) {
          node_.note_peer_stale(event.peer);
        }
      }
      rx_source_ = event.source;
      node_.on_radio_receive(
          event.peer, ByteView{event.data.data(), event.length}, meta, now);
      rx_source_ = {};
    }
  }
  // Callback watchdog on the reserved send: a driver that never calls back
  // must not wedge pending_tx_ forever. Fencing moves it to the stale lane
  // where a late callback resolves as Unknown evidence, never success.
  {
    bool fence = false;
    portENTER_CRITICAL(&callback_lock_);
    if (pending_tx_ &&
        now - pending_sent_ms_ >= config_.node.callback_watchdog_ms) {
      fence = true;
    }
    portEXIT_CRITICAL(&callback_lock_);
    if (fence) {
      channel_fence_tx();
    }
  }
  // Watchdog-retired raw sends surface as Unknown completions.
  for (;;) {
    RawTx retired{};
    portENTER_CRITICAL(&callback_lock_);
    if (expired_tx_count_ == 0) {
      portEXIT_CRITICAL(&callback_lock_);
      break;
    }
    retired = expired_tx_[--expired_tx_count_];
    portEXIT_CRITICAL(&callback_lock_);
    RadioTxObservation obs{};
    obs.peer = retired.node;
    obs.binding_generation = retired.binding;
    obs.radio_generation = retired.radio_generation;
    obs.channel_epoch = retired.channel_epoch;
    obs.submitted_us = retired.submitted_us;
    obs.completed_us = 0;
    obs.frame_length_class = retired.length_class;
    obs.outcome = RadioTxOutcome::Unknown;
    // The submission was real driver work — only the outcome is unknown.
    obs.provenance = ObservationProvenance::LocalDriver;
    node_.note_radio_tx(obs, now);
  }
  // Quarantine notices staged inside callback_lock_ drain here — observer
  // work runs only on the poll task (same rule as expired_tx_).
  for (;;) {
    NodeId peer = kInvalidNodeId;
    portENTER_CRITICAL(&callback_lock_);
    if (quarantine_notice_count_ == 0) {
      portEXIT_CRITICAL(&callback_lock_);
      break;
    }
    peer = quarantine_notices_[--quarantine_notice_count_];
    portEXIT_CRITICAL(&callback_lock_);
    observer_.on_diagnostic("OP_TX_QUARANTINED", peer, nullptr);
  }
  // Raw-lane quarantine self-recovery (02 §2.3/X-02): entries release only
  // via the owed callback or recover()->rebuild_driver(). The node's
  // reserved-lane watchdog is the sole in-band recover() caller and it
  // needs an in-flight DATA send — a node that only runs discovery would
  // hold a quarantined MAC forever, every later send returning WouldBlock.
  // After kQuarantineRecoverWindows watchdog windows of dwell the runtime
  // recovers itself; the trigger defers while a serialized channel
  // operation owns the radio (rebuild_driver() must not tear down an
  // in-flight survey/visit) and is rate-limited to one attempt per
  // watchdog window so a failing driver cannot storm rebuilds.
  {
    NodeId recover_peer = kInvalidNodeId;
    bool due = false;
    portENTER_CRITICAL(&callback_lock_);
    if (quarantined_count_ != 0 && now >= quarantine_recover_next_ms_) {
      std::size_t oldest = 0;
      for (std::size_t i = 1; i < quarantined_count_; ++i) {
        if (quarantined_tx_[i].sent_ms < quarantined_tx_[oldest].sent_ms) {
          oldest = i;
        }
      }
      if (now - quarantined_tx_[oldest].sent_ms >=
          static_cast<MonotonicMs>(config_.node.callback_watchdog_ms) *
              kQuarantineRecoverWindows) {
        due = true;
        recover_peer = quarantined_tx_[oldest].node;
      }
    }
    portEXIT_CRITICAL(&callback_lock_);
    if (due && !channel_runner_.busy()) {
      observer_.on_diagnostic("OP_TX_QUARANTINE_RECOVER", recover_peer,
                              nullptr);
      quarantine_recover_next_ms_ =
          now + config_.node.callback_watchdog_ms;
      (void)recover();
    }
  }
  poll_bootstrap(now);
  // Serialized channel operations advance here: drain fence -> verified
  // apply -> bounded visit dwell -> verified return home (04 §3/§8).
  channel_runner_.poll(now);
  if (migration_ != nullptr) {
    migration_->poll(now);
  }
  node_.poll(now);
}

void EspNowRuntime::poll_bootstrap(const MonotonicMs now) noexcept {
  if (bootstrap_queue_ != nullptr &&
      (discovery_ != nullptr || bootstrap_sink_ != nullptr)) {
    BootstrapEvent rx{};
    for (std::size_t i = 0; i < kBootstrapQueueCapacity &&
                            xQueueReceive(bootstrap_queue_, &rx, 0) == pdTRUE; ++i) {
      if (bootstrap_sink_ != nullptr) {
        // The security owner demuxes: ZT to its Joiner, member link
        // frames to its engine, member Discovers back into discovery.
        sdkv1::JoinRxMeta meta{};
        meta.source = rx.source;
        meta.destination = rx.destination;
        meta.channel = rx.channel;
        meta.rssi = rx.rssi_dbm;
        bootstrap_sink_->on_bootstrap_rld1(meta, rx.radio_generation,
                                           ByteView{rx.data.data(), rx.length},
                                           rx.received_ms);
      } else {
        discovery_->on_rld1_rx(
            DiscoveryRxMetadata{rx.source, rx.destination},
            ByteView{rx.data.data(), rx.length}, rx.received_ms);
      }
    }
    if (discovery_ != nullptr && started_) {
      discovery_->poll(now);
      reconcile_autonomy(now);
    }
  }
}

void EspNowRuntime::wait_for_event(const MonotonicMs timeout_ms) noexcept {
  if (event_queue_ == nullptr) {
    vTaskDelay(pdMS_TO_TICKS(timeout_ms));
    return;
  }
  // Staged completions bypass the queue: a TX callback that lands on a
  // full queue while poll_once is draining stages its completion AFTER
  // the pass's entry check — the queue is empty now but the node's job is
  // still unresolved. Blocking here would idle until the next tick
  // (issue #60-3), so re-check the staging slots under the lock for the
  // shared owner wait below.
  bool staged = false;
  portENTER_CRITICAL(&callback_lock_);
  staged = lost_node_tx_valid_ || lost_tx_count_ != 0;
  portEXIT_CRITICAL(&callback_lock_);
  // Thin FreeRTOS binding of the shared owner wait (owner_pump.hpp — the
  // host harness executes the same routine against a fake queue). Peek,
  // not receive: the event stays queued for poll_once's ordered drain
  // (reserved slots -> lost completions -> queued events -> node poll).
  // A TX completion posted while we sleep releases the wait NOW — the
  // event wins over the periodic tick (issue #60-3). Bootstrap-queue
  // traffic keeps its old bounded latency via the periodic timeout.
  struct QueueWait {
    QueueHandle_t queue;
    void wait_until_posted(const MonotonicMs wait_ms) noexcept {
      Event peek{};
      (void)xQueuePeek(queue, &peek, pdMS_TO_TICKS(wait_ms));
    }
  };
  QueueWait wait{event_queue_};
  owner_wait_for_event(wait, timeout_ms, staged);
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
  // Completion callbacks identify a send only by des_addr: never let two
  // sends share a destination MAC while a completion is outstanding.
  const MonotonicMs now = now_ms();
  portENTER_CRITICAL(&callback_lock_);
  if (pending_tx_ && pending_mac_ == mac) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock,
                         "reserved DATA TX in flight to peer");
  }
  // Retire entries whose completion never arrived (callback watchdog). The
  // expiry is evidence too: each retires into expired_tx_ for Unknown
  // accounting AND into the MAC quarantine — the still-owed callback must
  // never resolve a replacement send to the same destination (02 §2.3).
  // When the quarantine table is full the entry is NOT retired: it stays
  // outstanding (blocking that MAC) rather than losing callback tracking.
  std::size_t kept = 0;
  for (std::size_t i = 0; i < raw_tx_count_; ++i) {
    if (now - raw_tx_[i].sent_ms < config_.node.callback_watchdog_ms) {
      raw_tx_[kept++] = raw_tx_[i];
      continue;
    }
    if (quarantined_count_ < quarantined_tx_.size()) {
      quarantined_tx_[quarantined_count_++] = raw_tx_[i];
      stage_quarantine_notice(raw_tx_[i].node);
      if (expired_tx_count_ < expired_tx_.size()) {
        expired_tx_[expired_tx_count_++] = raw_tx_[i];
      } else {
        ++telemetry_event_drops_;
      }
      continue;
    }
    raw_tx_[kept++] = raw_tx_[i];  // stays outstanding — MAC remains blocked
  }
  raw_tx_count_ = kept;
  if (tx_quarantined(mac)) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock,
                         "TX callback quarantine on peer");
  }
  // The reserved-send fence gates raw sends too: a watchdog-retired
  // reserved TX still owes a callback that must never resolve this send.
  // No timer releases the fence — only the owed callback or driver
  // recovery (02 §2.3); the peer stays unavailable until then.
  if (fenced_outstanding_ && fenced_mac_ == mac) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock, "TX_FENCE_GUARD");
  }
  for (std::size_t i = 0; i < raw_tx_count_; ++i) {
    if (raw_tx_[i].mac == mac) {
      portEXIT_CRITICAL(&callback_lock_);
      return Status::error(StatusCode::WouldBlock,
                           "autonomy TX already in flight to peer");
    }
  }
  if (raw_tx_count_ == raw_tx_.size()) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock, "autonomy TX window full");
  }
  RawTx& raw = raw_tx_[raw_tx_count_];
  raw.mac = mac;
  raw.sent_ms = now;
  // Submit-time observation record (02 §2.2): identity snapshot taken now —
  // the completion can never attribute to a newer binding/radio/channel.
  raw.submitted_us = now_us();
  raw.radio_generation = channel_runner_.radio_generation();
  raw.channel_epoch = channel_epoch_;
  raw.length_class = frame_length_class(frame.size);
  raw.node = kInvalidNodeId;
  raw.binding = BindingGeneration{0};
  if (const Peer* record = find_peer(mac.bytes.data())) {
    raw.node = record->node;
    raw.binding = record->binding;
  }
  ++raw_tx_count_;
  portEXIT_CRITICAL(&callback_lock_);
  const esp_err_t error =
      esp_now_send(mac.bytes.data(), frame.data, frame.size);
  if (error != ESP_OK) {
    portENTER_CRITICAL(&callback_lock_);
    for (std::size_t i = 0; i < raw_tx_count_; ++i) {
      if (raw_tx_[i].mac == mac) {
        raw_tx_[i] = raw_tx_[--raw_tx_count_];
        break;
      }
    }
    portEXIT_CRITICAL(&callback_lock_);
    return esp_send_status(error);
  }
  return Status::success();
}

bool EspNowRuntime::reply_mapping(const NodeId peer,
                                     ReplyBinding& out) noexcept {
  out = ReplyBinding{};
  if (peer == kInvalidNodeId) return false;
  portENTER_CRITICAL(&callback_lock_);
  const Peer* record = find_peer(peer);
  if (record != nullptr && !record->release_pending &&
      record->driver_registered &&
      record->binding_id != kInvalidBindingId &&
      record->binding != BindingGeneration{0} &&
      record->rx_context_id != 0) {
    out.peer = peer;
    out.id = record->binding_id;
    out.generation = record->binding;
    out.rx_context_id = record->rx_context_id;
  }
  portEXIT_CRITICAL(&callback_lock_);
  return out.id != kInvalidBindingId &&
         reply_context_current(peer, out.rx_context_id).ok();
}

Status EspNowRuntime::reply_context_current(
    const NodeId peer, const std::uint32_t context) noexcept {
  std::uint32_t provider_context = 0;
  const Status status = security_.current_rx_epoch(
      SecurityScope::Link, peer, provider_context);
  if (status.code == StatusCode::Unsupported &&
      security_.security_profile() == SecurityProfile::Development) {
    return Status::success();
  }
  if (!status) return status;
  if (provider_context == 0 || provider_context != context) {
    return Status::error(StatusCode::Conflict, "reply context changed");
  }
  return Status::success();
}

Status EspNowRuntime::reply_observe_authenticated_rx(
    const ReplyBinding captured) noexcept {
  ReplyCallGuard guard(reply_call_active_);
  if (!guard.entered()) {
    return Status::error(StatusCode::Busy, "reentrant reply call");
  }
  if (captured.peer == kInvalidNodeId || captured.id == kInvalidBindingId ||
      captured.generation == BindingGeneration{0} ||
      captured.rx_context_id == 0) {
    return Status::error(StatusCode::InvalidArgument, "invalid RX binding");
  }
  std::uint32_t provider_context = 0;
  const Status context_status = security_.current_rx_epoch(
      SecurityScope::Link, captured.peer, provider_context);
  const bool ordered_development =
      context_status.code == StatusCode::Unsupported &&
      security_.security_profile() == SecurityProfile::Development;
  if (!ordered_development && !context_status) return context_status;
  if (!ordered_development && provider_context != captured.rx_context_id) {
    return Status::error(StatusCode::Conflict, "old RX context");
  }
  portENTER_CRITICAL(&callback_lock_);
  Peer* record = find_peer(captured.peer);
  Status status = Status::success();
  if (record == nullptr || !record->driver_registered ||
      record->binding_retired ||
      record->binding_id != captured.id ||
      record->binding != captured.generation) {
    status = Status::error(StatusCode::Conflict, "binding mapping changed");
  } else if (record->release_pending &&
             record->rx_context_id != captured.rx_context_id) {
    // A Stale peer can still answer an already submitted exchange under its
    // held binding; it cannot establish a new context while release waits.
    status = Status::error(StatusCode::Conflict, "binding release pending");
  } else if (ordered_development && record->rx_context_id != 0 &&
             captured.rx_context_id < record->rx_context_id) {
    status = Status::error(StatusCode::Conflict, "old RX context");
  } else if (record->rx_context_id != captured.rx_context_id) {
    if (record->rx_context_id != 0) {
      status = reply_leases_.invalidate_binding(record->binding_id);
    }
    if (status) record->rx_context_id = captured.rx_context_id;
  }
  portEXIT_CRITICAL(&callback_lock_);
  return status;
}

Status EspNowRuntime::reply_acquire(const ReplyBinding captured,
                                       const MonotonicMs deadline,
                                       const MonotonicMs now,
                                       ReplyLeaseToken& out) noexcept {
  out = kInvalidReplyLeaseToken;
  ReplyCallGuard guard(reply_call_active_);
  if (!guard.entered()) return Status::error(StatusCode::Busy, "reentrant reply call");
  const Status context_status =
      reply_context_current(captured.peer, captured.rx_context_id);
  if (!context_status) return context_status;
  portENTER_CRITICAL(&callback_lock_);
  const Peer* record = find_peer(captured.peer);
  const bool pinned =
      record != nullptr && record->driver_registered;
  ReplyBinding live{};
  if (record != nullptr && !record->release_pending &&
      record->binding_id != kInvalidBindingId &&
      record->binding != BindingGeneration{0}) {
    live.peer = captured.peer;
    live.id = record->binding_id;
    live.generation = record->binding;
    live.rx_context_id = record->rx_context_id;
  }
  Status status = Status::success();
  if (live.id == kInvalidBindingId || live.id != captured.id ||
      live.generation != captured.generation ||
      captured.rx_context_id == 0 ||
      captured.rx_context_id != live.rx_context_id) {
    // The live mapping moved (rebind, MAC flip, retire) or the capture
    // never had one — refuse rather than lease under a dead identity.
    status = Status::error(StatusCode::Conflict, "binding mapping changed");
  } else if (!pinned) {
    // A use must pin a driver record before it may succeed: a
    // driverless Stale marker cannot carry a reply.
    status = Status::error(StatusCode::Conflict, "peer driver not pinned");
  } else {
    status = reply_leases_.acquire(captured, deadline, now, out);
  }
  portEXIT_CRITICAL(&callback_lock_);
  return status;
}

Status EspNowRuntime::reply_release(const ReplyLeaseToken token) noexcept {
  ReplyCallGuard guard(reply_call_active_);
  if (!guard.entered()) return Status::error(StatusCode::Busy, "reentrant reply call");
  portENTER_CRITICAL(&callback_lock_);
  const Status status = reply_leases_.release(token);
  portEXIT_CRITICAL(&callback_lock_);
  // No driver unpin here: driver lifetime belongs to the lease sync, which
  // defers the physical release while any use holds the binding.
  return status;
}

Status EspNowRuntime::reply_validate(const ReplyLeaseToken token,
                                         const MonotonicMs now) noexcept {
  ReplyCallGuard guard(reply_call_active_);
  if (!guard.entered()) return Status::error(StatusCode::Busy, "reentrant reply call");
  portENTER_CRITICAL(&callback_lock_);
  const Status status = reply_leases_.validate(token, now);
  portEXIT_CRITICAL(&callback_lock_);
  return status;
}

Status EspNowRuntime::reply_send_reply(const ReplyLeaseToken token,
                                          const std::uint64_t tx_token,
                                          const ByteView frame,
                                          const MonotonicMs now) noexcept {
  ReplyCallGuard guard(reply_call_active_);
  if (!guard.entered()) return Status::error(StatusCode::Busy, "reentrant reply call");
  portENTER_CRITICAL(&callback_lock_);
  ReplyBinding bound{};
  Status status = reply_leases_.use_binding(token, bound);
  if (status) {
    status = reply_leases_.validate(token, now);
  }
  if (status) {
    const Peer* record = find_peer(bound.peer);
    if (record == nullptr || record->binding_retired ||
        !record->driver_registered ||
        record->binding_id != bound.id ||
        record->binding != bound.generation) {
      status = Status::error(StatusCode::Conflict, "binding mapping changed");
    }
  }
  portEXIT_CRITICAL(&callback_lock_);
  if (!status) return status;
  status = reply_context_current(bound.peer, bound.rx_context_id);
  if (!status) return status;
  return send(bound.peer, tx_token, frame);
}

Status EspNowRuntime::reply_snapshot_binding(const NodeId peer,
                                                 ReplyBinding& out) noexcept {
  out = ReplyBinding{};
  ReplyCallGuard guard(reply_call_active_);
  if (!guard.entered()) return Status::error(StatusCode::Busy, "reentrant reply call");
  if (reply_mapping(peer, out)) {
    return Status::success();
  }
  // Unknown, unbound, driverless or release-pending: an ACK-awaiting TX
  // to this peer must not pin a binding it cannot hold.
  return Status::error(StatusCode::Conflict, "no live binding for peer");
}

Status EspNowRuntime::reply_send_bound(const ReplyBinding binding,
                                          const std::uint64_t tx_token,
                                          const ByteView frame) noexcept {
  ReplyCallGuard guard(reply_call_active_);
  if (!guard.entered()) return Status::error(StatusCode::Busy, "reentrant reply call");
  ReplyBinding live{};
  if (!reply_mapping(binding.peer, live) || live != binding) {
    return Status::error(StatusCode::Conflict, "binding mapping changed");
  }
  return send(binding.peer, tx_token, frame);
}

Status EspNowRuntime::send(const NodeId peer, const std::uint64_t token,
                           const ByteView frame) noexcept {
  if (channel_runner_.busy()) {
    // A serialized channel operation owns the radio: DATA submissions wait
    // rather than transmit against a stale configuration (04 §8).
    return Status::error(StatusCode::WouldBlock, "RADIO_OP_IN_PROGRESS");
  }
  // Resolve under callback_lock_: peer-table fields can be rewritten by the
  // poll task's lease sync while this call runs on the bridge task.
  MacAddress peer_mac{};
  bool driver_registered = false;
  portENTER_CRITICAL(&callback_lock_);
  if (peer == kBroadcastNodeId) {
    // Route broadcasts use the permanent ESP-NOW peer, but still reserve the
    // same physical TX slot and callback fence as ordinary node traffic.
    peer_mac.bytes = discovery_const::kBroadcastMac;
    driver_registered = broadcast_peer_;
  } else if (const Peer* record = find_peer(peer)) {
    peer_mac = record->mac;
    driver_registered = record->driver_registered;
  }
  portEXIT_CRITICAL(&callback_lock_);
  if (!driver_registered) {
    return Status::error(StatusCode::NotFound,
                         "peer is not registered");
  }
  if (frame.data == nullptr || frame.size == 0 ||
      frame.size > ESP_NOW_MAX_DATA_LEN) {
    return Status::error(StatusCode::InvalidArgument,
                         "invalid ESP-NOW frame");
  }
  const MonotonicMs now = now_ms();
  portENTER_CRITICAL(&callback_lock_);
  if (pending_tx_) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock,
                         "physical TX already in flight");
  }
  {
    // A raw autonomy send to this MAC may still owe a callback that would
    // otherwise satisfy this reservation — refuse until it retires.
    bool raw_outstanding = false;
    std::size_t kept = 0;
    for (std::size_t i = 0; i < raw_tx_count_; ++i) {
      if (now - raw_tx_[i].sent_ms < config_.node.callback_watchdog_ms) {
        raw_outstanding |= raw_tx_[i].mac == peer_mac;
        raw_tx_[kept++] = raw_tx_[i];
        continue;
      }
      if (quarantined_count_ < quarantined_tx_.size()) {
        quarantined_tx_[quarantined_count_++] = raw_tx_[i];
        stage_quarantine_notice(raw_tx_[i].node);
        if (expired_tx_count_ < expired_tx_.size()) {
          expired_tx_[expired_tx_count_++] = raw_tx_[i];
        } else {
          ++telemetry_event_drops_;
        }
        continue;
      }
      // Quarantine full: keep it outstanding — its MAC stays blocked
      // rather than losing callback tracking (X-02).
      raw_outstanding |= raw_tx_[i].mac == peer_mac;
      raw_tx_[kept++] = raw_tx_[i];
    }
    raw_tx_count_ = kept;
    if (raw_outstanding) {
      portEXIT_CRITICAL(&callback_lock_);
      return Status::error(StatusCode::WouldBlock,
                           "autonomy TX in flight to peer");
    }
  }
  if (tx_quarantined(peer_mac)) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock,
                         "TX callback quarantine on peer");
  }
  // The fence releases only on the owed callback or driver recovery —
  // neither a timer nor a generation change establishes callback
  // quiescence (02 §2.3 / X-02). The MAC stays fenced until then and
  // recovery-required is visible via tx_fence_active().
  if (fenced_outstanding_ && fenced_mac_ == peer_mac) {
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::WouldBlock, "TX_FENCE_GUARD");
  }
  pending_tx_ = true;
  pending_token_ = token;
  pending_node_ = peer;
  pending_mac_ = peer_mac;
  pending_sent_ms_ = now;
  pending_generation_ = channel_runner_.radio_generation().value;
  // Submit-time observation record: the completion copies these verbatim so
  // attribution never re-reads live identity state (02 §2.2/X-02).
  pending_submitted_us_ = now_us();
  pending_length_class_ = frame_length_class(frame.size);
  pending_channel_epoch_ = channel_epoch_;
  pending_binding_ = BindingGeneration{0};
  if (const Peer* record = find_peer(peer)) {
    pending_binding_ = record->binding;
  }
  // Hand the frozen submit identity to the node so submission accounting
  // uses the SAME key the completion will carry (02 §2.3 — never a
  // re-guessed identity mid-attempt).
  const ObservationKey submit_key{pending_binding_,
                                  ObservationDirection::Egress,
                                  RadioGeneration{pending_generation_},
                                  pending_channel_epoch_,
                                  pending_length_class_, peer};
  portEXIT_CRITICAL(&callback_lock_);
  // Broadcast completion only confirms driver submission, not reception by
  // any particular neighbor. Never seed per-peer telemetry with this key.
  if (peer != kBroadcastNodeId) node_.note_tx_submit_identity(token, submit_key);
  const esp_err_t error =
      esp_now_send(peer_mac.bytes.data(), frame.data, frame.size);
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
  if (discovery_ == nullptr && bootstrap_sink_ == nullptr) {
    return Status::error(StatusCode::InvalidState,
                         "no bootstrap owner attached");
  }
  if (channel_runner_.busy()) {
    // A serialized channel operation owns the radio (04 §3/§8): RLD1
    // bootstrap frames hold rather than emit onto the survey/visit channel.
    return Status::error(StatusCode::WouldBlock, "RADIO_OP_IN_PROGRESS");
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
  if (channel_runner_.busy() && !channel_runner_.visiting()) {
    // The authenticated home lane holds while the Owner runs a serialized
    // channel operation (04 §3/§8) — except inside the off-channel dwell,
    // where authenticated probe traffic IS the stranded-node recovery lane
    // the visit exists to reach (04 §9.2). Only the allowlist below rides
    // it, so nothing else can slip onto the visit channel.
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
  Peer* record = find_peer(mac.bytes.data());
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
  } else if (!record->driver_registered) {
    // A kept resolvable marker (Stale/Suspended) re-arms its driver
    // registration on demand — releasing it never deleted the mapping.
    const Status status = register_driver_peer(*record);
    if (!status) {
      return status;
    }
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
                                      const MonotonicMs now_ms,
                                      const MonotonicMs captured_ms) noexcept {
  // Migration control payloads route to the attached migration sink; the
  // MeshNode admission gate (open_link + identity checks) already ran, and
  // the sink re-validates semantics (authority signature, phase) itself.
  switch (type) {
    case FrameType::TimeSync:
    case FrameType::ChannelNotice:
    case FrameType::ControlObject:
    case FrameType::ObjectChunk:
    case FrameType::ObjectAck:
      if (migration_ != nullptr) {
        migration_->on_migration_frame(peer, type, payload, now_ms,
                                       captured_ms);
      }
      return;
    default:
      break;
  }
  if (discovery_ == nullptr) {
    return;
  }
  // Feed the engine the MAC the frame was observed from (captured at enqueue)
  // — never a peer-table re-resolution that could lag a lease remap.
  discovery_->on_wire_rx(rx_source_, type, payload, now_ms);
}

void EspNowRuntime::note_link_activity(const NodeId peer,
                                       const MonotonicMs now_ms) noexcept {
  // VERIFY closes on new-channel evidence only. While the runner owns ANY
  // radio operation the channel context is not the settled home channel —
  // a visit parks on a foreign channel, and a queued frame observed
  // mid-cutover drain/fence is stale old-channel traffic. Neither may
  // satisfy the oracle.
  if (migration_ == nullptr || channel_runner_.busy()) {
    return;
  }
  migration_->note_link_activity(peer, now_ms);
}

// --- Migration transport (04 §5-§9) ------------------------------------------------

Status EspNowRuntime::attach_migration(MigrationFrameSink& sink) noexcept {
  if (migration_ != nullptr) {
    return Status::error(StatusCode::InvalidState,
                         "migration already attached");
  }
  // Helper old-channel visits dwell up to the committed 800ms (04 §9.2) —
  // beyond the 200ms survey cap. The runner's hard cap is the failsafe;
  // survey leases still enforce their own bound at the coordinator.
  const Status status =
      channel_runner_.set_visit_hard_cap(migration_const::kHelperDwellMs);
  if (!status) return status;
  migration_ = &sink;
  return Status::success();
}

Status EspNowRuntime::migration_send(const NodeId peer, const FrameType type,
                                     const ByteView payload) noexcept {
  if (migration_ == nullptr) {
    return Status::error(StatusCode::InvalidState,
                         "migration not attached");
  }
  // The serialized channel operation owns the radio — except inside the
  // off-channel dwell, where migration control is the visit's purpose.
  if (channel_runner_.busy() && !channel_runner_.visiting()) {
    return Status::error(StatusCode::WouldBlock, "RADIO_OP_IN_PROGRESS");
  }
  switch (type) {
    case FrameType::TimeSync:
    case FrameType::ChannelNotice:
    case FrameType::ControlObject:
    case FrameType::ObjectChunk:
    case FrameType::ObjectAck:
      break;  // explicit allowlist — no other type rides this lane
    default:
      return Status::error(StatusCode::InvalidArgument,
                           "type not allowed on the migration lane");
  }
  Peer* record = find_peer(peer);
  if (record == nullptr) {
    return Status::error(StatusCode::NotFound,
                         "peer is not driver-registered");
  }
  if (record->autonomy) {
    // Discovery-managed peers additionally need a verified Bound/Reachable
    // record — a stale driver peer never silently carries plan material.
    NeighborPhase phase{};
    if (discovery_ == nullptr ||
        !discovery_->phase_of(peer, phase) ||
        (phase != NeighborPhase::Bound &&
         phase != NeighborPhase::Reachable)) {
      return Status::error(StatusCode::AuthorizationFailed,
                           "peer binding not current");
    }
  }
  if (!record->driver_registered) {
    // Kept resolvable markers re-arm on demand (04 §9.2).
    const Status status = register_driver_peer(*record);
    if (!status) {
      return status;
    }
  }
  wire::PlainFrame frame{};
  frame.header.type = type;
  frame.header.delivery = DeliveryClass::BestEffort;
  frame.header.hop_remaining = 1;
  frame.header.network = config_.node.network;
  frame.header.origin = config_.node.node;
  frame.header.destination = peer;
  frame.header.previous_hop = config_.node.node;
  frame.header.next_hop = peer;
  frame.header.message =
      MessageId{config_.node.message_session, ++autonomy_sequence_};
  frame.header.remaining_deadline_ms = kAutonomyWireLifetimeMs;
  frame.header.original_lifetime_ms = kAutonomyWireLifetimeMs;
  frame.header.link_epoch = config_.node.link_epoch;
  frame.header.end_epoch = config_.node.end_epoch;
  if (payload.size > frame.payload.size()) {
    return Status::error(StatusCode::NoCapacity,
                         "migration payload exceeds wire budget");
  }
  if (payload.size > 0) {
    std::memcpy(frame.payload.data(), payload.data, payload.size);
  }
  frame.payload_size = payload.size;
  wire::EncodedFrame encoded{};
  const Status status = wire::encode_new(frame, security_, encoded);
  if (!status) {
    return status;
  }
  return send_raw(record->mac, encoded.view());
}

std::size_t EspNowRuntime::migration_peers(NodeId* out,
                                           const std::size_t capacity)
    const noexcept {
  std::size_t count = 0;
  for (const auto& peer : peers_) {
    if (count >= capacity) break;
    if (!peer.used) continue;
    if (peer.autonomy) {
      // Discovery-managed peers qualify by verified phase alone: a kept
      // marker may be driverless while resolvable — migration_send re-arms
      // the driver registration when the plan actually transmits.
      NeighborPhase phase{};
      if (discovery_ == nullptr ||
          !discovery_->phase_of(peer.node, phase) ||
          (phase != NeighborPhase::Bound &&
           phase != NeighborPhase::Reachable)) {
        continue;
      }
    } else if (!peer.driver_registered) {
      continue;  // static peers still need the driver record itself
    }
    out[count++] = peer.node;
  }
  return count;
}

// --- Peer lease sync (02 §7, contracts peer_partition) ---------------------------

// Caller holds callback_lock_. A driverless resolvable marker (autonomy
// slot kept for a Stale/Suspended record) is the only evictable regular
// peer: its verified mapping is provably idle, and freeing it is how the
// partition recovers slots for fresh bindings. Bound/Reachable records and
// static peers are never victims.
bool EspNowRuntime::evict_driverless_marker() noexcept {
  for (auto& candidate : peers_) {
    if (!candidate.used || !candidate.autonomy ||
        candidate.driver_registered) {
      continue;
    }
    NeighborPhase phase{};
    if (discovery_ == nullptr ||
        !discovery_->phase_of(candidate.node, phase) ||
        (phase != NeighborPhase::Stale &&
         phase != NeighborPhase::Suspended)) {
      continue;
    }
    candidate.used = false;
    candidate.autonomy = false;
    candidate.node = kInvalidNodeId;
    return true;
  }
  return false;
}

Status EspNowRuntime::promote_to_regular(const NodeId node,
                                         const MacAddress& mac) noexcept {
  portENTER_CRITICAL(&callback_lock_);
  Peer* record = find_peer(node);
  if (record == nullptr) {
    record = find_peer(mac.bytes.data());
  }
  if (record != nullptr) {
    const bool mismatch = record->node != node || !(record->mac == mac);
    if (!mismatch) {
      BindingId current{kInvalidBindingId};
      BindingGeneration generation{0};
      if (record->autonomy && record->binding_id != kInvalidBindingId &&
          discovery_ != nullptr &&
          discovery_->binding_of(node, current) &&
          discovery_->binding_generation_of(node, generation) &&
          (record->binding_id != current || record->binding != generation)) {
        portEXIT_CRITICAL(&callback_lock_);
        return Status::error(StatusCode::Conflict,
                             "prior binding still draining");
      }
      if (record->binding_retired) {
        portEXIT_CRITICAL(&callback_lock_);
        return Status::error(StatusCode::Conflict,
                             "prior binding still draining");
      }
      const bool registered = record->driver_registered;
      portEXIT_CRITICAL(&callback_lock_);
      // An existing (e.g. statically configured) mapping stays
      // owner-managed; it satisfies the lease but is never auto-released.
      if (!registered) {
        const Status status = register_driver_peer(*record);
        if (!status) {
          return status;
        }
      }
      // A transient slot may still pin this MAC: the driver registration
      // moved to this record, so release its bookkeeping or the duplicate
      // pin never frees.
      portENTER_CRITICAL(&callback_lock_);
      if (TransientPeer* slot = find_transient(mac.bytes.data())) {
        slot->used = false;
      }
      portEXIT_CRITICAL(&callback_lock_);
      return Status::success();
    }
    // The mapping moved: this driverless resolvable marker is superseded
    // by a newer binding on the same node or MAC, so evict it and take the
    // fresh path below — otherwise the stale slot blocks the new mapping
    // forever. A registered or non-resolvable record still conflicts.
    NeighborPhase phase{};
    const bool superseded =
        record->autonomy && !record->driver_registered &&
        discovery_ != nullptr &&
        discovery_->phase_of(record->node, phase) &&
        (phase == NeighborPhase::Stale ||
         phase == NeighborPhase::Suspended);
    if (!superseded) {
      portEXIT_CRITICAL(&callback_lock_);
      return Status::error(StatusCode::Conflict,
                           "peer identity mismatch");
    }
    record->used = false;
    record->autonomy = false;
    record->node = kInvalidNodeId;
    record = nullptr;
  }
  if (regular_used() >= regular_budget()) {
    // Full partition: a driverless marker is the only thing that may make
    // room — a Bound/Reachable peer is never evicted for capacity.
    (void)evict_driverless_marker();
  }
  if (regular_used() >= regular_budget()) {
    portEXIT_CRITICAL(&callback_lock_);
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
    portEXIT_CRITICAL(&callback_lock_);
    return Status::error(StatusCode::PeerCapacity, "peer mapping full");
  }
  record->used = true;
  record->node = node;
  record->mac = mac;
  record->metric = 1;
  record->autonomy = true;
  record->neighbor_added = false;
  record->driver_registered = false;
  // Fresh lease identity: the mirror loop resolves the id from the engine
  // on the next sync; until then the mapping refuses (safe direction).
  record->binding_id = kInvalidBindingId;
  record->rx_context_id = 0;
  record->release_pending = false;
  record->binding_retired = false;
  if (TransientPeer* slot = find_transient(mac.bytes.data())) {
    // The transient slot's driver registration moves to the regular peer;
    // only the bookkeeping is released.
    slot->used = false;
    record->driver_registered = true;
    portEXIT_CRITICAL(&callback_lock_);
    return Status::success();
  }
  portEXIT_CRITICAL(&callback_lock_);
  const Status status = register_driver_peer(*record);
  if (!status) {
    portENTER_CRITICAL(&callback_lock_);
    record->used = false;
    record->autonomy = false;
    portEXIT_CRITICAL(&callback_lock_);
    return status;
  }
  return Status::success();
}

Status EspNowRuntime::release_driver_peer(const MacAddress& mac,
                                          const NodeId node,
                                          const bool transfer) noexcept {
  DriverReleaseEvidence evidence{};
  portENTER_CRITICAL(&callback_lock_);
  if (const Peer* peer = find_peer(mac.bytes.data())) {
    evidence.reply_uses_live =
        reply_leases_.holds_binding(peer->binding_id, peer->binding);
  }
  evidence.tx_in_flight = pending_tx_ && pending_mac_ == mac;
  bool raw_outstanding = false;
  for (std::size_t i = 0; i < raw_tx_count_; ++i) {
    raw_outstanding |= raw_tx_[i].mac == mac;
  }
  bool quarantined = false;
  for (std::size_t i = 0; i < quarantined_count_; ++i) {
    quarantined |= quarantined_tx_[i].mac == mac;
  }
  const bool fenced = fenced_outstanding_ && fenced_mac_ == mac;
  evidence.fence_or_quarantine = fenced || quarantined;
  evidence.other_lease_hold = raw_outstanding || channel_runner_.busy();
  evidence.topology_pin_live =
      node != kInvalidNodeId && discovery_ != nullptr &&
      discovery_->topology_pinned(node);
  evidence.callbacks_drained =
      !evidence.tx_in_flight && !raw_outstanding && !quarantined && !fenced;
  portEXIT_CRITICAL(&callback_lock_);
  if (!(transfer ? driver_transfer_allowed(evidence)
                 : driver_release_allowed(evidence))) {
    return Status::error(StatusCode::WouldBlock,
                         "driver peer still held");
  }
  if (transfer) return Status::success();
  const esp_err_t error = esp_now_del_peer(mac.bytes.data());
  if (error != ESP_OK && error != ESP_ERR_ESPNOW_NOT_FOUND) {
    observer_.on_diagnostic("PEER_DRIVER_RELEASE_FAILED", node, nullptr);
    return esp_status(error, StatusCode::RadioFailure,
                      "esp_now_del_peer failed");
  }
  return Status::success();
}

void EspNowRuntime::release_autonomy_peer(Peer& peer,
                                          const MonotonicMs now) noexcept {
  if (peer.neighbor_added) {
    // Stale/suspended/evicted peers leave the routing neighbor table;
    // re-confirmation requires a fresh exchange (02 §9).
    (void)node_.remove_neighbor(peer.node, now);
  }
  // The binding dies with the record: retire the lease entry so no new use
  // can start on it. Outstanding uses drain via release; while any is
  // live the slot and its driver registration stay and the next sync
  // retries — the physical deletion below needs a drained binding.
  (void)reply_leases_.invalidate_binding(peer.binding_id);
  const bool had_driver = peer.driver_registered;
  const MacAddress mac = peer.mac;
  const NodeId node = peer.node;
  NodeId successor_node = kInvalidNodeId;
  BindingId successor_id{kInvalidBindingId};
  BindingGeneration successor_generation{0};
  const bool same_mac_successor =
      discovery_ != nullptr &&
      discovery_->node_of(mac.bytes, successor_node) && successor_node == node &&
      discovery_->binding_of(node, successor_id) &&
      discovery_->binding_generation_of(node, successor_generation) &&
      (successor_id != peer.binding_id ||
       successor_generation != peer.binding);
  portENTER_CRITICAL(&callback_lock_);
  peer.neighbor_added = false;
  peer.binding_retired = true;
  peer.registration_failed = false;
  peer.release_pending = true;
  const bool transfer = same_mac_successor ||
                        find_transient(mac.bytes.data()) != nullptr;
  portEXIT_CRITICAL(&callback_lock_);
  if (had_driver && !release_driver_peer(mac, node, transfer)) {
    return;
  }
  portENTER_CRITICAL(&callback_lock_);
  if (same_mac_successor) {
    peer.binding_id = successor_id;
    peer.binding = successor_generation;
    peer.rx_context_id = 0;
    peer.release_pending = false;
    peer.binding_retired = false;
    if (TransientPeer* slot = find_transient(mac.bytes.data())) {
      slot->used = false;
    }
    portEXIT_CRITICAL(&callback_lock_);
    return;
  }
  peer.driver_registered = false;
  peer.used = false;
  peer.autonomy = false;
  peer.node = kInvalidNodeId;
  peer.binding_id = kInvalidBindingId;
  peer.rx_context_id = 0;
  peer.release_pending = false;
  peer.binding_retired = false;
  portEXIT_CRITICAL(&callback_lock_);
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
      if (release_driver_peer(slot.mac, kInvalidNodeId)) slot.used = false;
      continue;
    }
    switch (phase) {
      case NeighborPhase::Candidate:
      case NeighborPhase::Authenticating:
        break;  // in-flight exchange holds the transient slot
      case NeighborPhase::ApprovalPending:
      case NeighborPhase::Bound:
      case NeighborPhase::Reachable:
      case NeighborPhase::Stale:
      case NeighborPhase::Suspended: {
        // Resolvable records hold the lane: the transient registration
        // promotes under the verified mapping so bootstrap traffic keeps
        // working through a lease lapse (02 §9, 04 §9.2).
        NodeId node = kInvalidNodeId;
        if (discovery_->node_of(slot.mac.bytes, node) &&
            promote_to_regular(node, slot.mac).ok()) {
          // promote_to_regular released the slot bookkeeping on success.
          break;
        }
        // peers_ partition full: do not park a bound peer in the transient
        // budget — release it and let wire sends surface PEER_CAPACITY.
        if (release_driver_peer(slot.mac, node)) slot.used = false;
        break;
      }
      default:
        // Conflict/Revoked (or a record the engine dropped): dead records
        // keep no driver peer.
        if (release_driver_peer(slot.mac, kInvalidNodeId)) slot.used = false;
        break;
    }
  }
  // Mirror the verified binding generation onto every used peer slot —
  // telemetry attribution keys on it (02-telemetry §2.4); unresolved peers
  // keep generation 0, which reports honestly as "no binding epoch".
  for (auto& peer : peers_) {
    if (!peer.used || !peer.autonomy) {
      continue;
    }
    BindingGeneration generation{0};
    BindingId binding_id{kInvalidBindingId};
    if (discovery_->binding_generation_of(peer.node, generation) &&
        discovery_->binding_of(peer.node, binding_id)) {
      if (peer.binding_id != kInvalidBindingId &&
          (peer.binding_id != binding_id || peer.binding != generation)) {
        // Retire the old identity before publishing a new one. Its lease
        // uses and physical callbacks must drain against the old record.
        release_autonomy_peer(peer, now);
        continue;
      }
      peer.binding = generation;
      peer.binding_id = binding_id;
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
      // Cross-check the MAC: when the engine's binding for this node moved
      // to a different MAC, this stale (node, MAC) slot must be released —
      // keeping it would pin sends to the wrong address and block the new
      // mapping's promotion forever.
      NodeId bound = kInvalidNodeId;
      if (!discovery_->node_of(peer.mac.bytes, bound) ||
          bound != peer.node) {
        release_autonomy_peer(peer, now);
        continue;
      }
      // The engine confirms this (node, MAC) again: any deferred release
      // is cancelled — the slot is live, not a retiree.
      if (peer.release_pending && !peer.binding_retired) {
        portENTER_CRITICAL(&callback_lock_);
        peer.release_pending = false;
        portEXIT_CRITICAL(&callback_lock_);
      }
      if (peer.binding_retired) {
        release_autonomy_peer(peer, now);
        continue;
      }
      if (phase == NeighborPhase::Reachable && !peer.neighbor_added &&
          started_) {
        // REACHABLE is the only phase where policy-limited DATA may flow;
        // routing learns the link here (register_neighbor-equivalent).
        if (node_.add_neighbor(peer.node, peer.metric, now).ok()) {
          portENTER_CRITICAL(&callback_lock_);
          peer.neighbor_added = true;
          portEXIT_CRITICAL(&callback_lock_);
        }
      }
      continue;
    }
    if (known && resolvable_phase(phase)) {
      // Stale/Suspended (the resolvable phases left): the verified binding
      // still resolves, so keep the logical slot — enqueue_rx must keep
      // attributing this MAC's frames to the engine record or the
      // re-join lane dies for good (issue #40, 04 §9.2). Only the driver
      // registration and the routing-neighbor link are released; sends
      // re-arm the driver on demand.
      NodeId bound = kInvalidNodeId;
      if (!discovery_->node_of(peer.mac.bytes, bound) ||
          bound != peer.node) {
        // The engine's binding for this node moved to another MAC — this
        // slot pins sends to a dead address; release it entirely.
        release_autonomy_peer(peer, now);
        continue;
      }
      if (peer.neighbor_added) {
        (void)node_.remove_neighbor(peer.node, now);
      }
      const bool had_driver = peer.driver_registered;
      const MacAddress mac = peer.mac;
      const NodeId node = peer.node;
      if (had_driver && !release_driver_peer(mac, node)) {
        portENTER_CRITICAL(&callback_lock_);
        peer.neighbor_added = false;
        peer.release_pending = true;
        portEXIT_CRITICAL(&callback_lock_);
        continue;
      }
      portENTER_CRITICAL(&callback_lock_);
      peer.neighbor_added = false;
      peer.driver_registered = false;
      peer.release_pending = false;
      portEXIT_CRITICAL(&callback_lock_);
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
  portENTER_CRITICAL(&callback_lock_);
  for (auto& peer : peers_) {
    peer.driver_registered = false;
  }
  portEXIT_CRITICAL(&callback_lock_);
  broadcast_peer_ = false;
  return initialize_espnow();
}

Status EspNowRuntime::recover() noexcept {
  // Fence the dropped reservation: a late completion from the pre-recover
  // send may still arrive and must never satisfy a post-recover send to
  // the same MAC (X-02). The driver rebuild below re-registers peers but
  // cannot cancel an already-queued driver completion.
  portENTER_CRITICAL(&callback_lock_);
  if (pending_tx_) {
    fenced_mac_ = pending_mac_;
    fenced_outstanding_ = true;
    pending_tx_ = false;
    pending_token_ = 0;
  }
  portEXIT_CRITICAL(&callback_lock_);
  const Status status = rebuild_driver();
  if (status) {
    // rebuild_driver() is the tested callback-quiescence barrier
    // (02 §2.3): esp_now_deinit unregisters the send callback and tears
    // down driver state, so no pre-recovery completion can arrive after
    // this point — every quarantined/fenced MAC is released. Queued stale
    // events resolve by token/lane, never by MAC reuse.
    portENTER_CRITICAL(&callback_lock_);
    // Raw sends still in flight die with the driver: the owed callback can
    // never arrive after the rebuild, so retire each into expired_tx_ —
    // the same Unknown-evidence path the callback watchdog uses — rather
    // than dropping their resolution silently (02 §2.3/§2.5).
    for (std::size_t i = 0; i < raw_tx_count_; ++i) {
      if (expired_tx_count_ < expired_tx_.size()) {
        expired_tx_[expired_tx_count_++] = raw_tx_[i];
      } else {
        ++telemetry_event_drops_;
      }
    }
    quarantined_count_ = 0;
    fenced_outstanding_ = false;
    raw_tx_count_ = 0;
    portEXIT_CRITICAL(&callback_lock_);
  }
  return status;
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
    if (info->des_addr != nullptr) {
      std::memcpy(event.destination.data(), info->des_addr,
                  event.destination.size());
    }
    event.received_ms = now_ms();
    event.length = static_cast<std::uint16_t>(length);
    event.rssi_dbm = info->rx_ctrl != nullptr ? info->rx_ctrl->rssi : 0;
    event.channel =
        info->rx_ctrl != nullptr ? static_cast<std::uint8_t>(info->rx_ctrl->channel) : 0;
    portENTER_CRITICAL(&callback_lock_);
    event.radio_generation = channel_runner_.radio_generation().value;
    portEXIT_CRITICAL(&callback_lock_);
    std::memcpy(event.data.data(), data, event.length);
    // Only the generation read above needs callback_lock_; the queue send
    // runs outside it (same shape as the wire lane below and enqueue_tx)
    // — holding the WiFi-task critical section across queue internals
    // stretches it over every RLD1 frame.
    if (xQueueSend(bootstrap_queue_, &event, 0) != pdTRUE) {
      portENTER_CRITICAL(&callback_lock_);
      ++bootstrap_rx_dropped_;
      portEXIT_CRITICAL(&callback_lock_);
    }
    return;
  }
  // The peer table can be rewritten by the poll task's lease sync — resolve
  // and copy the (node, mac, binding) triple under the lock so the queued
  // event keeps the MAC the frame actually arrived from.
  NodeId peer_node = kInvalidNodeId;
  BindingGeneration peer_binding{0};
  BindingId peer_binding_id{kInvalidBindingId};
  portENTER_CRITICAL(&callback_lock_);
  if (const Peer* peer = find_peer(info->src_addr)) {
    peer_node = peer->node;
    peer_binding = peer->binding;
    peer_binding_id = peer->binding_id;
  } else {
    // Unknown-MAC non-RLD1 frames are dropped — counted so neighbouring
    // networks and peer churn are observable.
    ++unknown_peer_rx_;
  }
  const RadioGeneration radio_gen = channel_runner_.radio_generation();
  const ChannelEpoch channel_epoch = channel_epoch_;
  portEXIT_CRITICAL(&callback_lock_);
  if (peer_node == kInvalidNodeId) {
    return;
  }
  Event event{};
  event.kind = EventKind::Rx;
  event.peer = peer_node;
  event.binding = peer_binding;
  event.binding_id = peer_binding_id;
  event.radio_generation = radio_gen;
  event.channel_epoch = channel_epoch;
  std::memcpy(event.source.data(), info->src_addr, event.source.size());
  event.length = static_cast<std::uint16_t>(length);
  event.frame_length_class = frame_length_class(event.length);
  if (info->rx_ctrl != nullptr) {
    event.rssi_dbm = info->rx_ctrl->rssi;
    event.rssi_valid = true;
    event.channel = static_cast<std::uint8_t>(info->rx_ctrl->channel);
    event.channel_valid = info->rx_ctrl->channel > 0;
  }
  // rx_ctrl->timestamp runs on the Wi-Fi MAC's own 32-bit µs clock (epoch =
  // Wi-Fi init, wraps ~71.6 min) — a different time base than esp_timer, so
  // it must never feed deadline accounting against now_ms(). The esp_timer
  // enqueue stamp still bounds driver-queue dwell from above at ms
  // granularity, which is all the rx_age_ms_ debit requires, and is the
  // only stamp that can measure queue residence (TimeSync captured_ms).
  event.observed_us = now_us();
  std::memcpy(event.data.data(), data, event.length);
  if (xQueueSend(event_queue_, &event, 0) != pdTRUE) {
    // Queue-full drops are load evidence (05 §5), not silent loss.
    portENTER_CRITICAL(&callback_lock_);
    ++rx_dropped_;
    portEXIT_CRITICAL(&callback_lock_);
  }
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
  event.observed_us = now_us();
  portENTER_CRITICAL(&callback_lock_);
  const bool pending_match =
      pending_tx_ && std::memcmp(pending_mac_.bytes.data(), info->des_addr,
                                 pending_mac_.bytes.size()) == 0;
  if (pending_match &&
      pending_generation_ != channel_runner_.radio_generation().value) {
    // Completion for a pre-switch configuration: it cannot resolve the
    // newer send — accounted under its ORIGINAL generations as Unknown,
    // never as success or failure on the new identity (X-02).
    ++stale_tx_results_;
    event.tx_lane = TxLane::Stale;
    event.peer = pending_node_;
    event.success = status == ESP_NOW_SEND_SUCCESS;
    event.submitted_us = pending_submitted_us_;
    event.binding = pending_binding_;
    event.radio_generation = RadioGeneration{pending_generation_};
    event.channel_epoch = pending_channel_epoch_;
    event.frame_length_class = pending_length_class_;
    pending_tx_ = false;
    pending_token_ = 0;
    if (xQueueSend(event_queue_, &event, 0) != pdTRUE) {
      // A completed send must resolve exactly once: the observation is
      // staged for poll_once, never dropped into queue overflow (02 §2.5).
      stage_lost_tx(event);
    }
    portEXIT_CRITICAL(&callback_lock_);
    return;
  }
  if (!pending_match) {
    // A callback for a watchdog-retired (quarantined) MAC is the owed
    // straggler itself: consume the marker as stale evidence — it can never
    // resolve a replacement send that reused the destination (02 §2.3).
    for (std::size_t i = 0; i < quarantined_count_; ++i) {
      if (std::memcmp(quarantined_tx_[i].mac.bytes.data(), info->des_addr,
                      quarantined_tx_[i].mac.bytes.size()) == 0) {
        ++stale_tx_results_;
        quarantined_tx_[i] = quarantined_tx_[--quarantined_count_];
        portEXIT_CRITICAL(&callback_lock_);
        return;
      }
    }
    if (fenced_outstanding_ &&
        std::memcmp(fenced_mac_.bytes.data(), info->des_addr,
                    fenced_mac_.bytes.size()) == 0) {
      // The fenced straggler arrived late: Unknown evidence under its own
      // generations, never merged with a send that ran under the newer
      // configuration (X-02).
      ++stale_tx_results_;
      event.tx_lane = TxLane::Stale;
      event.peer = fenced_pending_.node;
      event.submitted_us = fenced_pending_.submitted_us;
      event.binding = fenced_pending_.binding;
      event.radio_generation = fenced_pending_.radio_generation;
      event.channel_epoch = fenced_pending_.channel_epoch;
      event.frame_length_class = fenced_pending_.length_class;
      fenced_outstanding_ = false;
      if (xQueueSend(event_queue_, &event, 0) != pdTRUE) {
        stage_lost_tx(event);
      }
      portEXIT_CRITICAL(&callback_lock_);
      return;
    }
    // Not the reserved node-TX completion: retire the tracked raw send for
    // this MAC (if any) and account it — never as the reserved slot.
    bool raw_found = false;
    for (std::size_t i = 0; i < raw_tx_count_; ++i) {
      if (std::memcmp(raw_tx_[i].mac.bytes.data(), info->des_addr,
                      raw_tx_[i].mac.bytes.size()) == 0) {
        event.tx_lane = TxLane::Raw;
        event.peer = raw_tx_[i].node;
        event.submitted_us = raw_tx_[i].submitted_us;
        event.binding = raw_tx_[i].binding;
        event.radio_generation = raw_tx_[i].radio_generation;
        event.channel_epoch = raw_tx_[i].channel_epoch;
        event.frame_length_class = raw_tx_[i].length_class;
        raw_tx_[i] = raw_tx_[--raw_tx_count_];
        raw_found = true;
        break;
      }
    }
    if (!raw_found) {
      // A callback for a send we already watchdog-retired or never tracked:
      // counted, never attributed to anything.
      ++stale_tx_results_;
      portEXIT_CRITICAL(&callback_lock_);
      return;
    }
    event.success = status == ESP_NOW_SEND_SUCCESS;
    if (status == ESP_NOW_SEND_SUCCESS) {
      ++autonomy_tx_ok_;
    } else {
      ++autonomy_tx_failed_;
    }
    portEXIT_CRITICAL(&callback_lock_);
    if (xQueueSend(event_queue_, &event, 0) != pdTRUE) {
      portENTER_CRITICAL(&callback_lock_);
      stage_lost_tx(event);
      portEXIT_CRITICAL(&callback_lock_);
    }
    return;
  }
  event.token = pending_token_;
  event.peer = pending_node_;
  event.success = status == ESP_NOW_SEND_SUCCESS;
  event.submitted_us = pending_submitted_us_;
  event.binding = pending_binding_;
  event.radio_generation = RadioGeneration{pending_generation_};
  event.channel_epoch = pending_channel_epoch_;
  event.frame_length_class = pending_length_class_;
  pending_tx_ = false;
  pending_token_ = 0;
  if (xQueueSend(event_queue_, &event, 0) != pdTRUE) {
    stage_lost_tx(event);
  }
  portEXIT_CRITICAL(&callback_lock_);
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
    fenced_pending_.mac = pending_mac_;
    fenced_pending_.node = pending_node_;
    fenced_pending_.sent_ms = pending_sent_ms_;
    fenced_pending_.submitted_us = pending_submitted_us_;
    fenced_pending_.binding = pending_binding_;
    fenced_pending_.radio_generation = RadioGeneration{pending_generation_};
    fenced_pending_.channel_epoch = pending_channel_epoch_;
    fenced_pending_.length_class = pending_length_class_;
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

bool EspNowRuntime::tx_quarantined(const MacAddress& mac) noexcept {
  // Quarantine release has exactly two paths (02 §2.3): the owed callback
  // arrives and consumes the entry in the TX callback handler, or driver
  // recovery (recover()->rebuild_driver()) establishes callback
  // quiescence. No timer and no software generation change can release an
  // entry — a callback that is still owed would resolve a replacement
  // send to this MAC with no way to tell it apart.
  for (std::size_t i = 0; i < quarantined_count_; ++i) {
    if (quarantined_tx_[i].mac == mac) return true;
  }
  return false;
}

void EspNowRuntime::stage_quarantine_notice(const NodeId node) noexcept {
  if (quarantine_notice_count_ < quarantine_notices_.size()) {
    quarantine_notices_[quarantine_notice_count_++] = node;
  } else {
    ++telemetry_event_drops_;
  }
}

void EspNowRuntime::stage_lost_tx(const Event& event) noexcept {
  // The reserved (node) completion gets a dedicated slot — it is the only
  // lane whose result resolves job state, and it can never be displaced by
  // raw-completions filling the shared staging array (02 §2.5).
  if (event.tx_lane == TxLane::Reserved) {
    if (!lost_node_tx_valid_) {
      lost_node_tx_ = event;
      lost_node_tx_valid_ = true;
    } else {
      ++telemetry_event_drops_;
    }
    return;
  }
  if (lost_tx_count_ < lost_tx_.size()) {
    lost_tx_[lost_tx_count_++] = event;
  } else {
    ++telemetry_event_drops_;
  }
}

void EspNowRuntime::channel_committed(const std::uint8_t channel) noexcept {
  // Only after readback-verified apply + peer re-apply: config_.channel is
  // never assigned alone (04 §8 forbids the bare assignment cutover).
  config_.channel = channel;
  // Telemetry attribution epoch: observations before and after this commit
  // must never merge (02-telemetry §2.4).
  portENTER_CRITICAL(&callback_lock_);
  ++channel_epoch_.value;
  portEXIT_CRITICAL(&callback_lock_);
}

void EspNowRuntime::note_diagnostic(const char* reason,
                                    const NodeId peer) noexcept {
  observer_.on_diagnostic(reason, peer, nullptr);
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
