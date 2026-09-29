// Test-only ESP-IDF/FreeRTOS implementations (issue #117 host regression
// test): success defaults, a fake clock, heap-backed FIFOs, and counting
// hooks for the driver calls under test.

#include <algorithm>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>

#include "driver/usb_serial_jtag.h"
#include "esp_app_desc.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_now.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/task.h"
#include "idf_stubs.hpp"
#include "nvs_flash.h"

namespace {

std::int64_t g_now_us = 0;
std::uint8_t g_channel = 6;
unsigned g_send_count = 0;
unsigned g_del_peer_count = 0;
bool g_fail_del_peer = false;
bool g_fail_add_peer = false;
constexpr std::size_t kPeerTableMax = 32;
std::uint8_t g_peer_macs[kPeerTableMax][6] = {};
std::size_t g_peer_count = 0;
std::size_t g_peer_limit = 0;
esp_now_send_cb_t g_send_cb = nullptr;
esp_now_recv_cb_t g_recv_cb = nullptr;
std::uint8_t g_last_dest[6] = {0};
std::uint8_t g_mac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
// Captured TX payloads (FIFO) plus the completion backlog. complete_send
// reports the oldest entry's destination, like the driver attributing a
// completion to (des_addr, status).
constexpr std::size_t kTxCaptureCapacity = 32;
idf_stub::TxFrame g_tx_queue[kTxCaptureCapacity];
std::size_t g_tx_head = 0;
std::size_t g_tx_count = 0;
// Completion destinations in esp_now_send order. take_tx drains the capture
// queue above while completions arrive later, so the destinations live in
// their own FIFO: without it every completion of a multi-TX tick would
// report the last destination and the runtime would leak the older MACs'
// in-flight tracking into the TX callback quarantine.
std::uint8_t g_completion_macs[kTxCaptureCapacity][6] = {};
std::size_t g_completion_head = 0;
std::size_t g_completion_count = 0;
std::uint8_t g_completion_mac[6] = {0};
unsigned g_send_outstanding = 0;
unsigned g_tx_overruns = 0;

void (*g_receive_hook)(void*) = nullptr;
void* g_receive_hook_context = nullptr;
unsigned g_last_peek_ticks = 0;
char g_logs[8192] = {};
std::size_t g_logs_size = 0;

struct FakeQueue {
  std::size_t item_size{0};
  std::size_t capacity{0};
  std::size_t count{0};
  std::size_t head{0};
  std::uint8_t* storage{nullptr};
};

}  // namespace

namespace idf_stub {

void reset() noexcept {
  static const std::uint8_t kDefaultMac[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
  g_now_us = 0;
  g_channel = 6;
  g_send_count = 0;
  g_del_peer_count = 0;
  g_fail_del_peer = false;
  g_fail_add_peer = false;
  g_peer_count = 0;
  g_peer_limit = 0;
  g_send_cb = nullptr;
  g_recv_cb = nullptr;
  std::memcpy(g_mac, kDefaultMac, sizeof(g_mac));
  g_tx_head = 0;
  g_tx_count = 0;
  g_completion_head = 0;
  g_completion_count = 0;
  std::memset(g_completion_mac, 0, sizeof(g_completion_mac));
  g_send_outstanding = 0;
  g_tx_overruns = 0;
  g_receive_hook = nullptr;
  g_receive_hook_context = nullptr;
  g_last_peek_ticks = 0;
  g_logs[0] = '\0';
  g_logs_size = 0;
}

void set_receive_hook(void (*hook)(void*), void* context) noexcept {
  g_receive_hook = hook;
  g_receive_hook_context = context;
}

unsigned last_peek_ticks() noexcept { return g_last_peek_ticks; }

void record_log(const char* tag, const char* format, ...) noexcept {
  (void)tag;
  if (format == nullptr || g_logs_size >= sizeof(g_logs) - 1) return;
  va_list args;
  va_start(args, format);
  const int written = std::vsnprintf(g_logs + g_logs_size,
                                     sizeof(g_logs) - g_logs_size, format, args);
  va_end(args);
  if (written < 0) return;
  g_logs_size += std::min(static_cast<std::size_t>(written),
                          sizeof(g_logs) - g_logs_size - 1);
  if (g_logs_size < sizeof(g_logs) - 1) g_logs[g_logs_size++] = '\n';
  g_logs[g_logs_size] = '\0';
}

bool log_contains(const char* text) noexcept {
  return text != nullptr && std::strstr(g_logs, text) != nullptr;
}

void set_now_us(const std::int64_t now_us) noexcept { g_now_us = now_us; }

void advance_ms(const std::uint32_t ms) noexcept {
  g_now_us += static_cast<std::int64_t>(ms) * 1000;
}

std::int64_t now_us() noexcept { return g_now_us; }
unsigned send_count() noexcept { return g_send_count; }
bool last_send_to(const std::uint8_t mac[6]) noexcept {
  return mac != nullptr && std::memcmp(mac, g_last_dest, sizeof(g_last_dest)) == 0;
}
unsigned del_peer_count() noexcept { return g_del_peer_count; }
void fail_del_peer(const bool fail) noexcept { g_fail_del_peer = fail; }
void fail_add_peer(const bool fail) noexcept { g_fail_add_peer = fail; }
void set_peer_limit(const std::size_t limit) noexcept { g_peer_limit = limit; }
std::size_t peer_count() noexcept { return g_peer_count; }

void set_mac(const std::uint8_t mac[6]) noexcept {
  if (mac != nullptr) std::memcpy(g_mac, mac, sizeof(g_mac));
}

bool inject_rx(const std::uint8_t source[6], const std::uint8_t dest[6],
               const std::uint8_t* frame, const std::size_t length) noexcept {
  if (g_recv_cb == nullptr || source == nullptr || dest == nullptr || frame == nullptr) {
    return false;
  }
  wifi_pkt_rx_ctrl_t ctrl{};
  ctrl.rssi = -45;
  ctrl.channel = g_channel;
  esp_now_recv_info_t info{};
  info.src_addr = const_cast<std::uint8_t*>(source);
  info.des_addr = const_cast<std::uint8_t*>(dest);
  info.rx_ctrl = &ctrl;
  g_recv_cb(&info, frame, static_cast<int>(length));
  return true;
}

bool inject_rx(const std::uint8_t source[6], const std::uint8_t* frame,
               const std::size_t length) noexcept {
  return inject_rx(source, g_mac, frame, length);
}

bool complete_send(const bool success) noexcept {
  if (g_send_outstanding == 0 || g_send_cb == nullptr) return false;
  --g_send_outstanding;
  esp_now_send_info_t info{};
  if (g_completion_count > 0) {
    std::memcpy(g_completion_mac, g_completion_macs[g_completion_head],
                sizeof(g_completion_mac));
    g_completion_head = (g_completion_head + 1) % kTxCaptureCapacity;
    --g_completion_count;
    info.des_addr = g_completion_mac;
  } else {
    info.des_addr = g_last_dest;
  }
  g_send_cb(&info, success ? ESP_NOW_SEND_SUCCESS : ESP_NOW_SEND_FAIL);
  return true;
}

bool take_tx(TxFrame& out) noexcept {
  if (g_tx_count == 0) return false;
  out = g_tx_queue[g_tx_head];
  g_tx_head = (g_tx_head + 1) % kTxCaptureCapacity;
  --g_tx_count;
  return true;
}

std::size_t tx_pending() noexcept { return g_tx_count; }

unsigned tx_overruns() noexcept { return g_tx_overruns; }

bool pop_tx(TxFrame& out) noexcept { return take_tx(out); }

unsigned tx_drops() noexcept { return tx_overruns(); }

}  // namespace idf_stub

int64_t esp_timer_get_time(void) { return g_now_us; }

std::uint32_t esp_log_timestamp(void) { return static_cast<std::uint32_t>(g_now_us / 1000); }

esp_err_t nvs_flash_init_partition(const char* partition) {
  return partition == nullptr ? ESP_FAIL : ESP_OK;
}

esp_err_t nvs_flash_deinit_partition(const char* partition) {
  return partition == nullptr ? ESP_FAIL : ESP_OK;
}

QueueHandle_t xQueueCreate(const UBaseType_t length,
                           const UBaseType_t item_size) {
  if (length == 0 || item_size == 0) return nullptr;
  FakeQueue* queue = new (std::nothrow) FakeQueue();
  if (queue == nullptr) return nullptr;
  queue->storage = static_cast<std::uint8_t*>(
      std::malloc(static_cast<std::size_t>(length) * item_size));
  if (queue->storage == nullptr) {
    delete queue;
    return nullptr;
  }
  queue->item_size = item_size;
  queue->capacity = length;
  return static_cast<QueueHandle_t>(queue);
}

BaseType_t xQueueSend(const QueueHandle_t handle, const void* item,
                      const TickType_t ticks) {
  (void)ticks;
  if (handle == nullptr || item == nullptr) return 0;
  FakeQueue* queue = static_cast<FakeQueue*>(handle);
  if (queue->count >= queue->capacity) return 0;
  const std::size_t slot =
      (queue->head + queue->count) % queue->capacity;
  std::memcpy(queue->storage + slot * queue->item_size, item,
              queue->item_size);
  ++queue->count;
  return pdTRUE;
}

BaseType_t xQueueReceive(const QueueHandle_t handle, void* item,
                         const TickType_t ticks) {
  (void)ticks;
  if (handle == nullptr || item == nullptr) return 0;
  FakeQueue* queue = static_cast<FakeQueue*>(handle);
  if (queue->count == 0) return 0;
  std::memcpy(item, queue->storage + queue->head * queue->item_size,
              queue->item_size);
  queue->head = (queue->head + 1) % queue->capacity;
  --queue->count;
  if (g_receive_hook != nullptr) g_receive_hook(g_receive_hook_context);
  return pdTRUE;
}

BaseType_t xQueuePeek(const QueueHandle_t handle, void* item,
                      const TickType_t ticks) {
  g_last_peek_ticks = ticks;
  if (handle == nullptr || item == nullptr) return 0;
  const FakeQueue* queue = static_cast<const FakeQueue*>(handle);
  if (queue->count == 0) return 0;
  std::memcpy(item, queue->storage + queue->head * queue->item_size,
              queue->item_size);
  return pdTRUE;
}

UBaseType_t uxQueueMessagesWaiting(const QueueHandle_t handle) {
  if (handle == nullptr) return 0;
  return static_cast<UBaseType_t>(static_cast<const FakeQueue*>(handle)->count);
}

void vQueueDelete(const QueueHandle_t handle) {
  if (handle == nullptr) return;
  FakeQueue* queue = static_cast<FakeQueue*>(handle);
  std::free(queue->storage);
  delete queue;
}

BaseType_t xTaskCreatePinnedToCore(const TaskFunction_t fn, const char* name,
                                   const uint32_t stack_depth, void* param,
                                   const UBaseType_t prio,
                                   TaskHandle_t* handle,
                                   const BaseType_t core) {
  (void)fn;
  (void)name;
  (void)stack_depth;
  (void)param;
  (void)prio;
  (void)handle;
  (void)core;
  return pdPASS;
}

BaseType_t xTaskCreate(const TaskFunction_t fn, const char* name,
                       const uint32_t stack_depth, void* param,
                       const UBaseType_t prio, TaskHandle_t* handle) {
  (void)fn;
  (void)name;
  (void)stack_depth;
  (void)param;
  (void)prio;
  (void)handle;
  return pdPASS;
}

void vTaskSuspend(const TaskHandle_t task) { (void)task; }

const esp_app_desc_t* esp_app_get_description(void) { return nullptr; }

esp_err_t usb_serial_jtag_driver_install(usb_serial_jtag_driver_config_t* config) {
  (void)config;
  return ESP_OK;
}

int usb_serial_jtag_write_bytes(const void* data, const unsigned length,
                                const unsigned timeout) {
  (void)data;
  (void)timeout;
  return static_cast<int>(length);
}

int usb_serial_jtag_read_bytes(void* data, const unsigned length,
                               const unsigned timeout) {
  (void)data;
  (void)length;
  (void)timeout;
  return 0;
}

TaskHandle_t xTaskGetCurrentTaskHandle(void) {
  return reinterpret_cast<TaskHandle_t>(0x1);
}

void vTaskDelay(const TickType_t ticks) { (void)ticks; }
void vTaskDelete(const TaskHandle_t task) { (void)task; }

uint32_t uxTaskGetStackHighWaterMark(const TaskHandle_t task) {
  (void)task;
  return 4096;
}

const char* pcTaskGetName(const TaskHandle_t task) {
  (void)task;
  return "stub";
}

esp_err_t esp_event_loop_create_default(void) { return ESP_OK; }
esp_err_t esp_netif_init(void) { return ESP_OK; }

esp_err_t esp_now_init(void) { return ESP_OK; }
esp_err_t esp_now_deinit(void) { return ESP_OK; }

esp_err_t esp_now_register_recv_cb(const esp_now_recv_cb_t cb) {
  g_recv_cb = cb;
  return ESP_OK;
}

esp_err_t esp_now_unregister_recv_cb(void) {
  g_recv_cb = nullptr;
  return ESP_OK;
}

esp_err_t esp_now_register_send_cb(const esp_now_send_cb_t cb) {
  g_send_cb = cb;
  return ESP_OK;
}

esp_err_t esp_now_unregister_send_cb(void) {
  g_send_cb = nullptr;
  return ESP_OK;
}

esp_err_t esp_now_add_peer(const esp_now_peer_info_t* peer) {
  if (g_fail_add_peer) return ESP_FAIL;
  if (g_peer_limit == 0) return ESP_OK;
  if (peer == nullptr) return ESP_FAIL;
  for (std::size_t i = 0; i < g_peer_count; ++i) {
    if (std::memcmp(g_peer_macs[i], peer->peer_addr, 6) == 0) return ESP_ERR_ESPNOW_EXIST;
  }
  if (g_peer_count >= g_peer_limit || g_peer_count >= kPeerTableMax) return ESP_ERR_ESPNOW_FULL;
  std::memcpy(g_peer_macs[g_peer_count++], peer->peer_addr, 6);
  return ESP_OK;
}

esp_err_t esp_now_del_peer(const uint8_t* peer_addr) {
  ++g_del_peer_count;
  if (g_fail_del_peer) return ESP_FAIL;
  if (g_peer_limit == 0) return ESP_OK;
  if (peer_addr == nullptr) return ESP_FAIL;
  for (std::size_t i = 0; i < g_peer_count; ++i) {
    if (std::memcmp(g_peer_macs[i], peer_addr, 6) == 0) {
      --g_peer_count;
      std::memcpy(g_peer_macs[i], g_peer_macs[g_peer_count], 6);
      return ESP_OK;
    }
  }
  return ESP_ERR_ESPNOW_NOT_FOUND;
}

esp_err_t esp_now_send(const uint8_t* peer_addr, const uint8_t* data,
                       const size_t len) {
  if (len > ESP_NOW_MAX_DATA_LEN) return ESP_FAIL;
  if (g_peer_limit != 0 && peer_addr != nullptr) {
    bool found = false;
    for (std::size_t i = 0; i < g_peer_count; ++i) {
      found |= std::memcmp(g_peer_macs[i], peer_addr, 6) == 0;
    }
    if (!found) return ESP_ERR_ESPNOW_NOT_FOUND;
  }
  if (peer_addr != nullptr) {
    std::memcpy(g_last_dest, peer_addr, sizeof(g_last_dest));
  }
  if (data == nullptr && len != 0) return ESP_FAIL;
  if (g_tx_count < kTxCaptureCapacity) {
    idf_stub::TxFrame& slot = g_tx_queue[(g_tx_head + g_tx_count) % kTxCaptureCapacity];
    std::memcpy(slot.dest, g_last_dest, sizeof(slot.dest));
    if (len != 0) std::memcpy(slot.bytes, data, len);
    slot.length = len;
    ++g_tx_count;
  } else {
    ++g_tx_overruns;
  }
  if (g_completion_count < kTxCaptureCapacity) {
    std::memcpy(g_completion_macs[(g_completion_head + g_completion_count) %
                                  kTxCaptureCapacity],
                g_last_dest, sizeof(g_completion_macs[0]));
    ++g_completion_count;
  } else {
    ++g_tx_overruns;
  }
  ++g_send_outstanding;
  ++g_send_count;
  return ESP_OK;
}

esp_err_t esp_now_set_peer_rate_config(const uint8_t* peer_addr,
                                       esp_now_rate_config_t* config) {
  (void)peer_addr;
  (void)config;
  return ESP_OK;
}

esp_err_t esp_wifi_init(const wifi_init_config_t* config) {
  (void)config;
  return ESP_OK;
}

esp_err_t esp_wifi_deinit(void) { return ESP_OK; }

esp_err_t esp_wifi_set_storage(const wifi_storage_t storage) {
  (void)storage;
  return ESP_OK;
}

esp_err_t esp_wifi_set_mode(const wifi_mode_t mode) {
  (void)mode;
  return ESP_OK;
}

esp_err_t esp_wifi_set_country(const wifi_country_t* country) {
  (void)country;
  return ESP_OK;
}

esp_err_t esp_wifi_set_protocol(const wifi_interface_t ifx,
                                const uint8_t protocol_bitmap) {
  (void)ifx;
  (void)protocol_bitmap;
  return ESP_OK;
}

esp_err_t esp_wifi_set_bandwidth(const wifi_interface_t ifx,
                                 const wifi_bandwidth_t bw) {
  (void)ifx;
  (void)bw;
  return ESP_OK;
}

esp_err_t esp_wifi_start(void) { return ESP_OK; }
esp_err_t esp_wifi_stop(void) { return ESP_OK; }

esp_err_t esp_wifi_set_channel(const uint8_t primary,
                               const wifi_second_chan_t second) {
  (void)second;
  g_channel = primary;
  return ESP_OK;
}

esp_err_t esp_wifi_get_channel(uint8_t* primary,
                               wifi_second_chan_t* second) {
  if (primary != nullptr) *primary = g_channel;
  if (second != nullptr) *second = WIFI_SECOND_CHAN_NONE;
  return ESP_OK;
}

esp_err_t esp_wifi_get_mac(const wifi_interface_t ifx, uint8_t mac[6]) {
  (void)ifx;
  if (mac == nullptr) return ESP_FAIL;
  std::memcpy(mac, g_mac, sizeof(g_mac));
  return ESP_OK;
}

esp_err_t esp_read_mac(uint8_t mac[6], const esp_mac_type_t type) {
  if (mac == nullptr || type != ESP_MAC_WIFI_STA) return ESP_FAIL;
  std::memcpy(mac, g_mac, sizeof(g_mac));
  return ESP_OK;
}

esp_err_t esp_wifi_set_max_tx_power(const int8_t power) {
  (void)power;
  return ESP_OK;
}
