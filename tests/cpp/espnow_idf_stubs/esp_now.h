// Test-only ESP-IDF stand-in (issue #117 host regression test): the ESP-NOW
// API surface the real runtime calls. Implementations live in idf_stubs.cpp
// (success defaults, controllable time, counting send/del_peer hooks).
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "esp_err.h"
#include "esp_wifi_types.h"

#define ESP_NOW_MAX_DATA_LEN 250

typedef enum { ESP_NOW_SEND_SUCCESS = 0, ESP_NOW_SEND_FAIL = 1 } esp_now_send_status_t;

typedef struct {
  uint8_t *src_addr;
  uint8_t *des_addr;
  wifi_pkt_rx_ctrl_t *rx_ctrl;
} esp_now_recv_info_t;

typedef struct {
  uint8_t *des_addr;
} esp_now_send_info_t;

typedef struct {
  uint8_t peer_addr[6];
  uint8_t channel;
  int ifidx;
  bool encrypt;
} esp_now_peer_info_t;

typedef struct {
  int phymode;
  int rate;
  bool ersu;
  bool dcm;
} esp_now_rate_config_t;

typedef void (*esp_now_recv_cb_t)(const esp_now_recv_info_t *, const uint8_t *,
                                  int);
typedef void (*esp_now_send_cb_t)(const esp_now_send_info_t *,
                                  esp_now_send_status_t);

esp_err_t esp_now_init(void);
esp_err_t esp_now_deinit(void);
esp_err_t esp_now_register_recv_cb(esp_now_recv_cb_t cb);
esp_err_t esp_now_unregister_recv_cb(void);
esp_err_t esp_now_register_send_cb(esp_now_send_cb_t cb);
esp_err_t esp_now_unregister_send_cb(void);
esp_err_t esp_now_add_peer(const esp_now_peer_info_t *peer);
esp_err_t esp_now_del_peer(const uint8_t *peer_addr);
esp_err_t esp_now_send(const uint8_t *peer_addr, const uint8_t *data,
                       size_t len);
esp_err_t esp_now_set_peer_rate_config(const uint8_t *peer_addr,
                                       esp_now_rate_config_t *config);
