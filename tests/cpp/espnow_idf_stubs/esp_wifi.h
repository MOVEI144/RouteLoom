// Test-only ESP-IDF stand-in (issue #117 host regression test): the Wi-Fi API
// surface the real runtime calls. Implementations live in idf_stubs.cpp.
#pragma once

#include <stdint.h>

#include "esp_err.h"

typedef enum { WIFI_IF_STA = 0, WIFI_IF_AP = 1 } wifi_interface_t;
typedef enum { WIFI_MODE_STA = 1 } wifi_mode_t;
typedef enum { WIFI_STORAGE_RAM = 0 } wifi_storage_t;
typedef enum { WIFI_BW20 = 1 } wifi_bandwidth_t;
typedef enum { WIFI_SECOND_CHAN_NONE = 0 } wifi_second_chan_t;
typedef enum { WIFI_COUNTRY_POLICY_MANUAL = 1 } wifi_country_policy_t;

#define WIFI_PROTOCOL_11B 1
#define WIFI_PROTOCOL_11G 2
#define WIFI_PROTOCOL_11N 4
#define WIFI_PROTOCOL_LR 8
#define WIFI_PHY_MODE_LR 3
#define WIFI_PHY_RATE_LORA_250K 1

typedef struct {
  char cc[3];
  uint8_t schan;
  uint8_t nchan;
  int8_t max_tx_power;
  wifi_country_policy_t policy;
} wifi_country_t;

typedef struct {
  int dummy;
} wifi_init_config_t;
#define WIFI_INIT_CONFIG_DEFAULT() wifi_init_config_t()

esp_err_t esp_wifi_init(const wifi_init_config_t *config);
esp_err_t esp_wifi_deinit(void);
esp_err_t esp_wifi_set_storage(wifi_storage_t storage);
esp_err_t esp_wifi_set_mode(wifi_mode_t mode);
esp_err_t esp_wifi_set_country(const wifi_country_t *country);
esp_err_t esp_wifi_set_protocol(wifi_interface_t ifx, uint8_t protocol_bitmap);
esp_err_t esp_wifi_set_bandwidth(wifi_interface_t ifx, wifi_bandwidth_t bw);
esp_err_t esp_wifi_start(void);
esp_err_t esp_wifi_stop(void);
esp_err_t esp_wifi_set_channel(uint8_t primary, wifi_second_chan_t second);
esp_err_t esp_wifi_get_channel(uint8_t *primary, wifi_second_chan_t *second);
esp_err_t esp_wifi_get_mac(wifi_interface_t ifx, uint8_t mac[6]);
esp_err_t esp_wifi_set_max_tx_power(int8_t power);
