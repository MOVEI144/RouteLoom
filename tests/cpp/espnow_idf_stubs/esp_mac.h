// Test-only MAC identity surface used by the linked firmware entry point.
#pragma once

#include <stdint.h>

#include "esp_err.h"

typedef enum { ESP_MAC_WIFI_STA = 0 } esp_mac_type_t;

esp_err_t esp_read_mac(uint8_t mac[6], esp_mac_type_t type);
