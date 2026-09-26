// Test-only ESP-IDF stand-in: NVS flash-init declarations. The host fake
// NVS (defined per test binary) is always mounted, so these are never
// called — declared only to satisfy the quoted include.
#pragma once

#include "esp_err.h"

esp_err_t nvs_flash_init_partition(const char* partition);
esp_err_t nvs_flash_deinit_partition(const char* partition);
