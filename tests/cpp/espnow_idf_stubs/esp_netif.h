// Test-only ESP-IDF stand-in (issue #117 host regression test).
#pragma once

#include "esp_err.h"

esp_err_t esp_netif_init(void);
