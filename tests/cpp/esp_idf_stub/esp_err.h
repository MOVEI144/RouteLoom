// Test-only ESP-IDF stand-in: the real esp_err.h provides esp_err_t and
// ESP_OK, which this stub directory already declares in nvs.h. Forward so
// translation units including both keep one definition.
#pragma once

#include "nvs.h"
