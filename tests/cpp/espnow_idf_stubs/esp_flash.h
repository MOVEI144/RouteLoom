#pragma once

#include <cstdint>

#include "esp_err.h"

struct esp_flash_t {};
extern esp_flash_t* esp_flash_default_chip;
esp_err_t esp_flash_get_physical_size(esp_flash_t*, std::uint32_t*);
const char* esp_err_to_name(esp_err_t);
