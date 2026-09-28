#pragma once

#include <cstdint>

#include "esp_err.h"

struct esp_flash_t {
  std::uint32_t size;  // configured size, as in IDF
};
extern esp_flash_t* esp_flash_default_chip;
const char* esp_err_to_name(esp_err_t);
