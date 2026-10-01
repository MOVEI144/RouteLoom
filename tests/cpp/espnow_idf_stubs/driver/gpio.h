#pragma once

#include <cstdint>
#include "esp_err.h"

enum gpio_num_t { GPIO_NUM_3 = 3, GPIO_NUM_14 = 14 };
enum gpio_mode_t { GPIO_MODE_OUTPUT = 2 };
esp_err_t gpio_set_direction(gpio_num_t gpio, gpio_mode_t mode);
esp_err_t gpio_set_level(gpio_num_t gpio, std::uint32_t level);
