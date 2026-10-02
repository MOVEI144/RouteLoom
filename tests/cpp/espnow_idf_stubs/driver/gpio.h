#pragma once

#include <cstdint>
#include "esp_err.h"

enum gpio_num_t { GPIO_NUM_3 = 3, GPIO_NUM_14 = 14 };
esp_err_t gpio_output_enable(gpio_num_t gpio);
esp_err_t gpio_set_level(gpio_num_t gpio, std::uint32_t level);
