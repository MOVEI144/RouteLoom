#pragma once
#include <stdint.h>
#include "esp_err.h"
enum esp_sleep_gpio_wake_up_mode_t { ESP_GPIO_WAKEUP_GPIO_HIGH = 1 };
esp_err_t esp_sleep_enable_timer_wakeup(uint64_t time_us);
esp_err_t esp_sleep_enable_gpio_wakeup_on_hp_periph_powerdown(uint64_t mask,
                                                              esp_sleep_gpio_wake_up_mode_t mode);
void esp_deep_sleep_start();
