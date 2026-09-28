#pragma once

#include "esp_err.h"
#include "esp_partition.h"

enum esp_ota_img_states_t { ESP_OTA_IMG_VALID, ESP_OTA_IMG_PENDING_VERIFY };
const esp_partition_t* esp_ota_get_running_partition();
esp_err_t esp_ota_get_state_partition(const esp_partition_t*, esp_ota_img_states_t*);
esp_err_t esp_ota_mark_app_valid_cancel_rollback();
