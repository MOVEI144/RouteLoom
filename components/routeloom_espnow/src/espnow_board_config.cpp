#include "routeloom/espnow_board_config.hpp"

#include "nvs_flash.h"
#include "sdkconfig.h"

#if CONFIG_IDF_TARGET_ESP32C6
#include "driver/gpio.h"
#include "esp_log.h"
#endif

#include "routeloom/sdkv1_blob_storage.hpp"

namespace routeloom::espnow {

BoardStores::BoardStores() noexcept
    : config_slots_(sdkv1::BlobRecordSlotStorage::board_config(config_ns_)),
      secrets_slots_(sdkv1::BlobRecordSlotStorage::board_secrets(secrets_ns_)),
      config_(config_slots_),
      secrets_(secrets_slots_) {}

Status BoardStores::open(const bool writable) noexcept {
  // Each partition mounts independently so one bad area never masks the
  // other; a mount failure is a storage fault, never an implicit format.
  const nvs_open_mode_t mode = writable ? NVS_READWRITE : NVS_READONLY;
  // Field-boot opens read-only: a missing namespace is NOT created, the
  // open fails, and the field gate reports CONFIG_REQUIRED.
  esp_err_t error = nvs_flash_init_partition(sdkv1::kBoardConfigPartition);
  if (error != ESP_OK) {
    return Status::error(StatusCode::StorageFailure, "rlcfg partition init failed");
  }
  Status status = config_ns_.open(sdkv1::kBoardConfigPartition,
                                sdkv1::kBoardConfigNamespace, mode);
  if (!status) {
    return !writable && config_ns_.last_error().native == ESP_ERR_NVS_NOT_FOUND
               ? Status::error(StatusCode::NotFound, "board configuration required")
               : status;
  }
  error = nvs_flash_init_partition(sdkv1::kBoardSecretsPartition);
  if (error != ESP_OK) {
    return Status::error(StatusCode::StorageFailure, "rlkeys partition init failed");
  }
  status = secrets_ns_.open(sdkv1::kBoardSecretsPartition,
                            sdkv1::kBoardSecretsNamespace, mode);
  if (!status && !writable && secrets_ns_.last_error().native == ESP_ERR_NVS_NOT_FOUND) {
    return Status::error(StatusCode::NotFound, "board configuration required");
  }
  return status;
}

Status BoardStores::initialize() noexcept {
  // Report the first failure but always initialize both stores so each
  // keeps its own accurate impairment state.
  const Status config_status = config_.initialize();
  const Status secrets_status = secrets_.initialize();
  return config_status.ok() ? secrets_status : config_status;
}

Status initialize_board_rf() noexcept {
#if CONFIG_IDF_TARGET_ESP32C6
  constexpr gpio_num_t kRfSwitchEnableGpio = GPIO_NUM_3;
  constexpr gpio_num_t kAntennaSelectGpio = GPIO_NUM_14;
#if CONFIG_ROUTELOOM_BOARD_C6_EXTERNAL_ANTENNA
  constexpr int kAntennaLevel = 1;
#else
  constexpr int kAntennaLevel = 0;
#endif
  // These reserved RF pins use the reset push-pull mode.
  // GPIO3 is active-low; GPIO14 selects the internal (0) or external (1) antenna.
  if (gpio_output_enable(kRfSwitchEnableGpio) != ESP_OK ||
      gpio_set_level(kRfSwitchEnableGpio, 0) != ESP_OK ||
      gpio_output_enable(kAntennaSelectGpio) != ESP_OK ||
      gpio_set_level(kAntennaSelectGpio, kAntennaLevel) != ESP_OK) {
    return Status::error(StatusCode::RadioFailure, "rf switch GPIO setup failed");
  }
  ESP_LOGI("RouteLoomBoard", "rf switch: enabled, antenna: %s",
           kAntennaLevel == 0 ? "internal" : "external");
#endif
  return Status::success();
}

std::uint8_t board_chip() noexcept {
#if CONFIG_IDF_TARGET_ESP32C3
  return kBoardChipEsp32C3;
#elif CONFIG_IDF_TARGET_ESP32S3
  return kBoardChipEsp32S3;
#elif CONFIG_IDF_TARGET_ESP32C5
  return kBoardChipEsp32C5;
#elif CONFIG_IDF_TARGET_ESP32C6
  return kBoardChipEsp32C6;
#else
  return 0;
#endif
}

}  // namespace routeloom::espnow
