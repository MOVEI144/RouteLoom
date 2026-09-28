#include "routeloom/espnow_board_config.hpp"

#include "nvs_flash.h"
#include "sdkconfig.h"

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
    // The setup console creates both namespaces together; an erased
    // board has neither.
    return config_ns_.last_error().native == ESP_ERR_NVS_NOT_FOUND
               ? Status::error(StatusCode::NotFound, "board configuration required")
               : status;
  }
  error = nvs_flash_init_partition(sdkv1::kBoardSecretsPartition);
  if (error != ESP_OK) {
    return Status::error(StatusCode::StorageFailure, "rlkeys partition init failed");
  }
  return secrets_ns_.open(sdkv1::kBoardSecretsPartition,
                          sdkv1::kBoardSecretsNamespace, mode);
}

Status BoardStores::initialize() noexcept {
  // Report the first failure but always initialize both stores so each
  // keeps its own accurate impairment state.
  const Status config_status = config_.initialize();
  const Status secrets_status = secrets_.initialize();
  return config_status.ok() ? secrets_status : config_status;
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
