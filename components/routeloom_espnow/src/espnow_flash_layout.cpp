#include "routeloom/espnow_flash_layout.hpp"

#include "esp_flash.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_partition.h"

namespace routeloom::espnow {

namespace {
constexpr char kTag[] = "rl_flash";
}  // namespace

// sdk_version follows components/*/idf_component.yml. storage_epoch 2 is
// PT-4M-v2: crossing from the factory layout needs erase and reprovision.
const ImageInfo kImageInfo = {"RLIMG1", "0.1.0", "PT-4M-v2", 2};

Status verify_flash_layout() noexcept {
  ESP_LOGI(kTag, "image: sdk=%s layout=%s storage_epoch=%lu",
           kImageInfo.sdk_version, kImageInfo.partition_id,
           static_cast<unsigned long>(kImageInfo.storage_epoch));
  std::uint32_t physical = 0;
  const esp_err_t size_error =
      esp_flash_get_physical_size(esp_flash_default_chip, &physical);
  if (size_error != ESP_OK || physical < kMinFlashBytes) {
    ESP_LOGE(kTag,
             "flash size %lu B (%s) is below the %lu B %s needs; RF not "
             "started",
             static_cast<unsigned long>(physical), esp_err_to_name(size_error),
             static_cast<unsigned long>(kMinFlashBytes), kPartitionLayoutId);
    return Status::error(StatusCode::StorageFailure, "flash smaller than PT-4M-v2");
  }
  for (const PartitionRow& row : kPt4mV2) {
    const esp_partition_t* found = esp_partition_find_first(
        ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, row.label);
    if (found == nullptr || found->address != row.offset || found->size != row.size) {
      ESP_LOGE(kTag,
               "partition %s: expected 0x%lx+0x%lx, flashed %s0x%lx+0x%lx; the "
               "table is not %s (erase flash, then write bootloader, table "
               "and app); RF not started",
               row.label, static_cast<unsigned long>(row.offset),
               static_cast<unsigned long>(row.size),
               found == nullptr ? "(missing) " : "",
               static_cast<unsigned long>(found == nullptr ? 0 : found->address),
               static_cast<unsigned long>(found == nullptr ? 0 : found->size),
               kPartitionLayoutId);
      return Status::error(StatusCode::StorageFailure,
                           "partition table is not PT-4M-v2");
    }
  }
  return Status::success();
}

void mark_app_valid() noexcept {
  const esp_err_t error = esp_ota_mark_app_valid_cancel_rollback();
  if (error != ESP_OK) {
    ESP_LOGW(kTag, "confirming the running image failed: %s",
             esp_err_to_name(error));
  }
}

}  // namespace routeloom::espnow
