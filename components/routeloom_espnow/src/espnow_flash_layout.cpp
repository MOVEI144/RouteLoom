#include "routeloom/espnow_flash_layout.hpp"

#include <cstring>
#include <iterator>

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
  std::uint32_t seen = 0;
  for (esp_partition_iterator_t it = esp_partition_find(
           ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, nullptr);
       it != nullptr;) {
    const esp_partition_t* found = esp_partition_get(it);
    std::size_t index = 0;
    while (index < std::size(kPt4mV2) &&
           std::strcmp(found->label, kPt4mV2[index].label) != 0) {
      ++index;
    }
    const bool known = index < std::size(kPt4mV2);
    const PartitionRow* expected = known ? &kPt4mV2[index] : nullptr;
    if (!known || (seen & (1u << index)) != 0 ||
        found->type != expected->type || found->subtype != expected->subtype ||
        found->address != expected->offset || found->size != expected->size) {
      ESP_LOGE(kTag,
               "partition %s: flashed type=%u subtype=%u 0x%lx+0x%lx; "
               "table is not %s (erase flash and write full image); RF not started",
               found->label, static_cast<unsigned>(found->type),
               static_cast<unsigned>(found->subtype),
               static_cast<unsigned long>(found->address),
               static_cast<unsigned long>(found->size), kPartitionLayoutId);
      esp_partition_iterator_release(it);
      return Status::error(StatusCode::StorageFailure, "partition table is not PT-4M-v2");
    }
    seen |= 1u << index;
    it = esp_partition_next(it);
  }
  if (seen != (1u << std::size(kPt4mV2)) - 1u) {
    ESP_LOGE(kTag, "partition table is missing PT-4M-v2 rows; RF not started");
    return Status::error(StatusCode::StorageFailure, "partition table is not PT-4M-v2");
  }
  return Status::success();
}

void mark_app_valid() noexcept {
  esp_ota_img_states_t state{};
  const esp_err_t state_error =
      esp_ota_get_state_partition(esp_ota_get_running_partition(), &state);
  if (state_error == ESP_ERR_NOT_FOUND) return;
  if (state_error != ESP_OK) {
    ESP_LOGW(kTag, "reading running image state failed: %s",
             esp_err_to_name(state_error));
    return;
  }
  if (state != ESP_OTA_IMG_PENDING_VERIFY) return;
  const esp_err_t error = esp_ota_mark_app_valid_cancel_rollback();
  if (error != ESP_OK) {
    ESP_LOGW(kTag, "confirming the running image failed: %s",
             esp_err_to_name(error));
  }
}

}  // namespace routeloom::espnow
