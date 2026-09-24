#include "routeloom/nvs_boot_session.hpp"

#include "nvs.h"

namespace routeloom {

Status NvsBootSessionPort::read(std::uint32_t& stored, bool& found) noexcept {
  nvs_handle_t handle = 0;
  const esp_err_t opened = nvs_open("rlboot", NVS_READONLY, &handle);
  if (opened == ESP_ERR_NVS_NOT_FOUND) {
    found = false;
    stored = 0;
    return Status::success();
  }
  if (opened != ESP_OK) return Status::error(StatusCode::StorageFailure, "boot open");
  const esp_err_t result = nvs_get_u32(handle, "session", &stored);
  nvs_close(handle);
  if (result != ESP_OK && result != ESP_ERR_NVS_NOT_FOUND) {
    return Status::error(StatusCode::StorageFailure, "boot read");
  }
  found = result == ESP_OK;
  if (!found) stored = 0;
  return Status::success();
}

Status NvsBootSessionPort::commit(const std::uint32_t value) noexcept {
  nvs_handle_t handle = 0;
  esp_err_t result = nvs_open("rlboot", NVS_READWRITE, &handle);
  if (result != ESP_OK) return Status::error(StatusCode::StorageFailure, "boot open");
  result = nvs_set_u32(handle, "session", value);
  if (result == ESP_OK) result = nvs_commit(handle);
  nvs_close(handle);
  return result == ESP_OK ? Status::success()
                          : Status::error(StatusCode::StorageFailure, "boot commit");
}

Status next_boot_session(std::uint32_t& session) noexcept {
  NvsBootSessionPort port;
  sdkv1::BootSessionStore store(port);
  // The normal boot increment precedes rlsec/site classification. A site
  // witness is checked later by the Coordinator, not inferred from NVS here.
  return store.advance(false, 0, session);
}

}  // namespace routeloom
