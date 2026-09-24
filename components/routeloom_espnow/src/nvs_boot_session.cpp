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

Status NvsDevBootHighWaterPort::read(std::uint32_t& stored, bool& found) noexcept {
  nvs_handle_t handle = 0;
  const esp_err_t opened = nvs_open_from_partition("rlsec", "rldev", NVS_READONLY, &handle);
  if (opened == ESP_ERR_NVS_NOT_FOUND) {
    found = false;
    stored = 0;
    return Status::success();
  }
  if (opened != ESP_OK) return Status::error(StatusCode::StorageFailure, "dev boot open");
  const esp_err_t result = nvs_get_u32(handle, "boot_hi", &stored);
  nvs_close(handle);
  if (result != ESP_OK && result != ESP_ERR_NVS_NOT_FOUND) {
    return Status::error(StatusCode::StorageFailure, "dev boot read");
  }
  found = result == ESP_OK;
  if (!found) stored = 0;
  return Status::success();
}

Status NvsDevBootHighWaterPort::commit(const std::uint32_t value) noexcept {
  nvs_handle_t handle = 0;
  esp_err_t result = nvs_open_from_partition("rlsec", "rldev", NVS_READWRITE, &handle);
  if (result != ESP_OK) return Status::error(StatusCode::StorageFailure, "dev boot open");
  result = nvs_set_u32(handle, "boot_hi", value);
  if (result == ESP_OK) result = nvs_commit(handle);
  nvs_close(handle);
  return result == ESP_OK ? Status::success()
                          : Status::error(StatusCode::StorageFailure, "dev boot commit");
}

Status next_dev_group_boot_session(std::uint32_t& session) noexcept {
  NvsBootSessionPort system;
  NvsDevBootHighWaterPort high_water;
  sdkv1::BootSessionStore store(system);
  return store.advance_dev_group(high_water, session);
}

Status next_boot_session(std::uint32_t& session) noexcept {
  NvsBootSessionPort port;
  sdkv1::BootSessionStore store(port);
  // The normal boot increment precedes rlsec/site classification. A site
  // witness is reconciled after the independent site store is initialized.
  return store.advance(false, 0, session);
}

Status reconcile_boot_session(const sdkv1::SiteStore& site,
                              std::uint32_t& session) noexcept {
  if (!site.initialized() || site.quarantined() || site.uncertain()) {
    return Status::error(StatusCode::RecoveryRequired, "site boot witness unavailable");
  }
  if (!site.has_site()) return Status::success();
  NvsBootSessionPort port;
  sdkv1::BootSessionStore store(port);
  return store.reconcile_site(site.site().boot_witness, session);
}

}  // namespace routeloom
