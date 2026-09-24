#include "routeloom/nvs_security_floor.hpp"

#include <cstring>

#include "esp_err.h"

namespace routeloom::espnow {
namespace {

constexpr char kStateKey[] = "state";

Status nvs_status(const esp_err_t error, const char* detail) noexcept {
  if (error == ESP_OK) return Status::success();
  return Status::error(StatusCode::StorageFailure, detail);
}

}  // namespace

NvsSecurityFloorStore::~NvsSecurityFloorStore() { close(); }

Status NvsSecurityFloorStore::open(const char* name_space,
                                   const char* partition) noexcept {
  if (name_space == nullptr || name_space[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument, "NVS namespace missing");
  }
  close();
  const esp_err_t error =
      partition == nullptr
          ? nvs_open(name_space, NVS_READWRITE, &handle_)
          : nvs_open_from_partition(partition, name_space, NVS_READWRITE, &handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_open failed");
  open_ = true;
  return Status::success();
}

void NvsSecurityFloorStore::close() noexcept {
  if (open_) nvs_close(handle_);
  handle_ = 0;
  open_ = false;
}

Status NvsSecurityFloorStore::read(const MutableByteView target) noexcept {
  if (!open_ || target.data == nullptr ||
      target.size != kSecurityFloorBlobBytes) {
    return Status::error(StatusCode::InvalidState, "NVS floor store not ready");
  }
  std::size_t actual = 0;
  esp_err_t error = nvs_get_blob(handle_, kStateKey, nullptr, &actual);
  if (error == ESP_ERR_NVS_NOT_FOUND) {
    // Never provisioned: not an empty floor — the portable store turns
    // this into RecoveryRequired and stops privileged intake.
    return Status::error(StatusCode::NotFound, "security floor not provisioned");
  }
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob size failed");
  if (actual != kSecurityFloorBlobBytes) {
    return Status::error(StatusCode::StorageFailure, "security floor size mismatch");
  }
  std::size_t read_len = actual;
  error = nvs_get_blob(handle_, kStateKey, target.data, &read_len);
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob failed");
  if (read_len != actual) {
    return Status::error(StatusCode::StorageFailure, "security floor torn read");
  }
  return Status::success();
}

Status NvsSecurityFloorStore::write(const ByteView data) noexcept {
  if (!open_ || data.data == nullptr || data.size != kSecurityFloorBlobBytes) {
    return Status::error(StatusCode::InvalidState, "NVS floor store not ready");
  }
  esp_err_t error = nvs_set_blob(handle_, kStateKey, data.data, data.size);
  if (error != ESP_OK) return nvs_status(error, "nvs_set_blob failed");
  error = nvs_commit(handle_);
  return nvs_status(error, "nvs_commit failed");
}

}  // namespace routeloom::espnow
