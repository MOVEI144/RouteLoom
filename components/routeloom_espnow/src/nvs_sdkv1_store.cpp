#include "routeloom/nvs_sdkv1_store.hpp"

#include "esp_err.h"

namespace routeloom::espnow {
namespace {

Status nvs_status(const esp_err_t error, const char* detail) noexcept {
  if (error == ESP_OK) return Status::success();
  return Status::error(StatusCode::StorageFailure, detail);
}

}  // namespace

NvsBlobNamespace::~NvsBlobNamespace() { close(); }

Status NvsBlobNamespace::open(const char* partition, const char* name_space) noexcept {
  if (name_space == nullptr || name_space[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument, "NVS sdkv1 namespace missing");
  }
  close();
  const esp_err_t error =
      partition == nullptr
          ? nvs_open(name_space, NVS_READWRITE, &handle_)
          : nvs_open_from_partition(partition, name_space, NVS_READWRITE, &handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_open sdkv1 failed");
  open_ = true;
  return Status::success();
}

void NvsBlobNamespace::close() noexcept {
  if (open_) nvs_close(handle_);
  handle_ = 0;
  open_ = false;
}

Status NvsBlobNamespace::blob_size(const char* key, std::size_t& size, bool& found) noexcept {
  size = 0;
  found = false;
  if (!open_ || key == nullptr) {
    return Status::error(StatusCode::InvalidState, "NVS sdkv1 namespace not ready");
  }
  std::size_t actual = 0;
  const esp_err_t error = nvs_get_blob(handle_, key, nullptr, &actual);
  if (error == ESP_ERR_NVS_NOT_FOUND) return Status::success();
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob size failed");
  size = actual;
  found = true;
  return Status::success();
}

Status NvsBlobNamespace::blob_read(const char* key, const MutableByteView target,
                                   std::size_t& read_len) noexcept {
  read_len = 0;
  if (!open_ || key == nullptr || target.data == nullptr || target.size == 0) {
    return Status::error(StatusCode::InvalidState, "NVS sdkv1 namespace not ready");
  }
  std::size_t length = target.size;
  const esp_err_t error = nvs_get_blob(handle_, key, target.data, &length);
  // A blob that grew between the size query and this read reports
  // ESP_ERR_NVS_INVALID_LENGTH: a storage fault, never silently truncated.
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob failed");
  read_len = length;
  return Status::success();
}

Status NvsBlobNamespace::blob_write(const char* key, const ByteView data) noexcept {
  if (!open_ || key == nullptr || data.data == nullptr || data.size == 0) {
    return Status::error(StatusCode::InvalidState, "NVS sdkv1 namespace not ready");
  }
  esp_err_t error = nvs_set_blob(handle_, key, data.data, data.size);
  if (error != ESP_OK) return nvs_status(error, "nvs_set_blob failed");
  error = nvs_commit(handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_commit failed");
  // Only committed writes count toward the wear budget.
  ++stats_.commits;
  stats_.bytes += data.size;
  return Status::success();
}

Status NvsBlobNamespace::blob_erase(const char* key) noexcept {
  if (!open_ || key == nullptr) {
    return Status::error(StatusCode::InvalidState, "NVS sdkv1 namespace not ready");
  }
  esp_err_t error = nvs_erase_key(handle_, key);
  if (error == ESP_ERR_NVS_NOT_FOUND) return Status::success();
  if (error != ESP_OK) return nvs_status(error, "nvs_erase_key failed");
  error = nvs_commit(handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_commit failed");
  ++stats_.commits;
  return Status::success();
}

}  // namespace routeloom::espnow
