#include "routeloom/nvs_sdkv1_store.hpp"

#include "esp_err.h"
#include "esp_log.h"

namespace routeloom::espnow {
namespace {

bool IsNoSpace(const esp_err_t error) noexcept {
  return error == ESP_ERR_NVS_NOT_ENOUGH_SPACE || error == ESP_ERR_NVS_NO_FREE_PAGES;
}

template <std::size_t N>
void CopyLabel(char (&out)[N], const char* src) noexcept {
  std::size_t i = 0;
  for (; src[i] != '\0' && i + 1 < N; ++i) out[i] = src[i];
  out[i] = '\0';
}

}  // namespace

NvsBlobNamespace::~NvsBlobNamespace() { close(); }

Status NvsBlobNamespace::note_error(const char* op, const esp_err_t error,
                                    const char* failed_detail,
                                    const char* nospace_detail) noexcept {
  last_.op = op;
  last_.native = error;
  CopyLabel(last_.partition, partition_);
  CopyLabel(last_.name_space, space_);
  ESP_LOGE("RouteLoomNVS", "%s %s/%s native=0x%x", op, partition_, space_,
           static_cast<unsigned int>(error));
  return Status::error(StatusCode::StorageFailure,
                       IsNoSpace(error) ? nospace_detail : failed_detail);
}

Status NvsBlobNamespace::open(const char* partition, const char* name_space) noexcept {
  if (name_space == nullptr || name_space[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument, "NVS sdkv1 namespace missing");
  }
  close();
  CopyLabel(partition_, partition == nullptr ? "nvs" : partition);
  CopyLabel(space_, name_space);
  const esp_err_t error =
      partition == nullptr
          ? nvs_open(name_space, NVS_READWRITE, &handle_)
          : nvs_open_from_partition(partition, name_space, NVS_READWRITE, &handle_);
  if (error != ESP_OK) {
    return note_error("open", error, "nvs_open sdkv1 failed",
                      "nvs_open sdkv1 failed (no space)");
  }
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
  if (error != ESP_OK) {
    return note_error("blob_size", error, "nvs_get_blob size failed",
                      "nvs_get_blob size failed (no space)");
  }
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
  if (error != ESP_OK) {
    return note_error("blob_read", error, "nvs_get_blob failed",
                      "nvs_get_blob failed (no space)");
  }
  read_len = length;
  return Status::success();
}

Status NvsBlobNamespace::blob_write(const char* key, const ByteView data) noexcept {
  if (!open_ || key == nullptr || data.data == nullptr || data.size == 0) {
    return Status::error(StatusCode::InvalidState, "NVS sdkv1 namespace not ready");
  }
  esp_err_t error = nvs_set_blob(handle_, key, data.data, data.size);
  if (error != ESP_OK) {
    return note_error("blob_write", error, "nvs_set_blob failed",
                      "nvs_set_blob failed (no space)");
  }
  error = nvs_commit(handle_);
  if (error != ESP_OK) {
    return note_error("commit", error, "nvs_commit failed",
                      "nvs_commit failed (no space)");
  }
  // Only committed writes count toward the wear budget.
  ++stats_.commits;
  stats_.bytes += data.size;
  return Status::success();
}

}  // namespace routeloom::espnow
