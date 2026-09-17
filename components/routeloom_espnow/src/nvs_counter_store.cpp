#include "routeloom/nvs_counter_store.hpp"

#include <cstdio>

#include "esp_err.h"

namespace routeloom::espnow {
namespace {
Status nvs_status(const esp_err_t error, const char* detail) noexcept {
  if (error == ESP_OK) return Status::success();
  return Status::error(StatusCode::StorageFailure, detail);
}
}  // namespace

NvsCounterStore::~NvsCounterStore() { close(); }

Status NvsCounterStore::open(const char* name_space) noexcept {
  if (name_space == nullptr || name_space[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument, "NVS namespace missing");
  }
  close();
  const esp_err_t error = nvs_open(name_space, NVS_READWRITE, &handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_open failed");
  open_ = true;
  return Status::success();
}

void NvsCounterStore::close() noexcept {
  if (open_) nvs_close(handle_);
  handle_ = 0;
  open_ = false;
}

Status NvsCounterStore::load_blob(const char* key, void* value, const std::size_t size,
                                  bool& found) noexcept {
  found = false;
  if (!open_ || key == nullptr || value == nullptr || size == 0) {
    return Status::error(StatusCode::InvalidState, "NVS store not ready");
  }
  std::size_t actual = size;
  const esp_err_t error = nvs_get_blob(handle_, key, value, &actual);
  if (error == ESP_ERR_NVS_NOT_FOUND) return Status::success();
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob failed");
  if (actual != size) return Status::error(StatusCode::IntegrityError, "NVS blob size mismatch");
  found = true;
  return Status::success();
}

Status NvsCounterStore::commit_blob(const char* key, const void* value,
                                    const std::size_t size) noexcept {
  if (!open_ || key == nullptr || value == nullptr || size == 0) {
    return Status::error(StatusCode::InvalidState, "NVS store not ready");
  }
  esp_err_t error = nvs_set_blob(handle_, key, value, size);
  if (error != ESP_OK) return nvs_status(error, "nvs_set_blob failed");
  error = nvs_commit(handle_);
  return nvs_status(error, "nvs_commit failed");
}

Status NvsCounterStore::load(const std::uint32_t slot, CounterRecord& record,
                             bool& found) noexcept {
  char key[12]{};
  std::snprintf(key, sizeof(key), "c%08lx", static_cast<unsigned long>(slot));
  return load_blob(key, &record, sizeof(record), found);
}

Status NvsCounterStore::commit(const std::uint32_t slot,
                               const CounterRecord& record) noexcept {
  char key[12]{};
  std::snprintf(key, sizeof(key), "c%08lx", static_cast<unsigned long>(slot));
  return commit_blob(key, &record, sizeof(record));
}

}  // namespace routeloom::espnow
