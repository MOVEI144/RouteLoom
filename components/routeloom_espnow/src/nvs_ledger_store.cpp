#include "routeloom/nvs_ledger_store.hpp"

#include <cstdio>
#include <cstring>

#include "esp_err.h"

namespace routeloom::espnow {
namespace {

constexpr std::uint8_t kCorruptFill = 0xA5U;

Status nvs_status(const esp_err_t error, const char* detail) noexcept {
  if (error == ESP_OK) return Status::success();
  return Status::error(StatusCode::StorageFailure, detail);
}

Status slot_key(const std::uint8_t slot, char (&key)[4]) noexcept {
  if (slot >= kAuthorityLedgerSlots) {
    return Status::error(StatusCode::InvalidArgument, "NVS ledger slot out of range");
  }
  std::snprintf(key, sizeof(key), "lg%u", static_cast<unsigned>(slot));
  return Status::success();
}

}  // namespace

NvsLedgerStore::~NvsLedgerStore() { close(); }

Status NvsLedgerStore::open(const char* name_space) noexcept {
  if (name_space == nullptr || name_space[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument, "NVS namespace missing");
  }
  close();
  const esp_err_t error = nvs_open(name_space, NVS_READWRITE, &handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_open failed");
  open_ = true;
  return Status::success();
}

void NvsLedgerStore::close() noexcept {
  if (open_) nvs_close(handle_);
  handle_ = 0;
  open_ = false;
}

Status NvsLedgerStore::read(const std::uint8_t slot, const MutableByteView target) noexcept {
  if (!open_ || target.data == nullptr || target.size == 0) {
    return Status::error(StatusCode::InvalidState, "NVS ledger store not ready");
  }
  char key[4]{};
  const auto status = slot_key(slot, key);
  if (!status) return status;
  std::size_t actual = 0;
  esp_err_t error = nvs_get_blob(handle_, key, nullptr, &actual);
  if (error == ESP_ERR_NVS_NOT_FOUND) {
    std::memset(target.data, 0, target.size);
    return Status::success();
  }
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob size failed");
  if (actual != target.size) {
    // Wrong-size blob is unusable data, not an erased slot: report a fixed
    // non-erased pattern so the ledger quarantines rather than trusts it.
    std::memset(target.data, kCorruptFill, target.size);
    return Status::success();
  }
  error = nvs_get_blob(handle_, key, target.data, &actual);
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob failed");
  if (actual != target.size) std::memset(target.data, kCorruptFill, target.size);
  return Status::success();
}

Status NvsLedgerStore::write(const std::uint8_t slot, const ByteView data) noexcept {
  if (!open_ || data.data == nullptr || data.size == 0) {
    return Status::error(StatusCode::InvalidState, "NVS ledger store not ready");
  }
  char key[4]{};
  const auto status = slot_key(slot, key);
  if (!status) return status;
  esp_err_t error = nvs_set_blob(handle_, key, data.data, data.size);
  if (error != ESP_OK) return nvs_status(error, "nvs_set_blob failed");
  error = nvs_commit(handle_);
  return nvs_status(error, "nvs_commit failed");
}

}  // namespace routeloom::espnow
