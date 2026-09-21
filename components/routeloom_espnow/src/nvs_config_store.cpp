#include "routeloom/nvs_config_store.hpp"

#include <cstdio>
#include <cstring>

#include "esp_err.h"

namespace routeloom::espnow {
namespace {

constexpr std::uint8_t kErasedFill = 0xFFU;
constexpr std::uint8_t kCorruptFill = 0xA5U;

Status nvs_status(const esp_err_t error, const char* detail) noexcept {
  if (error == ESP_OK) return Status::success();
  return Status::error(StatusCode::StorageFailure, detail);
}

Status slot_key(const std::uint8_t slot, char (&key)[4]) noexcept {
  if (slot >= kConfigJournalSlots) {
    return Status::error(StatusCode::InvalidArgument, "NVS config slot out of range");
  }
  std::snprintf(key, sizeof(key), "j%u", static_cast<unsigned>(slot));
  return Status::success();
}

}  // namespace

NvsConfigStore::~NvsConfigStore() { close(); }

Status NvsConfigStore::open(const char* name_space) noexcept {
  if (name_space == nullptr || name_space[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument, "NVS config namespace missing");
  }
  close();
  const esp_err_t error = nvs_open(name_space, NVS_READWRITE, &handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_open failed");
  open_ = true;
  return Status::success();
}

void NvsConfigStore::close() noexcept {
  if (open_) nvs_close(handle_);
  handle_ = 0;
  open_ = false;
}

Status NvsConfigStore::read(const std::uint8_t slot, const MutableByteView target) noexcept {
  if (!open_ || target.data == nullptr || target.size == 0) {
    return Status::error(StatusCode::InvalidState, "NVS config store not ready");
  }
  char key[4]{};
  const auto status = slot_key(slot, key);
  if (!status) return status;
  std::size_t actual = 0;
  esp_err_t error = nvs_get_blob(handle_, key, nullptr, &actual);
  if (error == ESP_ERR_NVS_NOT_FOUND) {
    // Never written: a uniformly-erased slot the journal classifies Empty.
    std::memset(target.data, kErasedFill, target.size);
    return Status::success();
  }
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob size failed");
  if (actual > target.size) {
    // A blob that cannot fit the slot is unusable, not erased: report a
    // fixed non-erased pattern so the journal quarantines it.
    std::memset(target.data, kCorruptFill, target.size);
    return Status::success();
  }
  std::size_t read_len = actual;
  error = nvs_get_blob(handle_, key, target.data, &read_len);
  if (error != ESP_OK) return nvs_status(error, "nvs_get_blob failed");
  if (read_len != actual || read_len > target.size) {
    std::memset(target.data, kCorruptFill, target.size);
    return Status::success();
  }
  // The journal wrote only record_len bytes; the unread tail of the slot
  // reads back as erased flash, matching the on-flash image it produced.
  if (actual < target.size) {
    std::memset(target.data + actual, kErasedFill, target.size - actual);
  }
  // A blob that EXISTS but reads back uniformly erased (or zeroed) is a
  // torn/anomalous write — evidence the slot was touched, never proof it
  // was never written. Only a missing key (NOT_FOUND above) may classify
  // Empty; a present-but-erased blob is reported Corrupt so the journal
  // quarantines instead of treating the slot as provably absent and
  // silently restarting at revision 0.
  const std::uint8_t fill = target.data[0];
  if (fill == kErasedFill || fill == 0x00U) {
    bool uniform = true;
    for (std::size_t i = 1; i < target.size; ++i) {
      if (target.data[i] != fill) {
        uniform = false;
        break;
      }
    }
    if (uniform) {
      std::memset(target.data, kCorruptFill, target.size);
    }
  }
  return Status::success();
}

Status NvsConfigStore::write(const std::uint8_t slot, const ByteView data) noexcept {
  if (!open_ || data.data == nullptr || data.size == 0 ||
      data.size > kConfigJournalSlotBytes) {
    return Status::error(StatusCode::InvalidState, "NVS config store not ready");
  }
  char key[4]{};
  const auto status = slot_key(slot, key);
  if (!status) return status;
  esp_err_t error = nvs_set_blob(handle_, key, data.data, data.size);
  if (error != ESP_OK) return nvs_status(error, "nvs_set_blob failed");
  error = nvs_commit(handle_);
  if (error != ESP_OK) return nvs_status(error, "nvs_commit failed");
  // Count only committed writes — the §6.8 flash budget measures what
  // actually landed, not attempted calls that NVS rejected.
  ++stats_.commits;
  stats_.bytes += data.size;
  return Status::success();
}

}  // namespace routeloom::espnow
