#include "routeloom/nvs_legacy_purge.hpp"

#include <cstring>

#include "nvs.h"
#include "nvs_flash.h"

namespace routeloom::espnow {
namespace {

constexpr char kPartition[] = "rlsec";
constexpr char kCounterSpace[] = "rlcounter";
constexpr char kReplaySpace[] = "rlreplay";
constexpr char kDevSpace[] = "rldev";
constexpr char kMigrationKey[] = "migration";

// Takes the entry at ordinal `skip` (0-based) of the rlcounter listing
// followed by the rlreplay listing (NVS_TYPE_ANY; the shape filter
// decides), copying its namespace and key. Every call re-finds, so the
// caller may commit erases between calls.
Status take_across(std::size_t skip, const char*& name_space, char key[16],
                   bool& found) noexcept {
  static constexpr const char* kSpaces[] = {kCounterSpace, kReplaySpace};
  found = false;
  for (const char* space : kSpaces) {
    nvs_iterator_t iterator = nullptr;
    esp_err_t error = nvs_entry_find(kPartition, space, NVS_TYPE_ANY, &iterator);
    if (error == ESP_ERR_NVS_NOT_FOUND || error == ESP_ERR_INVALID_ARG) continue;
    if (error != ESP_OK) {
      nvs_release_iterator(iterator);
      return Status::error(StatusCode::StorageFailure, "legacy find failed");
    }
    for (;;) {
      nvs_entry_info_t info{};
      error = nvs_entry_info(iterator, &info);
      if (error != ESP_OK) break;
      if (skip == 0) {
        std::memcpy(key, info.key, sizeof(info.key));
        name_space = space;
        found = true;
        break;
      }
      --skip;
      error = nvs_entry_next(&iterator);
      if (error == ESP_ERR_NVS_NOT_FOUND) {
        error = ESP_OK;  // ran past the end of this namespace
        break;
      }
      if (error != ESP_OK) break;
    }
    nvs_release_iterator(iterator);
    if (error != ESP_OK) {
      return Status::error(StatusCode::StorageFailure, "legacy iterate failed");
    }
    if (found) return Status::success();
  }
  return Status::success();
}

}  // namespace

Status NvsLegacyPurgePort::migration(bool& present) noexcept {
  present = false;
  nvs_handle_t handle = 0;
  const esp_err_t opened = nvs_open_from_partition(kPartition, kDevSpace, NVS_READONLY, &handle);
  if (opened == ESP_ERR_NVS_NOT_FOUND) return Status::success();
  if (opened != ESP_OK) {
    return Status::error(StatusCode::StorageFailure, "legacy migration open");
  }
  std::uint32_t value = 0;
  const esp_err_t result = nvs_get_u32(handle, kMigrationKey, &value);
  nvs_close(handle);
  if (result == ESP_ERR_NVS_NOT_FOUND) return Status::success();
  // A wrong type or an unreadable key is not absence: never guess.
  if (result != ESP_OK) {
    return Status::error(StatusCode::StorageFailure, "legacy migration read");
  }
  present = value == kLegacyMigrationMagic;
  return Status::success();
}

Status NvsLegacyPurgePort::commit_migration() noexcept {
  nvs_handle_t handle = 0;
  esp_err_t result = nvs_open_from_partition(kPartition, kDevSpace, NVS_READWRITE, &handle);
  if (result != ESP_OK) {
    return Status::error(StatusCode::StorageFailure, "legacy migration open");
  }
  result = nvs_set_u32(handle, kMigrationKey, kLegacyMigrationMagic);
  if (result == ESP_OK) result = nvs_commit(handle);
  nvs_close(handle);
  return result == ESP_OK
             ? Status::success()
             : Status::error(StatusCode::StorageFailure, "legacy migration commit");
}

Status NvsLegacyPurgePort::next(std::size_t& cursor, sdkv1::LegacyKey& key,
                                bool& found) noexcept {
  key = sdkv1::LegacyKey{};
  found = false;
  // Every erase in this pass removed an entry ahead of the cursor, so the
  // live ordinal trails the walk by exactly that many (a zero cursor opens
  // a new pass and resets the compensation).
  if (cursor == 0) pass_erases_ = 0;
  const std::size_t skip = cursor < pass_erases_ ? 0 : cursor - pass_erases_;
  const char* space = nullptr;
  bool hit = false;
  const Status status = take_across(skip, space, key_, hit);
  if (!status) return status;
  if (!hit) return Status::success();
  std::memcpy(space_, space, std::strlen(space) + 1);
  key.name_space = space_;
  key.key = key_;
  found = true;
  ++cursor;
  return Status::success();
}

Status NvsLegacyPurgePort::erase(const sdkv1::LegacyKey& key) noexcept {
  // Re-check the shape at the erase boundary: only enumerated legacy
  // peer records die here, even if a caller passes something else.
  if (!sdkv1::is_legacy_peer_key(key)) {
    return Status::error(StatusCode::InvalidArgument, "legacy erase shape");
  }
  char space[16]{};
  char name[16]{};
  std::memcpy(space, key.name_space, sizeof(space) - 1);
  std::memcpy(name, key.key, sizeof(name) - 1);
  nvs_handle_t handle = 0;
  esp_err_t result =
      nvs_open_from_partition(kPartition, space, NVS_READWRITE, &handle);
  if (result != ESP_OK) {
    return Status::error(StatusCode::StorageFailure, "legacy erase open");
  }
  result = nvs_erase_key(handle, name);
  if (result == ESP_OK) result = nvs_commit(handle);
  nvs_close(handle);
  if (result == ESP_ERR_NVS_NOT_FOUND) return Status::success();  // idempotent
  if (result != ESP_OK) {
    return Status::error(StatusCode::StorageFailure, "legacy erase failed");
  }
  ++pass_erases_;
  return Status::success();
}

}  // namespace routeloom::espnow
