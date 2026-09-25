#include <array>
#include <cstdio>
#include <cstring>

#include "nvs.h"
#include "routeloom/nvs_legacy_purge.hpp"

#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); return 1; } } while (false)

namespace {
struct Entry {
  const char* space;
  const char* key;
  std::uint32_t value;
  bool live;
  bool u32;
};
std::array<Entry, 8> entries{{
    {"rldev", "migration", 0xDEADBEEFU, true, true},
    {"rlcounter", "c00000001", 0, true, true},
    {"rlreplay", "f00000002", 0, true, true},
    {"rlreplay", "r00000003", 0, true, true},
    {"rlcounter", "cmax", 0, true, true},
    {"rlreplay", "f0000000x", 0, true, true},
    {"rldev", "boot_hi", 44, true, true},
    {"rlres", "s00", 0, true, true},
}};
const char* opened_space = nullptr;
std::size_t erase_calls = 0;
bool invalid_find = false;
}

struct NvsIterator { const char* space; std::size_t index; };

esp_err_t nvs_open_from_partition(const char* partition, const char* space, int,
                                  nvs_handle_t* handle) {
  if (std::strcmp(partition, "rlsec") != 0 || handle == nullptr) return ESP_ERR_INVALID_ARG;
  opened_space = space;
  *handle = 1;
  return ESP_OK;
}
esp_err_t nvs_get_u32(nvs_handle_t, const char* key, std::uint32_t* value) {
  for (const auto& entry : entries) {
    if (entry.live && std::strcmp(entry.space, opened_space) == 0 &&
        std::strcmp(entry.key, key) == 0) {
      if (!entry.u32) return ESP_ERR_NVS_TYPE_MISMATCH;
      *value = entry.value;
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_FOUND;
}
esp_err_t nvs_set_u32(nvs_handle_t, const char* key, std::uint32_t value) {
  for (auto& entry : entries) {
    if (std::strcmp(entry.space, opened_space) == 0 && std::strcmp(entry.key, key) == 0) {
      entry.value = value;
      entry.live = true;
      entry.u32 = true;
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_FOUND;
}
esp_err_t nvs_erase_key(nvs_handle_t, const char* key) {
  for (auto& entry : entries) {
    if (entry.live && std::strcmp(entry.space, opened_space) == 0 &&
        std::strcmp(entry.key, key) == 0) {
      entry.live = false;
      ++erase_calls;
      return ESP_OK;
    }
  }
  return ESP_ERR_NVS_NOT_FOUND;
}
esp_err_t nvs_commit(nvs_handle_t) { return ESP_OK; }
void nvs_close(nvs_handle_t) {}
esp_err_t nvs_entry_find(const char* partition, const char* space, int,
                         nvs_iterator_t* iterator) {
  if (invalid_find && std::strcmp(space, "rlcounter") == 0) return ESP_ERR_INVALID_ARG;
  if (std::strcmp(partition, "rlsec") != 0) return ESP_ERR_INVALID_ARG;
  *iterator = new NvsIterator{space, static_cast<std::size_t>(-1)};
  return nvs_entry_next(iterator);
}
esp_err_t nvs_entry_info(nvs_iterator_t iterator, nvs_entry_info_t* info) {
  if (iterator == nullptr || iterator->index >= entries.size()) return ESP_ERR_INVALID_ARG;
  std::snprintf(info->namespace_name, sizeof(info->namespace_name), "%s", iterator->space);
  std::snprintf(info->key, sizeof(info->key), "%s", entries[iterator->index].key);
  return ESP_OK;
}
esp_err_t nvs_entry_next(nvs_iterator_t* iterator) {
  if (iterator == nullptr || *iterator == nullptr) return ESP_ERR_INVALID_ARG;
  const std::size_t start = (*iterator)->index == static_cast<std::size_t>(-1)
                                ? 0 : (*iterator)->index + 1;
  for (std::size_t i = start; i < entries.size(); ++i) {
    if (entries[i].live && std::strcmp(entries[i].space, (*iterator)->space) == 0) {
      (*iterator)->index = i;
      return ESP_OK;
    }
  }
  delete *iterator;
  *iterator = nullptr;
  return ESP_ERR_NVS_NOT_FOUND;
}
void nvs_release_iterator(nvs_iterator_t iterator) { delete iterator; }

int main() {
  using namespace routeloom;
  using namespace routeloom::espnow;
  NvsLegacyPurgePort port;
  bool marker = true;
  CHECK(port.migration(marker).code == StatusCode::StorageFailure);
  CHECK(!marker);
  CHECK(refuse_legacy_boot_after_migration().code == StatusCode::StorageFailure);
  sdkv1::LegacyPurgeResult result{};
  CHECK(purge_legacy_state(port, true, true, result).code == StatusCode::StorageFailure);
  CHECK(entries[0].value == 0xDEADBEEFU && erase_calls == 0);
  entries[0].value = kLegacyMigrationMagic;
  CHECK(port.migration(marker).ok() && marker);
  CHECK(refuse_legacy_boot_after_migration().code == StatusCode::RecoveryRequired);
  invalid_find = true;
  CHECK(purge_legacy_state(port, true, true, result).code == StatusCode::StorageFailure);
  CHECK(erase_calls == 0);
  invalid_find = false;
  CHECK(purge_legacy_state(port, true, true, result).ok());
  CHECK(result.erased == 3 && result.remaining == 0 && erase_calls == 3);
  CHECK(port.erase(sdkv1::LegacyKey{"rlcounter", "c00000001"}).ok());
  CHECK(entries[4].live && entries[5].live && entries[6].live && entries[7].live);
  entries[0].u32 = false;
  CHECK(port.migration(marker).code == StatusCode::StorageFailure);
  entries[0].live = false;
  CHECK(refuse_legacy_boot_after_migration().ok());
  return 0;
}
