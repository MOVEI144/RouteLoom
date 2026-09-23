#include "routeloom/nvs_counter_store.hpp"

#include <cstdio>
#include <cstring>

#include "esp_err.h"

namespace routeloom::espnow {
namespace {
constexpr char kWitnessKey[] = "cmax";

Status nvs_status(const esp_err_t error, const char* detail) noexcept {
  if (error == ESP_OK) return Status::success();
  return Status::error(StatusCode::StorageFailure, detail);
}

void slot_key(char out[12], const char prefix, const std::uint32_t slot) noexcept {
  std::snprintf(out, 12, "%c%08lx", prefix, static_cast<unsigned long>(slot));
}

// Inverse of slot_key: exactly <prefix> followed by 8 lowercase hex digits.
bool parse_slot_key(const char* key, const char prefix, std::uint32_t& slot) noexcept {
  if (key == nullptr || key[0] != prefix || std::strlen(key) != 9) return false;
  std::uint32_t value = 0;
  for (int index = 1; index < 9; ++index) {
    const char digit = key[index];
    std::uint32_t nibble = 0;
    if (digit >= '0' && digit <= '9') {
      nibble = static_cast<std::uint32_t>(digit - '0');
    } else if (digit >= 'a' && digit <= 'f') {
      nibble = static_cast<std::uint32_t>(digit - 'a' + 10);
    } else {
      return false;
    }
    value = (value << 4U) | nibble;
  }
  slot = value;
  return true;
}
}  // namespace

NvsCounterStore::~NvsCounterStore() { close(); }

Status NvsCounterStore::open(const char* name_space, const char* partition) noexcept {
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
  slot_key(key, 'c', slot);
  return load_blob(key, &record, sizeof(record), found);
}

Status NvsCounterStore::commit(const std::uint32_t slot,
                               const CounterRecord& record) noexcept {
  char key[12]{};
  slot_key(key, 'c', slot);
  return commit_blob(key, &record, sizeof(record));
}

Status NvsCounterStore::for_each_key_slot(const char prefix,
                                          SlotVisitor& visitor) noexcept {
  if (!open_) return Status::error(StatusCode::InvalidState, "NVS store not ready");
  nvs_iterator_t iterator = nullptr;
  esp_err_t error = nvs_entry_find_in_handle(handle_, NVS_TYPE_BLOB, &iterator);
  // The visitor may read (never write) through this handle while the
  // iterator is live; NVS reads do not invalidate an iterator.
  while (error == ESP_OK) {
    nvs_entry_info_t info{};
    error = nvs_entry_info(iterator, &info);
    if (error != ESP_OK) break;
    std::uint32_t slot = 0;
    if (parse_slot_key(info.key, prefix, slot) && !visitor.visit(slot)) {
      nvs_release_iterator(iterator);
      return Status::success();
    }
    error = nvs_entry_next(&iterator);
  }
  nvs_release_iterator(iterator);
  if (error == ESP_ERR_NVS_NOT_FOUND) return Status::success();  // end of entries
  return nvs_status(error, "nvs entry iteration failed");
}

Status NvsCounterStore::for_each_slot(SlotVisitor& visitor) noexcept {
  return for_each_key_slot('c', visitor);
}

Status NvsCounterStore::erase(const std::uint32_t slot) noexcept {
  if (!open_) return Status::error(StatusCode::InvalidState, "NVS store not ready");
  char key[12]{};
  slot_key(key, 'c', slot);
  esp_err_t error = nvs_erase_key(handle_, key);
  if (error == ESP_ERR_NVS_NOT_FOUND) return Status::success();
  if (error != ESP_OK) return nvs_status(error, "nvs_erase_key failed");
  error = nvs_commit(handle_);
  return nvs_status(error, "nvs_commit failed");
}

Status NvsCounterStore::load_witness(std::uint32_t& witness, bool& found) noexcept {
  found = false;
  witness = 0;
  if (!open_) return Status::error(StatusCode::InvalidState, "NVS store not ready");
  const esp_err_t error = nvs_get_u32(handle_, kWitnessKey, &witness);
  if (error == ESP_ERR_NVS_NOT_FOUND) {
    witness = 0;
    return Status::success();
  }
  if (error != ESP_OK) {
    // A type mismatch or read error leaves the swept range unknown.
    return Status::error(StatusCode::IntegrityError, "counter witness unreadable");
  }
  found = true;
  return Status::success();
}

Status NvsCounterStore::commit_witness(const std::uint32_t witness) noexcept {
  if (!open_) return Status::error(StatusCode::InvalidState, "NVS store not ready");
  esp_err_t error = nvs_set_u32(handle_, kWitnessKey, witness);
  if (error != ESP_OK) return nvs_status(error, "counter witness write failed");
  error = nvs_commit(handle_);
  return nvs_status(error, "counter witness commit failed");
}

Status nvs_partition_peer_capacity(const char* partition, const std::uint32_t configured,
                                   std::uint32_t& effective) noexcept {
  effective = 0;
  nvs_stats_t stats{};
  const esp_err_t error = nvs_get_stats(partition, &stats);
  if (error != ESP_OK) return nvs_status(error, "nvs_get_stats failed");
  // size_t is 32-bit on every supported target; the cast is lossless.
  const std::uint32_t fits = max_persisted_peers_for_entries(
      static_cast<std::uint32_t>(stats.total_entries));
  effective = configured < fits ? configured : fits;
  if (effective == 0) {
    return Status::error(StatusCode::NoCapacity, "security NVS partition too small");
  }
  return Status::success();
}

bool nvs_namespace_in_use(const char* partition, const char* name_space) noexcept {
  nvs_iterator_t iterator = nullptr;
  const esp_err_t error = nvs_entry_find(partition, name_space, NVS_TYPE_ANY, &iterator);
  if (error == ESP_ERR_INVALID_ARG) return false;  // iterator untouched, nothing to release
  nvs_release_iterator(iterator);
  return error == ESP_OK;
}

}  // namespace routeloom::espnow
