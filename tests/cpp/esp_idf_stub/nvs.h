#pragma once

#include <cstdint>

using esp_err_t = int;
using nvs_handle_t = std::uint32_t;
struct NvsIterator;
using nvs_iterator_t = NvsIterator*;

#ifndef ESP_OK
inline constexpr esp_err_t ESP_OK = 0;
#endif
inline constexpr esp_err_t ESP_ERR_NVS_NOT_FOUND = 1;
inline constexpr esp_err_t ESP_ERR_INVALID_ARG = 2;
inline constexpr esp_err_t ESP_ERR_NVS_TYPE_MISMATCH = 3;
inline constexpr esp_err_t ESP_ERR_NVS_NOT_ENOUGH_SPACE = 4;
inline constexpr int NVS_READONLY = 0;
inline constexpr int NVS_READWRITE = 1;
inline constexpr int NVS_TYPE_ANY = 0;

struct nvs_entry_info_t {
  char namespace_name[16]{};
  char key[16]{};
};

esp_err_t nvs_open(const char*, int, nvs_handle_t*);
esp_err_t nvs_open_from_partition(const char*, const char*, int, nvs_handle_t*);
esp_err_t nvs_get_u32(nvs_handle_t, const char*, std::uint32_t*);
esp_err_t nvs_set_u32(nvs_handle_t, const char*, std::uint32_t);
esp_err_t nvs_erase_key(nvs_handle_t, const char*);
esp_err_t nvs_commit(nvs_handle_t);
void nvs_close(nvs_handle_t);
esp_err_t nvs_entry_find(const char*, const char*, int, nvs_iterator_t*);
esp_err_t nvs_entry_info(nvs_iterator_t, nvs_entry_info_t*);
esp_err_t nvs_entry_next(nvs_iterator_t*);
void nvs_release_iterator(nvs_iterator_t);
