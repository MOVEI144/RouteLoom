// Test-only ESP-IDF stand-in: capture info logs for diagnostic tests; warnings
// and errors stay quiet but still use the tag so tag-only callers compile clean.
#pragma once

namespace idf_stub {
void record_log(const char* tag, const char* format, ...) noexcept;
}

#define ESP_LOGI(...) ::idf_stub::record_log(__VA_ARGS__)
#define ESP_LOGW(tag, ...) ((void)(tag))
#define ESP_LOGE(tag, ...) ((void)(tag))

#include <cstdint>

// Runtime level control the remote-config provider drives (diagnostics
// level field); the stub keeps no level. The timestamp is the virtual clock.
typedef enum {
  ESP_LOG_NONE,
  ESP_LOG_ERROR,
  ESP_LOG_WARN,
  ESP_LOG_INFO,
  ESP_LOG_DEBUG,
  ESP_LOG_VERBOSE,
} esp_log_level_t;
inline void esp_log_level_set(const char*, esp_log_level_t) {}
std::uint32_t esp_log_timestamp(void);
