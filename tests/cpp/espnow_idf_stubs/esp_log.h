// Test-only ESP-IDF stand-in: capture info logs for diagnostic tests.
#pragma once

namespace idf_stub {
void record_log(const char* tag, const char* format, ...) noexcept;
}

#define ESP_LOGI(...) ::idf_stub::record_log(__VA_ARGS__)
#define ESP_LOGW(...) ((void)0)
#define ESP_LOGE(...) ((void)0)
