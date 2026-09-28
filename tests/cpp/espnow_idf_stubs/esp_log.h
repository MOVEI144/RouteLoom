// Test-only ESP-IDF stand-in: capture info logs for diagnostic tests; warnings
// and errors stay quiet but still use the tag so tag-only callers compile clean.
#pragma once

namespace idf_stub {
void record_log(const char* tag, const char* format, ...) noexcept;
}

#define ESP_LOGI(...) ::idf_stub::record_log(__VA_ARGS__)
#define ESP_LOGW(tag, ...) ((void)(tag))
#define ESP_LOGE(tag, ...) ((void)(tag))
