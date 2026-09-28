// Test-only ESP-IDF stand-in: log payloads stay quiet in host tests.
#pragma once

// Use the tag, while keeping formatted arguments unevaluated in host tests.
#define ESP_LOGI(tag, ...) ((void)(tag))
#define ESP_LOGW(tag, ...) ((void)(tag))
#define ESP_LOGE(tag, ...) ((void)(tag))
