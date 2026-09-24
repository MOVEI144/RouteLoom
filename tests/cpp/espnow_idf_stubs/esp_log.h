// Test-only ESP-IDF stand-in (issue #117 host regression test): log macros
// discard their arguments so host runs stay quiet.
#pragma once

// `...`-only form: call sites with no format arguments (legal under the
// GNU extension the real IDF headers rely on) must also expand cleanly.
#define ESP_LOGI(...) ((void)0)
#define ESP_LOGW(...) ((void)0)
