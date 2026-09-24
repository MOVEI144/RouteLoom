// Test-only ESP-IDF stand-in (issue #117 host regression test): the timer
// reads the fake clock driven through idf_stubs.hpp, so tests advance the
// runtime's time deterministically.
#pragma once

#include <stdint.h>

int64_t esp_timer_get_time(void);
