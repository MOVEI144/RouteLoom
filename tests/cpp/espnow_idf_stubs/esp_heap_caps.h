// Test-only ESP-IDF stand-in for Wi-Fi startup heap diagnostics.
#pragma once

#include <stddef.h>

#define MALLOC_CAP_8BIT 1
static inline size_t heap_caps_get_free_size(unsigned) { return 0; }
static inline size_t heap_caps_get_largest_free_block(unsigned) { return 0; }
