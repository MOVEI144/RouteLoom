// Test-only FreeRTOS stand-in: critical sections synchronize external
// producers with the Owner, and handles are plain pointers.
#pragma once

#include <stdint.h>
#include <mutex>

typedef int BaseType_t;
typedef unsigned int UBaseType_t;
typedef unsigned int TickType_t;
typedef uint8_t StackType_t;
struct StaticTask_t {};
typedef void *TaskHandle_t;
typedef void *QueueHandle_t;

#define pdTRUE 1
#define pdPASS 1
// A 100 Hz tick (ESP-IDF's minimum) with ESP-IDF's truncating conversion,
// so waits that round a short ms interval down to 0 ticks are visible.
#define configTICK_RATE_HZ 100
#define pdMS_TO_TICKS(ms) ((TickType_t)(((uint64_t)(ms) * configTICK_RATE_HZ) / 1000U))
#define tskNO_AFFINITY (-1)

using portMUX_TYPE = std::recursive_mutex;
#define portMUX_INITIALIZER_UNLOCKED \
  {}
#define portENTER_CRITICAL(mux) ((mux)->lock())
#define portEXIT_CRITICAL(mux) ((mux)->unlock())
