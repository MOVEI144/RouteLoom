// Test-only FreeRTOS stand-in (issue #117 host regression test): single
// thread, so critical sections are no-ops and handles are plain pointers.
#pragma once

#include <stdint.h>

typedef int BaseType_t;
typedef unsigned int UBaseType_t;
typedef unsigned int TickType_t;
typedef uint8_t StackType_t;
typedef void *TaskHandle_t;
typedef void *QueueHandle_t;

#define pdTRUE 1
#define pdPASS 1
#define pdMS_TO_TICKS(ms) ((TickType_t)(ms))
#define tskNO_AFFINITY (-1)

typedef struct {
  int dummy;
} portMUX_TYPE;
#define portMUX_INITIALIZER_UNLOCKED \
  { 0 }
#define portENTER_CRITICAL(mux) ((void)0)
#define portEXIT_CRITICAL(mux) ((void)0)
