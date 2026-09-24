// Test-only FreeRTOS stand-in (issue #117 host regression test): the test
// drives poll_once() directly, so task creation never runs — declared only
// to satisfy the reference from start_task().
#pragma once

#include "freertos/FreeRTOS.h"

typedef void (*TaskFunction_t)(void *);

BaseType_t xTaskCreatePinnedToCore(TaskFunction_t fn, const char *name,
                                   uint32_t stack_depth, void *param,
                                   UBaseType_t prio, TaskHandle_t *handle,
                                   BaseType_t core);
TaskHandle_t xTaskGetCurrentTaskHandle(void);
void vTaskDelay(TickType_t ticks);
void vTaskDelete(TaskHandle_t task);
uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t task);
