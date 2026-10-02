// Test-only FreeRTOS stand-in (issue #117 host regression test): the test
// drives poll_once() directly, so task creation never runs — declared only
// to satisfy the reference from start_task().
#pragma once

#include "freertos/FreeRTOS.h"

typedef void (*TaskFunction_t)(void *);

#define tskIDLE_PRIORITY 0
#define portMAX_DELAY ((TickType_t)0xFFFFFFFFu)

TaskHandle_t xTaskCreateStatic(TaskFunction_t fn, const char* name,
                             uint32_t stack_depth, void* param,
                             UBaseType_t prio, StackType_t* stack,
                             StaticTask_t* storage);

BaseType_t xTaskCreate(TaskFunction_t fn, const char *name,
                       uint32_t stack_depth, void *param,
                       UBaseType_t prio, TaskHandle_t *handle);
BaseType_t xTaskCreatePinnedToCore(TaskFunction_t fn, const char *name,
                                   uint32_t stack_depth, void *param,
                                   UBaseType_t prio, TaskHandle_t *handle,
                                   BaseType_t core);
void vTaskSuspend(TaskHandle_t task);
TaskHandle_t xTaskGetCurrentTaskHandle(void);
UBaseType_t uxTaskPriorityGet(TaskHandle_t task);
void vTaskPrioritySet(TaskHandle_t task, UBaseType_t priority);
void vTaskDelay(TickType_t ticks);
void vTaskDelete(TaskHandle_t task);
uint32_t uxTaskGetStackHighWaterMark(TaskHandle_t task);
const char* pcTaskGetName(TaskHandle_t task);

void xTaskNotifyGive(TaskHandle_t task);
uint32_t ulTaskNotifyTake(BaseType_t clear, TickType_t ticks);
