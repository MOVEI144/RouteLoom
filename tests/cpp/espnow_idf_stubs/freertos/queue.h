// Test-only FreeRTOS stand-in (issue #117 host regression test): heap-backed
// FIFO queues sized by xQueueCreate, freed by vQueueDelete.
#pragma once

#include "freertos/FreeRTOS.h"

QueueHandle_t xQueueCreate(UBaseType_t length, UBaseType_t item_size);
BaseType_t xQueueSend(QueueHandle_t queue, const void *item, TickType_t ticks);
BaseType_t xQueueReceive(QueueHandle_t queue, void *item, TickType_t ticks);
BaseType_t xQueuePeek(QueueHandle_t queue, void *item, TickType_t ticks);
void vQueueDelete(QueueHandle_t queue);
