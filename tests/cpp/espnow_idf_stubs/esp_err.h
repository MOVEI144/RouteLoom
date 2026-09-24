// Test-only ESP-IDF stand-in (issue #117 host regression test): declares just
// the error type and codes the real espnow runtime references. Resolved from
// this directory only on host test builds — never on a firmware path.
#pragma once

typedef int esp_err_t;
#define ESP_OK 0
#define ESP_FAIL 0x101
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_ESPNOW_NO_MEM 0x1201
#define ESP_ERR_ESPNOW_NOT_FOUND 0x1204
#define ESP_ERR_ESPNOW_FULL 0x1206
#define ESP_ERR_ESPNOW_EXIST 0x1207
#define ESP_ERR_ESPNOW_CHAN 0x1209
