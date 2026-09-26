// Test-only ESP-IDF stand-in: application-description declarations. Only
// the fields the linked firmware code reads are modelled.
#pragma once

typedef struct {
  char version[32];
} esp_app_desc_t;

const esp_app_desc_t* esp_app_get_description(void);
