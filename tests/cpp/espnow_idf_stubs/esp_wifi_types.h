// Test-only ESP-IDF stand-in (issue #117 host regression test): the Wi-Fi RX
// control fields the real runtime reads. Sizes mirror the IDF layout the
// code depends on (8-bit rssi/channel, 32-bit MAC timestamp).
#pragma once

#include <stdint.h>

typedef struct {
  int8_t rssi;
  uint8_t channel;
  uint32_t timestamp;
} wifi_pkt_rx_ctrl_t;
