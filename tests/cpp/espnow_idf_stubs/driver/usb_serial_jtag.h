// Test-only ESP-IDF stand-in: USB-Serial/JTAG driver declarations. The
// mesh harness peers exchange USB bytes over their pipe instead, so these
// are never called — declared only to satisfy the quoted include.
#pragma once

#include "esp_err.h"

typedef struct {
  int rx_buffer_size;
  int tx_buffer_size;
} usb_serial_jtag_driver_config_t;

esp_err_t usb_serial_jtag_driver_install(usb_serial_jtag_driver_config_t* config);
int usb_serial_jtag_write_bytes(const void* data, unsigned length, unsigned timeout);
int usb_serial_jtag_read_bytes(void* data, unsigned length, unsigned timeout);
