#pragma once

extern "C" void routeloom_test_log_error(const char* tag, const char* format, ...);

#define ESP_LOGE(...) routeloom_test_log_error(__VA_ARGS__)
