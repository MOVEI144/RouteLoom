idf_component_register(SRCS "src/node_boot.cpp" INCLUDE_DIRS "include"
  REQUIRES routeloom routeloom_espnow nvs_flash esp_wifi esp_timer freertos
           esp_driver_usb_serial_jtag app_update)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
# ESP-IDF public headers use GNU extensions. Keep actionable project warnings
# strict without promoting extensions in those headers to errors.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
