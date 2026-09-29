idf_component_register(SRCS "src/device.cpp" "src/device_config.cpp" "src/device_esp.cpp"
                            "src/device_migration.cpp"
                       INCLUDE_DIRS "include"
  REQUIRES routeloom routeloom_espnow nvs_flash esp_wifi esp_timer freertos
           esp_driver_usb_serial_jtag app_update)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
# ESP-IDF public headers use GNU extensions. Keep actionable project warnings
# strict without promoting extensions in those headers to errors.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
# The remote-config journal takes about 42 KB of static RAM. On ESP32-C3 only
# the endpoint resource profile keeps the boot heap floor that esp_wifi_init
# needs (docs/design/sdk-v1/ram-budget.md §5, issue #166); a relay or gateway
# profile with the journal would link and then fail to start the radio.
if(NOT CMAKE_BUILD_EARLY_EXPANSION AND CONFIG_ROUTELOOM_CONFIG
   AND CONFIG_IDF_TARGET_ESP32C3 AND NOT CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT)
  message(FATAL_ERROR
    "CONFIG_ROUTELOOM_CONFIG on ESP32-C3 needs "
    "CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT=y and CONFIG_ROUTELOOM_ROLE_ENDPOINT=y: "
    "the config journal does not fit the static RAM floor of the relay or gateway profiles")
endif()
