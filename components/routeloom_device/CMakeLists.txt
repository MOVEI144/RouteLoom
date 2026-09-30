idf_component_register(SRCS "src/device.cpp" "src/device_config.cpp" "src/device_esp.cpp"
                            "src/device_migration.cpp"
                       INCLUDE_DIRS "include"
  REQUIRES routeloom routeloom_espnow nvs_flash esp_wifi esp_timer freertos
           esp_driver_usb_serial_jtag app_update)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
# ESP-IDF public headers use GNU extensions. Keep actionable project warnings
# strict without promoting extensions in those headers to errors.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
if(NOT CMAKE_BUILD_EARLY_EXPANSION)
  # IDF keeps unknown assignments in sdkconfig. Refuse a retired explicit
  # selection before its old value silently becomes the new default.
  string(CONCAT retired_mode "CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY" "_FIXTURE=y")
  if(SDKCONFIG)
    set(config_path "${SDKCONFIG}")
  else()
    set(config_path "${PROJECT_SOURCE_DIR}/sdkconfig")
  endif()
  if(EXISTS "${config_path}")
    file(STRINGS "${config_path}" retired_selected REGEX "^${retired_mode}$")
    if(retired_selected)
      message(FATAL_ERROR "The retired RouteLoom security mode was explicitly selected")
    endif()
  endif()
endif()
# The remote-config journal takes about 42 KB of static RAM. On ESP32-C3 only
# the endpoint resource profile keeps the boot heap floor that esp_wifi_init
# needs (docs/design/sdk-v1/ram-budget.md §5, issue #166); a relay or gateway
# profile with the journal would link and then fail to start the radio.
if(NOT CMAKE_BUILD_EARLY_EXPANSION AND CONFIG_ROUTELOOM_CONFIG
   AND CONFIG_IDF_TARGET_ESP32C3 AND
   (NOT CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT OR NOT CONFIG_ROUTELOOM_ROLE_ENDPOINT))
  message(FATAL_ERROR
    "CONFIG_ROUTELOOM_CONFIG on ESP32-C3 needs "
    "CONFIG_ROUTELOOM_RESOURCE_PROFILE_ENDPOINT=y and CONFIG_ROUTELOOM_ROLE_ENDPOINT=y: "
    "the config journal does not fit the static RAM floor of the relay or gateway profiles")
endif()
