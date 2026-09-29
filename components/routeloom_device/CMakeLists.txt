idf_component_register(SRCS "src/device.cpp" "src/device_config.cpp" "src/device_esp.cpp"
                       INCLUDE_DIRS "include"
  REQUIRES routeloom routeloom_espnow nvs_flash esp_wifi esp_timer freertos
           esp_driver_usb_serial_jtag app_update)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
# ESP-IDF public headers use GNU extensions. Keep actionable project warnings
# strict without promoting extensions in those headers to errors.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
# The public Kconfig default must not reach a deployment silently: it is
# published in this repo, so any host holding it can open the USB session.
if(CONFIG_ROUTELOOM_ROLE_GATEWAY AND CONFIG_ROUTELOOM_SECURITY_MODE_LEGACY_FIXTURE AND
   CONFIG_ROUTELOOM_USB_DEV_SECRET STREQUAL "routeloom-dev-secret")
  message(WARNING
    "CONFIG_ROUTELOOM_USB_DEV_SECRET is the public development default; "
    "set a private secret for any real deployment")
endif()
