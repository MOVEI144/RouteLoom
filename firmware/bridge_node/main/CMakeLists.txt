idf_component_register(SRCS "main.cpp" INCLUDE_DIRS "." REQUIRES routeloom routeloom_espnow nvs_flash esp_driver_usb_serial_jtag app_update)
# The public Kconfig default must not reach a deployment silently: it is
# published in this repo, so any host holding it can open the USB session.
if(CONFIG_ROUTELOOM_USB_DEV_SECRET STREQUAL "routeloom-dev-secret")
  message(WARNING
    "CONFIG_ROUTELOOM_USB_DEV_SECRET is the public development default; "
    "set a private secret for any real deployment")
endif()
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
# ESP-IDF public headers use GNU extensions. Keep actionable project warnings
# strict without promoting extensions in those headers to errors.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
