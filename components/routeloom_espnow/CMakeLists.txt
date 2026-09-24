idf_component_register(
  SRCS
    src/espnow_autonomy.cpp
    src/espnow_migration.cpp
    src/espnow_sdkv1.cpp
    src/espnow_sdkv1_entropy.cpp
    src/espnow_power.cpp
    src/espnow_runtime.cpp
    src/nvs_config_store.cpp
    src/nvs_counter_store.cpp
    src/nvs_cred_store.cpp
    src/nvs_ledger_store.cpp
    src/nvs_replay_store.cpp
    src/nvs_sdkv1_store.cpp
    src/nvs_security_floor.cpp
    src/nvs_trust_store.cpp
    src/psa_edhoc_aead.cpp
    src/psk_security.cpp
  INCLUDE_DIRS include
  REQUIRES routeloom esp_wifi esp_event esp_netif esp_timer freertos nvs_flash mbedtls bootloader_support esp_driver_usb_serial_jtag
)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
# ESP-IDF public headers intentionally use GNU C/C++ extensions. Keep strict
# warnings for RouteLoom itself without promoting those system-header
# extensions to errors through -Wpedantic.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
