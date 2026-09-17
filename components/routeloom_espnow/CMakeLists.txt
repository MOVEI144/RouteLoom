idf_component_register(
  SRCS
    src/espnow_runtime.cpp
    src/nvs_counter_store.cpp
    src/psk_security.cpp
  INCLUDE_DIRS include
  REQUIRES routeloom esp_wifi esp_event esp_netif esp_timer freertos nvs_flash mbedtls
)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
