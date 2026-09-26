idf_component_register(SRCS "main.cpp" INCLUDE_DIRS "." REQUIRES routeloom_node_boot routeloom_bench esp_app_format esp_timer heap)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
# ESP-IDF public headers use GNU extensions. Keep actionable project warnings
# strict without promoting extensions in those headers to errors.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
