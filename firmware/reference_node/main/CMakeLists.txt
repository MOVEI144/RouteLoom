idf_component_register(SRCS "main.cpp" INCLUDE_DIRS "." REQUIRES routeloom routeloom_espnow nvs_flash)
target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
