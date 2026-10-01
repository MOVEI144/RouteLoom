idf_component_register(SRCS "main.c" INCLUDE_DIRS "." REQUIRES routeloom_device)
# ESP-IDF public headers use GNU extensions. Keep actionable project warnings
# strict without promoting extensions in those headers to errors.
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
