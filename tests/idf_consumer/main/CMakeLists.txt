# A C and a C++ translation unit, each on the public headers only.
idf_component_register(SRCS "main.c" "consumer.cpp" REQUIRES routeloom_device)
target_compile_features(${COMPONENT_LIB} PRIVATE cxx_std_17)
target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Werror)
