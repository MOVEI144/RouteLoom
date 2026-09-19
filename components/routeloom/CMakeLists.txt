set(ROUTELOOM_CORE_SOURCES
  src/authority.cpp
  src/byte_io.cpp
  src/crc32.cpp
  src/c_api.cpp
  src/counter_store.cpp
  src/node.cpp
  src/routing.cpp
  src/status.cpp
  src/wire.cpp
)

if(COMMAND idf_component_register)
  idf_component_register(
    SRCS ${ROUTELOOM_CORE_SOURCES}
    INCLUDE_DIRS include
  )
  target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
  target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic -Werror)
else()
  add_library(routeloom_core STATIC ${ROUTELOOM_CORE_SOURCES})
  target_include_directories(routeloom_core PUBLIC include)
  target_compile_features(routeloom_core PUBLIC cxx_std_17)
  target_compile_options(routeloom_core PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()
