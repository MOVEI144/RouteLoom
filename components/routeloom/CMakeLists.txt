set(ROUTELOOM_CORE_SOURCES
  src/authority.cpp
  src/autonomy_wire.cpp
  src/byte_io.cpp
  src/channel_plan.cpp
  src/config.cpp
  src/config_cose.cpp
  src/config_dev.cpp
  src/config_wire.cpp
  src/crc32.cpp
  src/c_api.cpp
  src/counter_store.cpp
  src/discovery.cpp
  src/discovery_scope.cpp
  src/endpoint_wire.cpp
  src/gateway.cpp
  src/migration.cpp
  src/migration_wire.cpp
  src/node.cpp
  src/power.cpp
  src/replay.cpp
  src/routing.cpp
  src/status.cpp
  src/telemetry.cpp
  src/usb_bridge.cpp
  src/usb_codec.cpp
  src/usb_host_ops.cpp
  src/usb_session.cpp
  src/wire.cpp
)

# Vendored micro-ecc (BSD-2, third_party/micro-ecc/LICENSE.txt): the
# RLCP1_COSE_ESP256 permit verifier's P-256 backend. Identical arithmetic on
# host and firmware. Only secp256r1 is compiled; other curves stay disabled.
set(ROUTELOOM_UECC_SRC
  ${CMAKE_CURRENT_LIST_DIR}/../../third_party/micro-ecc/uECC.c
)
# uECC_* defines only affect uECC.c, so they are applied target-wide: the
# IDF component-requirements pass forbids set_source_files_properties.
set(ROUTELOOM_UECC_DEFS
  uECC_SUPPORTS_secp160r1=0 uECC_SUPPORTS_secp192r1=0
  uECC_SUPPORTS_secp224r1=0 uECC_SUPPORTS_secp256k1=0
  uECC_SUPPORTS_secp256r1=1 uECC_SQUARE_FUNC=0 uECC_OPTIMIZATION_LEVEL=2
)

if(COMMAND idf_component_register)
  idf_component_register(
    SRCS ${ROUTELOOM_CORE_SOURCES} ${ROUTELOOM_UECC_SRC}
    INCLUDE_DIRS include ${CMAKE_CURRENT_LIST_DIR}/../../third_party/micro-ecc
  )
  target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
  target_compile_definitions(${COMPONENT_LIB} PRIVATE ${ROUTELOOM_UECC_DEFS})
  target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra -Wpedantic)
  target_compile_options(${COMPONENT_LIB} PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Werror>)
else()
  add_library(routeloom_core STATIC ${ROUTELOOM_CORE_SOURCES} ${ROUTELOOM_UECC_SRC})
  target_include_directories(routeloom_core PUBLIC include)
  target_include_directories(routeloom_core PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/../../third_party/micro-ecc)
  target_compile_features(routeloom_core PUBLIC cxx_std_17)
  target_compile_definitions(routeloom_core PRIVATE ${ROUTELOOM_UECC_DEFS})
  target_compile_options(routeloom_core PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -Wpedantic -Werror>)
endif()
