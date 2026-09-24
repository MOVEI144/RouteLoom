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
  src/device_credential.cpp
  src/discovery.cpp
  src/discovery_scope.cpp
  src/endpoint_wire.cpp
  src/gateway.cpp
  src/group.cpp
  src/group_replay.cpp
  src/group_wire.cpp
  src/kdf.cpp
  src/key_schedule.cpp
  src/migration.cpp
  src/migration_wire.cpp
  src/node.cpp
  src/node_status.cpp
  src/peer_state.cpp
  src/power.cpp
  src/replay.cpp
  src/rlcw1.cpp
  src/rlres1.cpp
  src/route_scale.cpp
  src/routing.cpp
  src/sdkv1_authority.cpp
  src/sdkv1_blob_storage.cpp
  src/sdkv1_ead.cpp
  src/sdkv1_join_candidates.cpp
  src/sdkv1_join_handshake.cpp
  src/sdkv1_joiner.cpp
  src/sdkv1_join_relay.cpp
  src/sdkv1_join_transport.cpp
  src/sdkv1_records.cpp
  src/sdkv1_store.cpp
  src/status.cpp
  src/telemetry.cpp
  src/trust_manifest.cpp
  src/trust_store.cpp
  src/trust_view.cpp
  src/usb_bridge.cpp
  src/usb_codec.cpp
  src/usb_host_ops.cpp
  src/usb_session.cpp
  src/wire.cpp
)

# Vendored micro-ecc (BSD-2, third_party/micro-ecc/LICENSE.txt inside this
# component): the RLCP1_COSE_ESP256 permit verifier's P-256 backend. Identical
# arithmetic on host and firmware. Only secp256r1 is compiled; other curves
# stay disabled. The copy lives inside the component so the component stays
# self-contained when fetched by the IDF component manager (a git `path`
# dependency copies only this directory).
set(ROUTELOOM_UECC_SRC
  ${CMAKE_CURRENT_LIST_DIR}/third_party/micro-ecc/uECC.c
)
# uECC_* defines only affect uECC.c, so they are applied target-wide: the
# IDF component-requirements pass forbids set_source_files_properties.
set(ROUTELOOM_UECC_DEFS
  uECC_SUPPORTS_secp160r1=0 uECC_SUPPORTS_secp192r1=0
  uECC_SUPPORTS_secp224r1=0 uECC_SUPPORTS_secp256k1=0
  uECC_SUPPORTS_secp256r1=1 uECC_SQUARE_FUNC=0 uECC_OPTIMIZATION_LEVEL=2
)

# Vendored libedhoc (MIT) + zcbor (Apache-2.0), the EDHOC (RFC 9528) engine
# of the SDK v1 join/link handshakes (docs/design/sdk-v1/08 P2-1; pins and
# licenses in NOTICE and third_party/VENDORED.json). RouteLoom's bounded
# backend is src/edhoc/. Built on every target so firmware CI compiles it for
# the 32-bit ESP32 chips, but nothing in the firmware calls it yet, so the
# linker keeps none of it (no static RAM is added; see ram-budget.md).
include(${CMAKE_CURRENT_LIST_DIR}/edhoc_sources.cmake)
# Third-party C only. zcbor's float16 helpers type-pun through pointer casts
# (zcbor_common.c; undefined behaviour under strict aliasing, and GCC -O2/-Os
# then reports -Wstrict-aliasing and -Wuninitialized, both in -Wall), so the
# vendored C is compiled with -fno-strict-aliasing, which makes that code
# well-defined (EDHOC never encodes floats anyway). Two upstream unused-code
# warnings (libedhoc's comp_message_number without LIBEDHOC_TESTS,
# zcbor_any_skip's `additional`) are silenced. ESP-IDF promotes -Wall to
# errors with -Werror=all, which is why this matters there; RouteLoom's own
# C++ keeps -Werror, and src/edhoc/edhoc_port.c is the only RouteLoom C file.
set(ROUTELOOM_THIRD_PARTY_C_RELAX
  -fno-strict-aliasing -Wno-unused-function -Wno-unused-but-set-variable
)

# Dedup pool capacity (docs/reference/resource-profiles.json dedup_entries,
# issue #39) is a compile-time resource-profile constant. It changes
# sizeof(MeshNode), so it is a PUBLIC definition: every translation unit that
# includes the headers must see the same value. ESP-IDF selects it through the
# component Kconfig (RouteLoom -> Dedup capacity profile); host builds through
# ROUTELOOM_DEDUP_PROFILE. The default is the relay profile.
if(COMMAND idf_component_register)
  # ESP-IDF: libedhoc + zcbor + the glue, without the host-only TF-PSA-Crypto
  # AES/CCM/GCM subset (its mbedtls_* symbols would duplicate ESP-IDF's own
  # Mbed TLS); builtin_aead_ccm()/builtin_aead_gcm() are nullptr here and the
  # adapter passes PSA implementations (routeloom_espnow, psa_edhoc_aead.hpp
  # and psa_aead_gcm.hpp).
  idf_component_register(
    SRCS ${ROUTELOOM_CORE_SOURCES} ${ROUTELOOM_UECC_SRC}
         ${ROUTELOOM_LIBEDHOC_SRC} ${ROUTELOOM_ZCBOR_SRC} ${ROUTELOOM_EDHOC_GLUE_SRC}
    INCLUDE_DIRS include ${CMAKE_CURRENT_LIST_DIR}/third_party/micro-ecc
    PRIV_INCLUDE_DIRS ${ROUTELOOM_EDHOC_INCLUDE_DIRS}
  )
  target_compile_features(${COMPONENT_LIB} PUBLIC cxx_std_17)
  target_compile_definitions(${COMPONENT_LIB} PRIVATE ${ROUTELOOM_UECC_DEFS}
    ${ROUTELOOM_EDHOC_C_DEFS})
  # -Wpedantic is C++-only here: ESP-IDF's libc wrappers (esp_libc
  # platform_include stdio.h/time.h) use #include_next and reach C
  # translation units as ordinary -I headers, so C -Wpedantic under ESP-IDF's
  # -Werror rejects any vendored C file that includes <stdio.h> (libedhoc's
  # log backend does). The host build keeps -Wpedantic on its C targets.
  target_compile_options(${COMPONENT_LIB} PRIVATE -Wall -Wextra
    $<$<COMPILE_LANGUAGE:CXX>:-Wpedantic>)
  target_compile_options(${COMPONENT_LIB} PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Werror>
    "$<$<COMPILE_LANGUAGE:C>:${ROUTELOOM_THIRD_PARTY_C_RELAX}>")
  if(CONFIG_ROUTELOOM_DEDUP_CAPACITY)
    target_compile_definitions(${COMPONENT_LIB} PUBLIC
      ROUTELOOM_DEDUP_CAPACITY=${CONFIG_ROUTELOOM_DEDUP_CAPACITY})
  endif()
else()
  set(ROUTELOOM_DEDUP_PROFILE "relay" CACHE STRING
    "Dedup capacity resource profile: leaf (32), relay (96) or gateway (256)")
  set_property(CACHE ROUTELOOM_DEDUP_PROFILE PROPERTY STRINGS leaf relay gateway)
  if(ROUTELOOM_DEDUP_PROFILE STREQUAL "leaf")
    set(ROUTELOOM_DEDUP_CAPACITY 32)
  elseif(ROUTELOOM_DEDUP_PROFILE STREQUAL "relay")
    set(ROUTELOOM_DEDUP_CAPACITY 96)
  elseif(ROUTELOOM_DEDUP_PROFILE STREQUAL "gateway")
    set(ROUTELOOM_DEDUP_CAPACITY 256)
  else()
    message(FATAL_ERROR
      "ROUTELOOM_DEDUP_PROFILE must be leaf, relay or gateway "
      "(got '${ROUTELOOM_DEDUP_PROFILE}')")
  endif()
  # Vendored C for EDHOC in its own target, so its (relaxed) warning set stays
  # scoped to it — like micro-ecc, upstream code builds without RouteLoom's
  # -Werror. Host builds add the TF-PSA-Crypto AES/CCM subset.
  add_library(routeloom_edhoc_third_party STATIC
    ${ROUTELOOM_LIBEDHOC_SRC} ${ROUTELOOM_ZCBOR_SRC} ${ROUTELOOM_TFPSA_SRC})
  set_target_properties(routeloom_edhoc_third_party PROPERTIES
    C_STANDARD 11 C_STANDARD_REQUIRED ON C_EXTENSIONS ON)
  target_include_directories(routeloom_edhoc_third_party PRIVATE
    ${ROUTELOOM_EDHOC_INCLUDE_DIRS} ${ROUTELOOM_TFPSA_INCLUDE_DIRS})
  target_compile_definitions(routeloom_edhoc_third_party PRIVATE
    ${ROUTELOOM_EDHOC_C_DEFS} ${ROUTELOOM_TFPSA_DEFS})
  target_compile_options(routeloom_edhoc_third_party PRIVATE
    ${ROUTELOOM_THIRD_PARTY_C_RELAX})

  # libedhoc's headers for the glue and for tests that drive the raw API.
  add_library(routeloom_edhoc_headers INTERFACE)
  target_include_directories(routeloom_edhoc_headers INTERFACE
    ${ROUTELOOM_EDHOC_INCLUDE_DIRS})

  add_library(routeloom_core STATIC ${ROUTELOOM_CORE_SOURCES} ${ROUTELOOM_UECC_SRC}
    ${ROUTELOOM_EDHOC_GLUE_SRC})
  target_include_directories(routeloom_core PUBLIC include)
  target_include_directories(routeloom_core PRIVATE
    ${CMAKE_CURRENT_LIST_DIR}/third_party/micro-ecc ${ROUTELOOM_TFPSA_API_INCLUDE_DIRS})
  target_link_libraries(routeloom_core PRIVATE routeloom_edhoc_headers
    routeloom_edhoc_third_party)
  target_compile_features(routeloom_core PUBLIC cxx_std_17)
  target_compile_definitions(routeloom_core PRIVATE ${ROUTELOOM_UECC_DEFS}
    ${ROUTELOOM_EDHOC_C_DEFS} ${ROUTELOOM_TFPSA_DEFS} ROUTELOOM_EDHOC_BUILTIN_AEAD)
  target_compile_options(routeloom_core PRIVATE
    $<$<COMPILE_LANGUAGE:CXX>:-Wall -Wextra -Wpedantic -Werror>)
  # The one RouteLoom-owned C file gets the same strictness as the C++.
  set_source_files_properties(${CMAKE_CURRENT_LIST_DIR}/src/edhoc/edhoc_port.c
    PROPERTIES COMPILE_OPTIONS "-Wall;-Wextra;-Wpedantic;-Werror")
  target_compile_definitions(routeloom_core PUBLIC
    ROUTELOOM_DEDUP_CAPACITY=${ROUTELOOM_DEDUP_CAPACITY})
endif()
