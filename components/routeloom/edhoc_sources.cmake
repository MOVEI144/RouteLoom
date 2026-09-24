# EDHOC sources for the routeloom component (docs/design/sdk-v1/08 P2-1).
#
# Explicit lists, mirroring upstream libedhoc's cmake/sources.cmake at the
# pinned commit (NOTICE): LIBEDHOC_CORE_SOURCES and
# LIBEDHOC_BACKEND_CBOR_SOURCES, plus the zcbor runtime libedhoc's generated
# CBOR code is built against. Upstream's library/cipher_suites/ (PSA
# reference implementations) is not vendored: RouteLoom binds its own
# callbacks (src/edhoc/edhoc_session.cpp).
#
# Plain set() only: this file is also read during ESP-IDF's
# component-requirements pass, which runs in CMake script mode.

set(ROUTELOOM_LIBEDHOC_DIR ${CMAKE_CURRENT_LIST_DIR}/third_party/libedhoc)
set(ROUTELOOM_ZCBOR_DIR ${CMAKE_CURRENT_LIST_DIR}/third_party/zcbor)
set(ROUTELOOM_TFPSA_DIR ${CMAKE_CURRENT_LIST_DIR}/third_party/tf-psa-crypto)

set(ROUTELOOM_LIBEDHOC_SRC
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/classic/edhoc_classic_message_1.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/classic/edhoc_classic_message_2.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/classic/edhoc_classic_message_3.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/classic/edhoc_classic_message_4.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/psk/edhoc_psk_message_2.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/psk/edhoc_psk_message_3.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_error_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_exporter_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_cbor_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_kdf_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_transcript_hash_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_ead_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_key_slot_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_mac_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_cipher_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_key_schedule_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_plaintext_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_connection_id_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_credentials_internal.c
  ${ROUTELOOM_LIBEDHOC_DIR}/library/core/edhoc_coap.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_bstr_type_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_bstr_type_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_connection_identifier_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_connection_identifier_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_ead_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_ead_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_enc_structure_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_enc_structure_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_id_cred_x_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_id_cred_x_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_info_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_info_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_int_type_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_int_type_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_1_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_1_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_2_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_2_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_3_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_3_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_4_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_4_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_error_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_message_error_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_2_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_2_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_3_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_3_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_4_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_4_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_2a_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_2a_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_3a_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_3a_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_3b_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_plaintext_3b_encode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_sig_structure_decode.c
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/src/backend_cbor_sig_structure_encode.c
)

set(ROUTELOOM_ZCBOR_SRC
  ${ROUTELOOM_ZCBOR_DIR}/src/zcbor_common.c
  ${ROUTELOOM_ZCBOR_DIR}/src/zcbor_decode.c
  ${ROUTELOOM_ZCBOR_DIR}/src/zcbor_encode.c
)

# Header search path of the vendored C code and of the RouteLoom glue that
# calls it. src/edhoc holds the RouteLoom-owned edhoc_config.h that replaces
# upstream's generated one.
set(ROUTELOOM_EDHOC_INCLUDE_DIRS
  ${CMAKE_CURRENT_LIST_DIR}/src/edhoc
  ${ROUTELOOM_LIBEDHOC_DIR}/include
  ${ROUTELOOM_LIBEDHOC_DIR}/library/internal
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/cbor/include
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/memory/include
  ${ROUTELOOM_LIBEDHOC_DIR}/backends/log/include
  ${ROUTELOOM_ZCBOR_DIR}/include
)

# upstream builds zcbor with ZCBOR_CANONICAL (shortest-form encoding), which
# EDHOC's deterministic CBOR requires.
set(ROUTELOOM_EDHOC_C_DEFS ZCBOR_CANONICAL)

# RouteLoom glue (built on every target).
set(ROUTELOOM_EDHOC_GLUE_SRC
  ${CMAKE_CURRENT_LIST_DIR}/src/edhoc/edhoc_session.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/edhoc/edhoc_aead_builtin.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/edhoc/aead_gcm_builtin.cpp
  ${CMAKE_CURRENT_LIST_DIR}/src/edhoc/edhoc_port.c
)

# Host only: TF-PSA-Crypto builtin AES + CCM (AES-CCM-16-64-128 of suite 2)
# + GCM (AES-GCM-128 of the SDK v1 authority channel) and exactly the
# headers they include under src/edhoc/tf_psa_crypto_config.h.
set(ROUTELOOM_TFPSA_SRC
  ${ROUTELOOM_TFPSA_DIR}/drivers/builtin/src/aes.c
  ${ROUTELOOM_TFPSA_DIR}/drivers/builtin/src/ccm.c
  ${ROUTELOOM_TFPSA_DIR}/drivers/builtin/src/gcm.c
  ${ROUTELOOM_TFPSA_DIR}/drivers/builtin/src/block_cipher.c
  ${ROUTELOOM_TFPSA_DIR}/platform/platform_util.c
  ${ROUTELOOM_TFPSA_DIR}/utilities/constant_time.c
)
set(ROUTELOOM_TFPSA_INCLUDE_DIRS
  ${CMAKE_CURRENT_LIST_DIR}/src/edhoc
  ${ROUTELOOM_TFPSA_DIR}/include
  ${ROUTELOOM_TFPSA_DIR}/drivers/builtin/include
  ${ROUTELOOM_TFPSA_DIR}/drivers/builtin/src
  ${ROUTELOOM_TFPSA_DIR}/core
  ${ROUTELOOM_TFPSA_DIR}/utilities
)
# What the glue (src/edhoc/edhoc_aead_builtin.cpp) needs for mbedtls/private/ccm.h.
set(ROUTELOOM_TFPSA_API_INCLUDE_DIRS
  ${ROUTELOOM_TFPSA_DIR}/include
  ${ROUTELOOM_TFPSA_DIR}/drivers/builtin/include
)
set(ROUTELOOM_TFPSA_DEFS "TF_PSA_CRYPTO_CONFIG_FILE=\"tf_psa_crypto_config.h\"")
