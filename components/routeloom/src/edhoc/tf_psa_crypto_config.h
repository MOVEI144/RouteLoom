/*
 * RouteLoom configuration for the vendored TF-PSA-Crypto subset
 * (components/routeloom/third_party/tf-psa-crypto, pinned in NOTICE).
 *
 * Selected through TF_PSA_CRYPTO_CONFIG_FILE, so it replaces the upstream
 * include/psa/crypto_config.h (which is not vendored). Only the builtin AES
 * block cipher and the CCM and GCM modes are compiled: they back the
 * AES-CCM-16-64-128 AEAD of EDHOC cipher suite 2 and the AES-GCM-128 AEAD of
 * the SDK v1 authority channel in host builds
 * (components/routeloom/src/edhoc/edhoc_aead_builtin.cpp and
 * aead_gcm_builtin.cpp). No PSA core, no RNG, no other algorithm is built;
 * the ESP-IDF component does not compile this subset at all (firmware uses
 * the PSA API of ESP-IDF's own Mbed TLS instead).
 *
 * MBEDTLS_PSA_CRYPTO_C is what makes the builtin-driver adjustment headers
 * turn PSA_WANT_KEY_TYPE_AES / PSA_WANT_ALG_CCM / PSA_WANT_ALG_GCM into
 * MBEDTLS_AES_C / MBEDTLS_CCM_C / MBEDTLS_GCM_C; psa_crypto.c itself is not
 * compiled, so MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG only keeps the configuration
 * consistent (no entropy module is pulled in).
 *
 * MBEDTLS_AES_ROM_TABLES keeps the AES tables in .rodata (no RAM table
 * generation, no global init state); MBEDTLS_AES_FEWER_TABLES shrinks them to
 * one quarter. The builtin AES is table based and therefore not constant time
 * against a co-located cache attacker; it is used on the host only (see
 * docs/design/sdk-v1/08-implementation-plan.md, P2-1).
 */
#ifndef ROUTELOOM_TF_PSA_CRYPTO_CONFIG_H
#define ROUTELOOM_TF_PSA_CRYPTO_CONFIG_H

#define PSA_WANT_KEY_TYPE_AES 1
#define PSA_WANT_ALG_CCM 1
#define PSA_WANT_ALG_GCM 1

#define MBEDTLS_PSA_CRYPTO_C
#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG

#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_AES_FEWER_TABLES

#endif /* ROUTELOOM_TF_PSA_CRYPTO_CONFIG_H */
