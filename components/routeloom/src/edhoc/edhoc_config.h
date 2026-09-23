/*
 * RouteLoom build configuration for the vendored libedhoc
 * (components/routeloom/third_party/libedhoc, pinned in NOTICE).
 *
 * Upstream generates this header from cmake/edhoc_config.h.in (standalone
 * build) or takes the values from Kconfig (Zephyr). RouteLoom builds libedhoc
 * from its own CMake (host) and from the ESP-IDF component, so it owns the
 * header instead: every value below is sized for the SDK v1 profile
 * RLPSEC1 (docs/design/host-security-readiness/05-production-security.md §1:
 * method 0, cipher suite 2 = P-256 / ES256 / SHA-256 / AES-CCM-16-64-128),
 * with the ESP32-C3 (400 KB SRAM, no PSRAM) as the sizing floor.
 *
 * The upstream defaults are "maximal" (post-quantum KEM buffers of 800 B,
 * three suites, four methods, VLA stack buffers). Here:
 *   - KEM/NIKE buffers are 32 B: suite 2 transports only the P-256
 *     x-coordinate (RFC 9528 §3.7).
 *   - MAC buffers are 32 B: method 0 uses mac_length = hash_length = 32.
 *   - Two cipher suites fit the RFC 9529 §3 negotiation ([6, 2]); the
 *     RouteLoom backend implements suite 2 only.
 *   - One method per context (the caller picks it; RouteLoom uses 0).
 *   - The custom memory backend (2) routes every EDHOC_MEM_ALLOC to the
 *     per-session bounded arena in routeloom/edhoc.hpp; no VLA, no heap.
 *   - Logging is compiled out (no key material can reach a log).
 *
 * Every value is guarded with #ifndef like the upstream template, so a build
 * may still override one on the command line.
 */
#ifndef ROUTELOOM_EDHOC_CONFIG_H
#define ROUTELOOM_EDHOC_CONFIG_H

#ifndef CONFIG_LIBEDHOC_ENABLE
#define CONFIG_LIBEDHOC_ENABLE 1
#endif

/* Backend key handles are 4 bytes (slot index + generation, see edhoc.hpp). */
#ifndef CONFIG_LIBEDHOC_KEY_ID_LEN
#define CONFIG_LIBEDHOC_KEY_ID_LEN 4
#endif

#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES
#define CONFIG_LIBEDHOC_MAX_NR_OF_CIPHER_SUITES 2
#endif

#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_METHODS
#define CONFIG_LIBEDHOC_MAX_NR_OF_METHODS 1
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID
#define CONFIG_LIBEDHOC_MAX_LEN_OF_CONN_ID 4
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_ENCAPSULATION_KEY
#define CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_ENCAPSULATION_KEY 32
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT
#define CONFIG_LIBEDHOC_MAX_LEN_OF_KEM_CIPHERTEXT 32
#endif

#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_MAC
#define CONFIG_LIBEDHOC_MAX_LEN_OF_MAC 32
#endif

#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS
#define CONFIG_LIBEDHOC_MAX_NR_OF_EAD_TOKENS 3
#endif

/* kid = SHA-256 of the canonical public COSE_Key, all 32 bytes. */
#ifndef CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID
#define CONFIG_LIBEDHOC_MAX_LEN_OF_CRED_KEY_ID 32
#endif

/* X.509 is not used by RouteLoom; 1 is the smallest value upstream accepts. */
#ifndef CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN
#define CONFIG_LIBEDHOC_MAX_NR_OF_CERTS_IN_X509_CHAIN 1
#endif

#ifndef CONFIG_LIBEDHOC_LOG_LEVEL
#define CONFIG_LIBEDHOC_LOG_LEVEL 0
#endif

/* EDHOC_MEM_BACKEND_CUSTOM: edhoc_mem_alloc / edhoc_mem_free are provided by
 * components/routeloom/src/edhoc/edhoc_session.cpp. */
#ifndef CONFIG_LIBEDHOC_MEM_BACKEND
#define CONFIG_LIBEDHOC_MEM_BACKEND 2
#endif

/* The upstream reference cipher-suite sources (library/cipher_suites/, PSA)
 * are not vendored; RouteLoom binds its own callbacks. */
#ifndef CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE
#define CONFIG_LIBEDHOC_CIPHER_SUITE_0_ENABLE 0
#endif
#ifndef CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE
#define CONFIG_LIBEDHOC_CIPHER_SUITE_2_ENABLE 0
#endif
#ifndef CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE
#define CONFIG_LIBEDHOC_CIPHER_SUITE_4_ENABLE 0
#endif
#ifndef CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE
#define CONFIG_LIBEDHOC_CIPHER_SUITE_24_ENABLE 0
#endif
#ifndef CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE
#define CONFIG_LIBEDHOC_CIPHER_SUITE_PQC_1_ENABLE 0
#endif

#endif /* ROUTELOOM_EDHOC_CONFIG_H */
