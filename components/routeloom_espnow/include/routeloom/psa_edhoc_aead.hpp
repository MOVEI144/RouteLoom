#pragma once

#include "routeloom/edhoc.hpp"

namespace routeloom::espnow {

// AES-CCM-16-64-128 for routeloom::edhoc (EDHOC cipher suite 2) through
// ESP-IDF's PSA Crypto API (the Mbed TLS pinned with ESP-IDF v6.0.3, AES
// hardware where the chip has it). Pass it as SessionConfig::aead: the
// portable core's builtin AES-CCM is host-only, so ESP-IDF builds have no
// default. Each call imports the 16-byte key as a volatile PSA key, runs
// one AEAD operation and destroys the key; psa_crypto_init() is called
// (idempotently) first.
//
// docs/design/sdk-v1/08-implementation-plan.md P2-1 supplies only this AEAD
// hook; P-256, SHA-256 and HKDF stay on the portable backend. A full PSA
// backend (hardware ECC/SHA) and the C3/S3 timing, stack and heap figures
// are P2-2. Nothing in the firmware calls this yet.
const edhoc::AeadCcm* psa_edhoc_aead_ccm() noexcept;

}  // namespace routeloom::espnow
