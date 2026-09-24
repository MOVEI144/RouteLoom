#pragma once

#include "routeloom/aead_gcm.hpp"

namespace routeloom::espnow {

// AES-GCM-128 for the SDK v1 channel AEADs (routeloom/aead_gcm.hpp) through
// ESP-IDF's PSA Crypto API (the Mbed TLS pinned with ESP-IDF v6.0.3, AES
// hardware where the chip has it). Pass it as the authority client's AEAD:
// the portable core's builtin AES-GCM is host-only, so ESP-IDF builds have
// no default. Each call imports the 16-byte key as a volatile PSA key, runs
// one AEAD operation and destroys the key; psa_crypto_init() is called
// (idempotently) first.
//
// G-SEC P5 supplies only this AEAD hook; the authority channel's SHA-256
// and HKDF stay on the portable backend. A full PSA backend (hardware
// SHA) and the C3/S3 timing, stack and heap figures are P5-4/P8. Nothing
// in the firmware calls this yet.
const AeadGcm* psa_aead_gcm() noexcept;

}  // namespace routeloom::espnow
