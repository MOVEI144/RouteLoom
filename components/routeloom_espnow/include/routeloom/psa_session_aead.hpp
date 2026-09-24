#pragma once

#include "routeloom/session_bank.hpp"

namespace routeloom::espnow {

// AES-GCM-128 for the P4 RAM SessionBank (sdkv1::AeadGcm: 16-byte key,
// 12-byte nonce, 16-byte tag) through ESP-IDF's PSA Crypto API (the Mbed
// TLS pinned with ESP-IDF v6.0.3, AES hardware where the chip has it).
// Pass it as SecurityCoordinator::Deps::bank_aead on device builds: the
// portable core has no GCM of its own, so ESP-IDF builds have no default.
// Each call imports the key as a volatile PSA key, runs one multipart
// AEAD operation (ciphertext and tag land in their separate bank buffers
// with no staging copy) and destroys the key; psa_crypto_init() is
// called (idempotently) first. No heap, no retained state.
sdkv1::AeadGcm psa_session_aead_gcm() noexcept;

}  // namespace routeloom::espnow
