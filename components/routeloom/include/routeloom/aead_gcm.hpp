#pragma once

// AES-GCM-128 backend seam for the SDK v1 channel AEADs (authority channel
// of docs/design/sdk-v1/03-key-hierarchy.md §3/§5.3, plan G-SEC P5). The
// portable core never implements AES or GHASH itself: the owner passes an
// `AeadGcm` whose callbacks come from an audited backend — the vendored
// TF-PSA-Crypto builtin AES + GCM on host builds (`builtin_aead_gcm()`), or
// ESP-IDF's Mbed TLS through PSA on firmware (`routeloom_espnow`'s
// `psa_aead_gcm()`, which the IDF build wires in because the vendored
// subset's mbedtls_* symbols would duplicate ESP-IDF's own Mbed TLS).
//
// Shape mirrors routeloom::edhoc::AeadCcm: `seal` writes ciphertext || tag
// (plaintext.size + 16 bytes); `open` takes ciphertext || tag and returns
// true only when the tag verified, leaving the output zeroed otherwise.
// Both return false on any failure and never throw.
//
// `open`'s output may alias its input with a forward offset (the authority
// channel decrypts in place: plaintext at the buffer front, ciphertext 12
// bytes ahead of it). Backends must therefore read each input byte before
// writing the output byte derived from it — true of every streaming
// decrypt — and must zero the whole output span on failure.

#include <cstddef>
#include <cstdint>

#include "routeloom/types.hpp"

namespace routeloom {

constexpr std::size_t kAeadGcmKeySize = 16;
constexpr std::size_t kAeadGcmNonceSize = 12;
constexpr std::size_t kAeadGcmTagSize = 16;

struct AeadGcm {
  bool (*seal)(void* ctx, const std::uint8_t* key, const std::uint8_t* nonce,
               ByteView aad, ByteView plaintext, std::uint8_t* out) noexcept;
  bool (*open)(void* ctx, const std::uint8_t* key, const std::uint8_t* nonce,
               ByteView aad, ByteView ciphertext_and_tag,
               std::uint8_t* out) noexcept;
  void* ctx;
};

// Host builds: the vendored TF-PSA-Crypto builtin AES + GCM. ESP-IDF builds
// do not compile that subset, so this returns nullptr there and the adapter
// passes its PSA implementation.
const AeadGcm* builtin_aead_gcm() noexcept;

}  // namespace routeloom
