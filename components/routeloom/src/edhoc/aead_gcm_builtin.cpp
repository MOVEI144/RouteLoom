// AES-GCM-128 for the SDK v1 channel AEADs (routeloom/aead_gcm.hpp).
//
// Host builds define ROUTELOOM_EDHOC_BUILTIN_AEAD and link the vendored
// TF-PSA-Crypto builtin AES + GCM (components/routeloom/third_party/
// tf-psa-crypto, configured by src/edhoc/tf_psa_crypto_config.h). ESP-IDF
// builds do not compile that subset — the firmware already links ESP-IDF's
// Mbed TLS, whose symbols the subset would duplicate — so there
// builtin_aead_gcm() is nullptr and the adapter supplies a PSA AeadGcm.

#include "routeloom/aead_gcm.hpp"

#if defined(ROUTELOOM_EDHOC_BUILTIN_AEAD)

// The GCM context layout and entry points sit in TF-PSA-Crypto's private
// headers; consumers of the builtin driver opt in explicitly.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/private/gcm.h"

#include <cstring>

namespace routeloom {
namespace {

class GcmContext {
 public:
  GcmContext() noexcept { mbedtls_gcm_init(&ctx_); }
  ~GcmContext() { mbedtls_gcm_free(&ctx_); }  // zeroizes the key schedule
  GcmContext(const GcmContext&) = delete;
  GcmContext& operator=(const GcmContext&) = delete;
  bool set_key(const std::uint8_t* key) noexcept {
    return mbedtls_gcm_setkey(&ctx_, MBEDTLS_CIPHER_ID_AES, key,
                              static_cast<unsigned int>(kAeadGcmKeySize * 8)) == 0;
  }
  mbedtls_gcm_context* get() noexcept { return &ctx_; }

 private:
  mbedtls_gcm_context ctx_;
};

bool seal(void* /*ctx*/, const std::uint8_t* key, const std::uint8_t* nonce,
          const ByteView aad, const ByteView plaintext, std::uint8_t* out) noexcept {
  if (key == nullptr || nonce == nullptr || out == nullptr ||
      (aad.data == nullptr && aad.size != 0) ||
      (plaintext.data == nullptr && plaintext.size != 0)) {
    return false;
  }
  GcmContext gcm;
  if (!gcm.set_key(key)) {
    return false;
  }
  // mbedtls_gcm_crypt_and_tag rejects overlapping outputs; the authority
  // channel always seals into its dedicated TX buffer.
  return mbedtls_gcm_crypt_and_tag(gcm.get(), MBEDTLS_GCM_ENCRYPT, plaintext.size, nonce,
                                   kAeadGcmNonceSize, aad.data, aad.size, plaintext.data, out,
                                   kAeadGcmTagSize, out + plaintext.size) == 0;
}

bool open(void* /*ctx*/, const std::uint8_t* key, const std::uint8_t* nonce,
          const ByteView aad, const ByteView ciphertext_and_tag,
          std::uint8_t* out) noexcept {
  if (key == nullptr || nonce == nullptr || out == nullptr ||
      (aad.data == nullptr && aad.size != 0) || ciphertext_and_tag.data == nullptr ||
      ciphertext_and_tag.size < kAeadGcmTagSize) {
    return false;
  }
  const std::size_t length = ciphertext_and_tag.size - kAeadGcmTagSize;
  GcmContext gcm;
  if (!gcm.set_key(key)) {
    std::memset(out, 0, length);
    return false;
  }
  // mbedtls_gcm_auth_decrypt checks the tag in constant time and zeroes the
  // output on mismatch.
  return mbedtls_gcm_auth_decrypt(gcm.get(), length, nonce, kAeadGcmNonceSize, aad.data, aad.size,
                                  ciphertext_and_tag.data + length, kAeadGcmTagSize,
                                  ciphertext_and_tag.data, out) == 0;
}

const AeadGcm kBuiltinAeadGcm{&seal, &open, nullptr};

}  // namespace

const AeadGcm* builtin_aead_gcm() noexcept { return &kBuiltinAeadGcm; }

}  // namespace routeloom

#else

namespace routeloom {
const AeadGcm* builtin_aead_gcm() noexcept { return nullptr; }
}  // namespace routeloom

#endif
