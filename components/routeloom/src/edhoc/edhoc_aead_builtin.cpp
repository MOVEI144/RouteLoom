// AES-CCM-16-64-128 for EDHOC cipher suite 2 (routeloom/edhoc.hpp).
//
// Host builds define ROUTELOOM_EDHOC_BUILTIN_AEAD and link the vendored
// TF-PSA-Crypto builtin AES + CCM (components/routeloom/third_party/
// tf-psa-crypto, configured by src/edhoc/tf_psa_crypto_config.h). ESP-IDF
// builds do not compile that subset — the firmware already links ESP-IDF's
// Mbed TLS, whose symbols the subset would duplicate — so there
// builtin_aead_ccm() is nullptr and the adapter supplies a PSA AeadCcm.

#include "routeloom/edhoc.hpp"

#if defined(ROUTELOOM_EDHOC_BUILTIN_AEAD)

// The CCM context layout and entry points sit in TF-PSA-Crypto's private
// headers; consumers of the builtin driver opt in explicitly.
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include "mbedtls/private/ccm.h"

#include <cstring>

namespace routeloom::edhoc {
namespace {

class CcmContext {
 public:
  CcmContext() noexcept { mbedtls_ccm_init(&ctx_); }
  ~CcmContext() { mbedtls_ccm_free(&ctx_); }  // zeroizes the key schedule
  CcmContext(const CcmContext&) = delete;
  CcmContext& operator=(const CcmContext&) = delete;
  bool set_key(const std::uint8_t* key) noexcept {
    return mbedtls_ccm_setkey(&ctx_, MBEDTLS_CIPHER_ID_AES, key,
                              static_cast<unsigned int>(kSuite2AeadKeySize * 8)) == 0;
  }
  mbedtls_ccm_context* get() noexcept { return &ctx_; }

 private:
  mbedtls_ccm_context ctx_;
};

bool seal(void* /*ctx*/, const std::uint8_t* key, const std::uint8_t* nonce,
          const ByteView aad, const ByteView plaintext, std::uint8_t* out) noexcept {
  if (key == nullptr || nonce == nullptr || out == nullptr ||
      (aad.data == nullptr && aad.size != 0) ||
      (plaintext.data == nullptr && plaintext.size != 0)) {
    return false;
  }
  CcmContext ccm;
  return ccm.set_key(key) &&
         mbedtls_ccm_encrypt_and_tag(ccm.get(), plaintext.size, nonce, kSuite2AeadNonceSize,
                                     aad.data, aad.size, plaintext.data, out,
                                     out + plaintext.size, kSuite2AeadTagSize) == 0;
}

bool open(void* /*ctx*/, const std::uint8_t* key, const std::uint8_t* nonce,
          const ByteView aad, const ByteView ciphertext_and_tag,
          std::uint8_t* out) noexcept {
  if (key == nullptr || nonce == nullptr || out == nullptr ||
      (aad.data == nullptr && aad.size != 0) || ciphertext_and_tag.data == nullptr ||
      ciphertext_and_tag.size < kSuite2AeadTagSize) {
    return false;
  }
  const std::size_t length = ciphertext_and_tag.size - kSuite2AeadTagSize;
  CcmContext ccm;
  // mbedtls_ccm_auth_decrypt checks the tag in constant time and zeroes the
  // output on mismatch.
  return ccm.set_key(key) &&
         mbedtls_ccm_auth_decrypt(ccm.get(), length, nonce, kSuite2AeadNonceSize, aad.data,
                                  aad.size, ciphertext_and_tag.data, out,
                                  ciphertext_and_tag.data + length,
                                  kSuite2AeadTagSize) == 0;
}

const AeadCcm kBuiltinAeadCcm{&seal, &open, nullptr};

}  // namespace

const AeadCcm* builtin_aead_ccm() noexcept { return &kBuiltinAeadCcm; }

}  // namespace routeloom::edhoc

#else

namespace routeloom::edhoc {
const AeadCcm* builtin_aead_ccm() noexcept { return nullptr; }
}  // namespace routeloom::edhoc

#endif
