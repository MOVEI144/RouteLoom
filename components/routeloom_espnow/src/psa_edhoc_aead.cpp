#include "routeloom/psa_edhoc_aead.hpp"

#include <cstddef>
#include <cstdint>

#include "psa/crypto.h"

namespace routeloom::espnow {
namespace {

constexpr psa_algorithm_t kCcm8 =
    PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_CCM, edhoc::kSuite2AeadTagSize);

bool import_key(const std::uint8_t* key, psa_key_id_t& key_id) noexcept {
  if (psa_crypto_init() != PSA_SUCCESS) {
    return false;
  }
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attributes, kCcm8);
  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, edhoc::kSuite2AeadKeySize * 8U);
  const psa_status_t result =
      psa_import_key(&attributes, key, edhoc::kSuite2AeadKeySize, &key_id);
  psa_reset_key_attributes(&attributes);
  return result == PSA_SUCCESS;
}

bool seal(void* /*ctx*/, const std::uint8_t* key, const std::uint8_t* nonce,
          const ByteView aad, const ByteView plaintext, std::uint8_t* out) noexcept {
  if (key == nullptr || nonce == nullptr || out == nullptr ||
      (aad.size != 0 && aad.data == nullptr) ||
      (plaintext.size != 0 && plaintext.data == nullptr)) {
    return false;
  }
  psa_key_id_t key_id = 0;
  if (!import_key(key, key_id)) {
    return false;
  }
  const std::uint8_t empty = 0;
  std::size_t written = 0;
  const psa_status_t result = psa_aead_encrypt(
      key_id, kCcm8, nonce, edhoc::kSuite2AeadNonceSize,
      aad.size == 0 ? &empty : aad.data, aad.size,
      plaintext.size == 0 ? &empty : plaintext.data, plaintext.size, out,
      plaintext.size + edhoc::kSuite2AeadTagSize, &written);
  (void)psa_destroy_key(key_id);
  return result == PSA_SUCCESS && written == plaintext.size + edhoc::kSuite2AeadTagSize;
}

bool open(void* /*ctx*/, const std::uint8_t* key, const std::uint8_t* nonce,
          const ByteView aad, const ByteView ciphertext_and_tag,
          std::uint8_t* out) noexcept {
  if (key == nullptr || nonce == nullptr || out == nullptr ||
      (aad.size != 0 && aad.data == nullptr) || ciphertext_and_tag.data == nullptr ||
      ciphertext_and_tag.size < edhoc::kSuite2AeadTagSize) {
    return false;
  }
  psa_key_id_t key_id = 0;
  if (!import_key(key, key_id)) {
    return false;
  }
  const std::size_t plaintext_size = ciphertext_and_tag.size - edhoc::kSuite2AeadTagSize;
  const std::uint8_t empty = 0;
  std::size_t written = 0;
  const psa_status_t result = psa_aead_decrypt(
      key_id, kCcm8, nonce, edhoc::kSuite2AeadNonceSize,
      aad.size == 0 ? &empty : aad.data, aad.size, ciphertext_and_tag.data,
      ciphertext_and_tag.size, out, plaintext_size, &written);
  (void)psa_destroy_key(key_id);
  if (result != PSA_SUCCESS || written != plaintext_size) {
    for (std::size_t i = 0; i < plaintext_size; ++i) {
      out[i] = 0;  // never hand out unauthenticated plaintext
    }
    return false;
  }
  return true;
}

const edhoc::AeadCcm kPsaAeadCcm{&seal, &open, nullptr};

}  // namespace

const edhoc::AeadCcm* psa_edhoc_aead_ccm() noexcept { return &kPsaAeadCcm; }

}  // namespace routeloom::espnow
