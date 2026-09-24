#include "routeloom/psa_session_aead.hpp"

#include <cstddef>
#include <cstdint>

#include "psa/crypto.h"

namespace routeloom::espnow {
namespace {

bool import_key(const std::uint8_t key[16], psa_key_id_t& key_id) noexcept {
  if (psa_crypto_init() != PSA_SUCCESS) {
    return false;
  }
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attributes, PSA_ALG_GCM);
  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, 128);
  const psa_status_t result = psa_import_key(&attributes, key, 16, &key_id);
  psa_reset_key_attributes(&attributes);
  return result == PSA_SUCCESS;
}

bool seal(void* /*ctx*/, const std::uint8_t key[16], const std::uint8_t nonce[12],
          const ByteView aad, const ByteView plaintext, std::uint8_t* out_ciphertext,
          std::uint8_t out_tag[16]) noexcept {
  if (key == nullptr || nonce == nullptr || out_ciphertext == nullptr || out_tag == nullptr ||
      (aad.size != 0 && aad.data == nullptr) ||
      (plaintext.size != 0 && plaintext.data == nullptr)) {
    return false;
  }
  psa_key_id_t key_id = 0;
  if (!import_key(key, key_id)) {
    return false;
  }
  const std::uint8_t empty = 0;
  bool ok = false;
  psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
  std::size_t written = 0;
  std::size_t tail = 0;
  std::size_t tag_written = 0;
  if (psa_aead_encrypt_setup(&op, key_id, PSA_ALG_GCM) == PSA_SUCCESS &&
      psa_aead_set_nonce(&op, nonce, kSessionIvSize) == PSA_SUCCESS &&
      psa_aead_update_ad(&op, aad.size == 0 ? &empty : aad.data, aad.size) == PSA_SUCCESS &&
      psa_aead_update(&op, plaintext.size == 0 ? &empty : plaintext.data, plaintext.size,
                      out_ciphertext, plaintext.size, &written) == PSA_SUCCESS &&
      written == plaintext.size &&
      psa_aead_finish(&op, out_ciphertext + written, 0, &tail, out_tag, kAeadTagSize,
                      &tag_written) == PSA_SUCCESS &&
      tail == 0 && tag_written == kAeadTagSize) {
    ok = true;
  }
  (void)psa_aead_abort(&op);
  (void)psa_destroy_key(key_id);
  if (!ok) {
    for (std::size_t i = 0; i < plaintext.size; ++i) {
      out_ciphertext[i] = 0;
    }
    for (std::size_t i = 0; i < kAeadTagSize; ++i) {
      out_tag[i] = 0;
    }
  }
  return ok;
}

bool open(void* /*ctx*/, const std::uint8_t key[16], const std::uint8_t nonce[12],
          const ByteView aad, const ByteView ciphertext, const std::uint8_t tag[16],
          std::uint8_t* out_plaintext) noexcept {
  if (key == nullptr || nonce == nullptr || tag == nullptr || out_plaintext == nullptr ||
      (aad.size != 0 && aad.data == nullptr) ||
      (ciphertext.size != 0 && ciphertext.data == nullptr)) {
    return false;
  }
  psa_key_id_t key_id = 0;
  if (!import_key(key, key_id)) {
    return false;
  }
  const std::uint8_t empty = 0;
  bool ok = false;
  psa_aead_operation_t op = PSA_AEAD_OPERATION_INIT;
  std::size_t written = 0;
  std::size_t tail = 0;
  if (psa_aead_decrypt_setup(&op, key_id, PSA_ALG_GCM) == PSA_SUCCESS &&
      psa_aead_set_nonce(&op, nonce, kSessionIvSize) == PSA_SUCCESS &&
      psa_aead_update_ad(&op, aad.size == 0 ? &empty : aad.data, aad.size) == PSA_SUCCESS &&
      psa_aead_update(&op, ciphertext.size == 0 ? &empty : ciphertext.data, ciphertext.size,
                      out_plaintext, ciphertext.size, &written) == PSA_SUCCESS &&
      written == ciphertext.size &&
      psa_aead_verify(&op, out_plaintext + written, 0, &tail, tag, kAeadTagSize) ==
          PSA_SUCCESS &&
      tail == 0) {
    ok = true;
  }
  (void)psa_aead_abort(&op);
  (void)psa_destroy_key(key_id);
  if (!ok) {
    for (std::size_t i = 0; i < ciphertext.size; ++i) {
      out_plaintext[i] = 0;  // never hand out unauthenticated plaintext
    }
  }
  return ok;
}

}  // namespace

sdkv1::AeadGcm psa_session_aead_gcm() noexcept {
  return sdkv1::AeadGcm{&seal, &open, nullptr};
}

}  // namespace routeloom::espnow
