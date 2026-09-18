#include "routeloom/psk_security.hpp"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>

#include "mbedtls/md.h"
#include "nvs.h"
#include "psa/crypto.h"

namespace routeloom::espnow {
namespace {
constexpr psa_algorithm_t kAeadAlgorithm =
    PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, kAeadTagSize);

void append_u16(std::uint8_t*& out, const std::uint16_t value) noexcept {
  *out++ = static_cast<std::uint8_t>(value >> 8U);
  *out++ = static_cast<std::uint8_t>(value);
}

void append_u64(std::uint8_t*& out, const std::uint64_t value) noexcept {
  for (int shift = 56; shift >= 0; shift -= 8) {
    *out++ = static_cast<std::uint8_t>(value >> shift);
  }
}

Status import_aes_key(const std::array<std::uint8_t, 32>& key,
                      psa_key_id_t& key_id) noexcept {
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(
      &attributes, PSA_KEY_USAGE_ENCRYPT | PSA_KEY_USAGE_DECRYPT);
  psa_set_key_algorithm(&attributes, kAeadAlgorithm);
  psa_set_key_type(&attributes, PSA_KEY_TYPE_AES);
  psa_set_key_bits(&attributes, key.size() * 8U);

  const psa_status_t result =
      psa_import_key(&attributes, key.data(), key.size(), &key_id);
  psa_reset_key_attributes(&attributes);
  return result == PSA_SUCCESS
             ? Status::success()
             : Status::error(StatusCode::InternalError,
                             "PSA AES-GCM key import failed");
}

void destroy_key(psa_key_id_t& key_id) noexcept {
  if (key_id != 0) {
    (void)psa_destroy_key(key_id);
    key_id = 0;
  }
}
}  // namespace

DevelopmentPskSecurityProvider::~DevelopmentPskSecurityProvider() { close(); }

Status DevelopmentPskSecurityProvider::initialize(
    const std::array<std::uint8_t, kMasterKeySize>& master_key,
    NvsCounterStore& counter_store, const char* replay_namespace) noexcept {
  if (replay_namespace == nullptr || replay_namespace[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument,
                         "replay namespace missing");
  }

  close();
  if (psa_crypto_init() != PSA_SUCCESS) {
    return Status::error(StatusCode::InternalError,
                         "PSA crypto initialization failed");
  }

  master_key_ = master_key;
  counter_store_ = &counter_store;
  const esp_err_t error =
      nvs_open(replay_namespace, NVS_READWRITE, &replay_handle_);
  if (error != ESP_OK) {
    counter_store_ = nullptr;
    std::fill(master_key_.begin(), master_key_.end(), 0);
    return Status::error(StatusCode::StorageFailure,
                         "replay nvs_open failed");
  }
  replay_open_ = true;
  ready_ = true;
  return Status::success();
}

void DevelopmentPskSecurityProvider::close() noexcept {
  if (replay_open_) {
    nvs_close(replay_handle_);
  }
  replay_handle_ = 0;
  replay_open_ = false;
  ready_ = false;
  counter_store_ = nullptr;
  std::fill(master_key_.begin(), master_key_.end(), 0);
}

bool DevelopmentPskSecurityProvider::same_context(
    const SecurityContext& left, const SecurityContext& right) noexcept {
  return left.scope == right.scope && left.network == right.network &&
         left.sender == right.sender && left.receiver == right.receiver &&
         left.epoch == right.epoch;
}

std::uint64_t DevelopmentPskSecurityProvider::fingerprint(
    const SecurityContext& context) noexcept {
  std::uint64_t hash = 1469598103934665603ULL;
  auto add = [&](const std::uint64_t value) {
    for (unsigned shift = 0; shift < 64; shift += 8) {
      hash ^= static_cast<std::uint8_t>(value >> shift);
      hash *= 1099511628211ULL;
    }
  };
  add(static_cast<std::uint64_t>(context.scope));
  add(context.network);
  add(context.sender);
  add(context.receiver);
  add(context.epoch);
  return hash;
}

std::uint32_t DevelopmentPskSecurityProvider::slot(
    const SecurityContext& context) noexcept {
  const std::uint64_t value = fingerprint(context);
  return static_cast<std::uint32_t>(value ^ (value >> 32U));
}

Status DevelopmentPskSecurityProvider::derive_key(
    const SecurityContext& context,
    std::array<std::uint8_t, 32>& key) const noexcept {
  std::array<std::uint8_t, 1 + 8 + 8 + 8 + 2> info{};
  std::uint8_t* cursor = info.data();
  *cursor++ = static_cast<std::uint8_t>(context.scope);
  append_u64(cursor, context.network);
  append_u64(cursor, context.sender);
  append_u64(cursor, context.receiver);
  append_u16(cursor, context.epoch);
  const mbedtls_md_info_t* md =
      mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == nullptr) {
    return Status::error(StatusCode::InternalError,
                         "SHA-256 unavailable");
  }
  const int result =
      mbedtls_md_hmac(md, master_key_.data(), master_key_.size(), info.data(),
                      info.size(), key.data());
  return result == 0
             ? Status::success()
             : Status::error(StatusCode::InternalError,
                             "HMAC key derivation failed");
}

void DevelopmentPskSecurityProvider::make_nonce(
    const SecurityContext& context, const std::uint64_t counter,
    std::array<std::uint8_t, 12>& nonce) noexcept {
  nonce[0] = static_cast<std::uint8_t>(context.scope);
  nonce[1] =
      static_cast<std::uint8_t>(context.sender < context.receiver ? 0U : 1U);
  nonce[2] = static_cast<std::uint8_t>(context.epoch >> 8U);
  nonce[3] = static_cast<std::uint8_t>(context.epoch);
  for (int index = 0; index < 8; ++index) {
    nonce[4 + index] =
        static_cast<std::uint8_t>(counter >> (56 - index * 8));
  }
}

DevelopmentPskSecurityProvider::TxContext*
DevelopmentPskSecurityProvider::tx_context(
    const SecurityContext& context) noexcept {
  if (auto* existing = tx_contexts_.find([&](const TxContext& value) {
        return same_context(value.context, context);
      })) {
    return existing;
  }
  auto* created = tx_contexts_.allocate();
  if (created == nullptr || counter_store_ == nullptr) {
    return nullptr;
  }
  created->context = context;
  created->fingerprint = fingerprint(context);
  const std::uint8_t direction = static_cast<std::uint8_t>(
      (context.scope == SecurityScope::EndToEnd ? 2U : 0U) |
      (context.sender < context.receiver ? 0U : 1U));
  created->lease.emplace(
      *counter_store_, slot(context),
      static_cast<std::uint32_t>(created->fingerprint ^
                                 (created->fingerprint >> 32U)),
      context.epoch, direction, 256);
  if (!created->lease->initialize()) {
    tx_contexts_.release(created);
    return nullptr;
  }
  return created;
}

Status DevelopmentPskSecurityProvider::next_counter(
    const SecurityContext& context, std::uint64_t& counter) noexcept {
  if (!ready_) {
    return Status::error(StatusCode::InvalidState,
                         "security provider not ready");
  }
  auto* entry = tx_context(context);
  if (entry == nullptr || !entry->lease.has_value()) {
    return Status::error(StatusCode::NoCapacity,
                         "security tx context table full");
  }
  return entry->lease->next(counter);
}

Status DevelopmentPskSecurityProvider::rx_context(
    const SecurityContext& context, RxContext*& result) noexcept {
  if (auto* existing = rx_contexts_.find([&](const RxContext& value) {
        return same_context(value.context, context);
      })) {
    result = existing;
    return Status::success();
  }
  auto* created = rx_contexts_.allocate();
  if (created == nullptr) {
    return Status::error(StatusCode::NoCapacity,
                         "security rx context table full");
  }
  created->context = context;
  created->record.fingerprint = fingerprint(context);
  char key[12]{};
  std::snprintf(key, sizeof(key), "r%08lx",
                static_cast<unsigned long>(slot(context)));
  std::size_t size = sizeof(created->record);
  const esp_err_t error =
      nvs_get_blob(replay_handle_, key, &created->record, &size);
  if (error == ESP_ERR_NVS_NOT_FOUND) {
    created->record = ReplayRecord{};
    created->record.fingerprint = fingerprint(context);
  } else if (error != ESP_OK || size != sizeof(created->record) ||
             created->record.fingerprint != fingerprint(context)) {
    rx_contexts_.release(created);
    return error == ESP_OK
               ? Status::error(
                     StatusCode::Conflict,
                     "replay record hash collision or size mismatch")
               : Status::error(StatusCode::StorageFailure,
                               "replay state load failed");
  }
  result = created;
  return Status::success();
}

Status DevelopmentPskSecurityProvider::persist_replay(
    RxContext& context) noexcept {
  char key[12]{};
  std::snprintf(key, sizeof(key), "r%08lx",
                static_cast<unsigned long>(slot(context.context)));
  esp_err_t error =
      nvs_set_blob(replay_handle_, key, &context.record,
                   sizeof(context.record));
  if (error == ESP_OK) {
    error = nvs_commit(replay_handle_);
  }
  return error == ESP_OK
             ? Status::success()
             : Status::error(StatusCode::StorageFailure,
                             "replay state commit failed");
}

Status DevelopmentPskSecurityProvider::accept_counter(
    RxContext& context, const std::uint64_t counter) noexcept {
  ReplayRecord next = context.record;
  if (next.initialized == 0) {
    next.maximum_counter = counter;
    next.bitmap = 1;
    next.initialized = 1;
  } else if (counter > next.maximum_counter) {
    const std::uint64_t delta = counter - next.maximum_counter;
    next.bitmap =
        delta >= 64 ? 1ULL : ((next.bitmap << delta) | 1ULL);
    next.maximum_counter = counter;
  } else {
    const std::uint64_t delta = next.maximum_counter - counter;
    if (delta >= 64 || (next.bitmap & (1ULL << delta)) != 0) {
      return Status::error(StatusCode::ReplayRejected,
                           "replayed security counter");
    }
    next.bitmap |= 1ULL << delta;
  }
  ++next.generation;
  const ReplayRecord previous = context.record;
  context.record = next;
  const auto status = persist_replay(context);
  if (!status) {
    context.record = previous;
  }
  return status;
}

Status DevelopmentPskSecurityProvider::seal(
    const SecurityContext& context, const std::uint64_t counter,
    const ByteView aad, const ByteView plaintext,
    const MutableByteView ciphertext,
    std::array<std::uint8_t, kAeadTagSize>& tag) noexcept {
  if (!ready_ || plaintext.size > kMaxEspNowBody ||
      ciphertext.size < plaintext.size ||
      (aad.size != 0 && aad.data == nullptr) ||
      (plaintext.size != 0 &&
       (plaintext.data == nullptr || ciphertext.data == nullptr))) {
    return Status::error(StatusCode::InvalidArgument,
                         "invalid AES-GCM seal input");
  }

  std::array<std::uint8_t, 32> key{};
  std::array<std::uint8_t, 12> nonce{};
  std::array<std::uint8_t, kMaxEspNowBody + kAeadTagSize> output{};
  auto status = derive_key(context, key);
  if (!status) {
    return status;
  }
  make_nonce(context, counter, nonce);

  psa_key_id_t key_id = 0;
  status = import_aes_key(key, key_id);
  if (!status) {
    std::fill(key.begin(), key.end(), 0);
    return status;
  }

  const std::uint8_t empty = 0;
  const std::uint8_t* aad_data = aad.size == 0 ? &empty : aad.data;
  const std::uint8_t* plaintext_data =
      plaintext.size == 0 ? &empty : plaintext.data;
  std::size_t output_length = 0;
  const psa_status_t result = psa_aead_encrypt(
      key_id, kAeadAlgorithm, nonce.data(), nonce.size(), aad_data, aad.size,
      plaintext_data, plaintext.size, output.data(), output.size(),
      &output_length);
  destroy_key(key_id);
  std::fill(key.begin(), key.end(), 0);

  if (result != PSA_SUCCESS ||
      output_length != plaintext.size + kAeadTagSize) {
    std::fill(output.begin(), output.end(), 0);
    return Status::error(StatusCode::InternalError,
                         "PSA AES-GCM seal failed");
  }
  if (plaintext.size != 0) {
    std::memcpy(ciphertext.data, output.data(), plaintext.size);
  }
  std::memcpy(tag.data(), output.data() + plaintext.size, tag.size());
  std::fill(output.begin(), output.end(), 0);
  return Status::success();
}

Status DevelopmentPskSecurityProvider::open(
    const SecurityContext& context, const std::uint64_t counter,
    const ByteView aad, const ByteView ciphertext,
    const std::array<std::uint8_t, kAeadTagSize>& tag,
    const MutableByteView plaintext) noexcept {
  if (!ready_ || ciphertext.size > kMaxEspNowBody ||
      plaintext.size < ciphertext.size ||
      (aad.size != 0 && aad.data == nullptr) ||
      (ciphertext.size != 0 &&
       (ciphertext.data == nullptr || plaintext.data == nullptr))) {
    return Status::error(StatusCode::InvalidArgument,
                         "invalid AES-GCM open input");
  }

  std::array<std::uint8_t, 32> key{};
  std::array<std::uint8_t, 12> nonce{};
  std::array<std::uint8_t, kMaxEspNowBody + kAeadTagSize> input{};
  std::array<std::uint8_t, kMaxEspNowBody> output{};
  auto status = derive_key(context, key);
  if (!status) {
    return status;
  }
  make_nonce(context, counter, nonce);

  if (ciphertext.size != 0) {
    std::memcpy(input.data(), ciphertext.data, ciphertext.size);
  }
  std::memcpy(input.data() + ciphertext.size, tag.data(), tag.size());

  psa_key_id_t key_id = 0;
  status = import_aes_key(key, key_id);
  if (!status) {
    std::fill(key.begin(), key.end(), 0);
    return status;
  }

  const std::uint8_t empty = 0;
  const std::uint8_t* aad_data = aad.size == 0 ? &empty : aad.data;
  std::size_t output_length = 0;
  const psa_status_t result = psa_aead_decrypt(
      key_id, kAeadAlgorithm, nonce.data(), nonce.size(), aad_data, aad.size,
      input.data(), ciphertext.size + tag.size(), output.data(),
      output.size(), &output_length);
  destroy_key(key_id);
  std::fill(key.begin(), key.end(), 0);
  std::fill(input.begin(), input.end(), 0);

  if (result != PSA_SUCCESS || output_length != ciphertext.size) {
    std::fill(output.begin(), output.end(), 0);
    if (plaintext.data != nullptr && plaintext.size != 0) {
      std::memset(plaintext.data, 0, plaintext.size);
    }
    return Status::error(StatusCode::AuthenticationFailed,
                         "AES-GCM authentication failed");
  }

  if (output_length != 0) {
    std::memcpy(plaintext.data, output.data(), output_length);
  }
  std::fill(output.begin(), output.end(), 0);

  RxContext* replay = nullptr;
  status = rx_context(context, replay);
  if (status) {
    status = accept_counter(*replay, counter);
  }
  if (!status && plaintext.data != nullptr && plaintext.size != 0) {
    std::memset(plaintext.data, 0, plaintext.size);
  }
  return status;
}

}  // namespace routeloom::espnow
