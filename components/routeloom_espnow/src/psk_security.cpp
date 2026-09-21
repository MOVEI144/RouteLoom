#include "routeloom/psk_security.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "psa/crypto.h"

namespace routeloom::espnow {
namespace {
constexpr psa_algorithm_t kAeadAlgorithm =
    PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, kAeadTagSize);
constexpr psa_algorithm_t kDerivationAlgorithm =
    PSA_ALG_HMAC(PSA_ALG_SHA_256);

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

Status compute_hmac_sha256(
    const std::array<std::uint8_t,
                     DevelopmentPskSecurityProvider::kMasterKeySize>& key,
    const ByteView input, std::array<std::uint8_t, 32>& output) noexcept {
  psa_key_attributes_t attributes = PSA_KEY_ATTRIBUTES_INIT;
  psa_set_key_usage_flags(&attributes, PSA_KEY_USAGE_SIGN_MESSAGE);
  psa_set_key_algorithm(&attributes, kDerivationAlgorithm);
  psa_set_key_type(&attributes, PSA_KEY_TYPE_HMAC);
  psa_set_key_bits(&attributes, key.size() * 8U);

  psa_key_id_t key_id = 0;
  psa_status_t result =
      psa_import_key(&attributes, key.data(), key.size(), &key_id);
  psa_reset_key_attributes(&attributes);
  if (result != PSA_SUCCESS) {
    return Status::error(StatusCode::InternalError,
                         "PSA HMAC key import failed");
  }

  std::size_t output_length = 0;
  result = psa_mac_compute(key_id, kDerivationAlgorithm, input.data, input.size,
                           output.data(), output.size(), &output_length);
  (void)psa_destroy_key(key_id);
  if (result != PSA_SUCCESS || output_length != output.size()) {
    std::fill(output.begin(), output.end(), 0);
    return Status::error(StatusCode::InternalError,
                         "PSA HMAC key derivation failed");
  }
  return Status::success();
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
  const auto store_status = replay_store_.open(replay_namespace);
  if (!store_status) {
    counter_store_ = nullptr;
    std::fill(master_key_.begin(), master_key_.end(), 0);
    return Status::error(StatusCode::StorageFailure,
                         "replay nvs_open failed");
  }
  ready_ = true;
  return Status::success();
}

void DevelopmentPskSecurityProvider::close() noexcept {
  // Cached contexts hold leases bound to the old counter store and replay
  // windows tied to the old store handle: they must not survive a close or a
  // later re-initialize would reuse stale state.
  tx_contexts_.clear();
  rx_contexts_.clear();
  replay_store_.close();
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
  return compute_hmac_sha256(master_key_, ByteView{info.data(), info.size()},
                             key);
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
    existing->use_stamp = ++context_stamp_;
    return existing;
  }
  if (counter_store_ == nullptr) {
    return nullptr;
  }
  auto* created = tx_contexts_.allocate();
  if (created == nullptr) {
    // Bounded pool: evict the least-recently-used context. A dropped lease
    // forfeits only the uncommitted remainder of its reserved block, which is
    // the designed crash-recovery behavior — counters never rewind.
    TxContext* oldest = nullptr;
    tx_contexts_.for_each([&](TxContext& value) {
      if (oldest == nullptr || value.use_stamp < oldest->use_stamp) {
        oldest = &value;
      }
    });
    if (oldest == nullptr || !tx_contexts_.release(oldest)) {
      return nullptr;
    }
    created = tx_contexts_.allocate();
    if (created == nullptr) {
      return nullptr;
    }
  }
  created->use_stamp = ++context_stamp_;
  created->context = context;
  created->fingerprint = replay_context_fingerprint(context);
  // The lease occupies one slot per peer pair (the epoch-free floor slot),
  // so every boot-advancing epoch rewrites the same record rather than
  // leaking one persisted counter record per boot. Epoch identity lives in
  // CounterRecord::key_epoch; initialize() treats an older persisted epoch
  // as superseded and a newer one as a conflict.
  const std::uint64_t peer_fingerprint = replay_peer_fingerprint(context);
  const std::uint8_t direction = static_cast<std::uint8_t>(
      (context.scope == SecurityScope::EndToEnd ? 2U : 0U) |
      (context.sender < context.receiver ? 0U : 1U));
  created->lease.emplace(
      *counter_store_, ReplayGuard::floor_slot(context),
      static_cast<std::uint32_t>(peer_fingerprint ^ (peer_fingerprint >> 32U)),
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
    // The peer epoch floor must hold on every frame, not only at context
    // creation: the floor may have advanced since this context was cached
    // (peer re-handshake), which makes the cached epoch stale.
    const auto floor_status = replay_guard_.check_floor(context);
    if (!floor_status) return floor_status;
    existing->use_stamp = ++context_stamp_;
    result = existing;
    return Status::success();
  }
  auto* created = rx_contexts_.allocate();
  if (created == nullptr) {
    // Bounded pool: evict the least-recently-used cached window. Windows are
    // persisted on accept, so eviction only forces a reload from the store.
    RxContext* oldest = nullptr;
    rx_contexts_.for_each([&](RxContext& value) {
      if (oldest == nullptr || value.use_stamp < oldest->use_stamp) {
        oldest = &value;
      }
    });
    if (oldest == nullptr || !rx_contexts_.release(oldest)) {
      return Status::error(StatusCode::NoCapacity,
                           "security rx context table full");
    }
    created = rx_contexts_.allocate();
    if (created == nullptr) {
      return Status::error(StatusCode::NoCapacity,
                           "security rx context table full");
    }
  }
  created->use_stamp = ++context_stamp_;
  created->context = context;
  // Loads the persisted window and enforces the peer epoch floor. Stale
  // epochs, corrupt records and windows lost mid-epoch are all rejected
  // rather than silently re-initialized (see replay.hpp).
  const auto status = replay_guard_.open_context(context, created->window);
  if (!status) {
    rx_contexts_.release(created);
    return status;
  }
  result = created;
  return Status::success();
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
    status = replay_guard_.accept(replay->window, counter);
  }
  if (!status && plaintext.data != nullptr && plaintext.size != 0) {
    std::memset(plaintext.data, 0, plaintext.size);
  }
  return status;
}

}  // namespace routeloom::espnow
