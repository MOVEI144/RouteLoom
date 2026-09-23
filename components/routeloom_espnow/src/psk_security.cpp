#include "routeloom/psk_security.hpp"

#include "routeloom/secure_clear.hpp"

#include <algorithm>
#include <array>
#include <cstring>

#include "esp_log.h"
#include "nvs.h"
#include "psa/crypto.h"

namespace routeloom::espnow {
namespace {
constexpr psa_algorithm_t kAeadAlgorithm =
    PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, kAeadTagSize);
constexpr psa_algorithm_t kDerivationAlgorithm =
    PSA_ALG_HMAC(PSA_ALG_SHA_256);

void append_u32(std::uint8_t*& out, const std::uint32_t value) noexcept {
  for (int shift = 24; shift >= 0; shift -= 8) {
    *out++ = static_cast<std::uint8_t>(value >> shift);
  }
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
    secure_clear(output);
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
    NvsCounterStore& counter_store, const PeerStateConfig& config) noexcept {
  if (config.replay_namespace == nullptr ||
      config.replay_namespace[0] == '\0') {
    return Status::error(StatusCode::InvalidArgument,
                         "replay namespace missing");
  }
  if (config.tx_epoch == 0 || config.max_persisted_peers == 0) {
    return Status::error(StatusCode::InvalidArgument,
                         "peer state config invalid");
  }

  close();
  if (psa_crypto_init() != PSA_SUCCESS) {
    return Status::error(StatusCode::InternalError,
                         "PSA crypto initialization failed");
  }

  const PeerStateLimits limits = peer_state_limits(config.max_persisted_peers);
  // Sweeps TX records of epochs below tx_epoch (witness committed first) and
  // refuses a tx_epoch at or below the witness: fail closed before any key
  // could be reused.
  const auto counter_status = counters_.open(
      counter_store, limits.max_counter_records, config.tx_epoch);
  if (!counter_status) return counter_status;
  const auto store_status =
      replay_store_.open(config.replay_namespace, config.partition);
  if (!store_status) {
    counters_.close();
    return Status::error(StatusCode::StorageFailure,
                         "replay nvs_open failed");
  }
  (void)replay_bounds_.open(replay_store_, limits.max_replay_peers);
  master_key_ = master_key;
  ready_ = true;
  return Status::success();
}

PeerStateStats DevelopmentPskSecurityProvider::peer_state_stats()
    const noexcept {
  PeerStateStats stats{};
  stats.counter_records = counters_.records();
  stats.counter_capacity = counters_.max_records();
  stats.replay_peers = replay_bounds_.peers();
  stats.replay_capacity = replay_bounds_.max_peers();
  stats.capacity_rejects =
      counters_.capacity_rejects() + replay_bounds_.capacity_rejects();
  stats.witness_rejects = counters_.witness_rejects();
  stats.witness = counters_.witness();
  stats.witness_present = counters_.witness_present();
  stats.counts_known =
      counters_.records_known() && replay_bounds_.peers_known();
  stats.sweep = counters_.sweep_report();
  return stats;
}

void DevelopmentPskSecurityProvider::close() noexcept {
  // Cached contexts hold leases bound to the old counter store and replay
  // windows tied to the old store handle: they must not survive a close or a
  // later re-initialize would reuse stale state. Live replay windows first
  // lower their persisted ceiling to the live maximum (best effort; a
  // failure keeps the higher, still safe ceiling), so a clean restart
  // rejects only out-of-order stragglers rather than a reservation step.
  rx_contexts_.for_each([&](RxContext& value) {
    (void)replay_guard_.close_context(value.window);
  });
  tx_contexts_.clear();
  parked_leases_.clear();
  rx_contexts_.clear();
  replay_bounds_.close();
  replay_store_.close();
  counters_.close();
  ready_ = false;
  secure_clear(master_key_);
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
  std::array<std::uint8_t, 1 + 8 + 8 + 8 + 4> info{};
  std::uint8_t* cursor = info.data();
  *cursor++ = static_cast<std::uint8_t>(context.scope);
  append_u64(cursor, context.network);
  append_u64(cursor, context.sender);
  append_u64(cursor, context.receiver);
  append_u32(cursor, context.epoch);
  return compute_hmac_sha256(master_key_, ByteView{info.data(), info.size()},
                             key);
}

void DevelopmentPskSecurityProvider::make_nonce(
    const SecurityContext& context, const std::uint64_t counter,
    std::array<std::uint8_t, 12>& nonce) noexcept {
  nonce[0] = static_cast<std::uint8_t>(context.scope);
  nonce[1] =
      static_cast<std::uint8_t>(context.sender < context.receiver ? 0U : 1U);
  // Wire v2: scope u8 | direction u8 | epoch u32 | counter u48. Counters
  // are bounded by kMaxCryptoCounter, so the 48-bit field is lossless and
  // (context, epoch, counter) stays unique per key.
  for (int index = 0; index < 4; ++index) {
    nonce[2 + index] =
        static_cast<std::uint8_t>(context.epoch >> (24 - index * 8));
  }
  for (int index = 0; index < 6; ++index) {
    nonce[6 + index] =
        static_cast<std::uint8_t>(counter >> (40 - index * 8));
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
  if (!counters_.is_open()) {
    return nullptr;
  }
  // The lease occupies one slot per peer pair (the epoch-free floor slot),
  // so every boot-advancing epoch rewrites the same record rather than
  // leaking one persisted counter record per boot. Epoch identity lives in
  // CounterRecord::key_epoch; initialize() treats an older persisted epoch
  // as superseded and a newer one as a conflict.
  const std::uint64_t peer_fingerprint = replay_peer_fingerprint(context);
  CounterLeaseCheckpoint identity{};
  identity.slot = ReplayGuard::floor_slot(context);
  identity.context_id =
      static_cast<std::uint32_t>(peer_fingerprint ^ (peer_fingerprint >> 32U));
  identity.key_epoch = context.epoch;
  identity.direction = static_cast<std::uint8_t>(
      (context.scope == SecurityScope::EndToEnd ? 2U : 0U) |
      (context.sender < context.receiver ? 0U : 1U));
  // Claim this context's parked block (if any) BEFORE the eviction below
  // parks another lease: a full cache would otherwise drop the very
  // checkpoint about to be resumed. take() removes it, so a parked block
  // resumes at most once; resume() re-validates it against the store.
  CounterLeaseCheckpoint parked{};
  const bool resume_parked = parked_leases_.take(identity, parked);
  auto* created = tx_contexts_.allocate();
  if (created == nullptr) {
    // Bounded pool: evict the least-recently-used context. Its unissued
    // block remainder is parked as a RAM checkpoint so re-creating the
    // context resumes the block instead of committing a new one (#57). A
    // checkpoint dropped from the full cache forfeits only that remainder,
    // the designed crash-recovery behavior — counters never rewind.
    TxContext* oldest = nullptr;
    tx_contexts_.for_each([&](TxContext& value) {
      if (oldest == nullptr || value.use_stamp < oldest->use_stamp) {
        oldest = &value;
      }
    });
    if (oldest == nullptr) {
      return nullptr;
    }
    if (oldest->lease.has_value()) {
      parked_leases_.park(oldest->lease->checkpoint());
    }
    if (!tx_contexts_.release(oldest)) {
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
  created->lease.emplace(counters_, identity.slot, identity.context_id,
                         identity.key_epoch, identity.direction, 256);
  const Status lease_status = resume_parked ? created->lease->resume(parked)
                                            : created->lease->initialize();
  if (!lease_status) {
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
    // Bounded pool: evict the least-recently-used cached window. The live
    // window is RAM-only above a persisted ceiling; close_context lowers
    // that ceiling to the live maximum (<= 1 commit) so the reopen rejects
    // only out-of-order stragglers, not a whole reservation step of fresh
    // counters. A failed tighten keeps the higher ceiling: still replay-safe.
    RxContext* oldest = nullptr;
    rx_contexts_.for_each([&](RxContext& value) {
      if (oldest == nullptr || value.use_stamp < oldest->use_stamp) {
        oldest = &value;
      }
    });
    if (oldest != nullptr) {
      (void)replay_guard_.close_context(oldest->window);
    }
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
    secure_clear(key);
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
  secure_clear(key);

  if (result != PSA_SUCCESS ||
      output_length != plaintext.size + kAeadTagSize) {
    secure_clear(output);
    return Status::error(StatusCode::InternalError,
                         "PSA AES-GCM seal failed");
  }
  if (plaintext.size != 0) {
    std::memcpy(ciphertext.data, output.data(), plaintext.size);
  }
  std::memcpy(tag.data(), output.data() + plaintext.size, tag.size());
  secure_clear(output);
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
    secure_clear(key);
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
  secure_clear(key);
  secure_clear(input);

  if (result != PSA_SUCCESS || output_length != ciphertext.size) {
    secure_clear(output);
    if (plaintext.data != nullptr && plaintext.size != 0) {
      secure_clear(plaintext.data, plaintext.size);
    }
    return Status::error(StatusCode::AuthenticationFailed,
                         "AES-GCM authentication failed");
  }

  if (output_length != 0) {
    std::memcpy(plaintext.data, output.data(), output_length);
  }
  secure_clear(output);

  RxContext* replay = nullptr;
  status = rx_context(context, replay);
  if (status) {
    status = replay_guard_.accept(replay->window, counter);
  }
  if (!status && plaintext.data != nullptr && plaintext.size != 0) {
    secure_clear(plaintext.data, plaintext.size);
  }
  return status;
}

void log_peer_state(const char* tag,
                    const DevelopmentPskSecurityProvider& security,
                    const char* partition) noexcept {
  const PeerStateStats stats = security.peer_state_stats();
  ESP_LOGI(tag,
           "peer state: tx_records=%lu/%lu rx_peers=%lu/%lu swept=%lu "
           "kept_current=%lu kept_future=%lu kept_unreadable=%lu "
           "witness=%lu%s",
           static_cast<unsigned long>(stats.counter_records),
           static_cast<unsigned long>(stats.counter_capacity),
           static_cast<unsigned long>(stats.replay_peers),
           static_cast<unsigned long>(stats.replay_capacity),
           static_cast<unsigned long>(stats.sweep.erased),
           static_cast<unsigned long>(stats.sweep.retained_current),
           static_cast<unsigned long>(stats.sweep.retained_future),
           static_cast<unsigned long>(stats.sweep.retained_unreadable),
           static_cast<unsigned long>(stats.witness),
           stats.witness_present ? "" : " (none)");
  const Status sweep = security.counter_sweep_status();
  if (!sweep) {
    ESP_LOGE(tag,
             "PEER_STATE sweep incomplete (%s): dead TX records kept, new "
             "TX peers refused until the next boot",
             sweep.detail);
  }
  const Status census = security.replay_census_status();
  if (!census) {
    ESP_LOGE(tag,
             "PEER_STATE replay census failed (%s): new RX peers refused",
             census.detail);
  }
  if (stats.sweep.retained_future != 0) {
    ESP_LOGE(tag,
             "PEER_STATE %lu TX record(s) newer than this boot session: the "
             "boot session regressed; those peers fail closed",
             static_cast<unsigned long>(stats.sweep.retained_future));
  }
  nvs_stats_t nvs_stats{};
  if (nvs_get_stats(partition, &nvs_stats) == ESP_OK) {
    ESP_LOGI(tag, "nvs '%s': used=%u free=%u total=%u namespaces=%u",
             partition == nullptr ? NVS_DEFAULT_PART_NAME : partition,
             static_cast<unsigned>(nvs_stats.used_entries),
             static_cast<unsigned>(nvs_stats.free_entries),
             static_cast<unsigned>(nvs_stats.total_entries),
             static_cast<unsigned>(nvs_stats.namespace_count));
  }
}

}  // namespace routeloom::espnow
