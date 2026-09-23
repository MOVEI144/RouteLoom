#pragma once

#include <array>
#include <cstdint>
#include <optional>

#include "routeloom/counter_store.hpp"
#include "routeloom/fixed_containers.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/nvs_replay_store.hpp"
#include "routeloom/replay.hpp"
#include "routeloom/security.hpp"

namespace routeloom::espnow {

// Development baseline for CORE_FIXED_250. It supplies real AES-GCM, durable
// counters and replay state, but a shared master key is not a production device
// identity system. Replace it with the qualified EDHOC/RPK provider before a
// secure production release. security_profile() is pinned to Development.
class DevelopmentPskSecurityProvider final : public SecurityProvider {
 public:
  static constexpr std::size_t kMasterKeySize = 32;
  static constexpr std::size_t kContextCapacity = 32;

  DevelopmentPskSecurityProvider() = default;
  ~DevelopmentPskSecurityProvider() override;

  Status initialize(const std::array<std::uint8_t, kMasterKeySize>& master_key,
                    NvsCounterStore& counter_store,
                    const char* replay_namespace) noexcept;
  void close() noexcept;

  bool ready() const noexcept override { return ready_; }
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }
  // Replay-state diagnostics: rejects caused by fingerprint-mismatched
  // records — the u32 slot-collision signature (see ReplayGuard).
  std::uint32_t foreign_fingerprint_rejects() const noexcept {
    return replay_guard_.foreign_fingerprint_rejects();
  }
  Status next_counter(const SecurityContext& context,
                      std::uint64_t& counter) noexcept override;
  Status seal(const SecurityContext& context, std::uint64_t counter,
              ByteView aad, ByteView plaintext, MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override;
  Status open(const SecurityContext& context, std::uint64_t counter,
              ByteView aad, ByteView ciphertext,
              const std::array<std::uint8_t, kAeadTagSize>& tag,
              MutableByteView plaintext) noexcept override;

 private:
  struct TxContext {
    SecurityContext context{};
    std::uint64_t fingerprint{0};
    std::optional<CounterLease> lease{};
    // LRU stamp: evicted first when the bounded context pool fills.
    std::uint64_t use_stamp{0};
  };

  struct RxContext {
    SecurityContext context{};
    ReplayGuard::Window window{};
    std::uint64_t use_stamp{0};
  };

  static bool same_context(const SecurityContext& left,
                           const SecurityContext& right) noexcept;
  Status derive_key(const SecurityContext& context,
                    std::array<std::uint8_t, 32>& key) const noexcept;
  static void make_nonce(const SecurityContext& context, std::uint64_t counter,
                         std::array<std::uint8_t, 12>& nonce) noexcept;
  TxContext* tx_context(const SecurityContext& context) noexcept;
  Status rx_context(const SecurityContext& context, RxContext*& result) noexcept;

  std::array<std::uint8_t, kMasterKeySize> master_key_{};
  NvsCounterStore* counter_store_{nullptr};
  NvsReplayStore replay_store_{};
  ReplayGuard replay_guard_{replay_store_};
  bool ready_{false};
  FixedPool<TxContext, kContextCapacity> tx_contexts_{};
  FixedPool<RxContext, kContextCapacity> rx_contexts_{};
  std::uint64_t context_stamp_{0};
};

}  // namespace routeloom::espnow
