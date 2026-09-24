#pragma once

// Production GK GroupEnd/GroupLink cryptography. Pairwise calls go straight
// to the installed P4 provider; there is no PSK fallback for group traffic.
#include "routeloom/aead_gcm.hpp"
#include "routeloom/sdkv1_group_keys.hpp"

namespace routeloom::sdkv1 {

struct GroupReplayBank {
  std::uint32_t epoch{0};
  std::uint64_t max{0};
  std::uint64_t bitmap{0};
};
struct GroupReplaySender {
  NodeId sender{0};
  std::uint32_t boot{0};
  GroupReplayBank banks[2]{};
};
static_assert(sizeof(GroupReplaySender) <= 64, "group sender RAM budget");

class GroupSecurityProvider final : public SecurityProvider {
 public:
  GroupSecurityProvider(GroupKeyState& keys, SecurityProvider& pairwise,
                        const AeadGcm& aead, NodeId self) noexcept
      : keys_(keys), pairwise_(pairwise), aead_(aead), self_(self) {}
  GroupSecurityProvider(const GroupSecurityProvider&) = delete;
  GroupSecurityProvider& operator=(const GroupSecurityProvider&) = delete;
  ~GroupSecurityProvider();

  bool ready() const noexcept override { return pairwise_.ready(); }
  Status tx_epoch(SecurityScope scope, NodeId peer, std::uint32_t& epoch) noexcept override;
  ContextState context_state(SecurityScope scope, NodeId peer) const noexcept override;
  Status tx_group_link_epochs(std::uint32_t& boot, std::uint32_t& g) noexcept override;
  bool accepts_group_epoch(std::uint32_t epoch) const noexcept override {
    return keys_.accepts(epoch);
  }
  Status next_counter(const SecurityContext& context, std::uint64_t& counter) noexcept override;
  Status seal(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView plaintext, MutableByteView ciphertext,
              std::array<std::uint8_t, kAeadTagSize>& tag) noexcept override;
  Status open(const SecurityContext& context, std::uint64_t counter, ByteView aad,
              ByteView ciphertext, const std::array<std::uint8_t, kAeadTagSize>& tag,
              MutableByteView plaintext) noexcept override;
 private:
  Status material(const SecurityContext& context, keys::TrafficKey& out,
                  bool transmit) noexcept;
  bool allowed_sender(const SecurityContext& context) const noexcept;
  GroupReplaySender* sender(const SecurityContext& context) noexcept;
  GroupReplaySender* free_sender(SecurityScope scope) noexcept;
  static bool replay_ok(const GroupReplaySender& sender, std::uint32_t epoch,
                        std::uint32_t boot, std::uint64_t counter) noexcept;
  void replay_commit(GroupReplaySender& sender, NodeId peer, std::uint32_t epoch,
                            std::uint32_t boot, std::uint64_t counter) noexcept;

  GroupKeyState& keys_;
  SecurityProvider& pairwise_;
  const AeadGcm& aead_;
  NodeId self_;
  std::array<GroupReplaySender, 128> link_rx_{};
  std::array<GroupReplaySender, 8> end_rx_{};
  std::array<std::uint8_t, kMaxEspNowBody> staging_{};
  std::uint64_t link_tx_{0};
  std::uint64_t end_tx_{0};
  std::uint64_t link_sealed_{0};
  std::uint64_t end_sealed_{0};
  bool link_has_sealed_{false};
  bool end_has_sealed_{false};
  bool in_call_{false};
};

}  // namespace routeloom::sdkv1
