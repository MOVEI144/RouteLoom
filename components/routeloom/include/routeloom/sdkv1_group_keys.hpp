#pragma once

// One Owner-owned GK state for RLS1, group AEAD and Member discovery. Neither
// a verified scope tag nor an unverified epoch hint promotes the durable key.
#include <array>
#include <cstdint>

#include "routeloom/discovery_scope.hpp"
#include "routeloom/key_schedule.hpp"
#include "routeloom/sdkv1_store.hpp"
#include "routeloom/security.hpp"

namespace routeloom::sdkv1 {

class GroupKeyState final {
 public:
  explicit GroupKeyState(SiteStore& store) noexcept : store_(store) {}
  GroupKeyState(const GroupKeyState&) = delete;
  GroupKeyState& operator=(const GroupKeyState&) = delete;
  ~GroupKeyState();

  enum class Op : std::uint8_t { Start, Stage, Activate, AuthenticatedNext, Tick, Stop };
  struct Input {
    Op op{Op::Tick};
    std::uint32_t epoch{0};
    keys::Secret key{};  // Stage only; authenticated authority body, never application input
    std::uint32_t boot{0};  // Start: durable rlboot; Activate: latest durable witness
    std::uint32_t generation{0};  // assignment generation for Stage/Activate
    std::uint16_t overlap_s{10};  // only 10 or 60
  };
  Status advance(const Input& input, MonotonicMs now) noexcept;
  bool ready() const noexcept { return started_ && !blocked_ && !store_.group_scrub_needed(); }
  bool tx_ready() const noexcept { return ready() && boot_ok_; }
  std::uint32_t current() const noexcept { return ready() ? store_.site().gk_epoch_current : 0; }
  std::uint32_t boot() const noexcept { return boot_; }
  NetworkId network() const noexcept { return ready() ? store_.site().network : 0; }
  bool accepts(std::uint32_t epoch) const noexcept;
  bool in_call() const noexcept { return in_call_; }
  bool promotion_pending() const noexcept { return pending_; }

 private:
  friend class GkMemberScopeProvider;
  friend class GroupSecurityProvider;
  Status derive(std::uint32_t epoch, ScopeDigest& prk) const noexcept;
  SiteStore& store_;
  keys::Secret previous_{};
  std::uint32_t previous_epoch_{0};
  MonotonicMs previous_deadline_{0};
  MonotonicMs previous_started_{0};
  std::uint32_t boot_{0};
  std::uint16_t overlap_s_{10};
  bool in_call_{false};
  bool started_{false};
  bool blocked_{false};
  bool boot_ok_{false};
  bool pending_{false};
  Status promote(std::uint32_t epoch, std::uint32_t witness, MonotonicMs now) noexcept;
  void expire() noexcept;
};

// A scope view: no duplicate GK cache, no fallback to a dev PSK. The caller
// must configure Member discovery with ScopeMode::Required.
class GkMemberScopeProvider final : public DiscoveryScopeProvider {
 public:
  GkMemberScopeProvider(GroupKeyState& keys, ScopeRef member) noexcept
      : keys_(keys), member_(member) {}
  bool current_generation(ScopeRef scope, std::uint32_t& out) noexcept override;
  bool accepted_generation(ScopeRef scope, std::uint32_t generation,
                           MonotonicMs now) noexcept override;
  Status scope_tag(ScopeRef scope, std::uint32_t generation, ByteView input,
                   ScopeTag& out) noexcept override;
 private:
  GroupKeyState& keys_;
  ScopeRef member_;
};

}  // namespace routeloom::sdkv1
