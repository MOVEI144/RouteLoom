#pragma once

#include <cstring>

#include "routeloom/discovery_scope.hpp"
#include "routeloom/status.hpp"

namespace routeloom::espnow {

// Development discovery-scope key provider (EXPERIMENTAL). Per-generation
// scope keys are derived on demand:
//
//   K_gen = HMAC-SHA-256(base_key, "RouteLoom/scope-gen/v1" || u32be gen)
//
// and tags are left-128 HMAC-SHA-256 under K_gen (discovery_scope.hpp
// §provider boundary). A deployment installs one base key plus a starting
// generation; rotation demotes current to previous for the bounded overlap
// window (02 §2.6). Derivations on demand keep provider state O(1): only
// base_key + the two ring generations exist, no per-generation key table.
//
// This is a DEVELOPMENT provider: the base key lives in firmware config, so
// flash readout recovers it. Production deployments must plug a
// hardware-backed provider where key material never leaves secure storage —
// see docs/design/sdk-completion/04-provisioning-lifecycle.md. The provider
// fails closed: an uninstalled key, a foreign ScopeRef, or a generation the
// ring does not know all error out rather than guess.
class DevScopeProvider final : public DiscoveryScopeProvider {
 public:
  explicit DevScopeProvider(const ScopeRef ref) noexcept : ref_(ref) {}

  ScopeRef ref() const noexcept { return ref_; }

  // EXPERIMENTAL — Development profile by interface default; the honest
  // override exists so a production adapter cannot silently inherit it.
  SecurityProfile security_profile() const noexcept override {
    return SecurityProfile::Development;
  }

  // First install. `base_key` must be exactly kScopeKeyBytes; `generation`
  // must be nonzero (ScopeKeyRing enforces). Repeat installs fail.
  Status install(ByteView base_key, std::uint32_t generation,
                 MonotonicMs now_ms) noexcept {
    if (base_key.size != kScopeKeyBytes || base_key.data == nullptr) {
      return Status::error(StatusCode::InvalidArgument,
                           "scope key must be 32 bytes");
    }
    const Status status = ring_.install(generation, now_ms);
    if (status) {
      std::memcpy(base_key_.data(), base_key.data, kScopeKeyBytes);
      installed_ = true;
    }
    return status;
  }

  // Monotonic rotation: next must be strictly greater than current
  // (u32 exhaustion ends the scope rather than wrapping — 02 §2.6).
  Status rotate(std::uint32_t next_generation, MonotonicMs now_ms) noexcept {
    if (!installed_) {
      return Status::error(StatusCode::InvalidState, "no scope key installed");
    }
    return ring_.rotate(next_generation, now_ms);
  }

  // After a reboot the elapsed previous-overlap window is unprovable; drop
  // the demoted generation rather than extend its acceptance beyond intent.
  void drop_previous() noexcept { ring_.drop_previous(); }

  bool current_generation(const ScopeRef scope,
                          std::uint32_t& out) noexcept override {
    return scope == ref_ && installed_ && ring_.current(out);
  }

  bool accepted_generation(const ScopeRef scope, std::uint32_t generation,
                           MonotonicMs now_ms) noexcept override {
    return scope == ref_ && installed_ &&
           ring_.accepted(generation, now_ms);
  }

  Status scope_tag(const ScopeRef scope, const std::uint32_t generation,
                   const ByteView input, ScopeTag& out) noexcept override {
    if (scope != ref_ || !installed_) {
      return Status::error(StatusCode::AuthProfileUnavailable,
                           "scope key unavailable");
    }
    // The interface contract requires failure for generations we would not
    // accept. scope_tag carries no clock, so we restrict to generations the
    // ring knows (current or demoted-previous); the engine additionally
    // gates acceptance through accepted_generation on the verify path.
    if (generation != ring_current() && generation != ring_.previous()) {
      return Status::error(StatusCode::NotFound, "unknown scope generation");
    }
    std::array<std::uint8_t, kScopeKeyBytes> key{};
    key_for(generation, key);
    ScopeDigest mac{};
    hmac_sha256(ByteView{key.data(), key.size()}, input, mac);
    std::memcpy(out.data(), mac.data(), out.size());
    return Status::success();
  }

 private:
  std::uint32_t ring_current() const noexcept {
    std::uint32_t out = 0;
    ring_.current(out);
    return out;
  }

  // K_gen = HMAC-SHA-256(base_key, domain || u32be generation)
  void key_for(const std::uint32_t generation,
               std::array<std::uint8_t, kScopeKeyBytes>& out) const noexcept {
    static constexpr char kDomain[] = "RouteLoom/scope-gen/v1";
    std::uint8_t gen_be[4] = {
        static_cast<std::uint8_t>(generation >> 24U),
        static_cast<std::uint8_t>(generation >> 16U),
        static_cast<std::uint8_t>(generation >> 8U),
        static_cast<std::uint8_t>(generation),
    };
    hmac_sha256(ByteView{base_key_.data(), base_key_.size()},
                ByteView{reinterpret_cast<const std::uint8_t*>(kDomain),
                         sizeof(kDomain) - 1},
                ByteView{gen_be, sizeof(gen_be)}, ByteView{}, out);
  }

  ScopeRef ref_{};
  std::array<std::uint8_t, kScopeKeyBytes> base_key_{};
  ScopeKeyRing ring_{};
  bool installed_{false};
};

}  // namespace routeloom::espnow
