#pragma once

#include <array>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

struct SecurityContext {
  SecurityScope scope{SecurityScope::Link};
  NetworkId network{0};
  NodeId sender{kInvalidNodeId};
  NodeId receiver{kInvalidNodeId};
  std::uint16_t epoch{0};
};

// Deployment assurance level a provider is allowed to claim. The default is
// Development: only a provider implementing the qualified production profile
// (G-SEC: EDHOC/RPK device identity, audited entropy contract) may return
// Production. Anything else — including the development PSK — is EXPERIMENTAL
// and must be surfaced to operators as such.
enum class SecurityProfile : std::uint8_t {
  Development = 0,  // EXPERIMENTAL; never advertise as production-secure
  Production = 1,
};

class SecurityProvider {
 public:
  virtual ~SecurityProvider() = default;

  virtual bool ready() const noexcept = 0;
  // Deliberately defaults to Development so a provider cannot accidentally
  // claim production status by omission.
  virtual SecurityProfile security_profile() const noexcept {
    return SecurityProfile::Development;
  }
  virtual Status next_counter(const SecurityContext& context,
                              std::uint64_t& counter) noexcept = 0;
  virtual Status seal(const SecurityContext& context,
                      std::uint64_t counter,
                      ByteView aad,
                      ByteView plaintext,
                      MutableByteView ciphertext,
                      std::array<std::uint8_t, kAeadTagSize>& tag) noexcept = 0;
  virtual Status open(const SecurityContext& context,
                      std::uint64_t counter,
                      ByteView aad,
                      ByteView ciphertext,
                      const std::array<std::uint8_t, kAeadTagSize>& tag,
                      MutableByteView plaintext) noexcept = 0;
};

}  // namespace routeloom
