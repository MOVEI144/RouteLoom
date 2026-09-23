#pragma once

#include <array>
#include <cstdint>

#include "routeloom/status.hpp"
#include "routeloom/types.hpp"

namespace routeloom {

// Largest crypto counter a context may issue: Wire v2 carries u48 counters
// (2.8e14 frames per epoch). A context that reaches it must move to a new
// epoch; counters are never wrapped under the same key.
constexpr std::uint64_t kMaxCryptoCounter = 0xFFFFFFFFFFFFULL;

struct SecurityContext {
  SecurityScope scope{SecurityScope::Link};
  NetworkId network{0};
  NodeId sender{kInvalidNodeId};
  NodeId receiver{kInvalidNodeId};
  std::uint32_t epoch{0};  // Wire v2: 32-bit, never wraps in a device lifetime
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
