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

class SecurityProvider {
 public:
  virtual ~SecurityProvider() = default;

  virtual bool ready() const noexcept = 0;
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
