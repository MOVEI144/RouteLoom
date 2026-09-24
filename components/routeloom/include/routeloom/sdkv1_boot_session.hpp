#pragma once

#include <cstdint>

#include "routeloom/status.hpp"

namespace routeloom::sdkv1 {

// Only the system rlboot namespace backs this port. A missing key is distinct
// from an unreadable key: an IO error must never authorize a fresh epoch.
class BootSessionPort {
 public:
  virtual ~BootSessionPort() = default;
  virtual Status read(std::uint32_t& stored, bool& found) noexcept = 0;
  virtual Status commit(std::uint32_t value) noexcept = 0;
};

class BootSessionStore final {
 public:
  explicit BootSessionStore(BootSessionPort& port) noexcept : port_(port) {}

  // The caller publishes the result only after commit and readback. When a
  // site exists, missing/rolled-back rlboot must skip past its witness.
  Status advance(bool has_site, std::uint32_t witness,
                 std::uint32_t& session) noexcept;

 private:
  BootSessionPort& port_;
};

}  // namespace routeloom::sdkv1
