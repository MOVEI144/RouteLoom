#pragma once

// Pre-RF factory key generation keeps the chip's internal entropy source
// active while PSA's ESP-IDF RNG provider draws. Keys require a ready provider.

#include <cstdint>

#include "routeloom/discovery.hpp"

namespace routeloom::espnow {

class EspMaintenanceEntropy final : public EntropySource {
 public:
  EspMaintenanceEntropy() noexcept = default;
  ~EspMaintenanceEntropy() noexcept override;

  EspMaintenanceEntropy(const EspMaintenanceEntropy&) = delete;
  EspMaintenanceEntropy& operator=(const EspMaintenanceEntropy&) = delete;

  Status begin() noexcept;
  Status fill(MutableByteView out) noexcept override;

 private:
  enum class State : std::uint8_t { Uninitialized, Ready, Failed };
  State state_{State::Uninitialized};
  bool source_enabled_{false};
};

}  // namespace routeloom::espnow
