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

// Post-RF boot entropy for the P4 security owner (G-SEC P4 §8.4): PSA
// draws after the radio is up (esp_fill_random is RF-fed from WiFi init,
// so no bootloader_random source is needed — and must not be enabled
// here). begin() runs once the runtime initialized the radio; fill()
// refuses until then and wipes its target on any draw failure.
class EspOwnerEntropy final : public EntropySource {
 public:
  EspOwnerEntropy() noexcept = default;
  Status begin() noexcept;
  Status fill(MutableByteView out) noexcept override;

 private:
  enum class State : std::uint8_t { Uninitialized, Ready, Failed };
  State state_{State::Uninitialized};
};

}  // namespace routeloom::espnow
