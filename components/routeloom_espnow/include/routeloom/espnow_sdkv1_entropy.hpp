#pragma once

// Pre-RF factory key generation uses the chip's internal entropy source
// to seed a fresh CTR-DRBG. Keys cannot be drawn before seeding succeeds.

#include <cstdint>

#include "mbedtls/ctr_drbg.h"
#include "routeloom/discovery.hpp"

namespace routeloom::espnow {

class EspMaintenanceEntropy final : public EntropySource {
 public:
  EspMaintenanceEntropy() noexcept;
  ~EspMaintenanceEntropy() noexcept override;

  EspMaintenanceEntropy(const EspMaintenanceEntropy&) = delete;
  EspMaintenanceEntropy& operator=(const EspMaintenanceEntropy&) = delete;

  Status begin() noexcept;
  Status fill(MutableByteView out) noexcept override;

 private:
  enum class State : std::uint8_t { Uninitialized, Ready, Failed };
  mbedtls_ctr_drbg_context drbg_{};
  State state_{State::Uninitialized};
  bool source_enabled_{false};
};

}  // namespace routeloom::espnow
