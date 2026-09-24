#include "routeloom/espnow_sdkv1_entropy.hpp"

#include "bootloader_random.h"
#include "psa/crypto.h"
#include "routeloom/secure_clear.hpp"

namespace routeloom::espnow {

EspMaintenanceEntropy::~EspMaintenanceEntropy() noexcept {
  if (source_enabled_) bootloader_random_disable();
}

Status EspMaintenanceEntropy::begin() noexcept {
  if (state_ != State::Uninitialized) {
    return Status::error(StatusCode::InvalidState, "maintenance entropy already started");
  }
  // The maintenance build owns neither RF nor ADC. ESP-IDF's PSA external
  // RNG reads esp_fill_random(), which needs this continuous source pre-RF.
  bootloader_random_enable();
  source_enabled_ = true;
  if (psa_crypto_init() != PSA_SUCCESS) {
    state_ = State::Failed;
    bootloader_random_disable();
    source_enabled_ = false;
    return Status::error(StatusCode::InvalidState, "maintenance PSA init failed");
  }
  std::uint8_t probe[32]{};
  const psa_status_t probe_status = psa_generate_random(probe, sizeof(probe));
  secure_clear(probe, sizeof(probe));
  if (probe_status != PSA_SUCCESS) {
    state_ = State::Failed;
    bootloader_random_disable();
    source_enabled_ = false;
    return Status::error(StatusCode::InvalidState, "maintenance entropy probe failed");
  }
  state_ = State::Ready;
  return Status::success();
}

Status EspMaintenanceEntropy::fill(const MutableByteView out) noexcept {
  if (out.data == nullptr && out.size != 0) {
    return Status::error(StatusCode::InvalidArgument, "maintenance entropy target");
  }
  if (state_ != State::Ready) {
    return Status::error(StatusCode::InvalidState, "maintenance entropy not ready");
  }
  if (out.size == 0) return Status::success();
  if (psa_generate_random(out.data, out.size) != PSA_SUCCESS) {
    secure_clear(out.data, out.size);
    state_ = State::Failed;
    bootloader_random_disable();
    source_enabled_ = false;
    return Status::error(StatusCode::InvalidState, "maintenance entropy draw failed");
  }
  return Status::success();
}

}  // namespace routeloom::espnow
