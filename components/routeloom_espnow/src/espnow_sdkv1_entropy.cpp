#include "routeloom/espnow_sdkv1_entropy.hpp"

#include "bootloader_random.h"
#include "esp_random.h"
#include "routeloom/secure_clear.hpp"

namespace routeloom::espnow {
namespace {

constexpr unsigned char kPersonalization[] = "RouteLoom/maintenance-keygen/v1";

int hardware_entropy(void*, unsigned char* output, const std::size_t length) {
  if (output == nullptr) return -1;
  esp_fill_random(output, length);
  return 0;
}

}  // namespace

EspMaintenanceEntropy::EspMaintenanceEntropy() noexcept { mbedtls_ctr_drbg_init(&drbg_); }

EspMaintenanceEntropy::~EspMaintenanceEntropy() noexcept {
  mbedtls_ctr_drbg_free(&drbg_);
  if (source_enabled_) bootloader_random_disable();
}

Status EspMaintenanceEntropy::begin() noexcept {
  if (state_ != State::Uninitialized) {
    return Status::error(StatusCode::InvalidState, "maintenance entropy already started");
  }
  // The bootloader turns this source off before app_main. The maintenance
  // build owns neither RF nor ADC, so it can keep the source active for
  // DRBG reseeds throughout the console session.
  bootloader_random_enable();
  source_enabled_ = true;
  if (mbedtls_ctr_drbg_seed(&drbg_, hardware_entropy, nullptr, kPersonalization,
                            sizeof(kPersonalization) - 1) != 0) {
    state_ = State::Failed;
    bootloader_random_disable();
    source_enabled_ = false;
    return Status::error(StatusCode::InvalidState, "maintenance entropy seed failed");
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
  if (mbedtls_ctr_drbg_random(&drbg_, out.data, out.size) != 0) {
    secure_clear(out.data, out.size);
    state_ = State::Failed;
    bootloader_random_disable();
    source_enabled_ = false;
    return Status::error(StatusCode::InvalidState, "maintenance entropy draw failed");
  }
  return Status::success();
}

}  // namespace routeloom::espnow
