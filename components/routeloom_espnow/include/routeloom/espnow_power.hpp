#pragma once

#include <cstdint>

#include "routeloom/espnow_runtime.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/power.hpp"

namespace routeloom::espnow {

// PowerPort implementation for EspNowRuntime. Peer capture/restore goes
// through the runtime's peer table so driver peers are re-registered with
// the LR250 rate config on resume. Deep-sleep entry is guarded by firmware
// configuration; this class never sleeps unless enter_sleep() is invoked.
class EspNowPowerPort final : public PowerPort {
 public:
  explicit EspNowPowerPort(EspNowRuntime& runtime) noexcept : runtime_(runtime) {}

  Status capture_cache(PowerImage& image) noexcept override;
  Status quiesce_radio() noexcept override;
  Status start_radio(const PowerImage* image) noexcept override;
  Status configure_wake(const WakePlan& plan) noexcept override;
  Status enter_sleep() noexcept override;
  Status start_discovery(const PowerImage& image) noexcept override;

 private:
  EspNowRuntime& runtime_;
  bool quiesced_{false};
};

// Two-slot PowerStorage backed by NVS blobs ("img0"/"img1") in an existing
// NvsCounterStore namespace.
class NvsSleepStorage final : public PowerStorage {
 public:
  explicit NvsSleepStorage(NvsCounterStore& store) noexcept : store_(store) {}

  Status read(std::uint8_t slot, MutableByteView target) noexcept override;
  Status write(std::uint8_t slot, ByteView data) noexcept override;

 private:
  NvsCounterStore& store_;
};

}  // namespace routeloom::espnow
