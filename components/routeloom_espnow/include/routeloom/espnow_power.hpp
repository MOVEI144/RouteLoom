#pragma once

#include <cstdint>

#include "routeloom/espnow_runtime.hpp"
#include "routeloom/nvs_counter_store.hpp"
#include "routeloom/power.hpp"

namespace routeloom::espnow {

// Point-of-no-return notification inside EspNowPowerPort::enter_sleep():
// fired after the Wi-Fi driver is stopped, immediately before
// esp_deep_sleep_start() — the last instant firmware can still observe
// that a coordinated sleep is actually entering. The reference node's
// boot-fault streak uses it as its stability proof. If
// esp_deep_sleep_start() ever returned (it does not on real silicon), the
// hook would have already run — a benign false clear on an impossible
// path.
class PreSleepHook {
 public:
  virtual ~PreSleepHook() = default;
  virtual void on_pre_sleep() noexcept = 0;
};

// PowerPort implementation for EspNowRuntime. Peer capture/restore goes
// through the runtime's peer table so driver peers are re-registered with
// the LR250 rate config on resume. Deep-sleep entry is guarded by firmware
// configuration; this class never sleeps unless enter_sleep() is invoked.
class EspNowPowerPort final : public PowerPort {
 public:
  explicit EspNowPowerPort(EspNowRuntime& runtime) noexcept : runtime_(runtime) {}

  // Optional last-instant observer; see PreSleepHook. Not owned.
  void set_pre_sleep_hook(PreSleepHook* hook) noexcept {
    pre_sleep_hook_ = hook;
  }

  Status capture_cache(PowerImage& image) noexcept override;
  Status quiesce_radio() noexcept override;
  Status start_radio(const PowerImage* image) noexcept override;
  Status configure_wake(const WakePlan& plan) noexcept override;
  Status enter_sleep() noexcept override;
  Status start_discovery(const PowerImage& image) noexcept override;

 private:
  EspNowRuntime& runtime_;
  PreSleepHook* pre_sleep_hook_{nullptr};
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
