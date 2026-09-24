#pragma once

#include <cstdint>

namespace routeloom {

// Boot-fault escalation shared by the firmware mains (issue #34). A fatal
// during boot originally hung in a silent vTaskDelay loop — dead until the
// next power cycle. Restarting unbounded is the other failure mode: every
// boot commits one NVS session write, so a persistent fault (for example a
// corrupted security partition) would burn flash write cycles at restart
// rate forever. The consecutive-failure streak — kept in RTC noinit memory
// on device, so it survives esp_restart and the deep-sleep wake below alike
// — bounds the cadence: exponential backoff capped at 32 s, then one retry
// per long deep sleep once the fault proves persistent. A transient fault
// still self-heals; a persistent one drops to deep-sleep current and a
// flash-bounded retry rate. Pure arithmetic so the cadence contract is
// host-testable.
struct FailAction {
  // false: wait delay_ms, then esp_restart. true: esp_wifi_stop, arm a
  // delay_ms timer wake and esp_deep_sleep_start — the safe halt.
  bool deep_sleep;
  std::uint32_t delay_ms;
};

// 500 ms << 6 = 32 s backoff cap. Eight consecutive failed boots (~2 min of
// escalating restarts) mark the fault persistent; from then on each retry
// costs one 30-minute sleep — at most ~57 boot attempts per day.
constexpr std::uint32_t kFailBackoffBaseMs = 500;
constexpr std::uint32_t kFailBackoffMaxShift = 6;
constexpr std::uint32_t kFailSleepStreakMin = 8;
constexpr std::uint32_t kFailSleepMs = 30U * 60U * 1000U;

constexpr FailAction fail_action(const std::uint32_t streak) noexcept {
  if (streak >= kFailSleepStreakMin) {
    return FailAction{/*deep_sleep=*/true, kFailSleepMs};
  }
  const std::uint32_t shift =
      streak < kFailBackoffMaxShift ? streak : kFailBackoffMaxShift;
  return FailAction{/*deep_sleep=*/false, kFailBackoffBaseMs << shift};
}

}  // namespace routeloom
