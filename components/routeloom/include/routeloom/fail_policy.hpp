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
//
// Streak retention contract (issue #34 r2): the count may clear ONLY on a
// profile-defined stability proof — reaching the runtime main loop on
// always-on builds, or an actually-entered coordinated sleep (the power
// port's pre-sleep hook, fired at the point of no return inside
// enter_sleep) on the DEEP_SLEEP build — plus the power-on magic check.
// Never clear mid-boot: the round-2 bug cleared it when the pump loop
// started, so a persistent late-boot fault (a sleep image store that
// keeps failing, hitting "sleep deadline exceeded" ~40 s in) re-armed the
// 500 ms restart every cycle and never escalated. The FailStreak
// functions below are the only writers of the state — in firmware and in
// the host regression replays alike — so the contract is exercised
// through the same code the device runs.
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

// The two noinit words a firmware main persists the streak in. One struct
// gives the pair a single .rtc_noinit placement and lets the functions
// below be its only writers.
struct FailStreak {
  std::uint32_t magic;
  std::uint32_t count;
};

// "RLFA" — a matching magic is the only thing distinguishing a streak
// that survived esp_restart/deep-sleep wake from power-on garbage.
constexpr std::uint32_t kFailStreakMagic = 0x524c4641;

// Boot-time load, called once at the top of app_main before any fail()
// can run: a foreign magic marks power-on garbage, so re-arm the pair and
// start the count at zero.
inline void fail_streak_boot(FailStreak& streak) noexcept {
  if (streak.magic != kFailStreakMagic) {
    streak.magic = kFailStreakMagic;
    streak.count = 0;
  }
}

// fail()'s consume: hand the retained count to the policy decision and
// immediately retain count+1 for the next boot — a fatal never returns,
// so the bump must precede the restart/sleep it selects.
inline std::uint32_t fail_streak_consume(FailStreak& streak) noexcept {
  const std::uint32_t count = streak.count;
  streak.count = count + 1U;
  return count;
}

// The only mid-run clear: a profile-defined stability proof — the runtime
// main loop starting on always-on builds, an actually-entered coordinated
// sleep (the power port's pre-sleep hook) on the DEEP_SLEEP build. Never
// call this mid-boot: the awake window still runs fallible work whose
// fail() must see the retained count (issue #34 r2).
inline void fail_streak_clear(FailStreak& streak) noexcept {
  streak.count = 0;
}

}  // namespace routeloom
