#pragma once

// Owner-task pump cadence shared by every runtime loop that drives a
// MeshNode: the ESP-NOW runtime task (espnow_runtime task_entry), the
// firmware app_main pump loops, and the host-side simulation harness.
//
// Issue #60-3: an idle owner task must sleep at most one poll period —
// and must wake EARLIER when a driver event (TX completion, RX frame) is
// queued. A TX completion posted mid-sleep that rides out the full period
// leaves idle airtime between back-to-back frames: ~1-2ms of dead time on
// a ~6ms HOP_ACCEPT-class exchange is the 25-30% throughput loss the issue
// measured. Firmware binds the wait to the OS queue
// (EspNowRuntime::wait_for_event); the host sim computes it with
// owner_wake_at — the period and the event-wins rule are fixed here once
// for both.

#include "types.hpp"

namespace routeloom {

// Maximum idle between owner-task passes: poll()'s timers, retries and
// advertisement cadence are tuned to this granularity.
inline constexpr MonotonicMs kOwnerPollPeriodMs = 2;

// The wait policy every owner pump implements: wake at the earlier of the
// next queued driver event and the periodic tick. `next_event_ms` is the
// stamp of the soonest queued event — pass a value >= idle_since_ms +
// kOwnerPollPeriodMs (or UINT64_MAX) when nothing is pending.
inline MonotonicMs owner_wake_at(const MonotonicMs idle_since_ms,
                                 const MonotonicMs next_event_ms) noexcept {
  const MonotonicMs tick = idle_since_ms + kOwnerPollPeriodMs;
  return next_event_ms < tick ? next_event_ms : tick;
}

}  // namespace routeloom
