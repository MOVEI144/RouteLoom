#pragma once

// Owner-task pump cadence shared by every runtime loop that drives a
// MeshNode: the ESP-NOW runtime task (espnow_runtime task_entry), the
// firmware app_main pump loops, and the host-side simulation harness.
//
// Issue #60-3: an idle owner task must sleep at most one poll period —
// and must never sleep while work is already staged. A TX completion
// posted mid-sleep that rides out the full period leaves idle airtime
// between back-to-back frames: ~1-2ms of dead time on a ~6ms
// HOP_ACCEPT-class exchange is the 25-30% throughput loss the issue
// measured. Firmware binds the wait to the OS queue
// (EspNowRuntime::wait_for_event); the host harness models the same wait
// in OwnerPump — the period and the staged-skips-wait gate below are the
// one wait judgment both sides execute.

#include "types.hpp"

namespace routeloom {

// Maximum idle between owner-task passes: poll()'s timers, retries and
// advertisement cadence are tuned to this granularity.
inline constexpr MonotonicMs kOwnerPollPeriodMs = 2;

// Owner-task wait gate (issue #60-3): `staged_pending` reports work held
// OUTSIDE the queue the task would block on — the firmware lost-TX
// staging slots (wait_for_event checks them under the callback lock), or
// the harness's staged completion. Such work must run NOW: blocking
// would sleep through a resolvable TX completion and leave idle airtime
// before the next submit. Returns the wait timeout: 0 skips the wait and
// runs the next pass immediately, otherwise `timeout_ms`.
inline MonotonicMs owner_wait_timeout_ms(const MonotonicMs timeout_ms,
                                         const bool staged_pending) noexcept {
  return staged_pending ? 0 : timeout_ms;
}

}  // namespace routeloom
