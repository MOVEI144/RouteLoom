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
// measured. owner_wait_for_event below is the one wait procedure both
// firmware (EspNowRuntime::wait_for_event) and the host harness
// (OwnerPump::wake_at) execute: staged work skips the wait, otherwise a
// bounded event wait where a posted event wins over the timeout.

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

// Shared owner wait (issue #60-3): staged work runs NOW, otherwise block
// at most `timeout_ms` for a queued event — a posted event releases the
// wait early instead of riding out the tick. `EventQueue` injects only
// the blocking primitive and must provide:
//
//   void wait_until_posted(MonotonicMs timeout_ms) noexcept;
//
// Firmware binds it to the FreeRTOS event queue (xQueuePeek); the host
// harness binds it to a virtual-time fake. Everything else — the staged
// gate, the timeout bound, the event-wins ordering — lives here, so both
// sides execute the same wait judgment. Replacing the queue wait with a
// fixed delay reintroduces the tick tax; the host regression test pins
// the early-wake path through this routine.
template <typename EventQueue>
inline void owner_wait_for_event(EventQueue& queue,
                                 const MonotonicMs timeout_ms,
                                 const bool staged_pending) noexcept {
  if (owner_wait_timeout_ms(timeout_ms, staged_pending) == 0) {
    return;
  }
  queue.wait_until_posted(timeout_ms);
}

}  // namespace routeloom
