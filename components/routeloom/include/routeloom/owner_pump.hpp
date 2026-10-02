#pragma once

// Shared Owner wait gate: staged work skips the wait; otherwise a producer
// notification releases it before the next timer. Queue contents remain
// authoritative, including completions staged outside a full radio queue.

#include "types.hpp"

namespace routeloom {

// Compatibility cadence for components without a complete deadline
// contract. A Device with supported deadlines uses its role ceiling.
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
// The host harness binds this gate to a virtual-time fake; the firmware
// uses task notifications after checking its staging. The staged
// gate models the timeout bound and event-wins ordering. Replacing the
// event wait with a fixed delay reintroduces the tick tax; the host
// regression test pins
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
