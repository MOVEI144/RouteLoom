### Fixed

- Restore live Owner mesh E2E setup for staged identity-only joins, idle Probe/Result loss and delayed DATA callbacks under the current neighbor lease rules.
- Verify the pending Result on its directed leg within the callback recovery window, so later probes cannot hide a lost reply.
- Preserve the radio cadence during cutover preparation so queued carriers and route reports survive; retain all existing approval, delivery, epoch and deadline assertions.
