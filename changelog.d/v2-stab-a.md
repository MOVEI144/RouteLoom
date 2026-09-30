### Changed

- A USB gateway reclaims its oldest reported terminal legacy send record when
  its 16-record table is full, so one boot accepts an unbounded number of
  sends. A resubmitted key whose record was reclaimed is not executed again:
  the gateway answers `Conflict` with the new reason `RESULT_EXPIRED`, and the
  daemon marks that SEND `indeterminate` / `RESULT_EXPIRED`. Only a table of
  in-flight or unreported sends still answers `IDEMPOTENCY_FULL`. The fixed
  tombstone set is replaced by a floor scoped to the authenticated session;
  legacy keys must not be retried across reconnects.
- A resubmitted legacy key whose send already ended now replays its terminal
  state (or its refusal) with `IDEMPOTENT_REPLAY`, instead of `accepted`.

### Fixed

- Back-to-back legacy SENDs through a USB gateway no longer stay `queued`,
  `waiting-for-mac` or `sent`: the gateway keeps each terminal outcome until
  its USB queue takes it, and sends one coalesced RX credit grant at a time,
  so grants no longer crowd out delivery events (H0 F7, H1 S5).
- A USB gateway no longer refuses every send with `IDEMPOTENCY_FULL` after
  about 112 sends in one boot (H0 F8, H1 S4).
- In-flight retries reserve a terminal notification for each request within
  the same 16-record bound. Retrying cannot steal the original notification,
  and time alone never evicts an in-flight record.
- Capacity, conflict and expired-result refusals survive a full CONTROL queue
  within the granted receive window.
