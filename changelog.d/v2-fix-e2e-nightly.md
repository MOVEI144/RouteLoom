Real-Owner E2E now exercises the 32-process simultaneous latest/group case
with bounded tree fanout and verified receive records. Repeated burst tests
establish direct gateway bindings and use the existing 256-entry gateway
dedup profile while leaving member profiles and retention unchanged.

Added host latest-value coverage through a USB disconnect and fresh-session
reconnect: 12 admissions per minute replace 11 queued values, and only the
last value reaches the destination. Hardware qualification remains pending.
