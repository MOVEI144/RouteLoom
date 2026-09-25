# Live Owner E2E harness (P5 §10.4, P6 §11.4)

The portable C++ Joiner, AuthorityClient, GroupKeyState and
MembershipLifecycle on fake radio/flash run against the real Rust Site
Authority (SQLite ledger, API1 socket, KGuard) over a pipe. The pipe
carries join relay objects plus whole authority carriers; the USB
HostOps 0x64/0x65 fragment layer (`UsbAuthorityAdapter`) runs for real
on the Rust side, so session checks, reassembly limits and the 20 s
down TTL are exercised code, not doubles.

- C++ end: `tests/cpp/joiner_interop_peer.cpp` (build target
  `routeloom_joiner_interop_peer`).
- Rust end: `host/routeloom-host/src/site/joiner_interop.rs`
  (`live_owner_*` tests; the six older `cpp_joiner_*` pipe tests share
  the same binary).

## Running it locally

```sh
cmake -S . -B build -DROUTELOOM_BUILD_TESTS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build --parallel 6 --target routeloom_joiner_interop_peer
cd host
ROUTELOOM_OWNER_PEER=$PWD/../build/tests/cpp/routeloom_joiner_interop_peer \
  cargo test -p routeloom-host --bins site::joiner_interop
```

`ROUTELOOM_OWNER_PEER` names the peer binary; `ROUTELOOM_JOINER_PEER`
still works as a fallback. With no peer configured or built, the tests
skip (ignore-equivalent, never a failure), so a bare
`cargo test --workspace` stays green. CI runs the same module in the
`joiner-interop` job with an ASan/UBSan peer, which always runs live.

## What runs live

P5: join → JoinConfirm → first-contact GK → manual rotation
(Update/Activate with staged/active evidence) → pull recovery of a key
stale across two rotations → exclusion of a removed member (live
channel, notice delivered, fresh GK never sent). P6: RRS1 delivery and
apply over the channel with operation convergence → RemovalNotice,
site erasure and the 600 s holdoff → cutover PREPARE/COMMIT with new
network/GK adoption and channel re-open → SelfRevoked (#139) via an
RRS1 heard ahead of its notice. Power cuts kill and respawn the peer
mid-holdoff and after GK convergence with only the flash files
crossing over (`P` identity/site image, `X` RRS/journal image).

## Determinism

Fixed seeds per test, one virtual clock (`t0` = wall `now_ms` at
start), every pump budgeted, 25 ms steps (1 s steps across the long
600 s windows). Two wall-clock seams exist by construction and stay
deterministic: the adapter stamps down admissions with wall time while
the harness drains on wall time too (virtual time runs ahead, so
draining on virtual time would expire every down past the 20 s TTL —
production runs the two together); API1 stamps wall time, so
back-to-back rotations in one test drive the second `rotate` on the
virtual clock past the 60 s cleanup window.

## Harness boundaries (deliberate)

- Single device, no gossip peers: RRS1 normally arrives over the
  authority channel; the SelfRevoked test injects the genuine
  authority-minted RRS1 bytes as a gossip object (`J` tag) and the
  lifecycle verifies them for real.
- `OwnerLeg` is the test wiring for the portable security components,
  not the firmware `EspNowSecurityOwner` or `MeshNode`. Its runtime port
  records RRS enforcement, trust erasure and cutover callbacks; it does
  not run P4 session or route retirement. The E2E asserts that the
  lifecycle reaches those callbacks and that its durable state changes.
- The cutover test fakes only the offline gateway's Prepared receipt
  (digested over the authority's own staged grant bytes); the pipe
  device prepares, commits and adopts over its real channel.
- Recovery/rejoin legs respawn the peer (power-cut handover), like the
  existing R07/R08 pipe tests; the peer never restarts its Joiner in
  place after `RestartUnassigned`/`RecoveryRequired`.
- Radio muting (`F` tag) stands in for the production discovery gate
  across the removal holdoff.
