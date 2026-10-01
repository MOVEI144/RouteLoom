# V2-STAB-B blocking review and acceptance rerun (2026-10-01 JST)

This round started at `aa8aa4ba52b3c936e292197c272a0dc49b7d8c31`.
`git fetch origin && git merge origin/main` merged main
`d5d307556a918d030f590b8a27b088d69a4c6bfc` as `ede3e610`; no conflicts.
The reviewed production fixes end at `5820b8d8`; subsequent changes are tests,
measured CI budgets and this evidence. STATUS and implementation-plan 08 were
not edited. No push, eFuse write, security downgrade, capacity change or
production channel/rate fallback was made.

## Software findings and verification

- Cached migration blobs could bypass site/authority and structural validation
  during late commit adoption and restart. Both paths now validate size, digest,
  site, authority, epoch and the plan structure before adopting the blob. The
  table-driven regression failed four assertions before the fix.
- A retained link M4 occupied the crypto flight while another exchange waited;
  a fresh discovery carrier could also be mistaken for the old completed one.
  The existing bounded retry record retains exact M4 bytes, M1/M3 hashes, RX
  context and the original deadline. A cookie-verified fresh link carrier can
  supersede the completed link. The workspace can serve another link or a
  routed exchange; end-to-end authentication confirmation is still required.
  Lost M4, altered M3, forged cookie and exact installed-context confirmation
  are covered. No allocated buffer or state machine was added.
- While awaiting M4, an initiator retried its obsolete small M1 cache instead
  of the composed M3. M3 now replaces that cache. A regression loses the first
  M3 and first M4 and verifies exact M3 retry and one installation; it failed
  nine assertions before the fix.
- A newly bound gateway neighbour did not exchange its current scoped route
  records if an obsolete indirect gateway route suppressed the bootstrap pull.
  Fresh bindings now use the existing bounded pull-answer queue. Queue refusal
  keeps the pending work; accepted enqueue advances it. The regression failed
  two assertions before the fix. The real Owner/MeshNode M06 reset-cycle test
  improved from 88/100 to 99/100; this is virtual-time interop, not hardware.
- Three tests depended on sampling/poll cadence: M06 counted transient accepted
  snapshots, C1 advanced a busy radio in large clock jumps, and queue pressure
  checked one instant. They now check each request's terminal receipt, poll at
  the normal 25 ms cadence and wait boundedly for actual queue pressure.
  Delivery, authentication, READY, persistence and capacity assertions remain.
  M06's first-delivery deadline is measured from reset, rather than reauth.

Red/green and final logs are retained in ignored `build-review-logs`, with
hashes in the evidence index. Existing J05, stranded-plan, host epoch and N1
changes were reviewed and exercised; their implementation report was not used
as proof of acceptance.

## Bench, images and provenance

The pinned bench is `bench-2026-09-29-h0`: C3 gateway Node1
`94:a9:90:7a:26:ac`, C6 relay Node2 `10:bd:a3:b1:48:a8`, and C6 endpoint Node3
`10:bd:a3:b1:47:54`. Chip/MAC checks preceded writes; app-only changes preserve
sealed NVS by matching before/after hashes. Only these three authorised boards
were factory erased for a fresh site. Keys and NVS contents stay outside Git in
private directories. The fresh site's public SiteId is `160382f4bd6d8c2b`, home
channel 6; endpoint membership advances from generation 1 to 2 in J05.

All SDK images use pinned ESP-IDF v6.0.3, commit
`76f5dedd9950a3012fee8fb7d5586df21fc67802`. Public image/config/RAM manifests
and hashes are under `artifacts/hil/2026-10-01-stab-review/images/`.
The normal `review-br`, `review-relay` and `review-ep` bundles record base
`33e44b04` plus then-uncommitted changes later committed as `2a885a1c` and
`5820b8d8`, with source digest
`c05d619998dd9b462d24579589e657fcde67ee0465cc587ebea238b139434c38`.
This is not labelled a clean build of the base SHA. The forced-chain and N1
bundles record `acece452`, with the same final production code. The chain
uses the existing HIL MAC RX filters on G and A to exclude their direct link;
normal images have empty filters. No quiet handshake trace was added to the
normal images.

## Hardware acceptance

The raw evidence is under `artifacts/hil/2026-10-01-stab-review/`.
Observed receipt completion includes send latency. A tool's process exit code
alone is not an acceptance verdict.

| Gate | Observation | Acceptance |
|---|---|---|
| Simultaneous boot, five normal-image fresh-daemon common resets | Both members participate in all five runs; routes observed 46.67, 4.10, 7.19, 4.09 and 5.13 s after common release. Fresh gateway sessions and live node-status sources were checked. Subsequent balanced sends 20/20. | 5/5 this round; the earlier 4/5 failure is not erased or explained. |
| N1, C3 node status compiled out | Authenticated HelloAck capability `0x1e27`, bit 6 clear; 5/5 relay deliveries; gateway remained awake/authenticated. | PASS for this image. |
| J05 recovery removal and holdoff | Endpoint learns removal through recovery join, restarts unassigned after 600.49 s, logs `local_revocation: none`, returns at generation 2 and delivers 10/10. | Cleanup/rejoin verified; strict 8 s isolation variant is not a hardware PASS (controls below). |
| Gateway reset, ten cycles | 88/100 post-reauth deliveries, all 100 requests terminal; per cycle 10,10,10,8,10,0,10,10,10,10. Reauth 2.1–2.34 s; cycle 5 had no neighbour/route in the 20 s send window. | FAIL, below 95/100. |
| Relay reset, forced G–B–A, ten cycles | Forced next hop 2 verified, baseline 3/3, 65/100; per cycle 9,5,6,8,5,6,4,8,4,10. Both-neighbour ≤6 s and first receipt ≤10 s in only 3/10 cycles. First delivery 4.60–37.27 s; no IDEMPOTENCY_FULL or boot-floor failure. | FAIL. |
| Channel plan 6→1→6 and exact missed 1→6 switch | Forward READY 2/2 and channel 1 / epoch 1, then 0/20 to each member. After 650 s cooldown, return offer admitted; READY 0/2, Aborted, unreleased. Endpoint was never held for this offer. | FAIL; exact missed 1→6 switch not started. |

### Channel-plan controls

The first two offer attempts returned BUSY while an asynchronous status request
was still in flight; no plan was issued then. The final attempt waited for a
fresh report and used bounded BUSY retries. The released forward plan hash is
`ed0863fac2158691c010d0d2a2a7a97040609df83da18141cf5a959a2565bf1c`,
ledger sequence 1. Both C6 radios read back channel 1 / generation 1. Their
raw send failures rose while driver admission errors stayed zero. The 40
accepted sends all ended HOP_ACCEPT_TIMEOUT. Each member later searched the
home channel 6 and bound the other member there; the authority remained on 1.
This does not establish a successful verified return cutover.

The return hash is
`dadd49e518064e62ff0f8d2b671d9a0dde03b33677d1c0d97c930fa8dfb3df98`,
ledger sequence 2. At 130 s after admission its fresh report was Aborted,
READY 0/2 and unreleased. No READY or authentication gate was bypassed, and
11→6 is not substituted for the required 1→6 scenario.

### J05 controls

The nominal isolation script recorded 11.57 s, not 8 s. A console/reset
interaction left the C6 in ROM; captures were closed, then reset and reopened.
An additional watchdog-reset control reported that C6 watchdog hard reset is
unsupported and fell back to the normal reset. The endpoint then logged RX=0
with largest free block 143,360 B. Resetting the relay made advertisements
available and the endpoint received again, then learned its removal at
01:13:32.640 UTC. This observation alone does not establish a driver receive
fault: quiet authenticated peers and the changed membership group also affect
what reaches this device. The holdoff restart was at 01:23:33.132 UTC.
The join approval observer was restarted after the deliberate N1 daemon swap
closed its socket. No persisted removal record or holdoff was manually erased.
The exact 8 s variant remains covered by live Owner/MeshNode interop, not by
this interrupted physical control sequence.

### Independent radio controls

The preserved app-slot probe tests LR250/LR500, channels 1/6 and configured
power 40/8 qdBm, 20 frames per directed link. All original OTA0 full slots
were restored with matching readback SHA-256 before SDK provisioning.

- Channel 6, 40 qdBm: all six directed links 20/20 at both LR rates.
- Channel 1, both powers and LR rates: C3→C6 20/20; C6→C3 and C6→C6 0/20.
- Channel 6, 8 qdBm: C3→C6 20/20; C6 outgoing mostly 0/20 (one link 1/20).
- No synchronous driver send errors. These are MAC receipt controls, not
  authenticated SDK application deliveries. Probe Wi-Fi buffers differ from
  the SDK profile.

Lowering transmit power or using LR500 did not repair channel 1. These results
reproduce below mesh but do not uniquely separate RF, antenna/board and
IDF/PHY effects. Neither an RF-only cause nor a defective endpoint is proven.

A second independent probe uses official ESP-IDF v5.5.3, commit
`2c211b236707889e8400c4dc5644dd5c4ee071e0`, container digest
`sha256:8ccd4d2ce413889c6c2bba57e986c670302094efb91c913c6091152e317a7805`.
The same eight phases and 48 directed-link observations are retained in
`radio-driver/results.json`, with the exact probe source and image hashes.
On channel 1 at 40 qdBm / LR250, relay→gateway is 20/20 and
endpoint→gateway 12/20, whereas both were 0/20 with v6.0.3. Other directions
also change: gateway→endpoint and relay→endpoint are 0/20 in most or all
phases, including channel 6. This is an entire IDF-version control, not an
isolated PHY-library change, and does not establish a unique driver regression.
There are no synchronous send errors. Original OTA0 slots and all three sealed
NVS partitions were restored with matching before/after hashes on every board.

No spare board, antenna change, independent RF environment or physical USB
power-cycle control was available. The gateway/endpoint USB hub shares power
control with unrelated devices, including a network interface; its power was
not toggled. Those missing controls remain necessary to distinguish causes.
The official ESP-NOW documentation also distinguishes MAC send completion from
application receipt; it is not used as proof of the cause:
<https://docs.espressif.com/projects/esp-idf/en/stable/esp32c6/api-reference/network/esp_now.html>.

## Flash and static RAM

Matching normal bench configs are byte-identical to the previous `e597da2e`
bundles, including the existing HIL heap telemetry. No extra handshake trace
is enabled. `images/normal-footprint.json` retains both RAM reports.

| Image | Previous app | Reviewed app | Delta | Static RAM delta | Static free / floor |
|---|---:|---:|---:|---:|---:|
| C3 bridge | 1,268,416 B | 1,268,672 B | +256 B | 0 B | 34,192 / 27,648 B |
| C6 relay | 1,352,672 B | 1,352,896 B | +224 B | 0 B | 93,977 / 8,192 B |
| C6 endpoint | 1,297,312 B | 1,297,536 B | +224 B | 0 B | 161,869 / 8,192 B |

Eight CI app budgets exceeded their old baseline plus the 2,048 B drift.
They were refreshed only to measured final image sizes: C3 normal 1,293,168 B,
C3 sleep 1,308,336 B, S3 normal 1,306,384 B, S3 sleep 1,321,280 B, C5 normal
1,458,256 B, C5 sleep 1,473,648 B, C6 bench 1,425,056 B and the C6 C++ endpoint
example 1,325,792 B. Static-free, RTC and hard RAM floors are unchanged.
The first full matrix was 46/54, the next 52/54: the helper's first-six failure
display hid the remaining two budget failures until the second run. All cells
compiled and passed their RAM guards. Proper-cell budget failures and successful
checks of the same artifacts are retained; these were real budget failures,
not infrastructure failures. No capacity reduction is claimed.

## Bench state at completion

After preserving the failed plan evidence, the three authorised boards were
provisioned with a new site through the normal setup and sealing path, home
channel 6, public SiteId `e8b98b1442c655ba`. This did not roll back sealed NVS
or bypass plan READY. The old test site's private directory remains outside
Git; no key contents are included here. Final apps are the reviewed normal
SDK images and member readbacks match their hashes.

Both members participated after the common reset. The first balanced smoke
was 19/20 (one endpoint request DEADLINE_EXPIRED), so the restoration script
returned failure; that result is retained. After settling, a separate balanced
smoke was 20/20. Fresh gateway status reports channel 6 / epoch 0 / ledger 0;
both members are direct reachable neighbours. Member radio readbacks also show
channel 6. The task daemon and captures were stopped and all three serial
ports have no users. This restoration smoke is not substituted for any failed
acceptance gate.

The final port check resolves the pinned `/dev/serial/by-id` paths: relay had
re-enumerated as `ttyACM3` during the driver control. The earlier numeric
`ttyACM0` cleanup query was stale and did not validate that relay port;
`restored-home/final-serial-ports.json` records the corrected check for all
three present devices, with no users.

## Validation and remaining work

Final-source GCC sanitizer Debug ctest: 104/104. Explicit clang 18 containers,
sanitizers ON/OFF: 103/103 each. Rust 1.85 fmt/clippy clean, workspace
1,076 passed; live C++ Owner/MeshNode peers were supplied. Existing ignored
M01-T3 is not a pass. Python suites: repository 177, HIL 34, meshviz 280
including GUI tests with PySide6, no GUI skips. Manifest and reference generation
checks match. Final `routeloom-selfcheck .` returned `VERIFY: PASS`: GCC
104/104, Rust 1,076/0 failures and all 54 firmware cells passed. The complete
matrix cell-name set was checked against `tools/check.py firmware --list`,
with zero failures or skips. All cells enforce the pinned IDF build,
sdkconfig assertions, static RAM floors and measured size budgets.
Final documentation checks are 1,685/1,685 and review contracts 182/182.

Commands retained in the indexed logs include:

- `cmake -S . -B build-rf -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug`,
  `cmake --build build-rf -j8`, `ctest --test-dir build-rf -j8`.
- The requested `silkeh/clang:18` container command, with full build/ctest
  output and exit status, separately for sanitizers ON and OFF. These explicit
  runs do not rely on the common helper's filtered clang output.
- `cargo +1.85.0 fmt --all -- --check`,
  `cargo +1.85.0 clippy --workspace --all-targets -- -D warnings`,
  `cargo +1.85.0 test --workspace` with built C++ joiner/Owner/MeshNode peer
  paths supplied. Selfcheck also supplies all three live-peer environment
  variables before its workspace run.
- `python3 tools/check_docs.py`, `python3 tools/check_review_contracts.py`,
  `python3 tools/gen_manifest.py --check`,
  `python3 tools/sync_reference_tables.py --check`, `tools/check.py scenarios`.
- `python3 -m unittest discover -s tests`,
  `PYTHONPATH=tools/hil python3 -m unittest discover -s tools/hil`,
  `PYTHONPATH=tools/meshviz/src:tools QT_QPA_PLATFORM=offscreen build/gui-venv/bin/python -m unittest discover -s tools/meshviz/tests`.
- Pinned `tools/hil/build_image.sh` for normal, forced-chain and N1 images;
  final `routeloom-selfcheck .`, including `routeloom-idf-build --matrix`.

No PR exists for this branch (`gh pr list --head Aero123421/v2-stab-b --state all`
returned `[]`). Remote CI is unverified; local CI-equivalent results are not
labelled remote CI checks. Common helpers and source files outside this
repository were not edited, and no helper cell addition is needed.

Authentication, persistence, READY and the public wire/API/defaults contracts
remain in force. S4/S5 are V2-STAB-A; multi-hop manual-plan distribution and
V2-16 ECC/poll work are separate scope. Normal-image security poll peaks near
690 ms are a timing observation, not a proved explanation or an exemption
from STAB-B acceptance. The failed reset gates and exact channel requirements
remain obligations of this PR.

A separate lifecycle investigation should cover a leave/readmission to a
different site while retaining `rlplan`/`rlmauth`. The current Trust erasure
clears the site trust and RLV1, but does not clear these namespaces or the
coordinator's plan-channel override; plan active records carry no site id.
This round did not exercise that different-site transition. Its persistence
ownership and regression need review; it is not an explanation for the
same-site reset/channel failures measured here.

STATUS/08 should record the cache-validation, retained link retry, correct M3
retry and fresh scoped route exchange fixes with their regressions; hardware
acceptance remains partial with the measured failures above. Do not mark this
PR complete based on virtual-time interop alone.
