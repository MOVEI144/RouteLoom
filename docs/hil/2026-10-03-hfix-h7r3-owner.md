# H7R3 focused recovery — host regressions, hardware pending

## Target and change

Base: `091114ba2f9b4e86f290854b53ea4a06cd02e273`, after the initial
fetch/merge of main. The authoritative H7R3 observations were made on
`ede5dda32c85e6bbabf4617765ce35d5088f7487`; their failures remain recorded in
[the H7R3 report](2026-10-03-h7r3.md).

The final main integration is `5e207ed78b83c3d154e982e1bc57ab589a1ac3c7`,
including H7R2 through `83057228085e3e356c93ad86c0c44b437b7b4dc7`.
It merged without conflicts. Both H7R2's send/callback hook and this change's
notification-clock hook remain; its admitted End retry accounting is retained.

The focused review started at `bc22c46621cc4e28650e4ef0826e798e74a2fe0d`.
A fresh fetch/merge found main already integrated.

This change fixes idle Owner execution in the existing ESP-NOW runtime,
SecurityCoordinator and MembershipLifecycle. It adds IDF-stub wait accounting
and a three-hop AppObject/foreground-control row to the existing real Owner
harness. It does not qualify the archived C6 hardware failure.

## Contracts and waiting audit

No capacity/profile default, terminal/dedup/replay retention, authentication,
boot/session/generation/context check, API/wire/storage format, transmission
attempt limit or operation lifetime changes. No production state or buffer
is added; the existing outbound filter byte now distinguishes unbound and
unconfirmed peers. M08 receiver quota/source admission remains a separate
design decision. STATUS and implementation-plan section 08 are unchanged.

| Wait source | Result of the audit/change |
| --- | --- |
| Due or elapsed timer, no staged event | `wait_for_event(0)` now reaches the atomic notification take, rounded up to one RTOS tick. It releases CPU even if an unresolved retry keeps publishing a due timer. |
| External USB/post/worker wake | No notification is cleared before the atomic take. A racing wake remains observable; already-drained notifications cost one extra pass. Existing worker completion/cancellation regressions still pass. |
| RX filter, unknown peer, overflow | Only successfully queued input notifies Owner. A discarded frame creates no runnable work. A full queue already contains retained work; the existing queue/staging inspection remains authoritative. |
| Full TX queue/completions | Existing lost-TX staging and queue inspection retain immediate service; the bounded drain is unchanged. |
| Authority carrier/ACK retry | Coordinator maps the client's zero retry marker to the existing 2 ms compatibility wait, while separately retaining handshake/confirmation/retirement deadlines. The same bytes remain staged on refusal. |
| RRS manifest/chunk refusal | The existing ACK timestamp also schedules unsent transfer retries, 2 ms after a refused attempt. Absolute fetch expiry and successful transmission attempt limits are unchanged. Incomplete ACKs still resume from their frontier on the next pass. |
| RRS gossip | The deadline is the maximum of peer notification time and the existing global control gap. A second peer or a refused send no longer leaves a stale runnable timestamp. Disabled gossip contributes no notification timer. |
| RRS/permit reacquisition | Existing Get/ACK cooldowns and asynchronous signature/crypto completion paths remain. Their idle waits now use the same blocking gate; no extra polling engine or timer is introduced. |
| Missing link demand/route re-exchange | Existing 2 ms demand fallback, route retry timers and full-scheduler deadline handling remain. The existing full-scheduler regression verifies future deadlines under sustained refusal. |

## Targeted commands and results

Only affected tests, fmt/clippy and one C3 firmware cell were used. CMake
builds used at most four jobs; Cargo builds used at most four jobs and test
threads at most two.

```sh
cmake -S . -B build-v2 -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug
cmake --build build-v2 -j4 --target routeloom_espnow_owner_reapply_tests routeloom_espnow_runtime_tests routeloom_hil_rx_filtered_tests routeloom_hil_rx_empty_tests routeloom_sdkv1_revocation_tests routeloom_sdkv1_authority_tests routeloom_sdkv1_coordinator_tests routeloom_session_tests routeloom_deadline_tests routeloom_owner_mesh_peer routeloom_joiner_interop_peer
ctest --test-dir build-v2 -j4 -R '^routeloom_(espnow_owner_reapply|espnow_runtime|hil_rx_filtered|hil_rx_empty|sdkv1_revocation|sdkv1_authority|sdkv1_coordinator|session|deadline)_tests$' --output-on-failure
cmake --build build-v2 -j2 --target routeloom_usb_tests routeloom_usb_boot_gate_tests routeloom_usb_state_gate_tests
ctest --test-dir build-v2 -j2 -R '^routeloom_usb(_boot_gate|_state_gate)?_tests$' --output-on-failure
```

The original filters ran in smaller dependency groups. After the focused
fixes, the final ASan filter below passed **17/17** CTests, including the
mandatory session test and USB pre-authentication/old-session gates:

```sh
cmake --build build-v2 -j4 --target routeloom_discovery_tests routeloom_scope_tests routeloom_sdkv1_handshake_tests routeloom_sdkv1_coordinator_tests
ctest --test-dir build-v2 -j4 -R '^routeloom_(discovery|scope|sdkv1_handshake|espnow_owner_reapply|espnow_runtime|hil_rx_filtered|hil_rx_empty|sdkv1_revocation|sdkv1_authority|sdkv1_coordinator|session|deadline|usb|usb_boot_gate|usb_state_gate|espnow_callback_order_trace0|espnow_callback_order_trace1)_tests$' --output-on-failure
ctest --test-dir build-v2-object -j2 -R '^routeloom_app_object(_endpoint)?_tests$' --output-on-failure
```

The two AppObject CTests also passed: **19/19 related CTests** in total.
No full suite was run.

## Focused recovery fixes and fail-before evidence

- A cold discovery round could accept a late scoped OFFER from a peer that
  became Reachable while MAC verification was queued, replacing the newly
  confirmed context. Cold recovery now filters Reachable peers both before
  and after verification; Bound peers may still retry. The queued-OFFER
  regression fails before and passes after, covering both states.
- A responder's initial Probe could precede the initiator's context install.
  An authenticated lower local binding-counter Probe now schedules a prompt
  retry of an outstanding Bound confirmation. It neither refreshes the lease
  nor permits DATA before the matching Result. Its regression fails one
  assertion before and passes after. Membership generation/boot checks are
  unchanged.
- Committed End M4 retained the shared crypto workspace until confirmation
  or timeout, blocking handshakes with other peers. It now releases that
  workspace while retaining the existing small M4 cache, exact M1/M3 hashes,
  context evidence and retry deadline. The existing lost-M4 regression gains
  one End-to-End row: twelve assertions fail before and pass after. It checks
  an unrelated peer's progress, rejection of altered M3, identical cached M4,
  and retirement only after authenticated RX in the exact installed context.
- End chunk replies previously matched the transfer ID without checking the
  origin peer. A different peer's matching-ID reply is now ignored. The
  existing chunk progression regression fails one assertion before and
  passes after; genuine replies still advance immediately.

Fail-before/pass-after uses the real Member Owner/coordinator/runtime and
an Authority port that refuses admission. Only the stub clock assigns a
100 us CPU charge to each pass; a blocking RTOS wait advances virtual time.
Thirty-two preexisting notifications are coalesced. The regression limits
passes/waits to `2 * configTICK_RATE_HZ + 1` per one-second window, and
continuous execution to 25 ms.

| Virtual Owner metric | Before | After |
| --- | ---: | ---: |
| Passes | 2000 (test cap reached) | 100 |
| Blocking waits | 0 | 99 |
| Notifications | 32 | 32 |
| Longest continuous modeled execution | 200000 us | 200 us |

These are simulated execution charges, not C6 CPU measurements. RRS
backpressure/gossip deadline assertions also failed before and pass after.
The RX regression previously produced wakes for 1000 discarded unknown-peer
frames; afterward it records zero wakes and 1000 blocking waits. Allowed RX
still wakes normally, including the finite allow-list variants.

Rust 1.85.0 workspace `cargo fmt --all -- --check` and
`cargo clippy --workspace --all-targets -- -D warnings`: PASS.
`python3 tools/check.py scenarios` and `git diff --check`: PASS.
`git clang-format --diff origin/main`: unavailable locally, NOT_RUN.

Live harness commands use both actual peers:

```sh
export ROUTELOOM_MESH_PEER="$PWD/build-v2/tests/cpp/routeloom_owner_mesh_peer"
export ROUTELOOM_OWNER_PEER="$PWD/build-v2/tests/cpp/routeloom_joiner_interop_peer"
CARGO_BUILD_JOBS=4 cargo +1.85.0 test --manifest-path host/Cargo.toml -p routeloom-host --bins mesh_uplink_five_hop_cold_line_delivers -- --nocapture --test-threads=2
CARGO_BUILD_JOBS=4 cargo +1.85.0 test --manifest-path host/Cargo.toml -p routeloom-host --bins mesh_m06_gateway_reset_cycles_deliver -- --nocapture --test-threads=2
cmake -S . -B build-v2-object -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug -DROUTELOOM_APP_OBJECT_TRANSFER=ON
cmake --build build-v2-object -j4 --target routeloom_owner_mesh_peer
export ROUTELOOM_MESH_PEER="$PWD/build-v2-object/tests/cpp/routeloom_owner_mesh_peer"
CARGO_BUILD_JOBS=4 cargo +1.85.0 test --manifest-path host/Cargo.toml -p routeloom-host --bins mesh_uplink_five_hop_cold_line_delivers -- --nocapture --test-threads=2
CARGO_BUILD_JOBS=4 cargo +1.85.0 test --manifest-path host/Cargo.toml -p routeloom-host --bins mesh_m10_three_hop_with_control -- --ignored --nocapture --test-threads=2
CARGO_BUILD_JOBS=2 cargo +1.85.0 test --manifest-path host/Cargo.toml -p routeloom-host --bins mesh_h7r3_thirty_three_hop_objects_with_1hz_control -- --ignored --nocapture --test-threads=2
CARGO_BUILD_JOBS=4 cargo +1.85.0 test --manifest-path host/Cargo.toml -p routeloom-host --bins site::owner_mesh::object::load::mesh_m10_ -- --ignored --nocapture --test-threads=2
cmake -S . -B build-v2-small -DROUTELOOM_ENABLE_SANITIZERS=ON -DCMAKE_BUILD_TYPE=Debug -DROUTELOOM_RESOURCE_PROFILE=gateway_small
cmake --build build-v2-small -j2 --target routeloom_owner_mesh_peer routeloom_joiner_interop_peer
export ROUTELOOM_MESH_PEER="$PWD/build-v2/tests/cpp/routeloom_owner_mesh_peer"
export ROUTELOOM_MESH_PEER_GW="$PWD/build-v2-small/tests/cpp/routeloom_owner_mesh_peer"
export ROUTELOOM_OWNER_PEER_GW="$PWD/build-v2-small/tests/cpp/routeloom_joiner_interop_peer"
CARGO_BUILD_JOBS=2 cargo +1.85.0 test --manifest-path host/Cargo.toml -p routeloom-host --bins site::owner_mesh::m08hw::mesh_m08hw_contention_ -- --include-ignored --nocapture --test-threads=2
```

No missing-peer skip was treated as success. AppObject tests marked ignored
for the required ON peer were explicitly executed with `--ignored`.

- Cold five-hop, AppObject OFF and ON/no-object: PASS, 100/100 each direction,
  no duplicate receive or terminal. Both reach all End/Authority readiness
  in **166300 ms virtual time**. This is a readiness observation, not a
  45-second hardware-window success or a claim of watchdog qualification.
- Existing three-hop AppObject/control smoke: PASS, one 4 KiB object.
- New `M10-HFIX-H7R3`: 30/30 immediate 2 KiB objects and 271/271 foreground
  controls; p99 230 to 190 ms. Control-only baseline is 20 samples, as in
  the H7R3 spec. Ten-ms frame/callback delays, five-ms Owner steps and
  154-ms crypto worker are modeled. There are no added hop/End timeouts,
  route flaps or duplicate object callbacks. This uses the full host
  resource profile; it does not certify product-profile/HIL performance.
- Existing load regressions: PASS, both explicitly executed. Immediate
  2 KiB/two hop delivers 100/100 objects and 722/722 controls, p99 115 to
  120 ms; 2 KiB/one hop gives 100/100 and 500/500, 50 to 55 ms; 4 KiB/one
  hop gives 100/100 and 852/852, 55 to 60 ms. The worker/blocked-route
  regression gives 100/100 objects and 721/721 healthy controls, 115 to
  120 ms. Each older row retains its same-count baseline and original
  >=99%/<=20% gates; its injected absent-route expiry is the only excluded
  End failure. The shared helper now also verifies the 1 Hz submission
  cadence. These two tests took 397.92 s wall time together.
- Gateway reset before the focused recovery fixes: **FAIL**, 99/100
  Delivered and first send 9/10 after H7R2 integration (96/100 before it).
  The failing cycle's first request expired; its first Delivered arrived
  at 7350 ms. The Owner wait fix alone did not resolve this failure.
- Gateway reset after the focused fixes: **PASS**, 100/100 Delivered and
  first send 10/10. The real Owner/UsbBridge test submits immediately after
  authenticated boot/session, without a warm-up probe or fixed extra wait.
  Each accepted request has exactly one terminal within its original 5 s
  lifetime plus one 25 ms observation poll. Admission and terminal events
  are checked separately; the daemon lane is retained.
- Final M08 contention boundaries: below-quota **PASS**, 20/20 unique
  receipts, two modeled collision losses and no terminal refusal. The
  explicitly executed small32 overload still **FAILS**, 28/40 accepted
  messages delivered, 47 terminal refusals and 12 collision losses; each
  source delivers 8/8, 8/8, 2/8, 2/8, 8/8. Every accepted request terminates
  exactly once and source queues are empty by 30 s. Gateway capacity remains
  32 dedup entries / 28 terminal pins. No capacity or retention was changed.

Final related Rust runs therefore pass five configurations (reset, cold OFF,
cold ON, three-hop 30-object/control, below-quota M08) and fail one known
M08 overload configuration. The older smoke/load results above are retained
as earlier evidence and were not repeated in the final pass.

## C3 footprint and remaining qualification

ESP-IDF v6.0.3, only `bridge_node-esp32c3-normal-off-off`, TRACE OFF and
worker ON. `python3 tools/check.py firmware --cell` built the same cell
before/after; the final RX change was rebuilt incrementally with `idf.py
build`, followed by JSON size, RAM guard and the same cell budget check.
Ninja used at most four jobs; the final focused-review rebuild used four.
After main integration, the same cell was rebuilt incrementally. A clean
archive of final main `83057228` was separately built with the same cell
command and two jobs, to keep its incoming code size out of this PR's delta.

| C3 metric | Final main baseline | Reviewed H7R3 | Difference |
| --- | ---: | ---: | ---: |
| app.bin | 1243984 B | 1244208 B | +224 B |
| static BSS | 211976 B | 211976 B | 0 B |
| static data | 13348 B | 13348 B | 0 B |
| static free | 46624 B | 46624 B | 0 B |
| RTC SLOW used | 6552 B | 6552 B | 0 B |

Before focused review, integrated H7R3 was 1244048 B; these additional fixes
add 160 B. The retained main archive was checked against tracked main source
files before using its measured binary as the baseline. DRAM used is
274672 B in both builds; all RAM figures above are unchanged.

IDF compile and the 27648 B hard static-RAM floor PASS both builds. The
complete firmware/size check **FAILS both builds** at the existing app budget
1239056 B plus its 2048 B drift allowance. Static/RTC checks pass within
existing allowances. No budget was loosened. No measured RAM/flash reduction
or hardware CPU/heap/power improvement is claimed.

Full CTest, full Rust live workspace tests, clang-wide checks, other firmware
cells, quick/selfcheck/nightly and on-board campaigns: NOT_RUN under the PM
scope. No serial port, flash or eFuse action was performed. Hardware C6
watchdog/TRACE qualification, product OFF/ON five-hop membership/BOUND and
45-second readiness observations remain for the combined main campaign and
H7R2 coordination. Gateway first-send recovery passes the software harness
but has not been rerun on hardware. Formal M08
receiver-quota/admission design and sustained five-minute >=99% acceptance
are unchanged and unresolved; no shortened retention or larger pool is used.
The three-hop host load adds coverage, not a claim that the archived product
AppObject/control failure is fixed.
