# 2. Real RF telemetry

Status: **documented / proposed**. All numeric resource/performance budgets below are estimates or proposed gates. Callback metadata is a radio observation; neither simulated samples nor this document is RF validation.

## 2.1 Current state and purpose

[EspNowRuntime](../../../components/routeloom_espnow/src/espnow_runtime.cpp) already copies `rx_ctrl->rssi` into an RX event, but a missing `rx_ctrl` becomes zero and `MeshNode::on_radio_receive()` currently ignores the metadata. TX callbacks are reduced to a boolean for the reserved node send or aggregate autonomy counters. Normal RX lacks a callback timestamp; TX event enqueue failure is not checked. These are concrete integration gaps, not a reason to replace the existing congestion core.

[ObservationBucket](../../../components/routeloom/include/routeloom/congestion.hpp) already separates queue delay, driver service, authenticated hop acceptance, BUSY, unknown outcomes and delivery outcomes. Eight detailed buckets currently exist. M1 supplies real provenance and preserves those distinctions. It must also make callback/event loss visible so missing samples cannot improve a route's apparent quality.

The pinned [ESP-NOW header](https://raw.githubusercontent.com/espressif/esp-idf/v6.0.3/components/esp_wifi/include/esp_now.h) supplies `esp_now_recv_info_t` and aliases send information to `wifi_tx_info_t`. The pinned [Wi-Fi type](https://raw.githubusercontent.com/espressif/esp-idf/v6.0.3/components/esp_wifi/include/esp_wifi_types_generic.h) contains rate and TX status, but **no hardware retry count**. RX metadata pointers are copied during the callback; they are never retained. ESP-NOW success is a MAC-layer indication, not application delivery, as described in [Espressif's ESP-NOW API guide](https://docs.espressif.com/projects/esp-idf/en/stable/esp32c3/api-reference/network/esp_now.html).

## 2.2 Measurement dictionary

| Field | Measurement and attribution | Limitations / unavailable representation |
|---|---|---|
| RX RSSI, dBm | Signed `rx_ctrl->rssi` for the immediate transmitter of a received frame | Receiver-specific, success-biased, no forward-path RSSI, no noise floor/SNR or path distance. Missing metadata is invalid, not 0 dBm |
| RX channel/rate | Copied documented chip-specific fields, with capability/validity bits | A configured rate is labelled configured; it is not an observed RX/TX rate. Do not assume identical bitfields across C3/S3/C5 |
| TX submissions | Successful `esp_now_send()` handoffs, tracked by Owner token/peer/generations | API rejection is a separate reason and not an over-air failure |
| TX callback success/fail | Status for an attributable attempt, timestamped in the callback | Driver-internal retry number and failure cause remain unknown |
| SDK retries | Explicit second/subsequent submissions by RouteLoom for one hop job | Measured software count; never named MAC retries or inferred from callback duration |
| Hop accepts/timeouts/BUSY | Correlated authenticated protocol events | HOP_ACCEPT includes receiver admission and return scheduling; BUSY is capacity pressure, not RF corruption |
| Driver service time | Local callback-entry time minus local driver-submission time | Includes driver queue/CCA/internal retry/callback scheduling; not pure airtime or RTT |
| Queue residence | Submission time minus local Owner admission time, with RX wait reported separately | Software scheduling/load, not RF propagation |
| Hop ACK RTT | RX callback time of matching HOP_ACCEPT minus submission time of its sole unambiguous attempt | Available only when no retransmission/ambiguity occurred; otherwise Karn-style exclusion |
| End-to-end receipt elapsed | Local authenticated terminal receipt arrival minus origin's first send time | Includes all hops, queueing and endpoint work. Config challenge/status latency also includes target processing. Never used as per-link RTT |
| Unknown/stale/lost | Callback watchdog, generation fence, event overflow, unmatched completion and snapshot loss counters | Remain separate from success/fail; missing is `null` with reason, not zero or inferred success |
| Airtime estimate / ETX-like ratio | Configured rate and encoded length; SDK attempt work divided by authenticated accepts | Modelled quantities. No channel occupancy/CCA-busy percentage or PHY retry estimate is claimed |

For radio measurements, identify the *observing node and peer*, not the end-to-end origin in the frame. A relay receiving a permit from R measures R's signal, not the issuer's. Link authentication makes the peer attribution eligible for control use; it does not turn an RSSI value or an authenticated peer's self-report into an independently verified RF fact.

## 2.3 Callback and ownership changes

Extend RX metadata with monotonic `received_us:u64`, RSSI validity, observed channel validity, source binding generation and captured radio generation/channel epoch. Snapshot the source MAC/node/binding tuple under the existing lock. Validate the generation again when the Owner processes the event. Events from an old channel/binding can contribute to loss diagnostics, never current-channel connectivity or route improvement.

Extend TX bookkeeping with submission time, encoded length class, SDK attempt ordinal, job type, binding/radio/channel generations and the expected MAC. The callback copies timestamp, status and rate validity into a fixed completion mailbox. Preserve the one reserved node completion plus at most four raw-send records; raw and node sends to the same MAC cannot overlap. A watchdog fences the old send before any replacement can be attributed. If attribution is ambiguous, record unknown; do not match a late completion to the next job by MAC alone.

Because the callback carries no RouteLoom submission token, expiration of a guessed guard timer alone is not a safe fence. Quarantine that MAC until the old callback is consumed or driver recovery establishes a tested callback-quiescence barrier. If the pinned driver cannot establish such a barrier, keep the peer unavailable and expose recovery-required. A locally assigned radio generation does not manufacture a generation field in an old callback. This rule covers raw sends as well as the reserved node slot.

Use a reserved completion mailbox for the node send and four raw completions, separate from the ordinary RX queue; coalesced overflow flags/counters survive even when a mailbox is full. Queueing failures are checked. The Owner resolves each submitted token exactly once, including watchdog/unknown, and increments overflow/stale/unmatched counters. A duplicate callback cannot resolve a job twice. Pending callback timestamps must be consumed before evaluating a timeout at the same Owner poll, avoiding false timeouts caused by RX backlog.

Callbacks do no crypto or aggregation and never block on a full queue. Copy at most 250 frame bytes plus fixed metadata; avoid retaining `info`, `data` or `rx_ctrl` pointers. Aggregation and peer eviction happen only in the Owner. Invalid/unbound RF frames count toward raw activity/abuse and sleep invalidation, but do not update authenticated peer link quality.

Proposed API additions are `RadioRxMetadataV2`, `RadioTxObservation`, a read-only `TelemetrySnapshot` copier and `ObservationProvenance` values `InjectedTest`, `LocalDriver`, `AuthenticatedRemoteReport`. The portable engine remains FreeRTOS-free. The production adapter does not expose a switch that relabels injected observations as LocalDriver.

## 2.4 Fixed aggregation and freshness

Keep **19 per-peer summaries** (the adapter's actual non-broadcast peer capacity), with current binding/radio/channel identity, RSSI last/min/max, signed Q8.8 EWMA, valid sample count and freshness. Use integer alpha=1/8 with explicit signed arithmetic. Saturating counters include a saturation flag. Exclude broadcast/discovery RSSI from authenticated link-quality summaries; optional raw discovery totals have no per-source table.

Retain **eight detailed observation buckets**, keyed by `(peer, binding generation, direction, radio generation, channel epoch, frame length class)`. Length classes remain ≤96, 97..180, 181..250 encoded bytes. Pin buckets for active critical/awaiting-hop work, release stale buckets after their 3-second validity expires, and admit new buckets only into free/unpinned slots. Full means `observation_overflow` and unavailable detailed statistics for that link; no eviction of a control input still in use. Nineteen peers do not imply 19 × 6 detailed buckets or complete network coverage.

Per bucket, finalize a 2-second window and retain bounded current/previous summaries; control feedback expires after 3 seconds. Maintain lifetime totals separately for diagnostics so a window reset is not a counter rollback. Boot, binding generation, channel epoch or radio generation change resets EWMA/window eligibility and marks prior data stale. Eight-record control-observation capacity is a deliberate bound; if critical links exceed it, metric coupling/AutoGuarded reports insufficient coverage.

Unknown TX completion is never placed in the success/failure denominator. A window with completion loss, unresolved attempts or unknown attribution cannot improve a metric. A timestamp gap does not fabricate empty successful windows. Host reboot and device reboot are separately identified, and samples from separate boots cannot be subtracted as one counter stream.

Detailed snapshot format in [§4.2](04-cross-cutting.md) carries lifetime counter values plus current-window EWMAs/sample time/validity. RSSI fields describe the peer summary across received frame sizes, while TX/RTT fields describe the selected detailed bucket. `window_ms` is the detailed aggregation interval, not the duration represented by lifetime counters. Host deltas require the same observer boot, peer/binding and bucket identity. A per-peer record can be returned with detailed-valid clear if no bucket exists.

Snapshot v1 carries channel and configured-profile identity through the existing adapter view, but has no per-attempt rate field. Optional observed rate is retained only in bounded local attempt/debug evidence for backend validation; no unused snapshot byte is repurposed. A future structured rate field needs a versioned record.

## 2.5 Congestion and route metric input

Admission and queue watermarks continue working even when radio telemetry is absent. Supply real queue residence, SDK attempt/accept counts and authenticated BUSY to the existing [cost functions](../../../components/routeloom/include/routeloom/congestion.hpp). Driver service duration, RSSI and hardware-retry guesses do **not** enter the ETX-like term. Preserve the current nominal × attempts/accepts model, at least four authenticated accepts, positive/saturating metrics, queue penalty and existing 10-second improvement/5-second switch holds. Observation updates never renew route leases or erase feasible-distance tombstones.

RF loss, receiver BUSY, scheduled absence and local CPU/queue pressure remain separate. Do not count the same submission twice as both callback failure and hop timeout when computing attempt work; raw counters may record both events but the attempt has one outcome classification. A link's DATA/config/forwarded work all consume its real scheduler/driver budget. Frame length classes prevent a short ACK success rate from pretending that maximum permit chunks have the same evidence.

If samples are too few, expired, injected, from the wrong generation or incomplete, retain nominal link cost and expose the cause. A real failure can still withdraw a route through existing failure handling. Missing telemetry neither restores an infeasible route nor hides a known failure. Feedback roll-out starts in observe-only mode; metric coupling is separately opt-in after host and bench comparison against nominal routing. Hop RTT is diagnostic-only in M1: retain the existing configured hop timeout and callback watchdog. Adaptive RTO needs its own bounds/review; it is not silently introduced by collecting RTT.

## 2.6 AutoGuarded: evidence that this work can and cannot supply

Map eligible windows into `HealthEvidence` only after completing two 30-second windows. Proposed classifier: at least 20 resolved, non-BUSY/non-absence hop exchanges per window and more than 20% without authenticated acceptance indicate link impairment. Local RX/CPU saturation is reported separately and cannot by itself justify a channel move. RSSI below a deployment-chosen threshold is descriptive only. These classifier thresholds are M1 screening choices for review/measurement, not universal RF constants.

Distinct MACs, two directions, two relays repeating one report, and multiple buckets of one observer do not count as independent observers. Preserve original observer NodeId/boot in authenticated reports, and require freshness with a bounded clock mapping for remote windows. Without mapping/uncertainty, a remote snapshot is host diagnostics only. A snapshot query's local deadline bounds transport time but does not establish remote clock synchronization.

| Existing precondition | Evidence source / M1 limit |
|---|---|
| Two consecutive bad windows and ≥2 independent observers, or protected critical-link impairment | Real local observations; authenticated remote summaries only when provenance/window mapping exists. A critical-link exception still requires an explicitly configured protected link |
| Candidate channel measurements and 19/20 screening exchanges per direction | Only actual bounded survey visits, four exchanges/direction/visit, ≤200 ms visit and ≥30 s gap. Home-channel RSSI cannot fill candidate-channel evidence |
| Authority path, required participants and cut safety | Actual route/connectivity/participant evidence including relays; single-hop migration controls do not automatically cover a multi-hop fleet |
| Authority availability, correct verifier and durable plan | Existing migration authority/verifier path, not the ConfigPermit ESP256 verifier just because it uses the same curve |
| Clock uncertainty, maintenance, cooldown, recovery and approved RF profile | Existing gate checks remain mandatory and visible; telemetry cannot synthesize them |

M1 requires real observation input and honest blocked-condition reporting. It does **not** require automatically enabling channel changes. If authenticated remote evidence or multi-hop migration coordination is not available, leave AutoGuarded blocked/Observe. A host-injected scenario may test the gate but cannot set a hardware-tested automatic migration claim. Forwarding itself does not change the one-hop channel-management wire contract.

## 2.7 Wire, host diagnostics and backpressure

DATA/Service/Control/object payload delta: **0 bytes**. Wire header/tag delta: **0 bytes**. Use the separate fixed 128-byte diagnostic snapshot and 24-byte query in [§4.2](04-cross-cutting.md). Local USB snapshots use new negotiated HostOps subtypes; remote queries use end-protected type 48 to the explicitly addressed observer. End-to-end context unavailable means `AUTH_PROFILE_UNAVAILABLE`, not unprotected telemetry. Remote telemetry is opt-in and can be disabled independently of local collection.

Poll at most one snapshot per second per device, one outstanding query and ≤5-second query lifetime; on RF additionally one request per peer per 5 seconds, global burst 1. A remote snapshot costs its own route transmissions, and is shed before accepted user work. Do not piggyback remote telemetry on a signature-bearing permit or mutate application payloads. Legacy USB Diagnostic=33 text reason events retain their encoding; old daemon/firmware combinations never receive binary data disguised as a reason string.

Daemon changes: `telemetry.get`/`routeloomctl telemetry` read negotiated structured snapshots, export observer/boot/peer, sample age, security/provenance/validity and measured-vs-estimated labels, and preserve `null` for unavailable values. Add real retry *software* counts, MAC status, hop RTT and receipt elapsed to operation diagnostics. Existing reason events and DIAGNOSTICS remain usable when structured telemetry is unsupported. The host keeps at most 19 peer summaries per attached observer and a bounded event ring; it reports sequence gaps and expiry instead of interpolating good RF health.

## 2.8 Error paths and resource budget

| Condition | Required behavior |
|---|---|
| No RX control metadata | RSSI/channel validity clear; missing counter increments |
| Unknown peer or failed link authentication | Raw activity totals only; never authenticated RSSI for a claimed origin |
| RX queue overflow | Drop frame before admission, count it; remote sender retries/times out, no fabricated receive |
| TX mailbox overflow, missing or ambiguous callback | Resolve accounting as unknown; block metric improvement for incomplete window |
| Radio switch/rebinding/reboot | Fence old completions; invalidate old windows and retain explicit stale counts |
| Bucket pool full | Summary still available, detailed fields invalid with capacity reason; no fake zero measurements |
| Host credit exhausted/query lost | Keep collection bounded, drop/coalesce snapshot notification and count loss; caller gets timeout |
| Counter saturation | Clamp at maximum and set saturation flag; host stops computing deltas until reset/epoch change |

| Increment over baseline | Planning allowance |
|---|---:|
| Peer summaries | 19 × ≤96 B = 1,824 B |
| RX/bootstrap metadata enlargement | 56 events × ≤24 B = 1,344 B |
| Eight bucket extensions and fixed completion mailboxes | ≤2 KiB; existing bucket storage is baseline |
| Snapshot, query, loss counters and alignment | ≤928 B; total incremental ceiling 6 KiB |
| Owner stack / flash | ≤512 B additional peak / 8–16 KiB |

No raw-sample history and no per-message telemetry allocation. Measure callback added service with a ≤100 µs target excluding the existing frame copy/queue cost; callbacks may not run aggregation to meet this budget. Measure all task stack watermarks and memory under simultaneous forwarding and verification, not only idle polling. If eight expanded buckets exceed the extension allowance, revise the estimate explicitly before implementation acceptance.

## 2.9 Tests and maturity

Host tests: null `rx_ctrl`, signed negative RSSI EWMA/min/max, counter saturation, 2/3-second boundaries, boot/rebind/channel changes, callback success-before-timeout ordering, queue overflow, loss accounting conservation, out-of-order/raw/reserved completion correlation, Karn exclusion, timestamp wrap/uncertainty, missing buckets and old/new snapshot decoding. Injected tests assert `InjectedTest` provenance. Property: every accepted driver submission is pending or exactly one of known success/known failure/unknown; no callback disappearance creates a success. Verify an impaired-link window cannot improve a metric because the failure sample was dropped.

| Six-board case | Required evidence |
|---|---|
| T1 — direct C3/S3 pairs, swap roles | Compare copied RX/TX samples with callback trace; missing metadata remains invalid; report actual rate metadata availability per chip |
| T2 — three-link path with S3-D load | Per-peer RSSI attributed to immediate relays; queue pressure, BUSY and MAC loss separate; host receipt elapsed is not per-hop RTT |
| T3 — shield/attenuate one allowed link | Track sample coverage, acceptance ratio and RSSI trend without asserting a calibrated range/SNR; nominal/observed routing comparison retains hysteresis |
| T4 — force queue/credit pressure and callback watchdog | Every lost/unknown sample accounted; host sees gaps; no optimistic AutoGuarded or metric evidence |
| T5 — C3 target verifies maximum permits while relaying | CPU-induced delay visible as queue/driver/endpoint components; no signature duration mislabelled radio RTT |
| T6 — observe/survey and stale generation tests | Only executed, approved visits create candidate-channel evidence; insufficient observers/clock/authority yields explicit blocked conditions |

Run the common six-board fixture and archive at least 100 resolved exchanges per tested directed link/length class where RF conditions permit. Report shortfall rather than synthesizing samples. A 19/20 survey screen is not a delivery reliability qualification. Allowed maturity is **real callback telemetry hardware-tested on the named C3/S3 builds**; it does not establish spectrum occupancy, true PHY retry counts, AutoGuarded qualification, C5 behavior or RF reliability guarantees.
