# 2. Dedup capacity and the continuous-send steady state (Issue #9)

Status: **documented / proposed**. Baseline: `main` @ `d73cd81`. This document
designs the on-device (SDK) half of issue #9 — "continuous sending capacity
while preserving dedup". The host-side capacity model (operation journal,
dispatch window, epoch retirement) is already specified in
[host-security-readiness/04-capacity-storage.md](../host-security-readiness/04-capacity-storage.md)
and implemented in `host/routeloom-host/src/send_store.rs` / `dispatch.rs`; this
document references it only where the host/device bounds interact. Normative
retention inputs come from [spec/crash-time-resources.md](../../spec/crash-time-resources.md)
§4 and [m1-completion/01-forwarding.md](../m1-completion/01-forwarding.md) §1.3.
Nothing here is implemented; all constants are **proposals** for the
implementation change, not registrations.

## 2.1 Problem statement and the invariant being preserved

Today every accepted inbound send allocates one `DedupEntry` in the shared
64-slot `dedup_` pool ([node.cpp](../../../components/routeloom/src/node.cpp)
`allocate_dedup`, `handle_data`, `handle_routed`, `handle_end_receipt`) with a
**flat 60-second expiry**, plus the origin-side tracking record
(`deliveries_`, 8 slots) held until terminal evidence arrives. Under a
continuous stream the pool fills inside one retention window; the code then
has only two moves: refuse admission (pre-acceptance BUSY — availability
loss) or wait for expiry (head-of-line stall). There is no eviction path at
all in `dedup_` today — `expire_dedup` is the only release — so a sustained
ingress rate above `64 / 60 s ≈ 1.07 msg/s` aggregate wedges the table.

The invariant to preserve (M1 §1.3, crash-time §4):

> Exactly-once application delivery for in-flight messages: a re-received
> frame must never produce a second `on_message` / second terminal handoff,
> and a retained failure must never be re-ACKed as live work.

The dedup window must therefore cover the **maximum retransmit horizon** —
the latest time at which a legitimate duplicate of the same
`(origin, session, sequence, type, round)` can arrive. §2.2 derives that
horizon; §2.3 splits the pool's three resident roles into capacity classes;
§2.5 gives the phase-ordered eviction that makes eviction of *resolved*
records safe while keeping *live* and *terminal* records unevictable.

Non-goals: changing the Wire v1 layout, the HOP_ACCEPT/BUSY/TransitFailure
contracts, the gateway component's own dedup table
(`kGatewayReceiptRecords = 32`, `first_seen + 60 s`, never extended —
[gateway.hpp](../../../components/routeloom/include/routeloom/gateway.hpp)),
the host store, or the scheduler pools.

## 2.2 The retransmit horizon

Duplicates are produced only by bounded retry machinery, all of which is
bounded by the frame's own deadline. Constants in play:

| Bound | Value | Source |
|---|---:|---|
| `max_link_attempts` (RF retries per hop exchange) | ≤ `kRfAttemptsMax` = 2 | congestion.hpp |
| `hop_accept_timeout_ms` (per-attempt hop wait) | 60 ms default | NodeConfig |
| `callback_watchdog_ms` (fences a missing TX callback) | 1000 ms | NodeConfig |
| `kBusyReadmissionsMax` / per-deferral wait | 4 / ≤1000 ms | congestion.hpp |
| `kCombinedPhysicalAttemptsMax` | 6 submissions/job | congestion.hpp |
| `max_end_to_end_rounds` | 3 | NodeConfig |
| `max_message_lifetime_ms` (profile) | 30 000 ms | resource-profiles.json |
| TransitFailure report budget | 3 s (01 §1.4) | m1 set |

Per-hop exchange worst case: `6 × (1000 + 60) + 4 × 1000 ≈ 10.4 s`, but every
job's `deadline_ms` is set from the frame's `remaining_deadline_ms` minus the
driver-queue debit (`queue_forward`, node.cpp:801), so **no sender emits a
retry past the frame deadline**. A duplicate of a given round can therefore
arrive at a node no later than `horizon + ε` where
`horizon = now + (remaining_deadline − rx_age)` at that node — the
"× hop timeouts × max hops" product lives inside the deadline arithmetic:
each relay's record only has to cover *its own* upstream's retransmissions,
not the whole path, because every hop's deadline is the same absolute origin
expiry. The path-length factor is spent by the remaining-deadline debit, not
by multiplied retention.

Three horizons matter, by record role:

| Role | Duty ends at | Slack rationale |
|---|---|---|
| Transit record (forwarded DATA/routed/receipt) | upstream's last retry of this round (≤ horizon), plus propagation window for a downstream TransitFailure (≤ horizon + 3 s report budget) | `kTransitSlackMs = 5000` covers the 3 s report budget + drain/jitter margin |
| Terminal DATA record (`delivered`, `destination == self`) | the origin's last *round* (≤ origin expiry) — the round-agnostic lookup at node.cpp:1694 is the cross-round exactly-once pin | `kTerminalSlackMs = 30000` — the spec'd late-result TTL (crash-time §4), kept verbatim |
| Retained failure evidence | upstream retries of the dead round (≤ horizon + small drain) | `kTransitSlackMs`, plus the existing replay caps |

Retention rule (per record, set at admission, refreshed only on legitimate
terminal re-receipt — §2.6):

```
expires_at_ms = min(first_seen_ms + kDedupHardCapMs,
                    horizon_ms + slack(phase))
kDedupHardCapMs = 60000     // absolute cap from first admission (M1 §1.3)
```

This implements the M1 formula ("original local expiry plus late-evidence
interval, capped at 60 s from first admission") that the current code
approximates as a flat `now + 60000`. For a 5 s-lifetime stream the transit
record lives ~10 s instead of 60 s — that is the primary capacity lever for
continuous sending. **Deviation flag:** applying the 5 s transit slack rather
than M1's blanket 30 s to transit records is a deliberate refinement —
transit duties after the deadline are the 3 s report budget plus sub-second
stragglers, and terminal records keep the full 30 s. If review prefers the
spec-literal uniform 30 s slack, the design is unchanged and the relay
capacity numbers in §2.7 shrink by the documented factor; only
`kTransitSlackMs` differs.

## 2.3 Capacity classes

| Class | Contents | Bound | Eviction rule |
|---|---|---|---|
| **(a) Origin tracking** | `deliveries_`: `FixedPool<Delivery,8>` (224 B each) — one per `send()`/`resume_delivery()`; typed-lane sends (`send_service`/`send_typed`) are tracked by their owning components instead (GatewayDelivery `sends_`=8/`pending_`=8, host `ConfigOps`=128) and are out of this pool | 8 live+terminal records; in-flight concurrency, not rate | Oldest **terminal-state** record evicted on admission pressure (existing behavior at node.cpp:663–688); a live (non-terminal) record is never evicted — `send()` returns `NoCapacity`. Consequence of terminal eviction: the result becomes unqueryable (`delivery()` → NOT_FOUND); dedup is unaffected because origin records are not dedup state. Add a counter — today this eviction is silent |
| **(b) Relay dedup** | `dedup_`: `FixedPool<DedupEntry,64>` — phases Live (job in flight), Resolved (forward completed or routed/receipt consumed — residual duty: re-ACK + propagate late report), Terminal (delivered DATA at this node — the cross-round pin) | 64 shared; `kDedupTransitReserve = 8` slots reserved for non-terminal admissions; `kDedupPerUpstreamMax = 24` transit records per previous-hop | Phase-ordered victim selection on allocation failure (§2.5): expired → Resolved (earliest expiry first) → Evidence (oldest first, bounded by `kEvidenceCap = 16`) → refuse. **Live and Terminal are never evicted** |
| **(c) Retained failure evidence** | Evidence-phase `dedup_` records (`failure_reported` + `reported_*` fields — verbatim replay material for `replay_retained_failure`) plus the inbound seen-table `transit_failure_seen_` (8 × 40 B) | ≤ 16 Evidence-phase records inside `dedup_`; 8 seen records | Evidence records evictable only after all Resolved records are gone; oldest first. Seen-table keeps its existing rule (reuse expired slot, else drop+count) but its expiry changes to the referenced record's expiry rather than flat 60 s |

Adjacent bounded state that interacts but is not dedup: `awaiting_hop_`
(8 × 904 B) bounds live hop exchanges; `scheduler_` (32 × 888 B, 8-slot
control lane) bounds queued work; `diag_budget_` paces failure-report
emission (2/s/peer). These are unchanged; §2.7 counts them in RAM.

## 2.4 Data-model changes

`DedupEntry` (node.hpp:594) gains:

| Field | Type | Purpose |
|---|---|---|
| `phase` | `DedupPhase` u8: `Live`, `Resolved`, `Evidence`, `Terminal` | drives retention slack + eviction rank; set at admission, transitioned at job resolution (§2.6) |
| `first_seen_ms` | `MonotonicMs` | base of the 60 s hard cap; mirrors `GatewayDelivery::DedupRecord::first_seen_ms` precedent |

Entry size: 144 B → **160 B** measured (host `sizeof`; Xtensa may differ by
alignment only — all fields are u8/u64/arrays). Pool total: `64×160 + 64`
(used-bits) = 10,304 B ≈ **10.1 KiB** vs 9.28 KiB today (+~0.8 KiB).
Eviction ordering
uses existing `expires_at_ms` (earliest first within a class) — no
`resolved_at` field is needed.

New constants (node.hpp):

```cpp
kDedupHardCapMs        = 60000   // first_seen cap (spec floor)
kTerminalSlackMs       = 30000   // cross-round exactly-once pin slack
kTransitSlackMs        = 5000    // downstream report budget + drain margin
kDedupTransitReserve   = 8       // last slots unreachable by terminal admissions
kDedupPerUpstreamMax   = 24      // transit records per previous-hop peer
kEvidenceCap           = 16      // Evidence-phase residency bound
```

New surface: `DedupStats` (u64 saturating counters in the `CongestionStats`
idiom — a counter that would exceed `UINT64_MAX` pins; unreachable within a
boot) returned by `dedup_stats()`:

```cpp
struct DedupStats {
  std::uint64_t admitted_terminal, admitted_transit;
  std::uint64_t refused_pool_full;        // sweep found no evictable record
  std::uint64_t refused_terminal_reserve; // terminal denied a reserved slot
  std::uint64_t refused_upstream_cap;     // per-upstream bound hit
  std::uint64_t evicted_resolved;         // Resolved records force-reclaimed
  std::uint64_t evicted_evidence;         // Evidence records force-reclaimed
  std::uint64_t expired;                  // normal expire_dedup releases
  std::uint64_t delivery_terminal_evicted;// class (a) result-history loss
};
```

## 2.5 Eviction policy (allocation-time sweep)

`allocate_dedup` becomes phase-aware. The sweep runs only when the pool has
no free slot; each scan is a bounded O(64) `for_each`. Pseudocode:

```cpp
DedupEntry* allocate_dedup(key, type, round, role, upstream, frame_deadline, now):
    if (auto* e = find_dedup(key, type, round)) return e;          // dup: refresh-free

    // Class admission gates (before touching the pool)
    if (role == Terminal && dedup_.size() >= kDedupCapacity - kDedupTransitReserve)
        { ++stats.refused_terminal_reserve; diag("DEDUP_TERMINAL_RESERVE"); return nullptr; }
    if (role == Transit && count_transit_upstream(upstream) >= kDedupPerUpstreamMax)
        { ++stats.refused_upstream_cap; diag("DEDUP_UPSTREAM_CAP"); return nullptr; }

    DedupEntry* slot = dedup_.allocate();
    if (slot == nullptr) {
        slot = evict_first_expired(now);                 // opportunistic reclaim
        if (slot == nullptr) slot = evict_oldest_in_phase(Resolved);
        if (slot == nullptr) slot = evict_oldest_in_phase(Evidence);
        if (slot == nullptr) {
            ++stats.refused_pool_full;                   // saturating counter
            diag("DEDUP_OVERFLOW");                      // observer diagnostic
            return nullptr;                              // caller: BUSY/drop path
        }
        ++(victim.phase == Resolved ? stats.evicted_resolved
                                   : stats.evicted_evidence);
        diag(victim.phase == Resolved ? "DEDUP_EVICTED_RESOLVED"
                                      : "DEDUP_EVICTED_EVIDENCE");
    }
    // init: phase by role (Terminal | Live), first_seen = now,
    //       expires_at = min(first_seen + 60s, frame_deadline + slack(role))
```

Rules:

- **Live** records hold a still-committed forward job; evicting one would
  orphan accepted work and fabricate a phantom admission. Never a victim.
- **Terminal** records are the exactly-once pin for application delivery.
  Never a victim; pressure becomes refusal (BUSY), not dedup weakening.
- **Resolved** eviction consequence (honest, bounded): a late same-round
  duplicate is re-admitted as new and re-forwarded once; the *next* node's
  dedup still suppresses it, and the terminal pin still suppresses a second
  `on_message`. Worst case is one extra link transmission per eviction —
  counted, never silent.
- **Evidence** eviction consequence: the verbatim-replay path is lost; a late
  duplicate of the dead round is re-forwarded (may now succeed on a repaired
  route — failure evidence was advisory per 01 §1.4) or fails again
  downstream, generating a *new* report cycle against the new record.
  Bounded; counted.
- The upstream scope cap mirrors the scheduler's `kMaxJobsPerScope = 12`
  idiom: dedup records outlive jobs (~seconds vs ~tens of ms), so the dedup
  bound is set at 2× the job bound to stop one flooding upstream from
  monopolizing retained state.

## 2.6 Lifecycle interaction (HOP_ACCEPT / END_RECEIPT)

Phase transitions and refresh rules, wired at the existing call sites:

| Event | Site (node.cpp) | Dedup effect |
|---|---|---|
| Transit admission (DATA/routed/EndReceipt forward) | `handle_data`:1830, `handle_routed`:1994, `handle_end_receipt`:2209 | allocate `Live`; `horizon` from `remaining_deadline − rx_age` |
| Terminal DATA delivery | `handle_data`:1765 | allocate `Terminal`; expiry `min(first_seen+60s, horizon+30s)` |
| Terminal routed-type delivery | `handle_routed`:1929 | allocate **Resolved** at birth — the component's own dedup (gateway 32×60 s / config endpoint) is the second layer; node record's residual duty is re-ACK only |
| Terminal EndReceipt consumed at origin | `handle_end_receipt`:2246 | allocate **Resolved**; the delivery record turns `Delivered`; residual duty is re-ACK of retried receipts |
| Forward job completes (hop-accepted) | `complete_job` — new hook for `owner == Transit`: `find_dedup(ack)` → `Live → Resolved` | residual duties: re-ACK upstream dups, propagate a late downstream report |
| Forward job fails post-accept | `report_transit_failure` (existing entry lookup) | `→ Evidence`; `failure_reported`/`reported_*` already retained verbatim |
| Terminal re-receipt (new round, same key) | `handle_data`:1694 round-agnostic find → must match `phase == Terminal` | `expires_at = max(current, min(first_seen+60s, now+remaining+30s))`; re-ACK + re-emit END_RECEIPT; **no new entry per round** — terminal footprint stays 1 per logical message; the refresh can never pass the 60 s cap (fixes today's unbounded `now+60000` extension vs crash-time §4 "duplicates do not extend retention") |
| `expire_dedup` | unchanged | frees at `expires_at`; ++`stats.expired` |

Why the phase split is safe for routed types: DATA at a terminal has **no
second dedup layer** — `on_message` fires the application directly — so its
record is pinned. Routed types hand off to a component that dedups on
MessageKey itself; a node-level record evicted early costs at most a
suppressed component-level re-delivery. For a bridge node there is a further
backstop: the host `receive_log.rs` folds same-MessageKey duplicates inside
its own 60 s window — an honest "duplicate observed" record, never a second
application delivery.

Dedup records are still committed *before* the HOP_ACCEPT reply is queued
(the atomic admission unit per radio.md §13); a failed ACK reservation leaves
the committed record so the upstream retry dedups instead of
double-forwarding — unchanged semantics.

## 2.7 Capacity arithmetic — sizes and a worked ESP32-C3 example

Measured `sizeof` (host toolchain, this tree):

| Object | Bytes | Pool | Bytes total |
|---|---:|---:|---:|
| `DedupEntry` now → proposed | 144 → 160 | 64 | 9,280 → **10,304** |
| `Delivery` | 224 | 8 | 1,800 |
| `TxJob` | 888 | 32 | 28,448 |
| `AwaitingHop` | 904 | 8 | 7,240 |
| `TransitFailureSeen` | 40 | 8 | 320 |
| `DiagBudget` / `PendingCapQuery` | 40 | 8 + 8 | 640 |
| `RouteTable` | — | — | 30,376 |
| `MeshNode` whole object | — | — | **93,616** (~91.4 KiB BSS) |

**RAM budget assumed:** the `relay-c3` profile ceiling of 131,072 B
SDK-side ([resource-profiles.json](../../reference/resource-profiles.json)),
with the standing C3 gate of ≥32 KiB free internal heap / ≥16 KiB largest
block under combined peak load (resource-profiles.md). Note the profile's
`dedup_and_compact_receipt_records` line (6,144 B for 96 entries) is stale
against the actual 144 B entry — reconcile the JSON line, don't shrink the
record. The proposed pool stays inside the M1 ≤12 KiB forwarding increment
that already carried "expanded dedup/outcome state".

**Steady-state formulas** (`r` = aggregate new-message rate per class,
`L` = message lifetime in seconds; receipts add a second transit record per
reliable message per relay):

- relay occupancy ≈ `2·r·min(L + 5 s, 60 s)` (DATA transit + EndReceipt transit)
- terminal occupancy ≈ `r·min(L + 30 s, 60 s)` against `64 − 8 = 56` pinnable
- origin: `deliveries_` recycles on terminal state — throughput bound is
  8 concurrent ops; failure residency ≈ L (then evictable-terminal), success
  residency ≈ RTT

**Worked example** — six-node bench shape (C3-A origin → S3 relays → C3-B
terminal), Reliable DATA, 128 B payload, L = 5 s:

| Role | Occupancy @ 1 msg/s | Saturation rate (sustained) |
|---|---:|---:|
| Relay (per node) | `2·1·10` = 20 entries | ~3.2 msg/s aggregate transit |
| Terminal | `1·35` = 35 pins | ~1.6 msg/s (56-pin cap) |
| Same, flat-60 today | 60 / 60 entries | ~0.53 msg/s relay, ~1.07 msg/s terminal |

At L = 30 s (profile maximum): relay ≈ 0.91 msg/s, terminal ≈ 0.93 msg/s —
the spec's own design point. **Conclusion for the issue:** continuous sending
is supported up to the class bound; above it, the boundary is explicit BUSY
backpressure with saturating counters — never silent dedup weakening. A
multi-origin aggregate flood is further split by `kDedupPerUpstreamMax` and
the existing scheduler scope/origin caps.

## 2.8 What "dedup overflow" emits

A true overflow (sweep found only Live/Terminal records) produces, per event:

1. `++stats.refused_pool_full` (saturating u64; surfaced via `dedup_stats()`);
2. `observer_.on_diagnostic("DEDUP_OVERFLOW", peer, &message_id)` — unifying
   today's `ADMISSION_NO_DEDUP_SLOT`/`ROUTED_NO_DEDUP_SLOT` diagnostics at the
   four emitting sites and adding emission at the two EndReceipt sites
   (node.cpp:2211, :2248) that are silently lossy today;
3. `emit_busy_or_drop(peer, header, QueueFull)` toward a busy-capable peer
   when a reply slot is affordable (existing path; a BUSY that cannot be
   queued is counted as `busy_send_failed`, never fabricated);
4. for terminal-bound traffic the pre-refusal `DEDUP_TERMINAL_RESERVE` /
   transit-side `DEDUP_UPSTREAM_CAP` diagnostics distinguish *which* bound
   fired.

Every forced eviction emits `DEDUP_EVICTED_RESOLVED` / `DEDUP_EVICTED_EVIDENCE`
with its counter — the "duplicate-risk note" consequence is therefore always
recorded at the node, and surfaced to the host via the existing diagnostic
observer path. Class (a) terminal-record eviction gets
`delivery_terminal_evicted` + a `DELIVERY_HISTORY_EVICTED` diagnostic.

## 2.9 Rolling-window alternative — considered and rejected

**Proposal analyzed:** a monotonically advancing per-(origin, session)
sequence floor (optionally + sliding bitmap), replacing per-record dedup.
It fails on out-of-order multi-hop, for reasons that cannot be patched
without recreating per-record state:

1. **Floors conflate "new" with "greater".** Route repair means origin O's
   seq 7 can arrive via the new path while seq 5 is still retrying on the
   old one. Floor at 7 → seq 5 dropped as "old" — but it was never
   delivered. The floor turns dedup into *at-most-once by ordering*, losing
   messages outright — worse than BUSY, which is honest backpressure.
2. **Rounds defeat sequence keys.** A new delivery round reuses the same
   `(session, sequence)`; under a floor it is `≤ floor` and suppressed even
   though the terminal never delivered it — silent loss in exactly the
   END_RECEIPT-loss case dedup exists for. Per-(seq,round,type) floors are
   per-record dedup again with worse fields.
3. **The record carries duty, not just seen-ness.** DedupEntry stores the
   upstream/downstream correlation, fingerprint and retained failure
   evidence needed for re-ACK, MESSAGE_CONFLICT and verbatim replay. A
   floor/bitmap answers only "was seq s seen" — losing conflict detection
   (same key, different bytes silently accepted) and the failure-evidence
   chain.
4. **Spoofability at relays.** A relay cannot end-verify the origin field;
   one forged high-seq frame poisons the floor and drops the origin's real
   stream — one frame buys a whole window of damage, vs one record per
   forged frame today.
5. **Cardinality is not saved.** A floor is per (origin, session, type); a
   bounded pool of floors is a smaller-record table with the same "what if
   a new origin arrives when full" question — except eviction now loses
   *ordering* state for every sequence of that origin, a strictly worse
   failure per byte. Session wrap/reboot resets compound it (cf. the u16
   epoch exhaustion gate in 04 §4.7).

A floor could still serve as a *coarse pre-filter* (drop counting of
manifestly-old traffic before admission work). Rejected anyway: it adds a
second state class whose eviction failure mode (whole-origin amnesia) is
worse than the pool it protects, and the scheduler's scope caps already
bound pre-admission CPU.

## 2.10 Failure matrix

| Condition | Behavior | Emission | Consequence |
|---|---|---|---|
| `deliveries_` all live | `send()` → `NoCapacity` | existing status path | honest pre-admission refusal |
| `deliveries_` full, terminal present | evict oldest terminal | `delivery_terminal_evicted` + `DELIVERY_HISTORY_EVICTED` | result no longer queryable; dedup unaffected |
| dedup full, Resolved present | evict earliest-expiry Resolved | `evicted_resolved` + diagnostic | possible one-extra re-forward on late dup; downstream dedup + terminal pin still suppress double delivery |
| dedup full, only Evidence evictable | evict oldest Evidence (≤16 cap) | `evicted_evidence` + diagnostic | verbatim replay lost; late dup re-forwards; fresh failure cycle possible; advisory evidence only |
| dedup full, all Live/Terminal | refuse admission | `refused_pool_full` + `DEDUP_OVERFLOW` + BUSY-or-counted-drop | availability loss, zero dedup weakening; upstream bounded retry recovers after expiry |
| Terminal pins ≥ 56 | new terminal admissions refused | `refused_terminal_reserve` + diagnostic | transit reserve survives; terminal stream self-throttles |
| Upstream > 24 transit records | refuse that upstream's transit | `refused_upstream_cap` + diagnostic | flood isolation; other upstreams unaffected |
| `awaiting_hop_` full at TX result | `retry_or_fail("HOP_WAIT_TABLE_FULL")` → Evidence on final fail | existing reason + report chain | bounded retry/failure, honest report |
| `transit_failure_seen_` full | drop inbound report | `telemetry_event_drops_` (existing) | report loss counted; upstream timeout still bounds |
| DiagBudget exhausted | report not emitted | counted (existing) | bounded emission, no flood |
| Receipt dedup alloc fails (transit or terminal) | drop + BUSY where admissible | `DEDUP_OVERFLOW` + counter | origin's next DATA round regenerates terminal emit — self-healing |
| Post-eviction downstream report arrives | uncorrelated — drop | `telemetry_event_drops_` (existing) | counted silence; origin deadline still terminal |
| Host resubmit of evicted delivery | new MessageId or `resume_delivery` reuse | dispatch.rs resend path | destination Terminal pin / component dedup suppresses re-effect |

## 2.11 Test plan

Host sims (`test_sim.hpp` / `SimWorld` — add a "replay delivered frame"
injection hook for duplicate storms; the harness already supports drops):

| Case | Assert |
|---|---|
| Phase transitions | admit→Live; hop-accept→Resolved; post-accept fail→Evidence; terminal deliver→Terminal; receipt consume→Resolved |
| Retention formula | `expires_at == min(first_seen+60 s, horizon+slack)` per role; refresh on terminal re-receipt never exceeds `first_seen+60 s` |
| Eviction order | mixed-phase pool; new admission evicts Resolved before Evidence, never Live/Terminal; counters and diagnostics emitted |
| Evicted-Resolved replay | re-received frame re-forwards once; terminal `on_message` fires exactly once end-to-end |
| Evicted-Evidence replay | no verbatim re-emit; re-forward occurs; counter incremented |
| Terminal pin bound | 56 pins refuse the next terminal admission while transit still admits into the reserve |
| Upstream cap | flood from one previous-hop caps at 24; second upstream unaffected |
| Cross-round dedup | END_RECEIPT dropped → round+1 arrives → suppressed by pinned Terminal record, receipt re-emitted, one `on_message` |
| Continuous streams | sustained send at 0.5×/1×/1.5× the §2.7 bound for L=5 s and L=30 s: below bound zero BUSY and zero dups; above bound bounded BUSY fraction, zero dups, all counters account for every refused frame |
| True overflow | pool all-Live → BUSY to capable peer; counted drop to incapable peer |
| Expiry sweep | expired reclaim beats eviction (no `evicted_*` when expired records exist) |

Regression: existing `test_congestion`, `test_gateway` (dedup hold semantics),
`test_power` (resume dedup), `test_routing_sims` F1–F6 analogs must stay
green; the F6 "full dedup" case now expects BUSY + `DEDUP_OVERFLOW`.

Six-board (documented, not executed): sustained multi-origin stream through
the relay chain below/above bound; terminal+relay co-located flood showing
the reserve working; relay-off mid-stream drain; evidence storm with
`kMaxFailureReplays` respected.

## 2.12 Implementation checklist

| File | Change |
|---|---|
| `components/routeloom/include/routeloom/node.hpp` | `DedupPhase` enum; `DedupEntry` += `phase`, `first_seen_ms`; constants (§2.4); `DedupStats` + `dedup_stats()`; decl `dedup_expiry_for()`, `evict_dedup_for_admission()`, `resolve_dedup_for_job()`, `count_transit_upstream()` |
| `components/routeloom/src/node.cpp` | `allocate_dedup` signature (+role, upstream, deadline) and the §2.5 sweep; six call sites (`handle_data` ×2, `handle_routed` ×2, `handle_end_receipt` ×2); `complete_job` Transit→Resolved hook; `report_transit_failure` → Evidence; terminal refresh formula (~:1698); counters/diagnostics; `transit_failure_seen_` expiry = referenced record expiry (:3977) |
| `tests/cpp/test_dedup_capacity.cpp` | new; `test_sim.hpp` duplicate-injection hook; CMake registration |
| `docs/reference/resource-profiles.json` + `spec/resource-profiles.md` | reconcile `dedup_and_compact_receipt_records` with the real 160 B entry |
| `host/routeloom-host/src/{dispatch.rs,send_store.rs}` | **no functional change** — resend/NotRetained and 24 h op journal already assume bounded device dedup; add doc cross-reference comments only if touched |

## 2.13 Open questions

- Exact `kTransitSlackMs` (5 s proposal vs spec-literal 30 s uniform slack —
  the relay-capacity multiplier at stake); bench evidence can pin it.
- Whether `DedupStats` folds into `CongestionStats` or stays a separate
  accessor; telemetry-snapshot exposure is a separate wire question (04
  §4.2 fields are frozen).
- Whether `AwaitingHop` residency (8) needs a transit-specific sub-reserve;
  current per-peer window + retry path is judged sufficient — sim evidence.
