# 3. Congestion → route-metric coupling

Status: **implemented / host-tested** (was: design proposal) for [issue #4](https://github.com/MOVEI144/RouteLoom/issues/4). This document specifies the coupling contract that [03-congestion.md](../autonomous-mesh/03-congestion.md) §6/§7 deferred as "P3" and that [02-telemetry.md](../m1-completion/02-telemetry.md) §2.5 gates behind freshness/provenance rules. Parts of the coupling already exist in the portable core and are marked *implemented / host-tested* below; the additions are implemented and host-tested as of this revision. One deliberate deviation from the checklist: the refresh bound is surfaced as a one-shot `ROUTE_REFRESH_BOUND_EXCEEDED` diagnostic rather than a `validate_config` rejection — the bound is worst-case (a full table at one page per period) and hard-rejecting it would brick otherwise-valid default configurations. Nothing here changes the frozen Wire v1 byte layout.

Source documents: `docs/design/autonomous-mesh/03-congestion.md` (D4-01…D4-04, §3 observation contract, §6 metric ownership, §7 switching discipline, §8 control budget, §9 failure behaviour), `docs/design/m1-completion/02-telemetry.md` (§2.4 windows, §2.5 metric input rules), `docs/design/autonomous-mesh/contracts.json` `congestion.*` pins, `docs/spec/routing.md` §10 (FD semantics).

## 3.1 Overview

Route selection is a Babel-derived distance-vector table (`RouteTable`, `routing.hpp`). Each candidate's total is `advertised + link_cost`: the metric the next hop self-reported plus the cost of our link to it. The coupling defined here decides what goes into `link_cost` and how the result moves through selection and advertisement, under four invariants:

1. **Honesty.** Only fresh, correctly-provenanced local observations may move a metric. Stale, absent, incomplete, injected or remote-reported evidence must never make a route look *better*; it may still withdraw a route through failure handling (02-telemetry §2.5).
2. **Stability.** Queue effects are immediate; route effects are seconds-scale (D4-04). Inputs are smoothed and decayed, the output cost is slew-bounded on the improving side, and selection changes pass the committed-next-hop hysteresis.
3. **Symmetry of responsibility.** Each node contributes exactly its own egress-queue delay and its own measured exchange work. A node's congestion raises the metric *it* advertises (self-reported, authenticated by the link layer) and never enters a neighbour's books a second time.
4. **Boundedness.** All coupling state lives in the fixed `Neighbor` record (32), the `BusyLink` pool (32), the observation buckets (8) and the peer summaries (19). No history buffers, no per-message state.

### What already exists (implemented, host-tested in `test_routing_load.cpp`)

- Pure cost functions `measured_link_base()` / `queue_penalized_cost()` and pinned parameters (`congestion.hpp` lines 60–82, 328–372): queue target 50 ms, 50 ms steps, ×4 cap, minimum 4 authenticated accepts.
- Per-neighbour measurement mirror (`Neighbor::exchange_work/exchange_accepts/exchange_window_ms`, `queue_sojourn_ewma_ms/sojourn_samples/last_sojourn_ms`, `node.hpp` lines 550–571) fed by `obs_tx_submitted()` / `obs_hop_result()` (`node.cpp` lines 2955–3013).
- `refresh_neighbor_load()` / `refresh_link_cost()` (`node.cpp` lines 4001–4071): decaying exchange counters (halve per 2 s window), busy-feedback TTL (3 s), cost recompute and `RouteTable::update_link_cost()`.
- The switching discipline in `RouteTable` (`routing.cpp` `evaluate_entry`, lines 167–265): committed next hop, ≥20 %-and-≥1 improvement margin sustained for 10 s + per-(node, destination) jitter, 5 s post-switch hold, 2 s severe-BUSY fast repair, prompt commit for topology-fresh (newer sequence or strictly better *advertised*) information.
- `update_link_cost()` recomputes candidates from their **stored** advertised metric; it never extends leases, never touches FD, refuses cost 0 (routing.cpp lines 271–297).
- Advertised metrics already carry our own link cost: `queue_route_update()` emits `selection.metric` (`node.cpp` lines 1004–1023), which includes the penalized `link_cost` toward the committed next hop.
- Dispatch-time route re-verification: a queued job is retargeted to the *live* selection under the same MessageId/deadline/round, or held (deadline-bounded) when no feasible route exists (`node.cpp` lines 1351–1385).
- Triggered-update pacing: ≥1 s between bursts (2 s under ≥50 % occupancy), ≤64 ms deterministic jitter, per-destination 2 s gap on pure metric improvements (`kTriggeredUpdateMinIntervalMs`, `kTriggeredJitterMs`, `for_each_selected_change` in `routing.hpp` lines 194–224).
- Relay-off withdrawal: `set_relay_enabled(false)` triggers an immediate all-infinity advertisement round (`node.cpp` lines 1007–1013, 4031–4039) and `transit_permitted()` refuses new transit with `TransitFailure(RelayDisabled)`.

### What this document adds (implemented / host-tested in `test_routing_load.cpp` and `test_congestion.cpp`)

- §3.3 — the **provenance/freshness gate** made explicit at the *neighbour mirror* level (the `ObservationBucket::positive_metric_input()` contract exists but is not wired to the metric path; the mirror is written unconditionally today).
- §3.4 — a **refusal-pressure floor** closing the starvation blind spot: when the TX pool refuses admissions, no new sojourn samples are produced, so the queue term would decay while the node is still saturated.
- §3.5 — an **asymmetric slew bound** on `link_cost`: worsening applies immediately; improvement decays by at most half of its excess per observation window (the "bound metric movement per advertisement interval" requirement).
- §3.7 — the **identity-reset rule**: peer restart / rebind / channel-epoch change resets the neighbour measurement window so evidence from an old identity never carries into the new one.
- §3.8 — the relay-off vs. overload advertisement semantics and the FD/saturation edge cases.
- §3.9–§3.12 — oscillation analysis, failure matrix, test plan, implementation checklist.

## 3.2 Signals and their admissibility

| Signal | Producer | Provenance | Metric use |
|---|---|---|---|
| `queue_sojourn_ewma_ms` per neighbour | `obs_tx_submitted()` — enqueue → driver-handoff time of our own jobs | local owner bookkeeping (implicitly `LocalDriver`) | queue-penalty input `Q_ms` |
| `exchange_work` / `exchange_accepts` | submission count of hop-accept jobs / authenticated `HOP_ACCEPT` arrivals (`handle_hop_accept`, node.cpp:1663) | local + link-authenticated peer event | measured base ratio |
| TX pool `occupancy_percent()` | `TxScheduler` | local | refusal-pressure floor `steps_r` |
| Peer BUSY (`Reject`/`PressureHint`), `BusyPayload.pressure`, `NeighborResult.queue_delay_ms` | peer self-report, link-authenticated, sequence-ordered, TTL 3 s | `AuthenticatedRemoteReport` | **never a metric input** — feeds admission/window and the severe-busy repair hint only (03 §6.2) |
| `unknown_results`, callback watchdog | Owner | local | marks the measurement window *incomplete*; never merges into a failure counter |
| RSSI, driver service time, hop RTT | telemetry path | local/remote | **diagnostic only** — driver service may contain CCA/MAC retries; re-multiplying it into an ETX term double-counts (03 §6.1, 02 §2.5) |

Two consequences of this table:

- **The metric input is exclusively our own bookkeeping plus authenticated protocol events.** Nothing a peer *says* — BUSY pressure, probe results, telemetry snapshots — enters `link_cost`. A peer can only move our cost to them by what it *does* to our real traffic (accept, refuse, drop). Anti-gaming reduces to: self-reported congestion lives inside the reporter's own advertised metric, where it can only hurt the reporter.
- `RadioRxMetadataV2`-tagged observations (`note_radio_tx`, `note_rx`) carry a provenance field precisely so that `InjectedTest`/`AuthenticatedRemoteReport` samples are separable. The neighbour mirror must keep that separation: mirror writes are permitted only from the submission/accept bookkeeping paths, never from `note_rx`/`note_radio_tx` or remote summaries. This is stated as an invariant and guarded by §3.3.

## 3.3 Evidence gate — when the mirror may move the metric

The bucket-level contract `ObservationBucket::positive_metric_input()` (congestion.hpp:275–284) already encodes 02 §2.5: only a complete, fresh, purely-`LocalDriver` window may improve a metric. The neighbour mirror needs the same contract at its own level — it deliberately survives bucket-pool overflow (node.cpp:2955–2957), so it cannot delegate the check to the bucket pool.

Per neighbour `N`, per decay window `W` (2 s, same cadence as the exchange-counter halving):

- **Fresh**: `last_sojourn_ms` within `kObservationWindowMs` for the queue term; the exchange ratio is valid while its decayed counters still satisfy `exchange_accepts >= kExchangeMinAccepts`. Absent evidence → conservative defaults (`Q_ms = 0`, base = nominal), never an improved guess.
- **Provenance-clean**: all contributing samples are local bookkeeping or link-authenticated events. A window into which any `InjectedTest` or remote-derived sample was folded is *tainted*: treat it as absent (decay proceeds; the tainted samples contribute nothing). In practice the mirror fields are written only by local paths — the gate is a stated invariant plus a `metric_sources`-style bitmask on the neighbour so a future wiring change (e.g., remote telemetry feeding the mirror) cannot silently violate it.
- **Complete**: a window in which any attempt toward `N` resolved `Unknown` (callback watchdog, fenced, unmatched) is flagged `metric_window_dirty`. Dirty evidence may *worsen* the cost but never improve it: while dirty, the §3.5 relax step is suppressed. The flag clears at the next window roll — a bounded suppression, not a latch.
- **Current identity**: samples taken under a previous binding/radio/channel generation or a previous peer incarnation are stale (§3.7).

Missing-window rule restated positively: `link_cost` may move *toward* nominal on the strength of "no fresh trusted evidence of congestion"; it may move *away* from nominal only on fresh trusted evidence; it may *never* improve on the strength of tainted/incomplete evidence.

## 3.4 Metric formula — exact EWMA → metric mapping

All arithmetic is `RouteMetric` (u16), saturating at `kInfiniteRouteMetric = 65535`, in wide intermediates; cost 0 is never produced (only self-origin distance is 0). Refreshed for every active neighbour on each `poll()` inside `refresh_neighbor_load()`.

**Step 1 — decay the exchange window** (exists). While `now − exchange_window_ms ≥ 2000`: `exchange_work >>= 1; exchange_accepts >>= 1; exchange_window_ms += 2000`. Both counters halve together, so the *ratio* is preserved while confidence decays to the minimum-sample gate. A window roll also clears `metric_window_dirty`.

**Step 2 — measured base** (exists):

```
base = neighbor.metric                                              // nominal, add_neighbor input
if (!metric_window_dirty && exchange_accepts >= kExchangeMinAccepts) // 4
    base = measured_link_base(nominal, exchange_work, exchange_accepts)
//  = clamp_positive(ceil(nominal * work / accepts))  — ETX-like, dimensionless
```

`work` counts every physical submission of a hop-accept job toward the peer — failures included, so success-only sampling cannot flatter the link. `accepts` counts authenticated `HOP_ACCEPT` completions. `accepts == 0` or `work <= accepts` keeps nominal. Driver service time never enters this term (retry double-count, 03 §6.1). A dirty window keeps the last-computed ratio from *falling*; work/accepts in it still count for worsening.

**Step 3 — queue penalty in units of base multiples** (new formulation, backward-compatible with `queue_penalized_cost`):

```
Q_ms   = (last_sojourn_ms != 0 && now - last_sojourn_ms <= 2000) ? queue_sojourn_ewma_ms : 0
steps_q = min(4, ceil(max(0, Q_ms - 50) / 50))                   // existing term (03 §6.2)

// refusal-pressure floor (implemented): a saturated scheduler stops producing
// sojourn samples precisely when congestion is worst. Pool occupancy is not
// a time unit, so it maps directly to penalty *steps* — never added as ms.
steps_r = occupancy >= 50% ? min(4, 1 + (occupancy - 50) / 10) : 0
//       50–59 % → 1, 60–69 % → 2, 70–79 % → 3, ≥80 % → 4

m     = min(4, max(steps_q, steps_r))                            // one congestion signal, counted once
target = sat65535(base * (1 + m));  target == 0 → 1
```

`max()`, not `+`: pool saturation and per-peer sojourn are two readings of the same congestion; adding them would punish one phenomenon twice. Both are bounded by the same ×4 cap. `steps_r` is node-level (the pool is shared) and applies identically to every neighbour — a saturated node becomes less attractive wholesale, which is the required self-report direction.

**Step 4 — asymmetric slew bound** (implemented). `link_cost` tracks `target`, but improvement is time-gated so a quiet burst cannot swing a route:

```
if (target >= link_cost) {
    link_cost = target                        // worsen immediately (bounded by saturation)
} else if (!metric_window_dirty && now - last_cost_relax_ms >= kObservationWindowMs) {
    excess = link_cost - target
    if (excess <= max(1, ceil(base / 4))) link_cost = target     // residual snaps
    else                                  link_cost -= max(1, excess / 2)
    last_cost_relax_ms = now
}
```

Per observation window the cost may recover at most half of its excess above the honest target; per 5 s advertisement interval that is ≲ 80 % of the excess — a bounded, quantifiable movement. Full recovery from the worst queue penalty (5·base → base) takes ~5 windows ≈ 10 s, matching the 10 s improvement hold downstream. Worsening is deliberately *not* slew-limited: delaying congestion harm buys no stability (selection hysteresis already gates the route change) and slow-worse would let a fresh burst hide behind an old good cost.

On any change: `routes_.update_link_cost(neighbor.node, link_cost, now_ms)` — recomputes all candidates via that hop from stored advertised metrics; leases, FD, tombstones untouched (exists).

**Worked examples** (nominal = 10):

| Input | base | m | target |
|---|---|---|---|
| quiet, no samples | 10 | 0 | 10 |
| Q_ms EWMA = 200 | 10 | 3 (ceil(150/50)) | 40 |
| pool 83 % full, sojourn stale | 10 | 4 (floor) | 50 |
| work = 10, accepts = 4 | ceil(10·10/4) = 25 | 0 | 25 |
| work = 10, accepts = 4, Q_ms = 60 | 25 | 1 | 50 |
| ratio ×8, Q_ms ≥ 200 | 80 | 4 | 400 |

**Saturation is meaningful**: if `base·(1+m)` reaches 65535 the link cost *is* wire-infinity — a locally-computed "do not route through me this way". On our own advertisements this legitimately emits infinity for affected destinations (§3.8); on a stored candidate it makes the hop unselectable and triggers the normal repair path — never a fabricated finite cost.

## 3.5 Selection-side contract (exists — restated as the coupling's obligations)

- **Committed next hop**: DATA forwarding, advertised metric and FD updates all derive from the same `select()` snapshot (03 §6.3 — no "hidden routing" where DATA takes one path and advertisements describe another).
- **Improvement**: an alternative must be ≥20 % and ≥1 better than the committed route, continuously, for `kImprovementHoldMs` (10 s) + `improvement_jitter` (0–2 s, deterministic per (self, destination)). Streak breaks reset the hold (test_routing_load.cpp:300–313).
- **Post-switch hold**: 5 s before any further voluntary switch — applies to repairs too, so the abandoned hop cannot instantly win the route back.
- **Severe-BUSY fast repair**: sustained authenticated busy on the committed hop ≥ `kSevereBusyMs` (2 s) permits immediate commit of a *fresh feasible* alternative that is not itself severely busy. This is the only consumer of peer-reported pressure.
- **Failure recovery never waits**: expired/withdrawn/invalidate → immediate best-candidate commit, no improvement hold.
- **Feasibility is load-immune** (D4-02): load only scales finite metrics between feasible candidates; it can never revive an infeasible candidate, delete FD/tombstone state, or extend a lease.

## 3.6 FD interaction — the one sharp edge

Feasibility compares the *advertised* metric in a received record against our current FD for the same sequence. A congestion-inflated advertised metric can cross the FD threshold: `advertised ≥ FD` at same sequence → candidate infeasible even though the link is merely slow. Consequences, by design:

- The inflated advertisement is **honest** — we never clamp our claim to stay under a neighbour's FD. The route becomes unselectable *to that neighbour*, which is the intended "less attractive" taken to its limit.
- Recovery needs no sequence bump: when congestion clears, the advertised metric drops below FD again and the candidate is feasible once more (same sequence, lower metric is accepted).
- Persistent inflation past FD resolves through the existing SeqNoRequest path (bounded attempts, linear backoff, `kSeqnoMaxInflight`) — the origin advances its sequence and FD re-arms on fresh information. **Never** resolve it by relaxing feasibility on load evidence (D4-02; the stale-FD counterexample in test_routing_load.cpp:251–270 is the regression guard).
- Our own FD only ever tightens via `mark_advertised()` (same-sequence `min(old,new)`), so a transient inflation of our advertised metric does not raise the bar our neighbours must clear.

## 3.7 Identity and staleness resets (implemented)

Metric evidence is keyed to the identity it was measured under. Reset the neighbour measurement window (`exchange_work`, `exchange_accepts`, `exchange_window_ms`, `queue_sojourn_ewma_ms`, `sojourn_samples`, `last_sojourn_ms`, `metric_window_dirty`; and recompute `link_cost` to the nominal-after-slew position) on:

- **Peer incarnation change**: self-record generation bump in `handle_route_update` (node.cpp:2286–2297 already drops via-peer candidates without hold-down; the measurement mirror must reset with them — evidence was gathered against a different incarnation).
- **Binding/radio/channel identity change**: `note_peer_stale()` (node.hpp:259) currently retires only the telemetry summary; extend it to the mirror fields. A rebind makes prior accepts/sojourn unattributable to the current link identity (02 §2.3).
- **Neighbour removal/re-add**: `add_neighbor` already zero-initializes (node.cpp:469–476); keep that the single init point.

## 3.8 Advertisement semantics — wire compatibility and the two directions

**Wire delta: 0 bytes.** The congestion penalty folds into the existing `metric` u16 of the 14-byte route record (`dest u64 | gen u16 | seq u16 | metric u16`, `kMaxRouteRecordsPerFrame` = 9 at node.cpp:18–22). Rationale for not adding a field:

1. Wire v1 is frozen (`contracts.json` `wire.preserve_major = 1`); a new per-record field would cut the record budget and invalidate golden vectors.
2. The metric field already *means* "the advertiser's total claimed distance" — the advertiser's forwarding conditions are part of its distance. Receivers add only their own link cost (03 §6.2 ownership: never re-add the peer's queue).
3. A parallel optional field would create a gaming/ambiguity surface (receivers could discount it; non-upgraded peers would see different metrics → divergent tables). One scalar, one semantics.
4. Sequence/generation/FD semantics are unchanged; infinity keeps its existing withdrawal meaning, with the §3.4 saturation caveat that computed infinity and explicit withdrawal share wire encoding.

**Outbound (self-report direction)**: `queue_route_update` emits `selection.metric` for each selected destination, which is `committed_candidate.advertised + link_cost(committed_next_hop)` — i.e., our measured base plus queue/refusal penalty toward our next hop is *inside* what we advertise, authenticated because RouteUpdate is link-protected to the receiving neighbour. The self record stays `metric = 0` (distance-to-self; inbound congestion is signalled by BUSY refusals, not by inflating our own origin distance). Split-horizon retractions (`selection.next_hop == neighbor`) stay infinity.

**Inbound**: `handle_route_update` considers each record with `neighbor->link_cost` — the same penalized cost `update_link_cost` maintains (node.cpp:2302–2305). New and stored candidates are built from one consistent cost basis.

**Ordering/rate**: worsening metric changes and withdrawals are never rate-limited; pure improvements per destination are gated by `kImprovementAdGapMs` (2 s) inside `for_each_selected_change`, and all triggered rounds respect `kTriggeredUpdateMinIntervalMs` (1 s, doubled under ≥50 % occupancy) + ≤64 ms jitter. Net effect: bad news propagates at triggered-update speed, good news is damped on the wire as well as in the cost function.

**Relay-off vs. overload — the required distinction**:

| State | Advertised metric | New transit | Accepted work |
|---|---|---|---|
| `relay_enabled_ == false` | **infinity** for every selected route (prompt withdrawal, 03 §9 / 01 §policy) | refused — `TransitFailure(RelayDisabled)` | drains on original deadlines; dedup evidence retained |
| Overloaded but willing | **finite, inflated** (×cap or saturation) | BUSY rejections per admission verdict; pressure hints post-acceptance | never cancelled by queue control |
| Overloaded to true saturation (cost = 65535) | infinity — computed, honest | same | same |

Rules: a node must not emit infinity while still willing to forward at a finite cost (infinity is withdrawal — it arms hold-downs/tombstones at receivers and can trigger SeqNoRequest churn), and must not keep low finite metrics while refusing all work (the §3.4 refusal floor makes that state self-inflating anyway). Conversely, BUSY/pressure signals alone never touch the metric — a congested-but-functioning relay is steered around by finite inflation, not by disappearance.

**Lease safety under churn** (03 §8, D4-06): `update_link_cost` never extends `expires_at_ms`, so metric churn cannot keep a dead peer's route alive; and because the refresh is local, a neighbour that goes silent still expires on schedule. Profile authors must satisfy `route_lifetime_ms > pages_per_neighbor × route_advertisement_period_ms + jitter + loss_margin` where `pages_per_neighbor = ceil(route_entries / 9)` — the rotating-cursor dump otherwise cannot refresh the tail of a large table inside one lease. `validate_config` currently only checks `lifetime > period`; extending it to the full refresh bound is in the checklist.

## 3.9 Oscillation analysis

Mechanisms that bound oscillation, in order of the pipeline:

1. **Input damping**: sojourn EWMA α = 1/8 (≈8 samples to converge); exchange counters halve per 2 s; penalty quantized to 50 ms steps and capped at ×4.
2. **Output slew** (§3.4 step 4): improvement ≤ halving of excess per 2 s per neighbour; worsening immediate but range-bounded.
3. **Selection hysteresis** (§3.5): ≥20 % margin, 10 s + jitter hold, 5 s post-switch hold → at most one voluntary switch per destination per node per ~15 s worst case.
4. **Wire pacing** (§3.8): improvements ≥2 s apart per destination, triggered bursts ≥1 s (≥2 s under load).

Two-arm ping-pong (A congests → herd moves to B → B congests → back to A): the move to B requires B's total to stay ≥20 % under A's for the whole jittered hold; as load shifts, B's advertised metric rises (fast, unbounded upward), eroding the margin and resetting pending streaks before they commit. Even if a switch commits, the abandoned arm's metric recovers only through the slew — by the time it looks attractive again, ≥5 s post-switch hold plus ≥10 s improvement hold must re-elapse. The jitter (per node+destination, 0–2 s) decorrelates the herd's evaluations so they do not crest B simultaneously.

Worst-case bounds to *demonstrate in simulation* (D4-07): per-destination voluntary switch rate ≤ 1/(hold + switch_hold); advertisement rate per neighbour ≤ periodic + triggered bounds independent of load oscillation frequency; route-loop freedom unaffected (feasibility is load-immune, so oscillating metrics cannot construct a cycle — only oscillating *choices* among feasible paths).

Residual risk acknowledged: severe-busy repair (2 s) is the fastest switch path and bypasses the improvement hold — a fleet under synchronized BUSY could still migrate in step. Mitigations present: the alternative must be fresh *and* feasible *and* not itself severely busy; the 5 s post-switch hold still applies; busy state requires sustained authenticated feedback within 3 s TTL. D4-07's 100-node simultaneous-evaluation requirement stands as the acceptance gate for this residual.

## 3.10 Failure matrix

| Condition | Metric-path behaviour | Route-path behaviour |
|---|---|---|
| No samples / all stale | `Q_ms = 0`, base = nominal | none (conservative default) |
| `accepts < 4` | base = nominal | none |
| Sojourn stale (>2 s) | penalty term = 0 (subject to refusal floor) | relax via slew |
| Pool ≥50 % with starved sojourn | `steps_r` floor keeps penalty ≥1 | cost stays inflated — closes starvation blind spot |
| Window dirty (unknown completions) | rises allowed, relax suppressed this window | conservative |
| Tainted provenance in window | window treated as absent | no improvement possible |
| Authenticated BUSY (matched) | **no metric effect** | busy hint → severe-busy repair after 2 s; sender-side window/readmission budgets apply |
| BUSY stale/replayed/unmatched | counted (`busy_stale`/`busy_unmatched`) | ignored |
| Peer restart (generation ↑) | measurement mirror reset (§3.7) | via-peer candidates dropped, no hold-down |
| Rebind / radio / channel epoch change | summary stale + mirror reset | old-identity evidence unusable |
| Link cost saturates to 65535 | cost = infinity | candidate unselectable → repair; our own ads for affected destinations become computed-infinity |
| Relay disabled | — | all-infinity triggered ad + transit refusal + drain |
| Bucket pool full | `observation_overflow` counted; mirror still updates | cost path unaffected; snapshot shows bucket-invalid |
| Telemetry table full | `telemetry_event_drops++` | no metric input change (missing evidence ≠ good news) |
| `update_link_cost(0)` or unknown hop | refused | — |
| `last_sample_ms > now` (clock uncertainty) | sample ineligible (`positive_metric_input` rule) | — |
| Neighbour silent | metric churn cannot renew lease | candidate expires at `expires_at_ms` |
| Infeasible alternative under load | feasibility re-checked live at select time | never selected regardless of cheapness |

## 3.11 Resource bounds

| State | Bound |
|---|---|
| Per-neighbour metric cache | inside `Neighbor` (32 max): +8 B (`last_cost_relax_ms` 8 B, `metric_window_dirty`/`metric_sources` packed flags) |
| Busy hints | `FixedPool<BusyLink, 32>` — a dropped report is a lost hint, never growth |
| Observation buckets | 8, pinned while in use; overflow counted |
| Peer summaries | 19 |
| History | none — EWMA/counters/decay only; no raw samples, no per-message metric state |
| `update_link_cost` work per change | O(destinations × 3 candidates) ≤ 384 comparisons, only on actual cost change |

## 3.12 Test plan

Extend `tests/cpp/test_routing_load.cpp` (and `test_congestion.cpp` where scheduler-level), keeping the pure-function tests separate from harness tests:

**Pure math** (`test_cost_helpers` additions)
- `refusal_penalty_steps`: 49 % → 0, 50 % → 1, 65 % → 2, 79 % → 3, ≥80 % → 4.
- `relax_link_cost`: halving sequence 50→30→20→15→13→10 at base 10; snap threshold; never overshoots target; `dirty` suppresses the step.
- Composed formula table from §3.4 examples, including saturation at 65535.

**Table level** (RouteTable)
- Saturated link cost → committed hop unselectable → immediate repair; recovery when cost falls.
- `update_link_cost` still never renews leases (existing test retained).
- Infeasible candidate stays unselected while its link cost drops through the floor.

**Node level** (Harness/SimWorld)
- Starvation blind spot: fill the pool so admissions refuse; verify `peer_link_cost` stays inflated by `steps_r` after sojourn goes stale.
- Dirty window: inject an unknown completion, then drop queue pressure; relax must not apply until the next window roll.
- Identity reset: peer generation bump and `note_peer_stale` both zero the measurement mirror (no penalty carryover).
- Self-report direction: congest node 1's queue toward its next hop; verify the *advertised* metric emitted to a third neighbour rises (decode RouteUpdate records), and that a BUSY/pressure hint from a peer changes *no* link cost.
- Advertised-infinity discipline: `set_relay_enabled(false)` → all records infinity on next ad; sustained congestion alone → finite inflation (or saturation) but never a *policy* infinity while willing.
- Lease/churn: oscillating costs through `update_link_cost` never extend `expires_at_ms`.
- Refresh bound: implemented as a one-shot `ROUTE_REFRESH_BOUND_EXCEEDED` diagnostic at start when `route_lifetime_ms <= pages * period + jitter + period`; a hard `validate_config` rejection was evaluated and rejected — the bound assumes a worst-case full table and would fail valid defaults.

**Sim / scenario level** (scenarios.json D4 series — all `planned_not_run` today)
- D4-01 diamond asymmetric delay: switch happens once, sustained; single burst causes no flap.
- D4-02 stale-FD counterexample + cost updates interleaved with `mark_advertised`.
- D4-06 refresh-bound calculation with 100+ origins; no healthy-route expiry from our own ad backlog.
- D4-07 100-node simultaneous load evaluation, fixed seeds: bound switch counts, report oscillation; assert no sustained synchronized ping-pong.
- D4-08 congested committed hop with only infeasible/expired alternatives: no DATA to infeasible hops; budgets honoured.
- D4-10 post-acceptance congestion: hints don't retract accepted work; dedup/receipt integrity retained.
- New: advertisement-count bound — under oscillating injected load, RouteUpdate frames per neighbour per interval never exceed the §3.8 bounds; metric improvements propagate ≥2 s apart per destination.
- Regression baseline: fixed-metric/FIFO vs this profile on the same scenario seeds; report in-deadline delivery, P95/P99, total TX, refusal counts, switch counts, RAM ceiling — denominators include failed deliveries, not just successes (03 §10).

## 3.13 Implementation checklist

| File | Change |
|---|---|
| `components/routeloom/include/routeloom/congestion.hpp` | Add pins `kRefusalStepWatermarkLowPercent` (50), `kRefusalStepPerTenPercent`, `kLinkCostRelaxWindowMs` (= `kObservationWindowMs`), `kLinkCostRelaxSnapDivisor` (4); add pure functions `refusal_penalty_steps(occupancy_percent)` and `relax_link_cost(current, target, base)`. Keep `measured_link_base`/`queue_penalized_cost` signatures (compose around them) or generalize penalty input to step count — decide once; update the header's "stays off until P3" banner. |
| `components/routeloom/include/routeloom/node.hpp` | `Neighbor`: add `MonotonicMs last_cost_relax_ms{0}`, `bool metric_window_dirty{0}`, `std::uint8_t metric_sources{0}`; extend `note_peer_stale()` to reset the measurement mirror; document `link_cost` slew semantics on the `peer_link_cost` accessor. |
| `components/routeloom/src/node.cpp` | `refresh_link_cost` (4001): add `steps_r` floor + asymmetric slew + dirty gate; call `update_link_cost` on change (exists). `refresh_neighbor_load` (4041): clear `metric_window_dirty` on window roll. `obs_tx_submitted`/`obs_hop_result`: keep mirror writes local-only; tag `metric_sources` with the bookkeeping bit. Unknown-resolution paths (`on_radio_tx_result` watchdog 1313–1328, `note_radio_tx` unknown 3071): set `metric_window_dirty` for `job.peer`/`observation.peer`. `handle_route_update` restart branch (2293): reset the neighbour measurement mirror. `validate_config` (414): `route_lifetime_ms > refresh_bound` surfaced as diagnostic `ROUTE_REFRESH_BOUND_EXCEEDED` (see status note — deviation from the original hard-reject wording). `queue_route_update` (994–1023): no code change — verify in tests that `selection.metric` carries the penalized cost; self record stays 0. |
| `components/routeloom/src/routing.cpp` / `routing.hpp` | No functional change required — `update_link_cost`, `evaluate_entry`, `for_each_selected_change` already enforce the safety contract; adjust comments to reference this document. |
| `docs/design/autonomous-mesh/contracts.json` | Add `congestion.link_cost_relax_window_ms`, `congestion.link_cost_relax_snap_divisor`, `congestion.refusal_step_watermark_percent`, `congestion.refusal_step_per_ten_percent`. |
| `tests/cpp/test_routing_load.cpp`, `test_congestion.cpp`, `test_telemetry.cpp` | Add §3.12 cases; `positive_metric_input` already covered in test_telemetry.cpp:299. |
| `docs/design/autonomous-mesh/03-congestion.md`, `docs/STATUS.md` | After implementation lands: update the "P3 deferred" note and the maturity line — currently "EXPERIMENTAL portable implementation + host tests"; model/HIL evidence tracked separately per the maturity convention. |

Explicit non-goals: no multipath/striping (D4-03), no adaptive RTO (02 §2.5 — diagnostic only), no network-wide credit ledger (03 §5), no channel action (defers to #5/AutoGuarded evidence rules), no new wire fields or neighbour polling for congestion data.
