# 1. APPLIED delivery semantics (Issue #12)

Status: **partially implemented / host-tested**. Baseline: `main` @ `d73cd81` plus this change. This document specifies the SDK-completion slice of [issue #12](https://github.com/MOVEI144/RouteLoom/issues/12): the destination's *application endpoint* — not merely its SDK ingress — confirms the outcome of a `DeliveryClass::Applied` send, and the originator learns *applied / rejected / timed out* as a distinct evidence class from `END_RECEIVED`. The upstream contract is [host-security-readiness/07-applied-delivery.md](../host-security-readiness/07-applied-delivery.md) (terminal state machine, ticket/digest binding, retry bounds) and [spec/delivery-storage.md](../../spec/delivery-storage.md) §1/§4/§5/§9 (class table, dedup floor, `max_message_lifetime_ms` = 30000, `late_result_ttl_ms` = 30000). Wire v1 is unchanged: `FrameType::AppResult = 19` and `DeliveryClass::Applied = 2` are already registered in `protocol/semantics.json` (`frame_numeric_ids`, `membership_allowlist.MEMBER`) — this design consumes existing type space and adds **zero** header bytes, zero new frame types and zero flag bits.

Marker convention follows the sibling documents: *implemented / host-tested* items are backed by `tests/cpp/test_applied_delivery.cpp`; *proposed* items are designed here but not built and must not be claimed as done.

## 1.1 Semantics and boundary

| Delivery class | Completion evidence |
|---|---|
| BestEffort | one transmission attempted (`TX_MAC_DONE`) |
| Reliable | authenticated `END_RECEIPT` from the bound destination's SDK (`END_RECEIVED`) |
| **Applied** | end-verified `APP_RESULT` RESULT from the bound destination's *application endpoint* (`APP_APPLIED` / `APP_REJECTED`) |

An APPLIED send is a RELIABLE send with an additional confirmation stage: the destination SDK still emits `END_RECEIPT` (it proves SDK-level acceptance and stops DATA round retries), then the destination's installed endpoint produces a verdict that travels back as `APP_RESULT`. In between, the originator's delivery waits in `WaitingForEndReceipt` with reason `APP_RESULT_PENDING` — it is *not* promoted on `END_RECEIVED` alone. If the deadline passes after `END_RECEIPT` but before RESULT, the delivery ends `Indeterminate` (`APP_RESULT_TIMEOUT`), never Delivered: receipt at the SDK layer says nothing about the application.

What APPLIED does **not** mean (07 §1): no claim about physical actuation, business-DB commits or general exactly-once side effects; no `provider_failover` (semantics.json `applied_provider_failover_default = false`) — a retransmission may reach the destination over a repaired route but the *executing destination identity never changes* mid-operation; a result is the endpoint's own statement, end-authenticated to the bound destination.

### What already exists (implemented, host-tested)

- `DeliveryClass::Applied = 2` and `FrameType::AppResult = 19` registrations (types.hpp, semantics.json) — previously unreachable: `send()` rejected Applied with `Unsupported`, and inbound AppResult frames fell to `FRAME_TYPE_UNSUPPORTED_IN_CORE_FIXED_250`.
- The routed end-protected lane (`handle_routed`): dedup + bounded forward + hop ACK keyed on the frame's own type + terminal `open_end`, used by Service/Control/Diagnostic/object types — AppResult rides it verbatim.
- The terminal dedup pin (node.cpp `handle_data`): a round-agnostic `(key, Data, delivered)` record re-ACKs and re-receipts a retransmitted round without re-delivering — the hook point this design extends for stored-result replay.
- `Sha256`/`sha256`/`constant_time_equal` (discovery_scope.hpp) — the digest primitive both digest inputs use.

### What this document adds (implemented / host-tested unless marked)

- §1.2 — the APP_RESULT body codecs (RESULT/QUERY/RESULT_ACK/STATUS), the APPLIED request body shape (`execution_lease ‖ payload`), and both digest definitions.
- §1.3 — the originator-side phase machine (END_RECEIPT → RESULT wait → bounded QUERY recovery → terminal/late handling).
- §1.4 — the terminal-side endpoint contract (synchronous verdict callback, result record, bounded RESULT emission, RESULT_ACK, QUERY/STATUS answering).
- §1.5 — dedup/retry interaction, including replayed-confirmation handling.
- §1.6/§1.7 — bounds table, eviction policy, RAM accounting.
- §1.10 — deferred items: asynchronous execution tickets, DURABLE_TERMINAL, host surfacing, capability advertisement.

## 1.2 Wire format (implemented / host-tested)

All bodies are fixed-width big-endian, decoded strictly (wrong version, nonzero flags, wrong length, reserved identity fields or trailing bytes are all rejected). All four subtypes share the 68-byte head (07 §4):

```
offset  size  field
 0      1     version = 1
 1      1     subtype: 1=RESULT, 2=QUERY, 3=RESULT_ACK, 4=STATUS
 2      1     outcome (subtype-scoped, below)
 3      1     flags = 0
 4      4     network (low 32 bits — must equal the frame's header network)
 8      8     original_origin      (the APPLIED request's origin)
16      4     original_session     (its MessageId.session)
20      8     original_sequence    (its MessageId.sequence)
28      8     original_destination (its bound destination)
36     32     request_digest       (binds body+header of the request)
```

| Subtype | Tail | Total | `outcome` field |
|---|---|---:|---|
| RESULT (1) | application_code u32 ‖ result_len u16 ‖ result[0..48] | 74..122 | 0 = success, 1 = failure |
| QUERY (2) | query_nonce u64 | 76 | 0 |
| RESULT_ACK (3) | result_digest 32B | 100 | 0 |
| STATUS (4) | query_nonce u64 | 76 | 1=Pending, 2=Indeterminate, 3=Expired, 4=NotRetained |

Sizes honour the 128-byte payload ceiling; a worst-case RESULT frame is 88 + 122 + 32 = 242 B ≤ 250 B. `APP_RESULT` frames are always end-protected routed traffic (`DeliveryClass::Reliable` on the carrier header, hop-accepted per hop, Management sched class): **the carrier is never itself an APPLIED request**, and no RESULT_ACK ever spawns a terminal ACK-of-ACK.

**APPLIED request body** (inside a normal end-protected DATA frame whose header `delivery = Applied`): `execution_lease 16B ‖ user_payload 0..112B`. The lease binds the request to the destination's current boot incarnation so a replayed request after a cold restart — where RAM dedup is gone — is refused instead of re-executed (07 §6). Lease layout (G-SEC P4 §9.1): `message_session u32 ‖ boot_session u32 ‖ boot_incarnation u64` — the second field is the destination's durable boot token, so an E2E rekey or route change leaves the lease unchanged while a destination reboot changes it (an unset `boot_session` rides `message_session`; `end_epoch` is never the fallback). It is a freshness token, not a secret; a node recomputes its expected lease from its own `NodeConfig`. A lease that mismatches (or an all-zero "no assertion" lease, or a body shorter than 16 B) is refused with an SDK-coded RESULT carrying the current lease in the 48-byte result field — that refusal is how an origin bootstraps the lease in this slice (authenticated, since RESULT is end-protected).

**request_digest** = SHA-256 over `"RouteLoom/app-request/v1" ‖ NUL ‖` the request's end-immutable identity: `network u64 ‖ origin u64 ‖ destination u64 ‖ session u32 ‖ sequence u64 ‖ delivery u8 ‖ original_lifetime u32 ‖ payload_len u16 ‖ payload`. Hop-mutable fields and both crypto counters are excluded, so origin and destination compute identical digests and any round's retransmission maps to the same request. A RESULT/QUERY/STATUS/ACK whose digest does not match the stored record's is never acted on.

**result_digest** = SHA-256 over `"RouteLoom/app-result/v1" ‖ NUL ‖` the canonical RESULT body bytes. The encoding is deterministic, so the destination recomputes it from its stored record to validate a RESULT_ACK.

**SDK refusal codes** occupy the reserved application_code band `0xFFFF0000..`: `StaleLease`, `NoEndpoint`, `Capacity`, `Malformed`. An endpoint callback may not emit codes in this band (the node clamps it — an app-supplied SDK-band code is rewritten to `InternalError` so app text cannot impersonate an SDK refusal).

## 1.3 Originator state machine (implemented / host-tested)

`send_applied(destination, user_payload, lease, options, now, id)` — `options.delivery` must be `Applied`; payload ≤ 112 B; `persist_across_sleep` is refused (`InvalidArgument`: sleep persistence of APPLIED is deferred, §1.10). The DATA body stored in the delivery record is `lease ‖ user_payload`.

```
Accepted → Queued → WaitingForMac → WaitingForHopAccept → WaitingForEndReceipt
      ── END_RECEIPT (verified, digest-matched by existing path) ──▶
      WaitingForEndReceipt / "APP_RESULT_PENDING"   [app_phase = AwaitResult]
      ── verified RESULT ──▶ Delivered "APP_APPLIED"   (outcome = success)
                          └▶ Failed    "APP_REJECTED"  (outcome = failure)
      ── STATUS (matched to a sent QUERY) ──▶ Indeterminate "APP_RESULT_*"
      ── expiry while app_phase = AwaitResult ──▶ Indeterminate "APP_RESULT_TIMEOUT"
      ── expiry before END_RECEIPT ──▶ Expired / Failed "END_RECEIPT_TIMEOUT"
                          (unchanged Reliable semantics)
```

- While `app_phase = AwaitReceipt` the DATA round machinery is unchanged: up to `max_end_to_end_rounds` rounds, each dedup-pinned at the destination.
- Once `END_RECEIPT` lands (`app_phase = AwaitResult`) DATA rounds stop. The wait is the same hop-scaled window used for receipts (`max(250 ms, hop_limit × hop_accept_timeout × 2)`); on expiry of the window the origin emits a bounded **QUERY** (≤ 2 total, fresh nonce stored on the delivery). A QUERY never creates work at the destination — it reads existing records.
- A verified RESULT resolves the delivery regardless of phase — RESULT is stronger evidence than END_RECEIPT and may arrive first if the receipt was lost. Resolution requires: `original_origin == self`, `original_destination == frame.header.origin` (only the bound destination may issue the result), the MessageId matching a live or retained delivery of class Applied, and `request_digest` recomputed from the stored request body equal to the body's — a mismatch is `APPLIED_RESULT_MISMATCH`, counted, never acted on.
- Each accepted RESULT (including duplicates on new rounds and RESULTs for already-terminal or even evicted deliveries) is answered with **RESULT_ACK** — it only stops the destination's retransmission budget; it asserts receipt, not re-processing. ACKs are one-per-received-RESULT; dedup suppresses same-round duplicates before they reach the handler.
- **Late results**: a RESULT arriving after the delivery went terminal (`APP_RESULT_TIMEOUT`/`Expired`) is still validated, stored on the delivery record when it survives (`applied_result()` exposes it with `late = true`, reason becomes `APP_RESULT_LATE`), ACKed, and surfaced through `on_applied_result` — the terminal state does not flip. Late means late: the deadline promise was already broken.
- `delivery(id)` reports the coarse state; `applied_result(id, out)` returns `{present, late, outcome, code, data}` — the code is the endpoint's own `application_code` (or an SDK refusal code), the data ≤ 48 B of endpoint-chosen bytes. `observer_.on_applied_result(key, view)` fires exactly once per stored outcome.
- `send()` continues to reject `delivery == Applied` (`Unsupported`) — the lease parameter makes `send_applied` mandatory; no silent downgrade path exists.

## 1.4 Terminal state machine (implemented / host-tested)

The terminal endpoint is synchronous and bounded in this slice:

```cpp
class AppliedEndpointSink {              // installed via set_applied_sink()
  virtual void on_applied_request(const AppliedRequest& req,
                                  AppliedReply& reply) noexcept = 0;
};
// req: {key, source, payload view (lease stripped), remaining_ms}
// reply: {outcome success|failure, code u32, data ≤48B} — always committed
```

A request passes `on_message`-free delivery: APPLIED payloads never reach the application observer path (`on_message` is the BestEffort/Reliable semantic — firing it would expose the lease prefix as app bytes and would report *receipt* as *delivery*). Terminal flow in `handle_data` for `delivery == Applied`:

1. `open_end` (bound-destination proof) → reply-slot reservation → dedup allocation (unchanged).
2. **Result-record reservation is part of admission**: a find-or-allocate against `applied_records_` happens before the HOP_ACCEPT is queued; a full pool (after the §1.6 sweep) is a pre-acceptance refusal — dedup entry released, `emit_busy_or_drop(QueueFull)`, `APPLIED_NO_RESULT_SLOT` diagnostic. Accepted work never lands without a place to store its verdict.
3. HOP_ACCEPT queued → `delivered = true` → `END_RECEIPT` queued → dispatch:
   - existing record for the key (dedup survived a re-admission across rounds or a re-received frame): **replay the stored outcome** — the app is never invoked twice for one MessageKey. A digest mismatch against the stored record is `APPLIED_KEY_CONFLICT` (counted) and still replays the stored result — the first committed outcome is never overwritten (07 §3).
   - new record: validate body ≥ 16 B and `lease == applied_lease()` → run the sink → commit `{outcome, code, data}` into the record. Refusal verdicts (`StaleLease`, `NoEndpoint`, `Malformed`) are generated by the node, not the app.
4. RESULT emitted: emits ≤ 3 total transmissions per record (initial + retries + replays share one budget), spaced by the hop-scaled retry window, all inside `emit_deadline = request_deadline + late_result_ttl (30 s)`, itself inside the 60 s record hold.
5. **QUERY** for a held record replays the stored RESULT within the same emit budget; unknown key → `STATUS NotRetained`; record past `emit_deadline` → `STATUS Expired`; digest mismatch → drop + diagnostic. Negative answers pass a per-peer answer gate (≤ 1 per 200 ms per peer via `diag_budget_`) so QUERY floods cannot amplify.
6. **RESULT_ACK** matching `(key, request_digest, result_digest-of-stored-encoding)` sets `acked` — emit retries stop. Mismatched ACKs are dropped and counted.

`DeliveryClass::Applied` DATA received at a node with **no** installed sink produces a committed `NoEndpoint` refusal RESULT — an honest terminal failure at the origin (`APP_REJECTED` + SDK code), never a silent timeout and never an `on_message` delivery.

## 1.5 Dedup and retry interaction (implemented / host-tested)

- Same-round duplicate DATA: existing dedup path re-ACKs; for Applied it additionally replays the committed RESULT (emit budget permitting).
- New-round retransmission of a delivered key: the round-agnostic terminal pin extends the record and re-ACKs + re-emits END_RECEIPT + replays the stored RESULT — one record per logical message, no per-round growth, no second app invocation.
- Replayed RESULT at the origin: same-round suppressed by the routed dedup; new-round re-validates — identical fields → idempotent re-ACK only; a *different* verdict under the same key/digest is `APPLIED_RESULT_CONFLICT`, the first committed outcome stands.
- Replayed QUERY/RESULT_ACK: dedup-suppressed per round; new-round QUERY replays a stored RESULT without touching the app; a replayed ACK is idempotent (`acked` already set).
- `END_RECEIPT` loss: the origin's DATA rounds resend; the destination's pin replays receipt + stored RESULT. RESULT loss without QUERY: the destination's bounded emit retries cover it; RESULT_ACK loss: at most the emit budget of redundant RESULTs, each dedup'd/ACKed at the origin.
- `resume_delivery`/`persist_across_sleep`: APPLIED work does not persist across sleep in this slice (§1.10) — a settled delivery reports `Indeterminate` like any post-TX unresolved work.

## 1.6 Bounds (implemented / host-tested)

| Object | Bound | Behaviour at limit |
|---|---|---|
| user payload per APPLIED send | 112 B (128 − 16 lease) | `InvalidArgument` at `send_applied` |
| result data per verdict | 48 B | `InvalidArgument` at the sink boundary (oversize replies are refused before commit) |
| terminal result records | `kAppliedResultCapacity` = **8** (CORE_FIXED_250; the 32-record profile target is proposed, §1.10) | sweep expired → oldest `acked` → refuse admission with BUSY + `APPLIED_NO_RESULT_SLOT`; unacked in-window records are never evicted |
| record retention | 60 s from first dispatch (`kAppliedResultHoldMs`) | expiry frees the record; late QUERY then answers `NotRetained` |
| RESULT transmissions | ≤ 3 per record, spacing = `max(250 ms, hop_limit × hop_accept_timeout × 2)`, all ≤ `emit_deadline` | exhausted → `result_emits_suppressed` counter + diagnostic |
| origin QUERYs | ≤ 2 per delivery, only after END_RECEIPT | window exhausted → wait for deadline → `Indeterminate` |
| per-peer negative-answer gate | 1 / 200 ms (`kAppliedAnswerMinIntervalMs`) via `diag_budget_` | gated answers counted, not sent |
| origin tracking | existing `deliveries_` (8) | unchanged eviction of oldest terminal record |
| dedup records | existing `dedup_` (64), unchanged roles | unchanged |
| RESULT frame on the wire | ≤ 242 B | fits the 250 B ESP-NOW body |

RAM delta on `MeshNode` (host `sizeof`): `Delivery` 224 → ~312 B (×8 = +~700 B) for the stored outcome + query state; `AppliedRecord` ~136 B (×8 ≈ 1.1 KiB); total ≈ +1.8 KiB — inside the leaf-small `dedup_and_compact_receipt_records` headroom the profile already reserves for dedup/receipt records.

## 1.7 Eviction and capacity policy

`allocate_applied` order on a full pool: (a) expired records, (b) oldest `acked` record — an ACKed record's residual duty is only dedup answers, whose loss costs the origin one extra QUERY/STATUS round; (c) refuse. Uncommitted… — in the synchronous model every stored record is born committed, so the protected class is *unacked records inside their emit window*: evicting one would orphan a result the origin was promised at accept time. Refusal is pre-acceptance and explicit; protected records are never evicted to make room for newer work (same rule as dedup Terminal records in 02 §2.5).

## 1.8 Security notes

- Every APP_RESULT subtype travels end-protected: `open_end` at the receiver proves the issuer under `SecurityScope::EndToEnd`, so a relay or third party cannot inject a result, query, status or ack. Subtype-specific identity rules (RESULT/STATUS must come from `original_destination`, QUERY/ACK from `original_origin`) are enforced after open.
- `request_digest` binds a result to the exact request bytes (lease included) and header identity — a RESULT answering a *different* payload under a reused MessageKey fails verification and is counted.
- The execution lease blocks replayed cross-boot re-execution; it is deliberately not entropy — integrity comes from end authentication, the lease only sequences incarnations.
- RESULT/STATUS emission is reply-budget-bounded and gated; QUERY/ACK floods degrade to counted drops, never unbounded transmissions.
- Nothing here weakens existing checks: APPLIED DATA without `kFlagEndProtected` is dropped by the existing `END_PROTECTION_REQUIRED` rule (AppResult added to that gate).

## 1.9 Failure matrix (implemented / host-tested)

| Case | Behaviour |
|---|---|
| happy path | DATA → ACK/END_RECEIPT → app → RESULT → `Delivered "APP_APPLIED"` + ACK |
| app verdict = failure | RESULT outcome 1 → `Failed "APP_REJECTED"`, code preserved |
| no sink installed | committed `NoEndpoint` RESULT → `Failed "APP_REJECTED"` |
| stale/zero/short lease | committed `StaleLease`/`Malformed` RESULT carrying current lease → `APP_REJECTED`; origin may resend with the hinted lease |
| RESULT lost | bounded emit retry (≤3); also answered on DATA-dup replay or QUERY |
| RESULT lost + QUERYs exhausted | `Indeterminate "APP_RESULT_TIMEOUT"` at expiry |
| RESULT after timeout | stored on retained record as `late`, ACKed, surfaced; terminal state unchanged |
| malformed APP_RESULT body | decode reject → diagnostic + `malformed` counter |
| RESULT wrong issuer/dest/digest/delivery | drop + `APPLIED_RESULT_MISMATCH` diagnostic + counter |
| replayed RESULT (same/new round) | dedup / idempotent re-ACK; conflicting verdict → `APPLIED_RESULT_CONFLICT`, first outcome kept |
| QUERY for unknown/stale key | `STATUS NotRetained`/`Expired` (gate-limited); digest mismatch → drop |
| RESULT_ACK mismatch | drop + diagnostic |
| STATUS pending | extends nothing; the origin keeps waiting within its deadline |
| STATUS expired/not-retained/indeterminate (nonce-matched) | `Indeterminate "APP_RESULT_*"` |
| applied pool full at terminal | pre-acceptance BUSY + diagnostic; app never invoked |
| cancel() post-TX | `Indeterminate` (unchanged); a later RESULT still records late |

## 1.10 Deferred items (proposed — not implemented)

- **Asynchronous endpoint execution** (07 §3 `rl_report_application_result` tickets, DISPATCH_INTENT/EXECUTING durability states). The synchronous sink is the shipped contract; STATUS `Pending` exists in the codec for the future async path.
- **DURABLE_TERMINAL** records across reboot (NVS-backed request/result ledger); current semantics are RAM_ONLY — reboot loses records and the lease refuses stale replays.
- **Host surfacing**: `operations.get` `application_outcome` fields, `usb_host_ops` mapping, gateway-terminated APPLIED (`pc_service_destination`) — all explicitly Unsupported in this slice.
- **Capability advertisement** of APPLIED support to peers (e.g. via `CapabilitiesReply`); sending APPLIED to a node without the endpoint yields `NoEndpoint`, which is honest but discovered per-send.
- **32-record result profile** for relay/gateway-scale nodes (07 §5); `kAppliedResultCapacity = 8` matches the fixed-250 prototype pools.
- Hardware/HIL evidence — none exists; this is portable-core code plus host tests only.

## 1.11 Test plan and status

`tests/cpp/test_applied_delivery.cpp` (target `routeloom_applied_tests`), all **implemented / host-tested**:

1. Codec round-trips + strict rejects (wrong version/subtype/flags/length/trailing bytes) for all four bodies; digest determinism.
2. Happy path end-to-end over the sim harness: `APP_APPLIED`, result bytes/code visible via `applied_result()`, RESULT_ACK emitted, observer fired once.
3. App failure verdict → `APP_REJECTED` with the app's code.
4. No sink → `NoEndpoint` refusal → `APP_REJECTED`.
5. Stale lease → `StaleLease` refusal carrying the current lease; resend with the learned lease succeeds.
6. RESULT dropped once → QUERY recovery resolves the delivery.
7. RESULT never answered → `Indeterminate "APP_RESULT_TIMEOUT"` (never `END_RECEIVED`-promoted).
8. Late RESULT after timeout → recorded `late`, state stays `Indeterminate`.
9. DATA retransmission after terminal dispatch → single app invocation, replayed RESULT.
10. Replayed/forged RESULTs (wrong issuer, wrong digest, unknown key, conflicting verdict) → rejected/counted; first outcome stands.
11. QUERY for unknown key → `STATUS NotRetained`; RESULT_ACK mismatch → dropped.
12. Payload > 112 B refused at `send_applied`; `send()` still refuses `Applied`.
