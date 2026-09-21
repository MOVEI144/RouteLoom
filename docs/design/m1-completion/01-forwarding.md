# 1. Multi-hop forwarding

Status: **documented / proposed**, relative to [the M1 baseline](00-overview.md). Existing routing/portable transit tests are reusable evidence for those components, not evidence that this runtime integration or the six-board scenarios have passed.

## 1.1 Motivation and current connection points

A gateway or config target must be reachable through admitted neighbors without changing its identity or receipt boundary. [RouteTable](../../../components/routeloom/include/routeloom/routing.hpp) already owns 128 destinations, three candidates per destination, feasible distances, generation/sequence checks, 60-second tombstones, 500 ms failed-hop hold-down and load hysteresis. Reuse it unchanged unless an integration test exposes a defect.

[MeshNode](../../../components/routeloom/src/node.cpp) already routes DATA, Service, Control, end-protected object traffic and EndReceipt through portable handlers. [EspNowRuntime](../../../components/routeloom_espnow/src/espnow_runtime.cpp) drains RX into that node. Missing M1 contracts include operational transit eligibility, `relay_allowed`, bounded post-acceptance failure evidence, timestamped observation provenance and a runtime/bench acceptance matrix. The runtime's one-hop `send_wire()` and `migration_send()` are local-control paths and are not converted into generic forwarding.

The target wiring is:

```text
Wi-Fi RX callback → copied bounded event → Radio Owner
  → wire::open_link + identity/replay/protection checks
  → local destination: open_end → existing endpoint
  → transit: relay policy → existing RouteTable → atomic admission
       → existing TX scheduler → wire::forward → RadioPort::send
       → callback / HOP_ACCEPT / deadline → retained outcome evidence
```

There is one route table, one scheduler and one radio submission owner. No relay sends directly from a callback or creates an independent raw-send lane for DATA.

## 1.2 Exact forwarding and deadline rules

`hop_remaining` counts the link transmissions available starting with the transmission carrying that value. An origin selects `hop_limit` in 1..10. A direct transmission carries 1; A→R→B carries 2 on A→R and 1 on R→B. A relay can forward only when the received value is greater than 1. It decrements exactly once when constructing the outgoing hop; retries of that hop retain the decremented value. A final destination accepts a value in 1..10, including 1, without another decrement. M1 rejects received zero or values above 10, including the legacy codec's permissive final-hop-zero case; upgraded senders never emit them.

The runtime must pass the caller's hop limit through `send_application()`/MeshNode. One-hop neighbor controls always use 1. No flood or implicit “try all peers” fallback is allowed. `next_hop` must be local on RX, and the mapped, current binding for the observed source MAC must equal `previous_hop`. The selected next hop must be admitted, current, not self, not the incoming peer, and eligible under §1.6.

`wire::forward()` changes only the existing hop-mutable fields: previous/next hop, hop remaining, remaining deadline, link epoch/counter and link protection. Preserve origin, destination, message ID, original lifetime, type, delivery class, end epoch/counter, end ciphertext and end tag. Keep delivery round unchanged during transit; only the origin starts a new round. Its current classification as hop-mutable in Wire v1 is not permission for relays to invent rounds.

At RX, capture local time in the callback. At dispatch, subtract elapsed local residence, including RX queue, TX queue and retry waits, from the received remaining budget using saturating arithmetic. Keep a local absolute expiry; never refresh it on duplicate or route change. Existing previous-hop residence is already charged. Without synchronized clocks the field cannot exactly charge one-way time in flight: origin's original absolute deadline remains authoritative, and the implementation must document any conservative link-time debit. Config additionally enforces its target-local challenge deadline. A relay cannot extend either contract by rewriting a forwarding budget.

If the remaining budget reaches zero or a required clock interval is uncertain, stop the attempt with `DEADLINE`/`TIME_UNCERTAIN` evidence. Do not debit twice on retransmission, reset a retry budget on repair, or replace the caller's lifetime with a fresh lifetime.

## 1.3 Admission, deduplication and loops

Use existing route feasibility/tombstones as the first loop defense, immediate-back-edge exclusion as the second, bounded duplicate state as the third, and the hop/deadline bounds as the final limit. A node receiving its own origin/message back as transit rejects it as a loop against its origin record; it never creates a relay parent pointing back into that path. TTL alone does not make an unstable routing algorithm acceptable.

Extend the existing 64-entry dedup pool, rather than introducing an unbounded cache. The lookup key is `(Network implicit in node, origin, message session, message sequence, frame type, delivery round)`. Store destination, first upstream peer/binding generation and a SHA-256 fingerprint of the end-immutable header encoding plus protected payload/end tag. Exclude link counters, hop fields and remaining deadline. This detects the same key/round carrying different bytes; it is consistency evidence, not end authentication of the origin.

| Existing/new record condition | Action |
|---|---|
| New transit key | Reserve dedup/outcome record, forward TX job and upstream ACK capacity as one admission unit; then commit and emit HOP_ACCEPT |
| Same key, same fingerprint, same upstream; pending or next hop accepted | Re-ACK the same bounded acceptance; never enqueue a second forward job |
| Same key, same fingerprint, different upstream | Treat as convergence/possible loop; refuse this additional parent with `DUPLICATE_PATH`. Do not replace the original reverse path or create another forward |
| Same key, different fingerprint/destination | `MESSAGE_CONFLICT`; never re-ACK as accepted |
| Same key after known transit failure | Re-emit retained failure evidence; never blindly re-ACK a dead job as newly accepted |
| New origin round, same logical message | May be admitted within original lifetime; terminal DATA dedup remains across rounds, and endpoint transaction/object dedup retains its own semantics |
| Pool full | Refuse before acceptance; BUSY if reply capacity exists, otherwise count refusal and allow upstream timeout |

Keep records for the original local expiry plus a 30-second late-evidence interval, capped at 60 seconds from first admission for the M1 lifetime cap of 30 seconds. Duplicates do not extend retention. Active/retained records cannot be evicted by LRU to accept new work. At the terminal, application/Config/Gateway result retention remains its existing, separate contract; Config retains eight results for at least 300 seconds. No general exactly-once claim follows from a finite frame cache.

Raw replay rejection occurs before this lookup; tests must distinguish a replayed link counter from a legitimate SDK retransmission with an admissible link counter. Any retransmission/re-ACK behavior must satisfy the existing security provider's replay contract.

## 1.4 ACKs and failure honesty

| Evidence | Meaning | What it does not prove |
|---|---|---|
| `esp_now_send()` accepted | Driver took the attempt | MAC delivery or neighbor acceptance |
| TX callback success | Driver reports MAC-layer success for this attempt | Application receipt, end-to-end delivery, permit validity |
| HOP_ACCEPT | Immediate receiver reserved responsibility for this frame | Any later hop or target success |
| EndReceipt | Addressed DATA endpoint's existing receipt boundary | Application side effects or durable Host storage |
| Service receipt | Named gateway and explicitly requested scope accepted | Another gateway or stronger persistence scope |
| ObjectAck Ok | Object assembled under existing object transport semantics | Signature acceptance, journal decision or apply |
| Config Status ACTIVE | Target journal reports verified active revision/hash | Fleet-wide success |

BUSY remains strictly **pre-acceptance** and one-hop. A later failure must not send BUSY to retract an earlier HOP_ACCEPT. Add `TransitFailure` as the bounded one-hop diagnostic defined in [§4.2](04-cross-cutting.md). Correlate it against a retained job using the reference key/type/round/destination/fingerprint and the actual downstream peer/binding. The relay propagates a newly link-authenticated report to its retained upstream peer. Keep the original reporting node as an explicitly unverified claim; the receiver has authenticated only the immediate reporting neighbor. There is no end-to-end signature on this failure chain.

Each retained record sends at most one report per state transition, and one repeat on an upstream duplicate, limited to two reports/second per peer and one repeat/second per record. Reports have a 3-second local budget, no HOP_ACCEPT, no reply-to-error, and no independent route lookup. A chain traverses only remembered parents of the referenced attempt; duplicate reports do not recursively create reports. Reject late, unmatched, wrong-round or wrong-peer evidence. Expired breadcrumbs cause `failure_unreportable`, not new allocation or an assumed delivery failure at the origin.

| Failure | Local evidence and upstream behavior | Origin result |
|---|---|---|
| Invalid length/type/link auth/replay or unknown binding | Reject, rate-limited diagnostic and saturating counter; no reply to unauthenticated traffic | No authenticated acceptance; bounded retry/timeout |
| Relay disabled, hop exhausted, no feasible route, backward next hop | Before-accept report if authenticatable and capacity permits; otherwise local reason counter | Attempt reason if report arrives; retry within original budgets, else expiry |
| Scheduler/dedup/peer capacity | Pre-accept BUSY, or explicit unsent-reply counter | BUSY/backoff or hop timeout; never accepted-success |
| After acceptance: neighbor removed, retries exhausted, counter allocation/security failure | Retained failed state plus post-accept report chain and local diagnostic | Failure evidence is advisory; outcome may be unknown, not “target definitely did nothing” |
| Callback missing/overflow/fenced | Mark attempt unknown; completion accounting in telemetry doc | No fabricated MAC failure or success; eventual terminal evidence or deadline |
| Final endpoint rejects signature/schema/apply | Existing endpoint Config/Service reason, end-protected when a response is possible | Preserve endpoint reason; do not translate into routing success |
| Relay power loss or reverse path gone | No report can be guaranteed | Original deadline always produces a terminal local result |
| Terminal receipt lost | Target may already have accepted/applied | `Indeterminate` when effect/delivery is possible; query Config status by original operation ID |

The origin retains `last_evidence` (none/driver/hop/terminal), last authenticated reporting neighbor, claimed failing node, reason, round and elapsed budget. Intermediate reports can accelerate a bounded new origin round or route repair, but cannot certify end-to-end non-delivery. Only locally proven pre-transmit cancellation/refusal may claim no transmission. A final timeout after any possible send is exposed as unknown delivery/effect with a deadline cause. BestEffort may retain its existing `TX_MAC_DONE` boundary but must display that boundary explicitly; never relabel it end-to-end delivered.

“No silent drop” means every accepted operation has a bounded terminal observation at its origin and every local refusal/loss has retained counters/evidence. It cannot mean guaranteed delivery of a failure packet through a partition or a crashed relay. Diagnostic queue loss itself increments a persistent-in-boot counter; RF diagnostics are not a durable audit log.

## 1.5 Scheduler and traffic fairness

Reuse the existing 32-job TX pool, eight reserved control-lane slots and eight awaiting-hop slots. These are actual core constants, distinct from older abstract resource-profile estimates. Forwarded and self-originated traffic share the same class weights (Management/Urgent/Normal/Bulk = 4/8/4/1), peer windows 1..4 and flow descriptors. Attribute transit quotas to the authenticated upstream scope **and** claimed origin/destination; an origin field does not prove a principal.

Reserve two of the 24 non-control admission positions for locally originated work while it is waiting; cap admitted transit non-control jobs at 22. Unused slots are not an entitlement to evict accepted work. DRR rotates within class and across flows so one upstream cannot monopolize it. Management is rate-limited; a permit's nine chunks do not all enter an urgent FIFO. Control reservations cover ACK/BUSY/failure reports but remain finite. Under control saturation, suppress periodic telemetry/probes first and count suppressed evidence.

Retain RF attempts ≤2, BUSY readmissions ≤4, combined physical submissions ≤6 and origin rounds ≤3. A next-hop change does not reset those counters. Queue watermark 50% reduces background work; 80% suspends bulk/improvement probes. No queued accepted reliable frame is discarded just to lower a watermark.

An in-flight send pins the peer binding through callback resolution. The existing reserved DATA completion and bounded raw-send bookkeeping must preserve attribution per MAC and radio generation. All new diagnostic TX uses the same Owner arbitration. Sleep tickets include accepted transit, queued replies, retained pending completions and crypto work; an active relay cannot sleep merely because its application queue is empty.

## 1.6 Relay policy, routes and compatibility

Effective transit permission is `build_support && runtime_enable && relay_allowed && membership_valid && !draining`. Expose configured and effective values separately. Both firmware apps use this policy. Compile-disabled firmware accepts a false config value but rejects a request to set true as `UNSUPPORTED`; it does not journal ACTIVE for unavailable behavior.

Add Owner commands to query/set effective relay policy and to drain transit. Turning relay off first stops new admission and withdraws non-self advertised routes, while already accepted transit/replies finish within their original deadlines. The config provider reports APPLYING until drain completes and readback confirms the gate. If its apply deadline cannot accommodate drain, reject during prepare or report the actual interrupted outcome; never clear queues and claim success. New data cannot extend drain. Maintenance checks must account for removal of the management path; retain local status recovery when the remote return path disappears.

A leaf still advertises its own reachable identity and handles final-destination traffic. It does not advertise paths through itself. Old peers or peers without authenticated current `forward_v1` capability are eligible as directly attached final destinations only. Do not accept/advertise their routes to other destinations. Every new relay applies that rule recursively; therefore old endpoints can sit at the edge without being mistaken for transit nodes. Capability expiration/reboot or disabling relay withdraws affected transit routes without deleting feasibility tombstones. Re-enabling requires a current binding/capability exchange and fresh route evidence.

The nonce-bound capability exchange in [§4.2](04-cross-cutting.md) leaves RouteUpdate and RLD1 layouts unchanged. A configured inventory can opt into M1 probing; a missing response means unsupported/unknown, never “legacy probably forwards”. Capability to forward includes failure-evidence support. `CONFIG_ROUTELOOM_FORWARDING=n` advertises no transit capability. Already-deployed single-hop endpoints continue to use their old payloads and security profile.

## 1.7 API, host and resource deltas

Proposed portable additions: `RelayPolicy`, bounded `TransitOutcome`, policy/drain accessors, observation timestamps/generations, and observer events with structured evidence. `RadioPort` retains a single submission contract. Do not make a caller-provided boolean an authentication proof. New C ABI exposure needs size/versioned structures in the implementation change; this document does not silently modify today's ABI.

The daemon adds evidence fields to operation inspection and structured diagnostics, preserving message IDs and original deadlines. `routeloomctl` shows hop limit, effective relay policy, attempt/round counts, terminal boundary and unknown outcomes. Diagnostic failure hints cannot complete Config as ACTIVE. Gateway Host ingress still means actual ReceiveLog admission, not a relay's receipt.

| Incremental resource | Planning allowance, not measurement |
|---|---:|
| Extra reverse-path/fingerprint/outcome fields in 64 dedup records | 64 × ≤80 B = 5 KiB |
| Policy/capability peer state, failure scheduling and counters | ≤3 KiB |
| Scratch and alignment margin | ≤4 KiB; no object reassembly on relays |
| Stack | ≤1.5 KiB extra peak on existing 8 KiB Owner; no recursion |
| Flash | 12–24 KiB over baseline, excluding already-linked routing/link crypto |

Per forwarded maximum frame, expect one link open, one link seal and one bounded fingerprint hash; **zero public-key permit verifies** and zero 1024-byte permit buffers. Budget CPU service ≤5 ms per maximum frame on C3, measured separately from queue wait, RF time and ACKs. This is a performance gate to measure, not an asserted benchmark. Nine permit chunks multiply forwarding work and air traffic, not relay crypto workspace. Capacity failure remains explicit if the actual structure sizes exceed this proposal.

## 1.8 Tests and allowed claims

Host tests must use the actual MeshNode/Owner adapter seams: 1/2/10/0 hop boundaries; lost route and loop/diamond convergence; deadline debit through RX/TX queue; ACK lost before/after admission; same key changed bytes; duplicate arriving from a different parent; later origin rounds; pool/control exhaustion; late failure reports; peer rebinding; callback loss; power drain and relay-off during Config. Assert no extra terminal delivery, no new permit apply, no premature HOP_ACCEPT, bounded retries, and a terminal origin result even when every report is lost. Golden tests cover old/new capability and failure payloads and preserve all existing DATA/Service/Config encodings.

| Six-board case | Required observation |
|---|---|
| F1 — pair, two-link, three-link, five-link chains | 100 reliable messages per topology, 0/1/128 B payloads; every accepted operation terminal within requested lifetime; exact hop decrement and receipt boundary in traces |
| F2 — diamond, cut primary relay after HOP_ACCEPT | Alternative obeys feasibility/holds; no duplicate application delivery; origin sees explicit reason or deadline unknown |
| F3 — relay off/config drain and relay power cycle | No newly accepted transit after gate; accepted work drains or expires honestly; no false ACTIVE while gate remains on |
| F4 — S3-D competing origin plus maximum permit to C3-B | Own and transit traffic both progress below overload; at overload finite BUSY/refusals; no starvation hidden by unbounded queues |
| F5 — C3 relay role and old firmware at an edge | Same bounded behavior on C3; old node never selected as transit; direct legacy DATA/dev config still works |
| F6 — lost reverse receipts, callback fault injection and full dedup | No success fabricated; recorded unknowns, counters and origin expiry account for every accepted operation |

For timing/fairness, record offered load and queue delay distributions; a successful low-load chain is not a network capacity claim. The allowed result is scoped **C3/S3 multi-hop hardware-tested at named load/topology/security profile**. It is not RF range, adversarial routing security, persistent delivery, ten-hop qualification or C5 hardware evidence.
