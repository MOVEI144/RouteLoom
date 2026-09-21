# 0. M1 completion — integrated design

Design version **0.1-draft / 2026-09-21**. Baseline: branch `design/m1-completion`, SHA `fbde7963a5b9261d331514fe4729ac53bdb230c0`. This set is **documented only**. It proposes implementation contracts; it does not change code, registrations, default configuration, or existing qualification records.

## 0.1 Scope and evidence boundary

M1 connects three capabilities: bounded multi-hop delivery, observations from the real radio, and asymmetric authorization of small configuration permits. They share the Radio Owner, scheduler, security contexts, configuration journal, and diagnostics. They must be tested together because forwarding creates additional load, signature verification consumes target CPU, and telemetry must distinguish both from RF loss.

| Baseline accepted for this design | M1 work |
|---|---|
| Discovery scope HMAC tags and rotation, explicit gateway delivery, challenge → dev-HMAC permit → apply → journal are implemented and host-tested; the task supplies a successful two-C3 bench baseline | Preserve these flows and their acceptance boundaries. Exercise them over relay paths; do not redesign their semantics |
| The routing engine exists, including feasibility, metrics, hysteresis, tombstones and next-hop selection | Integrate its existing transit machinery with runtime policy, operational evidence, relay configuration and mixed-version behavior |
| Operational hardware baseline is single-hop | Establish separately evidenced two-, three- and five-link forwarding on six boards |
| Development permits use a shared HMAC key and remain explicitly experimental | Add an explicitly selected COSE/ESP256 verifier and issuer profile alongside development mode |
| Congestion, sleep tickets and AutoGuarded have portable implementations using injected observations | Supply bounded, provenance-labelled real observations; keep unavailable preconditions false |

Source nuance matters: [runtime](../../../components/routeloom_espnow/src/espnow_runtime.cpp) `poll_once()` already calls `MeshNode::on_radio_receive()`, and [node.cpp](../../../components/routeloom/src/node.cpp) contains `handle_data`, `handle_routed`, `handle_end_receipt` and `queue_forward`. The explicit runtime `hop_remaining=1` assignments belong to neighbor/autonomy and migration sends. Those assignments must remain one-hop. M1 is not a new routing algorithm or a second forwarding loop in the Wi-Fi callback. Existing portable code does not constitute multi-hop runtime acceptance or RF evidence. The task's single-hop deployment baseline remains the acceptance starting point.

Earlier design documents have older maturity snapshots. The two-board evidence supplied with this task is accepted as a baseline statement, not re-run or expanded here. This set does not amend those historical records.

## 0.2 Reading order and decisions

1. [Forwarding](01-forwarding.md): transit ownership, hop budgets, ACKs, failure evidence and relay policy.
2. [Telemetry](02-telemetry.md): actual callback observations, aggregation and host reporting.
3. [Signing](03-signing.md): algorithm choice, fixed permit shape, provisioning and verifier isolation.
4. [Cross-cutting contracts](04-cross-cutting.md): exact shared wire additions, interaction matrix, sizes and compatibility.

The design retains Wire v1's 88-byte header, 128-byte payload and 16-byte link/end tags. No telemetry is appended to DATA, Service, RCC1 or object chunks. New diagnostic messages use already allocated Wire type 48 with explicit subtypes and protection classes. New numbers in this set are **proposals**, not registrations in `contracts.json` or implemented capabilities.

A relay authenticates its immediate neighbor and rewraps the unchanged end-protected bytes. Only the addressed target reconstructs and verifies a permit. A hop acceptance, a MAC callback, an assembled object, an endpoint receipt and `Status ACTIVE` remain distinct evidence.

## 0.3 Goals and non-goals

M1 must deliver or terminate every locally accepted operation within its original deadline, expose the strongest available evidence, remain bounded under overload, and work with an explicitly identified security profile. A lost failure report produces an honest timeout/unknown outcome, never inferred success or a claim that the target definitely did nothing.

Non-goals: new discovery semantics; arbitrary command execution; OTA; mesh flooding; anycast; synchronized sleeping relays; radio changes outside the existing Owner; larger ESP-NOW v2 frames; a new identity/key-exchange protocol; automatic fleet trust-root distribution; 100-node/10-hop qualification; RF range or regulatory certification. The existing production identity design remains a separate dependency for production deployment, not something a permit signature implements.

The C3/S3/C5 SDK target set remains. The requested bench has **two C3 and four S3 boards** and therefore cannot establish C5 hardware-tested status.

## 0.4 Dependency order

| Stage | Deliverable before moving on | Dependencies and permitted interim behavior |
|---|---|---|
| D0 — freeze contracts | Review this set, reconcile proposed diagnostic/USB IDs, golden byte fixtures and ownership invariants | No implementation or maturity promotion in this change |
| D1 — measurement and capability boundary | Callback timestamps/validity/generations, reliable completion accounting, authenticated M1 capability exchange, structured diagnostics | Local telemetry can land with forwarding disabled. No measured-RF claim from host injection |
| D2 — bounded transit | Relay gate, eligible route advertisement, admission/dedup/outcome records, fair scheduling, end-to-end deadline evidence | Existing dev transport/permits allowed in an explicitly experimental bench profile; nominal route metrics remain a supported mode |
| D3 — asymmetric target/issuer | Fixed COSE shape, real verifier, key policy/store, async completion and durable issuer bytes | Can land on one hop before D2. Requires a pinned crypto capability/size/timing probe on C3, not a guessed benchmark |
| D4 — integrated acceptance | Host tests, C3/S3/C5 build tests and all six-board scenarios from the three item docs | Forwarding, callback load and target verification must run simultaneously |
| D5 — deployment qualification | Identity/security review, actual provisioning/revocation operations, C5 RF evidence and deployment-specific RF/scale/power work | Separate from M1 engineering completion; no automatic production or qualified label |

Metric coupling follows D1 validity checks. AutoGuarded remains opt-in and blocked until **all** existing preconditions are backed by current evidence. D2 or D3 alone does not authorize automatic channel changes. Missing channel-plan signing is not supplied by a config-permit signer.

## 0.5 Configuration and bounded ownership

Proposed build gates are `CONFIG_ROUTELOOM_FORWARDING`, `CONFIG_ROUTELOOM_RF_TELEMETRY`, `CONFIG_ROUTELOOM_CONFIG_COSE_P256` and explicit `CONFIG_ROUTELOOM_CONFIG_DEV_HMAC`. Existing feature defaults are not changed here. Production permit policy excludes development acceptance even if a development component was accidentally linked. Selection is provisioned policy, not opportunistic verification fallback.

`relay_allowed` becomes a real Owner-controlled transit gate, with drain semantics in [§1.6](01-forwarding.md). Compile-disabled forwarding cannot be enabled by remote config. Self-originated traffic, final-destination delivery and neighbor control remain available on leaves.

Portable state machines use fixed pools and no heap or FreeRTOS types. Callbacks copy bounded metadata and enqueue events; they do not route, verify signatures, write flash, parse JSON or invoke applications. IDF-specific task and crypto storage is statically bounded and separately measured. A backend with unbounded internal allocation does not satisfy this design merely because the C++ wrapper uses no `new`.

| Increment over the same baseline firmware | Planned RAM reservation | Flash estimate | Measurement condition |
|---|---:|---:|---|
| Forwarding policy/evidence | ≤12 KiB, existing 8 KiB Owner stack retained | 12–24 KiB | Includes expanded dedup/outcome state; does not allocate a second route or TX table |
| Telemetry/diagnostics | ≤6 KiB | 8–16 KiB | Eight detailed observation buckets, 19 peer summaries, callback metadata and one snapshot |
| ESP256 target verifier | ≤36 KiB, including 24 KiB arena and 8 KiB worker stack | 32–80 KiB if ECC newly linked | Target only; reused P-256 backend may cost less |
| Combined target + relay | **≤54 KiB incremental planning ceiling** | **52–120 KiB additive estimate** | Not a total firmware size, not a measured C3 fit, not additive if some crypto code already exists |

Measure against [existing resource profiles](../../reference/resource-profiles.json), including IDF/Wi-Fi, both application types, existing config buffers, and existing production security scratch if linked. Do not double-count a shared arena as free memory. Do not claim the older relay-C3 total budget is met from these incremental figures. C3 gates include ≥32 KiB free internal heap and ≥16 KiB largest free internal block under combined peak load, plus ≥25% unused task stack. Failure requires a reviewed budget/implementation change, not a silent cap increase or PSRAM assumption.

## 0.6 Six-board acceptance fixture

Name boards C3-A, C3-B, S3-A through S3-D; record exact module revisions, MACs, firmware SHA, IDF SHA, sdkconfig, channel, LR250 rate and approved RF profile. Use C3-A as USB origin/bridge, C3-B as permit target, S3-A/B as primary relays, S3-C as alternate relay and S3-D as competing origin/observer. Repeat with a C3 acting as relay and an S3 as target.

Fixtures: direct pair; two-link chain; three-link chain with alternate path; six-node/five-link chain; diamond with competing traffic; mixed old/new firmware. A software neighbor allowlist can establish a logical topology, but proves only topology-controlled RF forwarding. For an actual no-direct-path claim, use measured attenuation/shielding and a direct-link negative control. Do not infer a forced RF path from deskside placement.

Store message keys, local monotonic times/boot IDs, route selections, callbacks, ACKs, terminal receipts, journal phases, queue high watermarks, drops, crypto elapsed time and stack/arena peaks. Cross-board latency requires clock mapping with uncertainty; local elapsed measurements do not. Archive raw traces and a machine-readable verdict per scenario. All tests described here are **planned**, not executed by writing the documents.

## 0.7 What “M1 complete” means

| Label | Evidence required for each feature |
|---|---|
| documented | Reviewed contracts, bounds, failure semantics and test cases; this deliverable reaches only the design stage |
| implemented | Code and host integration exist under explicit guards, including refusal/error paths |
| host-tested | Executed deterministic state-machine, real-signature and C++/Rust wire tests, with SHA and results |
| build-tested | Both firmware applications, C3/S3/C5, feature ON/OFF and asymmetric/development configurations; size artifacts |
| hardware-tested | Executed six-board C3/S3 scenarios, including combined stress and fault cases, with traces and resource measurements |
| qualified | Separate deployment security, RF, scale, longevity and recovery criteria satisfied for named hardware/configuration |

**M1 engineering complete** requires implemented + host-tested + build-tested for all three items and the scoped six-board hardware-tested evidence. It allows “multi-hop C3/S3 bench tested”, “callback-derived RF observations” and “asymmetric permit profile tested with provisioned test keys”. It does not allow “production-secure mesh”, “RF-qualified”, “C5 hardware-tested”, or “100 nodes / 10 hops validated”. Failed or unrun acceptance cases stay explicit. The open measurement and operational decisions are collected in [§4.7](04-cross-cutting.md).
