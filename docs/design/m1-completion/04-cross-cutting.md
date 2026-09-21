# 4. Shared contracts, interactions and acceptance decisions

This is the shared wire/resource decision record for [M1](00-overview.md). All additions are **proposed**, with no registration or implementation claim. Reconcile the numbers against the implementation branch before adding codecs; do not edit existing `contracts.json` as part of this document-only task.

## 4.1 Authentication at each boundary

| Boundary | Required check | Evidence / work that is deliberately absent |
|---|---|---|
| Discovery scope | Existing neighbor-local scope MAC/generation policy | Not membership, identity, permit authorization or a multi-hop scope proof |
| Relay RX | Wire shape, Network, destination/next-hop, actual previous-hop binding, link AEAD and replay; current admission and relay policy | No `open_end`, no permit parsing, no signature verification; claimed original sender remains unverified at the relay |
| Relay TX | Existing feasible next hop, bounded lifetime/hop budget, new link counter and link AEAD | End ciphertext/tag and signed permit fragments unchanged |
| Config target transport | End AEAD bound to actual origin and target; valid manifest/chunks/hash and quotas | Origin's right to transport a permit does not itself authorize config |
| Config target authorization | Fixed COSE profile, actual signature and key policy, RCC1 context/challenge/sequence/revision/hash, journal/provider rules | Link acceptance, assembler ACK or capability bit cannot substitute |
| Intermediate failure chain | Authenticate immediate reporting peer and correlate retained job | Claimed remote reporting node is not end-authenticated; report is a routing hint, not proof of target state |
| Remote telemetry | End-authenticated named observer plus sample provenance/freshness | A relay cannot append “measured RSSI” for another node or grant independent-observer status |

Pairwise link contexts and origin-to-terminal end contexts are separate requirements. A routing path does not establish an end context. Missing context returns an explicit security-unavailable failure. The existing production identity design must supply authenticated context establishment for a production deployment; the experimental shared-key bench must still report its actual transport profile.

Forwarding costs one link open + one link seal + bounded consistency hash per frame, no public-key operations. The [forwarding budget](01-forwarding.md) is ≤12 KiB incremental RAM, 12–24 KiB flash and ≤5 ms proposed C3 CPU service per maximum frame. Target verification adds the [signing budget](03-signing.md) once per assembled permit. A relay that is itself the target of a different command must budget both roles. Wi-Fi receive callbacks perform neither kind of crypto.

## 4.2 Exact wire/API additions and compatibility

All integers below are big-endian; reserved fields/unknown flags are zero; lengths are exact and trailing bytes are rejected. The unchanged Wire v1 header remains 88 bytes, payload≤128, link tag16 and optional end tag16. No reserved Wire header byte or new flag is repurposed. RLD1 and RouteUpdate shapes are unchanged.

Use already allocated **FrameType Diagnostic=48**. New body prefix is `version:u8=1 / subtype:u8 / flags:u16=0`. Dispatch first on outer protection class and address, then on subtype. Relays of end-protected diagnostics cannot read the subtype; they forward that type under the same bounded policy as other end-protected traffic. The terminal rejects subtype/protection mismatches. A failed protected parse never falls through to a link-only parser.

| Subtype | Protection and delivery | Body after 4-byte prefix | Total payload / ESP-NOW body |
|---|---|---|---:|
| 1 CapabilitiesQuery | Link-only, immediate peer, hop=1, BestEffort | nonce16 / reserved4 | 24 / 128 B |
| 2 CapabilitiesReply | Link-only, immediate peer, hop=1, BestEffort | echo_nonce16 / node_boot8 / features4 / permit_profiles4 / valid_for_ms4 | 40 / 144 B |
| 3 TelemetryQuery | Link+end, named observer, Reliable | request_id4 / peer8 / direction1 / length_class1 / reserved2 / max_age_ms4 | 24 / 144 B |
| 4 TelemetrySnapshot | Link+end, requester, Reliable | Fixed record below | 128 / 248 B |
| 5 TransitFailure | Link-only, immediate retained parent, hop=1, BestEffort | Fixed record below | 80 / 184 B |
| 6 DiagnosticReject | Link+end, requester, Reliable | request_id4 / reason2 / reserved2 / observer8 / detail4 | 24 / 144 B |

Subtype6 reasons: 1 UNSUPPORTED, 2 CAPACITY, 3 STALE, 4 NO_PEER, 5 NO_BUCKET, 6 DENIED, 7 DEADLINE; detail is zero in v1. It responds only to an authenticated query, never to a report or reject. A summary with no detailed bucket may instead use subtype4 with detailed-valid clear. A query's original deadline bounds its response; no response starts a fresh operation lifetime. If return context/route/capacity is absent, retain a counter and let the query timeout.

Capabilities: `features` bit0=`forward_v1`, bit1=`local_telemetry_v1`, bit2=`transit_failure_v1`, bit3=`remote_telemetry_v1`, bit4=`busy_v1`; other bits zero. `forward_v1` implies bits2/4 and current effective relay permission. Feed authenticated bit4 into the existing `set_peer_busy_capable` gate; old peers without BUSY evidence are not sent an assumed-supported BUSY. `permit_profiles` bit0=dev-HMAC, bit1=RLCP1_COSE_ESP256; advertise only configured **accepted** profiles with ready providers, not every compiled algorithm. A target with no config endpoint advertises zero. This is independent of USB config capability bit4.

M1 permit policy selects one profile globally, so `permit_profiles` is zero or one of those single bits, never both. `node_boot`/`observer_boot` use the same nonzero per-boot u64 incarnation as the node's diagnostic identity (distinct from the message-session u32); reset changes it and invalidates retained capability/sample state. It is correlation metadata, not a credential.

The query uses an unpredictable nonzero 128-bit nonce, one pending query per peer; response must echo it under the current link binding. Bind the reply to that peer's incarnation and binding generation, retain for at most 15 seconds, renew at most once per 5 seconds, and invalidate immediately on reboot/rebind/policy change. Reject zero boot/invalid validity; cap accepted validity at 15 seconds. Unsolicited stale replies do not grant capability. Initial probing is bounded to configured M1 candidates or admitted peers; old firmware may diagnose an unsupported type and fail to reply. Timeout yields unknown capability. Authentication does not make an adversarial admitted node's capability assertion truthful.

TelemetrySnapshot layout:

| Offset | Field | Bytes / semantics |
|---:|---|---|
| 0 | version / subtype4 / flags0 | 4 |
| 4 | request_id | 4, nonzero query correlation |
| 8 | observer / observer_boot / peer | 8 + 8 + 8 |
| 32 | binding_generation / radio_generation / channel_epoch | 4 + 4 + 4 |
| 44 | channel / direction / length_class / validity | 1 + 1 + 1 + 1 |
| 48 | sampled_at_ms | 8, observer's monotonic clock |
| 56 | window_ms / sample_age_ms | 4 + 4, at serialization time |
| 64 | rssi_last / rssi_min / rssi_max / reserved0 | signed i8 + i8 + i8 + u8 |
| 68 | rssi_ewma_q8_8 / reserved0 | signed i16 + u16 |
| 72 | rssi_samples | u32 |
| 76 | tx_submitted / tx_mac_success / tx_mac_fail / tx_unknown | 4 × u32 |
| 92 | sdk_retries / hop_accepts / hop_timeouts / busy | 4 × u32 |
| 108 | queue_us_ewma / driver_us_ewma / hop_rtt_us_ewma | 3 × u32 |
| 120 | event_drops / saturation_mask | u32 + u32 |

This totals **128 bytes**. Direction0=egress, 1=ingress. Length class0/1/2 uses the existing size classes; 255 selects a peer summary without detailed fields. Query requires a nonzero peer, direction0/1, class0..2 or255 and max_age≤3000 ms (zero means latest available, still explicitly stale if old). Exact field offsets are authoritative in this set.

A nonzero requested max_age that cannot be met returns DiagnosticReject STALE. An ingress record does not claim egress TX/RTT fields; those fields become host null. A query can request the latest peer summary to inspect sparse RSSI without claiming that a usable route metric exists.

Validity bits: 0 RSSI present, 1 detailed bucket present, 2 driver-service EWMA present, 3 unambiguous hop-RTT EWMA present, 4 samples from LocalDriver, 5 samples from InjectedTest, 6 window incomplete, 7 stale. Bits4/5 are mutually exclusive. For remote data, the host additionally labels transport provenance AuthenticatedRemoteReport; it preserves original sample source. Unknown numeric fields encode zero with validity clear and become host `null`. Source lacking a detailed bucket sets class255 and detailed fields to zero. `sample_age_ms` is age of the oldest contributing *current-window* sample (RSSI last sample for summary-only); a missing/unknown age uses UINT32_MAX with stale set. This timestamp does not claim all lifetime counts occurred in that window.

Counters from offset72 through104 and event_drops are saturating lifetime u32 totals for the current boot/binding/bucket identity. Saturation mask bits0..8 correspond in order to rssi_samples, tx_submitted, tx_mac_success, tx_mac_fail, tx_unknown, sdk_retries, hop_accepts, hop_timeouts, busy; bit9=event_drops, bit10=time/EWMA encoding saturation; others zero. Device-global event_drops is repeated as a global gap indicator, never summed across peers. RSSI summarizes that peer across frame sizes; other detailed fields follow the requested bucket. Observation completeness for control is enforced locally from richer bounded state, not inferred by treating this diagnostic snapshot as a full migration authorization object.

TransitFailure layout:

| Offset | Field | Bytes / rule |
|---:|---|---|
| 0 | version / subtype5 / flags0 | 4 |
| 4 | referenced_origin / session / sequence | 8 + 4 + 8 |
| 24 | referenced_destination | 8 |
| 32 | referenced_type / round / phase / reason | 1 + 1 + 1 + 1 |
| 36 | claimed_reporting_node / report_id | 8 + 4 |
| 48 | referenced_fingerprint | 32 |

Phase0=refused before local acceptance, 1=failed after local acceptance, 2=attempt outcome unknown. Reasons: 1 RELAY_DISABLED, 2 HOP_EXHAUSTED, 3 NO_ROUTE, 4 DUPLICATE_PATH, 5 MESSAGE_CONFLICT, 6 RETRY_EXHAUSTED, 7 DEADLINE, 8 PEER_GONE, 9 SECURITY_UNAVAILABLE, 10 CALLBACK_UNKNOWN, 11 TIME_UNCERTAIN. Capacity before acceptance uses existing BUSY rather than redefining it. Unknown values are rejected. `report_id` is a per-reporting-boot monotonically increasing nonzero u32; stop reports on wrap until a new binding/boot. Receiver also dedups the reference/phase/reason so a different report ID cannot restart work.

Fingerprint input is ASCII `RouteLoom/transit-fingerprint/v1` + NUL + the existing exact end-AAD encoding used by `wire.cpp` + protected payload including its end tag. It excludes hop-mutable fields. This requires no new crypto primitive beyond SHA-256 already used for objects. The outer Network scopes the reference. Each propagating relay creates a fresh link-only header, preserves the reference/claimed reporter/report ID, and sends only to the record's original upstream. Parent records, lifetimes and per-record suppression bound propagation; no ACK or negative reply is sent for subtype5. Late or uncorrelated reports cannot cancel an unrelated operation.

Add type48 to the existing routed-type/HOP_ACCEPT allowlists **only for the new end-protected diagnostic lane**. HOP_ACCEPT body remains22 bytes, outer link-only frame126 bytes. Capability/failure packets are BestEffort and never require a HOP_ACCEPT. This is a codec/dispatch change, even though numeric type48 already exists; old firmware supporting Wire v1 does not thereby support this design.

USB proposal: retain FrameKind Diagnostic33 reason-event bytes. Add Hello capability bit5 `m1_diagnostics_v1`, bound to the authenticated Hello transcript and advertised only with the handler attached. Under existing HostOps19 schema1 add sub0x30 `DiagnosticRequest`: `observer:u64 || query_body:24` (32-byte payload; 36 with inner header). It accepts a local CapabilitiesQuery or local/remote TelemetryQuery; link-only capability discovery is not tunneled as a remote mesh query. A remote target's permit profile therefore requires managed inventory or separately obtained authenticated capability evidence. Sub0x31 `DiagnosticResponse` is `result:u16 || observer:u64 || body_len:u16 || body`, body=CapabilitiesReply40, Snapshot128, Reject24 or empty on local failure. Maximum payload140/inner144 bytes. Existing result codes, USB request/session correlation and credit rules apply; no unnegotiated push. Request IDs in diagnostic bodies correlate remote responses and cannot alias a new USB session. Unknown capability/op returns Unsupported. A credit timeout expires the query and increments lost-snapshot evidence.

## 4.3 Frame, transfer and airtime arithmetic

The existing body budget is `88 + 16 + 16 + 128 = 248 ≤ 250`; the spare two bytes are not an extension mechanism. ESP-NOW v2's larger packet allowance is not used. [Espressif's pinned header](https://raw.githubusercontent.com/espressif/esp-idf/v6.0.3/components/esp_wifi/include/esp_now.h) distinguishes 250-byte v1 from larger v2 frames; deployed compatibility is why this design stays within 250.

For an object of length L and 90-byte chunks, `N=ceil(L/90)`. Request-direction RouteLoom bytes per path edge are `158 + 158N + L`: a manifest and N chunks, each with its envelope. This excludes challenge/status traffic, retransmissions and intermediate object ACKs. Assume just one final 157-byte ObjectAck, and one 126-byte HOP_ACCEPT for each reliable frame including that ACK.

| Maximum envelope | Chunks | Request bytes/edge | Object exchange bytes/edge including final ObjectAck and 11 hop accepts | Successful frame transmissions over H edges |
|---|---:|---:|---:|---:|
| dev749 | 9 | 2,329 | 3,872 | 22H |
| COSE774 | 9 | 2,354 | 3,897 | 22H |
| future cap1024 | 12 | 3,078 | 4,999 (14 hop accepts) | 28H |

Thus COSE adds **25H bytes** in this no-loss comparison, with the same nine-chunk count as the maximum dev permit. On a three-edge path the minimal object exchange is 66 transmissions; on five edges, 110. Any actual assembler per-chunk ACK, route control, challenge, Status or retry increases these lower-bound counts. RCC1's contents are not independently rechunked or re-signed at a relay; the entire envelope digest identifies one object.

At 250 kbit/s, serializing a 248-byte RouteLoom body alone is `248×8/250000 = 7.936 ms`. The COSE table's 3,897 bytes correspond to 124.704 ms of **body-bit serialization per edge**, or 623.52 ms summed over five edges. These are arithmetic lower bounds, not PHY airtime or end-to-end latency: MAC headers, vendor elements, preamble, CCA, turnarounds, internal retries, ACK scheduling, contention and target processing are absent. The 10-second reassembly bound and separate target-local challenge bound (at most 30 seconds) remain enforceable admission/deadline limits, not promises that five-hop completion always fits.

A remote telemetry query plus snapshot costs at least 144+248 bytes and two hop accepts126 per edge = **644 bytes/edge**, four transmissions/edge, excluding retries. Its bounded polling rate and background priority are therefore material. No piggyback bytes compete with the 90-byte chunk or 128-byte data limits. A failure report costs184 bytes per reported reverse edge; reporting floods are bounded by §1.4.

## 4.4 What remains one-hop

| Traffic/state | M1 scope |
|---|---|
| Discovery scope DISCOVER/OFFER and bootstrap authentication | Neighbor-local: cookies, observed MAC, channel/density and scope checks concern direct discovery. No relay of RLD1. Provisioning a scope key fleet-wide does not turn discovery into routed discovery |
| NeighborProbe/NeighborResult and membership/binding liveness | Direct peer only; MAC/driver registration is not a remote-node peer entry |
| HOP_ACCEPT, BUSY, capability exchange and each TransitFailure report | One-hop authenticated events; failure **information** can be regenerated along remembered parents without forwarding the original one-hop frame |
| RouteUpdate | Neighbor exchange; route knowledge propagates through separately generated advertisements. Do not forward an old advertisement as a DATA frame |
| SeqnoRequest | Existing bounded routing-control propagation with its own TTL/dedup, regenerated one hop at a time; not a newly routed application or a claim it cannot propagate |
| TimeSync, ChannelNotice and link-only object kinds1/2 | Existing neighbor-local migration protocol; multi-hop DATA does not automatically extend migration coordination or its protected participant set |
| RSSI, MAC result, driver service and hop RTT | Local observations of one peer/direction; a routed report preserves their observer identity |
| DATA/EndReceipt, Service, Control and end-protected config kind3 | End-to-end routed through eligible relays |
| End-protected diagnostics type48 | Routed observer query/response, separately negotiated; all link-only subtypes remain local |

Only direct neighbors occupy the ESP-NOW driver peer table. A route to 100 remote node identities would not require 100 driver peers, but route table capacity is not evidence of 100-node RF qualification.

## 4.5 Interaction matrix and alternate landing orders

| Combination / differing landing | Forwarding consequence | Telemetry consequence | Signing / claim consequence |
|---|---|---|---|
| All three land as selected | One scheduler carries data, nine permit chunks and diagnostics; target verification is asynchronous | Count each real hop, original observer and CPU/queue delay separately | Verify once at target; dev transport still makes the deployment experimental |
| Forwarding lands before real telemetry | Use nominal link cost and existing feasibility/hysteresis; expose measurement unavailable | No fabricated RSSI/retry/AutoGuarded samples | Asymmetric permits may traverse paths if target supports them; no congestion/RF-feedback validation claim |
| Telemetry lands before forwarding | Collect direct-neighbor observations; remote query limited by actual reachability | Same snapshot version/meaning; do not infer a mesh path from multiple devices' logs | Direct asymmetric testing remains useful; no multi-hop result |
| Signing lands before forwarding | No routing change; direct transfer remains nine chunks | Measure verification work independently of link RTT | Real asymmetric one-hop permit is testable; no relay validation claim |
| Forwarding + telemetry, dev signing retained | Same caps/queues/TTL and fingerprints | Real radio observations still valid with Development transport explicitly labelled | No asymmetric/security completion of M1; shared-key compromise can mint dev permits |
| Forwarding + signing, telemetry disabled at build | Failure/capability protocol stays available independent of RF telemetry flag | Structured measurement replies Unsupported; queue/admission counters still exist | Real permit verification possible; metric and AutoGuarded readiness remain limited |
| Ed25519 chosen after backend evidence | No relay or chunk-size change for same COSE shape | Measure different target CPU service; thresholds cannot assume P-256 timings | New explicit profile/alg/key records and vectors; no P-256→Ed fallback. Both signatures remain64 B |
| Larger kid/credential chain requested | Relays still opaque, but object caps/scheduler occupancy must be re-budgeted | More work changes class/load and sampling | 32-byte kid alone fits800 B/9 chunks; chains may exceed1024 and require a versioned design, not silent growth |
| Old leaf / old intermediate present | Old leaf allowed as direct final endpoint; old intermediate excluded from transit eligibility | Old endpoint supplies no new structured snapshots; absence is explicit | Choose an authorized supported endpoint profile or fail; never downgrade a production policy |
| Relay disabled or sleeps during verification | Stop new transit, drain accepted work, invalidate sleep tickets for outstanding jobs | Absence/maintenance distinguished from RF loss | Preserve target decision journal and policy checks; loss of status leaves host unknown |
| Channel migration happens during transfer | Existing serialized radio owner fences attempts; original deadlines continue | Radio generation changes invalidate metrics/RTT; no stale success | Partial object expires/retries as transport allows; no new challenge or re-sign hidden inside recovery |

Telemetry is not an admission credential. A high RSSI never relaxes signature checks, scope/membership or route feasibility. A valid permit never grants a relay flag until the addressed provider/journal actually applies it. A policy change must use the same effective relay gate that route advertisement and power management read; three copies of `relay_allowed` would violate the design.

## 4.6 Combined failure and acceptance ledger

The shared invariant is **no success conversion across layers**. Driver success cannot become hop acceptance; hop acceptance cannot become end receipt; assembled object cannot become valid permit; valid permit cannot become ACTIVE before journal/provider verification; a valid signature cannot become a production deployment claim.

Record per test: accepted origin operation count, terminal receipts/endpoint statuses, proven pre-send refusals, deadline-unknowns, outstanding count at cutoff, relay refusals/post-accept failures, callback unknowns, diagnostic losses and policy epochs. Outstanding must reach zero after the largest original deadline plus finite evidence-drain time. Endpoint/journal invariants must hold even when throughput is poor. Count RF loss honestly; acceptance does not require pretending every offered message succeeds in a hostile link condition.

Integrated six-board run: C3 origin/bridge and C3 target, four S3 relay/load roles, then C3 relay rotation. For at least 30 minutes below saturation, combine maximum-sized reliable DATA, rate-limited maximum permits, structured telemetry and competing origins; deliberately exceed admission capacity in a separate run. Run legal config changes at the existing target rate limits, not a signature benchmark rate over the config API. Cut a primary relay, lose the reverse receipt, revoke a test issuer, fence a callback and request relay-off while work is pending. Run deterministic single-fault cases before combined faults so failures remain attributable.

Acceptance requires bounded queues/arena/stack and eventual evidence for every accepted origin operation, no unauthorized/duplicate config effect, no silent downgrade, no stale telemetry affecting AutoGuarded, and measured fairness for self/transit traffic below saturation. A 30-minute six-board run does not establish long-term reliability or production security. C5 receives build-only status until a C5 board is tested.

## 4.7 Open gates and questions

| Gate / question | Decision now | Evidence or owner needed before closing |
|---|---|---|
| Exact recursive PSA backend support and allocator strategy | P-256 selected; Ed25519 availability unproven on the pinned configuration | Implementation owner: record nested SHAs, valid/invalid probe, allocation behavior and C3 flash/timing/stack data |
| Incremental and total C3 fit | 54 KiB incremental ceiling; no PSRAM dependency | Firmware owner: combined peaks and map files against full baseline, including existing journals/Wi-Fi/identity scratch |
| New diagnostic/USB registrations | Proposed type48 subtypes1..6, HostOps0x30/0x31 and capability bit5 | Protocol owner: reconcile registry/codec allowlists and old/new fixtures in a later implementation change |
| Fleet trust-manifest provisioning/revocation | Controlled local/root-authorized provisioning; no RCC1 key-management extension | Security/deployment owner: administrative format/channel, custody, rollback-resistant storage and offline revocation-latency policy |
| RF health thresholds and optional rate metadata | Conservative classifier proposed; metadata validity explicit | Bench owner: direction/size-class coverage, effects of target CPU load, chip-specific callback evidence; adjust thresholds with recorded rationale |
| Actual forced multi-hop RF topology | Logical allowlists and physical isolation claims kept separate | Bench owner: chosen attenuation/shielding fixture and direct-link negative controls |
| Automatic channel migration | Remains opt-in and may remain blocked after M1 | Migration owner: real survey, mapped independent observations, required multi-hop participant safety and correct plan verifier; config signatures alone are insufficient |
| Production-grade claim | Not granted by M1 | Independent security review plus deployed provisioning, revocation, identity, recovery and named hardware/RF qualification evidence |

These are explicit implementation/qualification gates, not unanswered basic forwarding or wire semantics. None authorizes modifying unrelated docs/code, changing the current registry, publishing credentials, or committing this design task.
