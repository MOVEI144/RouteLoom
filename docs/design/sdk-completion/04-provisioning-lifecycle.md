# 4. Provisioning lifecycle — credential deployment, rotation and revocation

Status: **documented / proposed**, not implemented and not production-qualified. This document closes the lifecycle gap left by [m1-completion/03-signing.md](../m1-completion/03-signing.md) §3.4 and the open gate in [04-cross-cutting.md](../m1-completion/04-cross-cutting.md) §4.7 ("Fleet trust-manifest provisioning/revocation", "Replay/counter epoch exhaustion"): M1 delivered a real `RLCP1_COSE_ESP256` permit verifier but no answer to *how a production key reaches a device, how it is superseded, and how a compromised device is excluded*. It is the credential-lifecycle installment for GitHub issue #10 and complements [host-security-readiness/05-production-security.md](../host-security-readiness/05-production-security.md), which owns the EDHOC/RPK handshake profile; this document owns **what is persisted, where it lives, who may change it, and what happens when it goes wrong**. No code, registry or contract is changed by this document; every new number below is a proposal pending registration.

Baseline evidence (current tree): the production permit verifier is a single compile-time key — [config_cose.cpp](../../../components/routeloom/src/config_cose.cpp) `CoseEsp256AuthorityVerifier::provision()` takes one `(authority_id, pubkey)` pair provisioned in RAM at boot from `CONFIG_ROUTELOOM_CONFIG_COSE_KEY_HEX` ([reference_node main.cpp:685-702](../../../firmware/reference_node/main/main.cpp)), and the journal compares `command.authority_generation` against the Kconfig value `CONFIG_ROUTELOOM_CONFIG_AUTHORITY_GENERATION` ([config.cpp:1171](../../../components/routeloom/src/config.cpp)). Rotation today therefore means *reflash*. The durable machinery this design reuses: `SingleAuthority` dual-slot ledger with seal/generation floors ([authority.cpp](../../../components/routeloom/src/authority.cpp)), `ConfigJournal` dual-slot records with `proven_floor_` and explicit `recover()` ([config.cpp:1720](../../../components/routeloom/src/config.cpp)), the replay floor/window pair ([replay.cpp](../../../components/routeloom/src/replay.cpp)), and the NVS adapters ([nvs_config_store.cpp](../../../components/routeloom_espnow/src/nvs_config_store.cpp), [nvs_ledger_store.cpp](../../../components/routeloom_espnow/src/nvs_ledger_store.cpp), [nvs_counter_store.cpp](../../../components/routeloom_espnow/src/nvs_counter_store.cpp)).

## 4.1 Scope and boundary

In scope: the on-device **trust store** (root anchors, config-authority key records, revocation set, epochs), the **device credential record** (RPK + grant), the two provisioning channels (physical bootstrap and in-band signed manifest), rotation and revocation protocols, and their interaction with NVS wear and the u16 wire epoch.

Out of scope (owned elsewhere): the EDHOC method/suite/credential codec and exporter labels (host-security-readiness §5), the MembershipGrant payload shape (§3 there), the permit envelope itself (03-signing), and operator PKI/custody infrastructure. This document does not claim any device is production-secure; it defines the lifecycle contract a production profile must satisfy.

**Design invariant** (same family as the rest of the tree): *no success conversion across layers, no silent downgrade, no unbounded state.* A physical write path substitutes for cryptography only at first install and is always an explicit, gated, auditable act — never ambient. A signed manifest is **self-authenticating**: its authorization travels inside the signature, so the same bytes are acceptable over the routed mesh or a serial console with identical semantics.

## 4.2 Credential model

### 4.2.1 Key classes and separation

Following 03-signing §3.4, four purposes stay cryptographically and administratively separate:

| Class | Held where | Private half | Mutability |
|---|---|---|---|
| Deployment root anchor | `rltrust` anchor slots (public key only, ≤2) | Offline operator custody; **never on any device or networked host by default** | In-band by a still-active anchor; bootstrap/reset only via the physical path |
| Config authority key records | `rltrust` key slots (public key only, ≤4) | Isolated signer/HSM at the issuer (host-security §5 daemon boundary) | Root-signed trust manifest only |
| Device identity (RPK) + MembershipGrant | `rlcred` record | On device, or in eFuse/secure element at higher tiers | Device-side rotation via authority re-grant; private key never crosses any wire |
| Session/link/end keys | RAM + `rlcounter`/`rlreplay` counter/replay state | Derived per context; the *counters* persist, the keys do not | Per context establishment (EDHOC profile or dev provider) |

The dev-HMAC permit key and dev link PSK are **not** trust-store content: they are compile-time material for the bench profile, deliberately outside this lifecycle so that "provisioned" always means "from the trust store or the physical path". A deployment-wide discovery scope key, when the production profile defines one, rides as an optional trust-image extension section (§4.3.5); the dev scope key is not it.

### 4.2.2 NVS region map

Existing namespaces (observed in [main.cpp](../../../firmware/reference_node/main/main.cpp) and the ESP-NOW adapters):

| Namespace | Content | Write rate |
|---|---|---|
| `rlboot` | u32 boot session | 1 entry/boot |
| `rlcounter` | `CounterRecord` leases (256-block reservation) | ~1 commit per 256 sends per context |
| `rlreplay` | `r*` window (40 B) + `f*` floor (24 B) per peer pair | window (accepted-ceiling) commit per 65 counters advanced per context since #30 (was: per accepted frame); floor per epoch advance |
| `rlplan` | migration plan/commit/active | rare |
| `rlmauth` | authority ledger, 2×156 B slots | per committed authority operation |
| `rlcfg` | config journal, 2×4096 B slots | per config phase advance (≤2 updates/min by admission cap) |
| `rlcfgv` | provider's applied snapshot blob | per config apply |

New namespaces proposed:

| Namespace | Keys | Content | Write rate |
|---|---|---|---|
| `rltrust` | `t0`, `t1` | `TrustStoreImage` dual-slot, ≤2048 B each | per accepted trust manifest (operator cadence; ~4 blob writes per application) |
| `rlcred` | `d0`, `d1` | `DeviceCredentialRecord` dual-slot, ≤1024 B each | per device re-credentialing (rare) |

Rule (mirrors `nvs_config_store` semantics): a missing blob reads back uniformly erased and classifies as *never written*; an existing-but-uniform, oversized, short-read or CRC/seal-failing blob classifies *corrupt* and quarantines — never re-initialized in place. No code path calls `nvs_flash_erase`; recovery is always explicit.

## 4.3 Persisted record layouts

All integers big-endian via the existing `ByteWriter`/`ByteReader` conventions; CRC is `crc32_iso_hdlc` over `[0, used_len-4)`; write is two-phase (`seal=0` pending, then sealed) with readback — the same commit discipline as `store_record()` in authority.cpp/config.cpp.

### 4.3.1 `TrustStoreImage` — `RLT1`, dual-slot ≤2048 B

```text
 0   u32  magic "RLT1" (0x524C5431)
 4   u16  format = 1
 6   u16  used_len (bytes incl. CRC, ≤2048)
 8   u32  schema_version = 1
12   u32  seal (0 pending / 0x7A51C9E2 committed)
16   u32  store_epoch            — ordinal, starts at 1, strictly increases per accepted image
20   u32  min_authority_generation — deny permits signed under any key generation below this floor
24   u64  network                — FULL NetworkId; see §4.8 for the deployment-generation split
32   u64  deployment_id          — operator-assigned deployment identifier (audit label, not a credential)
40   u8   flags                  — bit0: provisioning_console_locked; bit1: deployment requires production profile; others 0
41   u8   anchor_count  (≤2)
42   u8   key_count     (≤4)
43   u8   revocation_count (≤24)
44   u32  reserved = 0
48   anchors[anchor_count]      × 80 B
208  keys[key_count]            × 80 B
528  revocations[revocation_count] × 48 B
len-4 u32 crc32
```

Anchor entry (80 B): `root_id u64 | pubkey X||Y 64 B | status u8 | reserved 7 B`. Status: 1 `active` (may sign manifests), 2 `disabled`. `root_id` is the 8-byte `kid` the manifest's protected header names — an administrative identifier assigned at key creation, *not* a truncated key hash (collision semantics belong to the operator's inventory, not to a field width).

Key entry (80 B): `authority_id u64 | generation u32 | profile u8 | role u8 | status u8 | scope u8 | pubkey X||Y 64 B`. `profile`: 1 = `RLCP1_COSE_ESP256`. `role`: 1 = config-issuer (other roles reserved — membership signing uses the same record kind when that workstream lands). `status`: 1 `staged`, 2 `active`, 3 `retired`, 4 `revoked`. `scope`: 0 = whole network; other values reserved.

Revocation entry (48 B): `node_id u64 | kid_fingerprint 32 B | revoked_at_epoch u32 | kind u8 | reserved 3 B`. `kind`: 1 = device credential (matches the kid computed in host-security §3). An entry names the *credential* (kid fingerprint of the canonical COSE_Key), not merely the claimed NodeId — a revoked device that re-presents the same NodeId under a different kid is a different credential and a different decision.

Maximum image: `48 + 2·80 + 4·80 + 24·48 + 4 = 1684 B` — inside the 2048 B bound 03-signing §3.4 already budgeted ("two ≤2048-byte trust-store slots").

Boot classification of a slot: `Empty` / `Pending` (discardable) / `Corrupt` / `Unsupported` (intact, other schema) / `Valid`. A committed-seal record whose CRC fails still bounds `store_epoch`/`min_authority_generation` for recovery — the same "committed fields still bound how far state advanced" rule the authority ledger uses (authority.cpp:113-120). Both slots lost → `SECURITY_RECOVERY_REQUIRED` quarantine: the config verifier reports not-ready, privileged intake refuses, and routing continues degraded (same posture as the config journal's impairment rule — never a node-fatal halt, never an implicit reset).

### 4.3.2 `DeviceCredentialRecord` — `RLC1`, dual-slot ≤1024 B in `rlcred`

```text
 0   u32  magic "RLC1" (0x524C4331)
 4   u16  format = 1 | u16 used_len
 8   u32  schema_version = 1
12   u32  seal
16   u64  network | u64 node_id
32   u32  generation_base_session — rlboot session at which the current deployment generation took effect (§4.8)
36   u8   key_location — 0 none/dev, 1 nvs-plaintext, 2 efuse/ds-bound, 3 secure-element
37   u8   cred_status — 1 pending-registration, 2 active, 3 suspended-local
38   u16  grant_len (≤256)
40   32 B  kid = SHA-256(canonical COSE_Key of pubkey)
72   64 B  pubkey X||Y
136  32 B  private_key (key_location=1) | opaque key handle (key_location≥2) | zero (key_location=0)
168  grant bytes (≤256 B)
len-4 u32 crc32
```

Boot checks: `kid == SHA256(canonical COSE_Key(pubkey))`; for `key_location=1`, `uECC_compute_public_key(d) == pubkey`; grant network/node/kid fields match the record. Any mismatch is corruption, never a cue to "re-derive" a credential. `suspended-local` is a sticky operator state, not a wire verdict.

### 4.3.3 Trust manifest object — `RTM1`

The in-band update unit is a **complete replacement image**, not a delta. The signed payload is byte-for-byte the image's semantic content — `RLT1` bytes `[16, used_len-4)` — so verification, persistence and catch-up share one codec and one truth. `seal`, `used_len`, `format` head fields and CRC are storage-local and reconstructed on write. Complete images make convergence trivial: any newer epoch fully supersedes, missed intermediate manifests are irrelevant, and replaying an old manifest is a harmless ordinal rejection.

Envelope: the same restricted COSE_Sign1 shape as the permit profile (tag 18, array 4, canonical protected `{1:-9, 4:bstr8}`, empty unprotected, low-S), with two differences: `kid` names a **root anchor** (`root_id`), and the external AAD is

```text
"RouteLoom/trust-manifest/v1" || NUL || network u64        — 36 bytes
```

supplied from the device's own committed store, never from transport claims. Cheap parse order: envelope shape → RLT1 content head (epoch, network, counts) → anchor lookup by kid → signature verify → semantic acceptance (§4.5.1). A manifest whose signature verifies under a *disabled* anchor fails.

Maximum signed content 1664 B + 86 B COSE overhead ≈ **1750 B object**, under the existing `kAuthenticatedObjectMax` 2048 — 20 chunks of 90 B on the kind-3 carrier family.

### 4.3.4 Wire-carrier and registry (registered)

| Item | Registration | Notes |
|---|---|---|
| `ControlObjectKind::TrustManifest = 5` | end-protected, routed, same manifest/chunk/ack carrier as permits | kind 4 is the recovery lane; link-scoped kinds 1/2 unaffected; the object cap is the existing 2048 |
| Control subtype 5 `TrustStatusQuery` | `ver\|sub5\|reserved u16=0\|nonce 16 B` = 20 B | end-authenticated origin only |
| Control subtype 6 `TrustStatus` | `ver\|sub6\|reserved u16\|nonce_echo 16 B\|store_epoch u32\|min_authority_generation u32\|network u64\|image_fingerprint 32 B\|anchor_count/key_count/revocation_count u8×3\|flags u8` = 72 B | fingerprint = SHA-256 over the committed image; **public fields only — never keys, never grant bytes**. Flags v1: bit 0 has-active, bit 1 uncertain, bit 2 quarantined |
| Dispatch | `ConfigTarget` owns ONE bounded assembler shared by kinds 3/4/5 with the SAME 10 s reassembly bound — manifest, permit and recovery can never assemble concurrently, preserving the device-global object bound. Completion dispatches by kind: kind 3 → `submit_permit`, kind 4 → `submit_recovery`, kind 5 → `trust_manifest_accept` (never a journal). Caps differ: kind 5 may use the full `kAuthenticatedObjectMax` 2048, kind 3/4 the permit's 1024 | ObjectAck semantics unchanged: acknowledges assembly, never authorization |
| Rate limiting | manifest signature verification consumes `consume_expensive_verify()` — the existing 1-per-5 s device-wide gate | a manifest is the same P-256 cost as a permit |

### 4.3.5 Optional extension sections

`flags`/reserved space allows a future schema_version bump to add a discovery-scope-key section (network-wide symmetric material for the production discovery profile) and a trusted-time hint. v1 ships neither: the dev scope key stays dev, and the image deliberately carries **no time fields** — ordering is by `store_epoch` only (see §4.7 on why the design does not lean on wall-clock validity).

## 4.4 Initial provisioning — trust-anchor bootstrap

The first install cannot verify a signature (no anchor exists yet), so it is a **physical act**, gated and audited. Two concrete realizations, same on-flash result:

**P-A1 — manufactured NVS image.** The provisioning host emits a complete `rltrust`/`rlcred`/`rlboot` NVS blob set (same record encodings as the device would write — the *record format is the contract*, not the tool). Written during flash programming via an NVS-partition image or a first-boot injector. Use for factory lines and bench fleets.

**P-A2 — maintenance console.** A bounded UART/USB-Serial-JTAG verb accepting a hex/blob payload, available only when (a) a dedicated maintenance build flag is compiled in, or (b) a physical strap (GPIO sampled at boot, within a bounded window) arms it. The verb validates full structure — magic/length/counts/CRC-self-consistency, all pubkeys on-curve via the same `uECC_valid_public_key` check the verifier uses — then commits dual-slot + readback. Field firmware without the strap/build gate carries no install verb at all; at tier ≥2 (§4.10) `flags.provisioning_console_locked` set at factory disables A2 permanently for that deployment.

Initial provisioning sequence (per device):

1. Offline: operator generates the deployment root pair. Custody requirement — root private key lives on an offline machine/HSM; the tooling boundary is a `RootSigner` interface so a file-backed dev root and an HSM-backed prod root share the manifest pipeline.
2. Operator builds `TrustStoreImage` epoch 1: anchor (root pubkey, active), key record (authority gen 1, staged→active), empty revocation set, `(network, deployment_id)`.
3. Device-side key generation on-device where the tier allows (security.md §9 entropy contract: READY before any keygen, pre-RF boot, internal sources quiesced before ADC/RF hand-back). `key_location=1` writes `d` into `rlcred`; injected-at-factory keys are permitted only with a documented transport-hygiene step and are the T1-lower option — on-device generation is the default because the private half then never exists outside the device.
4. Host records `(node_id, kid, pubkey)` into the authority's inventory — the fleet registry the SingleAuthority's genesis commits.
5. First boot: validate `rltrust` (seal, CRC, epoch ≥ 1, ≥1 active anchor, on-curve points), validate `rlcred` (kid recompute + keypair consistency), open counter/replay stores, then expose capabilities. A committed store is what makes `permit_profile_bits()` advertise the COSE bit; an absent/quarantined store leaves the verifier `!ready()` — fail closed, as `provision()` already does today.
6. Production-profile builds treat the Kconfig hex-key path as **development provenance**: the store is the only accepted key source, and a build-time key is a test fixture that cannot claim `SecurityProfile::Production`. The dev-HMAC verifier is a separate class, selectable only in dev-profile builds; a production policy must never accept a dev envelope — enforced by profile selection (single configured verifier), never by trying both.

What is deliberately absent: network trust-on-first-use, in-band anchor install, default/test anchors, derive-from-MAC material. These stay absent.

## 4.5 Trust manifest protocol (in-band lifecycle)

### 4.5.1 Acceptance

A device accepts a manifest iff ALL hold, in this order:

1. Envelope parse: exact restricted COSE shape (same cheap parser rules as permits); object ≤2048 B; reassembled under the shared 10 s bound.
2. Content head parse: `network` equals the committed image's network; `store_epoch` is a nonzero u32; counts within caps; entry tables exactly sized (no trailing bytes).
3. `store_epoch` strictly greater than the committed epoch (ordinal compare — u32 wrap is a re-provision event, not modular arithmetic; same stance as the m1-completion §4.7 gate's rejection of modular epoch comparison).
4. `kid` names an anchor with status `active` in the *current* image; signature verifies under it.
5. Semantic floor: `min_authority_generation` ≥ current floor (floors never regress); resulting image retains ≥1 `active` anchor (a manifest may zero active config keys — config disabled deliberately — but may never break its own signature chain, or recovery becomes physical-only by accident).
6. Two-phase dual-slot commit + readback; activate; bump in-memory epoch; re-resolve verifier state from the new image.

Failure classes: malformed → INVALID (assembly released); epoch ≤ current or unknown/disabled anchor or bad signature → denied, generic reason remotely; storage fault → STORAGE_FAILURE/quarantine path; a power cut mid-commit leaves pending-slot evidence the boot classifier discards — the old image stays authoritative.

### 4.5.2 Effects and re-resolution

On activation: the permit verifier re-resolves its key set from the image (no cached key survives an epoch change); the revocation set replaces wholesale; `min_authority_generation` applies to the NEXT permit intake and to any in-flight transaction's decision-time recheck (§4.6.3). Diagnostics export only epoch, fingerprint, counts — never keys.

A device's honest status answer (TrustStatus subtype 6) lets an operator measure fleet convergence instead of assuming it: poll a bounded sample, resend to stragglers, and treat "unreachable" as *unknown*, never applied.

### 4.5.3 Transport realities

Manifests ride the member-only end-protected lane; a non-member or partitioned device cannot be reached this way — it catches up via the physical path or on rejoin (§4.7). The lane delivers at member cadence: one object at a time per device, ~5.1 kB/edge serialization for a maximum manifest per the request-direction arithmetic of m1-completion §4.3 — material, so distribution is an operator-paced rollout, not a flood. Manifests are idempotent, so resends and multi-path duplicates are safe; the epoch check makes them no-ops.

## 4.6 Rotation procedures

### 4.6.1 Config-authority key rotation — planned

Three images, each independently signed by the root:

| Step | Image delta | Issuer behavior |
|---|---|---|
| e+1 | add `(authority_id, gen g+1, staged)` | still signs under g |
| e+2 | g+1 → `active` (g stays `active` — bounded overlap window) | issuer switches to g+1 after its own ledger commits the generation advance (mechanism is an implementation item — §4.11; today generation only changes via `recover()`, which resets `applied_sequence` to a fresh genesis — the target-side guard is the generation floor, since the journal deliberately does not order on `authority_sequence`) |
| e+3 | g → `retired`, `min_authority_generation` = g+1 | old-key permits now fail everywhere the floor landed |

The overlap is explicit and operator-bounded — the default is zero overlap after the floor advances (03-signing §3.4), and a `retired` or `revoked` record verifies nothing. A device that missed e+2 sees e+3 directly: full-image semantics make intermediate states unnecessary.

### 4.6.2 Key lookup model (verifier API delta)

Today `context.authority_generation` is one Kconfig scalar. The production verifier takes a `TrustView` interface — `resolve_authority_key(authority_id, generation) -> {pubkey, status}` — consulted at verify time:

- Parse RCC1's `(authority, authority_generation)` as untrusted hints (inside the signed payload — 03-signing's hint pattern).
- Reject unless `authority_id == context.authorized_issuer`, the record exists, `status == active`, and `generation ≥ min_authority_generation`.
- Verify; then the decoded command's `(network, target, namespace, authority, generation)` must still match context and the resolved record — the hint can never select a foreign key.

`ConfigPermitContext` additionally captures `trust_epoch` at intake. The compile-time `(CONFIG_..._COSE_KEY_HEX, CONFIG_..._AUTHORITY_GENERATION)` path becomes a one-record static `TrustView` for tests and dev builds — same verifier code, honest provenance.

### 4.6.3 In-flight permits across a rotation

A permit's verification epoch is recorded at intake; before the DECIDED commit the journal re-evaluates the *current* image: verifying key still active, generation ≥ floor, epoch advanced → abort to IDLE/denied rather than decide under stale trust. This is the lifecycle-side enforcement of 03-signing §3.3's "recheck against the latest epoch before decision" and it is what makes revocation meaningful against an in-flight transaction. Async verify (begin/poll worker) makes the window real; the recheck closes it. Journaled decisions that already committed stay committed — later revocation does not rewrite history.

### 4.6.4 Root anchor rotation

Two-image handover: e+1 adds the new anchor `active` (signed by the old root — the chain is self-hosting); e+2 marks the old anchor `disabled`. Both anchors may sign during the window; a disabled anchor signs nothing. Root *compromise* is different: an attacker-controlled root can sign any image — there is no in-band defense. Mitigation is custody (offline key, split/HSM at tier ≥2) plus fleet inventory audit; recovery is physical re-anchor per §4.4. This is stated plainly rather than papered over.

### 4.6.5 Device credential rotation

Device generates a fresh pair on-device → registers `(node_id, new kid, pubkey)` to the authority over its existing authenticated member channel → authority commits `MembershipApproval` and issues a new grant → device commits the new `RLC1` record atomically (single dual-slot swap) → old kid enters the revocation set at the next routine image. The device's private key never traverses the mesh in either direction — there is no wire format for it at any tier.

## 4.7 Revocation procedures

### 4.7.1 What "revoked" means mechanically

Revocation is enforced **at the peers, never by delivering anything to the revoked device** — which may be unreachable, powered off, or adversarial. Three layers with distinct guarantees:

| Layer | Mechanism | Bound | Requirement |
|---|---|---|---|
| R1 — grant expiry (passive) | MembershipGrants carry `not_after` (host-security §6: ≤24 h, renew ~12 h); stop renewing the compromised credential | Worst case = remaining grant lifetime, **with no message delivered to anyone** | peers must hold trustworthy time; a cold-booted node that cannot prove time revalidates against the authority or fails closed — it does not invent validity |
| R2 — revocation set (active) | entries in the trust image, propagated by manifest | propagation-limited: each peer enforces when its image lands | peers updated ⇒ new contexts refused, live contexts terminate inside the existing ≤60 s rekey-overlap bound; persisted, so reboots don't help the revoked device |
| R3 — generation cutover (heavy) | advance the deployment generation (§4.8): new context fingerprints + new scope material fleet-wide; the revoked credential is simply never admitted to the new generation | fleet re-adoption time | operator-scheduled; also the escape when the 24-entry set overflows |

A revocation check happens wherever a peer credential is authenticated — context establishment/resume and grant validation — i.e., inside the membership/authenticator path (the sibling EDHOC document wires it; this document supplies the set and its semantics). Under the **dev-PSK profile there is no per-device identity, so there is no per-device revocation**: a shared key can only exclude everyone or no one. Revocation is a production-profile capability, full stop.

### 4.7.2 Honest offline semantics

- A partitioned/sleeping peer learns revocation when a manifest reaches it — no bound is claimed. Until then it can still accept the revoked credential's contexts; that is the documented exposure window.
- The *revoked* device needs nothing delivered: neighbors' state does the excluding.
- Deployments that need a *hard* worst-case bound rely on R1 (short grants + trustworthy time). If neither trusted time nor periodic revalidation exists, the honest claim is "revocation propagates at manifest-delivery latency"; long-lived offline devices cannot promise more.
- Revoked-credential re-admission requires an explicit later-epoch image lifting the entry — allowed and audited, but the recommended recovery is a *new* device credential, not resurrection of a suspect kid.
- Set capacity 24 entries; on overflow the policy is R3 cutover, not silent eviction or a longer list — bounded storage is a design constraint, not a suggestion.

### 4.7.3 Authority-key revocation

Different object, faster path: signer compromise is the §4.6.1 emergency single-image step (`revoked` + replacement `active` + floor advance in one epoch). In-flight permits die at the decision-time recheck. The compromised authority cannot self-rescue: it does not sign manifests.

## 4.8 Epoch/boot-session interaction and the u16 bound

Wire v1 carries `link_epoch`/`end_epoch` as u16 and the replay floor compares ordinally — the m1-completion §4.7 gate: a sender that wraps to epoch 1 while a peer floor sits at 65,535 wedges that pair fail-closed, and modular comparison is rejected. This section defines the lifecycle that bound implies.

**Where epochs come from today**: `rlboot` session is u32; `route_generation`/`link_epoch`/`end_epoch` = `((session-1) % 0xFFFF)+1` ([main.cpp:509-517](../../../firmware/reference_node/main/main.cpp)) — silently wrapping at boot 65,536.

**The provisioning axis**: `SecurityContext.network` is the *full u64* `NetworkId`, while the wire header encodes only its low 32 bits (wire.hpp:71 — "upper bits must be zero" refers to the encoded field). The replay floor and counter fingerprints bind `(scope, network, sender, receiver)` on the full u64 ([replay.cpp:49-59](../../../components/routeloom/src/replay.cpp)). This design therefore defines:

```text
NetworkId = (deployment_generation u32 << 32) | network_low32
```

The **deployment generation** lives in the trust image and enters every *internal* binding — replay fingerprints, counter context ids, EDHOC exporter context, permit AAD, journal/ledger `network` fields — while the wire header keeps carrying `network_low32` unchanged (routing/discovery unaffected; generation-mismatched peers are cryptographically disjoint anyway, which is the point). One implementation subtlety: wire.cpp's `link_context()`/`end_context()` build `SecurityContext.network` from the header's 32-bit field today; the production profile must construct contexts from the **provisioned** u64 (the value the endpoints negotiated in the handshake/exporter context), not the wire field — the dev provider keeps seeing the 32-bit value because a dev network *is* 32-bit. Advancing the generation via manifest yields a fresh epoch space per peer pair — the sanctioned exhaustion→re-provision lifecycle for wire v1, aligned with the persisted counter wear-out the gate mentions. Wire v2's 32-bit epoch remains the structural fix; until then this is the honest escape hatch.

**Per-device bookkeeping**: `RLC1.generation_base_session` records the `rlboot` session at which the current generation took effect; epochs derive as `((session - base - 1) % 0xFFFF) + 1` — the existing mapping with the window origin moved. Boot-time check: if `(session - base)` would wrap the u16 epoch (threshold at `0xFFF0`), the node refuses network bring-up with `REPROVISION_REQUIRED` — a deliberate wedge with a diagnostic — rather than silently reusing epoch 1 under a peer floor that can never accept it. For the dev-PSK bench (no trust store, 32-bit network), exhaustion recovery is literal re-provisioning: a new `ROUTELOOM_NETWORK_ID` or a wiped-and-reflashed pair; the bench profile is expected to hit this — 65,535 boots at one reset per minute is ~45 days of soak testing.

**Costs of a generation advance** (so it's not treated as free): every peer-pair floor/window re-keys — old records orphan in `rlreplay`/`rlcounter` (~2 small NVS entries per peer per generation; bounded, noted); journal/ledger `network` mismatch makes prior records `Foreign` — the applied config *snapshot* survives in provider storage but history does not carry across generations, which is semantically correct: a new generation is a new deployment epoch. Cross-generation permit replay is impossible regardless — `config_permit_aad` binds the full u64 network.

## 4.9 NVS wear and capacity budget

Two distinct bounds interact and must not be conflated: the **logical** u16 epoch bound (65,535 boots/pair, §4.8) and the **physical** flash-endurance bound (engineering estimate ~100 k erase cycles/sector for the NOR parts Espressif modules ship — a planning figure, not a datasheet guarantee).

Capacity check on the default table (`CONFIG_PARTITION_TABLE_SINGLE_APP_LARGE` → 24 kB NVS ≈ 6×4 kB pages ≈ ~126 32-byte entries/page): `rlcfg` two ≤4 kB slots ≈ 2 pages of entries, `rltrust` 2×2048 B ≈ ~1.1 pages, `rlcred` ≈ 0.4, ledger/plan/boot ≈ ~0.7, replay+counters ≈ 1–2 pages fleet-size-dependent — **the pool is effectively full, and NVS needs a free page to compact**. Production profile therefore *requires* an enlarged or a dedicated second NVS partition for `rltrust`/`rlcred` (isolation has a second benefit: high-churn regions' page compaction can't sit adjacent to trust state). This is a deployment partition-table item, flagged here so it cannot be forgotten at integration.

Write amplification per event (committed blobs; each `write()` is one `nvs_set_blob`+`nvs_commit`):

| Event | Blob writes | Approx. entry cost |
|---|---|---|
| Boot | 1 (`rlboot`) + ≤P floor commits | ~1 + ~2/peer |
| TX traffic | 1 commit per 256-counter lease | ~2/context-block |
| RX traffic | 1 ceiling commit per 65 counters advanced per context ([replay.cpp](../../../components/routeloom/src/replay.cpp); before #30: **1 window commit per accepted frame**) | ~2/65 per frame at a destination (was ~2/frame, the dominant wear term under sustained load) |
| Config update | 2 slots × 2 phases = 4 writes of `record_len` (≈152 B–2.2 kB worst case) | ~0.2–2.2 pages/update |
| Trust manifest apply | 2 slots × 2 phases = 4 writes ≤2048 B | ~0.5–2 pages |
| Device re-credential | 2 slots × 2 phases ≤1024 B | <1 page |

Endurance arithmetic (ideal uniform leveling, ~6 pages): the sustainable entry-write budget is on the order of `126 entries × 6 pages × 100 k erases` — tens of millions of entries, or equivalently ~600 k total page-erases. Rotations and manifests at operator cadence (even daily) are noise — under ~10⁴ page-equivalents/year. The honest drivers: sustained RX traffic (per-frame commits) and sustained max-rate config updates (2/min cap; a worst-case record is ~2.2 kB ⇒ ~2 page-equivalents per update ⇒ ~4/min ⇒ the erase budget is measurable in months of continuous abuse — and a deployment that actually sustains the cap has bigger problems than wear). Conclusion: **the lifecycle this document adds is wear-trivial; the pre-existing per-frame commit design was the wear ceiling** (since #30 the replay term is ~1/65 of that — budget in [crash-time-resources §7](../../spec/crash-time-resources.md)) — extend `WriteStats` to the new stores and measure, and treat the config acceptance cap as a wear bound too. The epoch bound and the endurance bound are independent: a quiet node lives decades and never sees either; a busy bench hits the epoch bound first (reboot-driven), a chatty node hits endurance first.

## 4.10 Threat model and deployment tiers

| Threat | T0 dev bench (today) | T1 production-NVS (plain C3/S3) | T2 eFuse + secure boot + flash encryption | T3 + secure element |
|---|---|---|---|---|
| RF-only attacker: replay/drop/inject | Dev HMAC forgeable iff PSK known; replay floors hold | Cannot mint permits or manifests; replays die on epochs; can only degrade availability | as T1 | as T1 |
| Flash **readout** of one device | Master PSK → impersonate *any* node, mint dev permits, decrypt everything — total loss | That device's private key → impersonate *that* node until revocation lands; anchors/authority keys are public — no signing capability gained; counters/floors readable but not secretly rewindable in place | Ciphertext only; private key in eFuse/DS peripheral never exports | Nothing of use leaves the SE |
| Flash **write / full-image restore** | n/a (already lost) | Can replace the whole trust store = equivalent to holding the physical provisioning gate; and **old-image restore rolls back epoch/revocations/floors/counter leases → rollback window incl. AEAD nonce-reuse risk on TX counter rewind** | Secure boot blocks unsigned firmware; NVS rollback still possible unless an eFuse monotonic counter backs `store_epoch` — recommended at T2 | as T2 + key custody |
| Compromised config authority key | (same as dev) | Mints permits until the emergency image lands; cannot rotate itself or touch anchors | as T1 | as T1 |
| Compromised root | — | Fleet game over: physical re-anchor required; custody + inventory audit are the only mitigations | as T1 | as T1 |
| Compromised/sleeping/straggler device | — | Impersonation bounded by R2 propagation + R1 expiry | as T1 | as T1 |

Tier facts, honestly: the reference XIAO ESP32-C3 carries **no secure element**; T3 is a BOM+driver addition. C3 *does* have secure-boot-v2, flash encryption, HMAC/DS peripherals and eFuse blocks, so T2 is on-chip work — but implementing eFuse keying is a separate, irreversible provisioning step that this SDK never performs unattended (security.md §5: eFuse changes are a separately approved deployment profile). T1's honest boundary: physical flash-write access already grants provisioning rights, so an attacker with a programmer is equivalent to an operator with the maintenance path — a deployment must decide that trade explicitly.

## 4.11 Honest limitations

- **No in-band bootstrap of first trust.** First install is physical custody; a stolen-conveyor device is out of scope.
- **No instant global revocation.** Manifest latency is unbounded for partitioned peers; only R1 (grant expiry + trustworthy time) gives a hard bound, and cold-boot-without-time fails closed rather than extends validity.
- **NVS is not rollback-proof.** CRCs and dual slots defend power loss, not a restored old image; true anti-rollback needs T2's eFuse monotonic backing for `store_epoch`/counters or external revalidation — documented as accepted residual risk at T1.
- **Mixed-epoch transients exist.** Fleet convergence is measured (TrustStatus), not assumed; during planned rotation both generations verify — by design, bounded by the floor.
- **u16 epochs are finite.** The bound is managed by generation cutover (§4.8), not eliminated; wire v2 remains the structural fix.
- **Trust manifests are fleet-scoped.** No per-device targeting; device secrets never travel in-band at all (keys are born on-device or injected physically).
- **Dev profile cannot revoke a device.** Shared-PSK exclusion is all-or-nothing; this is stated, not mitigated — dev is EXPERIMENTAL.
- **Issuer-side generation advance** needs a ledger mechanism (the current `SingleAuthority` only changes generation via `recover()`); specified as an implementation item, not assumed to exist.
- **C5 remains build-only** until hardware-tested; nothing here changes that.

## 4.12 Test plan

Host/model tests (all dual-slot stores share the existing power-cut harness conventions):

- **Codec goldens**: byte-exact `RLT1`/`RTM1`/`RLC1` fixtures produced by an independent implementation (Python `cryptography` signing, mirroring `test_config_cose.cpp`'s independently generated P-256 fixture); shared C++/Rust vectors under a `protocol/trust-golden` directory — generated, `git diff`-checked.
- **Manifest acceptance matrix**: stale/equal/future epoch; skip-ahead catch-up; unknown/disabled anchor; wrong network; tampered entry; counts over cap; trailing bytes; image leaving zero active anchors → reject; image with zero active config keys → accept (config-off is a legal state).
- **Rotation**: staged key verifies nothing; active cutover; floor advance kills old-generation permits *including* a permit verified under epoch e and decided after e+1 landed (the in-flight recheck); issuer sequence continuity across generations.
- **Revocation**: revoked kid refused at context establishment; live-context termination within the overlap bound; persisted set survives reboot; capacity-full → cutover-required verdict, never silent eviction; lifted entry vs fresh-credential paths.
- **Slot failure injection**: power cut at pending/seal/readback for both new stores; committed-but-CRC-failed slots still bound the epoch/generation floor; both-lost → quarantine + explicit recover only.
- **Provenance**: dev-baked key cannot raise the production bit; production build + absent/quarantined store → verifier `!ready()`; a dev-HMAC permit against the COSE profile is rejected by profile (existing behavior, extended to store-backed provisioning).
- **Epoch lifecycle**: forced `generation_base_session` near the wrap → `REPROVISION_REQUIRED`, wedge evidence, then generation-cutover recovery with fresh floors; orphan-record accounting.
- **Wear instrumentation**: `WriteStats` on `rltrust`/`rlcred`; per-event commit counts match §4.9's table; partition-budget check in CI (namespace byte accounting vs configured partition size).

Bench/HIL:

- Both bootstrap paths on C3/S3 (manufactured image; strapped console window — verify the verb is absent in field builds).
- Manifest delivery over real multi-hop mesh; power cut mid-transfer; straggler catch-up after partition.
- Accelerated epoch exhaustion (injected boot session) → wedge → cutover recovery.
- **Documented-attack test**: at T1, restore an old full-flash image and record the observed rollback — evidence for §4.11's limitation claim, not a pass/fail gate.
- Re-run the combined six-board faults run of [m1-completion/04-cross-cutting.md](../m1-completion/04-cross-cutting.md) §4.6 with a rotation *during* forwarding/telemetry load.

## 4.13 Implementation checklist

Portable core (`components/routeloom`):

- [ ] `trust_store.hpp/.cpp`: `RLT1` codec + dual-slot state machine (reuse the authority/journal seal/CRC/readback conventions), key/anchor/revocation accessors, epoch + `min_authority_generation` floors, quarantine + explicit `recover()`.
- [ ] `trust_manifest.hpp/.cpp`: `RTM1` content codec + manifest COSE profile (shared restricted parser; distinct AAD domain; anchor-sourced kid), acceptance pipeline per §4.5.1.
- [ ] `device_credential.hpp/.cpp`: `RLC1` codec, kid/keypair consistency checks, `generation_base_session` handling.
- [ ] `TrustView` interface + store-backed resolution in `CoseEsp256AuthorityVerifier` (retain a static one-record view for tests/dev); `ConfigPermitContext` gains `trust_epoch`; journal decision-time recheck (§4.6.3); `permit_profile_bits()` provenance gating.
- [x] Kind-5 dispatch to `trust_manifest_accept` in the `ConfigTarget` single assembler; Control subtype 5/6 codecs (registered); HostOps 0x25 transfer + 0x26 query.
- [ ] Boot-path epoch-exhaustion check (`REPROVISION_REQUIRED` instead of silent wrap).

ESP-NOW layer (`components/routeloom_espnow`) + firmware:

- [ ] `NvsTrustStore` (`rltrust`, `t0`/`t1`) and `NvsCredStore` (`rlcred`, `d0`/`d1`) adapters with `WriteStats`.
- [ ] Maintenance-console provisioning verb (build/strap-gated); production wiring: verifier boots from `rltrust`, `config.node.network` sources the full u64 from the trust image (low 32 on the wire), Kconfig key path restricted to dev provenance.
- [ ] Partition-table work: enlarged or dedicated NVS partition for trust/credential regions (deployment gate per §4.9).

Host (`host/`):

- [ ] `RootSigner` boundary (offline file + HSM-shaped interface); manifest build/sign; fleet inventory record keeping.
- [ ] `routeloomctl provision-*` verbs: image build, manifest sign/deliver, trust-status poll, NVS-image generation for the manufactured path; API1 methods proposed alongside.
- [ ] Issuer-side: `ConfigPermitSigner` consumes the active authority key record; ledger generation-advance mechanism (§4.11 item).
- [ ] Shared golden vectors with the device (§4.12).

Docs/registry:

- [ ] Register `ControlObjectKind=4`, Control subtypes 5/6, the `RTM1` AAD domain and NVS namespaces in `contracts.json`/`semantics.json` on implementation landing — none are registered by this document.
