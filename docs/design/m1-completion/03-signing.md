# 3. Asymmetric configuration permit profile

Status: **documented / proposed**, not production-qualified. The selected profile is **RLCP1_COSE_ESP256**: COSE_Sign1 with ECDSA P-256/SHA-256, fully specified COSE algorithm `ESP256=-9`. Development HMAC remains a separate experimental profile. No device signing key is needed to verify an issuer's permit.

## 3.1 Current state and selection

[config_dev.cpp](../../../components/routeloom/src/config_dev.cpp) and the [Rust issuer](../../../host/routeloom-host/src/config.rs) implement `aad || RCC1 || HMAC-SHA256[..16]` with a shared dev key. A device possessing that key can mint permits. The existing challenge, revision/hash CAS, durable authority sequence, apply journal and result retention remain; changing the signature does not replace them.

The earlier [permit design](../scope-gateway-config/05-wire-api.md) proposed COSE/ES256 `alg=-7`, but its verifier is not implemented. This set refines that proposed asymmetric profile, without changing the deployed dev envelope. [RFC 9864](https://www.rfc-editor.org/rfc/rfc9864.html) specifies ESP256 `-9` and Ed25519 `-19`, and deprecates the older polymorphic ES256/EdDSA identifiers. Both new identifiers still encode in one CBOR byte. Do not silently accept `-7` as an alias for `-9`; any test-only older fixture must identify its own profile. The cryptographic primitive remains P-256/SHA-256.

| Evaluation on ESP32-C3 | COSE_Sign1 / Ed25519 (`-19`) | COSE_Sign1 / ESP256 (`-9`) |
|---|---|---|
| Signature and public key | 64-byte signature, 32-byte public key | 64-byte COSE raw R\|S signature; 65-byte uncompressed SEC1 public key at the backend boundary |
| Pinned IDF integration | Availability is **not established** by a Curve25519 Kconfig option; X25519 key agreement is not Ed25519 verification. Require a real PSA import/verify probe or a separately pinned/reviewed backend | Explicit P-256 configuration in the pinned IDF; matches the existing planned P-256 identity stack and avoids choosing a second curve implementation |
| C3 performance assumption | Software verification; do not assume a published result from a different chip/compiler applies | Budget as software ECC on C3; do not assume newer-chip ECC acceleration or infer it from SHA/AES acceleration |
| Incremental flash estimate | 20–60 KiB for a small standalone verifier/needed SHA-512, potentially additive to existing P-256 | 32–80 KiB when ECC is newly linked; approximately 4–16 KiB glue/codec if the required P-256 backend is already linked |
| Workspace/stack estimate | 4–12 KiB workspace plus 2–6 KiB stack, backend-dependent | 12–24 KiB bounded crypto workspace plus 4–8 KiB worker stack |
| Planning verification envelope at C3 160 MHz | 5–100 ms | 20–250 ms |
| Issuer provisioning | Deterministic signature generation simplifies nonce handling, but requires vetted signing/key storage and Ed25519 backend support | Existing P-256 credential/tooling alignment; issuer must use vetted deterministic ECDSA or correctly generated unique nonces |
| Decision | Viable future explicit profile after availability, strict-point-validation and resource evidence | **Select for M1**; pinned implementation probe and measurements are mandatory gates |

These timing and footprint ranges are **engineering estimates, not benchmarks or acceptance evidence**; they are not a claim that Ed25519 is faster on this build. COSE is an envelope choice shared by both algorithms, not an alternative to ECDSA.

The pinned [IDF Kconfig](https://raw.githubusercontent.com/espressif/esp-idf/v6.0.3/components/mbedtls/Kconfig) exposes P-256 and SoC-dependent acceleration switches. Its inspected configuration does not establish EdDSA support. The pinned [Mbed TLS README](https://raw.githubusercontent.com/espressif/mbedtls/ce3f3485a121c100f58f36d700cb35b060f6e866/README.md) places cryptography in the nested TF-PSA-Crypto dependency. Therefore record **recursive** submodule SHAs, generated PSA configuration and test results, not just “mbedTLS installed”. The design baseline is IDF v6.0.3 / `76f5dedd9950a3012fee8fb7d5586df21fc67802`, Mbed TLS `ce3f3485a121c100f58f36d700cb35b060f6e866`; nested crypto capability remains a build-probe requirement. No guessed nested SHA is supplied here.

Before implementation acceptance, build a minimal public-key import + valid/invalid verification probe using the same toolchain/configuration as reference_node. On C3 measure 1,000 valid and 1,000 invalid signatures, cold/warm key handling, min/median/p95/max elapsed, arena high water and stack; compare firmware maps with the same feature OFF. Repeat under forwarding load. Proposed gate: verification p95 ≤250 ms, single-job deadline ≤1 second, no Owner service starvation or allocation beyond the arena. If unavailable or too large, report `AUTH_PROFILE_UNAVAILABLE`/resource failure and revisit the backend; never fall back to HMAC.

## 3.2 Exact permit encoding and frame budget

Use tagged COSE_Sign1 with attached payload and a restricted canonical encoding, following the structure and Sig_structure in [RFC 9052](https://www.rfc-editor.org/rfc/rfc9052.html). ECDSA's COSE signature encoding is fixed-width R followed by S, not ASN.1 DER; algorithm details are specified in [RFC 9053](https://www.rfc-editor.org/rfc/rfc9053.html).

```text
18([
  bstr(canonical_map { 1: -9, 4: bstr(authority_id_u64_BE) }),
  {},
  bstr(RCC1),
  bstr(signature_R32 || signature_S32)
])

protected bytes = a2 01 28 04 48 <authority_id:8>   # 13 bytes
Sig_structure = ["Signature1", protected_bstr, external_aad_bstr, RCC1_bstr]
external_aad = ASCII("RouteLoom/config-permit/v1") || NUL
               || Network:u64_BE || target:u64_BE || namespace:u16_BE
```

The AAD is exactly 45 bytes and is supplied from the target's expected context, not copied from unauthenticated transport claims. It is signed but **not duplicated in the transmitted COSE object**. `kid` is the 8-byte Authority ID lookup hint already proposed for permits. It is not the 32-byte public-key fingerprint used by the separate device-identity profile, and neither identifier grants permission by itself.

At maximum RCC1 length, bytes are: tag 1 + array 1 + protected-bstr prefix 1 + protected map 13 + empty map 1 + payload-bstr prefix 3 + RCC1 688 + signature-bstr prefix 2 + signature 64 = **774 bytes**. For RCC1 below 256 bytes, the payload prefix is 2 bytes and overhead is 85 instead of 86. No certificates, embedded public keys or unprotected algorithm headers are carried.

| Envelope | Maximum object | Space left in `kConfigPermitObjectMax=1024` | 90-byte object chunks |
|---|---:|---:|---:|
| Current dev HMAC | 45 + 688 + 16 = **749 B** | 275 B | 9; last chunk 29 B |
| Selected COSE/ESP256 | 688 + 86 = **774 B** | 250 B | 9; last chunk 54 B |
| Candidate COSE/Ed25519, same 8-byte kid | **774 B** | 250 B | 9 |
| Hypothetical 32-byte kid, same fixed fields | **800 B** (extra 26 B, including CBOR length-prefix growth) | 224 B | 9; last chunk 80 B |
| Full object cap, requiring a future larger payload profile | **1024 B** | 0 B | 12; last chunk 34 B |

The signature grows by 48 bytes over the dev tag, but at maximum RCC1 size the **whole envelope grows by only 25 bytes** because COSE omits the 45-byte transmitted AAD and adds its own framing (24-byte growth below RCC1 length256). Equal maximum chunk counts do not imply equal counts for every command: RCC1 length200 gives dev261 B/3 chunks versus COSE285 B/4 chunks. RCC1 remains header176 + patch≤512, field count≤16, unchanged bytes/hashes/challenge/revisions. The available 250 bytes are headroom, not authorization to enlarge the patch, accept arbitrary COSE headers or increase `kConfigPermitEncodedMax=774`.

Object transport stays kind 3: manifest38, chunk38+n (n≤90), ObjectAck37. End/link protection yields frames 158, 158+n≤248 and 157 bytes respectively. At the maximum permit: one manifest + nine chunks + at least one final object ACK; each routed reliable frame also has its existing hop acceptance. Detailed link-count/airtime arithmetic is in [§4.3](04-cross-cutting.md). A single 774-byte ESP-NOW send is forbidden, even on a device capable of ESP-NOW v2.

## 3.3 Parsing, verification and API delta

The configured target policy chooses exactly one permitted profile. A development build may explicitly accept the dev envelope; an asymmetric target accepts only the fixed COSE shape. Missing readiness, unknown profile/alg/kid, malformed COSE or failed signature never triggers another verifier. Mixed firmware is handled by explicit provisioning/capability discovery before proposal, not by sending multiple signatures until something succeeds.

Cheap parser checks precede expensive work: exact tag18/array4, definite/minimal CBOR, protected labels exactly 1 and 4 in canonical order, unprotected empty, kid length8, payload RCC1 bounds, signature length64, no duplicate/unknown headers, no detached payload and no trailing data. The profile fixes P-256, SHA-256 and key usage independently of input. Public keys must be validated points of the correct curve. Require 1≤R,S<n; the issuer emits low-S and the verifier rejects high-S as this profile's canonicality rule. This narrows generic COSE interoperability deliberately; persist and retransmit exact signed bytes anyway.

For key lookup, parse only bounded RCC1 authority/generation as **untrusted lookup hints**, choose at most one `(authority_id, generation, profile)` key record, and verify the complete signature before trusting any command. The verified RCC1 authority must equal protected kid and configured authorized issuer; Network, target, namespace, schema, boot/challenge and generation must match policy. Then perform existing authority-sequence/replay checks, revision/hash CAS and schema/provider checks. A valid signature from the wrong role, target or generation is denied.

Current `ConfigAuthorityVerifier::verify_permit(..., payload, bool& verified)` is synchronous and does not express pending work or the policy epoch. Add a versioned interface with `begin(context, immutable_permit, token)` and `poll(token, result)`/cancel, one job maximum. Result contains a discriminated `Pending / Verified / Denied / Malformed / Unavailable / ResourceFailure / Expired`, canonical RCC1 bytes, verified authority/generation/profile/key fingerprint, and trust-store epoch. Do not overload `Status::Ok` to mean verified. Keep the old dev verifier behind an adapter; its false verdict never becomes success.

The context adds accepted profile, trust-store epoch, local deadline and expected identity/policy. An opaque verified result is created only by the verifier and consumed once by the coordinator. Recheck challenge/deadline, current trust-store epoch/revocation, authority sequence, expected revision and maintenance immediately before PREPARED/DECIDED according to the existing journal's transaction order. A worker completion after timeout/cancel/rekey is stale and cannot authorize apply. Do not put unauthenticated RCC1 into the provider's prepare/apply path.

Reassembly remains one ≤1024-byte object with a 10-second assembly bound inside the original challenge/host deadlines. Reserve verification capacity before admitting a new complete object. Object ACK may acknowledge assembly while verification is pending; it never acknowledges permission. Duplicate transport frames use frame/object dedup. Limit new expensive permit verification to one start per 5 seconds globally, burst1, in addition to the unchanged config acceptance rate. Charge failed signatures too; no per-MAC bypass. Repeated complete permits first face this cheap bounded intake gate and cannot create extra verifier jobs; retained verified transaction results can answer exact duplicates under current policy. Crypto capacity/rate refusal reports CAPACITY without consuming a config revision. This permit-specific limiter does not expand other security providers' preauthentication budgets.

On C3 run the backend in a lower-priority crypto worker with one fixed job and one fixed result mailbox, separate from the Owner. Portable code exposes asynchronous progress without FreeRTOS. The worker borrows immutable retained object bytes; no flash or apply runs there. Signature verification may take longer than a hop ACK timeout and therefore must not block the Owner. If the backend cannot yield/preempt safely, integration fails the scheduling gate rather than stretching every network deadline.

Timeout/cancel invalidates the authorization token immediately but does not release the borrowed object/arena while the worker still accesses it. Reassembly cannot overwrite that storage for the next request. Reclaim only on worker completion or a proven safe abort; an unresponsive worker makes config unavailable until recovery while forwarding continues. A late result cannot authorize a later transaction occupying the same slot.

## 3.4 Key hierarchy, provisioning and revocation

Separate four purposes: device identity/link/end session keys; discovery scope keys; online config Authority signing keys; offline administrative trust-root/recovery keys. No scope key or dev shared secret derives a production permit key. Reusing an ECC implementation is acceptable; reusing the same private key for device identity and config authority is not.

| Level | Placement and authorization |
|---|---|
| Offline deployment root | Public anchor/fingerprint provisioned into each target's protected trust store; private key held offline by the deployment operator |
| Online config Authority | P-256 private key held by an isolated signer/HSM-backed service where available; root-authorized public record binds Network, Authority ID, generation, config-only role, namespace/target scope and profile |
| Target policy | One authorized logical config Authority, current/next key generation, minimum accepted generation/sequence and trust-store epoch; targets hold public keys only |
| Recovery administration | Distinct root-authorized process to install a newer trust manifest or revoke a key; ordinary config permits cannot grant themselves signing authority |

M1 uses **directly provisioned root-authorized key records**, not an on-wire certificate chain in each permit. Initial provisioning and recovery require a controlled local maintenance path or an already authenticated administrative channel defined by the production identity work. Import validates the whole signed trust manifest, scope and monotonically increasing store epoch, writes a dual-slot record, commits/readbacks, then activates. No network trust-on-first-use, no default test key and no derive-from-MAC secret. The exact administrative manifest codec/transport is a deployment integration gate, not an undocumented extension to RCC1.

Bound storage to two root anchors and four Authority key records (active/next plus bounded recovery/rotation records), with two ≤2048-byte trust-store slots. Unknown kid/generation is a denial; no unbounded chain fetch or remote URL resolution. Export only nonsecret key fingerprints/generations/status in diagnostics. Do not put keys or entire permit bodies in default logs.

Rotate by provisioning next public key/generation first, verifying target readback, activating issuer generation, then persisting the minimum accepted generation and retiring the old key. Default is no old-key overlap after the floor advances. Any deployment-specific overlap must be explicit, bounded by trustworthy time and never apply to a revoked key. Recheck an assembled/in-flight permit against the latest epoch before decision. Durable decisions are recovered by the journal; later revocation does not erase history or falsely report rollback of already applied effects.

Revocation is a higher-epoch root-authorized trust update, never authorized only by the key being revoked. On corruption/loss of both store slots, quarantine privileged config as `SECURITY_RECOVERY_REQUIRED`; no erase-and-reinitialize with an old floor. Issuer outbox and target sequence/revision floors survive reset. Restoring an old firmware image must not lower accepted schema/profile/trust epoch/key generation/sequence floors.

Challenge freshness limits replay of already signed permits, but **does not revoke a compromised private key** capable of signing a fresh challenge. An offline/disconnected target cannot learn a new revocation. Deployments needing bounded revocation latency must impose a fresh management authorization lease using trusted time or secure revalidation after boot; if unavailable, privileged config fails closed. This limitation must be part of the deployment claim. Secure Boot, protected rollback floors and debug controls are separately required to resist hostile flash restoration; ordinary NVS dual slots only handle accidental power loss.

## 3.5 Host-side signing and errors

Keep the existing issuer's propose → canonical RCC1 → durable authority/outbox sequence → sign → retain exact permit → transport flow. Add a profile-aware `PermitSigner` behind the same daemon, with a local service/HSM boundary. Persist chosen profile, authority generation, canonical digest, final exact signature bytes and permit digest. After a crash, never replace a retained signature with a newly signed equivalent object under the same operation identity. A new challenge/generation requires a new approved proposal and idempotency decision.

The daemon verifies signer output against the pinned public record before transfer, refuses scope/profile mismatch, and surfaces signer unavailable/busy/denied without pretending the target saw a permit. `routeloomctl config-*` displays `permit_profile`, verified issuer fingerprint/generation and separate transport-security profile. Existing dev mode remains visibly EXPERIMENTAL. Capability bit `config_endpoint_v1` alone does not mean COSE support; use authenticated M1 capability metadata or explicit managed inventory. Old targets may still receive intentionally selected dev proposals; no automatic downgrade is allowed.

| Failure | Target / host evidence |
|---|---|
| Unsupported profile/provider not ready | `AUTH_PROFILE_UNAVAILABLE` or UNSUPPORTED, no prepare/apply |
| Parse/length/unknown critical structure | Malformed/INVALID, assembly released at bounded deadline, no crypto fallback |
| Bad signature, unknown/revoked key, wrong authority/scope | Generic `AUTHORITY_DENIED` remotely; bounded detailed local audit reason; no oracle exposing secret data |
| Crypto arena/job full | CAPACITY/BUSY before verification admission; no partially verified result |
| Worker timeout/stale policy/challenge | DEADLINE or authority denial as appropriate; late completion discarded |
| Trust/journal storage failure | STORAGE_FAILURE/RECOVERY_REQUIRED with actual phase; never ACTIVE |
| Radio loss after decision/apply | Host outcome unknown pending status reconciliation; never infer non-application from timeout |

Existing Config wire reasons remain unchanged. New local detail names are diagnostics, not newly invented Config reason numbers. Remote denial need not reveal whether a particular key exists. A relay cannot manufacture a valid endpoint status, and a valid permit does not authenticate a status received over an experimental shared-key transport against all insiders.

## 3.6 Resource, growth and rollback policy

Incremental target ceiling: 24 KiB fixed crypto arena, 8 KiB worker stack, ≤4 KiB parser/key-policy/job metadata = **36 KiB**. Reuse existing 1024-byte assembly and command/journal storage; do not count them as new free scratch. Key store adds 4 KiB nonvolatile dual slots, excluding NVS overhead. Flash/timing estimates are in §3.1. The relay-only forwarding feature links no permit verifier solely to forward a permit; a relay that is also a config target pays the target cost once.

A PSA/Mbed TLS backend may allocate internally. Route its allocations through a bounded, audited arena or a supported fixed-memory configuration; initialization/import and verification must be included. Serialize arena ownership with any other crypto client using it, or budget separate arenas explicitly. Do not install a global allocator hook that silently breaks existing AES/identity users. Arena exhaustion is a normal reported failure. No portable-core heap and no runtime growth are permitted.

Keep object1024, encoded permit774, patch512 and existing journals/outboxes unchanged. A future certificate-bearing, Ed25519 or larger-kid profile requires a new explicit profile/version, resource accounting, codec vectors, capability migration and measured acceptance. Do not consume the 250-byte margin by accepting arbitrary headers. A schema upgrade that cannot be read by rollback firmware must be staged only after boot confirmation and must keep security floors enforceable; otherwise rollback firmware refuses privileged config and requires maintenance recovery. Downgrade to development is a separately authorized reprovisioning operation, never timeout recovery.

## 3.7 Tests, six-board acceptance and maturity

Host tests use real independently generated P-256 signatures and verify them through the selected device backend; zero-filled length fixtures never count as signature evidence. Test both algorithms' size calculations, C++/Rust exact CBOR/RCC1/AAD bytes, endian and full Network binding, DER-vs-raw rejection, high-S rule, invalid/off-curve key, R/S boundaries, mutated header/payload/signature, duplicate CBOR keys, indefinite lengths, unknown alg, embedded keys, foreign target/namespace/generation and dev/COSE cross-rejection. Exercise old transport codecs unchanged.

Fault tests cover arena exhaustion, job cancellation, late completion, challenge expiry during verification, revoked epoch between verification and decision, issuer crash before/after signature persistence, all trust/journal write boundaries, restoring one old slot, both slots invalid, stale firmware floor enforcement and duplicate permit after ACTIVE. Assert no unauthorized prepare/apply and no weaker-profile fallback. The fixed parser is a fuzz target in the future implementation work, not a request to add code in this change.

| Six-board case | Required evidence |
|---|---|
| S1 — direct C3 target, S3 issuer bridge | Maximum valid permit reaches ACTIVE; bad signature never reaches PREPARED; record real C3 verification/arena/stack measurements |
| S2 — same target across three/five links | Same signed bytes/digest at target; nine chunks, no relay public-key verify; route/ACK traces distinguish assembly and apply |
| S3 — C3 target simultaneously relays, S3-D supplies load | One verifier job; Owner services forwarding/ACK deadlines; CPU work visible in telemetry; no heap growth |
| S4 — next-key activation/revocation, reboot at persistence boundaries | Accepted floor survives reboot; revoked/in-flight old key denied; interrupted committed operation recovered honestly |
| S5 — partition or power loss after apply before Status | Host reports unknown until original operation status resolves; no re-sign/reapply under a new interpretation |
| S6 — old target, new target with dev policy, new asymmetric target | Explicit selected profile only; older target never silently receives a downgraded permit; test keys never reported as production provisioning |

M1 can claim **asymmetric permit signing/verifying implemented and tested**, with named profile/build and test-key provisioning. “Production signing profile” names the intended trust model and fail-closed contract, not security certification. A deployment may call it production-enabled only after real key custody/provisioning, revocation freshness, transport identity, secure storage/boot/rollback policy, independent crypto review, incident recovery and device evidence are accepted. A signature alone does not secure routing, discovery, Host ACLs, unsigned telemetry, radio availability or a compromised target.
