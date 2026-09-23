# SDK v1 (G-SEC) shared golden vectors

Byte-exact vectors for the SDK v1 zero-touch security formats
(`docs/design/sdk-v1/`, plan items P1-2 and P1-3): RLCW1 certificates
(DevCert / SiteCert / MemberCert), the RLI1 identity record, the RLS1 site
record, the RRS1 revocation set (payload, external AAD, Sig_structure,
COSE_Sign1 object and the `rlrevo` storage record) and the RLP1
resumption-cache slot.

Three implementations must agree on every byte:

| side | code | what it does with the vectors |
|---|---|---|
| generator | `tools/gen_sdkv1_vectors.py` | independent reference encoder from the design text (shares no code with the others) |
| C++ | `components/routeloom/src/{rlcw1,sdkv1_records}.cpp`, test `tests/cpp/test_sdkv1_golden.cpp` | decode, re-encode, rebuild AAD/Sig_structure/Sign1, **verify** signatures (micro-ecc) |
| Rust | `host/routeloom-provision/src/sdkv1/`, test `host/routeloom-provision/tests/sdkv1_golden.rs` | the same, and **re-sign** every certificate and revocation set (RustCrypto `p256`, RFC 6979, low-S) |

Regenerate with `python3 tools/gen_sdkv1_vectors.py`; CI regenerates and
requires `git diff --exit-code` plus no untracked files here.

## Signatures and keys

ECDSA P-256 over SHA-256(Sig_structure), RFC 6979 deterministic nonce,
normalized to low-S (S ≤ (n−1)/2 is also required by every verifier, so a
certificate has exactly one valid encoding). The Python standard library has
no ECDSA, so the generator carries a small pure-Python P-256 used only for
these vectors; it self-checks against the RFC 6979 A.2.5 known answer
(P-256/SHA-256, "sample") and the provisioning `test_keypair(0x11)` public
key before emitting anything. RustCrypto reproduces its signatures exactly.
micro-ecc's deterministic signer is not RFC 6979 (it orders the HMAC-DRBG
output differently), so the C++ harness is verify-only.

All keys are **test material** — the private scalar is one seed byte
repeated 32 times (`signer_secret_hex` is in the vectors on purpose):
Device CA `0x51`, Site CA `0x52`, SAK `0x53`, device `0x54`, assignment
verifier `0x55`, peer `0x56`, disabled Site CA `0x57`.

## Layouts pinned here

Integers big-endian, reserved bytes zero, CRC-32/ISO-HDLC over `[0, len-4)`.
Sealed records share the RLT1/RLC1 head `magic u32 | format u16 = 1 |
used_len u16 | schema u32 = 1 | seal u32` (0 = pending).

**RLCW1** (02 §3): `d2 84 43 a1 01 26 a0 58 <len> <payload> 58 40 <R||S>`
— tag 18, protected `{1:-7}`, empty unprotected map, external AAD empty.
Payload `a4 01 <iss> 02 <sub> 08 a1 01 <COSE_Key 77 B> 3a 00 01 00 00
<private array>`; COSE_Key `a5 01 02 03 26 20 01 21 58 20 x 22 58 20 y`
(the RLC1 kid key). Private claim: DevCert `[1, model, hw_rev, serial]`,
SiteCert `[2, network_low32, site_epoch, usage, serial]`, MemberCert
`[3, network, role, assignment_generation, site_epoch, serial]`. Shortest
integers only, no other claims, ≤ 256 B (largest v1 certificate 208 B;
vectors: DevCert 190 B, SiteCert 191 B, MemberCert 198 B). Field rules:
ids not 0/all-ones, key on curve, fields of other types zero; SiteCert
`usage` bit0 (Site Authority) only; MemberCert `role` bits {0 endpoint,
1 relay, 2 gateway} nonzero, `network>>32 == site_epoch`, generation ≥ 1.

**RLI1** (02 §2, seal `0x1DE71771`): node_id, key_location (RLC1 values),
flags (bit0 console_locked, bit1 strict_assignment), 1..3 anchors of 80 B
(`anchor_id | kind 1 SiteCA / 2 AssignmentVerifier | status 1/2 | 6 zero |
pubkey`), `devcert_len | 0 | DevCert`. ≤ 664 B, written as an identical twin
pair. Boot checks: kid, keypair (location 1), ≥ 1 active SiteCA, strict ⇒
active verifier, DevCert sub/cnf = node_id/pubkey (DevCert signature not
checked on the device).

**RLS1** (02 §10.3, seal `0x5173AB1E`): the design layout with
`commit_seq u32` inserted at offset 16 (A/B ordinal), so every design offset
moves by +4 and the maximum is 712 B. `state` 0 is the removal tombstone
(all body bytes zero, 200 B). Member records: certificates agree with the
record (SiteCert sub/network_low32/site_epoch, MemberCert
iss/network/generation/role), gateway_count 1..4 with a zero tail, channel
1..14, gk_next present iff gk_epoch_next (> current).

**RRS1** (04 §2): payload `ver | flags | count | site_id | network |
rs_epoch | site_epoch_floor | entries×16` (≤ 32 entries, strictly ascending
node_id, reason 1..4, min_generation ≥ 1, rs_epoch ≥ 1, floor ≤
network>>32) in the same restricted Sign1, external AAD
`"RouteLoom/revocation-set/v1" 00 || network u64` (36 B). Object ≤ 616 B.
Storage record (seal `0x2E5E7C0D`): sealed head, `commit_seq u32`, the
signed object as received (so it can be re-gossiped), CRC — exactly 640 B at
32 entries; an object-less 24 B record is the cleared tombstone.

**RLP1** (05 §3.2): 84 B, no seal (single-slot write; a torn slot fails its
CRC and is treated as empty). An empty slot has purpose, state and every
later field zero.

## Files

- `valid/*.json` — `codec` (`rlcw1`, `rli1`, `rls1`, `rrs1`, `rrs1_record`,
  `rlp1`), the decoded fields, the encodings (`cert_hex`, `payload_hex`,
  `sig_structure_hex`, `record_hex`, …), `expect: "ok"`.
- `invalid/*.json` — `codec`, `encoded_hex`, `note`, and `expect`:
  `"error"` (every decoder must reject it) or `"deny"` (well-formed, but the
  signature/site/network check fails under the listed `signer_pubkey_hex`,
  `expected_site_id`, `expected_network`).
