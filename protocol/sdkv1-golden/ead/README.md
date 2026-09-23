# SDK v1 join EAD golden vectors (P2-3)

Byte-exact vectors for the EDHOC External Authorization Data items of the
zero-touch join ([02 zero-touch join](../../../docs/design/sdk-v1/02-zero-touch-join.md)
§6.1/§6.2) and the SAK-signed RemovalNotice
([04 removal](../../../docs/design/sdk-v1/04-removal-revocation.md) §6.1).
The choices the design left open are recorded in 02 "Resolved in
implementation (P2-3)".

| side | code | what it does with the vectors |
|---|---|---|
| generator | `tools/gen_sdkv1_ead_vectors.py` | independent reference encoder from the design text; reuses only the Python P-256/RFC 6979 and RLCW1 helpers of `tools/gen_sdkv1_vectors.py` |
| C++ | `components/routeloom/src/sdkv1_ead.cpp`, test `tests/cpp/test_sdkv1_ead.cpp` | decode, re-encode, EAD item/field walk, authorization checks, **verify** RemovalNotice and MemberCert signatures (micro-ecc) |
| Rust | `host/routeloom-join`, test `host/routeloom-join/tests/golden.rs` | the same, and as the Site Authority **re-issues** every Allow MemberCert and RemovalNotice (RustCrypto `p256`, RFC 6979, low-S) and rebuilds the JoinResult |

Regenerate with `python3 tools/gen_sdkv1_ead_vectors.py`; CI regenerates
and requires `git diff --exit-code` plus no untracked files here. The same
run rewrites the fuzz seeds `tests/fuzz/corpus/sdkv1_ead/` (raw value, item,
field and object bytes of every valid vector) for `fuzz_sdkv1_ead`.

Keys are the test material of the parent README (seed byte ×32): Device CA
`0x51`, Site CA `0x52`, SAK `0x53`, device `0x54`, peer `0x56`.

## Layouts pinned here

Integers big-endian, reserved bytes and undefined flag bits zero, every
length exact, first byte `ver = 1` (another version is `Unsupported`).

**EAD item**: `-label || bstr(value)`, always critical, labels outside the
IANA EDHOC EAD registry range (0..65535; the registry has no private-use
block): JoinIntent `3a 00 01 00 00` (−65537), SiteOffer `…01` (−65538),
JoinRequest `…02` (−65539), JoinResult `…03` (−65540). An EAD field (CBOR
sequence) must hold the message's item exactly once with a canonical
definite bstr of the item's size; padding (label 0, optional bstr value) is
skipped; any other item, a non-critical join label, a non-canonical head or
a trailing byte is rejected.

| item | message | value |
|---|---|---|
| JoinIntent | m1 | `ver \| flags \| org_hint u32 \| profile_bits u32 (bit0 RLJOIN1 required, bit1 RLRES1) \| reserved u16` = 12 B |
| SiteOffer | m2 | `ver \| flags \| site_id u64 \| network_low32 u32 \| site_epoch u32 \| decision_timeout_ms u16 (500..5000) \| reserved u16` = 22 B |
| JoinRequest | m3 | `ver \| flags \| model u16 \| fw_version u32 \| capability u32 (bit0 sleepy, bit1 relay, bit2 gateway) \| requested_role u8 \| reserved u8 \| last_site_id u64 \| last_generation u32` = 26 B |
| JoinResult | m4 | `ver \| verdict u8 (1..6) \| reason u16 = 0 \| retry_after_s u32 \| body_len u16 \| reserved u16` + body, 12..520 B |

`org_hint = first4(SHA-256("RouteLoom/org-hint/v1" 00 || Site CA pubkey))`,
`site_hint = first4(SHA-256("RouteLoom/site-hint/v1" 00 || site_id u64))`.
JoinRequest: `requested_role` uses the MemberCert role bits (nonzero; relay
and gateway only with that capability); `last_site_id = 0` ⇔
`last_generation = 0`, otherwise a valid id with generation ≥ 1.

JoinResult bodies and `retry_after_s`:

| verdict | retry_after_s | body |
|---|---|---|
| 1 Allow | 0 | `u16 membercert_len (1..256) \| MemberCert \| SitePackage 120 B \| u16 ticket_len (0..128) \| AssignmentTicket` |
| 2 PendingAssignment | 30..3600 | pending ticket, 1..48 B (opaque) |
| 3 DenyNotHere / 4 DenyBlocked | 0 | empty |
| 5 Removed | 0 | RemovalNotice, 103 B |
| 6 AuthorityBusy | 1..3600 | empty |

**SitePackage** (02 §6.2, 120 B): layout as designed; site_id valid,
network low32 ≠ 0, gk_epoch ≥ 1, GK nonzero, channel 1..14, role nonzero
known bits, gateway_count 1..4 with valid unique ids and a zero tail.

**RemovalNotice**: restricted ES256 COSE_Sign1 (tag 18, `{1:-7}`, low-S) —
`d2 84 43 a1 01 26 a0 58 1c <payload 28 B> 58 40 <sig>` — payload
`ver | reason (1..4, the RRS1 reasons) | reserved u16 | site_id u64 |
node_id u64 | generation u32 (≥ 1) | rs_epoch u32 (≥ 1)`, external AAD
`"RouteLoom/removal-notice/v1" 00 || network u64` (36 B). The device
accepts it only for its own site, node and network and a generation ≥ its
MemberCert's.

**Allow check** (02 §10.2, `join_allow_verify`): MemberCert signed by the
SAK of the m2 SiteCert; sub/cnf = own node/key; iss = SiteCert sub;
network low32/site_epoch = SiteCert; SitePackage site_id = SiteCert sub,
network = MemberCert network, role = MemberCert role. The AssignmentTicket
format is not pinned: an A1 device ignores it; an A2 (strict) device denies
an Allow without one and fails closed (`Unsupported`) with one.

## Files

- `valid/*.json` — `codec` (`hint`, `join_intent`, `site_offer`,
  `join_request`, `site_package`, `removal_notice`, `join_result`,
  `ead_field`), the decoded fields, `value_hex` and `item_hex` (or
  `object_hex` / `ead_hex`), `expect: "ok"`. Allow vectors carry the
  verification context (`site_cert_hex`, `node`, `device_pubkey_hex`,
  `strict_assignment`, `sak_secret_hex`) and `verified`.
- `invalid/*.json` — `codec`, `encoded_hex`, `note`, and `expect`:
  `"error"` (every decoder rejects it) or `"deny"` (decodes, but the named
  check fails: SiteOffer vs SiteCert, JoinRequest vs DevCert, JoinIntent
  org_hint vs Site CA, RemovalNotice acceptance, or the Allow check — the
  `join_allow_*` files are acceptance V1-J12).
