# SDK v1 revocation wire golden vectors (P6-1 PR A)

Byte-exact vectors for the PR-A revocation wire
([04 removal](../../../docs/design/sdk-v1/04-removal-revocation.md) §2–§5):
the link-only 1-hop Control (22) gossip bodies (StateEpochs, RrsRequest),
the authority type-5 device→Host bodies (RrsApplied, RrsGet,
RrsNoticeAccepted), and the kind-6 (RevocationSet) autonomy object envelope
(manifest + chunks) carrying a real SAK-signed RRS1 object end to end.

| side | code | what it does with the vectors |
|---|---|---|
| generator | `tools/gen_sdkv1_revocation_vectors.py` | independent reference encoder from the layout text; reuses only the Python P-256/RFC 6979 and Sign1 helpers of `tools/gen_sdkv1_vectors.py` |
| C++ | `components/routeloom/src/{sdkv1_revocation,autonomy_wire}.cpp`, test `tests/cpp/test_sdkv1_revocation.cpp` | decode, re-encode, kind-6 reassembly, **verify** the RRS1 signatures (micro-ecc) |
| Rust | `host/routeloom-wire/src/{revocation,autonomy}.rs`, test `host/routeloom-wire/tests/revocation.rs` | the same, plus RRS1 decode/**verify** via `routeloom-provision` (RustCrypto `p256`, low-S) |

Regenerate with `python3 tools/gen_sdkv1_revocation_vectors.py`; CI
regenerates and requires `git diff --exit-code` plus no untracked files
here.

Keys are the test material of the parent README (seed byte ×32): SAK
`0x53`, same test site as the existing `rrs1_*` vectors.

## Layouts pinned here

Integers big-endian, reserved bytes and undefined flag bits zero, every
length exact, first byte `ver = 1`.

**Gossip** (Control 22, exact shapes only — hints, never evidence):
StateEpochs `ver | sub 0x61 | site_epoch u32 | applied_rs u32 | gk_epoch
u32` = 14 B; RrsRequest `ver | sub 0x62 | site_epoch u32 | have_rs u32` =
10 B.

**Type 5** (device→Host; Host→device is the bare RRS1 object): Applied
`ver | sub 1 | reserved u16 | rs_epoch u32 | object_sha256[32]` = 40 B;
Get `ver | sub 2 | reserved u16 | wanted_rs_epoch u32` = 8 B (0 = latest);
NoticeAccepted `ver | sub 3 | reserved u16 | rs_epoch u32 |
notice_sha256[32]` = 40 B.

**Kind 6** (content = the RRS1 COSE object bytes verbatim; the manifest
hash proves reassembly identity only, the SAK signature inside the object
is the authority): manifest `ver | subtype 1 | kind 6 | flags 0 |
total_len u16 (1..2048) | object_hash[32]` = 38 B; chunk `ver | subtype 1
| object_hash[32] | offset u16 | length u16 | data[length]`, `offset +
length ≤ 2048`, whole chunk ≤ 128 B.

## Files

- `valid/*.json` — `codec` (`rrs_state_epochs`, `rrs_request`,
  `rrs_applied`, `rrs_get`, `rrs_notice_accepted`, `rrs1_object`,
  `rrs_kind6_manifest`, `rrs_kind6_chunk`), the decoded fields,
  `body_hex` (or `manifest_hex` / `chunk_hex` / `object_hex`), `expect:
  "ok"`. The `rrs1_object` and `rrs_kind6_manifest` vectors carry the
  RRS1 fields plus `signer_pubkey_hex`, `site_id` and `network` so both
  harnesses verify the same object.
- `invalid/*.json` — `codec`, `encoded_hex`, `note`, `expect: "error"`
  (every decoder rejects it: wrong version/subtype/sub, nonzero
  reserved/flags, short/long, unassigned kind, empty/oversize total_len,
  chunk length mismatch/overrun/oversize).
