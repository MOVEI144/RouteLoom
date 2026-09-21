# Provisioning shared golden vectors

Byte-exact test vectors for the provisioning wire formats and the trust
manifest acceptance pipeline (`docs/design/sdk-completion/
04-provisioning-lifecycle.md` §4.3, §4.5.1, §4.12). The Rust harness
(`host/routeloom-provision/tests/golden.rs`) loads every document here;
the device C++ suite reads the same files so both implementations agree
on every byte and every verdict.

All documents carry `"format": "routeloom-provisioning-golden-v1"` and a
`kind` tag. Every multi-byte wire field is big-endian; byte strings are
lowercase hex; 8-byte ids (`network`, `root_id`, `node_id`, …) are
16-hex strings so no consumer loses precision through `f64`.

## Key material

`keys.json` holds the fixed `test_keypair(seed)` family — the private
scalar is the seed byte repeated 32 times and the public half is derived
on-curve (P-256, `X || Y`, 64 bytes). The same seeds produce the same
pubkeys in `tests/cpp/test_provisioning.hpp`. **TEST MATERIAL ONLY** —
these secrets are published in the repository and must never anchor a
real deployment.

| name      | seed  | id                              |
|-----------|-------|---------------------------------|
| root_a    | 0x11  | `root_id` 0x100 — manifest kid  |
| root_b    | 0x22  | `root_id` 0x200                 |
| authority | 0x33  | `authority_id` 0xA17, gen 1     |
| device    | 0x55  | `node_id` 0xC3                  |

Signatures are RFC 6979 deterministic ECDSA P-256/SHA-256 with low-S
normalization (`s ≤ (n−1)/2`), so `manifest-epoch2.json` regenerates
byte-identically on any conforming implementation.

## Layout

- `keys.json` — the key table above.
- `image-epoch1.json`, `image-epoch2.json` — `kind: "trust-image"`: the
  spec fields (`store_epoch`, `min_authority_generation`, `network`,
  `deployment_id`, `flags`, `anchors`, `keys`, `revocations`) plus
  `record_hex` (the committed RLT1 record), `content_hex` (the RTM1
  signed content — RLT1 bytes `[16, used_len−4)`) and
  `fingerprint_hex` (SHA-256 over `[0, used_len)`). These documents
  double as `routeloomctl provision-image --spec` inputs.
- `manifest-epoch2.json` — `kind: "manifest-verify"`, `expect:
  "accept"`: `current_record_hex` is the committed epoch-1 image,
  `object_hex` the RTM1 envelope (COSE tag 18, array(4), protected
  `a2 01 28 04 48 <root_id:8>`, empty unprotected map, payload bstr,
  64-byte `R || S`).
- `credential.json` — `kind: "credential"`: the RLC1 record for node
  0xC3 — `record_hex`, `kid_hex` (SHA-256 over `cose_key_hex`),
  `pubkey_hex`, `grant_hex`. Grant signature bytes are zeros: grant
  signature verification belongs to the membership workstream, not the
  RLC1 codec.
- `nvs-set.json` — `kind: "nvs-set"`: the P-A1 manufactured NVS blob
  set — `rltrust` `t0`/`t1` twin committed records (slot 2048 B),
  `rlcred` `d0`/`d1` twin committed records (slot 1024 B) and `rlboot`
  `session` = 0 (the first boot runs session 1). Blobs are stored at
  `used_len`, never slot-padded — those are the bytes the device's own
  write path produces.
- `invalid/*.json` — `kind: "manifest-verify"` rejection vectors.
  `expect` is the device `StatusCode` name the offline pipeline must
  report; `expect_detail` is the static detail string.

## Invalid vectors and expected verdicts

| vector                   | expect                 | exercised rule                                   |
|--------------------------|------------------------|--------------------------------------------------|
| `stale-epoch`            | `Conflict`             | epoch ≤ committed (§4.5.1 rule 3)                |
| `unknown-anchor`         | `AuthorizationFailed`  | kid names no anchor (rule 4)                     |
| `disabled-anchor`        | `AuthorizationFailed`  | kid names a disabled anchor (rule 4)             |
| `bad-signature`          | `AuthorizationFailed`  | flipped signature byte (rule 4)                  |
| `foreign-network`        | `AuthorizationFailed`  | content network ≠ committed (rule 2)             |
| `aad-mismatch`           | `AuthorizationFailed`  | signature binds foreign-network AAD (§4.3.3)     |
| `no-active-anchor`       | `InvalidArgument`      | result leaves zero active anchors (rule 5)       |
| `floor-regression`       | `AuthorizationFailed`  | `min_authority_generation` regressed (rule 5)    |
| `truncated`              | `ProtocolError`        | malformed envelope (rule 1)                      |

## Regenerating

```sh
cargo run -p routeloom-provision --example gen_provisioning_golden
cargo test -p routeloom-provision --test golden
```

The generator is deterministic (fixed keys + RFC 6979); a `git diff`
after regeneration must be empty. The equivalent `routeloomctl` flow —
`provision-keygen`, `provision-image`, `provision-manifest`,
`provision-verify` — consumes the same spec/record shapes.
