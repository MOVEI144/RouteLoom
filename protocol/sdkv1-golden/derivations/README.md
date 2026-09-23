# SDK v1 key-derivation golden vectors (P1-4 / P1-5)

Byte-exact vectors for the FROZEN RouteLoom derivation labels and `info`
encodings of [03 key hierarchy](../../../docs/design/sdk-v1/03-key-hierarchy.md)
§2.2/§3/§5.3/§6.1 and the RLRES1 resume transcript of
[06 fast rejoin](../../../docs/design/sdk-v1/06-fast-rejoin.md) §2.1.

- Generator: `python3 tools/gen_sdkv1_derivation_vectors.py` — written from
  the design text with the Python standard library only (`hmac`, `hashlib`,
  `struct`). It shares no code with either implementation.
- C++: `tests/cpp/test_key_schedule.cpp` (`routeloom_key_schedule_tests`)
  checks every derivation primitive and also drives two real
  `rlres1::Engine`s with the vector's nonces/context ids, which must emit
  exactly `r1_hex`/`r2_hex`/`r3_hex` and install the vector's keys.
- Rust: `host/routeloom-keysched/tests/golden.rs`.
- CI (`wire-golden` job) regenerates the files and requires
  `git diff --exit-code -- protocol/sdkv1-golden/derivations`.

`valid/` codecs: `group` (PRK_g, K_bcast, K_gend, K_dsk and their `info`
bytes), `aead_nonce`, `rlres1` (link / end / authority / pending-join full
transcripts: rid, K_auth, binding, R1, R2, TH, PRK, K_conf, R3, directional
key/iv), `rlres1_hint` (12-byte unauthenticated R2) and
`authority_envelope` (12-byte header = AAD, nonce). `invalid/` holds malformed
R1/R2/R3/AuthorityEnvelope encodings with the refusal `reason` both decoders
must report.

All secrets, nonces and ids here are synthetic test values. The vectors pin
RouteLoom's own constructions; they are not an independent security review
(plan P8-2), and no AEAD output is included (AES-GCM stays in the
SecurityProvider).
