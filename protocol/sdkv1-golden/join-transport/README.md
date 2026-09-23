# SDK v1 join transport golden vectors (P3-1 / P3-2)

Byte-exact vectors for the zero-touch join transport of
[02 zero-touch join](../../../docs/design/sdk-v1/02-zero-touch-join.md) §5
(RLD1 body v3, BootstrapAuth phases 4–6, the ≤ 1024 B assembly object) and
§7.1 (the Wire relay object between a member proxy and its gateway). The
choices the design left open are recorded in 02 §5.4 and §7.4 ("Resolved in
implementation").

| side | code | what it does with the vectors |
|---|---|---|
| generator | `tools/gen_sdkv1_join_transport_vectors.py` | independent reference encoder from the design text; borrows only the P-256 public-key helper of `tools/gen_sdkv1_vectors.py` (for the test Site CA's org_hint) |
| C++ | `components/routeloom/src/sdkv1_join_transport.cpp`, test `tests/cpp/test_sdkv1_join_transport.cpp` | decode, re-encode, regenerate every chunk frame and reply from the object, reassemble in order and in reverse with duplicates, admission of each frame for the sending and receiving role |
| Rust | `host/routeloom-protocol/src/join_relay.rs`, test `host/routeloom-protocol/tests/join_relay_golden.rs` | the relay objects (the host parses what the gateway hands it in USB 0x60 and builds what it sends in 0x61) |

Regenerate with `python3 tools/gen_sdkv1_join_transport_vectors.py`; CI
regenerates and requires `git diff --exit-code` plus no untracked files. The
same run rewrites the fuzz seeds `tests/fuzz/corpus/sdkv1_join/` (raw codec
inputs plus two length-prefixed scripts of complete RLD1 and Wire exchanges)
for `fuzz_sdkv1_join`. EDHOC / RLRES1 message bytes are opaque filler of
realistic lengths — the transport never parses them. The flat JSON carries
only strings and non-negative integers (RSSI as `rssi_u8`, two's complement).

## Layouts pinned here

Integers big-endian, reserved bytes zero, every length exact.

**RLD1 DISCOVER v3** (24 B body, broadcast): `body_version=3 | class=3 |
flags u16 (bit0 preferred_site_valid ⇔ preferred hint ≠ 0) | profile_bits u32
(bit0 RLJOIN1 required, bit1 RLRES1) | org_hint u32 | preferred_site_hint u32
| avoid[0] u32 | avoid[1] u32` (avoid slots pack from the front, distinct,
never the preferred hint). Header: network_hint 0, claimed node valid,
capability 0.

**RLD1 OFFER v3** (48 B body, unicast): `3 | 3 | density | flags (bit0
authority_reachable, bit1 proxy_busy) | cookie 16 | responder nonce 16 |
org_hint u32 | site_hint u32 | authority_hops (255 unknown) | load |
reserved u16`. Header: network_hint = network_low32 (≠ 0), claimed = proxy,
the DISCOVER's nonce, capability 0.

**Join object** (≤ 1024 B, the BootstrapAuth body): `ver=1 | phase | step |
reserved` then

| phase | steps | rest |
|---|---|---|
| 4 EDHOC | 1..4 = message_1..4, 5 = error | `cookie_echo_present u8 (1 ⇔ step 1) \| reserved u8 \| [cookie 16] \| message 1..960 B` |
| 5 RLRES1 | 1..3 | same; the cookie may ride step 1 only (the zero-touch proxy requires it) |
| 6 RelayStatus | 1 | `status u8 (1 queued, 2 authority_unreachable, 3 busy, 4 aborted) \| retry_after_ms u32 (≤ 600000)` — 9 B |

An object of ≤ 116 B is one BootstrapAuth frame; a larger one is split into
**chunks** (RLD1 kind 5 / Wire FrameType 5): `ver=1 | sub = phase<<4 | step
(0x41..0x45, 0x51..0x53) | id u32 | offset u16 | total u16 | data` with
offsets on the 106 B (RLD1) / 118 B (Wire) grid, total above the carrier's
single-frame limit (116 / 128 B) and at most 1024. `id` is the first four
transaction-nonce bytes on RLD1 and the relay_id on Wire. Each chunk is
answered by a **reply** (kind 6 / FrameType 6, 10 B): `ver=1 | sub | id |
received u16 (contiguous prefix; Complete carries the total) | status (0
progress, 1 complete, 2 aborted, received 0) | reserved`.

**Relay object** (Wire, proxy ⇄ gateway, ≤ 984 B): RelayHeader 24 B `ver=1 |
dir (1 up, 2 down) | relay_id u32 ≠ 0 | proxy u64 | joiner MAC 6 (unicast) |
step | state (0 continue, 1 final, 2 abort) | joiner_rssi_dbm i8 (up ≤ 0,
down 0) | phase (4, 5)` followed by one message (1..960 B) or, for an abort,
`status u8 | retry_after_ms u32`. Up continue: EDHOC 1/3/5, RLRES1 1/3; down
continue: step 2; down final: EDHOC 4/5, RLRES1 2; up aborts carry status 4,
down aborts 2..4. Objects of ≤ 128 B ride one Wire frame — FrameType 4 for a
down final/abort, 3 otherwise; larger ones ride the chunks above.

**OFFER cookie** (proxy-local, pinned for independent checking):
`first16(HMAC-SHA-256(key, "RouteLoom/zt-cookie/v1" 00 || MAC 6 || nonce 16
|| proxy u64 || network_low32 u32 || bucket u64))`, current and previous
bucket accepted.

## Files

`valid/*.json` carry a `codec` (`zt_discover_frame`, `zt_offer_frame`,
`cookie`, `join_object`, `rld1_object_frames`, `join_chunk`, `join_reply`,
`relay_object`) and the decoded fields; sequences list `frame_NN_hex` (and
`reply_NN_hex` / `receipt_NN_hex`) in order. `invalid/*.json` carry
`encoded_hex`, the `codec` (plus `carrier` / `wire_type` where it matters),
`expect = error` and a `note` naming the violated rule.
