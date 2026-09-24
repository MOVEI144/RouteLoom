# SDK v1 join relay v2 golden vectors (P3-2 #116)

Byte-exact vectors for the Wire relay v2 carrier of
[02 zero-touch join](../../../docs/design/sdk-v1/02-zero-touch-join.md) §7.5
(the 32 B RelayHeader with both service epochs, 18 B chunks/replies, the
24 B gateway-epoch query/reply). RLD1 (device ⇄ proxy) bytes are unchanged
and stay in `../join-transport/`; the old Wire v1 vectors moved to
`../join-transport/v1-history/` as negative cases (v2 decoders refuse them,
never upgrade them).

| side | code | what it does with the vectors |
|---|---|---|
| generator | `tools/gen_sdkv1_join_relay_v2_vectors.py` | independent reference encoder from the design text (stdlib only, never calls the C++/Rust codecs) |
| C++ | `components/routeloom/src/sdkv1_join_transport.cpp`, test `tests/cpp/test_sdkv1_join_transport.cpp` | decode, canonical re-encode, regenerate every chunk frame and reply from the object, reassemble in order and in reverse with duplicates, refuse every invalid vector and the v1-history shapes |
| Rust | `host/routeloom-protocol/src/join_relay.rs`, test `host/routeloom-protocol/tests/join_relay_golden.rs` | decode and re-encode the relay objects, epoch datagrams and single frames; refuse the invalid set |

Regenerate with `python3 tools/gen_sdkv1_join_relay_v2_vectors.py`; CI
regenerates and requires `git diff --exit-code` plus no untracked files. The
same run adds the v2 fuzz seeds under `tests/fuzz/corpus/sdkv1_join/` (the v1 seeds stay)
(raw codec inputs plus a length-prefixed script of a query plus a complete
m1..m4 Wire exchange) for `fuzz_sdkv1_join`. EDHOC / RLRES1 message bytes
are opaque filler of realistic lengths — the transport never parses them.
The flat JSON carries only strings and non-negative integers (RSSI as
`rssi_u8`, two's complement).

## Layouts pinned here

Integers big-endian, reserved bytes zero, every length exact.

**Relay object** (Wire, proxy ⇄ gateway, ≤ 992 B): RelayHeader 32 B `ver=2 |
dir (1 up, 2 down) | relay_id u32 ≠ 0 | proxy u64 | joiner MAC 6 (unicast) |
step | state (0 continue, 1 final, 2 abort) | joiner_rssi_dbm i8 (up ≤ 0,
down 0) | phase (4, 5) | gateway_epoch u32 ≠ 0 | proxy_epoch u32 ≠ 0`
followed by one message (1..960 B) or, for an abort, `status u8 |
retry_after_ms u32`. Up continue: EDHOC 1/3/5, RLRES1 1/3; down continue:
step 2; down final: EDHOC 4/5, RLRES1 2; up aborts carry status 4, down
aborts 2..4. Objects of ≤ 128 B ride one Wire frame — FrameType 4 for a
down final/abort, 3 otherwise; larger ones ride the chunks below. The
`(gateway_epoch, proxy_epoch, relay_id)` triple is the exchange key
(`RelayToken`); comparison is by `(proxy_epoch, relay_id)` once the
gateway epoch matches.

**Wire chunks** (FrameType 5): `ver=2 | sub = phase<<4 | step | relay_id u32
| offset u16 | total u16 | gateway_epoch u32 ≠ 0 | proxy_epoch u32 ≠ 0 |
data` — an 18 B header on the 110 B grid, total above 128 B and at most
1024. Each chunk is answered by a **reply** (FrameType 6, 18 B): `ver=2 |
sub | relay_id u32 | received u16 (contiguous prefix; Complete carries the
total) | status (0 progress, 1 complete, 2 aborted, received 0) | reserved
| gateway_epoch u32 | proxy_epoch u32`. A chunk/reply applies to the
Sending object of its same token, phase and step only.

**Gateway epoch query/reply** (FrameType 3 single frames, 24 B each, told
apart from relay objects by byte 1): query `ver=2 | kind=3 | flags=0 |
reserved | u32 0 | nonce 16`; reply `ver=2 | kind=4 | flags (bit0
authority_ready) | reserved | gateway_epoch u32 ≠ 0 | nonce echo 16`.

## Files

`valid/*.json` carry a `codec` (`relay_object`, `join_chunk`, `join_reply`,
`epoch_query`, `epoch_reply`) and the decoded fields; sequences list
`frame_NN_hex` (and `reply_NN_hex` / `receipt_NN_hex`) in order.
`invalid/*.json` carry `encoded_hex`, the `codec` (plus `carrier` /
`wire_type` where it matters), `expect = error` and a `note` naming the
violated rule.
