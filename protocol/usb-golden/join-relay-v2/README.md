# USB join relay v2 golden vectors (P3-2 #116)

Byte-exact vectors for the HostOps join-relay family v2 of
[02 zero-touch join](../../../docs/design/sdk-v1/02-zero-touch-join.md) §7.5
(schema 2, capability bit 9, the same 0x60–0x63 subcommands carrying the
full `RelayToken`). The v1 session in `../join-relay/` stays as history;
schema-1 join inners are refused by the v2 decoders, never upgraded.

| side | code | what it does with the vectors |
|---|---|---|
| generators | `tools/gen_sdkv1_join_relay_v2_vectors.py` (valid/invalid codec inners, stdlib only) and `host/routeloom-protocol/examples/gen_usb_golden.rs` (`join_relay_scenario`, the sealed session) | independent reference encoders; the session seals the same inners the codec vectors pin |
| C++ | `components/routeloom/src/usb_host_ops.cpp` + `usb_bridge.cpp`, test `tests/cpp/test_usb.cpp` | decodes and re-encodes every inner byte-for-byte; replays the 20-step session through a real `UsbBridge` with an attached `JoinRelayGateway` and reproduces every device-to-host byte, including the Wire abort the live relay emits |
| Rust | `host/routeloom-protocol/src/join_relay.rs`, test `host/routeloom-protocol/tests/usb_golden.rs` | decodes and re-encodes the inners, opens every sealed session frame and checks the up/down/result/abort correlation |

Regenerate the codec vectors with
`python3 tools/gen_sdkv1_join_relay_v2_vectors.py` and the session with
`cargo run -p routeloom-protocol --example gen_usb_golden`; CI regenerates
both and requires `git diff --exit-code` plus no untracked files.

## Layouts pinned here

Integers big-endian, reserved bytes zero, every length exact. Inner head:
`schema=2 | sub | payload_len u16`.

- `0x60 JOIN_RELAY_UP` (G→H, request id 0): `gateway u64 | from_proxy u64
  | hops u8 (1..254; 0 only for the gateway's own join) | relay object`
  (dir up, proxy = from_proxy).
- `0x61 JOIN_RELAY_DOWN` (H→G): `to_proxy u64 | relay object` (dir down,
  proxy = to_proxy), answered by `0x63`.
- `0x62 JOIN_RELAY_ABORT`: `proxy u64 | relay_id u32 ≠ 0 | gateway_epoch u32
  ≠ 0 | proxy_epoch u32 ≠ 0 | reason u8` (1 proxy_aborted, 2
  gateway_expired, 3 delivery_failed, 4 host_aborted, 5 superseded). H→G
  carries reason 4 only and is answered by `0x63`; G→H (request id 0) is an
  unsolicited end-of-relay notice.
- `0x63 JOIN_RELAY_RESULT` (G→H, under the 0x61/0x62 request id): `result
  u16 (ConfigOpsResult) | proxy u64 | relay_id u32 | gateway_epoch u32 |
  proxy_epoch u32`. Ok means handed to the Wire lane, not delivered — and an
  Ok always carries the complete nonzero token.

## The session

`session.json` + `frames/01_*.json … 20_*.json`: HELLO → AUTH → m1 up →
m2 down → m3 up → m4 down → host abort of the relay while its final down
is still in flight (Ok: SendingFinal is live, #116 Q116-04) → a second
relay's m1 → the proxy's abort of it → close. The C++ replay injects the
proxy's Wire frames (m1, m1 of relay 2, the four m3 chunks, the proxy
abort object) into the gateway and checks the gateway's Wire output: four
m2 chunks, four m3 receipts, four m4 chunks, one abort object.
