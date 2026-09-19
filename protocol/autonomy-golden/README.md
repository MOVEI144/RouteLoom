# Autonomy payload shared golden vectors

Byte-exact test vectors for the autonomous-mesh control payloads and the
`RLD1` 1-hop bootstrap carrier (`components/routeloom/include/routeloom/
autonomy_wire.hpp`). Wire v1 itself is unchanged — these pin the
**payload** byte layouts carried inside existing FrameTypes plus the RLD1
envelope. Both the C++ harness (`tests/cpp/test_autonomy.cpp`) and the Rust
harness (`host/routeloom-wire/tests/autonomy.rs`) load these files and must
agree on every byte.

These vectors fix meaning and maximum length only. They carry no
cryptographic claims: the production suite is still pending (G-SEC), so
unlike `protocol/golden/` there is no test cipher involved — the bytes here
are plaintext payload encodings and the unprotected RLD1 envelope.

## Layouts pinned here

Every autonomy payload starts with `version u8 (=1) | subtype u8`; all
integers are big-endian; reserved bytes are 0. Budgets follow
`docs/design/autonomous-mesh/contracts.json`: Busy payload ≤ 64B,
authenticated object ≤ 2048B, RLD1 header 44B / body ≤ 116B / total ≤ 160B.

| codec | carrier/FrameType | size |
|---|---|---|
| `busy` | Busy=20 payload | 38B fixed |
| `time_sync` | TimeSync=23 payload | 26B fixed |
| `channel_notice` | ChannelNotice=24 payload | 24B fixed |
| `neighbor_probe` | NeighborProbe=40 payload | 22B fixed |
| `neighbor_result` | NeighborResult=41 payload | 24B fixed |
| `control_object` | ControlObject=49 payload | 38B fixed |
| `object_chunk` | ObjectChunk=50 payload | 38B header + data ≤ 90B |
| `object_ack` | ObjectAck=51 payload | 37B fixed |
| `bootstrap_auth` | BootstrapAuth=3 body | 4B header + body (phase in subtype byte) |
| `rld1` | standalone envelope | 44B header + body ≤ 116B |

RLD1 header (44B): `magic "RLD1" 4 | version u8 | kind u8 | header_len u16
| total_len u16 | flags u16 (=0) | network hint u32 | claimed node u64 |
transaction nonce 16B | capability bits u32`. Allowed kinds are the existing
FrameType ids {1,2,3,5,6}; MembershipResult(4), MembershipQuery(7), DATA(16)
and unknown kinds are rejected, and a Wire v1 `"RL"` frame never classifies
as RLD1 (`probe: "false"` in the invalid vector marks that case).

## Layout

- `valid/*.json` — flat objects: `codec`, the decoded fields,
  `encoded_hex`, `expect: "ok"`. Encoders must reproduce `encoded_hex`
  exactly and decoders must recover every listed field.
- `invalid/*.json` — `codec`, `encoded_hex`, `expect: "error"` and a `note`.
  Decoders must reject every one.

Regenerate with `python3 tools/gen_autonomy_vectors.py`, then run both test
harnesses to confirm cross-language agreement.
