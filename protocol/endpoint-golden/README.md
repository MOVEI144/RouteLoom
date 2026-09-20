# Endpoint codec shared golden vectors

Byte-exact test vectors for the scope-gateway-config wire codec contract
(`components/routeloom/include/routeloom/endpoint_wire.hpp`,
`host/routeloom-wire/src/endpoint.rs`) implementing
`docs/design/scope-gateway-config/05-wire-api.md` §5.2–§5.5. Carriers are
unchanged — these pin BODY and PAYLOAD layouts inside existing RLD1 envelopes
and Wire v1 FrameTypes (Service=21, Control=22), plus the RCC1 canonical
config command carried as a COSE_Sign1 payload. Both the C++ harness
(`tests/cpp/test_endpoint.cpp`) and the Rust harness
(`host/routeloom-wire/tests/endpoint.rs`) load these files and must agree on
every byte.

These vectors fix meaning and maximum length only. They carry no
cryptographic claims: no scope tags are verified, no COSE signature is
validated — the bytes are plaintext canonical encodings. Vectors marked with
design-example bytes (`scope_discover_v2`, `scope_offer_v2`,
`service_submit_*`, `config_command`) reuse
`docs/design/scope-gateway-config/{examples,config-example}.json` verbatim so
the codec is pinned to the published design fixtures.

## Layouts pinned here

All integers are big-endian; reserved bytes and flags are 0. nonce, token,
boot and ID fields are never zero; a scope-1 (GATEWAY_SDK_RAM) endpoint
carries an all-zero host digest while scope-2 (HOST_RECEIVE_RAM) requires a
nonzero digest.

| codec | carrier | size |
|---|---|---|
| `scope_discover` | RLD1 Discover body v2 | 24B fixed |
| `scope_offer` | RLD1 Offer body v2 | 60B fixed |
| `scope_binding` | auth-binding canonical input | 71B fixed |
| `scope_discover_mac_input` | discover tag canonical input | 100B fixed |
| `scope_offer_mac_input` | offer tag canonical input | 167B fixed |
| `service_query` | Service=21 Query1 | 52B fixed |
| `service_descriptor` | Service=21 Descriptor2 | 86B fixed |
| `service_submit` | Service=21 Submit3 | 32B header + payload ≤ 96B |
| `service_outcome` | Service=21 Receipt4/Pending5/Reject6 | 84B fixed |
| `control_challenge_query` | Control=22 ChallengeQuery1 | 24B fixed |
| `control_challenge` | Control=22 Challenge2 | 92B fixed |
| `control_status_query` | Control=22 StatusQuery3 | 20B fixed |
| `control_status` | Control=22 Status4 | 72B fixed |
| `config_command` | RCC1 canonical command | 176B header + TLV patch ≤ 512B |
| `config_snapshot_input` | snapshot-hash canonical input | domain+4B+snapshot ≤ 512B |

Service prelude: `version u8 (=1) | subtype u8 | scope u8 | flags u8 (=0)`.
Control prelude: `version u8 (=1) | subtype u8`. Scope bodies use
`version u8 (=2)` and `scheme u8 (=1)`; scope classes are Member=1 and
Commissioning=2. Config namespaces are 1 (SDK) or app-registered
0x8000..0xfffe — every other value is rejected. RCC1 requires
`next_revision = expected_revision + 1` and a strictly-ascending, non-empty
TLV patch (`field_id u16 | type u8 | length u16 | value`; types bool=1,
u8=2, u32=3, bytes=4; max 16 fields, max 96B values, max 512B patch).

## Layout

- `valid/*.json` — flat objects: `codec`, the decoded fields,
  `encoded_hex`, `expect: "ok"`. Encoders must reproduce `encoded_hex`
  exactly and decoders must recover every listed field. `config_command`
  vectors carry `fields` as `id:type:valuehex` comma-separated entries.
- `invalid/*.json` — `codec`, `encoded_hex`, `expect: "error"` and a `note`.
  Decoders must reject every one.

Regenerate with `python3 tools/gen_endpoint_vectors.py`, then run both test
harnesses to confirm cross-language agreement.
