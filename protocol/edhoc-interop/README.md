# EDHOC interop transcripts (device libedhoc ⇄ host Site Authority)

Two recorded EDHOC method 0 / cipher suite 2 handshakes between the
**device-side stack** (vendored libedhoc v2.3.2 with the `routeloom::edhoc`
bounded backend, [edhoc.hpp](../../components/routeloom/include/routeloom/edhoc.hpp))
and the **Site Authority's Rust EDHOC** (`host/routeloom-edhoc`,
[docs/design/sdk-v1/08](../../docs/design/sdk-v1/08-implementation-plan.md) P3-3).
Each file holds both directions:

| prefix | Initiator | Responder |
|---|---|---|
| `a_` | libedhoc (the joining device) | Rust (the Site Authority) |
| `b_` | Rust | libedhoc |

The inputs are the SDK v1 join profile: an RLCW1 DevCert (test Device CA)
and SiteCert (test Site CA) referenced by `kid` (SHA-256 of the cnf
COSE_Key), EAD_1 JoinIntent, EAD_2 SiteOffer, EAD_3 JoinRequest, EAD_4
JoinResult (Allow with a MemberCert and SitePackage), fixed ephemeral keys,
and the DAMS Exporter output (label 32771, the pinned context of
`routeloom_join::dams_exporter_context`). Both ES256 implementations are
deterministic (micro-ecc HMAC-DRBG nonce, RustCrypto RFC 6979), so every
message is reproducible byte for byte.

| file | EAD_2 / EAD_3 | libedhoc arena high water (Initiator / Responder) |
|---|---|---|
| [method0_join.txt](method0_join.txt) | join item **+ the certificate by value** (label `-65541`, pinned) | 1408 B / 1440 B |
| [method0_join_kid_only.txt](method0_join_kid_only.txt) | join item only | 808 B / 840 B |

**Finding for the device side (resolved in P3-1).** The backend's EDHOC
arena was 1280 B (`ROUTELOOM_EDHOC_ARENA_BYTES`). With the certificate
carried by value — the resolution of the kcwt gap (02 §3) — libedhoc failed
`process_message_2` (Initiator) and `process_message_3` (Responder) with
`EDHOC_ERROR_NOT_ENOUGH_MEMORY` (-106). The arena is 2048 B now, so both
transcripts replay byte for byte on the device stack as well
(`routeloom_edhoc_interop_replay*`).

## Who checks what

| check | where | profile |
|---|---|---|
| Rust reproduces its own messages from the recorded inputs and accepts libedhoc's | `cargo test -p routeloom-edhoc --test interop` (`transcript_replays_byte_for_byte`, always) | both files |
| libedhoc reproduces its own messages and accepts Rust's | ctest `routeloom_edhoc_interop_replay` (`tests/cpp/edhoc_interop_peer.cpp --replay`) | kid only (fits the current arena) |
| live handshake over pipes, compared with the files | `ROUTELOOM_EDHOC_PEER=<build>/tests/cpp/routeloom_edhoc_interop_peer cargo test -p routeloom-edhoc --test interop live_against_libedhoc -- --nocapture` | both (the join file needs a peer built with a larger arena) |

`ROUTELOOM_EDHOC_INTEROP_RECORD=1` on the live test rewrites the files
instead of comparing. The files are not produced by a Python generator and
no golden generator touches them.

Test keys only: every private key here comes from `test_keypair` and must
never appear in a deployment.
