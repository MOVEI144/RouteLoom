# Compatibility and versioning policy

Status: **pre-1.0 prototype**. This policy defines what RouteLoom treats as a
compatibility surface, which rules are already enforced in code, and which are
only specified. It does not claim production readiness — see
[STATUS](../STATUS.md) for open qualification gates (notably `G-SEC` for the
production security profile and `G-USB` for USB driver qualification).

## 1. Surfaces and stability summary

| Surface | Identifier | Status | Stability promise |
|---|---|---|---|
| Wire frame format | Wire v2: `kMajor=2`, `kMinor=0` | **Frozen** for `CORE_FIXED_250` | Byte layout and type IDs never change in place; any change is a new major (v1 → v2: 32-bit epochs, 48-bit counters) |
| USB/serial framing | `"RLU1"`, `kProtocolVersion=1` | Implemented, spec rev 1.2 not final | Strict version equality today; final field offsets may still change |
| C API / ABI | `RL_ABI_VERSION 1` | Implemented | Bumps on ABI-breaking change; additive source-compatible growth allowed |
| C++ API | `routeloom::` headers | Implemented | Unstable pre-1.0; semver from the first numbered release |
| Rust host API | workspace `0.1.0` | Implemented | Unstable pre-1.0; semver from the first numbered release |
| Daemon JSON protocol | routeloom-json/routeloom-protocol | Implemented | Unstable pre-1.0; canonical payload schemas are versioned (below) |
| Persisted records | per-store `schema_version` | Implemented | Readers refuse unknown versions; formats are never silently reinterpreted |
| kconfig schema | `CONFIG_ROUTELOOM_*` | Implemented | Additive; renaming/repurposing a symbol is a breaking change |

## 2. Wire protocol (frozen: Wire v2)

Authoritative sources: the offset table in
[`wire.hpp`](../../components/routeloom/include/routeloom/wire.hpp) and
`frame_numeric_ids` in [`protocol/semantics.json`](../../protocol/semantics.json),
with shared C++/Rust golden vectors under `protocol/golden`. Normative text:
[wire-protocol.md](wire-protocol.md).

- The 88-byte header, frame-type numeric IDs, and field widths are **frozen**
  for the `CORE_FIXED_250` profile. Fields are split into an **end-immutable**
  set (magic, versions, type, flags, delivery class, payload length, network,
  origin, destination, session, sequence, original lifetime, end epoch, end
  counter) authenticated by the end-to-end AEAD, and a **hop-mutable** set
  (delivery round, hop remaining, previous/next hop, remaining deadline, link
  epoch, link counter) that relays may rewrite under the link AEAD. New
  hop-mutable behavior must not enter the end-immutable AAD.
- The cryptographic suite itself is **not** frozen (`G-SEC` open): Wire v2
  fixes the layout, not the production cipher suite or credentials.
- **v1 → v2 (breaking, pre-1.0):** link/end epochs widened from 16 to 32 bits
  and link/end crypto counters narrowed from 64 to 48 bits (the header stays
  88 bytes), ROUTE_UPDATE generations widened to 32 bits (16-byte records),
  and the APPLIED execution lease carries a 32-bit end epoch. v1 frames are
  rejected. Persisted TX counter and replay floor records moved to layout 2;
  v1 records fail closed (`IntegrityError`), so a device flashed with v1
  firmware needs an NVS erase before running v2. The C ABI bumped
  `RL_ABI_VERSION` to 2 (`rl_node_config_t` / `rl_security_context_t` epoch
  and generation fields are `uint32_t`). Rationale: issue #29/#48 — a 16-bit
  epoch consumed per boot wrapped after 65,535 boots and permanently locked
  the node out.

### Negotiation rules — implemented vs planned

| Rule | State |
|---|---|
| Decode rejects `magic != "RL"`, `major != 2`, `minor > local minor`, or `reserved != 0` | **Implemented** in `components/routeloom/src/wire.cpp` (`decode_header`) and mirrored in `host/routeloom-wire/src/lib.rs`; covered by invalid golden vectors |
| Emit `major=1, minor=0` always | **Implemented** (`kMajor`/`kMinor` constants) |
| Equal major required to participate; unknown frame types rejected | **Implemented** (spec §7: major mismatch means join refusal; unknown types fail decode) |
| Minor-version feature negotiation between peers | **Specified, not implemented** — v1 has no on-wire capability field; a peer emitting `minor > 0` is rejected by today's code. Any future minor bump must remain decodable by this rule or move to a new major |
| Crypto-suite agility | **Planned** under `G-SEC`; not negotiated today |

## 3. USB / serial protocol

Defined by [usb-protocol.md](usb-protocol.md) (revision 1.2) and implemented in
`usb_codec.hpp`/`usb_session.hpp` plus `host/routeloom-protocol`, with shared
vectors in `protocol/usb-golden`.

- Framing: COBS with `0x00` delimiter, decoded frame `"RLU1" || version(1) ||
  kind(1) || flags(2) || session || request || body || CRC-32/ISO-HDLC`,
  decoded maximum 4096 bytes.
- **Implemented:** the frame `version` byte must equal `kProtocolVersion` (1) —
  strict equality, no range. The HELLO→AUTH session binds the selected
  version, both nonces, Node/Boot/Network IDs and a capability digest into the
  authenticated transcript, so a mismatched or downgraded selection fails
  authentication rather than silently degrading.
- **Implemented:** device endpoint capabilities (`CONFIG_ROUTELOOM_CAPABILITY`
  bits 3–4) are advertised in `HelloAck`; unattached endpoints reject
  operations as `Unsupported`.
- **Specified, not implemented:** a protocol min/max range handshake (spec §2
  binds "protocol range, selected version" — current transcript carries one
  selected version), the production authentication profile, and final field
  offsets, which revision 1.2 explicitly leaves unfrozen.

## 4. C API and ABI

The C boundary is [`routeloom.h`](../../components/routeloom/include/routeloom/routeloom.h)
(there is no `c_api.h`; `routeloom.h` is the C API). Rules:

- `RL_ABI_VERSION` (currently `2`) identifies the ABI. It is bumped on any
  change that alters existing field offsets, enum values, or function
  signatures; `rl_init` requires an exact match.
- Extensible structs (`rl_node_config_t`, `rl_send_options_t`) carry
  `struct_size` + `abi_version` and zeroed reserved bytes; callers must use
  the `rl_*_init` helpers. Growth is additive and source-compatible: new
  fields are appended at the tail without an ABI bump and are read only when
  `struct_size` covers them. `rl_node_config_t` grew this way for the
  gateway-scoped routing profile (`route_gateway_count`,
  `route_refresh_ticks`, `route_gateways[2]`); `rl_init` still accepts the
  pre-extension size `RL_NODE_CONFIG_SIZE_BASE` (64 bytes) as the flat
  profile and refuses sizes between the two layouts. A binary built against
  an older header must not call a newer `rl_node_config_init()` (it writes
  the whole current struct) — pre-1.0, rebuild from one source drop.
- Group delivery was added the same additive way, without an ABI bump:
  `rl_send_options_t.ordered` takes the first former reserved byte (zero
  keeps the old unordered behaviour; the struct stays 28 bytes), and the new
  `rl_group_send_options_t` / `rl_group_result_t` / `rl_send_group` /
  `rl_get_group_result` / `rl_set_group_membership` symbols and
  `RL_SECURITY_GROUP` scope value are new names only. `rl_context_size()`
  grew with the group state, which is why storage is always sized at run
  time ([design](../design/sdk-v1/group-delivery.md)).
- `rl_context` is opaque; storage is caller-provided via
  `rl_context_size()`/`rl_context_alignment()` + `rl_init`.
- Pre-1.0 the header may still change; consumers should build from the same
  source drop. From the first numbered release, `RL_ABI_VERSION` bumps follow
  the deprecation policy in §9.

## 5. C++ API

All headers under `components/routeloom/include/routeloom/*.hpp` in namespace
`routeloom` form the C++ API (portable core plus the `routeloom_espnow` ESP-IDF
adapter). **Unstable before the first numbered release** — signatures may
change without notice. From the first release, semver applies: breaking header
changes only in major releases.

## 6. Rust host API and daemon protocol

The `host/` workspace (version `0.1.0`, MSRV `rust-version = 1.78`) is not
published to crates.io; crates are consumed by path. Semver applies from the
first numbered release. The daemon's JSON protocol over the Unix socket
(routeloom-json request/response model shared by `routeloomctl` and
`routeloom-tui`) is likewise pre-stable; clients should treat unknown fields
as ignorable and absent fields as `unknown`.

Canonical send payloads are versioned by an explicit schema byte:
`SCHEMA_VERSION = 1` (node destinations) and `SCHEMA_VERSION_GATEWAY = 2`
(gateway destinations with the endpoint extension) in
`host/routeloom-host/src/canonical.rs`. New canonical forms get a new schema
value; existing ones are never reinterpreted.

## 7. Persisted storage formats

Every durable record carries an explicit schema version; readers refuse
unknown versions rather than guessing:

| Store | Constant (current) | Unknown-version behavior |
|---|---|---|
| Authority ledger (device) | `kAuthorityLedgerSchemaVersion = 1` (`authority.hpp`) | Record reported `Unsupported`; never applied |
| Config journal (device) | `kJournalSchemaVersion = 1` (`config.cpp`) | Slot rejected |
| Config outbox (device) | `kOutboxSchemaVersion = 1` (`config.cpp`) | Slot rejected |
| Power image (device) | `kPowerImageSchemaVersion = 1` (`power.hpp`) | Image rejected, cold resume |
| Host operation store | `SCHEMA_VERSION = 2` (`sqlite_store.rs`) | Accepts versions `1..=2` and migrates forward; anything else refused |

Policy: schema bumps must ship an explicit migration or a loud refusal —
never a silent reinterpretation. Device stores favor refusal (fail closed on
identity/counter state); the host store performs logged, one-way migrations.

## 8. kconfig schema

Firmware configuration lives in `firmware/*/main/Kconfig.projbuild` under the
`CONFIG_ROUTELOOM_*` namespace. Rules:

- New symbols are additive and default to the safe/off value (EXPERIMENTAL
  features default off; opt-ins are explicit, e.g. `ROUTELOOM_DISCOVERY`,
  `ROUTELOOM_CONFIG`, `ROUTELOOM_CAPABILITY` bits).
- Renaming a symbol, changing its type, or changing the meaning of an existing
  value is a **breaking change** requiring release-note documentation.
- `CONFIG_ROUTELOOM_DEVELOPMENT_KEY_HEX` defaults to a public test fixture
  (`ROUTELOOM-DEVELOPMENT-KEY-ONLY!!`) — a development key, never a
  credential. See [SECURITY.md](../../SECURITY.md).

## 9. Deprecation and breaking-change policy

- **Pre-1.0 (now):** all surfaces except frozen Wire v2 may change without a
  deprecation period; changes are recorded in release notes and this file.
- **Post-1.0:** a breaking change to the C ABI, C++/Rust APIs, daemon JSON
  protocol, or kconfig schema requires a major version bump (or, for
  additive-then-remove flows, a deprecation announced in release notes and
  kept for at least one minor release).
- **Wire and persisted formats never break in place.** Wire changes require a
  new `major`; storage changes require a new `schema_version` with the rules
  in §7. Old nodes must reject rather than misinterpret new formats — that is
  already the implemented decode behavior.
- Spec version (`docs/reference/radio-defaults.json` `spec_version`) and
  software release versions are tracked independently, per the README.
