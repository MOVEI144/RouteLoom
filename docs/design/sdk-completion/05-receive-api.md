# 5. Receive API — poll semantics, subscription streams, and multi-consumer delivery

Status: **design proposal** for [issue #7](https://github.com/MOVEI144/RouteLoom/issues/7). This document specifies the complete host-side receive surface: the existing `messages.read` cursor poll, its long-poll extension, and a new push/stream surface (`messages.subscribe` / `messages.unsubscribe` / `messages.subscriptions`). It supersedes the "subscribe push is initially Unsupported" clause of [host-security-readiness/02-receive-api.md](../host-security-readiness/02-receive-api.md) §1 and [01-contracts.md](../host-security-readiness/01-contracts.md) §4; the poll contract itself is unchanged. Nothing here is implemented; method names, JSON shapes, constants and error codes are **proposed** until the checklist in §5.11 lands. Source documents: `docs/spec/host.md` §3/§5/§6/§8 (names `messages.subscribe`, per-subscriber bounds), `docs/design/host-security-readiness/02-receive-api.md` (cursor/record contract, RX01–RX08), `contracts.json` `receive.*`/`ipc.*` pins, and `docs/design/scope-gateway-config/03-explicit-gateway.md` §3.4 (Host ReceiveLog ack boundary).

Implementation baseline referenced below: `host/routeloom-host/src/{api1,receive_log,main,dispatch,send_store,acl,canonical}.rs`, `host/routeloomctl/src/main.rs`, `host/routeloom-tui/src/client.rs`.

## 5.1 Overview and adopted model

Two delivery modes over one data source. The **only** payload store is the existing bounded per-network `ReceiveLog` (`receive_log.rs`: 4096 records / 2 MiB per network, 300 s retention, ≤4 networks, 8 MiB global, 512 B per-record charge, drop-oldest reclaim with an `evicted_through` tombstone). Both modes read it:

| Mode | Method(s) | Shape | Backlog |
|---|---|---|---|
| Pull (existing) | `messages.read` | request → one bounded page + `next_cursor` | log contents |
| Pull + wait (new, additive) | `messages.read` with `wait_ms` | parks ≤15 s until ≥1 record or honest timeout | log contents |
| Push (new) | `messages.subscribe` | request → response → asynchronous notification lines on the same connection | per-subscription cursor position + bounded staging queue in front of the socket |

The adopted subscription model is **cursor-following**, not copy-per-subscriber: a subscription is a per-connection object holding `{filter, position, counters, staging queue}`; a per-connection pump thread advances `position` through the shared log and serializes notifications. The log itself is the replay backlog — a subscriber that falls behind is *not* re-buffered into a second copy, it simply lags, and if its position falls behind `evicted_through` the stream emits an in-band `gap` marker. A per-subscription staging queue (128 notifications / 256 KiB, per `host.md` §8) sits between pump and socket and is the bounded in-flight queue the issue asks for; its overflow rule is drop-oldest + coalesced marker (§5.5).

A separate **`events` stream** multiplexes the daemon's diagnostic event ring (`state.events`, `MAX_EVENTS = 256`, drop-oldest, `event_seq`/`events_dropped` counters in `main.rs:728-740`) to subscribers that want observation metadata — `data_from_mesh` summaries, `delivery_event`, `diagnostic`, `gw_ingress` outcomes, `rx_drop`/`rx_conflict` — without payload rights. The two streams are deliberately distinct: payload delivery is ACL-gated (`READ_PAYLOAD`), cursor-resumable and at-most-once per subscription; the event stream is a volatile diagnostic surface (same trust level as the existing unauthenticated `EVENTS` verb), at-most-once, with an `overflow` marker instead of cursors.

This keeps the issue's §3 layering explicit: a payload that could not be honestly stored (conflict, oversize, network cap) is an **event**, never a `message` notification; `HOST_RAM_RETAINED` remains the strongest receive evidence and socket delivery is never promoted to application receipt (§5.7).

### Rejected alternatives

- **Copy-per-subscriber queue as the primary backlog.** A second 128-entry payload copy per subscriber costs ≤16 × 256 KiB worst-case RAM while adding no durability the log does not already have, and makes "the record is still fetchable via `messages.read`" a lie once the copy is dropped. The staging queue exists only to decouple socket write rate from ingest bursts; loss is marked at the queue boundary (recoverable) and the log boundary (terminal).
- **Disconnect-on-overflow.** Dropping the whole connection punishes a merely-slow reader and loses its other subscriptions. Chosen instead: drop-oldest in the staging queue with an explicit `gap` marker, and never let a subscriber stall ingest or other clients (`host.md` §6). Genuine socket stall remains covered by the existing 2 s write timeout (`CLIENT_WRITE_TIMEOUT`, `main.rs:48`) — a transport teardown, not an overflow policy.
- **Exactly-once delivery claims / ack-protocol.** No application ack exists; cross-restart dedup is impossible while the log is RAM-only. §5.4 states what is and is not claimable.
- **Wildcard/multi-network subscriptions.** ACLs are per-network; `*` would require per-record re-authorization and hide which networks a principal may see. One network per messages subscription; up to 4 per connection covers the realistic fan-out.
- **Sharing the `EVENTS` ring for payloads.** Rejected already in 02 §1; unchanged — the ring is diagnostic and its entries stay payload-free.

## 5.2 Data contract

### 5.2.1 Message record (unchanged from `messages.read`)

The record shape in notifications is **byte-identical** to the `records[]` elements of `messages.read` (`api1.rs:479`), including the per-record `cursor` — the cursor is the resume position *after* that record, so a client can feed it back into `messages.read` or `messages.subscribe` verbatim:

```json
{"v":1,"network":"0000000000000001","gateway":"0000000000000002","origin":"0000000000000003","message":{"session":"00000004","sequence":"0000000000000005"},"payload_hex":"00ff80","payload_len":3,"cursor":"AQAAAAAAAAAB…","endpoint_kind":"gateway_mirror","evidence":"HOST_RAM_RETAINED","assurance":{"profile":"UNKNOWN","origin":"unverified"}}
```

Payload is lowercase hex, `payload_len` bytes, 0–128 B, never transcoded (non-UTF-8 and 0x00 pass through). The current USB receive body has no effective gateway security profile or per-frame origin verification result; `UNKNOWN` means the host lacks that evidence, regardless of Site Authority or ledger state.

### 5.2.2 Metadata record (`payloads:false` subscriptions)

A metadata subscription requires only `READ_OPERATION` (payload rights stay `READ_PAYLOAD`). The record omits `payload_hex` and adds a digest — same rule as `operations.get`, which exposes `canonical_hash` but never the body (`api1.rs:1785`):

```json
{"v":1,"network":"0000000000000001","gateway":"0000000000000002","origin":"0000000000000003","message":{"session":"00000004","sequence":"0000000000000005"},"payload_len":3,"payload_sha256":"<64 hex>","cursor":"AQAAAAAAAAAB…","endpoint_kind":"gateway_mirror","evidence":"HOST_RAM_RETAINED","assurance":{"profile":"UNKNOWN","origin":"unverified"}}
```

### 5.2.3 Notification line envelope

Notifications are bare JSON lines on the socket — no `API1 ` prefix (responses carry none either). Demux rule for clients: a line with `"ok"` is a response (correlated by `request_id`); a line with `"subscription"` and `"kind"` is a notification. Every notification carries a per-subscription ordinal `n` (assigned at socket-write time, monotone from 1) — combined with `kind:"gap"`/`"overflow"` ranges this makes any loss in the pipe auditable. Notification lines are bounded: **≤ 8192 B** (`ipc`-style bound; a serialized record line is < 1 KiB at the 128 B payload ceiling).

| `kind` | Stream | Body |
|---|---|---|
| `"message"` | messages | `"record":{…§5.2.1…}` |
| `"message_meta"` | messages (`payloads:false`) | `"record":{…§5.2.2…}` |
| `"gap"` | messages | `"cause":"start_position"\|"queue_overflow"\|"log_evicted"`, `"lost_from":u64`, `"lost_to":u64`, `"resume_cursor":"…"`, `"recoverable_via_read":bool`, `"ms":u64` |
| `"heartbeat"` | both | `"cursor":"…"`, `"tail_seq":u64` (messages) or `"event_seq":u64`, `"dropped_total":u64` (events); `"ms":u64` |
| `"event"` | events | `"event":{…}` — verbatim ring entry (already carries `seq`,`ms`,`kind` fields) |
| `"overflow"` | events | `"lost_from":u64`, `"lost_to":u64`, `"dropped_total":u64`, `"resume_seq":u64`, `"ms":u64` |
| `"ended"` | both | `"reason":"acl_view_changed"\|"unauthorized"\|"daemon_shutdown"`, `"delivered":u64`, `"dropped":u64` |

Rules: `gap.lost_from..=lost_to` is the closed log-seq range skipped on **this stream** — `recoverable_via_read:true` when the range may still sit in the log (staging-queue drop), `false` when it passed `evicted_through`. `resume_cursor` is a normal read cursor positioned after `lost_to`. `overflow.resume_seq` is the next event seq that will be delivered. Markers and `ended` are control lines — they are never dropped (§5.5).

## 5.3 Socket protocol (API1 additions)

All additions are ordinary `API1 ` requests on the existing Unix socket — same 8192 B request / 65536 B response / depth-8 / strict-envelope rules (`api1.rs:48-53`), same `v:1` envelope, same `request_id`. Three new methods plus one optional parameter:

### 5.3.1 `messages.subscribe`

```text
-> API1 {"v":1,"request_id":"s1","method":"messages.subscribe","params":{
     "stream":"messages",                    // optional, default "messages"; "events" selects the diagnostic stream
     "network":"0000000000000001",           // required for messages; forbidden for events
     "from":"earliest"|"latest",             // exactly one of from|cursor (same rule as messages.read)
     "cursor":"<base64url>",                 //   messages.read-issued token; forbidden for events
     "on_gap":"fail"|"skip",                 // default "fail" — start-position gap handling only
     "payloads":true,                        // default true → READ_PAYLOAD; false → READ_OPERATION, meta records
     "filter":{"origins":["16hex",…≤8],"gateways":["16hex",…≤8]},   // optional; absent = all
     "heartbeat_ms":10000,                   // 0 disables; range 1000..=60000, default 10000
     "durable":false                         // optional; only false/absent legal — true → UNSUPPORTED
   }}
<- {"v":1,"request_id":"s1","ok":true,"result":{
     "subscription":"sub0000000000000007",
     "stream":"messages",
     "network":"0000000000000001",
     "payloads":true,
     "epoch":"<32-hex>",                     // the receive-log epoch all cursors are minted under
     "acl_revision":1,
     "position":{"cursor":"<tok>","oldest_cursor":"<tok>","tail_cursor":"<tok>"},
     "queue":{"max_notifications":128,"max_bytes":262144,"line_max_bytes":8192},
     "heartbeat_ms":10000}}
```

`stream:"events"` variant:

```text
-> {"v":1,"request_id":"s2","method":"messages.subscribe","params":{
     "stream":"events",
     "from":"earliest"|"latest",             // default "latest"; no cursor exists for events
     "filter":{"kinds":["data_from_mesh","diagnostic",…≤16]}}}      // exact event-kind names; absent = all
<- {"v":1,"request_id":"s2","ok":true,"result":{
     "subscription":"sub0000000000000008","stream":"events",
     "position":{"event_seq":412,"oldest_event_seq":157,"dropped_total":23},
     "queue":{…same…},"heartbeat_ms":10000}}
```

After the `ok` response line is flushed, the subscription activates and notification lines begin (§5.8 ordering rule: **never before the response**). The connection remains usable for further requests — including more `messages.subscribe` (≤4 per connection), `messages.read`, `messages.unsubscribe`.

Per-stream parameter legality (strict schema — a parameter invalid for the selected stream is `INVALID_ARGUMENT`, never ignored): `heartbeat_ms` applies to both streams; `network`/`cursor`/`on_gap`/`payloads`/`durable`/`filter.origins`/`filter.gateways` are messages-only; `filter.kinds` is events-only; a start position (exactly one of `from`|`cursor`) is required for messages, while `from` is optional and defaults to `"latest"` for events.

### 5.3.2 `messages.unsubscribe`

```text
-> API1 {"v":1,"request_id":"u1","method":"messages.unsubscribe","params":{"subscription":"sub0000000000000007"}}
<- {"v":1,"request_id":"u1","ok":true,"result":{"ended":true,"delivered":57,"dropped":2,"gaps":1,"lifetime_ms":18342}}
```

Subscription ids are scoped to the owning connection: an id minted on another connection resolves `NOT_FOUND` (no cross-connection oracle, same discipline as `operations.get` for foreign records).

### 5.3.3 `messages.subscriptions`

```text
-> API1 {"v":1,"request_id":"l1","method":"messages.subscriptions","params":{}}
<- {"v":1,"request_id":"l1","ok":true,"result":{"subscriptions":[
     {"id":"sub0000000000000007","stream":"messages","network":"0000000000000001",
      "payloads":true,"position_cursor":"<tok>","delivered":57,"dropped":2,"gaps":0,
      "queued":3,"queued_bytes":1904,"created_ms":…},
     {"id":"sub0000000000000008","stream":"events","event_seq":412,"delivered":12,
      "dropped":0,"gaps":0,"queued":0,"queued_bytes":0,"created_ms":…}]}}
```

Own connection only — the listing can never reveal another principal's filters or positions.

### 5.3.4 `messages.read` long-poll (additive)

```text
-> …"method":"messages.read","params":{"network":"…","cursor":"<tok>","limit":32,"wait_ms":15000}
```

`wait_ms` ∈ 0..=15000, default 0 (identical to today). With `wait_ms > 0` and a caught-up position the daemon waits until ≥1 retained record exists beyond the cursor or the deadline passes, whichever first; timeout returns a normal empty batch plus `"wait_expired":true` and the caller's unchanged `next_cursor`. Position errors (`CURSOR_GAP`, `INVALID_CURSOR`, `CURSOR_EPOCH_CHANGED`, `CURSOR_SCOPE_MISMATCH`) return **immediately** — a wait never delays an honest error. Implemented on the subscription hub's change condvar; never holds the receive-log lock across the wait.

### 5.3.5 Error codes

Existing codes apply unchanged; new/extended uses:

| Code | When | `retryable` |
|---|---|---|
| `INVALID_ARGUMENT` | bad param type/range; `cursor`+`from` together; `network` on `stream:"events"`; `kinds` name not a known event kind; `origins`/`gateways` entry not 16-hex or >8 entries; `heartbeat_ms` out of range; `wait_ms` >15000 | false |
| `AuthorizationFailed` | messages sub without `READ_PAYLOAD` (`payloads:true`) or `READ_OPERATION` (`payloads:false`) on the network | false |
| `NO_CAPACITY` | subscription caps exceeded (per-connection 4, per-principal 4, total 16) | true |
| `UNSUPPORTED` | `durable:true`, or any future capability advertised as `false` | false |
| `NOT_FOUND` | unknown/foreign `subscription` id | false |
| `INVALID_CURSOR` / `CURSOR_SCOPE_MISMATCH` / `CURSOR_EPOCH_CHANGED` / `CURSOR_GAP` | same semantics and `detail` shape as `messages.read` (`api1.rs:409-463`), including `oldest_cursor`/`tail_cursor` in the epoch/gap details | false |

### 5.3.6 Capability advertisement

`capabilities.get` additions (all honest — emitted only when the code lands):

```json
"methods":{ … ,"messages.subscribe":true,"messages.unsubscribe":true,"messages.subscriptions":true}
"receive":{ … ,"mode":"cursor_poll","push":"subscribe_v1","streams":["messages","events"],
  "subscriptions_per_connection":4,"subscriptions_per_principal":4,"subscriptions_total":16,
  "subscription_queue_events":128,"subscription_queue_bytes":262144,"notify_line_max_bytes":8192,
  "heartbeat_ms":{"min":1000,"max":60000,"default":10000},"long_poll_ms_max":15000,
  "durable_receive":false,"durable_subscription":false,"pc_service_destination":false}
```

`mode` stays `"cursor_poll"` for compatibility (it describes the read path); `push` names the new mechanism. `rx_events_v1:false` and `ingress_loss_observable:false` are **unchanged** — gateway-side drops before `DataFromMesh`/`GATEWAY_INGRESS` remain unprovable; the `events` stream only covers post-decode daemon observations (see §5.9). A matching `contracts.json` `receive.*` block addition is proposed in §5.12.

## 5.4 Cursor and durability semantics

### 5.4.1 Positions

- Message subscriptions reuse the `messages.read` cursor token verbatim: 41-byte body `version(1)|network(8)|acl_view(8)|epoch(16)|last_scanned(8)`, base64url no-pad (`receive_log.rs:428-521`). `position` is a `last_scanned` seq — the next notification is the first retained record with `seq > position`.
- `from:"earliest"` → position 0 (replays all retained); `from:"latest"` → tail at subscribe time (live-only). Registration takes the position snapshot **under the receive-log lock** so an ingest can never slip between snapshot and registration.
- Cursor path runs the identical validation as `messages.read`: decode → `CURSOR_SCOPE_MISMATCH` on network/acl_view divergence → `CURSOR_EPOCH_CHANGED` (with fresh `oldest_cursor`/`tail_cursor`, `loss_count:null`) on epoch mismatch → probe read: `Future` → `INVALID_CURSOR`; `Gap` → `CURSOR_GAP` error or, with `on_gap:"skip"`, a successful subscribe whose first notification is `gap{cause:"start_position",…}` then delivery continues from the oldest retained record.
- The events stream has **no cursor** — positions are bare `event_seq` values, valid only while the owning connection lives. A reconnecting events consumer re-subscribes `from:"latest"` (or `earliest` to drain the ring); there is no resume contract to defend.

### 5.4.2 Volatile vs. durable cursor

Cursors are **volatile**: the log epoch is a fresh 128-bit value per daemon start (`receive_log.rs:208`), so a cursor from a previous run provably fails `CURSOR_EPOCH_CHANGED` rather than aliasing recycled sequence space. Durability is advertised and enforced as follows:

- `durable_receive:false`, `durable_subscription:false` in capabilities — a `durable:true` subscribe param (or any future durable-cursor request) is refused `UNSUPPORTED`, never silently downgraded.
- The events ring, subscriptions, and their positions are RAM-only; daemon restart ends every stream (sockets EOF — no marker can be delivered to a dead peer).
- A future durable receive store (`--rx-store`, mirroring `--op-store`) would mint a **durable cursor class** (distinct token version byte) so a durable token can never be presented where a volatile one was expected, and vice versa. That is out of scope here; the refusal path is defined now so clients do not invent it.

### 5.4.3 Ordering, at-least-once, exactly-once — honest matrix

- **Ordering**: notifications on one messages subscription are strictly `seq`-ordered within the epoch (per-network seq is a total order; the pump advances `position` monotonically). `gap` markers appear at the position where the loss occurred. Events stream: `seq`-ordered. Between subscriptions on one connection, and vs. request/response lines: interleaved arbitrarily — clients must demux by line shape, never by order.
- **Per subscription**: at-most-once — the pump emits each retained record at most once; filtered-out records advance `position` without emitting (a filter is a view, not a second log, so skipping a filtered record is not a `gap`).
- **Reconnect, same epoch**: subscribe with the last received `record.cursor` → resumes exactly at the next unseen record. If the client's persisted cursor lags what it already consumed (e.g., crash before persisting), previously seen records re-arrive → **at-least-once**; client-side dedup key is the MessageKey `(network, origin, message.session, message.sequence)` or the per-record `cursor`. The daemon never claims it deduplicated the client's view.
- **Daemon restart**: new epoch → `CURSOR_EPOCH_CHANGED`, `loss_count:null` — the unquantifiable loss is never fabricated into a count. Client resyncs explicitly (`from` choice is its own policy).
- **Server-side dedup**: the log's 60 s MessageKey window still folds identical re-observations into one record (`receive_log.rs:252-283`); dedup and delivery are orthogonal — a `Duplicate` ingest emits no notification (visibility lives on the events stream via `gw_ingress`/`rx_*` entries).
- **Exactly-once is not claimed.** It would require an application-level ack plus a durable cursor store; neither exists. A client can build effective-once processing by persisting `record.cursor` after handling each notification — across reconnects within an epoch — and treating any `gap`/`overflow`/`CURSOR_*` as "unknown coverage, resync".

## 5.5 Backpressure model

Bounds (proposed contract keys, aligned with `host.md` §8):

| Bound | Value | Scope |
|---|---|---|
| `SUBS_PER_CONNECTION` | 4 | per socket |
| `SUBS_PER_PRINCIPAL` | 4 | across all of a uid's connections (same-accounting rule as `MAX_CLIENTS_PER_PRINCIPAL`) |
| `SUBS_TOTAL` | 16 | daemon-wide |
| `SUB_QUEUE_EVENTS` | 128 notifications | per subscription staging queue |
| `SUB_QUEUE_BYTES` | 256 KiB | per subscription staging queue |
| `SUB_CONTROL_RESERVE` | 8 lines | per subscription — markers/`ended`/`heartbeat` bypass the data bound, bounded separately |
| `NOTIFY_LINE_MAX` | 8192 B | per serialized line |
| `SUB_PAGE` | 32 records | per drain pass per subscription (== `PAGE_LIMIT`) |
| `WAIT_MS_MAX` | 15000 ms | `messages.read` long-poll |
| `HEARTBEAT_MS` | 1000–60000, default 10000 | per subscription |
| existing | 32 clients / 4 per principal / 2 s write timeout | unchanged |

Overflow semantics, in pipeline order:

1. **Staging queue full** (socket draining slower than ingest): the pump drops the oldest **record** notifications, and each contiguous dropped run is replaced *in place* by one `gap{cause:"queue_overflow", lost_from, lost_to, resume_cursor, recoverable_via_read:true}` marker — the marker sits at the queue position where the loss occurred, so it always precedes the first record delivered after the skipped range. Control lines (markers, `heartbeat`, `ended`) are never dropped; they charge against the separate `SUB_CONTROL_RESERVE` bound, and if that too is full the connection is dead for practical purposes and the write-timeout path (3) takes it down.
2. **Log eviction ahead of position**: `gap{cause:"log_evicted", recoverable_via_read:false}` — terminal loss, named with the exact reclaimed range. The subscription keeps running; it does not silently jump.
3. **Socket write stall > 2 s** (`CLIENT_WRITE_TIMEOUT`): transport failure → connection closed → all its subscriptions torn down (§5.6). Not an overflow policy — a dead-peer cleanup.
4. **Subscription caps**: `NO_CAPACITY` (retryable) at subscribe time — never an implicit overflow.
5. **Upstream**: ingest never blocks on subscribers — the hub notify is an O(1) dirty-flag + condvar broadcast outside the log lock. USB receive, the dispatch thread, and other clients are structurally isolated from subscriber speed (`host.md` §6, RX05).

## 5.6 Multi-consumer semantics

- **Fan-out**: each ingest → one hub notify → each matching subscription independently serializes its own notification. `K` subscriptions on a network produce `K` deliveries; filters are per-subscription (`origins`/`gateways` on messages; `kinds` on events).
- **Ownership**: a subscription belongs to its connection. `unsubscribe`/`subscriptions` see only the caller's own ids; foreign ids → `NOT_FOUND`.
- **Cleanup**: connection EOF, read/write error, `QUIT`, or thread panic → the connection's `ClientGuard`-style cleanup removes all its subscriptions and frees principal/global counts; the pump exits when `conn_alive` clears. No subscription outlives its socket.
- **Server-initiated end**: `ended{reason:"acl_view_changed"|"unauthorized"}` when a lazy per-pass ACL re-check fails (ACL reload does not exist today — `acl.rs:84` loads once — but the contract is defined for when it does); `ended{reason:"daemon_shutdown"}` is reserved (no graceful shutdown exists; today a dying daemon is plain EOF).
- **Fairness**: the per-connection pump drains ≤`SUB_PAGE` records per subscription per pass, round-robin — one flooded subscription cannot starve its siblings; staging queues are per-subscription so one sub's backlog cannot consume another's bound.
- **Delivery counters**: `delivered` (lines written), `dropped` (record lines lost from the staging queue), `gaps` (markers emitted) — returned by `unsubscribe` and `subscriptions`, so a client can audit its own loss after the fact.

## 5.7 Message stream vs. event stream — evidence boundary

| | `stream:"messages"` | `stream:"events"` |
|---|---|---|
| Content | verified payload records (or metadata under `payloads:false`) | daemon diagnostic ring entries — `data_from_mesh` summaries (no body), `delivery_event`, `diagnostic`, `gw_ingress` outcomes, `rx_drop`, `rx_conflict`, `adapter`, `session_drop`, `dispatch`, `error`, `credit_*`, `host_ops_rx`, `frame`, `decode_error`, `keepalive` |
| Grant | `READ_PAYLOAD` / `READ_OPERATION` per network | none — same surface as the unauthenticated `EVENTS` verb (socket file mode `0600` is the outer boundary, `main.rs:1997-2025`) |
| Position | shared cursor tokens; resume across reconnect within an epoch | `event_seq` only; no resume contract |
| Loss signal | `gap` marker with seq range + recoverable flag | `overflow` marker with seq range + cumulative `dropped_total` |
| Claim | `HOST_RAM_RETAINED` (unchanged) | none — observation only |

Socket delivery of a notification is **not** an application receipt: `HOST_RECEIVE_RAM` scope ends at ReceiveLog storage + ingress ACK (`03-explicit-gateway.md` §3.1); whether the PC app read, stored, or acted is the app's own evidence domain. `pc_service_destination:false` stays false — a payload handed to a subscriber is never reported upstream as "delivered to the application".

## 5.8 Wire-ordering and lifecycle rules

1. The `ok` response to `messages.subscribe` is flushed **before** any notification of that subscription is written — registration sits in a `pending` state until the response is on the wire, then activates. A client can therefore bind `subscription` ids to streams without a race.
2. Notifications of *other* subscriptions on the same connection may interleave with any response; both are complete JSON lines, demuxed by shape.
3. Within one subscription: `n` strictly increasing per emitted line; record `seq`s strictly increasing; a `gap` marker always precedes the first record delivered after the skipped range; `ended` is always the last line of a server-ended subscription.
4. A second `messages.subscribe` reusing a live subscription id is impossible (ids are minted, never chosen); `unsubscribe` of an already-ended id → `NOT_FOUND`.
5. `QUIT`/EOF on a subscribed connection is normal teardown — no `ended` is owed to a peer that is gone.
6. On the wire nothing changes for non-subscribing clients: requests, responses, and the legacy verb surface are untouched.

## 5.9 Compatibility and unchanged surfaces

- `messages.read` request/response/cursor/error contract is unchanged; `wait_ms` is the only additive parameter and defaults to today's behavior.
- `EVENTS`, `DELIVERIES`, `NODES`, `STATUS`, `ADAPTER`, `AUTHORITY`, `AUTONOMY`, `SEND`, `QUIT` — unchanged.
- The TUI (`routeloom-tui/src/client.rs`) keeps its `POLL_COMMANDS` poll pattern — it is an observer, and subscription support there is an optional later change (e.g., replacing `EVENTS` polling with `stream:"events"`), not part of this design.
- `routeloomctl receive` unchanged; new `subscribe` verb streams lines until EOF/`--count` (§5.11).
- USB/firmware: **no new host-ops subcommands**. The receive path (verified `DataFromMesh`, digest-proven `GATEWAY_INGRESS` 0x11 → `ReceiveLog` → ACK 0x12) already lands everything the streams serve. The diagnostic HostOps 0x30/0x31 lane (`usb_host_ops.hpp:76-77`, `kCapM1DiagnosticsV1`) and the extended `DataFromMesh` body with `rx_event_seq` proposed in 02-receive-api §4 remain separate capabilities — until they exist, `ingress_loss_observable:false` and `rx_events_v1:false` keep their honest values and the streams only cover post-decode visibility.
- 60 s ingest dedup, conflict-first-wins, and all reclaim rules are unchanged — the streams inherit them, they do not alter them.

## 5.10 Failure matrix

| # | Trigger / state | Wire result | Client's next step |
|---|---|---|---|
| F01 | First subscribe, `from:"earliest"`/`"latest"` | `ok` + position block; replay notifications then live | none |
| F02 | Subscribe with a valid `messages.read` cursor | resumes at `last_scanned+1`; no dup, no skip | none |
| F03 | Reconnect same epoch, re-subscribe last `record.cursor` | resumes exactly; possibly replays already-seen records if the client's persisted cursor lagged | dedup on MessageKey/cursor |
| F04 | Cursor from a previous daemon run | `CURSOR_EPOCH_CHANGED` + `loss_count:null` + fresh oldest/tail cursors | explicit re-subscribe (`from` choice is client policy) |
| F05 | Start position older than `evicted_through` | `on_gap:"fail"` → `CURSOR_GAP` + `lost_from/lost_to` + oldest/tail cursors; `"skip"` → subscribe OK, first line `gap{cause:"start_position"}` then live | read policy decision |
| F06 | Cursor beyond tail | `INVALID_CURSOR` (never rounded into validity) | re-anchor |
| F07 | Slow consumer (socket drains < ingest rate) | staging fills → `gap{queue_overflow, recoverable_via_read:true}`; further lag → `gap{log_evicted, recoverable_via_read:false}`; stream continues | optionally `messages.read` the lost range while retained |
| F08 | Socket write stall > 2 s | connection dropped; all its subscriptions removed; counts restored | reconnect + re-subscribe (F03/F04 rules) |
| F09 | 5th subscription on one connection / per-principal or global cap | `NO_CAPACITY` `retryable:true` | unsubscribe or retry |
| F10 | No `READ_PAYLOAD` on network (`payloads:true`) | `AuthorizationFailed` | request grant or use `payloads:false` under `READ_OPERATION` |
| F11 | ACL revision change mid-stream (future reload) | `ended{reason:"acl_view_changed"}` + counters | re-subscribe under the new view |
| F12 | USB adapter disconnects | no new message records; stream stays open; `heartbeat` keeps position fresh; `adapter`/`session_drop` visible on events stream | wait for reconnect; records arriving after re-link flow normally |
| F13 | Ingest `Duplicate` (60 s dedup fold) | **no** message notification; `gw_ingress`/`rx` coverage on events stream only | none — the record is already held |
| F14 | Ingest `Conflict`/`RejectedOversize`/`RejectedNetworkCap` | never a `message`; diagnostic event on the events stream only | none (honest non-storage) |
| F15 | Events ring churn > 256 ahead of a slow events subscriber | `overflow{lost_from,lost_to,dropped_total,resume_seq}` then live | none — diagnostic loss, not data loss |
| F16 | `wait_ms` timeout, caught-up position | normal empty batch + `wait_expired:true`, unchanged `next_cursor` | re-issue read |
| F17 | `wait_ms` with a gap/epoch/future cursor | immediate `CURSOR_GAP`/`CURSOR_EPOCH_CHANGED`/`INVALID_CURSOR` — never delayed by the wait | per F04/F05/F06 |
| F18 | Filter matches nothing for a long period | no notifications; `heartbeat` shows advancing `tail_seq`/cursor | none — silence is honest, not a stall |
| F19 | Foreign/other-connection `subscription` id in `unsubscribe` | `NOT_FOUND` | none (no existence oracle) |
| F20 | `durable:true` on subscribe | `UNSUPPORTED` (`durable_subscription:false` advertised) | volatile subscribe or future durable store |
| F21 | Daemon shutdown mid-stream | socket EOF (no `ended` — no graceful shutdown exists); subscriptions die with the process | reconnect → F04 path |

## 5.11 Implementation checklist (design → code)

New module **`host/routeloom-host/src/subscribe.rs`**:

- `pub struct SubscriptionHub { inner: Mutex<HubInner>, changed: Condvar }` — registry `{conn_id → ConnSubs}`, `next_sub` counter tagged with `host_boot` exactly like `ConfigOps::with_boot` (`dispatch.rs:270`) so a token can never alias across daemon runs: `id = (tag32<<32)|seq`, `bit0|1`; `fn token(id) → "sub%016x"` + `parse_token`.
- `pub struct Subscription { id, kind: SubKind, uid: Option<u32>, acl_view: u64, position: u64, created_ms, last_emit_ms, heartbeat_ms, delivered, dropped, gaps, pending: bool }`; `enum SubKind { Messages(MsgFilter), Events(EvFilter) }`; `struct MsgFilter { network: u64, origins: Option<Vec<u64>>, gateways: Option<Vec<u64>>, payloads: bool }`; `struct EvFilter { kinds: Option<Vec<String>> }`.
- `fn subscribe(conn_id, uid, kind, position, acl_view, now) → Result<u64, CapacityDeny>` enforcing the three caps; `fn activate(conn_id, id)` (pending→live, §5.8 rule 1); `fn unsubscribe`, `fn list(conn_id)`, `fn remove_conn(conn_id)`; `fn notify(&self)` (dirty flag + `changed.notify_all()`); `fn wait(&self, seen_epoch, dur)`.
- `struct StageQueue` — per-subscription bounded deque with the §5.5 drop-oldest/coalesced-marker rule and control reserve.
- `fn pump_connection(state: Arc<State>, conn_id: u64, writer: Arc<Mutex<UnixStream>>, conn_alive: Arc<AtomicBool>)` — the §5.5/§5.6 loop: condvar wait (min heartbeat due) → per-sub ACL re-check → `receive_log.read(network, position, SUB_PAGE, now, check_position:true)` → map `Gap`/`Batch` to staged lines → drain queue to the socket under the writer mutex; events path reads `state.events` seqs > position.
- Lock order contract: **never hold `receive_log`/`state.events` while acquiring `hub`** — notify happens after the producing lock is released (mirrors the `DispatchInbox` discipline).

**`api1.rs`**:

- `ApiContext` += `subscriptions: &'a SubscriptionHub`, `conn_id: u64`.
- `handle` keeps its `String` signature for all existing tests; add `handle_conn(body, ctx) → (String, Option<ConnEffect>)` where `ConnEffect::Subscribed{id}` tells `serve_client` to activate post-flush (a failed write discards the pending sub with connection cleanup).
- `messages_subscribe` / `messages_unsubscribe` / `messages_subscriptions` with §5.3 param whitelists; extract `resolve_start_position(log, network, from, cursor, now)` shared with `messages_read` (same cursor validation ladder).
- `messages_read`: `wait_ms` param + condvar wait loop (predicate re-check under the log lock, never held across `wait_timeout`).
- Extract `record_json(record, cursor)` and `record_meta_json(record, cursor)` from `read_result` for reuse by the pump serializer.
- `capabilities` method/recv blocks per §5.3.6; `LATER_PHASE_METHODS` unchanged.

**`main.rs`**:

- `State.subscriptions: SubscriptionHub` (minted with `host_boot`); `next_conn_id: Arc<AtomicU64>`.
- `serve_client`: wrap the writer in `Arc<Mutex<UnixStream>>` (line-atomic writes shared with the pump); after each `handle_conn` response flush, apply `ConnEffect`; spawn `pump_connection` lazily on first activation; extend `ClientGuard` cleanup to `hub.remove_conn(conn_id)`.
- Notify hooks: `receive_ingest` after `IngestOutcome::Stored` (`main.rs:1145-1162`), `gateway_ingress_ack` stored path (`dispatch.rs:2416-2449`), and inside `push_event` after the ring append (`main.rs:728-740`) for the events stream.

**`routeloomctl/src/main.rs`**: `subscribe --network <16hex> [--from earliest|latest | --cursor CUR] [--on-gap fail|skip] [--meta] [--events [--kinds a,b,c]] [--heartbeat-ms N] [--count N]` — builds the API1 request; unlike one-shot commands it keeps the connection open and prints each line until EOF, error, or `--count`; Ctrl-C/EOF is the unsubscribe (daemon cleans up on disconnect).

**`routeloom-tui`**: no change in this phase.

**Contracts/tests ledger (proposed, not edited by this doc)**: `contracts.json` `receive.*` += `push:"subscribe_v1"`, `streams`, `subscriptions_*`, `subscription_queue_*`, `notify_line_max_bytes`, `heartbeat_ms`, `long_poll_ms_max`, `durable_subscription:false`; `scenarios.json` += SUB01–SUB21 below.

## 5.12 Test plan

Unit tests live beside the code (`subscribe.rs`, `api1.rs` `#[cfg(test)]`); socket-level tests drive the pump over `UnixStream::pair()` — no on-disk socket needed. RX01–RX08 fixtures are reused for the unchanged poll path.

| Case | Drives | Expect |
|---|---|---|
| SUB01 | subscribe `latest`, then ingest 3 records | 3 `message` lines in seq order, `n` 1-3, record shape == `messages.read` |
| SUB02 | subscribe `earliest` on populated log | replay then live, no duplication at the seam |
| SUB03 | subscribe with mid-log cursor | only `seq > cursor`; first line is the next record |
| SUB04 | stale cursor + `on_gap:"fail"`/`"skip"` | `CURSOR_GAP` detail identical to read / `gap{start_position}` then delivery |
| SUB05 | restart, old-epoch cursor | `CURSOR_EPOCH_CHANGED`, `loss_count:null` |
| SUB06 | throttled socket, ingest faster than drain | `gap{queue_overflow}` marker(s) with exact ranges; sibling sub unaffected; ingest never stalls |
| SUB07 | socket write blocked > 2 s | connection torn down; `subscriptions` on a new conn is empty; counts restored |
| SUB08 | 5th sub on conn; 5th across a uid's connections; 17th global | `NO_CAPACITY` retryable |
| SUB09 | sub without `READ_PAYLOAD`; `payloads:false` under `READ_OPERATION` | `AuthorizationFailed`; `message_meta` lines with `payload_sha256`, no `payload_hex` |
| SUB10 | `origins`/`gateways` filters | only matching records emitted; `position` advances past filtered records; heartbeat reflects tail |
| SUB11 | two subs same network, different filters | independent copies and counters |
| SUB12 | `unsubscribe` mid-stream | stats response; zero further notifications; slot freed |
| SUB13 | client killed mid-stream | hub empty; principal/global counts restored (panic path too — RAII guard) |
| SUB14 | `stream:"events"`: `earliest` replay, `kinds` filter, >256 churn | verbatim ring entries, filtered; `overflow` marker with `dropped_total`; `cursor`/`network` params → `INVALID_ARGUMENT` |
| SUB15 | quiet stream + `heartbeat_ms` | heartbeat at interval carrying current `tail_seq`/cursor |
| SUB16 | `wait_ms`: data present / timeout / gap cursor | immediate batch / `wait_expired:true` / immediate `CURSOR_GAP` |
| SUB17 | requests on a subscribed connection | responses interleave with notifications; demux by `ok` vs `subscription` |
| SUB18 | subscribe-response ordering | no notification precedes the `ok` line (pending→activate) |
| SUB19 | `durable:true` | `UNSUPPORTED` |
| SUB20 | notification line bound | serialized line ≤ 8192 B (assert; oversized → marker, never truncated JSON) |
| SUB21 | params fuzz: unknown keys, >8 origins, bad kinds, `network` on events, `from`+`cursor` together | `INVALID_ARGUMENT` each, error envelope schema-valid (`assert_error_schema` harness, `api1.rs:2040`) |

Acceptance mapping to issue #7 §完了条件: F01–F21 cover 初回取得/再接続/cursor期限切れ/daemon再起動/遅い利用者/容量不足; SUB01–SUB21 are the executable form; retention/permission/evidence boundaries are §5.3–§5.7; the only intentionally uncovered loss window remains gateway-side pre-ingest drops (`ingress_loss_observable:false` — unchanged, honestly advertised).
