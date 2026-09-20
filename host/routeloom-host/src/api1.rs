//! IPC v1 (`API1 `) request handling — the application-facing line protocol
//! of the daemon's existing Unix socket.
//!
//! One line starting with `API1 ` carries one UTF-8 JSON request; the daemon
//! answers with one JSON line:
//!
//! ```text
//! -> API1 {"v":1,"request_id":"r1","method":"messages.read","params":{...}}
//! <- {"v":1,"request_id":"r1","ok":true,"result":{...}}
//! <- {"v":1,"request_id":"r1","ok":false,"error":{"code":"...","detail":{...},"retryable":false}}
//! ```
//!
//! Contract bounds (contracts.json `ipc.*`): request ≤ 8192B including the
//! newline, response ≤ 65536B, JSON depth ≤ 8. The shared parser already
//! rejects duplicate object keys, non-RFC-8259 numbers (incl. bare NaN) and
//! invalid UTF-8; this module adds the envelope schema: `v`, `request_id`
//! (1–64 printable ASCII chars), `method`, optional `params` object — any
//! other field is rejected, never ignored.
//!
//! Methods in this phase: `capabilities.get` (unauthenticated),
//! `messages.read` (READ_PAYLOAD), `operations.open_epoch` + `messages.submit`
//! (SEND), `operations.get`/`operations.get_by_key` (READ_OPERATION) and
//! `operations.cancel` (owning principal with SEND). The principal always
//! comes from the socket peer's OS credential, never from request JSON.

use crate::acl::{self, Acl};
use crate::canonical;
use crate::config::{ConfigOutcome, ConfigRequest};
use crate::receive_log::{
    hex_lower, Cursor, IngestOutcome, ReadOutcome, ReceiveLog, CURSOR_MAX_DECODED_BYTES, PAGE_LIMIT,
};
use crate::send_store::{
    AdmissionLimiter, CancelOutcome, CapacityStatus, DispatchState, OpIdentity, OpenEpochError,
    OperationStore, RateDeny, StoredOperation, SubmitOutcome,
};
use routeloom_json::{escape_string, Json};
use routeloom_protocol::host_ops::ConfigOpsResult;
use routeloom_wire::endpoint::{ConfigField, ConfigFieldType, ConfigPhase, ConfigReason};
use std::sync::Mutex;

use crate::dispatch::ConfigOpRecord;

use crate::SessionInfo;

// contracts.json `ipc.*`
pub const REQUEST_MAX_BYTES: usize = 8192;
pub const RESPONSE_MAX_BYTES: usize = 65536;
pub const JSON_MAX_DEPTH: usize = 8;
pub const REQUEST_ID_MAX: usize = 64;

/// Per-request inputs the dispatch layer needs. `uid` is the socket peer's
/// OS credential (None when the platform cannot supply one — default deny).
/// The store is generic over `OperationStore` so CAP-I1 can swap the memory
/// table for SQLite without touching this dispatch layer. `rate_limiter`
/// is daemon-wide (04 §4: per-principal and global budgets), so limits
/// hold across connections. `session`/`gateway_lane` expose the live USB
/// session and the dispatcher's host-registration mirror — read-only here:
/// the schema-2 binding always comes from the daemon's own lane state,
/// never from request JSON.
pub struct ApiContext<'a, S: OperationStore> {
    pub uid: Option<u32>,
    pub acl: &'a Acl,
    pub receive_log: &'a Mutex<ReceiveLog>,
    pub operation_store: &'a Mutex<S>,
    pub rate_limiter: &'a Mutex<AdmissionLimiter>,
    pub session: &'a Mutex<SessionInfo>,
    pub gateway_lane: &'a crate::dispatch::GatewayLane,
    /// Config op registry (P5): `config.*` submits queue here and `config.get`
    /// reads outcomes. Separate operation space from messages.*/gateway.*.
    pub config_ops: &'a crate::dispatch::ConfigOps,
    /// The daemon's configured config issuer node id — None means no
    /// authority is provisioned, so `config.propose` is refused honestly
    /// while queries still run.
    pub config_authority: Option<u64>,
    pub now_ms: u64,
    /// Process-monotonic clock on the same axis as the registration
    /// mirror's `lease_deadline_mono` — wall `now_ms` cannot judge a
    /// mono-anchored deadline.
    pub now_mono: u64,
}

struct ApiError {
    code: &'static str,
    /// `error.detail.message` — every error carries one.
    message: String,
    /// Additional `error.detail` members as `"key":value` pairs joined by
    /// commas (no leading comma; the serializer adds the separator).
    extra_fields: String,
    retryable: bool,
}

impl ApiError {
    fn simple(code: &'static str, message: &str) -> Self {
        Self {
            code,
            message: message.to_string(),
            extra_fields: String::new(),
            retryable: false,
        }
    }
}

/// Methods named by 01-contracts.md but implemented in later phases — they
/// must not fall through to UNKNOWN_METHOD and pretend they don't exist.
const LATER_PHASE_METHODS: &[&str] = &[];

/// Handle one API1 request body (the bytes after `API1 `, newline stripped).
/// Always returns a complete JSON response document (no trailing newline).
pub fn handle<S: OperationStore>(body: &[u8], ctx: &ApiContext<'_, S>) -> String {
    if body.len() >= REQUEST_MAX_BYTES {
        return error_response(
            None,
            &ApiError::simple("INVALID_REQUEST", "request too large"),
        );
    }
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        Err(_) => {
            return error_response(
                None,
                &ApiError::simple("INVALID_REQUEST", "request is not valid UTF-8"),
            )
        }
    };
    let root = match routeloom_json::parse_bounded(text, JSON_MAX_DEPTH) {
        Ok(root) => root,
        Err(error) => {
            return error_response(
                None,
                &ApiError::simple("INVALID_REQUEST", &format!("invalid JSON: {error}")),
            )
        }
    };
    let Json::Object(fields) = &root else {
        return error_response(
            None,
            &ApiError::simple("INVALID_REQUEST", "request must be an object"),
        );
    };
    // Envelope schema: exactly the defined fields — unknown fields are a
    // schema violation, not something to skip.
    for (key, _) in fields {
        if !matches!(key.as_str(), "v" | "request_id" | "method" | "params") {
            return error_response(
                extract_request_id(&root).as_deref(),
                &ApiError::simple("INVALID_REQUEST", &format!("unknown field \"{key}\"")),
            );
        }
    }
    let request_id = extract_request_id(&root);
    let Some(request_id) = request_id.as_deref() else {
        return error_response(
            None,
            &ApiError::simple(
                "INVALID_REQUEST",
                "request_id must be a string of 1-64 ASCII chars",
            ),
        );
    };
    if root.get("v").and_then(Json::as_u64) != Some(1) {
        return error_response(
            Some(request_id),
            &ApiError::simple("INVALID_REQUEST", "v must be 1"),
        );
    }
    let Some(method) = root.get("method").and_then(Json::as_str) else {
        return error_response(
            Some(request_id),
            &ApiError::simple("INVALID_REQUEST", "method must be a string"),
        );
    };
    let params = match root.get("params") {
        None | Some(Json::Null) => Json::Object(Vec::new()),
        Some(value @ Json::Object(_)) => value.clone(),
        Some(_) => {
            return error_response(
                Some(request_id),
                &ApiError::simple("INVALID_REQUEST", "params must be an object"),
            )
        }
    };
    let response = match method {
        "capabilities.get" => capabilities(&params, ctx).map(|r| (request_id, r)),
        "messages.read" => messages_read(&params, ctx).map(|r| (request_id, r)),
        "operations.open_epoch" => operations_open_epoch(&params, ctx).map(|r| (request_id, r)),
        "messages.submit" => messages_submit(&params, ctx).map(|r| (request_id, r)),
        "operations.get" => operations_get(&params, ctx).map(|r| (request_id, r)),
        "operations.get_by_key" => operations_get_by_key(&params, ctx).map(|r| (request_id, r)),
        "operations.cancel" => operations_cancel(&params, ctx).map(|r| (request_id, r)),
        "gateway.resolve" => gateway_resolve(&params, ctx).map(|r| (request_id, r)),
        "gateway.get" => gateway_get(&params, ctx).map(|r| (request_id, r)),
        "config.challenge" => config_challenge(&params, ctx).map(|r| (request_id, r)),
        "config.status" => config_status(&params, ctx).map(|r| (request_id, r)),
        "config.propose" => config_propose(&params, ctx).map(|r| (request_id, r)),
        "config.get" => config_get(&params, ctx).map(|r| (request_id, r)),
        method if LATER_PHASE_METHODS.contains(&method) => Err(ApiError::simple(
            "UNSUPPORTED_METHOD",
            &format!("\"{method}\" is not implemented in this phase"),
        )),
        method => Err(ApiError::simple(
            "UNKNOWN_METHOD",
            &format!("unknown method \"{method}\""),
        )),
    };
    match response {
        Ok((request_id, result)) => ok_response(request_id, &result),
        Err(error) => error_response(Some(request_id), &error),
    }
}

fn extract_request_id(root: &Json) -> Option<String> {
    let id = root.get("request_id")?.as_str()?;
    // Printable ASCII only: is_ascii() would admit C0 controls smuggled
    // through \uXXXX escapes, which then echo back inside response JSON.
    if id.is_empty() || id.len() > REQUEST_ID_MAX || !id.bytes().all(|b| (0x20..=0x7e).contains(&b))
    {
        return None;
    }
    Some(id.to_string())
}

fn ok_response(request_id: &str, result: &str) -> String {
    let response = format!(
        "{{\"v\":1,\"request_id\":\"{}\",\"ok\":true,\"result\":{result}}}",
        escape_string(request_id)
    );
    bound_response(response)
}

fn error_response(request_id: Option<&str>, error: &ApiError) -> String {
    let id = request_id.map_or_else(
        || "null".to_string(),
        |id| format!("\"{}\"", escape_string(id)),
    );
    let extra = if error.extra_fields.is_empty() {
        String::new()
    } else {
        format!(",{}", error.extra_fields)
    };
    let response = format!(
        "{{\"v\":1,\"request_id\":{id},\"ok\":false,\"error\":{{\"code\":\"{}\",\"detail\":{{\"message\":\"{}\"{extra}}},\"retryable\":{}}}}}",
        error.code,
        escape_string(&error.message),
        error.retryable,
    );
    bound_response(response)
}

/// A response that would exceed the wire cap is replaced by a small
/// INTERNAL error — never truncated mid-JSON.
fn bound_response(response: String) -> String {
    // +1 for the newline the socket layer appends.
    if response.len() + 1 > RESPONSE_MAX_BYTES {
        return "{\"v\":1,\"request_id\":null,\"ok\":false,\"error\":{\"code\":\"INTERNAL\",\"detail\":{\"message\":\"response exceeded size bound\"},\"retryable\":true}}".to_string();
    }
    response
}

/// Honest capability advertisement: only what this daemon implements.
/// `rx_events_v1`/`ingress_loss_observable` are false on the old firmware —
/// gateway-side drops before DataFromMesh cannot be proven or counted here.
/// `storage_durable` follows the bound operation store (true with
/// `--op-store`, false for the memory provider). `dispatch` names the TX-I2
/// mechanism: the host_ops_v1 dispatch-window protocol over the USB session.
/// A live session is not guaranteed — records still admit HOST_QUEUED while
/// the link is down and the dispatcher picks them up on connect.
fn capabilities<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    // Every sibling method whitelists its param keys; this one takes none,
    // so a non-empty params object is the same schema violation.
    if !params.object_entries().is_empty() {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "capabilities.get takes no params",
        ));
    }
    let epoch_known = ctx.uid.is_some();
    let durable = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned")
        .durable();
    Ok(format!(
        "{{\"api\":{{\"version\":1,\"request_max_bytes\":{REQUEST_MAX_BYTES},\"response_max_bytes\":{RESPONSE_MAX_BYTES},\"max_depth\":{JSON_MAX_DEPTH}}},\"methods\":{{\"capabilities.get\":true,\"messages.read\":true,\"messages.submit\":true,\"operations.open_epoch\":true,\"operations.get\":true,\"operations.get_by_key\":true,\"operations.cancel\":true,\"gateway.resolve\":true,\"gateway.get\":true,\"config.challenge\":true,\"config.status\":true,\"config.propose\":true,\"config.get\":true}},\"receive\":{{\"mode\":\"cursor_poll\",\"retention_seconds\":{},\"entries_per_network\":{},\"bytes_per_network\":{},\"record_charge_bytes\":{},\"max_networks\":{},\"global_log_bytes\":{},\"page_limit\":{PAGE_LIMIT},\"durable_receive\":false,\"pc_service_destination\":false}},\"send\":{{\"storage_durable\":{durable},\"dispatch\":\"usb_host_ops_v1\",\"delivery\":[\"BEST_EFFORT\",\"RELIABLE\"],\"priority\":[\"NORMAL\"],\"deadline_policy\":\"WALL_ELAPSED_VALIDITY\",\"ttl_ms\":{{\"min\":{},\"max\":{},\"default\":{}}},\"hop_limit\":{{\"min\":{},\"max\":{},\"default\":{}}},\"payload_max_bytes\":{}}},\"config\":{{\"dispatch\":\"usb_host_ops_v1\",\"permit_profile\":\"dev-hmac-sha256-16\",\"authority_configured\":{config_auth}}},\"rx_events_v1\":false,\"ingress_loss_observable\":false,\"acl_revision\":{},\"peer_credential_resolved\":{epoch_known}}}",
        crate::receive_log::RETENTION_SECONDS,
        crate::receive_log::ENTRIES_PER_NETWORK,
        crate::receive_log::BYTES_PER_NETWORK,
        crate::receive_log::RECORD_CHARGE_BYTES,
        crate::receive_log::MAX_NETWORKS,
        crate::receive_log::GLOBAL_LOG_BYTES,
        crate::canonical::TTL_MIN_MS,
        crate::canonical::TTL_MAX_MS,
        crate::canonical::TTL_DEFAULT_MS,
        crate::canonical::HOP_MIN,
        crate::canonical::HOP_MAX,
        crate::canonical::HOP_DEFAULT,
        crate::receive_log::NORMAL_PAYLOAD_MAX,
        ctx.acl.revision(),
        config_auth = ctx.config_authority.is_some(),
    ))
}

/// `messages.read` params: `{network, from:"earliest"|"latest" XOR cursor,
/// limit}`. Result per 02-receive-api.md §2.
fn messages_read<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "network" | "from" | "cursor" | "limit") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(network_text) = params.get("network").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "network must be a 16-hex string",
        ));
    };
    let network = acl::parse_network_hex(network_text)
        .map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?;
    let from = params.get("from").and_then(Json::as_str);
    let cursor_token = params.get("cursor").and_then(Json::as_str);
    if params.get("from").is_some() && from.is_none()
        || params.get("cursor").is_some() && cursor_token.is_none()
    {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "from/cursor must be strings",
        ));
    }
    if from.is_some() == cursor_token.is_some() {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "exactly one of from or cursor is required",
        ));
    }
    if let Some(from) = from {
        if from != "earliest" && from != "latest" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "from must be \"earliest\" or \"latest\"",
            ));
        }
    }
    let limit = match params.get("limit") {
        None => PAGE_LIMIT,
        Some(value) => match value.as_u64() {
            Some(n) if (1..=PAGE_LIMIT as u64).contains(&n) => n as usize,
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    &format!("limit must be an integer 1..={PAGE_LIMIT}"),
                ))
            }
        },
    };

    // The token is a position, not a permission: re-check the OS principal's
    // ACL grant on every request, before any cursor is trusted.
    let authorized = ctx
        .uid
        .is_some_and(|uid| ctx.acl.permit(uid, network, acl::PERM_READ_PAYLOAD));
    if !authorized {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks READ_PAYLOAD on this network",
        ));
    }

    let mut log = ctx.receive_log.lock().expect("receive log poisoned");
    let epoch = log.epoch();
    let acl_view = ctx.acl.revision();
    let cursor_at = |last_scanned: u64| {
        Cursor {
            network,
            acl_view,
            epoch,
            last_scanned,
        }
        .encode()
    };

    if let Some(from) = from {
        let after = if from == "latest" {
            log.bounds(network, ctx.now_ms).1
        } else {
            0
        };
        let outcome = log.read(network, after, limit, ctx.now_ms, false);
        return Ok(read_result(outcome, &cursor_at));
    }

    let token = cursor_token.expect("cursor checked above");
    let Some(cursor) = Cursor::decode(token) else {
        return Err(ApiError::simple(
            "INVALID_CURSOR",
            "cursor is malformed, oversized, or wrong version",
        ));
    };
    if cursor.network != network {
        return Err(ApiError::simple(
            "CURSOR_SCOPE_MISMATCH",
            "cursor was issued for a different network",
        ));
    }
    if cursor.acl_view != acl_view {
        return Err(ApiError::simple(
            "CURSOR_SCOPE_MISMATCH",
            "cursor was issued under a different ACL view",
        ));
    }
    if cursor.epoch != epoch {
        // A previous daemon epoch's loss count is unknowable — report null
        // rather than fabricating one. The cursors below are minted under
        // the current epoch so the client can resume explicitly.
        let (oldest, tail, ..) = log.bounds(network, ctx.now_ms);
        return Err(ApiError {
            code: "CURSOR_EPOCH_CHANGED",
            message: "cursor belongs to a previous daemon epoch".to_string(),
            extra_fields: format!(
                "\"loss_count\":null,\"oldest_cursor\":\"{}\",\"tail_cursor\":\"{}\"",
                cursor_at(oldest.saturating_sub(1)),
                cursor_at(tail),
            ),
            retryable: false,
        });
    }
    match log.read(network, cursor.last_scanned, limit, ctx.now_ms, true) {
        ReadOutcome::Gap {
            lost_from,
            lost_to,
            oldest_seq,
            tail_seq,
        } => Err(ApiError {
            code: "CURSOR_GAP",
            message: "receive-log records were reclaimed ahead of this cursor".to_string(),
            extra_fields: format!(
                "\"lost_from\":{lost_from},\"lost_to\":{lost_to},\"oldest_cursor\":\"{}\",\"tail_cursor\":\"{}\"",
                cursor_at(oldest_seq.saturating_sub(1)),
                cursor_at(tail_seq),
            ),
            retryable: false,
        }),
        ReadOutcome::Future => Err(ApiError::simple(
            "INVALID_CURSOR",
            "cursor points beyond the current tail",
        )),
        outcome @ ReadOutcome::Batch(_) => Ok(read_result(outcome, &cursor_at)),
    }
}

/// Serialize a read batch. `cursor_at` mints cursors under the current
/// epoch/acl_view/network.
fn read_result(outcome: ReadOutcome, cursor_at: &dyn Fn(u64) -> String) -> String {
    let ReadOutcome::Batch(batch) = outcome else {
        unreachable!("gap/future handled by caller")
    };
    let mut records_json = String::from("[");
    for (index, record) in batch.records.iter().enumerate() {
        if index > 0 {
            records_json.push(',');
        }
        records_json.push_str(&format!(
            "{{\"v\":1,\"network\":\"{:016x}\",\"gateway\":{},\"origin\":\"{:016x}\",\"message\":{{\"session\":\"{:08x}\",\"sequence\":\"{:016x}\"}},\"payload_hex\":\"{}\",\"payload_len\":{},\"cursor\":\"{}\",\"endpoint_kind\":\"gateway_mirror\",\"evidence\":\"HOST_RAM_RETAINED\",\"assurance\":{{\"profile\":\"EXPERIMENTAL_DEV_PSK\",\"origin\":\"group-key-claim\"}}}}",
            record.network,
            record.gateway.map_or_else(
                || "null".to_string(),
                |g| format!("\"{g:016x}\""),
            ),
            record.origin,
            record.msg_session,
            record.msg_seq,
            crate::receive_log::hex_lower(&record.payload),
            record.payload.len(),
            cursor_at(record.seq),
        ));
    }
    records_json.push(']');
    // Position after the last returned record; an empty batch resumes at
    // the caller's own position (earliest→before-oldest, latest→tail, and a
    // caught-up cursor stays put rather than rewinding to oldest-1).
    let next_cursor = match batch.records.last() {
        Some(record) => cursor_at(record.seq),
        None => cursor_at(batch.after_seq),
    };
    format!(
        "{{\"records\":{records_json},\"next_cursor\":\"{next_cursor}\",\"oldest_cursor\":\"{}\",\"tail_cursor\":\"{}\",\"more\":{},\"retention\":{{\"seconds\":{},\"entries\":{},\"bytes\":{}}}}}",
        cursor_at(batch.oldest_seq.saturating_sub(1)),
        cursor_at(batch.tail_seq),
        batch.more,
        crate::receive_log::RETENTION_SECONDS,
        batch.entries,
        batch.bytes,
    )
}

/// `operations.open_epoch` params: `{network}`. Binds the caller's
/// admission epoch for that network (SEND grant required), opening epoch 1
/// on first use and rotating hourly past it. At the unretired-epoch
/// ceiling no new epoch can be issued and admission stops with
/// NO_CAPACITY; already admitted keys stay queryable.
fn operations_open_epoch<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if key != "network" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(network_text) = params.get("network").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "network must be a 16-hex string",
        ));
    };
    let network = acl::parse_network_hex(network_text)
        .map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?;
    let Some(uid) = ctx
        .uid
        .filter(|uid| ctx.acl.permit(*uid, network, acl::PERM_SEND))
    else {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks SEND on this network",
        ));
    };
    // Rate limit before any admission work so epoch spam cannot bypass
    // the budget either (04 §4).
    if let Err(deny) = ctx
        .rate_limiter
        .lock()
        .expect("rate limiter poisoned")
        .admit(uid, ctx.now_ms)
    {
        return Err(rate_limited(deny));
    }
    let mut store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    match store.open_epoch((uid, network), ctx.now_ms) {
        Ok((epoch, _)) => Ok(format!(
            "\"network\":\"{network:016x}\",\"admission_epoch\":\"{epoch:016x}\""
        )),
        Err(OpenEpochError::NoCapacity) => Err(no_capacity(&store.capacity_status(ctx.now_ms))),
        Err(OpenEpochError::StoreFault) => Err(store_fault()),
    }
    .map(|fields| format!("{{{fields}}}"))
}

/// `messages.submit`: validate, gate capabilities, authorize SEND, then
/// admit into the operation table. Replays return the same OperationId
/// with the record's current status — the same document operations.get
/// reports, so a resubmitted key on a cancelled/expired/delivered
/// operation answers its real state, never a fabricated HOST_QUEUED.
/// Same key with different bytes is a CONFLICT, never an overwrite.
fn messages_submit<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    // The schema-2 binding comes from the daemon's own registration
    // mirror — the client can never declare token/boot/egress itself.
    // Node destinations ignore it; gateway destinations REQUIRE a live
    // binding or the parse names GATEWAY_UNAVAILABLE instead of minting
    // one (05 §5.7).
    let binding = gateway_binding(ctx);
    let req = canonical::parse_submit(params, binding.as_ref()).map_err(|reject| ApiError {
        code: reject.code,
        message: reject.message,
        extra_fields: String::new(),
        retryable: reject.retryable,
    })?;
    // The durability flag is immutable per store, so a short lock here
    // cannot race the admission below.
    let store_durable = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned")
        .durable();
    canonical::admission_check(&req, canonical::wants_persist_sleep(params), store_durable)
        .map_err(|reject| ApiError {
            code: reject.code,
            message: reject.message,
            extra_fields: String::new(),
            retryable: reject.retryable,
        })?;
    let Some(uid) = ctx
        .uid
        .filter(|uid| ctx.acl.permit(*uid, req.network, acl::PERM_SEND))
    else {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks SEND on this network",
        ));
    };
    // Charged before the store sees the request: replays and CONFLICTs
    // cost a token too, so a spammed key cannot ride the dedup path for
    // free (04 §4).
    if let Err(deny) = ctx
        .rate_limiter
        .lock()
        .expect("rate limiter poisoned")
        .admit(uid, ctx.now_ms)
    {
        return Err(rate_limited(deny));
    }
    let mut store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    // The monotonic stamp rides alongside the wall admit time so a
    // wall-clock rewind can never stretch the dispatch deadline.
    match store.submit_at(uid, &req, ctx.now_ms, crate::mono_ms()) {
        SubmitOutcome::Accepted { seq } => {
            Ok(submit_result(&store.lineage(), seq, req.storage))
        }
        // Replay answers the committed record through the operations.get
        // serializer — its committed dispatch_state, evidence and
        // message_key, not the admission-time placeholders.
        SubmitOutcome::Replay { seq } => {
            let record = store
                .get_by_seq(seq)
                .map_err(|()| store_fault())?
                .expect("replay seq admitted above");
            Ok(op_status(&record, &store.lineage(), ctx.now_ms))
        }
        SubmitOutcome::Conflict { existing_seq } => Err(ApiError {
            code: "CONFLICT",
            message: "same idempotency key with different request bytes".to_string(),
            extra_fields: format!(
                "\"existing_operation_id\":\"{}\"",
                canonical::format_operation_id(&store.lineage(), existing_seq),
            ),
            retryable: false,
        }),
        SubmitOutcome::UnknownEpoch => Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "admission_epoch is not open for this principal and network; call operations.open_epoch",
        )),
        SubmitOutcome::EpochClosed => Err(ApiError::simple(
            "EPOCH_CLOSED",
            "admission_epoch is closed for new keys; known keys stay queryable via operations.get_by_key",
        )),
        SubmitOutcome::NoCapacity => Err(no_capacity(&store.capacity_status(ctx.now_ms))),
        SubmitOutcome::StoreFault => Err(store_fault()),
    }
}

/// Admission throttle (04 §4): retryable, and names which scope — the
/// caller's own bucket or the all-principals one — ran dry.
fn rate_limited(deny: RateDeny) -> ApiError {
    ApiError {
        code: "RATE_LIMITED",
        message: "admission rate limit exceeded".to_string(),
        extra_fields: format!(
            "\"scope\":\"{}\",\"retry_after_ms\":{}",
            deny.scope, deny.retry_after_ms,
        ),
        retryable: true,
    }
}

fn no_capacity(status: &CapacityStatus) -> ApiError {
    let reclaimable = status
        .reclaimable_at_ms
        .map_or_else(|| "null".to_string(), |ms| ms.to_string());
    ApiError {
        code: "NO_CAPACITY",
        message: "operation store has no free admission slot".to_string(),
        extra_fields: format!(
            "\"free_slots\":{},\"free_bytes\":{},\"reclaimable_at\":{reclaimable}",
            status.free_slots, status.free_bytes,
        ),
        retryable: true,
    }
}

fn store_fault() -> ApiError {
    ApiError::simple(
        "STORE_RECOVERY_REQUIRED",
        "operation store fault; the daemon cannot vouch for this outcome",
    )
}

/// Accept response per 03-send-api.md §1. The evidence tag follows the
/// admitted storage class: HOST_DURABLE_RETAINED only leaves a store that
/// actually retains the record across restarts.
fn submit_result(lineage: &[u8; 16], seq: u64, storage: u8) -> String {
    let evidence = if storage == canonical::STORAGE_DURABLE {
        "HOST_DURABLE_RETAINED"
    } else {
        "HOST_RAM_RETAINED"
    };
    format!(
        "{{\"operation_id\":\"{}\",\"dispatch_state\":\"HOST_QUEUED\",\"evidence\":[\"{evidence}\"],\"message_key\":null}}",
        canonical::format_operation_id(lineage, seq)
    )
}

/// The daemon's live schema-2 binding: the registration mirror pinned to
/// the CURRENT authenticated session, dropped when the mirror names a
/// dead session or an expired lease. `None` means "no usable binding" —
/// never "mint one anyway".
fn gateway_binding<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
) -> Option<canonical::GatewayEndpointBinding> {
    let registration = ctx.gateway_lane.current()?;
    let (authenticated, session_id) = {
        let info = ctx.session.lock().expect("session poisoned");
        (info.authenticated, info.id.unwrap_or(0))
    };
    if !authenticated || registration.usb_session != session_id {
        return None;
    }
    if ctx.now_mono >= registration.lease_deadline_mono {
        return None;
    }
    Some(canonical::GatewayEndpointBinding {
        token: registration.token,
        gateway_boot: registration.gateway_boot,
        egress: registration.egress,
    })
}

/// `gateway.resolve` params per 05-wire-api.md §5.7:
/// `{network, gateway, scope, expected_host}`. The only endpoint this
/// daemon can honestly resolve is its OWN host endpoint at the attached
/// gateway — the registration lane's live state. A remote gateway's
/// endpoint is a mesh-side question the USB session cannot answer, and a
/// missing/mismatched registration is reported as `resolved:false` with
/// the reason, never as a fabricated descriptor. The token itself is
/// deliberately not in the result: callers bind schema-2 through
/// `messages.submit`, which reads the mirror directly.
fn gateway_resolve<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "network" | "gateway" | "scope" | "expected_host"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let network = match params.get("network").and_then(Json::as_str) {
        Some(text) => {
            acl::parse_network_hex(text).map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?
        }
        None => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "network must be a 16-hex string",
            ))
        }
    };
    let gateway = match params.get("gateway").and_then(Json::as_str) {
        Some(text) => parse_hex_u64(text)
            .ok_or_else(|| ApiError::simple("INVALID_ARGUMENT", "gateway must be a 16-hex id"))?,
        None => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "gateway must be a 16-hex id",
            ))
        }
    };
    if gateway == 0 || gateway == u64::MAX {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "gateway must not be a reserved id",
        ));
    }
    let scope = match params.get("scope").and_then(Json::as_str) {
        Some(name @ ("HOST_RECEIVE_RAM" | "GATEWAY_SDK_RAM")) => name,
        Some(_) => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "scope must be HOST_RECEIVE_RAM or GATEWAY_SDK_RAM",
            ))
        }
        None => return Err(ApiError::simple("INVALID_ARGUMENT", "scope is required")),
    };
    // Scope 2 names a specific host digest; scope 1's digest slot is the
    // all-zero sentinel, so a nonzero expected_host there is malformed.
    let expected_host = match params.get("expected_host") {
        None if scope == "HOST_RECEIVE_RAM" => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "expected_host is required for HOST_RECEIVE_RAM",
            ))
        }
        None => None,
        Some(Json::String(text)) => {
            let digest = parse_hex_32(text).ok_or_else(|| {
                ApiError::simple("INVALID_ARGUMENT", "expected_host must be a 64-hex digest")
            })?;
            if scope == "GATEWAY_SDK_RAM" && digest != [0; 32] {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "expected_host must be all-zero for GATEWAY_SDK_RAM",
                ));
            }
            Some(digest)
        }
        Some(_) => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "expected_host must be a 64-hex string",
            ))
        }
    };
    // The query reads daemon state only — still an operation read on the
    // named network, so an unauthorized principal gets the same denial
    // shape the other queries use.
    if !ctx
        .uid
        .is_some_and(|uid| ctx.acl.permit(uid, network, acl::PERM_READ_OPERATION))
    {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks READ_OPERATION on this network",
        ));
    }
    let unresolved = |reason: &str| Ok(format!("{{\"resolved\":false,\"reason\":\"{reason}\"}}"));
    let (authenticated, session_network, session_node, session_id) = {
        let info = ctx.session.lock().expect("session poisoned");
        (
            info.authenticated,
            info.network.unwrap_or(0),
            info.node.unwrap_or(0),
            info.id.unwrap_or(0),
        )
    };
    if !authenticated {
        return unresolved("session_not_authenticated");
    }
    if session_network != network {
        return unresolved("network_not_on_session");
    }
    if session_node != gateway {
        // Only the ATTACHED gateway's host endpoint is resolvable here —
        // a remote endpoint is a mesh-side resolve the daemon cannot see.
        return unresolved("gateway_not_attached");
    }
    if scope == "GATEWAY_SDK_RAM" {
        // The host daemon is a HOST endpoint only; the gateway's own SDK
        // mailbox is not ours to describe.
        return unresolved("scope_not_host_endpoint");
    }
    let Some(registration) = ctx.gateway_lane.current() else {
        return unresolved("not_registered");
    };
    if registration.usb_session != session_id || ctx.now_mono >= registration.lease_deadline_mono {
        return unresolved("not_registered");
    }
    if expected_host != Some(registration.host_digest) {
        return unresolved("host_digest_mismatch");
    }
    Ok(format!(
        "{{\"resolved\":true,\"scope\":\"HOST_RECEIVE_RAM\",\"host_digest\":\"{}\",\"gateway_boot\":\"{:016x}\",\"egress\":\"{:016x}\",\"lease_ms\":{}}}",
        crate::receive_log::hex_lower(&registration.host_digest),
        registration.gateway_boot,
        registration.egress,
        registration.lease_deadline_mono.saturating_sub(ctx.now_mono),
    ))
}

/// `gateway.get` params: `{operation_id}` — the outcome query for a
/// schema-2 submit (G11: consult the original outcome rather than
/// re-issuing toward another egress). Same visibility rules as
/// operations.get; a node-destination record is answered with the same
/// NOT_FOUND shape so the method cannot be used as a destination-kind
/// oracle.
fn gateway_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if key != "operation_id" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(text) = params.get("operation_id").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "operation_id must be a string",
        ));
    };
    let Some((lineage, seq)) = canonical::parse_operation_id(text) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "operation_id must be <32-hex lineage>:<16-hex sequence>",
        ));
    };
    let store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    let record = match store.get_by_seq(seq) {
        Ok(Some(record)) if store.lineage() == lineage => record,
        Ok(_) => {
            return Err(ApiError::simple(
                "NOT_FOUND",
                "no gateway operation with that id in this store",
            ))
        }
        Err(()) => return Err(store_fault()),
    };
    if !ctx.uid.is_some_and(|uid| {
        ctx.acl
            .permit(uid, record.network, acl::PERM_READ_OPERATION)
    }) {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no gateway operation with that id in this store",
        ));
    }
    if record.dest_kind != canonical::DEST_GATEWAY {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no gateway operation with that id in this store",
        ));
    }
    Ok(op_status(&record, &store.lineage(), ctx.now_ms))
}

fn parse_hex_u64(text: &str) -> Option<u64> {
    if text.len() != 16 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(text, 16).ok()
}

fn parse_hex_32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// `operations.get` params: `{operation_id}`. Any principal holding
/// READ_OPERATION on the operation's network may query it. A record the
/// caller may not read answers the same NOT_FOUND as a missing id —
/// distinguishing the two would make the method an existence oracle.
fn operations_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if key != "operation_id" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(text) = params.get("operation_id").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "operation_id must be a string",
        ));
    };
    let Some((lineage, seq)) = canonical::parse_operation_id(text) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "operation_id must be <32-hex lineage>:<16-hex sequence>",
        ));
    };
    let store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    let record = match store.get_by_seq(seq) {
        Ok(Some(record)) if store.lineage() == lineage => record,
        Ok(_) => {
            return Err(ApiError::simple(
                "NOT_FOUND",
                "no operation with that id in this store",
            ))
        }
        Err(()) => return Err(store_fault()),
    };
    if !ctx.uid.is_some_and(|uid| {
        ctx.acl
            .permit(uid, record.network, acl::PERM_READ_OPERATION)
    }) {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no operation with that id in this store",
        ));
    }
    Ok(op_status(&record, &store.lineage(), ctx.now_ms))
}

/// `operations.get_by_key` params: `{network, admission_epoch, key}`.
/// Resolves under the caller's own identity — one principal's key never
/// reads another's record.
fn operations_get_by_key<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "network" | "admission_epoch" | "key") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let network = match params.get("network").and_then(Json::as_str) {
        Some(text) => {
            acl::parse_network_hex(text).map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?
        }
        None => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "network must be a 16-hex string",
            ))
        }
    };
    let epoch = match params.get("admission_epoch").and_then(Json::as_str) {
        Some(text) => canonical::parse_epoch_hex(text)
            .map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?,
        None => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "admission_epoch must be a 16-hex string",
            ))
        }
    };
    let key = match params.get("key").and_then(Json::as_str) {
        Some(text) => {
            canonical::parse_key_hex(text).map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?
        }
        None => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "key must be a 32-hex string",
            ))
        }
    };
    let Some(uid) = ctx
        .uid
        .filter(|uid| ctx.acl.permit(*uid, network, acl::PERM_READ_OPERATION))
    else {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks READ_OPERATION on this network",
        ));
    };
    let store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    let identity = OpIdentity {
        uid,
        network,
        epoch,
        key,
    };
    let Some(record) = store.get_by_key(&identity).map_err(|()| store_fault())? else {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no operation with that key in this store",
        ));
    };
    Ok(op_status(&record, &store.lineage(), ctx.now_ms))
}

/// `operations.cancel` params: `{operation_id}` (03 §5). Only the owning
/// principal — the uid that submitted — holding SEND on the record's
/// network may cancel; READ_OPERATION is deliberately not enough because
/// cancellation mutates someone else's send pipeline. The store's
/// `cancel_operation` linearizes against the dispatcher's claim: a cancel
/// that lands before any USB write could have begun returns the record's
/// new CANCELLED_BEFORE_DISPATCH status; a late one answers
/// CANCEL_TOO_LATE with the current state (the `cancel_requested`
/// observation is still recorded — never silently dropped). Non-owners
/// get the same NOT_FOUND as a missing id: naming foreign ownership
/// would leak that the operation exists.
fn operations_cancel<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if key != "operation_id" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(text) = params.get("operation_id").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "operation_id must be a string",
        ));
    };
    let Some((lineage, seq)) = canonical::parse_operation_id(text) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "operation_id must be <32-hex lineage>:<16-hex sequence>",
        ));
    };
    let mut store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    if store.lineage() != lineage {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no operation with that id in this store",
        ));
    }
    let record = match store.get_by_seq(seq) {
        Ok(Some(record)) => record,
        Ok(None) => {
            return Err(ApiError::simple(
                "NOT_FOUND",
                "no operation with that id in this store",
            ))
        }
        Err(()) => return Err(store_fault()),
    };
    let owns = ctx.uid.is_some_and(|uid| {
        uid == record.uid && ctx.acl.permit(uid, record.network, acl::PERM_SEND)
    });
    if !owns {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no operation with that id in this store",
        ));
    }
    match store.cancel_operation(seq, ctx.now_ms) {
        Ok(CancelOutcome::Cancelled) => {
            // Re-read so the response reports the committed record —
            // including the SKIP bookkeeping the cancel installed.
            let record = store
                .get_by_seq(seq)
                .map_err(|()| store_fault())?
                .expect("record committed by cancel");
            Ok(op_status(&record, &store.lineage(), ctx.now_ms))
        }
        Ok(CancelOutcome::TooLate(state)) => Err(ApiError {
            code: "CANCEL_TOO_LATE",
            message: "a USB write may already have begun; remote undo is not promised".to_string(),
            extra_fields: format!("\"dispatch_state\":\"{}\"", state.name()),
            retryable: false,
        }),
        // The record was there at authorization; a race removed it.
        Ok(CancelOutcome::NotFound) => Err(ApiError::simple(
            "NOT_FOUND",
            "no operation with that id in this store",
        )),
        Err(()) => Err(store_fault()),
    }
}

// --- Remote-config methods (scope-gateway-config P5, 05-wire-api.md §5.6) ----
//
// `config.*` is an asynchronous admin surface: a submit queues a request on
// the config lane and returns a config op id the caller polls with
// `config.get`. Acceptance is NEVER a config verdict — the honest outcome
// (CHALLENGED/STATUS/NO_CHANGE/REFUSED/TIMEOUT/INDETERMINATE/…) arrives via
// the lane. PERM_CONFIG gates every verb: a normal messages.send grant can
// neither read config state nor issue a permit.

/// The config op id token — a `cfg`-prefixed space so it can never collide
/// with a messages.* or gateway.* operation id.
fn config_op_token(op_id: u64) -> String {
    format!("cfg{op_id:016x}")
}

fn parse_config_op(text: &str) -> Option<u64> {
    let hex = text.strip_prefix("cfg").unwrap_or(text);
    if hex.is_empty() || hex.len() > 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok().filter(|&v| v != 0)
}

/// A u16 field accepts a JSON number or a hex/decimal string.
fn u16_field(value: Option<&Json>, name: &str) -> Result<u16, ApiError> {
    let invalid = || {
        ApiError::simple(
            "INVALID_ARGUMENT",
            &format!("{name} must be a u16 (number or hex string)"),
        )
    };
    match value {
        None => Err(ApiError::simple(
            "INVALID_ARGUMENT",
            &format!("{name} is required"),
        )),
        Some(json) => {
            if let Some(n) = json.as_u64() {
                return u16::try_from(n).map_err(|_| invalid());
            }
            if let Some(text) = json.as_str() {
                return u16::from_str_radix(text.trim_start_matches("0x"), 16)
                    .or_else(|_| text.parse::<u16>())
                    .map_err(|_| invalid());
            }
            Err(invalid())
        }
    }
}

/// Variable-length hex → bytes (even length, ≤ `max` bytes).
fn parse_hex_bytes(text: &str, max: usize) -> Option<Vec<u8>> {
    if text.len() % 2 != 0 || text.len() > max * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = Vec::with_capacity(text.len() / 2);
    for pair in text.as_bytes().chunks_exact(2) {
        out.push(u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?);
    }
    Some(out)
}

fn parse_hex_16(text: &str) -> Option<[u8; 16]> {
    parse_hex_bytes(text, 16)?.try_into().ok()
}

/// `config.*` shared ACL check: PERM_CONFIG on the named network. An
/// unauthorized principal gets the same denial shape as the other admin
/// verbs — never a hint about what the config surface can do.
fn config_permit(ctx: &ApiContext<'_, impl OperationStore>, network: u64) -> bool {
    ctx.uid
        .is_some_and(|uid| ctx.acl.permit(uid, network, acl::PERM_CONFIG))
}

fn config_denied() -> ApiError {
    ApiError::simple(
        "AuthorizationFailed",
        "principal lacks CONFIG on this network",
    )
}

/// `config.challenge` params: `{network, target, config_namespace, schema}`.
/// Issues a ChallengeQuery for (target, namespace); the ControlChallenge body
/// — the freshness + CAS inputs a propose consumes — is the outcome read via
/// config.get.
fn config_challenge<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "network" | "target" | "config_namespace" | "schema"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let (network, target) = config_target_params(params)?;
    let config_namespace = u16_field(params.get("config_namespace"), "config_namespace")?;
    let schema = u16_field(params.get("schema"), "schema")?;
    if !config_permit(ctx, network) {
        return Err(config_denied());
    }
    let request = ConfigRequest::Challenge {
        target,
        config_namespace,
        schema,
    };
    config_submit_op(
        ctx,
        request,
        format!("challenge ns={config_namespace} schema={schema}"),
        network,
        target,
    )
}

/// `config.status` params: `{network, target, config_namespace, operation_id}`.
/// Issues a StatusQuery for `operation_id` — reads the real phase/reason
/// verdict of the config operation that id names.
fn config_status<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "network" | "target" | "config_namespace" | "operation_id"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let (network, target) = config_target_params(params)?;
    let config_namespace = u16_field(params.get("config_namespace"), "config_namespace")?;
    let Some(op_text) = params.get("operation_id").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "operation_id must be a 32-hex string",
        ));
    };
    let Some(operation_id) = parse_hex_16(op_text) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "operation_id must be a 32-hex string",
        ));
    };
    if !config_permit(ctx, network) {
        return Err(config_denied());
    }
    let request = ConfigRequest::Status {
        target,
        config_namespace,
        operation_id,
    };
    config_submit_op(
        ctx,
        request,
        format!("status ns={config_namespace} op={op_text}"),
        network,
        target,
    )
}

/// `config.propose` params: `{network, target, config_namespace, schema,
/// base_snapshot, patch, apply_budget_ms?}`. Runs challenge → sign → permit
/// transfer → status read. `base_snapshot` is the issuer's held snapshot TLV
/// the CAS chain verifies; `patch` is an array of `{field_id, field_type,
/// value}` entries. Requires a configured authority AND PERM_CONFIG — a
/// normal send grant can never issue a permit.
fn config_propose<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "network"
                | "target"
                | "config_namespace"
                | "schema"
                | "base_snapshot"
                | "patch"
                | "apply_budget_ms"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let (network, target) = config_target_params(params)?;
    let config_namespace = u16_field(params.get("config_namespace"), "config_namespace")?;
    let schema = u16_field(params.get("schema"), "schema")?;
    let Some(base_text) = params.get("base_snapshot").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "base_snapshot must be a hex string",
        ));
    };
    let Some(base_snapshot) = parse_hex_bytes(base_text, 512) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "base_snapshot must be even-length hex ≤ 512 bytes",
        ));
    };
    let patch = config_patch_fields(params.get("patch"))?;
    let apply_budget_ms = match params.get("apply_budget_ms") {
        None => 0,
        Some(value) => match value.as_u64().and_then(|n| u32::try_from(n).ok()) {
            Some(n) => n,
            None => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "apply_budget_ms must be a u32",
                ))
            }
        },
    };
    if !config_permit(ctx, network) {
        return Err(config_denied());
    }
    // Honest early refusal: no configured authority means no permit can be
    // signed — say so rather than queue a request the lane will deny.
    if ctx.config_authority.is_none() {
        return Err(ApiError::simple(
            "CONFIG_NO_AUTHORITY",
            "no config authority configured (daemon --config-authority); permits cannot be issued",
        ));
    }
    let field_count = patch.len();
    let request = ConfigRequest::Propose {
        target,
        config_namespace,
        schema,
        base_snapshot,
        patch,
        apply_budget_ms,
    };
    config_submit_op(
        ctx,
        request,
        format!("propose ns={config_namespace} schema={schema} fields={field_count}"),
        network,
        target,
    )
}

/// `config.get` params: `{config_op}`. Reads one config op's record — the
/// honest terminal outcome once resolved, or PENDING. An unauthorized
/// principal gets NOT_FOUND (no existence oracle), matching gateway.get.
fn config_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if key != "config_op" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(text) = params.get("config_op").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "config_op must be a config op token string",
        ));
    };
    let Some(op_id) = parse_config_op(text) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "config_op must be a cfg-prefixed hex token",
        ));
    };
    let Some(record) = ctx.config_ops.get(op_id) else {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no config operation with that id",
        ));
    };
    if !ctx
        .uid
        .is_some_and(|uid| ctx.acl.permit(uid, record.network, acl::PERM_CONFIG))
    {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no config operation with that id",
        ));
    }
    Ok(config_outcome_json(&record))
}

/// Shared `{network, target}` parsing for the submit verbs.
fn config_target_params(params: &Json) -> Result<(u64, u64), ApiError> {
    let Some(network_text) = params.get("network").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "network must be a 16-hex string",
        ));
    };
    let network = acl::parse_network_hex(network_text)
        .map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?;
    let Some(target_text) = params.get("target").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "target must be a 16-hex node id",
        ));
    };
    let Some(target) = parse_hex_u64(target_text) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "target must be a 16-hex node id",
        ));
    };
    Ok((network, target))
}

/// Queue one config request on the lane; answers the accepted submit shape.
/// A full inbox is an honest NO_CAPACITY, never a silent drop.
fn config_submit_op<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
    request: ConfigRequest,
    summary: String,
    network: u64,
    target: u64,
) -> Result<String, ApiError> {
    match ctx
        .config_ops
        .submit(request, summary, network, target, ctx.now_ms)
    {
        Ok(op_id) => Ok(format!(
            "{{\"config_op\":\"{}\",\"state\":\"PENDING\",\"submitted_ms\":{}}}",
            config_op_token(op_id),
            ctx.now_ms
        )),
        Err(()) => Err(ApiError {
            code: "NO_CAPACITY",
            message: "config op queue is full; retry when in-flight ops resolve".to_string(),
            extra_fields: String::new(),
            retryable: true,
        }),
    }
}

/// `patch` array → sorted `ConfigField` vec. Field ids must be unique; the
/// wire encoder requires them strictly ascending, so they are sorted here.
fn config_patch_fields(value: Option<&Json>) -> Result<Vec<ConfigField>, ApiError> {
    let invalid = |m: &str| ApiError::simple("INVALID_ARGUMENT", m);
    let Some(arr) = value.and_then(Json::as_array) else {
        return Err(invalid(
            "patch must be an array of {field_id, field_type, value} entries",
        ));
    };
    if arr.is_empty() || arr.len() > 16 {
        return Err(invalid("patch must carry 1-16 fields"));
    }
    let mut fields = Vec::with_capacity(arr.len());
    for entry in arr {
        let field_id = u16_field(entry.get("field_id"), "patch field_id")?;
        let field_type = config_field_type(entry.get("field_type"))?;
        let Some(value_text) = entry.get("value").and_then(Json::as_str) else {
            return Err(invalid("patch value must be a hex string"));
        };
        let Some(value) = parse_hex_bytes(value_text, 96) else {
            return Err(invalid("patch value must be even-length hex ≤ 96 bytes"));
        };
        fields.push(ConfigField {
            field_id,
            field_type,
            value,
        });
    }
    fields.sort_by_key(|f| f.field_id);
    if fields.windows(2).any(|w| w[0].field_id == w[1].field_id) {
        return Err(invalid("patch field_ids must be unique"));
    }
    Ok(fields)
}

/// `field_type` accepts a name ("bool"|"u8"|"u32"|"bytes") or a number 1-4.
fn config_field_type(value: Option<&Json>) -> Result<ConfigFieldType, ApiError> {
    if let Some(name) = value.and_then(Json::as_str) {
        match name.to_ascii_lowercase().as_str() {
            "bool" => return Ok(ConfigFieldType::Bool),
            "u8" => return Ok(ConfigFieldType::U8),
            "u32" => return Ok(ConfigFieldType::U32),
            "bytes" => return Ok(ConfigFieldType::Bytes),
            _ => {}
        }
    }
    match u16_field(value, "patch field_type")? {
        1 => Ok(ConfigFieldType::Bool),
        2 => Ok(ConfigFieldType::U8),
        3 => Ok(ConfigFieldType::U32),
        4 => Ok(ConfigFieldType::Bytes),
        _ => Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "patch field_type must be 1(Bool)|2(U8)|3(U32)|4(Bytes)",
        )),
    }
}

fn config_phase_name(phase: ConfigPhase) -> &'static str {
    match phase {
        ConfigPhase::Idle => "IDLE",
        ConfigPhase::Prepared => "PREPARED",
        ConfigPhase::Decided => "DECIDED",
        ConfigPhase::ApplyIntent => "APPLY_INTENT",
        ConfigPhase::Applying => "APPLYING",
        ConfigPhase::Verifying => "VERIFYING",
        ConfigPhase::Active => "ACTIVE",
        ConfigPhase::Interrupted => "INTERRUPTED",
        ConfigPhase::Quarantined => "QUARANTINED",
    }
}

fn config_reason_name(reason: ConfigReason) -> &'static str {
    match reason {
        ConfigReason::Ok => "OK",
        ConfigReason::InProgress => "IN_PROGRESS",
        ConfigReason::StaleRevision => "STALE_REVISION",
        ConfigReason::BaseHashMismatch => "BASE_HASH_MISMATCH",
        ConfigReason::InvalidPatch => "INVALID_PATCH",
        ConfigReason::Deadline => "DEADLINE",
        ConfigReason::AuthorityDenied => "AUTHORITY_DENIED",
        ConfigReason::Unsupported => "UNSUPPORTED",
        ConfigReason::Capacity => "CAPACITY",
        ConfigReason::StorageFailure => "STORAGE_FAILURE",
        ConfigReason::ApplyInterrupted => "APPLY_INTERRUPTED",
        ConfigReason::VerifyFailed => "VERIFY_FAILED",
        ConfigReason::RecoveryRequired => "RECOVERY_REQUIRED",
        ConfigReason::MaintenanceBusy => "MAINTENANCE_BUSY",
        ConfigReason::NoChange => "NO_CHANGE",
        ConfigReason::ResultExpired => "RESULT_EXPIRED",
    }
}

fn config_ops_result_name(result: ConfigOpsResult) -> &'static str {
    match result {
        ConfigOpsResult::Ok => "OK",
        ConfigOpsResult::Busy => "BUSY",
        ConfigOpsResult::Denied => "DENIED",
        ConfigOpsResult::Unsupported => "UNSUPPORTED",
        ConfigOpsResult::Invalid => "INVALID",
        ConfigOpsResult::Indeterminate => "INDETERMINATE",
        ConfigOpsResult::NoRoute => "NO_ROUTE",
        ConfigOpsResult::Timeout => "TIMEOUT",
    }
}

/// Serialize a config op record for `config.get`. The `state` names the
/// honest outcome — PERMIT_ASSEMBLED is reported as assembled, never ACTIVE;
/// only the Status body's phase/reason is a real config verdict.
fn config_outcome_json(record: &ConfigOpRecord) -> String {
    let base = format!(
        "\"config_op\":\"{}\",\"network\":\"{:016x}\",\"target\":\"{:016x}\",\"op\":\"{}\"",
        config_op_token(record.op_id),
        record.network,
        record.target,
        escape_string(&record.summary)
    );
    match &record.outcome {
        None => format!(
            "{{{base},\"state\":\"PENDING\",\"submitted_ms\":{}}}",
            record.submitted_ms
        ),
        Some(outcome) => {
            let (state, detail) = match outcome {
                ConfigOutcome::Challenged(c) => (
                    "CHALLENGED",
                    format!(
                        ",\"challenge\":{{\"config_namespace\":{},\"schema\":{},\"target_boot\":{},\"revision\":{},\"active_hash\":\"{}\",\"valid_for_ms\":{}}}",
                        c.config_namespace,
                        c.schema,
                        c.target_boot,
                        c.revision,
                        hex_lower(&c.active_hash),
                        c.valid_for_ms
                    ),
                ),
                ConfigOutcome::Statused(s) => (
                    "STATUS",
                    format!(
                        ",\"status\":{{\"phase\":\"{}\",\"reason\":\"{}\",\"config_namespace\":{},\"operation_id\":\"{}\",\"decision_revision\":{},\"active_revision\":{},\"active_hash\":\"{}\"}}",
                        config_phase_name(s.phase),
                        config_reason_name(s.reason),
                        s.config_namespace,
                        hex_lower(&s.operation_id),
                        s.decision_revision,
                        s.active_revision,
                        hex_lower(&s.active_hash)
                    ),
                ),
                ConfigOutcome::PermitAssembled => ("PERMIT_ASSEMBLED", String::new()),
                ConfigOutcome::NoChange => ("NO_CHANGE", String::new()),
                ConfigOutcome::Refused(r) => (
                    "REFUSED",
                    format!(",\"result\":\"{}\"", config_ops_result_name(*r)),
                ),
                ConfigOutcome::Timeout => ("TIMEOUT", String::new()),
                ConfigOutcome::Indeterminate => ("INDETERMINATE", String::new()),
                ConfigOutcome::ProtocolError => ("PROTOCOL_ERROR", String::new()),
            };
            format!(
                "{{{base},\"state\":\"{state}\"{detail},\"resolved_ms\":{}}}",
                record.resolved_ms.unwrap_or(0)
            )
        }
    }
}

/// Query response (01 §5: state, evidence, application_outcome and
/// observation are orthogonal fields). Payload bytes are never included:
/// READ_OPERATION must not leak what only READ_PAYLOAD may read — length
/// and hash suffice. `evidence` accumulates honestly: the retention tag
/// first, then each device-attested stage once it was actually reported —
/// GATEWAY_ACCEPTED when the stable MessageKey was learned,
/// MAC_ATTEMPT_REPORTED for a best-effort completion (never promoted to
/// END_SDK_RECEIVED), END_SDK_RECEIVED on the end receipt.
/// `application_outcome` stays null — APPLIED delivery is a later phase.
/// `deadline_elapsed` is a read-only wall-clock observation; the record's
/// `dispatch_state` is the committed conclusion.
fn op_status(record: &StoredOperation, lineage: &[u8; 16], now_ms: u64) -> String {
    let elapsed = now_ms.saturating_sub(record.accepted_ms) >= u64::from(record.ttl_ms);
    let mut evidence = vec![if record.storage == canonical::STORAGE_DURABLE {
        "HOST_DURABLE_RETAINED"
    } else {
        "HOST_RAM_RETAINED"
    }];
    let mut message_key = "null".to_string();
    let mut cancel_requested = false;
    let mut time_uncertain = record.dispatch_state == DispatchState::TimeUncertain;
    if let Some(att) = &record.dispatch {
        if att.ev_gateway_accepted {
            evidence.push("GATEWAY_ACCEPTED");
        }
        if att.ev_mac_attempt {
            evidence.push("MAC_ATTEMPT_REPORTED");
        }
        if att.ev_end_sdk {
            evidence.push("END_SDK_RECEIVED");
        }
        // Scope-2 terminal: the registered host's ReceiveLog stored the
        // payload — a distinct proof, never promoted to END_SDK_RECEIVED.
        if att.ev_host_receive {
            evidence.push("HOST_RAM_RECEIVED");
        }
        if let (Some(session), Some(seq)) = (att.msg_session, att.msg_seq) {
            message_key = format!("{{\"session\":\"{session:08x}\",\"sequence\":\"{seq:016x}\"}}");
        }
        cancel_requested = att.cancel_requested;
        time_uncertain |= att.time_uncertain;
    }
    let evidence_json = evidence
        .iter()
        .map(|tag| format!("\"{tag}\""))
        .collect::<Vec<_>>()
        .join(",");
    // A schema-2 record's destination reports the binding that was hashed
    // in — read back out of the retained canonical bytes, so the answer
    // always reflects what was committed rather than a parallel field.
    let destination_json = gateway_destination_json(record).unwrap_or_else(|| {
        format!(
            "{{\"kind\":\"{}\",\"id\":\"{:016x}\"}}",
            canonical::dest_kind_name(record.dest_kind),
            record.dest,
        )
    });
    format!(
        "{{\"operation_id\":\"{}\",\"network\":\"{:016x}\",\"admission_epoch\":\"{:016x}\",\"key\":\"{}\",\"destination\":{destination_json},\"payload_len\":{},\"canonical_hash\":\"{}\",\"options\":{{\"delivery\":\"{}\",\"priority\":\"{}\",\"ttl_ms\":{},\"deadline_policy\":\"WALL_ELAPSED_VALIDITY\",\"storage\":\"{}\",\"hop_limit\":{},\"persist_across_sleep\":false}},\"dispatch_state\":\"{}\",\"evidence\":[{evidence_json}],\"message_key\":{message_key},\"application_outcome\":null,\"observation\":{{\"deadline_elapsed\":{elapsed},\"cancel_requested\":{cancel_requested},\"time_uncertain\":{time_uncertain}}}}}",
        canonical::format_operation_id(lineage, record.seq),
        record.network,
        record.epoch,
        crate::receive_log::hex_lower(&record.key),
        record.payload.len(),
        crate::receive_log::hex_lower(&record.hash),
        canonical::delivery_name(record.delivery),
        canonical::priority_name(record.priority),
        record.ttl_ms,
        canonical::storage_name(record.storage),
        record.hop_limit,
        record.dispatch_state.name(),
    )
}

/// The schema-2 destination object for a gateway operation: the extension
/// is decoded out of the retained canonical bytes (version 2, dest_kind
/// gateway, 60-byte head) — `None` for anything else, so a record can
/// never report a binding it did not hash.
fn gateway_destination_json(record: &StoredOperation) -> Option<String> {
    let c = &record.canonical;
    if record.dest_kind != canonical::DEST_GATEWAY || c.len() < 60 || c[0] != 2 || c[5] != 1 {
        return None;
    }
    let scope = match c[24] {
        canonical::GATEWAY_SCOPE_SDK_RAM => "GATEWAY_SDK_RAM",
        canonical::GATEWAY_SCOPE_HOST_RAM => "HOST_RECEIVE_RAM",
        _ => return None,
    };
    let mut token = [0u8; 16];
    token.copy_from_slice(&c[26..42]);
    let gateway_boot = u64::from_be_bytes(c[42..50].try_into().expect("8"));
    let egress = u64::from_be_bytes(c[50..58].try_into().expect("8"));
    Some(format!(
        "{{\"kind\":\"gateway\",\"id\":\"{:016x}\",\"scope\":\"{scope}\",\"token\":\"{}\",\"gateway_boot\":\"{gateway_boot:016x}\",\"egress\":\"{egress:016x}\"}}",
        record.dest,
        crate::receive_log::hex_lower(&token),
    ))
}

/// Result of pushing one DataFromMesh payload into the log — surfaced as a
/// bounded diagnostic event when it is not a plain store/dedup.
pub fn ingest_diagnostic(outcome: &IngestOutcome) -> Option<String> {
    match outcome {
        IngestOutcome::Stored { .. } | IngestOutcome::Duplicate { .. } => None,
        IngestOutcome::Conflict { existing_seq } => Some(format!(
            "\"kind\":\"rx_conflict\",\"detail\":\"same MessageKey different payload\",\"existing_seq\":{existing_seq}"
        )),
        IngestOutcome::RejectedNetworkCap => Some(
            "\"kind\":\"rx_drop\",\"reason\":\"network_cap\"".to_string(),
        ),
        IngestOutcome::RejectedOversize => Some(
            "\"kind\":\"rx_drop\",\"reason\":\"payload_oversize\"".to_string(),
        ),
    }
}

/// Compile-time guard that the cursor budget holds.
const _: () = assert!(CURSOR_MAX_DECODED_BYTES >= 41);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::receive_log::Ingress;
    use crate::send_store::MemoryOperationStore;
    use std::sync::Mutex;

    fn acl_with(uid: u32) -> Acl {
        Acl::parse(&format!(
            "{{\"principals\":{{\"{uid}\":{{\"networks\":{{\"*\":[\"READ_PAYLOAD\"]}}}}}}}}"
        ))
        .unwrap()
    }

    fn send_acl() -> Acl {
        Acl::parse(
            "{\"principals\":{\"501\":{\"networks\":{\"0000000000000001\":[\"SEND\",\"READ_OPERATION\"]}},\"7\":{\"networks\":{\"0000000000000002\":[\"SEND\",\"READ_OPERATION\"]}}}}",
        )
        .unwrap()
    }

    fn ctx<'a, S: OperationStore>(
        uid: Option<u32>,
        acl: &'a Acl,
        log: &'a Mutex<ReceiveLog>,
        store: &'a Mutex<S>,
        limiter: &'a Mutex<AdmissionLimiter>,
        now: u64,
    ) -> ApiContext<'a, S> {
        // Node-path tests never touch the session/lane — fresh, empty
        // fixtures are leaked per call (test-local, no cross-test state).
        ctx_lane(
            uid,
            acl,
            log,
            store,
            limiter,
            leaked_session(),
            leaked_lane(),
            leaked_config_ops(),
            None,
            now,
        )
    }

    fn leaked_session() -> &'static Mutex<SessionInfo> {
        Box::leak(Box::new(Mutex::new(SessionInfo::default())))
    }

    fn leaked_lane() -> &'static crate::dispatch::GatewayLane {
        Box::leak(Box::new(crate::dispatch::GatewayLane::default()))
    }

    fn leaked_config_ops() -> &'static crate::dispatch::ConfigOps {
        Box::leak(Box::new(crate::dispatch::ConfigOps::default()))
    }

    #[allow(clippy::too_many_arguments)]
    fn ctx_lane<'a, S: OperationStore>(
        uid: Option<u32>,
        acl: &'a Acl,
        log: &'a Mutex<ReceiveLog>,
        store: &'a Mutex<S>,
        limiter: &'a Mutex<AdmissionLimiter>,
        session: &'a Mutex<SessionInfo>,
        lane: &'a crate::dispatch::GatewayLane,
        config_ops: &'a crate::dispatch::ConfigOps,
        config_authority: Option<u64>,
        now: u64,
    ) -> ApiContext<'a, S> {
        ApiContext {
            uid,
            acl,
            receive_log: log,
            operation_store: store,
            rate_limiter: limiter,
            session,
            gateway_lane: lane,
            config_ops,
            config_authority,
            now_ms: now,
            now_mono: now,
        }
    }

    #[allow(clippy::type_complexity)]
    fn test_env() -> (
        Acl,
        Mutex<ReceiveLog>,
        Mutex<MemoryOperationStore>,
        Mutex<AdmissionLimiter>,
    ) {
        (
            send_acl(),
            Mutex::new(ReceiveLog::new([9; 16])),
            Mutex::new(MemoryOperationStore::new([0xab; 16])),
            Mutex::new(AdmissionLimiter::new(0)),
        )
    }

    /// Open the epoch for uid 501 on network 1; returns the epoch token.
    fn open_test_epoch(
        acl: &Acl,
        log: &Mutex<ReceiveLog>,
        store: &Mutex<MemoryOperationStore>,
        limiter: &Mutex<AdmissionLimiter>,
    ) -> String {
        let c = ctx(Some(501), acl, log, store, limiter, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"e\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000001\"}}",
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        let parsed = routeloom_json::parse(&response).unwrap();
        parsed
            .get("result")
            .unwrap()
            .get("admission_epoch")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }

    fn submit_line(key: &str, epoch: &str) -> String {
        format!(
            "{{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"00ff\",\"payload_len\":2,\"options\":{{\"storage\":\"RAM_ONLY\"}}}}}}"
        )
    }

    fn result_field(response: &str, field: &str) -> String {
        let parsed = routeloom_json::parse(response).unwrap();
        parsed
            .get("result")
            .unwrap()
            .get(field)
            .unwrap()
            .as_str()
            .unwrap()
            .to_string()
    }

    /// Every error response must parse as JSON and carry the contracted
    /// envelope — `ok:false`, `error.code` string, `error.detail` object
    /// with a `message` member, `error.retryable` bool. Substring asserts
    /// missed the malformed `"detail":{,...}` emission; a real parse does
    /// not. Returns the document for per-code member checks.
    fn assert_error_schema(response: &str, code: &str) -> Json {
        let parsed = routeloom_json::parse(response).unwrap_or_else(|error| {
            panic!("{code} response is not valid JSON ({error}): {response}")
        });
        assert_eq!(
            parsed.get("v").and_then(Json::as_u64),
            Some(1),
            "{response}"
        );
        assert_eq!(
            parsed.get("ok").and_then(Json::as_bool),
            Some(false),
            "{response}"
        );
        let error = parsed.get("error").expect("error member missing");
        assert_eq!(
            error.get("code").and_then(Json::as_str),
            Some(code),
            "{response}"
        );
        let detail = error.get("detail").expect("detail member missing");
        assert!(matches!(detail, Json::Object(_)), "{response}");
        assert!(
            detail.get("message").and_then(Json::as_str).is_some(),
            "{response}"
        );
        assert!(
            error.get("retryable").and_then(Json::as_bool).is_some(),
            "{response}"
        );
        parsed
    }

    fn ingest(log: &Mutex<ReceiveLog>, network: u64, msg_seq: u64, payload: &[u8], ms: u64) {
        log.lock().unwrap().ingest(
            Ingress {
                network,
                gateway: Some(2),
                origin: 3,
                msg_session: 5,
                msg_seq,
                payload: payload.to_vec(),
            },
            ms,
        );
    }

    #[test]
    fn envelope_validation() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        // Missing request_id / bad v / unknown field / dup key / non-object.
        for body in [
            "{\"v\":1,\"method\":\"capabilities.get\"}",
            "{\"v\":2,\"request_id\":\"r\",\"method\":\"capabilities.get\"}",
            "{\"v\":1,\"request_id\":\"r\",\"method\":\"capabilities.get\",\"extra\":1}",
            "{\"v\":1,\"request_id\":\"r\",\"request_id\":\"r\",\"method\":\"capabilities.get\"}",
            "[1,2]",
            "{\"v\":1,\"request_id\":\"\",\"method\":\"capabilities.get\"}",
            "{\"v\":1.0,\"request_id\":\"r\",\"method\":\"capabilities.get\"}",
        ] {
            let response = handle(body.as_bytes(), &c);
            assert!(
                response.contains("\"ok\":false"),
                "expected rejection for {body}: {response}"
            );
            assert!(response.contains("INVALID_REQUEST"), "{response}");
        }
        // request_id over 64 chars.
        let long_id = format!(
            "{{\"v\":1,\"request_id\":\"{}\",\"method\":\"capabilities.get\"}}",
            "x".repeat(65)
        );
        assert!(handle(long_id.as_bytes(), &c).contains("INVALID_REQUEST"));
        // Depth beyond 8 (a nested value inside params still counts).
        let deep = "{\"v\":1,\"request_id\":\"r\",\"method\":\"x\",\"params\":{\"a\":{\"b\":{\"c\":{\"d\":{\"e\":{\"f\":{\"g\":{\"h\":1}}}}}}}}}";
        assert!(handle(deep.as_bytes(), &c).contains("INVALID_REQUEST"));
        // Bad UTF-8.
        let mut bad = b"API1 {\"v\":1}".to_vec();
        bad.push(0xff);
        assert!(handle(&bad[5..], &c).contains("INVALID_REQUEST"));
    }

    #[test]
    fn capabilities_reports_honest_set() {
        let acl = Acl::empty();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"c1\",\"method\":\"capabilities.get\"}",
            &c,
        );
        assert!(response.contains("\"ok\":true"));
        assert!(response.contains("\"messages.read\":true"));
        assert!(response.contains("\"messages.submit\":true"));
        assert!(response.contains("\"operations.open_epoch\":true"));
        assert!(response.contains("\"operations.get\":true"));
        assert!(response.contains("\"operations.get_by_key\":true"));
        assert!(response.contains("\"operations.cancel\":true"));
        assert!(response.contains("\"rx_events_v1\":false"));
        assert!(response.contains("\"ingress_loss_observable\":false"));
        assert!(response.contains("\"durable_receive\":false"));
        assert!(response.contains("\"pc_service_destination\":false"));
        assert!(response.contains("\"storage_durable\":false"));
        assert!(response.contains("\"dispatch\":\"usb_host_ops_v1\""));
    }

    #[test]
    fn unknown_method_rejected() {
        let acl = Acl::empty();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"u\",\"method\":\"bogus\",\"params\":{}}",
            &c,
        );
        assert!(response.contains("UNKNOWN_METHOD"));
    }

    #[test]
    fn messages_read_requires_acl_grant() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        ingest(&log, 1, 1, b"hello", 100);
        // Authorized uid reads the payload.
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 200);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(response.contains("\"payload_hex\":\"68656c6c6f\""));
        assert!(response.contains("\"payload_len\":5"));
        assert!(response.contains("\"endpoint_kind\":\"gateway_mirror\""));
        assert!(response.contains("\"evidence\":\"HOST_RAM_RETAINED\""));
        // Unknown uid and ungranted uid are denied, even though legacy
        // diagnostic verbs keep working for them.
        for uid in [None, Some(7)] {
            let c = ctx(uid, &acl, &log, &store, &limiter, 200);
            let response = handle(
                b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
                &c,
            );
            assert!(response.contains("AuthorizationFailed"), "{response}");
        }
    }

    #[test]
    fn messages_read_empty_is_normal() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"latest\"}}",
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(response.contains("\"records\":[]"));
        assert!(response.contains("\"more\":false"));
    }

    #[test]
    fn cursor_flow_and_errors() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        for i in 0..5_u64 {
            ingest(&log, 1, i, format!("m{i}").as_bytes(), 100);
        }
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 200);
        let first = handle(
            b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\",\"limit\":2}}",
            &c,
        );
        assert!(first.contains("\"more\":true"), "{first}");
        // Extract next_cursor and follow it.
        let parsed = routeloom_json::parse(&first).unwrap();
        let next = parsed
            .get("result")
            .unwrap()
            .get("next_cursor")
            .unwrap()
            .as_str()
            .unwrap()
            .to_string();
        let second = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"r2\",\"method\":\"messages.read\",\"params\":{{\"network\":\"0000000000000001\",\"cursor\":\"{next}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        // Payloads serialize as lowercase hex: "m2" is "6d32".
        assert!(second.contains("\"payload_hex\":\"6d32\""), "{second}");
        assert!(!second.contains("6d30"), "{second}");
        // Same cursor twice → same records (RX02).
        let again = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"r3\",\"method\":\"messages.read\",\"params\":{{\"network\":\"0000000000000001\",\"cursor\":\"{next}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(again.contains("\"payload_hex\":\"6d32\""));
        // Wrong network → scope mismatch.
        let wrong_net = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"r4\",\"method\":\"messages.read\",\"params\":{{\"network\":\"0000000000000002\",\"cursor\":\"{next}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(wrong_net.contains("CURSOR_SCOPE_MISMATCH"), "{wrong_net}");
        // Malformed / future cursors.
        let bad = handle(
            b"{\"v\":1,\"request_id\":\"r5\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"cursor\":\"!!bogus!!\"}}",
            &c,
        );
        assert!(bad.contains("INVALID_CURSOR"), "{bad}");
        let future = Cursor {
            network: 1,
            acl_view: acl.revision(),
            epoch: [9; 16],
            last_scanned: 999,
        }
        .encode();
        let fut = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"r6\",\"method\":\"messages.read\",\"params\":{{\"network\":\"0000000000000001\",\"cursor\":\"{future}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(fut.contains("INVALID_CURSOR"), "{fut}");
        // Different epoch → CURSOR_EPOCH_CHANGED with loss_count null.
        let old_epoch = Cursor {
            network: 1,
            acl_view: acl.revision(),
            epoch: [3; 16],
            last_scanned: 1,
        }
        .encode();
        let epoch_changed = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"r7\",\"method\":\"messages.read\",\"params\":{{\"network\":\"0000000000000001\",\"cursor\":\"{old_epoch}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(
            epoch_changed.contains("CURSOR_EPOCH_CHANGED"),
            "{epoch_changed}"
        );
        assert!(
            epoch_changed.contains("\"loss_count\":null"),
            "{epoch_changed}"
        );
        // Different ACL view → scope mismatch.
        let foreign_view = Cursor {
            network: 1,
            acl_view: 77,
            epoch: [9; 16],
            last_scanned: 1,
        }
        .encode();
        let scoped = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"r8\",\"method\":\"messages.read\",\"params\":{{\"network\":\"0000000000000001\",\"cursor\":\"{foreign_view}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(scoped.contains("CURSOR_SCOPE_MISMATCH"), "{scoped}");
    }

    #[test]
    fn messages_read_param_validation() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        for params in [
            "{\"from\":\"earliest\"}",            // no network
            "{\"network\":\"0000000000000001\"}", // neither
            "{\"network\":\"0000000000000001\",\"from\":\"earliest\",\"cursor\":\"AA\"}",
            "{\"network\":\"0000000000000001\",\"from\":\"now\"}",
            "{\"network\":\"0000000000000001\",\"from\":\"earliest\",\"limit\":0}",
            "{\"network\":\"0000000000000001\",\"from\":\"earliest\",\"limit\":33}",
            "{\"network\":\"0000000000000001\",\"from\":\"earliest\",\"limit\":2.5}",
            "{\"network\":\"0000000000000001\",\"from\":\"earliest\",\"bogus\":1}",
            "{\"network\":\"1\",\"from\":\"earliest\"}",
            "{\"network\":\"0000000100000000\",\"from\":\"earliest\"}", // > wire v1
        ] {
            let request = format!(
                "{{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{params}}}"
            );
            let response = handle(request.as_bytes(), &c);
            assert!(
                response.contains("INVALID_ARGUMENT"),
                "{params} → {response}"
            );
        }
        // Uppercase hex normalizes.
        let ok = handle(
            b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"00000000000000AB\",\"from\":\"earliest\"}}",
            &c,
        );
        assert!(ok.contains("\"ok\":true"), "{ok}");
    }

    #[test]
    fn gap_error_reports_lost_range_and_cursors() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        // Fill past the per-network cap so the front is reclaimed.
        for i in 0..(crate::receive_log::ENTRIES_PER_NETWORK + 2) as u64 {
            ingest(&log, 1, i, b"p", 100);
        }
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 200);
        let stale = Cursor {
            network: 1,
            acl_view: acl.revision(),
            epoch: [9; 16],
            last_scanned: 1,
        }
        .encode();
        let response = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{{\"network\":\"0000000000000001\",\"cursor\":\"{stale}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(response.contains("CURSOR_GAP"), "{response}");
        assert!(response.contains("\"lost_from\":2"), "{response}");
        assert!(response.contains("\"lost_to\":2"), "{response}");
        assert!(response.contains("oldest_cursor"), "{response}");
        assert!(response.contains("tail_cursor"), "{response}");
    }

    #[test]
    fn open_epoch_binds_and_requires_send() {
        let (acl, log, store, limiter) = test_env();
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let first = handle(
            b"{\"v\":1,\"request_id\":\"e1\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000001\"}}",
            &c,
        );
        assert!(first.contains("\"ok\":true"), "{first}");
        assert!(
            first.contains("\"admission_epoch\":\"0000000000000001\""),
            "{first}"
        );
        // Re-open binds the same epoch.
        let second = handle(
            b"{\"v\":1,\"request_id\":\"e2\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000001\"}}",
            &c,
        );
        assert!(
            second.contains("\"admission_epoch\":\"0000000000000001\""),
            "{second}"
        );
        // Unknown uid, ungranted network and bad params are denied/rejected.
        for (uid, params, code) in [
            (
                None,
                "{\"network\":\"0000000000000001\"}",
                "AuthorizationFailed",
            ),
            (
                Some(7),
                "{\"network\":\"0000000000000001\"}",
                "AuthorizationFailed",
            ),
            (
                Some(501),
                "{\"network\":\"0000000000000002\"}",
                "AuthorizationFailed",
            ),
            (
                Some(501),
                "{\"network\":\"0000000100000000\"}",
                "INVALID_ARGUMENT",
            ),
            (
                Some(501),
                "{\"network\":\"0000000000000001\",\"extra\":1}",
                "INVALID_ARGUMENT",
            ),
            (Some(501), "{}", "INVALID_ARGUMENT"),
        ] {
            let c = ctx(uid, &acl, &log, &store, &limiter, 0);
            let request = format!(
                "{{\"v\":1,\"request_id\":\"e\",\"method\":\"operations.open_epoch\",\"params\":{params}}}"
            );
            let response = handle(request.as_bytes(), &c);
            assert!(response.contains(code), "{params} → {response}");
        }
    }

    #[test]
    fn submit_accepts_replays_and_conflicts() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 1000);
        let key = "00112233445566778899aabbccddeeff";
        let first = handle(submit_line(key, &epoch).as_bytes(), &c);
        assert!(first.contains("\"ok\":true"), "{first}");
        assert!(
            first.contains("\"dispatch_state\":\"HOST_QUEUED\""),
            "{first}"
        );
        assert!(
            first.contains("\"evidence\":[\"HOST_RAM_RETAINED\"]"),
            "{first}"
        );
        assert!(first.contains("\"message_key\":null"), "{first}");
        assert!(!first.contains("HOST_DURABLE_RETAINED"), "{first}");
        let id = result_field(&first, "operation_id");
        assert!(id.ends_with(":0000000000000001"), "{id}");
        // Replay: same key+payload returns the same OperationId.
        let replay = handle(submit_line(key, &epoch).as_bytes(), &c);
        assert_eq!(result_field(&replay, "operation_id"), id, "{replay}");
        // Conflict: same key, different payload — original preserved.
        let conflict = format!(
            "{{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"ffff\",\"payload_len\":2,\"options\":{{\"storage\":\"RAM_ONLY\"}}}}}}"
        );
        let response = handle(conflict.as_bytes(), &c);
        assert!(response.contains("CONFLICT"), "{response}");
        assert!(
            response.contains(&format!("\"existing_operation_id\":\"{id}\"")),
            "{response}"
        );
        // The original still replays.
        let again = handle(submit_line(key, &epoch).as_bytes(), &c);
        assert_eq!(result_field(&again, "operation_id"), id);
    }

    #[test]
    fn submit_requires_open_epoch_and_send_grant() {
        let (acl, log, store, limiter) = test_env();
        // No epoch opened yet: well-formed submit is rejected.
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let response = handle(
            submit_line("00112233445566778899aabbccddeeff", "0000000000000001").as_bytes(),
            &c,
        );
        assert!(response.contains("INVALID_ARGUMENT"), "{response}");
        assert!(response.contains("open_epoch"), "{response}");
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        // SEND denied without a grant; principal is the peer uid, never a
        // request field (which is itself an unknown-param reject).
        for uid in [None, Some(7)] {
            let c = ctx(uid, &acl, &log, &store, &limiter, 0);
            let response = handle(
                submit_line("00112233445566778899aabbccddeeff", &epoch).as_bytes(),
                &c,
            );
            assert!(response.contains("AuthorizationFailed"), "{response}");
        }
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let spoofed = format!(
            "{{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"00112233445566778899aabbccddeeff\",\"principal\":7,\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{{\"storage\":\"RAM_ONLY\"}}}}}}"
        );
        assert!(handle(spoofed.as_bytes(), &c).contains("INVALID_ARGUMENT"));
    }

    #[test]
    fn submit_validation_rejects() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let base = |params: &str| {
            format!("{{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{params}}}")
        };
        let valid_options = "\"options\":{\"storage\":\"RAM_ONLY\"}";
        let params = |body: &str| {
            format!("{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",{body}}}")
        };
        let big = "00".repeat(129);
        for (params, code) in [
            (
                params(&format!(
                    "\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"{big}\",\"payload_len\":129,{valid_options}"
                )),
                "PAYLOAD_TOO_LARGE",
            ),
            (
                params(                   "\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{\"storage\":\"RAM_ONLY\",\"delivery\":\"APPLIED\"}"),
                "UNSUPPORTED",
            ),
            (
                params(                   "\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{\"storage\":\"RAM_ONLY\",\"priority\":\"URGENT\"}"),
                "UNSUPPORTED",
            ),
            (
                params(                   "\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0"),
                "UNSUPPORTED", // HOST_DURABLE default, no durable store yet
            ),
            (
                params(                   "\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{\"storage\":\"RAM_ONLY\",\"ttl_ms\":0}"),
                "INVALID_ARGUMENT",
            ),
            (
                params(                   "\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{\"storage\":\"RAM_ONLY\",\"future_flag\":true}"),
                "INVALID_ARGUMENT",
            ),
            (
                params(&format!(
                    "\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"0\",\"payload_len\":1,{valid_options}"
                )),
                "INVALID_ARGUMENT",
            ),
        ] {
            let response = handle(base(&params).as_bytes(), &c);
            assert!(response.contains(code), "{params} → {response}");
        }
    }

    #[test]
    fn query_needs_read_operation_and_is_network_scoped() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let key = "00112233445566778899aabbccddeeff";
        let submitter = ctx(Some(501), &acl, &log, &store, &limiter, 1000);
        let accepted = handle(submit_line(key, &epoch).as_bytes(), &submitter);
        let id = result_field(&accepted, "operation_id");
        // Owner queries by id and by key.
        for request in [
            format!(
                "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
            ),
            format!(
                "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get_by_key\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\"}}}}"
            ),
        ] {
            let response = handle(request.as_bytes(), &submitter);
            assert!(response.contains("\"ok\":true"), "{response}");
            assert!(response.contains(&format!("\"operation_id\":\"{id}\"")), "{response}");
            assert!(response.contains("\"payload_len\":2"), "{response}");
            assert!(response.contains("\"canonical_hash\":\""), "{response}");
            assert!(response.contains("\"dispatch_state\":\"HOST_QUEUED\""), "{response}");
            assert!(!response.contains("payload_hex"), "{response}");
        }
        // deadline_elapsed flips once ttl passes (read-only observation).
        let late = ctx(Some(501), &acl, &log, &store, &limiter, 1000 + 5000);
        let request = format!(
            "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
        );
        let response = handle(request.as_bytes(), &late);
        assert!(response.contains("\"deadline_elapsed\":true"), "{response}");
        // Another uid's grant is scoped to network 2: on network 1's
        // record it sees the same NOT_FOUND as a missing id (never an
        // existence leak), and its own key namespace finds nothing.
        let other = ctx(Some(7), &acl, &log, &store, &limiter, 1000);
        let by_id = format!(
            "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
        );
        let denied = handle(by_id.as_bytes(), &other);
        assert!(denied.contains("NOT_FOUND"), "{denied}");
        assert!(!denied.contains("AuthorizationFailed"), "{denied}");
        let by_key = format!(
            "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get_by_key\",\"params\":{{\"network\":\"0000000000000002\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\"}}}}"
        );
        assert!(handle(by_key.as_bytes(), &other).contains("NOT_FOUND"));
        // Unknown id/key and malformed ids.
        for request in [
            "{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{\"operation_id\":\"abababababababababababababababab:0000000000000009\"}}".to_string(),
            "{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{\"operation_id\":\"not-an-id\"}}".to_string(),
            format!(
                "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get_by_key\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"ffffffffffffffffffffffffffffffff\"}}}}"
            ),
        ] {
            let response = handle(request.as_bytes(), &submitter);
            assert!(
                response.contains("NOT_FOUND") || response.contains("INVALID_ARGUMENT"),
                "{response}"
            );
        }
        // Wrong-store lineage never resolves.
        let foreign = "{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{\"operation_id\":\"00000000000000000000000000000000:0000000000000001\"}}";
        assert!(handle(foreign.as_bytes(), &submitter).contains("NOT_FOUND"));
    }

    /// CAP04 over the wire: rotation closes the epoch; new keys fail
    /// with EPOCH_CLOSED while the known key replays and stays queryable.
    #[test]
    fn closed_epoch_rejects_new_keys_but_replays_known() {
        let (acl, log, store, limiter) = test_env();
        let first = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let key = "00112233445566778899aabbccddeeff";
        let accepted = handle(submit_line(key, &epoch).as_bytes(), &first);
        let id = result_field(&accepted, "operation_id");
        // An hour later the daemon rotates to epoch 2.
        let later = ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            crate::send_store::EPOCH_WINDOW_MS,
        );
        let rotated = handle(
            b"{\"v\":1,\"request_id\":\"e2\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000001\"}}",
            &later,
        );
        assert!(
            rotated.contains("\"admission_epoch\":\"0000000000000002\""),
            "{rotated}"
        );
        let fresh = submit_line("ffffffffffffffffffffffffffffffff", &epoch);
        let closed = handle(fresh.as_bytes(), &later);
        assert!(closed.contains("EPOCH_CLOSED"), "{closed}");
        assert!(closed.contains("\"retryable\":false"), "{closed}");
        // Same key+payload still replays the original id; queries work.
        let replay = handle(submit_line(key, &epoch).as_bytes(), &later);
        assert_eq!(result_field(&replay, "operation_id"), id, "{replay}");
        let query = format!(
            "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get_by_key\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\"}}}}"
        );
        let status = handle(query.as_bytes(), &later);
        assert!(status.contains("\"ok\":true"), "{status}");
        assert!(
            status.contains(&format!("\"operation_id\":\"{id}\"")),
            "{status}"
        );
    }

    /// CAP-I1 restart over the wire: HOST_DURABLE submits are admitted
    /// with durable evidence, and a reopened store answers the same ids.
    #[test]
    fn durable_submit_survives_store_reopen() {
        use crate::sqlite_store::SqliteOperationStore;
        let path = std::env::temp_dir().join(format!(
            "routeloom-cap1-api1-{}-{}.db",
            std::process::id(),
            "restart"
        ));
        let _ = std::fs::remove_file(&path);
        let acl = send_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let durable_lineage;
        let id;
        {
            let store = Mutex::new(SqliteOperationStore::open(&path).unwrap());
            durable_lineage = store.lock().unwrap().lineage();
            let c = ctx(Some(501), &acl, &log, &store, &limiter, 1000);
            let caps = handle(
                b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capabilities.get\"}",
                &c,
            );
            assert!(caps.contains("\"storage_durable\":true"), "{caps}");
            let epoch = handle(
                b"{\"v\":1,\"request_id\":\"e\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000001\"}}",
                &c,
            );
            assert!(
                epoch.contains("\"admission_epoch\":\"0000000000000001\""),
                "{epoch}"
            );
            // Default options mean HOST_DURABLE — admittable here.
            let submit = handle(
                b"{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00ff\",\"payload_len\":2}}",
                &c,
            );
            assert!(submit.contains("\"ok\":true"), "{submit}");
            assert!(
                submit.contains("\"evidence\":[\"HOST_DURABLE_RETAINED\"]"),
                "{submit}"
            );
            id = result_field(&submit, "operation_id");
            // RAM_ONLY still admits, tagged for what it is.
            let ram = handle(
                b"{\"v\":1,\"request_id\":\"s2\",\"method\":\"messages.submit\",\"params\":{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{\"storage\":\"RAM_ONLY\"}}}",
                &c,
            );
            assert!(
                ram.contains("\"evidence\":[\"HOST_RAM_RETAINED\"]"),
                "{ram}"
            );
        }
        // Simulate the daemon restart: reopen the same file.
        {
            let store = Mutex::new(SqliteOperationStore::open(&path).unwrap());
            assert_eq!(store.lock().unwrap().lineage(), durable_lineage);
            let c = ctx(Some(501), &acl, &log, &store, &limiter, 2000);
            let query = format!(
                "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
            );
            let status = handle(query.as_bytes(), &c);
            assert!(status.contains("\"ok\":true"), "{status}");
            assert!(status.contains("\"payload_len\":2"), "{status}");
            assert!(
                status.contains("\"dispatch_state\":\"HOST_QUEUED\""),
                "{status}"
            );
            assert!(
                status.contains("\"evidence\":[\"HOST_DURABLE_RETAINED\"]"),
                "{status}"
            );
            // The RAM record did not survive the restart.
            let gone = handle(
                b"{\"v\":1,\"request_id\":\"q2\",\"method\":\"operations.get_by_key\",\"params\":{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\"}}",
                &c,
            );
            assert!(gone.contains("NOT_FOUND"), "{gone}");
        }
        let _ = std::fs::remove_file(&path);
        for suffix in ["-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    #[test]
    fn full_table_reports_no_capacity() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        {
            let mut guard = store.lock().unwrap();
            for i in 0..crate::send_store::RECORD_CAP {
                let json = format!(
                    "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{i:032x}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{{\"storage\":\"RAM_ONLY\"}}}}"
                );
                let req =
                    canonical::parse_submit(&routeloom_json::parse(&json).unwrap(), None).unwrap();
                assert!(matches!(
                    guard.submit(501, &req, 0),
                    SubmitOutcome::Accepted { .. }
                ));
            }
        }
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let response = handle(
            submit_line("ffffffffffffffffffffffffffffffff", &epoch).as_bytes(),
            &c,
        );
        assert!(response.contains("NO_CAPACITY"), "{response}");
        assert!(response.contains("\"free_slots\":0"), "{response}");
        assert!(response.contains("\"free_bytes\":0"), "{response}");
        assert!(response.contains("\"reclaimable_at\":null"), "{response}");
        assert!(response.contains("\"retryable\":true"), "{response}");
    }

    /// Rate limiting (capacity.host_rate_per_minute/burst, 04 §4):
    /// open_epoch and submit share one budget, the burst drains then
    /// denial names the tighter scope, duplicates are still charged, and
    /// a token interval later admission recovers.
    #[test]
    fn admission_rate_limit_scopes_and_recovers() {
        let (acl, log, store, limiter) = test_env();
        // open_epoch itself spends from the same budget.
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let key = |i: usize| format!("{i:032x}");
        // Burst: open_epoch + 15 submits spend all 16 tokens.
        for i in 0..15 {
            let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
            let response = handle(submit_line(&key(i), &epoch).as_bytes(), &c);
            assert!(response.contains("\"ok\":true"), "{i}: {response}");
        }
        // Next submit from the same principal: its own bucket is empty.
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let denied = handle(submit_line(&key(15), &epoch).as_bytes(), &c);
        assert!(denied.contains("RATE_LIMITED"), "{denied}");
        assert!(denied.contains("\"scope\":\"principal\""), "{denied}");
        assert!(denied.contains("\"retryable\":true"), "{denied}");
        assert!(denied.contains("\"retry_after_ms\":"), "{denied}");
        // Duplicates are charged too: replaying a known key throttles
        // rather than answering for free.
        let replay = handle(submit_line(&key(0), &epoch).as_bytes(), &c);
        assert!(replay.contains("RATE_LIMITED"), "{replay}");
        // The shared bucket binds other principals: uid 7's open_epoch on
        // its own network is throttled by the global scope.
        let c7 = ctx(Some(7), &acl, &log, &store, &limiter, 0);
        let denied7 = handle(
            b"{\"v\":1,\"request_id\":\"e\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000002\"}}",
            &c7,
        );
        assert!(denied7.contains("RATE_LIMITED"), "{denied7}");
        assert!(denied7.contains("\"scope\":\"global\""), "{denied7}");
        // One token-interval later a single admission succeeds again.
        let later = ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            crate::send_store::RATE_TOKEN_INTERVAL_MS,
        );
        let ok = handle(submit_line(&key(15), &epoch).as_bytes(), &later);
        assert!(ok.contains("\"ok\":true"), "{ok}");
    }

    fn get_line(operation_id: &str) -> String {
        format!(
            "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{operation_id}\"}}}}"
        )
    }

    fn cancel_line(operation_id: &str) -> String {
        format!(
            "{{\"v\":1,\"request_id\":\"x\",\"method\":\"operations.cancel\",\"params\":{{\"operation_id\":\"{operation_id}\"}}}}"
        )
    }

    /// TX-I2 `operations.cancel` (03 §5): linearized against dispatch —
    /// cancellable only while no external write may have begun, late
    /// requests answer CANCEL_TOO_LATE and still record the observation.
    #[test]
    fn operations_cancel_lifecycle() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let owner = ctx(Some(501), &acl, &log, &store, &limiter, 1000);
        let accepted = handle(
            submit_line("00112233445566778899aabbccddeeff", &epoch).as_bytes(),
            &owner,
        );
        let id = result_field(&accepted, "operation_id");
        // Owner cancels a still-queued record: ok + the committed status.
        let response = handle(cancel_line(&id).as_bytes(), &owner);
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(
            response.contains("\"dispatch_state\":\"CANCELLED_BEFORE_DISPATCH\""),
            "{response}"
        );
        // A second cancel hits the committed terminal state → TOO_LATE.
        let again = handle(cancel_line(&id).as_bytes(), &owner);
        assert!(again.contains("\"ok\":false"), "{again}");
        assert!(again.contains("CANCEL_TOO_LATE"), "{again}");
        assert!(
            again.contains("\"dispatch_state\":\"CANCELLED_BEFORE_DISPATCH\""),
            "{again}"
        );
        // Non-owner and unidentified principals see the same NOT_FOUND as
        // a missing id — cancel is not an existence oracle. Malformed ids
        // get their own codes.
        let key2 = "11111111111111111111111111111111";
        let accepted2 = handle(submit_line(key2, &epoch).as_bytes(), &owner);
        let id2 = result_field(&accepted2, "operation_id");
        for uid in [None, Some(7)] {
            let c = ctx(uid, &acl, &log, &store, &limiter, 1000);
            let response = handle(cancel_line(&id2).as_bytes(), &c);
            assert!(response.contains("NOT_FOUND"), "{uid:?}: {response}");
            assert!(
                !response.contains("AuthorizationFailed"),
                "{uid:?}: {response}"
            );
        }
        let response = handle(
            cancel_line("abababababababababababababababab:0000000000000009").as_bytes(),
            &owner,
        );
        assert!(response.contains("NOT_FOUND"), "{response}");
        let response = handle(cancel_line("not-an-id").as_bytes(), &owner);
        assert!(response.contains("INVALID_ARGUMENT"), "{response}");
        let response = handle(
            b"{\"v\":1,\"request_id\":\"x\",\"method\":\"operations.cancel\",\"params\":{}}",
            &owner,
        );
        assert!(response.contains("INVALID_ARGUMENT"), "{response}");
        // Once a USB write may have left, cancel is TOO_LATE — and the
        // observation lands on the record for later queries.
        {
            let mut guard = store.lock().unwrap();
            let seq = 2_u64; // second submit
            assert!(matches!(
                guard.prepare_dispatch(seq, [9; 16], [8; 16]).unwrap(),
                crate::send_store::PrepareOutcome::Prepared(_)
            ));
            guard
                .update_operation(seq, &mut |op| {
                    if let Some(d) = op.dispatch.as_mut() {
                        d.submitted = true;
                    }
                    true
                })
                .unwrap();
        }
        let late = handle(cancel_line(&id2).as_bytes(), &owner);
        assert!(late.contains("CANCEL_TOO_LATE"), "{late}");
        assert!(
            late.contains("\"dispatch_state\":\"DISPATCH_PREPARED\""),
            "{late}"
        );
        let query = format!(
            "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id2}\"}}}}"
        );
        let status = handle(query.as_bytes(), &owner);
        assert!(status.contains("\"cancel_requested\":true"), "{status}");
        assert!(
            status.contains("\"dispatch_state\":\"DISPATCH_PREPARED\""),
            "{status}"
        );
    }

    /// Evidence/message_key/observation fields follow the committed
    /// attachment rather than staying static placeholders.
    #[test]
    fn op_status_reflects_dispatch_evidence() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let owner = ctx(Some(501), &acl, &log, &store, &limiter, 1000);
        let accepted = handle(
            submit_line("00112233445566778899aabbccddeeff", &epoch).as_bytes(),
            &owner,
        );
        let id = result_field(&accepted, "operation_id");
        {
            let mut guard = store.lock().unwrap();
            guard.prepare_dispatch(1, [9; 16], [8; 16]).unwrap();
            guard
                .update_operation(1, &mut |op| {
                    let d = op.dispatch.as_mut().unwrap();
                    d.submitted = true;
                    d.ev_gateway_accepted = true;
                    d.msg_session = Some(0x0abc);
                    d.msg_seq = Some(77);
                    op.dispatch_state = crate::send_store::DispatchState::GatewayAccepted;
                    true
                })
                .unwrap();
        }
        let query = format!(
            "{{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
        );
        let status = handle(query.as_bytes(), &owner);
        assert!(
            status.contains("\"evidence\":[\"HOST_RAM_RETAINED\",\"GATEWAY_ACCEPTED\"]"),
            "{status}"
        );
        assert!(
            status.contains(
                "\"message_key\":{\"session\":\"00000abc\",\"sequence\":\"000000000000004d\"}"
            ),
            "{status}"
        );
        assert!(status.contains("\"application_outcome\":null"), "{status}");
        assert!(status.contains("\"cancel_requested\":false"), "{status}");
        assert!(status.contains("\"time_uncertain\":false"), "{status}");
    }

    /// capabilities.get takes no params: a non-empty object is the same
    /// INVALID_ARGUMENT every sibling method returns for unknown keys.
    #[test]
    fn capabilities_get_rejects_params() {
        let acl = Acl::empty();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capabilities.get\",\"params\":{\"anything\":1}}",
            &c,
        );
        assert!(response.contains("INVALID_ARGUMENT"), "{response}");
        assert!(response.contains("\"ok\":false"), "{response}");
        // An empty params object stays accepted.
        let ok = handle(
            b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capabilities.get\",\"params\":{}}",
            &c,
        );
        assert!(ok.contains("\"ok\":true"), "{ok}");
    }

    /// request_id must be printable ASCII: C0 controls smuggled through
    /// \uXXXX escapes (and DEL/non-ASCII) are rejected, while plain
    /// printable ids — spaces included — still pass.
    #[test]
    fn request_id_must_be_printable_ascii() {
        let acl = Acl::empty();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        for id in ["\\u0001", "a\\u001fb", "\\u007f", "\\u00e9"] {
            let request =
                format!("{{\"v\":1,\"request_id\":\"{id}\",\"method\":\"capabilities.get\"}}");
            let response = handle(request.as_bytes(), &c);
            assert!(response.contains("INVALID_REQUEST"), "{id} → {response}");
        }
        let ok = handle(
            b"{\"v\":1,\"request_id\":\"req 42 ~!\",\"method\":\"capabilities.get\"}",
            &c,
        );
        assert!(ok.contains("\"ok\":true"), "{ok}");
    }

    /// operations.get and operations.cancel answer an unauthorized caller
    /// with exactly the NOT_FOUND a missing id gets — same code, same
    /// message — so neither is an existence oracle.
    #[test]
    fn get_and_cancel_are_not_existence_oracles() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let owner = ctx(Some(501), &acl, &log, &store, &limiter, 1000);
        let accepted = handle(
            submit_line("00112233445566778899aabbccddeeff", &epoch).as_bytes(),
            &owner,
        );
        let id = result_field(&accepted, "operation_id");
        // Same lineage, never-issued sequence: a truly missing id.
        let missing_id = format!("{}:0000000000000009", id.split(':').next().unwrap());
        // uid 7's grant is scoped to network 2; the record lives on 1.
        // An unidentified principal is denied the same way.
        for uid in [Some(7), None] {
            let other = ctx(uid, &acl, &log, &store, &limiter, 1000);
            for method in ["operations.get", "operations.cancel"] {
                let real = format!(
                    "{{\"v\":1,\"request_id\":\"q\",\"method\":\"{method}\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
                );
                let missing = format!(
                    "{{\"v\":1,\"request_id\":\"q\",\"method\":\"{method}\",\"params\":{{\"operation_id\":\"{missing_id}\"}}}}"
                );
                let real_response = handle(real.as_bytes(), &other);
                let missing_response = handle(missing.as_bytes(), &other);
                assert!(real_response.contains("NOT_FOUND"), "{real_response}");
                assert!(
                    !real_response.contains("AuthorizationFailed"),
                    "{real_response}"
                );
                assert_eq!(
                    real_response, missing_response,
                    "{method} leaked existence to {uid:?}"
                );
            }
        }
    }

    /// A cursor claiming last_scanned > 0 on a network that never
    /// ingested a record is a future/forged position: INVALID_CURSOR,
    /// not a successful empty page ratifying the claim.
    #[test]
    fn forged_cursor_on_absent_network_is_invalid() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 200);
        // from=earliest on the absent network is still a normal empty page.
        let empty = handle(
            b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000002\",\"from\":\"earliest\"}}",
            &c,
        );
        assert!(empty.contains("\"ok\":true"), "{empty}");
        assert!(empty.contains("\"records\":[]"), "{empty}");
        let forged = Cursor {
            network: 2,
            acl_view: acl.revision(),
            epoch: [9; 16],
            last_scanned: 5,
        }
        .encode();
        let response = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{{\"network\":\"0000000000000002\",\"cursor\":\"{forged}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(response.contains("INVALID_CURSOR"), "{response}");
    }

    /// Regression for the malformed `"detail":{,...}` emission: every
    /// error path — message-only (simple) and each format!-built
    /// multi-field detail — must emit a document a real JSON parser
    /// accepts, with the contracted envelope shape.
    #[test]
    fn error_responses_are_valid_json() {
        // Envelope, method and receive-path errors (READ_PAYLOAD grant).
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        for (body, code) in [
            ("{\"v\":1,\"method\":\"x\"}", "INVALID_REQUEST"),
            (
                "{\"v\":1,\"request_id\":\"u\",\"method\":\"bogus\"}",
                "UNKNOWN_METHOD",
            ),
            (
                "{\"v\":1,\"request_id\":\"u\",\"method\":\"capabilities.get\",\"params\":{\"x\":1}}",
                "INVALID_ARGUMENT",
            ),
            (
                "{\"v\":1,\"request_id\":\"u\",\"method\":\"messages.read\",\"params\":{\"from\":\"earliest\"}}",
                "INVALID_ARGUMENT",
            ),
            (
                "{\"v\":1,\"request_id\":\"u\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"cursor\":\"!!bogus!!\"}}",
                "INVALID_CURSOR",
            ),
        ] {
            assert_error_schema(&handle(body.as_bytes(), &c), code);
        }
        let denied = ctx(None, &acl, &log, &store, &limiter, 0);
        assert_error_schema(
            &handle(
                b"{\"v\":1,\"request_id\":\"u\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
                &denied,
            ),
            "AuthorizationFailed",
        );
        // Cursor errors carry multi-field details: each member must be a
        // real object member, not a comma-glued fragment.
        for i in 0..(crate::receive_log::ENTRIES_PER_NETWORK + 2) as u64 {
            ingest(&log, 1, i, b"p", 100);
        }
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 200);
        let mint = |network: u64, epoch: [u8; 16], last_scanned: u64| {
            Cursor {
                network,
                acl_view: acl.revision(),
                epoch,
                last_scanned,
            }
            .encode()
        };
        let read = |network: &str, token: &str| {
            handle(
                format!(
                    "{{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{{\"network\":\"{network}\",\"cursor\":\"{token}\"}}}}"
                )
                .as_bytes(),
                &c,
            )
        };
        assert_error_schema(
            &read("0000000000000002", &mint(1, [9; 16], 1)),
            "CURSOR_SCOPE_MISMATCH",
        );
        let epoch_changed = assert_error_schema(
            &read("0000000000000001", &mint(1, [3; 16], 1)),
            "CURSOR_EPOCH_CHANGED",
        );
        let detail = epoch_changed.get("error").unwrap().get("detail").unwrap();
        assert!(detail.get("loss_count").unwrap().is_null());
        assert!(detail.get("oldest_cursor").unwrap().as_str().is_some());
        assert!(detail.get("tail_cursor").unwrap().as_str().is_some());
        let gap = assert_error_schema(
            &read("0000000000000001", &mint(1, [9; 16], 1)),
            "CURSOR_GAP",
        );
        let detail = gap.get("error").unwrap().get("detail").unwrap();
        assert!(detail.get("lost_from").unwrap().as_u64().is_some());
        assert!(detail.get("lost_to").unwrap().as_u64().is_some());

        // Send-path and store errors (SEND + READ_OPERATION grants).
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let submit = |params: &str| {
            format!("{{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{params}}}")
        };
        let key = "00112233445566778899aabbccddeeff";
        let big = "00".repeat(129);
        for (params, code) in [
            (
                format!(
                    "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"{big}\",\"payload_len\":129,\"options\":{{\"storage\":\"RAM_ONLY\"}}}}"
                ),
                "PAYLOAD_TOO_LARGE",
            ),
            (
                format!(
                    "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{{\"storage\":\"RAM_ONLY\",\"delivery\":\"APPLIED\"}}}}"
                ),
                "UNSUPPORTED",
            ),
        ] {
            assert_error_schema(&handle(submit(&params).as_bytes(), &c), code);
        }
        // Accept, then same key + different bytes → CONFLICT carrying the
        // existing id as a real member.
        let accepted = handle(submit_line(key, &epoch).as_bytes(), &c);
        let id = result_field(&accepted, "operation_id");
        let conflict = submit(&format!(
            "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"ffff\",\"payload_len\":2,\"options\":{{\"storage\":\"RAM_ONLY\"}}}}"
        ));
        let conflicted = assert_error_schema(&handle(conflict.as_bytes(), &c), "CONFLICT");
        assert_eq!(
            conflicted
                .get("error")
                .unwrap()
                .get("detail")
                .unwrap()
                .get("existing_operation_id")
                .unwrap()
                .as_str(),
            Some(id.as_str())
        );
        // A never-issued seq is NOT_FOUND.
        let missing = format!("{}:00000000000000ff", id.split(':').next().unwrap());
        assert_error_schema(&handle(get_line(&missing).as_bytes(), &c), "NOT_FOUND");
        // The second cancel lands on the committed terminal state →
        // CANCEL_TOO_LATE with dispatch_state as a real member.
        let cancelled = handle(cancel_line(&id).as_bytes(), &c);
        assert!(cancelled.contains("\"ok\":true"), "{cancelled}");
        let too_late =
            assert_error_schema(&handle(cancel_line(&id).as_bytes(), &c), "CANCEL_TOO_LATE");
        assert_eq!(
            too_late
                .get("error")
                .unwrap()
                .get("detail")
                .unwrap()
                .get("dispatch_state")
                .unwrap()
                .as_str(),
            Some("CANCELLED_BEFORE_DISPATCH")
        );
        // Fill the table (direct store writes, like the capacity test);
        // a fresh key then answers NO_CAPACITY with numeric members.
        {
            let mut guard = store.lock().unwrap();
            for i in 0..crate::send_store::RECORD_CAP {
                let json = format!(
                    "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{i:032x}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{{\"storage\":\"RAM_ONLY\"}}}}"
                );
                let req =
                    canonical::parse_submit(&routeloom_json::parse(&json).unwrap(), None).unwrap();
                let _ = guard.submit(501, &req, 0);
            }
        }
        let full = assert_error_schema(
            &handle(
                submit_line("ffffffffffffffffffffffffffffffff", &epoch).as_bytes(),
                &c,
            ),
            "NO_CAPACITY",
        );
        let detail = full.get("error").unwrap().get("detail").unwrap();
        assert_eq!(detail.get("free_slots").unwrap().as_u64(), Some(0));
        assert_eq!(detail.get("free_bytes").unwrap().as_u64(), Some(0));
        assert!(detail.get("reclaimable_at").unwrap().as_u64().is_some());
        // RATE_LIMITED: drain the admission budget (some tokens already
        // spent above); each rejection is still a valid envelope.
        let mut limited = None;
        for i in 0..64_u64 {
            let response = handle(submit_line(&format!("ff{i:030x}"), &epoch).as_bytes(), &c);
            if response.contains("RATE_LIMITED") {
                limited = Some(assert_error_schema(&response, "RATE_LIMITED"));
                break;
            }
            assert_error_schema(&response, "NO_CAPACITY");
        }
        let limited = limited.expect("admission budget drains within 64 submits");
        let detail = limited.get("error").unwrap().get("detail").unwrap();
        assert_eq!(detail.get("scope").unwrap().as_str(), Some("principal"));
        assert!(detail.get("retry_after_ms").unwrap().as_u64().is_some());
        assert_eq!(
            limited
                .get("error")
                .unwrap()
                .get("retryable")
                .unwrap()
                .as_bool(),
            Some(true)
        );
        // Rotating the epoch closes it for new keys → EPOCH_CLOSED.
        let later = ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            crate::send_store::EPOCH_WINDOW_MS,
        );
        let rotated = handle(
            b"{\"v\":1,\"request_id\":\"e\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000001\"}}",
            &later,
        );
        assert!(
            rotated.contains("\"admission_epoch\":\"0000000000000002\""),
            "{rotated}"
        );
        assert_error_schema(
            &handle(
                submit_line("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", &epoch).as_bytes(),
                &later,
            ),
            "EPOCH_CLOSED",
        );
        // The response-size fallback is a hand-written literal; it must
        // satisfy the same envelope contract.
        assert_error_schema(&bound_response("x".repeat(RESPONSE_MAX_BYTES)), "INTERNAL");
    }

    /// STORE_RECOVERY_REQUIRED over the wire: a vetoed store commit must
    /// still surface as a well-formed error envelope.
    #[test]
    fn store_fault_response_is_valid_json() {
        use crate::sqlite_store::SqliteOperationStore;
        let path =
            std::env::temp_dir().join(format!("routeloom-api1-fault-{}.db", std::process::id()));
        let _ = std::fs::remove_file(&path);
        let acl = send_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let fault_store = Mutex::new(SqliteOperationStore::open(&path).unwrap());
        let c = ctx(Some(501), &acl, &log, &fault_store, &limiter, 0);
        let opened = handle(
            b"{\"v\":1,\"request_id\":\"e\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000001\"}}",
            &c,
        );
        assert!(opened.contains("\"ok\":true"), "{opened}");
        fault_store.lock().unwrap().veto_next_commit();
        assert_error_schema(
            &handle(
                submit_line("55555555555555555555555555555555", "0000000000000001").as_bytes(),
                &c,
            ),
            "STORE_RECOVERY_REQUIRED",
        );
        drop(fault_store);
        let _ = std::fs::remove_file(&path);
        for suffix in ["-wal", "-shm", "-journal"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", path.display()));
        }
    }

    /// A replayed submit reports the record's committed state — the same
    /// document operations.get returns — never a fabricated HOST_QUEUED
    /// (the reviewer's reproduction: submit, cancel, resubmit lied).
    #[test]
    fn submit_replay_reports_committed_state() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let owner = ctx(Some(501), &acl, &log, &store, &limiter, 1000);
        let get =
            |id: &str| routeloom_json::parse(&handle(get_line(id).as_bytes(), &owner)).unwrap();
        let replay_result = |key: &str| {
            let response = handle(submit_line(key, &epoch).as_bytes(), &owner);
            let parsed = routeloom_json::parse(&response).unwrap();
            assert_eq!(
                parsed.get("ok").and_then(Json::as_bool),
                Some(true),
                "{response}"
            );
            parsed.get("result").unwrap().clone()
        };
        // The reviewer's reproduction: cancel, then resubmit the same
        // key+content → CANCELLED_BEFORE_DISPATCH, not HOST_QUEUED.
        let key = "00112233445566778899aabbccddeeff";
        let accepted = handle(submit_line(key, &epoch).as_bytes(), &owner);
        let id = result_field(&accepted, "operation_id");
        let cancelled = handle(cancel_line(&id).as_bytes(), &owner);
        assert!(cancelled.contains("\"ok\":true"), "{cancelled}");
        let replay = replay_result(key);
        assert_eq!(
            replay.get("dispatch_state").and_then(Json::as_str),
            Some("CANCELLED_BEFORE_DISPATCH"),
        );
        assert_eq!(Some(&replay), get(&id).get("result"));
        // Other committed states replay honestly too — expired,
        // indeterminate, rejected — each equal to operations.get's report.
        for (key, state) in [
            (
                "11111111111111111111111111111111",
                DispatchState::ExpiredBeforeDispatch,
            ),
            (
                "22222222222222222222222222222222",
                DispatchState::Indeterminate,
            ),
            (
                "33333333333333333333333333333333",
                DispatchState::RejectedNotAccepted,
            ),
        ] {
            let accepted = handle(submit_line(key, &epoch).as_bytes(), &owner);
            let id = result_field(&accepted, "operation_id");
            let seq = u64::from_str_radix(id.rsplit(':').next().unwrap(), 16).unwrap();
            store
                .lock()
                .unwrap()
                .set_state_for_test(seq, state, Some(1000));
            let replay = replay_result(key);
            assert_eq!(
                replay.get("dispatch_state").and_then(Json::as_str),
                Some(state.name()),
            );
            assert_eq!(Some(&replay), get(&id).get("result"), "{key}");
        }
        // A delivered op replays its terminal state plus the learned
        // message_key and evidence.
        let key = "44444444444444444444444444444444";
        let accepted = handle(submit_line(key, &epoch).as_bytes(), &owner);
        let id = result_field(&accepted, "operation_id");
        let seq = u64::from_str_radix(id.rsplit(':').next().unwrap(), 16).unwrap();
        {
            let mut guard = store.lock().unwrap();
            guard.prepare_dispatch(seq, [9; 16], [8; 16]).unwrap();
            guard
                .update_operation(seq, &mut |op| {
                    let d = op.dispatch.as_mut().unwrap();
                    d.submitted = true;
                    d.ev_gateway_accepted = true;
                    d.ev_end_sdk = true;
                    d.msg_session = Some(0x0abc);
                    d.msg_seq = Some(77);
                    op.dispatch_state = DispatchState::EndSdkReceived;
                    op.terminal_ms = Some(1000);
                    true
                })
                .unwrap();
        }
        let replay = replay_result(key);
        assert_eq!(
            replay.get("dispatch_state").and_then(Json::as_str),
            Some("END_SDK_RECEIVED"),
        );
        let message_key = replay.get("message_key").unwrap();
        assert_eq!(
            message_key.get("session").and_then(Json::as_str),
            Some("00000abc")
        );
        assert_eq!(
            message_key.get("sequence").and_then(Json::as_str),
            Some("000000000000004d")
        );
        assert_eq!(Some(&replay), get(&id).get("result"));
        // A still-queued op still replays HOST_QUEUED.
        let key = "55555555555555555555555555555555";
        let accepted = handle(submit_line(key, &epoch).as_bytes(), &owner);
        let id = result_field(&accepted, "operation_id");
        let replay = replay_result(key);
        assert_eq!(
            replay.get("dispatch_state").and_then(Json::as_str),
            Some("HOST_QUEUED"),
        );
        assert_eq!(Some(&replay), get(&id).get("result"));
    }

    // ---- Gateway API (05-wire-api.md §5.7) ----

    /// An authenticated session on the attached gateway plus the
    /// dispatcher's published registration mirror — the state a live
    /// schema-2 binding needs.
    fn gw_fixture() -> (Mutex<SessionInfo>, crate::dispatch::GatewayLane) {
        let session = Mutex::new(SessionInfo {
            authenticated: true,
            id: Some(7),
            node: Some(0x0abc),
            boot: Some(7),
            network: Some(1),
            ..SessionInfo::default()
        });
        let lane = crate::dispatch::GatewayLane::default();
        lane.set(crate::dispatch::GatewayRegistration {
            token: [0xa1; 16],
            gateway_boot: 0x999,
            host_digest: [0x44; 32],
            egress: 0x0abc,
            usb_session: 7,
            lease_deadline_mono: u64::MAX,
        });
        (session, lane)
    }

    fn gw_submit_line(key: &str, epoch: &str, scope: &str) -> String {
        format!(
            "{{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"gateway\",\"id\":\"0000000000000020\",\"scope\":\"{scope}\"}},\"payload_hex\":\"00ff\",\"payload_len\":2,\"options\":{{\"storage\":\"RAM_ONLY\"}}}}}}"
        )
    }

    fn gw_resolve_line(scope: &str, expected_host: Option<&str>) -> String {
        let host =
            expected_host.map_or_else(String::new, |h| format!(",\"expected_host\":\"{h}\""));
        format!(
            "{{\"v\":1,\"request_id\":\"r\",\"method\":\"gateway.resolve\",\"params\":{{\"network\":\"0000000000000001\",\"gateway\":\"0000000000000abc\",\"scope\":\"{scope}\"{host}}}}}"
        )
    }

    fn gw_get_line(id: &str) -> String {
        format!(
            "{{\"v\":1,\"request_id\":\"g\",\"method\":\"gateway.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
        )
    }

    #[test]
    fn gateway_submit_without_registration_is_retryable_unavailable() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        // Session authenticated but NO registration mirror: the daemon
        // must refuse rather than mint a binding — GATEWAY_UNAVAILABLE,
        // retryable (a later resolve+submit may succeed).
        let session = Mutex::new(SessionInfo {
            authenticated: true,
            id: Some(7),
            node: Some(0x0abc),
            boot: Some(7),
            network: Some(1),
            ..SessionInfo::default()
        });
        let lane = crate::dispatch::GatewayLane::default();
        let c = ctx_lane(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            leaked_config_ops(),
            None,
            100,
        );
        let key = "66666666666666666666666666666666";
        let response = handle(
            gw_submit_line(key, &epoch, "HOST_RECEIVE_RAM").as_bytes(),
            &c,
        );
        let parsed = assert_error_schema(&response, "GATEWAY_UNAVAILABLE");
        assert_eq!(
            parsed
                .get("error")
                .unwrap()
                .get("retryable")
                .and_then(Json::as_bool),
            Some(true),
            "{response}"
        );
        // And the op never entered the store.
        assert!(store.lock().unwrap().dispatch_view().unwrap().is_empty());
    }

    #[test]
    fn gateway_submit_binds_schema2_and_get_reports_it() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let (session, lane) = gw_fixture();
        let c = ctx_lane(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            leaked_config_ops(),
            None,
            100,
        );
        let key = "77777777777777777777777777777777";
        let accepted = handle(
            gw_submit_line(key, &epoch, "HOST_RECEIVE_RAM").as_bytes(),
            &c,
        );
        assert!(accepted.contains("\"ok\":true"), "{accepted}");
        let id = result_field(&accepted, "operation_id");
        // The admitted record is a real schema-2 canonical bound to the
        // registration mirror — version 2, kind gateway, token/boot/egress
        // embedded in the hashed bytes.
        let seq = u64::from_str_radix(id.rsplit(':').next().unwrap(), 16).unwrap();
        let record = store
            .lock()
            .unwrap()
            .get_by_seq(seq)
            .unwrap()
            .expect("admitted above");
        assert_eq!(record.dest_kind, 1);
        assert_eq!(record.canonical[0], 2);
        assert_eq!(record.canonical.len(), 60 + 2);
        // gateway.get answers the same status document operations.get
        // reports — with the schema-2 destination rendered.
        let got = handle(gw_get_line(&id).as_bytes(), &c);
        assert!(got.contains("\"ok\":true"), "{got}");
        let parsed = routeloom_json::parse(&got).unwrap();
        let result = parsed.get("result").unwrap();
        assert_eq!(
            result.get("operation_id").and_then(Json::as_str),
            Some(id.as_str()),
            "{got}"
        );
        let destination = result.get("destination").unwrap();
        assert_eq!(
            destination.get("kind").and_then(Json::as_str),
            Some("gateway"),
            "{got}"
        );
        assert_eq!(
            destination.get("scope").and_then(Json::as_str),
            Some("HOST_RECEIVE_RAM"),
            "{got}"
        );
        // Replay of the same key answers the committed record, and
        // gateway.get stays the honest outcome query for it.
        let replay = handle(
            gw_submit_line(key, &epoch, "HOST_RECEIVE_RAM").as_bytes(),
            &c,
        );
        assert!(replay.contains("\"ok\":true"), "{replay}");
        assert_eq!(
            routeloom_json::parse(&replay)
                .unwrap()
                .get("result")
                .unwrap()
                .get("operation_id")
                .and_then(Json::as_str),
            Some(id.as_str()),
            "{replay}"
        );
    }

    #[test]
    fn gateway_get_hides_node_and_foreign_ops() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let (session, lane) = gw_fixture();
        let c = ctx_lane(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            leaked_config_ops(),
            None,
            100,
        );
        // A node-destination op is answered with the same NOT_FOUND an
        // unknown id gets — the method is not a destination-kind oracle.
        let key = "88888888888888888888888888888888";
        let accepted = handle(submit_line(key, &epoch).as_bytes(), &c);
        let id = result_field(&accepted, "operation_id");
        let response = handle(gw_get_line(&id).as_bytes(), &c);
        assert_error_schema(&response, "NOT_FOUND");
        let response = handle(
            gw_get_line("0000000000000000000000000000abcd:00000000000000ff").as_bytes(),
            &c,
        );
        assert_error_schema(&response, "NOT_FOUND");
        // A principal without READ_OPERATION on the op's network gets the
        // same NOT_FOUND (no existence oracle).
        let uid7 = ctx_lane(
            Some(7),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            leaked_config_ops(),
            None,
            100,
        );
        let response = handle(gw_get_line(&id).as_bytes(), &uid7);
        assert_error_schema(&response, "NOT_FOUND");
    }

    #[test]
    fn gateway_resolve_reports_the_live_binding() {
        let (acl, log, store, limiter) = test_env();
        let (session, lane) = gw_fixture();
        let c = ctx_lane(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            leaked_config_ops(),
            None,
            100,
        );
        let digest = "44".repeat(32);
        let response = handle(
            gw_resolve_line("HOST_RECEIVE_RAM", Some(&digest)).as_bytes(),
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").unwrap();
        assert_eq!(
            result.get("resolved").and_then(Json::as_bool),
            Some(true),
            "{response}"
        );
        assert_eq!(
            result.get("host_digest").and_then(Json::as_str),
            Some(digest.as_str()),
            "{response}"
        );
        assert_eq!(
            result.get("gateway_boot").and_then(Json::as_str),
            Some("0000000000000999"),
            "{response}"
        );
        assert_eq!(
            result.get("egress").and_then(Json::as_str),
            Some("0000000000000abc"),
            "{response}"
        );
        // The token itself is never disclosed through the API.
        assert!(!response.contains("a1a1a1a1"), "{response}");
        // Wrong expected_host → resolved:false with the reason.
        let wrong = handle(
            gw_resolve_line("HOST_RECEIVE_RAM", Some(&"55".repeat(32))).as_bytes(),
            &c,
        );
        let parsed = routeloom_json::parse(&wrong).unwrap();
        assert_eq!(
            parsed
                .get("result")
                .unwrap()
                .get("resolved")
                .and_then(Json::as_bool),
            Some(false),
            "{wrong}"
        );
        assert_eq!(
            parsed
                .get("result")
                .unwrap()
                .get("reason")
                .and_then(Json::as_str),
            Some("host_digest_mismatch"),
            "{wrong}"
        );
        // SDK scope is the gateway's own mailbox — not ours to describe.
        let sdk = handle(
            gw_resolve_line("GATEWAY_SDK_RAM", Some(&"00".repeat(32))).as_bytes(),
            &c,
        );
        assert!(
            routeloom_json::parse(&sdk)
                .unwrap()
                .get("result")
                .unwrap()
                .get("reason")
                .and_then(Json::as_str)
                == Some("scope_not_host_endpoint"),
            "{sdk}"
        );
        // A different attached node id is "not attached", never resolved.
        let other = handle(
            "{\"v\":1,\"request_id\":\"r\",\"method\":\"gateway.resolve\",\"params\":{\"network\":\"0000000000000001\",\"gateway\":\"0000000000000020\",\"scope\":\"HOST_RECEIVE_RAM\",\"expected_host\":\"4444444444444444444444444444444444444444444444444444444444444444\"}}".as_bytes(),
            &c,
        );
        assert!(
            routeloom_json::parse(&other)
                .unwrap()
                .get("result")
                .unwrap()
                .get("reason")
                .and_then(Json::as_str)
                == Some("gateway_not_attached"),
            "{other}"
        );
        // No registration → not_registered (still ok:true, resolved:false).
        let empty_lane = crate::dispatch::GatewayLane::default();
        let c2 = ctx_lane(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &empty_lane,
            leaked_config_ops(),
            None,
            100,
        );
        let response = handle(
            gw_resolve_line("HOST_RECEIVE_RAM", Some(&digest)).as_bytes(),
            &c2,
        );
        assert!(
            routeloom_json::parse(&response)
                .unwrap()
                .get("result")
                .unwrap()
                .get("reason")
                .and_then(Json::as_str)
                == Some("not_registered"),
            "{response}"
        );
        // Missing expected_host on HOST scope is an argument error, not
        // an unresolved answer.
        let response = handle(gw_resolve_line("HOST_RECEIVE_RAM", None).as_bytes(), &c);
        assert_error_schema(&response, "INVALID_ARGUMENT");
    }

    #[test]
    fn gateway_acl_is_enforced() {
        // READ_PAYLOAD only — no SEND, no READ_OPERATION.
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let (session, lane) = gw_fixture();
        let c = ctx_lane(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            leaked_config_ops(),
            None,
            100,
        );
        let digest = "44".repeat(32);
        let response = handle(
            gw_resolve_line("HOST_RECEIVE_RAM", Some(&digest)).as_bytes(),
            &c,
        );
        assert_error_schema(&response, "AuthorizationFailed");
        store.lock().unwrap().open_epoch((501, 1), 0).unwrap();
        let response = handle(
            gw_submit_line(
                "99999999999999999999999999999999",
                "0000000000000001",
                "HOST_RECEIVE_RAM",
            )
            .as_bytes(),
            &c,
        );
        assert_error_schema(&response, "AuthorizationFailed");
        // Unauthenticated socket peer is denied outright.
        let anon = ctx_lane(
            None,
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            leaked_config_ops(),
            None,
            100,
        );
        let response = handle(
            gw_resolve_line("HOST_RECEIVE_RAM", Some(&digest)).as_bytes(),
            &anon,
        );
        assert_error_schema(&response, "AuthorizationFailed");
    }

    // --- config.* verbs ------------------------------------------------------
    //
    // uid 9 is a config admin (CONFIG on every network, no SEND — the grants
    // are orthogonal); uid 501 is a plain sender (SEND+READ_OPERATION on net
    // 1, no CONFIG). The pair proves the admin ACL is distinct from
    // messages.send in both directions.

    fn config_acl() -> Acl {
        Acl::parse(
            "{\"principals\":{\"9\":{\"networks\":{\"*\":[\"CONFIG\"]}},\"501\":{\"networks\":{\"0000000000000001\":[\"SEND\",\"READ_OPERATION\"]}}}}",
        )
        .unwrap()
    }

    /// A config-facing fixture: a REAL ConfigOps hub (ops are queryable, not
    /// a leaked sink) plus an authenticated session. The gateway lane is
    /// unused by the config verbs.
    fn config_fixture() -> (
        Mutex<SessionInfo>,
        crate::dispatch::GatewayLane,
        crate::dispatch::ConfigOps,
    ) {
        let session = Mutex::new(SessionInfo {
            authenticated: true,
            id: Some(7),
            node: Some(0x0abc),
            boot: Some(7),
            network: Some(1),
            ..SessionInfo::default()
        });
        (
            session,
            crate::dispatch::GatewayLane::default(),
            crate::dispatch::ConfigOps::default(),
        )
    }

    fn cfg_req(method: &str, params: &str) -> String {
        format!("{{\"v\":1,\"request_id\":\"c\",\"method\":\"{method}\",\"params\":{{{params}}}}}")
    }

    const CFG_TARGET: &str = "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\"";
    const CFG_CHALLENGE_PARAMS: &str = "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":7,\"schema\":1";
    const CFG_STATUS_PARAMS: &str = "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":7,\"operation_id\":\"00112233445566778899aabbccddeeff\"";
    const CFG_PROPOSE_PARAMS: &str = "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":7,\"schema\":1,\"base_snapshot\":\"aabb\",\"patch\":[{\"field_id\":1,\"field_type\":\"u32\",\"value\":\"0000002a\"}]";

    #[test]
    fn config_challenge_submits_a_pending_op() {
        let acl = config_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let (session, lane, config_ops) = config_fixture();
        let c = ctx_lane(
            Some(9),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            Some(0xabc),
            100,
        );
        let response = handle(
            cfg_req("config.challenge", CFG_CHALLENGE_PARAMS).as_bytes(),
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(response.contains("\"state\":\"PENDING\""), "{response}");
        // Acceptance mints a cfg-namespaced op id — never a verdict.
        let token = result_field(&response, "config_op");
        assert!(token.starts_with("cfg"), "{token}");
        // The op is queryable via config.get and still honestly PENDING.
        let get = handle(
            cfg_req("config.get", &format!("\"config_op\":\"{token}\"")).as_bytes(),
            &c,
        );
        assert!(get.contains("\"ok\":true"), "{get}");
        assert!(get.contains("\"state\":\"PENDING\""), "{get}");
        assert!(get.contains("\"op\":\"challenge ns=7 schema=1\""), "{get}");
        assert!(get.contains("\"network\":\"0000000000000001\""), "{get}");
    }

    #[test]
    fn config_verbs_require_config_grant_not_send() {
        let acl = config_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let (session, lane, config_ops) = config_fixture();
        // uid 501: SEND+READ_OPERATION on net 1 but no CONFIG. Valid params for
        // every verb so the failure is purely the missing admin grant.
        let c = ctx_lane(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            Some(0xabc),
            100,
        );
        for (method, params) in [
            ("config.challenge", CFG_CHALLENGE_PARAMS),
            ("config.status", CFG_STATUS_PARAMS),
            ("config.propose", CFG_PROPOSE_PARAMS),
        ] {
            let response = handle(cfg_req(method, params).as_bytes(), &c);
            assert_error_schema(&response, "AuthorizationFailed");
        }
        // Anonymous socket peer is denied outright.
        let anon = ctx_lane(
            None,
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            Some(0xabc),
            100,
        );
        let response = handle(
            cfg_req("config.challenge", CFG_CHALLENGE_PARAMS).as_bytes(),
            &anon,
        );
        assert_error_schema(&response, "AuthorizationFailed");
    }

    #[test]
    fn config_propose_without_authority_is_an_honest_refusal() {
        let acl = config_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let (session, lane, config_ops) = config_fixture();
        // CONFIG grant present but NO --config-authority: the daemon cannot
        // sign a permit, so it refuses rather than queue a doomed request.
        let c = ctx_lane(
            Some(9),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            None,
            100,
        );
        let response = handle(cfg_req("config.propose", CFG_PROPOSE_PARAMS).as_bytes(), &c);
        assert_error_schema(&response, "CONFIG_NO_AUTHORITY");
        // The read-only verbs still work without an authority — they never
        // sign anything.
        let response = handle(
            cfg_req("config.challenge", CFG_CHALLENGE_PARAMS).as_bytes(),
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
    }

    #[test]
    fn config_propose_submits_a_pending_op() {
        let acl = config_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let (session, lane, config_ops) = config_fixture();
        let c = ctx_lane(
            Some(9),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            Some(0xabc),
            100,
        );
        let response = handle(cfg_req("config.propose", CFG_PROPOSE_PARAMS).as_bytes(), &c);
        assert!(response.contains("\"ok\":true"), "{response}");
        // Acceptance is PENDING — never ACTIVE or APPLIED.
        assert!(response.contains("\"state\":\"PENDING\""), "{response}");
        assert!(!response.contains("ACTIVE"), "{response}");
    }

    #[test]
    fn config_params_are_validated() {
        let acl = config_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let (session, lane, config_ops) = config_fixture();
        let c = ctx_lane(
            Some(9),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            Some(0xabc),
            100,
        );
        // Unknown param key.
        let bad = format!("{CFG_CHALLENGE_PARAMS},\"bogus\":1");
        assert_error_schema(
            &handle(cfg_req("config.challenge", &bad).as_bytes(), &c),
            "INVALID_ARGUMENT",
        );
        // Missing required field (network).
        assert_error_schema(
            &handle(
                cfg_req(
                    "config.challenge",
                    "\"target\":\"0000000000000009\",\"config_namespace\":7,\"schema\":1",
                )
                .as_bytes(),
                &c,
            ),
            "INVALID_ARGUMENT",
        );
        // Bad target hex.
        let bad = "\"network\":\"0000000000000001\",\"target\":\"zz\",\"config_namespace\":7,\"schema\":1";
        assert_error_schema(
            &handle(cfg_req("config.challenge", bad).as_bytes(), &c),
            "INVALID_ARGUMENT",
        );
        // status: operation_id must be a 32-hex string.
        assert_error_schema(
            &handle(
                cfg_req(
                    "config.status",
                    "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":7,\"operation_id\":\"short\"",
                )
                .as_bytes(),
                &c,
            ),
            "INVALID_ARGUMENT",
        );
        // propose: empty patch, bad field_type, and duplicate field_id.
        for patch in [
            "\"patch\":[]",
            "\"patch\":[{\"field_id\":1,\"field_type\":\"bogus\",\"value\":\"00\"}]",
            "\"patch\":[{\"field_id\":1,\"field_type\":\"u8\",\"value\":\"00\"},{\"field_id\":1,\"field_type\":\"u8\",\"value\":\"01\"}]",
        ] {
            let params = format!(
                "{CFG_TARGET},\"config_namespace\":7,\"schema\":1,\"base_snapshot\":\"aabb\",{patch}"
            );
            assert_error_schema(
                &handle(cfg_req("config.propose", &params).as_bytes(), &c),
                "INVALID_ARGUMENT",
            );
        }
    }

    #[test]
    fn config_get_has_no_existence_oracle() {
        let acl = config_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let (session, lane, config_ops) = config_fixture();
        // uid 9 (config admin) submits a challenge on net 1.
        let c9 = ctx_lane(
            Some(9),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            Some(0xabc),
            100,
        );
        let response = handle(
            cfg_req("config.challenge", CFG_CHALLENGE_PARAMS).as_bytes(),
            &c9,
        );
        let token = result_field(&response, "config_op");
        // A principal without CONFIG on that network gets NOT_FOUND — the same
        // shape as an unknown id, so config ops are no existence oracle.
        let c501 = ctx_lane(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            Some(0xabc),
            100,
        );
        let get = cfg_req("config.get", &format!("\"config_op\":\"{token}\""));
        assert_error_schema(&handle(get.as_bytes(), &c501), "NOT_FOUND");
        // A malformed token is INVALID_ARGUMENT; a well-formed unknown op is
        // NOT_FOUND (identical to the forbidden case).
        assert_error_schema(
            &handle(
                cfg_req("config.get", "\"config_op\":\"bogus\"").as_bytes(),
                &c9,
            ),
            "INVALID_ARGUMENT",
        );
        assert_error_schema(
            &handle(
                cfg_req("config.get", "\"config_op\":\"cfg0000000000000fff\"").as_bytes(),
                &c9,
            ),
            "NOT_FOUND",
        );
    }

    #[test]
    fn config_outcome_json_reports_honest_states() {
        // Direct serialization coverage for the distinct terminal states —
        // the lane's verdict is surfaced verbatim; PERMIT_ASSEMBLED is never
        // claimed ACTIVE, and INDETERMINATE/TIMEOUT stay distinct.
        let base = ConfigOpRecord {
            op_id: 7,
            summary: "propose ns=7".to_string(),
            network: 1,
            target: 9,
            outcome: None,
            submitted_ms: 100,
            resolved_ms: None,
        };
        let pending = config_outcome_json(&base);
        assert!(pending.contains("\"state\":\"PENDING\""), "{pending}");
        for (outcome, want) in [
            (ConfigOutcome::PermitAssembled, "PERMIT_ASSEMBLED"),
            (ConfigOutcome::NoChange, "NO_CHANGE"),
            (ConfigOutcome::Timeout, "TIMEOUT"),
            (ConfigOutcome::Indeterminate, "INDETERMINATE"),
            (ConfigOutcome::ProtocolError, "PROTOCOL_ERROR"),
        ] {
            let json = config_outcome_json(&ConfigOpRecord {
                outcome: Some(outcome),
                resolved_ms: Some(150),
                ..base.clone()
            });
            assert!(json.contains(&format!("\"state\":\"{want}\"")), "{json}");
            assert!(!json.contains("ACTIVE"), "{json}");
        }
        let refused = config_outcome_json(&ConfigOpRecord {
            outcome: Some(ConfigOutcome::Refused(ConfigOpsResult::Denied)),
            resolved_ms: Some(150),
            ..base.clone()
        });
        assert!(refused.contains("\"state\":\"REFUSED\""), "{refused}");
        assert!(refused.contains("\"result\":\"DENIED\""), "{refused}");
    }
}
