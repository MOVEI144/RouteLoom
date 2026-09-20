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
//! (1–64 ASCII chars), `method`, optional `params` object — any other field
//! is rejected, never ignored.
//!
//! Methods in this phase: `capabilities.get` (unauthenticated) and
//! `messages.read` (requires the principal's READ_PAYLOAD grant on the
//! network — the principal comes from the socket peer's OS credential, never
//! from request JSON). The other methods named in 01-contracts.md are later
//! phases and answer UNSUPPORTED_METHOD rather than silently degrading.

use crate::acl::{self, Acl};
use crate::receive_log::{
    Cursor, IngestOutcome, ReadOutcome, ReceiveLog, CURSOR_MAX_DECODED_BYTES, PAGE_LIMIT,
};
use routeloom_json::{escape_string, Json};
use std::sync::Mutex;

// contracts.json `ipc.*`
pub const REQUEST_MAX_BYTES: usize = 8192;
pub const RESPONSE_MAX_BYTES: usize = 65536;
pub const JSON_MAX_DEPTH: usize = 8;
pub const REQUEST_ID_MAX: usize = 64;

/// Per-request inputs the dispatch layer needs. `uid` is the socket peer's
/// OS credential (None when the platform cannot supply one — default deny).
pub struct ApiContext<'a> {
    pub uid: Option<u32>,
    pub acl: &'a Acl,
    pub receive_log: &'a Mutex<ReceiveLog>,
    pub now_ms: u64,
}

struct ApiError {
    code: &'static str,
    /// JSON object body for `error.detail` (without the braces content is
    /// appended after the mandatory "message" member).
    extra_fields: String,
    retryable: bool,
}

impl ApiError {
    fn simple(code: &'static str, message: &str) -> Self {
        Self {
            code,
            extra_fields: format!(",\"message\":\"{}\"", escape_string(message)),
            retryable: false,
        }
    }
}

/// Methods named by 01-contracts.md but implemented in later phases — they
/// must not fall through to UNKNOWN_METHOD and pretend they don't exist.
const LATER_PHASE_METHODS: &[&str] = &[
    "operations.open_epoch",
    "messages.submit",
    "operations.get",
    "operations.get_by_key",
    "operations.cancel",
];

/// Handle one API1 request body (the bytes after `API1 `, newline stripped).
/// Always returns a complete JSON response document (no trailing newline).
pub fn handle(body: &[u8], ctx: &ApiContext<'_>) -> String {
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
        "capabilities.get" => capabilities(ctx).map(|r| (request_id, r)),
        "messages.read" => messages_read(&params, ctx).map(|r| (request_id, r)),
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
    if id.is_empty() || id.len() > REQUEST_ID_MAX || !id.is_ascii() {
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
    let response = format!(
        "{{\"v\":1,\"request_id\":{id},\"ok\":false,\"error\":{{\"code\":\"{}\",\"detail\":{{{}}},\"retryable\":{}}}}}",
        error.code,
        error.extra_fields,
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

/// Honest capability advertisement: only what this phase implements.
/// `rx_events_v1`/`ingress_loss_observable` are false on the old firmware —
/// gateway-side drops before DataFromMesh cannot be proven or counted here.
fn capabilities(ctx: &ApiContext<'_>) -> Result<String, ApiError> {
    let epoch_known = ctx.uid.is_some();
    Ok(format!(
        "{{\"api\":{{\"version\":1,\"request_max_bytes\":{REQUEST_MAX_BYTES},\"response_max_bytes\":{RESPONSE_MAX_BYTES},\"max_depth\":{JSON_MAX_DEPTH}}},\"methods\":{{\"capabilities.get\":true,\"messages.read\":true,\"messages.submit\":false,\"operations.open_epoch\":false,\"operations.get\":false,\"operations.get_by_key\":false,\"operations.cancel\":false}},\"receive\":{{\"mode\":\"cursor_poll\",\"retention_seconds\":{},\"entries_per_network\":{},\"bytes_per_network\":{},\"record_charge_bytes\":{},\"max_networks\":{},\"global_log_bytes\":{},\"page_limit\":{PAGE_LIMIT},\"durable_receive\":false,\"pc_service_destination\":false}},\"rx_events_v1\":false,\"ingress_loss_observable\":false,\"acl_revision\":{},\"peer_credential_resolved\":{epoch_known}}}",
        crate::receive_log::RETENTION_SECONDS,
        crate::receive_log::ENTRIES_PER_NETWORK,
        crate::receive_log::BYTES_PER_NETWORK,
        crate::receive_log::RECORD_CHARGE_BYTES,
        crate::receive_log::MAX_NETWORKS,
        crate::receive_log::GLOBAL_LOG_BYTES,
        ctx.acl.revision(),
    ))
}

/// `messages.read` params: `{network, from:"earliest"|"latest" XOR cursor,
/// limit}`. Result per 02-receive-api.md §2.
fn messages_read(params: &Json, ctx: &ApiContext<'_>) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "network" | "from" | "cursor" | "limit") {
            return Err(ApiError::simple(
                "INVALID_PARAMS",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(network_text) = params.get("network").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_PARAMS",
            "network must be a 16-hex string",
        ));
    };
    let network =
        acl::parse_network_hex(network_text).map_err(|e| ApiError::simple("INVALID_PARAMS", &e))?;
    let from = params.get("from").and_then(Json::as_str);
    let cursor_token = params.get("cursor").and_then(Json::as_str);
    if params.get("from").is_some() && from.is_none()
        || params.get("cursor").is_some() && cursor_token.is_none()
    {
        return Err(ApiError::simple(
            "INVALID_PARAMS",
            "from/cursor must be strings",
        ));
    }
    if from.is_some() == cursor_token.is_some() {
        return Err(ApiError::simple(
            "INVALID_PARAMS",
            "exactly one of from or cursor is required",
        ));
    }
    if let Some(from) = from {
        if from != "earliest" && from != "latest" {
            return Err(ApiError::simple(
                "INVALID_PARAMS",
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
                    "INVALID_PARAMS",
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
            extra_fields: format!(
                ",\"message\":\"cursor belongs to a previous daemon epoch\",\"loss_count\":null,\"oldest_cursor\":\"{}\",\"tail_cursor\":\"{}\"",
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
            extra_fields: format!(
                ",\"message\":\"receive-log records were reclaimed ahead of this cursor\",\"lost_from\":{lost_from},\"lost_to\":{lost_to},\"oldest_cursor\":\"{}\",\"tail_cursor\":\"{}\"",
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
    use std::sync::Mutex;

    fn acl_with(uid: u32) -> Acl {
        Acl::parse(&format!(
            "{{\"principals\":{{\"{uid}\":{{\"networks\":{{\"*\":[\"READ_PAYLOAD\"]}}}}}}}}"
        ))
        .unwrap()
    }

    fn ctx<'a>(
        uid: Option<u32>,
        acl: &'a Acl,
        log: &'a Mutex<ReceiveLog>,
        now: u64,
    ) -> ApiContext<'a> {
        ApiContext {
            uid,
            acl,
            receive_log: log,
            now_ms: now,
        }
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
        let c = ctx(Some(501), &acl, &log, 0);
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
        let c = ctx(None, &acl, &log, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"c1\",\"method\":\"capabilities.get\"}",
            &c,
        );
        assert!(response.contains("\"ok\":true"));
        assert!(response.contains("\"messages.read\":true"));
        assert!(response.contains("\"messages.submit\":false"));
        assert!(response.contains("\"rx_events_v1\":false"));
        assert!(response.contains("\"ingress_loss_observable\":false"));
        assert!(response.contains("\"durable_receive\":false"));
        assert!(response.contains("\"pc_service_destination\":false"));
    }

    #[test]
    fn unsupported_and_unknown_methods() {
        let acl = Acl::empty();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let c = ctx(None, &acl, &log, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"u\",\"method\":\"messages.submit\",\"params\":{}}",
            &c,
        );
        assert!(response.contains("UNSUPPORTED_METHOD"));
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
        ingest(&log, 1, 1, b"hello", 100);
        // Authorized uid reads the payload.
        let c = ctx(Some(501), &acl, &log, 200);
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
            let c = ctx(uid, &acl, &log, 200);
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
        let c = ctx(Some(501), &acl, &log, 0);
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
        for i in 0..5_u64 {
            ingest(&log, 1, i, format!("m{i}").as_bytes(), 100);
        }
        let c = ctx(Some(501), &acl, &log, 200);
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
        let c = ctx(Some(501), &acl, &log, 0);
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
            assert!(response.contains("INVALID_PARAMS"), "{params} → {response}");
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
        // Fill past the per-network cap so the front is reclaimed.
        for i in 0..(crate::receive_log::ENTRIES_PER_NETWORK + 2) as u64 {
            ingest(&log, 1, i, b"p", 100);
        }
        let c = ctx(Some(501), &acl, &log, 200);
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
}
