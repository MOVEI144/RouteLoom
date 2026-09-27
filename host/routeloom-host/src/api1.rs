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
//! `messages.read` (READ_PAYLOAD — now with optional `wait_ms`
//! long-polling), the push receive surface `messages.subscribe` /
//! `messages.unsubscribe` / `messages.subscriptions` (issue #7;
//! `messages` stream needs READ_PAYLOAD, or READ_OPERATION for
//! metadata-only; the `events` stream is unauthenticated like EVENTS),
//! `operations.open_epoch` + `messages.submit` (SEND),
//! `operations.get`/`operations.get_by_key` (READ_OPERATION) and
//! `operations.cancel` (owning principal with SEND). The principal always
//! comes from the socket peer's OS credential, never from request JSON.
//!
//! A successful `messages.subscribe` also returns a [`ConnEffect`] — the
//! socket layer applies it only after the ok line is flushed, which is
//! how the daemon guarantees no notification can ever precede the
//! response that created the subscription.

use crate::acl::{self, Acl};
use crate::canonical;
use crate::config::{ConfigOutcome, ConfigRequest};
use crate::receive_log::{
    hex_lower, Cursor, IngestOutcome, ReadOutcome, ReceiveLog, RxRecord, CURSOR_MAX_DECODED_BYTES,
    PAGE_LIMIT,
};
use crate::send_store::{
    self, AdmissionLimiter, CancelOutcome, CapacityStatus, DispatchState, OpIdentity,
    OpenEpochError, OperationStore, RateDeny, StoredOperation, SubmitOutcome,
};
use crate::subscribe::{
    self, CapacityDeny, EvFilter, MsgFilter, SubKind, SubscriptionHub, HEARTBEAT_MS_DEFAULT,
    HEARTBEAT_MS_MAX, HEARTBEAT_MS_MIN, NOTIFY_LINE_MAX, SUBS_PER_CONNECTION, SUBS_PER_PRINCIPAL,
    SUBS_TOTAL, SUB_QUEUE_BYTES, SUB_QUEUE_EVENTS, WAIT_MS_MAX,
};
use routeloom_json::{escape_string, Json};
use routeloom_protocol::host_ops::ConfigOpsResult;
use routeloom_wire::endpoint::{
    config_namespace_valid, config_tlv_encode, ConfigField, ConfigFieldType, ConfigPhase,
    ConfigReason,
};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::dispatch::ConfigOpRecord;

/// Site Authority methods (SDK v1 zero-touch join, plan P3-3).
pub(crate) mod site;

use crate::SessionInfo;

// contracts.json `ipc.*`: the bound names the WHOLE request line —
// `API1 ` (5B) + JSON body + newline (1B) — and the socket layer enforces
// it on the raw bytes before this module ever sees the body.
pub const REQUEST_MAX_BYTES: usize = 8192;
pub const RESPONSE_MAX_BYTES: usize = 65536;
pub const JSON_MAX_DEPTH: usize = 8;
pub const REQUEST_ID_MAX: usize = 64;
/// Capabilities document version: clients key their parsing off this and
/// ignore unknown fields/methods — never an exact document match.
/// Additive-only: a removal or rename bumps this and the spec
/// (docs/spec/host.md §3 records the policy).
pub const CAPS_VERSION: u32 = 1;
// Legacy assurance for records without per-delivery evidence: USB receive
// bodies on an unnegotiated session carry no profile or verdict.
const RX_ASSURANCE: &str = "\"assurance\":{\"profile\":\"UNKNOWN\",\"origin\":\"unverified\"}";

/// Renders a record's assurance: the gateway's evidence when the flagged
/// DataFromMesh tail carried it (profile names share the observation
/// registry — the same id space `health.get` reports), else the legacy
/// UNKNOWN/unverified shape above. `site_epoch` only exists on the
/// evidenced shape (additive — no caps bump).
fn assurance_json(record: &RxRecord) -> String {
    match &record.assurance {
        None => RX_ASSURANCE.to_string(),
        Some(assurance) => format!(
            "\"assurance\":{{\"profile\":\"{}\",\"origin\":\"{}\",\"site_epoch\":{}}}",
            routeloom_protocol::observation::profile_name(assurance.profile),
            if assurance.verified {
                "verified"
            } else {
                "unverified"
            },
            assurance.site_epoch,
        ),
    }
}

/// Per-request inputs the dispatch layer needs. `principal` is the socket peer's
/// OS credential (None when the platform cannot supply one — default deny).
/// The store is generic over `OperationStore` so CAP-I1 can swap the memory
/// table for SQLite without touching this dispatch layer. `rate_limiter`
/// is daemon-wide (04 §4: per-principal and global budgets), so limits
/// hold across connections. `session`/`gateway_lane` expose the live USB
/// session and the dispatcher's host-registration mirror — read-only here:
/// the schema-2 binding always comes from the daemon's own lane state,
/// never from request JSON.
/// Point-in-time USB link snapshot handed in per request: `configured`
/// says a --device path exists at all, `connected` that the adapter fd is
/// currently open. Combined with the session mirror (`attached` =
/// connected AND authenticated) so clients can distinguish disconnected /
/// reconnecting / attached without parsing the event ring.
#[derive(Clone, Default)]
pub struct LinkStatus {
    pub configured: bool,
    pub connected: bool,
    /// Last adapter/session error the supervisor recorded — the "why"
    /// behind a disconnected state.
    pub last_error: Option<String>,
}

pub struct ApiContext<'a, S: OperationStore> {
    pub principal: Option<routeloom_peercred::Principal>,
    pub acl: &'a Acl,
    pub receive_log: &'a Mutex<ReceiveLog>,
    pub operation_store: &'a Mutex<S>,
    pub rate_limiter: &'a Mutex<AdmissionLimiter>,
    pub session: &'a Mutex<SessionInfo>,
    pub gateway_lane: &'a crate::dispatch::GatewayLane,
    /// node_status_v1 table (read-only here): `nodes.list` / `nodes.get`
    /// answer from it; the node lane thread is its only writer.
    pub node_table: &'a Mutex<crate::nodes::NodeTable>,
    /// Config op registry (P5): `config.*` submits queue here and `config.get`
    /// reads outcomes. Separate operation space from messages.*/gateway.*.
    pub config_ops: &'a crate::dispatch::ConfigOps,
    /// group_delivery_v1 op table: `group.send` admits here, `group.get`
    /// reads; the group lane thread is the only driver.
    pub group_ops: &'a crate::group::GroupOps,
    /// The daemon-owned rollcall run (design-devflow §6.4, D09):
    /// `lab.rollcall.*` starts, steers and reads it; the rollcall lane
    /// thread drives its polls through `group_ops`.
    pub rollcall: &'a crate::rollcall::RollcallService,
    /// m1 diagnostics query table: `diagnostics.snapshot` submits and
    /// waits here; the telemetry lane thread drives the device exchange.
    pub telemetry_ops: &'a crate::telemetry::TelemetryOps,
    pub observation_ops: &'a crate::observation::ObservationOps,
    pub remote_observation_ops: &'a crate::remote_observation::RemoteObservationOps,
    /// SDK v1 Site Authority (`--site-authority`); None = not configured,
    /// the site methods then answer SITE_AUTHORITY_UNAVAILABLE.
    pub site: Option<&'a crate::site::SiteService>,
    /// The daemon's configured config issuer node id — None means no
    /// authority is provisioned, so `config.propose` is refused honestly
    /// while queries still run.
    pub config_authority: Option<u64>,
    /// The daemon's issuance profile (`ISSUE_PROFILE_DEV`/`ISSUE_PROFILE_COSE`)
    /// — mirrored by `config_lane_for` into the lane issuer. Reported by
    /// `capabilities.get` as the permit_profile the daemon signs under.
    pub config_profile: u8,
    /// USB link snapshot captured by the socket layer before dispatch —
    /// powers link.get.
    pub link: LinkStatus,
    /// Push-receive subscription registry (issue #7): subscribe/
    /// unsubscribe/subscriptions register and deregister here, and
    /// `messages.read` long-polls wait on its change condvar. RAM-only —
    /// subscriptions die with their connection.
    pub subscriptions: &'a SubscriptionHub,
    /// Connection id the socket layer minted — scopes subscription
    /// ownership (ids are never resolvable across connections).
    pub conn_id: u64,
    /// The daemon's diagnostic event ring — the `stream:"events"`
    /// subscribe source.
    pub event_ring: EventRing<'a>,
    pub now_ms: u64,
    /// Process-monotonic clock on the same axis as the registration
    /// mirror's `lease_deadline_mono` — wall `now_ms` cannot judge a
    /// mono-anchored deadline.
    pub now_mono: u64,
}

/// Borrowed views of the daemon's diagnostic event ring — the
/// `stream:"events"` subscribe source. `events` entries carry `seq`
/// (from `next_seq`), `kind` and the serialized JSON line.
#[derive(Clone, Copy)]
pub struct EventRing<'a> {
    pub events: &'a Mutex<VecDeque<crate::Event>>,
    pub next_seq: &'a AtomicU64,
    pub dropped: &'a AtomicU64,
}

/// Side effects the socket layer applies only AFTER the response line is
/// flushed — §5.8 rule 1: no notification may precede the ok that created
/// its subscription.
pub enum ConnEffect {
    /// Activate this pending subscription (spawn the connection pump if
    /// it is not running yet).
    Subscribed { id: u64 },
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
///
/// `handle` discards connection-level effects — it exists for direct
/// request/response tests. The socket layer uses [`handle_conn`], which
/// additionally returns the [`ConnEffect`] a successful
/// `messages.subscribe` carries (pending → activate after the response
/// flush).
#[cfg(test)]
pub fn handle<S: OperationStore>(body: &[u8], ctx: &ApiContext<'_, S>) -> String {
    handle_conn(body, ctx).0
}

/// Handle one API1 request body, returning `(response, effect)`.
/// The response must be flushed to the socket BEFORE the effect is
/// applied — that is what keeps notification lines ordered behind the ok
/// they belong to.
pub fn handle_conn<S: OperationStore>(
    body: &[u8],
    ctx: &ApiContext<'_, S>,
) -> (String, Option<ConnEffect>) {
    // The advertised bound covers the whole line: `API1 ` + body + '\n'.
    // The body alone therefore may not exceed REQUEST_MAX_BYTES - 6 —
    // an oversized line the socket layer would have refused must get the
    // same answer from a direct call, never a different one.
    if body.len() + 6 > REQUEST_MAX_BYTES {
        return (
            error_response(
                None,
                &ApiError::simple("INVALID_REQUEST", "request too large"),
            ),
            None,
        );
    }
    let text = match std::str::from_utf8(body) {
        Ok(text) => text,
        Err(_) => {
            return (
                error_response(
                    None,
                    &ApiError::simple("INVALID_REQUEST", "request is not valid UTF-8"),
                ),
                None,
            )
        }
    };
    let root = match routeloom_json::parse_bounded(text, JSON_MAX_DEPTH) {
        Ok(root) => root,
        Err(error) => {
            return (
                error_response(
                    None,
                    &ApiError::simple("INVALID_REQUEST", &format!("invalid JSON: {error}")),
                ),
                None,
            )
        }
    };
    let Json::Object(fields) = &root else {
        return (
            error_response(
                None,
                &ApiError::simple("INVALID_REQUEST", "request must be an object"),
            ),
            None,
        );
    };
    // Envelope schema: exactly the defined fields — unknown fields are a
    // schema violation, not something to skip.
    for (key, _) in fields {
        if !matches!(key.as_str(), "v" | "request_id" | "method" | "params") {
            return (
                error_response(
                    extract_request_id(&root).as_deref(),
                    &ApiError::simple("INVALID_REQUEST", &format!("unknown field \"{key}\"")),
                ),
                None,
            );
        }
    }
    let request_id = extract_request_id(&root);
    let Some(request_id) = request_id.as_deref() else {
        return (
            error_response(
                None,
                &ApiError::simple(
                    "INVALID_REQUEST",
                    "request_id must be a string of 1-64 ASCII chars",
                ),
            ),
            None,
        );
    };
    if root.get("v").and_then(Json::as_u64) != Some(1) {
        return (
            error_response(
                Some(request_id),
                &ApiError::simple("INVALID_REQUEST", "v must be 1"),
            ),
            None,
        );
    }
    let Some(method) = root.get("method").and_then(Json::as_str) else {
        return (
            error_response(
                Some(request_id),
                &ApiError::simple("INVALID_REQUEST", "method must be a string"),
            ),
            None,
        );
    };
    let params = match root.get("params") {
        None | Some(Json::Null) => Json::Object(Vec::new()),
        Some(value @ Json::Object(_)) => value.clone(),
        Some(_) => {
            return (
                error_response(
                    Some(request_id),
                    &ApiError::simple("INVALID_REQUEST", "params must be an object"),
                ),
                None,
            )
        }
    };
    let dispatch: Result<(String, Option<ConnEffect>), ApiError> = match method {
        "capabilities.get" => capabilities(&params, ctx).map(|r| (r, None)),
        "capacity.get" => capacity_get(&params, ctx).map(|r| (r, None)),
        "messages.read" => messages_read(&params, ctx).map(|r| (r, None)),
        "messages.subscribe" => messages_subscribe(&params, ctx).map(|(r, e)| (r, Some(e))),
        "messages.unsubscribe" => messages_unsubscribe(&params, ctx).map(|r| (r, None)),
        "messages.subscriptions" => messages_subscriptions(&params, ctx).map(|r| (r, None)),
        "operations.open_epoch" => operations_open_epoch(&params, ctx).map(|r| (r, None)),
        "messages.submit" => messages_submit(&params, ctx).map(|r| (r, None)),
        "operations.get" => operations_get(&params, ctx).map(|r| (r, None)),
        "operations.get_by_key" => operations_get_by_key(&params, ctx).map(|r| (r, None)),
        "operations.cancel" => operations_cancel(&params, ctx).map(|r| (r, None)),
        "gateway.resolve" => gateway_resolve(&params, ctx).map(|r| (r, None)),
        "gateway.get" => gateway_get(&params, ctx).map(|r| (r, None)),
        "link.get" => link_get(&params, ctx).map(|r| (r, None)),
        "nodes.list" => nodes_list(&params, ctx).map(|r| (r, None)),
        "nodes.get" => nodes_get(&params, ctx).map(|r| (r, None)),
        "diagnostics.snapshot" => diagnostics_snapshot(&params, ctx).map(|r| (r, None)),
        "health.get" => health_get(&params, ctx).map(|r| (r, None)),
        "topology.get" => topology_get(&params, ctx).map(|r| (r, None)),
        "config.challenge" => config_challenge(&params, ctx).map(|r| (r, None)),
        "config.status" => config_status(&params, ctx).map(|r| (r, None)),
        "config.retry" => config_retry(&params, ctx).map(|r| (r, None)),
        "config.propose" => config_propose(&params, ctx).map(|r| (r, None)),
        "config.recover" => config_recover(&params, ctx).map(|r| (r, None)),
        "config.recovery_info" => config_recovery_info(&params, ctx).map(|r| (r, None)),
        "trust.install" => trust_install(&params, ctx).map(|r| (r, None)),
        "trust.status" => trust_status(&params, ctx).map(|r| (r, None)),
        "config.get" => config_get(&params, ctx).map(|r| (r, None)),
        "group.send" => group_send(&params, ctx).map(|r| (r, None)),
        "group.get" => group_get(&params, ctx).map(|r| (r, None)),
        "lab.rollcall.start" => rollcall_start(&params, ctx).map(|r| (r, None)),
        "lab.rollcall.update" => rollcall_update(&params, ctx).map(|r| (r, None)),
        "lab.rollcall.stop" => rollcall_stop(&params, ctx).map(|r| (r, None)),
        "lab.rollcall.status" => rollcall_status(&params, ctx).map(|r| (r, None)),
        method if site::SITE_METHODS.contains(&method) => site::dispatch(method, &params, ctx)
            .unwrap_or_else(|| Err(ApiError::simple("INTERNAL", "site method table mismatch")))
            .map(|r| (r, None)),
        method if LATER_PHASE_METHODS.contains(&method) => Err(ApiError::simple(
            "UNSUPPORTED_METHOD",
            &format!("\"{method}\" is not implemented in this phase"),
        )),
        method => Err(ApiError::simple(
            "UNKNOWN_METHOD",
            &format!("unknown method \"{method}\""),
        )),
    };
    match dispatch {
        Ok((result, effect)) => (ok_response(request_id, &result), effect),
        Err(error) => (error_response(Some(request_id), &error), None),
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
    let epoch_known = ctx.principal.is_some();
    let durable = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned")
        .durable();
    Ok(format!(
        "{{\"api\":{{\"version\":1,\"request_max_bytes\":{REQUEST_MAX_BYTES},\"response_max_bytes\":{RESPONSE_MAX_BYTES},\"max_depth\":{JSON_MAX_DEPTH}}},\"methods\":{{\"capabilities.get\":true,\"capacity.get\":true,\"messages.read\":true,\"messages.subscribe\":true,\"messages.unsubscribe\":true,\"messages.subscriptions\":true,\"messages.submit\":true,\"operations.open_epoch\":true,\"operations.get\":true,\"operations.get_by_key\":true,\"operations.cancel\":true,\"gateway.resolve\":true,\"gateway.get\":true,\"link.get\":true,\"nodes.list\":true,\"nodes.get\":true,\"config.challenge\":true,\"config.status\":true,\"config.retry\":true,\"config.propose\":true,\"config.recover\":true,\"config.recovery_info\":true,\"trust.install\":true,\"trust.status\":true,\"config.get\":true,\"group.send\":true,\"group.get\":true,\"lab.rollcall.start\":true,\"lab.rollcall.update\":true,\"lab.rollcall.stop\":true,\"lab.rollcall.status\":true,\"diagnostics.snapshot\":true,\"health.get\":true,\"topology.get\":true{site_methods}}},\"receive\":{{\"mode\":\"cursor_poll\",\"push\":\"subscribe_v1\",\"streams\":[\"messages\",\"events\"],\"retention_seconds\":{},\"entries_per_network\":{},\"bytes_per_network\":{},\"record_charge_bytes\":{},\"max_networks\":{},\"global_log_bytes\":{},\"page_limit\":{PAGE_LIMIT},\"subscriptions_per_connection\":{SUBS_PER_CONNECTION},\"subscriptions_per_principal\":{SUBS_PER_PRINCIPAL},\"subscriptions_total\":{SUBS_TOTAL},\"subscription_queue_events\":{SUB_QUEUE_EVENTS},\"subscription_queue_bytes\":{SUB_QUEUE_BYTES},\"notify_line_max_bytes\":{NOTIFY_LINE_MAX},\"long_poll_ms_max\":{WAIT_MS_MAX},\"heartbeat_ms\":{{\"min\":{HEARTBEAT_MS_MIN},\"max\":{HEARTBEAT_MS_MAX},\"default\":{HEARTBEAT_MS_DEFAULT}}},\"durable_receive\":false,\"durable_subscription\":false,\"pc_service_destination\":false}},\"send\":{{\"storage_durable\":{durable},\"dispatch\":\"usb_host_ops_v1\",\"delivery\":[\"BEST_EFFORT\",\"RELIABLE\"],\"priority\":[\"NORMAL\"],\"deadline_policy\":\"WALL_ELAPSED_VALIDITY\",\"queue_mode\":[\"FIFO\",\"LATEST_PER_DESTINATION\"],\"ttl_ms\":{{\"min\":{},\"max\":{},\"default\":{}}},\"hop_limit\":{{\"min\":{},\"max\":{},\"default\":{}}},\"payload_max_bytes\":{}}},\"config\":{{\"dispatch\":\"usb_host_ops_v1\",\"permit_profile\":\"{config_profile}\",\"authority_configured\":{config_auth}}},\"nodes\":{{\"source\":\"usb_node_status_v1\",\"page_max\":{NODES_PAGE_MAX},\"events\":[\"node_joined\",\"node_left\",\"link_changed\"],\"clock\":\"host_unix_ms\"}},\"group\":{{\"dispatch\":\"usb_group_delivery_v1\",\"gateway_capable\":{group_capable},\"payload_max_bytes\":{},\"priority\":[\"BULK\",\"NORMAL\",\"MANAGEMENT\",\"URGENT\"],\"ttl_ms\":{{\"min\":{},\"max\":{},\"default\":{}}},\"hop_limit\":{{\"min\":{},\"max\":{},\"default\":{}}},\"records_max\":{},\"queue_max\":{},\"unsettled_max\":{},\"memberships_per_node\":{},\"membership_set\":false,\"events\":[\"group_settled\"],\"storage_durable\":false}},\"observation\":{observation_caps},\"site\":{site_caps},\"rollcall\":{{\"dispatch\":\"usb_group_delivery_v1\",\"min_interval_ms\":{rollcall_min},\"max_inflight\":1}},\"rx_events_v1\":false,\"ingress_loss_observable\":false,\"acl_revision\":{},\"peer_credential_resolved\":{epoch_known},\"caps_version\":{CAPS_VERSION}}}",
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
        crate::group::PAYLOAD_MAX,
        crate::group::TTL_MIN_MS,
        crate::group::TTL_MAX_MS,
        crate::group::TTL_DEFAULT_MS,
        crate::group::HOP_MIN,
        crate::group::HOP_MAX,
        crate::group::HOP_DEFAULT,
        crate::group::RECORD_CAP,
        crate::group::QUEUE_CAP,
        crate::group::LIVE_CAP,
        crate::group::MEMBERSHIPS_PER_NODE,
        ctx.acl.revision(),
        config_auth = ctx.config_authority.is_some(),
        config_profile = config_profile_name(ctx.config_profile),
        group_capable = group_capability_json(ctx),
        observation_caps = observation_capability_json(ctx),
        site_methods = site::SITE_METHODS
            .iter()
            .fold(String::new(), |mut out, m| {
                out.push_str(",\"");
                out.push_str(m);
                out.push_str("\":true");
                out
            }),
        site_caps = site::capability_json(ctx),
        rollcall_min = crate::rollcall::MIN_INTERVAL_MS,
    ))
}

/// `capacity.get` (design-devflow D10): the effective admission profile
/// and every store/lane budget a long-plan validator needs — always the
/// enforced values, never requested ones. `admission.client` carries the
/// bench-v1 caller discipline (inflight cap and the initial-run window);
/// null under the normal profile because the contract defines none.
fn capacity_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    if !params.object_entries().is_empty() {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "capacity.get takes no params",
        ));
    }
    let profile = ctx
        .rate_limiter
        .lock()
        .expect("rate limiter poisoned")
        .profile();
    let store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    let status = store.capacity_status(ctx.now_ms);
    let client = match profile {
        send_store::AdmissionProfile::Normal => "null".to_string(),
        send_store::AdmissionProfile::BenchV1 => format!(
            "{{\"inflight_max\":{},\"run_window_calls\":{},\"run_window_ms\":{}}}",
            send_store::BENCH_INFLIGHT_MAX,
            send_store::BENCH_RUN_WINDOW_CALLS,
            send_store::BENCH_RUN_WINDOW_MS,
        ),
    };
    let reclaimable = match status.reclaimable_at_ms {
        Some(at) => at.to_string(),
        None => "null".to_string(),
    };
    Ok(format!(
        "{{\"admission\":{{\"profile\":\"{profile}\",\"calls_per_minute\":{rate},\"burst\":{burst},\"charges\":[\"messages.submit\",\"operations.open_epoch\"],\"client\":{client}}},\"store\":{{\"durable\":{durable},\"records_max\":{records},\"bytes_max\":{bytes},\"record_charge_bytes\":{charge},\"retention_ms\":{retention},\"unretired_epochs_max\":{epochs},\"active_max\":{active},\"active_per_principal_max\":{per_principal},\"free_slots\":{free_slots},\"free_bytes\":{free_bytes},\"reclaimable_at_ms\":{reclaimable}}},\"payload\":{{\"node_max_bytes\":{node_max},\"gateway_max_bytes\":{gw_max},\"group_max_bytes\":{group_max}}},\"group\":{{\"records_max\":{group_records},\"queue_max\":{group_queue},\"live_max\":{group_live},\"tombstones_max\":{group_tombstones},\"inbox_max\":{group_inbox}}},\"queue_mode\":{{\"LATEST_PER_DESTINATION\":{{\"requires\":{{\"delivery\":\"BEST_EFFORT\",\"storage\":\"RAM_ONLY\"}},\"supersede\":\"newest committed record retires still-queued older records to the same destination\"}}}}}}",
        profile = profile.name(),
        rate = profile.rate_per_minute(),
        burst = profile.burst(),
        durable = store.durable(),
        records = send_store::RECORD_CAP,
        bytes = send_store::STORE_BYTES_CAP,
        charge = send_store::RECORD_RESERVATION_BYTES,
        retention = send_store::RETENTION_MS,
        epochs = send_store::MAX_UNRETIRED_EPOCHS,
        active = send_store::ACTIVE_CAP,
        per_principal = send_store::ACTIVE_PER_PRINCIPAL_CAP,
        free_slots = status.free_slots,
        free_bytes = status.free_bytes,
        node_max = crate::receive_log::NORMAL_PAYLOAD_MAX,
        gw_max = canonical::GATEWAY_PAYLOAD_MAX,
        group_max = crate::group::PAYLOAD_MAX,
        group_records = crate::group::RECORD_CAP,
        group_queue = crate::group::QUEUE_CAP,
        group_live = crate::group::LIVE_CAP,
        group_tombstones = crate::group::TOMBSTONE_CAP,
        group_inbox = crate::group::INBOX_CAP,
    ))
}

/// `messages.read` params: `{network, from:"earliest"|"latest" XOR cursor,
/// limit, wait_ms}`. Result per 02-receive-api.md §2; `wait_ms` adds the
/// additive long-poll mode from 05-receive-api.md §5.3.2 — park until at
/// least one retained record exists or the window expires, never holding
/// the receive-log lock across the sleep.
fn messages_read<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "network" | "from" | "cursor" | "limit" | "wait_ms"
        ) {
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
    let wait_ms = match params.get("wait_ms") {
        None => 0,
        Some(value) => match value.as_u64() {
            Some(n) if n <= WAIT_MS_MAX => n,
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    &format!("wait_ms must be an integer 0..={WAIT_MS_MAX}"),
                ))
            }
        },
    };

    // The token is a position, not a permission: re-check the OS principal's
    // ACL grant on every request, before any cursor is trusted.
    let authorized = ctx.principal.as_ref().is_some_and(|uid| {
        ctx.acl
            .permit_principal(uid, network, acl::PERM_READ_PAYLOAD)
    });
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

    // Resolve the read start once: `from` anchors at earliest/latest, the
    // cursor path runs the shared validation ladder (decode → scope →
    // epoch). Position errors are returned before any wait begins.
    let (after, check_position) = if let Some(from) = from {
        let after = if from == "latest" {
            log.bounds(network, ctx.now_ms).1
        } else {
            0
        };
        (after, false)
    } else {
        let cursor = checked_cursor(
            &mut log,
            cursor_token.expect("cursor checked above"),
            network,
            acl_view,
            ctx.now_ms,
        )?;
        (cursor.last_scanned, true)
    };

    // Long-poll: re-check under the lock each pass, sleep on the
    // subscription hub's change condvar (ingest notifies) in between —
    // the log lock is dropped for the entire sleep so producers and other
    // readers are never blocked by a parked waiter.
    let deadline = (wait_ms > 0).then(|| Instant::now() + Duration::from_millis(wait_ms));
    loop {
        let outcome = log.read(network, after, limit, ctx.now_ms, check_position);
        match outcome {
            ReadOutcome::Gap {
                lost_from,
                lost_to,
                oldest_seq,
                tail_seq,
            } => {
                return Err(cursor_gap(
                    lost_from, lost_to, oldest_seq, tail_seq, &cursor_at,
                ))
            }
            ReadOutcome::Future => {
                return Err(ApiError::simple(
                    "INVALID_CURSOR",
                    "cursor points beyond the current tail",
                ))
            }
            ReadOutcome::Batch(batch) => {
                if let (true, Some(dl)) = (batch.records.is_empty(), deadline) {
                    let remaining = dl.checked_duration_since(Instant::now());
                    if let Some(remaining) = remaining.filter(|r| !r.is_zero()) {
                        // Snapshot the dirty epoch BEFORE releasing the
                        // lock so a notify landing between the read and
                        // the wait is observed, never slept through.
                        let seen = ctx.subscriptions.dirty_epoch();
                        drop(log);
                        ctx.subscriptions.wait(seen, remaining);
                        log = ctx.receive_log.lock().expect("receive log poisoned");
                        continue;
                    }
                    // Window expired: the last (still empty) batch is the
                    // honest answer, flagged wait_expired.
                    return Ok(read_result(
                        ReadOutcome::Batch(batch),
                        &cursor_at,
                        Some(true),
                    ));
                }
                return Ok(read_result(
                    ReadOutcome::Batch(batch),
                    &cursor_at,
                    deadline.map(|_| false),
                ));
            }
        }
    }
}

/// Shared cursor-validation ladder for `messages.read` and
/// `messages.subscribe` (§5.4.2): decode → network scope → ACL-view scope
/// → epoch. The epoch failure mints fresh oldest/tail cursors under the
/// live epoch so the client can resume explicitly.
fn checked_cursor(
    log: &mut ReceiveLog,
    token: &str,
    network: u64,
    acl_view: u64,
    now_ms: u64,
) -> Result<Cursor, ApiError> {
    let epoch = log.epoch();
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
        let (oldest, tail, ..) = log.bounds(network, now_ms);
        let cursor_at = |last_scanned: u64| {
            Cursor {
                network,
                acl_view,
                epoch,
                last_scanned,
            }
            .encode()
        };
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
    Ok(cursor)
}

/// The CURSOR_GAP error — same shape for `messages.read` and a failed
/// `messages.subscribe` (`on_gap:"fail"`).
fn cursor_gap(
    lost_from: u64,
    lost_to: u64,
    oldest_seq: u64,
    tail_seq: u64,
    cursor_at: &dyn Fn(u64) -> String,
) -> ApiError {
    ApiError {
        code: "CURSOR_GAP",
        message: "receive-log records were reclaimed ahead of this cursor".to_string(),
        extra_fields: format!(
            "\"lost_from\":{lost_from},\"lost_to\":{lost_to},\"oldest_cursor\":\"{}\",\"tail_cursor\":\"{}\"",
            cursor_at(oldest_seq.saturating_sub(1)),
            cursor_at(tail_seq),
        ),
        retryable: false,
    }
}

/// Serialize a read batch. `cursor_at` mints cursors under the current
/// epoch/acl_view/network. `wait_expired` is `Some(_)` only when the
/// request carried `wait_ms` — true on timeout, false when data arrived.
fn read_result(
    outcome: ReadOutcome,
    cursor_at: &dyn Fn(u64) -> String,
    wait_expired: Option<bool>,
) -> String {
    let ReadOutcome::Batch(batch) = outcome else {
        unreachable!("gap/future handled by caller")
    };
    let mut records_json = String::from("[");
    for (index, record) in batch.records.iter().enumerate() {
        if index > 0 {
            records_json.push(',');
        }
        records_json.push_str(&record_json(record, &cursor_at(record.seq)));
    }
    records_json.push(']');
    // Position after the last returned record; an empty batch resumes at
    // the caller's own position (earliest→before-oldest, latest→tail, and a
    // caught-up cursor stays put rather than rewinding to oldest-1).
    let next_cursor = match batch.records.last() {
        Some(record) => cursor_at(record.seq),
        None => cursor_at(batch.after_seq),
    };
    let wait_field = wait_expired.map_or_else(String::new, |expired| {
        format!(",\"wait_expired\":{expired}")
    });
    format!(
        "{{\"records\":{records_json},\"next_cursor\":\"{next_cursor}\",\"oldest_cursor\":\"{}\",\"tail_cursor\":\"{}\",\"more\":{},\"retention\":{{\"seconds\":{},\"entries\":{},\"bytes\":{}}}{wait_field}}}",
        cursor_at(batch.oldest_seq.saturating_sub(1)),
        cursor_at(batch.tail_seq),
        batch.more,
        crate::receive_log::RETENTION_SECONDS,
        batch.entries,
        batch.bytes,
    )
}

/// One received record with its payload — the shared shape of
/// `messages.read` batches and `kind:"message"` subscription
/// notifications. `cursor` is the per-record cursor (seq position).
pub(crate) fn record_json(record: &RxRecord, cursor: &str) -> String {
    format!(
        "{{\"v\":1,\"network\":\"{:016x}\",\"gateway\":{},\"origin\":\"{:016x}\",\"message\":{{\"session\":\"{:08x}\",\"sequence\":\"{:016x}\"}},\"payload_hex\":\"{}\",\"payload_len\":{},\"cursor\":\"{}\",\"endpoint_kind\":\"gateway_mirror\",\"evidence\":\"HOST_RAM_RETAINED\",{}}}",
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
        cursor,
        assurance_json(record),
    )
}

/// The metadata-only sibling used by `payloads:false` subscriptions
/// (READ_OPERATION): every field except the payload, replaced by its
/// sha256 so a metadata client can still deduplicate/audit.
pub(crate) fn record_meta_json(record: &RxRecord, cursor: &str) -> String {
    format!(
        "{{\"v\":1,\"network\":\"{:016x}\",\"gateway\":{},\"origin\":\"{:016x}\",\"message\":{{\"session\":\"{:08x}\",\"sequence\":\"{:016x}\"}},\"payload_len\":{},\"payload_sha256\":\"{}\",\"cursor\":\"{}\",\"endpoint_kind\":\"gateway_mirror\",\"evidence\":\"HOST_RAM_RETAINED\",{}}}",
        record.network,
        record.gateway.map_or_else(
            || "null".to_string(),
            |g| format!("\"{g:016x}\""),
        ),
        record.origin,
        record.msg_session,
        record.msg_seq,
        record.payload.len(),
        hex_lower(&canonical::sha256(&record.payload)),
        cursor,
        assurance_json(record),
    )
}

/// Capacity refusal for `messages.subscribe` (§5.3.5): retryable, and
/// names which of the three bounds ran dry — the caller's connection, its
/// principal across connections, or the daemon-wide total.
fn subscribe_capacity(deny: CapacityDeny) -> ApiError {
    let scope = match deny {
        CapacityDeny::Connection => "connection",
        CapacityDeny::Principal => "principal",
        CapacityDeny::Global => "global",
    };
    ApiError {
        code: "NO_CAPACITY",
        message: "subscription capacity exhausted".to_string(),
        extra_fields: format!("\"scope\":\"{scope}\""),
        retryable: true,
    }
}

/// Parse a `filter.origins`/`filter.gateways` member: an array of ≤8
/// 16-hex node ids. The values are positions, not validated principals —
/// any well-formed id is a legal filter term even if it never matches.
fn parse_id_list(params: &Json, key: &str) -> Result<Option<Vec<u64>>, ApiError> {
    let Some(value) = params.get(key) else {
        return Ok(None);
    };
    let Some(items) = value.as_array() else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            &format!("filter.{key} must be an array"),
        ));
    };
    if items.len() > subscribe::FILTER_MAX {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            &format!(
                "filter.{key} accepts at most {} entries",
                subscribe::FILTER_MAX
            ),
        ));
    }
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let Some(text) = item.as_str() else {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("filter.{key} entries must be 16-hex strings"),
            ));
        };
        let lowered = text.to_ascii_lowercase();
        if lowered.len() != 16 || !lowered.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("filter.{key} entries must be 16-hex strings"),
            ));
        }
        ids.push(u64::from_str_radix(&lowered, 16).expect("validated hex"));
    }
    Ok(Some(ids))
}

/// `messages.subscribe` params (05-receive-api.md §5.3.1):
/// `{stream?, network?, from|cursor?, on_gap?, payloads?, filter?,
/// heartbeat_ms?, durable?}`.
///
/// Registers a PENDING subscription in the hub and returns the ok result
/// plus `ConnEffect::Subscribed` — the socket layer flips it live only
/// after this response is on the wire, so a notification can never beat
/// the response that created it. Position is resolved under the
/// receive-log lock (the `from:"latest"` tail snapshot) but the hub
/// registration follows after the lock is released — an ingest landing
/// in between is still delivered, just flagged as post-snapshot.
fn messages_subscribe<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<(String, ConnEffect), ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "stream"
                | "network"
                | "from"
                | "cursor"
                | "on_gap"
                | "payloads"
                | "filter"
                | "heartbeat_ms"
                | "durable"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let stream = match params.get("stream") {
        None => "messages",
        Some(value) => match value.as_str() {
            Some(text) => text,
            None => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "stream must be a string",
                ))
            }
        },
    };
    let events = match stream {
        "messages" => false,
        "events" => true,
        _ => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "stream must be \"messages\" or \"events\"",
            ))
        }
    };
    // durable is refused as a capability, never silently downgraded —
    // capabilities advertises durable_subscription:false (§5.4.4).
    match params.get("durable") {
        None => {}
        Some(Json::Bool(true)) => {
            return Err(ApiError::simple(
                "UNSUPPORTED",
                "durable subscriptions are not supported",
            ))
        }
        Some(Json::Bool(false)) => {}
        Some(_) => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "durable must be a boolean",
            ))
        }
    }
    let heartbeat_ms = match params.get("heartbeat_ms") {
        None => subscribe::HEARTBEAT_MS_DEFAULT,
        Some(value) => match value.as_u64() {
            Some(0) => 0,
            Some(n) if (subscribe::HEARTBEAT_MS_MIN..=subscribe::HEARTBEAT_MS_MAX).contains(&n) => {
                n
            }
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    &format!(
                        "heartbeat_ms must be 0 or {}..={}",
                        subscribe::HEARTBEAT_MS_MIN,
                        subscribe::HEARTBEAT_MS_MAX,
                    ),
                ))
            }
        },
    };
    let filter = match params.get("filter") {
        None | Some(Json::Null) => None,
        Some(value @ Json::Object(_)) => Some(value),
        Some(_) => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "filter must be an object",
            ))
        }
    };

    if events {
        // The events stream is a volatile diagnostic mirror — it has no
        // network, no cursor, no payload knob, and no durability knob.
        for key in ["network", "cursor", "on_gap", "payloads", "durable"] {
            if params.get(key).is_some() {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    &format!("{key} is not valid for stream \"events\""),
                ));
            }
        }
        let from = match params.get("from") {
            None => "latest",
            Some(value) => match value.as_str() {
                Some(text) => text,
                None => {
                    return Err(ApiError::simple(
                        "INVALID_ARGUMENT",
                        "from must be \"earliest\" or \"latest\"",
                    ))
                }
            },
        };
        if from != "earliest" && from != "latest" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "from must be \"earliest\" or \"latest\"",
            ));
        }
        let mut kinds: Option<Vec<String>> = None;
        if let Some(filter) = filter {
            for (key, _) in filter.object_entries() {
                if key != "kinds" {
                    return Err(ApiError::simple(
                        "INVALID_ARGUMENT",
                        &format!("unknown filter key \"{key}\" for stream \"events\""),
                    ));
                }
            }
            if let Some(value) = filter.get("kinds") {
                let Some(items) = value.as_array() else {
                    return Err(ApiError::simple(
                        "INVALID_ARGUMENT",
                        "filter.kinds must be an array",
                    ));
                };
                if items.len() > subscribe::KINDS_MAX {
                    return Err(ApiError::simple(
                        "INVALID_ARGUMENT",
                        &format!(
                            "filter.kinds accepts at most {} entries",
                            subscribe::KINDS_MAX
                        ),
                    ));
                }
                let mut list = Vec::with_capacity(items.len());
                for item in items {
                    let Some(text) = item.as_str() else {
                        return Err(ApiError::simple(
                            "INVALID_ARGUMENT",
                            "filter.kinds entries must be strings",
                        ));
                    };
                    if !subscribe::EVENT_KINDS.contains(&text)
                        && !site::SITE_EVENT_KINDS.contains(&text)
                    {
                        return Err(ApiError::simple(
                            "INVALID_ARGUMENT",
                            &format!("unknown event kind \"{text}\""),
                        ));
                    }
                    list.push(text.to_string());
                }
                kinds = Some(list);
            }
        }
        // Positions are bare event seqs — valid only on this connection.
        let (position, oldest) = {
            let ring = ctx.event_ring.events.lock().expect("events poisoned");
            let next = ctx.event_ring.next_seq.load(Ordering::Relaxed);
            let oldest = ring.front().map_or(next, |event| event.seq);
            (if from == "earliest" { oldest } else { next }, oldest)
        };
        let dropped_total = ctx.event_ring.dropped.load(Ordering::Relaxed);
        let acl_view = ctx.acl.revision();
        let id = ctx
            .subscriptions
            .subscribe_principal(
                ctx.conn_id,
                ctx.principal.clone(),
                SubKind::Events(EvFilter { kinds }),
                position,
                acl_view,
                heartbeat_ms,
                ctx.now_ms,
            )
            .map_err(subscribe_capacity)?;
        let result = format!(
            "{{\"subscription\":\"{}\",\"stream\":\"events\",\"position\":{{\"event_seq\":{position},\"oldest_event_seq\":{oldest},\"dropped_total\":{dropped_total}}},\"queue\":{{\"max_notifications\":{SUB_QUEUE_EVENTS},\"max_bytes\":{SUB_QUEUE_BYTES},\"line_max_bytes\":{NOTIFY_LINE_MAX}}},\"heartbeat_ms\":{heartbeat_ms}}}",
            subscribe::token(id),
        );
        return Ok((result, ConnEffect::Subscribed { id }));
    }

    // ---- stream:"messages" ----
    if let Some(filter) = filter {
        for (key, _) in filter.object_entries() {
            if !matches!(key.as_str(), "origins" | "gateways") {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    &format!("unknown filter key \"{key}\" for stream \"messages\""),
                ));
            }
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
    let on_gap = match params.get("on_gap") {
        None => "fail",
        Some(value) => match value.as_str() {
            Some(text @ ("fail" | "skip")) => text,
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "on_gap must be \"fail\" or \"skip\"",
                ))
            }
        },
    };
    let payloads = match params.get("payloads") {
        None => true,
        Some(Json::Bool(value)) => *value,
        Some(_) => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "payloads must be a boolean",
            ))
        }
    };
    let origins = match filter {
        Some(filter) => parse_id_list(filter, "origins")?,
        None => None,
    };
    let gateways = match filter {
        Some(filter) => parse_id_list(filter, "gateways")?,
        None => None,
    };

    // Grant follows the payload mode: payloads:true needs READ_PAYLOAD,
    // payloads:false needs only READ_OPERATION (§5.6).
    let permission = if payloads {
        acl::PERM_READ_PAYLOAD
    } else {
        acl::PERM_READ_OPERATION
    };
    if !ctx
        .principal
        .as_ref()
        .is_some_and(|uid| ctx.acl.permit_principal(uid, network, permission))
    {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks the required receive grant on this network",
        ));
    }

    // Resolve the start position under the receive-log lock — the
    // `from:"latest"` tail snapshot and the cursor ladder both run here.
    // Registration in the hub follows immediately after unlock; an ingest
    // landing in between still has seq > position and is delivered live.
    let mut log = ctx.receive_log.lock().expect("receive log poisoned");
    let epoch = log.epoch();
    let acl_view = ctx.acl.revision();
    let cursor_at = |position: u64| {
        Cursor {
            network,
            acl_view,
            epoch,
            last_scanned: position,
        }
        .encode()
    };
    let mut start_gap: Option<String> = None;
    let position = if let Some(from) = from {
        if from == "latest" {
            log.bounds(network, ctx.now_ms).1
        } else {
            0
        }
    } else {
        let token = cursor_token.expect("cursor checked above");
        let cursor = checked_cursor(&mut log, token, network, acl_view, ctx.now_ms)?;
        // Probe the position without consuming a page: limit 0 still runs
        // the Future/Gap checks against the tombstone.
        match log.read(network, cursor.last_scanned, 0, ctx.now_ms, true) {
            ReadOutcome::Future => {
                return Err(ApiError::simple(
                    "INVALID_CURSOR",
                    "cursor points beyond the current tail",
                ))
            }
            ReadOutcome::Gap {
                lost_from,
                lost_to,
                oldest_seq,
                tail_seq,
            } => {
                if on_gap == "fail" {
                    return Err(cursor_gap(
                        lost_from, lost_to, oldest_seq, tail_seq, &cursor_at,
                    ));
                }
                // skip: subscribe succeeds and the FIRST notification is a
                // gap{start_position} marker naming the unrecoverable range.
                start_gap = Some(format!(
                    "\"cause\":\"start_position\",\"lost_from\":{lost_from},\"lost_to\":{lost_to},\"resume_cursor\":\"{}\",\"recoverable_via_read\":false,\"ms\":{}",
                    cursor_at(lost_to),
                    ctx.now_ms,
                ));
                lost_to
            }
            ReadOutcome::Batch(_) => cursor.last_scanned,
        }
    };
    let (oldest, tail, ..) = log.bounds(network, ctx.now_ms);
    drop(log);

    let id = ctx
        .subscriptions
        .subscribe_principal(
            ctx.conn_id,
            ctx.principal.clone(),
            SubKind::Messages(MsgFilter {
                network,
                origins,
                gateways,
                payloads,
            }),
            position,
            acl_view,
            heartbeat_ms,
            ctx.now_ms,
        )
        .map_err(subscribe_capacity)?;
    if let Some(body) = start_gap {
        ctx.subscriptions.stage_marker(ctx.conn_id, id, "gap", body);
    }
    let result = format!(
        "{{\"subscription\":\"{}\",\"stream\":\"messages\",\"network\":\"{network:016x}\",\"payloads\":{payloads},\"epoch\":\"{}\",\"acl_revision\":{acl_view},\"position\":{{\"cursor\":\"{}\",\"oldest_cursor\":\"{}\",\"tail_cursor\":\"{}\"}},\"queue\":{{\"max_notifications\":{SUB_QUEUE_EVENTS},\"max_bytes\":{SUB_QUEUE_BYTES},\"line_max_bytes\":{NOTIFY_LINE_MAX}}},\"heartbeat_ms\":{heartbeat_ms}}}",
        subscribe::token(id),
        hex_lower(&epoch),
        cursor_at(position),
        cursor_at(oldest.saturating_sub(1)),
        cursor_at(tail),
    );
    Ok((result, ConnEffect::Subscribed { id }))
}

/// `messages.unsubscribe` params: `{subscription}` — own-connection ids
/// only; unknown or foreign ids resolve NOT_FOUND (there is no
/// cross-connection existence oracle). The response carries the
/// subscription's final counters.
fn messages_unsubscribe<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if key != "subscription" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(token) = params.get("subscription").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "subscription must be a subscription id string",
        ));
    };
    let Some(id) = subscribe::parse_token(token) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "subscription is not a subscription id",
        ));
    };
    match ctx.subscriptions.unsubscribe(ctx.conn_id, id, ctx.now_ms) {
        Some(stats) => Ok(format!(
            "{{\"ended\":true,\"delivered\":{},\"dropped\":{},\"gaps\":{},\"lifetime_ms\":{}}}",
            stats.delivered, stats.dropped, stats.gaps, stats.lifetime_ms,
        )),
        None => Err(ApiError::simple("NOT_FOUND", "unknown subscription id")),
    }
}

/// `messages.subscriptions` takes no params and lists the caller's own
/// connection's subscriptions — never another connection's.
fn messages_subscriptions<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    if !params.object_entries().is_empty() {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "messages.subscriptions takes no params",
        ));
    }
    let epoch = ctx
        .receive_log
        .lock()
        .expect("receive log poisoned")
        .epoch();
    let acl_view = ctx.acl.revision();
    let entries = ctx.subscriptions.list(ctx.conn_id);
    let mut out = String::from("{\"subscriptions\":[");
    for (index, entry) in entries.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        if entry.is_events {
            out.push_str(&format!(
                "{{\"id\":\"{}\",\"stream\":\"events\",\"event_seq\":{},\"delivered\":{},\"dropped\":{},\"gaps\":{},\"queued\":{},\"queued_bytes\":{},\"created_ms\":{}}}",
                subscribe::token(entry.id),
                entry.position,
                entry.delivered,
                entry.dropped,
                entry.gaps,
                entry.queued,
                entry.queued_bytes,
                entry.created_ms,
            ));
        } else {
            let cursor = Cursor {
                network: entry.network.unwrap_or(0),
                acl_view,
                epoch,
                last_scanned: entry.position,
            }
            .encode();
            out.push_str(&format!(
                "{{\"id\":\"{}\",\"stream\":\"messages\",\"network\":\"{:016x}\",\"payloads\":{},\"position_cursor\":\"{}\",\"delivered\":{},\"dropped\":{},\"gaps\":{},\"queued\":{},\"queued_bytes\":{},\"created_ms\":{}}}",
                subscribe::token(entry.id),
                entry.network.unwrap_or(0),
                entry.payloads,
                cursor,
                entry.delivered,
                entry.dropped,
                entry.gaps,
                entry.queued,
                entry.queued_bytes,
                entry.created_ms,
            ));
        }
    }
    out.push_str("]}");
    Ok(out)
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
        .principal
        .as_ref()
        .filter(|uid| ctx.acl.permit_principal(uid, network, acl::PERM_SEND))
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
        .admit_principal(uid, ctx.now_ms)
    {
        return Err(rate_limited(deny));
    }
    let mut store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    match store.open_epoch_principal((uid.clone(), network), ctx.now_ms) {
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
    // Authorize before the binding-dependent parse can leak registration
    // state: a gateway destination parses differently depending on whether
    // a live registration exists, so an unauthorized principal probing a
    // well-formed network must meet AuthorizationFailed — never the
    // GATEWAY_UNAVAILABLE-shaped rejection that would reveal the mirror
    // (05 §5.7). A malformed network cannot satisfy the probe and falls
    // through to the parse error below, identical for every principal.
    if let Some(network) = params
        .get("network")
        .and_then(Json::as_str)
        .and_then(|text| acl::parse_network_hex(text).ok())
    {
        ctx.principal
            .as_ref()
            .filter(|uid| ctx.acl.permit_principal(uid, network, acl::PERM_SEND))
            .ok_or_else(|| {
                ApiError::simple(
                    "AuthorizationFailed",
                    "principal lacks SEND on this network",
                )
            })?;
    }
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
        .principal
        .as_ref()
        .filter(|uid| ctx.acl.permit_principal(uid, req.network, acl::PERM_SEND))
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
        .admit_principal(uid, ctx.now_ms)
    {
        return Err(rate_limited(deny));
    }
    let mut store = ctx
        .operation_store
        .lock()
        .expect("operation store poisoned");
    // The monotonic stamp rides alongside the wall admit time so a
    // wall-clock rewind can never stretch the dispatch deadline.
    match store.submit_at_principal(uid, &req, ctx.now_ms, crate::mono_ms()) {
        SubmitOutcome::Accepted { seq } => {
            // KG control discipline (D10): once the replacement is
            // committed, retire still-queued older values to the same
            // destination. The supersede runs after commit so a lost
            // replacement can never take the previous value down with it.
            if req.queue_mode == canonical::QUEUE_LATEST_PER_DESTINATION {
                let superseded = store
                    .supersede_latest_for_dest(uid, &req, seq, ctx.now_ms)
                    .map_err(|()| store_fault())?;
                return Ok(submit_result_supersede(
                    &store.lineage(),
                    seq,
                    req.storage,
                    &superseded,
                ));
            }
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

/// `submit_result` plus the control-profile supersede list: the seqs the
/// newest value retired before dispatch, rendered as operation ids so a
/// caller can audit which queued records this submit displaced.
fn submit_result_supersede(
    lineage: &[u8; 16],
    seq: u64,
    storage: u8,
    superseded: &[u64],
) -> String {
    let base = submit_result(lineage, seq, storage);
    let ids = superseded.iter().fold(String::new(), |mut out, s| {
        if !out.is_empty() {
            out.push(',');
        }
        out.push('"');
        out.push_str(&canonical::format_operation_id(lineage, *s));
        out.push('"');
        out
    });
    format!("{},\"superseded\":[{}]}}", &base[..base.len() - 1], ids)
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
    if !ctx.principal.as_ref().is_some_and(|uid| {
        ctx.acl
            .permit_principal(uid, network, acl::PERM_READ_OPERATION)
    }) {
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
    if !ctx.principal.as_ref().is_some_and(|uid| {
        ctx.acl
            .permit_principal(uid, record.network, acl::PERM_READ_OPERATION)
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

/// `link.get` takes no params and needs no grant: the adapter state is a
/// daemon-health fact, not a network-scoped secret — a disconnected link
/// is observable by the absence of every other surface anyway. `state`
/// distinguishes "disconnected" (adapter absent or open keeps failing),
/// "reconnecting" (fd open, handshake/session not yet authenticated), and
/// "attached" (authenticated session on a live adapter). The lane token
/// itself stays hidden — `lane_registered` and `lane_lease_ms` are what a
/// caller needs to know whether dispatch will run.
fn link_get<S: OperationStore>(params: &Json, ctx: &ApiContext<'_, S>) -> Result<String, ApiError> {
    if !params.object_entries().is_empty() {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "link.get takes no params",
        ));
    }
    let (authenticated, session_id, gateway_node, gateway_boot) = {
        let info = ctx.session.lock().expect("session poisoned");
        (info.authenticated, info.id, info.node, info.boot)
    };
    let attached = ctx.link.connected && authenticated;
    let state = if attached {
        "attached"
    } else if ctx.link.connected {
        "reconnecting"
    } else {
        "disconnected"
    };
    let opt_hex =
        |v: Option<u64>| v.map_or_else(|| "null".to_string(), |v| format!("\"{v:016x}\""));
    let opt_u64 = |v: Option<u64>| v.map_or_else(|| "null".to_string(), |v| v.to_string());
    // The registration mirror only counts when it still belongs to THIS
    // session and its lease has not lapsed — a stale mirror must never
    // report a lane the dispatcher would refuse to use.
    let (lane_registered, lane_lease_ms) = match ctx.gateway_lane.current() {
        Some(reg)
            if authenticated
                && Some(reg.usb_session) == session_id
                && ctx.now_mono < reg.lease_deadline_mono =>
        {
            (true, reg.lease_deadline_mono.saturating_sub(ctx.now_mono))
        }
        _ => (false, 0),
    };
    let last_error = ctx.link.last_error.as_deref().map_or_else(
        || "null".to_string(),
        |e| format!("\"{}\"", escape_string(e)),
    );
    Ok(format!(
        "{{\"configured\":{},\"connected\":{},\"authenticated\":{authenticated},\"state\":\"{state}\",\"session_id\":{},\"gateway\":{},\"gateway_boot\":{},\"lane_registered\":{lane_registered},\"lane_lease_ms\":{lane_lease_ms},\"last_error\":{last_error}}}",
        ctx.link.configured,
        ctx.link.connected,
        opt_u64(session_id),
        opt_hex(gateway_node),
        opt_hex(gateway_boot),
    ))
}

/// `nodes.list` page bound: 128 node objects stay well inside the 64 KiB
/// response cap (each object is < 450 bytes).
pub const NODES_PAGE_MAX: usize = 128;

/// `nodes.list` params: `{connected?: bool, after?: "16hex", limit?:
/// 1..=128}`. Nodes come back ascending by id; `next_after` is the cursor
/// for the next page (null when this page completed the listing).
/// Diagnostics-class like `link.get`: no ACL grant needed — it exposes the
/// gateway's routing view, never payloads.
fn nodes_list<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "connected" | "after" | "limit") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let connected = match params.get("connected") {
        None | Some(Json::Null) => None,
        Some(Json::Bool(value)) => Some(*value),
        Some(_) => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "connected must be a boolean",
            ))
        }
    };
    let after = match params.get("after") {
        None | Some(Json::Null) => 0,
        Some(value) => value.as_str().and_then(parse_hex_u64).ok_or_else(|| {
            ApiError::simple("INVALID_ARGUMENT", "after must be a 16-hex node id")
        })?,
    };
    let limit = match params.get("limit") {
        None => NODES_PAGE_MAX,
        Some(value) => match value.as_u64() {
            Some(n) if (1..=NODES_PAGE_MAX as u64).contains(&n) => n as usize,
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    &format!("limit must be 1..={NODES_PAGE_MAX}"),
                ))
            }
        },
    };
    let table = ctx.node_table.lock().expect("node table poisoned");
    let (records, more) = table.list(after, limit, connected);
    let nodes: Vec<String> = records
        .iter()
        .map(|record| crate::nodes::node_json(record, ctx.now_ms))
        .collect();
    let next_after = match records.last() {
        Some(last) if more => format!("\"{:016x}\"", last.node),
        _ => "null".to_string(),
    };
    Ok(format!(
        "{{\"source\":{},\"nodes\":[{}],\"next_after\":{next_after}}}",
        crate::nodes::source_json(&table),
        nodes.join(","),
    ))
}

/// `nodes.get` params: `{node:"16hex"}`. A node the gateway never reported
/// is NOT_FOUND — the caller reads that as "no communication", never as a
/// synthesized record.
fn nodes_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if key != "node" {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(node) = params
        .get("node")
        .and_then(Json::as_str)
        .and_then(parse_hex_u64)
    else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "node must be a 16-hex node id",
        ));
    };
    let table = ctx.node_table.lock().expect("node table poisoned");
    let source = crate::nodes::source_json(&table);
    match table.get(node) {
        Some(record) => Ok(format!(
            "{{\"source\":{source},\"node\":{}}}",
            crate::nodes::node_json(record, ctx.now_ms)
        )),
        None => Err(ApiError {
            code: "NOT_FOUND",
            message: "node not reported by the attached gateway".to_string(),
            extra_fields: format!("\"node\":\"{node:016x}\",\"source\":{source}"),
            retryable: true,
        }),
    }
}

/// Gates a telemetry query on the live session: an authenticated
/// gateway whose HelloAck advertises m1_diagnostics_v1. No ACL grant is
/// needed (diagnostics class, like link.get) — snapshots carry RF
/// observations, never payloads or secrets.
/// Method-specific wording for the shared live-gateway gate, so
/// errors keep naming the refused method.
struct GateScope {
    /// "telemetry queries" / "group sends" — completes "…; {action} are
    /// not queued across a disconnect".
    action: &'static str,
    /// Network the live session must serve, when the method is
    /// network-scoped (`group.send`); mesh-relayed queries pass None.
    network: Option<u64>,
    /// `required_capability` value for the UNSUPPORTED arm.
    required_capability: &'static str,
    /// "(HelloAck capability bit 5 with host_ops_v1)"-style hint.
    capability_hint: &'static str,
    capable: fn(u32) -> bool,
}

/// The live-gateway gate shared by capability-gated methods
/// (`diagnostics.snapshot`, `group.send`): an authenticated session that
/// serves the method's network when scoped and advertises the required
/// capability. Returns the session id the lane binds its exchange to.
fn live_gateway_gate<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
    scope: GateScope,
) -> Result<u64, ApiError> {
    let (authenticated, session, session_network, capability) = {
        let info = ctx.session.lock().expect("session poisoned");
        (
            info.authenticated && info.id.is_some(),
            info.id.unwrap_or(0),
            info.network,
            info.capability,
        )
    };
    if !authenticated {
        return Err(ApiError {
            code: "GATEWAY_UNAVAILABLE",
            message: format!(
                "no authenticated gateway session; {} are not queued across a disconnect",
                scope.action
            ),
            extra_fields: "\"reason\":\"no_session\"".to_string(),
            retryable: true,
        });
    }
    if scope
        .network
        .is_some_and(|network| session_network != Some(network))
    {
        return Err(ApiError {
            code: "GATEWAY_UNAVAILABLE",
            message: "the attached gateway serves a different network".to_string(),
            extra_fields: "\"reason\":\"network_mismatch\"".to_string(),
            retryable: true,
        });
    }
    if !capability.is_some_and(scope.capable) {
        return Err(ApiError {
            code: "UNSUPPORTED",
            message: format!(
                "the attached gateway does not advertise {} ({})",
                scope.required_capability, scope.capability_hint
            ),
            extra_fields: format!(
                "\"required_capability\":\"{}\",\"capability\":{}",
                scope.required_capability,
                capability.map_or_else(|| "null".to_string(), |c| c.to_string())
            ),
            retryable: false,
        });
    }
    Ok(session)
}

fn telemetry_gate<S: OperationStore>(ctx: &ApiContext<'_, S>) -> Result<u64, ApiError> {
    live_gateway_gate(
        ctx,
        GateScope {
            action: "telemetry queries",
            network: None,
            required_capability: "m1_diagnostics_v1",
            capability_hint: "HelloAck capability bit 5 with host_ops_v1",
            capable: crate::telemetry::telemetry_capable,
        },
    )
}

/// Maps a resolved query onto the API answer. A snapshot or a mesh
/// refusal is a successful query (the device proved the step); anything
/// else is the honest error for why no answer arrived.
fn telemetry_outcome_result(
    outcome: crate::telemetry::QueryOutcome,
    observer: u64,
    peer: u64,
) -> Result<String, ApiError> {
    use crate::telemetry::QueryOutcome;
    let scope = format!("\"observer\":\"{observer:016x}\",\"peer\":\"{peer:016x}\"");
    match outcome {
        QueryOutcome::Snapshot(snapshot) => Ok(format!(
            "{{\"outcome\":\"snapshot\",\"scope\":{{{scope}}},\"snapshot\":{}}}",
            crate::telemetry::snapshot_json(&snapshot),
        )),
        QueryOutcome::Reject(reject) => Ok(format!(
            "{{\"outcome\":\"reject\",\"scope\":{{{scope}}},\"reject\":{}}}",
            crate::telemetry::reject_json(&reject),
        )),
        QueryOutcome::Device(result) => Err(device_result_error(result, &scope)),
        QueryOutcome::DecodeError(detail) => Err(ApiError {
            code: "INDETERMINATE",
            message: format!("the gateway answered with a malformed 0x31 body: {detail}"),
            extra_fields: scope,
            retryable: true,
        }),
        QueryOutcome::Timeout => Err(ApiError {
            code: "TIMEOUT",
            message: format!(
                "no telemetry answer inside {} ms",
                crate::telemetry::API_WAIT_MS
            ),
            extra_fields: scope,
            retryable: true,
        }),
        QueryOutcome::SessionLost => Err(ApiError {
            code: "GATEWAY_UNAVAILABLE",
            message: "the gateway session changed while the query was in flight".to_string(),
            extra_fields: format!("{scope},\"reason\":\"session_lost\""),
            retryable: true,
        }),
        QueryOutcome::ErrorFrame(code) => Err(ApiError {
            code: "INDETERMINATE",
            message: "the gateway refused the query at the frame level".to_string(),
            extra_fields: format!("{scope},\"error_code\":{code}"),
            retryable: true,
        }),
    }
}

/// A non-Ok 0x31 device result, mapped onto the API error vocabulary.
/// Busy/Timeout/NoRoute are retryable states of the mesh; the rest name
/// a configuration or daemon-side defect.
fn device_result_error(
    result: routeloom_protocol::host_ops::ConfigOpsResult,
    scope: &str,
) -> ApiError {
    use routeloom_protocol::host_ops::ConfigOpsResult;
    let (code, message, retryable) = match result {
        ConfigOpsResult::Ok => ("INTERNAL", "unreachable device Ok", false),
        ConfigOpsResult::Busy => (
            "NO_CAPACITY",
            "the gateway is busy; retry the telemetry query",
            true,
        ),
        ConfigOpsResult::Denied => (
            "AuthorizationFailed",
            "the gateway denied the telemetry query",
            false,
        ),
        ConfigOpsResult::Unsupported => (
            "UNSUPPORTED",
            "the gateway no longer serves telemetry queries",
            false,
        ),
        ConfigOpsResult::Invalid => (
            "INTERNAL",
            "the gateway rejected the telemetry query as malformed",
            false,
        ),
        ConfigOpsResult::Indeterminate => (
            "INDETERMINATE",
            "the gateway cannot prove the telemetry outcome",
            true,
        ),
        ConfigOpsResult::NoRoute => ("NO_ROUTE", "no mesh route to the telemetry observer", true),
        ConfigOpsResult::Timeout => (
            "TIMEOUT",
            "the telemetry observer did not answer the gateway",
            true,
        ),
    };
    ApiError {
        code,
        message: message.to_string(),
        extra_fields: format!(
            "{scope},\"device_result\":\"{}\"",
            config_ops_result_name(result)
        ),
        retryable,
    }
}

/// `diagnostics.snapshot {observer, peer, direction?, length_class?,
/// max_age_ms?}`: one on-demand RF telemetry snapshot for a directed
/// (observer, peer) link. No ACL grant needed (diagnostics class).
/// Answers within `telemetry::API_WAIT_MS` — a mesh refusal arrives as
/// `outcome:reject`, never an error.
fn diagnostics_snapshot<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    use routeloom_protocol::telemetry::{
        DIRECTION_EGRESS, DIRECTION_INGRESS, LENGTH_CLASS_PEER_SUMMARY, MAX_AGE_LIMIT_MS,
    };
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "observer" | "peer" | "direction" | "length_class" | "max_age_ms"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let observer = params
        .get("observer")
        .and_then(Json::as_str)
        .and_then(parse_hex_u64)
        .filter(|id| *id != 0 && *id != u64::MAX)
        .ok_or_else(|| {
            ApiError::simple(
                "INVALID_ARGUMENT",
                "observer must be a non-reserved 16-hex node id",
            )
        })?;
    let peer = params
        .get("peer")
        .and_then(Json::as_str)
        .and_then(parse_hex_u64)
        .filter(|id| *id != 0 && *id != u64::MAX)
        .ok_or_else(|| {
            ApiError::simple(
                "INVALID_ARGUMENT",
                "peer must be a non-reserved 16-hex node id",
            )
        })?;
    let direction = match params.get("direction") {
        None | Some(Json::Null) => DIRECTION_EGRESS,
        Some(value) => match value.as_str() {
            Some("egress") => DIRECTION_EGRESS,
            Some("ingress") => DIRECTION_INGRESS,
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "direction must be \"egress\" or \"ingress\"",
                ));
            }
        },
    };
    let length_class = match params.get("length_class") {
        None | Some(Json::Null) => LENGTH_CLASS_PEER_SUMMARY,
        Some(value) => match value.as_u64() {
            Some(0) => 0,
            Some(1) => 1,
            Some(2) => 2,
            Some(255) => LENGTH_CLASS_PEER_SUMMARY,
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "length_class must be 0, 1, 2 or 255 (peer summary)",
                ));
            }
        },
    };
    let max_age_ms = match params.get("max_age_ms") {
        None | Some(Json::Null) => 0,
        Some(value) => match value.as_u64() {
            Some(ms) if ms <= u64::from(MAX_AGE_LIMIT_MS) => ms as u32,
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "max_age_ms must be 0..3000 (0 = latest)",
                ));
            }
        },
    };
    let session = telemetry_gate(ctx)?;
    let token = ctx
        .telemetry_ops
        .submit(
            crate::telemetry::TelemetryQueryParams {
                observer,
                peer,
                direction,
                length_class,
                max_age_ms,
            },
            session,
            ctx.now_mono,
        )
        .map_err(|_| ApiError {
            code: "NO_CAPACITY",
            message: "too many telemetry queries in flight; retry when one settles".to_string(),
            extra_fields: format!("\"in_flight\":{}", ctx.telemetry_ops.pending()),
            retryable: true,
        })?;
    let outcome = ctx
        .telemetry_ops
        .wait_for(token, Duration::from_millis(crate::telemetry::API_WAIT_MS))
        .ok_or_else(|| ApiError {
            code: "TIMEOUT",
            message: format!(
                "telemetry query did not resolve inside {} ms",
                crate::telemetry::API_WAIT_MS
            ),
            extra_fields: format!("\"observer\":\"{observer:016x}\",\"peer\":\"{peer:016x}\""),
            retryable: true,
        })?;
    telemetry_outcome_result(outcome, observer, peer)
}

/// The live session an observation query runs against: authenticated,
/// carrying the gateway identity, and advertising observation_v1.
struct ObservationLink {
    session: u64,
    gateway: u64,
    boot: u64,
    network: Option<u64>,
}

/// The live session an observation query runs against, without the
/// capability bit: the locality (gateway or foreign observer) decides
/// which bit the caller must hold (`observation_require_local` vs
/// `observation_require_remote` below).
fn observation_session_link<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
) -> Result<ObservationLink, ApiError> {
    let info = ctx.session.lock().expect("session poisoned");
    let link = ObservationLink {
        session: info.id.unwrap_or(0),
        gateway: info.node.unwrap_or(0),
        boot: info.boot.unwrap_or(0),
        network: info.network,
    };
    let identified = info.authenticated && info.id.is_some() && info.node.is_some();
    drop(info);
    if !identified {
        return Err(ApiError {
            code: "GATEWAY_UNAVAILABLE",
            message: "no authenticated gateway session; observation queries are not queued across a disconnect"
                .to_string(),
            extra_fields: "\"reason\":\"no_session\"".to_string(),
            retryable: true,
        });
    }
    Ok(link)
}

/// Gates a local observation query on the live session: an authenticated
/// gateway whose HelloAck advertises observation_v1 (capability bit 11
/// with host_ops_v1). No ACL grant is needed (diagnostics class, like
/// link.get) — snapshots carry device health and routing views, never
/// payloads or secrets.
/// Requires the observation_v1 bit (capability bit 11 with
/// host_ops_v1) for a local (gateway) query, after
/// `observation_session_link` fixed the session.
fn observation_require_local<S: OperationStore>(ctx: &ApiContext<'_, S>) -> Result<(), ApiError> {
    let capable = ctx
        .session
        .lock()
        .expect("session poisoned")
        .capability
        .is_some_and(crate::observation::observation_capable);
    if !capable {
        return Err(ApiError {
            code: "UNSUPPORTED",
            message: "the attached gateway does not advertise observation_v1 (HelloAck capability bit 11 with host_ops_v1)".to_string(),
            extra_fields: "\"required_capability\":\"observation_v1\"".to_string(),
            retryable: false,
        });
    }
    Ok(())
}

/// Requires the m1 diagnostics bit (capability bit 5 with host_ops_v1)
/// for a remote (foreign observer) query: the forward leg rides
/// Diagnostic 0x30, so the gateway's own observation_v1 bit is
/// irrelevant to a peer's sections. OBSERVE is independently required
/// because a remote pull reveals another node's state and costs radio.
fn observation_require_remote<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
    network: Option<u64>,
) -> Result<(), ApiError> {
    if !network.is_some_and(|network| {
        ctx.principal.as_ref().is_some_and(|principal| {
            ctx.acl
                .permit_principal(principal, network, acl::PERM_OBSERVE)
        })
    }) {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks OBSERVE on this network",
        ));
    }
    let capable = ctx
        .session
        .lock()
        .expect("session poisoned")
        .capability
        .is_some_and(crate::telemetry::telemetry_capable);
    if !capable {
        return Err(ApiError {
            code: "UNSUPPORTED",
            message: "the attached gateway does not advertise m1 diagnostics (HelloAck capability bit 5 with host_ops_v1) for remote observation".to_string(),
            extra_fields: "\"required_capability\":\"diagnostics_v1\"".to_string(),
            retryable: false,
        });
    }
    Ok(())
}

/// `network` is an optional scope check: when present it must name the
/// attached session's network (same GATEWAY_UNAVAILABLE shape as the
/// group gate — never a silent cross-scope read).
fn observation_network_param(params: &Json, link: &ObservationLink) -> Result<(), ApiError> {
    let Some(text) = params.get("network") else {
        return Ok(());
    };
    if text.is_null() {
        return Ok(());
    }
    let network = text
        .as_str()
        .and_then(|text| acl::parse_network_hex(text).ok())
        .ok_or_else(|| ApiError::simple("INVALID_ARGUMENT", "network must be a 16-hex string"))?;
    if link.network.is_some_and(|session| session != network) {
        return Err(ApiError {
            code: "GATEWAY_UNAVAILABLE",
            message: "the attached gateway session is on another network".to_string(),
            extra_fields: "\"reason\":\"network_mismatch\"".to_string(),
            retryable: true,
        });
    }
    Ok(())
}

/// `observer` names the observed node: the attached gateway itself
/// (served over local USB) or any foreign mesh node (served over the
/// gateway-forwarded remote leg). Reserved ids are never observable.
fn observation_observer_param(params: &Json) -> Result<u64, ApiError> {
    params
        .get("observer")
        .and_then(Json::as_str)
        .and_then(parse_hex_u64)
        .filter(|id| *id != 0 && *id != u64::MAX)
        .ok_or_else(|| {
            ApiError::simple(
                "INVALID_ARGUMENT",
                "observer must be a non-reserved 16-hex node id",
            )
        })
}

/// `max_age_ms`: 0..=60000, default 10000. Zero bypasses the singleton
/// cache (a fresh device pull); routes pages are never cached.
fn observation_max_age_param(params: &Json) -> Result<u64, ApiError> {
    match params.get("max_age_ms") {
        None | Some(Json::Null) => Ok(10_000),
        Some(value) => match value.as_u64() {
            Some(ms) if ms <= crate::observation::MAX_AGE_LIMIT_MS => Ok(ms),
            _ => Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "max_age_ms must be an integer 0..=60000",
            )),
        },
    }
}

/// `subscribe`: false by default. True (re)arms the 0x72 change-event
/// stream — and restarts the device event sequence, which the lane
/// absorbs by re-syncing its watermark when it sends the query.
fn observation_subscribe_param(params: &Json) -> Result<bool, ApiError> {
    match params.get("subscribe") {
        None | Some(Json::Null) => Ok(false),
        Some(Json::Bool(subscribe)) => Ok(*subscribe),
        Some(_) => Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "subscribe must be a boolean",
        )),
    }
}

/// One answered observation section: the decoded body plus the envelope
/// readings, whether freshly queried or served from the singleton cache.
/// `store_mark` is Some only for a fresh page (the dirty mark its query
/// took — the caller offers it to the cache); cache hits never re-store.
/// `radio_queries` is the mesh load this call spent: 0 on the local USB
/// leg, 0/1 on the remote leg (singleflight join or negative-cache hit
/// vs a fresh mesh query).
struct ObservationAnswer {
    revision: u32,
    boot: u64,
    sampled_ms: Option<u64>,
    received_ms: u64,
    received_mono_ms: u64,
    rtt_ms: u64,
    armed: bool,
    more: bool,
    next_after: u64,
    count: u8,
    body: Vec<u8>,
    store_mark: Option<u64>,
    radio_queries: u32,
}

/// One answered remote section: the decoded answer, or the mesh
/// refusal the observer (or the path) returned — data, like telemetry's
/// `outcome:reject`, never an error. The local leg answers
/// `Answer` only.
enum RemoteSection {
    Answer(ObservationAnswer),
    Reject(routeloom_protocol::telemetry::DiagnosticReject),
}

/// Renders a remote refusal: the same `outcome:reject` shape as
/// `diagnostics.snapshot`, scoped to the observed node.
fn remote_reject_json(
    scope: &str,
    reject: &routeloom_protocol::telemetry::DiagnosticReject,
) -> String {
    format!(
        "{{\"outcome\":\"reject\",\"scope\":{{{scope}}},\"reject\":{}}}",
        crate::telemetry::reject_json(reject),
    )
}

/// Runs one section query on the leg the observer selects: the 0x70
/// local leg for the gateway itself (or the singleton cache), the
/// gateway-forwarded 0x30 remote leg for a foreign observer. A
/// non-answer outcome maps onto the honest error for why no answer
/// arrived; a mesh refusal arrives as `RemoteSection::Reject`.
#[allow(clippy::too_many_arguments)]
fn observation_query<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
    link: &ObservationLink,
    scope: &str,
    observer: u64,
    section: u8,
    after: u64,
    exact: bool,
    subscribe: bool,
    max_age_ms: u64,
) -> Result<RemoteSection, ApiError> {
    if observer != link.gateway {
        return observation_query_remote(
            ctx, link, scope, observer, section, after, exact, subscribe,
        );
    }
    let answer = observation_query_local(
        ctx, link, scope, section, after, exact, subscribe, max_age_ms,
    )?;
    Ok(RemoteSection::Answer(answer))
}

/// Runs one 0x70 query (or answers from the singleton cache): submit,
/// wait within `observation::API_WAIT_MS`, decode. A non-page outcome
/// maps onto the honest error for why no answer arrived.
#[allow(clippy::too_many_arguments)]
fn observation_query_local<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
    link: &ObservationLink,
    scope: &str,
    section: u8,
    after: u64,
    exact: bool,
    subscribe: bool,
    max_age_ms: u64,
) -> Result<ObservationAnswer, ApiError> {
    use crate::observation::{ObservationOps, QueryOutcome};
    use routeloom_protocol::observation::PAGE_MAX;
    if !crate::observation::is_paged_section(section) && max_age_ms > 0 {
        if let Some(cached) =
            ctx.observation_ops
                .cached(section, link.session, link.boot, max_age_ms, ctx.now_mono)
        {
            return Ok(ObservationAnswer {
                revision: cached.revision,
                boot: link.boot,
                sampled_ms: None,
                received_ms: cached.received_ms,
                received_mono_ms: cached.received_mono_ms,
                rtt_ms: cached.rtt_ms,
                armed: cached.armed,
                more: false,
                next_after: 0,
                count: 1,
                body: cached.body,
                store_mark: None,
                radio_queries: 0,
            });
        }
    }
    let ops: &ObservationOps = ctx.observation_ops;
    let dirty_mark = ops.dirty_mark();
    let token = ops
        .submit(
            crate::observation::ObservationQueryParams {
                section,
                after,
                max_entries: PAGE_MAX as u8,
                exact,
                subscribe,
            },
            link.session,
            ctx.now_mono,
        )
        .map_err(|_| ApiError {
            code: "NO_CAPACITY",
            message: "too many observation queries in flight; retry when one settles".to_string(),
            extra_fields: format!("\"in_flight\":{}", ops.pending()),
            retryable: true,
        })?;
    let outcome = ops
        .wait_for(
            token,
            Duration::from_millis(crate::observation::API_WAIT_MS),
        )
        .ok_or_else(|| ApiError {
            code: "TIMEOUT",
            message: format!(
                "observation query did not resolve inside {} ms",
                crate::observation::API_WAIT_MS
            ),
            extra_fields: scope.to_string(),
            retryable: true,
        })?;
    match outcome {
        QueryOutcome::Page {
            header,
            body,
            received_ms,
            received_mono_ms,
            rtt_ms,
        } => {
            use routeloom_protocol::observation::{PAGE_ARMED, PAGE_MORE};
            if header.boot_id != link.boot {
                return Err(ApiError {
                    code: "GATEWAY_UNAVAILABLE",
                    message: "gateway boot changed during the observation query".to_string(),
                    extra_fields: "\"reason\":\"boot_changed\"".to_string(),
                    retryable: true,
                });
            }
            Ok(ObservationAnswer {
                revision: header.revision,
                boot: header.boot_id,
                sampled_ms: None,
                received_ms,
                received_mono_ms,
                rtt_ms,
                armed: header.flags & PAGE_ARMED != 0,
                more: header.flags & PAGE_MORE != 0,
                next_after: header.next_after,
                count: header.count,
                body,
                store_mark: Some(dirty_mark),
                radio_queries: 0,
            })
        }
        outcome => Err(observation_outcome_error(outcome, scope)),
    }
}

/// A resolved-but-not-a-page outcome, mapped onto the API error
/// vocabulary. A mesh refusal cannot happen here (local USB round trip);
/// anything else names why no answer arrived.
fn observation_outcome_error(outcome: crate::observation::QueryOutcome, scope: &str) -> ApiError {
    use crate::observation::QueryOutcome;
    match outcome {
        QueryOutcome::Page { .. } => ApiError::simple("INTERNAL", "unreachable observation page"),
        QueryOutcome::Device(result) => observation_device_error(result, scope),
        QueryOutcome::DecodeError(detail) => ApiError {
            code: "INDETERMINATE",
            message: format!("the gateway answered with a malformed 0x71 body: {detail}"),
            extra_fields: scope.to_string(),
            retryable: true,
        },
        QueryOutcome::Timeout => ApiError {
            code: "TIMEOUT",
            message: format!(
                "no observation answer inside {} ms",
                crate::observation::QUERY_TIMEOUT_MS
            ),
            extra_fields: scope.to_string(),
            retryable: true,
        },
        QueryOutcome::SessionLost => ApiError {
            code: "GATEWAY_UNAVAILABLE",
            message: "the gateway session changed while the query was in flight".to_string(),
            extra_fields: format!("{scope},\"reason\":\"session_lost\""),
            retryable: true,
        },
        QueryOutcome::ErrorFrame(code) => ApiError {
            code: "INDETERMINATE",
            message: "the gateway refused the query at the frame level".to_string(),
            extra_fields: format!("{scope},\"error_code\":{code}"),
            retryable: true,
        },
    }
}

/// A non-Ok 0x71 device result, mapped onto the API error vocabulary.
fn observation_device_error(
    result: routeloom_protocol::host_ops::ConfigOpsResult,
    scope: &str,
) -> ApiError {
    use routeloom_protocol::host_ops::ConfigOpsResult;
    let (code, message, retryable) = match result {
        ConfigOpsResult::Ok => ("INTERNAL", "unreachable device Ok", false),
        ConfigOpsResult::Busy => (
            "NO_CAPACITY",
            "the gateway is busy; retry the observation query",
            true,
        ),
        ConfigOpsResult::Denied => (
            "AuthorizationFailed",
            "the gateway denied the observation query",
            false,
        ),
        ConfigOpsResult::Unsupported => (
            "UNSUPPORTED",
            "the gateway does not serve this observation section",
            false,
        ),
        ConfigOpsResult::Invalid => (
            "INTERNAL",
            "the gateway rejected the observation query as malformed",
            false,
        ),
        ConfigOpsResult::Indeterminate => (
            "INDETERMINATE",
            "the gateway cannot prove the observation outcome",
            true,
        ),
        ConfigOpsResult::NoRoute => ("NO_ROUTE", "no mesh route to the observation target", true),
        ConfigOpsResult::Timeout => (
            "TIMEOUT",
            "the observation target did not answer the gateway",
            true,
        ),
    };
    ApiError {
        code,
        message: message.to_string(),
        extra_fields: format!(
            "{scope},\"device_result\":\"{}\"",
            config_ops_result_name(result)
        ),
        retryable,
    }
}

/// Runs one gateway-forwarded 0x30 subtype-7 query for a foreign
/// observer: submit, wait within `remote_observation::API_WAIT_MS`,
/// decode. Always a fresh pull (no change events cross the radio, so
/// there is no cache to honor — `max_age_ms` does not apply); the lane
/// still bounds the load (in-flight cap, singleflight, negative cache)
/// and every answer reports its `radio_queries`. A mesh refusal arrives
/// as `RemoteSection::Reject`, never an error.
#[allow(clippy::too_many_arguments)]
fn observation_query_remote<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
    link: &ObservationLink,
    scope: &str,
    observer: u64,
    section: u8,
    after: u64,
    exact: bool,
    subscribe: bool,
) -> Result<RemoteSection, ApiError> {
    use crate::remote_observation::{QueryOutcome, RemoteObservationParams, SubmitOutcome};
    use routeloom_protocol::observation::{
        REMOTE_NEIGHBORS_MAX, REMOTE_ROUTES_MAX, REMOTE_SNAPSHOT_MORE, SECTION_NEIGHBORS,
        SECTION_ROUTES,
    };
    if subscribe {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "subscribe is local-only; remote observation is pull-only",
        ));
    }
    let max_entries = match section {
        SECTION_ROUTES => REMOTE_ROUTES_MAX,
        SECTION_NEIGHBORS => REMOTE_NEIGHBORS_MAX,
        _ => 1,
    };
    let ops = ctx.remote_observation_ops;
    let submitted = ops
        .submit(
            RemoteObservationParams {
                observer,
                section,
                max_entries,
                exact,
                after,
            },
            link.session,
            ctx.now_mono,
        )
        .map_err(|_| ApiError {
            code: "NO_CAPACITY",
            message: "too many remote observation queries in flight; retry when one settles"
                .to_string(),
            extra_fields: format!("\"in_flight\":{}", ops.pending()),
            retryable: true,
        })?;
    let (outcome, received_ms, received_mono_ms, rtt_ms, radio_queries) = match submitted {
        // A cached mesh failure: served without radio, stamped now.
        SubmitOutcome::Cached(outcome) => (outcome, ctx.now_ms, ctx.now_mono, 0, 0),
        SubmitOutcome::Live { token, fresh } => {
            let answer = ops
                .wait_for(
                    token,
                    Duration::from_millis(crate::remote_observation::API_WAIT_MS),
                )
                .ok_or_else(|| ApiError {
                    code: "TIMEOUT",
                    message: format!(
                        "remote observation query did not resolve inside {} ms",
                        crate::remote_observation::API_WAIT_MS
                    ),
                    extra_fields: scope.to_string(),
                    retryable: true,
                })?;
            // Marginal radio: a singleflight join reports 0 — the shared
            // row's query is the leader's cost, not this call's.
            let radio_queries = u32::from(fresh && answer.sent);
            (
                answer.outcome,
                answer.received_ms,
                answer.received_mono_ms,
                answer.rtt_ms,
                radio_queries,
            )
        }
    };
    match outcome {
        QueryOutcome::Snapshot(snapshot) => Ok(RemoteSection::Answer(ObservationAnswer {
            revision: snapshot.revision,
            boot: snapshot.observer_boot,
            sampled_ms: Some(snapshot.sampled_ms),
            received_ms,
            received_mono_ms,
            rtt_ms,
            armed: false,
            more: snapshot.flags & REMOTE_SNAPSHOT_MORE != 0,
            next_after: remote_next_after(section, after, &snapshot.body),
            count: snapshot.count,
            body: snapshot.body,
            store_mark: None,
            radio_queries,
        })),
        QueryOutcome::Reject(reject) => Ok(RemoteSection::Reject(reject)),
        QueryOutcome::Device(result) => Err(observation_device_error(result, scope)),
        QueryOutcome::DecodeError(detail) => Err(ApiError {
            code: "INDETERMINATE",
            message: format!("the gateway answered with a malformed 0x31 body: {detail}"),
            extra_fields: scope.to_string(),
            retryable: true,
        }),
        QueryOutcome::Timeout => Err(ApiError {
            code: "TIMEOUT",
            message: format!(
                "no remote observation answer inside {} ms",
                crate::remote_observation::QUERY_TIMEOUT_MS
            ),
            extra_fields: scope.to_string(),
            retryable: true,
        }),
        QueryOutcome::SessionLost => Err(ApiError {
            code: "GATEWAY_UNAVAILABLE",
            message: "the gateway session changed while the query was in flight".to_string(),
            extra_fields: format!("{scope},\"reason\":\"session_lost\""),
            retryable: true,
        }),
        QueryOutcome::ErrorFrame(code) => Err(ApiError {
            code: "INDETERMINATE",
            message: "the gateway refused the query at the frame level".to_string(),
            extra_fields: format!("{scope},\"error_code\":{code}"),
            retryable: true,
        }),
    }
}

/// The follow-up cursor for a remote paged section: entries ascend like
/// 0x71 pages, so it is the last entry's destination/peer id. An empty
/// page echoes the query cursor (honest past-the-end); an undecodable
/// body echoes it too — the caller fails INDETERMINATE on the render
/// anyway, so the cursor value is never served.
fn remote_next_after(section: u8, after: u64, body: &[u8]) -> u64 {
    use routeloom_protocol::observation::{
        decode_neighbor_detail_entry, decode_route_detail_entry, NEIGHBOR_ENTRY_SIZE,
        ROUTE_ENTRY_SIZE, SECTION_NEIGHBORS, SECTION_ROUTES,
    };
    let entry_size = if section == SECTION_ROUTES {
        ROUTE_ENTRY_SIZE
    } else if section == SECTION_NEIGHBORS {
        NEIGHBOR_ENTRY_SIZE
    } else {
        return after;
    };
    if body.is_empty() || body.len() % entry_size != 0 {
        return after;
    }
    let last = &body[body.len() - entry_size..];
    if section == SECTION_ROUTES {
        decode_route_detail_entry(last).map_or(after, |entry| entry.destination)
    } else {
        decode_neighbor_detail_entry(last).map_or(after, |entry| entry.peer)
    }
}

/// The common observation envelope: schema, source identity (host-side
/// session plus the device-reported boot), revision and freshness. Ages
/// inside the section body map against `received_unix_ms`
/// (`received_unix_ms - age`, an upper bound); `received_mono_ms` is the
/// same instant on the host monotonic clock and `rtt_ms` the measured
/// submit→receive round trip — the mapping's uncertainty bound (the true
/// sample time is at most `rtt_ms` before the receive).
#[allow(clippy::too_many_arguments)]
fn observation_envelope(
    section: &str,
    gateway: u64,
    session: u64,
    observer: u64,
    answer: &ObservationAnswer,
    now_mono: u64,
    complete: bool,
) -> String {
    // The transport names the leg that served the body: local USB for the
    // gateway itself, the gateway-forwarded mesh leg for a foreign
    // observer. `radio_queries` is the mesh load this call spent (0 on
    // the local leg; 0/1 remote for a shared/cached vs fresh query).
    let transport = if observer == gateway {
        "usb_local"
    } else {
        "mesh_remote"
    };
    let transfer_bound = if answer.sampled_ms.is_some() {
        answer.rtt_ms
    } else {
        0
    };
    let sampled = answer
        .sampled_ms
        .map_or("null".to_string(), |ms| ms.to_string());
    let (sample_earliest, sample_latest) = if answer.sampled_ms.is_some() {
        (
            answer.received_ms.saturating_sub(answer.rtt_ms).to_string(),
            answer.received_ms.to_string(),
        )
    } else {
        ("null".to_string(), "null".to_string())
    };
    format!(
        "\"schema\":1,\"section\":\"{section}\",\"source\":{{\"gateway\":\"{gateway:016x}\",\"usb_session\":{session},\"observer\":\"{observer:016x}\",\"observer_boot\":\"{:016x}\",\"transport\":\"{transport}\"}},\"revision\":{},\"sampled_at_device_ms\":{sampled},\"sampled_unix_ms_earliest\":{sample_earliest},\"sampled_unix_ms_latest\":{sample_latest},\"received_unix_ms\":{},\"received_mono_ms\":{},\"rtt_ms\":{},\"age_ms\":{},\"age_uncertainty_ms\":{transfer_bound},\"stale\":false,\"complete\":{complete},\"armed\":{},\"radio_queries\":{}",
        answer.boot,
        answer.revision,
        answer.received_ms,
        answer.received_mono_ms,
        answer.rtt_ms,
        now_mono.saturating_sub(answer.received_mono_ms).saturating_add(transfer_bound),
        answer.armed,
        answer.radio_queries,
    )
}

// A page token binds the last id to the producing snapshot and both
// device incarnations. A changed table must restart at its first page.
#[derive(Clone, Copy)]
struct ObservationCursor {
    after: u64,
    revision: u32,
    observer_boot: u64,
    gateway_boot: u64,
    session: u64,
    observer: u64,
    section: u8,
}

impl ObservationCursor {
    fn parse(text: &str) -> Option<Self> {
        let mut fields = text.split('.');
        let parts = [
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
            fields.next()?,
        ];
        if fields.next().is_some()
            || [16, 8, 16, 16, 16, 16, 2]
                .iter()
                .zip(&parts)
                .any(|(len, part)| {
                    part.len() != *len || !part.bytes().all(|b| b.is_ascii_hexdigit())
                })
        {
            return None;
        }
        Some(Self {
            after: u64::from_str_radix(parts[0], 16).ok()?,
            revision: u32::from_str_radix(parts[1], 16).ok()?,
            observer_boot: u64::from_str_radix(parts[2], 16).ok()?,
            gateway_boot: u64::from_str_radix(parts[3], 16).ok()?,
            session: u64::from_str_radix(parts[4], 16).ok()?,
            observer: u64::from_str_radix(parts[5], 16).ok()?,
            section: u8::from_str_radix(parts[6], 16).ok()?,
        })
    }

    fn encode(self) -> String {
        format!(
            "{:016x}.{:08x}.{:016x}.{:016x}.{:016x}.{:016x}.{:02x}",
            self.after,
            self.revision,
            self.observer_boot,
            self.gateway_boot,
            self.session,
            self.observer,
            self.section
        )
    }
}

fn observation_page_changed() -> ApiError {
    ApiError {
        code: "SNAPSHOT_CHANGED",
        message: "snapshot changed; restart from the first page".to_string(),
        extra_fields: String::new(),
        retryable: true,
    }
}

/// `health.get {observer, section?:"system"|"tables"|"milestones",
/// network?, max_age_ms?, subscribe?}`: one read-only device-health
/// singleton of the attached gateway — or, for a foreign observer, of
/// that mesh node over the gateway-forwarded remote leg (pull-only:
/// `subscribe` is refused and `max_age_ms` ignored there). Diagnostics
/// class for local USB; remote pulls require OBSERVE on the live network.
fn health_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    use routeloom_protocol::observation::{SECTION_MILESTONES, SECTION_SYSTEM, SECTION_TABLES};
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "observer" | "section" | "network" | "max_age_ms" | "subscribe"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let link = observation_session_link(ctx)?;
    observation_network_param(params, &link)?;
    let observer = observation_observer_param(params)?;
    if observer == link.gateway {
        observation_require_local(ctx)?;
    } else {
        observation_require_remote(ctx, link.network)?;
    }
    let section = match params.get("section") {
        None | Some(Json::Null) => SECTION_SYSTEM,
        Some(value) => match value.as_str() {
            Some("system") => SECTION_SYSTEM,
            Some("tables") => SECTION_TABLES,
            Some("milestones") => SECTION_MILESTONES,
            _ => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "section must be \"system\", \"tables\" or \"milestones\"",
                ));
            }
        },
    };
    let max_age_ms = observation_max_age_param(params)?;
    let subscribe = observation_subscribe_param(params)?;
    let scope = format!("\"observer\":\"{observer:016x}\"");
    let section_name = match section {
        SECTION_SYSTEM => "system",
        SECTION_TABLES => "tables",
        _ => "milestones",
    };
    // A cached body that no longer decodes is never served: fall through
    // to a fresh query (bodies are only stored after a decode, so this is
    // a can't-happen made honest anyway). A mesh refusal is data, not an
    // error — it renders `outcome:reject` as-is.
    let mut answer = match observation_query(
        ctx, &link, &scope, observer, section, 0, false, subscribe, max_age_ms,
    )? {
        RemoteSection::Answer(answer) => answer,
        RemoteSection::Reject(reject) => return Ok(remote_reject_json(&scope, &reject)),
    };
    let mut rendered = render_health_section(section, &answer.body, answer.received_ms);
    if rendered.is_none() {
        answer = match observation_query(
            ctx, &link, &scope, observer, section, 0, false, subscribe, 0,
        )? {
            RemoteSection::Answer(answer) => answer,
            RemoteSection::Reject(reject) => return Ok(remote_reject_json(&scope, &reject)),
        };
        rendered = render_health_section(section, &answer.body, answer.received_ms);
    }
    let Some(body_json) = rendered else {
        let message = if observer == link.gateway {
            "the gateway answered with a malformed 0x71 section body"
        } else {
            "the observer answered with a malformed section body"
        };
        return Err(ApiError {
            code: "INDETERMINATE",
            message: message.to_string(),
            extra_fields: scope,
            retryable: true,
        });
    };
    // Only singletons reach here, only fresh pages (never a cache hit),
    // and only after a successful decode. A skipped store (an event
    // landed mid-query) just costs the next call a re-pull.
    if let Some(dirty_mark) = answer.store_mark {
        ctx.observation_ops.store(crate::observation::CacheStore {
            section,
            session: link.session,
            boot: answer.boot,
            body: answer.body.clone(),
            revision: answer.revision,
            received_ms: answer.received_ms,
            received_mono_ms: answer.received_mono_ms,
            rtt_ms: answer.rtt_ms,
            armed: answer.armed,
            dirty_mark,
        });
    }
    Ok(format!(
        "{{\"outcome\":\"snapshot\",\"scope\":{{{scope}}},\"snapshot\":{{{envelope},\"{section_name}\":{body_json}}}}}",
        envelope = observation_envelope(
            section_name,
            link.gateway,
            link.session,
            observer,
            &answer,
            ctx.now_mono,
            true,
        ),
    ))
}

/// Decodes and renders one health section body; None when the body the
/// device sent does not match its section.
fn render_health_section(section: u8, body: &[u8], received_ms: u64) -> Option<String> {
    use routeloom_protocol::observation::{
        decode_observation_milestones, decode_observation_system, decode_observation_tables,
        SECTION_MILESTONES, SECTION_SYSTEM, SECTION_TABLES,
    };
    if section == SECTION_SYSTEM {
        decode_observation_system(body)
            .ok()
            .map(|system| crate::observation::system_json(&system, received_ms))
    } else if section == SECTION_TABLES {
        decode_observation_tables(body)
            .ok()
            .map(|tables| crate::observation::tables_json(&tables))
    } else if section == SECTION_MILESTONES {
        decode_observation_milestones(body)
            .ok()
            .map(|milestones| crate::observation::milestones_json(&milestones, received_ms))
    } else {
        None
    }
}

/// `topology.get {observer, section:"routes"|"summary", network?,
/// destination?, cursor?, max_age_ms?, subscribe?}`: the attached
/// gateway's selected-route table or neighbor table (one page per call,
/// or one exact destination/peer) or its topology summary — or, for a
/// foreign observer, that mesh node's, over the gateway-forwarded
/// remote leg (pull-only, 2 routes / 3 neighbors per page). Remote pulls
/// require OBSERVE on the live network.
fn topology_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    use routeloom_protocol::observation::{
        decode_observation_summary, SECTION_NEIGHBORS, SECTION_ROUTES, SECTION_SUMMARY,
    };
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "observer"
                | "section"
                | "network"
                | "destination"
                | "cursor"
                | "max_age_ms"
                | "subscribe"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let link = observation_session_link(ctx)?;
    observation_network_param(params, &link)?;
    let observer = observation_observer_param(params)?;
    if observer == link.gateway {
        observation_require_local(ctx)?;
    } else {
        observation_require_remote(ctx, link.network)?;
    }
    let section = match params.get("section").and_then(Json::as_str) {
        Some("routes") => SECTION_ROUTES,
        Some("summary") => SECTION_SUMMARY,
        Some("neighbors") => SECTION_NEIGHBORS,
        _ => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "section must be \"routes\", \"neighbors\" or \"summary\"",
            ));
        }
    };
    let destination = match params.get("destination") {
        None | Some(Json::Null) => None,
        Some(value) => {
            let id = value
                .as_str()
                .and_then(parse_hex_u64)
                .filter(|id| *id != 0 && *id != u64::MAX);
            match id {
                Some(id) => Some(id),
                None => {
                    return Err(ApiError::simple(
                        "INVALID_ARGUMENT",
                        "destination must be a non-reserved 16-hex node id",
                    ));
                }
            }
        }
    };
    let cursor = match params.get("cursor") {
        None | Some(Json::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(ObservationCursor::parse)
                .ok_or_else(|| {
                    ApiError::simple("INVALID_ARGUMENT", "cursor must be a snapshot page token")
                })?,
        ),
    };
    if !crate::observation::is_paged_section(section) && (destination.is_some() || cursor.is_some())
    {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "destination and cursor are routes/neighbors-only",
        ));
    }
    if destination.is_some() && params.get("cursor").is_some_and(|v| !v.is_null()) {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "destination and cursor are mutually exclusive",
        ));
    }
    if cursor.is_some_and(|cursor| {
        cursor.after == u64::MAX
            || cursor.observer != observer
            || cursor.section != section
            || cursor.session != link.session
            || cursor.gateway_boot != link.boot
    }) {
        return Err(observation_page_changed());
    }
    let max_age_ms = observation_max_age_param(params)?;
    let subscribe = observation_subscribe_param(params)?;
    let scope = format!("\"observer\":\"{observer:016x}\"");
    if section == SECTION_SUMMARY {
        let mut answer = match observation_query(
            ctx, &link, &scope, observer, section, 0, false, subscribe, max_age_ms,
        )? {
            RemoteSection::Answer(answer) => answer,
            RemoteSection::Reject(reject) => return Ok(remote_reject_json(&scope, &reject)),
        };
        let mut summary = decode_observation_summary(&answer.body).ok();
        if summary.is_none() {
            answer = match observation_query(
                ctx, &link, &scope, observer, section, 0, false, subscribe, 0,
            )? {
                RemoteSection::Answer(answer) => answer,
                RemoteSection::Reject(reject) => return Ok(remote_reject_json(&scope, &reject)),
            };
            summary = decode_observation_summary(&answer.body).ok();
        }
        let Some(summary) = summary else {
            let message = if observer == link.gateway {
                "the gateway answered with a malformed 0x71 section body"
            } else {
                "the observer answered with a malformed section body"
            };
            return Err(ApiError {
                code: "INDETERMINATE",
                message: message.to_string(),
                extra_fields: scope,
                retryable: true,
            });
        };
        if let Some(dirty_mark) = answer.store_mark {
            ctx.observation_ops.store(crate::observation::CacheStore {
                section,
                session: link.session,
                boot: answer.boot,
                body: answer.body.clone(),
                revision: answer.revision,
                received_ms: answer.received_ms,
                received_mono_ms: answer.received_mono_ms,
                rtt_ms: answer.rtt_ms,
                armed: answer.armed,
                dirty_mark,
            });
        }
        return Ok(format!(
            "{{\"outcome\":\"snapshot\",\"scope\":{{{scope}}},\"snapshot\":{{{envelope},\"summary\":{},\"entries\":[],\"next_cursor\":null}}}}",
            crate::observation::summary_json(&summary),
            envelope = observation_envelope(
                "summary",
                link.gateway,
                link.session,
                observer,
                &answer,
                ctx.now_mono,
                true,
            ),
        ));
    }
    let exact = destination.is_some();
    let after = destination.unwrap_or(cursor.map_or(0, |cursor| cursor.after));
    let answer = match observation_query(
        ctx, &link, &scope, observer, section, after, exact, subscribe, 0,
    )? {
        RemoteSection::Answer(answer) => answer,
        RemoteSection::Reject(reject) => return Ok(remote_reject_json(&scope, &reject)),
    };
    let first = observation_first_page_id(section, &answer.body)?;
    if exact {
        if answer.more
            || answer.count > 1
            || (answer.count == 0 && answer.next_after != after)
            || first.is_some_and(|id| id != after)
        {
            return Err(ApiError::simple(
                "INDETERMINATE",
                "the observation answer does not match the exact destination",
            ));
        }
    } else if (answer.count == 0 && (answer.more || answer.next_after != after))
        || first.is_some_and(|id| id <= after || answer.next_after <= after)
    {
        return Err(observation_page_changed());
    }
    if cursor.is_some_and(|cursor| {
        cursor.revision != answer.revision || cursor.observer_boot != answer.boot
    }) {
        return Err(observation_page_changed());
    }
    let complete = !answer.more;
    let next_cursor = if answer.more {
        format!(
            "\"{}\"",
            ObservationCursor {
                after: answer.next_after,
                revision: answer.revision,
                observer_boot: answer.boot,
                gateway_boot: link.boot,
                session: link.session,
                observer,
                section
            }
            .encode()
        )
    } else {
        "null".to_string()
    };
    let present = if exact {
        format!("\"present\":{},", answer.count > 0)
    } else {
        String::new()
    };
    let section_name = if section == SECTION_ROUTES {
        "routes"
    } else {
        "neighbors"
    };
    let remote = observer != link.gateway;
    let entries = if section == SECTION_ROUTES {
        decode_route_entries(&answer.body, remote)?
    } else {
        decode_neighbor_entries(&answer.body, answer.received_ms, remote)?
    };
    Ok(format!(
        "{{\"outcome\":\"snapshot\",\"scope\":{{{scope}}},\"snapshot\":{{{envelope},{present}\"entries\":[{entries}],\"next_cursor\":{next_cursor}}}}}",
        envelope = observation_envelope(
            section_name,
            link.gateway,
            link.session,
            observer,
            &answer,
            ctx.now_mono,
            complete,
        ),
        entries = entries.join(","),
    ))
}

fn observation_first_page_id(section: u8, body: &[u8]) -> Result<Option<u64>, ApiError> {
    use routeloom_protocol::observation::{
        decode_neighbor_detail_entry, decode_route_detail_entry, NEIGHBOR_ENTRY_SIZE,
        ROUTE_ENTRY_SIZE, SECTION_ROUTES,
    };
    let entry_size = if section == SECTION_ROUTES {
        ROUTE_ENTRY_SIZE
    } else {
        NEIGHBOR_ENTRY_SIZE
    };
    let malformed = || ApiError::simple("INDETERMINATE", "malformed observation page entry order");
    let chunks = body.chunks_exact(entry_size);
    if !chunks.remainder().is_empty() {
        return Err(malformed());
    }
    let mut first = None;
    let mut previous = None;
    for chunk in chunks {
        let id = if section == SECTION_ROUTES {
            decode_route_detail_entry(chunk).map(|entry| entry.destination)
        } else {
            decode_neighbor_detail_entry(chunk).map(|entry| entry.peer)
        }
        .map_err(|_| malformed())?;
        if previous.is_some_and(|previous| id <= previous) {
            return Err(malformed());
        }
        if first.is_none() {
            first = Some(id);
        }
        previous = Some(id);
    }
    Ok(first)
}

/// Decodes a routes page body into rendered entries; a body that does
/// not match its validated page header is INDETERMINATE, never partial.
fn decode_route_entries(body: &[u8], remote: bool) -> Result<Vec<String>, ApiError> {
    use routeloom_protocol::observation::{decode_route_detail_entry, ROUTE_ENTRY_SIZE};
    let malformed = || {
        ApiError::simple(
            "INDETERMINATE",
            if remote {
                "the observer answered with a malformed routes section body"
            } else {
                "the gateway answered with a malformed 0x71 routes body"
            },
        )
    };
    if body.len() % ROUTE_ENTRY_SIZE != 0 {
        return Err(malformed());
    }
    let mut entries = Vec::new();
    for chunk in body.chunks_exact(ROUTE_ENTRY_SIZE) {
        match decode_route_detail_entry(chunk) {
            Ok(entry) => entries.push(crate::observation::route_entry_json(&entry)),
            Err(_) => {
                return Err(malformed());
            }
        }
    }
    Ok(entries)
}

/// Decodes a neighbors page body into rendered entries; heard ages map
/// onto the host receive time like every other device age.
fn decode_neighbor_entries(
    body: &[u8],
    received_ms: u64,
    remote: bool,
) -> Result<Vec<String>, ApiError> {
    use routeloom_protocol::observation::{decode_neighbor_detail_entry, NEIGHBOR_ENTRY_SIZE};
    let malformed = || {
        ApiError::simple(
            "INDETERMINATE",
            if remote {
                "the observer answered with a malformed neighbors section body"
            } else {
                "the gateway answered with a malformed 0x71 neighbors body"
            },
        )
    };
    if body.len() % NEIGHBOR_ENTRY_SIZE != 0 {
        return Err(malformed());
    }
    let mut entries = Vec::new();
    for chunk in body.chunks_exact(NEIGHBOR_ENTRY_SIZE) {
        match decode_neighbor_detail_entry(chunk) {
            Ok(entry) => entries.push(crate::observation::neighbor_entry_json(&entry, received_ms)),
            Err(_) => {
                return Err(malformed());
            }
        }
    }
    Ok(entries)
}

// --- group_delivery_v1 (group.send / group.get) --------------------------
//
// `group.send` needs SEND on the network (it transmits application data to
// many nodes at once — the same grant as messages.submit, never a weaker
// one); `group.get` needs READ_OPERATION like operations.get and answers
// NOT_FOUND to a principal without it (no existence oracle). Records are
// RAM-only (crate::group bounds); idempotency identity is (principal,
// network, key) as in host.md §8.

/// `gateway_capable` for capabilities.get: null while no authenticated
/// session says either way.
fn group_capability_json<S: OperationStore>(ctx: &ApiContext<'_, S>) -> String {
    let info = ctx.session.lock().expect("session poisoned");
    match (info.authenticated, info.capability) {
        (true, Some(capability)) => crate::group::group_capable(capability).to_string(),
        _ => "null".to_string(),
    }
}

/// `observation` for capabilities.get: which observation methods the
/// attached gateway can actually serve (false while detached — link.get
/// tells those apart), plus the static local bounds. `remote` is true
/// when the gateway forwards subtype-7 queries (the m1 diagnostics bit
/// — the remote leg's only requirement); `max_in_flight`/`api_wait_ms`
/// below are the local leg's bounds.
fn observation_capability_json<S: OperationStore>(ctx: &ApiContext<'_, S>) -> String {
    let info = ctx.session.lock().expect("session poisoned");
    let live = info.authenticated && info.id.is_some();
    let telemetry = live
        && info
            .capability
            .is_some_and(crate::telemetry::telemetry_capable);
    let observation = live
        && info
            .capability
            .is_some_and(crate::observation::observation_capable);
    let remote = live
        && info
            .capability
            .is_some_and(crate::telemetry::telemetry_capable);
    drop(info);
    format!(
        "{{\"telemetry\":{telemetry},\"topology\":{observation},\"health\":{observation},\"board\":false,\"remote\":{remote},\"limits\":{{\"routes_page_max\":{},\"neighbors_page_max\":{},\"max_in_flight\":{},\"max_age_ms_max\":{},\"api_wait_ms\":{}}},\"events\":[\"topology.changed\",\"milestone.advanced\",\"observation.gap\"]}}",
        routeloom_protocol::observation::PAGE_MAX,
        routeloom_protocol::observation::PAGE_MAX,
        crate::observation::MAX_IN_FLIGHT,
        crate::observation::MAX_AGE_LIMIT_MS,
        crate::observation::API_WAIT_MS,
    )
}

/// `wait_ms`: 0..=WAIT_MS_MAX (default 0 = answer immediately).
fn group_wait_ms(params: &Json) -> Result<u64, ApiError> {
    match params.get("wait_ms") {
        None => Ok(0),
        Some(value) => value
            .as_u64()
            .filter(|ms| *ms <= WAIT_MS_MAX)
            .ok_or_else(|| {
                ApiError::simple(
                    "INVALID_ARGUMENT",
                    &format!("wait_ms must be an integer 0..={WAIT_MS_MAX}"),
                )
            }),
    }
}

/// `group`: 1..=65535 as a number, or the string "ALL" (= 65535).
fn group_id_field(value: Option<&Json>) -> Result<u16, ApiError> {
    let invalid = || {
        ApiError::simple(
            "INVALID_ARGUMENT",
            "group must be an integer 1..=65535 or \"ALL\"",
        )
    };
    match value {
        Some(Json::String(name)) if name == "ALL" => Ok(routeloom_protocol::group_ops::GROUP_ALL),
        Some(json) => json
            .as_u64()
            .and_then(|n| u16::try_from(n).ok())
            .filter(|n| *n != 0)
            .ok_or_else(invalid),
        None => Err(invalid()),
    }
}

/// `options`: `{priority?, ordered?, ttl_ms?, hop_limit?}` with the
/// device's ranges (lifetime ≤ 30000 ms, hop_limit 1..=254).
fn group_options(value: Option<&Json>) -> Result<(u8, bool, u32, u8), ApiError> {
    use crate::group::{HOP_DEFAULT, HOP_MAX, HOP_MIN, TTL_DEFAULT_MS, TTL_MAX_MS, TTL_MIN_MS};
    let invalid = |m: String| ApiError::simple("INVALID_ARGUMENT", &m);
    let value = match value {
        None | Some(Json::Null) => {
            return Ok((
                canonical::PRIORITY_NORMAL,
                false,
                TTL_DEFAULT_MS,
                HOP_DEFAULT,
            ))
        }
        Some(value @ Json::Object(_)) => value,
        Some(_) => return Err(invalid("options must be an object".to_string())),
    };
    for (key, _) in value.object_entries() {
        if !matches!(
            key.as_str(),
            "priority" | "ordered" | "ttl_ms" | "hop_limit"
        ) {
            return Err(invalid(format!("unknown option \"{key}\"")));
        }
    }
    let priority = match value.get("priority") {
        None => canonical::PRIORITY_NORMAL,
        Some(Json::String(name)) => match name.as_str() {
            "BULK" => canonical::PRIORITY_BULK,
            "NORMAL" => canonical::PRIORITY_NORMAL,
            "MANAGEMENT" => canonical::PRIORITY_MANAGEMENT,
            "URGENT" => canonical::PRIORITY_URGENT,
            _ => return Err(invalid("unknown priority value".to_string())),
        },
        Some(_) => return Err(invalid("priority must be a string".to_string())),
    };
    let ordered = match value.get("ordered") {
        None => false,
        Some(Json::Bool(ordered)) => *ordered,
        Some(_) => return Err(invalid("ordered must be a boolean".to_string())),
    };
    let ttl_ms = match value.get("ttl_ms") {
        None => TTL_DEFAULT_MS,
        Some(number) => number
            .as_u64()
            .filter(|ms| (u64::from(TTL_MIN_MS)..=u64::from(TTL_MAX_MS)).contains(ms))
            .map(|ms| ms as u32)
            .ok_or_else(|| {
                invalid(format!(
                    "ttl_ms must be an integer {TTL_MIN_MS}..={TTL_MAX_MS}"
                ))
            })?,
    };
    let hop_limit = match value.get("hop_limit") {
        None => HOP_DEFAULT,
        Some(number) => number
            .as_u64()
            .filter(|hop| (u64::from(HOP_MIN)..=u64::from(HOP_MAX)).contains(hop))
            .map(|hop| hop as u8)
            .ok_or_else(|| {
                invalid(format!(
                    "hop_limit must be an integer {HOP_MIN}..={HOP_MAX}"
                ))
            })?,
    };
    Ok((priority, ordered, ttl_ms, hop_limit))
}

/// `payload_hex` + `payload_len` (must agree), ≤ 127 bytes (the group
/// payload is 128 B including the device's flags byte).
fn group_payload(params: &Json) -> Result<Vec<u8>, ApiError> {
    let invalid_hex =
        || ApiError::simple("INVALID_ARGUMENT", "payload_hex must be even-length hex");
    let Some(text) = params.get("payload_hex").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "payload_hex must be a string",
        ));
    };
    if text.len() % 2 != 0 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(invalid_hex());
    }
    let Some(declared) = params.get("payload_len").and_then(Json::as_u64) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "payload_len must be an integer",
        ));
    };
    if declared != (text.len() / 2) as u64 {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "payload_len does not match payload_hex bytes",
        ));
    }
    if text.len() / 2 > crate::group::PAYLOAD_MAX {
        return Err(ApiError::simple(
            "PAYLOAD_TOO_LARGE",
            &format!("group payload exceeds {} bytes", crate::group::PAYLOAD_MAX),
        ));
    }
    parse_hex_bytes(text, crate::group::PAYLOAD_MAX).ok_or_else(invalid_hex)
}

/// The live-gateway gates for a NEW group send (replays skip them).
fn group_gate<S: OperationStore>(ctx: &ApiContext<'_, S>, network: u64) -> Option<ApiError> {
    live_gateway_gate(
        ctx,
        GateScope {
            action: "group sends",
            network: Some(network),
            required_capability: "group_delivery_v1",
            capability_hint: "HelloAck capability bit 7 with host_ops_v1",
            capable: crate::group::group_capable,
        },
    )
    .err()
}

/// `group.send` params: `{network, group, key, payload_hex, payload_len,
/// options?:{priority, ordered, ttl_ms, hop_limit}, wait_ms?}`.
///
/// Order: SEND authorization → schema → idempotency (a known
/// key answers its record even while the gateway is away) → live-gateway
/// gates (GATEWAY_UNAVAILABLE / UNSUPPORTED without capability bit 7) →
/// admission (NO_CAPACITY). With `wait_ms` the answer waits until the
/// gateway accepted or refused the send (or the window ends).
fn group_send<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    use crate::group::{GroupOps, GroupRequest, SubmitError, SubmitOutcome};
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "network" | "group" | "key" | "payload_hex" | "payload_len" | "options" | "wait_ms"
        ) {
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
        .principal
        .as_ref()
        .filter(|uid| ctx.acl.permit_principal(uid, network, acl::PERM_SEND))
    else {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks SEND on this network",
        ));
    };
    let group = group_id_field(params.get("group"))?;
    let Some(key) = params
        .get("key")
        .and_then(Json::as_str)
        .and_then(|text| canonical::parse_key_hex(text).ok())
    else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "key must be a 32-hex string",
        ));
    };
    let payload = group_payload(params)?;
    let (priority, ordered, ttl_ms, hop_limit) = group_options(params.get("options"))?;
    let wait_ms = group_wait_ms(params)?;
    // Not charged to the messages.submit token bucket (2/min, burst 16):
    // an URGENT ALARM must never wait behind a burst of display updates.
    // Group work is bounded instead by the op table (QUEUE_CAP host-queued,
    // LIVE_CAP unsettled — NO_CAPACITY beyond), the gateway's 3-entry
    // source table (REFUSED/BUSY GROUP_QUEUE_FULL) and its own group
    // air-time bucket (group-delivery.md §7).
    let request = GroupRequest {
        network,
        group,
        priority,
        ordered,
        ttl_ms,
        hop_limit,
        payload,
    };
    // A replay must not depend on the gateway still being there: the gates
    // apply only to an identity the table has never seen.
    let known = ctx.group_ops.knows_principal(uid, network, &key);
    if !known {
        if let Some(error) = group_gate(ctx, network) {
            return Err(error);
        }
    }
    let op_id = match ctx.group_ops.submit_principal(uid, key, request, ctx.now_ms) {
        Ok(SubmitOutcome::Accepted(op_id) | SubmitOutcome::Replay(op_id)) => op_id,
        Err(SubmitError::Conflict { existing }) => {
            return Err(ApiError {
                code: "CONFLICT",
                message: "same idempotency key with a different group request".to_string(),
                extra_fields: format!(
                    "\"existing_group_op\":\"{}\"",
                    crate::group::op_token(existing)
                ),
                retryable: false,
            })
        }
        Err(SubmitError::WindowExpired) => {
            return Err(ApiError::simple(
                "IDEMPOTENCY_WINDOW_EXPIRED",
                "this key's group operation was evicted from the bounded table; its outcome is no longer held",
            ))
        }
        Err(SubmitError::NoCapacity { queued, live }) => {
            return Err(ApiError {
                code: "NO_CAPACITY",
                message: "group operation table is full; retry when in-flight group sends settle"
                    .to_string(),
                extra_fields: format!("\"queued\":{queued},\"unsettled\":{live}"),
                retryable: true,
            })
        }
    };
    let record = ctx
        .group_ops
        .wait_for(
            op_id,
            Duration::from_millis(wait_ms),
            GroupOps::admission_answered,
        )
        .ok_or_else(|| ApiError::simple("NOT_FOUND", "no group operation with that id"))?;
    Ok(crate::group::record_json(&record))
}

/// `group.get` params: `{group_op, wait_ms?}`. With `wait_ms` the answer
/// waits until the record is final (or the window ends).
fn group_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "group_op" | "wait_ms") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let Some(op_id) = params
        .get("group_op")
        .and_then(Json::as_str)
        .and_then(crate::group::parse_op_token)
    else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "group_op must be a grp-prefixed 16-hex token",
        ));
    };
    let wait_ms = group_wait_ms(params)?;
    let not_found = || ApiError::simple("NOT_FOUND", "no group operation with that id");
    let network = ctx
        .group_ops
        .get(op_id)
        .ok_or_else(not_found)?
        .request
        .network;
    if !ctx.principal.as_ref().is_some_and(|uid| {
        ctx.acl
            .permit_principal(uid, network, acl::PERM_READ_OPERATION)
    }) {
        return Err(not_found());
    }
    let record = ctx
        .group_ops
        .wait_for(
            op_id,
            Duration::from_millis(wait_ms),
            crate::group::GroupOps::settled,
        )
        .ok_or_else(not_found)?;
    Ok(crate::group::record_json(&record))
}

// --- lab.rollcall.* (RollcallService, design-devflow §6.4–6.5, D09) --------
//
// The service owns one run per daemon: `start` is idempotent for a matching
// request — a GUI reconnect or a racing scenario runner answers the live
// run's id instead of stacking a second loop (the acceptance's "GUI 切断で
// 二重 loop なし" property). `start`/`update`/`stop` command wire traffic,
// so they need SEND on the run's network; `status` needs READ_OPERATION.
// The run's actual polls still travel the group lane — they inherit its
// session/network/capability gates at write time.

/// The network the run operates on: the session's own network (a lab run
/// always calls its own site). `network` in params must match it.
fn rollcall_network<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<u64, ApiError> {
    let session_network = ctx.session.lock().expect("session poisoned").network;
    let Some(session_network) = session_network else {
        return Err(ApiError {
            code: "GATEWAY_UNAVAILABLE",
            message: "no authenticated gateway session; rollcall cannot start without a site"
                .to_string(),
            extra_fields: "\"reason\":\"no_session\"".to_string(),
            retryable: true,
        });
    };
    match params.get("network") {
        None => Ok(session_network),
        Some(Json::String(text)) => {
            let network = acl::parse_network_hex(text)
                .map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?;
            if network != session_network {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "network does not match the attached gateway's session",
                ));
            }
            Ok(network)
        }
        Some(_) => Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "network must be a 16-hex string",
        )),
    }
}

/// `desired_interval_ms` (meshviz §10.2): the operator's interval floor —
/// validated here, clamped to MIN_INTERVAL_MS at the service. The effective
/// interval is `max(desired, airtime budget)`, never the bare request.
fn desired_interval_ms(params: &Json) -> Result<Option<u64>, ApiError> {
    match params.get("desired_interval_ms") {
        None => Ok(None),
        Some(value) => {
            let ms = value.as_u64().ok_or_else(|| {
                ApiError::simple("INVALID_ARGUMENT", "desired_interval_ms must be an integer")
            })?;
            if !(crate::rollcall::MIN_INTERVAL_MS..=600_000).contains(&ms) {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "desired_interval_ms must be 2000..=600000",
                ));
            }
            Ok(Some(ms))
        }
    }
}

fn rollcall_start<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "network" | "group" | "desired_interval_ms") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let network = rollcall_network(params, ctx)?;
    let desired = desired_interval_ms(params)?.unwrap_or(crate::rollcall::MIN_INTERVAL_MS);
    let Some(uid) = ctx
        .principal
        .as_ref()
        .filter(|p| ctx.acl.permit_principal(p, network, acl::PERM_SEND))
    else {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks SEND on this network",
        ));
    };
    let group = match params.get("group") {
        None => crate::rollcall::DEFAULT_GROUP,
        Some(value) => group_id_field(Some(value))?,
    };
    // The run's polls ride the group lane — refuse up front when the
    // session could never write them (capability bit 7 + host_ops).
    if let Some(error) = group_gate(ctx, network) {
        return Err(error);
    }
    match ctx.rollcall.start(uid.clone(), network, group, desired, ctx.now_ms) {
        Ok(run_uuid) => Ok(format!(
            "{{\"running\":true,\"state\":\"running\",\"run_id\":\"{}\",\"run_uuid\":\"{}\",\"group\":{},\"network\":\"{network:016x}\",\"desired_interval_ms\":{desired}}}",
            crate::rollcall::RunUuid(run_uuid),
            crate::rollcall::RunUuid(run_uuid),
            group,
        )),
        Err(message) => Err(ApiError {
            code: "CONFLICT",
            message: message.to_string(),
            extra_fields: String::new(),
            retryable: false,
        }),
    }
}

fn rollcall_update<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(
            key.as_str(),
            "run_uuid" | "run_id" | "group" | "desired_interval_ms"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    // `run_id` is the contract alias for the service's `run_uuid`.
    let run_id = params
        .get("run_uuid")
        .or_else(|| params.get("run_id"))
        .and_then(Json::as_str)
        .and_then(crate::rollcall::parse_run_uuid);
    let Some(run_uuid) = run_id else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "run_uuid must be the 32-hex id lab.rollcall.start returned",
        ));
    };
    let group = match params.get("group") {
        None => None,
        Some(value) => Some(group_id_field(Some(value))?),
    };
    let desired = desired_interval_ms(params)?;
    let network = ctx.session.lock().expect("session poisoned").network;
    let Some(network) = network else {
        return Err(ApiError::simple(
            "GATEWAY_UNAVAILABLE",
            "no authenticated gateway session",
        ));
    };
    let Some(uid) = ctx
        .principal
        .as_ref()
        .filter(|p| ctx.acl.permit_principal(p, network, acl::PERM_SEND))
    else {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks SEND on this network",
        ));
    };
    ctx.rollcall
        .update(uid, &run_uuid, group, desired)
        .map_err(|message| ApiError {
            code: "CONFLICT",
            message: message.to_string(),
            extra_fields: String::new(),
            retryable: false,
        })?;
    Ok(format!(
        "{{\"running\":true,\"state\":\"running\",\"run_id\":\"{}\",\"run_uuid\":\"{}\"}}",
        crate::rollcall::RunUuid(run_uuid),
        crate::rollcall::RunUuid(run_uuid),
    ))
}

fn rollcall_stop<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "run_uuid" | "run_id") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let network = ctx.session.lock().expect("session poisoned").network;
    let Some(network) = network else {
        return Err(ApiError::simple(
            "GATEWAY_UNAVAILABLE",
            "no authenticated gateway session",
        ));
    };
    if !ctx
        .principal
        .as_ref()
        .is_some_and(|p| ctx.acl.permit_principal(p, network, acl::PERM_SEND))
    {
        return Err(ApiError::simple(
            "AuthorizationFailed",
            "principal lacks SEND on this network",
        ));
    }
    let run_id = params
        .get("run_uuid")
        .or_else(|| params.get("run_id"))
        .and_then(Json::as_str)
        .and_then(crate::rollcall::parse_run_uuid);
    let stopped = if params.get("run_uuid").is_none() && params.get("run_id").is_none() {
        ctx.rollcall.stop()
    } else {
        match run_id {
            Some(uuid) => ctx.rollcall.stop_if(&uuid),
            None => {
                return Err(ApiError::simple(
                    "INVALID_ARGUMENT",
                    "run_uuid must be the 32-hex id lab.rollcall.start returned",
                ))
            }
        }
    };
    Ok(format!("{{\"stopped\":{stopped}}}"))
}

fn rollcall_status<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    if !params.object_entries().is_empty() {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "lab.rollcall.status takes no params",
        ));
    }
    // READ_OPERATION on the run's network — a principal without it gets
    // the same answer as "no run" (no existence oracle, matching group.get).
    let run_network = ctx.rollcall.run_network();
    let authorized = run_network.is_some_and(|network| {
        ctx.principal.as_ref().is_some_and(|p| {
            ctx.acl
                .permit_principal(p, network, acl::PERM_READ_OPERATION)
        })
    });
    if !authorized {
        return Err(ApiError::simple(
            "NOT_FOUND",
            "no rollcall run visible to this principal",
        ));
    }
    // The contract view (meshviz §10.2) composes what the run cannot own:
    // live roster, site member kid/milestones, lab inventory size. A status
    // read may outlive the site authority — absent pieces stay honest nulls
    // rather than failing the whole read.
    let roster_now = {
        let table = ctx.node_table.lock().expect("node table poisoned");
        let (records, _) = table.list(0, usize::MAX, Some(true));
        records.len() as u64
    };
    let (members, inventory_planned) = ctx.site.map_or_else(
        || (Vec::new(), None),
        |service| {
            service
                .with(|authority| {
                    let members = authority
                        .member_briefs()
                        .into_iter()
                        .map(|(node, kid, approved_ms, confirmed_ms)| {
                            crate::rollcall::MemberBrief {
                                node,
                                kid,
                                approved_ms,
                                confirmed_ms,
                            }
                        })
                        .collect();
                    (members, authority.lab_inventory_planned())
                })
                .0
        },
    );
    Ok(ctx.rollcall.status_json(&crate::rollcall::StatusView {
        now_ms: ctx.now_ms,
        roster_now,
        inventory_planned,
        members,
    }))
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
    // Site Authority operations (`op-` tokens) live in the site ledger.
    if let Some(answer) = site::operation_get(text, ctx) {
        return answer;
    }
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
    if !ctx.principal.as_ref().is_some_and(|uid| {
        ctx.acl
            .permit_principal(uid, record.network, acl::PERM_READ_OPERATION)
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
    let Some(uid) = ctx.principal.as_ref().filter(|uid| {
        ctx.acl
            .permit_principal(uid, network, acl::PERM_READ_OPERATION)
    }) else {
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
        principal: uid.clone(),
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
    let owns = ctx.principal.as_ref().is_some_and(|uid| {
        uid == &record.principal
            && ctx
                .acl
                .permit_principal(uid, record.network, acl::PERM_SEND)
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

/// `config_op` accepts exactly the canonical token `config_op_token`
/// mints: `cfg` + 16 lowercase hex digits. Bare hex, short forms and any
/// other spelling are rejected, never trimmed into a valid id.
fn parse_config_op(text: &str) -> Option<u64> {
    let hex = text.strip_prefix("cfg")?;
    if hex.len() != 16
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    u64::from_str_radix(hex, 16).ok().filter(|&v| v != 0)
}

/// A u16 field accepts a JSON number or a string. String parsing follows
/// routeloomctl's rule exactly: only an explicit `0x`/`0X` prefix means
/// hexadecimal — an unprefixed "10" is decimal 10, never 16.
fn u16_field(value: Option<&Json>, name: &str) -> Result<u16, ApiError> {
    let invalid = || {
        ApiError::simple(
            "INVALID_ARGUMENT",
            &format!("{name} must be a u16 (number, decimal, or 0x-hex string)"),
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
                return match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    Some(hex) => u16::from_str_radix(hex, 16).map_err(|_| invalid()),
                    None => text.parse::<u16>().map_err(|_| invalid()),
                };
            }
            Err(invalid())
        }
    }
}

/// A u32 field — same number-or-string parsing rule as `u16_field`.
fn u32_field(value: Option<&Json>, name: &str) -> Result<u32, ApiError> {
    let invalid = || {
        ApiError::simple(
            "INVALID_ARGUMENT",
            &format!("{name} must be a u32 (number, decimal, or 0x-hex string)"),
        )
    };
    match value {
        None => Err(ApiError::simple(
            "INVALID_ARGUMENT",
            &format!("{name} is required"),
        )),
        Some(json) => {
            if let Some(n) = json.as_u64() {
                return u32::try_from(n).map_err(|_| invalid());
            }
            if let Some(text) = json.as_str() {
                return match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
                    Some(hex) => u32::from_str_radix(hex, 16).map_err(|_| invalid()),
                    None => text.parse::<u32>().map_err(|_| invalid()),
                };
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
    ctx.principal
        .as_ref()
        .is_some_and(|uid| ctx.acl.permit_principal(uid, network, acl::PERM_CONFIG))
}

fn config_denied() -> ApiError {
    ApiError::simple(
        "AuthorizationFailed",
        "principal lacks CONFIG on this network",
    )
}

/// `config_namespace` must name a registered namespace — SDK `1` or an
/// application `0x8000..=0xFFFE`. The endpoint codecs refuse anything
/// else, so the API refuses it at admission with INVALID_ARGUMENT rather
/// than queueing a request the wire cannot carry.
fn config_ns_field(value: Option<&Json>) -> Result<u16, ApiError> {
    let ns = u16_field(value, "config_namespace")?;
    if !config_namespace_valid(ns) {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "config_namespace must be 1 (SDK) or 0x8000-0xfffe (application)",
        ));
    }
    Ok(ns)
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
    let config_namespace = config_ns_field(params.get("config_namespace"))?;
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
    config_status_or_retry(params, ctx, false)
}

/// `config.retry` resends only the signed original held in the authority
/// outbox under the device operation id. It spends no new sequence.
fn config_retry<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    config_status_or_retry(params, ctx, true)
}

fn config_status_or_retry<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
    retry: bool,
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
    let config_namespace = config_ns_field(params.get("config_namespace"))?;
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
    if retry && ctx.config_authority.is_none() {
        return Err(ApiError::simple(
            "CONFIG_NO_AUTHORITY",
            "no config authority configured; saved-original retry is unavailable",
        ));
    }
    let request = if retry {
        ConfigRequest::Retry {
            target,
            config_namespace,
            operation_id,
        }
    } else {
        ConfigRequest::Status {
            target,
            config_namespace,
            operation_id,
        }
    };
    config_submit_op(
        ctx,
        request,
        format!(
            "{} ns={config_namespace} op={op_text}",
            if retry { "retry" } else { "status" }
        ),
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
    let config_namespace = config_ns_field(params.get("config_namespace"))?;
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

/// `config.recover` params: `{network, target, config_namespace, schema,
/// mode, new_store_generation, new_revision, snapshot_hash?, baseline?}`.
/// Signs an RCR2 recovery intent against the operator-read RecoveryInfo
/// baseline and delivers it on the kind-4 lane, then reads the terminal
/// status. `mode` is `adopt-known` (bind the proven survivor by
/// `snapshot_hash`, no `baseline`) or `reprovision` (carry the complete
/// `baseline` TLV to re-apply). (`new_store_generation`, `new_revision`)
/// must name the floor's exact next — read the current floors from
/// `config.recovery_info` first and add one to each; a skewed pair is
/// refused by the target, never coerced. Requires a configured
/// authority AND PERM_CONFIG.
fn config_recover<S: OperationStore>(
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
                | "mode"
                | "new_store_generation"
                | "new_revision"
                | "snapshot_hash"
                | "baseline"
        ) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let (network, target) = config_target_params(params)?;
    let config_namespace = config_ns_field(params.get("config_namespace"))?;
    let schema = u16_field(params.get("schema"), "schema")?;
    let mode = match params.get("mode").and_then(Json::as_str) {
        Some("adopt-known") => 0,
        Some("reprovision") => 1,
        _ => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "mode must be \"adopt-known\" or \"reprovision\"",
            ));
        }
    };
    let new_store_generation =
        u32_field(params.get("new_store_generation"), "new_store_generation")?;
    let new_revision = match params.get("new_revision").and_then(Json::as_u64) {
        Some(revision) => revision,
        None => {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                "new_revision must be a u64",
            ));
        }
    };
    let snapshot_hash = match params.get("snapshot_hash").and_then(Json::as_str) {
        Some(text) => parse_hex_32(text).ok_or_else(|| {
            ApiError::simple("INVALID_ARGUMENT", "snapshot_hash must be a 64-hex string")
        })?,
        None => [0; 32],
    };
    let baseline = match params.get("baseline").and_then(Json::as_str) {
        Some(text) => parse_hex_bytes(text, 512).ok_or_else(|| {
            ApiError::simple(
                "INVALID_ARGUMENT",
                "baseline must be hex, at most 512 bytes",
            )
        })?,
        None => Vec::new(),
    };
    if mode == 0 && !baseline.is_empty() {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "adopt-known carries no baseline (the survivor is bound by hash)",
        ));
    }
    if mode == 0 && snapshot_hash == [0; 32] {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "adopt-known needs the proven survivor snapshot_hash",
        ));
    }
    if !config_permit(ctx, network) {
        return Err(config_denied());
    }
    if ctx.config_authority.is_none() {
        return Err(ApiError::simple(
            "CONFIG_NO_AUTHORITY",
            "no config authority configured (daemon --config-authority); recovery cannot be issued",
        ));
    }
    let request = ConfigRequest::Recover {
        target,
        config_namespace,
        schema,
        mode,
        new_store_generation,
        new_revision,
        snapshot_hash,
        baseline,
    };
    config_submit_op(
        ctx,
        request,
        format!("recover ns={config_namespace} mode={mode} store_gen={new_store_generation} rev={new_revision}"),
        network,
        target,
    )
}

/// `config.recovery_info` params: `{network, target, config_namespace}`.
/// Reads the target's RecoveryInfo — the floor readings and the
/// survivor/testimony hashes the operator's RCR2 baseline binds. Needs
/// PERM_CONFIG; needs no authority (a pure query).
fn config_recovery_info<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "network" | "target" | "config_namespace") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let (network, target) = config_target_params(params)?;
    let config_namespace = config_ns_field(params.get("config_namespace"))?;
    if !config_permit(ctx, network) {
        return Err(config_denied());
    }
    config_submit_op(
        ctx,
        ConfigRequest::RecoveryInfo {
            target,
            network,
            config_namespace,
        },
        format!("recovery_info ns={config_namespace}"),
        network,
        target,
    )
}

/// `trust.install` params: `{network, target, manifest}`. Delivers an
/// offline-signed trust manifest (RTM1, hex ≤ 2048 B) on the kind-5 lane
/// and reads back the target's TrustStatus as the install receipt.
/// Deliberately independent of the config authority (§6.3): a rotation
/// must work while the authority is being rebuilt. Needs PERM_CONFIG.
/// The envelope shape is checked at admission; the target's TrustView
/// verifies the root signature.
fn trust_install<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "network" | "target" | "manifest") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let (network, target) = config_target_params(params)?;
    let Some(manifest_text) = params.get("manifest").and_then(Json::as_str) else {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "manifest must be a hex string",
        ));
    };
    let manifest = parse_hex_bytes(manifest_text, 2048).ok_or_else(|| {
        ApiError::simple(
            "INVALID_ARGUMENT",
            "manifest must be hex, at most 2048 bytes",
        )
    })?;
    if routeloom_provision::manifest::manifest_parse(&manifest).is_err() {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "manifest is not a restricted COSE_Sign1 trust envelope",
        ));
    }
    if !config_permit(ctx, network) {
        return Err(config_denied());
    }
    config_submit_op(
        ctx,
        ConfigRequest::TrustInstall {
            target,
            network,
            manifest,
        },
        "trust_install".to_string(),
        network,
        target,
    )
}

/// `trust.status` params: `{network, target}`. Reads the target's
/// TrustStatus — the install receipt and the generation/image evidence
/// for a rotation. Needs PERM_CONFIG; needs no authority.
fn trust_status<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    for (key, _) in params.object_entries() {
        if !matches!(key.as_str(), "network" | "target") {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    let (network, target) = config_target_params(params)?;
    if !config_permit(ctx, network) {
        return Err(config_denied());
    }
    config_submit_op(
        ctx,
        ConfigRequest::TrustStatus { target, network },
        "trust_status".to_string(),
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
    if !ctx.principal.as_ref().is_some_and(|uid| {
        ctx.acl
            .permit_principal(uid, record.network, acl::PERM_CONFIG)
    }) {
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
    // Reserved wire addresses (0 and u64::MAX) are not config targets —
    // same rule canonical::parse_node_hex applies to messages.submit and
    // gateway.resolve.
    let target = canonical::parse_node_hex(target_text)
        .map_err(|e| ApiError::simple("INVALID_ARGUMENT", &e))?;
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
    // The admission check IS the wire check: the same validator
    // `config_command_encode` runs — exact type/value lengths (bool/u8
    // = 1B, u32 = 4B), bool values 0|1, strictly ascending ids and the
    // 512-byte patch total — so a patch the wire cannot carry is refused
    // here with INVALID_ARGUMENT, never queued to fail downstream.
    if let Err(error) = config_tlv_encode(&fields) {
        return Err(invalid(error.detail));
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

/// The issuance profile name `capabilities.get` reports: the profile the
/// daemon's lane signs under — never a fixed string.
fn config_profile_name(profile: u8) -> &'static str {
    if profile == crate::config::ISSUE_PROFILE_COSE {
        "rlcp1-cose-esp256"
    } else {
        "dev-hmac-sha256-16"
    }
}

/// The device operation_id an outcome carries, rendered for `config.get`:
/// on outcomes where the device-side operation may still be unresolved
/// (permit assembled, indeterminate transfer) the caller needs the id to
/// issue `config.status` against it. RAM-only records keep it only while
/// the record lives — a daemon restart forgets both.
fn operation_id_detail(operation_id: Option<[u8; 16]>) -> String {
    operation_id.map_or_else(String::new, |id| {
        format!(",\"operation_id\":\"{}\"", hex_lower(&id))
    })
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
                ConfigOutcome::TrustStatus(s) => (
                    "TRUST_STATUS",
                    format!(
                        ",\"trust_status\":{{\"store_epoch\":{},\"min_authority_generation\":{},\"network\":\"{:016x}\",\"image_fingerprint\":\"{}\",\"anchor_count\":{},\"key_count\":{},\"revocation_count\":{},\"flags\":{}}}",
                        s.store_epoch,
                        s.min_authority_generation,
                        s.network,
                        hex_lower(&s.image_fingerprint),
                        s.anchor_count,
                        s.key_count,
                        s.revocation_count,
                        s.flags
                    ),
                ),
                ConfigOutcome::RecoveryInfo(i) => (
                    "RECOVERY_INFO",
                    format!(
                        ",\"recovery_info\":{{\"config_namespace\":{},\"schema\":{},\"network\":\"{:016x}\",\"store_floor\":{},\"decision_floor\":{},\"flags\":{},\"recovery_version\":{},\"profile_bits\":{},\"snapshot_hash\":\"{}\"}}",
                        i.config_namespace,
                        i.schema,
                        i.network,
                        i.store_floor,
                        i.decision_floor,
                        i.flags,
                        i.recovery_version,
                        i.profile_bits,
                        hex_lower(&i.snapshot_hash)
                    ),
                ),
                ConfigOutcome::PermitAssembled(op) => {
                    ("PERMIT_ASSEMBLED", operation_id_detail(*op))
                }
                ConfigOutcome::NoChange => ("NO_CHANGE", String::new()),
                ConfigOutcome::Refused(r) => (
                    "REFUSED",
                    format!(",\"result\":\"{}\"", config_ops_result_name(*r)),
                ),
                ConfigOutcome::RefusedStale => ("REFUSED", ",\"result\":\"STALE\"".to_string()),
                ConfigOutcome::RefusedProfile => {
                    ("REFUSED", ",\"result\":\"PROFILE_UNAVAILABLE\"".to_string())
                }
                ConfigOutcome::Timeout => ("TIMEOUT", String::new()),
                ConfigOutcome::Indeterminate(op) => {
                    ("INDETERMINATE", operation_id_detail(*op))
                }
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
    let mut device_outcome = "null".to_string();
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
        // Device-attested terminal detail (reason-carrying DeliveryEvent):
        // names the failure cause without touching terminality — the
        // window-derived `dispatch_state` stays authoritative.
        if let Some(state) = &att.device_state {
            let reason = att.device_reason.as_deref().map_or_else(
                || "null".to_string(),
                |r| format!("\"{}\"", crate::json_escape(r)),
            );
            device_outcome = format!(
                "{{\"state\":\"{}\",\"reason\":{reason}}}",
                crate::json_escape(state)
            );
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
    // A superseded record carries the replacing seq as an operation id —
    // provenance, so the cancel reads as the control profile's retire
    // rather than an operator request.
    let superseded_by = record
        .superseded_by
        .map(|seq| format!("\"{}\"", canonical::format_operation_id(lineage, seq)))
        .unwrap_or_else(|| "null".to_string());
    format!(
        "{{\"operation_id\":\"{}\",\"network\":\"{:016x}\",\"admission_epoch\":\"{:016x}\",\"key\":\"{}\",\"destination\":{destination_json},\"payload_len\":{},\"canonical_hash\":\"{}\",\"options\":{{\"delivery\":\"{}\",\"priority\":\"{}\",\"ttl_ms\":{},\"deadline_policy\":\"WALL_ELAPSED_VALIDITY\",\"storage\":\"{}\",\"hop_limit\":{},\"persist_across_sleep\":false,\"queue_mode\":\"{}\"}},\"dispatch_state\":\"{}\",\"evidence\":[{evidence_json}],\"message_key\":{message_key},\"device_outcome\":{device_outcome},\"application_outcome\":null,\"observation\":{{\"deadline_elapsed\":{elapsed},\"cancel_requested\":{cancel_requested},\"superseded_by\":{superseded_by},\"time_uncertain\":{time_uncertain}}}}}",
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
        canonical::queue_mode_name(record.queue_mode),
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
            "{\"principals\":{\"501\":{\"networks\":{\"0000000000000001\":[\"SEND\",\"READ_OPERATION\",\"OBSERVE\"]}},\"7\":{\"networks\":{\"0000000000000002\":[\"SEND\",\"READ_OPERATION\"]}}}}",
        )
        .unwrap()
    }

    fn private_test_db(name: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("routeloom-api1-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        routeloom_peercred::create_private_dir_all(&dir).unwrap();
        dir.join("ops.db")
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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

    fn leaked_group_ops() -> &'static crate::group::GroupOps {
        Box::leak(Box::new(crate::group::GroupOps::default()))
    }

    fn leaked_rollcall() -> &'static crate::rollcall::RollcallService {
        Box::leak(Box::new(crate::rollcall::RollcallService::default()))
    }

    fn leaked_telemetry_ops() -> &'static crate::telemetry::TelemetryOps {
        Box::leak(Box::new(crate::telemetry::TelemetryOps::default()))
    }

    fn leaked_observation_ops() -> &'static crate::observation::ObservationOps {
        Box::leak(Box::new(crate::observation::ObservationOps::default()))
    }

    fn leaked_remote_observation_ops() -> &'static crate::remote_observation::RemoteObservationOps {
        Box::leak(Box::new(
            crate::remote_observation::RemoteObservationOps::default(),
        ))
    }

    fn leaked_hub() -> &'static SubscriptionHub {
        Box::leak(Box::new(SubscriptionHub::default()))
    }

    fn leaked_event_ring() -> EventRing<'static> {
        EventRing {
            events: Box::leak(Box::new(Mutex::new(VecDeque::new()))),
            next_seq: Box::leak(Box::new(AtomicU64::new(0))),
            dropped: Box::leak(Box::new(AtomicU64::new(0))),
        }
    }

    static EMPTY_NODE_TABLE: Mutex<crate::nodes::NodeTable> =
        Mutex::new(crate::nodes::NodeTable::empty());

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
        subscriptions: &'a SubscriptionHub,
        conn_id: u64,
        event_ring: EventRing<'a>,
        now: u64,
    ) -> ApiContext<'a, S> {
        ApiContext {
            principal: uid.map(routeloom_peercred::Principal::UnixUid),
            acl,
            receive_log: log,
            operation_store: store,
            rate_limiter: limiter,
            session,
            gateway_lane: lane,
            node_table: &EMPTY_NODE_TABLE,
            config_ops,
            group_ops: leaked_group_ops(),
            rollcall: leaked_rollcall(),
            telemetry_ops: leaked_telemetry_ops(),
            observation_ops: leaked_observation_ops(),
            remote_observation_ops: leaked_remote_observation_ops(),
            site: None,
            config_authority,
            config_profile: crate::config::ISSUE_PROFILE_DEV,
            subscriptions,
            conn_id,
            event_ring,
            link: LinkStatus::default(),
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
                assurance: None,
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
        assert!(response.contains("\"nodes.list\":true"));
        assert!(response.contains("\"nodes.get\":true"));
        assert!(response.contains(
            "\"events\":[\"node_joined\",\"node_left\",\"link_changed\"],\"clock\":\"host_unix_ms\""
        ));
        // The config/trust verbs are registered and the profile reflects
        // the daemon's selected issuance profile (dev here).
        assert!(response.contains("\"config.propose\":true"));
        assert!(response.contains("\"config.retry\":true"));
        assert!(response.contains("\"config.recover\":true"));
        assert!(response.contains("\"config.recovery_info\":true"));
        assert!(response.contains("\"trust.install\":true"));
        assert!(response.contains("\"trust.status\":true"));
        assert!(response.contains("\"permit_profile\":\"dev-hmac-sha256-16\""));
    }

    #[test]
    fn capabilities_reports_version_and_keeps_known_keys() {
        // Clients key their parsing off caps_version and ignore unknown
        // fields — never an exact document match. This golden pins the
        // baseline keys: additions are welcome, removals are a break.
        let acl = Acl::empty();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"c1\",\"method\":\"capabilities.get\"}",
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").expect("ok result");
        assert_eq!(
            result.get("caps_version").and_then(Json::as_u64),
            Some(1),
            "{response}"
        );
        let keys: Vec<&str> = result
            .object_entries()
            .iter()
            .map(|(key, _)| key.as_str())
            .collect();
        for key in [
            "api",
            "methods",
            "receive",
            "send",
            "config",
            "nodes",
            "group",
            "site",
            "rx_events_v1",
            "ingress_loss_observable",
            "acl_revision",
            "peer_credential_resolved",
            "caps_version",
        ] {
            assert!(keys.contains(&key), "capabilities dropped {key}: {keys:?}");
        }
    }

    /// nodes.list / nodes.get JSON shapes against a populated node table:
    /// source block, ascending pagination with `next_after`, the connected
    /// filter, NOT_FOUND for unreported nodes and param validation.
    #[test]
    fn nodes_list_and_get_shapes() {
        use crate::nodes::{NodeTable, Origin};
        use routeloom_protocol::node_status::{
            NodeStatusEntry, FLAG_DIRECT, FLAG_HEARD_VALID, FLAG_NEIGHBOR, FLAG_NEIGHBOR_ACTIVE,
            FLAG_REACHABLE, FLAG_RSSI_VALID, INFINITE_METRIC,
        };
        let acl = Acl::empty();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let table = Mutex::new(NodeTable::default());
        {
            let mut t = table.lock().unwrap();
            t.attach(0x0abc, 77, true, 1_000);
            let sweep = t.begin_sweep();
            for node in 1..=5_u64 {
                let reachable = node != 4;
                let entry = NodeStatusEntry {
                    node,
                    flags: FLAG_NEIGHBOR
                        | FLAG_NEIGHBOR_ACTIVE
                        | FLAG_RSSI_VALID
                        | FLAG_HEARD_VALID
                        | if reachable {
                            FLAG_REACHABLE | FLAG_DIRECT
                        } else {
                            0
                        },
                    rssi_last_dbm: -50 - node as i8,
                    rssi_ewma_q8_8: -55 * 256,
                    link_cost: 1,
                    route_metric: if reachable { 1 } else { INFINITE_METRIC },
                    next_hop: if reachable { node } else { 0 },
                    heard_age_ms: 100,
                };
                t.apply(&entry, Origin::Sync, Some(sweep), 2_000);
            }
            t.finish_sweep(sweep, 2_000);
        }
        let base = ctx(None, &acl, &log, &store, &limiter, 5_000);
        let c = ApiContext {
            node_table: &table,
            ..base
        };
        // No ACL grant is needed (diagnostics class, like link.get).
        let response = handle(
            b"{\"v\":1,\"request_id\":\"n1\",\"method\":\"nodes.list\",\"params\":{\"limit\":3}}",
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").expect("ok result");
        let source = result.get("source").unwrap();
        assert_eq!(source.get("state").and_then(Json::as_str), Some("live"));
        assert_eq!(
            source.get("gateway").and_then(Json::as_str),
            Some("0000000000000abc")
        );
        assert_eq!(source.get("synced_ms").and_then(Json::as_u64), Some(2_000));
        assert_eq!(
            source.get("clock").and_then(Json::as_str),
            Some("host_unix_ms")
        );
        let nodes = result.get("nodes").and_then(Json::as_array).unwrap();
        let ids: Vec<&str> = nodes
            .iter()
            .map(|n| n.get("node").and_then(Json::as_str).unwrap())
            .collect();
        assert_eq!(
            ids,
            ["0000000000000001", "0000000000000002", "0000000000000003"]
        );
        let first = &nodes[0];
        assert_eq!(first.get("connected").and_then(Json::as_bool), Some(true));
        assert_eq!(first.get("hops").and_then(Json::as_u64), Some(1));
        assert_eq!(first.get("rssi_dbm").and_then(Json::as_i64), Some(-51));
        assert_eq!(first.get("link_cost").and_then(Json::as_u64), Some(1));
        assert_eq!(
            first.get("last_heard_ms").and_then(Json::as_u64),
            Some(1_900)
        );
        assert_eq!(
            first.get("heard_age_ms").and_then(Json::as_u64),
            Some(3_100)
        );
        assert_eq!(
            result.get("next_after").and_then(Json::as_str),
            Some("0000000000000003")
        );
        // Second page from the cursor completes the listing (gateway 0xabc
        // is listed too, as role "gateway").
        let response = handle(
            b"{\"v\":1,\"request_id\":\"n2\",\"method\":\"nodes.list\",\"params\":{\"after\":\"0000000000000003\"}}",
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").unwrap();
        let nodes = result.get("nodes").and_then(Json::as_array).unwrap();
        assert_eq!(nodes.len(), 3);
        assert!(result.get("next_after").unwrap().is_null());
        assert_eq!(nodes[2].get("role").and_then(Json::as_str), Some("gateway"));
        // connected:false filter isolates the unreachable node.
        let response = handle(
            b"{\"v\":1,\"request_id\":\"n3\",\"method\":\"nodes.list\",\"params\":{\"connected\":false}}",
            &c,
        );
        assert!(
            response.contains("\"node\":\"0000000000000004\""),
            "{response}"
        );
        assert!(!response.contains("\"node\":\"0000000000000001\""));
        assert!(response.contains("\"hops\":null"));
        // nodes.get: found / NOT_FOUND / bad params.
        let response = handle(
            b"{\"v\":1,\"request_id\":\"g1\",\"method\":\"nodes.get\",\"params\":{\"node\":\"0000000000000002\"}}",
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        let node = parsed.get("result").and_then(|r| r.get("node")).unwrap();
        assert_eq!(
            node.get("next_hop").and_then(Json::as_str),
            Some("0000000000000002")
        );
        let response = handle(
            b"{\"v\":1,\"request_id\":\"g2\",\"method\":\"nodes.get\",\"params\":{\"node\":\"0000000000000099\"}}",
            &c,
        );
        assert!(response.contains("\"code\":\"NOT_FOUND\""), "{response}");
        assert!(response.contains("\"state\":\"live\""));
        for bad in [
            "{\"v\":1,\"request_id\":\"b1\",\"method\":\"nodes.get\",\"params\":{\"node\":\"2\"}}",
            "{\"v\":1,\"request_id\":\"b2\",\"method\":\"nodes.get\",\"params\":{\"node\":\"0000000000000002\",\"x\":1}}",
            "{\"v\":1,\"request_id\":\"b3\",\"method\":\"nodes.list\",\"params\":{\"limit\":0}}",
            "{\"v\":1,\"request_id\":\"b4\",\"method\":\"nodes.list\",\"params\":{\"limit\":129}}",
            "{\"v\":1,\"request_id\":\"b5\",\"method\":\"nodes.list\",\"params\":{\"connected\":\"yes\"}}",
            "{\"v\":1,\"request_id\":\"b6\",\"method\":\"nodes.list\",\"params\":{\"after\":\"xyz\"}}",
        ] {
            assert!(
                handle(bad.as_bytes(), &c).contains("INVALID_ARGUMENT"),
                "{bad}"
            );
        }
        // An empty table (no session yet) is an honest empty listing.
        let empty = ctx(None, &acl, &log, &store, &limiter, 5_000);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"e\",\"method\":\"nodes.list\"}",
            &empty,
        );
        assert!(response.contains("\"state\":\"unavailable\""), "{response}");
        assert!(response.contains("\"nodes\":[]"));
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
    fn messages_read_and_metadata_report_unknown_assurance() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        log.lock().unwrap().ingest(
            Ingress {
                network: 1,
                gateway: Some(2),
                origin: 3,
                msg_session: 5,
                msg_seq: 1,
                payload: vec![1],
                assurance: None,
            },
            100,
        );
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 200);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(
            response.contains("\"profile\":\"UNKNOWN\",\"origin\":\"unverified\""),
            "{response}"
        );
        // The metadata-only sibling renders the same assurance.
        let record = RxRecord {
            seq: 9,
            network: 1,
            gateway: Some(2),
            origin: 3,
            msg_session: 5,
            msg_seq: 2,
            payload: vec![2],
            stored_ms: 100,
            assurance: None,
        };
        assert!(
            record_meta_json(&record, "cursor")
                .contains("\"assurance\":{\"profile\":\"UNKNOWN\",\"origin\":\"unverified\"}"),
            "{}",
            record_meta_json(&record, "cursor")
        );
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
    fn operations_get_reports_device_outcome() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 1000);
        let key = "00112233445566778899aabbccddeeff";
        let accepted = handle(submit_line(key, &epoch).as_bytes(), &c);
        let id = result_field(&accepted, "operation_id");
        // No device outcome yet: null, and terminality untouched.
        let before = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"g\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(before.contains("\"device_outcome\":null"), "{before}");
        // The dispatch lane binds the key; the DeliveryEvent pump
        // attaches the device-attested failure detail.
        {
            let mut store = store.lock().unwrap();
            let seq = 1;
            match store.prepare_dispatch(seq, [7; 16], [8; 16]) {
                Ok(crate::send_store::PrepareOutcome::Prepared(_)) => {}
                _ => panic!("expected prepare"),
            }
            store
                .update_operation(seq, &mut |op| {
                    let d = op.dispatch.as_mut().unwrap();
                    d.msg_session = Some(5);
                    d.msg_seq = Some(900);
                    true
                })
                .unwrap();
            let mut operation_id = [8_u8; 24];
            operation_id[16..].copy_from_slice(&seq.to_be_bytes());
            assert!(store
                .attach_device_outcome(&operation_id, 5, 900, "failed", Some("NO_ROUTE"))
                .unwrap());
        }
        let after = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"g\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(
            after.contains("\"device_outcome\":{\"state\":\"failed\",\"reason\":\"NO_ROUTE\"}"),
            "{after}"
        );
        // Two different failure causes stay distinguishable on the API.
        {
            let mut store = store.lock().unwrap();
            let mut operation_id = [8_u8; 24];
            operation_id[16..].copy_from_slice(&1_u64.to_be_bytes());
            store
                .attach_device_outcome(
                    &operation_id,
                    5,
                    900,
                    "indeterminate",
                    Some("END_RECEIPT_TIMEOUT"),
                )
                .unwrap();
        }
        let later = handle(
            format!(
                "{{\"v\":1,\"request_id\":\"g\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
            )
            .as_bytes(),
            &c,
        );
        assert!(
            later.contains(
                "\"device_outcome\":{\"state\":\"indeterminate\",\"reason\":\"END_RECEIPT_TIMEOUT\"}"
            ),
            "{later}"
        );
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
        let path = private_test_db("restart");
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
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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
        let path = private_test_db("fault");
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
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
    fn gateway_submit_denied_before_registration_state_can_leak() {
        // uid 999 has no SEND grant: it must meet AuthorizationFailed
        // regardless of registration state — GATEWAY_UNAVAILABLE would
        // reveal whether a live mirror exists to a principal that may
        // never learn it.
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
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
            Some(999),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            leaked_config_ops(),
            None,
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        let key = "77777777777777777777777777777777";
        let response = handle(
            gw_submit_line(key, &epoch, "HOST_RECEIVE_RAM").as_bytes(),
            &c,
        );
        assert_error_schema(&response, "AuthorizationFailed");
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            "{\"principals\":{\"9\":{\"networks\":{\"*\":[\"CONFIG\"]}},\"501\":{\"networks\":{\"0000000000000001\":[\"SEND\",\"READ_OPERATION\",\"OBSERVE\"]}}}}",
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
    const CFG_CHALLENGE_PARAMS: &str = "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":1,\"schema\":1";
    const CFG_STATUS_PARAMS: &str = "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":1,\"operation_id\":\"00112233445566778899aabbccddeeff\"";
    const CFG_PROPOSE_PARAMS: &str = "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":1,\"schema\":1,\"base_snapshot\":\"aabb\",\"patch\":[{\"field_id\":1,\"field_type\":\"u32\",\"value\":\"0000002a\"}]";
    const CFG_RECOVER_PARAMS: &str = "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":1,\"schema\":1,\"mode\":\"adopt-known\",\"new_store_generation\":4,\"new_revision\":8,\"snapshot_hash\":\"abababababababababababababababababababababababababababababababab\"";
    const CFG_RECOVERY_INFO_PARAMS: &str =
        "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":1";
    const CFG_TRUST_STATUS_PARAMS: &str =
        "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\"";

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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
        assert!(get.contains("\"op\":\"challenge ns=1 schema=1\""), "{get}");
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
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        // The trust verbs need the manifest hex, which no const can hold.
        let manifest =
            routeloom_provision::manifest::manifest_assemble(&[7_u8; 64], 0x100, &[9_u8; 64])
                .unwrap();
        let trust_install = format!(
            "{CFG_TRUST_STATUS_PARAMS},\"manifest\":\"{}\"",
            hex_lower(&manifest)
        );
        for (method, params) in [
            ("config.challenge", CFG_CHALLENGE_PARAMS.to_string()),
            ("config.status", CFG_STATUS_PARAMS.to_string()),
            ("config.retry", CFG_STATUS_PARAMS.to_string()),
            ("config.propose", CFG_PROPOSE_PARAMS.to_string()),
            ("config.recover", CFG_RECOVER_PARAMS.to_string()),
            ("config.recovery_info", CFG_RECOVERY_INFO_PARAMS.to_string()),
            ("trust.install", trust_install.clone()),
            ("trust.status", CFG_TRUST_STATUS_PARAMS.to_string()),
        ] {
            let response = handle(cfg_req(method, &params).as_bytes(), &c);
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        let response = handle(cfg_req("config.propose", CFG_PROPOSE_PARAMS).as_bytes(), &c);
        assert!(response.contains("\"ok\":true"), "{response}");
        // Acceptance is PENDING — never ACTIVE or APPLIED.
        assert!(response.contains("\"state\":\"PENDING\""), "{response}");
        assert!(!response.contains("ACTIVE"), "{response}");
    }

    #[test]
    fn config_recover_validates_mode_and_baseline() {
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
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        // A well-formed adopt-known submits PENDING.
        let response = handle(cfg_req("config.recover", CFG_RECOVER_PARAMS).as_bytes(), &c);
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(response.contains("\"state\":\"PENDING\""), "{response}");
        // Unknown mode, adopt-with-baseline, adopt-without-hash refuse.
        for params in [
            CFG_RECOVER_PARAMS.replace("adopt-known", "attest"),
            format!("{CFG_RECOVER_PARAMS},\"baseline\":\"aabb\""),
            CFG_RECOVER_PARAMS.replace(
                "\"snapshot_hash\":\"abababababababababababababababababababababababababababababababab\"",
                "\"snapshot_hash\":\"0000000000000000000000000000000000000000000000000000000000000000\"",
            ),
        ] {
            let response = handle(cfg_req("config.recover", &params).as_bytes(), &c);
            assert_error_schema(&response, "INVALID_ARGUMENT");
        }
        // Without an authority the daemon cannot sign a recovery.
        let no_auth = ctx_lane(
            Some(9),
            &acl,
            &log,
            &store,
            &limiter,
            &session,
            &lane,
            &config_ops,
            None,
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        let response = handle(
            cfg_req("config.recover", CFG_RECOVER_PARAMS).as_bytes(),
            &no_auth,
        );
        assert_error_schema(&response, "CONFIG_NO_AUTHORITY");
        let retry = handle(cfg_req("config.retry", CFG_STATUS_PARAMS).as_bytes(), &c);
        assert!(retry.contains("\"state\":\"PENDING\""), "{retry}");
        let retry = handle(
            cfg_req("config.retry", CFG_STATUS_PARAMS).as_bytes(),
            &no_auth,
        );
        assert_error_schema(&retry, "CONFIG_NO_AUTHORITY");
    }

    #[test]
    fn trust_verbs_submit_without_an_authority() {
        // Trust delivery is independent of the config authority (§6.3):
        // with NO authority configured, trust.install/status and
        // config.recovery_info still submit — only the ACL gates them.
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
            None,
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        let manifest =
            routeloom_provision::manifest::manifest_assemble(&[7_u8; 64], 0x100, &[9_u8; 64])
                .unwrap();
        let install = format!(
            "{CFG_TRUST_STATUS_PARAMS},\"manifest\":\"{}\"",
            hex_lower(&manifest)
        );
        for (method, params) in [
            ("trust.install", install),
            ("trust.status", CFG_TRUST_STATUS_PARAMS.to_string()),
            ("config.recovery_info", CFG_RECOVERY_INFO_PARAMS.to_string()),
        ] {
            let response = handle(cfg_req(method, &params).as_bytes(), &c);
            assert!(response.contains("\"ok\":true"), "{method}: {response}");
            assert!(
                response.contains("\"state\":\"PENDING\""),
                "{method}: {response}"
            );
        }
        // A non-envelope manifest refuses at admission, never queued.
        let bad = format!("{CFG_TRUST_STATUS_PARAMS},\"manifest\":\"d284\"");
        let response = handle(cfg_req("trust.install", &bad).as_bytes(), &c);
        assert_error_schema(&response, "INVALID_ARGUMENT");
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
                    "\"target\":\"0000000000000009\",\"config_namespace\":1,\"schema\":1",
                )
                .as_bytes(),
                &c,
            ),
            "INVALID_ARGUMENT",
        );
        // Bad target hex.
        let bad = "\"network\":\"0000000000000001\",\"target\":\"zz\",\"config_namespace\":1,\"schema\":1";
        assert_error_schema(
            &handle(cfg_req("config.challenge", bad).as_bytes(), &c),
            "INVALID_ARGUMENT",
        );
        // status: operation_id must be a 32-hex string.
        assert_error_schema(
            &handle(
                cfg_req(
                    "config.status",
                    "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":1,\"operation_id\":\"short\"",
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
                "{CFG_TARGET},\"config_namespace\":1,\"schema\":1,\"base_snapshot\":\"aabb\",{patch}"
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            leaked_hub(),
            7,
            leaked_event_ring(),
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
            summary: "propose ns=1".to_string(),
            network: 1,
            target: 9,
            outcome: None,
            submitted_ms: 100,
            resolved_ms: None,
        };
        let pending = config_outcome_json(&base);
        assert!(pending.contains("\"state\":\"PENDING\""), "{pending}");
        for (outcome, want) in [
            (ConfigOutcome::PermitAssembled(None), "PERMIT_ASSEMBLED"),
            (ConfigOutcome::NoChange, "NO_CHANGE"),
            (ConfigOutcome::Timeout, "TIMEOUT"),
            (ConfigOutcome::Indeterminate(None), "INDETERMINATE"),
            (ConfigOutcome::ProtocolError, "PROTOCOL_ERROR"),
        ] {
            let json = config_outcome_json(&ConfigOpRecord {
                outcome: Some(outcome),
                resolved_ms: Some(150),
                ..base.clone()
            });
            assert!(json.contains(&format!("\"state\":\"{want}\"")), "{json}");
            assert!(!json.contains("ACTIVE"), "{json}");
            // No issued operation id: the field stays absent, never null.
            assert!(!json.contains("operation_id"), "{json}");
        }
        // Unresolved outcomes name the device operation they may still hold.
        for outcome in [
            ConfigOutcome::PermitAssembled(Some([0x42; 16])),
            ConfigOutcome::Indeterminate(Some([0x42; 16])),
        ] {
            let json = config_outcome_json(&ConfigOpRecord {
                outcome: Some(outcome),
                resolved_ms: Some(150),
                ..base.clone()
            });
            assert!(
                json.contains("\"operation_id\":\"42424242424242424242424242424242\""),
                "{json}"
            );
        }
        let refused = config_outcome_json(&ConfigOpRecord {
            outcome: Some(ConfigOutcome::Refused(ConfigOpsResult::Denied)),
            resolved_ms: Some(150),
            ..base.clone()
        });
        assert!(refused.contains("\"state\":\"REFUSED\""), "{refused}");
        assert!(refused.contains("\"result\":\"DENIED\""), "{refused}");
        // The issuer-side stale-CAS refusal is a distinct refused result.
        let stale = config_outcome_json(&ConfigOpRecord {
            outcome: Some(ConfigOutcome::RefusedStale),
            resolved_ms: Some(150),
            ..base.clone()
        });
        assert!(stale.contains("\"state\":\"REFUSED\""), "{stale}");
        assert!(stale.contains("\"result\":\"STALE\""), "{stale}");
    }

    #[test]
    fn u16_field_parses_decimal_unless_0x_prefixed() {
        let num = |v: u64| Json::Number(v.to_string());
        let text = |s: &str| Json::String(s.to_string());
        let get = |v: &Json| u16_field(Some(v), "x").ok();
        // Numbers pass through; strings follow routeloomctl: only an
        // explicit 0x/0X prefix means hex — "10" is decimal 10, not 16.
        assert_eq!(get(&num(42)), Some(42));
        assert_eq!(get(&text("10")), Some(10));
        assert_eq!(get(&text("0x10")), Some(16));
        assert_eq!(get(&text("0X1f")), Some(31));
        assert_eq!(get(&text("010")), Some(10));
        assert_eq!(get(&text("65535")), Some(65535));
        assert_eq!(get(&text("0xffff")), Some(65535));
        for bad in [
            num(65_536),
            text("0x"),
            text("0x10000"),
            text("zz"),
            text(""),
        ] {
            assert_eq!(get(&bad), None, "{bad:?}");
        }
        // "-1" parses as decimal, fails the u16 range — never as hex.
        assert_eq!(get(&text("-1")), None);
    }

    #[test]
    fn parse_config_op_requires_the_canonical_token() {
        assert_eq!(parse_config_op("cfg0000000000000001"), Some(1));
        assert_eq!(parse_config_op("cfgffffffffffffffff"), Some(u64::MAX));
        // Bare hex, short forms, missing prefix, zero id, uppercase —
        // none of them name an op.
        for bad in [
            "0000000000000001",
            "cfg1",
            "cfg",
            "cfg0000000000000000",
            "cfg00000000000000001",
            "cfgABCDEFABCDEFABCD",
            "op0000000000000001",
            "cfg-000000000000001",
        ] {
            assert_eq!(parse_config_op(bad), None, "{bad}");
        }
    }

    #[test]
    fn request_body_bound_counts_the_whole_line() {
        let acl = acl_with(501);
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::test_store());
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        // The advertised 8192 bound covers `API1 ` + body + '\n': a body
        // of 8186 is the largest that fits the line; 8187 is too large.
        let body = vec![b'x'; REQUEST_MAX_BYTES - 6];
        let response = handle(&body, &c);
        assert!(!response.contains("request too large"), "{response}");
        assert_error_schema(&response, "INVALID_REQUEST");
        let body = vec![b'x'; REQUEST_MAX_BYTES - 5];
        let response = handle(&body, &c);
        assert_error_schema(&response, "INVALID_REQUEST");
        assert!(response.contains("request too large"), "{response}");
    }

    #[test]
    fn config_verbs_reject_reserved_target_ids() {
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
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        // Node ids 0 and u64::MAX are reserved wire addresses (01 §6) —
        // config targets follow the same rule as messages.submit.
        for target in ["0000000000000000", "ffffffffffffffff"] {
            let params = format!(
                "\"network\":\"0000000000000001\",\"target\":\"{target}\",\"config_namespace\":1,\"schema\":1"
            );
            assert_error_schema(
                &handle(cfg_req("config.challenge", &params).as_bytes(), &c),
                "INVALID_ARGUMENT",
            );
        }
    }

    #[test]
    fn config_namespace_must_be_registered() {
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
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        // 2 is not a namespace (SDK=1, application 0x8000-0xfffe); the
        // wire codecs refuse it, so the API refuses it up front.
        for (method, params) in [
            (
                "config.challenge",
                "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":2,\"schema\":1",
            ),
            (
                "config.status",
                "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":2,\"operation_id\":\"00112233445566778899aabbccddeeff\"",
            ),
            (
                "config.propose",
                "\"network\":\"0000000000000001\",\"target\":\"0000000000000009\",\"config_namespace\":2,\"schema\":1,\"base_snapshot\":\"aabb\",\"patch\":[{\"field_id\":1,\"field_type\":\"u8\",\"value\":\"01\"}]",
            ),
        ] {
            assert_error_schema(
                &handle(cfg_req(method, params).as_bytes(), &c),
                "INVALID_ARGUMENT",
            );
        }
        // The application range's own bounds hold too.
        for ns in [0x7fff_u16, 0xffff_u16] {
            let params = format!("{CFG_TARGET},\"config_namespace\":{ns},\"schema\":1");
            assert_error_schema(
                &handle(cfg_req("config.challenge", &params).as_bytes(), &c),
                "INVALID_ARGUMENT",
            );
        }
    }

    #[test]
    fn config_patch_must_be_wire_encodable() {
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
            leaked_hub(),
            7,
            leaked_event_ring(),
            100,
        );
        let propose = |patch: &str| {
            let params = format!(
                "{CFG_TARGET},\"config_namespace\":1,\"schema\":1,\"base_snapshot\":\"aabb\",{patch}"
            );
            handle(cfg_req("config.propose", &params).as_bytes(), &c)
        };
        // Exact type/value lengths: bool/u8 = 1 byte, u32 = 4 bytes.
        for patch in [
            "\"patch\":[{\"field_id\":1,\"field_type\":\"bool\",\"value\":\"02\"}]", // bool not 0|1
            "\"patch\":[{\"field_id\":1,\"field_type\":\"bool\",\"value\":\"0000\"}]", // bool len 2
            "\"patch\":[{\"field_id\":1,\"field_type\":\"u8\",\"value\":\"0001\"}]", // u8 len 2
            "\"patch\":[{\"field_id\":1,\"field_type\":\"u32\",\"value\":\"0001\"}]", // u32 len 2
            "\"patch\":[{\"field_id\":1,\"field_type\":\"u32\",\"value\":\"0000000001\"}]", // u32 len 5
            "\"patch\":[{\"field_id\":1,\"field_type\":\"u8\",\"value\":\"\"}]", // u8 empty
        ] {
            assert_error_schema(&propose(patch), "INVALID_ARGUMENT");
        }
        // The 512-byte patch total is a wire bound: each field costs
        // 5 + value_len. 6 x (5+96) = 606 > 512 must refuse at the API.
        let big = format!(
            "\"patch\":[{}]",
            (0..6_u16)
                .map(|i| format!(
                    "{{\"field_id\":{},\"field_type\":\"bytes\",\"value\":\"{}\"}}",
                    i + 1,
                    "ab".repeat(96)
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        assert_error_schema(&propose(&big), "INVALID_ARGUMENT");
        // A maximal legal patch is accepted (16 x u8: 16*(5+1)=96 <= 512).
        let ok = format!(
            "\"patch\":[{}]",
            (0..16_u16)
                .map(|i| format!(
                    "{{\"field_id\":{},\"field_type\":\"u8\",\"value\":\"{:02x}\"}}",
                    i + 1,
                    i
                ))
                .collect::<Vec<_>>()
                .join(",")
        );
        let response = propose(&ok);
        assert!(response.contains("\"ok\":true"), "{response}");
        // And bytes fields accept 0-length values on the wire.
        let response =
            propose("\"patch\":[{\"field_id\":1,\"field_type\":\"bytes\",\"value\":\"\"}]");
        assert!(response.contains("\"ok\":true"), "{response}");
    }

    // --- group.send / group.get -------------------------------------------

    fn group_session(capability: u32, network: u64) -> &'static Mutex<SessionInfo> {
        let session = leaked_session();
        {
            let mut info = session.lock().unwrap();
            info.authenticated = true;
            info.id = Some(0x5e55);
            info.node = Some(1);
            info.network = Some(network);
            info.capability = Some(capability);
        }
        session
    }

    fn group_line(method: &str, params: &str) -> String {
        format!("{{\"v\":1,\"request_id\":\"g\",\"method\":\"{method}\",\"params\":{params}}}")
    }

    fn snapshot_line(params: &str) -> String {
        format!(
            "{{\"v\":1,\"request_id\":\"t\",\"method\":\"diagnostics.snapshot\",\"params\":{params}}}"
        )
    }

    fn snapshot_params() -> String {
        "{\"observer\":\"0000000000000abc\",\"peer\":\"0000000000000005\"}".to_string()
    }

    #[test]
    fn diagnostics_snapshot_is_advertised() {
        let (acl, log, store, limiter) = test_env();
        let line = b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capabilities.get\"}";
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        let response = handle(line, &c);
        let parsed = routeloom_json::parse(&response).unwrap();
        let methods = parsed.get("result").unwrap().get("methods").unwrap();
        assert_eq!(
            methods.get("diagnostics.snapshot").and_then(Json::as_bool),
            Some(true)
        );
    }

    #[test]
    fn diagnostics_snapshot_rejects_bad_params() {
        let (acl, log, store, limiter) = test_env();
        let base = ctx(None, &acl, &log, &store, &limiter, 0);
        let c = ApiContext {
            session: group_session(0xFFFF_FFFF, 1),
            ..base
        };
        let cases = [
            "{\"observer\":\"0000000000000abc\"}",
            "{\"peer\":\"0000000000000005\"}",
            "{\"observer\":\"zz\",\"peer\":\"0000000000000005\"}",
            "{\"observer\":\"0000000000000000\",\"peer\":\"0000000000000005\"}",
            "{\"observer\":\"0000000000000abc\",\"peer\":\"ffffffffffffffff\"}",
            "{\"observer\":\"0000000000000abc\",\"peer\":\"0000000000000005\",\"direction\":\"sideways\"}",
            "{\"observer\":\"0000000000000abc\",\"peer\":\"0000000000000005\",\"length_class\":3}",
            "{\"observer\":\"0000000000000abc\",\"peer\":\"0000000000000005\",\"max_age_ms\":3001}",
            "{\"observer\":\"0000000000000abc\",\"peer\":\"0000000000000005\",\"bogus\":1}",
        ];
        for params in cases {
            let line = snapshot_line(params);
            let response = handle(line.as_bytes(), &c);
            assert!(
                response.contains("\"code\":\"INVALID_ARGUMENT\""),
                "{params}: {response}"
            );
        }
    }

    #[test]
    fn diagnostics_snapshot_gates_session_and_capability() {
        let (acl, log, store, limiter) = test_env();
        let line = snapshot_line(&snapshot_params());
        // No session at all.
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        let response = handle(line.as_bytes(), &c);
        assert!(
            response.contains("\"code\":\"GATEWAY_UNAVAILABLE\""),
            "{response}"
        );
        // Session without the diagnostics bit.
        let c = ApiContext {
            session: group_session(0x04, 1),
            ..ctx(None, &acl, &log, &store, &limiter, 0)
        };
        let response = handle(line.as_bytes(), &c);
        assert!(response.contains("\"code\":\"UNSUPPORTED\""), "{response}");
    }

    #[test]
    fn telemetry_outcomes_map_honestly() {
        use crate::telemetry::QueryOutcome;
        use routeloom_protocol::telemetry::decode_telemetry_snapshot;
        // A snapshot is a successful query with the evidence inline.
        let body = hex_bytes("010400000000004d00000000000000c300000000deadbeef00000000000000050000000700000003000000010b00011300000000075bcd15000007d000000028c9b0ce00c40000000000000c00000064000000600000000300000001000000040000005f0000000200000001000004d20000162e000023340000000200000200");
        let snapshot = decode_telemetry_snapshot(&body).unwrap();
        let result = match telemetry_outcome_result(QueryOutcome::Snapshot(snapshot), 0x0abc, 0x05)
        {
            Ok(result) => result,
            Err(error) => panic!("expected snapshot ok: {}", error.message),
        };
        assert!(result.contains("\"outcome\":\"snapshot\""), "{result}");
        assert!(result.contains("\"sample_age_ms\":40"), "{result}");
        // A mesh refusal is data, not an error.
        let reject = routeloom_protocol::telemetry::DiagnosticReject {
            request_id: 42,
            reason: routeloom_protocol::telemetry::RejectReason::NoPeer,
            observer: 0x0abc,
            detail: 0,
        };
        let result = match telemetry_outcome_result(QueryOutcome::Reject(reject), 0x0abc, 0x05) {
            Ok(result) => result,
            Err(error) => panic!("expected reject ok: {}", error.message),
        };
        assert!(result.contains("\"outcome\":\"reject\""), "{result}");
        assert!(result.contains("\"reason\":\"NO_PEER\""), "{result}");
        // Everything else is the honest error for the missing answer.
        let cases = [
            (
                QueryOutcome::Device(routeloom_protocol::host_ops::ConfigOpsResult::Busy),
                "\"code\":\"NO_CAPACITY\"",
            ),
            (
                QueryOutcome::Device(routeloom_protocol::host_ops::ConfigOpsResult::NoRoute),
                "\"code\":\"NO_ROUTE\"",
            ),
            (QueryOutcome::Timeout, "\"code\":\"TIMEOUT\""),
            (
                QueryOutcome::SessionLost,
                "\"code\":\"GATEWAY_UNAVAILABLE\"",
            ),
            (
                QueryOutcome::DecodeError("truncated".to_string()),
                "\"code\":\"INDETERMINATE\"",
            ),
            (QueryOutcome::ErrorFrame(7), "\"code\":\"INDETERMINATE\""),
        ];
        for (outcome, code) in cases {
            let error = telemetry_outcome_result(outcome, 0x0abc, 0x05).unwrap_err();
            let response = error_response(Some("t"), &error);
            assert!(response.contains(code), "{code}: {response}");
            assert!(
                response.contains("\"observer\":\"0000000000000abc\""),
                "{response}"
            );
        }
    }

    #[test]
    fn diagnostics_snapshot_round_trip_through_the_table() {
        // The method submits and waits; a 0x31 posted from another thread
        // (here the test thread, standing in for the USB read loop)
        // resolves it with the snapshot inline.
        let ops: &'static crate::telemetry::TelemetryOps = leaked_telemetry_ops();
        let line = snapshot_line(&snapshot_params());
        let (acl, log, store, limiter) = test_env();
        let answer = std::thread::scope(|scope| {
            let waiter = scope.spawn(|| {
                let c = ApiContext {
                    session: group_session(0xFFFF_FFFF, 1),
                    telemetry_ops: ops,
                    now_ms: u64::MAX - 100,
                    ..ctx(None, &acl, &log, &store, &limiter, 1_000)
                };
                handle(line.as_bytes(), &c)
            });
            let request = {
                let mut request = None;
                for _ in 0..500 {
                    if let Some(token) = ops.tokens().first() {
                        assert_eq!(ops.submitted_ms_for(*token), Some(1_000));
                        request = ops.request_for(*token);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                request.expect("the method submits a query")
            };
            let mut body = vec![0x01, 0x31, 0x00, 0x8c, 0x00, 0x00];
            body.extend_from_slice(&0x0abc_u64.to_be_bytes());
            body.extend_from_slice(&128_u16.to_be_bytes());
            let mut snapshot = hex_bytes("010400000000004d00000000000000c300000000deadbeef00000000000000050000000700000003000000010b00011300000000075bcd15000007d000000028c9b0ce00c40000000000000c00000064000000600000000300000001000000040000005f0000000200000001000004d20000162e000023340000000200000200");
            snapshot[4..8].copy_from_slice(&(request as u32).to_be_bytes());
            snapshot[8..16].copy_from_slice(&0x0abc_u64.to_be_bytes());
            snapshot[45] = 0;
            snapshot[46] = 255;
            body.extend_from_slice(&snapshot);
            assert!(ops.post_reply(request, 0x5e55, body));
            waiter.join().unwrap()
        });
        assert!(answer.contains("\"ok\":true"), "{answer}");
        assert!(answer.contains("\"outcome\":\"snapshot\""), "{answer}");
        assert!(answer.contains("\"mac_fail\":3"), "{answer}");
    }

    fn hex_bytes(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    const ALARM_PARAMS: &str = "{\"network\":\"0000000000000001\",\"group\":\"ALL\",\"key\":\"000102030405060708090a0b0c0d0e0f\",\"payload_hex\":\"50554d5033204f56455254454d50\",\"payload_len\":14,\"options\":{\"priority\":\"URGENT\",\"ttl_ms\":5000,\"hop_limit\":10}}";

    #[test]
    fn group_send_authorization_and_schema() {
        let (acl, log, store, limiter) = test_env();
        let session = group_session(0x87, 1);
        let base = ctx(Some(501), &acl, &log, &store, &limiter, 1_000);
        let c = ApiContext { session, ..base };
        // uid 7 holds SEND only on network 2.
        let other = ApiContext {
            principal: Some(routeloom_peercred::Principal::UnixUid(7)),
            ..ctx(Some(7), &acl, &log, &store, &limiter, 1_000)
        };
        let response = handle(group_line("group.send", ALARM_PARAMS).as_bytes(), &other);
        assert_error_schema(&response, "AuthorizationFailed");
        let unauthenticated = ctx(None, &acl, &log, &store, &limiter, 1_000);
        let response = handle(
            group_line("group.send", ALARM_PARAMS).as_bytes(),
            &unauthenticated,
        );
        assert_error_schema(&response, "AuthorizationFailed");
        let mutate = |from: &str, to: &str| ALARM_PARAMS.replacen(from, to, 1);
        let long = format!(
            "\"payload_hex\":\"{}\",\"payload_len\":128",
            "00".repeat(128)
        );
        for (params, code) in [
            (
                mutate("\"group\":\"ALL\"", "\"group\":0"),
                "INVALID_ARGUMENT",
            ),
            (
                mutate("\"group\":\"ALL\"", "\"group\":65536"),
                "INVALID_ARGUMENT",
            ),
            (
                mutate("\"group\":\"ALL\"", "\"group\":\"all\""),
                "INVALID_ARGUMENT",
            ),
            (mutate(",\"group\":\"ALL\"", ""), "INVALID_ARGUMENT"),
            (
                mutate(
                    "\"key\":\"000102030405060708090a0b0c0d0e0f\"",
                    "\"key\":\"00\"",
                ),
                "INVALID_ARGUMENT",
            ),
            (
                mutate("\"payload_len\":14", "\"payload_len\":13"),
                "INVALID_ARGUMENT",
            ),
            (
                mutate(
                    "\"payload_hex\":\"50554d5033204f56455254454d50\",\"payload_len\":14",
                    &long,
                ),
                "PAYLOAD_TOO_LARGE",
            ),
            (
                mutate("\"ttl_ms\":5000", "\"ttl_ms\":0"),
                "INVALID_ARGUMENT",
            ),
            (
                mutate("\"ttl_ms\":5000", "\"ttl_ms\":30001"),
                "INVALID_ARGUMENT",
            ),
            (
                mutate("\"hop_limit\":10", "\"hop_limit\":255"),
                "INVALID_ARGUMENT",
            ),
            (mutate("\"URGENT\"", "\"HIGH\""), "INVALID_ARGUMENT"),
            (
                mutate("\"ttl_ms\":5000", "\"ordered\":\"yes\""),
                "INVALID_ARGUMENT",
            ),
            (
                mutate("\"ttl_ms\":5000", "\"delivery\":\"RELIABLE\""),
                "INVALID_ARGUMENT",
            ),
            (
                mutate("\"group\":\"ALL\"", "\"group\":\"ALL\",\"wait_ms\":15001"),
                "INVALID_ARGUMENT",
            ),
            (
                mutate("\"group\":\"ALL\"", "\"group\":\"ALL\",\"extra\":1"),
                "INVALID_ARGUMENT",
            ),
        ] {
            let response = handle(group_line("group.send", &params).as_bytes(), &c);
            assert_error_schema(&response, code);
        }
        // Nothing above was admitted.
        let response = handle(
            group_line("group.get", "{\"group_op\":\"grp0000000000000001\"}").as_bytes(),
            &c,
        );
        assert_error_schema(&response, "NOT_FOUND");
    }

    #[test]
    fn group_send_live_gateway_gates() {
        let (acl, log, store, limiter) = test_env();
        // No authenticated session: retryable, nothing queued.
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 1_000);
        let response = handle(group_line("group.send", ALARM_PARAMS).as_bytes(), &c);
        let doc = assert_error_schema(&response, "GATEWAY_UNAVAILABLE");
        let error = doc.get("error").unwrap();
        assert_eq!(error.get("retryable").and_then(Json::as_bool), Some(true));
        assert_eq!(
            error
                .get("detail")
                .and_then(|d| d.get("reason"))
                .and_then(Json::as_str),
            Some("no_session")
        );
        // Session on another network.
        let c = ApiContext {
            session: group_session(0x87, 2),
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let response = handle(group_line("group.send", ALARM_PARAMS).as_bytes(), &c);
        let doc = assert_error_schema(&response, "GATEWAY_UNAVAILABLE");
        assert!(
            doc.get("error")
                .unwrap()
                .get("detail")
                .unwrap()
                .get("reason")
                .and_then(Json::as_str)
                == Some("network_mismatch")
        );
        // Gateway without capability bit 7 (or without host_ops_v1).
        for capability in [0x07_u32, 0x80] {
            let c = ApiContext {
                session: group_session(capability, 1),
                ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
            };
            let response = handle(group_line("group.send", ALARM_PARAMS).as_bytes(), &c);
            let doc = assert_error_schema(&response, "UNSUPPORTED");
            let error = doc.get("error").unwrap();
            assert_eq!(error.get("retryable").and_then(Json::as_bool), Some(false));
            let detail = error.get("detail").unwrap();
            assert_eq!(
                detail.get("required_capability").and_then(Json::as_str),
                Some("group_delivery_v1")
            );
            assert_eq!(
                detail.get("capability").and_then(Json::as_u64),
                Some(u64::from(capability))
            );
        }
    }

    #[test]
    fn group_send_admits_replays_and_get_follows_the_lane() {
        use crate::group::{GroupLane, GroupLink, GroupOps};
        use routeloom_protocol::group_ops::{encode_group_status, GroupStatus};
        let (acl, log, store, limiter) = test_env();
        let ops: &'static GroupOps = Box::leak(Box::new(GroupOps::default()));
        let session = group_session(0x87, 1);
        let c = ApiContext {
            session,
            group_ops: ops,
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let response = handle(group_line("group.send", ALARM_PARAMS).as_bytes(), &c);
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").expect("ok result");
        let token = result
            .get("group_op")
            .and_then(Json::as_str)
            .unwrap()
            .to_string();
        assert!(token.starts_with("grp"));
        assert_eq!(
            result.get("state").and_then(Json::as_str),
            Some("HOST_QUEUED")
        );
        assert_eq!(result.get("final").and_then(Json::as_bool), Some(false));
        assert_eq!(result.get("group").and_then(Json::as_u64), Some(65535));
        assert_eq!(
            result.get("priority").and_then(Json::as_str),
            Some("URGENT")
        );
        assert_eq!(result.get("payload_len").and_then(Json::as_u64), Some(14));
        for field in [
            "delivered",
            "nonmember",
            "missing_total",
            "message",
            "admitted_ms",
        ] {
            assert!(
                result.get(field).unwrap().is_null(),
                "{field} must be null: {response}"
            );
        }
        // Same key + same request: the same op, even with the gateway gone.
        session.lock().unwrap().authenticated = false;
        let replay = handle(group_line("group.send", ALARM_PARAMS).as_bytes(), &c);
        assert_eq!(result_field(&replay, "group_op"), token);
        // Same key, different bytes: CONFLICT naming the existing op.
        let conflict = handle(
            group_line(
                "group.send",
                &ALARM_PARAMS.replace("\"URGENT\"", "\"NORMAL\""),
            )
            .as_bytes(),
            &c,
        );
        let doc = assert_error_schema(&conflict, "CONFLICT");
        assert_eq!(
            doc.get("error")
                .and_then(|e| e.get("detail"))
                .and_then(|d| d.get("existing_group_op"))
                .and_then(Json::as_str),
            Some(token.as_str())
        );
        session.lock().unwrap().authenticated = true;

        // group.get: READ_OPERATION on the op's network, else NOT_FOUND.
        let get = group_line("group.get", &format!("{{\"group_op\":\"{token}\"}}"));
        let stranger = ApiContext {
            principal: Some(routeloom_peercred::Principal::UnixUid(7)),
            ..ApiContext {
                session,
                group_ops: ops,
                ..ctx(Some(7), &acl, &log, &store, &limiter, 1_000)
            }
        };
        assert_error_schema(&handle(get.as_bytes(), &stranger), "NOT_FOUND");
        assert_error_schema(
            &handle(
                group_line("group.get", "{\"group_op\":\"cfg0000000000000001\"}").as_bytes(),
                &c,
            ),
            "INVALID_ARGUMENT",
        );
        assert_eq!(
            result_field(&handle(get.as_bytes(), &c), "state"),
            "HOST_QUEUED"
        );

        // Drive the lane: admission, then FINAL.
        let link = GroupLink {
            active: true,
            capable: true,
            session: 0x5e55,
            gateway: 1,
            network: 1,
        };
        let mut lane = GroupLane::default();
        let out = ops.step(&mut lane, &link, 1_000);
        let request = out.frames[0].0;
        let mut status = GroupStatus {
            result: 0,
            session: 0x1b59,
            sequence: (1 << 63) | 1,
            group: 0xFFFF,
            state: 6,
            rounds: 1,
            reason: "GROUP_ROUND_PENDING".to_string(),
            ..GroupStatus::default()
        };
        ops.post_status(request, encode_group_status(&status).unwrap());
        ops.step(&mut lane, &link, 1_010);
        let response = handle(get.as_bytes(), &c);
        assert_eq!(result_field(&response, "state"), "WAITING_FOR_END_RECEIPT");
        assert_eq!(
            routeloom_json::parse(&response)
                .unwrap()
                .get("result")
                .unwrap()
                .get("message")
                .unwrap()
                .get("sequence")
                .and_then(Json::as_str),
            Some("8000000000000001")
        );
        status.state = 7;
        status.delivered = 99;
        status.reason = "GROUP_COMPLETE".to_string();
        ops.post_status(request, encode_group_status(&status).unwrap());
        let out = ops.step(&mut lane, &link, 1_100);
        assert_eq!(out.events.len(), 1);
        let response = handle(
            group_line(
                "group.get",
                &format!("{{\"group_op\":\"{token}\",\"wait_ms\":1000}}"),
            )
            .as_bytes(),
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").unwrap();
        assert_eq!(
            result.get("state").and_then(Json::as_str),
            Some("DELIVERED")
        );
        assert_eq!(result.get("final").and_then(Json::as_bool), Some(true));
        assert_eq!(result.get("delivered").and_then(Json::as_u64), Some(99));
        assert_eq!(result.get("result").and_then(Json::as_str), Some("OK"));
        assert_eq!(result.get("settled_ms").and_then(Json::as_u64), Some(1_100));
        assert_eq!(
            result.get("clock").and_then(Json::as_str),
            Some("host_unix_ms")
        );
    }

    /// `wait_ms` on group.send returns as soon as the gateway answered.
    #[test]
    fn group_send_wait_returns_on_admission() {
        use crate::group::{GroupLane, GroupLink, GroupOps};
        use routeloom_protocol::group_ops::{encode_group_status, GroupStatus};
        let (acl, log, store, limiter) = test_env();
        let ops: &'static GroupOps = Box::leak(Box::new(GroupOps::default()));
        let c = ApiContext {
            session: group_session(0x87, 1),
            group_ops: ops,
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let driver = std::thread::spawn(move || {
            let link = GroupLink {
                active: true,
                capable: true,
                session: 0x5e55,
                gateway: 1,
                network: 1,
            };
            let mut lane = GroupLane::default();
            for _ in 0..400 {
                let out = ops.step(&mut lane, &link, 1_000);
                if let Some((request, _)) = out.frames.first() {
                    let refusal = GroupStatus {
                        result: 4, // Unsupported
                        group: 0xFFFF,
                        reason: "GROUP_REQUIRES_GATEWAY_SCOPED".to_string(),
                        ..GroupStatus::default()
                    };
                    ops.post_status(*request, encode_group_status(&refusal).unwrap());
                    ops.step(&mut lane, &link, 1_001);
                    return true;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            false
        });
        let started = Instant::now();
        let response = handle(
            group_line(
                "group.send",
                &ALARM_PARAMS.replacen("\"group\":\"ALL\"", "\"group\":7,\"wait_ms\":10000", 1),
            )
            .as_bytes(),
            &c,
        );
        assert!(driver.join().unwrap());
        assert!(started.elapsed() < Duration::from_secs(5));
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").expect("ok result");
        assert_eq!(result.get("state").and_then(Json::as_str), Some("REFUSED"));
        assert_eq!(result.get("final").and_then(Json::as_bool), Some(true));
        assert_eq!(
            result.get("result").and_then(Json::as_str),
            Some("UNSUPPORTED")
        );
        assert_eq!(
            result.get("reason").and_then(Json::as_str),
            Some("GROUP_REQUIRES_GATEWAY_SCOPED")
        );
        assert_eq!(result.get("all").and_then(Json::as_bool), Some(false));
    }

    #[test]
    fn capabilities_advertise_group_delivery() {
        let (acl, log, store, limiter) = test_env();
        let line = b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capabilities.get\"}";
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        let response = handle(line, &c);
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").unwrap();
        let methods = result.get("methods").unwrap();
        assert_eq!(
            methods.get("group.send").and_then(Json::as_bool),
            Some(true)
        );
        assert_eq!(methods.get("group.get").and_then(Json::as_bool), Some(true));
        let group = result.get("group").unwrap();
        assert_eq!(
            group.get("dispatch").and_then(Json::as_str),
            Some("usb_group_delivery_v1")
        );
        assert!(group.get("gateway_capable").unwrap().is_null());
        assert_eq!(
            group.get("payload_max_bytes").and_then(Json::as_u64),
            Some(127)
        );
        assert_eq!(
            group.get("membership_set").and_then(Json::as_bool),
            Some(false)
        );
        let c = ApiContext {
            session: group_session(0x87, 1),
            ..ctx(None, &acl, &log, &store, &limiter, 0)
        };
        assert!(handle(line, &c).contains("\"gateway_capable\":true"));
        let c = ApiContext {
            session: group_session(0x07, 1),
            ..ctx(None, &acl, &log, &store, &limiter, 0)
        };
        assert!(handle(line, &c).contains("\"gateway_capable\":false"));
        // group_settled is a subscribable event kind.
        assert!(crate::subscribe::EVENT_KINDS.contains(&"group_settled"));
    }

    // --- lab.rollcall.* (design-devflow §6.4–6.5, D09) ----------------------

    /// ctx with the rollcall service and group ops the test drives by hand
    /// — the service is otherwise owned by the daemon `State`.
    #[allow(clippy::too_many_arguments)]
    fn rollcall_ctx<'a, S: OperationStore>(
        uid: Option<u32>,
        acl: &'a Acl,
        log: &'a Mutex<ReceiveLog>,
        store: &'a Mutex<S>,
        limiter: &'a Mutex<AdmissionLimiter>,
        session: &'a Mutex<SessionInfo>,
        rollcall: &'a crate::rollcall::RollcallService,
        group_ops: &'a crate::group::GroupOps,
    ) -> ApiContext<'a, S> {
        ApiContext {
            session,
            rollcall,
            group_ops,
            ..ctx_lane(
                uid,
                acl,
                log,
                store,
                limiter,
                session,
                leaked_lane(),
                leaked_config_ops(),
                None,
                leaked_hub(),
                7,
                leaked_event_ring(),
                1_000,
            )
        }
    }

    // --- health.get / topology.get ----------------------------------------

    fn observation_session(capability: u32) -> &'static Mutex<SessionInfo> {
        let session = leaked_session();
        {
            let mut info = session.lock().unwrap();
            info.authenticated = true;
            info.id = Some(0x5e55);
            info.node = Some(0x0abc);
            info.boot = Some(0xB007);
            info.network = Some(1);
            info.capability = Some(capability);
        }
        session
    }

    fn observation_line(method: &str, params: &str) -> String {
        format!("{{\"v\":1,\"request_id\":\"o\",\"method\":\"{method}\",\"params\":{params}}}")
    }

    const OBSERVER: &str = "\"observer\":\"0000000000000abc\"";

    #[test]
    fn remote_observation_requires_observe_grant() {
        let (acl, log, store, limiter) = test_env();
        for uid in [None, Some(7)] {
            let c = ApiContext {
                session: observation_session(0x04 | 0x20),
                ..ctx(uid, &acl, &log, &store, &limiter, 1_000)
            };
            for method in ["health.get", "topology.get"] {
                let section = if method == "health.get" {
                    "system"
                } else {
                    "routes"
                };
                let line = observation_line(
                    method,
                    &format!("{{\"observer\":\"0000000000000005\",\"section\":\"{section}\"}}"),
                );
                assert_error_schema(&handle(line.as_bytes(), &c), "AuthorizationFailed");
            }
        }
    }

    #[test]
    fn lab_rollcall_advertised_and_gated() {
        let (acl, log, store, limiter) = test_env();
        let rollcall: &'static crate::rollcall::RollcallService =
            Box::leak(Box::new(crate::rollcall::RollcallService::default()));
        let c = rollcall_ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            group_session(0x87, 1),
            rollcall,
            leaked_group_ops(),
        );
        // Advertised with the dispatch + the 2 s floor.
        let response = handle(
            b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capabilities.get\"}",
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        let methods = parsed.get("result").unwrap().get("methods").unwrap();
        assert_eq!(
            methods.get("lab.rollcall.start").and_then(Json::as_bool),
            Some(true)
        );
        assert_eq!(
            methods.get("lab.rollcall.status").and_then(Json::as_bool),
            Some(true)
        );
        let roll = parsed.get("result").unwrap().get("rollcall").unwrap();
        assert_eq!(
            roll.get("dispatch").and_then(Json::as_str),
            Some("usb_group_delivery_v1")
        );
        assert_eq!(
            roll.get("min_interval_ms").and_then(Json::as_u64),
            Some(2_000)
        );

        // Schema: start takes only network/group, status takes none.
        let response = handle(
            group_line(
                "lab.rollcall.start",
                "{\"network\":\"0000000000000001\",\"bogus\":1}",
            )
            .as_bytes(),
            &c,
        );
        assert_error_schema(&response, "INVALID_ARGUMENT");
        let response = handle(
            group_line("lab.rollcall.status", "{\"x\":1}").as_bytes(),
            &c,
        );
        assert_error_schema(&response, "INVALID_ARGUMENT");

        // No run yet — status is the same NOT_FOUND a missing group op gets.
        let response = handle(group_line("lab.rollcall.status", "{}").as_bytes(), &c);
        assert_error_schema(&response, "NOT_FOUND");

        // Without SEND, start is denied before any run exists.
        let denied = ApiContext {
            principal: Some(routeloom_peercred::Principal::UnixUid(7)),
            ..rollcall_ctx(
                Some(7),
                &acl,
                &log,
                &store,
                &limiter,
                group_session(0x87, 1),
                rollcall,
                leaked_group_ops(),
            )
        };
        let response = handle(group_line("lab.rollcall.start", "{}").as_bytes(), &denied);
        assert_error_schema(&response, "AuthorizationFailed");
        assert!(rollcall.run_network().is_none(), "no run was created");
    }

    /// A disconnected GUI re-issuing `start` answers the single owned run —
    /// the "no duplicate loop" acceptance lives in the service; this test
    /// proves the API hands it through.
    #[test]
    fn lab_rollcall_single_run_across_clients() {
        let (acl, log, store, limiter) = test_env();
        let rollcall: &'static crate::rollcall::RollcallService =
            Box::leak(Box::new(crate::rollcall::RollcallService::default()));
        let ops = leaked_group_ops();
        let session = group_session(0x87, 1);
        let c = rollcall_ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            session,
            rollcall,
            ops,
        );
        let start = |params: &str, ctx: &ApiContext<'_, MemoryOperationStore>| {
            handle(group_line("lab.rollcall.start", params).as_bytes(), ctx)
        };
        let response = start("{}", &c);
        let parsed = routeloom_json::parse(&response).unwrap();
        assert_eq!(parsed.get("ok").and_then(Json::as_bool), Some(true));
        let run_uuid = parsed
            .get("result")
            .unwrap()
            .get("run_uuid")
            .and_then(Json::as_str)
            .unwrap()
            .to_string();
        assert_eq!(run_uuid.len(), 32);

        // Same params from the same or another authorized principal: the
        // live run's uuid, never a second loop.
        for uid in [Some(501), Some(501)] {
            let c = rollcall_ctx(uid, &acl, &log, &store, &limiter, session, rollcall, ops);
            let response = start("{}", &c);
            let reparsed = routeloom_json::parse(&response).unwrap();
            assert_eq!(
                reparsed
                    .get("result")
                    .unwrap()
                    .get("run_uuid")
                    .and_then(Json::as_str),
                Some(run_uuid.as_str())
            );
        }
        // A different group is a conflict — the run keeps its group.
        let response = start("{\"group\":7}", &c);
        assert_error_schema(&response, "CONFLICT");

        // A poll actually schedules through the shared GroupOps lane once
        // the service ticks with a nonempty roster.
        crate::rollcall::service_step(rollcall, ops, 5, false, 1_100);
        let status =
            routeloom_json::parse(&rollcall.status_json(&crate::rollcall::StatusView::default()))
                .unwrap();
        assert_eq!(status.get("poll_seq").and_then(Json::as_u64), Some(1));
        assert!(status.get("in_flight").and_then(Json::as_str).is_some());

        // update is owner-bound; a stranger's run_uuid is refused.
        let stranger = rollcall_ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            session,
            rollcall,
            ops,
        );
        let response = handle(
            group_line(
                "lab.rollcall.update",
                "{\"run_uuid\":\"00000000000000000000000000000000\",\"group\":7}",
            )
            .as_bytes(),
            &stranger,
        );
        assert_error_schema(&response, "CONFLICT");

        // status reads under READ_OPERATION; a foreign-network principal
        // sees the same NOT_FOUND as group.get.
        let response = handle(group_line("lab.rollcall.status", "{}").as_bytes(), &c);
        let parsed = routeloom_json::parse(&response).unwrap();
        assert_eq!(parsed.get("ok").and_then(Json::as_bool), Some(true));
        assert_eq!(
            parsed
                .get("result")
                .unwrap()
                .get("run_uuid")
                .and_then(Json::as_str),
            Some(run_uuid.as_str())
        );
        let foreign = rollcall_ctx(
            Some(7),
            &acl,
            &log,
            &store,
            &limiter,
            session,
            rollcall,
            ops,
        );
        let response = handle(group_line("lab.rollcall.status", "{}").as_bytes(), &foreign);
        assert_error_schema(&response, "NOT_FOUND");

        // stop{run_uuid} ends the run; a second stop is just false.
        let response = handle(
            group_line(
                "lab.rollcall.stop",
                &format!("{{\"run_uuid\":\"{run_uuid}\"}}"),
            )
            .as_bytes(),
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        assert_eq!(
            parsed
                .get("result")
                .unwrap()
                .get("stopped")
                .and_then(Json::as_bool),
            Some(true)
        );
        let response = handle(
            group_line(
                "lab.rollcall.stop",
                &format!("{{\"run_uuid\":\"{run_uuid}\"}}"),
            )
            .as_bytes(),
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        assert_eq!(
            parsed
                .get("result")
                .unwrap()
                .get("stopped")
                .and_then(Json::as_bool),
            Some(false)
        );
        let response = handle(group_line("lab.rollcall.status", "{}").as_bytes(), &c);
        assert_error_schema(&response, "NOT_FOUND");
    }

    /// `lab.rollcall.start` reuses the same session/network/capability gates
    /// as `group.send`: a poll cannot schedule where a send could not fly.
    #[test]
    fn lab_rollcall_start_inherits_group_gates() {
        let (acl, log, store, limiter) = test_env();
        // No session at all.
        let c = rollcall_ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            leaked_session(),
            leaked_rollcall(),
            leaked_group_ops(),
        );
        let response = handle(group_line("lab.rollcall.start", "{}").as_bytes(), &c);
        assert_error_schema(&response, "GATEWAY_UNAVAILABLE");
        // Session on a different network.
        let c = rollcall_ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            group_session(0x87, 2),
            leaked_rollcall(),
            leaked_group_ops(),
        );
        let response = handle(
            group_line("lab.rollcall.start", "{\"network\":\"0000000000000001\"}").as_bytes(),
            &c,
        );
        assert_error_schema(&response, "INVALID_ARGUMENT");
        // Gateway lacking the group capability.
        let c = rollcall_ctx(
            Some(501),
            &acl,
            &log,
            &store,
            &limiter,
            group_session(0x07, 1),
            leaked_rollcall(),
            leaked_group_ops(),
        );
        let response = handle(group_line("lab.rollcall.start", "{}").as_bytes(), &c);
        assert_error_schema(&response, "UNSUPPORTED");
    }

    /// D10: `capacity.get` reports the enforced profile and budgets; the
    /// bench profile's client discipline appears only under bench-v1.
    #[test]
    fn capacity_get_reports_profile_and_budgets() {
        let (acl, log, store, limiter) = test_env();
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capacity.get\",\"params\":{}}",
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").unwrap();
        let admission = result.get("admission").unwrap();
        assert_eq!(admission.get("profile").unwrap().as_str(), Some("normal"));
        assert_eq!(admission.get("calls_per_minute").unwrap().as_u64(), Some(2));
        assert_eq!(admission.get("burst").unwrap().as_u64(), Some(16));
        assert!(matches!(admission.get("client"), Some(Json::Null)));
        let store_block = result.get("store").unwrap();
        assert_eq!(store_block.get("records_max").unwrap().as_u64(), Some(4096));
        assert_eq!(store_block.get("free_slots").unwrap().as_u64(), Some(4096));
        assert!(result.get("queue_mode").is_some());
        // Params are rejected like every other nullary verb.
        let response = handle(
            b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capacity.get\",\"params\":{\"bogus\":1}}",
            &c,
        );
        assert!(response.contains("\"ok\":false"), "{response}");
        // Under bench-v1 the effective budget is the raised one, and the
        // client discipline is populated.
        let bench = Mutex::new(AdmissionLimiter::with_profile(
            send_store::AdmissionProfile::BenchV1,
            0,
        ));
        let c = ctx(Some(501), &acl, &log, &store, &bench, 0);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capacity.get\",\"params\":{}}",
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        let admission = parsed.get("result").unwrap().get("admission").unwrap();
        assert_eq!(admission.get("profile").unwrap().as_str(), Some("bench-v1"));
        assert_eq!(
            admission.get("calls_per_minute").unwrap().as_u64(),
            Some(600)
        );
        assert_eq!(admission.get("burst").unwrap().as_u64(), Some(8));
        let client = admission.get("client").unwrap();
        assert_eq!(client.get("inflight_max").unwrap().as_u64(), Some(4));
        assert_eq!(client.get("run_window_calls").unwrap().as_u64(), Some(64));
    }

    /// D10 KG control profile end-to-end: a LATEST_PER_DESTINATION submit
    /// retires the still-queued predecessor, names it in the response,
    /// and the retired record reports the replacing operation id.
    #[test]
    fn control_queue_mode_supersedes_via_api() {
        let (acl, log, store, limiter) = test_env();
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let control_line = |key: &str| {
            format!(
                "{{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"00ff\",\"payload_len\":2,\"options\":{{\"storage\":\"RAM_ONLY\",\"delivery\":\"BEST_EFFORT\",\"queue_mode\":\"LATEST_PER_DESTINATION\"}}}}}}"
            )
        };
        let response = handle(
            control_line("00112233445566778899aabbccddeeff").as_bytes(),
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        let first_id = result_field(&response, "operation_id");
        let response = handle(
            control_line("11112233445566778899aabbccddeeff").as_bytes(),
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        let second_id = result_field(&response, "operation_id");
        let parsed = routeloom_json::parse(&response).unwrap();
        let superseded = parsed
            .get("result")
            .unwrap()
            .get("superseded")
            .unwrap()
            .as_array()
            .unwrap();
        assert_eq!(superseded.len(), 1);
        assert_eq!(superseded[0].as_str(), Some(first_id.as_str()));
        // The retired record: CANCELLED_BEFORE_DISPATCH with the replacing
        // operation id in `superseded_by`, never cancel_requested.
        let get = format!(
            "{{\"v\":1,\"request_id\":\"g\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{first_id}\"}}}}"
        );
        let response = handle(get.as_bytes(), &c);
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(response.contains("CANCELLED_BEFORE_DISPATCH"), "{response}");
        assert!(
            response.contains(&format!("\"superseded_by\":\"{second_id}\"")),
            "{response}"
        );
        assert!(
            response.contains("\"queue_mode\":\"LATEST_PER_DESTINATION\""),
            "{response}"
        );
        assert!(
            response.contains("\"cancel_requested\":false"),
            "{response}"
        );
        // FIFO submits never emit the supersede field.
        let response = handle(
            submit_line("22112233445566778899aabbccddeeff", &epoch).as_bytes(),
            &c,
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(!response.contains("superseded"), "{response}");
    }

    #[test]
    fn remote_observation_accepts_authenticated_sid_grant() {
        let (_, log, store, limiter) = test_env();
        let sid = "S-1-5-21-100-200-300-1001";
        let acl = Acl::parse(&format!(
            "{{\"principals\":{{\"{sid}\":{{\"networks\":{{\"0000000000000001\":[\"OBSERVE\"]}}}}}}}}"
        ))
        .unwrap();
        let c = ApiContext {
            principal: Some(routeloom_peercred::Principal::WindowsSid(sid.into())),
            session: observation_session(0x04 | 0x20),
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        assert!(observation_require_remote(&c, Some(1)).is_ok());
    }

    #[test]
    fn observation_methods_are_advertised() {
        let (acl, log, store, limiter) = test_env();
        let line = b"{\"v\":1,\"request_id\":\"c\",\"method\":\"capabilities.get\"}";
        let c = ctx(None, &acl, &log, &store, &limiter, 0);
        let response = handle(line, &c);
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").unwrap();
        let methods = result.get("methods").unwrap();
        assert_eq!(
            methods.get("health.get").and_then(Json::as_bool),
            Some(true)
        );
        assert_eq!(
            methods.get("topology.get").and_then(Json::as_bool),
            Some(true)
        );
        let observation = result.get("observation").unwrap();
        // Detached: servable flags are false, limits static.
        assert_eq!(
            observation.get("health").and_then(Json::as_bool),
            Some(false)
        );
        assert_eq!(
            observation.get("remote").and_then(Json::as_bool),
            Some(false)
        );
        let limits = observation.get("limits").unwrap();
        assert_eq!(
            limits.get("routes_page_max").and_then(Json::as_u64),
            Some(8)
        );
        // Attached with bit 11: servable; without: not.
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            ..ctx(None, &acl, &log, &store, &limiter, 0)
        };
        let response = handle(line, &c);
        assert!(response.contains("\"topology\":true"), "{response}");
        assert!(response.contains("\"health\":true"), "{response}");
        assert!(response.contains("\"remote\":true"), "{response}");
        let c = ApiContext {
            session: observation_session(0x07),
            ..ctx(None, &acl, &log, &store, &limiter, 0)
        };
        let response = handle(line, &c);
        assert!(response.contains("\"topology\":false"), "{response}");
        // Diagnostics bit without host_ops: neither telemetry nor remote.
        let c = ApiContext {
            session: observation_session(0x20),
            ..ctx(None, &acl, &log, &store, &limiter, 0)
        };
        let response = handle(line, &c);
        assert!(response.contains("\"remote\":false"), "{response}");
        // The 0x72-fed ring events are subscribable.
        for kind in ["topology.changed", "milestone.advanced", "observation.gap"] {
            assert!(crate::subscribe::EVENT_KINDS.contains(&kind), "{kind}");
        }
    }

    #[test]
    fn health_get_rejects_bad_params() {
        let (acl, log, store, limiter) = test_env();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let cases = [
            "{}",
            "{\"observer\":\"zz\"}",
            "{\"observer\":\"0000000000000000\"}",
            "{\"observer\":\"ffffffffffffffff\"}",
            "{\"observer\":\"0000000000000abc\",\"section\":\"neighbors\"}",
            "{\"observer\":\"0000000000000abc\",\"section\":0}",
            "{\"observer\":\"0000000000000abc\",\"max_age_ms\":60001}",
            "{\"observer\":\"0000000000000abc\",\"max_age_ms\":-1}",
            "{\"observer\":\"0000000000000abc\",\"subscribe\":\"yes\"}",
            "{\"observer\":\"0000000000000abc\",\"network\":\"zz\"}",
            "{\"observer\":\"0000000000000abc\",\"destination\":\"0000000000000005\"}",
            "{\"observer\":\"0000000000000abc\",\"bogus\":1}",
        ];
        for params in cases {
            let response = handle(observation_line("health.get", params).as_bytes(), &c);
            assert!(
                response.contains("\"code\":\"INVALID_ARGUMENT\""),
                "{params}: {response}"
            );
        }
    }

    #[test]
    fn observation_network_param_treats_null_as_absent() {
        let link = ObservationLink {
            session: 1,
            gateway: 2,
            boot: 3,
            network: Some(1),
        };
        for (params, ok) in [
            ("{}", true),
            ("{\"network\":null}", true),
            ("{\"network\":\"0000000000000001\"}", true),
            ("{\"network\":\"0000000000000002\"}", false),
            ("{\"network\":\"zz\"}", false),
        ] {
            let parsed = routeloom_json::parse(params).unwrap();
            assert_eq!(
                observation_network_param(&parsed, &link).is_ok(),
                ok,
                "{params}"
            );
        }
    }

    #[test]
    fn observation_gate_and_scope() {
        let (acl, log, store, limiter) = test_env();
        let params = format!("{{{OBSERVER},\"section\":\"system\"}}");
        let line = observation_line("health.get", &params);
        // No session.
        let c = ctx(None, &acl, &log, &store, &limiter, 1_000);
        let response = handle(line.as_bytes(), &c);
        assert_error_schema(&response, "GATEWAY_UNAVAILABLE");
        // Session without the observation bit.
        let c = ApiContext {
            session: observation_session(0x07),
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let doc = assert_error_schema(&handle(line.as_bytes(), &c), "UNSUPPORTED");
        assert_eq!(
            doc.get("error")
                .unwrap()
                .get("detail")
                .unwrap()
                .get("required_capability")
                .and_then(Json::as_str),
            Some("observation_v1")
        );
        // Foreign observer without the diagnostics bit: the remote leg
        // is UNSUPPORTED (the observation bit does not serve peers).
        let c = ApiContext {
            session: observation_session(0x04 | 0x800),
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let foreign = observation_line(
            "health.get",
            "{\"observer\":\"0000000000000005\",\"section\":\"system\"}",
        );
        let doc = assert_error_schema(&handle(foreign.as_bytes(), &c), "UNSUPPORTED");
        assert_eq!(
            doc.get("error")
                .unwrap()
                .get("detail")
                .unwrap()
                .get("required_capability")
                .and_then(Json::as_str),
            Some("diagnostics_v1")
        );
        // Foreign observer with the diagnostics bit: the remote leg opens
        // (then times out with no lane — the wait budget is what proves
        // the gate opened); the observation bit is not required.
        let c = ApiContext {
            session: observation_session(0x04 | 0x20),
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let response = handle(foreign.as_bytes(), &c);
        assert!(response.contains("\"code\":\"TIMEOUT\""), "{response}");
        // Network scope mismatch.
        let scoped = observation_line(
            "health.get",
            &format!("{{{OBSERVER},\"section\":\"system\",\"network\":\"0000000000000002\"}}"),
        );
        let doc = assert_error_schema(&handle(scoped.as_bytes(), &c), "GATEWAY_UNAVAILABLE");
        assert_eq!(
            doc.get("error")
                .unwrap()
                .get("detail")
                .unwrap()
                .get("reason")
                .and_then(Json::as_str),
            Some("network_mismatch")
        );
        // Matching network passes the gate (then times out with no lane —
        // the wait budget is what proves the gate opened).
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let scoped = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"routes\",\"network\":\"0000000000000001\"}}"),
        );
        let response = handle(scoped.as_bytes(), &c);
        assert!(response.contains("\"code\":\"TIMEOUT\""), "{response}");
    }

    /// Posts one 0x71 page for the single in-flight query and returns the
    /// method response the waiter observed.
    fn drive_observation_once(
        ops: &'static crate::observation::ObservationOps,
        line: &str,
        c: &ApiContext<'_, MemoryOperationStore>,
        page: Vec<u8>,
        received_ms: u64,
    ) -> String {
        drive_observation_once_at(ops, line, c, page, received_ms, 1_060)
    }

    /// Same, with an explicit monotonic receive time (the round trip is
    /// measured against the submit's mono clock, never the wall clock).
    fn drive_observation_once_at(
        ops: &'static crate::observation::ObservationOps,
        line: &str,
        c: &ApiContext<'_, MemoryOperationStore>,
        page: Vec<u8>,
        received_ms: u64,
        received_mono_ms: u64,
    ) -> String {
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| handle(line.as_bytes(), c));
            let request = {
                let mut request = None;
                for _ in 0..500 {
                    if let Some(token) = ops.tokens().first() {
                        // Submitted against the monotonic clock (ctx.now_mono),
                        // never the wall clock the ages render in.
                        assert_eq!(ops.submitted_ms_for(*token), Some(1_000));
                        request = ops.request_for(*token);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                request.expect("the method submits a query")
            };
            assert!(ops.post_reply(request, 0x5e55, page, received_ms, received_mono_ms));
            waiter.join().unwrap()
        })
    }

    /// Posts one 0x31 subtype-8/reject reply for the single in-flight
    /// remote query and returns the method response the waiter observed.
    /// No lane runs, so the row never sends (`radio_queries` 0 — the
    /// lane tests own the sent flag; here the envelope leg and the
    /// section decode are what matter).
    fn drive_remote_observation_once(
        ops: &'static crate::remote_observation::RemoteObservationOps,
        line: &str,
        c: &ApiContext<'_, MemoryOperationStore>,
        reply: Vec<u8>,
        received_ms: u64,
    ) -> String {
        std::thread::scope(|scope| {
            let waiter = scope.spawn(|| handle(line.as_bytes(), c));
            let request = {
                let mut request = None;
                for _ in 0..500 {
                    if let Some(token) = ops.tokens().first() {
                        request = ops.request_for(*token);
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(10));
                }
                request.expect("the method submits a remote query")
            };
            assert!(crate::remote_observation::owns_request(request));
            assert!(ops.post_reply(request, 0x5e55, reply, received_ms, received_ms));
            waiter.join().unwrap()
        })
    }

    fn remote_reply_inner(result: u16, observer: u64, body: &[u8]) -> Vec<u8> {
        use routeloom_protocol::telemetry::SUB_DIAGNOSTIC_RESPONSE;
        let mut inner = vec![0x01, SUB_DIAGNOSTIC_RESPONSE];
        inner.extend_from_slice(&((12 + body.len()) as u16).to_be_bytes());
        inner.extend_from_slice(&result.to_be_bytes());
        inner.extend_from_slice(&observer.to_be_bytes());
        inner.extend_from_slice(&(body.len() as u16).to_be_bytes());
        inner.extend_from_slice(body);
        inner
    }

    // C++-encoded subtype-8 oracle (components/routeloom/src/telemetry.cpp):
    // neighbors, MORE, one entry (peer 2). The observer bytes are patched
    // per test — the gateway here is 0xabc, so foreign means anything else.
    const REMOTE_SNAPSHOT_HEX: &str = "01080000010203040000000000000abc112233445566778805010100a5a5a5a500000000000003e800000000000000020000007800013880000100000607b900";

    #[test]
    fn topology_get_remote_rejects_nonascending_neighbors() {
        use routeloom_protocol::observation::*;
        let (acl, log, store, limiter) = test_env();
        let ops = leaked_remote_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            remote_observation_ops: ops,
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let mut snapshot = hex_bytes(REMOTE_SNAPSHOT_HEX);
        snapshot[8..16].copy_from_slice(&5_u64.to_be_bytes());
        snapshot[26] = 2;
        snapshot.extend_from_slice(&encode_neighbor_detail_entry(&NeighborDetailEntry {
            peer: 1,
            ..NeighborDetailEntry::default()
        }));
        let line = observation_line(
            "topology.get",
            "{\"observer\":\"0000000000000005\",\"section\":\"neighbors\"}",
        );
        let response = drive_remote_observation_once(
            ops,
            &line,
            &c,
            remote_reply_inner(0, 5, &snapshot),
            2_000,
        );
        assert_error_schema(&response, "INDETERMINATE");
    }

    #[test]
    fn topology_get_remote_neighbors_roundtrip() {
        let (acl, log, store, limiter) = test_env();
        let ops: &'static crate::remote_observation::RemoteObservationOps =
            leaked_remote_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            remote_observation_ops: ops,
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let line = observation_line(
            "topology.get",
            "{\"observer\":\"0000000000000005\",\"section\":\"neighbors\"}",
        );
        let mut snapshot = hex_bytes(REMOTE_SNAPSHOT_HEX);
        snapshot[8..16].copy_from_slice(&5_u64.to_be_bytes());
        let response = drive_remote_observation_once(
            ops,
            &line,
            &c,
            remote_reply_inner(0, 5, &snapshot),
            2_000,
        );
        let doc: Json = routeloom_json::parse(&response).unwrap();
        let result = doc.get("result").unwrap();
        assert_eq!(
            result.get("outcome").and_then(Json::as_str),
            Some("snapshot")
        );
        let snap = result.get("snapshot").unwrap();
        assert_eq!(
            snap.get("section").and_then(Json::as_str),
            Some("neighbors")
        );
        let source = snap.get("source").unwrap();
        assert_eq!(
            source.get("transport").and_then(Json::as_str),
            Some("mesh_remote")
        );
        assert_eq!(
            source.get("observer").and_then(Json::as_str),
            Some("0000000000000005")
        );
        assert_eq!(snap.get("radio_queries").and_then(Json::as_u64), Some(0));
        assert_eq!(
            snap.get("sampled_at_device_ms").and_then(Json::as_u64),
            Some(1_000)
        );
        assert_eq!(snap.get("age_ms").and_then(Json::as_u64), Some(1_000));
        assert_eq!(
            snap.get("age_uncertainty_ms").and_then(Json::as_u64),
            Some(1_000)
        );
        assert_eq!(
            snap.get("sampled_unix_ms_earliest").and_then(Json::as_u64),
            Some(1_000)
        );
        assert_eq!(
            snap.get("sampled_unix_ms_latest").and_then(Json::as_u64),
            Some(2_000)
        );
        let entries = snap.get("entries").unwrap().as_array().unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].get("peer").and_then(Json::as_str),
            Some("0000000000000002")
        );
        // MORE with an ascending page: the cursor is the last entry's id.
        assert!(snap
            .get("next_cursor")
            .and_then(Json::as_str)
            .unwrap()
            .contains('.'));
        // The remote age maps onto the host receive time like a local one.
        assert_eq!(
            entries[0].get("last_heard_at_ms").and_then(Json::as_u64),
            Some(1_880)
        );
        let cursor = snap.get("next_cursor").and_then(Json::as_str).unwrap();
        let next_ops = leaked_remote_observation_ops();
        let next_ctx = ApiContext {
            session: c.session,
            remote_observation_ops: next_ops,
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let next_line = observation_line("topology.get", &format!(
            "{{\"observer\":\"0000000000000005\",\"section\":\"neighbors\",\"cursor\":\"{cursor}\"}}"
        ));
        let mut changed = hex_bytes(REMOTE_SNAPSHOT_HEX);
        changed[8..16].copy_from_slice(&5_u64.to_be_bytes());
        changed[28..32].copy_from_slice(&0xb6b6b6b6_u32.to_be_bytes());
        let response = drive_remote_observation_once(
            next_ops,
            &next_line,
            &next_ctx,
            remote_reply_inner(0, 5, &changed),
            2_100,
        );
        assert_error_schema(&response, "SNAPSHOT_CHANGED");
    }

    #[test]
    fn topology_get_refuses_empty_nonterminal_page() {
        let (acl, log, store, limiter) = test_env();
        let ops = leaked_remote_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            remote_observation_ops: ops,
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let line = observation_line(
            "topology.get",
            "{\"observer\":\"0000000000000005\",\"section\":\"neighbors\"}",
        );
        let mut empty = hex_bytes(REMOTE_SNAPSHOT_HEX);
        empty[8..16].copy_from_slice(&5_u64.to_be_bytes());
        empty[26] = 0;
        empty.truncate(40);
        let response =
            drive_remote_observation_once(ops, &line, &c, remote_reply_inner(0, 5, &empty), 2_000);
        assert_error_schema(&response, "SNAPSHOT_CHANGED");
    }

    #[test]
    fn health_get_remote_reject_is_data() {
        let (acl, log, store, limiter) = test_env();
        let ops: &'static crate::remote_observation::RemoteObservationOps =
            leaked_remote_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            remote_observation_ops: ops,
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let line = observation_line(
            "health.get",
            "{\"observer\":\"0000000000000005\",\"section\":\"system\"}",
        );
        // DiagnosticReject NO_PEER for observer 5 (the reason space the
        // device encodes in usb_bridge.cpp).
        let mut reject = hex_bytes("010600000000002a00040000000000000000009900000000");
        reject[12..20].copy_from_slice(&5_u64.to_be_bytes());
        let response =
            drive_remote_observation_once(ops, &line, &c, remote_reply_inner(0, 5, &reject), 2_000);
        let doc: Json = routeloom_json::parse(&response).unwrap();
        let result = doc.get("result").unwrap();
        assert_eq!(result.get("outcome").and_then(Json::as_str), Some("reject"));
        let rendered = result.get("reject").unwrap();
        assert_eq!(
            rendered.get("reason").and_then(Json::as_str),
            Some("NO_PEER")
        );
        // The refusal is negative-cached: the same call costs no radio
        // and no lane — it resolves from the cache immediately.
        let again = handle(line.as_bytes(), &c);
        assert_eq!(
            routeloom_json::parse(&again)
                .unwrap()
                .get("result")
                .unwrap()
                .get("outcome")
                .and_then(Json::as_str),
            Some("reject")
        );
    }

    #[test]
    fn topology_get_remote_subscribe_is_refused() {
        let (acl, log, store, limiter) = test_env();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            ..ctx(Some(501), &acl, &log, &store, &limiter, 1_000)
        };
        let line = observation_line(
            "topology.get",
            "{\"observer\":\"0000000000000005\",\"section\":\"neighbors\",\"subscribe\":true}",
        );
        let doc = assert_error_schema(&handle(line.as_bytes(), &c), "INVALID_ARGUMENT");
        assert!(
            doc.get("error")
                .unwrap()
                .get("detail")
                .unwrap()
                .get("message")
                .and_then(Json::as_str)
                .unwrap()
                .contains("pull-only"),
            "{doc:?}"
        );
    }

    #[test]
    fn health_get_roundtrip_serves_and_caches() {
        use routeloom_protocol::observation::*;
        let (acl, log, store, limiter) = test_env();
        let ops: &'static crate::observation::ObservationOps = leaked_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            observation_ops: ops,
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let body = encode_observation_system(&ObservationSystem {
            uptime_ms: 400,
            heap_free_bytes: 100,
            heap_min_bytes: 90,
            heap_largest_bytes: 80,
            reset_code: 3,
            power_mode: 1,
            coord_mode: 3,
            sec_profile: 1,
        });
        let page = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_SYSTEM,
                flags: 0,
                count: 1,
                boot_id: 0xB007,
                revision: 0,
                next_after: 0,
            },
            &body,
        )
        .unwrap();
        let line = observation_line("health.get", &format!("{{{OBSERVER}}}"));
        let response = drive_observation_once(ops, &line, &c, page, 1_000);
        let parsed = routeloom_json::parse(&response).unwrap();
        let result = parsed.get("result").expect("ok result");
        assert_eq!(
            result.get("outcome").and_then(Json::as_str),
            Some("snapshot")
        );
        let snapshot = result.get("snapshot").unwrap();
        assert_eq!(
            snapshot.get("section").and_then(Json::as_str),
            Some("system")
        );
        assert_eq!(
            snapshot
                .get("source")
                .unwrap()
                .get("observer_boot")
                .and_then(Json::as_str),
            Some("000000000000b007")
        );
        assert_eq!(
            snapshot
                .get("system")
                .unwrap()
                .get("uptime_ms")
                .and_then(Json::as_u64),
            Some(400)
        );
        // The clock mapping: wall receive renders the ages, mono receive
        // plus the submit→receive round trip bounds the mapping.
        assert_eq!(
            snapshot.get("received_unix_ms").and_then(Json::as_u64),
            Some(1_000)
        );
        assert_eq!(
            snapshot.get("received_mono_ms").and_then(Json::as_u64),
            Some(1_060)
        );
        assert_eq!(snapshot.get("rtt_ms").and_then(Json::as_u64), Some(60));
        assert_eq!(
            snapshot
                .get("system")
                .unwrap()
                .get("reset")
                .unwrap()
                .get("name")
                .and_then(Json::as_str),
            Some("watchdog")
        );
        // Second call within max_age: served from cache, no new submit.
        let response = handle(line.as_bytes(), &c);
        assert!(response.contains("\"outcome\":\"snapshot\""), "{response}");
        assert!(ops.tokens().is_empty());
        // max_age_ms:0 bypasses the cache: a fresh submit appears (and
        // times out with no lane driving it).
        let fresh = observation_line("health.get", &format!("{{{OBSERVER},\"max_age_ms\":0}}"));
        let response = handle(fresh.as_bytes(), &c);
        assert!(response.contains("\"code\":\"TIMEOUT\""), "{response}");
    }

    #[test]
    fn topology_get_routes_pages_and_exact() {
        use routeloom_protocol::observation::*;
        let (acl, log, store, limiter) = test_env();
        let ops: &'static crate::observation::ObservationOps = leaked_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            observation_ops: ops,
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let entry = |destination: u64, valid: bool| RouteDetailEntry {
            destination,
            next_hop: 2,
            generation: 1,
            sequence: 9,
            metric: 3,
            valid,
            remaining_ms: 500,
        };
        let mut body = encode_route_detail_entry(&entry(2, true));
        body.extend_from_slice(&encode_route_detail_entry(&entry(3, false)));
        let page = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_ROUTES,
                flags: PAGE_MORE,
                count: 2,
                boot_id: 0xB007,
                revision: 0x1122_3344,
                next_after: 3,
            },
            &body,
        )
        .unwrap();
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"routes\"}}"),
        );
        let response = drive_observation_once(ops, &line, &c, page, 1_000);
        let parsed = routeloom_json::parse(&response).unwrap();
        let snapshot = parsed.get("result").unwrap().get("snapshot").unwrap();
        assert_eq!(
            snapshot.get("complete").and_then(Json::as_bool),
            Some(false)
        );
        assert!(snapshot
            .get("next_cursor")
            .and_then(Json::as_str)
            .unwrap()
            .starts_with("0000000000000003.11223344."));
        assert_eq!(
            snapshot.get("revision").and_then(Json::as_u64),
            Some(0x1122_3344)
        );
        let entries = snapshot.get("entries").unwrap().as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].get("next_hop").and_then(Json::as_str),
            Some("0000000000000002")
        );
        assert_eq!(entries[1].get("valid").and_then(Json::as_bool), Some(false));
        assert!(entries[1].get("next_hop").unwrap().is_null());
        // Exact destination with no selection: present:false.
        let empty = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_ROUTES,
                flags: 0,
                count: 0,
                boot_id: 0xB007,
                revision: 0x1122_3344,
                next_after: 9,
            },
            &[],
        )
        .unwrap();
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"routes\",\"destination\":\"0000000000000009\"}}"),
        );
        let response = drive_observation_once(ops, &line, &c, empty, 1_000);
        assert!(response.contains("\"present\":false"), "{response}");
        // Routes pages are never cached: every call queries.
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"routes\"}}"),
        );
        let response = handle(line.as_bytes(), &c);
        assert!(response.contains("\"code\":\"TIMEOUT\""), "{response}");
    }

    #[test]
    fn topology_get_rejects_a_page_that_repeats_the_cursor() {
        use routeloom_protocol::observation::*;
        let (acl, log, store, limiter) = test_env();
        let ops = leaked_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            observation_ops: ops,
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let cursor = ObservationCursor {
            after: 2,
            revision: 7,
            observer_boot: 0xB007,
            gateway_boot: 0xB007,
            session: 0x5e55,
            observer: 0x0abc,
            section: SECTION_ROUTES,
        }
        .encode();
        let mut body = encode_route_detail_entry(&RouteDetailEntry {
            destination: 2,
            next_hop: 2,
            valid: true,
            ..RouteDetailEntry::default()
        });
        body.extend_from_slice(&encode_route_detail_entry(&RouteDetailEntry {
            destination: 3,
            next_hop: 2,
            valid: true,
            ..RouteDetailEntry::default()
        }));
        let page = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_ROUTES,
                flags: 0,
                count: 2,
                boot_id: 0xB007,
                revision: 7,
                next_after: 3,
            },
            &body,
        )
        .unwrap();
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"routes\",\"cursor\":\"{cursor}\"}}"),
        );
        let response = drive_observation_once(ops, &line, &c, page, 1_000);
        assert_error_schema(&response, "SNAPSHOT_CHANGED");
    }

    #[test]
    fn topology_get_exact_rejects_another_destination() {
        use routeloom_protocol::observation::*;
        let (acl, log, store, limiter) = test_env();
        let ops = leaked_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            observation_ops: ops,
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let body = encode_route_detail_entry(&RouteDetailEntry {
            destination: 2,
            next_hop: 2,
            valid: true,
            ..RouteDetailEntry::default()
        });
        let page = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_ROUTES,
                flags: 0,
                count: 1,
                boot_id: 0xB007,
                revision: 7,
                next_after: 2,
            },
            &body,
        )
        .unwrap();
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"routes\",\"destination\":\"0000000000000009\"}}"),
        );
        let response = drive_observation_once(ops, &line, &c, page, 1_000);
        assert_error_schema(&response, "INDETERMINATE");
    }

    #[test]
    fn health_get_rejects_a_different_gateway_boot() {
        use routeloom_protocol::observation::*;
        let (acl, log, store, limiter) = test_env();
        let ops = leaked_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            observation_ops: ops,
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let body = encode_observation_system(&ObservationSystem::default());
        let page = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_SYSTEM,
                flags: 0,
                count: 1,
                boot_id: 0xB008,
                revision: 0,
                next_after: 0,
            },
            &body,
        )
        .unwrap();
        let line = observation_line("health.get", &format!("{{{OBSERVER}}}"));
        let response = drive_observation_once(ops, &line, &c, page, 1_000);
        assert_error_schema(&response, "GATEWAY_UNAVAILABLE");
    }

    #[test]
    fn topology_get_neighbors_pages_and_exact() {
        use routeloom_protocol::observation::*;
        let (acl, log, store, limiter) = test_env();
        let ops: &'static crate::observation::ObservationOps = leaked_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            observation_ops: ops,
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        let bound = NeighborDetailEntry {
            peer: 2,
            heard_age_ms: 120,
            lease_remaining_ms: 80_000,
            link_cost: 1,
            rssi_ewma_q8_8: -70 * 256,
            phase: 6,
            flags: NBR_ACTIVE | NBR_RSSI_VALID | NBR_HEARD_VALID,
            rssi_last_dbm: -71,
        };
        let bare = NeighborDetailEntry {
            peer: 3,
            heard_age_ms: AGE_UNKNOWN,
            lease_remaining_ms: AGE_UNKNOWN,
            link_cost: 2,
            ..NeighborDetailEntry::default()
        };
        let mut body = encode_neighbor_detail_entry(&bound);
        body.extend_from_slice(&encode_neighbor_detail_entry(&bare));
        let page = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_NEIGHBORS,
                flags: PAGE_MORE,
                count: 2,
                boot_id: 0xB007,
                revision: 0xA5A5_A5A5,
                next_after: 3,
            },
            &body,
        )
        .unwrap();
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"neighbors\"}}"),
        );
        let response = drive_observation_once(ops, &line, &c, page, 1_000);
        let parsed = routeloom_json::parse(&response).unwrap();
        let snapshot = parsed.get("result").unwrap().get("snapshot").unwrap();
        assert_eq!(
            snapshot.get("section").and_then(Json::as_str),
            Some("neighbors")
        );
        assert!(snapshot
            .get("next_cursor")
            .and_then(Json::as_str)
            .unwrap()
            .starts_with("0000000000000003.a5a5a5a5."));
        let entries = snapshot.get("entries").unwrap().as_array().unwrap();
        assert_eq!(entries.len(), 2);
        assert_eq!(
            entries[0].get("peer").and_then(Json::as_str),
            Some("0000000000000002")
        );
        assert_eq!(
            entries[0]
                .get("phase")
                .unwrap()
                .get("name")
                .and_then(Json::as_str),
            Some("reachable")
        );
        assert_eq!(
            entries[0].get("lease_remaining_ms").and_then(Json::as_u64),
            Some(80_000)
        );
        assert_eq!(
            entries[0].get("last_heard_at_ms").and_then(Json::as_u64),
            Some(880)
        );
        // The bare row carries no evidence: nulls, never zeros.
        assert!(entries[1].get("rssi_last_dbm").unwrap().is_null());
        assert!(entries[1].get("last_heard_at_ms").unwrap().is_null());
        assert!(entries[1].get("lease_remaining_ms").unwrap().is_null());
        // Exact peer with no neighbor record: present:false.
        let empty = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_NEIGHBORS,
                flags: 0,
                count: 0,
                boot_id: 0xB007,
                revision: 0xA5A5_A5A5,
                next_after: 9,
            },
            &[],
        )
        .unwrap();
        let line = observation_line(
            "topology.get",
            &format!(
                "{{{OBSERVER},\"section\":\"neighbors\",\"destination\":\"0000000000000009\"}}"
            ),
        );
        let response = drive_observation_once(ops, &line, &c, empty, 1_000);
        assert!(response.contains("\"present\":false"), "{response}");
        // Neighbors pages are never cached: every call queries.
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"neighbors\"}}"),
        );
        let response = handle(line.as_bytes(), &c);
        assert!(response.contains("\"code\":\"TIMEOUT\""), "{response}");
    }

    #[test]
    fn topology_get_rejects_bad_cursor() {
        let (acl, log, store, limiter) = test_env();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        for params in [
            format!("{{{OBSERVER}}}"),
            format!("{{{OBSERVER},\"section\":\"routes\",\"cursor\":\"ffffffffffffffff\"}}"),
            format!("{{{OBSERVER},\"section\":\"routes\",\"cursor\":\"zz\"}}"),
            format!("{{{OBSERVER},\"section\":\"routes\",\"destination\":\"0000000000000000\"}}"),
            format!(
                "{{{OBSERVER},\"section\":\"routes\",\"destination\":\"0000000000000009\",\"cursor\":\"0000000000000001\"}}"
            ),
            format!("{{{OBSERVER},\"section\":\"summary\",\"cursor\":\"0000000000000001\"}}"),
            format!("{{{OBSERVER},\"section\":\"routes\",\"bogus\":1}}"),
        ] {
            let response = handle(observation_line("topology.get", &params).as_bytes(), &c);
            assert!(
                response.contains("\"code\":\"INVALID_ARGUMENT\""),
                "{params}: {response}"
            );
        }
        // neighbors is a real section now: the call queries the device
        // (TIMEOUT with no reply posted) instead of UNSUPPORTED.
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"neighbors\"}}"),
        );
        assert_error_schema(&handle(line.as_bytes(), &c), "TIMEOUT");
    }

    #[test]
    fn observation_device_outcomes_map_honestly() {
        use routeloom_protocol::observation::*;
        let (acl, log, store, limiter) = test_env();
        let ops: &'static crate::observation::ObservationOps = leaked_observation_ops();
        let c = ApiContext {
            session: observation_session(0xFFFF_FFFF),
            observation_ops: ops,
            ..ctx(None, &acl, &log, &store, &limiter, 1_000)
        };
        // A summary page round-trips through the cache path.
        let summary = encode_observation_summary(&ObservationSummary {
            neighbor_digest: 0xA5A5_A5A5,
            route_digest: 0x5A5A_5A5A,
            milestone_gen: 7,
            ..ObservationSummary::default()
        });
        let page = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_OK,
                section: SECTION_SUMMARY,
                flags: PAGE_ARMED,
                count: 1,
                boot_id: 0xB007,
                revision: 0x5A5A_5A5A,
                next_after: 0,
            },
            &summary,
        )
        .unwrap();
        let line = observation_line(
            "topology.get",
            &format!("{{{OBSERVER},\"section\":\"summary\"}}"),
        );
        let response = drive_observation_once(ops, &line, &c, page, 1_000);
        assert!(response.contains("\"milestone_gen\":7"), "{response}");
        assert!(response.contains("\"armed\":true"), "{response}");
        // A device refusal arrives as its honest error, with the device
        // result attached.
        let refused = encode_observation_page(
            &ObservationPageHeader {
                result: RESULT_UNSUPPORTED,
                section: SECTION_TABLES,
                flags: 0,
                count: 0,
                boot_id: 0xB007,
                revision: 0,
                next_after: 0,
            },
            &[],
        )
        .unwrap();
        let line = observation_line(
            "health.get",
            &format!("{{{OBSERVER},\"section\":\"tables\",\"max_age_ms\":0}}"),
        );
        let response = drive_observation_once(ops, &line, &c, refused, 1_000);
        let doc = assert_error_schema(&response, "UNSUPPORTED");
        assert_eq!(
            doc.get("error")
                .unwrap()
                .get("detail")
                .unwrap()
                .get("device_result")
                .and_then(Json::as_str),
            Some("UNSUPPORTED")
        );
    }

    // --- Bench (RLB1) commands through API1 + HostOps (design-devflow §5) ---
    // firmware/bench_node speaks RLB1 as the application payload. This
    // harness drives a command down the real daemon path — API1
    // messages.submit -> operation store -> Dispatcher -> HostOps SUBMIT
    // body -> receipt -> operations.get — and the device's reply back
    // through the receive log -> messages.read -> bench codec. Neither leg
    // is replayed from goldens: every byte crosses the interfaces the
    // daemon uses in production.

    use routeloom_protocol::bench;

    /// Hex-decode the `payload_hex` field of one messages.read record.
    fn read_payload(response: &str) -> (String, Vec<u8>) {
        let parsed = routeloom_json::parse(response).unwrap();
        let records = parsed
            .get("result")
            .and_then(|r| r.get("records"))
            .expect("records member");
        let Json::Array(list) = records else {
            panic!("records is not an array: {response}")
        };
        assert!(!list.is_empty(), "expected at least one record: {response}");
        let record = &list[list.len() - 1];
        let origin = record
            .get("origin")
            .and_then(Json::as_str)
            .unwrap_or_default()
            .to_string();
        let text = record
            .get("payload_hex")
            .and_then(Json::as_str)
            .expect("payload_hex");
        let mut payload = Vec::with_capacity(text.len() / 2);
        let bytes = text.as_bytes();
        for i in (0..bytes.len()).step_by(2) {
            payload.push(
                u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap(), 16).unwrap(),
            );
        }
        (origin, payload)
    }

    fn bench_acl() -> Acl {
        Acl::parse(
            "{\"principals\":{\"501\":{\"networks\":{\"0000000000000001\":[\"SEND\",\"READ_OPERATION\",\"READ_PAYLOAD\"]}}}}",
        )
        .unwrap()
    }

    fn bench_submit(epoch: &str, key: &str, dest: &str, payload: &[u8]) -> String {
        format!(
            "{{\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"{dest}\"}},\"payload_hex\":\"{}\",\"payload_len\":{},\"options\":{{\"storage\":\"RAM_ONLY\"}}}}}}",
            hex_lower(payload),
            payload.len(),
        )
    }

    /// Drive the operation store's queued records to a HostOps SUBMIT and
    /// return the emitted request. Mirrors the dispatcher's own test driver:
    /// lease change emits a floor probe and a time sample, both answered,
    /// then the dispatch pass emits SUBMIT.
    fn drive_to_submit_request(
        dispatcher: &mut crate::dispatch::Dispatcher,
        store: &mut MemoryOperationStore,
        link: &crate::dispatch::LinkSnapshot,
        now: u64,
    ) -> crate::dispatch::DispatchRequest {
        use routeloom_protocol::host_ops;
        let out = dispatcher.tick_mono(store, link, now, now);
        let retire = out
            .iter()
            .find(|r| r.body[1] == host_ops::SUB_RETIRE_THROUGH)
            .expect("floor probe emitted");
        let sample = out
            .iter()
            .find(|r| r.body[1] == host_ops::SUB_TIME_SAMPLE)
            .expect("time sample emitted");
        let retire_req = retire.request;
        let sample_req = sample.request;
        let nonce = host_ops::decode_time_sample_request(&sample.body)
            .unwrap()
            .nonce;
        let lease = routeloom_protocol::host_ops::BootLease::derive(link.boot, link.node);
        dispatcher.handle_reply(
            store,
            retire_req,
            &host_ops::encode_retire_response(&host_ops::RetireResponse {
                result: host_ops::HostOpsResult::Ok,
                lease,
                retired_through: 0,
            }),
            now + 5,
        );
        dispatcher.handle_reply(
            store,
            sample_req,
            &host_ops::encode_time_sample_response(&host_ops::TimeSampleResponse {
                result: host_ops::HostOpsResult::Ok,
                lease,
                nonce,
                device_time: 42_000,
            }),
            now + 5,
        );
        dispatcher
            .tick_mono(store, link, now + 10, now + 10)
            .into_iter()
            .find(|r| r.body[1] == host_ops::SUB_SUBMIT)
            .expect("submit emitted")
    }

    /// The node-destination canonical body: 26B head + payload
    /// (canonical.rs §schema-1), so the application payload starts at 26.
    fn canonical_payload(canonical_bytes: &[u8]) -> &[u8] {
        assert_eq!(canonical_bytes[0], canonical::SCHEMA_VERSION);
        let len = u16::from_be_bytes([canonical_bytes[24], canonical_bytes[25]]) as usize;
        assert_eq!(canonical_bytes.len(), 26 + len, "canonical length field");
        &canonical_bytes[26..]
    }

    #[test]
    fn bench_echo_command_round_trips_api1_host_ops() {
        use routeloom_protocol::host_ops;

        let acl = bench_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));
        let epoch = open_test_epoch(&acl, &log, &store, &limiter);

        // A real RLB1 ECHO_REQUEST addressed at bench node 3.
        let mut run = [0u8; 16];
        run[0] = 0x52;
        run[1] = 0x55;
        run[15] = 0x42;
        let wire = bench::encode(bench::Opcode::EchoRequest, 0, &run, 7, b"ping").unwrap();
        let line = bench_submit(
            &epoch,
            "00112233445566778899aabbccddeeff",
            "0000000000000003",
            &wire,
        );
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 0);
        let response = handle(line.as_bytes(), &c);
        assert!(response.contains("\"ok\":true"), "{response}");
        let operation_id = result_field(&response, "operation_id");

        // The dispatcher emits a HostOps SUBMIT whose canonical carries the
        // RLB1 frame unchanged — decode at both layers to prove it.
        let mut dispatcher = crate::dispatch::Dispatcher::new([7; 16]);
        let link = crate::dispatch::LinkSnapshot {
            active: true,
            host_ops: true,
            gateway_ops: true,
            config_ops: true,
            session: 0,
            host_boot: 0x99,
            node: 0x0abc,
            boot: 7,
            network: 1,
            rx_assurance: false,
        };
        let submit = {
            let mut guard = store.lock().unwrap();
            drive_to_submit_request(&mut dispatcher, &mut guard, &link, 1_000)
        };
        let parsed = host_ops::decode_submit(&submit.body).unwrap();
        let payload = canonical_payload(&parsed.canonical).to_vec();
        let msg = bench::decode(&payload).expect("canonical payload is RLB1");
        assert_eq!(msg.opcode, bench::Opcode::EchoRequest as u8);
        assert_eq!(msg.sequence, 7);
        assert_eq!(msg.run, run);
        assert_eq!(msg.body, b"ping");

        // The gateway accepted the position: a receipt resolves the
        // operation, and API1 operations.get reports committed state.
        let hash = canonical::sha256(&parsed.canonical);
        {
            let mut guard = store.lock().unwrap();
            dispatcher.handle_reply(
                &mut *guard,
                submit.request,
                &host_ops::encode_receipt(&host_ops::Receipt {
                    sub: host_ops::SUB_SUBMIT,
                    result: host_ops::HostOpsResult::Ok,
                    state: host_ops::SlotState::Sent,
                    lease: routeloom_protocol::host_ops::BootLease::derive(link.boot, link.node),
                    dispatch_seq: parsed.dispatch_seq,
                    hash,
                    msg_session: 9,
                    msg_seq: 77,
                    msg_valid: true,
                    evidence: host_ops::Evidence::GatewayAccepted,
                }),
                1_020,
            );
        }
        let get = format!(
            "{{\"v\":1,\"request_id\":\"g\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{operation_id}\"}}}}"
        );
        let response = handle(
            get.as_bytes(),
            &ctx(Some(501), &acl, &log, &store, &limiter, 1_050),
        );
        assert!(
            response.contains("\"dispatch_state\":\"GATEWAY_ACCEPTED\""),
            "{response}"
        );
        assert!(response.contains("GATEWAY_ACCEPTED"), "{response}");

        // The bench node's ECHO_REPLY arrives as a scope-1 ingress record:
        // the daemon stores the raw application payload, and messages.read
        // returns it byte-identical for the bench codec to decode.
        let reply = bench::encode(
            bench::Opcode::EchoReply,
            bench::FLAG_RESPONSE,
            &run,
            7,
            b"ping",
        )
        .unwrap();
        log.lock().unwrap().ingest(
            Ingress {
                network: 1,
                gateway: Some(2),
                origin: 3,
                msg_session: 5,
                msg_seq: 88,
                payload: reply,
                assurance: None,
            },
            1_100,
        );
        let response = handle(
            b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
            &ctx(Some(501), &acl, &log, &store, &limiter, 1_100),
        );
        let (origin, payload) = read_payload(&response);
        assert_eq!(origin, "0000000000000003");
        let reply_msg = bench::decode(&payload).expect("read payload is RLB1");
        assert_eq!(reply_msg.opcode, bench::Opcode::EchoReply as u8);
        assert_ne!(reply_msg.flags & bench::FLAG_RESPONSE, 0);
        assert_eq!(reply_msg.sequence, 7);
        assert_eq!(reply_msg.run, run);
        assert_eq!(reply_msg.body, b"ping");
    }

    #[test]
    fn bench_stale_notice_and_malformed_via_api1_read() {
        let acl = bench_acl();
        let log = Mutex::new(ReceiveLog::new([9; 16]));
        let store = Mutex::new(MemoryOperationStore::new([0xab; 16]));
        let limiter = Mutex::new(AdmissionLimiter::new(0));

        // A post-reset destination's stale COUNT_STATUS: the daemon must
        // deliver it untouched so the controller sees the STALE_BOOT state
        // (the source-side run then closes unknown, never restarts).
        let mut run = [0u8; 16];
        run[0] = 0x52;
        run[1] = 0x55;
        run[15] = 0x43;
        let stale_body = bench::encode_count_status(&bench::CountStatusBody {
            state: bench::count_state::STALE_BOOT,
            ..bench::CountStatusBody::default()
        });
        let stale_wire = bench::encode(
            bench::Opcode::CountStatus,
            bench::FLAG_RESPONSE | bench::FLAG_LATE,
            &run,
            9,
            &stale_body,
        )
        .unwrap();
        // Garbage that is not RLB1 at all — corrupted on the wire or a
        // non-bench payload; the log stores it verbatim either way. Long
        // enough to reach the magic check rather than stopping at truncated.
        let garbage = vec![0xde; 36];
        {
            let mut guard = log.lock().unwrap();
            guard.ingest(
                Ingress {
                    network: 1,
                    gateway: Some(2),
                    origin: 3,
                    msg_session: 5,
                    msg_seq: 90,
                    payload: stale_wire,
                    assurance: None,
                },
                1_000,
            );
            guard.ingest(
                Ingress {
                    network: 1,
                    gateway: Some(2),
                    origin: 3,
                    msg_session: 5,
                    msg_seq: 91,
                    payload: garbage,
                    assurance: None,
                },
                1_001,
            );
        }
        let c = ctx(Some(501), &acl, &log, &store, &limiter, 1_010);
        let response = handle(
            b"{\"v\":1,\"request_id\":\"r\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
            &c,
        );
        let parsed = routeloom_json::parse(&response).unwrap();
        let Json::Array(records) = parsed
            .get("result")
            .and_then(|r| r.get("records"))
            .expect("records member")
        else {
            panic!("records is not an array: {response}")
        };
        assert_eq!(records.len(), 2, "{response}");
        let decode_at = |index: usize| {
            let hex = records[index]
                .get("payload_hex")
                .and_then(Json::as_str)
                .expect("payload_hex");
            let mut payload = Vec::with_capacity(hex.len() / 2);
            let bytes = hex.as_bytes();
            for i in (0..bytes.len()).step_by(2) {
                payload.push(
                    u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap(), 16).unwrap(),
                );
            }
            payload
        };
        let stale_payload = decode_at(0);
        let stale = bench::decode(&stale_payload).expect("stale notice is RLB1");
        assert_eq!(stale.opcode, bench::Opcode::CountStatus as u8);
        assert_ne!(stale.flags & bench::FLAG_LATE, 0);
        assert_eq!(
            bench::decode_count_status(stale.body).unwrap().state,
            bench::count_state::STALE_BOOT
        );
        // Corrupt payload: honest codec verdict, never silently dropped or
        // re-interpreted.
        assert_eq!(
            bench::decode(&decode_at(1)),
            Err(bench::DecodeError::BadMagic)
        );
    }
}
