//! API1 surface of the Site Authority (docs/design/sdk-v1/07 §2, plan
//! P3-3, G-SEC P5): `site.status`, `join.policy.get/set`,
//! `join.requests.list`, `join.decide`, `devices.discovered.list`,
//! `members.list/get`, `membership.revoke`, `membership.cutover`,
//! `group_keys.status/rotate`, and `operations.get` for `op-` tokens.
//!
//! Authorization (07 §2): `MEMBERSHIP_READ` for the read side,
//! `MEMBERSHIP_DECIDE` for `join.decide` / `membership.revoke`,
//! `MEMBERSHIP_ADMIN` for the policy, `membership.cutover` and
//! `group_keys.rotate`. The network
//! the ACL is checked on is the site's wire network (network_low32 of the
//! SiteCert). The principal comes from the socket peer credential only;
//! idempotency identity is `(principal, idempotency_key)`.
//!
//! Every successful call appends the authority's events (`join.decided`,
//! `member.revoked`, …) to the daemon event ring — the `stream:"events"`
//! subscribe source — after the authority lock is released.

use routeloom_json::Json;

use super::{ApiContext, ApiError};
use crate::acl;
use crate::send_store::OperationStore;
use crate::site::group_keys::HostTime;
use crate::site::records::{parse_op_token, parse_request_token, parse_role, Verdict};
use crate::site::{
    parse_reason, CutoverRequest, DecideRequest, DecisionMode, Events, PolicyPatch, RevokeRequest,
    RotateRequest, SiteError, SiteService,
};

/// `limit` ceiling of the paged site listings.
pub const SITE_PAGE_MAX: usize = 128;

/// Kinds the Site Authority appends to the event ring (also accepted by
/// `messages.subscribe {stream:"events", filter:{kinds:[...]}}`).
pub const SITE_EVENT_KINDS: &[&str] = &[
    "authority.channel_lost",
    "authority.channel_ready",
    "authority.passthrough",
    "authority.pull",
    "authority.pull_throttled",
    "join.request",
    "join.decided",
    "join_relay_failed",
    "device.discovered",
    "member.reissued",
    "member.confirmed",
    "member.revoked",
    "member.removal_notified",
    "rrs.published",
    "cutover.progress",
    "gk.staged",
    "gk.rotated",
    "gk.member_applied",
    "authority.error",
    "site.session_drop",
];

pub const SITE_METHODS: &[&str] = &[
    "site.status",
    "join.policy.get",
    "join.policy.set",
    "join.requests.list",
    "join.decide",
    "devices.discovered.list",
    "members.list",
    "members.get",
    "membership.revoke",
    "membership.cutover",
    "group_keys.status",
    "group_keys.rotate",
];

impl From<SiteError> for ApiError {
    fn from(error: SiteError) -> Self {
        Self {
            code: error.code,
            message: error.message,
            extra_fields: error.extra,
            retryable: error.retryable,
        }
    }
}

/// Appends authority events to the daemon ring (same discipline as
/// `push_event`: seq allocated under the ring lock, hub woken after).
pub(super) fn push_events<S: OperationStore>(ctx: &ApiContext<'_, S>, events: Events) {
    if events.is_empty() {
        return;
    }
    {
        let mut ring = ctx.event_ring.events.lock().expect("events poisoned");
        for (ms, fields) in events {
            let kind = crate::event_kind(&fields);
            let seq = ctx
                .event_ring
                .next_seq
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            let json = format!("{{\"seq\":{seq},\"ms\":{ms},{fields}}}");
            if ring.len() >= crate::MAX_EVENTS {
                ring.pop_front();
                ctx.event_ring
                    .dropped
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            }
            ring.push_back(crate::Event { seq, kind, json });
        }
    }
    ctx.subscriptions.notify();
}

fn service<'a, S: OperationStore>(ctx: &ApiContext<'a, S>) -> Result<&'a SiteService, ApiError> {
    ctx.site.ok_or_else(|| {
        ApiError::simple(
            "SITE_AUTHORITY_UNAVAILABLE",
            "this daemon runs no Site Authority (start it with --site-authority DIR)",
        )
    })
}

/// The principal, if it holds `permission` on the site network.
fn authorize<S: OperationStore>(
    ctx: &ApiContext<'_, S>,
    service: &SiteService,
    permission: u8,
    name: &str,
) -> Result<u32, ApiError> {
    let network = service.acl_network();
    ctx.uid
        .filter(|uid| ctx.acl.permit(*uid, network, permission))
        .ok_or_else(|| {
            ApiError::simple(
                "AuthorizationFailed",
                &format!("principal lacks {name} on the site network"),
            )
        })
}

fn only(params: &Json, allowed: &[&str]) -> Result<(), ApiError> {
    for (key, _) in params.object_entries() {
        if !allowed.contains(&key.as_str()) {
            return Err(ApiError::simple(
                "INVALID_ARGUMENT",
                &format!("unknown param \"{key}\""),
            ));
        }
    }
    Ok(())
}

fn device_id(params: &Json) -> Result<u64, ApiError> {
    params
        .get("device_id")
        .and_then(Json::as_str)
        .and_then(|t| super::parse_hex_u64(&t.to_ascii_lowercase()))
        .ok_or_else(|| ApiError::simple("INVALID_ARGUMENT", "device_id must be a 16-hex node id"))
}

fn idempotency_key(params: &Json) -> Result<String, ApiError> {
    let key = params
        .get("idempotency_key")
        .and_then(Json::as_str)
        .unwrap_or("");
    if key.is_empty() || key.len() > 64 || !key.bytes().all(|b| (0x21..=0x7e).contains(&b)) {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "idempotency_key must be 1-64 printable ASCII characters without spaces",
        ));
    }
    Ok(key.to_string())
}

fn paging(params: &Json) -> Result<(Option<u64>, usize), ApiError> {
    let after = match params.get("after") {
        None | Some(Json::Null) => None,
        Some(value) => Some(
            value
                .as_str()
                .and_then(|t| super::parse_hex_u64(&t.to_ascii_lowercase()))
                .ok_or_else(|| {
                    ApiError::simple("INVALID_ARGUMENT", "after must be a 16-hex node id")
                })?,
        ),
    };
    let limit = match params.get("limit") {
        None => SITE_PAGE_MAX,
        Some(value) => value
            .as_u64()
            .filter(|n| (1..=SITE_PAGE_MAX as u64).contains(n))
            .ok_or_else(|| {
                ApiError::simple(
                    "INVALID_ARGUMENT",
                    &format!("limit must be 1..={SITE_PAGE_MAX}"),
                )
            })? as usize,
    };
    Ok((after, limit))
}

/// Dispatches one site method; `None` when `method` is not one of them.
pub(super) fn dispatch<S: OperationStore>(
    method: &str,
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Option<Result<String, ApiError>> {
    let handler: fn(&Json, &ApiContext<'_, S>) -> Result<String, ApiError> = match method {
        "site.status" => site_status,
        "join.policy.get" => policy_get,
        "join.policy.set" => policy_set,
        "join.requests.list" => requests_list,
        "join.decide" => join_decide,
        "devices.discovered.list" => discovered_list,
        "members.list" => members_list,
        "members.get" => members_get,
        "membership.revoke" => membership_revoke,
        "membership.cutover" => membership_cutover,
        "group_keys.status" => group_keys_status,
        "group_keys.rotate" => group_keys_rotate,
        _ => return None,
    };
    Some(handler(params, ctx))
}

fn site_status<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(params, &[])?;
    let service = service(ctx)?;
    authorize(ctx, service, acl::PERM_MEMBERSHIP_READ, "MEMBERSHIP_READ")?;
    let time = HostTime {
        mono_ms: ctx.now_mono,
        unix_ms: ctx.now_ms,
    };
    let (status, events) = service.with(|a| a.status_json(time));
    push_events(ctx, events);
    // The USB link view (gateway attachment) comes from the daemon, not the
    // authority: `usb.attached` says a gateway session is up at all, and
    // `usb.join_relay` says the site lane can serve joins on it — the same
    // gate the lane applies (authenticated + CAP_JOIN_RELAY_V1).
    let attached =
        ctx.session.lock().expect("session poisoned").node.is_some() && ctx.link.connected;
    let join_relay = join_relay_status(ctx);
    Ok(format!(
        "{},\"usb\":{{\"configured\":{},\"attached\":{attached},\"join_relay\":\"{join_relay}\"}}}}",
        &status[..status.len() - 1],
        ctx.link.configured
    ))
}

fn policy_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(params, &[])?;
    let service = service(ctx)?;
    authorize(ctx, service, acl::PERM_MEMBERSHIP_ADMIN, "MEMBERSHIP_ADMIN")?;
    Ok(service.with(|a| a.policy().json()).0)
}

fn policy_set<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(
        params,
        &[
            "zero_touch_open",
            "decision_mode",
            "decision_timeout_ms",
            "pending_retry_after_s",
        ],
    )?;
    let service = service(ctx)?;
    authorize(ctx, service, acl::PERM_MEMBERSHIP_ADMIN, "MEMBERSHIP_ADMIN")?;
    let invalid = |m: &str| ApiError::simple("INVALID_ARGUMENT", m);
    // Parse into a patch WITHOUT reading the policy: the read-modify-write
    // below runs inside one authority lock, so a concurrent partial update
    // cannot slip between our read and our write.
    let mut patch = PolicyPatch::default();
    if let Some(value) = params.get("zero_touch_open") {
        patch.zero_touch_open = Some(
            value
                .as_bool()
                .ok_or_else(|| invalid("zero_touch_open must be a boolean"))?,
        );
    }
    if let Some(value) = params.get("decision_mode") {
        patch.decision_mode = Some(match value.as_str() {
            Some("kguard") => DecisionMode::Kguard,
            Some("closed") => DecisionMode::Closed,
            _ => return Err(invalid("decision_mode must be \"kguard\" or \"closed\"")),
        });
    }
    if let Some(value) = params.get("decision_timeout_ms") {
        patch.decision_timeout_ms = Some(
            value
                .as_u64()
                .and_then(|v| u16::try_from(v).ok())
                .ok_or_else(|| invalid("decision_timeout_ms must be 500..=5000"))?,
        );
    }
    if let Some(value) = params.get("pending_retry_after_s") {
        patch.pending_retry_after_s = Some(
            value
                .as_u64()
                .and_then(|v| u32::try_from(v).ok())
                .ok_or_else(|| invalid("pending_retry_after_s must be 30..=3600"))?,
        );
    }
    let (result, events) = service.with(|a| a.update_policy(&patch));
    push_events(ctx, events);
    Ok(result?)
}

fn requests_list<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(params, &[])?;
    let service = service(ctx)?;
    authorize(ctx, service, acl::PERM_MEMBERSHIP_READ, "MEMBERSHIP_READ")?;
    Ok(service.with(|a| a.join_requests_json(ctx.now_ms)).0)
}

fn join_decide<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(
        params,
        &[
            "join_request_id",
            "device_id",
            "verdict",
            "role",
            "retry_after_s",
            "reason",
            "idempotency_key",
        ],
    )?;
    let service = service(ctx)?;
    let principal = authorize(
        ctx,
        service,
        acl::PERM_MEMBERSHIP_DECIDE,
        "MEMBERSHIP_DECIDE",
    )?;
    let invalid = |m: &str| ApiError::simple("INVALID_ARGUMENT", m);
    let join_request_id = params
        .get("join_request_id")
        .and_then(Json::as_str)
        .and_then(parse_request_token)
        .ok_or_else(|| invalid("join_request_id must be a jr- token"))?;
    let device = device_id(params)?;
    let key = idempotency_key(params)?;
    let verdict_name = params.get("verdict").and_then(Json::as_str).unwrap_or("");
    // Each verdict takes exactly its own parameter (07 §2.1 table).
    let (verdict, own) = match verdict_name {
        "allow" => (
            Verdict::Allow {
                role: params
                    .get("role")
                    .and_then(Json::as_str)
                    .and_then(parse_role)
                    .ok_or_else(|| invalid("allow needs role: endpoint / relay / gateway"))?,
            },
            "role",
        ),
        "pending" => (
            Verdict::Pending {
                retry_after_s: params
                    .get("retry_after_s")
                    .and_then(Json::as_u64)
                    .and_then(|v| u32::try_from(v).ok())
                    .filter(|v| {
                        (routeloom_join::PENDING_RETRY_MIN_S..=routeloom_join::RETRY_AFTER_MAX_S)
                            .contains(v)
                    })
                    .ok_or_else(|| invalid("pending needs retry_after_s 30..=3600"))?,
            },
            "retry_after_s",
        ),
        "deny" => (
            match params.get("reason").and_then(Json::as_str) {
                Some("not_here") => Verdict::DenyNotHere,
                Some("blocked") => Verdict::DenyBlocked,
                _ => return Err(invalid("deny needs reason: not_here / blocked")),
            },
            "reason",
        ),
        _ => return Err(invalid("verdict must be allow / pending / deny")),
    };
    for other in ["role", "retry_after_s", "reason"] {
        if other != own && params.get(other).is_some() {
            return Err(invalid(&format!(
                "{other} does not apply to verdict {verdict_name}"
            )));
        }
    }
    let (result, events) = service.with(|a| {
        a.decide(
            principal,
            DecideRequest {
                join_request_id,
                device,
                verdict,
                key,
            },
            ctx.now_ms,
        )
    });
    push_events(ctx, events);
    Ok(result?)
}

fn discovered_list<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(params, &["after", "limit"])?;
    let service = service(ctx)?;
    authorize(ctx, service, acl::PERM_MEMBERSHIP_READ, "MEMBERSHIP_READ")?;
    let (after, limit) = paging(params)?;
    Ok(service.with(|a| a.discovered_json(after, limit)).0)
}

fn members_list<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(params, &["after", "limit", "include_removed"])?;
    let service = service(ctx)?;
    authorize(ctx, service, acl::PERM_MEMBERSHIP_READ, "MEMBERSHIP_READ")?;
    let (after, limit) = paging(params)?;
    let include_removed = match params.get("include_removed") {
        None => false,
        Some(value) => value.as_bool().ok_or_else(|| {
            ApiError::simple("INVALID_ARGUMENT", "include_removed must be a boolean")
        })?,
    };
    Ok(service
        .with(|a| a.members_json(after, limit, include_removed))
        .0)
}

fn members_get<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(params, &["device_id"])?;
    let service = service(ctx)?;
    authorize(ctx, service, acl::PERM_MEMBERSHIP_READ, "MEMBERSHIP_READ")?;
    let node = device_id(params)?;
    service
        .with(|a| a.member_get_json(node))
        .0
        .ok_or_else(|| ApiError::simple("NOT_FOUND", "no member or removed device with that id"))
}

fn membership_revoke<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(
        params,
        &[
            "device_id",
            "expected_generation",
            "reason",
            "idempotency_key",
        ],
    )?;
    let service = service(ctx)?;
    let principal = authorize(
        ctx,
        service,
        acl::PERM_MEMBERSHIP_DECIDE,
        "MEMBERSHIP_DECIDE",
    )?;
    let device = device_id(params)?;
    let expected_generation = params
        .get("expected_generation")
        .and_then(Json::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v >= 1)
        .ok_or_else(|| ApiError::simple("INVALID_ARGUMENT", "expected_generation must be >= 1"))?;
    let reason = params
        .get("reason")
        .and_then(Json::as_str)
        .and_then(parse_reason)
        .ok_or_else(|| {
            ApiError::simple(
                "INVALID_ARGUMENT",
                "reason must be removed / lost / replaced / blocked",
            )
        })?;
    let key = idempotency_key(params)?;
    let time = HostTime {
        mono_ms: ctx.now_mono,
        unix_ms: ctx.now_ms,
    };
    let (result, events) = service.with(|a| {
        a.revoke(
            principal,
            RevokeRequest {
                device,
                expected_generation,
                reason,
                key,
            },
            time,
        )
    });
    push_events(ctx, events);
    Ok(result?)
}

fn membership_cutover<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(
        params,
        &["expected_site_epoch", "next_site_cert", "idempotency_key"],
    )?;
    let service = service(ctx)?;
    let principal = authorize(ctx, service, acl::PERM_MEMBERSHIP_ADMIN, "MEMBERSHIP_ADMIN")?;
    let expected_site_epoch = params
        .get("expected_site_epoch")
        .and_then(Json::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v >= 1)
        .ok_or_else(|| ApiError::simple("INVALID_ARGUMENT", "expected_site_epoch must be >= 1"))?;
    let cert_hex = params
        .get("next_site_cert")
        .and_then(Json::as_str)
        .ok_or_else(|| ApiError::simple("INVALID_ARGUMENT", "next_site_cert must be hex bytes"))?;
    if cert_hex.len() > 2048 || !cert_hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(ApiError::simple(
            "INVALID_ARGUMENT",
            "next_site_cert must be hex bytes",
        ));
    }
    let next_site_cert = (0..cert_hex.len() / 2)
        .map(|i| u8::from_str_radix(&cert_hex[2 * i..2 * i + 2], 16))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ApiError::simple("INVALID_ARGUMENT", "next_site_cert must be hex bytes"))?;
    let key = idempotency_key(params)?;
    let time = HostTime {
        mono_ms: ctx.now_mono,
        unix_ms: ctx.now_ms,
    };
    let (result, events) = service.with(|a| {
        a.cutover(
            principal,
            CutoverRequest {
                expected_site_epoch,
                next_site_cert,
                key,
            },
            time,
        )
    });
    push_events(ctx, events);
    Ok(result?)
}

fn group_keys_status<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(params, &[])?;
    let service = service(ctx)?;
    authorize(ctx, service, acl::PERM_MEMBERSHIP_READ, "MEMBERSHIP_READ")?;
    let time = HostTime {
        mono_ms: ctx.now_mono,
        unix_ms: ctx.now_ms,
    };
    let (status, events) = service.with(|a| a.group_keys_status_json(time));
    push_events(ctx, events);
    Ok(status)
}

fn group_keys_rotate<S: OperationStore>(
    params: &Json,
    ctx: &ApiContext<'_, S>,
) -> Result<String, ApiError> {
    only(params, &["expected_active_epoch", "idempotency_key"])?;
    let service = service(ctx)?;
    let principal = authorize(ctx, service, acl::PERM_MEMBERSHIP_ADMIN, "MEMBERSHIP_ADMIN")?;
    let expected_active_epoch = params
        .get("expected_active_epoch")
        .and_then(Json::as_u64)
        .and_then(|v| u32::try_from(v).ok())
        .filter(|v| *v >= 1)
        .ok_or_else(|| {
            ApiError::simple("INVALID_ARGUMENT", "expected_active_epoch must be >= 1")
        })?;
    let key = idempotency_key(params)?;
    let time = HostTime {
        mono_ms: ctx.now_mono,
        unix_ms: ctx.now_ms,
    };
    let (result, events) = service.with(|a| {
        a.rotate(
            principal,
            RotateRequest {
                expected_active_epoch,
                key,
            },
            time,
        )
    });
    push_events(ctx, events);
    Ok(result?)
}

/// `operations.get` for a Site Authority `op-` token; `None` when `text`
/// is not one (the caller then parses a message operation id).
pub(super) fn operation_get<S: OperationStore>(
    text: &str,
    ctx: &ApiContext<'_, S>,
) -> Option<Result<String, ApiError>> {
    let id = parse_op_token(text)?;
    let not_found = || ApiError::simple("NOT_FOUND", "no operation with that id in this store");
    Some((|| {
        let service = ctx.site.ok_or_else(not_found)?;
        // Existence is not revealed without the grant.
        authorize(ctx, service, acl::PERM_MEMBERSHIP_READ, "MEMBERSHIP_READ")
            .map_err(|_| not_found())?;
        let time = HostTime {
            mono_ms: ctx.now_mono,
            unix_ms: ctx.now_ms,
        };
        service
            .with(|a| a.operation_json(id, time))
            .0
            .ok_or_else(not_found)
    })())
}

/// Live USB join-relay view: `ready` exactly when the site lane can
/// serve joins (an authenticated session advertising 0x60-0x63).
fn join_relay_status<S: OperationStore>(ctx: &ApiContext<'_, S>) -> &'static str {
    let info = ctx.session.lock().expect("session poisoned");
    if info.authenticated
        && info.id.is_some()
        && info.capability.is_some_and(crate::site::usb::site_capable)
    {
        "ready"
    } else {
        "not_ready"
    }
}

/// The `site` object of `capabilities.get`.
pub(super) fn capability_json<S: OperationStore>(ctx: &ApiContext<'_, S>) -> String {
    let kinds = SITE_EVENT_KINDS
        .iter()
        .map(|k| format!("\"{k}\""))
        .collect::<Vec<_>>()
        .join(",");
    let (configured, durable) = match ctx.site {
        Some(service) => (true, service.with(|a| a.storage_durable()).0),
        None => (false, false),
    };
    let distribution = match ctx.site {
        Some(service) => service.with(|a| a.p6_distribution_status()).0,
        None => "rrs_no_transport",
    };
    let join_relay = join_relay_status(ctx);
    format!(
        "{{\"configured\":{configured},\"edhoc\":\"rfc9528-method0-suite2\",\"verdicts\":[\"allow\",\"pending\",\"deny\"],\"permissions\":[\"MEMBERSHIP_READ\",\"MEMBERSHIP_DECIDE\",\"MEMBERSHIP_ADMIN\"],\"page_max\":{SITE_PAGE_MAX},\"events\":[{kinds}],\"join_relay\":\"{join_relay}\",\"distribution\":\"{distribution}\",\"storage_durable\":{durable}}}"
    )
}

#[cfg(test)]
mod tests {
    use super::SITE_EVENT_KINDS;

    #[test]
    fn join_relay_failures_can_be_filtered_and_advertised() {
        for kind in [
            "join_relay_failed",
            "authority.channel_ready",
            "authority.channel_lost",
            "authority.pull",
            "authority.pull_throttled",
            "authority.passthrough",
        ] {
            assert!(SITE_EVENT_KINDS.contains(&kind), "missing {kind}");
        }
    }
}
