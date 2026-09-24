//! [`SiteAdmin`] over the routeloom-host API1 socket, and the parsers of
//! the daemon's Site Authority JSON (public so the daemon's own tests can
//! check that what it emits is what this client reads).

use routeloom_json::Json;

use super::{parse_hex_u64, protocol, Notifications, RouteLoomTransport};
use crate::site::{
    Decision, DecisionOutcome, DiscoveredDevice, DistributionProgress, GroupKeyStatus, JoinRequest,
    LastRotation, Member, OperationProgress, RemovalReason, RevokeOutcome, RotateOutcome,
    SiteAdmin, SiteEvent, SiteEventStream, SiteStatus, Via, SITE_EVENT_KINDS,
};
use crate::{NodeId, TransportError};

fn u32_of(json: &Json, key: &str) -> Option<u32> {
    json.get(key)?.as_u64().and_then(|v| u32::try_from(v).ok())
}

fn opt_u64(json: &Json, key: &str) -> Option<u64> {
    json.get(key).and_then(Json::as_u64)
}

fn nullable_u32(json: &Json, key: &str) -> Option<Option<u32>> {
    let value = json.get(key)?;
    if value.is_null() {
        Some(None)
    } else {
        Some(Some(u32::try_from(value.as_u64()?).ok()?))
    }
}

fn nullable_u64(json: &Json, key: &str) -> Option<Option<u64>> {
    let value = json.get(key)?;
    if value.is_null() {
        Some(None)
    } else {
        Some(Some(value.as_u64()?))
    }
}

fn nullable_string(json: &Json, key: &str) -> Option<Option<String>> {
    let value = json.get(key)?;
    if value.is_null() {
        Some(None)
    } else {
        Some(Some(value.as_str()?.to_string()))
    }
}

fn node_of(json: &Json, key: &str) -> Option<NodeId> {
    parse_hex_u64(json.get(key)?.as_str()?)
}

fn string_of(json: &Json, key: &str) -> Option<String> {
    Some(json.get(key)?.as_str()?.to_string())
}

fn via_of(json: &Json) -> Option<Via> {
    let via = json.get("via")?;
    Some(Via {
        gateway: node_of(via, "gateway")?,
        proxy: node_of(via, "proxy")?,
        authority_hops: u8::try_from(via.get("authority_hops")?.as_u64()?).ok()?,
        joiner_rssi_dbm: i8::try_from(via.get("joiner_rssi_dbm")?.as_i64()?).ok()?,
    })
}

pub fn site_status_from_json(json: &Json) -> Option<SiteStatus> {
    Some(SiteStatus {
        site_id: node_of(json, "site_id")?,
        network: node_of(json, "network")?,
        site_epoch: u32_of(json, "site_epoch")?,
        rs_epoch: u32_of(json, "rs_epoch")?,
        gk_epoch: u32_of(json, "gk_epoch")?,
        members: u32_of(json, "members")?,
        members_unconfirmed: u32_of(json, "members_unconfirmed")?,
        removed: u32_of(json, "removed")?,
        discovered: u32_of(json, "discovered")?,
        join_requests: u32_of(json, "join_requests")?,
        storage_durable: json.get("storage_durable")?.as_bool()?,
    })
}

pub fn join_request_from_json(json: &Json) -> Option<JoinRequest> {
    Some(JoinRequest {
        id: string_of(json, "join_request_id")?,
        device: node_of(json, "device_id")?,
        kid: string_of(json, "kid")?,
        model: u16::try_from(json.get("model")?.as_u64()?).ok()?,
        hw_rev: u8::try_from(json.get("hw_rev")?.as_u64()?).ok()?,
        cert_serial: u32_of(json, "cert_serial")?,
        fw_version: u32_of(json, "fw_version")?,
        capability: json
            .get("capability")?
            .as_array()?
            .iter()
            .map(|c| c.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()?,
        requested_role: string_of(json, "requested_role")?,
        previously_removed: json.get("previously_removed")?.as_bool()?,
        kid_conflict: json.get("kid_conflict")?.as_bool()?,
        via: via_of(json)?,
        attempt: u32_of(json, "attempt")?,
        remaining_ms: opt_u64(json, "remaining_ms")
            .or_else(|| opt_u64(json, "deadline_ms"))
            .unwrap_or(0),
        decided: json.get("state").and_then(Json::as_str) == Some("decided"),
    })
}

pub fn discovered_from_json(json: &Json) -> Option<DiscoveredDevice> {
    Some(DiscoveredDevice {
        device: node_of(json, "device_id")?,
        kid: string_of(json, "kid")?,
        model: u16::try_from(json.get("model")?.as_u64()?).ok()?,
        hw_rev: u8::try_from(json.get("hw_rev")?.as_u64()?).ok()?,
        cert_serial: u32_of(json, "cert_serial")?,
        fw_version: u32_of(json, "fw_version")?,
        first_seen_ms: opt_u64(json, "first_seen_ms")?,
        last_seen_ms: opt_u64(json, "last_seen_ms")?,
        attempts: u32_of(json, "attempts")?,
        via: via_of(json)?,
        last_verdict: string_of(json, "last_verdict")?,
        previously_removed: json.get("previously_removed")?.as_bool()?,
        kid_conflict: json.get("kid_conflict")?.as_bool()?,
    })
}

pub fn member_from_json(json: &Json) -> Option<Member> {
    Some(Member {
        device: node_of(json, "device_id")?,
        kid: string_of(json, "kid")?,
        member: json.get("state")?.as_str()? == "member",
        generation: u32_of(json, "generation")?,
        role: string_of(json, "role")?,
        member_cert_serial: u32_of(json, "member_cert_serial")?,
        confirm_state: json
            .get("confirm_state")
            .and_then(Json::as_str)
            .map(str::to_string),
        delivered: json.get("delivered")?.as_bool()?,
        approved_ms: opt_u64(json, "approved_ms")?,
        removed_ms: opt_u64(json, "removed_ms"),
        removal_reason: json
            .get("removal_reason")
            .and_then(Json::as_str)
            .map(str::to_string),
    })
}

pub fn group_key_status_from_json(json: &Json) -> Option<GroupKeyStatus> {
    Some(GroupKeyStatus {
        active: u32_of(json, "active")?,
        staged: nullable_u32(json, "staged")?,
        phase: string_of(json, "phase")?,
        cause: nullable_string(json, "cause")?,
        targets: u32_of(json, "targets")?,
        staged_ack: u32_of(json, "staged_ack")?,
        active_ack: u32_of(json, "active_ack")?,
        unknown: u32_of(json, "unknown")?,
        last_rotation: match json.get("last_rotation")? {
            value if value.is_null() => None,
            value => Some(LastRotation {
                from_epoch: u32_of(value, "from")?,
                to_epoch: u32_of(value, "to")?,
                cause: string_of(value, "cause")?,
                activated_ms: opt_u64(value, "activated_ms")?,
            }),
        },
        next_due_ms: nullable_u64(json, "next_due_ms")?,
    })
}

pub fn rotate_outcome_from_json(json: &Json) -> Option<RotateOutcome> {
    Some(RotateOutcome {
        operation_id: string_of(json, "operation_id")?,
        state: string_of(json, "state")?,
        from_epoch: u32_of(json, "from")?,
        to_epoch: u32_of(json, "to")?,
        targets: u32_of(json, "targets")?,
    })
}

pub fn site_event_from_json(event: &Json) -> Option<SiteEvent> {
    let kind = event.get("kind")?.as_str()?;
    if !SITE_EVENT_KINDS.contains(&kind) {
        return None;
    }
    Some(SiteEvent {
        kind: kind.to_string(),
        at_ms: opt_u64(event, "ms").unwrap_or(0),
        device: node_of(event, "device_id"),
        join_request_id: string_of(event, "join_request_id"),
        raw: routeloom_json_text(event),
    })
}

/// A revoke `operations.get` result with its RRS distribution progress.
/// Required: `operation_id`, `kind`, `state`, `device_id`, `generation`,
/// `rs_epoch`, and the `distribution` object; counts default to 0 only
/// for fields the daemon omits, never for mismatched shapes.
pub fn operation_from_json(json: &Json) -> Option<OperationProgress> {
    let dist = json.get("distribution")?;
    Some(OperationProgress {
        operation_id: string_of(json, "operation_id")?,
        kind: string_of(json, "kind")?,
        state: string_of(json, "state")?,
        device: node_of(json, "device_id")?,
        generation: u32_of(json, "generation")?,
        rs_epoch: u32_of(json, "rs_epoch")?,
        distribution: DistributionProgress {
            state: string_of(dist, "state").unwrap_or_else(|| "unknown".to_string()),
            applied: opt_u64(dist, "applied").unwrap_or(0),
            retired: opt_u64(dist, "retired").unwrap_or(0),
            unknown: opt_u64(dist, "unknown").unwrap_or(0),
            total: opt_u64(dist, "total").unwrap_or(0),
        },
    })
}

/// Canonical re-serialization of an event (keys in received order).
fn routeloom_json_text(json: &Json) -> String {
    match json {
        Json::Null => "null".to_string(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => n.clone(),
        Json::String(s) => format!("\"{}\"", routeloom_json::escape_string(s)),
        Json::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(routeloom_json_text)
                .collect::<Vec<_>>()
                .join(",")
        ),
        Json::Object(entries) => format!(
            "{{{}}}",
            entries
                .iter()
                .map(|(k, v)| format!(
                    "\"{}\":{}",
                    routeloom_json::escape_string(k),
                    routeloom_json_text(v)
                ))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

fn parse_site_event_notification(root: &Json) -> Option<Option<SiteEvent>> {
    match root.get("kind").and_then(Json::as_str) {
        Some("event") => Some(site_event_from_json(root.get("event")?)),
        _ => Some(None),
    }
}

/// Walks a paged listing (`after` / `next_after`), bounded.
fn all_pages<T>(
    transport: &RouteLoomTransport,
    method: &str,
    field: &str,
    parse: fn(&Json) -> Option<T>,
) -> Result<Vec<T>, TransportError> {
    let mut out = Vec::new();
    let mut after: Option<String> = None;
    // ≤ 1024 entries at 128 a page.
    for _ in 0..16 {
        let params = after
            .as_ref()
            .map_or_else(|| "{}".to_string(), |a| format!("{{\"after\":\"{a}\"}}"));
        let result = transport.call(method, &params)?;
        for item in result
            .get(field)
            .and_then(Json::as_array)
            .ok_or_else(|| protocol(format!("{method} without {field}")))?
        {
            out.push(parse(item).ok_or_else(|| protocol(format!("unparsable {method} entry")))?);
        }
        match result.get("next_after").and_then(Json::as_str) {
            Some(next) => after = Some(next.to_string()),
            None => return Ok(out),
        }
    }
    Err(protocol(format!("{method} did not terminate")))
}

impl SiteAdmin for RouteLoomTransport {
    fn site_status(&self) -> Result<SiteStatus, TransportError> {
        let result = self.call("site.status", "{}")?;
        site_status_from_json(&result).ok_or_else(|| protocol("unparsable site.status"))
    }

    fn join_requests(&self) -> Result<Vec<JoinRequest>, TransportError> {
        let result = self.call("join.requests.list", "{}")?;
        result
            .get("requests")
            .and_then(Json::as_array)
            .ok_or_else(|| protocol("join.requests.list without requests"))?
            .iter()
            .map(|r| join_request_from_json(r).ok_or_else(|| protocol("unparsable join request")))
            .collect()
    }

    fn decide(
        &self,
        request: &JoinRequest,
        decision: Decision,
        idempotency_key: &str,
    ) -> Result<DecisionOutcome, TransportError> {
        let verdict = match decision {
            Decision::Allow(role) => {
                format!("\"verdict\":\"allow\",\"role\":\"{}\"", role.as_str())
            }
            Decision::Pending { retry_after_s } => {
                format!("\"verdict\":\"pending\",\"retry_after_s\":{retry_after_s}")
            }
            Decision::DenyNotHere => "\"verdict\":\"deny\",\"reason\":\"not_here\"".to_string(),
            Decision::DenyBlocked => "\"verdict\":\"deny\",\"reason\":\"blocked\"".to_string(),
        };
        let params = format!(
            "{{\"join_request_id\":\"{}\",\"device_id\":\"{:016x}\",{verdict},\"idempotency_key\":\"{}\"}}",
            routeloom_json::escape_string(&request.id),
            request.device,
            routeloom_json::escape_string(idempotency_key)
        );
        let result = self.call("join.decide", &params)?;
        Ok(DecisionOutcome {
            state: string_of(&result, "state")
                .ok_or_else(|| protocol("join.decide without state"))?,
            generation: u32_of(&result, "generation"),
            member_cert_serial: u32_of(&result, "member_cert_serial"),
            operation_id: string_of(&result, "operation_id"),
            applied: string_of(&result, "applied").unwrap_or_default(),
        })
    }

    fn discovered(&self) -> Result<Vec<DiscoveredDevice>, TransportError> {
        all_pages(
            self,
            "devices.discovered.list",
            "devices",
            discovered_from_json,
        )
    }

    fn members(&self) -> Result<Vec<Member>, TransportError> {
        all_pages(self, "members.list", "members", member_from_json)
    }

    fn member(&self, device: NodeId) -> Result<Option<Member>, TransportError> {
        match self.call(
            "members.get",
            &format!("{{\"device_id\":\"{device:016x}\"}}"),
        ) {
            Ok(result) => result
                .get("member")
                .and_then(member_from_json)
                .map(Some)
                .ok_or_else(|| protocol("members.get without a member")),
            Err(TransportError::Rejected { code, .. }) if code == "NOT_FOUND" => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn revoke(
        &self,
        device: NodeId,
        expected_generation: u32,
        reason: RemovalReason,
        idempotency_key: &str,
    ) -> Result<RevokeOutcome, TransportError> {
        let result = self.call(
            "membership.revoke",
            &format!(
                "{{\"device_id\":\"{device:016x}\",\"expected_generation\":{expected_generation},\"reason\":\"{}\",\"idempotency_key\":\"{}\"}}",
                reason.as_str(),
                routeloom_json::escape_string(idempotency_key)
            ),
        )?;
        Ok(RevokeOutcome {
            operation_id: string_of(&result, "operation_id")
                .ok_or_else(|| protocol("revoke without operation_id"))?,
            state: string_of(&result, "state").ok_or_else(|| protocol("revoke without state"))?,
            generation: u32_of(&result, "generation")
                .ok_or_else(|| protocol("revoke without generation"))?,
            rs_epoch: u32_of(&result, "rs_epoch")
                .ok_or_else(|| protocol("revoke without rs_epoch"))?,
        })
    }

    fn group_key_status(&self) -> Result<GroupKeyStatus, TransportError> {
        let result = self.call("group_keys.status", "{}")?;
        group_key_status_from_json(&result).ok_or_else(|| protocol("unparsable group_keys.status"))
    }

    fn rotate_group_key(
        &self,
        expected_active_epoch: u32,
        idempotency_key: &str,
    ) -> Result<RotateOutcome, TransportError> {
        let result = self.call(
            "group_keys.rotate",
            &format!(
                "{{\"expected_active_epoch\":{expected_active_epoch},\"idempotency_key\":\"{}\"}}",
                routeloom_json::escape_string(idempotency_key)
            ),
        )?;
        rotate_outcome_from_json(&result).ok_or_else(|| protocol("unparsable group_keys.rotate"))
    }

    fn operation(&self, operation_id: &str) -> Result<Option<OperationProgress>, TransportError> {
        let result = match self.call(
            "operations.get",
            &format!(
                "{{\"operation_id\":\"{}\"}}",
                routeloom_json::escape_string(operation_id)
            ),
        ) {
            Ok(result) => result,
            Err(TransportError::Rejected { code, .. }) if code == "NOT_FOUND" => {
                return Ok(None);
            }
            Err(error) => return Err(error),
        };
        operation_from_json(&result)
            .map(Some)
            .ok_or_else(|| protocol("unparsable revoke operation"))
    }

    fn site_events(&self) -> Result<SiteEventStream, TransportError> {
        let kinds: Vec<String> = SITE_EVENT_KINDS
            .iter()
            .map(|k| format!("\"{k}\""))
            .collect();
        let reader = self.subscribe(&format!(
            "{{\"stream\":\"events\",\"from\":\"latest\",\"filter\":{{\"kinds\":[{}]}}}}",
            kinds.join(",")
        ))?;
        Ok(Box::new(Notifications {
            reader,
            parse: parse_site_event_notification,
            done: false,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_key_status_maps_the_daemon_shape() {
        let json = routeloom_json::parse(
            "{\"active\":2,\"staged\":3,\"phase\":\"staging\",\"cause\":\"manual\",\"targets\":5,\
             \"staged_ack\":2,\"active_ack\":1,\"unknown\":3,\
             \"last_rotation\":{\"from\":1,\"to\":2,\"cause\":\"periodic\",\"activated_ms\":777},\
             \"next_due_ms\":null,\"clock\":{\"unix_ms\":1,\"mono_ms\":2}}",
        )
        .unwrap();
        let status = group_key_status_from_json(&json).unwrap();
        assert_eq!(status.active, 2);
        assert_eq!(status.staged, Some(3));
        assert_eq!(status.phase, "staging");
        assert_eq!(status.cause.as_deref(), Some("manual"));
        assert_eq!(
            (
                status.targets,
                status.staged_ack,
                status.active_ack,
                status.unknown
            ),
            (5, 2, 1, 3)
        );
        let last = status.last_rotation.unwrap();
        assert_eq!(
            (last.from_epoch, last.to_epoch, last.activated_ms),
            (1, 2, 777)
        );
        assert_eq!(last.cause, "periodic");
        assert_eq!(status.next_due_ms, None);
        // The stable shape (nulls) parses too.
        let json = routeloom_json::parse(
            "{\"active\":1,\"staged\":null,\"phase\":\"stable\",\"cause\":null,\"targets\":0,\
             \"staged_ack\":0,\"active_ack\":0,\"unknown\":0,\"last_rotation\":null,\
             \"next_due_ms\":99,\"clock\":{\"unix_ms\":1,\"mono_ms\":2}}",
        )
        .unwrap();
        let status = group_key_status_from_json(&json).unwrap();
        assert_eq!((status.active, status.staged), (1, None));
        assert_eq!(status.last_rotation, None);
        assert_eq!(status.next_due_ms, Some(99));
    }

    #[test]
    fn review_group_key_status_rejects_malformed_nullable_fields() {
        let good = "{\"active\":1,\"staged\":null,\"phase\":\"stable\",\"cause\":null,\"targets\":0,\
                    \"staged_ack\":0,\"active_ack\":0,\"unknown\":0,\"last_rotation\":null,\"next_due_ms\":99}";
        assert!(group_key_status_from_json(&routeloom_json::parse(good).unwrap()).is_some());
        for bad in [
            good.replace("\"staged\":null", "\"staged\":\"bad\""),
            good.replace("\"cause\":null", "\"cause\":4"),
            good.replace("\"last_rotation\":null", "\"last_rotation\":{}"),
            good.replace("\"next_due_ms\":99", "\"next_due_ms\":\"soon\""),
            good.replace("\"staged\":null,", ""),
        ] {
            assert!(group_key_status_from_json(&routeloom_json::parse(&bad).unwrap()).is_none());
        }
    }

    #[test]
    fn rotate_outcome_maps_the_daemon_shape() {
        let json = routeloom_json::parse(
            "{\"operation_id\":\"op-0000000000000009\",\"state\":\"committed\",\"from\":1,\"to\":2,\"targets\":4}",
        )
        .unwrap();
        let outcome = rotate_outcome_from_json(&json).unwrap();
        assert_eq!(outcome.operation_id, "op-0000000000000009");
        assert_eq!(outcome.state, "committed");
        assert_eq!(
            (outcome.from_epoch, outcome.to_epoch, outcome.targets),
            (1, 2, 4)
        );
        assert!(rotate_outcome_from_json(
            &routeloom_json::parse("{\"operation_id\":\"x\"}").unwrap()
        )
        .is_none());
    }
}
