//! Bookkeeping records of the Site Authority — discovered devices, join
//! requests, stored decisions (idempotency) and operations — with the JSON
//! the API returns. The same JSON (plus a few private fields) is what the
//! store keeps in its `docs` table, so a restart reloads exactly what the
//! API showed.

use routeloom_json::{escape_string, Json};

use super::cutover::CutoverState;
use super::revocation::{NoticeState, OperationDistribution};
use crate::receive_log::hex_lower;

pub fn h16(value: u64) -> String {
    format!("{value:016x}")
}

pub fn parse_h16(text: &str) -> Option<u64> {
    (text.len() == 16 && text.bytes().all(|b| b.is_ascii_hexdigit()))
        .then(|| u64::from_str_radix(text, 16).ok())
        .flatten()
}

pub fn parse_hex(text: &str, len: usize) -> Option<Vec<u8>> {
    if text.len() != len * 2 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..len)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).ok())
        .collect()
}

fn arr<const N: usize>(json: &Json, key: &str) -> Option<[u8; N]> {
    parse_hex(json.get(key)?.as_str()?, N)?.try_into().ok()
}

fn num(json: &Json, key: &str) -> Option<u64> {
    json.get(key)?.as_u64()
}

fn opt_num(json: &Json, key: &str) -> Option<Option<u64>> {
    match json.get(key)? {
        Json::Null => Some(None),
        value => Some(Some(value.as_u64()?)),
    }
}

fn opt_json(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |v| v.to_string())
}

pub const ROLE_ENDPOINT: u8 = 1;
pub const ROLE_RELAY: u8 = 2;
pub const ROLE_GATEWAY: u8 = 4;

/// MemberCert role bits as API names (`"endpoint"`, `"relay"`,
/// `"gateway"`, joined with `+` when several are set).
pub fn role_name(bits: u8) -> String {
    let mut names = Vec::new();
    for (bit, name) in [
        (ROLE_ENDPOINT, "endpoint"),
        (ROLE_RELAY, "relay"),
        (ROLE_GATEWAY, "gateway"),
    ] {
        if bits & bit != 0 {
            names.push(name);
        }
    }
    if names.is_empty() {
        "none".to_string()
    } else {
        names.join("+")
    }
}

/// The single-role names KGuard sends with `join.decide`.
pub fn parse_role(name: &str) -> Option<u8> {
    Some(match name {
        "endpoint" => ROLE_ENDPOINT,
        "relay" => ROLE_RELAY,
        "gateway" => ROLE_GATEWAY,
        _ => return None,
    })
}

pub fn capability_json(bits: u32) -> String {
    let mut names = Vec::new();
    for (bit, name) in [(1_u32, "sleepy"), (2, "relay"), (4, "gateway")] {
        if bits & bit != 0 {
            names.push(format!("\"{name}\""));
        }
    }
    format!("[{}]", names.join(","))
}

/// Unauthenticated routing facts of the latest attempt (02 §9 `via`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Via {
    pub gateway: u64,
    pub proxy: u64,
    pub hops: u8,
    pub rssi_dbm: i8,
}

impl Via {
    pub fn json(&self) -> String {
        format!(
            "{{\"gateway\":\"{}\",\"proxy\":\"{}\",\"authority_hops\":{},\"joiner_rssi_dbm\":{}}}",
            h16(self.gateway),
            h16(self.proxy),
            self.hops,
            self.rssi_dbm
        )
    }

    fn parse(json: &Json) -> Option<Self> {
        Some(Self {
            gateway: parse_h16(json.get("gateway")?.as_str()?)?,
            proxy: parse_h16(json.get("proxy")?.as_str()?)?,
            hops: u8::try_from(num(json, "authority_hops")?).ok()?,
            rssi_dbm: i8::try_from(json.get("joiner_rssi_dbm")?.as_i64()?).ok()?,
        })
    }
}

/// What the verified DevCert and JoinRequest said (02 §9).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceFacts {
    pub node: u64,
    pub kid: [u8; 32],
    pub pubkey: [u8; 64],
    pub model: u16,
    pub hw_rev: u8,
    pub cert_serial: u32,
    pub fw_version: u32,
    pub capability: u32,
    pub requested_role: u8,
    pub last_site_id: u64,
    pub last_generation: u32,
    /// The verified DevCert (kept for the ledger row).
    pub dev_cert: Vec<u8>,
}

impl DeviceFacts {
    fn json_fields(&self) -> String {
        format!(
            "\"device_id\":\"{}\",\"kid\":\"{}\",\"model\":{},\"hw_rev\":{},\"cert_serial\":{},\"fw_version\":{},\"capability\":{},\"requested_role\":\"{}\"",
            h16(self.node),
            hex_lower(&self.kid),
            self.model,
            self.hw_rev,
            self.cert_serial,
            self.fw_version,
            capability_json(self.capability),
            role_name(self.requested_role)
        )
    }

    fn private_fields(&self) -> String {
        format!(
            "\"pubkey\":\"{}\",\"dev_cert\":\"{}\",\"capability_bits\":{},\"requested_role_bits\":{},\"last_site_id\":\"{}\",\"last_generation\":{}",
            hex_lower(&self.pubkey),
            hex_lower(&self.dev_cert),
            self.capability,
            self.requested_role,
            h16(self.last_site_id),
            self.last_generation
        )
    }

    fn parse(json: &Json) -> Option<Self> {
        Some(Self {
            node: parse_h16(json.get("device_id")?.as_str()?)?,
            kid: arr(json, "kid")?,
            pubkey: arr(json, "pubkey")?,
            model: u16::try_from(num(json, "model")?).ok()?,
            hw_rev: u8::try_from(num(json, "hw_rev")?).ok()?,
            cert_serial: u32::try_from(num(json, "cert_serial")?).ok()?,
            fw_version: u32::try_from(num(json, "fw_version")?).ok()?,
            capability: u32::try_from(num(json, "capability_bits")?).ok()?,
            requested_role: u8::try_from(num(json, "requested_role_bits")?).ok()?,
            last_site_id: parse_h16(json.get("last_site_id")?.as_str()?)?,
            last_generation: u32::try_from(num(json, "last_generation")?).ok()?,
            dev_cert: {
                let text = json.get("dev_cert")?.as_str()?;
                parse_hex(text, text.len() / 2)?
            },
        })
    }
}

/// One entry of the discovered-device table (02 §9, bounded LRU).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Discovered {
    pub facts: DeviceFacts,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub attempts: u32,
    pub via: Via,
    /// `awaiting` / `pending` / `not_here` / `blocked` / `busy` / `allowed`.
    pub last_verdict: String,
    pub previously_removed: bool,
    pub kid_conflict: bool,
    /// A pending verdict told the device to come back after this.
    pub retry_not_before_ms: Option<u64>,
    /// Last `device.discovered` event (rate: one a minute).
    pub last_event_ms: u64,
}

impl Discovered {
    pub fn api_json(&self) -> String {
        format!(
            "{{{},\"first_seen_ms\":{},\"last_seen_ms\":{},\"attempts\":{},\"via\":{},\"last_verdict\":\"{}\",\"previously_removed\":{},\"kid_conflict\":{},\"retry_not_before_ms\":{}}}",
            self.facts.json_fields(),
            self.first_seen_ms,
            self.last_seen_ms,
            self.attempts,
            self.via.json(),
            escape_string(&self.last_verdict),
            self.previously_removed,
            self.kid_conflict,
            opt_json(self.retry_not_before_ms)
        )
    }

    pub fn doc(&self) -> String {
        let api = self.api_json();
        format!(
            "{},{},\"last_event_ms\":{}}}",
            &api[..api.len() - 1],
            self.facts.private_fields(),
            self.last_event_ms
        )
    }

    pub fn from_doc(text: &str) -> Option<Self> {
        let json = routeloom_json::parse(text).ok()?;
        Some(Self {
            facts: DeviceFacts::parse(&json)?,
            first_seen_ms: num(&json, "first_seen_ms")?,
            last_seen_ms: num(&json, "last_seen_ms")?,
            attempts: u32::try_from(num(&json, "attempts")?).ok()?,
            via: Via::parse(json.get("via")?)?,
            last_verdict: json.get("last_verdict")?.as_str()?.to_string(),
            previously_removed: json.get("previously_removed")?.as_bool()?,
            kid_conflict: json.get("kid_conflict")?.as_bool()?,
            retry_not_before_ms: opt_num(&json, "retry_not_before_ms")?,
            last_event_ms: num(&json, "last_event_ms")?,
        })
    }
}

/// A KGuard verdict (07 §2.1).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Verdict {
    Allow { role: u8 },
    Pending { retry_after_s: u32 },
    DenyNotHere,
    DenyBlocked,
}

impl Verdict {
    pub fn json_fields(&self) -> String {
        match self {
            Self::Allow { role } => {
                format!("\"verdict\":\"allow\",\"role\":\"{}\"", role_name(*role))
            }
            Self::Pending { retry_after_s } => {
                format!("\"verdict\":\"pending\",\"retry_after_s\":{retry_after_s}")
            }
            Self::DenyNotHere => "\"verdict\":\"deny\",\"reason\":\"not_here\"".to_string(),
            Self::DenyBlocked => "\"verdict\":\"deny\",\"reason\":\"blocked\"".to_string(),
        }
    }

    fn parse(json: &Json) -> Option<Self> {
        Some(match json.get("verdict")?.as_str()? {
            "allow" => Self::Allow {
                role: parse_role(json.get("role")?.as_str()?)?,
            },
            "pending" => Self::Pending {
                retry_after_s: u32::try_from(num(json, "retry_after_s")?).ok()?,
            },
            "deny" => match json.get("reason")?.as_str()? {
                "not_here" => Self::DenyNotHere,
                "blocked" => Self::DenyBlocked,
                _ => return None,
            },
            _ => return None,
        })
    }

    /// Discovered-table label once delivered.
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow { .. } => "allowed",
            Self::Pending { .. } => "pending",
            Self::DenyNotHere => "not_here",
            Self::DenyBlocked => "blocked",
        }
    }
}

/// An open join request (07 §2.1: "決定待ち・pending", ≤ 256).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinRequestRec {
    pub id: u64,
    pub facts: DeviceFacts,
    pub previously_removed: bool,
    pub kid_conflict: bool,
    pub via: Via,
    pub attempt: u32,
    pub created_ms: u64,
    pub updated_ms: u64,
    /// When the current attempt stops waiting (then: PendingAssignment).
    pub deadline_ms: u64,
    pub decision: Option<Verdict>,
    pub decided_ms: Option<u64>,
    /// The `join.decide` result JSON (returned again for the same verdict).
    pub decision_result: Option<String>,
}

pub fn request_token(id: u64) -> String {
    format!("jr-{id:016x}")
}

pub fn parse_request_token(text: &str) -> Option<u64> {
    parse_h16(text.strip_prefix("jr-")?)
}

impl JoinRequestRec {
    pub fn api_json(&self, now_ms: u64) -> String {
        let decision = self.decision.as_ref().map_or_else(
            || "null".to_string(),
            |v| {
                format!(
                    "{{{},\"decided_ms\":{}}}",
                    v.json_fields(),
                    opt_json(self.decided_ms)
                )
            },
        );
        format!(
            "{{\"join_request_id\":\"{}\",{},\"previously_removed\":{},\"kid_conflict\":{},\"via\":{},\"attempt\":{},\"created_ms\":{},\"updated_ms\":{},\"deadline_ms\":{},\"remaining_ms\":{},\"state\":\"{}\",\"decision\":{}}}",
            request_token(self.id),
            self.facts.json_fields(),
            self.previously_removed,
            self.kid_conflict,
            self.via.json(),
            self.attempt,
            self.created_ms,
            self.updated_ms,
            self.deadline_ms,
            self.deadline_ms.saturating_sub(now_ms),
            if self.decision.is_some() { "decided" } else { "awaiting" },
            decision
        )
    }

    /// The `join.request` event body (fields only; the ring adds seq/ms).
    pub fn event_fields(&self, now_ms: u64) -> String {
        format!(
            "\"kind\":\"join.request\",\"join_request_id\":\"{}\",{},\"previously_removed\":{},\"kid_conflict\":{},\"via\":{},\"deadline_ms\":{},\"attempt\":{}",
            request_token(self.id),
            self.facts.json_fields(),
            self.previously_removed,
            self.kid_conflict,
            self.via.json(),
            self.deadline_ms.saturating_sub(now_ms),
            self.attempt
        )
    }

    pub fn doc(&self) -> String {
        let api = self.api_json(0);
        format!(
            "{},{},\"decision_result\":{}}}",
            &api[..api.len() - 1],
            self.facts.private_fields(),
            self.decision_result.as_ref().map_or_else(
                || "null".to_string(),
                |r| format!("\"{}\"", escape_string(r))
            )
        )
    }

    pub fn from_doc(text: &str) -> Option<Self> {
        let json = routeloom_json::parse(text).ok()?;
        let decision_json = json.get("decision")?;
        let (decision, decided_ms) = if decision_json.is_null() {
            (None, None)
        } else {
            (
                Some(Verdict::parse(decision_json)?),
                opt_num(decision_json, "decided_ms")?,
            )
        };
        Some(Self {
            id: parse_request_token(json.get("join_request_id")?.as_str()?)?,
            facts: DeviceFacts::parse(&json)?,
            previously_removed: json.get("previously_removed")?.as_bool()?,
            kid_conflict: json.get("kid_conflict")?.as_bool()?,
            via: Via::parse(json.get("via")?)?,
            attempt: u32::try_from(num(&json, "attempt")?).ok()?,
            created_ms: num(&json, "created_ms")?,
            updated_ms: num(&json, "updated_ms")?,
            deadline_ms: num(&json, "deadline_ms")?,
            decision,
            decided_ms,
            decision_result: match json.get("decision_result")? {
                Json::Null => None,
                value => Some(value.as_str()?.to_string()),
            },
        })
    }
}

/// An idempotency record: `(principal, key)` → request digest + result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StoredDecision {
    pub principal: routeloom_peercred::Principal,
    pub key: String,
    pub digest: [u8; 32],
    pub result: String,
    pub ms: u64,
}

impl StoredDecision {
    pub fn doc_key(principal: &routeloom_peercred::Principal, key: &str) -> String {
        match principal {
            routeloom_peercred::Principal::UnixUid(uid) => format!("{uid}:{key}"),
            _ => format!("{}:{key}", principal.storage_key()),
        }
    }

    pub fn doc(&self) -> String {
        let principal = match &self.principal {
            routeloom_peercred::Principal::UnixUid(uid) => uid.to_string(),
            sid => format!("\"{}\"", escape_string(&sid.storage_key())),
        };
        format!(
            "{{\"principal\":{},\"key\":\"{}\",\"digest\":\"{}\",\"result\":\"{}\",\"ms\":{}}}",
            principal,
            escape_string(&self.key),
            hex_lower(&self.digest),
            escape_string(&self.result),
            self.ms
        )
    }

    pub fn from_doc(text: &str) -> Option<Self> {
        let json = routeloom_json::parse(text).ok()?;
        Some(Self {
            principal: match json.get("principal")? {
                Json::String(key) => routeloom_peercred::Principal::from_storage_key(key).ok()?,
                _ => routeloom_peercred::Principal::UnixUid(
                    u32::try_from(num(&json, "principal")?).ok()?,
                ),
            },
            key: json.get("key")?.as_str()?.to_string(),
            digest: arr(&json, "digest")?,
            result: json.get("result")?.as_str()?.to_string(),
            ms: num(&json, "ms")?,
        })
    }
}

/// An approve, revoke, rotate or cutover operation (07 §2.2,
/// `operations.get`).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Operation {
    pub id: u64,
    /// "approve", "revoke", "rotate" or "cutover".
    pub kind: String,
    pub node: u64,
    pub generation: u32,
    pub member_cert_serial: u32,
    pub rs_epoch: u32,
    pub gk_from: u32,
    pub gk_to: u32,
    pub created_ms: u64,
    /// Rotation cause ("periodic"/"removal"/"manual"); empty when the
    /// operation stages no key.
    pub gk_cause: String,
    /// Terminal GK state ("converged"/"superseded"); empty while live or
    /// when the operation stages no key.
    pub gk_end: String,
    /// P6-1 RRS1 distribution snapshot (`revoke` only). `None` on
    /// pre-P6-1 docs, which read back as distribution state `unknown`.
    pub distribution: Option<OperationDistribution>,
    /// P6-2 cutover snapshot (`cutover` only). `None` on older docs.
    pub cutover: Option<CutoverState>,
    /// P6-2 RemovalNotice delivery (`revoke` only). `None` on older
    /// docs, which read back as delivery `unknown`.
    pub notice: Option<NoticeState>,
}

pub fn op_token(id: u64) -> String {
    format!("op-{id:016x}")
}

pub fn parse_op_token(text: &str) -> Option<u64> {
    parse_h16(text.strip_prefix("op-")?)
}

impl Operation {
    pub fn doc(&self) -> String {
        let distribution = self.distribution.as_ref().map_or_else(
            || "null".to_string(),
            super::revocation::OperationDistribution::doc,
        );
        let cutover = self
            .cutover
            .as_ref()
            .map_or_else(|| "null".to_string(), super::cutover::CutoverState::doc);
        let notice = self
            .notice
            .as_ref()
            .map_or_else(|| "null".to_string(), super::revocation::NoticeState::doc);
        format!(
            "{{\"id\":{},\"kind\":\"{}\",\"node\":\"{}\",\"generation\":{},\"member_cert_serial\":{},\"rs_epoch\":{},\"gk_from\":{},\"gk_to\":{},\"created_ms\":{},\"gk_cause\":\"{}\",\"gk_end\":\"{}\",\"distribution\":{distribution},\"cutover\":{cutover},\"notice\":{notice}}}",

            self.id,
            escape_string(&self.kind),
            h16(self.node),
            self.generation,
            self.member_cert_serial,
            self.rs_epoch,
            self.gk_from,
            self.gk_to,
            self.created_ms,
            escape_string(&self.gk_cause),
            escape_string(&self.gk_end)
        )
    }

    pub fn from_doc(text: &str) -> Option<Self> {
        let json = routeloom_json::parse(text).ok()?;
        // The distribution fragment is optional (missing on pre-P6-1
        // docs) and degrades to `unknown` when unreadable, so a torn
        // fragment can never brick the operation it rides on. The P6-2
        // fragments degrade the same way.
        let distribution = match json.get("distribution") {
            None | Some(Json::Null) => None,
            Some(fragment) => OperationDistribution::from_doc(fragment),
        };
        let cutover = match json.get("cutover") {
            None | Some(Json::Null) => None,
            Some(fragment) => CutoverState::from_doc(fragment),
        };
        let notice = match json.get("notice") {
            None | Some(Json::Null) => None,
            Some(fragment) => NoticeState::from_doc(fragment),
        };
        Some(Self {
            id: num(&json, "id")?,
            kind: json.get("kind")?.as_str()?.to_string(),
            node: parse_h16(json.get("node")?.as_str()?)?,
            generation: u32::try_from(num(&json, "generation")?).ok()?,
            member_cert_serial: u32::try_from(num(&json, "member_cert_serial")?).ok()?,
            rs_epoch: u32::try_from(num(&json, "rs_epoch")?).ok()?,
            gk_from: u32::try_from(num(&json, "gk_from")?).ok()?,
            gk_to: u32::try_from(num(&json, "gk_to")?).ok()?,
            created_ms: num(&json, "created_ms")?,
            // Pre-P5 records predate both fields.
            gk_cause: json
                .get("gk_cause")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            gk_end: json
                .get("gk_end")
                .and_then(Json::as_str)
                .unwrap_or("")
                .to_string(),
            distribution,
            cutover,
            notice,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn facts() -> DeviceFacts {
        DeviceFacts {
            node: 0x00A1_0000_0000_1234,
            kid: [0xB3; 32],
            pubkey: [4; 64],
            model: 17,
            hw_rev: 2,
            cert_serial: 90211,
            fw_version: 0x0104_0000,
            capability: 2,
            requested_role: 1,
            last_site_id: 0,
            last_generation: 0,
            dev_cert: vec![0xD2, 0x84],
        }
    }

    #[test]
    fn docs_round_trip() {
        let discovered = Discovered {
            facts: facts(),
            first_seen_ms: 1,
            last_seen_ms: 2,
            attempts: 3,
            via: Via {
                gateway: 1,
                proxy: 0x777,
                hops: 3,
                rssi_dbm: -71,
            },
            last_verdict: "pending".into(),
            previously_removed: true,
            kid_conflict: false,
            retry_not_before_ms: Some(9),
            last_event_ms: 2,
        };
        assert_eq!(
            Discovered::from_doc(&discovered.doc()),
            Some(discovered.clone())
        );
        routeloom_json::parse(&discovered.api_json()).unwrap();
        let request = JoinRequestRec {
            id: 0x7F3A,
            facts: facts(),
            previously_removed: false,
            kid_conflict: true,
            via: discovered.via,
            attempt: 2,
            created_ms: 5,
            updated_ms: 6,
            deadline_ms: 7,
            decision: Some(Verdict::Pending { retry_after_s: 90 }),
            decided_ms: Some(8),
            decision_result: Some("{\"state\":\"recorded\"}".into()),
        };
        assert_eq!(
            JoinRequestRec::from_doc(&request.doc()),
            Some(request.clone())
        );
        routeloom_json::parse(&format!("{{{}}}", request.event_fields(0))).unwrap();
        for verdict in [
            Verdict::Allow { role: ROLE_RELAY },
            Verdict::DenyNotHere,
            Verdict::DenyBlocked,
        ] {
            let text = format!("{{{}}}", verdict.json_fields());
            assert_eq!(
                Verdict::parse(&routeloom_json::parse(&text).unwrap()),
                Some(verdict)
            );
        }
        let decision = StoredDecision {
            principal: routeloom_peercred::Principal::UnixUid(501),
            key: "kg-\"1".into(),
            digest: [1; 32],
            result: "{\"a\":1}".into(),
            ms: 4,
        };
        assert_eq!(StoredDecision::from_doc(&decision.doc()), Some(decision));
        let sid_decision = StoredDecision {
            principal: routeloom_peercred::Principal::WindowsSid("S-1-5-21-100-200-300-501".into()),
            key: "same-key".into(),
            digest: [2; 32],
            result: "{}".into(),
            ms: 5,
        };
        assert_eq!(
            StoredDecision::from_doc(&sid_decision.doc()),
            Some(sid_decision.clone())
        );
        assert_ne!(
            StoredDecision::doc_key(&sid_decision.principal, &sid_decision.key),
            StoredDecision::doc_key(
                &routeloom_peercred::Principal::UnixUid(501),
                &sid_decision.key
            ),
        );
        let op = Operation {
            id: 9,
            kind: "revoke".into(),
            node: 5,
            generation: 3,
            member_cert_serial: 0,
            rs_epoch: 14,
            gk_from: 203,
            gk_to: 204,
            created_ms: 1,
            gk_cause: "removal".into(),
            gk_end: "superseded".into(),
            distribution: None,
            cutover: None,
            notice: None,
        };
        assert_eq!(Operation::from_doc(&op.doc()), Some(op));
        // Pre-P5 records without the GK fields still parse.
        let legacy = "{\"id\":9,\"kind\":\"revoke\",\"node\":\"0000000000000005\",\"generation\":3,\"member_cert_serial\":0,\"rs_epoch\":14,\"gk_from\":203,\"gk_to\":204,\"created_ms\":1}";
        let parsed = Operation::from_doc(legacy).unwrap();
        assert_eq!((parsed.gk_cause, parsed.gk_end), ("".into(), "".into()));
        // Pre-P6-1 docs carry no distribution fragment at all.
        let legacy = "{\"id\":9,\"kind\":\"revoke\",\"node\":\"0000000000000005\",\"generation\":3,\"member_cert_serial\":0,\"rs_epoch\":14,\"gk_from\":203,\"gk_to\":204,\"created_ms\":1}";
        assert_eq!(Operation::from_doc(legacy).unwrap().distribution, None);

        assert_eq!(parse_request_token(&request_token(0x7F3A)), Some(0x7F3A));
        assert_eq!(parse_op_token(&op_token(12)), Some(12));
        assert_eq!(role_name(3), "endpoint+relay");
    }
}
