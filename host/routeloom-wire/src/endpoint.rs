//! Wire codec contract for the scope-gateway-config feature set — mirror of
//! `components/routeloom/src/endpoint_wire.cpp`
//! (docs/design/scope-gateway-config/05-wire-api.md §5.2–§5.5). Byte layouts
//! only: no state machines, no providers, no dispatch.
//!
//! All integers are fixed-width big-endian; reserved bytes are 0. Decoders
//! reject wrong versions, wrong lengths, nonzero reserved/flags, zero
//! nonce/token/boot/ID fields, duplicate or out-of-order TLV fields and any
//! trailing bytes. Layouts are pinned by `protocol/endpoint-golden/`.

use crate::autonomy::EncodedPayload;
use crate::{ErrorCode, Result, WireError, BROADCAST_NODE_ID};

fn err<T>(detail: &'static str) -> Result<T> {
    Err(WireError::new(ErrorCode::ProtocolError, detail))
}

fn invalid<T>(detail: &'static str) -> Result<T> {
    Err(WireError::new(ErrorCode::InvalidArgument, detail))
}

fn reject<T>() -> Result<T> {
    err("endpoint payload rejected")
}

fn all_zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

fn any_nonzero(bytes: &[u8]) -> bool {
    !all_zero(bytes)
}

// --- RLD1 body v2: scoped Discover/Offer (§5.2) --------------------------------

pub const SCOPE_BODY_VERSION: u8 = 2;
pub const SCOPE_SCHEME: u8 = 1;
pub const RLD1_DISCOVER_BODY_V2_SIZE: usize = 24;
pub const RLD1_OFFER_BODY_V2_SIZE: usize = 60;
pub const SCOPE_BINDING_SIZE: usize = 71;

/// MAC/hash domain strings (contracts.json scope.*) — ASCII plus one NUL.
pub const SCOPE_HINT_DOMAIN: &[u8] = b"RouteLoom/DSK/v1/hint\0";
pub const SCOPE_DISCOVER_DOMAIN: &[u8] = b"RouteLoom/DSK/v1/discover\0";
pub const SCOPE_OFFER_DOMAIN: &[u8] = b"RouteLoom/DSK/v1/offer\0";
pub const SCOPE_BINDING_DOMAIN: &[u8] = b"RouteLoom/DSK/v1/auth-binding\0";
pub const CONFIG_SNAPSHOT_DOMAIN: &[u8] = b"RouteLoom/config-snapshot/v1\0";

/// 02-discovery-scope.md §2.2: the only registered scope classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ScopeClass {
    Member = 1,
    Commissioning = 2,
}

impl ScopeClass {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::Member),
            2 => Ok(Self::Commissioning),
            _ => reject(),
        }
    }
}

/// DiscoverV2 body (24B): version u8=2 | class u8 | scheme u8=1 | flags u8=0 |
/// generation u32 | tag 16B.
#[derive(Clone, Debug)]
pub struct Rld1DiscoverBodyV2 {
    pub scope_class: ScopeClass,
    pub generation: u32,
    pub tag: [u8; 16],
}

pub fn scope_discover_body_encode(body: &Rld1DiscoverBodyV2) -> Result<Vec<u8>> {
    let mut raw = Vec::with_capacity(RLD1_DISCOVER_BODY_V2_SIZE);
    raw.push(SCOPE_BODY_VERSION);
    raw.push(body.scope_class as u8);
    raw.push(SCOPE_SCHEME);
    raw.push(0);
    raw.extend_from_slice(&body.generation.to_be_bytes());
    raw.extend_from_slice(&body.tag);
    debug_assert_eq!(raw.len(), RLD1_DISCOVER_BODY_V2_SIZE);
    Ok(raw)
}

pub fn scope_discover_body_decode(encoded: &[u8]) -> Result<Rld1DiscoverBodyV2> {
    if encoded.len() != RLD1_DISCOVER_BODY_V2_SIZE {
        return reject();
    }
    let version = encoded[0];
    let scope_class = ScopeClass::from_u8(encoded[1])?;
    let scheme = encoded[2];
    let flags = encoded[3];
    if version != SCOPE_BODY_VERSION || scheme != SCOPE_SCHEME || flags != 0 {
        return reject();
    }
    let mut tag = [0_u8; 16];
    tag.copy_from_slice(&encoded[8..24]);
    Ok(Rld1DiscoverBodyV2 {
        scope_class,
        generation: u32::from_be_bytes(encoded[4..8].try_into().expect("fixed")),
        tag,
    })
}

/// OfferV2 body (60B): version u8=2 | density u8 | reserved u16=0 |
/// cookie 16B | responder_nonce 16B | class u8 | scheme u8=1 | flags u16=0 |
/// generation u32 | tag 16B.
#[derive(Clone, Debug)]
pub struct Rld1OfferBodyV2 {
    pub density: u8,
    pub cookie: [u8; 16],
    pub responder_nonce: [u8; 16],
    pub scope_class: ScopeClass,
    pub generation: u32,
    pub tag: [u8; 16],
}

pub fn scope_offer_body_encode(body: &Rld1OfferBodyV2) -> Result<Vec<u8>> {
    if all_zero(&body.cookie) || all_zero(&body.responder_nonce) {
        return invalid("offer v2 cookie/responder nonce must be nonzero");
    }
    let mut raw = Vec::with_capacity(RLD1_OFFER_BODY_V2_SIZE);
    raw.push(SCOPE_BODY_VERSION);
    raw.push(body.density);
    raw.extend_from_slice(&0_u16.to_be_bytes());
    raw.extend_from_slice(&body.cookie);
    raw.extend_from_slice(&body.responder_nonce);
    raw.push(body.scope_class as u8);
    raw.push(SCOPE_SCHEME);
    raw.extend_from_slice(&0_u16.to_be_bytes());
    raw.extend_from_slice(&body.generation.to_be_bytes());
    raw.extend_from_slice(&body.tag);
    debug_assert_eq!(raw.len(), RLD1_OFFER_BODY_V2_SIZE);
    Ok(raw)
}

pub fn scope_offer_body_decode(encoded: &[u8]) -> Result<Rld1OfferBodyV2> {
    if encoded.len() != RLD1_OFFER_BODY_V2_SIZE {
        return reject();
    }
    let version = encoded[0];
    let reserved = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let scope_class = ScopeClass::from_u8(encoded[36])?;
    let scheme = encoded[37];
    let flags = u16::from_be_bytes(encoded[38..40].try_into().expect("fixed"));
    let mut cookie = [0_u8; 16];
    cookie.copy_from_slice(&encoded[4..20]);
    let mut responder_nonce = [0_u8; 16];
    responder_nonce.copy_from_slice(&encoded[20..36]);
    if version != SCOPE_BODY_VERSION
        || scheme != SCOPE_SCHEME
        || reserved != 0
        || flags != 0
        || all_zero(&cookie)
        || all_zero(&responder_nonce)
    {
        return reject();
    }
    let mut tag = [0_u8; 16];
    tag.copy_from_slice(&encoded[44..60]);
    Ok(Rld1OfferBodyV2 {
        density: encoded[1],
        cookie,
        responder_nonce,
        scope_class,
        generation: u32::from_be_bytes(encoded[40..44].try_into().expect("fixed")),
        tag,
    })
}

/// Canonical auth-binding input (71B): class u8 | generation u32 | scheme u8 |
/// scoped u8 | discover_digest 32B | offer_digest 32B. Callers hash
/// `SCOPE_BINDING_DOMAIN || these bytes` — the crypto lives elsewhere.
#[derive(Clone, Debug)]
pub struct ScopeBindingInput {
    pub scope_class: ScopeClass,
    pub generation: u32,
    /// 1 scoped, 0 legacy exchange.
    pub scoped: u8,
    pub discover_digest: [u8; 32],
    pub offer_digest: [u8; 32],
}

pub fn scope_binding_encode(input: &ScopeBindingInput) -> [u8; SCOPE_BINDING_SIZE] {
    let mut out = [0_u8; SCOPE_BINDING_SIZE];
    out[0] = input.scope_class as u8;
    out[1..5].copy_from_slice(&input.generation.to_be_bytes());
    out[5] = SCOPE_SCHEME;
    out[6] = input.scoped;
    out[7..39].copy_from_slice(&input.discover_digest);
    out[39..71].copy_from_slice(&input.offer_digest);
    out
}

pub const SCOPE_DISCOVER_MAC_INPUT_SIZE: usize = SCOPE_DISCOVER_DOMAIN.len() + 8 + 6 + 6 + 44 + 8;
pub const SCOPE_OFFER_MAC_INPUT_SIZE: usize = SCOPE_OFFER_DOMAIN.len() + 8 + 6 + 6 + 32 + 44 + 44;

/// DISCOVER tag input (§2.4): domain_discover || Network u64 | observed
/// requester MAC 6B | broadcast MAC 6B | RLD1 header 44B | body prefix 8B.
pub fn scope_discover_mac_input(
    network: u64,
    requester: &[u8; 6],
    destination: &[u8; 6],
    rld1_header: &[u8],
    body_prefix: &[u8],
) -> Result<Vec<u8>> {
    if rld1_header.len() != 44 || body_prefix.len() != 8 {
        return invalid("discover MAC input needs the 44B header and 8B body prefix");
    }
    let mut raw = Vec::with_capacity(SCOPE_DISCOVER_MAC_INPUT_SIZE);
    raw.extend_from_slice(SCOPE_DISCOVER_DOMAIN);
    raw.extend_from_slice(&network.to_be_bytes());
    raw.extend_from_slice(requester);
    raw.extend_from_slice(destination);
    raw.extend_from_slice(rld1_header);
    raw.extend_from_slice(body_prefix);
    Ok(raw)
}

/// OFFER tag input: domain_offer || Network u64 | requester MAC 6B | observed
/// responder MAC 6B | SHA256(discover) 32B | RLD1 header 44B | body prefix 44B.
pub fn scope_offer_mac_input(
    network: u64,
    requester: &[u8; 6],
    responder: &[u8; 6],
    discover_digest: &[u8],
    rld1_header: &[u8],
    body_prefix: &[u8],
) -> Result<Vec<u8>> {
    if discover_digest.len() != 32 || rld1_header.len() != 44 || body_prefix.len() != 44 {
        return invalid("offer MAC input needs digest32/header44/prefix44");
    }
    let mut raw = Vec::with_capacity(SCOPE_OFFER_MAC_INPUT_SIZE);
    raw.extend_from_slice(SCOPE_OFFER_DOMAIN);
    raw.extend_from_slice(&network.to_be_bytes());
    raw.extend_from_slice(requester);
    raw.extend_from_slice(responder);
    raw.extend_from_slice(discover_digest);
    raw.extend_from_slice(rld1_header);
    raw.extend_from_slice(body_prefix);
    Ok(raw)
}

// --- Service=21 payloads (§5.3) --------------------------------------------------

pub const SERVICE_PAYLOAD_VERSION: u8 = 1;
pub const GATEWAY_PAYLOAD_MAX: usize = 96;
pub const SERVICE_QUERY_SIZE: usize = 52;
pub const SERVICE_DESCRIPTOR_SIZE: usize = 86;
pub const SERVICE_SUBMIT_HEADER_SIZE: usize = 32;
pub const SERVICE_OUTCOME_SIZE: usize = 84;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum GatewayScope {
    GatewaySdkRam = 1,
    HostReceiveRam = 2,
}

impl GatewayScope {
    fn from_u8(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::GatewaySdkRam),
            2 => Ok(Self::HostReceiveRam),
            _ => reject(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ServiceSubtype {
    Query = 1,
    Descriptor = 2,
    Submit = 3,
    Receipt = 4,
    Pending = 5,
    Reject = 6,
}

/// Service-local reasons (§5.3) — Receipt is only reason 0, Pending only
/// reason 1; Reject carries 2..8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ServiceReason {
    Ok = 0,
    PendingWait = 1,
    TokenStale = 2,
    HostUnavailable = 3,
    Capacity = 4,
    RoleDenied = 5,
    Unsupported = 6,
    Deadline = 7,
    Conflict = 8,
}

fn service_preamble_push(raw: &mut Vec<u8>, subtype: ServiceSubtype, scope: GatewayScope) {
    raw.push(SERVICE_PAYLOAD_VERSION);
    raw.push(subtype as u8);
    raw.push(scope as u8);
    raw.push(0);
}

fn service_preamble_check(encoded: &[u8], subtype: ServiceSubtype) -> Result<GatewayScope> {
    if encoded.len() < 4
        || encoded[0] != SERVICE_PAYLOAD_VERSION
        || encoded[1] != subtype as u8
        || encoded[3] != 0
    {
        return reject();
    }
    GatewayScope::from_u8(encoded[2])
}

/// The host-digest rule: scope 1 carries an all-zero digest; scope 2 requires
/// the authenticated principal's nonzero SHA-256 digest (no any-host wildcard).
fn host_digest_scope_check(scope: GatewayScope, digest: &[u8; 32]) -> Result<()> {
    match scope {
        GatewayScope::GatewaySdkRam if all_zero(digest) => Ok(()),
        GatewayScope::HostReceiveRam if any_nonzero(digest) => Ok(()),
        _ => reject(),
    }
}

/// Query1 (52B): ver/sub1/scope/flags | nonce 16B | expected_host_digest 32B.
#[derive(Clone, Debug)]
pub struct ServiceQuery {
    pub scope: GatewayScope,
    pub nonce: [u8; 16],
    pub expected_host_digest: [u8; 32],
}

pub fn service_query_encode(payload: &ServiceQuery, out: &mut EncodedPayload) -> Result<()> {
    if all_zero(&payload.nonce) {
        return invalid("service query nonce must be nonzero");
    }
    host_digest_scope_check(payload.scope, &payload.expected_host_digest).map_err(|_| {
        WireError::new(
            ErrorCode::InvalidArgument,
            "host digest violates scope rule",
        )
    })?;
    let mut raw = Vec::with_capacity(SERVICE_QUERY_SIZE);
    service_preamble_push(&mut raw, ServiceSubtype::Query, payload.scope);
    raw.extend_from_slice(&payload.nonce);
    raw.extend_from_slice(&payload.expected_host_digest);
    debug_assert_eq!(raw.len(), SERVICE_QUERY_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn service_query_decode(encoded: &[u8]) -> Result<ServiceQuery> {
    if encoded.len() != SERVICE_QUERY_SIZE {
        return reject();
    }
    let scope = service_preamble_check(encoded, ServiceSubtype::Query)?;
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&encoded[4..20]);
    let mut expected_host_digest = [0_u8; 32];
    expected_host_digest.copy_from_slice(&encoded[20..52]);
    if all_zero(&nonce) {
        return reject();
    }
    host_digest_scope_check(scope, &expected_host_digest)?;
    Ok(ServiceQuery {
        scope,
        nonce,
        expected_host_digest,
    })
}

/// Descriptor2 (86B): ver/sub2/scope/flags | echo_nonce 16B | token 16B |
/// gateway_boot u64 | host_digest 32B | caps u32 | max_payload u16 | lease u32.
#[derive(Clone, Debug)]
pub struct ServiceDescriptor {
    pub scope: GatewayScope,
    pub echo_nonce: [u8; 16],
    pub token: [u8; 16],
    pub gateway_boot: u64,
    pub host_digest: [u8; 32],
    pub capabilities: u32,
    pub max_payload: u16,
    pub lease_ms: u32,
}

pub fn service_descriptor_encode(
    payload: &ServiceDescriptor,
    out: &mut EncodedPayload,
) -> Result<()> {
    if all_zero(&payload.echo_nonce) || all_zero(&payload.token) || payload.gateway_boot == 0 {
        return invalid("service descriptor nonce/token/boot must be nonzero");
    }
    if usize::from(payload.max_payload) > GATEWAY_PAYLOAD_MAX {
        return invalid("service descriptor max_payload exceeds registry bound");
    }
    host_digest_scope_check(payload.scope, &payload.host_digest).map_err(|_| {
        WireError::new(
            ErrorCode::InvalidArgument,
            "host digest violates scope rule",
        )
    })?;
    let mut raw = Vec::with_capacity(SERVICE_DESCRIPTOR_SIZE);
    service_preamble_push(&mut raw, ServiceSubtype::Descriptor, payload.scope);
    raw.extend_from_slice(&payload.echo_nonce);
    raw.extend_from_slice(&payload.token);
    raw.extend_from_slice(&payload.gateway_boot.to_be_bytes());
    raw.extend_from_slice(&payload.host_digest);
    raw.extend_from_slice(&payload.capabilities.to_be_bytes());
    raw.extend_from_slice(&payload.max_payload.to_be_bytes());
    raw.extend_from_slice(&payload.lease_ms.to_be_bytes());
    debug_assert_eq!(raw.len(), SERVICE_DESCRIPTOR_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn service_descriptor_decode(encoded: &[u8]) -> Result<ServiceDescriptor> {
    if encoded.len() != SERVICE_DESCRIPTOR_SIZE {
        return reject();
    }
    let scope = service_preamble_check(encoded, ServiceSubtype::Descriptor)?;
    let mut echo_nonce = [0_u8; 16];
    echo_nonce.copy_from_slice(&encoded[4..20]);
    let mut token = [0_u8; 16];
    token.copy_from_slice(&encoded[20..36]);
    let gateway_boot = u64::from_be_bytes(encoded[36..44].try_into().expect("fixed"));
    let mut host_digest = [0_u8; 32];
    host_digest.copy_from_slice(&encoded[44..76]);
    let max_payload = u16::from_be_bytes(encoded[80..82].try_into().expect("fixed"));
    if all_zero(&echo_nonce)
        || all_zero(&token)
        || gateway_boot == 0
        || usize::from(max_payload) > GATEWAY_PAYLOAD_MAX
    {
        return reject();
    }
    host_digest_scope_check(scope, &host_digest)?;
    Ok(ServiceDescriptor {
        scope,
        echo_nonce,
        token,
        gateway_boot,
        host_digest,
        capabilities: u32::from_be_bytes(encoded[76..80].try_into().expect("fixed")),
        max_payload,
        lease_ms: u32::from_be_bytes(encoded[82..86].try_into().expect("fixed")),
    })
}

/// Submit3 (32..128B): ver/sub3/scope/flags | token 16B | gateway_boot u64 |
/// payload_len u16 | reserved u16=0 | payload 0..96B.
#[derive(Clone, Debug)]
pub struct ServiceSubmit {
    pub scope: GatewayScope,
    pub token: [u8; 16],
    pub gateway_boot: u64,
    /// 0..96 bytes; a 0B payload is a legal empty message.
    pub payload: Vec<u8>,
}

pub fn service_submit_encode(payload: &ServiceSubmit, out: &mut EncodedPayload) -> Result<()> {
    if all_zero(&payload.token) || payload.gateway_boot == 0 {
        return invalid("service submit token/boot must be nonzero");
    }
    if payload.payload.len() > GATEWAY_PAYLOAD_MAX {
        return invalid("service submit payload exceeds 96 bytes");
    }
    let mut raw = Vec::with_capacity(SERVICE_SUBMIT_HEADER_SIZE + payload.payload.len());
    service_preamble_push(&mut raw, ServiceSubtype::Submit, payload.scope);
    raw.extend_from_slice(&payload.token);
    raw.extend_from_slice(&payload.gateway_boot.to_be_bytes());
    raw.extend_from_slice(&(payload.payload.len() as u16).to_be_bytes());
    raw.extend_from_slice(&0_u16.to_be_bytes());
    raw.extend_from_slice(&payload.payload);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn service_submit_decode(encoded: &[u8]) -> Result<ServiceSubmit> {
    if encoded.len() < SERVICE_SUBMIT_HEADER_SIZE
        || encoded.len() > SERVICE_SUBMIT_HEADER_SIZE + GATEWAY_PAYLOAD_MAX
    {
        return reject();
    }
    let scope = service_preamble_check(encoded, ServiceSubtype::Submit)?;
    let mut token = [0_u8; 16];
    token.copy_from_slice(&encoded[4..20]);
    let gateway_boot = u64::from_be_bytes(encoded[20..28].try_into().expect("fixed"));
    let payload_len = usize::from(u16::from_be_bytes(
        encoded[28..30].try_into().expect("fixed"),
    ));
    let reserved = u16::from_be_bytes(encoded[30..32].try_into().expect("fixed"));
    if reserved != 0
        || payload_len > GATEWAY_PAYLOAD_MAX
        || encoded.len() - SERVICE_SUBMIT_HEADER_SIZE != payload_len
        || all_zero(&token)
        || gateway_boot == 0
    {
        return reject();
    }
    Ok(ServiceSubmit {
        scope,
        token,
        gateway_boot,
        payload: encoded[SERVICE_SUBMIT_HEADER_SIZE..].to_vec(),
    })
}

/// Receipt4 / Pending5 / Reject6 (84B shared): ver/sub/scope/flags | token 16B
/// | gateway_boot u64 | ref_origin u64 | ref_session u32 | ref_sequence u64 |
/// request_digest 32B | reason u16 | reserved u16=0.
#[derive(Clone, Debug)]
pub struct ServiceOutcome {
    pub subtype: ServiceSubtype,
    pub scope: GatewayScope,
    pub token: [u8; 16],
    pub gateway_boot: u64,
    pub ref_origin: u64,
    pub ref_session: u32,
    pub ref_sequence: u64,
    pub request_digest: [u8; 32],
    pub reason: ServiceReason,
}

fn outcome_reason_ok(subtype: ServiceSubtype, reason: u16) -> bool {
    match subtype {
        ServiceSubtype::Receipt => reason == 0,
        ServiceSubtype::Pending => reason == 1,
        ServiceSubtype::Reject => (2..=8).contains(&reason),
        _ => false,
    }
}

pub fn service_outcome_encode(payload: &ServiceOutcome, out: &mut EncodedPayload) -> Result<()> {
    if !outcome_reason_ok(payload.subtype, payload.reason as u16) {
        return invalid("service outcome reason does not match its subtype");
    }
    if all_zero(&payload.token)
        || payload.gateway_boot == 0
        || payload.ref_origin == 0
        || payload.ref_origin == BROADCAST_NODE_ID
    {
        return invalid("service outcome token/boot/origin must be nonzero");
    }
    let mut raw = Vec::with_capacity(SERVICE_OUTCOME_SIZE);
    service_preamble_push(&mut raw, payload.subtype, payload.scope);
    raw.extend_from_slice(&payload.token);
    raw.extend_from_slice(&payload.gateway_boot.to_be_bytes());
    raw.extend_from_slice(&payload.ref_origin.to_be_bytes());
    raw.extend_from_slice(&payload.ref_session.to_be_bytes());
    raw.extend_from_slice(&payload.ref_sequence.to_be_bytes());
    raw.extend_from_slice(&payload.request_digest);
    raw.extend_from_slice(&(payload.reason as u16).to_be_bytes());
    raw.extend_from_slice(&0_u16.to_be_bytes());
    debug_assert_eq!(raw.len(), SERVICE_OUTCOME_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn service_outcome_decode(encoded: &[u8]) -> Result<ServiceOutcome> {
    if encoded.len() != SERVICE_OUTCOME_SIZE || encoded[0] != SERVICE_PAYLOAD_VERSION {
        return reject();
    }
    let subtype = match encoded[1] {
        4 => ServiceSubtype::Receipt,
        5 => ServiceSubtype::Pending,
        6 => ServiceSubtype::Reject,
        _ => return reject(),
    };
    if encoded[3] != 0 {
        return reject();
    }
    let scope = GatewayScope::from_u8(encoded[2])?;
    let mut token = [0_u8; 16];
    token.copy_from_slice(&encoded[4..20]);
    let gateway_boot = u64::from_be_bytes(encoded[20..28].try_into().expect("fixed"));
    let ref_origin = u64::from_be_bytes(encoded[28..36].try_into().expect("fixed"));
    let reason = u16::from_be_bytes(encoded[80..82].try_into().expect("fixed"));
    let reserved = u16::from_be_bytes(encoded[82..84].try_into().expect("fixed"));
    if reserved != 0
        || !outcome_reason_ok(subtype, reason)
        || all_zero(&token)
        || gateway_boot == 0
        || ref_origin == 0
        || ref_origin == BROADCAST_NODE_ID
    {
        return reject();
    }
    let mut request_digest = [0_u8; 32];
    request_digest.copy_from_slice(&encoded[48..80]);
    Ok(ServiceOutcome {
        subtype,
        scope,
        token,
        gateway_boot,
        ref_origin,
        ref_session: u32::from_be_bytes(encoded[36..40].try_into().expect("fixed")),
        ref_sequence: u64::from_be_bytes(encoded[40..48].try_into().expect("fixed")),
        request_digest,
        reason: match reason {
            0 => ServiceReason::Ok,
            1 => ServiceReason::PendingWait,
            2 => ServiceReason::TokenStale,
            3 => ServiceReason::HostUnavailable,
            4 => ServiceReason::Capacity,
            5 => ServiceReason::RoleDenied,
            6 => ServiceReason::Unsupported,
            7 => ServiceReason::Deadline,
            8 => ServiceReason::Conflict,
            _ => return reject(),
        },
    })
}

// --- Control=22 payloads (§5.5) ---------------------------------------------------

pub const CONTROL_PAYLOAD_VERSION: u8 = 1;
pub const CONFIG_NAMESPACE_SDK: u16 = 1;
pub const CONFIG_NAMESPACE_APP_MIN: u16 = 0x8000;
pub const CONFIG_NAMESPACE_APP_MAX: u16 = 0xfffe;
pub const CONTROL_CHALLENGE_QUERY_SIZE: usize = 24;
pub const CONTROL_CHALLENGE_SIZE: usize = 92;
pub const CONTROL_STATUS_QUERY_SIZE: usize = 20;
pub const CONTROL_STATUS_SIZE: usize = 72;
pub const TRUST_STATUS_QUERY_SIZE: usize = 20;
pub const TRUST_STATUS_SIZE: usize = 72;
pub const RECOVERY_INFO_QUERY_SIZE: usize = 20;
pub const RECOVERY_INFO_SIZE: usize = 80;

pub fn config_namespace_valid(value: u16) -> bool {
    value == CONFIG_NAMESPACE_SDK
        || (CONFIG_NAMESPACE_APP_MIN..=CONFIG_NAMESPACE_APP_MAX).contains(&value)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConfigPhase {
    Idle = 0,
    Prepared = 1,
    Decided = 2,
    ApplyIntent = 3,
    Applying = 4,
    Verifying = 5,
    Active = 6,
    Interrupted = 7,
    Quarantined = 8,
}

/// Config-local reason table (§5.5).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ConfigReason {
    Ok = 0,
    InProgress = 1,
    StaleRevision = 2,
    BaseHashMismatch = 3,
    InvalidPatch = 4,
    Deadline = 5,
    AuthorityDenied = 6,
    Unsupported = 7,
    Capacity = 8,
    StorageFailure = 9,
    ApplyInterrupted = 10,
    VerifyFailed = 11,
    RecoveryRequired = 12,
    MaintenanceBusy = 13,
    NoChange = 14,
    ResultExpired = 15,
}

fn control_preamble_check(encoded: &[u8], subtype: u8) -> Result<()> {
    if encoded.len() < 2 || encoded[0] != CONTROL_PAYLOAD_VERSION || encoded[1] != subtype {
        return reject();
    }
    Ok(())
}

/// ChallengeQuery1 (24B): ver/sub1 | ns u16 | schema u16 | reserved u16=0 |
/// client_nonce 16B.
#[derive(Clone, Debug)]
pub struct ControlChallengeQuery {
    pub config_namespace: u16,
    pub schema: u16,
    pub client_nonce: [u8; 16],
}

pub fn control_challenge_query_encode(
    payload: &ControlChallengeQuery,
    out: &mut EncodedPayload,
) -> Result<()> {
    if !config_namespace_valid(payload.config_namespace) {
        return invalid("control namespace is not registered");
    }
    if all_zero(&payload.client_nonce) {
        return invalid("challenge query client nonce must be nonzero");
    }
    let mut raw = Vec::with_capacity(CONTROL_CHALLENGE_QUERY_SIZE);
    raw.push(CONTROL_PAYLOAD_VERSION);
    raw.push(1);
    raw.extend_from_slice(&payload.config_namespace.to_be_bytes());
    raw.extend_from_slice(&payload.schema.to_be_bytes());
    raw.extend_from_slice(&0_u16.to_be_bytes());
    raw.extend_from_slice(&payload.client_nonce);
    debug_assert_eq!(raw.len(), CONTROL_CHALLENGE_QUERY_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn control_challenge_query_decode(encoded: &[u8]) -> Result<ControlChallengeQuery> {
    if encoded.len() != CONTROL_CHALLENGE_QUERY_SIZE {
        return reject();
    }
    control_preamble_check(encoded, 1)?;
    let config_namespace = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let reserved = u16::from_be_bytes(encoded[6..8].try_into().expect("fixed"));
    let mut client_nonce = [0_u8; 16];
    client_nonce.copy_from_slice(&encoded[8..24]);
    if reserved != 0 || !config_namespace_valid(config_namespace) || all_zero(&client_nonce) {
        return reject();
    }
    Ok(ControlChallengeQuery {
        config_namespace,
        schema: u16::from_be_bytes(encoded[4..6].try_into().expect("fixed")),
        client_nonce,
    })
}

/// Challenge2 (92B): the ChallengeQuery 24B head with sub2 (client_nonce is
/// the echo) | target_boot u64 | challenge_nonce 16B | revision u64 |
/// active_hash 32B | valid_for_ms u32.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlChallenge {
    pub config_namespace: u16,
    pub schema: u16,
    pub client_nonce: [u8; 16],
    pub target_boot: u64,
    pub challenge_nonce: [u8; 16],
    pub revision: u64,
    pub active_hash: [u8; 32],
    pub valid_for_ms: u32,
}

pub fn control_challenge_encode(
    payload: &ControlChallenge,
    out: &mut EncodedPayload,
) -> Result<()> {
    if !config_namespace_valid(payload.config_namespace) {
        return invalid("control namespace is not registered");
    }
    if all_zero(&payload.client_nonce)
        || all_zero(&payload.challenge_nonce)
        || payload.target_boot == 0
    {
        return invalid("challenge nonce/boot fields must be nonzero");
    }
    let mut raw = Vec::with_capacity(CONTROL_CHALLENGE_SIZE);
    raw.push(CONTROL_PAYLOAD_VERSION);
    raw.push(2);
    raw.extend_from_slice(&payload.config_namespace.to_be_bytes());
    raw.extend_from_slice(&payload.schema.to_be_bytes());
    raw.extend_from_slice(&0_u16.to_be_bytes());
    raw.extend_from_slice(&payload.client_nonce);
    raw.extend_from_slice(&payload.target_boot.to_be_bytes());
    raw.extend_from_slice(&payload.challenge_nonce);
    raw.extend_from_slice(&payload.revision.to_be_bytes());
    raw.extend_from_slice(&payload.active_hash);
    raw.extend_from_slice(&payload.valid_for_ms.to_be_bytes());
    debug_assert_eq!(raw.len(), CONTROL_CHALLENGE_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn control_challenge_decode(encoded: &[u8]) -> Result<ControlChallenge> {
    if encoded.len() != CONTROL_CHALLENGE_SIZE {
        return reject();
    }
    control_preamble_check(encoded, 2)?;
    let config_namespace = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let reserved = u16::from_be_bytes(encoded[6..8].try_into().expect("fixed"));
    let mut client_nonce = [0_u8; 16];
    client_nonce.copy_from_slice(&encoded[8..24]);
    let target_boot = u64::from_be_bytes(encoded[24..32].try_into().expect("fixed"));
    let mut challenge_nonce = [0_u8; 16];
    challenge_nonce.copy_from_slice(&encoded[32..48]);
    if reserved != 0
        || !config_namespace_valid(config_namespace)
        || all_zero(&client_nonce)
        || all_zero(&challenge_nonce)
        || target_boot == 0
    {
        return reject();
    }
    let mut active_hash = [0_u8; 32];
    active_hash.copy_from_slice(&encoded[56..88]);
    Ok(ControlChallenge {
        config_namespace,
        schema: u16::from_be_bytes(encoded[4..6].try_into().expect("fixed")),
        client_nonce,
        target_boot,
        challenge_nonce,
        revision: u64::from_be_bytes(encoded[48..56].try_into().expect("fixed")),
        active_hash,
        valid_for_ms: u32::from_be_bytes(encoded[88..92].try_into().expect("fixed")),
    })
}

/// StatusQuery3 (20B): ver/sub3 | ns u16 | opid 16B.
#[derive(Clone, Debug)]
pub struct ControlStatusQuery {
    pub config_namespace: u16,
    pub operation_id: [u8; 16],
}

pub fn control_status_query_encode(
    payload: &ControlStatusQuery,
    out: &mut EncodedPayload,
) -> Result<()> {
    if !config_namespace_valid(payload.config_namespace) {
        return invalid("control namespace is not registered");
    }
    if all_zero(&payload.operation_id) {
        return invalid("status query operation id must be nonzero");
    }
    let mut raw = Vec::with_capacity(CONTROL_STATUS_QUERY_SIZE);
    raw.push(CONTROL_PAYLOAD_VERSION);
    raw.push(3);
    raw.extend_from_slice(&payload.config_namespace.to_be_bytes());
    raw.extend_from_slice(&payload.operation_id);
    debug_assert_eq!(raw.len(), CONTROL_STATUS_QUERY_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn control_status_query_decode(encoded: &[u8]) -> Result<ControlStatusQuery> {
    if encoded.len() != CONTROL_STATUS_QUERY_SIZE {
        return reject();
    }
    control_preamble_check(encoded, 3)?;
    let config_namespace = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let mut operation_id = [0_u8; 16];
    operation_id.copy_from_slice(&encoded[4..20]);
    if !config_namespace_valid(config_namespace) || all_zero(&operation_id) {
        return reject();
    }
    Ok(ControlStatusQuery {
        config_namespace,
        operation_id,
    })
}

/// Status4 (72B): ver/sub4 | ns u16 | opid 16B | decision_rev u64 |
/// active_rev u64 | phase u8 | reserved u8=0 | reason u16 | active_hash 32B.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ControlStatus {
    pub config_namespace: u16,
    pub operation_id: [u8; 16],
    pub decision_revision: u64,
    pub active_revision: u64,
    pub phase: ConfigPhase,
    pub reason: ConfigReason,
    pub active_hash: [u8; 32],
}

pub fn control_status_encode(payload: &ControlStatus, out: &mut EncodedPayload) -> Result<()> {
    if !config_namespace_valid(payload.config_namespace) {
        return invalid("control namespace is not registered");
    }
    if all_zero(&payload.operation_id) {
        return invalid("status operation id must be nonzero");
    }
    let mut raw = Vec::with_capacity(CONTROL_STATUS_SIZE);
    raw.push(CONTROL_PAYLOAD_VERSION);
    raw.push(4);
    raw.extend_from_slice(&payload.config_namespace.to_be_bytes());
    raw.extend_from_slice(&payload.operation_id);
    raw.extend_from_slice(&payload.decision_revision.to_be_bytes());
    raw.extend_from_slice(&payload.active_revision.to_be_bytes());
    raw.push(payload.phase as u8);
    raw.push(0);
    raw.extend_from_slice(&(payload.reason as u16).to_be_bytes());
    raw.extend_from_slice(&payload.active_hash);
    debug_assert_eq!(raw.len(), CONTROL_STATUS_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn control_status_decode(encoded: &[u8]) -> Result<ControlStatus> {
    if encoded.len() != CONTROL_STATUS_SIZE {
        return reject();
    }
    control_preamble_check(encoded, 4)?;
    let config_namespace = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let mut operation_id = [0_u8; 16];
    operation_id.copy_from_slice(&encoded[4..20]);
    let phase = match encoded[36] {
        0 => ConfigPhase::Idle,
        1 => ConfigPhase::Prepared,
        2 => ConfigPhase::Decided,
        3 => ConfigPhase::ApplyIntent,
        4 => ConfigPhase::Applying,
        5 => ConfigPhase::Verifying,
        6 => ConfigPhase::Active,
        7 => ConfigPhase::Interrupted,
        8 => ConfigPhase::Quarantined,
        _ => return reject(),
    };
    let reserved = encoded[37];
    let reason = match u16::from_be_bytes(encoded[38..40].try_into().expect("fixed")) {
        0 => ConfigReason::Ok,
        1 => ConfigReason::InProgress,
        2 => ConfigReason::StaleRevision,
        3 => ConfigReason::BaseHashMismatch,
        4 => ConfigReason::InvalidPatch,
        5 => ConfigReason::Deadline,
        6 => ConfigReason::AuthorityDenied,
        7 => ConfigReason::Unsupported,
        8 => ConfigReason::Capacity,
        9 => ConfigReason::StorageFailure,
        10 => ConfigReason::ApplyInterrupted,
        11 => ConfigReason::VerifyFailed,
        12 => ConfigReason::RecoveryRequired,
        13 => ConfigReason::MaintenanceBusy,
        14 => ConfigReason::NoChange,
        15 => ConfigReason::ResultExpired,
        _ => return reject(),
    };
    if reserved != 0 || !config_namespace_valid(config_namespace) || all_zero(&operation_id) {
        return reject();
    }
    let mut active_hash = [0_u8; 32];
    active_hash.copy_from_slice(&encoded[40..72]);
    Ok(ControlStatus {
        config_namespace,
        operation_id,
        decision_revision: u64::from_be_bytes(encoded[20..28].try_into().expect("fixed")),
        active_revision: u64::from_be_bytes(encoded[28..36].try_into().expect("fixed")),
        phase,
        reason,
        active_hash,
    })
}

/// TrustStatusQuery5 (20B): ver/sub5 | reserved u16=0 | nonce 16B.
/// Device global (trust has no namespace); the reply echoes the nonce.
#[derive(Clone, Debug)]
pub struct TrustStatusQuery {
    pub nonce: [u8; 16],
}

pub fn trust_status_query_encode(
    payload: &TrustStatusQuery,
    out: &mut EncodedPayload,
) -> Result<()> {
    if all_zero(&payload.nonce) {
        return invalid("trust query nonce must be nonzero");
    }
    let mut raw = Vec::with_capacity(TRUST_STATUS_QUERY_SIZE);
    raw.push(CONTROL_PAYLOAD_VERSION);
    raw.push(5);
    raw.extend_from_slice(&0_u16.to_be_bytes());
    raw.extend_from_slice(&payload.nonce);
    debug_assert_eq!(raw.len(), TRUST_STATUS_QUERY_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn trust_status_query_decode(encoded: &[u8]) -> Result<TrustStatusQuery> {
    if encoded.len() != TRUST_STATUS_QUERY_SIZE {
        return reject();
    }
    control_preamble_check(encoded, 5)?;
    let reserved = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&encoded[4..20]);
    if reserved != 0 || all_zero(&nonce) {
        return reject();
    }
    Ok(TrustStatusQuery { nonce })
}

pub const TRUST_STATUS_FLAG_HAS_ACTIVE: u8 = 0x01;
pub const TRUST_STATUS_FLAG_UNCERTAIN: u8 = 0x02;
pub const TRUST_STATUS_FLAG_QUARANTINED: u8 = 0x04;
const TRUST_STATUS_FLAG_MASK: u8 = 0x07;

/// TrustStatus6 (72B): ver/sub6 | reserved u16=0 | nonce_echo 16B |
/// store_epoch u32 | min_authority_generation u32 | network u64 |
/// image_fingerprint 32B | anchor/key/revocation counts u8 | flags u8.
/// Public fields only — never keys, never grant bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustStatus {
    pub nonce_echo: [u8; 16],
    pub store_epoch: u32,
    pub min_authority_generation: u32,
    pub network: u64,
    pub image_fingerprint: [u8; 32],
    pub anchor_count: u8,
    pub key_count: u8,
    pub revocation_count: u8,
    pub flags: u8,
}

pub fn trust_status_encode(payload: &TrustStatus, out: &mut EncodedPayload) -> Result<()> {
    if all_zero(&payload.nonce_echo) {
        return invalid("trust status nonce echo must be nonzero");
    }
    if payload.flags & !TRUST_STATUS_FLAG_MASK != 0 {
        return invalid("trust status flags out of range");
    }
    let mut raw = Vec::with_capacity(TRUST_STATUS_SIZE);
    raw.push(CONTROL_PAYLOAD_VERSION);
    raw.push(6);
    raw.extend_from_slice(&0_u16.to_be_bytes());
    raw.extend_from_slice(&payload.nonce_echo);
    raw.extend_from_slice(&payload.store_epoch.to_be_bytes());
    raw.extend_from_slice(&payload.min_authority_generation.to_be_bytes());
    raw.extend_from_slice(&payload.network.to_be_bytes());
    raw.extend_from_slice(&payload.image_fingerprint);
    raw.push(payload.anchor_count);
    raw.push(payload.key_count);
    raw.push(payload.revocation_count);
    raw.push(payload.flags);
    debug_assert_eq!(raw.len(), TRUST_STATUS_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn trust_status_decode(encoded: &[u8]) -> Result<TrustStatus> {
    if encoded.len() != TRUST_STATUS_SIZE {
        return reject();
    }
    control_preamble_check(encoded, 6)?;
    let reserved = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let mut nonce_echo = [0_u8; 16];
    nonce_echo.copy_from_slice(&encoded[4..20]);
    let mut image_fingerprint = [0_u8; 32];
    image_fingerprint.copy_from_slice(&encoded[36..68]);
    let flags = encoded[71];
    if reserved != 0 || all_zero(&nonce_echo) || flags & !TRUST_STATUS_FLAG_MASK != 0 {
        return reject();
    }
    Ok(TrustStatus {
        nonce_echo,
        store_epoch: u32::from_be_bytes(encoded[20..24].try_into().expect("fixed")),
        min_authority_generation: u32::from_be_bytes(encoded[24..28].try_into().expect("fixed")),
        network: u64::from_be_bytes(encoded[28..36].try_into().expect("fixed")),
        image_fingerprint,
        anchor_count: encoded[68],
        key_count: encoded[69],
        revocation_count: encoded[70],
        flags,
    })
}

/// RecoveryInfoQuery7 (20B): ver/sub7 | ns u16 | nonce 16B. Selects the
/// journal; the reply echoes the nonce.
#[derive(Clone, Debug)]
pub struct RecoveryInfoQuery {
    pub config_namespace: u16,
    pub nonce: [u8; 16],
}

pub fn recovery_info_query_encode(
    payload: &RecoveryInfoQuery,
    out: &mut EncodedPayload,
) -> Result<()> {
    if !config_namespace_valid(payload.config_namespace) {
        return invalid("control namespace is not registered");
    }
    if all_zero(&payload.nonce) {
        return invalid("recovery query nonce must be nonzero");
    }
    let mut raw = Vec::with_capacity(RECOVERY_INFO_QUERY_SIZE);
    raw.push(CONTROL_PAYLOAD_VERSION);
    raw.push(7);
    raw.extend_from_slice(&payload.config_namespace.to_be_bytes());
    raw.extend_from_slice(&payload.nonce);
    debug_assert_eq!(raw.len(), RECOVERY_INFO_QUERY_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn recovery_info_query_decode(encoded: &[u8]) -> Result<RecoveryInfoQuery> {
    if encoded.len() != RECOVERY_INFO_QUERY_SIZE {
        return reject();
    }
    control_preamble_check(encoded, 7)?;
    let config_namespace = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let mut nonce = [0_u8; 16];
    nonce.copy_from_slice(&encoded[4..20]);
    if !config_namespace_valid(config_namespace) || all_zero(&nonce) {
        return reject();
    }
    Ok(RecoveryInfoQuery {
        config_namespace,
        nonce,
    })
}

pub const RECOVERY_INFO_FLAG_IMPAIRED: u8 = 0x01;
pub const RECOVERY_INFO_FLAG_UNCERTAIN: u8 = 0x02;
pub const RECOVERY_INFO_FLAG_QUARANTINED: u8 = 0x04;
pub const RECOVERY_INFO_FLAG_SURVIVOR_KNOWN: u8 = 0x08;
const RECOVERY_INFO_FLAG_MASK: u8 = 0x0F;

/// RecoveryInfo8 (80B): ver/sub8 | ns u16 | schema u16 | nonce_echo 16B |
/// network u64 | store floor J u32 | decision floor R u64 | flags u8 |
/// recovery_version u8 | profile_bits u32 | snapshot_hash 32B. Read-only
/// and advisory: J/R name the exact-next recovery, the hash names the
/// known survivor baseline (or explicit unknown).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryInfo {
    pub config_namespace: u16,
    pub schema: u16,
    pub nonce_echo: [u8; 16],
    pub network: u64,
    pub store_floor: u32,
    pub decision_floor: u64,
    pub flags: u8,
    pub recovery_version: u8,
    pub profile_bits: u32,
    pub snapshot_hash: [u8; 32],
}

pub fn recovery_info_encode(payload: &RecoveryInfo, out: &mut EncodedPayload) -> Result<()> {
    if !config_namespace_valid(payload.config_namespace) {
        return invalid("control namespace is not registered");
    }
    if all_zero(&payload.nonce_echo) {
        return invalid("recovery info nonce echo must be nonzero");
    }
    if payload.flags & !RECOVERY_INFO_FLAG_MASK != 0 {
        return invalid("recovery info flags out of range");
    }
    if payload.recovery_version == 0 {
        return invalid("recovery info version must be nonzero");
    }
    let mut raw = Vec::with_capacity(RECOVERY_INFO_SIZE);
    raw.push(CONTROL_PAYLOAD_VERSION);
    raw.push(8);
    raw.extend_from_slice(&payload.config_namespace.to_be_bytes());
    raw.extend_from_slice(&payload.schema.to_be_bytes());
    raw.extend_from_slice(&payload.nonce_echo);
    raw.extend_from_slice(&payload.network.to_be_bytes());
    raw.extend_from_slice(&payload.store_floor.to_be_bytes());
    raw.extend_from_slice(&payload.decision_floor.to_be_bytes());
    raw.push(payload.flags);
    raw.push(payload.recovery_version);
    raw.extend_from_slice(&payload.profile_bits.to_be_bytes());
    raw.extend_from_slice(&payload.snapshot_hash);
    debug_assert_eq!(raw.len(), RECOVERY_INFO_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn recovery_info_decode(encoded: &[u8]) -> Result<RecoveryInfo> {
    if encoded.len() != RECOVERY_INFO_SIZE {
        return reject();
    }
    control_preamble_check(encoded, 8)?;
    let config_namespace = u16::from_be_bytes(encoded[2..4].try_into().expect("fixed"));
    let schema = u16::from_be_bytes(encoded[4..6].try_into().expect("fixed"));
    let mut nonce_echo = [0_u8; 16];
    nonce_echo.copy_from_slice(&encoded[6..22]);
    let flags = encoded[42];
    let recovery_version = encoded[43];
    let mut snapshot_hash = [0_u8; 32];
    snapshot_hash.copy_from_slice(&encoded[48..80]);
    if !config_namespace_valid(config_namespace)
        || all_zero(&nonce_echo)
        || flags & !RECOVERY_INFO_FLAG_MASK != 0
        || recovery_version == 0
    {
        return reject();
    }
    Ok(RecoveryInfo {
        config_namespace,
        schema,
        nonce_echo,
        network: u64::from_be_bytes(encoded[22..30].try_into().expect("fixed")),
        store_floor: u32::from_be_bytes(encoded[30..34].try_into().expect("fixed")),
        decision_floor: u64::from_be_bytes(encoded[34..42].try_into().expect("fixed")),
        flags,
        recovery_version,
        profile_bits: u32::from_be_bytes(encoded[44..48].try_into().expect("fixed")),
        snapshot_hash,
    })
}

// --- RCC1 canonical config command (§5.4) ------------------------------------------

pub const RCC1_MAGIC: u32 = 0x5243_4331; // "RCC1"
pub const RCC1_VERSION: u8 = 1;
pub const RCC1_HEADER_SIZE: usize = 176;
pub const CONFIG_PATCH_MAX: usize = 512;
pub const CONFIG_FIELD_COUNT_MAX: usize = 16;
pub const CONFIG_FIELD_VALUE_MAX: usize = 96;
pub const RCC1_MAX_TOTAL: usize = RCC1_HEADER_SIZE + CONFIG_PATCH_MAX; // 688

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ConfigFieldType {
    Bool = 1,
    U8 = 2,
    U32 = 3,
    Bytes = 4,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigField {
    pub field_id: u16,
    pub field_type: ConfigFieldType,
    /// Exact type length: bool/u8 = 1, u32 = 4, bytes = 0..96.
    pub value: Vec<u8>,
}

fn tlv_value_length(field_type: u8, declared: u16) -> Option<usize> {
    let declared = usize::from(declared);
    match field_type {
        1 => (declared == 1).then_some(1),
        2 => (declared == 1).then_some(1),
        3 => (declared == 4).then_some(4),
        4 => (declared <= CONFIG_FIELD_VALUE_MAX).then_some(declared),
        _ => None,
    }
}

/// 176B fixed header + sorted TLV patch (max 512B) = max 688B.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigCommand {
    pub config_namespace: u16,
    pub schema: u16,
    pub network: u64,
    pub target: u64,
    pub authority: u64,
    pub authority_generation: u32,
    pub authority_sequence: u64,
    pub operation_id: [u8; 16],
    pub expected_revision: u64,
    /// Must equal expected_revision + 1.
    pub next_revision: u64,
    pub base_snapshot_hash: [u8; 32],
    pub next_snapshot_hash: [u8; 32],
    pub target_boot: u64,
    pub challenge_nonce: [u8; 16],
    pub apply_within_ms: u32,
    /// 1..16 fields; field ids strictly ascending.
    pub fields: Vec<ConfigField>,
}

fn config_command_valid_fields(fields: &[ConfigField]) -> Result<usize> {
    // The bare-TLV path shares this validator and the C++ encoder refuses
    // >16 fields outright — enforce the same bound here or a host-encoded
    // snapshot diverges from what the device can accept.
    if fields.len() > CONFIG_FIELD_COUNT_MAX {
        return invalid("config field count exceeds 16");
    }
    let mut patch_len = 0_usize;
    let mut previous_id = 0_u16;
    for (index, field) in fields.iter().enumerate() {
        if field.value.len() > CONFIG_FIELD_VALUE_MAX {
            return invalid("config field value exceeds 96 bytes");
        }
        let value_len = tlv_value_length(field.field_type as u8, field.value.len() as u16)
            .ok_or_else(|| {
                WireError::new(
                    ErrorCode::InvalidArgument,
                    "config field type/length invalid",
                )
            })?;
        if value_len != field.value.len() {
            return invalid("config field value length disagrees with its type");
        }
        if field.field_type == ConfigFieldType::Bool && field.value != [0] && field.value != [1] {
            return invalid("config bool field must be 0 or 1");
        }
        if index > 0 && field.field_id <= previous_id {
            return invalid("config field ids must be strictly ascending");
        }
        previous_id = field.field_id;
        patch_len += 5 + value_len;
        if patch_len > CONFIG_PATCH_MAX {
            return invalid("config patch exceeds 512 bytes");
        }
    }
    Ok(patch_len)
}

fn config_command_header_check(command: &ConfigCommand) -> Result<()> {
    if !config_namespace_valid(command.config_namespace) {
        return invalid("config namespace is not registered");
    }
    // target/authority are logical unicast node ids: 0 (invalid) and
    // u64::MAX (broadcast) are both reserved and can never be a peer —
    // mirrors the C++ codec's check in endpoint_wire.cpp.
    if command.network == 0
        || command.target == 0
        || command.target == BROADCAST_NODE_ID
        || command.authority == 0
        || command.authority == BROADCAST_NODE_ID
        || all_zero(&command.operation_id)
        || command.target_boot == 0
        || all_zero(&command.challenge_nonce)
    {
        return invalid("config command identity/nonce fields must be nonzero");
    }
    // The u64 axis reserves its top value: next == MAX can never be a
    // decision (nothing could follow it), and the authority sequence
    // shares the same reservation so both counters fail closed at the
    // bound.
    if command.expected_revision == u64::MAX
        || command.next_revision != command.expected_revision + 1
        || command.next_revision == u64::MAX
        || command.authority_sequence == u64::MAX
    {
        return invalid("config revision must satisfy next = expected + 1");
    }
    if command.fields.is_empty() || command.fields.len() > CONFIG_FIELD_COUNT_MAX {
        return invalid("config field_count out of range");
    }
    Ok(())
}

pub fn config_command_encode(command: &ConfigCommand, out: &mut Vec<u8>) -> Result<()> {
    config_command_header_check(command)?;
    let patch_len = config_command_valid_fields(&command.fields)?;
    out.clear();
    out.reserve(RCC1_HEADER_SIZE + patch_len);
    out.extend_from_slice(&RCC1_MAGIC.to_be_bytes());
    out.push(RCC1_VERSION);
    out.push(0);
    out.extend_from_slice(&command.config_namespace.to_be_bytes());
    out.extend_from_slice(&command.schema.to_be_bytes());
    out.extend_from_slice(&(command.fields.len() as u16).to_be_bytes());
    out.extend_from_slice(&command.network.to_be_bytes());
    out.extend_from_slice(&command.target.to_be_bytes());
    out.extend_from_slice(&command.authority.to_be_bytes());
    out.extend_from_slice(&command.authority_generation.to_be_bytes());
    out.extend_from_slice(&command.authority_sequence.to_be_bytes());
    out.extend_from_slice(&command.operation_id);
    out.extend_from_slice(&command.expected_revision.to_be_bytes());
    out.extend_from_slice(&command.next_revision.to_be_bytes());
    out.extend_from_slice(&command.base_snapshot_hash);
    out.extend_from_slice(&command.next_snapshot_hash);
    out.extend_from_slice(&command.target_boot.to_be_bytes());
    out.extend_from_slice(&command.challenge_nonce);
    out.extend_from_slice(&command.apply_within_ms.to_be_bytes());
    out.extend_from_slice(&(patch_len as u16).to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    for field in &command.fields {
        out.extend_from_slice(&field.field_id.to_be_bytes());
        out.push(field.field_type as u8);
        out.extend_from_slice(&(field.value.len() as u16).to_be_bytes());
        out.extend_from_slice(&field.value);
    }
    debug_assert_eq!(out.len(), RCC1_HEADER_SIZE + patch_len);
    Ok(())
}

pub fn config_command_decode(encoded: &[u8]) -> Result<ConfigCommand> {
    if encoded.len() < RCC1_HEADER_SIZE || encoded.len() > RCC1_MAX_TOTAL {
        return reject();
    }
    let magic = u32::from_be_bytes(encoded[0..4].try_into().expect("fixed"));
    let version = encoded[4];
    let flags = encoded[5];
    let config_namespace = u16::from_be_bytes(encoded[6..8].try_into().expect("fixed"));
    let schema = u16::from_be_bytes(encoded[8..10].try_into().expect("fixed"));
    let field_count = usize::from(u16::from_be_bytes(
        encoded[10..12].try_into().expect("fixed"),
    ));
    let expected_revision = u64::from_be_bytes(encoded[64..72].try_into().expect("fixed"));
    let next_revision = u64::from_be_bytes(encoded[72..80].try_into().expect("fixed"));
    let patch_len = usize::from(u16::from_be_bytes(
        encoded[172..174].try_into().expect("fixed"),
    ));
    let reserved = u16::from_be_bytes(encoded[174..176].try_into().expect("fixed"));
    let mut operation_id = [0_u8; 16];
    operation_id.copy_from_slice(&encoded[48..64]);
    let mut challenge_nonce = [0_u8; 16];
    challenge_nonce.copy_from_slice(&encoded[152..168]);
    let network = u64::from_be_bytes(encoded[12..20].try_into().expect("fixed"));
    let target = u64::from_be_bytes(encoded[20..28].try_into().expect("fixed"));
    let authority = u64::from_be_bytes(encoded[28..36].try_into().expect("fixed"));
    let authority_sequence = u64::from_be_bytes(encoded[40..48].try_into().expect("fixed"));
    let target_boot = u64::from_be_bytes(encoded[144..152].try_into().expect("fixed"));
    if magic != RCC1_MAGIC
        || version != RCC1_VERSION
        || flags != 0
        || reserved != 0
        || !config_namespace_valid(config_namespace)
        || field_count == 0
        || field_count > CONFIG_FIELD_COUNT_MAX
        || encoded.len() - RCC1_HEADER_SIZE != patch_len
        || expected_revision == u64::MAX
        || next_revision != expected_revision + 1
        || next_revision == u64::MAX
        || authority_sequence == u64::MAX
        || network == 0
        || target == 0
        || target == BROADCAST_NODE_ID
        || authority == 0
        || authority == BROADCAST_NODE_ID
        || target_boot == 0
        || all_zero(&operation_id)
        || all_zero(&challenge_nonce)
    {
        return reject();
    }
    // Sorted TLV patch: strict ascending ids, known types, exact lengths.
    let patch = &encoded[RCC1_HEADER_SIZE..];
    let mut fields = Vec::with_capacity(field_count);
    let mut cursor = 0_usize;
    let mut previous_id = 0_u16;
    for index in 0..field_count {
        if patch.len() - cursor < 5 {
            return reject();
        }
        let field_id = u16::from_be_bytes(patch[cursor..cursor + 2].try_into().expect("fixed"));
        let field_type_raw = patch[cursor + 2];
        let declared = u16::from_be_bytes(patch[cursor + 3..cursor + 5].try_into().expect("fixed"));
        let Some(value_len) = tlv_value_length(field_type_raw, declared) else {
            return reject();
        };
        if index > 0 && field_id <= previous_id {
            return reject();
        }
        previous_id = field_id;
        let start = cursor + 5;
        if patch.len() - start < value_len {
            return reject();
        }
        let value = patch[start..start + value_len].to_vec();
        if field_type_raw == 1 && value != [0] && value != [1] {
            return reject();
        }
        let field_type = match field_type_raw {
            1 => ConfigFieldType::Bool,
            2 => ConfigFieldType::U8,
            3 => ConfigFieldType::U32,
            4 => ConfigFieldType::Bytes,
            _ => return reject(),
        };
        fields.push(ConfigField {
            field_id,
            field_type,
            value,
        });
        cursor = start + value_len;
    }
    if cursor != patch.len() {
        return reject();
    }
    let mut base_snapshot_hash = [0_u8; 32];
    base_snapshot_hash.copy_from_slice(&encoded[80..112]);
    let mut next_snapshot_hash = [0_u8; 32];
    next_snapshot_hash.copy_from_slice(&encoded[112..144]);
    Ok(ConfigCommand {
        config_namespace,
        schema,
        network,
        target,
        authority,
        authority_generation: u32::from_be_bytes(encoded[36..40].try_into().expect("fixed")),
        authority_sequence: u64::from_be_bytes(encoded[40..48].try_into().expect("fixed")),
        operation_id,
        expected_revision,
        next_revision,
        base_snapshot_hash,
        next_snapshot_hash,
        target_boot,
        challenge_nonce,
        apply_within_ms: u32::from_be_bytes(encoded[168..172].try_into().expect("fixed")),
        fields,
    })
}

// --- RCR2 canonical recovery command (04-remote-config §4.7, 06 §6.3) --------
//
// Fixed 112B header plus the 0–512B adopted snapshot, carried as the signed
// payload of a kind-4 recovery object — never an RCC1 extension and never a
// kind-3 permit. RCR2 replaces RCR1 outright: no compatibility interpretation
// of the old magic or version exists. The Rust mirror must stay byte-identical
// with the C++ codec in endpoint_wire.cpp.

pub const RCR2_MAGIC: u32 = 0x5243_5232; // "RCR2"
pub const RCR2_VERSION: u8 = 2;
pub const RCR2_HEADER_SIZE: usize = 112;
pub const RCR2_MAX_TOTAL: usize = RCR2_HEADER_SIZE + CONFIG_SNAPSHOT_MAX;

pub const RCR2_MODE_ADOPT_KNOWN: u8 = 0;
pub const RCR2_MODE_REPROVISION: u8 = 1;

/// Recovery intent — no challenge/nonce binding by design (freshness is the
/// floor's exact-next authorization, replay protection the floor + dedup).
/// AdoptKnown binds the proven survivor by hash alone; Reprovision carries
/// the complete adopted snapshot as its baseline.
#[derive(Clone, Debug)]
pub struct ConfigRecoveryIntent {
    pub mode: u8,
    pub config_namespace: u16,
    pub schema: u16,
    pub network: u64,
    pub target: u64,
    pub authority: u64,
    /// The generation the signature verifies under.
    pub authority_generation: u32,
    pub authority_sequence: u64,
    pub operation_id: [u8; 16],
    /// The attested exact-next store generation.
    pub new_store_generation: u32,
    /// The attested exact-next decision revision.
    pub new_revision: u64,
    /// Domain-tagged SHA-256 of the adopted canonical snapshot.
    pub snapshot_hash: [u8; 32],
    /// The adopted baseline bytes (empty for AdoptKnown).
    pub baseline: Vec<u8>,
}

/// The adopted baseline is a complete canonical snapshot: strict ascending
/// field ids, known TLV types with exact lengths, canonical bools, at most
/// the field-count bound. The same shape rule as the RCC1 patch loop.
fn rcr2_snapshot_shape_valid(snapshot: &[u8]) -> bool {
    if snapshot.len() > CONFIG_SNAPSHOT_MAX {
        return false;
    }
    let mut cursor = 0_usize;
    let mut previous_id = 0_u16;
    let mut count = 0_usize;
    while cursor < snapshot.len() {
        if count >= CONFIG_FIELD_COUNT_MAX || snapshot.len() - cursor < 5 {
            return false;
        }
        let field_id = u16::from_be_bytes(snapshot[cursor..cursor + 2].try_into().expect("fixed"));
        let field_type = snapshot[cursor + 2];
        let declared =
            u16::from_be_bytes(snapshot[cursor + 3..cursor + 5].try_into().expect("fixed"));
        let Some(value_len) = tlv_value_length(field_type, declared) else {
            return false;
        };
        if snapshot.len() - (cursor + 5) < value_len {
            return false;
        }
        if count > 0 && field_id <= previous_id {
            return false;
        }
        previous_id = field_id;
        if field_type == 1 && snapshot[cursor + 5] > 1 {
            return false;
        }
        cursor += 5 + value_len;
        count += 1;
    }
    true
}

fn config_recovery_check(intent: &ConfigRecoveryIntent) -> Result<()> {
    if !config_namespace_valid(intent.config_namespace)
        || intent.network == 0
        || intent.target == 0
        || intent.target == BROADCAST_NODE_ID
        || intent.authority == 0
        || intent.authority == BROADCAST_NODE_ID
        || all_zero(&intent.operation_id)
    {
        return invalid("config recovery identity fields invalid");
    }
    if intent.mode != RCR2_MODE_ADOPT_KNOWN && intent.mode != RCR2_MODE_REPROVISION {
        return invalid("config recovery mode unknown");
    }
    if intent.mode == RCR2_MODE_ADOPT_KNOWN && !intent.baseline.is_empty() {
        return invalid("config recovery adopt-known carries no snapshot");
    }
    if intent.new_store_generation == 0
        || intent.new_store_generation == u32::MAX
        || intent.new_revision == 0
        || intent.new_revision == u64::MAX
        || intent.authority_sequence == u64::MAX
    {
        return invalid("config recovery counters invalid");
    }
    if !rcr2_snapshot_shape_valid(&intent.baseline) {
        return invalid("config recovery snapshot shape invalid");
    }
    Ok(())
}

pub fn config_recovery_encode(intent: &ConfigRecoveryIntent, out: &mut Vec<u8>) -> Result<()> {
    config_recovery_check(intent)?;
    out.clear();
    out.reserve(RCR2_HEADER_SIZE + intent.baseline.len());
    out.extend_from_slice(&RCR2_MAGIC.to_be_bytes());
    out.push(RCR2_VERSION);
    out.push(intent.mode);
    out.extend_from_slice(&intent.config_namespace.to_be_bytes());
    out.extend_from_slice(&intent.schema.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&intent.network.to_be_bytes());
    out.extend_from_slice(&intent.target.to_be_bytes());
    out.extend_from_slice(&intent.authority.to_be_bytes());
    out.extend_from_slice(&intent.authority_generation.to_be_bytes());
    out.extend_from_slice(&intent.authority_sequence.to_be_bytes());
    out.extend_from_slice(&intent.operation_id);
    out.extend_from_slice(&intent.new_store_generation.to_be_bytes());
    out.extend_from_slice(&intent.new_revision.to_be_bytes());
    out.extend_from_slice(&(intent.baseline.len() as u16).to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&intent.snapshot_hash);
    out.extend_from_slice(&intent.baseline);
    debug_assert_eq!(out.len(), RCR2_HEADER_SIZE + intent.baseline.len());
    Ok(())
}

pub fn config_recovery_decode(encoded: &[u8]) -> Result<ConfigRecoveryIntent> {
    if encoded.len() > RCR2_MAX_TOTAL {
        return reject();
    }
    // No compatibility interpretation of the old wire exists: anything that
    // is not an RCR2 body is Unsupported — including an RCR1 body, which is
    // shorter than the RCR2 header. The magic/version gate therefore runs
    // before the size gate, mirroring the C++ codec.
    if encoded.len() < 6 {
        return reject();
    }
    let magic = u32::from_be_bytes(encoded[0..4].try_into().expect("fixed"));
    let version = encoded[4];
    if magic != RCR2_MAGIC || version != RCR2_VERSION {
        return Err(WireError::new(
            ErrorCode::Unsupported,
            "config recovery version unsupported",
        ));
    }
    if encoded.len() < RCR2_HEADER_SIZE {
        return reject();
    }
    let mode = encoded[5];
    let config_namespace = u16::from_be_bytes(encoded[6..8].try_into().expect("fixed"));
    let schema = u16::from_be_bytes(encoded[8..10].try_into().expect("fixed"));
    let flags = u16::from_be_bytes(encoded[10..12].try_into().expect("fixed"));
    let network = u64::from_be_bytes(encoded[12..20].try_into().expect("fixed"));
    let target = u64::from_be_bytes(encoded[20..28].try_into().expect("fixed"));
    let authority = u64::from_be_bytes(encoded[28..36].try_into().expect("fixed"));
    let authority_generation = u32::from_be_bytes(encoded[36..40].try_into().expect("fixed"));
    let authority_sequence = u64::from_be_bytes(encoded[40..48].try_into().expect("fixed"));
    let mut operation_id = [0_u8; 16];
    operation_id.copy_from_slice(&encoded[48..64]);
    let new_store_generation = u32::from_be_bytes(encoded[64..68].try_into().expect("fixed"));
    let new_revision = u64::from_be_bytes(encoded[68..76].try_into().expect("fixed"));
    let snapshot_len = u16::from_be_bytes(encoded[76..78].try_into().expect("fixed")) as usize;
    let reserved = u16::from_be_bytes(encoded[78..80].try_into().expect("fixed"));
    let mut snapshot_hash = [0_u8; 32];
    snapshot_hash.copy_from_slice(&encoded[80..112]);
    let intent = ConfigRecoveryIntent {
        mode,
        config_namespace,
        schema,
        network,
        target,
        authority,
        authority_generation,
        authority_sequence,
        operation_id,
        new_store_generation,
        new_revision,
        snapshot_hash,
        baseline: encoded[RCR2_HEADER_SIZE..].to_vec(),
    };
    if flags != 0
        || reserved != 0
        || encoded.len() - RCR2_HEADER_SIZE != snapshot_len
        || config_recovery_check(&intent).is_err()
    {
        return reject();
    }
    Ok(intent)
}

/// Snapshot-hash input (§5.4): domain_snapshot || namespace u16 | schema u16 |
/// complete sorted TLV snapshot bytes.
pub const CONFIG_SNAPSHOT_MAX: usize = 512;
pub const CONFIG_SNAPSHOT_INPUT_MAX: usize = CONFIG_SNAPSHOT_DOMAIN.len() + 4 + CONFIG_SNAPSHOT_MAX;

pub fn config_snapshot_hash_input(
    config_namespace: u16,
    schema: u16,
    snapshot_tlv: &[u8],
) -> Result<Vec<u8>> {
    if !config_namespace_valid(config_namespace) {
        return invalid("config namespace is not registered");
    }
    if snapshot_tlv.len() > CONFIG_SNAPSHOT_MAX {
        return invalid("config snapshot exceeds the 512-byte bound");
    }
    let mut raw = Vec::with_capacity(CONFIG_SNAPSHOT_DOMAIN.len() + 4 + snapshot_tlv.len());
    raw.extend_from_slice(CONFIG_SNAPSHOT_DOMAIN);
    raw.extend_from_slice(&config_namespace.to_be_bytes());
    raw.extend_from_slice(&schema.to_be_bytes());
    raw.extend_from_slice(snapshot_tlv);
    Ok(raw)
}

// --- Snapshot / patch TLV (§5.4) ----------------------------------------------
//
// A snapshot is the complete sorted TLV of every active config field; a patch
// is a sorted TLV of the fields to change. Both share the RCC1 field record
// (id u16 | type u8 | len u16 | value), strictly ascending ids, <=16 fields,
// value <=96 B, no trailing bytes.

fn tlv_field_encode(field: &ConfigField, out: &mut Vec<u8>) {
    out.extend_from_slice(&field.field_id.to_be_bytes());
    out.push(field.field_type as u8);
    out.extend_from_slice(&(field.value.len() as u16).to_be_bytes());
    out.extend_from_slice(&field.value);
}

/// Serialize already-sorted, already-valid fields into snapshot TLV bytes.
/// `config_command_valid_fields` enforces the sort/type/length/512 bound;
/// an empty field set encodes to an empty snapshot.
pub fn config_tlv_encode(fields: &[ConfigField]) -> Result<Vec<u8>> {
    let patch_len = config_command_valid_fields(fields)?;
    let mut out = Vec::with_capacity(patch_len);
    for field in fields {
        tlv_field_encode(field, &mut out);
    }
    Ok(out)
}

/// Parse a snapshot TLV into fields: known types, exact lengths, strictly
/// ascending ids, <=16 fields, no trailing bytes.
pub fn config_tlv_decode(tlv: &[u8]) -> Result<Vec<ConfigField>> {
    if tlv.len() > CONFIG_SNAPSHOT_MAX {
        return reject();
    }
    let mut fields: Vec<ConfigField> = Vec::new();
    let mut cursor = 0_usize;
    let mut previous_id = 0_u16;
    while cursor < tlv.len() {
        if tlv.len() - cursor < 5 {
            return reject();
        }
        let field_id = u16::from_be_bytes(tlv[cursor..cursor + 2].try_into().expect("fixed"));
        let field_type_raw = tlv[cursor + 2];
        let declared = u16::from_be_bytes(tlv[cursor + 3..cursor + 5].try_into().expect("fixed"));
        let Some(value_len) = tlv_value_length(field_type_raw, declared) else {
            return reject();
        };
        if !fields.is_empty() && field_id <= previous_id {
            return reject();
        }
        previous_id = field_id;
        let start = cursor + 5;
        if tlv.len() - start < value_len {
            return reject();
        }
        let value = tlv[start..start + value_len].to_vec();
        if field_type_raw == 1 && value != [0] && value != [1] {
            return reject();
        }
        let field_type = match field_type_raw {
            1 => ConfigFieldType::Bool,
            2 => ConfigFieldType::U8,
            3 => ConfigFieldType::U32,
            4 => ConfigFieldType::Bytes,
            _ => return reject(),
        };
        fields.push(ConfigField {
            field_id,
            field_type,
            value,
        });
        if fields.len() > CONFIG_FIELD_COUNT_MAX {
            return reject();
        }
        cursor = start + value_len;
    }
    Ok(fields)
}

/// Merge a validated patch onto a base snapshot: patch fields overwrite the
/// same id, others are retained; the output stays strictly ascending. The
/// bool is `false` when the merged result equals the base — the issuer's
/// NO_CHANGE check before signing (no revision, no flash write).
pub fn config_patch_apply(base_tlv: &[u8], patch: &[ConfigField]) -> Result<(Vec<u8>, bool)> {
    let base = config_tlv_decode(base_tlv)?;
    config_command_valid_fields(patch)?;
    let mut merged: Vec<ConfigField> = Vec::with_capacity(base.len() + patch.len());
    let (mut i, mut j) = (0_usize, 0_usize);
    while i < base.len() || j < patch.len() {
        if i < base.len() && (j >= patch.len() || base[i].field_id < patch[j].field_id) {
            merged.push(base[i].clone());
            i += 1;
        } else if j < patch.len() && (i >= base.len() || patch[j].field_id < base[i].field_id) {
            merged.push(patch[j].clone());
            j += 1;
        } else {
            // Same field id on both sides: the patch value wins.
            merged.push(patch[j].clone());
            i += 1;
            j += 1;
        }
    }
    let next = config_tlv_encode(&merged)?;
    let changed = next != base_tlv;
    Ok((next, changed))
}
