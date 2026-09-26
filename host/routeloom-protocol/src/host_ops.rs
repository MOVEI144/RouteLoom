//! Device dispatch-window protocol (CAP-I2): the host_ops_v1 subcommand
//! codec the daemon uses to drive SUBMIT / QUERY_DISPATCH / RETIRE_THROUGH /
//! SKIP / TIME_SAMPLE. Byte-identical to the device side in
//! `components/routeloom/{include/routeloom/usb_host_ops.hpp,src/usb_host_ops.cpp}`
//! — the two files together are the shared USB source of truth the design
//! (03-send-api.md §6) requires subcommands to be registered in once.
//!
//! This module is protocol support only: it builds request inner bodies and
//! parses response inner bodies. The dispatch loop that assigns sequences,
//! maps deadlines and retires prefixes is TX-I2's job; nothing here sends
//! frames or owns retry state.

use std::fmt;

pub const CAP_HOST_OPS_V1: u32 = 1 << 2;
/// scope-gateway-config P3 (05-wire-api.md §5.6): the device serves the
/// Gateway HostOps subcommands 0x10-0x13 — host endpoint registration,
/// scope-2 ReceiveLog ingress + ACK, and unregister. Advertised separately
/// from host_ops_v1.
pub const CAP_GATEWAY_ENDPOINT_V1: u32 = 1 << 3;
/// scope-gateway-config P5 (05-wire-api.md §5.6): the device serves the
/// Config HostOps subcommands 0x20-0x23 — challenge/status queries and
/// permit-object transfer — through the attached ConfigGateway. Advertised
/// separately from host_ops_v1 and the gateway endpoint.
pub const CAP_CONFIG_ENDPOINT_V1: u32 = 1 << 4;
pub const HOST_OPS_SCHEMA: u8 = 1;

pub const SUB_SUBMIT: u8 = 0x01;
pub const SUB_QUERY_DISPATCH: u8 = 0x02;
pub const SUB_RETIRE_THROUGH: u8 = 0x03;
pub const SUB_SKIP: u8 = 0x04;
pub const SUB_TIME_SAMPLE: u8 = 0x05;
pub const SUB_HOST_REGISTER: u8 = 0x10;
pub const SUB_GATEWAY_INGRESS: u8 = 0x11;
pub const SUB_GATEWAY_INGRESS_ACK: u8 = 0x12;
pub const SUB_HOST_UNREGISTER: u8 = 0x13;

pub const BOOT_LEASE_SIZE: usize = 16;
pub const DISPATCHER_ID_SIZE: usize = 16;
pub const OPERATION_ID_SIZE: usize = 24;
pub const CANONICAL_HASH_SIZE: usize = 32;

pub const SUBMIT_FIXED_SIZE: usize = 108;
/// Schema-2 ceiling: 108 + 60 + 96 (the schema-1 form tops out at 262).
pub const SUBMIT_MAX_SIZE: usize = 264;
/// Schema-2 ceiling: 60 + 96 (schema-1 canonical tops out at 154).
pub const CANONICAL_MAX_SIZE: usize = 156;
pub const CANONICAL_MIN_SIZE: usize = 26;
/// Schema-2 gateway destination extension: scope+reserved+token16+boot8+
/// egress8 inserted before payload_len → 60B fixed, ≤96B payload.
pub const CANONICAL_GATEWAY_FIXED_SIZE: usize = 60;
pub const CANONICAL_GATEWAY_PAYLOAD_MAX: usize = 96;
pub const LANE_REQUEST_SIZE: usize = 42;
pub const TIME_SAMPLE_REQUEST_SIZE: usize = 26;
pub const RECEIPT_SIZE: usize = 74;
pub const QUERY_RESPONSE_SIZE: usize = 98;
pub const RETIRE_RESPONSE_SIZE: usize = 27;
pub const TIME_SAMPLE_RESPONSE_SIZE: usize = 35;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HostOpsError {
    Truncated,
    LengthMismatch,
    BadSchema,
    SubcommandMismatch,
    UnknownEnum(&'static str, u8),
    CanonicalTooLarge,
    /// Structurally complete but semantically invalid (reserved bits,
    /// out-of-range counts, broken ordering) — names the violated rule.
    Invalid(&'static str),
}

impl fmt::Display for HostOpsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for HostOpsError {}

impl HostOpsError {
    /// Shared refusal vocabulary with the C++ decoder and the golden
    /// `reason` strings (authority fragments and site-state bodies).
    pub fn name(&self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::LengthMismatch => "length_mismatch",
            Self::BadSchema => "bad_schema",
            Self::SubcommandMismatch => "subcommand_mismatch",
            Self::UnknownEnum(tag, _) => match *tag {
                "kind" => "bad_kind",
                "action" => "bad_action",
                "result" => "bad_result",
                _ => "unknown_enum",
            },
            Self::CanonicalTooLarge => "canonical_too_large",
            Self::Invalid(reason) => reason,
        }
    }
}

/// Typed outcome carried inside every host_ops response (mirrors the C++
/// `HostOpsResult`). Malformed inner bodies never surface here — those are
/// USB Error frames (ProtocolError/Unsupported).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum HostOpsResult {
    Ok = 0,
    Existing = 1,
    Conflict = 2,
    Retired = 3,
    WindowFull = 4,
    LeaseMismatch = 5,
    NotRetained = 6,
    RetireRefused = 7,
    SkipRefused = 8,
    Expired = 9,
    MeshRejected = 10,
    LaneMismatch = 11,
    InvalidRequest = 12,
    Unsupported = 13,
}

impl HostOpsResult {
    pub fn try_from_byte(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            0 => Self::Ok,
            1 => Self::Existing,
            2 => Self::Conflict,
            3 => Self::Retired,
            4 => Self::WindowFull,
            5 => Self::LeaseMismatch,
            6 => Self::NotRetained,
            7 => Self::RetireRefused,
            8 => Self::SkipRefused,
            9 => Self::Expired,
            10 => Self::MeshRejected,
            11 => Self::LaneMismatch,
            12 => Self::InvalidRequest,
            13 => Self::Unsupported,
            _ => return Err(HostOpsError::UnknownEnum("result", value)),
        })
    }
}

/// Per-position dispatch state (mirrors `DispatchWindow::State`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SlotState {
    Empty = 0,
    Sent = 1,
    Delivered = 2,
    Failed = 3,
    Expired = 4,
    Skipped = 5,
    Indeterminate = 6,
}

impl SlotState {
    pub fn try_from_byte(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            0 => Self::Empty,
            1 => Self::Sent,
            2 => Self::Delivered,
            3 => Self::Failed,
            4 => Self::Expired,
            5 => Self::Skipped,
            6 => Self::Indeterminate,
            _ => return Err(HostOpsError::UnknownEnum("state", value)),
        })
    }

    pub fn is_terminal(self) -> bool {
        !matches!(self, Self::Empty | Self::Sent)
    }
}

/// Evidence stage (mirrors `DispatchWindow::Evidence`). HostRamReceived is
/// the scope-2 gateway terminal: the verified Service Receipt for
/// HOST_RECEIVE_RAM — the registered host's ReceiveLog stored the payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Evidence {
    None = 0,
    GatewayAccepted = 1,
    MacAttemptReported = 2,
    EndSdkReceived = 3,
    HostRamReceived = 4,
}

impl Evidence {
    pub fn try_from_byte(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            0 => Self::None,
            1 => Self::GatewayAccepted,
            2 => Self::MacAttemptReported,
            3 => Self::EndSdkReceived,
            4 => Self::HostRamReceived,
            _ => return Err(HostOpsError::UnknownEnum("evidence", value)),
        })
    }
}

/// Typed result/outcome for the Gateway HostOps family (0x10-0x13 replies
/// and the 0x12 ingress ACK outcome) — a u16 on the wire so the family can
/// grow without colliding with `HostOpsResult`. STORAGE names "the host
/// could not persist"; INDETERMINATE names "the host could not prove the
/// outcome" — neither is a success.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum GatewayOpsResult {
    Ok = 0,
    Busy = 1,
    Stale = 2,
    Denied = 3,
    Unsupported = 4,
    Invalid = 5,
    Storage = 6,
    Indeterminate = 7,
}

impl GatewayOpsResult {
    pub fn try_from_u16(value: u16) -> Result<Self, HostOpsError> {
        Ok(match value {
            0 => Self::Ok,
            1 => Self::Busy,
            2 => Self::Stale,
            3 => Self::Denied,
            4 => Self::Unsupported,
            5 => Self::Invalid,
            6 => Self::Storage,
            7 => Self::Indeterminate,
            _ => return Err(HostOpsError::UnknownEnum("gateway_result", 0xFF)),
        })
    }
}

/// Per-boot gateway identity: NVS-monotonic boot generation bound to the
/// provisioned node id, big-endian halves. The daemon derives the expected
/// lease from HelloAck's boot+node fields — no separate discovery.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootLease(pub [u8; BOOT_LEASE_SIZE]);

impl BootLease {
    pub fn derive(boot_generation: u64, node: u64) -> Self {
        let mut bytes = [0_u8; BOOT_LEASE_SIZE];
        bytes[..8].copy_from_slice(&boot_generation.to_be_bytes());
        bytes[8..].copy_from_slice(&node.to_be_bytes());
        Self(bytes)
    }

    /// Both halves must sit outside the reserved 0/MAX range.
    pub fn valid(self) -> bool {
        let generation = u64::from_be_bytes(self.0[..8].try_into().expect("half"));
        let node = u64::from_be_bytes(self.0[8..].try_into().expect("half"));
        generation != 0 && generation != u64::MAX && node != 0 && node != u64::MAX
    }
}

fn check_head(inner: &[u8], sub: u8) -> Result<(), HostOpsError> {
    if inner.len() < 2 {
        return Err(HostOpsError::Truncated);
    }
    if inner[0] != HOST_OPS_SCHEMA {
        return Err(HostOpsError::BadSchema);
    }
    if inner[1] != sub {
        return Err(HostOpsError::SubcommandMismatch);
    }
    Ok(())
}

fn fixed<const N: usize>(inner: &[u8], offset: usize) -> Result<[u8; N], HostOpsError> {
    inner
        .get(offset..offset + N)
        .ok_or(HostOpsError::Truncated)?
        .try_into()
        .map_err(|_| HostOpsError::Truncated)
}

fn u64_at(inner: &[u8], offset: usize) -> Result<u64, HostOpsError> {
    Ok(u64::from_be_bytes(fixed(inner, offset)?))
}

/// SUBMIT request inner body (design §6 layout, 108 + canonical bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubmitRequest {
    pub lease: BootLease,
    pub dispatcher: [u8; DISPATCHER_ID_SIZE],
    pub dispatch_seq: u64,
    pub operation_id: [u8; OPERATION_ID_SIZE],
    pub canonical_hash: [u8; CANONICAL_HASH_SIZE],
    pub device_deadline: u64,
    pub canonical: Vec<u8>,
}

pub fn encode_submit(request: &SubmitRequest) -> Result<Vec<u8>, HostOpsError> {
    if request.canonical.len() > CANONICAL_MAX_SIZE {
        return Err(HostOpsError::CanonicalTooLarge);
    }
    let mut out = Vec::with_capacity(SUBMIT_FIXED_SIZE + request.canonical.len());
    out.push(HOST_OPS_SCHEMA);
    out.push(SUB_SUBMIT);
    out.extend_from_slice(&request.lease.0);
    out.extend_from_slice(&request.dispatcher);
    out.extend_from_slice(&request.dispatch_seq.to_be_bytes());
    out.extend_from_slice(&request.operation_id);
    out.extend_from_slice(&request.canonical_hash);
    out.extend_from_slice(&request.device_deadline.to_be_bytes());
    out.extend_from_slice(&(request.canonical.len() as u16).to_be_bytes());
    out.extend_from_slice(&request.canonical);
    Ok(out)
}

pub fn decode_submit(inner: &[u8]) -> Result<SubmitRequest, HostOpsError> {
    if inner.len() < SUBMIT_FIXED_SIZE || inner.len() > SUBMIT_MAX_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    check_head(inner, SUB_SUBMIT)?;
    let canonical_len = u16::from_be_bytes(fixed::<2>(inner, SUBMIT_FIXED_SIZE - 2)?) as usize;
    if canonical_len != inner.len() - SUBMIT_FIXED_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    Ok(SubmitRequest {
        lease: BootLease(fixed(inner, 2)?),
        dispatcher: fixed(inner, 18)?,
        dispatch_seq: u64_at(inner, 34)?,
        operation_id: fixed(inner, 42)?,
        canonical_hash: fixed(inner, 66)?,
        device_deadline: u64_at(inner, 98)?,
        canonical: inner[SUBMIT_FIXED_SIZE..].to_vec(),
    })
}

/// QUERY_DISPATCH / RETIRE_THROUGH / SKIP share one request shape; `seq` is
/// the dispatch_seq or the retire_through floor.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LaneRequest {
    pub lease: BootLease,
    pub dispatcher: [u8; DISPATCHER_ID_SIZE],
    pub seq: u64,
}

pub fn encode_lane_request(sub: u8, request: &LaneRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(LANE_REQUEST_SIZE);
    out.push(HOST_OPS_SCHEMA);
    out.push(sub);
    out.extend_from_slice(&request.lease.0);
    out.extend_from_slice(&request.dispatcher);
    out.extend_from_slice(&request.seq.to_be_bytes());
    out
}

pub fn decode_lane_request(inner: &[u8], sub: u8) -> Result<LaneRequest, HostOpsError> {
    if inner.len() != LANE_REQUEST_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    check_head(inner, sub)?;
    Ok(LaneRequest {
        lease: BootLease(fixed(inner, 2)?),
        dispatcher: fixed(inner, 18)?,
        seq: u64_at(inner, 34)?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeSampleRequest {
    pub lease: BootLease,
    pub nonce: u64,
}

pub fn encode_time_sample_request(request: &TimeSampleRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(TIME_SAMPLE_REQUEST_SIZE);
    out.push(HOST_OPS_SCHEMA);
    out.push(SUB_TIME_SAMPLE);
    out.extend_from_slice(&request.lease.0);
    out.extend_from_slice(&request.nonce.to_be_bytes());
    out
}

pub fn decode_time_sample_request(inner: &[u8]) -> Result<TimeSampleRequest, HostOpsError> {
    if inner.len() != TIME_SAMPLE_REQUEST_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    check_head(inner, SUB_TIME_SAMPLE)?;
    Ok(TimeSampleRequest {
        lease: BootLease(fixed(inner, 2)?),
        nonce: u64_at(inner, 18)?,
    })
}

/// SUBMIT/SKIP answer (74B fixed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Receipt {
    pub sub: u8,
    pub result: HostOpsResult,
    pub state: SlotState,
    pub lease: BootLease,
    pub dispatch_seq: u64,
    pub hash: [u8; CANONICAL_HASH_SIZE],
    pub msg_session: u32,
    pub msg_seq: u64,
    pub msg_valid: bool,
    pub evidence: Evidence,
}

pub fn encode_receipt(receipt: &Receipt) -> Vec<u8> {
    let mut out = Vec::with_capacity(RECEIPT_SIZE);
    out.push(HOST_OPS_SCHEMA);
    out.push(receipt.sub);
    out.push(receipt.result as u8);
    out.push(receipt.state as u8);
    out.extend_from_slice(&receipt.lease.0);
    out.extend_from_slice(&receipt.dispatch_seq.to_be_bytes());
    out.extend_from_slice(&receipt.hash);
    out.extend_from_slice(&receipt.msg_session.to_be_bytes());
    out.extend_from_slice(&receipt.msg_seq.to_be_bytes());
    out.push(u8::from(receipt.msg_valid));
    out.push(receipt.evidence as u8);
    out
}

pub fn decode_receipt(inner: &[u8], sub: u8) -> Result<Receipt, HostOpsError> {
    if inner.len() != RECEIPT_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    check_head(inner, sub)?;
    let msg_valid = match inner[72] {
        0 => false,
        1 => true,
        other => return Err(HostOpsError::UnknownEnum("msg_valid", other)),
    };
    Ok(Receipt {
        sub,
        result: HostOpsResult::try_from_byte(inner[2])?,
        state: SlotState::try_from_byte(inner[3])?,
        lease: BootLease(fixed(inner, 4)?),
        dispatch_seq: u64_at(inner, 20)?,
        hash: fixed(inner, 28)?,
        msg_session: u32::from_be_bytes(fixed(inner, 60)?),
        msg_seq: u64_at(inner, 64)?,
        msg_valid,
        evidence: Evidence::try_from_byte(inner[73])?,
    })
}

/// A slot-free MeshRejected receipt uses the fixed hash position for a
/// bounded ASCII reason (`RLFR`, length, bytes, zero padding). Older
/// devices echoed the canonical hash there; that value is never a reason.
pub fn mesh_refusal_detail<'a>(
    receipt: &'a Receipt,
    canonical_hash: &[u8; CANONICAL_HASH_SIZE],
) -> Option<&'a str> {
    let field = &receipt.hash;
    if receipt.result != HostOpsResult::MeshRejected
        || field == canonical_hash
        || &field[..4] != b"RLFR"
    {
        return None;
    }
    let len = usize::from(field[4]);
    if len == 0
        || len > field.len() - 5
        || !field[5..5 + len].iter().all(|b| (0x20..=0x7e).contains(b))
        || field[5 + len..].iter().any(|b| *b != 0)
    {
        return None;
    }
    std::str::from_utf8(&field[5..5 + len]).ok()
}

/// QUERY_DISPATCH answer: receipt + bound operation id (98B fixed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryResponse {
    pub result: HostOpsResult,
    pub state: SlotState,
    pub lease: BootLease,
    pub dispatch_seq: u64,
    pub hash: [u8; CANONICAL_HASH_SIZE],
    pub operation_id: [u8; OPERATION_ID_SIZE],
    pub msg_session: u32,
    pub msg_seq: u64,
    pub msg_valid: bool,
    pub evidence: Evidence,
}

pub fn encode_query_response(response: &QueryResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(QUERY_RESPONSE_SIZE);
    out.push(HOST_OPS_SCHEMA);
    out.push(SUB_QUERY_DISPATCH);
    out.push(response.result as u8);
    out.push(response.state as u8);
    out.extend_from_slice(&response.lease.0);
    out.extend_from_slice(&response.dispatch_seq.to_be_bytes());
    out.extend_from_slice(&response.hash);
    out.extend_from_slice(&response.operation_id);
    out.extend_from_slice(&response.msg_session.to_be_bytes());
    out.extend_from_slice(&response.msg_seq.to_be_bytes());
    out.push(u8::from(response.msg_valid));
    out.push(response.evidence as u8);
    out
}

pub fn decode_query_response(inner: &[u8]) -> Result<QueryResponse, HostOpsError> {
    if inner.len() != QUERY_RESPONSE_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    check_head(inner, SUB_QUERY_DISPATCH)?;
    let msg_valid = match inner[96] {
        0 => false,
        1 => true,
        other => return Err(HostOpsError::UnknownEnum("msg_valid", other)),
    };
    Ok(QueryResponse {
        result: HostOpsResult::try_from_byte(inner[2])?,
        state: SlotState::try_from_byte(inner[3])?,
        lease: BootLease(fixed(inner, 4)?),
        dispatch_seq: u64_at(inner, 20)?,
        hash: fixed(inner, 28)?,
        operation_id: fixed(inner, 60)?,
        msg_session: u32::from_be_bytes(fixed(inner, 84)?),
        msg_seq: u64_at(inner, 88)?,
        msg_valid,
        evidence: Evidence::try_from_byte(inner[97])?,
    })
}

/// RETIRE_THROUGH answer (27B fixed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetireResponse {
    pub result: HostOpsResult,
    pub lease: BootLease,
    pub retired_through: u64,
}

pub fn encode_retire_response(response: &RetireResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(RETIRE_RESPONSE_SIZE);
    out.push(HOST_OPS_SCHEMA);
    out.push(SUB_RETIRE_THROUGH);
    out.push(response.result as u8);
    out.extend_from_slice(&response.lease.0);
    out.extend_from_slice(&response.retired_through.to_be_bytes());
    out
}

pub fn decode_retire_response(inner: &[u8]) -> Result<RetireResponse, HostOpsError> {
    if inner.len() != RETIRE_RESPONSE_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    check_head(inner, SUB_RETIRE_THROUGH)?;
    Ok(RetireResponse {
        result: HostOpsResult::try_from_byte(inner[2])?,
        lease: BootLease(fixed(inner, 3)?),
        retired_through: u64_at(inner, 19)?,
    })
}

/// TIME_SAMPLE answer (35B fixed).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TimeSampleResponse {
    pub result: HostOpsResult,
    pub lease: BootLease,
    pub nonce: u64,
    pub device_time: u64,
}

pub fn encode_time_sample_response(response: &TimeSampleResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(TIME_SAMPLE_RESPONSE_SIZE);
    out.push(HOST_OPS_SCHEMA);
    out.push(SUB_TIME_SAMPLE);
    out.push(response.result as u8);
    out.extend_from_slice(&response.lease.0);
    out.extend_from_slice(&response.nonce.to_be_bytes());
    out.extend_from_slice(&response.device_time.to_be_bytes());
    out
}

pub fn decode_time_sample_response(inner: &[u8]) -> Result<TimeSampleResponse, HostOpsError> {
    if inner.len() != TIME_SAMPLE_RESPONSE_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    check_head(inner, SUB_TIME_SAMPLE)?;
    Ok(TimeSampleResponse {
        result: HostOpsResult::try_from_byte(inner[2])?,
        lease: BootLease(fixed(inner, 3)?),
        nonce: u64_at(inner, 19)?,
        device_time: u64_at(inner, 27)?,
    })
}

// --- Gateway host endpoint subcommands (scope-gateway-config/05-wire-api.md
// §5.6, P3) -------------------------------------------------------------
//
// These four subcommands share a different inner common form than the
// 0x01-0x05 family: schema:u8=1, sub:u8, payload_len:u16, payload. Every
// request gets a same-sub reply carrying a u16 GatewayOpsResult first —
// except 0x12, which IS the reply to a device-issued 0x11 (the frame-level
// request id correlates them). Exact length only: the family never accepts
// a trailing byte.
pub const GATEWAY_INNER_HEAD_SIZE: usize = 4;
pub const HOST_REGISTER_REQUEST_PAYLOAD: usize = 20; // network8+boot8+lease4
pub const HOST_REGISTER_RESPONSE_PAYLOAD: usize = 62; // result2+token16+boot8+digest32+lease4
pub const GATEWAY_INGRESS_FIXED_PAYLOAD: usize = 84; // prefix32+ref20+digest32
pub const GATEWAY_INGRESS_MAX_PAYLOAD: usize = 180; // +96 payload
pub const GATEWAY_INGRESS_ACK_PAYLOAD: usize = 70; // token16+ref20+digest32+outcome2
pub const HOST_UNREGISTER_REQUEST_PAYLOAD: usize = 16; // token16
pub const HOST_UNREGISTER_RESPONSE_PAYLOAD: usize = 2; // result16

fn gateway_head(out: &mut Vec<u8>, sub: u8, payload_len: usize) {
    out.push(HOST_OPS_SCHEMA);
    out.push(sub);
    out.extend_from_slice(&(payload_len as u16).to_be_bytes());
}

/// Validates schema/sub/payload_len and returns the payload span.
fn gateway_body(
    inner: &[u8],
    sub: u8,
    min_payload: usize,
    max_payload: usize,
) -> Result<&[u8], HostOpsError> {
    if inner.len() < GATEWAY_INNER_HEAD_SIZE || inner.len() > GATEWAY_INNER_HEAD_SIZE + max_payload
    {
        return Err(HostOpsError::LengthMismatch);
    }
    check_head(inner, sub)?;
    let payload_len = u16::from_be_bytes(fixed::<2>(inner, 2)?) as usize;
    if payload_len != inner.len() - GATEWAY_INNER_HEAD_SIZE
        || payload_len < min_payload
        || payload_len > max_payload
    {
        return Err(HostOpsError::LengthMismatch);
    }
    Ok(&inner[GATEWAY_INNER_HEAD_SIZE..])
}

fn u16_at(inner: &[u8], offset: usize) -> Result<u16, HostOpsError> {
    Ok(u16::from_be_bytes(fixed(inner, offset)?))
}

fn u32_at(inner: &[u8], offset: usize) -> Result<u32, HostOpsError> {
    Ok(u32::from_be_bytes(fixed(inner, offset)?))
}

pub const SERVICE_PREFIX_SIZE: usize = 32;
/// scope byte position inside the Service Submit prefix.
pub const SERVICE_PREFIX_SCOPE_OFFSET: usize = 2;
/// token position inside the Service Submit prefix.
pub const SERVICE_PREFIX_TOKEN_OFFSET: usize = 4;
/// gateway_boot position inside the Service Submit prefix.
pub const SERVICE_PREFIX_BOOT_OFFSET: usize = 20;
/// payload_len position inside the Service Submit prefix.
pub const SERVICE_PREFIX_LEN_OFFSET: usize = 28;

/// The sub byte of a gateway-family inner body, if it is one (0x10-0x13).
/// Used to peel device-issued 0x11 ingress out of the generic
/// response-routing lane without decoding the whole family up front.
pub fn gateway_sub(inner: &[u8]) -> Option<u8> {
    if inner.len() < 2 || inner[0] != HOST_OPS_SCHEMA {
        return None;
    }
    match inner[1] {
        SUB_HOST_REGISTER | SUB_GATEWAY_INGRESS | SUB_GATEWAY_INGRESS_ACK | SUB_HOST_UNREGISTER => {
            Some(inner[1])
        }
        _ => None,
    }
}

/// 0x10 HOST_REGISTER (H→G): network:u64, host_boot:u64, lease_ms:u32.
/// host_boot is the daemon's own per-run generation — a fresh boot is a
/// fresh principal, so the gateway never conflates registrations across
/// daemon restarts on the same machine.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRegisterRequest {
    pub network: u64,
    pub host_boot: u64,
    pub lease_ms: u32,
}

pub fn encode_host_register(request: &HostRegisterRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + HOST_REGISTER_REQUEST_PAYLOAD);
    gateway_head(&mut out, SUB_HOST_REGISTER, HOST_REGISTER_REQUEST_PAYLOAD);
    out.extend_from_slice(&request.network.to_be_bytes());
    out.extend_from_slice(&request.host_boot.to_be_bytes());
    out.extend_from_slice(&request.lease_ms.to_be_bytes());
    out
}

pub fn decode_host_register(inner: &[u8]) -> Result<HostRegisterRequest, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_HOST_REGISTER,
        HOST_REGISTER_REQUEST_PAYLOAD,
        HOST_REGISTER_REQUEST_PAYLOAD,
    )?;
    Ok(HostRegisterRequest {
        network: u64_at(payload, 0)?,
        host_boot: u64_at(payload, 8)?,
        lease_ms: u32_at(payload, 16)?,
    })
}

/// 0x10 reply: result:u16, token:16, gateway_boot:u64, host_digest:32,
/// lease_ms:u32. The token binds principal + host boot + USB session and is
/// the value the schema-2 canonical carries as gateway_token.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostRegisterResponse {
    pub result: u16,
    pub token: [u8; 16],
    pub gateway_boot: u64,
    pub host_digest: [u8; 32],
    pub lease_ms: u32,
}

pub fn encode_host_register_response(response: &HostRegisterResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + HOST_REGISTER_RESPONSE_PAYLOAD);
    gateway_head(&mut out, SUB_HOST_REGISTER, HOST_REGISTER_RESPONSE_PAYLOAD);
    out.extend_from_slice(&response.result.to_be_bytes());
    out.extend_from_slice(&response.token);
    out.extend_from_slice(&response.gateway_boot.to_be_bytes());
    out.extend_from_slice(&response.host_digest);
    out.extend_from_slice(&response.lease_ms.to_be_bytes());
    out
}

pub fn decode_host_register_response(inner: &[u8]) -> Result<HostRegisterResponse, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_HOST_REGISTER,
        HOST_REGISTER_RESPONSE_PAYLOAD,
        HOST_REGISTER_RESPONSE_PAYLOAD,
    )?;
    let result = u16_at(payload, 0)?;
    GatewayOpsResult::try_from_u16(result)?;
    Ok(HostRegisterResponse {
        result,
        token: fixed(payload, 2)?,
        gateway_boot: u64_at(payload, 18)?,
        host_digest: fixed(payload, 26)?,
        lease_ms: u32_at(payload, 58)?,
    })
}

/// 0x11 GATEWAY_INGRESS (G→H, device-issued): the canonical Service Submit
/// prefix:32, the referenced MessageKey:20 (origin:u64, session:u32,
/// sequence:u64), the request digest:32 (SHA-256 over prefix+payload), and
/// the payload itself (0..96B). The host recomputes the digest before
/// storing — a mismatched digest can never produce a success ACK.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayIngress {
    pub submit_prefix: [u8; 32],
    pub ref_origin: u64,
    pub ref_session: u32,
    pub ref_sequence: u64,
    pub request_digest: [u8; 32],
    pub payload: Vec<u8>,
}

pub fn encode_gateway_ingress(request: &GatewayIngress) -> Result<Vec<u8>, HostOpsError> {
    if request.payload.len() > CANONICAL_GATEWAY_PAYLOAD_MAX {
        return Err(HostOpsError::CanonicalTooLarge);
    }
    let payload_len = GATEWAY_INGRESS_FIXED_PAYLOAD + request.payload.len();
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + payload_len);
    gateway_head(&mut out, SUB_GATEWAY_INGRESS, payload_len);
    out.extend_from_slice(&request.submit_prefix);
    out.extend_from_slice(&request.ref_origin.to_be_bytes());
    out.extend_from_slice(&request.ref_session.to_be_bytes());
    out.extend_from_slice(&request.ref_sequence.to_be_bytes());
    out.extend_from_slice(&request.request_digest);
    out.extend_from_slice(&request.payload);
    Ok(out)
}

pub fn decode_gateway_ingress(inner: &[u8]) -> Result<GatewayIngress, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_GATEWAY_INGRESS,
        GATEWAY_INGRESS_FIXED_PAYLOAD,
        GATEWAY_INGRESS_MAX_PAYLOAD,
    )?;
    Ok(GatewayIngress {
        submit_prefix: fixed(payload, 0)?,
        ref_origin: u64_at(payload, 32)?,
        ref_session: u32_at(payload, 40)?,
        ref_sequence: u64_at(payload, 44)?,
        request_digest: fixed(payload, 52)?,
        payload: payload[GATEWAY_INGRESS_FIXED_PAYLOAD..].to_vec(),
    })
}

/// 0x12 GATEWAY_INGRESS_ACK (H→G): session token:16, ref MessageKey:20,
/// request digest:32, outcome:u16 (GatewayOpsResult). The device verifies
/// all bound fields before trusting the outcome — a wrong key/digest/token
/// can never mark a record stored.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GatewayIngressAck {
    pub token: [u8; 16],
    pub ref_origin: u64,
    pub ref_session: u32,
    pub ref_sequence: u64,
    pub request_digest: [u8; 32],
    pub outcome: u16,
}

pub fn encode_gateway_ingress_ack(ack: &GatewayIngressAck) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + GATEWAY_INGRESS_ACK_PAYLOAD);
    gateway_head(
        &mut out,
        SUB_GATEWAY_INGRESS_ACK,
        GATEWAY_INGRESS_ACK_PAYLOAD,
    );
    out.extend_from_slice(&ack.token);
    out.extend_from_slice(&ack.ref_origin.to_be_bytes());
    out.extend_from_slice(&ack.ref_session.to_be_bytes());
    out.extend_from_slice(&ack.ref_sequence.to_be_bytes());
    out.extend_from_slice(&ack.request_digest);
    out.extend_from_slice(&ack.outcome.to_be_bytes());
    out
}

pub fn decode_gateway_ingress_ack(inner: &[u8]) -> Result<GatewayIngressAck, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_GATEWAY_INGRESS_ACK,
        GATEWAY_INGRESS_ACK_PAYLOAD,
        GATEWAY_INGRESS_ACK_PAYLOAD,
    )?;
    let outcome = u16_at(payload, 68)?;
    GatewayOpsResult::try_from_u16(outcome)?;
    Ok(GatewayIngressAck {
        token: fixed(payload, 0)?,
        ref_origin: u64_at(payload, 16)?,
        ref_session: u32_at(payload, 24)?,
        ref_sequence: u64_at(payload, 28)?,
        request_digest: fixed(payload, 36)?,
        outcome,
    })
}

/// 0x13 HOST_UNREGISTER (H→G): token:16. Only the registration bound to the
/// CURRENT session may be released — a stale token can never revoke the
/// replacement session's endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostUnregisterRequest {
    pub token: [u8; 16],
}

pub fn encode_host_unregister(request: &HostUnregisterRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + HOST_UNREGISTER_REQUEST_PAYLOAD);
    gateway_head(
        &mut out,
        SUB_HOST_UNREGISTER,
        HOST_UNREGISTER_REQUEST_PAYLOAD,
    );
    out.extend_from_slice(&request.token);
    out
}

pub fn decode_host_unregister(inner: &[u8]) -> Result<HostUnregisterRequest, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_HOST_UNREGISTER,
        HOST_UNREGISTER_REQUEST_PAYLOAD,
        HOST_UNREGISTER_REQUEST_PAYLOAD,
    )?;
    Ok(HostUnregisterRequest {
        token: fixed(payload, 0)?,
    })
}

/// 0x13 reply: result:u16.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HostUnregisterResponse {
    pub result: u16,
}

pub fn encode_host_unregister_response(response: &HostUnregisterResponse) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + HOST_UNREGISTER_RESPONSE_PAYLOAD);
    gateway_head(
        &mut out,
        SUB_HOST_UNREGISTER,
        HOST_UNREGISTER_RESPONSE_PAYLOAD,
    );
    out.extend_from_slice(&response.result.to_be_bytes());
    out
}

pub fn decode_host_unregister_response(
    inner: &[u8],
) -> Result<HostUnregisterResponse, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_HOST_UNREGISTER,
        HOST_UNREGISTER_RESPONSE_PAYLOAD,
        HOST_UNREGISTER_RESPONSE_PAYLOAD,
    )?;
    let result = u16_at(payload, 0)?;
    GatewayOpsResult::try_from_u16(result)?;
    Ok(HostUnregisterResponse { result })
}

// --- Config endpoint subcommands (scope-gateway-config/05-wire-api.md
// §5.6, P5) ------------------------------------------------------------------
//
// The remote-config HostOps family (0x20-0x24) shares the gateway inner
// common form (schema:u8=1, sub:u8, payload_len:u16, payload). 0x20's async
// reply is the separate 0x22 subcommand; 0x21/0x23/0x24 answer under their
// own sub — the frame-level request id correlates them. Every reply opens
// with a u16 ConfigOpsResult: Ok only means the device proved the mesh step
// it was asked for (a query answer or an assembled object), never a
// config verdict — the object's own phase/reason is a separate status read.
pub const SUB_CONFIG_QUERY: u8 = 0x20;
pub const SUB_CONFIG_PERMIT: u8 = 0x21;
pub const SUB_CONFIG_STATUS: u8 = 0x22;
pub const SUB_CONFIG_CHALLENGE: u8 = 0x23;
pub const SUB_CONFIG_RECOVER: u8 = 0x24;

pub const CONFIG_QUERY_REQUEST_PAYLOAD: usize = 26; // target8+ns2+opid16
pub const CONFIG_CHALLENGE_REQUEST_PAYLOAD: usize = 28; // target8+ns2+schema2+nonce16
pub const CONFIG_PERMIT_MAX: usize = 1024; // kind-3 object ceiling
pub const CONFIG_REPLY_FIXED_PAYLOAD: usize = 10; // result2+target8
pub const CONFIG_STATUS_BODY_SIZE: usize = 72; // endpoint::ControlStatus
pub const CONFIG_CHALLENGE_BODY_SIZE: usize = 92; // endpoint::ControlChallenge

/// Typed result for the Config HostOps family — a u16 on the wire. Ok means
/// the device proved the mesh step (query answered / object assembled),
/// never a config verdict. INDETERMINATE names "the outcome cannot be
/// proven" — never a success and never a silent retry trigger.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum ConfigOpsResult {
    /// Answered / object assembled at the target.
    Ok = 0,
    /// A config operation is already in flight.
    Busy = 1,
    /// Authenticated but not authorized (ACL/capability).
    Denied = 3,
    /// The config endpoint is not enabled on this device.
    Unsupported = 4,
    /// Malformed request or field-inconsistent.
    Invalid = 5,
    /// Outcome cannot be proven (deadline, torn exchange).
    Indeterminate = 7,
    /// No mesh route to the target.
    NoRoute = 8,
    /// The target did not answer inside the window.
    Timeout = 9,
}

impl ConfigOpsResult {
    pub fn try_from_u16(value: u16) -> Result<Self, HostOpsError> {
        Ok(match value {
            0 => Self::Ok,
            1 => Self::Busy,
            3 => Self::Denied,
            4 => Self::Unsupported,
            5 => Self::Invalid,
            7 => Self::Indeterminate,
            8 => Self::NoRoute,
            9 => Self::Timeout,
            _ => return Err(HostOpsError::UnknownEnum("config_result", 0xFF)),
        })
    }
}

fn config_result_valid(result: u16) -> bool {
    ConfigOpsResult::try_from_u16(result).is_ok()
}

/// The body length a 0x21/0x22/0x23/0x24 reply may carry, by subcommand.
/// The object replies are result-only; the query replies carry the fixed
/// endpoint body on Ok and none on failure — so {0, N} is the legal set.
fn config_reply_body_valid(sub: u8, body_size: usize) -> bool {
    match sub {
        SUB_CONFIG_PERMIT | SUB_CONFIG_RECOVER | SUB_CONFIG_TRUST => body_size == 0,
        SUB_CONFIG_STATUS => body_size == 0 || body_size == CONFIG_STATUS_BODY_SIZE,
        SUB_CONFIG_CHALLENGE => body_size == 0 || body_size == CONFIG_CHALLENGE_BODY_SIZE,
        SUB_CONFIG_TRUST_STATUS => body_size == 0 || body_size == CONFIG_TRUST_STATUS_BODY_SIZE,
        SUB_CONFIG_RECOVERY_INFO => body_size == 0 || body_size == CONFIG_RECOVERY_INFO_BODY_SIZE,
        _ => false,
    }
}

/// The sub byte of a config-family inner body, if it is one (0x20-0x24).
/// Used to peel config replies out of the generic response-routing lane
/// without decoding the whole family up front.
pub fn config_sub(inner: &[u8]) -> Option<u8> {
    if inner.len() < 2 || inner[0] != HOST_OPS_SCHEMA {
        return None;
    }
    match inner[1] {
        SUB_CONFIG_QUERY | SUB_CONFIG_PERMIT | SUB_CONFIG_STATUS | SUB_CONFIG_CHALLENGE
        | SUB_CONFIG_RECOVER => Some(inner[1]),
        _ => None,
    }
}

/// 0x20 CONFIG_QUERY (H→G): target:u64, config_namespace:u16, operation_id:16.
/// Async reply -> 0x22 CONFIG_STATUS.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigQueryRequest {
    pub target: u64,
    pub config_namespace: u16,
    pub operation_id: [u8; 16],
}

pub fn encode_config_query(request: &ConfigQueryRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + CONFIG_QUERY_REQUEST_PAYLOAD);
    gateway_head(&mut out, SUB_CONFIG_QUERY, CONFIG_QUERY_REQUEST_PAYLOAD);
    out.extend_from_slice(&request.target.to_be_bytes());
    out.extend_from_slice(&request.config_namespace.to_be_bytes());
    out.extend_from_slice(&request.operation_id);
    out
}

pub fn decode_config_query(inner: &[u8]) -> Result<ConfigQueryRequest, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_CONFIG_QUERY,
        CONFIG_QUERY_REQUEST_PAYLOAD,
        CONFIG_QUERY_REQUEST_PAYLOAD,
    )?;
    Ok(ConfigQueryRequest {
        target: u64_at(payload, 0)?,
        config_namespace: u16_at(payload, 8)?,
        operation_id: fixed(payload, 10)?,
    })
}

/// 0x23 CONFIG_CHALLENGE (H→G query): target:u64, config_namespace:u16,
/// schema:u16, client_nonce:16. Async reply -> 0x23 CONFIG_CHALLENGE.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigChallengeRequest {
    pub target: u64,
    pub config_namespace: u16,
    pub schema: u16,
    pub client_nonce: [u8; 16],
}

pub fn encode_config_challenge(request: &ConfigChallengeRequest) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + CONFIG_CHALLENGE_REQUEST_PAYLOAD);
    gateway_head(
        &mut out,
        SUB_CONFIG_CHALLENGE,
        CONFIG_CHALLENGE_REQUEST_PAYLOAD,
    );
    out.extend_from_slice(&request.target.to_be_bytes());
    out.extend_from_slice(&request.config_namespace.to_be_bytes());
    out.extend_from_slice(&request.schema.to_be_bytes());
    out.extend_from_slice(&request.client_nonce);
    out
}

pub fn decode_config_challenge(inner: &[u8]) -> Result<ConfigChallengeRequest, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_CONFIG_CHALLENGE,
        CONFIG_CHALLENGE_REQUEST_PAYLOAD,
        CONFIG_CHALLENGE_REQUEST_PAYLOAD,
    )?;
    Ok(ConfigChallengeRequest {
        target: u64_at(payload, 0)?,
        config_namespace: u16_at(payload, 8)?,
        schema: u16_at(payload, 10)?,
        client_nonce: fixed(payload, 12)?,
    })
}

/// 0x21 CONFIG_PERMIT (H→G): target:u64, permit bytes (1..CONFIG_PERMIT_MAX).
/// Async reply -> 0x21 CONFIG_PERMIT (result only, no body).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigPermitRequest {
    pub target: u64,
    pub permit: Vec<u8>,
}

pub fn encode_config_permit(request: &ConfigPermitRequest) -> Result<Vec<u8>, HostOpsError> {
    if request.permit.is_empty() || request.permit.len() > CONFIG_PERMIT_MAX {
        return Err(HostOpsError::CanonicalTooLarge);
    }
    let payload_len = 8 + request.permit.len();
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + payload_len);
    gateway_head(&mut out, SUB_CONFIG_PERMIT, payload_len);
    out.extend_from_slice(&request.target.to_be_bytes());
    out.extend_from_slice(&request.permit);
    Ok(out)
}

pub fn decode_config_permit(inner: &[u8]) -> Result<ConfigPermitRequest, HostOpsError> {
    // target:u64 (8) + permit (1..CONFIG_PERMIT_MAX).
    let payload = gateway_body(inner, SUB_CONFIG_PERMIT, 8 + 1, 8 + CONFIG_PERMIT_MAX)?;
    Ok(ConfigPermitRequest {
        target: u64_at(payload, 0)?,
        permit: payload[8..].to_vec(),
    })
}

/// 0x24 CONFIG_RECOVER (H→G): target:u64, recovery object bytes
/// (1..CONFIG_PERMIT_MAX). Identical layout to 0x21 — the signed kind-4
/// object is opaque to the bridge — but delivered on the dedicated
/// recovery lane and answered under 0x24 (result only, no body). A
/// recovery object is never accepted on the 0x21 permit path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigRecoverRequest {
    pub target: u64,
    pub object: Vec<u8>,
}

pub fn encode_config_recover(request: &ConfigRecoverRequest) -> Result<Vec<u8>, HostOpsError> {
    if request.object.is_empty() || request.object.len() > CONFIG_PERMIT_MAX {
        return Err(HostOpsError::CanonicalTooLarge);
    }
    let payload_len = 8 + request.object.len();
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + payload_len);
    gateway_head(&mut out, SUB_CONFIG_RECOVER, payload_len);
    out.extend_from_slice(&request.target.to_be_bytes());
    out.extend_from_slice(&request.object);
    Ok(out)
}

pub fn decode_config_recover(inner: &[u8]) -> Result<ConfigRecoverRequest, HostOpsError> {
    // target:u64 (8) + object (1..CONFIG_PERMIT_MAX).
    let payload = gateway_body(inner, SUB_CONFIG_RECOVER, 8 + 1, 8 + CONFIG_PERMIT_MAX)?;
    Ok(ConfigRecoverRequest {
        target: u64_at(payload, 0)?,
        object: payload[8..].to_vec(),
    })
}

/// Trust-manifest transfer (0x25): target:u64 + the signed RTM1 bytes.
/// The gateway holds the whole object in one slot before handing it to
/// the unified target assembler as a kind-5 intake — no chunk protocol
/// above the host_ops ceiling (≤ 2048 B).
pub const SUB_CONFIG_TRUST: u8 = 0x25;
/// Trust-status query (0x26): target:u64 + network:u64. The reply body is
/// the raw 72 B TrustStatus the target's TrustView produced.
pub const SUB_CONFIG_TRUST_STATUS: u8 = 0x26;
/// Recovery-info query (0x27): target:u64 + config_namespace:u16. The
/// reply body is the raw 80 B RecoveryInfo with the floor readings and
/// the survivor/testimony hashes the RCR2 issuance binds.
pub const SUB_CONFIG_RECOVERY_INFO: u8 = 0x27;
/// Largest RTM1 the 0x25 transfer carries (the device's kind-5 cap).
pub const CONFIG_TRUST_MANIFEST_MAX: usize = 2048;
/// Endpoint TrustStatus / RecoveryInfo body sizes (0x26/0x27 replies).
pub const CONFIG_TRUST_STATUS_BODY_SIZE: usize = 72;
pub const CONFIG_RECOVERY_INFO_BODY_SIZE: usize = 80;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigTrustRequest {
    pub target: u64,
    pub manifest: Vec<u8>,
}

pub fn encode_config_trust(request: &ConfigTrustRequest) -> Result<Vec<u8>, HostOpsError> {
    if request.manifest.is_empty() || request.manifest.len() > CONFIG_TRUST_MANIFEST_MAX {
        return Err(HostOpsError::CanonicalTooLarge);
    }
    let payload_len = 8 + request.manifest.len();
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + payload_len);
    gateway_head(&mut out, SUB_CONFIG_TRUST, payload_len);
    out.extend_from_slice(&request.target.to_be_bytes());
    out.extend_from_slice(&request.manifest);
    Ok(out)
}

pub fn decode_config_trust(inner: &[u8]) -> Result<ConfigTrustRequest, HostOpsError> {
    // target:u64 (8) + manifest (1..CONFIG_TRUST_MANIFEST_MAX).
    let payload = gateway_body(
        inner,
        SUB_CONFIG_TRUST,
        8 + 1,
        8 + CONFIG_TRUST_MANIFEST_MAX,
    )?;
    Ok(ConfigTrustRequest {
        target: u64_at(payload, 0)?,
        manifest: payload[8..].to_vec(),
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigTrustStatusRequest {
    pub target: u64,
    pub network: u64,
    pub nonce: [u8; 16],
}

pub fn encode_config_trust_status(
    request: &ConfigTrustStatusRequest,
) -> Result<Vec<u8>, HostOpsError> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + 32);
    gateway_head(&mut out, SUB_CONFIG_TRUST_STATUS, 32);
    out.extend_from_slice(&request.target.to_be_bytes());
    out.extend_from_slice(&request.network.to_be_bytes());
    out.extend_from_slice(&request.nonce);
    Ok(out)
}

pub fn decode_config_trust_status(inner: &[u8]) -> Result<ConfigTrustStatusRequest, HostOpsError> {
    // target:u64 (8) + network:u64 (8) + nonce (16).
    let payload = gateway_body(inner, SUB_CONFIG_TRUST_STATUS, 32, 32)?;
    Ok(ConfigTrustStatusRequest {
        target: u64_at(payload, 0)?,
        network: u64_at(payload, 8)?,
        nonce: fixed(payload, 16)?,
    })
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigRecoveryInfoRequest {
    pub target: u64,
    pub network: u64,
    pub config_namespace: u16,
    pub nonce: [u8; 16],
}

pub fn encode_config_recovery_info(
    request: &ConfigRecoveryInfoRequest,
) -> Result<Vec<u8>, HostOpsError> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + 34);
    gateway_head(&mut out, SUB_CONFIG_RECOVERY_INFO, 34);
    out.extend_from_slice(&request.target.to_be_bytes());
    out.extend_from_slice(&request.network.to_be_bytes());
    out.extend_from_slice(&request.config_namespace.to_be_bytes());
    out.extend_from_slice(&request.nonce);
    Ok(out)
}

pub fn decode_config_recovery_info(
    inner: &[u8],
) -> Result<ConfigRecoveryInfoRequest, HostOpsError> {
    // target:u64 (8) + network:u64 (8) + ns:u16 (2) + nonce (16).
    let payload = gateway_body(inner, SUB_CONFIG_RECOVERY_INFO, 34, 34)?;
    Ok(ConfigRecoveryInfoRequest {
        target: u64_at(payload, 0)?,
        network: u64_at(payload, 8)?,
        config_namespace: u16_at(payload, 16)?,
        nonce: fixed(payload, 18)?,
    })
}

/// Shared reply shape for 0x21–0x27: result:u16, target:u64, then an
/// optional body — the raw ControlStatus (72 B) for a 0x22 reply, the raw
/// ControlChallenge (92 B) for 0x23, the TrustStatus (72 B) for 0x26, or
/// the RecoveryInfo (80 B) for 0x27 on Ok; empty on any failure and always
/// for the 0x21/0x24/0x25 transfers. The host decodes the body with the
/// endpoint codec; the device forwards it verbatim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigReply {
    pub result: u16,
    pub target: u64,
    pub body: Vec<u8>,
}

/// `sub` must be one of the config subs (0x20–0x27); the body length
/// the codec accepts is derived from it (0 for the 0x21/0x24/0x25
/// transfers; 0-or-fixed for the query replies).
pub fn encode_config_reply(sub: u8, reply: &ConfigReply) -> Result<Vec<u8>, HostOpsError> {
    if !config_reply_body_valid(sub, reply.body.len()) || !config_result_valid(reply.result) {
        return Err(HostOpsError::LengthMismatch);
    }
    let payload_len = CONFIG_REPLY_FIXED_PAYLOAD + reply.body.len();
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + payload_len);
    gateway_head(&mut out, sub, payload_len);
    out.extend_from_slice(&reply.result.to_be_bytes());
    out.extend_from_slice(&reply.target.to_be_bytes());
    out.extend_from_slice(&reply.body);
    Ok(out)
}

pub fn decode_config_reply(inner: &[u8], sub: u8) -> Result<ConfigReply, HostOpsError> {
    let payload = gateway_body(
        inner,
        sub,
        CONFIG_REPLY_FIXED_PAYLOAD,
        CONFIG_REPLY_FIXED_PAYLOAD + CONFIG_CHALLENGE_BODY_SIZE,
    )?;
    let result = u16_at(payload, 0)?;
    let target = u64_at(payload, 2)?;
    let body = payload[CONFIG_REPLY_FIXED_PAYLOAD..].to_vec();
    if !config_result_valid(result) || !config_reply_body_valid(sub, body.len()) {
        return Err(HostOpsError::LengthMismatch);
    }
    Ok(ConfigReply {
        result,
        target,
        body,
    })
}

// --- Authority channel subcommands (G-SEC P5 design §3.3) ----------------------
//
// 0x64 AUTHORITY_UP (G→H, request id 0) / 0x65 AUTHORITY_DOWN (H→G) carry
// one carrier Fragment each; 0x66 SITE_STATE_SET (H→G) carries WakeLocal /
// QueryLocal; 0x67 SITE_STATE_REPORT (G→H) answers 0x65/0x66. Same inner
// common form as the gateway family (schema/sub/payload_len, exact
// length). The gateway relays opaque bytes; 0x67 results are transport
// receipts, never decrypt/apply evidence.
//
// The kind values are `authority::CarrierKind` 1..=5; the object lengths a
// kind pins are USB wire facts re-declared here (they match
// routeloom-keysched's RLRES1 sizes and the 28..=2048 envelope span, which
// this crate must not depend on).
// Join-relay-v2 owns bit 9; an authority-only lane needs its own transcript bit.
pub const CAP_AUTHORITY_CHANNEL_V1: u32 = 1 << 10;
const _: () = assert!(CAP_AUTHORITY_CHANNEL_V1 & crate::join_relay::CAP_JOIN_RELAY_V2 == 0);
pub const SUB_AUTHORITY_UP: u8 = 0x64;
pub const SUB_AUTHORITY_DOWN: u8 = 0x65;
pub const SUB_SITE_STATE_SET: u8 = 0x66;
pub const SUB_SITE_STATE_REPORT: u8 = 0x67;

pub const AUTHORITY_FRAGMENT_HEAD: usize = 20;
pub const AUTHORITY_FRAGMENT_DATA_MAX: usize = 960;
pub const AUTHORITY_FRAGMENT_TOTAL_MAX: usize = 2048;
pub const AUTHORITY_FRAGMENT_MAX: usize = AUTHORITY_FRAGMENT_HEAD + AUTHORITY_FRAGMENT_DATA_MAX;
pub const AUTHORITY_HOPS_MAX: u8 = 16;
pub const SITE_STATE_SET_PAYLOAD: usize = 16;
pub const SITE_STATE_REPORT_PAYLOAD: usize = 28;

pub const CARRIER_R1_TOTAL: u16 = 60;
pub const CARRIER_R2_OK_TOTAL: u16 = 52;
pub const CARRIER_R2_HINT_TOTAL: u16 = 12;
pub const CARRIER_R3_TOTAL: u16 = 16;
pub const CARRIER_ENVELOPE_MIN_TOTAL: u16 = 28;
pub const CARRIER_WAKE_TOTAL: u16 = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SiteStateAction {
    WakeLocal = 1,
    QueryLocal = 2,
}

impl SiteStateAction {
    pub fn try_from_byte(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            1 => Self::WakeLocal,
            2 => Self::QueryLocal,
            _ => return Err(HostOpsError::UnknownEnum("action", value)),
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum SiteStateResult {
    FragmentQueued = 0,
    ObjectQueued = 1,
    Busy = 2,
    Unreachable = 3,
    Unsupported = 4,
    Conflict = 5,
    Timeout = 6,
}

impl SiteStateResult {
    pub fn try_from_byte(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            0 => Self::FragmentQueued,
            1 => Self::ObjectQueued,
            2 => Self::Busy,
            3 => Self::Unreachable,
            4 => Self::Unsupported,
            5 => Self::Conflict,
            6 => Self::Timeout,
            _ => return Err(HostOpsError::UnknownEnum("result", value)),
        })
    }
}

/// One carrier fragment (20 B head + data).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityFragment {
    pub device: u64,
    pub transfer_id: u32,
    pub kind: crate::authority::CarrierKind,
    pub hops: u8,
    pub total: u16,
    pub offset: u16,
    pub data: Vec<u8>,
}

fn authority_kind_total_ok(kind: crate::authority::CarrierKind, total: u16) -> bool {
    match kind {
        crate::authority::CarrierKind::R1 => total == CARRIER_R1_TOTAL,
        crate::authority::CarrierKind::R2 => {
            total == CARRIER_R2_OK_TOTAL || total == CARRIER_R2_HINT_TOTAL
        }
        crate::authority::CarrierKind::R3 => total == CARRIER_R3_TOTAL,
        crate::authority::CarrierKind::Envelope => {
            total >= CARRIER_ENVELOPE_MIN_TOTAL && total <= AUTHORITY_FRAGMENT_TOTAL_MAX as u16
        }
        crate::authority::CarrierKind::Wake => total == CARRIER_WAKE_TOTAL,
    }
}

fn check_authority_fragment(fragment: &AuthorityFragment, up: bool) -> Result<(), HostOpsError> {
    if fragment.device == 0 || fragment.device == u64::MAX {
        return Err(HostOpsError::Invalid("bad device"));
    }
    if fragment.transfer_id == 0 {
        return Err(HostOpsError::Invalid("zero_transfer_id"));
    }
    if up {
        if fragment.hops > AUTHORITY_HOPS_MAX {
            return Err(HostOpsError::Invalid("bad_hops"));
        }
    } else if fragment.hops != 0 {
        return Err(HostOpsError::Invalid("bad_hops"));
    }
    // (device == gateway) <=> (hops == 0) needs the gateway identity, which
    // the codec does not have; the bridge enforces it when the lane lands.
    if !authority_kind_total_ok(fragment.kind, fragment.total) {
        if fragment.total > AUTHORITY_FRAGMENT_TOTAL_MAX as u16 {
            return Err(HostOpsError::Invalid("oversized"));
        }
        return Err(HostOpsError::Invalid("bad total for kind"));
    }
    if fragment.offset as usize % AUTHORITY_FRAGMENT_DATA_MAX != 0
        || fragment.offset >= fragment.total
    {
        return Err(HostOpsError::Invalid("bad_grid"));
    }
    if fragment.data.is_empty()
        || fragment.data.len() > AUTHORITY_FRAGMENT_DATA_MAX
        || fragment.offset as usize + fragment.data.len() > fragment.total as usize
    {
        return Err(HostOpsError::LengthMismatch);
    }
    let last = fragment.offset as usize + fragment.data.len() == fragment.total as usize;
    if !last && fragment.data.len() != AUTHORITY_FRAGMENT_DATA_MAX {
        return Err(HostOpsError::Invalid("short middle fragment"));
    }
    Ok(())
}

fn encode_authority_fragment(
    sub: u8,
    fragment: &AuthorityFragment,
    up: bool,
) -> Result<Vec<u8>, HostOpsError> {
    check_authority_fragment(fragment, up)?;
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + AUTHORITY_FRAGMENT_HEAD);
    gateway_head(&mut out, sub, AUTHORITY_FRAGMENT_HEAD + fragment.data.len());
    out.extend_from_slice(&fragment.device.to_be_bytes());
    out.extend_from_slice(&fragment.transfer_id.to_be_bytes());
    out.push(fragment.kind as u8);
    out.push(fragment.hops);
    out.extend_from_slice(&fragment.total.to_be_bytes());
    out.extend_from_slice(&fragment.offset.to_be_bytes());
    out.extend_from_slice(&(fragment.data.len() as u16).to_be_bytes());
    out.extend_from_slice(&fragment.data);
    Ok(out)
}

fn decode_authority_fragment(
    inner: &[u8],
    sub: u8,
    up: bool,
) -> Result<AuthorityFragment, HostOpsError> {
    let payload = gateway_body(
        inner,
        sub,
        AUTHORITY_FRAGMENT_HEAD + 1,
        AUTHORITY_FRAGMENT_MAX,
    )?;
    let device = u64_at(payload, 0)?;
    let transfer_id = u32_at(payload, 8)?;
    let kind = crate::authority::CarrierKind::try_from_byte(payload[12])
        .map_err(|_| HostOpsError::UnknownEnum("kind", payload[12]))?;
    let hops = payload[13];
    let total = u16_at(payload, 14)?;
    let offset = u16_at(payload, 16)?;
    let length = u16_at(payload, 18)? as usize;
    if payload.len() != AUTHORITY_FRAGMENT_HEAD + length {
        return Err(HostOpsError::LengthMismatch);
    }
    let fragment = AuthorityFragment {
        device,
        transfer_id,
        kind,
        hops,
        total,
        offset,
        data: payload[AUTHORITY_FRAGMENT_HEAD..].to_vec(),
    };
    check_authority_fragment(&fragment, up)?;
    Ok(fragment)
}

pub fn encode_authority_up(fragment: &AuthorityFragment) -> Result<Vec<u8>, HostOpsError> {
    encode_authority_fragment(SUB_AUTHORITY_UP, fragment, true)
}

pub fn decode_authority_up(inner: &[u8]) -> Result<AuthorityFragment, HostOpsError> {
    decode_authority_fragment(inner, SUB_AUTHORITY_UP, true)
}

pub fn encode_authority_down(fragment: &AuthorityFragment) -> Result<Vec<u8>, HostOpsError> {
    encode_authority_fragment(SUB_AUTHORITY_DOWN, fragment, false)
}

pub fn decode_authority_down(inner: &[u8]) -> Result<AuthorityFragment, HostOpsError> {
    decode_authority_fragment(inner, SUB_AUTHORITY_DOWN, false)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteStateSet {
    pub action: SiteStateAction,
    pub site_epoch: u32,
    pub rs_epoch_hint: u32,
    pub gk_epoch_hint: u32,
}

pub fn encode_site_state_set(set: &SiteStateSet) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + SITE_STATE_SET_PAYLOAD);
    gateway_head(&mut out, SUB_SITE_STATE_SET, SITE_STATE_SET_PAYLOAD);
    out.push(1);
    out.push(set.action as u8);
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&set.site_epoch.to_be_bytes());
    out.extend_from_slice(&set.rs_epoch_hint.to_be_bytes());
    out.extend_from_slice(&set.gk_epoch_hint.to_be_bytes());
    out
}

pub fn decode_site_state_set(inner: &[u8]) -> Result<SiteStateSet, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_SITE_STATE_SET,
        SITE_STATE_SET_PAYLOAD,
        SITE_STATE_SET_PAYLOAD,
    )?;
    if payload[0] != 1 {
        return Err(HostOpsError::Invalid("bad version"));
    }
    let action = SiteStateAction::try_from_byte(payload[1])?;
    if payload[2] != 0 || payload[3] != 0 {
        return Err(HostOpsError::Invalid("reserved_nonzero"));
    }
    Ok(SiteStateSet {
        action,
        site_epoch: u32_at(payload, 4)?,
        rs_epoch_hint: u32_at(payload, 8)?,
        gk_epoch_hint: u32_at(payload, 12)?,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteStateReport {
    pub result: SiteStateResult,
    pub local_state_valid: bool,
    pub device: u64,
    pub transfer_id: u32,
    pub received_len: u16,
    pub local_current: u32,
    pub local_next: u32,
}

pub fn encode_site_state_report(report: &SiteStateReport) -> Vec<u8> {
    let mut out = Vec::with_capacity(GATEWAY_INNER_HEAD_SIZE + SITE_STATE_REPORT_PAYLOAD);
    gateway_head(&mut out, SUB_SITE_STATE_REPORT, SITE_STATE_REPORT_PAYLOAD);
    out.push(1);
    out.push(report.result as u8);
    out.extend_from_slice(&(u16::from(report.local_state_valid)).to_be_bytes());
    out.extend_from_slice(&report.device.to_be_bytes());
    out.extend_from_slice(&report.transfer_id.to_be_bytes());
    out.extend_from_slice(&report.received_len.to_be_bytes());
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&report.local_current.to_be_bytes());
    out.extend_from_slice(&report.local_next.to_be_bytes());
    out
}

pub fn decode_site_state_report(inner: &[u8]) -> Result<SiteStateReport, HostOpsError> {
    let payload = gateway_body(
        inner,
        SUB_SITE_STATE_REPORT,
        SITE_STATE_REPORT_PAYLOAD,
        SITE_STATE_REPORT_PAYLOAD,
    )?;
    if payload[0] != 1 {
        return Err(HostOpsError::Invalid("bad version"));
    }
    let result = SiteStateResult::try_from_byte(payload[1])?;
    let flags = u16_at(payload, 2)?;
    if flags > 1 {
        return Err(HostOpsError::Invalid("reserved_nonzero"));
    }
    if payload[18] != 0 || payload[19] != 0 {
        return Err(HostOpsError::Invalid("reserved_nonzero"));
    }
    Ok(SiteStateReport {
        result,
        local_state_valid: flags == 1,
        device: u64_at(payload, 4)?,
        transfer_id: u32_at(payload, 12)?,
        received_len: u16_at(payload, 16)?,
        local_current: u32_at(payload, 20)?,
        local_next: u32_at(payload, 24)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease() -> BootLease {
        BootLease::derive(0x00b0_071d_0001, 1)
    }

    fn dispatcher() -> [u8; DISPATCHER_ID_SIZE] {
        *b"host-dispatcher1"
    }

    fn submit(seq: u64, canonical_len: usize) -> SubmitRequest {
        SubmitRequest {
            lease: lease(),
            dispatcher: dispatcher(),
            dispatch_seq: seq,
            operation_id: [0xA0; OPERATION_ID_SIZE],
            canonical_hash: [0x10; CANONICAL_HASH_SIZE],
            device_deadline: 60_000,
            canonical: vec![0x5A; canonical_len],
        }
    }

    #[test]
    fn lease_layout_and_validity() {
        let lease = lease();
        assert!(lease.valid());
        assert_eq!(&lease.0[..8], &0x00b0_071d_0001_u64.to_be_bytes());
        assert_eq!(&lease.0[8..], &1_u64.to_be_bytes());
        assert!(!BootLease::derive(0, 1).valid());
        assert!(!BootLease::derive(u64::MAX, 1).valid());
        assert!(!BootLease::derive(9, 0).valid());
        assert!(!BootLease::derive(9, u64::MAX).valid());
    }

    #[test]
    fn submit_round_trip_and_bounds() {
        for canonical_len in [0, 26, 35, CANONICAL_MAX_SIZE] {
            let request = submit(3, canonical_len);
            let bytes = encode_submit(&request).unwrap();
            assert_eq!(bytes.len(), SUBMIT_FIXED_SIZE + canonical_len);
            assert_eq!(decode_submit(&bytes).unwrap(), request);
        }
        assert_eq!(
            encode_submit(&submit(1, CANONICAL_MAX_SIZE + 1)),
            Err(HostOpsError::CanonicalTooLarge)
        );
    }

    #[test]
    fn submit_rejects_malformed() {
        let bytes = encode_submit(&submit(3, 35)).unwrap();
        for cut in [0, 1, SUBMIT_FIXED_SIZE - 1, bytes.len() - 1] {
            assert!(decode_submit(&bytes[..cut]).is_err(), "cut {cut}");
        }
        let mut overlong = bytes.clone();
        overlong.push(0);
        assert_eq!(decode_submit(&overlong), Err(HostOpsError::LengthMismatch));
        let mut lied = bytes.clone();
        lied[SUBMIT_FIXED_SIZE - 1] ^= 0xFF;
        assert_eq!(decode_submit(&lied), Err(HostOpsError::LengthMismatch));
        let mut schema = bytes.clone();
        schema[0] = 2;
        assert_eq!(decode_submit(&schema), Err(HostOpsError::BadSchema));
        let mut sub = bytes.clone();
        sub[1] = SUB_QUERY_DISPATCH;
        assert_eq!(decode_submit(&sub), Err(HostOpsError::SubcommandMismatch));
    }

    #[test]
    fn lane_requests_round_trip() {
        for sub in [SUB_QUERY_DISPATCH, SUB_RETIRE_THROUGH, SUB_SKIP] {
            let request = LaneRequest {
                lease: lease(),
                dispatcher: dispatcher(),
                seq: 17,
            };
            let bytes = encode_lane_request(sub, &request);
            assert_eq!(bytes.len(), LANE_REQUEST_SIZE);
            assert_eq!(decode_lane_request(&bytes, sub).unwrap(), request);
            assert_eq!(
                decode_lane_request(&bytes[..LANE_REQUEST_SIZE - 1], sub),
                Err(HostOpsError::LengthMismatch)
            );
            let other = if sub == SUB_SKIP {
                SUB_QUERY_DISPATCH
            } else {
                SUB_SKIP
            };
            assert_eq!(
                decode_lane_request(&bytes, other),
                Err(HostOpsError::SubcommandMismatch)
            );
        }
    }

    #[test]
    fn time_sample_round_trip() {
        let request = TimeSampleRequest {
            lease: lease(),
            nonce: 0x1234,
        };
        let bytes = encode_time_sample_request(&request);
        assert_eq!(bytes.len(), TIME_SAMPLE_REQUEST_SIZE);
        assert_eq!(decode_time_sample_request(&bytes).unwrap(), request);
        assert!(decode_time_sample_request(&bytes[..25]).is_err());

        let response = TimeSampleResponse {
            result: HostOpsResult::Ok,
            lease: lease(),
            nonce: 9,
            device_time: 4242,
        };
        let bytes = encode_time_sample_response(&response);
        assert_eq!(bytes.len(), TIME_SAMPLE_RESPONSE_SIZE);
        assert_eq!(decode_time_sample_response(&bytes).unwrap(), response);
        assert!(decode_time_sample_response(&bytes[..34]).is_err());
        let mut bad = bytes.clone();
        bad[2] = 14;
        assert!(decode_time_sample_response(&bad).is_err());
    }

    #[test]
    fn receipt_round_trip() {
        let receipt = Receipt {
            sub: SUB_SUBMIT,
            result: HostOpsResult::Ok,
            state: SlotState::Sent,
            lease: lease(),
            dispatch_seq: 5,
            hash: [0x20; CANONICAL_HASH_SIZE],
            msg_session: 7001,
            msg_seq: 2,
            msg_valid: true,
            evidence: Evidence::GatewayAccepted,
        };
        let bytes = encode_receipt(&receipt);
        assert_eq!(bytes.len(), RECEIPT_SIZE);
        assert_eq!(decode_receipt(&bytes, SUB_SUBMIT).unwrap(), receipt);
        assert!(decode_receipt(&bytes[..RECEIPT_SIZE - 1], SUB_SUBMIT).is_err());
        assert_eq!(
            decode_receipt(&bytes, SUB_SKIP),
            Err(HostOpsError::SubcommandMismatch)
        );
        for (offset, value) in [(2, 14), (3, 7), (72, 2), (73, 5)] {
            let mut bad = bytes.clone();
            bad[offset] = value;
            assert!(decode_receipt(&bad, SUB_SUBMIT).is_err(), "offset {offset}");
        }
    }

    #[test]
    fn query_and_retire_round_trip() {
        let query = QueryResponse {
            result: HostOpsResult::Ok,
            state: SlotState::Delivered,
            lease: lease(),
            dispatch_seq: 6,
            hash: [0x21; CANONICAL_HASH_SIZE],
            operation_id: [0xA1; OPERATION_ID_SIZE],
            msg_session: 7001,
            msg_seq: 3,
            msg_valid: true,
            evidence: Evidence::EndSdkReceived,
        };
        let bytes = encode_query_response(&query);
        assert_eq!(bytes.len(), QUERY_RESPONSE_SIZE);
        assert_eq!(decode_query_response(&bytes).unwrap(), query);
        assert!(decode_query_response(&bytes[..QUERY_RESPONSE_SIZE - 1]).is_err());

        let retire = RetireResponse {
            result: HostOpsResult::Ok,
            lease: lease(),
            retired_through: 11,
        };
        let bytes = encode_retire_response(&retire);
        assert_eq!(bytes.len(), RETIRE_RESPONSE_SIZE);
        assert_eq!(decode_retire_response(&bytes).unwrap(), retire);
        assert!(decode_retire_response(&bytes[..RETIRE_RESPONSE_SIZE - 1]).is_err());
    }

    #[test]
    fn slot_terminality() {
        assert!(!SlotState::Empty.is_terminal());
        assert!(!SlotState::Sent.is_terminal());
        for state in [
            SlotState::Delivered,
            SlotState::Failed,
            SlotState::Expired,
            SlotState::Skipped,
            SlotState::Indeterminate,
        ] {
            assert!(state.is_terminal());
        }
    }

    // --- Config endpoint family (0x20-0x23) --------------------------------

    #[test]
    fn config_result_round_trip_and_unknown() {
        for value in [0u16, 1, 3, 4, 5, 7, 8, 9] {
            let result = ConfigOpsResult::try_from_u16(value).unwrap();
            assert_eq!(result as u16, value);
        }
        for bad in [2u16, 6, 10, 0xFFFF] {
            assert!(ConfigOpsResult::try_from_u16(bad).is_err(), "bad {bad}");
        }
    }

    #[test]
    fn config_sub_peels_only_config_family() {
        for sub in [
            SUB_CONFIG_QUERY,
            SUB_CONFIG_PERMIT,
            SUB_CONFIG_STATUS,
            SUB_CONFIG_CHALLENGE,
        ] {
            let inner = [HOST_OPS_SCHEMA, sub, 0, 0];
            assert_eq!(config_sub(&inner), Some(sub));
        }
        for sub in [SUB_HOST_REGISTER, SUB_GATEWAY_INGRESS, 0x7F] {
            let inner = [HOST_OPS_SCHEMA, sub, 0, 0];
            assert_eq!(config_sub(&inner), None);
        }
        assert_eq!(config_sub(&[2, SUB_CONFIG_QUERY]), None); // wrong schema
        assert_eq!(config_sub(&[HOST_OPS_SCHEMA]), None); // too short
    }

    #[test]
    fn config_query_round_trip() {
        let request = ConfigQueryRequest {
            target: 0x1122_3344_5566_7788,
            config_namespace: 1,
            operation_id: [0xAB; 16],
        };
        let bytes = encode_config_query(&request);
        assert_eq!(
            bytes.len(),
            GATEWAY_INNER_HEAD_SIZE + CONFIG_QUERY_REQUEST_PAYLOAD
        );
        assert_eq!(bytes[1], SUB_CONFIG_QUERY);
        assert_eq!(decode_config_query(&bytes).unwrap(), request);
        assert!(decode_config_query(&bytes[..bytes.len() - 1]).is_err());
        let mut wrong_sub = bytes.clone();
        wrong_sub[1] = SUB_CONFIG_STATUS;
        assert_eq!(
            decode_config_query(&wrong_sub),
            Err(HostOpsError::SubcommandMismatch)
        );
    }

    #[test]
    fn config_challenge_round_trip() {
        let request = ConfigChallengeRequest {
            target: 0x0102_0304_0506_0708,
            config_namespace: 1,
            schema: 1,
            client_nonce: [0xCD; 16],
        };
        let bytes = encode_config_challenge(&request);
        assert_eq!(
            bytes.len(),
            GATEWAY_INNER_HEAD_SIZE + CONFIG_CHALLENGE_REQUEST_PAYLOAD
        );
        assert_eq!(decode_config_challenge(&bytes).unwrap(), request);
        assert!(decode_config_challenge(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn config_permit_round_trip_and_bounds() {
        for permit_len in [1usize, 100, CONFIG_PERMIT_MAX] {
            let request = ConfigPermitRequest {
                target: 7,
                permit: vec![0x5C; permit_len],
            };
            let bytes = encode_config_permit(&request).unwrap();
            assert_eq!(bytes.len(), GATEWAY_INNER_HEAD_SIZE + 8 + permit_len);
            assert_eq!(decode_config_permit(&bytes).unwrap(), request);
        }
        assert!(encode_config_permit(&ConfigPermitRequest {
            target: 1,
            permit: Vec::new()
        })
        .is_err());
        assert!(encode_config_permit(&ConfigPermitRequest {
            target: 1,
            permit: vec![0; CONFIG_PERMIT_MAX + 1]
        })
        .is_err());
        // A zero-length permit body (target only) is below the 9-byte floor.
        let mut short = Vec::new();
        gateway_head(&mut short, SUB_CONFIG_PERMIT, 8);
        short.extend_from_slice(&7_u64.to_be_bytes());
        assert!(decode_config_permit(&short).is_err());
    }

    #[test]
    fn config_trust_and_info_codecs_round_trip() {
        // 0x25 trust transfer: target + manifest bytes, bounded.
        for manifest_len in [1usize, 100, CONFIG_TRUST_MANIFEST_MAX] {
            let request = ConfigTrustRequest {
                target: 7,
                manifest: vec![0x5C; manifest_len],
            };
            let bytes = encode_config_trust(&request).unwrap();
            assert_eq!(bytes.len(), GATEWAY_INNER_HEAD_SIZE + 8 + manifest_len);
            assert_eq!(decode_config_trust(&bytes).unwrap(), request);
        }
        assert!(encode_config_trust(&ConfigTrustRequest {
            target: 1,
            manifest: Vec::new()
        })
        .is_err());
        assert!(encode_config_trust(&ConfigTrustRequest {
            target: 1,
            manifest: vec![0; CONFIG_TRUST_MANIFEST_MAX + 1]
        })
        .is_err());
        // 0x26 trust-status query: target + network + nonce (32 B).
        let status = ConfigTrustStatusRequest {
            target: 7,
            network: 9,
            nonce: [0x11; 16],
        };
        let bytes = encode_config_trust_status(&status).unwrap();
        assert_eq!(bytes.len(), GATEWAY_INNER_HEAD_SIZE + 32);
        assert_eq!(decode_config_trust_status(&bytes).unwrap(), status);
        // 0x27 recovery-info query: target + network + ns + nonce (34 B).
        let info = ConfigRecoveryInfoRequest {
            target: 7,
            network: 9,
            config_namespace: 3,
            nonce: [0x22; 16],
        };
        let bytes = encode_config_recovery_info(&info).unwrap();
        assert_eq!(bytes.len(), GATEWAY_INNER_HEAD_SIZE + 34);
        assert_eq!(decode_config_recovery_info(&bytes).unwrap(), info);
        let mut short = Vec::new();
        gateway_head(&mut short, SUB_CONFIG_RECOVERY_INFO, 33);
        short.extend_from_slice(&[0; 33]);
        assert!(decode_config_recovery_info(&short).is_err());
        // Replies: 0x25 result-only; 0x26/0x27 fixed bodies on Ok.
        let trust_reply = ConfigReply {
            result: ConfigOpsResult::Ok as u16,
            target: 9,
            body: Vec::new(),
        };
        let bytes = encode_config_reply(SUB_CONFIG_TRUST, &trust_reply).unwrap();
        assert_eq!(
            decode_config_reply(&bytes, SUB_CONFIG_TRUST).unwrap(),
            trust_reply
        );
        assert!(encode_config_reply(
            SUB_CONFIG_TRUST,
            &ConfigReply {
                body: vec![0; 4],
                ..trust_reply.clone()
            },
        )
        .is_err());
        for (sub, size) in [
            (SUB_CONFIG_TRUST_STATUS, CONFIG_TRUST_STATUS_BODY_SIZE),
            (SUB_CONFIG_RECOVERY_INFO, CONFIG_RECOVERY_INFO_BODY_SIZE),
        ] {
            let reply = ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target: 9,
                body: vec![0x71; size],
            };
            let bytes = encode_config_reply(sub, &reply).unwrap();
            assert_eq!(decode_config_reply(&bytes, sub).unwrap(), reply);
            let bad = ConfigReply {
                body: vec![0x71; size - 1],
                ..reply.clone()
            };
            assert!(encode_config_reply(sub, &bad).is_err());
        }
    }

    #[test]
    fn config_reply_per_sub_body_rules() {
        // Permit reply: result-only (empty body always).
        let reply = ConfigReply {
            result: ConfigOpsResult::Ok as u16,
            target: 9,
            body: Vec::new(),
        };
        let bytes = encode_config_reply(SUB_CONFIG_PERMIT, &reply).unwrap();
        assert_eq!(
            bytes.len(),
            GATEWAY_INNER_HEAD_SIZE + CONFIG_REPLY_FIXED_PAYLOAD
        );
        assert_eq!(
            decode_config_reply(&bytes, SUB_CONFIG_PERMIT).unwrap(),
            reply
        );
        // A permit reply may not carry a body.
        let with_body = ConfigReply {
            body: vec![0; 4],
            ..reply.clone()
        };
        assert!(encode_config_reply(SUB_CONFIG_PERMIT, &with_body).is_err());

        // Status reply: 72-byte body on Ok.
        let status_reply = ConfigReply {
            result: ConfigOpsResult::Ok as u16,
            target: 9,
            body: vec![0x22; CONFIG_STATUS_BODY_SIZE],
        };
        let bytes = encode_config_reply(SUB_CONFIG_STATUS, &status_reply).unwrap();
        assert_eq!(
            bytes.len(),
            GATEWAY_INNER_HEAD_SIZE + CONFIG_REPLY_FIXED_PAYLOAD + CONFIG_STATUS_BODY_SIZE
        );
        assert_eq!(
            decode_config_reply(&bytes, SUB_CONFIG_STATUS).unwrap(),
            status_reply
        );
        // Wrong body size is rejected.
        let bad_body = ConfigReply {
            body: vec![0; 10],
            ..status_reply.clone()
        };
        assert!(encode_config_reply(SUB_CONFIG_STATUS, &bad_body).is_err());
        let mut forged = encode_config_reply(SUB_CONFIG_STATUS, &status_reply).unwrap();
        forged.truncate(forged.len() - 1);
        assert!(decode_config_reply(&forged, SUB_CONFIG_STATUS).is_err());

        // Challenge reply: 92-byte body on Ok.
        let challenge_reply = ConfigReply {
            result: ConfigOpsResult::Ok as u16,
            target: 9,
            body: vec![0x23; CONFIG_CHALLENGE_BODY_SIZE],
        };
        let bytes = encode_config_reply(SUB_CONFIG_CHALLENGE, &challenge_reply).unwrap();
        assert_eq!(
            decode_config_reply(&bytes, SUB_CONFIG_CHALLENGE).unwrap(),
            challenge_reply
        );

        // Failure replies carry no body, whatever the sub.
        for sub in [SUB_CONFIG_STATUS, SUB_CONFIG_CHALLENGE, SUB_CONFIG_PERMIT] {
            let failure = ConfigReply {
                result: ConfigOpsResult::Timeout as u16,
                target: 9,
                body: Vec::new(),
            };
            let bytes = encode_config_reply(sub, &failure).unwrap();
            assert_eq!(decode_config_reply(&bytes, sub).unwrap(), failure);
        }
        // An unknown result value is rejected on decode.
        let mut bad_result = encode_config_reply(SUB_CONFIG_PERMIT, &reply).unwrap();
        bad_result[GATEWAY_INNER_HEAD_SIZE] = 0;
        bad_result[GATEWAY_INNER_HEAD_SIZE + 1] = 2; // result=2 (unused)
        assert!(decode_config_reply(&bad_result, SUB_CONFIG_PERMIT).is_err());
    }

    #[test]
    fn authority_fragments_round_trip_and_refuse() {
        use crate::authority::CarrierKind;
        let fragment = AuthorityFragment {
            device: 0x101,
            transfer_id: 0xC0FFEE,
            kind: CarrierKind::Envelope,
            hops: 3,
            total: 1920,
            offset: 960,
            data: vec![0x55; 960],
        };
        let bytes = encode_authority_up(&fragment).expect("encode up");
        assert_eq!(decode_authority_up(&bytes).expect("decode up"), fragment);
        assert!(decode_authority_down(&bytes).is_err());
        // The largest legal fragment fits the 1024-byte USB queue slot.
        assert_eq!(GATEWAY_INNER_HEAD_SIZE + AUTHORITY_FRAGMENT_MAX, 984);
        let mut full = fragment.clone();
        full.total = 2048;
        full.offset = 0;
        full.data = vec![0xAA; AUTHORITY_FRAGMENT_DATA_MAX];
        assert!(encode_authority_up(&full).expect("encode").len() <= 1024);
        // Down fragments must carry hops 0.
        let mut down = fragment.clone();
        down.hops = 0;
        assert!(encode_authority_down(&down).is_ok());
        down.hops = 1;
        assert!(encode_authority_down(&down).is_err());
        // Kind pins total: R1 is exactly 60 bytes, Wake exactly 8.
        let mut r1 = fragment.clone();
        r1.kind = CarrierKind::R1;
        r1.total = 60;
        r1.offset = 0;
        r1.data = vec![0; 60];
        assert!(encode_authority_up(&r1).is_ok());
        r1.total = 61;
        r1.data = vec![0; 61];
        assert!(encode_authority_up(&r1).is_err());
        // A short middle fragment is malformed.
        let mut short = fragment;
        short.total = 1920;
        short.offset = 0;
        short.data = vec![0; 900];
        assert!(encode_authority_up(&short).is_err());
    }

    #[test]
    fn authority_site_state_round_trip_and_refuse() {
        let set = SiteStateSet {
            action: SiteStateAction::WakeLocal,
            site_epoch: 7,
            rs_epoch_hint: 4,
            gk_epoch_hint: 11,
        };
        let bytes = encode_site_state_set(&set);
        assert_eq!(decode_site_state_set(&bytes).expect("decode"), set);
        let mut bad = bytes.clone();
        bad[GATEWAY_INNER_HEAD_SIZE + 1] = 9;
        assert_eq!(
            decode_site_state_set(&bad).unwrap_err().name(),
            "bad_action"
        );

        let report = SiteStateReport {
            result: SiteStateResult::ObjectQueued,
            local_state_valid: true,
            device: 0x101,
            transfer_id: 0xC0FFEE,
            received_len: 2048,
            local_current: 10,
            local_next: 11,
        };
        let bytes = encode_site_state_report(&report);
        assert_eq!(decode_site_state_report(&bytes).expect("decode"), report);
        let mut bad = bytes;
        bad[GATEWAY_INNER_HEAD_SIZE + 1] = 9;
        assert_eq!(
            decode_site_state_report(&bad).unwrap_err().name(),
            "bad_result"
        );
    }
}
