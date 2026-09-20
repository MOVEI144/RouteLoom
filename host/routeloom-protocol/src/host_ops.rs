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
pub const HOST_OPS_SCHEMA: u8 = 1;

pub const SUB_SUBMIT: u8 = 0x01;
pub const SUB_QUERY_DISPATCH: u8 = 0x02;
pub const SUB_RETIRE_THROUGH: u8 = 0x03;
pub const SUB_SKIP: u8 = 0x04;
pub const SUB_TIME_SAMPLE: u8 = 0x05;

pub const BOOT_LEASE_SIZE: usize = 16;
pub const DISPATCHER_ID_SIZE: usize = 16;
pub const OPERATION_ID_SIZE: usize = 24;
pub const CANONICAL_HASH_SIZE: usize = 32;

pub const SUBMIT_FIXED_SIZE: usize = 108;
pub const SUBMIT_MAX_SIZE: usize = 262;
pub const CANONICAL_MAX_SIZE: usize = 154;
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
}

impl fmt::Display for HostOpsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for HostOpsError {}

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

/// Evidence stage (mirrors `DispatchWindow::Evidence`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Evidence {
    None = 0,
    GatewayAccepted = 1,
    MacAttemptReported = 2,
    EndSdkReceived = 3,
}

impl Evidence {
    pub fn try_from_byte(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            0 => Self::None,
            1 => Self::GatewayAccepted,
            2 => Self::MacAttemptReported,
            3 => Self::EndSdkReceived,
            _ => return Err(HostOpsError::UnknownEnum("evidence", value)),
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
        for (offset, value) in [(2, 14), (3, 7), (72, 2), (73, 4)] {
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
}
