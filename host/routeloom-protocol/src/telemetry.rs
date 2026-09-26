//! m1 diagnostics HostOps codec (subcommands 0x30/0x31): a
//! DiagnosticRequest tunnels one TelemetryQuery to an observer and the
//! DiagnosticResponse carries a TelemetrySnapshot or DiagnosticReject.
//! Byte-identical to the device side in
//! `components/routeloom/{include/routeloom/{usb_host_ops,telemetry}.hpp,src/{usb_host_ops,telemetry}.cpp}`.
//!
//! Inner common form (the gateway/config family shape): schema:u8=1,
//! sub:u8, payload_len:u16, payload — big-endian, exact length only.
//!
//! Clock domain: `sampled_at_ms`/`window_ms`/`sample_age_ms` are durations
//! on the observer's monotonic clock at snapshot time, never absolute
//! timestamps.

use crate::host_ops::{ConfigOpsResult, HostOpsError, HOST_OPS_SCHEMA};

/// HelloAck capability bit: the device serves 0x30/0x31.
pub const CAP_M1_DIAGNOSTICS_V1: u32 = 1 << 5;

pub const SUB_DIAGNOSTIC_REQUEST: u8 = 0x30;
pub const SUB_DIAGNOSTIC_RESPONSE: u8 = 0x31;

pub const INNER_HEAD_SIZE: usize = 4;
/// 0x30 payload head: observer:u64, then one diagnostic query body.
pub const REQUEST_FIXED: usize = 8;
/// 0x31 payload head: result:u16 + observer:u64 + body_len:u16.
pub const REPLY_FIXED: usize = 12;
/// Largest 0x31 body (a TelemetrySnapshot).
pub const REPLY_MAX_BODY: usize = 128;

pub const DIAG_BODY_VERSION: u8 = 1;
pub const DIAG_SUB_TELEMETRY_QUERY: u8 = 3;
pub const DIAG_SUB_TELEMETRY_SNAPSHOT: u8 = 4;
pub const DIAG_SUB_DIAGNOSTIC_REJECT: u8 = 6;
pub const DIAG_PREFIX_SIZE: usize = 4;

pub const QUERY_BODY_SIZE: usize = 24;
pub const SNAPSHOT_BODY_SIZE: usize = 128;
pub const REJECT_BODY_SIZE: usize = 24;

pub const DIRECTION_EGRESS: u8 = 0;
pub const DIRECTION_INGRESS: u8 = 1;

/// Length class 255 = peer summary only (no per-length buckets).
pub const LENGTH_CLASS_PEER_SUMMARY: u8 = 255;
pub const MAX_AGE_LIMIT_MS: u32 = 3000;

/// Snapshot validity bits (04 §4.2); the two source bits are exclusive.
pub const VALID_RSSI: u8 = 1 << 0;
pub const VALID_BUCKET: u8 = 1 << 1;
pub const VALID_DRIVER_EWMA: u8 = 1 << 2;
pub const VALID_HOP_RTT_EWMA: u8 = 1 << 3;
pub const SOURCE_LOCAL_DRIVER: u8 = 1 << 4;
pub const SOURCE_INJECTED_TEST: u8 = 1 << 5;
pub const WINDOW_INCOMPLETE: u8 = 1 << 6;
pub const STALE: u8 = 1 << 7;

/// Saturation mask bits, in snapshot field order.
pub const SAT_RSSI_SAMPLES: u32 = 1 << 0;
pub const SAT_TX_SUBMITTED: u32 = 1 << 1;
pub const SAT_TX_MAC_SUCCESS: u32 = 1 << 2;
pub const SAT_TX_MAC_FAIL: u32 = 1 << 3;
pub const SAT_TX_UNKNOWN: u32 = 1 << 4;
pub const SAT_SDK_RETRIES: u32 = 1 << 5;
pub const SAT_HOP_ACCEPTS: u32 = 1 << 6;
pub const SAT_HOP_TIMEOUTS: u32 = 1 << 7;
pub const SAT_BUSY: u32 = 1 << 8;
pub const SAT_EVENT_DROPS: u32 = 1 << 9;
pub const SAT_TIME_EWMA: u32 = 1 << 10;

fn reserved_id(value: u64) -> bool {
    value == 0 || value == u64::MAX
}

/// The sub byte of a diagnostics inner body (0x30/0x31), if it is one.
/// Lets the daemon's frame router peel this family off the dispatcher lane.
pub fn diagnostic_sub(inner: &[u8]) -> Option<u8> {
    if inner.len() < 2 || inner[0] != HOST_OPS_SCHEMA {
        return None;
    }
    matches!(inner[1], SUB_DIAGNOSTIC_REQUEST | SUB_DIAGNOSTIC_RESPONSE).then_some(inner[1])
}

fn head(out: &mut Vec<u8>, sub: u8, payload_len: usize) {
    out.push(HOST_OPS_SCHEMA);
    out.push(sub);
    out.extend_from_slice(&(payload_len as u16).to_be_bytes());
}

fn body(inner: &[u8], sub: u8, min: usize, max: usize) -> Result<&[u8], HostOpsError> {
    if inner.len() < INNER_HEAD_SIZE || inner.len() > INNER_HEAD_SIZE + max {
        return Err(HostOpsError::LengthMismatch);
    }
    if inner[0] != HOST_OPS_SCHEMA {
        return Err(HostOpsError::BadSchema);
    }
    if inner[1] != sub {
        return Err(HostOpsError::SubcommandMismatch);
    }
    let payload_len = usize::from(u16::from_be_bytes([inner[2], inner[3]]));
    if payload_len != inner.len() - INNER_HEAD_SIZE || payload_len < min || payload_len > max {
        return Err(HostOpsError::LengthMismatch);
    }
    Ok(&inner[INNER_HEAD_SIZE..])
}

fn be<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], HostOpsError> {
    bytes
        .get(offset..offset + N)
        .ok_or(HostOpsError::Truncated)?
        .try_into()
        .map_err(|_| HostOpsError::Truncated)
}

fn check_query(query: &TelemetryQuery) -> Result<(), HostOpsError> {
    if query.request_id == 0 {
        return Err(HostOpsError::Invalid("request_id"));
    }
    if reserved_id(query.peer) {
        return Err(HostOpsError::Invalid("peer"));
    }
    if query.direction != DIRECTION_EGRESS && query.direction != DIRECTION_INGRESS {
        return Err(HostOpsError::Invalid("direction"));
    }
    if query.length_class > 2 && query.length_class != LENGTH_CLASS_PEER_SUMMARY {
        return Err(HostOpsError::Invalid("length_class"));
    }
    if query.max_age_ms > MAX_AGE_LIMIT_MS {
        return Err(HostOpsError::Invalid("max_age_ms"));
    }
    Ok(())
}

/// 0x30 DIAGNOSTIC_REQUEST (H→G): observer:u64 + one TelemetryQuery body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetryQuery {
    /// Nonzero daemon-minted correlation id (local queries echo it; the
    /// bridge mints its own for remote ones).
    pub request_id: u32,
    /// Observed peer (nonzero, non-broadcast).
    pub peer: u64,
    /// DIRECTION_EGRESS | DIRECTION_INGRESS.
    pub direction: u8,
    /// 0..2, or LENGTH_CLASS_PEER_SUMMARY for the summary only.
    pub length_class: u8,
    /// 0 = latest; 1..=MAX_AGE_LIMIT_MS bounds freshness.
    pub max_age_ms: u32,
}

pub fn encode_diagnostic_request(
    observer: u64,
    query: &TelemetryQuery,
) -> Result<Vec<u8>, HostOpsError> {
    if reserved_id(observer) {
        return Err(HostOpsError::Invalid("observer"));
    }
    check_query(query)?;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + REQUEST_FIXED + QUERY_BODY_SIZE);
    head(
        &mut out,
        SUB_DIAGNOSTIC_REQUEST,
        REQUEST_FIXED + QUERY_BODY_SIZE,
    );
    out.extend_from_slice(&observer.to_be_bytes());
    out.extend_from_slice(&[DIAG_BODY_VERSION, DIAG_SUB_TELEMETRY_QUERY, 0, 0]);
    out.extend_from_slice(&query.request_id.to_be_bytes());
    out.extend_from_slice(&query.peer.to_be_bytes());
    out.push(query.direction);
    out.push(query.length_class);
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&query.max_age_ms.to_be_bytes());
    Ok(out)
}

/// 0x31 DIAGNOSTIC_RESPONSE (G→H): result + observer + one body (empty
/// unless the result is Ok).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DiagnosticReply {
    pub result: ConfigOpsResult,
    pub observer: u64,
    pub body: Vec<u8>,
}

pub fn decode_diagnostic_reply(inner: &[u8]) -> Result<DiagnosticReply, HostOpsError> {
    let payload = body(
        inner,
        SUB_DIAGNOSTIC_RESPONSE,
        REPLY_FIXED,
        REPLY_FIXED + REPLY_MAX_BODY,
    )?;
    let result = ConfigOpsResult::try_from_u16(u16::from_be_bytes(be::<2>(payload, 0)?))?;
    let observer = u64::from_be_bytes(be::<8>(payload, 2)?);
    let body_len = usize::from(u16::from_be_bytes(be::<2>(payload, 10)?));
    if body_len != payload.len() - REPLY_FIXED {
        return Err(HostOpsError::LengthMismatch);
    }
    if result != ConfigOpsResult::Ok && body_len != 0 {
        return Err(HostOpsError::Invalid("reply body on failure"));
    }
    Ok(DiagnosticReply {
        result,
        observer,
        body: payload[REPLY_FIXED..].to_vec(),
    })
}

/// Fixed 128-byte TelemetrySnapshot record (04 §4.2 offset table).
/// Generations are raw u32 values; the daemon renders them verbatim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TelemetrySnapshot {
    pub request_id: u32,
    pub observer: u64,
    pub observer_boot: u64,
    pub peer: u64,
    pub binding: u32,
    pub radio: u32,
    pub channel_epoch: u32,
    pub channel: u8,
    pub direction: u8,
    pub length_class: u8,
    pub validity: u8,
    pub sampled_at_ms: u64,
    pub window_ms: u32,
    pub sample_age_ms: u32,
    pub rssi_last: i8,
    pub rssi_min: i8,
    pub rssi_max: i8,
    pub rssi_ewma_q8_8: i16,
    pub rssi_samples: u32,
    pub tx_submitted: u32,
    pub tx_mac_success: u32,
    pub tx_mac_fail: u32,
    pub tx_unknown: u32,
    pub sdk_retries: u32,
    pub hop_accepts: u32,
    pub hop_timeouts: u32,
    pub busy: u32,
    pub queue_us_ewma: u32,
    pub driver_us_ewma: u32,
    pub hop_rtt_us_ewma: u32,
    pub event_drops: u32,
    pub saturation_mask: u32,
}

pub fn decode_telemetry_snapshot(body: &[u8]) -> Result<TelemetrySnapshot, HostOpsError> {
    if body.len() != SNAPSHOT_BODY_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    if body[0] != DIAG_BODY_VERSION
        || body[1] != DIAG_SUB_TELEMETRY_SNAPSHOT
        || body[2] != 0
        || body[3] != 0
    {
        return Err(HostOpsError::Invalid("snapshot prefix"));
    }
    if body[67] != 0 || body[70] != 0 || body[71] != 0 {
        return Err(HostOpsError::Invalid("snapshot reserved"));
    }
    let observer = u64::from_be_bytes(be::<8>(body, 8)?);
    let peer = u64::from_be_bytes(be::<8>(body, 24)?);
    let direction = body[45];
    let length_class = body[46];
    let validity = body[47];
    if reserved_id(observer) || reserved_id(peer) {
        return Err(HostOpsError::Invalid("snapshot endpoints"));
    }
    if direction != DIRECTION_EGRESS && direction != DIRECTION_INGRESS {
        return Err(HostOpsError::Invalid("snapshot direction"));
    }
    if length_class > 2 && length_class != LENGTH_CLASS_PEER_SUMMARY {
        return Err(HostOpsError::Invalid("snapshot length_class"));
    }
    if validity & SOURCE_LOCAL_DRIVER != 0 && validity & SOURCE_INJECTED_TEST != 0 {
        return Err(HostOpsError::Invalid("snapshot sources"));
    }
    Ok(TelemetrySnapshot {
        request_id: u32::from_be_bytes(be::<4>(body, 4)?),
        observer,
        observer_boot: u64::from_be_bytes(be::<8>(body, 16)?),
        peer,
        binding: u32::from_be_bytes(be::<4>(body, 32)?),
        radio: u32::from_be_bytes(be::<4>(body, 36)?),
        channel_epoch: u32::from_be_bytes(be::<4>(body, 40)?),
        channel: body[44],
        direction,
        length_class,
        validity,
        sampled_at_ms: u64::from_be_bytes(be::<8>(body, 48)?),
        window_ms: u32::from_be_bytes(be::<4>(body, 56)?),
        sample_age_ms: u32::from_be_bytes(be::<4>(body, 60)?),
        rssi_last: body[64] as i8,
        rssi_min: body[65] as i8,
        rssi_max: body[66] as i8,
        rssi_ewma_q8_8: i16::from_be_bytes(be::<2>(body, 68)?),
        rssi_samples: u32::from_be_bytes(be::<4>(body, 72)?),
        tx_submitted: u32::from_be_bytes(be::<4>(body, 76)?),
        tx_mac_success: u32::from_be_bytes(be::<4>(body, 80)?),
        tx_mac_fail: u32::from_be_bytes(be::<4>(body, 84)?),
        tx_unknown: u32::from_be_bytes(be::<4>(body, 88)?),
        sdk_retries: u32::from_be_bytes(be::<4>(body, 92)?),
        hop_accepts: u32::from_be_bytes(be::<4>(body, 96)?),
        hop_timeouts: u32::from_be_bytes(be::<4>(body, 100)?),
        busy: u32::from_be_bytes(be::<4>(body, 104)?),
        queue_us_ewma: u32::from_be_bytes(be::<4>(body, 108)?),
        driver_us_ewma: u32::from_be_bytes(be::<4>(body, 112)?),
        hop_rtt_us_ewma: u32::from_be_bytes(be::<4>(body, 116)?),
        event_drops: u32::from_be_bytes(be::<4>(body, 120)?),
        saturation_mask: u32::from_be_bytes(be::<4>(body, 124)?),
    })
}

/// DiagnosticReject reason (1..7 on the wire).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RejectReason {
    Unsupported = 1,
    Capacity = 2,
    Stale = 3,
    NoPeer = 4,
    NoBucket = 5,
    Denied = 6,
    Deadline = 7,
}

impl RejectReason {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unsupported => "UNSUPPORTED",
            Self::Capacity => "CAPACITY",
            Self::Stale => "STALE",
            Self::NoPeer => "NO_PEER",
            Self::NoBucket => "NO_BUCKET",
            Self::Denied => "DENIED",
            Self::Deadline => "DEADLINE",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticReject {
    pub request_id: u32,
    pub reason: RejectReason,
    pub observer: u64,
    pub detail: u32,
}

pub fn decode_diagnostic_reject(body: &[u8]) -> Result<DiagnosticReject, HostOpsError> {
    if body.len() != REJECT_BODY_SIZE {
        return Err(HostOpsError::LengthMismatch);
    }
    if body[0] != DIAG_BODY_VERSION
        || body[1] != DIAG_SUB_DIAGNOSTIC_REJECT
        || body[2] != 0
        || body[3] != 0
    {
        return Err(HostOpsError::Invalid("reject prefix"));
    }
    let request_id = u32::from_be_bytes(be::<4>(body, 4)?);
    let reason = u16::from_be_bytes(be::<2>(body, 8)?);
    let reserved = u16::from_be_bytes(be::<2>(body, 10)?);
    let observer = u64::from_be_bytes(be::<8>(body, 12)?);
    let detail = u32::from_be_bytes(be::<4>(body, 20)?);
    if request_id == 0 || reserved != 0 || reserved_id(observer) {
        return Err(HostOpsError::Invalid("reject fields"));
    }
    let reason = match reason {
        1 => RejectReason::Unsupported,
        2 => RejectReason::Capacity,
        3 => RejectReason::Stale,
        4 => RejectReason::NoPeer,
        5 => RejectReason::NoBucket,
        6 => RejectReason::Denied,
        7 => RejectReason::Deadline,
        _ => return Err(HostOpsError::Invalid("reject reason")),
    };
    Ok(DiagnosticReject {
        request_id,
        reason,
        observer,
        detail,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    // C++-encoded (`components/routeloom/src/telemetry.cpp`) oracle vectors.
    const QUERY_HEX: &str = "01030000a1b2c3d4000000112233445500ff0000000005dc";
    const SNAPSHOT_HEX: &str = "010400000000004d00000000000000c300000000deadbeef00000000000000050000000700000003000000010b00011300000000075bcd15000007d000000028c9b0ce00c40000000000000c00000064000000600000000300000001000000040000005f0000000200000001000004d20000162e000023340000000200000200";
    const REJECT_HEX: &str = "010600000000002a00040000000000000000009900000000";

    #[test]
    fn request_encodes_the_cpp_layout() {
        let inner = encode_diagnostic_request(
            0x0abc,
            &TelemetryQuery {
                request_id: 0xA1B2C3D4,
                peer: 0x1122334455,
                direction: DIRECTION_EGRESS,
                length_class: LENGTH_CLASS_PEER_SUMMARY,
                max_age_ms: 1500,
            },
        )
        .unwrap();
        let mut expect = vec![0x01, SUB_DIAGNOSTIC_REQUEST, 0x00, 0x20];
        expect.extend_from_slice(&0x0abc_u64.to_be_bytes());
        expect.extend_from_slice(&hex(QUERY_HEX));
        assert_eq!(inner, expect);
        // Encoder enforces the same bounds the device decodes.
        let bad = TelemetryQuery {
            request_id: 0,
            peer: 1,
            direction: DIRECTION_EGRESS,
            length_class: 0,
            max_age_ms: 0,
        };
        assert!(encode_diagnostic_request(0x0abc, &bad).is_err());
    }

    #[test]
    fn reply_and_snapshot_decode_the_cpp_vectors() {
        let mut inner = vec![0x01, SUB_DIAGNOSTIC_RESPONSE, 0x00, 0x8c, 0x00, 0x00];
        inner.extend_from_slice(&0x0abc_u64.to_be_bytes());
        inner.extend_from_slice(&128_u16.to_be_bytes());
        inner.extend_from_slice(&hex(SNAPSHOT_HEX));
        let reply = decode_diagnostic_reply(&inner).unwrap();
        assert_eq!(reply.result, ConfigOpsResult::Ok);
        assert_eq!(reply.observer, 0x0abc);
        let snapshot = decode_telemetry_snapshot(&reply.body).unwrap();
        assert_eq!(snapshot.request_id, 77);
        assert_eq!(snapshot.observer, 0xc3);
        assert_eq!(snapshot.observer_boot, 0xdeadbeef);
        assert_eq!(snapshot.peer, 0x05);
        assert_eq!(snapshot.binding, 7);
        assert_eq!(snapshot.radio, 3);
        assert_eq!(snapshot.channel_epoch, 1);
        assert_eq!(snapshot.channel, 11);
        assert_eq!(snapshot.direction, DIRECTION_EGRESS);
        assert_eq!(snapshot.length_class, 1);
        assert_eq!(
            snapshot.validity,
            VALID_RSSI | VALID_BUCKET | SOURCE_LOCAL_DRIVER
        );
        assert_eq!(snapshot.sampled_at_ms, 123456789);
        assert_eq!(snapshot.window_ms, 2000);
        assert_eq!(snapshot.sample_age_ms, 40);
        assert_eq!(snapshot.rssi_last, -55);
        assert_eq!(snapshot.rssi_min, -80);
        assert_eq!(snapshot.rssi_max, -50);
        assert_eq!(snapshot.rssi_ewma_q8_8, -60 * 256);
        assert_eq!(snapshot.rssi_samples, 12);
        assert_eq!(snapshot.tx_submitted, 100);
        assert_eq!(snapshot.tx_mac_success, 96);
        assert_eq!(snapshot.tx_mac_fail, 3);
        assert_eq!(snapshot.tx_unknown, 1);
        assert_eq!(snapshot.sdk_retries, 4);
        assert_eq!(snapshot.hop_accepts, 95);
        assert_eq!(snapshot.hop_timeouts, 2);
        assert_eq!(snapshot.busy, 1);
        assert_eq!(snapshot.queue_us_ewma, 1234);
        assert_eq!(snapshot.driver_us_ewma, 5678);
        assert_eq!(snapshot.hop_rtt_us_ewma, 9012);
        assert_eq!(snapshot.event_drops, 2);
        assert_eq!(snapshot.saturation_mask, SAT_EVENT_DROPS);
    }

    #[test]
    fn reject_decodes_and_reasons_have_names() {
        let mut inner = vec![0x01, SUB_DIAGNOSTIC_RESPONSE, 0x00, 0x24, 0x00, 0x00];
        inner.extend_from_slice(&0x0abc_u64.to_be_bytes());
        inner.extend_from_slice(&24_u16.to_be_bytes());
        inner.extend_from_slice(&hex(REJECT_HEX));
        let reply = decode_diagnostic_reply(&inner).unwrap();
        let reject = decode_diagnostic_reject(&reply.body).unwrap();
        assert_eq!(reject.request_id, 42);
        assert_eq!(reject.reason, RejectReason::NoPeer);
        assert_eq!(reject.reason.name(), "NO_PEER");
        assert_eq!(reject.observer, 0x99);
        // Non-Ok device results surface with an empty body.
        let mut busy = vec![0x01, SUB_DIAGNOSTIC_RESPONSE, 0x00, 0x0c, 0x00, 0x01];
        busy.extend_from_slice(&0x0abc_u64.to_be_bytes());
        busy.extend_from_slice(&0_u16.to_be_bytes());
        let reply = decode_diagnostic_reply(&busy).unwrap();
        assert_eq!(reply.result, ConfigOpsResult::Busy);
        assert!(reply.body.is_empty());
    }

    #[test]
    fn malformed_bodies_are_refused() {
        // Wrong schema / sub / short / trailing garbage.
        assert!(decode_diagnostic_reply(&[]).is_err());
        assert!(decode_diagnostic_reply(&[0x02, SUB_DIAGNOSTIC_RESPONSE, 0, 0]).is_err());
        assert!(decode_diagnostic_reply(&[0x01, SUB_DIAGNOSTIC_REQUEST, 0, 0]).is_err());
        // Snapshot with both source bits set (mutually exclusive).
        let mut bad = hex(SNAPSHOT_HEX);
        bad[47] |= SOURCE_INJECTED_TEST;
        assert!(decode_telemetry_snapshot(&bad).is_err());
        // Snapshot of the wrong size; reject of the wrong size.
        assert!(decode_telemetry_snapshot(&hex(SNAPSHOT_HEX)[..127]).is_err());
        assert!(decode_diagnostic_reject(&hex(REJECT_HEX)[..23]).is_err());
        // Reserved bytes must be zero.
        let mut bad = hex(SNAPSHOT_HEX);
        bad[67] = 1;
        assert!(decode_telemetry_snapshot(&bad).is_err());
    }
}
