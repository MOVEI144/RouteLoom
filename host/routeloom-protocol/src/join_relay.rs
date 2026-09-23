//! join_relay_v1: the SDK v1 zero-touch join relay between a gateway and the
//! host's Site Authority (docs/design/sdk-v1/02-zero-touch-join.md §7, as
//! resolved in §7.4). Two layers, byte-identical to the device side:
//!
//! - the relay object a member proxy exchanges with the gateway over the
//!   Wire lane and the gateway hands to the host unchanged
//!   (`components/routeloom/{include/routeloom/sdkv1_join_transport.hpp,
//!   src/sdkv1_join_transport.cpp}`, vectors `protocol/sdkv1-golden/
//!   join-transport/`): RelayHeader 24 B + one EDHOC / RLRES1 message
//!   (<= 960 B) or a 5 B abort body;
//! - the USB HostOps subcommands 0x60-0x63 that carry it
//!   (`components/routeloom/src/usb_host_ops.cpp`, session vectors
//!   `protocol/usb-golden/join-relay/`).
//!
//! The design proposed 0x40-0x42 and capability bit 6, which node_status_v1
//! owns; the SDK v1 site-authority family uses 0x60-0x6F and bit 8.
//!
//! Inner common form: schema:u8=1, sub:u8, payload_len:u16, payload —
//! big-endian, exact length.
//! - 0x60 JOIN_RELAY_UP (G→H, request id 0): gateway u64, from_proxy u64,
//!   hops u8 (1..=254; 0 only for the gateway's own join, from_proxy ==
//!   gateway), relay object with dir = up and proxy == from_proxy.
//! - 0x61 JOIN_RELAY_DOWN (H→G): to_proxy u64, relay object with dir = down
//!   and proxy == to_proxy. Answered by 0x63.
//! - 0x62 JOIN_RELAY_ABORT: proxy u64, relay_id u32 (nonzero), reason u8
//!   (1 proxy_aborted, 2 gateway_expired, 3 delivery_failed, 4 host_aborted).
//!   H→G (reason 4) is answered by 0x63; G→H arrives with request id 0.
//! - 0x63 JOIN_RELAY_RESULT (G→H, the 0x61/0x62 request id): result u16
//!   (ConfigOpsResult; Ok = handed to the Wire lane, not delivered to the
//!   device), proxy u64, relay_id u32.

use crate::host_ops::{ConfigOpsResult, HostOpsError, HOST_OPS_SCHEMA};

/// HelloAck capability bit: the device serves 0x60-0x63.
pub const CAP_JOIN_RELAY_V1: u32 = 1 << 8;

pub const SUB_JOIN_RELAY_UP: u8 = 0x60;
pub const SUB_JOIN_RELAY_DOWN: u8 = 0x61;
pub const SUB_JOIN_RELAY_ABORT: u8 = 0x62;
pub const SUB_JOIN_RELAY_RESULT: u8 = 0x63;

pub const INNER_HEAD_SIZE: usize = 4;
pub const RELAY_VERSION: u8 = 1;
pub const RELAY_HEADER_SIZE: usize = 24;
pub const RELAY_ABORT_BODY_SIZE: usize = 5;
/// One EDHOC / RLRES1 message (02 §7.4).
pub const JOIN_MESSAGE_MAX: usize = 960;
pub const RELAY_OBJECT_MAX: usize = RELAY_HEADER_SIZE + JOIN_MESSAGE_MAX; // 984
pub const RETRY_AFTER_MAX_MS: u32 = 600_000;
/// Wire payload budget: larger relay objects are chunked on the Wire lane.
pub const WIRE_PAYLOAD_MAX: usize = 128;

pub const UP_FIXED_PAYLOAD: usize = 17;
pub const DOWN_FIXED_PAYLOAD: usize = 8;
pub const ABORT_PAYLOAD: usize = 13;
pub const RESULT_PAYLOAD: usize = 14;
pub const UP_MAX_PAYLOAD: usize = UP_FIXED_PAYLOAD + RELAY_OBJECT_MAX;
pub const DOWN_MAX_PAYLOAD: usize = DOWN_FIXED_PAYLOAD + RELAY_OBJECT_MAX;
pub const HOPS_MAX: u8 = 254;

/// BootstrapAuth phases a relay object can carry.
pub const PHASE_EDHOC: u8 = 4;
pub const PHASE_RESUME: u8 = 5;
/// EDHOC error message step.
pub const EDHOC_ERROR_STEP: u8 = 5;

/// Wire FrameTypes of the relay lane.
pub const WIRE_TYPE_BOOTSTRAP_AUTH: u8 = 3;
pub const WIRE_TYPE_MEMBERSHIP_RESULT: u8 = 4;
pub const WIRE_TYPE_BOOTSTRAP_CHUNK: u8 = 5;
pub const WIRE_TYPE_BOOTSTRAP_REPLY: u8 = 6;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelayDirection {
    Up = 1,
    Down = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelayState {
    /// More messages follow.
    Continue = 0,
    /// Down only: the last message of the exchange; the proxy frees its slot.
    Final = 1,
    /// Either way: the body is an abort (status, retry hint).
    Abort = 2,
}

/// The unauthenticated hint the proxy passes to the device (02 §5.3 phase 6).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelayStatusCode {
    Queued = 1,
    AuthorityUnreachable = 2,
    Busy = 3,
    Aborted = 4,
}

/// Why a relay ended without an answer (0x62 reason).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RelayAbortReason {
    ProxyAborted = 1,
    GatewayExpired = 2,
    DeliveryFailed = 3,
    HostAborted = 4,
}

impl RelayAbortReason {
    pub fn try_from_u8(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            1 => Self::ProxyAborted,
            2 => Self::GatewayExpired,
            3 => Self::DeliveryFailed,
            4 => Self::HostAborted,
            other => return Err(HostOpsError::UnknownEnum("relay abort reason", other)),
        })
    }
}

impl RelayStatusCode {
    fn try_from_u8(value: u8) -> Result<Self, HostOpsError> {
        Ok(match value {
            1 => Self::Queued,
            2 => Self::AuthorityUnreachable,
            3 => Self::Busy,
            4 => Self::Aborted,
            other => return Err(HostOpsError::UnknownEnum("relay status", other)),
        })
    }
}

/// RelayHeader (24 B): ver u8 = 1 | dir u8 | relay_id u32 | proxy u64 |
/// joiner MAC 6 B | step u8 | state u8 | joiner_rssi_dbm i8 | phase u8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayHeader {
    pub dir: RelayDirection,
    /// Chosen by the proxy, nonzero, unique within the proxy.
    pub relay_id: u32,
    pub proxy: u64,
    /// The joiner's radio address as the proxy observed it (unicast).
    pub joiner_mac: [u8; 6],
    /// 4 EDHOC (steps 1..=5, 5 = error), 5 RLRES1 (steps 1..=3).
    pub phase: u8,
    pub step: u8,
    pub state: RelayState,
    /// Up objects only (<= 0 dBm, display hint); 0 on down objects.
    pub joiner_rssi_dbm: i8,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RelayBody {
    /// Continue / Final: one EDHOC or RLRES1 message, 1..=960 B.
    Message(Vec<u8>),
    /// Abort: up objects carry Aborted; down objects AuthorityUnreachable,
    /// Busy or Aborted.
    Abort {
        status: RelayStatusCode,
        retry_after_ms: u32,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayObject {
    pub header: RelayHeader,
    pub body: RelayBody,
}

fn node_valid(node: u64) -> bool {
    node != 0 && node != u64::MAX
}

fn step_valid(phase: u8, step: u8) -> bool {
    match phase {
        PHASE_EDHOC => (1..=EDHOC_ERROR_STEP).contains(&step),
        PHASE_RESUME => (1..=3).contains(&step),
        _ => false,
    }
}

/// True when the step flows device -> authority (or either way: EDHOC error).
fn step_may_go_up(phase: u8, step: u8) -> bool {
    match phase {
        PHASE_EDHOC => step % 2 == 1,
        PHASE_RESUME => step != 2,
        _ => false,
    }
}

fn invalid<T>(what: &'static str) -> Result<T, HostOpsError> {
    Err(HostOpsError::Invalid(what))
}

impl RelayObject {
    /// The device-side rules (sdkv1_join_transport.hpp relay_object_validate).
    pub fn validate(&self) -> Result<(), HostOpsError> {
        let h = &self.header;
        if h.relay_id == 0 || !node_valid(h.proxy) {
            return invalid("relay identity");
        }
        if h.joiner_mac == [0; 6] || h.joiner_mac[0] & 1 != 0 {
            return invalid("relay joiner mac");
        }
        if !step_valid(h.phase, h.step) {
            return invalid("relay step");
        }
        let up = h.dir == RelayDirection::Up;
        if (up && h.joiner_rssi_dbm > 0) || (!up && h.joiner_rssi_dbm != 0) {
            return invalid("relay rssi");
        }
        let edhoc = h.phase == PHASE_EDHOC;
        match h.state {
            RelayState::Continue => {
                if up && !step_may_go_up(h.phase, h.step) {
                    return invalid("relay up step");
                }
                if !up && h.step != 2 {
                    return invalid("relay down step");
                }
            }
            RelayState::Final => {
                let final_ok = if edhoc {
                    h.step == 4 || h.step == EDHOC_ERROR_STEP
                } else {
                    h.step == 2
                };
                if up || !final_ok {
                    return invalid("relay final");
                }
            }
            RelayState::Abort => {}
        }
        match (&self.body, h.state) {
            (
                RelayBody::Abort {
                    status,
                    retry_after_ms,
                },
                RelayState::Abort,
            ) => {
                let status_ok = if up {
                    *status == RelayStatusCode::Aborted
                } else {
                    *status != RelayStatusCode::Queued
                };
                if !status_ok || *retry_after_ms > RETRY_AFTER_MAX_MS {
                    return invalid("relay abort body");
                }
            }
            (RelayBody::Message(message), RelayState::Continue | RelayState::Final) => {
                if message.is_empty() || message.len() > JOIN_MESSAGE_MAX {
                    return invalid("relay message size");
                }
            }
            _ => return invalid("relay body"),
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, HostOpsError> {
        self.validate()?;
        let h = &self.header;
        let mut out = Vec::with_capacity(RELAY_HEADER_SIZE + JOIN_MESSAGE_MAX);
        out.push(RELAY_VERSION);
        out.push(h.dir as u8);
        out.extend_from_slice(&h.relay_id.to_be_bytes());
        out.extend_from_slice(&h.proxy.to_be_bytes());
        out.extend_from_slice(&h.joiner_mac);
        out.push(h.step);
        out.push(h.state as u8);
        out.extend_from_slice(&h.joiner_rssi_dbm.to_be_bytes());
        out.push(h.phase);
        match &self.body {
            RelayBody::Message(message) => out.extend_from_slice(message),
            RelayBody::Abort {
                status,
                retry_after_ms,
            } => {
                out.push(*status as u8);
                out.extend_from_slice(&retry_after_ms.to_be_bytes());
            }
        }
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, HostOpsError> {
        if bytes.len() <= RELAY_HEADER_SIZE || bytes.len() > RELAY_OBJECT_MAX {
            return Err(HostOpsError::LengthMismatch);
        }
        if bytes[0] != RELAY_VERSION {
            return invalid("relay version");
        }
        let dir = match bytes[1] {
            1 => RelayDirection::Up,
            2 => RelayDirection::Down,
            other => return Err(HostOpsError::UnknownEnum("relay direction", other)),
        };
        let state = match bytes[21] {
            0 => RelayState::Continue,
            1 => RelayState::Final,
            2 => RelayState::Abort,
            other => return Err(HostOpsError::UnknownEnum("relay state", other)),
        };
        let phase = bytes[23];
        if phase != PHASE_EDHOC && phase != PHASE_RESUME {
            return Err(HostOpsError::UnknownEnum("relay phase", phase));
        }
        let header = RelayHeader {
            dir,
            relay_id: u32::from_be_bytes(bytes[2..6].try_into().expect("4")),
            proxy: u64::from_be_bytes(bytes[6..14].try_into().expect("8")),
            joiner_mac: bytes[14..20].try_into().expect("6"),
            phase,
            step: bytes[20],
            state,
            joiner_rssi_dbm: i8::from_be_bytes([bytes[22]]),
        };
        let rest = &bytes[RELAY_HEADER_SIZE..];
        let body = if state == RelayState::Abort {
            if rest.len() != RELAY_ABORT_BODY_SIZE {
                return Err(HostOpsError::LengthMismatch);
            }
            RelayBody::Abort {
                status: RelayStatusCode::try_from_u8(rest[0])?,
                retry_after_ms: u32::from_be_bytes(rest[1..5].try_into().expect("4")),
            }
        } else {
            RelayBody::Message(rest.to_vec())
        };
        let object = Self { header, body };
        object.validate()?;
        Ok(object)
    }

    /// The Wire FrameType of a single-frame object (<= 128 B): down
    /// Final/Abort ride 4 (MembershipResult), everything else 3.
    pub fn single_frame_type(&self) -> u8 {
        if self.header.dir == RelayDirection::Down && self.header.state != RelayState::Continue {
            WIRE_TYPE_MEMBERSHIP_RESULT
        } else {
            WIRE_TYPE_BOOTSTRAP_AUTH
        }
    }
}

/// Checks a single-frame Wire relay payload against its FrameType.
pub fn decode_single_frame(wire_type: u8, payload: &[u8]) -> Result<RelayObject, HostOpsError> {
    if payload.len() > WIRE_PAYLOAD_MAX {
        return Err(HostOpsError::LengthMismatch);
    }
    let object = RelayObject::decode(payload)?;
    if object.single_frame_type() != wire_type {
        return invalid("relay frame type");
    }
    Ok(object)
}

// --- USB HostOps 0x60-0x63 ------------------------------------------------------

/// The sub byte of a join relay inner body (0x60-0x63), if it is one.
pub fn join_relay_sub(inner: &[u8]) -> Option<u8> {
    if inner.len() < 2 || inner[0] != HOST_OPS_SCHEMA {
        return None;
    }
    (SUB_JOIN_RELAY_UP..=SUB_JOIN_RELAY_RESULT)
        .contains(&inner[1])
        .then_some(inner[1])
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

fn be_u64(bytes: &[u8]) -> u64 {
    u64::from_be_bytes(bytes[..8].try_into().expect("8"))
}

fn relay_object_for(
    object: &[u8],
    dir: RelayDirection,
    proxy: u64,
) -> Result<RelayObject, HostOpsError> {
    let decoded = RelayObject::decode(object)?;
    if decoded.header.dir != dir || decoded.header.proxy != proxy {
        return invalid("relay object header");
    }
    Ok(decoded)
}

/// 0x60 JOIN_RELAY_UP (G→H).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinRelayUp {
    pub gateway: u64,
    pub from_proxy: u64,
    pub hops: u8,
    /// Raw relay object bytes (forwarded to the Site Authority unchanged).
    pub object: Vec<u8>,
}

impl JoinRelayUp {
    fn check(&self) -> Result<RelayObject, HostOpsError> {
        if !node_valid(self.gateway)
            || !node_valid(self.from_proxy)
            || self.hops > HOPS_MAX
            || (self.hops == 0) != (self.from_proxy == self.gateway)
        {
            return invalid("join relay up");
        }
        relay_object_for(&self.object, RelayDirection::Up, self.from_proxy)
    }

    /// The decoded relay object (validated).
    pub fn relay_object(&self) -> Result<RelayObject, HostOpsError> {
        self.check()
    }
}

pub fn encode_join_relay_up(up: &JoinRelayUp) -> Result<Vec<u8>, HostOpsError> {
    up.check()?;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + UP_FIXED_PAYLOAD + up.object.len());
    head(
        &mut out,
        SUB_JOIN_RELAY_UP,
        UP_FIXED_PAYLOAD + up.object.len(),
    );
    out.extend_from_slice(&up.gateway.to_be_bytes());
    out.extend_from_slice(&up.from_proxy.to_be_bytes());
    out.push(up.hops);
    out.extend_from_slice(&up.object);
    Ok(out)
}

pub fn decode_join_relay_up(inner: &[u8]) -> Result<JoinRelayUp, HostOpsError> {
    let payload = body(
        inner,
        SUB_JOIN_RELAY_UP,
        UP_FIXED_PAYLOAD + 1,
        UP_MAX_PAYLOAD,
    )?;
    let up = JoinRelayUp {
        gateway: be_u64(&payload[0..8]),
        from_proxy: be_u64(&payload[8..16]),
        hops: payload[16],
        object: payload[UP_FIXED_PAYLOAD..].to_vec(),
    };
    up.check()?;
    Ok(up)
}

/// 0x61 JOIN_RELAY_DOWN (H→G).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinRelayDown {
    pub to_proxy: u64,
    pub object: Vec<u8>,
}

pub fn encode_join_relay_down(down: &JoinRelayDown) -> Result<Vec<u8>, HostOpsError> {
    if !node_valid(down.to_proxy) {
        return invalid("join relay down");
    }
    relay_object_for(&down.object, RelayDirection::Down, down.to_proxy)?;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + DOWN_FIXED_PAYLOAD + down.object.len());
    head(
        &mut out,
        SUB_JOIN_RELAY_DOWN,
        DOWN_FIXED_PAYLOAD + down.object.len(),
    );
    out.extend_from_slice(&down.to_proxy.to_be_bytes());
    out.extend_from_slice(&down.object);
    Ok(out)
}

pub fn decode_join_relay_down(inner: &[u8]) -> Result<JoinRelayDown, HostOpsError> {
    let payload = body(
        inner,
        SUB_JOIN_RELAY_DOWN,
        DOWN_FIXED_PAYLOAD + 1,
        DOWN_MAX_PAYLOAD,
    )?;
    let down = JoinRelayDown {
        to_proxy: be_u64(&payload[0..8]),
        object: payload[DOWN_FIXED_PAYLOAD..].to_vec(),
    };
    if !node_valid(down.to_proxy) {
        return invalid("join relay down");
    }
    relay_object_for(&down.object, RelayDirection::Down, down.to_proxy)?;
    Ok(down)
}

/// 0x62 JOIN_RELAY_ABORT (H→G request or G→H notice).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinRelayAbort {
    pub proxy: u64,
    pub relay_id: u32,
    pub reason: RelayAbortReason,
}

pub fn encode_join_relay_abort(abort: &JoinRelayAbort) -> Result<Vec<u8>, HostOpsError> {
    if !node_valid(abort.proxy) || abort.relay_id == 0 {
        return invalid("join relay abort");
    }
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + ABORT_PAYLOAD);
    head(&mut out, SUB_JOIN_RELAY_ABORT, ABORT_PAYLOAD);
    out.extend_from_slice(&abort.proxy.to_be_bytes());
    out.extend_from_slice(&abort.relay_id.to_be_bytes());
    out.push(abort.reason as u8);
    Ok(out)
}

pub fn decode_join_relay_abort(inner: &[u8]) -> Result<JoinRelayAbort, HostOpsError> {
    let payload = body(inner, SUB_JOIN_RELAY_ABORT, ABORT_PAYLOAD, ABORT_PAYLOAD)?;
    let abort = JoinRelayAbort {
        proxy: be_u64(&payload[0..8]),
        relay_id: u32::from_be_bytes(payload[8..12].try_into().expect("4")),
        reason: RelayAbortReason::try_from_u8(payload[12])?,
    };
    if !node_valid(abort.proxy) || abort.relay_id == 0 {
        return invalid("join relay abort");
    }
    Ok(abort)
}

/// 0x63 JOIN_RELAY_RESULT (G→H).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinRelayResult {
    pub result: ConfigOpsResult,
    pub proxy: u64,
    pub relay_id: u32,
}

fn result_known(result: ConfigOpsResult) -> bool {
    !matches!(result, ConfigOpsResult::Timeout)
}

fn check_result(result: &JoinRelayResult) -> Result<(), HostOpsError> {
    let ok = result.result == ConfigOpsResult::Ok;
    if !result_known(result.result)
        || result.proxy == u64::MAX
        || (ok && (!node_valid(result.proxy) || result.relay_id == 0))
    {
        return invalid("join relay result");
    }
    Ok(())
}

pub fn encode_join_relay_result(result: &JoinRelayResult) -> Result<Vec<u8>, HostOpsError> {
    check_result(result)?;
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + RESULT_PAYLOAD);
    head(&mut out, SUB_JOIN_RELAY_RESULT, RESULT_PAYLOAD);
    out.extend_from_slice(&(result.result as u16).to_be_bytes());
    out.extend_from_slice(&result.proxy.to_be_bytes());
    out.extend_from_slice(&result.relay_id.to_be_bytes());
    Ok(out)
}

pub fn decode_join_relay_result(inner: &[u8]) -> Result<JoinRelayResult, HostOpsError> {
    let payload = body(inner, SUB_JOIN_RELAY_RESULT, RESULT_PAYLOAD, RESULT_PAYLOAD)?;
    let result = JoinRelayResult {
        result: ConfigOpsResult::try_from_u16(u16::from_be_bytes([payload[0], payload[1]]))?,
        proxy: be_u64(&payload[2..10]),
        relay_id: u32::from_be_bytes(payload[10..14].try_into().expect("4")),
    };
    check_result(&result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn up_object(message: Vec<u8>) -> RelayObject {
        RelayObject {
            header: RelayHeader {
                dir: RelayDirection::Up,
                relay_id: 9,
                proxy: 2,
                joiner_mac: [2, 0, 0, 0, 0x12, 0x34],
                phase: PHASE_EDHOC,
                step: 1,
                state: RelayState::Continue,
                joiner_rssi_dbm: -70,
            },
            body: RelayBody::Message(message),
        }
    }

    #[test]
    fn relay_object_round_trips_and_refuses_bad_shapes() {
        let object = up_object(vec![7; 59]);
        let bytes = object.encode().unwrap();
        assert_eq!(bytes.len(), RELAY_HEADER_SIZE + 59);
        assert_eq!(RelayObject::decode(&bytes).unwrap(), object);
        assert_eq!(object.single_frame_type(), WIRE_TYPE_BOOTSTRAP_AUTH);
        let mut bad = object.clone();
        bad.header.step = 2; // m2 does not flow up
        assert!(bad.encode().is_err());
        let mut big = object.clone();
        big.body = RelayBody::Message(vec![0; JOIN_MESSAGE_MAX + 1]);
        assert!(big.encode().is_err());
        assert!(RelayObject::decode(&bytes[..RELAY_HEADER_SIZE]).is_err());
    }

    #[test]
    fn usb_bodies_round_trip() {
        let object = up_object(vec![1, 2, 3]).encode().unwrap();
        let up = JoinRelayUp {
            gateway: 1,
            from_proxy: 2,
            hops: 3,
            object,
        };
        let inner = encode_join_relay_up(&up).unwrap();
        assert_eq!(join_relay_sub(&inner), Some(SUB_JOIN_RELAY_UP));
        assert_eq!(decode_join_relay_up(&inner).unwrap(), up);
        // hops 0 only for the gateway's own join
        let mut own = up.clone();
        own.hops = 0;
        assert!(encode_join_relay_up(&own).is_err());
        let abort = JoinRelayAbort {
            proxy: 2,
            relay_id: 9,
            reason: RelayAbortReason::HostAborted,
        };
        let inner = encode_join_relay_abort(&abort).unwrap();
        assert_eq!(decode_join_relay_abort(&inner).unwrap(), abort);
        let result = JoinRelayResult {
            result: ConfigOpsResult::Unsupported,
            proxy: 0,
            relay_id: 0,
        };
        let inner = encode_join_relay_result(&result).unwrap();
        assert_eq!(decode_join_relay_result(&inner).unwrap(), result);
        let ok_without_id = JoinRelayResult {
            result: ConfigOpsResult::Ok,
            proxy: 2,
            relay_id: 0,
        };
        assert!(encode_join_relay_result(&ok_without_id).is_err());
    }
}
