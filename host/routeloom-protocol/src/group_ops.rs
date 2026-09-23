//! group_delivery_v1 HostOps codec (subcommands 0x50-0x52): ask the attached
//! gateway node to send a group/ALL message along its tree and read the
//! aggregated delivery summary. Byte-identical to the device side in
//! `components/routeloom/{include/routeloom/usb_host_ops.hpp,src/usb_host_ops.cpp}`;
//! the shared vectors under `protocol/usb-golden/group-ops` pin both.
//!
//! Inner common form (the gateway/config/node-status family shape):
//! schema:u8=1, sub:u8, payload_len:u16, payload — big-endian, exact length.
//!
//! A 0x50 GROUP_SEND is answered at once (same request id) with a 0x51
//! GROUP_STATUS carrying the admission outcome; an admitted message later
//! gets exactly one more 0x51 with the FINAL flag under the same request id
//! (session-scoped: after a reconnect the host polls 0x52 GROUP_QUERY).

use crate::host_ops::{ConfigOpsResult, HostOpsError, HOST_OPS_SCHEMA};

/// HelloAck capability bit: the device serves 0x50-0x52.
pub const CAP_GROUP_DELIVERY_V1: u32 = 1 << 7;

pub const SUB_GROUP_SEND: u8 = 0x50;
pub const SUB_GROUP_STATUS: u8 = 0x51;
pub const SUB_GROUP_QUERY: u8 = 0x52;

pub const INNER_HEAD_SIZE: usize = 4;
/// Group 0xFFFF addresses every node of the network.
pub const GROUP_ALL: u16 = 0xFFFF;
/// Top bit of a group MessageId sequence (the group stream space).
pub const GROUP_SEQUENCE_FLAG: u64 = 1 << 63;
/// Node ids at or above this value are group addresses, never devices.
pub const GROUP_ADDRESS_BASE: u64 = 0xFFFF_FFFF_FFFF_0000;
/// Application bytes per group message (128 B payload minus the flags byte).
pub const GROUP_PAYLOAD_MAX: usize = 127;
pub const GROUP_MISSING_MAX: usize = 12;
/// Device message lifetime ceiling (kMaxMessageLifetimeMs).
pub const MAX_LIFETIME_MS: u32 = 30_000;

pub const SEND_FIXED_PAYLOAD: usize = 12;
pub const SEND_MAX_PAYLOAD: usize = SEND_FIXED_PAYLOAD + GROUP_PAYLOAD_MAX;
pub const QUERY_PAYLOAD: usize = 12;
pub const STATUS_FIXED_PAYLOAD: usize = 30;
pub const STATUS_REASON_MAX: usize = 32;
pub const STATUS_MAX_PAYLOAD: usize =
    STATUS_FIXED_PAYLOAD + GROUP_MISSING_MAX * 8 + STATUS_REASON_MAX;

pub const SEND_ORDERED: u8 = 0x01;
pub const STATUS_TRUNCATED: u8 = 0x01;
pub const STATUS_FINAL: u8 = 0x02;

/// DeliveryState values (routeloom::DeliveryState) a summary can carry.
pub const STATE_EMPTY: u8 = 0;
pub const STATE_DELIVERED: u8 = 7;
pub const STATE_FAILED: u8 = 8;
pub const STATE_INDETERMINATE: u8 = 11;

/// True for the states a group summary never leaves (Delivered, Failed,
/// Expired, CancelledBeforeTx, Indeterminate).
pub const fn state_final(state: u8) -> bool {
    matches!(state, 7..=11)
}

const fn reserved_node_id(node: u64) -> bool {
    node == 0 || node >= GROUP_ADDRESS_BASE
}

/// The sub byte of a group inner body (0x50-0x52), if it is one.
pub fn group_ops_sub(inner: &[u8]) -> Option<u8> {
    if inner.len() < 2 || inner[0] != HOST_OPS_SCHEMA {
        return None;
    }
    matches!(
        inner[1],
        SUB_GROUP_SEND | SUB_GROUP_STATUS | SUB_GROUP_QUERY
    )
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

fn be<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], HostOpsError> {
    bytes
        .get(offset..offset + N)
        .ok_or(HostOpsError::Truncated)?
        .try_into()
        .map_err(|_| HostOpsError::Truncated)
}

/// 0x50 GROUP_SEND (H→G).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GroupSend {
    /// 1..=0xFFFF (GROUP_ALL = every node).
    pub group: u16,
    /// 0 Bulk, 1 Normal, 2 Management, 3 Urgent.
    pub priority: u8,
    /// In-order delivery at every receiver (bounded hold).
    pub ordered: bool,
    /// 1..=MAX_LIFETIME_MS.
    pub lifetime_ms: u32,
    /// 1..=254.
    pub hop_limit: u8,
    /// <= GROUP_PAYLOAD_MAX bytes.
    pub data: Vec<u8>,
}

fn check_send(send: &GroupSend) -> Result<(), HostOpsError> {
    if send.group == 0 {
        return Err(HostOpsError::Invalid("group"));
    }
    if send.priority > 3 {
        return Err(HostOpsError::Invalid("priority"));
    }
    if send.lifetime_ms == 0 || send.lifetime_ms > MAX_LIFETIME_MS {
        return Err(HostOpsError::Invalid("lifetime_ms"));
    }
    if send.hop_limit == 0 || send.hop_limit == u8::MAX {
        return Err(HostOpsError::Invalid("hop_limit"));
    }
    if send.data.len() > GROUP_PAYLOAD_MAX {
        return Err(HostOpsError::Invalid("data length"));
    }
    Ok(())
}

pub fn encode_group_send(send: &GroupSend) -> Result<Vec<u8>, HostOpsError> {
    check_send(send)?;
    let payload_len = SEND_FIXED_PAYLOAD + send.data.len();
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + payload_len);
    head(&mut out, SUB_GROUP_SEND, payload_len);
    out.extend_from_slice(&send.group.to_be_bytes());
    out.push(send.priority);
    out.push(if send.ordered { SEND_ORDERED } else { 0 });
    out.extend_from_slice(&send.lifetime_ms.to_be_bytes());
    out.push(send.hop_limit);
    out.push(0);
    out.extend_from_slice(&(send.data.len() as u16).to_be_bytes());
    out.extend_from_slice(&send.data);
    Ok(out)
}

pub fn decode_group_send(inner: &[u8]) -> Result<GroupSend, HostOpsError> {
    let payload = body(inner, SUB_GROUP_SEND, SEND_FIXED_PAYLOAD, SEND_MAX_PAYLOAD)?;
    let flags = payload[3];
    if flags & !SEND_ORDERED != 0 {
        return Err(HostOpsError::Invalid("send flags"));
    }
    if payload[9] != 0 {
        return Err(HostOpsError::Invalid("reserved"));
    }
    let data_len = usize::from(u16::from_be_bytes(be(payload, 10)?));
    if data_len != payload.len() - SEND_FIXED_PAYLOAD {
        return Err(HostOpsError::LengthMismatch);
    }
    let send = GroupSend {
        group: u16::from_be_bytes(be(payload, 0)?),
        priority: payload[2],
        ordered: flags & SEND_ORDERED != 0,
        lifetime_ms: u32::from_be_bytes(be(payload, 4)?),
        hop_limit: payload[8],
        data: payload[SEND_FIXED_PAYLOAD..].to_vec(),
    };
    check_send(&send)?;
    Ok(send)
}

/// 0x52 GROUP_QUERY (H→G): a group MessageId.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupQuery {
    pub session: u32,
    /// Must carry GROUP_SEQUENCE_FLAG.
    pub sequence: u64,
}

pub fn encode_group_query(query: &GroupQuery) -> Result<Vec<u8>, HostOpsError> {
    if query.sequence & GROUP_SEQUENCE_FLAG == 0 {
        return Err(HostOpsError::Invalid("group sequence"));
    }
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + QUERY_PAYLOAD);
    head(&mut out, SUB_GROUP_QUERY, QUERY_PAYLOAD);
    out.extend_from_slice(&query.session.to_be_bytes());
    out.extend_from_slice(&query.sequence.to_be_bytes());
    Ok(out)
}

pub fn decode_group_query(inner: &[u8]) -> Result<GroupQuery, HostOpsError> {
    let payload = body(inner, SUB_GROUP_QUERY, QUERY_PAYLOAD, QUERY_PAYLOAD)?;
    let query = GroupQuery {
        session: u32::from_be_bytes(be(payload, 0)?),
        sequence: u64::from_be_bytes(be(payload, 4)?),
    };
    if query.sequence & GROUP_SEQUENCE_FLAG == 0 {
        return Err(HostOpsError::Invalid("group sequence"));
    }
    Ok(query)
}

/// 0x51 GROUP_STATUS (G→H). The flags byte is derived from the fields (see
/// `flags()`), never stored: a decoder refuses a frame whose flags disagree.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GroupStatus {
    /// ConfigOpsResult (Ok / Unsupported / Busy / Invalid / Indeterminate).
    pub result: u16,
    pub session: u32,
    pub sequence: u64,
    pub group: u16,
    /// routeloom::DeliveryState (0 = unknown / reclaimed on an Ok answer).
    pub state: u8,
    pub rounds: u8,
    /// Nodes that accepted the message as a member of the group.
    pub delivered: u16,
    /// Nodes reached that are not members of the group.
    pub nonmember: u16,
    /// Tree nodes without a confirmation.
    pub missing_total: u16,
    /// Nodes the gateway knows that no report accounted for.
    pub unaccounted: u16,
    /// Up to GROUP_MISSING_MAX of the missing node ids.
    pub missing: Vec<u64>,
    /// Printable ASCII, <= STATUS_REASON_MAX bytes (e.g. "GROUP_COMPLETE").
    pub reason: String,
}

impl GroupStatus {
    pub fn truncated(&self) -> bool {
        usize::from(self.missing_total) > self.missing.len()
    }
    pub fn is_final(&self) -> bool {
        state_final(self.state)
    }
    pub fn flags(&self) -> u8 {
        (if self.truncated() {
            STATUS_TRUNCATED
        } else {
            0
        }) | (if self.is_final() { STATUS_FINAL } else { 0 })
    }

    fn validate(&self) -> Result<(), HostOpsError> {
        let result = ConfigOpsResult::try_from_u16(self.result)?;
        if self.state > STATE_INDETERMINATE {
            return Err(HostOpsError::UnknownEnum("state", self.state));
        }
        if self.missing.len() > GROUP_MISSING_MAX
            || self.missing.len() > usize::from(self.missing_total)
        {
            return Err(HostOpsError::Invalid("missing count"));
        }
        if self.reason.len() > STATUS_REASON_MAX
            || !self
                .reason
                .bytes()
                .all(|byte| (0x20..=0x7E).contains(&byte))
        {
            return Err(HostOpsError::Invalid("reason"));
        }
        if result != ConfigOpsResult::Ok
            && (self.session != 0
                || self.sequence != 0
                || self.state != STATE_EMPTY
                || self.rounds != 0
                || self.delivered != 0
                || self.nonmember != 0
                || self.missing_total != 0
                || self.unaccounted != 0)
        {
            return Err(HostOpsError::Invalid("refusal carries an id"));
        }
        if result == ConfigOpsResult::Ok && self.sequence & GROUP_SEQUENCE_FLAG == 0 {
            return Err(HostOpsError::Invalid("group sequence"));
        }
        if self.missing.iter().any(|&id| reserved_node_id(id)) {
            return Err(HostOpsError::Invalid("missing id"));
        }
        Ok(())
    }
}

pub fn encode_group_status(status: &GroupStatus) -> Result<Vec<u8>, HostOpsError> {
    status.validate()?;
    let payload_len = STATUS_FIXED_PAYLOAD + status.missing.len() * 8 + status.reason.len();
    let mut out = Vec::with_capacity(INNER_HEAD_SIZE + payload_len);
    head(&mut out, SUB_GROUP_STATUS, payload_len);
    out.extend_from_slice(&status.result.to_be_bytes());
    out.extend_from_slice(&status.session.to_be_bytes());
    out.extend_from_slice(&status.sequence.to_be_bytes());
    out.extend_from_slice(&status.group.to_be_bytes());
    out.push(status.state);
    out.push(status.rounds);
    out.extend_from_slice(&status.delivered.to_be_bytes());
    out.extend_from_slice(&status.nonmember.to_be_bytes());
    out.extend_from_slice(&status.missing_total.to_be_bytes());
    out.extend_from_slice(&status.unaccounted.to_be_bytes());
    out.push(status.flags());
    out.push(status.missing.len() as u8);
    out.push(status.reason.len() as u8);
    out.push(0);
    for id in &status.missing {
        out.extend_from_slice(&id.to_be_bytes());
    }
    out.extend_from_slice(status.reason.as_bytes());
    Ok(out)
}

pub fn decode_group_status(inner: &[u8]) -> Result<GroupStatus, HostOpsError> {
    let payload = body(
        inner,
        SUB_GROUP_STATUS,
        STATUS_FIXED_PAYLOAD,
        STATUS_MAX_PAYLOAD,
    )?;
    let flags = payload[26];
    let missing_count = usize::from(payload[27]);
    let reason_len = usize::from(payload[28]);
    if payload[29] != 0 {
        return Err(HostOpsError::Invalid("reserved"));
    }
    if missing_count > GROUP_MISSING_MAX || reason_len > STATUS_REASON_MAX {
        return Err(HostOpsError::Invalid("missing count"));
    }
    if payload.len() != STATUS_FIXED_PAYLOAD + missing_count * 8 + reason_len {
        return Err(HostOpsError::LengthMismatch);
    }
    let mut missing = Vec::with_capacity(missing_count);
    for index in 0..missing_count {
        missing.push(u64::from_be_bytes(be(
            payload,
            STATUS_FIXED_PAYLOAD + index * 8,
        )?));
    }
    let reason_start = STATUS_FIXED_PAYLOAD + missing_count * 8;
    let reason_bytes = &payload[reason_start..reason_start + reason_len];
    if !reason_bytes.iter().all(|byte| (0x20..=0x7E).contains(byte)) {
        return Err(HostOpsError::Invalid("reason"));
    }
    let status = GroupStatus {
        result: u16::from_be_bytes(be(payload, 0)?),
        session: u32::from_be_bytes(be(payload, 2)?),
        sequence: u64::from_be_bytes(be(payload, 6)?),
        group: u16::from_be_bytes(be(payload, 14)?),
        state: payload[16],
        rounds: payload[17],
        delivered: u16::from_be_bytes(be(payload, 18)?),
        nonmember: u16::from_be_bytes(be(payload, 20)?),
        missing_total: u16::from_be_bytes(be(payload, 22)?),
        unaccounted: u16::from_be_bytes(be(payload, 24)?),
        missing,
        reason: reason_bytes.iter().map(|&byte| char::from(byte)).collect(),
    };
    status.validate()?;
    if flags != status.flags() {
        return Err(HostOpsError::Invalid("status flags"));
    }
    Ok(status)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alarm() -> GroupSend {
        GroupSend {
            group: GROUP_ALL,
            priority: 3,
            ordered: false,
            lifetime_ms: 5000,
            hop_limit: 10,
            data: b"PUMP3 OVERTEMP".to_vec(),
        }
    }

    fn incomplete() -> GroupStatus {
        GroupStatus {
            result: ConfigOpsResult::Ok as u16,
            session: 7001,
            sequence: GROUP_SEQUENCE_FLAG | 3,
            group: 7,
            state: STATE_FAILED,
            rounds: 12,
            delivered: 80,
            nonmember: 3,
            missing_total: 16,
            unaccounted: 1,
            missing: vec![41, 42],
            reason: "GROUP_INCOMPLETE".to_string(),
        }
    }

    #[test]
    fn send_roundtrip_and_bounds() {
        let bytes = encode_group_send(&alarm()).unwrap();
        assert_eq!(bytes.len(), INNER_HEAD_SIZE + SEND_FIXED_PAYLOAD + 14);
        assert_eq!(group_ops_sub(&bytes), Some(SUB_GROUP_SEND));
        assert_eq!(decode_group_send(&bytes).unwrap(), alarm());
        for (offset, value) in [(6, 4_u8), (7, 2), (12, 0), (12, 0xFF), (13, 1), (15, 13)] {
            let mut copy = bytes.clone();
            copy[offset] = value;
            assert!(decode_group_send(&copy).is_err(), "offset {offset}");
        }
        let mut zero_group = bytes.clone();
        zero_group[4] = 0;
        zero_group[5] = 0;
        assert!(decode_group_send(&zero_group).is_err());
        let mut long = alarm();
        long.data = vec![0; GROUP_PAYLOAD_MAX + 1];
        assert!(encode_group_send(&long).is_err());
        long.data.pop();
        assert_eq!(
            encode_group_send(&long).unwrap().len(),
            INNER_HEAD_SIZE + SEND_MAX_PAYLOAD
        );
        let mut late = alarm();
        late.lifetime_ms = MAX_LIFETIME_MS + 1;
        assert!(encode_group_send(&late).is_err());
    }

    #[test]
    fn query_requires_group_sequence() {
        let query = GroupQuery {
            session: 7001,
            sequence: GROUP_SEQUENCE_FLAG | 3,
        };
        let bytes = encode_group_query(&query).unwrap();
        assert_eq!(decode_group_query(&bytes).unwrap(), query);
        assert!(encode_group_query(&GroupQuery {
            session: 7001,
            sequence: 3
        })
        .is_err());
    }

    #[test]
    fn status_flags_are_derived_and_checked() {
        let status = incomplete();
        assert_eq!(status.flags(), STATUS_TRUNCATED | STATUS_FINAL);
        let bytes = encode_group_status(&status).unwrap();
        assert_eq!(
            bytes.len(),
            INNER_HEAD_SIZE + STATUS_FIXED_PAYLOAD + 16 + 16
        );
        assert_eq!(decode_group_status(&bytes).unwrap(), status);
        let mut flags = bytes.clone();
        flags[4 + 26] = STATUS_FINAL;
        assert!(decode_group_status(&flags).is_err());
        let mut reserved = bytes.clone();
        reserved[4 + 29] = 1;
        assert!(decode_group_status(&reserved).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode_group_status(&trailing).is_err());
        let mut reason = bytes;
        let last = reason.len() - 1;
        reason[last] = 0x07;
        assert!(decode_group_status(&reason).is_err());
    }

    #[test]
    fn refusal_carries_no_id() {
        let refusal = GroupStatus {
            result: ConfigOpsResult::Busy as u16,
            group: 7,
            reason: "GROUP_QUEUE_FULL".to_string(),
            ..GroupStatus::default()
        };
        let bytes = encode_group_status(&refusal).unwrap();
        assert_eq!(decode_group_status(&bytes).unwrap(), refusal);
        let forged = GroupStatus {
            delivered: 1,
            ..refusal
        };
        assert!(encode_group_status(&forged).is_err());
        let reserved_id = GroupStatus {
            missing: vec![GROUP_ADDRESS_BASE | 7],
            ..incomplete()
        };
        assert!(encode_group_status(&reserved_id).is_err());
    }
}
