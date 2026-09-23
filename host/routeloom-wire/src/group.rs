//! Group delivery payload codecs — byte-for-byte mirror of
//! `components/routeloom/include/routeloom/group.hpp` / `src/group.cpp`
//! (docs/design/sdk-v1/group-delivery.md, docs/spec/wire-protocol.md).
//!
//! * GROUP_DATA (type 25) destination = group address
//!   `GROUP_ADDRESS_BASE | group_id`; MessageId sequence =
//!   `GROUP_SEQUENCE_FLAG | stream number`; end-protected payload =
//!   `flags u8 || application bytes (<= 127)`.
//! * GROUP_REPORT (type 26), link-only, one hop:
//!   `source u64 | session u32 | sequence u64 | round u8 | flags u8 |
//!   delivered u16 | nonmember u16 | missing_total u16 | missing_count u8 |
//!   missing ids (missing_count x u64, <= 12)`.

use crate::{ErrorCode, MessageId, Result, WireError, INVALID_NODE_ID, MAX_APPLICATION_PAYLOAD};

pub const GROUP_ALL: u16 = 0xFFFF;
pub const GROUP_ADDRESS_BASE: u64 = 0xFFFF_FFFF_FFFF_0000;
pub const GROUP_SEQUENCE_FLAG: u64 = 1 << 63;

pub const GROUP_DATA_HEADER_BYTES: usize = 1;
pub const GROUP_PAYLOAD_MAX: usize = MAX_APPLICATION_PAYLOAD - GROUP_DATA_HEADER_BYTES;
pub const GROUP_FLAG_ORDERED: u8 = 0x01;
pub const GROUP_PRIORITY_SHIFT: u8 = 1;
pub const GROUP_PRIORITY_MASK: u8 = 0x06;

pub const GROUP_REPORT_FIXED_BYTES: usize = 29;
pub const GROUP_REPORT_MISSING_MAX: usize = 12;
pub const GROUP_REPORT_NOT_CHILD: u8 = 0x01;
pub const GROUP_REPORT_TRUNCATED: u8 = 0x02;

const _: () = assert!(GROUP_PAYLOAD_MAX == 127);
const _: () =
    assert!(GROUP_REPORT_FIXED_BYTES + GROUP_REPORT_MISSING_MAX * 8 <= MAX_APPLICATION_PAYLOAD);

pub const fn group_address(group: u16) -> u64 {
    GROUP_ADDRESS_BASE | group as u64
}

/// Group 0 is reserved: its address (the base itself) is not a group address.
pub const fn is_group_address(node: u64) -> bool {
    node > GROUP_ADDRESS_BASE
}

/// Node ids a device may never carry: invalid and the group namespace.
pub const fn reserved_node_id(node: u64) -> bool {
    node == INVALID_NODE_ID || node >= GROUP_ADDRESS_BASE
}

pub const fn is_group_sequence(sequence: u64) -> bool {
    let stream = sequence & !GROUP_SEQUENCE_FLAG;
    sequence & GROUP_SEQUENCE_FLAG != 0 && stream != 0 && stream <= u32::MAX as u64
}

fn protocol(detail: &'static str) -> WireError {
    WireError::new(ErrorCode::ProtocolError, detail)
}

/// GROUP_DATA end-protected payload header.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GroupDataHeader {
    pub ordered: bool,
    /// Priority class 0 Bulk, 1 Normal, 2 Management, 3 Urgent.
    pub priority: u8,
}

pub fn encode_group_data(header: &GroupDataHeader, app: &[u8]) -> Result<Vec<u8>> {
    if app.len() > GROUP_PAYLOAD_MAX || header.priority > 3 {
        return Err(WireError::new(
            ErrorCode::InvalidArgument,
            "invalid group payload",
        ));
    }
    let mut out = Vec::with_capacity(GROUP_DATA_HEADER_BYTES + app.len());
    let ordered = if header.ordered {
        GROUP_FLAG_ORDERED
    } else {
        0
    };
    out.push(ordered | (header.priority << GROUP_PRIORITY_SHIFT));
    out.extend_from_slice(app);
    Ok(out)
}

pub fn decode_group_data(input: &[u8]) -> Result<(GroupDataHeader, &[u8])> {
    if input.is_empty() || input.len() > MAX_APPLICATION_PAYLOAD {
        return Err(protocol("group payload length"));
    }
    let flags = input[0];
    if flags & !(GROUP_FLAG_ORDERED | GROUP_PRIORITY_MASK) != 0 {
        return Err(protocol("group payload flags"));
    }
    Ok((
        GroupDataHeader {
            ordered: flags & GROUP_FLAG_ORDERED != 0,
            priority: (flags & GROUP_PRIORITY_MASK) >> GROUP_PRIORITY_SHIFT,
        },
        &input[GROUP_DATA_HEADER_BYTES..],
    ))
}

/// GROUP_REPORT payload.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct GroupReport {
    pub source: u64,
    pub message: MessageId,
    pub round: u8,
    pub flags: u8,
    pub delivered: u16,
    pub nonmember: u16,
    pub missing_total: u16,
    pub missing: Vec<u64>,
}

fn check_report(report: &GroupReport) -> Result<()> {
    if reserved_node_id(report.source) || !is_group_sequence(report.message.sequence) {
        return Err(protocol("group report message"));
    }
    if report.flags & !(GROUP_REPORT_NOT_CHILD | GROUP_REPORT_TRUNCATED) != 0
        || report.missing.len() > GROUP_REPORT_MISSING_MAX
        || report.missing.len() > usize::from(report.missing_total)
    {
        return Err(protocol("group report flags"));
    }
    let truncated = report.flags & GROUP_REPORT_TRUNCATED != 0;
    if truncated != (usize::from(report.missing_total) > report.missing.len()) {
        return Err(protocol("group report truncation"));
    }
    if report.flags & GROUP_REPORT_NOT_CHILD != 0
        && (report.delivered != 0 || report.nonmember != 0 || report.missing_total != 0)
    {
        return Err(protocol("group report not-child counts"));
    }
    if report.missing.iter().any(|id| reserved_node_id(*id)) {
        return Err(protocol("group report missing id"));
    }
    Ok(())
}

pub fn encode_group_report(report: &GroupReport) -> Result<Vec<u8>> {
    check_report(report).map_err(|e| WireError::new(ErrorCode::InvalidArgument, e.detail))?;
    let mut out = Vec::with_capacity(GROUP_REPORT_FIXED_BYTES + 8 * report.missing.len());
    out.extend_from_slice(&report.source.to_be_bytes());
    out.extend_from_slice(&report.message.session.to_be_bytes());
    out.extend_from_slice(&report.message.sequence.to_be_bytes());
    out.push(report.round);
    out.push(report.flags);
    out.extend_from_slice(&report.delivered.to_be_bytes());
    out.extend_from_slice(&report.nonmember.to_be_bytes());
    out.extend_from_slice(&report.missing_total.to_be_bytes());
    out.push(report.missing.len() as u8);
    for id in &report.missing {
        out.extend_from_slice(&id.to_be_bytes());
    }
    Ok(out)
}

pub fn decode_group_report(input: &[u8]) -> Result<GroupReport> {
    if input.len() < GROUP_REPORT_FIXED_BYTES {
        return Err(protocol("group report length"));
    }
    let u16_at = |at: usize| u16::from_be_bytes([input[at], input[at + 1]]);
    let u64_at =
        |at: usize| u64::from_be_bytes(input[at..at + 8].try_into().expect("fixed length"));
    let count = usize::from(input[28]);
    if count > GROUP_REPORT_MISSING_MAX || input.len() != GROUP_REPORT_FIXED_BYTES + 8 * count {
        return Err(protocol("group report length"));
    }
    let report = GroupReport {
        source: u64_at(0),
        message: MessageId {
            session: u32::from_be_bytes(input[8..12].try_into().expect("fixed length")),
            sequence: u64_at(12),
        },
        round: input[20],
        flags: input[21],
        delivered: u16_at(22),
        nonmember: u16_at(24),
        missing_total: u16_at(26),
        missing: (0..count)
            .map(|i| u64_at(GROUP_REPORT_FIXED_BYTES + 8 * i))
            .collect(),
    };
    check_report(&report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn report() -> GroupReport {
        GroupReport {
            source: 1,
            message: MessageId {
                session: 101,
                sequence: GROUP_SEQUENCE_FLAG | 7,
            },
            round: 1,
            flags: GROUP_REPORT_TRUNCATED,
            delivered: 40,
            nonmember: 3,
            missing_total: 5,
            missing: vec![11, 12],
        }
    }

    #[test]
    fn addresses() {
        assert_eq!(group_address(GROUP_ALL), crate::BROADCAST_NODE_ID);
        assert!(is_group_address(group_address(1)));
        assert!(!is_group_address(GROUP_ADDRESS_BASE));
        assert!(reserved_node_id(GROUP_ADDRESS_BASE));
        assert!(!reserved_node_id(GROUP_ADDRESS_BASE - 1));
        assert!(is_group_sequence(GROUP_SEQUENCE_FLAG | 1));
        assert!(!is_group_sequence(GROUP_SEQUENCE_FLAG));
        assert!(!is_group_sequence(7));
        assert!(!is_group_sequence(GROUP_SEQUENCE_FLAG | (1 << 32)));
    }

    #[test]
    fn group_data_round_trip() {
        let header = GroupDataHeader {
            ordered: true,
            priority: 3,
        };
        let bytes = encode_group_data(&header, b"ALARM").unwrap();
        assert_eq!(bytes[0], 0x07);
        let (decoded, app) = decode_group_data(&bytes).unwrap();
        assert_eq!(decoded, header);
        assert_eq!(app, b"ALARM");
        assert!(decode_group_data(&[0x08]).is_err());
        assert!(decode_group_data(&[]).is_err());
        assert!(encode_group_data(&header, &[0; GROUP_PAYLOAD_MAX + 1]).is_err());
    }

    #[test]
    fn group_report_round_trip_and_rejections() {
        let bytes = encode_group_report(&report()).unwrap();
        assert_eq!(bytes.len(), GROUP_REPORT_FIXED_BYTES + 16);
        assert_eq!(decode_group_report(&bytes).unwrap(), report());
        // Length must match missing_count exactly.
        assert!(decode_group_report(&bytes[..bytes.len() - 1]).is_err());
        // TRUNCATED must match missing_total > count.
        let mut untruncated = report();
        untruncated.flags = 0;
        assert!(encode_group_report(&untruncated).is_err());
        // NOT_CHILD carries zero counts.
        let mut not_child = report();
        not_child.flags = GROUP_REPORT_NOT_CHILD;
        not_child.missing.clear();
        assert!(encode_group_report(&not_child).is_err());
        not_child.delivered = 0;
        not_child.nonmember = 0;
        not_child.missing_total = 0;
        assert!(encode_group_report(&not_child).is_ok());
        // Reserved ids and non-group sequences are refused.
        let mut reserved = report();
        reserved.missing[0] = GROUP_ADDRESS_BASE;
        assert!(encode_group_report(&reserved).is_err());
        let mut unicast = report();
        unicast.message.sequence = 7;
        assert!(encode_group_report(&unicast).is_err());
    }
}
