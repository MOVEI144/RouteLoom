//! Scoped ROUTE_UPDATE broadcast payload. The caller must authenticate the
//! sender binding separately; a group tag is not pairwise identity proof.

use crate::{ErrorCode, Result, WireError, BROADCAST_NODE_ID, INVALID_NODE_ID};

pub const INFINITY: u16 = u16::MAX;
pub const MAX_RECORDS: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub destination: u64,
    pub generation: u32,
    pub sequence: u16,
    pub metric: u16,
    pub via: u64,
}

fn valid(records: &[Record], sender: u64) -> bool {
    if sender == INVALID_NODE_ID
        || sender == BROADCAST_NODE_ID
        || records.is_empty()
        || records.len() > MAX_RECORDS
        || records[0].destination != sender
        || records[0].metric != 0
        || records[0].via != 0
    {
        return false;
    }
    for (i, record) in records.iter().enumerate() {
        if record.destination == INVALID_NODE_ID
            || record.destination == BROADCAST_NODE_ID
            || record.generation == 0
            || records[..i]
                .iter()
                .any(|other| other.destination == record.destination)
        {
            return false;
        }
        if i > 0
            && (record.metric == 0
                || if record.metric == INFINITY {
                    record.via != 0
                } else {
                    record.via == 0
                        || record.via == BROADCAST_NODE_ID
                        || record.via == sender
                        || record.via == record.destination
                })
        {
            return false;
        }
    }
    true
}

pub fn encode(records: &[Record], sender: u64) -> Result<Vec<u8>> {
    if !valid(records, sender) {
        return Err(WireError::new(
            ErrorCode::InvalidArgument,
            "broadcast route records",
        ));
    }
    let mut out = Vec::with_capacity(4 + 24 * records.len());
    out.extend_from_slice(&[1, 0, records.len() as u8, 0]);
    for record in records {
        out.extend_from_slice(&record.destination.to_be_bytes());
        out.extend_from_slice(&record.generation.to_be_bytes());
        out.extend_from_slice(&record.sequence.to_be_bytes());
        out.extend_from_slice(&record.metric.to_be_bytes());
        out.extend_from_slice(&record.via.to_be_bytes());
    }
    Ok(out)
}

pub fn decode(input: &[u8], sender: u64) -> Result<Vec<Record>> {
    if input.len() < 28
        || input[0] != 1
        || input[1] != 0
        || input[3] != 0
        || input[2] == 0
        || input[2] as usize > MAX_RECORDS
        || input.len() != 4 + 24 * input[2] as usize
    {
        return Err(WireError::new(
            ErrorCode::ProtocolError,
            "broadcast route length/head",
        ));
    }
    let mut records = Vec::with_capacity(input[2] as usize);
    for bytes in input[4..].chunks_exact(24) {
        records.push(Record {
            destination: u64::from_be_bytes(bytes[0..8].try_into().unwrap()),
            generation: u32::from_be_bytes(bytes[8..12].try_into().unwrap()),
            sequence: u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
            metric: u16::from_be_bytes(bytes[14..16].try_into().unwrap()),
            via: u64::from_be_bytes(bytes[16..24].try_into().unwrap()),
        });
    }
    if !valid(&records, sender) {
        return Err(WireError::new(
            ErrorCode::ProtocolError,
            "broadcast route records",
        ));
    }
    Ok(records)
}

pub const fn projected_metric(record: &Record, receiver: u64) -> u16 {
    if record.via == receiver {
        INFINITY
    } else {
        record.metric
    }
}
