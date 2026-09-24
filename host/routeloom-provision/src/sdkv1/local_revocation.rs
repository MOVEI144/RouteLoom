//! RLV1 — durable local-removal evidence (G-SEC P4 §3.3, issue #60-2),
//! mirror of the C++ `local_revocation_record_*`.
//!
//! A record of refusal, not permission: while one stands unresolved the
//! node must not return to Member, not even across reboot.
//!
//! ```text
//!  0 u32 magic "RLV1" | 4 u16 format=1 | 6 u16 used_len=108 | 8 u32 schema=1
//! 12 u32 seal | 16 u32 commit_seq
//! 20 u64 local_node | 28 u64 site_id | 36 u64 network
//! 44 u32 removed_generation | 48 u32 rs_epoch_floor | 52 u32 site_epoch_floor
//! 56 u8 state (1 Blocked, 2 Cleaned) | 57 u8 cause | 58 u16 reserved=0
//! 60 32B evidence_digest | 92 u32 rls_commit_seq | 96 u32 boot_witness
//! 100 u32 holdoff_ms | 104 u32 crc32
//! ```

use crate::{err, Code, Error, Result};

use super::{begin_record, finish_record, id_valid, read_record};

pub const LOCAL_REVOCATION_MAGIC: u32 = 0x524C_5631; // "RLV1"
pub const LOCAL_REVOCATION_SEAL_COMMITTED: u32 = 0x7256_4B31;
pub const LOCAL_REVOCATION_SLOT_BYTES: usize = 108;
pub const LOCAL_REVOCATION_RECORD_LEN: usize = 108;
pub const LOCAL_REVOCATION_HOLDOFF_MS: u32 = 600_000;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum LocalRevocationState {
    #[default]
    Blocked = 1,
    Cleaned = 2,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum LocalRevocationCause {
    /// An accepted RRS1 set rejected this node.
    #[default]
    Rrs = 1,
    /// A verified RemovalNotice named this node.
    Notice = 2,
    /// Physical maintenance revocation (dev).
    LocalMaintenance = 3,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalRevocationRecord {
    pub state: LocalRevocationState,
    pub cause: LocalRevocationCause,
    pub local_node: u64,
    pub site_id: u64,
    pub network: u64,
    pub removed_generation: u32,
    pub rs_epoch_floor: u32,
    pub site_epoch_floor: u32,
    pub evidence_digest: [u8; 32],
    pub rls_commit_seq: u32,
    pub boot_witness: u32,
    pub holdoff_ms: u32,
}

pub fn local_revocation_validate(record: &LocalRevocationRecord) -> Result<()> {
    if !matches!(
        record.cause,
        LocalRevocationCause::Rrs
            | LocalRevocationCause::Notice
            | LocalRevocationCause::LocalMaintenance
    ) || !id_valid(record.local_node)
        || record.site_id == 0
        || record.network == 0
        || record.removed_generation == 0
        || record.evidence_digest.iter().all(|&b| b == 0)
        || record.holdoff_ms != LOCAL_REVOCATION_HOLDOFF_MS
    {
        return err(Code::InvalidArgument, "rlv1 fields");
    }
    Ok(())
}

pub fn local_revocation_record_encode(
    record: &LocalRevocationRecord,
    seal: u32,
    commit_seq: u32,
) -> Result<Vec<u8>> {
    local_revocation_validate(record)?;
    if seal != super::SEAL_PENDING && seal != LOCAL_REVOCATION_SEAL_COMMITTED {
        return err(Code::InvalidArgument, "rlv1 seal value");
    }
    let mut out = begin_record(LOCAL_REVOCATION_MAGIC, seal);
    out.extend_from_slice(&commit_seq.to_be_bytes());
    out.extend_from_slice(&record.local_node.to_be_bytes());
    out.extend_from_slice(&record.site_id.to_be_bytes());
    out.extend_from_slice(&record.network.to_be_bytes());
    out.extend_from_slice(&record.removed_generation.to_be_bytes());
    out.extend_from_slice(&record.rs_epoch_floor.to_be_bytes());
    out.extend_from_slice(&record.site_epoch_floor.to_be_bytes());
    out.push(record.state as u8);
    out.push(record.cause as u8);
    out.extend_from_slice(&0_u16.to_be_bytes());
    out.extend_from_slice(&record.evidence_digest);
    out.extend_from_slice(&record.rls_commit_seq.to_be_bytes());
    out.extend_from_slice(&record.boot_witness.to_be_bytes());
    out.extend_from_slice(&record.holdoff_ms.to_be_bytes());
    Ok(finish_record(out))
}

pub fn local_revocation_record_decode(record: &[u8]) -> Result<(LocalRevocationRecord, u32)> {
    let mut reader = read_record(
        record,
        LOCAL_REVOCATION_MAGIC,
        LOCAL_REVOCATION_SEAL_COMMITTED,
        LOCAL_REVOCATION_RECORD_LEN,
        LOCAL_REVOCATION_RECORD_LEN,
    )?;
    let commit_seq = reader.u32()?;
    let mut out = LocalRevocationRecord {
        local_node: reader.u64()?,
        site_id: reader.u64()?,
        network: reader.u64()?,
        removed_generation: reader.u32()?,
        rs_epoch_floor: reader.u32()?,
        site_epoch_floor: reader.u32()?,
        ..LocalRevocationRecord::default()
    };
    let state = reader.u8()?;
    let cause = reader.u8()?;
    let reserved = reader.u16()?;
    out.evidence_digest = reader.array()?;
    out.rls_commit_seq = reader.u32()?;
    out.boot_witness = reader.u32()?;
    out.holdoff_ms = reader.u32()?;
    // Head, seal, length and CRC already verified by read_record.
    if reserved != 0 {
        return err(Code::ProtocolError, "rlv1 reserved");
    }
    out.state = match state {
        1 => LocalRevocationState::Blocked,
        2 => LocalRevocationState::Cleaned,
        _ => return err(Code::ProtocolError, "rlv1 fields"),
    };
    out.cause = match cause {
        1 => LocalRevocationCause::Rrs,
        2 => LocalRevocationCause::Notice,
        3 => LocalRevocationCause::LocalMaintenance,
        _ => return err(Code::ProtocolError, "rlv1 fields"),
    };
    local_revocation_validate(&out).map_err(|e| Error::new(Code::ProtocolError, e.detail))?;
    Ok((out, commit_seq))
}
