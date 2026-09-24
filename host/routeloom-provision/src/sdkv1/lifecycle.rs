//! RLX1 removal journal record, byte mirror of the portable device codec.
//! This module describes sealed records; the device owns the two-slot commit
//! and power-cut recovery state machine.

use crate::{err, Code, Result};

use super::cert::CERT_MAX;
use super::{begin_record, cose_es256_parse, finish_record, id_valid, read_record, Reader};

pub const LIFECYCLE_MAGIC: u32 = 0x524c_5831;
pub const LIFECYCLE_SEAL_COMMITTED: u32 = 0x4c58_3101;
pub const LIFECYCLE_SLOT_BYTES: usize = 2048;
pub const REMOVAL_NOTICE_OBJECT_SIZE: usize = 103;
pub const LIFECYCLE_PAYLOAD_MAX: usize = 1521;
pub const LIFECYCLE_RECORD_MIN: usize = 88;
pub const LIFECYCLE_RECORD_MAX: usize = LIFECYCLE_RECORD_MIN + LIFECYCLE_PAYLOAD_MAX;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum LifecycleMode {
    Idle = 0,
    Removing = 1,
    Holdoff = 2,
    UnassignedReady = 3,
    Prepared = 4,
    Switching = 5,
}

impl LifecycleMode {
    fn decode(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Idle),
            1 => Ok(Self::Removing),
            2 => Ok(Self::Holdoff),
            3 => Ok(Self::UnassignedReady),
            4 => Ok(Self::Prepared),
            5 => Ok(Self::Switching),
            _ => err(Code::Unsupported, "rlx mode reserved"),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LifecycleRecord {
    pub mode: LifecycleMode,
    pub self_node: u64,
    pub site_id: u64,
    pub old_network: u64,
    pub new_network: u64,
    pub generation: u32,
    pub rs_floor: u32,
    pub gk_floor: u32,
    pub boot_witness: u32,
    pub cutover_id: u64,
    pub revision: u32,
    pub payload: Vec<u8>,
}

fn validate(record: &LifecycleRecord) -> Result<()> {
    if !id_valid(record.self_node)
        || record.site_id == 0
        || record.generation == 0
        || record.old_network == 0
        || (matches!(
            record.mode,
            LifecycleMode::Prepared | LifecycleMode::Switching
        ) != (record.new_network != 0 && record.cutover_id != 0 && record.revision != 0))
    {
        return err(Code::ProtocolError, "rlx binding");
    }
    if matches!(
        record.mode,
        LifecycleMode::Removing | LifecycleMode::Holdoff
    ) {
        if record.payload.len() < 4 || record.payload.len() > LIFECYCLE_PAYLOAD_MAX {
            return err(Code::ProtocolError, "rlx proof size");
        }
        let cert_len = usize::from(u16::from_be_bytes(record.payload[..2].try_into().unwrap()));
        let notice_len = usize::from(u16::from_be_bytes(record.payload[2..4].try_into().unwrap()));
        if cert_len == 0
            || cert_len > CERT_MAX
            || notice_len != REMOVAL_NOTICE_OBJECT_SIZE
            || record.payload.len() != 4 + cert_len + notice_len
        {
            return err(Code::ProtocolError, "rlx proof lengths");
        }
        let notice = &record.payload[4 + cert_len..];
        let parts = cose_es256_parse(notice, 28, 28, REMOVAL_NOTICE_OBJECT_SIZE)?;
        let mut reader = Reader::new(parts.payload);
        if reader.u8()? != 1 || !(1..=4).contains(&reader.u8()?) {
            return err(Code::ProtocolError, "rlx notice head");
        }
        reader.zeros(2, "rlx notice reserved")?;
        let site_id = reader.u64()?;
        let node_id = reader.u64()?;
        let generation = reader.u32()?;
        let rs_epoch = reader.u32()?;
        if reader.remaining() != 0
            || !id_valid(site_id)
            || !id_valid(node_id)
            || generation == 0
            || rs_epoch == 0
            || site_id != record.site_id
            || node_id != record.self_node
            || generation != record.generation
            || rs_epoch > record.rs_floor
        {
            return err(Code::ProtocolError, "rlx notice binding");
        }
    } else if matches!(
        record.mode,
        LifecycleMode::Prepared | LifecycleMode::Switching
    ) {
        if record.old_network as u32 != record.new_network as u32
            || (record.old_network >> 32).checked_add(1) != Some(record.new_network >> 32)
        {
            return err(Code::ProtocolError, "rlx cutover binding");
        }
        let p = &record.payload;
        if record.mode == LifecycleMode::Prepared {
            if p.len() < 34 {
                return err(Code::ProtocolError, "rlx prepared length");
            }
            let len = usize::from(u16::from_be_bytes(p[..2].try_into().unwrap()));
            if len == 0 || len > 712 || p.len() != 2 + len + 32 {
                return err(Code::ProtocolError, "rlx prepared length");
            }
        } else {
            if p.len() < 38 {
                return err(Code::ProtocolError, "rlx switching length");
            }
            let site = usize::from(u16::from_be_bytes(p[..2].try_into().unwrap()));
            let rrs = usize::from(u16::from_be_bytes(p[2..4].try_into().unwrap()));
            let commit = usize::from(u16::from_be_bytes(p[4..6].try_into().unwrap()));
            if site == 0
                || site > 712
                || rrs == 0
                || rrs > 616
                || commit != 155
                || p.len() != 6 + site + rrs + commit + 32
            {
                return err(Code::ProtocolError, "rlx switching length");
            }
        }
    } else if !record.payload.is_empty() {
        return err(Code::ProtocolError, "rlx watermark payload");
    }
    Ok(())
}

pub fn lifecycle_record_encode(record: &LifecycleRecord, seal: u32, seq: u32) -> Result<Vec<u8>> {
    validate(record)?;
    if seq == 0 || (seal != 0 && seal != LIFECYCLE_SEAL_COMMITTED) {
        return err(Code::InvalidArgument, "rlx seal/seq");
    }
    let mut out = begin_record(LIFECYCLE_MAGIC, seal);
    out.extend_from_slice(&seq.to_be_bytes());
    out.push(record.mode as u8);
    out.push(0);
    out.extend_from_slice(&(record.payload.len() as u16).to_be_bytes());
    out.extend_from_slice(&record.self_node.to_be_bytes());
    out.extend_from_slice(&record.site_id.to_be_bytes());
    out.extend_from_slice(&record.old_network.to_be_bytes());
    out.extend_from_slice(&record.new_network.to_be_bytes());
    out.extend_from_slice(&record.generation.to_be_bytes());
    out.extend_from_slice(&record.rs_floor.to_be_bytes());
    out.extend_from_slice(&record.gk_floor.to_be_bytes());
    out.extend_from_slice(&record.boot_witness.to_be_bytes());
    out.extend_from_slice(&record.cutover_id.to_be_bytes());
    out.extend_from_slice(&record.revision.to_be_bytes());
    out.extend_from_slice(&record.payload);
    Ok(finish_record(out))
}

pub fn lifecycle_record_decode(encoded: &[u8]) -> Result<(LifecycleRecord, u32)> {
    let mut reader = read_record(
        encoded,
        LIFECYCLE_MAGIC,
        LIFECYCLE_SEAL_COMMITTED,
        LIFECYCLE_RECORD_MIN,
        LIFECYCLE_RECORD_MAX,
    )?;
    let seq = reader.u32()?;
    let mode = LifecycleMode::decode(reader.u8()?)?;
    reader.zeros(1, "rlx reserved")?;
    let payload_len = usize::from(reader.u16()?);
    let record = LifecycleRecord {
        mode,
        self_node: reader.u64()?,
        site_id: reader.u64()?,
        old_network: reader.u64()?,
        new_network: reader.u64()?,
        generation: reader.u32()?,
        rs_floor: reader.u32()?,
        gk_floor: reader.u32()?,
        boot_witness: reader.u32()?,
        cutover_id: reader.u64()?,
        revision: reader.u32()?,
        payload: reader.bytes(payload_len)?.to_vec(),
    };
    if seq == 0 || reader.remaining() != 0 || payload_len > LIFECYCLE_PAYLOAD_MAX {
        return err(Code::ProtocolError, "rlx structure");
    }
    validate(&record)?;
    Ok((record, seq))
}
