//! RLP2 — one fixed-size resumption-cache slot with the enforceable 64-use
//! ceiling (G-SEC P4 §6.2), mirror of the C++ `resume2_slot_*`.
//!
//! ```text
//!  0 u32 magic "RLP2" | 4 u8 format=1 | 5 u8 purpose (1 link, 2 end; 0 empty)
//!  6 u8 state (0 empty, 1 valid) | 7 u8 flags (bit0 pinned)
//!  8 u64 peer | 16 u64 network | 24 8B peer_cert_id | 32 8B local_cert_id
//! 40 u32 peer_generation | 44 u32 peer_role | 48 u32 created_gk_epoch
//! 52 u32 last_used_boot | 56 u32 reserved_uses (0..64) | 60 32B rms | 92 u32 crc32
//! ```

use crate::crc32::crc32_iso_hdlc;
use crate::{err, Code, Error, Result};

use super::resume::ResumePurpose;
use super::{id_valid, Reader};

pub const RESUME2_MAGIC: u32 = 0x524C_5032; // "RLP2"
pub const RESUME2_FORMAT: u8 = 1;
pub const RESUME2_SLOT_BYTES: usize = 96;
pub const RESUME2_MAX_USES: u32 = 64;

/// `valid == false` is the empty slot: every other field zero.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResumeSlot2 {
    pub valid: bool,
    pub purpose: ResumePurpose,
    pub flags: u8,
    pub peer: u64,
    pub network: u64,
    pub peer_cert_id: [u8; 8],
    pub local_cert_id: [u8; 8],
    pub peer_generation: u32,
    pub peer_role: u32,
    pub created_gk_epoch: u32,
    pub last_used_boot: u32,
    pub reserved_uses: u32,
    pub rms: [u8; 32],
}

pub fn resume2_validate(slot: &ResumeSlot2) -> Result<()> {
    if !slot.valid {
        let empty = ResumeSlot2 {
            purpose: slot.purpose,
            ..ResumeSlot2::default()
        };
        if *slot != empty {
            return err(Code::InvalidArgument, "rlp2 empty residue");
        }
        return Ok(());
    }
    if !matches!(slot.purpose, ResumePurpose::Link | ResumePurpose::End)
        || slot.flags & !super::resume::RESUME_FLAG_PINNED != 0
        || !id_valid(slot.peer)
        || slot.network == 0
        || slot.peer_generation == 0
        || slot.peer_role == 0
        || slot.created_gk_epoch == 0
        || slot.reserved_uses > RESUME2_MAX_USES
        || slot.rms.iter().all(|&b| b == 0)
    {
        return err(Code::InvalidArgument, "rlp2 fields");
    }
    Ok(())
}

pub fn resume2_slot_encode(slot: &ResumeSlot2) -> Result<[u8; RESUME2_SLOT_BYTES]> {
    resume2_validate(slot)?;
    let mut out = Vec::with_capacity(RESUME2_SLOT_BYTES);
    out.extend_from_slice(&RESUME2_MAGIC.to_be_bytes());
    out.push(RESUME2_FORMAT);
    out.push(if slot.valid { slot.purpose as u8 } else { 0 });
    out.push(u8::from(slot.valid));
    out.push(slot.flags);
    out.extend_from_slice(&slot.peer.to_be_bytes());
    out.extend_from_slice(&slot.network.to_be_bytes());
    out.extend_from_slice(&slot.peer_cert_id);
    out.extend_from_slice(&slot.local_cert_id);
    out.extend_from_slice(&slot.peer_generation.to_be_bytes());
    out.extend_from_slice(&slot.peer_role.to_be_bytes());
    out.extend_from_slice(&slot.created_gk_epoch.to_be_bytes());
    out.extend_from_slice(&slot.last_used_boot.to_be_bytes());
    out.extend_from_slice(&slot.reserved_uses.to_be_bytes());
    out.extend_from_slice(&slot.rms);
    let crc = crc32_iso_hdlc(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out.try_into().expect("96 bytes"))
}

pub fn resume2_slot_decode(bytes: &[u8]) -> Result<ResumeSlot2> {
    if bytes.len() != RESUME2_SLOT_BYTES {
        return err(Code::ProtocolError, "rlp2 size");
    }
    let mut reader = Reader::new(bytes);
    let magic = reader.u32()?;
    let format = reader.u8()?;
    let purpose = reader.u8()?;
    let state = reader.u8()?;
    let mut slot = ResumeSlot2 {
        flags: reader.u8()?,
        peer: reader.u64()?,
        network: reader.u64()?,
        peer_cert_id: reader.array()?,
        local_cert_id: reader.array()?,
        peer_generation: reader.u32()?,
        peer_role: reader.u32()?,
        created_gk_epoch: reader.u32()?,
        last_used_boot: reader.u32()?,
        reserved_uses: reader.u32()?,
        ..ResumeSlot2::default()
    };
    slot.rms = reader.array()?;
    let crc = reader.u32()?;
    if magic != RESUME2_MAGIC || format != RESUME2_FORMAT {
        return err(Code::ProtocolError, "rlp2 head");
    }
    if crc32_iso_hdlc(&bytes[..RESUME2_SLOT_BYTES - 4]) != crc {
        return err(Code::IntegrityError, "rlp2 crc");
    }
    if state > 1 || (state == 0 && purpose != 0) {
        return err(Code::ProtocolError, "rlp2 fields");
    }
    slot.valid = state == 1;
    if slot.valid {
        slot.purpose = match purpose {
            1 => ResumePurpose::Link,
            2 => ResumePurpose::End,
            _ => return err(Code::ProtocolError, "rlp2 fields"),
        };
    }
    resume2_validate(&slot).map_err(|e| Error::new(Code::ProtocolError, e.detail))?;
    Ok(slot)
}
