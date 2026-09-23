//! RLP1 — one fixed-size resumption-cache slot (docs/design/sdk-v1/05 §3.2),
//! mirror of the C++ `resume_slot_*`.
//!
//! ```text
//!  0 u32 magic "RLP1" | 4 u8 format=1 | 5 u8 purpose (1 link, 2 end; 0 empty)
//!  6 u8 state (0 empty, 1 valid) | 7 u8 flags (bit0 pinned)
//!  8 u64 peer | 16 u64 network | 24 8B peer_cert_id
//! 32 u32 peer_generation | 36 u32 created_gk_epoch
//! 40 u32 last_used_boot  | 44 u32 reserved | 48 32B rms | 80 u32 crc32
//! ```

use crate::crc32::crc32_iso_hdlc;
use crate::sha256::sha256;
use crate::{err, Code, Error, Result};

use super::{id_valid, Reader};

pub const RESUME_MAGIC: u32 = 0x524C_5031; // "RLP1"
pub const RESUME_FORMAT: u8 = 1;
pub const RESUME_SLOT_BYTES: usize = 84;
pub const RESUME_FLAG_PINNED: u8 = 0x01;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum ResumePurpose {
    #[default]
    Link = 1,
    End = 2,
}

/// `valid == false` is the empty slot: every other field zero.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ResumeSlot {
    pub valid: bool,
    pub purpose: ResumePurpose,
    pub flags: u8,
    pub peer: u64,
    pub network: u64,
    pub peer_cert_id: [u8; 8],
    pub peer_generation: u32,
    pub created_gk_epoch: u32,
    pub last_used_boot: u32,
    pub rms: [u8; 32],
}

pub fn resume_validate(slot: &ResumeSlot) -> Result<()> {
    if !slot.valid {
        let empty = ResumeSlot {
            purpose: slot.purpose,
            ..ResumeSlot::default()
        };
        if *slot != empty {
            return err(Code::InvalidArgument, "rlp1 empty residue");
        }
        return Ok(());
    }
    if slot.flags & !RESUME_FLAG_PINNED != 0
        || !id_valid(slot.peer)
        || slot.network == 0
        || slot.peer_generation == 0
        || slot.created_gk_epoch == 0
        || slot.rms.iter().all(|&b| b == 0)
    {
        return err(Code::InvalidArgument, "rlp1 fields");
    }
    Ok(())
}

pub fn resume_slot_encode(slot: &ResumeSlot) -> Result<[u8; RESUME_SLOT_BYTES]> {
    resume_validate(slot)?;
    let mut out = Vec::with_capacity(RESUME_SLOT_BYTES);
    out.extend_from_slice(&RESUME_MAGIC.to_be_bytes());
    out.push(RESUME_FORMAT);
    out.push(if slot.valid { slot.purpose as u8 } else { 0 });
    out.push(u8::from(slot.valid));
    out.push(slot.flags);
    out.extend_from_slice(&slot.peer.to_be_bytes());
    out.extend_from_slice(&slot.network.to_be_bytes());
    out.extend_from_slice(&slot.peer_cert_id);
    out.extend_from_slice(&slot.peer_generation.to_be_bytes());
    out.extend_from_slice(&slot.created_gk_epoch.to_be_bytes());
    out.extend_from_slice(&slot.last_used_boot.to_be_bytes());
    out.extend_from_slice(&0_u32.to_be_bytes());
    out.extend_from_slice(&slot.rms);
    let crc = crc32_iso_hdlc(&out);
    out.extend_from_slice(&crc.to_be_bytes());
    Ok(out.try_into().expect("84 bytes"))
}

pub fn resume_slot_decode(bytes: &[u8]) -> Result<ResumeSlot> {
    if bytes.len() != RESUME_SLOT_BYTES {
        return err(Code::ProtocolError, "rlp1 size");
    }
    let mut reader = Reader::new(bytes);
    let magic = reader.u32()?;
    let format = reader.u8()?;
    let purpose = reader.u8()?;
    let state = reader.u8()?;
    let mut slot = ResumeSlot {
        flags: reader.u8()?,
        peer: reader.u64()?,
        network: reader.u64()?,
        peer_cert_id: reader.array()?,
        peer_generation: reader.u32()?,
        created_gk_epoch: reader.u32()?,
        last_used_boot: reader.u32()?,
        ..ResumeSlot::default()
    };
    let reserved = reader.u32()?;
    slot.rms = reader.array()?;
    let crc = reader.u32()?;
    if magic != RESUME_MAGIC || format != RESUME_FORMAT {
        return err(Code::ProtocolError, "rlp1 head");
    }
    if crc32_iso_hdlc(&bytes[..RESUME_SLOT_BYTES - 4]) != crc {
        return err(Code::IntegrityError, "rlp1 crc");
    }
    if reserved != 0 || state > 1 || (state == 0 && purpose != 0) {
        return err(Code::ProtocolError, "rlp1 fields");
    }
    slot.valid = state == 1;
    if slot.valid {
        slot.purpose = match purpose {
            1 => ResumePurpose::Link,
            2 => ResumePurpose::End,
            _ => return err(Code::ProtocolError, "rlp1 fields"),
        };
    }
    resume_validate(&slot).map_err(|e| Error::new(Code::ProtocolError, e.detail))?;
    Ok(slot)
}

/// first8(SHA-256(peer MemberCert)).
pub fn resume_peer_cert_id(member_cert: &[u8]) -> [u8; 8] {
    sha256(member_cert)[..8].try_into().expect("8")
}
