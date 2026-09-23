//! RRS1 — SAK-signed revocation set (docs/design/sdk-v1/04 §2) and its
//! `rlrevo` storage record, mirror of the C++ `revocation_*`.
//!
//! ```text
//! payload:  0 u8 ver=1 | u8 flags=0 | u16 count (<=32)
//!           4 u64 site_id | 12 u64 network
//!          20 u32 rs_epoch (>=1) | 24 u32 site_epoch_floor (<= network>>32)
//!          28 entries x 16: node_id u64 | min_generation u32 (>=1) |
//!                           reason u8 (1..4) | reserved 3   (ascending node_id)
//! object:  restricted ES256 Sign1, external AAD
//!          "RouteLoom/revocation-set/v1" 0x00 || network u64
//! record:  sealed head "RRS1" | u32 commit_seq | object (empty = cleared) | crc
//! ```

use crate::signer::RootSigner;
use crate::{err, Code, Error, Result};

use super::{
    begin_record, cose_es256_assemble, cose_es256_parse, cose_es256_sig_structure, cose_es256_sign,
    cose_es256_verify, finish_record, id_valid, read_record, Reader, SEQUENCED_HEAD_SIZE,
};

pub const REVOCATION_VERSION: u8 = 1;
pub const REVOCATION_ENTRY_MAX: usize = 32;
pub const REVOCATION_HEAD_SIZE: usize = 28;
pub const REVOCATION_ENTRY_SIZE: usize = 16;
pub const REVOCATION_PAYLOAD_MAX: usize =
    REVOCATION_HEAD_SIZE + REVOCATION_ENTRY_MAX * REVOCATION_ENTRY_SIZE; // 540
pub const REVOCATION_OBJECT_MAX: usize = 7 + 3 + REVOCATION_PAYLOAD_MAX + 2 + 64; // 616
pub const REVOCATION_DOMAIN: &[u8] = b"RouteLoom/revocation-set/v1";
pub const REVOCATION_MAGIC: u32 = 0x5252_5331; // "RRS1"
pub const REVOCATION_SEAL_COMMITTED: u32 = 0x2E5E_7C0D;
pub const REVOCATION_SLOT_BYTES: usize = 640;
pub const REVOCATION_RECORD_MIN: usize = SEQUENCED_HEAD_SIZE + 4;
pub const REVOCATION_RECORD_MAX: usize = SEQUENCED_HEAD_SIZE + REVOCATION_OBJECT_MAX + 4; // 640

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum RevocationReason {
    Removed = 1,
    Lost = 2,
    Replaced = 3,
    Blocked = 4,
}

impl RevocationReason {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Removed,
            2 => Self::Lost,
            3 => Self::Replaced,
            4 => Self::Blocked,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationEntry {
    pub node_id: u64,
    pub min_generation: u32,
    pub reason: RevocationReason,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RevocationSet {
    pub site_id: u64,
    pub network: u64,
    pub rs_epoch: u32,
    pub site_epoch_floor: u32,
    pub entries: Vec<RevocationEntry>,
}

pub fn revocation_validate(set: &RevocationSet) -> Result<()> {
    if !id_valid(set.site_id)
        || set.network == 0
        || set.network & 0xFFFF_FFFF == 0
        || set.rs_epoch == 0
        || set.entries.len() > REVOCATION_ENTRY_MAX
        || set.site_epoch_floor > (set.network >> 32) as u32
    {
        return err(Code::InvalidArgument, "rrs1 head");
    }
    for (i, entry) in set.entries.iter().enumerate() {
        if !id_valid(entry.node_id) || entry.min_generation == 0 {
            return err(Code::InvalidArgument, "rrs1 entry");
        }
        if i > 0 && set.entries[i - 1].node_id >= entry.node_id {
            return err(Code::InvalidArgument, "rrs1 entries not ascending");
        }
    }
    Ok(())
}

pub fn revocation_payload_encode(set: &RevocationSet) -> Result<Vec<u8>> {
    revocation_validate(set)?;
    let mut out = Vec::with_capacity(REVOCATION_PAYLOAD_MAX);
    out.push(REVOCATION_VERSION);
    out.push(0);
    out.extend_from_slice(&(set.entries.len() as u16).to_be_bytes());
    out.extend_from_slice(&set.site_id.to_be_bytes());
    out.extend_from_slice(&set.network.to_be_bytes());
    out.extend_from_slice(&set.rs_epoch.to_be_bytes());
    out.extend_from_slice(&set.site_epoch_floor.to_be_bytes());
    for entry in &set.entries {
        out.extend_from_slice(&entry.node_id.to_be_bytes());
        out.extend_from_slice(&entry.min_generation.to_be_bytes());
        out.push(entry.reason as u8);
        out.extend_from_slice(&[0; 3]);
    }
    Ok(out)
}

pub fn revocation_payload_decode(payload: &[u8]) -> Result<RevocationSet> {
    if payload.len() < REVOCATION_HEAD_SIZE || payload.len() > REVOCATION_PAYLOAD_MAX {
        return err(Code::ProtocolError, "rrs1 payload bounds");
    }
    let mut reader = Reader::new(payload);
    let version = reader.u8()?;
    let flags = reader.u8()?;
    let count = usize::from(reader.u16()?);
    let mut set = RevocationSet {
        site_id: reader.u64()?,
        network: reader.u64()?,
        rs_epoch: reader.u32()?,
        site_epoch_floor: reader.u32()?,
        entries: Vec::new(),
    };
    if version != REVOCATION_VERSION {
        return err(Code::Unsupported, "rrs1 version");
    }
    if flags != 0
        || count > REVOCATION_ENTRY_MAX
        || payload.len() != REVOCATION_HEAD_SIZE + count * REVOCATION_ENTRY_SIZE
    {
        return err(Code::ProtocolError, "rrs1 payload shape");
    }
    for _ in 0..count {
        let node_id = reader.u64()?;
        let min_generation = reader.u32()?;
        let Some(reason) = RevocationReason::from_u8(reader.u8()?) else {
            return err(Code::ProtocolError, "rrs1 entry");
        };
        reader.zeros(3, "rrs1 entry reserved")?;
        set.entries.push(RevocationEntry {
            node_id,
            min_generation,
            reason,
        });
    }
    revocation_validate(&set).map_err(|e| Error::new(Code::ProtocolError, e.detail))?;
    Ok(set)
}

pub fn revocation_aad(network: u64) -> Vec<u8> {
    let mut out = REVOCATION_DOMAIN.to_vec();
    out.push(0);
    out.extend_from_slice(&network.to_be_bytes());
    out
}

pub fn revocation_sig_structure(payload: &[u8], network: u64) -> Vec<u8> {
    cose_es256_sig_structure(payload, &revocation_aad(network))
}

pub fn revocation_object_assemble(payload: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>> {
    revocation_payload_decode(payload)?;
    Ok(cose_es256_assemble(payload, signature))
}

/// Structure only (no signature).
pub fn revocation_object_decode(object: &[u8]) -> Result<RevocationSet> {
    let parts = cose_es256_parse(
        object,
        REVOCATION_HEAD_SIZE,
        REVOCATION_PAYLOAD_MAX,
        REVOCATION_OBJECT_MAX,
    )?;
    revocation_payload_decode(parts.payload)
}

/// Acceptance-side check: `Ok((set, verified))`; another site/network or a
/// bad signature is `verified == false`, malformed input an error.
pub fn revocation_object_verify(
    object: &[u8],
    sak_pubkey: &[u8; 64],
    expected_site_id: u64,
    expected_network: u64,
) -> Result<(RevocationSet, bool)> {
    let parts = cose_es256_parse(
        object,
        REVOCATION_HEAD_SIZE,
        REVOCATION_PAYLOAD_MAX,
        REVOCATION_OBJECT_MAX,
    )?;
    let set = revocation_payload_decode(parts.payload)?;
    if set.site_id != expected_site_id || set.network != expected_network {
        return Ok((set, false));
    }
    let verified = cose_es256_verify(
        parts.payload,
        &revocation_aad(expected_network),
        &parts.signature,
        sak_pubkey,
    );
    Ok((set, verified))
}

/// Publish a set through the SAK custody seam (signer id = site_id).
pub fn revocation_issue(set: &RevocationSet, sak: &dyn RootSigner) -> Result<Vec<u8>> {
    if sak.root_id() != set.site_id {
        return err(Code::InvalidArgument, "signer is not the site authority");
    }
    let payload = revocation_payload_encode(set)?;
    let signature = cose_es256_sign(sak, &payload, &revocation_aad(set.network))?;
    Ok(cose_es256_assemble(&payload, &signature))
}

/// Storage record (`rlrevo` slot); an empty object is the cleared tombstone.
pub fn revocation_record_encode(object: &[u8], seal: u32, commit_seq: u32) -> Result<Vec<u8>> {
    if seal != super::SEAL_PENDING && seal != REVOCATION_SEAL_COMMITTED {
        return err(Code::InvalidArgument, "rrs1 seal value");
    }
    if !object.is_empty() {
        revocation_object_decode(object)?;
    }
    let mut out = begin_record(REVOCATION_MAGIC, seal);
    out.extend_from_slice(&commit_seq.to_be_bytes());
    out.extend_from_slice(object);
    Ok(finish_record(out))
}

/// Committed record → `(set, object, commit_seq)`; the set is `None` for
/// the cleared tombstone.
pub fn revocation_record_decode(record: &[u8]) -> Result<(Option<RevocationSet>, Vec<u8>, u32)> {
    let mut reader = read_record(
        record,
        REVOCATION_MAGIC,
        REVOCATION_SEAL_COMMITTED,
        REVOCATION_RECORD_MIN,
        REVOCATION_RECORD_MAX,
    )?;
    let commit_seq = reader.u32()?;
    let object = reader.bytes(reader.remaining())?.to_vec();
    if object.is_empty() {
        return Ok((None, object, commit_seq));
    }
    let set = revocation_object_decode(&object)?;
    Ok((Some(set), object, commit_seq))
}

/// Whether a MemberCert (node, generation, site_epoch) is rejected.
pub fn revocation_rejects(
    set: &RevocationSet,
    node: u64,
    generation: u32,
    site_epoch: u32,
) -> bool {
    site_epoch < set.site_epoch_floor
        || set
            .entries
            .iter()
            .any(|e| e.node_id == node && generation < e.min_generation)
}
