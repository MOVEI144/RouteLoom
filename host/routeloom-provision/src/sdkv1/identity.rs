//! RLI1 — site-independent device identity record
//! (docs/design/sdk-v1/02-zero-touch-join.md §2), mirror of the C++
//! `identity_record_*`. Written once at the office as an identical twin
//! pair (`rlsec`/`rlident`), never re-derived on the device.
//!
//! ```text
//!   0 sealed head (magic "RLI1", 16 B)
//!  16 u64 node_id
//!  24 u8 key_location | u8 flags | u8 anchor_count (1..3) | u8 reserved
//!  28 u32 reserved
//!  32 32B kid | 64 64B pubkey | 128 32B key_material
//! 160 anchors x 80: anchor_id u64 | kind u8 | status u8 | reserved 6 | pubkey 64
//!     u16 devcert_len (1..256) | u16 reserved | DevCert
//! len-4 u32 crc32
//! ```

use crate::credential::{credential_kid, KeyLocation};
use crate::image::pubkey_on_curve;
use crate::signer::pubkey_from_secret;
use crate::{err, Code, Error, Result};

use super::cert::{cert_decode, cert_verify, CertClaims, CertType, CERT_MAX};
use super::{begin_record, finish_record, id_valid, read_record};

pub const IDENTITY_MAGIC: u32 = 0x524C_4931; // "RLI1"
pub const IDENTITY_SEAL_COMMITTED: u32 = 0x1DE7_1771;
pub const IDENTITY_SLOT_BYTES: usize = 1024;
pub const IDENTITY_ANCHOR_MAX: usize = 3;
pub const IDENTITY_FIXED_SIZE: usize = 160;
pub const IDENTITY_RECORD_MIN: usize = IDENTITY_FIXED_SIZE + 80 + 4 + 1 + 4;
pub const IDENTITY_RECORD_MAX: usize = IDENTITY_FIXED_SIZE + 3 * 80 + 4 + CERT_MAX + 4; // 664

pub const FLAG_CONSOLE_LOCKED: u8 = 0x01;
pub const FLAG_STRICT_ASSIGNMENT: u8 = 0x02;
pub const FLAG_MASK: u8 = 0x03;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AnchorKind {
    SiteCa = 1,
    AssignmentVerifier = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AnchorStatus {
    Active = 1,
    Disabled = 2,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityAnchor {
    pub anchor_id: u64,
    pub kind: AnchorKind,
    pub status: AnchorStatus,
    pub pubkey: [u8; 64],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IdentityRecord {
    pub node_id: u64,
    pub key_location: KeyLocation,
    pub flags: u8,
    pub kid: [u8; 32],
    pub pubkey: [u8; 64],
    pub key_material: [u8; 32],
    pub anchors: Vec<IdentityAnchor>,
    pub devcert: Vec<u8>,
}

/// Boot checks (same rules and order as `identity_validate`).
pub fn identity_validate(r: &IdentityRecord) -> Result<()> {
    if !id_valid(r.node_id) {
        return err(Code::InvalidArgument, "rli1 node id");
    }
    if r.flags & !FLAG_MASK != 0
        || r.anchors.is_empty()
        || r.anchors.len() > IDENTITY_ANCHOR_MAX
        || r.devcert.is_empty()
        || r.devcert.len() > CERT_MAX
    {
        return err(Code::InvalidArgument, "rli1 fields");
    }
    if !pubkey_on_curve(&r.pubkey) {
        return err(Code::InvalidArgument, "rli1 pubkey off curve");
    }
    if credential_kid(&r.pubkey) != r.kid {
        return err(Code::IntegrityError, "rli1 kid mismatch");
    }
    match r.key_location {
        KeyLocation::None => {
            if r.key_material.iter().any(|&b| b != 0) {
                return err(Code::InvalidArgument, "rli1 key residue");
            }
        }
        KeyLocation::NvsPlaintext => {
            if pubkey_from_secret(&r.key_material) != Some(r.pubkey) {
                return err(Code::IntegrityError, "rli1 keypair mismatch");
            }
        }
        _ => {}
    }
    let mut site_ca = false;
    let mut verifier = false;
    for (i, anchor) in r.anchors.iter().enumerate() {
        if !id_valid(anchor.anchor_id) {
            return err(Code::InvalidArgument, "rli1 anchor fields");
        }
        if r.anchors[i + 1..]
            .iter()
            .any(|other| other.anchor_id == anchor.anchor_id)
        {
            return err(Code::InvalidArgument, "rli1 anchor duplicated");
        }
        if !pubkey_on_curve(&anchor.pubkey) {
            return err(Code::InvalidArgument, "rli1 anchor off curve");
        }
        if anchor.status == AnchorStatus::Active {
            site_ca |= anchor.kind == AnchorKind::SiteCa;
            verifier |= anchor.kind == AnchorKind::AssignmentVerifier;
        }
    }
    if !site_ca {
        return err(Code::InvalidArgument, "rli1 no active site ca");
    }
    if r.flags & FLAG_STRICT_ASSIGNMENT != 0 && !verifier {
        return err(Code::InvalidArgument, "rli1 strict without verifier");
    }
    let devcert = cert_decode(&r.devcert)?;
    if devcert.cert_type != CertType::Device
        || devcert.subject != r.node_id
        || devcert.pubkey != r.pubkey
    {
        return err(Code::IntegrityError, "rli1 devcert mismatch");
    }
    Ok(())
}

pub fn identity_record_encode(r: &IdentityRecord, seal: u32) -> Result<Vec<u8>> {
    identity_validate(r)?;
    if seal != super::SEAL_PENDING && seal != IDENTITY_SEAL_COMMITTED {
        return err(Code::InvalidArgument, "rli1 seal value");
    }
    let mut out = begin_record(IDENTITY_MAGIC, seal);
    out.extend_from_slice(&r.node_id.to_be_bytes());
    out.push(r.key_location as u8);
    out.push(r.flags);
    out.push(r.anchors.len() as u8);
    out.extend_from_slice(&[0; 5]);
    out.extend_from_slice(&r.kid);
    out.extend_from_slice(&r.pubkey);
    out.extend_from_slice(&r.key_material);
    for anchor in &r.anchors {
        out.extend_from_slice(&anchor.anchor_id.to_be_bytes());
        out.push(anchor.kind as u8);
        out.push(anchor.status as u8);
        out.extend_from_slice(&[0; 6]);
        out.extend_from_slice(&anchor.pubkey);
    }
    out.extend_from_slice(&(r.devcert.len() as u16).to_be_bytes());
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&r.devcert);
    Ok(finish_record(out))
}

pub fn identity_record_decode(record: &[u8]) -> Result<IdentityRecord> {
    let mut reader = read_record(
        record,
        IDENTITY_MAGIC,
        IDENTITY_SEAL_COMMITTED,
        IDENTITY_RECORD_MIN,
        IDENTITY_RECORD_MAX,
    )?;
    let node_id = reader.u64()?;
    let location = reader.u8()?;
    let flags = reader.u8()?;
    let anchor_count = usize::from(reader.u8()?);
    reader.zeros(5, "rli1 reserved")?;
    let Some(key_location) = KeyLocation::from_u8(location) else {
        return err(Code::ProtocolError, "rli1 head fields");
    };
    if anchor_count == 0 || anchor_count > IDENTITY_ANCHOR_MAX {
        return err(Code::ProtocolError, "rli1 head fields");
    }
    let kid = reader.array()?;
    let pubkey = reader.array()?;
    let key_material = reader.array()?;
    let mut anchors = Vec::with_capacity(anchor_count);
    for _ in 0..anchor_count {
        let anchor_id = reader.u64()?;
        let kind = match reader.u8()? {
            1 => AnchorKind::SiteCa,
            2 => AnchorKind::AssignmentVerifier,
            _ => return err(Code::ProtocolError, "rli1 anchor enum"),
        };
        let status = match reader.u8()? {
            1 => AnchorStatus::Active,
            2 => AnchorStatus::Disabled,
            _ => return err(Code::ProtocolError, "rli1 anchor enum"),
        };
        reader.zeros(6, "rli1 anchor reserved")?;
        anchors.push(IdentityAnchor {
            anchor_id,
            kind,
            status,
            pubkey: reader.array()?,
        });
    }
    let devcert_len = usize::from(reader.u16()?);
    let reserved = reader.u16()?;
    if reserved != 0
        || devcert_len == 0
        || devcert_len > CERT_MAX
        || reader.remaining() != devcert_len
    {
        return err(Code::ProtocolError, "rli1 devcert length");
    }
    let record = IdentityRecord {
        node_id,
        key_location,
        flags,
        kid,
        pubkey,
        key_material,
        anchors,
        devcert: reader.bytes(devcert_len)?.to_vec(),
    };
    identity_validate(&record).map_err(|e| {
        Error::new(
            if e.code == Code::InvalidArgument {
                Code::ProtocolError
            } else {
                e.code
            },
            e.detail,
        )
    })?;
    Ok(record)
}

/// SiteCert chain step: issuer must name an ACTIVE SiteCA anchor and the
/// signature must verify under it. `Ok((claims, verified))`.
pub fn identity_verify_site_cert(
    record: &IdentityRecord,
    site_cert: &[u8],
) -> Result<(CertClaims, bool)> {
    let claims = cert_decode(site_cert)?;
    if claims.cert_type != CertType::Site {
        return Ok((claims, false));
    }
    let Some(anchor) = record.anchors.iter().find(|a| {
        a.anchor_id == claims.issuer
            && a.kind == AnchorKind::SiteCa
            && a.status == AnchorStatus::Active
    }) else {
        return Ok((claims, false));
    };
    cert_verify(site_cert, &anchor.pubkey)
}
