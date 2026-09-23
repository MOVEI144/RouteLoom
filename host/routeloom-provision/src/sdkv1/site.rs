//! RLS1 — site membership record (docs/design/sdk-v1/02-zero-touch-join.md
//! §10.3 plus the A/B `commit_seq`), mirror of the C++ `site_record_*`.
//!
//! ```text
//!   0 sealed head (magic "RLS1") | 16 u32 commit_seq
//!  20 u64 site_id | 28 u64 network
//!  36 u32 assignment_generation | 40 u32 rs_epoch_floor
//!  44 u32 gk_epoch_current | 48 u32 gk_epoch_next
//!  52 32B gk_current | 84 32B gk_next | 116 32B dams
//! 148 u8 state | u8 role | u8 gateway_count | u8 channel
//! 152 u32 channel_epoch | 156 u32 boot_witness | 160 4 x u64 gateways
//! 192 u16 sitecert_len | u16 membercert_len | 196 SiteCert | MemberCert
//! len-4 u32 crc32
//! ```
//! state 0 is the cleared tombstone (every body byte zero, 200 B).

use crate::{err, Code, Error, Result};

use super::cert::{cert_decode, member_cert_matches, CertType, CERT_MAX, MEMBER_ROLE_MASK};
use super::identity::IdentityRecord;
use super::{begin_record, finish_record, id_valid, read_record};

pub const SITE_MAGIC: u32 = 0x524C_5331; // "RLS1"
pub const SITE_SEAL_COMMITTED: u32 = 0x5173_AB1E;
pub const SITE_SLOT_BYTES: usize = 1024;
pub const SITE_FIXED_SIZE: usize = 196;
pub const SITE_GATEWAY_MAX: usize = 4;
pub const SITE_RECORD_MIN: usize = SITE_FIXED_SIZE + 4;
pub const SITE_RECORD_MAX: usize = SITE_FIXED_SIZE + 2 * CERT_MAX + 4; // 712

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum SiteState {
    #[default]
    Cleared = 0,
    Member = 1,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SiteRecord {
    pub state: SiteState,
    pub site_id: u64,
    pub network: u64,
    pub assignment_generation: u32,
    pub rs_epoch_floor: u32,
    pub gk_epoch_current: u32,
    pub gk_epoch_next: u32,
    pub gk_current: [u8; 32],
    pub gk_next: [u8; 32],
    pub dams: [u8; 32],
    pub role: u8,
    pub gateway_count: u8,
    pub channel: u8,
    pub channel_epoch: u32,
    pub boot_witness: u32,
    pub gateways: [u64; SITE_GATEWAY_MAX],
    pub site_cert: Vec<u8>,
    pub member_cert: Vec<u8>,
}

fn zero(bytes: &[u8]) -> bool {
    bytes.iter().all(|&b| b == 0)
}

/// Same rules as `site_validate`.
pub fn site_validate(r: &SiteRecord) -> Result<()> {
    if r.state == SiteState::Cleared {
        if *r != SiteRecord::default() {
            return err(Code::InvalidArgument, "rls1 tombstone not empty");
        }
        return Ok(());
    }
    if !id_valid(r.site_id)
        || r.network == 0
        || r.network & 0xFFFF_FFFF == 0
        || r.assignment_generation == 0
    {
        return err(Code::InvalidArgument, "rls1 identity");
    }
    if r.gk_epoch_current == 0 || zero(&r.gk_current) || zero(&r.dams) {
        return err(Code::InvalidArgument, "rls1 keys");
    }
    if r.gk_epoch_next == 0 {
        if !zero(&r.gk_next) {
            return err(Code::InvalidArgument, "rls1 gk_next residue");
        }
    } else if r.gk_epoch_next <= r.gk_epoch_current || zero(&r.gk_next) {
        return err(Code::InvalidArgument, "rls1 gk_next");
    }
    if r.role == 0
        || u32::from(r.role) & !MEMBER_ROLE_MASK != 0
        || !(1..=14).contains(&r.channel)
        || r.gateway_count < 1
        || usize::from(r.gateway_count) > SITE_GATEWAY_MAX
    {
        return err(Code::InvalidArgument, "rls1 fields");
    }
    let count = usize::from(r.gateway_count);
    for (i, &gateway) in r.gateways.iter().enumerate() {
        if i < count {
            if !id_valid(gateway) {
                return err(Code::InvalidArgument, "rls1 gateway id");
            }
            if r.gateways[i + 1..count].contains(&gateway) {
                return err(Code::InvalidArgument, "rls1 gateway duplicated");
            }
        } else if gateway != 0 {
            return err(Code::InvalidArgument, "rls1 gateway tail");
        }
    }
    if r.site_cert.is_empty()
        || r.site_cert.len() > CERT_MAX
        || r.member_cert.is_empty()
        || r.member_cert.len() > CERT_MAX
    {
        return err(Code::InvalidArgument, "rls1 cert lengths");
    }
    let site = cert_decode(&r.site_cert)?;
    let member = cert_decode(&r.member_cert)?;
    let site_epoch = (r.network >> 32) as u32;
    if site.cert_type != CertType::Site
        || member.cert_type != CertType::Member
        || site.subject != r.site_id
        || site.network_low32 != (r.network & 0xFFFF_FFFF) as u32
        || site.site_epoch != site_epoch
        || member.issuer != r.site_id
        || member.network != r.network
        || member.assignment_generation != r.assignment_generation
        || member.role != u32::from(r.role)
    {
        return err(Code::IntegrityError, "rls1 certificate mismatch");
    }
    Ok(())
}

pub fn site_record_encode(r: &SiteRecord, seal: u32, commit_seq: u32) -> Result<Vec<u8>> {
    site_validate(r)?;
    if seal != super::SEAL_PENDING && seal != SITE_SEAL_COMMITTED {
        return err(Code::InvalidArgument, "rls1 seal value");
    }
    let mut out = begin_record(SITE_MAGIC, seal);
    out.extend_from_slice(&commit_seq.to_be_bytes());
    out.extend_from_slice(&r.site_id.to_be_bytes());
    out.extend_from_slice(&r.network.to_be_bytes());
    for value in [
        r.assignment_generation,
        r.rs_epoch_floor,
        r.gk_epoch_current,
        r.gk_epoch_next,
    ] {
        out.extend_from_slice(&value.to_be_bytes());
    }
    out.extend_from_slice(&r.gk_current);
    out.extend_from_slice(&r.gk_next);
    out.extend_from_slice(&r.dams);
    out.extend_from_slice(&[r.state as u8, r.role, r.gateway_count, r.channel]);
    out.extend_from_slice(&r.channel_epoch.to_be_bytes());
    out.extend_from_slice(&r.boot_witness.to_be_bytes());
    for gateway in r.gateways {
        out.extend_from_slice(&gateway.to_be_bytes());
    }
    out.extend_from_slice(&(r.site_cert.len() as u16).to_be_bytes());
    out.extend_from_slice(&(r.member_cert.len() as u16).to_be_bytes());
    out.extend_from_slice(&r.site_cert);
    out.extend_from_slice(&r.member_cert);
    Ok(finish_record(out))
}

/// Committed record → `(record, commit_seq)`.
pub fn site_record_decode(record: &[u8]) -> Result<(SiteRecord, u32)> {
    let mut reader = read_record(
        record,
        SITE_MAGIC,
        SITE_SEAL_COMMITTED,
        SITE_RECORD_MIN,
        SITE_RECORD_MAX,
    )?;
    let commit_seq = reader.u32()?;
    let mut r = SiteRecord {
        site_id: reader.u64()?,
        network: reader.u64()?,
        assignment_generation: reader.u32()?,
        rs_epoch_floor: reader.u32()?,
        gk_epoch_current: reader.u32()?,
        gk_epoch_next: reader.u32()?,
        gk_current: reader.array()?,
        gk_next: reader.array()?,
        dams: reader.array()?,
        ..SiteRecord::default()
    };
    r.state = match reader.u8()? {
        0 => SiteState::Cleared,
        1 => SiteState::Member,
        _ => return err(Code::ProtocolError, "rls1 structure"),
    };
    r.role = reader.u8()?;
    r.gateway_count = reader.u8()?;
    r.channel = reader.u8()?;
    r.channel_epoch = reader.u32()?;
    r.boot_witness = reader.u32()?;
    for gateway in r.gateways.iter_mut() {
        *gateway = reader.u64()?;
    }
    let site_len = usize::from(reader.u16()?);
    let member_len = usize::from(reader.u16()?);
    if site_len > CERT_MAX || member_len > CERT_MAX || reader.remaining() != site_len + member_len {
        return err(Code::ProtocolError, "rls1 structure");
    }
    r.site_cert = reader.bytes(site_len)?.to_vec();
    r.member_cert = reader.bytes(member_len)?.to_vec();
    site_validate(&r).map_err(|e| {
        Error::new(
            if e.code == Code::InvalidArgument {
                Code::ProtocolError
            } else {
                e.code
            },
            e.detail,
        )
    })?;
    Ok((r, commit_seq))
}

/// 02 §10.2 step 2: the MemberCert names this device.
pub fn site_matches_identity(site: &SiteRecord, identity: &IdentityRecord) -> Result<()> {
    if site.state != SiteState::Member {
        return err(Code::InvalidState, "rls1 not member");
    }
    let member = cert_decode(&site.member_cert)?;
    let site_claims = cert_decode(&site.site_cert)?;
    member_cert_matches(&member, &site_claims, identity.node_id, &identity.pubkey)
}
