//! RLCW1 certificates (docs/design/sdk-v1/02-zero-touch-join.md §3) — the
//! mirror of `components/routeloom/src/rlcw1.cpp`. A certificate is a CWT
//! in a tagged, restricted ES256 COSE_Sign1:
//!
//! ```text
//! d2 84 43 a1 01 26 a0 58 <len> <payload> 58 40 <R || S>
//! payload = a4 01 <iss> 02 <sub> 08 a1 01 <COSE_Key 77 B>
//!              3a 00 01 00 00 <private claim array>
//! DevCert    [1, model u16, hw_rev u8, serial u32]
//! SiteCert   [2, network_low32 u32, site_epoch u32, usage u8, serial u32]
//! MemberCert [3, network u64, role u32, assignment_generation u32,
//!             site_epoch u32, serial u32]
//! ```
//!
//! Canonical CBOR only, no unknown claims (no exp/nbf), no trailing bytes,
//! at most [`CERT_MAX`] bytes; Sig_structure has an empty external AAD and
//! signatures must be low-S.

use crate::cbor;
use crate::credential::credential_cose_key_encode;
use crate::image::pubkey_on_curve;
use crate::signer::RootSigner;
use crate::{err, Code, Result};

use super::{
    cose_es256_assemble, cose_es256_parse, cose_es256_sig_structure, cose_es256_sign,
    cose_es256_verify, id_valid,
};

pub const CERT_MAX: usize = 256;
pub const CERT_PAYLOAD_MAX: usize = 137;
/// Largest certificate with the v1 role bits.
pub const CERT_LARGEST: usize = 208;

pub const SITE_USAGE_AUTHORITY: u8 = 0x01;
pub const SITE_USAGE_MASK: u8 = 0x01;
pub const MEMBER_ROLE_ENDPOINT: u32 = 1 << 0;
pub const MEMBER_ROLE_RELAY: u32 = 1 << 1;
pub const MEMBER_ROLE_GATEWAY: u32 = 1 << 2;
pub const MEMBER_ROLE_MASK: u32 = 0x7;

const PRIVATE_LABEL: [u8; 5] = [0x3A, 0x00, 0x01, 0x00, 0x00];
const CNF_HEAD: [u8; 3] = [0xA1, 0x01, 0xA5];

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[repr(u8)]
pub enum CertType {
    #[default]
    Device = 1,
    Site = 2,
    Member = 3,
}

impl CertType {
    fn from_u8(value: u8) -> Option<Self> {
        Some(match value {
            1 => Self::Device,
            2 => Self::Site,
            3 => Self::Member,
            _ => return None,
        })
    }
    fn array_len(self) -> u8 {
        match self {
            Self::Device => 4,
            Self::Site => 5,
            Self::Member => 6,
        }
    }
}

/// One certificate's claims. Fields the type does not carry must be zero.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CertClaims {
    pub cert_type: CertType,
    pub issuer: u64,
    pub subject: u64,
    pub pubkey: [u8; 64],
    pub model: u16,
    pub hw_rev: u8,
    pub network_low32: u32,
    pub usage: u8,
    pub network: u64,
    pub role: u32,
    pub assignment_generation: u32,
    pub site_epoch: u32,
    pub serial: u32,
}

impl Default for CertClaims {
    fn default() -> Self {
        Self {
            cert_type: CertType::Device,
            issuer: 0,
            subject: 0,
            pubkey: [0; 64],
            model: 0,
            hw_rev: 0,
            network_low32: 0,
            usage: 0,
            network: 0,
            role: 0,
            assignment_generation: 0,
            site_epoch: 0,
            serial: 0,
        }
    }
}

/// Field rules (same as `cert_claims_validate`).
pub fn cert_claims_validate(c: &CertClaims) -> Result<()> {
    if !id_valid(c.issuer) || !id_valid(c.subject) {
        return err(Code::InvalidArgument, "cert issuer/subject");
    }
    if !pubkey_on_curve(&c.pubkey) {
        return err(Code::InvalidArgument, "cert key off curve");
    }
    match c.cert_type {
        CertType::Device => {
            if c.network_low32 != 0
                || c.usage != 0
                || c.network != 0
                || c.role != 0
                || c.assignment_generation != 0
                || c.site_epoch != 0
            {
                return err(Code::InvalidArgument, "devcert foreign field");
            }
        }
        CertType::Site => {
            if c.model != 0
                || c.hw_rev != 0
                || c.network != 0
                || c.role != 0
                || c.assignment_generation != 0
            {
                return err(Code::InvalidArgument, "sitecert foreign field");
            }
            if c.network_low32 == 0 || c.usage == 0 || c.usage & !SITE_USAGE_MASK != 0 {
                return err(Code::InvalidArgument, "sitecert fields");
            }
        }
        CertType::Member => {
            if c.model != 0 || c.hw_rev != 0 || c.network_low32 != 0 || c.usage != 0 {
                return err(Code::InvalidArgument, "membercert foreign field");
            }
            if c.network & 0xFFFF_FFFF == 0
                || (c.network >> 32) as u32 != c.site_epoch
                || c.role == 0
                || c.role & !MEMBER_ROLE_MASK != 0
                || c.assignment_generation == 0
            {
                return err(Code::InvalidArgument, "membercert fields");
            }
        }
    }
    Ok(())
}

pub fn cert_payload_encode(c: &CertClaims) -> Result<Vec<u8>> {
    cert_claims_validate(c)?;
    let mut out = Vec::with_capacity(CERT_PAYLOAD_MAX);
    out.push(0xA4);
    out.push(0x01);
    cbor::write_uint(&mut out, c.issuer);
    out.push(0x02);
    cbor::write_uint(&mut out, c.subject);
    out.push(0x08);
    out.extend_from_slice(&[0xA1, 0x01]);
    out.extend_from_slice(&credential_cose_key_encode(&c.pubkey));
    out.extend_from_slice(&PRIVATE_LABEL);
    out.push(0x80 + c.cert_type.array_len());
    cbor::write_uint(&mut out, c.cert_type as u64);
    match c.cert_type {
        CertType::Device => {
            cbor::write_uint(&mut out, u64::from(c.model));
            cbor::write_uint(&mut out, u64::from(c.hw_rev));
        }
        CertType::Site => {
            cbor::write_uint(&mut out, u64::from(c.network_low32));
            cbor::write_uint(&mut out, u64::from(c.site_epoch));
            cbor::write_uint(&mut out, u64::from(c.usage));
        }
        CertType::Member => {
            cbor::write_uint(&mut out, c.network);
            cbor::write_uint(&mut out, u64::from(c.role));
            cbor::write_uint(&mut out, u64::from(c.assignment_generation));
            cbor::write_uint(&mut out, u64::from(c.site_epoch));
        }
    }
    cbor::write_uint(&mut out, u64::from(c.serial));
    Ok(out)
}

fn expect(body: &[u8], pos: &mut usize, bytes: &[u8], what: &'static str) -> Result<()> {
    if *pos + bytes.len() > body.len() || &body[*pos..*pos + bytes.len()] != bytes {
        return err(Code::ProtocolError, what);
    }
    *pos += bytes.len();
    Ok(())
}

fn uint(body: &[u8], pos: &mut usize, max: u64, what: &'static str) -> Result<u64> {
    let value = cbor::read_uint(body, pos, what)?;
    if value > max {
        return err(Code::ProtocolError, what);
    }
    Ok(value)
}

/// Strict payload decode: the exact canonical shape, then the field rules.
pub fn cert_payload_decode(payload: &[u8]) -> Result<CertClaims> {
    if payload.len() > CERT_PAYLOAD_MAX {
        return err(Code::ProtocolError, "cert payload bounds");
    }
    let mut c = CertClaims::default();
    let mut pos = 0;
    expect(payload, &mut pos, &[0xA4, 0x01], "cert claims map")?;
    c.issuer = uint(payload, &mut pos, u64::MAX, "cert iss")?;
    expect(payload, &mut pos, &[0x02], "cert sub label")?;
    c.subject = uint(payload, &mut pos, u64::MAX, "cert sub")?;
    expect(payload, &mut pos, &[0x08], "cert cnf label")?;
    expect(payload, &mut pos, &CNF_HEAD, "cert cnf")?;
    // The COSE_Key must be byte-identical to the canonical encoding of the
    // X || Y it carries; rebuild and compare.
    let key_start = pos - 1;
    expect(
        payload,
        &mut pos,
        &[0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20],
        "cert cnf key",
    )?;
    if pos + 32 + 3 + 32 > payload.len() {
        return err(Code::ProtocolError, "cert cnf truncated");
    }
    c.pubkey[..32].copy_from_slice(&payload[pos..pos + 32]);
    pos += 32;
    expect(payload, &mut pos, &[0x22, 0x58, 0x20], "cert cnf y label")?;
    c.pubkey[32..].copy_from_slice(&payload[pos..pos + 32]);
    pos += 32;
    debug_assert_eq!(
        &payload[key_start..pos],
        &credential_cose_key_encode(&c.pubkey)[..]
    );
    expect(payload, &mut pos, &PRIVATE_LABEL, "cert private label")?;
    if pos + 2 > payload.len() {
        return err(Code::ProtocolError, "cert private claim");
    }
    let (head, type_byte) = (payload[pos], payload[pos + 1]);
    let Some(cert_type) = CertType::from_u8(type_byte) else {
        return err(Code::ProtocolError, "cert private claim type");
    };
    if head != 0x80 + cert_type.array_len() {
        return err(Code::ProtocolError, "cert private claim type");
    }
    pos += 2;
    c.cert_type = cert_type;
    match cert_type {
        CertType::Device => {
            c.model = uint(payload, &mut pos, 0xFFFF, "devcert model")? as u16;
            c.hw_rev = uint(payload, &mut pos, 0xFF, "devcert hw_rev")? as u8;
        }
        CertType::Site => {
            c.network_low32 =
                uint(payload, &mut pos, 0xFFFF_FFFF, "sitecert network_low32")? as u32;
            c.site_epoch = uint(payload, &mut pos, 0xFFFF_FFFF, "sitecert site_epoch")? as u32;
            c.usage = uint(payload, &mut pos, 0xFF, "sitecert usage")? as u8;
        }
        CertType::Member => {
            c.network = uint(payload, &mut pos, u64::MAX, "membercert network")?;
            c.role = uint(payload, &mut pos, 0xFFFF_FFFF, "membercert role")? as u32;
            c.assignment_generation =
                uint(payload, &mut pos, 0xFFFF_FFFF, "membercert generation")? as u32;
            c.site_epoch = uint(payload, &mut pos, 0xFFFF_FFFF, "membercert site_epoch")? as u32;
        }
    }
    c.serial = uint(payload, &mut pos, 0xFFFF_FFFF, "cert serial")? as u32;
    if pos != payload.len() {
        return err(Code::ProtocolError, "cert payload trailing");
    }
    cert_claims_validate(&c).map_err(|e| crate::Error::new(Code::ProtocolError, e.detail))?;
    Ok(c)
}

/// Envelope + payload decode (no signature check).
pub fn cert_decode(cert: &[u8]) -> Result<CertClaims> {
    let parts = cose_es256_parse(cert, 1, CERT_PAYLOAD_MAX, CERT_MAX)?;
    cert_payload_decode(parts.payload)
}

pub fn cert_sig_structure(payload: &[u8]) -> Vec<u8> {
    cose_es256_sig_structure(payload, &[])
}

pub fn cert_assemble(payload: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>> {
    cert_payload_decode(payload)?;
    Ok(cose_es256_assemble(payload, signature))
}

/// Decode and verify under `issuer_pubkey`: `Ok((claims, verified))`.
/// Malformed certificates are errors; a bad or high-S signature is
/// `verified == false`.
pub fn cert_verify(cert: &[u8], issuer_pubkey: &[u8; 64]) -> Result<(CertClaims, bool)> {
    let parts = cose_es256_parse(cert, 1, CERT_PAYLOAD_MAX, CERT_MAX)?;
    let claims = cert_payload_decode(parts.payload)?;
    let verified = cose_es256_verify(parts.payload, &[], &parts.signature, issuer_pubkey);
    Ok((claims, verified))
}

/// Issue a certificate through the custody seam. The signer's id must be
/// the certificate's issuer (Device CA id, Site CA id, or site_id for the
/// SAK) — a mismatch is refused rather than minted.
pub fn cert_issue(claims: &CertClaims, signer: &dyn RootSigner) -> Result<Vec<u8>> {
    if signer.root_id() != claims.issuer {
        return err(
            Code::InvalidArgument,
            "signer is not the certificate issuer",
        );
    }
    let payload = cert_payload_encode(claims)?;
    let signature = cose_es256_sign(signer, &payload, &[])?;
    Ok(cose_es256_assemble(&payload, &signature))
}

/// 02 §10.2 steps 2-4: MemberCert names `node` and `device_pubkey` and
/// belongs to the SiteCert's site/network/epoch.
pub fn member_cert_matches(
    member: &CertClaims,
    site: &CertClaims,
    node: u64,
    device_pubkey: &[u8; 64],
) -> Result<()> {
    if member.cert_type != CertType::Member || site.cert_type != CertType::Site {
        return err(Code::InvalidArgument, "cert types");
    }
    cert_claims_validate(member)?;
    cert_claims_validate(site)?;
    if member.subject != node || &member.pubkey != device_pubkey {
        return err(Code::AuthorizationFailed, "membercert not ours");
    }
    if member.issuer != site.subject
        || (member.network & 0xFFFF_FFFF) as u32 != site.network_low32
        || member.site_epoch != site.site_epoch
    {
        return err(Code::AuthorizationFailed, "membercert not this site");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::signer::{test_keypair, FileRootSigner};

    fn member(pubkey: [u8; 64]) -> CertClaims {
        CertClaims {
            cert_type: CertType::Member,
            issuer: 0x5173_0000_0000_0042,
            subject: 0x00A1_0000_0000_1234,
            pubkey,
            network: (3 << 32) | 0x0A1B_2C3D,
            role: MEMBER_ROLE_ENDPOINT,
            assignment_generation: 3,
            site_epoch: 3,
            serial: 4412,
            ..CertClaims::default()
        }
    }

    #[test]
    fn issue_verify_roundtrip_and_issuer_binding() {
        let (sak_secret, sak_pub) = test_keypair(0x53);
        let (_, device_pub) = test_keypair(0x54);
        let claims = member(device_pub);
        let sak = FileRootSigner::from_secret(claims.issuer, &sak_secret).unwrap();
        let cert = cert_issue(&claims, &sak).unwrap();
        assert!(cert.len() <= CERT_LARGEST);
        let (decoded, verified) = cert_verify(&cert, &sak_pub).unwrap();
        assert!(verified);
        assert_eq!(decoded, claims);
        // Deterministic (RFC 6979): the same claims issue the same bytes.
        assert_eq!(cert_issue(&claims, &sak).unwrap(), cert);
        let other = FileRootSigner::from_secret(7, &sak_secret).unwrap();
        assert!(cert_issue(&claims, &other).is_err());
        let (_, device_pub_other) = test_keypair(0x56);
        let (_, verified) = cert_verify(&cert, &device_pub_other).unwrap();
        assert!(!verified);
    }

    #[test]
    fn field_rules() {
        let (_, device_pub) = test_keypair(0x54);
        let mut claims = member(device_pub);
        claims.site_epoch = 4;
        assert!(cert_payload_encode(&claims).is_err());
        let mut claims = member(device_pub);
        claims.model = 1;
        assert!(cert_payload_encode(&claims).is_err());
        let mut claims = member(device_pub);
        claims.role = 8;
        assert!(cert_payload_encode(&claims).is_err());
        let mut claims = member(device_pub);
        claims.subject = u64::MAX;
        assert!(cert_payload_encode(&claims).is_err());
    }
}
