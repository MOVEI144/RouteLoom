//! SDK v1 zero-touch join: EDHOC External Authorization Data codecs — the
//! host mirror of `components/routeloom/{include/routeloom/sdkv1_ead.hpp,
//! src/sdkv1_ead.cpp}` (docs/design/sdk-v1/02-zero-touch-join.md §6.1/§6.2,
//! 04-removal-revocation.md §6.1; plan P2-3).
//!
//! The Site Authority (EDHOC Responder, `routeloom-host`, plan P3-3) reads
//! the device's `JoinIntent` (EAD_1) and `JoinRequest` (EAD_3) and writes
//! the `SiteOffer` (EAD_2) and `JoinResult` (EAD_4, with the MemberCert,
//! `SitePackage` and — for a removed device — the SAK-signed
//! `RemovalNotice`). The device-side checks are mirrored too so both ends
//! can be tested against the same vectors.
//!
//! EAD item: `-label (critical) || bstr(value)`, labels 65537..65540 —
//! outside the IANA EDHOC EAD registry range (0..65535, which has no
//! private-use block), so no registered item can collide. Values are
//! fixed-width big-endian; reserved bytes and undefined flags are zero.
//! Label 65541 (P3-1) carries the peer's RLCW1 certificate in EAD_2
//! (SiteCert) and EAD_3 (DevCert) because ID_CRED_x is a kid reference
//! (`join_ead_find_with_credential`, `join_credential_check`).
//!
//! `protocol/sdkv1-golden/ead/` (independent generator
//! `tools/gen_sdkv1_ead_vectors.py`) pins every byte; this crate re-signs
//! each RemovalNotice with RFC 6979 and must match the generator exactly.
//!
//! Scope, honestly: codecs and field checks only. No EDHOC, no transport
//! and no Site Authority state machine; the AssignmentTicket (A2) format is
//! not pinned by the design yet, so it is carried as bounded opaque bytes
//! and a strict (A2) device fails closed.

use routeloom_provision::sdkv1::cert::{
    cert_decode, cert_verify, member_cert_matches, CertClaims, CertType, CERT_MAX,
    MEMBER_ROLE_GATEWAY, MEMBER_ROLE_MASK, MEMBER_ROLE_RELAY,
};
use routeloom_provision::sdkv1::revocation::RevocationReason;
use routeloom_provision::sdkv1::{
    cose_es256_assemble, cose_es256_parse, cose_es256_sig_structure, cose_es256_sign,
    cose_es256_verify,
};
use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::RootSigner;
use routeloom_provision::{Code, Error, Result};

fn err<T>(code: Code, detail: &'static str) -> Result<T> {
    Err(Error::new(code, detail))
}

fn malformed<T>(detail: &'static str) -> Result<T> {
    err(Code::ProtocolError, detail)
}

fn id_valid(id: u64) -> bool {
    id != 0 && id != u64::MAX
}

pub const JOIN_EAD_VERSION: u8 = 1;
pub const JOIN_EAD_LABEL_SIZE: usize = 5;

/// Absolute EAD label values; the wire carries `-label` (critical).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum JoinEad {
    Intent = 65537,
    Offer = 65538,
    Request = 65539,
    Result = 65540,
    /// P3-1 (02 §3 "Resolved in implementation"): libedhoc cannot carry
    /// `ID_CRED_x = {13: CWT}` by value, so ID_CRED_x is the kid (SHA-256 of
    /// the cnf COSE_Key) and the full RLCW1 certificate rides this critical
    /// item after the message item: the SiteCert in EAD_2 (the Site
    /// Authority writes it), the DevCert in EAD_3 (the Site Authority reads
    /// it before authenticating the device).
    Credential = 65541,
}

impl JoinEad {
    /// The four per-message items (the Credential item is separate).
    pub const ALL: [JoinEad; 4] = [Self::Intent, Self::Offer, Self::Request, Self::Result];

    fn value_size_ok(self, size: usize) -> bool {
        match self {
            Self::Intent => size == JOIN_INTENT_SIZE,
            Self::Offer => size == SITE_OFFER_SIZE,
            Self::Request => size == JOIN_REQUEST_SIZE,
            Self::Result => (JOIN_RESULT_HEAD_SIZE..=JOIN_RESULT_MAX).contains(&size),
            Self::Credential => (1..=CERT_MAX).contains(&size),
        }
    }
}

/// Big-endian cursor; a short read is a ProtocolError.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    fn bytes(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.pos + count > self.data.len() {
            return malformed("join ead truncated");
        }
        let out = &self.data[self.pos..self.pos + count];
        self.pos += count;
        Ok(out)
    }
    fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        Ok(self.bytes(N)?.try_into().expect("length checked"))
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.bytes(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.array()?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.array()?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.array()?))
    }
    /// `ver | flags` prefix: unknown version is Unsupported, flags zero.
    fn version_flags(&mut self, what: &'static str) -> Result<()> {
        let version = self.u8()?;
        let flags = self.u8()?;
        if version != JOIN_EAD_VERSION {
            return err(Code::Unsupported, what);
        }
        if flags != 0 {
            return malformed(what);
        }
        Ok(())
    }
    fn end(&self, what: &'static str) -> Result<()> {
        if self.pos != self.data.len() {
            return malformed(what);
        }
        Ok(())
    }
}

fn first4(bytes: &[u8]) -> u32 {
    let digest = sha256(bytes);
    u32::from_be_bytes(digest[..4].try_into().expect("4"))
}

/// 02 §5.1: `first4(SHA-256("RouteLoom/org-hint/v1" 00 || Site CA pubkey))`.
pub fn join_org_hint(site_ca_pubkey: &[u8; 64]) -> u32 {
    let mut input = b"RouteLoom/org-hint/v1\0".to_vec();
    input.extend_from_slice(site_ca_pubkey);
    first4(&input)
}

/// 02 §5.2: `first4(SHA-256("RouteLoom/site-hint/v1" 00 || site_id u64))`.
pub fn join_site_hint(site_id: u64) -> u32 {
    let mut input = b"RouteLoom/site-hint/v1\0".to_vec();
    input.extend_from_slice(&site_id.to_be_bytes());
    first4(&input)
}

// --- JoinIntent ----------------------------------------------------------------

pub const JOIN_INTENT_SIZE: usize = 12;
pub const JOIN_PROFILE_RLJOIN1: u32 = 1 << 0;
pub const JOIN_PROFILE_RLRES1: u32 = 1 << 1;
pub const JOIN_PROFILE_MASK: u32 = 0x3;

/// EAD_1 (plaintext): `ver | flags | org_hint u32 | profile_bits u32 | reserved u16`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinIntent {
    pub org_hint: u32,
    pub profile_bits: u32,
}

impl JoinIntent {
    pub fn validate(&self) -> Result<()> {
        if self.profile_bits & JOIN_PROFILE_RLJOIN1 == 0
            || self.profile_bits & !JOIN_PROFILE_MASK != 0
        {
            return malformed("join intent profile_bits");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; JOIN_INTENT_SIZE]> {
        self.validate()
            .map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
        let mut out = [0_u8; JOIN_INTENT_SIZE];
        out[0] = JOIN_EAD_VERSION;
        out[2..6].copy_from_slice(&self.org_hint.to_be_bytes());
        out[6..10].copy_from_slice(&self.profile_bits.to_be_bytes());
        Ok(out)
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        if value.len() != JOIN_INTENT_SIZE {
            return malformed("join intent size");
        }
        let mut r = Reader::new(value);
        r.version_flags("join intent head")?;
        let intent = Self {
            org_hint: r.u32()?,
            profile_bits: r.u32()?,
        };
        if r.u16()? != 0 {
            return malformed("join intent reserved");
        }
        r.end("join intent trailing")?;
        intent.validate()?;
        Ok(intent)
    }
}

// --- SiteOffer -------------------------------------------------------------------

pub const SITE_OFFER_SIZE: usize = 22;
pub const DECISION_TIMEOUT_MIN_MS: u16 = 500;
pub const DECISION_TIMEOUT_MAX_MS: u16 = 5000;

/// EAD_2: `ver | flags | site_id u64 | network_low32 u32 | site_epoch u32 |
/// decision_timeout_ms u16 | reserved u16` (22 B).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SiteOffer {
    pub site_id: u64,
    pub network_low32: u32,
    pub site_epoch: u32,
    pub decision_timeout_ms: u16,
}

impl SiteOffer {
    pub fn validate(&self) -> Result<()> {
        if !id_valid(self.site_id) {
            return malformed("site offer site_id");
        }
        if self.network_low32 == 0 {
            return malformed("site offer network_low32");
        }
        if !(DECISION_TIMEOUT_MIN_MS..=DECISION_TIMEOUT_MAX_MS).contains(&self.decision_timeout_ms)
        {
            return malformed("site offer decision_timeout_ms");
        }
        Ok(())
    }

    pub fn network(&self) -> u64 {
        (u64::from(self.site_epoch) << 32) | u64::from(self.network_low32)
    }

    /// The Site Authority builds its offer from its own SiteCert.
    pub fn from_site_cert(site_cert: &CertClaims, decision_timeout_ms: u16) -> Result<Self> {
        if site_cert.cert_type != CertType::Site {
            return err(Code::InvalidArgument, "site offer: not a SiteCert");
        }
        let offer = Self {
            site_id: site_cert.subject,
            network_low32: site_cert.network_low32,
            site_epoch: site_cert.site_epoch,
            decision_timeout_ms,
        };
        offer
            .validate()
            .map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
        Ok(offer)
    }

    pub fn encode(&self) -> Result<[u8; SITE_OFFER_SIZE]> {
        self.validate()
            .map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
        let mut out = [0_u8; SITE_OFFER_SIZE];
        out[0] = JOIN_EAD_VERSION;
        out[2..10].copy_from_slice(&self.site_id.to_be_bytes());
        out[10..14].copy_from_slice(&self.network_low32.to_be_bytes());
        out[14..18].copy_from_slice(&self.site_epoch.to_be_bytes());
        out[18..20].copy_from_slice(&self.decision_timeout_ms.to_be_bytes());
        Ok(out)
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        if value.len() != SITE_OFFER_SIZE {
            return malformed("site offer size");
        }
        let mut r = Reader::new(value);
        r.version_flags("site offer head")?;
        let offer = Self {
            site_id: r.u64()?,
            network_low32: r.u32()?,
            site_epoch: r.u32()?,
            decision_timeout_ms: r.u16()?,
        };
        if r.u16()? != 0 {
            return malformed("site offer reserved");
        }
        r.end("site offer trailing")?;
        offer.validate()?;
        Ok(offer)
    }

    /// Device, after authenticating m2: the offer names the SiteCert's
    /// site, network_low32 and site_epoch.
    pub fn matches_site_cert(&self, site_cert: &CertClaims) -> Result<()> {
        if site_cert.cert_type != CertType::Site {
            return err(Code::InvalidArgument, "site offer: not a SiteCert");
        }
        if self.site_id != site_cert.subject
            || self.network_low32 != site_cert.network_low32
            || self.site_epoch != site_cert.site_epoch
        {
            return err(
                Code::AuthorizationFailed,
                "site offer disagrees with SiteCert",
            );
        }
        Ok(())
    }
}

// --- JoinRequest ------------------------------------------------------------------

pub const JOIN_REQUEST_SIZE: usize = 26;
pub const JOIN_CAPABILITY_SLEEPY: u32 = 1 << 0;
pub const JOIN_CAPABILITY_RELAY: u32 = 1 << 1;
pub const JOIN_CAPABILITY_GATEWAY: u32 = 1 << 2;
pub const JOIN_CAPABILITY_MASK: u32 = 0x7;

/// EAD_3: `ver | flags | model u16 | fw_version u32 | capability u32 |
/// requested_role u8 | reserved u8 | last_site_id u64 | last_generation u32`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinRequest {
    pub model: u16,
    pub fw_version: u32,
    pub capability: u32,
    pub requested_role: u8,
    pub last_site_id: u64,
    pub last_generation: u32,
}

impl JoinRequest {
    pub fn validate(&self) -> Result<()> {
        if self.capability & !JOIN_CAPABILITY_MASK != 0 {
            return malformed("join request capability");
        }
        let role = u32::from(self.requested_role);
        if role == 0 || role & !MEMBER_ROLE_MASK != 0 {
            return malformed("join request role");
        }
        if role & MEMBER_ROLE_RELAY != 0 && self.capability & JOIN_CAPABILITY_RELAY == 0 {
            return malformed("join request relay role without capability");
        }
        if role & MEMBER_ROLE_GATEWAY != 0 && self.capability & JOIN_CAPABILITY_GATEWAY == 0 {
            return malformed("join request gateway role without capability");
        }
        if self.last_site_id == 0 {
            if self.last_generation != 0 {
                return malformed("join request last_generation");
            }
        } else if !id_valid(self.last_site_id) || self.last_generation == 0 {
            return malformed("join request last site");
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; JOIN_REQUEST_SIZE]> {
        self.validate()
            .map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
        let mut out = [0_u8; JOIN_REQUEST_SIZE];
        out[0] = JOIN_EAD_VERSION;
        out[2..4].copy_from_slice(&self.model.to_be_bytes());
        out[4..8].copy_from_slice(&self.fw_version.to_be_bytes());
        out[8..12].copy_from_slice(&self.capability.to_be_bytes());
        out[12] = self.requested_role;
        out[14..22].copy_from_slice(&self.last_site_id.to_be_bytes());
        out[22..26].copy_from_slice(&self.last_generation.to_be_bytes());
        Ok(out)
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        if value.len() != JOIN_REQUEST_SIZE {
            return malformed("join request size");
        }
        let mut r = Reader::new(value);
        r.version_flags("join request head")?;
        let model = r.u16()?;
        let fw_version = r.u32()?;
        let capability = r.u32()?;
        let requested_role = r.u8()?;
        if r.u8()? != 0 {
            return malformed("join request reserved");
        }
        let request = Self {
            model,
            fw_version,
            capability,
            requested_role,
            last_site_id: r.u64()?,
            last_generation: r.u32()?,
        };
        r.end("join request trailing")?;
        request.validate()?;
        Ok(request)
    }

    /// Site Authority, after verifying the DevCert from m3.
    pub fn matches_dev_cert(&self, dev_cert: &CertClaims) -> Result<()> {
        if dev_cert.cert_type != CertType::Device {
            return err(Code::InvalidArgument, "join request: not a DevCert");
        }
        if self.model != dev_cert.model {
            return err(
                Code::AuthorizationFailed,
                "join request model disagrees with DevCert",
            );
        }
        Ok(())
    }
}

// --- SitePackage --------------------------------------------------------------------

pub const SITE_PACKAGE_SIZE: usize = 120;
pub const SITE_PACKAGE_GATEWAY_MAX: usize = 4;

/// Allow body (02 §6.2), 120 B fixed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct SitePackage {
    pub site_id: u64,
    pub network: u64,
    pub rs_epoch: u32,
    pub gk_epoch: u32,
    pub gk: [u8; 32],
    pub channel: u8,
    pub role: u8,
    pub gateway_count: u8,
    pub channel_epoch: u32,
    pub gateways: [u64; SITE_PACKAGE_GATEWAY_MAX],
    pub authority_time_s: u64,
    pub time_uncertainty_ms: u32,
    pub membership_revision: u32,
}

impl SitePackage {
    pub fn validate(&self) -> Result<()> {
        if !id_valid(self.site_id) {
            return malformed("site package site_id");
        }
        if self.network & 0xFFFF_FFFF == 0 {
            return malformed("site package network");
        }
        if self.gk_epoch == 0 {
            return malformed("site package gk_epoch");
        }
        if self.gk.iter().all(|&b| b == 0) {
            return malformed("site package gk");
        }
        if !(1..=14).contains(&self.channel) {
            return malformed("site package channel");
        }
        if self.role == 0 || u32::from(self.role) & !MEMBER_ROLE_MASK != 0 {
            return malformed("site package role");
        }
        let count = usize::from(self.gateway_count);
        if !(1..=SITE_PACKAGE_GATEWAY_MAX).contains(&count) {
            return malformed("site package gateway_count");
        }
        for (i, &gateway) in self.gateways.iter().enumerate() {
            if i < count {
                if !id_valid(gateway) {
                    return malformed("site package gateway id");
                }
                if self.gateways[..i].contains(&gateway) {
                    return malformed("site package gateway duplicate");
                }
            } else if gateway != 0 {
                return malformed("site package gateway tail");
            }
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<[u8; SITE_PACKAGE_SIZE]> {
        self.validate()
            .map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
        let mut out = Vec::with_capacity(SITE_PACKAGE_SIZE);
        out.extend_from_slice(&[JOIN_EAD_VERSION, 0, 0, 0]);
        out.extend_from_slice(&self.site_id.to_be_bytes());
        out.extend_from_slice(&self.network.to_be_bytes());
        out.extend_from_slice(&self.rs_epoch.to_be_bytes());
        out.extend_from_slice(&self.gk_epoch.to_be_bytes());
        out.extend_from_slice(&self.gk);
        out.extend_from_slice(&[self.channel, self.role, self.gateway_count, 0]);
        out.extend_from_slice(&self.channel_epoch.to_be_bytes());
        for gateway in self.gateways {
            out.extend_from_slice(&gateway.to_be_bytes());
        }
        out.extend_from_slice(&self.authority_time_s.to_be_bytes());
        out.extend_from_slice(&self.time_uncertainty_ms.to_be_bytes());
        out.extend_from_slice(&self.membership_revision.to_be_bytes());
        out.extend_from_slice(&0_u32.to_be_bytes());
        Ok(out.try_into().expect("120 bytes"))
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SITE_PACKAGE_SIZE {
            return malformed("site package size");
        }
        let mut r = Reader::new(bytes);
        r.version_flags("site package head")?;
        if r.u16()? != 0 {
            return malformed("site package reserved");
        }
        let site_id = r.u64()?;
        let network = r.u64()?;
        let rs_epoch = r.u32()?;
        let gk_epoch = r.u32()?;
        let gk = r.array()?;
        let channel = r.u8()?;
        let role = r.u8()?;
        let gateway_count = r.u8()?;
        if r.u8()? != 0 {
            return malformed("site package reserved");
        }
        let channel_epoch = r.u32()?;
        let mut gateways = [0_u64; SITE_PACKAGE_GATEWAY_MAX];
        for gateway in &mut gateways {
            *gateway = r.u64()?;
        }
        let package = Self {
            site_id,
            network,
            rs_epoch,
            gk_epoch,
            gk,
            channel,
            role,
            gateway_count,
            channel_epoch,
            gateways,
            authority_time_s: r.u64()?,
            time_uncertainty_ms: r.u32()?,
            membership_revision: r.u32()?,
        };
        if r.u32()? != 0 {
            return malformed("site package reserved");
        }
        r.end("site package trailing")?;
        package.validate()?;
        Ok(package)
    }
}

// --- RemovalNotice --------------------------------------------------------------------

pub const REMOVAL_NOTICE_PAYLOAD_SIZE: usize = 28;
pub const REMOVAL_NOTICE_OBJECT_SIZE: usize = 7 + 2 + REMOVAL_NOTICE_PAYLOAD_SIZE + 2 + 64; // 103
pub const REMOVAL_NOTICE_DOMAIN: &[u8] = b"RouteLoom/removal-notice/v1";

/// 04 §6.1 payload: `ver | reason | reserved u16 | site_id u64 | node_id u64 |
/// generation u32 | rs_epoch u32`, signed by the SAK.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RemovalNotice {
    pub reason: RevocationReason,
    pub site_id: u64,
    pub node_id: u64,
    pub generation: u32,
    pub rs_epoch: u32,
}

fn reason_from_u8(value: u8) -> Option<RevocationReason> {
    Some(match value {
        1 => RevocationReason::Removed,
        2 => RevocationReason::Lost,
        3 => RevocationReason::Replaced,
        4 => RevocationReason::Blocked,
        _ => return None,
    })
}

/// `"RouteLoom/removal-notice/v1" 00 || network u64` (36 B).
pub fn removal_notice_aad(network: u64) -> Vec<u8> {
    let mut out = REMOVAL_NOTICE_DOMAIN.to_vec();
    out.push(0);
    out.extend_from_slice(&network.to_be_bytes());
    out
}

impl RemovalNotice {
    pub fn validate(&self) -> Result<()> {
        if !id_valid(self.site_id) {
            return malformed("removal notice site_id");
        }
        if !id_valid(self.node_id) {
            return malformed("removal notice node_id");
        }
        if self.generation == 0 {
            return malformed("removal notice generation");
        }
        if self.rs_epoch == 0 {
            return malformed("removal notice rs_epoch");
        }
        Ok(())
    }

    pub fn payload_encode(&self) -> Result<[u8; REMOVAL_NOTICE_PAYLOAD_SIZE]> {
        self.validate()
            .map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
        let mut out = [0_u8; REMOVAL_NOTICE_PAYLOAD_SIZE];
        out[0] = JOIN_EAD_VERSION;
        out[1] = self.reason as u8;
        out[4..12].copy_from_slice(&self.site_id.to_be_bytes());
        out[12..20].copy_from_slice(&self.node_id.to_be_bytes());
        out[20..24].copy_from_slice(&self.generation.to_be_bytes());
        out[24..28].copy_from_slice(&self.rs_epoch.to_be_bytes());
        Ok(out)
    }

    pub fn payload_decode(payload: &[u8]) -> Result<Self> {
        if payload.len() != REMOVAL_NOTICE_PAYLOAD_SIZE {
            return malformed("removal notice payload size");
        }
        let mut r = Reader::new(payload);
        if r.u8()? != JOIN_EAD_VERSION {
            return err(Code::Unsupported, "removal notice version");
        }
        let reason = r.u8()?;
        if r.u16()? != 0 {
            return malformed("removal notice reserved");
        }
        let Some(reason) = reason_from_u8(reason) else {
            return malformed("removal notice reason");
        };
        let notice = Self {
            reason,
            site_id: r.u64()?,
            node_id: r.u64()?,
            generation: r.u32()?,
            rs_epoch: r.u32()?,
        };
        r.end("removal notice trailing")?;
        notice.validate()?;
        Ok(notice)
    }

    /// `["Signature1", h'a10126', aad(network), payload]`.
    pub fn sig_structure(&self, network: u64) -> Result<Vec<u8>> {
        Ok(cose_es256_sig_structure(
            &self.payload_encode()?,
            &removal_notice_aad(network),
        ))
    }

    /// Sign with the SAK (RFC 6979, low-S) and assemble the 103 B Sign1.
    pub fn issue(&self, network: u64, sak: &dyn RootSigner) -> Result<Vec<u8>> {
        let payload = self.payload_encode()?;
        let signature = cose_es256_sign(sak, &payload, &removal_notice_aad(network))?;
        Ok(cose_es256_assemble(&payload, &signature))
    }

    pub fn assemble(payload: &[u8], signature: &[u8; 64]) -> Result<Vec<u8>> {
        Self::payload_decode(payload).map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
        Ok(cose_es256_assemble(payload, signature))
    }

    /// Structure only (envelope + payload), no signature.
    pub fn decode(object: &[u8]) -> Result<Self> {
        let parts = cose_es256_parse(
            object,
            REMOVAL_NOTICE_PAYLOAD_SIZE,
            REMOVAL_NOTICE_PAYLOAD_SIZE,
            REMOVAL_NOTICE_OBJECT_SIZE,
        )?;
        Self::payload_decode(parts.payload)
    }

    /// Device acceptance (04 §6.1), from its own RLS1: signature under the
    /// SAK with the AAD bound to `own_network`, own site and node,
    /// generation >= own MemberCert generation. `Ok((notice, verified))`;
    /// only `verified` may erase site state.
    pub fn verify(
        object: &[u8],
        sak_pubkey: &[u8; 64],
        own_site_id: u64,
        own_network: u64,
        own_node: u64,
        own_generation: u32,
    ) -> Result<(Self, bool)> {
        let parts = cose_es256_parse(
            object,
            REMOVAL_NOTICE_PAYLOAD_SIZE,
            REMOVAL_NOTICE_PAYLOAD_SIZE,
            REMOVAL_NOTICE_OBJECT_SIZE,
        )?;
        let notice = Self::payload_decode(parts.payload)?;
        if notice.site_id != own_site_id
            || notice.node_id != own_node
            || notice.generation < own_generation
        {
            return Ok((notice, false));
        }
        let verified = cose_es256_verify(
            parts.payload,
            &removal_notice_aad(own_network),
            &parts.signature,
            sak_pubkey,
        );
        Ok((notice, verified))
    }
}

// --- JoinResult ---------------------------------------------------------------------

pub const JOIN_RESULT_HEAD_SIZE: usize = 12;
pub const PENDING_TICKET_MAX: usize = 48;
pub const ASSIGNMENT_TICKET_MAX: usize = 128;
pub const JOIN_ALLOW_BODY_MIN: usize = 2 + 1 + SITE_PACKAGE_SIZE + 2;
pub const JOIN_ALLOW_BODY_MAX: usize = 2 + CERT_MAX + SITE_PACKAGE_SIZE + 2 + ASSIGNMENT_TICKET_MAX;
pub const JOIN_RESULT_MAX: usize = JOIN_RESULT_HEAD_SIZE + JOIN_ALLOW_BODY_MAX; // 520
pub const PENDING_RETRY_MIN_S: u32 = 30;
pub const RETRY_AFTER_MAX_S: u32 = 3600;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum JoinVerdict {
    Allow = 1,
    PendingAssignment = 2,
    DenyNotHere = 3,
    DenyBlocked = 4,
    Removed = 5,
    AuthorityBusy = 6,
}

/// EAD_4: `ver | verdict | reason u16 = 0 | retry_after_s u32 | body_len u16 |
/// reserved u16` + verdict body. Each variant carries exactly its fields,
/// so the retry/body rules of 02 §6.1 hold by construction (validate
/// checks ranges and body shapes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum JoinResult {
    Allow {
        member_cert: Vec<u8>,
        site_package: SitePackage,
        /// A2 AssignmentTicket (opaque, <= 128 B); empty in A1.
        assignment_ticket: Vec<u8>,
    },
    PendingAssignment {
        retry_after_s: u32,
        ticket: Vec<u8>,
    },
    DenyNotHere,
    DenyBlocked,
    Removed {
        removal_notice: Vec<u8>,
    },
    AuthorityBusy {
        retry_after_s: u32,
    },
}

impl JoinResult {
    pub fn verdict(&self) -> JoinVerdict {
        match self {
            Self::Allow { .. } => JoinVerdict::Allow,
            Self::PendingAssignment { .. } => JoinVerdict::PendingAssignment,
            Self::DenyNotHere => JoinVerdict::DenyNotHere,
            Self::DenyBlocked => JoinVerdict::DenyBlocked,
            Self::Removed { .. } => JoinVerdict::Removed,
            Self::AuthorityBusy { .. } => JoinVerdict::AuthorityBusy,
        }
    }

    pub fn retry_after_s(&self) -> u32 {
        match self {
            Self::PendingAssignment { retry_after_s, .. }
            | Self::AuthorityBusy { retry_after_s } => *retry_after_s,
            _ => 0,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Allow {
                member_cert,
                site_package,
                assignment_ticket,
            } => {
                if member_cert.is_empty() || member_cert.len() > CERT_MAX {
                    return malformed("join result membercert length");
                }
                if cert_decode(member_cert)?.cert_type != CertType::Member {
                    return malformed("join result not a MemberCert");
                }
                site_package.validate()?;
                if assignment_ticket.len() > ASSIGNMENT_TICKET_MAX {
                    return malformed("join result assignment ticket length");
                }
            }
            Self::PendingAssignment {
                retry_after_s,
                ticket,
            } => {
                if !(PENDING_RETRY_MIN_S..=RETRY_AFTER_MAX_S).contains(retry_after_s) {
                    return malformed("join result retry_after_s");
                }
                if ticket.is_empty() || ticket.len() > PENDING_TICKET_MAX {
                    return malformed("join result pending ticket length");
                }
            }
            Self::AuthorityBusy { retry_after_s } => {
                if !(1..=RETRY_AFTER_MAX_S).contains(retry_after_s) {
                    return malformed("join result retry_after_s");
                }
            }
            Self::Removed { removal_notice } => {
                RemovalNotice::decode(removal_notice)?;
            }
            Self::DenyNotHere | Self::DenyBlocked => {}
        }
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()
            .map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
        let mut body = Vec::new();
        match self {
            Self::Allow {
                member_cert,
                site_package,
                assignment_ticket,
            } => {
                body.extend_from_slice(&(member_cert.len() as u16).to_be_bytes());
                body.extend_from_slice(member_cert);
                body.extend_from_slice(&site_package.encode()?);
                body.extend_from_slice(&(assignment_ticket.len() as u16).to_be_bytes());
                body.extend_from_slice(assignment_ticket);
            }
            Self::PendingAssignment { ticket, .. } => body.extend_from_slice(ticket),
            Self::Removed { removal_notice } => body.extend_from_slice(removal_notice),
            Self::DenyNotHere | Self::DenyBlocked | Self::AuthorityBusy { .. } => {}
        }
        let mut out = Vec::with_capacity(JOIN_RESULT_HEAD_SIZE + body.len());
        out.push(JOIN_EAD_VERSION);
        out.push(self.verdict() as u8);
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&self.retry_after_s().to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(&0_u16.to_be_bytes());
        out.extend_from_slice(&body);
        if out.len() > JOIN_RESULT_MAX {
            return err(Code::InvalidArgument, "join result size");
        }
        Ok(out)
    }

    pub fn decode(value: &[u8]) -> Result<Self> {
        if !(JOIN_RESULT_HEAD_SIZE..=JOIN_RESULT_MAX).contains(&value.len()) {
            return malformed("join result size");
        }
        let mut r = Reader::new(value);
        let version = r.u8()?;
        let verdict = r.u8()?;
        let reason = r.u16()?;
        let retry_after_s = r.u32()?;
        let body_len = usize::from(r.u16()?);
        let reserved = r.u16()?;
        if version != JOIN_EAD_VERSION {
            return err(Code::Unsupported, "join result version");
        }
        if !(1..=6).contains(&verdict)
            || reason != 0
            || reserved != 0
            || body_len != value.len() - JOIN_RESULT_HEAD_SIZE
        {
            return malformed("join result head");
        }
        let body = &value[JOIN_RESULT_HEAD_SIZE..];
        let empty = |result: Self| -> Result<Self> {
            if !body.is_empty() {
                return malformed("join result body on an empty verdict");
            }
            Ok(result)
        };
        let result = match verdict {
            1 => {
                if body.len() < JOIN_ALLOW_BODY_MIN {
                    return malformed("join result allow body");
                }
                let cert_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
                if cert_len == 0
                    || cert_len > CERT_MAX
                    || 2 + cert_len + SITE_PACKAGE_SIZE + 2 > body.len()
                {
                    return malformed("join result membercert length");
                }
                let member_cert = body[2..2 + cert_len].to_vec();
                let mut pos = 2 + cert_len;
                let site_package = SitePackage::decode(&body[pos..pos + SITE_PACKAGE_SIZE])?;
                pos += SITE_PACKAGE_SIZE;
                let ticket_len = usize::from(u16::from_be_bytes([body[pos], body[pos + 1]]));
                pos += 2;
                if ticket_len > ASSIGNMENT_TICKET_MAX || pos + ticket_len != body.len() {
                    return malformed("join result assignment ticket length");
                }
                Self::Allow {
                    member_cert,
                    site_package,
                    assignment_ticket: body[pos..].to_vec(),
                }
            }
            2 => Self::PendingAssignment {
                retry_after_s,
                ticket: body.to_vec(),
            },
            3 => empty(Self::DenyNotHere)?,
            4 => empty(Self::DenyBlocked)?,
            5 => Self::Removed {
                removal_notice: body.to_vec(),
            },
            _ => empty(Self::AuthorityBusy { retry_after_s })?,
        };
        // Verdicts that carry no retry must have sent 0.
        if result.retry_after_s() != retry_after_s {
            return malformed("join result retry_after_s");
        }
        result.validate()?;
        Ok(result)
    }
}

/// 02 §10.2 on the device side (mirrored for the Site Authority's own
/// self-check and the shared vectors): `Ok((member, verified))`. A result
/// that is not an Allow is InvalidArgument; A2 (`strict_assignment`) with
/// a ticket present is Unsupported (format not pinned; fail closed), and
/// without one is `verified == false`.
pub fn join_allow_verify(
    result: &JoinResult,
    site_cert: &CertClaims,
    node: u64,
    device_pubkey: &[u8; 64],
    strict_assignment: bool,
) -> Result<(CertClaims, bool)> {
    let JoinResult::Allow {
        member_cert,
        site_package,
        assignment_ticket,
    } = result
    else {
        return err(Code::InvalidArgument, "join allow verify arguments");
    };
    if site_cert.cert_type != CertType::Site {
        return err(Code::InvalidArgument, "join allow verify arguments");
    }
    result.validate()?;
    let (member, signature_ok) = cert_verify(member_cert, &site_cert.pubkey)?;
    if !signature_ok || member_cert_matches(&member, site_cert, node, device_pubkey).is_err() {
        return Ok((member, false));
    }
    if site_package.site_id != site_cert.subject
        || site_package.network != member.network
        || u32::from(site_package.role) != member.role
    {
        return Ok((member, false));
    }
    if strict_assignment {
        if assignment_ticket.is_empty() {
            return Ok((member, false));
        }
        return err(Code::Unsupported, "assignment ticket format not pinned");
    }
    Ok((member, true))
}

// --- EAD items and fields -------------------------------------------------------------

pub const JOIN_EAD_ITEM_MAX: usize = JOIN_EAD_LABEL_SIZE + 3 + JOIN_RESULT_MAX; // 528
pub const JOIN_EAD_FIELD_MAX: usize = 1024;

/// One critical item: `-label || bstr(value)`.
pub fn join_ead_item_encode(label: JoinEad, value: &[u8]) -> Result<Vec<u8>> {
    if !label.value_size_ok(value.len()) {
        return err(Code::InvalidArgument, "ead value size");
    }
    let mut out = Vec::with_capacity(JOIN_EAD_LABEL_SIZE + 3 + value.len());
    out.push(0x3A);
    out.extend_from_slice(&(label as u32 - 1).to_be_bytes());
    routeloom_provision::cbor::write_bstr(&mut out, value);
    Ok(out)
}

/// Canonical major-0/1 integer: `(negative, argument)`.
fn read_int(ead: &[u8], pos: &mut usize) -> Result<(bool, u64)> {
    let Some(&ib) = ead.get(*pos) else {
        return malformed("ead label");
    };
    *pos += 1;
    let major = ib >> 5;
    if major > 1 {
        return malformed("ead label");
    }
    let info = ib & 0x1F;
    if info <= 23 {
        return Ok((major == 1, u64::from(info)));
    }
    let (bytes, minimum): (usize, u64) = match info {
        24 => (1, 24),
        25 => (2, 0x100),
        26 => (4, 0x1_0000),
        27 => (8, 0x1_0000_0000),
        _ => return malformed("ead label"),
    };
    if *pos + bytes > ead.len() {
        return malformed("ead label");
    }
    let argument = ead[*pos..*pos + bytes]
        .iter()
        .fold(0_u64, |acc, &b| (acc << 8) | u64::from(b));
    *pos += bytes;
    if argument < minimum {
        return malformed("ead label non-canonical");
    }
    Ok((major == 1, argument))
}

/// Strict EAD field parse: exactly one critical `expected` item with a
/// canonical bstr value of the item's size; padding (label 0, RFC 9528
/// §3.8.1) is skipped; any other item or trailing byte is rejected.
pub fn join_ead_find(ead: &[u8], expected: JoinEad) -> Result<&[u8]> {
    if ead.is_empty() || ead.len() > JOIN_EAD_FIELD_MAX {
        return malformed("ead field bounds");
    }
    if expected == JoinEad::Credential {
        // Only the four message items stand alone (device: join_ead_known).
        return malformed("ead unexpected critical item");
    }
    let mut found: Option<&[u8]> = None;
    let mut pos = 0;
    while pos < ead.len() {
        let (negative, argument) = read_int(ead, &mut pos)?;
        let mut value: Option<&[u8]> = None;
        if pos < ead.len() && ead[pos] >> 5 == 2 {
            value = Some(
                routeloom_provision::cbor::read_bstr(ead, &mut pos, "ead value")
                    .map_err(|e| Error::new(Code::ProtocolError, e.detail))?,
            );
        }
        if !negative && argument == 0 {
            continue; // padding
        }
        let label = if negative {
            argument.wrapping_add(1)
        } else {
            argument
        };
        if !negative || label != u64::from(expected as u32) {
            return malformed(if negative {
                "ead unexpected critical item"
            } else {
                "ead unexpected item"
            });
        }
        if found.is_some() {
            return malformed("ead item duplicated");
        }
        match value {
            Some(v) if expected.value_size_ok(v.len()) => found = Some(v),
            _ => return malformed("ead value size"),
        }
    }
    found.ok_or(Error::new(Code::ProtocolError, "ead item missing"))
}

// --- EDHOC binding (P3-3, provisional) ------------------------------------------------
//
// libedhoc v2.3.2 (the device backend) cannot carry `ID_CRED_x = {13 (kcwt):
// CWT}` by value, so the join references both credentials by kid
// (`ID_CRED_x = {4: kid}`, kid = SHA-256 of the cnf COSE_Key, the RLC1 rule)
// and ships the RLCW1 certificate itself in one more EAD item: the SiteCert
// in EAD_2, the DevCert in EAD_3. CRED_x (what EDHOC MACs and signs) is that
// certificate's bytes, so a substituted certificate fails Signature_2/3.
//
// The device side (sdkv1_ead.hpp, P3-1) uses the same label; both are pinned
// by the shared vectors in protocol/sdkv1-golden/ead and the EDHOC interop
// transcripts (a mismatch fails closed: the device refuses the unknown
// critical item).

/// Absolute EAD label of the "RLCW1 certificate by value" item (sent
/// critical, `-65541`), next after the four join items.
pub const JOIN_EAD_CREDENTIAL_LABEL: u32 = JoinEad::Credential as u32;

/// One critical credential item: `-JOIN_EAD_CREDENTIAL_LABEL || bstr(cert)`.
/// The value must be one canonical RLCW1 certificate (<= 256 B).
pub fn join_ead_credential_item(cert: &[u8]) -> Result<Vec<u8>> {
    cert_decode(cert).map_err(|e| Error::new(Code::InvalidArgument, e.detail))?;
    let mut out = Vec::with_capacity(JOIN_EAD_LABEL_SIZE + 3 + cert.len());
    out.push(0x3A);
    out.extend_from_slice(&(JOIN_EAD_CREDENTIAL_LABEL - 1).to_be_bytes());
    routeloom_provision::cbor::write_bstr(&mut out, cert);
    Ok(out)
}

/// EDHOC Exporter label of DAMS, the device–authority master secret
/// (03 §2.1, private use).
pub const EXPORTER_LABEL_DAMS: u64 = 32771;
/// DAMS length (03 §2.1).
pub const DAMS_SIZE: usize = 32;
/// Exporter `purpose` of the authority channel (03 §2 rule 3).
pub const EXPORTER_PURPOSE_AUTHORITY: u64 = 4;

/// PROVISIONAL Exporter context for DAMS. 05 §5 fixes the shape of the
/// RouteLoom context (a deterministic CBOR array starting `'RouteLoom', 1,
/// purpose, network, initiator_node, responder_node, initiator_kid,
/// responder_kid, …`) but not the join's trailing fields, so this uses its
/// first eight members only: `["RouteLoom", 1, 4, network, node, site_id,
/// device_kid, sak_kid]` (`responder_node = site_id`, 03 §2.2). The device
/// side must derive DAMS with the same bytes; pin both in a shared vector
/// before P5 uses DAMS.
pub fn dams_exporter_context(
    network: u64,
    node: u64,
    site_id: u64,
    device_kid: &[u8; 32],
    sak_kid: &[u8; 32],
) -> Vec<u8> {
    use routeloom_provision::cbor::{write_bstr, write_uint};
    let mut out = vec![0x88, 0x69];
    out.extend_from_slice(b"RouteLoom");
    write_uint(&mut out, 1);
    write_uint(&mut out, EXPORTER_PURPOSE_AUTHORITY);
    write_uint(&mut out, network);
    write_uint(&mut out, node);
    write_uint(&mut out, site_id);
    write_bstr(&mut out, device_kid);
    write_bstr(&mut out, sak_kid);
    out
}

/// Largest Credential item: label 5 + bstr head 3 + certificate 256.
pub const JOIN_CREDENTIAL_ITEM_MAX: usize = JOIN_EAD_LABEL_SIZE + 3 + CERT_MAX;

/// EAD_2 / EAD_3 with the certificate (P3-1): exactly the `expected` message
/// item (Offer or Request) then `Credential`, both critical with canonical
/// bstr values, once each; padding is skipped; anything else, another
/// order or a trailing byte is rejected. Returns `(certificate, value)`.
pub fn join_ead_find_with_credential(ead: &[u8], expected: JoinEad) -> Result<(&[u8], &[u8])> {
    if expected != JoinEad::Offer && expected != JoinEad::Request {
        return err(Code::InvalidArgument, "credential rides EAD_2/EAD_3 only");
    }
    if ead.is_empty() || ead.len() > JOIN_EAD_FIELD_MAX {
        return malformed("ead field bounds");
    }
    let mut found: Vec<&[u8]> = Vec::with_capacity(2);
    let mut pos = 0;
    while pos < ead.len() {
        let (negative, argument) = read_int(ead, &mut pos)?;
        let mut value: Option<&[u8]> = None;
        if pos < ead.len() && ead[pos] >> 5 == 2 {
            value = Some(
                routeloom_provision::cbor::read_bstr(ead, &mut pos, "ead value")
                    .map_err(|e| Error::new(Code::ProtocolError, e.detail))?,
            );
        }
        if !negative && argument == 0 {
            continue; // padding
        }
        if !negative {
            return malformed("ead unexpected item");
        }
        let want = match found.len() {
            0 => expected,
            1 => JoinEad::Credential,
            _ => return malformed("ead item after the credential"),
        };
        if argument.wrapping_add(1) != u64::from(want as u32) {
            return malformed("ead message item or credential out of order");
        }
        match value {
            Some(v) if want.value_size_ok(v.len()) => found.push(v),
            _ => return malformed("ead value size"),
        }
    }
    if found.len() != 2 {
        return malformed("ead item missing");
    }
    Ok((found[1], found[0]))
}

/// The certificate of a Credential item: one canonical RLCW1 certificate of
/// `cert_type` whose cnf key hashes to `kid` (the ID_CRED_x kid of the same
/// message). Malformed -> ProtocolError; wrong type or kid ->
/// AuthorizationFailed (the C++ device side: AuthenticationFailed; this
/// crate has no separate authentication code). Signature and chain stay the caller's check (the
/// Site Authority verifies the DevCert under the Device CA).
pub fn join_credential_check(cert: &[u8], cert_type: CertType, kid: &[u8]) -> Result<CertClaims> {
    let claims = cert_decode(cert)?;
    if claims.cert_type != cert_type {
        return err(Code::AuthorizationFailed, "credential certificate type");
    }
    if routeloom_provision::credential::credential_kid(&claims.pubkey).as_slice() != kid {
        return err(
            Code::AuthorizationFailed,
            "credential does not match the kid",
        );
    }
    Ok(claims)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_item_and_dams_context_shapes() {
        use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
        use routeloom_provision::signer::{test_keypair, FileRootSigner};
        let (ca_secret, _) = test_keypair(0x41);
        let (_, device_pub) = test_keypair(0x42);
        let claims = CertClaims {
            cert_type: CertType::Device,
            issuer: 0x0DCA_0000_0000_0001,
            subject: 0x00A1_0000_0000_1234,
            pubkey: device_pub,
            model: 17,
            hw_rev: 2,
            serial: 9,
            ..CertClaims::default()
        };
        let signer = FileRootSigner::from_secret(claims.issuer, &ca_secret).unwrap();
        let cert = cert_issue(&claims, &signer).unwrap();
        let item = join_ead_credential_item(&cert).unwrap();
        assert_eq!(&item[..5], &[0x3A, 0x00, 0x01, 0x00, 0x04]);
        assert_eq!(item.len(), 5 + 2 + cert.len());
        assert!(join_ead_credential_item(&[0x40]).is_err());
        // The strict per-message parser keeps refusing a second item: the
        // Site Authority splits the credential item off before using it.
        let mut field = join_ead_item_encode(JoinEad::Request, &[0; JOIN_REQUEST_SIZE]).unwrap();
        field.extend_from_slice(&item);
        assert!(join_ead_find(&field, JoinEad::Request).is_err());
        let context = dams_exporter_context((1 << 32) | 7, 2, 3, &[4; 32], &[5; 32]);
        assert_eq!(&context[..11], b"\x88\x69RouteLoom");
        assert_eq!(context.len(), 11 + 1 + 1 + 9 + 1 + 1 + 34 + 34);
    }

    #[test]
    fn labels_are_outside_the_registry_and_critical() {
        for label in JoinEad::ALL {
            assert!(label as u32 > 65535);
        }
        let item = join_ead_item_encode(JoinEad::Intent, &[0; JOIN_INTENT_SIZE]).unwrap();
        assert_eq!(&item[..6], &[0x3A, 0x00, 0x01, 0x00, 0x00, 0x4C]);
    }

    #[test]
    fn encoders_refuse_what_decoders_refuse() {
        let intent = JoinIntent {
            org_hint: 1,
            profile_bits: 0,
        };
        assert_eq!(intent.encode().unwrap_err().code, Code::InvalidArgument);
        let pending = JoinResult::PendingAssignment {
            retry_after_s: 10,
            ticket: vec![1],
        };
        assert_eq!(pending.encode().unwrap_err().code, Code::InvalidArgument);
        assert_eq!(
            JoinResult::DenyNotHere.encode().unwrap(),
            [1, 3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(join_ead_item_encode(JoinEad::Offer, &[0; 24]).is_err());
    }

    #[test]
    fn size_constants_match_the_device() {
        assert_eq!(REMOVAL_NOTICE_OBJECT_SIZE, 103);
        assert_eq!(JOIN_RESULT_MAX, 520);
        assert_eq!(JOIN_EAD_ITEM_MAX, 528);
        assert_eq!(removal_notice_aad(0).len(), 36);
    }
}
