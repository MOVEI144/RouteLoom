//! SDK v1 key schedule — the host mirror of
//! `components/routeloom/{include/routeloom/key_schedule.hpp,src/key_schedule.cpp}`
//! and the RLRES1 message codecs/transcript of `rlres1.cpp`
//! (docs/design/sdk-v1/03-key-hierarchy.md §2.2/§3/§5.3/§6.1,
//! 06-fast-rejoin.md §2.1; plan P1-4).
//!
//! The labels and `info` encodings here are FROZEN: both this crate and the
//! C++ core must reproduce `protocol/sdkv1-golden/derivations/` byte for
//! byte, and those files come from the independent Python generator
//! `tools/gen_sdkv1_derivation_vectors.py`.
//!
//! Encoding rule: `info = ASCII label || 0x00 || fixed-width big-endian
//! fields`, every label `"RouteLoom/v1/<name>"`; a 28-byte expansion is
//! `key16 || iv12`; the AEAD nonce is `iv XOR (zero6 || counter u48)`.
//!
//! Scope, honestly: derivations and codecs only — no AEAD, no EDHOC and no
//! resume state machine (the Site Authority's responder arrives with P5).
//! RouteLoom's own constructions are unreviewed until plan P8-2.

pub mod authority;
pub mod rlres1;

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

pub const LABEL_GROUP_SALT: &str = "RouteLoom/v1/group";
pub const LABEL_BCAST_LINK: &str = "RouteLoom/v1/bcast-link";
pub const LABEL_GROUP_END: &str = "RouteLoom/v1/group-end";
pub const LABEL_DSK_MEMBER: &str = "RouteLoom/v1/dsk-member";
pub const LABEL_RESUME_ID: &str = "RouteLoom/v1/rid";
pub const LABEL_RESUME_AUTH: &str = "RouteLoom/v1/resume-auth";
pub const LABEL_RESUME_BINDING: &str = "RouteLoom/v1/resume-binding";
pub const LABEL_RESUME_R1: &str = "RouteLoom/v1/R1";
pub const LABEL_RESUME_R2: &str = "RouteLoom/v1/R2";
pub const LABEL_RESUME_R3: &str = "RouteLoom/v1/R3";
pub const LABEL_RESUME_CONFIRM: &str = "RouteLoom/v1/resume-confirm";
pub const LABEL_RESUME_KEY: &str = "RouteLoom/v1/resume-key";
/// Authority channel (03 §5.3, G-SEC P5): GK-id binds (network, epoch, GK)
/// for ACK key confirmation. Never a raw-GK export.
pub const LABEL_GK_ID: &str = "RouteLoom/v1/gk-id";

/// EDHOC Exporter labels (private use, 03 §2.1); consumed by plan P2.
pub const EXPORTER_AEAD_KEY: u32 = 32768;
pub const EXPORTER_BASE_IV: u32 = 32769;
pub const EXPORTER_RESUME_MASTER: u32 = 32770;
pub const EXPORTER_DAMS: u32 = 32771;
pub const EXPORTER_PENDING: u32 = 32772;

pub const MAX_AEAD_COUNTER: u64 = (1 << 48) - 1;

/// Exporter-context / RLRES1 purpose (03 §2 rule 3). `Usb` is never an RLRES1 purpose.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Purpose {
    Link = 1,
    End = 2,
    Usb = 3,
    Authority = 4,
    PendingJoin = 5,
}

impl Purpose {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Link),
            2 => Some(Self::End),
            3 => Some(Self::Usb),
            4 => Some(Self::Authority),
            5 => Some(Self::PendingJoin),
            _ => None,
        }
    }
}

/// RLRES1 traffic direction byte in the resume-key info.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Direction {
    InitiatorToResponder = 1,
    ResponderToInitiator = 2,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TrafficKey {
    pub key: [u8; 16],
    pub iv: [u8; 12],
}

/// `label || 0x00 || fields...`
pub fn info(label: &str, fields: &[&[u8]]) -> Vec<u8> {
    let mut out =
        Vec::with_capacity(label.len() + 1 + fields.iter().map(|f| f.len()).sum::<usize>());
    out.extend_from_slice(label.as_bytes());
    out.push(0);
    for field in fields {
        out.extend_from_slice(field);
    }
    out
}

pub fn hmac_sha256(key: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    for part in parts {
        mac.update(part);
    }
    mac.finalize().into_bytes().into()
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut hash = Sha256::new();
    for part in parts {
        hash.update(part);
    }
    hash.finalize().into()
}

pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), ikm);
    prk.into()
}

fn expand<const N: usize>(prk: &[u8; 32], info: &[u8]) -> [u8; N] {
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("32-byte PRK");
    let mut out = [0_u8; N];
    hk.expand(info, &mut out).expect("N <= 255 * 32");
    out
}

fn expand_key_iv(prk: &[u8; 32], info: &[u8]) -> TrafficKey {
    let okm: [u8; 28] = expand(prk, info);
    let mut key = TrafficKey::default();
    key.key.copy_from_slice(&okm[..16]);
    key.iv.copy_from_slice(&okm[16..]);
    key
}

/// `iv XOR (zero6 || counter u48)`; `None` above 2^48-1 (retire the key, never wrap).
pub fn aead_nonce(iv: &[u8; 12], counter: u64) -> Option<[u8; 12]> {
    if counter > MAX_AEAD_COUNTER {
        return None;
    }
    let mut out = *iv;
    for (slot, byte) in out[6..].iter_mut().zip(&counter.to_be_bytes()[2..]) {
        *slot ^= byte;
    }
    Some(out)
}

// --- network group key (03 §6.1) -------------------------------------------

/// `PRK_g = HKDF-Extract(salt = "RouteLoom/v1/group" 0x00 || network u64, GK_g)`
pub fn group_prk(network: u64, gk: &[u8; 32]) -> [u8; 32] {
    hkdf_extract(&info(LABEL_GROUP_SALT, &[&network.to_be_bytes()]), gk)
}

pub fn group_bcast_info(gk_epoch: u32, tx: u64, tx_boot: u32) -> Vec<u8> {
    info(
        LABEL_BCAST_LINK,
        &[
            &gk_epoch.to_be_bytes(),
            &tx.to_be_bytes(),
            &tx_boot.to_be_bytes(),
        ],
    )
}

pub fn group_end_info(gk_epoch: u32, group_id: u64, origin: u64, session: u32) -> Vec<u8> {
    info(
        LABEL_GROUP_END,
        &[
            &gk_epoch.to_be_bytes(),
            &group_id.to_be_bytes(),
            &origin.to_be_bytes(),
            &session.to_be_bytes(),
        ],
    )
}

pub fn group_dsk_info(gk_epoch: u32) -> Vec<u8> {
    info(LABEL_DSK_MEMBER, &[&gk_epoch.to_be_bytes()])
}

pub fn group_bcast_key(prk: &[u8; 32], gk_epoch: u32, tx: u64, tx_boot: u32) -> TrafficKey {
    expand_key_iv(prk, &group_bcast_info(gk_epoch, tx, tx_boot))
}

pub fn group_end_key(
    prk: &[u8; 32],
    gk_epoch: u32,
    group_id: u64,
    origin: u64,
    session: u32,
) -> TrafficKey {
    expand_key_iv(prk, &group_end_info(gk_epoch, group_id, origin, session))
}

pub fn group_dsk_key(prk: &[u8; 32], gk_epoch: u32) -> [u8; 32] {
    expand(prk, &group_dsk_info(gk_epoch))
}

// --- RLRES1 derivations (06 §2.1) --------------------------------------------

/// `rid = first8(HMAC(RMS, "RouteLoom/v1/rid" 0x00 || purpose))`
pub fn resume_id(rms: &[u8; 32], purpose: Purpose) -> [u8; 8] {
    let mac = hmac_sha256(rms, &[&info(LABEL_RESUME_ID, &[&[purpose as u8]])]);
    let mut out = [0_u8; 8];
    out.copy_from_slice(&mac[..8]);
    out
}

pub fn resume_auth_info(purpose: Purpose, network: u64, node_i: u64, node_r: u64) -> Vec<u8> {
    info(
        LABEL_RESUME_AUTH,
        &[
            &[purpose as u8],
            &network.to_be_bytes(),
            &node_i.to_be_bytes(),
            &node_r.to_be_bytes(),
        ],
    )
}

/// `K_auth = HKDF(salt = "RouteLoom/v1/resume-auth", RMS, resume_auth_info, 32)`.
/// `node_r` is the responder NodeId (link/end) or the site_id (authority/pending).
pub fn resume_auth_key(
    rms: &[u8; 32],
    purpose: Purpose,
    network: u64,
    node_i: u64,
    node_r: u64,
) -> [u8; 32] {
    let prk = hkdf_extract(LABEL_RESUME_AUTH.as_bytes(), rms);
    expand(&prk, &resume_auth_info(purpose, network, node_i, node_r))
}

pub fn resume_binding_routed(purpose: Purpose, node_i: u64, node_r: u64) -> [u8; 32] {
    sha256(&[&info(
        LABEL_RESUME_BINDING,
        &[
            &[purpose as u8],
            &node_i.to_be_bytes(),
            &node_r.to_be_bytes(),
        ],
    )])
}

pub fn resume_binding_link(
    mac_i: &[u8; 6],
    mac_r: &[u8; 6],
    carrier_digest: &[u8; 32],
) -> [u8; 32] {
    sha256(&[&info(
        LABEL_RESUME_BINDING,
        &[&[Purpose::Link as u8], mac_i, mac_r, carrier_digest],
    )])
}

/// `PRK = HKDF-Extract(salt = nonce_I || nonce_R, IKM = RMS)`
pub fn resume_prk(nonce_i: &[u8; 16], nonce_r: &[u8; 16], rms: &[u8; 32]) -> [u8; 32] {
    let mut salt = [0_u8; 32];
    salt[..16].copy_from_slice(nonce_i);
    salt[16..].copy_from_slice(nonce_r);
    hkdf_extract(&salt, rms)
}

pub fn resume_confirm_key(prk: &[u8; 32], th: &[u8; 32]) -> [u8; 32] {
    expand(prk, &info(LABEL_RESUME_CONFIRM, &[th]))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResumeKeyContext {
    pub purpose: Purpose,
    pub network: u64,
    pub node_i: u64,
    pub node_r: u64,
    pub cid_i: u32,
    pub cid_r: u32,
}

pub fn resume_key_info(context: &ResumeKeyContext, direction: Direction, th: &[u8; 32]) -> Vec<u8> {
    info(
        LABEL_RESUME_KEY,
        &[
            &[context.purpose as u8, direction as u8],
            &context.network.to_be_bytes(),
            &context.node_i.to_be_bytes(),
            &context.node_r.to_be_bytes(),
            &context.cid_i.to_be_bytes(),
            &context.cid_r.to_be_bytes(),
            th,
        ],
    )
}

pub fn resume_traffic_key(
    prk: &[u8; 32],
    context: &ResumeKeyContext,
    direction: Direction,
    th: &[u8; 32],
) -> TrafficKey {
    expand_key_iv(prk, &resume_key_info(context, direction, th))
}

/// `first16(HMAC(key, label 0x00 || parts...))` — mac_I / mac_R / mac_I3.
pub fn resume_mac(key: &[u8], label: &str, parts: &[&[u8]]) -> [u8; 16] {
    let head = info(label, &[]);
    let mut all: Vec<&[u8]> = Vec::with_capacity(parts.len() + 1);
    all.push(&head);
    all.extend_from_slice(parts);
    let mac = hmac_sha256(key, &all);
    let mut out = [0_u8; 16];
    out.copy_from_slice(&mac[..16]);
    out
}

// --- AuthorityEnvelope (03 §5.3) ---------------------------------------------

pub const AUTHORITY_ENVELOPE_VERSION: u8 = 1;
pub const AUTHORITY_ENVELOPE_HEADER: usize = 12;
pub const AUTHORITY_ENVELOPE_MIN: usize = AUTHORITY_ENVELOPE_HEADER + 16;
pub const AUTHORITY_ENVELOPE_MAX: usize = 2048;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorityEnvelopeHeader {
    pub version: u8,
    /// 1 JoinConfirm .. 8 TimeSample
    pub env_type: u8,
    pub ctx_id: u32,
    pub counter: u64,
}

/// Decode refusal reasons, shared with the C++ `keys::DecodeError` and the
/// golden `reason` strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated,
    Oversized,
    LengthMismatch,
    BadPurpose,
    UnsupportedFlags,
    ReservedNonZero,
    ZeroContextId,
    TicketLength,
    BadStatus,
    BadVersion,
    BadType,
}

impl DecodeError {
    pub fn name(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::Oversized => "oversized",
            Self::LengthMismatch => "length_mismatch",
            Self::BadPurpose => "bad_purpose",
            Self::UnsupportedFlags => "unsupported_flags",
            Self::ReservedNonZero => "reserved_nonzero",
            Self::ZeroContextId => "zero_context_id",
            Self::TicketLength => "ticket_length",
            Self::BadStatus => "bad_status",
            Self::BadVersion => "bad_version",
            Self::BadType => "bad_type",
        }
    }
}

impl AuthorityEnvelopeHeader {
    /// The 12-byte header, which is also the AEAD AAD. `None` for invalid fields.
    pub fn encode(&self) -> Option<[u8; AUTHORITY_ENVELOPE_HEADER]> {
        if self.version != AUTHORITY_ENVELOPE_VERSION
            || !(1..=8).contains(&self.env_type)
            || self.ctx_id == 0
            || self.counter > MAX_AEAD_COUNTER
        {
            return None;
        }
        let mut out = [0_u8; AUTHORITY_ENVELOPE_HEADER];
        out[0] = self.version;
        out[1] = self.env_type;
        out[2..6].copy_from_slice(&self.ctx_id.to_be_bytes());
        out[6..].copy_from_slice(&self.counter.to_be_bytes()[2..]);
        Some(out)
    }

    /// Validates a whole envelope (header + ciphertext + 16-byte tag).
    pub fn decode(envelope: &[u8]) -> Result<Self, DecodeError> {
        if envelope.len() < AUTHORITY_ENVELOPE_MIN {
            return Err(DecodeError::Truncated);
        }
        if envelope.len() > AUTHORITY_ENVELOPE_MAX {
            return Err(DecodeError::Oversized);
        }
        if envelope[0] != AUTHORITY_ENVELOPE_VERSION {
            return Err(DecodeError::BadVersion);
        }
        if !(1..=8).contains(&envelope[1]) {
            return Err(DecodeError::BadType);
        }
        let ctx_id = u32::from_be_bytes(envelope[2..6].try_into().expect("4 bytes"));
        if ctx_id == 0 {
            return Err(DecodeError::ZeroContextId);
        }
        let mut counter = [0_u8; 8];
        counter[2..].copy_from_slice(&envelope[6..12]);
        Ok(Self {
            version: envelope[0],
            env_type: envelope[1],
            ctx_id,
            counter: u64::from_be_bytes(counter),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    /// RFC 5869 A.1 through the same `hkdf` path the derivations use.
    #[test]
    fn rfc5869_case_1() {
        let ikm = [0x0b_u8; 22];
        let salt = hex("000102030405060708090a0b0c");
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            prk.to_vec(),
            hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5")
        );
        let okm: [u8; 42] = expand(&prk, &hex("f0f1f2f3f4f5f6f7f8f9"));
        assert_eq!(
            okm.to_vec(),
            hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
        );
    }

    #[test]
    fn nonce_refuses_wrap() {
        assert!(aead_nonce(&[0; 12], MAX_AEAD_COUNTER + 1).is_none());
        assert_eq!(aead_nonce(&[0; 12], 1).expect("ok")[11], 1);
    }
}
