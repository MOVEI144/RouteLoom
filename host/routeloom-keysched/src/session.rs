//! Member session wire — the host mirror of
//! `components/routeloom/{include/routeloom/sdkv1_session_wire.hpp,src/sdkv1_session_wire.cpp}`
//! and the P4 §5 digest helpers of `key_schedule.{hpp,cpp}`
//! (G-SEC P4 §5.1–§5.4).
//!
//! Layouts are FROZEN: this module, the C++ core and the Python
//! generator must reproduce `protocol/sdkv1-golden/handshake/` byte for
//! byte (test `tests/session_golden.rs`).

use super::{info, sha256, DecodeError};

pub const LABEL_LINK_CARRIER: &str = "RouteLoom/v1/link-carrier";
pub const LABEL_END_CARRIER: &str = "RouteLoom/v1/end-carrier";
pub const LABEL_SESSION_PROFILE: &str = "RouteLoom/v1/session-profile";
pub const LABEL_CONTEXT_CONFIRM: &str = "RouteLoom/v1/context-confirm";

/// RLD1 capability bits (P4 §5.1).
pub const RLD1_CAP_MEMBER_EDHOC_V1: u32 = 1 << 24;
pub const RLD1_CAP_MEMBER_RESUME_V1: u32 = 1 << 25;
pub const RLD1_CAP_DEV_RAM_SESSION_V1: u32 = 1 << 26;
pub const RLD1_CAP_P4_MASK: u32 =
    RLD1_CAP_MEMBER_EDHOC_V1 | RLD1_CAP_MEMBER_RESUME_V1 | RLD1_CAP_DEV_RAM_SESSION_V1;

/// Session EAD labels (critical) and value widths (P4 §5.3).
pub const EAD_SESSION_INTENT: i32 = -65542;
pub const EAD_SESSION_STATE: i32 = -65543;
pub const EAD_CONTEXT_CONFIRM: i32 = -65544;
pub const SESSION_INTENT_BYTES: usize = 44;
pub const SESSION_STATE_BYTES: usize = 24;
pub const SESSION_CONFIRM_BYTES: usize = 36;
pub const SESSION_PROFILE_MEMBER: u8 = 1;
pub const SESSION_PURPOSE_LINK: u8 = 1;
pub const SESSION_PURPOSE_END: u8 = 2;

/// Largest Exporter application context the profile encodes (P4 §5.4).
pub const EXPORTER_CONTEXT_MAX: usize = 256;

/// Refused builder inputs (encode side). Decode failures use [`DecodeError`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SessionError {
    Shape,
}

// --- carrier and session digests (P4 §5.2/§5.4) -------------------------------

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct LinkCarrier {
    pub network: u64,
    pub node_i: u64,
    pub node_r: u64,
    pub requester_nonce: [u8; 16],
    pub responder_nonce: [u8; 16],
    pub cookie: [u8; 16],
    pub capability_i: u32,
    pub capability_r: u32,
    pub scope_binding: [u8; 32],
}

pub fn link_carrier_digest(carrier: &LinkCarrier) -> [u8; 32] {
    sha256(&[&info(
        LABEL_LINK_CARRIER,
        &[
            &[1],
            &carrier.network.to_be_bytes(),
            &carrier.node_i.to_be_bytes(),
            &carrier.node_r.to_be_bytes(),
            &carrier.requester_nonce,
            &carrier.responder_nonce,
            &carrier.cookie,
            &carrier.capability_i.to_be_bytes(),
            &carrier.capability_r.to_be_bytes(),
            &carrier.scope_binding,
        ],
    )])
}

pub fn end_carrier_binding(network: u64, node_i: u64, node_r: u64, exchange_id: u32) -> [u8; 32] {
    sha256(&[&info(
        LABEL_END_CARRIER,
        &[
            &network.to_be_bytes(),
            &node_i.to_be_bytes(),
            &node_r.to_be_bytes(),
            &exchange_id.to_be_bytes(),
        ],
    )])
}

pub fn session_capability_digest(
    intent: &[u8],
    state_r: &[u8],
    state_i: &[u8],
) -> Result<[u8; 32], SessionError> {
    if intent.len() != SESSION_INTENT_BYTES
        || state_r.len() != SESSION_STATE_BYTES
        || state_i.len() != SESSION_STATE_BYTES
    {
        return Err(SessionError::Shape);
    }
    Ok(sha256(&[&info(
        LABEL_SESSION_PROFILE,
        &[intent, state_r, state_i],
    )]))
}

pub fn session_contexts_digest(
    dir1: &[u8],
    dir2: &[u8],
    rms: &[u8],
) -> Result<[u8; 32], SessionError> {
    for context in [dir1, dir2, rms] {
        if context.is_empty() || context.len() > EXPORTER_CONTEXT_MAX {
            return Err(SessionError::Shape);
        }
    }
    let mut parts: Vec<u8> = Vec::with_capacity(6 + dir1.len() + dir2.len() + rms.len());
    for context in [dir1, dir2, rms] {
        parts.extend_from_slice(&(context.len() as u16).to_be_bytes());
        parts.extend_from_slice(context);
    }
    Ok(sha256(&[&info(LABEL_CONTEXT_CONFIRM, &[&parts])]))
}

// --- session EAD values (P4 §5.3) ----------------------------------------------

fn head_ok(bytes: &[u8]) -> Option<(u8, u8)> {
    if bytes.len() < 4 || bytes[0] != 1 || bytes[3] != 0 {
        return None;
    }
    let (purpose, profile) = (bytes[1], bytes[2]);
    if purpose != SESSION_PURPOSE_LINK && purpose != SESSION_PURPOSE_END {
        return None;
    }
    if profile != SESSION_PROFILE_MEMBER {
        return None;
    }
    Some((purpose, profile))
}

fn head_put(out: &mut [u8], purpose: u8) {
    out[0] = 1;
    out[1] = purpose;
    out[2] = SESSION_PROFILE_MEMBER;
    out[3] = 0;
}

fn u32_at(bytes: &[u8], at: usize) -> u32 {
    u32::from_be_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]])
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionIntent {
    pub purpose: u8,
    pub profile: u8,
    pub caps_i: u32,
    pub boot_i: u32,
    pub binding: [u8; 32],
}

impl SessionIntent {
    pub fn encode(&self) -> Result<[u8; SESSION_INTENT_BYTES], SessionError> {
        if self.purpose != SESSION_PURPOSE_LINK && self.purpose != SESSION_PURPOSE_END {
            return Err(SessionError::Shape);
        }
        if self.profile != SESSION_PROFILE_MEMBER || self.boot_i == 0 || self.binding == [0; 32] {
            return Err(SessionError::Shape);
        }
        let mut out = [0_u8; SESSION_INTENT_BYTES];
        head_put(&mut out, self.purpose);
        out[4..8].copy_from_slice(&self.caps_i.to_be_bytes());
        out[8..12].copy_from_slice(&self.boot_i.to_be_bytes());
        out[12..44].copy_from_slice(&self.binding);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < SESSION_INTENT_BYTES {
            return Err(DecodeError::Truncated);
        }
        if bytes.len() > SESSION_INTENT_BYTES {
            return Err(DecodeError::Oversized);
        }
        let Some((purpose, profile)) = head_ok(bytes) else {
            return Err(DecodeError::BadVersion);
        };
        let mut binding = [0_u8; 32];
        binding.copy_from_slice(&bytes[12..44]);
        let intent = Self {
            purpose,
            profile,
            caps_i: u32_at(bytes, 4),
            boot_i: u32_at(bytes, 8),
            binding,
        };
        if intent.boot_i == 0 || intent.binding == [0; 32] {
            return Err(DecodeError::LengthMismatch);
        }
        Ok(intent)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SessionState {
    pub purpose: u8,
    pub profile: u8,
    pub site_epoch: u32,
    pub rs_epoch: u32,
    pub gk_epoch: u32,
    pub boot: u32,
    pub caps: u32,
}

impl SessionState {
    pub fn encode(&self) -> Result<[u8; SESSION_STATE_BYTES], SessionError> {
        if self.purpose != SESSION_PURPOSE_LINK && self.purpose != SESSION_PURPOSE_END {
            return Err(SessionError::Shape);
        }
        if self.profile != SESSION_PROFILE_MEMBER || self.boot == 0 {
            return Err(SessionError::Shape);
        }
        let mut out = [0_u8; SESSION_STATE_BYTES];
        head_put(&mut out, self.purpose);
        out[4..8].copy_from_slice(&self.site_epoch.to_be_bytes());
        out[8..12].copy_from_slice(&self.rs_epoch.to_be_bytes());
        out[12..16].copy_from_slice(&self.gk_epoch.to_be_bytes());
        out[16..20].copy_from_slice(&self.boot.to_be_bytes());
        out[20..24].copy_from_slice(&self.caps.to_be_bytes());
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < SESSION_STATE_BYTES {
            return Err(DecodeError::Truncated);
        }
        if bytes.len() > SESSION_STATE_BYTES {
            return Err(DecodeError::Oversized);
        }
        let Some((purpose, profile)) = head_ok(bytes) else {
            return Err(DecodeError::BadVersion);
        };
        let state = Self {
            purpose,
            profile,
            site_epoch: u32_at(bytes, 4),
            rs_epoch: u32_at(bytes, 8),
            gk_epoch: u32_at(bytes, 12),
            boot: u32_at(bytes, 16),
            caps: u32_at(bytes, 20),
        };
        if state.boot == 0 {
            return Err(DecodeError::LengthMismatch);
        }
        Ok(state)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ContextConfirm {
    pub purpose: u8,
    pub profile: u8,
    pub contexts_digest: [u8; 32],
}

impl ContextConfirm {
    pub fn encode(&self) -> Result<[u8; SESSION_CONFIRM_BYTES], SessionError> {
        if self.purpose != SESSION_PURPOSE_LINK && self.purpose != SESSION_PURPOSE_END {
            return Err(SessionError::Shape);
        }
        if self.profile != SESSION_PROFILE_MEMBER || self.contexts_digest == [0; 32] {
            return Err(SessionError::Shape);
        }
        let mut out = [0_u8; SESSION_CONFIRM_BYTES];
        head_put(&mut out, self.purpose);
        out[4..36].copy_from_slice(&self.contexts_digest);
        Ok(out)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() < SESSION_CONFIRM_BYTES {
            return Err(DecodeError::Truncated);
        }
        if bytes.len() > SESSION_CONFIRM_BYTES {
            return Err(DecodeError::Oversized);
        }
        let Some((purpose, profile)) = head_ok(bytes) else {
            return Err(DecodeError::BadVersion);
        };
        let mut contexts_digest = [0_u8; 32];
        contexts_digest.copy_from_slice(&bytes[4..36]);
        if contexts_digest == [0; 32] {
            return Err(DecodeError::LengthMismatch);
        }
        Ok(Self {
            purpose,
            profile,
            contexts_digest,
        })
    }
}

// --- Exporter application context (P4 §5.4) -------------------------------------

fn cbor_uint(value: u64, out: &mut Vec<u8>) {
    if value < 24 {
        out.push(value as u8);
    } else if value <= 0xFF {
        out.extend_from_slice(&[0x18, value as u8]);
    } else if value <= 0xFFFF {
        out.extend_from_slice(&[0x19]);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFF_FFFF {
        out.extend_from_slice(&[0x1A]);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.extend_from_slice(&[0x1B]);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

fn cbor_bstr(bytes: &[u8], out: &mut Vec<u8>) {
    let mut head = Vec::new();
    cbor_uint(bytes.len() as u64, &mut head);
    head[0] |= 2 << 5;
    out.extend_from_slice(&head);
    out.extend_from_slice(bytes);
}

fn cbor_text(text: &[u8], out: &mut Vec<u8>) {
    let mut head = Vec::new();
    cbor_uint(text.len() as u64, &mut head);
    head[0] |= 3 << 5;
    out.extend_from_slice(&head);
    out.extend_from_slice(text);
}

fn cbor_array_len(count: usize, out: &mut Vec<u8>) {
    let mut head = Vec::new();
    cbor_uint(count as u64, &mut head);
    head[0] |= 4 << 5;
    out.extend_from_slice(&head);
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExporterContextParams {
    pub purpose: u8,
    pub network: u64,
    pub node_i: u64,
    pub node_r: u64,
    pub kid_i: [u8; 32],
    pub kid_r: [u8; 32],
    pub role_i: u32,
    pub role_r: u32,
    pub generation_i: u32,
    pub generation_r: u32,
    pub context_epoch: u32,
    pub direction: u8,
    pub capability_digest: [u8; 32],
}

pub fn exporter_context_encode(params: &ExporterContextParams) -> Result<Vec<u8>, SessionError> {
    if params.purpose != SESSION_PURPOSE_LINK && params.purpose != SESSION_PURPOSE_END {
        return Err(SessionError::Shape);
    }
    if params.network == 0
        || params.node_i == 0
        || params.node_r == 0
        || params.node_i == u64::MAX
        || params.node_r == u64::MAX
        || params.node_i == params.node_r
        || params.role_i == 0
        || params.role_r == 0
        || params.generation_i == 0
        || params.generation_r == 0
        || params.direction > 2
        || (params.direction == 0) != (params.context_epoch == 0)
    {
        return Err(SessionError::Shape);
    }
    let mut out = Vec::with_capacity(EXPORTER_CONTEXT_MAX);
    cbor_array_len(15, &mut out);
    cbor_text(b"RouteLoom", &mut out);
    cbor_uint(1, &mut out);
    cbor_uint(params.purpose as u64, &mut out);
    cbor_uint(params.network, &mut out);
    cbor_uint(params.node_i, &mut out);
    cbor_uint(params.node_r, &mut out);
    cbor_bstr(&params.kid_i, &mut out);
    cbor_bstr(&params.kid_r, &mut out);
    cbor_uint(params.role_i as u64, &mut out);
    cbor_uint(params.role_r as u64, &mut out);
    cbor_array_len(2, &mut out);
    cbor_uint(params.generation_i as u64, &mut out);
    cbor_uint(params.generation_r as u64, &mut out);
    cbor_array_len(2, &mut out);
    cbor_uint(2, &mut out);
    cbor_uint(0, &mut out);
    cbor_uint(params.context_epoch as u64, &mut out);
    cbor_uint(params.direction as u64, &mut out);
    cbor_bstr(&params.capability_digest, &mut out);
    if out.len() > EXPORTER_CONTEXT_MAX {
        return Err(SessionError::Shape);
    }
    Ok(out)
}

/// EDHOC-Exporter KDF info (RFC 9528 §4.1): `uint(label) || bstr(context) ||
/// uint(length)`.
pub fn edhoc_kdf_info_encode(label: u32, context: &[u8], length: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8 + context.len());
    cbor_uint(label as u64, &mut out);
    cbor_bstr(context, &mut out);
    cbor_uint(length as u64, &mut out);
    out
}
