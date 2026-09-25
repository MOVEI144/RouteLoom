//! Diagnostic CapabilitiesReply feature bits (not USB Hello or JoinRequest bits).
//!
//! The broadcast opt-in remains disabled until old P6 bit-5 RRS grants can
//! be distinguished; a group tag cannot upgrade a peer's capability grant.

pub const CAP_ROUTE_BROADCAST_V1: u32 = 1 << 5;
pub const CAP_MEMBERSHIP_LIFECYCLE_V1: u32 = 1 << 6;
pub const CAP_RRS_GOSSIP_V1: u32 = 1 << 7;
pub const FEATURE_MASK: u32 = 0xff;

use crate::{ErrorCode, Result, WireError};

const QUERY_LEN: usize = 24;
const REPLY_LEN: usize = 40;
const NONCE_LEN: usize = 16;
const MAX_VALID_FOR_MS: u32 = 15000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilitiesReply {
    pub echo_nonce: [u8; NONCE_LEN],
    pub node_boot: u64,
    pub features: u32,
    pub permit_profiles: u32,
    pub valid_for_ms: u32,
}

fn reject() -> WireError {
    WireError::new(ErrorCode::ProtocolError, "diagnostic capability body")
}

fn valid_nonce(nonce: &[u8; NONCE_LEN]) -> bool {
    nonce.iter().any(|byte| *byte != 0)
}

pub fn encode_query(nonce: [u8; NONCE_LEN]) -> Result<[u8; QUERY_LEN]> {
    if !valid_nonce(&nonce) {
        return Err(reject());
    }
    let mut body = [0; QUERY_LEN];
    body[0..2].copy_from_slice(&[1, 1]);
    body[4..20].copy_from_slice(&nonce);
    Ok(body)
}

pub fn decode_query(body: &[u8]) -> Result<[u8; NONCE_LEN]> {
    if body.len() != QUERY_LEN || body[0..4] != [1, 1, 0, 0] || body[20..24] != [0; 4] {
        return Err(reject());
    }
    let nonce: [u8; NONCE_LEN] = body[4..20].try_into().map_err(|_| reject())?;
    if !valid_nonce(&nonce) {
        return Err(reject());
    }
    Ok(nonce)
}

fn valid_reply(reply: &CapabilitiesReply) -> bool {
    valid_nonce(&reply.echo_nonce)
        && reply.node_boot != 0
        && reply.features & !FEATURE_MASK == 0
        && reply.permit_profiles & !3 == 0
        && (1..=MAX_VALID_FOR_MS).contains(&reply.valid_for_ms)
}

pub fn encode_reply(reply: CapabilitiesReply) -> Result<[u8; REPLY_LEN]> {
    if !valid_reply(&reply) {
        return Err(reject());
    }
    let mut body = [0; REPLY_LEN];
    body[0..2].copy_from_slice(&[1, 2]);
    body[4..20].copy_from_slice(&reply.echo_nonce);
    body[20..28].copy_from_slice(&reply.node_boot.to_be_bytes());
    body[28..32].copy_from_slice(&reply.features.to_be_bytes());
    body[32..36].copy_from_slice(&reply.permit_profiles.to_be_bytes());
    body[36..40].copy_from_slice(&reply.valid_for_ms.to_be_bytes());
    Ok(body)
}

pub fn decode_reply(body: &[u8]) -> Result<CapabilitiesReply> {
    if body.len() != REPLY_LEN || body[0..4] != [1, 2, 0, 0] {
        return Err(reject());
    }
    // Fixed lengths above make each conversion total; malformed input never
    // leaves a partially accepted grant with a defaulted boot or nonce.
    let reply = CapabilitiesReply {
        echo_nonce: body[4..20].try_into().map_err(|_| reject())?,
        node_boot: u64::from_be_bytes(body[20..28].try_into().map_err(|_| reject())?),
        features: u32::from_be_bytes(body[28..32].try_into().map_err(|_| reject())?),
        permit_profiles: u32::from_be_bytes(body[32..36].try_into().map_err(|_| reject())?),
        valid_for_ms: u32::from_be_bytes(body[36..40].try_into().map_err(|_| reject())?),
    };
    if !valid_reply(&reply) {
        return Err(reject());
    }
    Ok(reply)
}
