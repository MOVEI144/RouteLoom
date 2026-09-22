//! EXPERIMENTAL development-profile session authentication for the USB
//! bridge. This is a byte-for-byte port of the C++ implementation in
//! `components/routeloom/src/usb_session.cpp`; both sides must agree on every
//! byte so the shared vectors under `protocol/usb-golden` mean something.
//!
//! Like `DevelopmentPskSecurityProvider` it exercises the real state machine,
//! transcript binding, per-direction counters and tag verification, but the
//! MAC is a documented deterministic mixer, NOT a cryptographic primitive.
//! The production profile is G-SEC's job; do not ship this as a security
//! boundary.

use crate::{Frame, FrameKind, ProtocolError};

pub const DEV_TAG_SIZE: usize = 16;
pub const SESSION_KEY_SIZE: usize = 16;
pub const MAX_PRINCIPAL_SIZE: usize = 32;
pub const PROTECTED_BODY_OVERHEAD: usize = 8 + DEV_TAG_SIZE;
pub const TRANSCRIPT_SIZE: usize = 8 + 8 + 8 + 1 + 8 + 8 + 8 + 4 + 1 + MAX_PRINCIPAL_SIZE;

pub const DIRECTION_HOST_TO_DEVICE: u8 = 0;
pub const DIRECTION_DEVICE_TO_HOST: u8 = 1;
pub const FLAG_AUTH: u16 = 0x0001;

pub const CREDIT_GRANT: u8 = 0;
pub const CREDIT_QUERY: u8 = 1;
pub const CREDIT_CLOSE: u8 = 2;

const DEV_MAC_SEED: u64 = 0x524c_5531_4445_5631; // "RLU1DEV1"
const LANE_LEFT: u64 = 0x4c45_4654; // "LEFT"
const LANE_RIGHT: u64 = 0x5247_4854; // "RGHT"
const TRANSCRIPT_MAGIC: u64 = 0x524c_5531_5452_4e31; // "RLU1TRN1"

fn dev_mix(mut state: u64, value: u64) -> u64 {
    state ^= value
        .wrapping_add(0x9e37_79b9_7f4a_7c15)
        .wrapping_add(state << 6)
        .wrapping_add(state >> 2);
    state.wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

/// Deterministic dev MAC. `new(secret)` absorbs the secret then its length;
/// `absorb*` appends fields big-endian; `tag()` finalizes two lanes:
/// `mix(state, "LEFT")` MSB-first then `mix(state, "RGHT")` MSB-first.
#[derive(Clone)]
pub struct DevMac {
    state: u64,
}

impl DevMac {
    pub fn new(secret: &[u8]) -> Self {
        let mut mac = Self {
            state: DEV_MAC_SEED,
        };
        mac.absorb(secret);
        mac.absorb_u64(secret.len() as u64);
        mac
    }

    pub fn absorb(&mut self, data: &[u8]) {
        for byte in data {
            self.state = dev_mix(self.state, u64::from(*byte));
        }
    }

    pub fn absorb_u8(&mut self, value: u8) {
        self.state = dev_mix(self.state, u64::from(value));
    }

    pub fn absorb_u16(&mut self, value: u16) {
        self.absorb(&value.to_be_bytes());
    }

    pub fn absorb_u32(&mut self, value: u32) {
        self.absorb(&value.to_be_bytes());
    }

    pub fn absorb_u64(&mut self, value: u64) {
        self.absorb(&value.to_be_bytes());
    }

    pub fn tag(&self) -> [u8; DEV_TAG_SIZE] {
        let left = dev_mix(self.state, LANE_LEFT);
        let right = dev_mix(self.state, LANE_RIGHT);
        let mut out = [0_u8; DEV_TAG_SIZE];
        out[..8].copy_from_slice(&left.to_be_bytes());
        out[8..].copy_from_slice(&right.to_be_bytes());
        out
    }
}

/// proof = DevMac(secret).absorb(label).absorb(message).absorb_u64(len).tag()
pub fn dev_proof(secret: &[u8], label: &[u8], message: &[u8]) -> [u8; DEV_TAG_SIZE] {
    let mut mac = DevMac::new(secret);
    mac.absorb(label);
    mac.absorb(message);
    mac.absorb_u64(message.len() as u64);
    mac.tag()
}

/// Transcript bound into the session proof: host nonce, device nonce,
/// selected version, Node ID, Boot ID, Network ID, capability digest and
/// host principal.
#[derive(Clone, Debug)]
pub struct Transcript {
    pub host_nonce: u64,
    pub device_nonce: u64,
    pub version: u8,
    pub node: u64,
    pub boot: u64,
    pub network: u64,
    pub capability: u32,
    pub principal: Vec<u8>,
}

impl Transcript {
    /// Canonical encoding: "RLU1TRN1" || host_nonce || device_nonce ||
    /// version || node || boot || network || capability || plen ||
    /// principal (zero-padded to TRANSCRIPT_SIZE). Principals longer than
    /// MAX_PRINCIPAL_SIZE are rejected rather than silently truncated —
    /// truncation would make two distinct principals collide.
    pub fn encode(&self) -> Result<Vec<u8>, ProtocolError> {
        if self.principal.len() > MAX_PRINCIPAL_SIZE || self.principal.len() > u8::MAX as usize {
            return Err(ProtocolError::PrincipalTooLong);
        }
        let mut out = Vec::with_capacity(TRANSCRIPT_SIZE);
        out.extend_from_slice(&TRANSCRIPT_MAGIC.to_be_bytes());
        out.extend_from_slice(&self.host_nonce.to_be_bytes());
        out.extend_from_slice(&self.device_nonce.to_be_bytes());
        out.push(self.version);
        out.extend_from_slice(&self.node.to_be_bytes());
        out.extend_from_slice(&self.boot.to_be_bytes());
        out.extend_from_slice(&self.network.to_be_bytes());
        out.extend_from_slice(&self.capability.to_be_bytes());
        out.push(self.principal.len() as u8);
        out.extend_from_slice(&self.principal);
        out.resize(TRANSCRIPT_SIZE, 0);
        Ok(out)
    }
}

#[derive(Clone, Debug)]
pub struct SessionProof {
    pub session_id: u64,
    pub key: [u8; SESSION_KEY_SIZE],
    pub hello_tag: [u8; DEV_TAG_SIZE],
    pub auth_tag: [u8; DEV_TAG_SIZE],
    pub auth_ok_tag: [u8; DEV_TAG_SIZE],
}

/// key = proof("session-key"), hello = proof("hello"), auth = proof("auth"),
/// auth_ok = proof("auth-ok"), session_id = u64 BE of proof("session-id")[..8].
pub fn derive_session_proof(secret: &[u8], transcript: &[u8]) -> SessionProof {
    let key = dev_proof(secret, b"session-key", transcript);
    let id = dev_proof(secret, b"session-id", transcript);
    SessionProof {
        session_id: u64::from_be_bytes(id[..8].try_into().expect("tag prefix")),
        key,
        hello_tag: dev_proof(secret, b"hello", transcript),
        auth_tag: dev_proof(secret, b"auth", transcript),
        auth_ok_tag: dev_proof(secret, b"auth-ok", transcript),
    }
}

/// frame_tag = DevMac(key).absorb_u8(dir).absorb_u64(counter).absorb_u8(kind)
///   .absorb_u16(flags).absorb_u64(request).absorb(inner)
///   .absorb_u64(inner.len).tag()
pub fn frame_tag(
    key: &[u8; SESSION_KEY_SIZE],
    direction: u8,
    counter: u64,
    kind: FrameKind,
    flags: u16,
    request: u64,
    inner: &[u8],
) -> [u8; DEV_TAG_SIZE] {
    let mut mac = DevMac::new(key);
    mac.absorb_u8(direction);
    mac.absorb_u64(counter);
    mac.absorb_u8(kind as u8);
    mac.absorb_u16(flags);
    mac.absorb_u64(request);
    mac.absorb(inner);
    mac.absorb_u64(inner.len() as u64);
    mac.tag()
}

/// Protected body layout: counter(8 BE) || tag(16) || inner.
pub fn seal_body(
    key: &[u8; SESSION_KEY_SIZE],
    direction: u8,
    counter: u64,
    kind: FrameKind,
    flags: u16,
    request: u64,
    inner: &[u8],
) -> Vec<u8> {
    let tag = frame_tag(key, direction, counter, kind, flags, request, inner);
    let mut out = Vec::with_capacity(PROTECTED_BODY_OVERHEAD + inner.len());
    out.extend_from_slice(&counter.to_be_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(inner);
    out
}

/// Verifies the tag over the frame's own kind/flags/request, then returns
/// the embedded counter and the inner view. The caller enforces the
/// counter/replay policy.
pub fn open_body<'a>(
    key: &[u8; SESSION_KEY_SIZE],
    direction: u8,
    frame: &'a Frame,
) -> Result<(u64, &'a [u8]), ProtocolError> {
    if frame.body.len() < PROTECTED_BODY_OVERHEAD {
        return Err(ProtocolError::FrameTooShort);
    }
    let counter = u64::from_be_bytes(frame.body[..8].try_into().expect("counter"));
    let inner = &frame.body[PROTECTED_BODY_OVERHEAD..];
    let expected = frame_tag(
        key,
        direction,
        counter,
        frame.kind,
        frame.flags,
        frame.request,
        inner,
    );
    // Constant-time tag check, mirroring the XOR fold in the C++ peer
    // (usb_session.cpp): slice `!=` short-circuits on the first mismatch.
    let mut diff = 0_u8;
    for (a, b) in expected.iter().zip(&frame.body[8..8 + DEV_TAG_SIZE]) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(ProtocolError::CrcMismatch); // integrity failure class
    }
    Ok((counter, inner))
}
