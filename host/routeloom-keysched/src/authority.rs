//! AuthorityEnvelope bodies and channel crypto (03-key-hierarchy.md §5.3,
//! G-SEC P5 PR1) — the host mirror of
//! `components/routeloom/{include/routeloom/sdkv1_authority.hpp,
//! src/sdkv1_authority.cpp}`.
//!
//! Covers the body codecs (JoinConfirm / GroupKeyUpdate / GroupKeyActivate /
//! GroupKeyPull), the GK-id derivation, the AES-GCM-128 seal/open helpers
//! and the 64-frame replay window. It shares no code with the C++ side:
//! both must reproduce `protocol/sdkv1-golden/authority/` byte for byte,
//! and both report the same [`BodyError::name`] for the same malformed
//! input. No AEAD counter ever wraps under its key.

use aes_gcm::{AeadInPlace, Aes128Gcm, KeyInit, Nonce, Tag};
use zeroize::Zeroize;

use crate::{
    aead_nonce, sha256, AuthorityEnvelopeHeader, DecodeError, TrafficKey,
    AUTHORITY_ENVELOPE_HEADER, AUTHORITY_ENVELOPE_MAX, AUTHORITY_ENVELOPE_MIN, LABEL_GK_ID,
    MAX_AEAD_COUNTER,
};

pub const BODY_HEAD: usize = 16;
pub const BODY_VERSION: u8 = 1;
pub const JOIN_CONFIRM_UP: usize = 60;
pub const JOIN_CONFIRM_DOWN: usize = 24;
pub const GROUP_KEY_UPDATE: usize = 56;
pub const GROUP_KEY_ACK: usize = 56;
pub const GROUP_KEY_ACTIVATE: usize = 56;
pub const GROUP_KEY_PULL: usize = 28;

pub const OVERLAP_REMOVAL_S: u16 = 10;
pub const OVERLAP_NORMAL_S: u16 = 60;

/// Refusal reasons for malformed bodies. [`BodyError::name`] is the shared
/// vocabulary with the C++ decoder and the golden `reason` strings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BodyError {
    Truncated,
    Surplus,
    BadVersion,
    BadOp,
    ReservedNonZero,
    ZeroGeneration,
    ZeroRequestId,
    BadCause,
    BadOverlap,
    BadResult,
    BadStoredState,
    BadReason,
}

impl BodyError {
    pub fn name(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::Surplus => "surplus",
            Self::BadVersion => "bad_version",
            Self::BadOp => "bad_op",
            Self::ReservedNonZero => "reserved_nonzero",
            Self::ZeroGeneration => "zero_generation",
            Self::ZeroRequestId => "zero_request_id",
            Self::BadCause => "bad_cause",
            Self::BadOverlap => "bad_overlap",
            Self::BadResult => "bad_result",
            Self::BadStoredState => "bad_stored_state",
            Self::BadReason => "bad_reason",
        }
    }
}

impl std::fmt::Display for BodyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for BodyError {}

/// Common 16-byte head: body_version:u8=1 | op:u8 | flags:u16=0 |
/// assignment_generation:u32!=0 | request_id:u64!=0.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct BodyHead {
    pub op: u8,
    pub generation: u32,
    pub request_id: u64,
}

impl BodyHead {
    pub fn encode(&self, op: u8) -> Result<[u8; BODY_HEAD], BodyError> {
        if self.op != op || !(1..=2).contains(&op) {
            return Err(BodyError::BadOp);
        }
        if self.generation == 0 {
            return Err(BodyError::ZeroGeneration);
        }
        if self.request_id == 0 {
            return Err(BodyError::ZeroRequestId);
        }
        let mut out = [0_u8; BODY_HEAD];
        out[0] = BODY_VERSION;
        out[1] = self.op;
        out[4..8].copy_from_slice(&self.generation.to_be_bytes());
        out[8..16].copy_from_slice(&self.request_id.to_be_bytes());
        Ok(out)
    }

    pub fn decode(input: &[u8], op: u8) -> Result<Self, BodyError> {
        if input.len() < BODY_HEAD {
            return Err(BodyError::Truncated);
        }
        if input[0] != BODY_VERSION {
            return Err(BodyError::BadVersion);
        }
        if input[1] != op || !(1..=2).contains(&op) {
            return Err(BodyError::BadOp);
        }
        if input[2] != 0 || input[3] != 0 {
            return Err(BodyError::ReservedNonZero);
        }
        let generation = u32::from_be_bytes(input[4..8].try_into().expect("4 bytes"));
        let request_id = u64::from_be_bytes(input[8..16].try_into().expect("8 bytes"));
        if generation == 0 {
            return Err(BodyError::ZeroGeneration);
        }
        if request_id == 0 {
            return Err(BodyError::ZeroRequestId);
        }
        Ok(Self {
            op,
            generation,
            request_id,
        })
    }
}

fn check_len(input: &[u8], want: usize) -> Result<(), BodyError> {
    if input.len() < want {
        return Err(BodyError::Truncated);
    }
    if input.len() > want {
        return Err(BodyError::Surplus);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UpdateCause {
    Periodic = 1,
    Removal = 2,
    Manual = 3,
}

impl UpdateCause {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::Periodic),
            2 => Some(Self::Removal),
            3 => Some(Self::Manual),
            _ => None,
        }
    }

    /// Only 60 s (periodic/manual) and 10 s (removal) exist; the pairing is
    /// part of the wire rule so a removal cannot smuggle a long overlap.
    pub fn overlap_ok(self, overlap_s: u16) -> bool {
        match self {
            Self::Removal => overlap_s == OVERLAP_REMOVAL_S,
            Self::Periodic | Self::Manual => overlap_s == OVERLAP_NORMAL_S,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum UpdateResult {
    Durable = 0,
    Conflict = 1,
    StorageFailure = 2,
    Busy = 3,
    Unsupported = 4,
}

impl UpdateResult {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Durable),
            1 => Some(Self::Conflict),
            2 => Some(Self::StorageFailure),
            3 => Some(Self::Busy),
            4 => Some(Self::Unsupported),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum StoredState {
    None = 0,
    Staged = 1,
    Active = 2,
}

impl StoredState {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::None),
            1 => Some(Self::Staged),
            2 => Some(Self::Active),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PullReason {
    UnknownNewerEpoch = 1,
    BootReconnectSync = 2,
    LostAckRepair = 3,
}

impl PullReason {
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            1 => Some(Self::UnknownNewerEpoch),
            2 => Some(Self::BootReconnectSync),
            3 => Some(Self::LostAckRepair),
            _ => None,
        }
    }
}

/// Type 1 JoinConfirm, op 1 (device -> authority), 60 bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct JoinConfirmUp {
    pub head: BodyHead,
    pub cert_hash: [u8; 32],
    pub boot: u32,
    pub current: u32,
    pub next: u32,
}

impl JoinConfirmUp {
    pub fn encode(&self) -> Result<[u8; JOIN_CONFIRM_UP], BodyError> {
        let head = self.head.encode(1)?;
        let mut out = [0_u8; JOIN_CONFIRM_UP];
        out[..BODY_HEAD].copy_from_slice(&head);
        out[16..48].copy_from_slice(&self.cert_hash);
        out[48..52].copy_from_slice(&self.boot.to_be_bytes());
        out[52..56].copy_from_slice(&self.current.to_be_bytes());
        out[56..60].copy_from_slice(&self.next.to_be_bytes());
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, BodyError> {
        check_len(input, JOIN_CONFIRM_UP)?;
        Ok(Self {
            head: BodyHead::decode(input, 1)?,
            cert_hash: input[16..48].try_into().expect("32 bytes"),
            boot: u32::from_be_bytes(input[48..52].try_into().expect("4 bytes")),
            current: u32::from_be_bytes(input[52..56].try_into().expect("4 bytes")),
            next: u32::from_be_bytes(input[56..60].try_into().expect("4 bytes")),
        })
    }
}

/// Type 1 JoinConfirm, op 2 (authority -> device), 24 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct JoinConfirmDown {
    pub head: BodyHead,
    pub confirmed_generation: u32,
    pub authority_active: u32,
}

impl JoinConfirmDown {
    pub fn encode(&self) -> Result<[u8; JOIN_CONFIRM_DOWN], BodyError> {
        let head = self.head.encode(2)?;
        let mut out = [0_u8; JOIN_CONFIRM_DOWN];
        out[..BODY_HEAD].copy_from_slice(&head);
        out[16..20].copy_from_slice(&self.confirmed_generation.to_be_bytes());
        out[20..24].copy_from_slice(&self.authority_active.to_be_bytes());
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, BodyError> {
        check_len(input, JOIN_CONFIRM_DOWN)?;
        Ok(Self {
            head: BodyHead::decode(input, 2)?,
            confirmed_generation: u32::from_be_bytes(input[16..20].try_into().expect("4 bytes")),
            authority_active: u32::from_be_bytes(input[20..24].try_into().expect("4 bytes")),
        })
    }
}

/// Type 2 GroupKeyUpdate, op 1 (authority -> device), 56 bytes. Holds a raw
/// group key: no `Debug` that prints it (see the manual impl below).
#[derive(Clone, Eq, PartialEq)]
pub struct GroupKeyUpdate {
    pub head: BodyHead,
    pub g: u32,
    pub cause: UpdateCause,
    pub overlap_s: u16,
    pub gk: [u8; 32],
}

impl std::fmt::Debug for GroupKeyUpdate {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("GroupKeyUpdate")
            .field("head", &self.head)
            .field("g", &self.g)
            .field("cause", &self.cause)
            .field("overlap_s", &self.overlap_s)
            .field("gk", &"[redacted; 32 bytes]")
            .finish()
    }
}

impl Drop for GroupKeyUpdate {
    fn drop(&mut self) {
        self.gk.zeroize();
    }
}

impl GroupKeyUpdate {
    pub fn encode(&self) -> Result<[u8; GROUP_KEY_UPDATE], BodyError> {
        if !self.cause.overlap_ok(self.overlap_s) {
            return Err(BodyError::BadOverlap);
        }
        let head = self.head.encode(1)?;
        let mut out = [0_u8; GROUP_KEY_UPDATE];
        out[..BODY_HEAD].copy_from_slice(&head);
        out[16..20].copy_from_slice(&self.g.to_be_bytes());
        out[20] = self.cause as u8;
        out[22..24].copy_from_slice(&self.overlap_s.to_be_bytes());
        out[24..56].copy_from_slice(&self.gk);
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, BodyError> {
        check_len(input, GROUP_KEY_UPDATE)?;
        let head = BodyHead::decode(input, 1)?;
        let cause = UpdateCause::from_u8(input[20]).ok_or(BodyError::BadCause)?;
        if input[21] != 0 {
            return Err(BodyError::ReservedNonZero);
        }
        let overlap_s = u16::from_be_bytes(input[22..24].try_into().expect("2 bytes"));
        if !cause.overlap_ok(overlap_s) {
            return Err(BodyError::BadOverlap);
        }
        Ok(Self {
            head,
            g: u32::from_be_bytes(input[16..20].try_into().expect("4 bytes")),
            cause,
            overlap_s,
            gk: input[24..56].try_into().expect("32 bytes"),
        })
    }
}

/// Type 2/3 ACK, op 2 (device -> authority), 56 bytes. Only
/// `result == Durable` is convergence evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupKeyAck {
    pub head: BodyHead,
    pub g: u32,
    pub gk_id: [u8; 32],
    pub result: UpdateResult,
    pub stored_state: StoredState,
}

impl GroupKeyAck {
    pub fn encode(&self) -> Result<[u8; GROUP_KEY_ACK], BodyError> {
        if self.result == UpdateResult::Durable && self.stored_state == StoredState::None {
            return Err(BodyError::BadStoredState);
        }
        let head = self.head.encode(2)?;
        let mut out = [0_u8; GROUP_KEY_ACK];
        out[..BODY_HEAD].copy_from_slice(&head);
        out[16..20].copy_from_slice(&self.g.to_be_bytes());
        out[20..52].copy_from_slice(&self.gk_id);
        out[52] = self.result as u8;
        out[53] = self.stored_state as u8;
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, BodyError> {
        check_len(input, GROUP_KEY_ACK)?;
        let head = BodyHead::decode(input, 2)?;
        if input[54] != 0 || input[55] != 0 {
            return Err(BodyError::ReservedNonZero);
        }
        let ack = Self {
            head,
            g: u32::from_be_bytes(input[16..20].try_into().expect("4 bytes")),
            gk_id: input[20..52].try_into().expect("32 bytes"),
            result: UpdateResult::from_u8(input[52]).ok_or(BodyError::BadResult)?,
            stored_state: StoredState::from_u8(input[53]).ok_or(BodyError::BadStoredState)?,
        };
        if ack.result == UpdateResult::Durable && ack.stored_state == StoredState::None {
            return Err(BodyError::BadStoredState);
        }
        Ok(ack)
    }
}

/// Type 3 GroupKeyActivate, op 1 (authority -> device), 56 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupKeyActivate {
    pub head: BodyHead,
    pub g: u32,
    pub gk_id: [u8; 32],
    pub cause: UpdateCause,
    pub overlap_s: u16,
}

impl GroupKeyActivate {
    pub fn encode(&self) -> Result<[u8; GROUP_KEY_ACTIVATE], BodyError> {
        if !self.cause.overlap_ok(self.overlap_s) {
            return Err(BodyError::BadOverlap);
        }
        let head = self.head.encode(1)?;
        let mut out = [0_u8; GROUP_KEY_ACTIVATE];
        out[..BODY_HEAD].copy_from_slice(&head);
        out[16..20].copy_from_slice(&self.g.to_be_bytes());
        out[20..52].copy_from_slice(&self.gk_id);
        out[52] = self.cause as u8;
        out[54..56].copy_from_slice(&self.overlap_s.to_be_bytes());
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, BodyError> {
        check_len(input, GROUP_KEY_ACTIVATE)?;
        let head = BodyHead::decode(input, 1)?;
        let cause = UpdateCause::from_u8(input[52]).ok_or(BodyError::BadCause)?;
        if input[53] != 0 {
            return Err(BodyError::ReservedNonZero);
        }
        let overlap_s = u16::from_be_bytes(input[54..56].try_into().expect("2 bytes"));
        if !cause.overlap_ok(overlap_s) {
            return Err(BodyError::BadOverlap);
        }
        Ok(Self {
            head,
            g: u32::from_be_bytes(input[16..20].try_into().expect("4 bytes")),
            gk_id: input[20..52].try_into().expect("32 bytes"),
            cause,
            overlap_s,
        })
    }
}

/// Type 4 GroupKeyPull, op 1 (device -> authority), 28 bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GroupKeyPull {
    pub head: BodyHead,
    pub current: u32,
    pub next: u32,
    pub reason: PullReason,
}

impl GroupKeyPull {
    pub fn encode(&self) -> Result<[u8; GROUP_KEY_PULL], BodyError> {
        let head = self.head.encode(1)?;
        let mut out = [0_u8; GROUP_KEY_PULL];
        out[..BODY_HEAD].copy_from_slice(&head);
        out[16..20].copy_from_slice(&self.current.to_be_bytes());
        out[20..24].copy_from_slice(&self.next.to_be_bytes());
        out[24] = self.reason as u8;
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, BodyError> {
        check_len(input, GROUP_KEY_PULL)?;
        let head = BodyHead::decode(input, 1)?;
        if input[25] != 0 || input[26] != 0 || input[27] != 0 {
            return Err(BodyError::ReservedNonZero);
        }
        Ok(Self {
            head,
            current: u32::from_be_bytes(input[16..20].try_into().expect("4 bytes")),
            next: u32::from_be_bytes(input[20..24].try_into().expect("4 bytes")),
            reason: PullReason::from_u8(input[24]).ok_or(BodyError::BadReason)?,
        })
    }
}

/// GK-id = SHA256("RouteLoom/v1/gk-id" || 0x00 || network:u64 ||
/// epoch:u32 || GK:32): the ACK's key-confirmation identifier, never a
/// raw-GK export.
pub fn gk_id(network: u64, epoch: u32, gk: &[u8; 32]) -> [u8; 32] {
    let mut input = Vec::with_capacity(19 + 8 + 4 + 32);
    input.extend_from_slice(LABEL_GK_ID.as_bytes());
    input.push(0);
    input.extend_from_slice(&network.to_be_bytes());
    input.extend_from_slice(&epoch.to_be_bytes());
    input.extend_from_slice(gk);
    let id = sha256(&[&input]);
    input.zeroize();
    id
}

// --- Channel crypto ----------------------------------------------------------

/// Seal refusal reasons.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SealError {
    ZeroContextId,
    CounterExhausted,
    PlaintextTooLarge,
    BadType,
}

impl SealError {
    pub fn name(self) -> &'static str {
        match self {
            Self::ZeroContextId => "zero_context_id",
            Self::CounterExhausted => "counter_exhausted",
            Self::PlaintextTooLarge => "plaintext_too_large",
            Self::BadType => "bad_type",
        }
    }
}

impl std::fmt::Display for SealError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for SealError {}

/// Open refusal reasons. `BadTag` never yields plaintext.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OpenError {
    Header(DecodeError),
    ContextMismatch,
    BadTag,
}

impl OpenError {
    pub fn name(self) -> &'static str {
        match self {
            Self::Header(error) => error.name(),
            Self::ContextMismatch => "context_mismatch",
            Self::BadTag => "bad_tag",
        }
    }
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for OpenError {}

fn cipher(key: &TrafficKey) -> Aes128Gcm {
    Aes128Gcm::new_from_slice(&key.key).expect("16-byte AES-128 key")
}

/// Seals one envelope (header + ciphertext + tag, 28..=2048 bytes).
/// Refuses counter > 2^48-1: the key must be retired, never wrapped.
pub fn seal_envelope(
    key: &TrafficKey,
    env_type: u8,
    ctx_id: u32,
    counter: u64,
    plaintext: &[u8],
) -> Result<Vec<u8>, SealError> {
    if ctx_id == 0 {
        return Err(SealError::ZeroContextId);
    }
    if counter > MAX_AEAD_COUNTER {
        return Err(SealError::CounterExhausted);
    }
    if plaintext.len() > AUTHORITY_ENVELOPE_MAX - AUTHORITY_ENVELOPE_MIN {
        return Err(SealError::PlaintextTooLarge);
    }
    let header = AuthorityEnvelopeHeader {
        version: crate::AUTHORITY_ENVELOPE_VERSION,
        env_type,
        ctx_id,
        counter,
    };
    let aad = header.encode().ok_or(SealError::BadType)?;
    let nonce = aead_nonce(&key.iv, counter).ok_or(SealError::CounterExhausted)?;
    let nonce = Nonce::from(nonce);
    let mut buffer = plaintext.to_vec();
    let tag = cipher(key)
        .encrypt_in_place_detached(&nonce, &aad, &mut buffer)
        .expect("seal cannot fail for valid inputs");
    let mut out = Vec::with_capacity(AUTHORITY_ENVELOPE_HEADER + buffer.len() + 16);
    out.extend_from_slice(&aad);
    out.extend_from_slice(&buffer);
    out.extend_from_slice(&tag);
    buffer.zeroize();
    Ok(out)
}

/// Opens one envelope addressed to `want_ctx`. On any failure returns the
/// reason and no plaintext (the scratch is zeroized, never returned).
pub fn open_envelope(
    key: &TrafficKey,
    envelope: &[u8],
    want_ctx: u32,
) -> Result<(AuthorityEnvelopeHeader, Vec<u8>), OpenError> {
    let header = AuthorityEnvelopeHeader::decode(envelope).map_err(OpenError::Header)?;
    if want_ctx == 0 || header.ctx_id != want_ctx {
        return Err(OpenError::ContextMismatch);
    }
    let nonce = aead_nonce(&key.iv, header.counter).ok_or(OpenError::BadTag)?;
    let nonce = Nonce::from(nonce);
    let mut buffer = envelope[AUTHORITY_ENVELOPE_HEADER..envelope.len() - 16].to_vec();
    let mut tag_bytes = [0_u8; 16];
    tag_bytes.copy_from_slice(&envelope[envelope.len() - 16..]);
    let tag = Tag::from(tag_bytes);
    let ok = cipher(key)
        .decrypt_in_place_detached(
            &nonce,
            &envelope[..AUTHORITY_ENVELOPE_HEADER],
            &mut buffer,
            &tag,
        )
        .is_ok();
    if !ok {
        buffer.zeroize();
        return Err(OpenError::BadTag);
    }
    Ok((header, buffer))
}

/// 64-frame replay window over one direction's envelope counter. `accept`
/// commits only after the caller verified the AEAD tag.
#[derive(Clone, Debug)]
pub struct ReplayWindow {
    max: u64,
    bitmap: u64,
    empty: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self {
            max: 0,
            bitmap: 0,
            empty: true,
        }
    }

    pub fn accept(&mut self, counter: u64) -> bool {
        if self.empty {
            self.empty = false;
            self.max = counter;
            self.bitmap = 1;
            return true;
        }
        if counter > self.max {
            let shift = counter - self.max;
            self.bitmap = if shift >= 64 {
                1
            } else {
                (self.bitmap << shift) | 1
            };
            self.max = counter;
            return true;
        }
        let back = self.max - counter;
        if back >= 64 {
            return false;
        }
        let bit = 1_u64 << back;
        if self.bitmap & bit != 0 {
            return false;
        }
        self.bitmap |= bit;
        true
    }

    pub fn max_seen(&self) -> Option<u64> {
        (!self.empty).then_some(self.max)
    }
}

/// Constant-time 16-byte comparison for MAC checks (avoids a new
/// dependency for one comparison; the crate otherwise has no need for
/// `subtle`).
pub fn mac_equal(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff = 0_u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Domain check shared with the USB fragment codec: the object length the
/// carrier kind pins. `None` for an unknown kind.
pub fn carrier_total_for_kind(kind: u8, total: u16) -> bool {
    match kind {
        1 => total == crate::rlres1::R1_BASE as u16,
        2 => total == crate::rlres1::R2_OK as u16 || total == crate::rlres1::R2_HINT as u16,
        3 => total == crate::rlres1::R3_SIZE as u16,
        4 => total >= AUTHORITY_ENVELOPE_MIN as u16 && total <= AUTHORITY_ENVELOPE_MAX as u16,
        5 => total == 8,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head() -> BodyHead {
        BodyHead {
            op: 1,
            generation: 9,
            request_id: 0x0102030405060708,
        }
    }

    #[test]
    fn bodies_round_trip() {
        let up = JoinConfirmUp {
            head: head(),
            cert_hash: [0xC0; 32],
            boot: 5,
            current: 10,
            next: 11,
        };
        let encoded = up.encode().expect("encode");
        assert_eq!(JoinConfirmUp::decode(&encoded).expect("decode"), up);

        let mut down_head = head();
        down_head.op = 2;
        let down = JoinConfirmDown {
            head: down_head,
            confirmed_generation: 9,
            authority_active: 10,
        };
        let encoded = down.encode().expect("encode");
        assert_eq!(JoinConfirmDown::decode(&encoded).expect("decode"), down);

        let update = GroupKeyUpdate {
            head: head(),
            g: 11,
            cause: UpdateCause::Removal,
            overlap_s: OVERLAP_REMOVAL_S,
            gk: [0xA0; 32],
        };
        let encoded = update.encode().expect("encode");
        assert_eq!(GroupKeyUpdate::decode(&encoded).expect("decode").g, 11);

        let mut ack_head = head();
        ack_head.op = 2;
        let ack = GroupKeyAck {
            head: ack_head,
            g: 11,
            gk_id: [0x11; 32],
            result: UpdateResult::Durable,
            stored_state: StoredState::Active,
        };
        let encoded = ack.encode().expect("encode");
        assert_eq!(GroupKeyAck::decode(&encoded).expect("decode"), ack);

        let activate = GroupKeyActivate {
            head: head(),
            g: 11,
            gk_id: [0x11; 32],
            cause: UpdateCause::Manual,
            overlap_s: OVERLAP_NORMAL_S,
        };
        let encoded = activate.encode().expect("encode");
        assert_eq!(
            GroupKeyActivate::decode(&encoded).expect("decode"),
            activate
        );

        let pull = GroupKeyPull {
            head: head(),
            current: 10,
            next: 0,
            reason: PullReason::LostAckRepair,
        };
        let encoded = pull.encode().expect("encode");
        assert_eq!(GroupKeyPull::decode(&encoded).expect("decode"), pull);
    }

    #[test]
    fn body_refusals_match_the_shared_vocabulary() {
        let update = GroupKeyUpdate {
            head: head(),
            g: 11,
            cause: UpdateCause::Periodic,
            overlap_s: OVERLAP_NORMAL_S,
            gk: [0xA0; 32],
        };
        let good = update.encode().expect("encode").to_vec();
        assert_eq!(
            GroupKeyUpdate::decode(&good[..55]).unwrap_err(),
            BodyError::Truncated
        );
        let mut surplus = good.clone();
        surplus.push(0);
        assert_eq!(
            GroupKeyUpdate::decode(&surplus).unwrap_err(),
            BodyError::Surplus
        );
        let mut bad = good.clone();
        bad[0] = 2;
        assert_eq!(
            GroupKeyUpdate::decode(&bad).unwrap_err(),
            BodyError::BadVersion
        );
        let mut bad = good.clone();
        bad[20] = 9;
        assert_eq!(
            GroupKeyUpdate::decode(&bad).unwrap_err(),
            BodyError::BadCause
        );
        let mut bad = good.clone();
        bad[22] = 0;
        bad[23] = 61;
        assert_eq!(
            GroupKeyUpdate::decode(&bad).unwrap_err(),
            BodyError::BadOverlap
        );
        // Removal must pair cause 2 with overlap 10 s.
        let mut bad = good.clone();
        bad[20] = 2;
        assert_eq!(
            GroupKeyUpdate::decode(&bad).unwrap_err(),
            BodyError::BadOverlap
        );
        let removal = GroupKeyUpdate {
            cause: UpdateCause::Removal,
            overlap_s: OVERLAP_REMOVAL_S,
            ..update
        };
        assert!(removal.encode().is_ok());
        // The key bytes never reach a Debug log.
        assert!(!format!("{update:?}").contains("a0"));
    }

    #[test]
    fn seal_open_round_trip_and_refusals() {
        let key = TrafficKey {
            key: [0x42; 16],
            iv: [0x24; 12],
        };
        let plaintext = b"authority-test-plaintext....................";
        let envelope = seal_envelope(&key, 4, 0x66666666, 7, plaintext).expect("seal");
        let (header, opened) = open_envelope(&key, &envelope, 0x66666666).expect("open");
        assert_eq!(header.counter, 7);
        assert_eq!(header.env_type, 4);
        assert_eq!(opened, plaintext);

        assert_eq!(
            seal_envelope(&key, 4, 0, 0, plaintext).unwrap_err(),
            SealError::ZeroContextId
        );
        assert_eq!(
            seal_envelope(&key, 4, 1, MAX_AEAD_COUNTER + 1, plaintext).unwrap_err(),
            SealError::CounterExhausted
        );
        assert_eq!(
            open_envelope(&key, &envelope, 0xDEAD).unwrap_err(),
            OpenError::ContextMismatch
        );
        let mut tampered = envelope.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert_eq!(
            open_envelope(&key, &tampered, 0x66666666).unwrap_err(),
            OpenError::BadTag
        );
    }

    #[test]
    fn replay_window_matches_the_device_rule() {
        let mut window = ReplayWindow::new();
        assert!(window.accept(7));
        assert!(!window.accept(7));
        assert!(window.accept(9));
        assert!(window.accept(8));
        assert!(window.accept(0));
        assert!(!window.accept(0));
        for counter in 10..10 + 64 {
            assert!(window.accept(counter));
        }
        assert!(!window.accept(10));
        assert!(window.accept(1000));
        assert!(window.accept(1000 - 63));
        assert!(!window.accept(1000 - 63));
        assert!(!window.accept(1000 - 64));
    }

    #[test]
    fn default_replay_window_starts_empty() {
        let mut window = ReplayWindow::default();
        assert_eq!(window.max_seen(), None);
        assert!(window.accept(0));
        assert!(!window.accept(0));
    }

    #[test]
    fn unknown_body_op_is_refused() {
        let head = BodyHead {
            op: 3,
            generation: 9,
            request_id: 1,
        };
        assert_eq!(head.encode(3), Err(BodyError::BadOp));
        let mut encoded = BodyHead { op: 1, ..head }.encode(1).expect("head");
        encoded[1] = 3;
        assert_eq!(BodyHead::decode(&encoded, 3), Err(BodyError::BadOp));
    }

    #[test]
    fn durable_ack_requires_a_stored_key_state() {
        let ack = GroupKeyAck {
            head: BodyHead {
                op: 2,
                generation: 9,
                request_id: 1,
            },
            g: 12,
            gk_id: [0xA5; 32],
            result: UpdateResult::Durable,
            stored_state: StoredState::None,
        };
        assert_eq!(ack.encode(), Err(BodyError::BadStoredState));
        let good = GroupKeyAck {
            stored_state: StoredState::Staged,
            ..ack
        }
        .encode()
        .expect("ack");
        let mut invalid = good;
        invalid[53] = 0;
        assert_eq!(
            GroupKeyAck::decode(&invalid),
            Err(BodyError::BadStoredState)
        );
    }

    #[test]
    fn mac_compare_is_correct() {
        assert!(mac_equal(&[0xAA; 16], &[0xAA; 16]));
        assert!(!mac_equal(&[0xAA; 16], &[0xAB; 16]));
    }
}
