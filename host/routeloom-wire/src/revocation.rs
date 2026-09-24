//! P6 revocation wire codecs (04-removal-revocation.md §4, plan P6-1
//! PR A), mirrored field-for-field from the C++ implementation in
//! `components/routeloom/src/sdkv1_revocation.cpp`. Byte layouts are
//! pinned by `protocol/sdkv1-golden/revocation/`.
//!
//! * [`StateEpochs`] / [`RrsRequest`]: link-only 1-hop Control (22)
//!   gossip bodies (exact shapes only; hints, never evidence).
//! * [`RrsApplied`] / [`RrsGet`] / [`RrsNoticeAccepted`]: authority
//!   type-5 device→Host bodies. Host→device is the RRS1 COSE object
//!   itself (see `routeloom-provision::sdkv1::revocation`).

use crate::{ErrorCode, Result, WireError};

pub const RRS_CONTROL_VERSION: u8 = 1;
pub const RRS_SUB_STATE_EPOCHS: u8 = 0x61;
pub const RRS_SUB_REQUEST: u8 = 0x62;
pub const STATE_EPOCHS_SIZE: usize = 14;
pub const RRS_REQUEST_SIZE: usize = 10;
pub const AUTHORITY_TYPE_REVOCATION: u8 = 5;
pub const RRS_APPLIED_SIZE: usize = 40;
pub const RRS_GET_SIZE: usize = 8;
pub const RRS_NOTICE_ACCEPTED_SIZE: usize = 40;

const SUB_APPLIED: u8 = 1;
const SUB_GET: u8 = 2;
const SUB_NOTICE_ACCEPTED: u8 = 3;

fn reject<T>() -> Result<T> {
    Err(WireError::new(
        ErrorCode::ProtocolError,
        "rrs wire rejected",
    ))
}

/// What the sender has durably applied — a hint, not evidence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StateEpochs {
    pub site_epoch: u32,
    pub applied_rs_epoch: u32,
    pub gk_epoch: u32,
}

pub fn state_epochs_encode(epochs: &StateEpochs) -> [u8; STATE_EPOCHS_SIZE] {
    let mut out = [0_u8; STATE_EPOCHS_SIZE];
    out[0] = RRS_CONTROL_VERSION;
    out[1] = RRS_SUB_STATE_EPOCHS;
    out[2..6].copy_from_slice(&epochs.site_epoch.to_be_bytes());
    out[6..10].copy_from_slice(&epochs.applied_rs_epoch.to_be_bytes());
    out[10..14].copy_from_slice(&epochs.gk_epoch.to_be_bytes());
    out
}

pub fn state_epochs_decode(body: &[u8]) -> Result<StateEpochs> {
    if body.len() != STATE_EPOCHS_SIZE
        || body[0] != RRS_CONTROL_VERSION
        || body[1] != RRS_SUB_STATE_EPOCHS
    {
        return reject();
    }
    Ok(StateEpochs {
        site_epoch: u32::from_be_bytes(body[2..6].try_into().expect("fixed")),
        applied_rs_epoch: u32::from_be_bytes(body[6..10].try_into().expect("fixed")),
        gk_epoch: u32::from_be_bytes(body[10..14].try_into().expect("fixed")),
    })
}

/// A pull for the receiver's RRS1 when it advertised a newer epoch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrsRequest {
    pub site_epoch: u32,
    pub have_rs_epoch: u32,
}

pub fn rrs_request_encode(request: &RrsRequest) -> [u8; RRS_REQUEST_SIZE] {
    let mut out = [0_u8; RRS_REQUEST_SIZE];
    out[0] = RRS_CONTROL_VERSION;
    out[1] = RRS_SUB_REQUEST;
    out[2..6].copy_from_slice(&request.site_epoch.to_be_bytes());
    out[6..10].copy_from_slice(&request.have_rs_epoch.to_be_bytes());
    out
}

pub fn rrs_request_decode(body: &[u8]) -> Result<RrsRequest> {
    if body.len() != RRS_REQUEST_SIZE
        || body[0] != RRS_CONTROL_VERSION
        || body[1] != RRS_SUB_REQUEST
    {
        return reject();
    }
    Ok(RrsRequest {
        site_epoch: u32::from_be_bytes(body[2..6].try_into().expect("fixed")),
        have_rs_epoch: u32::from_be_bytes(body[6..10].try_into().expect("fixed")),
    })
}

fn head_encode(sub: u8, out: &mut [u8]) {
    out[0] = RRS_CONTROL_VERSION;
    out[1] = sub;
    out[2] = 0;
    out[3] = 0;
}

fn head_decode(body: &[u8], sub: u8) -> Result<()> {
    if body.len() < 4
        || body[0] != RRS_CONTROL_VERSION
        || body[1] != sub
        || body[2] != 0
        || body[3] != 0
    {
        return reject();
    }
    Ok(())
}

/// "This device applied that set" (device→Host, type 5 / sub 1).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RrsApplied {
    pub rs_epoch: u32,
    pub object_sha256: [u8; 32],
}

pub fn rrs_applied_encode(applied: &RrsApplied) -> [u8; RRS_APPLIED_SIZE] {
    let mut out = [0_u8; RRS_APPLIED_SIZE];
    head_encode(SUB_APPLIED, &mut out);
    out[4..8].copy_from_slice(&applied.rs_epoch.to_be_bytes());
    out[8..40].copy_from_slice(&applied.object_sha256);
    out
}

pub fn rrs_applied_decode(body: &[u8]) -> Result<RrsApplied> {
    if body.len() != RRS_APPLIED_SIZE {
        return reject();
    }
    head_decode(body, SUB_APPLIED)?;
    let mut object_sha256 = [0_u8; 32];
    object_sha256.copy_from_slice(&body[8..40]);
    Ok(RrsApplied {
        rs_epoch: u32::from_be_bytes(body[4..8].try_into().expect("fixed")),
        object_sha256,
    })
}

/// "Send me the set" (device→Host, type 5 / sub 2; 0 = latest).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RrsGet {
    pub wanted_rs_epoch: u32,
}

pub fn rrs_get_encode(get: &RrsGet) -> [u8; RRS_GET_SIZE] {
    let mut out = [0_u8; RRS_GET_SIZE];
    head_encode(SUB_GET, &mut out);
    out[4..8].copy_from_slice(&get.wanted_rs_epoch.to_be_bytes());
    out
}

pub fn rrs_get_decode(body: &[u8]) -> Result<RrsGet> {
    if body.len() != RRS_GET_SIZE {
        return reject();
    }
    head_decode(body, SUB_GET)?;
    Ok(RrsGet {
        wanted_rs_epoch: u32::from_be_bytes(body[4..8].try_into().expect("fixed")),
    })
}

/// Durable removal-intent evidence (device→Host, type 5 / sub 3; PR B
/// consumes it, PR A only pins the bytes).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RrsNoticeAccepted {
    pub rs_epoch: u32,
    pub notice_sha256: [u8; 32],
}

pub fn rrs_notice_accepted_encode(accepted: &RrsNoticeAccepted) -> [u8; RRS_NOTICE_ACCEPTED_SIZE] {
    let mut out = [0_u8; RRS_NOTICE_ACCEPTED_SIZE];
    head_encode(SUB_NOTICE_ACCEPTED, &mut out);
    out[4..8].copy_from_slice(&accepted.rs_epoch.to_be_bytes());
    out[8..40].copy_from_slice(&accepted.notice_sha256);
    out
}

pub fn rrs_notice_accepted_decode(body: &[u8]) -> Result<RrsNoticeAccepted> {
    if body.len() != RRS_NOTICE_ACCEPTED_SIZE {
        return reject();
    }
    head_decode(body, SUB_NOTICE_ACCEPTED)?;
    let mut notice_sha256 = [0_u8; 32];
    notice_sha256.copy_from_slice(&body[8..40]);
    Ok(RrsNoticeAccepted {
        rs_epoch: u32::from_be_bytes(body[4..8].try_into().expect("fixed")),
        notice_sha256,
    })
}
