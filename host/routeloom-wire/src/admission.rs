//! Coarse admission screen — mirror of
//! `components/routeloom/include/routeloom/admission.hpp`, synchronized with
//! the authoritative `membership_allowlist` in `protocol/semantics.json`.
//!
//! This is the second conjunct of the full admission product, never the
//! final gate: carrier, role, transaction liveness, evidence, feature
//! capability and budget still apply. See
//! docs/design/autonomous-mesh/06-membership-admission.md §4.

use crate::FrameType;

/// Node x Network belonging — the authoritative six membership states.
/// Values 0-5 are frozen; the membership controller is the only writer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum MembershipState {
    Unprovisioned = 0,
    Discovering = 1,
    Authenticating = 2,
    AuthorizedPendingCommit = 3,
    Member = 4,
    Revoked = 5,
}

impl TryFrom<u8> for MembershipState {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0 => Self::Unprovisioned,
            1 => Self::Discovering,
            2 => Self::Authenticating,
            3 => Self::AuthorizedPendingCommit,
            4 => Self::Member,
            5 => Self::Revoked,
            _ => return Err(()),
        })
    }
}

/// Carrier the frame arrived on / would leave on. RLD1 is the limited 1-hop
/// bootstrap carrier; it shares FrameType numbers with Wire v1 but is a
/// different carrier with a smaller kind set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AdmissionCarrier {
    WireV1 = 0,
    Rld1 = 1,
}

/// True for every FrameType id assigned in v1 — the semantics.json MEMBER
/// allowlist is the bootstrap set plus the member_only set, i.e. every known
/// type. Unknown ids are unconstructable: `FrameType::try_from` already
/// rejected them at the decode boundary (same contract as the C++ explicit
/// `member_frame_type` list).
pub fn member_frame_type(_frame_type: FrameType) -> bool {
    true
}

/// The seven bootstrap-scope type ids (semantics.json `membership_allowlist`
/// bootstrap set, ids 1-7).
pub fn bootstrap_frame_type(frame_type: FrameType) -> bool {
    matches!(
        frame_type,
        FrameType::Discover
            | FrameType::Offer
            | FrameType::BootstrapAuth
            | FrameType::MembershipResult
            | FrameType::BootstrapChunk
            | FrameType::BootstrapReply
            | FrameType::MembershipQuery
    )
}

/// Coarse candidate screen synchronized with `protocol/semantics.json`
/// `membership_allowlist`. Never the final authorization.
pub fn frame_allowed(state: MembershipState, frame_type: FrameType) -> bool {
    match state {
        MembershipState::Unprovisioned | MembershipState::Discovering => {
            matches!(frame_type, FrameType::Discover | FrameType::Offer)
        }
        MembershipState::Authenticating => matches!(
            frame_type,
            FrameType::Discover
                | FrameType::Offer
                | FrameType::BootstrapAuth
                | FrameType::BootstrapChunk
                | FrameType::BootstrapReply
        ),
        MembershipState::AuthorizedPendingCommit => matches!(
            frame_type,
            FrameType::MembershipQuery
                | FrameType::MembershipResult
                | FrameType::BootstrapChunk
                | FrameType::BootstrapReply
        ),
        MembershipState::Member => member_frame_type(frame_type),
        MembershipState::Revoked => false,
    }
}

/// RLD1 kind allowlist {1,2,3,5,6} — MembershipResult/MembershipQuery, DATA
/// and every unknown kind are forbidden on the RLD1 carrier
/// (contracts.json `admission.rld1_type_ids`).
pub fn rld1_kind_allowed(frame_type: FrameType) -> bool {
    matches!(
        frame_type,
        FrameType::Discover
            | FrameType::Offer
            | FrameType::BootstrapAuth
            | FrameType::BootstrapChunk
            | FrameType::BootstrapReply
    )
}
