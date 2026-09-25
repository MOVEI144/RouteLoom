//! Diagnostic CapabilitiesReply feature bits (not USB Hello or JoinRequest bits).
//!
//! The broadcast opt-in remains disabled until old P6 bit-5 RRS grants can
//! be distinguished; a group tag cannot upgrade a peer's capability grant.

pub const CAP_ROUTE_BROADCAST_V1: u32 = 1 << 5;
pub const CAP_MEMBERSHIP_LIFECYCLE_V1: u32 = 1 << 6;
pub const CAP_RRS_GOSSIP_V1: u32 = 1 << 7;
pub const FEATURE_MASK: u32 = 0xff;
