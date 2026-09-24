//! bootstrap_v1: the routed member-session bootstrap lane (G-SEC P4 §7.3-§7.4).
//! The byte mirror of the device side
//! (`components/routeloom/{include/routeloom/bootstrap_transport.hpp,
//! src/bootstrap_transport.cpp}`, vectors `protocol/sdkv1-golden/handshake/`
//! with codec `end_object` / `end_sub`):
//!
//! - the end-session object a member exchanges with another member over the
//!   Wire lane: 12 B header + one EDHOC (m1..m4) / RLRES1 (R1..R3) message
//!   (1..960 B). Single-frame objects ride Wire type 3; larger ones ride
//!   type-5 chunks with the lane-separated sub `0x80|(phase<<4)|step` and
//!   type-6 replies. Type 4 stays join-relay Final/Abort only.
//! - the chunk/reply sub namespace shared with the join lane
//!   (`join_sub` in `sdkv1_join_transport.hpp`): the 0x80 lane bit keeps
//!   the two assemblies apart while join golden bytes stay identical.
//!
//! Like the relay lane, every hop protects the frame with its own link
//! session; hop authentication is NOT origin authentication — only the
//! terminal EDHOC/resume verification proves the origin.

use crate::join_relay::{
    EDHOC_ERROR_STEP, JOIN_MESSAGE_MAX, PHASE_EDHOC, PHASE_RESUME, WIRE_TYPE_BOOTSTRAP_AUTH,
};

/// End-object envelope version (P4 §7.3).
pub const END_OBJECT_VERSION: u8 = 1;
pub const END_OBJECT_HEADER_SIZE: usize = 12;
pub const END_OBJECT_MAX: usize = END_OBJECT_HEADER_SIZE + JOIN_MESSAGE_MAX; // 972
/// Purpose byte: pinned to End (2); a link object on this lane is refused.
pub const END_PURPOSE_END: u8 = 2;
/// Session profiles: 1 member production protocol, 2 DevRam.
pub const END_PROFILE_MEMBER: u8 = 1;
pub const END_PROFILE_DEV: u8 = 2;
/// Lane bit of the chunk/reply sub byte (P4 §7.3).
pub const END_SUB_LANE_BIT: u8 = 0x80;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootstrapError {
    /// Structurally wrong for this codec (bad version, flags, step, id).
    Malformed,
    /// Well-formed but not an end object (wrong type, purpose, profile).
    NotAnEndObject,
    /// The output buffer is too small.
    NoCapacity,
}

/// One routed end-session handshake object (P4 §7.3).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EndObject {
    pub phase: u8,
    pub step: u8,
    pub exchange_id: u32,
    pub profile: u8,
    pub message: Vec<u8>,
}

/// Member step rules: EDHOC runs m1..m4 (no step-5 error object),
/// RLRES1 R1..R3.
pub fn end_step_valid(phase: u8, step: u8) -> bool {
    (phase == PHASE_EDHOC && (1..EDHOC_ERROR_STEP).contains(&step))
        || (phase == PHASE_RESUME && (1..=3).contains(&step))
}

/// Chunk/reply sub byte of an end object: `0x80|(phase<<4)|step`.
pub fn end_sub(phase: u8, step: u8) -> Result<u8, BootstrapError> {
    if phase != PHASE_EDHOC && phase != PHASE_RESUME {
        return Err(BootstrapError::NotAnEndObject);
    }
    if !end_step_valid(phase, step) {
        return Err(BootstrapError::NotAnEndObject);
    }
    Ok(END_SUB_LANE_BIT | (phase << 4) | step)
}

/// Splits a chunk/reply sub byte into lane and coordinates. Returns
/// `(is_end_lane, phase, step)`: the join lane keeps the legacy
/// 0x41..0x53 values, the end lane 0xC1..0xC4/0xD1..0xD3.
pub fn object_sub_decode(sub: u8) -> Result<(bool, u8, u8), BootstrapError> {
    if sub & END_SUB_LANE_BIT != 0 {
        let phase = (sub & !END_SUB_LANE_BIT) >> 4;
        let step = sub & 0x0F;
        if !end_step_valid(phase, step) {
            return Err(BootstrapError::Malformed);
        }
        return Ok((true, phase, step));
    }
    let phase = sub >> 4;
    let step = sub & 0x0F;
    let join_ok = (phase == PHASE_EDHOC && (1..=EDHOC_ERROR_STEP).contains(&step))
        || (phase == PHASE_RESUME && (1..=3).contains(&step));
    if !join_ok {
        return Err(BootstrapError::Malformed);
    }
    Ok((false, phase, step))
}

pub fn end_object_encoded_size(message_len: usize) -> usize {
    END_OBJECT_HEADER_SIZE + message_len
}

pub fn end_object_encode(object: &EndObject) -> Result<Vec<u8>, BootstrapError> {
    if object.phase != PHASE_EDHOC && object.phase != PHASE_RESUME {
        return Err(BootstrapError::NotAnEndObject);
    }
    if !end_step_valid(object.phase, object.step) {
        return Err(BootstrapError::Malformed);
    }
    if object.exchange_id == 0 {
        return Err(BootstrapError::Malformed);
    }
    if object.profile != END_PROFILE_MEMBER && object.profile != END_PROFILE_DEV {
        return Err(BootstrapError::NotAnEndObject);
    }
    if object.message.is_empty() || object.message.len() > JOIN_MESSAGE_MAX {
        return Err(BootstrapError::Malformed);
    }
    let mut out = Vec::with_capacity(end_object_encoded_size(object.message.len()));
    out.push(END_OBJECT_VERSION);
    out.push(object.phase);
    out.push(object.step);
    out.push(0);
    out.extend_from_slice(&object.exchange_id.to_be_bytes());
    out.push(END_PURPOSE_END);
    out.push(object.profile);
    out.extend_from_slice(&(object.message.len() as u16).to_be_bytes());
    out.extend_from_slice(&object.message);
    Ok(out)
}

pub fn end_object_decode(encoded: &[u8]) -> Result<EndObject, BootstrapError> {
    if encoded.len() <= END_OBJECT_HEADER_SIZE
        || encoded.len() > END_OBJECT_MAX
        || encoded[0] != END_OBJECT_VERSION
        || encoded[3] != 0
    {
        return Err(BootstrapError::Malformed);
    }
    let phase = encoded[1];
    if phase != PHASE_EDHOC && phase != PHASE_RESUME {
        return Err(BootstrapError::Malformed);
    }
    let step = encoded[2];
    if !end_step_valid(phase, step) {
        return Err(BootstrapError::Malformed);
    }
    let exchange_id = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
    if exchange_id == 0 {
        return Err(BootstrapError::Malformed);
    }
    if encoded[8] != END_PURPOSE_END {
        return Err(BootstrapError::NotAnEndObject);
    }
    let profile = encoded[9];
    if profile != END_PROFILE_MEMBER && profile != END_PROFILE_DEV {
        return Err(BootstrapError::NotAnEndObject);
    }
    let length = u16::from_be_bytes([encoded[10], encoded[11]]) as usize;
    if length == 0 || length > JOIN_MESSAGE_MAX || length + END_OBJECT_HEADER_SIZE != encoded.len()
    {
        return Err(BootstrapError::Malformed);
    }
    Ok(EndObject {
        phase,
        step,
        exchange_id,
        profile,
        message: encoded[END_OBJECT_HEADER_SIZE..].to_vec(),
    })
}

/// Single-frame carriage: only Wire type 3 carries an end object; type 4
/// (join-relay Final/Abort) is refused even when the bytes would parse.
pub fn end_single_frame_decode(wire_type: u8, payload: &[u8]) -> Result<EndObject, BootstrapError> {
    if wire_type != WIRE_TYPE_BOOTSTRAP_AUTH {
        return Err(BootstrapError::NotAnEndObject);
    }
    end_object_decode(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::join_relay::WIRE_TYPE_MEMBERSHIP_RESULT;

    #[test]
    fn sub_namespaces_do_not_overlap() {
        for phase in [PHASE_EDHOC, PHASE_RESUME] {
            let max_step = if phase == PHASE_EDHOC { 4 } else { 3 };
            for step in 1..=max_step {
                let sub = end_sub(phase, step).unwrap();
                assert_eq!(sub & END_SUB_LANE_BIT, END_SUB_LANE_BIT);
                assert_eq!(object_sub_decode(sub).unwrap(), (true, phase, step));
            }
        }
        // The join lane keeps the legacy values byte-identical.
        assert_eq!(object_sub_decode(0x41).unwrap(), (false, 4, 1));
        assert_eq!(object_sub_decode(0x45).unwrap(), (false, 4, 5));
        assert_eq!(object_sub_decode(0x53).unwrap(), (false, 5, 3));
        assert!(object_sub_decode(0xC5).is_err());
        assert!(object_sub_decode(0xD4).is_err());
        assert!(object_sub_decode(0xE1).is_err());
        assert!(object_sub_decode(0x01).is_err());
    }

    #[test]
    fn single_frame_type_is_pinned() {
        let object = EndObject {
            phase: PHASE_EDHOC,
            step: 1,
            exchange_id: 9,
            profile: END_PROFILE_MEMBER,
            message: vec![0xAA],
        };
        let bytes = end_object_encode(&object).unwrap();
        assert_eq!(
            end_single_frame_decode(WIRE_TYPE_BOOTSTRAP_AUTH, &bytes).unwrap(),
            object
        );
        assert!(end_single_frame_decode(WIRE_TYPE_MEMBERSHIP_RESULT, &bytes).is_err());
    }
}
