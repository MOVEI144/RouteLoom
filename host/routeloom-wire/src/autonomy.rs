//! Payload registry for the autonomous-mesh control payloads — mirror of
//! `components/routeloom/src/autonomy_wire.cpp`. Wire v1 itself is frozen:
//! these are versioned PAYLOAD layouts carried inside existing FrameTypes,
//! plus the separate RLD1 1-hop bootstrap carrier.
//!
//! Every payload begins with `version u8 (=1) | subtype u8`, then
//! fixed-width big-endian fields; reserved bytes are 0. Decoders reject
//! unknown versions, unknown subtypes, nonzero reserved fields and length
//! mismatches. Byte layouts are pinned by `protocol/autonomy-golden/`.

use crate::admission::{member_frame_type, rld1_kind_allowed};
use crate::{ErrorCode, FrameType, Result, WireError, MAX_APPLICATION_PAYLOAD};

pub const PAYLOAD_VERSION: u8 = 1;
pub const BUSY_PAYLOAD_MAX: usize = 64;
pub const AUTHENTICATED_OBJECT_MAX: usize = 2048;
pub const BOOTSTRAP_OBJECT_MAX: usize = 1024;

pub const BUSY_PAYLOAD_SIZE: usize = 38;
pub const TIME_SYNC_PAYLOAD_SIZE: usize = 26;
pub const CHANNEL_NOTICE_PAYLOAD_SIZE: usize = 25;
pub const NEIGHBOR_PROBE_PAYLOAD_SIZE: usize = 22;
pub const NEIGHBOR_RESULT_PAYLOAD_SIZE: usize = 24;
pub const CONTROL_OBJECT_PAYLOAD_SIZE: usize = 38;
pub const OBJECT_CHUNK_HEADER_SIZE: usize = 38;
pub const OBJECT_ACK_PAYLOAD_SIZE: usize = 37;
pub const BOOTSTRAP_AUTH_HEADER_SIZE: usize = 4;

pub const RLD1_MAGIC: u32 = 0x524c_4431; // "RLD1"
pub const RLD1_VERSION: u8 = 1;
pub const RLD1_HEADER_SIZE: usize = 44;
pub const RLD1_MAX_BODY: usize = 116;
pub const RLD1_MAX_TOTAL: usize = 160;

const _: () = assert!(
    RLD1_HEADER_SIZE + RLD1_MAX_BODY == RLD1_MAX_TOTAL,
    "RLD1 header + body budget must equal the total limit"
);

const PRELUDE: usize = 2;

fn err<T>(detail: &'static str) -> Result<T> {
    Err(WireError::new(ErrorCode::ProtocolError, detail))
}

fn invalid<T>(detail: &'static str) -> Result<T> {
    Err(WireError::new(ErrorCode::InvalidArgument, detail))
}

fn reject<T>() -> Result<T> {
    err("autonomy payload rejected")
}

fn prelude(encoded: &[u8], subtype: u8) -> Result<()> {
    if encoded.len() < PRELUDE || encoded[0] != PAYLOAD_VERSION || encoded[1] != subtype {
        return reject();
    }
    Ok(())
}

/// Fixed-capacity encoded payload buffer (mirror of the C++ EncodedPayload).
pub struct EncodedPayload {
    pub bytes: [u8; MAX_APPLICATION_PAYLOAD],
    pub size: usize,
}

impl Default for EncodedPayload {
    fn default() -> Self {
        Self {
            bytes: [0; MAX_APPLICATION_PAYLOAD],
            size: 0,
        }
    }
}

impl EncodedPayload {
    pub fn view(&self) -> &[u8] {
        &self.bytes[..self.size]
    }

    pub(crate) fn wrap(raw: &[u8]) -> Result<Self> {
        if raw.len() > MAX_APPLICATION_PAYLOAD {
            return Err(WireError::new(
                ErrorCode::NoCapacity,
                "payload exceeds v1 limit",
            ));
        }
        let mut out = Self::default();
        out.bytes[..raw.len()].copy_from_slice(raw);
        out.size = raw.len();
        Ok(out)
    }
}

// --- Busy (FrameType::Busy=20) ------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BusySubtype {
    Reject = 1,
    PressureHint = 2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BusyReason {
    None = 0,
    QueueFull = 1,
    PeerCapacityBusy = 2,
    BudgetExhausted = 3,
    PlannedAbsence = 4,
    RateLimited = 5,
}

#[derive(Clone, Debug)]
pub struct BusyPayload {
    pub subtype: BusySubtype,
    pub reason: BusyReason,
    pub referenced_type: FrameType,
    pub referenced_origin: u64,
    pub referenced_session: u32,
    pub referenced_sequence: u64,
    pub referenced_round: u8,
    pub binding_generation: u32,
    pub feedback_sequence: u32,
    pub retry_after_ms: u32,
    pub pressure: u8,
}

pub fn busy_encode(payload: &BusyPayload, out: &mut EncodedPayload) -> Result<()> {
    let mut raw = Vec::with_capacity(BUSY_PAYLOAD_SIZE);
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.subtype as u8);
    raw.push(payload.reason as u8);
    raw.push(payload.referenced_type as u8);
    raw.extend_from_slice(&payload.referenced_origin.to_be_bytes());
    raw.extend_from_slice(&payload.referenced_session.to_be_bytes());
    raw.extend_from_slice(&payload.referenced_sequence.to_be_bytes());
    raw.push(payload.referenced_round);
    raw.extend_from_slice(&payload.binding_generation.to_be_bytes());
    raw.extend_from_slice(&payload.feedback_sequence.to_be_bytes());
    raw.extend_from_slice(&payload.retry_after_ms.to_be_bytes());
    raw.push(payload.pressure);
    debug_assert_eq!(raw.len(), BUSY_PAYLOAD_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn busy_decode(encoded: &[u8]) -> Result<BusyPayload> {
    if encoded.len() != BUSY_PAYLOAD_SIZE || encoded[0] != PAYLOAD_VERSION {
        return reject();
    }
    let subtype = match encoded[1] {
        1 => BusySubtype::Reject,
        2 => BusySubtype::PressureHint,
        _ => return reject(),
    };
    let reason = match encoded[2] {
        0 => BusyReason::None,
        1 => BusyReason::QueueFull,
        2 => BusyReason::PeerCapacityBusy,
        3 => BusyReason::BudgetExhausted,
        4 => BusyReason::PlannedAbsence,
        5 => BusyReason::RateLimited,
        _ => return reject(),
    };
    let referenced_type = FrameType::try_from(encoded[3])?;
    if !member_frame_type(referenced_type) {
        return reject();
    }
    Ok(BusyPayload {
        subtype,
        reason,
        referenced_type,
        referenced_origin: u64::from_be_bytes(encoded[4..12].try_into().expect("fixed")),
        referenced_session: u32::from_be_bytes(encoded[12..16].try_into().expect("fixed")),
        referenced_sequence: u64::from_be_bytes(encoded[16..24].try_into().expect("fixed")),
        referenced_round: encoded[24],
        binding_generation: u32::from_be_bytes(encoded[25..29].try_into().expect("fixed")),
        feedback_sequence: u32::from_be_bytes(encoded[29..33].try_into().expect("fixed")),
        retry_after_ms: u32::from_be_bytes(encoded[33..37].try_into().expect("fixed")),
        pressure: encoded[37],
    })
}

// --- TimeSync (FrameType::TimeSync=23) -----------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TimeSyncSubtype {
    Sample = 1,
}

#[derive(Clone, Debug)]
pub struct TimeSyncPayload {
    pub subtype: TimeSyncSubtype,
    pub source: u64,
    pub sequence: u32,
    pub reference_ms: u64,
    pub uncertainty_ms: u32,
}

pub fn time_sync_encode(payload: &TimeSyncPayload, out: &mut EncodedPayload) -> Result<()> {
    let mut raw = Vec::with_capacity(TIME_SYNC_PAYLOAD_SIZE);
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.subtype as u8);
    raw.extend_from_slice(&payload.source.to_be_bytes());
    raw.extend_from_slice(&payload.sequence.to_be_bytes());
    raw.extend_from_slice(&payload.reference_ms.to_be_bytes());
    raw.extend_from_slice(&payload.uncertainty_ms.to_be_bytes());
    debug_assert_eq!(raw.len(), TIME_SYNC_PAYLOAD_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn time_sync_decode(encoded: &[u8]) -> Result<TimeSyncPayload> {
    if encoded.len() != TIME_SYNC_PAYLOAD_SIZE {
        return reject();
    }
    prelude(encoded, TimeSyncSubtype::Sample as u8)?;
    Ok(TimeSyncPayload {
        subtype: TimeSyncSubtype::Sample,
        source: u64::from_be_bytes(encoded[2..10].try_into().expect("fixed")),
        sequence: u32::from_be_bytes(encoded[10..14].try_into().expect("fixed")),
        reference_ms: u64::from_be_bytes(encoded[14..22].try_into().expect("fixed")),
        uncertainty_ms: u32::from_be_bytes(encoded[22..26].try_into().expect("fixed")),
    })
}

// --- ChannelNotice (FrameType::ChannelNotice=24) --------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ChannelNoticeSubtype {
    PlannedAbsence = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AbsenceReason {
    None = 0,
    SurveyVisit = 1,
    HelperVisit = 2,
    Cutover = 3,
}

#[derive(Clone, Debug)]
pub struct ChannelNoticePayload {
    pub subtype: ChannelNoticeSubtype,
    pub subject: u64,
    pub channel_epoch: u32,
    pub starts_in_ms: u32,
    pub duration_ms: u32,
    pub reason: AbsenceReason,
    pub protected_cut_id: u16,
}

pub fn channel_notice_encode(
    payload: &ChannelNoticePayload,
    out: &mut EncodedPayload,
) -> Result<()> {
    let mut raw = Vec::with_capacity(CHANNEL_NOTICE_PAYLOAD_SIZE);
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.subtype as u8);
    raw.extend_from_slice(&payload.subject.to_be_bytes());
    raw.extend_from_slice(&payload.channel_epoch.to_be_bytes());
    raw.extend_from_slice(&payload.starts_in_ms.to_be_bytes());
    raw.extend_from_slice(&payload.duration_ms.to_be_bytes());
    raw.push(payload.reason as u8);
    raw.extend_from_slice(&payload.protected_cut_id.to_be_bytes());
    debug_assert_eq!(raw.len(), CHANNEL_NOTICE_PAYLOAD_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn channel_notice_decode(encoded: &[u8]) -> Result<ChannelNoticePayload> {
    if encoded.len() != CHANNEL_NOTICE_PAYLOAD_SIZE {
        return reject();
    }
    prelude(encoded, ChannelNoticeSubtype::PlannedAbsence as u8)?;
    let reason = match encoded[22] {
        0 => AbsenceReason::None,
        1 => AbsenceReason::SurveyVisit,
        2 => AbsenceReason::HelperVisit,
        3 => AbsenceReason::Cutover,
        _ => return reject(),
    };
    Ok(ChannelNoticePayload {
        subtype: ChannelNoticeSubtype::PlannedAbsence,
        subject: u64::from_be_bytes(encoded[2..10].try_into().expect("fixed")),
        channel_epoch: u32::from_be_bytes(encoded[10..14].try_into().expect("fixed")),
        starts_in_ms: u32::from_be_bytes(encoded[14..18].try_into().expect("fixed")),
        duration_ms: u32::from_be_bytes(encoded[18..22].try_into().expect("fixed")),
        reason,
        protected_cut_id: u16::from_be_bytes(encoded[23..25].try_into().expect("fixed")),
    })
}

// --- NeighborProbe / NeighborResult (FrameType 40/41) ----------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NeighborProbeSubtype {
    AvailabilityProbe = 1,
}

#[derive(Clone, Debug)]
pub struct NeighborProbePayload {
    pub subtype: NeighborProbeSubtype,
    pub binding_generation: u32,
    pub probe_sequence: u32,
    pub sent_ms: u64,
    pub requested_lease_ms: u32,
}

pub fn neighbor_probe_encode(
    payload: &NeighborProbePayload,
    out: &mut EncodedPayload,
) -> Result<()> {
    let mut raw = Vec::with_capacity(NEIGHBOR_PROBE_PAYLOAD_SIZE);
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.subtype as u8);
    raw.extend_from_slice(&payload.binding_generation.to_be_bytes());
    raw.extend_from_slice(&payload.probe_sequence.to_be_bytes());
    raw.extend_from_slice(&payload.sent_ms.to_be_bytes());
    raw.extend_from_slice(&payload.requested_lease_ms.to_be_bytes());
    debug_assert_eq!(raw.len(), NEIGHBOR_PROBE_PAYLOAD_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn neighbor_probe_decode(encoded: &[u8]) -> Result<NeighborProbePayload> {
    if encoded.len() != NEIGHBOR_PROBE_PAYLOAD_SIZE {
        return reject();
    }
    prelude(encoded, NeighborProbeSubtype::AvailabilityProbe as u8)?;
    Ok(NeighborProbePayload {
        subtype: NeighborProbeSubtype::AvailabilityProbe,
        binding_generation: u32::from_be_bytes(encoded[2..6].try_into().expect("fixed")),
        probe_sequence: u32::from_be_bytes(encoded[6..10].try_into().expect("fixed")),
        sent_ms: u64::from_be_bytes(encoded[10..18].try_into().expect("fixed")),
        requested_lease_ms: u32::from_be_bytes(encoded[18..22].try_into().expect("fixed")),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NeighborResultSubtype {
    AvailabilityResult = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NeighborResultCode {
    Unknown = 0,
    Reachable = 1,
    NotListening = 2,
    Leaving = 3,
}

#[derive(Clone, Debug)]
pub struct NeighborResultPayload {
    pub subtype: NeighborResultSubtype,
    pub binding_generation: u32,
    pub probe_sequence: u32,
    pub result: NeighborResultCode,
    pub pressure: u8,
    pub queue_delay_ms: u32,
    pub est_airtime_us: u32,
    pub lease_granted_ms: u32,
}

pub fn neighbor_result_encode(
    payload: &NeighborResultPayload,
    out: &mut EncodedPayload,
) -> Result<()> {
    let mut raw = Vec::with_capacity(NEIGHBOR_RESULT_PAYLOAD_SIZE);
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.subtype as u8);
    raw.extend_from_slice(&payload.binding_generation.to_be_bytes());
    raw.extend_from_slice(&payload.probe_sequence.to_be_bytes());
    raw.push(payload.result as u8);
    raw.push(payload.pressure);
    raw.extend_from_slice(&payload.queue_delay_ms.to_be_bytes());
    raw.extend_from_slice(&payload.est_airtime_us.to_be_bytes());
    raw.extend_from_slice(&payload.lease_granted_ms.to_be_bytes());
    debug_assert_eq!(raw.len(), NEIGHBOR_RESULT_PAYLOAD_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn neighbor_result_decode(encoded: &[u8]) -> Result<NeighborResultPayload> {
    if encoded.len() != NEIGHBOR_RESULT_PAYLOAD_SIZE {
        return reject();
    }
    prelude(encoded, NeighborResultSubtype::AvailabilityResult as u8)?;
    let result = match encoded[10] {
        0 => NeighborResultCode::Unknown,
        1 => NeighborResultCode::Reachable,
        2 => NeighborResultCode::NotListening,
        3 => NeighborResultCode::Leaving,
        _ => return reject(),
    };
    Ok(NeighborResultPayload {
        subtype: NeighborResultSubtype::AvailabilityResult,
        binding_generation: u32::from_be_bytes(encoded[2..6].try_into().expect("fixed")),
        probe_sequence: u32::from_be_bytes(encoded[6..10].try_into().expect("fixed")),
        result,
        pressure: encoded[11],
        queue_delay_ms: u32::from_be_bytes(encoded[12..16].try_into().expect("fixed")),
        est_airtime_us: u32::from_be_bytes(encoded[16..20].try_into().expect("fixed")),
        lease_granted_ms: u32::from_be_bytes(encoded[20..24].try_into().expect("fixed")),
    })
}

// --- Authenticated objects (FrameType 49/50/51) ----------------------------------

pub type ObjectHash = [u8; 32];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlObjectSubtype {
    Manifest = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ControlObjectKind {
    ChannelPlan = 1,
    RecoverySnapshot = 2,
    /// Scope-gateway-config §5.1: end-protected routed config permits ride
    /// the same object transfer; link-only kinds 1/2 keep their path.
    ConfigPermit = 3,
    /// Signed recovery commands (RCR1) ride a dedicated lane of the same
    /// transfer (04 §4.7, 06 §6.3): separate from kind-3 intake so an
    /// impaired journal can receive recovery evidence while refusing
    /// normal permits.
    ConfigRecovery = 4,
}

#[derive(Clone, Debug)]
pub struct ControlObjectPayload {
    pub subtype: ControlObjectSubtype,
    pub kind: ControlObjectKind,
    pub total_len: u16,
    pub object_hash: ObjectHash,
}

pub fn control_object_encode(
    payload: &ControlObjectPayload,
    out: &mut EncodedPayload,
) -> Result<()> {
    if payload.total_len == 0 || usize::from(payload.total_len) > AUTHENTICATED_OBJECT_MAX {
        return invalid("control object length out of range");
    }
    let mut raw = Vec::with_capacity(CONTROL_OBJECT_PAYLOAD_SIZE);
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.subtype as u8);
    raw.push(payload.kind as u8);
    raw.push(0);
    raw.extend_from_slice(&payload.total_len.to_be_bytes());
    raw.extend_from_slice(&payload.object_hash);
    debug_assert_eq!(raw.len(), CONTROL_OBJECT_PAYLOAD_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn control_object_decode(encoded: &[u8]) -> Result<ControlObjectPayload> {
    if encoded.len() != CONTROL_OBJECT_PAYLOAD_SIZE {
        return reject();
    }
    prelude(encoded, ControlObjectSubtype::Manifest as u8)?;
    let kind = match encoded[2] {
        1 => ControlObjectKind::ChannelPlan,
        2 => ControlObjectKind::RecoverySnapshot,
        3 => ControlObjectKind::ConfigPermit,
        4 => ControlObjectKind::ConfigRecovery,
        _ => return reject(),
    };
    let total_len = u16::from_be_bytes(encoded[4..6].try_into().expect("fixed"));
    if encoded[3] != 0 || total_len == 0 || usize::from(total_len) > AUTHENTICATED_OBJECT_MAX {
        return reject();
    }
    let mut object_hash = [0_u8; 32];
    object_hash.copy_from_slice(&encoded[6..38]);
    Ok(ControlObjectPayload {
        subtype: ControlObjectSubtype::Manifest,
        kind,
        total_len,
        object_hash,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObjectChunkSubtype {
    Chunk = 1,
}

#[derive(Clone, Debug)]
pub struct ObjectChunkPayload {
    pub subtype: ObjectChunkSubtype,
    pub object_hash: ObjectHash,
    pub offset: u16,
    pub data: Vec<u8>,
}

pub fn object_chunk_encode(payload: &ObjectChunkPayload, out: &mut EncodedPayload) -> Result<()> {
    if payload.data.len() > MAX_APPLICATION_PAYLOAD - OBJECT_CHUNK_HEADER_SIZE
        || usize::from(payload.offset) + payload.data.len() > AUTHENTICATED_OBJECT_MAX
    {
        return invalid("object chunk out of range");
    }
    let mut raw = Vec::with_capacity(OBJECT_CHUNK_HEADER_SIZE + payload.data.len());
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.subtype as u8);
    raw.extend_from_slice(&payload.object_hash);
    raw.extend_from_slice(&payload.offset.to_be_bytes());
    raw.extend_from_slice(&(payload.data.len() as u16).to_be_bytes());
    raw.extend_from_slice(&payload.data);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn object_chunk_decode(encoded: &[u8]) -> Result<ObjectChunkPayload> {
    if encoded.len() < OBJECT_CHUNK_HEADER_SIZE || encoded.len() > MAX_APPLICATION_PAYLOAD {
        return reject();
    }
    prelude(encoded, ObjectChunkSubtype::Chunk as u8)?;
    let mut object_hash = [0_u8; 32];
    object_hash.copy_from_slice(&encoded[2..34]);
    let offset = u16::from_be_bytes(encoded[34..36].try_into().expect("fixed"));
    let length = usize::from(u16::from_be_bytes(
        encoded[36..38].try_into().expect("fixed"),
    ));
    if encoded.len() - OBJECT_CHUNK_HEADER_SIZE != length
        || usize::from(offset) + length > AUTHENTICATED_OBJECT_MAX
    {
        return reject();
    }
    Ok(ObjectChunkPayload {
        subtype: ObjectChunkSubtype::Chunk,
        object_hash,
        offset,
        data: encoded[OBJECT_CHUNK_HEADER_SIZE..].to_vec(),
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObjectAckSubtype {
    Ack = 1,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ObjectAckStatus {
    Ok = 0,
    Incomplete = 1,
    Failed = 2,
}

#[derive(Clone, Debug)]
pub struct ObjectAckPayload {
    pub subtype: ObjectAckSubtype,
    pub object_hash: ObjectHash,
    pub received_len: u16,
    pub status: ObjectAckStatus,
}

pub fn object_ack_encode(payload: &ObjectAckPayload, out: &mut EncodedPayload) -> Result<()> {
    let mut raw = Vec::with_capacity(OBJECT_ACK_PAYLOAD_SIZE);
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.subtype as u8);
    raw.extend_from_slice(&payload.object_hash);
    raw.extend_from_slice(&payload.received_len.to_be_bytes());
    raw.push(payload.status as u8);
    debug_assert_eq!(raw.len(), OBJECT_ACK_PAYLOAD_SIZE);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn object_ack_decode(encoded: &[u8]) -> Result<ObjectAckPayload> {
    if encoded.len() != OBJECT_ACK_PAYLOAD_SIZE {
        return reject();
    }
    prelude(encoded, ObjectAckSubtype::Ack as u8)?;
    let status = match encoded[36] {
        0 => ObjectAckStatus::Ok,
        1 => ObjectAckStatus::Incomplete,
        2 => ObjectAckStatus::Failed,
        _ => return reject(),
    };
    let mut object_hash = [0_u8; 32];
    object_hash.copy_from_slice(&encoded[2..34]);
    Ok(ObjectAckPayload {
        subtype: ObjectAckSubtype::Ack,
        object_hash,
        received_len: u16::from_be_bytes(encoded[34..36].try_into().expect("fixed")),
        status,
    })
}

// --- BootstrapAuth body (FrameType::BootstrapAuth=3) -----------------------------

/// PROVE/CONFIRM/FINISH are logical phases INSIDE type 3 — never new
/// top-level frame types. The phase rides in the payload subtype byte.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum AuthPhase {
    Prove = 1,
    Confirm = 2,
    Finish = 3,
}

#[derive(Clone, Debug)]
pub struct BootstrapAuthBody {
    pub phase: AuthPhase,
    pub step_index: u8,
    pub body: Vec<u8>,
}

pub fn bootstrap_auth_encode(payload: &BootstrapAuthBody, out: &mut EncodedPayload) -> Result<()> {
    if payload.body.len() > MAX_APPLICATION_PAYLOAD - BOOTSTRAP_AUTH_HEADER_SIZE {
        return invalid("bootstrap auth body too large");
    }
    let mut raw = Vec::with_capacity(BOOTSTRAP_AUTH_HEADER_SIZE + payload.body.len());
    raw.push(PAYLOAD_VERSION);
    raw.push(payload.phase as u8);
    raw.push(payload.step_index);
    raw.push(0);
    raw.extend_from_slice(&payload.body);
    *out = EncodedPayload::wrap(&raw)?;
    Ok(())
}

pub fn bootstrap_auth_decode(encoded: &[u8]) -> Result<BootstrapAuthBody> {
    if encoded.len() < BOOTSTRAP_AUTH_HEADER_SIZE || encoded.len() > MAX_APPLICATION_PAYLOAD {
        return reject();
    }
    if encoded[0] != PAYLOAD_VERSION {
        return reject();
    }
    let phase = match encoded[1] {
        1 => AuthPhase::Prove,
        2 => AuthPhase::Confirm,
        3 => AuthPhase::Finish,
        _ => return reject(),
    };
    if encoded[3] != 0 {
        return reject();
    }
    Ok(BootstrapAuthBody {
        phase,
        step_index: encoded[2],
        body: encoded[BOOTSTRAP_AUTH_HEADER_SIZE..].to_vec(),
    })
}

// --- RLD1 discovery carrier -------------------------------------------------------

/// Cheap carrier probe for the single classification point: true iff the
/// bytes start with the full RLD1 magic. A true probe followed by a decode
/// error is a REJECT, never a fallback into Wire.
pub fn rld1_probe(encoded: &[u8]) -> bool {
    encoded.len() >= 4 && encoded[..4] == RLD1_MAGIC.to_be_bytes()
}

#[derive(Clone, Debug)]
pub struct Rld1Envelope {
    pub kind: FrameType, // only {1,2,3,5,6} — see rld1_kind_allowed
    pub flags: u16,      // v1: all bits reserved, must be 0
    pub network_hint: u32,
    pub claimed_node: u64,
    pub transaction_nonce: [u8; 16],
    pub capability_bits: u32,
    pub body: Vec<u8>,
}

pub fn rld1_encode(envelope: &Rld1Envelope, out: &mut Vec<u8>) -> Result<()> {
    if !rld1_kind_allowed(envelope.kind) {
        return invalid("kind not permitted on RLD1");
    }
    if envelope.flags != 0 {
        return invalid("RLD1 v1 flags are reserved");
    }
    if envelope.body.len() > RLD1_MAX_BODY {
        return Err(WireError::new(
            ErrorCode::NoCapacity,
            "RLD1 body exceeds budget",
        ));
    }
    out.clear();
    out.reserve(RLD1_HEADER_SIZE + envelope.body.len());
    out.extend_from_slice(&RLD1_MAGIC.to_be_bytes());
    out.push(RLD1_VERSION);
    out.push(envelope.kind as u8);
    out.extend_from_slice(&(RLD1_HEADER_SIZE as u16).to_be_bytes());
    out.extend_from_slice(&((RLD1_HEADER_SIZE + envelope.body.len()) as u16).to_be_bytes());
    out.extend_from_slice(&envelope.flags.to_be_bytes());
    out.extend_from_slice(&envelope.network_hint.to_be_bytes());
    out.extend_from_slice(&envelope.claimed_node.to_be_bytes());
    out.extend_from_slice(&envelope.transaction_nonce);
    out.extend_from_slice(&envelope.capability_bits.to_be_bytes());
    out.extend_from_slice(&envelope.body);
    Ok(())
}

pub fn rld1_decode(encoded: &[u8]) -> Result<Rld1Envelope> {
    if encoded.len() < RLD1_HEADER_SIZE || encoded.len() > RLD1_MAX_TOTAL {
        return reject();
    }
    let magic = u32::from_be_bytes(encoded[0..4].try_into().expect("fixed"));
    let version = encoded[4];
    let kind = encoded[5];
    let header_len = u16::from_be_bytes(encoded[6..8].try_into().expect("fixed"));
    let total_len = usize::from(u16::from_be_bytes(
        encoded[8..10].try_into().expect("fixed"),
    ));
    let flags = u16::from_be_bytes(encoded[10..12].try_into().expect("fixed"));
    if magic != RLD1_MAGIC
        || version != RLD1_VERSION
        || usize::from(header_len) != RLD1_HEADER_SIZE
        || total_len != encoded.len()
        || total_len > RLD1_MAX_TOTAL
        || flags != 0
    {
        return reject();
    }
    let kind = FrameType::try_from(kind).map_err(|_| WireError {
        code: ErrorCode::ProtocolError,
        detail: "autonomy payload rejected",
    })?;
    if !rld1_kind_allowed(kind) {
        return reject();
    }
    let mut transaction_nonce = [0_u8; 16];
    transaction_nonce.copy_from_slice(&encoded[24..40]);
    Ok(Rld1Envelope {
        kind,
        flags,
        network_hint: u32::from_be_bytes(encoded[12..16].try_into().expect("fixed")),
        claimed_node: u64::from_be_bytes(encoded[16..24].try_into().expect("fixed")),
        transaction_nonce,
        capability_bits: u32::from_be_bytes(encoded[40..44].try_into().expect("fixed")),
        body: encoded[RLD1_HEADER_SIZE..].to_vec(),
    })
}
