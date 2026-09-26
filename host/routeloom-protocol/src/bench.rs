//! RLB1 bench application wire codec (design-devflow.md §5.2): the
//! application-level payload format spoken between the bench host and
//! `firmware/bench_node` over the public SDK data path. Byte-identical to
//! the device side in `components/routeloom_bench/{include/routeloom/bench/
//! protocol.hpp,src/protocol.cpp}`; the shared vectors under
//! `protocol/bench-golden` pin both.
//!
//!   0   magic   4B  "RLB1"
//!   4   version 1B  = 1
//!   5   opcode  1B
//!   6   flags   u16 (big-endian)
//!   8   run_uuid 16B — one host-side run; commands for a dead/foreign run
//!                     are late
//!  24   sequence u32 — ordinal inside the run
//!  28   body CRC32 — ISO HDLC over the body bytes only
//!  32   body
//!
//! The three payload ceilings are distinct: an SDK unicast application
//! payload is 128 B (body <= 96 B), a group application payload is 127 B
//! (body <= 95 B), and a command that must also survive the normal HostOps
//! lane stays <= 96 B total (body <= 64 B). Host-originated commands use the
//! command bound so they work on either path; device replies only ever ride
//! unicast DATA.

use std::fmt;

use crate::crc32_iso_hdlc;

pub const MAGIC: [u8; 4] = *b"RLB1";
pub const PROTOCOL_VERSION: u8 = 1;
pub const HEADER_SIZE: usize = 32;
/// Unicast application payload ceiling (SDK kMaxApplicationPayload).
pub const MAX_UNICAST_PAYLOAD: usize = 128;
/// Group application payload ceiling.
pub const MAX_GROUP_PAYLOAD: usize = 127;
/// Body bound on the unicast path.
pub const MAX_BODY: usize = MAX_UNICAST_PAYLOAD - HEADER_SIZE; // 96
/// Body bound on the group path.
pub const MAX_GROUP_BODY: usize = MAX_GROUP_PAYLOAD - HEADER_SIZE; // 95
/// Body bound for a command that also fits the 96 B HostOps payload lane.
pub const MAX_COMMAND_BODY: usize = 96 - HEADER_SIZE; // 64

pub const RUN_UUID_SIZE: usize = 16;
pub type RunUuid = [u8; RUN_UUID_SIZE];
pub const NULL_RUN: RunUuid = [0; RUN_UUID_SIZE];

/// Reserved NodeId values the bench never treats as a device.
pub const INVALID_NODE: u64 = 0;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum Opcode {
    Hello = 0x01,
    Capabilities = 0x02,
    EchoRequest = 0x10,
    EchoReply = 0x11,
    CountOnly = 0x20,
    CountGet = 0x21,
    CountStatus = 0x22,
    Rollcall = 0x30,
    StatusGet = 0x40,
    Status = 0x41,
    PeerSendStart = 0x50,
    PeerSendStatus = 0x51,
    PeerSendStop = 0x52,
    CounterReset = 0x60,
    FaultSet = 0x61,
    ResetRequest = 0x70,
    ResetAck = 0x71,
}

impl Opcode {
    /// The opcode list CAPABILITIES advertises — kept in lockstep with the
    /// enum (the C++ `opcode_known` switch is the device-side check).
    pub const ALL: [Opcode; 17] = [
        Opcode::Hello,
        Opcode::Capabilities,
        Opcode::EchoRequest,
        Opcode::EchoReply,
        Opcode::CountOnly,
        Opcode::CountGet,
        Opcode::CountStatus,
        Opcode::Rollcall,
        Opcode::StatusGet,
        Opcode::Status,
        Opcode::PeerSendStart,
        Opcode::PeerSendStatus,
        Opcode::PeerSendStop,
        Opcode::CounterReset,
        Opcode::FaultSet,
        Opcode::ResetRequest,
        Opcode::ResetAck,
    ];

    pub fn from_byte(value: u8) -> Option<Opcode> {
        Self::ALL.iter().copied().find(|op| *op as u8 == value)
    }

    /// Replies carry FLAG_RESPONSE; this predicate is the reply-opcode list
    /// for encoders and "is this opcode ever a response" checks.
    pub fn is_reply(self) -> bool {
        matches!(
            self,
            Opcode::Capabilities
                | Opcode::EchoReply
                | Opcode::CountStatus
                | Opcode::Status
                | Opcode::PeerSendStatus
                | Opcode::ResetAck
        )
    }
}

/// A reply: device answers a request. Response-flagged input is never
/// dispatched as a request, which is what makes replies unechoable.
pub const FLAG_RESPONSE: u16 = 0x0001;
/// A reply re-sent for a request already answered inside the run window.
pub const FLAG_DUPLICATE: u16 = 0x0002;
/// A reply to a request whose run is retired/unknown, or a control command
/// bound to a previous boot incarnation — the run is never re-opened.
pub const FLAG_LATE: u16 = 0x0004;
/// A sender-side marker: a constrained fault injection is currently active.
pub const FLAG_FAULT: u16 = 0x0008;

/// Wire-decode verdicts. An unknown opcode is NOT an error — the header is
/// well formed and the application layer rejects it (the device counts it
/// as `unknown_opcode`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    Truncated,
    BadMagic,
    UnsupportedVersion(u8),
    CrcMismatch,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DecodeError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Message<'a> {
    /// Raw opcode byte — may be a value `Opcode` does not know.
    pub opcode: u8,
    pub flags: u16,
    pub run: RunUuid,
    pub sequence: u32,
    /// Borrows `wire`; copy out if the message must outlive the buffer.
    pub body: &'a [u8],
}

/// Decode one wire message.
pub fn decode(wire: &[u8]) -> Result<Message<'_>, DecodeError> {
    if wire.len() < HEADER_SIZE {
        return Err(DecodeError::Truncated);
    }
    if wire[..4] != MAGIC {
        return Err(DecodeError::BadMagic);
    }
    let version = wire[4];
    if version != PROTOCOL_VERSION {
        return Err(DecodeError::UnsupportedVersion(version));
    }
    let opcode = wire[5];
    let flags = u16::from_be_bytes([wire[6], wire[7]]);
    let mut run = [0u8; RUN_UUID_SIZE];
    run.copy_from_slice(&wire[8..24]);
    let sequence = u32::from_be_bytes(wire[24..28].try_into().unwrap());
    let crc = u32::from_be_bytes(wire[28..32].try_into().unwrap());
    let body = &wire[HEADER_SIZE..];
    if crc32_iso_hdlc(body) != crc {
        return Err(DecodeError::CrcMismatch);
    }
    Ok(Message {
        opcode,
        flags,
        run,
        sequence,
        body,
    })
}

/// Encode one wire message. Errors on a body over the unicast bound — the
/// caller picks the bound that applies to the lane in use.
pub fn encode(
    opcode: Opcode,
    flags: u16,
    run: &RunUuid,
    sequence: u32,
    body: &[u8],
) -> Result<Vec<u8>, BenchError> {
    if body.len() > MAX_BODY {
        return Err(BenchError::BodyTooLarge);
    }
    let mut out = Vec::with_capacity(HEADER_SIZE + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(PROTOCOL_VERSION);
    out.push(opcode as u8);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(run);
    out.extend_from_slice(&sequence.to_be_bytes());
    out.extend_from_slice(&crc32_iso_hdlc(body).to_be_bytes());
    out.extend_from_slice(body);
    Ok(out)
}

/// Codec failures beyond the wire envelope (fixed-layout bodies).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BenchError {
    BodyTooLarge,
    Truncated,
    TrailingGarbage,
    /// Structurally complete but semantically invalid — names the violated
    /// rule.
    Invalid(&'static str),
}

impl fmt::Display for BenchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for BenchError {}

struct Reader<'a> {
    input: &'a [u8],
}

impl<'a> Reader<'a> {
    fn u8(&mut self) -> Result<u8, BenchError> {
        let (head, rest) = self.input.split_first().ok_or(BenchError::Truncated)?;
        self.input = rest;
        Ok(*head)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], BenchError> {
        if self.input.len() < n {
            return Err(BenchError::Truncated);
        }
        let (head, rest) = self.input.split_at(n);
        self.input = rest;
        Ok(head)
    }

    fn u16(&mut self) -> Result<u16, BenchError> {
        Ok(u16::from_be_bytes(self.take(2)?.try_into().unwrap()))
    }

    fn u32(&mut self) -> Result<u32, BenchError> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }

    fn u64(&mut self) -> Result<u64, BenchError> {
        Ok(u64::from_be_bytes(self.take(8)?.try_into().unwrap()))
    }

    fn finish(self) -> Result<(), BenchError> {
        if self.input.is_empty() {
            Ok(())
        } else {
            Err(BenchError::TrailingGarbage)
        }
    }
}

// --- Bodies -------------------------------------------------------------
// Every body is a fixed prefix plus optional opaque payload; each codec is
// a pure encode/decode pair that rejects trailing garbage where the layout
// is fixed — the same rule the C++ `decode_*` functions apply.

/// CAPABILITIES body (HELLO reply and the once-per-join announce).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CapabilitiesBody {
    pub app_protocol: u8,
    pub app_version: u8,
    pub max_unicast_body: u8,
    pub max_group_body: u8,
    pub max_command_body: u8,
    pub run_slots: u8,
    pub reply_queue: u8,
    pub generator_max_inflight: u8,
    pub boot_incarnation: u64,
    pub firmware_digest: u32,
    pub config_digest: u32,
    pub opcodes: Vec<u8>,
}

/// The opcode list is sized beyond the current 17 so later tickets can add
/// opcodes without changing the body layout budget.
pub const CAPABILITIES_OPCODES_MAX: usize = 24;

pub fn encode_capabilities(body: &CapabilitiesBody) -> Result<Vec<u8>, BenchError> {
    if body.opcodes.len() > CAPABILITIES_OPCODES_MAX {
        return Err(BenchError::Invalid("opcode list over 24"));
    }
    let mut out = Vec::with_capacity(25 + body.opcodes.len());
    out.push(body.app_protocol);
    out.push(body.app_version);
    out.push(body.max_unicast_body);
    out.push(body.max_group_body);
    out.push(body.max_command_body);
    out.push(body.run_slots);
    out.push(body.reply_queue);
    out.push(body.generator_max_inflight);
    out.extend_from_slice(&body.boot_incarnation.to_be_bytes());
    out.extend_from_slice(&body.firmware_digest.to_be_bytes());
    out.extend_from_slice(&body.config_digest.to_be_bytes());
    out.push(body.opcodes.len() as u8);
    out.extend_from_slice(&body.opcodes);
    Ok(out)
}

pub fn decode_capabilities(body: &[u8]) -> Result<CapabilitiesBody, BenchError> {
    let mut r = Reader { input: body };
    let out = CapabilitiesBody {
        app_protocol: r.u8()?,
        app_version: r.u8()?,
        max_unicast_body: r.u8()?,
        max_group_body: r.u8()?,
        max_command_body: r.u8()?,
        run_slots: r.u8()?,
        reply_queue: r.u8()?,
        generator_max_inflight: r.u8()?,
        boot_incarnation: r.u64()?,
        firmware_digest: r.u32()?,
        config_digest: r.u32()?,
        opcodes: {
            let count = r.u8()? as usize;
            if count > CAPABILITIES_OPCODES_MAX {
                return Err(BenchError::Invalid("opcode count over 24"));
            }
            r.take(count)?.to_vec()
        },
    };
    r.finish()?;
    Ok(out)
}

/// COUNT_STATUS body — the state of one tracked run (header run_uuid).
/// `window` covers sequences [window_base - 63, window_base] seen uniquely.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CountStatusBody {
    /// 0 unknown run, 1 active, 2 retired.
    pub state: u8,
    pub unique_packets: u32,
    pub unique_bytes: u32,
    pub duplicates: u32,
    pub crc_invalid: u32,
    pub first_ms: u32,
    pub last_ms: u32,
    pub window_base: u32,
    pub window: u64,
}

pub const COUNT_STATUS_SIZE: usize = 37;

pub fn encode_count_status(body: &CountStatusBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(COUNT_STATUS_SIZE);
    out.push(body.state);
    for word in [
        body.unique_packets,
        body.unique_bytes,
        body.duplicates,
        body.crc_invalid,
        body.first_ms,
        body.last_ms,
        body.window_base,
    ] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out.extend_from_slice(&body.window.to_be_bytes());
    out
}

pub fn decode_count_status(body: &[u8]) -> Result<CountStatusBody, BenchError> {
    let mut r = Reader { input: body };
    let out = CountStatusBody {
        state: r.u8()?,
        unique_packets: r.u32()?,
        unique_bytes: r.u32()?,
        duplicates: r.u32()?,
        crc_invalid: r.u32()?,
        first_ms: r.u32()?,
        last_ms: r.u32()?,
        window_base: r.u32()?,
        window: r.u64()?,
    };
    r.finish()?;
    Ok(out)
}

/// ROLLCALL body: the optional per-device STATUS page request; 0xFF = none.
pub const ROLLCALL_NO_PAGE: u8 = 0xFF;

/// STATUS_GET body: which page to return.
pub fn encode_page_body(page: u8) -> Vec<u8> {
    vec![page]
}

pub fn decode_page_body(body: &[u8]) -> Result<u8, BenchError> {
    let mut r = Reader { input: body };
    let page = r.u8()?;
    r.finish()?;
    Ok(page)
}

/// STATUS body head: a bounded page of device state. `sample_seq`
/// identifies one consistent snapshot generation — a host discards a page
/// set whose sample_seq or boot_incarnation changed mid-scan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StatusHead {
    pub sample_seq: u16,
    pub boot_incarnation: u64,
    pub page: u8,
    pub page_count: u8,
}

pub const STATUS_HEAD_SIZE: usize = 12;

pub fn decode_status_head(body: &[u8]) -> Result<(StatusHead, &[u8]), BenchError> {
    let mut r = Reader { input: body };
    let head = StatusHead {
        sample_seq: r.u16()?,
        boot_incarnation: r.u64()?,
        page: r.u8()?,
        page_count: r.u8()?,
    };
    Ok((head, r.input))
}

/// STATUS page ids (design §5.3 categories, bounded per page).
pub mod status_page {
    pub const IDENTITY: u8 = 0;
    pub const PARTICIPATION: u8 = 1;
    pub const COUNTERS: u8 = 2;
    pub const RUN0: u8 = 3;
    pub const RUN1: u8 = 4;
    pub const GENERATOR: u8 = 5;
    pub const RESOURCES: u8 = 6;
    pub const COUNT: u8 = 7;
}

/// PEER_SEND_START body: start a bounded device-to-device run.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerSendStartBody {
    /// Must equal the device's boot_incarnation — a replayed command after
    /// a reset mismatches and is refused.
    pub expected_boot: u64,
    pub destination: u64,
    pub sequence_begin: u32,
    /// Planned packets, <= the device bound (64).
    pub count: u16,
    /// Bench body bytes per packet.
    pub payload_len: u8,
    /// Deterministic payload fill.
    pub seed: u32,
    /// Spacing between sends.
    pub interval_ms: u32,
    /// Per-packet delivery lifetime.
    pub ttl_ms: u32,
    /// Clamped to the device bound (1).
    pub max_inflight: u8,
}

pub const PEER_SEND_START_SIZE: usize = 36;

pub fn encode_peer_send_start(body: &PeerSendStartBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(PEER_SEND_START_SIZE);
    out.extend_from_slice(&body.expected_boot.to_be_bytes());
    out.extend_from_slice(&body.destination.to_be_bytes());
    out.extend_from_slice(&body.sequence_begin.to_be_bytes());
    out.extend_from_slice(&body.count.to_be_bytes());
    out.push(body.payload_len);
    out.extend_from_slice(&body.seed.to_be_bytes());
    out.extend_from_slice(&body.interval_ms.to_be_bytes());
    out.extend_from_slice(&body.ttl_ms.to_be_bytes());
    out.push(body.max_inflight);
    out
}

pub fn decode_peer_send_start(body: &[u8]) -> Result<PeerSendStartBody, BenchError> {
    let mut r = Reader { input: body };
    let out = PeerSendStartBody {
        expected_boot: r.u64()?,
        destination: r.u64()?,
        sequence_begin: r.u32()?,
        count: r.u16()?,
        payload_len: r.u8()?,
        seed: r.u32()?,
        interval_ms: r.u32()?,
        ttl_ms: r.u32()?,
        max_inflight: r.u8()?,
    };
    r.finish()?;
    Ok(out)
}

/// PEER_SEND_STATUS body — answer to START/STOP and to an empty-body query.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PeerSendStatusBody {
    /// PeerSendResult below.
    pub result: u8,
    /// GeneratorState below.
    pub state: u8,
    pub planned: u16,
    pub submitted: u16,
    pub admitted: u16,
    pub delivered: u16,
    pub failed: u16,
    pub unknown: u16,
    pub first_ms: u32,
    pub last_ms: u32,
}

pub const PEER_SEND_STATUS_SIZE: usize = 22;

/// `result` field values of [`PeerSendStatusBody`].
pub mod peer_send_result {
    pub const QUERY: u8 = 0;
    pub const STARTED: u8 = 1;
    /// Same (origin, run, seq) seen — the run was not restarted.
    pub const DUPLICATE: u8 = 2;
    /// expected_boot mismatch — the run never restarts across a reset.
    pub const STALE_BOOT: u8 = 3;
    /// Another generator run lives.
    pub const BUSY: u8 = 4;
    pub const INVALID: u8 = 5;
    pub const STOPPED: u8 = 6;
    pub const NOT_RUNNING: u8 = 7;
}

/// `state` field values of [`PeerSendStatusBody`].
pub mod gen_state {
    pub const IDLE: u8 = 0;
    pub const RUNNING: u8 = 1;
    pub const COMPLETE: u8 = 2;
    pub const STOPPED: u8 = 3;
    /// Stopped by the 60 s run bound.
    pub const TIME_BOUND: u8 = 4;
}

pub fn encode_peer_send_status(body: &PeerSendStatusBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(PEER_SEND_STATUS_SIZE);
    out.push(body.result);
    out.push(body.state);
    for word in [
        body.planned,
        body.submitted,
        body.admitted,
        body.delivered,
        body.failed,
        body.unknown,
    ] {
        out.extend_from_slice(&word.to_be_bytes());
    }
    out.extend_from_slice(&body.first_ms.to_be_bytes());
    out.extend_from_slice(&body.last_ms.to_be_bytes());
    out
}

pub fn decode_peer_send_status(body: &[u8]) -> Result<PeerSendStatusBody, BenchError> {
    let mut r = Reader { input: body };
    let out = PeerSendStatusBody {
        result: r.u8()?,
        state: r.u8()?,
        planned: r.u16()?,
        submitted: r.u16()?,
        admitted: r.u16()?,
        delivered: r.u16()?,
        failed: r.u16()?,
        unknown: r.u16()?,
        first_ms: r.u32()?,
        last_ms: r.u32()?,
    };
    r.finish()?;
    Ok(out)
}

/// Shared scalar body for the control commands that carry only the device
/// boot incarnation they were minted against (PEER_SEND_STOP,
/// COUNTER_RESET).
pub fn encode_expected_boot(expected_boot: u64) -> Vec<u8> {
    expected_boot.to_be_bytes().to_vec()
}

pub fn decode_expected_boot(body: &[u8]) -> Result<u64, BenchError> {
    let mut r = Reader { input: body };
    let boot = r.u64()?;
    r.finish()?;
    Ok(boot)
}

/// FAULT_SET body: arm one constrained fault for `duration_ms` (0 clears).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FaultSetBody {
    pub expected_boot: u64,
    pub fault: u8,
    pub duration_ms: u32,
    pub param: u32,
}

pub const FAULT_SET_SIZE: usize = 17;

/// `fault` field values of [`FaultSetBody`].
pub mod fault {
    pub const NONE: u8 = 0;
    /// Consume echoes, never reply.
    pub const ECHO_SUPPRESS: u8 = 1;
    /// Hold replies `param` ms.
    pub const ECHO_DELAY: u8 = 2;
    /// One small COUNT_ONLY to the commander every `param` ms (floored at
    /// 50) until `duration_ms` elapses — a finite send-load injection, not
    /// an open-ended flood.
    pub const SEND_LOAD: u8 = 3;
}

pub fn encode_fault_set(body: &FaultSetBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(FAULT_SET_SIZE);
    out.extend_from_slice(&body.expected_boot.to_be_bytes());
    out.push(body.fault);
    out.extend_from_slice(&body.duration_ms.to_be_bytes());
    out.extend_from_slice(&body.param.to_be_bytes());
    out
}

pub fn decode_fault_set(body: &[u8]) -> Result<FaultSetBody, BenchError> {
    let mut r = Reader { input: body };
    let out = FaultSetBody {
        expected_boot: r.u64()?,
        fault: r.u8()?,
        duration_ms: r.u32()?,
        param: r.u32()?,
    };
    r.finish()?;
    Ok(out)
}

/// RESET_REQUEST body: `expected_boot` binds to this incarnation;
/// `delay_ms` defers execution until after the ACK is on the wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResetRequestBody {
    pub expected_boot: u64,
    pub delay_ms: u32,
}

pub const RESET_REQUEST_SIZE: usize = 12;

pub fn encode_reset_request(body: &ResetRequestBody) -> Vec<u8> {
    let mut out = Vec::with_capacity(RESET_REQUEST_SIZE);
    out.extend_from_slice(&body.expected_boot.to_be_bytes());
    out.extend_from_slice(&body.delay_ms.to_be_bytes());
    out
}

pub fn decode_reset_request(body: &[u8]) -> Result<ResetRequestBody, BenchError> {
    let mut r = Reader { input: body };
    let out = ResetRequestBody {
        expected_boot: r.u64()?,
        delay_ms: r.u32()?,
    };
    r.finish()?;
    Ok(out)
}

/// RESET_ACK body.
pub fn encode_reset_ack(accepted: u8) -> Vec<u8> {
    vec![accepted]
}

pub fn decode_reset_ack(body: &[u8]) -> Result<u8, BenchError> {
    let mut r = Reader { input: body };
    let accepted = r.u8()?;
    r.finish()?;
    Ok(accepted)
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: RunUuid = *b"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff";

    #[test]
    fn envelope_roundtrip() {
        let wire = encode(Opcode::EchoRequest, 0, &RUN, 7, b"ping").expect("encode");
        assert_eq!(wire.len(), HEADER_SIZE + 4);
        assert_eq!(&wire[..4], b"RLB1");
        let msg = decode(&wire).expect("decode");
        assert_eq!(msg.opcode, Opcode::EchoRequest as u8);
        assert_eq!(msg.flags, 0);
        assert_eq!(msg.run, RUN);
        assert_eq!(msg.sequence, 7);
        assert_eq!(msg.body, b"ping");
    }

    #[test]
    fn decode_rejects() {
        let wire = encode(Opcode::EchoRequest, 0, &RUN, 1, b"x").unwrap();
        assert_eq!(decode(&wire[..20]), Err(DecodeError::Truncated));
        let mut bad = wire.clone();
        bad[0] = b'X';
        assert_eq!(decode(&bad), Err(DecodeError::BadMagic));
        let mut bad = wire.clone();
        bad[4] = 9;
        assert_eq!(decode(&bad), Err(DecodeError::UnsupportedVersion(9)));
        let mut bad = wire.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert_eq!(decode(&bad), Err(DecodeError::CrcMismatch));
        // An unknown opcode is a well-formed header — the app decides.
        let unknown = encode(Opcode::Hello, 0, &RUN, 1, b"").unwrap();
        let mut unknown = unknown;
        unknown[5] = 0x7f;
        // Re-stamp the body CRC (unchanged body) is unnecessary — opcode is
        // a header field, not covered by the CRC.
        let msg = decode(&unknown).expect("unknown opcode decodes");
        assert_eq!(msg.opcode, 0x7f);
        assert!(Opcode::from_byte(msg.opcode).is_none());
    }

    #[test]
    fn encode_body_bound() {
        assert!(encode(Opcode::CountOnly, 0, &RUN, 0, &[0; MAX_BODY]).is_ok());
        assert_eq!(
            encode(Opcode::CountOnly, 0, &RUN, 0, &[0; MAX_BODY + 1]),
            Err(BenchError::BodyTooLarge)
        );
    }

    #[test]
    fn body_roundtrips() {
        let caps = CapabilitiesBody {
            app_protocol: PROTOCOL_VERSION,
            app_version: 1,
            max_unicast_body: MAX_BODY as u8,
            max_group_body: MAX_GROUP_BODY as u8,
            max_command_body: MAX_COMMAND_BODY as u8,
            run_slots: 2,
            reply_queue: 4,
            generator_max_inflight: 1,
            boot_incarnation: 0x1122_3344_5566_7788,
            firmware_digest: 0xc0ff_ee01,
            config_digest: 0,
            opcodes: Opcode::ALL.iter().map(|op| *op as u8).collect(),
        };
        assert_eq!(
            decode_capabilities(&encode_capabilities(&caps).unwrap()).unwrap(),
            caps
        );

        let count = CountStatusBody {
            state: 1,
            unique_packets: 9,
            unique_bytes: 99,
            duplicates: 2,
            crc_invalid: 1,
            first_ms: 100,
            last_ms: 900,
            window_base: 10,
            window: 0xABCD,
        };
        assert_eq!(
            decode_count_status(&encode_count_status(&count)).unwrap(),
            count
        );

        let start = PeerSendStartBody {
            expected_boot: 0x0102_0304_0506_0708,
            destination: 0xB,
            sequence_begin: 100,
            count: 64,
            payload_len: 24,
            seed: 0xDEAD_BEEF,
            interval_ms: 250,
            ttl_ms: 30_000,
            max_inflight: 1,
        };
        assert_eq!(
            decode_peer_send_start(&encode_peer_send_start(&start)).unwrap(),
            start
        );

        let status = PeerSendStatusBody {
            result: peer_send_result::STARTED,
            state: gen_state::RUNNING,
            planned: 64,
            submitted: 3,
            admitted: 3,
            delivered: 2,
            failed: 0,
            unknown: 1,
            first_ms: 1000,
            last_ms: 1500,
        };
        assert_eq!(
            decode_peer_send_status(&encode_peer_send_status(&status)).unwrap(),
            status
        );

        let fault = FaultSetBody {
            expected_boot: 0x0102_0304_0506_0708,
            fault: fault::ECHO_DELAY,
            duration_ms: 5_000,
            param: 250,
        };
        assert_eq!(decode_fault_set(&encode_fault_set(&fault)).unwrap(), fault);

        let reset = ResetRequestBody {
            expected_boot: 0x0102_0304_0506_0708,
            delay_ms: 300,
        };
        assert_eq!(
            decode_reset_request(&encode_reset_request(&reset)).unwrap(),
            reset
        );
        assert_eq!(decode_reset_ack(&encode_reset_ack(1)).unwrap(), 1);
        assert_eq!(decode_page_body(&encode_page_body(4)).unwrap(), 4);
        assert_eq!(decode_expected_boot(&encode_expected_boot(9)).unwrap(), 9);
    }

    #[test]
    fn bodies_reject_short_and_trailing() {
        assert_eq!(decode_count_status(&[0; 3]), Err(BenchError::Truncated));
        let mut padded = encode_count_status(&CountStatusBody::default());
        padded.push(0);
        assert_eq!(
            decode_count_status(&padded),
            Err(BenchError::TrailingGarbage)
        );
        assert_eq!(decode_peer_send_start(&[0; 20]), Err(BenchError::Truncated));
        assert_eq!(decode_fault_set(&[0; 5]), Err(BenchError::Truncated));
        assert_eq!(decode_reset_request(&[0; 8]), Err(BenchError::Truncated));
        assert_eq!(decode_page_body(&[]), Err(BenchError::Truncated));
        assert_eq!(decode_page_body(&[1, 2]), Err(BenchError::TrailingGarbage));
        let mut caps_body = encode_capabilities(&CapabilitiesBody {
            app_protocol: 1,
            app_version: 1,
            max_unicast_body: 96,
            max_group_body: 95,
            max_command_body: 64,
            run_slots: 2,
            reply_queue: 4,
            generator_max_inflight: 1,
            boot_incarnation: 0,
            firmware_digest: 0,
            config_digest: 0,
            opcodes: vec![],
        })
        .unwrap();
        // opcode_count beyond the 24-entry budget is refused outright.
        let count_pos = caps_body.len() - 1;
        caps_body[count_pos] = 25;
        assert_eq!(
            decode_capabilities(&caps_body),
            Err(BenchError::Invalid("opcode count over 24"))
        );
    }

    #[test]
    fn reply_opcodes_match_flag() {
        for op in Opcode::ALL {
            // Every reply opcode must be carried with FLAG_RESPONSE so a
            // device never dispatches it as a request.
            let flags = if op.is_reply() { FLAG_RESPONSE } else { 0 };
            let wire = encode(op, flags, &RUN, 0, b"").unwrap();
            let msg = decode(&wire).unwrap();
            assert_eq!(msg.flags & FLAG_RESPONSE != 0, op.is_reply());
        }
    }
}
