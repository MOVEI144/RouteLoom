//! RouteLoom host/device framing primitives.
//! The byte layout is a v0.1 implementation profile, not the frozen mesh wire ABI.

use std::fmt;

pub mod authority;
pub mod bootstrap;
pub mod dev_session;
pub mod group_ops;
pub mod host_ops;
pub mod join_relay;
pub mod node_status;

pub const MAX_DECODED_FRAME: usize = 4096;
pub const MAGIC: [u8; 4] = *b"RLU1";
pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + 1 + 2 + 8 + 8 + 2;
const CRC_LEN: usize = 4;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameKind {
    Hello = 1,
    HelloAck = 2,
    DataToMesh = 16,
    DataFromMesh = 17,
    DeliveryEvent = 18,
    HostOps = 19,
    Credit = 32,
    Diagnostic = 33,
    Error = 34,
    KeepAlive = 35,
}

impl TryFrom<u8> for FrameKind {
    type Error = ProtocolError;

    fn try_from(value: u8) -> Result<Self, ProtocolError> {
        Ok(match value {
            1 => Self::Hello,
            2 => Self::HelloAck,
            16 => Self::DataToMesh,
            17 => Self::DataFromMesh,
            18 => Self::DeliveryEvent,
            19 => Self::HostOps,
            32 => Self::Credit,
            33 => Self::Diagnostic,
            34 => Self::Error,
            35 => Self::KeepAlive,
            _ => return Err(ProtocolError::UnknownKind(value)),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameKind,
    pub flags: u16,
    pub session: u64,
    pub request: u64,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProtocolError {
    FrameTooLarge,
    FrameTooShort,
    InvalidCobs,
    InvalidMagic,
    UnsupportedVersion(u8),
    UnknownKind(u8),
    InvalidLength,
    CrcMismatch,
    CreditSessionMismatch,
    /// Retained for match compatibility: stale cumulative grants are now
    /// absorbed per usb-protocol.md §3, so `update` never returns this.
    CreditRegression,
    CreditExhausted,
    PrincipalTooLong,
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for ProtocolError {}

pub fn crc32_iso_hdlc(input: &[u8]) -> u32 {
    let mut crc = 0xffff_ffff_u32;
    for byte in input {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0_u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

pub fn cobs_encode(input: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(input.len() + input.len() / 254 + 2);
    let mut code_index = 0;
    output.push(0);
    let mut code = 1_u8;
    for &byte in input {
        if byte == 0 {
            output[code_index] = code;
            code_index = output.len();
            output.push(0);
            code = 1;
        } else {
            output.push(byte);
            code = code.wrapping_add(1);
            if code == 0xff {
                output[code_index] = code;
                code_index = output.len();
                output.push(0);
                code = 1;
            }
        }
    }
    output[code_index] = code;
    output
}

pub fn cobs_decode(input: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    // Encoded COBS data never contains a 0x00 byte anywhere (the delimiter is
    // stripped by the caller), so a zero inside the segment is malformed.
    if input.contains(&0) {
        return Err(ProtocolError::InvalidCobs);
    }
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        let code = input[index];
        if code == 0 {
            return Err(ProtocolError::InvalidCobs);
        }
        index += 1;
        let next = index + usize::from(code) - 1;
        if next > input.len() {
            return Err(ProtocolError::InvalidCobs);
        }
        output.extend_from_slice(&input[index..next]);
        index = next;
        if code != 0xff && index < input.len() {
            output.push(0);
        }
    }
    Ok(output)
}

pub fn encode_frame(frame: &Frame) -> Result<Vec<u8>, ProtocolError> {
    if frame.body.len() > u16::MAX as usize
        || HEADER_LEN + frame.body.len() + CRC_LEN > MAX_DECODED_FRAME
    {
        return Err(ProtocolError::FrameTooLarge);
    }
    let mut decoded = Vec::with_capacity(HEADER_LEN + frame.body.len() + CRC_LEN);
    decoded.extend_from_slice(&MAGIC);
    decoded.push(VERSION);
    decoded.push(frame.kind as u8);
    decoded.extend_from_slice(&frame.flags.to_be_bytes());
    decoded.extend_from_slice(&frame.session.to_be_bytes());
    decoded.extend_from_slice(&frame.request.to_be_bytes());
    decoded.extend_from_slice(&(frame.body.len() as u16).to_be_bytes());
    decoded.extend_from_slice(&frame.body);
    let crc = crc32_iso_hdlc(&decoded);
    decoded.extend_from_slice(&crc.to_be_bytes());
    let mut encoded = cobs_encode(&decoded);
    encoded.push(0);
    Ok(encoded)
}

pub fn decode_frame(encoded_without_delimiter: &[u8]) -> Result<Frame, ProtocolError> {
    let decoded = cobs_decode(encoded_without_delimiter)?;
    if decoded.len() < HEADER_LEN + CRC_LEN {
        return Err(ProtocolError::FrameTooShort);
    }
    if decoded.len() > MAX_DECODED_FRAME {
        return Err(ProtocolError::FrameTooLarge);
    }
    if decoded[..4] != MAGIC {
        return Err(ProtocolError::InvalidMagic);
    }
    if decoded[4] != VERSION {
        return Err(ProtocolError::UnsupportedVersion(decoded[4]));
    }
    let kind = FrameKind::try_from(decoded[5])?;
    let flags = u16::from_be_bytes([decoded[6], decoded[7]]);
    let session = u64::from_be_bytes(decoded[8..16].try_into().expect("fixed length"));
    let request = u64::from_be_bytes(decoded[16..24].try_into().expect("fixed length"));
    let body_len = usize::from(u16::from_be_bytes([decoded[24], decoded[25]]));
    if decoded.len() != HEADER_LEN + body_len + CRC_LEN {
        return Err(ProtocolError::InvalidLength);
    }
    let expected = u32::from_be_bytes(
        decoded[decoded.len() - CRC_LEN..]
            .try_into()
            .expect("fixed length"),
    );
    if crc32_iso_hdlc(&decoded[..decoded.len() - CRC_LEN]) != expected {
        return Err(ProtocolError::CrcMismatch);
    }
    Ok(Frame {
        kind,
        flags,
        session,
        request,
        body: decoded[HEADER_LEN..HEADER_LEN + body_len].to_vec(),
    })
}

#[derive(Default)]
pub struct StreamDecoder {
    pending: Vec<u8>,
    discarding: bool,
}

impl StreamDecoder {
    pub fn push(&mut self, input: &[u8]) -> Vec<Result<Frame, ProtocolError>> {
        let mut results = Vec::new();
        for byte in input {
            if *byte == 0 {
                if self.discarding {
                    // Bounded discard ends at the delimiter; resync.
                    self.discarding = false;
                } else if !self.pending.is_empty() {
                    results.push(decode_frame(&self.pending));
                    self.pending.clear();
                }
            } else if self.discarding {
                continue;
            } else if self.pending.len() >= MAX_DECODED_FRAME + 64 {
                self.pending.clear();
                self.discarding = true;
                results.push(Err(ProtocolError::FrameTooLarge));
            } else {
                self.pending.push(*byte);
            }
        }
        results
    }

    pub fn reset(&mut self) {
        self.pending.clear();
        self.discarding = false;
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CumulativeCredit {
    session: u64,
    granted_frames: u64,
    granted_bytes: u64,
    consumed_frames: u64,
    consumed_bytes: u64,
}

impl CumulativeCredit {
    pub fn new(session: u64) -> Self {
        Self {
            session,
            ..Self::default()
        }
    }

    /// Adopt a cumulative grant notice (usb-protocol.md §3): each axis takes
    /// the max, so a stale or partially-stale notice is absorbed without
    /// error and never shrinks the allowance.
    pub fn update(
        &mut self,
        session: u64,
        granted_frames: u64,
        granted_bytes: u64,
    ) -> Result<(), ProtocolError> {
        if session != self.session {
            return Err(ProtocolError::CreditSessionMismatch);
        }
        self.granted_frames = self.granted_frames.max(granted_frames);
        self.granted_bytes = self.granted_bytes.max(granted_bytes);
        Ok(())
    }

    pub fn consume(&mut self, bytes: usize) -> Result<(), ProtocolError> {
        let bytes = u64::try_from(bytes).map_err(|_| ProtocolError::FrameTooLarge)?;
        // Saturating comparisons: raw addition could wrap past u64::MAX and
        // pass the check, so never let consumed exceed grant by wrap-around.
        if self.consumed_frames >= self.granted_frames
            || self.consumed_bytes > self.granted_bytes
            || bytes > self.granted_bytes - self.consumed_bytes
        {
            return Err(ProtocolError::CreditExhausted);
        }
        self.consumed_frames += 1;
        self.consumed_bytes += bytes;
        Ok(())
    }

    pub fn available(&self) -> (u64, u64) {
        (
            self.granted_frames.saturating_sub(self.consumed_frames),
            self.granted_bytes.saturating_sub(self.consumed_bytes),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_known_vector() {
        assert_eq!(crc32_iso_hdlc(b"123456789"), 0xcbf4_3926);
    }

    #[test]
    fn frame_round_trip_and_chunked_decode() {
        let frame = Frame {
            kind: FrameKind::DataToMesh,
            flags: 7,
            session: 11,
            request: 12,
            body: vec![0, 1, 2, 0, 3],
        };
        let encoded = encode_frame(&frame).unwrap();
        let mut decoder = StreamDecoder::default();
        let mut output = Vec::new();
        for chunk in encoded.chunks(2) {
            output.extend(decoder.push(chunk));
        }
        assert_eq!(output, vec![Ok(frame)]);
    }

    #[test]
    fn corruption_is_rejected() {
        let mut encoded = encode_frame(&Frame {
            kind: FrameKind::KeepAlive,
            flags: 0,
            session: 1,
            request: 2,
            body: vec![3],
        })
        .unwrap();
        encoded[5] ^= 1;
        assert!(decode_frame(&encoded[..encoded.len() - 1]).is_err());
    }

    #[test]
    fn cumulative_credit_is_not_additive() {
        let mut credit = CumulativeCredit::new(9);
        credit.update(9, 2, 20).unwrap();
        credit.update(9, 2, 20).unwrap();
        credit.consume(10).unwrap();
        credit.consume(10).unwrap();
        assert_eq!(credit.consume(1), Err(ProtocolError::CreditExhausted));
        assert_eq!(credit.available(), (0, 0));
    }

    #[test]
    fn cumulative_credit_stale_grants_are_absorbed() {
        // usb-protocol.md §3: each grant axis adopts the max — a reordered
        // (stale) or zero notice must not error or shrink the allowance.
        let mut credit = CumulativeCredit::new(9);
        credit.update(9, 16, 65536).unwrap();
        credit.update(9, 4, 1024).unwrap(); // stale: lower on both axes
        credit.update(9, 0, 0).unwrap(); // stale zero grant
        credit.update(9, 20, 4096).unwrap(); // mixed: frames up, bytes stale
        assert_eq!(credit.available(), (20, 65536));
        assert_eq!(
            credit.update(8, 100, 100),
            Err(ProtocolError::CreditSessionMismatch)
        );
    }
}
