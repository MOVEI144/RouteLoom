//! AuthorityCarrier kinds and the mesh carrier head (G-SEC P5 design §3.2).
//! Byte-identical to the device side: the kind enum lives in
//! `components/routeloom/include/routeloom/sdkv1_authority.hpp`
//! (`AuthorityCarrierKind`), the 8-byte head is encoded by the PR4 mesh/USB
//! transport. The USB 0x64/0x65 fragments (`host_ops`) reuse the same kind
//! values 1..=5.
//!
//! Head (8 B, mesh FrameType 22 Control subtype 5 payload prefix):
//! `v:u8=1 | sub:u8=5 | kind:u8=1..5 | reserved:u8=0 | exchange_id:u32`.
//! Kinds 1..=3 (R1/R2/R3) need a nonzero exchange id; kinds 4..=5
//! (Envelope/Wake) need zero.

use std::fmt;

pub const CARRIER_VERSION: u8 = 1;
pub const CARRIER_SUBTYPE: u8 = 5;
pub const CARRIER_HEAD: usize = 8;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CarrierKind {
    R1 = 1,
    R2 = 2,
    R3 = 3,
    Envelope = 4,
    Wake = 5,
}

impl CarrierKind {
    pub fn try_from_byte(value: u8) -> Result<Self, CarrierError> {
        Ok(match value {
            1 => Self::R1,
            2 => Self::R2,
            3 => Self::R3,
            4 => Self::Envelope,
            5 => Self::Wake,
            _ => return Err(CarrierError::BadKind),
        })
    }

    /// R1/R2/R3 ride an exchange id; Envelope/Wake are addressed by the
    /// envelope ctx / the Wake body instead.
    pub fn wants_exchange_id(self) -> bool {
        matches!(self, Self::R1 | Self::R2 | Self::R3)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CarrierError {
    Truncated,
    Surplus,
    BadVersion,
    BadSubtype,
    BadKind,
    ReservedNonZero,
    ZeroExchangeId,
    BadExchangeId,
}

impl CarrierError {
    /// Shared vocabulary with the golden `reason` strings.
    pub fn name(self) -> &'static str {
        match self {
            Self::Truncated => "truncated",
            Self::Surplus => "surplus",
            Self::BadVersion => "bad_version",
            Self::BadSubtype => "bad_subtype",
            Self::BadKind => "bad_kind",
            Self::ReservedNonZero => "reserved_nonzero",
            Self::ZeroExchangeId => "zero_exchange_id",
            Self::BadExchangeId => "bad_exchange_id",
        }
    }
}

impl fmt::Display for CarrierError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl std::error::Error for CarrierError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CarrierHead {
    pub kind: CarrierKind,
    pub exchange_id: u32,
}

impl CarrierHead {
    pub fn encode(&self) -> Result<[u8; CARRIER_HEAD], CarrierError> {
        if self.kind.wants_exchange_id() == (self.exchange_id == 0) {
            return Err(if self.exchange_id == 0 {
                CarrierError::ZeroExchangeId
            } else {
                CarrierError::BadExchangeId
            });
        }
        let mut out = [0_u8; CARRIER_HEAD];
        out[0] = CARRIER_VERSION;
        out[1] = CARRIER_SUBTYPE;
        out[2] = self.kind as u8;
        out[4..8].copy_from_slice(&self.exchange_id.to_be_bytes());
        Ok(out)
    }

    pub fn decode(input: &[u8]) -> Result<Self, CarrierError> {
        if input.len() < CARRIER_HEAD {
            return Err(CarrierError::Truncated);
        }
        if input.len() > CARRIER_HEAD {
            return Err(CarrierError::Surplus);
        }
        if input[0] != CARRIER_VERSION {
            return Err(CarrierError::BadVersion);
        }
        if input[1] != CARRIER_SUBTYPE {
            return Err(CarrierError::BadSubtype);
        }
        let kind = CarrierKind::try_from_byte(input[2])?;
        if input[3] != 0 {
            return Err(CarrierError::ReservedNonZero);
        }
        let exchange_id = u32::from_be_bytes(input[4..8].try_into().expect("4 bytes"));
        if kind.wants_exchange_id() && exchange_id == 0 {
            return Err(CarrierError::ZeroExchangeId);
        }
        if !kind.wants_exchange_id() && exchange_id != 0 {
            return Err(CarrierError::BadExchangeId);
        }
        Ok(Self { kind, exchange_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn head_round_trip() {
        let head = CarrierHead {
            kind: CarrierKind::R1,
            exchange_id: 0x11223344,
        };
        let encoded = head.encode().expect("encode");
        assert_eq!(encoded, [1, 5, 1, 0, 0x11, 0x22, 0x33, 0x44]);
        assert_eq!(CarrierHead::decode(&encoded).expect("decode"), head);

        let envelope = CarrierHead {
            kind: CarrierKind::Envelope,
            exchange_id: 0,
        };
        let encoded = envelope.encode().expect("encode");
        assert_eq!(CarrierHead::decode(&encoded).expect("decode"), envelope);
    }

    #[test]
    fn head_refusals() {
        assert_eq!(
            CarrierHead::decode(&[1, 5, 1, 0, 0, 0, 0]).unwrap_err(),
            CarrierError::Truncated
        );
        assert_eq!(
            CarrierHead::decode(&[2, 5, 1, 0, 0, 0, 0, 1]).unwrap_err(),
            CarrierError::BadVersion
        );
        assert_eq!(
            CarrierHead::decode(&[1, 6, 1, 0, 0, 0, 0, 1]).unwrap_err(),
            CarrierError::BadSubtype
        );
        assert_eq!(
            CarrierHead::decode(&[1, 5, 9, 0, 0, 0, 0, 1]).unwrap_err(),
            CarrierError::BadKind
        );
        assert_eq!(
            CarrierHead::decode(&[1, 5, 1, 0, 0, 0, 0, 0]).unwrap_err(),
            CarrierError::ZeroExchangeId
        );
        assert_eq!(
            CarrierHead::decode(&[1, 5, 4, 0, 0, 0, 0, 7]).unwrap_err(),
            CarrierError::BadExchangeId
        );
        assert!(CarrierHead {
            kind: CarrierKind::R2,
            exchange_id: 0
        }
        .encode()
        .is_err());
    }
}
