//! RLRES1 message codecs and transcript (06-fast-rejoin.md §2.1) — the host
//! mirror of `components/routeloom/src/rlres1.cpp`'s codecs and key schedule.
//! Strict: the same inputs are refused with the same `DecodeError` as C++.

use crate::{
    resume_auth_key, resume_confirm_key, resume_id, resume_mac, resume_prk, resume_traffic_key,
    sha256, DecodeError, Direction, Purpose, ResumeKeyContext, TrafficKey, LABEL_RESUME_R1,
    LABEL_RESUME_R2, LABEL_RESUME_R3,
};

pub const R1_BASE: usize = 60;
pub const TICKET_MAX: usize = 48;
pub const R1_MAX: usize = R1_BASE + 1 + TICKET_MAX;
pub const R2_OK: usize = 52;
pub const R2_HINT: usize = 12;
pub const R3_SIZE: usize = 16;
const R1_TICKET_OFFSET: usize = 44;
const R2_BODY: usize = 36;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Epochs {
    pub site_epoch: u32,
    pub rs_epoch: u32,
    pub gk_epoch: u32,
}

impl Epochs {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.site_epoch.to_be_bytes());
        out.extend_from_slice(&self.rs_epoch.to_be_bytes());
        out.extend_from_slice(&self.gk_epoch.to_be_bytes());
    }
    fn decode(bytes: &[u8]) -> Self {
        let word = |i: usize| u32::from_be_bytes(bytes[i..i + 4].try_into().expect("4 bytes"));
        Self {
            site_epoch: word(0),
            rs_epoch: word(4),
            gk_epoch: word(8),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct R1 {
    pub purpose: Purpose,
    pub rid: [u8; 8],
    pub nonce_i: [u8; 16],
    pub cid_i: u32,
    pub epochs: Epochs,
    /// PendingJoin only (1..=48 bytes); empty otherwise.
    pub ticket: Vec<u8>,
    pub mac: [u8; 16],
}

impl R1 {
    /// Every byte covered by mac_I (all of R1 except the trailing MAC).
    pub fn body(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(R1_MAX);
        out.extend_from_slice(&[self.purpose as u8, 0, 0, 0]);
        out.extend_from_slice(&self.rid);
        out.extend_from_slice(&self.nonce_i);
        out.extend_from_slice(&self.cid_i.to_be_bytes());
        self.epochs.encode(&mut out);
        if self.purpose == Purpose::PendingJoin {
            out.push(self.ticket.len() as u8);
            out.extend_from_slice(&self.ticket);
        }
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = self.body();
        out.extend_from_slice(&self.mac);
        out
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < R1_BASE {
            return Err(DecodeError::Truncated);
        }
        if input.len() > R1_MAX {
            return Err(DecodeError::Oversized);
        }
        let purpose = match Purpose::from_u8(input[0]) {
            Some(p) if p != Purpose::Usb => p,
            _ => return Err(DecodeError::BadPurpose),
        };
        if input[1] != 0 {
            return Err(DecodeError::UnsupportedFlags);
        }
        if input[2] != 0 || input[3] != 0 {
            return Err(DecodeError::ReservedNonZero);
        }
        let mut ticket = Vec::new();
        if purpose == Purpose::PendingJoin {
            if input.len() < R1_BASE + 1 {
                return Err(DecodeError::LengthMismatch);
            }
            let len = usize::from(input[R1_TICKET_OFFSET]);
            if len == 0 || len > TICKET_MAX {
                return Err(DecodeError::TicketLength);
            }
            if input.len() != R1_BASE + 1 + len {
                return Err(DecodeError::LengthMismatch);
            }
            ticket.extend_from_slice(&input[R1_TICKET_OFFSET + 1..R1_TICKET_OFFSET + 1 + len]);
        } else if input.len() != R1_BASE {
            return Err(DecodeError::LengthMismatch);
        }
        let cid_i = u32::from_be_bytes(input[28..32].try_into().expect("4 bytes"));
        if cid_i == 0 {
            return Err(DecodeError::ZeroContextId);
        }
        Ok(Self {
            purpose,
            rid: input[4..12].try_into().expect("8 bytes"),
            nonce_i: input[12..28].try_into().expect("16 bytes"),
            cid_i,
            epochs: Epochs::decode(&input[32..44]),
            ticket,
            mac: input[input.len() - 16..].try_into().expect("16 bytes"),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum R2 {
    /// Authenticated answer (52 bytes).
    Ok {
        nonce_r: [u8; 16],
        cid_r: u32,
        epochs: Epochs,
        mac: [u8; 16],
    },
    /// Unauthenticated hint (12 bytes): status 1 unknown_id, 2 expired, 3 revoked_hint,
    /// echoing the R1 rid.
    Hint { status: u8, rid: [u8; 8] },
}

impl R2 {
    pub fn ok_body(nonce_r: &[u8; 16], cid_r: u32, epochs: &Epochs) -> Vec<u8> {
        let mut out = Vec::with_capacity(R2_OK);
        out.extend_from_slice(&[0, 0, 0, 0]);
        out.extend_from_slice(nonce_r);
        out.extend_from_slice(&cid_r.to_be_bytes());
        epochs.encode(&mut out);
        out
    }

    pub fn encode(&self) -> Vec<u8> {
        match self {
            Self::Ok {
                nonce_r,
                cid_r,
                epochs,
                mac,
            } => {
                let mut out = Self::ok_body(nonce_r, *cid_r, epochs);
                out.extend_from_slice(mac);
                out
            }
            Self::Hint { status, rid } => {
                let mut out = vec![*status, 0, 0, 0];
                out.extend_from_slice(rid);
                out
            }
        }
    }

    pub fn decode(input: &[u8]) -> Result<Self, DecodeError> {
        if input.len() < R2_HINT {
            return Err(DecodeError::Truncated);
        }
        if input.len() > R2_OK {
            return Err(DecodeError::Oversized);
        }
        if input[0] > 3 {
            return Err(DecodeError::BadStatus);
        }
        if input[1] != 0 {
            return Err(DecodeError::UnsupportedFlags);
        }
        if input[2] != 0 || input[3] != 0 {
            return Err(DecodeError::ReservedNonZero);
        }
        if input[0] != 0 {
            if input.len() != R2_HINT {
                return Err(DecodeError::LengthMismatch);
            }
            return Ok(Self::Hint {
                status: input[0],
                rid: input[4..12].try_into().expect("8 bytes"),
            });
        }
        if input.len() != R2_OK {
            return Err(DecodeError::LengthMismatch);
        }
        let cid_r = u32::from_be_bytes(input[20..24].try_into().expect("4 bytes"));
        if cid_r == 0 {
            return Err(DecodeError::ZeroContextId);
        }
        Ok(Self::Ok {
            nonce_r: input[4..20].try_into().expect("16 bytes"),
            cid_r,
            epochs: Epochs::decode(&input[24..36]),
            mac: input[R2_BODY..].try_into().expect("16 bytes"),
        })
    }
}

pub fn decode_r3(input: &[u8]) -> Result<[u8; 16], DecodeError> {
    if input.len() < R3_SIZE {
        return Err(DecodeError::Truncated);
    }
    if input.len() > R3_SIZE {
        return Err(DecodeError::Oversized);
    }
    Ok(input.try_into().expect("16 bytes"))
}

/// Everything both ends agree on before the exchange, plus each side's fresh values.
#[derive(Clone, Debug)]
pub struct TranscriptInput {
    pub purpose: Purpose,
    pub network: u64,
    pub node_i: u64,
    /// Responder NodeId (link/end) or site_id (authority/pending-join).
    pub node_r: u64,
    pub rms: [u8; 32],
    pub binding: [u8; 32],
    pub nonce_i: [u8; 16],
    pub nonce_r: [u8; 16],
    pub cid_i: u32,
    pub cid_r: u32,
    pub epochs_i: Epochs,
    pub epochs_r: Epochs,
    pub ticket: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct Transcript {
    pub rid: [u8; 8],
    pub k_auth: [u8; 32],
    pub r1: Vec<u8>,
    pub r2: Vec<u8>,
    pub th: [u8; 32],
    pub prk: [u8; 32],
    pub k_conf: [u8; 32],
    pub r3: [u8; 16],
    pub initiator_to_responder: TrafficKey,
    pub responder_to_initiator: TrafficKey,
}

/// The honest R1 → R2 → R3 exchange and the derived keys.
pub fn transcript(input: &TranscriptInput) -> Transcript {
    let rid = resume_id(&input.rms, input.purpose);
    let k_auth = resume_auth_key(
        &input.rms,
        input.purpose,
        input.network,
        input.node_i,
        input.node_r,
    );
    let mut r1 = R1 {
        purpose: input.purpose,
        rid,
        nonce_i: input.nonce_i,
        cid_i: input.cid_i,
        epochs: input.epochs_i,
        ticket: input.ticket.clone(),
        mac: [0; 16],
    };
    r1.mac = resume_mac(&k_auth, LABEL_RESUME_R1, &[&input.binding, &r1.body()]);
    let r1 = r1.encode();
    let body2 = R2::ok_body(&input.nonce_r, input.cid_r, &input.epochs_r);
    let mac_r = resume_mac(&k_auth, LABEL_RESUME_R2, &[&input.binding, &r1, &body2]);
    let mut r2 = body2;
    r2.extend_from_slice(&mac_r);
    let th = sha256(&[&r1, &r2]);
    let prk = resume_prk(&input.nonce_i, &input.nonce_r, &input.rms);
    let k_conf = resume_confirm_key(&prk, &th);
    let r3 = resume_mac(&k_conf, LABEL_RESUME_R3, &[&th]);
    let context = ResumeKeyContext {
        purpose: input.purpose,
        network: input.network,
        node_i: input.node_i,
        node_r: input.node_r,
        cid_i: input.cid_i,
        cid_r: input.cid_r,
    };
    Transcript {
        rid,
        k_auth,
        r1,
        r2,
        th,
        prk,
        k_conf,
        r3,
        initiator_to_responder: resume_traffic_key(
            &prk,
            &context,
            Direction::InitiatorToResponder,
            &th,
        ),
        responder_to_initiator: resume_traffic_key(
            &prk,
            &context,
            Direction::ResponderToInitiator,
            &th,
        ),
    }
}
