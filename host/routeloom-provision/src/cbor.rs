//! Restricted canonical-CBOR helpers — the same definite/minimal-length
//! rules the device applies in `trust_manifest.cpp` and
//! `device_credential.cpp` (those keep file-local copies; host-side they
//! are shared here because both the RTM1 envelope and the RLC1 grant parse
//! need them). Only what the profiles use: fixed-tag/array expect bytes,
//! definite bstr read/write, canonical unsigned read/write.

use crate::{err, Code, Error, Result};

/// Expect one exact byte (a fixed tag/array head in the restricted
/// profile). `what` names the field in the failure detail.
pub fn expect_u8(body: &[u8], pos: &mut usize, value: u8, what: &'static str) -> Result<()> {
    if *pos >= body.len() || body[*pos] != value {
        return err(Code::ProtocolError, what);
    }
    *pos += 1;
    Ok(())
}

/// Read a definite-length bstr with minimal length encoding only:
/// 0x40..=0x57 inline, 0x58 u8 (len > 23), 0x59 u16 (len > 255).
/// Longer forms are never minimal at these sizes and are rejected — the
/// same rule the device helpers apply.
pub fn read_bstr<'a>(body: &'a [u8], pos: &mut usize, what: &'static str) -> Result<&'a [u8]> {
    if *pos >= body.len() {
        return err(Code::ProtocolError, what);
    }
    let ib = body[*pos];
    *pos += 1;
    let len: usize;
    if (0x40..=0x57).contains(&ib) {
        len = usize::from(ib - 0x40);
    } else if ib == 0x58 {
        if *pos >= body.len() {
            return err(Code::ProtocolError, what);
        }
        len = usize::from(body[*pos]);
        *pos += 1;
        if len <= 23 {
            return err(Code::ProtocolError, what);
        }
    } else if ib == 0x59 {
        if *pos + 2 > body.len() {
            return err(Code::ProtocolError, what);
        }
        len = (usize::from(body[*pos]) << 8) | usize::from(body[*pos + 1]);
        *pos += 2;
        if len <= 255 {
            return err(Code::ProtocolError, what);
        }
    } else {
        return err(Code::ProtocolError, what);
    }
    if *pos + len > body.len() {
        return err(Code::ProtocolError, what);
    }
    let out = &body[*pos..*pos + len];
    *pos += len;
    Ok(out)
}

/// Canonical unsigned integer: shortest form only — 0x18 requires >=24,
/// 0x19 >0xFF, 0x1A >0xFFFF, 0x1B >0xFFFFFFFF (the deterministic rule the
/// grant payload profile uses, mirrored from `cbor_read_uint`).
pub fn read_uint(body: &[u8], pos: &mut usize, what: &'static str) -> Result<u64> {
    if *pos >= body.len() {
        return err(Code::ProtocolError, what);
    }
    let ib = body[*pos];
    *pos += 1;
    if ib <= 0x17 {
        return Ok(u64::from(ib));
    }
    let (bytes, minimum): (usize, u64) = match ib {
        0x18 => (1, 24),
        0x19 => (2, 0x100),
        0x1A => (4, 0x1_0000),
        0x1B => (8, 0x1_0000_0000),
        _ => return err(Code::ProtocolError, what),
    };
    if *pos + bytes > body.len() {
        return err(Code::ProtocolError, what);
    }
    let mut value = 0_u64;
    for _ in 0..bytes {
        value = (value << 8) | u64::from(body[*pos]);
        *pos += 1;
    }
    if value < minimum {
        return err(Code::ProtocolError, what);
    }
    Ok(value)
}

/// Write a definite-length bstr with the minimal head form (the exact
/// encoder the device uses in `cbor_write_bstr`).
pub fn write_bstr(out: &mut Vec<u8>, data: &[u8]) {
    if data.len() <= 23 {
        out.push(0x40 + data.len() as u8);
    } else if data.len() <= 255 {
        out.push(0x58);
        out.push(data.len() as u8);
    } else {
        out.push(0x59);
        out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    }
    out.extend_from_slice(data);
}

/// Canonical unsigned integer write (shortest form) — for building grant
/// payloads in fixtures and the manufactured-credential path.
pub fn write_uint(out: &mut Vec<u8>, value: u64) {
    if value <= 0x17 {
        out.push(value as u8);
    } else if value <= 0xFF {
        out.push(0x18);
        out.push(value as u8);
    } else if value <= 0xFFFF {
        out.push(0x19);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFF_FFFF {
        out.push(0x1A);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(0x1B);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::new(std::io::ErrorKind::InvalidData, e.detail)
    }
}
