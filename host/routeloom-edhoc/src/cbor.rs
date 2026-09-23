//! The small deterministic-CBOR subset EDHOC needs (RFC 8949 §4.2.1): major
//! types 0/1 (integers), 2 (bstr), 3 (tstr), 4 (array head), 5 (map head).
//! Decoding is strict — shortest-form heads only, no indefinite lengths —
//! so a non-canonical message (RFC 9529 §4.3.1/§4.3.2) is refused instead
//! of being read as its canonical twin.

use crate::{Error, Result};

pub(crate) fn write_head(out: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    if value < 24 {
        out.push(major | value as u8);
    } else if value <= 0xFF {
        out.push(major | 24);
        out.push(value as u8);
    } else if value <= 0xFFFF {
        out.push(major | 25);
        out.extend_from_slice(&(value as u16).to_be_bytes());
    } else if value <= 0xFFFF_FFFF {
        out.push(major | 26);
        out.extend_from_slice(&(value as u32).to_be_bytes());
    } else {
        out.push(major | 27);
        out.extend_from_slice(&value.to_be_bytes());
    }
}

pub(crate) fn write_int(out: &mut Vec<u8>, value: i64) {
    if value >= 0 {
        write_head(out, 0, value as u64);
    } else {
        write_head(out, 1, (-1 - value) as u64);
    }
}

pub(crate) fn write_bstr(out: &mut Vec<u8>, data: &[u8]) {
    write_head(out, 2, data.len() as u64);
    out.extend_from_slice(data);
}

pub(crate) fn write_tstr(out: &mut Vec<u8>, text: &str) {
    write_head(out, 3, text.len() as u64);
    out.extend_from_slice(text.as_bytes());
}

pub(crate) fn bstr(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 3);
    write_bstr(&mut out, data);
    out
}

/// Strict reader over one CBOR sequence.
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    pub(crate) fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    pub(crate) fn position(&self) -> usize {
        self.pos
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// Major type of the next item without consuming it.
    pub(crate) fn peek_major(&self) -> Option<u8> {
        self.data.get(self.pos).map(|b| b >> 5)
    }

    /// `(major, argument)` of the next head, shortest form enforced.
    fn head(&mut self, what: &'static str) -> Result<(u8, u64)> {
        let Some(&ib) = self.data.get(self.pos) else {
            return Err(Error::Decode(what));
        };
        self.pos += 1;
        let major = ib >> 5;
        let info = ib & 0x1F;
        if info < 24 {
            return Ok((major, u64::from(info)));
        }
        let (width, minimum): (usize, u64) = match info {
            24 => (1, 24),
            25 => (2, 0x100),
            26 => (4, 0x1_0000),
            27 => (8, 0x1_0000_0000),
            // 28..30 reserved, 31 indefinite length: never deterministic.
            _ => return Err(Error::Decode(what)),
        };
        let Some(bytes) = self.data.get(self.pos..self.pos + width) else {
            return Err(Error::Decode(what));
        };
        self.pos += width;
        let value = bytes
            .iter()
            .fold(0_u64, |acc, &b| (acc << 8) | u64::from(b));
        if value < minimum {
            return Err(Error::Decode(what));
        }
        Ok((major, value))
    }

    pub(crate) fn int(&mut self, what: &'static str) -> Result<i64> {
        let (major, value) = self.head(what)?;
        let value = i64::try_from(value).map_err(|_| Error::Decode(what))?;
        match major {
            0 => Ok(value),
            1 => Ok(-1 - value),
            _ => Err(Error::Decode(what)),
        }
    }

    pub(crate) fn bstr(&mut self, what: &'static str) -> Result<&'a [u8]> {
        let (major, len) = self.head(what)?;
        if major != 2 {
            return Err(Error::Decode(what));
        }
        self.take(len, what)
    }

    pub(crate) fn tstr(&mut self, what: &'static str) -> Result<&'a str> {
        let (major, len) = self.head(what)?;
        if major != 3 {
            return Err(Error::Decode(what));
        }
        let bytes = self.take(len, what)?;
        core::str::from_utf8(bytes).map_err(|_| Error::Decode(what))
    }

    pub(crate) fn array(&mut self, what: &'static str) -> Result<u64> {
        let (major, len) = self.head(what)?;
        if major != 4 {
            return Err(Error::Decode(what));
        }
        Ok(len)
    }

    fn take(&mut self, len: u64, what: &'static str) -> Result<&'a [u8]> {
        let len = usize::try_from(len).map_err(|_| Error::Decode(what))?;
        let end = self.pos.checked_add(len).ok_or(Error::Decode(what))?;
        let Some(bytes) = self.data.get(self.pos..end) else {
            return Err(Error::Decode(what));
        };
        self.pos = end;
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heads_round_trip_and_refuse_non_shortest_forms() {
        for value in [0_i64, 23, 24, 255, 256, 65535, 65536, -1, -24, -25, -65537] {
            let mut out = Vec::new();
            write_int(&mut out, value);
            let mut reader = Reader::new(&out);
            assert_eq!(reader.int("int").unwrap(), value);
            assert!(reader.at_end());
        }
        // 0x19 0x00 0x03 is 3 in a 2-byte head (RFC 9529 §4.3.1).
        assert!(Reader::new(&[0x19, 0x00, 0x03]).int("int").is_err());
        assert!(Reader::new(&[0x18, 0x17]).int("int").is_err());
        // Indefinite-length array (RFC 9529 §4.3.2).
        assert!(Reader::new(&[0x9F, 0x06, 0xFF]).array("array").is_err());
        assert!(Reader::new(&[0x42, 0x01]).bstr("bstr").is_err());
    }
}
