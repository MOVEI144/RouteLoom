//! CRC-32/ISO-HDLC — byte-for-byte mirror of
//! `components/routeloom/src/crc32.cpp` (`crc32_iso_hdlc`): reflected
//! polynomial 0xEDB88320, init 0xFFFFFFFF, final XOR 0xFFFFFFFF. This is the
//! record-integrity field at the tail of every RLT1/RLC1 slot record —
//! `[0, used_len-4)`, big-endian at `used_len-4`.

pub fn crc32_iso_hdlc(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFF_u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xEDB8_8320 & (0_u32.wrapping_sub(crc & 1)));
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc32_check_value() {
        // CRC-32/ISO-HDLC check value for "123456789" is 0xCBF43926.
        assert_eq!(crc32_iso_hdlc(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32_iso_hdlc(b""), 0);
    }
}
