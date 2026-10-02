//! HostLink N-1 is a loud refusal at the major-version boundary.
use routeloom_protocol::{
    cobs_decode, cobs_encode, crc32_iso_hdlc, decode_frame, encode_frame, Frame, FrameKind,
    ProtocolError, VERSION,
};

#[test]
fn previous_hostlink_major_is_rejected_with_a_valid_crc() {
    let frame = Frame {
        kind: FrameKind::Hello,
        flags: 0,
        session: 0,
        request: 1,
        body: vec![0; 11],
    };
    let encoded = encode_frame(&frame).unwrap();
    assert_eq!(decode_frame(&encoded[..encoded.len() - 1]).unwrap(), frame);
    let mut previous = cobs_decode(&encoded[..encoded.len() - 1]).unwrap();
    previous[4] = VERSION - 1;
    let payload_len = previous.len() - 4;
    let crc = crc32_iso_hdlc(&previous[..payload_len]);
    previous[payload_len..].copy_from_slice(&crc.to_be_bytes());
    assert_eq!(
        decode_frame(&cobs_encode(&previous)),
        Err(ProtocolError::UnsupportedVersion(VERSION - 1))
    );
}
