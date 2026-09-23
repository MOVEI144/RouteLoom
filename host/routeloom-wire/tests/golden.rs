//! Shared golden-vector harness: loads the same protocol/golden/*.json files
//! as the C++ harness (tests/cpp/test_golden.cpp) and asserts byte-for-byte
//! encode and decode equivalence.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use routeloom_wire::test_security::TestSecurity;
use routeloom_wire::*;

type Fields = BTreeMap<String, String>;

/// Minimal extractor for the flat "key": value objects used by the golden
/// files. Values may be strings or unsigned integers; no nesting or escapes.
fn parse_flat_json(text: &str) -> Fields {
    let bytes = text.as_bytes();
    let mut fields = Fields::new();
    let mut pos = 0;
    while pos < bytes.len() {
        let Some(key_begin) = find(bytes, b'"', pos) else {
            break;
        };
        let Some(key_end) = find(bytes, b'"', key_begin + 1) else {
            break;
        };
        let Some(colon) = find(bytes, b':', key_end + 1) else {
            break;
        };
        let mut cursor = colon + 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let value;
        if cursor < bytes.len() && bytes[cursor] == b'"' {
            let Some(value_end) = find(bytes, b'"', cursor + 1) else {
                break;
            };
            value = text[cursor + 1..value_end].to_string();
            pos = value_end + 1;
        } else {
            let mut value_end = cursor;
            while value_end < bytes.len()
                && (bytes[value_end].is_ascii_digit() || bytes[value_end] == b'-')
            {
                value_end += 1;
            }
            value = text[cursor..value_end].to_string();
            pos = value_end;
        }
        fields.insert(text[key_begin + 1..key_end].to_string(), value);
    }
    fields
}

fn find(bytes: &[u8], byte: u8, from: usize) -> Option<usize> {
    bytes[from..]
        .iter()
        .position(|&b| b == byte)
        .map(|i| from + i)
}

fn u64_field(fields: &Fields, key: &str) -> u64 {
    fields
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
        .parse()
        .unwrap_or_else(|_| panic!("bad integer in field {key}"))
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "odd hex length");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/golden")
}

fn list_json(dir: &Path) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .expect("golden dir missing")
        .filter_map(|entry| {
            let path = entry.expect("dir entry").path();
            (path.extension().and_then(|e| e.to_str()) == Some("json")).then_some(path)
        })
        .collect();
    files.sort();
    files
}

fn header_from_fields(fields: &Fields) -> Header {
    Header {
        frame_type: FrameType::try_from(u64_field(fields, "type") as u8).expect("type"),
        flags: u64_field(fields, "flags") as u8,
        delivery: DeliveryClass::try_from(u64_field(fields, "delivery") as u8).expect("delivery"),
        delivery_round: u64_field(fields, "delivery_round") as u8,
        hop_remaining: u64_field(fields, "hop_remaining") as u8,
        network: u64_field(fields, "network"),
        origin: u64_field(fields, "origin"),
        destination: u64_field(fields, "destination"),
        previous_hop: u64_field(fields, "previous_hop"),
        next_hop: u64_field(fields, "next_hop"),
        message: MessageId {
            session: u64_field(fields, "session") as u32,
            sequence: u64_field(fields, "sequence"),
        },
        remaining_deadline_ms: u64_field(fields, "remaining_deadline_ms") as u32,
        original_lifetime_ms: u64_field(fields, "original_lifetime_ms") as u32,
        link_epoch: u64_field(fields, "link_epoch") as u32,
        end_epoch: u64_field(fields, "end_epoch") as u32,
        ..Header::default()
    }
}

fn check_header(header: &Header, fields: &Fields) {
    assert_eq!(header.frame_type as u8, u64_field(fields, "type") as u8);
    assert_eq!(header.flags, u64_field(fields, "flags") as u8);
    assert_eq!(header.delivery as u8, u64_field(fields, "delivery") as u8);
    assert_eq!(
        header.delivery_round,
        u64_field(fields, "delivery_round") as u8
    );
    assert_eq!(
        header.hop_remaining,
        u64_field(fields, "hop_remaining") as u8
    );
    assert_eq!(header.network, u64_field(fields, "network"));
    assert_eq!(header.origin, u64_field(fields, "origin"));
    assert_eq!(header.destination, u64_field(fields, "destination"));
    assert_eq!(header.previous_hop, u64_field(fields, "previous_hop"));
    assert_eq!(header.next_hop, u64_field(fields, "next_hop"));
    assert_eq!(header.message.session, u64_field(fields, "session") as u32);
    assert_eq!(header.message.sequence, u64_field(fields, "sequence"));
    assert_eq!(
        header.remaining_deadline_ms,
        u64_field(fields, "remaining_deadline_ms") as u32
    );
    assert_eq!(
        header.original_lifetime_ms,
        u64_field(fields, "original_lifetime_ms") as u32
    );
    assert_eq!(header.link_epoch, u64_field(fields, "link_epoch") as u32);
    assert_eq!(header.end_epoch, u64_field(fields, "end_epoch") as u32);
}

#[test]
fn valid_vectors_encode_and_decode_byte_exact() {
    let dir = golden_dir().join("valid");
    let files = list_json(&dir);
    assert!(files.len() >= 6, "expected at least 6 valid vectors");
    for path in files {
        let text = fs::read_to_string(&path).expect("read vector");
        let fields = parse_flat_json(&text);
        let name = fields.get("name").cloned().unwrap_or_default();

        let mut plain = PlainFrame {
            header: header_from_fields(&fields),
            ..PlainFrame::default()
        };
        let payload = hex_decode(fields.get("payload_hex").expect("payload_hex"));
        plain.payload[..payload.len()].copy_from_slice(&payload);
        plain.payload_size = payload.len();
        let expected = hex_decode(fields.get("encoded_hex").expect("encoded_hex"));

        // Encode must reproduce the golden bytes exactly (fresh provider).
        let mut encode_security = TestSecurity::new();
        let mut produced = EncodedFrame::default();
        encode_new(&plain, &mut encode_security, &mut produced)
            .unwrap_or_else(|e| panic!("{name}: encode_new failed: {e}"));
        assert!(produced.size <= MAX_ESPNOW_BODY, "{name}: exceeds body");
        assert_eq!(
            produced.view(),
            expected.as_slice(),
            "{name}: encode bytes differ"
        );

        // Decode at the addressed hop must recover header and payload.
        let mut decode_security = TestSecurity::new();
        let mut opened = LinkOpenedFrame::default();
        let receiver = plain.header.next_hop;
        open_link(&expected, receiver, &mut decode_security, &mut opened)
            .unwrap_or_else(|e| panic!("{name}: open_link failed: {e}"));
        check_header(&opened.header, &fields);

        if plain.header.destination == receiver {
            let mut end_security = TestSecurity::new();
            let mut out = PlainFrame::default();
            open_end(
                &opened,
                plain.header.destination,
                &mut end_security,
                &mut out,
            )
            .unwrap_or_else(|e| panic!("{name}: open_end failed: {e}"));
            assert_eq!(
                &out.payload[..out.payload_size],
                payload.as_slice(),
                "{name}"
            );
        } else {
            let mut end_security = TestSecurity::new();
            let mut out = PlainFrame::default();
            let result = open_end(&opened, receiver, &mut end_security, &mut out);
            assert_eq!(
                result.unwrap_err().code,
                ErrorCode::AuthorizationFailed,
                "{name}: open_end at relay must be denied"
            );
        }

        // Optional second hop: the relay re-wraps the link layer only.
        if let Some(fwd_hex) = fields.get("fwd_encoded_hex") {
            let forwarder = u64_field(&fields, "fwd_local_node");
            let forward_next = u64_field(&fields, "fwd_next_hop");
            let budget = u64_field(&fields, "fwd_remaining_deadline_ms") as u32;
            // The forwarder stamps its OWN link epoch; vectors that predate
            // the field share the origin epoch, so fall back to link_epoch.
            let forward_epoch = if fields.contains_key("fwd_link_epoch") {
                u64_field(&fields, "fwd_link_epoch") as u32
            } else {
                u64_field(&fields, "link_epoch") as u32
            };
            let expected_fwd = hex_decode(fwd_hex);

            let mut forward_security = TestSecurity::new();
            let mut forwarded = EncodedFrame::default();
            forward(
                &opened,
                forwarder,
                forward_next,
                forward_epoch,
                budget,
                &mut forward_security,
                &mut forwarded,
            )
            .unwrap_or_else(|e| panic!("{name}: forward failed: {e}"));
            assert_eq!(
                forwarded.view(),
                expected_fwd.as_slice(),
                "{name}: fwd bytes differ"
            );

            let mut next_security = TestSecurity::new();
            let mut at_next = LinkOpenedFrame::default();
            open_link(
                &expected_fwd,
                forward_next,
                &mut next_security,
                &mut at_next,
            )
            .unwrap_or_else(|e| panic!("{name}: fwd open_link failed: {e}"));
            assert_eq!(at_next.header.previous_hop, forwarder, "{name}");
            assert_eq!(at_next.header.next_hop, forward_next, "{name}");
            assert_eq!(
                at_next.header.hop_remaining + 1,
                plain.header.hop_remaining,
                "{name}"
            );
            // End-immutable fields survive the hop rewrite.
            assert_eq!(at_next.header.origin, plain.header.origin, "{name}");
            assert_eq!(
                at_next.header.destination, plain.header.destination,
                "{name}"
            );
            assert_eq!(at_next.header.message, plain.header.message, "{name}");
            assert_eq!(
                at_next.header.end_counter, plain.header.end_counter,
                "{name}"
            );

            if plain.header.destination == forward_next {
                let mut end_security = TestSecurity::new();
                let mut out = PlainFrame::default();
                open_end(
                    &at_next,
                    plain.header.destination,
                    &mut end_security,
                    &mut out,
                )
                .unwrap_or_else(|e| panic!("{name}: fwd open_end failed: {e}"));
                assert_eq!(
                    &out.payload[..out.payload_size],
                    payload.as_slice(),
                    "{name}"
                );
            }
        }
    }
}

#[test]
fn invalid_vectors_are_rejected() {
    let dir = golden_dir().join("invalid");
    let files = list_json(&dir);
    assert!(files.len() >= 7, "expected at least 7 invalid vectors");
    for path in files {
        let text = fs::read_to_string(&path).expect("read vector");
        let fields = parse_flat_json(&text);
        let name = fields.get("name").cloned().unwrap_or_default();
        let encoded = hex_decode(fields.get("encoded_hex").expect("encoded_hex"));
        let local = u64_field(&fields, "local_node");
        let expect = fields.get("expect").expect("expect").as_str();

        let mut security = TestSecurity::new();
        let mut opened = LinkOpenedFrame::default();
        let status = open_link(&encoded, local, &mut security, &mut opened);
        match expect {
            "link" => assert!(status.is_err(), "{name}: unexpectedly decoded"),
            "end" => {
                status.unwrap_or_else(|e| panic!("{name}: link layer should open: {e}"));
                let end_node = u64_field(&fields, "end_node");
                let mut out = PlainFrame::default();
                assert!(
                    open_end(&opened, end_node, &mut security, &mut out).is_err(),
                    "{name}: end open unexpectedly succeeded"
                );
            }
            other => panic!("{name}: unknown expect={other}"),
        }
    }
}
