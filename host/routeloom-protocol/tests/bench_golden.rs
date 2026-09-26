//! Shared-vector interop check for the RLB1 bench codec. Replays the same
//! protocol/bench-golden files as tests/cpp/test_bench.cpp: every
//! `expect: "ok"` vector must decode with matching header fields and
//! re-encode byte-identically; negative vectors must fail with the named
//! verdict.

use routeloom_protocol::bench::*;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

fn golden_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("protocol/bench-golden")
}

fn parse_flat_json(text: &str) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    let bytes = text.as_bytes();
    let mut pos = 0;
    while pos < bytes.len() {
        let key_begin = match text[pos..].find('"') {
            Some(offset) => pos + offset,
            None => break,
        };
        let key_end = text[key_begin + 1..]
            .find('"')
            .map(|offset| key_begin + 1 + offset)
            .expect("unterminated key");
        let colon = text[key_end + 1..]
            .find(':')
            .map(|offset| key_end + 1 + offset)
            .expect("missing colon");
        let mut cursor = colon + 1;
        while cursor < bytes.len() && bytes[cursor].is_ascii_whitespace() {
            cursor += 1;
        }
        let (value, next);
        if cursor < bytes.len() && bytes[cursor] == b'"' {
            let value_end = text[cursor + 1..]
                .find('"')
                .map(|offset| cursor + 1 + offset)
                .expect("unterminated value");
            value = text[cursor + 1..value_end].to_string();
            next = value_end + 1;
        } else {
            let mut value_end = cursor;
            while value_end < bytes.len() && bytes[value_end].is_ascii_digit() {
                value_end += 1;
            }
            value = text[cursor..value_end].to_string();
            next = value_end;
        }
        fields.insert(text[key_begin + 1..key_end].to_string(), value);
        pos = next;
    }
    fields
}

fn field<'a>(fields: &'a BTreeMap<String, String>, key: &str) -> &'a str {
    fields.get(key).map(String::as_str).unwrap_or("")
}

fn unhex(text: &str) -> Vec<u8> {
    assert!(text.len() % 2 == 0, "odd hex length");
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let s = std::str::from_utf8(pair).expect("hex utf8");
            u8::from_str_radix(s, 16).expect("hex pair")
        })
        .collect()
}

#[test]
fn bench_golden_vectors_replay() {
    let mut files: Vec<_> = fs::read_dir(golden_dir())
        .expect("bench-golden dir")
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    files.sort();
    assert!(files.len() >= 20, "expected the bench vector set");

    let mut positive = 0usize;
    let mut negative = 0usize;
    for path in files {
        let fields = parse_flat_json(&fs::read_to_string(&path).unwrap());
        let name = field(&fields, "name").to_string();
        let wire = unhex(field(&fields, "wire_hex"));
        match field(&fields, "expect") {
            "ok" => {
                let msg = decode(&wire).unwrap_or_else(|e| panic!("{name}: {e}"));
                let opcode: u8 = field(&fields, "opcode").parse().unwrap();
                let flags: u16 = field(&fields, "flags").parse().unwrap();
                let sequence: u32 = field(&fields, "sequence").parse().unwrap();
                let run = unhex(field(&fields, "run_uuid_hex"));
                let body = unhex(field(&fields, "body_hex"));
                assert_eq!(msg.opcode, opcode, "{name} opcode");
                assert_eq!(msg.flags, flags, "{name} flags");
                assert_eq!(msg.run.as_slice(), run.as_slice(), "{name} run");
                assert_eq!(msg.sequence, sequence, "{name} sequence");
                assert_eq!(msg.body, body.as_slice(), "{name} body");
                if let Some(op) = Opcode::from_byte(opcode) {
                    // Re-encoding through the typed encoder must reproduce
                    // the wire bytes exactly.
                    let rewired = encode(op, flags, &msg.run, sequence, &body)
                        .unwrap_or_else(|e| panic!("{name}: re-encode {e}"));
                    assert_eq!(rewired, wire, "{name} re-encode");
                    if op.is_reply() {
                        assert_ne!(flags & FLAG_RESPONSE, 0, "{name} reply flag");
                    }
                } else {
                    assert_eq!(name, "unknown_opcode");
                }
                positive += 1;
            }
            expected => {
                let err = decode(&wire).expect_err(&format!("{name}: must fail"));
                let verdict = match err {
                    DecodeError::Truncated => "truncated",
                    DecodeError::BadMagic => "bad_magic",
                    DecodeError::UnsupportedVersion(_) => "unsupported_version",
                    DecodeError::CrcMismatch => "crc_mismatch",
                };
                assert_eq!(verdict, expected, "{name} verdict");
                negative += 1;
            }
        }
    }
    assert!(positive >= 20 && negative >= 4);
}

#[test]
fn bench_golden_typed_bodies() {
    // Spot-check the typed body codecs against the same bytes the device
    // decodes — field-level agreement, not just envelope agreement.
    let fields =
        parse_flat_json(&fs::read_to_string(golden_dir().join("13_peer_send_start.json")).unwrap());
    let body = unhex(field(&fields, "body_hex"));
    let start = decode_peer_send_start(&body).unwrap();
    assert_eq!(start.count, 64);
    assert_eq!(start.destination, 0xB);
    assert_eq!(start.payload_len, 24);
    assert_eq!(start.max_inflight, 1);
    assert_eq!(encode_peer_send_start(&start), body);

    let fields =
        parse_flat_json(&fs::read_to_string(golden_dir().join("17_fault_set.json")).unwrap());
    let body = unhex(field(&fields, "body_hex"));
    let fault = decode_fault_set(&body).unwrap();
    assert_eq!(fault.fault, fault::ECHO_DELAY);
    assert_eq!(fault.duration_ms, 5000);
    assert_eq!(fault.param, 250);
    assert_eq!(encode_fault_set(&fault), body);

    let fields =
        parse_flat_json(&fs::read_to_string(golden_dir().join("02_capabilities.json")).unwrap());
    let caps = decode_capabilities(&unhex(field(&fields, "body_hex"))).unwrap();
    assert_eq!(caps.opcodes.len(), 17);
    assert_eq!(
        caps.opcodes,
        Opcode::ALL.iter().map(|op| *op as u8).collect::<Vec<_>>()
    );
}
