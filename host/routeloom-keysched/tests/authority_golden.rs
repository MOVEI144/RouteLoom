//! Shared golden vectors for the authority channel (G-SEC P5 PR1):
//! loads the same protocol/sdkv1-golden/authority/*.json as the C++ harness
//! (tests/cpp/test_sdkv1_authority.cpp) and asserts every body, GK-id and
//! sealed envelope byte for byte; every malformed body must be refused with
//! the same reason word.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use routeloom_keysched::authority::*;
use routeloom_keysched::*;

type Fields = BTreeMap<String, String>;

/// Minimal extractor for the flat "key": value golden objects (strings or
/// unsigned integers), same subset as the other golden harnesses.
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
            while value_end < bytes.len() && bytes[value_end].is_ascii_digit() {
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

fn int(f: &Fields, key: &str) -> u64 {
    f.get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
        .parse()
        .unwrap_or_else(|_| panic!("bad integer in {key}"))
}

fn int32(f: &Fields, key: &str) -> u32 {
    u32::try_from(int(f, key)).expect("u32 field")
}

fn hex(f: &Fields, key: &str) -> Vec<u8> {
    let text = f.get(key).unwrap_or_else(|| panic!("missing {key}"));
    assert!(text.len() % 2 == 0, "odd hex in {key}");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn arr<const N: usize>(f: &Fields, key: &str) -> [u8; N] {
    hex(f, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is not {N} bytes"))
}

fn list(sub: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/sdkv1-golden/authority")
        .join(sub);
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .expect("golden dir missing")
        .filter_map(|entry| {
            let path = entry.expect("dir entry").path();
            (path.extension().and_then(|e| e.to_str()) == Some("json")).then_some(path)
        })
        .collect();
    files.sort();
    files
}

fn load(path: &Path) -> Fields {
    let f = parse_flat_json(&fs::read_to_string(path).expect("read vector"));
    assert_eq!(
        f["format"],
        "routeloom-sdkv1-authority-golden-v1",
        "{}",
        path.display()
    );
    f
}

fn check_body(f: &Fields) {
    let plaintext = hex(f, "plaintext_hex");
    let body_type = int(f, "type") as u8;
    let op = int(f, "op") as u8;
    match (body_type, op) {
        (1, 1) => {
            let msg = JoinConfirmUp::decode(&plaintext).expect("decode");
            assert_eq!(msg.head.generation, int32(f, "generation"));
            assert_eq!(msg.head.request_id, int(f, "request_id"));
            assert_eq!(msg.boot, int32(f, "boot"));
            assert_eq!(msg.current, int32(f, "current"));
            assert_eq!(msg.next, int32(f, "next"));
            assert_eq!(msg.encode().expect("encode").to_vec(), plaintext);
        }
        (1, 2) => {
            let msg = JoinConfirmDown::decode(&plaintext).expect("decode");
            assert_eq!(msg.confirmed_generation, int32(f, "confirmed_generation"));
            assert_eq!(msg.authority_active, int32(f, "authority_active"));
            assert_eq!(msg.encode().expect("encode").to_vec(), plaintext);
        }
        (2, 1) => {
            let msg = GroupKeyUpdate::decode(&plaintext).expect("decode");
            assert_eq!(msg.g, int32(f, "g"));
            assert_eq!(msg.cause as u8, int(f, "cause") as u8);
            assert_eq!(msg.overlap_s, int(f, "overlap_s") as u16);
            assert_eq!(msg.encode().expect("encode").to_vec(), plaintext);
        }
        (2, 2) | (3, 2) => {
            let msg = GroupKeyAck::decode(&plaintext).expect("decode");
            assert_eq!(msg.g, int32(f, "g"));
            assert_eq!(msg.result as u8, int(f, "result") as u8);
            assert_eq!(msg.stored_state as u8, int(f, "stored_state") as u8);
            assert_eq!(msg.encode().expect("encode").to_vec(), plaintext);
        }
        (3, 1) => {
            let msg = GroupKeyActivate::decode(&plaintext).expect("decode");
            assert_eq!(msg.g, int32(f, "g"));
            assert_eq!(msg.cause as u8, int(f, "cause") as u8);
            assert_eq!(msg.overlap_s, int(f, "overlap_s") as u16);
            assert_eq!(msg.encode().expect("encode").to_vec(), plaintext);
        }
        (4, 1) => {
            let msg = GroupKeyPull::decode(&plaintext).expect("decode");
            assert_eq!(msg.current, int32(f, "current"));
            assert_eq!(msg.next, int32(f, "next"));
            assert_eq!(msg.reason as u8, int(f, "reason") as u8);
            assert_eq!(msg.encode().expect("encode").to_vec(), plaintext);
        }
        _ => panic!("unknown valid body {body_type}/{op}"),
    }
}

fn check_body_invalid(path: &Path, f: &Fields) {
    let raw = hex(f, "encoded_hex");
    let name = &f["name"];
    let error = if name.contains("pull") {
        GroupKeyPull::decode(&raw).unwrap_err()
    } else if name.contains("ack") {
        GroupKeyAck::decode(&raw).unwrap_err()
    } else {
        GroupKeyUpdate::decode(&raw).unwrap_err()
    };
    assert_eq!(error.name(), f["reason"], "{}", path.display());
}

fn check_envelope(f: &Fields) {
    let key = TrafficKey {
        key: arr(f, "key_hex"),
        iv: arr(f, "iv_hex"),
    };
    let envelope = hex(f, "envelope_hex");
    let plaintext = hex(f, "plaintext_hex");
    let ctx = int32(f, "ctx_id");
    let (header, opened) = open_envelope(&key, &envelope, ctx).expect("open");
    assert_eq!(opened, plaintext);
    assert_eq!(header.counter, int(f, "counter"));
    assert_eq!(header.env_type, int(f, "type") as u8);
    // GCM is deterministic: sealing reproduces the golden bytes exactly.
    let sealed =
        seal_envelope(&key, header.env_type, ctx, header.counter, &plaintext).expect("seal");
    assert_eq!(sealed, envelope);
}

fn check_envelope_invalid(f: &Fields) {
    let key = TrafficKey {
        key: arr(f, "key_hex"),
        iv: arr(f, "iv_hex"),
    };
    let envelope = hex(f, "envelope_hex");
    let error = open_envelope(&key, &envelope, 0x66666666).unwrap_err();
    assert_eq!(error, OpenError::BadTag);
    assert_eq!(error.name(), f["reason"]);
}

#[test]
fn authority_bodies_match() {
    let mut valid = 0;
    let mut invalid = 0;
    for path in list("valid") {
        let f = load(&path);
        if f["codec"] != "authority_body" {
            continue;
        }
        check_body(&f);
        valid += 1;
    }
    for path in list("invalid") {
        let f = load(&path);
        if f["codec"] != "authority_body" {
            continue;
        }
        check_body_invalid(&path, &f);
        invalid += 1;
    }
    assert_eq!(valid, 7);
    assert_eq!(invalid, 15);
}

#[test]
fn authority_gk_id_matches() {
    let mut seen = 0;
    for path in list("valid") {
        let f = load(&path);
        if f["codec"] != "gk_id" {
            continue;
        }
        let id = gk_id(int(&f, "network"), int32(&f, "epoch"), &arr(&f, "gk_hex"));
        assert_eq!(id.to_vec(), hex(&f, "gk_id_hex"));
        seen += 1;
    }
    assert_eq!(seen, 2);
}

#[test]
fn authority_envelopes_match() {
    let mut valid = 0;
    let mut invalid = 0;
    for path in list("valid") {
        let f = load(&path);
        if f["codec"] != "authority_envelope" {
            continue;
        }
        check_envelope(&f);
        valid += 1;
    }
    for path in list("invalid") {
        let f = load(&path);
        if f["codec"] != "authority_envelope" {
            continue;
        }
        check_envelope_invalid(&f);
        invalid += 1;
    }
    assert_eq!(valid, 11);
    assert_eq!(invalid, 2);
}
