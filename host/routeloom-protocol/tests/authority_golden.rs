//! Authority USB/carrier goldens (G-SEC P5 PR1): the
//! `protocol/sdkv1-golden/authority/` fragment, site-state and carrier-head
//! vectors both languages must reproduce byte for byte.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use routeloom_protocol::authority::{CarrierHead, CarrierKind};
use routeloom_protocol::host_ops::*;

type Fields = BTreeMap<String, String>;

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

fn hex(f: &Fields, key: &str) -> Vec<u8> {
    let text = f.get(key).unwrap_or_else(|| panic!("missing {key}"));
    assert!(text.len() % 2 == 0, "odd hex in {key}");
    (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
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

#[test]
fn authority_fragments_match() {
    let mut valid = 0;
    for path in list("valid") {
        let f = load(&path);
        if f["codec"] != "authority_fragment" {
            continue;
        }
        let inner = hex(&f, "inner_hex");
        let fragment = if int(&f, "sub") == 0x64 {
            decode_authority_up(&inner).expect("decode up")
        } else {
            decode_authority_down(&inner).expect("decode down")
        };
        assert_eq!(fragment.device, int(&f, "device"));
        assert_eq!(fragment.transfer_id, int(&f, "transfer_id") as u32);
        assert_eq!(fragment.kind as u8, int(&f, "kind") as u8);
        assert_eq!(fragment.hops, int(&f, "hops") as u8);
        assert_eq!(fragment.total, int(&f, "total") as u16);
        assert_eq!(fragment.offset, int(&f, "offset") as u16);
        assert_eq!(fragment.data.len(), int(&f, "length") as usize);
        let again = if int(&f, "sub") == 0x64 {
            encode_authority_up(&fragment).expect("encode up")
        } else {
            encode_authority_down(&fragment).expect("encode down")
        };
        assert_eq!(again, inner);
        valid += 1;
    }
    assert_eq!(valid, 18);

    let mut invalid = 0;
    for path in list("invalid") {
        let f = load(&path);
        if f["codec"] != "authority_fragment" || f["name"].contains("site_state") {
            continue;
        }
        let inner = hex(&f, "inner_hex");
        let up = decode_authority_up(&inner).unwrap_err();
        let down = decode_authority_down(&inner).unwrap_err();
        // One side fails on the sub byte; the other must report the golden
        // reason. (`fragment_down_hops_nonzero` arrives as 0x65.)
        let reason = f["reason"].clone();
        assert!(
            up.name() == reason || down.name() == reason,
            "{}",
            path.display()
        );
        invalid += 1;
    }
    assert_eq!(invalid, 8);
}

#[test]
fn authority_site_state_matches() {
    let mut sets = 0;
    let mut reports = 0;
    for path in list("valid") {
        let f = load(&path);
        if f["codec"] != "site_state_set" && f["codec"] != "site_state_report" {
            continue;
        }
        let inner = hex(&f, "inner_hex");
        if f["codec"] == "site_state_set" {
            let set = decode_site_state_set(&inner).expect("decode set");
            assert_eq!(set.action as u8, int(&f, "action") as u8);
            assert_eq!(set.site_epoch, int(&f, "site_epoch") as u32);
            assert_eq!(encode_site_state_set(&set), inner);
            sets += 1;
        } else if f["codec"] == "site_state_report" {
            let report = decode_site_state_report(&inner).expect("decode report");
            assert_eq!(report.result as u8, int(&f, "result") as u8);
            assert_eq!(report.local_state_valid, int(&f, "flags") == 1);
            assert_eq!(report.device, int(&f, "device"));
            assert_eq!(report.received_len, int(&f, "received_len") as u16);
            assert_eq!(encode_site_state_report(&report), inner);
            reports += 1;
        }
    }
    assert_eq!(sets, 2);
    assert_eq!(reports, 1);

    let mut invalid = 0;
    for path in list("invalid") {
        let f = load(&path);
        if !f["name"].contains("site_state") {
            continue;
        }
        let inner = hex(&f, "inner_hex");
        if f["name"].contains("site_state_set") {
            assert_eq!(
                decode_site_state_set(&inner).unwrap_err().name(),
                f["reason"],
                "{}",
                path.display()
            );
        } else {
            assert_eq!(
                decode_site_state_report(&inner).unwrap_err().name(),
                f["reason"],
                "{}",
                path.display()
            );
        }
        invalid += 1;
    }
    assert_eq!(invalid, 4);
}

#[test]
fn authority_carrier_heads_match() {
    let mut valid = 0;
    for path in list("valid") {
        let f = load(&path);
        if f["codec"] != "authority_carrier" {
            continue;
        }
        let head = hex(&f, "head_hex");
        let decoded = CarrierHead::decode(&head).expect("decode head");
        assert_eq!(decoded.kind as u8, int(&f, "kind") as u8);
        assert_eq!(decoded.exchange_id, int(&f, "exchange_id") as u32);
        assert_eq!(decoded.encode().expect("encode head").to_vec(), head);
        valid += 1;
    }
    assert_eq!(valid, 3);

    let mut invalid = 0;
    for path in list("invalid") {
        let f = load(&path);
        if f["codec"] != "authority_carrier" {
            continue;
        }
        assert_eq!(
            CarrierHead::decode(&hex(&f, "head_hex"))
                .unwrap_err()
                .name(),
            f["reason"],
            "{}",
            path.display()
        );
        invalid += 1;
    }
    assert_eq!(invalid, 5);
    assert!(CarrierKind::try_from_byte(4).is_ok());
}
