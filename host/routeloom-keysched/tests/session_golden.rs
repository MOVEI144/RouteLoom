//! Member session handshake golden vectors (G-SEC P4 §5): loads the same
//! protocol/sdkv1-golden/handshake/*.json as the C++ harness
//! (tests/cpp/test_sdkv1_session_wire.cpp) and asserts every EAD value,
//! binding, digest, Exporter context and KDF output byte for byte;
//! malformed values must be refused, and `*_flip_*` vectors must differ
//! from their base.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use routeloom_keysched::session::{
    edhoc_kdf_info_encode, end_carrier_binding, exporter_context_encode, link_carrier_digest,
    session_capability_digest, session_contexts_digest, ContextConfirm, ExporterContextParams,
    LinkCarrier, SessionIntent, SessionState, EXPORTER_CONTEXT_MAX,
};
use routeloom_keysched::{hkdf_expand, resume_binding_link};

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

fn int8(f: &Fields, key: &str) -> u8 {
    u8::try_from(int(f, key)).expect("u8 field")
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

fn dir(sub: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/sdkv1-golden/handshake")
        .join(sub)
}

fn list(sub: &str) -> Vec<PathBuf> {
    let mut files: Vec<PathBuf> = fs::read_dir(dir(sub))
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
        "routeloom-sdkv1-handshake-golden-v1",
        "{}",
        path.display()
    );
    f
}

fn check_intent(f: &Fields) {
    let value = hex(f, "value_hex");
    let intent = SessionIntent::decode(&value).expect("decode intent");
    assert_eq!(intent.purpose, int8(f, "purpose"));
    assert_eq!(intent.profile, int8(f, "profile"));
    assert_eq!(intent.caps_i, int32(f, "caps_i"));
    assert_eq!(intent.boot_i, int32(f, "boot_i"));
    assert_eq!(intent.binding.to_vec(), hex(f, "binding_hex"));
    assert_eq!(intent.encode().expect("encode intent").to_vec(), value);
}

fn check_state(f: &Fields) {
    let value = hex(f, "value_hex");
    let state = SessionState::decode(&value).expect("decode state");
    assert_eq!(state.purpose, int8(f, "purpose"));
    assert_eq!(state.profile, int8(f, "profile"));
    assert_eq!(state.site_epoch, int32(f, "site_epoch"));
    assert_eq!(state.rs_epoch, int32(f, "rs_epoch"));
    assert_eq!(state.gk_epoch, int32(f, "gk_epoch"));
    assert_eq!(state.boot, int32(f, "boot"));
    assert_eq!(state.caps, int32(f, "caps"));
    assert_eq!(state.encode().expect("encode state").to_vec(), value);
}

fn check_confirm(f: &Fields) {
    let value = hex(f, "value_hex");
    let confirm = ContextConfirm::decode(&value).expect("decode confirm");
    assert_eq!(confirm.purpose, int8(f, "purpose"));
    assert_eq!(confirm.profile, int8(f, "profile"));
    assert_eq!(confirm.contexts_digest.to_vec(), hex(f, "digest_hex"));
    assert_eq!(confirm.encode().expect("encode confirm").to_vec(), value);
}

fn check_carrier(f: &Fields, all: &BTreeMap<String, Fields>) {
    let carrier = LinkCarrier {
        network: int(f, "network"),
        node_i: int(f, "node_i"),
        node_r: int(f, "node_r"),
        requester_nonce: arr(f, "nonce_i_hex"),
        responder_nonce: arr(f, "nonce_r_hex"),
        cookie: arr(f, "cookie_hex"),
        capability_i: int32(f, "cap_i"),
        capability_r: int32(f, "cap_r"),
        scope_binding: arr(f, "scope_binding_hex"),
    };
    let digest = link_carrier_digest(&carrier);
    assert_eq!(digest.to_vec(), hex(f, "carrier_digest_hex"));
    let binding = resume_binding_link(&arr(f, "mac_i_hex"), &arr(f, "mac_r_hex"), &digest);
    assert_eq!(binding.to_vec(), hex(f, "binding_link_hex"));
    if let Some(base) = f.get("differs_from").map(|name| &all[name]) {
        let same_digest = digest.to_vec() == hex(base, "carrier_digest_hex");
        let same_binding = binding.to_vec() == hex(base, "binding_link_hex");
        assert!(!same_digest || !same_binding, "flip must move the pair");
    }
}

fn check_end_binding(f: &Fields, all: &BTreeMap<String, Fields>) {
    let binding = end_carrier_binding(
        int(f, "network"),
        int(f, "node_i"),
        int(f, "node_r"),
        int32(f, "exchange_id"),
    );
    assert_eq!(binding.to_vec(), hex(f, "binding_hex"));
    if let Some(base) = f.get("differs_from").map(|name| &all[name]) {
        assert_ne!(binding.to_vec(), hex(base, "binding_hex"));
    }
}

fn check_capability(f: &Fields) {
    let digest = session_capability_digest(
        &hex(f, "intent_hex"),
        &hex(f, "state_r_hex"),
        &hex(f, "state_i_hex"),
    )
    .expect("capability digest");
    assert_eq!(digest.to_vec(), hex(f, "digest_hex"));
}

fn check_exporter_context(f: &Fields, all: &BTreeMap<String, Fields>) {
    let params = ExporterContextParams {
        purpose: int8(f, "purpose"),
        network: int(f, "network"),
        node_i: int(f, "node_i"),
        node_r: int(f, "node_r"),
        kid_i: arr(f, "kid_i_hex"),
        kid_r: arr(f, "kid_r_hex"),
        role_i: int32(f, "role_i"),
        role_r: int32(f, "role_r"),
        generation_i: int32(f, "generation_i"),
        generation_r: int32(f, "generation_r"),
        context_epoch: int32(f, "context_epoch"),
        direction: int8(f, "direction"),
        capability_digest: arr(f, "capability_hex"),
    };
    let context = exporter_context_encode(&params).expect("encode context");
    assert_eq!(context.len() as u64, int(f, "context_len"));
    assert!(context.len() <= EXPORTER_CONTEXT_MAX);
    assert_eq!(context, hex(f, "context_hex"));
    if let Some(base) = f.get("differs_from").map(|name| &all[name]) {
        assert_ne!(context, hex(base, "context_hex"));
    }
}

fn check_contexts_digest(f: &Fields) {
    let digest =
        session_contexts_digest(&hex(f, "dir1_hex"), &hex(f, "dir2_hex"), &hex(f, "rms_hex"))
            .expect("contexts digest");
    assert_eq!(digest.to_vec(), hex(f, "digest_hex"));
}

fn check_exporter_output(f: &Fields) {
    let context = hex(f, "context_hex");
    let length = int(f, "length") as usize;
    let info = edhoc_kdf_info_encode(int32(f, "label"), &context, length as u32);
    assert_eq!(info, hex(f, "info_hex"));
    let prk: [u8; 32] = arr(f, "prk_hex");
    let out = hkdf_expand(&prk, &info, length).expect("expand");
    assert_eq!(out, hex(f, "output_hex"));
}

fn check_invalid(f: &Fields) {
    let encoded = hex(f, "encoded_hex");
    match f["codec"].as_str() {
        "session_intent" => assert!(SessionIntent::decode(&encoded).is_err()),
        "session_state" => assert!(SessionState::decode(&encoded).is_err()),
        "context_confirm" => assert!(ContextConfirm::decode(&encoded).is_err()),
        codec => panic!("unknown invalid codec {codec}"),
    }
}

#[test]
fn handshake_vectors_agree() {
    let mut all = BTreeMap::new();
    for path in list("valid") {
        let f = load(&path);
        all.insert(f["name"].clone(), f);
    }
    for (name, f) in &all {
        assert!(
            f.get("differs_from")
                .is_none_or(|base| all.contains_key(base)),
            "{name} names a missing base"
        );
    }
    for (name, f) in &all {
        match f["codec"].as_str() {
            "session_intent" => check_intent(f),
            "session_state" => check_state(f),
            "context_confirm" => check_confirm(f),
            "carrier_link" => check_carrier(f, &all),
            "end_binding" => check_end_binding(f, &all),
            "capability_digest" => check_capability(f),
            "exporter_context" => check_exporter_context(f, &all),
            "contexts_digest" => check_contexts_digest(f),
            "exporter_output" => check_exporter_output(f),
            codec => panic!("{name}: unknown codec {codec}"),
        }
    }
    let max = int(&all["exporter_max"], "context_len");
    assert!(max <= EXPORTER_CONTEXT_MAX as u64);
    for (name, f) in &all {
        if f["codec"] == "exporter_context" {
            assert!(
                int(f, "context_len") <= max,
                "{name} exceeds the pinned max"
            );
        }
    }
    for path in list("invalid") {
        check_invalid(&load(&path));
    }
}
