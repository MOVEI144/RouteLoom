//! P6-1 (PR A) revocation wire golden vectors: loads the same
//! `protocol/sdkv1-golden/revocation/*.json` files as the C++ harness
//! (`tests/cpp/test_sdkv1_revocation.cpp`) and asserts byte-for-byte
//! encode/decode equivalence for the gossip bodies, the authority type-5
//! bodies and the kind-6 (RevocationSet) object envelope. Kind-6 chunks
//! must reassemble to a manifest-matching RRS1 object that verifies under
//! the vector's SAK key.
//!
//! Regenerate with `python3 tools/gen_sdkv1_revocation_vectors.py`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use routeloom_provision::sdkv1::revocation::{revocation_object_verify, revocation_payload_decode};
use routeloom_wire::autonomy::*;
use routeloom_wire::revocation::*;
use sha2::{Digest, Sha256};

const FMT: &str = "routeloom-sdkv1-revocation-golden-v1";

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

fn u64_field(fields: &Fields, key: &str) -> u64 {
    fields
        .get(key)
        .unwrap_or_else(|| panic!("missing field {key}"))
        .parse()
        .unwrap_or_else(|_| panic!("bad integer in field {key}"))
}

fn u32_field(fields: &Fields, key: &str) -> u32 {
    u32::try_from(u64_field(fields, key)).expect("u32 field")
}

fn hex_decode(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0, "odd hex length");
    (0..hex.len() / 2)
        .map(|i| u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).expect("bad hex"))
        .collect()
}

fn hex_field(fields: &Fields, key: &str) -> Vec<u8> {
    hex_decode(fields.get(key).unwrap_or_else(|| panic!("missing {key}")))
}

fn hash_field(fields: &Fields, key: &str) -> [u8; 32] {
    hex_field(fields, key).try_into().expect("32-byte field")
}

fn sha256_of(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/sdkv1-golden/revocation")
}

fn files_in(sub: &str) -> Vec<(String, Fields)> {
    let mut paths: Vec<PathBuf> = fs::read_dir(golden_dir().join(sub))
        .unwrap_or_else(|e| panic!("read {sub}: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let text = fs::read_to_string(&path).unwrap();
            (name, parse_flat_json(&text))
        })
        .collect()
}

/// The manifest/chunk content is a real SAK-signed RRS1 object: decode it
/// and verify the signature against the vector's key and expectations.
fn check_object(name: &str, object: &[u8], fields: &Fields) {
    let key: [u8; 64] = hex_field(fields, "signer_pubkey_hex")
        .try_into()
        .expect("64-byte pubkey");
    let (set, verified) = revocation_object_verify(
        object,
        &key,
        u64_field(fields, "site_id"),
        u64_field(fields, "network"),
    )
    .unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(verified, "{name}");
    assert_eq!(set.rs_epoch, u32_field(fields, "rs_epoch"), "{name}");
    assert_eq!(
        set.entries.len() as u64,
        u64_field(fields, "count"),
        "{name}"
    );
}

#[test]
fn revocation_valid_vectors_match_byte_for_byte() {
    let valid = files_in("valid");
    assert_eq!(valid.len(), 15);
    let mut manifests: BTreeMap<[u8; 32], Vec<u8>> = BTreeMap::new();
    let mut reassembled: Vec<u8> = Vec::new();
    let mut chunk_hash = None;
    for (name, fields) in &valid {
        assert_eq!(
            fields.get("format").map(String::as_str),
            Some(FMT),
            "{name}"
        );
        assert_eq!(
            fields.get("expect").map(String::as_str),
            Some("ok"),
            "{name}"
        );
        match fields.get("codec").map(String::as_str) {
            Some("rrs_state_epochs") => {
                let epochs = StateEpochs {
                    site_epoch: u32_field(fields, "site_epoch"),
                    applied_rs_epoch: u32_field(fields, "applied_rs_epoch"),
                    gk_epoch: u32_field(fields, "gk_epoch"),
                };
                let want = hex_field(fields, "body_hex");
                assert_eq!(state_epochs_encode(&epochs).to_vec(), want, "{name}");
                assert_eq!(state_epochs_decode(&want).unwrap(), epochs, "{name}");
            }
            Some("rrs_request") => {
                let request = RrsRequest {
                    site_epoch: u32_field(fields, "site_epoch"),
                    have_rs_epoch: u32_field(fields, "have_rs_epoch"),
                };
                let want = hex_field(fields, "body_hex");
                assert_eq!(rrs_request_encode(&request).to_vec(), want, "{name}");
                assert_eq!(rrs_request_decode(&want).unwrap(), request, "{name}");
            }
            Some("rrs_applied") => {
                let applied = RrsApplied {
                    rs_epoch: u32_field(fields, "rs_epoch"),
                    object_sha256: hash_field(fields, "object_sha256_hex"),
                };
                let want = hex_field(fields, "body_hex");
                assert_eq!(rrs_applied_encode(&applied).to_vec(), want, "{name}");
                assert_eq!(rrs_applied_decode(&want).unwrap(), applied, "{name}");
            }
            Some("rrs_get") => {
                let get = RrsGet {
                    wanted_rs_epoch: u32_field(fields, "wanted_rs_epoch"),
                };
                let want = hex_field(fields, "body_hex");
                assert_eq!(rrs_get_encode(&get).to_vec(), want, "{name}");
                assert_eq!(rrs_get_decode(&want).unwrap(), get, "{name}");
            }
            Some("rrs_notice_accepted") => {
                let accepted = RrsNoticeAccepted {
                    rs_epoch: u32_field(fields, "rs_epoch"),
                    notice_sha256: hash_field(fields, "notice_sha256_hex"),
                };
                let want = hex_field(fields, "body_hex");
                assert_eq!(
                    rrs_notice_accepted_encode(&accepted).to_vec(),
                    want,
                    "{name}"
                );
                assert_eq!(
                    rrs_notice_accepted_decode(&want).unwrap(),
                    accepted,
                    "{name}"
                );
            }
            Some("rrs1_object") => {
                let payload = hex_field(fields, "payload_hex");
                let set = revocation_payload_decode(&payload).unwrap();
                assert_eq!(
                    set.entries.len() as u64,
                    u64_field(fields, "count"),
                    "{name}"
                );
                assert_eq!(set.rs_epoch, u32_field(fields, "rs_epoch"), "{name}");
                check_object(name, &hex_field(fields, "object_hex"), fields);
            }
            Some("rrs_kind6_manifest") => {
                let payload = ControlObjectPayload {
                    subtype: ControlObjectSubtype::Manifest,
                    kind: ControlObjectKind::RevocationSet,
                    total_len: u64_field(fields, "total_len") as u16,
                    object_hash: hash_field(fields, "object_sha256_hex"),
                };
                let mut raw = EncodedPayload::default();
                control_object_encode(&payload, &mut raw).unwrap();
                let want = hex_field(fields, "manifest_hex");
                assert_eq!(raw.bytes[..raw.size].to_vec(), want, "{name}");
                let back = control_object_decode(&want).unwrap();
                assert_eq!(back.kind, ControlObjectKind::RevocationSet, "{name}");
                assert_eq!(back.total_len, payload.total_len, "{name}");
                assert_eq!(back.object_hash, payload.object_hash, "{name}");
                let object = hex_field(fields, "object_hex");
                assert_eq!(
                    object.len() as u64,
                    u64_field(fields, "total_len"),
                    "{name}"
                );
                assert_eq!(sha256_of(&object), payload.object_hash, "{name}");
                check_object(name, &object, fields);
                manifests.insert(payload.object_hash, object);
            }
            Some("rrs_kind6_chunk") => {
                let payload = ObjectChunkPayload {
                    subtype: ObjectChunkSubtype::Chunk,
                    object_hash: hash_field(fields, "object_sha256_hex"),
                    offset: u64_field(fields, "offset") as u16,
                    data: hex_field(fields, "data_hex"),
                };
                assert_eq!(
                    payload.data.len() as u64,
                    u64_field(fields, "length"),
                    "{name}"
                );
                let mut raw = EncodedPayload::default();
                object_chunk_encode(&payload, &mut raw).unwrap();
                let want = hex_field(fields, "chunk_hex");
                assert_eq!(raw.bytes[..raw.size].to_vec(), want, "{name}");
                let back = object_chunk_decode(&want).unwrap();
                assert_eq!(back.offset, payload.offset, "{name}");
                assert_eq!(back.data, payload.data, "{name}");
                assert_eq!(back.object_hash, payload.object_hash, "{name}");
                // Offsets tile from zero (files are sorted by name).
                match chunk_hash {
                    None => chunk_hash = Some(payload.object_hash),
                    Some(hash) => assert_eq!(hash, payload.object_hash, "{name}"),
                }
                assert_eq!(payload.offset as usize, reassembled.len(), "{name}");
                reassembled.extend_from_slice(&payload.data);
            }
            other => panic!("{name}: unknown codec {other:?}"),
        }
    }
    let hash = chunk_hash.expect("chunk vectors present");
    assert_eq!(sha256_of(&reassembled), hash);
    assert_eq!(manifests.get(&hash).unwrap(), &reassembled);
}

#[test]
fn revocation_invalid_vectors_are_rejected() {
    let invalid = files_in("invalid");
    assert_eq!(invalid.len(), 33);
    for (name, fields) in &invalid {
        assert_eq!(
            fields.get("expect").map(String::as_str),
            Some("error"),
            "{name}"
        );
        let encoded = hex_field(fields, "encoded_hex");
        match fields.get("codec").map(String::as_str) {
            Some("rrs_state_epochs") => assert!(state_epochs_decode(&encoded).is_err(), "{name}"),
            Some("rrs_request") => assert!(rrs_request_decode(&encoded).is_err(), "{name}"),
            Some("rrs_applied") => assert!(rrs_applied_decode(&encoded).is_err(), "{name}"),
            Some("rrs_get") => assert!(rrs_get_decode(&encoded).is_err(), "{name}"),
            Some("rrs_notice_accepted") => {
                assert!(rrs_notice_accepted_decode(&encoded).is_err(), "{name}");
            }
            Some("rrs_kind6_manifest") => {
                assert!(
                    control_object_decode(&encoded).map_or(true, |manifest| manifest.kind
                        != ControlObjectKind::RevocationSet),
                    "{name}"
                );
            }
            Some("rrs_kind6_chunk") => assert!(object_chunk_decode(&encoded).is_err(), "{name}"),
            other => panic!("{name}: unknown codec {other:?}"),
        }
    }
}
