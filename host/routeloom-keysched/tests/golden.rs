//! Shared golden vectors for the SDK v1 key schedule (plan P1-4, V1-K01 HKDF
//! part, V1-F03): loads the same protocol/sdkv1-golden/derivations/*.json as
//! the C++ harness (tests/cpp/test_key_schedule.cpp) and asserts every
//! derivation, RLRES1 message and AuthorityEnvelope header byte for byte;
//! every malformed message must be refused with the same reason.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use routeloom_keysched::rlres1::{self, Epochs, TranscriptInput, R1, R2};
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

fn cat(k: &TrafficKey) -> Vec<u8> {
    let mut out = k.key.to_vec();
    out.extend_from_slice(&k.iv);
    out
}

fn list(sub: &str) -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../protocol/sdkv1-golden/derivations")
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
        "routeloom-sdkv1-derivations-golden",
        "{}",
        path.display()
    );
    f
}

fn check_group(f: &Fields) {
    let prk = group_prk(int(f, "network"), &arr(f, "gk_hex"));
    assert_eq!(prk.to_vec(), hex(f, "prk_hex"));
    let g = int32(f, "gk_epoch");
    assert_eq!(
        group_bcast_info(g, int(f, "tx"), int32(f, "tx_boot")),
        hex(f, "bcast_info_hex")
    );
    assert_eq!(
        group_end_info(g, int(f, "group_id"), int(f, "origin"), int32(f, "session")),
        hex(f, "gend_info_hex")
    );
    assert_eq!(group_dsk_info(g), hex(f, "dsk_info_hex"));
    let bcast = group_bcast_key(&prk, g, int(f, "tx"), int32(f, "tx_boot"));
    assert_eq!(bcast.key.to_vec(), hex(f, "bcast_key_hex"));
    assert_eq!(bcast.iv.to_vec(), hex(f, "bcast_iv_hex"));
    let gend = group_end_key(
        &prk,
        g,
        int(f, "group_id"),
        int(f, "origin"),
        int32(f, "session"),
    );
    assert_eq!(gend.key.to_vec(), hex(f, "gend_key_hex"));
    assert_eq!(gend.iv.to_vec(), hex(f, "gend_iv_hex"));
    assert_eq!(group_dsk_key(&prk, g).to_vec(), hex(f, "dsk_hex"));
    assert_ne!(cat(&bcast), cat(&gend));
}

fn check_rlres1(f: &Fields) {
    let purpose = Purpose::from_u8(u8::try_from(int(f, "purpose")).expect("u8")).expect("purpose");
    let (network, node_i, node_r) = (int(f, "network"), int(f, "node_i"), int(f, "node_r"));
    let binding = if f["binding_kind"] == "link" {
        resume_binding_link(
            &arr(f, "mac_i_hex"),
            &arr(f, "mac_r_hex"),
            &arr(f, "carrier_digest_hex"),
        )
    } else {
        resume_binding_routed(purpose, node_i, node_r)
    };
    assert_eq!(binding.to_vec(), hex(f, "binding_hex"));
    assert_eq!(
        resume_auth_info(purpose, network, node_i, node_r),
        hex(f, "auth_info_hex")
    );
    let input = TranscriptInput {
        purpose,
        network,
        node_i,
        node_r,
        rms: arr(f, "rms_hex"),
        binding,
        nonce_i: arr(f, "nonce_i_hex"),
        nonce_r: arr(f, "nonce_r_hex"),
        cid_i: int32(f, "cid_i"),
        cid_r: int32(f, "cid_r"),
        epochs_i: Epochs {
            site_epoch: int32(f, "i_site_epoch"),
            rs_epoch: int32(f, "i_rs_epoch"),
            gk_epoch: int32(f, "i_gk_epoch"),
        },
        epochs_r: Epochs {
            site_epoch: int32(f, "r_site_epoch"),
            rs_epoch: int32(f, "r_rs_epoch"),
            gk_epoch: int32(f, "r_gk_epoch"),
        },
        ticket: hex(f, "ticket_hex"),
    };
    let t = rlres1::transcript(&input);
    assert_eq!(t.rid.to_vec(), hex(f, "rid_hex"));
    assert_eq!(t.k_auth.to_vec(), hex(f, "k_auth_hex"));
    assert_eq!(t.r1, hex(f, "r1_hex"));
    assert_eq!(t.r2, hex(f, "r2_hex"));
    assert_eq!(t.th.to_vec(), hex(f, "th_hex"));
    assert_eq!(t.prk.to_vec(), hex(f, "prk_hex"));
    assert_eq!(t.k_conf.to_vec(), hex(f, "k_conf_hex"));
    assert_eq!(t.r3.to_vec(), hex(f, "r3_hex"));
    let context = ResumeKeyContext {
        purpose,
        network,
        node_i,
        node_r,
        cid_i: input.cid_i,
        cid_r: input.cid_r,
    };
    assert_eq!(
        resume_key_info(&context, Direction::InitiatorToResponder, &t.th),
        hex(f, "key_info_ir_hex")
    );
    assert_eq!(t.initiator_to_responder.key.to_vec(), hex(f, "key_ir_hex"));
    assert_eq!(t.initiator_to_responder.iv.to_vec(), hex(f, "iv_ir_hex"));
    assert_eq!(t.responder_to_initiator.key.to_vec(), hex(f, "key_ri_hex"));
    assert_eq!(t.responder_to_initiator.iv.to_vec(), hex(f, "iv_ri_hex"));
    // V1-K01 (HKDF part): directions never share key or IV.
    assert_ne!(t.initiator_to_responder.key, t.responder_to_initiator.key);
    assert_ne!(t.initiator_to_responder.iv, t.responder_to_initiator.iv);

    // Decoders round-trip the golden messages exactly.
    let r1 = R1::decode(&t.r1).expect("golden R1 decodes");
    assert_eq!(r1.encode(), t.r1);
    assert_eq!(r1.ticket, input.ticket);
    let r2 = R2::decode(&t.r2).expect("golden R2 decodes");
    assert_eq!(r2.encode(), t.r2);
    assert_eq!(rlres1::decode_r3(&t.r3).expect("R3"), t.r3);
}

fn check_hint(f: &Fields) {
    let hint = R2::Hint {
        status: u8::try_from(int(f, "status")).expect("u8"),
        rid: arr(f, "rid_hex"),
    };
    assert_eq!(hint.encode(), hex(f, "encoded_hex"));
    assert_eq!(R2::decode(&hex(f, "encoded_hex")).expect("hint"), hint);
}

fn check_envelope(f: &Fields) {
    let header = AuthorityEnvelopeHeader {
        version: u8::try_from(int(f, "version")).expect("u8"),
        env_type: u8::try_from(int(f, "type")).expect("u8"),
        ctx_id: int32(f, "ctx_id"),
        counter: int(f, "counter"),
    };
    let encoded = header.encode().expect("valid header");
    assert_eq!(encoded.to_vec(), hex(f, "header_hex"));
    let mut whole = encoded.to_vec();
    whole.extend_from_slice(&[0xEE; 21]);
    assert_eq!(AuthorityEnvelopeHeader::decode(&whole), Ok(header));
    assert_eq!(
        aead_nonce(&arr(f, "iv_hex"), header.counter)
            .expect("nonce")
            .to_vec(),
        hex(f, "nonce_hex")
    );
}

#[test]
fn valid_vectors_match_byte_for_byte() {
    let mut rlres1_count = 0;
    let files = list("valid");
    assert!(files.len() >= 15, "expected the full valid set");
    for path in &files {
        let f = load(path);
        match f["codec"].as_str() {
            "group" => check_group(&f),
            "aead_nonce" => assert_eq!(
                aead_nonce(&arr(&f, "iv_hex"), int(&f, "counter"))
                    .expect("nonce")
                    .to_vec(),
                hex(&f, "nonce_hex")
            ),
            "authority_envelope" => check_envelope(&f),
            "rlres1_hint" => check_hint(&f),
            "rlres1" => {
                check_rlres1(&f);
                rlres1_count += 1;
            }
            other => panic!("unknown codec {other} in {}", path.display()),
        }
    }
    assert_eq!(rlres1_count, 4, "link, end, authority, pending-join");
}

#[test]
fn invalid_vectors_are_refused_with_the_same_reason() {
    let files = list("invalid");
    assert!(files.len() >= 28, "expected the full invalid set");
    for path in &files {
        let f = load(path);
        let bytes = hex(&f, "encoded_hex");
        let got = match f["codec"].as_str() {
            "rlres1_r1" => R1::decode(&bytes).err(),
            "rlres1_r2" => R2::decode(&bytes).err(),
            "rlres1_r3" => rlres1::decode_r3(&bytes).err(),
            "authority_envelope" => AuthorityEnvelopeHeader::decode(&bytes).err(),
            other => panic!("unknown codec {other}"),
        };
        let got = got.unwrap_or_else(|| panic!("{} was accepted", path.display()));
        assert_eq!(got.name(), f["reason"], "{}", path.display());
    }
}

#[test]
fn frozen_labels() {
    assert_eq!(LABEL_RESUME_KEY, "RouteLoom/v1/resume-key");
    assert_eq!(LABEL_GROUP_SALT, "RouteLoom/v1/group");
    assert_eq!(
        info(LABEL_RESUME_R3, &[&[1, 2]]),
        b"RouteLoom/v1/R3\x00\x01\x02".to_vec()
    );
    // Purposes separate identifiers and keys for the same RMS.
    let rms = [7_u8; 32];
    assert_ne!(
        resume_id(&rms, Purpose::Link),
        resume_id(&rms, Purpose::End)
    );
    assert_ne!(
        resume_auth_key(&rms, Purpose::Link, 1, 2, 3),
        resume_auth_key(&rms, Purpose::End, 1, 2, 3)
    );
    assert!(AuthorityEnvelopeHeader {
        version: 1,
        env_type: 4,
        ctx_id: 0,
        counter: 0
    }
    .encode()
    .is_none());
}
