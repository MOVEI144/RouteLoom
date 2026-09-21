//! Shared provisioning golden-vector harness: loads the same
//! `protocol/provisioning-golden/*.json` files the C++ suite
//! (`tests/cpp/test_provisioning_golden.cpp`) reads and asserts
//! byte-for-byte codec equivalence plus the §4.5.1 acceptance verdicts.
//!
//! Regenerate the vectors with:
//! `cargo run -p routeloom-provision --example gen_provisioning_golden`

use std::fs;
use std::path::{Path, PathBuf};

use routeloom_json::Json;
use routeloom_provision::credential::{
    credential_cose_key_encode, credential_kid, credential_record_decode, credential_record_encode,
    KeyLocation, CRED_SEAL_COMMITTED,
};
use routeloom_provision::image::{
    image_body_encode, image_decode, image_encode, image_fingerprint, TrustImage,
    TRUST_SEAL_COMMITTED,
};
use routeloom_provision::manifest::{manifest_aad, manifest_parse, manifest_sig_structure};
use routeloom_provision::signer::pubkey_from_secret;
use routeloom_provision::verify::{verify_manifest, Verdict};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/provisioning-golden")
}

fn load(name: &str) -> Json {
    let path = golden_dir().join(name);
    let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {}: {e}", path.display()));
    routeloom_json::parse(&text).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

fn hex_field(doc: &Json, key: &str) -> Vec<u8> {
    let text = doc
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{key} missing"));
    let bytes = (0..text.len() / 2)
        .map(|i| u8::from_str_radix(&text[2 * i..2 * i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    assert_eq!(text.len(), bytes.len() * 2, "{key} odd hex");
    bytes
}

fn u64_field(doc: &Json, key: &str) -> u64 {
    doc.get(key)
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!("{key} missing"))
}

fn id_field(doc: &Json, key: &str) -> u64 {
    let text = doc
        .get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{key} missing"));
    u64::from_str_radix(text, 16).unwrap()
}

fn expect_format(doc: &Json, kind: &str) {
    assert_eq!(
        doc.get("format").and_then(|v| v.as_str()),
        Some("routeloom-provisioning-golden-v1")
    );
    assert_eq!(doc.get("kind").and_then(|v| v.as_str()), Some(kind));
}

/// spec ↔ decoded-image agreement for one golden trust-image document.
fn check_image_doc(doc: &Json) -> TrustImage {
    expect_format(doc, "trust-image");
    let record = hex_field(doc, "record_hex");
    let image = image_decode(&record).unwrap_or_else(|e| panic!("decode: {e}"));
    // Byte-exact round trip of the committed record.
    assert_eq!(
        image_encode(&image, TRUST_SEAL_COMMITTED).unwrap(),
        record,
        "{}: re-encode drift",
        doc.get("name").and_then(|v| v.as_str()).unwrap_or("?")
    );
    // The RTM1 signed content is byte-for-byte RLT1 [16, used-4).
    assert_eq!(
        image_body_encode(&image).unwrap(),
        hex_field(doc, "content_hex")
    );
    assert_eq!(
        &image_fingerprint(&record).unwrap()[..],
        &hex_field(doc, "fingerprint_hex")[..]
    );
    // Spec fields agree with the decoded image.
    assert_eq!(image.store_epoch as u64, u64_field(doc, "store_epoch"));
    assert_eq!(
        image.min_authority_generation as u64,
        u64_field(doc, "min_authority_generation")
    );
    assert_eq!(image.network, id_field(doc, "network"));
    assert_eq!(image.deployment_id, id_field(doc, "deployment_id"));
    assert_eq!(image.flags as u64, u64_field(doc, "flags"));
    let anchors = doc.get("anchors").and_then(|v| v.as_array()).unwrap();
    assert_eq!(image.anchors.len(), anchors.len());
    for (decoded, spec) in image.anchors.iter().zip(anchors) {
        assert_eq!(decoded.root_id, id_field(spec, "root_id"));
        assert_eq!(&decoded.pubkey[..], &hex_field(spec, "pubkey_hex")[..]);
    }
    let keys = doc.get("keys").and_then(|v| v.as_array()).unwrap();
    assert_eq!(image.keys.len(), keys.len());
    for (decoded, spec) in image.keys.iter().zip(keys) {
        assert_eq!(decoded.authority_id, id_field(spec, "authority_id"));
        assert_eq!(decoded.generation as u64, u64_field(spec, "generation"));
        assert_eq!(&decoded.pubkey[..], &hex_field(spec, "pubkey_hex")[..]);
    }
    let revocations = doc.get("revocations").and_then(|v| v.as_array()).unwrap();
    assert_eq!(image.revocations.len(), revocations.len());
    for (decoded, spec) in image.revocations.iter().zip(revocations) {
        assert_eq!(decoded.node_id, id_field(spec, "node_id"));
        assert_eq!(
            &decoded.kid_fingerprint[..],
            &hex_field(spec, "kid_hex")[..]
        );
    }
    image
}

/// One manifest-verify vector: `current_record_hex` is the committed
/// image, `object_hex` the RTM1 object, `expect` the device-equivalent
/// verdict ("accept" or a Code name).
fn check_verify_doc(doc: &Json) {
    expect_format(doc, "manifest-verify");
    let name = doc.get("name").and_then(|v| v.as_str()).unwrap_or("?");
    let current = image_decode(&hex_field(doc, "current_record_hex"))
        .unwrap_or_else(|e| panic!("{name}: current: {e}"));
    let object = hex_field(doc, "object_hex");
    let expect = doc.get("expect").and_then(|v| v.as_str()).unwrap();
    let report = verify_manifest(&current, &object);
    match (&report.verdict, expect) {
        (Verdict::Accept(image), "accept") => {
            assert!(image.store_epoch > current.store_epoch, "{name}");
        }
        (Verdict::Refuse(error), expected) => {
            assert_ne!(expected, "accept", "{name}: refused but expected accept");
            assert_eq!(
                format!("{:?}", error.code),
                expected,
                "{name}: wrong refusal code"
            );
            assert_eq!(
                error.detail,
                doc.get("expect_detail").and_then(|v| v.as_str()).unwrap(),
                "{name}: wrong refusal detail"
            );
        }
        (Verdict::Accept(_), expected) => {
            panic!("{name}: accepted but expected {expected}")
        }
    }
}

#[test]
fn keys_recompute() {
    let doc = load("keys.json");
    expect_format(&doc, "keys");
    for section in ["root_a", "root_b", "authority", "device"] {
        let entry = doc.get(section).unwrap();
        let secret: [u8; 32] = hex_field(entry, "secret_hex").try_into().unwrap();
        let pubkey: [u8; 64] = hex_field(entry, "pubkey_hex").try_into().unwrap();
        assert_eq!(
            pubkey_from_secret(&secret).unwrap(),
            pubkey,
            "{section}: pubkey does not recompute from secret"
        );
    }
    // The credential kid is SHA-256 over the canonical COSE_Key.
    let device = doc.get("device").unwrap();
    let pubkey: [u8; 64] = hex_field(device, "pubkey_hex").try_into().unwrap();
    assert_eq!(
        &credential_kid(&pubkey)[..],
        &hex_field(device, "kid_hex")[..]
    );
}

#[test]
fn trust_images_byte_exact() {
    for name in ["image-epoch1.json", "image-epoch2.json"] {
        check_image_doc(&load(name));
    }
}

#[test]
fn manifest_epoch2_accepts_and_parses() {
    let doc = load("manifest-epoch2.json");
    check_verify_doc(&doc);
    // Structural agreement: the parsed manifest's Sig_structure with the
    // committed-network AAD is what the device hashes.
    let object = hex_field(&doc, "object_hex");
    let parts = manifest_parse(&object).unwrap();
    let aad = manifest_aad(7);
    let sig = manifest_sig_structure(parts.protected_bytes, &aad, parts.payload).unwrap();
    assert_eq!(sig[0], 0x84);
    assert_eq!(&sig[2..12], b"Signature1");
}

#[test]
fn invalid_verdicts_match() {
    for entry in fs::read_dir(golden_dir().join("invalid")).unwrap() {
        let path = entry.unwrap().path();
        let text = fs::read_to_string(&path).unwrap();
        let doc = routeloom_json::parse(&text).unwrap();
        check_verify_doc(&doc);
    }
}

#[test]
fn credential_byte_exact() {
    let doc = load("credential.json");
    expect_format(&doc, "credential");
    let record = hex_field(&doc, "record_hex");
    let credential = credential_record_decode(&record).unwrap();
    assert_eq!(&record[..4], b"RLC1");
    assert_eq!(credential.network, id_field(&doc, "network"));
    assert_eq!(credential.node_id, id_field(&doc, "node_id"));
    assert_eq!(credential.key_location, KeyLocation::NvsPlaintext);
    assert_eq!(&credential.kid[..], &hex_field(&doc, "kid_hex")[..]);
    assert_eq!(&credential.pubkey[..], &hex_field(&doc, "pubkey_hex")[..]);
    assert_eq!(&credential.grant[..], &hex_field(&doc, "grant_hex")[..]);
    assert_eq!(
        &credential_cose_key_encode(&credential.pubkey)[..],
        &hex_field(&doc, "cose_key_hex")[..]
    );
    // Byte-exact re-encode of the committed record.
    assert_eq!(
        credential_record_encode(&credential, CRED_SEAL_COMMITTED).unwrap(),
        record
    );
    // kid recomputes from the public half only.
    assert_eq!(credential.kid, credential_kid(&credential.pubkey));
}

#[test]
fn nvs_set_matches_twin_policy() {
    let doc = load("nvs-set.json");
    expect_format(&doc, "nvs-set");
    let entries = doc.get("entries").and_then(|v| v.as_array()).unwrap();
    // rltrust t0/t1, rlcred d0/d1, rlboot session.
    assert_eq!(entries.len(), 5);
    let image_record = hex_field(&load("image-epoch1.json"), "record_hex");
    let cred_record = hex_field(&load("credential.json"), "record_hex");
    for (i, key) in ["t0", "t1"].iter().enumerate() {
        assert_eq!(
            entries[i].get("namespace").unwrap().as_str(),
            Some("rltrust")
        );
        assert_eq!(entries[i].get("key").unwrap().as_str(), Some(*key));
        assert_eq!(entries[i].get("slot_bytes").unwrap().as_u64(), Some(2048));
        assert_eq!(hex_field(&entries[i], "data_hex"), image_record);
    }
    for (i, key) in ["d0", "d1"].iter().enumerate() {
        let entry = &entries[2 + i];
        assert_eq!(entry.get("namespace").unwrap().as_str(), Some("rlcred"));
        assert_eq!(entry.get("key").unwrap().as_str(), Some(*key));
        assert_eq!(entry.get("slot_bytes").unwrap().as_u64(), Some(1024));
        assert_eq!(hex_field(entry, "data_hex"), cred_record);
    }
    assert_eq!(
        entries[4].get("namespace").unwrap().as_str(),
        Some("rlboot")
    );
    assert_eq!(entries[4].get("type").unwrap().as_str(), Some("u32"));
    assert_eq!(entries[4].get("value").unwrap().as_u64(), Some(0));
}
