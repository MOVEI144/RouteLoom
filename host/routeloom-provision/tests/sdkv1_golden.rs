//! SDK v1 shared golden vectors: loads `protocol/sdkv1-golden/` — the same
//! files the C++ harness (`tests/cpp/test_sdkv1_golden.cpp`) reads — and
//! asserts byte-for-byte agreement of the RLCW1 / RLI1 / RLS1 / RRS1 / RLP1
//! codecs. Unlike the C++ side (verify-only), this harness also RE-SIGNS
//! every certificate and revocation set with RustCrypto `p256` (RFC 6979,
//! low-S) and requires the generator's signatures exactly.
//!
//! Regenerate with `python3 tools/gen_sdkv1_vectors.py`.

use std::fs;
use std::path::{Path, PathBuf};

use routeloom_json::Json;
use routeloom_provision::credential::KeyLocation;
use routeloom_provision::sdkv1::cert::{
    cert_assemble, cert_decode, cert_issue, cert_payload_encode, cert_sig_structure, cert_verify,
    CertType, CERT_LARGEST,
};
use routeloom_provision::sdkv1::identity::{
    identity_record_decode, identity_record_encode, AnchorKind, AnchorStatus,
    IDENTITY_SEAL_COMMITTED,
};
use routeloom_provision::sdkv1::local_revocation::{
    local_revocation_record_decode, local_revocation_record_encode, LOCAL_REVOCATION_SEAL_COMMITTED,
};
use routeloom_provision::sdkv1::resume::{
    resume_peer_cert_id, resume_slot_decode, resume_slot_encode, ResumePurpose,
};
use routeloom_provision::sdkv1::resume2::{resume2_slot_decode, resume2_slot_encode};
use routeloom_provision::sdkv1::revocation::{
    revocation_aad, revocation_issue, revocation_object_assemble, revocation_object_decode,
    revocation_object_verify, revocation_payload_decode, revocation_payload_encode,
    revocation_record_decode, revocation_record_encode, revocation_sig_structure,
    REVOCATION_SEAL_COMMITTED,
};
use routeloom_provision::sdkv1::site::{
    site_record_decode, site_record_encode, SiteState, SITE_SEAL_COMMITTED,
};
use routeloom_provision::signer::{pubkey_from_secret, FileRootSigner, RootSigner};

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/sdkv1-golden")
}

fn files(sub: &str) -> Vec<(String, Json)> {
    let mut paths: Vec<PathBuf> = fs::read_dir(golden_dir().join(sub))
        .unwrap_or_else(|e| panic!("read {sub}: {e}"))
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let text = fs::read_to_string(&path).unwrap();
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            let doc = routeloom_json::parse(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
            (name, doc)
        })
        .collect()
}

fn text<'a>(doc: &'a Json, key: &str) -> &'a str {
    doc.get(key)
        .and_then(|v| v.as_str())
        .unwrap_or_else(|| panic!("{key} missing"))
}

fn num(doc: &Json, key: &str) -> u64 {
    doc.get(key)
        .and_then(|v| v.as_u64())
        .unwrap_or_else(|| panic!("{key} missing"))
}

fn hex(doc: &Json, key: &str) -> Vec<u8> {
    let s = text(doc, key);
    assert_eq!(s.len() % 2, 0, "{key} odd hex");
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

fn arr<const N: usize>(doc: &Json, key: &str) -> [u8; N] {
    hex(doc, key)
        .try_into()
        .unwrap_or_else(|_| panic!("{key} is not {N} bytes"))
}

fn check_cert(name: &str, doc: &Json) {
    let cert = hex(doc, "cert_hex");
    let claims = cert_decode(&cert).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(claims.cert_type as u64, num(doc, "cert_type"), "{name}");
    assert_eq!(claims.issuer, num(doc, "issuer"), "{name}");
    assert_eq!(claims.subject, num(doc, "subject"), "{name}");
    assert_eq!(claims.pubkey, arr::<64>(doc, "pubkey_hex"), "{name}");
    assert_eq!(u64::from(claims.model), num(doc, "model"), "{name}");
    assert_eq!(u64::from(claims.hw_rev), num(doc, "hw_rev"), "{name}");
    assert_eq!(
        u64::from(claims.network_low32),
        num(doc, "network_low32"),
        "{name}"
    );
    assert_eq!(u64::from(claims.usage), num(doc, "usage"), "{name}");
    assert_eq!(claims.network, num(doc, "network"), "{name}");
    assert_eq!(u64::from(claims.role), num(doc, "role"), "{name}");
    assert_eq!(
        u64::from(claims.assignment_generation),
        num(doc, "assignment_generation"),
        "{name}"
    );
    assert_eq!(
        u64::from(claims.site_epoch),
        num(doc, "site_epoch"),
        "{name}"
    );
    assert_eq!(u64::from(claims.serial), num(doc, "serial"), "{name}");

    let payload = cert_payload_encode(&claims).unwrap();
    assert_eq!(payload, hex(doc, "payload_hex"), "{name}: payload");
    let structure = cert_sig_structure(&payload);
    assert_eq!(
        structure,
        hex(doc, "sig_structure_hex"),
        "{name}: Sig_structure"
    );
    let signature = arr::<64>(doc, "signature_hex");
    assert_eq!(cert_assemble(&payload, &signature).unwrap(), cert, "{name}");
    assert!(cert.len() <= CERT_LARGEST, "{name}");

    let secret = arr::<32>(doc, "signer_secret_hex");
    let signer_pub = arr::<64>(doc, "signer_pubkey_hex");
    assert_eq!(pubkey_from_secret(&secret), Some(signer_pub), "{name}");
    let (_, verified) = cert_verify(&cert, &signer_pub).unwrap();
    assert!(verified, "{name}: verify");
    // RFC 6979 re-sign: RustCrypto must reproduce the generator exactly.
    let signer = FileRootSigner::from_secret(claims.issuer, &secret).unwrap();
    assert_eq!(
        signer.sign(&structure).unwrap(),
        signature,
        "{name}: re-sign"
    );
    assert_eq!(cert_issue(&claims, &signer).unwrap(), cert, "{name}: issue");
    assert_eq!(
        routeloom_provision::credential::credential_kid(&claims.pubkey),
        arr::<32>(doc, "subject_kid_hex"),
        "{name}: kid"
    );
}

fn check_rli1(name: &str, doc: &Json) {
    let record = hex(doc, "record_hex");
    let r = identity_record_decode(&record).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(r.node_id, num(doc, "node_id"));
    let location = match num(doc, "key_location") {
        0 => KeyLocation::None,
        1 => KeyLocation::NvsPlaintext,
        2 => KeyLocation::EfuseDsBound,
        _ => KeyLocation::SecureElement,
    };
    assert_eq!(r.key_location, location);
    assert_eq!(u64::from(r.flags), num(doc, "flags"));
    assert_eq!(r.kid, arr::<32>(doc, "kid_hex"));
    assert_eq!(r.pubkey, arr::<64>(doc, "pubkey_hex"));
    assert_eq!(r.key_material, arr::<32>(doc, "key_material_hex"));
    assert_eq!(r.anchors.len() as u64, num(doc, "anchor_count"));
    for (i, anchor) in r.anchors.iter().enumerate() {
        assert_eq!(anchor.anchor_id, num(doc, &format!("anchor{i}_id")));
        let kind = if num(doc, &format!("anchor{i}_kind")) == 1 {
            AnchorKind::SiteCa
        } else {
            AnchorKind::AssignmentVerifier
        };
        assert_eq!(anchor.kind, kind);
        let status = if num(doc, &format!("anchor{i}_status")) == 1 {
            AnchorStatus::Active
        } else {
            AnchorStatus::Disabled
        };
        assert_eq!(anchor.status, status);
        assert_eq!(
            anchor.pubkey,
            arr::<64>(doc, &format!("anchor{i}_pubkey_hex"))
        );
    }
    assert_eq!(r.devcert, hex(doc, "devcert_hex"));
    assert_eq!(
        identity_record_encode(&r, IDENTITY_SEAL_COMMITTED).unwrap(),
        record,
        "{name}: re-encode"
    );
}

fn check_rls1(name: &str, doc: &Json) {
    let record = hex(doc, "record_hex");
    let (r, seq) = site_record_decode(&record).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(u64::from(seq), num(doc, "commit_seq"));
    let state = if num(doc, "state") == 1 {
        SiteState::Member
    } else {
        SiteState::Cleared
    };
    assert_eq!(r.state, state);
    assert_eq!(r.site_id, num(doc, "site_id"));
    assert_eq!(r.network, num(doc, "network"));
    assert_eq!(
        u64::from(r.assignment_generation),
        num(doc, "assignment_generation")
    );
    assert_eq!(u64::from(r.rs_epoch_floor), num(doc, "rs_epoch_floor"));
    assert_eq!(u64::from(r.gk_epoch_current), num(doc, "gk_epoch_current"));
    assert_eq!(u64::from(r.gk_epoch_next), num(doc, "gk_epoch_next"));
    assert_eq!(r.gk_current, arr::<32>(doc, "gk_current_hex"));
    assert_eq!(r.gk_next, arr::<32>(doc, "gk_next_hex"));
    assert_eq!(r.dams, arr::<32>(doc, "dams_hex"));
    assert_eq!(u64::from(r.role), num(doc, "role"));
    assert_eq!(u64::from(r.gateway_count), num(doc, "gateway_count"));
    assert_eq!(u64::from(r.channel), num(doc, "channel"));
    assert_eq!(u64::from(r.channel_epoch), num(doc, "channel_epoch"));
    assert_eq!(u64::from(r.boot_witness), num(doc, "boot_witness"));
    for (i, gateway) in r.gateways.iter().enumerate() {
        assert_eq!(*gateway, num(doc, &format!("gateway{i}")));
    }
    assert_eq!(r.site_cert, hex(doc, "site_cert_hex"));
    assert_eq!(r.member_cert, hex(doc, "member_cert_hex"));
    assert_eq!(
        site_record_encode(&r, SITE_SEAL_COMMITTED, seq).unwrap(),
        record,
        "{name}: re-encode"
    );
}

fn check_rrs1(name: &str, doc: &Json) {
    let payload = hex(doc, "payload_hex");
    let set = revocation_payload_decode(&payload).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(set.site_id, num(doc, "site_id"));
    assert_eq!(set.network, num(doc, "network"));
    assert_eq!(u64::from(set.rs_epoch), num(doc, "rs_epoch"));
    assert_eq!(
        u64::from(set.site_epoch_floor),
        num(doc, "site_epoch_floor")
    );
    assert_eq!(set.entries.len() as u64, num(doc, "count"));
    for (i, entry) in set.entries.iter().enumerate() {
        assert_eq!(entry.node_id, num(doc, &format!("entry{i:02}_node")));
        assert_eq!(
            u64::from(entry.min_generation),
            num(doc, &format!("entry{i:02}_min_generation"))
        );
        assert_eq!(
            entry.reason as u64,
            num(doc, &format!("entry{i:02}_reason"))
        );
    }
    assert_eq!(revocation_payload_encode(&set).unwrap(), payload, "{name}");
    assert_eq!(revocation_aad(set.network), hex(doc, "aad_hex"), "{name}");
    let structure = revocation_sig_structure(&payload, set.network);
    assert_eq!(structure, hex(doc, "sig_structure_hex"), "{name}");
    let signature = arr::<64>(doc, "signature_hex");
    let object = hex(doc, "object_hex");
    assert_eq!(
        revocation_object_assemble(&payload, &signature).unwrap(),
        object,
        "{name}"
    );
    let signer_pub = arr::<64>(doc, "signer_pubkey_hex");
    let (verified_set, verified) =
        revocation_object_verify(&object, &signer_pub, set.site_id, set.network).unwrap();
    assert!(verified, "{name}: verify");
    assert_eq!(verified_set, set);
    let secret = arr::<32>(doc, "signer_secret_hex");
    let sak = FileRootSigner::from_secret(set.site_id, &secret).unwrap();
    assert_eq!(sak.sign(&structure).unwrap(), signature, "{name}: re-sign");
    assert_eq!(
        revocation_issue(&set, &sak).unwrap(),
        object,
        "{name}: issue"
    );
    let seq = num(doc, "commit_seq") as u32;
    let record = hex(doc, "record_hex");
    assert_eq!(
        revocation_record_encode(&object, REVOCATION_SEAL_COMMITTED, seq).unwrap(),
        record,
        "{name}: record"
    );
    let (stored, stored_object, stored_seq) = revocation_record_decode(&record).unwrap();
    assert_eq!(stored, Some(set));
    assert_eq!(stored_object, object);
    assert_eq!(stored_seq, seq);
}

fn check_rrs1_record(name: &str, doc: &Json) {
    let record = hex(doc, "record_hex");
    let (set, object, seq) =
        revocation_record_decode(&record).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert!(set.is_none() && object.is_empty());
    assert_eq!(u64::from(seq), num(doc, "commit_seq"));
    assert_eq!(
        revocation_record_encode(&[], REVOCATION_SEAL_COMMITTED, seq).unwrap(),
        record
    );
}

fn check_rlp1(name: &str, doc: &Json) {
    let record = hex(doc, "record_hex");
    let slot = resume_slot_decode(&record).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(slot.valid, num(doc, "state") == 1);
    if slot.valid {
        let purpose = if num(doc, "purpose") == 1 {
            ResumePurpose::Link
        } else {
            ResumePurpose::End
        };
        assert_eq!(slot.purpose, purpose);
    }
    assert_eq!(u64::from(slot.flags), num(doc, "flags"));
    assert_eq!(slot.peer, num(doc, "peer"));
    assert_eq!(slot.network, num(doc, "network"));
    assert_eq!(slot.peer_cert_id, arr::<8>(doc, "peer_cert_id_hex"));
    assert_eq!(u64::from(slot.peer_generation), num(doc, "peer_generation"));
    assert_eq!(
        u64::from(slot.created_gk_epoch),
        num(doc, "created_gk_epoch")
    );
    assert_eq!(u64::from(slot.last_used_boot), num(doc, "last_used_boot"));
    assert_eq!(slot.rms, arr::<32>(doc, "rms_hex"));
    assert_eq!(
        resume_slot_encode(&slot).unwrap().to_vec(),
        record,
        "{name}"
    );
    if doc.get("peer_cert_hex").is_some() {
        assert_eq!(
            resume_peer_cert_id(&hex(doc, "peer_cert_hex")),
            slot.peer_cert_id
        );
    }
}

fn check_rlp2(name: &str, doc: &Json) {
    let record = hex(doc, "record_hex");
    let slot = resume2_slot_decode(&record).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(slot.valid, num(doc, "state") == 1);
    if slot.valid {
        let purpose = if num(doc, "purpose") == 1 {
            ResumePurpose::Link
        } else {
            ResumePurpose::End
        };
        assert_eq!(slot.purpose, purpose);
    }
    assert_eq!(u64::from(slot.flags), num(doc, "flags"));
    assert_eq!(slot.peer, num(doc, "peer"));
    assert_eq!(slot.network, num(doc, "network"));
    assert_eq!(slot.peer_cert_id, arr::<8>(doc, "peer_cert_id_hex"));
    assert_eq!(slot.local_cert_id, arr::<8>(doc, "local_cert_id_hex"));
    assert_eq!(u64::from(slot.peer_generation), num(doc, "peer_generation"));
    assert_eq!(u64::from(slot.peer_role), num(doc, "peer_role"));
    assert_eq!(
        u64::from(slot.created_gk_epoch),
        num(doc, "created_gk_epoch")
    );
    assert_eq!(u64::from(slot.last_used_boot), num(doc, "last_used_boot"));
    assert_eq!(u64::from(slot.reserved_uses), num(doc, "reserved_uses"));
    assert_eq!(slot.rms, arr::<32>(doc, "rms_hex"));
    assert_eq!(
        resume2_slot_encode(&slot).unwrap().to_vec(),
        record,
        "{name}"
    );
}

fn check_rlv1(name: &str, doc: &Json) {
    let record = hex(doc, "record_hex");
    let (decoded, seq) =
        local_revocation_record_decode(&record).unwrap_or_else(|e| panic!("{name}: {e}"));
    assert_eq!(u64::from(seq), num(doc, "commit_seq"), "{name}");
    assert_eq!(decoded.local_node, num(doc, "local_node"), "{name}");
    assert_eq!(decoded.site_id, num(doc, "site_id"), "{name}");
    assert_eq!(decoded.network, num(doc, "network"), "{name}");
    assert_eq!(
        u64::from(decoded.removed_generation),
        num(doc, "removed_generation"),
        "{name}"
    );
    assert_eq!(
        u64::from(decoded.rs_epoch_floor),
        num(doc, "rs_epoch_floor"),
        "{name}"
    );
    assert_eq!(
        u64::from(decoded.site_epoch_floor),
        num(doc, "site_epoch_floor"),
        "{name}"
    );
    assert_eq!(decoded.state as u64, num(doc, "state"), "{name}");
    assert_eq!(decoded.cause as u64, num(doc, "cause"), "{name}");
    assert_eq!(
        decoded.evidence_digest,
        arr::<32>(doc, "evidence_digest_hex"),
        "{name}"
    );
    assert_eq!(
        u64::from(decoded.rls_commit_seq),
        num(doc, "rls_commit_seq"),
        "{name}"
    );
    assert_eq!(
        u64::from(decoded.boot_witness),
        num(doc, "boot_witness"),
        "{name}"
    );
    assert_eq!(
        u64::from(decoded.holdoff_ms),
        num(doc, "holdoff_ms"),
        "{name}"
    );
    assert_eq!(
        local_revocation_record_encode(&decoded, LOCAL_REVOCATION_SEAL_COMMITTED, seq).unwrap(),
        record,
        "{name}"
    );
}

#[test]
fn sdkv1_valid_vectors_match_byte_for_byte() {
    let valid = files("valid");
    assert!(valid.len() >= 15);
    for (name, doc) in &valid {
        assert_eq!(text(doc, "format"), "routeloom-sdkv1-golden-v1");
        assert_eq!(text(doc, "expect"), "ok", "{name}");
        match text(doc, "codec") {
            "rlcw1" => check_cert(name, doc),
            "rli1" => check_rli1(name, doc),
            "rls1" => check_rls1(name, doc),
            "rrs1" => check_rrs1(name, doc),
            "rrs1_record" => check_rrs1_record(name, doc),
            "rlp1" => check_rlp1(name, doc),
            "rlp2" => check_rlp2(name, doc),
            "rlv1" => check_rlv1(name, doc),
            other => panic!("{name}: unknown codec {other}"),
        }
    }
}

#[test]
fn sdkv1_invalid_vectors_are_rejected() {
    let invalid = files("invalid");
    assert!(invalid.len() >= 60);
    for (name, doc) in &invalid {
        let bytes = hex(doc, "encoded_hex");
        let deny = match text(doc, "expect") {
            "deny" => true,
            "error" => false,
            other => panic!("{name}: expect {other}"),
        };
        match text(doc, "codec") {
            "rlcw1" => {
                let signer = arr::<64>(doc, "signer_pubkey_hex");
                let result = cert_verify(&bytes, &signer);
                if deny {
                    let (claims, verified) = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                    assert!(!verified, "{name}");
                    assert!(matches!(
                        claims.cert_type,
                        CertType::Device | CertType::Site | CertType::Member
                    ));
                } else {
                    assert!(result.is_err(), "{name}");
                    assert!(cert_decode(&bytes).is_err(), "{name}");
                }
            }
            "rli1" => assert!(identity_record_decode(&bytes).is_err(), "{name}"),
            "rls1" => assert!(site_record_decode(&bytes).is_err(), "{name}"),
            "rrs1" => {
                let result = revocation_object_verify(
                    &bytes,
                    &arr::<64>(doc, "signer_pubkey_hex"),
                    num(doc, "expected_site_id"),
                    num(doc, "expected_network"),
                );
                if deny {
                    let (_, verified) = result.unwrap_or_else(|e| panic!("{name}: {e}"));
                    assert!(!verified, "{name}");
                } else {
                    assert!(result.is_err(), "{name}");
                    assert!(revocation_object_decode(&bytes).is_err(), "{name}");
                }
            }
            "rrs1_record" => assert!(revocation_record_decode(&bytes).is_err(), "{name}"),
            "rlp1" => assert!(resume_slot_decode(&bytes).is_err(), "{name}"),
            "rlp2" => assert!(resume2_slot_decode(&bytes).is_err(), "{name}"),
            "rlv1" => assert!(local_revocation_record_decode(&bytes).is_err(), "{name}"),
            other => panic!("{name}: unknown codec {other}"),
        }
    }
}
