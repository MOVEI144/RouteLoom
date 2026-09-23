//! SDK v1 join EAD golden vectors: loads `protocol/sdkv1-golden/ead/` — the
//! files the C++ harness (`tests/cpp/test_sdkv1_ead.cpp`) reads — and
//! asserts byte-for-byte agreement of every codec. Unlike the C++ side
//! (verify-only), this harness plays the Site Authority: it RE-ISSUES each
//! Allow's MemberCert and each RemovalNotice with RustCrypto `p256`
//! (RFC 6979, low-S) and rebuilds the JoinResult, which must equal the
//! generator's bytes exactly.
//!
//! Regenerate with `python3 tools/gen_sdkv1_ead_vectors.py`.

use std::fs;
use std::path::{Path, PathBuf};

use routeloom_join::{
    join_allow_verify, join_ead_find, join_ead_item_encode, join_org_hint, join_site_hint,
    removal_notice_aad, JoinEad, JoinIntent, JoinRequest, JoinResult, RemovalNotice, SiteOffer,
    SitePackage,
};
use routeloom_json::Json;
use routeloom_provision::sdkv1::cert::{cert_decode, cert_issue, CertClaims};
use routeloom_provision::signer::FileRootSigner;
use routeloom_provision::Code;

fn golden_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../protocol/sdkv1-golden/ead")
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

fn label_named(name: &str) -> JoinEad {
    match name {
        "intent" => JoinEad::Intent,
        "offer" => JoinEad::Offer,
        "request" => JoinEad::Request,
        _ => JoinEad::Result,
    }
}

fn cert(doc: &Json, key: &str) -> CertClaims {
    cert_decode(&hex(doc, key)).unwrap()
}

fn check_item(name: &str, doc: &Json, label: JoinEad) {
    assert_eq!(num(doc, "label"), u64::from(label as u32), "{name}");
    let value = hex(doc, "value_hex");
    let item = hex(doc, "item_hex");
    assert_eq!(join_ead_item_encode(label, &value).unwrap(), item, "{name}");
    assert_eq!(join_ead_find(&item, label).unwrap(), value, "{name}");
    for other in JoinEad::ALL {
        if other != label {
            assert!(join_ead_find(&item, other).is_err(), "{name}");
        }
    }
}

fn package_from(doc: &Json) -> SitePackage {
    SitePackage {
        site_id: num(doc, "site_id"),
        network: num(doc, "network"),
        rs_epoch: num(doc, "rs_epoch") as u32,
        gk_epoch: num(doc, "gk_epoch") as u32,
        gk: arr::<32>(doc, "gk_hex"),
        channel: num(doc, "channel") as u8,
        role: num(doc, "role") as u8,
        gateway_count: num(doc, "gateway_count") as u8,
        channel_epoch: num(doc, "channel_epoch") as u32,
        gateways: [0, 1, 2, 3].map(|i| num(doc, &format!("gateway{i}"))),
        authority_time_s: num(doc, "authority_time_s"),
        time_uncertainty_ms: num(doc, "time_uncertainty_ms") as u32,
        membership_revision: num(doc, "membership_revision") as u32,
    }
}

fn allow_verified(doc: &Json, result: &JoinResult) -> routeloom_provision::Result<bool> {
    join_allow_verify(
        result,
        &cert(doc, "site_cert_hex"),
        num(doc, "node"),
        &arr::<64>(doc, "device_pubkey_hex"),
        num(doc, "strict_assignment") != 0,
    )
    .map(|(_, verified)| verified)
}

fn notice_verify(doc: &Json, object: &[u8]) -> routeloom_provision::Result<bool> {
    RemovalNotice::verify(
        object,
        &arr::<64>(doc, "signer_pubkey_hex"),
        num(doc, "own_site_id"),
        num(doc, "own_network"),
        num(doc, "own_node"),
        num(doc, "own_generation") as u32,
    )
    .map(|(_, verified)| verified)
}

fn valid(name: &str, doc: &Json) {
    match text(doc, "codec") {
        "hint" => {
            assert_eq!(
                u64::from(join_org_hint(&arr::<64>(doc, "site_ca_pubkey_hex"))),
                num(doc, "org_hint"),
                "{name}"
            );
            assert_eq!(
                u64::from(join_site_hint(num(doc, "site_id"))),
                num(doc, "site_hint"),
                "{name}"
            );
        }
        "join_intent" => {
            let intent = JoinIntent::decode(&hex(doc, "value_hex")).unwrap();
            assert_eq!(u64::from(intent.org_hint), num(doc, "org_hint"), "{name}");
            assert_eq!(
                u64::from(intent.profile_bits),
                num(doc, "profile_bits"),
                "{name}"
            );
            assert_eq!(intent.encode().unwrap().to_vec(), hex(doc, "value_hex"));
            check_item(name, doc, JoinEad::Intent);
        }
        "site_offer" => {
            let site = cert(doc, "site_cert_hex");
            let offer = SiteOffer::decode(&hex(doc, "value_hex")).unwrap();
            // The Site Authority derives its offer from its SiteCert.
            let built =
                SiteOffer::from_site_cert(&site, num(doc, "decision_timeout_ms") as u16).unwrap();
            assert_eq!(offer, built, "{name}");
            assert_eq!(offer.encode().unwrap().to_vec(), hex(doc, "value_hex"));
            offer.matches_site_cert(&site).unwrap();
            check_item(name, doc, JoinEad::Offer);
        }
        "join_request" => {
            let request = JoinRequest::decode(&hex(doc, "value_hex")).unwrap();
            assert_eq!(u64::from(request.model), num(doc, "model"), "{name}");
            assert_eq!(
                u64::from(request.fw_version),
                num(doc, "fw_version"),
                "{name}"
            );
            assert_eq!(
                u64::from(request.capability),
                num(doc, "capability"),
                "{name}"
            );
            assert_eq!(
                u64::from(request.requested_role),
                num(doc, "requested_role"),
                "{name}"
            );
            assert_eq!(request.last_site_id, num(doc, "last_site_id"), "{name}");
            assert_eq!(
                u64::from(request.last_generation),
                num(doc, "last_generation"),
                "{name}"
            );
            assert_eq!(request.encode().unwrap().to_vec(), hex(doc, "value_hex"));
            request
                .matches_dev_cert(&cert(doc, "dev_cert_hex"))
                .unwrap();
            check_item(name, doc, JoinEad::Request);
        }
        "site_package" => {
            let package = SitePackage::decode(&hex(doc, "value_hex")).unwrap();
            assert_eq!(package, package_from(doc), "{name}");
            assert_eq!(package.encode().unwrap().to_vec(), hex(doc, "value_hex"));
        }
        "removal_notice" => {
            let object = hex(doc, "object_hex");
            let notice = RemovalNotice::decode(&object).unwrap();
            assert_eq!(notice.reason as u64, num(doc, "reason"), "{name}");
            assert_eq!(notice.site_id, num(doc, "site_id"), "{name}");
            assert_eq!(notice.node_id, num(doc, "node_id"), "{name}");
            assert_eq!(u64::from(notice.generation), num(doc, "generation"));
            assert_eq!(u64::from(notice.rs_epoch), num(doc, "rs_epoch"));
            let network = num(doc, "network");
            assert_eq!(
                notice.payload_encode().unwrap().to_vec(),
                hex(doc, "payload_hex")
            );
            assert_eq!(removal_notice_aad(network), hex(doc, "aad_hex"));
            assert_eq!(
                notice.sig_structure(network).unwrap(),
                hex(doc, "sig_structure_hex")
            );
            let payload = hex(doc, "payload_hex");
            assert_eq!(
                RemovalNotice::assemble(&payload, &arr::<64>(doc, "signature_hex")).unwrap(),
                object
            );
            let sak =
                FileRootSigner::from_secret(notice.site_id, &arr::<32>(doc, "signer_secret_hex"))
                    .unwrap();
            assert_eq!(
                notice.issue(network, &sak).unwrap(),
                object,
                "{name}: re-sign"
            );
            assert!(notice_verify(doc, &object).unwrap(), "{name}");
        }
        "join_result" => {
            let value = hex(doc, "value_hex");
            let result = JoinResult::decode(&value).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(result.verdict() as u64, num(doc, "verdict"), "{name}");
            assert_eq!(
                u64::from(result.retry_after_s()),
                num(doc, "retry_after_s"),
                "{name}"
            );
            assert_eq!(value.len() as u64, 12 + num(doc, "body_len"), "{name}");
            assert_eq!(result.encode().unwrap(), value, "{name}");
            match &result {
                JoinResult::Allow {
                    member_cert,
                    site_package,
                    assignment_ticket,
                } => {
                    assert_eq!(member_cert, &hex(doc, "member_cert_hex"), "{name}");
                    assert_eq!(assignment_ticket, &hex(doc, "assignment_ticket_hex"));
                    assert_eq!(
                        site_package.encode().unwrap().to_vec(),
                        hex(doc, "site_package_hex")
                    );
                    assert_eq!(
                        allow_verified(doc, &result).unwrap(),
                        num(doc, "verified") == 1,
                        "{name}"
                    );
                    // Site Authority path: issue the MemberCert with the SAK
                    // and build the JoinResult from scratch.
                    let claims = cert_decode(member_cert).unwrap();
                    let sak = FileRootSigner::from_secret(
                        claims.issuer,
                        &arr::<32>(doc, "sak_secret_hex"),
                    )
                    .unwrap();
                    let rebuilt = JoinResult::Allow {
                        member_cert: cert_issue(&claims, &sak).unwrap(),
                        site_package: site_package.clone(),
                        assignment_ticket: assignment_ticket.clone(),
                    };
                    assert_eq!(rebuilt.encode().unwrap(), value, "{name}: re-issue");
                    if !assignment_ticket.is_empty() {
                        // A2 device: ticket format not pinned -> fail closed.
                        let err = join_allow_verify(
                            &result,
                            &cert(doc, "site_cert_hex"),
                            num(doc, "node"),
                            &arr::<64>(doc, "device_pubkey_hex"),
                            true,
                        )
                        .unwrap_err();
                        assert_eq!(err.code, Code::Unsupported, "{name}");
                    }
                }
                JoinResult::PendingAssignment { ticket, .. } => {
                    assert_eq!(ticket, &hex(doc, "pending_ticket_hex"), "{name}");
                }
                JoinResult::Removed { removal_notice } => {
                    assert_eq!(removal_notice, &hex(doc, "removal_notice_hex"), "{name}");
                    assert!(notice_verify(doc, removal_notice).unwrap(), "{name}");
                }
                _ => {}
            }
            check_item(name, doc, JoinEad::Result);
        }
        "ead_field" => {
            let ead = hex(doc, "ead_hex");
            let value = join_ead_find(&ead, label_named(text(doc, "expected"))).unwrap();
            assert_eq!(value, hex(doc, "value_hex"), "{name}");
        }
        other => panic!("{name}: unknown codec {other}"),
    }
}

fn invalid(name: &str, doc: &Json) {
    let encoded = hex(doc, "encoded_hex");
    let deny = match text(doc, "expect") {
        "deny" => true,
        "error" => false,
        other => panic!("{name}: expect {other}"),
    };
    match text(doc, "codec") {
        "join_intent" => {
            let decoded = JoinIntent::decode(&encoded);
            assert_eq!(decoded.is_ok(), deny, "{name}");
            if let Ok(intent) = decoded {
                assert_ne!(
                    intent.org_hint,
                    join_org_hint(&arr::<64>(doc, "site_ca_pubkey_hex")),
                    "{name}"
                );
            }
        }
        "site_offer" => {
            let decoded = SiteOffer::decode(&encoded);
            assert_eq!(decoded.is_ok(), deny, "{name}");
            if let Ok(offer) = decoded {
                let e = offer
                    .matches_site_cert(&cert(doc, "site_cert_hex"))
                    .unwrap_err();
                assert_eq!(e.code, Code::AuthorizationFailed, "{name}");
            }
        }
        "join_request" => {
            let decoded = JoinRequest::decode(&encoded);
            assert_eq!(decoded.is_ok(), deny, "{name}");
            if let Ok(request) = decoded {
                let e = request
                    .matches_dev_cert(&cert(doc, "dev_cert_hex"))
                    .unwrap_err();
                assert_eq!(e.code, Code::AuthorizationFailed, "{name}");
            }
        }
        "site_package" => {
            assert!(!deny, "{name}");
            assert!(SitePackage::decode(&encoded).is_err(), "{name}");
        }
        "removal_notice" => {
            assert_eq!(RemovalNotice::decode(&encoded).is_ok(), deny, "{name}");
            match notice_verify(doc, &encoded) {
                Ok(verified) => assert!(deny && !verified, "{name}"),
                Err(_) => assert!(!deny, "{name}"),
            }
        }
        "join_result" => {
            let decoded = JoinResult::decode(&encoded);
            assert_eq!(decoded.is_ok(), deny, "{name}: {decoded:?}");
            if let Ok(result) = decoded {
                assert!(!allow_verified(doc, &result).unwrap(), "{name}");
            }
        }
        "ead_field" => {
            assert!(!deny, "{name}");
            assert!(
                join_ead_find(&encoded, label_named(text(doc, "expected"))).is_err(),
                "{name}"
            );
        }
        other => panic!("{name}: unknown codec {other}"),
    }
}

#[test]
fn sdkv1_ead_golden_vectors() {
    let valid_files = files("valid");
    let invalid_files = files("invalid");
    assert!(valid_files.len() >= 30);
    assert!(invalid_files.len() >= 120);
    for (name, doc) in &valid_files {
        assert_eq!(text(doc, "expect"), "ok", "{name}");
        valid(name, doc);
    }
    for (name, doc) in &invalid_files {
        invalid(name, doc);
    }
}
