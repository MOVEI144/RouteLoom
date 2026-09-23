//! RFC 9529 §3 (method 3, cipher suite 2) byte for byte through both roles,
//! and every §4 invalid message refused — the same upstream trace the C++
//! libedhoc backend replays (protocol/edhoc-rfc9529/chapter3.txt).
//!
//! Method 3 is not RouteLoom's profile; it is here because it is the only
//! suite-2 trace in RFC 9529 and it pins everything method 0 shares with it
//! (TH_2/TH_3/TH_4, PRK_2e, KEYSTREAM_2, the plaintext layouts, K_3/IV_3,
//! K_4/IV_4, PRK_out, the exporter, the error message).

use std::collections::HashMap;

use routeloom_edhoc::crypto::edhoc_kdf;
use routeloom_edhoc::{
    error_message_decode, error_message_wrong_suite, Error, ErrorInfo, Initiator, LocalCredential,
    LocalKey, Method, PeerCredential, Responder, SUITE_2,
};

fn vectors() -> HashMap<String, Vec<u8>> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../protocol/edhoc-rfc9529/chapter3.txt"
    );
    let text = std::fs::read_to_string(path).expect("chapter3.txt");
    let mut out = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (name, value) = line.split_once(" = ").expect("name = hex");
        let bytes = (0..value.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&value[i..i + 2], 16).expect("hex"))
            .collect();
        out.insert(name.to_string(), bytes);
    }
    out
}

fn arr32(bytes: &[u8]) -> [u8; 32] {
    bytes.try_into().expect("32 bytes")
}

fn pk(v: &HashMap<String, Vec<u8>>, who: &str) -> [u8; 64] {
    let mut out = [0_u8; 64];
    out[..32].copy_from_slice(&v[&format!("PK_{who}_x")]);
    out[32..].copy_from_slice(&v[&format!("PK_{who}_y")]);
    out
}

fn responder(v: &HashMap<String, Vec<u8>>) -> Responder {
    Responder::new(Method::StaticStatic, v["C_R"].clone()).unwrap()
}

fn initiator(v: &HashMap<String, Vec<u8>>) -> Initiator {
    Initiator::new(Method::StaticStatic, vec![6, SUITE_2], v["C_I"].clone()).unwrap()
}

#[test]
fn section_3_trace_byte_for_byte() {
    let v = vectors();
    let kid_r = [0x32_u8];
    let kid_i = [0x2B_u8];
    let sk_r = arr32(&v["SK_R"]);
    let sk_i = arr32(&v["SK_I"]);

    // §3.1-3.2: a suite-2 Responder refuses SUITES_I = 6 with 0x0202.
    let mut first = Responder::new(Method::StaticStatic, v["C_R"].clone()).unwrap();
    assert_eq!(
        first.process_message_1(&v["message_1_first"]),
        Err(Error::WrongSelectedSuite)
    );
    let error = error_message_wrong_suite(&[SUITE_2]);
    assert_eq!(error, v["error"]);
    assert_eq!(
        error_message_decode(&error).unwrap(),
        (2, ErrorInfo::Suites(vec![SUITE_2]))
    );

    let mut i = initiator(&v);
    let mut r = responder(&v);
    let m1 = i.compose_message_1(arr32(&v["X"]), &[]).unwrap();
    assert_eq!(m1, v["message_1"]);
    let parsed = r.process_message_1(&m1).unwrap();
    assert_eq!(parsed.c_i, v["C_I"]);
    assert_eq!(parsed.suites_i, vec![6, 2]);
    assert!(parsed.ead.is_empty());

    let local_r = LocalCredential {
        kid: &kid_r,
        cred: &v["CRED_R"],
        key: LocalKey::StaticDh(&sk_r),
    };
    let m2 = r.compose_message_2(arr32(&v["Y"]), &local_r, &[]).unwrap();
    assert_eq!(m2, v["message_2"]);

    let cred_r = v["CRED_R"].clone();
    let pk_r = pk(&v, "R");
    let got2 = i
        .process_message_2(&m2, |kid, ead| {
            assert_eq!(kid, [0x32]);
            assert!(ead.is_empty());
            Ok(PeerCredential {
                cred: cred_r.clone(),
                public_key: pk_r,
            })
        })
        .unwrap();
    assert_eq!(got2.c_r, v["C_R"]);

    let local_i = LocalCredential {
        kid: &kid_i,
        cred: &v["CRED_I"],
        key: LocalKey::StaticDh(&sk_i),
    };
    let m3 = i.compose_message_3(&local_i, &[]).unwrap();
    assert_eq!(m3, v["message_3"]);

    let cred_i = v["CRED_I"].clone();
    let pk_i = pk(&v, "I");
    let got3 = r
        .process_message_3(&m3, |kid, _| {
            assert_eq!(kid, [0x2B]);
            Ok(PeerCredential {
                cred: cred_i.clone(),
                public_key: pk_i,
            })
        })
        .unwrap();
    assert_eq!(got3.kid, vec![0x2B]);

    let m4 = r.compose_message_4(&[]).unwrap();
    assert_eq!(m4, v["message_4"]);
    assert!(i.process_message_4(&m4).unwrap().is_empty());

    // §3.7 PRK_out, §3.8 the OSCORE exporter outputs (labels 0 and 1).
    assert_eq!(i.prk_out().unwrap().to_vec(), v["PRK_out"]);
    assert_eq!(r.prk_out().unwrap().to_vec(), v["PRK_out"]);
    for party in [
        i.exporter(0, &[], 16).unwrap(),
        r.exporter(0, &[], 16).unwrap(),
    ] {
        assert_eq!(party, v["OSCORE_master_secret"]);
    }
    for party in [
        i.exporter(1, &[], 8).unwrap(),
        r.exporter(1, &[], 8).unwrap(),
    ] {
        assert_eq!(party, v["OSCORE_master_salt"]);
    }
    // PRK_exporter itself (§3.7): EDHOC_KDF(PRK_out, 10, h'', 32).
    let prk_out = arr32(&v["PRK_out"]);
    assert_eq!(edhoc_kdf(&prk_out, 10, &[], 32).unwrap(), v["PRK_exporter"]);
}

#[test]
fn section_4_invalid_message_1_refused() {
    let v = vectors();
    for name in [
        "invalid_4_1_1_message_1",
        // §4.1.2: C_I = 0x0e sent as bstr 41 0e. libedhoc accepts it as the
        // same C_I; this implementation refuses the non-canonical form.
        "invalid_4_1_2_message_1",
        "invalid_4_1_3_message_1",
        "invalid_4_1_4_message_1",
        "invalid_4_2_1_message_1",
        "invalid_4_2_2_message_1",
        "invalid_4_2_3_message_1",
        "invalid_4_2_4_message_1",
        "invalid_4_2_6_message_1",
        "invalid_4_3_1_message_1",
        "invalid_4_3_2_message_1",
    ] {
        let mut r = responder(&v);
        assert!(r.process_message_1(&v[name]).is_err(), "{name} accepted");
        // A failed session refuses to continue.
        assert!(r.process_message_1(&v["message_1"]).is_err(), "{name}");
    }
}

#[test]
fn section_4_invalid_message_2_refused() {
    let v = vectors();
    let accept = |_: &[u8], _: &[routeloom_edhoc::EadItem]| {
        Ok(PeerCredential {
            cred: v["CRED_R"].clone(),
            public_key: pk(&v, "R"),
        })
    };
    let mut i = initiator(&v);
    i.compose_message_1(arr32(&v["X"]), &[]).unwrap();
    assert!(i
        .process_message_2(&v["invalid_4_1_5_message_2"], accept)
        .is_err());

    // The invalid PLAINTEXT_2s, encrypted with the RFC's keystream
    // construction: KEYSTREAM_2 = EDHOC_KDF(PRK_2e, 0, TH_2, len).
    let prk_2e = arr32(&v["PRK_2e"]);
    for name in [
        "invalid_4_1_6_PLAINTEXT_2",
        "invalid_4_1_7_PLAINTEXT_2",
        "invalid_4_2_5_PLAINTEXT_2",
    ] {
        let plaintext = &v[name];
        let keystream = edhoc_kdf(&prk_2e, 0, &v["TH_2"], plaintext.len()).unwrap();
        let mut body = v["G_Y"].clone();
        body.extend(plaintext.iter().zip(&keystream).map(|(p, k)| p ^ k));
        let mut message = vec![0x58, body.len() as u8];
        message.extend_from_slice(&body);
        let mut i = initiator(&v);
        i.compose_message_1(arr32(&v["X"]), &[]).unwrap();
        assert!(
            i.process_message_2(&message, accept).is_err(),
            "{name} accepted"
        );
    }
    // The construction itself reproduces the valid message_2.
    let plaintext = &v["PLAINTEXT_2"];
    let keystream = edhoc_kdf(&prk_2e, 0, &v["TH_2"], plaintext.len()).unwrap();
    assert_eq!(keystream, v["KEYSTREAM_2"]);
}
