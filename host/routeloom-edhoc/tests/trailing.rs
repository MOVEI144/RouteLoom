//! Exact-length rejection against the same RFC 9529 message_2/3/4 fixtures
//! and suffixes as tests/cpp/test_edhoc.cpp.
use routeloom_edhoc::{
    Initiator, LocalCredential, LocalKey, Method, PeerCredential, Responder, SUITE_2,
};
use std::collections::HashMap;

fn vectors() -> HashMap<String, Vec<u8>> {
    let text = include_str!("../../../protocol/edhoc-rfc9529/chapter3.txt");
    text.lines()
        .filter(|s| !s.is_empty() && !s.starts_with('#'))
        .map(|s| {
            let (name, hex) = s.split_once(" = ").unwrap();
            (
                name.to_string(),
                (0..hex.len())
                    .step_by(2)
                    .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                    .collect(),
            )
        })
        .collect()
}

#[test]
fn reject_surplus_message_bytes() {
    let v = vectors();
    let arr = |key: &str| -> [u8; 32] { v[key].as_slice().try_into().unwrap() };
    let mut public = [0u8; 64];
    public[..32].copy_from_slice(&v["PK_R_x"]);
    public[32..].copy_from_slice(&v["PK_R_y"]);
    let peer_r = |_: &[u8], _: &[routeloom_edhoc::EadItem]| {
        Ok(PeerCredential {
            cred: v["CRED_R"].clone(),
            public_key: public,
        })
    };
    let sk_i = arr("SK_I");
    let sk_r = arr("SK_R");
    let local_i = LocalCredential {
        kid: &[0x2b],
        cred: &v["CRED_I"],
        key: LocalKey::StaticDh(&sk_i),
    };
    for suffix in [0xff, 0x00] {
        let mut i =
            Initiator::new(Method::StaticStatic, vec![6, SUITE_2], v["C_I"].clone()).unwrap();
        i.compose_message_1(arr("X"), &[]).unwrap();
        let mut bad = v["message_2"].clone();
        bad.push(suffix);
        assert!(i.process_message_2(&bad, peer_r).is_err());

        let mut r = Responder::new(Method::StaticStatic, v["C_R"].clone()).unwrap();
        r.process_message_1(&v["message_1"]).unwrap();
        let local_r = LocalCredential {
            kid: &[0x32],
            cred: &v["CRED_R"],
            key: LocalKey::StaticDh(&sk_r),
        };
        r.compose_message_2(arr("Y"), &local_r, &[]).unwrap();
        bad = v["message_3"].clone();
        bad.push(suffix);
        assert!(r
            .process_message_3(&bad, |_, _| Ok(PeerCredential {
                cred: v["CRED_I"].clone(),
                public_key: {
                    let mut p = [0u8; 64];
                    p[..32].copy_from_slice(&v["PK_I_x"]);
                    p[32..].copy_from_slice(&v["PK_I_y"]);
                    p
                },
            }))
            .is_err());

        let mut i =
            Initiator::new(Method::StaticStatic, vec![6, SUITE_2], v["C_I"].clone()).unwrap();
        i.compose_message_1(arr("X"), &[]).unwrap();
        i.process_message_2(&v["message_2"], peer_r).unwrap();
        i.compose_message_3(&local_i, &[]).unwrap();
        bad = v["message_4"].clone();
        bad.push(suffix);
        assert!(i.process_message_4(&bad).is_err());
    }
}
