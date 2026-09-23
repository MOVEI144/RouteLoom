//! Method 0 (RouteLoom's profile) between the two roles of this crate:
//! agreement, EAD delivery, and the failure cases — tampering with every
//! message, unknown kid, wrong key, resolver refusal, ordering.

use routeloom_edhoc::crypto::{public_key_xy, random_scalar};
use routeloom_edhoc::{
    ead_decode, ead_encode, EadItem, Error, Initiator, LocalCredential, LocalKey, Method,
    PeerCredential, Responder, ScalarSigner, SUITE_2,
};

struct Party {
    kid: Vec<u8>,
    cred: Vec<u8>,
    signer: ScalarSigner,
    public: [u8; 64],
}

fn party(seed: u8) -> Party {
    let mut scalar = [seed; 32];
    scalar[0] = 0x01;
    let public = public_key_xy(&scalar).unwrap();
    Party {
        kid: vec![seed; 32],
        // Any CBOR data item serves as CRED_x here (a bstr of the key).
        cred: [&[0x58, 0x40][..], &public].concat(),
        signer: ScalarSigner(scalar),
        public,
    }
}

fn local(p: &Party) -> LocalCredential<'_> {
    LocalCredential {
        kid: &p.kid,
        cred: &p.cred,
        key: LocalKey::Signature(&p.signer),
    }
}

fn known(p: &Party) -> impl Fn(&[u8], &[EadItem]) -> Result<PeerCredential, String> + '_ {
    move |kid, _| {
        if kid == p.kid {
            Ok(PeerCredential {
                cred: p.cred.clone(),
                public_key: p.public,
            })
        } else {
            Err("unknown kid".into())
        }
    }
}

/// Runs a handshake; `tamper(n, message)` may change message n in flight.
/// Returns how many messages were accepted.
fn run(i: &Party, r: &Party, tamper: &dyn Fn(u8, &mut Vec<u8>)) -> (u8, Initiator, Responder) {
    let mut ini =
        Initiator::new(Method::SignatureSignature, vec![SUITE_2], vec![0x01, 0x02]).unwrap();
    let mut res = Responder::new(Method::SignatureSignature, vec![0x0A, 0x0B, 0x0C, 0x0D]).unwrap();
    let ead_1 = vec![EadItem::critical(65537, vec![1; 12])];
    let mut m1 = ini
        .compose_message_1(random_scalar().unwrap(), &ead_1)
        .unwrap();
    tamper(1, &mut m1);
    let Ok(got1) = res.process_message_1(&m1) else {
        return (0, ini, res);
    };
    // EAD_1 is plaintext: a flipped byte in it is only caught at message_2.
    assert_eq!(got1.ead.len(), ead_1.len());
    let ead_2 = vec![
        EadItem::critical(65538, vec![2; 22]),
        EadItem {
            label: 7,
            value: None,
        },
    ];
    let mut m2 = res
        .compose_message_2(random_scalar().unwrap(), &local(r), &ead_2)
        .unwrap();
    tamper(2, &mut m2);
    let Ok(got2) = ini.process_message_2(&m2, known(r)) else {
        return (1, ini, res);
    };
    assert_eq!(got2.ead, ead_2);
    let mut m3 = ini.compose_message_3(&local(i), &[]).unwrap();
    tamper(3, &mut m3);
    let Ok(got3) = res.process_message_3(&m3, known(i)) else {
        return (2, ini, res);
    };
    assert!(got3.ead.is_empty());
    let ead_4 = vec![EadItem::critical(65540, vec![4; 300])];
    let mut m4 = res.compose_message_4(&ead_4).unwrap();
    tamper(4, &mut m4);
    let Ok(got4) = ini.process_message_4(&m4) else {
        return (3, ini, res);
    };
    assert_eq!(got4, ead_4);
    (4, ini, res)
}

#[test]
fn round_trip_agrees_and_each_run_is_fresh() {
    let (i, r) = (party(0x11), party(0x22));
    let (n, ini, res) = run(&i, &r, &|_, _| {});
    assert_eq!(n, 4);
    assert_eq!(ini.prk_out(), res.prk_out());
    let a = ini.exporter(32771, b"ctx", 32).unwrap();
    assert_eq!(a, res.exporter(32771, b"ctx", 32).unwrap());
    assert_ne!(a, ini.exporter(32771, b"other", 32).unwrap());
    let (_, ini2, _) = run(&i, &r, &|_, _| {});
    assert_ne!(ini.prk_out(), ini2.prk_out());
}

#[test]
fn tampering_stops_the_exchange_at_that_message() {
    let (i, r) = (party(0x11), party(0x22));
    for which in 1..=4_u8 {
        let (n, _, _) = run(&i, &r, &|n, m| {
            if n == which {
                let last = m.len() - 1;
                m[last] ^= 0x01;
            }
        });
        // message_1's last byte is inside EAD_1 (not authenticated until
        // TH_2), so its change surfaces at message_2 like the RFC's C_I.
        let expected = if which == 1 { 1 } else { which - 1 };
        assert_eq!(n, expected, "tampered message {which}");
    }
}

#[test]
fn unknown_or_impostor_credentials_are_refused() {
    let (i, r, other) = (party(0x11), party(0x22), party(0x33));
    let mut ini = Initiator::new(Method::SignatureSignature, vec![SUITE_2], vec![]).unwrap();
    let mut res = Responder::new(Method::SignatureSignature, vec![0x07]).unwrap();
    let m1 = ini
        .compose_message_1(random_scalar().unwrap(), &[])
        .unwrap();
    res.process_message_1(&m1).unwrap();
    let m2 = res
        .compose_message_2(random_scalar().unwrap(), &local(&r), &[])
        .unwrap();
    // The resolver maps the Responder's kid to another party's key.
    let impostor = |_: &[u8], _: &[EadItem]| {
        Ok(PeerCredential {
            cred: r.cred.clone(),
            public_key: other.public,
        })
    };
    assert!(matches!(
        ini.process_message_2(&m2, impostor),
        Err(Error::Authentication(_))
    ));
    // A refused kid is a Credential error and the session is dead.
    let mut ini = Initiator::new(Method::SignatureSignature, vec![SUITE_2], vec![]).unwrap();
    let mut res = Responder::new(Method::SignatureSignature, vec![0x07]).unwrap();
    let m1 = ini
        .compose_message_1(random_scalar().unwrap(), &[])
        .unwrap();
    res.process_message_1(&m1).unwrap();
    let m2 = res
        .compose_message_2(random_scalar().unwrap(), &local(&r), &[])
        .unwrap();
    assert!(matches!(
        ini.process_message_2(&m2, known(&other)),
        Err(Error::Credential(_))
    ));
    assert!(matches!(
        ini.compose_message_3(&local(&i), &[]),
        Err(Error::State(_))
    ));
}

#[test]
fn methods_suites_and_order_are_enforced() {
    let r = party(0x22);
    let mut ini = Initiator::new(Method::StaticStatic, vec![SUITE_2], vec![]).unwrap();
    let m1 = ini
        .compose_message_1(random_scalar().unwrap(), &[])
        .unwrap();
    let mut res = Responder::new(Method::SignatureSignature, vec![]).unwrap();
    assert!(matches!(
        res.process_message_1(&m1),
        Err(Error::Unsupported(_))
    ));
    let mut ini = Initiator::new(Method::SignatureSignature, vec![SUITE_2, 3], vec![]).unwrap();
    let m1 = ini
        .compose_message_1(random_scalar().unwrap(), &[])
        .unwrap();
    let mut res = Responder::new(Method::SignatureSignature, vec![]).unwrap();
    assert_eq!(res.process_message_1(&m1), Err(Error::WrongSelectedSuite));
    let mut res = Responder::new(Method::SignatureSignature, vec![]).unwrap();
    assert!(matches!(res.compose_message_4(&[]), Err(Error::State(_))));
    assert!(matches!(
        res.compose_message_2(random_scalar().unwrap(), &local(&r), &[]),
        Err(Error::State(_))
    ));
    assert!(Responder::new(Method::SignatureSignature, vec![0; 5]).is_err());
    assert!(res.exporter(1, &[], 16).is_err());
}

#[test]
fn ead_codec_round_trips_and_bounds() {
    let items = vec![
        EadItem::critical(65541, vec![9; 200]),
        EadItem {
            label: 0,
            value: None,
        },
        EadItem {
            label: 3,
            value: Some(vec![]),
        },
    ];
    assert_eq!(ead_decode(&ead_encode(&items)).unwrap(), items);
    let four = vec![
        EadItem {
            label: 1,
            value: None
        };
        4
    ];
    assert!(ead_decode(&ead_encode(&four)).is_err());
    assert!(ead_decode(&[0x41, 0x00]).is_err());
}
