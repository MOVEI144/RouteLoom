//! Byte-exact interoperability with the device-side EDHOC stack (vendored
//! libedhoc v2.3.2 + routeloom::edhoc backend), method 0 / suite 2, SDK v1
//! join profile (docs/design/sdk-v1/08 P3-3).
//!
//! `protocol/edhoc-interop/method0_join.txt` records two full handshakes:
//!
//! - direction `a_`: libedhoc is the device (Initiator), this crate the Site
//!   Authority (Responder);
//! - direction `b_`: this crate is the Initiator, libedhoc the Responder.
//!
//! Credentials are real RLCW1 certificates (DevCert from a test Device CA,
//! SiteCert from a test Site CA) referenced by kid, with the certificate by
//! value and the join items in EAD_1..EAD_4, and the DAMS Exporter output.
//! Ephemeral keys are fixed and both ES256 implementations are
//! deterministic, so every message is reproducible:
//!
//! - `transcript_replays_byte_for_byte` (always): this crate reproduces its
//!   own messages from the recorded inputs and accepts libedhoc's;
//! - ctest `routeloom_edhoc_interop_replay`: libedhoc does the same from the
//!   same file;
//! - `live_against_libedhoc` (when `ROUTELOOM_EDHOC_PEER` names the built
//!   `routeloom_edhoc_interop_peer`): runs both handshakes against the C++
//!   program over pipes and requires the result to equal the file
//!   (`ROUTELOOM_EDHOC_INTEROP_RECORD=1` rewrites it instead).

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};

use routeloom_edhoc::{
    EadItem, Initiator, LocalCredential, LocalKey, Method, PeerCredential, Responder, ScalarSigner,
    SUITE_2,
};
use routeloom_join::{
    dams_exporter_context, JoinEad, JoinIntent, JoinRequest, JoinResult, SiteOffer, SitePackage,
    EXPORTER_LABEL_DAMS, JOIN_EAD_CREDENTIAL_LABEL, JOIN_PROFILE_RLJOIN1,
};
use routeloom_provision::credential::credential_kid;
use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType, MEMBER_ROLE_ENDPOINT};
use routeloom_provision::signer::{test_keypair, FileRootSigner};

/// The two recorded profiles: the SDK v1 join as specified (certificates
/// by value in EAD_2/EAD_3) and the same exchange without the certificate
/// items (kid only), which fits the device backend's current 1280-B arena.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Profile {
    Join,
    KidOnly,
}

impl Profile {
    const ALL: [Profile; 2] = [Profile::Join, Profile::KidOnly];

    fn transcript(self) -> String {
        let name = match self {
            Self::Join => "method0_join.txt",
            Self::KidOnly => "method0_join_kid_only.txt",
        };
        format!(
            "{}/../../protocol/edhoc-interop/{name}",
            env!("CARGO_MANIFEST_DIR")
        )
    }
}

const DEVICE: u64 = 0x00A1_0000_0000_1234;
const DEVICE_CA: u64 = 0x0DCA_0000_0000_0001;
const SITE_CA: u64 = 0x05CA_0000_0000_0001;
const SITE: u64 = 0x5173_0000_0000_0042;
const NETWORK_LOW: u32 = 0x0A1B_2C3D;
const SITE_EPOCH: u32 = 3;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    bytes.iter().fold(String::new(), |mut out, b| {
        let _ = write!(out, "{b:02x}");
        out
    })
}

/// The other side of a handshake: `peer(n, sent)` delivers our message (if
/// any) and returns the peer's message `n`.
type PeerFn<'a> = dyn FnMut(u8, Option<&[u8]>) -> Vec<u8> + 'a;

/// Kills and reaps the peer process on every path (a failed assert included).
struct Reap(std::process::Child);

impl Drop for Reap {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn unhex(text: &str) -> Vec<u8> {
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex"))
        .collect()
}

fn ead_text(items: &[EadItem]) -> String {
    if items.is_empty() {
        return "none".to_string();
    }
    items
        .iter()
        .map(|item| {
            format!(
                "{}:{}",
                item.label,
                hex(item.value.as_deref().unwrap_or(&[]))
            )
        })
        .collect::<Vec<_>>()
        .join(",")
}

fn critical(label: u32, value: Vec<u8>) -> EadItem {
    EadItem::critical(label, value)
}

/// Everything both sides need, derived from fixed test keys.
struct Fixture {
    device_priv: [u8; 32],
    device_pub: [u8; 64],
    device_kid: [u8; 32],
    dev_cert: Vec<u8>,
    sak_priv: [u8; 32],
    sak_pub: [u8; 64],
    sak_kid: [u8; 32],
    site_cert: Vec<u8>,
    exporter_context: Vec<u8>,
    ead: [Vec<EadItem>; 4],
}

fn fixture(profile: Profile) -> Fixture {
    let (device_priv, device_pub) = test_keypair(0x31);
    let (sak_priv, sak_pub) = test_keypair(0x32);
    let (device_ca_priv, _) = test_keypair(0x33);
    let (site_ca_priv, _) = test_keypair(0x34);
    let device_ca = FileRootSigner::from_secret(DEVICE_CA, &device_ca_priv).unwrap();
    let site_ca = FileRootSigner::from_secret(SITE_CA, &site_ca_priv).unwrap();
    let sak = FileRootSigner::from_secret(SITE, &sak_priv).unwrap();
    let dev_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Device,
            issuer: DEVICE_CA,
            subject: DEVICE,
            pubkey: device_pub,
            model: 17,
            hw_rev: 2,
            serial: 90211,
            ..CertClaims::default()
        },
        &device_ca,
    )
    .unwrap();
    let site_claims = CertClaims {
        cert_type: CertType::Site,
        issuer: SITE_CA,
        subject: SITE,
        pubkey: sak_pub,
        network_low32: NETWORK_LOW,
        site_epoch: SITE_EPOCH,
        usage: 1,
        serial: 7,
        ..CertClaims::default()
    };
    let site_cert = cert_issue(&site_claims, &site_ca).unwrap();
    let network = (u64::from(SITE_EPOCH) << 32) | u64::from(NETWORK_LOW);
    let member_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Member,
            issuer: SITE,
            subject: DEVICE,
            pubkey: device_pub,
            network,
            role: MEMBER_ROLE_ENDPOINT,
            assignment_generation: 1,
            site_epoch: SITE_EPOCH,
            serial: 4412,
            ..CertClaims::default()
        },
        &sak,
    )
    .unwrap();
    let intent = JoinIntent {
        org_hint: 0x1234_5678,
        profile_bits: JOIN_PROFILE_RLJOIN1,
    }
    .encode()
    .unwrap();
    let offer = SiteOffer::from_site_cert(&site_claims, 2000)
        .unwrap()
        .encode()
        .unwrap();
    let request = JoinRequest {
        model: 17,
        fw_version: 0x0104_0000,
        capability: 0,
        requested_role: 1,
        last_site_id: 0,
        last_generation: 0,
    }
    .encode()
    .unwrap();
    let result = JoinResult::Allow {
        member_cert,
        site_package: SitePackage {
            site_id: SITE,
            network,
            rs_epoch: 0,
            gk_epoch: 1,
            gk: [0x5A; 32],
            channel: 1,
            role: 1,
            gateway_count: 1,
            channel_epoch: 1,
            gateways: [0x00A1_0000_0000_0001, 0, 0, 0],
            authority_time_s: 1_790_000_000,
            time_uncertainty_ms: 0,
            membership_revision: 1,
        },
        assignment_ticket: Vec::new(),
    }
    .encode()
    .unwrap();
    let device_kid = credential_kid(&device_pub);
    let sak_kid = credential_kid(&sak_pub);
    let with_certificate = |mut items: Vec<EadItem>, cert: Vec<u8>| {
        if profile == Profile::Join {
            items.push(critical(JOIN_EAD_CREDENTIAL_LABEL, cert));
        }
        items
    };
    Fixture {
        device_priv,
        device_pub,
        device_kid,
        dev_cert: dev_cert.clone(),
        sak_priv,
        sak_pub,
        sak_kid,
        site_cert: site_cert.clone(),
        exporter_context: dams_exporter_context(network, DEVICE, SITE, &device_kid, &sak_kid),
        ead: [
            vec![critical(JoinEad::Intent as u32, intent.to_vec())],
            with_certificate(
                vec![critical(JoinEad::Offer as u32, offer.to_vec())],
                site_cert,
            ),
            with_certificate(
                vec![critical(JoinEad::Request as u32, request.to_vec())],
                dev_cert,
            ),
            vec![critical(JoinEad::Result as u32, result)],
        ],
    }
}

struct Direction {
    c_i: Vec<u8>,
    c_r: Vec<u8>,
    x: [u8; 32],
    y: [u8; 32],
}

fn directions() -> [(&'static str, Direction); 2] {
    [
        (
            "a_",
            Direction {
                c_i: vec![0x2C, 0x7F, 0x1A, 0x09],
                c_r: vec![0x5A, 0x17, 0xC0, 0xDE],
                x: test_keypair(0x51).0,
                y: test_keypair(0x52).0,
            },
        ),
        (
            "b_",
            // A one-byte C_I with an int form (sent as 0x21 = -2).
            Direction {
                c_i: vec![0x21],
                c_r: vec![0x00, 0x00, 0x01, 0x07],
                x: test_keypair(0x53).0,
                y: test_keypair(0x54).0,
            },
        ),
    ]
}

/// The inputs part of the transcript file (no messages).
fn inputs_text(f: &Fixture) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        out.insert(k.to_string(), v);
    };
    put("device_priv", hex(&f.device_priv));
    put("device_pub", hex(&f.device_pub));
    put("device_kid", hex(&f.device_kid));
    put("device_cred", hex(&f.dev_cert));
    put("authority_priv", hex(&f.sak_priv));
    put("authority_pub", hex(&f.sak_pub));
    put("authority_kid", hex(&f.sak_kid));
    put("authority_cred", hex(&f.site_cert));
    put("exporter_label", EXPORTER_LABEL_DAMS.to_string());
    put("exporter_context", hex(&f.exporter_context));
    for (prefix, d) in directions() {
        put(&format!("{prefix}c_i"), hex(&d.c_i));
        put(&format!("{prefix}c_r"), hex(&d.c_r));
        put(&format!("{prefix}x"), hex(&d.x));
        put(&format!("{prefix}y"), hex(&d.y));
        for (i, items) in f.ead.iter().enumerate() {
            put(&format!("{prefix}ead{}", i + 1), ead_text(items));
        }
    }
    out
}

fn load_transcript(profile: Profile) -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(profile.transcript()).expect("transcript");
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once(" = ").expect("name = value");
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn device_local<'a>(f: &'a Fixture, signer: &'a ScalarSigner) -> LocalCredential<'a> {
    LocalCredential {
        kid: &f.device_kid,
        cred: &f.dev_cert,
        key: LocalKey::Signature(signer),
    }
}

fn authority_local<'a>(f: &'a Fixture, signer: &'a ScalarSigner) -> LocalCredential<'a> {
    LocalCredential {
        kid: &f.sak_kid,
        cred: &f.site_cert,
        key: LocalKey::Signature(signer),
    }
}

/// Resolver of the tests: the kid must be the expected one and the
/// certificate carried by value in the EAD must be the expected CRED.
fn resolver(
    profile: Profile,
    kid: [u8; 32],
    cred: Vec<u8>,
    public_key: [u8; 64],
) -> impl FnOnce(&[u8], &[EadItem]) -> Result<PeerCredential, String> {
    move |got, ead| {
        if got != kid {
            return Err("unknown kid".into());
        }
        let carried = ead
            .iter()
            .find(|item| item.absolute_label() == u64::from(JOIN_EAD_CREDENTIAL_LABEL))
            .and_then(|item| item.value.clone());
        let expected = (profile == Profile::Join).then_some(&cred[..]);
        if carried.as_deref() != expected {
            return Err("certificate item mismatch".into());
        }
        Ok(PeerCredential { cred, public_key })
    }
}

/// The Rust side of direction `a_` (Responder): takes libedhoc's m1/m3 from
/// `peer`, returns (m2, m4, exporter).
fn rust_responder(
    profile: Profile,
    f: &Fixture,
    d: &Direction,
    peer: &mut PeerFn<'_>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let signer = ScalarSigner(f.sak_priv);
    let mut r = Responder::new(Method::SignatureSignature, d.c_r.clone()).unwrap();
    let m1 = peer(1, None);
    let got1 = r.process_message_1(&m1).unwrap();
    assert_eq!(got1.c_i, d.c_i);
    assert_eq!(got1.ead, f.ead[0]);
    let m2 = r
        .compose_message_2(d.y, &authority_local(f, &signer), &f.ead[1])
        .unwrap();
    let m3 = peer(3, Some(&m2));
    let got3 = r
        .process_message_3(
            &m3,
            resolver(profile, f.device_kid, f.dev_cert.clone(), f.device_pub),
        )
        .unwrap();
    assert_eq!(got3.ead, f.ead[2]);
    let m4 = r.compose_message_4(&f.ead[3]).unwrap();
    peer(5, Some(&m4));
    let exporter = r
        .exporter(EXPORTER_LABEL_DAMS, &f.exporter_context, 32)
        .unwrap();
    (m2, m4, exporter)
}

/// The Rust side of direction `b_` (Initiator): returns (m1, m3, exporter).
fn rust_initiator(
    profile: Profile,
    f: &Fixture,
    d: &Direction,
    peer: &mut PeerFn<'_>,
) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let signer = ScalarSigner(f.device_priv);
    let mut i = Initiator::new(Method::SignatureSignature, vec![SUITE_2], d.c_i.clone()).unwrap();
    let m1 = i.compose_message_1(d.x, &f.ead[0]).unwrap();
    let m2 = peer(2, Some(&m1));
    let got2 = i
        .process_message_2(
            &m2,
            resolver(profile, f.sak_kid, f.site_cert.clone(), f.sak_pub),
        )
        .unwrap();
    assert_eq!(got2.c_r, d.c_r);
    assert_eq!(got2.ead, f.ead[1]);
    let m3 = i
        .compose_message_3(&device_local(f, &signer), &f.ead[2])
        .unwrap();
    let m4 = peer(4, Some(&m3));
    assert_eq!(i.process_message_4(&m4).unwrap(), f.ead[3]);
    let exporter = i
        .exporter(EXPORTER_LABEL_DAMS, &f.exporter_context, 32)
        .unwrap();
    (m1, m3, exporter)
}

#[test]
fn transcript_replays_byte_for_byte() {
    for profile in Profile::ALL {
        replay(profile);
    }
}

fn replay(profile: Profile) {
    let f = fixture(profile);
    let file = load_transcript(profile);
    // The recorded inputs are exactly what this fixture derives.
    for (key, value) in inputs_text(&f) {
        assert_eq!(file.get(&key), Some(&value), "transcript input {key}");
    }
    for (prefix, d) in directions() {
        let get = |name: &str| unhex(&file[&format!("{prefix}{name}")]);
        if prefix == "a_" {
            // libedhoc Initiator → this crate as Responder.
            let (m2, m4, exporter) = rust_responder(profile, &f, &d, &mut |n, _| match n {
                1 => get("m1"),
                3 => get("m3"),
                _ => Vec::new(),
            });
            assert_eq!(m2, get("m2"), "a_m2");
            assert_eq!(m4, get("m4"), "a_m4");
            assert_eq!(exporter, get("exporter"), "a_exporter");
        } else {
            let (m1, m3, exporter) = rust_initiator(profile, &f, &d, &mut |n, _| match n {
                2 => get("m2"),
                4 => get("m4"),
                _ => Vec::new(),
            });
            assert_eq!(m1, get("m1"), "b_m1");
            assert_eq!(m3, get("m3"), "b_m3");
            assert_eq!(exporter, get("exporter"), "b_exporter");
        }
    }
}

/// One live run of the C++ peer for `prefix`; returns the four messages
/// and both exporter outputs.
fn live(
    peer_bin: &str,
    inputs_path: &str,
    prefix: &str,
    profile: Profile,
    f: &Fixture,
    d: &Direction,
) -> BTreeMap<String, String> {
    let role = if prefix == "a_" {
        "initiator"
    } else {
        "responder"
    };
    let mut child = Reap(
        Command::new(peer_bin)
            .args(["--live", role, prefix, inputs_path])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("spawn peer"),
    );
    let mut stdin = child.0.stdin.take().unwrap();
    let mut stdout = BufReader::new(child.0.stdout.take().unwrap());
    let mut read_line = || {
        let mut line = String::new();
        stdout.read_line(&mut line).expect("peer output");
        line.trim_end().to_string()
    };
    let mut messages = BTreeMap::new();
    let mut peer = |n: u8, send: Option<&[u8]>| -> Vec<u8> {
        if let Some(bytes) = send {
            // n is the number the peer answers with; what we send is n-1
            // (n == 5: our final message_4, no answer expected).
            let sent = if n == 5 { 4 } else { n - 1 };
            writeln!(stdin, "m{sent} {}", hex(bytes)).unwrap();
            stdin.flush().unwrap();
        }
        if n == 5 {
            return Vec::new();
        }
        let line = read_line();
        let head = format!("m{n} ");
        assert!(line.starts_with(&head), "peer said {line:?}");
        let bytes = unhex(&line[head.len()..]);
        messages.insert(format!("{prefix}m{n}"), hex(&bytes));
        bytes
    };
    let (first, second, exporter) = if prefix == "a_" {
        let (m2, m4, exporter) = rust_responder(profile, f, d, &mut peer);
        ((2, m2), (4, m4), exporter)
    } else {
        let (m1, m3, exporter) = rust_initiator(profile, f, d, &mut peer);
        ((1, m1), (3, m3), exporter)
    };
    drop(stdin);
    let mut rest = String::new();
    for line in stdout.lines() {
        rest.push_str(&line.unwrap());
        rest.push('\n');
    }
    assert!(child.0.wait().unwrap().success(), "peer failed:\n{rest}");
    assert!(
        rest.contains(&format!("exporter {}", hex(&exporter))),
        "{rest}"
    );
    assert!(rest.trim_end().ends_with("ok"), "{rest}");
    messages.insert(format!("{prefix}m{}", first.0), hex(&first.1));
    messages.insert(format!("{prefix}m{}", second.0), hex(&second.1));
    messages.insert(format!("{prefix}exporter"), hex(&exporter));
    messages
}

#[test]
fn live_against_libedhoc() {
    let Ok(peer_bin) = std::env::var("ROUTELOOM_EDHOC_PEER") else {
        eprintln!("ROUTELOOM_EDHOC_PEER not set: live libedhoc run skipped (the transcript replay still ran)");
        return;
    };
    for profile in Profile::ALL {
        live_profile(&peer_bin, profile);
    }
}

fn live_profile(peer_bin: &str, profile: Profile) {
    let f = fixture(profile);
    let inputs = inputs_text(&f);
    let dir = std::env::temp_dir().join(format!(
        "routeloom-edhoc-interop-{}-{profile:?}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let inputs_path = dir.join("inputs.txt");
    let body = inputs.iter().fold(String::new(), |mut out, (k, v)| {
        out.push_str(&format!("{k} = {v}\n"));
        out
    });
    std::fs::write(&inputs_path, &body).unwrap();
    let mut all = inputs.clone();
    for (prefix, d) in directions() {
        all.extend(live(
            peer_bin,
            inputs_path.to_str().unwrap(),
            prefix,
            profile,
            &f,
            &d,
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    let mut text = format!(
        "# EDHOC method 0 / suite 2 join transcript ({}): libedhoc v2.3.2 (device stack) <-> host/routeloom-edhoc.\n\
         # Generated by `ROUTELOOM_EDHOC_PEER=<build>/tests/cpp/routeloom_edhoc_interop_peer ROUTELOOM_EDHOC_INTEROP_RECORD=1\n\
         # cargo test -p routeloom-edhoc --test interop live_against_libedhoc`. Test keys only. See README.md.\n",
        match profile {
            Profile::Join => "certificates by value in EAD_2/EAD_3",
            Profile::KidOnly => "kid only, no certificate items",
        }
    );
    for (k, v) in &all {
        text.push_str(&format!("{k} = {v}\n"));
    }
    if std::env::var("ROUTELOOM_EDHOC_INTEROP_RECORD").as_deref() == Ok("1") {
        std::fs::write(profile.transcript(), &text).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(profile.transcript()).unwrap(), text);
    }
}
