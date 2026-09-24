//! P4 member handshake interop: method 0 / suite 2 between libedhoc (the
//! device stack, via the C++ `routeloom_edhoc_interop_peer`) and
//! host/routeloom-edhoc, with the session EAD items of design-p4 §5.2/§5.3
//! and the five session Exporter outputs of §5.4 (dir1/dir2 key+IV, RMS).
//!
//! The fixture mirrors the join profile in `interop.rs`: two members with
//! real MemberCerts issued by a test Site Authority Key. Member A always
//! initiates, member B always responds; the two directions differ in the
//! CIDs (both fixed 4-byte strings per §5.1, big-endian into the Exporter
//! contexts) and the ephemeral keys, so the direction-bound Exporter
//! contexts, the ContextConfirm digest, and all five outputs differ per
//! direction while the Intent/State items are shared:
//!
//! - `transcript_replays_byte_for_byte` (always): this crate reproduces its
//!   own messages from the recorded inputs and accepts libedhoc's;
//! - ctest `routeloom_edhoc_interop_replay_member`: libedhoc does the same
//!   from the same file;
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
use routeloom_keysched::session::{
    exporter_context_encode, link_carrier_digest, session_capability_digest,
    session_contexts_digest, ContextConfirm, ExporterContextParams, LinkCarrier, SessionIntent,
    SessionState, EAD_CONTEXT_CONFIRM, EAD_SESSION_INTENT, EAD_SESSION_STATE,
    RLD1_CAP_MEMBER_EDHOC_V1, RLD1_CAP_MEMBER_RESUME_V1, SESSION_CONFIRM_BYTES,
    SESSION_INTENT_BYTES, SESSION_PROFILE_MEMBER, SESSION_PURPOSE_LINK, SESSION_STATE_BYTES,
};
use routeloom_keysched::{EXPORTER_AEAD_KEY, EXPORTER_BASE_IV, EXPORTER_RESUME_MASTER};
use routeloom_provision::credential::credential_kid;
use routeloom_provision::sdkv1::cert::{
    cert_issue, cert_verify, CertClaims, CertType, MEMBER_ROLE_ENDPOINT, MEMBER_ROLE_GATEWAY,
};
use routeloom_provision::signer::{test_keypair, FileRootSigner};

const MEMBER_A: u64 = 0x00A1_0000_0000_1234;
const MEMBER_B: u64 = 0x00A1_0000_0000_5678;
const SITE_CA: u64 = 0x05CA_0000_0000_0001;
const SITE: u64 = 0x5173_0000_0000_0042;
const NETWORK_LOW: u32 = 0x0A1B_2C3D;
const SITE_EPOCH: u32 = 3;

fn transcript() -> String {
    format!(
        "{}/../../protocol/edhoc-interop/method0_member.txt",
        env!("CARGO_MANIFEST_DIR")
    )
}

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

/// Everything both sides need, derived from fixed test keys. The Intent and
/// State items name no CIDs, so they are shared; the Exporter contexts and
/// the ContextConfirm bind the direction's CIDs (see [`DirMatter`]).
struct Fixture {
    a_priv: [u8; 32],
    a_pub: [u8; 64],
    a_kid: [u8; 32],
    a_cert: Vec<u8>,
    b_priv: [u8; 32],
    b_pub: [u8; 64],
    b_kid: [u8; 32],
    b_cert: Vec<u8>,
    sak_pub: [u8; 64],
    intent: [u8; SESSION_INTENT_BYTES],
    state_r: [u8; SESSION_STATE_BYTES],
    state_i: [u8; SESSION_STATE_BYTES],
    capability: [u8; 32],
    rms: Vec<u8>,
}

fn fixture() -> Fixture {
    let (a_priv, a_pub) = test_keypair(0x41);
    let (b_priv, b_pub) = test_keypair(0x42);
    let (site_ca_priv, _) = test_keypair(0x43);
    let (sak_priv, sak_pub) = test_keypair(0x44);
    let site_ca = FileRootSigner::from_secret(SITE_CA, &site_ca_priv).unwrap();
    let sak = FileRootSigner::from_secret(SITE, &sak_priv).unwrap();
    // The site certificate itself (needed only so the issuer chain exists).
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
    let _ = cert_issue(&site_claims, &site_ca).unwrap();
    let network = (u64::from(SITE_EPOCH) << 32) | u64::from(NETWORK_LOW);
    let a_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Member,
            issuer: SITE,
            subject: MEMBER_A,
            pubkey: a_pub,
            network,
            role: MEMBER_ROLE_ENDPOINT,
            assignment_generation: 1,
            site_epoch: SITE_EPOCH,
            serial: 4401,
            ..CertClaims::default()
        },
        &sak,
    )
    .unwrap();
    let b_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Member,
            issuer: SITE,
            subject: MEMBER_B,
            pubkey: b_pub,
            network,
            role: MEMBER_ROLE_GATEWAY,
            assignment_generation: 1,
            site_epoch: SITE_EPOCH,
            serial: 4402,
            ..CertClaims::default()
        },
        &sak,
    )
    .unwrap();
    let a_kid = credential_kid(&a_pub);
    let b_kid = credential_kid(&b_pub);

    // Session EAD values of design-p4 §5.3: the Intent binding is a real
    // link-carrier digest over fixed nonces, the States carry the two
    // members' epochs and boots.
    let caps = RLD1_CAP_MEMBER_EDHOC_V1 | RLD1_CAP_MEMBER_RESUME_V1;
    let binding = link_carrier_digest(&LinkCarrier {
        network,
        node_i: MEMBER_A,
        node_r: MEMBER_B,
        requester_nonce: [0x11; 16],
        responder_nonce: [0x22; 16],
        cookie: [0x33; 16],
        capability_i: caps,
        capability_r: caps,
        scope_binding: [0x44; 32],
    });
    let intent = SessionIntent {
        purpose: SESSION_PURPOSE_LINK,
        profile: SESSION_PROFILE_MEMBER,
        caps_i: caps,
        boot_i: 1,
        binding,
    }
    .encode()
    .unwrap();
    let state_r = SessionState {
        purpose: SESSION_PURPOSE_LINK,
        profile: SESSION_PROFILE_MEMBER,
        site_epoch: SITE_EPOCH,
        rs_epoch: 0,
        gk_epoch: 1,
        boot: 2,
        caps,
    }
    .encode()
    .unwrap();
    let state_i = SessionState {
        purpose: SESSION_PURPOSE_LINK,
        profile: SESSION_PROFILE_MEMBER,
        site_epoch: SITE_EPOCH,
        rs_epoch: 0,
        gk_epoch: 1,
        boot: 1,
        caps,
    }
    .encode()
    .unwrap();
    let capability = session_capability_digest(&intent, &state_r, &state_i).unwrap();
    let rms = exporter_context_encode(&context_params(a_kid, b_kid, capability, 0, 0)).unwrap();
    Fixture {
        a_priv,
        a_pub,
        a_kid,
        a_cert,
        b_priv,
        b_pub,
        b_kid,
        b_cert,
        sak_pub,
        intent,
        state_r,
        state_i,
        capability,
        rms,
    }
}

fn context_params(
    a_kid: [u8; 32],
    b_kid: [u8; 32],
    capability: [u8; 32],
    context_epoch: u32,
    direction: u8,
) -> ExporterContextParams {
    ExporterContextParams {
        purpose: SESSION_PURPOSE_LINK,
        network: (u64::from(SITE_EPOCH) << 32) | u64::from(NETWORK_LOW),
        node_i: MEMBER_A,
        node_r: MEMBER_B,
        kid_i: a_kid,
        kid_r: b_kid,
        role_i: MEMBER_ROLE_ENDPOINT,
        role_r: MEMBER_ROLE_GATEWAY,
        generation_i: 1,
        generation_r: 1,
        context_epoch,
        direction,
        capability_digest: capability,
    }
}

struct Direction {
    c_i: [u8; 4],
    c_r: [u8; 4],
    x: [u8; 32],
    y: [u8; 32],
}

fn directions() -> [(&'static str, Direction); 2] {
    [
        (
            "a_",
            Direction {
                c_i: [0x2C, 0x7F, 0x1A, 0x09],
                c_r: [0x5A, 0x17, 0xC0, 0xDE],
                x: test_keypair(0x51).0,
                y: test_keypair(0x52).0,
            },
        ),
        (
            "b_",
            Direction {
                c_i: [0x00, 0x00, 0x01, 0x07],
                c_r: [0x11, 0x22, 0x33, 0x44],
                x: test_keypair(0x53).0,
                y: test_keypair(0x54).0,
            },
        ),
    ]
}

/// The per-direction handshake matter: the four EAD lists (only the
/// ContextConfirm differs, through the direction-bound contexts) and the
/// three Exporter contexts feeding the five outputs.
struct DirMatter {
    ead: [Vec<EadItem>; 4],
    dir1: Vec<u8>,
    dir2: Vec<u8>,
}

/// The five session Exporter checks of §5.4 as (label, context, length):
/// dir1 key+IV, dir2 key+IV, RMS.
fn checks(m: &DirMatter, f: &Fixture) -> [(u64, Vec<u8>, usize); 5] {
    [
        (u64::from(EXPORTER_AEAD_KEY), m.dir1.clone(), 16),
        (u64::from(EXPORTER_BASE_IV), m.dir1.clone(), 12),
        (u64::from(EXPORTER_AEAD_KEY), m.dir2.clone(), 16),
        (u64::from(EXPORTER_BASE_IV), m.dir2.clone(), 12),
        (u64::from(EXPORTER_RESUME_MASTER), f.rms.clone(), 32),
    ]
}

fn dir_matter(f: &Fixture, d: &Direction) -> DirMatter {
    // Direction 1 (I->R) binds the receiver's C_R, direction 2 the C_I
    // (both big-endian u32, nonzero 4-byte strings per §5.1).
    let cid_i = u32::from_be_bytes(d.c_i);
    let cid_r = u32::from_be_bytes(d.c_r);
    assert_ne!(cid_i, 0);
    assert_ne!(cid_r, 0);
    let dir1 =
        exporter_context_encode(&context_params(f.a_kid, f.b_kid, f.capability, cid_r, 1)).unwrap();
    let dir2 =
        exporter_context_encode(&context_params(f.a_kid, f.b_kid, f.capability, cid_i, 2)).unwrap();
    let digest = session_contexts_digest(&dir1, &dir2, &f.rms).unwrap();
    assert_ne!(digest, [0u8; 32]);
    let confirm: [u8; SESSION_CONFIRM_BYTES] = ContextConfirm {
        purpose: SESSION_PURPOSE_LINK,
        profile: SESSION_PROFILE_MEMBER,
        contexts_digest: digest,
    }
    .encode()
    .unwrap();
    DirMatter {
        ead: [
            vec![critical(
                EAD_SESSION_INTENT.unsigned_abs(),
                f.intent.to_vec(),
            )],
            vec![critical(
                EAD_SESSION_STATE.unsigned_abs(),
                f.state_r.to_vec(),
            )],
            vec![critical(
                EAD_SESSION_STATE.unsigned_abs(),
                f.state_i.to_vec(),
            )],
            vec![critical(
                EAD_CONTEXT_CONFIRM.unsigned_abs(),
                confirm.to_vec(),
            )],
        ],
        dir1,
        dir2,
    }
}

/// The inputs part of the transcript file (no messages).
fn inputs_text(f: &Fixture) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut put = |k: &str, v: String| {
        out.insert(k.to_string(), v);
    };
    put("member_a_priv", hex(&f.a_priv));
    put("member_a_pub", hex(&f.a_pub));
    put("member_a_kid", hex(&f.a_kid));
    put("member_a_cred", hex(&f.a_cert));
    put("member_b_priv", hex(&f.b_priv));
    put("member_b_pub", hex(&f.b_pub));
    put("member_b_kid", hex(&f.b_kid));
    put("member_b_cred", hex(&f.b_cert));
    for (prefix, d) in directions() {
        let m = dir_matter(f, &d);
        put(&format!("{prefix}c_i"), hex(&d.c_i));
        put(&format!("{prefix}c_r"), hex(&d.c_r));
        put(&format!("{prefix}x"), hex(&d.x));
        put(&format!("{prefix}y"), hex(&d.y));
        for (i, items) in m.ead.iter().enumerate() {
            put(&format!("{prefix}ead{}", i + 1), ead_text(items));
        }
        for (i, (label, context, length)) in checks(&m, f).iter().enumerate() {
            let tag = if i == 0 {
                "exporter".to_string()
            } else {
                format!("exporter{}", i + 1)
            };
            put(&format!("{prefix}{tag}_label"), label.to_string());
            put(&format!("{prefix}{tag}_context"), hex(context));
            put(&format!("{prefix}{tag}_length"), length.to_string());
        }
    }
    out
}

fn load_transcript() -> BTreeMap<String, String> {
    let text = std::fs::read_to_string(transcript()).expect("transcript");
    text.lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| {
            let (k, v) = l.split_once(" = ").expect("name = value");
            (k.to_string(), v.to_string())
        })
        .collect()
}

fn a_local<'a>(f: &'a Fixture, signer: &'a ScalarSigner) -> LocalCredential<'a> {
    LocalCredential {
        kid: &f.a_kid,
        cred: &f.a_cert,
        key: LocalKey::Signature(signer),
    }
}

fn b_local<'a>(f: &'a Fixture, signer: &'a ScalarSigner) -> LocalCredential<'a> {
    LocalCredential {
        kid: &f.b_kid,
        cred: &f.b_cert,
        key: LocalKey::Signature(signer),
    }
}

/// Resolver of the tests: the kid must be the peer's, the peer's State item
/// must carry the expected bytes, and the peer's MemberCert (presented by
/// value, as in the join profile) must verify under the test SAK and pin
/// the expected claims.
fn resolver(
    kid: [u8; 32],
    cred: Vec<u8>,
    public_key: [u8; 64],
    sak_pub: [u8; 64],
    expect_state: Vec<u8>,
    expect_subject: u64,
    expect_role: u32,
) -> impl FnOnce(&[u8], &[EadItem]) -> Result<PeerCredential, String> {
    move |got, ead| {
        if got != kid {
            return Err("unknown kid".into());
        }
        let carried = ead
            .iter()
            .find(|item| item.absolute_label() == u64::from(EAD_SESSION_STATE.unsigned_abs()))
            .and_then(|item| item.value.clone());
        if carried.as_deref() != Some(&expect_state[..]) {
            return Err("session-state item mismatch".into());
        }
        let (claims, ok) = cert_verify(&cred, &sak_pub).map_err(|e| e.to_string())?;
        if !ok {
            return Err("member cert signature rejected".into());
        }
        if claims.cert_type != CertType::Member
            || claims.issuer != SITE
            || claims.subject != expect_subject
            || claims.role != expect_role
            || claims.site_epoch != SITE_EPOCH
            || claims.network != (u64::from(SITE_EPOCH) << 32) | u64::from(NETWORK_LOW)
        {
            return Err("member cert claims mismatch".into());
        }
        Ok(PeerCredential { cred, public_key })
    }
}

type ExportFn<'a> = dyn Fn(u64, &[u8], usize) -> Vec<u8> + 'a;

fn check_exporters(exporter: &ExportFn<'_>, m: &DirMatter, f: &Fixture) -> [Vec<u8>; 5] {
    let list = checks(m, f);
    std::array::from_fn(|i| exporter(list[i].0, &list[i].1, list[i].2))
}

/// The Rust side of direction `a_` (member B as Responder): takes
/// libedhoc's m1/m3 from `peer`, returns (m2, m4, exporter outputs).
fn rust_responder(
    f: &Fixture,
    d: &Direction,
    m: &DirMatter,
    peer: &mut PeerFn<'_>,
) -> (Vec<u8>, Vec<u8>, [Vec<u8>; 5]) {
    let signer = ScalarSigner(f.b_priv);
    let mut r = Responder::new(Method::SignatureSignature, d.c_r.to_vec()).unwrap();
    let m1 = peer(1, None);
    let got1 = r.process_message_1(&m1).unwrap();
    assert_eq!(got1.c_i, d.c_i);
    assert_eq!(got1.ead, m.ead[0]);
    let intent = SessionIntent::decode(&m.ead[0][0].value.clone().unwrap()).unwrap();
    assert_eq!(intent.purpose, SESSION_PURPOSE_LINK);
    assert_eq!(intent.profile, SESSION_PROFILE_MEMBER);
    assert_eq!(
        intent.caps_i,
        RLD1_CAP_MEMBER_EDHOC_V1 | RLD1_CAP_MEMBER_RESUME_V1
    );
    let m2 = r
        .compose_message_2(d.y, &b_local(f, &signer), &m.ead[1])
        .unwrap();
    let m3 = peer(3, Some(&m2));
    let got3 = r
        .process_message_3(
            &m3,
            resolver(
                f.a_kid,
                f.a_cert.clone(),
                f.a_pub,
                f.sak_pub,
                m.ead[2][0].value.clone().unwrap(),
                MEMBER_A,
                MEMBER_ROLE_ENDPOINT,
            ),
        )
        .unwrap();
    assert_eq!(got3.ead, m.ead[2]);
    // The ContextConfirm we are about to send binds the three Exporter
    // contexts of this direction; recompute the digest here so the
    // transcript cannot pin a stale one.
    let digest = session_contexts_digest(&m.dir1, &m.dir2, &f.rms).unwrap();
    let confirm = ContextConfirm::decode(&m.ead[3][0].value.clone().unwrap()).unwrap();
    assert_eq!(confirm.contexts_digest, digest);
    let m4 = r.compose_message_4(&m.ead[3]).unwrap();
    peer(5, Some(&m4));
    let out = check_exporters(&|l, c, n| r.exporter(l, c, n).unwrap(), m, f);
    (m2, m4, out)
}

/// The Rust side of direction `b_` (member A as Initiator): returns
/// (m1, m3, exporter outputs).
fn rust_initiator(
    f: &Fixture,
    d: &Direction,
    m: &DirMatter,
    peer: &mut PeerFn<'_>,
) -> (Vec<u8>, Vec<u8>, [Vec<u8>; 5]) {
    let signer = ScalarSigner(f.a_priv);
    let mut i = Initiator::new(Method::SignatureSignature, vec![SUITE_2], d.c_i.to_vec()).unwrap();
    let m1 = i.compose_message_1(d.x, &m.ead[0]).unwrap();
    let m2 = peer(2, Some(&m1));
    let got2 = i
        .process_message_2(
            &m2,
            resolver(
                f.b_kid,
                f.b_cert.clone(),
                f.b_pub,
                f.sak_pub,
                m.ead[1][0].value.clone().unwrap(),
                MEMBER_B,
                MEMBER_ROLE_GATEWAY,
            ),
        )
        .unwrap();
    assert_eq!(got2.c_r, d.c_r);
    assert_eq!(got2.ead, m.ead[1]);
    let state = SessionState::decode(&m.ead[1][0].value.clone().unwrap()).unwrap();
    assert_eq!(state.site_epoch, SITE_EPOCH);
    let m3 = i
        .compose_message_3(&a_local(f, &signer), &m.ead[2])
        .unwrap();
    let m4 = peer(4, Some(&m3));
    let ead4 = i.process_message_4(&m4).unwrap();
    assert_eq!(ead4, m.ead[3]);
    let digest = session_contexts_digest(&m.dir1, &m.dir2, &f.rms).unwrap();
    let confirm = ContextConfirm::decode(&ead4[0].value.clone().unwrap()).unwrap();
    assert_eq!(confirm.contexts_digest, digest);
    let out = check_exporters(&|l, c, n| i.exporter(l, c, n).unwrap(), m, f);
    (m1, m3, out)
}

fn check_tag(prefix: &str, i: usize) -> String {
    if i == 0 {
        format!("{prefix}exporter")
    } else {
        format!("{prefix}exporter{}", i + 1)
    }
}

#[test]
fn transcript_replays_byte_for_byte() {
    let f = fixture();
    let file = load_transcript();
    // The recorded inputs are exactly what this fixture derives.
    for (key, value) in inputs_text(&f) {
        assert_eq!(file.get(&key), Some(&value), "transcript input {key}");
    }
    for (prefix, d) in directions() {
        let m = dir_matter(&f, &d);
        let get = |name: &str| unhex(&file[&format!("{prefix}{name}")]);
        let want: [Vec<u8>; 5] = std::array::from_fn(|i| unhex(&file[&check_tag(prefix, i)]));
        if prefix == "a_" {
            // libedhoc Initiator → this crate as Responder.
            let (m2, m4, out) = rust_responder(&f, &d, &m, &mut |n, _| match n {
                1 => get("m1"),
                3 => get("m3"),
                _ => Vec::new(),
            });
            assert_eq!(m2, get("m2"), "a_m2");
            assert_eq!(m4, get("m4"), "a_m4");
            assert_eq!(out, want, "a_exporter");
        } else {
            let (m1, m3, out) = rust_initiator(&f, &d, &m, &mut |n, _| match n {
                2 => get("m2"),
                4 => get("m4"),
                _ => Vec::new(),
            });
            assert_eq!(m1, get("m1"), "b_m1");
            assert_eq!(m3, get("m3"), "b_m3");
            assert_eq!(out, want, "b_exporter");
        }
    }
}

/// One live run of the C++ peer for `prefix`; returns the four messages
/// and the five exporter outputs.
fn live(
    peer_bin: &str,
    inputs_path: &str,
    prefix: &str,
    f: &Fixture,
    d: &Direction,
    m: &DirMatter,
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
    let (first, second, out) = if prefix == "a_" {
        let (m2, m4, out) = rust_responder(f, d, m, &mut peer);
        ((2, m2), (4, m4), out)
    } else {
        let (m1, m3, out) = rust_initiator(f, d, m, &mut peer);
        ((1, m1), (3, m3), out)
    };
    drop(stdin);
    let mut rest = String::new();
    for line in stdout.lines() {
        rest.push_str(&line.unwrap());
        rest.push('\n');
    }
    assert!(child.0.wait().unwrap().success(), "peer failed:\n{rest}");
    for (i, o) in out.iter().enumerate() {
        let tag = if i == 0 {
            "exporter".to_string()
        } else {
            format!("exporter{}", i + 1)
        };
        assert!(rest.contains(&format!("{tag} {}", hex(o))), "{rest}");
    }
    assert!(rest.trim_end().ends_with("ok"), "{rest}");
    messages.insert(format!("{prefix}m{}", first.0), hex(&first.1));
    messages.insert(format!("{prefix}m{}", second.0), hex(&second.1));
    for (i, o) in out.iter().enumerate() {
        messages.insert(check_tag(prefix, i), hex(o));
    }
    messages
}

#[test]
fn live_against_libedhoc() {
    let Ok(peer_bin) = std::env::var("ROUTELOOM_EDHOC_PEER") else {
        eprintln!(
            "ROUTELOOM_EDHOC_PEER not set: live libedhoc run skipped (the transcript replay still ran)"
        );
        return;
    };
    let f = fixture();
    let inputs = inputs_text(&f);
    let dir = std::env::temp_dir().join(format!(
        "routeloom-edhoc-interop-member-{}",
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
        let m = dir_matter(&f, &d);
        all.extend(live(
            &peer_bin,
            inputs_path.to_str().unwrap(),
            prefix,
            &f,
            &d,
            &m,
        ));
    }
    let _ = std::fs::remove_dir_all(&dir);
    let mut text = String::from(
        "# EDHOC method 0 / suite 2 member transcript: libedhoc v2.3.2 (device stack) <-> host/routeloom-edhoc.\n\
         # Session EAD items (Intent/State/Confirm) per design-p4 §5.2/§5.3, five session Exporter outputs per §5.4.\n\
         # Generated by `ROUTELOOM_EDHOC_PEER=<build>/tests/cpp/routeloom_edhoc_interop_peer ROUTELOOM_EDHOC_INTEROP_RECORD=1\n\
         # cargo test -p routeloom-edhoc --test member live_against_libedhoc`. Test keys only. See README.md.\n",
    );
    for (k, v) in &all {
        text.push_str(&format!("{k} = {v}\n"));
    }
    if std::env::var("ROUTELOOM_EDHOC_INTEROP_RECORD").as_deref() == Ok("1") {
        std::fs::write(transcript(), &text).unwrap();
    } else {
        assert_eq!(std::fs::read_to_string(transcript()).unwrap(), text);
    }
}
