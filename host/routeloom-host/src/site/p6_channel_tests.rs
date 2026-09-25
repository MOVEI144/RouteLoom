//! Production P6 channel port acceptance (04 §7.1/§8.5/§9.1, P6-2
//! PR D): sealed RRS1/Notice/Grant delivery over live channel contexts,
//! the 60 s removed-binding retention, the COMMIT grace across a
//! cutover, and verified-report routing — all against real AES-GCM
//! handshakes, with no fake port in the loop.

use std::sync::{Arc, Mutex};

use routeloom_keysched::authority::{
    open_envelope, seal_envelope, BodyHead, ReplayWindow, BODY_HEAD,
};
use routeloom_keysched::rlres1::{Epochs, R1, R2};
use routeloom_keysched::{
    resume_auth_key, resume_binding_routed, resume_confirm_key, resume_id, resume_mac, resume_prk,
    resume_traffic_key, sha256, Direction, Purpose, ResumeKeyContext, TrafficKey, LABEL_RESUME_R1,
    LABEL_RESUME_R2, LABEL_RESUME_R3,
};
use routeloom_protocol::authority::CarrierKind;

use super::authority_channel::{AuthorityOutbound, AuthorityTransport, ChannelMember};
use super::group_keys::HostTime;
use super::p6_channel::{
    decode_type5, P6ChannelHub, P6ChannelTransport, P6Type5, P6_BINDING_GRACE_MS,
};
use super::records::{Verdict, ROLE_ENDPOINT};
use super::store::MemoryStore;
use super::testkit::{self, request_id, Outcome, SimDevice};
use super::transport::InProcessTransport;
use super::{RevokeRequest, SiteService};

const T0: u64 = 1_790_000_000_000;
const KGUARD: u32 = 501;
const MEMBER_A: u64 = 0x00A1_0000_0000_00A1;
const MEMBER_B: u64 = 0x00A1_0000_0000_00B2;

/// Minimal fake device: RLRES1 initiator plus envelope seal/open with
/// real AES-GCM, parameterized by the site it talks to.
struct FakeDevice {
    device: u64,
    network: u64,
    site: u64,
    site_epoch: u32,
    dams: [u8; 32],
    k_auth: [u8; 32],
    binding: [u8; 32],
    nonce_i: [u8; 16],
    cid_i: u32,
    r1_bytes: Vec<u8>,
    rx_key: TrafficKey,
    tx_key: TrafficKey,
    rx_ctx: u32,
    tx_ctx: u32,
    tx_counter: u64,
    next_request: u64,
    rx_window: ReplayWindow,
}

impl FakeDevice {
    fn begin(
        device: u64,
        dams: [u8; 32],
        network: u64,
        site: u64,
        site_epoch: u32,
        cid_i: u32,
        nonce_i: [u8; 16],
    ) -> (Vec<u8>, Self) {
        let k_auth = resume_auth_key(&dams, Purpose::Authority, network, device, site);
        let binding = resume_binding_routed(Purpose::Authority, device, site);
        let mut r1 = R1 {
            purpose: Purpose::Authority,
            rid: resume_id(&dams, Purpose::Authority),
            nonce_i,
            cid_i,
            epochs: Epochs {
                site_epoch,
                rs_epoch: 0,
                gk_epoch: 0,
            },
            ticket: Vec::new(),
            mac: [0; 16],
        };
        r1.mac = resume_mac(&k_auth, LABEL_RESUME_R1, &[&binding, &r1.body()]);
        let r1_bytes = r1.encode();
        (
            r1_bytes.clone(),
            Self {
                device,
                network,
                site,
                site_epoch,
                dams,
                k_auth,
                binding,
                nonce_i,
                cid_i,
                r1_bytes,
                rx_key: TrafficKey {
                    key: [0; 16],
                    iv: [0; 12],
                },
                tx_key: TrafficKey {
                    key: [0; 16],
                    iv: [0; 12],
                },
                rx_ctx: 0,
                tx_ctx: 0,
                tx_counter: 0,
                next_request: 1,
                rx_window: ReplayWindow::new(),
            },
        )
    }

    fn on_r2(&mut self, r2_bytes: &[u8]) -> Vec<u8> {
        let R2::Ok {
            nonce_r,
            cid_r,
            epochs,
            mac,
        } = R2::decode(r2_bytes).expect("R2 ok")
        else {
            panic!("expected R2 ok");
        };
        assert_eq!(epochs.site_epoch, self.site_epoch);
        let body = R2::ok_body(&nonce_r, cid_r, &epochs);
        // Rebuild the exact R2 bytes the host sealed the MAC over.
        let mut full = body.clone();
        full.extend_from_slice(&mac);
        let expect = resume_mac(
            &self.k_auth,
            LABEL_RESUME_R2,
            &[&self.binding, &self.r1_bytes, &body],
        );
        assert!(routeloom_keysched::authority::mac_equal(&expect, &mac));
        let context = ResumeKeyContext {
            purpose: Purpose::Authority,
            network: self.network,
            node_i: self.device,
            node_r: self.site,
            cid_i: self.cid_i,
            cid_r,
        };
        let th = sha256(&[&self.r1_bytes, &full]);
        let prk = resume_prk(&self.nonce_i, &nonce_r, &self.dams);
        let k_conf = resume_confirm_key(&prk, &th);
        self.tx_key = resume_traffic_key(&prk, &context, Direction::InitiatorToResponder, &th);
        self.rx_key = resume_traffic_key(&prk, &context, Direction::ResponderToInitiator, &th);
        self.rx_ctx = self.cid_i;
        self.tx_ctx = cid_r;
        resume_mac(&k_conf, LABEL_RESUME_R3, &[&th]).to_vec()
    }

    fn seal(&mut self, env_type: u8, plaintext: &[u8]) -> Vec<u8> {
        let envelope = seal_envelope(
            &self.tx_key,
            env_type,
            self.tx_ctx,
            self.tx_counter,
            plaintext,
        )
        .expect("seal");
        self.tx_counter += 1;
        envelope
    }

    fn open(&mut self, envelope: &[u8]) -> (u8, Vec<u8>) {
        let (header, plaintext) = open_envelope(&self.rx_key, envelope, self.rx_ctx).expect("open");
        assert!(self.rx_window.accept(header.counter));
        (header.env_type, plaintext)
    }

    fn head(&mut self, generation: u32) -> [u8; BODY_HEAD] {
        let head = BodyHead {
            op: 2,
            generation,
            request_id: self.next_request,
        }
        .encode(2)
        .expect("head");
        self.next_request += 1;
        head
    }
}

fn test_dams(seed: u8) -> [u8; 32] {
    let mut dams = [0_u8; 32];
    for (i, b) in dams.iter_mut().enumerate() {
        *b = seed.wrapping_add(i as u8);
    }
    dams
}

fn hub_with(dams: [u8; 32]) -> (P6ChannelHub, ChannelMember) {
    let member = ChannelMember {
        member: true,
        kid: [0x11; 32],
        generation: 9,
        dams,
        network: testkit::network(),
    };
    let hub = P6ChannelHub::new(
        testkit::network(),
        testkit::SITE,
        testkit::SITE_EPOCH,
        4,
        12,
    );
    (hub, member)
}

fn handshake(hub: &mut P6ChannelHub, member: &ChannelMember, at: u64) -> FakeDevice {
    hub.refresh(&[(MEMBER_A, member.clone())], testkit::network(), 4, 12, at);
    let (r1, mut device) = FakeDevice::begin(
        MEMBER_A,
        member.dams,
        testkit::network(),
        testkit::SITE,
        testkit::SITE_EPOCH,
        0xA001,
        [0x11; 16],
    );
    hub.push_carrier(MEMBER_A, CarrierKind::R1, &r1, at);
    let r2 = hub.take_carriers();
    assert_eq!(r2.len(), 1);
    assert_eq!(r2[0].kind, CarrierKind::R2);
    let r3 = device.on_r2(&r2[0].bytes);
    hub.push_carrier(MEMBER_A, CarrierKind::R3, &r3, at);
    // The ChannelReady waits for the P5 pump, not the P6 receipts.
    assert!(hub.poll_receipts().is_empty());
    assert_eq!(hub.poll_other().len(), 1);
    device
}

fn open_headless(device: &mut FakeDevice, carrier: &AuthorityOutbound) -> (u8, u32, Vec<u8>) {
    assert_eq!(carrier.kind, CarrierKind::Envelope);
    let (env_type, plaintext) = device.open(&carrier.bytes);
    assert!(plaintext.len() > BODY_HEAD);
    let head = BodyHead::decode(&plaintext[..BODY_HEAD], plaintext[1]).expect("head");
    (env_type, head.generation, plaintext[BODY_HEAD..].to_vec())
}

#[test]
fn seals_rrs_behind_the_generation_head() {
    let (mut hub, member) = hub_with(test_dams(0xD0));
    let mut device = handshake(&mut hub, &member, 1000);
    let object = vec![0x52, 0x53, 0x31];
    assert!(hub.send_rrs(MEMBER_A, &object, 1000));
    let carriers = hub.take_carriers();
    assert_eq!(carriers.len(), 1);
    let (env_type, generation, tail) = open_headless(&mut device, &carriers[0]);
    assert_eq!(env_type, 5);
    assert_eq!(generation, 9);
    assert_eq!(tail, object);
}

#[test]
fn refuses_send_without_a_channel() {
    let (mut hub, member) = hub_with(test_dams(0xD0));
    hub.refresh(&[(MEMBER_A, member)], testkit::network(), 4, 12, 1000);
    // Live binding, but no handshake ran: nothing seals.
    assert!(!hub.send_rrs(MEMBER_A, &[1, 2, 3], 1000));
    assert!(hub.take_carriers().is_empty());
}

#[test]
fn stale_dams_refuses_and_retires() {
    let (mut hub, member) = hub_with(test_dams(0xD0));
    let _device = handshake(&mut hub, &member, 1000);
    assert!(hub.send_rrs(MEMBER_A, &[1], 1000));
    assert_eq!(hub.take_carriers().len(), 1);
    // The member reissued: the same node under fresh DAMS.
    let mut fresh = member.clone();
    fresh.dams = test_dams(0xE0);
    hub.refresh(&[(MEMBER_A, fresh)], testkit::network(), 4, 12, 2000);
    assert!(!hub.send_rrs(MEMBER_A, &[2], 2000));
    assert!(hub.take_carriers().is_empty());
}

#[test]
fn notice_survives_removal_for_60s() {
    let (mut hub, member) = hub_with(test_dams(0xD0));
    let mut device = handshake(&mut hub, &member, 1000);
    // The row disappears (revoke committed): retention keeps the removed
    // binding for the best-effort window.
    hub.refresh(&[], testkit::network(), 4, 12, 2000);
    let notice = vec![0x4E; 103];
    assert!(hub.notice_sealable(MEMBER_A, testkit::network(), 2000));
    assert!(hub.send_notice(MEMBER_A, testkit::network(), &notice, 2000));
    let carriers = hub.take_carriers();
    assert_eq!(carriers.len(), 1);
    let (env_type, generation, tail) = open_headless(&mut device, &carriers[0]);
    assert_eq!(env_type, 6);
    assert_eq!(generation, 9);
    assert_eq!(tail, notice);
    // Past the window the binding is gone: RRS and notice both refuse,
    // and the distributor learns to mark `unreachable`.
    hub.refresh(&[], testkit::network(), 4, 12, 2000 + P6_BINDING_GRACE_MS);
    assert!(!hub.send_notice(
        MEMBER_A,
        testkit::network(),
        &notice,
        2000 + P6_BINDING_GRACE_MS
    ));
    assert!(!hub.send_rrs(MEMBER_A, &[1], 2000 + P6_BINDING_GRACE_MS));
    assert!(!hub.notice_sealable(MEMBER_A, testkit::network(), 2000 + P6_BINDING_GRACE_MS));
}

#[test]
fn cutover_grace_serves_commit_then_flips() {
    let (mut hub, member) = hub_with(test_dams(0xD0));
    let mut device = handshake(&mut hub, &member, 1000);
    let old = testkit::network();
    let new = (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW);
    hub.note_cutover(old, 5000);
    // New rows carry new DAMS, but the table still serves the old
    // network inside the grace: only the COMMIT seals.
    let mut staged = member.clone();
    staged.dams = test_dams(0xE0);
    staged.network = new;
    hub.refresh(&[(MEMBER_A, staged)], new, 7, 13, 6000);
    assert_eq!(hub.network(), old);
    assert!(hub.send_grant(MEMBER_A, old, &[0xC0], 6000));
    assert!(!hub.send_rrs(MEMBER_A, &[1], 6000));
    let carriers = hub.take_carriers();
    assert_eq!(carriers.len(), 1);
    let (env_type, _, tail) = open_headless(&mut device, &carriers[0]);
    assert_eq!(env_type, 7);
    assert_eq!(tail, vec![0xC0]);
    // Past the grace the table flips: old COMMITs refuse, stragglers
    // recover over ZT instead of sealing under a retired context.
    hub.refresh(
        &[(MEMBER_A, member.clone())],
        new,
        7,
        13,
        5000 + P6_BINDING_GRACE_MS,
    );
    assert_eq!(hub.network(), new);
    assert!(!hub.send_grant(MEMBER_A, old, &[0xC0], 5000 + P6_BINDING_GRACE_MS));
}

#[test]
fn new_handshake_waits_out_the_grace() {
    let (mut hub, member) = hub_with(test_dams(0xD0));
    let _device = handshake(&mut hub, &member, 1000);
    let old = testkit::network();
    let new = (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW);
    hub.note_cutover(old, 5000);
    let mut staged = member.clone();
    staged.dams = test_dams(0xE0);
    staged.network = new;
    hub.refresh(&[(MEMBER_A, staged.clone())], new, 7, 13, 6000);
    // An R1 under the new DAMS is answered with a hint, not a channel.
    let (r1, _) = FakeDevice::begin(
        MEMBER_A,
        staged.dams,
        new,
        testkit::SITE,
        testkit::SITE_EPOCH + 1,
        0xB002,
        [0x22; 16],
    );
    hub.push_carrier(MEMBER_A, CarrierKind::R1, &r1, 6000);
    let out = hub.take_carriers();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].kind, CarrierKind::R2);
    assert!(hub.poll_other().is_empty());
    // After the flip the same R1 completes a new-network channel.
    hub.refresh(
        &[(MEMBER_A, staged)],
        new,
        7,
        13,
        5000 + P6_BINDING_GRACE_MS,
    );
    let (r1, mut device) = FakeDevice::begin(
        MEMBER_A,
        test_dams(0xE0),
        new,
        testkit::SITE,
        testkit::SITE_EPOCH + 1,
        0xB003,
        [0x33; 16],
    );
    hub.push_carrier(MEMBER_A, CarrierKind::R1, &r1, 5000 + P6_BINDING_GRACE_MS);
    let out = hub.take_carriers();
    assert_eq!(out.len(), 1);
    let r3 = device.on_r2(&out[0].bytes);
    hub.push_carrier(MEMBER_A, CarrierKind::R3, &r3, 5000 + P6_BINDING_GRACE_MS);
    assert!(hub.send_rrs(MEMBER_A, &[9], 5000 + P6_BINDING_GRACE_MS));
}

#[test]
fn decode_type5_accepts_exact_bodies_only() {
    let mut applied = vec![1u8, 1, 0, 0, 0, 0, 0, 31];
    applied.extend_from_slice(&[0xA5; 32]);
    assert_eq!(
        decode_type5(&applied),
        Some(P6Type5::Applied {
            rs_epoch: 31,
            sha: [0xA5; 32]
        })
    );
    assert_eq!(
        decode_type5(&[1, 2, 0, 0, 0, 0, 0, 0]),
        Some(P6Type5::Get { wanted_rs_epoch: 0 })
    );
    let mut accept = vec![1u8, 3, 0, 0, 0, 0, 0, 7];
    accept.extend_from_slice(&[0x5A; 32]);
    assert_eq!(
        decode_type5(&accept),
        Some(P6Type5::NoticeAccepted {
            rs_epoch: 7,
            sha: [0x5A; 32]
        })
    );
    // Malformed: bad version, nonzero reserved, wrong length, bad sub.
    assert_eq!(decode_type5(&[2, 2, 0, 0, 0, 0, 0, 0]), None);
    assert_eq!(decode_type5(&[1, 2, 0, 1, 0, 0, 0, 0]), None);
    assert_eq!(decode_type5(&[1, 2, 0, 0, 0, 0, 0]), None);
    assert_eq!(decode_type5(&[1, 9, 0, 0, 0, 0, 0, 0]), None);
    let mut long = applied.clone();
    long.push(0);
    assert_eq!(decode_type5(&long), None);
    assert_eq!(decode_type5(&[]), None);
}

// --- Authority integration: the real port, the real sinks -----------------

#[derive(Default)]
struct RecordSink {
    inner: Mutex<Vec<AuthorityOutbound>>,
}

impl RecordSink {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn take(&self) -> Vec<AuthorityOutbound> {
        std::mem::take(&mut *self.inner.lock().unwrap())
    }
}

impl AuthorityTransport for RecordSink {
    fn deliver(&self, outbound: AuthorityOutbound) {
        self.inner.lock().unwrap().push(outbound);
    }
}

fn service_with_port() -> (SiteService, Arc<InProcessTransport>, Arc<RecordSink>) {
    let service = SiteService::new(testkit::authority(Box::new(MemoryStore::default()), T0));
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    let hub = Arc::new(Mutex::new(P6ChannelHub::new(
        testkit::network(),
        testkit::SITE,
        testkit::SITE_EPOCH,
        0,
        1,
    )));
    service.with(|a| a.set_rrs_transport(Some(Box::new(P6ChannelTransport::share(&hub)))));
    let sink = RecordSink::new();
    service.set_authority_sink(sink.clone());
    (service, transport, sink)
}

fn join_member(
    service: &SiteService,
    transport: &Arc<InProcessTransport>,
    device: &mut SimDevice,
    key: &str,
    at: u64,
) {
    let (mut exchange, _, events) = device.start(service, transport, at);
    let (answer, _) = service.with(|a| {
        a.decide(
            KGUARD,
            super::DecideRequest {
                join_request_id: request_id(&events).unwrap(),
                device: device.node,
                verdict: Verdict::Allow {
                    role: ROLE_ENDPOINT,
                },
                key: key.into(),
            },
            at + 10,
        )
    });
    answer.unwrap();
    assert!(matches!(
        device.finish(&mut exchange, transport),
        Outcome::Result(routeloom_join::JoinResult::Allow { .. })
    ));
}

fn row_dams(service: &SiteService, node: u64) -> [u8; 32] {
    service.with(|a| a.devices.get(&node).unwrap().dams).0
}

fn row_generation(service: &SiteService, node: u64) -> u32 {
    service.with(|a| a.devices.get(&node).unwrap().generation).0
}

/// Handshakes `node`'s channel through the service carriers, returning
/// the device side. Every carrier crosses `handle_carrier` / the sink.
fn handshake_node(service: &SiteService, sink: &Arc<RecordSink>, node: u64, at: u64) -> FakeDevice {
    service.with(|a| a.tick(HostTime::sync(at)));
    let _ = sink.take();
    let (r1, mut device) = FakeDevice::begin(
        node,
        row_dams(service, node),
        testkit::network(),
        testkit::SITE,
        testkit::SITE_EPOCH,
        0xC001,
        [0x44; 16],
    );
    service.handle_carrier(node, CarrierKind::R1, &r1, HostTime::sync(at));
    let out = sink.take();
    assert_eq!(out.len(), 1);
    let r3 = device.on_r2(&out[0].bytes);
    service.handle_carrier(node, CarrierKind::R3, &r3, HostTime::sync(at));
    assert!(sink.take().is_empty());
    device
}

fn revoke(service: &SiteService, node: u64, key: &str, at: u64) -> u64 {
    let generation = service.with(|a| a.devices.get(&node).unwrap().generation).0;
    let (answer, _) = service.with(|a| {
        a.revoke(
            KGUARD,
            RevokeRequest {
                device: node,
                expected_generation: generation,
                reason: routeloom_provision::sdkv1::revocation::RevocationReason::Removed,
                key: key.into(),
            },
            HostTime::sync(at),
        )
    });
    let view = routeloom_json::parse(&answer.unwrap()).expect("JSON");
    super::records::parse_op_token(view.get("operation_id").unwrap().as_str().unwrap()).unwrap()
}

fn applied_body(rs_epoch: u32, sha: &[u8; 32]) -> Vec<u8> {
    let mut body = vec![1u8, 1, 0, 0];
    body.extend_from_slice(&rs_epoch.to_be_bytes());
    body.extend_from_slice(sha);
    body
}

#[test]
fn applied_over_the_wire_converges() {
    let (service, transport, sink) = service_with_port();
    let mut device_a = SimDevice::new(MEMBER_A, 0xA1);
    let mut device_b = SimDevice::new(MEMBER_B, 0xB2);
    join_member(&service, &transport, &mut device_a, "a", T0);
    join_member(&service, &transport, &mut device_b, "b", T0 + 1000);
    assert_eq!(service.with(|a| a.p6_distribution_status()).0, "rrs_ready");

    let mut chan_b = handshake_node(&service, &sink, MEMBER_B, T0 + 2000);
    let op = revoke(&service, MEMBER_A, "revoke-a", T0 + 3000);
    // MEMBER_A never handshook: the direct notice is unreachable, while
    // the RRS1 fan-out to the survivor still seals.
    service.with(|a| a.tick(HostTime::sync(T0 + 3000)));
    let view = service
        .with(|a| a.operation_json(op, HostTime::sync(T0 + 3000)).unwrap())
        .0;
    let json = routeloom_json::parse(&view).expect("JSON");
    assert_eq!(
        json.get("notice")
            .unwrap()
            .get("delivery")
            .unwrap()
            .as_str()
            .unwrap(),
        "unreachable"
    );
    let out = sink.take();
    assert_eq!(out.len(), 1);
    assert_eq!(out[0].device, MEMBER_B);
    let (env_type, generation, tail) = open_headless(&mut chan_b, &out[0]);
    assert_eq!(env_type, 5);
    assert_eq!(generation, row_generation(&service, MEMBER_B));

    // The survivor applies and reports; the report is head-wrapped on
    // the wire and stripped before the sink fences it.
    let sha = routeloom_provision::sha256::sha256(&tail);
    let mut report = chan_b.head(row_generation(&service, MEMBER_B)).to_vec();
    report.extend_from_slice(&applied_body(1, &sha));
    service.handle_carrier(
        MEMBER_B,
        CarrierKind::Envelope,
        &chan_b.seal(5, &report),
        HostTime::sync(T0 + 4000),
    );
    let view = service
        .with(|a| a.operation_json(op, HostTime::sync(T0 + 4000)).unwrap())
        .0;
    let json = routeloom_json::parse(&view).expect("JSON");
    let dist = json.get("distribution").unwrap();
    assert_eq!(dist.get("state").unwrap().as_str().unwrap(), "converged");
    assert_eq!(dist.get("applied").unwrap().as_u64().unwrap(), 1);
    assert_eq!(dist.get("unknown").unwrap().as_u64().unwrap(), 0);
}

#[test]
fn notice_round_trip_confirms_intent() {
    let (service, transport, sink) = service_with_port();
    let mut device_a = SimDevice::new(MEMBER_A, 0xA1);
    let mut device_b = SimDevice::new(MEMBER_B, 0xB2);
    join_member(&service, &transport, &mut device_a, "a", T0);
    join_member(&service, &transport, &mut device_b, "b", T0 + 1000);

    // The removal target holds a channel when the revoke commits.
    let mut chan_a = handshake_node(&service, &sink, MEMBER_A, T0 + 2000);
    let generation_a = row_generation(&service, MEMBER_A);
    let op = revoke(&service, MEMBER_A, "revoke-a", T0 + 3000);
    service.with(|a| a.tick(HostTime::sync(T0 + 3000)));
    let out = sink.take();
    // The notice goes first, ahead of the RRS1 fan-out.
    assert!(!out.is_empty());
    assert_eq!(out[0].device, MEMBER_A);
    let (env_type, generation, tail) = open_headless(&mut chan_a, &out[0]);
    assert_eq!(env_type, 6);
    assert_eq!(generation, generation_a);
    assert_eq!(tail.len(), 103);

    let sha = routeloom_provision::sha256::sha256(&tail);
    let mut body = vec![1u8, 3, 0, 0];
    body.extend_from_slice(&1u32.to_be_bytes());
    body.extend_from_slice(&sha);
    let mut report = chan_a.head(generation_a).to_vec();
    report.extend_from_slice(&body);
    service.handle_carrier(
        MEMBER_A,
        CarrierKind::Envelope,
        &chan_a.seal(5, &report),
        HostTime::sync(T0 + 4000),
    );
    let view = service
        .with(|a| a.operation_json(op, HostTime::sync(T0 + 4000)).unwrap())
        .0;
    let json = routeloom_json::parse(&view).expect("JSON");
    let notice = json.get("notice").unwrap();
    assert_eq!(notice.get("delivery").unwrap().as_str().unwrap(), "sent");
    assert!(notice.get("intent_confirmed").unwrap().as_bool().unwrap());
}

#[test]
fn get_bootstraps_the_baseline_and_answers() {
    let (service, transport, sink) = service_with_port();
    let mut device_b = SimDevice::new(MEMBER_B, 0xB2);
    join_member(&service, &transport, &mut device_b, "b", T0);
    let mut chan = handshake_node(&service, &sink, MEMBER_B, T0 + 1000);

    // A site that never revoked bootstraps the empty set at epoch 1.
    let generation = row_generation(&service, MEMBER_B);
    let mut report = chan.head(generation).to_vec();
    report.extend_from_slice(&[1u8, 2, 0, 0, 0, 0, 0, 0]);
    service.handle_carrier(
        MEMBER_B,
        CarrierKind::Envelope,
        &chan.seal(5, &report),
        HostTime::sync(T0 + 2000),
    );
    let out = sink.take();
    assert_eq!(out.len(), 1);
    let (env_type, _, tail) = open_headless(&mut chan, &out[0]);
    assert_eq!(env_type, 5);
    let set =
        routeloom_provision::sdkv1::revocation::revocation_object_decode(&tail).expect("RRS1");
    assert_eq!(set.rs_epoch, 1);
    assert!(set.entries.is_empty());
    // An immediate second Get is dropped by the spam gap, not answered.
    let mut report = chan.head(generation).to_vec();
    report.extend_from_slice(&[1u8, 2, 0, 0, 0, 0, 0, 0]);
    service.handle_carrier(
        MEMBER_B,
        CarrierKind::Envelope,
        &chan.seal(5, &report),
        HostTime::sync(T0 + 2000),
    );
    assert!(sink.take().is_empty());
    assert_eq!(service.with(|a| a.rs_epoch).0, 1);
}

#[test]
fn malformed_reports_drop_without_state_change() {
    let (service, transport, sink) = service_with_port();
    let mut device_b = SimDevice::new(MEMBER_B, 0xB2);
    join_member(&service, &transport, &mut device_b, "b", T0);
    let mut chan = handshake_node(&service, &sink, MEMBER_B, T0 + 1000);
    let generation = row_generation(&service, MEMBER_B);
    // Well-AEAD'd but garbage P6 bodies: dropped, no baseline commit.
    for tail in [&[9u8, 9, 9][..], &[1u8, 1, 0, 0, 0][..]] {
        let mut report = chan.head(generation).to_vec();
        report.extend_from_slice(tail);
        service.handle_carrier(
            MEMBER_B,
            CarrierKind::Envelope,
            &chan.seal(5, &report),
            HostTime::sync(T0 + 2000),
        );
    }
    assert!(sink.take().is_empty());
    assert_eq!(service.with(|a| a.rs_epoch).0, 0);
}

#[test]
fn capabilities_track_the_production_port() {
    let (service, _, _) = service_with_port();
    assert_eq!(service.with(|a| a.p6_distribution_status()).0, "rrs_ready");
    service.with(|a| a.set_rrs_transport(None));
    assert_eq!(
        service.with(|a| a.p6_distribution_status()).0,
        "rrs_no_transport"
    );
}
