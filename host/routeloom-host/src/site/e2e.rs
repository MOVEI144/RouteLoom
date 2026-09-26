//! End to end through the daemon (plan P3-3 acceptance): the real API1
//! socket (`serve_client`, peer-credential principal, ACL), the Site
//! Authority on a SQLite store, KGuard as `routeloom_client::site::
//! KGuardMock` driving the `SiteAdmin` facade over the socket, and a
//! simulated device (Rust EDHOC Initiator + routeloom-join device checks)
//! on the in-process join transport.
//!
//! discovered → pending → KGuard assigns → Allow verified by
//! `join_allow_verify`; deny not_here; removal with a verified
//! RemovalNotice; the event stream; the ACL (V1-H06); idempotency (V1-H03).
//! G-SEC P5 adds the `group_keys.*` API over the same socket (status,
//! rotate, ACL, events).

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::MetadataExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::atomic::AtomicU64;
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use routeloom_client::api1::RouteLoomTransport;
use routeloom_client::site::{Assignment, Decision, KGuardMock, RemovalReason, Role, SiteAdmin};
use routeloom_client::TransportError;
use routeloom_join::JoinResult;

use super::store::SqliteSiteStore;
use super::testkit::{self, Outcome, SimDevice};
use super::transport::InProcessTransport;
use super::SiteService;
use crate::acl::Acl;
use crate::{now_ms, push_event, serve_client, DeviceSession, State};

struct Daemon {
    state: Arc<State>,
    service: Arc<SiteService>,
    transport: Arc<InProcessTransport>,
    socket: std::path::PathBuf,
    dir: std::path::PathBuf,
    _outbound: mpsc::Receiver<crate::Outbound>,
}

impl Daemon {
    fn start(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-site-e2e-{tag}-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // This process's uid is the socket principal; grant it the three
        // membership permissions on the site network only.
        let uid = std::fs::metadata(&dir).unwrap().uid();
        let acl = Acl::parse(&format!(
            "{{\"principals\":{{\"{uid}\":{{\"networks\":{{\"{:016x}\":[\"MEMBERSHIP_READ\",\"MEMBERSHIP_DECIDE\",\"MEMBERSHIP_ADMIN\"]}}}},\"7\":{{\"networks\":{{\"*\":[\"MEMBERSHIP_READ\"]}}}}}}}}",
            testkit::NETWORK_LOW
        ))
        .unwrap();
        let store = SqliteSiteStore::open(&dir.join("site.db")).unwrap();
        let service = Arc::new(SiteService::new(testkit::authority(
            Box::new(store),
            now_ms(),
        )));
        let transport = InProcessTransport::new();
        service.set_transport(transport.clone());
        let state = Arc::new(State {
            acl,
            site: Some(Arc::clone(&service)),
            ..State::default()
        });
        let socket = dir.join("api.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let (outbound_tx, outbound_rx) = mpsc::sync_channel(64);
        let accept_state = Arc::clone(&state);
        thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(stream) = stream else { return };
                let uid = routeloom_peercred::peer_uid(&stream).ok();
                let state = Arc::clone(&accept_state);
                let outbound = outbound_tx.clone();
                thread::spawn(move || {
                    let _ = serve_client(
                        stream,
                        state,
                        outbound,
                        0,
                        Arc::new(AtomicU64::new(1)),
                        Arc::new(AtomicU64::new(1)),
                        Arc::new(Mutex::new(DeviceSession::new())),
                        uid,
                    );
                });
            }
        });
        Self {
            state,
            service,
            transport,
            socket,
            dir,
            _outbound: outbound_rx,
        }
    }

    /// The daemon's relay lane: authority events go to the ring.
    fn ring(&self, events: super::Events) {
        for (ms, fields) in events {
            push_event(&self.state, ms, fields);
        }
    }

    fn start_join(&self, device: &mut SimDevice, now: u64) -> (testkit::Exchange, Outcome) {
        let (exchange, outcome, events) = device.start(&self.service, &self.transport, now);
        self.ring(events);
        (exchange, outcome)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn raw_api1(state: &Arc<State>, uid: u32, line: &str) -> String {
    let (client, server) = UnixStream::pair().unwrap();
    let (tx, _rx) = mpsc::sync_channel(4);
    let state = Arc::clone(state);
    thread::spawn(move || {
        let _ = serve_client(
            server,
            state,
            tx,
            0,
            Arc::new(AtomicU64::new(1)),
            Arc::new(AtomicU64::new(1)),
            Arc::new(Mutex::new(DeviceSession::new())),
            Some(uid),
        );
    });
    let mut writer = client.try_clone().unwrap();
    writer.write_all(line.as_bytes()).unwrap();
    writer.write_all(b"\n").unwrap();
    let mut reader = BufReader::new(client);
    let mut response = String::new();
    reader.read_line(&mut response).unwrap();
    response
}

#[test]
fn kguard_drives_the_join_over_the_api_socket() {
    let daemon = Daemon::start("kguard");
    let kguard_link = RouteLoomTransport::new(&daemon.socket, u64::from(testkit::NETWORK_LOW));
    let mut kguard = KGuardMock::default();
    kguard.pending_retry_s = 30;

    // KGuard watches the site events (join.request etc.) as they happen.
    let stream = kguard_link.site_events().unwrap();
    let (event_tx, event_rx) = mpsc::channel();
    thread::spawn(move || {
        for event in stream {
            if event_tx.send(event).is_err() {
                return;
            }
        }
    });
    let next_event = |kind: &str| loop {
        let event = event_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("no {kind} event"))
            .unwrap();
        if event.kind == kind {
            return event;
        }
    };

    let status = kguard_link.site_status().unwrap();
    assert_eq!(status.site_id, testkit::SITE);
    assert_eq!(status.network, testkit::network());
    assert!(status.storage_durable);
    assert_eq!(status.members, 0);

    // 1. A new, unassigned device: discovered, KGuard answers pending.
    let t0 = now_ms();
    let mut device = SimDevice::new(0x00A1_0000_0000_1234, 0x71);
    let (mut exchange, outcome) = daemon.start_join(&mut device, t0);
    assert!(matches!(outcome, Outcome::Waiting));
    let announced = next_event("join.request");
    assert_eq!(announced.device, Some(device.node));
    let decided = kguard.serve_once(&kguard_link).unwrap();
    assert_eq!(decided.len(), 1);
    assert_eq!(decided[0].1, Decision::Pending { retry_after_s: 30 });
    assert_eq!(decided[0].2.applied, "current_attempt");
    let Outcome::Result(JoinResult::PendingAssignment {
        retry_after_s: 30, ..
    }) = device.finish(&mut exchange, &daemon.transport)
    else {
        panic!("expected PendingAssignment");
    };
    let discovered = kguard_link.discovered().unwrap();
    assert_eq!(discovered.len(), 1);
    assert_eq!(discovered[0].device, device.node);
    assert_eq!(discovered[0].last_verdict, "pending");
    assert_eq!(discovered[0].model, 17);

    // 2. The operator assigns it here; the device's next attempt is allowed
    //    and the Allow passes the device-side 02 §10.2 check (in the kit).
    kguard.assign(device.node, Assignment::Here(Role::Endpoint));
    let (mut exchange, outcome) = daemon.start_join(&mut device, t0 + 31_000);
    assert!(matches!(outcome, Outcome::Waiting));
    next_event("join.request");
    let decided = kguard.serve_once(&kguard_link).unwrap();
    assert_eq!(decided[0].1, Decision::Allow(Role::Endpoint));
    let outcome = &decided[0].2;
    assert_eq!(outcome.state, "committed");
    assert_eq!(outcome.generation, Some(1));
    let Outcome::Result(JoinResult::Allow { .. }) = device.finish(&mut exchange, &daemon.transport)
    else {
        panic!("expected Allow");
    };
    assert_eq!(
        device.site.as_ref().unwrap().member.assignment_generation,
        1
    );
    let member = kguard_link.member(device.node).unwrap().unwrap();
    assert!(member.member && member.delivered);
    assert_eq!(member.generation, 1);
    assert_eq!(member.confirm_state.as_deref(), Some("allowed_unconfirmed"));
    assert_eq!(kguard_link.members().unwrap().len(), 1);
    // The same decision replayed with the same key is the same answer
    // (V1-H03) — the request is closed now, so a new key is NOT_FOUND.
    let replay = kguard_link
        .decide(
            &decided[0].0,
            Decision::Allow(Role::Endpoint),
            &format!("kgmock-{}-{}", decided[0].0.id, decided[0].0.attempt),
        )
        .unwrap();
    assert_eq!(replay.generation, Some(1));
    assert!(matches!(
        kguard_link.decide(&decided[0].0, Decision::DenyBlocked, "another"),
        Err(TransportError::Rejected { ref code, .. }) if code == "NOT_FOUND"
    ));

    // 3. A device assigned to another site: deny not_here.
    let mut stranger = SimDevice::new(0x00A1_0000_0000_5678, 0x72);
    kguard.assign(stranger.node, Assignment::Elsewhere);
    let (mut exchange, outcome) = daemon.start_join(&mut stranger, t0 + 32_000);
    assert!(matches!(outcome, Outcome::Waiting));
    kguard.serve_once(&kguard_link).unwrap();
    assert!(matches!(
        stranger.finish(&mut exchange, &daemon.transport),
        Outcome::Result(JoinResult::DenyNotHere)
    ));

    // 4. V1-H06: a read-only principal can list but not decide or remove.
    let read_only = raw_api1(
        &daemon.state,
        7,
        "API1 {\"v\":1,\"request_id\":\"r\",\"method\":\"members.list\",\"params\":{}}",
    );
    assert!(read_only.contains("\"ok\":true"), "{read_only}");
    let denied = raw_api1(
        &daemon.state,
        7,
        &format!(
            "API1 {{\"v\":1,\"request_id\":\"d\",\"method\":\"membership.revoke\",\"params\":{{\"device_id\":\"{:016x}\",\"expected_generation\":1,\"reason\":\"lost\",\"idempotency_key\":\"x\"}}}}",
            device.node
        ),
    );
    assert!(denied.contains("AuthorizationFailed"), "{denied}");
    let stranger_uid = raw_api1(
        &daemon.state,
        8,
        "API1 {\"v\":1,\"request_id\":\"s\",\"method\":\"site.status\",\"params\":{}}",
    );
    assert!(
        stranger_uid.contains("AuthorizationFailed"),
        "{stranger_uid}"
    );

    // 5. Removal: a stale screen (wrong generation) is refused; the real
    //    removal commits a new revocation set.
    assert!(matches!(
        kguard_link.revoke(device.node, 2, RemovalReason::Lost, "rm-0"),
        Err(TransportError::Rejected { ref code, .. }) if code == "CONFLICT"
    ));
    let removed = kguard_link
        .revoke(device.node, 1, RemovalReason::Lost, "rm-1")
        .unwrap();
    assert_eq!(removed.state, "committed");
    assert_eq!(removed.rs_epoch, 1);
    next_event("member.revoked");
    next_event("rrs.published");
    let op = kguard_link
        .call(
            "operations.get",
            &format!("{{\"operation_id\":\"{}\"}}", removed.operation_id),
        )
        .unwrap();
    assert_eq!(
        op.get("kind").and_then(routeloom_json::Json::as_str),
        Some("revoke")
    );
    // The device still holds the site state: Removed + a RemovalNotice it
    // verifies under the SAK, then it erases (04 §6).
    let (mut exchange, outcome) = daemon.start_join(&mut device, t0 + 60_000);
    let outcome = match outcome {
        Outcome::Waiting => device.finish(&mut exchange, &daemon.transport),
        other => other,
    };
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::Removed { .. })),
        "{outcome:?}"
    );
    assert!(device.site.is_none());
    let member = kguard_link.member(device.node).unwrap().unwrap();
    assert!(!member.member);
    assert_eq!(member.removal_reason.as_deref(), Some("lost"));
    let status = kguard_link.site_status().unwrap();
    assert_eq!((status.members, status.removed, status.rs_epoch), (0, 1, 1));
}

#[test]
fn api_surface_validates_and_advertises() {
    let daemon = Daemon::start("api");
    let uid = std::fs::metadata(&daemon.dir).unwrap().uid();
    let call = |method: &str, params: &str| {
        raw_api1(
            &daemon.state,
            uid,
            &format!(
                "API1 {{\"v\":1,\"request_id\":\"t\",\"method\":\"{method}\",\"params\":{params}}}"
            ),
        )
    };
    let caps = call("capabilities.get", "{}");
    assert!(caps.contains("\"join.decide\":true"), "{caps}");
    assert!(caps.contains("\"site\":{\"configured\":true"), "{caps}");
    assert!(caps.contains("\"join_relay\":\"not_ready\""), "{caps}");
    routeloom_json::parse(caps.trim_end()).unwrap();
    // Policy: admin read/write, validated ranges.
    let policy = call(
        "join.policy.set",
        "{\"decision_timeout_ms\":800,\"decision_mode\":\"closed\"}",
    );
    assert!(policy.contains("\"decision_timeout_ms\":800"), "{policy}");
    assert!(policy.contains("\"decision_mode\":\"closed\""), "{policy}");
    // P2-5: the set minted generation 1, and the read side distinguishes
    // the Host approval state from the undistributed radio intent.
    assert!(policy.contains("\"policy_generation\":1"), "{policy}");
    assert!(
        policy.contains("\"radio_distributed_generation\":null"),
        "{policy}"
    );
    assert!(call("join.policy.set", "{\"decision_timeout_ms\":100}").contains("INVALID_ARGUMENT"));
    assert!(call("join.policy.set", "{\"bogus\":1}").contains("INVALID_ARGUMENT"));
    assert!(call("join.policy.get", "{}").contains("\"pending_retry_after_s\":60"));
    // join.decide: each verdict takes exactly its own parameter.
    for params in [
        "{\"join_request_id\":\"jr-0000000000000001\",\"device_id\":\"00a1000000001234\",\"verdict\":\"allow\",\"role\":\"endpoint\",\"reason\":\"blocked\",\"idempotency_key\":\"k\"}",
        "{\"join_request_id\":\"jr-0000000000000001\",\"device_id\":\"00a1000000001234\",\"verdict\":\"pending\",\"retry_after_s\":5,\"idempotency_key\":\"k\"}",
        "{\"join_request_id\":\"x\",\"device_id\":\"00a1000000001234\",\"verdict\":\"deny\",\"reason\":\"not_here\",\"idempotency_key\":\"k\"}",
        "{\"join_request_id\":\"jr-0000000000000001\",\"device_id\":\"00a1000000001234\",\"verdict\":\"deny\",\"reason\":\"not_here\",\"idempotency_key\":\"has space\"}",
    ] {
        assert!(call("join.decide", params).contains("INVALID_ARGUMENT"), "{params}");
    }
    let missing = call(
        "join.decide",
        "{\"join_request_id\":\"jr-0000000000000001\",\"device_id\":\"00a1000000001234\",\"verdict\":\"deny\",\"reason\":\"not_here\",\"idempotency_key\":\"k\"}",
    );
    assert!(missing.contains("NOT_FOUND"), "{missing}");
    assert!(call("members.get", "{\"device_id\":\"00a1000000001234\"}").contains("NOT_FOUND"));
    assert!(call("devices.discovered.list", "{\"limit\":0}").contains("INVALID_ARGUMENT"));
    assert!(call(
        "operations.get",
        "{\"operation_id\":\"op-00000000000000ff\"}"
    )
    .contains("NOT_FOUND"));
    // Site event kinds are accepted by the events subscribe filter.
    let subscribed = call(
        "messages.subscribe",
        "{\"stream\":\"events\",\"from\":\"latest\",\"filter\":{\"kinds\":[\"join.request\",\"member.revoked\"]}}",
    );
    assert!(subscribed.contains("\"ok\":true"), "{subscribed}");
    // A daemon without a Site Authority answers honestly.
    let bare = Arc::new(State {
        acl: Acl::parse(&format!(
            "{{\"principals\":{{\"{uid}\":{{\"networks\":{{\"*\":[\"MEMBERSHIP_READ\"]}}}}}}}}"
        ))
        .unwrap(),
        ..State::default()
    });
    let unavailable = raw_api1(
        &bare,
        uid,
        "API1 {\"v\":1,\"request_id\":\"u\",\"method\":\"site.status\",\"params\":{}}",
    );
    assert!(
        unavailable.contains("SITE_AUTHORITY_UNAVAILABLE"),
        "{unavailable}"
    );
    let caps = raw_api1(
        &bare,
        uid,
        "API1 {\"v\":1,\"request_id\":\"c\",\"method\":\"capabilities.get\",\"params\":{}}",
    );
    assert!(caps.contains("\"site\":{\"configured\":false"), "{caps}");
}

#[test]
fn join_relay_advertises_only_on_a_capable_session() {
    let daemon = Daemon::start("relay-ready");
    let uid = std::fs::metadata(&daemon.dir).unwrap().uid();
    let caps = || {
        raw_api1(
            &daemon.state,
            uid,
            "API1 {\"v\":1,\"request_id\":\"t\",\"method\":\"capabilities.get\",\"params\":{}}",
        )
    };
    assert!(caps().contains("\"join_relay\":\"not_ready\""));
    {
        let mut info = daemon.state.session.lock().unwrap();
        info.authenticated = true;
        info.id = Some(7);
        info.node = Some(1);
        info.capability = Some(
            routeloom_protocol::join_relay::CAP_JOIN_RELAY_V2
                | routeloom_protocol::host_ops::CAP_HOST_OPS_V1,
        );
    }
    let ready = caps();
    assert!(ready.contains("\"join_relay\":\"ready\""), "{ready}");
    {
        // The capability bit alone is not enough without authentication.
        daemon.state.session.lock().unwrap().authenticated = false;
    }
    assert!(caps().contains("\"join_relay\":\"not_ready\""));
}

/// G-SEC P5 PR3 (§6.4): `group_keys.*` over the API1 socket — the typed
/// client facade, the MEMBERSHIP_READ/ADMIN split, parameter validation,
/// and the rotation events on the stream.
#[test]
fn group_keys_api_over_the_socket() {
    let daemon = Daemon::start("gk");
    let link = RouteLoomTransport::new(&daemon.socket, u64::from(testkit::NETWORK_LOW));
    let kguard = KGuardMock::default();
    let stream = link.site_events().unwrap();
    let (event_tx, event_rx) = mpsc::channel();
    thread::spawn(move || {
        for event in stream {
            if event_tx.send(event).is_err() {
                return;
            }
        }
    });
    let next_event = |kind: &str| loop {
        let event = event_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("no {kind} event"))
            .unwrap();
        if event.kind == kind {
            return event;
        }
    };

    // One member, so the rotation has a target.
    let t0 = now_ms();
    let mut device = SimDevice::new(0x00A1_0000_0000_4321, 0x73);
    kguard.assign(device.node, Assignment::Here(Role::Endpoint));
    let (mut exchange, outcome) = daemon.start_join(&mut device, t0);
    assert!(matches!(outcome, Outcome::Waiting));
    next_event("join.request");
    let decided = kguard.serve_once(&link).unwrap();
    assert_eq!(decided[0].1, Decision::Allow(Role::Endpoint));
    let Outcome::Result(JoinResult::Allow { .. }) = device.finish(&mut exchange, &daemon.transport)
    else {
        panic!("expected Allow");
    };

    // Status before any rotation: stable, epoch 1, no secrets on the wire.
    let status = link.group_key_status().unwrap();
    assert_eq!(status.active, 1);
    assert_eq!(status.staged, None);
    assert_eq!(status.phase, "stable");
    assert_eq!(status.targets, 0);
    assert_eq!(status.unknown, 0);
    assert_eq!(status.last_rotation, None);
    assert!(status.next_due_ms.is_some());

    // A manual rotation commits and announces itself.
    let rotated = link.rotate_group_key(1, "e2e-rotate-1").unwrap();
    assert_eq!(rotated.state, "committed");
    assert_eq!((rotated.from_epoch, rotated.to_epoch), (1, 2));
    assert_eq!(rotated.targets, 1);
    next_event("gk.staged");
    let status = link.group_key_status().unwrap();
    assert_eq!(status.phase, "staging");
    assert_eq!(status.staged, Some(2));
    assert_eq!(status.cause.as_deref(), Some("manual"));
    assert_eq!(status.targets, 1);
    let op = link
        .call(
            "operations.get",
            &format!("{{\"operation_id\":\"{}\"}}", rotated.operation_id),
        )
        .unwrap();
    assert_eq!(
        op.get("kind").and_then(routeloom_json::Json::as_str),
        Some("rotate")
    );
    assert_eq!(
        op.get("state").and_then(routeloom_json::Json::as_str),
        Some("distributing")
    );

    // Validation before anything else: unknown params, bad epoch, no key.
    let uid = std::fs::metadata(&daemon.dir).unwrap().uid();
    let call = |method: &str, params: &str| {
        raw_api1(
            &daemon.state,
            uid,
            &format!(
                "API1 {{\"v\":1,\"request_id\":\"g\", \"method\":\"{method}\",\"params\":{params}}}"
            ),
        )
    };
    assert!(call(
        "group_keys.rotate",
        "{\"expected_active_epoch\":2,\"idempotency_key\":\"k\",\"cause\":\"removal\"}"
    )
    .contains("INVALID_ARGUMENT"));
    assert!(call(
        "group_keys.rotate",
        "{\"expected_active_epoch\":0,\"idempotency_key\":\"k\"}"
    )
    .contains("INVALID_ARGUMENT"));
    assert!(call("group_keys.rotate", "{\"expected_active_epoch\":2}").contains("INVALID_ARGUMENT"));
    assert!(call("group_keys.status", "{\"x\":1}").contains("INVALID_ARGUMENT"));
    // A stale screen conflicts instead of staging (active is still 1,
    // but a rotation is already distributing under another key).
    let stale = call(
        "group_keys.rotate",
        "{\"expected_active_epoch\":9,\"idempotency_key\":\"stale\"}",
    );
    assert!(stale.contains("CONFLICT"), "{stale}");
    let busy = call(
        "group_keys.rotate",
        "{\"expected_active_epoch\":1,\"idempotency_key\":\"other\"}",
    );
    assert!(busy.contains("BUSY"), "{busy}");

    // The ACL split: uid 7 reads but never rotates.
    let read = raw_api1(
        &daemon.state,
        7,
        "API1 {\"v\":1,\"request_id\":\"r\",\"method\":\"group_keys.status\",\"params\":{}}",
    );
    assert!(read.contains("\"ok\":true"), "{read}");
    assert!(read.contains("\"phase\":\"staging\""), "{read}");
    let denied = raw_api1(
        &daemon.state,
        7,
        "API1 {\"v\":1,\"request_id\":\"d\",\"method\":\"group_keys.rotate\",\"params\":{\"expected_active_epoch\":1,\"idempotency_key\":\"x\"}}",
    );
    assert!(denied.contains("AuthorizationFailed"), "{denied}");

    // Revoking the member supersedes with a fresh epoch (announced too).
    let removed = link
        .revoke(device.node, 1, RemovalReason::Lost, "e2e-rm-1")
        .unwrap();
    assert_eq!(removed.state, "committed");
    next_event("member.revoked");
    next_event("gk.staged");
}

/// P6-2 PR D acceptance over the real API1 socket: KGuard joins a
/// gateway and two members, starts `membership.cutover`, the tick paces
/// PREPAREs to the fake channel, PREPARED receipts flow back, the lapse
/// commits, COMMITs flow, APPLIEDs converge — every step observed
/// through the `SiteAdmin` facade — and a member that heard nothing
/// full-joins back into an authenticated reissue on the new epoch with
/// no KGuard round-trip.
#[test]
fn cutover_flows_end_to_end_over_the_api_socket() {
    use routeloom_join::renew::{Head, Phase, Receipt};
    use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
    use routeloom_provision::sha256::sha256;
    use routeloom_provision::signer::{test_keypair, FileRootSigner};

    use super::cutover::CUTOVER_PREPARE_WINDOW_MS;
    use super::group_keys::HostTime;
    use super::revocation::RevocationTransport;

    type GrantMail = (u64, u64, Vec<u8>);
    type GrantOutbox = Arc<Mutex<Vec<GrantMail>>>;

    struct Channel {
        outbox: GrantOutbox,
    }
    impl RevocationTransport for Channel {
        fn send_rrs(&mut self, _node: u64, _object: &[u8]) -> bool {
            true
        }
        fn send_notice(&mut self, _node: u64, _network: u64, _notice: &[u8]) -> bool {
            true
        }
        fn send_grant(&mut self, node: u64, network: u64, plaintext: &[u8]) -> bool {
            self.outbox
                .lock()
                .unwrap()
                .push((node, network, plaintext.to_vec()));
            true
        }
        fn carries_notice(&self) -> bool {
            true
        }
        fn carries_grant(&self) -> bool {
            true
        }
    }

    let daemon = Daemon::start("cutover");
    let admin = RouteLoomTransport::new(&daemon.socket, u64::from(testkit::NETWORK_LOW));
    let mut kguard = KGuardMock::default();
    kguard.pending_retry_s = 30;
    let t0 = now_ms();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let mut member = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut straggler = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    kguard.assign(gateway.node, Assignment::Here(Role::Gateway));
    kguard.assign(member.node, Assignment::Here(Role::Endpoint));
    kguard.assign(straggler.node, Assignment::Here(Role::Endpoint));
    for (device, at) in [
        (&mut gateway, t0),
        (&mut member, t0 + 1_000),
        (&mut straggler, t0 + 2_000),
    ] {
        let (mut exchange, outcome) = daemon.start_join(device, at);
        assert!(matches!(outcome, Outcome::Waiting), "{outcome:?}");
        let done = kguard.serve_once(&admin).unwrap();
        assert_eq!(done.len(), 1);
        let outcome = device.finish(&mut exchange, &daemon.transport);
        assert!(
            matches!(outcome, Outcome::Result(JoinResult::Allow { .. })),
            "{outcome:?}"
        );
    }
    // The fake authority channel plugs into the live daemon.
    let grants: GrantOutbox = Arc::new(Mutex::new(Vec::new()));
    daemon.service.with(|a| {
        a.set_rrs_transport(Some(Box::new(Channel {
            outbox: grants.clone(),
        })))
    });
    let site_ca = FileRootSigner::from_secret(testkit::SITE_CA, &test_keypair(0x61).0).unwrap();
    let next_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Site,
            issuer: testkit::SITE_CA,
            subject: testkit::SITE,
            pubkey: test_keypair(0x62).1,
            network_low32: testkit::NETWORK_LOW,
            site_epoch: testkit::SITE_EPOCH + 1,
            usage: 1,
            serial: 8,
            ..CertClaims::default()
        },
        &site_ca,
    )
    .unwrap();
    let outcome = admin
        .cutover(
            testkit::SITE_EPOCH,
            &crate::receive_log::hex_lower(&next_cert),
            "e2e-cut-1",
        )
        .unwrap();
    assert_eq!(outcome.state, "preparing");
    assert_eq!(outcome.new_site_epoch, testkit::SITE_EPOCH + 1);
    assert_eq!(outcome.targets, 3);
    let progress = admin
        .cutover_operation(&outcome.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(progress.phase, "preparing");
    assert_eq!(progress.total, 3);
    // PREPAREs pace out; the gateway and the member ACK, the straggler
    // hears nothing.
    daemon.service.with(|a| a.tick(HostTime::sync(t0 + 3_000)));
    daemon.service.with(|a| a.tick(HostTime::sync(t0 + 3_100)));
    daemon.service.with(|a| a.tick(HostTime::sync(t0 + 3_200)));
    assert_eq!(grants.lock().unwrap().len(), 3);
    let op = super::records::parse_op_token(&outcome.operation_id).unwrap();
    let (gk_epoch, old_network, new_network) = daemon
        .service
        .with(|a| {
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.old_network, state.new_network)
        })
        .0;
    for (node, _, bytes) in grants.lock().unwrap().clone() {
        if node == straggler.node {
            continue;
        }
        let receipt = Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: op,
                revision: 1,
                old_network,
            },
            new_network,
            gk_epoch,
            rs_epoch: 0,
            digest: sha256(&bytes),
            status: 0,
        }
        .encode()
        .unwrap()
        .to_vec();
        let (moved, _) = daemon
            .service
            .with(|a| a.handle_grant_receipt(node, 1, old_network, &receipt, t0 + 4_000));
        assert!(moved);
    }
    let progress = admin
        .cutover_operation(&outcome.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(progress.prepared, 2);
    assert_eq!(progress.unknown, 1);
    // The lapse commits on the gateway's ACK; COMMITs flow over the old
    // context and the two live targets APPLY over the new one.
    let lapse = t0 + 3_000 + CUTOVER_PREPARE_WINDOW_MS;
    daemon.service.with(|a| a.tick(HostTime::sync(lapse)));
    let progress = admin
        .cutover_operation(&outcome.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(progress.phase, "committed");
    daemon.service.with(|a| a.tick(HostTime::sync(lapse + 100)));
    daemon.service.with(|a| a.tick(HostTime::sync(lapse + 200)));
    daemon.service.with(|a| a.tick(HostTime::sync(lapse + 300)));
    let commits: Vec<_> = grants
        .lock()
        .unwrap()
        .iter()
        .filter(|(_, _, bytes)| bytes[1] == Phase::Commit as u8)
        .cloned()
        .collect();
    assert_eq!(commits.len(), 3);
    let (commit_object, commit_rs) = daemon
        .service
        .with(|a| {
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.commit_object.clone(), state.commit_rs_epoch)
        })
        .0;
    for (node, _, _) in &commits {
        if *node == straggler.node {
            continue;
        }
        let receipt = Receipt {
            head: Head {
                phase: Phase::Applied,
                cutover_id: op,
                revision: 1,
                old_network,
            },
            new_network,
            gk_epoch,
            rs_epoch: commit_rs,
            digest: sha256(&commit_object),
            status: 0,
        }
        .encode()
        .unwrap()
        .to_vec();
        let (moved, _) = daemon
            .service
            .with(|a| a.handle_grant_receipt(*node, 1, new_network, &receipt, lapse + 400));
        assert!(moved);
    }
    let progress = admin
        .cutover_operation(&outcome.operation_id)
        .unwrap()
        .unwrap();
    assert_eq!(progress.applied, 2);
    assert_eq!(progress.unknown, 1);
    // The straggler comes back on its old RLS1: an authenticated
    // reissue on the new epoch, with no join.request for KGuard.
    let open_before = admin.join_requests().unwrap().len();
    straggler.recovery_existing = true;
    let (outcome, _) = straggler.attempt(&daemon.service, &daemon.transport, lapse + 5_000);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::Allow { .. })),
        "{outcome:?}"
    );
    let state = straggler.site.as_ref().unwrap();
    assert_eq!(
        state.member.network >> 32,
        u64::from(testkit::SITE_EPOCH + 1)
    );
    assert_eq!(state.member.assignment_generation, 1);
    let open_after = admin.join_requests().unwrap().len();
    assert_eq!(
        open_before, open_after,
        "no KGuard round-trip for a reissue"
    );
    let member_view = admin.member(member.node).unwrap().unwrap();
    assert_eq!(member_view.generation, 1);
}

/// P2-6 over the API socket (SQLite store): `membership.archive` forgets
/// the removed row, validates its inputs, and requires MEMBERSHIP_ADMIN
/// (restart durability is covered in `tests.rs`, where the store can be
/// reopened without the daemon's live connection).
#[test]
fn membership_archive_over_the_api_socket() {
    let daemon = Daemon::start("archive");
    let uid = std::fs::metadata(&daemon.dir).unwrap().uid();
    let kguard_link = RouteLoomTransport::new(&daemon.socket, u64::from(testkit::NETWORK_LOW));
    let kguard = KGuardMock::default();
    kguard.assign(0x00A1_0000_0000_1234, Assignment::Here(Role::Endpoint));

    let stream = kguard_link.site_events().unwrap();
    let (event_tx, event_rx) = mpsc::channel();
    thread::spawn(move || {
        for event in stream {
            if event_tx.send(event).is_err() {
                return;
            }
        }
    });
    let next_event = |kind: &str| loop {
        let event = event_rx
            .recv_timeout(Duration::from_secs(5))
            .unwrap_or_else(|_| panic!("no {kind} event"))
            .unwrap();
        if event.kind == kind {
            return event;
        }
    };

    let t0 = now_ms();
    let mut device = SimDevice::new(0x00A1_0000_0000_1234, 0x71);
    let (mut exchange, outcome) = daemon.start_join(&mut device, t0);
    assert!(matches!(outcome, Outcome::Waiting));
    next_event("join.request");
    kguard.serve_once(&kguard_link).unwrap();
    let Outcome::Result(JoinResult::Allow { .. }) = device.finish(&mut exchange, &daemon.transport)
    else {
        panic!("expected Allow");
    };
    kguard_link
        .revoke(device.node, 1, RemovalReason::Lost, "rm-1")
        .unwrap();

    // A read-only principal may list but not archive (ADMIN only).
    let denied = raw_api1(
        &daemon.state,
        7,
        &format!(
            "API1 {{\"v\":1,\"request_id\":\"d\",\"method\":\"membership.archive\",\"params\":{{\"device_ids\":[\"{:016x}\"],\"idempotency_key\":\"x\"}}}}",
            device.node
        ),
    );
    assert!(denied.contains("AuthorizationFailed"), "{denied}");

    // Wire validation: empty, over-long, bad-hex and unknown params.
    let bad_cases = [
        "\"device_ids\":[],\"idempotency_key\":\"x\"".to_string(),
        format!(
            "\"device_ids\":[{}],\"idempotency_key\":\"x\"",
            (0..129)
                .map(|_| "\"00a1000000000001\"".to_string())
                .collect::<Vec<_>>()
                .join(",")
        ),
        "\"device_ids\":[\"zz\"],\"idempotency_key\":\"x\"".to_string(),
        format!(
            "\"device_ids\":[\"{:016x}\"],\"idempotency_key\":\"x\",\"extra\":1",
            device.node
        ),
    ];
    for params in &bad_cases {
        let refused = raw_api1(
            &daemon.state,
            uid,
            &format!("API1 {{\"v\":1,\"request_id\":\"v\",\"method\":\"membership.archive\",\"params\":{{{params}}}}}"),
        );
        assert!(refused.contains("INVALID_ARGUMENT"), "{params}: {refused}");
    }

    let answer = kguard_link
        .call(
            "membership.archive",
            &format!(
                "{{\"device_ids\":[\"{:016x}\",\"00a100000000ffff\"],\"idempotency_key\":\"arc-1\"}}",
                device.node
            ),
        )
        .unwrap();
    let archived = answer.get("archived").unwrap().as_array().unwrap();
    assert_eq!(archived.len(), 1);
    assert_eq!(
        archived[0].as_str().unwrap(),
        format!("{:016x}", device.node)
    );
    let skipped = answer.get("skipped_unknown").unwrap().as_array().unwrap();
    assert_eq!(skipped.len(), 1);
    next_event("member.archived");

    // The row is gone from the member surface; the counter is up.
    let gone = raw_api1(
        &daemon.state,
        uid,
        &format!(
            "API1 {{\"v\":1,\"request_id\":\"g\",\"method\":\"members.get\",\"params\":{{\"device_id\":\"{:016x}\"}}}}",
            device.node
        ),
    );
    assert!(gone.contains("NOT_FOUND"), "{gone}");
    assert!(kguard_link.members().unwrap().is_empty());
    let status = raw_api1(
        &daemon.state,
        uid,
        "API1 {\"v\":1,\"request_id\":\"s\",\"method\":\"site.status\",\"params\":{}}",
    );
    assert!(status.contains("\"archived_total\":1"), "{status}");
}
