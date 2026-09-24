//! Site Authority core tests (plan P3-3; acceptance IDs of 02 §14, 04 §11
//! and 07 §8 named per test). Devices are simulated with the Rust EDHOC
//! Initiator and routeloom-join's device-side checks (testkit).

use std::sync::{Arc, Mutex};

use routeloom_join::JoinResult;
use routeloom_provision::sdkv1::revocation::{revocation_object_verify, RevocationReason};
use routeloom_provision::sha256::sha256;

use super::records::{Verdict, ROLE_ENDPOINT, ROLE_RELAY};
use super::store::{MemoryStore, SqliteSiteStore};
use super::testkit::{self, kinds, request_id, Outcome, SimDevice};
use super::transport::{AbortReason, InProcessTransport, RelayKey, RelayUp};
use super::*;

const T0: u64 = 1_790_000_000_000;
const KGUARD: u32 = 501;

fn service_with(store: Box<dyn SiteStore>) -> (SiteService, Arc<InProcessTransport>) {
    let service = SiteService::new(testkit::authority(store, T0));
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    (service, transport)
}

fn service() -> (SiteService, Arc<InProcessTransport>) {
    service_with(Box::<MemoryStore>::default())
}

fn decide(
    service: &SiteService,
    id: u64,
    device: u64,
    verdict: Verdict,
    key: &str,
    now: u64,
) -> Result<String, SiteError> {
    service
        .with(|a| {
            a.decide(
                KGUARD,
                DecideRequest {
                    join_request_id: id,
                    device,
                    verdict,
                    key: key.into(),
                },
                now,
            )
        })
        .0
}

fn json(text: &str) -> routeloom_json::Json {
    routeloom_json::parse(text).unwrap_or_else(|e| panic!("{e}: {text}"))
}

/// V1-H01 (host part) / V1-J03: unassigned → pending → assigned → allow;
/// the approval is committed before message_4, DAMS agrees on both ends.
#[test]
fn pending_then_allow_on_the_next_attempt() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_1234, 0x71);
    let (mut exchange, outcome, events) = device.start(&service, &transport, T0);
    assert!(matches!(outcome, Outcome::Waiting));
    assert_eq!(kinds(&events), ["device.discovered", "join.request"]);
    let id = request_id(&events).unwrap();
    // KGuard: unassigned → pending.
    let answer = decide(
        &service,
        id,
        device.node,
        Verdict::Pending { retry_after_s: 30 },
        "kg-1",
        T0 + 100,
    )
    .unwrap();
    assert_eq!(
        json(&answer).get("applied").unwrap().as_str(),
        Some("current_attempt")
    );
    let Outcome::Result(JoinResult::PendingAssignment {
        retry_after_s,
        ticket,
    }) = device.finish(&mut exchange, &transport)
    else {
        panic!("expected PendingAssignment");
    };
    assert_eq!(retry_after_s, 30);
    assert!(!ticket.is_empty());
    let (discovered, _) = service.with(|a| a.discovered_json(None, 10));
    let listed = json(&discovered);
    let entry = &listed.get("devices").unwrap().as_array().unwrap()[0];
    assert_eq!(entry.get("last_verdict").unwrap().as_str(), Some("pending"));
    assert_eq!(
        entry.get("device_id").unwrap().as_str(),
        Some("00a1000000001234")
    );

    // Next attempt (after retry_after): a new request, KGuard allows.
    let later = T0 + 31_000;
    let (mut exchange, outcome, events) = device.start(&service, &transport, later);
    assert!(matches!(outcome, Outcome::Waiting));
    let id2 = request_id(&events).unwrap();
    assert_ne!(id2, id);
    let answer = decide(
        &service,
        id2,
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "kg-2",
        later + 50,
    )
    .unwrap();
    let answer = json(&answer);
    assert_eq!(answer.get("state").unwrap().as_str(), Some("committed"));
    assert_eq!(answer.get("generation").unwrap().as_u64(), Some(1));
    let Outcome::Result(JoinResult::Allow { .. }) = device.finish(&mut exchange, &transport) else {
        panic!("expected Allow");
    };
    // join_allow_verify passed inside the kit; DAMS agrees with the host.
    let state = device.site.clone().unwrap();
    assert_eq!(state.member.assignment_generation, 1);
    let stored_dams = service.with(|a| a.devices[&device.node].dams).0;
    assert_eq!(state.dams, stored_dams.to_vec());
    let (member, _) = service.with(|a| a.member_get_json(device.node).unwrap());
    let member = json(&member);
    let member = member.get("member").unwrap();
    assert_eq!(
        member.get("confirm_state").unwrap().as_str(),
        Some("allowed_unconfirmed")
    );
    assert_eq!(member.get("delivered").unwrap().as_bool(), Some(true));
    // JoinConfirm hook (P5 wires the channel) → active.
    let (confirmed, events) = service.with(|a| a.member_confirmed(device.node, 1, later + 900));
    assert!(confirmed);
    assert_eq!(kinds(&events), ["member.confirmed"]);
}

/// V1-J09 / V1-H02: KGuard silent → PendingAssignment at the deadline; a
/// later allow applies at the next attempt without a new join.request.
#[test]
fn silent_kguard_pends_and_a_late_decision_applies_next_time() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_2001, 0x72);
    let (mut exchange, outcome, events) = device.start(&service, &transport, T0);
    assert!(matches!(outcome, Outcome::Waiting));
    let id = request_id(&events).unwrap();
    // Before the deadline nothing happens; at it, pending with the policy
    // default retry.
    service.tick(T0 + 1_999);
    assert!(matches!(
        device.finish(&mut exchange, &transport),
        Outcome::Waiting
    ));
    service.tick(T0 + 2_000);
    let Outcome::Result(JoinResult::PendingAssignment { retry_after_s, .. }) =
        device.finish(&mut exchange, &transport)
    else {
        panic!("expected PendingAssignment");
    };
    assert_eq!(retry_after_s, JoinPolicy::default().pending_retry_after_s);
    // The request is still open; KGuard decides late.
    let (list, _) = service.with(|a| a.join_requests_json(T0 + 5_000));
    assert_eq!(
        json(&list)
            .get("requests")
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let answer = decide(
        &service,
        id,
        device.node,
        Verdict::Allow { role: ROLE_RELAY },
        "late",
        T0 + 5_000,
    )
    .unwrap();
    assert_eq!(
        json(&answer).get("applied").unwrap().as_str(),
        Some("next_attempt")
    );
    // The device retries early — the approval wins over the pending holdoff.
    let (outcome, events) = device.attempt(&service, &transport, T0 + 6_000);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::Allow { .. })),
        "{outcome:?}"
    );
    assert!(kinds(&events).iter().all(|k| k != "join.request"));
    assert_eq!(
        device.site.as_ref().unwrap().member.role,
        u32::from(ROLE_RELAY)
    );
}

/// A late pending/deny decision applies at the next attempt; an early
/// retry inside a delivered pending window is answered AuthorityBusy.
#[test]
fn late_deny_applies_and_early_retries_are_busy() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_3001, 0x73);
    let (_, _, events) = device.start(&service, &transport, T0);
    let id = request_id(&events).unwrap();
    service.tick(T0 + 2_000);
    transport.take();
    decide(
        &service,
        id,
        device.node,
        Verdict::DenyNotHere,
        "d",
        T0 + 3_000,
    )
    .unwrap();
    // Early retry, but a decision is on record: it applies at once.
    let (outcome, _) = device.attempt(&service, &transport, T0 + 4_000);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::DenyNotHere)),
        "{outcome:?}"
    );
    // A pending verdict delivered with a 60 s window…
    let mut other = SimDevice::new(0x00A1_0000_0000_3002, 0x74);
    let (mut exchange, _, events) = other.start(&service, &transport, T0);
    let id = request_id(&events).unwrap();
    decide(
        &service,
        id,
        other.node,
        Verdict::Pending { retry_after_s: 60 },
        "p",
        T0 + 10,
    )
    .unwrap();
    other.finish(&mut exchange, &transport);
    // …an attempt 10 s later is Busy with the remaining time, no request.
    let (outcome, events) = other.attempt(&service, &transport, T0 + 10_000);
    let Outcome::Result(JoinResult::AuthorityBusy { retry_after_s }) = outcome else {
        panic!("expected AuthorityBusy, got {outcome:?}");
    };
    assert!((40..=50).contains(&retry_after_s), "{retry_after_s}");
    assert!(kinds(&events).iter().all(|k| k != "join.request"));
    // DenyBlocked straight away.
    let mut blocked = SimDevice::new(0x00A1_0000_0000_3003, 0x75);
    let (mut exchange, _, events) = blocked.start(&service, &transport, T0);
    decide(
        &service,
        request_id(&events).unwrap(),
        blocked.node,
        Verdict::DenyBlocked,
        "b",
        T0 + 10,
    )
    .unwrap();
    assert!(matches!(
        blocked.finish(&mut exchange, &transport),
        Outcome::Result(JoinResult::DenyBlocked)
    ));
}

/// V1-H03: same key → same result; another verdict for a decided request
/// → CONFLICT; a mismatched device id → CONFLICT; unknown id → NOT_FOUND.
#[test]
fn decisions_are_idempotent() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_4001, 0x76);
    let (_, _, events) = device.start(&service, &transport, T0);
    let id = request_id(&events).unwrap();
    assert_eq!(
        decide(&service, id, device.node + 1, Verdict::DenyBlocked, "x", T0)
            .unwrap_err()
            .code,
        "CONFLICT"
    );
    assert_eq!(
        decide(
            &service,
            id + 99,
            device.node,
            Verdict::DenyBlocked,
            "x",
            T0
        )
        .unwrap_err()
        .code,
        "NOT_FOUND"
    );
    service.tick(T0 + 2_000); // pending delivered; request stays open
    let first = decide(
        &service,
        id,
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "k1",
        T0 + 3_000,
    )
    .unwrap();
    let again = decide(
        &service,
        id,
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "k1",
        T0 + 3_500,
    )
    .unwrap();
    assert_eq!(first, again);
    // Same verdict under a new key: the stored answer, no second approval.
    let other_key = decide(
        &service,
        id,
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "k2",
        T0 + 3_600,
    )
    .unwrap();
    assert_eq!(first, other_key);
    let conflict = decide(
        &service,
        id,
        device.node,
        Verdict::DenyNotHere,
        "k3",
        T0 + 3_700,
    )
    .unwrap_err();
    assert_eq!(conflict.code, "CONFLICT");
    let reused = decide(
        &service,
        id,
        device.node,
        Verdict::DenyNotHere,
        "k1",
        T0 + 3_800,
    )
    .unwrap_err();
    assert_eq!(reused.code, "CONFLICT");
    assert_eq!(
        service.with(|a| a.next_serial).0,
        2,
        "exactly one MemberCert issued"
    );
}

/// V1-H07 / 07 §3 crash rule: approval committed, host dies before
/// message_4 — the device's retry after restart gets the same MemberCert
/// (reissued, no KGuard), from the SQLite store.
#[test]
fn restart_after_commit_reissues_the_same_member_cert() {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-site-crash-{}-{}",
        std::process::id(),
        T0
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("site.db");
    let mut device = SimDevice::new(0x00A1_0000_0000_5001, 0x77);
    let member_cert = {
        let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        let (_, _, events) = device.start(&service, &transport, T0);
        let id = request_id(&events).unwrap();
        service.tick(T0 + 2_000);
        decide(
            &service,
            id,
            device.node,
            Verdict::Allow {
                role: ROLE_ENDPOINT,
            },
            "a",
            T0 + 3_000,
        )
        .unwrap();
        service
            .with(|a| a.devices[&device.node].member_cert.clone())
            .0
        // dropped: the "crash"
    };
    let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
    let (outcome, events) = device.attempt(&service, &transport, T0 + 10_000);
    let Outcome::Result(JoinResult::Allow {
        member_cert: got, ..
    }) = outcome
    else {
        panic!("expected Allow, got {outcome:?}");
    };
    assert_eq!(got, member_cert);
    assert_eq!(kinds(&events), ["member.reissued"]);
    // A second retry (m4 lost again) is the same bytes again.
    let (outcome, _) = device.attempt(&service, &transport, T0 + 20_000);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::Allow { member_cert, .. }) if member_cert == got)
    );
    drop(service);
    let _ = std::fs::remove_dir_all(&dir);
}

/// V1-H04 / V1-R01 (host part) / V1-R05 / V1-R07: revoke with the wrong
/// generation is CONFLICT; revoke commits RRS1 (SAK-signed, verifiable);
/// the removed device gets Removed + a RemovalNotice it verifies, erases
/// its site state, then shows up as previously_removed and can be
/// re-assigned at generation 2.
#[test]
fn removal_end_to_end() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_6001, 0x78);
    let (mut exchange, _, events) = device.start(&service, &transport, T0);
    decide(
        &service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "a",
        T0 + 10,
    )
    .unwrap();
    assert!(matches!(
        device.finish(&mut exchange, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    let revoke = |generation, key: &str, now| {
        service.with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: device.node,
                    expected_generation: generation,
                    reason: RevocationReason::Lost,
                    key: key.into(),
                },
                now,
            )
        })
    };
    assert_eq!(revoke(2, "r0", T0 + 20).0.unwrap_err().code, "CONFLICT");
    let (answer, events) = revoke(1, "r1", T0 + 30);
    let answer = json(&answer.unwrap());
    assert_eq!(answer.get("state").unwrap().as_str(), Some("committed"));
    assert_eq!(answer.get("rs_epoch").unwrap().as_u64(), Some(1));
    assert_eq!(
        kinds(&events),
        ["member.revoked", "rrs.published", "gk.staged"]
    );
    // Idempotent replay; a second removal is CONFLICT.
    assert_eq!(json(&revoke(1, "r1", T0 + 40).0.unwrap()), answer);
    assert_eq!(revoke(1, "r2", T0 + 40).0.unwrap_err().code, "CONFLICT");
    // The RRS1 verifies under the SAK for this network and lists the node.
    let rrs = service.with(|a| a.latest_rrs()).0.unwrap();
    let (set, ok) = revocation_object_verify(
        &rrs,
        &testkit::sak().pubkey(),
        testkit::SITE,
        testkit::network(),
    )
    .unwrap();
    assert!(ok);
    assert_eq!(set.entries.len(), 1);
    assert_eq!(set.entries[0].node_id, device.node);
    assert_eq!(set.entries[0].min_generation, 2);
    // Operation view: committed, distribution honestly not implemented.
    let op = answer
        .get("operation_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let op_id = records::parse_op_token(&op).unwrap();
    let (view, _) = service.with(|a| a.operation_json(op_id).unwrap());
    let view = json(&view);
    // P6-1: the sole member was removed, so the snapshot is empty and the
    // distribution converges vacuously on the first tick — nothing owed.
    assert_eq!(
        view.get("distribution")
            .unwrap()
            .get("state")
            .unwrap()
            .as_str(),
        Some("pending")
    );
    service.tick(T0 + 50);
    let (view, _) = service.with(|a| a.operation_json(op_id).unwrap());
    let view = json(&view);
    let distribution = view.get("distribution").unwrap();
    assert_eq!(
        distribution.get("state").unwrap().as_str(),
        Some("converged")
    );
    assert_eq!(distribution.get("total").unwrap().as_u64(), Some(0));
    // The device still holds site state: Removed + notice, then it erases.
    let (outcome, _) = device.attempt(&service, &transport, T0 + 60_000);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::Removed { .. })),
        "{outcome:?}"
    );
    assert!(device.site.is_none());
    // Unassigned again: KGuard sees previously_removed and may re-assign.
    let (mut exchange, outcome, events) = device.start(&service, &transport, T0 + 660_000);
    assert!(matches!(outcome, Outcome::Waiting));
    let request = events
        .iter()
        .find(|(_, f)| f.contains("join.request"))
        .unwrap();
    assert!(
        request.1.contains("\"previously_removed\":true"),
        "{}",
        request.1
    );
    decide(
        &service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "a2",
        T0 + 660_010,
    )
    .unwrap();
    assert!(matches!(
        device.finish(&mut exchange, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    assert_eq!(
        device.site.as_ref().unwrap().member.assignment_generation,
        2
    );
}

/// V1-J07: a DevCert from another Device CA is refused with an EDHOC
/// error, counted by reason, and never listed as discovered.
#[test]
fn unverified_devices_are_refused_and_not_listed() {
    let (service, transport) = service();
    let foreign_ca = routeloom_provision::signer::FileRootSigner::from_secret(
        testkit::DEVICE_CA,
        &routeloom_provision::signer::test_keypair(0x6F).0,
    )
    .unwrap();
    let mut device = SimDevice::with_ca(0x00A1_0000_0000_7001, 0x79, &foreign_ca);
    let (outcome, events) = device.attempt(&service, &transport, T0);
    let Outcome::EdhocError(body) = outcome else {
        panic!("expected an EDHOC error, got {outcome:?}");
    };
    // ERR_CODE 1 with a generic text: nothing about why is disclosed.
    assert_eq!(
        routeloom_edhoc::error_message_decode(&body).unwrap(),
        (1, routeloom_edhoc::ErrorInfo::Text("join refused".into()))
    );
    assert!(events.is_empty());
    let (status, _) = service.with(|a| a.status_json(T0));
    let status = json(&status);
    let counters = status.get("counters").unwrap();
    assert_eq!(
        counters
            .get("rejected_unverified")
            .unwrap()
            .get("devcert")
            .unwrap()
            .as_u64(),
        Some(1)
    );
    assert_eq!(status.get("discovered").unwrap().as_u64(), Some(0));
}

/// 02 §13: at most four exchanges at once, one message_1 per MAC per 2 s;
/// beyond that the relay is aborted `busy`. Unknown relays are refused.
#[test]
fn admission_is_bounded() {
    let (service, transport) = service();
    let mut devices: Vec<SimDevice> = (0..5)
        .map(|i| SimDevice::new(0x00A1_0000_0000_8000 + i, 0x80 + i as u8))
        .collect();
    // Four exchanges parked in DECIDE.
    for device in devices.iter_mut().take(4) {
        let (_, outcome, _) = device.start(&service, &transport, T0);
        assert!(matches!(outcome, Outcome::Waiting));
    }
    let (outcome, _) = devices[4].attempt(&service, &transport, T0 + 1);
    assert!(
        matches!(outcome, Outcome::Aborted(AbortReason::Busy)),
        "{outcome:?}"
    );
    // Same MAC again within 2 s after the slots free up: still busy.
    service.tick(T0 + 5_000);
    transport.take();
    let (outcome, _) = devices[4].attempt(&service, &transport, T0 + 5_001);
    assert!(!matches!(outcome, Outcome::Aborted(_)), "{outcome:?}");
    let (outcome, _) = devices[4].attempt(&service, &transport, T0 + 5_002);
    assert!(
        matches!(outcome, Outcome::Aborted(AbortReason::Busy)),
        "{outcome:?}"
    );
    // A message_3 for a relay nobody started.
    service.handle_up(
        RelayUp {
            key: RelayKey {
                gateway: 1,
                proxy: 2,
                relay_id: 3,
                joiner_mac: [9; 6],
            },
            hops: 0,
            step: 3,
            joiner_rssi_dbm: 0,
            body: vec![0x40],
        },
        T0 + 6_000,
    );
    assert!(matches!(
        transport.take().as_slice(),
        [transport::Outbound::Abort {
            reason: AbortReason::UnknownRelay,
            ..
        }]
    ));
}

/// 02 §8 COMMIT: a failed store commit is never success — decide answers
/// STORE_FAILURE with nothing changed, and a failed delivery commit turns
/// the Allow into AuthorityBusy.
#[test]
fn store_failures_never_become_success() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_9001, 0x90);
    let (mut exchange, _, events) = device.start(&service, &transport, T0);
    let id = request_id(&events).unwrap();
    // Inject: the next commit fails.
    service.with(|a| {
        let mut failing = MemoryStore::default();
        failing.fail_next = 1;
        a.store = Box::new(failing);
    });
    let error = decide(
        &service,
        id,
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "f",
        T0 + 10,
    )
    .unwrap_err();
    assert_eq!(error.code, "STORE_FAILURE");
    assert!(error.retryable);
    assert!(service.with(|a| a.devices.is_empty()).0);
    // The exchange is still waiting; KGuard retries and it goes through.
    decide(
        &service,
        id,
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "f",
        T0 + 20,
    )
    .unwrap();
    assert!(matches!(
        device.finish(&mut exchange, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    // Delivery commit failure on a reissue → AuthorityBusy, not Allow.
    service.with(|a| {
        let mut failing = MemoryStore::default();
        failing.fail_next = 1;
        a.store = Box::new(failing);
    });
    let (outcome, _) = device.attempt(&service, &transport, T0 + 30_000);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::AuthorityBusy { .. })),
        "{outcome:?}"
    );
}

/// Policy `closed` (or zero_touch_open=false): no join.request, pending.
#[test]
fn closed_policy_pends_without_asking() {
    let (service, transport) = service();
    let policy = JoinPolicy {
        decision_mode: DecisionMode::Closed,
        pending_retry_after_s: 120,
        ..JoinPolicy::default()
    };
    service.with(|a| a.set_policy(policy)).0.unwrap();
    let mut bad = policy;
    bad.decision_timeout_ms = 100;
    assert_eq!(
        service.with(|a| a.set_policy(bad)).0.unwrap_err().code,
        "INVALID_ARGUMENT"
    );
    let mut device = SimDevice::new(0x00A1_0000_0000_A001, 0xA0);
    let (outcome, events) = device.attempt(&service, &transport, T0);
    assert!(matches!(
        outcome,
        Outcome::Result(JoinResult::PendingAssignment {
            retry_after_s: 120,
            ..
        })
    ));
    assert_eq!(kinds(&events), ["device.discovered"]);
}

/// 07 §7: the same NodeId with another key is a different device —
/// join.request carries kid_conflict and allow is refused.
#[test]
fn kid_conflict_is_never_auto_allowed() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_B001, 0xB0);
    let (mut exchange, _, events) = device.start(&service, &transport, T0);
    decide(
        &service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "a",
        T0 + 1,
    )
    .unwrap();
    device.finish(&mut exchange, &transport);
    let mut clone = SimDevice::new(device.node, 0xB1);
    let (_, outcome, events) = clone.start(&service, &transport, T0 + 10_000);
    assert!(matches!(outcome, Outcome::Waiting));
    let request = events
        .iter()
        .find(|(_, f)| f.contains("join.request"))
        .unwrap();
    assert!(request.1.contains("\"kid_conflict\":true"));
    let error = decide(
        &service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "c",
        T0 + 10_001,
    )
    .unwrap_err();
    assert_eq!(error.code, "CONFLICT");
}

/// A message_1 selecting another suite gets the 0x0202-style error
/// (ERR_CODE 2, SUITES_R 2), a malformed one ERR_CODE 1.
#[test]
fn message_1_refusals_answer_edhoc_errors() {
    let (service, transport) = service();
    let key = RelayKey {
        gateway: 1,
        proxy: 2,
        relay_id: 3,
        joiner_mac: [1; 6],
    };
    let mut initiator = routeloom_edhoc::Initiator::new(
        routeloom_edhoc::Method::SignatureSignature,
        vec![3],
        vec![],
    )
    .unwrap();
    let m1 = initiator
        .compose_message_1(routeloom_edhoc::crypto::random_scalar().unwrap(), &[])
        .unwrap();
    service.handle_up(
        RelayUp {
            key,
            hops: 0,
            step: 1,
            joiner_rssi_dbm: 0,
            body: m1,
        },
        T0,
    );
    let sent = transport.take();
    let transport::Outbound::Down(down) = &sent[0] else {
        panic!()
    };
    assert_eq!((down.step, down.status), (5, transport::DownStatus::Final));
    assert_eq!(down.body, [0x02, 0x02]);
    // Valid EDHOC, but no JoinIntent: ERR_CODE 1.
    let mut initiator = routeloom_edhoc::Initiator::new(
        routeloom_edhoc::Method::SignatureSignature,
        vec![2],
        vec![],
    )
    .unwrap();
    let m1 = initiator
        .compose_message_1(routeloom_edhoc::crypto::random_scalar().unwrap(), &[])
        .unwrap();
    let key = RelayKey {
        joiner_mac: [2; 6],
        ..key
    };
    service.handle_up(
        RelayUp {
            key,
            hops: 0,
            step: 1,
            joiner_rssi_dbm: 0,
            body: m1,
        },
        T0,
    );
    let sent = transport.take();
    let transport::Outbound::Down(down) = &sent[0] else {
        panic!()
    };
    assert_eq!(
        routeloom_edhoc::error_message_decode(&down.body).unwrap().0,
        1
    );
}

/// A store bound to one site refuses to open for another SAK / site.
#[test]
fn a_store_is_bound_to_its_site() {
    let dir =
        std::env::temp_dir().join(format!("routeloom-site-bind-{}-{}", std::process::id(), T0));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("site.db");
    drop(testkit::authority(
        Box::new(SqliteSiteStore::open(&db).unwrap()),
        T0,
    ));
    let mut setup = testkit::setup();
    setup.channel = 6; // channel is not part of the binding
    assert!(SiteAuthority::open(
        &setup,
        Box::new(testkit::sak()),
        Box::new(SqliteSiteStore::open(&db).unwrap()),
        T0
    )
    .is_ok());
    // A SiteCert for another site_id with its own SAK: refused.
    let other_sak = routeloom_provision::signer::FileRootSigner::from_secret(
        testkit::SITE + 1,
        &routeloom_provision::signer::test_keypair(0x62).0,
    )
    .unwrap();
    let site_ca = routeloom_provision::signer::FileRootSigner::from_secret(
        testkit::SITE_CA,
        &routeloom_provision::signer::test_keypair(0x61).0,
    )
    .unwrap();
    let mut claims = routeloom_provision::sdkv1::cert::cert_decode(&setup.site_cert).unwrap();
    claims.subject = testkit::SITE + 1;
    setup.site_cert = routeloom_provision::sdkv1::cert::cert_issue(&claims, &site_ca).unwrap();
    let refused = SiteAuthority::open(
        &setup,
        Box::new(other_sak),
        Box::new(SqliteSiteStore::open(&db).unwrap()),
        T0,
    );
    assert!(refused.is_err());
    let _ = std::fs::remove_dir_all(&dir);
}

/// #107: two join requests for one NodeId with different keys, both
/// opened before any approval — the kid_conflict stored at request time
/// is re-checked against the live membership at commit, so the later
/// different-key allow is CONFLICT while the first-approved key holds
/// the row.
#[test]
fn review_concurrent_different_keys_rechecks_current_membership() {
    let (service, transport) = service();
    let mut a = SimDevice::new(0x00A1_0000_0000_C001, 0xC1);
    let mut b = SimDevice::new(a.node, 0xC2);
    let (mut exchange_a, _, events_a) = a.start(&service, &transport, T0);
    let (mut exchange_b, _, events_b) = b.start(&service, &transport, T0 + 10);
    decide(
        &service,
        request_id(&events_a).unwrap(),
        a.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "review-a",
        T0 + 20,
    )
    .unwrap();
    a.finish(&mut exchange_a, &transport);
    let second = decide(
        &service,
        request_id(&events_b).unwrap(),
        b.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "review-b",
        T0 + 30,
    );
    assert!(matches!(second, Err(ref e) if e.code == "CONFLICT"));
    // A's committed row is untouched: A's key, generation 1, serial 1.
    let (row, _) = service.with(|auth| auth.devices[&a.node].clone());
    assert!(row.member && row.kid == a.kid && row.generation == 1);
    assert_eq!(row.member_cert_serial, 1);
    // B's request stays open and undecided — a verdict can still apply
    // once the conflict is gone (or a deny right away).
    let (list, _) = service.with(|auth| auth.join_requests_json(T0 + 40));
    let requests = json(&list);
    let requests = requests.get("requests").unwrap().as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].get("state").unwrap().as_str(), Some("awaiting"));
    // The CONFLICT message's guidance works: revoke the holding
    // membership and the still-open request can be allowed — the
    // replacement commits at generation 2.
    let (revoked, _) = service.with(|auth| {
        auth.revoke(
            KGUARD,
            RevokeRequest {
                device: a.node,
                expected_generation: 1,
                reason: RevocationReason::Replaced,
                key: "rv".into(),
            },
            T0 + 50,
        )
    });
    revoked.unwrap();
    let committed = decide(
        &service,
        request_id(&events_b).unwrap(),
        b.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "review-b2",
        T0 + 60,
    )
    .unwrap();
    assert_eq!(
        json(&committed).get("generation").unwrap().as_u64(),
        Some(2)
    );
    assert!(matches!(
        b.finish(&mut exchange_b, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    let (row, _) = service.with(|auth| auth.devices[&a.node].clone());
    assert!(row.member && row.kid == b.kid && row.generation == 2);
}

/// #108: the documented recovery works — revoke the live membership and
/// a replacement key joins without a conflict (still an explicit KGuard
/// allow, never auto-approved); the new row is generation 2 with a fresh
/// MemberCert while the old key's revocation floor and history stay.
#[test]
fn review_revoked_membership_allows_explicit_replacement_key() {
    let (service, transport) = service();
    let mut a = SimDevice::new(0x00A1_0000_0000_C002, 0xC3);
    let (mut exchange, _, events) = a.start(&service, &transport, T0);
    decide(
        &service,
        request_id(&events).unwrap(),
        a.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "a",
        T0 + 10,
    )
    .unwrap();
    a.finish(&mut exchange, &transport);
    let old_cert = service
        .with(|auth| auth.devices[&a.node].member_cert.clone())
        .0;
    let (revoked, _) = service.with(|auth| {
        auth.revoke(
            KGUARD,
            RevokeRequest {
                device: a.node,
                expected_generation: 1,
                reason: RevocationReason::Replaced,
                key: "rv".into(),
            },
            T0 + 20,
        )
    });
    assert_eq!(
        json(&revoked.unwrap()).get("state").unwrap().as_str(),
        Some("committed")
    );
    // The replacement key joins on the removed row: the node's removal
    // history shows but there is no conflict, and nothing is approved
    // without KGuard.
    let mut b = SimDevice::new(a.node, 0xC4);
    let (mut exchange, outcome, events) = b.start(&service, &transport, T0 + 30_000);
    assert!(matches!(outcome, Outcome::Waiting));
    let request = events
        .iter()
        .find(|(_, f)| f.contains("join.request"))
        .unwrap();
    assert!(
        request.1.contains("\"kid_conflict\":false"),
        "{}",
        request.1
    );
    assert!(
        request.1.contains("\"previously_removed\":true"),
        "{}",
        request.1
    );
    let committed = decide(
        &service,
        request_id(&events).unwrap(),
        b.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "b",
        T0 + 30_010,
    )
    .unwrap();
    assert_eq!(
        json(&committed).get("generation").unwrap().as_u64(),
        Some(2)
    );
    assert!(matches!(
        b.finish(&mut exchange, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    assert_eq!(b.site.as_ref().unwrap().member.assignment_generation, 2);
    // The row is the replacement's: new key, generation 2, a fresh
    // MemberCert — the old cert does not come back as a new generation.
    let (row, _) = service.with(|auth| auth.devices[&a.node].clone());
    assert!(row.member && row.kid == b.kid && row.generation == 2);
    assert_ne!(row.member_cert, old_cert);
    let claims = cert_decode(&row.member_cert).unwrap();
    assert_eq!(claims.assignment_generation, 2);
    assert_eq!(claims.pubkey, b.pubkey);
    // The revocation floor is kept here: the RRS still revokes this node
    // below generation 2, for the recorded reason.
    let rrs = service.with(|auth| auth.latest_rrs()).0.unwrap();
    let (set, ok) = revocation_object_verify(
        &rrs,
        &testkit::sak().pubkey(),
        testkit::SITE,
        testkit::network(),
    )
    .unwrap();
    assert!(ok);
    let entry = set.entries.iter().find(|e| e.node_id == a.node).unwrap();
    assert_eq!(entry.min_generation, 2);
    assert_eq!(entry.reason, RevocationReason::Replaced);
}

/// #108 across a daemon restart: the removed row, the RRS and the
/// ledger reload from SQLite, and the same replacement flow completes
/// at generation 2.
#[test]
fn review_replacement_flow_survives_a_restart() {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-site-replace-{}-{}",
        std::process::id(),
        T0
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("site.db");
    let node = 0x00A1_0000_0000_C003;
    {
        let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        let mut a = SimDevice::new(node, 0xC5);
        let (mut exchange, _, events) = a.start(&service, &transport, T0);
        decide(
            &service,
            request_id(&events).unwrap(),
            node,
            Verdict::Allow {
                role: ROLE_ENDPOINT,
            },
            "a",
            T0 + 10,
        )
        .unwrap();
        a.finish(&mut exchange, &transport);
        let (revoked, _) = service.with(|auth| {
            auth.revoke(
                KGUARD,
                RevokeRequest {
                    device: node,
                    expected_generation: 1,
                    reason: RevocationReason::Replaced,
                    key: "rv".into(),
                },
                T0 + 20,
            )
        });
        revoked.unwrap();
        // dropped: the daemon stops with the removed row on disk
    }
    let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
    let mut b = SimDevice::new(node, 0xC6);
    let (mut exchange, outcome, events) = b.start(&service, &transport, T0 + 30_000);
    assert!(matches!(outcome, Outcome::Waiting));
    let request = events
        .iter()
        .find(|(_, f)| f.contains("join.request"))
        .unwrap();
    assert!(
        request.1.contains("\"kid_conflict\":false"),
        "{}",
        request.1
    );
    let committed = decide(
        &service,
        request_id(&events).unwrap(),
        node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "b",
        T0 + 30_010,
    )
    .unwrap();
    assert_eq!(
        json(&committed).get("generation").unwrap().as_u64(),
        Some(2)
    );
    assert!(matches!(
        b.finish(&mut exchange, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    let (row, _) = service.with(|auth| auth.devices[&node].clone());
    assert!(row.member && row.kid == b.kid && row.generation == 2);
    // The RRS floor and the ledger chain reloaded intact (open()
    // verifies the chain); the node stays revoked below generation 2.
    let rrs = service.with(|auth| auth.latest_rrs()).0.unwrap();
    let (set, ok) = revocation_object_verify(
        &rrs,
        &testkit::sak().pubkey(),
        testkit::SITE,
        testkit::network(),
    )
    .unwrap();
    assert!(ok);
    assert!(set
        .entries
        .iter()
        .any(|e| e.node_id == node && e.min_generation == 2));
    drop(service);
    let _ = std::fs::remove_dir_all(&dir);
}

/// #107 follow-through: a decision applies to the membership as it is
/// at commit. An allow delayed past an approve+revoke cannot resurrect
/// the old request (delivered → NOT_FOUND), a stored kid_conflict flag
/// clears once the member is gone, and a decided allow replayed under a
/// new idempotency key is re-checked against the live membership —
/// CONFLICT once it is removed or replaced, while the same key's resend
/// keeps returning the recorded answer (idempotency contract).
#[test]
fn review_late_allow_follows_the_current_membership() {
    let (service, transport) = service();
    let mut a = SimDevice::new(0x00A1_0000_0000_C004, 0xC7);
    let (mut exchange, _, events) = a.start(&service, &transport, T0);
    let id_a = request_id(&events).unwrap();
    decide(
        &service,
        id_a,
        a.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "a",
        T0 + 10,
    )
    .unwrap();
    a.finish(&mut exchange, &transport);
    // B's request while A is a member: kid_conflict is stored and shown
    // to KGuard, but it is not the final word.
    let mut b = SimDevice::new(a.node, 0xC8);
    let (mut exchange_b, outcome, events) = b.start(&service, &transport, T0 + 100);
    assert!(matches!(outcome, Outcome::Waiting));
    let request = events
        .iter()
        .find(|(_, f)| f.contains("join.request"))
        .unwrap();
    assert!(request.1.contains("\"kid_conflict\":true"), "{}", request.1);
    let id_b = request_id(&events).unwrap();
    // Revoke A; a delayed allow for the delivered old request is
    // NOT_FOUND, not a resurrection.
    let (revoked, _) = service.with(|auth| {
        auth.revoke(
            KGUARD,
            RevokeRequest {
                device: a.node,
                expected_generation: 1,
                reason: RevocationReason::Replaced,
                key: "rv".into(),
            },
            T0 + 200,
        )
    });
    revoked.unwrap();
    assert_eq!(
        decide(
            &service,
            id_a,
            a.node,
            Verdict::Allow {
                role: ROLE_ENDPOINT
            },
            "a-late",
            T0 + 210
        )
        .unwrap_err()
        .code,
        "NOT_FOUND"
    );
    // B's stored kid_conflict is stale — the delayed allow commits the
    // replacement at generation 2.
    let committed = decide(
        &service,
        id_b,
        b.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "b",
        T0 + 220,
    )
    .unwrap();
    assert_eq!(
        json(&committed).get("generation").unwrap().as_u64(),
        Some(2)
    );
    assert!(matches!(
        b.finish(&mut exchange_b, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    // A decision recorded for next_attempt stays open. A new idempotency
    // key replays the stored committed answer only while the membership
    // it created is still live…
    let mut c = SimDevice::new(0x00A1_0000_0000_C005, 0xC9);
    let (_, _, events) = c.start(&service, &transport, T0 + 300);
    let id_c = request_id(&events).unwrap();
    service.tick(T0 + 300 + 2_000); // KGuard silent → pending, request open
    transport.take();
    let first = decide(
        &service,
        id_c,
        c.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "c",
        T0 + 2_310,
    )
    .unwrap();
    assert_eq!(
        json(&first).get("applied").unwrap().as_str(),
        Some("next_attempt")
    );
    let live_replay = decide(
        &service,
        id_c,
        c.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "c2",
        T0 + 2_315,
    )
    .unwrap();
    assert_eq!(live_replay, first);
    let (revoked, _) = service.with(|auth| {
        auth.revoke(
            KGUARD,
            RevokeRequest {
                device: c.node,
                expected_generation: 1,
                reason: RevocationReason::Lost,
                key: "rvc".into(),
            },
            T0 + 2_320,
        )
    });
    revoked.unwrap();
    // …the same key's resend still returns the recorded answer (the
    // idempotency contract is about the call, not the state)…
    let replay = decide(
        &service,
        id_c,
        c.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "c",
        T0 + 2_330,
    )
    .unwrap();
    assert_eq!(replay, first);
    // …and so does a different key that already received the committed
    // answer — it was recorded under its own key at the live replay…
    let recorded = decide(
        &service,
        id_c,
        c.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "c2",
        T0 + 2_335,
    )
    .unwrap();
    assert_eq!(recorded, first);
    // …but an unrecorded key asks again and is checked against the
    // current row: CONFLICT, nothing committed, the device stays removed.
    let stale = decide(
        &service,
        id_c,
        c.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "c3",
        T0 + 2_340,
    )
    .unwrap_err();
    assert_eq!(stale.code, "CONFLICT");
    let (still_removed, _) = service.with(|auth| !auth.devices[&c.node].member);
    assert!(still_removed);
    // The same check after a replacement: the committed (kid, generation)
    // is gone even though the node is a member again. (The join is after
    // the pending holdoff the earlier KGuard-silent expiry set.)
    let mut d = SimDevice::new(c.node, 0xCA);
    let (mut exchange_d, _, events) = d.start(&service, &transport, T0 + 60_000);
    let id_d = request_id(&events).unwrap();
    decide(
        &service,
        id_d,
        d.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "d",
        T0 + 60_010,
    )
    .unwrap();
    d.finish(&mut exchange_d, &transport);
    let replaced = decide(
        &service,
        id_c,
        c.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "c4",
        T0 + 60_020,
    )
    .unwrap_err();
    assert_eq!(replaced.code, "CONFLICT");
}

/// P6-1 distribution test fake: the in-process stand-in for the P5
/// authority channel. Refusals exercise the outbox backoff.
#[derive(Default)]
struct FakeRrsSends {
    sent: Vec<(u64, Vec<u8>)>,
    refuse: bool,
}

struct FakeRrsTransport {
    shared: Arc<Mutex<FakeRrsSends>>,
}

impl super::revocation::RevocationTransport for FakeRrsTransport {
    fn send_rrs(&mut self, node: u64, object: &[u8]) -> bool {
        let mut sends = self.shared.lock().unwrap();
        if sends.refuse {
            return false;
        }
        sends.sent.push((node, object.to_vec()));
        true
    }
}

fn join_member(
    service: &SiteService,
    transport: &Arc<InProcessTransport>,
    device: &mut SimDevice,
    key: &str,
    at: u64,
) {
    let (mut exchange, _, events) = device.start(service, transport, at);
    decide(
        service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        key,
        at + 10,
    )
    .unwrap();
    assert!(matches!(
        device.finish(&mut exchange, transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
}

fn revoke(
    service: &SiteService,
    device: u64,
    generation: u32,
    key: &str,
    at: u64,
) -> (u64, routeloom_json::Json) {
    let (answer, _) = service.with(|a| {
        a.revoke(
            KGUARD,
            RevokeRequest {
                device,
                expected_generation: generation,
                reason: RevocationReason::Lost,
                key: key.into(),
            },
            at,
        )
    });
    let answer = json(&answer.unwrap());
    let op =
        records::parse_op_token(answer.get("operation_id").unwrap().as_str().unwrap()).unwrap();
    (op, answer)
}

fn distribution_of(service: &SiteService, op: u64) -> routeloom_json::Json {
    let (view, _) = service.with(|a| a.operation_json(op).unwrap());
    let view = json(&view);
    view.get("distribution").unwrap().clone()
}

/// V1-R01 (P6-1): `membership.revoke` answers `committed` with a
/// `"pending"` distribution string, and `operations.get` reports the
/// surviving members as unknown targets until their Applied ACKs arrive —
/// never a success count without evidence.
#[test]
fn revoke_reports_pending_distribution_with_unknown_targets() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(&service, &transport, &mut keeper, "k", T0);
    join_member(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let (op, answer) = revoke(&service, leaver.node, 1, "r-dist", T0 + 10_000);
    assert_eq!(
        answer.get("distribution").unwrap().as_str(),
        Some("pending")
    );
    let distribution = distribution_of(&service, op);
    assert_eq!(distribution.get("state").unwrap().as_str(), Some("pending"));
    assert_eq!(distribution.get("applied").unwrap().as_u64(), Some(0));
    assert_eq!(distribution.get("unknown").unwrap().as_u64(), Some(1));
    assert_eq!(distribution.get("total").unwrap().as_u64(), Some(1));
    // Compatibility fields keep the old shape: reached == applied.
    assert_eq!(distribution.get("reached").unwrap().as_u64(), Some(0));
    assert_eq!(distribution.get("members").unwrap().as_u64(), Some(1));
}

/// V1-R01 (P6-1): the full push cycle — tick sends the RRS1 to the
/// snapshot, the Applied ACK converges the operation, and anything but
/// a context-bound ACK for the exact issued bytes is ignored.
#[test]
fn revocation_distribution_converges_on_applied() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(&service, &transport, &mut keeper, "k", T0);
    join_member(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op, _) = revoke(&service, leaver.node, 1, "r-push", T0 + 10_000);
    service.tick(T0 + 10_100);
    assert_eq!(sends.lock().unwrap().sent.len(), 1);
    assert_eq!(sends.lock().unwrap().sent[0].0, keeper.node);
    let object = sends.lock().unwrap().sent[0].1.clone();
    let digest = sha256(&object);
    let distribution = distribution_of(&service, op);
    assert_eq!(
        distribution.get("state").unwrap().as_str(),
        Some("distributing")
    );
    let network = testkit::network();
    // Wrong generation, wrong node, unknown epoch, wrong bytes: ignored.
    assert!(
        !service
            .with(|a| a.handle_rrs_applied(keeper.node, 9, network, 1, &digest, T0 + 10_200))
            .0
    );
    assert!(
        !service
            .with(|a| a.handle_rrs_applied(leaver.node, 1, network, 1, &digest, T0 + 10_200))
            .0
    );
    assert!(
        !service
            .with(|a| a.handle_rrs_applied(keeper.node, 1, network, 99, &digest, T0 + 10_200))
            .0
    );
    assert!(
        !service
            .with(|a| {
                a.handle_rrs_applied(keeper.node, 1, network, 1, &[0xEE; 32], T0 + 10_200)
            })
            .0
    );
    assert_eq!(
        distribution_of(&service, op)
            .get("applied")
            .unwrap()
            .as_u64(),
        Some(0)
    );
    // The genuine ACK converges the operation.
    assert!(
        service
            .with(|a| a.handle_rrs_applied(keeper.node, 1, network, 1, &digest, T0 + 10_300))
            .0
    );
    let distribution = distribution_of(&service, op);
    assert_eq!(
        distribution.get("state").unwrap().as_str(),
        Some("converged")
    );
    assert_eq!(distribution.get("applied").unwrap().as_u64(), Some(1));
    assert_eq!(distribution.get("unknown").unwrap().as_u64(), Some(0));
}

/// V1-R01 (P6-1): what the daemon emits from `operations.get` is what the
/// client reads — the `committed → distributing → converged` top-level
/// state and the per-snapshot counts survive the client parser, and an
/// un-ACKed snapshot never parses as converged.
#[test]
fn operations_get_round_trips_through_the_client_parser() {
    use routeloom_client::api1::site::operation_from_json;

    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(&service, &transport, &mut keeper, "k", T0);
    join_member(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op, _) = revoke(&service, leaver.node, 1, "r-client", T0 + 10_000);
    let progress = || {
        let (view, _) = service.with(|a| a.operation_json(op).unwrap());
        operation_from_json(&json(&view)).expect("client parses operations.get")
    };
    let seen = progress();
    assert_eq!(seen.operation_id, format!("op-{op:016x}"));
    assert_eq!(seen.kind, "revoke");
    assert_eq!(seen.state, "committed");
    assert_eq!(seen.device, leaver.node);
    assert_eq!(seen.distribution.state, "pending");
    assert_eq!(
        (
            seen.distribution.applied,
            seen.distribution.retired,
            seen.distribution.unknown,
            seen.distribution.total
        ),
        (0, 0, 1, 1)
    );
    service.tick(T0 + 10_100);
    let seen = progress();
    assert_eq!(seen.state, "distributing");
    assert_eq!(seen.distribution.state, "distributing");
    assert_eq!(seen.distribution.unknown, 1);
    let object = sends.lock().unwrap().sent[0].1.clone();
    let digest = sha256(&object);
    assert!(
        service
            .with(|a| {
                a.handle_rrs_applied(keeper.node, 1, testkit::network(), 1, &digest, T0 + 10_200)
            })
            .0
    );
    let seen = progress();
    assert_eq!(seen.state, "converged");
    assert_eq!(seen.distribution.state, "converged");
    assert_eq!(
        (
            seen.distribution.applied,
            seen.distribution.retired,
            seen.distribution.unknown,
            seen.distribution.total
        ),
        (1, 0, 0, 1)
    );
}

/// V1-R01 (P6-1): un-ACKed targets get three attempts per operation
/// (5/10/20 s), then honestly stay `unknown`; a refusing transport
/// backs the whole outbox off instead of spinning.
#[test]
fn revocation_distribution_attempts_and_backoff() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(&service, &transport, &mut keeper, "k", T0);
    join_member(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op, _) = revoke(&service, leaver.node, 1, "r-try", T0 + 10_000);
    service.tick(T0 + 10_000);
    assert_eq!(sends.lock().unwrap().sent.len(), 1);
    service.tick(T0 + 14_999); // inside the 5 s backoff
    assert_eq!(sends.lock().unwrap().sent.len(), 1);
    service.tick(T0 + 15_000);
    assert_eq!(sends.lock().unwrap().sent.len(), 2);
    service.tick(T0 + 25_000); // +10 s
    assert_eq!(sends.lock().unwrap().sent.len(), 3);
    service.tick(T0 + 1_000_000); // exhausted: no fourth attempt
    assert_eq!(sends.lock().unwrap().sent.len(), 3);
    let distribution = distribution_of(&service, op);
    assert_eq!(
        distribution.get("state").unwrap().as_str(),
        Some("distributing")
    );
    assert_eq!(distribution.get("unknown").unwrap().as_u64(), Some(1));
    // A refusing transport backs off 5 s before the next dispatch.
    sends.lock().unwrap().refuse = true;
    sends.lock().unwrap().sent.clear();
    let mut third = SimDevice::new(0x00A1_0000_0000_7003, 0x73);
    join_member(&service, &transport, &mut third, "t", T0 + 20_000);
    let (op2, _) = revoke(&service, third.node, 1, "r-busy", T0 + 30_000);
    service.tick(T0 + 30_000);
    assert!(sends.lock().unwrap().sent.is_empty());
    service.tick(T0 + 34_999);
    assert!(sends.lock().unwrap().sent.is_empty());
    sends.lock().unwrap().refuse = false;
    service.tick(T0 + 35_000);
    assert_eq!(sends.lock().unwrap().sent.len(), 1);
    assert_eq!(
        distribution_of(&service, op2)
            .get("state")
            .unwrap()
            .as_str(),
        Some("distributing")
    );
}

/// V1-R01 (P6-1): a restart resumes the same operation from its durable
/// snapshot — the target is re-sent and its ACK still converges it.
#[test]
fn revocation_distribution_survives_restart() {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-site-rrs-restart-{}-{T0}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("site.db");
    let (keeper_node, op) = {
        let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
        let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
        join_member(&service, &transport, &mut keeper, "k", T0);
        join_member(&service, &transport, &mut leaver, "l", T0 + 5_000);
        let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
        service.with(|a| {
            a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
                shared: sends.clone(),
            })))
        });
        let (op, _) = revoke(&service, leaver.node, 1, "r-restart", T0 + 10_000);
        service.tick(T0 + 10_100);
        assert_eq!(sends.lock().unwrap().sent.len(), 1);
        (keeper.node, op)
    };
    let (service, _) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
    let distribution = distribution_of(&service, op);
    assert_eq!(
        distribution.get("state").unwrap().as_str(),
        Some("distributing")
    );
    assert_eq!(distribution.get("unknown").unwrap().as_u64(), Some(1));
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    service.tick(T0 + 20_000); // the un-ACKed target is re-sent, not rebuilt
    assert_eq!(sends.lock().unwrap().sent.len(), 1);
    let object = sends.lock().unwrap().sent[0].1.clone();
    let digest = sha256(&object);
    assert!(
        service
            .with(|a| {
                a.handle_rrs_applied(keeper_node, 1, testkit::network(), 1, &digest, T0 + 20_100)
            })
            .0
    );
    assert_eq!(
        distribution_of(&service, op).get("state").unwrap().as_str(),
        Some("converged")
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// V1-R01 (P6-1): a later revoke retires the removed device in older
/// operations, and an ACK for a newer set coalesces onto the older ones
/// it covers — epoch order alone never decides.
#[test]
fn revocation_retires_and_coalesces_across_operations() {
    let (service, transport) = service();
    let mut a = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut b = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    let mut c = SimDevice::new(0x00A1_0000_0000_7003, 0x73);
    join_member(&service, &transport, &mut a, "a", T0);
    join_member(&service, &transport, &mut b, "b", T0 + 5_000);
    join_member(&service, &transport, &mut c, "c", T0 + 10_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op1, _) = revoke(&service, a.node, 1, "r-a", T0 + 20_000);
    let (op2, _) = revoke(&service, b.node, 1, "r-b", T0 + 30_000);
    // op1's snapshot held B: B's removal retires it there, atomically.
    let first = distribution_of(&service, op1);
    assert_eq!(first.get("retired").unwrap().as_u64(), Some(1));
    assert_eq!(first.get("unknown").unwrap().as_u64(), Some(1)); // C only
    assert_eq!(
        distribution_of(&service, op2)
            .get("total")
            .unwrap()
            .as_u64(),
        Some(1)
    );
    // C ACKs the newest set (epoch 2): it covers both operations.
    service.tick(T0 + 30_100);
    let object = sends
        .lock()
        .unwrap()
        .sent
        .iter()
        .find(|(node, _)| *node == c.node)
        .unwrap()
        .1
        .clone();
    let digest = sha256(&object);
    assert!(
        service
            .with(|a| {
                a.handle_rrs_applied(c.node, 1, testkit::network(), 2, &digest, T0 + 30_200)
            })
            .0
    );
    assert_eq!(
        distribution_of(&service, op1)
            .get("state")
            .unwrap()
            .as_str(),
        Some("converged")
    );
    assert_eq!(
        distribution_of(&service, op2)
            .get("state")
            .unwrap()
            .as_str(),
        Some("converged")
    );
}

/// P6-1 (04 §9.1): the first Get on a site that never revoked bootstraps
/// the empty baseline set (rs_epoch 1, verifiable); a floor above the
/// Host's latest is an integrity error. The next revoke continues at 2.
#[test]
fn revocation_baseline_bootstrap_on_first_get() {
    let (service1, _) = service();
    let object = service1.with(|a| a.handle_rrs_get(0, T0)).0.unwrap();
    let (set, ok) = revocation_object_verify(
        &object,
        &testkit::sak().pubkey(),
        testkit::SITE,
        testkit::network(),
    )
    .unwrap();
    assert!(ok);
    assert_eq!(set.rs_epoch, 1);
    assert!(set.entries.is_empty());
    assert_eq!(
        service1
            .with(|a| a.handle_rrs_get(9, T0 + 1))
            .0
            .unwrap_err()
            .code,
        "INTEGRITY_ERROR"
    );
    let (service2, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(&service2, &transport, &mut keeper, "k", T0);
    join_member(&service2, &transport, &mut leaver, "l", T0 + 5_000);
    service2
        .with(|a| a.handle_rrs_get(0, T0 + 6_000))
        .0
        .unwrap();
    let (op, _) = revoke(&service2, leaver.node, 1, "r-base", T0 + 10_000);
    let (view, _) = service2.with(|a| a.operation_json(op).unwrap());
    assert_eq!(json(&view).get("rs_epoch").unwrap().as_u64(), Some(2));
}

/// P6-1 (04 §2): a staged GK the removed device may hold is never
/// reused — the next revoke stages a fresh key. An unexposed staged key
/// is still reused (one rotation per removal).
#[test]
fn revocation_replaces_exposed_staged_key() {
    let (service, transport) = service();
    let mut a = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut b = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    let mut c = SimDevice::new(0x00A1_0000_0000_7003, 0x73);
    join_member(&service, &transport, &mut a, "a", T0);
    join_member(&service, &transport, &mut b, "b", T0 + 5_000);
    join_member(&service, &transport, &mut c, "c", T0 + 10_000);
    revoke(&service, a.node, 1, "r-1", T0 + 20_000);
    let staged = service.with(|auth| auth.gk_staged.clone().unwrap()).0;
    assert!(service.with(|auth| auth.mark_gk_staged_distributed()).0);
    revoke(&service, b.node, 1, "r-2", T0 + 30_000);
    let replaced = service.with(|auth| auth.gk_staged.clone().unwrap()).0;
    assert_eq!(replaced.epoch, staged.epoch);
    assert_ne!(replaced.key, staged.key);
    // Unexposed again: the next revoke reuses the staged key.
    revoke(&service, c.node, 1, "r-3", T0 + 40_000);
    let reused = service.with(|auth| auth.gk_staged.clone().unwrap()).0;
    assert_eq!(reused.key, replaced.key);
}
