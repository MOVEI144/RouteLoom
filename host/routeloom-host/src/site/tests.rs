//! Site Authority core tests (plan P3-3; acceptance IDs of 02 §14, 04 §11
//! and 07 §8 named per test). Devices are simulated with the Rust EDHOC
//! Initiator and routeloom-join's device-side checks (testkit).

use std::sync::Arc;

use routeloom_join::JoinResult;
use routeloom_provision::sdkv1::revocation::{revocation_object_verify, RevocationReason};

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
    let (view, _) = service.with(|a| {
        a.operation_json(records::parse_op_token(&op).unwrap())
            .unwrap()
    });
    let view = json(&view);
    assert_eq!(
        view.get("distribution")
            .unwrap()
            .get("state")
            .unwrap()
            .as_str(),
        Some("not_implemented")
    );
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
