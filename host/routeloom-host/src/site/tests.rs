//! Site Authority core tests (plan P3-3; acceptance IDs of 02 §14, 04 §11
//! and 07 §8 named per test). Devices are simulated with the Rust EDHOC
//! Initiator and routeloom-join's device-side checks (testkit).

use std::sync::Arc;

use routeloom_join::JoinResult;
use routeloom_provision::sdkv1::revocation::{revocation_object_verify, RevocationReason};

use super::group_keys::{
    gk_id, AckOutcome, ConfirmOutcome, GroupKeyAck, GroupKeyCommand, GroupKeyPull, HostTime,
    PullOutcome, RotationCause, TargetState,
};
use super::records::{Verdict, ROLE_ENDPOINT, ROLE_RELAY};
use super::store::{Batch, DeviceRow, MemoryStore, SqliteSiteStore};
use super::testkit::{self, kinds, request_id, FakeGroupKeyTransport, Outcome, SimDevice};
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

/// Joins one device end to end (Allow delivered and verified).
fn join_member(
    service: &SiteService,
    transport: &InProcessTransport,
    node: u64,
    seed: u8,
    now: u64,
) -> SimDevice {
    let mut device = SimDevice::new(node, seed);
    let (mut exchange, _, events) = device.start(service, transport, now);
    decide(
        service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        &format!("allow-{node:016x}"),
        now + 10,
    )
    .unwrap();
    assert!(
        matches!(
            device.finish(&mut exchange, transport),
            Outcome::Result(JoinResult::Allow { .. })
        ),
        "join of {node:016x} failed"
    );
    device
}

fn revoke(
    service: &SiteService,
    device: u64,
    generation: u32,
    key: &str,
    now: u64,
) -> Result<String, SiteError> {
    service
        .with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device,
                    expected_generation: generation,
                    reason: RevocationReason::Removed,
                    key: key.into(),
                },
                HostTime::sync(now),
            )
        })
        .0
}

fn gk_rotation_of(answer: &str) -> (u32, u32) {
    let rotation = json(answer).get("gk_rotation").unwrap().clone();
    (
        u32::try_from(rotation.get("from").unwrap().as_u64().unwrap()).unwrap(),
        u32::try_from(rotation.get("to").unwrap().as_u64().unwrap()).unwrap(),
    )
}

/// A service with the fake GK transport attached (the PR1 channel seam).
fn gk_service() -> (
    SiteService,
    Arc<InProcessTransport>,
    Arc<FakeGroupKeyTransport>,
) {
    let (service, transport) = service();
    let gk = FakeGroupKeyTransport::new();
    service.set_group_key_transport(gk.clone());
    (service, transport, gk)
}

fn rotate(service: &SiteService, expected: u32, key: &str, now: u64) -> Result<String, SiteError> {
    service
        .with(|a| {
            a.rotate(
                KGUARD,
                RotateRequest {
                    expected_active_epoch: expected,
                    key: key.into(),
                },
                HostTime::sync(now),
            )
        })
        .0
}

fn gk_status(service: &SiteService, now: u64) -> routeloom_json::Json {
    let (status, _) = service.with(|a| a.group_keys_status_json(HostTime::sync(now)));
    json(&status)
}

/// Channel identity of a joined member, as the channel layer would report.
fn channel_id(service: &SiteService, node: u64) -> ([u8; 32], u32, [u8; 32]) {
    service
        .with(|a| {
            let row = &a.devices[&node];
            (row.kid, row.generation, row.dams)
        })
        .0
}

/// The ACK a member sends for a received key (GK-id over the key bytes,
/// exactly like the device computes it).
fn member_ack(
    service: &SiteService,
    node: u64,
    epoch: u32,
    key: &[u8; 32],
    result: u8,
    stored: u8,
) -> GroupKeyAck {
    let (kid, generation, dams) = channel_id(service, node);
    GroupKeyAck {
        node,
        kid,
        generation,
        dams,
        epoch,
        gk_id: gk_id(testkit::network(), epoch, key),
        result,
        stored_state: stored,
    }
}

fn ack_key(
    service: &SiteService,
    node: u64,
    epoch: u32,
    key: &[u8; 32],
    stored: u8,
    now: u64,
) -> AckOutcome {
    let ack = member_ack(service, node, epoch, key, 0, stored);
    service
        .with(|a| a.on_group_key_ack(ack, HostTime::sync(now)))
        .0
}

fn member_pull(
    service: &SiteService,
    node: u64,
    current: u32,
    next: u32,
    reason: u8,
) -> GroupKeyPull {
    let (kid, generation, dams) = channel_id(service, node);
    GroupKeyPull {
        node,
        kid,
        generation,
        dams,
        current,
        next,
        reason,
    }
}

fn pull(
    service: &SiteService,
    node: u64,
    current: u32,
    next: u32,
    reason: u8,
    now: u64,
) -> PullOutcome {
    let pull = member_pull(service, node, current, next, reason);
    service
        .with(|a| a.on_group_key_pull(pull, HostTime::sync(now)))
        .0
}

/// The (epoch, key) of the latest Update for `node`.
fn update_key(commands: &[GroupKeyCommand], node: u64) -> (u32, [u8; 32]) {
    commands
        .iter()
        .find_map(|c| match c {
            GroupKeyCommand::Update {
                node: n,
                epoch,
                key,
                ..
            } if *n == node => Some((*epoch, *key.bytes())),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no Update for {node:016x}"))
}

fn updates_of(commands: &[GroupKeyCommand]) -> Vec<(u64, u32)> {
    commands
        .iter()
        .filter_map(|c| match c {
            GroupKeyCommand::Update { node, epoch, .. } => Some((*node, *epoch)),
            _ => None,
        })
        .collect()
}

fn activates_of(commands: &[GroupKeyCommand]) -> Vec<(u64, u32)> {
    commands
        .iter()
        .filter_map(|c| match c {
            GroupKeyCommand::Activate { node, epoch, .. } => Some((*node, *epoch)),
            _ => None,
        })
        .collect()
}

/// The GK-id an Activate carries (never the key itself).
fn activate_id(commands: &[GroupKeyCommand], node: u64) -> [u8; 32] {
    commands
        .iter()
        .find_map(|c| match c {
            GroupKeyCommand::Activate { node: n, gk_id, .. } if *n == node => Some(*gk_id),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no Activate for {node:016x}"))
}

fn wakes_of(commands: &[GroupKeyCommand]) -> Vec<u64> {
    commands
        .iter()
        .filter_map(|c| match c {
            GroupKeyCommand::Wake { node } => Some(*node),
            _ => None,
        })
        .collect()
}

fn secret_rows(service: &SiteService) -> usize {
    service.with(|a| a.store.load().unwrap().group_keys.len()).0
}

/// A store whose next commit fails (fault injection).
fn failing_store() -> MemoryStore {
    let mut failing = MemoryStore::default();
    failing.fail_next = 1;
    failing
}

/// Pre-fills a store with `members` live rows plus an active key (the fast
/// path to cap and rate tests; the join flow itself is covered elsewhere).
fn member_rows(members: usize, active_epoch: u32) -> MemoryStore {
    let mut store = MemoryStore::default();
    let devices: Vec<DeviceRow> = (0..members)
        .map(|i| DeviceRow {
            node: 0x00A1_0000_0000_0000 + 0x1000 + i as u64,
            kid: [((i % 251) + 1) as u8; 32],
            member: true,
            generation: 1,
            role: 1,
            dams: [((i % 251) + 1) as u8; 32],
            approved_ms: T0,
            ..DeviceRow::default()
        })
        .collect();
    store
        .commit(&Batch {
            devices,
            group_keys: vec![crate::site::store::GroupKeyRow {
                epoch: active_epoch,
                key: [0x11; 32],
                state: "active".into(),
                created_ms: T0,
            }],
            meta: vec![(
                crate::site::group_keys::META_HIGH_WATER,
                active_epoch.to_be_bytes().to_vec(),
            )],
            ..Batch::default()
        })
        .unwrap();
    store
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
    let (cert_hash, dams) = service
        .with(|a| {
            let row = &a.devices[&device.node];
            (
                routeloom_provision::sha256::sha256(&row.member_cert),
                row.dams,
            )
        })
        .0;
    let (confirmed, events) =
        service.with(|a| a.member_confirmed(device.node, 1, &cert_hash, &dams, later + 900));
    assert_eq!(confirmed, ConfirmOutcome::Confirmed);
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
    service.tick(HostTime::sync(T0 + 1_999));
    assert!(matches!(
        device.finish(&mut exchange, &transport),
        Outcome::Waiting
    ));
    service.tick(HostTime::sync(T0 + 2_000));
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
    service.tick(HostTime::sync(T0 + 2_000));
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
    service.tick(HostTime::sync(T0 + 2_000)); // pending delivered; request stays open
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
        service.tick(HostTime::sync(T0 + 2_000));
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
    let revoke = |generation, key: &str, now: u64| {
        service.with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: device.node,
                    expected_generation: generation,
                    reason: RevocationReason::Lost,
                    key: key.into(),
                },
                HostTime::sync(now),
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
    let (status, _) = service.with(|a| a.status_json(HostTime::sync(T0)));
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
    service.tick(HostTime::sync(T0 + 5_000));
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
            HostTime::sync(T0 + 50),
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
            HostTime::sync(T0 + 20),
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
                HostTime::sync(T0 + 20),
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
            HostTime::sync(T0 + 200),
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
    service.tick(HostTime::sync(T0 + 300 + 2_000)); // KGuard silent → pending, request open
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
            HostTime::sync(T0 + 2_320),
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

/// G-SEC P5 (Issue #96) PR3, design §6.3: removing a second member never
/// reuses the staged key — each removal mints a fresh epoch, and the
/// removed member is never queued the new key.
#[test]
fn review_second_removal_mints_a_fresh_epoch() {
    let (service, transport) = service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_9001, 0x91, T0);
    let b = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_9002,
        0x92,
        T0 + 1_000,
    );
    // The first removal stages epoch 2.
    let first = revoke(&service, a.node, 1, "rv-a", T0 + 2_000).unwrap();
    assert_eq!(gk_rotation_of(&first), (1, 2));
    // The second removal must mint epoch 3: the staged epoch 2 may already
    // be known to the first victim, so reusing it would hand the new key
    // to a removed device.
    let second = revoke(&service, b.node, 1, "rv-b", T0 + 3_000).unwrap();
    assert_eq!(gk_rotation_of(&second), (1, 3));
}

/// G-SEC P5 PR3 (V1-K06/K07 host, V1-H05): the 24 h periodic rotation —
/// stage, durable staged-ACKs, early activation, Activates, convergence —
/// with honest operation views and secret hygiene throughout.
#[test]
fn gk_periodic_rotation_converges_end_to_end() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_A001, 0xA1, T0);
    let b = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_A002,
        0xA2,
        T0 + 1_000,
    );
    gk.set_ready(a.node, true);
    gk.set_ready(b.node, true);
    // Nothing before the period elapses.
    service.tick(HostTime::sync(T0 + 3_600_000));
    assert!(gk.take().is_empty());
    let status = gk_status(&service, T0 + 3_600_000);
    assert_eq!(status.get("phase").unwrap().as_str(), Some("stable"));
    assert_eq!(status.get("active").unwrap().as_u64(), Some(1));
    assert_eq!(
        status.get("next_due_ms").unwrap().as_u64(),
        Some(T0 + 86_400_000)
    );
    // 24 h after activation the tick stages epoch 2; sends flow on the
    // tick (the staging tick only commits).
    let due = T0 + 86_400_000 + 1;
    service.tick(HostTime::sync(due));
    assert!(gk.take().is_empty());
    service.tick(HostTime::sync(due));
    let staged = gk.take();
    assert_eq!(updates_of(&staged), vec![(a.node, 2), (b.node, 2)]);
    for command in &staged {
        let GroupKeyCommand::Update {
            cause, overlap_s, ..
        } = command
        else {
            panic!("expected Updates, got {command:?}");
        };
        assert_eq!((*cause, *overlap_s), (RotationCause::Periodic, 60));
    }
    // One staged key for every member.
    let (epoch_a, key_a) = update_key(&staged, a.node);
    let (epoch_b, key_b) = update_key(&staged, b.node);
    assert_eq!((epoch_a, epoch_b), (2, 2));
    assert_eq!(key_a, key_b);
    assert_eq!(secret_rows(&service), 2);
    let status = gk_status(&service, due);
    assert_eq!(status.get("phase").unwrap().as_str(), Some("staging"));
    assert_eq!(status.get("cause").unwrap().as_str(), Some("periodic"));
    assert_eq!(status.get("targets").unwrap().as_u64(), Some(2));
    assert_eq!(status.get("unknown").unwrap().as_u64(), Some(2));
    // The operation view distributes.
    let op_id = service
        .with(|a| a.gks.rotation().unwrap().row.operation_id)
        .0;
    let (view, _) = service.with(|a| a.operation_json(op_id).unwrap());
    let view = json(&view);
    assert_eq!(view.get("kind").unwrap().as_str(), Some("rotate"));
    assert_eq!(view.get("state").unwrap().as_str(), Some("distributing"));
    // The first staged-ACK records evidence without activating.
    assert_eq!(
        ack_key(&service, a.node, 2, &key_a, 1, due + 1_000),
        AckOutcome::StagedRecorded
    );
    assert!(gk.take().is_empty(), "staging sends no Activates");
    let status = gk_status(&service, due + 1_000);
    assert_eq!(status.get("staged_ack").unwrap().as_u64(), Some(1));
    // Full staged evidence activates early, before the deadline.
    let ack_b = member_ack(&service, b.node, 2, &key_b, 0, 1);
    let (outcome, events) =
        service.with(|a| a.on_group_key_ack(ack_b, HostTime::sync(due + 2_000)));
    assert_eq!(outcome, AckOutcome::StagedRecorded);
    assert!(
        kinds(&events).contains(&"gk.rotated".to_string()),
        "{events:?}"
    );
    let rotated = events
        .iter()
        .find(|(_, f)| f.contains("gk.rotated"))
        .unwrap();
    assert!(rotated.1.contains("\"unknown\":0"), "{}", rotated.1);
    assert_eq!(
        gk_status(&service, due + 2_000)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("activating")
    );
    // Activation deleted the old secret row before any Activate went out.
    assert_eq!(secret_rows(&service), 1);
    let activated = gk.take();
    assert_eq!(activates_of(&activated), vec![(a.node, 2), (b.node, 2)]);
    // The Activate identifies the key without exporting it.
    assert_eq!(
        activate_id(&activated, a.node),
        gk_id(testkit::network(), 2, &key_a)
    );
    // Active-ACKs converge: rotation deleted, operation converged.
    assert_eq!(
        ack_key(&service, a.node, 2, &key_a, 2, due + 3_000),
        AckOutcome::ActiveRecorded
    );
    assert_eq!(
        ack_key(&service, b.node, 2, &key_b, 2, due + 3_000),
        AckOutcome::ActiveRecorded
    );
    let status = gk_status(&service, due + 3_000);
    assert_eq!(status.get("phase").unwrap().as_str(), Some("stable"));
    assert_eq!(status.get("active").unwrap().as_u64(), Some(2));
    assert!(status.get("staged").unwrap().is_null());
    let last = status.get("last_rotation").unwrap();
    assert_eq!(last.get("from").unwrap().as_u64(), Some(1));
    assert_eq!(last.get("to").unwrap().as_u64(), Some(2));
    assert_eq!(last.get("cause").unwrap().as_str(), Some("periodic"));
    let typed = service.with(|a| a.gks.last_rotation()).0.unwrap();
    assert_eq!((typed.from_epoch, typed.to_epoch), (1, 2));
    assert_eq!(
        status.get("next_due_ms").unwrap().as_u64(),
        Some(due + 2_000 + 86_400_000)
    );
    let (view, _) = service.with(|a| a.operation_json(op_id).unwrap());
    assert_eq!(
        json(&view).get("state").unwrap().as_str(),
        Some("converged")
    );
}

/// G-SEC P5 PR3 (V1-K06 host): the staging deadline activates with
/// unknowns honestly kept, and a behind member repairs through
/// Update(active) before it stages (§6.3).
#[test]
fn gk_staging_deadline_activates_with_unknowns() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_B001, 0xB1, T0);
    let b = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_B002,
        0xB2,
        T0 + 1_000,
    );
    gk.set_ready(a.node, true);
    gk.set_ready(b.node, true);
    let t = T0 + 2_000;
    rotate(&service, 1, "m1", t).unwrap();
    service.tick(HostTime::sync(t));
    let staged = gk.take();
    assert_eq!(updates_of(&staged), vec![(a.node, 2), (b.node, 2)]);
    // B pulls while current with the host active key: nothing to repair,
    // but the contact re-arms its retry round.
    assert_eq!(
        pull(&service, b.node, 1, 0, 2, t + 1_000),
        PullOutcome::Answered
    );
    // A stages; B stays silent past the 60 s manual deadline.
    let (_, key_a) = update_key(&staged, a.node);
    assert_eq!(
        ack_key(&service, a.node, 2, &key_a, 1, t + 2_000),
        AckOutcome::StagedRecorded
    );
    // B's re-armed round sent its Update from the ACK's send flush.
    assert_eq!(updates_of(&gk.take()), vec![(b.node, 2)]);
    let events = service.tick(HostTime::sync(t + 60_000));
    assert!(kinds(&events).contains(&"gk.rotated".to_string()));
    let rotated = events
        .iter()
        .find(|(_, f)| f.contains("gk.rotated"))
        .unwrap();
    assert!(rotated.1.contains("\"unknown\":1"), "{}", rotated.1);
    // A gets its Activate; B (still pending) gets Update(2) again.
    let round = gk.take();
    assert_eq!(activates_of(&round), vec![(a.node, 2)]);
    assert_eq!(updates_of(&round), vec![(b.node, 2)]);
    let status = gk_status(&service, t + 60_000);
    assert_eq!(
        status.get("phase").unwrap().as_str(),
        Some("catching_up"),
        "first Activate round done with a straggler"
    );
    // A converges; B repairs late through the normal target flow.
    let (_, key_a2) = update_key(&staged, a.node);
    assert_eq!(
        ack_key(&service, a.node, 2, &key_a2, 2, t + 61_000),
        AckOutcome::ActiveRecorded
    );
    let (_, key_b) = update_key(&round, b.node);
    assert_eq!(
        ack_key(&service, b.node, 2, &key_b, 1, t + 62_000),
        AckOutcome::StagedRecorded
    );
    let round = gk.take();
    assert_eq!(activates_of(&round), vec![(b.node, 2)]);
    assert_eq!(
        ack_key(&service, b.node, 2, &key_b, 2, t + 63_000),
        AckOutcome::ActiveRecorded
    );
    assert_eq!(
        gk_status(&service, t + 63_000)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("stable")
    );
}

/// G-SEC P5 PR3 (V1-K07 host): revoking a staged member supersedes with a
/// fresh epoch — the old staged ACKs go stale and the removed member never
/// sees the new key.
#[test]
fn gk_revoke_supersedes_staging_with_fresh_epoch() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_C001, 0xC1, T0);
    let b = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_C002,
        0xC2,
        T0 + 1_000,
    );
    gk.set_ready(a.node, true);
    gk.set_ready(b.node, true);
    rotate(&service, 1, "m1", T0 + 2_000).unwrap();
    service.tick(HostTime::sync(T0 + 2_000));
    let staged = gk.take();
    let (_, key_a) = update_key(&staged, a.node);
    assert_eq!(
        ack_key(&service, a.node, 2, &key_a, 1, T0 + 3_000),
        AckOutcome::StagedRecorded
    );
    let first_op = service
        .with(|a| a.gks.rotation().unwrap().row.operation_id)
        .0;
    // Revoking the staged member mints epoch 3 over the survivors only.
    let answer = revoke(&service, a.node, 1, "rv-a", T0 + 4_000).unwrap();
    assert_eq!(gk_rotation_of(&answer), (1, 3));
    let status = gk_status(&service, T0 + 4_000);
    assert_eq!(status.get("targets").unwrap().as_u64(), Some(1));
    assert_eq!(status.get("cause").unwrap().as_str(), Some("removal"));
    let (view, _) = service.with(|a| a.operation_json(first_op).unwrap());
    assert_eq!(
        json(&view).get("state").unwrap().as_str(),
        Some("superseded")
    );
    // The old staged ACKs are stale now; only two secret rows exist.
    let (_, key_b_old) = update_key(&staged, b.node);
    assert_eq!(
        ack_key(&service, b.node, 2, &key_b_old, 1, T0 + 5_000),
        AckOutcome::Stale {
            reason: "ack_epoch"
        }
    );
    assert_eq!(secret_rows(&service), 2);
    // B converges on epoch 3; A never sees it.
    service.tick(HostTime::sync(T0 + 5_000));
    let restaged = gk.take();
    assert_eq!(updates_of(&restaged), vec![(b.node, 3)]);
    let (_, key_b) = update_key(&restaged, b.node);
    assert_ne!(key_b, key_b_old, "the superseding key is fresh");
    assert_eq!(
        ack_key(&service, b.node, 3, &key_b, 1, T0 + 6_000),
        AckOutcome::StagedRecorded
    );
    let round = gk.take();
    assert_eq!(activates_of(&round), vec![(b.node, 3)]);
    assert_eq!(
        ack_key(&service, b.node, 3, &key_b, 2, T0 + 7_000),
        AckOutcome::ActiveRecorded
    );
    assert_eq!(
        gk_status(&service, T0 + 7_000)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("stable")
    );
    for command in gk.take() {
        assert_ne!(command.node(), a.node, "removed member must see no key");
    }
}

/// G-SEC P5 PR3 (§6.3): consecutive removals keep the first removal
/// batch's staging deadline instead of extending it.
#[test]
fn gk_consecutive_removals_keep_first_deadline() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_D001, 0xD1, T0);
    let b = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_D002,
        0xD2,
        T0 + 1_000,
    );
    let c = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_D003,
        0xD3,
        T0 + 2_000,
    );
    for node in [a.node, b.node, c.node] {
        gk.set_ready(node, true);
    }
    revoke(&service, a.node, 1, "rv-a", T0 + 3_000).unwrap();
    let first_deadline = service.with(|a| a.gks.rotation().unwrap().deadline_mono).0;
    assert_eq!(first_deadline, T0 + 3_000 + 30_000);
    revoke(&service, b.node, 1, "rv-b", T0 + 10_000).unwrap();
    let kept = service.with(|a| a.gks.rotation().unwrap().deadline_mono).0;
    assert_eq!(kept, first_deadline, "no extension on a new removal");
    // The first deadline activates epoch 3, not a pushed-back one.
    service.tick(HostTime::sync(first_deadline));
    assert_eq!(
        gk_status(&service, first_deadline)
            .get("active")
            .unwrap()
            .as_u64(),
        Some(3)
    );
}

/// G-SEC P5 PR3 (§6.3): an allow during staging joins the newcomer to the
/// rotation's targets in the same transaction — the deadline never moves —
/// while its SitePackage still carries the current active key.
#[test]
fn gk_allow_during_staging_joins_targets() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_E001, 0xE1, T0);
    gk.set_ready(a.node, true);
    rotate(&service, 1, "m1", T0 + 1_000).unwrap();
    let deadline = service.with(|a| a.gks.rotation().unwrap().deadline_mono).0;
    // A newcomer joins mid-staging.
    let mut b = SimDevice::new(0x00A1_0000_0000_E002, 0xE2);
    let (mut exchange, _, events) = b.start(&service, &transport, T0 + 2_000);
    decide(
        &service,
        request_id(&events).unwrap(),
        b.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "allow-b",
        T0 + 2_010,
    )
    .unwrap();
    let Outcome::Result(JoinResult::Allow { site_package, .. }) =
        b.finish(&mut exchange, &transport)
    else {
        panic!("expected Allow");
    };
    assert_eq!(site_package.gk_epoch, 1, "joins carry the active key");
    gk.set_ready(b.node, true);
    // Same transaction, same deadline, one more target.
    assert_eq!(
        service.with(|a| a.gks.rotation().unwrap().deadline_mono).0,
        deadline
    );
    assert_eq!(
        gk_status(&service, T0 + 2_010)
            .get("targets")
            .unwrap()
            .as_u64(),
        Some(2)
    );
    service.tick(HostTime::sync(T0 + 3_000));
    let sent = gk.take();
    assert_eq!(updates_of(&sent), vec![(a.node, 2), (b.node, 2)]);
}

/// G-SEC P5 PR3 (§6.3/§6.4): manual rotate rules — idempotent replay,
/// expected-epoch conflict, BUSY while distributing or cleaning up, and a
/// revocation preempting where a second rotate waits.
#[test]
fn gk_manual_rotate_api_rules() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_F001, 0xF1, T0);
    gk.set_ready(a.node, true);
    // Wrong expectation first: conflict, nothing staged.
    assert_eq!(
        rotate(&service, 7, "m1", T0 + 1_000).unwrap_err().code,
        "CONFLICT"
    );
    assert!(service.with(|a| a.gks.rotation().is_none()).0);
    let first = rotate(&service, 1, "m1", T0 + 1_000).unwrap();
    assert_eq!(gk_rotation_answer(&first), (1, 2));
    // Same key replays the committed answer; another key waits BUSY.
    assert_eq!(rotate(&service, 1, "m1", T0 + 1_100).unwrap(), first);
    let busy = rotate(&service, 1, "m2", T0 + 1_100).unwrap_err();
    assert_eq!(busy.code, "BUSY");
    assert!(busy.retryable);
    // A revocation preempts the manual staging with a fresh epoch.
    let answer = revoke(&service, a.node, 1, "rv-a", T0 + 2_000).unwrap();
    assert_eq!(gk_rotation_of(&answer), (1, 3));
    // Zero survivors: the rotation converges on the next tick.
    service.tick(HostTime::sync(T0 + 2_000));
    assert_eq!(
        gk_status(&service, T0 + 2_000)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("stable")
    );
    assert_eq!(
        gk_status(&service, T0 + 2_000)
            .get("active")
            .unwrap()
            .as_u64(),
        Some(3)
    );
    // Inside the 60 s cleanup window a further rotate waits BUSY.
    let busy = rotate(&service, 3, "m3", T0 + 30_000).unwrap_err();
    assert_eq!(busy.code, "BUSY");
    // Past the window it stages again.
    let third = rotate(&service, 3, "m4", T0 + 62_001).unwrap();
    assert_eq!(gk_rotation_answer(&third), (3, 4));

    fn gk_rotation_answer(answer: &str) -> (u32, u32) {
        let parsed = json(answer);
        (
            u32::try_from(parsed.get("from").unwrap().as_u64().unwrap()).unwrap(),
            u32::try_from(parsed.get("to").unwrap().as_u64().unwrap()).unwrap(),
        )
    }
}

/// G-SEC P5 PR3 (§6.1): 128 live members rotate; the 129th allow is
/// refused before commit.
#[test]
fn gk_member_cap_128() {
    let store = member_rows(128, 5);
    let service = SiteService::new(testkit::authority(Box::new(store), T0));
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    let gk = FakeGroupKeyTransport::new();
    service.set_group_key_transport(gk.clone());
    // The 129th member cannot join.
    let mut extra = SimDevice::new(0x00A1_0000_0000_FF00, 0xF0);
    let (_, _, events) = extra.start(&service, &transport, T0 + 1_000);
    let error = decide(
        &service,
        request_id(&events).unwrap(),
        extra.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "allow-129",
        T0 + 1_010,
    )
    .unwrap_err();
    assert_eq!(error.code, "NO_CAPACITY");
    // But 128 targets rotate fine.
    for i in 0..128 {
        gk.set_ready(0x00A1_0000_0000_0000 + 0x1000 + i, true);
    }
    let answer = rotate(&service, 5, "m1", T0 + 2_000).unwrap();
    assert_eq!(json(&answer).get("targets").unwrap().as_u64(), Some(128));
    service.tick(HostTime::sync(T0 + 2_000));
    assert_eq!(updates_of(&gk.take()).len(), 4, "burst of four");
}

/// G-SEC P5 PR3 (§6.1): a migrated database past the cap refuses new
/// rotations explicitly without truncating targets — and revoking down
/// re-enables them.
#[test]
fn gk_overcap_migrated_db_refuses_rotations() {
    let store = member_rows(129, 5);
    let service = SiteService::new(testkit::authority(Box::new(store), T0));
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    let gk = FakeGroupKeyTransport::new();
    service.set_group_key_transport(gk.clone());
    // Reads still work; rotations refuse explicitly.
    assert_eq!(
        gk_status(&service, T0).get("active").unwrap().as_u64(),
        Some(5)
    );
    let error = rotate(&service, 5, "m1", T0 + 1_000).unwrap_err();
    assert_eq!(error.code, "NO_CAPACITY");
    assert!(error.message.contains("129"), "{}", error.message);
    assert!(service.with(|a| a.gks.rotation().is_none()).0);
    // Revoking down to 128 re-enables the rotation with all survivors.
    let victim = 0x00A1_0000_0000_0000 + 0x1000;
    let answer = revoke(&service, victim, 1, "rv", T0 + 2_000).unwrap();
    assert_eq!(gk_rotation_of(&answer), (5, 6));
    assert_eq!(
        gk_status(&service, T0 + 2_000)
            .get("targets")
            .unwrap()
            .as_u64(),
        Some(128)
    );
}

/// G-SEC P5 PR3 (§4/§6.3): the DAMS incarnation fence — reports from a
/// retired channel are stale, only the current incarnation counts.
#[test]
fn gk_dams_fence_retires_old_channel() {
    let (service, transport, gk) = gk_service();
    let mut a = join_member(&service, &transport, 0x00A1_0000_0000_AA01, 0xAA, T0);
    gk.set_ready(a.node, true);
    rotate(&service, 1, "m1", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let staged = gk.take();
    let (_, key) = update_key(&staged, a.node);
    let (kid, generation, dams1) = channel_id(&service, a.node);
    // The member re-joins (reissue): a fresh DAMS incarnation.
    let (outcome, _) = a.attempt(&service, &transport, T0 + 30_000);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::Allow { .. })),
        "{outcome:?}"
    );
    let (_, _, dams2) = channel_id(&service, a.node);
    assert_ne!(dams1, dams2);
    // The old incarnation's ACK is stale.
    let stale = GroupKeyAck {
        node: a.node,
        kid,
        generation,
        dams: dams1,
        epoch: 2,
        gk_id: gk_id(testkit::network(), 2, &key),
        result: 0,
        stored_state: 1,
    };
    let (outcome, _) = service.with(|a| a.on_group_key_ack(stale, HostTime::sync(T0 + 31_000)));
    assert_eq!(
        outcome,
        AckOutcome::Stale {
            reason: "ack_fence"
        }
    );
    // So is its pull.
    let stale_pull = GroupKeyPull {
        node: a.node,
        kid,
        generation,
        dams: dams1,
        current: 1,
        next: 0,
        reason: 2,
    };
    let (outcome, _) =
        service.with(|a| a.on_group_key_pull(stale_pull, HostTime::sync(T0 + 31_000)));
    assert_eq!(
        outcome,
        PullOutcome::Rejected {
            reason: "pull_fence"
        }
    );
    // The current incarnation records.
    assert_eq!(
        ack_key(&service, a.node, 2, &key, 1, T0 + 32_000),
        AckOutcome::StagedRecorded
    );
}

/// G-SEC P5 PR3 (§6.2): distribution holds 10 commands/s with a burst of
/// four across a full 128-target rotation.
#[test]
fn gk_send_rate_is_bounded() {
    let store = member_rows(128, 5);
    let service = SiteService::new(testkit::authority(Box::new(store), T0));
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    let gk = FakeGroupKeyTransport::new();
    service.set_group_key_transport(gk.clone());
    for i in 0..128 {
        gk.set_ready(0x00A1_0000_0000_0000 + 0x1000 + i, true);
    }
    rotate(&service, 5, "m1", T0).unwrap();
    service.tick(HostTime::sync(T0));
    assert_eq!(updates_of(&gk.take()).len(), 4);
    service.tick(HostTime::sync(T0 + 100));
    assert_eq!(updates_of(&gk.take()).len(), 1);
    service.tick(HostTime::sync(T0 + 200));
    assert_eq!(updates_of(&gk.take()).len(), 1);
    // Draining the round reaches every target exactly once per round.
    let mut total = 6;
    for step in 3..200 {
        service.tick(HostTime::sync(T0 + step * 100));
        let sent = gk.take();
        total += updates_of(&sent).len();
        if total >= 128 {
            break;
        }
    }
    assert_eq!(total, 128);
}

/// G-SEC P5 PR3 (§6.3): a member two epochs behind converges to the host
/// active key first and only stages after its active ACK.
#[test]
fn gk_pull_behind_stages_active_first() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_AB01, 0xAB, T0);
    let b = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_AB02,
        0xAC,
        T0 + 1_000,
    );
    gk.set_ready(a.node, true);
    gk.set_ready(b.node, true);
    // Epoch 2 activates while B sleeps through it.
    rotate(&service, 1, "m1", T0 + 2_000).unwrap();
    service.tick(HostTime::sync(T0 + 2_000));
    let staged = gk.take();
    let (_, key_a) = update_key(&staged, a.node);
    assert_eq!(
        ack_key(&service, a.node, 2, &key_a, 1, T0 + 3_000),
        AckOutcome::StagedRecorded
    );
    gk.take();
    service.tick(HostTime::sync(T0 + 62_000));
    let round = gk.take();
    assert_eq!(activates_of(&round), vec![(a.node, 2)]);
    assert_eq!(
        ack_key(&service, a.node, 2, &key_a, 2, T0 + 63_000),
        AckOutcome::ActiveRecorded
    );
    // A straggler never blocks the next rotation: epoch 3 stages.
    let t = T0 + 130_000;
    rotate(&service, 2, "m2", t).unwrap();
    assert_eq!(
        gk_status(&service, t).get("phase").unwrap().as_str(),
        Some("staging")
    );
    // B wakes two epochs behind: Update(active 2) comes before Update(3).
    assert_eq!(
        pull(&service, b.node, 1, 0, 2, t + 1_000),
        PullOutcome::Answered
    );
    service.tick(HostTime::sync(t + 1_000));
    let sent = gk.take();
    let b_updates = updates_of(&sent)
        .into_iter()
        .filter(|(n, _)| *n == b.node)
        .collect::<Vec<_>>();
    assert_eq!(
        b_updates,
        vec![(b.node, 2)],
        "active first, not the staged 3"
    );
    let (_, key_b2) = update_key(&sent, b.node);
    assert_eq!(
        ack_key(&service, b.node, 2, &key_b2, 1, t + 2_000),
        AckOutcome::StagedRecorded
    );
    let sent = gk.take();
    assert_eq!(activates_of(&sent), vec![(b.node, 2)]);
    assert_eq!(
        ack_key(&service, b.node, 2, &key_b2, 2, t + 3_000),
        AckOutcome::ActiveRecorded
    );
    // Only now does B stage epoch 3.
    service.tick(HostTime::sync(t + 4_000));
    let sent = gk.take();
    assert!(updates_of(&sent).contains(&(b.node, 3)), "{sent:?}");
}

/// G-SEC P5 PR3 (§6.3): the stable-phase pull matrix — behind repairs,
/// repair of the converged, ahead-of-high-water refused, strangers fenced.
#[test]
fn gk_pull_matrix_on_stable() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_AC01, 0xAD, T0);
    gk.set_ready(a.node, true);
    // Converge to epoch 2 so pulls land on stable ground.
    rotate(&service, 1, "m1", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let staged = gk.take();
    let (_, key) = update_key(&staged, a.node);
    assert_eq!(
        ack_key(&service, a.node, 2, &key, 1, T0 + 2_000),
        AckOutcome::StagedRecorded
    );
    gk.take();
    assert_eq!(
        ack_key(&service, a.node, 2, &key, 2, T0 + 3_000),
        AckOutcome::ActiveRecorded
    );
    assert_eq!(
        gk_status(&service, T0 + 3_000)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("stable")
    );
    // Behind (current 1 < active 2): Update(2), then Activate on the ACK.
    assert_eq!(
        pull(&service, a.node, 1, 0, 2, T0 + 4_000),
        PullOutcome::Answered
    );
    let sent = gk.take();
    assert_eq!(updates_of(&sent), vec![(a.node, 2)]);
    let (_, key2) = update_key(&sent, a.node);
    assert_eq!(
        ack_key(&service, a.node, 2, &key2, 1, T0 + 5_000),
        AckOutcome::StagedRecorded
    );
    assert_eq!(activates_of(&gk.take()), vec![(a.node, 2)]);
    assert_eq!(
        ack_key(&service, a.node, 2, &key2, 2, T0 + 6_000),
        AckOutcome::ActiveRecorded
    );
    // Converged repair pull: answered with the same current key.
    assert_eq!(
        pull(&service, a.node, 2, 0, 3, T0 + 7_000),
        PullOutcome::Answered
    );
    assert_eq!(updates_of(&gk.take()), vec![(a.node, 2)]);
    // Ahead of the issued high-water: refused with a diagnostic, floor kept.
    let ahead = member_pull(&service, a.node, 99, 0, 1);
    let (outcome, events) =
        service.with(|a| a.on_group_key_pull(ahead, HostTime::sync(T0 + 8_000)));
    assert_eq!(
        outcome,
        PullOutcome::Rejected {
            reason: "pull_ahead"
        }
    );
    assert!(events.iter().any(|(_, f)| f.contains("gk_pull_ahead")));
    assert_eq!(
        gk_status(&service, T0 + 8_000)
            .get("active")
            .unwrap()
            .as_u64(),
        Some(2)
    );
    // Malformed and stranger pulls fence out.
    assert_eq!(
        pull(&service, a.node, 0, 0, 2, T0 + 9_000),
        PullOutcome::Rejected {
            reason: "pull_shape"
        }
    );
    let stranger = member_pull(&service, a.node, 1, 0, 2);
    let stranger = GroupKeyPull {
        node: 0x00A1_0000_0000_FFFF,
        ..stranger
    };
    let (outcome, _) = service.with(|a| a.on_group_key_pull(stranger, HostTime::sync(T0 + 9_000)));
    assert_eq!(
        outcome,
        PullOutcome::Rejected {
            reason: "pull_fence"
        }
    );
}

/// G-SEC P5 PR3 (§3.2/§6.2): channel-less targets get rate-limited Wake
/// hints (no attempt consumed) until the channel comes up.
#[test]
fn gk_wake_for_channel_less_targets() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_AE01, 0xAE, T0);
    rotate(&service, 1, "m1", T0 + 1_000).unwrap();
    // No channel: Wake, and the Update round is not spent on it.
    service.tick(HostTime::sync(T0 + 1_000));
    assert_eq!(wakes_of(&gk.take()), vec![a.node]);
    let target = service
        .with(|auth| auth.gks.target(a.node).unwrap().row.clone())
        .0;
    assert_eq!(target.state, TargetState::Pending);
    let attempts = service
        .with(|auth| auth.gks.target(a.node).unwrap().attempts)
        .0;
    assert_eq!(attempts, 0);
    // Wakes re-send at most every 2 s.
    service.tick(HostTime::sync(T0 + 1_500));
    assert!(gk.take().is_empty());
    service.tick(HostTime::sync(T0 + 3_000));
    assert_eq!(wakes_of(&gk.take()), vec![a.node]);
    // The channel comes up: the Update flows once the Wake backoff lapses.
    gk.set_ready(a.node, true);
    service.tick(HostTime::sync(T0 + 5_000));
    assert_eq!(updates_of(&gk.take()), vec![(a.node, 2)]);
}

/// G-SEC P5 PR3 (§3.1/§9): only a durable ACK is convergence evidence —
/// every other report is diagnosed and never moves the phase.
#[test]
fn gk_stale_ack_matrix() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_AF01, 0xAF, T0);
    gk.set_ready(a.node, true);
    rotate(&service, 1, "m1", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let staged = gk.take();
    let (_, key) = update_key(&staged, a.node);
    // Wrong GK-id: not this key.
    let mut bad = member_ack(&service, a.node, 2, &key, 0, 1);
    bad.gk_id[0] ^= 0xFF;
    let (outcome, _) = service.with(|a| a.on_group_key_ack(bad, HostTime::sync(T0 + 2_000)));
    assert_eq!(outcome, AckOutcome::Stale { reason: "ack_gkid" });
    // Durable but unapplied: no evidence either.
    assert_eq!(
        ack_key(&service, a.node, 2, &key, 0, T0 + 2_000),
        AckOutcome::Stale {
            reason: "ack_unapplied"
        }
    );
    // Device conflict: diagnosed, target unknown, minute round.
    let conflict = member_ack(&service, a.node, 2, &key, 1, 0);
    let (outcome, events) =
        service.with(|a| a.on_group_key_ack(conflict, HostTime::sync(T0 + 2_000)));
    assert_eq!(
        outcome,
        AckOutcome::Stale {
            reason: "ack_conflict"
        }
    );
    assert!(events.iter().any(|(_, f)| f.contains("ack_conflict")));
    let target = service
        .with(|auth| auth.gks.target(a.node).unwrap().row.clone())
        .0;
    assert_eq!(target.state, TargetState::Unknown);
    // Busy: no evidence lost, retried soon.
    let busy = member_ack(&service, a.node, 2, &key, 3, 0);
    let (outcome, _) = service.with(|a| a.on_group_key_ack(busy, HostTime::sync(T0 + 3_000)));
    assert_eq!(outcome, AckOutcome::Stale { reason: "ack_busy" });
    let due = service
        .with(|auth| auth.gks.target(a.node).unwrap().next_due_mono)
        .0;
    assert_eq!(due, T0 + 5_000);
    // Nothing above moved the phase or the evidence.
    let status = gk_status(&service, T0 + 3_000);
    assert_eq!(status.get("phase").unwrap().as_str(), Some("staging"));
    assert_eq!(status.get("staged_ack").unwrap().as_u64(), Some(0));
    // A duplicate of a recorded ACK is a no-op, not an error.
    assert_eq!(
        ack_key(&service, a.node, 2, &key, 1, T0 + 4_000),
        AckOutcome::StagedRecorded
    );
    assert_eq!(
        ack_key(&service, a.node, 2, &key, 1, T0 + 5_000),
        AckOutcome::Duplicate
    );
}

/// G-SEC P5 PR3 (§6.1/§6.2): a store fault changes nothing and queues
/// nothing — every GK commit fails closed.
#[test]
fn gk_store_fault_changes_nothing() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_BA01, 0xBA, T0);
    gk.set_ready(a.node, true);
    rotate(&service, 1, "m1", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let staged = gk.take();
    let (_, key) = update_key(&staged, a.node);
    // ACK evidence fails closed (the store is swapped back afterwards).
    let failed = member_ack(&service, a.node, 2, &key, 0, 1);
    let (outcome, _) = service.with(|a| {
        let live = std::mem::replace(&mut a.store, Box::new(failing_store()));
        let outcome = a.on_group_key_ack(failed, HostTime::sync(T0 + 2_000));
        a.store = live;
        outcome
    });
    assert_eq!(outcome, AckOutcome::Stale { reason: "store" });
    let target = service
        .with(|auth| auth.gks.target(a.node).unwrap().row.clone())
        .0;
    assert_eq!(target.state, TargetState::Pending, "RAM unchanged");
    // Converge, then fail a fresh staging the same way.
    assert_eq!(
        ack_key(&service, a.node, 2, &key, 1, T0 + 3_000),
        AckOutcome::StagedRecorded
    );
    gk.take();
    assert_eq!(
        ack_key(&service, a.node, 2, &key, 2, T0 + 4_000),
        AckOutcome::ActiveRecorded
    );
    service.with(|a| {
        a.store = Box::new(failing_store());
    });
    let error = rotate(&service, 2, "m2", T0 + 70_000).unwrap_err();
    assert_eq!(error.code, "STORE_FAILURE");
    assert_eq!(
        service.with(|a| a.gks.staged_epoch()).0,
        None,
        "RAM unchanged"
    );
    assert!(gk.take().is_empty(), "outbound is zero");
    let failures = service.with(|a| a.counters.store_failures).0;
    assert_eq!(failures, 2);
}

/// G-SEC P5 PR3 (§3.1): JoinConfirm resolution is typed — duplicates ACK
/// as saved fact, staleness and store failure never do.
#[test]
fn gk_member_confirm_is_typed() {
    let (service, transport, _) = gk_service();
    let dev = join_member(&service, &transport, 0x00A1_0000_0000_BB01, 0xBB, T0);
    let (cert_hash, dams) = service
        .with(|a| {
            let row = &a.devices[&dev.node];
            (
                routeloom_provision::sha256::sha256(&row.member_cert),
                row.dams,
            )
        })
        .0;
    let confirm = |node, generation, hash: &[u8; 32], dams: &[u8; 32], now: u64| {
        service
            .with(|a| a.member_confirmed(node, generation, hash, dams, now))
            .0
    };
    assert_eq!(
        confirm(dev.node, 1, &cert_hash, &dams, T0 + 1_000),
        ConfirmOutcome::Confirmed
    );
    assert_eq!(
        confirm(dev.node, 1, &cert_hash, &dams, T0 + 1_100),
        ConfirmOutcome::AlreadyConfirmed
    );
    assert_eq!(
        confirm(dev.node, 2, &cert_hash, &dams, T0 + 1_200),
        ConfirmOutcome::Stale
    );
    assert_eq!(
        confirm(dev.node, 1, &[9; 32], &dams, T0 + 1_200),
        ConfirmOutcome::Stale
    );
    assert_eq!(
        confirm(dev.node, 1, &cert_hash, &[9; 32], T0 + 1_200),
        ConfirmOutcome::Stale
    );
    assert_eq!(
        confirm(0x00A1_0000_0000_FFFF, 1, &cert_hash, &dams, T0 + 1_200),
        ConfirmOutcome::UnknownDevice
    );
    // A store fault surfaces instead of confirming.
    let b = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_BB02,
        0xBC,
        T0 + 2_000,
    );
    let (cert_b, dams_b) = service
        .with(|a| {
            let row = &a.devices[&b.node];
            (
                routeloom_provision::sha256::sha256(&row.member_cert),
                row.dams,
            )
        })
        .0;
    service.with(|a| {
        a.store = Box::new(failing_store());
    });
    assert_eq!(
        confirm(b.node, 1, &cert_b, &dams_b, T0 + 3_000),
        ConfirmOutcome::StoreFailure
    );
}

fn crash_db(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-site-gk-{tag}-{}-{}",
        std::process::id(),
        T0
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("site.db")
}

/// G-SEC P5 PR3 (§6.2): a restart never extends a staging deadline — the
/// persisted staging rotation resumes as expired and activates at the
/// first tick, with staged evidence intact and unknowns honest.
#[test]
fn gk_restart_resumes_staging_as_expired() {
    let db = crash_db("resume");
    let a_node = 0x00A1_0000_0000_CA01;
    let b_node = 0x00A1_0000_0000_CA02;
    let staged_key = {
        let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        let gk = FakeGroupKeyTransport::new();
        service.set_group_key_transport(gk.clone());
        let a = join_member(&service, &transport, a_node, 0xCA, T0);
        let b = join_member(&service, &transport, b_node, 0xCB, T0 + 500);
        gk.set_ready(a.node, true);
        gk.set_ready(b.node, true);
        rotate(&service, 1, "m1", T0 + 1_000).unwrap();
        service.tick(HostTime::sync(T0 + 1_000));
        let staged = gk.take();
        let (_, key) = update_key(&staged, a.node);
        // Only A stages: the crash lands mid-staging, 58 s early.
        assert_eq!(
            ack_key(&service, a.node, 2, &key, 1, T0 + 2_000),
            AckOutcome::StagedRecorded
        );
        key
        // dropped: the "crash"
    };
    let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
    let gk = FakeGroupKeyTransport::new();
    service.set_group_key_transport(gk.clone());
    gk.set_ready(a_node, true);
    gk.set_ready(b_node, true);
    let _ = transport;
    // First tick after the crash activates (expired resume, not extended),
    // with B honestly unknown.
    let events = service.tick(HostTime::sync(T0 + 10_000));
    let rotated = events
        .iter()
        .find(|(_, f)| f.contains("gk.rotated"))
        .unwrap();
    assert!(rotated.1.contains("\"unknown\":1"), "{}", rotated.1);
    assert_eq!(
        gk_status(&service, T0 + 10_000)
            .get("active")
            .unwrap()
            .as_u64(),
        Some(2)
    );
    // A's staged evidence survived (Activate); B restarts at Update.
    let sent = gk.take();
    assert_eq!(activates_of(&sent), vec![(a_node, 2)]);
    assert_eq!(updates_of(&sent), vec![(b_node, 2)]);
    assert_eq!(
        ack_key(&service, a_node, 2, &staged_key, 2, T0 + 11_000),
        AckOutcome::ActiveRecorded
    );
    let (_, key_b) = update_key(&sent, b_node);
    assert_eq!(
        ack_key(&service, b_node, 2, &key_b, 1, T0 + 12_000),
        AckOutcome::StagedRecorded
    );
    assert_eq!(activates_of(&gk.take()), vec![(b_node, 2)]);
    assert_eq!(
        ack_key(&service, b_node, 2, &key_b, 2, T0 + 13_000),
        AckOutcome::ActiveRecorded
    );
    assert_eq!(
        gk_status(&service, T0 + 13_000)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("stable")
    );
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// G-SEC P5 PR3 (§6.2): a three-day outage rotates exactly once on return
/// — never a catch-up burst for the missed days.
#[test]
fn gk_three_day_outage_rotates_once() {
    let db = crash_db("outage");
    let node = 0x00A1_0000_0000_CB01;
    let activated = {
        let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        let gk = FakeGroupKeyTransport::new();
        service.set_group_key_transport(gk.clone());
        let a = join_member(&service, &transport, node, 0xCB, T0);
        gk.set_ready(a.node, true);
        rotate(&service, 1, "m1", T0 + 1_000).unwrap();
        service.tick(HostTime::sync(T0 + 1_000));
        let staged = gk.take();
        let (_, key) = update_key(&staged, a.node);
        assert_eq!(
            ack_key(&service, a.node, 2, &key, 1, T0 + 2_000),
            AckOutcome::StagedRecorded
        );
        gk.take();
        assert_eq!(
            ack_key(&service, a.node, 2, &key, 2, T0 + 3_000),
            AckOutcome::ActiveRecorded
        );
        T0 + 2_000
    };
    let back = activated + 3 * 86_400_000;
    let (service, _) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
    let gk = FakeGroupKeyTransport::new();
    service.set_group_key_transport(gk.clone());
    gk.set_ready(node, true);
    // One rotation for the whole outage, not three.
    service.tick(HostTime::sync(back));
    service.tick(HostTime::sync(back));
    let sent = gk.take();
    assert_eq!(updates_of(&sent), vec![(node, 3)]);
    assert_eq!(service.with(|a| a.gks.high_water()).0, 3);
    service.tick(HostTime::sync(back + 60_000));
    service.tick(HostTime::sync(back + 120_000));
    assert_eq!(service.with(|a| a.gks.high_water()).0, 3);
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// G-SEC P5 PR3 (§6.1): a v1 staged key migrates into a live removal
/// rotation over every valid member, linked to the revoke that staged it.
#[test]
fn gk_migrated_staged_key_rebuilds_its_rotation() {
    let db = crash_db("migrate");
    // A hand-built version-1 database: active + staged keys, one member,
    // and the revoke operation that staged epoch 2.
    {
        let conn = rusqlite::Connection::open(&db).unwrap();
        conn.execute_batch(
            "CREATE TABLE meta (name TEXT PRIMARY KEY, value BLOB NOT NULL);
             CREATE TABLE devices (
                node INTEGER PRIMARY KEY, kid BLOB NOT NULL, dev_cert BLOB NOT NULL,
                model INTEGER NOT NULL, hw_rev INTEGER NOT NULL, cert_serial INTEGER NOT NULL,
                member INTEGER NOT NULL, generation INTEGER NOT NULL, role INTEGER NOT NULL,
                member_cert BLOB NOT NULL, member_cert_serial INTEGER NOT NULL,
                confirmed INTEGER NOT NULL, dams BLOB NOT NULL, approved_ms INTEGER NOT NULL,
                delivered_ms INTEGER, confirmed_ms INTEGER, last_seen_ms INTEGER,
                removed_ms INTEGER, removal_reason INTEGER NOT NULL);
             CREATE TABLE ledger (
                seq INTEGER PRIMARY KEY, kind TEXT NOT NULL, node INTEGER NOT NULL,
                kid BLOB NOT NULL, generation INTEGER NOT NULL, digest BLOB NOT NULL,
                ms INTEGER NOT NULL, hash BLOB NOT NULL);
             CREATE TABLE rrs (rs_epoch INTEGER PRIMARY KEY, object BLOB NOT NULL);
             CREATE TABLE group_keys (
                gk_epoch INTEGER PRIMARY KEY, gk BLOB NOT NULL, state TEXT NOT NULL,
                created_ms INTEGER NOT NULL);
             CREATE TABLE docs (
                kind TEXT NOT NULL, key TEXT NOT NULL, body TEXT NOT NULL,
                PRIMARY KEY (kind, key));",
        )
        .unwrap();
        conn.execute(
            "INSERT INTO meta (name, value) VALUES ('schema_version', ?1)",
            rusqlite::params![1_u32.to_be_bytes().to_vec()],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO group_keys (gk_epoch, gk, state, created_ms) VALUES (1, ?1, 'active', ?2)",
            rusqlite::params![vec![0x11u8; 32], T0 as i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO group_keys (gk_epoch, gk, state, created_ms) VALUES (2, ?1, 'staged', ?2)",
            rusqlite::params![vec![0x22u8; 32], (T0 + 1_000) as i64],
        )
        .unwrap();
        let kid = vec![0x33u8; 32];
        conn.execute(
            "INSERT INTO devices (node, kid, dev_cert, model, hw_rev, cert_serial, member,
                generation, role, member_cert, member_cert_serial, confirmed, dams,
                approved_ms, delivered_ms, confirmed_ms, last_seen_ms, removed_ms, removal_reason)
             VALUES (?1, ?2, zeroblob(0), 0, 0, 0, 1, 1, 1, zeroblob(0), 1, 0, ?2,
                ?3, NULL, NULL, NULL, NULL, 0)",
            rusqlite::params![0x00A1_0000_0000_CC01u64 as i64, kid, T0 as i64],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO docs (kind, key, body) VALUES ('operation', 'op-x', ?1)",
            rusqlite::params![format!(
                "{{\"id\":7,\"kind\":\"revoke\",\"node\":\"{:016x}\",\"generation\":1,\
                 \"member_cert_serial\":1,\"rs_epoch\":1,\"gk_from\":1,\"gk_to\":2,\
                 \"created_ms\":{}}}",
                0x00A1_0000_0000_CC02u64,
                T0 + 1_000
            )],
        )
        .unwrap();
    }
    std::fs::set_permissions(&db, std::os::unix::fs::PermissionsExt::from_mode(0o600)).unwrap();
    let (service, _) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
    let gk = FakeGroupKeyTransport::new();
    service.set_group_key_transport(gk.clone());
    // The rotation is live (removal cause, unknown causes count as such),
    // linked to the staging revoke, targeting the surviving member.
    let status = gk_status(&service, T0 + 2_000);
    assert_eq!(status.get("phase").unwrap().as_str(), Some("staging"));
    assert_eq!(status.get("cause").unwrap().as_str(), Some("removal"));
    assert_eq!(status.get("targets").unwrap().as_u64(), Some(1));
    let op_id = service
        .with(|a| a.gks.rotation().unwrap().row.operation_id)
        .0;
    assert_eq!(op_id, 7);
    let (view, _) = service.with(|a| a.operation_json(7).unwrap());
    let view = json(&view);
    assert_eq!(view.get("state").unwrap().as_str(), Some("committed"));
    let rotation = view.get("gk_rotation").unwrap();
    assert_eq!(
        rotation.get("state").unwrap().as_str(),
        Some("distributing")
    );
    // It resumes as expired (migration sets no deadline): first tick
    // activates over the survivor.
    gk.set_ready(0x00A1_0000_0000_CC01, true);
    service.tick(HostTime::sync(T0 + 3_000));
    assert_eq!(
        gk_status(&service, T0 + 3_000)
            .get("active")
            .unwrap()
            .as_u64(),
        Some(2)
    );
    assert_eq!(
        updates_of(&gk.take()),
        vec![(0x00A1_0000_0000_CC01, 2)],
        "unknown survivor gets its Update after the resume"
    );
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

/// G-SEC P5 PR3 (§6.1): the store never holds more than the active and
/// staged secrets, across staging, supersede and activation.
#[test]
fn gk_secret_rows_never_exceed_two() {
    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_CD01, 0xCD, T0);
    let b = join_member(
        &service,
        &transport,
        0x00A1_0000_0000_CD02,
        0xCE,
        T0 + 1_000,
    );
    gk.set_ready(a.node, true);
    gk.set_ready(b.node, true);
    assert_eq!(secret_rows(&service), 1);
    rotate(&service, 1, "m1", T0 + 2_000).unwrap();
    assert_eq!(secret_rows(&service), 2);
    revoke(&service, a.node, 1, "rv-a", T0 + 3_000).unwrap();
    assert_eq!(secret_rows(&service), 2, "supersede deletes the old staged");
    service.tick(HostTime::sync(T0 + 33_000));
    assert_eq!(
        secret_rows(&service),
        1,
        "activation deletes the old active"
    );
    rotate(&service, 3, "m2", T0 + 100_000).unwrap();
    assert_eq!(secret_rows(&service), 2);
}
