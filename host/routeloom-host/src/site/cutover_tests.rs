//! Host site_epoch cutover acceptance (04 §7, P6-2 PR D): the V1-R08
//! scenarios as regression tests — commit-before-send, the 600 s window
//! with the gateway gate, revoke-during-prepare conflicts, restart
//! resume, the RemovalNotice outbox, old-kid recovery and the
//! no-decider reissue after a missed cutover.

use std::sync::{Arc, Mutex};

use routeloom_join::renew::{Head, Phase, Receipt, RouteState};
use routeloom_join::JoinResult;
use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
use routeloom_provision::sdkv1::revocation::RevocationReason;
use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::{test_keypair, FileRootSigner};

use super::cutover::{
    CutoverRequest, CutoverState, GrantState, CUTOVER_GATEWAY_FLUSH_MS, CUTOVER_GRACE_MS,
    CUTOVER_PREPARE_WINDOW_MS,
};
use super::group_keys::HostTime;
use super::records::{parse_op_token, Verdict, ROLE_ENDPOINT, ROLE_GATEWAY};
use super::revocation::{OutboundKind, RevocationTransport};
use super::store::{MemoryStore, SiteStore};
use super::testkit::{self, request_id, Outcome, SimDevice};
use super::transport::InProcessTransport;
use super::{RevokeRequest, SiteService};

const T0: u64 = 1_790_000_000_000;
const DECIDER: u32 = 501;

fn service_with(store: Box<dyn SiteStore>) -> (SiteService, Arc<InProcessTransport>) {
    let service = SiteService::new(testkit::authority(store, T0));
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    (service, transport)
}

fn service() -> (SiteService, Arc<InProcessTransport>) {
    service_with(Box::new(MemoryStore::default()))
}

fn json(text: &str) -> routeloom_json::Json {
    routeloom_json::parse(text).expect("JSON")
}

fn decide(service: &SiteService, request: u64, device: u64, verdict: Verdict, key: &str, at: u64) {
    let (answer, _) = service.with(|a| {
        a.decide(
            DECIDER,
            super::DecideRequest {
                join_request_id: request,
                device,
                verdict,
                key: key.into(),
            },
            at,
        )
    });
    answer.unwrap();
}

fn join_member(
    service: &SiteService,
    transport: &Arc<InProcessTransport>,
    device: &mut SimDevice,
    role: u8,
    key: &str,
    at: u64,
) {
    let (mut exchange, _, events) = device.start(service, transport, at);
    decide(
        service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow { role },
        key,
        at + 10,
    );
    assert!(matches!(
        device.finish(&mut exchange, transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
}

/// The next-epoch SiteCert (epoch 4) from the same Site CA, SAK and
/// low32 as the testkit site (epoch 3).
fn next_site_cert() -> Vec<u8> {
    let site_ca = FileRootSigner::from_secret(testkit::SITE_CA, &test_keypair(0x61).0).unwrap();
    cert_issue(
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
    .unwrap()
}

#[derive(Default)]
struct GrantSends {
    refused: bool,
    notice_supported: bool,
    notices: Vec<(u64, u64, Vec<u8>)>,
    grants: Vec<(u64, u64, Vec<u8>)>,
    rrs: Vec<(u64, Vec<u8>)>,
}

struct FakeCutoverTransport {
    shared: Arc<Mutex<GrantSends>>,
}

impl RevocationTransport for FakeCutoverTransport {
    fn send_rrs(&mut self, node: u64, object: &[u8]) -> bool {
        let mut sends = self.shared.lock().unwrap();
        if sends.refused {
            return false;
        }
        sends.rrs.push((node, object.to_vec()));
        true
    }

    fn send_notice(&mut self, node: u64, network: u64, notice: &[u8]) -> bool {
        let mut sends = self.shared.lock().unwrap();
        if sends.refused {
            return false;
        }
        sends.notices.push((node, network, notice.to_vec()));
        true
    }

    fn send_grant(&mut self, node: u64, network: u64, plaintext: &[u8]) -> bool {
        let mut sends = self.shared.lock().unwrap();
        if sends.refused {
            return false;
        }
        sends.grants.push((node, network, plaintext.to_vec()));
        true
    }

    fn carries_notice(&self) -> bool {
        self.shared.lock().unwrap().notice_supported
    }

    fn carries_grant(&self) -> bool {
        true
    }
}

fn with_grant_transport(service: &SiteService) -> Arc<Mutex<GrantSends>> {
    let shared = Arc::new(Mutex::new(GrantSends {
        notice_supported: true,
        ..GrantSends::default()
    }));
    let port = FakeCutoverTransport {
        shared: shared.clone(),
    };
    service.with(|a| a.set_rrs_transport(Some(Box::new(port))));
    shared
}

fn start_cutover(service: &SiteService, key: &str, at: u64) -> (u64, routeloom_json::Json) {
    let (answer, _) = service.with(|a| {
        a.cutover(
            DECIDER,
            CutoverRequest {
                expected_site_epoch: testkit::SITE_EPOCH,
                next_site_cert: next_site_cert(),
                key: key.into(),
            },
            HostTime::sync(at),
        )
    });
    let answer = json(&answer.unwrap());
    let op = parse_op_token(answer.get("operation_id").unwrap().as_str().unwrap()).unwrap();
    (op, answer)
}

fn cutover_gk_epoch(service: &SiteService, op: u64) -> u32 {
    service
        .with(|a| {
            a.operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .next_gk_epoch
        })
        .0
}

fn operation(service: &SiteService, op: u64, at: u64) -> routeloom_json::Json {
    let (view, _) = service.with(|a| a.operation_json(op, HostTime::sync(at)).unwrap());
    json(&view)
}

fn tick(service: &SiteService, at: u64) {
    service.with(|a| a.tick(HostTime::sync(at)));
}

fn prepare_gateway(
    service: &SiteService,
    transport: &Arc<InProcessTransport>,
    at: u64,
    key: &str,
) -> (u64, Arc<Mutex<GrantSends>>) {
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    join_member(
        service,
        transport,
        &mut gateway,
        ROLE_GATEWAY,
        "gateway",
        at,
    );
    let sends = with_grant_transport(service);
    let (op, _) = start_cutover(service, key, at + 10_000);
    tick(service, at + 10_000);
    let prepare = sends.lock().unwrap().grants[0].2.clone();
    let receipt = Receipt {
        head: Head {
            phase: Phase::Prepared,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        },
        new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW),
        gk_epoch: cutover_gk_epoch(service, op),
        rs_epoch: 0,
        digest: sha256(&prepare),
        status: 0,
    }
    .encode()
    .unwrap();
    assert!(
        service
            .with(|a| a.handle_grant_receipt(
                gateway.node,
                1,
                testkit::network(),
                &receipt,
                HostTime::sync(at + 11_000)
            ))
            .0
    );
    (op, sends)
}

#[test]
fn prepared_commit_waits_for_retry_window() {
    let (service, transport) = service();
    let (op, _) = prepare_gateway(&service, &transport, T0, "commit-backoff");
    let at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, at);
    // PREPARE's retry clock must not delay the first COMMIT, but a
    // successful COMMIT send must suppress it until the ACK window ends.
    service.with(|a| {
        assert!(a.grant_still_due(op, testkit::GATEWAY, OutboundKind::Commit, at));
        a.note_grant_sent(op, testkit::GATEWAY, at);
        assert!(!a.grant_still_due(op, testkit::GATEWAY, OutboundKind::Commit, at + 100));
        assert!(a.grant_still_due(op, testkit::GATEWAY, OutboundKind::Commit, at + 10_000));
    });
}

#[test]
fn committed_cutover_reopens_with_old_network_rrs_history() {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-cutover-history-{}-{}",
        std::process::id(),
        crate::now_ms()
    ));
    routeloom_peercred::create_private_dir_all(&dir).unwrap();
    let path = dir.join("site.db");
    let store = super::store::SqliteSiteStore::open(&path).unwrap();
    let (service, transport) = service_with(Box::new(store));
    service.with(|a| a.handle_rrs_get(0, T0).unwrap());
    let (op, _) = prepare_gateway(&service, &transport, T0, "history");
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    assert_eq!(
        operation(&service, op, committed_at)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("committed")
    );
    drop(service);
    let store = super::store::SqliteSiteStore::open(&path).unwrap();
    let reopened = super::SiteAuthority::open(
        &testkit::setup(),
        Box::new(testkit::sak()),
        Box::new(store),
        committed_at + 1_000,
    );
    assert!(reopened.is_ok(), "{}", reopened.err().unwrap_or_default());
    assert_eq!(reopened.unwrap().network() >> 32, 4);
    std::fs::remove_dir_all(dir).unwrap();
}

/// Mints a RouteState query for `node` and adopts a matching report
/// (04 §7): the direct-drive equivalent of a query round trip, for
/// frontier tests that steer the tree rather than the queue.
fn adopt_route_report(
    service: &SiteService,
    op: u64,
    node: u64,
    root: u64,
    parent: u64,
    at: u64,
) -> bool {
    let query_id = service
        .with(|a| {
            a.route_query_bytes(op, node);
            a.cutover_routes
                .get(&(op, node))
                .map(|plan| plan.query_id)
                .unwrap_or(0)
        })
        .0;
    assert_ne!(query_id, 0, "query mints an id for {node:016x}");
    let revision = service
        .with(|a| {
            a.operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .revision
        })
        .0;
    let report = RouteState {
        head: Head {
            phase: Phase::RouteState,
            cutover_id: op,
            revision,
            old_network: testkit::network(),
        },
        mode: 1,
        status: 0,
        root,
        parent,
        boot: 7,
        route_stamp: 9,
        query_id,
        valid_for_ms: 3_600_000,
    }
    .encode()
    .unwrap()
    .to_vec();
    service
        .with(|a| a.handle_route_report(node, 1, testkit::network(), &report, at))
        .0
}

/// Injects `node`'s new-network APPLIED receipt (04 §7): the
/// adoption proof, over the current binding.
fn inject_applied(service: &SiteService, op: u64, node: u64, at: u64) -> bool {
    let (commit_object, commit_rs) = service
        .with(|a| {
            let state = a.operations.get(&op).unwrap().cutover.as_ref().unwrap();
            (state.commit_object.clone(), state.commit_rs_epoch)
        })
        .0;
    let new_network = (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW);
    let receipt = Receipt {
        head: Head {
            phase: Phase::Applied,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        },
        new_network,
        gk_epoch: cutover_gk_epoch(service, op),
        rs_epoch: commit_rs,
        digest: sha256(&commit_object),
        status: 0,
    }
    .encode()
    .unwrap()
    .to_vec();
    service
        .with(|a| a.handle_grant_receipt(node, 1, new_network, &receipt, HostTime::sync(at)))
        .0
}

/// Injects `node`'s verified COMMIT_STORED receipt (04 §7): same
/// cutover/revision/digest/epochs over the live old binding.
fn inject_commit_stored(service: &SiteService, op: u64, node: u64, at: u64) -> bool {
    let (commit_object, commit_rs) = service
        .with(|a| {
            let state = a.operations.get(&op).unwrap().cutover.as_ref().unwrap();
            (state.commit_object.clone(), state.commit_rs_epoch)
        })
        .0;
    let receipt = Receipt {
        head: Head {
            phase: Phase::CommitStored,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        },
        new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW),
        gk_epoch: cutover_gk_epoch(service, op),
        rs_epoch: commit_rs,
        digest: sha256(&commit_object),
        status: 0,
    }
    .encode()
    .unwrap()
    .to_vec();
    service
        .with(|a| a.handle_commit_stored(node, 1, testkit::network(), &receipt, at))
        .0
}

#[test]
fn unreadable_cutover_timeline_cannot_commit() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct FailLoad {
        inner: Box<dyn SiteStore>,
        fail: Arc<AtomicBool>,
    }
    impl SiteStore for FailLoad {
        fn load(&mut self) -> Result<super::store::Snapshot, super::store::StoreError> {
            if self.fail.swap(false, Ordering::SeqCst) {
                return Err(super::store::StoreError("timeline read failed".into()));
            }
            self.inner.load()
        }
        fn commit(&mut self, batch: &super::store::Batch) -> Result<(), super::store::StoreError> {
            self.inner.commit(batch)
        }
        fn durable(&self) -> bool {
            self.inner.durable()
        }
    }

    let (service, transport) = service();
    let (op, _) = prepare_gateway(&service, &transport, T0, "timeline");
    let fail = Arc::new(AtomicBool::new(false));
    service.with(|a| {
        let inner = std::mem::replace(&mut a.store, Box::new(MemoryStore::default()));
        a.store = Box::new(FailLoad {
            inner,
            fail: fail.clone(),
        });
    });
    fail.store(true, Ordering::SeqCst);
    let at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, at);
    assert_eq!(service.with(|a| a.network()).0, testkit::network());
    assert_eq!(
        operation(&service, op, at).get("phase").unwrap().as_str(),
        Some("preparing")
    );
}

#[test]
fn applied_after_delivery_grace_converges_the_cutover() {
    let (service, transport) = service();
    let (op, _) = prepare_gateway(&service, &transport, T0, "late-applied");
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    tick(&service, committed_at + 60_001);
    assert_eq!(
        operation(&service, op, committed_at + 60_001)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("recovery_pending")
    );
    let state = service
        .with(|a| {
            a.operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone()
        })
        .0;
    let receipt = Receipt {
        head: Head {
            phase: Phase::Applied,
            cutover_id: op,
            revision: state.revision,
            old_network: state.old_network,
        },
        new_network: state.new_network,
        gk_epoch: state.next_gk_epoch,
        rs_epoch: state.commit_rs_epoch,
        digest: sha256(&state.commit_object),
        status: 0,
    }
    .encode()
    .unwrap();
    assert!(
        service
            .with(|a| a.handle_grant_receipt(
                testkit::GATEWAY,
                1,
                state.new_network,
                &receipt,
                HostTime::sync(committed_at + 60_002)
            ))
            .0
    );
    assert_eq!(
        operation(&service, op, committed_at + 60_002)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("converged")
    );
}

#[test]
fn failed_phase_commit_does_not_publish_recovery_pending() {
    struct FailCommit {
        inner: Box<dyn SiteStore>,
        failed: bool,
    }
    impl SiteStore for FailCommit {
        fn load(&mut self) -> Result<super::store::Snapshot, super::store::StoreError> {
            self.inner.load()
        }
        fn commit(&mut self, batch: &super::store::Batch) -> Result<(), super::store::StoreError> {
            if !self.failed {
                self.failed = true;
                return Err(super::store::StoreError("phase commit failed".into()));
            }
            self.inner.commit(batch)
        }
        fn durable(&self) -> bool {
            self.inner.durable()
        }
    }

    let (service, transport) = service();
    let (op, _) = prepare_gateway(&service, &transport, T0, "phase-failure");
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    service.with(|a| {
        let inner = std::mem::replace(&mut a.store, Box::new(MemoryStore::default()));
        a.store = Box::new(FailCommit {
            inner,
            failed: false,
        });
    });
    let at = committed_at + 60_001;
    tick(&service, at);
    assert_eq!(
        operation(&service, op, at).get("phase").unwrap().as_str(),
        Some("committed")
    );
    tick(&service, at + 1);
    assert_eq!(
        operation(&service, op, at + 1)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("recovery_pending")
    );
}

#[test]
fn cutover_requires_a_grant_carrier_before_staging() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    join_member(
        &service,
        &transport,
        &mut gateway,
        ROLE_GATEWAY,
        "gateway",
        T0,
    );
    let (answer, _) = service.with(|a| {
        a.cutover(
            DECIDER,
            CutoverRequest {
                expected_site_epoch: testkit::SITE_EPOCH,
                next_site_cert: next_site_cert(),
                key: "no-carrier".into(),
            },
            HostTime::sync(T0 + 10_000),
        )
    });
    assert_eq!(answer.unwrap_err().code, "CUTOVER_UNAVAILABLE");
    assert!(
        service
            .with(|a| a.operations.values().all(|op| op.cutover.is_none()))
            .0
    );
}

#[test]
fn cutover_doc_rejects_oversized_commit_artifacts() {
    let (service, transport) = service();
    let (op, _) = prepare_gateway(&service, &transport, T0, "artifact-size");
    let doc = service
        .with(|a| {
            a.operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .doc()
        })
        .0;
    let oversized_proof = doc.replace(
        "\"commit_object\":\"\"",
        &format!("\"commit_object\":\"{}\"", "00".repeat(156)),
    );
    assert!(CutoverState::from_doc(&json(&oversized_proof)).is_none());
    let oversized_rrs = doc.replace(
        "\"commit_rrs\":\"\"",
        &format!("\"commit_rrs\":\"{}\"", "00".repeat(617)),
    );
    assert!(CutoverState::from_doc(&json(&oversized_rrs)).is_none());
}

#[test]
fn exhausted_site_counter_requires_maintenance() {
    let error = super::revocation::checked_next(u32::MAX, "rs_epoch").unwrap_err();
    assert_eq!(error.code, "COUNTER_EXHAUSTED");
    assert!(error.message.contains("maintenance"));
}

#[test]
fn retired_network_notice_is_not_sent_after_cutover_commit() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let mut victim = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(
        &service,
        &transport,
        &mut gateway,
        ROLE_GATEWAY,
        "gateway",
        T0,
    );
    join_member(
        &service,
        &transport,
        &mut victim,
        ROLE_ENDPOINT,
        "victim",
        T0 + 1_000,
    );
    let sends = with_grant_transport(&service);
    sends.lock().unwrap().notice_supported = false;
    service
        .with(|a| {
            a.revoke(
                DECIDER,
                RevokeRequest {
                    device: victim.node,
                    expected_generation: 1,
                    reason: RevocationReason::Lost,
                    key: "remove-victim".into(),
                },
                HostTime::sync(T0 + 2_000),
            )
        })
        .0
        .unwrap();
    let (op, _) = start_cutover(&service, "after-revoke", T0 + 10_000);
    tick(&service, T0 + 10_000);
    let prepare = sends
        .lock()
        .unwrap()
        .grants
        .iter()
        .find(|(node, _, bytes)| *node == gateway.node && bytes[1] == Phase::Prepare as u8)
        .unwrap()
        .2
        .clone();
    let receipt = Receipt {
        head: Head {
            phase: Phase::Prepared,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        },
        new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW),
        gk_epoch: cutover_gk_epoch(&service, op),
        rs_epoch: 0,
        digest: sha256(&prepare),
        status: 0,
    }
    .encode()
    .unwrap();
    assert!(
        service
            .with(|a| a.handle_grant_receipt(
                gateway.node,
                1,
                testkit::network(),
                &receipt,
                HostTime::sync(T0 + 11_000)
            ))
            .0
    );
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    assert_eq!(service.with(|a| a.network() >> 32).0, 4);
    let (notice_delivery, _) = service.with(|a| {
        a.operations
            .values()
            .find(|op| op.node == victim.node && op.notice.is_some())
            .unwrap()
            .notice
            .as_ref()
            .unwrap()
            .delivery
    });
    assert_eq!(
        notice_delivery,
        super::revocation::NoticeDelivery::Unreachable
    );
    sends.lock().unwrap().notice_supported = true;
    tick(&service, committed_at + 100);
    assert!(sends.lock().unwrap().notices.is_empty());
}

/// V1-R08: nothing is sent before the Preparing transaction commits; a
/// store failure leaves no cutover, no new epochs and no outbound bytes.
#[test]
fn cutover_sends_nothing_before_commit() {
    let (service, _) = service();
    let sends = with_grant_transport(&service);
    // Fail the Preparing commit itself.
    struct FailOnce {
        inner: Box<dyn SiteStore>,
        failed: bool,
    }
    impl SiteStore for FailOnce {
        fn load(&mut self) -> Result<super::store::Snapshot, super::store::StoreError> {
            self.inner.load()
        }
        fn commit(&mut self, batch: &super::store::Batch) -> Result<(), super::store::StoreError> {
            if !self.failed {
                self.failed = true;
                return Err(super::store::StoreError(
                    "injected Preparing failure".into(),
                ));
            }
            self.inner.commit(batch)
        }
        fn durable(&self) -> bool {
            self.inner.durable()
        }
    }
    service.with(|a| {
        let inner = std::mem::replace(&mut a.store, Box::new(MemoryStore::default()));
        a.store = Box::new(FailOnce {
            inner,
            failed: false,
        });
    });
    let (answer, _) = service.with(|a| {
        a.cutover(
            DECIDER,
            CutoverRequest {
                expected_site_epoch: testkit::SITE_EPOCH,
                next_site_cert: next_site_cert(),
                key: "cut-fail".into(),
            },
            HostTime::sync(T0),
        )
    });
    assert!(answer.is_err());
    tick(&service, T0 + 1_000);
    let sends = sends.lock().unwrap();
    assert!(sends.grants.is_empty());
    assert!(sends.rrs.is_empty());
    let (status, _) = service.with(|a| a.status_json(HostTime::sync(T0 + 1_000)));
    assert!(status.contains("\"site_epoch\":3"));
}

/// V1-R08: PREPAREs flow after commit, the 600 s window is not skipped
/// even with all ACKs early, and the commit needs a current-revision
/// gateway PREPARED.
#[test]
fn cutover_holds_the_window_and_the_gateway_gate() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let mut member = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    join_member(
        &service,
        &transport,
        &mut member,
        ROLE_ENDPOINT,
        "m",
        T0 + 5_000,
    );
    let sends = with_grant_transport(&service);
    let (op, answer) = start_cutover(&service, "cut-1", T0 + 10_000);
    assert_eq!(answer.get("state").unwrap().as_str(), Some("preparing"));
    assert_eq!(
        answer.get("new_site_epoch").unwrap().as_u64(),
        Some(u64::from(testkit::SITE_EPOCH + 1))
    );
    // PREPAREs go out on the tick over the old network, paced.
    tick(&service, T0 + 10_000);
    tick(&service, T0 + 10_100);
    tick(&service, T0 + 10_200);
    assert_eq!(sends.lock().unwrap().grants.len(), 2);
    let first = sends.lock().unwrap().grants[0].2.clone();
    assert_eq!(first[0], 1); // type-7 head version
    assert_eq!(first[1], Phase::Prepare as u8);
    assert_eq!(
        sends.lock().unwrap().grants[0].1,
        testkit::network(),
        "PREPARE travels the old authority context"
    );
    // Both targets PREPARE-ACK early — the window still does not skip.
    for (node, _, bytes) in sends.lock().unwrap().grants.clone() {
        let head = Head {
            phase: Phase::Prepared,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        };
        let receipt = Receipt {
            head,
            new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32)
                | u64::from(testkit::NETWORK_LOW),
            gk_epoch: cutover_gk_epoch(&service, op),
            rs_epoch: 0,
            digest: sha256(&bytes),
            status: 0,
        };
        let bytes = receipt.encode().unwrap().to_vec();
        let (moved, _) = service.with(|a| {
            a.handle_grant_receipt(
                node,
                1,
                testkit::network(),
                &bytes,
                HostTime::sync(T0 + 20_000),
            )
        });
        assert!(moved, "PREPARED counts for {node:016x}");
    }
    // A stale revision and a wrong digest never count.
    let stale = Receipt {
        head: Head {
            phase: Phase::Prepared,
            cutover_id: op,
            revision: 9,
            old_network: testkit::network(),
        },
        new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW),
        gk_epoch: cutover_gk_epoch(&service, op),
        rs_epoch: 0,
        digest: [0xEE; 32],
        status: 0,
    };
    let stale = stale.encode().unwrap().to_vec();
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            member.node,
            1,
            testkit::network(),
            &stale,
            HostTime::sync(T0 + 20_000),
        )
    });
    assert!(!moved);
    tick(&service, T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS - 1);
    assert_eq!(
        operation(&service, op, T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS - 1)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("preparing")
    );
    // The window lapses with the gateway ACK in hand: commit.
    tick(&service, T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS);
    let view = operation(&service, op, T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS);
    assert_eq!(view.get("phase").unwrap().as_str(), Some("committed"));
    assert_eq!(view.get("new_site_epoch").unwrap().as_u64(), Some(4));
    let (status, _) =
        service.with(|a| a.status_json(HostTime::sync(T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS)));
    assert!(status.contains("\"site_epoch\":4"), "{status}");
    // COMMITs flow over the old context — the member first: the
    // gateway adopts last, so its retire+reboot cannot partition
    // members that have not been served yet (#168 cutover).
    // RouteState queries drain ahead of the COMMITs (04 §7), one
    // mail per paced tick, so pump until the member COMMIT lands.
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    let commits = || {
        sends
            .lock()
            .unwrap()
            .grants
            .iter()
            .filter(|(_, _, b)| b[1] == Phase::Commit as u8)
            .cloned()
            .collect::<Vec<_>>()
    };
    let mut at = committed_at;
    for _ in 0..8 {
        if commits().len() == 1 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits().len(), 1);
    assert_eq!(commits()[0].0, member.node);
    let new_network = (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW);
    let applied = |node: u64, at: u64| {
        let commit_object = service
            .with(|a| {
                a.operations
                    .get(&op)
                    .unwrap()
                    .cutover
                    .as_ref()
                    .unwrap()
                    .commit_object
                    .clone()
            })
            .0;
        let head = Head {
            phase: Phase::Applied,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        };
        let view = operation(&service, op, at);
        let rs = view.get("commit_rs_epoch").unwrap().as_u64().unwrap() as u32;
        let receipt = Receipt {
            head,
            new_network,
            gk_epoch: cutover_gk_epoch(&service, op),
            rs_epoch: rs,
            digest: sha256(&commit_object),
            status: 0,
        };
        let bytes = receipt.encode().unwrap().to_vec();
        let (moved, _) = service
            .with(|a| a.handle_grant_receipt(node, 1, new_network, &bytes, HostTime::sync(at)));
        assert!(moved);
    };
    // The member APPLIEDs; the held gateway COMMIT follows on the tick.
    applied(member.node, at + 100);
    for _ in 0..8 {
        if commits().len() == 2 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits().len(), 2);
    assert_eq!(commits()[1].0, gateway.node);
    applied(gateway.node, at + 100);
    tick(&service, at + 200);
    let view = operation(&service, op, at + 200);
    assert_eq!(view.get("phase").unwrap().as_str(), Some("converged"));
    assert_eq!(view.get("unknown").unwrap().as_u64(), Some(0));
}

/// #168 cutover: the held gateway COMMIT flushes once little grace
/// remains, even while a member never settles — a dead member must
/// not wedge the site (the unserved fall back to the ZT reissue).
#[test]
fn cutover_flushes_the_held_gateway_commit() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let mut member = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    join_member(
        &service,
        &transport,
        &mut member,
        ROLE_ENDPOINT,
        "m",
        T0 + 5_000,
    );
    let sends = with_grant_transport(&service);
    let (_op, _) = start_cutover(&service, "cut-flush", T0 + 10_000);
    tick(&service, T0 + 10_000);
    tick(&service, T0 + 10_100);
    tick(&service, T0 + 10_200);
    for (node, _, bytes) in sends.lock().unwrap().grants.clone() {
        let receipt = Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: _op,
                revision: 1,
                old_network: testkit::network(),
            },
            new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32)
                | u64::from(testkit::NETWORK_LOW),
            gk_epoch: cutover_gk_epoch(&service, _op),
            rs_epoch: 0,
            digest: sha256(&bytes),
            status: 0,
        };
        let bytes = receipt.encode().unwrap().to_vec();
        let (moved, _) = service.with(|a| {
            a.handle_grant_receipt(
                node,
                1,
                testkit::network(),
                &bytes,
                HostTime::sync(T0 + 20_000),
            )
        });
        assert!(moved);
    }
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    // The member COMMIT flows; the gateway's is held (no flush yet).
    // Queries drain first (04 §7), so pump until it lands.
    let commits = || {
        sends
            .lock()
            .unwrap()
            .grants
            .iter()
            .filter(|(_, _, b)| b[1] == Phase::Commit as u8)
            .cloned()
            .collect::<Vec<_>>()
    };
    let mut at = committed_at;
    for _ in 0..8 {
        if commits().len() == 1 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits().len(), 1);
    assert_eq!(commits()[0].0, member.node);
    // The member never settles; near the grace end the gateway COMMIT
    // flushes anyway while the member plan closes (no more retries —
    // the unserved fall back to the ZT reissue).
    let flush_at = committed_at + CUTOVER_GRACE_MS - CUTOVER_GATEWAY_FLUSH_MS + 100;
    tick(&service, flush_at);
    tick(&service, flush_at + 100);
    let flushed = commits();
    assert_eq!(flushed.len(), 2);
    assert_eq!(flushed[1].0, gateway.node);
    let deferred = service
        .with(|a| {
            a.cutover_routes
                .get(&(_op, member.node))
                .is_some_and(|plan| plan.deferred)
        })
        .0;
    assert!(deferred, "the plan closes the unsettled member");
}

/// #168 cutover / 04 §7: an authenticated old-context APPLIED counts
/// inside the COMMIT grace (the device adopts over its old channel
/// and reports before any new-context channel exists); past the
/// grace only the new context proves.
#[test]
fn cutover_accepts_grace_applied_only_in_grace() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let mut member = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    join_member(
        &service,
        &transport,
        &mut member,
        ROLE_ENDPOINT,
        "m",
        T0 + 5_000,
    );
    let sends = with_grant_transport(&service);
    let (op, _) = start_cutover(&service, "cut-grace-applied", T0 + 10_000);
    tick(&service, T0 + 10_000);
    tick(&service, T0 + 10_100);
    tick(&service, T0 + 10_200);
    for (node, _, bytes) in sends.lock().unwrap().grants.clone() {
        let receipt = Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: op,
                revision: 1,
                old_network: testkit::network(),
            },
            new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32)
                | u64::from(testkit::NETWORK_LOW),
            gk_epoch: cutover_gk_epoch(&service, op),
            rs_epoch: 0,
            digest: sha256(&bytes),
            status: 0,
        };
        let bytes = receipt.encode().unwrap().to_vec();
        let (moved, _) = service.with(|a| {
            a.handle_grant_receipt(
                node,
                1,
                testkit::network(),
                &bytes,
                HostTime::sync(T0 + 20_000),
            )
        });
        assert!(moved);
    }
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    let new_network = (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW);
    let applied_bytes = || {
        let (commit_object, rs) = service
            .with(|a| {
                let state = a.operations.get(&op).unwrap().cutover.as_ref().unwrap();
                (state.commit_object.clone(), state.commit_rs_epoch)
            })
            .0;
        Receipt {
            head: Head {
                phase: Phase::Applied,
                cutover_id: op,
                revision: 1,
                old_network: testkit::network(),
            },
            new_network,
            gk_epoch: cutover_gk_epoch(&service, op),
            rs_epoch: rs,
            digest: sha256(&commit_object),
            status: 0,
        }
        .encode()
        .unwrap()
        .to_vec()
    };
    // The last true in-grace instant counts; D and D+1 are rejected
    // at receive time even before a tick advances the operation phase.
    // (The bytes are built outside `with`: the builder locks too.)
    let bytes = applied_bytes();
    let deadline = committed_at + CUTOVER_GRACE_MS;
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            member.node,
            1,
            testkit::network(),
            &bytes,
            HostTime::sync(deadline - 1),
        )
    });
    assert!(moved);
    for at in [deadline, deadline + 1] {
        let (moved, _) = service.with(|a| {
            a.handle_grant_receipt(
                gateway.node,
                1,
                testkit::network(),
                &bytes,
                HostTime::sync(at),
            )
        });
        assert!(!moved, "old-context APPLIED at {at} is outside grace");
    }
    // The grace lapses with the gateway unsettled: recovery_pending.
    tick(&service, deadline + 100);
    let view = operation(&service, op, deadline + 100);
    assert_eq!(
        view.get("phase").unwrap().as_str(),
        Some("recovery_pending")
    );
    // Old-context APPLIED past the grace: ignored; new-context counts.
    let bytes = applied_bytes();
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            gateway.node,
            1,
            testkit::network(),
            &bytes,
            HostTime::sync(committed_at + CUTOVER_GRACE_MS + 200),
        )
    });
    assert!(!moved);
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            gateway.node,
            1,
            new_network,
            &bytes,
            HostTime::sync(committed_at + CUTOVER_GRACE_MS + 200),
        )
    });
    assert!(moved);
}

/// V1-R08: without a gateway PREPARED the lapse parks in
/// `waiting_gateway` on the old network; the late gateway ACK commits.
#[test]
fn cutover_waits_for_a_gateway() {
    let (service, transport) = service();
    let mut member = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut member, ROLE_ENDPOINT, "m", T0);
    let sends = with_grant_transport(&service);
    let (op, _) = start_cutover(&service, "cut-gw", T0 + 10_000);
    tick(&service, T0 + 10_100);
    assert_eq!(sends.lock().unwrap().grants.len(), 1);
    // Only the plain member ACKs; the gateway never joined, so no
    // gateway target exists — the lapse must still park, honestly.
    let prepared = {
        let bytes = sends.lock().unwrap().grants[0].2.clone();
        Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: op,
                revision: 1,
                old_network: testkit::network(),
            },
            new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32)
                | u64::from(testkit::NETWORK_LOW),
            gk_epoch: cutover_gk_epoch(&service, op),
            rs_epoch: 0,
            digest: sha256(&bytes),
            status: 0,
        }
        .encode()
        .unwrap()
        .to_vec()
    };
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            member.node,
            1,
            testkit::network(),
            &prepared,
            HostTime::sync(T0 + 20_000),
        )
    });
    assert!(moved);
    let lapse = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, lapse);
    let view = operation(&service, op, lapse);
    assert_eq!(view.get("phase").unwrap().as_str(), Some("waiting_gateway"));
    assert_eq!(view.get("waiting_gateway").unwrap().as_bool(), Some(true));
    let (status, _) = service.with(|a| a.status_json(HostTime::sync(lapse)));
    assert!(
        status.contains("\"site_epoch\":3"),
        "old network kept: {status}"
    );
    // The gateway joins late, gets its PREPARE and ACKs: commit.
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    join_member(
        &service,
        &transport,
        &mut gateway,
        ROLE_GATEWAY,
        "g",
        lapse + 1_000,
    );
    tick(&service, lapse + 1_100);
    tick(&service, lapse + 1_200);
    let gw_prepare = sends
        .lock()
        .unwrap()
        .grants
        .iter()
        .find(|(n, _, b)| *n == gateway.node && b[1] == Phase::Prepare as u8)
        .unwrap()
        .2
        .clone();
    let prepared = Receipt {
        head: Head {
            phase: Phase::Prepared,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        },
        new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW),
        gk_epoch: cutover_gk_epoch(&service, op),
        rs_epoch: 0,
        digest: sha256(&gw_prepare),
        status: 0,
    }
    .encode()
    .unwrap()
    .to_vec();
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            gateway.node,
            1,
            testkit::network(),
            &prepared,
            HostTime::sync(lapse + 1_300),
        )
    });
    assert!(moved);
    tick(&service, lapse + 1_400);
    assert_eq!(
        operation(&service, op, lapse + 1_400)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("committed")
    );
}

/// V1-R08 §8.3: a revoke during Preparing commits to the current
/// network first, then invalidates every PREPARED, re-stages the next
/// GK under a new revision and restarts the window; the issued grant
/// survives into the next RRS1 as a carry entry.
#[test]
fn revoke_during_prepare_restages_and_carries() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    join_member(
        &service,
        &transport,
        &mut keeper,
        ROLE_ENDPOINT,
        "k",
        T0 + 1_000,
    );
    join_member(
        &service,
        &transport,
        &mut leaver,
        ROLE_ENDPOINT,
        "l",
        T0 + 2_000,
    );
    let sends = with_grant_transport(&service);
    let (op, _) = start_cutover(&service, "cut-r", T0 + 10_000);
    for t in 0..4 {
        tick(&service, T0 + 10_000 + t * 100);
    }
    assert_eq!(sends.lock().unwrap().grants.len(), 3);
    // The keeper PREPAREs at revision 1.
    let keeper_prepare = sends
        .lock()
        .unwrap()
        .grants
        .iter()
        .find(|(n, _, _)| *n == keeper.node)
        .unwrap()
        .2
        .clone();
    let prepared = |bytes: &[u8]| {
        Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: op,
                revision: 1,
                old_network: testkit::network(),
            },
            new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32)
                | u64::from(testkit::NETWORK_LOW),
            gk_epoch: cutover_gk_epoch(&service, op),
            rs_epoch: 0,
            digest: sha256(bytes),
            status: 0,
        }
        .encode()
        .unwrap()
        .to_vec()
    };
    let bytes = prepared(&keeper_prepare);
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            keeper.node,
            1,
            testkit::network(),
            &bytes,
            HostTime::sync(T0 + 11_000),
        )
    });
    assert!(moved);
    // A transport refusal from revision 1 must not delay the freshly
    // restaged PREPARE for this same member and operation.
    service.with(|a| {
        a.rrs_refusals.insert(
            (op, keeper.node, super::revocation::OutboundKind::Prepare),
            (T0 + 72_000, 4),
        );
    });
    // Revoke the leaver mid-prepare.
    let (answer, _) = service.with(|a| {
        a.revoke(
            DECIDER,
            RevokeRequest {
                device: leaver.node,
                expected_generation: 1,
                reason: RevocationReason::Lost,
                key: "rev-mid".into(),
            },
            HostTime::sync(T0 + 12_000),
        )
    });
    let answer = json(&answer.unwrap());
    assert_eq!(answer.get("rs_epoch").unwrap().as_u64(), Some(2));
    let view = operation(&service, op, T0 + 12_000);
    assert_eq!(view.get("revision").unwrap().as_u64(), Some(2));
    assert_eq!(view.get("prepared").unwrap().as_u64(), Some(0));
    // The revision-1 PREPARED no longer counts; the keeper re-PREPAREs
    // at revision 2 with the re-staged key.
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            keeper.node,
            1,
            testkit::network(),
            &bytes,
            HostTime::sync(T0 + 12_100),
        )
    });
    assert!(!moved, "stale-revision PREPARED is ignored");
    for t in 0..4 {
        tick(&service, T0 + 12_100 + t * 100);
    }
    let rev2: Vec<_> = sends
        .lock()
        .unwrap()
        .grants
        .iter()
        .filter(|(_, _, b)| {
            b[1] == Phase::Prepare as u8 && u32::from_be_bytes(b[12..16].try_into().unwrap()) == 2
        })
        .cloned()
        .collect();
    assert_eq!(
        rev2.len(),
        2,
        "keeper + gateway at revision 2, leaver excluded"
    );
    // The window restarted: the original lapse does not commit.
    tick(&service, T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS);
    assert_eq!(
        operation(&service, op, T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("preparing")
    );
}

/// The shared outbox paces on the wall axis while the cutover
/// window runs on the monotonic one: with split clocks (production),
/// PREPAREs pace and retry on unix while the window lapses on mono.
/// (A mono/unix mixup here parks grants behind a retry gate that can
/// never open — `HostTime::sync` tests cannot see it.)
#[test]
fn cutover_survives_split_clocks() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    let sends = with_grant_transport(&service);
    let (answer, _) = service.with(|a| {
        a.cutover(
            DECIDER,
            CutoverRequest {
                expected_site_epoch: testkit::SITE_EPOCH,
                next_site_cert: next_site_cert(),
                key: "cut-split".into(),
            },
            HostTime {
                mono_ms: 100_000,
                unix_ms: T0 + 10_000,
            },
        )
    });
    let answer = json(&answer.unwrap());
    assert_eq!(answer.get("state").unwrap().as_str(), Some("preparing"));
    let tick_at = |service: &SiteService, mono: u64, unix: u64| {
        service.with(|a| {
            a.tick(HostTime {
                mono_ms: mono,
                unix_ms: unix,
            })
        });
    };
    tick_at(&service, 100_100, T0 + 10_100);
    assert_eq!(sends.lock().unwrap().grants.len(), 1);
    // Inside the 5 s backoff nothing requeues; past it the PREPARE
    // retries on the wall axis.
    tick_at(&service, 100_200, T0 + 10_200);
    assert_eq!(sends.lock().unwrap().grants.len(), 1);
    tick_at(&service, 100_300, T0 + 16_000);
    assert_eq!(sends.lock().unwrap().grants.len(), 2);
}

/// V1-R01/R08: a restart mid-prepare restarts the window without
/// consuming new epochs; a restart after commit ends the old-network
/// grace and parks stragglers in recovery_pending.
#[test]
fn cutover_survives_restart() {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-cutover-restart-{}-{}",
        std::process::id(),
        crate::now_ms()
    ));
    routeloom_peercred::create_private_dir_all(&dir).unwrap();
    let path = dir.join("site.db");
    let open = |at: u64| {
        let store = super::store::SqliteSiteStore::open(&path).expect("site store");
        let service = SiteService::new(testkit::authority(Box::new(store), at));
        let transport = InProcessTransport::new();
        service.set_transport(transport.clone());
        (service, transport)
    };
    let (service, transport) = open(T0);
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    let sends = with_grant_transport(&service);
    let (op, _) = start_cutover(&service, "cut-rs", T0 + 10_000);
    tick(&service, T0 + 10_100);
    assert_eq!(sends.lock().unwrap().grants.len(), 1);
    drop(service);
    // Reopen before the lapse: the window restarts, the serials and the
    // staged key are reused, nothing new is consumed.
    let (service, _) = open(T0 + 20_000);
    let sends = with_grant_transport(&service);
    let view = operation(&service, op, T0 + 20_000);
    assert_eq!(view.get("phase").unwrap().as_str(), Some("preparing"));
    assert_eq!(view.get("revision").unwrap().as_u64(), Some(1));
    tick(&service, T0 + 20_100);
    assert_eq!(sends.lock().unwrap().grants.len(), 1, "PREPARE reflows");
    let (serial_meta, _) = service.with(|a| {
        a.store
            .load()
            .unwrap()
            .meta
            .get("next_serial")
            .map(|b| u32::from_be_bytes(b.as_slice().try_into().unwrap()))
            .unwrap_or(0)
    });
    // One member: serial 1 (current cert) + 2 (next cert) consumed at
    // allow/prepare time; the restart consumed nothing more.
    assert_eq!(serial_meta, 3);
    drop(service);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// V1-R07/R08: the reissue path needs no decider verdict — a member that
/// missed the cutover full-joins and gets the active-epoch cert back.
#[test]
fn missed_cutover_reissues_without_decider() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let mut straggler = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    join_member(
        &service,
        &transport,
        &mut straggler,
        ROLE_ENDPOINT,
        "m",
        T0 + 1_000,
    );
    let sends = with_grant_transport(&service);
    let (op, _) = start_cutover(&service, "cut-re", T0 + 10_000);
    for t in 0..3 {
        tick(&service, T0 + 10_000 + t * 100);
    }
    // Only the gateway ACKs; the straggler hears nothing.
    let gw_prepare = sends
        .lock()
        .unwrap()
        .grants
        .iter()
        .find(|(n, _, _)| *n == gateway.node)
        .unwrap()
        .2
        .clone();
    let prepared = Receipt {
        head: Head {
            phase: Phase::Prepared,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        },
        new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW),
        gk_epoch: cutover_gk_epoch(&service, op),
        rs_epoch: 0,
        digest: sha256(&gw_prepare),
        status: 0,
    }
    .encode()
    .unwrap()
    .to_vec();
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            gateway.node,
            1,
            testkit::network(),
            &prepared,
            HostTime::sync(T0 + 11_000),
        )
    });
    assert!(moved);
    let lapse = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, lapse);
    assert_eq!(
        operation(&service, op, lapse)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("committed")
    );
    // The straggler comes back on its old RLS1 and asks. No join
    // request may appear: this is an authenticated reissue.
    straggler.recovery_existing = true;
    let (outcome, events) = straggler.attempt(&service, &transport, lapse + 5_000);
    let kinds = testkit::kinds(&events);
    assert!(
        !kinds.iter().any(|k| k == "join.request"),
        "no decider round-trip: {kinds:?}"
    );
    assert!(
        kinds.iter().any(|k| k == "member.reissued"),
        "reissued: {kinds:?}"
    );
    match outcome {
        Outcome::Result(JoinResult::Allow { .. }) => {}
        other => panic!("expected Allow, got {other:?}"),
    }
    let state = straggler.site.as_ref().unwrap();
    assert_eq!(state.member.network >> 32, 4, "active-epoch cert");
    assert_eq!(
        state.member.assignment_generation, 1,
        "cutover keeps the generation"
    );
}

/// A readmitted replacement key (#146) cannot suppress the old key's
/// recovery notice.
#[test]
fn old_kid_recovery_gets_removed() {
    let (service, transport) = service();
    let mut old = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut old, ROLE_ENDPOINT, "m", T0);
    let (answer, _) = service.with(|a| {
        a.revoke(
            DECIDER,
            RevokeRequest {
                device: old.node,
                expected_generation: 1,
                reason: RevocationReason::Replaced,
                key: "rev-replace".into(),
            },
            HostTime::sync(T0 + 1_000),
        )
    });
    answer.unwrap();
    // Once the revoke's rotation activated, a different key reclaims the
    // NodeId above the revoked generation.
    service.tick(HostTime::sync(T0 + 40_000));
    let mut new = SimDevice::new(old.node, 0x72);
    let (_, _, events) = new.start(&service, &transport, T0 + 42_000);
    let (answer, _) = service.with(|a| {
        a.decide(
            DECIDER,
            super::DecideRequest {
                join_request_id: request_id(&events).unwrap(),
                device: new.node,
                verdict: Verdict::Allow {
                    role: ROLE_ENDPOINT,
                },
                key: "m2".into(),
            },
            T0 + 42_010,
        )
    });
    assert!(answer.unwrap().contains("\"generation\":2"));
    // The old key comes back holding generation 1.
    old.recovery_existing = true;
    let (outcome, _) = old.attempt(&service, &transport, T0 + 43_000);
    match outcome {
        Outcome::Result(JoinResult::Removed { .. }) => {}
        other => panic!("expected Removed, got {other:?}"),
    }
    assert!(old.site.is_none(), "device erased its site state");
}

/// RRS-full sites refuse a 33rd entry until the cutover empties the
/// set; after the commit the same generation retries cleanly.
#[test]
fn rrs_full_recovers_through_cutover() {
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    // Fill the 32-entry set with transient members.
    for i in 0..32_u64 {
        let mut d = SimDevice::new(0x00A1_0000_0001_0000 + i, (0x80 + i) as u8);
        join_member(
            &service,
            &transport,
            &mut d,
            ROLE_ENDPOINT,
            &format!("k{i}"),
            T0 + 1_000 + i,
        );
        let (answer, _) = service.with(|a| {
            a.revoke(
                DECIDER,
                RevokeRequest {
                    device: d.node,
                    expected_generation: 1,
                    reason: RevocationReason::Lost,
                    key: format!("r{i}"),
                },
                HostTime::sync(T0 + 2_000 + i),
            )
        });
        answer.unwrap();
    }
    let mut extra = SimDevice::new(0x00A1_0000_0000_7009, 0x79);
    join_member(
        &service,
        &transport,
        &mut extra,
        ROLE_ENDPOINT,
        "ke",
        T0 + 5_000,
    );
    let (answer, _) = service.with(|a| {
        a.revoke(
            DECIDER,
            RevokeRequest {
                device: extra.node,
                expected_generation: 1,
                reason: RevocationReason::Lost,
                key: "r-full".into(),
            },
            HostTime::sync(T0 + 6_000),
        )
    });
    let err = answer.unwrap_err();
    assert_eq!(err.code, "CUTOVER_REQUIRED");
    // Cut over with only the gateway (all others removed): the next
    // set starts empty and the retry commits. Notices queue ahead of
    // grants (§7.1), so the 32 removal notices drain first — bounded
    // (3 sends each) against the 600 s window.
    let sends = with_grant_transport(&service);
    let (op, _) = start_cutover(&service, "cut-full", T0 + 10_000);
    let mut at = T0 + 10_000;
    for _ in 0..200 {
        tick(&service, at);
        at += 100;
        if sends.lock().unwrap().grants.len() >= 2 {
            break;
        }
    }
    assert_eq!(sends.lock().unwrap().grants.len(), 2, "gateway + extra");
    for (node, _, bytes) in sends.lock().unwrap().grants.clone() {
        let receipt = Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: op,
                revision: 1,
                old_network: testkit::network(),
            },
            new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32)
                | u64::from(testkit::NETWORK_LOW),
            gk_epoch: cutover_gk_epoch(&service, op),
            rs_epoch: 0,
            digest: sha256(&bytes),
            status: 0,
        };
        let bytes = receipt.encode().unwrap().to_vec();
        let (moved, _) = service.with(|a| {
            a.handle_grant_receipt(
                node,
                1,
                testkit::network(),
                &bytes,
                HostTime::sync(T0 + 11_000),
            )
        });
        assert!(moved);
    }
    let lapse = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, lapse);
    assert_eq!(
        operation(&service, op, lapse)
            .get("phase")
            .unwrap()
            .as_str(),
        Some("committed")
    );
    let (answer, _) = service.with(|a| {
        a.revoke(
            DECIDER,
            RevokeRequest {
                device: extra.node,
                expected_generation: 1,
                reason: RevocationReason::Lost,
                key: "r-retry".into(),
            },
            HostTime::sync(lapse + 1_000),
        )
    });
    let answer = json(&answer.unwrap());
    assert_eq!(answer.get("rs_epoch").unwrap().as_u64(), Some(35));
}

/// The RemovalNotice outbox: the revoke commits the notice, the tick
/// sends it after commit (never before), and the accept receipt flips
/// `intent_confirmed` — while `erase_confirmed` stays honestly null.
#[test]
fn removal_notice_outbox_and_accept() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(&service, &transport, &mut keeper, ROLE_ENDPOINT, "k", T0);
    join_member(
        &service,
        &transport,
        &mut leaver,
        ROLE_ENDPOINT,
        "l",
        T0 + 1_000,
    );
    let sends = with_grant_transport(&service);
    let (answer, _) = service.with(|a| {
        a.revoke(
            DECIDER,
            RevokeRequest {
                device: leaver.node,
                expected_generation: 1,
                reason: RevocationReason::Lost,
                key: "r-notice".into(),
            },
            HostTime::sync(T0 + 2_000),
        )
    });
    let answer = json(&answer.unwrap());
    let op = parse_op_token(answer.get("operation_id").unwrap().as_str().unwrap()).unwrap();
    assert!(
        sends.lock().unwrap().notices.is_empty(),
        "nothing before the tick"
    );
    tick(&service, T0 + 2_100);
    let notices = sends.lock().unwrap().notices.clone();
    assert_eq!(notices.len(), 1);
    assert_eq!(notices[0].0, leaver.node);
    assert_eq!(notices[0].1, testkit::network());
    assert_eq!(notices[0].2.len(), 103);
    let (view, _) = service.with(|a| a.operation_json(op, HostTime::sync(T0 + 2_100)).unwrap());
    let view = json(&view);
    let notice = view.get("notice").unwrap();
    assert_eq!(notice.get("delivery").unwrap().as_str(), Some("sent"));
    assert_eq!(
        notice.get("intent_confirmed").unwrap().as_bool(),
        Some(false)
    );
    assert!(notice.get("erase_confirmed").unwrap().is_null());
    // The accept receipt (type 5 sub 3) confirms the durable intent.
    let digest = sha256(&notices[0].2);
    let (moved, _) = service.with(|a| {
        a.handle_notice_accepted(leaver.node, 1, testkit::network(), 1, &digest, T0 + 2_200)
    });
    assert!(moved);
    let (view, _) = service.with(|a| a.operation_json(op, HostTime::sync(T0 + 2_200)).unwrap());
    let notice = json(&view).get("notice").unwrap().clone();
    assert_eq!(
        notice.get("intent_confirmed").unwrap().as_bool(),
        Some(true)
    );
    // A forged accept (wrong hash, wrong generation, future set)
    // never counts.
    let (moved, _) = service.with(|a| {
        a.handle_notice_accepted(leaver.node, 2, testkit::network(), 1, &digest, T0 + 2_300)
    });
    assert!(!moved);
    let (moved, _) = service.with(|a| {
        a.handle_notice_accepted(leaver.node, 1, testkit::network(), 999, &digest, T0 + 2_300)
    });
    assert!(!moved);
    // The confirmed notice never resends, even inside its window.
    tick(&service, T0 + 2_400);
    tick(&service, T0 + 2_500);
    assert_eq!(sends.lock().unwrap().notices.len(), 1);
}

/// The direct-notice window is 60 s from the revoke commit: past it
/// the notice closes (attempts capped, delivery history kept) and
/// never sends again — while the RRS1 fan-out to survivors proceeds
/// independently of the unconfirmed notice.
#[test]
fn notice_direct_send_closes_after_60s() {
    use super::p6_channel::P6_BINDING_GRACE_MS;
    use super::revocation::NOTICE_SEND_MAX;

    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(&service, &transport, &mut keeper, ROLE_ENDPOINT, "k", T0);
    join_member(
        &service,
        &transport,
        &mut leaver,
        ROLE_ENDPOINT,
        "l",
        T0 + 1_000,
    );
    let sends = with_grant_transport(&service);
    let commit_at = T0 + 2_000;
    let (answer, _) = service.with(|a| {
        a.revoke(
            DECIDER,
            RevokeRequest {
                device: leaver.node,
                expected_generation: 1,
                reason: RevocationReason::Lost,
                key: "r-notice-window".into(),
            },
            HostTime::sync(commit_at),
        )
    });
    let answer = json(&answer.unwrap());
    let op = parse_op_token(answer.get("operation_id").unwrap().as_str().unwrap()).unwrap();
    tick(&service, commit_at + 100);
    assert_eq!(sends.lock().unwrap().notices.len(), 1);
    // Past the window the direct send closes: no more airtime even
    // though the transport would still deliver.
    tick(&service, commit_at + P6_BINDING_GRACE_MS);
    tick(&service, commit_at + P6_BINDING_GRACE_MS + 1_000);
    assert_eq!(sends.lock().unwrap().notices.len(), 1);
    let view = operation(&service, op, commit_at + P6_BINDING_GRACE_MS + 1_000);
    let notice = view.get("notice").unwrap();
    assert_eq!(notice.get("delivery").unwrap().as_str(), Some("sent"));
    assert_eq!(
        notice.get("intent_confirmed").unwrap().as_bool(),
        Some(false)
    );
    let attempts = service
        .with(|a| {
            a.operations
                .get(&op)
                .unwrap()
                .notice
                .as_ref()
                .unwrap()
                .attempts
        })
        .0;
    assert_eq!(attempts, NOTICE_SEND_MAX);
    // The survivor's RRS1 fan-out never waited on the notice.
    assert!(
        sends
            .lock()
            .unwrap()
            .rrs
            .iter()
            .any(|(node, _)| *node == keeper.node),
        "RRS1 reaches the survivor while the notice stays unconfirmed"
    );
}

/// Cutover start refuses a next SiteCert that is not exactly the next
/// epoch under the configured Site CA — and commits nothing.
#[test]
fn cutover_refuses_a_bad_next_cert() {
    let (service, transport) = service();
    let mut member = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut member, ROLE_ENDPOINT, "m", T0);
    // Same epoch (not +1).
    let (answer, _) = service.with(|a| {
        a.cutover(
            DECIDER,
            CutoverRequest {
                expected_site_epoch: testkit::SITE_EPOCH,
                next_site_cert: testkit::site_cert(),
                key: "cut-bad".into(),
            },
            HostTime::sync(T0 + 1_000),
        )
    });
    assert!(answer.is_err());
    // Garbage bytes.
    let (answer, _) = service.with(|a| {
        a.cutover(
            DECIDER,
            CutoverRequest {
                expected_site_epoch: testkit::SITE_EPOCH,
                next_site_cert: vec![0xC0, 0xFF, 0xEE],
                key: "cut-bad2".into(),
            },
            HostTime::sync(T0 + 1_000),
        )
    });
    assert!(answer.is_err());
    // A second cutover while one is live is refused.
    with_grant_transport(&service);
    let (_, _) = start_cutover(&service, "cut-ok", T0 + 2_000);
    let (answer, _) = service.with(|a| {
        a.cutover(
            DECIDER,
            CutoverRequest {
                expected_site_epoch: testkit::SITE_EPOCH,
                next_site_cert: next_site_cert(),
                key: "cut-dup".into(),
            },
            HostTime::sync(T0 + 3_000),
        )
    });
    let err = answer.unwrap_err();
    assert_eq!(err.code, "CONFLICT");
}

/// Joins the gateway plus `members`, stages a cutover, and PREPAREs
/// every target: the common route-tree-test setup. Returns the op and
/// the shared sends; member nodes keep their join order.
fn start_tree(
    service: &SiteService,
    transport: &Arc<InProcessTransport>,
    key: &str,
    members: &[u64],
) -> (u64, Arc<Mutex<GrantSends>>) {
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    join_member(service, transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    for (i, node) in members.iter().enumerate() {
        let mut member = SimDevice::new(*node, 0x71 + i as u8);
        join_member(
            service,
            transport,
            &mut member,
            ROLE_ENDPOINT,
            &format!("m{i}"),
            T0 + 1_000 * (i as u64 + 1),
        );
    }
    let sends = with_grant_transport(service);
    let (op, _) = start_cutover(service, key, T0 + 10_000);
    for t in 0..(members.len() + 2) {
        tick(service, T0 + 10_000 + t as u64 * 100);
    }
    for (node, _, bytes) in sends.lock().unwrap().grants.clone() {
        if bytes[1] != Phase::Prepare as u8 {
            continue;
        }
        let receipt = Receipt {
            head: Head {
                phase: Phase::Prepared,
                cutover_id: op,
                revision: 1,
                old_network: testkit::network(),
            },
            new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32)
                | u64::from(testkit::NETWORK_LOW),
            gk_epoch: cutover_gk_epoch(service, op),
            rs_epoch: 0,
            digest: sha256(&bytes),
            status: 0,
        };
        let bytes = receipt.encode().unwrap().to_vec();
        let (moved, _) = service.with(|a| {
            a.handle_grant_receipt(
                node,
                1,
                testkit::network(),
                &bytes,
                HostTime::sync(T0 + 20_000),
            )
        });
        assert!(moved, "PREPARED counts for {node:016x}");
    }
    (op, sends)
}

/// 04 §7: COMMITs dispatch leaf-first over the route tree — a relay
/// moves only after its whole reporting subtree stored, the gateway
/// after every member settled. APPLIED stays zero throughout: parents
/// move on COMMIT_STORED, never on adoption.
#[test]
fn cutover_commits_leaf_first_over_the_route_tree() {
    let (service, transport) = service();
    let r1 = 0x00A1_0000_0000_7101;
    let r2 = 0x00A1_0000_0000_7102;
    let leaf = 0x00A1_0000_0000_7103;
    let branch = 0x00A1_0000_0000_7104;
    let gw = testkit::GATEWAY;
    let (op, sends) = start_tree(&service, &transport, "cut-tree", &[r1, r2, leaf, branch]);
    for (node, parent) in [(r1, gw), (r2, r1), (leaf, r2), (branch, gw)] {
        assert!(
            adopt_route_report(&service, op, node, gw, parent, T0 + 20_000),
            "report adopts for {node:016x}"
        );
    }
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    let commits = || {
        sends
            .lock()
            .unwrap()
            .grants
            .iter()
            .filter(|(_, _, b)| b[1] == Phase::Commit as u8)
            .map(|(n, _, _)| *n)
            .collect::<Vec<_>>()
    };
    let mut at = committed_at;
    let pump =
        |sends: &Arc<Mutex<GrantSends>>, service: &SiteService, at: &mut u64, want: usize| {
            for _ in 0..12 {
                let n = sends
                    .lock()
                    .unwrap()
                    .grants
                    .iter()
                    .filter(|(_, _, b)| b[1] == Phase::Commit as u8)
                    .count();
                if n == want {
                    break;
                }
                *at += 100;
                tick(service, *at);
            }
        };
    // The two leaves go first, in target order; relays hold.
    pump(&sends, &service, &mut at, 2);
    assert_eq!(commits(), vec![leaf, branch]);
    // Each stored receipt releases exactly its parent, down the chain.
    assert!(inject_commit_stored(&service, op, leaf, at + 50));
    assert!(adopt_route_report(&service, op, r2, gw, r1, at + 50));
    pump(&sends, &service, &mut at, 3);
    assert_eq!(commits()[2], r2);
    assert!(inject_commit_stored(&service, op, r2, at + 50));
    assert!(adopt_route_report(&service, op, r1, gw, gw, at + 50));
    pump(&sends, &service, &mut at, 4);
    assert_eq!(commits()[3], r1);
    assert!(inject_commit_stored(&service, op, branch, at + 50));
    assert!(inject_commit_stored(&service, op, r1, at + 50));
    pump(&sends, &service, &mut at, 5);
    assert_eq!(commits()[4], gw);
    // No APPLIED anywhere: the whole chain moved on STORED alone.
    let view = operation(&service, op, at);
    assert_eq!(view.get("applied").unwrap().as_u64(), Some(0));
}

/// 04 §7: a route cycle resolves to nothing — the pair holds each
/// other past the deepest layer, then defers to the ZT reissue at the
/// earliest cutoff while the healthy chain proceeds. The gateway only
/// moves once the cycle settled (deferred).
#[test]
fn cutover_cycle_defers_early_without_blocking_the_chain() {
    let (service, transport) = service();
    let r = 0x00A1_0000_0000_7201;
    let leaf = 0x00A1_0000_0000_7202;
    let m = 0x00A1_0000_0000_7203;
    let n = 0x00A1_0000_0000_7204;
    let gw = testkit::GATEWAY;
    let (op, sends) = start_tree(&service, &transport, "cut-cycle", &[r, leaf, m, n]);
    for (node, parent) in [(r, gw), (leaf, r), (m, n), (n, m)] {
        assert!(adopt_route_report(
            &service,
            op,
            node,
            gw,
            parent,
            T0 + 20_000
        ));
    }
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    let commits = || {
        sends
            .lock()
            .unwrap()
            .grants
            .iter()
            .filter(|(_, _, b)| b[1] == Phase::Commit as u8)
            .map(|(n, _, _)| *n)
            .collect::<Vec<_>>()
    };
    // The healthy leaf moves at once; the cycle and the relay hold.
    let mut at = committed_at;
    for _ in 0..12 {
        if commits().len() == 1 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits(), vec![leaf]);
    assert!(inject_commit_stored(&service, op, leaf, at + 50));
    assert!(adopt_route_report(&service, op, r, gw, gw, at + 50));
    assert!(adopt_route_report(&service, op, m, gw, n, at + 50));
    assert!(adopt_route_report(&service, op, n, gw, m, at + 50));
    for _ in 0..12 {
        if commits().len() == 2 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits()[1], r);
    // The cycle (unresolved, deepest layer) defers at the earliest
    // cutoff — H=2 here, so T0+20 s — without ever dispatching.
    assert!(!commits().contains(&m) && !commits().contains(&n));
    tick(&service, committed_at + 21_000);
    at = committed_at + 21_000;
    assert!(!commits().contains(&m) && !commits().contains(&n));
    for node in [m, n] {
        let deferred = service
            .with(|a| {
                a.cutover_routes
                    .get(&(op, node))
                    .is_some_and(|plan| plan.deferred)
            })
            .0;
        assert!(deferred, "cycle member {node:016x} deferred");
    }
    // With the cycle settled, the relay's stored receipt releases the
    // gateway; the healthy three apply, and only the cycle pair stays
    // unknown for the ZT reissue.
    assert!(inject_commit_stored(&service, op, r, at + 50));
    for _ in 0..12 {
        if commits().contains(&gw) {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert!(commits().contains(&gw));
    for node in [leaf, r, gw] {
        assert!(inject_applied(&service, op, node, at + 50));
    }
    tick(&service, at + 100);
    let view = operation(&service, op, at + 100);
    assert_eq!(view.get("applied").unwrap().as_u64(), Some(3));
    assert_eq!(view.get("unknown").unwrap().as_u64(), Some(2));
}

/// 04 §7: the first 40 s split into H layer frames from the deepest
/// layer — each unconfirmed layer defers at its own cutoff, which
/// releases its parent, and a deferred target sends no more COMMITs.
#[test]
fn cutover_layer_deadlines_defer_deepest_first() {
    let (service, transport) = service();
    let r = 0x00A1_0000_0000_7301;
    let leaf = 0x00A1_0000_0000_7302;
    let gw = testkit::GATEWAY;
    let (op, sends) = start_tree(&service, &transport, "cut-layer", &[r, leaf]);
    assert!(adopt_route_report(&service, op, r, gw, gw, T0 + 20_000));
    assert!(adopt_route_report(&service, op, leaf, gw, r, T0 + 20_000));
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    let commits_to = |node: u64| {
        sends
            .lock()
            .unwrap()
            .grants
            .iter()
            .filter(|(n, _, b)| *n == node && b[1] == Phase::Commit as u8)
            .count()
    };
    // H=2: the leaf (depth 2) owns the first frame, T0+20 s.
    let mut at = committed_at;
    for _ in 0..12 {
        if commits_to(leaf) == 1 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits_to(r), 0, "relay holds for the leaf");
    tick(&service, committed_at + 19_000);
    assert_eq!(commits_to(r), 0, "still held before the leaf cutoff");
    // Past T0+20 s the leaf defers, its COMMITs stop, and the relay —
    // settled child — moves.
    tick(&service, committed_at + 21_000);
    at = committed_at + 21_000;
    let leaf_deferred = service
        .with(|a| {
            a.cutover_routes
                .get(&(op, leaf))
                .is_some_and(|plan| plan.deferred)
        })
        .0;
    assert!(leaf_deferred);
    for _ in 0..12 {
        if commits_to(r) == 1 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits_to(r), 1);
    let leaf_sends = commits_to(leaf);
    tick(&service, committed_at + 30_000);
    assert_eq!(
        commits_to(leaf),
        leaf_sends,
        "deferred leaf sends no more COMMITs"
    );
    // The relay (depth 1) defers at T0+40 s with the plan, and only
    // the gateway still moves.
    tick(&service, committed_at + 41_000);
    at = committed_at + 41_000;
    for _ in 0..12 {
        if commits_to(gw) == 1 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits_to(gw), 1);
    let relay_sends = commits_to(r);
    tick(&service, committed_at + 50_000);
    assert_eq!(commits_to(r), relay_sends, "plan closed for members");
}

/// 04 §7: the frontier re-checks at dispatch — a COMMIT mail queued
/// while its target looked like a leaf must not jump the queue once
/// a report shows an unsettled child underneath it.
#[test]
fn cutover_dispatch_rechecks_the_frontier() {
    let (service, transport) = service();
    let r = 0x00A1_0000_0000_7401;
    let leaf = 0x00A1_0000_0000_7402;
    let (op, sends) = start_tree(&service, &transport, "cut-recheck", &[r, leaf]);
    // No reports: both members queue as unknown leaves.
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    tick(&service, committed_at + 100);
    // Before either mail drains, the tree resolves: the leaf hangs
    // under the relay, so the relay's queued COMMIT is stale.
    let gw = testkit::GATEWAY;
    assert!(adopt_route_report(
        &service,
        op,
        leaf,
        gw,
        r,
        committed_at + 100
    ));
    assert!(adopt_route_report(
        &service,
        op,
        r,
        gw,
        gw,
        committed_at + 100
    ));
    let commits = || {
        sends
            .lock()
            .unwrap()
            .grants
            .iter()
            .filter(|(_, _, b)| b[1] == Phase::Commit as u8)
            .map(|(n, _, _)| *n)
            .collect::<Vec<_>>()
    };
    // The leaf's mail still dispatches; the relay's drops at the gate.
    let mut at = committed_at + 100;
    for _ in 0..12 {
        if commits().len() == 1 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits(), vec![leaf]);
    for _ in 0..8 {
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits(), vec![leaf], "stale relay mail never sends");
    // Once the leaf stores, the relay re-queues honestly and sends.
    assert!(inject_commit_stored(&service, op, leaf, at + 50));
    assert!(adopt_route_report(&service, op, r, gw, gw, at + 50));
    for _ in 0..12 {
        if commits().len() == 2 {
            break;
        }
        at += 100;
        tick(&service, at);
    }
    assert_eq!(commits(), vec![leaf, r]);
}

/// 04 §7: RouteState queries go out only in the last minute of
/// PREPARE and never to gateways — earlier reports would expire
/// before the commit, and a root needs no uplink.
#[test]
fn cutover_queries_only_late_prepare_and_never_gateways() {
    use super::cutover::CUTOVER_ROUTE_QUERY_WINDOW_MS;
    let (service, transport) = service();
    let m = 0x00A1_0000_0000_7501;
    let (op, sends) = start_tree(&service, &transport, "cut-query", &[m]);
    let queries = || {
        sends
            .lock()
            .unwrap()
            .grants
            .iter()
            .filter(|(_, _, b)| b[1] == Phase::RouteState as u8)
            .cloned()
            .collect::<Vec<_>>()
    };
    let started = T0 + 10_000;
    // Early and mid window: nothing asks, even fully PREPARED.
    tick(&service, started + 100_000);
    tick(
        &service,
        started + CUTOVER_PREPARE_WINDOW_MS - CUTOVER_ROUTE_QUERY_WINDOW_MS - 1_000,
    );
    assert!(queries().is_empty(), "no early queries");
    // The last minute: the member gets exactly one query; the gateway
    // never does.
    tick(
        &service,
        started + CUTOVER_PREPARE_WINDOW_MS - CUTOVER_ROUTE_QUERY_WINDOW_MS + 1_000,
    );
    let asked = queries();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].0, m);
    let query = RouteState::decode(&asked[0].2).unwrap();
    assert_eq!(query.mode, 0);
    assert_ne!(query.query_id, 0);
    assert_eq!(query.head.cutover_id, op);
    assert_eq!(query.head.revision, 1);
    assert_eq!(query.head.old_network, testkit::network());
    let _ = (op, query);
}

/// 04 §7: a straggler that missed the COMMIT rejoins through the ZT
/// reissue and counts Recovered — never Applied — once its JoinConfirm
/// (current MemberCert), its RRS Applied, and its current GK all
/// evidenced. Any missing third keeps it unknown; the reissue alone
/// moves nothing.
#[test]
fn cutover_straggler_recovers_through_the_reissue() {
    use super::authority_channel::{ChannelEvent, JoinConfirmFields};
    let (service, transport) = service();
    let mut gateway = SimDevice::new(testkit::GATEWAY, 0x60);
    gateway.capability |= routeloom_join::JOIN_CAPABILITY_GATEWAY;
    let mut straggler = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut gateway, ROLE_GATEWAY, "g", T0);
    join_member(
        &service,
        &transport,
        &mut straggler,
        ROLE_ENDPOINT,
        "m",
        T0 + 1_000,
    );
    let sends = with_grant_transport(&service);
    let (op, _) = start_cutover(&service, "cut-rec", T0 + 10_000);
    for t in 0..3 {
        tick(&service, T0 + 10_000 + t * 100);
    }
    // Only the gateway PREPAREs; the straggler hears nothing.
    let gw_prepare = sends
        .lock()
        .unwrap()
        .grants
        .iter()
        .find(|(n, _, _)| *n == gateway.node)
        .unwrap()
        .2
        .clone();
    let prepared = Receipt {
        head: Head {
            phase: Phase::Prepared,
            cutover_id: op,
            revision: 1,
            old_network: testkit::network(),
        },
        new_network: (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW),
        gk_epoch: cutover_gk_epoch(&service, op),
        rs_epoch: 0,
        digest: sha256(&gw_prepare),
        status: 0,
    }
    .encode()
    .unwrap()
    .to_vec();
    let (moved, _) = service.with(|a| {
        a.handle_grant_receipt(
            gateway.node,
            1,
            testkit::network(),
            &prepared,
            HostTime::sync(T0 + 11_000),
        )
    });
    assert!(moved);
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at);
    // Past the member plan the gateway COMMIT flows; it adopts while
    // the straggler — never PREPARED, never COMMITted — waits out the
    // grace into RecoveryPending.
    tick(&service, committed_at + 41_000);
    tick(&service, committed_at + 41_100);
    assert!(inject_applied(
        &service,
        op,
        gateway.node,
        committed_at + 41_100
    ));
    tick(&service, committed_at + 61_000);
    let view = operation(&service, op, committed_at + 61_000);
    assert_eq!(
        view.get("phase").unwrap().as_str(),
        Some("recovery_pending")
    );
    assert_eq!(view.get("unknown").unwrap().as_u64(), Some(1));
    // The straggler comes back on its old RLS1: reissued, no decider —
    // but the reissue alone is not recovery evidence.
    straggler.recovery_existing = true;
    let (outcome, _) = straggler.attempt(&service, &transport, committed_at + 65_000);
    assert!(matches!(outcome, Outcome::Result(JoinResult::Allow { .. })));
    let target_state = |service: &SiteService| {
        service
            .with(|a| {
                a.operations
                    .get(&op)
                    .unwrap()
                    .cutover
                    .as_ref()
                    .unwrap()
                    .targets
                    .iter()
                    .find(|t| t.node == straggler.node)
                    .unwrap()
                    .state
            })
            .0
    };
    assert_eq!(target_state(&service), GrantState::Unknown);
    // JoinConfirm with the current MemberCert and the active GK: two
    // thirds evidenced, still unknown without the RRS Applied.
    let (cert_hash, generation, active) = service
        .with(|a| {
            let row = a.devices.get(&straggler.node).unwrap();
            (
                sha256(&row.member_cert),
                row.generation,
                a.gks.active_epoch(),
            )
        })
        .0;
    assert_ne!(active, 0);
    service.with(|a| {
        a.map_channel_event(
            ChannelEvent::JoinConfirm {
                device: straggler.node,
                confirm: JoinConfirmFields {
                    generation,
                    request_id: 3,
                    cert_hash,
                    boot: 1,
                    current: active,
                    next: 0,
                },
            },
            HostTime::sync(committed_at + 66_000),
        );
    });
    assert_eq!(target_state(&service), GrantState::Unknown);
    // A later revoke distributes the current RRS on the new network;
    // the straggler's Applied for it completes the recovery.
    let mut victim = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member(
        &service,
        &transport,
        &mut victim,
        ROLE_ENDPOINT,
        "v",
        committed_at + 67_000,
    );
    let (answer, _) = service.with(|a| {
        a.revoke(
            DECIDER,
            RevokeRequest {
                device: victim.node,
                expected_generation: 1,
                reason: RevocationReason::Removed,
                key: "rev-v".into(),
            },
            HostTime::sync(committed_at + 68_000),
        )
    });
    answer.unwrap();
    let new_network = (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW);
    let (rs_epoch, digest) = service
        .with(|a| {
            let dist = a
                .operations
                .values()
                .filter_map(|op| op.distribution.as_ref())
                .find(|dist| {
                    dist.network == new_network
                        && dist.targets.iter().any(|t| t.node == straggler.node)
                })
                .unwrap();
            let rs = dist.rs_epoch;
            (rs, *a.rrs_history_digests.get(&rs).unwrap())
        })
        .0;
    let mut body = vec![1u8, 1, 0, 0];
    body.extend_from_slice(&rs_epoch.to_be_bytes());
    body.extend_from_slice(&digest);
    service.with(|a| {
        a.apply_type5_receipt(
            super::p6_channel::P6Receipt {
                device: straggler.node,
                generation,
                network: new_network,
                env_type: 5,
                body,
            },
            HostTime::sync(committed_at + 69_000),
        );
    });
    assert_eq!(target_state(&service), GrantState::Recovered);
    // Recovered converges like Applied but never counts as it: the
    // straggler never sent an APPLIED for a COMMIT it never held.
    let view = operation(&service, op, committed_at + 69_000);
    assert_eq!(view.get("applied").unwrap().as_u64(), Some(1));
    assert_eq!(view.get("recovered").unwrap().as_u64(), Some(1));
    assert_eq!(view.get("unknown").unwrap().as_u64(), Some(0));
    assert_eq!(view.get("total").unwrap().as_u64(), Some(2));
    assert_eq!(view.get("phase").unwrap().as_str(), Some("converged"));
}
