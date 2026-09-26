//! Host site_epoch cutover acceptance (04 §7, P6-2 PR D): the V1-R08
//! scenarios as regression tests — commit-before-send, the 600 s window
//! with the gateway gate, revoke-during-prepare conflicts, restart
//! resume, the RemovalNotice outbox, old-kid recovery and the
//! no-KGuard reissue after a missed cutover.

use std::sync::{Arc, Mutex};

use routeloom_join::renew::{Head, Phase, Receipt};
use routeloom_join::JoinResult;
use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
use routeloom_provision::sdkv1::revocation::RevocationReason;
use routeloom_provision::sha256::sha256;
use routeloom_provision::signer::{test_keypair, FileRootSigner};

use super::cutover::{CutoverRequest, CutoverState, CUTOVER_PREPARE_WINDOW_MS};
use super::group_keys::HostTime;
use super::records::{parse_op_token, Verdict, ROLE_ENDPOINT, ROLE_GATEWAY};
use super::revocation::{OutboundKind, RevocationTransport};
use super::store::{MemoryStore, SiteStore};
use super::testkit::{self, request_id, Outcome, SimDevice};
use super::transport::InProcessTransport;
use super::{RevokeRequest, SiteService};

const T0: u64 = 1_790_000_000_000;
const KGUARD: u32 = 501;

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
            KGUARD,
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
            KGUARD,
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
                at + 11_000
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
    std::fs::create_dir_all(&dir).unwrap();
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
                committed_at + 60_002
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
            KGUARD,
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
                KGUARD,
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
                T0 + 11_000
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
            KGUARD,
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
        let (moved, _) = service
            .with(|a| a.handle_grant_receipt(node, 1, testkit::network(), &bytes, T0 + 20_000));
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
    let (moved, _) = service
        .with(|a| a.handle_grant_receipt(member.node, 1, testkit::network(), &stale, T0 + 20_000));
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
    // COMMITs flow over the old context; APPLIEDs converge.
    let committed_at = T0 + 10_000 + CUTOVER_PREPARE_WINDOW_MS;
    tick(&service, committed_at + 100);
    tick(&service, committed_at + 200);
    let commits: Vec<_> = sends
        .lock()
        .unwrap()
        .grants
        .iter()
        .filter(|(_, _, b)| b[1] == Phase::Commit as u8)
        .cloned()
        .collect();
    assert_eq!(commits.len(), 2);
    let new_network = (u64::from(testkit::SITE_EPOCH + 1) << 32) | u64::from(testkit::NETWORK_LOW);
    for (node, _, _) in &commits {
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
        let view = operation(&service, op, committed_at + 300);
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
            .with(|a| a.handle_grant_receipt(*node, 1, new_network, &bytes, committed_at + 300));
        assert!(moved);
    }
    tick(&service, committed_at + 400);
    let view = operation(&service, op, committed_at + 400);
    assert_eq!(view.get("phase").unwrap().as_str(), Some("converged"));
    assert_eq!(view.get("unknown").unwrap().as_u64(), Some(0));
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
        a.handle_grant_receipt(member.node, 1, testkit::network(), &prepared, T0 + 20_000)
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
            lapse + 1_300,
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
    let (moved, _) = service
        .with(|a| a.handle_grant_receipt(keeper.node, 1, testkit::network(), &bytes, T0 + 11_000));
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
            KGUARD,
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
    assert_eq!(answer.get("rs_epoch").unwrap().as_u64(), Some(1));
    let view = operation(&service, op, T0 + 12_000);
    assert_eq!(view.get("revision").unwrap().as_u64(), Some(2));
    assert_eq!(view.get("prepared").unwrap().as_u64(), Some(0));
    // The revision-1 PREPARED no longer counts; the keeper re-PREPAREs
    // at revision 2 with the re-staged key.
    let (moved, _) = service
        .with(|a| a.handle_grant_receipt(keeper.node, 1, testkit::network(), &bytes, T0 + 12_100));
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
            KGUARD,
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
    std::fs::create_dir_all(&dir).unwrap();
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
    std::fs::remove_dir_all(&dir).unwrap();
}

/// V1-R07/R08: the reissue path needs no KGuard verdict — a member that
/// missed the cutover full-joins and gets the active-epoch cert back.
#[test]
fn missed_cutover_reissues_without_kguard() {
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
        a.handle_grant_receipt(gateway.node, 1, testkit::network(), &prepared, T0 + 11_000)
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
        "no KGuard round-trip: {kinds:?}"
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

/// A rejected replacement cannot suppress the old key's recovery notice.
#[test]
fn old_kid_recovery_gets_removed() {
    let (service, transport) = service();
    let mut old = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    join_member(&service, &transport, &mut old, ROLE_ENDPOINT, "m", T0);
    let (answer, _) = service.with(|a| {
        a.revoke(
            KGUARD,
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
    // A different key cannot reclaim a revoked group sender ID.
    let mut new = SimDevice::new(old.node, 0x72);
    let (_, _, events) = new.start(&service, &transport, T0 + 2_000);
    let (answer, _) = service.with(|a| {
        a.decide(
            KGUARD,
            super::DecideRequest {
                join_request_id: request_id(&events).unwrap(),
                device: new.node,
                verdict: Verdict::Allow {
                    role: ROLE_ENDPOINT,
                },
                key: "m2".into(),
            },
            T0 + 2_010,
        )
    });
    assert_eq!(answer.unwrap_err().code, "CONFLICT");
    // The old key comes back holding generation 1.
    old.recovery_existing = true;
    let (outcome, _) = old.attempt(&service, &transport, T0 + 3_000);
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
                KGUARD,
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
            KGUARD,
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
        let (moved, _) = service
            .with(|a| a.handle_grant_receipt(node, 1, testkit::network(), &bytes, T0 + 11_000));
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
            KGUARD,
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
    assert_eq!(answer.get("rs_epoch").unwrap().as_u64(), Some(34));
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
            KGUARD,
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
            KGUARD,
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
            KGUARD,
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
            KGUARD,
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
