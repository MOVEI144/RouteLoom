//! Site Authority core tests (plan P3-3; acceptance IDs of 02 §14, 04 §11
//! and 07 §8 named per test). Devices are simulated with the Rust EDHOC
//! Initiator and routeloom-join's device-side checks (testkit).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use routeloom_join::JoinResult;
use routeloom_provision::sdkv1::revocation::{revocation_object_verify, RevocationReason};

use super::group_keys::{
    gk_id, AckOutcome, ConfirmOutcome, GroupKeyAck, GroupKeyCommand, GroupKeyPull, HostTime,
    PullOutcome, RotationCause, TargetState,
};
use super::records::{Verdict, ROLE_ENDPOINT, ROLE_RELAY};
use super::store::{Batch, DeviceRow, MemoryStore, Snapshot, SqliteSiteStore, StoreError};
use super::testkit::{self, kinds, request_id, FakeGroupKeyTransport, Outcome, SimDevice};
use super::transport::{
    AbortReason, DeliverReject, InProcessTransport, JoinTransport, RelayKey, RelayUp,
};
use super::*;

const T0: u64 = 1_790_000_000_000;
const KGUARD: u32 = 501;

#[test]
fn lab_inventory_only_allows_the_bound_site_and_key() {
    let mut setup = testkit::setup();
    let node = 0x00a1_0000_0000_d0a1;
    let device = SimDevice::new(node, 0xd1);
    let kid = routeloom_provision::credential::credential_kid(&device.pubkey);
    setup.purpose = SitePurpose::Development;
    setup.lab = Some(LabBinding {
        site_id: testkit::SITE,
        site_ca_fingerprint: sha256(&testkit::site_ca_pub()),
        device_ca_fingerprint: sha256(&setup.device_ca_pubkey),
        sak_fingerprint: routeloom_provision::credential::credential_kid(&testkit::sak().pubkey()),
        inventory_revision: 1,
        inventory: vec![LabDevice {
            node,
            kid,
            role: ROLE_ENDPOINT,
        }],
    });
    let authority = SiteAuthority::open(
        &setup,
        Box::new(testkit::sak()),
        Box::<MemoryStore>::default(),
        T0,
    )
    .unwrap();
    let service = SiteService::new(authority);
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    service.with(|a| {
        a.update_policy_at(
            &PolicyPatch {
                decision_mode: Some(DecisionMode::LabInventory),
                ..PolicyPatch::default()
            },
            T0,
        )
        .unwrap()
    });
    let mut device = SimDevice::new(node, 0xd1);
    let (_, outcome, events) = device.start(&service, &transport, T0);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::Allow { .. })),
        "{events:?}"
    );
    assert!(events
        .iter()
        .any(|(_, fields)| fields.contains("\"internal_policy_v1\"")
            && fields.contains("\"inventory_revision\":1")
            && fields.contains("\"policy_generation\":1")));
    let audit = service.with(|a| a.store.load().unwrap().approval_audit).0;
    assert_eq!(audit.len(), 1);
    assert!(audit[0].1.contains("\"internal_policy_v1\""));
}

#[test]
fn lab_approval_audit_survives_sqlite_restart() {
    let node = 0x00a1_0000_0000_d0a1;
    let device = SimDevice::new(node, 0xd1);
    let mut setup = testkit::setup();
    setup.purpose = SitePurpose::Development;
    setup.lab = Some(LabBinding {
        site_id: testkit::SITE,
        site_ca_fingerprint: sha256(&testkit::site_ca_pub()),
        device_ca_fingerprint: sha256(&setup.device_ca_pubkey),
        sak_fingerprint: routeloom_provision::credential::credential_kid(&testkit::sak().pubkey()),
        inventory_revision: 1,
        inventory: vec![LabDevice {
            node,
            kid: device.kid,
            role: ROLE_ENDPOINT,
        }],
    });
    let dir =
        std::env::temp_dir().join(format!("routeloom-lab-audit-{}-{}", std::process::id(), T0));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir(&dir).unwrap();
    let db = dir.join("site.db");
    {
        let store = SqliteSiteStore::open(&db).unwrap();
        let service = SiteService::new(
            SiteAuthority::open(&setup, Box::new(testkit::sak()), Box::new(store), T0).unwrap(),
        );
        let transport = InProcessTransport::new();
        service.set_transport(transport.clone());
        service.with(|a| {
            a.update_policy_at(
                &PolicyPatch {
                    decision_mode: Some(DecisionMode::LabInventory),
                    ..PolicyPatch::default()
                },
                T0,
            )
            .unwrap()
        });
        let mut device = SimDevice::new(node, 0xd1);
        assert!(matches!(
            device.start(&service, &transport, T0).1,
            Outcome::Result(JoinResult::Allow { .. })
        ));
    }
    let conn = rusqlite::Connection::open(&db).unwrap();
    let body: String = conn
        .query_row("SELECT body FROM approval_audit", [], |row| row.get(0))
        .unwrap();
    assert!(body.contains("\"internal_policy_v1\""));
    assert!(body.contains("\"inventory_revision\":1"));
    drop(conn);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn lab_policy_rejects_unbound_import_and_wrong_manifest() {
    let setup = testkit::setup();
    for purpose in [SitePurpose::Import, SitePurpose::Production] {
        let mut managed = setup.clone();
        managed.purpose = purpose;
        let mut authority = SiteAuthority::open(
            &managed,
            Box::new(testkit::sak()),
            Box::<MemoryStore>::default(),
            T0,
        )
        .unwrap();
        assert_eq!(
            authority
                .update_policy(&PolicyPatch {
                    decision_mode: Some(DecisionMode::LabInventory),
                    ..PolicyPatch::default()
                })
                .unwrap_err()
                .code,
            "INVALID_ARGUMENT"
        );
    }
    let device = SimDevice::new(0x00a1_0000_0000_d0a1, 0xd1);
    let mut lab = setup;
    lab.purpose = SitePurpose::Development;
    lab.lab = Some(LabBinding {
        site_id: testkit::SITE,
        site_ca_fingerprint: sha256(&testkit::site_ca_pub()),
        device_ca_fingerprint: sha256(&lab.device_ca_pubkey),
        sak_fingerprint: routeloom_provision::credential::credential_kid(&testkit::sak().pubkey()),
        inventory_revision: 1,
        inventory: vec![LabDevice {
            node: device.node,
            kid: device.kid,
            role: ROLE_ENDPOINT,
        }],
    });
    assert!(SiteAuthority::open(
        &lab,
        Box::new(testkit::sak()),
        Box::<MemoryStore>::default(),
        T0
    )
    .is_ok());
    lab.lab.as_mut().unwrap().site_ca_fingerprint = [0; 32];
    assert!(SiteAuthority::open(
        &lab,
        Box::new(testkit::sak()),
        Box::<MemoryStore>::default(),
        T0
    )
    .is_err());
}

#[test]
fn lab_inventory_mismatch_and_closed_never_auto_allow() {
    let node = 0x00a1_0000_0000_d0a1;
    let device = SimDevice::new(node, 0xd1);
    let mut setup = testkit::setup();
    setup.purpose = SitePurpose::Development;
    setup.lab = Some(LabBinding {
        site_id: testkit::SITE,
        site_ca_fingerprint: sha256(&testkit::site_ca_pub()),
        device_ca_fingerprint: sha256(&setup.device_ca_pubkey),
        sak_fingerprint: routeloom_provision::credential::credential_kid(&testkit::sak().pubkey()),
        inventory_revision: 1,
        inventory: vec![LabDevice {
            node,
            kid: device.kid,
            role: ROLE_ENDPOINT,
        }],
    });
    for (wrong_kid, wrong_role, closed) in [
        (true, false, false),
        (false, true, false),
        (false, false, true),
    ] {
        let mut current = setup.clone();
        if wrong_kid {
            current.lab.as_mut().unwrap().inventory[0].kid = [1; 32];
        }
        if wrong_role {
            current.lab.as_mut().unwrap().inventory[0].role = ROLE_RELAY;
        }
        let authority = SiteAuthority::open(
            &current,
            Box::new(testkit::sak()),
            Box::<MemoryStore>::default(),
            T0,
        )
        .unwrap();
        let service = SiteService::new(authority);
        let transport = InProcessTransport::new();
        service.set_transport(transport.clone());
        service.with(|a| {
            a.update_policy_at(
                &PolicyPatch {
                    decision_mode: Some(if closed {
                        DecisionMode::Closed
                    } else {
                        DecisionMode::LabInventory
                    }),
                    ..PolicyPatch::default()
                },
                T0,
            )
            .unwrap()
        });
        let mut device = SimDevice::new(node, 0xd1);
        let (_, outcome, _) = device.start(&service, &transport, T0);
        if closed {
            assert!(matches!(
                outcome,
                Outcome::Result(JoinResult::PendingAssignment { .. })
            ));
        } else {
            assert!(matches!(outcome, Outcome::Waiting));
        }
        assert_eq!(service.with(|a| a.devices.len()).0, 0);
    }
}

#[test]
fn lab_enrollment_expires_on_monotonic_clock_and_must_be_rearmed() {
    let node = 0x00a1_0000_0000_d0a1;
    let device = SimDevice::new(node, 0xd1);
    let mut setup = testkit::setup();
    setup.purpose = SitePurpose::Development;
    setup.lab = Some(LabBinding {
        site_id: testkit::SITE,
        site_ca_fingerprint: sha256(&testkit::site_ca_pub()),
        device_ca_fingerprint: sha256(&setup.device_ca_pubkey),
        sak_fingerprint: routeloom_provision::credential::credential_kid(&testkit::sak().pubkey()),
        inventory_revision: 1,
        inventory: vec![LabDevice {
            node,
            kid: device.kid,
            role: ROLE_ENDPOINT,
        }],
    });
    let service = SiteService::new(
        SiteAuthority::open(
            &setup,
            Box::new(testkit::sak()),
            Box::<MemoryStore>::default(),
            T0,
        )
        .unwrap(),
    );
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    service.with(|a| {
        a.update_policy_at(
            &PolicyPatch {
                decision_mode: Some(DecisionMode::LabInventory),
                ..PolicyPatch::default()
            },
            T0,
        )
        .unwrap()
    });
    service.tick(HostTime::sync(T0 + 3_600_001));
    let mut device = SimDevice::new(node, 0xd1);
    let (_, outcome, _) = device.start(&service, &transport, T0 + 3_600_001);
    assert!(matches!(
        outcome,
        Outcome::Result(JoinResult::PendingAssignment { .. })
    ));
    assert!(
        service
            .with(|a| a.store.load().unwrap().approval_audit.is_empty())
            .0
    );
    assert!(
        service
            .with(|a| a.policy_json().contains("\"lab_enrollment_active\":false"))
            .0
    );
}

struct FailLabApprovalStore {
    inner: MemoryStore,
    fail: Arc<AtomicBool>,
}

impl SiteStore for FailLabApprovalStore {
    fn load(&mut self) -> Result<Snapshot, StoreError> {
        self.inner.load()
    }
    fn commit(&mut self, batch: &Batch) -> Result<(), StoreError> {
        if !batch.approval_audit.is_empty() && self.fail.swap(false, Ordering::Relaxed) {
            return Err(StoreError("injected approval commit failure".into()));
        }
        self.inner.commit(batch)
    }
    fn durable(&self) -> bool {
        false
    }
}

#[test]
fn lab_failed_commit_closes_automatic_enrollment_until_reopen() {
    let node = 0x00a1_0000_0000_d0a1;
    let device = SimDevice::new(node, 0xd1);
    let mut setup = testkit::setup();
    setup.purpose = SitePurpose::Development;
    setup.lab = Some(LabBinding {
        site_id: testkit::SITE,
        site_ca_fingerprint: sha256(&testkit::site_ca_pub()),
        device_ca_fingerprint: sha256(&setup.device_ca_pubkey),
        sak_fingerprint: routeloom_provision::credential::credential_kid(&testkit::sak().pubkey()),
        inventory_revision: 1,
        inventory: vec![LabDevice {
            node,
            kid: device.kid,
            role: ROLE_ENDPOINT,
        }],
    });
    let fail = Arc::new(AtomicBool::new(true));
    let authority = SiteAuthority::open(
        &setup,
        Box::new(testkit::sak()),
        Box::new(FailLabApprovalStore {
            inner: MemoryStore::default(),
            fail: Arc::clone(&fail),
        }),
        T0,
    )
    .unwrap();
    let service = SiteService::new(authority);
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    service.with(|a| {
        a.update_policy_at(
            &PolicyPatch {
                decision_mode: Some(DecisionMode::LabInventory),
                ..Default::default()
            },
            T0,
        )
        .unwrap()
    });
    let mut device = SimDevice::new(node, 0xd1);
    assert!(matches!(
        device.start(&service, &transport, T0).1,
        Outcome::Waiting
    ));
    assert!(!fail.load(Ordering::Relaxed));
    assert!(service.with(|a| a.lab_write_poisoned).0);
    assert!(
        service
            .with(|a| a.store.load().unwrap().approval_audit.is_empty())
            .0
    );
    assert_eq!(
        service
            .with(|a| a.update_policy_at(
                &PolicyPatch {
                    decision_mode: Some(DecisionMode::LabInventory),
                    ..Default::default()
                },
                T0 + 1
            ))
            .0
            .unwrap_err()
            .code,
        "STORE_FAILURE"
    );
}

#[test]
fn two_development_sites_with_one_node_never_share_inventory_kids() {
    use routeloom_provision::sdkv1::cert::{cert_issue, CertClaims, CertType};
    use routeloom_provision::signer::{test_keypair, FileRootSigner};
    let node = 0x00a1_0000_0000_d0a1;
    let device_a = SimDevice::new(node, 0xd1);
    let mut a = testkit::setup();
    a.purpose = SitePurpose::Development;
    a.lab = Some(LabBinding {
        site_id: testkit::SITE,
        site_ca_fingerprint: sha256(&testkit::site_ca_pub()),
        device_ca_fingerprint: sha256(&a.device_ca_pubkey),
        sak_fingerprint: routeloom_provision::credential::credential_kid(&testkit::sak().pubkey()),
        inventory_revision: 1,
        inventory: vec![LabDevice {
            node,
            kid: device_a.kid,
            role: ROLE_ENDPOINT,
        }],
    });
    let site_b = 0x00b1_0000_0000_0001;
    let device_ca_b =
        FileRootSigner::from_secret(0x00ca_0000_0000_0002, &test_keypair(0xb1).0).unwrap();
    // The initiator fixture anchors one Site CA; independent site/SAK and
    // Device CA bindings still exercise cross-site inventory isolation.
    let site_ca_b = FileRootSigner::from_secret(testkit::SITE_CA, &test_keypair(0x61).0).unwrap();
    let sak_b = FileRootSigner::from_secret(site_b, &test_keypair(0xb3).0).unwrap();
    let cert_b = cert_issue(
        &CertClaims {
            cert_type: CertType::Site,
            issuer: site_ca_b.root_id(),
            subject: site_b,
            pubkey: sak_b.pubkey(),
            network_low32: testkit::NETWORK_LOW,
            site_epoch: testkit::SITE_EPOCH,
            usage: 1,
            serial: 1,
            ..CertClaims::default()
        },
        &site_ca_b,
    )
    .unwrap();
    let device_b = SimDevice::with_ca(node, 0xd2, &device_ca_b);
    let b = SiteSetup {
        site_cert: cert_b,
        site_ca_pubkey: Some(site_ca_b.pubkey()),
        device_ca_id: device_ca_b.root_id(),
        device_ca_pubkey: device_ca_b.pubkey(),
        channel: 1,
        channel_epoch: 1,
        gateways: a.gateways.clone(),
        purpose: SitePurpose::Development,
        lab: Some(LabBinding {
            site_id: site_b,
            site_ca_fingerprint: sha256(&site_ca_b.pubkey()),
            device_ca_fingerprint: sha256(&device_ca_b.pubkey()),
            sak_fingerprint: routeloom_provision::credential::credential_kid(&sak_b.pubkey()),
            inventory_revision: 1,
            inventory: vec![LabDevice {
                node,
                kid: device_b.kid,
                role: ROLE_ENDPOINT,
            }],
        }),
    };
    for (setup, sak, mut device, allowed) in [
        (a.clone(), testkit::sak(), SimDevice::new(node, 0xd1), true),
        (
            a.clone(),
            testkit::sak(),
            SimDevice::with_ca(node, 0xd2, &device_ca_b),
            false,
        ),
        (a, testkit::sak(), SimDevice::new(node, 0xd2), false),
        (b, sak_b, SimDevice::with_ca(node, 0xd2, &device_ca_b), true),
    ] {
        let service = SiteService::new(
            SiteAuthority::open(&setup, Box::new(sak), Box::<MemoryStore>::default(), T0).unwrap(),
        );
        let transport = InProcessTransport::new();
        service.set_transport(transport.clone());
        service.with(|authority| {
            authority
                .update_policy_at(
                    &PolicyPatch {
                        decision_mode: Some(DecisionMode::LabInventory),
                        ..PolicyPatch::default()
                    },
                    T0,
                )
                .unwrap()
        });
        let (_, outcome, _) = device.start(&service, &transport, T0);
        assert_eq!(
            matches!(outcome, Outcome::Result(JoinResult::Allow { .. })),
            allowed
        );
    }
}

#[test]
fn lab_revoked_node_is_not_reapproved_from_inventory() {
    let node = 0x00a1_0000_0000_d0a1;
    let mut device = SimDevice::new(node, 0xd1);
    let mut setup = testkit::setup();
    setup.purpose = SitePurpose::Development;
    setup.lab = Some(LabBinding {
        site_id: testkit::SITE,
        site_ca_fingerprint: sha256(&testkit::site_ca_pub()),
        device_ca_fingerprint: sha256(&setup.device_ca_pubkey),
        sak_fingerprint: routeloom_provision::credential::credential_kid(&testkit::sak().pubkey()),
        inventory_revision: 1,
        inventory: vec![LabDevice {
            node,
            kid: device.kid,
            role: ROLE_ENDPOINT,
        }],
    });
    let service = SiteService::new(
        SiteAuthority::open(
            &setup,
            Box::new(testkit::sak()),
            Box::<MemoryStore>::default(),
            T0,
        )
        .unwrap(),
    );
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    service.with(|a| {
        a.update_policy_at(
            &PolicyPatch {
                decision_mode: Some(DecisionMode::LabInventory),
                ..PolicyPatch::default()
            },
            T0,
        )
        .unwrap()
    });
    let (_, outcome, _) = device.start(&service, &transport, T0);
    assert!(matches!(outcome, Outcome::Result(JoinResult::Allow { .. })));
    service
        .with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: node,
                    expected_generation: 1,
                    reason: RevocationReason::Lost,
                    key: "lab-revoke".into(),
                },
                HostTime::sync(T0 + 1),
            )
        })
        .0
        .unwrap();
    let mut rebooted = SimDevice::new(node, 0xd1);
    let (_, outcome, _) = rebooted.start(&service, &transport, T0 + 10_000);
    assert!(!matches!(
        outcome,
        Outcome::Result(JoinResult::Allow { .. })
    ));
    assert!(!service.with(|a| a.devices[&node].member).0);
}

fn service_with(store: Box<dyn SiteStore>) -> (SiteService, Arc<InProcessTransport>) {
    let service = SiteService::new(testkit::authority(store, T0));
    let transport = InProcessTransport::new();
    service.set_transport(transport.clone());
    (service, transport)
}

fn service() -> (SiteService, Arc<InProcessTransport>) {
    service_with(Box::<MemoryStore>::default())
}

struct RejectDownlink(DeliverReject);

impl JoinTransport for RejectDownlink {
    fn deliver(&self, _: super::transport::Outbound) -> Result<(), DeliverReject> {
        Err(self.0)
    }
}

struct PausedReject {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl JoinTransport for PausedReject {
    fn deliver(&self, _: super::transport::Outbound) -> Result<(), DeliverReject> {
        self.entered.send(()).unwrap();
        self.release
            .lock()
            .unwrap()
            .recv_timeout(Duration::from_secs(5))
            .unwrap();
        Err(DeliverReject::QueueFull)
    }
}

#[test]
fn rejected_downlink_is_recorded_before_another_authority_mutation() {
    let (service, transport) = service();
    let service = Arc::new(service);
    let mut device = SimDevice::new(0x00A1_0000_0000_D0A1, 0xD1);
    assert!(matches!(
        device.start(&service, &transport, T0).1,
        Outcome::Waiting
    ));
    let key = service.with(|a| a.txns[0].key).0;
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    service.set_transport(Arc::new(PausedReject {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    }));
    let first_service = Arc::clone(&service);
    let first =
        std::thread::spawn(move || first_service.with(|a| a.abort(key, AbortReason::Timeout)).1);
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let (mutated_tx, mutated_rx) = mpsc::channel();
    let second_service = Arc::clone(&service);
    let second = std::thread::spawn(move || {
        second_service
            .with(|a| {
                mutated_tx.send(()).unwrap();
                a.fail_relay(key, "concurrent", "later".to_string(), T0)
            })
            .0
    });
    let mutated_during_delivery = mutated_rx.recv_timeout(Duration::from_secs(1)).is_ok();
    release_tx.send(()).unwrap();
    let events = first.join().unwrap();
    let later_failure = second.join().unwrap();
    assert!(
        !mutated_during_delivery,
        "authority changed before the delivery result"
    );
    assert!(later_failure.is_none());
    assert!(events
        .iter()
        .any(|(_, fields)| fields.contains("\"reason\":\"queue_full\"")));
}

#[test]
fn rejected_downlink_keeps_the_reason_on_the_ended_relay() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_D0A1, 0xD1);
    let (_, outcome, _) = device.start(&service, &transport, T0);
    assert!(matches!(outcome, Outcome::Waiting));
    let key = service.with(|a| a.txns[0].key).0;
    service.set_transport(Arc::new(RejectDownlink(DeliverReject::QueueFull)));
    let (_, events) = service.with(|a| a.abort(key, AbortReason::Timeout));
    let failure = events
        .iter()
        .map(|(_, fields)| json(&format!("{{{fields}}}")))
        .find(|event| {
            event.get("kind").and_then(routeloom_json::Json::as_str) == Some("join_relay_failed")
        })
        .expect("the rejected attempt needs an event");
    assert_eq!(
        failure.get("source").unwrap().as_str(),
        Some("downlink_rejected")
    );
    assert_eq!(failure.get("reason").unwrap().as_str(), Some("queue_full"));
    assert_eq!(
        failure.get("proxy").unwrap().as_str(),
        Some("00a1000000000777")
    );
    assert_eq!(failure.get("stage").unwrap().as_str(), Some("deciding"));
    let (status, _) = service.with(|a| a.status_json(HostTime::sync(T0)));
    let status = json(&status);
    let recent = status
        .get("recent_relay_failures")
        .unwrap()
        .as_array()
        .unwrap();
    assert_eq!(
        recent.last().unwrap().get("reason").unwrap().as_str(),
        Some("queue_full")
    );
    assert!(service.with(|a| a.txns.is_empty()).0);
}

struct PresenceOnlyStore {
    inner: MemoryStore,
    fail_lookup: Arc<AtomicBool>,
}

impl SiteStore for PresenceOnlyStore {
    fn load(&mut self) -> Result<Snapshot, StoreError> {
        self.inner.load()
    }
    fn commit(&mut self, batch: &Batch) -> Result<(), StoreError> {
        self.inner.commit(batch)
    }
    fn durable(&self) -> bool {
        false
    }
    fn ledger_for(&mut self, _: u64) -> Result<Vec<LedgerRow>, StoreError> {
        Err(StoreError("full ledger lookup unavailable".into()))
    }
    fn has_revocation(&mut self, node: u64) -> Result<bool, StoreError> {
        if self.fail_lookup.load(Ordering::Relaxed) {
            return Err(StoreError("revocation lookup failed".into()));
        }
        self.inner.has_revocation(node)
    }
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

fn archive(
    service: &SiteService,
    devices: &[u64],
    key: &str,
    now: u64,
) -> (Result<String, SiteError>, Events) {
    service.with(|a| {
        a.archive_removed(
            KGUARD,
            ArchiveRequest {
                devices: devices.to_vec(),
                key: key.into(),
            },
            now,
        )
    })
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

struct FailSecondCommit {
    inner: Box<dyn SiteStore>,
    calls: usize,
}

#[derive(Default)]
struct FailJoinRequestCommit {
    inner: MemoryStore,
}

impl SiteStore for FailJoinRequestCommit {
    fn load(&mut self) -> Result<store::Snapshot, store::StoreError> {
        self.inner.load()
    }

    fn commit(&mut self, batch: &Batch) -> Result<(), store::StoreError> {
        if batch
            .docs
            .iter()
            .any(|(kind, _, body)| *kind == store::DocKind::JoinRequest && body.is_some())
        {
            return Err(store::StoreError("join request commit failed".into()));
        }
        self.inner.commit(batch)
    }

    fn durable(&self) -> bool {
        false
    }
}

impl SiteStore for FailSecondCommit {
    fn load(&mut self) -> Result<store::Snapshot, store::StoreError> {
        self.inner.load()
    }

    fn commit(&mut self, batch: &Batch) -> Result<(), store::StoreError> {
        self.calls += 1;
        if self.calls == 2 {
            return Err(store::StoreError("activation commit failed".into()));
        }
        self.inner.commit(batch)
    }

    fn durable(&self) -> bool {
        self.inner.durable()
    }
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
        .map(|i| {
            let mut row = DeviceRow::default();
            row.node = 0x00A1_0000_0000_0000 + 0x1000 + i as u64;
            row.kid = [((i % 251) + 1) as u8; 32];
            row.member = true;
            row.generation = 1;
            row.role = 1;
            row.dams = [((i % 251) + 1) as u8; 32];
            row.approved_ms = T0;
            row
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

/// A failed relay attempt keeps its reason, stage and links: the USB
/// lane fails the live attempt on gateway abort, and the failure stays
/// queryable in `site.status` for triage.
#[test]
fn relay_failure_keeps_reason_stage_and_links() {
    let (service, transport) = service();
    let node = 0x00A1_0000_0000_7001;
    let mut device = SimDevice::new(node, 0x79);
    let (_, outcome, events) = device.start(&service, &transport, T0);
    assert!(matches!(outcome, Outcome::Waiting));
    let request = request_id(&events).expect("join request");
    let keys: Vec<RelayKey> = service.with(|a| a.txns.iter().map(|t| t.key).collect()).0;
    assert_eq!(keys.len(), 1);
    let failure = service
        .with(|a| {
            a.fail_relay(
                keys[0],
                "gateway_abort",
                "GatewayExpired".to_string(),
                T0 + 5,
            )
        })
        .0
        .expect("live attempt");
    let fields = failure.event_fields();
    for want in [
        "\"kind\":\"join_relay_failed\"",
        "\"source\":\"gateway_abort\"",
        "\"reason\":\"GatewayExpired\"",
        "\"gateway\":\"00a1000000000001\"",
        "\"stage\":\"deciding\"",
        &format!("\"device\":\"{node:016x}\""),
        &format!("\"join_request\":\"jr-{request:016x}\""),
    ] {
        assert!(fields.contains(want), "{fields}");
    }
    let (status, _) = service.with(|a| a.status_json(HostTime::sync(T0 + 5)));
    assert!(
        status.contains("\"recent_relay_failures\":[{") && status.contains("GatewayExpired"),
        "{status}"
    );
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

/// An allow needs only revocation presence; a failed lookup must never
/// issue an assignment.
#[test]
fn allow_uses_revocation_presence_and_fails_closed_on_lookup_error() {
    let fail_lookup = Arc::new(AtomicBool::new(false));
    let (service, transport) = service_with(Box::new(PresenceOnlyStore {
        inner: MemoryStore::default(),
        fail_lookup: fail_lookup.clone(),
    }));
    let node = 0x00A1_0000_0000_5009;
    join_member(&service, &transport, node, 0x79, T0);
    revoke(&service, node, 1, "revoke", T0 + 10_000).unwrap();

    let mut replacement = SimDevice::new(node, 0x7a);
    let (_, outcome, events) = replacement.start(&service, &transport, T0 + 20_000);
    assert!(matches!(outcome, Outcome::Waiting));
    let id = request_id(&events).unwrap();
    fail_lookup.store(true, Ordering::Relaxed);
    assert_eq!(
        decide(
            &service,
            id,
            node,
            Verdict::Allow {
                role: ROLE_ENDPOINT
            },
            "retry",
            T0 + 20_010
        )
        .unwrap_err()
        .code,
        "STORE_FAILURE"
    );
    fail_lookup.store(false, Ordering::Relaxed);
    assert_eq!(
        decide(
            &service,
            id,
            node,
            Verdict::Allow {
                role: ROLE_ENDPOINT
            },
            "retry",
            T0 + 20_020
        )
        .unwrap_err()
        .code,
        "CONFLICT"
    );
    assert!(!service.with(|a| a.devices[&node].member).0);
}

/// V1-H04 / V1-R01 (host part) / V1-R05 / V1-R07: revoke commits a
/// verifiable RRS1; the removed device erases its site state, and only
/// a newly provisioned NodeId can join after removal.
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
    // Operation view: RRS1 distribution remains pending without a transport.
    let op = answer
        .get("operation_id")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let (view, _) = service.with(|a| {
        a.operation_json(records::parse_op_token(&op).unwrap(), HostTime::sync(T0))
            .unwrap()
    });
    let view = json(&view);
    assert_eq!(
        view.get("distribution")
            .unwrap()
            .get("state")
            .unwrap()
            .as_str(),
        Some("pending")
    );
    // The device still holds site state: Removed + notice, then it erases.
    let (outcome, _) = device.attempt(&service, &transport, T0 + 60_000);
    assert!(
        matches!(outcome, Outcome::Result(JoinResult::Removed { .. })),
        "{outcome:?}"
    );
    assert!(device.site.is_none());
    // KGuard sees the removed identity, but its NodeId cannot be re-allowed.
    let (_, outcome, events) = device.start(&service, &transport, T0 + 660_000);
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
    let error = decide(
        &service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "a2",
        T0 + 660_010,
    )
    .unwrap_err();
    assert_eq!(error.code, "CONFLICT");
    assert!(error.message.contains("new NodeId"));

    // The office reprovisions RLI1/DevCert with a fresh NodeId; only that
    // identity can join while the old RRS1 entry remains in force.
    let mut replacement = SimDevice::new(device.node + 1, 0x78);
    let (mut new_exchange, _, new_events) = replacement.start(&service, &transport, T0 + 663_000);
    decide(
        &service,
        request_id(&new_events).unwrap(),
        replacement.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "fresh",
        T0 + 663_010,
    )
    .unwrap();
    assert!(matches!(
        replacement.finish(&mut new_exchange, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    assert_eq!(
        replacement
            .site
            .as_ref()
            .unwrap()
            .member
            .assignment_generation,
        1
    );
}

#[test]
fn removed_recovery_notice_uses_retained_network() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_60A1, 0x79);
    let (mut exchange, _, events) = device.start(&service, &transport, T0);
    decide(
        &service,
        request_id(&events).unwrap(),
        device.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "allow-old-network",
        T0 + 10,
    )
    .unwrap();
    assert!(matches!(
        device.finish(&mut exchange, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    service
        .with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: device.node,
                    expected_generation: 1,
                    reason: RevocationReason::Lost,
                    key: "revoke-old-network".into(),
                },
                HostTime::sync(T0 + 20),
            )
        })
        .0
        .unwrap();
    let old_network = (2_u64 << 32) | u64::from(testkit::NETWORK_LOW);
    device.site.as_mut().unwrap().member.network = old_network;
    device.recovery_existing = true;
    let (outcome, _) = device.attempt(&service, &transport, T0 + 60_000);
    assert!(matches!(
        outcome,
        Outcome::Result(JoinResult::Removed { .. })
    ));
    assert!(device.site.is_none());
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
fn join_deadlines_use_monotonic_time_after_wall_rollback() {
    let (service, transport) = service();
    let mut devices: Vec<SimDevice> = (0..4)
        .map(|i| SimDevice::new(0x00A1_0000_0000_8800 + i, 0x88 + i as u8))
        .collect();
    for device in &mut devices {
        let (_, outcome, _) = device.start(&service, &transport, T0);
        assert!(matches!(outcome, Outcome::Waiting));
    }
    service.tick(HostTime {
        unix_ms: T0 - 3_600_000,
        mono_ms: T0 + 60_000,
    });
    let live = service.with(|a| a.txns.len()).0;
    assert_eq!(live, 0);
    transport.take();
    let key = RelayKey {
        gateway: 1,
        proxy: 2,
        gateway_epoch: 7,
        proxy_epoch: 3,
        relay_id: 99,
        joiner_mac: devices[0].mac,
    };
    service.handle_up_time(
        RelayUp {
            key,
            hops: 0,
            phase: super::transport::PHASE_EDHOC,
            step: 1,
            joiner_rssi_dbm: 0,
            body: vec![0x40],
        },
        HostTime {
            unix_ms: T0 - 3_600_000,
            mono_ms: T0 + 60_001,
        },
    );
    assert!(!transport.take().iter().any(|event| matches!(
        event,
        transport::Outbound::Abort {
            reason: AbortReason::Busy,
            ..
        }
    )));
}

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
                gateway_epoch: 7,
                proxy_epoch: 3,
                relay_id: 3,
                joiner_mac: [9; 6],
            },
            hops: 0,
            phase: super::transport::PHASE_EDHOC,
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

/// #116: the EDHOC service accepts phase 4 only — a phase-5 step 1 is not
/// an EDHOC m1 and ends the relay instead of opening a session.
#[test]
fn non_edhoc_phase_is_never_an_edhoc_message() {
    let (service, transport) = service();
    let key = RelayKey {
        gateway: 1,
        proxy: 2,
        gateway_epoch: 7,
        proxy_epoch: 3,
        relay_id: 3,
        joiner_mac: [7; 6],
    };
    service.handle_up(
        RelayUp {
            key,
            hops: 0,
            phase: super::transport::PHASE_RESUME,
            step: 1,
            joiner_rssi_dbm: 0,
            body: vec![0x40],
        },
        T0,
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
        gateway_epoch: 7,
        proxy_epoch: 3,
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
            phase: super::transport::PHASE_EDHOC,
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
            phase: super::transport::PHASE_EDHOC,
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
    let (_, _, events_b) = b.start(&service, &transport, T0 + 10);
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
    // Revocation does not release a NodeId for a waiting request.
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
    let error = decide(
        &service,
        request_id(&events_b).unwrap(),
        b.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "review-b2",
        T0 + 60,
    )
    .unwrap_err();
    assert_eq!(error.code, "CONFLICT");
    assert!(error.message.contains("new NodeId"));
}

/// A replacement key needs a fresh office-issued NodeId after revocation.
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
    // Even another key cannot claim the revoked NodeId.
    let mut b = SimDevice::new(a.node, 0xC4);
    let (_, outcome, events) = b.start(&service, &transport, T0 + 30_000);
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
    assert_eq!(
        decide(
            &service,
            request_id(&events).unwrap(),
            b.node,
            Verdict::Allow {
                role: ROLE_ENDPOINT
            },
            "b",
            T0 + 30_010
        )
        .unwrap_err()
        .code,
        "CONFLICT"
    );
    let mut fresh = SimDevice::new(a.node + 1, 0xC4);
    let (mut next, _, next_events) = fresh.start(&service, &transport, T0 + 40_000);
    decide(
        &service,
        request_id(&next_events).unwrap(),
        fresh.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "fresh",
        T0 + 40_010,
    )
    .unwrap();
    assert!(matches!(
        fresh.finish(&mut next, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    let (row, _) = service.with(|auth| auth.devices[&fresh.node].clone());
    assert!(row.member && row.kid == fresh.kid && row.generation == 1);
    assert_ne!(row.member_cert, old_cert);
    assert_eq!(cert_decode(&row.member_cert).unwrap().pubkey, fresh.pubkey);
    // The RRS still denies the old NodeId.
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
    let (_, outcome, events) = b.start(&service, &transport, T0 + 30_000);
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
    assert_eq!(
        decide(
            &service,
            request_id(&events).unwrap(),
            node,
            Verdict::Allow {
                role: ROLE_ENDPOINT
            },
            "b",
            T0 + 30_010
        )
        .unwrap_err()
        .code,
        "CONFLICT"
    );
    let mut fresh = SimDevice::new(node + 1, 0xC6);
    let (mut next, _, next_events) = fresh.start(&service, &transport, T0 + 40_000);
    decide(
        &service,
        request_id(&next_events).unwrap(),
        fresh.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "fresh",
        T0 + 40_010,
    )
    .unwrap();
    assert!(matches!(
        fresh.finish(&mut next, &transport),
        Outcome::Result(JoinResult::Allow { .. })
    ));
    // The RRS floor and the ledger chain reloaded intact (open() verifies the chain).
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
    let (_, outcome, events) = b.start(&service, &transport, T0 + 100);
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
    // Clearing the live kid conflict cannot clear the revocation history.
    assert_eq!(
        decide(
            &service,
            id_b,
            b.node,
            Verdict::Allow {
                role: ROLE_ENDPOINT
            },
            "b",
            T0 + 220
        )
        .unwrap_err()
        .code,
        "CONFLICT"
    );
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
    // Reprovision with a different NodeId after the pending holdoff.
    let mut d = SimDevice::new(c.node + 1, 0xCA);
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
    let (view, _) = service.with(|a| a.operation_json(op_id, HostTime::sync(T0)).unwrap());
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
    let (view, _) = service.with(|a| a.operation_json(op_id, HostTime::sync(T0)).unwrap());
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
    // B reported no epoch above active=1. The ACK flush starts its
    // active-key repair; stage 2 waits for an active ACK.
    assert_eq!(updates_of(&gk.take()), vec![(b.node, 1)]);
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
    let (view, _) = service.with(|a| a.operation_json(first_op, HostTime::sync(T0)).unwrap());
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

struct DamsBoundTransport {
    node: u64,
    dams: [u8; 32],
    sent: Mutex<Vec<GroupKeyCommand>>,
}

impl DamsBoundTransport {
    fn take(&self) -> Vec<GroupKeyCommand> {
        std::mem::take(&mut *self.sent.lock().unwrap())
    }
}

impl group_keys::GroupKeyTransport for DamsBoundTransport {
    fn channel_ready(&self, node: u64, expected_dams: &[u8; 32]) -> bool {
        self.node == node && self.dams == *expected_dams
    }

    fn send(&self, command: GroupKeyCommand, expected_dams: Option<&[u8; 32]>) {
        if expected_dams.is_none_or(|dams| self.node == command.node() && self.dams == *dams) {
            self.sent.lock().unwrap().push(command);
        }
    }
}

#[test]
fn review_key_handoff_rejects_retired_dams_channel() {
    let (service, join_transport, _) = gk_service();
    let mut member = join_member(&service, &join_transport, 0x00A1_0000_0000_D010, 0xDF, T0);
    let (_, _, old_dams) = channel_id(&service, member.node);
    let (outcome, _) = member.attempt(&service, &join_transport, T0 + 30_000);
    assert!(matches!(outcome, Outcome::Result(JoinResult::Allow { .. })));
    assert_ne!(channel_id(&service, member.node).2, old_dams);
    let stale = Arc::new(DamsBoundTransport {
        node: member.node,
        dams: old_dams,
        sent: Mutex::new(Vec::new()),
    });
    service.set_group_key_transport(stale.clone());
    rotate(&service, 1, "after-reissue", T0 + 31_000).unwrap();
    service.tick(HostTime::sync(T0 + 31_000));
    assert!(updates_of(&stale.take()).is_empty());
    assert_eq!(
        pull(&service, member.node, 1, 0, 3, T0 + 32_000),
        PullOutcome::Answered
    );
    assert!(updates_of(&stale.take()).is_empty());
}

#[test]
fn review_key_handoff_requires_nonzero_member_dams() {
    let mut store = member_rows(1, 1);
    let mut member = store.load().unwrap().devices.remove(0);
    member.dams = [0; 32];
    let node = member.node;
    store
        .commit(&Batch {
            devices: vec![member],
            ..Batch::default()
        })
        .unwrap();
    let service = SiteService::new(testkit::authority(Box::new(store), T0));
    let gk = FakeGroupKeyTransport::new();
    gk.set_ready(node, true);
    service.set_group_key_transport(gk.clone());
    rotate(&service, 1, "zero-dams", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    assert!(updates_of(&gk.take()).is_empty());
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
    assert!(sent.iter().any(|command| matches!(
        command,
        GroupKeyCommand::Update {
            node,
            epoch: 2,
            cause: RotationCause::Removal,
            overlap_s: 10,
            ..
        } if *node == b.node
    )));
    let (_, key_b2) = update_key(&sent, b.node);
    assert_eq!(
        ack_key(&service, b.node, 2, &key_b2, 1, t + 2_000),
        AckOutcome::StagedRecorded
    );
    let sent = gk.take();
    assert_eq!(activates_of(&sent), vec![(b.node, 2)]);
    service.tick(HostTime::sync(t + 3_000));
    let between = gk.take();
    assert!(
        !updates_of(&between).contains(&(b.node, 3)),
        "the staged epoch must wait for the active ACK: {between:?}"
    );
    assert_eq!(
        ack_key(&service, b.node, 2, &key_b2, 2, t + 4_000),
        AckOutcome::ActiveRecorded
    );
    // Only now does B stage epoch 3.
    service.tick(HostTime::sync(t + 5_000));
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
    // Keyless (current 0): the maximally-behind case is served the
    // active key (§6.3), never stranded to the next rotation. Only a
    // bad reason still fails the shape — and strangers fence out.
    assert_eq!(
        pull(&service, a.node, 0, 0, 2, T0 + 9_000),
        PullOutcome::Answered
    );
    assert_eq!(updates_of(&gk.take()), vec![(a.node, 2)]);
    assert_eq!(
        pull(&service, a.node, 0, 0, 0, T0 + 9_000),
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

/// G-SEC P5 PR4 (§4): repeats inside the 60 s bucket fold into one
/// pending answer — served once at reopen with the latest epochs,
/// never dropped, never doubled.
#[test]
fn gk_pull_repeats_coalesce_into_one_pending_answer() {
    use super::authority_channel::{ChannelEvent, PullFields, PullReason};

    let (service, transport, gk) = gk_service();
    let a = join_member(&service, &transport, 0x00A1_0000_0000_AE01, 0xAE, T0);

    fn wire_pull(
        service: &SiteService,
        node: u64,
        request_id: u64,
        current: u32,
        next: u32,
        now: u64,
    ) -> Vec<(u64, String)> {
        let (_, generation, _) = channel_id(service, node);
        service
            .with(|auth| {
                auth.map_channel_event(
                    ChannelEvent::Pull {
                        device: node,
                        pull: PullFields {
                            generation,
                            request_id,
                            current,
                            next,
                            reason: PullReason::UnknownNewerEpoch,
                        },
                    },
                    HostTime::sync(now),
                )
            })
            .1
    }

    // First pull: answered at once.
    let events = wire_pull(&service, a.node, 1, 1, 0, T0);
    assert!(
        events
            .iter()
            .any(|(_, f)| f.contains("\"kind\":\"authority.pull\"")
                && f.contains("\"request_id\":1")
                && f.contains("\"outcome\":\"answered\"")),
        "first pull answered: {events:?}"
    );
    assert_eq!(updates_of(&gk.take()), vec![(a.node, 1)]);

    // Two repeats inside the bucket: throttled, nothing queued.
    let events = wire_pull(&service, a.node, 2, 1, 0, T0 + 10_000);
    assert!(
        events
            .iter()
            .any(|(_, f)| f.contains("authority.pull_throttled")),
        "repeat throttled: {events:?}"
    );
    let events = wire_pull(&service, a.node, 3, 1, 1, T0 + 20_000);
    assert!(
        events
            .iter()
            .any(|(_, f)| f.contains("authority.pull_throttled")),
        "second repeat throttled: {events:?}"
    );
    assert!(gk.take().is_empty());

    // Still inside the window: the tick serves nothing.
    let events = service.tick(HostTime::sync(T0 + 30_000));
    assert!(
        !events
            .iter()
            .any(|(_, f)| f.contains("\"kind\":\"authority.pull\"")),
        "nothing served early: {events:?}"
    );
    assert!(gk.take().is_empty());

    // Past the window: exactly one answer, with the latest epochs.
    let events = service.tick(HostTime::sync(T0 + 61_000));
    assert!(
        events
            .iter()
            .any(|(_, f)| f.contains("\"kind\":\"authority.pull\"")
                && f.contains("\"request_id\":3")
                && f.contains("\"current\":1")
                && f.contains("\"next\":1")
                && f.contains("\"outcome\":\"answered\"")),
        "pending served with latest epochs: {events:?}"
    );
    assert_eq!(updates_of(&gk.take()), vec![(a.node, 1)]);

    // The bit cleared: no second serve.
    let events = service.tick(HostTime::sync(T0 + 62_000));
    assert!(
        !events
            .iter()
            .any(|(_, f)| f.contains("\"kind\":\"authority.pull\"")),
        "no double serve: {events:?}"
    );
    assert!(gk.take().is_empty());
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

#[test]
fn failed_key_ack_does_not_restore_obsolete_staging_evidence() {
    let db = crash_db("failed-key-ack");
    let node = 0x00A1_0000_0000_AF11;
    {
        let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        let gk = FakeGroupKeyTransport::new();
        service.set_group_key_transport(gk.clone());
        let a = join_member(&service, &transport, node, 0xD1, T0);
        let b = join_member(&service, &transport, node + 1, 0xD2, T0 + 500);
        gk.set_ready(a.node, true);
        gk.set_ready(b.node, true);
        rotate(&service, 1, "failed-key-ack", T0 + 1_000).unwrap();
        service.tick(HostTime::sync(T0 + 1_000));
        let (_, key) = update_key(&gk.take(), a.node);
        assert_eq!(
            ack_key(&service, a.node, 2, &key, 1, T0 + 2_000),
            AckOutcome::StagedRecorded
        );
        let failed = member_ack(&service, a.node, 2, &key, 1, 0);
        assert_eq!(
            service
                .with(|authority| authority.on_group_key_ack(failed, HostTime::sync(T0 + 3_000)))
                .0,
            AckOutcome::Stale {
                reason: "ack_conflict"
            }
        );
        assert_eq!(
            gk_status(&service, T0 + 3_000)
                .get("staged_ack")
                .unwrap()
                .as_u64(),
            Some(0)
        );
    }
    let (service, _) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
    assert_eq!(
        gk_status(&service, T0 + 4_000)
            .get("staged_ack")
            .unwrap()
            .as_u64(),
        Some(0)
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
    let conflict = member_ack(&service, a.node, 2, &key, 1, 0);
    let (outcome, _) = service.with(|a| {
        let live = std::mem::replace(&mut a.store, Box::new(failing_store()));
        let outcome = a.on_group_key_ack(conflict, HostTime::sync(T0 + 3_500));
        a.store = live;
        outcome
    });
    assert_eq!(outcome, AckOutcome::Stale { reason: "store" });
    let node = a.node;
    assert_eq!(
        service.with(|a| a.gks.target(node).unwrap().row.state).0,
        TargetState::StagedAcked
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
    assert_eq!(failures, 3);
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
    let (view, _) = service.with(|a| a.operation_json(7, HostTime::sync(T0)).unwrap());
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

#[test]
fn gk_migrated_staged_key_keeps_operation_cap() {
    let mut store = member_rows(0, 1);
    let docs = (1..=OPERATIONS_CAP as u64)
        .map(|id| {
            let op = Operation {
                id,
                kind: "rotate".into(),
                node: 0,
                generation: 0,
                member_cert_serial: 0,
                rs_epoch: 0,
                gk_from: 1,
                gk_to: 1,
                created_ms: T0,
                gk_cause: "manual".into(),
                gk_end: "converged".into(),
                distribution: None,
                cutover: None,
                notice: None,
            };
            (store::DocKind::Operation, h16(id), Some(op.doc()))
        })
        .collect();
    store
        .commit(&Batch {
            group_keys: vec![store::GroupKeyRow {
                epoch: 2,
                key: [0x22; 32],
                state: "staged".into(),
                created_ms: T0 + 1_000,
            }],
            meta: vec![(group_keys::META_HIGH_WATER, 2_u32.to_be_bytes().to_vec())],
            docs,
            ..Batch::default()
        })
        .unwrap();
    let mut auth = SiteAuthority::open(
        &testkit::setup(),
        Box::new(testkit::sak()),
        Box::new(store),
        T0,
    )
    .unwrap();
    assert_eq!(auth.operations.len(), OPERATIONS_CAP);
    assert_eq!(
        auth.gks.rotation().unwrap().row.operation_id,
        OPERATIONS_CAP as u64 + 1
    );
    assert!(!auth.operations.contains_key(&1));
    let persisted = auth.store.load().unwrap();
    assert_eq!(persisted.docs.len(), OPERATIONS_CAP);
    assert!(!persisted
        .docs
        .contains_key(&(store::DocKind::Operation, h16(1))));
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

#[test]
fn review_failed_activation_keeps_the_rotation_and_evidence() {
    let (service, transport, gk) = gk_service();
    let member = join_member(&service, &transport, 0x00A1_0000_0000_D001, 0xD0, T0);
    gk.set_ready(member.node, true);
    rotate(&service, 1, "activation-fault", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let (_, key) = update_key(&gk.take(), member.node);
    service.with(|a| {
        let inner = std::mem::replace(&mut a.store, Box::new(MemoryStore::default()));
        a.store = Box::new(FailSecondCommit { inner, calls: 0 });
    });
    assert_eq!(
        ack_key(&service, member.node, 2, &key, 2, T0 + 2_000),
        AckOutcome::ActiveRecorded
    );
    let (phase, snapshot) = service
        .with(|a| {
            (
                a.gks.rotation().map(|r| r.row.phase),
                a.store.load().unwrap(),
            )
        })
        .0;
    assert_eq!(phase, Some(group_keys::RotationPhase::Staging));
    assert_eq!(
        snapshot.gk_rotation.unwrap().phase,
        group_keys::RotationPhase::Staging
    );
    assert_eq!(
        gk_status(&service, T0 + 2_000)
            .get("active")
            .unwrap()
            .as_u64(),
        Some(1)
    );
}

#[test]
fn review_pull_uses_highest_device_epoch_for_direct_staging() {
    let (service, transport, gk) = gk_service();
    let member = join_member(&service, &transport, 0x00A1_0000_0000_D002, 0xD1, T0);
    gk.set_ready(member.node, true);
    rotate(&service, 1, "first", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let (_, key2) = update_key(&gk.take(), member.node);
    assert_eq!(
        ack_key(&service, member.node, 2, &key2, 1, T0 + 2_000),
        AckOutcome::StagedRecorded
    );
    assert_eq!(
        ack_key(&service, member.node, 2, &key2, 2, T0 + 3_000),
        AckOutcome::ActiveRecorded
    );
    gk.take();
    rotate(&service, 2, "second", T0 + 70_000).unwrap();
    service.tick(HostTime::sync(T0 + 70_000));
    gk.take();
    // This device has current=1 and next=3. Since d=max(1,3)=3 is above
    // host active=2, it must receive staged 3 directly.
    assert_eq!(
        pull(&service, member.node, 1, 3, 2, T0 + 71_000),
        PullOutcome::Answered
    );
    service.tick(HostTime::sync(T0 + 71_000));
    assert_eq!(updates_of(&gk.take()), vec![(member.node, 3)]);
}

#[test]
fn review_pull_at_active_epoch_waits_for_active_ack_before_staging() {
    let (service, transport, gk) = gk_service();
    let member = join_member(&service, &transport, 0x00A1_0000_0000_D006, 0xD5, T0);
    gk.set_ready(member.node, true);
    rotate(&service, 1, "first-equal", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let (_, key2) = update_key(&gk.take(), member.node);
    assert_eq!(
        ack_key(&service, member.node, 2, &key2, 1, T0 + 2_000),
        AckOutcome::StagedRecorded
    );
    assert_eq!(
        ack_key(&service, member.node, 2, &key2, 2, T0 + 3_000),
        AckOutcome::ActiveRecorded
    );
    gk.take();
    rotate(&service, 2, "second-equal", T0 + 70_000).unwrap();
    assert_eq!(
        pull(&service, member.node, 2, 0, 2, T0 + 71_000),
        PullOutcome::Answered
    );
    service.tick(HostTime::sync(T0 + 71_000));
    assert_eq!(updates_of(&gk.take()), vec![(member.node, 2)]);
}

#[test]
fn review_post_activation_pull_promotes_after_staged_ack() {
    let (service, transport, gk) = gk_service();
    let member = join_member(&service, &transport, 0x00A1_0000_0000_D007, 0xD6, T0);
    gk.set_ready(member.node, true);
    rotate(&service, 1, "late-member", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 61_000));
    gk.take();
    assert_eq!(
        gk_status(&service, T0 + 61_000)
            .get("active")
            .unwrap()
            .as_u64(),
        Some(2)
    );
    assert_eq!(
        pull(&service, member.node, 1, 0, 2, T0 + 62_000),
        PullOutcome::Answered
    );
    service.tick(HostTime::sync(T0 + 62_000));
    let (_, key) = update_key(&gk.take(), member.node);
    assert_eq!(
        ack_key(&service, member.node, 2, &key, 1, T0 + 63_000),
        AckOutcome::StagedRecorded
    );
    assert_eq!(activates_of(&gk.take()), vec![(member.node, 2)]);
}

#[test]
fn review_active_acked_target_can_repair_a_lost_key() {
    let (service, transport, gk) = gk_service();
    let member = join_member(&service, &transport, 0x00A1_0000_0000_D008, 0xD7, T0);
    let sleeper = join_member(&service, &transport, 0x00A1_0000_0000_D009, 0xD8, T0);
    gk.set_ready(member.node, true);
    gk.set_ready(sleeper.node, true);
    rotate(&service, 1, "repair-live", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let (_, key) = update_key(&gk.take(), member.node);
    assert_eq!(
        ack_key(&service, member.node, 2, &key, 1, T0 + 2_000),
        AckOutcome::StagedRecorded
    );
    service.tick(HostTime::sync(T0 + 61_000));
    gk.take();
    assert_eq!(
        ack_key(&service, member.node, 2, &key, 2, T0 + 62_000),
        AckOutcome::ActiveRecorded
    );
    assert_eq!(
        service
            .with(|a| a.gks.target(member.node).map(|t| t.row.state))
            .0,
        Some(TargetState::ActiveAcked)
    );
    let request = member_pull(&service, member.node, 1, 0, 3);
    let ((outcome, queued), _) = service.with(|a| {
        let outcome = a.on_group_key_pull(request, HostTime::sync(T0 + 63_000));
        (outcome, a.gk_outbox.len())
    });
    assert_eq!(outcome, PullOutcome::Answered);
    assert_eq!(queued, 1);
    let sent = gk.take();
    assert_eq!(updates_of(&sent), vec![(member.node, 2)], "{sent:?}");
    assert_eq!(
        ack_key(&service, member.node, 2, &key, 1, T0 + 64_000),
        AckOutcome::Duplicate
    );
    assert_eq!(activates_of(&gk.take()), vec![(member.node, 2)]);
}

#[test]
fn review_active_acked_target_repairs_host_active_before_future_stage() {
    let (service, transport, gk) = gk_service();
    let member = join_member(&service, &transport, 0x00A1_0000_0000_D00E, 0xDD, T0);
    let _sleeper = join_member(&service, &transport, 0x00A1_0000_0000_D00F, 0xDE, T0);
    gk.set_ready(member.node, true);
    rotate(&service, 1, "early-active", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let (_, key2) = update_key(&gk.take(), member.node);
    let key1 = service.with(|a| *a.gks.active_key().bytes()).0;
    assert_eq!(
        ack_key(&service, member.node, 2, &key2, 2, T0 + 2_000),
        AckOutcome::ActiveRecorded
    );
    gk.take();
    assert_eq!(
        pull(&service, member.node, 1, 0, 3, T0 + 3_000),
        PullOutcome::Answered
    );
    assert_eq!(updates_of(&gk.take()), vec![(member.node, 1)]);
    assert_eq!(
        ack_key(&service, member.node, 1, &key1, 1, T0 + 4_000),
        AckOutcome::StagedRecorded
    );
    assert_eq!(activates_of(&gk.take()), vec![(member.node, 1)]);
    assert_eq!(
        ack_key(&service, member.node, 1, &key1, 2, T0 + 5_000),
        AckOutcome::ActiveRecorded
    );
    assert_eq!(updates_of(&gk.take()), vec![(member.node, 2)]);
}

#[test]
fn review_staged_acked_target_reinstalls_key_after_pull_reports_loss() {
    let (service, transport, gk) = gk_service();
    let member = join_member(&service, &transport, 0x00A1_0000_0000_D00A, 0xD9, T0);
    let _sleeper = join_member(&service, &transport, 0x00A1_0000_0000_D00B, 0xDA, T0);
    gk.set_ready(member.node, true);
    rotate(&service, 1, "staged-repair", T0 + 1_000).unwrap();
    service.tick(HostTime::sync(T0 + 1_000));
    let (_, key2) = update_key(&gk.take(), member.node);
    assert_eq!(
        ack_key(&service, member.node, 2, &key2, 1, T0 + 2_000),
        AckOutcome::StagedRecorded
    );
    gk.take();
    assert_eq!(
        pull(&service, member.node, 1, 0, 3, T0 + 3_000),
        PullOutcome::Answered
    );
    service.tick(HostTime::sync(T0 + 3_000));
    let (_, key1) = update_key(&gk.take(), member.node);
    assert_eq!(
        ack_key(&service, member.node, 1, &key1, 1, T0 + 4_000),
        AckOutcome::StagedRecorded
    );
    gk.take();
    assert_eq!(
        ack_key(&service, member.node, 1, &key1, 2, T0 + 5_000),
        AckOutcome::ActiveRecorded
    );
    service.tick(HostTime::sync(T0 + 6_000));
    assert_eq!(updates_of(&gk.take()), vec![(member.node, 2)]);
}

#[test]
fn review_revoke_discards_unflushed_group_key_commands() {
    let (service, transport, gk) = gk_service();
    let victim = join_member(&service, &transport, 0x00A1_0000_0000_D003, 0xD2, T0);
    let survivor = join_member(&service, &transport, 0x00A1_0000_0000_D004, 0xD3, T0);
    gk.set_ready(victim.node, true);
    gk.set_ready(survivor.node, true);
    rotate(&service, 1, "before-revoke", T0 + 1_000).unwrap();
    service
        .with(|a| {
            a.tick(HostTime::sync(T0 + 1_000));
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: victim.node,
                    expected_generation: 1,
                    reason: RevocationReason::Removed,
                    key: "remove-victim".into(),
                },
                HostTime::sync(T0 + 2_000),
            )
        })
        .0
        .unwrap();
    assert!(
        gk.take().is_empty(),
        "superseded commands must never leave the queue"
    );
}

struct PausedGroupKeyTransport {
    entered: mpsc::Sender<()>,
    release: Mutex<mpsc::Receiver<()>>,
}

impl group_keys::GroupKeyTransport for PausedGroupKeyTransport {
    fn channel_ready(&self, _: u64, _: &[u8; 32]) -> bool {
        true
    }

    fn send(&self, _: GroupKeyCommand, _: Option<&[u8; 32]>) {
        self.entered.send(()).unwrap();
        self.release.lock().unwrap().recv().unwrap();
    }
}

#[test]
fn review_revoke_waits_for_inflight_key_handoff() {
    let service = Arc::new(SiteService::new(testkit::authority(
        Box::new(member_rows(1, 1)),
        T0,
    )));
    let (entered_tx, entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    service.set_group_key_transport(Arc::new(PausedGroupKeyTransport {
        entered: entered_tx,
        release: Mutex::new(release_rx),
    }));
    rotate(&service, 1, "before-handoff", T0 + 1_000).unwrap();
    let tick_service = Arc::clone(&service);
    let tick = std::thread::spawn(move || tick_service.tick(HostTime::sync(T0 + 1_000)));
    entered_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let victim = 0x00A1_0000_0000_0000 + 0x1000;
    let revoke_service = Arc::clone(&service);
    let (started_tx, started_rx) = mpsc::channel();
    let (committed_tx, committed_rx) = mpsc::channel();
    let revocation = std::thread::spawn(move || {
        started_tx.send(()).unwrap();
        let result = revoke(&revoke_service, victim, 1, "during-handoff", T0 + 2_000);
        committed_tx.send(result).unwrap();
    });
    started_rx.recv_timeout(Duration::from_secs(2)).unwrap();
    let early = committed_rx.recv_timeout(Duration::from_millis(500));
    let committed_before_send = early.is_ok();
    release_tx.send(()).unwrap();
    tick.join().unwrap();
    revocation.join().unwrap();
    let result = match early {
        Ok(result) => result,
        Err(_) => committed_rx.recv_timeout(Duration::from_secs(2)).unwrap(),
    };
    result.unwrap();
    assert!(
        !committed_before_send,
        "a removed member can receive an old key after revoke commits"
    );
}

#[test]
fn review_rejects_missing_high_water_and_partial_fresh_store() {
    let mut partial = MemoryStore::default();
    partial
        .commit(&Batch {
            meta: vec![(group_keys::META_HIGH_WATER, 9_u32.to_be_bytes().to_vec())],
            ..Batch::default()
        })
        .unwrap();
    assert!(SiteAuthority::open(
        &testkit::setup(),
        Box::new(testkit::sak()),
        Box::new(partial),
        T0
    )
    .is_err());

    let db = crash_db("missing-high-water");
    drop(testkit::authority(
        Box::new(SqliteSiteStore::open(&db).unwrap()),
        T0,
    ));
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute("DELETE FROM meta WHERE name='gk_epoch_high_water'", [])
        .unwrap();
    drop(conn);
    let reopened = SiteAuthority::open(
        &testkit::setup(),
        Box::new(testkit::sak()),
        Box::new(SqliteSiteStore::open(&db).unwrap()),
        T0 + 1_000,
    );
    assert!(
        reopened.is_err(),
        "a missing high-water mark permits epoch reuse"
    );
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

#[test]
fn review_revoke_rejects_generation_overflow() {
    let mut store = member_rows(1, 1);
    let mut member = store.load().unwrap().devices.remove(0);
    member.generation = u32::MAX;
    let node = member.node;
    store
        .commit(&Batch {
            devices: vec![member],
            ..Batch::default()
        })
        .unwrap();
    let service = SiteService::new(testkit::authority(Box::new(store), T0));
    let error = revoke(&service, node, u32::MAX, "overflow", T0 + 1_000).unwrap_err();
    assert_eq!(error.code, "AUTHORITY_ERROR");
    assert_eq!(
        gk_status(&service, T0 + 1_000)
            .get("active")
            .unwrap()
            .as_u64(),
        Some(1)
    );
}

#[test]
fn review_open_rejects_exhausted_operation_id() {
    let mut store = member_rows(0, 1);
    let op = Operation {
        id: u64::MAX,
        kind: "rotate".into(),
        node: 0,
        generation: 0,
        member_cert_serial: 0,
        rs_epoch: 0,
        gk_from: 1,
        gk_to: 1,
        created_ms: T0,
        gk_cause: String::new(),
        gk_end: String::new(),
        distribution: None,
        cutover: None,
        notice: None,
    };
    store
        .commit(&Batch {
            docs: vec![(store::DocKind::Operation, h16(op.id), Some(op.doc()))],
            ..Batch::default()
        })
        .unwrap();
    assert!(SiteAuthority::open(
        &testkit::setup(),
        Box::new(testkit::sak()),
        Box::new(store),
        T0
    )
    .is_err());
}

#[test]
fn review_failed_join_request_commit_creates_no_phantom_request() {
    let (service, transport) = service_with(Box::<FailJoinRequestCommit>::default());
    let mut member = SimDevice::new(0x00A1_0000_0000_D00C, 0xDB);
    let (_, outcome, events) = member.start(&service, &transport, T0);
    assert!(matches!(
        outcome,
        Outcome::Result(JoinResult::AuthorityBusy { .. })
    ));
    assert!(request_id(&events).is_none());
    assert!(service.with(|a| a.requests.is_empty()).0);
}

#[test]
fn review_rejects_forged_rotation_evidence_on_restart() {
    let db = crash_db("forged-target");
    {
        let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        let member = join_member(&service, &transport, 0x00A1_0000_0000_D005, 0xD4, T0);
        assert_eq!(
            json(&rotate(&service, 1, "target-rotate", T0 + 1_000).unwrap())
                .get("to")
                .unwrap()
                .as_u64(),
            Some(2)
        );
        assert!(service.with(|a| a.gks.target(member.node).is_some()).0);
    }
    let conn = rusqlite::Connection::open(&db).unwrap();
    conn.execute(
        "UPDATE gk_targets SET state='active_acked', confirmed_epoch=2, confirmed_gkid=zeroblob(32)",
        [],
    )
    .unwrap();
    drop(conn);
    let reopened = SiteAuthority::open(
        &testkit::setup(),
        Box::new(testkit::sak()),
        Box::new(SqliteSiteStore::open(&db).unwrap()),
        T0 + 2_000,
    );
    assert!(
        reopened.is_err(),
        "a target's GK-id must match the saved key"
    );
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
}

#[test]
fn review_rejects_rotation_operation_cause_mismatch_on_restart() {
    let db = crash_db("rotation-operation-cause");
    {
        let (service, _) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        rotate(&service, 1, "manual-cause", T0 + 1_000).unwrap();
    }
    let conn = rusqlite::Connection::open(&db).unwrap();
    let body: String = conn
        .query_row("SELECT body FROM docs WHERE kind='operation'", [], |row| {
            row.get(0)
        })
        .unwrap();
    let altered = body.replace("\"gk_cause\":\"manual\"", "\"gk_cause\":\"removal\"");
    assert_ne!(body, altered);
    conn.execute(
        "UPDATE docs SET body=?1 WHERE kind='operation'",
        rusqlite::params![altered],
    )
    .unwrap();
    drop(conn);
    assert!(SiteAuthority::open(
        &testkit::setup(),
        Box::new(testkit::sak()),
        Box::new(SqliteSiteStore::open(&db).unwrap()),
        T0 + 2_000,
    )
    .is_err());
    let _ = std::fs::remove_dir_all(db.parent().unwrap());
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

fn join_member_rrs(
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

fn revoke_rrs(
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
            HostTime::sync(at),
        )
    });
    let answer = json(&answer.unwrap());
    let op =
        records::parse_op_token(answer.get("operation_id").unwrap().as_str().unwrap()).unwrap();
    (op, answer)
}

fn distribution_of(service: &SiteService, op: u64) -> routeloom_json::Json {
    let (view, _) = service.with(|a| a.operation_json(op, HostTime::sync(T0)).unwrap());
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
    join_member_rrs(&service, &transport, &mut keeper, "k", T0);
    join_member_rrs(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let (op, answer) = revoke_rrs(&service, leaver.node, 1, "r-dist", T0 + 10_000);
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
    join_member_rrs(&service, &transport, &mut keeper, "k", T0);
    join_member_rrs(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op, _) = revoke_rrs(&service, leaver.node, 1, "r-push", T0 + 10_000);
    service.tick(HostTime::sync(T0 + 10_100));
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

#[test]
fn applied_ack_requires_the_snapshot_credential() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member_rrs(&service, &transport, &mut keeper, "k", T0);
    join_member_rrs(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let (op, _) = revoke_rrs(&service, leaver.node, 1, "r-binding", T0 + 10_000);
    let digest = service.with(|a| sha256(&a.rrs_latest_object)).0;
    let network = testkit::network();
    service.with(|a| a.devices.get_mut(&keeper.node).unwrap().generation = 2);
    assert!(
        !service
            .with(|a| a.handle_rrs_applied(keeper.node, 2, network, 1, &digest, T0 + 10_100))
            .0
    );
    service.with(|a| {
        let row = a.devices.get_mut(&keeper.node).unwrap();
        row.generation = 1;
        row.kid = [0x55; 32];
    });
    assert!(
        !service
            .with(|a| a.handle_rrs_applied(keeper.node, 1, network, 1, &digest, T0 + 10_200))
            .0
    );
    assert_eq!(
        distribution_of(&service, op)
            .get("applied")
            .unwrap()
            .as_u64(),
        Some(0)
    );
}

struct FailNextStore {
    inner: Box<dyn SiteStore>,
    fail_next: bool,
}

impl SiteStore for FailNextStore {
    fn load(&mut self) -> Result<Snapshot, StoreError> {
        self.inner.load()
    }
    fn commit(&mut self, batch: &Batch) -> Result<(), StoreError> {
        if self.fail_next {
            self.fail_next = false;
            return Err(StoreError("injected ACK commit failure".into()));
        }
        self.inner.commit(batch)
    }
    fn durable(&self) -> bool {
        self.inner.durable()
    }
}

#[test]
fn applied_ack_is_not_reported_before_commit() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member_rrs(&service, &transport, &mut keeper, "k", T0);
    join_member_rrs(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let (op, _) = revoke_rrs(&service, leaver.node, 1, "r-ack-fault", T0 + 10_000);
    let digest = service.with(|a| sha256(&a.rrs_latest_object)).0;
    service.with(|a| {
        let inner = std::mem::replace(&mut a.store, Box::new(MemoryStore::default()));
        a.store = Box::new(FailNextStore {
            inner,
            fail_next: true,
        });
    });
    assert!(
        !service
            .with(|a| a.handle_rrs_applied(
                keeper.node,
                1,
                testkit::network(),
                1,
                &digest,
                T0 + 10_100
            ))
            .0
    );
    assert_eq!(
        distribution_of(&service, op)
            .get("applied")
            .unwrap()
            .as_u64(),
        Some(0)
    );
    assert!(
        service
            .with(|a| a.handle_rrs_applied(
                keeper.node,
                1,
                testkit::network(),
                1,
                &digest,
                T0 + 10_200
            ))
            .0
    );
    assert_eq!(
        distribution_of(&service, op)
            .get("applied")
            .unwrap()
            .as_u64(),
        Some(1)
    );
}

#[test]
fn unfinished_operation_is_not_evicted_at_capacity() {
    let (service, transport) = service();
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member_rrs(&service, &transport, &mut leaver, "l", T0);
    service.with(|a| {
        let mut template = a.operations.values().next().unwrap().clone();
        template.kind = "revoke".into();
        template.distribution = Some(revocation::OperationDistribution {
            state: revocation::DistState::Pending,
            rs_epoch: 1,
            network: testkit::network(),
            object_sha256: [0; 32],
            targets: vec![revocation::DistributionTarget {
                node: leaver.node,
                kid: [0; 32],
                generation: 1,
                network: testkit::network(),
                state: revocation::TargetState::Pending,
                attempts: 0,
                next_retry_ms: 0,
                ack_rs_epoch: None,
            }],
            overflow: 0,
        });
        a.operations.clear();
        for id in 1..=OPERATIONS_CAP as u64 {
            let mut op = template.clone();
            op.id = id;
            a.operations.insert(id, op);
        }
        a.next_op_id = OPERATIONS_CAP as u64 + 1;
    });
    let result = service
        .with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: leaver.node,
                    expected_generation: 1,
                    reason: RevocationReason::Lost,
                    key: "r-cap".into(),
                },
                HostTime::sync(T0 + 10_000),
            )
        })
        .0;
    assert_eq!(result.unwrap_err().code, "NO_CAPACITY");
    service.with(|a| {
        assert_eq!(a.operations.len(), OPERATIONS_CAP);
        assert!(a.operations.contains_key(&1));
        assert_eq!(a.rs_epoch, 0);
        assert!(a.devices.get(&leaver.node).unwrap().member);
    });
}

#[test]
fn distribution_retries_after_the_initial_contact() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member_rrs(&service, &transport, &mut keeper, "k", T0);
    join_member_rrs(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op, _) = revoke_rrs(&service, leaver.node, 1, "r-retry", T0 + 10_000);
    for at in [10_000, 15_000, 25_000, 45_000, 85_000, 145_000] {
        service.tick(HostTime::sync(T0 + at));
    }
    assert_eq!(sends.lock().unwrap().sent.len(), 6);
    assert_eq!(
        distribution_of(&service, op)
            .get("unknown")
            .unwrap()
            .as_u64(),
        Some(1)
    );
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
    join_member_rrs(&service, &transport, &mut keeper, "k", T0);
    join_member_rrs(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op, _) = revoke_rrs(&service, leaver.node, 1, "r-client", T0 + 10_000);
    let progress = || {
        let (view, _) = service.with(|a| a.operation_json(op, HostTime::sync(T0)).unwrap());
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
    service.tick(HostTime::sync(T0 + 10_100));
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

/// V1-R01 (P6-1): un-ACKed targets keep retrying at bounded intervals
/// and remain `unknown`; a refusing transport backs the whole outbox off.
#[test]
fn revocation_distribution_attempts_and_backoff() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_7001, 0x71);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_7002, 0x72);
    join_member_rrs(&service, &transport, &mut keeper, "k", T0);
    join_member_rrs(&service, &transport, &mut leaver, "l", T0 + 5_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op, _) = revoke_rrs(&service, leaver.node, 1, "r-try", T0 + 10_000);
    service.tick(HostTime::sync(T0 + 10_000));
    assert_eq!(sends.lock().unwrap().sent.len(), 1);
    service.tick(HostTime::sync(T0 + 14_999)); // inside the 5 s backoff
    assert_eq!(sends.lock().unwrap().sent.len(), 1);
    service.tick(HostTime::sync(T0 + 15_000));
    assert_eq!(sends.lock().unwrap().sent.len(), 2);
    service.tick(HostTime::sync(T0 + 25_000)); // +10 s
    assert_eq!(sends.lock().unwrap().sent.len(), 3);
    service.tick(HostTime::sync(T0 + 45_000)); // +20 s: the next host contact
    assert_eq!(sends.lock().unwrap().sent.len(), 4);
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
    join_member_rrs(&service, &transport, &mut third, "t", T0 + 50_000);
    let (op2, _) = revoke_rrs(&service, third.node, 1, "r-busy", T0 + 60_000);
    service.tick(HostTime::sync(T0 + 60_000));
    assert!(sends.lock().unwrap().sent.is_empty());
    service.tick(HostTime::sync(T0 + 64_999));
    assert!(sends.lock().unwrap().sent.is_empty());
    sends.lock().unwrap().refuse = false;
    service.tick(HostTime::sync(T0 + 65_000));
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
        join_member_rrs(&service, &transport, &mut keeper, "k", T0);
        join_member_rrs(&service, &transport, &mut leaver, "l", T0 + 5_000);
        let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
        service.with(|a| {
            a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
                shared: sends.clone(),
            })))
        });
        let (op, _) = revoke_rrs(&service, leaver.node, 1, "r-restart", T0 + 10_000);
        service.tick(HostTime::sync(T0 + 10_100));
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
    service.tick(HostTime::sync(T0 + 20_000)); // the un-ACKed target is re-sent, not rebuilt
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
    join_member_rrs(&service, &transport, &mut a, "a", T0);
    join_member_rrs(&service, &transport, &mut b, "b", T0 + 5_000);
    join_member_rrs(&service, &transport, &mut c, "c", T0 + 10_000);
    let sends = Arc::new(Mutex::new(FakeRrsSends::default()));
    service.with(|a| {
        a.set_rrs_transport(Some(Box::new(FakeRrsTransport {
            shared: sends.clone(),
        })))
    });
    let (op1, _) = revoke_rrs(&service, a.node, 1, "r-a", T0 + 20_000);
    let (op2, _) = revoke_rrs(&service, b.node, 1, "r-b", T0 + 30_000);
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
    service.tick(HostTime::sync(T0 + 30_100));
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
    join_member_rrs(&service2, &transport, &mut keeper, "k", T0);
    join_member_rrs(&service2, &transport, &mut leaver, "l", T0 + 5_000);
    service2
        .with(|a| a.handle_rrs_get(0, T0 + 6_000))
        .0
        .unwrap();
    let (op, _) = revoke_rrs(&service2, leaver.node, 1, "r-base", T0 + 10_000);
    let (view, _) = service2.with(|a| a.operation_json(op, HostTime::sync(T0)).unwrap());
    assert_eq!(json(&view).get("rs_epoch").unwrap().as_u64(), Some(2));
}

/// V1-H11 (P2-6): archiving removed rows deletes the device rows
/// (reclaiming the 1024-row ledger capacity) while the `revoke` ledger
/// rows keep the no-reissue rule intact: the NodeId still refuses a
/// fresh key.
#[test]
fn archive_removed_reclaims_capacity_without_losing_no_reissue_history() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_C002, 0xC3);
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
    device.finish(&mut exchange, &transport);
    revoke(&service, device.node, 1, "rv", T0 + 20).unwrap();

    let (answer, events) = archive(&service, &[device.node], "arc", T0 + 30);
    let answer = json(&answer.unwrap());
    let archived = answer.get("archived").unwrap().as_array().unwrap();
    assert_eq!(archived.len(), 1);
    assert_eq!(
        archived[0].as_str().unwrap(),
        format!("{:016x}", device.node)
    );
    assert!(answer
        .get("skipped_unknown")
        .unwrap()
        .as_array()
        .unwrap()
        .is_empty());
    assert_eq!(kinds(&events), vec!["member.archived".to_string()]);

    // The row is gone from the member surface and the ledger map.
    assert!(service.with(|a| a.member_get_json(device.node)).0.is_none());
    assert_eq!(service.with(|a| a.devices.len()).0, 0);

    // ... but the NodeId still refuses a fresh key.
    let mut fresh_key = SimDevice::new(device.node, 0xC4);
    let (_, outcome, events) = fresh_key.start(&service, &transport, T0 + 40_000);
    assert!(matches!(outcome, Outcome::Waiting));
    assert_eq!(
        decide(
            &service,
            request_id(&events).unwrap(),
            fresh_key.node,
            Verdict::Allow {
                role: ROLE_ENDPOINT
            },
            "b",
            T0 + 40_010
        )
        .unwrap_err()
        .code,
        "CONFLICT"
    );
    let rows = service.with(|a| a.store.ledger_for(device.node).unwrap()).0;
    assert!(rows.iter().any(|r| r.kind == "revoke"));
    assert!(rows.iter().any(|r| r.kind == "archive"));
    let status = service
        .with(|a| a.status_json(HostTime::sync(T0 + 40_010)))
        .0;
    assert!(status.contains("\"archived_total\":1"), "{status}");
}

/// P2-6: one live member in the batch vetoes the whole call — no partial
/// delete — and unknown ids are reported, not refused.
#[test]
fn archive_refuses_live_member_without_partial_delete() {
    let (service, transport) = service();
    let mut keeper = SimDevice::new(0x00A1_0000_0000_A001, 0xA1);
    let (mut exchange, _, events) = keeper.start(&service, &transport, T0);
    decide(
        &service,
        request_id(&events).unwrap(),
        keeper.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "a",
        T0 + 10,
    )
    .unwrap();
    keeper.finish(&mut exchange, &transport);
    let mut leaver = SimDevice::new(0x00A1_0000_0000_A002, 0xA2);
    let (mut exchange, _, events) = leaver.start(&service, &transport, T0 + 100);
    decide(
        &service,
        request_id(&events).unwrap(),
        leaver.node,
        Verdict::Allow {
            role: ROLE_ENDPOINT,
        },
        "b",
        T0 + 110,
    )
    .unwrap();
    leaver.finish(&mut exchange, &transport);
    revoke(&service, leaver.node, 1, "rv", T0 + 120).unwrap();

    let error = archive(&service, &[keeper.node, leaver.node], "arc", T0 + 130)
        .0
        .unwrap_err();
    assert_eq!(error.code, "CONFLICT");
    // Nothing was deleted: both rows are still listed.
    assert_eq!(service.with(|a| a.devices.len()).0, 2);
    assert!(service.with(|a| a.member_get_json(leaver.node)).0.is_some());

    let (answer, _) = archive(
        &service,
        &[leaver.node, 0x00A1_0000_0000_FFFF],
        "arc-ok",
        T0 + 140,
    );
    let answer = json(&answer.unwrap());
    assert_eq!(answer.get("archived").unwrap().as_array().unwrap().len(), 1);
    let skipped = answer.get("skipped_unknown").unwrap().as_array().unwrap();
    assert_eq!(skipped.len(), 1);
    assert_eq!(skipped[0].as_str(), Some("00a100000000ffff"));
    assert_eq!(service.with(|a| a.devices.len()).0, 1);
}

/// P2-6: an archive replay under the same idempotency key returns the
/// stored answer without touching state; the key binds the id set.
#[test]
fn archive_replay_returns_stored_answer() {
    let (service, transport) = service();
    let mut device = SimDevice::new(0x00A1_0000_0000_C003, 0xC3);
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
    device.finish(&mut exchange, &transport);
    revoke(&service, device.node, 1, "rv", T0 + 20).unwrap();

    let (first, _) = archive(&service, &[device.node], "arc", T0 + 30);
    let first = first.unwrap();
    let (second, events) = archive(&service, &[device.node], "arc", T0 + 40);
    assert_eq!(second.unwrap(), first);
    assert!(events.is_empty());
    let status = service.with(|a| a.status_json(HostTime::sync(T0 + 40))).0;
    assert!(status.contains("\"archived_total\":1"), "{status}");

    let error = archive(&service, &[0x00A1_0000_0000_FFFF], "arc", T0 + 50)
        .0
        .unwrap_err();
    assert_eq!(error.code, "CONFLICT");
}

/// P2-6: the archive is durable — after a restart the row stays gone, the
/// counter stays, and the `revoke` ledger row still refuses the NodeId.
#[test]
fn archive_survives_restart() {
    let dir = std::env::temp_dir().join(format!(
        "routeloom-site-archive-{}-{}",
        std::process::id(),
        T0
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let db = dir.join("site.db");
    let node = 0x00A1_0000_0000_C004;
    {
        let (service, transport) = service_with(Box::new(SqliteSiteStore::open(&db).unwrap()));
        let mut device = SimDevice::new(node, 0xC3);
        let (mut exchange, _, events) = device.start(&service, &transport, T0);
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
        device.finish(&mut exchange, &transport);
        revoke(&service, node, 1, "rv", T0 + 20).unwrap();
        archive(&service, &[node], "arc", T0 + 30).0.unwrap();
    }
    // Reopen replays the snapshot and verifies the ledger chain — a
    // corrupt `archive` row would refuse to start.
    let reopened = SiteService::new(testkit::authority(
        Box::new(SqliteSiteStore::open(&db).unwrap()),
        T0 + 40,
    ));
    let status = reopened.with(|a| a.status_json(HostTime::sync(T0 + 40))).0;
    assert!(status.contains("\"archived_total\":1"), "{status}");
    assert!(reopened.with(|a| a.member_get_json(node)).0.is_none());
    assert!(reopened.with(|a| a.store.has_revocation(node).unwrap()).0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// V1-H12 (P2-5): every policy content change mints a new durable
/// generation (the version the radio distribution will converge on); a
/// no-op set keeps the generation. `radio_distributed_generation`
/// reports how far the proxies have confirmed — null while
/// undistributed.
#[test]
fn policy_set_versions_content_changes() {
    let (service, _) = service();
    assert_eq!(service.with(|a| a.policy()).0.policy_generation, 0);

    let mut policy = JoinPolicy {
        zero_touch_open: false,
        ..JoinPolicy::default()
    };
    service.with(|a| a.set_policy(policy)).0.unwrap();
    assert_eq!(service.with(|a| a.policy()).0.policy_generation, 1);

    // A no-op set is not a new version.
    service.with(|a| a.set_policy(policy)).0.unwrap();
    assert_eq!(service.with(|a| a.policy()).0.policy_generation, 1);

    policy.decision_mode = DecisionMode::Closed;
    service.with(|a| a.set_policy(policy)).0.unwrap();
    assert_eq!(service.with(|a| a.policy()).0.policy_generation, 2);

    let body = service.with(|a| a.policy_json()).0;
    assert!(body.contains("\"policy_generation\":2"), "{body}");
    assert!(
        body.contains("\"radio_distributed_generation\":null"),
        "{body}"
    );
}

/// P2-5: the policy encoding carries the generation; pre-generation
/// 8-byte rows decode as generation 0.
#[test]
fn policy_encoding_roundtrips_generation() {
    let policy = JoinPolicy {
        zero_touch_open: false,
        policy_generation: 41,
        ..JoinPolicy::default()
    };
    let bytes = policy.encode();
    assert_eq!(bytes.len(), 12);
    assert_eq!(JoinPolicy::decode(&bytes).unwrap(), policy);

    let legacy = JoinPolicy {
        zero_touch_open: false,
        ..JoinPolicy::default()
    };
    let full = legacy.encode();
    let decoded = JoinPolicy::decode(&full[..8]).unwrap();
    assert_eq!(decoded.policy_generation, 0);
    assert!(!decoded.zero_touch_open);
}
