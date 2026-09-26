//! Authority-channel E2E with a Rust simulated device: EDHOC, RLRES1,
//! JoinConfirm, pull, rotation and removal run through `SiteService` and
//! `UsbAuthorityAdapter`, with USB 0x64/0x65 fragments and real AES-GCM.
//! `FakeDevice` checks the sealed answers; the C++ Owner and MeshNode are
//! outside this test's process boundary.

use std::collections::HashMap;
use std::sync::Arc;

use routeloom_join::JoinResult;
use routeloom_keysched::authority::{
    gk_id, BodyHead, GroupKeyAck, GroupKeyActivate, GroupKeyPull, GroupKeyUpdate, JoinConfirmDown,
    JoinConfirmUp, PullReason, StoredState, UpdateResult,
};
use routeloom_keysched::rlres1::Epochs;
use routeloom_protocol::authority::CarrierKind;
use routeloom_protocol::host_ops::{
    decode_authority_down, encode_authority_up, AuthorityFragment, AUTHORITY_FRAGMENT_DATA_MAX,
    SUB_AUTHORITY_DOWN,
};
use routeloom_provision::sdkv1::revocation::RevocationReason;
use routeloom_provision::sha256::sha256;

use super::group_keys::{GkSecret, GroupKeyCommand, HostTime, RotationCause};
use super::records::{Verdict, ROLE_ENDPOINT};
use super::store::{MemoryStore, SiteStore, SqliteSiteStore};
use super::testkit::{self, AuthorityNet, FakeDevice, Outcome, SimDevice};
use super::transport::InProcessTransport;
use super::usb::{authority_sub, UsbAuthorityAdapter};
use super::{ChannelGroupKeyTransport, DecideRequest, Events, RevokeRequest, SiteService};

const T0: u64 = 1_790_000_000_000;
const KGUARD: u32 = 501;
const NODE_A: u64 = 0x00A1_0000_0000_0101;
const NODE_B: u64 = 0x00A1_0000_0000_0102;

/// The live rig: a real service, the join relay for enrolment, the
/// channel-backed GK transport and the USB authority adapter as the
/// fragment sink — the same composition the daemon lane builds.
struct Rig {
    service: Arc<SiteService>,
    relay: Arc<InProcessTransport>,
    usb: Arc<UsbAuthorityAdapter>,
    rng_state: u64,
    transfer: u32,
    now: u64,
    mono_offset: u64,
    request_id: u64,
}

impl Rig {
    fn new() -> Self {
        Self::with_store(Box::<MemoryStore>::default())
    }

    fn with_store(store: Box<dyn SiteStore>) -> Self {
        let service = Arc::new(SiteService::new(testkit::authority(store, T0)));
        let relay = InProcessTransport::new();
        service.set_transport(relay.clone());
        service.set_group_key_transport(ChannelGroupKeyTransport::new(&service));
        let usb = UsbAuthorityAdapter::new(testkit::GATEWAY, 7);
        service.set_authority_transport(Some(usb.clone()));
        Self {
            service,
            relay,
            usb,
            rng_state: 0x1234_5678_9ABC_DEF0,
            transfer: 0,
            now: T0,
            mono_offset: 0,
            request_id: 0,
        }
    }

    fn next_request_id(&mut self) -> u64 {
        self.request_id += 1;
        self.request_id
    }

    /// Joins one member end to end (Allow delivered and verified).
    fn join(&self, node: u64, seed: u8, now: u64) -> SimDevice {
        let mut device = SimDevice::new(node, seed);
        let (mut exchange, _, events) = device.start(&self.service, &self.relay, now);
        self.service
            .with(|a| {
                a.decide(
                    KGUARD,
                    DecideRequest {
                        join_request_id: testkit::request_id(&events).unwrap(),
                        device: node,
                        verdict: Verdict::Allow {
                            role: ROLE_ENDPOINT,
                        },
                        key: format!("allow-{node:016x}"),
                    },
                    now + 10,
                )
            })
            .0
            .unwrap();
        assert!(
            matches!(
                device.finish(&mut exchange, &self.relay),
                Outcome::Result(JoinResult::Allow { .. })
            ),
            "join of {node:016x} failed"
        );
        device
    }

    fn net(&self) -> AuthorityNet {
        let (_, rs_epoch, gk_epoch) = self.service.authority_epochs();
        AuthorityNet {
            network: testkit::network(),
            site: testkit::SITE,
            epochs_i: Epochs {
                site_epoch: testkit::SITE_EPOCH,
                rs_epoch: 0,
                gk_epoch: 0,
            },
            epochs_r: Epochs {
                site_epoch: testkit::SITE_EPOCH,
                rs_epoch,
                gk_epoch,
            },
        }
    }

    /// Device → owner: fragments the carrier like a gateway would and
    /// pumps every completed assembly through the service.
    fn send_up(&mut self, device: u64, kind: CarrierKind, bytes: &[u8]) -> Events {
        let total = bytes.len();
        self.transfer += 1;
        let transfer = self.transfer;
        let mut offset = 0;
        let mut events = Vec::new();
        while offset < total {
            let end = (offset + AUTHORITY_FRAGMENT_DATA_MAX).min(total);
            let body = encode_authority_up(&AuthorityFragment {
                device,
                transfer_id: transfer,
                kind,
                hops: 1,
                total: total as u16,
                offset: offset as u16,
                data: bytes[offset..end].to_vec(),
            })
            .unwrap();
            for up in self.usb.handle_up(&body, self.now).unwrap() {
                let mut state = self.rng_state;
                let mut rng = |out: &mut [u8]| {
                    for b in out.iter_mut() {
                        state = state
                            .wrapping_mul(6364136223846793005)
                            .wrapping_add(1442695040888963407);
                        *b = (state >> 33) as u8;
                    }
                    true
                };
                events.extend(self.service.handle_authority_up(
                    up.device,
                    up.kind,
                    &up.bytes,
                    HostTime {
                        unix_ms: self.now,
                        mono_ms: self.now - self.mono_offset,
                    },
                    &mut rng,
                ));
                self.rng_state = state;
            }
            offset = end;
        }
        events
    }

    /// Owner → device: drains the adapter queue and reassembles the 0x65
    /// fragments like a gateway would, returning whole carriers.
    fn recv_downs(&mut self) -> Vec<(u64, CarrierKind, Vec<u8>)> {
        let mut partial: HashMap<(u64, u32), (CarrierKind, Vec<u8>, usize)> = HashMap::new();
        let mut whole = Vec::new();
        for down in self.usb.take_ready(crate::mono_ms()) {
            if authority_sub(&down.bytes) != Some(SUB_AUTHORITY_DOWN) {
                continue;
            }
            let fragment = decode_authority_down(&down.bytes).unwrap();
            let entry = partial
                .entry((fragment.device, fragment.transfer_id))
                .or_insert_with(|| (fragment.kind, vec![0; fragment.total as usize], 0));
            assert_eq!(entry.0, fragment.kind);
            let start = fragment.offset as usize;
            entry.1[start..start + fragment.data.len()].copy_from_slice(&fragment.data);
            entry.2 += fragment.data.len();
            if entry.2 == fragment.total as usize {
                let ((device, _), (kind, bytes, _)) = partial
                    .remove_entry(&(fragment.device, fragment.transfer_id))
                    .unwrap();
                whole.push((device, kind, bytes));
            }
        }
        whole
    }

    /// Runs the RLRES1 handshake for `peer` (whose R1 is passed in) over
    /// the fragment layer; returns the service events.
    fn handshake(&mut self, node: u64, peer: &mut FakeDevice, r1: Vec<u8>) -> Events {
        let mut events = self.send_up(node, CarrierKind::R1, &r1);
        let downs = self.recv_downs();
        assert_eq!(downs.len(), 1, "handshake must yield exactly R2");
        assert_eq!(downs[0].0, node);
        assert_eq!(downs[0].1, CarrierKind::R2);
        let r3 = peer.on_r2(&downs[0].2);
        events.extend(self.send_up(node, CarrierKind::R3, &r3));
        assert!(
            self.recv_downs().is_empty(),
            "R3 completes the channel silently"
        );
        events
    }

    fn tick(&mut self) -> Events {
        self.now += 1_000;
        self.service.tick(HostTime {
            unix_ms: self.now,
            mono_ms: self.now - self.mono_offset,
        })
    }
}

fn has_kind(events: &Events, kind: &str) -> bool {
    events.iter().any(|(_, fields)| fields.contains(kind))
}

#[test]
fn live_channel_idle_uses_monotonic_time_after_group_key_send() {
    let mut rig = Rig::new();
    let _ = rig.join(NODE_A, 0xA1, T0);
    rig.mono_offset = T0 - 1_000;
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    let (r1, mut peer) = FakeDevice::begin(NODE_A, row.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer, r1);
    let next = rig.service.with(|a| a.gks.active_epoch() + 1).0;
    rig.service
        .seal_group_key(
            GroupKeyCommand::Update {
                node: NODE_A,
                epoch: next,
                key: GkSecret::new([0xA5; 32]),
                cause: RotationCause::Manual,
                overlap_s: RotationCause::Manual.overlap_s(),
            },
            Some(&row.dams),
        )
        .unwrap();
    let _ = rig.service.with(|_| ());
    let idle = 1_000 + super::authority_channel::IDLE_RETIRE_MS + 1;
    let events = rig.service.tick(HostTime {
        unix_ms: T0 + idle,
        mono_ms: idle,
    });
    assert!(has_kind(&events, "authority.channel_lost"), "{events:?}");
}

#[test]
fn live_revoke_persists_presealed_notice_before_delivery() {
    let mut rig = Rig::new();
    let _ = rig.join(NODE_A, 0xA1, T0);
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    let (r1, mut peer) = FakeDevice::begin(NODE_A, row.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer, r1);
    let request = RevokeRequest {
        device: NODE_A,
        expected_generation: row.generation,
        reason: RevocationReason::Removed,
        key: "presealed-notice".into(),
    };
    rig.service
        .with(|a| a.revoke(KGUARD, request, HostTime::sync(T0)))
        .0
        .unwrap();
    let (notice_doc, sealed) = rig
        .service
        .with(|a| {
            a.operations
                .values()
                .find(|op| op.kind == "revoke" && op.node == NODE_A)
                .and_then(|op| op.notice.as_ref())
                .map(|notice| (notice.doc(), notice.sealed.clone()))
                .unwrap()
        })
        .0;
    assert!(notice_doc.contains("\"sealed\":\""), "{notice_doc}");
    let sealed = sealed.unwrap();
    let parsed =
        super::revocation::NoticeState::from_doc(&routeloom_json::parse(&notice_doc).unwrap())
            .unwrap();
    assert_eq!(parsed.sealed, Some(sealed.clone()));
    let mut delivered = false;
    for _ in 0..5 {
        rig.tick();
        delivered |= rig.recv_downs().iter().any(|(node, kind, bytes)| {
            *node == NODE_A && *kind == CarrierKind::Envelope && *bytes == sealed
        });
    }
    assert!(delivered, "the committed ciphertext must be the one sent");
}

#[test]
fn detached_usb_keeps_presealed_notice_for_reconnect() {
    let mut rig = Rig::new();
    let _ = rig.join(NODE_A, 0xA1, T0);
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    let (r1, mut peer) = FakeDevice::begin(NODE_A, row.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer, r1);
    rig.service.set_authority_transport(None);
    rig.service
        .with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: NODE_A,
                    expected_generation: row.generation,
                    reason: RevocationReason::Removed,
                    key: "reconnect-notice".into(),
                },
                HostTime::sync(T0),
            )
        })
        .0
        .unwrap();
    for _ in 0..5 {
        rig.tick();
    }
    let attempts = rig
        .service
        .with(|a| {
            a.operations
                .values()
                .find(|op| op.kind == "revoke" && op.node == NODE_A)
                .unwrap()
                .notice
                .as_ref()
                .unwrap()
                .attempts
        })
        .0;
    assert_eq!(attempts, 0, "a detached USB lane cannot deliver");
    let sealed = rig
        .service
        .with(|a| {
            a.operations
                .values()
                .find(|op| op.kind == "revoke" && op.node == NODE_A)
                .unwrap()
                .notice
                .as_ref()
                .unwrap()
                .sealed
                .clone()
                .unwrap()
        })
        .0;
    rig.service.set_authority_transport(Some(rig.usb.clone()));
    let mut saw_notice = false;
    for _ in 0..30 {
        rig.tick();
        for (_, kind, bytes) in rig.recv_downs() {
            if kind == CarrierKind::Envelope && bytes == sealed {
                saw_notice = true;
            }
        }
    }
    assert!(saw_notice);
}

#[test]
fn host_restart_replays_exact_committed_notice_without_channel() {
    let path = std::env::temp_dir().join(format!(
        "routeloom-p6-presealed-{}-{}.db",
        std::process::id(),
        T0
    ));
    let _ = std::fs::remove_file(&path);
    let mut rig = Rig::with_store(Box::new(SqliteSiteStore::open(&path).unwrap()));
    let _ = rig.join(NODE_A, 0xA1, T0);
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    let (r1, mut peer) = FakeDevice::begin(NODE_A, row.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer, r1);
    rig.service
        .with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: NODE_A,
                    expected_generation: row.generation,
                    reason: RevocationReason::Removed,
                    key: "restart-notice".into(),
                },
                HostTime::sync(T0),
            )
        })
        .0
        .unwrap();
    let sealed = rig
        .service
        .with(|a| {
            a.operations
                .values()
                .find(|op| op.kind == "revoke" && op.node == NODE_A)
                .unwrap()
                .notice
                .as_ref()
                .unwrap()
                .sealed
                .clone()
                .unwrap()
        })
        .0;
    drop(rig);
    let mut restarted = Rig::with_store(Box::new(SqliteSiteStore::open(&path).unwrap()));
    restarted.tick();
    assert!(restarted
        .recv_downs()
        .iter()
        .any(|(node, kind, bytes)| *node == NODE_A
            && *kind == CarrierKind::Envelope
            && *bytes == sealed));
    drop(restarted);
    let _ = std::fs::remove_file(&path);
}

#[test]
fn live_p6_uses_the_existing_usb_authority_channel() {
    let mut rig = Rig::new();
    let _a = rig.join(NODE_A, 0xA1, T0);
    let _b = rig.join(NODE_B, 0xB2, T0 + 100);
    assert_eq!(
        rig.service.with(|a| a.p6_distribution_status()).0,
        "rrs_ready"
    );

    let a = rig.service.with(|s| s.devices[&NODE_A].clone()).0;
    let b = rig.service.with(|s| s.devices[&NODE_B].clone()).0;
    let (r1_a, mut peer_a) = FakeDevice::begin(NODE_A, a.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer_a, r1_a);
    let (r1_b, mut peer_b) = FakeDevice::begin(NODE_B, b.dams, 0xA002, [0x22; 16], rig.net());
    rig.handshake(NODE_B, &mut peer_b, r1_b);
    assert_eq!(
        rig.service
            .with(|s| s.channels.lock().unwrap().stats().channels)
            .0,
        2
    );

    let result = rig.service.with(|authority| {
        authority.revoke(
            501,
            RevokeRequest {
                device: NODE_B,
                expected_generation: b.generation,
                reason: RevocationReason::Removed,
                key: "live-p6-revoke".into(),
            },
            HostTime::sync(rig.now + 100),
        )
    });
    result.0.unwrap();
    let mut kinds = Vec::new();
    let sealed_notice = rig
        .service
        .with(|s| {
            s.operations
                .values()
                .find(|op| op.kind == "revoke" && op.node == NODE_B)
                .unwrap()
                .notice
                .as_ref()
                .unwrap()
                .sealed
                .clone()
                .unwrap()
        })
        .0;
    let mut opened_notice = false;
    for _ in 0..5 {
        rig.tick();
        for (node, kind, bytes) in rig.recv_downs() {
            assert_eq!(kind, CarrierKind::Envelope);
            if node == NODE_A {
                kinds.push((node, peer_a.open(&bytes).0));
            } else {
                assert_eq!(bytes, sealed_notice);
                if !opened_notice {
                    kinds.push((node, peer_b.open(&bytes).0));
                    opened_notice = true;
                }
            }
        }
    }
    assert!(kinds.contains(&(NODE_A, 5)));
    assert!(kinds.contains(&(NODE_B, 6)));

    let (rs_epoch, rrs_hash, notice_hash) = rig
        .service
        .with(|s| {
            let op = s
                .operations
                .values()
                .find(|op| op.kind == "revoke" && op.node == NODE_B)
                .unwrap();
            (
                s.rs_epoch,
                sha256(&s.rrs_latest_object),
                sha256(&op.notice.as_ref().unwrap().object),
            )
        })
        .0;
    let mut applied = BodyHead {
        op: 2,
        generation: a.generation,
        request_id: 11,
    }
    .encode(2)
    .unwrap()
    .to_vec();
    applied.extend_from_slice(&[1, 1, 0, 0]);
    applied.extend_from_slice(&rs_epoch.to_be_bytes());
    applied.extend_from_slice(&rrs_hash);
    rig.send_up(NODE_A, CarrierKind::Envelope, &peer_a.seal(5, &applied));

    let mut accepted = BodyHead {
        op: 2,
        generation: b.generation,
        request_id: 12,
    }
    .encode(2)
    .unwrap()
    .to_vec();
    accepted.extend_from_slice(&[1, 3, 0, 0]);
    accepted.extend_from_slice(&rs_epoch.to_be_bytes());
    accepted.extend_from_slice(&notice_hash);
    rig.send_up(NODE_B, CarrierKind::Envelope, &peer_b.seal(5, &accepted));
    let (applied, accepted) = rig
        .service
        .with(|s| {
            let op = s
                .operations
                .values()
                .find(|op| op.kind == "revoke" && op.node == NODE_B)
                .unwrap();
            (
                op.distribution.as_ref().unwrap().targets.iter().any(|t| {
                    t.node == NODE_A && t.state == super::revocation::TargetState::Applied
                }),
                op.notice.as_ref().unwrap().intent_confirmed,
            )
        })
        .0;
    assert!(applied);
    assert!(accepted);
}

/// Full confirm loop: handshake, JoinConfirm, the sealed answer, the
/// confirm-accompanying active key, and the staged/active ACK catch-up —
/// every step over real USB fragments with real AES-GCM.
#[test]
fn live_confirm_pull_update_ack_over_usb_fragments() {
    let mut rig = Rig::new();
    let _device = rig.join(NODE_A, 0xA1, T0);
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    assert!(!row.confirmed);

    let (r1, mut peer) = FakeDevice::begin(NODE_A, row.dams, 0xA001, [0x11; 16], rig.net());
    let events = rig.handshake(NODE_A, &mut peer, r1);
    assert!(has_kind(&events, "authority.channel_ready"));

    // The keyless member confirms: durable fact first, then the sealed
    // answer plus the active key (the blessed first-contact sync).
    let request_id = rig.next_request_id();
    let confirm = JoinConfirmUp {
        head: BodyHead {
            op: 1,
            generation: row.generation,
            request_id,
        },
        cert_hash: sha256(&row.member_cert),
        boot: 7,
        current: 0,
        next: 0,
    }
    .encode()
    .unwrap();
    let events = rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(1, &confirm));
    assert!(has_kind(&events, "member.confirmed"));
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    assert!(row.confirmed);

    let downs = rig.recv_downs();
    assert_eq!(downs.len(), 2, "confirm answer plus the active key");
    let mut saw_answer = false;
    let mut saw_key = false;
    for (node, kind, bytes) in &downs {
        assert_eq!(*node, NODE_A);
        assert_eq!(*kind, CarrierKind::Envelope);
        let (env_type, plaintext) = peer.open(bytes);
        match env_type {
            1 => {
                let answer = JoinConfirmDown::decode(&plaintext).unwrap();
                assert_eq!(answer.confirmed_generation, row.generation);
                let active = rig.service.with(|a| a.gks.active_epoch()).0;
                assert_eq!(answer.authority_active, active);
                saw_answer = true;
            }
            2 => {
                let update = GroupKeyUpdate::decode(&plaintext).unwrap();
                let active = rig.service.with(|a| a.gks.active_epoch()).0;
                assert_eq!(update.g, active);
                // The sealed key is byte-exact the owner's active key.
                let stored = rig
                    .service
                    .with(|a| a.store.load().unwrap())
                    .0
                    .group_keys
                    .into_iter()
                    .find(|row| row.state == "active")
                    .unwrap();
                assert_eq!(update.gk, stored.key.as_slice());
                assert_eq!(
                    gk_id(testkit::network(), update.g, &update.gk),
                    gk_id(
                        testkit::network(),
                        active,
                        &stored.key.as_slice().try_into().unwrap()
                    )
                );
                saw_key = true;
            }
            other => panic!("unexpected envelope type {other}"),
        }
    }
    assert!(saw_answer && saw_key);

    // Catch-up: staged ACK for the active key earns its Activate, the
    // active ACK converges the member — still no rotation anywhere.
    let active = rig.service.with(|a| a.gks.active_epoch()).0;
    let active_key: [u8; 32] = rig
        .service
        .with(|a| a.store.load().unwrap())
        .0
        .group_keys
        .into_iter()
        .find(|row| row.state == "active")
        .unwrap()
        .key
        .as_slice()
        .try_into()
        .unwrap();
    let ack_id = rig.next_request_id();
    let ack = GroupKeyAck {
        head: BodyHead {
            op: 2,
            generation: row.generation,
            request_id: ack_id,
        },
        g: active,
        gk_id: gk_id(testkit::network(), active, &active_key),
        result: UpdateResult::Durable,
        stored_state: StoredState::Staged,
    }
    .encode()
    .unwrap();
    rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(2, &ack));
    let downs = rig.recv_downs();
    assert_eq!(downs.len(), 1, "staged ACK earns the Activate");
    let (env_type, plaintext) = peer.open(&downs[0].2);
    assert_eq!(env_type, 3);
    let activate = GroupKeyActivate::decode(&plaintext).unwrap();
    assert_eq!(activate.g, active);
    assert_eq!(
        activate.gk_id,
        gk_id(testkit::network(), active, &active_key)
    );

    let ack_id = rig.next_request_id();
    let ack = GroupKeyAck {
        head: BodyHead {
            op: 2,
            generation: row.generation,
            request_id: ack_id,
        },
        g: active,
        gk_id: gk_id(testkit::network(), active, &active_key),
        result: UpdateResult::Durable,
        stored_state: StoredState::Active,
    }
    .encode()
    .unwrap();
    rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(3, &ack));
    assert!(rig.recv_downs().is_empty(), "converged: nothing to send");
    // The status block reports the live link honestly.
    let status = rig
        .service
        .with(|a| a.status_json(HostTime::sync(rig.now)))
        .0;
    assert!(status.contains("\"attached\":true"));
    assert!(status.contains("\"channels\":1"));
}

/// A removed member is excluded from the very next rotation: no Update,
/// no Activate, no Wake is ever sealed for it, while the surviving
/// member converges through staged and active evidence.
#[test]
fn live_rotation_excludes_removed_member() {
    let mut rig = Rig::new();
    let a = rig.join(NODE_A, 0xA1, T0);
    let b = rig.join(NODE_B, 0xB2, T0 + 100);
    let row_a = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    let row_b = rig.service.with(|a| a.devices[&NODE_B].clone()).0;

    let (r1, mut peer_a) = FakeDevice::begin(NODE_A, row_a.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer_a, r1);
    let (r1, mut peer_b) = FakeDevice::begin(NODE_B, row_b.dams, 0xB001, [0x22; 16], rig.net());
    rig.handshake(NODE_B, &mut peer_b, r1);

    // Both confirm and drain their first-contact keys.
    for (node, peer, row) in [(NODE_A, &mut peer_a, &row_a), (NODE_B, &mut peer_b, &row_b)] {
        let request_id = rig.next_request_id();
        let confirm = JoinConfirmUp {
            head: BodyHead {
                op: 1,
                generation: row.generation,
                request_id,
            },
            cert_hash: sha256(&row.member_cert),
            boot: 7,
            current: 0,
            next: 0,
        }
        .encode()
        .unwrap();
        rig.send_up(node, CarrierKind::Envelope, &peer.seal(1, &confirm));
        for (_, _, bytes) in rig.recv_downs() {
            peer.open(&bytes);
        }
    }
    assert!(rig.recv_downs().is_empty());
    let _ = (a, b);

    // Removal closes B's normal member lane and starts a fresh rotation.
    rig.service
        .with(|a| {
            a.revoke(
                KGUARD,
                RevokeRequest {
                    device: NODE_B,
                    expected_generation: row_b.generation,
                    reason: RevocationReason::Removed,
                    key: "revoke-b".into(),
                },
                HostTime::sync(rig.now),
            )
        })
        .0
        .unwrap();
    let to_epoch = rig
        .service
        .with(|a| a.gks.rotation().unwrap().row.to_epoch)
        .0;
    let status = rig
        .service
        .with(|a| a.status_json(HostTime::sync(rig.now)))
        .0;
    assert!(
        status.contains("\"channels\":2"),
        "B's notice-only context retained: {status}"
    );
    let sealed_notice = rig
        .service
        .with(|a| {
            a.operations
                .values()
                .find(|op| op.kind == "revoke" && op.node == NODE_B)
                .unwrap()
                .notice
                .as_ref()
                .unwrap()
                .sealed
                .clone()
                .unwrap()
        })
        .0;

    // Drive the rotation: A answers every sealed command with durable
    // evidence until the rotation converges. B can receive only the
    // exact presealed notice, never a GK command or Wake.
    let mut staged_key: Option<[u8; 32]> = None;
    for _ in 0..20 {
        rig.tick();
        for (node, kind, bytes) in rig.recv_downs() {
            if node == NODE_B {
                assert_eq!(kind, CarrierKind::Envelope);
                assert_eq!(
                    bytes, sealed_notice,
                    "removed member receives only its notice"
                );
                continue;
            }
            assert_eq!(node, NODE_A, "excluded member received a carrier");
            assert_eq!(kind, CarrierKind::Envelope);
            let (env_type, plaintext) = peer_a.open(&bytes);
            match env_type {
                2 => {
                    let update = GroupKeyUpdate::decode(&plaintext).unwrap();
                    assert_eq!(update.g, to_epoch);
                    staged_key = Some(update.gk);
                    let ack_id = rig.next_request_id();
                    let ack = GroupKeyAck {
                        head: BodyHead {
                            op: 2,
                            generation: row_a.generation,
                            request_id: ack_id,
                        },
                        g: update.g,
                        gk_id: gk_id(testkit::network(), update.g, &update.gk),
                        result: UpdateResult::Durable,
                        stored_state: StoredState::Staged,
                    }
                    .encode()
                    .unwrap();
                    rig.send_up(NODE_A, CarrierKind::Envelope, &peer_a.seal(2, &ack));
                }
                3 => {
                    let activate = GroupKeyActivate::decode(&plaintext).unwrap();
                    assert_eq!(activate.g, to_epoch);
                    assert_eq!(
                        activate.gk_id,
                        gk_id(testkit::network(), to_epoch, &staged_key.unwrap())
                    );
                    let ack_id = rig.next_request_id();
                    let ack = GroupKeyAck {
                        head: BodyHead {
                            op: 2,
                            generation: row_a.generation,
                            request_id: ack_id,
                        },
                        g: activate.g,
                        gk_id: activate.gk_id,
                        result: UpdateResult::Durable,
                        stored_state: StoredState::Active,
                    }
                    .encode()
                    .unwrap();
                    rig.send_up(NODE_A, CarrierKind::Envelope, &peer_a.seal(3, &ack));
                }
                5 => {
                    assert!(plaintext.len() > routeloom_keysched::authority::BODY_HEAD);
                }
                other => panic!("unexpected envelope type {other}"),
            }
        }
        if rig.service.with(|a| a.gks.rotation().is_none()).0 {
            break;
        }
    }
    assert!(
        rig.service.with(|a| a.gks.rotation().is_none()).0,
        "rotation converged"
    );
    assert_eq!(rig.service.with(|a| a.gks.active_epoch()).0, to_epoch);
    assert!(rig.recv_downs().is_empty(), "converged: wire silent");
}

/// Wire pulls flow through the typed sink: answered with the active key,
/// throttled at one per 60 s per device, and the request id arrives.
#[test]
fn live_pull_answers_and_throttles() {
    let mut rig = Rig::new();
    let device = rig.join(NODE_A, 0xA1, T0);
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    let _ = device;
    let (r1, mut peer) = FakeDevice::begin(NODE_A, row.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer, r1);

    // Confirm without keys, then drain the first-contact sync.
    let request_id = rig.next_request_id();
    let confirm = JoinConfirmUp {
        head: BodyHead {
            op: 1,
            generation: row.generation,
            request_id,
        },
        cert_hash: sha256(&row.member_cert),
        boot: 7,
        current: 0,
        next: 0,
    }
    .encode()
    .unwrap();
    rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(1, &confirm));
    for (_, _, bytes) in rig.recv_downs() {
        peer.open(&bytes);
    }

    // A behind pull is answered with the active key at once.
    let active = rig.service.with(|a| a.gks.active_epoch()).0;
    let pull = GroupKeyPull {
        head: BodyHead {
            op: 1,
            generation: row.generation,
            request_id: 7,
        },
        current: active,
        next: 0,
        reason: PullReason::LostAckRepair,
    }
    .encode()
    .unwrap();
    let events = rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(4, &pull));
    assert!(
        events
            .iter()
            .any(|(_, f)| f.contains("\"kind\":\"authority.pull\"")
                && f.contains("\"request_id\":7")
                && f.contains("\"outcome\":\"answered\"")),
        "pull answered with its request id: {events:?}"
    );
    let downs = rig.recv_downs();
    assert_eq!(downs.len(), 1);
    let (env_type, plaintext) = peer.open(&downs[0].2);
    assert_eq!(env_type, 2);
    assert_eq!(GroupKeyUpdate::decode(&plaintext).unwrap().g, active);

    // The same device pulling again inside the bucket is throttled —
    // hopping the reason cannot bypass it.
    let pull = GroupKeyPull {
        head: BodyHead {
            op: 1,
            generation: row.generation,
            request_id: 8,
        },
        current: active,
        next: 0,
        reason: PullReason::BootReconnectSync,
    }
    .encode()
    .unwrap();
    let events = rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(4, &pull));
    assert!(
        has_kind(&events, "authority.pull_throttled"),
        "second pull throttled: {events:?}"
    );
    assert!(rig.recv_downs().is_empty());

    // Past the bucket the pull is answered again.
    rig.now += 60_000;
    let pull = GroupKeyPull {
        head: BodyHead {
            op: 1,
            generation: row.generation,
            request_id: 9,
        },
        current: active,
        next: 0,
        reason: PullReason::BootReconnectSync,
    }
    .encode()
    .unwrap();
    let events = rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(4, &pull));
    assert!(
        events
            .iter()
            .any(|(_, f)| f.contains("\"kind\":\"authority.pull\"")
                && f.contains("\"request_id\":9")),
        "pull answered past the bucket: {events:?}"
    );
    assert_eq!(rig.recv_downs().len(), 1);
}

/// A keyless member's wire pull (current == 0) is the
/// maximally-behind case (§6.3), not a malformed one: it is answered
/// with the active key, and the staged/active ACK catch-up converges
/// it — the same loop as the confirm sync, over real fragments.
#[test]
fn live_keyless_pull_recovers_member() {
    let mut rig = Rig::new();
    let device = rig.join(NODE_A, 0xA1, T0);
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    let _ = device;
    let (r1, mut peer) = FakeDevice::begin(NODE_A, row.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer, r1);

    // Confirm keyless and drain the first-contact sync; the member
    // then loses its keys (storage failure) and pulls from zero.
    let request_id = rig.next_request_id();
    let confirm = JoinConfirmUp {
        head: BodyHead {
            op: 1,
            generation: row.generation,
            request_id,
        },
        cert_hash: sha256(&row.member_cert),
        boot: 7,
        current: 0,
        next: 0,
    }
    .encode()
    .unwrap();
    rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(1, &confirm));
    for (_, _, bytes) in rig.recv_downs() {
        peer.open(&bytes);
    }

    let active = rig.service.with(|a| a.gks.active_epoch()).0;
    let pull = GroupKeyPull {
        head: BodyHead {
            op: 1,
            generation: row.generation,
            request_id: 11,
        },
        current: 0,
        next: 0,
        reason: PullReason::LostAckRepair,
    }
    .encode()
    .unwrap();
    let events = rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(4, &pull));
    assert!(
        events
            .iter()
            .any(|(_, f)| f.contains("\"kind\":\"authority.pull\"")
                && f.contains("\"request_id\":11")
                && f.contains("\"outcome\":\"answered\"")),
        "keyless pull answered: {events:?}"
    );
    let downs = rig.recv_downs();
    assert_eq!(downs.len(), 1);
    let (env_type, plaintext) = peer.open(&downs[0].2);
    assert_eq!(env_type, 2);
    let update = GroupKeyUpdate::decode(&plaintext).unwrap();
    assert_eq!(update.g, active);

    // Staged ACK earns the Activate; active ACK converges.
    for (stored, expect_type) in [(StoredState::Staged, 3), (StoredState::Active, 0)] {
        let ack_id = rig.next_request_id();
        let ack = GroupKeyAck {
            head: BodyHead {
                op: 2,
                generation: row.generation,
                request_id: ack_id,
            },
            g: active,
            gk_id: gk_id(testkit::network(), active, &update.gk),
            result: UpdateResult::Durable,
            stored_state: stored,
        }
        .encode()
        .unwrap();
        rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(2, &ack));
        let downs = rig.recv_downs();
        if expect_type == 0 {
            assert!(downs.is_empty(), "converged: wire silent");
        } else {
            assert_eq!(downs.len(), 1);
            let (env_type, plaintext) = peer.open(&downs[0].2);
            assert_eq!(env_type, expect_type);
            assert_eq!(GroupKeyActivate::decode(&plaintext).unwrap().g, active);
        }
    }
}

/// Types 5..8 carry no P5 handler: verified plaintext is diagnosed, and
/// no processed ACK is faked back.
#[test]
fn live_passthrough_diagnoses_without_answer() {
    let mut rig = Rig::new();
    let device = rig.join(NODE_A, 0xA1, T0);
    let row = rig.service.with(|a| a.devices[&NODE_A].clone()).0;
    let _ = device;
    let (r1, mut peer) = FakeDevice::begin(NODE_A, row.dams, 0xA001, [0x11; 16], rig.net());
    rig.handshake(NODE_A, &mut peer, r1);

    // A hand-framed head (the head codec only speaks ops 1/2): the
    // sink checks the generation, the tail stays opaque to P5.
    let mut body = vec![1, 2, 0, 0];
    body.extend_from_slice(&row.generation.to_be_bytes());
    body.extend_from_slice(&3_u64.to_be_bytes());
    body.extend_from_slice(&[0x5A; 12]);
    let events = rig.send_up(NODE_A, CarrierKind::Envelope, &peer.seal(6, &body));
    assert!(
        events
            .iter()
            .any(|(_, f)| f.contains("\"kind\":\"authority.passthrough\"")
                && f.contains("\"env_type\":6")),
        "passthrough diagnosed: {events:?}"
    );
    assert!(rig.recv_downs().is_empty(), "no faked ACK");
}

/// An unknown device completes no handshake: the directory fence holds
/// on the live wire, not just in channel unit tests. It gets the
/// unauthenticated R2 hint (unknown id) — never an R2-Ok, never a
/// channel.
#[test]
fn live_unknown_device_gets_no_channel() {
    let mut rig = Rig::new();
    let _ = rig.join(NODE_A, 0xA1, T0);
    // Stranger DAMS the authority never issued.
    let stranger = [0xE5; 32];
    let node = 0x00A1_0000_0000_09FF;
    let (r1, _) = FakeDevice::begin(node, stranger, 0xC001, [0x33; 16], rig.net());
    let events = rig.send_up(node, CarrierKind::R1, &r1);
    assert!(!has_kind(&events, "authority.channel_ready"));
    let downs = rig.recv_downs();
    assert_eq!(downs.len(), 1, "exactly the R2 hint");
    assert_eq!(downs[0].0, node);
    assert_eq!(downs[0].1, CarrierKind::R2);
    assert!(
        matches!(
            routeloom_keysched::rlres1::R2::decode(&downs[0].2),
            Ok(routeloom_keysched::rlres1::R2::Hint { .. })
        ),
        "a hint, not an R2-Ok"
    );
    let status = rig
        .service
        .with(|a| a.status_json(HostTime::sync(rig.now)))
        .0;
    assert!(status.contains("\"channels\":0"));
}
