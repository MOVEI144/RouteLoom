//! Features ported from LegacyFixture onto the Owner profiles (row P03 of
//! tests/e2e/scenarios.json, V2-08): the site-signed remote config of a
//! Member and explicit gateway delivery, both over the production Device
//! boot path of every peer.

use super::*;
use crate::config::{
    config_dev_key, ConfigIssuer, ConfigLane, ConfigOutcome, ConfigRequest, ConfigStep,
    SITE_CONFIG_AUTHORITY_GENERATION,
};
use crate::send_store::{MemoryOperationStore, ISSUE_PROFILE_COSE};
use routeloom_protocol::host_ops::{ChannelPlanReport, ChannelPlanRequest};
use routeloom_provision::signer::FileAuthoritySigner;
use routeloom_wire::endpoint::{ConfigField, ConfigFieldType, ConfigPhase, ControlStatus};

// C++ `EndpointState` / `GatewaySendState` (gateway.hpp).
const ENDPOINT_FAILED: u8 = 4;
const GATEWAY_RECEIVED: u8 = 4;
// SDK namespace, schema 1; field 1 = diagnostics_level (u8 0..2).
const SDK_NAMESPACE: u16 = 1;
const DIAGNOSTICS_LEVEL: u16 = 1;

/// A config lane issuing as the site: COSE permits signed by `signer`
/// under kid = site_id, bound like the daemon binds them — to the low word
/// of the gateway's HelloAck network.
fn site_lane(world: &MeshWorld, signer: FileAuthoritySigner) -> ConfigLane {
    let network = world.usb_host.hello_network.expect("gateway hello") & 0xFFFF_FFFF;
    let mut issuer = ConfigIssuer::new(Vec::new(), network, testkit::SITE, 500);
    issuer.set_profile(ISSUE_PROFILE_COSE);
    issuer.set_cose_signer(signer);
    let mut counter = 0u8;
    ConfigLane::new(
        issuer,
        SITE_CONFIG_AUTHORITY_GENERATION,
        Box::new(move |out: &mut [u8]| {
            for byte in out.iter_mut() {
                counter = counter.wrapping_add(1);
                *byte = counter;
            }
        }),
    )
}

/// Drives one lane request over the gateway's real USB config endpoint
/// until it resolves.
fn config_run(
    world: &mut MeshWorld,
    lane: &mut ConfigLane,
    ledger: &mut MemoryOperationStore,
    request: ConfigRequest,
) -> ConfigOutcome {
    let mut step = lane.submit(ledger, request, world.now);
    loop {
        let (lane_request, body) = match step {
            ConfigStep::Done(outcome) => return outcome,
            ConfigStep::Emit { request, body } => (request, body),
        };
        let wire = world.usb_host.queue_data(FrameKind::HostOps, body);
        world.usb_host.watch = Some(wire);
        world.usb_host.watched = None;
        loop {
            world.step(25);
            if let Some(inner) = world.usb_host.watched.take() {
                step = lane.on_reply(ledger, lane_request, &inner, world.now);
                break;
            }
            if let Some(outcome) = lane.poll(world.now) {
                world.usb_host.watch = None;
                return outcome;
            }
        }
    }
}

/// The target's active (revision, hash) as its challenge reports them.
fn active(
    world: &mut MeshWorld,
    lane: &mut ConfigLane,
    ledger: &mut MemoryOperationStore,
) -> (u64, [u8; 32]) {
    match config_run(
        world,
        lane,
        ledger,
        ConfigRequest::Challenge {
            target: NODE_A,
            config_namespace: SDK_NAMESPACE,
            schema: 1,
        },
    ) {
        ConfigOutcome::Challenged(challenge) => (challenge.revision, challenge.active_hash),
        other => panic!("challenge answered: {other:?}"),
    }
}

fn diagnostics(level: u8) -> ConfigRequest {
    ConfigRequest::Propose {
        target: NODE_A,
        config_namespace: SDK_NAMESPACE,
        schema: 1,
        base_snapshot: Vec::new(),
        patch: vec![ConfigField {
            field_id: DIAGNOSTICS_LEVEL,
            field_type: ConfigFieldType::U8,
            value: vec![level],
        }],
        apply_budget_ms: 0,
    }
}

fn assert_no_retired_peer_nvs(world: &mut MeshWorld) {
    for peer in &mut world.peers {
        let image = peer.nvs_image();
        for retired in [b"rlcounter".as_slice(), b"rlreplay".as_slice()] {
            assert!(
                !image.windows(retired.len()).any(|window| window == retired),
                "retired peer state namespace was created"
            );
        }
    }
}

/// DevRam uses the same Device config target and gateway delivery path as a
/// Member, but verifies a permit under its development PSK-derived key.
#[test]
fn mesh_p03_devram_config_and_gateway_survive_reset() {
    let cap = format!("{}", USB_CAP | 0x18);
    let Some(mut world) = MeshWorld::start_with_args(
        "p03-devram",
        Switch::direct(),
        &["--devram", "--cap", &cap],
        &["--devram", "--remote-config"],
    ) else {
        return;
    };
    world.pump_until(800, |snaps| {
        snaps.iter().all(|s| s.mode == 3 && s.link_sessions > 0)
    });
    assert!(
        world
            .snaps
            .iter()
            .all(|s| s.mode == 3 && s.link_sessions > 0),
        "all peers adopted DevRam and established links: {:?}",
        world.snaps
    );
    world.pump_until(400, |_| false);
    world.peers[0].app_send(NODE_A, b"devram-ready");
    world.step(25);
    world.pump_until(800, |snaps| snaps[1].rx_count > 0);
    assert_eq!(world.snaps[1].rx_count, 1, "DevRam end session ready");
    world.peers[1].app_send(testkit::GATEWAY, b"devram-return");
    world.step(25);
    world.pump_until(800, |snaps| snaps[0].rx_count > 0);
    assert_eq!(world.snaps[0].rx_count, 1, "DevRam return route ready");

    let key = config_dev_key(&[0x42; 32]);
    let issuer = ConfigIssuer::new(key.to_vec(), u64::from(testkit::NETWORK_LOW), 1, 500);
    let mut counter = 0u8;
    let mut lane = ConfigLane::new(
        issuer,
        1,
        Box::new(move |out: &mut [u8]| {
            for byte in out.iter_mut() {
                counter = counter.wrapping_add(1);
                *byte = counter;
            }
        }),
    );
    let mut ledger = MemoryOperationStore::new([0xD3; 16]);
    let mut forged_lane = ConfigLane::new(
        ConfigIssuer::new(
            config_dev_key(&[0x43; 32]).to_vec(),
            u64::from(testkit::NETWORK_LOW),
            1,
            500,
        ),
        1,
        Box::new(|out: &mut [u8]| out.fill(0xA5)),
    );
    let forged = config_run(&mut world, &mut forged_lane, &mut ledger, diagnostics(2));
    assert!(
        !matches!(
            forged,
            ConfigOutcome::Statused(ControlStatus {
                phase: ConfigPhase::Active,
                ..
            })
        ),
        "foreign DevRam key applied: {forged:?}"
    );
    world.pump_until(200, |_| false);
    let (revision0, _) = active(&mut world, &mut lane, &mut ledger);
    assert_eq!(revision0, 0);
    let mut outcome = config_run(&mut world, &mut lane, &mut ledger, diagnostics(2));
    for _ in 0..20 {
        let ConfigOutcome::Statused(status) = &outcome else {
            break;
        };
        if status.phase == ConfigPhase::Active {
            break;
        }
        let operation_id = status.operation_id;
        world.pump_until(20, |_| false);
        outcome = config_run(
            &mut world,
            &mut lane,
            &mut ledger,
            ConfigRequest::Status {
                target: NODE_A,
                config_namespace: SDK_NAMESPACE,
                operation_id,
            },
        );
    }
    let ConfigOutcome::Statused(applied) = outcome else {
        panic!("DevRam permit: {outcome:?}")
    };
    assert_eq!(applied.phase, ConfigPhase::Active);
    assert_eq!(
        active(&mut world, &mut lane, &mut ledger),
        (applied.active_revision, applied.active_hash)
    );

    world.peers[1].gateway_send(testkit::GATEWAY, b"p03-devram");
    world.step(25);
    world.pump_until(400, |snaps| snaps[1].gw_send == GATEWAY_RECEIVED);
    assert_eq!(world.snaps[1].gw_send, GATEWAY_RECEIVED);
    world.peers[1].gateway_send(NODE_B, b"p03-wrong");
    world.step(25);
    world.pump_until(400, |snaps| snaps[1].gw_endpoint == ENDPOINT_FAILED);
    assert_eq!(world.snaps[1].gw_endpoint, ENDPOINT_FAILED);

    world.peers[1].power_cut();
    let until = world.now + 1000;
    while world.peers[1].reboots < 1 && world.now < until {
        world.step(25);
    }
    assert_eq!(world.peers[1].reboots, 1);
    world.pump_until(800, |snaps| {
        snaps.iter().all(|s| s.mode == 3 && s.link_sessions > 0)
    });
    world.peers[1].app_send(testkit::GATEWAY, b"devram-reboot");
    world.step(25);
    world.pump_until(800, |snaps| snaps[0].rx_count > 1);
    assert_eq!(
        world.snaps[0].rx_count, 2,
        "DevRam re-established end session"
    );
    assert_eq!(
        active(&mut world, &mut lane, &mut ledger),
        (applied.active_revision, applied.active_hash)
    );
    assert_no_retired_peer_nvs(&mut world);
}

/// P03 (Member remote config): a permit forged under the site's kid is
/// refused with nothing applied; the SAK-signed permit reaches Active
/// (journal readback verified), and after a power cut the member rebinds
/// to its site and reports the same revision and hash.
#[test]
fn mesh_p03_site_signed_config_applies_and_survives_reset() {
    let cap = format!("{}", USB_CAP | 0x10);
    let Some(mut world) = MeshWorld::start_with_args(
        "p03-config",
        Switch::direct(),
        &["--cap", &cap],
        &["--remote-config"],
    ) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge(&mut world, "p03 config");
    assert!(
        world
            .usb_host
            .hello_capability
            .is_some_and(|c| c & 0x10 != 0),
        "gateway advertises config_endpoint_v1"
    );
    let mut ledger = MemoryOperationStore::new([0xC3; 16]);

    let (forger, _) = routeloom_provision::signer::test_keypair(0x5F);
    let forged = FileAuthoritySigner::from_secret(testkit::SITE, &forger).expect("forger key");
    let mut forged_lane = site_lane(&world, forged);
    let forged_outcome = config_run(&mut world, &mut forged_lane, &mut ledger, diagnostics(2));
    // The target starts one expensive verification per 5 s (03-signing
    // §3.3), failures included.
    world.pump_until(200, |_| false);
    assert!(
        !matches!(
            forged_outcome,
            ConfigOutcome::Statused(ControlStatus {
                phase: ConfigPhase::Active,
                ..
            })
        ),
        "a forged permit never activates: {forged_outcome:?}"
    );

    let signer = testkit::sak()
        .config_authority_signer()
        .expect("site config signer");
    let mut lane = site_lane(&world, signer);
    let (revision0, _) = active(&mut world, &mut lane, &mut ledger);
    assert_eq!(revision0, 0, "nothing applied before the signed permit");
    let mut outcome = config_run(&mut world, &mut lane, &mut ledger, diagnostics(2));
    for _ in 0..20 {
        let ConfigOutcome::Statused(status) = &outcome else {
            break;
        };
        if status.phase == ConfigPhase::Active {
            break;
        }
        let operation_id = status.operation_id;
        world.pump_until(20, |_| false);
        outcome = config_run(
            &mut world,
            &mut lane,
            &mut ledger,
            ConfigRequest::Status {
                target: NODE_A,
                config_namespace: SDK_NAMESPACE,
                operation_id,
            },
        );
    }
    let ConfigOutcome::Statused(applied) = outcome else {
        panic!("signed permit status: {outcome:?}");
    };
    assert_eq!(
        applied.phase,
        ConfigPhase::Active,
        "signed permit applied: {applied:?}"
    );
    assert_eq!(applied.active_revision, 1, "one revision: {applied:?}");
    assert_eq!(
        active(&mut world, &mut lane, &mut ledger),
        (applied.active_revision, applied.active_hash),
        "readback matches the applied snapshot"
    );

    world.peers[1].power_cut();
    let until = world.now + 1000;
    while world.peers[1].reboots < 1 && world.now < until {
        world.step(25);
    }
    assert_eq!(world.peers[1].reboots, 1, "member respawned");
    converge(&mut world, "p03 config after reset");
    assert_eq!(
        active(&mut world, &mut lane, &mut ledger),
        (applied.active_revision, applied.active_hash),
        "the applied config survives the reset"
    );
    assert_no_retired_peer_nvs(&mut world);
}

/// P03 (explicit gateway): A resolves the site gateway and five sends
/// each complete with the gateway's receipt (GATEWAY_SDK_RAM); resolving
/// a member that holds no gateway role fails and nothing is stored there
/// or at the gateway in its place.
#[test]
fn mesh_p03_explicit_gateway_delivers_only_to_named_gateway() {
    let cap = format!("{}", USB_CAP | 0x8);
    let Some(mut world) =
        MeshWorld::start_with_args("p03-gateway", Switch::direct(), &["--cap", &cap], &[])
    else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge(&mut world, "p03 gateway");
    // The application may first request the gateway facade from an inbound
    // observer callback. Attachment must recover on the next Owner call.
    world.peers[2].app_send(NODE_A, b"attach-gateway");
    world.step(25);
    world.pump_until(400, |snaps| snaps[1].rx_count > 0);
    assert_eq!(world.snaps[1].rx_count, 1, "callback reached A");
    for round in 1..=5u32 {
        world.peers[1].gateway_send(testkit::GATEWAY, b"p03-gateway");
        world.step(25);
        world.pump_until(400, |snaps| snaps[1].gw_send == GATEWAY_RECEIVED);
        assert_eq!(
            world.snaps[1].gw_send, GATEWAY_RECEIVED,
            "send {round} received at the named gateway: A {:?}",
            world.snaps[1]
        );
        assert_eq!(world.snaps[0].gw_mailbox_stored, round, "gateway mailbox");
        assert_eq!(
            world.snaps[0].gw_sdk_ram_receipts, round,
            "gateway receipts"
        );
        assert_eq!(
            world.snaps[1].gw_receipts, round,
            "origin verified receipts"
        );
    }

    world.peers[1].gateway_send(NODE_B, b"p03-wrong");
    world.step(25);
    world.pump_until(400, |snaps| snaps[1].gw_endpoint == ENDPOINT_FAILED);
    assert_eq!(
        world.snaps[1].gw_endpoint, ENDPOINT_FAILED,
        "no gateway role at B"
    );
    assert_eq!(
        world.snaps[1].gw_send, 0,
        "nothing sent without an endpoint"
    );
    assert_eq!(world.snaps[2].gw_mailbox_stored, 0, "B stores nothing");
    assert_eq!(
        world.snaps[0].gw_mailbox_stored, 5,
        "no substitute delivery"
    );
    assert_eq!(world.snaps[1].gw_receipts, 5, "no extra receipt");
}

// --- Manual channel plan (P03 channel plan, V2-08) ---------------------------

/// C++ `ParticipantPhase::Stable`; `StatusCode::AuthenticationFailed`.
const PLAN_STABLE: u8 = 0;
const STATUS_AUTHENTICATION_FAILED: u8 = 11;
const CONFIG_OPS_DENIED: u16 = 3;

/// Plan waits step 10 ms: a TimeSync sample counts its RX queue residence
/// as clock uncertainty (bounded at 20 ms, 04 §8). Hardware drains the
/// queue every 2 ms Owner poll; 25 ms harness steps would refuse every
/// sample.
const PLAN_STEP_MS: u64 = 10;

fn plan_pump(world: &mut MeshWorld, ticks: u32, done: impl Fn(&[MeshSnap]) -> bool) {
    for _ in 0..ticks {
        world.step(PLAN_STEP_MS);
        if done(&world.snaps) {
            return;
        }
    }
}

/// Runs one queued channel-plan request through the real site lane and
/// the gateway's 0x68 handler; returns (result, detail) and the report.
fn plan_settle(world: &mut MeshWorld) -> (u16, u8, ChannelPlanReport) {
    let service = Arc::clone(&world.provision.site.service);
    for _ in 0..500 {
        world.step(PLAN_STEP_MS);
        let (done, _) = service.with(|a| {
            (!a.channel_plan.busy())
                .then(|| {
                    a.channel_plan
                        .last()
                        .zip(a.channel_plan.fresh_report(world.now).cloned())
                })
                .flatten()
        });
        if let Some(((_, result, detail), report)) = done {
            return (result, detail, report);
        }
    }
    panic!("the gateway answered no channel plan request");
}

fn plan_status(world: &mut MeshWorld) -> ChannelPlanReport {
    let service = Arc::clone(&world.provision.site.service);
    service
        .with(|a| a.channel_plan_refresh())
        .0
        .expect("status queued");
    let (result, _, report) = plan_settle(world);
    assert_eq!(result, 0, "status answered");
    report
}

/// Offers `new_channel` as the site, waits for every member's READY,
/// releases the commit and runs the switch until every node settled on
/// the new channel under `epoch`.
fn plan_switch(world: &mut MeshWorld, new_channel: u8, epoch: u32) {
    let service = Arc::clone(&world.provision.site.service);
    let before = plan_status(world);
    assert_eq!(before.cooldown_ms, 0, "no cooldown: {before:?}");
    let now = world.now;
    let started = now;
    let signed = service
        .with(|a| a.channel_plan_offer(new_channel, 30_000, now))
        .0
        .expect("plan offered");
    let (result, detail, report) = plan_settle(world);
    assert_eq!(
        (result, detail),
        (0, 0),
        "SAK-signed plan admitted: {report:?}"
    );
    assert_eq!(report.offered_plan, signed.plan_hash, "the offered plan");
    let members = (world.peers.len() - 1) as u8;
    let mut ready = report.ready;
    for _ in 0..20 {
        if ready >= members {
            break;
        }
        plan_pump(world, 100, |_| false);
        ready = plan_status(world).ready;
    }
    assert_eq!(ready, members, "every member answered READY");
    service
        .with(|a| a.channel_plan_release(world.now))
        .0
        .expect("release queued");
    let (result, _, report) = plan_settle(world);
    assert_eq!(result, 0, "commit released: {report:?}");
    assert!(report.released, "released: {report:?}");
    plan_pump(world, 10_000, |snaps| {
        snaps.iter().all(|s| {
            s.channel == new_channel
                && s.plan_epoch == epoch
                && s.plan_channel == new_channel
                && s.plan_phase == PLAN_STABLE
        })
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            (snap.channel, snap.plan_epoch, snap.plan_phase),
            (new_channel, epoch, PLAN_STABLE),
            "peer {index} switched and verified: {snap:?}"
        );
    }
    // Row P03: a switch completes within 60 s of the offer.
    assert!(
        world.now - started <= 60_000,
        "switch took {} ms",
        world.now - started
    );
}

/// A member reaches the gateway on the current channel: 20 of 20 sends
/// (row P03).
fn plan_traffic(world: &mut MeshWorld, what: &str) {
    for round in 1..=20u32 {
        let before = world.snaps[0].rx_count;
        world.peers[1].app_send(testkit::GATEWAY, what.as_bytes());
        world.step(25);
        world.pump_until(800, |snaps| snaps[0].rx_count > before);
        assert!(
            world.snaps[0].rx_count > before,
            "{what}: send {round} reached the gateway"
        );
    }
}

/// P03 (manual channel plan, issue #5): the gateway admits only plans the
/// site's SAK signed (a forged and an unsigned commit are refused and
/// nothing moves); a signed plan moves every node 6 -> 1 after the
/// members answered READY and the host released the commit. Traffic
/// flows on the new channel, a power-cut member re-adopts its site on the
/// plan channel (not the SitePackage one), and after the cooldown a second
/// plan brings the whole mesh back to 6.
#[test]
fn mesh_p03_manual_channel_plan_switches_and_returns() {
    let cap = format!("{}", USB_CAP | 0x2000);
    let Some(mut world) = MeshWorld::start_with_args(
        "p03-channel-plan",
        Switch::direct(),
        &["--cap", &cap, "--channel-plan"],
        &["--channel-plan"],
    ) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge(&mut world, "p03 channel plan");
    assert!(
        world
            .usb_host
            .hello_capability
            .is_some_and(|c| c & 0x2000 != 0),
        "gateway advertises channel_plan_v1"
    );
    plan_pump(&mut world, 1000, |snaps| {
        snaps.iter().all(|s| s.plan_phase == PLAN_STABLE)
    });
    assert!(
        world
            .snaps
            .iter()
            .all(|s| s.plan_phase == PLAN_STABLE && s.channel == 6),
        "every node runs the plan participant on channel 6"
    );
    let status = plan_status(&mut world);
    assert_eq!(
        (
            status.active_channel,
            status.active_epoch,
            status.ledger_sequence
        ),
        (6, 0, 0),
        "fresh plan authority: {status:?}"
    );

    // Forged (another key under the site's id) and unsigned commits are
    // refused at the gateway: nothing is distributed, nobody moves.
    let service = Arc::clone(&world.provision.site.service);
    let now = world.now;
    let plan = service
        .with(|a| a.channel_plan_build(1, 30_000, now))
        .0
        .expect("plan built");
    let (forger, _) = routeloom_provision::signer::test_keypair(0x5F);
    let forger =
        routeloom_provision::signer::FileRootSigner::from_secret(testkit::SITE, &forger).unwrap();
    let forged = routeloom_provision::sdkv1::channel_plan::issue(&plan, &forger).expect("forged");
    let unsigned = ChannelPlanRequest::Offer {
        blob: forged.blob.clone(),
        commit_signature: [0; 64],
    };
    let forged = ChannelPlanRequest::Offer {
        blob: forged.blob,
        commit_signature: forged.commit_signature,
    };
    for request in [forged, unsigned] {
        service
            .with(|a| a.channel_plan.queue(request))
            .0
            .expect("queued");
        let (result, detail, report) = plan_settle(&mut world);
        assert_eq!(
            (result, detail),
            (CONFIG_OPS_DENIED, STATUS_AUTHENTICATION_FAILED),
            "refused: {report:?}"
        );
        assert_eq!(report.offered_plan, [0; 32], "nothing offered");
    }
    world.pump_until(200, |_| false);
    assert!(
        world
            .snaps
            .iter()
            .all(|s| s.plan_phase == PLAN_STABLE && s.channel == 6 && s.plan_epoch == 0),
        "no node prepared a refused plan"
    );

    plan_switch(&mut world, 1, 1);
    plan_traffic(&mut world, "p03-channel-1");
    world.pump_until(2400, |_| false);
    assert!(
        world
            .snaps
            .iter()
            .all(|s| s.mode == MODE_MEMBER && s.phase == PHASE_ACTIVE && s.channel == 1),
        "the mesh stays up on channel 1"
    );

    // The stored plan owns the channel across a power cut.
    world.peers[1].power_cut();
    let until = world.now + 1000;
    while world.peers[1].reboots < 1 && world.now < until {
        world.step(25);
    }
    assert_eq!(world.peers[1].reboots, 1, "member respawned");
    converge(&mut world, "p03 channel plan after reset");
    world.pump_until(400, |snaps| snaps[1].plan_phase == PLAN_STABLE);
    assert_eq!(
        (world.snaps[1].channel, world.snaps[1].plan_epoch),
        (1, 1),
        "the member re-adopted on the plan channel"
    );
    plan_traffic(&mut world, "p03-after-reset");

    // Back to 6 once the 10 min inter-plan cooldown has passed.
    for _ in 0..(600_000 / 250) {
        world.step(250);
    }
    plan_switch(&mut world, 6, 2);
    plan_traffic(&mut world, "p03-channel-6");
}

#[test]
fn mesh_p03_observe_does_not_advertise_plan_authority() {
    let cap = format!("{}", USB_CAP | 0x2000);
    let Some(mut world) = MeshWorld::start_with_args(
        "p03-channel-observe",
        Switch::direct(),
        &["--cap", &cap, "--channel-plan-observe"],
        &[],
    ) else {
        return;
    };
    converge(&mut world, "p03 channel observe");
    assert_eq!(
        world.usb_host.hello_capability.unwrap_or(0) & 0x2000,
        0,
        "Observe cannot issue a manual plan"
    );
}

/// The channel plan is MemberEdhoc only: DevRam has no Site Authority to
/// sign a plan, so a DevRam node asking for one refuses to boot instead of
/// silently running without it.
#[test]
fn mesh_p03_devram_refuses_channel_plan() {
    let Some(path) = mesh_peer_path() else {
        return;
    };
    for mode in ["--channel-plan", "--channel-plan-observe"] {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-owner-mesh-devram-plan-{}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let output = Command::new(&path)
            .args(["--node", &format!("{NODE_A:#x}"), "--mac", &hex(&MAC_A)])
            .args(["--role", &format!("{ROLE_ENDPOINT}")])
            .args(["--t0", "1000", "--seed", "7", "--member", "--channel", "6"])
            .args(["--netlow", &format!("{:#x}", testkit::NETWORK_LOW)])
            .args(["--devram", mode])
            .arg("--nvs-save")
            .arg(dir.join("nvs.bin"))
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn DevRam channel-plan peer");
        let _ = std::fs::remove_dir_all(&dir);
        assert!(
            !output.status.success(),
            "{mode}: DevRam booted with a plan"
        );
        assert!(output.stdout.len() >= 3, "{mode}: missing fatal frame");
        let length = usize::from(u16::from_le_bytes([output.stdout[0], output.stdout[1]]));
        assert_eq!(
            output.stdout.len(),
            length + 2,
            "{mode}: only one fatal frame"
        );
        assert_eq!(output.stdout[2], b'E', "{mode}: fatal frame tag");
        assert_eq!(&output.stdout[3..], b"CHANNEL_PLAN_MEMBER_ONLY", "{mode}");
    }
}
