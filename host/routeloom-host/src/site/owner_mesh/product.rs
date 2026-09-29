//! Features ported from LegacyFixture onto the Owner profiles (row P03 of
//! tests/e2e/scenarios.json, V2-08): the site-signed remote config of a
//! Member and explicit gateway delivery, both over the production Device
//! boot path of every peer.

use super::*;
use crate::config::{
    ConfigIssuer, ConfigLane, ConfigOutcome, ConfigRequest, ConfigStep,
    SITE_CONFIG_AUTHORITY_GENERATION,
};
use crate::send_store::{MemoryOperationStore, ISSUE_PROFILE_COSE};
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
