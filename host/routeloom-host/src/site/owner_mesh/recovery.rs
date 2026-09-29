//! Recovery rows: rerouting, resets, simultaneous power loss, long
//! isolation and missed group keys, all healed without a rescue reset
//! (tests/e2e/scenarios.json M02, M04, M05, M06, J08).

use super::join::rotate_direct;
use super::mesh::{converge_outward, deliver_each};
use super::*;
use routeloom_client::site::SiteAdmin;

const STEP_MS: u64 = 25;

fn run_for(world: &mut MeshWorld, ms: u64) {
    for _ in 0..ms / STEP_MS {
        world.step(STEP_MS);
    }
}

/// `(phase, unknown)` of the host GK status.
fn gk_phase(world: &MeshWorld) -> (String, u32) {
    let status = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status");
    (status.phase, status.unknown)
}

/// The steady tail after a recovery: 15 min virtual with a Reliable
/// message every 9 s, alternating A→G and G→A (50 each). Every one
/// arrives exactly once, A stays a Member and neither end of the A—B
/// leg goes stale (no re-isolation, no rescue), and the host never
/// reports an unknown GK target again.
fn steady_tail(world: &mut MeshWorld, what: &str) {
    let a = world.index_of(NODE_A);
    let b = world.index_of(NODE_B);
    let (base_g, base_a) = (world.snaps[0].rx_count, world.snaps[a].rx_count);
    for message in 0..100u32 {
        let (from, to) = if message % 2 == 0 { (a, 0) } else { (0, a) };
        let payload = [what.as_bytes(), &message.to_le_bytes()].concat();
        world.peers[from].app_send(world.nodes[to], &payload);
        for _ in 0..9_000 / STEP_MS {
            world.step(STEP_MS);
            let (sa, sb) = (&world.snaps[a], &world.snaps[b]);
            assert!(
                sa.mode == MODE_MEMBER
                    && sa.phases[b] != PHASE_STALE
                    && sb.phases[a] != PHASE_STALE,
                "{what}: A stays attached through the tail (message {message}): {sa:?}"
            );
        }
        let (phase, unknown) = gk_phase(world);
        assert!(
            phase == "stable" && unknown == 0,
            "{what}: no unknown GK target in the tail: {phase} {unknown}"
        );
    }
    assert_eq!(world.snaps[0].rx_count, base_g + 50, "{what}: A→G 50/50");
    assert_eq!(world.snaps[a].rx_count, base_a + 50, "{what}: G→A 50/50");
}

/// Steps until `done` holds (checked once per virtual second) or
/// `budget_ms` passes; returns the elapsed virtual ms.
fn wait_until(world: &mut MeshWorld, budget_ms: u64, done: impl Fn(&MeshWorld) -> bool) -> u64 {
    let start = world.now;
    while world.now - start < budget_ms && !done(world) {
        run_for(world, 1_000);
    }
    world.now - start
}

/// Waits (at most `budget_ms`) for A's route leg to B to be reachable on
/// both ends; returns the elapsed virtual ms.
fn wait_route(world: &mut MeshWorld, budget_ms: u64) -> u64 {
    let (a, b) = (world.index_of(NODE_A), world.index_of(NODE_B));
    let start = world.now;
    world.pump_until((budget_ms / STEP_MS) as u32, |snaps| {
        snaps[a].mode == MODE_MEMBER
            && snaps[a].phases[b] == PHASE_REACHABLE
            && snaps[b].phases[a] == PHASE_REACHABLE
    });
    world.now - start
}

/// M04 (K1a): A on forced G—B—A is radio-isolated for 15 min virtual —
/// long enough that its quiet-authority probes tear the member engine
/// down into the retained-site refresh — then healed with no reboot,
/// re-provision or forced bind. Within 60 s the link and route are back
/// and 10 messages cross each way; the 15 min tail stays clean.
#[test]
fn mesh_m04_long_isolation_recovers_without_reset() {
    let Some(mut world) = MeshWorld::start("m04-k1a", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "m04");
    deliver_each(&mut world, 1, 0, 1, b"m04-before");
    world.switch.isolate(1);
    run_for(&mut world, 15 * 60_000);
    assert_eq!(
        world.snaps[1].mode, MODE_ZERO_TOUCH,
        "the heal lands inside A's retained-site refresh"
    );
    world.switch.heal(1);
    let took = wait_route(&mut world, 60_000);
    assert!(
        world.snaps[1].phases[2] == PHASE_REACHABLE && world.snaps[2].phases[1] == PHASE_REACHABLE,
        "A—B route back within 60 s of the heal (took {took} ms): {:?}",
        world.snaps[1]
    );
    deliver_each(&mut world, 1, 0, 10, b"m04-up");
    deliver_each(&mut world, 0, 1, 10, b"m04-down");
    steady_tail(&mut world, "m04");
}

/// J08 (K1a/K1b, isolation variant): A is isolated for 10 min virtual
/// while G and B rotate to g+2 and the old key's overlap expires. A's
/// refresh abandons while it is out of range; after the heal it
/// re-verifies at once (no cooldown for a refresh that never heard its
/// site), reaches g+2 and relinks within 120 s, and the host holds
/// durable active ACKs from every member (stable) for the 15 min tail.
#[test]
fn mesh_j08_k1b_isolated_miss_recovers() {
    let Some(mut world) = MeshWorld::start("j08-k1b-iso", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "j08 isolation");
    let gk0 = world.active_gk();
    world.switch.isolate(1);
    let gk1 = rotate_direct(&mut world, gk0, "j08-gk-1").expect("rotate commits");
    run_for(&mut world, 3 * 60_000);
    assert_eq!(world.snaps[0].gk_current, gk1, "gateway at g+1");
    let gk2 = rotate_direct(&mut world, gk1, "j08-gk-2").expect("rotate 2 commits");
    run_for(&mut world, 7 * 60_000);
    assert_eq!(world.snaps[0].gk_current, gk2, "gateway at g+2");
    assert_eq!(world.snaps[1].gk_current, gk0, "A missed both rotations");
    assert_eq!(world.snaps[1].mode, MODE_MEMBER, "A's refresh abandoned");
    assert_eq!(gk_phase(&world), ("catching_up".into(), 1));
    world.switch.heal(1);
    let took = wait_until(&mut world, 120_000, |world| {
        let a = &world.snaps[1];
        a.gk_current == gk2
            && a.phases[2] == PHASE_REACHABLE
            && world.snaps[2].phases[1] == PHASE_REACHABLE
            && gk_phase(world) == ("stable".into(), 0)
    });
    assert!(
        world.snaps[1].gk_current == gk2 && world.snaps[1].phases[2] == PHASE_REACHABLE,
        "A at g+2 and relinked (took {took} ms): {:?}",
        world.snaps[1]
    );
    assert_eq!(
        gk_phase(&world),
        ("stable".into(), 0),
        "durable ACKs from all"
    );
    deliver_each(&mut world, 1, 0, 10, b"j08-up");
    deliver_each(&mut world, 0, 1, 10, b"j08-down");
    steady_tail(&mut world, "j08-iso");
}

/// J08-K1b (answer-loss variant): the route stays up, but every GK
/// envelope to A (the rotation's Updates and the answers to its pulls)
/// is dropped until the host's resend round is spent. A is honestly
/// unknown then; once the envelopes flow again it converges within
/// 120 s, and the host keeps its active evidence through the tail.
#[test]
fn mesh_j08_k1b_pull_answers_dropped() {
    let Some(mut world) = MeshWorld::start("j08-k1b-drop", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "j08 answer loss");
    let gk0 = world.active_gk();
    world.usb_host.drop_envelopes_to = Some(NODE_A);
    let gk1 = rotate_direct(&mut world, gk0, "j08-drop-gk-1").expect("rotate commits");
    // Staging deadline (60 s), then the resend round of the catch-up.
    run_for(&mut world, 90_000);
    assert!(
        world.usb_host.envelopes_dropped >= 4,
        "the resend round was spent"
    );
    assert_eq!(world.snaps[1].gk_current, gk0, "A never got g+1");
    assert_eq!(
        gk_phase(&world),
        ("catching_up".into(), 1),
        "A honestly unknown"
    );
    assert_eq!(
        world.snaps[1].phases[2], PHASE_REACHABLE,
        "the route stayed up"
    );
    world.usb_host.drop_envelopes_to = None;
    let took = wait_until(&mut world, 120_000, |world| {
        world.snaps[1].gk_current == gk1 && gk_phase(world) == ("stable".into(), 0)
    });
    assert_eq!(world.snaps[1].gk_current, gk1, "A at g+1 (took {took} ms)");
    assert_eq!(
        gk_phase(&world),
        ("stable".into(), 0),
        "durable ACKs from all"
    );
    steady_tail(&mut world, "j08-drop");
}

/// Every peer a Member, Active, channel-ready and confirmed.
fn all_ready(snaps: &[MeshSnap]) -> bool {
    snaps.iter().all(|s| {
        s.mode == MODE_MEMBER && s.phase == PHASE_ACTIVE && s.authority_ready && s.join_confirmed
    })
}

/// M05: the four diamond members (G, R1, R2, E; one and two hops) lose
/// power on the same tick and boot together with no offset. All are
/// back with channels ready within 60 s, each booted exactly once (no
/// reboot loop), and 10 messages each way between E and G arrive once.
///
#[test]
fn mesh_m05_simultaneous_power_loss_recovers() {
    let Some(mut world) = MeshWorld::start("m05", Switch::new(&Topology::diamond())) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_outward(&mut world, "m05");
    let reboots: Vec<u32> = world.peers.iter().map(|peer| peer.reboots).collect();
    for peer in &mut world.peers {
        peer.power_cut();
    }
    let start = world.now;
    world.step(STEP_MS);
    world.pump_until((60_000 / STEP_MS) as u32, all_ready);
    let took = world.now - start;
    assert!(
        all_ready(&world.snaps),
        "all back within 60 s (took {took} ms): {:?}",
        world.snaps
    );
    for (index, peer) in world.peers.iter().enumerate() {
        assert_eq!(peer.reboots, reboots[index] + 1, "peer {index} booted once");
    }
    assert!(
        world.snaps.iter().all(|snap| snap.j_attempts == 0),
        "retained members did not start a new join"
    );
    deliver_each(&mut world, 3, 0, 10, b"m05-up");
    deliver_each(&mut world, 0, 3, 10, b"m05-down");
}

/// Sends one Reliable message each way between A and G every 2 s until
/// both directions delivered one sent after the call; true within
/// `budget_ms`.
fn resume_both_ways(world: &mut MeshWorld, budget_ms: u64) -> bool {
    let a = world.index_of(NODE_A);
    let (base_g, base_a) = (world.snaps[0].rx_count, world.snaps[a].rx_count);
    let start = world.now;
    while world.now - start < budget_ms {
        if (world.now - start) % 2_000 == 0 {
            world.peers[a].app_send(testkit::GATEWAY, b"m06-resume-up");
            world.peers[0].app_send(NODE_A, b"m06-resume-down");
        }
        world.step(STEP_MS);
        if world.snaps[0].rx_count > base_g && world.snaps[a].rx_count > base_a {
            return true;
        }
    }
    false
}

/// M06 (reset matrix, one reset per role): on forced G—B—A, E (A), R (B)
/// and G lose power in turn. After each reset Reliable delivery resumes
/// both ways within 15 s and 10 messages each way then arrive exactly
/// once; the node boots exactly once, and a gateway reset
/// re-authenticates the USB session within 5 s.
#[test]
fn mesh_m06_reset_matrix_resumes() {
    let Some(mut world) = MeshWorld::start("m06", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps), "converged: {:?}", world.snaps);
    for (role, index) in [("E", 1usize), ("R", 2), ("G", 0)] {
        let reboots = world.peers[index].reboots;
        let auths = world.usb_auth_total();
        world.peers[index].power_cut();
        world.step(STEP_MS);
        assert_eq!(world.peers[index].reboots, reboots + 1, "{role} rebooted");
        let start = world.now;
        if index == 0 {
            while world.usb_auth_total() <= auths && world.now - start < 5_000 {
                world.step(STEP_MS);
            }
            assert!(
                world.usb_auth_total() > auths,
                "{role}: USB re-authenticated within 5 s"
            );
        }
        let left = 15_000 - (world.now - start);
        assert!(
            resume_both_ways(&mut world, left),
            "{role}: delivery resumed both ways within 15 s: {:?}",
            world.snaps
        );
        // Recovery-window messages still in flight land or expire first.
        run_for(&mut world, 30_000);
        deliver_each(&mut world, 1, 0, 10, b"m06-up");
        deliver_each(&mut world, 0, 1, 10, b"m06-down");
        assert_eq!(
            world.peers[index].reboots,
            reboots + 1,
            "{role}: no reboot loop"
        );
    }
}

/// M02 (diamond reroute and flap): E sends one Reliable message a second
/// to G for 4 min over G—R1—E and G—R2—E; R1 drops off the air at 60 s
/// and comes back at 180 s. Delivery continues through R2 within 15 s of
/// the loss, at least 98% arrive, and none arrives twice.
#[test]
fn mesh_m02_diamond_reroute_and_flap() {
    let Some(mut world) = MeshWorld::start("m02", Switch::new(&Topology::diamond())) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    // Rerouting is under test, not the boot: attach outward from G.
    converge_outward(&mut world, "m02");
    let base = world.snaps[0].rx_count;
    let mut rerouted_ms = None;
    for second in 0..240u32 {
        if second == 60 {
            world.switch.isolate(1);
        }
        if second == 180 {
            world.switch.heal(1);
        }
        world.peers[3].app_send(testkit::GATEWAY, &second.to_le_bytes());
        let received = world.snaps[0].rx_count;
        for step in 0..1_000 / STEP_MS {
            world.step(STEP_MS);
            let rx = &world.snaps[0];
            if rerouted_ms.is_none()
                && (60..180).contains(&second)
                && rx.rx_count > received
                && rx.rx.len() == 4
                && u32::from_le_bytes([rx.rx[0], rx.rx[1], rx.rx[2], rx.rx[3]]) >= 60
            {
                rerouted_ms = Some(u64::from(second - 60) * 1_000 + (step + 1) * STEP_MS);
            }
        }
    }
    run_for(&mut world, 30_000);
    let delivered = world.snaps[0].rx_count - base;
    let rerouted_ms = rerouted_ms.expect("delivery resumed after R1 dropped");
    assert!(
        rerouted_ms <= 15_000,
        "rerouted within 15 s: {rerouted_ms} ms"
    );
    assert!(delivered <= 240, "no message twice: {delivered}");
    assert!(
        delivered * 100 >= 240 * 98,
        "at least 98% delivered: {delivered}/240"
    );
}
