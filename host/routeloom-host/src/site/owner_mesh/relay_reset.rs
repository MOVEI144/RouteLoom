//! M06-HC6: relay reset with a lost final authentication message.

use super::join::rotate_direct;
use super::recovery::{all_ready, run_for};
use super::send::{legacy_send, terminal_events};
use super::*;

const STEP_MS: u64 = 25;

fn bound(phase: u8) -> bool {
    phase == 4 || phase == PHASE_REACHABLE
}

fn step_bound(
    world: &mut MeshWorld,
    binds: &mut [Option<u64>; 2],
    received: &mut Vec<Vec<u8>>,
    start: u64,
) {
    let count = world.snaps[1].rx_count;
    world.step(STEP_MS);
    if world.snaps[1].rx_count != count {
        assert_eq!(world.snaps[1].rx_count, count + 1);
        let payload = world.snaps[1].rx.clone();
        assert!(
            !received.contains(&payload),
            "duplicate application delivery"
        );
        received.push(payload);
    }
    for (slot, peer) in binds.iter_mut().zip([0, 1]) {
        if slot.is_none() && bound(world.snaps[2].phases[peer]) {
            *slot = Some(world.now - start);
        }
    }
}

fn reset_relay(world: &mut MeshWorld) {
    world.peers[2].power_cut();
    world.peers[2].booted = false;
    world.gate[2] = true;
    // reset_cycles.py holds EN for 0.5 s. Only the surviving Owners tick
    // during the hold; the relay respawns from NVS after release.
    run_for(world, 500);
    world.gate[2] = false;
}

/// Normal authority rotations age the leaf's RMS, so the relay's reset
/// needs EDHOC there. Lose its first M4: chunk dedup acknowledges repeated
/// M3 without delivering it again to the engine. The original M4 must still
/// reach the relay before the six-second bind deadline, without rejoining.
#[test]
fn mesh_m06_relay_reset_lost_m4_recovers() {
    let mut world = MeshWorld::start("m06-hc6", Switch::forced_multihop())
        .expect("M06-HC6 requires live C++ Owner peers");
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps), "converged: {:?}", world.snaps);
    let mut key = 0x6c00;
    // Preflight reset followed by three actual terminal receipts, rather
    // than trusting the gateway's retained route to the leaf.
    reset_relay(&mut world);
    run_for(&mut world, 6_000);
    for _ in 0..3 {
        key += 1;
        let request = legacy_send(&mut world, key, NODE_A, b"preflight");
        run_for(&mut world, 6_000);
        assert_eq!(
            terminal_events(&world, request)
                .map(|(s, _, _)| s)
                .collect::<Vec<_>>(),
            [Some(DELIVERY_DELIVERED)],
            "preflight receipt {request}"
        );
    }
    let mut gk = world.active_gk();
    for round in 0..2 {
        gk = rotate_direct(&mut world, gk, &format!("m06-age-{round}")).expect("rotate commits");
        run_for(&mut world, 90_000);
        assert!(world.snaps.iter().all(|s| s.gk_current == gk));
    }
    world.switch.drop_link_step = Some((1, 2, 4, 4));
    let mut per_cycle = Vec::new();
    let mut delivered = 0;
    for cycle in 0..10 {
        let reboots = world.peers[2].reboots;
        let received = world.snaps[1].rx_count;
        reset_relay(&mut world);
        let start = world.now;
        let mut binds = [None; 2];
        let mut payloads = Vec::new();
        let mut got = 0;
        let mut first = None;
        // reset_cycles.py waits for each terminal outcome before its 1 s
        // send gap; these are ten sequential sends, not a concurrent burst.
        for _ in 0..10 {
            key += 1;
            let request = legacy_send(&mut world, key, NODE_A, &key.to_be_bytes());
            let submitted = world.now;
            while terminal_events(&world, request).next().is_none() && world.now - submitted < 9_000
            {
                step_bound(&mut world, &mut binds, &mut payloads, start);
            }
            let terminal: Vec<_> = terminal_events(&world, request).collect();
            assert_eq!(
                terminal.len(),
                1,
                "cycle {cycle} request {request}: {terminal:?}"
            );
            let (state, _, at) = terminal[0];
            if state == Some(DELIVERY_DELIVERED) {
                got += 1;
                first = Some(first.map_or(at - start, |t: u64| t.min(at - start)));
            } else {
                eprintln!("cycle {cycle} request {request}: terminal={terminal:?}");
            }
            for _ in 0..1_000 / STEP_MS {
                step_bound(&mut world, &mut binds, &mut payloads, start);
            }
        }
        assert_eq!(world.peers[2].reboots, reboots + 1);
        let received = world.snaps[1].rx_count - received;
        assert_eq!(received as usize, payloads.len());
        assert!(
            (got..=10).contains(&received),
            "application deliveries: {received}"
        );
        assert!(
            world.snaps.iter().all(|s| s.mode == MODE_MEMBER
                && s.stores_healthy
                && s.has_site
                && s.has_identity
                && s.own_generation == 1
                && s.gk_current == gk
                && s.j_attempts == 0),
            "retained membership after cycle {cycle}: {:?}",
            world.snaps
        );
        eprintln!("M06-HC6 cycle {cycle}: bind={binds:?} first={first:?} delivered={got}");
        per_cycle.push((binds, first, got));
        delivered += got;
        run_for(&mut world, 2_000);
    }
    eprintln!("M06-HC6 baseline 3/3, {delivered}/100, (bind ms, first receipt ms, delivered): {per_cycle:?}");
    assert_eq!(world.switch.link_steps_dropped, 1, "M4 loss fired");
    assert!(
        delivered >= 90
            && per_cycle.iter().all(|(binds, first, _)| {
                binds.iter().all(|t| t.is_some_and(|t| t <= 6_000))
                    && first.is_some_and(|t| t <= 10_000)
            }),
        "original recovery gates: {delivered}/100 {per_cycle:?}"
    );
}
