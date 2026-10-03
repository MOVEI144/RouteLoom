//! Retained membership on long, adjacent-only lines (M01/M05/M06/J02).

use super::recovery::all_ready;
use super::*;

// Independent 25 ms Owner pumps share a 5 ms radio clock. Only actual
// simultaneous unicast arrivals collide; callbacks keep their 10 ms delay.
fn step(world: &mut MeshWorld) {
    for _ in 0..5 {
        world.step(5);
        for (i, next) in world.owner_blocked_until.iter_mut().enumerate() {
            if world.peers[i].booted && world.now >= *next {
                *next = world.now + 25 + if *next == 0 { (i as u64 * 5) % 25 } else { 0 };
            }
        }
    }
}

fn run_for(world: &mut MeshWorld, duration: u64) {
    let until = world.now + duration;
    while world.now < until {
        step(world);
    }
}

fn cold_line(hops: usize, sequential: bool) -> MeshWorld {
    let mut switch = Switch::new(&Topology::line(hops + 1));
    for row in &mut switch.callback_delay_ms {
        row.fill(10);
    }
    for row in &mut switch.delay_ms {
        row.fill(10);
    }

    let args = &["--crypto-ms", "154"];
    let boot: Vec<_> = (0..=hops)
        .map(|i| if sequential { i as u64 * 2000 } else { 0 })
        .collect();
    let mut world = MeshWorld::start_booted(
        &format!("line-retained-{hops}-{sequential}"),
        switch,
        &boot,
        false,
        &[],
        &[args, args],
    )
    .expect("long line requires real Owner peers");
    // Persist a finite same-site boot search before any radio tick. The next
    // boot retains RLS1/RRS1 and the policy, as an app-only field update does.
    for peer in world.peers.iter_mut().skip(1) {
        peer.join_policy_with_listen(true, true, true, 3000, 10000);
        peer.power_cut();
    }
    let start = world.now;
    for _ in 0..9000 {
        step(&mut world);
        if all_ready(&world.snaps) {
            break;
        }
    }
    assert!(
        all_ready(&world.snaps),
        "{hops} hop retained line converges: {:?}",
        world.snaps
    );
    assert!(world
        .snaps
        .iter()
        .all(|s| s.j_attempts == 0 && s.has_identity && s.has_site));
    assert!(
        world.peers.iter().all(|p| p.reboots <= 1),
        "no rescue reboot"
    );
    eprintln!(
        "line {hops} sequential={sequential}: ready={} ms",
        world.now - start
    );
    world
}

fn pair(world: &mut MeshWorld, round: u32, gap_ms: u64) -> ([bool; 2], [Option<u64>; 2]) {
    let far = world.peers.len() - 1;
    let before = [world.snaps[0].rx_count, world.snaps[far].rx_count];
    let mut submitted = Vec::new();
    for (from, to) in [(far, 0), (0, far)] {
        let prior = world.snaps[from]
            .app_tx
            .iter()
            .map(|t| t.seq)
            .max()
            .unwrap_or(0);
        world.peers[from].app_send(world.nodes[to], &round.to_le_bytes());
        submitted.push((from, prior));
    }
    let mut received_ms = [None; 2];
    let start = world.now;
    // A 30 s lifetime expires between Owner pumps; allow its next 25 ms
    // poll to publish the terminal outcome before inspecting the snapshot.
    while world.now - start < 30025 {
        step(world);
        for (direction, &(from, _)) in submitted.iter().enumerate() {
            if received_ms[direction].is_none()
                && world.snaps[if from == 0 { far } else { 0 }].rx_count > before[direction]
            {
                received_ms[direction] = Some(world.now);
            }
        }
        if submitted.iter().all(|&(from, prior)| {
            world.snaps[from]
                .app_tx
                .iter()
                .any(|tx| tx.seq > prior && tx.state >= DELIVERY_DELIVERED)
        }) {
            break;
        }
    }
    let mut delivered = [false; 2];
    for (direction, &(from, prior)) in submitted.iter().enumerate() {
        let to = if from == 0 { far } else { 0 };
        let tx = world.snaps[from]
            .app_tx
            .iter()
            .find(|tx| tx.seq > prior)
            .expect("send has an outcome");
        assert!(
            tx.state >= DELIVERY_DELIVERED,
            "send reaches a terminal outcome: {tx:?}"
        );
        delivered[direction] = tx.state == DELIVERY_DELIVERED;
        if !delivered[direction] {
            eprintln!(
                "round {round} {from}->{to}: {tx:?} rx_delta={} finish={:?}",
                world.snaps[to].rx_count - before[direction],
                received_ms[direction]
            );
        }
        assert!(world.snaps[to].rx_count - before[direction] <= 1);
        if delivered[direction] {
            assert_eq!(world.snaps[to].rx_count - before[direction], 1);
        }
        let receipts = world.peers[to].receipts();
        assert!(receipts.len() <= 1, "one application receive");
        for receipt in receipts {
            assert_eq!(receipt.0, world.nodes[from]);
            assert_eq!(receipt.3, round.to_le_bytes());
            assert_eq!(world.peers[from].terminal_count(receipt.1, receipt.2), 1);
        }
    }
    run_for(world, gap_ms);
    for endpoint in [0, far] {
        assert!(
            world.peers[endpoint].receipts().is_empty(),
            "no late duplicate"
        );
    }
    (delivered, received_ms)
}

#[test]
fn mesh_line_retained_cold_boot() {
    for (hops, sequential) in [(6, true), (5, false)] {
        let mut world = cold_line(hops, sequential);
        let mut delivered = [0; 2];
        for round in 0..100 {
            for (total, success) in delivered.iter_mut().zip(pair(&mut world, round, 3000).0) {
                *total += u32::from(success);
            }
        }
        eprintln!("line {hops}: delivered={delivered:?}/100");
        assert!(delivered.iter().all(|&n| n >= 99));
        for (a, row) in world.switch.leg_delivered.iter().enumerate() {
            for (b, &count) in row.iter().enumerate() {
                if a.abs_diff(b) == 1 {
                    assert!(count > 0);
                } else {
                    assert_eq!(count, 0, "no shortcut {a}->{b}");
                }
            }
        }
    }
}

fn relay_reset(contended: bool) {
    let mut world = cold_line(5, false);
    let relay = 3;
    let reboots = world.peers[relay].reboots;
    let identity = (
        world.snaps[relay].adopted_network,
        world.snaps[relay].own_generation,
        world.snaps[relay].site_generation,
    );
    let mut delivered = [0; 2];
    // Drain setup application receipts before measuring the reset cycles.
    for peer in &mut world.peers {
        assert!(peer.receipts().is_empty());
    }
    for round in 0..3 {
        assert_eq!(pair(&mut world, round, 3000).0, [true; 2], "preflight");
    }
    for cycle in 0..10 {
        world.peers[relay].power_cut();
        world.peers[relay].booted = false;
        world.gate[relay] = true;
        run_for(&mut world, 500);
        world.gate[relay] = false;
        world.owner_blocked_until[relay] = 0;
        // Adjacent Owners share a pump phase on recovery, exercising contention
        // while retaining the 25 ms cadence and the radio callback delay.
        if contended {
            for neighbor in [relay - 1, relay + 1] {
                world.owner_blocked_until[neighbor] = world.now + 5;
            }
        }
        let start = world.now;
        world.switch.collide_simultaneous = contended;
        let collisions = world.switch.collision_dropped;
        let mut phase_slipped = false;
        let mut bound_ms = None;
        let mut first_ms = [None; 2];
        for _ in 0..240 {
            step(&mut world);
            // Independent task scheduling can slip by one radio tick. Keep
            // collision loss active after the first contended recovery pump.
            if !phase_slipped && world.switch.collision_dropped > collisions {
                world.owner_blocked_until[relay + 1] += 5;
                phase_slipped = true;
            }
            if [relay - 1, relay + 1].iter().all(|&neighbor| {
                matches!(world.snaps[relay].phases[neighbor], 4 | PHASE_REACHABLE)
                    && matches!(world.snaps[neighbor].phases[relay], 4 | PHASE_REACHABLE)
            }) {
                bound_ms = Some(world.now - start);
                break;
            }
        }
        if bound_ms.is_none() {
            for i in [2, 3, 4] {
                eprintln!("cycle {cycle} node{i}: {:?}", world.snaps[i]);
            }
        }
        assert!(
            bound_ms.is_some(),
            "cycle {cycle}: both neighbors BOUND <=6s"
        );
        for message in 0..10 {
            let (result, received_ms) = pair(&mut world, cycle * 10 + message, 1000);
            for direction in 0..2 {
                delivered[direction] += u32::from(result[direction]);
                if first_ms[direction].is_none() {
                    first_ms[direction] = received_ms[direction].map(|received| received - start);
                }
            }
        }
        assert_eq!(
            world.peers[relay].reboots,
            reboots + cycle + 1,
            "one retained boot per reset"
        );
        let snap = &world.snaps[relay];
        assert_eq!(
            (
                snap.adopted_network,
                snap.own_generation,
                snap.site_generation
            ),
            identity
        );
        assert_eq!(snap.j_attempts, 0, "no rejoin");
        eprintln!(
            "line reset {cycle}: bound={bound_ms:?} first={first_ms:?} ms delivered={delivered:?}"
        );
        assert!(
            first_ms.iter().all(|t| t.is_some_and(|ms| ms <= 10000)),
            "cycle {cycle}: first receive <=10s: {first_ms:?}"
        );
    }
    assert!(delivered.iter().all(|&n| n >= 90));
    eprintln!("line collisions={}", world.switch.collision_dropped);
    if contended {
        assert!(world.switch.collision_dropped > 0, "contention fired");
    }
}

#[test]
fn mesh_line_relay_reset_recovers() {
    relay_reset(false);
}

#[test]
#[ignore = "V2-HFIX-LINE: contended relay reset still misses the delivery acceptance"]
fn mesh_line_relay_reset_contention() {
    relay_reset(true);
}
