use super::super::recovery::all_ready;
use super::*;

fn next_hops(world: &mut MeshWorld, source: usize) -> Vec<u64> {
    // Issue all read-only route queries before waiting on the peers.
    for (index, peer) in world.peers.iter_mut().enumerate() {
        let destination = if index == 0 {
            world.nodes[source]
        } else {
            testkit::GATEWAY
        };
        let mut command = [b'v'; 9];
        command[1..].copy_from_slice(&destination.to_le_bytes());
        peer.send(&command);
    }
    world
        .peers
        .iter_mut()
        .map(|peer| {
            let reply = peer.recv().expect("route selection");
            assert_eq!(reply[0], b'v');
            assert_eq!(reply.len(), 9);
            u64::from_le_bytes(reply[1..].try_into().unwrap())
        })
        .collect()
}

fn control_load(
    world: &mut MeshWorld,
    object_bytes: Option<usize>,
    blocked_foreground: bool,
    target_controls: usize,
    source: usize,
    target_objects: u32,
) -> (u64, u32, usize) {
    let start = world.now;
    let hops = next_hops(world, source);
    let timeouts: Vec<_> = world
        .snaps
        .iter()
        .map(|snap| (snap.end_failed, snap.hop_accept_expired))
        .collect();
    let data = vec![0x61; object_bytes.unwrap_or(1)];
    let mut objects = 0;
    let mut successes = 0;
    let mut object_pending = false;
    let mut control_pending = None;
    let mut next_control = start;
    let mut latency = Vec::new();
    loop {
        if let Some(bytes) = object_bytes {
            if object_pending {
                let (_, results, state, _) = world.peers[source].object_snapshot();
                if results != 0 {
                    assert_eq!(results, 1);
                    objects += 1;
                    if state != 1 {
                        eprintln!(
                            "object {objects} failed state={state} at {} ms",
                            world.now - start
                        );
                    }
                    successes += u32::from(state == 1);
                    if blocked_foreground {
                        assert!(
                            objects - successes <= 1,
                            "object stalled behind blocked foreground"
                        );
                    }
                    if state == 1 {
                        let (received, _, _, payload) = world.peers[0].object_snapshot();
                        assert_eq!(received, successes, "one callback per object result");
                        assert_eq!(payload, data);
                    }
                    object_pending = false;
                }
            }
            if !object_pending && objects < target_objects {
                assert_eq!(
                    world.peers[source].object_send(testkit::GATEWAY, &data[..bytes], 30000),
                    0
                );
                object_pending = true;
            }
        }
        if control_pending.is_none() && world.now >= next_control {
            assert!(
                world.now - next_control <= 5,
                "1 Hz control submission stalled"
            );
            let last = world.snaps[0]
                .app_tx
                .iter()
                .map(|tx| tx.seq)
                .max()
                .unwrap_or(0);
            world.peers[0].app_send(world.nodes[source], b"control");
            if blocked_foreground && (next_control - start) % 30000 == 0 {
                // An accepted Reliable send to an absent destination has no
                // frame ready to transmit during its route/retry wait.
                world.peers[source].app_send(0xffff, b"waiting for route");
            }
            control_pending = Some((world.now, world.snaps[source].rx_count, last));
            next_control += 1000;
        }
        world.step(5);
        assert_eq!(next_hops(world, source), hops, "route flap");
        world.usb_host.object_frames.clear();
        if let Some((sent, received, last)) = control_pending {
            if world.snaps[source].rx_count == received + 1
                && world.snaps[0]
                    .app_tx
                    .iter()
                    .any(|tx| tx.seq > last && tx.state == DELIVERY_DELIVERED)
            {
                latency.push(world.now - sent);
                control_pending = None;
            } else {
                assert!(world.now - sent < 5000, "1 Hz control timeout");
            }
        }
        let done = if object_bytes.is_some() {
            objects == target_objects
        } else {
            latency.len() >= target_controls
        };
        if done && control_pending.is_none() {
            break;
        }
        assert!(world.now - start < 3_000_000, "bounded load campaign");
    }
    assert_eq!(
        world
            .snaps
            .iter()
            .enumerate()
            .map(|(index, snap)| {
                // Only the injected route wait may expire; controls originate at G.
                let end_failed = if blocked_foreground && index == source {
                    timeouts[index].0
                } else {
                    snap.end_failed
                };
                (end_failed, snap.hop_accept_expired)
            })
            .collect::<Vec<_>>(),
        timeouts,
        "no additional receipt or HOP_ACCEPT timeouts"
    );
    if object_bytes.is_some() {
        assert_eq!(
            world.peers[0].object_snapshot().0,
            successes,
            "exactly one callback per delivered object"
        );
        assert!(
            u64::from(successes) * 100 >= u64::from(target_objects) * 99,
            "continuous objects: {successes}/{target_objects} delivered"
        );
    }
    eprintln!(
        "load duration={} ms, control samples={}",
        world.now - start,
        latency.len()
    );
    latency.sort_unstable();
    (
        latency[(latency.len() * 99).div_ceil(100) - 1],
        successes,
        latency.len(),
    )
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON real Owner mesh peer"]
fn mesh_m10_immediate_objects_with_1hz_control() {
    for (two_hop, bytes) in [(true, 2048), (false, 2048), (false, 4096)] {
        let mut p99 = Vec::new();
        let mut control_samples = 100;
        // Use the same number of periodic controls in both campaigns.
        for with_object in [true, false] {
            let switch = if two_hop {
                Switch::forced_multihop()
            } else {
                Switch::direct()
            };
            let mut world = mesh::route_loss_world("m10-immediate", switch, two_hop)
                .expect("M10 requires real Owner peers");
            assert_eq!(world.peers[0].object_buffer(), 0);
            // Model a 10 ms LR frame/driver turn independently of the 5 ms
            // Owner clock. Warm the RTT estimator under the same delays.
            for row in &mut world.switch.delay_ms {
                row.fill(10);
            }
            for row in &mut world.switch.callback_delay_ms {
                row.fill(10);
            }
            for _ in 0..30 {
                mesh::deliver_each(&mut world, 1, 0, 1, b"warm");
                for _ in 0..200 {
                    world.step(5);
                }
            }
            let (latency, delivered, samples) = control_load(
                &mut world,
                with_object.then_some(bytes),
                false,
                control_samples,
                1,
                100,
            );
            control_samples = samples;
            eprintln!(
                "M10 immediate: hops={} bytes={bytes} objects={delivered} p99={latency} ms",
                if two_hop { 2 } else { 1 }
            );
            p99.push(latency);
        }
        assert!(
            p99[0] * 100 <= p99[1] * 120,
            "control p99 increase exceeds 20%: two_hop={two_hop} bytes={bytes} p99={p99:?}"
        );
    }
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON real Owner mesh peer"]
fn mesh_m10_objects_progress_while_foreground_waits_for_route() {
    let mut p99 = Vec::new();
    let mut control_samples = 100;
    // Match baseline exposure to the object campaign, including periodic
    // route/crypto maintenance and the injected 30-second route waits.
    for with_object in [true, false] {
        let worker = ["--crypto-ms", "154"];
        let mut world = MeshWorld::start_booted(
            "m10-blocked-foreground",
            Switch::forced_multihop(),
            &staggered_boot(3),
            true,
            &[],
            &[&worker, &worker],
        )
        .expect("M10 requires real Owner peers");
        world.gate[1] = true;
        world.pump_until(9000, |snaps| {
            snaps[0].authority_ready && snaps[2].authority_ready && snaps[2].join_confirmed
        });
        assert!(world.snaps[2].authority_ready, "relay reached gateway");
        world.gate[1] = false;
        world.pump_until(9000, all_ready);
        assert!(all_ready(&world.snaps), "worker-enabled mesh converged");
        assert!(world
            .snaps
            .iter()
            .all(|snap| snap.crypto_submitted > 0 && snap.crypto_completed > 0));
        assert_eq!(world.peers[0].object_buffer(), 0);
        for row in &mut world.switch.delay_ms {
            row.fill(10);
        }
        for row in &mut world.switch.callback_delay_ms {
            row.fill(10);
        }
        for _ in 0..30 {
            mesh::deliver_each(&mut world, 1, 0, 1, b"warm");
            for _ in 0..200 {
                world.step(5);
            }
        }

        let (latency, delivered, samples) = control_load(
            &mut world,
            with_object.then_some(2048),
            true,
            control_samples,
            1,
            100,
        );
        control_samples = samples;
        assert!(
            world.snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.reason == "NO_ROUTE"),
            "route wait exercised"
        );
        eprintln!("M10 blocked foreground: objects={delivered} control p99={latency} ms");
        p99.push(latency);
    }
    assert!(
        p99[0] * 100 <= p99[1] * 120,
        "control p99 increase exceeds 20%: {p99:?}"
    );
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON real Owner mesh peer"]
fn mesh_h7r3_thirty_three_hop_objects_with_1hz_control() {
    let worker = ["--crypto-ms", "154"];
    let mut world = MeshWorld::start_with_args(
        "h7r3-three-hop-object",
        Switch::new(&Topology::line(4)),
        &worker,
        &worker,
    )
    .expect("H7R3 requires real Owner peers");
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps), "three-hop mesh ready");
    assert!(world
        .snaps
        .iter()
        .all(|snap| snap.crypto_submitted > 0 && snap.crypto_completed > 0));
    assert_eq!(world.peers[0].object_buffer(), 0);
    for row in &mut world.switch.delay_ms {
        row.fill(10);
    }
    for row in &mut world.switch.callback_delay_ms {
        row.fill(10);
    }
    let (baseline, _, baseline_controls) = control_load(&mut world, None, false, 20, 3, 30);
    assert_eq!(baseline_controls, 20);
    let (loaded, objects, loaded_controls) = control_load(&mut world, Some(2048), false, 20, 3, 30);
    eprintln!("H7R3 three hop: objects={objects}/30 control={loaded_controls}/{loaded_controls} p99={baseline}->{loaded} ms");
    assert_eq!(objects, 30);
    assert!(
        loaded * 100 <= baseline * 120,
        "control p99 increase exceeds 20%"
    );
}
