use super::*;

fn next_hops(world: &mut MeshWorld) -> Vec<u64> {
    // Issue all read-only route queries before waiting on the peers.
    for (index, peer) in world.peers.iter_mut().enumerate() {
        let destination = if index == 0 {
            world.nodes[1]
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

fn control_load(world: &mut MeshWorld, object_bytes: Option<usize>) -> (u64, u32) {
    let start = world.now;
    let hops = next_hops(world);
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
                let (_, results, state, _) = world.peers[1].object_snapshot();
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
                    if state == 1 {
                        let (received, _, _, payload) = world.peers[0].object_snapshot();
                        assert_eq!(received, successes, "one callback per object result");
                        assert_eq!(payload, data);
                    }
                    object_pending = false;
                }
            }
            if !object_pending && objects < 100 {
                assert_eq!(
                    world.peers[1].object_send(testkit::GATEWAY, &data[..bytes], 30000),
                    0
                );
                object_pending = true;
            }
        }
        if control_pending.is_none() && world.now >= next_control {
            let last = world.snaps[0]
                .app_tx
                .iter()
                .map(|tx| tx.seq)
                .max()
                .unwrap_or(0);
            world.peers[0].app_send(world.nodes[1], b"control");
            control_pending = Some((world.now, world.snaps[1].rx_count, last));
            next_control += 1000;
        }
        world.step(5);
        assert_eq!(next_hops(world), hops, "route flap");
        world.usb_host.object_frames.clear();
        if let Some((sent, received, last)) = control_pending {
            if world.snaps[1].rx_count == received + 1
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
            objects == 100
        } else {
            latency.len() >= 100
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
            .map(|snap| (snap.end_failed, snap.hop_accept_expired))
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
            successes >= 99,
            "continuous objects: {successes}/100 delivered"
        );
    }
    eprintln!(
        "load duration={} ms, control samples={}",
        world.now - start,
        latency.len()
    );
    latency.sort_unstable();
    (latency[(latency.len() * 99).div_ceil(100) - 1], successes)
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON real Owner mesh peer"]
fn mesh_m10_immediate_objects_with_1hz_control() {
    for (two_hop, bytes) in [(true, 2048), (false, 2048), (false, 4096)] {
        let mut p99 = Vec::new();
        for with_object in [false, true] {
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
            let (latency, delivered) = control_load(&mut world, with_object.then_some(bytes));
            eprintln!(
                "M10 immediate: hops={} bytes={bytes} objects={delivered} p99={latency} ms",
                if two_hop { 2 } else { 1 }
            );
            p99.push(latency);
        }
        assert!(
            p99[1] * 100 <= p99[0] * 120,
            "control p99 increase exceeds 20%: two_hop={two_hop} bytes={bytes} p99={p99:?}"
        );
    }
}
