//! M10: explicit AppObject through real Device, Owner, sessions and MeshNode.
use super::*;

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_app_objects() {
    for size in [1, 121, 122, 2048, 4096] {
        let mut world = mesh::route_loss_world("m10-objects", Switch::forced_multihop(), true)
            .expect("M10 requires real Owner peers");
        assert_eq!(world.peers[0].object_buffer(), 0);
        world.peers[1].app_send(testkit::GATEWAY, b"establish end session");
        world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
        assert!(world.snaps[0].rx_count > 0);
        let bytes: Vec<u8> = (0..size).map(|i| (i % 251) as u8).collect();
        let before = world.peers[0].object_snapshot().0;
        if size == 4096 {
            world.switch.watch_kind = Some(65);
            world.switch.drop_wire_kind(1, 2, 65, 1);
        }
        assert_eq!(
            world.peers[1].object_send(testkit::GATEWAY, &bytes, 30000),
            0
        );
        let started = world.now;
        let mut previous_tx = None;
        let mut watched = 0;
        loop {
            world.step(25);
            if size == 4096 {
                for (from, _, _) in &world.switch.watched[watched..] {
                    if *from == 1 {
                        if let Some(previous) = previous_tx {
                            assert!(
                                world.now - previous >= 200,
                                "object airtime includes hop retransmissions: {} ms",
                                world.now - previous
                            );
                        }
                        previous_tx = Some(world.now);
                    }
                }
                watched = world.switch.watched.len();
            }
            let (_, results, state, _) = world.peers[1].object_snapshot();
            if results != 0 {
                assert_eq!(results, 1);
                assert_eq!(state, 1, "whole-object Delivered, size={size}");
                break;
            }
            assert!(world.now - started < 30000, "M10 deadline, size={size}");
        }
        if size == 4096 {
            assert!(world
                .switch
                .watched
                .iter()
                .any(|(from, to, h)| *from == 2 && *to == 0 && h[4] == 65 && h[9] == 1));
            assert!(world
                .switch
                .watched
                .iter()
                .all(|(_, _, h)| h[4] == 65 && h[9] == 1));
        }
        let (received, _, _, data) = world.peers[0].object_snapshot();
        assert_eq!(received, before + 1);
        assert_eq!(data, bytes);
        let mut ingress = crate::objects::IngressAssembly::default();
        let mut host_objects = Vec::new();
        for _ in 0..20 {
            world.step(25);
        }
        for (_, session, body) in world.usb_host.object_frames.drain(..) {
            if body.get(1) == Some(&0x86) {
                if let Some((object, _, _)) = ingress.fragment(session, &body) {
                    host_objects.push(object.payload);
                }
            }
        }
        assert_eq!(
            host_objects,
            vec![bytes.clone()],
            "whole-object USB ingress"
        );
        world.step(1000);
        assert_eq!(world.peers[0].object_snapshot().0, received);
        assert_eq!(world.peers[1].object_send(testkit::GATEWAY, &[], 30000), 1);
        assert_eq!(
            world.peers[1].object_send(testkit::GATEWAY, &[0; 4097], 30000),
            38
        );
    }
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_object_deadline_busy_and_cancel() {
    for cancel in [false, true] {
        let mut world = mesh::route_loss_world("m10-abort", Switch::forced_multihop(), true)
            .expect("M10 requires real Owner peers");
        assert_eq!(world.peers[0].object_buffer(), 0);
        world.peers[1].app_send(testkit::GATEWAY, b"warm");
        world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
        assert!(world.snaps[0].rx_count > 0);
        assert_eq!(
            world.peers[1].object_send(testkit::GATEWAY, &[9; 4096], 2000),
            0
        );
        assert_eq!(
            world.peers[1].object_send(testkit::GATEWAY, &[8; 121], 30000),
            21
        );
        if cancel {
            assert_eq!(world.peers[1].object_cancel(), 0);
        } else {
            world.switch.isolate(1);
        }
        world.step(2200);
        let (_, results, state, _) = world.peers[1].object_snapshot();
        assert_eq!(results, 1);
        assert_eq!(state, if cancel { 3 } else { 2 });
        assert_eq!(world.peers[0].object_snapshot().0, 0);
        world.step(1000);
        assert_eq!(world.peers[1].object_snapshot().1, 1);
    }
}

#[test]
#[ignore = "requires ON source and ROUTELOOM_MESH_PEER_GW pointing at an OFF peer"]
fn mesh_p04_object_off_terminal() {
    let mut world = mesh::route_loss_world("p04-off-object", Switch::forced_multihop(), true)
        .expect("P04 requires real Owner peers");
    assert_eq!(world.peers[0].object_buffer(), 5);
    world.peers[1].app_send(testkit::GATEWAY, b"warm");
    world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
    assert!(world.snaps[0].rx_count > 0);
    assert_eq!(
        world.peers[1].object_send(testkit::GATEWAY, &[8; 122], 30000),
        0
    );
    for _ in 0..1200 {
        world.step(25);
        if world.peers[1].object_snapshot().1 != 0 {
            break;
        }
    }
    assert_eq!(world.peers[1].object_snapshot().2, 6);
    assert_eq!(world.peers[0].object_snapshot().0, 0);
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_object_reorder_duplicate_and_conflict() {
    for conflict in 0..3 {
        let mut world = mesh::route_loss_world("m10-grid", Switch::direct(), false)
            .expect("M10 requires real Owner peers");
        assert_eq!(world.peers[0].object_buffer(), 0);
        world.peers[1].app_send(testkit::GATEWAY, b"warm");
        world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
        assert!(world.snaps[0].rx_count > 0);
        let data: Vec<u8> = (0..122).collect();
        let digest = routeloom_keysched::sha256(&[&data]);
        let mut start = vec![1];
        start.extend_from_slice(&1u32.to_be_bytes());
        start.extend_from_slice(&122u16.to_be_bytes());
        start.extend_from_slice(&[2, 0, 7, 0]);
        start.extend_from_slice(&digest[..16]);
        start.extend_from_slice(&5000u32.to_be_bytes());
        let mut bodies = vec![(64, start.clone())];
        if conflict == 2 {
            start[9] ^= 1; // same transfer, conflicting app tag
            bodies.push((64, start));
        }
        for index in [1u8, 1, 0] {
            let part = if index == 1 {
                &data[121..]
            } else {
                &data[..121]
            };
            let mut chunk = vec![1];
            chunk.extend_from_slice(&1u32.to_be_bytes());
            chunk.extend_from_slice(&[index, part.len() as u8]);
            chunk.extend_from_slice(part);
            if conflict == 1 && bodies.len() == 2 {
                chunk[7] ^= 1;
            }
            bodies.push((65, chunk));
        }
        for (kind, body) in bodies {
            let frame =
                world.peers[1].craft_frame(testkit::GATEWAY, testkit::GATEWAY, kind, 0, 1, &body);
            world.peers[0].send_rx(&world.macs[1], &world.macs[0], &frame);
            world.step(400);
        }
        world.step(1000);
        let (count, _, _, received) = world.peers[0].object_snapshot();
        assert_eq!(count, u32::from(conflict == 0));
        if conflict == 0 {
            assert_eq!(received, data);
        }
    }
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_host_usb_object_upload() {
    let mut world = mesh::route_loss_world("m10-host", Switch::forced_multihop(), true)
        .expect("M10 requires real Owner peers");
    assert_eq!(world.peers[1].object_buffer(), 0);
    world.peers[1].app_send(testkit::GATEWAY, b"warm");
    world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
    assert!(world.snaps[0].rx_count > 0);
    let ops = crate::objects::ObjectOps::with_boot(17);
    let principal = routeloom_peercred::Principal::UnixUid(1);
    let data = vec![0x73; 4096];
    let network = world.usb_host.hello_network.unwrap();
    let request = crate::objects::Request {
        node: NODE_A,
        data: data.clone(),
        deadline_ms: 120000,
        app_tag: 7,
        encoding: 0,
    };
    let record = ops
        .submit(principal.clone(), network, [1; 16], request.clone())
        .unwrap();
    assert_eq!(
        ops.submit(principal.clone(), network, [1; 16], request)
            .unwrap()
            .id,
        record.id
    );
    let (sender, receiver) = mpsc::sync_channel(16);
    let started = std::time::Instant::now();
    loop {
        ops.step(world.usb_host.session.session_id, network, true, &sender);
        while let Ok(outbound) = receiver.try_recv() {
            if let crate::Outbound::Seal(frame) = outbound {
                world.usb_host.pending.push(usb_host::PendingFrame {
                    frame,
                    join_note: None,
                });
            }
        }
        world.step(25);
        for (request, session, bytes) in world.usb_host.object_frames.drain(..) {
            ops.reply(request, session, &bytes);
        }
        if ops.get(&principal, record.id).unwrap().state == "DELIVERED" {
            break;
        }
        assert!(
            started.elapsed() < std::time::Duration::from_secs(20),
            "host state {}",
            ops.get(&principal, record.id).unwrap().state
        );
        thread::sleep(std::time::Duration::from_millis(10));
    }
    assert_eq!(world.peers[1].object_snapshot().0, 1);
    assert_eq!(world.peers[1].object_snapshot().3, data);
}

#[test]
fn mesh_m10_three_hop_with_control() {
    let topology = switch::Topology::line(4);
    let mut world = MeshWorld::start_plan(
        "m10-three-hop",
        Switch::new(&topology),
        &staggered_boot(4),
        true,
    )
    .expect("M10 requires real Owner peers");
    world.pump_until(20000, |snaps| {
        snaps.iter().all(|s| s.authority_ready && s.join_confirmed)
    });
    assert!(world
        .snaps
        .iter()
        .all(|s| s.authority_ready && s.join_confirmed));
    assert_eq!(world.peers[0].object_buffer(), 0);
    world.peers[3].app_send(testkit::GATEWAY, b"warm");
    world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
    assert!(world.snaps[0].rx_count > 0);
    let data = vec![0x85; 4096];
    assert_eq!(
        world.peers[3].object_send(testkit::GATEWAY, &data, 30000),
        0
    );
    for _ in 0..10 {
        mesh::deliver_each(&mut world, 1, 0, 1, b"control");
    }
    assert_eq!(world.peers[0].object_snapshot().0, 1);
    assert_eq!(world.peers[0].object_snapshot().3, data);
    assert_eq!(world.peers[3].object_snapshot().2, 1);
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_c_object_apis() {
    let mut world = MeshWorld::start_with_args("m10-c", Switch::direct(), &[], &["--c-app"])
        .expect("M10 requires real Owner peers");
    converge_gated(&mut world, 1, "m10-c");
    assert_eq!(world.peers[0].object_buffer(), 0);
    assert_eq!(world.peers[1].object_buffer(), 0);
    world.peers[1].app_send(testkit::GATEWAY, b"warm");
    world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
    assert!(world.snaps[0].rx_count > 0);
    let data = vec![0x35; 4096];
    for (from, to) in [(1, 0), (0, 1)] {
        let destination = world.nodes[to];
        let hop_timeouts: Vec<_> = world.snaps.iter().map(|s| s.hop_accept_expired).collect();
        assert_eq!(world.peers[from].object_send(destination, &data, 30000), 0);
        for _ in 0..1200 {
            world.step(25);
            if world.peers[from].object_snapshot().1 != 0 {
                break;
            }
        }
        assert_eq!(world.peers[from].object_snapshot().2, 1);
        assert_eq!(world.peers[to].object_snapshot().0, 1);
        assert_eq!(world.peers[to].object_snapshot().3, data);
        world.step(1000);
        assert_eq!(
            world
                .snaps
                .iter()
                .map(|s| s.hop_accept_expired)
                .collect::<Vec<_>>(),
            hop_timeouts,
            "AppObject HOP_ACCEPT must resolve on every hop"
        );
    }
    assert!(world.snaps.iter().all(|s| s.c_check_failures == 0));
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_boot_revoke_and_route_repair() {
    use routeloom_client::site::{RemovalReason, SiteAdmin};
    for fault in [0, 1, 2, 3] {
        let mut world = mesh::route_loss_world("m10-lifecycle", Switch::forced_multihop(), true)
            .expect("M10 requires real Owner peers");
        assert_eq!(world.peers[0].object_buffer(), 0);
        world.peers[1].app_send(testkit::GATEWAY, b"warm");
        world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
        assert!(world.snaps[0].rx_count > 0);
        assert_eq!(
            world.peers[1].object_send(testkit::GATEWAY, &[0x61; 4096], 30000),
            0
        );
        for _ in 0..40 {
            world.step(25);
        }
        assert_eq!(world.peers[0].object_snapshot().0, 0);
        match fault {
            0 => world.peers[1].power_cut(),
            1 => world.peers[0].power_cut(),
            2 => {
                world
                    .provision
                    .site
                    .link
                    .revoke(NODE_A, 1, RemovalReason::Removed, "m10-revoke")
                    .unwrap();
            }
            3 => {
                world.switch.isolate(2);
                for _ in 0..40 {
                    world.step(25);
                }
                world.switch.heal(2);
            }
            _ => unreachable!(),
        }
        for _ in 0..1200 {
            world.step(25);
        }
        assert_eq!(world.peers[0].object_snapshot().0, u32::from(fault == 3));
        if fault == 3 {
            assert_eq!(world.peers[1].object_snapshot().2, 1);
        }
        if fault == 1 {
            let (_, results, state, _) = world.peers[1].object_snapshot();
            assert_eq!(results, 1);
            assert!(matches!(state, 2 | 5));
        }
    }
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_completion_record_pressure() {
    let mut world = mesh::route_loss_world("m10-records", Switch::direct(), false)
        .expect("M10 requires real Owner peers");
    assert_eq!(world.peers[0].object_buffer(), 0);
    world.peers[1].app_send(testkit::GATEWAY, b"warm");
    world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
    assert!(world.snaps[0].rx_count > 0);
    for index in 0..5 {
        assert_eq!(
            world.peers[1].object_send(testkit::GATEWAY, &[index], 30000),
            0
        );
        for _ in 0..400 {
            world.step(25);
            if world.peers[1].object_snapshot().1 != 0 {
                break;
            }
        }
        let (_, results, state, _) = world.peers[1].object_snapshot();
        assert_eq!(results, 1);
        assert_eq!(state, if index < 4 { 1 } else { 5 });
        for _ in 0..40 {
            world.step(25);
        }
    }
    assert_eq!(world.peers[0].object_snapshot().0, 4);
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_object_queue_pressure() {
    let mut world = mesh::route_loss_world("m10-queue", Switch::direct(), false)
        .expect("M10 requires real Owner peers");
    assert_eq!(world.peers[0].object_buffer(), 0);
    world.peers[1].app_send(testkit::GATEWAY, b"warm");
    world.pump_until(9000, |snaps| snaps[0].rx_count > 0);
    assert!(world.snaps[0].rx_count > 0);
    let (accepted, refused) = world.peers[1].object_fill_queue(testkit::GATEWAY);
    assert!(
        accepted > 0 && refused > 0,
        "bounded queue must refuse before acceptance"
    );
    let bytes = vec![0x27; 4096];
    assert_eq!(
        world.peers[1].object_send(testkit::GATEWAY, &bytes, 30000),
        0
    );
    assert_eq!(world.peers[0].object_snapshot().0, 0);
    assert_eq!(world.peers[1].object_snapshot().1, 0);
    for _ in 0..1200 {
        world.step(25);
        if world.peers[1].object_snapshot().1 != 0 {
            break;
        }
    }
    assert_eq!(world.peers[1].object_snapshot().2, 1);
    assert_eq!(world.peers[0].object_snapshot().0, 1);
    assert_eq!(world.peers[0].object_snapshot().3, bytes);
}

#[test]
#[ignore = "requires ON endpoints and an OFF relay"]
fn mesh_m10_control_p99() {
    let mut world = mesh::route_loss_world("m10-control", Switch::forced_multihop(), true)
        .expect("M10 requires real Owner peers");
    assert_eq!(world.peers[0].object_buffer(), 0);
    mesh::deliver_each(&mut world, 1, 0, 1, b"warm");
    let failed: Vec<_> = world.snaps.iter().map(|s| s.end_failed).collect();
    let mut p99 = Vec::new();
    for with_object in [false, true] {
        if with_object {
            assert_eq!(
                world.peers[1].object_send(testkit::GATEWAY, &[0x61; 4096], 30000),
                0
            );
            world.switch.drop_wire_kind(1, 2, 65, 1);
        }
        let start = world.now;
        let mut latency = Vec::new();
        for sample in 0..18u64 {
            let scheduled = start + sample * 5000;
            while world.now < scheduled {
                world.step((scheduled - world.now).min(25));
            }
            let sent = world.now;
            let received = world.snaps[0].rx_count;
            let last = world.snaps[1]
                .app_tx
                .iter()
                .map(|tx| tx.seq)
                .max()
                .unwrap_or(0);
            world.peers[1].app_send(testkit::GATEWAY, &sample.to_le_bytes());
            loop {
                world.step(25);
                if world.snaps[0].rx_count == received + 1
                    && world.snaps[1]
                        .app_tx
                        .iter()
                        .any(|tx| tx.seq > last && tx.state == DELIVERY_DELIVERED)
                {
                    break;
                }
                assert!(
                    world.now - sent < 5000,
                    "control timeout with_object={with_object}"
                );
            }
            latency.push(world.now - sent);
        }
        latency.sort_unstable();
        p99.push(*latency.last().unwrap());
        if with_object {
            assert_eq!(world.peers[1].object_snapshot().2, 1);
            assert_eq!(world.peers[0].object_snapshot().0, 1);
        }
    }
    eprintln!(
        "M10 Reliable p99: baseline={} ms, object={} ms",
        p99[0], p99[1]
    );
    assert!(
        p99[1] * 100 <= p99[0] * 120,
        "control p99 increase exceeds 20%"
    );
    assert_eq!(
        world.snaps.iter().map(|s| s.end_failed).collect::<Vec<_>>(),
        failed
    );
}

#[test]
#[ignore = "requires ROUTELOOM_APP_OBJECT_TRANSFER=ON mesh peer"]
fn mesh_m10_concurrent_usb_ingress() {
    let mut world = mesh::route_loss_world(
        "m10-rx-slots",
        Switch::new(&super::switch::Topology {
            nodes: 3,
            edges: vec![(0, 1), (0, 2)],
        }),
        false,
    )
    .expect("M10 requires real Owner peers");
    assert_eq!(world.peers[0].object_buffer(), 0);
    for from in [1, 2] {
        mesh::deliver_each(&mut world, from, 0, 1, b"warm");
    }
    // Two authenticated sources occupy the gateway's two registered loans.
    for kind in [64, 65] {
        for from in [1usize, 2] {
            let data = [from as u8];
            let mut body = vec![1];
            body.extend_from_slice(&1u32.to_be_bytes());
            if kind == 64 {
                body.extend_from_slice(&[0, 1, 1, 0, 0, 0]);
                body.extend_from_slice(&routeloom_keysched::sha256(&[&data])[..16]);
                body.extend_from_slice(&5000u32.to_be_bytes());
            } else {
                body.extend_from_slice(&[0, 1, data[0]]);
            }
            let frame = world.peers[from].craft_frame(
                testkit::GATEWAY,
                testkit::GATEWAY,
                kind,
                0,
                1,
                &body,
            );
            world.peers[0].send_rx(&world.macs[from], &world.macs[0], &frame);
        }
        world.step(25);
    }
    for _ in 0..40 {
        world.step(25);
    }
    assert_eq!(world.peers[0].object_snapshot().0, 2);
    let mut assembly = crate::objects::IngressAssembly::default();
    let mut received = Vec::new();
    for (_, session, body) in world.usb_host.object_frames.drain(..) {
        if let Some((object, _, _)) = assembly.fragment(session, &body) {
            received.push(object.payload);
        }
    }
    received.sort();
    assert_eq!(received, vec![vec![1], vec![2]]);
}
