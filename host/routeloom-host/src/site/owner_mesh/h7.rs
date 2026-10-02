//! H7 receiver pressure through the real Device/Owner and Authority.

use super::recovery::{all_ready, run_for};
use super::*;

#[test]
fn mesh_h7_seven_node_burst_with_serial_callbacks() {
    let mut world = super::mesh::route_loss_world(
        "h7-serial-ack",
        Switch::new(&Topology {
            nodes: 7,
            edges: (1..7).map(|peer| (0, peer)).collect(),
        }),
        false,
    )
    .expect("H7 requires real Owner peers");
    for row in &mut world.switch.delay_ms {
        row.fill(10);
    }
    for row in &mut world.switch.callback_delay_ms {
        row.fill(10);
    }
    let results: Vec<_> = world
        .peers
        .iter_mut()
        .skip(1)
        .map(|peer| peer.tracked_burst(16, testkit::GATEWAY))
        .collect();
    for source in &results {
        assert_eq!(source.iter().filter(|r| r.0 == 0).count(), 8);
        assert!(source.iter().all(|r| matches!(r.0, 0 | 21)));
    }
    for _ in 0..30_000 {
        world.step(1);
    }
    let received = world.peers[0].receipts();
    let keys: std::collections::BTreeSet<_> = received
        .iter()
        .map(|&(source, session, seq, _)| (source, session, seq))
        .collect();
    assert_eq!(keys.len(), received.len(), "one receive per key");
    let mut delivered = 0;
    for (peer, source) in results.iter().enumerate() {
        let mut count = 0;
        for &(_, session, seq) in source.iter().filter(|r| r.0 == 0) {
            assert_eq!(world.peers[peer + 1].terminal_count(session, seq), 1);
            let tx = world.snaps[peer + 1]
                .app_tx
                .iter()
                .find(|tx| tx.seq == seq)
                .unwrap();
            count += usize::from(tx.state == DELIVERY_DELIVERED);
            if tx.state == DELIVERY_DELIVERED {
                assert!(keys.contains(&(world.nodes[peer + 1], session, seq)));
            }
        }
        eprintln!(
            "H7 serial callbacks: source={} delivered={count}/8 hop_expired={}",
            peer + 1,
            world.snaps[peer + 1].hop_accept_expired
        );
        delivered += count;
        assert_eq!(world.snaps[peer + 1].queued, 0);
    }
    eprintln!(
        "H7 serial callbacks: received={} delivered={delivered}/48",
        received.len()
    );
    assert_eq!(delivered, 48, "each sender Reliable >=99%");
    assert_eq!(received.len(), 48);
}

#[test]
fn mesh_h7_terminal_pressure_preserves_same_round_retry() {
    let mut world =
        MeshWorld::start("h7-pressure", Switch::direct()).expect("H7 requires real Owner peers");
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps));
    super::hfinal::fill_terminal_quota(&mut world);
    run_for(&mut world, 30_000);
    let source = world.macs[1];
    let destination = world.macs[0];
    let frame = world.peers[1].craft_frame(
        testkit::GATEWAY,
        testkit::GATEWAY,
        WIRE_DATA,
        0,
        0,
        b"pressure-retry",
    );
    world.peers[0].send_rx(&source, &destination, &frame);
    world.step(1);
    assert!(
        world.peers[0].receipts().is_empty(),
        "full terminal quota refuses"
    );
    run_for(&mut world, 3000);
    let retry = world.peers[1].retry_crafted_frame(1999, false);
    world.peers[0].send_rx(&source, &destination, &retry);
    world.step(1);
    let receipts = world.peers[0].receipts();
    assert_eq!(
        receipts.len(),
        1,
        "capacity refusal must not consume End replay"
    );
    assert_eq!(receipts[0].3, b"pressure-retry");
    let duplicate = world.peers[1].retry_crafted_frame(1998, false);
    world.peers[0].send_rx(&source, &destination, &duplicate);
    world.step(1);
    assert!(
        world.peers[0].receipts().is_empty(),
        "same round delivers once"
    );
}
