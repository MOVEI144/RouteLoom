//! M08/F04: bounded admission and receive floods through the real Owners.

use super::mesh::route_loss_world;
use super::*;

#[test]
fn mesh_m08_repeated_bursts_account_for_every_send() {
    {
        let Some(mut boundary) = route_loss_world("m08-boundary", Switch::direct(), false) else {
            return;
        };
        for count in [7, 8, 9] {
            let results = boundary.peers[1].tracked_burst(count, testkit::GATEWAY);
            assert_eq!(
                results.iter().filter(|r| r.0 == 0).count(),
                usize::from(count.min(8))
            );
            assert!(
                results.iter().all(|r| r.0 == 0 || r.0 == 21),
                "full admission is Busy"
            );
            boundary.pump_until(400, |_| false);
            assert_eq!(
                boundary.peers[0].receipts().len(),
                usize::from(count.min(8))
            );
        }
    }
    let nodes = if max_nodes() == 32 { 5 } else { 3 };
    let Some(mut world) = route_loss_world("m08", Switch::new(&Topology::full(nodes)), false)
    else {
        return;
    };
    // Start the load after the full topology and its improvement hold settle.
    world.pump_until(2400, |snaps| {
        snaps.iter().enumerate().all(|(index, snap)| {
            snap.phases
                .iter()
                .enumerate()
                .all(|(peer, &phase)| peer == index || phase == PHASE_REACHABLE)
        })
    });
    world.pump_until(600, |_| false);
    world.peers[0].receipts();
    let routes: Vec<_> = world
        .peers
        .iter_mut()
        .skip(1)
        .map(|peer| peer.next_hop(testkit::GATEWAY))
        .collect();
    assert!(
        routes.iter().all(|&hop| hop == testkit::GATEWAY),
        "full mesh direct gateway routes settled"
    );
    let mut expected = std::collections::BTreeMap::new();
    let mut received = std::collections::BTreeSet::new();
    let mut terminal = std::collections::BTreeMap::new();
    let mut refused = 0;
    for round in 0..32 {
        if round < 30 {
            for source in 1..nodes {
                let results = world.peers[source].tracked_burst(16, testkit::GATEWAY);
                for (index, (status, session, seq)) in results.into_iter().enumerate() {
                    if status == 0 {
                        assert!(expected
                            .insert((world.nodes[source], session, seq), index as u8)
                            .is_none());
                    } else {
                        refused += 1;
                        assert!(
                            matches!(status, 7 | 21),
                            "capacity or busy refusal: {status}"
                        );
                    }
                }
            }
        }
        // Keep the 10 s burst cadence and allow every send its 30 s lifetime.
        for _ in 0..400 {
            world.step(25);
            for (peer, &hop) in world.peers.iter_mut().skip(1).zip(&routes) {
                assert_eq!(peer.next_hop(testkit::GATEWAY), hop, "no route flap");
            }
            assert!(
                world
                    .snaps
                    .iter()
                    .all(|s| s.mode == MODE_MEMBER && s.phase == PHASE_ACTIVE),
                "membership stayed active under load"
            );
        }
        for (source, session, seq, payload) in world.peers[0].receipts() {
            let key = (source, session, seq);
            assert_eq!(
                payload,
                [*expected.get(&key).expect("accepted receive key")]
            );
            assert!(received.insert(key), "one receive per key");
        }
        for &key in expected.keys() {
            let peer = world.index_of(key.0);
            for tx in world.snaps[peer].app_tx.iter().filter(|tx| tx.seq == key.2) {
                if tx.state >= DELIVERY_DELIVERED {
                    terminal.insert(key, tx.state);
                }
            }
        }
    }
    let delivered = terminal
        .values()
        .filter(|&&s| s == DELIVERY_DELIVERED)
        .count();
    eprintln!(
        "M08: accepted={}, refused={refused}, received={}, delivered={delivered}, terminal={}",
        expected.len(),
        received.len(),
        terminal.len()
    );
    assert_eq!(expected.len() + refused, 30 * (nodes - 1) * 16);
    assert!(refused > 0, "admission bound reached");
    for snapshot in &world.snaps {
        assert_eq!(snapshot.queued, 0, "queue drained within 30 s");
    }
    assert_eq!(
        terminal.len(),
        expected.len(),
        "every accepted send terminates"
    );
    assert!(
        terminal
            .iter()
            .filter(|(_, state)| **state == DELIVERY_DELIVERED)
            .all(|(key, _)| received.contains(key)),
        "every Delivered has one verified receive"
    );
    assert!(
        delivered * 100 >= expected.len() * 99,
        "accepted Reliable >=99%"
    );
}

#[test]
fn mesh_f04_receive_flood_does_not_starve_delivery() {
    let Some(mut world) = route_loss_world("f04", Switch::forced_multihop(), true) else {
        return;
    };
    super::mesh::deliver_each(&mut world, 1, 0, 1, b"flood-warm");
    for peer in &mut world.peers {
        peer.receipts();
    }
    let source = world.macs[1];
    let relay = world.macs[2];
    let duplicate = world.peers[1].craft_frame(
        NODE_B,
        testkit::GATEWAY,
        WIRE_DATA,
        0,
        0,
        b"flood-duplicate",
    );
    let polls = world.snaps[2].owner_polls;
    for _ in 0..100 {
        world.peers[2].send_rx(&source, &relay, b"malformed");
        world.peers[2].send_rx(&source, &relay, &duplicate);
    }
    let results = world.peers[1].tracked_burst(16, testkit::GATEWAY);
    let mut expected = std::collections::BTreeMap::new();
    for (index, (status, session, seq)) in results.into_iter().enumerate() {
        if status == 0 {
            expected.insert((session, seq), index as u8);
        } else {
            assert!(
                matches!(status, 7 | 21),
                "capacity or busy refusal: {status}"
            );
        }
    }
    assert!(!expected.is_empty(), "legitimate burst accepted");
    world.pump_until(1200, |_| false);
    assert!(world.snaps[2].owner_polls > polls);
    let mut duplicate_receives = 0;
    let accepted = expected.len();
    for (origin, session, seq, payload) in world.peers[0].receipts() {
        assert_eq!(origin, NODE_A);
        if payload == b"flood-duplicate" {
            duplicate_receives += 1;
        } else {
            assert_eq!(
                payload,
                [expected
                    .remove(&(session, seq))
                    .expect("accepted key, once")]
            );
            let tx = world.snaps[1]
                .app_tx
                .iter()
                .find(|tx| tx.seq == seq)
                .unwrap();
            assert_eq!(tx.state, DELIVERY_DELIVERED, "burst sender has end receipt");
        }
    }
    assert_eq!(
        duplicate_receives, 1,
        "authenticated duplicates deliver once"
    );
    assert!(
        expected.is_empty(),
        "all accepted burst messages have end receipts"
    );
    eprintln!("F04: fault_hits=200, burst={accepted}/{accepted} within 30 s, duplicate receives=1");
    let peak = world.snaps[2].rx_queue_max;
    assert!(peak > 0 && peak <= 48, "bounded queue high-water: {peak}");
    world.peers[1].app_send(testkit::GATEWAY, b"second-send");
    world.pump_until(400, |_| false);
    assert_eq!(world.peers[0].receipts().len(), 1);
    assert_eq!(
        world.snaps[2].rx_queue_max, peak,
        "no continuing queue growth"
    );
}
