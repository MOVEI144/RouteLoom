//! M08/F04: bounded admission and receive floods through the real Owners.

use super::mesh::route_loss_world;
use super::*;

#[test]
#[ignore = "#54/#46: accepted concurrent Reliable sends are lost in a three-node world"]
fn mesh_m08_repeated_bursts_account_for_every_send() {
    let Some(mut world) = route_loss_world("m08", Switch::direct(), false) else {
        return;
    };
    world.peers[0].receipts();
    let mut expected = std::collections::BTreeMap::new();
    let mut received = std::collections::BTreeSet::new();
    let mut terminal = std::collections::BTreeMap::new();
    let mut refused = 0;
    for round in 0..33 {
        if round < 30 {
            for source in 1..3 {
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
        world.pump_until(400, |_| false);
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
    assert_eq!(expected.len() + refused, 30 * 2 * 16);
    assert!(refused > 0, "admission bound reached");
    assert_eq!(
        terminal.len(),
        expected.len(),
        "every accepted send terminates"
    );
    assert_eq!(
        received.len(),
        delivered,
        "receives match sender end receipts"
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
    for peer in &mut world.peers {
        peer.receipts();
    }
    let source = world.macs[1];
    let relay = world.macs[2];
    let polls = world.snaps[2].owner_polls;
    for _ in 0..200 {
        world.peers[2].send_rx(&source, &relay, b"malformed");
    }
    world.peers[1].app_send(testkit::GATEWAY, b"after-flood");
    world.pump_until(400, |_| false);
    assert!(world.snaps[2].owner_polls > polls);
    assert_eq!(world.peers[0].receipts().len(), 1);
    assert_eq!(world.snaps[0].rx, b"after-flood");
    assert_eq!(
        world.snaps[1].app_tx.last().unwrap().state,
        DELIVERY_DELIVERED
    );
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
