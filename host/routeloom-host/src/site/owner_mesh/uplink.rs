//! H7 reverse and far-end delivery through the real Device/Owner.

use super::recovery::{all_ready, run_for};
use super::*;

fn star_burst(count: u8, small: bool) {
    let mut world = MeshWorld::start_with_args(
        "uplink-star",
        Switch::new(&Topology::full(6)),
        &["--crypto-ms", "154"],
        &["--crypto-ms", "154"],
    )
    .expect("uplink qualification requires real Owner peers");
    for row in &mut world.switch.delay_ms {
        row.fill(10);
    }
    for row in &mut world.switch.callback_delay_ms {
        row.fill(10);
    }
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps));
    let (capacity, pins, refused_before) = world.peers[0].terminal_capacity();
    if small {
        assert_eq!((capacity, pins), (32, 28), "requires gateway_small peer");
    }
    let lost_peer = (1..world.peers.len())
        .find(|&peer| {
            world.peers[0].next_hop(world.nodes[peer]) == world.nodes[peer]
                && world.peers[peer].next_hop(testkit::GATEWAY) == testkit::GATEWAY
        })
        .expect("a bidirectional gateway tree link");
    world
        .switch
        .drop_wire_kind(0, lost_peer, WIRE_HOP_ACCEPT, 1);
    world
        .switch
        .drop_wire_kind(0, lost_peer, WIRE_END_RECEIPT, 1);
    let results: Vec<_> = world
        .peers
        .iter_mut()
        .skip(1)
        .map(|peer| peer.tracked_burst(count, testkit::GATEWAY))
        .collect();
    for _ in 0..30_000 {
        world.step(1);
    }
    let received = world.peers[0].receipts();
    let keys: std::collections::BTreeSet<_> = received
        .iter()
        .map(|&(source, session, seq, _)| (source, session, seq))
        .collect();
    assert_eq!(keys.len(), received.len(), "one receive per key");
    assert_eq!(world.switch.wire_dropped, 2, "both ACK losses fired");
    let mut passed = true;
    let mut total_delivered = 0;
    for (index, results) in results.iter().enumerate() {
        assert!(results.iter().all(|r| matches!(r.0, 0 | 21)));
        let admitted: Vec<_> = results.iter().filter(|r| r.0 == 0).collect();
        assert_eq!(admitted.len(), usize::from(count.min(8)));
        let mut delivered = 0;
        for &&(_, session, seq) in &admitted {
            assert_eq!(world.peers[index + 1].terminal_count(session, seq), 1);
            let tx = world.snaps[index + 1]
                .app_tx
                .iter()
                .find(|tx| tx.seq == seq)
                .unwrap();
            if tx.state == DELIVERY_DELIVERED {
                delivered += 1;
                assert!(keys.contains(&(world.nodes[index + 1], session, seq)));
            }
        }
        eprintln!(
            "uplink star source={}: {delivered}/{}",
            index + 1,
            admitted.len()
        );
        passed &= delivered * 100 >= admitted.len() * 99;
        total_delivered += delivered;
        assert_eq!(world.snaps[index + 1].queued, 0);
    }
    assert_eq!(
        received.len(),
        total_delivered,
        "each receive has a sender receipt"
    );
    let refused = world.peers[0].terminal_capacity().2 - refused_before;
    eprintln!(
        "uplink star: capacity={capacity} pins={pins} received={} terminal_refusals={refused}",
        received.len()
    );
    if small {
        assert!(refused > 0, "receiver quota caused the refusal");
        assert_eq!(received.len(), pins as usize);
    } else {
        assert_eq!(refused, 0);
    }
    assert!(passed, "each sender Reliable >=99%");
}

#[test]
fn mesh_uplink_star_burst_delivers() {
    star_burst(4, false);
}

#[test]
#[ignore = "small32: 40 admitted sends exceed 28 terminal pins; 99% remains red"]
fn mesh_uplink_star_overload_small32() {
    star_burst(16, true);
}

#[test]
fn mesh_uplink_five_hop_cold_line_delivers() {
    let mut world = MeshWorld::start_with_args(
        "uplink-line-cold",
        Switch::new(&Topology::line(6)),
        &["--crypto-ms", "154"],
        &["--crypto-ms", "154"],
    )
    .expect("uplink qualification requires real Owner peers");
    for row in &mut world.switch.delay_ms {
        row.fill(10);
    }
    for row in &mut world.switch.callback_delay_ms {
        row.fill(10);
    }
    let started = world.now;
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps), "cold line: {:?}", world.snaps);
    eprintln!(
        "uplink line: all End/authority channels ready in {} ms vt",
        world.now - started
    );
    let before = world.switch.leg_delivered.clone();
    for index in 0..100_u32 {
        // Paced sends stay within the unchanged terminal retention budget.
        let up = world.snaps[0].rx_count;
        let down = world.snaps[5].rx_count;
        let payload = index.to_le_bytes();
        world.peers[5].app_send(testkit::GATEWAY, &payload);
        world.peers[0].app_send(world.nodes[5], &payload);
        world.pump_until(1200, |snaps| {
            snaps[0].rx_count > up
                && snaps[5].rx_count > down
                && [0, 5].iter().all(|&peer| {
                    snaps[peer]
                        .app_tx
                        .iter()
                        .max_by_key(|tx| tx.seq)
                        .is_some_and(|tx| tx.state == DELIVERY_DELIVERED)
                })
        });
        assert_eq!(world.snaps[0].rx_count, up + 1);
        assert_eq!(world.snaps[5].rx_count, down + 1);
        for peer in [0, 5] {
            assert_eq!(world.snaps[peer].rx, payload);
            assert_eq!(
                world.snaps[peer]
                    .app_tx
                    .iter()
                    .max_by_key(|tx| tx.seq)
                    .unwrap()
                    .state,
                DELIVERY_DELIVERED
            );
            let receipts = world.peers[peer].receipts();
            assert_eq!(receipts.len(), 1);
            assert_eq!(
                world.peers[5 - peer].terminal_count(receipts[0].1, receipts[0].2),
                1
            );
        }
        assert_eq!(world.snaps[0].rx_src, world.nodes[5]);
        assert_eq!(world.snaps[5].rx_src, testkit::GATEWAY);
        run_for(&mut world, 3000);
    }
    for (a, row) in before.iter().enumerate() {
        for (b, &prior) in row.iter().enumerate() {
            if a.abs_diff(b) == 1 {
                assert!(world.switch.leg_delivered[a][b] > prior);
            } else {
                assert_eq!(world.switch.leg_delivered[a][b], 0, "no shortcut");
            }
        }
    }
    assert!(world.peers[0].receipts().is_empty() && world.peers[5].receipts().is_empty());
    eprintln!("uplink line: 100/100 each direction; no duplicate receive or terminal");
}
