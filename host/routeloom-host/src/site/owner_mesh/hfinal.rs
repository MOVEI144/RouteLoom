//! HFINAL software faults through the real Device/Owner and Authority.

use super::recovery::{all_ready, run_for};
use super::*;

#[test]
fn mesh_hfinal_delayed_burst_ack_progress() {
    let mut world =
        MeshWorld::start("hfinal-ack", Switch::direct()).expect("HFINAL requires real Owner peers");
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps));
    for from in 0..3 {
        for to in 0..3 {
            world.switch.delay_ms[from][to] = 10;
        }
    }
    world.switch.drop_wire_kind(0, 1, WIRE_HOP_ACCEPT, 2);
    let results = world.peers[1].tracked_burst(16, testkit::GATEWAY);
    let accepted: Vec<_> = results.iter().filter(|r| r.0 == 0).collect();
    assert_eq!(accepted.len(), 8);
    assert!(results.iter().all(|r| matches!(r.0, 0 | 21)));
    for _ in 0..30_000 {
        world.step(1);
    }
    let received = world.peers[0].receipts();
    let states: Vec<_> = accepted
        .iter()
        .map(|r| {
            world.snaps[1]
                .app_tx
                .iter()
                .find(|tx| tx.seq == r.2)
                .unwrap()
        })
        .collect();
    eprintln!(
        "HFINAL ack: attempted=16 admitted={} Busy={} received={} terminal={states:?}",
        accepted.len(),
        16 - accepted.len(),
        received.len()
    );
    assert!(states.iter().all(|tx| tx.state == DELIVERY_DELIVERED));
    assert_eq!(received.len(), accepted.len());
    for result in accepted {
        assert_eq!(world.peers[1].terminal_count(result.1, result.2), 1);
    }
    assert_eq!(world.snaps[1].queued, 0);
}

/// A long occupied Owner is a separate V2-16 control; it must not erase
/// queued RX or turn the radio off in the fault model.
#[test]
fn mesh_hfinal_owner_710ms_control() {
    let mut world = MeshWorld::start("hfinal-owner", Switch::direct())
        .expect("HFINAL requires real Owner peers");
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps));
    world.peers[1].tracked_burst(16, testkit::GATEWAY);
    world.owner_blocked_until[0] = world.now + 710;
    for _ in 0..2_000 {
        world.step(1);
    }
    let receipts = world.peers[0].receipts();
    eprintln!(
        "HFINAL 710 ms: receipts={} terminals={:?}",
        receipts.len(),
        world.snaps[1].app_tx
    );
    assert!(
        !receipts.is_empty(),
        "radio RX retained while Owner blocked"
    );
    run_for(&mut world, 30_000);
    assert!(world.snaps[1]
        .app_tx
        .iter()
        .filter(|tx| tx.seq != 0)
        .all(|tx| tx.state >= DELIVERY_DELIVERED));
}

#[test]
fn mesh_hfinal_relay_reset_delayed_resume() {
    let mut world = MeshWorld::start("hfinal-reset", Switch::forced_multihop())
        .expect("HFINAL requires real Owner peers");
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps));
    super::mesh::deliver_each(&mut world, 0, 1, 3, b"healthy-baseline");
    for from in 0..3 {
        for to in 0..3 {
            world.switch.delay_ms[from][to] = 20;
        }
    }
    world.switch.drop_link_step = Some((0, 2, 5, 2));
    world.peers[2].power_cut();
    world.peers[2].booted = false;
    world.gate[2] = true;
    run_for(&mut world, 500);
    world.gate[2] = false;
    let start = world.now;
    world.owner_blocked_until[0] = start + 710;
    let mut bound = [None; 2];
    for _ in 0..6_000 {
        world.step(1);
        for (slot, peer) in bound.iter_mut().zip([0, 1]) {
            if slot.is_none() && matches!(world.snaps[2].phases[peer], 4 | PHASE_REACHABLE) {
                *slot = Some(world.now - start);
            }
        }
    }
    eprintln!(
        "HFINAL delayed resume: bound={bound:?} dropped={}",
        world.switch.link_steps_dropped
    );
    assert_eq!(world.switch.link_steps_dropped, 1);
    assert!(bound.iter().all(|t| t.is_some_and(|t| t <= 6_000)));
    for index in 0..10u64 {
        let request = super::send::legacy_send(&mut world, 0x6f00 + index, NODE_A, b"reset-healed");
        let submitted = world.now;
        while super::send::terminal_events(&world, request)
            .next()
            .is_none()
            && world.now - submitted < 9_000
        {
            world.step(1);
        }
        let terminal: Vec<_> = super::send::terminal_events(&world, request).collect();
        assert_eq!(terminal.len(), 1);
        assert_eq!(terminal[0].0, Some(DELIVERY_DELIVERED));
        if index == 0 {
            eprintln!(
                "HFINAL delayed reset: first receipt={} ms",
                terminal[0].2 - start
            );
            assert!(terminal[0].2 - start <= 10_000, "first receipt within 10 s");
        }
        run_for(&mut world, 1_000);
    }
}

/// Keep the gateway boot and key while a same-identity leave/rejoin occurs
/// amid public host send history. A closed operation expires before retry.
#[test]
fn mesh_hfinal_rejoin_during_thousand_send_history() {
    rejoin_history(false, false);
}

#[test]
fn mesh_hfinal_rejoin_710ms_v2_16_control() {
    rejoin_history(true, false);
}

#[test]
fn mesh_hfinal_rejoin_with_delayed_crypto_worker() {
    rejoin_history(false, true);
}

fn rejoin_history(occupied: bool, worker: bool) {
    use super::send::{legacy_send, terminal_events};
    use crate::site::PolicyPatch;
    use routeloom_protocol::manifest as reasons;

    let mut world = if worker {
        MeshWorld::start_with_args(
            "hfinal-rejoin-worker",
            Switch::direct(),
            &["--crypto-ms", "154"],
            &["--crypto-ms", "154"],
        )
    } else {
        MeshWorld::start("hfinal-rejoin", Switch::direct())
    }
    .expect("HFINAL requires real Owner peers");
    world.pump_until(9000, all_ready);
    assert!(
        all_ready(&world.snaps),
        "worker baseline: {:?}",
        world
            .snaps
            .iter()
            .map(|s| (
                s.mode,
                s.phase,
                s.join_state,
                s.link_failed,
                s.link_last_error,
                s.crypto_submitted,
                s.crypto_completed,
                s.crypto_pending
            ))
            .collect::<Vec<_>>()
    );
    super::mesh::deliver_each(&mut world, 0, 1, 3, b"healthy-baseline");
    let identity = world.snaps[1].id_fp;
    let generation = world.snaps[1].own_generation;
    let boot = world.peers[0].reboots;
    let mut requests = Vec::new();
    for index in 0..1_000u64 {
        if index == 250 {
            world.provision.site.service.with(|a| {
                a.update_policy(&PolicyPatch {
                    zero_touch_open: Some(false),
                    ..PolicyPatch::default()
                })
                .unwrap()
            });
            run_for(&mut world, 5_000);
            let (status, leave) = world.peers[1].device_op(true, world.now).unwrap();
            assert_eq!(status, 0);
            world.pump_until(200, |s| s[1].op_last == leave);
            assert_eq!(world.snaps[1].op_result, reasons::REASON_LEFT);
            assert!(!world.snaps[1].has_site);
            assert_eq!(world.snaps[1].id_fp, identity);
            run_for(&mut world, 5_000);
            let offers = world.snaps[0].proxy_offers_tx;
            let (status, join) = world.peers[1].device_op(false, world.now).unwrap();
            assert_eq!(status, 0);
            assert_eq!(world.peers[1].device_op(false, world.now).unwrap().0, 21);
            world.pump_until(2_500, |s| {
                s[1].op_last == join && s[1].op_result == reasons::REASON_JOIN_TIMEOUT
            });
            assert_eq!(world.snaps[1].op_result, reasons::REASON_JOIN_TIMEOUT);
            assert_eq!(
                world.snaps[0].proxy_offers_tx, offers,
                "closed policy suppresses OFFER"
            );
            world.provision.site.service.with(|a| {
                a.update_policy(&PolicyPatch {
                    zero_touch_open: Some(true),
                    ..PolicyPatch::default()
                })
                .unwrap()
            });
            run_for(&mut world, 2_000);
            let applied = world
                .provision
                .site
                .service
                .with(|a| {
                    a.policy_applied.get(&testkit::GATEWAY).copied()
                        == Some(a.policy().policy_generation)
                })
                .0;
            assert!(applied, "gateway committed reopened policy generation");
            let rejoin_started = world.now;
            let (status, join) = world.peers[1].device_op(false, world.now).unwrap();
            assert_eq!(status, 0);
            if occupied {
                world.owner_blocked_until[0] = world.now + 710;
            }
            world.pump_until(2_400, |s| s[1].op_last == join && s[1].join_confirmed);
            if occupied {
                assert!(!world.snaps[1].join_confirmed, "V2-16 occupancy control");
                assert_eq!(world.snaps[1].op_last, join);
                assert_eq!(world.snaps[1].op_result, reasons::REASON_JOIN_TIMEOUT);
                eprintln!("HFINAL V2-16 control: reopened generation applied, 710 ms occupancy, join timed out; offers={}", world.snaps[0].proxy_offers_tx - offers);
                return;
            }
            assert!(
                world.snaps[1].join_confirmed,
                "same-key rejoin: {:?}; policy={:?}",
                world.snaps[1],
                world
                    .provision
                    .site
                    .service
                    .with(|a| a.policy_distribution())
                    .0
            );
            assert_eq!(world.snaps[1].op_result, reasons::REASON_JOINED);
            assert_eq!(world.snaps[1].id_fp, identity);
            assert_eq!(world.snaps[1].own_generation, generation);
            assert_eq!(world.snaps[1].site_generation, generation);
            assert!(world.snaps[1].has_site && world.snaps[1].stores_healthy);
            super::mesh::deliver_each(&mut world, 1, 0, 20, b"restored-member");
            assert!(
                world.now - rejoin_started <= 60_000,
                "rejoin and 20 receipts within operation deadline"
            );
            if worker {
                assert!(world.snaps.iter().all(|s| s.crypto_submitted > 0
                    && s.crypto_completed > 0
                    && s.crypto_owner_ms <= 25
                    && s.crypto_pending <= 1));
            }
        }
        requests.push(legacy_send(
            &mut world,
            0x5f00_0000 + index,
            if index % 2 == 0 { NODE_A } else { NODE_B },
            b"history",
        ));
        for _ in 0..12 {
            world.step(25);
        }
        for peer in &mut world.peers {
            peer.receipts();
        }
    }
    run_for(&mut world, 6_000);
    assert_eq!(world.peers[0].reboots, boot, "one gateway boot");
    let mut delivered = 0;
    for request in requests {
        let terminal: Vec<_> = terminal_events(&world, request).collect();
        assert_eq!(
            terminal.len(),
            1,
            "one terminal per accepted key: {terminal:?}"
        );
        assert!(
            terminal[0].0.is_some(),
            "public send admitted: {terminal:?}"
        );
        assert_ne!(terminal[0].1, reasons::REASON_IDEMPOTENCY_FULL);
        delivered += usize::from(terminal[0].0 == Some(DELIVERY_DELIVERED));
    }
    eprintln!(
        "HFINAL history: attempted=1000 admitted=1000 terminal=1000 delivered={delivered} Busy=0"
    );
}

fn fill_terminal_quota(world: &mut MeshWorld) {
    let source = world.macs[1];
    let destination = world.macs[0];
    let mut pins = 0;
    for _ in 0..224 {
        let frame =
            world.peers[1].craft_frame(testkit::GATEWAY, testkit::GATEWAY, WIRE_DATA, 0, 0, b"pin");
        world.peers[0].send_rx(&source, &destination, &frame);
        for _ in 0..10 {
            world.step(1);
        }
        pins += world.peers[0].receipts().len();
    }
    assert!(matches!(pins, 28 | 84 | 224), "terminal quota: {pins}");
}

#[test]
fn mesh_hfinal_terminal_quota_retry_preserves_end_replay() {
    let mut world = MeshWorld::start("hfinal-quota-retry", Switch::direct())
        .expect("HFINAL requires real Owner peers");
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps));
    let filled_at = world.now;
    fill_terminal_quota(&mut world);
    let source = world.macs[1];
    let destination = world.macs[0];
    // Refuse a fresh End envelope while every pin is still retained.
    world.now = filled_at + 34_990;
    for peer in &mut world.peers {
        assert_eq!(peer.sleep(4, world.now, 0).0, 0);
    }
    let frame = world.peers[1].craft_frame(
        testkit::GATEWAY,
        testkit::GATEWAY,
        WIRE_DATA,
        0,
        0,
        b"quota-retry",
    );
    world.peers[0].send_rx(&source, &destination, &frame);
    world.step(1);
    assert!(
        world.peers[0].receipts().is_empty(),
        "full quota refuses before expiry"
    );
    // The first pin expires at filled_at + 35_001 ms. The same End
    // envelope must remain admissible after legitimate quota recovery.
    for _ in 0..500 {
        world.step(1);
    }
    // A bad End tag under a valid Link wrapper must release its reservation
    // and leave the End counter available for the authenticated retry.
    let invalid = world.peers[1].retry_crafted_frame(4_499, true);
    world.peers[0].send_rx(&source, &destination, &invalid);
    world.step(1);
    assert!(world.peers[0].receipts().is_empty());
    let retry = world.peers[1].retry_crafted_frame(4_498, false);
    world.peers[0].send_rx(&source, &destination, &retry);
    world.step(1);
    let receipts = world.peers[0].receipts();
    assert_eq!(
        receipts.len(),
        1,
        "same End counter retries after quota expiry"
    );
    assert_eq!(receipts[0].3, b"quota-retry");
    let duplicate = world.peers[1].retry_crafted_frame(4_497, false);
    world.peers[0].send_rx(&source, &destination, &duplicate);
    world.step(1);
    assert!(
        world.peers[0].receipts().is_empty(),
        "accepted retry delivers once"
    );
}

#[test]
fn mesh_hfinal_expired_terminal_pins_admit_before_sweep() {
    let mut world = MeshWorld::start("hfinal-expiry", Switch::direct())
        .expect("HFINAL requires real Owner peers");
    world.pump_until(9000, all_ready);
    assert!(all_ready(&world.snaps));
    fill_terminal_quota(&mut world);
    let source = world.macs[1];
    let destination = world.macs[0];
    // Advance the platform clock without an Owner poll, then deliver a fresh
    // authenticated RX. Its admission precedes the next periodic dedup sweep.
    world.now += 35_000;
    for peer in &mut world.peers {
        assert_eq!(peer.sleep(4, world.now, 0).0, 0);
    }
    let frame = world.peers[1].craft_frame(
        testkit::GATEWAY,
        testkit::GATEWAY,
        WIRE_DATA,
        0,
        0,
        b"after-expiry",
    );
    world.peers[0].send_rx(&source, &destination, &frame);
    world.step(1);
    let receipts = world.peers[0].receipts();
    assert_eq!(receipts.len(), 1, "expired pins cannot reject fresh RX");
    assert_eq!(receipts[0].3, b"after-expiry");
}

#[test]
fn mesh_hfinal_m08_delayed_bursts() {
    super::load::repeated_bursts(10);
}
