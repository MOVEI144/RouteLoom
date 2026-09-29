//! Mesh rows: convergence, multi-hop delivery and route loss
//! (tests/e2e/scenarios.json M01, M03, F05).

use super::*;

/// The route-loss rows exercise one known A—gateway (or A—B—gateway)
/// binding, so they boot on the staggered compatibility plan: which
/// neighbor a node binds first is up to the radio at a simultaneous boot.
pub(super) fn route_loss_world(tag: &str, switch: Switch, relay_first: bool) -> Option<MeshWorld> {
    let boot = staggered_boot(switch.nodes());
    let mut world = MeshWorld::start_plan(tag, switch, &boot, true)?;
    if relay_first {
        world.gate[1] = true;
        world.pump_until(9000, |snaps| {
            snaps[0].authority_ready && snaps[2].authority_ready && snaps[2].join_confirmed
        });
        assert!(world.snaps[2].authority_ready, "relay reached gateway");
        world.gate[1] = false;
    }
    world.pump_until(9000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
        })
    });
    assert!(
        world
            .snaps
            .iter()
            .all(|s| s.authority_ready && s.join_confirmed),
        "Owner mesh converged: {:?}",
        world.snaps
    );
    Some(world)
}

/// The relay binds to the gateway before the leaf boots. The late leaf
/// reaches the gateway only through the real discovery and coordinator legs.
#[test]
fn mesh_route_loss_relay_binds_first() {
    let Some(mut world) = route_loss_world("route-relay-first", Switch::forced_multihop(), true)
    else {
        return;
    };
    assert_eq!(world.snaps[1].phases[2], PHASE_REACHABLE, "A-B BIND");
    assert_eq!(world.snaps[2].phases[0], PHASE_REACHABLE, "B-gateway BIND");
    let before = world.snaps[0].rx_count;
    world.peers[1].app_send(testkit::GATEWAY, b"relay-first");
    world.pump_until(2000, |snaps| snaps[0].rx_count > before);
    assert_eq!(world.snaps[0].rx_count, before + 1);
    assert_eq!(world.snaps[0].rx, b"relay-first");
}

/// A lost hop ACK and a lost routed receipt must preserve the End
/// envelope, so the relay accepts retries without duplicate delivery.
#[test]
fn mesh_route_loss_retry_has_one_terminal_delivery() {
    let Some(mut world) = route_loss_world("route-retry", Switch::forced_multihop(), true) else {
        return;
    };
    world.switch.drop_wire_kind(2, 1, WIRE_HOP_ACCEPT, 1);
    world.switch.drop_wire_kind(2, 1, WIRE_END_RECEIPT, 1);
    let before = world.snaps[0].rx_count;
    let expired_before = world.snaps[1].hop_accept_expired;
    world.peers[1].app_send(testkit::GATEWAY, b"retry-once");
    world.pump_until(3000, |snaps| {
        snaps[0].rx_count > before
            && snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert_eq!(world.switch.wire_dropped, 2, "both fault rules fired");
    assert_eq!(
        world.snaps[0].rx_count,
        before + 1,
        "one application receive"
    );
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "sender delivered: {:?}",
        world.snaps[1].app_tx
    );
    assert_eq!(world.snaps[2].transit_conflicts, 0);
    assert_eq!(world.snaps[2].receipt_conflicts, 0);
    assert!(
        world.snaps[1].hop_accept_expired > expired_before,
        "the dropped HOP_ACCEPT expired the wait"
    );
}

/// A stale binding remains the identity for authenticated Probe/Result
/// even after the runtime has released its transmit-side driver peer.
pub(super) fn stale_a_gateway(world: &mut MeshWorld) {
    assert_eq!(world.snaps[1].phases[0], PHASE_REACHABLE);
    let driver_peers = world.snaps[1].driver_peers;
    let logical_neighbors = world.snaps[1].neighbor_count;
    world.switch.isolate(1);
    world.pump_until(2400, |snaps| {
        snaps[1].phases[0] == PHASE_STALE && snaps[0].phases[1] == PHASE_STALE
    });
    assert_eq!(
        world.snaps[1].phases[0], PHASE_STALE,
        "A marks gateway stale"
    );
    assert_eq!(
        world.snaps[0].phases[1], PHASE_STALE,
        "gateway marks A stale"
    );
    assert!(world.snaps[1].stale_expirations > 0);
    assert_eq!(world.snaps[1].neighbor_count, logical_neighbors);
    world.pump_until(400, |snaps| snaps[1].driver_peers < driver_peers);
    assert!(
        world.snaps[1].driver_peers < driver_peers,
        "STALE released a driver slot: before {driver_peers}, after {}",
        world.snaps[1].driver_peers
    );
}

#[test]
fn mesh_route_loss_stale_peer_recovers() {
    let Some(mut world) = route_loss_world("route-stale", Switch::direct(), false) else {
        return;
    };
    stale_a_gateway(&mut world);
    let before = world.snaps[1].probes_tx;
    let repair_demands = world.snaps[1].repair_demands;
    world.switch.heal(1);
    world.peers[1].app_send(testkit::GATEWAY, b"request-repair");
    world.pump_until(8000, |snaps| {
        snaps[1].phases[0] == PHASE_REACHABLE && snaps[0].phases[1] == PHASE_REACHABLE
    });
    assert!(world.snaps[1].probes_tx > before, "A sent a repair Probe");
    assert!(world.snaps[1].repair_demands > repair_demands);
    assert_eq!(world.snaps[1].phases[0], PHASE_REACHABLE, "A recovered");
    assert_eq!(
        world.snaps[0].phases[1], PHASE_REACHABLE,
        "gateway recovered"
    );
    // The held request may still land after the route is back: wait for
    // the new message itself.
    let received = world.snaps[0].rx_count;
    world.peers[1].app_send(testkit::GATEWAY, b"after-repair");
    world.pump_until(2000, |snaps| snaps[0].rx == b"after-repair");
    assert!(world.snaps[0].rx_count > received);
    assert_eq!(world.snaps[0].rx, b"after-repair");
}

/// The Probe MAC callback may release a driver peer before the Result
/// reaches RX. The verified Result must still re-establish the binding.
#[test]
fn mesh_route_loss_result_after_probe_callback() {
    let Some(mut world) = route_loss_world("route-result-late", Switch::direct(), false) else {
        return;
    };
    stale_a_gateway(&mut world);
    let probes_before = world.switch.probes_seen;
    let results_before = world.switch.results_seen;
    world.switch.delay_ms[0][1] = 100;
    world.switch.heal(1);
    world.peers[1].app_send(testkit::GATEWAY, b"repair-late-result");
    world.pump_until(8000, |snaps| snaps[1].phases[0] == PHASE_REACHABLE);
    assert_eq!(world.snaps[1].phases[0], PHASE_REACHABLE);
    assert!(world.switch.probes_seen > probes_before);
    assert!(world.switch.results_seen > results_before);
}

/// Two directed management losses force a lease expiry; the next valid
/// Probe/Result restores the route without restarting either Owner.
#[test]
fn mesh_route_loss_management_loss_then_repair() {
    let Some(mut world) = route_loss_world("route-control-loss", Switch::direct(), false) else {
        return;
    };
    world.switch.drop_wire_kind(1, 0, WIRE_RESULT, 1);
    world.switch.drop_wire_kind(0, 1, WIRE_RESULT, 1);
    for _ in 0..1000 {
        if world.switch.wire_dropped == 2 {
            break;
        }
        world.step(25);
    }
    assert_eq!(world.switch.wire_dropped, 2, "both Results lost");
    world.switch.drop_wire_kind(1, 0, WIRE_PROBE, 32);
    world.switch.drop_wire_kind(0, 1, WIRE_PROBE, 32);
    world.pump_until(2400, |snaps| snaps[1].phases[0] == PHASE_STALE);
    assert_eq!(
        world.snaps[1].phases[0],
        PHASE_STALE,
        "lost={} stale={} probes={} results={} phases={:?} rules={:?}",
        world.switch.wire_dropped,
        world.snaps[1].stale_expirations,
        world.switch.probes_seen,
        world.switch.results_seen,
        world.snaps[1].phases,
        world.switch.drop_wire
    );
    assert!(world.switch.wire_dropped >= 4, "Probe losses fired");
    world.switch.drop_wire.clear();
    world.peers[1].app_send(testkit::GATEWAY, b"route-repair");
    world.pump_until(8000, |snaps| snaps[1].phases[0] == PHASE_REACHABLE);
    assert_eq!(world.snaps[1].phases[0], PHASE_REACHABLE);
    let received = world.snaps[0].rx_count;
    world.peers[1].app_send(testkit::GATEWAY, b"route-restored");
    world.pump_until(2000, |snaps| snaps[0].rx == b"route-restored");
    assert!(world.snaps[0].rx_count > received);
    assert_eq!(world.snaps[0].rx, b"route-restored");
}

/// Probe RX while a DATA MAC callback is pending leaves the Result queued
/// until the physical slot frees, for short and long callback latencies.
#[test]
fn mesh_route_loss_probe_result_survives_callback_delay() {
    let Some(mut world) = route_loss_world("route-callback-delay", Switch::direct(), false) else {
        return;
    };
    for delay in [20, 100, 500] {
        world.switch.delay_ms[0][1] = 1000;
        let pending_probe = |world: &MeshWorld| {
            world.delayed.iter().position(|(_, delivery)| {
                delivery.0 == 1
                    && delivery.1 == MAC_GW
                    && delivery.3.len() > 4
                    && delivery.3[..4] == *b"RL\x02\0"
                    && delivery.3[4] == WIRE_PROBE
            })
        };
        for _ in 0..1000 {
            if pending_probe(&world).is_some() {
                break;
            }
            world.step(25);
        }
        let probe_index = pending_probe(&world).expect("real gateway Probe captured in flight");
        world.delayed[probe_index].0 = world.now + 25;
        world.switch.delay_ms[0][1] = 0;
        let probe_pending = world.probe_while_callback_pending;
        let result_before = world.switch.results_seen;
        let received = world.snaps[0].rx_count;
        world.switch.callback_delay_ms[1][0] = delay;
        world.switch.callback_delay_kind = Some(WIRE_DATA);
        world.peers[1].app_send(testkit::GATEWAY, b"during-probe");
        world.step(25);
        assert!(
            world.probe_while_callback_pending > probe_pending,
            "{delay} ms: Probe RX scheduled with DATA callback pending"
        );
        for _ in 0..1000 {
            world.step(25);
            if world.snaps[0].rx_count > received
                && world.snaps[1]
                    .app_tx
                    .last()
                    .is_some_and(|tx| tx.state == DELIVERY_DELIVERED)
                && world.switch.results_seen > result_before
            {
                break;
            }
        }
        world.switch.callback_delay_ms[1][0] = 0;
        assert_eq!(world.snaps[0].rx_count, received + 1, "{delay} ms DATA");
        assert!(
            world.switch.results_seen > result_before,
            "{delay} ms: Result sent after slot freed"
        );
        assert_eq!(world.snaps[1].phases[0], PHASE_REACHABLE);
    }
}

/// An authenticated HopAccept can arrive before the DATA TX callback.
#[test]
fn mesh_route_loss_early_hop_accept() {
    let Some(mut world) = route_loss_world("route-early-ack", Switch::direct(), false) else {
        return;
    };
    world.switch.callback_delay_ms[1][0] = 100;
    world.switch.callback_delay_kind = Some(WIRE_DATA);
    let before = world.snaps[0].rx_count;
    world.peers[1].app_send(testkit::GATEWAY, b"early-ack");
    world.pump_until(1000, |snaps| {
        snaps[0].rx_count > before
            && snaps[1]
                .app_tx
                .last()
                .is_some_and(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(world.early_hop_accepts > 0, "ACK preceded MAC callback");
    assert_eq!(world.snaps[0].rx_count, before + 1);
    assert_eq!(
        world.snaps[1].app_tx.last().unwrap().state,
        DELIVERY_DELIVERED
    );
}

/// A callback arriving after the watchdog belongs to the old physical
/// send. The next application send must complete on its own evidence.
#[test]
fn mesh_route_loss_old_callback_cannot_complete_new_send() {
    let Some(mut world) = route_loss_world("route-old-callback", Switch::direct(), false) else {
        return;
    };
    let received = world.snaps[0].rx_count;
    world.switch.callback_delay_ms[1][0] = 1500;
    world.switch.callback_delay_kind = Some(WIRE_DATA);
    world.peers[1].app_send(testkit::GATEWAY, b"old-send");
    for _ in 0..100 {
        world.step(25);
        if world.callbacks[1]
            .iter()
            .any(|(at, _)| *at > world.now + 1200)
        {
            break;
        }
    }
    assert!(
        world.callbacks[1]
            .iter()
            .any(|(at, _)| *at > world.now + 1200),
        "first DATA callback held"
    );
    world.switch.callback_delay_ms[1][0] = 0;
    for _ in 0..44 {
        world.step(25);
    }
    assert!(!world.callbacks[1].is_empty(), "old callback still pending");
    world.peers[1].app_send(testkit::GATEWAY, b"new-send");
    world.pump_until(1000, |snaps| {
        snaps[0].rx_count >= received + 2
            && snaps[1]
                .app_tx
                .last()
                .is_some_and(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1].stale_tx_results > 0,
        "old callback quarantined"
    );
    assert_eq!(world.snaps[0].rx_count, received + 2);
    assert_eq!(world.snaps[0].rx, b"new-send");
    assert_eq!(
        world.snaps[1].app_tx.last().unwrap().state,
        DELIVERY_DELIVERED
    );
}

/// The driver models the 20 physical slots while the runtime enforces
/// sixteen regular mappings. A refused extra peer cannot evict live BINDs.
#[test]
fn mesh_route_loss_peer_capacity_keeps_live_bindings() {
    let Some(mut world) = route_loss_world("route-capacity", Switch::direct(), false) else {
        return;
    };
    world.pump_until(1000, |snaps| {
        snaps[0].phases[1] == PHASE_REACHABLE && snaps[0].phases[2] == PHASE_REACHABLE
    });
    let regular = usize::from(world.snaps[0].driver_peers - 1);
    assert!(regular <= 16, "broadcast plus regular table");
    let fill = 16 - regular;
    for index in 0..fill {
        let (ok, peers) = world.peers[0].peer_slot(b'V', index as u8);
        assert!(ok, "regular slot {index}");
        assert_eq!(usize::from(peers), regular + index + 2);
    }
    let (ok, peers) = world.peers[0].peer_slot(b'V', fill as u8);
    assert!(!ok, "17th regular refused");
    assert_eq!(peers, 17);
    if fill > 0 {
        let (ok, peers) = world.peers[0].peer_slot(b'V', 0);
        assert!(ok, "same MAC re-registration succeeds");
        assert_eq!(peers, 17);
    }
    for index in 0..3 {
        let (ok, peers) = world.peers[0].peer_slot(b'I', index);
        assert!(ok, "transient driver slot {index}");
        assert_eq!(peers, 18 + index);
    }
    let (ok, peers) = world.peers[0].peer_slot(b'I', 3);
    assert!(!ok, "21st physical peer refused");
    assert_eq!(peers, 20);
    world.peers[0].fail_driver_release(true);
    let (ok, peers) = world.peers[0].peer_slot(b'J', 0);
    assert!(!ok, "failed driver deletion kept its slot");
    assert_eq!(peers, 20);
    world.peers[0].fail_driver_release(false);
    for index in 0..3 {
        let (ok, peers) = world.peers[0].peer_slot(b'J', index);
        assert!(ok, "release transient {index}");
        assert_eq!(peers, 19 - index);
    }
    let received = world.snaps[1].rx_count;
    world.peers[0].app_send(NODE_A, b"capacity-survivor");
    world.pump_until(2000, |snaps| snaps[1].rx_count > received);
    assert_eq!(world.snaps[1].rx, b"capacity-survivor");
}

/// Repeated RLD1 handoffs in one boot must return each transient lease
/// to discovery; the fourth through tenth repairs cannot hit capacity.
#[test]
fn mesh_route_loss_ten_handovers_recover() {
    let Some(mut world) = route_loss_world("route-ten-handovers", Switch::forced_multihop(), true)
    else {
        return;
    };
    let capacity_before = world.snaps[1].peer_capacity;
    let starts_before = world.snaps[1].member_starts + world.snaps[2].member_starts;
    let failed_before = world.snaps[1].link_failed + world.snaps[2].link_failed;
    for attempt in 0..10 {
        assert_eq!(world.snaps[1].phases[2], PHASE_REACHABLE);
        let offers = world.snaps[1].offers_rx + world.snaps[2].offers_rx;
        let links = world.snaps[1].link_requests + world.snaps[2].link_requests;
        let established = world.snaps[1].link_established;
        let failed = world.snaps[1].link_failed;
        world.switch.isolate(1);
        world.pump_until(2400, |snaps| {
            snaps[1].phases[2] == PHASE_STALE && snaps[2].phases[1] == PHASE_STALE
        });
        assert_eq!(
            world.snaps[1].phases[2], PHASE_STALE,
            "cycle {attempt} stale"
        );
        world.switch.drop_wire_kind(1, 2, WIRE_PROBE, 32);
        world.switch.drop_wire_kind(2, 1, WIRE_PROBE, 32);
        world.switch.heal(1);
        world.peers[1].app_send(testkit::GATEWAY, b"renew-binding");
        world.pump_until(2000, |snaps| {
            snaps[1].link_requests + snaps[2].link_requests > links
        });
        assert!(
            world.snaps[1].offers_rx + world.snaps[2].offers_rx > offers,
            "cycle {attempt}: RLD1 offer reached initiator"
        );
        assert!(
            world.snaps[1].link_requests + world.snaps[2].link_requests > links,
            "cycle {attempt}: coordinator took another handshake; links {links}->{}+{}, offers {offers}->{}, starts {}, request_failures {}, link_failed {}, link_error {}, capacity {}->{}, phase {}",
            world.snaps[1].link_requests,
            world.snaps[2].link_requests,
            world.snaps[1].offers_rx + world.snaps[2].offers_rx,
            world.snaps[1].member_starts,
            world.snaps[1].link_request_failures,
            world.snaps[1].link_failed,
            world.snaps[1].link_last_error,
            capacity_before,
            world.snaps[1].peer_capacity,
            world.snaps[1].phases[2]
        );
        world.switch.drop_wire.clear();
        world.pump_until(3000, |snaps| {
            snaps[1].phases[2] == PHASE_REACHABLE
                && (snaps[1].link_established > established || snaps[1].link_failed > failed)
        });
        assert_eq!(
            world.snaps[1].phases[2], PHASE_REACHABLE,
            "cycle {attempt} re-BIND"
        );
        assert!(
            world.snaps[1].link_established > established || world.snaps[1].link_failed > failed,
            "cycle {attempt}: handshake result drained"
        );
        assert_eq!(
            world.snaps[1].peer_capacity, capacity_before,
            "cycle {attempt}: no leaked transient reservation"
        );
    }
    assert!(
        world.snaps[1].member_starts + world.snaps[2].member_starts >= starts_before + 10,
        "ten starts crossed discovery into the coordinators"
    );
    assert!(
        world.snaps[1].link_failed + world.snaps[2].link_failed > failed_before,
        "lost flights also exercised failed handoff cleanup"
    );
    let received = world.snaps[0].rx_count;
    world.peers[1].app_send(testkit::GATEWAY, b"after-ten");
    world.pump_until(2000, |snaps| snaps[0].rx == b"after-ten");
    assert!(world.snaps[0].rx_count > received);
    assert_eq!(world.snaps[0].rx, b"after-ten");
}

/// The field campaign shape runs on flat, real Owner routing: sixteen
/// early sends, then one every thirty virtual seconds, with relay traffic
/// alongside it. No process restarts over the sixty-minute clock span.
#[test]
fn mesh_route_loss_hundred_under_flat_load() {
    let Some(mut world) = route_loss_world("route-hundred", Switch::forced_multihop(), true) else {
        return;
    };
    let started = world.now;
    let baseline = world.snaps[1].rx_count;
    let capacity = world.snaps[0].peer_capacity;
    let no_route = world.snaps[0].no_route;
    for index in 0u32..16 {
        let received = world.snaps[1].rx_count;
        world.peers[0].app_send(NODE_A, &index.to_le_bytes());
        world.pump_until(200, |snaps| {
            snaps[1].rx_count > received
                && snaps[0]
                    .app_tx
                    .last()
                    .is_some_and(|tx| tx.state == DELIVERY_DELIVERED)
        });
        assert_eq!(
            world.snaps[1].rx_count,
            received + 1,
            "early message {index}"
        );
    }
    assert_eq!(world.snaps[1].rx_count, baseline + 16, "initial burst");
    assert!(
        world.snaps[0]
            .app_tx
            .iter()
            .all(|tx| tx.state == DELIVERY_DELIVERED),
        "all initial sends delivered: {:?}",
        world.snaps[0].app_tx
    );
    for index in 16u32..100 {
        for _ in 0..300 {
            world.step(100);
        }
        let received = world.snaps[1].rx_count;
        let last_sequence = world.snaps[0]
            .app_tx
            .iter()
            .map(|tx| tx.seq)
            .max()
            .unwrap_or(0);
        world.peers[0].app_send(NODE_A, &index.to_le_bytes());
        world.peers[2].app_send(testkit::GATEWAY, b"relay-load");
        world.pump_until(200, |snaps| {
            snaps[1].rx_count > received
                && snaps[0]
                    .app_tx
                    .iter()
                    .any(|tx| tx.seq > last_sequence && tx.state == DELIVERY_DELIVERED)
        });
        assert_eq!(world.snaps[1].rx_count, received + 1, "message {index}");
        assert_eq!(world.snaps[1].rx, index.to_le_bytes(), "payload {index}");
        assert!(
            world.snaps[0]
                .app_tx
                .iter()
                .any(|tx| tx.seq > last_sequence && tx.state == DELIVERY_DELIVERED),
            "message {index} sender receipt: {:?}",
            world.snaps[0].app_tx
        );
        assert_eq!(world.snaps[0].phases[2], PHASE_REACHABLE);
        assert_eq!(world.snaps[2].phases[1], PHASE_REACHABLE);
    }
    while world.now - started < 3_600_000 {
        world.step(100);
    }
    assert_eq!(
        world.snaps[1].rx_count,
        baseline + 100,
        "100 distinct receives"
    );
    assert_eq!(world.snaps[0].peer_capacity, capacity, "no capacity leak");
    assert_eq!(world.snaps[0].no_route, no_route, "no route diagnostic");
    assert_eq!(world.snaps[0].phases[2], PHASE_REACHABLE);
    assert_eq!(world.snaps[2].phases[1], PHASE_REACHABLE);
}

/// A multi-page flat table keeps its advertisement pending through queue
/// pressure and one lost RouteUpdate, so the two-hop route stays usable.
#[test]
fn mesh_route_loss_advertisement_survives_queue_pressure() {
    let Some(mut world) = route_loss_world("route-advertisement", Switch::forced_multihop(), true)
    else {
        return;
    };
    for index in 0..14 {
        let (ok, _) = world.peers[2].peer_slot(b'V', index);
        assert!(ok, "extra route record {index}");
    }
    world.step(25);
    assert!(world.snaps[2].queued >= 16, "multi-page queue reached 50%");
    let (accepted, queued) = world.peers[2].app_burst(16, testkit::GATEWAY);
    assert_eq!(accepted, 8, "bounded application admission");
    assert!(queued >= 16);
    world.step(5000);
    assert!(world.snaps[2].queued >= 26, "queue reached 80%");
    assert!(world.snaps[2].admissions_rejected > 0);
    let (accepted, _) = world.peers[0].app_burst(8, NODE_A);
    let mut max_queue = world.snaps[2].queued;
    for _ in 0..200 {
        world.step(25);
        max_queue = max_queue.max(world.snaps[2].queued);
    }
    assert_eq!(accepted, 8);
    assert!(max_queue >= 31, "application lane reached full occupancy");
    let updates = world.switch.route_updates_seen;
    world.switch.drop_wire_kind(2, 0, WIRE_ROUTE_UPDATE, 1);
    let start = world.now;
    let mut delivered = 0;
    while world.now - start < 20_000 {
        world.step(25);
        if world.now - start >= (delivered + 1) * 2000 {
            let received = world.snaps[1].rx_count;
            world.peers[0].app_send(NODE_A, b"route-kept");
            world.pump_until(200, |snaps| snaps[1].rx_count > received);
            assert_eq!(world.snaps[1].rx_count, received + 1);
            delivered += 1;
        }
    }
    assert_eq!(world.switch.wire_dropped, 1, "advertisement loss fired");
    assert!(
        world.switch.route_updates_seen > updates + 1,
        "later page retried"
    );
    assert_eq!(world.snaps[0].phases[2], PHASE_REACHABLE);
    assert_eq!(world.snaps[2].phases[1], PHASE_REACHABLE);
}

/// Phase-1 convergence on the direct radio: all three Owners adopt
/// from their Phase-0 images (member boots, no rejoins), open their
/// authority channels through the gateway's real USB relay, confirm,
/// and exchange app traffic over the real mesh.
#[test]
fn mesh_direct_converges_and_delivers() {
    let Some(mut world) = MeshWorld::start("direct", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    // Member boots: the adopted network matches the site, the lifecycle
    // is Active, the channels are ready and the joins confirmed — with
    // the gateway USB session authenticated for real.
    world.pump_until(6000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
                && s.has_site
        })
    });
    let active = world.active_gk();
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.mode, MODE_MEMBER, "peer {index} adopted");
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active");
        assert!(snap.authority_ready, "peer {index} channel ready");
        assert!(snap.join_confirmed, "peer {index} confirmed");
        assert!(snap.has_site, "peer {index} holds its site");
        assert!(snap.has_identity, "peer {index} holds its identity");
        assert!(snap.stores_healthy, "peer {index} stores healthy");
        assert_eq!(snap.site_generation, 1, "peer {index} generation");
        assert_eq!(snap.gk_current, active, "peer {index} on the active GK");
        assert_eq!(
            snap.adopted_network,
            testkit::network(),
            "peer {index} on the site network"
        );
        assert!(snap.sends > 0, "peer {index} used its radio");
    }
    // Real pairwise sessions came up, not just the authority lane.
    assert!(
        world.snaps[1].link_sessions > 0 && world.snaps[1].end_sessions > 0,
        "member A sessions: {:?}",
        world.snaps[1]
    );
    assert!(world.switch.delivered > 0, "frames crossed the switch");
    assert_eq!(
        world.switch.dropped, 0,
        "direct radio drops nothing: {}",
        world.switch.dropped
    );
    // The Owner counters reach the observer.
    for (index, snap) in world.snaps.iter().enumerate() {
        assert!(
            snap.owner_polls > snap.owner_empty_polls
                && snap.owner_empty_polls > 0
                && snap.rx_queue_max > 0
                && snap.expiry_slots_scanned > 0,
            "peer {index} owner counters: {snap:?}"
        );
    }
    assert_eq!(
        world.usb_host.auth_sessions.len(),
        1,
        "one gateway USB session, no re-hello loop"
    );
    assert_eq!(world.usb_host.hello_node, Some(testkit::GATEWAY));
    assert_eq!(world.usb_host.hello_network, Some(testkit::network()));
    assert_eq!(world.usb_host.hello_capability, Some(USB_CAP));
    assert_eq!(world.usb_host.session_losses, 0, "USB session held");
    assert!(
        world.usb_host.ups_seen > 0 && world.usb_host.downs_sent > 0,
        "authority carriers crossed the real USB both ways"
    );
    assert_eq!(world.snaps[0].usb_state, USB_ACTIVE);
    for node in world.nodes.clone() {
        let row = world.member_row(node).expect("member row");
        assert!(row.member && row.confirmed, "node {node:x} confirmed");
    }
    assert_eq!(
        world.member_row(NODE_A).expect("A row").role,
        if world.peers[1].role == ROLE_ENDPOINT {
            1
        } else {
            2
        }
    );
    // App traffic member A -> member B over the real mesh.
    let payload = b"mesh-direct-hello";
    world.peers[1].app_send(NODE_B, payload);
    world.pump_until(3000, |snaps| {
        snaps[2].rx_count > 0
            && snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    assert_eq!(world.snaps[2].rx_src, NODE_A);
    assert_eq!(&world.snaps[2].rx[..payload.len()], payload);
}

/// Forced multi-hop: A and the gateway cannot hear each other, so
/// A<->gateway traffic and A's authority channel relay via B. Delivery
/// through the switch proves the relay — direct frames cannot exist.
#[test]
fn mesh_forced_multihop_relays() {
    let Some(mut world) = MeshWorld::start("multihop", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    // All three boot together; A reaches the gateway only through B.
    world.pump_until(9000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
        })
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.mode, MODE_MEMBER, "peer {index} adopted");
        assert!(snap.authority_ready, "peer {index} channel ready");
        assert!(snap.join_confirmed, "peer {index} confirmed");
    }
    // A -> gateway app traffic must relay via B.
    let payload = b"mesh-multihop-hello";
    world.peers[1].app_send(testkit::GATEWAY, payload);
    world.pump_until(3000, |snaps| {
        snaps[0].rx_count > 0
            && snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "A->gateway delivered via relay: {:?}",
        world.snaps[1].app_tx
    );
    assert_eq!(world.snaps[0].rx_src, NODE_A);
    assert_eq!(&world.snaps[0].rx[..payload.len()], payload);
}

/// Boots a world outward from the gateway: nodes 2.. stay off the air
/// until every node before them converged (`converge_gated` applied
/// hop by hop, so no contender parks its M1 behind a busy relay).
pub(super) fn converge_outward(world: &mut MeshWorld, what: &str) {
    let nodes = world.peers.len();
    for gated in 2..nodes {
        world.gate[gated] = true;
    }
    for ready in 2..=nodes {
        world.pump_until(9000, |snaps| {
            snaps[..ready].iter().all(|s| {
                s.mode == MODE_MEMBER
                    && s.phase == PHASE_ACTIVE
                    && s.authority_ready
                    && s.join_confirmed
            })
        });
        assert!(
            world.snaps[..ready]
                .iter()
                .all(|s| s.authority_ready && s.join_confirmed),
            "{what}: nodes 0..{ready} converged: {:?}",
            world.snaps
        );
        if ready < nodes {
            world.gate[ready] = false;
        }
    }
}

/// Reliable sends from `from` to `to`, one at a time to its terminal
/// state within the 30 s send lifetime: each is delivered exactly once
/// with its payload and source, and the sender holds the receipt.
pub(super) fn deliver_each(
    world: &mut MeshWorld,
    from: usize,
    to: usize,
    count: u32,
    label: &[u8],
) {
    let dst = world.nodes[to];
    let base = world.snaps[to].rx_count;
    for index in 0..count {
        let received = world.snaps[to].rx_count;
        let last = world.snaps[from]
            .app_tx
            .iter()
            .map(|tx| tx.seq)
            .max()
            .unwrap_or(0);
        let payload = [label, &index.to_le_bytes()].concat();
        world.peers[from].app_send(dst, &payload);
        let done = |snaps: &[MeshSnap]| {
            snaps[to].rx_count > received
                && snaps[from]
                    .app_tx
                    .iter()
                    .any(|tx| tx.seq > last && tx.state == DELIVERY_DELIVERED)
        };
        world.pump_until(1200, done);
        assert!(
            done(&world.snaps),
            "{from}->{to} message {index}: {:?}",
            world.snaps[from].app_tx
        );
        assert_eq!(
            world.snaps[to].rx_count,
            received + 1,
            "message {index} once"
        );
        assert_eq!(world.snaps[to].rx, payload, "message {index} payload");
        assert_eq!(world.snaps[to].rx_src, world.nodes[from]);
    }
    // Late duplicates would land after the receipts: let them.
    for _ in 0..200 {
        world.step(25);
    }
    assert_eq!(
        world.snaps[to].rx_count,
        base + count,
        "no duplicate delivery"
    );
}

/// M01 (T3): G—A—B—C, three hops end to end. Twenty Reliable messages
/// each way between the gateway and the far leaf arrive exactly once,
/// and every frame crossed only the chain's legs.
///
/// Red today: the three-hop leaf's end-to-end handshake with the
/// gateway expires (end_last_error Expired) — the chunked m2 needs longer
/// over three hops than the initiator's resends last — and it never gets
/// its authority channel (tests/e2e/scenarios.json M01-T3).
#[test]
#[ignore = "M01-T3 red: three-hop end-to-end handshake expires"]
fn mesh_line_three_hops_delivers() {
    let Some(mut world) = MeshWorld::start("line-three-hops", Switch::new(&Topology::line(4)))
    else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_outward(&mut world, "three-hop line");
    let leaf = world.index_of(NODE_B + 1);
    assert_eq!(leaf, 3);
    let before = world.switch.leg_delivered.clone();
    deliver_each(&mut world, leaf, 0, 20, b"up");
    deliver_each(&mut world, 0, leaf, 20, b"down");
    for (a, b) in (0..4).flat_map(|a| (0..4).map(move |b| (a, b))) {
        let crossed = world.switch.leg_delivered[a][b] - before[a][b];
        if a.abs_diff(b) == 1 {
            assert!(crossed > 0, "leg {a}->{b} carried the traffic");
        } else {
            assert_eq!(crossed + before[a][b], 0, "no shortcut {a}->{b}");
        }
    }
}

/// M01 (TD under noise, G4): G—R1—E and G—R2—E with seeded 2% loss,
/// 1% duplication, 1% reordering and up to 20 ms jitter on every leg.
/// Twenty Reliable messages each way still arrive exactly once, and the
/// noise demonstrably fired.
#[test]
fn mesh_diamond_delivers_under_leg_noise() {
    let Some(mut world) = MeshWorld::start("diamond-noise", Switch::new(&Topology::diamond()))
    else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_outward(&mut world, "diamond");
    let leaf = world.index_of(world.nodes[3]);
    assert_eq!(world.snaps[1].phases.len(), world.peers.len());
    assert!(
        world.snaps[1].phases[leaf] == PHASE_REACHABLE
            || world.snaps[2].phases[leaf] == PHASE_REACHABLE,
        "the leaf binds to a diamond relay"
    );
    world.switch.set_noise(
        LegNoise {
            loss_ppm: 20_000,
            dup_ppm: 10_000,
            reorder_ppm: 10_000,
            jitter_ms: 20,
        },
        0x6E01_5E00,
    );
    deliver_each(&mut world, 3, 0, 20, b"up");
    deliver_each(&mut world, 0, 3, 20, b"down");
    let hits = world.switch.noise_hits;
    assert!(
        hits.lost > 0 && hits.duplicated > 0 && hits.reordered > 0 && hits.jittered > 0,
        "every noise kind fired: {hits:?}"
    );
    assert_eq!(world.switch.leg_delivered[0][3], 0, "no G—E leg");
    assert_eq!(world.switch.leg_delivered[1][2], 0, "no R1—R2 leg");
}

#[test]
fn mesh_provision_snapshot_reused_without_shared_world_state() {
    use routeloom_client::site::RemovalReason;
    use std::os::unix::fs::PermissionsExt;
    let Some(mut first) = MeshWorld::start("phase0-first", Switch::direct()) else {
        return;
    };
    let dir = &first.provision.site.dir;
    assert_eq!(
        std::fs::metadata(dir).unwrap().permissions().mode() & 0o777,
        0o700,
        "world directory holds copied credentials"
    );
    for name in [
        "site.db",
        "phase0-a1000000000101-flash.bin",
        "phase0-a1000000000101-flash-ext.bin",
    ] {
        assert_eq!(
            std::fs::metadata(dir.join(name))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "{name} holds copied credentials"
        );
    }
    converge(&mut first, "first snapshot world");
    let initial_epoch = first.active_gk();
    let row = first.member_row(NODE_A).expect("A is a member");
    first
        .provision
        .site
        .link
        .revoke(
            NODE_A,
            row.generation,
            RemovalReason::Removed,
            "phase0-isolation",
        )
        .expect("first world revocation commits");
    assert!(!first.member_row(NODE_A).expect("revoked row").member);
    drop(first);

    let Some(mut second) = MeshWorld::start("phase0-second", Switch::direct()) else {
        return;
    };
    assert_eq!(
        second.phase0_wall_ms, 0,
        "Phase 0 runs only once per topology size"
    );
    assert_eq!(second.active_gk(), initial_epoch);
    assert!(
        second
            .member_row(NODE_A)
            .expect("independent member row")
            .member
    );
    converge(&mut second, "reused snapshot world");
    let before = second.snaps[0].rx_count;
    second.peers[1].app_send(testkit::GATEWAY, b"snapshot-reused");
    second.pump_until(2000, |snaps| snaps[0].rx_count > before);
    assert_eq!(second.snaps[0].rx, b"snapshot-reused");
}

#[test]
fn mesh_profile_role_above_profile_refused() {
    let peers: Vec<std::path::PathBuf> = ["ROUTELOOM_MESH_PEER_A", "ROUTELOOM_MESH_PEER_B"]
        .iter()
        .filter_map(|key| std::env::var_os(key).map(std::path::PathBuf::from))
        .collect();
    for (index, path) in peers.iter().enumerate() {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-owner-mesh-role-{}-{index}-{}",
            std::process::id(),
            now_ms()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let output = Command::new(path)
            .args(["--node", &format!("{NODE_B:#x}"), "--mac", &hex(&MAC_B)])
            .args(["--role", &format!("{ROLE_GW}")])
            .args(["--t0", "1000", "--seed", "7", "--gateway", "--channel", "6"])
            .args(["--netlow", &format!("{:#x}", testkit::NETWORK_LOW)])
            .args(["--gw1", &format!("{:#x}", testkit::GATEWAY)])
            .args(["--usb-secret", &hex(&[0x11; 32])])
            .args(["--cap", &format!("{USB_CAP}")])
            .arg("--nvs-save")
            .arg(dir.join("nvs.bin"))
            .stdin(Stdio::null())
            .stderr(Stdio::inherit())
            .output()
            .expect("spawn profile peer");
        let _ = std::fs::remove_dir_all(&dir);
        let mut frames = Vec::new();
        let mut rest = output.stdout.as_slice();
        while rest.len() >= 2 {
            let length = usize::from(u16::from_le_bytes([rest[0], rest[1]]));
            assert!(
                rest.len() >= 2 + length,
                "{}: truncated frame",
                path.display()
            );
            frames.push(rest[2..2 + length].to_vec());
            rest = &rest[2 + length..];
        }
        assert!(rest.is_empty(), "{}: trailing bytes", path.display());
        assert_eq!(frames.len(), 1, "{}: only the fatal frame", path.display());
        assert_eq!(frames[0][0], b'E', "{}: fatal frame", path.display());
        assert_eq!(
            String::from_utf8_lossy(&frames[0][1..]),
            "RESOURCE_PROFILE_ROLE_MISMATCH",
            "{}",
            path.display()
        );
        assert!(!output.status.success(), "{}: exit status", path.display());
    }
    if let Some(path) = std::env::var_os("ROUTELOOM_MESH_PEER_A") {
        let output = Command::new(&path)
            .args(["--node", &format!("{NODE_A:#x}"), "--mac", &hex(&MAC_A)])
            .args(["--role", &format!("{ROLE_ENDPOINT}"), "--join-cap", "3"])
            .args(["--t0", "1000", "--seed", "7", "--member", "--channel", "6"])
            .output()
            .expect("spawn endpoint with relay capability");
        assert!(
            !output.status.success(),
            "over-profile join capability accepted"
        );
        assert!(output.stdout.len() >= 3, "missing fatal frame");
        let length = usize::from(u16::from_le_bytes([output.stdout[0], output.stdout[1]]));
        assert_eq!(output.stdout.len(), length + 2, "only one fatal frame");
        assert_eq!(output.stdout[2], b'E', "fatal frame tag");
        assert_eq!(
            &output.stdout[3..],
            b"RESOURCE_PROFILE_ROLE_MISMATCH",
            "role mismatch reason"
        );
    }
}
