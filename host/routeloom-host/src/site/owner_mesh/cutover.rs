//! Site-epoch cutover rows (tests/e2e/scenarios.json J09, J10).

use super::*;

/// #168 cutover over the real mesh: stage epoch+1, every node (real
/// gateway included) prepares over its own channel, the commit lands
/// past the window, all adopt the new network/GK, re-open channels
/// (USB re-auth), and new-epoch traffic flows with no straggler.
#[test]
fn mesh_cutover_prepare_commit_applied() {
    use routeloom_client::site::SiteAdmin;
    use routeloom_provision::signer::FileRootSigner;
    let Some(mut world) = MeshWorld::start("cutover", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    world.pump_until(6000, |snaps| {
        snaps.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.authority_ready
                && s.join_confirmed
        })
    });
    assert!(
        world.snaps.iter().all(|s| s.authority_ready),
        "mesh converged before cutover"
    );

    let site_ca = FileRootSigner::from_secret(testkit::SITE_CA, &test_keypair(0x61).0).unwrap();
    let next_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Site,
            issuer: testkit::SITE_CA,
            subject: testkit::SITE,
            pubkey: test_keypair(0x62).1,
            network_low32: testkit::NETWORK_LOW,
            site_epoch: testkit::SITE_EPOCH + 1,
            usage: 1,
            serial: 8,
            ..CertClaims::default()
        },
        &site_ca,
    )
    .unwrap();
    // Stage through the service with the virtual clock: the API socket
    // stamps operations with the process monotonic clock while the
    // harness ticks the authority on wall-based virtual time, which
    // would lapse the 600 s prepare window instantly (harness-only
    // clock mixup — the production daemon runs one clock).
    let staged_at = world.now;
    let outcome_json = world
        .provision
        .site
        .service
        .with(|a| {
            a.cutover(
                501,
                crate::site::cutover::CutoverRequest {
                    expected_site_epoch: testkit::SITE_EPOCH,
                    next_site_cert: next_cert.clone(),
                    key: "mesh-cut-1".into(),
                },
                HostTime::sync(world.now),
            )
        })
        .0
        .expect("cutover stages");
    let outcome_value: routeloom_json::Json =
        routeloom_json::parse(&outcome_json).expect("outcome parses");
    assert_eq!(
        outcome_value.get("state").and_then(|v| v.as_str()),
        Some("preparing")
    );
    let operation_id = outcome_value
        .get("operation_id")
        .and_then(|v| v.as_str())
        .expect("operation id")
        .to_string();

    // PREPARE lands over each channel; every node stages the epoch.
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.phase, PHASE_PREPARED,
            "peer {index} prepared: {snap:?}"
        );
    }

    // The peers' PREPARE receipts are still in flight when they stage:
    // drain them at 25 ms until the Owner has seen every target's
    // receipt before fast-forwarding. A queued carrier debits its
    // routed TTL while it waits, and a 1 s step ages it past the
    // receiver's dead-on-arrival gate — the same harness artifact as
    // the commit legs below.
    for _ in 0..4000 {
        let targets = world.cutover_targets(&operation_id);
        if !targets.is_empty() && targets.iter().all(|(_, state, _, _)| state == "prepared") {
            break;
        }
        world.step(25);
    }

    // Past the window the commit lands; all adopt the new network,
    // its GK, and re-open the channel there (USB re-auth included).
    // The stable window fast-forwards in 1 s steps ONLY while the
    // air is silent: a 1 s step stamps a full second of RX age on
    // every delivered frame, and one that also carries send-queue
    // delay dies on the receiver's dead-on-arrival gate — the same
    // harness artifact as the commit legs below (the design
    // promises no radio that jumps). Busy air ticks at 25 ms.
    let window_end = staged_at + crate::site::cutover::CUTOVER_PREPARE_WINDOW_MS;
    let mut quiet_ms = 0u64;
    while world.now + 10_000 < window_end {
        let delivered_before = world.switch.delivered;
        let jump = quiet_ms >= 3_000;
        world.step(if jump { 1_000 } else { 25 });
        quiet_ms = if world.switch.delivered == delivered_before {
            quiet_ms.saturating_add(if jump { 1_000 } else { 25 })
        } else {
            0
        };
    }
    for _ in 0..4000 {
        let phase = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.phase)
            .unwrap_or_default();
        if phase != "preparing" && phase != "waiting_gateway" {
            break;
        }
        world.step(25);
    }
    let (next_gk, new_network) = world
        .provision
        .site
        .service
        .with(|a| {
            let op = crate::site::records::parse_op_token(&operation_id).unwrap();
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.new_network)
        })
        .0;
    // Adoption converges when the peers are Active on the new
    // network/GK with re-opened channels AND their APPLIEDs landed: a
    // fresh Ready still has its APPLIED in flight (relay + USB +
    // authority ticks behind), so peer convergence alone is too eager.
    for _ in 0..8000 {
        world.step(25);
        let peers_done = world.snaps.iter().all(|s| {
            s.phase == PHASE_ACTIVE
                && s.adopted_network == new_network
                && s.gk_current == next_gk
                && s.authority_ready
        });
        if peers_done {
            let applied = world
                .provision
                .site
                .link
                .cutover_operation(&operation_id)
                .unwrap()
                .map(|p| p.applied)
                .unwrap_or(0);
            if applied == 3 {
                break;
            }
        }
    }
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active: {snap:?}");
        assert_eq!(
            snap.adopted_network, new_network,
            "peer {index} on the new network: {snap:?}"
        );
        assert_eq!(
            snap.gk_current, next_gk,
            "peer {index} on the new GK: {snap:?}"
        );
        assert!(
            snap.authority_ready,
            "peer {index} channel re-open: {snap:?}"
        );
    }
    // No straggler: every target applied, no recovery parking.
    let progress = world
        .provision
        .site
        .link
        .cutover_operation(&operation_id)
        .unwrap()
        .expect("cutover tracked");
    assert!(
        !progress.recovery_pending,
        "no straggler parked: {progress:?}"
    );
    assert_eq!(progress.applied, 3, "all targets applied: {progress:?}");
    // Adoption reboots exactly once per peer (#168: the retired
    // AdoptNetwork must reboot, never wait and never loop), and the
    // rebooted gateway re-authenticates its USB session (HIL R4).
    assert_eq!(
        [
            world.peers[0].reboots,
            world.peers[1].reboots,
            world.peers[2].reboots
        ],
        [1, 1, 1],
        "one adoption reboot each"
    );
    assert_eq!(
        world.usb_auth_total(),
        2,
        "gateway USB re-authenticated after its reboot"
    );

    // New-epoch traffic flows member to member.
    let payload = b"mesh-cutover-hello";
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
        "new-epoch A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    assert_eq!(&world.snaps[2].rx[..payload.len()], payload);
}

/// Stages a site-epoch cutover through the service on the virtual
/// clock (not the API socket's process clock — the 600 s prepare
/// window would lapse instantly otherwise; same harness-only mixup
/// the GK rotations work around). Returns the operation id.
pub(super) fn stage_cutover(world: &mut MeshWorld, key: &str) -> String {
    use routeloom_provision::signer::FileRootSigner;
    let site_ca = FileRootSigner::from_secret(testkit::SITE_CA, &test_keypair(0x61).0).unwrap();
    let next_cert = cert_issue(
        &CertClaims {
            cert_type: CertType::Site,
            issuer: testkit::SITE_CA,
            subject: testkit::SITE,
            pubkey: test_keypair(0x62).1,
            network_low32: testkit::NETWORK_LOW,
            site_epoch: testkit::SITE_EPOCH + 1,
            usage: 1,
            serial: 8,
            ..CertClaims::default()
        },
        &site_ca,
    )
    .unwrap();
    let outcome_json = world
        .provision
        .site
        .service
        .with(|a| {
            a.cutover(
                501,
                crate::site::cutover::CutoverRequest {
                    expected_site_epoch: testkit::SITE_EPOCH,
                    next_site_cert: next_cert.clone(),
                    key: key.into(),
                },
                HostTime::sync(world.now),
            )
        })
        .0
        .expect("cutover stages");
    let outcome_value: routeloom_json::Json =
        routeloom_json::parse(&outcome_json).expect("outcome parses");
    assert_eq!(
        outcome_value.get("state").and_then(|v| v.as_str()),
        Some("preparing")
    );
    outcome_value
        .get("operation_id")
        .and_then(|v| v.as_str())
        .expect("operation id")
        .to_string()
}

/// C1 (§5.2): healthy adoption from the leaves. Everyone holds the
/// latest PREPARED, then COMMITs dispatch leaf-first along the route
/// tree: no parent's COMMIT is sent (or adopted) before its child's
/// COMMIT_STORED verifies, parents still advance while APPLIED is 0,
/// and the run ends 3/0/0 with one adoption reboot each, a fresh USB
/// session, and bidirectional new-network delivery. `leaf`/`relay`
/// are peer indices; the direct gateway—leaf legs must stay silent.
pub(super) fn c1_once(tag: &str, switch: Switch, gate: usize, leaf: usize, relay: usize) {
    use routeloom_client::site::SiteAdmin;
    let nodes = [testkit::GATEWAY, NODE_A, NODE_B];
    let Some(mut world) = MeshWorld::start(tag, switch) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, gate, "c1 cutover");
    // Pre-cutover delivery works end to end (leaf to gateway).
    world.peers[leaf].app_send(testkit::GATEWAY, b"c1-before");
    world.pump_until(3000, |snaps| {
        snaps[leaf]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[leaf]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "pre-cutover leaf->gateway delivered: {:?}",
        world.snaps[leaf].app_tx
    );

    let staged_at = world.now;
    let operation_id = stage_cutover(&mut world, tag);
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.phase, PHASE_PREPARED,
            "peer {index} prepared: {snap:?}"
        );
    }
    // Everyone holds the latest PREPARED: same revision everywhere.
    // (The host-side ACKs lag the peer phases by a relay+USB beat.)
    for _ in 0..1000 {
        let targets = world.cutover_targets(&operation_id);
        if targets.len() == 3 && targets.iter().all(|t| t.1 == "prepared") {
            break;
        }
        world.step(25);
    }
    let targets = world.cutover_targets(&operation_id);
    assert_eq!(targets.len(), 3, "three targets: {targets:?}");
    assert!(
        targets.iter().all(|t| t.1 == "prepared"),
        "all prepared: {targets:?}"
    );
    assert_eq!(targets[0].2, targets[1].2, "same revision: {targets:?}");
    assert_eq!(targets[1].2, targets[2].2, "same revision: {targets:?}");

    // Fast-forward to just before the window end, then sample the
    // COMMIT dispatch at full resolution: send ticks (a target
    // leaving Prepared post-commit), stored ticks (verified
    // COMMIT_STORED), and the applied count at each parent send.
    // Keep the radio's normal resolution throughout the window. A coarse
    // clock jump also ages queued control frames and delayed callbacks;
    // silence in the previous step does not prove the next step is idle.
    let window_end = staged_at + crate::site::cutover::CUTOVER_PREPARE_WINDOW_MS;
    while world.now + 10_000 < window_end {
        world.step(25);
    }
    let mut send_tick = [None::<u64>; 3];
    let mut stored_tick = [None::<u64>; 3];
    let mut applied_at_send = [None::<u64>; 3];
    let mut phase_at_send = [PHASE_PREPARED; 3];
    for _ in 0..12000 {
        world.step(25);
        let phase = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.phase)
            .unwrap_or_default();
        if phase == "preparing" || phase == "waiting_gateway" {
            continue;
        }
        let progress = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .expect("cutover tracked");
        let targets = world.cutover_targets(&operation_id);
        for (index, node) in nodes.iter().enumerate() {
            // COMMIT dispatch is attempts-observed: sends never move
            // GrantState (only receipts do), and attempts restart at
            // zero on commit — the first post-commit attempt is the
            // dispatch tick the tree order governs.
            let dispatched = targets
                .iter()
                .find(|t| t.0 == *node)
                .map(|t| t.3 > 0)
                .unwrap_or(false);
            if send_tick[index].is_none() && dispatched {
                send_tick[index] = Some(world.now);
                applied_at_send[index] = Some(progress.applied);
                phase_at_send[index] = world.snaps[index].phase;
            }
            if stored_tick[index].is_none() {
                let stored = world
                    .cutover_route(&operation_id, *node)
                    .map(|plan| plan.stored)
                    .unwrap_or(false);
                if stored {
                    stored_tick[index] = Some(world.now);
                }
            }
        }
        let done = world.snaps.iter().all(|s| s.phase == PHASE_ACTIVE) && progress.applied == 3;
        // The root's stored gates nothing (nobody waits for it), so
        // only the gated children must show receipts.
        if done
            && send_tick.iter().all(|t| t.is_some())
            && stored_tick[leaf].is_some()
            && stored_tick[relay].is_some()
        {
            break;
        }
    }
    // The leaf's COMMIT is sent and verified before the relay's is
    // sent; the relay's before the gateway's. Neither parent adopts
    // (leaves Prepared) before its child's receipt verifies, and both
    // parents advance while APPLIED is still 0.
    assert!(
        send_tick.iter().all(Option::is_some),
        "every target sent: send={send_tick:?} stored={stored_tick:?} targets={:?} routes={:?}",
        world.cutover_targets(&operation_id),
        nodes.map(|node| world.cutover_route(&operation_id, node))
    );
    let send = send_tick.map(Option::unwrap);
    let stored_leaf = stored_tick[leaf].expect("leaf stored");
    let stored_relay = stored_tick[relay].expect("relay stored");
    let stored = [stored_tick[0], stored_tick[1], stored_tick[2]];
    assert!(
        send[leaf] < stored_leaf,
        "leaf sent before its stored verifies: send={send:?} stored={stored:?}"
    );
    // Cross-target gates admit the same tick: the host verifies a
    // STORED and releases the parent in one tick (receipts drain before
    // dispatch), which is causally after, not simultaneous.
    assert!(
        stored_leaf <= send[relay],
        "relay waits for the leaf receipt: send={send:?} stored={stored:?}"
    );
    assert!(
        stored_relay <= send[0],
        "gateway waits for the relay receipt: send={send:?} stored={stored:?}"
    );
    assert!(
        applied_at_send[relay] == Some(0),
        "relay advances while APPLIED is 0: {applied_at_send:?}"
    );
    assert!(
        applied_at_send[0] == Some(0),
        "gateway advances while APPLIED is 0: {applied_at_send:?}"
    );
    assert_eq!(
        phase_at_send[relay], PHASE_PREPARED,
        "relay still prepared at its send (adopts after)"
    );
    assert_eq!(
        phase_at_send[0], PHASE_PREPARED,
        "gateway still prepared at its send (adopts after)"
    );

    // Adoption converges on the new network/GK with re-opened
    // channels and all APPLIEDs landed.
    let (next_gk, new_network) = world
        .provision
        .site
        .service
        .with(|a| {
            let op = crate::site::records::parse_op_token(&operation_id).unwrap();
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.new_network)
        })
        .0;
    for _ in 0..8000 {
        world.step(25);
        let peers_done = world.snaps.iter().all(|s| {
            s.phase == PHASE_ACTIVE
                && s.adopted_network == new_network
                && s.gk_current == next_gk
                && s.authority_ready
        });
        if peers_done {
            let applied = world
                .provision
                .site
                .link
                .cutover_operation(&operation_id)
                .unwrap()
                .map(|p| p.applied)
                .unwrap_or(0);
            if applied == 3 {
                break;
            }
        }
    }
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active: {snap:?}");
        assert_eq!(
            snap.adopted_network, new_network,
            "peer {index} on the new network: {snap:?}"
        );
        assert_eq!(
            snap.gk_current, next_gk,
            "peer {index} on the new GK: {snap:?}"
        );
        assert!(snap.authority_ready, "peer {index} channel re-open");
    }
    let progress = world
        .provision
        .site
        .link
        .cutover_operation(&operation_id)
        .unwrap()
        .expect("cutover tracked");
    assert!(
        !progress.recovery_pending,
        "no straggler parked: {progress:?}"
    );
    assert_eq!(progress.applied, 3, "APPLIED=3: {progress:?}");
    assert_eq!(progress.recovered, 0, "recovered=0: {progress:?}");
    assert_eq!(progress.unknown, 0, "unknown=0: {progress:?}");
    assert_eq!(
        [
            world.peers[0].reboots,
            world.peers[1].reboots,
            world.peers[2].reboots
        ],
        [1, 1, 1],
        "one adoption reboot each"
    );
    assert_eq!(
        world.usb_auth_total(),
        2,
        "gateway USB re-authenticated after its reboot"
    );

    // Bidirectional new-network delivery, gateway to leaf and back.
    let payload = b"c1-down";
    world.peers[0].app_send(nodes[leaf], payload);
    let leaf_rx = world.snaps[leaf].rx_count;
    world.pump_until(3000, |snaps| snaps[leaf].rx_count > leaf_rx);
    assert!(
        world.snaps[leaf].rx_count > leaf_rx,
        "gateway->leaf delivered: {:?}",
        world.snaps[leaf]
    );
    assert_eq!(&world.snaps[leaf].rx[..payload.len()], payload);
    let payload = b"c1-upxx";
    world.peers[leaf].app_send(testkit::GATEWAY, payload);
    world.pump_until(3000, |snaps| {
        snaps[leaf]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[leaf]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "leaf->gateway delivered: {:?}",
        world.snaps[leaf].app_tx
    );

    // The direct gateway—leaf path stayed silent: everything the leaf
    // got came down the tree through the relay.
    assert_eq!(
        world.switch.leg_delivered[0][leaf], 0,
        "no direct gateway->leaf frame"
    );
    assert_eq!(
        world.switch.leg_delivered[leaf][0], 0,
        "no direct leaf->gateway frame"
    );
}

#[test]
fn mesh_c1_tree_ordered_adoption() {
    // Forward: G—B—A, where the tree order (A first) coincides with
    // the NodeId order — the scheduler must use the tree anyway.
    c1_once("c1-fwd", Switch::forced_multihop(), 1, 1, 2);
    // Reversed: G—A—B, where the tree order (B first) runs against
    // the NodeId order under the same conditions.
    let mut reversed = Switch::direct();
    reversed.set_audible(0, 2, false);
    reversed.set_audible(2, 0, false);
    c1_once("c1-rev", reversed, 2, 2, 1);
}

/// The decider-visible join requests currently open for one node (C2: the
/// ZT auto-reissue must not open any — "人手 allow 操作は 0" is the
/// absence of new requests, not a served decision).
pub(super) fn decider_requests_for(world: &MeshWorld, node: u64) -> usize {
    world
        .provision
        .site
        .service
        .with(|a| a.requests.values().filter(|r| r.facts.node == node).count())
        .0
}

/// C2 (§5.2): the leaf misses the whole COMMIT while everyone else
/// adopts. `island` selects the variant: only A's downstream dies
/// (G and B switch inside the deadline, A stays Prepared-unknown),
/// or G is cut from the B/A island (G adopts alone, the island
/// keeps old-network mutual comms, both stay unknown). Past the
/// grace the fault clears and the stragglers must come back through
/// the ZT auto-reissue — Recovered, never Applied, with no decider
/// request opened for them.
pub(super) fn c2_once(tag: &str, island: bool) {
    c2_with_policy(tag, island, false);
}

fn c2_with_policy(tag: &str, island: bool, closed: bool) {
    use routeloom_client::site::SiteAdmin;
    let Some(mut world) = MeshWorld::start(tag, Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "c2 cutover");
    if closed {
        for peer in &mut world.peers {
            peer.smart_join_policy(true, true, 60000);
        }
        world
            .provision
            .site
            .service
            .with(|a| {
                a.update_policy(&crate::site::PolicyPatch {
                    zero_touch_open: Some(false),
                    ..crate::site::PolicyPatch::default()
                })
            })
            .0
            .expect("closed policy durable");
        for _ in 0..1200 {
            let distribution = world
                .provision
                .site
                .service
                .with(|a| a.policy_distribution())
                .0;
            if distribution.proxies > 0 && distribution.applied == distribution.proxies {
                break;
            }
            world.step(25);
        }
        let distribution = world
            .provision
            .site
            .service
            .with(|a| a.policy_distribution())
            .0;
        assert_eq!(
            distribution.applied, distribution.proxies,
            "policy reached all proxies"
        );
    }
    let decider_a_before = decider_requests_for(&world, NODE_A);
    let decider_b_before = decider_requests_for(&world, NODE_B);

    let staged_at = world.now;
    let operation_id = stage_cutover(&mut world, tag);
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.phase, PHASE_PREPARED,
            "peer {index} prepared: {snap:?}"
        );
    }
    // The peers' PREPARE receipts are still in flight when they stage:
    // drain them at 25 ms until the Owner has seen every target's
    // receipt before fast-forwarding. A queued carrier debits its
    // routed TTL while it waits, and a 1 s step ages it past the
    // receiver's dead-on-arrival gate — the same harness artifact as
    // the commit legs below.
    for _ in 0..4000 {
        let targets = world.cutover_targets(&operation_id);
        if !targets.is_empty() && targets.iter().all(|(_, state, _, _)| state == "prepared") {
            break;
        }
        world.step(25);
    }
    let (next_gk, new_network, old_network) = world
        .provision
        .site
        .service
        .with(|a| {
            let op = crate::site::records::parse_op_token(&operation_id).unwrap();
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.new_network, state.old_network)
        })
        .0;

    // Fast-forward to the commit, then run the grace at full
    // resolution (same pacing as C1: the tree traffic needs it).
    // The stable window fast-forwards in 1 s steps ONLY while the
    // air is silent: a 1 s step stamps a full second of RX age on
    // every delivered frame, and one that also carries send-queue
    // delay dies on the receiver's dead-on-arrival gate. Busy air
    // ticks at 25 ms.
    let window_end = staged_at + crate::site::cutover::CUTOVER_PREPARE_WINDOW_MS;
    let mut quiet_ms = 0u64;
    while world.now + 10_000 < window_end {
        let delivered_before = world.switch.delivered;
        let jump = quiet_ms >= 3_000;
        world.step(if jump { 1_000 } else { 25 });
        quiet_ms = if world.switch.delivered == delivered_before {
            quiet_ms.saturating_add(if jump { 1_000 } else { 25 })
        } else {
            0
        };
    }
    for _ in 0..4000 {
        world.step(25);
        let phase = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.phase)
            .unwrap_or_default();
        if phase == "committed" {
            break;
        }
    }
    let t0 = world
        .provision
        .site
        .service
        .with(|a| {
            a.cutover_grace_until_mono
                .saturating_sub(crate::site::cutover::CUTOVER_GRACE_MS)
        })
        .0;
    assert!(
        t0 > staged_at,
        "durable COMMIT passed with a live grace: t0={t0} staged={staged_at}"
    );
    if island {
        // G—[B/A island] cut for the whole grace. The island keeps
        // old-Prepared-group mutual comms while G commits alone.
        world.switch.isolate(0);
        world.peers[1].app_send(NODE_B, b"c2-island");
        world.pump_until(3000, |snaps| {
            snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED)
        });
        assert!(
            world.snaps[1]
                .app_tx
                .iter()
                .any(|tx| tx.state == DELIVERY_DELIVERED),
            "island A->B delivers while Prepared: {:?}",
            world.snaps[1].app_tx
        );
    } else {
        // A's whole COMMIT dies downstream of the relay for the
        // grace: unicast only (broadcasts still cross, so discovery
        // survives — the fault is the transfer, not the radio).
        world.switch.drop_next[2][1] += 500;
    }
    // Run past D; the reachable side must have switched by then.
    let (want_applied, want_recovered) = if island { (1, 2) } else { (2, 1) };
    for _ in 0..4000 {
        world.step(25);
        if world.now < t0 + crate::site::cutover::CUTOVER_GRACE_MS + 5_000 {
            continue;
        }
        let applied = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.applied)
            .unwrap_or(0);
        if applied == want_applied {
            break;
        }
    }
    let progress = world
        .provision
        .site
        .link
        .cutover_operation(&operation_id)
        .unwrap()
        .expect("cutover tracked");
    assert!(
        world.now >= t0 + crate::site::cutover::CUTOVER_GRACE_MS,
        "past the grace: now={} t0={t0}",
        world.now
    );
    // The reachable side switched inside the deadline; the
    // stragglers sit Prepared-unknown (never silently dropped).
    assert_eq!(
        world.snaps[0].phase, PHASE_ACTIVE,
        "gateway adopted: {:?}",
        world.snaps[0]
    );
    assert_eq!(
        world.snaps[0].adopted_network, new_network,
        "gateway on the new network: {:?}",
        world.snaps[0]
    );
    assert_eq!(
        world.snaps[1].phase, PHASE_PREPARED,
        "A still Prepared: {:?}",
        world.snaps[1]
    );
    assert_eq!(
        world.snaps[1].adopted_network, old_network,
        "A still on the old network: {:?}",
        world.snaps[1]
    );
    if island {
        assert_eq!(
            world.snaps[2].phase, PHASE_PREPARED,
            "island B still Prepared: {:?}",
            world.snaps[2]
        );
    } else {
        assert_eq!(
            world.snaps[2].phase, PHASE_ACTIVE,
            "relay B adopted: {:?}",
            world.snaps[2]
        );
        assert_eq!(
            world.snaps[2].adopted_network, new_network,
            "relay B on the new network: {:?}",
            world.snaps[2]
        );
        assert!(
            world.switch.leg_dropped[2][1] > 0,
            "the downstream fault actually ate A's COMMIT"
        );
    }
    assert_eq!(progress.applied, want_applied, "applied: {progress:?}");
    assert_eq!(progress.recovered, 0, "nothing recovered yet: {progress:?}");
    assert_eq!(
        progress.unknown, want_recovered,
        "stragglers unknown: {progress:?}"
    );
    assert!(progress.recovery_pending, "recovery pending: {progress:?}");
    let targets = world.cutover_targets(&operation_id);
    let state_of = |node: u64| {
        targets
            .iter()
            .find(|t| t.0 == node)
            .map(|t| t.1.clone())
            .unwrap_or_default()
    };
    let attempts_of = |node: u64| {
        targets
            .iter()
            .find(|t| t.0 == node)
            .map(|t| t.3)
            .unwrap_or(0)
    };
    // Post-commit Prepared counts as unknown (not silently ready):
    // the row still says prepared while the split says unknown.
    assert_eq!(state_of(NODE_A), "prepared", "A row: {targets:?}");
    assert!(
        attempts_of(NODE_A) > 0,
        "A's COMMIT was dispatched (and missed): {targets:?}"
    );
    assert!(
        world
            .cutover_route(&operation_id, NODE_A)
            .is_some_and(|plan| plan.deferred),
        "A cut by its layer deadline"
    );
    if island {
        assert_eq!(state_of(NODE_B), "prepared", "B row: {targets:?}");
        assert!(
            world
                .cutover_route(&operation_id, NODE_B)
                .is_some_and(|plan| plan.deferred),
            "island B cut by its layer deadline"
        );
    }

    // The fault clears; Prepared must not wedge — the stragglers
    // come back through the ZT auto-reissue (no decider round trip).
    world.switch.drop_next = vec![vec![0; 3]; 3];
    world.switch.ack_drop_next = vec![vec![0; 3]; 3];
    if island {
        world.switch.heal(0);
    }
    let mut chatter_rounds = 0_u32;
    // The island serializes the stragglers: each can only ZT-verify
    // through the other while it is not itself in ZeroTouch, so one may
    // burn a full abandon (300 s) plus cooldown (600 s) before retrying.
    for i in 0..90000 {
        world.step(25);
        let progress = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .expect("cutover tracked");
        let peers_done = world.snaps.iter().all(|s| {
            s.phase == PHASE_ACTIVE
                && s.adopted_network == new_network
                && s.gk_current == next_gk
                && s.authority_ready
        });
        if peers_done && progress.unknown == 0 && progress.recovered == want_recovered {
            break;
        }
        // Survivor chatter carries the newer-generation evidence a
        // dark Prepared straggler strikes on (04 §3.5, like R1).
        if i % 1200 == 1199 && chatter_rounds < 8 {
            chatter_rounds += 1;
            world.peers[2].app_send(testkit::GATEWAY, b"c2-chatter");
            world.peers[0].app_send(NODE_B, b"c2-chatter");
        }
    }
    let progress = world
        .provision
        .site
        .link
        .cutover_operation(&operation_id)
        .unwrap()
        .expect("cutover tracked");
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active: {snap:?}");
        assert_eq!(
            snap.adopted_network, new_network,
            "peer {index} on the new network: {snap:?}"
        );
        assert_eq!(
            snap.gk_current, next_gk,
            "peer {index} on the new GK: {snap:?}"
        );
        assert!(snap.authority_ready, "peer {index} channel re-open");
    }
    // The straggler never held the COMMIT, so applied cannot move —
    // the reissue lands it in recovered instead.
    assert_eq!(
        progress.applied, want_applied,
        "applied never counts the straggler: {progress:?}"
    );
    assert_eq!(
        progress.recovered, want_recovered,
        "stragglers recovered: {progress:?}"
    );
    assert_eq!(progress.unknown, 0, "unknown drained: {progress:?}");
    assert!(!progress.recovery_pending, "converged: {progress:?}");
    let targets = world.cutover_targets(&operation_id);
    assert_eq!(
        targets.iter().find(|t| t.0 == NODE_A).map(|t| t.1.as_str()),
        Some("recovered"),
        "A recovered: {targets:?}"
    );
    assert_eq!(
        decider_requests_for(&world, NODE_A),
        decider_a_before,
        "no decider request for A (auto-reissue)"
    );
    if island {
        assert_eq!(
            targets.iter().find(|t| t.0 == NODE_B).map(|t| t.1.as_str()),
            Some("recovered"),
            "island B recovered: {targets:?}"
        );
        assert_eq!(
            decider_requests_for(&world, NODE_B),
            decider_b_before,
            "no decider request for island B (auto-reissue)"
        );
    }
    assert_eq!(
        [world.peers[0].reboots, world.peers[2].reboots],
        [1, 1],
        "gateway and relay took one adoption reboot each"
    );

    // Bidirectional new-network delivery, gateway to leaf and back.
    let payload = b"c2-down";
    world.peers[0].app_send(NODE_A, payload);
    let leaf_rx = world.snaps[1].rx_count;
    world.pump_until(3000, |snaps| snaps[1].rx_count > leaf_rx);
    assert!(
        world.snaps[1].rx_count > leaf_rx,
        "gateway->leaf delivered: {:?}",
        world.snaps[1]
    );
    assert_eq!(&world.snaps[1].rx[..payload.len()], payload);
    world.peers[1].app_send(testkit::GATEWAY, b"c2-upxxx");
    world.pump_until(3000, |snaps| {
        snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    assert!(
        world.snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "leaf->gateway delivered: {:?}",
        world.snaps[1].app_tx
    );
}

#[test]
fn mesh_c2_commit_miss_and_reissue() {
    // Only the leaf's downstream dies: G and B switch inside the
    // deadline, A recovers through the reissue.
    c2_once("c2-miss", false);
    // G cut from the B/A island: G adopts alone, the island keeps
    // old-network comms, both stragglers recover.
    c2_once("c2-island", true);
}

/// J10-N: retained-site recovery bypasses the expected list and closed intake.
#[test]
fn mesh_j10_closed_policy_keeps_cutover_rescue() {
    c2_with_policy("j10-closed", false, true);
}

/// Shared C3–C7 drive: converge, stage the cutover, drain every
/// PREPARED receipt at 25 ms, fast-forward the prepare window on
/// quiet air, then run until the authority durably commits and the
/// grace opens. Returns (operation, next_gk, new_network,
/// old_network, grace_start).
pub(super) fn cutover_through_commit(
    world: &mut MeshWorld,
    tag: &str,
) -> (String, u32, u64, u64, u64) {
    converge_gated(world, 1, "c3-c7 cutover");
    let staged_at = world.now;
    let operation_id = stage_cutover(world, tag);
    cutover_finish_prepare(world, operation_id, staged_at)
}

pub(super) fn cutover_finish_prepare(
    world: &mut MeshWorld,
    operation_id: String,
    staged_at: u64,
) -> (String, u32, u64, u64, u64) {
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.phase, PHASE_PREPARED,
            "peer {index} prepared: {snap:?}"
        );
    }
    // Peer-local PREPARED is not host evidence: drain the in-flight
    // receipts at 25 ms before any fast-forward, or a queued carrier
    // debits its routed TTL in a 1 s step and dies dead-on-arrival.
    for _ in 0..4000 {
        let targets = world.cutover_targets(&operation_id);
        if !targets.is_empty() && targets.iter().all(|(_, state, _, _)| state == "prepared") {
            break;
        }
        world.step(25);
    }
    let (next_gk, new_network, old_network) = world
        .provision
        .site
        .service
        .with(|a| {
            let op = crate::site::records::parse_op_token(&operation_id).unwrap();
            let state = a
                .operations
                .get(&op)
                .unwrap()
                .cutover
                .as_ref()
                .unwrap()
                .clone();
            (state.next_gk_epoch, state.new_network, state.old_network)
        })
        .0;
    let window_end = staged_at + crate::site::cutover::CUTOVER_PREPARE_WINDOW_MS;
    let mut quiet_ms = 0u64;
    while world.now + 10_000 < window_end {
        let delivered_before = world.switch.delivered;
        // RouteState queries start in the last minute. Keep their
        // carrier hops at the normal 25 ms radio cadence.
        let jump = quiet_ms >= 3_000
            && world.now
                < window_end.saturating_sub(crate::site::cutover::CUTOVER_ROUTE_QUERY_WINDOW_MS);
        world.step(if jump { 1_000 } else { 25 });
        quiet_ms = if world.switch.delivered == delivered_before {
            quiet_ms.saturating_add(if jump { 1_000 } else { 25 })
        } else {
            0
        };
    }
    for _ in 0..4000 {
        world.step(25);
        let phase = world
            .provision
            .site
            .link
            .cutover_operation(&operation_id)
            .unwrap()
            .map(|p| p.phase)
            .unwrap_or_default();
        if phase == "committed" {
            break;
        }
    }
    let t0 = world
        .provision
        .site
        .service
        .with(|a| {
            a.cutover_grace_until_mono
                .saturating_sub(crate::site::cutover::CUTOVER_GRACE_MS)
        })
        .0;
    assert!(
        t0 > staged_at,
        "durable COMMIT passed with a live grace: t0={t0} staged={staged_at}"
    );
    (operation_id, next_gk, new_network, old_network, t0)
}

/// C3–C7 progress snapshot for the running cutover op.
pub(super) fn cutover_progress(
    world: &MeshWorld,
    operation_id: &str,
) -> routeloom_client::site::CutoverProgress {
    world
        .provision
        .site
        .link
        .cutover_operation(operation_id)
        .unwrap()
        .expect("cutover tracked")
}

/// Run to the recovery verdict: every peer ACTIVE on the new
/// network/GK with its authority channel re-open, the ledger's
/// unknown drained, and no decider request for any straggler
/// (auto-reissue, not a manual round trip). `chatter` drives the
/// survivor evidence a dark straggler strikes on (04 §3.5).
pub(super) fn cutover_converged(
    world: &mut MeshWorld,
    operation_id: &str,
    new_network: u64,
    next_gk: u32,
    want_recovered: Option<u64>,
) {
    let mut chatter_rounds = 0_u32;
    for i in 0..48000 {
        world.step(25);
        let progress = cutover_progress(world, operation_id);
        let peers_done = world.snaps.iter().all(|s| {
            s.phase == PHASE_ACTIVE
                && s.adopted_network == new_network
                && s.gk_current == next_gk
                && s.authority_ready
        });
        if peers_done
            && progress.unknown == 0
            && want_recovered.is_none_or(|w| progress.recovered == w)
        {
            break;
        }
        if i % 1200 == 1199 && chatter_rounds < 8 {
            chatter_rounds += 1;
            world.peers[2].app_send(testkit::GATEWAY, b"c3-c7-chatter");
            world.peers[0].app_send(NODE_B, b"c3-c7-chatter");
        }
    }
    let progress = cutover_progress(world, operation_id);
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(snap.phase, PHASE_ACTIVE, "peer {index} active: {snap:?}");
        assert_eq!(
            snap.adopted_network, new_network,
            "peer {index} on the new network: {snap:?}"
        );
        assert_eq!(
            snap.gk_current, next_gk,
            "peer {index} on the new GK: {snap:?}"
        );
        assert!(
            snap.authority_ready,
            "peer {index} channel re-open: {:?}",
            world.snaps
        );
    }
    assert_eq!(progress.unknown, 0, "unknown drained: {progress:?}");
    if let Some(want) = want_recovered {
        assert_eq!(progress.recovered, want, "recovered: {progress:?}");
    }
    assert!(!progress.recovery_pending, "converged: {progress:?}");
}

/// C6: after PREPARE, move the tree from G—B—A to G—A—B. The
/// COMMIT frontier must use the new parent reports, then every
/// target adopts without a direct G—B radio leg.
#[test]
fn mesh_c6_route_change_mid_cutover() {
    let Some(mut world) = MeshWorld::start("c6", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "c6 cutover");
    let staged_at = world.now;
    let operation_id = stage_cutover(&mut world, "c6");
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for _ in 0..4000 {
        let targets = world.cutover_targets(&operation_id);
        if !targets.is_empty() && targets.iter().all(|(_, state, _, _)| state == "prepared") {
            break;
        }
        world.step(25);
    }
    assert!(
        world
            .cutover_targets(&operation_id)
            .iter()
            .all(|(_, state, _, _)| state == "prepared"),
        "Host has every PREPARED before the route flips"
    );
    let direct_before = world.switch.leg_delivered[2][0];
    world.switch.set_audible(0, 2, false);
    world.switch.set_audible(2, 0, false);
    world.switch.set_audible(0, 1, true);
    world.switch.set_audible(1, 0, true);
    // Field power cycling clears the old link contexts while NVS keeps
    // PREPARE. Each peer then forms its next hop over the changed air.
    for index in [0, 1, 2] {
        let before = world.peers[index].reboots;
        world.peers[index].power_cut();
        world.step(25);
        assert!(world.peers[index].reboots > before);
        for _ in 0..200 {
            world.step(25);
        }
    }
    for _ in 0..1200 {
        world.step(25);
    }
    let (operation_id, next_gk, new_network, _old_network, _t0) =
        cutover_finish_prepare(&mut world, operation_id, staged_at);
    assert_eq!(
        world
            .cutover_route(&operation_id, NODE_A)
            .and_then(|p| p.report)
            .map(|r| r.parent),
        Some(testkit::GATEWAY),
        "A reported the new parent: route={:?} targets={:?} snaps={:?}",
        world.cutover_route(&operation_id, NODE_A),
        world.cutover_targets(&operation_id),
        world.snaps
    );
    assert_eq!(
        world
            .cutover_route(&operation_id, NODE_B)
            .and_then(|p| p.report)
            .map(|r| r.parent),
        Some(NODE_A),
        "B reported the new parent"
    );
    cutover_converged(&mut world, &operation_id, new_network, next_gk, Some(0));
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied, 3, "new tree applied: {progress:?}");
    assert_eq!(world.switch.leg_delivered[2][0], direct_before);
}

#[test]
fn mesh_c6_adopted_leaf_blocks_old_relay() {
    let Some(mut world) = MeshWorld::start("c6-leaf", Switch::forced_multihop()) else {
        return;
    };
    let (operation_id, next_gk, new_network, old_network, t0) =
        cutover_through_commit(&mut world, "c6-leaf");
    let b_report = world
        .cutover_route(&operation_id, NODE_B)
        .and_then(|p| p.report)
        .expect("B has a pre-COMMIT RouteState");
    assert_eq!(b_report.parent, testkit::GATEWAY);
    assert!(b_report.recv_mono_ms + u64::from(b_report.lease_ms) > world.now);
    let b_attempts = world
        .cutover_targets(&operation_id)
        .iter()
        .find(|t| t.0 == NODE_B)
        .unwrap()
        .3;
    // Flip inside the harness step that accepts A's real STORED receipt,
    // before the distributor can release B from the old route plan.
    world.c6_flip_on_a_stored = Some(crate::site::records::parse_op_token(&operation_id).unwrap());
    for _ in 0..4000 {
        world.step(25);
        if world.c6_flipped {
            break;
        }
    }
    assert!(world.c6_flipped, "the receipt triggered the route fault");
    assert!(world
        .cutover_route(&operation_id, NODE_A)
        .is_some_and(|p| p.stored));
    assert_eq!(world.snaps[2].adopted_network, old_network);
    assert_eq!(
        world
            .cutover_targets(&operation_id)
            .iter()
            .find(|t| t.0 == NODE_B)
            .unwrap()
            .3,
        b_attempts,
        "no old-tree COMMIT to B was dispatched after A stored"
    );
    while world.now < t0 + crate::site::cutover::CUTOVER_GRACE_MS + 5_000 {
        world.step(25);
    }
    assert_eq!(
        world
            .cutover_targets(&operation_id)
            .iter()
            .find(|t| t.0 == NODE_B)
            .unwrap()
            .3,
        b_attempts,
        "stale COMMIT never entered the transport during grace"
    );
    assert_eq!(world.snaps[1].adopted_network, new_network);
    assert_eq!(world.snaps[2].adopted_network, old_network);
    assert!(world
        .cutover_route(&operation_id, NODE_B)
        .is_some_and(|p| p.deferred));
    let progress = cutover_progress(&world, &operation_id);
    assert!(progress.unknown > 0, "B remains unknown: {progress:?}");
    world.switch.set_audible(0, 2, true);
    world.switch.set_audible(2, 0, true);
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied + progress.recovered, 3);
    assert!(
        progress.recovered >= 1,
        "uncommitted B recovered: {progress:?}"
    );
}

/// C7: old carriers from A's actual Owner are refused after B adopts,
/// and an old authenticated receipt arriving exactly at D cannot
/// count merely because Host has not yet run its D tick.
#[test]
fn mesh_c7_old_epoch_boundary() {
    let mut switch = Switch::forced_multihop();
    switch.c7_capture = true;
    let Some(mut world) = MeshWorld::start("c7", switch) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "c7 cutover");
    world.peers[0].power_cut();
    world.step(25);
    converge(&mut world, "c7 resume capture");
    world.switch.c7_hold_data = true;
    let b_rx_before = world.snaps[2].rx_count;
    world.peers[1].app_send(NODE_B, b"c7-old-data");
    for _ in 0..400 {
        world.step(25);
        if world.switch.c7_old_data.is_some() {
            break;
        }
    }
    assert!(
        world.switch.c7_old_data.is_some(),
        "old DATA left A on the radio"
    );
    assert_eq!(
        world.snaps[2].rx_count, b_rx_before,
        "held DATA never reached B"
    );
    world.c7_hold_b_receipt = true;
    let staged_at = world.now;
    let operation_id = stage_cutover(&mut world, "c7");
    let (operation_id, next_gk, new_network, old_network, t0) =
        cutover_finish_prepare(&mut world, operation_id, staged_at);
    assert!(
        world.switch.c7_old_discover.is_some(),
        "old GK discover left A"
    );
    assert!(
        world.switch.c7_old_resume.is_some(),
        "old resume left G or A"
    );
    assert!(
        world.switch.c7_old_cert.is_some(),
        "old MemberCert handshake left A"
    );
    // Strand A fully dark while the COMMIT dispatch is still working
    // its way down the tree (the leaf commits last, so its downlink
    // has not landed yet). A stays Prepared on the old epoch.
    world.switch.isolate(1);
    world.switch.c7_hold_data = false;
    // The held B envelope crossed radio and USB, but its business
    // receipt is not delivered to the authority until D sharp.
    for _ in 0..4000 {
        world.step(25);
        if world.c7_old_receipt.is_some() {
            break;
        }
    }
    assert!(world.c7_old_receipt.is_some(), "old B type-7 wire was held");
    assert!(!world
        .cutover_route(&operation_id, NODE_B)
        .is_some_and(|p| p.stored));
    for _ in 0..2000 {
        world.step(25);
        if world.snaps[2].adopted_network == new_network {
            break;
        }
    }
    assert_eq!(
        world.snaps[2].adopted_network, new_network,
        "B adopted during grace"
    );
    assert!(world.now < t0 + crate::site::cutover::CUTOVER_GRACE_MS);
    for _ in 0..10 {
        world.step(25);
    }
    // Only these injected carriers may reach B during the refusal
    // sample; the old gateway's ambient discovery stays off this leg.
    world.switch.set_audible(0, 2, false);
    let before = world.snaps[2].clone();
    let old_data = world.switch.c7_old_data.as_ref().unwrap().clone();
    let old_discover = world.switch.c7_old_discover.as_ref().unwrap().clone();
    let (resume_from, old_resume) = world.switch.c7_old_resume.as_ref().unwrap().clone();
    let old_cert = world.switch.c7_old_cert.as_ref().unwrap().clone();
    assert_eq!(
        u32::from_be_bytes(old_data[12..16].try_into().unwrap()),
        old_network as u32
    );
    assert_eq!(
        u32::from_be_bytes(old_resume[12..16].try_into().unwrap()),
        old_network as u32
    );
    assert_eq!(
        u32::from_be_bytes(old_cert[12..16].try_into().unwrap()),
        old_network as u32
    );
    world.peers[2].send_rx(&world.macs[1], &world.macs[2], &old_data);
    world.peers[2].send_rx(&world.macs[1], &BROADCAST_MAC, &old_discover);
    for _ in 0..4 {
        world.step(25);
    }
    assert_eq!(
        world.snaps[2].rx_count, before.rx_count,
        "old DATA not delivered"
    );
    assert!(
        world.snaps[2].unknown_peer_rx > before.unknown_peer_rx,
        "old DATA has no adopted MAC binding: {:?}",
        world.snaps[2]
    );
    assert!(world.snaps[2].scope_raw_rx > before.scope_raw_rx);
    assert!(
        world.snaps[2].scope_unknown_generation > before.scope_unknown_generation,
        "old GK discovery refused: {:?}",
        world.snaps[2]
    );
    assert_eq!(world.snaps[2].scope_accepted, before.scope_accepted);
    let proxy_rejects = |snap: &MeshSnap| snap.proxy_frames_rejected + snap.proxy_cookie_rejects;
    let before_resume = proxy_rejects(&world.snaps[2]);
    world.peers[2].send_rx(&world.macs[resume_from], &world.macs[2], &old_resume);
    for _ in 0..4 {
        world.step(25);
    }
    assert!(
        proxy_rejects(&world.snaps[2]) > before_resume,
        "old resume was refused by the unbound proxy lane: {:?}",
        world.snaps[2]
    );
    let before_cert = proxy_rejects(&world.snaps[2]);
    world.peers[2].send_rx(&world.macs[1], &world.macs[2], &old_cert);
    for _ in 0..4 {
        world.step(25);
    }
    assert!(
        proxy_rejects(&world.snaps[2]) > before_cert,
        "old MemberCert handshake was refused: {:?}",
        world.snaps[2]
    );
    assert_eq!(
        world.snaps[2].link_sessions, before.link_sessions,
        "old resume/MemberCert must not reestablish a link"
    );
    world.switch.set_audible(0, 2, true);

    let deadline = t0 + crate::site::cutover::CUTOVER_GRACE_MS;
    while world.now + 25 < deadline {
        world.step(25);
    }
    assert!(world.now < deadline);
    let prior = cutover_progress(&world, &operation_id);
    assert_eq!(prior.phase, "committed", "Host has not ticked at D");
    let (kind, bytes) = world.c7_old_receipt.take().unwrap();
    world.now = deadline;
    world.deliver_authority_up(NODE_B, kind, &bytes, deadline);
    assert!(
        !world
            .cutover_route(&operation_id, NODE_B)
            .is_some_and(|p| p.stored),
        "old COMMIT_STORED is refused at D before the Host tick"
    );
    let after = cutover_progress(&world, &operation_id);
    assert_eq!(
        (after.applied, after.recovered),
        (prior.applied, prior.recovered)
    );
    // B and the gateway adopt inside the grace; A's row stays
    // unknown — never a silent applied. The ledger moves only on
    // durable receipts: the gateway releases at plan close, reboots,
    // and both receipts then ride the rebuilt channels — bound the
    // wait on the ledger itself, not just the peer snapshots.
    for _ in 0..16000 {
        world.step(25);
        let progress = cutover_progress(&world, &operation_id);
        if world.snaps[0].adopted_network == new_network
            && world.snaps[2].adopted_network == new_network
            && progress.applied + progress.recovered >= 2
        {
            break;
        }
    }
    assert_eq!(
        world.snaps[2].adopted_network, new_network,
        "B adopted: {:?}",
        world.snaps[2]
    );
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(
        progress.applied + progress.recovered,
        2,
        "A unaccounted: {progress:?}"
    );
    assert_eq!(
        progress.applied, 2,
        "the reachable pair applied, not recovered: {progress:?}"
    );
    assert_eq!(
        world.snaps[1].adopted_network, old_network,
        "A still on the old epoch: {:?}",
        world.snaps[1]
    );

    // The boundary: B's demoted previous generation authenticates for
    // kScopePreviousOverlapMaxMs (30 min) from B's adoption. Hold A
    // dark past it — 250 ms steps keep G↔B carriers inside their
    // routed TTL while the overlap ages out — then heal. Whatever A
    // still is (Prepared-dark or reverted), the only member-scope
    // traffic it can emit is the retired generation: require an actual
    // arrival and B's unknown-generation refusal. The ledger must
    // still resolve A through recovery; an old-epoch straggler cannot
    // be counted as applied.
    let b_demote = world.now.max(t0);
    let boundary = b_demote + 1_800_000 + 60_000;
    while world.now < boundary {
        world.step(250);
    }
    let b_unkgen = world.snaps[2].scope_unknown_generation;
    let b_raw = world.snaps[2].scope_raw_rx;
    world.switch.heal(1);
    // A's first post-heal member frames carry the retired epoch; give
    // the recovery road room to run at full resolution.
    let mut stale_seen = false;
    for _ in 0..9600 {
        world.step(25);
        if world.snaps[2].scope_raw_rx > b_raw {
            stale_seen = true;
        }
        if stale_seen && world.snaps[2].scope_unknown_generation > b_unkgen {
            break;
        }
        if world.snaps[1].adopted_network == new_network {
            break;
        }
    }
    assert!(
        stale_seen && world.snaps[2].scope_unknown_generation > b_unkgen,
        "B received A's old-epoch frame and refused its generation: B={:?} A={:?} unkgen {} > {}",
        world.snaps[2],
        world.snaps[1],
        world.snaps[2].scope_unknown_generation,
        b_unkgen
    );
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    // A resolves through the recovery road or re-emits its durable
    // APPLIED receipt after adoption — either is honest evidence; the
    // verdict that matters is above: it was never applied while it
    // sat dark on the old epoch.
    assert_eq!(
        progress.applied + progress.recovered,
        3,
        "every target resolved past the old-epoch boundary: {progress:?}"
    );
}
