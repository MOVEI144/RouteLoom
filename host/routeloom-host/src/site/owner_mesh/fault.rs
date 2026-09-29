//! Cutover fault rows: receipt loss and power cut, daemon restart and
//! gateway USB loss (tests/e2e/scenarios.json F01, F06, F07), and the
//! HostLink v2 negatives and gateway reset (F07-A, M06-G).

use super::cutover::{
    cutover_converged, cutover_finish_prepare, cutover_progress, cutover_through_commit,
    decider_requests_for, stage_cutover,
};
use super::*;
use routeloom_protocol::manifest as reasons;

/// C3: the member's APPLIED receipt dies in flight while the member
/// itself commits and adopts on time. A lost receipt copy is not a
/// lost adoption: the site can never count A applied on the evidence
/// it does not hold, so A's row goes unknown at the grace boundary —
/// while the member's own receipt is journal-durable and keeps
/// retrying. When the uplink heals the real receipt lands and the
/// row resolves applied; the op never wedges and no decider round
/// trip is needed.
#[test]
fn mesh_c3_commit_applied_receipt_loss() {
    let Some(mut world) = MeshWorld::start("c3", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    let decider_a_before = decider_requests_for(&world, NODE_A);
    let (operation_id, next_gk, new_network, _old_network, t0) =
        cutover_through_commit(&mut world, "c3");
    // A's COMMIT comes down B→A while its APPLIED receipt goes back
    // up A→B. The uplink can only be cut after the commit lands —
    // the endpoint's inbound manifest refuses while a wedged
    // outbound holds it, so a premature cut kills the commit too.
    // The observable seam is A's adoption reboot: adopted_network
    // flips before the channel re-opens and the receipt goes out.
    // Arm the uplink drop then and hold it through the whole grace —
    // the receipt is production-persistent inside the window.
    world.pump_until(15000, |snaps| snaps[1].adopted_network == new_network);
    assert_eq!(
        world.snaps[1].adopted_network, new_network,
        "A adopted the new network on time: {:?}",
        world.snaps[1]
    );
    assert_eq!(world.peers[1].reboots, 1, "A took its adoption reboot");
    world.switch.drop_next[1][2] += 100_000;
    // Run out the grace with the uplink dark.
    while world.now < t0 + crate::site::cutover::CUTOVER_GRACE_MS + 5_000 {
        world.step(100);
    }
    assert!(
        world.switch.leg_dropped[1][2] > 0,
        "the uplink fault actually ate A's receipt traffic"
    );
    // At the boundary the site holds no receipt for A, so A's row
    // can never read applied — the ledger classifies from evidence,
    // not absence of fault (the row may still lag at prepared).
    let progress = cutover_progress(&world, &operation_id);
    let targets = world.cutover_targets(&operation_id);
    assert_ne!(
        targets.iter().find(|t| t.0 == NODE_A).map(|t| t.1.as_str()),
        Some("applied"),
        "A unaccounted while its receipts die in flight: {targets:?}"
    );
    assert!(
        progress.applied < 3,
        "no applied without a landed receipt: {progress:?}"
    );
    // Heal: the journal-durable receipt retry lands and reclassifies
    // A applied — late real evidence is still real evidence.
    world.switch.drop_next[1][2] = 0;
    cutover_converged(&mut world, &operation_id, new_network, next_gk, Some(0));
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied, 3, "A's receipt landed: {progress:?}");
    assert_eq!(
        decider_requests_for(&world, NODE_A),
        decider_a_before,
        "no decider request for A (auto-recovery)"
    );
}

#[test]
fn mesh_c3_stored_receipt_loss_and_power_cut() {
    let Some(mut world) = MeshWorld::start("c3-stored", Switch::forced_multihop()) else {
        return;
    };
    let (operation_id, next_gk, new_network, old_network, t0) =
        cutover_through_commit(&mut world, "c3-stored");
    assert_eq!(
        world.snaps[1].adopted_network, old_network,
        "arm before A switches"
    );
    // A's COMMIT travels B→A. Cut power immediately after Switching
    // becomes durable, before the stored receipt can leave A.
    world.peers[1].cut_after_switching();
    for _ in 0..4000 {
        world.step(25);
        if world.peers[1].switching_cuts != 0 {
            break;
        }
    }
    assert_eq!(
        world.peers[1].switching_cuts, 1,
        "power cut after RLX1 Switching"
    );
    world.switch.drop_next[1][2] = 100_000;
    world.pump_until(4000, |snaps| snaps[1].adopted_network == new_network);
    assert!(
        !world
            .cutover_route(&operation_id, NODE_A)
            .is_some_and(|plan| plan.stored),
        "lost receipt is not stored evidence"
    );
    assert_eq!(
        world.snaps[1].adopted_network,
        new_network,
        "A resumed Switching: {:?}; targets={:?}",
        world.snaps[1],
        world.cutover_targets(&operation_id)
    );
    assert_ne!(world.snaps[1].adopted_network, old_network);
    while world.now < t0 + crate::site::cutover::CUTOVER_GRACE_MS + 5_000 {
        world.step(25);
    }
    assert!(world.switch.leg_dropped[1][2] > 0, "receipt leg was cut");
    let progress = cutover_progress(&world, &operation_id);
    assert!(
        progress.applied < 3,
        "lost receipt is not applied: {progress:?}"
    );
    assert!(progress.unknown > 0, "A remains unknown: {progress:?}");
    world.switch.drop_next[1][2] = 0;
    cutover_converged(&mut world, &operation_id, new_network, next_gk, Some(0));
    assert_eq!(cutover_progress(&world, &operation_id).applied, 3);
}

/// C4(a): reopen the whole daemon from SQLite while every member is
/// Prepared. The signed PREPARE and epoch allocation survive, while
/// the monotonic prepare window starts again in the new process.
#[test]
fn mesh_c4_daemon_restart_preparing() {
    let Some(mut world) = MeshWorld::start("c4-pre", Switch::forced_multihop()) else {
        return;
    };
    converge_gated(&mut world, 1, "c4 preparing");
    let operation_id = stage_cutover(&mut world, "c4-pre");
    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.phase == PHASE_PREPARED)
    });
    for _ in 0..4000 {
        if world
            .cutover_targets(&operation_id)
            .iter()
            .all(|(_, s, _, _)| s == "prepared")
        {
            break;
        }
        world.step(25);
    }
    let op = crate::site::records::parse_op_token(&operation_id).unwrap();
    let before = world
        .provision
        .site
        .service
        .with(|a| {
            let state = a.operations.get(&op).unwrap().cutover.as_ref().unwrap();
            (
                state.revision,
                state.next_gk_epoch,
                a.grant_bytes(op, NODE_A, crate::site::revocation::OutboundKind::Prepare),
                a.store.load().unwrap().meta.get("next_serial").cloned(),
            )
        })
        .0;
    let restart_at = world.now;
    world.daemon_restart();
    world.step(25);
    let after = world
        .provision
        .site
        .service
        .with(|a| {
            let state = a.operations.get(&op).unwrap().cutover.as_ref().unwrap();
            (
                state.revision,
                state.next_gk_epoch,
                a.grant_bytes(op, NODE_A, crate::site::revocation::OutboundKind::Prepare),
                a.store.load().unwrap().meta.get("next_serial").cloned(),
                state.started_mono_ms,
            )
        })
        .0;
    assert_eq!(before, (after.0, after.1, after.2, after.3));
    assert!(
        after.4 >= restart_at,
        "the prepare clock restarted: {} < {restart_at}",
        after.4
    );
    let (operation_id, next_gk, new_network, _old_network, t0) =
        cutover_finish_prepare(&mut world, operation_id, restart_at);
    assert!(t0 >= restart_at + crate::site::cutover::CUTOVER_PREPARE_WINDOW_MS);
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied + progress.recovered, 3);
}

/// C4(b): reopen after the COMMIT is durable with A still Prepared.
/// The new daemon has no old-context grace or queued sealed payloads;
/// the straggler recovers by reissue while committed peers stay new.
#[test]
fn mesh_c4_daemon_restart_committed() {
    let Some(mut world) = MeshWorld::start("c4-post", Switch::forced_multihop()) else {
        return;
    };
    let (operation_id, next_gk, new_network, old_network, _t0) =
        cutover_through_commit(&mut world, "c4-post");
    assert_eq!(world.snaps[1].adopted_network, old_network);
    world.switch.drop_next[2][1] = 500;
    let old_usb = Arc::clone(&world.provision.usb);
    let old_join = Arc::clone(&world.join_adapter);
    world.daemon_restart();
    assert_ne!(
        old_usb.usb_incarnation(),
        world.provision.usb.usb_incarnation()
    );
    assert!(matches!(
        old_usb.handle_up(&[], world.now),
        Err(crate::site::usb::AuthorityUpError::Closed)
    ));
    assert!(matches!(
        old_join.handle_up(&[], world.now),
        Err(crate::site::usb::UpError::Closed)
    ));
    let (network, grace) = world
        .provision
        .site
        .service
        .with(|a| (a.network(), a.cutover_grace_until_mono))
        .0;
    assert_eq!(network, new_network);
    assert_eq!(grace, 0);
    let progress = cutover_progress(&world, &operation_id);
    assert!(
        progress.unknown > 0,
        "undelivered A stays unknown: {progress:?}"
    );
    world.switch.drop_next[2][1] = 0;
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied + progress.recovered, 3);
}

/// C5: the gateway↔host USB lane dies right after the durable
/// COMMIT so every dispatched COMMIT dies on the cable. The ledger
/// honestly flips the targets unknown (it never saw a receipt),
/// recovery_pending opens, and the members stay Prepared on the old
/// network. Reconnecting re-authenticates the authority session and
/// the member-driven recovery road converges every straggler — no
/// decider request, no silent applied.
#[test]
fn mesh_c5_gateway_disconnect_and_resume() {
    let Some(mut world) = MeshWorld::start("c5", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    let (operation_id, next_gk, new_network, _old_network, t0) =
        cutover_through_commit(&mut world, "c5");
    let old_usb = Arc::clone(&world.provision.usb);
    let old_join = Arc::clone(&world.join_adapter);
    let old_incarnation = old_usb.usb_incarnation();
    // The cable pull: nothing crosses the USB seam while it is down.
    // Member probes still cross the radio but the authority can't
    // answer — a Prepared straggler whose probes go unanswered must
    // eventually strike out and take the ZeroTouch reissue road.
    world.usb_disconnect();
    assert!(matches!(
        old_usb.handle_up(&[], world.now),
        Err(crate::site::usb::AuthorityUpError::Closed)
    ));
    assert!(matches!(
        old_join.handle_up(&[], world.now),
        Err(crate::site::usb::UpError::Closed)
    ));
    // Run past the grace on the dead lane — the old bindings the
    // COMMITs rode have expired out of the host's table, so no member
    // can be reached on them at all — then past the stragglers'
    // dead-silence bound (~120 s), so their own evidence has struck
    // them into the ZT reissue before the cable returns. The heal
    // must land inside their first refresh window (~5 min): an
    // abandoned refresh cools down for ten.
    let grace_end = t0 + crate::site::cutover::CUTOVER_GRACE_MS;
    while world.now < grace_end + 130_000 {
        world.step(25);
    }
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(
        progress.applied, 0,
        "nothing could apply with the host lane down: {progress:?}"
    );
    assert!(
        progress.recovery_pending || progress.unknown > 0,
        "stragglers pending recovery: {progress:?}"
    );
    // Reconnect: the authority session re-authenticates (a fresh
    // session counts too — the physical rebind is its own evidence),
    // the refreshed members pull the ZT reissue, and the ledger
    // resolves honestly — a straggler that re-emits its durable
    // APPLIED receipt is applied, one proven through the recovery
    // road is recovered; only the split is timing.
    world.usb_reconnect();
    assert_ne!(world.provision.usb.usb_incarnation(), old_incarnation);
    assert_ne!(world.join_adapter.usb_incarnation(), old_incarnation);
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(
        progress.applied + progress.recovered,
        3,
        "every target resolved after resume: {progress:?}"
    );
}

#[test]
fn mesh_c5_radio_partition_and_stale_usb_adapter() {
    use routeloom_protocol::host_ops::{
        encode_authority_down, encode_authority_up, AuthorityFragment,
    };
    let Some(mut world) = MeshWorld::start("c5-radio", Switch::forced_multihop()) else {
        return;
    };
    let (operation_id, next_gk, new_network, old_network, t0) =
        cutover_through_commit(&mut world, "c5-radio");
    // The G—B leg fails while B/A still hold the old Prepared group.
    world.switch.isolate(0);
    let old_usb = Arc::clone(&world.provision.usb);
    let old_join = Arc::clone(&world.join_adapter);
    let delayed = AuthorityFragment {
        device: testkit::GATEWAY,
        transfer_id: 1,
        kind: CarrierKind::Envelope,
        hops: 0,
        total: 28,
        offset: 0,
        data: vec![0xA5; 28],
    };
    let delayed_up = encode_authority_up(&delayed).unwrap();
    let delayed_down = encode_authority_down(&delayed).unwrap();
    let sessions_before = world.usb_auth_total();
    // A gateway field reboot ends the old bridge session and binds
    // both host adapters to the fresh USB incarnation.
    let reboots_before = world.peers[0].reboots;
    world.peers[0].power_cut();
    world.step(25);
    assert!(world.peers[0].reboots > reboots_before);
    assert!(matches!(
        old_usb.handle_up(&delayed_up, world.now),
        Err(crate::site::usb::AuthorityUpError::Closed)
    ));
    old_usb.requeue_front(vec![crate::site::usb::AuthorityDown {
        bytes: delayed_down,
        device: testkit::GATEWAY,
        transfer_id: 1,
        admitted_ms: world.now,
    }]);
    assert!(old_usb.take_ready(world.now).is_empty());
    assert!(matches!(
        old_join.handle_up(&[], world.now),
        Err(crate::site::usb::UpError::Closed)
    ));
    while world.now < t0 + crate::site::cutover::CUTOVER_GRACE_MS + 5_000 {
        world.step(25);
    }
    assert!(
        world.usb_auth_total() > sessions_before,
        "USB reauthenticated"
    );
    assert_eq!(world.snaps[0].adopted_network, new_network);
    assert_eq!(world.snaps[1].adopted_network, old_network);
    assert_eq!(world.snaps[2].adopted_network, old_network);
    let progress = cutover_progress(&world, &operation_id);
    assert!(
        progress.unknown >= 2,
        "partitioned island stays unknown: {progress:?}"
    );
    world.switch.heal(0);
    cutover_converged(&mut world, &operation_id, new_network, next_gk, None);
    let progress = cutover_progress(&world, &operation_id);
    assert_eq!(progress.applied + progress.recovered, 3);
    let leaf_rx = world.snaps[1].rx_count;
    world.peers[0].app_send(NODE_A, b"c5-down");
    world.pump_until(3000, |snaps| snaps[1].rx_count > leaf_rx);
    assert!(world.snaps[1].rx_count > leaf_rx, "new-epoch downlink");
    world.peers[1].app_send(testkit::GATEWAY, b"c5-upxxx");
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
        "new-epoch uplink"
    );
}

/// Steps until the host holds a session newer than `before` (counted by
/// `usb_auth_total`) and returns the virtual time it took.
fn reauth_ms(world: &mut MeshWorld, before: usize, what: &str) -> u64 {
    let start = world.now;
    while world.usb_auth_total() <= before && world.now < start + 20_000 {
        world.step(25);
    }
    assert!(world.usb_auth_total() > before, "{what}: re-authenticated");
    assert_eq!(world.usb_host.session.phase, SessionPhase::Active, "{what}");
    world.now - start
}

/// Steps until the host has recorded `count` device Error frames.
fn await_errors(world: &mut MeshWorld, count: usize) -> (u16, u16) {
    for _ in 0..200 {
        if world.usb_host.errors.len() >= count {
            break;
        }
        world.step(25);
    }
    *world
        .usb_host
        .errors
        .get(count - 1)
        .expect("the gateway answered with an Error frame")
}

/// One KeepAlive sealed in the host's current session, as wire bytes.
fn sealed_keepalive(world: &mut MeshWorld) -> Vec<u8> {
    let mut frame = Frame {
        kind: FrameKind::KeepAlive,
        flags: 0,
        session: 0,
        request: 0,
        body: Vec::new(),
    };
    world
        .usb_host
        .session
        .protect(&mut frame)
        .expect("active session");
    encode_frame(&frame).expect("keepalive encodes")
}

/// F07-A: through the gateway's real bridge bytes, HostLink v2 refuses a
/// replayed counter, a forged frame tag and a protocol-1 HELLO, each with
/// its registered reason id; a wrong hostlink secret never reaches Active.
/// After every refusal the host is back on a fresh session within 5 s (vt).
#[test]
fn mesh_hostlink_v2_auth_negatives() {
    let Some(mut world) = MeshWorld::start("f07a", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge(&mut world, "f07a");
    assert_eq!(world.usb_host.session.phase, SessionPhase::Active);

    // Replay: the same sealed frame twice. The copy's counter is spent.
    let wire = sealed_keepalive(&mut world);
    world.peers[0].send_usb(&wire);
    world.step(25);
    let errors = world.usb_host.errors.len();
    let sessions = world.usb_auth_total();
    world.peers[0].send_usb(&wire);
    assert_eq!(
        await_errors(&mut world, errors + 1),
        (3, reasons::REASON_REPLAY_REJECTED)
    );
    assert!(reauth_ms(&mut world, sessions, "after replay") <= 5_000);

    // Forged tag: one flipped tag bit.
    let mut wire = sealed_keepalive(&mut world);
    let mut decoder = StreamDecoder::default();
    let mut forged = decoder.push(&wire).pop().unwrap().unwrap();
    forged.body[10] ^= 1;
    wire = encode_frame(&forged).unwrap();
    let errors = world.usb_host.errors.len();
    let sessions = world.usb_auth_total();
    world.peers[0].send_usb(&wire);
    assert_eq!(
        await_errors(&mut world, errors + 1),
        (2, reasons::REASON_SESSION_TAG_INVALID)
    );
    assert!(reauth_ms(&mut world, sessions, "after forged tag") <= 5_000);

    // Downgrade: a HELLO offering only protocol 1 is refused before any
    // transcript exists (pre-auth Error, session 0).
    let mut hello = 0x0DD5_u64.to_be_bytes().to_vec();
    hello.extend_from_slice(&[1, 1, 0]);
    let downgrade = Frame {
        kind: FrameKind::Hello,
        flags: 0,
        session: 0,
        request: 77,
        body: hello,
    };
    let errors = world.usb_host.errors.len();
    let sessions = world.usb_auth_total();
    world.peers[0].send_usb(&encode_frame(&downgrade).unwrap());
    assert_eq!(
        await_errors(&mut world, errors + 1),
        (7, reasons::REASON_VERSION_UNSUPPORTED)
    );
    assert!(reauth_ms(&mut world, sessions, "after downgrade") <= 5_000);

    // Wrong secret in the gateway's credential file: the HelloAck tag never
    // verifies, so the host sends no AUTH and nothing becomes Active.
    let credential = world
        .hostlink_dir
        .join(format!("{:016x}.key", testkit::GATEWAY));
    let secret = std::fs::read(&credential).unwrap();
    std::fs::write(&credential, b"not-this-gateway-secret").unwrap();
    world.usb_disconnect();
    world.usb_reconnect();
    let sessions = world.usb_auth_total();
    for _ in 0..400 {
        world.step(25);
    }
    assert_eq!(world.usb_auth_total(), sessions, "wrong secret: no session");
    assert_ne!(world.usb_host.session.phase, SessionPhase::Active);
    std::fs::write(&credential, &secret).unwrap();
    world.usb_disconnect();
    world.usb_reconnect();
    assert!(reauth_ms(&mut world, sessions, "after the credential fix") <= 5_000);
}

/// M06-G: a gateway power cut. The host is back on a new HostLink session
/// within 5 s (vt), a frame of the old session is dropped without effect,
/// and host sends through the new session reach A 10/10 with the first
/// delivery inside 15 s (vt).
#[test]
fn mesh_gateway_reset_reauthenticates_and_delivers() {
    // The compatibility boot plan: the TX_ACCEPTED count below holds for
    // its attach order. After a simultaneous boot the first sends after
    // the reset may report QUEUED while the end-to-end session re-forms.
    let plan = staggered_boot(3);
    let Some(mut world) = MeshWorld::start_plan("m06g", Switch::direct(), &plan, false) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge(&mut world, "m06g");
    let old_session = sealed_keepalive(&mut world);
    world.peers[0].send_usb(&old_session);
    world.step(25);
    let sessions = world.usb_auth_total();
    let reboots = world.peers[0].reboots;
    let cut_at = world.now;
    world.peers[0].power_cut();
    let reauth = reauth_ms(&mut world, sessions, "after the gateway reset");
    assert!(world.peers[0].reboots > reboots, "the gateway rebooted");
    assert!(
        world.now - cut_at <= 5_000,
        "re-authenticated in {reauth} ms"
    );

    // The old session's bytes are silently dropped: no Error, no new session.
    let errors = world.usb_host.errors.len();
    let sessions = world.usb_auth_total();
    world.peers[0].send_usb(&old_session);
    for _ in 0..40 {
        world.step(25);
    }
    assert_eq!(
        world.usb_host.errors.len(),
        errors,
        "stale session answered"
    );
    assert_eq!(
        world.usb_auth_total(),
        sessions,
        "stale session broke the new one"
    );

    // Host → A through the new session: 10/10, each reported with the
    // registered TX_ACCEPTED id.
    let resumed_at = world.now;
    for index in 0..10_u64 {
        let rx = world.snaps[1].rx_count;
        let mut body = (0x0600_u64 + index).to_be_bytes().to_vec();
        body.extend_from_slice(&NODE_A.to_be_bytes());
        body.extend_from_slice(b"m06g-down");
        world.usb_host.queue_data(FrameKind::DataToMesh, body);
        world.pump_until(1200, |snaps| snaps[1].rx_count > rx);
        assert!(world.snaps[1].rx_count > rx, "delivery {index} reached A");
        if index == 0 {
            assert!(
                world.now - resumed_at <= 15_000,
                "first delivery after the reset"
            );
        }
    }
    let accepted = world
        .usb_host
        .deliveries
        .iter()
        .filter(|(_, reason)| *reason == reasons::REASON_TX_ACCEPTED)
        .count();
    assert!(
        accepted >= 10,
        "TX_ACCEPTED ids: {:?}",
        world.usb_host.deliveries
    );
}
