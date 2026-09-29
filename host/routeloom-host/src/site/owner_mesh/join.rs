//! Membership rows: group-key rotation, revocation notices and the
//! missed-epoch recovery (tests/e2e/scenarios.json J07, J08).

use super::*;

/// #168 GK over the real mesh: a manual rotation stages, members ACK,
/// and the new epoch goes active on every node (no `catching_up`).
#[test]
fn mesh_group_key_rotate_acknowledged() {
    use routeloom_client::site::SiteAdmin;
    let Some(mut world) = MeshWorld::start("gk", Switch::direct()) else {
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
        "mesh converged before rotate"
    );
    let before: Vec<u32> = world.snaps.iter().map(|s| s.gk_current).collect();

    let active = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status")
        .active;
    let outcome = world
        .provision
        .site
        .link
        .rotate_group_key(active, "mesh-gk-1")
        .expect("rotate commits");
    assert_eq!(outcome.state, "committed");

    world.pump_until(8000, |snaps| {
        snaps.iter().all(|s| s.gk_current == outcome.to_epoch)
    });
    for (index, snap) in world.snaps.iter().enumerate() {
        assert_eq!(
            snap.gk_current, outcome.to_epoch,
            "peer {index} active GK advanced from {}: {snap:?}",
            before[index]
        );
    }
    // Active ACKs ride the authority channel behind the apply; let them
    // settle before reading the converged phase.
    for _ in 0..120 {
        world.step(25);
        let phase = world
            .provision
            .site
            .link
            .group_key_status()
            .expect("gk status")
            .phase;
        if phase == "stable" {
            break;
        }
    }
    let status = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status");
    assert_eq!(status.active, outcome.to_epoch);
    assert!(
        status.phase == "stable",
        "rotation converged, not catching_up: {status:?}"
    );
}

/// R1 (§5.2): notice versus prompt refusal on forced G—B—A. A is
/// revoked while its notice transfer is stalled mid-chunk; the
/// survivors must enforce first (no waiting on the notice timeout),
/// refuse A's traffic on every leg, keep their own delivery healthy,
/// and A must still erase — via the resumed direct send when it wins
/// the race, else over the ZT road. `stall` selects the main
/// condition (stalled) or the control (plain direct race).
pub(super) fn r1_once(tag: &str, stall: bool) {
    use routeloom_client::site::{RemovalReason, SiteAdmin};
    let Some(mut world) = MeshWorld::start(tag, Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "r1 revoke");
    let id_fp_before = world.snaps[1].id_fp;
    assert_ne!(id_fp_before, 0, "A holds an identity fingerprint");
    // Pre-revoke delivery works (and brings the A-B E2E up, so its
    // later retirement is observable rather than vacuous).
    world.peers[1].app_send(NODE_B, b"r1-before");
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
        "pre-revoke A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    let delivered_before = world.snaps[1]
        .app_tx
        .iter()
        .filter(|tx| tx.state == DELIVERY_DELIVERED)
        .count();
    let gw_rrs = world.snaps[0].rrs_applied;
    let b_rrs = world.snaps[2].rrs_applied;
    let b_link = world.snaps[2].link_sessions;
    let b_end = world.snaps[2].end_sessions;

    let row = world.member_row(NODE_A).expect("member row");
    let outcome = world
        .provision
        .site
        .link
        .revoke(NODE_A, row.generation, RemovalReason::Removed, tag)
        .expect("revoke commits");
    assert_eq!(outcome.state, "committed");
    if stall {
        // The revoke committed a Notice for A. Keep its chunk off the
        // B→A leg while its manifest and unrelated radio traffic pass.
        world.switch.drop_notice_chunks = true;
    }

    // Enforcement first: both survivors apply the RRS while the
    // notice is still unconfirmed and A still holds its site.
    let mut notice_live_at_rrs = false;
    for _ in 0..8000 {
        let was_g = world.snaps[0].rrs_applied;
        let live_before_g = world.snaps[0].notice_down_live;
        world.step(25);
        if world.snaps[0].rrs_applied > was_g {
            notice_live_at_rrs = live_before_g
                && world.switch.notice_manifests_delivered > 0
                && world.switch.notice_chunks_dropped > 0
                && world.snaps[1].phase == PHASE_ACTIVE;
        }
        if world.snaps[0].rrs_applied > gw_rrs && world.snaps[2].rrs_applied > b_rrs {
            break;
        }
    }
    assert!(
        world.snaps[0].rrs_applied > gw_rrs,
        "gateway enforced: {:?}",
        world.snaps[0]
    );
    assert!(
        world.snaps[2].rrs_applied > b_rrs,
        "relay B enforced: {:?}",
        world.snaps[2]
    );
    let notice = world.revoke_notice(&outcome.operation_id);
    assert!(
        matches!(notice, Some((_, false))),
        "enforced with the notice still unconfirmed: {notice:?}"
    );
    if stall {
        assert!(
            notice_live_at_rrs,
            "gateway had A's Notice down slot when RRS enforced"
        );
        assert_eq!(world.snaps[1].phase, PHASE_ACTIVE, "A still active at RRS");
        assert!(
            world.snaps[1].has_site,
            "A holds site during Notice transfer"
        );
        assert!(
            world.switch.notice_manifests_delivered > 0,
            "the Notice manifest reached A before the stalled chunk"
        );
        assert!(
            world.switch.notice_chunks_dropped > 0,
            "the stall ate a Notice chunk, not unrelated radio traffic"
        );
    }
    // The enforcement retired A's contexts on the relay that held
    // them (not a mere RX hush: the sessions are gone). The gateway
    // never held an A session (deaf by topology); its refusal shows
    // on the relayed A->gateway leg below.
    assert!(
        world.snaps[2].link_sessions < b_link,
        "relay retired A's link: {} -> {}",
        b_link,
        world.snaps[2].link_sessions
    );
    assert!(
        world.snaps[2].end_sessions < b_end,
        "relay retired A's E2E: {} -> {}",
        b_end,
        world.snaps[2].end_sessions
    );
    let gw_est = world.snaps[0].link_established + world.snaps[0].end_established;
    let b_est = world.snaps[2].link_established + world.snaps[2].end_established;
    let gw_rx = world.snaps[0].rx_count;
    let b_rx = world.snaps[2].rx_count;

    // Refusal on every leg: A keeps sending (it does not know yet),
    // nothing new is admitted, while the survivors still deliver to
    // each other. (Well before any ZT: the revoked road takes ~13
    // virtual minutes to even start asking.)
    // (A peer tracks 16 app sends per lifetime.)
    for round in 0..3 {
        // Alternate the direct and the relayed revoked leg.
        let dst = if round % 2 == 0 {
            NODE_B
        } else {
            testkit::GATEWAY
        };
        world.peers[1].app_send(dst, b"r1-revoked-data");
        world.peers[2].app_send(testkit::GATEWAY, b"r1-healthy-data");
        for _ in 0..40 {
            world.step(25);
        }
        let delivered_now = world.snaps[1]
            .app_tx
            .iter()
            .filter(|tx| tx.state == DELIVERY_DELIVERED)
            .count();
        assert_eq!(
            delivered_now, delivered_before,
            "round {round}: no revoked A send delivered: {:?}",
            world.snaps[1].app_tx
        );
    }
    assert_eq!(
        world.snaps[2].rx_count, b_rx,
        "B took no app RX from revoked A"
    );
    // The gateway's RX grew by exactly B's 3 healthy sends — A's
    // relayed send never arrived (B drops revoked origins).
    assert_eq!(
        world.snaps[0].rx_count,
        gw_rx + 3,
        "gateway RX is exactly the survivors' traffic"
    );
    assert_eq!(
        world.snaps[0].rx_src, NODE_B,
        "gateway RX came from survivor B"
    );
    assert_eq!(
        world.snaps[0].link_established + world.snaps[0].end_established,
        gw_est,
        "gateway admitted no new session from A"
    );
    assert_eq!(
        world.snaps[2].link_established + world.snaps[2].end_established,
        b_est,
        "relay admitted no new session from A"
    );
    assert!(
        world.snaps[2]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED),
        "survivor B->gateway still delivers: {:?}",
        world.snaps[2].app_tx
    );
    // The stall served its purpose (enforcement under a live notice
    // slot): let the recovery path use the radio again.
    world.switch.drop_notice_chunks = false;

    // Erasure, by whichever road won: the resumed direct send lands
    // Removing in seconds; the ZT road needs A's own retries — a
    // revoked device whose app keeps sending re-discovers, hears the
    // survivors' newer-generation offers, strikes out and re-verifies
    // (04 §3.5). The loop keeps both legs honest: A's retries must
    // never deliver, the survivors' traffic must.
    let mut chatter_rounds = 0_u32;
    for i in 0..48000 {
        world.step(25);
        if world.snaps[1].phase == PHASE_HOLDOFF {
            break;
        }
        // Every 30 s of virtual time: A retries (its app does not
        // know yet) while the survivors keep ordinary mesh activity
        // — delivered traffic plus an unanswered discovery round, the
        // chatter a live radio carries and A's newer-generation
        // evidence rides on (04 §3.5).
        if i % 1200 == 1199 && chatter_rounds < 8 {
            chatter_rounds += 1;
            let a_dst = if chatter_rounds % 2 == 0 {
                NODE_B
            } else {
                NODE_GHOST
            };
            world.peers[1].app_send(a_dst, b"r1-retry");
            let b_dst = if chatter_rounds % 2 == 0 {
                testkit::GATEWAY
            } else {
                NODE_GHOST
            };
            world.peers[2].app_send(b_dst, b"r1-chatter");
        }
    }
    let a = &world.snaps[1];
    assert_eq!(a.phase, PHASE_HOLDOFF, "A holdoff: {a:?}");
    assert!(!a.has_site, "A erased its site trust");
    assert!(
        a.holdoff_remaining_ms > 0,
        "holdoff runs after erasure: {}",
        a.holdoff_remaining_ms
    );
    assert_eq!(
        a.id_fp, id_fp_before,
        "revocation leaves the RLI1 fingerprint untouched"
    );
}

#[test]
fn mesh_r1_notice_and_prompt_refusal() {
    // Main condition: the notice stalls mid-chunk while RRS enforces.
    r1_once("r1-stall", true);
    // Control: the same race unstalled — enforcement-first and
    // erasure hold either way; only the winning road may differ.
    r1_once("r1-control", false);
}

/// Drives a revoked A to its end state over whichever road wins (the
/// resumed direct send or the ZT verify): holdoff with the site
/// erased and the identity fingerprint untouched. Same shape as R1's
/// loop — A retries while the survivors chatter, so a live radio's
/// newer-generation evidence keeps arriving (§3.5).
pub(super) fn revoked_a_to_holdoff(world: &mut MeshWorld, tag: &str, id_fp_before: u64) {
    let mut saw_removing = world.snaps[1].phase == PHASE_REMOVING;
    let mut chatter_rounds = 0_u32;
    for i in 0..48000 {
        world.step(25);
        saw_removing |= world.snaps[1].phase == PHASE_REMOVING;
        if world.snaps[1].phase == PHASE_HOLDOFF {
            break;
        }
        if i % 1200 == 1199 && chatter_rounds < 8 {
            chatter_rounds += 1;
            let a_dst = if chatter_rounds % 2 == 0 {
                NODE_B
            } else {
                NODE_GHOST
            };
            world.peers[1].app_send(a_dst, b"r2-retry");
            let b_dst = if chatter_rounds % 2 == 0 {
                testkit::GATEWAY
            } else {
                NODE_GHOST
            };
            world.peers[2].app_send(b_dst, b"r2-chatter");
        }
    }
    let a = &world.snaps[1];
    assert_eq!(a.phase, PHASE_HOLDOFF, "{tag}: A holdoff: {a:?}");
    assert!(!a.has_site, "{tag}: A erased its site trust");
    assert!(
        a.holdoff_remaining_ms > 0,
        "{tag}: holdoff runs after erasure: {}",
        a.holdoff_remaining_ms
    );
    assert_eq!(
        a.id_fp, id_fp_before,
        "{tag}: revocation leaves the RLI1 fingerprint untouched"
    );
    assert!(saw_removing, "{tag}: A passed through Removing");
}

/// R2 (§5.2): revoke while the target cannot be reached, expire the
/// 60 s direct-send window, then reconnect. `group` selects the
/// variant: only A isolated (the survivors enforce during the
/// outage), or B/A isolated from G as one group (in-group traffic
/// survives the revoke, B enforces only after the heal). Either way
/// the survivors' RRS/GK advance without the notice confirmation,
/// the outage never counts as reached, and A ends erased via ZT.
pub(super) fn r2_once(tag: &str, group: bool) {
    use routeloom_client::site::{RemovalReason, SiteAdmin};
    let Some(mut world) = MeshWorld::start(tag, Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "r2 revoke");
    let id_fp_before = world.snaps[1].id_fp;
    assert_ne!(id_fp_before, 0, "A holds an identity fingerprint");
    // Pre-revoke delivery works (and brings the A-B E2E up, so the
    // later refusal is observable rather than vacuous).
    world.peers[1].app_send(NODE_B, b"r2-before");
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
        "pre-revoke A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    let delivered_before = world.snaps[1]
        .app_tx
        .iter()
        .filter(|tx| tx.state == DELIVERY_DELIVERED)
        .count();
    let gw_rrs = world.snaps[0].rrs_applied;
    let b_rrs = world.snaps[2].rrs_applied;
    let gk0 = world.active_gk();

    if group {
        world.switch.isolate(0);
    } else {
        world.switch.isolate(1);
    }
    let row = world.member_row(NODE_A).expect("member row");
    let outcome = world
        .provision
        .site
        .link
        .revoke(NODE_A, row.generation, RemovalReason::Removed, tag)
        .expect("revoke commits");
    assert_eq!(outcome.state, "committed");

    if group {
        // The gateway enforces over its local USB channel while its
        // radio is cut; the island hears nothing yet.
        world.pump_until(8000, |snaps| snaps[0].rrs_applied > gw_rrs);
        assert!(
            world.snaps[0].rrs_applied > gw_rrs,
            "gateway enforced while cut: {:?}",
            world.snaps[0]
        );
        for _ in 0..200 {
            world.step(25);
        }
        assert_eq!(
            world.snaps[2].rrs_applied, b_rrs,
            "island B holds no RRS yet"
        );
        // In-group traffic survives the revoke (04 §6.2): B never saw
        // the RRS, so the old link still delivers.
        world.peers[1].app_send(NODE_B, b"r2-island");
        world.pump_until(3000, |snaps| {
            snaps[1]
                .app_tx
                .iter()
                .filter(|tx| tx.state == DELIVERY_DELIVERED)
                .count()
                > delivered_before
        });
        let delivered_island = world.snaps[1]
            .app_tx
            .iter()
            .filter(|tx| tx.state == DELIVERY_DELIVERED)
            .count();
        assert!(
            delivered_island > delivered_before,
            "in-group A->B delivers after the revoke: {:?}",
            world.snaps[1].app_tx
        );
    } else {
        // Both survivors enforce while the notice to A cannot move.
        world.pump_until(8000, |snaps| {
            snaps[0].rrs_applied > gw_rrs && snaps[2].rrs_applied > b_rrs
        });
        assert!(
            world.snaps[0].rrs_applied > gw_rrs,
            "gateway enforced: {:?}",
            world.snaps[0]
        );
        assert!(
            world.snaps[2].rrs_applied > b_rrs,
            "relay B enforced: {:?}",
            world.snaps[2]
        );
    }
    let notice = world.revoke_notice(&outcome.operation_id);
    assert!(
        matches!(notice, Some((_, false))),
        "enforced with the notice still unconfirmed: {notice:?}"
    );
    // The revoke-driven GK rotation advances on the reachable side
    // without the notice confirmation (the gateway only, in the group
    // variant — the island holds the old key).
    let gk1 = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status")
        .active;
    assert!(gk1 > gk0, "the revoke rotated the GK: {gk0} -> {gk1}");
    world.pump_until(8000, |snaps| {
        snaps[0].gk_current == gk1 && (group || snaps[2].gk_current == gk1)
    });
    assert_eq!(
        world.snaps[0].gk_current, gk1,
        "gateway GK advanced during the outage"
    );
    if group {
        assert_eq!(
            world.snaps[2].gk_current, gk0,
            "island B holds the old GK until the heal"
        );
    } else {
        assert_eq!(
            world.snaps[2].gk_current, gk1,
            "reachable B GK advanced during the outage"
        );
    }
    assert_eq!(
        world.snaps[1].gk_current, gk0,
        "isolated A holds the old GK"
    );
    let notice = world.revoke_notice(&outcome.operation_id);
    assert!(
        matches!(notice, Some((_, false))),
        "RRS+GK advanced, notice still unconfirmed: {notice:?}"
    );
    // The outage never counts as reached: solo leaves no reachable
    // member unapplied (A's erasure is not RRS distribution); the
    // group variant counts the legitimately unapplied B unknown.
    let progress = world
        .provision
        .site
        .link
        .operation(&outcome.operation_id)
        .expect("revoke status")
        .expect("revoke tracked");
    if group {
        assert!(
            progress.distribution.unknown >= 1,
            "island B counts unknown: {:?}",
            progress.distribution
        );
    } else {
        assert_eq!(
            progress.distribution.unknown, 0,
            "solo outage counts nothing unknown: {:?}",
            progress.distribution
        );
    }

    // Expire the 60 s direct-send window, then reconnect.
    for _ in 0..2600 {
        world.step(25);
    }
    let notice = world.revoke_notice(&outcome.operation_id);
    assert!(
        matches!(notice, Some((_, false))),
        "window expired, still unconfirmed: {notice:?}"
    );
    assert!(
        world.snaps[1].has_site,
        "isolated A still holds its site: {:?}",
        world.snaps[1]
    );
    if group {
        assert!(
            world.snaps[2].link_sessions > 0,
            "the in-group link is still up at the heal: {:?}",
            world.snaps[2]
        );
        world.switch.heal(0);
        // B enforces only now — and the live in-group link must not
        // block the recovery that follows.
        world.pump_until(12000, |snaps| snaps[2].rrs_applied > b_rrs);
        assert!(
            world.snaps[2].rrs_applied > b_rrs,
            "B enforced after the heal: {:?}",
            world.snaps[2]
        );
    } else {
        world.switch.heal(1);
    }
    let rs_epoch = world
        .provision
        .site
        .link
        .operation(&outcome.operation_id)
        .expect("revoke status")
        .expect("revoke tracked")
        .rs_epoch;
    assert_eq!(
        world.snaps[2].applied_rs, rs_epoch,
        "B enforces the RRS that revokes A"
    );

    // Refusal after the heal: A's retries (direct and relayed) never
    // deliver and admit no session; B's RRS epoch above is the
    // reason, not a mere RX hush. Re-convergence is still in flight
    // when the enforcement lands — B (not revoked) re-links to the
    // gateway and that bumps the same counters. Baseline only once
    // they have settled, so the window measures revoked-A admissions
    // alone.
    let mut last_gw = u32::MAX;
    let mut last_b = u32::MAX;
    let mut quiet = 0u32;
    for _ in 0..20000 {
        world.step(25);
        let gw = world.snaps[0].link_established + world.snaps[0].end_established;
        let b = world.snaps[2].link_established + world.snaps[2].end_established;
        if gw == last_gw && b == last_b {
            quiet += 1;
            if quiet >= 200 {
                break;
            }
        } else {
            quiet = 0;
            last_gw = gw;
            last_b = b;
        }
    }
    let b_rx = world.snaps[2].rx_count;
    let gw_est = world.snaps[0].link_established + world.snaps[0].end_established;
    let b_est = world.snaps[2].link_established + world.snaps[2].end_established;
    let delivered_pre = world.snaps[1]
        .app_tx
        .iter()
        .filter(|tx| tx.state == DELIVERY_DELIVERED)
        .count();
    for round in 0..3 {
        let dst = if round % 2 == 0 {
            NODE_B
        } else {
            testkit::GATEWAY
        };
        world.peers[1].app_send(dst, b"r2-revoked-data");
        for _ in 0..40 {
            world.step(25);
        }
        let delivered_now = world.snaps[1]
            .app_tx
            .iter()
            .filter(|tx| tx.state == DELIVERY_DELIVERED)
            .count();
        assert_eq!(
            delivered_now, delivered_pre,
            "round {round}: no revoked A send delivered: {:?}",
            world.snaps[1].app_tx
        );
    }
    assert_eq!(
        world.snaps[2].rx_count, b_rx,
        "B took no app RX from revoked A"
    );
    assert_eq!(
        world.snaps[0].link_established + world.snaps[0].end_established,
        gw_est,
        "gateway admitted no new session from A"
    );
    assert_eq!(
        world.snaps[2].link_established + world.snaps[2].end_established,
        b_est,
        "relay admitted no new session from A"
    );

    revoked_a_to_holdoff(&mut world, tag, id_fp_before);
}

#[test]
fn mesh_r2_isolated_revoke_and_recovery() {
    // Solo: only A isolated; the survivors enforce during the outage.
    r2_once("r2-solo", false);
    // Group: B/A isolated from G as one island; in-group traffic
    // survives the revoke until the heal.
    r2_once("r2-group", true);
}

/// A manual GK rotation through the service on the virtual clock
/// (not the API socket's process clock — see K1). Returns the new
/// epoch on commit, or the rejection code when BUSY/CONFLICT.
pub(super) fn rotate_direct(
    world: &mut MeshWorld,
    expected: u32,
    key: &str,
) -> Result<u32, String> {
    let now = world.now;
    let outcome = world
        .provision
        .site
        .service
        .with(|a| {
            a.rotate(
                501,
                crate::site::RotateRequest {
                    expected_active_epoch: expected,
                    key: key.into(),
                },
                HostTime::sync(now),
            )
        })
        .0;
    match outcome {
        Ok(json) => {
            let value: routeloom_json::Json = routeloom_json::parse(&json).expect("outcome parses");
            assert_eq!(
                value.get("state").and_then(|v| v.as_str()),
                Some("committed")
            );
            Ok(value.get("to").and_then(|v| v.as_u64()).expect("to epoch") as u32)
        }
        Err(error) => Err(error.code.to_string()),
    }
}

/// K1 (§5.2): A misses two consecutive GK epochs on forced G—B—A
/// while G/B advance to g+1 then g+2 and the old-key RX overlap
/// expires. A is never counted applied; its stale-keyed chatter is
/// refused on the generation (which never reaches tag verification,
/// so this is key rejection, not replay); then A converges straight
/// to g+2 (no g+1 redistribution) without a rescue reset, the host
/// holds durable ACKs from every member, and unicast flows both ways.
#[test]
fn mesh_k1_gk_double_miss() {
    use routeloom_client::site::SiteAdmin;
    let Some(mut world) = MeshWorld::start("k1", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "k1 rotate");
    let gk0 = world.active_gk();
    // Pre-rotation control: unicast delivers at g0.
    world.peers[1].app_send(NODE_B, b"k1-before");
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
        "pre-rotation A->B delivered: {:?}",
        world.snaps[1].app_tx
    );
    // A misses two rotations outright. Both rotate through the service
    // with the virtual clock: the API socket would stamp the process
    // monotonic clock while the harness ticks the authority on
    // wall-based virtual time, which wedges the 60 s cleanup gate
    // (same harness-only mixup the cutover test works around — the
    // production daemon runs one clock).
    world.switch.isolate(1);
    let gk1 = rotate_direct(&mut world, gk0, "k1-gk-1").expect("rotate 1 commits");
    assert!(gk1 > gk0);
    world.pump_until(8000, |snaps| {
        snaps[0].gk_current == gk1 && snaps[2].gk_current == gk1
    });
    assert_eq!(world.snaps[0].gk_current, gk1, "gateway at g+1");
    assert_eq!(world.snaps[2].gk_current, gk1, "B at g+1");
    assert_eq!(world.snaps[1].gk_current, gk0, "A missed g+1");
    // The authority activates g+1 late (A's stage deadline runs while
    // it is dark) and only then starts the 60 s post-activation
    // cleanup that BUSYs a successor — wait for the activation first.
    for _ in 0..4000 {
        world.step(25);
        let active = world
            .provision
            .site
            .link
            .group_key_status()
            .map(|s| s.active)
            .unwrap_or(0);
        if active == gk1 {
            break;
        }
    }
    assert_eq!(
        world
            .provision
            .site
            .link
            .group_key_status()
            .expect("gk status")
            .active,
        gk1,
        "authority activated g+1"
    );
    // A successor is allowed while catching_up (§6.3): G/B move on
    // to g+2 with A still dark. Retry past the cleanup window.
    let mut gk2 = None;
    for _ in 0..70 {
        match rotate_direct(&mut world, gk1, "k1-gk-2") {
            Ok(to) => {
                gk2 = Some(to);
                break;
            }
            Err(_) => {
                for _ in 0..40 {
                    world.step(25);
                }
            }
        }
    }
    let gk2 = gk2.expect("rotate 2 commits past cleanup");
    assert!(gk2 > gk1);
    world.pump_until(8000, |snaps| {
        snaps[0].gk_current == gk2 && snaps[2].gk_current == gk2
    });
    assert_eq!(world.snaps[0].gk_current, gk2, "gateway at g+2");
    assert_eq!(world.snaps[2].gk_current, gk2, "B at g+2");
    assert_eq!(world.snaps[1].gk_current, gk0, "A missed g+2");
    let status = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status");
    assert_eq!(status.active, gk2);
    assert!(
        status.unknown >= 1,
        "A is not counted g+2-applied: {status:?}"
    );
    // Past the old-key RX overlap (Manual: 60 s from the g+2
    // activation the pump just observed) before A may speak again.
    for _ in 0..2800 {
        world.step(25);
    }
    assert_eq!(
        world.snaps[1].gk_current, gk0,
        "A still holds g0 past the overlap"
    );

    // Stale-key rejection in the first breath after the heal: A's
    // links are down so it re-discovers immediately, still keyed g0,
    // while its own rescue (channel re-handshake, then Pull/ZT) needs
    // far longer. Arrival plus the generation verdict plus no
    // admission is the complete evidence: an unknown generation never
    // reaches tag verification — a replay verdict would need an
    // accepted generation first — so growth here is key rejection,
    // not replay. The trailing gk check voids the window loudly if A
    // ever converges too fast to judge.
    world.switch.heal(1);
    let b_raw = world.snaps[2].scope_raw_rx;
    let b_unkgen = world.snaps[2].scope_unknown_generation;
    let b_scope_ok = world.snaps[2].scope_accepted;
    for _ in 0..150 {
        world.step(25);
    }
    assert!(
        world.snaps[2].scope_raw_rx > b_raw,
        "A's stale chatter arrived: {:?}",
        world.snaps[2]
    );
    assert!(
        world.snaps[2].scope_unknown_generation > b_unkgen,
        "B rejects it as an unknown generation: {:?}",
        world.snaps[2]
    );
    assert_eq!(
        world.snaps[2].scope_accepted, b_scope_ok,
        "B admitted none of it: {:?}",
        world.snaps[2]
    );
    assert_eq!(
        world.snaps[1].gk_current, gk0,
        "A still stale at the verdict: {:?}",
        world.snaps[1]
    );

    // Full convergence, straight to g+2 — Pull or ZT, but never
    // through the dead g+1 (no redistribution of it exists to take).
    // Every step is sampled: any staging of the dead epoch fails.
    let mut saw_gk1 = false;
    for _ in 0..12000 {
        world.step(25);
        let held = world.snaps[1].gk_current;
        saw_gk1 |= held == gk1;
        if held == gk2 {
            break;
        }
    }
    assert_eq!(
        world.snaps[1].gk_current, gk2,
        "A converged to g+2: {:?}",
        world.snaps[1]
    );
    assert!(!saw_gk1, "A never staged the dead g+1");
    // No rescue: A keeps its links and reaches the site at g+2 on its
    // own; the host holds durable active ACKs from every member and
    // unicast crosses both ways (the 15 min tail: recovery.rs J08).
    let settled = world.now;
    while world.now - settled < 120_000 {
        let status = world
            .provision
            .site
            .link
            .group_key_status()
            .expect("gk status");
        if status.phase == "stable" && status.unknown == 0 {
            break;
        }
        for _ in 0..40 {
            world.step(25);
        }
    }
    let status = world
        .provision
        .site
        .link
        .group_key_status()
        .expect("gk status");
    assert_eq!(
        (status.phase.as_str(), status.unknown),
        ("stable", 0),
        "every member durably at g+2: {status:?}"
    );
    super::mesh::deliver_each(&mut world, 1, 0, 10, b"k1-up");
    super::mesh::deliver_each(&mut world, 0, 1, 10, b"k1-down");
}
