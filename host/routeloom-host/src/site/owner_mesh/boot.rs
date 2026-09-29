//! Device boot-path rows (tests/e2e/scenarios.json M06 gateway reset,
//! F02 boot-time NVS write failure, J01 identity-only join): every boot
//! and respawn goes through the production `routeloom::Device` path.

use std::collections::BTreeSet;

use super::cutover::decider_requests_for;
use super::*;

/// Records every sequence of `index`'s app sends seen Delivered so far.
fn note_delivered(world: &MeshWorld, index: usize, delivered: &mut BTreeSet<u64>) {
    for tx in &world.snaps[index].app_tx {
        if tx.state == DELIVERY_DELIVERED {
            delivered.insert(tx.seq);
        }
    }
}

/// Steps until `peer` finished `reboots` respawns (or `budget_ms` passed).
fn step_until_reboots(world: &mut MeshWorld, peer: usize, reboots: u32, budget_ms: u64) {
    let until = world.now + budget_ms;
    while world.peers[peer].reboots < reboots && world.now < until {
        world.step(25);
    }
    assert_eq!(world.peers[peer].reboots, reboots, "peer {peer} respawns");
}

/// M06, gateway row: A keeps a Reliable stream to the gateway (one send
/// every 2 s) across a gateway power cut. The respawned gateway boots from
/// its flash, re-authenticates USB with a newer boot id within 5 s, and
/// delivery resumes within 15 s (vt); ten further sends all arrive, each
/// exactly once at the gateway.
#[test]
fn mesh_m06_gateway_power_cut_resumes() {
    let Some(mut world) = MeshWorld::start("m06-gw", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "m06 gateway reset");
    let mut delivered = BTreeSet::new();
    world.peers[1].app_send(testkit::GATEWAY, b"m06-before");
    world.pump_until(4000, |snaps| {
        snaps[1]
            .app_tx
            .iter()
            .any(|tx| tx.state == DELIVERY_DELIVERED)
    });
    note_delivered(&world, 1, &mut delivered);
    assert_eq!(
        delivered.len(),
        1,
        "A->G before the cut: {:?}",
        world.snaps[1].app_tx
    );
    let boot_before = world.usb_host.hello_boot.expect("gateway hello");

    world.peers[0].power_cut();
    step_until_reboots(&mut world, 0, 1, 1000);
    let rebooted_at = world.now;
    let mut next_send = world.now;
    let mut resumed_at = None;
    while world.now < rebooted_at + 15_000 && resumed_at.is_none() {
        if world.now >= next_send {
            world.peers[1].app_send(testkit::GATEWAY, b"m06-stream");
            next_send += 2000;
        }
        world.step(25);
        let before = delivered.len();
        note_delivered(&world, 1, &mut delivered);
        if delivered.len() > before {
            resumed_at = Some(world.now);
        }
    }
    let resumed_at = resumed_at.unwrap_or_else(|| {
        panic!(
            "delivery resumed within 15 s of the gateway reboot: A {:?}; G {:?}",
            world.snaps[1].app_tx, world.snaps[0]
        )
    });
    assert!(
        !world.usb_host.auth_sessions.is_empty(),
        "gateway USB re-authenticated after its reboot"
    );
    let boot_after = world
        .usb_host
        .hello_boot
        .expect("gateway hello after reboot");
    assert!(
        boot_after > boot_before,
        "boot id {boot_after} after {boot_before}"
    );

    // Ten more sends, one every 2 s: all delivered (sequences rise per
    // send, so they are the ten newest).
    for _ in 0..10 {
        world.peers[1].app_send(testkit::GATEWAY, b"m06-after");
        for _ in 0..80 {
            world.step(25);
            note_delivered(&world, 1, &mut delivered);
        }
    }
    world.pump_until(400, |_| false);
    note_delivered(&world, 1, &mut delivered);
    let mut newest: Vec<&MeshAppTx> = world.snaps[1].app_tx.iter().collect();
    newest.sort_by_key(|tx| std::cmp::Reverse(tx.seq));
    assert!(
        newest.len() >= 10 && newest[..10].iter().all(|tx| tx.state == DELIVERY_DELIVERED),
        "10/10 after resume ({} ms after the reboot): {:?}",
        resumed_at - rebooted_at,
        world.snaps[1].app_tx
    );
    // Exactly once at the rebooted gateway: every message it took is one
    // of A's sends confirmed delivered after the cut.
    assert_eq!(
        world.snaps[0].rx_count as usize,
        delivered.len() - 1,
        "gateway rx equals A's deliveries since the cut (no duplicate)"
    );
    assert_eq!(world.snaps[0].rx_src, NODE_A);
}

/// F02, boot slice: A's next boot fails its `k`-th NVS write (the boot
/// session record and its commit). The Device refuses to start — no
/// radio, no membership claimed — and takes the firmware restart path;
/// the following boot, fault cleared, resumes membership from flash and
/// delivers 20/20 to the gateway.
#[test]
fn mesh_f02_boot_nvs_write_failure_restarts_clean() {
    for k in [1u32, 2] {
        let tag = format!("f02-boot-{k}");
        let Some(mut world) = MeshWorld::start(&tag, Switch::direct()) else {
            return; // no C++ peers: skip (ignore-equivalent)
        };
        converge(&mut world, "f02");
        let generation = world.snaps[1].site_generation;
        world.peers[1].nvs_fail_next = Some(k);
        world.peers[1].power_cut();
        // Power cut, then the faulted boot's own restart.
        step_until_reboots(&mut world, 1, 2, 2000);
        let recovered_from = world.now;
        world.pump_until(1200, |snaps| {
            snaps[1].mode == MODE_MEMBER
                && snaps[1].phase == PHASE_ACTIVE
                && snaps[1].authority_ready
        });
        assert!(
            world.now - recovered_from <= 30_000 && world.snaps[1].authority_ready,
            "k={k}: A back within 30 s: {:?}",
            world.snaps[1]
        );
        assert_eq!(
            world.snaps[1].mode, MODE_MEMBER,
            "k={k}: A resumed its membership"
        );
        assert_eq!(
            world.snaps[1].site_generation, generation,
            "k={k}: generation kept"
        );
        let mut delivered = BTreeSet::new();
        for _ in 0..20 {
            world.peers[1].app_send(testkit::GATEWAY, b"f02");
            for _ in 0..20 {
                world.step(25);
                note_delivered(&world, 1, &mut delivered);
            }
        }
        world.pump_until(2000, |snaps| {
            snaps[1]
                .app_tx
                .iter()
                .filter(|tx| tx.state == DELIVERY_DELIVERED)
                .count()
                >= 16
        });
        note_delivered(&world, 1, &mut delivered);
        assert_eq!(delivered.len(), 20, "k={k}: 20/20 after recovery");
    }
}

/// J01: A boots `identity_only` (its sealed RLI1, no site) behind relay B
/// (G—B—A, A never hears G). While the site has no decision A's join stays
/// pending and A claims no membership; once the site assigns A, A joins
/// through B's proxy (ZeroTouch over the real relay, USB and authority),
/// is Member within 30 s (vt) and delivers 20/20 to the gateway. The join
/// reached the authority as one request and the site ledger holds A at the
/// generation the device adopted.
#[test]
fn mesh_j01_identity_only_joins_through_relay() {
    let Some(mut world) = MeshWorld::start_identity_only("j01", Switch::forced_multihop(), &[1])
    else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    world.provision.site.decider.pending_retry_s = 5;
    world.pump_until(9000, |snaps| {
        snaps[0].authority_ready && snaps[2].authority_ready && snaps[2].join_confirmed
    });
    assert!(
        world.snaps[2].join_confirmed,
        "relay B converged: {:?}",
        world.snaps[2]
    );
    assert!(
        world.snaps[1].has_identity && !world.snaps[1].has_site,
        "A booted identity-only: {:?}",
        world.snaps[1]
    );
    // No decision yet: the request reaches the authority, A stays out.
    let until = world.now + 20_000;
    while decider_requests_for(&world, NODE_A) == 0 && world.now < until {
        world.step(25);
    }
    world.pump_until(400, |snaps| snaps[1].mode == MODE_MEMBER);
    assert_ne!(
        world.snaps[1].mode, MODE_MEMBER,
        "a pending join admits nothing"
    );
    assert!(!world.snaps[1].has_site, "no site record while pending");
    assert_eq!(
        decider_requests_for(&world, NODE_A),
        1,
        "one join request for A"
    );
    assert!(world.member_row(NODE_A).is_none_or(|row| !row.member));

    world
        .provision
        .site
        .decider
        .assign(NODE_A, Assignment::Here(Role::Relay));
    let approved_at = world.now;
    world.pump_until(1200, |snaps| {
        snaps[1].mode == MODE_MEMBER
            && snaps[1].phase == PHASE_ACTIVE
            && snaps[1].authority_ready
            && snaps[1].join_confirmed
    });
    assert!(
        world.snaps[1].join_confirmed && world.now - approved_at <= 30_000,
        "A Member within 30 s of the approval: {:?}",
        world.snaps[1]
    );
    assert!(
        world.snaps[1].proxy_relays_completed == 0,
        "A proxied nothing itself"
    );
    assert!(
        world.snaps[2].proxy_relays_completed > 0,
        "B relayed A's join"
    );
    let row = world.member_row(NODE_A).expect("A row");
    assert!(row.member && row.confirmed, "site ledger: {row:?}");
    assert_eq!(
        row.generation, world.snaps[1].site_generation,
        "ledger generation"
    );
    assert_eq!(decider_requests_for(&world, NODE_A), 1, "still one request");

    let mut delivered = BTreeSet::new();
    for _ in 0..20 {
        world.peers[1].app_send(testkit::GATEWAY, b"j01");
        for _ in 0..20 {
            world.step(25);
            note_delivered(&world, 1, &mut delivered);
        }
    }
    world.pump_until(400, |_| false);
    note_delivered(&world, 1, &mut delivered);
    assert_eq!(delivered.len(), 20, "20/20 A->G after the join");
}
