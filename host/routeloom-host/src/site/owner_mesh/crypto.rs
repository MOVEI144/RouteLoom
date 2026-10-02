//! V2-16 crypto-delay rows over the real Owner, runtime and Site Authority.

use super::*;

fn topology() -> Switch {
    Switch::new(&Topology {
        nodes: 6,
        edges: vec![(0, 2), (2, 1), (2, 3), (2, 4), (2, 5)],
    })
}

fn start(tag: &str, switch: Switch, identity: &[usize], blocked: bool) -> MeshWorld {
    let boot = vec![0; switch.nodes()];
    let args: &[&str] = if blocked {
        &["--crypto-ms", "154", "--crypto-sync"]
    } else {
        &["--crypto-ms", "154"]
    };
    MeshWorld::start_booted(tag, switch, &boot, false, identity, &[args, args])
        .expect("crypto acceptance requires live C++ peers")
}

fn ready(s: &MeshSnap) -> bool {
    s.mode == MODE_MEMBER && s.phase == PHASE_ACTIVE && s.authority_ready && s.join_confirmed
}

fn converge(world: &mut MeshWorld) {
    world.pump_until(6000, |s| s.iter().all(ready));
    assert!(
        world.snaps.iter().all(ready),
        "crypto boot: {:?}",
        world.snaps
    );
    assert!(world.snaps.iter().all(|s| s.crypto_submitted > 0));
}

fn balanced(world: &MeshWorld) {
    for s in &world.snaps {
        assert!(s.crypto_pending <= 1);
        assert!(s.crypto_completed <= s.crypto_submitted);
        assert!(s.crypto_submitted - s.crypto_completed <= 1);
        assert!(s.crypto_owner_ms <= 25);
    }
}

#[test]
fn mesh_m05_crypto_six_simultaneous_boots() {
    let mut world = start("m05-crypto", Switch::new(&Topology::full(6)), &[], false);
    let booted = |s: &[MeshSnap]| {
        s.iter().all(|s| {
            s.mode == MODE_MEMBER
                && s.phase == PHASE_ACTIVE
                && s.stores_healthy
                && s.applied_rs >= 1
        })
    };
    world.pump_until(6000, booted);
    assert!(booted(&world.snaps), "six cold boots adopted");
    assert!(world.snaps.iter().all(|s| s.crypto_submitted > 0));
    for peer in &mut world.peers {
        peer.power_cut();
    }
    world.step(25);
    world.pump_until(6000, booted);
    assert!(booted(&world.snaps), "six warm boots adopted");
    assert!(world.peers.iter().all(|p| p.reboots == 1));
    balanced(&world);
}

#[test]
fn mesh_j03_crypto_simultaneous_join_and_refusal() {
    let mut world = start(
        "j03-crypto",
        Switch::new(&Topology::full(4)),
        &[1, 3],
        false,
    );
    world
        .provision
        .site
        .decider
        .assign(world.nodes[1], Assignment::Here(Role::Relay));
    world
        .provision
        .site
        .decider
        .assign(world.nodes[3], Assignment::Blocked);
    world.pump_until(12000, |s| {
        ready(&s[0]) && ready(&s[1]) && ready(&s[2]) && s[3].j_m1 > 0
    });
    assert!(ready(&world.snaps[1]), "allowed join: {:?}", world.snaps);
    assert!(
        !world.snaps[3].has_site,
        "blocked join cannot install membership"
    );
    assert!(world.snaps[1].j_attempts <= 3);
    assert!(world.snaps[3].j_attempts <= 3);
    super::mesh::deliver_each(&mut world, 1, 0, 1, b"crypto-join");
    balanced(&world);
}

fn background(blocked: bool) -> (u32, u64) {
    let mut world = start(
        if blocked { "f08-control" } else { "f08-worker" },
        topology(),
        &[3, 4, 5],
        blocked,
    );
    for i in 3..6 {
        world.gate[i] = true;
        world
            .provision
            .site
            .decider
            .assign(world.nodes[i], Assignment::Here(Role::Relay));
    }
    world.gate[1] = true;
    world.pump_until(9000, |s| ready(&s[0]) && ready(&s[2]));
    world.gate[1] = false;
    world.pump_until(9000, |s| s[..3].iter().all(ready));
    assert!(
        world.snaps[..3].iter().all(ready),
        "background road: {:?}",
        world.snaps
    );
    super::mesh::deliver_each(&mut world, 1, 0, 1, b"crypto-warmup");
    let received = world.snaps[0].rx_count;
    let expired = world.snaps[..3]
        .iter()
        .map(|s| s.hop_accept_expired)
        .sum::<u64>();
    for i in 3..6 {
        world.gate[i] = false;
    }
    for sequence in 0u32..100 {
        world.peers[1].app_send(testkit::GATEWAY, &sequence.to_le_bytes());
        // A 10 ms air step resolves the 60 ms hop ACK deadline while
        // the delayed worker still costs 154 ms in the control model.
        for _ in 0..100 {
            world.step(10);
        }
    }
    world.pump_until(6000, |s| s.iter().all(ready));
    assert!(
        world.snaps.iter().all(ready),
        "join herd: {:?}",
        world.snaps
    );
    assert!(world.snaps[3..].iter().all(|s| s.crypto_submitted >= 8));
    let delivered = world.snaps[0].rx_count - received;
    let timeouts = world.snaps[..3]
        .iter()
        .map(|s| s.hop_accept_expired)
        .sum::<u64>()
        - expired;
    if !blocked {
        balanced(&world);
    } else {
        assert!(world.snaps.iter().any(|s| s.crypto_owner_ms > 25));
    }
    (delivered, timeouts)
}

#[test]
fn mesh_f08_crypto_preserves_relay_background() {
    let control = background(true);
    let worker = background(false);
    assert!(
        worker.0 >= 99,
        "background >=99%: control={control:?}, worker={worker:?}"
    );
    assert_eq!(
        worker.1, 0,
        "background path HOP_ACCEPT expiries: control={control:?}, worker={worker:?}"
    );
}

#[test]
fn mesh_k04_crypto_reset_resumes_view_and_status() {
    let mut world = start("k04-crypto", Switch::new(&Topology::full(3)), &[], false);
    converge(&mut world);
    super::mesh::deliver_each(&mut world, 0, 1, 1, b"view-old");
    super::mesh::deliver_each(&mut world, 1, 0, 1, b"status-old");
    world.peers[1].power_cut();
    let start = world.now;
    world.step(25);
    world.pump_until(350, |s| ready(&s[1]));
    assert!(ready(&world.snaps[1]), "reset: {:?}", world.snaps);
    let node = world.nodes[1];
    let before_view = world.snaps[1].rx_count;
    world.peers[0].app_send(node, b"view-new");
    world.pump_until(100, |s| s[1].rx_count > before_view);
    assert_eq!(world.snaps[1].rx, b"view-new");
    let before_status = world.snaps[0].rx_count;
    world.peers[1].app_send(testkit::GATEWAY, b"status-new");
    world.pump_until(100, |s| s[0].rx_count > before_status);
    assert_eq!(world.snaps[0].rx, b"status-new");
    assert!(world.now - start < 10000, "new view and status <10s");
    balanced(&world);
}

#[test]
fn mesh_crypto_cutover_replays_certificate_verification() {
    let mut world = start("crypto-cutover", Switch::direct(), &[], false);
    converge(&mut world);
    let staged_at = world.now;
    let operation = super::cutover::stage_cutover(&mut world, "crypto-cutover");
    let (operation, next_gk, network, _, _) =
        super::cutover::cutover_finish_prepare(&mut world, operation, staged_at);
    super::cutover::cutover_converged(&mut world, &operation, network, next_gk, None);
    super::mesh::deliver_each(&mut world, 1, 0, 1, b"crypto-cutover-new");
    balanced(&world);
}
