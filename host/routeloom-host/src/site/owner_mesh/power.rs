//! V2-15: Member sleep over the production Device, Owner, RTC and durable
//! power image; host clock skew and deadline-driven mesh time compression.
use super::mesh::route_loss_world;
use super::*;

#[test]
fn mesh_f03_g5_deadlines_survive_host_wall_skew() {
    let Some(mut world) = route_loss_world("f03-g5", Switch::forced_multihop(), true) else {
        panic!("F03/G5 require live C++ peers");
    };
    let start = world.now;
    let before = world.snaps[0].rx_count;
    world.peers[1].app_send(testkit::GATEWAY, b"wall-skew");
    let due = world.peers[1].deadline();
    // The authority receives explicit wall values, while every peer and
    // the distributor retain the same process-monotonic time.
    for wall in [0, start + 86_400_000] {
        world.wall_time = Some(wall);
        world.provision.site.service.tick(HostTime {
            mono_ms: world.now,
            unix_ms: wall,
        });
        assert_eq!(world.peers[1].deadline(), due);
    }
    let mut polls = 0;
    while world.now - start < 5000 && world.snaps[0].rx_count == before {
        let deadline = world
            .peers
            .iter_mut()
            .map(MeshPeer::deadline)
            .min()
            .unwrap();
        let dt = deadline.saturating_sub(world.now).clamp(1, 1000);
        world.step(dt);
        polls += 1;
    }
    assert_eq!(world.snaps[0].rx_count, before + 1);
    assert_eq!(world.snaps[0].rx, b"wall-skew");
    assert!(world.now - start <= 5000);
    let quiet = world.now;
    let mut idle_polls = 0;
    while world.now - quiet < 1000 {
        let deadline = world
            .peers
            .iter_mut()
            .map(MeshPeer::deadline)
            .min()
            .unwrap();
        let dt = deadline
            .saturating_sub(world.now)
            .clamp(1, 1000 - (world.now - quiet));
        world.step(dt);
        idle_polls += 1;
    }
    assert!(idle_polls < 750, "quiet Owner uses deadlines: {idle_polls}");
    eprintln!("G5 quiet real Owner: {idle_polls} deadline polls / 1000 eager polls");
    eprintln!(
        "G5 live Owner: {polls} deadline polls / {} eager 1 ms polls",
        world.now - start
    );
}

#[test]
fn mesh_f09_member_unified_sleep_and_isolated_day() {
    let Some(mut world) = route_loss_world("f09-sleep", Switch::forced_multihop(), true) else {
        panic!("F09-O requires live C++ peers");
    };
    let leaf = 1;
    let duration = 86_400_000;
    let start = world.now;
    world.switch.isolate(leaf);
    // Exhaust one bounded discovery window while the gateway is absent.
    // Every attempt shares the runtime's absolute cap; no queued bootstrap
    // retry may extend it past the next Owner tick.
    assert_eq!(world.peers[leaf].sleep(5, world.now, 1000).0, 0);
    world.step(1000);
    let exhausted = world.peers[leaf].sleep(4, world.now, duration).7;
    for _ in 0..5 {
        world.step(10);
    }
    assert_eq!(
        world.peers[leaf].sleep(4, world.now, duration).7,
        exhausted,
        "no driver submission after the discovery budget"
    );
    let prepared = world.peers[leaf].sleep(0, world.now, duration);
    assert_eq!(prepared.0, 0, "Device accepted Member sleep");
    let mut ready = prepared;
    // Sleep prepare cancels unfinished work and drains the actual radio.
    // The 500 ms production drain is below the per-wake 40 s radio budget.
    while !ready.2 && world.now - start < 2000 {
        world.step(1);
        ready = world.peers[leaf].sleep(4, world.now, duration);
    }
    assert!(
        ready.2 && ready.3,
        "ticket only after security park: {ready:?}"
    );
    let entered = world.peers[leaf].sleep(1, world.now, duration);
    assert_eq!(entered.0, 0, "Device sleep entry");
    assert_eq!(entered.1, 4, "Sleeping");
    assert_eq!(entered.4, 1);
    assert!(entered.6, "Member RTC session image committed");
    assert_eq!(
        world.peers[leaf].sleep(1, world.now, duration).0,
        2,
        "ticket consumed"
    );
    // No radio/Owner turn for the sleeping node. A full isolated day is
    // one external timer event, rather than 86 million empty polls.
    world.step(duration);
    world.switch.heal(leaf);
    let wake_at = world.now;
    let woke = world.peers[leaf].sleep(2, world.now, duration);
    assert_eq!(woke.0, 0, "Device wake");
    assert!(!woke.3, "security unparked");
    assert_eq!(woke.5, 1);
    // Deep sleep discards CPU RAM. The platform handoff uses the existing
    // peer respawn path, retaining flash and booting a fresh real Device.
    // The 24 h interval cannot reuse the old session's remaining lifetime.
    world.peers[leaf].power_cut();
    world.step(25);
    world.pump_until(2400, |snaps| {
        snaps[leaf].authority_ready && snaps[leaf].join_confirmed
    });
    assert_eq!(world.peers[leaf].sleep(5, world.now, 40_000).0, 0);
    mesh::deliver_each(&mut world, leaf, 0, 10, b"after-sleep");
    assert!(
        world.now - wake_at <= 60_000,
        "10/10 within the wake recovery bound"
    );
}
