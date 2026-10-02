//! M01 End sessions on forced chains, through the real Owners and MeshNodes.

use super::mesh::deliver_each;
use super::*;

fn chain(hops: usize, devram: bool) {
    let profile = if devram { "devram" } else { "member" };
    let tag = format!("end-{profile}-{hops}hop");
    let args: &[&str] = if devram { &["--devram"] } else { &[] };
    let Some(mut world) =
        MeshWorld::start_with_args(&tag, Switch::new(&Topology::line(hops + 1)), args, args)
    else {
        return;
    };
    let started = world.now;
    for gated in 2..=hops {
        world.gate[gated] = true;
    }
    for ready in 2..=hops + 1 {
        let released = world.now;
        let converged = |snaps: &[MeshSnap]| {
            snaps[..ready].iter().all(|snap| {
                if devram {
                    snap.mode == 3 && snap.link_sessions > 0
                } else {
                    snap.mode == MODE_MEMBER && snap.authority_ready && snap.join_confirmed
                }
            })
        };
        world.pump_until(2_400, converged);
        assert!(
            converged(&world.snaps),
            "{tag}: ready {ready}: {:?}",
            world.snaps
        );
        eprintln!(
            "{tag}: node {} ready in {} ms vt",
            ready - 1,
            world.now - released
        );
        if ready <= hops {
            world.gate[ready] = false;
        }
    }
    // DevRam opens End sessions on demand; Member's authority lane opens
    // them during convergence. Both must carry an application send.
    deliver_each(&mut world, hops, 0, 1, b"end-ready");
    assert!(world.snaps[hops].end_sessions > 0 && world.snaps[0].end_sessions > 0);
    let established_ms = world.now - started - 5_000;
    assert!(established_ms <= 60_000, "{tag}: End usable within 60 s");
    eprintln!("{tag}: End usable after {established_ms} ms vt");
    let before = world.switch.leg_delivered.clone();
    let count = if hops == 3 { 50 } else { 20 };
    // Fifty each way proves 100 deliveries without exhausting terminal pins.
    deliver_each(&mut world, hops, 0, count, b"up");
    deliver_each(&mut world, 0, hops, count, b"down");
    for (a, row) in before.iter().enumerate() {
        for (b, prior) in row.iter().enumerate() {
            let crossed = world.switch.leg_delivered[a][b];
            if a.abs_diff(b) == 1 {
                assert!(crossed > *prior, "{tag}: leg {a}->{b} carried traffic");
            } else {
                assert_eq!(crossed, 0, "{tag}: no shortcut {a}->{b}");
            }
        }
    }
}

#[test]
fn mesh_end_member_2_hops_deliver() {
    chain(2, false);
}

#[test]
fn mesh_end_member_3_hops_deliver() {
    chain(3, false);
}

#[test]
fn mesh_end_member_4_hops_deliver() {
    chain(4, false);
}

#[test]
fn mesh_end_devram_2_hops_deliver() {
    chain(2, true);
}

#[test]
fn mesh_end_devram_3_hops_deliver() {
    chain(3, true);
}

#[test]
fn mesh_end_devram_4_hops_deliver() {
    chain(4, true);
}
