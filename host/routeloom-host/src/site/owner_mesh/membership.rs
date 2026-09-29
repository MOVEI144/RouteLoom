//! Membership policy rows over the real Owners and Site Authority: the
//! ProxyPolicySet distribution (J06, #176) and the NodeId readmit (J05,
//! #146) — tests/e2e/scenarios.json.

use super::cutover::decider_requests_for;
use super::mesh::deliver_each;
use super::*;
use crate::site::PolicyPatch;
use routeloom_client::site::{RemovalReason, SiteAdmin};

/// `join.policy.set {zero_touch_open}` on the live authority; returns the
/// minted policy generation.
fn set_zero_touch_open(world: &MeshWorld, open: bool) -> u32 {
    world
        .provision
        .site
        .service
        .with(|a| {
            a.update_policy(&PolicyPatch {
                zero_touch_open: Some(open),
                ..PolicyPatch::default()
            })
            .map(|_| a.policy().policy_generation)
        })
        .0
        .expect("policy commits")
}

fn radio(world: &MeshWorld) -> crate::site::proxy_policy::PolicyDistribution {
    world
        .provision
        .site
        .service
        .with(|a| a.policy_distribution())
        .0
}

/// Steps until every proxy (the gateway and relay B) acknowledged the
/// current generation; returns the virtual time it took.
fn until_applied(world: &mut MeshWorld, budget_ms: u64) -> u64 {
    let start = world.now;
    while world.now - start < budget_ms {
        let r = radio(world);
        if r.proxies > 0 && r.applied == r.proxies {
            break;
        }
        world.step(25);
    }
    world.now - start
}

/// J06: `join.policy.set` closes the site. The ProxyPolicySet reaches both
/// proxies (gateway G, relay B) as durable ACKs within 30 s (vt); while
/// closed, identity-only A behind B sends ≥ 10 DISCOVERs and gets no
/// OFFER and raises no join request. B cut off while the policy reopens
/// receives the newer generation when it returns (never an older one),
/// and A then joins through B's proxy.
#[test]
fn mesh_j06_closed_policy_stops_offers_until_reopened() {
    let Some(mut world) = MeshWorld::start_identity_only("j06", Switch::forced_multihop(), &[1])
    else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    world.provision.site.decider.pending_retry_s = 5;
    world.gate[1] = true;
    world.pump_until(9000, |snaps| {
        snaps[0].authority_ready && snaps[2].authority_ready && snaps[2].join_confirmed
    });
    assert!(world.snaps[2].join_confirmed, "relay B converged");

    let closed = set_zero_touch_open(&world, false);
    let took = until_applied(&mut world, 30_000);
    let r = radio(&world);
    assert!(
        r.proxies == 2 && r.applied == 2 && r.distributed == Some(closed),
        "both proxies applied generation {closed} within 30 s (took {took} ms): {r:?}"
    );

    // A powers on while the site is closed.
    world.gate[1] = false;
    let discovers = world.snaps[2].proxy_disc_rx;
    let offers = world.snaps[2].proxy_offers_tx;
    // The joiner backs its rescans off: ten DISCOVERs span ~18 min (vt).
    // No OFFER can open a window, so coarse steps suffice.
    let until = world.now + 1_800_000;
    while world.snaps[2].proxy_disc_rx < discovers + 10 && world.now < until {
        world.step(100);
    }
    assert!(
        world.snaps[2].proxy_disc_rx >= discovers + 10,
        "A kept discovering: {} DISCOVERs",
        world.snaps[2].proxy_disc_rx - discovers
    );
    assert_eq!(
        world.snaps[2].proxy_offers_tx, offers,
        "no OFFER while closed"
    );
    assert_eq!(decider_requests_for(&world, NODE_A), 0, "no join request");
    assert_ne!(world.snaps[1].mode, MODE_MEMBER);

    // B is off the air while the site reopens: G applies, B does not.
    world.switch.isolate(2);
    let reopened = set_zero_touch_open(&world, true);
    assert!(reopened > closed, "generations only grow");
    world.pump_until(800, |_| false);
    let r = radio(&world);
    assert!(r.applied == 1 && r.applied < r.proxies, "B behind: {r:?}");
    world.switch.heal(2);
    let took = until_applied(&mut world, 60_000);
    let r = radio(&world);
    assert!(
        r.applied == 2 && r.distributed == Some(reopened),
        "returning B received generation {reopened} ({took} ms): {r:?}"
    );

    world
        .provision
        .site
        .decider
        .assign(NODE_A, Assignment::Here(Role::Relay));
    // A power-cycles instead of waiting out its rescan backoff.
    world.peers[1].power_cut();
    world.pump_until(4_000, |snaps| {
        snaps[1].mode == MODE_MEMBER && snaps[1].authority_ready && snaps[1].join_confirmed
    });
    assert!(
        world.snaps[1].join_confirmed,
        "A joined once reopened: {:?}",
        world.snaps[1]
    );
    assert!(world.snaps[2].proxy_offers_tx > offers, "B offered to A");
    assert!(
        world.snaps[2].proxy_relays_completed > 0,
        "B relayed A's join"
    );
}

/// J05 (b): B is revoked at generation 1, erases, waits out its holdoff
/// and rejoins with the same NodeId. The site readmits it at generation 2
/// (no reprovisioning) and marks B's RRS1 entry with the active GK E, which
/// the revocation's own rotation minted without B; B joins holding E.
/// B's RLV1 does not block generation 2; once the survivors apply the set,
/// group delivery reaches both members under E and B's unicast delivers
/// 20/20.
#[test]
fn mesh_j05_revoked_node_returns_with_the_same_node_id() {
    let Some(mut world) = MeshWorld::start("j05", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    world.provision.site.decider.pending_retry_s = 5;
    converge(&mut world, "j05");
    let a_group = world.snaps[1].group_delivered;
    let b_group = world.snaps[2].group_delivered;
    world.peers[0].group_send(0xFFFF, b"j05-before");
    world.pump_until(800, |snaps| {
        snaps[1].group_delivered > a_group && snaps[2].group_delivered > b_group
    });
    assert!(
        world.snaps[2].group_delivered > b_group,
        "B hears the group before"
    );

    let row = world.member_row(NODE_B).expect("B row");
    assert_eq!(row.generation, 1);
    let gk_before = world.active_gk();
    world
        .provision
        .site
        .link
        .revoke(NODE_B, 1, RemovalReason::Removed, "j05-revoke")
        .expect("revoke commits");
    world.pump_until(24_000, |snaps| snaps[2].phase == PHASE_HOLDOFF);
    assert_eq!(
        world.snaps[2].phase, PHASE_HOLDOFF,
        "B erased: {:?}",
        world.snaps[2]
    );
    assert!(!world.snaps[2].has_site && world.snaps[2].has_identity);

    // The same NodeId is expected back; nothing is reprovisioned.
    world
        .provision
        .site
        .decider
        .assign(NODE_B, Assignment::Here(Role::Relay));
    let reboots = world.peers[2].reboots;
    // The 10-minute holdoff runs on B's monotonic clock; quiet steps.
    let until = world.now + 700_000;
    while world.peers[2].reboots == reboots && world.now < until {
        world.step(250);
    }
    assert!(
        world.peers[2].reboots > reboots,
        "B restarted unassigned after its holdoff"
    );
    world.pump_until(6000, |snaps| {
        snaps[2].mode == MODE_MEMBER && snaps[2].authority_ready && snaps[2].join_confirmed
    });
    let b = &world.snaps[2];
    assert!(
        b.join_confirmed && b.site_generation == 2,
        "B back at generation 2: {b:?}"
    );
    let kid = row.kid;
    let row = world.member_row(NODE_B).expect("B row");
    assert!(
        row.member && row.generation == 2 && row.kid == kid,
        "same identity, generation 2"
    );
    let (readmit, active, rs_epoch) = world
        .provision
        .site
        .service
        .with(|a| {
            (
                a.rrs_entries
                    .iter()
                    .find(|e| e.node_id == NODE_B)
                    .map(|e| e.readmit_gk_epoch),
                a.gks.active_epoch(),
                a.rs_epoch,
            )
        })
        .0;
    assert!(
        readmit == Some(active) && active > gk_before,
        "RRS1 readmits B from GK {active}"
    );
    assert!(
        world.snaps.iter().all(|s| s.gk_current == active),
        "B joined with the readmit GK: {:?}",
        world.snaps.iter().map(|s| s.gk_current).collect::<Vec<_>>()
    );
    // The survivors apply the readmit set, then group delivery reaches
    // both members under GK `active`.
    world.pump_until(4000, |snaps| {
        snaps[0].applied_rs >= rs_epoch && snaps[1].applied_rs >= rs_epoch
    });
    assert!(world.snaps[0].applied_rs >= rs_epoch && world.snaps[1].applied_rs >= rs_epoch);
    deliver_each(&mut world, 2, 0, 20, b"j05");
    // B re-enters the gateway tree with its next route update (a child
    // lease from poison reverse): a round sent before that misses it.
    let a_group = world.snaps[1].group_delivered;
    let b_group = world.snaps[2].group_delivered;
    for round in 0..6_u8 {
        world.peers[0].group_send(0xFFFF, &[b'j', b'0', b'5', round]);
        world.pump_until(400, |snaps| {
            snaps[1].group_delivered > a_group && snaps[2].group_delivered > b_group
        });
        if world.snaps[2].group_delivered > b_group {
            break;
        }
    }
    assert!(
        world.snaps[1].group_delivered > a_group && world.snaps[2].group_delivered > b_group,
        "group delivery reaches A and the readmitted B: {:?}",
        world
            .snaps
            .iter()
            .map(|s| (s.group_delivered, s.group_rejected))
            .collect::<Vec<_>>()
    );
    assert!(
        world.snaps.iter().all(|s| s.group_rejected == 0),
        "no group frame refused"
    );
}

/// F01/F02 at the proxy-policy record (RLPP1, #176): B's next policy write
/// fails once, then loses power before the write lands, then loses power
/// after its commit before the ACK. In every case B is never counted
/// applied for a generation it did not store, the generation B holds never
/// goes back, and once the fault is gone B applies the current generation
/// within 30 s (vt).
#[test]
fn mesh_f01_f02_policy_record_faults() {
    let Some(mut world) = MeshWorld::start("f02-policy", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "f02 policy");
    let cuts = world.peers[2].switching_cuts;
    for (mode, open) in [(0_u8, false), (1, true), (2, false)] {
        let hits = world.snaps[2].key_fault_hits;
        let before = radio(&world).distributed.unwrap_or(0);
        world.peers[2].arm_key_fault(mode, "p0");
        let generation = set_zero_touch_open(&world, open);
        world.pump_until(4000, |snaps| {
            snaps[2].key_fault_hits > hits || snaps[2].phase == 0
        });
        let fired = world.snaps[2].key_fault_hits > hits || world.peers[2].switching_cuts > cuts;
        assert!(fired, "mode {mode}: the armed fault fired");
        let r = radio(&world);
        if mode == 0 {
            assert!(
                r.applied < r.proxies,
                "a failed write is never counted applied: {r:?}"
            );
        }
        assert!(
            r.distributed.unwrap_or(0) >= before,
            "mode {mode}: the lowest applied generation never goes back: {r:?}"
        );
        let took = until_applied(&mut world, 30_000);
        let r = radio(&world);
        assert!(
            r.applied == r.proxies && r.distributed == Some(generation),
            "mode {mode}: B applied generation {generation} within 30 s ({took} ms): {r:?}"
        );
    }
    assert_eq!(
        world.peers[2].switching_cuts,
        cuts + 2,
        "both power cuts respawned B from its saved image"
    );
}
