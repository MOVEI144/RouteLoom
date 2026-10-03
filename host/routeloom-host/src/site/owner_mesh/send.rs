//! Legacy send path rows (tests/e2e/scenarios.json M11, M12): every
//! accepted host send reaches a terminal outcome by its deadline, and one
//! gateway boot keeps accepting sends past its idempotency record bound
//! without executing any key twice.

use super::*;
use routeloom_protocol::manifest as reasons;

// C++ `DeliveryState` terminal range (types.hpp): Delivered..Indeterminate.
const TERMINAL_STATES: std::ops::RangeInclusive<u8> = 7..=11;
// Device default send lifetime (SendOptions::lifetime_ms) plus the grace
// for the last USB hop and one harness step.
const DEADLINE_MS: u64 = 5_000;
const GRACE_MS: u64 = 1_000;

pub(super) fn legacy_send(world: &mut MeshWorld, key: u64, destination: u64, tag: &[u8]) -> u64 {
    let mut body = key.to_be_bytes().to_vec();
    body.extend_from_slice(&destination.to_be_bytes());
    body.extend_from_slice(tag);
    world.usb_host.queue_data(FrameKind::DataToMesh, body)
}

/// Terminal outcomes the host saw for `request`: a terminal
/// DeliveryEvent or an Error, as (state or `None`, reason).
fn terminals(world: &MeshWorld, request: u64) -> Vec<(Option<u8>, u16)> {
    terminal_events(world, request)
        .map(|(state, reason, _)| (state, reason))
        .collect()
}

pub(super) fn terminal_events(
    world: &MeshWorld,
    request: u64,
) -> impl Iterator<Item = (Option<u8>, u16, u64)> + '_ {
    world
        .usb_host
        .outcomes
        .iter()
        .filter(move |(r, state, _, _)| {
            *r == request && state.map_or(true, |s| TERMINAL_STATES.contains(&s))
        })
        .map(|(_, state, reason, at)| (*state, *reason, *at))
}

fn sent_world(tag: &str, gateway_args: &[&str]) -> Option<MeshWorld> {
    let mut world = MeshWorld::start_booted(
        tag,
        Switch::direct(),
        &staggered_boot(3),
        false,
        &[],
        &[gateway_args, &[]],
    )?;
    converge(&mut world, tag);
    // Settle the end-to-end session with one delivered send first, so the
    // bursts below measure the send path rather than session setup.
    let rx = world.snaps[1].rx_count;
    let warm = legacy_send(&mut world, 1, NODE_A, b"warm");
    world.pump_until(1_200, |snaps| snaps[1].rx_count > rx);
    world.pump_until(400, |_| false);
    assert!(
        terminals(&world, warm)
            .iter()
            .any(|(state, _)| *state == Some(DELIVERY_DELIVERED)),
        "warm-up send delivered: {:?}",
        world.usb_host.outcomes
    );
    Some(world)
}

/// M11: back-to-back sends (0 ms and 50 ms apart, 50 and 20 of them)
/// each reach exactly one terminal outcome within the device deadline
/// plus grace; none is left queued, waiting for the MAC or sent. Sends the
/// mesh TX queue cannot take are refused explicitly.
#[test]
fn mesh_send_burst_every_accepted_send_terminates() {
    let Some(mut world) = sent_world("m11", &[]) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    let mut key = 0x5100_u64;
    for (count, gap_steps) in [(50_u64, 0_u32), (20, 2)] {
        let mut sends = Vec::new();
        for index in 0..count {
            key += 1;
            let request = legacy_send(&mut world, key, NODE_A, &index.to_be_bytes());
            sends.push((request, world.now));
            world.pump_until(gap_steps, |_| false);
        }
        world.pump_until(((DEADLINE_MS + GRACE_MS) / 25) as u32, |_| false);
        let mut delivered = 0;
        let mut refused = 0;
        for (request, queued_at) in &sends {
            let ends: Vec<_> = terminal_events(&world, *request).collect();
            assert_eq!(
                ends.len(),
                1,
                "{count} sends, {} ms apart: request {request} ends exactly once: {ends:?}",
                gap_steps * 25
            );
            let (state, _, at) = ends[0];
            assert!(
                at - queued_at <= DEADLINE_MS + GRACE_MS,
                "request {request} terminal after {} ms",
                at - queued_at
            );
            match state {
                Some(DELIVERY_DELIVERED) => delivered += 1,
                None => refused += 1,
                _ => {}
            }
        }
        eprintln!(
            "m11: {count} sends {} ms apart: {delivered} delivered, {refused} refused",
            gap_steps * 25
        );
    }
}

/// M12: one gateway boot accepts 1,000+ sends (far past its idempotency
/// record bound), each terminal. A resubmitted key replays its stored
/// result while the record is retained and answers RESULT_EXPIRED once
/// reclaimed; no key reaches a destination twice.
#[test]
fn mesh_send_thousand_per_boot_without_duplicates() {
    let Some(mut world) = sent_world("m12", &[]) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    let reboots = world.peers[0].reboots;
    let rx = |world: &MeshWorld| world.snaps[1].rx_count + world.snaps[2].rx_count;
    let rx_start = rx(&world);
    let base = 0x5200_0000_u64;
    let total = 1_100_u64;
    // Alternate A and B every 300 ms: each receiver stays inside its
    // exactly-once pin budget (84 terminal pins per ~35 s on the relay
    // profile), so the row measures the gateway's record reclamation.
    const GAP_STEPS: u32 = 12;
    let mut requests = Vec::new();
    for index in 0..total {
        let destination = if index % 2 == 0 { NODE_A } else { NODE_B };
        requests.push(legacy_send(&mut world, base + index, destination, b"m12"));
        world.pump_until(GAP_STEPS, |_| false);
    }
    world.pump_until(((DEADLINE_MS + GRACE_MS) / 25) as u32, |_| false);
    assert_eq!(world.peers[0].reboots, reboots, "one gateway boot");
    let mut delivered = 0_u32;
    let mut histogram = std::collections::BTreeMap::new();
    for request in &requests {
        let ends = terminals(&world, *request);
        assert_eq!(
            ends.len(),
            1,
            "request {request} ends exactly once: {ends:?}"
        );
        if ends[0].0 == Some(DELIVERY_DELIVERED) {
            delivered += 1;
        }
        *histogram.entry(ends[0]).or_insert(0_u32) += 1;
    }
    eprintln!("m12: {delivered}/{total} delivered; outcomes {histogram:?}");
    assert!(
        !histogram.contains_key(&(None, reasons::REASON_IDEMPOTENCY_FULL)),
        "no IDEMPOTENCY_FULL while terminal records are reclaimable"
    );
    assert_eq!(
        u64::from(delivered),
        total,
        "every send accepted and delivered"
    );

    // A recent key replays its stored result; the first key's record was
    // reclaimed long ago, so its resubmission is RESULT_EXPIRED. Neither
    // executes again.
    let rx_before = rx(&world);
    let recent = legacy_send(&mut world, base + total - 1, NODE_B, b"m12");
    let oldest = legacy_send(&mut world, base, NODE_A, b"m12");
    world.pump_until(200, |_| false);
    assert_eq!(
        terminals(&world, recent),
        vec![(Some(DELIVERY_DELIVERED), reasons::REASON_IDEMPOTENT_REPLAY)],
        "retained key replays its terminal result"
    );
    assert_eq!(
        terminals(&world, oldest),
        vec![(None, reasons::REASON_RESULT_EXPIRED)],
        "reclaimed key is RESULT_EXPIRED"
    );
    assert_eq!(rx(&world), rx_before, "no resubmission executed");
    assert_eq!(
        rx(&world) - rx_start,
        delivered,
        "each delivered key reached its destination exactly once"
    );
}

/// A retry before mesh completion must not steal the original request's
/// terminal notification. Both requests describe one mesh delivery.
#[test]
fn mesh_send_inflight_replay_terminates_both_requests() {
    let Some(mut world) = sent_world("m11-replay", &[]) else {
        return;
    };
    let rx = world.snaps[1].rx_count;
    let first = legacy_send(&mut world, 0x5300, NODE_A, b"retry");
    let retry = legacy_send(&mut world, 0x5300, NODE_A, b"retry");
    world.pump_until(((DEADLINE_MS + GRACE_MS) / 25) as u32, |_| false);
    for request in [first, retry] {
        let ends = terminals(&world, request);
        assert_eq!(ends.len(), 1, "request {request}: {ends:?}");
        assert_eq!(ends[0].0, Some(DELIVERY_DELIVERED));
    }
    assert_eq!(world.snaps[1].rx_count - rx, 1, "one logical delivery");
}

/// M06 (gateway, HIL shape): the gateway resets ten times while the host
/// keeps its daemon; after each re-authentication ten sends 2 s apart go
/// to A. Every send ends terminal, delivery resumes within 15 s (vt) of
/// each reset and at least 95 of 100 are delivered.
#[test]
fn mesh_m06_gateway_reset_cycles_deliver() {
    gateway_reset_cycles(10);
}

#[test]
fn mesh_m06_gateway_reauth_first_send_delivers() {
    gateway_reset_cycles(1);
}

fn gateway_reset_cycles(cycles: u32) {
    let tag = if cycles == 1 {
        "m06-gw-startup"
    } else {
        "m06-gw-cycles"
    };
    let mut world = sent_world(tag, &["--crypto-ms", "154"])
        .expect("gateway reset acceptance requires live C++ peers");
    let mut key = 0x6600_u64;
    let mut delivered = 0;
    let mut per_cycle = Vec::new();
    let mut first_outcomes = Vec::new();
    for _ in 0..cycles {
        let sessions = world.usb_auth_total();
        world.peers[0].power_cut();
        let reset_at = world.now;
        reauth_within(&mut world, sessions, reset_at);
        let mut sends = Vec::new();
        for index in 0..10_u64 {
            key += 1;
            sends.push((
                legacy_send(&mut world, key, NODE_A, &index.to_be_bytes()),
                world.now,
            ));
            world.pump_until(80, |_| false);
        }
        world.pump_until(((DEADLINE_MS + GRACE_MS) / 25) as u32, |_| false);
        let first_outcome = terminals(&world, sends[0].0);
        assert_eq!(first_outcome.len(), 1, "first send ends exactly once");
        first_outcomes.push(first_outcome[0]);
        let mut got = 0;
        let mut first = None;
        for (request, submitted_at) in &sends {
            let outcome = terminals(&world, *request);
            assert_eq!(outcome.len(), 1, "send {request} ends exactly once");
            assert!(
                world
                    .usb_host
                    .outcomes
                    .iter()
                    .any(|(r, state, _, _)| r == request && state.is_some_and(|s| s < 7)),
                "send {request} admitted before its terminal outcome"
            );
            let terminal_at = terminal_events(&world, *request).next().unwrap().2;
            assert!(
                terminal_at - submitted_at <= DEADLINE_MS + 25,
                "send {request} finishes within its original lifetime and one poll"
            );
            if outcome.iter().any(|(s, _)| *s == Some(DELIVERY_DELIVERED)) {
                got += 1;
                if first.is_none() {
                    first = terminal_events(&world, *request)
                        .next()
                        .map(|(_, _, at)| at - reset_at);
                }
            }
        }
        per_cycle.push((got, first));
        delivered += got;
    }
    let total = cycles * 10;
    eprintln!(
        "M06: {delivered}/{total}, per cycle: {per_cycle:?}, first sends: {first_outcomes:?}"
    );
    assert!(
        delivered * 100 >= total * 95
            && per_cycle
                .iter()
                .all(|(_, first)| first.is_some_and(|t| t <= 15_000)),
        "delivered {delivered}/{total}, (per cycle, first delivery ms): {per_cycle:?}"
    );
    assert!(
        first_outcomes
            .iter()
            .all(|(state, _)| *state == Some(DELIVERY_DELIVERED)),
        "every first send immediately after reauth delivers: {first_outcomes:?}"
    );
}

fn reauth_within(world: &mut MeshWorld, before: usize, since: u64) {
    while world.usb_auth_total() <= before && world.now < since + 5_000 {
        world.step(25);
    }
    assert!(
        world.usb_auth_total() > before,
        "re-authenticated after the reset"
    );
}
