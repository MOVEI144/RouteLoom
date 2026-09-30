//! Device API rows (V2-14) over the real Owners and Site Authority: leave
//! and rejoin (J04), power cuts around the leave intent (F01-L), calls
//! from inside Device callbacks (F05-R), latest-value sends (M09-D),
//! deferred APPLIED tickets (P05-O) and the Device C API (P05-C) —
//! tests/e2e/scenarios.json.

use super::mesh::deliver_each;
use super::*;
use routeloom_protocol::manifest as reasons;

// C++ `MembershipStage` (device.hpp).
const STAGE_JOINING: u8 = 1;
const STAGE_MEMBER: u8 = 3;
// C++ `StatusCode` (status.hpp).
const STATUS_OK: u8 = 0;
const STATUS_INVALID_ARGUMENT: u8 = 1;
const STATUS_CONFLICT: u8 = 20;
// C++ `DeliveryState` (types.hpp).
const DELIVERY_CANCELLED_BEFORE_TX: u8 = 10;
const DELIVERY_INDETERMINATE: u8 = 11;

/// Steps (25 ms) until `done` or `budget_ms`; returns the elapsed ms.
fn until(world: &mut MeshWorld, budget_ms: u64, done: impl Fn(&MeshWorld) -> bool) -> u64 {
    let start = world.now;
    while world.now - start < budget_ms && !done(world) {
        world.step(25);
    }
    world.now - start
}

/// request_join on peer `a` until it is a confirmed member again
/// (≤ 60 s); returns the elapsed ms.
fn rejoin(world: &mut MeshWorld, a: usize) -> u64 {
    let (status, op) = world.peers[a]
        .device_op(false, world.now)
        .expect("request_join answered");
    assert!(
        status == STATUS_OK && op != 0,
        "request_join accepted: {status}"
    );
    let took = until(world, 60_000, |w| {
        let s = &w.snaps[a];
        s.stage == STAGE_MEMBER && s.join_confirmed && s.op_last == op
    });
    let s = &world.snaps[a];
    assert!(
        s.stage == STAGE_MEMBER && s.join_confirmed && s.op_result == reasons::REASON_JOINED,
        "rejoined within 60 s ({took} ms): {s:?}"
    );
    took
}

/// J04: A (behind B) leaves. Its two unroutable sends end CANCELLED_LEAVE,
/// it restarts unassigned within 5 s keeping its identity (no site, same
/// key), and each stage change is one event (Member→Leaving, Leaving→LEFT).
/// A request_join brings it back to the same site within 60 s with the
/// same generation and key (no holdoff after a leave), and it delivers
/// 20/20.
#[test]
fn mesh_j04_leave_and_rejoin() {
    let Some(mut world) = MeshWorld::start("j04", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "j04");
    let a = world.index_of(NODE_A);
    let row = world.member_row(NODE_A).expect("A row");
    let id_fp = world.snaps[a].id_fp;
    world.peers[a].app_send(NODE_GHOST, b"j04-unroutable-1");
    world.peers[a].app_send(NODE_GHOST, b"j04-unroutable-2");
    world.step(25);
    let events = world.snaps[a].membership_events;
    let reboots = world.peers[a].reboots;
    let (status, op) = world.peers[a]
        .device_op(true, world.now)
        .expect("leave answered");
    assert!(status == STATUS_OK && op != 0, "leave accepted: {status}");
    world.peers[a].app_send_with(NODE_GHOST, 0, 0, b"after-leave-intent");
    world.step(25);
    assert!(
        world.snaps[a]
            .app_tx
            .iter()
            .any(|tx| tx.reason == "NODE_PAUSED"),
        "no new send after durable leave intent: {:?}",
        world.snaps[a].app_tx
    );
    let cancelled = world.snaps[a]
        .app_tx
        .iter()
        .filter(|tx| tx.state == DELIVERY_CANCELLED_BEFORE_TX && tx.reason == "CANCELLED_LE")
        .count();
    assert_eq!(
        cancelled, 2,
        "untransmitted sends end CANCELLED_LEAVE: {:?}",
        world.snaps[a].app_tx
    );
    let took = until(&mut world, 5_000, |w| w.peers[a].reboots > reboots);
    assert!(
        world.peers[a].reboots > reboots,
        "left within 5 s ({took} ms)"
    );
    world.step(25);
    let s = &world.snaps[a];
    assert!(
        s.has_identity && !s.has_site && s.id_fp == id_fp && s.stage == STAGE_JOINING,
        "identity kept, membership gone: {s:?}"
    );
    assert_eq!(
        s.membership_events,
        events + 2,
        "Leaving and LEFT, once each"
    );
    assert_eq!(s.last_cause, reasons::REASON_LEFT);
    assert!(s.op_last == op && s.op_result == reasons::REASON_LEFT);

    let events = world.snaps[a].membership_events;
    rejoin(&mut world, a);
    assert_eq!(world.snaps[a].membership_events, events + 1, "JOINED once");
    let back = world.member_row(NODE_A).expect("A row");
    assert!(
        back.member && back.generation == row.generation && back.kid == row.kid,
        "same identity and generation after the leave"
    );
    deliver_each(&mut world, a, 0, 20, b"j04");
}

/// F01-L: power cuts around the leave intent (RLX1 slot x0, written
/// pending then sealed). Before it lands, and after only the pending write
/// landed, A stays a member and no leave is left behind. After the sealed
/// intent lands, the respawned A finishes the erasure on its own and
/// restarts unassigned; a cut mid-erasure resumes to the same end. The
/// identity survives every cut.
#[test]
fn mesh_f01_leave_intent_power_cuts() {
    let Some(mut world) = MeshWorld::start("f01-leave", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "f01 leave");
    let a = world.index_of(NODE_A);
    let id_fp = world.snaps[a].id_fp;
    let mut cuts = world.peers[a].switching_cuts;
    for mode in [1_u8, 2] {
        world.peers[a].arm_key_fault(mode, "x0");
        assert!(
            world.peers[a].device_op(true, world.now).is_none(),
            "mode {mode}: power lost inside leave"
        );
        cuts += 1;
        assert_eq!(world.peers[a].switching_cuts, cuts);
        world.pump_until(2_000, |snaps| {
            snaps[a].stage == STAGE_MEMBER && snaps[a].authority_ready
        });
        let s = &world.snaps[a];
        assert!(
            s.has_site && s.stage == STAGE_MEMBER && s.phase == PHASE_ACTIVE,
            "mode {mode}: no durable intent, still a member: {s:?}"
        );
    }

    // The sealed intent landed: the next boot finishes the leave.
    world.peers[a].arm_key_fault(3, "x0");
    assert!(
        world.peers[a].device_op(true, world.now).is_none(),
        "cut after the seal"
    );
    assert_eq!(world.peers[a].switching_cuts, cuts + 1);
    until(&mut world, 5_000, |w| {
        !w.snaps[a].has_site && w.snaps[a].stage == STAGE_JOINING
    });
    let s = &world.snaps[a];
    assert!(
        !s.has_site && s.has_identity && s.id_fp == id_fp && s.last_cause == reasons::REASON_LEFT,
        "the respawned A finished its leave: {s:?}"
    );

    // Cut mid-erasure: resumes to the same end.
    rejoin(&mut world, a);
    let reboots = world.peers[a].reboots;
    let (status, _) = world.peers[a]
        .device_op(true, world.now)
        .expect("leave answered");
    assert_eq!(status, STATUS_OK);
    world.step(25);
    world.peers[a].power_cut();
    until(&mut world, 5_000, |w| w.peers[a].reboots >= reboots + 2);
    world.step(25);
    let s = &world.snaps[a];
    assert!(
        !s.has_site && s.has_identity && s.id_fp == id_fp && s.last_cause == reasons::REASON_LEFT,
        "the leave resumed after the cut: {s:?}"
    );
    rejoin(&mut world, a);

    // A failed tombstone commit keeps the intent and closes the gate.
    world.peers[a].arm_key_fault(0, "s0");
    let (status, op) = world.peers[a]
        .device_op(true, world.now)
        .expect("leave accepted");
    assert_eq!(status, STATUS_OK);
    until(&mut world, 5_000, |w| w.snaps[a].op_last == op);
    assert_eq!(world.snaps[a].stage, 5, "failed erasure reports Recovery");
    assert_eq!(world.snaps[a].op_result, reasons::REASON_RECOVERY_REQUIRED);
    let events = world.snaps[a].membership_events;
    until(&mut world, 1_000, |_| false);
    assert_eq!(
        world.snaps[a].membership_events, events,
        "Recovery event once"
    );
    world.peers[a].power_cut();
    until(&mut world, 5_000, |w| {
        !w.snaps[a].has_site && w.snaps[a].stage == STAGE_JOINING
    });
    assert!(
        !world.snaps[a].has_site && world.snaps[a].id_fp == id_fp,
        "reboot resumes the durable leave intent"
    );
}

/// F05-R: a send and a leave made from inside Device callbacks (a received
/// message, a membership event) answer Busy every time and change nothing.
/// A re-verification (request_join on a member) reports Member→Joining→
/// Member as two events and one JOINED result; the authority channel and
/// the end-to-end session to G come back after it.
#[test]
fn mesh_f05_device_callback_reentry_is_busy() {
    let Some(mut world) = MeshWorld::start("f05-reentry", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "f05 reentry");
    let a = world.index_of(NODE_A);
    world.peers[a].probe_reentry(true);
    deliver_each(&mut world, 0, a, 2, b"f05");
    let events = world.snaps[a].membership_events;
    let (status, op) = world.peers[a]
        .device_op(false, world.now)
        .expect("request_join answered");
    assert!(
        status == STATUS_OK && op != 0,
        "request_join accepted: {status}"
    );
    let took = until(&mut world, 60_000, |w| w.snaps[a].op_last == op);
    let s = &world.snaps[a];
    assert!(
        s.stage == STAGE_MEMBER && s.op_result == reasons::REASON_JOINED,
        "re-verified within 60 s ({took} ms): {s:?}"
    );
    assert_eq!(
        s.membership_events,
        events + 2,
        "Joining and Member, once each"
    );
    assert!(s.reentry_calls >= 6, "callbacks tried: {}", s.reentry_calls);
    assert_eq!(
        s.reentry_busy, s.reentry_calls,
        "every call from a callback is Busy"
    );
    world.peers[a].probe_reentry(false);
    until(&mut world, 120_000, |w| {
        w.snaps[a].authority_ready && w.snaps[a].join_confirmed
    });
    assert!(
        world.snaps[a].join_confirmed,
        "authority back after the re-verification"
    );
    deliver_each(&mut world, a, 0, 2, b"f05-after");
}

/// M09-D: ten BEST_EFFORT values with one coalesce key sent before A's
/// next Owner pass leave only the latest; the nine replaced ones end
/// CANCELLED_SUPERSEDED. Another key and another destination are kept, and
/// RELIABLE with a key is refused; G receives exactly the latest value of
/// each key. During a 10 s outage a value already handed to the radio is
/// never reported cancelled by a newer one, and the newest arrives after
/// the heal.
#[test]
fn mesh_m09_device_latest_value_sends() {
    let Some(mut world) = MeshWorld::start("m09-device", Switch::forced_multihop()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge_gated(&mut world, 1, "m09");
    let (a, b) = (world.index_of(NODE_A), world.index_of(NODE_B));
    deliver_each(&mut world, a, 0, 1, b"m09-warm");
    deliver_each(&mut world, a, b, 1, b"m09-warm-b");
    let (g_rx, b_rx) = (world.snaps[0].rx_count, world.snaps[b].rx_count);
    for value in 0..10_u8 {
        world.peers[a].app_send_with(testkit::GATEWAY, 0, 1, &[b'v', value]);
    }
    world.peers[a].app_send_with(testkit::GATEWAY, 0, 2, b"k2");
    world.peers[a].app_send_with(NODE_B, 0, 1, b"to-b");
    world.peers[a].app_send_with(testkit::GATEWAY, 1, 1, b"reliable");
    world.step(25);
    let tx = world.snaps[a].app_tx.clone();
    let superseded = tx.iter().filter(|t| t.reason == "CANCELLED_SU").count();
    assert_eq!(superseded, 9, "nine replaced values: {tx:?}");
    assert!(
        tx.iter().any(|t| t.reason.starts_with("COALESCE_REQ")),
        "RELIABLE with a key refused: {tx:?}"
    );
    until(&mut world, 5_000, |w| {
        w.snaps[0].rx_count >= g_rx + 2 && w.snaps[b].rx_count > b_rx
    });
    until(&mut world, 1_000, |_| false);
    assert_eq!(
        world.snaps[0].rx_count,
        g_rx + 2,
        "G got the latest of key 1 and key 2 only"
    );
    assert_eq!(
        world.snaps[b].rx_count,
        b_rx + 1,
        "the other destination kept its value"
    );

    // 10 s outage: the first value reaches the radio and fails there; the
    // newer ones never report it cancelled (later ones may wait for a
    // route, untransmitted, and be replaced).
    let before = world.snaps[a]
        .app_tx
        .iter()
        .map(|t| t.seq)
        .max()
        .unwrap_or(0);
    world.switch.isolate(a);
    for value in 0..5_u8 {
        world.peers[a].app_send_with(testkit::GATEWAY, 0, 1, &[b'o', value]);
        until(&mut world, 2_000, |_| false);
    }
    let first = world.snaps[a]
        .app_tx
        .iter()
        .find(|t| t.seq == before + 1)
        .cloned();
    assert!(
        first
            .as_ref()
            .is_some_and(|t| t.state == 8 && t.reason.starts_with("MAC_SEND")),
        "the value on the air failed, never cancelled: {:?}",
        world.snaps[a].app_tx
    );
    world.switch.heal(a);
    let g_rx = world.snaps[0].rx_count;
    world.peers[a].app_send_with(testkit::GATEWAY, 0, 1, b"after");
    until(&mut world, 30_000, |w| w.snaps[0].rx_count > g_rx);
    assert_eq!(
        world.snaps[0].rx, b"after",
        "the newest value arrives after the heal"
    );
}

/// P05-O: G's APPLIED request to A, whose endpoint defers and completes
/// 2 s later: no APPLIED before the completion, exactly one after it, 20
/// times. A completion after the request deadline is refused, and the
/// origin never reports it applied.
#[test]
fn mesh_p05_deferred_applied_ticket() {
    let Some(mut world) = MeshWorld::start("p05", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge(&mut world, "p05");
    let a = world.index_of(NODE_A);
    deliver_each(&mut world, 0, a, 1, b"p05-warm");
    world.peers[a].defer_applied(2_000);
    world.peers[a].probe_reentry(true);
    let lease = world.peers[a].applied_lease();
    for round in 0..20_u32 {
        let completed = world.snaps[a].applied_completed;
        let last = world.snaps[0]
            .app_tx
            .iter()
            .map(|t| t.seq)
            .max()
            .unwrap_or(0);
        world.peers[0].applied_send(NODE_A, &lease, &round.to_le_bytes());
        until(&mut world, 1_900, |_| false);
        assert!(
            world.snaps[a].reentry_calls >= 2,
            "APPLIED callback tried reentry"
        );
        assert_eq!(
            world.snaps[a].reentry_calls, world.snaps[a].reentry_busy,
            "APPLIED callback calls must be Busy"
        );
        let pending = world.snaps[0].app_tx.iter().find(|t| t.seq > last).cloned();
        assert!(
            pending
                .as_ref()
                .is_some_and(|t| t.state != DELIVERY_DELIVERED),
            "round {round}: not applied before the completion: {pending:?}"
        );
        until(&mut world, 3_000, |w| {
            w.snaps[0]
                .app_tx
                .iter()
                .any(|t| t.seq > last && t.state == DELIVERY_DELIVERED)
        });
        let done = world.snaps[0].app_tx.iter().find(|t| t.seq > last).cloned();
        assert!(
            done.as_ref().is_some_and(|t| t.state == DELIVERY_DELIVERED && t.reason == "APP_APPLIED"),
            "round {round}: applied once completed: {done:?} (A: {} requests, {} completed, {} refused)",
            world.snaps[a].applied_requests,
            world.snaps[a].applied_completed,
            world.snaps[a].applied_refused
        );
        assert_eq!(world.snaps[a].applied_completed, completed + 1);
    }
    // Completed after the 10 s request deadline: refused, never applied.
    world.peers[a].defer_applied(12_000);
    let last = world.snaps[0]
        .app_tx
        .iter()
        .map(|t| t.seq)
        .max()
        .unwrap_or(0);
    world.peers[0].applied_send(NODE_A, &lease, b"late");
    until(&mut world, 16_000, |_| false);
    assert_eq!(
        world.snaps[a].applied_refused, 1,
        "the late completion is refused"
    );
    let late = world.snaps[0].app_tx.iter().find(|t| t.seq > last).cloned();
    assert!(
        late.as_ref()
            .is_some_and(|t| t.state == DELIVERY_INDETERMINATE),
        "the origin never reports the late one applied: {late:?}"
    );
}

/// P05-C: the Device C API from C (owner_mesh_c_app.c on A and B). Short
/// and unknown-version structs are refused. A sends 20/20 to G with
/// rl_dev_send and receives in on_message. B's APPLIED request to A, which
/// A completes from C 2 s later, applies once only after the completion, 20
/// times; calls from the APPLIED callback are Busy; a completion after the
/// deadline is refused. rl_dev_leave restarts A unassigned (LEFT),
/// rl_dev_request_join brings it back (JOINED), and a job posted from the
/// membership callback runs on a later Owner pass.
#[test]
fn mesh_p05_c_device_api() {
    let Some(mut world) = MeshWorld::start_with_args("p05-c", Switch::direct(), &[], &["--c-app"])
    else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge(&mut world, "p05-c");
    let (a, b) = (world.index_of(NODE_A), world.index_of(NODE_B));
    for i in [a, b] {
        let s = &world.snaps[i];
        assert!(
            s.c_checks >= 15 && s.c_check_failures == 0,
            "C boundary checks on {i}: {} of {} failed",
            s.c_check_failures,
            s.c_checks
        );
    }
    deliver_each(&mut world, a, 0, 20, b"p05-c");
    let messages = world.snaps[a].c_messages;
    deliver_each(&mut world, 0, a, 1, b"p05-c-down");
    assert_eq!(world.snaps[a].c_messages, messages + 1, "C on_message");

    world.peers[a].defer_applied(2_000);
    let lease = world.peers[a].applied_lease();
    for round in 0..20_u32 {
        let completed = world.snaps[a].applied_completed;
        let last = world.snaps[b]
            .app_tx
            .iter()
            .map(|t| t.seq)
            .max()
            .unwrap_or(0);
        world.peers[b].applied_send(NODE_A, &lease, &round.to_le_bytes());
        until(&mut world, 1_900, |_| false);
        let pending = world.snaps[b].app_tx.iter().find(|t| t.seq > last).cloned();
        assert!(
            pending
                .as_ref()
                .is_some_and(|t| t.state != DELIVERY_DELIVERED),
            "round {round}: not applied before the completion: {pending:?}"
        );
        until(&mut world, 3_000, |w| {
            w.snaps[b]
                .app_tx
                .iter()
                .any(|t| t.seq > last && t.state == DELIVERY_DELIVERED)
        });
        let done = world.snaps[b].app_tx.iter().find(|t| t.seq > last).cloned();
        assert!(
            done.as_ref()
                .is_some_and(|t| t.state == DELIVERY_DELIVERED && t.reason == "APP_APPLIED"),
            "round {round}: applied once completed: {done:?}"
        );
        assert_eq!(world.snaps[a].applied_completed, completed + 1);
    }
    let s = &world.snaps[a];
    assert_eq!(s.c_check_failures, 0, "C ticket and capacity checks");
    assert_eq!(
        world.snaps[b].c_check_failures, 0,
        "C delivery/result checks"
    );
    assert!(
        s.reentry_calls >= 40 && s.reentry_calls == s.reentry_busy,
        "calls from the C APPLIED callback are Busy: {} of {}",
        s.reentry_busy,
        s.reentry_calls
    );
    world.peers[a].defer_applied(12_000);
    let last = world.snaps[b]
        .app_tx
        .iter()
        .map(|t| t.seq)
        .max()
        .unwrap_or(0);
    world.peers[b].applied_send(NODE_A, &lease, b"late");
    until(&mut world, 16_000, |_| false);
    assert_eq!(
        world.snaps[a].applied_refused, 1,
        "the late completion is refused"
    );
    let late = world.snaps[b].app_tx.iter().find(|t| t.seq > last).cloned();
    assert!(
        late.as_ref()
            .is_some_and(|t| t.state == DELIVERY_INDETERMINATE),
        "the origin never reports the late one applied: {late:?}"
    );

    let reboots = world.peers[a].reboots;
    let (status, op) = world.peers[a]
        .device_op(true, world.now)
        .expect("rl_dev_leave answered");
    assert!(
        status == STATUS_OK && op != 0,
        "rl_dev_leave accepted: {status}"
    );
    until(&mut world, 5_000, |w| w.peers[a].reboots > reboots);
    world.step(25);
    let s = &world.snaps[a];
    assert!(
        world.peers[a].reboots > reboots && !s.has_site && s.stage == STAGE_JOINING,
        "left and restarted unassigned: {s:?}"
    );
    assert!(s.op_last == op && s.op_result == reasons::REASON_LEFT);
    rejoin(&mut world, a);
    until(&mut world, 100, |_| false);
    assert!(
        world.snaps[a].c_posted_runs >= 1,
        "the job posted from on_membership ran"
    );
    deliver_each(&mut world, a, 0, 5, b"p05-c-back");
}

/// P06: the standalone example serves two C endpoints after the host is
/// disconnected. Each endpoint receives the example's "ok" response to
/// every message through its C observer, without an authority connection.
#[test]
fn mesh_p06_standalone_c_endpoints() {
    let Some(mut world) = MeshWorld::start_with_args(
        "p06-standalone",
        Switch::direct(),
        &["--standalone"],
        &["--c-app"],
    ) else {
        return;
    };
    converge(&mut world, "p06-standalone");
    world.usb_disconnect();
    for node in [NODE_A, NODE_B] {
        let index = world.index_of(node);
        for round in 0..10_u8 {
            let before = world.snaps[index].c_messages;
            deliver_each(&mut world, index, 0, 1, &[round]);
            until(&mut world, 3_000, |w| w.snaps[index].c_messages > before);
            let snap = &world.snaps[index];
            assert_eq!(snap.c_messages, before + 1, "one C response per request");
            assert_eq!(snap.rx_src, testkit::GATEWAY);
            assert_eq!(snap.rx, b"ok");
            assert_eq!(snap.c_check_failures, 0);
        }
    }
}

/// JoinPolicy (J06-P): range and compare-and-set on A, the stored revision
/// survives a power cut, and the shorter removal holdoff applies to A's
/// next removal: A restarts unassigned after 60 s, not 10 min.
#[test]
fn mesh_join_policy_range_cas_and_holdoff() {
    let Some(mut world) = MeshWorld::start("join-policy", Switch::direct()) else {
        return; // no C++ peers: skip (ignore-equivalent)
    };
    converge(&mut world, "join policy");
    let a = world.index_of(NODE_A);
    assert_eq!(
        world.peers[a].set_join_policy(59, 0).0,
        STATUS_INVALID_ARGUMENT
    );
    assert_eq!(world.peers[a].set_join_policy(60, 1).0, STATUS_CONFLICT);
    assert_eq!(world.peers[a].set_join_policy(60, 0), (STATUS_OK, 1));
    assert_eq!(world.peers[a].set_join_policy(60, 0).0, STATUS_CONFLICT);
    world.peers[a].power_cut();
    world.pump_until(2_000, |snaps| {
        snaps[a].stage == STAGE_MEMBER && snaps[a].authority_ready
    });
    assert_eq!(
        world.snaps[a].policy_revision, 1,
        "the policy survives the power cut"
    );

    world
        .provision
        .site
        .link
        .revoke(
            NODE_A,
            1,
            routeloom_client::site::RemovalReason::Removed,
            "policy-holdoff",
        )
        .expect("revoke commits");
    world.pump_until(24_000, |snaps| snaps[a].phase == PHASE_HOLDOFF);
    assert_eq!(
        world.snaps[a].phase, PHASE_HOLDOFF,
        "A erased: {:?}",
        world.snaps[a]
    );
    let reboots = world.peers[a].reboots;
    let held = until(&mut world, 120_000, |w| w.peers[a].reboots > reboots);
    assert!(
        world.peers[a].reboots > reboots && (59_000..=61_000).contains(&held),
        "restarted after the 60 s holdoff ({held} ms)"
    );
}

/// M04: G stops while A and B keep exchanging authenticated route updates.
/// B's lease refreshes cannot stand in for communication with G.
#[test]
fn mesh_m04_gateway_stop_does_not_refresh_evidence() {
    let Some(mut world) = MeshWorld::start("m04-gateway", Switch::forced_multihop()) else {
        return;
    };
    converge_gated(&mut world, 1, "m04 gateway");
    let a = world.index_of(NODE_A);
    deliver_each(&mut world, a, 0, 1, b"m04-before-stop");
    assert_eq!(world.snaps[a].connectivity, 1);
    let events = world.snaps[a].connectivity_events;
    world.switch.isolate(0);
    until(&mut world, 120_025, |_| false);
    assert_eq!(
        world.snaps[a].connectivity, 3,
        "Isolated at T_iso despite relay refreshes"
    );
    assert_eq!(
        world.snaps[a].connectivity_events,
        events + 2,
        "Degraded and Isolated once"
    );
    assert!(world.snaps[a].has_site, "isolation keeps membership");
    world.switch.heal(0);
    until(&mut world, 60_000, |w| w.snaps[a].join_confirmed);
    deliver_each(&mut world, 0, a, 1, b"m04-gateway-back");
    assert_eq!(
        world.snaps[a].connectivity, 1,
        "Reachable after verified communication"
    );
}
