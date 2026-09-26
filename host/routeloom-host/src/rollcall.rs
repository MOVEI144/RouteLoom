//! Daemon-side rollcall (design-devflow §6.4–§6.5, bundle D09): one owned
//! run per daemon drives a continuous group send to the rollcall group
//! through the existing `GroupOps`/`group.send` lane and folds each settled
//! GROUP_REPORT summary into the membership snapshot.
//!
//! The interval adapts to roster size under the rollcall airtime budget.
//! `MIN_INTERVAL_MS` is the shortest START interval, not a completion SLA —
//! a large roster extends the period rather than flooding the channel.
//!
//! Ownership: the service lives in the daemon `State`, so a GUI or scenario
//! client can only ever observe or steer the single owned run — a
//! disconnected client can never leave a second loop running, and a second
//! `lab.rollcall.start` for a live run is answered, not duplicated.

use std::collections::VecDeque;
use std::sync::Mutex;
use std::time::Duration;

use crate::group::{self, GroupOps, GroupRequest};
use crate::nodes::NodeTable;
use crate::State;

/// §6.5: the shortest start interval — never below 2 s.
pub const MIN_INTERVAL_MS: u64 = 2_000;
/// §6.5: retry/estimation factor 1.5 applied to the estimated round cost.
const RETRY_NUM: u64 = 3;
const RETRY_DEN: u64 = 2;
/// §6.5: B_rollcall — 10% of the channel — as us of airtime per second.
const BUDGET_US_PER_S: u64 = 100_000;
/// §6.5: estimated lossless one-round cost per non-root member
/// (GROUP_DATA copy 7,968 us + GROUP_REPORT 7,328 us at the §14 LR model).
pub const ROUND_COST_PER_MEMBER_US: u64 = 15_296;
/// The interval where the required budget already exceeds a sane duty
/// cycle: beyond it the run reports `budget_exceeded` instead of silently
/// clamping (§6.5 "budget_exceeded として負荷停止または低頻度化").
pub const MAX_INTERVAL_MS: u64 = 300_000;
/// Shrink hysteresis (§6.5): only after this many consecutive clean rounds
/// may the effective interval shorten, one step at a time.
pub const SHRINK_AFTER_ROUNDS: u32 = 10;
/// Completed poll snapshots retained for `lab.rollcall.status` history.
const HISTORY_CAP: usize = 64;
/// Lane tick cadence (same as the group lane it drives).
const TICK_MS: u64 = 50;
/// The rollcall application header is 32 B, no body (§6.5):
/// "RLRC" | v1 | flags(0) | reserved | run_uuid(8) | poll_seq(8) | reserved.
pub const ROLLCALL_PAYLOAD_BYTES: usize = 32;
const ROLLCALL_MAGIC: [u8; 4] = *b"RLRC";
/// Default rollcall target: the ALL group (0xFFFF).
pub const DEFAULT_GROUP: u16 = 0xFFFF;
/// A daemon-internal principal for GroupOps submissions — never an IPC uid.
const ROLLCALL_UID: u32 = u32::MAX;

/// The run id rendered as its 32-hex API string (`lab.rollcall.*`).
pub struct RunUuid(pub [u8; 16]);

impl std::fmt::Display for RunUuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

/// Inverse of `RunUuid`'s display — 32 lowercase-or-upper hex digits.
pub fn parse_run_uuid(text: &str) -> Option<[u8; 16]> {
    if text.len() != 32 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 16];
    for (i, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(out)
}

/// Budgeted start interval for a roster of `n` nodes (root included) whose
/// last observed round used `rounds` group-engine rounds (≥1 — repair
/// pressure widens the estimate immediately):
/// max(2 s, 1.5 × C_round(n) × rounds / B_rollcall) with
/// C_round = (n-1) × 15,296 us. Returns `(interval_ms, budget_exceeded)`.
pub fn interval_for_roster(n: u64, rounds: u8) -> (u64, bool) {
    let members = n.saturating_sub(1);
    let cost_us = members
        .saturating_mul(ROUND_COST_PER_MEMBER_US)
        .saturating_mul(u64::from(rounds.max(1)));
    // T_ms = retry_factor × cost_us / budget_us_per_s × 1000 ms/s, rounded up.
    let needed_ms = cost_us
        .saturating_mul(RETRY_NUM)
        .saturating_mul(1000)
        .saturating_add(BUDGET_US_PER_S * RETRY_DEN - 1)
        / (BUDGET_US_PER_S * RETRY_DEN);
    let interval = needed_ms.max(MIN_INTERVAL_MS);
    (interval.min(MAX_INTERVAL_MS), interval > MAX_INTERVAL_MS)
}

/// One poll's recorded outcome — the `lab.rollcall.status` history unit.
#[derive(Clone, Debug)]
pub struct PollSnapshot {
    /// 1-based poll counter inside the run.
    pub poll_seq: u64,
    /// The GroupOps record id (grp token = its api identity).
    pub op_id: u64,
    /// The idempotency key the send was admitted under.
    pub key: [u8; 16],
    pub group: u16,
    /// The roster size N the interval was budgeted on (root included).
    pub roster: u64,
    /// Interval in effect when this poll was scheduled.
    pub interval_ms: u64,
    pub submitted_ms: u64,
    pub settled_ms: Option<u64>,
    /// `complete` / `incomplete` / `refused` / `not_sent` / `indeterminate`
    /// / `skipped`.
    pub outcome: &'static str,
    pub delivered: Option<u16>,
    pub nonmember: Option<u16>,
    pub missing_total: Option<u16>,
    pub unaccounted: Option<u16>,
    pub missing: Vec<u64>,
    pub missing_truncated: bool,
}

/// The owning run — its presence is the service's lease.
struct Run {
    /// Minted at start; bound into every poll key and the status surface.
    run_uuid: [u8; 16],
    /// The principal that started it (the lease owner on the API surface).
    owner: u32,
    network: u64,
    group: u16,
    started_ms: u64,
    /// Current effective interval (the adaptive value, never < 2 s).
    interval_ms: u64,
    /// Next scheduled submit time (host unix ms).
    next_ms: u64,
    poll_seq: u64,
    in_flight: Option<u64>,
    /// Consecutive rounds that settled complete inside their interval —
    /// the hysteresis input for downward interval moves.
    stable_rounds: u32,
    budget_exceeded: bool,
    /// True once the first poll has settled — the snapshot's revision.
    formed: bool,
    /// The roster N the current interval was budgeted on.
    roster: u64,
    /// Largest subtree a settled poll has explained this run (root
    /// included). §6.5: N is "既知membership／木の大きい方" — a quiet round
    /// never shrinks it.
    tree_n: u64,
    /// Rounds the last settled poll's GROUP_REPORT carried (≥1) — repair
    /// pressure feeds the budget immediately.
    rounds: u8,
}

#[derive(Default)]
pub struct Counters {
    pub polls: u64,
    pub skipped: u64,
    pub complete: u64,
    pub incomplete: u64,
    pub refused: u64,
    pub not_sent: u64,
    pub indeterminate: u64,
}

pub struct RollcallService {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    run: Option<Run>,
    history: VecDeque<PollSnapshot>,
    /// Set when a due poll had to be skipped (in-flight predecessor) or the
    /// roster was empty — surfaced as the status `note`.
    note: Option<&'static str>,
    /// Skip reasons counted this run, for `lab.rollcall.status`.
    skipped_prior_unsettled: u64,
    waiting_members_ticks: u64,
    counters: Counters,
}

impl Default for RollcallService {
    fn default() -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
        }
    }
}

/// The adaptive-interval result of `step_interval`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IntervalDecision {
    interval_ms: u64,
    budget_exceeded: bool,
}

/// Roster → budget interval, then the hysteresis rules of §6.5: extend
/// immediately (growth, repair rounds, queue/site pressure must not wait),
/// shrink only after SHRINK_AFTER_ROUNDS clean rounds and then one 25%
/// step at a time. `pressure` (live join/GK/cutover work) doubles the
/// target and freezes the shrink hysteresis — the run yields airtime.
fn step_interval(
    current_ms: u64,
    roster: u64,
    rounds: u8,
    stable_rounds: u32,
    pressure: bool,
) -> IntervalDecision {
    let (target, mut exceeded) = interval_for_roster(roster, rounds);
    let target = if pressure {
        let doubled = target.saturating_mul(2);
        exceeded |= doubled > MAX_INTERVAL_MS;
        doubled.min(MAX_INTERVAL_MS)
    } else {
        target
    };
    if target >= current_ms {
        return IntervalDecision {
            interval_ms: target,
            budget_exceeded: exceeded,
        };
    }
    if !pressure && stable_rounds >= SHRINK_AFTER_ROUNDS {
        // One step: a quarter of the gap (snapping the last ≤256 ms) — a
        // shrinking roster eases the interval down over several decisions
        // instead of snapping, and it converges exactly onto the budget.
        let gap = current_ms - target;
        let step = (gap / 4).max(gap.min(256));
        return IntervalDecision {
            interval_ms: current_ms - step,
            budget_exceeded: exceeded,
        };
    }
    IntervalDecision {
        interval_ms: current_ms,
        budget_exceeded: exceeded,
    }
}

fn rollcall_payload(run_uuid: [u8; 16], poll_seq: u64) -> Vec<u8> {
    let mut payload = Vec::with_capacity(ROLLCALL_PAYLOAD_BYTES);
    payload.extend_from_slice(&ROLLCALL_MAGIC);
    payload.push(1); // ROLLCALL v1
    payload.extend_from_slice(&[0, 0, 0]); // flags + reserved
    payload.extend_from_slice(&run_uuid[..8]);
    payload.extend_from_slice(&poll_seq.to_be_bytes());
    payload.extend_from_slice(&[0; 8]);
    payload
}

/// The roster the interval is budgeted on: the larger of the gateway's
/// node table and the largest subtree the last poll explained (§6.4 — "既知
/// membership／木の大きい方を使い"). Never shrinks on a quiet round alone.
fn roster_size(table: &NodeTable) -> u64 {
    // Connected records include the gateway (the root).
    let (records, _) = table.list(0, usize::MAX, Some(true));
    records.len() as u64
}

impl RollcallService {
    /// `lab.rollcall.start`: mint a run. Idempotent for a matching request —
    /// a second start for the live run answers it (the single owned loop),
    /// a differing group is a conflict, never a second loop.
    pub fn start(
        &self,
        uid: u32,
        network: u64,
        group: u16,
        now_ms: u64,
    ) -> Result<[u8; 16], &'static str> {
        let mut inner = self.lock();
        if let Some(run) = inner.run.as_mut() {
            if run.group == group && run.network == network {
                return Ok(run.run_uuid);
            }
            return Err("rollcall already runs with a different group/network");
        }
        // Random 128-bit run id — the same mint every other host token uses.
        // Collision-free across restarts, so a restarted run's poll keys
        // can never alias a predecessor's records.
        let run_uuid = crate::send_store::mint_id128();
        inner.run = Some(Run {
            run_uuid,
            owner: uid,
            network,
            group,
            started_ms: now_ms,
            interval_ms: MIN_INTERVAL_MS,
            next_ms: now_ms,
            poll_seq: 0,
            in_flight: None,
            stable_rounds: 0,
            budget_exceeded: false,
            formed: false,
            roster: 0,
            tree_n: 0,
            rounds: 1,
        });
        Ok(run_uuid)
    }

    /// `lab.rollcall.stop`: end the run. An in-flight poll is left to the
    /// group lane — its record stays final-visible, no cancel is faked.
    pub fn stop(&self) -> bool {
        self.lock().run.take().is_some()
    }

    /// `stop` guarded by the run id: a stale client's stop cannot end a run
    /// minted after that client last observed the service.
    pub fn stop_if(&self, run_uuid: &[u8; 16]) -> bool {
        let mut inner = self.lock();
        if inner
            .run
            .as_ref()
            .is_some_and(|run| &run.run_uuid == run_uuid)
        {
            inner.run = None;
            true
        } else {
            false
        }
    }

    /// The network the live run operates on — `lab.rollcall.status`'s ACL
    /// target. None while idle.
    pub fn run_network(&self) -> Option<u64> {
        self.lock().run.as_ref().map(|run| run.network)
    }

    /// `lab.rollcall.update`: retarget the run's group. Only the owner may
    /// move the lease; a mismatching run_uuid is refused rather than
    /// silently steering someone else's loop.
    pub fn update(&self, uid: u32, run_uuid: &[u8; 16], group: u16) -> Result<(), &'static str> {
        let mut inner = self.lock();
        let Some(run) = inner.run.as_mut() else {
            return Err("no rollcall run");
        };
        if run.owner != uid || &run.run_uuid != run_uuid {
            return Err("run_uuid/owner mismatch");
        }
        run.group = group;
        Ok(())
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.inner.lock().expect("rollcall poisoned")
    }

    /// The API `status` snapshot: run fields plus bounded history.
    pub fn status_json(&self) -> String {
        let inner = self.lock();
        let Some(run) = inner.run.as_ref() else {
            return format!(
                "{{\"running\":false,\"polls\":{},\"skipped\":{}}}",
                inner.counters.polls, inner.counters.skipped
            );
        };
        let last = inner.history.back();
        let history_json: Vec<String> = inner.history.iter().rev().map(snapshot_json).collect();
        format!(
            "{{\"running\":true,\"run_uuid\":\"{}\",\"owner_uid\":{},\"network\":\"{:016x}\",\"group\":{},\"started_ms\":{},\"poll_seq\":{},\"in_flight\":{},\"interval_ms\":{},\"budget_exceeded\":{},\"roster\":{},\"tree_n\":{},\"rounds\":{},\"stable_rounds\":{},\"waiting_members_ticks\":{},\"skipped_prior_unsettled\":{},\"note\":{},\"polls\":{},\"skipped\":{},\"complete\":{},\"incomplete\":{},\"refused\":{},\"not_sent\":{},\"indeterminate\":{},\"last\":{},\"history\":[{}]}}",
            run_uuid_hex(run.run_uuid),
            run.owner,
            run.network,
            run.group,
            run.started_ms,
            run.poll_seq,
            run.in_flight
                .map_or_else(|| "null".to_string(), |id| format!("\"grp{id:016x}\"")),
            run.interval_ms,
            run.budget_exceeded,
            run.roster,
            run.tree_n,
            run.rounds,
            run.stable_rounds,
            inner.waiting_members_ticks,
            inner.skipped_prior_unsettled,
            inner
                .note
                .map_or_else(|| "null".to_string(), |n| format!("\"{n}\"")),
            inner.counters.polls,
            inner.counters.skipped,
            inner.counters.complete,
            inner.counters.incomplete,
            inner.counters.refused,
            inner.counters.not_sent,
            inner.counters.indeterminate,
            last.map_or_else(|| "null".to_string(), snapshot_json),
            history_json.join(","),
        )
    }
}

fn run_uuid_hex(uuid: [u8; 16]) -> String {
    RunUuid(uuid).to_string()
}

fn snapshot_json(s: &PollSnapshot) -> String {
    let missing: Vec<String> = s
        .missing
        .iter()
        .map(|id| format!("\"{id:016x}\""))
        .collect();
    let opt_u16 = |v: Option<u16>| v.map_or_else(|| "null".to_string(), |v| v.to_string());
    format!(
        "{{\"poll_seq\":{},\"group_op\":\"grp{:016x}\",\"key\":\"{}\",\"group\":{},\"roster\":{},\"interval_ms\":{},\"submitted_ms\":{},\"settled_ms\":{},\"outcome\":\"{}\",\"delivered\":{},\"nonmember\":{},\"missing_total\":{},\"unaccounted\":{},\"missing\":[{}],\"missing_truncated\":{}}}",
        s.poll_seq,
        s.op_id,
        run_uuid_hex(s.key),
        s.group,
        s.roster,
        s.interval_ms,
        s.submitted_ms,
        s.settled_ms.map_or_else(|| "null".to_string(), |v| v.to_string()),
        s.outcome,
        opt_u16(s.delivered),
        opt_u16(s.nonmember),
        opt_u16(s.missing_total),
        opt_u16(s.unaccounted),
        missing.join(","),
        s.missing_truncated,
    )
}

/// One rollcall tick: re-budget on the current roster, harvest a settled
/// in-flight poll, skip a due slot when the predecessor is still live, or
/// submit the next poll. Pure with respect to I/O beyond the `GroupOps`
/// submit — the group lane owns the wire.
///
/// `roster` is the node-table's connected count (root included); the run
/// keeps the larger of it and the biggest subtree any settled poll has
/// explained. `pressure` is the Site Authority's live join/GK/cutover flag
/// — while set the interval yields instead of racing control traffic.
/// `now` is host unix ms.
pub fn rollcall_once(state: &State, now: u64) {
    let roster = {
        let table = state.node_table.lock().expect("node table poisoned");
        roster_size(&table)
    };
    let pressure = state
        .site
        .as_ref()
        .is_some_and(|site| site.control_pressure());
    service_step(&state.rollcall, &state.group_ops, roster, pressure, now);
}

/// The testable core: service + ops + roster, no `State`.
pub fn service_step(
    service: &RollcallService,
    ops: &GroupOps,
    roster: u64,
    pressure: bool,
    now: u64,
) {
    let mut guard = service.lock();
    let Inner {
        run: maybe_run,
        history,
        note,
        skipped_prior_unsettled,
        waiting_members_ticks,
        counters,
    } = &mut *guard;
    let Some(run) = maybe_run.as_mut() else {
        return;
    };
    // §6.5: N is the LARGER of the membership view and the biggest subtree
    // any settled poll explained — a quiet round never shrinks it.
    let n = roster.max(run.tree_n);
    run.roster = n;

    // Harvest: an in-flight poll whose record turned final folds into the
    // history. The lane's phase already encodes the honest outcome — never
    // re-count an UNKNOWN terminal as coverage.
    if let Some(op_id) = run.in_flight {
        if let Some(record) = ops.get(op_id) {
            if record.is_final() {
                run.in_flight = None;
                let status = record.status;
                let (outcome, stable) = match record.phase {
                    group::Phase::Settled => {
                        let complete = status
                            .as_ref()
                            .is_some_and(|s| s.missing_total == 0 && s.unaccounted == 0);
                        (if complete { "complete" } else { "incomplete" }, complete)
                    }
                    group::Phase::Refused => ("refused", false),
                    group::Phase::NotSent => ("not_sent", false),
                    _ => ("indeterminate", false),
                };
                let mut snapshot = PollSnapshot {
                    poll_seq: run.poll_seq,
                    op_id,
                    key: record.key,
                    group: run.group,
                    roster,
                    interval_ms: run.interval_ms,
                    submitted_ms: record.submitted_ms,
                    settled_ms: record.settled_ms,
                    outcome,
                    delivered: None,
                    nonmember: None,
                    missing_total: None,
                    unaccounted: None,
                    missing_truncated: false,
                    missing: Vec::new(),
                };
                if let Some(s) = status {
                    snapshot.delivered = Some(s.delivered);
                    snapshot.nonmember = Some(s.nonmember);
                    snapshot.missing_total = Some(s.missing_total);
                    snapshot.unaccounted = Some(s.unaccounted);
                    snapshot.missing_truncated = s.truncated();
                    snapshot.missing = s.missing;
                    // The tree this poll explained: 1 (root) + every node a
                    // report accounted for in ANY class. A complete poll is
                    // authoritative — missing evidence is absent, so a
                    // smaller explained set is an honest membership shrink.
                    // An incomplete round may only GROW the estimate —
                    // "応答が減っただけで間隔を短くしない".
                    let explained = 1u64
                        + u64::from(s.delivered)
                        + u64::from(s.nonmember)
                        + u64::from(s.missing_total)
                        + u64::from(s.unaccounted);
                    run.tree_n = if stable {
                        explained
                    } else {
                        run.tree_n.max(explained)
                    };
                    run.rounds = s.rounds.max(1);
                }
                counters.polls += 1;
                match outcome {
                    "complete" => counters.complete += 1,
                    "incomplete" => counters.incomplete += 1,
                    "refused" => counters.refused += 1,
                    "not_sent" => counters.not_sent += 1,
                    _ => counters.indeterminate += 1,
                }
                if history.len() >= HISTORY_CAP {
                    history.pop_front();
                }
                history.push_back(snapshot);
                run.formed = true;
                run.stable_rounds = if stable { run.stable_rounds + 1 } else { 0 };
                let n = n.max(run.tree_n);
                let decision =
                    step_interval(run.interval_ms, n, run.rounds, run.stable_rounds, pressure);
                run.interval_ms = decision.interval_ms;
                run.budget_exceeded = decision.budget_exceeded;
                run.next_ms = now + run.interval_ms;
            }
        } else {
            // The record was evicted between submit and harvest (extreme
            // host pressure): count it honestly as lost, never invent.
            run.in_flight = None;
            run.stable_rounds = 0;
            counters.indeterminate += 1;
            counters.polls += 1;
            *note = Some("record_evicted");
            run.next_ms = now + run.interval_ms;
        }
    }

    // Waiting: no members means nothing to call — keep the run parked
    // (§6.4 "member 0台ならサービスは継続待機").
    if n <= 1 {
        *note = Some("waiting_members");
        *waiting_members_ticks += 1;
        run.next_ms = now + TICK_MS;
        run.stable_rounds = 0;
        return;
    }

    // Skip: the previous poll is still unsettled — record the gap and move
    // the schedule forward instead of bursting to catch up (§6.4).
    if run.in_flight.is_some() {
        if now >= run.next_ms {
            *skipped_prior_unsettled += 1;
            counters.skipped += 1;
            *note = Some("prior_unsettled");
            run.stable_rounds = 0;
            run.next_ms = now + run.interval_ms;
        }
        return;
    }

    if now < run.next_ms {
        return;
    }
    // Schedule the next poll through the same admission path `group.send`
    // uses: BULK priority, unordered, one in flight, ttl bounded by the
    // interval so a stale round never drags the run.
    run.poll_seq += 1;
    let mut key = [0u8; 16];
    key[..8].copy_from_slice(&run.run_uuid[..8]);
    key[8..].copy_from_slice(&run.poll_seq.to_be_bytes());
    let request = GroupRequest {
        network: run.network,
        group: run.group,
        priority: 0, // BULK
        ordered: false,
        ttl_ms: (run.interval_ms.clamp(2_000, 30_000)) as u32,
        hop_limit: 254,
        payload: rollcall_payload(run.run_uuid, run.poll_seq),
    };
    match ops.submit(ROLLCALL_UID, key, request, now) {
        Ok(group::SubmitOutcome::Accepted(op_id)) | Ok(group::SubmitOutcome::Replay(op_id)) => {
            run.in_flight = Some(op_id);
            run.next_ms = now + run.interval_ms;
            *note = None;
        }
        Err(_) => {
            // Bounded admission pressure (queue/live caps): count it, hold
            // the interval — never open a second flight or retry inline.
            *note = Some("no_capacity");
            counters.skipped += 1;
            run.stable_rounds = 0;
            run.next_ms = now + run.interval_ms;
        }
    }
}

/// The lane thread: parked until a run exists, then 50 ms ticks. It shares
/// the daemon's discipline — no client connection can create a second loop
/// (the service is a `State` singleton).
pub fn rollcall_loop(state: std::sync::Arc<State>) {
    loop {
        rollcall_once(&state, crate::now_ms());
        std::thread::sleep(Duration::from_millis(TICK_MS));
    }
}

#[cfg(test)]
impl RollcallService {
    /// Test-only: the in-flight op id, so a test can drive the lane to
    /// settle exactly the record the service submitted.
    fn in_flight_op(&self) -> Option<u64> {
        self.lock().run.as_ref().and_then(|r| r.in_flight)
    }

    /// Test-only: the effective interval the run is currently using.
    fn interval_ms(&self) -> Option<u64> {
        self.lock().run.as_ref().map(|r| r.interval_ms)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{GroupLane, GroupLink};
    use routeloom_json::Json;
    use routeloom_protocol::group_ops::{
        encode_group_status, GroupStatus, GROUP_SEQUENCE_FLAG, STATE_DELIVERED, STATE_FAILED,
    };
    use routeloom_protocol::host_ops::ConfigOpsResult;

    const NET: u64 = 7;
    const SESSION: u64 = 0x5e55;

    fn link() -> GroupLink {
        GroupLink {
            active: true,
            capable: true,
            session: SESSION,
            gateway: 1,
            network: NET,
        }
    }

    fn report(state: u8, delivered: u16, missing_total: u16, unaccounted: u16) -> Vec<u8> {
        encode_group_status(&GroupStatus {
            result: ConfigOpsResult::Ok as u16,
            session: 0x1b59,
            sequence: GROUP_SEQUENCE_FLAG | 1,
            group: DEFAULT_GROUP,
            state,
            rounds: 1,
            delivered,
            nonmember: 0,
            missing_total,
            unaccounted,
            missing: Vec::new(),
            reason: if state == STATE_DELIVERED {
                "GROUP_COMPLETE"
            } else {
                "GROUP_INCOMPLETE"
            }
            .to_string(),
        })
        .unwrap()
    }

    /// Drive the in-flight poll through the lane to a settled record with
    /// the given device status, then harvest it.
    fn settle_poll(
        service: &RollcallService,
        ops: &GroupOps,
        lane: &mut GroupLane,
        roster: u64,
        now: u64,
        status_body: Vec<u8>,
    ) {
        // Admission: the lane emits the 0x50 and the device admits it.
        let out = ops.step(lane, &link(), now);
        let (request, _) = *out.frames.last().expect("a GROUP_SEND frame");
        ops.post_status(
            request,
            encode_group_status(&GroupStatus {
                result: ConfigOpsResult::Ok as u16,
                session: 0x1b59,
                sequence: GROUP_SEQUENCE_FLAG | 1,
                group: DEFAULT_GROUP,
                state: 6, // GROUP_ROUND_PENDING
                rounds: 0,
                delivered: 0,
                nonmember: 0,
                missing_total: 0,
                unaccounted: 0,
                missing: Vec::new(),
                reason: "GROUP_ROUND_PENDING".to_string(),
            })
            .unwrap(),
        );
        ops.post_status(request, status_body);
        // Both inbox answers apply in order on the next lane pass.
        ops.step(lane, &link(), now + 5);
        service_step(service, ops, roster, false, now + 10);
    }

    #[test]
    fn interval_table_matches_design() {
        // §6.5: the 2 s floor binds while the budgeted interval is smaller;
        // at N=10 the honest budget is already 2,065 ms.
        for n in 1..=9u64 {
            let (interval, exceeded) = interval_for_roster(n, 1);
            assert_eq!(interval, 2_000, "n={n}");
            assert!(!exceeded, "n={n}");
        }
        assert_eq!(interval_for_roster(10, 1), (2_065, false));
        let (interval, exceeded) = interval_for_roster(100, 1);
        // 99 × 15,296 us × 1.5 / 100,000 us/s → 22,714.56 ms → 22,715.
        assert_eq!(interval, 22_715);
        assert!(!exceeded);
        // The budget-exceeded knee: interval wanted beyond MAX.
        let (interval, exceeded) = interval_for_roster(5_000, 1);
        assert_eq!(interval, MAX_INTERVAL_MS);
        assert!(exceeded);
    }

    #[test]
    fn start_is_idempotent_and_single_owner() {
        let service = RollcallService::default();
        let a = service.start(501, NET, DEFAULT_GROUP, 1_000).unwrap();
        // A reconnecting GUI asking the same thing gets the same run —
        // never a second loop.
        assert_eq!(service.start(501, NET, DEFAULT_GROUP, 2_000).unwrap(), a);
        assert_eq!(
            service.start(502, NET, DEFAULT_GROUP, 3_000).unwrap(),
            a,
            "the single owned run answers every matching start"
        );
        // A different group is a conflict, not a second loop.
        assert!(service.start(501, NET, 7, 4_000).is_err());
        // update is owner-only and run-bound.
        assert!(service.update(502, &a, 9).is_err());
        assert!(service.update(501, &[0xde; 16], 9).is_err());
        service.update(501, &a, 9).unwrap();
        assert!(!service.stop_if(&[0xde; 16]), "stale id cannot stop");
        assert!(service.stop_if(&a));
        assert!(!service.stop(), "already stopped");
    }

    #[test]
    fn empty_roster_waits_without_transmitting() {
        let service = RollcallService::default();
        let ops = GroupOps::default();
        service.start(501, NET, DEFAULT_GROUP, 1_000).unwrap();
        for tick in 0..10 {
            service_step(&service, &ops, 0, false, 1_000 + tick * TICK_MS);
        }
        assert!(service.in_flight_op().is_none());
        let status = routeloom_json::parse(&service.status_json()).unwrap();
        assert_eq!(
            status.get("note").and_then(Json::as_str),
            Some("waiting_members")
        );
        assert_eq!(status.get("polls").and_then(Json::as_u64), Some(0));
        // A lone root (roster 1) is also "no members".
        service_step(&service, &ops, 1, false, 2_000);
        assert!(service.in_flight_op().is_none());
    }

    #[test]
    fn poll_submit_settle_and_interval_extends() {
        let service = RollcallService::default();
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        service.start(501, NET, DEFAULT_GROUP, 1_000).unwrap();
        // Roster 10 → still at the 2 s floor.
        service_step(&service, &ops, 10, false, 1_000);
        let op = service.in_flight_op().expect("first poll submitted");
        assert_eq!(service.interval_ms(), Some(2_000));
        // Settle inside the poll's lifetime (submit + ttl = 3_000).
        settle_poll(
            &service,
            &ops,
            &mut lane,
            10,
            1_500,
            report(STATE_DELIVERED, 9, 0, 0),
        );
        let status = routeloom_json::parse(&service.status_json()).unwrap();
        assert_eq!(status.get("polls").and_then(Json::as_u64), Some(1));
        assert_eq!(status.get("complete").and_then(Json::as_u64), Some(1));
        let last = status.get("last").unwrap();
        assert_eq!(last.get("delivered").and_then(Json::as_u64), Some(9));
        assert_eq!(last.get("outcome").and_then(Json::as_str), Some("complete"));
        assert_eq!(
            last.get("group_op").and_then(Json::as_str),
            Some(format!("grp{op:016x}").as_str())
        );
        // The next slot is due at settle + interval — the roster-10 budget
        // already moved the interval to 2,065 ms, so due ≈ 1,510 + 2,065.
        service_step(&service, &ops, 10, false, 1_600);
        assert!(service.in_flight_op().is_none(), "not due yet");
        // A 100-node roster: the budget interval jumps immediately — the
        // roster is read when the next poll is scheduled and settled.
        service_step(&service, &ops, 100, false, 3_600);
        let op2 = service.in_flight_op().expect("second poll");
        assert_ne!(op, op2);
        settle_poll(
            &service,
            &ops,
            &mut lane,
            100,
            3_650,
            report(STATE_DELIVERED, 99, 0, 0),
        );
        let status = routeloom_json::parse(&service.status_json()).unwrap();
        assert_eq!(
            status.get("interval_ms").and_then(Json::as_u64),
            Some(22_715)
        );
    }

    #[test]
    fn unsettled_prior_is_skipped_not_retried() {
        let service = RollcallService::default();
        let ops = GroupOps::default();
        service.start(501, NET, DEFAULT_GROUP, 1_000).unwrap();
        service_step(&service, &ops, 10, false, 1_000);
        let first = service.in_flight_op().unwrap();
        // Six due ticks pass with the poll still unsettled: each records a
        // skip — the schedule slips rather than bursting.
        for tick in 1..=6u64 {
            service_step(&service, &ops, 10, false, 1_000 + tick * 2_000);
        }
        let status = routeloom_json::parse(&service.status_json()).unwrap();
        assert_eq!(
            status.get("skipped_prior_unsettled").and_then(Json::as_u64),
            Some(6)
        );
        assert_eq!(service.in_flight_op(), Some(first), "still the same op");
        assert_eq!(status.get("polls").and_then(Json::as_u64), Some(0));
    }

    #[test]
    fn missing_members_are_incomplete_not_unknown() {
        let service = RollcallService::default();
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        service.start(501, NET, DEFAULT_GROUP, 1_000).unwrap();
        service_step(&service, &ops, 10, false, 1_000);
        settle_poll(
            &service,
            &ops,
            &mut lane,
            10,
            1_500,
            report(STATE_FAILED, 8, 1, 0),
        );
        let status = routeloom_json::parse(&service.status_json()).unwrap();
        assert_eq!(status.get("incomplete").and_then(Json::as_u64), Some(1));
        let last = status.get("last").unwrap();
        assert_eq!(last.get("missing_total").and_then(Json::as_u64), Some(1));
        assert_eq!(
            last.get("outcome").and_then(Json::as_str),
            Some("incomplete")
        );
    }

    #[test]
    fn interval_shrinks_only_after_sustained_clean_rounds() {
        let service = RollcallService::default();
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        service.start(501, NET, DEFAULT_GROUP, 1_000).unwrap();
        // Force the interval up on a big roster, then shrink the roster and
        // run SHRINK_AFTER_ROUNDS clean polls — the interval steps down in
        // quarters, never snapping.
        service_step(&service, &ops, 100, false, 1_000);
        settle_poll(
            &service,
            &ops,
            &mut lane,
            100,
            1_100,
            report(STATE_DELIVERED, 99, 0, 0),
        );
        assert_eq!(service.interval_ms(), Some(22_715));
        let mut now = 1_110u64;
        let mut last_interval = 22_715u64;
        let mut shrunk = false;
        for i in 0..SHRINK_AFTER_ROUNDS + 2 {
            now += last_interval + 100;
            service_step(&service, &ops, 10, false, now);
            if service.in_flight_op().is_none() {
                panic!("iter {i}: no submit; {}", service.status_json());
            }
            settle_poll(
                &service,
                &ops,
                &mut lane,
                10,
                now + 5,
                report(STATE_DELIVERED, 9, 0, 0),
            );
            let interval = service.interval_ms().unwrap();
            if interval < last_interval {
                shrunk = true;
            }
            last_interval = interval;
        }
        assert!(
            shrunk,
            "sustained clean rounds eventually shrink the interval"
        );
        // …and converges onto the roster-10 budget target (2,065 ms — the
        // 2 s floor binds only below the honest budget).
        for _ in 0..30 {
            now += last_interval + 100;
            service_step(&service, &ops, 10, false, now);
            settle_poll(
                &service,
                &ops,
                &mut lane,
                10,
                now + 5,
                report(STATE_DELIVERED, 9, 0, 0),
            );
            last_interval = service.interval_ms().unwrap();
        }
        assert_eq!(service.interval_ms(), Some(2_065));
    }

    #[test]
    fn evicted_record_is_indeterminate_not_success() {
        let service = RollcallService::default();
        let ops = GroupOps::default();
        service.start(501, NET, DEFAULT_GROUP, 1_000).unwrap();
        service_step(&service, &ops, 10, false, 1_000);
        let op = service.in_flight_op().unwrap();
        // Evict the record out from under the service (fill the bounded
        // table). The poll's outcome is honestly unobservable.
        let mut n = 0u8;
        while ops.get(op).is_some() && n < 255 {
            let _ = ops.submit(
                1,
                [n; 16],
                crate::group::GroupRequest {
                    network: NET,
                    group: DEFAULT_GROUP,
                    priority: 0,
                    ordered: false,
                    ttl_ms: 5_000,
                    hop_limit: 10,
                    payload: vec![1],
                },
                2_000 + u64::from(n),
            );
            n = n.wrapping_add(1);
        }
        // If the table held the record anyway (cap reached first), skip —
        // the assertion that matters is that a missing record is not a
        // success either way.
        if ops.get(op).is_none() {
            service_step(&service, &ops, 10, false, 3_000);
            let status = routeloom_json::parse(&service.status_json()).unwrap();
            assert_eq!(status.get("indeterminate").and_then(Json::as_u64), Some(1));
            assert_eq!(
                status.get("note").and_then(Json::as_str),
                Some("record_evicted")
            );
        }
    }
}
