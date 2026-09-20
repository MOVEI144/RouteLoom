//! TX-I2 host dispatch loop (Issues #9/#10 host side, 03-send-api.md §4–§5).
//!
//! One dedicated thread owns the USB host-operation flow so the socket API
//! path never blocks on it. The discipline from the design docs:
//!
//! - The store commits `DISPATCH_PREPARED` (lease + dispatcher + dispatch_seq
//!   binding) before any USB write for that position can be claimed.
//! - A record's `submitted` flag is the "may have left the host" marker:
//!   while false the device provably holds nothing at the position, which is
//!   what makes CANCELLED_BEFORE_DISPATCH / EXPIRED_BEFORE_DISPATCH provable.
//!   It is set at claim time (before enqueue) and cleared only on proofs of
//!   emptiness — emit failure before the writer, or a device response
//!   showing no record (NotRetained/WindowFull/MeshRejected).
//! - QUERY_DISPATCH is read-only; lost receipts are recovered by query
//!   (Found → adopt slot, NotRetained → provably empty → resubmit), never
//!   by blind re-execution.
//! - RETIRE_THROUGH follows the contiguous device-terminal prefix only;
//!   proven-empty positions are filled with SKIP first.
//! - BootLease changes never re-bind old dispatches — live records under a
//!   dead lease become INDETERMINATE; queued records wait for the new link.
//! - Deadlines use wall-clock elapsed validity mapped onto the device's
//!   monotonic clock through TIME_SAMPLE mappings (review-addendum §1
//!   arithmetic); no mapping, no dispatch — and no deadline is ever
//!   extended.

use routeloom_protocol::host_ops::{
    self, BootLease, Evidence, HostOpsResult, LaneRequest, QueryResponse, Receipt, SlotState,
    SubmitRequest, TimeSampleRequest, CAP_HOST_OPS_V1, SUB_QUERY_DISPATCH, SUB_RETIRE_THROUGH,
    SUB_SKIP,
};
use routeloom_protocol::{Frame, FrameKind};
use std::collections::{BTreeMap, HashMap};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use crate::send_store::{DispatchState, OperationStore, PrepareOutcome, StoredOperation};
use crate::{json_escape, now_ms, push_event, Outbound, State};

// contracts.json / design constants.
pub const DISPATCH_WINDOW: u64 = 32;
pub const TIME_SAMPLE_MAX_AGE_MS: u64 = 5_000;
pub const CLOCK_PPM: u64 = 1_000;
pub const CLOCK_QUANTUM_MS: u64 = 1;

/// Poll cadence for live positions and the response window after which an
/// unanswered request is dropped and re-issued via QUERY.
const TICK_MS: u64 = 40;
const QUERY_INTERVAL_MS: u64 = 300;
const RESPONSE_TIMEOUT_MS: u64 = 800;
const SAMPLE_TIMEOUT_MS: u64 = 500;
/// Inbox bound — the read thread posts into it and must never block.
const INBOX_CAP: usize = 128;

/// Host-ops responses landed by `record_frame` wait here for the dispatch
/// thread. Keyed by the request id we issued; request ids are monotonic
/// per dispatcher so a stale-session reply can never alias a live entry.
#[derive(Default)]
pub struct DispatchInbox {
    map: Mutex<HashMap<u64, Vec<u8>>>,
    cv: Condvar,
}

impl DispatchInbox {
    /// Post one verified inner body. Never blocks; a full inbox drops the
    /// body — the affected request times out and the loop re-queries.
    pub fn post(&self, request: u64, body: Vec<u8>) {
        let mut map = self.map.lock().expect("dispatch inbox poisoned");
        if map.len() >= INBOX_CAP {
            drop(map);
            return;
        }
        map.insert(request, body);
        drop(map);
        self.cv.notify_one();
    }

    fn drain(&self) -> Vec<(u64, Vec<u8>)> {
        std::mem::take(&mut *self.map.lock().expect("dispatch inbox poisoned"))
            .into_iter()
            .collect()
    }

    fn wait(&self, dur: Duration) {
        let guard = self.map.lock().expect("dispatch inbox poisoned");
        let _ = self.cv.wait_timeout(guard, dur);
    }
}

/// What the session layer currently knows about the USB link.
#[derive(Clone, Copy, Debug)]
pub struct LinkSnapshot {
    pub active: bool,
    pub host_ops: bool,
    pub node: u64,
    pub boot: u64,
    pub network: u64,
}

impl LinkSnapshot {
    /// BootLease derived from the authenticated HelloAck identity — the
    /// only lease this session may dispatch under. None when the link is
    /// down, unauthenticated, lacks CAP_HOST_OPS_V1, or carries a reserved
    /// boot/node id.
    fn lease(&self) -> Option<[u8; 16]> {
        if !(self.active && self.host_ops) {
            return None;
        }
        let lease = BootLease::derive(self.boot, self.node);
        lease.valid().then_some(lease.0)
    }
}

fn link_snapshot(state: &State) -> LinkSnapshot {
    let info = state.session.lock().expect("session poisoned");
    LinkSnapshot {
        active: info.authenticated,
        host_ops: info.capability.is_some_and(|c| c & CAP_HOST_OPS_V1 != 0),
        node: info.node.unwrap_or(0),
        boot: info.boot.unwrap_or(0),
        network: info.network.unwrap_or(0),
    }
}

/// One authenticated device-clock observation: the device monotonic time
/// `d` measured between host send `h0` and host receipt `h1`.
#[derive(Clone, Copy, Debug)]
pub struct TimeMapping {
    pub d: u64,
    pub h0: u64,
    pub h1: u64,
}

/// Outcome of the deadline mapping arithmetic (review-addendum §1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeadlineDecision {
    /// Dispatch may proceed; carries the device-time deadline to submit.
    Ready(u64),
    /// No budget remains — provable expiry for never-sent records.
    ExpiredBudget,
    /// Remaining lifetime cannot be proven; dispatch is prohibited.
    TimeUncertain,
    /// Checked arithmetic overflowed — hold, never wrap a deadline.
    ArithmeticOverflow,
}

/// The addendum's deadline pipeline: `D = accepted + ttl` on the host wall
/// clock, `remaining = D - h1`, `margin = 1 + ceil(ppm*(D - h0)/1e6)`,
/// `device_deadline = d + (remaining - margin)`. `device_now` is the
/// host's current estimate of the device clock — production projects it
/// as `d + (now - h1)`; it is an explicit parameter so the reference
/// vectors can drive the `device_now < d` (clock inconsistency) and
/// `device_now >= device_deadline` boundaries directly. Order is
/// significant: malformed mappings fail before expiry arithmetic, the
/// margin comparison happens before any subtraction, and every add is
/// checked — nothing wraps or saturates into extra validity.
pub fn deadline_decision(
    accepted_ms: u64,
    ttl_ms: u32,
    mapping: Option<TimeMapping>,
    device_now: u64,
    host_now: u64,
) -> DeadlineDecision {
    let Some(deadline) = accepted_ms.checked_add(u64::from(ttl_ms)) else {
        return DeadlineDecision::ArithmeticOverflow;
    };
    // Host clock below the admission stamp: elapsed validity is
    // unprovable, so dispatch is prohibited until it recovers.
    if host_now < accepted_ms {
        return DeadlineDecision::TimeUncertain;
    }
    let Some(map) = mapping else {
        return DeadlineDecision::TimeUncertain;
    };
    // A sample whose own timestamps are unordered proves nothing.
    if map.h0 > map.h1 || map.h1 > host_now {
        return DeadlineDecision::TimeUncertain;
    }
    if host_now >= deadline {
        return DeadlineDecision::ExpiredBudget;
    }
    // Conservative sample age bound (time_sample_max_age_ms).
    if host_now - map.h0 > TIME_SAMPLE_MAX_AGE_MS {
        return DeadlineDecision::TimeUncertain;
    }
    let remaining = deadline - map.h1;
    let span = deadline - map.h0;
    // margin = 1ms quantum + ceil(ppm * span / 1e6): both clocks may drift
    // CLOCK_PPM relative over the whole measured span.
    let margin =
        CLOCK_QUANTUM_MS + span.saturating_mul(CLOCK_PPM).saturating_add(999_999) / 1_000_000;
    if remaining <= margin {
        return DeadlineDecision::ExpiredBudget;
    }
    let safe_remaining = remaining - margin;
    let Some(device_deadline) = map.d.checked_add(safe_remaining) else {
        return DeadlineDecision::ArithmeticOverflow;
    };
    if device_now < map.d {
        return DeadlineDecision::TimeUncertain;
    }
    if device_now >= device_deadline {
        return DeadlineDecision::ExpiredBudget;
    }
    DeadlineDecision::Ready(device_deadline)
}

/// Project the device clock forward from a mapping: `d + (now - h1)` at
/// the same rate. The drift margin already covers the relative error the
/// projection can hide, and the device re-checks the deadline on receipt,
/// at queue-pop, and on every retransmission.
fn project_device_now(map: &TimeMapping, host_now: u64) -> u64 {
    map.d.saturating_add(host_now.saturating_sub(map.h1))
}

/// One frame body the dispatcher wants on the wire. `request` is the
/// correlation id carried in the sealed Frame; `op_seq`/`kind` let
/// `emit_dropped` undo the claim when the queue refuses it.
pub struct DispatchRequest {
    pub request: u64,
    pub body: Vec<u8>,
}

/// Per-tick emit context threaded through the dispatch pass: the bound
/// device lease, the tick timestamp, and the request sink.
struct Pass<'a> {
    lease: BootLease,
    now: u64,
    out: &'a mut Vec<DispatchRequest>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Submit,
    Query,
    Skip,
    Retire,
}

struct Pending {
    op_seq: Option<u64>,
    kind: PendingKind,
    sent_ms: u64,
    /// The requested floor target for Retire pendings — the device's
    /// `retired_through` reply is its CURRENT floor, not the refused
    /// target, so the request must carry its own span. 0 for other kinds.
    through: u64,
}

#[derive(Clone, Copy)]
struct TimeSampleInFlight {
    request: u64,
    nonce: u64,
    h0: u64,
}

/// The TX-I2 dispatcher: a synchronous state machine driven by `tick`
/// (emits request bodies) and `handle_reply` (consumes inbox bodies).
/// All store access goes through `OperationStore` transitions, so the
/// dispatch/cancel boundary is the store lock for both providers.
pub struct Dispatcher {
    dispatcher_id: [u8; 16],
    /// BootLease bytes of the current session; None while the link is not
    /// dispatchable. Attachments under any other lease are dead tickets.
    lease: Option<[u8; 16]>,
    mapping: Option<TimeMapping>,
    /// Device `retired_through` as last reported to us.
    floor: u64,
    next_request: u64,
    next_nonce: u64,
    pending: HashMap<u64, Pending>,
    sample: Option<TimeSampleInFlight>,
    /// Last USB attempt per operation seq — throttles query re-polls.
    last_attempt: HashMap<u64, u64>,
    /// A device clock regression was observed on this lease.
    clock_degraded: bool,
    /// Bounded diagnostics drained by the loop into the event ring.
    notes: Vec<String>,
}

impl Dispatcher {
    pub fn new(dispatcher_id: [u8; 16]) -> Self {
        // The store lineage is the dispatcher identity. Reserved ids
        // (all-zero / all-0xFF) would be rejected by the device — only
        // reachable from a test lineage — so derive a stand-in.
        let mut id = dispatcher_id;
        if id.iter().all(|b| *b == 0) || id.iter().all(|b| *b == 0xFF) {
            id[0] ^= 0x52;
        }
        Self {
            dispatcher_id: id,
            lease: None,
            mapping: None,
            floor: 0,
            next_request: 0,
            next_nonce: 0,
            pending: HashMap::new(),
            sample: None,
            last_attempt: HashMap::new(),
            clock_degraded: false,
            notes: Vec::new(),
        }
    }

    fn alloc_request(&mut self) -> u64 {
        self.next_request = self.next_request.wrapping_add(1).max(1);
        self.next_request
    }

    fn note(&mut self, detail: String) {
        if self.notes.len() < 64 {
            self.notes.push(detail);
        }
    }

    /// Diagnostics collected this pass, drained by the driving loop.
    pub fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    /// One pass: consume nothing (replies go through `handle_reply`),
    /// produce the request bodies the wire needs next.
    pub fn tick<S: OperationStore>(
        &mut self,
        store: &mut S,
        link: &LinkSnapshot,
        now: u64,
    ) -> Vec<DispatchRequest> {
        let mut out = Vec::new();
        let lease = link.lease();
        if lease != self.lease {
            self.lease_changed(store, lease, now, &mut out);
            self.lease = lease;
        }
        // Drop timed-out pendings; their ops re-resolve via the query pass.
        self.pending
            .retain(|_, p| now.saturating_sub(p.sent_ms) < RESPONSE_TIMEOUT_MS);
        if self
            .sample
            .is_some_and(|s| now.saturating_sub(s.h0) >= SAMPLE_TIMEOUT_MS)
        {
            self.sample = None;
        }
        let Ok(ops) = store.dispatch_view() else {
            self.note("dispatch_view fault".to_string());
            return out;
        };
        // Host-side sweeps need no link: expiry and clock rewind are
        // provable locally for records that never reached USB.
        for op in &ops {
            self.sweep(store, op, now);
        }
        let Some(lease_bytes) = self.lease else {
            return out;
        };
        let lease = BootLease(lease_bytes);
        let mut sorted = ops;
        sorted.sort_by_key(|op| op.seq);
        let mut highwater = sorted
            .iter()
            .filter_map(|op| op.dispatch.as_ref())
            .filter(|att| att.lease == lease_bytes)
            .map(|att| att.dispatch_seq)
            .max()
            .unwrap_or(0);
        let mut pass = Pass {
            lease,
            now,
            out: &mut out,
        };
        self.dispatch_pass(store, &sorted, link, &mut pass, &mut highwater);
        self.query_pass(&sorted, lease_bytes, now, &mut out);
        self.skip_pass(&sorted, lease_bytes, now, &mut out);
        self.retire_pass(&sorted, lease_bytes, now, &mut out);
        out
    }

    /// Lease bookkeeping on any change: dead-lease live records become
    /// INDETERMINATE (a dispatch under another boot can never be resolved),
    /// volatile lane state resets, and a floor probe relearns the window.
    fn lease_changed<S: OperationStore>(
        &mut self,
        store: &mut S,
        lease: Option<[u8; 16]>,
        now: u64,
        out: &mut Vec<DispatchRequest>,
    ) {
        self.pending.clear();
        self.sample = None;
        self.mapping = None;
        self.last_attempt.clear();
        self.floor = 0;
        match lease {
            Some(bytes) => {
                self.note(format!("lease up {}", hex16(&bytes)));
                if let Ok(ops) = store.dispatch_view() {
                    for op in ops {
                        let dead = op.dispatch.as_ref().is_some_and(|a| a.lease != bytes)
                            && !op.concluded();
                        if !dead {
                            continue;
                        }
                        // Split on the submitted claim: a record whose
                        // SUBMIT may have left under the dead lease can
                        // never be resolved → INDETERMINATE. A record that
                        // provably never reached the writer is requeued —
                        // it re-prepares under the new lease with a fresh
                        // dispatch_seq; the abandoned position died with
                        // the old boot's window, so no hole needs a SKIP.
                        let submitted = op.dispatch.as_ref().is_some_and(|a| a.submitted);
                        let _ = store.update_operation(op.seq, &mut |o| {
                            if o.concluded() {
                                return false;
                            }
                            if submitted {
                                o.dispatch_state = DispatchState::Indeterminate;
                            } else {
                                o.dispatch_state = DispatchState::HostQueued;
                                o.dispatch = None;
                            }
                            true
                        });
                        if submitted {
                            self.note(format!("op {} indeterminate: lease changed", op.seq));
                        }
                    }
                }
                // Probe the floor: RETIRE_THROUGH(0) moves nothing and the
                // response carries the device's current retired_through.
                out.push(self.emit_retire(0, bytes, now));
            }
            None => self.note("link down".to_string()),
        }
    }

    /// Local sweeps that need no device: wall-clock expiry for provably
    /// unsubmitted records and clock-rewind uncertainty.
    fn sweep<S: OperationStore>(&mut self, store: &mut S, op: &StoredOperation, now: u64) {
        if op.concluded() {
            return;
        }
        if now < op.accepted_ms {
            // Host clock rewound below the admission stamp: the elapsed
            // proof is void — no dispatch, and the record holds
            // TIME_UNCERTAIN rather than guessing a remaining budget.
            if matches!(
                op.dispatch_state,
                DispatchState::HostQueued | DispatchState::DispatchPrepared
            ) {
                let _ = store.update_operation(op.seq, &mut |o| {
                    if o.concluded()
                        || !matches!(
                            o.dispatch_state,
                            DispatchState::HostQueued | DispatchState::DispatchPrepared
                        )
                    {
                        return false;
                    }
                    o.dispatch_state = DispatchState::TimeUncertain;
                    if let Some(d) = o.dispatch.as_mut() {
                        d.time_uncertain = true;
                    }
                    true
                });
            }
            return;
        }
        let Some(deadline) = op.accepted_ms.checked_add(u64::from(op.ttl_ms)) else {
            return;
        };
        if now < deadline {
            return;
        }
        self.expire_unsubmitted(store, op.seq, now);
    }

    /// Mark a provably-never-sent record EXPIRED_BEFORE_DISPATCH.
    /// Cancellable states only: HOST_QUEUED or DISPATCH_PREPARED with
    /// `submitted == false`. TIME_UNCERTAIN is the clock-rewind wrapper —
    /// the provable rule is the same as the state it parked. A prepared
    /// expiry leaves a hole to SKIP.
    fn expire_unsubmitted<S: OperationStore>(&mut self, store: &mut S, op_seq: u64, now: u64) {
        let _ = store.update_operation(op_seq, &mut |o| {
            let provable = match o.dispatch_state {
                DispatchState::HostQueued => true,
                DispatchState::DispatchPrepared | DispatchState::TimeUncertain => {
                    !o.dispatch.as_ref().is_some_and(|d| d.submitted)
                }
                _ => false,
            };
            if !provable {
                return false;
            }
            o.dispatch_state = DispatchState::ExpiredBeforeDispatch;
            o.terminal_ms = Some(now);
            if let Some(d) = o.dispatch.as_mut() {
                d.skip_pending = true;
            }
            true
        });
    }

    /// Emit or re-emit SUBMITs for records that may still go out: fresh
    /// HOST_QUEUED ops (prepare → claim → emit) and DISPATCH_PREPARED ops
    /// whose claim was proven undelivered (`submitted` cleared). Resends
    /// reuse the bound dispatch_seq — replay-safe, never a new position.
    fn dispatch_pass<S: OperationStore>(
        &mut self,
        store: &mut S,
        ops: &[StoredOperation],
        link: &LinkSnapshot,
        pass: &mut Pass<'_>,
        highwater: &mut u64,
    ) {
        let lease = pass.lease;
        let now = pass.now;
        let out = &mut *pass.out;
        for op in ops {
            let resend = op.dispatch_state == DispatchState::DispatchPrepared
                && op
                    .dispatch
                    .as_ref()
                    .is_some_and(|a| a.lease == lease.0 && !a.submitted);
            // A TIME_UNCERTAIN record whose clock proof recovered is
            // dispatchable again — restored to its pre-uncertainty state
            // below. Anything else non-queued never re-executes.
            let uncertain = op.dispatch_state == DispatchState::TimeUncertain;
            let fresh = op.dispatch_state == DispatchState::HostQueued || uncertain;
            if !fresh && !resend {
                continue;
            }
            // The canonical network must equal the session network — the
            // device rejects a mismatch, so mismatched ops stay queued.
            if op.network != link.network {
                continue;
            }
            if self.pending_for(op.seq) {
                continue;
            }
            if resend {
                // Re-drive no faster than the poll cadence: a
                // NotRetained/emit-drop loop must not churn claim commits
                // (two store writes per cycle) at round-trip rate.
                let last = self.last_attempt.get(&op.seq).copied().unwrap_or(0);
                if now.saturating_sub(last) < QUERY_INTERVAL_MS {
                    continue;
                }
            }
            // The device window holds DISPATCH_WINDOW positions above the
            // floor; never allocate ahead of it. Only records that will
            // call prepare_dispatch (no attachment yet) consume a position.
            if op.dispatch.is_none() && *highwater >= self.floor + DISPATCH_WINDOW {
                break;
            }
            let device_now = self
                .mapping
                .map(|m| project_device_now(&m, now))
                .unwrap_or(0);
            let decision =
                deadline_decision(op.accepted_ms, op.ttl_ms, self.mapping, device_now, now);
            let device_deadline = match decision {
                // "No budget" does not mean "deadline elapsed": the sweep
                // owns the EXPIRED_BEFORE_DISPATCH transition and only
                // fires once `now` actually reaches the wall deadline.
                DeadlineDecision::ExpiredBudget => continue,
                DeadlineDecision::TimeUncertain => {
                    // No dispatch without a fresh authenticated mapping.
                    self.maybe_sample(lease, now, out);
                    continue;
                }
                DeadlineDecision::ArithmeticOverflow => continue,
                DeadlineDecision::Ready(deadline) => deadline,
            };
            if uncertain {
                // The clock proof recovered: hand the record back to the
                // lane it came from (unprepared → HOST_QUEUED, prepared
                // but never sent → DISPATCH_PREPARED).
                let restored = store.update_operation(op.seq, &mut |o| {
                    if o.dispatch_state != DispatchState::TimeUncertain || o.concluded() {
                        return false;
                    }
                    o.dispatch_state = if o.dispatch.is_some() {
                        DispatchState::DispatchPrepared
                    } else {
                        DispatchState::HostQueued
                    };
                    true
                });
                if restored != Ok(true) {
                    continue;
                }
                if op.dispatch.is_some() {
                    // Prepared attachment survives; the resend path of the
                    // next pass emits it (fresh snapshot is stale now).
                    continue;
                }
            }
            let attachment = if fresh {
                match store.prepare_dispatch(op.seq, lease.0, self.dispatcher_id) {
                    Ok(PrepareOutcome::Prepared(att)) => att,
                    Ok(PrepareOutcome::NotQueued(state)) => {
                        self.note(format!("op {} prepare raced: {state:?}", op.seq));
                        continue;
                    }
                    _ => continue,
                }
            } else {
                op.dispatch.clone().expect("resend has attachment")
            };
            // Claim the write under the store lock: from this instant the
            // SUBMIT may leave, so cancel/expiry proofs close. An emit that
            // never reaches the writer re-opens them via emit_dropped.
            let dispatch_seq = attachment.dispatch_seq;
            let claimed = store.update_operation(op.seq, &mut |o| {
                let ok = o.dispatch_state == DispatchState::DispatchPrepared
                    && o.dispatch
                        .as_ref()
                        .is_some_and(|a| a.dispatch_seq == dispatch_seq && !a.submitted);
                if ok {
                    if let Some(d) = o.dispatch.as_mut() {
                        d.submitted = true;
                    }
                }
                ok
            });
            if claimed != Ok(true) {
                continue;
            }
            *highwater = (*highwater).max(dispatch_seq);
            let operation_id = op_id_bytes(&self.dispatcher_id, op.seq);
            let body = match host_ops::encode_submit(&SubmitRequest {
                lease,
                dispatcher: self.dispatcher_id,
                dispatch_seq,
                operation_id,
                canonical_hash: op.hash,
                device_deadline,
                canonical: op.canonical.clone(),
            }) {
                Ok(body) => body,
                Err(_) => {
                    // canonical bytes were bounded at admission; if encoding
                    // still fails, unclaim so the record is not stuck.
                    let _ = store.update_operation(op.seq, &mut |o| {
                        if let Some(d) = o.dispatch.as_mut() {
                            d.submitted = false;
                        }
                        true
                    });
                    continue;
                }
            };
            let request = self.alloc_request();
            self.pending.insert(
                request,
                Pending {
                    op_seq: Some(op.seq),
                    kind: PendingKind::Submit,
                    sent_ms: now,
                    through: 0,
                },
            );
            self.last_attempt.insert(op.seq, now);
            out.push(DispatchRequest { request, body });
        }
    }

    /// Poll live attached positions: submitted SUBMITs awaiting a receipt
    /// (or its loss), GATEWAY_ACCEPTED slots awaiting a mesh outcome, and
    /// INDETERMINATE positions whose terminality still gates the floor.
    /// Concluded records poll too whenever their confirmed-terminal
    /// marker is absent — a retire refusal clears markers so the span is
    /// re-verified, and lane tombstones resolve the same way.
    fn query_pass(
        &mut self,
        ops: &[StoredOperation],
        lease: [u8; 16],
        now: u64,
        out: &mut Vec<DispatchRequest>,
    ) {
        for op in ops {
            let Some(att) = op.dispatch.as_ref() else {
                continue;
            };
            if att.lease != lease || att.device_terminal || att.skip_pending || !att.submitted {
                continue;
            }
            // For a live record the vocabulary state must be one the lane
            // can act on; for a concluded one only the position's
            // terminality matters (marker re-verification above).
            if !op.concluded()
                && !matches!(
                    op.dispatch_state,
                    DispatchState::DispatchPrepared
                        | DispatchState::GatewayAccepted
                        | DispatchState::Indeterminate
                        | DispatchState::TimeUncertain
                )
            {
                continue;
            }
            if self.pending_for(op.seq) {
                continue;
            }
            let last = self.last_attempt.get(&op.seq).copied().unwrap_or(0);
            if now.saturating_sub(last) < QUERY_INTERVAL_MS {
                continue;
            }
            out.push(self.emit_lane(
                SUB_QUERY_DISPATCH,
                Some(op.seq),
                att.dispatch_seq,
                lease,
                PendingKind::Query,
                now,
            ));
        }
    }

    /// Fill proven-empty positions so the device retire prefix can pass.
    /// SKIP only goes to positions inside the window and never overwrites
    /// an occupied record — the device refuses that itself.
    fn skip_pass(
        &mut self,
        ops: &[StoredOperation],
        lease: [u8; 16],
        now: u64,
        out: &mut Vec<DispatchRequest>,
    ) {
        for op in ops {
            let Some(att) = op.dispatch.as_ref() else {
                continue;
            };
            if att.lease != lease || !att.skip_pending || att.device_terminal {
                continue;
            }
            if att.dispatch_seq > self.floor + DISPATCH_WINDOW {
                continue;
            }
            if self.pending_for(op.seq) {
                continue;
            }
            out.push(self.emit_lane(
                SUB_SKIP,
                Some(op.seq),
                att.dispatch_seq,
                lease,
                PendingKind::Skip,
                now,
            ));
        }
    }

    /// RETIRE_THROUGH over the contiguous prefix of positions the device
    /// has confirmed terminal (or we confirmed empty). Holes are filled by
    /// the skip pass first; a position with no settled record stops the
    /// floor — the design never retires across the unknown.
    fn retire_pass(
        &mut self,
        ops: &[StoredOperation],
        lease: [u8; 16],
        now: u64,
        out: &mut Vec<DispatchRequest>,
    ) {
        if self
            .pending
            .iter()
            .any(|(_, p)| p.kind == PendingKind::Retire)
        {
            return;
        }
        let attached: BTreeMap<u64, &StoredOperation> = ops
            .iter()
            .filter_map(|op| {
                let att = op.dispatch.as_ref()?;
                (att.lease == lease).then_some((att.dispatch_seq, op))
            })
            .collect();
        let mut target = self.floor;
        while let Some(op) = attached.get(&target.saturating_add(1)) {
            let settled = op.concluded()
                && op
                    .dispatch
                    .as_ref()
                    .is_some_and(|a| a.device_terminal && !a.skip_pending);
            if !settled {
                break;
            }
            target += 1;
        }
        if target > self.floor {
            out.push(self.emit_retire(target, lease, now));
        }
    }

    fn pending_for(&self, op_seq: u64) -> bool {
        self.pending.values().any(|p| p.op_seq == Some(op_seq))
    }

    /// A lane response's echoed lease and dispatch_seq must match the
    /// pending op's binding and the live lease — request-id correlation
    /// alone is not enough to trust a response.
    fn echo_matches(&self, op: &StoredOperation, lease: [u8; 16], dispatch_seq: u64) -> bool {
        self.lease == Some(lease)
            && op
                .dispatch
                .as_ref()
                .is_some_and(|a| a.lease == lease && a.dispatch_seq == dispatch_seq)
    }

    /// Divergent device evidence for an op: land it INDETERMINATE (unless
    /// a conclusion is already committed) — never a claimed outcome.
    fn mark_diverged<S: OperationStore>(&mut self, store: &mut S, op_seq: u64) {
        let _ = store.update_operation(op_seq, &mut |o| {
            if !o.concluded() {
                o.dispatch_state = DispatchState::Indeterminate;
            }
            true
        });
    }

    fn emit_lane(
        &mut self,
        sub: u8,
        op_seq: Option<u64>,
        seq: u64,
        lease: [u8; 16],
        kind: PendingKind,
        now: u64,
    ) -> DispatchRequest {
        let request = self.alloc_request();
        let body = host_ops::encode_lane_request(
            sub,
            &LaneRequest {
                lease: BootLease(lease),
                dispatcher: self.dispatcher_id,
                seq,
            },
        );
        self.pending.insert(
            request,
            Pending {
                op_seq,
                kind,
                sent_ms: now,
                through: 0,
            },
        );
        if let Some(op_seq) = op_seq {
            self.last_attempt.insert(op_seq, now);
        }
        DispatchRequest { request, body }
    }

    fn emit_retire(&mut self, through: u64, lease: [u8; 16], now: u64) -> DispatchRequest {
        let request = self.alloc_request();
        let body = host_ops::encode_lane_request(
            SUB_RETIRE_THROUGH,
            &LaneRequest {
                lease: BootLease(lease),
                dispatcher: self.dispatcher_id,
                seq: through,
            },
        );
        self.pending.insert(
            request,
            Pending {
                op_seq: None,
                kind: PendingKind::Retire,
                sent_ms: now,
                through,
            },
        );
        DispatchRequest { request, body }
    }

    fn maybe_sample(&mut self, lease: BootLease, now: u64, out: &mut Vec<DispatchRequest>) {
        if self.sample.is_some() {
            return;
        }
        self.next_nonce = self.next_nonce.wrapping_add(1).max(1);
        let nonce = self.next_nonce;
        let request = self.alloc_request();
        let body = host_ops::encode_time_sample_request(&TimeSampleRequest { lease, nonce });
        self.sample = Some(TimeSampleInFlight {
            request,
            nonce,
            h0: now,
        });
        out.push(DispatchRequest { request, body });
    }

    /// The outbound queue refused a frame — it provably never reached the
    /// writer. For SUBMITs that re-opens the not-sent proofs (submitted
    /// cleared); everything else simply re-issues on a later pass.
    pub fn emit_dropped<S: OperationStore>(&mut self, store: &mut S, request: u64) {
        if let Some(pending) = self.pending.remove(&request) {
            if pending.kind == PendingKind::Submit {
                if let Some(op_seq) = pending.op_seq {
                    let _ = store.update_operation(op_seq, &mut |o| {
                        if let Some(d) = o.dispatch.as_mut() {
                            d.submitted = false;
                        }
                        true
                    });
                }
            }
        }
        if self.sample.is_some_and(|s| s.request == request) {
            self.sample = None;
        }
    }

    /// One host-ops inner body from the inbox.
    pub fn handle_reply<S: OperationStore>(
        &mut self,
        store: &mut S,
        request: u64,
        inner: &[u8],
        now: u64,
    ) {
        if self.sample.is_some_and(|s| s.request == request) {
            self.on_time_sample(inner, now);
            return;
        }
        let Some(pending) = self.pending.remove(&request) else {
            self.note(format!("unmatched host-ops response request={request}"));
            return;
        };
        match pending.kind {
            PendingKind::Submit => match host_ops::decode_receipt(inner, host_ops::SUB_SUBMIT) {
                Ok(receipt) => {
                    self.on_submit_receipt(store, pending.op_seq.unwrap_or(0), &receipt, now)
                }
                Err(error) => self.note(format!("submit receipt undecodable: {error}")),
            },
            PendingKind::Query => match host_ops::decode_query_response(inner) {
                Ok(response) => {
                    self.on_query_response(store, pending.op_seq.unwrap_or(0), &response, now)
                }
                Err(error) => self.note(format!("query response undecodable: {error}")),
            },
            PendingKind::Skip => match host_ops::decode_receipt(inner, SUB_SKIP) {
                Ok(receipt) => {
                    self.on_skip_receipt(store, pending.op_seq.unwrap_or(0), &receipt, now)
                }
                Err(error) => self.note(format!("skip receipt undecodable: {error}")),
            },
            PendingKind::Retire => match host_ops::decode_retire_response(inner) {
                Ok(response) => self.on_retire_response(store, &response, pending.through),
                Err(error) => self.note(format!("retire response undecodable: {error}")),
            },
        }
    }

    /// SUBMIT receipt handling. Every branch either resolves the record or
    /// restores the provable-not-sent marker — ambiguity always lands in
    /// INDETERMINATE, never in a claimed outcome.
    fn on_submit_receipt<S: OperationStore>(
        &mut self,
        store: &mut S,
        op_seq: u64,
        receipt: &Receipt,
        now: u64,
    ) {
        let Ok(Some(op)) = store.get_by_seq(op_seq) else {
            self.note(format!("submit receipt for unknown op {op_seq}"));
            return;
        };
        if !self.echo_matches(&op, receipt.lease.0, receipt.dispatch_seq) {
            self.note(format!(
                "op {op_seq} submit receipt echoes a foreign binding"
            ));
            self.mark_diverged(store, op_seq);
            return;
        }
        match receipt.result {
            HostOpsResult::Ok | HostOpsResult::Existing => {
                // The device echoes the bound canonical hash; a mismatch
                // is a diverged position, not a state to adopt. (Lane
                // tombstones carry no hash to compare.)
                if !op.canonical.is_empty() && receipt.hash != op.hash {
                    self.note(format!("op {op_seq} submit receipt hash diverged"));
                    self.mark_diverged(store, op_seq);
                    return;
                }
                self.adopt_slot(
                    store,
                    op_seq,
                    receipt.state,
                    receipt.msg_valid,
                    receipt.msg_session,
                    receipt.msg_seq,
                    receipt.evidence,
                    now,
                )
            }
            // Terminal Expired at admission: provable never-sent.
            HostOpsResult::Expired => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    if o.concluded() {
                        if let Some(d) = o.dispatch.as_mut() {
                            d.device_terminal = true;
                        }
                        return true;
                    }
                    o.dispatch_state = DispatchState::ExpiredBeforeDispatch;
                    o.terminal_ms = Some(now);
                    if let Some(d) = o.dispatch.as_mut() {
                        d.device_terminal = true;
                        d.skip_pending = false;
                    }
                    true
                });
            }
            // The position is provably empty — retry (or cancel/expire)
            // stays honest.
            HostOpsResult::WindowFull
            | HostOpsResult::MeshRejected
            | HostOpsResult::NotRetained => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    if let Some(d) = o.dispatch.as_mut() {
                        d.submitted = false;
                    }
                    true
                });
            }
            // Divergence or a dead lease: the outcome can no longer be
            // proven either way.
            HostOpsResult::LeaseMismatch | HostOpsResult::Conflict => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    if !o.concluded() {
                        o.dispatch_state = DispatchState::Indeterminate;
                    }
                    true
                });
            }
            HostOpsResult::Retired => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    if let Some(d) = o.dispatch.as_mut() {
                        d.device_terminal = true;
                    }
                    if !o.concluded() {
                        o.dispatch_state = DispatchState::Indeterminate;
                    }
                    true
                });
            }
            // Proven pre-admission rejection — the record terminates
            // REJECTED_NOT_ACCEPTED and its hole still owes a SKIP.
            HostOpsResult::LaneMismatch
            | HostOpsResult::InvalidRequest
            | HostOpsResult::Unsupported => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    if !o.concluded() {
                        o.dispatch_state = DispatchState::RejectedNotAccepted;
                        o.terminal_ms = Some(now);
                    }
                    if let Some(d) = o.dispatch.as_mut() {
                        d.skip_pending = true;
                    }
                    true
                });
            }
            other => self.note(format!("unexpected submit result {other:?} op={op_seq}")),
        }
    }

    /// QUERY response handling: read-only adoption of the device's slot
    /// state — a QUERY never triggers resubmission by itself.
    fn on_query_response<S: OperationStore>(
        &mut self,
        store: &mut S,
        op_seq: u64,
        response: &QueryResponse,
        now: u64,
    ) {
        let Ok(Some(op)) = store.get_by_seq(op_seq) else {
            self.note(format!("query response for unknown op {op_seq}"));
            return;
        };
        if !self.echo_matches(&op, response.lease.0, response.dispatch_seq) {
            self.note(format!(
                "op {op_seq} query response echoes a foreign binding"
            ));
            self.mark_diverged(store, op_seq);
            return;
        }
        match response.result {
            HostOpsResult::Ok => {
                // Adopting a slot means trusting the echoed identity:
                // hash and operation id must be the ones we bound. (Lane
                // tombstones carry neither to compare.)
                let bound = op.canonical.is_empty()
                    || (response.hash == op.hash
                        && response.operation_id == op_id_bytes(&self.dispatcher_id, op.seq));
                if !bound {
                    self.note(format!("op {op_seq} query response identity diverged"));
                    self.mark_diverged(store, op_seq);
                    return;
                }
                self.adopt_slot(
                    store,
                    op_seq,
                    response.state,
                    response.msg_valid,
                    response.msg_session,
                    response.msg_seq,
                    response.evidence,
                    now,
                )
            }
            HostOpsResult::NotRetained => {
                // No record at the position under this lease: the SUBMIT
                // provably never landed (a torn USB frame cannot decode,
                // and FIFO ordering means any queued SUBMIT precedes this
                // query). Clearing `submitted` hands DISPATCH_PREPARED
                // records back to the resend path; an INDETERMINATE record
                // whose uncertainty is hereby resolved is restored to
                // DISPATCH_PREPARED too — this is not blind re-execution,
                // it is a re-emit of the still-bound seq after a proof of
                // emptiness.
                let _ = store.update_operation(op_seq, &mut |o| {
                    let concluded = o.concluded();
                    let Some(d) = o.dispatch.as_mut() else {
                        return false;
                    };
                    d.submitted = false;
                    if concluded {
                        // A late contradiction against a committed
                        // conclusion is logged, not rewritten — but the
                        // proven-empty position still owes a SKIP or the
                        // retire floor wedges behind the hole.
                        d.skip_pending = true;
                        return true;
                    }
                    match o.dispatch_state {
                        DispatchState::Indeterminate => {
                            o.dispatch_state = DispatchState::DispatchPrepared;
                        }
                        // A position we already advertised a stable
                        // MessageKey for cannot legitimately be empty —
                        // the device state diverged from our evidence.
                        DispatchState::GatewayAccepted => {
                            o.dispatch_state = DispatchState::Indeterminate;
                        }
                        _ => {}
                    }
                    true
                });
            }
            HostOpsResult::Retired => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    let Some(d) = o.dispatch.as_mut() else {
                        return false;
                    };
                    d.device_terminal = true;
                    if !o.concluded() {
                        o.dispatch_state = DispatchState::Indeterminate;
                    }
                    true
                });
            }
            HostOpsResult::LeaseMismatch
            | HostOpsResult::LaneMismatch
            | HostOpsResult::Conflict => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    if !o.concluded() {
                        o.dispatch_state = DispatchState::Indeterminate;
                    }
                    true
                });
            }
            // Transient or impossible here — the poll timer retries.
            _ => {}
        }
    }

    /// SKIP receipt handling.
    fn on_skip_receipt<S: OperationStore>(
        &mut self,
        store: &mut S,
        op_seq: u64,
        receipt: &Receipt,
        now: u64,
    ) {
        let Ok(Some(op)) = store.get_by_seq(op_seq) else {
            self.note(format!("skip receipt for unknown op {op_seq}"));
            return;
        };
        if !self.echo_matches(&op, receipt.lease.0, receipt.dispatch_seq) {
            self.note(format!("op {op_seq} skip receipt echoes a foreign binding"));
            self.mark_diverged(store, op_seq);
            return;
        }
        match receipt.result {
            HostOpsResult::Ok | HostOpsResult::Existing | HostOpsResult::Retired => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    let Some(d) = o.dispatch.as_mut() else {
                        return false;
                    };
                    d.skip_pending = false;
                    d.device_terminal = true;
                    true
                });
            }
            // Occupied: our "provable hole" was wrong — the cancelled or
            // expired claim cannot stand, so the record's latest conclusion
            // becomes INDETERMINATE rather than a false terminal proof.
            HostOpsResult::SkipRefused => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    o.dispatch_state = DispatchState::Indeterminate;
                    o.terminal_ms = None;
                    if let Some(d) = o.dispatch.as_mut() {
                        d.skip_pending = false;
                        // A lane tombstone has no conclusion to protect —
                        // re-arm `submitted` so the query pass resolves
                        // the occupied position instead of sitting dead.
                        if o.canonical.is_empty() {
                            d.submitted = true;
                        }
                    }
                    true
                });
                self.note(format!("op {op_seq} skip refused: position occupied"));
            }
            HostOpsResult::LeaseMismatch
            | HostOpsResult::LaneMismatch
            | HostOpsResult::InvalidRequest => {
                let _ = store.update_operation(op_seq, &mut |o| {
                    if !o.concluded() {
                        o.dispatch_state = DispatchState::Indeterminate;
                    }
                    true
                });
            }
            // WindowFull etc. — position not yet in window reach; retry.
            _ => {
                let _ = now;
            }
        }
    }

    /// RETIRE response: the floor advances to the reported value. A refusal
    /// means our terminality model disagreed with the device somewhere in
    /// the requested span — re-verify it by clearing the confirmed-terminal
    /// markers so the query pass re-learns them (positions nothing may
    /// have left re-prove via SKIP instead).
    fn on_retire_response<S: OperationStore>(
        &mut self,
        store: &mut S,
        response: &routeloom_protocol::host_ops::RetireResponse,
        through: u64,
    ) {
        if Some(response.lease.0) != self.lease {
            self.note("retire response under foreign lease".to_string());
            return;
        }
        match response.result {
            HostOpsResult::Ok => {
                self.floor = self.floor.max(response.retired_through);
            }
            HostOpsResult::RetireRefused => {
                self.note(format!(
                    "retire refused at through={} (requested {through})",
                    response.retired_through
                ));
                // The reported floor is authoritative here too — a lagging
                // view must not wedge the lane.
                self.floor = self.floor.max(response.retired_through);
                // The refused span is (floor, through]: the response's
                // retired_through is the device's CURRENT floor, not the
                // refused target. Records above the adopted floor get
                // their markers re-verified; ones the device retired get
                // skipped over.
                let lease = response.lease.0;
                if let Ok(ops) = store.dispatch_view() {
                    for op in ops {
                        let stale = op.dispatch.as_ref().is_some_and(|a| {
                            a.lease == lease
                                && a.device_terminal
                                && a.dispatch_seq > self.floor
                                && a.dispatch_seq <= through
                        });
                        if !stale {
                            continue;
                        }
                        let _ = store.update_operation(op.seq, &mut |o| {
                            if let Some(d) = o.dispatch.as_mut() {
                                d.device_terminal = false;
                                // The query pass only polls positions that
                                // may have left; a provably-unsent marker
                                // re-proves its hole via SKIP instead.
                                if !d.submitted {
                                    d.skip_pending = true;
                                }
                            }
                            true
                        });
                        self.last_attempt.remove(&op.seq);
                    }
                }
            }
            other => self.note(format!("retire result {other:?}")),
        }
    }

    /// TIME_SAMPLE response: bound to session lease + outstanding nonce.
    /// Stale, out-of-order or regressed samples are rejected — a clock
    /// regression invalidates the mapping rather than stretching it. A
    /// reply that fails binding does NOT consume the pending sample: the
    /// genuine response may still arrive, and the timeout path clears it.
    fn on_time_sample(&mut self, inner: &[u8], now: u64) {
        let Some(sample) = self.sample else {
            return;
        };
        let response = match host_ops::decode_time_sample_response(inner) {
            Ok(response) => response,
            Err(error) => {
                self.note(format!("time sample undecodable: {error}"));
                return;
            }
        };
        if response.nonce != sample.nonce {
            self.note("stale time sample nonce".to_string());
            return;
        }
        if response.result != HostOpsResult::Ok {
            self.note(format!("time sample refused: {:?}", response.result));
            return;
        }
        if Some(response.lease.0) != self.lease {
            self.note("time sample under foreign lease".to_string());
            return;
        }
        if self.mapping.is_some_and(|m| response.device_time < m.d) {
            self.clock_degraded = true;
            self.mapping = None;
            self.note("device clock regressed; mapping invalidated".to_string());
            return;
        }
        self.sample = None;
        self.mapping = Some(TimeMapping {
            d: response.device_time,
            h0: sample.h0,
            h1: now,
        });
    }

    /// Adopt the device's slot state (SUBMIT Ok/Existing and QUERY Ok share
    /// this map). Terminal slots close the position for retire purposes;
    /// concluded host records only merge late evidence, never reopen.
    #[allow(clippy::too_many_arguments)]
    fn adopt_slot<S: OperationStore>(
        &mut self,
        store: &mut S,
        op_seq: u64,
        state: SlotState,
        msg_valid: bool,
        msg_session: u32,
        msg_seq: u64,
        evidence: Evidence,
        now: u64,
    ) {
        let _ = store.update_operation(op_seq, &mut |o| {
            if o.dispatch.is_none() {
                return false;
            }
            // Snapshot the conclusion flag before borrowing the attachment:
            // o.concluded() would borrow all of `o` while `d` holds the
            // dispatch field. One arm runs per call, so a snapshot suffices.
            let concluded = o.concluded();
            let prepared = o.dispatch_state == DispatchState::DispatchPrepared;
            let d = o.dispatch.as_mut().expect("checked above");
            match state {
                SlotState::Empty => {
                    if concluded || o.canonical.is_empty() {
                        // The position is a hole under a committed
                        // conclusion (or a lane tombstone that can never
                        // be re-driven): it still owes a SKIP before the
                        // retire floor can pass.
                        d.skip_pending = true;
                    } else {
                        // Provably empty, same as a NotRetained result:
                        // reopen the not-sent proofs so the resend path
                        // (or cancel/expiry) stays honest.
                        d.submitted = false;
                        match o.dispatch_state {
                            DispatchState::Indeterminate => {
                                o.dispatch_state = DispatchState::DispatchPrepared;
                            }
                            // A position we already advertised a stable
                            // MessageKey for cannot legitimately be empty.
                            DispatchState::GatewayAccepted => {
                                o.dispatch_state = DispatchState::Indeterminate;
                            }
                            _ => {}
                        }
                    }
                }
                SlotState::Sent => {
                    if !concluded && prepared {
                        o.dispatch_state = DispatchState::GatewayAccepted;
                    }
                    d.ev_gateway_accepted = true;
                    if msg_valid {
                        d.msg_session = Some(msg_session);
                        d.msg_seq = Some(msg_seq);
                    }
                }
                SlotState::Delivered => {
                    // Delivered implies the gateway accepted the record —
                    // promote a still-prepared record before evidence.
                    if !concluded && prepared {
                        o.dispatch_state = DispatchState::GatewayAccepted;
                    }
                    d.ev_gateway_accepted = true;
                    if msg_valid {
                        d.msg_session = Some(msg_session);
                        d.msg_seq = Some(msg_seq);
                    }
                    match evidence {
                        Evidence::EndSdkReceived => {
                            d.ev_end_sdk = true;
                            if !concluded {
                                o.dispatch_state = DispatchState::EndSdkReceived;
                                o.terminal_ms = Some(now);
                            }
                        }
                        Evidence::MacAttemptReported => {
                            // Best-effort completion: terminal on the
                            // device, honest as MAC_ATTEMPT_REPORTED — no
                            // END_SDK promotion (03 §5). The record keeps
                            // GATEWAY_ACCEPTED but is concluded.
                            d.ev_mac_attempt = true;
                            if !concluded {
                                o.terminal_ms = Some(now);
                            }
                        }
                        _ => {
                            if !concluded {
                                o.dispatch_state = DispatchState::Indeterminate;
                            }
                        }
                    }
                    d.device_terminal = true;
                }
                SlotState::Failed | SlotState::Indeterminate => {
                    if !concluded {
                        o.dispatch_state = DispatchState::Indeterminate;
                    }
                    d.device_terminal = true;
                }
                SlotState::Expired => {
                    if !concluded {
                        // The device held the record past its deadline —
                        // even when our marker says provably-unsent, an
                        // expired slot is contradictory evidence:
                        // INDETERMINATE, never a claimed
                        // EXPIRED_BEFORE_DISPATCH.
                        o.dispatch_state = DispatchState::Indeterminate;
                    }
                    d.device_terminal = true;
                    d.skip_pending = false;
                }
                SlotState::Skipped => {
                    d.skip_pending = false;
                    d.device_terminal = true;
                    if !concluded {
                        o.dispatch_state = DispatchState::Indeterminate;
                    }
                }
            }
            true
        });
    }
}

/// OperationId wire form: store lineage(16) || seq(8), big-endian — the
/// same identity the API renders as `<lineage-hex>:<seq-hex>`. The
/// dispatcher_id IS the store lineage, so this binds the wire id to the
/// same identity the caller sees.
fn op_id_bytes(dispatcher_id: &[u8; 16], seq: u64) -> [u8; 24] {
    let mut id = [0u8; 24];
    id[..16].copy_from_slice(dispatcher_id);
    id[16..].copy_from_slice(&seq.to_be_bytes());
    id
}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut out = String::with_capacity(32);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// One dispatch pass against the shared daemon state: drain inbound
/// replies, run the tick, push the resulting frames at the writer queue.
/// Extracted from `dispatch_loop` so tests can drive it step by step.
pub fn dispatch_once(
    state: &State,
    outbound: &mpsc::SyncSender<Outbound>,
    dispatcher: &mut Dispatcher,
    now: u64,
) {
    let replies = state.dispatch_inbox.drain();
    let requests = {
        let mut store = state
            .operation_store
            .lock()
            .expect("operation store poisoned");
        for (request, body) in replies {
            dispatcher.handle_reply(&mut *store, request, &body, now);
        }
        dispatcher.tick(&mut *store, &link_snapshot(state), now)
    };
    for note in dispatcher.take_notes() {
        push_event(
            state,
            now,
            format!(
                "\"kind\":\"dispatch\",\"detail\":\"{}\"",
                json_escape(&note)
            ),
        );
    }
    for request in requests {
        let frame = Frame {
            kind: FrameKind::HostOps,
            flags: 0,
            session: 0,
            request: request.request,
            body: request.body,
        };
        match outbound.try_send(Outbound::Seal(frame)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                // Queue full: the frame never reached the writer — the
                // claim is provably void, so unclaim before the next pass.
                let mut store = state
                    .operation_store
                    .lock()
                    .expect("operation store poisoned");
                dispatcher.emit_dropped(&mut *store, request.request);
            }
            Err(mpsc::TrySendError::Disconnected(_)) => return,
        }
    }
}

/// The dispatch thread: keeps working through USB outages — records stay
/// queued while the link is down and host-side expiry still applies.
pub fn dispatch_loop(state: Arc<State>, outbound: mpsc::SyncSender<Outbound>) {
    let dispatcher_id = state
        .operation_store
        .lock()
        .expect("operation store poisoned")
        .lineage();
    let mut dispatcher = Dispatcher::new(dispatcher_id);
    loop {
        dispatch_once(&state, &outbound, &mut dispatcher, now_ms());
        state.dispatch_inbox.wait(Duration::from_millis(TICK_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{self, SendRequest};
    use crate::send_store::{CancelOutcome, MemoryOperationStore, SubmitOutcome};
    use routeloom_protocol::host_ops::{
        decode_lane_request, decode_submit, decode_time_sample_request, encode_query_response,
        encode_receipt, encode_retire_response, encode_time_sample_response, RetireResponse,
        TimeSampleResponse,
    };

    const UID: u32 = 501;
    const NET: u64 = 1;
    const NODE: u64 = 0x0abc;
    const BOOT: u64 = 7;

    fn link() -> LinkSnapshot {
        LinkSnapshot {
            active: true,
            host_ops: true,
            node: NODE,
            boot: BOOT,
            network: NET,
        }
    }

    fn offline() -> LinkSnapshot {
        LinkSnapshot {
            active: false,
            host_ops: false,
            node: 0,
            boot: 0,
            network: 0,
        }
    }

    fn lease() -> [u8; 16] {
        BootLease::derive(BOOT, NODE).0
    }

    fn request(key: u8, ttl: u32) -> SendRequest {
        let payload = vec![key, 0x55];
        let canonical = canonical::canonical_bytes(
            NET as u32,
            canonical::DEST_NODE,
            3,
            canonical::DELIVERY_RELIABLE,
            canonical::PRIORITY_NORMAL,
            canonical::STORAGE_RAM,
            ttl,
            canonical::HOP_DEFAULT,
            &payload,
        );
        SendRequest {
            network: NET,
            epoch: 1,
            key: [key; 16],
            dest_kind: canonical::DEST_NODE,
            dest: 3,
            delivery: canonical::DELIVERY_RELIABLE,
            priority: canonical::PRIORITY_NORMAL,
            ttl_ms: ttl,
            storage: canonical::STORAGE_RAM,
            hop_limit: canonical::HOP_DEFAULT,
            payload,
            hash: canonical::sha256(&canonical),
            canonical,
        }
    }

    fn admitted(store: &mut MemoryOperationStore, key: u8, ttl: u32, now: u64) -> u64 {
        store.open_epoch((UID, NET), now).unwrap();
        match store.submit(UID, &request(key, ttl), now) {
            SubmitOutcome::Accepted { seq } => seq,
            _ => panic!("submit failed"),
        }
    }

    fn op(store: &MemoryOperationStore, seq: u64) -> StoredOperation {
        store.get_by_seq(seq).unwrap().expect("record")
    }

    /// The echoed hash must be the record's canonical hash on adopt
    /// (Ok/Existing) paths; results that never adopt may pass [0; 32].
    fn receipt(
        sub: u8,
        result: HostOpsResult,
        state: SlotState,
        dispatch_seq: u64,
        evidence: Evidence,
        hash: [u8; 32],
    ) -> Vec<u8> {
        encode_receipt(&Receipt {
            sub,
            result,
            state,
            lease: BootLease(lease()),
            dispatch_seq,
            hash,
            msg_session: 9,
            msg_seq: 77,
            msg_valid: true,
            evidence,
        })
    }

    /// Same for QUERY responses: hash + operation id are verified on Ok.
    fn query_response(
        result: HostOpsResult,
        state: SlotState,
        dispatch_seq: u64,
        evidence: Evidence,
        hash: [u8; 32],
        operation_id: [u8; 24],
    ) -> Vec<u8> {
        encode_query_response(&QueryResponse {
            result,
            state,
            lease: BootLease(lease()),
            dispatch_seq,
            hash,
            operation_id,
            msg_session: 9,
            msg_seq: 77,
            msg_valid: true,
            evidence,
        })
    }

    fn retire_response(result: HostOpsResult, through: u64) -> Vec<u8> {
        encode_retire_response(&RetireResponse {
            result,
            lease: BootLease(lease()),
            retired_through: through,
        })
    }

    fn time_sample(nonce: u64, device_time: u64) -> Vec<u8> {
        encode_time_sample_response(&TimeSampleResponse {
            result: HostOpsResult::Ok,
            lease: BootLease(lease()),
            nonce,
            device_time,
        })
    }

    fn sub_of(request: &DispatchRequest) -> u8 {
        request.body[1]
    }

    /// Drive a record all the way to "SUBMIT emitted": link up, floor probe
    /// answered, time sample answered, then the dispatch pass emits SUBMIT.
    /// Returns the emitted SUBMIT request (and asserts the shape).
    fn drive_to_submit(
        dispatcher: &mut Dispatcher,
        store: &mut MemoryOperationStore,
        now: u64,
    ) -> DispatchRequest {
        let mut now = now;
        // Pass 1: lease change emits the floor probe; no mapping yet, so the
        // queued op triggers a TIME_SAMPLE instead of a SUBMIT.
        let out = dispatcher.tick(store, &link(), now);
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("floor probe");
        let sample = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_TIME_SAMPLE)
            .expect("time sample");
        let retire_req = retire.request;
        let sample_req = sample.request;
        let nonce = decode_time_sample_request(&sample.body).unwrap().nonce;
        now += 5;
        dispatcher.handle_reply(
            store,
            retire_req,
            &retire_response(HostOpsResult::Ok, 0),
            now,
        );
        dispatcher.handle_reply(store, sample_req, &time_sample(nonce, 42_000), now);
        // Pass 2: mapping in hand → SUBMIT.
        now += 5;
        let out = dispatcher.tick(store, &link(), now);
        out.into_iter()
            .find(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .expect("submit emitted")
    }

    #[test]
    fn deadline_reference_vectors() {
        // Cases transcribed from
        // docs/design/host-security-readiness/review-addendum/deadline-vectors.json.
        struct Case {
            h: u64,
            ttl: u32,
            h0: u64,
            h1: u64,
            host_now: u64,
            d: u64,
            device_now: u64,
            clock_valid: bool,
            expected: DeadlineDecision,
        }
        let cases = [
            Case {
                h: 1000,
                ttl: 5000,
                h0: 1100,
                h1: 1110,
                host_now: 1120,
                d: 2000,
                device_now: 2020,
                clock_valid: true,
                expected: DeadlineDecision::Ready(6884),
            },
            Case {
                h: 0,
                ttl: 1,
                h0: 0,
                h1: 0,
                host_now: 0,
                d: 0,
                device_now: 0,
                clock_valid: true,
                expected: DeadlineDecision::ExpiredBudget,
            },
            Case {
                h: 0,
                ttl: 2,
                h0: 0,
                h1: 0,
                host_now: 0,
                d: 0,
                device_now: 0,
                clock_valid: true,
                expected: DeadlineDecision::ExpiredBudget,
            },
            Case {
                h: 0,
                ttl: 3,
                h0: 0,
                h1: 0,
                host_now: 0,
                d: 0,
                device_now: 0,
                clock_valid: true,
                expected: DeadlineDecision::Ready(1),
            },
            Case {
                h: 0,
                ttl: 5000,
                h0: 0,
                h1: 0,
                host_now: 0,
                d: 0,
                device_now: 0,
                clock_valid: true,
                expected: DeadlineDecision::Ready(4994),
            },
            Case {
                h: 1000,
                ttl: 5000,
                h0: 1100,
                h1: 1110,
                host_now: 6000,
                d: 2000,
                device_now: 2020,
                clock_valid: true,
                expected: DeadlineDecision::ExpiredBudget,
            },
            Case {
                h: 1000,
                ttl: 5000,
                h0: 1100,
                h1: 1110,
                host_now: 1120,
                d: 2000,
                device_now: 6884,
                clock_valid: true,
                expected: DeadlineDecision::ExpiredBudget,
            },
            Case {
                h: 1000,
                ttl: 5000,
                h0: 1100,
                h1: 1110,
                host_now: 1120,
                d: 2000,
                device_now: 2020,
                clock_valid: false,
                expected: DeadlineDecision::TimeUncertain,
            },
            Case {
                h: 1000,
                ttl: 5000,
                h0: 1111,
                h1: 1110,
                host_now: 1120,
                d: 2000,
                device_now: 2020,
                clock_valid: true,
                expected: DeadlineDecision::TimeUncertain,
            },
            Case {
                h: 0,
                ttl: 30000,
                h0: 0,
                h1: 1,
                host_now: 5001,
                d: 0,
                device_now: 5001,
                clock_valid: true,
                expected: DeadlineDecision::TimeUncertain,
            },
            Case {
                h: 18_446_744_073_709_551_605,
                ttl: 11,
                h0: 18_446_744_073_709_551_605,
                h1: 18_446_744_073_709_551_605,
                host_now: 18_446_744_073_709_551_605,
                d: 2000,
                device_now: 2020,
                clock_valid: true,
                expected: DeadlineDecision::ArithmeticOverflow,
            },
            Case {
                h: 1000,
                ttl: 5000,
                h0: 1100,
                h1: 1110,
                host_now: 1120,
                d: 18_446_744_073_709_551_613,
                device_now: 18_446_744_073_709_551_613,
                clock_valid: true,
                expected: DeadlineDecision::ArithmeticOverflow,
            },
            Case {
                h: 1000,
                ttl: 5000,
                h0: 1100,
                h1: 1110,
                host_now: 1120,
                d: 18_446_744_073_709_546_731,
                device_now: 18_446_744_073_709_546_731,
                clock_valid: true,
                expected: DeadlineDecision::Ready(u64::MAX),
            },
            Case {
                h: 1000,
                ttl: 5000,
                h0: 1100,
                h1: 1110,
                host_now: 1120,
                d: 2000,
                device_now: 1999,
                clock_valid: true,
                expected: DeadlineDecision::TimeUncertain,
            },
        ];
        assert_eq!(cases.len(), 14, "one case per reference vector");
        for case in &cases {
            let mapping = case.clock_valid.then_some(TimeMapping {
                d: case.d,
                h0: case.h0,
                h1: case.h1,
            });
            let got = deadline_decision(case.h, case.ttl, mapping, case.device_now, case.host_now);
            assert_eq!(got, case.expected, "case h={} ttl={}", case.h, case.ttl);
        }
    }

    #[test]
    fn golden_path_submit_to_retire() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let now = 1_000;
        let seq = admitted(&mut store, 0x11, 30_000, now);
        let submit = drive_to_submit(&mut dispatcher, &mut store, now);
        let body = decode_submit(&submit.body).unwrap();
        assert_eq!(body.lease.0, lease());
        assert_eq!(body.dispatch_seq, 1);
        assert_eq!(body.operation_id, op_id_bytes(&[7; 16], seq));
        // The device deadline is the host deadline mapped conservatively:
        // D=31000, h0=1000, h1=1005 → remaining 29995, span 30000,
        // margin 31 → safe 29964 → d(42000)+29964.
        assert_eq!(body.device_deadline, 71_964);
        let record = op(&store, seq);
        assert_eq!(record.dispatch_state, DispatchState::DispatchPrepared);
        assert!(record.dispatch.as_ref().unwrap().submitted);

        // Receipt: position recorded as Sent → GATEWAY_ACCEPTED + key.
        let hash = op(&store, seq).hash;
        dispatcher.handle_reply(
            &mut store,
            submit.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Sent,
                1,
                Evidence::GatewayAccepted,
                hash,
            ),
            now + 20,
        );
        let record = op(&store, seq);
        assert_eq!(record.dispatch_state, DispatchState::GatewayAccepted);
        let att = record.dispatch.unwrap();
        assert_eq!(att.msg_session, Some(9));
        assert_eq!(att.msg_seq, Some(77));
        assert!(att.ev_gateway_accepted);

        // Live accepted positions are polled with QUERY_DISPATCH.
        let out = dispatcher.tick(&mut store, &link(), now + 20 + QUERY_INTERVAL_MS);
        let query = out
            .iter()
            .find(|r| sub_of(r) == SUB_QUERY_DISPATCH)
            .expect("query for live position");
        dispatcher.handle_reply(
            &mut store,
            query.request,
            &query_response(
                HostOpsResult::Ok,
                SlotState::Delivered,
                1,
                Evidence::EndSdkReceived,
                hash,
                op_id_bytes(&[7; 16], seq),
            ),
            now + 20 + QUERY_INTERVAL_MS + 5,
        );
        let record = op(&store, seq);
        assert_eq!(record.dispatch_state, DispatchState::EndSdkReceived);
        assert!(record.concluded());
        assert!(record.dispatch.as_ref().unwrap().device_terminal);
        assert!(record.dispatch.as_ref().unwrap().ev_end_sdk);

        // Device-terminal prefix → RETIRE_THROUGH.
        let out = dispatcher.tick(&mut store, &link(), now + 700);
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("retire after terminal prefix");
        assert_eq!(
            decode_lane_request(&retire.body, SUB_RETIRE_THROUGH)
                .unwrap()
                .seq,
            1
        );
        dispatcher.handle_reply(
            &mut store,
            retire.request,
            &retire_response(HostOpsResult::Ok, 1),
            now + 710,
        );
        assert_eq!(dispatcher.floor, 1);
    }

    #[test]
    fn best_effort_mac_attempt_is_not_end_sdk() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0x22, 30_000, 1_000);
        let submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        // Best-effort completion: Delivered + MAC_ATTEMPT_REPORTED keeps
        // GATEWAY_ACCEPTED and never promotes to END_SDK_RECEIVED.
        let hash = op(&store, seq).hash;
        dispatcher.handle_reply(
            &mut store,
            submit.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Delivered,
                1,
                Evidence::MacAttemptReported,
                hash,
            ),
            1_050,
        );
        let record = op(&store, seq);
        assert_eq!(record.dispatch_state, DispatchState::GatewayAccepted);
        assert!(record.concluded(), "device-terminal record concludes");
        let att = record.dispatch.unwrap();
        assert!(att.ev_mac_attempt);
        assert!(!att.ev_end_sdk);
        assert!(att.device_terminal);
    }

    #[test]
    fn lost_receipt_recovered_by_query() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0x33, 30_000, 1_000);
        let submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        let dispatch_seq = decode_submit(&submit.body).unwrap().dispatch_seq;
        // Receipt never arrives; pending times out and the query pass
        // picks the still-live position up.
        let out = dispatcher.tick(&mut store, &link(), 1_000 + RESPONSE_TIMEOUT_MS + 100);
        let query = out
            .iter()
            .find(|r| sub_of(r) == SUB_QUERY_DISPATCH)
            .expect("query after pending timeout");
        let hash = op(&store, seq).hash;
        dispatcher.handle_reply(
            &mut store,
            query.request,
            &query_response(
                HostOpsResult::Ok,
                SlotState::Sent,
                dispatch_seq,
                Evidence::GatewayAccepted,
                hash,
                op_id_bytes(&[7; 16], seq),
            ),
            1_000 + RESPONSE_TIMEOUT_MS + 110,
        );
        assert_eq!(
            op(&store, seq).dispatch_state,
            DispatchState::GatewayAccepted
        );
    }

    #[test]
    fn not_retained_redrives_same_dispatch_seq() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0x44, 30_000, 1_000);
        let submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        let first_seq = decode_submit(&submit.body).unwrap().dispatch_seq;
        // Receipt says the position was never recorded: the write provably
        // never landed, so the record re-drives the SAME bound seq.
        dispatcher.handle_reply(
            &mut store,
            submit.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::NotRetained,
                SlotState::Empty,
                first_seq,
                Evidence::None,
                [0; 32],
            ),
            1_050,
        );
        let record = op(&store, seq);
        assert_eq!(record.dispatch_state, DispatchState::DispatchPrepared);
        assert!(!record.dispatch.as_ref().unwrap().submitted);
        // The resend is throttled to the poll cadence — no churn at
        // round-trip rate — but re-drives the SAME bound seq.
        let out = dispatcher.tick(&mut store, &link(), 1_060);
        assert!(
            !out.iter().any(|r| sub_of(r) == host_ops::SUB_SUBMIT),
            "resubmit is paced, not instant"
        );
        let out = dispatcher.tick(&mut store, &link(), 1_020 + QUERY_INTERVAL_MS);
        let resubmit = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .expect("re-emit after NotRetained");
        let body = decode_submit(&resubmit.body).unwrap();
        assert_eq!(
            body.dispatch_seq, first_seq,
            "re-drive reuses the bound seq"
        );
    }

    #[test]
    fn cancel_boundaries() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        // Queued, never prepared: cancellable, no attachment needed.
        let a = admitted(&mut store, 0x51, 30_000, 1_000);
        assert_eq!(
            store.cancel_operation(a, 1_010).unwrap(),
            CancelOutcome::Cancelled
        );
        assert_eq!(
            op(&store, a).dispatch_state,
            DispatchState::CancelledBeforeDispatch
        );
        // Prepared but never submitted: still provably unsent → cancelled
        // and the allocated position is owed a SKIP.
        let b = admitted(&mut store, 0x52, 30_000, 1_000);
        assert!(matches!(
            store.prepare_dispatch(b, lease(), [7; 16]).unwrap(),
            PrepareOutcome::Prepared(_)
        ));
        assert_eq!(
            store.cancel_operation(b, 1_020).unwrap(),
            CancelOutcome::Cancelled
        );
        let record = op(&store, b);
        assert_eq!(
            record.dispatch_state,
            DispatchState::CancelledBeforeDispatch
        );
        assert!(record.dispatch.as_ref().unwrap().skip_pending);
        // The hole is skipped so the retire prefix can pass. The first
        // pass brings the lease up (floor probe) AND owes the SKIP
        // immediately — the skip pass needs no clock.
        let out = dispatcher.tick(&mut store, &link(), 1_100);
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("floor probe");
        let retire_req = retire.request;
        let skip = out
            .iter()
            .find(|r| sub_of(r) == SUB_SKIP)
            .expect("skip owed to the cancelled position");
        let skip_seq = decode_lane_request(&skip.body, SUB_SKIP).unwrap().seq;
        let skip_req = skip.request;
        assert_eq!(skip_seq, 1, "first prepared position is the hole");
        dispatcher.handle_reply(
            &mut store,
            retire_req,
            &retire_response(HostOpsResult::Ok, 0),
            1_105,
        );
        dispatcher.handle_reply(
            &mut store,
            skip_req,
            &receipt(
                SUB_SKIP,
                HostOpsResult::Ok,
                SlotState::Skipped,
                skip_seq,
                Evidence::None,
                [0; 32],
            ),
            1_120,
        );
        dispatcher.handle_reply(
            &mut store,
            skip.request,
            &receipt(
                SUB_SKIP,
                HostOpsResult::Ok,
                SlotState::Skipped,
                skip_seq,
                Evidence::None,
                [0; 32],
            ),
            1_120,
        );
        assert!(op(&store, b).dispatch.as_ref().unwrap().device_terminal);
        // After a SUBMIT may have left, cancel is too late but observed.
        let c = admitted(&mut store, 0x53, 30_000, 1_140);
        let _submit = drive_to_submit(&mut dispatcher, &mut store, 1_150);
        match store.cancel_operation(c, 1_160).unwrap() {
            CancelOutcome::TooLate(state) => {
                assert_eq!(state, DispatchState::DispatchPrepared)
            }
            other => panic!("expected TooLate, got {other:?}"),
        }
        let record = op(&store, c);
        assert_eq!(record.dispatch_state, DispatchState::DispatchPrepared);
        assert!(record.dispatch.as_ref().unwrap().cancel_requested);
    }

    #[test]
    fn emit_dropped_reopens_cancel() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0x61, 30_000, 1_000);
        let submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        // The outbound queue refused the frame: provably never sent.
        dispatcher.emit_dropped(&mut store, submit.request);
        let record = op(&store, seq);
        assert!(!record.dispatch.as_ref().unwrap().submitted);
        assert_eq!(
            store.cancel_operation(seq, 1_010).unwrap(),
            CancelOutcome::Cancelled,
            "a frame that never reached the writer is still cancellable"
        );
    }

    #[test]
    fn expiry_sweeps_without_link() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        // Queued record outlives its deadline while USB is absent.
        let a = admitted(&mut store, 0x71, 1_000, 1_000);
        dispatcher.tick(&mut store, &offline(), 2_500);
        assert_eq!(
            op(&store, a).dispatch_state,
            DispatchState::ExpiredBeforeDispatch
        );
        // Prepared-but-never-submitted record expires provably too and owes
        // a SKIP for its allocated position.
        let b = admitted(&mut store, 0x72, 1_000, 1_000);
        store.prepare_dispatch(b, lease(), [7; 16]).unwrap();
        dispatcher.tick(&mut store, &offline(), 2_500);
        let record = op(&store, b);
        assert_eq!(record.dispatch_state, DispatchState::ExpiredBeforeDispatch);
        assert!(record.dispatch.as_ref().unwrap().skip_pending);
    }

    #[test]
    fn no_link_means_no_frames_and_honest_queueing() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0x81, 30_000, 1_000);
        let out = dispatcher.tick(&mut store, &offline(), 1_010);
        assert!(out.is_empty(), "no USB, no wire traffic");
        assert_eq!(op(&store, seq).dispatch_state, DispatchState::HostQueued);
    }

    #[test]
    fn lease_change_respects_submitted_flag() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let submitted_op = admitted(&mut store, 0x91, 30_000, 1_000);
        let _submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        // Admitted after the first SUBMIT and prepared under the same
        // lease — but never claimed toward the writer.
        let unsent_op = admitted(&mut store, 0x92, 30_000, 1_010);
        store.prepare_dispatch(unsent_op, lease(), [7; 16]).unwrap();
        // Reconnect to a different boot: the old lane is dead, and the
        // same pass needs a fresh clock mapping for the requeued op.
        let new_link = LinkSnapshot {
            boot: BOOT + 1,
            ..link()
        };
        let out = dispatcher.tick(&mut store, &new_link, 2_000);
        let _sample = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_TIME_SAMPLE)
            .expect("fresh mapping needed for the new lease");
        assert_eq!(
            op(&store, submitted_op).dispatch_state,
            DispatchState::Indeterminate,
            "a SUBMIT that may have left is never re-executed"
        );
        let requeued = op(&store, unsent_op);
        assert_eq!(
            requeued.dispatch_state,
            DispatchState::HostQueued,
            "provably-never-sent is requeued, not stranded"
        );
        assert!(requeued.dispatch.is_none());
    }

    #[test]
    fn time_sample_nonce_and_lease_binding() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        admitted(&mut store, 0xa1, 30_000, 1_000);
        let out = dispatcher.tick(&mut store, &link(), 1_010);
        let sample = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_TIME_SAMPLE)
            .expect("sample request");
        let nonce = decode_time_sample_request(&sample.body).unwrap().nonce;
        // Wrong nonce is ignored; mapping stays unset.
        dispatcher.handle_reply(
            &mut store,
            sample.request,
            &time_sample(nonce + 1, 5_000),
            1_020,
        );
        assert!(dispatcher.mapping.is_none());
        // Right nonce under a foreign lease is ignored too.
        let foreign = encode_time_sample_response(&TimeSampleResponse {
            result: HostOpsResult::Ok,
            lease: BootLease::derive(BOOT + 9, NODE),
            nonce,
            device_time: 5_000,
        });
        dispatcher.handle_reply(&mut store, sample.request, &foreign, 1_020);
        assert!(dispatcher.mapping.is_none());
        // A clock regression invalidates the mapping and marks the lane.
        dispatcher.handle_reply(
            &mut store,
            sample.request,
            &time_sample(nonce, 5_000),
            1_020,
        );
        assert!(dispatcher.mapping.is_some());
        // The valid mapping lets the queued op SUBMIT on the next pass…
        let out = dispatcher.tick(&mut store, &link(), 1_030);
        assert!(out.iter().any(|r| sub_of(r) == host_ops::SUB_SUBMIT));
        // …and once the mapping ages out, a newly queued op's dispatch
        // attempt needs a fresh sample — which regresses and invalidates
        // the lane's clock.
        admitted(&mut store, 0xa2, 30_000, 6_000);
        let out = dispatcher.tick(&mut store, &link(), 1_010 + TIME_SAMPLE_MAX_AGE_MS + 1);
        let sample2 = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_TIME_SAMPLE)
            .expect("resample after mapping ages out");
        let nonce2 = decode_time_sample_request(&sample2.body).unwrap().nonce;
        dispatcher.handle_reply(
            &mut store,
            sample2.request,
            &time_sample(nonce2, 4_000),
            1_012 + TIME_SAMPLE_MAX_AGE_MS,
        );
        assert!(dispatcher.mapping.is_none(), "regression invalidates");
        assert!(dispatcher.clock_degraded);
    }

    #[test]
    fn retire_respects_contiguous_terminal_prefix() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let first = admitted(&mut store, 0xb1, 30_000, 1_000);
        // Drive the first op to SUBMIT (seq 1); the second is admitted
        // only after, so it takes seq 2 on a later pass.
        let s1 = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        let hash1 = op(&store, first).hash;
        dispatcher.handle_reply(
            &mut store,
            s1.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Sent,
                1,
                Evidence::GatewayAccepted,
                hash1,
            ),
            1_050,
        );
        let second = admitted(&mut store, 0xb2, 30_000, 1_055);
        let out = dispatcher.tick(&mut store, &link(), 1_060);
        let s2 = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .expect("second submit");
        assert_eq!(decode_submit(&s2.body).unwrap().dispatch_seq, 2);
        // Complete seq 2 while seq 1 is still live: the floor must NOT pass 1.
        let hash2 = op(&store, second).hash;
        dispatcher.handle_reply(
            &mut store,
            s2.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Delivered,
                2,
                Evidence::EndSdkReceived,
                hash2,
            ),
            1_070,
        );
        let out = dispatcher.tick(&mut store, &link(), 1_080);
        assert!(
            !out.iter().any(|r| sub_of(r) == SUB_RETIRE_THROUGH),
            "retire must not skip the live position 1"
        );
        // Resolve seq 1 → contiguous prefix advances to 2.
        let out = dispatcher.tick(&mut store, &link(), 1_080 + QUERY_INTERVAL_MS + 10);
        let q1 = out
            .iter()
            .find(|r| sub_of(r) == SUB_QUERY_DISPATCH)
            .expect("query for op 1");
        dispatcher.handle_reply(
            &mut store,
            q1.request,
            &query_response(
                HostOpsResult::Ok,
                SlotState::Delivered,
                1,
                Evidence::EndSdkReceived,
                hash1,
                op_id_bytes(&[7; 16], first),
            ),
            1_400,
        );
        let out = dispatcher.tick(&mut store, &link(), 1_410);
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("prefix now contiguous to 2");
        assert_eq!(
            decode_lane_request(&retire.body, SUB_RETIRE_THROUGH)
                .unwrap()
                .seq,
            2
        );
        assert_eq!(
            op(&store, first).dispatch_state,
            DispatchState::EndSdkReceived
        );
        assert_eq!(
            op(&store, second).dispatch_state,
            DispatchState::EndSdkReceived
        );
    }

    #[test]
    fn window_cap_limits_preparation() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        for key in 0..40u8 {
            admitted(&mut store, key, 30_000, 1_000);
        }
        // Learn the floor without consuming the pass's dispatch budget.
        let out = dispatcher.tick(&mut store, &link(), 1_010);
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .unwrap();
        let sample = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_TIME_SAMPLE)
            .unwrap();
        let retire_req = retire.request;
        let sample_req = sample.request;
        let nonce = decode_time_sample_request(&sample.body).unwrap().nonce;
        dispatcher.handle_reply(
            &mut store,
            retire_req,
            &retire_response(HostOpsResult::Ok, 0),
            1_020,
        );
        dispatcher.handle_reply(&mut store, sample_req, &time_sample(nonce, 9_000), 1_020);
        let out = dispatcher.tick(&mut store, &link(), 1_030);
        let submits = out
            .iter()
            .filter(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .count();
        assert_eq!(submits as u64, DISPATCH_WINDOW, "window caps new positions");
    }

    #[test]
    fn network_mismatch_stays_queued() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0xc1, 30_000, 1_000);
        let wrong_net = LinkSnapshot {
            network: NET + 9,
            ..link()
        };
        let mut now = 1_000;
        // Drain any sample/retire traffic for a few passes; the op must
        // never produce a SUBMIT on the wrong network.
        for _ in 0..4 {
            let out = dispatcher.tick(&mut store, &wrong_net, now);
            assert!(
                !out.iter().any(|r| sub_of(r) == host_ops::SUB_SUBMIT),
                "canonical network mismatch must not dispatch"
            );
            // Answer the sample so the pass isn't gated on the mapping.
            if let Some(sample) = out.iter().find(|r| sub_of(r) == host_ops::SUB_TIME_SAMPLE) {
                let nonce = decode_time_sample_request(&sample.body).unwrap().nonce;
                dispatcher.handle_reply(
                    &mut store,
                    sample.request,
                    &time_sample(nonce, 5_000),
                    now + 5,
                );
            }
            now += 50;
        }
        assert_eq!(op(&store, seq).dispatch_state, DispatchState::HostQueued);
    }

    #[test]
    fn submit_receipt_conflict_is_indeterminate() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0xd1, 30_000, 1_000);
        let submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        dispatcher.handle_reply(
            &mut store,
            submit.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Conflict,
                SlotState::Sent,
                1,
                Evidence::None,
                [0; 32],
            ),
            1_050,
        );
        // The position holds different bytes: our submission provably never
        // landed, but the store keeps INDETERMINATE — an anomaly to
        // investigate, never a silent overwrite or a claimed rejection.
        assert_eq!(op(&store, seq).dispatch_state, DispatchState::Indeterminate);
    }

    /// A refused RETIRE must not deadlock the floor: the requested span's
    /// confirmed-terminal markers are cleared and re-verified by QUERY,
    /// so the next attempt makes progress instead of retrying the
    /// identical request forever.
    #[test]
    fn retire_refused_recovers_floor() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0xe1, 30_000, 1_000);
        let submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        let hash = op(&store, seq).hash;
        dispatcher.handle_reply(
            &mut store,
            submit.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Delivered,
                1,
                Evidence::EndSdkReceived,
                hash,
            ),
            1_050,
        );
        assert!(op(&store, seq).dispatch.as_ref().unwrap().device_terminal);
        let out = dispatcher.tick(&mut store, &link(), 1_060);
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("retire over the terminal prefix");
        assert_eq!(
            decode_lane_request(&retire.body, SUB_RETIRE_THROUGH)
                .unwrap()
                .seq,
            1
        );
        // Refused: the requested target is what gets re-verified — not
        // the device's current floor — and the reported floor is adopted.
        dispatcher.handle_reply(
            &mut store,
            retire.request,
            &retire_response(HostOpsResult::RetireRefused, 0),
            1_070,
        );
        assert!(
            !op(&store, seq).dispatch.as_ref().unwrap().device_terminal,
            "the marker in the refused span is cleared for re-verification"
        );
        // The query pass re-verifies even the concluded record's position.
        let out = dispatcher.tick(&mut store, &link(), 1_080);
        let query = out
            .iter()
            .find(|r| sub_of(r) == SUB_QUERY_DISPATCH)
            .expect("concluded position re-polls after refusal");
        dispatcher.handle_reply(
            &mut store,
            query.request,
            &query_response(
                HostOpsResult::Ok,
                SlotState::Delivered,
                1,
                Evidence::EndSdkReceived,
                hash,
                op_id_bytes(&[7; 16], seq),
            ),
            1_090,
        );
        assert!(op(&store, seq).dispatch.as_ref().unwrap().device_terminal);
        // Re-marked: the floor retires through the position next pass.
        let out = dispatcher.tick(&mut store, &link(), 1_100);
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("retire retried after re-verification");
        dispatcher.handle_reply(
            &mut store,
            retire.request,
            &retire_response(HostOpsResult::Ok, 1),
            1_110,
        );
        assert_eq!(dispatcher.floor, 1);
    }

    /// TIME_UNCERTAIN only wraps the pre-rewind state: provably-unsent
    /// records still expire and cancel honestly through it.
    #[test]
    fn time_uncertain_expires_and_cancels() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        // A record parked by a clock rewind cancels like a queued one.
        let a = admitted(&mut store, 0xe2, 30_000, 1_000);
        dispatcher.tick(&mut store, &link(), 500);
        assert_eq!(op(&store, a).dispatch_state, DispatchState::TimeUncertain);
        assert_eq!(
            store.cancel_operation(a, 600).unwrap(),
            CancelOutcome::Cancelled,
            "provably-unsent cancels through the TIME_UNCERTAIN wrapper"
        );
        // And one parked past its deadline expires provably-unsent too.
        let b = admitted(&mut store, 0xe3, 1_000, 1_000);
        dispatcher.tick(&mut store, &link(), 500);
        assert_eq!(op(&store, b).dispatch_state, DispatchState::TimeUncertain);
        dispatcher.tick(&mut store, &offline(), 2_500);
        assert_eq!(
            op(&store, b).dispatch_state,
            DispatchState::ExpiredBeforeDispatch
        );
    }

    /// Echoed lease/dispatch_seq/hash on a correlated response must match
    /// the pending binding — a mismatch is divergence, not adoption.
    #[test]
    fn receipt_field_mismatch_is_indeterminate() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        // Wrong dispatch_seq echo.
        let a = admitted(&mut store, 0xf1, 30_000, 1_000);
        let s1 = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        let hash_a = op(&store, a).hash;
        dispatcher.handle_reply(
            &mut store,
            s1.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Sent,
                2,
                Evidence::GatewayAccepted,
                hash_a,
            ),
            1_050,
        );
        assert_eq!(op(&store, a).dispatch_state, DispatchState::Indeterminate);
        // Right seq, wrong canonical hash.
        let b = admitted(&mut store, 0xf2, 30_000, 1_000);
        store.prepare_dispatch(b, lease(), [7; 16]).unwrap();
        let out = dispatcher.tick(&mut store, &link(), 1_100 + QUERY_INTERVAL_MS);
        let s2 = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .expect("second submit");
        dispatcher.handle_reply(
            &mut store,
            s2.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Sent,
                2,
                Evidence::GatewayAccepted,
                [0xAA; 32],
            ),
            1_150 + QUERY_INTERVAL_MS,
        );
        assert_eq!(op(&store, b).dispatch_state, DispatchState::Indeterminate);
    }

    /// The device reporting an expired slot while our marker says
    /// provably-unsent is contradictory evidence: INDETERMINATE, never a
    /// claimed EXPIRED_BEFORE_DISPATCH.
    #[test]
    fn expired_slot_with_unsent_marker_is_indeterminate() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted(&mut store, 0xf5, 30_000, 1_000);
        let submit = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        // Race the marker back to provably-unsent (e.g. a concurrent
        // emit-drop), then deliver the receipt anyway.
        let _ = store.update_operation(seq, &mut |o| {
            if let Some(d) = o.dispatch.as_mut() {
                d.submitted = false;
            }
            true
        });
        let hash = op(&store, seq).hash;
        dispatcher.handle_reply(
            &mut store,
            submit.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Expired,
                1,
                Evidence::None,
                hash,
            ),
            1_050,
        );
        let record = op(&store, seq);
        assert_eq!(record.dispatch_state, DispatchState::Indeterminate);
        assert!(record.dispatch.as_ref().unwrap().device_terminal);
    }
}
