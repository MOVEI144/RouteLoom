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
//!   extended. Every deadline check is additionally capped by the
//!   record's monotonic-clock budget (`accepted_mono_ms + ttl`), so a
//!   wall-clock rewind that stays above the admit stamp still cannot
//!   stretch a TTL.

use routeloom_protocol::host_ops::{
    self, BootLease, ConfigOpsResult, Evidence, GatewayOpsResult, HostOpsResult, LaneRequest,
    QueryResponse, Receipt, SlotState, SubmitRequest, TimeSampleRequest, CAP_CONFIG_ENDPOINT_V1,
    CAP_GATEWAY_ENDPOINT_V1, CAP_HOST_OPS_V1, SUB_QUERY_DISPATCH, SUB_RETIRE_THROUGH, SUB_SKIP,
};
use routeloom_protocol::{Frame, FrameKind};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use crate::config::{
    config_dev_key, ConfigIssuer, ConfigLane, ConfigOutcome, ConfigRequest, ConfigStep,
    ISSUE_PROFILE_COSE,
};
use crate::send_store::{
    mint_id128, ConfigAuthorityLedger, DispatchState, OperationStore, PrepareOutcome,
    StoredOperation,
};
use crate::{json_escape, now_ms, push_event, Outbound, State};

// contracts.json / design constants.
pub const DISPATCH_WINDOW: u64 = 32;
pub const TIME_SAMPLE_MAX_AGE_MS: u64 = 5_000;
pub const CLOCK_PPM: u64 = 1_000;
pub const CLOCK_QUANTUM_MS: u64 = 1;

/// HostRegister lane (05-wire-api.md §5.6): the daemon asks for a 15s
/// lease — the device grants what it grants (it currently always grants
/// 15s and rejects requests above 60s). Renewal runs at half the granted
/// lease so one lost response never lapses the binding.
pub const HOST_REGISTER_LEASE_REQUEST_MS: u32 = 15_000;
/// Floor between registration attempts — a Busy/failed answer retries on
/// this cadence instead of every 40ms tick.
const REGISTER_RETRY_MS: u64 = 250;

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
    /// The device serves the Gateway HostOps family (cap bit 3): host
    /// registration, scope-2 ingress and unregister.
    pub gateway_ops: bool,
    /// The device serves the Config HostOps family (cap bit 4): challenge /
    /// status queries and permit-object transfer (P5).
    pub config_ops: bool,
    /// Authenticated USB session id — the registration binds this.
    pub session: u64,
    /// The daemon's own incarnation id (minted once per run, bound into
    /// every registration so two daemon runs can never alias).
    pub host_boot: u64,
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
        gateway_ops: info
            .capability
            .is_some_and(|c| c & CAP_GATEWAY_ENDPOINT_V1 != 0),
        config_ops: info
            .capability
            .is_some_and(|c| c & CAP_CONFIG_ENDPOINT_V1 != 0),
        session: info.id.unwrap_or(0),
        host_boot: state.host_boot,
        node: info.node.unwrap_or(0),
        boot: info.boot.unwrap_or(0),
        network: info.network.unwrap_or(0),
    }
}

/// The live host registration mirror the dispatcher publishes for the API
/// surface: the (session, host_boot) binding the attached gateway minted,
/// with the deadline it granted. `usb_session`/`egress` pin which session
/// and adapter this record belongs to — a new session or adapter can never
/// inherit it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayRegistration {
    pub token: [u8; 16],
    pub gateway_boot: u64,
    /// SHA-256 of the authenticated session principal — the digest a
    /// scope-2 endpoint expects.
    pub host_digest: [u8; 32],
    pub egress: u64,
    pub usb_session: u64,
    /// Process-monotonic deadline of the granted lease; the mirror stops
    /// being usable past it even before the next tick clears it.
    pub lease_deadline_mono: u64,
}

/// Shared, dispatcher-owned registration record. Writers are the dispatch
/// thread only; readers (api1) take the whole record under one short lock
/// and re-check `usb_session` against the session layer before trusting
/// the binding.
#[derive(Default)]
pub struct GatewayLane {
    current: Mutex<Option<GatewayRegistration>>,
}

impl GatewayLane {
    pub fn current(&self) -> Option<GatewayRegistration> {
        self.current.lock().expect("gateway lane poisoned").clone()
    }

    /// Publish a committed grant. Production callers are the dispatch
    /// loop only (via `take_gateway_publish`); `pub(crate)` so api-level
    /// tests can install a fixture without driving the wire lane.
    pub(crate) fn set(&self, registration: GatewayRegistration) {
        *self.current.lock().expect("gateway lane poisoned") = Some(registration);
    }

    pub fn clear(&self) {
        *self.current.lock().expect("gateway lane poisoned") = None;
    }
}

// --- Config operation registry (scope-gateway-config P5) ---------------------
//
// Config ops get their own operation space — never the messages.* or
// gateway.* tables. The api1 layer submits a `ConfigRequest` and gets back a
// config op id; the dispatch thread drives it through the `ConfigLane` and
// writes the terminal `ConfigOutcome` here. `config.get` reads the record.
// Both ends are bounded so a stalled link or a spammed submit can never grow
// the hub without limit, and a queued request is only drained while a live
// session can carry it — it stays PENDING rather than fabricating a result.

/// api→dispatch request bound for the config lane. Only the wire essentials
/// ride the inbox — the summary/network/target/submitted metadata is already
/// committed to the `ConfigOpRecord` at submit time, so `config.get` reads it
/// from there rather than carrying a second copy through the queue.
struct QueuedConfig {
    op_id: u64,
    request: ConfigRequest,
}

/// The api-visible record for one config op. `outcome` is None while the op
/// is queued or in flight — never a guessed verdict.
#[derive(Clone, Debug)]
pub struct ConfigOpRecord {
    pub op_id: u64,
    pub summary: String,
    pub network: u64,
    pub target: u64,
    pub outcome: Option<ConfigOutcome>,
    pub submitted_ms: u64,
    pub resolved_ms: Option<u64>,
}

/// Bound on queued (not yet driven) requests and on retained records.
const CONFIG_INBOX_CAP: usize = 32;
const CONFIG_RECORD_CAP: usize = 128;

#[derive(Default)]
struct ConfigOpsInner {
    next_op: u64,
    inbox: VecDeque<QueuedConfig>,
    records: HashMap<u64, ConfigOpRecord>,
    /// Resolved op ids in completion order — the FIFO eviction order once the
    /// record table is full (in-flight ops are never evicted).
    resolved_order: VecDeque<u64>,
}

/// Shared config op hub: api1 is the producer/reader, the dispatch thread the
/// consumer/writer. One Mutex guards the whole structure — submits and
/// resolutions are short and the dispatch pass never holds the store lock and
/// this lock together long enough to matter.
#[derive(Default)]
pub struct ConfigOps {
    inner: Mutex<ConfigOpsInner>,
}

impl ConfigOps {
    /// A config op id namespaces the daemon incarnation that minted it:
    /// `(tag << 32) | seq` where `tag` folds `host_boot` into the high word
    /// (bit 0 forced so the tag is never zero). The records table is
    /// RAM-only, so without the tag a restarted daemon would reissue
    /// `cfg...0001` and a stale `config.get` token would resolve to a
    /// DIFFERENT operation — the tag makes a pre-restart token provably
    /// not this boot's. `ConfigOps::default()` keeps the zero tag, which
    /// is only for tests and fixtures.
    pub fn with_boot(host_boot: u64) -> Self {
        let tag = ((host_boot as u32) ^ ((host_boot >> 32) as u32)) | 1;
        Self {
            inner: Mutex::new(ConfigOpsInner {
                next_op: u64::from(tag) << 32,
                ..ConfigOpsInner::default()
            }),
        }
    }

    /// Queue a client request for the dispatch lane. Returns the config op id
    /// the client polls with `config.get`, or Err(()) when the inbox is full —
    /// an honest capacity refusal, never a silent drop.
    pub fn submit(
        &self,
        request: ConfigRequest,
        summary: String,
        network: u64,
        target: u64,
        now_ms: u64,
    ) -> Result<u64, ()> {
        let mut inner = self.inner.lock().expect("config ops poisoned");
        // Evict one resolved record to make room BEFORE the capacity
        // check: the cap must refuse only while every retained record is
        // still live (queued or in flight) — a resolved record is history,
        // not occupancy. In-flight ops are never evicted.
        if inner.records.len() >= CONFIG_RECORD_CAP {
            while let Some(oldest) = inner.resolved_order.pop_front() {
                if inner.records.remove(&oldest).is_some() {
                    break;
                }
            }
        }
        if inner.inbox.len() >= CONFIG_INBOX_CAP || inner.records.len() >= CONFIG_RECORD_CAP {
            return Err(());
        }
        let op_id = inner.next_op.wrapping_add(1).max(1);
        inner.next_op = op_id;
        inner.inbox.push_back(QueuedConfig { op_id, request });
        inner.records.insert(
            op_id,
            ConfigOpRecord {
                op_id,
                summary,
                network,
                target,
                outcome: None,
                submitted_ms: now_ms,
                resolved_ms: None,
            },
        );
        Ok(op_id)
    }

    /// Pop the head queued request for the dispatch pass. Only called while a
    /// live session can carry it AND the lane is free — the caller gates on
    /// `link.active && !config_busy()`, so a queued op stays PENDING behind a
    /// busy lane rather than being pulled off the queue only to resolve Busy.
    fn take_request(&self) -> Option<QueuedConfig> {
        self.inner
            .lock()
            .expect("config ops poisoned")
            .inbox
            .pop_front()
    }

    /// Record the terminal outcome for an op the lane resolved.
    fn resolve(&self, op_id: u64, outcome: ConfigOutcome, now_ms: u64) {
        let mut inner = self.inner.lock().expect("config ops poisoned");
        if let Some(record) = inner.records.get_mut(&op_id) {
            record.outcome = Some(outcome);
            record.resolved_ms = Some(now_ms);
            inner.resolved_order.push_back(op_id);
        }
        // Bound the retained record table: evict the oldest RESOLVED entries
        // first so in-flight ops are never dropped out from under a reader.
        while inner.records.len() > CONFIG_RECORD_CAP {
            let Some(oldest) = inner.resolved_order.pop_front() else {
                break;
            };
            inner.records.remove(&oldest);
        }
    }

    /// Read one op's record for `config.get`.
    pub fn get(&self, op_id: u64) -> Option<ConfigOpRecord> {
        self.inner
            .lock()
            .expect("config ops poisoned")
            .records
            .get(&op_id)
            .cloned()
    }
}

/// The single in-flight wire step the dispatcher is tracking for the config
/// lane (the lane holds at most one outstanding request at a time).
#[derive(Clone, Copy)]
struct ConfigPending {
    /// Dispatcher-assigned wire request id stamped on the emitted frame.
    wire: u64,
    /// The lane's own request id — what `on_reply`/`on_dropped` expects.
    lane: u64,
    /// The config op id the in-flight request resolves.
    op_id: u64,
}

/// The dispatcher-owned config lane state. `authority`/`generation` are the
/// daemon's configured SingleAuthority inputs; the sequence is allocated and
/// durably committed per-propose by the store layer (`ConfigAuthorityLedger`).
struct ConfigRuntime {
    lane: ConfigLane,
    /// Configured issuer node id; 0 means no authority is configured and
    /// Propose is refused (queries still run).
    authority: u64,
    /// Authority generation bound into each signed command.
    generation: u32,
    pending: Option<ConfigPending>,
    /// Emit bodies the lane produced this pass, drained into the wire queue
    /// on the leased path — cleared when the link cannot carry them.
    emits: Vec<DispatchRequest>,
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
#[cfg(test)]
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
    deadline_decision_at(accepted_ms, deadline, mapping, device_now, host_now)
}

/// `deadline_decision` against a pre-computed deadline. The caller may
/// tighten `accepted_ms + ttl_ms` — the dispatcher caps it at the record's
/// monotonic budget — but never widen it. All other checks are unchanged:
/// malformed mappings still fail before expiry arithmetic and nothing
/// wraps or saturates into extra validity.
fn deadline_decision_at(
    accepted_ms: u64,
    deadline: u64,
    mapping: Option<TimeMapping>,
    device_now: u64,
    host_now: u64,
) -> DeadlineDecision {
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

/// The record's effective deadline: the wall deadline `accepted + ttl`
/// tightened by the monotonic budget. A wall-clock rewind that lands
/// above `accepted_ms` is invisible to `now < accepted_ms` checks, so the
/// monotonic anchor (`accepted_mono_ms`, stamped at admit time) supplies
/// the real remaining life: the deadline is pulled back to
/// `now + mono_remaining` whenever that is earlier — a rewound clock can
/// never hand a fresh TIME_SAMPLE more life than real elapsed leaves.
/// An unanchored record (pre-restart row, lane tombstone, legacy admit)
/// falls back to the wall deadline — across a boot boundary trusted
/// elapsed is unprovable, which is the restart path's existing contract.
/// `None` means the wall deadline itself overflowed — hold, never wrap.
fn capped_deadline_ms(op: &StoredOperation, now: u64, mono: u64) -> Option<u64> {
    let wall = op.accepted_ms.checked_add(u64::from(op.ttl_ms))?;
    if op.accepted_mono_ms == 0 {
        return Some(wall);
    }
    let mono_deadline = op.accepted_mono_ms.checked_add(u64::from(op.ttl_ms))?;
    let mono_remaining = mono_deadline.saturating_sub(mono);
    Some(wall.min(now.saturating_add(mono_remaining)))
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
/// device lease, the tick timestamps (wall `now` and rewind-proof
/// `mono`), and the request sink.
struct Pass<'a> {
    lease: BootLease,
    now: u64,
    mono: u64,
    out: &'a mut Vec<DispatchRequest>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingKind {
    Submit,
    Query,
    Skip,
    Retire,
    /// HOST_REGISTER request awaiting the device's reply.
    Register,
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
    /// The lease-up floor probe has been answered this lease: the device
    /// refuses the reserved `through = 0` target with InvalidRequest but
    /// still reports its live floor, so "unknown" and "confirmed 0" must
    /// be distinguished — a lost probe is re-issued until answered.
    floor_known: bool,
    next_request: u64,
    next_nonce: u64,
    pending: HashMap<u64, Pending>,
    sample: Option<TimeSampleInFlight>,
    /// Last USB attempt per operation seq — throttles query re-polls.
    last_attempt: HashMap<u64, u64>,
    /// A device clock regression was observed on this lease.
    clock_degraded: bool,
    /// Gateway registration lane: the USB session the current lane state
    /// binds (0 = unbound). Any session change clears the published mirror
    /// and forces a fresh 0x10 — a token minted under another session can
    /// never be inherited.
    gateway_session: u64,
    /// Session/egress the in-flight or published registration binds —
    /// stashed at emit time so `handle_reply` needs no link snapshot.
    gateway_bind: (u64, u64),
    /// Monotonic time of the next allowed 0x10 emit (renewal half-lease or
    /// a retry floor). 0 means "due now".
    gateway_next_emit: u64,
    /// The mirror value the dispatch loop must publish to
    /// `State.gateway_lane` — Some(record) on a fresh grant, None on
    /// session/link loss. Drained by `dispatch_once` only.
    gateway_publish: Option<Option<GatewayRegistration>>,
    /// The config lane runtime (P5) — None until `attach_config` wires a
    /// `ConfigLane`. Queries/proposes only run while it and the device's
    /// config capability are present.
    config: Option<ConfigRuntime>,
    /// Config outcomes resolved this pass, drained by `dispatch_once` into
    /// `State.config_ops`. Lives outside `config` so a refused submit can
    /// still be reported even when no lane is attached.
    config_done: Vec<(u64, ConfigOutcome)>,
    /// Bounded diagnostics drained by the loop into the event ring.
    notes: Vec<String>,
    /// Dedup marker for the LaneMismatch diagnostic — re-armed on every
    /// lease change. A bound foreign lane rejects every verb we emit, so
    /// an undeduplicated note would flood the 64-deep ring on every op
    /// and every skip_pending retry for the whole window lifetime.
    lane_mismatch_noted: bool,
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
            floor_known: false,
            next_request: 0,
            next_nonce: 0,
            pending: HashMap::new(),
            sample: None,
            last_attempt: HashMap::new(),
            clock_degraded: false,
            gateway_session: 0,
            gateway_bind: (0, 0),
            gateway_next_emit: 0,
            gateway_publish: None,
            config: None,
            config_done: Vec::new(),
            notes: Vec::new(),
            lane_mismatch_noted: false,
        }
    }

    /// Wire the config lane in (P5): the dispatch loop attaches a `ConfigLane`
    /// at startup with the daemon's configured authority inputs. `authority`
    /// is the issuer node id (0 = unconfigured → Propose refused, queries
    /// still run); `generation` is the authority generation bound into signed
    /// commands. The per-propose sequence comes from the durable ledger.
    pub fn attach_config(&mut self, lane: ConfigLane, authority: u64, generation: u32) {
        self.config = Some(ConfigRuntime {
            lane,
            authority,
            generation,
            pending: None,
            emits: Vec::new(),
        });
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

    /// The once-per-lease LaneMismatch diagnostic: the device lane is
    /// bound to a different dispatcher id — this daemon recreated its
    /// store and minted a new lineage, or a second daemon shares the
    /// gateway — so every verb bounces until the gateway reboots and
    /// wipes the window.
    fn note_lane_mismatch(&mut self) {
        if self.lane_mismatch_noted {
            return;
        }
        self.lane_mismatch_noted = true;
        self.note(
            "gateway dispatch lane bound to a different dispatcher id — dispatch rejected until gateway reboot (store lineage changed or a second daemon shares the gateway)"
                .to_string(),
        );
    }

    /// Diagnostics collected this pass, drained by the driving loop.
    pub fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    /// The mirror publish the dispatch loop owes `State.gateway_lane`, if
    /// any. Some(Some(reg)) publishes a fresh grant, Some(None) clears a
    /// dead binding — drained once per pass so readers only ever see
    /// committed values.
    pub fn take_gateway_publish(&mut self) -> Option<Option<GatewayRegistration>> {
        self.gateway_publish.take()
    }

    /// Config outcomes resolved this pass, drained by `dispatch_once` into
    /// `State.config_ops` — same once-per-pass committed-value discipline as
    /// the registration mirror.
    pub fn take_config_done(&mut self) -> Vec<(u64, ConfigOutcome)> {
        std::mem::take(&mut self.config_done)
    }

    /// Whether the config lane currently holds an in-flight request. The
    /// dispatch pass only pulls a queued op off `State.config_ops` while this
    /// is false, so a queued op stays PENDING behind a busy lane instead of
    /// being drained and refused Busy.
    pub fn config_busy(&self) -> bool {
        self.config.as_ref().is_some_and(|c| c.lane.busy())
    }

    /// Advance the config lane on a `ConfigStep`: an Emit becomes a wire
    /// request stamped with a fresh dispatcher request id (so it can never
    /// alias a SUBMIT/QUERY pending), and a Done resolves the op id's
    /// outcome. Wire id -> lane id rides in `pending` — one in-flight only.
    fn drive_config_step(&mut self, step: ConfigStep, op_id: u64) {
        if self.config.is_none() {
            return;
        }
        match step {
            ConfigStep::Emit { request, body } => {
                // alloc_request borrows the whole dispatcher, so it runs
                // before the config field borrow below.
                let wire = self.alloc_request();
                let cfg = self.config.as_mut().expect("checked above");
                cfg.emits.push(DispatchRequest {
                    request: wire,
                    body,
                });
                cfg.pending = Some(ConfigPending {
                    wire,
                    lane: request,
                    op_id,
                });
            }
            ConfigStep::Done(outcome) => {
                let cfg = self.config.as_mut().expect("checked above");
                cfg.pending = None;
                self.config_done.push((op_id, outcome));
            }
        }
    }

    /// Submit one queued api request to the lane. Gates on the device's
    /// config capability and, for the signing requests, on a configured
    /// authority — a refusal is an honest terminal outcome, never a
    /// fabricated result. The SingleAuthority commit order (reserve →
    /// bind → sign → store) runs inside the lane just before each
    /// transfer emits, so a crash can gap but never reuse a sequence.
    fn config_submit<L: ConfigAuthorityLedger>(
        &mut self,
        ledger: &mut L,
        link: &LinkSnapshot,
        op_id: u64,
        request: ConfigRequest,
        now: u64,
    ) {
        if !link.config_ops {
            self.config_done
                .push((op_id, ConfigOutcome::Refused(ConfigOpsResult::Unsupported)));
            return;
        }
        let Some(cfg) = self.config.as_mut() else {
            self.config_done
                .push((op_id, ConfigOutcome::Refused(ConfigOpsResult::Unsupported)));
            return;
        };
        if cfg.lane.busy() {
            self.config_done
                .push((op_id, ConfigOutcome::Refused(ConfigOpsResult::Busy)));
            return;
        }
        if let ConfigRequest::Propose { .. } | ConfigRequest::Recover { .. } = request {
            // A signed object needs a configured authority, a live mesh
            // network to bind into the AAD, and an issuer that actually
            // holds the selected profile's signing key — none of these is
            // client-supplied. All three refuse before any reservation.
            if cfg.authority == 0 || link.network == 0 || !cfg.lane.issuer_ready() {
                self.config_done
                    .push((op_id, ConfigOutcome::Refused(ConfigOpsResult::Denied)));
                return;
            }
            cfg.lane.set_issuer_identity(link.network, cfg.authority);
            cfg.lane.set_authority(cfg.generation);
        }
        let step = cfg.lane.submit(ledger, request, now);
        self.drive_config_step(step, op_id);
    }

    /// Route one inbox body to the lane when it answers the in-flight config
    /// wire request. Returns true when consumed (so `handle_reply` does not
    /// fall through to "unmatched"). The lane commits the permit issuance
    /// through `ledger` when the challenge reply lands.
    fn config_reply<L: ConfigAuthorityLedger>(
        &mut self,
        ledger: &mut L,
        request: u64,
        inner: &[u8],
        now: u64,
    ) -> bool {
        let pending = match self.config.as_ref().and_then(|c| c.pending) {
            Some(p) if p.wire == request => p,
            _ => return false,
        };
        let step = {
            let cfg = self.config.as_mut().expect("checked above");
            cfg.pending = None;
            cfg.lane.on_reply(ledger, pending.lane, inner, now)
        };
        self.drive_config_step(step, pending.op_id);
        true
    }

    /// Deadline enforcement for the in-flight config step: a query deadline
    /// resolves Timeout, a permit-transfer deadline Indeterminate. Runs every
    /// pass regardless of link state — a stalled step must still resolve.
    /// `carry` is false when the link cannot serve config right now, in which
    /// case buffered emits are dropped (the in-flight request then resolves
    /// via its own deadline) rather than sent to a dead endpoint.
    fn config_pass(&mut self, now: u64, carry: bool, out: &mut Vec<DispatchRequest>) {
        let Some(cfg) = self.config.as_mut() else {
            return;
        };
        if let Some(outcome) = cfg.lane.poll(now) {
            let op_id = cfg.pending.map(|p| p.op_id).unwrap_or(0);
            cfg.pending = None;
            self.config_done.push((op_id, outcome));
        }
        if carry {
            out.append(&mut cfg.emits);
        } else {
            cfg.emits.clear();
        }
    }

    /// A config emit the outbound queue refused — provably never reached the
    /// device, so resolve the in-flight step honestly instead of leaving it
    /// to time out. Returns true when `request` was the config wire id.
    fn config_dropped(&mut self, request: u64) -> bool {
        let pending = match self.config.as_ref().and_then(|c| c.pending) {
            Some(p) if p.wire == request => p,
            _ => return false,
        };
        let step = {
            let cfg = self.config.as_mut().expect("checked above");
            cfg.pending = None;
            cfg.lane.on_dropped(pending.lane)
        };
        self.drive_config_step(step, pending.op_id);
        true
    }

    /// Gateway registration lane (05 §5.6): keep one live (session,
    /// host_boot) binding while the link serves the family. The lane only
    /// ever binds the CURRENT session — a session id change retires the
    /// mirror immediately, so a stale-session token can never authorize a
    /// schema-2 canonical.
    fn gateway_pass(
        &mut self,
        link: &LinkSnapshot,
        now: u64,
        mono: u64,
        out: &mut Vec<DispatchRequest>,
    ) {
        if !(link.gateway_ops && link.session != 0 && link.host_boot != 0) {
            // No gateway family or no daemon incarnation id: the lane
            // cannot run. Drop any mirror bound to the dead session.
            if self.gateway_session != 0 {
                self.gateway_session = 0;
                self.gateway_publish = Some(None);
            }
            return;
        }
        if self.gateway_session != link.session {
            // New authenticated session: the device cleared its record —
            // publish the loss (only when a prior binding could still be
            // mirrored — a first bind has nothing to clear) and
            // re-register under the new binding.
            let had_binding = self.gateway_session != 0;
            self.gateway_session = link.session;
            self.gateway_bind = (link.session, link.node);
            self.gateway_next_emit = 0;
            if had_binding {
                self.gateway_publish = Some(None);
            }
        }
        // One 0x10 in flight at a time; renewal/failure cadence is bounded
        // by gateway_next_emit.
        let in_flight = self
            .pending
            .values()
            .any(|p| p.kind == PendingKind::Register);
        if in_flight || mono < self.gateway_next_emit {
            return;
        }
        let request = self.alloc_request();
        let body = host_ops::encode_host_register(&host_ops::HostRegisterRequest {
            network: link.network,
            host_boot: link.host_boot,
            lease_ms: HOST_REGISTER_LEASE_REQUEST_MS,
        });
        self.pending.insert(
            request,
            Pending {
                op_seq: None,
                kind: PendingKind::Register,
                sent_ms: now,
                // For Register pendings `through` carries the emit-time
                // monotonic stamp: lease deadlines anchored at the
                // REQUEST are strictly earlier than the device's
                // response-time grant — conservative, never overclaiming.
                through: mono,
            },
        );
        // Floor on re-emit: while a response is pending this only arms the
        // post-response gap; on Ok the handler pushes it out to half the
        // granted lease.
        self.gateway_next_emit = mono + REGISTER_RETRY_MS;
        out.push(DispatchRequest { request, body });
    }

    /// HOST_REGISTER reply: only a result-Ok bound to the CURRENT session
    /// publishes a mirror. Busy is the retryable answer (re-emit on the
    /// retry cadence); every other outcome is a diagnostic, never a silent
    /// rebind. `emit_mono` is the request's monotonic stamp — lease
    /// deadlines anchored there expire strictly before the device's own
    /// grant would, so the mirror never outlives the real binding.
    fn on_host_register_response(&mut self, inner: &[u8], emit_mono: u64, _now: u64) {
        match host_ops::decode_host_register_response(inner) {
            Ok(response) => {
                let Ok(result) = GatewayOpsResult::try_from_u16(response.result) else {
                    self.note(format!(
                        "host register reply carries unknown result {}",
                        response.result
                    ));
                    return;
                };
                match result {
                    GatewayOpsResult::Ok => {
                        let (session, egress) = self.gateway_bind;
                        // The granted lease clamps our renewal: refresh at
                        // half of it (at least one retry floor out).
                        let lease = u64::from(response.lease_ms);
                        self.gateway_next_emit = emit_mono + (lease / 2).max(REGISTER_RETRY_MS);
                        self.gateway_publish = Some(Some(GatewayRegistration {
                            token: response.token,
                            gateway_boot: response.gateway_boot,
                            host_digest: response.host_digest,
                            egress,
                            usb_session: session,
                            lease_deadline_mono: emit_mono + lease,
                        }));
                    }
                    GatewayOpsResult::Busy => {
                        // Retryable: leave the retry floor as armed.
                    }
                    other => {
                        self.note(format!(
                            "host register refused: {other:?} (binding stays unpublished)"
                        ));
                    }
                }
            }
            Err(error) => self.note(format!("host register reply undecodable: {error}")),
        }
    }

    /// One pass: consume nothing (replies go through `handle_reply`),
    /// produce the request bodies the wire needs next. `now` is the wall
    /// clock; `mono` is a process-monotonic millisecond clock on the same
    /// axis as `StoredOperation::accepted_mono_ms` — deadline checks are
    /// capped by the monotonic budget so a wall-clock rewind can never
    /// stretch a TTL.
    pub fn tick_mono<S: OperationStore>(
        &mut self,
        store: &mut S,
        link: &LinkSnapshot,
        now: u64,
        mono: u64,
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
        // Config lane sweep: deadline enforcement is a host-side proof and
        // runs every pass regardless of link state; buffered emits only go
        // out while the link actually serves the config family.
        self.config_pass(now, link.config_ops && self.lease.is_some(), &mut out);
        let Ok(ops) = store.dispatch_view() else {
            self.note("dispatch_view fault".to_string());
            return out;
        };
        // Host-side sweeps need no link: expiry and clock rewind are
        // provable locally for records that never reached USB.
        for op in &ops {
            self.sweep(store, op, now, mono);
        }
        let Some(lease_bytes) = self.lease else {
            return out;
        };
        self.gateway_pass(link, now, mono, &mut out);
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
            mono,
            out: &mut out,
        };
        self.dispatch_pass(store, &sorted, link, &mut pass, &mut highwater);
        self.query_pass(&sorted, lease_bytes, now, &mut out);
        self.skip_pass(&sorted, lease_bytes, now, &mut out);
        self.retire_pass(&sorted, lease_bytes, now, &mut out);
        out
    }

    /// Honest-clock convenience wrapper: tests that do not exercise a
    /// wall-clock rewind drive wall and monotonic time identically.
    #[cfg(test)]
    fn tick<S: OperationStore>(
        &mut self,
        store: &mut S,
        link: &LinkSnapshot,
        now: u64,
    ) -> Vec<DispatchRequest> {
        self.tick_mono(store, link, now, now)
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
        self.floor_known = false;
        // A new lease means a fresh device window — a lane conflict
        // under it is new evidence worth another diagnostic.
        self.lane_mismatch_noted = false;
        // The registration mirror cannot outlive the lease it was bound
        // under — a new boot/adapter gets a fresh lane. Publish the clear
        // only when a bound session could still be mirrored; the first
        // lease adoption has nothing to unpublish.
        if self.gateway_session != 0 {
            self.gateway_publish = Some(None);
        }
        self.gateway_session = 0;
        self.gateway_next_emit = 0;
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
                // Probe the floor: RETIRE_THROUGH(0) is a reserved target
                // the device refuses as InvalidRequest — but the response
                // still carries the live `retired_through`, which makes it
                // the read-only floor query. `retire_pass` re-issues the
                // probe until a response lands (`floor_known`).
                out.push(self.emit_retire(0, bytes, now));
            }
            None => self.note("link down".to_string()),
        }
    }

    /// Local sweeps that need no device: expiry for provably unsubmitted
    /// records and clock-rewind uncertainty. The expiry bar is the
    /// monotonic-capped deadline, so a wall rewind that lands above the
    /// admit stamp cannot stretch the TTL — the record expires on real
    /// elapsed time.
    fn sweep<S: OperationStore>(
        &mut self,
        store: &mut S,
        op: &StoredOperation,
        now: u64,
        mono: u64,
    ) {
        if op.concluded() {
            return;
        }
        let Some(deadline) = capped_deadline_ms(op, now, mono) else {
            return;
        };
        // The monotonic cap can expire a record while the rewound wall
        // clock still sits below the admit stamp — real elapsed time is
        // the proof that matters, so check expiry before the rewind park.
        if now >= deadline {
            self.expire_unsubmitted(store, op.seq, now);
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
        }
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
            // The device deadline derives from the monotonic-capped wall
            // deadline: a rewound host clock cannot hand a fresh
            // TIME_SAMPLE more remaining life than real elapsed leaves.
            let Some(deadline) = capped_deadline_ms(op, now, pass.mono) else {
                continue;
            };
            let decision =
                deadline_decision_at(op.accepted_ms, deadline, self.mapping, device_now, now);
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
    /// floor — the design never retires across the unknown. While the
    /// lease-up floor probe is unanswered it is re-issued here: the
    /// pending timeout dropping it must not strand the floor at 0.
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
        if !self.floor_known {
            // RETIRE_THROUGH(0) is the read-only floor query: the device
            // refuses the reserved target as InvalidRequest but reports
            // its current retired_through either way.
            out.push(self.emit_retire(0, lease, now));
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
            // 04 §5 keeps the gateway's send responsibility separate from
            // host long-term result tracking: once the device reported a
            // terminal slot (and the evidence is committed — the same
            // atomic record update sets the marker), the position may
            // retire even when the host record stays INDETERMINATE. What
            // must never retire is the unconfirmed: `device_terminal` is
            // only set by authenticated device evidence.
            let settled = op
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
        // A config emit that never reached the writer resolves its in-flight
        // step honestly (Timeout for a query, Indeterminate for a transfer).
        self.config_dropped(request);
        if self.sample.is_some_and(|s| s.request == request) {
            self.sample = None;
        }
    }

    /// One host-ops inner body from the inbox.
    pub fn handle_reply<S: OperationStore + ConfigAuthorityLedger>(
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
        // Config replies land in the same inbox keyed by the dispatcher's
        // wire request id — route them to the lane before the generic
        // pending lookup, which does not own them.
        if self.config_reply(store, request, inner, now) {
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
            PendingKind::Register => self.on_host_register_response(inner, pending.through, now),
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
                if receipt.result == HostOpsResult::LaneMismatch {
                    self.note_lane_mismatch();
                }
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
                if response.result == HostOpsResult::LaneMismatch {
                    self.note_lane_mismatch();
                }
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
                if receipt.result == HostOpsResult::LaneMismatch {
                    self.note_lane_mismatch();
                }
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
                self.adopt_floor(store, response.retired_through, response.lease.0);
            }
            // The device refuses the reserved `through = 0` target as
            // InvalidRequest — the probe's answer is the reported floor.
            // Only the probe may adopt from an error result, and only
            // after the same-lease check above: arbitrary failures under a
            // foreign or lane-mismatched echo are never trusted.
            HostOpsResult::InvalidRequest if through == 0 => {
                self.adopt_floor(store, response.retired_through, response.lease.0);
            }
            HostOpsResult::RetireRefused => {
                self.note(format!(
                    "retire refused at through={} (requested {through})",
                    response.retired_through
                ));
                // The reported floor is authoritative here too — a lagging
                // view must not wedge the lane.
                self.adopt_floor(store, response.retired_through, response.lease.0);
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

    /// Adopt a floor the device reported in a same-lease retire response
    /// (Ok, RetireRefused, or the InvalidRequest answer to the `through=0`
    /// probe). Positions at or below the reported floor are retired on the
    /// device — confirmed-terminal by definition — so mark ours the same
    /// way the QUERY `Retired` result would: a still-open record lands
    /// INDETERMINATE, and a pending SKIP is moot because the position no
    /// longer exists. This is what lets a restarted host whose tombstone
    /// window is shorter than the device's retire span rejoin the lane.
    fn adopt_floor<S: OperationStore>(&mut self, store: &mut S, reported: u64, lease: [u8; 16]) {
        self.floor_known = true;
        if reported <= self.floor {
            return;
        }
        self.floor = reported;
        self.note(format!("device floor adopted at {reported}"));
        let Ok(ops) = store.dispatch_view() else {
            self.note("dispatch_view fault during floor adoption".to_string());
            return;
        };
        for op in ops {
            let below = op
                .dispatch
                .as_ref()
                .is_some_and(|a| a.lease == lease && a.dispatch_seq <= reported);
            if !below {
                continue;
            }
            let _ = store.update_operation(op.seq, &mut |o| {
                // Snapshot the conclusion flag before borrowing the
                // attachment (same borrow split as `adopt_slot`).
                let concluded = o.concluded();
                let Some(d) = o.dispatch.as_mut() else {
                    return false;
                };
                if d.device_terminal && !d.skip_pending && concluded {
                    return false;
                }
                d.device_terminal = true;
                d.skip_pending = false;
                if !concluded {
                    o.dispatch_state = DispatchState::Indeterminate;
                }
                true
            });
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
                        // Scope-2 terminal: the verified Service Receipt
                        // proving the registered host's ReceiveLog stored
                        // the payload — terminal like END_SDK but kept as
                        // its own proof, never promoted to an ordinary
                        // SDK receipt (05 §5.6).
                        Evidence::HostRamReceived => {
                            d.ev_host_receive = true;
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

/// Resolve one device-issued GATEWAY_INGRESS (0x11) into its ACK body
/// (0x12) — or None when no honest answer can be formed. The ACK follows
/// storage, never precedes it: the payload is verified (prefix shape +
/// recomputed digest) and ingested into the ReceiveLog FIRST, and only the
/// committed ingest outcome names the ACK result. The request id and the
/// bound fields (token, ref MessageKey, request_digest) are echoed from
/// the ingress — the device correlates the ACK on all of them, so a stale
/// or foreign value can never mark a record stored.
fn gateway_ingress_ack(state: &State, inner: &[u8], now: u64) -> Option<Vec<u8>> {
    let ingress = match host_ops::decode_gateway_ingress(inner) {
        Ok(ingress) => ingress,
        Err(error) => {
            push_event(
                state,
                now,
                format!(
                    "\"kind\":\"gw_ingress\",\"outcome\":\"malformed\",\"detail\":\"{}\"",
                    json_escape(&error.to_string())
                ),
            );
            return None;
        }
    };
    let (authenticated, session_id, network, node, boot) = {
        let info = state.session.lock().expect("session poisoned");
        (
            info.authenticated,
            info.id.unwrap_or(0),
            info.network.unwrap_or(0),
            info.node.unwrap_or(0),
            info.boot.unwrap_or(0),
        )
    };
    let prefix = &ingress.submit_prefix;
    let mut prefix_token = [0u8; 16];
    prefix_token.copy_from_slice(
        &prefix[host_ops::SERVICE_PREFIX_TOKEN_OFFSET..host_ops::SERVICE_PREFIX_TOKEN_OFFSET + 16],
    );
    // The device binds the 0x12 ACK to its live HOST registration token —
    // `ack.token == registration_.token` in usb_bridge.cpp — never to the
    // Service Submit prefix token, which on a real mesh ingress is the
    // ORIGIN's lease token (they only coincide on loopback, where the
    // device synthesizes the prefix from the registration itself). The
    // prefix token still participates in the digest recompute below —
    // only the ACK's token field changes. When no mirror is bound to this
    // session the ACK can never bind anyway: echo the presented prefix
    // token so the device drops it honestly rather than claiming a
    // binding we do not hold.
    let ack_token = match state.gateway_lane.current() {
        Some(reg) if reg.usb_session == session_id => reg.token,
        _ => prefix_token,
    };
    let answer = |outcome: GatewayOpsResult| {
        Some(host_ops::encode_gateway_ingress_ack(
            &host_ops::GatewayIngressAck {
                token: ack_token,
                ref_origin: ingress.ref_origin,
                ref_session: ingress.ref_session,
                ref_sequence: ingress.ref_sequence,
                request_digest: ingress.request_digest,
                outcome: outcome as u16,
            },
        ))
    };
    let event = |outcome: &str, detail: String| {
        push_event(
            state,
            now,
            format!(
                "\"kind\":\"gw_ingress\",\"outcome\":\"{outcome}\",\"origin\":{},\"msg_session\":{},\"msg_seq\":{},\"detail\":\"{}\"",
                ingress.ref_origin,
                ingress.ref_session,
                ingress.ref_sequence,
                json_escape(&detail)
            ),
        );
    };
    // The frame arrived sealed on the live session; the prefix still has
    // to be the exact wire shape the digest commits to — version, submit
    // subtype, host-receive scope, zero flags/reserved, matching length.
    let prefix_len = u16::from_be_bytes([
        prefix[host_ops::SERVICE_PREFIX_LEN_OFFSET],
        prefix[host_ops::SERVICE_PREFIX_LEN_OFFSET + 1],
    ]) as usize;
    let prefix_boot = u64::from_be_bytes(
        prefix[host_ops::SERVICE_PREFIX_BOOT_OFFSET..host_ops::SERVICE_PREFIX_BOOT_OFFSET + 8]
            .try_into()
            .expect("8"),
    );
    let well_formed = prefix[0] == 1
        && prefix[1] == 3
        && prefix[host_ops::SERVICE_PREFIX_SCOPE_OFFSET] == 2
        && prefix[3] == 0
        && prefix[30] == 0
        && prefix[31] == 0
        && prefix_len == ingress.payload.len()
        && ingress.payload.len() <= host_ops::CANONICAL_GATEWAY_PAYLOAD_MAX;
    if !well_formed {
        event("invalid", "submit prefix shape".to_string());
        return answer(GatewayOpsResult::Invalid);
    }
    if !authenticated || session_id == 0 {
        event("invalid", "no authenticated session".to_string());
        return answer(GatewayOpsResult::Invalid);
    }
    // The device only issues ingress under a live registration; the prefix
    // token is the ORIGIN's lease token, which differs from the host
    // registration token on every real mesh submit. A divergence is
    // expected, not an error — noted for diagnostics only. The storage
    // decision never depends on either token: the digest recompute below
    // is the proof, and the device validates the ACK binding on its own
    // registration record.
    if let Some(reg) = state.gateway_lane.current() {
        if reg.usb_session == session_id && reg.token != prefix_token {
            event(
                "note",
                "prefix token differs from registration mirror".to_string(),
            );
        }
    }
    if boot != 0 && prefix_boot != boot {
        // The submit was bound to a different adapter boot — the device
        // could not have accepted it on this session.
        event("invalid", "gateway_boot mismatch".to_string());
        return answer(GatewayOpsResult::Invalid);
    }
    // The storage proof is recomputed, never trusted: digest over the
    // exact Service Submit prefix plus the payload as received.
    let mut digest_input = Vec::with_capacity(prefix.len() + ingress.payload.len());
    digest_input.extend_from_slice(prefix);
    digest_input.extend_from_slice(&ingress.payload);
    if crate::canonical::sha256(&digest_input) != ingress.request_digest {
        event("invalid", "request digest mismatch".to_string());
        return answer(GatewayOpsResult::Invalid);
    }
    let outcome = {
        let mut log = state.receive_log.lock().expect("receive log poisoned");
        log.ingest(
            crate::receive_log::Ingress {
                network,
                gateway: (node != 0).then_some(node),
                origin: ingress.ref_origin,
                msg_session: ingress.ref_session,
                msg_seq: ingress.ref_sequence,
                payload: ingress.payload.clone(),
            },
            now,
        )
    };
    let (outcome, name) = match outcome {
        // Stored AND Duplicate both name "the payload is in the log" —
        // the resend path depends on the second delivery being as good
        // as the first (G03).
        crate::receive_log::IngestOutcome::Stored { .. }
        | crate::receive_log::IngestOutcome::Duplicate { .. } => (GatewayOpsResult::Ok, "stored"),
        crate::receive_log::IngestOutcome::Conflict { .. } => {
            (GatewayOpsResult::Invalid, "conflict")
        }
        // Capacity/credit exhaustion is the retryable answer: the caller
        // may retry once room exists, and the record is never claimed
        // stored (G07/BUSY).
        crate::receive_log::IngestOutcome::RejectedNetworkCap => {
            (GatewayOpsResult::Busy, "network_cap")
        }
        crate::receive_log::IngestOutcome::RejectedOversize => {
            (GatewayOpsResult::Invalid, "oversize")
        }
    };
    event(name, String::new());
    answer(outcome)
}

/// One dispatch pass against the shared daemon state: drain inbound
/// replies and device-issued ingress, run the tick, publish the
/// registration mirror, push the resulting frames at the writer queue.
/// Extracted from `dispatch_loop` so tests can drive it step by step.
pub fn dispatch_once(
    state: &State,
    outbound: &mpsc::SyncSender<Outbound>,
    dispatcher: &mut Dispatcher,
    now: u64,
    mono: u64,
) {
    let replies = state.dispatch_inbox.drain();
    let ingress = state.ingress_inbox.drain();
    let link = link_snapshot(state);
    // A config submission drains only while a live session can carry it AND
    // the lane is free — a dead link or a busy lane leaves the head queued
    // for a later pass (still honestly PENDING) rather than pulling it off
    // the queue only to fabricate a refusal. A session that cannot serve
    // config refuses honestly inside config_submit instead.
    let config_req = if link.active && !dispatcher.config_busy() {
        state.config_ops.take_request()
    } else {
        None
    };
    let requests = {
        let mut store = state
            .operation_store
            .lock()
            .expect("operation store poisoned");
        for (request, body) in replies {
            dispatcher.handle_reply(&mut *store, request, &body, now);
        }
        // Feed a config submission before tick so its first Emit rides this
        // pass's wire queue.
        if let Some(queued) = config_req {
            dispatcher.config_submit(&mut *store, &link, queued.op_id, queued.request, now);
        }
        dispatcher.tick_mono(&mut *store, &link, now, mono)
    };
    // Publish config outcomes exactly once per pass — api1 only ever reads
    // committed values.
    for (op_id, outcome) in dispatcher.take_config_done() {
        state.config_ops.resolve(op_id, outcome, now);
    }
    // Publish the registration mirror exactly once per pass — api1 only
    // ever reads committed values.
    if let Some(publish) = dispatcher.take_gateway_publish() {
        match publish {
            Some(registration) => state.gateway_lane.set(registration),
            None => state.gateway_lane.clear(),
        }
    }
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
    // Device-issued ingress resolves here, not in the reply lane: the ACK
    // body is produced only after the storage outcome is decided, and it
    // rides the same bounded writer queue under the request id the device
    // issued. A full queue loses the ACK — the device's own resend inside
    // its ack window gives us another pass, and a lost record is honest
    // non-success, never a claimed store.
    for (request, body) in ingress {
        if let Some(ack) = gateway_ingress_ack(state, &body, now) {
            let frame = Frame {
                kind: FrameKind::HostOps,
                flags: 0,
                session: 0,
                request,
                body: ack,
            };
            let _ = outbound.try_send(Outbound::Seal(frame));
        }
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

/// Reserve subtracted from the challenge's apply budget before the issuer
/// signs — the same safety margin the device profile assumes so a permit is
/// never cut to the wire's last millisecond.
const CONFIG_SAFETY_MARGIN_MS: u32 = 500;

/// Fill `buf` with fresh entropy from the store's 128-bit minter (urandom
/// with a non-repeating fallback) — the lane's operation_id / client_nonce
/// draws. Injected as a closure so tests stay deterministic.
fn fill_config_entropy(buf: &mut [u8]) {
    let mut filled = 0;
    while filled < buf.len() {
        let block = mint_id128();
        let n = (buf.len() - filled).min(block.len());
        buf[filled..filled + n].copy_from_slice(&block[..n]);
        filled += n;
    }
}

/// Build the config lane for the dispatch thread: the issuer under the
/// daemon's configured profile — dev HMAC derived from the link
/// development secret (domain-separated — never the raw PSK), or COSE
/// under the loaded authority key — plus the configured
/// authority/generation and real entropy. An unset authority yields a
/// lane that can answer queries but refuses every issuance honestly.
fn config_lane_for(state: &State) -> ConfigLane {
    // The permit master must equal the target's own key material — the
    // firmware verifier derives identically from ROUTELOOM_DEVELOPMENT_KEY_HEX,
    // so a mismatched master signs permits the device can only deny.
    let dev_key = config_dev_key(&state.config_dev_key);
    let authority = state.config_authority.unwrap_or(0);
    let mut issuer = ConfigIssuer::new(
        dev_key.to_vec(),
        /*network=*/ 0, // rebound to the live session network per propose
        authority,
        CONFIG_SAFETY_MARGIN_MS,
    );
    issuer.set_profile(state.config_profile);
    if state.config_profile == ISSUE_PROFILE_COSE {
        match state
            .config_authority_key
            .as_ref()
            .map(|path| routeloom_provision::signer::FileAuthoritySigner::load(path))
        {
            Some(Ok(signer)) if signer.authority_id() == authority => {
                issuer.set_cose_signer(signer);
            }
            _ => {
                // Validated at startup; a key that vanished since leaves
                // the lane keyless — every issuance refuses honestly.
                eprintln!("config authority key unloadable; COSE issuance refuses");
            }
        }
    }
    ConfigLane::new(
        issuer,
        state.config_authority_generation,
        Box::new(fill_config_entropy),
    )
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
    dispatcher.attach_config(
        config_lane_for(&state),
        state.config_authority.unwrap_or(0),
        state.config_authority_generation,
    );
    loop {
        dispatch_once(
            &state,
            &outbound,
            &mut dispatcher,
            now_ms(),
            crate::mono_ms(),
        );
        state.dispatch_inbox.wait(Duration::from_millis(TICK_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{self, SendRequest};
    use crate::send_store::{CancelOutcome, MemoryOperationStore, SubmitOutcome};
    use crate::sqlite_store::SqliteOperationStore;
    use routeloom_protocol::host_ops::{
        decode_lane_request, decode_submit, decode_time_sample_request, encode_query_response,
        encode_receipt, encode_retire_response, encode_time_sample_response, RetireResponse,
        TimeSampleResponse,
    };
    use routeloom_wire::autonomy::EncodedPayload;
    use routeloom_wire::endpoint::{
        control_challenge_encode, control_status_encode, ConfigField, ConfigFieldType, ConfigPhase,
        ConfigReason, ControlChallenge, ControlStatus,
    };

    const UID: u32 = 501;
    const NET: u64 = 1;
    const NODE: u64 = 0x0abc;
    const BOOT: u64 = 7;
    const HOST_BOOT: u64 = 0x99;

    fn link() -> LinkSnapshot {
        LinkSnapshot {
            active: true,
            host_ops: true,
            node: NODE,
            boot: BOOT,
            network: NET,
            session: 0,
            host_boot: HOST_BOOT,
            gateway_ops: true,
            config_ops: true,
        }
    }

    fn offline() -> LinkSnapshot {
        LinkSnapshot {
            active: false,
            host_ops: false,
            node: 0,
            boot: 0,
            network: 0,
            session: 0,
            host_boot: 0,
            gateway_ops: false,
            config_ops: false,
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
            gateway: None,
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

    /// Admit with an explicit monotonic anchor — rewind tests drive wall
    /// and monotonic clocks on divergent synthetic values.
    fn admitted_mono(
        store: &mut MemoryOperationStore,
        key: u8,
        ttl: u32,
        now: u64,
        mono: u64,
    ) -> u64 {
        store.open_epoch((UID, NET), now).unwrap();
        match store.submit_at(UID, &request(key, ttl), now, mono) {
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

    /// LaneMismatch = the device lane is bound to another dispatcher id
    /// (recreated store lineage, or a second daemon on the gateway). The
    /// record terminates REJECTED_NOT_ACCEPTED and exactly one diagnostic
    /// reaches the note/event stream per lease: the mismatch recurs on
    /// every verb until the gateway reboots, so a per-receipt note would
    /// flood the ring.
    #[test]
    fn lane_mismatch_terminates_and_notes_once_per_lease() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let lane_notes =
            |notes: &[String]| notes.iter().filter(|n| n.contains("dispatcher id")).count();
        let a = admitted(&mut store, 0xf1, 30_000, 1_000);
        let s1 = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        let _ = dispatcher.take_notes();
        let seq_a = decode_submit(&s1.body).unwrap().dispatch_seq;
        dispatcher.handle_reply(
            &mut store,
            s1.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::LaneMismatch,
                SlotState::Empty,
                seq_a,
                Evidence::None,
                [0; 32],
            ),
            1_050,
        );
        assert_eq!(
            op(&store, a).dispatch_state,
            DispatchState::RejectedNotAccepted
        );
        let notes = dispatcher.take_notes();
        assert_eq!(lane_notes(&notes), 1, "{notes:?}");
        // The rejected hole still owes a SKIP — and the bound lane
        // refuses it too: the same recurring mismatch, no second note.
        let out = dispatcher.tick(&mut store, &link(), 1_100);
        let skip = out
            .iter()
            .find(|r| sub_of(r) == SUB_SKIP)
            .expect("skip emitted")
            .request;
        dispatcher.handle_reply(
            &mut store,
            skip,
            &receipt(
                SUB_SKIP,
                HostOpsResult::LaneMismatch,
                SlotState::Empty,
                seq_a,
                Evidence::None,
                [0; 32],
            ),
            1_110,
        );
        let notes = dispatcher.take_notes();
        assert_eq!(lane_notes(&notes), 0, "{notes:?}");
        // A second op's SUBMIT hits the same bound lane — still silent.
        let b = admitted(&mut store, 0xf2, 30_000, 1_000);
        let out = dispatcher.tick(&mut store, &link(), 1_200);
        let s2 = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .expect("second submit");
        let seq_b = decode_submit(&s2.body).unwrap().dispatch_seq;
        dispatcher.handle_reply(
            &mut store,
            s2.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::LaneMismatch,
                SlotState::Empty,
                seq_b,
                Evidence::None,
                [0; 32],
            ),
            1_210,
        );
        assert_eq!(
            op(&store, b).dispatch_state,
            DispatchState::RejectedNotAccepted
        );
        let notes = dispatcher.take_notes();
        assert_eq!(lane_notes(&notes), 0, "{notes:?}");
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

    /// RETIRE_THROUGH(0) is the read-only floor probe: the device refuses
    /// the reserved target as InvalidRequest but still reports its live
    /// retired_through. The host must adopt that floor — without it a
    /// floor ahead of our records can never be learned and the lane
    /// wedges at 0 (review: the probe previously stranded host restarts
    /// whose device had already retired past the retained window).
    #[test]
    fn floor_probe_adopts_reported_floor() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let out = dispatcher.tick(&mut store, &link(), 1_000);
        let probe = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("floor probe");
        assert_eq!(
            decode_lane_request(&probe.body, SUB_RETIRE_THROUGH)
                .unwrap()
                .seq,
            0
        );
        // Refused target, live floor in the response: adopted.
        dispatcher.handle_reply(
            &mut store,
            probe.request,
            &retire_response(HostOpsResult::InvalidRequest, 64),
            1_010,
        );
        assert_eq!(dispatcher.floor, 64);
        assert!(dispatcher.floor_known);
        // A known floor stops the probes.
        let out = dispatcher.tick(&mut store, &link(), 1_020);
        assert!(!out.iter().any(|r| sub_of(r) == SUB_RETIRE_THROUGH));
    }

    /// The probe answer is only trusted under the live lease — a foreign
    /// lease echo reports nothing.
    #[test]
    fn floor_probe_rejects_foreign_lease() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let out = dispatcher.tick(&mut store, &link(), 1_000);
        let probe = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("floor probe");
        let foreign = encode_retire_response(&RetireResponse {
            result: HostOpsResult::InvalidRequest,
            lease: BootLease::derive(BOOT + 9, NODE),
            retired_through: 64,
        });
        dispatcher.handle_reply(&mut store, probe.request, &foreign, 1_010);
        assert_eq!(dispatcher.floor, 0);
        assert!(!dispatcher.floor_known);
    }

    /// A probe that never gets its answer is re-issued: the pending
    /// timeout dropping it must not strand the floor unknown forever.
    #[test]
    fn lost_floor_probe_is_reissued() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let out = dispatcher.tick(&mut store, &link(), 1_000);
        assert!(out.iter().any(|r| sub_of(r) == SUB_RETIRE_THROUGH));
        // Never answered: the pending times out and the next pass probes
        // again instead of sitting at an unknown floor.
        let out = dispatcher.tick(&mut store, &link(), 1_000 + RESPONSE_TIMEOUT_MS + 50);
        let reprobe = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("lost probe re-issued");
        assert_eq!(
            decode_lane_request(&reprobe.body, SUB_RETIRE_THROUGH)
                .unwrap()
                .seq,
            0
        );
    }

    /// The review's wedge: a device floor ahead of every position the
    /// restarted host can still name (its tombstone window is only the
    /// top LANE_HOLE_WINDOW of consumed seqs) must not strand the lane.
    /// RAM_ONLY positions 1..=34 were consumed before the crash; on the
    /// same-boot device positions 1..=2 were already retired, 3..=34 are
    /// provable holes. After the probe adopts floor=2 the tombstones
    /// resolve via QUERY→NotRetained→SKIP, the floor climbs to 34 and a
    /// fresh operation dispatches on seq 35.
    #[test]
    fn restart_rejoins_lane_past_retired_prefix() {
        let dir = std::env::temp_dir().join(format!(
            "routeloom-dispatch-floor-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ops.db");
        // Boot N of the daemon: 34 volatile records claim lane positions
        // under this device's lease, then the process "dies".
        {
            let mut store = SqliteOperationStore::open(&path).unwrap();
            let lineage = store.lineage();
            store.open_epoch((UID, NET), 1_000).unwrap();
            // Submit everything while the records are still HostQueued —
            // the active quota counts DispatchPrepared/GatewayAccepted
            // records, and 34 prepared records would legitimately exceed
            // ACTIVE_CAP=32. The lane positions are what matter here.
            let mut seqs = Vec::new();
            for key in 0..34u8 {
                let SubmitOutcome::Accepted { seq } =
                    store.submit(UID, &request(key, 30_000), 1_000)
                else {
                    panic!("submit failed");
                };
                seqs.push(seq);
            }
            for seq in seqs {
                assert!(matches!(
                    store.prepare_dispatch(seq, lease(), lineage),
                    Ok(PrepareOutcome::Prepared(_))
                ));
            }
        }
        // Restart against the same device boot. Volatile records are gone;
        // tombstones stand in only for the top of the consumed range
        // (dispatch_next=35 → seqs 2..=34); the device retired 1..=2.
        let mut store = SqliteOperationStore::open(&path).unwrap();
        let mut dispatcher = Dispatcher::new(store.lineage());
        let out = dispatcher.tick(&mut store, &link(), 2_000);
        let probe = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("floor probe after restart");
        // The same tick already polls every unresolved attached position:
        // the 33 tombstones stand in for consumed seqs 2..=34.
        let queries: Vec<&DispatchRequest> = out
            .iter()
            .filter(|r| sub_of(r) == SUB_QUERY_DISPATCH)
            .collect();
        assert_eq!(queries.len(), 33, "33 tombstone positions to resolve");
        dispatcher.handle_reply(
            &mut store,
            probe.request,
            &retire_response(HostOpsResult::InvalidRequest, 2),
            2_010,
        );
        assert_eq!(dispatcher.floor, 2, "probe floor adopted");
        let mut pending_queries: Vec<(u64, u64)> = queries
            .iter()
            .map(|q| {
                (
                    q.request,
                    decode_lane_request(&q.body, SUB_QUERY_DISPATCH)
                        .unwrap()
                        .seq,
                )
            })
            .collect();
        for (request, dseq) in pending_queries.drain(..) {
            dispatcher.handle_reply(
                &mut store,
                request,
                &query_response(
                    HostOpsResult::NotRetained,
                    SlotState::Empty,
                    dseq,
                    Evidence::None,
                    [0; 32],
                    [0; 24],
                ),
                2_030,
            );
        }
        // Every hole owes a SKIP; only positions inside floor+32 emit now.
        let out = dispatcher.tick(&mut store, &link(), 2_040);
        let skips: Vec<(u64, u64)> = out
            .iter()
            .filter(|r| sub_of(r) == SUB_SKIP)
            .map(|s| {
                (
                    s.request,
                    decode_lane_request(&s.body, SUB_SKIP).unwrap().seq,
                )
            })
            .collect();
        // Position 2 was settled by floor adoption (already retired);
        // the remaining 32 holes each owe a SKIP.
        assert_eq!(skips.len(), 32);
        for (request, dseq) in skips {
            dispatcher.handle_reply(
                &mut store,
                request,
                &receipt(
                    SUB_SKIP,
                    HostOpsResult::Ok,
                    SlotState::Skipped,
                    dseq,
                    Evidence::None,
                    [0; 32],
                ),
                2_050,
            );
        }
        // The contiguous terminal prefix retires to 34.
        let out = dispatcher.tick(&mut store, &link(), 2_060);
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("retire over resolved tombstones");
        assert_eq!(
            decode_lane_request(&retire.body, SUB_RETIRE_THROUGH)
                .unwrap()
                .seq,
            34
        );
        dispatcher.handle_reply(
            &mut store,
            retire.request,
            &retire_response(HostOpsResult::Ok, 34),
            2_070,
        );
        assert_eq!(dispatcher.floor, 34);
        // The next operation dispatches on the allocator's resumed seq.
        let SubmitOutcome::Accepted { seq } = ({
            let (epoch, _) = store.open_epoch((UID, NET), 2_100).unwrap();
            let mut req = request(0x77, 30_000);
            req.epoch = epoch;
            store.submit(UID, &req, 2_100)
        }) else {
            panic!("submit failed");
        };
        let _ = seq;
        // No mapping yet: the pass emits TIME_SAMPLE; answer it, then the
        // SUBMIT must go out on dispatch_seq 35 — inside the device window.
        let out = dispatcher.tick(&mut store, &link(), 2_110);
        let sample = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_TIME_SAMPLE)
            .expect("fresh mapping needed");
        let nonce = decode_time_sample_request(&sample.body).unwrap().nonce;
        dispatcher.handle_reply(
            &mut store,
            sample.request,
            &time_sample(nonce, 42_000),
            2_120,
        );
        let out = dispatcher.tick(&mut store, &link(), 2_130);
        let submit = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .expect("new op dispatches after floor recovery");
        assert_eq!(decode_submit(&submit.body).unwrap().dispatch_seq, 35);
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Finding 2 control case: a wall-clock rewind that lands still above
    /// `accepted_ms` is invisible to `now < accepted_ms` — the monotonic
    /// budget must still retire the record at real TTL.
    #[test]
    fn rewind_midflight_expires_on_monotonic_budget() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        // Admitted at wall 1000 / mono 1000, ttl 1000 → wall deadline 2000.
        let seq = admitted_mono(&mut store, 0x10, 1_000, 1_000, 1_000);
        // Real elapsed 800ms; the wall clock was rewound 600ms mid-flight
        // and reads 1200 — still after the admit stamp, so the wall-only
        // check saw ~800ms of phantom life.
        dispatcher.tick_mono(&mut store, &offline(), 1_200, 1_800);
        assert_eq!(op(&store, seq).dispatch_state, DispatchState::HostQueued);
        // Real elapsed reaches the TTL while the wall clock shows 600ms.
        dispatcher.tick_mono(&mut store, &offline(), 1_600, 2_000);
        assert_eq!(
            op(&store, seq).dispatch_state,
            DispatchState::ExpiredBeforeDispatch,
            "expiry follows real elapsed time, not the rewound wall clock"
        );
        // An unanchored record (legacy admit / post-restart load) cannot
        // prove trusted elapsed and keeps wall-deadline semantics.
        let legacy = admitted(&mut store, 0x11, 1_000, 1_000);
        dispatcher.tick_mono(&mut store, &offline(), 1_600, 99_999);
        assert_eq!(op(&store, legacy).dispatch_state, DispatchState::HostQueued);
    }

    /// A fresh TIME_SAMPLE after a rewind must rebuild the device deadline
    /// from the monotonic budget — never regain the wall-inflated life.
    #[test]
    fn fresh_sample_after_rewind_gains_no_life() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted_mono(&mut store, 0x20, 1_000, 1_000, 1_000);
        // Lease up at wall 1000 / mono 1000 → probe + TIME_SAMPLE.
        let out = dispatcher.tick_mono(&mut store, &link(), 1_000, 1_000);
        let probe = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .unwrap();
        let sample = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_TIME_SAMPLE)
            .unwrap();
        dispatcher.handle_reply(
            &mut store,
            probe.request,
            &retire_response(HostOpsResult::InvalidRequest, 0),
            1_005,
        );
        let nonce = decode_time_sample_request(&sample.body).unwrap().nonce;
        dispatcher.handle_reply(
            &mut store,
            sample.request,
            &time_sample(nonce, 5_000),
            1_010,
        );
        // Mapping d=5000, h0=1000, h1=1010. Real elapsed 800: the wall
        // clock rewound 600 and reads 1200 while mono reads 1800 — only
        // 200ms of real budget remains of the ttl=1000.
        let out = dispatcher.tick_mono(&mut store, &link(), 1_200, 1_800);
        let submit = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .expect("real budget still permits dispatch");
        let body = decode_submit(&submit.body).unwrap();
        // Capped deadline: min(2000, 1200 + 200) = 1400 → remaining 390,
        // span 400, margin 2 → device deadline 5000 + 388. Uncapped wall
        // arithmetic would have granted ~990ms (≈5988).
        assert_eq!(body.device_deadline, 5_388);
        // At real elapsed 1000 (mono 2000, wall 1400) a still-queued
        // sibling expires even though the wall says 400ms remain.
        let queued = admitted_mono(&mut store, 0x21, 1_000, 1_000, 1_000);
        dispatcher.tick_mono(&mut store, &link(), 1_400, 2_000);
        assert_eq!(
            op(&store, queued).dispatch_state,
            DispatchState::ExpiredBeforeDispatch
        );
        assert_eq!(
            op(&store, seq).dispatch_state,
            DispatchState::DispatchPrepared,
            "already-sent record is governed by the device deadline it was given"
        );
    }

    /// The link-down wait cannot shelter a record past real TTL either:
    /// expiry while reconnecting consults the same monotonic budget.
    #[test]
    fn reconnect_wait_past_ttl_expires_on_monotonic_budget() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let seq = admitted_mono(&mut store, 0x22, 1_000, 1_000, 1_000);
        // Link down the whole time; real elapsed 1200ms, wall shows 200.
        dispatcher.tick_mono(&mut store, &offline(), 1_200, 2_200);
        assert_eq!(
            op(&store, seq).dispatch_state,
            DispatchState::ExpiredBeforeDispatch
        );
    }

    /// Finding 3: a device-terminal INDETERMINATE head position must not
    /// wedge the retire floor. The host record keeps INDETERMINATE (the
    /// outcome is honestly unknown) but the lane position is confirmed
    /// terminal — the gateway's send responsibility ended and 04 §5 lets
    /// the floor pass it once the evidence is committed.
    #[test]
    fn device_terminal_indeterminate_head_unblocks_retire() {
        let mut store = MemoryOperationStore::new([7; 16]);
        let mut dispatcher = Dispatcher::new([7; 16]);
        let first = admitted(&mut store, 0x30, 30_000, 1_000);
        let s1 = drive_to_submit(&mut dispatcher, &mut store, 1_000);
        // seq 1: the device reports Failed — terminal on the lane, honest
        // INDETERMINATE on the host record, never concluded.
        let hash1 = op(&store, first).hash;
        dispatcher.handle_reply(
            &mut store,
            s1.request,
            &receipt(
                host_ops::SUB_SUBMIT,
                HostOpsResult::Ok,
                SlotState::Failed,
                1,
                Evidence::None,
                hash1,
            ),
            1_050,
        );
        let record = op(&store, first);
        assert_eq!(record.dispatch_state, DispatchState::Indeterminate);
        assert!(!record.concluded());
        assert!(record.dispatch.as_ref().unwrap().device_terminal);
        // seq 2 Delivered; 31 more queued ops fill the window behind them.
        let second = admitted(&mut store, 0x31, 30_000, 1_055);
        let out = dispatcher.tick(&mut store, &link(), 1_060);
        let s2 = out
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .expect("second submit");
        // The confirmed-terminal head already lets the floor past seq 1.
        let r1 = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("retire through the terminal head");
        assert_eq!(
            decode_lane_request(&r1.body, SUB_RETIRE_THROUGH)
                .unwrap()
                .seq,
            1
        );
        dispatcher.handle_reply(
            &mut store,
            r1.request,
            &retire_response(HostOpsResult::Ok, 1),
            1_065,
        );
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
        for i in 0..31u8 {
            admitted(&mut store, 0x40 + i, 30_000, 1_100);
        }
        let out = dispatcher.tick(&mut store, &link(), 1_200);
        let submits = out
            .iter()
            .filter(|r| sub_of(r) == host_ops::SUB_SUBMIT)
            .count();
        // floor=1 frees position 33 — the regression proof: before the fix
        // the floor wedged at 0 and only 30 of the 31 queued ops could go.
        assert_eq!(submits, 31, "retired head frees the 33rd position");
        // The Failed head is device-terminal: the retire prefix must pass
        // it — before the fix, `concluded()` gated the walk and the floor
        // never moved, wedging every send behind position 33.
        let retire = out
            .iter()
            .find(|r| sub_of(r) == SUB_RETIRE_THROUGH)
            .expect("retire must pass the device-terminal head");
        assert_eq!(
            decode_lane_request(&retire.body, SUB_RETIRE_THROUGH)
                .unwrap()
                .seq,
            2
        );
        dispatcher.handle_reply(
            &mut store,
            retire.request,
            &retire_response(HostOpsResult::Ok, 2),
            1_210,
        );
        assert_eq!(dispatcher.floor, 2);
        // The head record keeps its honest INDETERMINATE outcome — the
        // position retired, the long-term tracking did not change.
        assert_eq!(
            op(&store, first).dispatch_state,
            DispatchState::Indeterminate
        );
    }

    // ---- Gateway registration lane (05-wire-api.md §5.6) ----

    /// A live snapshot bound to authenticated session 7 on the attached
    /// gateway — the shape the lane needs before it emits 0x10.
    fn gw_link() -> LinkSnapshot {
        let mut link = link();
        link.gateway_ops = true;
        link.session = 7;
        link.host_boot = HOST_BOOT;
        link
    }

    fn register_response(result: GatewayOpsResult, lease_ms: u32) -> Vec<u8> {
        host_ops::encode_host_register_response(&host_ops::HostRegisterResponse {
            result: result as u16,
            token: [0xa1; 16],
            gateway_boot: 0x999,
            host_digest: [0x44; 32],
            lease_ms,
        })
    }

    fn register_of(requests: &[DispatchRequest]) -> Option<&DispatchRequest> {
        requests
            .iter()
            .find(|r| sub_of(r) == host_ops::SUB_HOST_REGISTER)
    }

    #[test]
    fn register_lane_binds_session_and_publishes_mirror() {
        let mut store = MemoryOperationStore::new([0xab; 16]);
        let mut dispatcher = Dispatcher::new([0x77; 16]);
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_000, 2_000);
        let register = register_of(&out).expect("0x10 emitted for a live session");
        let request = host_ops::decode_host_register(&register.body).unwrap();
        assert_eq!(request.network, NET);
        assert_eq!(request.host_boot, HOST_BOOT);
        assert_eq!(request.lease_ms, HOST_REGISTER_LEASE_REQUEST_MS);
        // Nothing published until the device answers.
        assert!(dispatcher.take_gateway_publish().is_none());
        // One 0x10 in flight: an immediate re-tick emits nothing new.
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_010, 2_010);
        assert!(register_of(&out).is_none());
        dispatcher.handle_reply(
            &mut store,
            register.request,
            &register_response(GatewayOpsResult::Ok, 10_000),
            1_020,
        );
        let Some(Some(registration)) = dispatcher.take_gateway_publish() else {
            panic!("grant must publish the mirror");
        };
        assert_eq!(registration.token, [0xa1; 16]);
        assert_eq!(registration.gateway_boot, 0x999);
        assert_eq!(registration.host_digest, [0x44; 32]);
        assert_eq!(registration.egress, NODE);
        assert_eq!(registration.usb_session, 7);
        // The lease deadline is anchored at the REQUEST's monotonic stamp
        // (2_000) — strictly earlier than any response-time grant.
        assert_eq!(registration.lease_deadline_mono, 2_000 + 10_000);
        // Publish drained once — a second take returns None.
        assert!(dispatcher.take_gateway_publish().is_none());
    }

    #[test]
    fn register_renews_at_half_the_granted_lease() {
        let mut store = MemoryOperationStore::new([0xab; 16]);
        let mut dispatcher = Dispatcher::new([0x77; 16]);
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_000, 2_000);
        let register = register_of(&out).expect("0x10 emitted");
        dispatcher.handle_reply(
            &mut store,
            register.request,
            &register_response(GatewayOpsResult::Ok, 10_000),
            1_020,
        );
        dispatcher.take_gateway_publish();
        // Before emit_mono + lease/2 there is nothing to renew.
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 3_000, 6_999);
        assert!(register_of(&out).is_none());
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 3_100, 7_001);
        let renewal = register_of(&out).expect("renewal due at half lease");
        // The renewal re-asks under the same binding.
        let request = host_ops::decode_host_register(&renewal.body).unwrap();
        assert_eq!(request.host_boot, HOST_BOOT);
    }

    #[test]
    fn register_busy_retries_on_the_retry_floor() {
        let mut store = MemoryOperationStore::new([0xab; 16]);
        let mut dispatcher = Dispatcher::new([0x77; 16]);
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_000, 2_000);
        let register = register_of(&out).expect("0x10 emitted");
        dispatcher.handle_reply(
            &mut store,
            register.request,
            &register_response(GatewayOpsResult::Busy, 0),
            1_020,
        );
        // Busy publishes nothing and re-emits only after the retry floor.
        assert!(dispatcher.take_gateway_publish().is_none());
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_100, 2_100);
        assert!(register_of(&out).is_none());
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_300, 2_260);
        assert!(register_of(&out).is_some());
    }

    #[test]
    fn register_refusal_is_noted_and_never_published() {
        let mut store = MemoryOperationStore::new([0xab; 16]);
        let mut dispatcher = Dispatcher::new([0x77; 16]);
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_000, 2_000);
        let register = register_of(&out).expect("0x10 emitted");
        dispatcher.handle_reply(
            &mut store,
            register.request,
            &register_response(GatewayOpsResult::Denied, 0),
            1_020,
        );
        assert!(dispatcher.take_gateway_publish().is_none());
        let notes = dispatcher.take_notes();
        assert!(
            notes.iter().any(|n| n.contains("host register refused")),
            "{notes:?}"
        );
    }

    #[test]
    fn register_lane_needs_family_session_and_incarnation() {
        let mut store = MemoryOperationStore::new([0xab; 16]);
        let mut dispatcher = Dispatcher::new([0x77; 16]);
        // No gateway family → nothing.
        let mut no_family = gw_link();
        no_family.gateway_ops = false;
        let out = dispatcher.tick_mono(&mut store, &no_family, 1_000, 2_000);
        assert!(register_of(&out).is_none());
        // Session 0 (unauthenticated) → nothing.
        let mut no_session = gw_link();
        no_session.session = 0;
        let out = dispatcher.tick_mono(&mut store, &no_session, 1_000, 2_000);
        assert!(register_of(&out).is_none());
        // No daemon incarnation → nothing.
        let mut no_boot = gw_link();
        no_boot.host_boot = 0;
        let out = dispatcher.tick_mono(&mut store, &no_boot, 1_000, 2_000);
        assert!(register_of(&out).is_none());
    }

    #[test]
    fn session_change_drops_mirror_and_registers_fresh() {
        let mut store = MemoryOperationStore::new([0xab; 16]);
        let mut dispatcher = Dispatcher::new([0x77; 16]);
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_000, 2_000);
        let register = register_of(&out).expect("0x10 emitted");
        dispatcher.handle_reply(
            &mut store,
            register.request,
            &register_response(GatewayOpsResult::Ok, 10_000),
            1_020,
        );
        assert!(matches!(dispatcher.take_gateway_publish(), Some(Some(_))));
        // A new authenticated session can never inherit the old token:
        // the mirror is cleared and a fresh 0x10 goes out immediately.
        let mut new_session = gw_link();
        new_session.session = 8;
        let out = dispatcher.tick_mono(&mut store, &new_session, 1_100, 2_100);
        assert!(matches!(dispatcher.take_gateway_publish(), Some(None)));
        assert!(register_of(&out).is_some());
    }

    #[test]
    fn lane_loss_publishes_mirror_clear() {
        let mut store = MemoryOperationStore::new([0xab; 16]);
        let mut dispatcher = Dispatcher::new([0x77; 16]);
        let out = dispatcher.tick_mono(&mut store, &gw_link(), 1_000, 2_000);
        let register = register_of(&out).expect("0x10 emitted");
        dispatcher.handle_reply(
            &mut store,
            register.request,
            &register_response(GatewayOpsResult::Ok, 10_000),
            1_020,
        );
        dispatcher.take_gateway_publish();
        // Link down → the dead-session binding is unpublished, and the
        // lane stops emitting until a live session returns.
        let out = dispatcher.tick_mono(&mut store, &offline(), 1_100, 2_100);
        assert!(matches!(dispatcher.take_gateway_publish(), Some(None)));
        assert!(register_of(&out).is_none());
    }

    // ---- Gateway ingress → ReceiveLog → 0x12 (05-wire-api.md §5.6) ----

    /// A well-formed Service Submit prefix for `token`/`boot` carrying
    /// `payload_len` — exactly the shape `queue_ingress` synthesizes on
    /// the device.
    fn submit_prefix(token: [u8; 16], boot: u64, payload_len: usize) -> [u8; 32] {
        let mut prefix = [0u8; 32];
        prefix[0] = 1; // service payload version
        prefix[1] = 3; // ServiceSubtype::Submit
        prefix[host_ops::SERVICE_PREFIX_SCOPE_OFFSET] = 2; // host receive RAM
        prefix[host_ops::SERVICE_PREFIX_TOKEN_OFFSET..host_ops::SERVICE_PREFIX_TOKEN_OFFSET + 16]
            .copy_from_slice(&token);
        prefix[host_ops::SERVICE_PREFIX_BOOT_OFFSET..host_ops::SERVICE_PREFIX_BOOT_OFFSET + 8]
            .copy_from_slice(&boot.to_be_bytes());
        prefix[host_ops::SERVICE_PREFIX_LEN_OFFSET..host_ops::SERVICE_PREFIX_LEN_OFFSET + 2]
            .copy_from_slice(&(payload_len as u16).to_be_bytes());
        prefix
    }

    /// Encode a device-issued 0x11 with a digest honestly computed over
    /// prefix+payload — the only way to earn an Ok ACK.
    fn ingress_body(
        prefix: [u8; 32],
        origin: u64,
        msg_session: u32,
        msg_seq: u64,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut digest_input = Vec::with_capacity(32 + payload.len());
        digest_input.extend_from_slice(&prefix);
        digest_input.extend_from_slice(payload);
        host_ops::encode_gateway_ingress(&host_ops::GatewayIngress {
            submit_prefix: prefix,
            ref_origin: origin,
            ref_session: msg_session,
            ref_sequence: msg_seq,
            request_digest: canonical::sha256(&digest_input),
            payload: payload.to_vec(),
        })
        .unwrap()
    }

    fn ack_of(body: &[u8]) -> host_ops::GatewayIngressAck {
        host_ops::decode_gateway_ingress_ack(body).expect("decodable ack")
    }

    /// Daemon state with an authenticated session on the attached gateway.
    fn gw_state() -> State {
        let state = State::default();
        {
            let mut info = state.session.lock().unwrap();
            info.authenticated = true;
            info.id = Some(7);
            info.node = Some(NODE);
            info.boot = Some(BOOT);
            info.network = Some(NET);
            info.capability = Some(CAP_HOST_OPS_V1 | CAP_GATEWAY_ENDPOINT_V1);
        }
        state
    }

    /// Install the host registration mirror the dispatch pass publishes —
    /// `token` is what the device will bind the 0x12 ACK against.
    fn mirror(state: &State, token: [u8; 16], usb_session: u64) {
        state.gateway_lane.set(GatewayRegistration {
            token,
            gateway_boot: BOOT,
            host_digest: [0x9d; 32],
            egress: NODE,
            usb_session,
            lease_deadline_mono: u64::MAX,
        });
    }

    #[test]
    fn ingress_stores_then_acks_ok() {
        let state = gw_state();
        // Loopback shape: the device synthesizes the Service Submit prefix
        // from the registration itself, so prefix token == registration
        // token — the case the existing code happened to answer correctly.
        mirror(&state, [0xa1; 16], 7);
        let prefix = submit_prefix([0xa1; 16], BOOT, 3);
        let body = ingress_body(prefix, 0xdead, 9, 42, &[1, 2, 3]);
        let ack = gateway_ingress_ack(&state, &body, 5_000).expect("ack produced");
        let ack = ack_of(&ack);
        assert_eq!(ack.outcome, GatewayOpsResult::Ok as u16);
        // The ACK echoes the bound reference fields; the token is the
        // registration's (equal to the prefix token on loopback only).
        assert_eq!(ack.token, [0xa1; 16]);
        assert_eq!(ack.ref_origin, 0xdead);
        assert_eq!(ack.ref_session, 9);
        assert_eq!(ack.ref_sequence, 42);
        // And the payload is really in the log — the ACK follows storage.
        let read = {
            let mut log = state.receive_log.lock().unwrap();
            log.read(NET, 0, 8, 5_000, false)
        };
        let crate::receive_log::ReadOutcome::Batch(batch) = read else {
            panic!("stored record must be readable")
        };
        let records = batch.records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload, vec![1, 2, 3]);
        assert_eq!(records[0].origin, 0xdead);
        assert_eq!(records[0].gateway, Some(NODE));
    }

    #[test]
    fn ingress_acks_registration_token_not_prefix_token() {
        // Real mesh ingress: the Service Submit prefix carries the ORIGIN's
        // lease token, which differs from the host registration token. The
        // device binds the ACK with `ack.token == registration_.token` —
        // echoing the prefix token (the old behavior) made every real-path
        // ACK fail binding and the pending ingress expire unproven.
        let state = gw_state();
        mirror(&state, [0x5e; 16], 7);
        let prefix = submit_prefix([0xa1; 16], BOOT, 3);
        let body = ingress_body(prefix, 0xdead, 9, 42, &[1, 2, 3]);
        let ack = gateway_ingress_ack(&state, &body, 5_000).expect("ack produced");
        let ack = ack_of(&ack);
        assert_eq!(ack.outcome, GatewayOpsResult::Ok as u16);
        assert_eq!(
            ack.token, [0x5e; 16],
            "the ACK token is the registration mirror's, not the prefix's"
        );
        // The storage proof still commits to the prefix as received —
        // the payload lands in the log exactly once.
        let read = {
            let mut log = state.receive_log.lock().unwrap();
            log.read(NET, 0, 8, 5_000, false)
        };
        let crate::receive_log::ReadOutcome::Batch(batch) = read else {
            panic!("stored record must be readable")
        };
        assert_eq!(batch.records.len(), 1);
        // Refusals bind the same way — an Invalid outcome still carries
        // the registration token so the device can correlate it.
        let foreign = submit_prefix([0xa1; 16], BOOT + 1, 1);
        let body = ingress_body(foreign, 0xdead, 9, 43, &[9]);
        let ack = ack_of(&gateway_ingress_ack(&state, &body, 5_000).unwrap());
        assert_eq!(ack.outcome, GatewayOpsResult::Invalid as u16);
        assert_eq!(ack.token, [0x5e; 16]);
    }

    #[test]
    fn ingress_without_bound_mirror_cannot_bind_the_ack() {
        // No mirror published (or one bound to a dead session): no honest
        // token exists — the ACK echoes the presented prefix token so the
        // device drops it as unbound rather than accepting a binding the
        // host cannot vouch for. The storage outcome still reports truth.
        let state = gw_state();
        let prefix = submit_prefix([0x77; 16], BOOT, 1);
        let body = ingress_body(prefix, 0xdead, 9, 42, &[9]);
        let ack = ack_of(&gateway_ingress_ack(&state, &body, 5_000).unwrap());
        assert_eq!(ack.outcome, GatewayOpsResult::Ok as u16);
        assert_eq!(ack.token, [0x77; 16]);
        // A mirror minted under a DIFFERENT usb session is equally unusable.
        let state = gw_state();
        mirror(&state, [0x5e; 16], 8);
        let ack = ack_of(&gateway_ingress_ack(&state, &body, 5_000).unwrap());
        assert_eq!(ack.outcome, GatewayOpsResult::Ok as u16);
        assert_eq!(ack.token, [0x77; 16]);
    }

    #[test]
    fn ingress_duplicate_replays_ok_not_conflict() {
        let state = gw_state();
        let prefix = submit_prefix([0xa1; 16], BOOT, 2);
        let body = ingress_body(prefix, 0xdead, 9, 42, &[7, 7]);
        let first = gateway_ingress_ack(&state, &body, 5_000).unwrap();
        assert_eq!(ack_of(&first).outcome, GatewayOpsResult::Ok as u16);
        // G03: the resend path depends on a second delivery of identical
        // bytes being as good as the first — Ok again, never Conflict.
        let second = gateway_ingress_ack(&state, &body, 5_010).unwrap();
        assert_eq!(ack_of(&second).outcome, GatewayOpsResult::Ok as u16);
        let read = {
            let mut log = state.receive_log.lock().unwrap();
            log.read(NET, 0, 8, 5_010, false)
        };
        let crate::receive_log::ReadOutcome::Batch(batch) = read else {
            panic!()
        };
        let records = batch.records;
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn ingress_conflict_never_overwrites_or_acks_ok() {
        let state = gw_state();
        let prefix = submit_prefix([0xa1; 16], BOOT, 2);
        let first = ingress_body(prefix, 0xdead, 9, 42, &[1, 1]);
        gateway_ingress_ack(&state, &first, 5_000).unwrap();
        // Same MessageKey, different payload: the existing record is
        // authoritative — the answer is non-success and the log keeps
        // the first bytes.
        let mut conflicting = ingress_body(prefix, 0xdead, 9, 42, &[2, 2]);
        let ack = gateway_ingress_ack(&state, &conflicting, 5_010).unwrap();
        assert_eq!(ack_of(&ack).outcome, GatewayOpsResult::Invalid as u16);
        let read = {
            let mut log = state.receive_log.lock().unwrap();
            log.read(NET, 0, 8, 5_010, false)
        };
        let crate::receive_log::ReadOutcome::Batch(batch) = read else {
            panic!()
        };
        let records = batch.records;
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].payload, vec![1, 1]);
        conflicting.clear();
    }

    #[test]
    fn ingress_bad_digest_cannot_ack_success() {
        let state = gw_state();
        let prefix = submit_prefix([0xa1; 16], BOOT, 2);
        let mut body = ingress_body(prefix, 0xdead, 9, 42, &[1, 2]);
        // Corrupt the digest — storage must never be claimed for bytes
        // that do not hash to the bound value. The digest sits at inner
        // offset 4 (head) + 52 (prefix32 + refkey20) .. 84.
        body[60] ^= 0xFF;
        let ack = gateway_ingress_ack(&state, &body, 5_000).unwrap();
        assert_eq!(ack_of(&ack).outcome, GatewayOpsResult::Invalid as u16);
        let read = {
            let mut log = state.receive_log.lock().unwrap();
            log.read(NET, 0, 8, 5_000, false)
        };
        let crate::receive_log::ReadOutcome::Batch(batch) = read else {
            panic!()
        };
        let records = batch.records;
        assert!(records.is_empty());
    }

    #[test]
    fn ingress_malformed_prefix_and_wrong_boot_are_invalid() {
        let state = gw_state();
        // Scope 1 (SDK RAM) is not this daemon's endpoint — refused.
        let mut prefix = submit_prefix([0xa1; 16], BOOT, 1);
        prefix[host_ops::SERVICE_PREFIX_SCOPE_OFFSET] = 1;
        let body = ingress_body(prefix, 0xdead, 9, 42, &[9]);
        let ack = gateway_ingress_ack(&state, &body, 5_000).unwrap();
        assert_eq!(ack_of(&ack).outcome, GatewayOpsResult::Invalid as u16);
        // A prefix bound to a different adapter boot could not have been
        // accepted on this session.
        let foreign = submit_prefix([0xa1; 16], BOOT + 1, 1);
        let body = ingress_body(foreign, 0xdead, 9, 43, &[9]);
        let ack = gateway_ingress_ack(&state, &body, 5_000).unwrap();
        assert_eq!(ack_of(&ack).outcome, GatewayOpsResult::Invalid as u16);
    }

    #[test]
    fn ingress_without_session_is_invalid_not_stored() {
        let state = State::default(); // unauthenticated
        let prefix = submit_prefix([0xa1; 16], BOOT, 1);
        let body = ingress_body(prefix, 0xdead, 9, 42, &[9]);
        let ack = gateway_ingress_ack(&state, &body, 5_000).unwrap();
        assert_eq!(ack_of(&ack).outcome, GatewayOpsResult::Invalid as u16);
    }

    #[test]
    fn ingress_undecodable_gets_no_ack() {
        let state = gw_state();
        assert!(
            gateway_ingress_ack(&state, &[1, host_ops::SUB_GATEWAY_INGRESS, 0, 2], 5_000).is_none()
        );
    }

    #[test]
    fn ingress_at_network_capacity_acks_busy_never_stored() {
        let state = gw_state();
        // Saturate the network table with other networks first: the
        // session's network then lands beyond MAX_NETWORKS, and the honest
        // answer is the retryable Busy — the record is never claimed.
        {
            let mut log = state.receive_log.lock().unwrap();
            for network in 100..100 + crate::receive_log::MAX_NETWORKS as u64 {
                let outcome = log.ingest(
                    crate::receive_log::Ingress {
                        network,
                        gateway: None,
                        origin: 1,
                        msg_session: 1,
                        msg_seq: 1,
                        payload: vec![0xaa],
                    },
                    4_000,
                );
                assert!(matches!(
                    outcome,
                    crate::receive_log::IngestOutcome::Stored { .. }
                ));
            }
        }
        let prefix = submit_prefix([0xa1; 16], BOOT, 1);
        let body = ingress_body(prefix, 0xdead, 9, 42, &[9]);
        let ack = gateway_ingress_ack(&state, &body, 5_000).expect("ack produced");
        assert_eq!(ack_of(&ack).outcome, GatewayOpsResult::Busy as u16);
        let read = {
            let mut log = state.receive_log.lock().unwrap();
            log.read(NET, 0, 8, 5_000, false)
        };
        let crate::receive_log::ReadOutcome::Batch(batch) = read else {
            panic!("read on a missing network answers an empty batch")
        };
        assert!(batch.records.is_empty());
    }

    // --- Config lane dispatch (scope-gateway-config P5) ------------------------
    //
    // The api1 tests cannot reach this glue: the dispatcher's wire-id remap,
    // the emit/reply/drop/done plumbing, and the single-in-flight gate that
    // keeps a queued op PENDING behind a busy lane.

    /// A config lane for dispatch tests — the same dev-profile issuer the
    /// live loop builds (`config_lane_for`), over deterministic entropy.
    fn test_config_lane() -> ConfigLane {
        let issuer = ConfigIssuer::new(config_dev_key(crate::DEV_SECRET).to_vec(), NET, 0x42, 100);
        let mut counter = 0x30_u8;
        ConfigLane::new(
            issuer,
            1,
            Box::new(move |out: &mut [u8]| {
                counter = counter.wrapping_add(1);
                for b in out.iter_mut() {
                    *b = counter;
                }
            }),
        )
    }

    fn config_challenge_reply(target: u64, ch: &ControlChallenge) -> Vec<u8> {
        let mut body = EncodedPayload::default();
        control_challenge_encode(ch, &mut body).unwrap();
        host_ops::encode_config_reply(
            host_ops::SUB_CONFIG_CHALLENGE,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target,
                body: body.view().to_vec(),
            },
        )
        .unwrap()
    }

    fn config_challenge() -> ControlChallenge {
        ControlChallenge {
            config_namespace: 1,
            schema: 1,
            client_nonce: [0x11; 16],
            target_boot: 0x99,
            challenge_nonce: [0x22; 16],
            revision: 3,
            active_hash: [0x44; 32],
            valid_for_ms: 5_000,
        }
    }

    /// The wire request id of the config emit in a tick's queue, matched by
    /// the config subcommand byte (`body[1]`).
    fn config_wire(out: &[DispatchRequest], sub: u8) -> u64 {
        out.iter()
            .find(|r| r.body.get(1) == Some(&sub))
            .expect("a config emit this pass")
            .request
    }

    fn challenge_request() -> ConfigRequest {
        ConfigRequest::Challenge {
            target: 0x99,
            config_namespace: 1,
            schema: 1,
        }
    }

    fn status_request() -> ConfigRequest {
        ConfigRequest::Status {
            target: 0x99,
            config_namespace: 1,
            operation_id: [0xaa; 16],
        }
    }

    fn control_status(op_id: [u8; 16]) -> ControlStatus {
        ControlStatus {
            config_namespace: 1,
            operation_id: op_id,
            decision_revision: 5,
            active_revision: 5,
            phase: ConfigPhase::Active,
            reason: ConfigReason::Ok,
            active_hash: [0x33; 32],
        }
    }

    fn config_status_reply(target: u64, status: &ControlStatus) -> Vec<u8> {
        let mut body = EncodedPayload::default();
        control_status_encode(status, &mut body).unwrap();
        host_ops::encode_config_reply(
            host_ops::SUB_CONFIG_STATUS,
            &host_ops::ConfigReply {
                result: ConfigOpsResult::Ok as u16,
                target,
                body: body.view().to_vec(),
            },
        )
        .unwrap()
    }

    fn propose_request() -> ConfigRequest {
        ConfigRequest::Propose {
            target: 0x99,
            config_namespace: 1,
            schema: 1,
            base_snapshot: vec![0xaa],
            patch: vec![ConfigField {
                field_id: 1,
                field_type: ConfigFieldType::U8,
                value: vec![1],
            }],
            apply_budget_ms: 0,
        }
    }

    fn recover_request() -> ConfigRequest {
        ConfigRequest::Recover {
            target: 0x99,
            config_namespace: 1,
            schema: 1,
            mode: 0,
            new_store_generation: 4,
            new_revision: 8,
            snapshot_hash: [0xAB; 32],
            baseline: Vec::new(),
        }
    }

    #[test]
    fn config_lane_round_trip_through_the_dispatcher() {
        let mut dispatcher = Dispatcher::new([9; 16]);
        dispatcher.attach_config(test_config_lane(), 0x42, 1);
        let mut store = MemoryOperationStore::new([0xab; 16]);
        assert!(!dispatcher.config_busy());
        dispatcher.config_submit(&mut store, &link(), 7, challenge_request(), 1_000);
        assert!(
            dispatcher.config_busy(),
            "a submit leaves a request in flight"
        );
        // The first Emit rides this pass's wire queue under a dispatcher-
        // assigned wire request id, remapped from the lane's own id.
        let out = dispatcher.tick(&mut store, &link(), 1_000);
        let wire = config_wire(&out, host_ops::SUB_CONFIG_CHALLENGE);
        // A valid ControlChallenge reply on that wire id resolves the op —
        // the echo must carry the nonce the issuer drew, so replay it from
        // the emitted request body exactly as the device would.
        let emit = out
            .iter()
            .find(|r| r.body.get(1) == Some(&host_ops::SUB_CONFIG_CHALLENGE))
            .expect("the challenge emit");
        let mut ch = config_challenge();
        ch.client_nonce = host_ops::decode_config_challenge(&emit.body)
            .unwrap()
            .client_nonce;
        dispatcher.handle_reply(&mut store, wire, &config_challenge_reply(0x99, &ch), 1_050);
        assert_eq!(
            dispatcher.take_config_done(),
            vec![(7, ConfigOutcome::Challenged(ch))]
        );
        assert!(!dispatcher.config_busy());
    }

    #[test]
    fn config_emit_drop_resolves_an_honest_timeout() {
        let mut dispatcher = Dispatcher::new([9; 16]);
        dispatcher.attach_config(test_config_lane(), 0x42, 1);
        let mut store = MemoryOperationStore::new([0xab; 16]);
        dispatcher.config_submit(&mut store, &link(), 11, challenge_request(), 1_000);
        let out = dispatcher.tick(&mut store, &link(), 1_000);
        let wire = config_wire(&out, host_ops::SUB_CONFIG_CHALLENGE);
        // The outbound queue refused the frame — provably never reached the
        // device, so the in-flight query resolves Timeout, never a claim.
        dispatcher.emit_dropped(&mut store, wire);
        assert_eq!(
            dispatcher.take_config_done(),
            vec![(11, ConfigOutcome::Timeout)]
        );
    }

    #[test]
    fn config_submit_refuses_without_capability_or_authority() {
        let mut store = MemoryOperationStore::new([0xab; 16]);
        // A link that cannot serve config refuses honestly — not fabricated.
        let mut dispatcher = Dispatcher::new([9; 16]);
        dispatcher.attach_config(test_config_lane(), 0x42, 1);
        let mut dead = link();
        dead.config_ops = false;
        dispatcher.config_submit(&mut store, &dead, 21, challenge_request(), 1_000);
        assert_eq!(
            dispatcher.take_config_done(),
            vec![(21, ConfigOutcome::Refused(ConfigOpsResult::Unsupported))]
        );
        // A Propose against a lane with no configured authority is Denied
        // before any emit — the daemon cannot sign what it has no issuer for.
        let mut no_auth = Dispatcher::new([9; 16]);
        no_auth.attach_config(test_config_lane(), 0, 1);
        no_auth.config_submit(&mut store, &link(), 22, propose_request(), 1_000);
        assert_eq!(
            no_auth.take_config_done(),
            vec![(22, ConfigOutcome::Refused(ConfigOpsResult::Denied))]
        );
        // The authority-0 lane still answers a Challenge — queries never sign.
        no_auth.config_submit(&mut store, &link(), 23, challenge_request(), 1_000);
        let out = no_auth.tick(&mut store, &link(), 1_000);
        let wire = config_wire(&out, host_ops::SUB_CONFIG_CHALLENGE);
        let emit = out
            .iter()
            .find(|r| r.body.get(1) == Some(&host_ops::SUB_CONFIG_CHALLENGE))
            .expect("the challenge emit");
        let mut ch = config_challenge();
        ch.client_nonce = host_ops::decode_config_challenge(&emit.body)
            .unwrap()
            .client_nonce;
        no_auth.handle_reply(&mut store, wire, &config_challenge_reply(0x99, &ch), 1_050);
        assert_eq!(
            no_auth.take_config_done(),
            vec![(23, ConfigOutcome::Challenged(ch))]
        );
    }

    #[test]
    fn config_recover_submit_is_gated_and_memory_honest() {
        // A Recover submit passes the same dispatch gates as Propose
        // (capability, authority, liveness) and then refuses on a
        // memory-only store — recovery issuance needs the durable
        // outbox, and the refusal carries no fabricated bytes.
        let mut dispatcher = Dispatcher::new([9; 16]);
        dispatcher.attach_config(test_config_lane(), 0x42, 1);
        let mut store = MemoryOperationStore::new([0xab; 16]);
        dispatcher.config_submit(&mut store, &link(), 31, recover_request(), 1_000);
        assert_eq!(
            dispatcher.take_config_done(),
            vec![(31, ConfigOutcome::Refused(ConfigOpsResult::Unsupported))]
        );
        assert!(!dispatcher.config_busy());
        // No authority configured: Denied before the lane runs.
        let mut no_auth = Dispatcher::new([9; 16]);
        no_auth.attach_config(test_config_lane(), 0, 1);
        no_auth.config_submit(&mut store, &link(), 32, recover_request(), 1_000);
        assert_eq!(
            no_auth.take_config_done(),
            vec![(32, ConfigOutcome::Refused(ConfigOpsResult::Denied))]
        );
    }

    #[test]
    fn config_reply_with_a_foreign_echo_is_a_protocol_error() {
        // Regression: the device echoes the challenge's client_nonce / the
        // status's operation_id from the QUERY it answered. A reply that
        // carries someone else's echo — collision, replug-stale, buggy —
        // must not resolve the current op: PROTOCOL_ERROR, never a claim.
        let mut dispatcher = Dispatcher::new([9; 16]);
        dispatcher.attach_config(test_config_lane(), 0x42, 1);
        let mut store = MemoryOperationStore::new([0xab; 16]);
        dispatcher.config_submit(&mut store, &link(), 7, challenge_request(), 1_000);
        let out = dispatcher.tick(&mut store, &link(), 1_000);
        let wire = config_wire(&out, host_ops::SUB_CONFIG_CHALLENGE);
        let ch = config_challenge(); // nonce 0x11.. — never what we emitted
        dispatcher.handle_reply(&mut store, wire, &config_challenge_reply(0x99, &ch), 1_050);
        assert_eq!(
            dispatcher.take_config_done(),
            vec![(7, ConfigOutcome::ProtocolError)]
        );
        // Same for a Status reply echoing a different operation id.
        let mut dispatcher = Dispatcher::new([9; 16]);
        dispatcher.attach_config(test_config_lane(), 0x42, 1);
        dispatcher.config_submit(&mut store, &link(), 8, status_request(), 1_000);
        let out = dispatcher.tick(&mut store, &link(), 1_000);
        let wire = config_wire(&out, host_ops::SUB_CONFIG_QUERY);
        dispatcher.handle_reply(
            &mut store,
            wire,
            &config_status_reply(0x99, &control_status([0xbb; 16])),
            1_050,
        );
        assert_eq!(
            dispatcher.take_config_done(),
            vec![(8, ConfigOutcome::ProtocolError)]
        );
    }

    #[test]
    fn config_ops_evict_resolved_records_before_refusing() {
        // Regression: the inbox bound is separate from the record bound.
        // Resolved records are memory, not capacity — at the cap they are
        // evicted oldest-first; refusal is only for a table full of LIVE
        // records (all-live refusal: config_ops_refuse_only_when_all_live).
        let ops = crate::dispatch::ConfigOps::default();
        let mut live = Vec::new();
        for _ in 0..CONFIG_RECORD_CAP {
            let op_id = ops
                .submit(challenge_request(), "x".to_string(), NET, 9, 0)
                .unwrap();
            live.push(op_id);
            // Drain the inbox so the record bound, not the inbox bound,
            // is what the table is full of — in-flight records are live.
            ops.take_request();
        }
        // Resolve the first half — they become eviction candidates.
        for &op_id in &live[..CONFIG_RECORD_CAP / 2] {
            ops.resolve(op_id, ConfigOutcome::Timeout, 1_000);
        }
        // A fresh submit fits: resolved records yield, not refuse.
        let next = ops.submit(challenge_request(), "y".to_string(), NET, 9, 0);
        assert!(next.is_ok(), "resolved records must not count as capacity");
        // The newest resolved records still poll; the oldest are gone.
        assert_eq!(
            ops.get(live[CONFIG_RECORD_CAP / 2]).map(|r| r.op_id),
            Some(live[CONFIG_RECORD_CAP / 2])
        );
        assert!(ops.get(live[0]).is_none(), "oldest resolved evicted first");
    }

    #[test]
    fn config_ops_refuse_only_when_all_live() {
        // The record cap's refusal is reserved for genuine occupancy: 128
        // records still queued or in flight. (Draining the inbox keeps the
        // records live — take_request does not resolve them.)
        let ops = crate::dispatch::ConfigOps::default();
        for _ in 0..CONFIG_RECORD_CAP {
            ops.submit(challenge_request(), "x".to_string(), NET, 9, 0)
                .unwrap();
            ops.take_request();
        }
        assert!(
            ops.submit(challenge_request(), "y".to_string(), NET, 9, 0)
                .is_err(),
            "128 live records must refuse — the table is honestly full"
        );
        // The inbox bound is independent: 32 undrained submits refuse even
        // with the record table nearly empty.
        let ops = crate::dispatch::ConfigOps::default();
        for _ in 0..CONFIG_INBOX_CAP {
            ops.submit(challenge_request(), "x".to_string(), NET, 9, 0)
                .unwrap();
        }
        assert!(ops
            .submit(challenge_request(), "y".to_string(), NET, 9, 0)
            .is_err());
    }

    #[test]
    fn config_op_ids_are_namespaced_by_host_boot() {
        // After a reboot the RAM-only table restarts its counter — a stale
        // caller's `cfg...1` must not reach a NEW op. The op id embeds a
        // boot tag in the high 32 bits (the folded host_boot, bit 0 forced
        // so the tag is never zero); two boots can never mint the same
        // token for the same sequence.
        let ops_a = crate::dispatch::ConfigOps::with_boot(0x1122_3344);
        let ops_b = crate::dispatch::ConfigOps::with_boot(0x5566_7788);
        let a = ops_a
            .submit(challenge_request(), "a".to_string(), NET, 9, 0)
            .unwrap();
        let b = ops_b
            .submit(challenge_request(), "b".to_string(), NET, 9, 0)
            .unwrap();
        let tag_a = 0x1122_3344_u32 | 1;
        let tag_b = 0x5566_7788_u32 | 1;
        assert_eq!(a >> 32, u64::from(tag_a));
        assert_eq!(b >> 32, u64::from(tag_b));
        assert_ne!(a >> 32, 0, "the tag word is never zero");
        assert_ne!(a, b, "same counter, different boot — different token");
        assert_ne!(a & 0xffff_ffff, 0, "the sequence never starts at zero");
        // Per-boot counters count up within their own namespace.
        let a2 = ops_a
            .submit(challenge_request(), "c".to_string(), NET, 9, 0)
            .unwrap();
        assert_eq!(a2 - a, 1);
    }

    #[test]
    fn config_ops_inbox_pops_one_at_a_time_fifo() {
        // The busy-lane gate (`config_busy`) keeps a queued op PENDING; the
        // inbox hands out one op per free pass in FIFO order, never draining
        // a waiting op just to refuse it Busy.
        let ops = crate::dispatch::ConfigOps::default();
        let a = ops
            .submit(challenge_request(), "a".to_string(), NET, 9, 0)
            .unwrap();
        let b = ops
            .submit(challenge_request(), "b".to_string(), NET, 9, 0)
            .unwrap();
        assert_eq!(ops.take_request().map(|q| q.op_id), Some(a));
        assert_eq!(ops.take_request().map(|q| q.op_id), Some(b));
        assert!(ops.take_request().is_none());
    }
}
