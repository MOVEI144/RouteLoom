//! group_delivery_v1 lane (USB HostOps 0x50-0x52) and the RAM operation
//! table behind API1 `group.send` / `group.get` and the `group_settled`
//! event (docs/design/sdk-v1/group-delivery.md §11, docs/spec/host.md §10).
//!
//! Flow. `group.send` admits one record into [`GroupOps`] (HOST_QUEUED) and
//! wakes the lane thread, which writes a 0x50 GROUP_SEND on the single
//! writer queue (DEVICE_PENDING). The gateway answers at once with a 0x51
//! GROUP_STATUS under the same request id: a refusal (REFUSED — e.g.
//! `GROUP_REQUIRES_GATEWAY_SCOPED`, `GROUP_QUEUE_FULL`) or the admitted
//! summary with the group MessageId. An admitted, unsettled message gets
//! exactly one more 0x51 with the FINAL flag under that request id. The
//! lane also polls 0x52 GROUP_QUERY every [`POLL_INTERVAL_MS`] while a
//! record is unsettled — the FINAL push is session-scoped (lost with the
//! USB session) and the device keeps only three push slots, so the poll is
//! what makes a lost push or a reconnect harmless. Every record ends in
//! exactly one terminal state and emits exactly one `group_settled` event.
//!
//! Honesty rules. Counts stay `null` until the device reported them; a
//! frame that may or may not have reached the device ends INDETERMINATE
//! (never retried — a duplicate ALARM would be a second message, not a
//! retransmission); a record that never reached the device ends NOT_SENT.
//!
//! Bounds (RAM only, lost on daemon restart): [`RECORD_CAP`] retained
//! records (terminal ones evicted oldest-first), at most [`QUEUE_CAP`]
//! host-queued and [`LIVE_CAP`] unsettled records, [`TOMBSTONE_CAP`]
//! remembered idempotency identities of evicted records, [`INBOX_CAP`]
//! device replies waiting for the lane.

use routeloom_protocol::group_ops::{
    decode_group_status, encode_group_query, encode_group_send, group_ops_sub, GroupQuery,
    GroupSend, GroupStatus, CAP_GROUP_DELIVERY_V1, GROUP_ALL, GROUP_PAYLOAD_MAX, MAX_LIFETIME_MS,
    STATE_EMPTY, SUB_GROUP_STATUS,
};
use routeloom_protocol::host_ops::{ConfigOpsResult, CAP_HOST_OPS_V1};
use routeloom_protocol::{Frame, FrameKind};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use crate::{json_escape, now_ms, push_event, Outbound, State};

/// Retained records (terminal ones are evicted oldest-first beyond this).
pub const RECORD_CAP: usize = 256;
/// Records admitted by the API but not yet written to the device.
pub const QUEUE_CAP: usize = 8;
/// Unsettled records (queued + awaiting admission + in progress). The
/// gateway itself tracks at most three unsettled group messages.
pub const LIVE_CAP: usize = 16;
/// Idempotency identities remembered after their record was evicted —
/// a resubmit then answers IDEMPOTENCY_WINDOW_EXPIRED, never a new send.
pub const TOMBSTONE_CAP: usize = 1024;
/// Device replies waiting for the lane thread.
pub const INBOX_CAP: usize = 64;
/// A 0x50 unanswered this long ends INDETERMINATE (the device may have
/// admitted it; it is never re-sent).
pub const ADMISSION_TIMEOUT_MS: u64 = 3_000;
/// 0x52 poll cadence for unsettled admitted records.
pub const POLL_INTERVAL_MS: u64 = 2_000;
/// How long past the message lifetime the lane keeps asking before it
/// gives up with INDETERMINATE `NO_FINAL_STATUS`.
pub const FINAL_GRACE_MS: u64 = 30_000;
pub const TTL_MIN_MS: u32 = 1;
pub const TTL_MAX_MS: u32 = MAX_LIFETIME_MS;
pub const TTL_DEFAULT_MS: u32 = 5_000;
pub const HOP_MIN: u8 = 1;
pub const HOP_MAX: u8 = 254;
pub const HOP_DEFAULT: u8 = 10;
pub const PAYLOAD_MAX: usize = GROUP_PAYLOAD_MAX;
/// Group memberships a node can hold (kGroupMembershipMax) — advertised
/// only; membership is node-local and not settable over USB.
pub const MEMBERSHIPS_PER_NODE: usize = 8;
const TICK_MS: u64 = 50;
/// Request ids for this lane live in their own high range ("GR") so an
/// Error frame echoing one can be routed back here and can never alias a
/// DataToMesh, dispatcher or node-status request.
const REQUEST_BASE: u64 = 0x4752_0000_0000_0000;
const REQUEST_MASK: u64 = 0xFFFF_0000_0000_0000;

/// True for the HostOps bodies this lane owns (0x51 GROUP_STATUS; 0x50 and
/// 0x52 are host→device and never arrive from a well-behaved device).
pub fn owns(inner: &[u8]) -> bool {
    group_ops_sub(inner) == Some(SUB_GROUP_STATUS)
}

/// True when an Error frame's request id is one this lane minted.
pub fn owns_request(request: u64) -> bool {
    request & REQUEST_MASK == REQUEST_BASE
}

/// The family rides the HostOps carrier: both bits must be advertised.
pub fn group_capable(capability: u32) -> bool {
    capability & CAP_GROUP_DELIVERY_V1 != 0 && capability & CAP_HOST_OPS_V1 != 0
}

pub fn priority_name(priority: u8) -> &'static str {
    match priority {
        0 => "BULK",
        1 => "NORMAL",
        2 => "MANAGEMENT",
        _ => "URGENT",
    }
}

/// routeloom::DeliveryState as the API spells it.
pub fn device_state_name(state: u8) -> &'static str {
    match state {
        0 => "EMPTY",
        1 => "ACCEPTED",
        2 => "WAITING_FOR_ROUTE",
        3 => "QUEUED",
        4 => "WAITING_FOR_MAC",
        5 => "WAITING_FOR_HOP_ACCEPT",
        6 => "WAITING_FOR_END_RECEIPT",
        7 => "DELIVERED",
        8 => "FAILED",
        9 => "EXPIRED",
        10 => "CANCELLED_BEFORE_TX",
        11 => "INDETERMINATE",
        _ => "UNKNOWN",
    }
}

pub fn result_name(result: u16) -> &'static str {
    match ConfigOpsResult::try_from_u16(result) {
        Ok(ConfigOpsResult::Ok) => "OK",
        Ok(ConfigOpsResult::Busy) => "BUSY",
        Ok(ConfigOpsResult::Denied) => "DENIED",
        Ok(ConfigOpsResult::Unsupported) => "UNSUPPORTED",
        Ok(ConfigOpsResult::Invalid) => "INVALID",
        Ok(ConfigOpsResult::Indeterminate) => "INDETERMINATE",
        Ok(ConfigOpsResult::NoRoute) => "NO_ROUTE",
        _ => "UNKNOWN",
    }
}

/// The `grp`-prefixed op token (its own space: never a messages.* or
/// config.* id).
pub fn op_token(op_id: u64) -> String {
    format!("grp{op_id:016x}")
}

/// Accepts exactly the canonical token: `grp` + 16 lowercase hex digits.
pub fn parse_op_token(text: &str) -> Option<u64> {
    let hex = text.strip_prefix("grp")?;
    if hex.len() != 16
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return None;
    }
    u64::from_str_radix(hex, 16).ok().filter(|&v| v != 0)
}

/// What the caller asked for — the idempotency comparison unit.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupRequest {
    pub network: u64,
    /// 1..=0xFFFF (0xFFFF = ALL).
    pub group: u16,
    pub priority: u8,
    pub ordered: bool,
    pub ttl_ms: u32,
    pub hop_limit: u8,
    pub payload: Vec<u8>,
}

/// Host lane phase of one record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    /// Admitted by the API, not yet written to the device.
    HostQueued,
    /// 0x50 handed to the writer; the admission 0x51 has not arrived.
    DevicePending {
        request: u64,
        session: u64,
        sent_ms: u64,
    },
    /// Admitted by the gateway, not settled. `push_session` is the USB
    /// session whose FINAL push (under `push_request`) may still arrive.
    InProgress {
        push_request: u64,
        push_session: u64,
        next_poll_ms: u64,
        poll: Option<(u64, u64)>,
    },
    /// The device reported a terminal DeliveryState.
    Settled,
    /// The device (or the lane, for a gateway without the capability)
    /// refused the send: nothing was transmitted.
    Refused,
    /// Never reached the device (deadline, network change).
    NotSent,
    /// The host lost track: the device may or may not have sent it.
    Indeterminate,
}

impl Phase {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Settled | Self::Refused | Self::NotSent | Self::Indeterminate
        )
    }
    fn admission_answered(self) -> bool {
        !matches!(self, Self::HostQueued | Self::DevicePending { .. })
    }
}

#[derive(Clone, Debug)]
pub struct GroupOpRecord {
    pub op_id: u64,
    pub uid: u32,
    pub key: [u8; 16],
    pub request: GroupRequest,
    pub phase: Phase,
    /// ConfigOpsResult of the admission answer (None before it).
    pub result: Option<u16>,
    /// Latest device summary (None before admission / on refusal).
    pub status: Option<GroupStatus>,
    /// Device reason string, or the host's own reason for a host-side
    /// terminal state.
    pub reason: Option<String>,
    /// Gateway node that admitted the message.
    pub gateway: Option<u64>,
    pub submitted_ms: u64,
    pub admitted_ms: Option<u64>,
    pub settled_ms: Option<u64>,
}

impl GroupOpRecord {
    /// The API `state` name.
    pub fn state_name(&self) -> &'static str {
        match self.phase {
            Phase::HostQueued => "HOST_QUEUED",
            Phase::DevicePending { .. } => "DEVICE_PENDING",
            Phase::InProgress { .. } | Phase::Settled => self
                .status
                .as_ref()
                .map_or("UNKNOWN", |s| device_state_name(s.state)),
            Phase::Refused => "REFUSED",
            Phase::NotSent => "NOT_SENT",
            Phase::Indeterminate => "INDETERMINATE",
        }
    }

    pub fn is_final(&self) -> bool {
        self.phase.terminal()
    }
}

fn opt_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |v| v.to_string())
}

fn opt_str(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), |v| format!("\"{}\"", json_escape(v)))
}

/// Summary fields shared by the record and the event body. Counts are
/// null until the device reported them — never an inferred zero.
fn summary_fields(record: &GroupOpRecord) -> String {
    let status = record.status.as_ref();
    let count = |f: fn(&GroupStatus) -> u16| {
        status.map_or_else(|| "null".to_string(), |s| f(s).to_string())
    };
    let missing = status.map_or_else(
        || "null".to_string(),
        |s| {
            let ids: Vec<String> = s
                .missing
                .iter()
                .map(|id| format!("\"{id:016x}\""))
                .collect();
            format!("[{}]", ids.join(","))
        },
    );
    let message = status.filter(|s| s.sequence != 0).map_or_else(
        || "null".to_string(),
        |s| {
            format!(
                "{{\"session\":\"{:08x}\",\"sequence\":\"{:016x}\"}}",
                s.session, s.sequence
            )
        },
    );
    format!(
        "\"group_op\":\"{}\",\"network\":\"{:016x}\",\"group\":{},\"all\":{},\"state\":\"{}\",\"final\":{},\"result\":{},\"reason\":{},\"message\":{message},\"gateway\":{},\"rounds\":{},\"delivered\":{},\"nonmember\":{},\"missing_total\":{},\"unaccounted\":{},\"missing\":{missing},\"missing_truncated\":{}",
        op_token(record.op_id),
        record.request.network,
        record.request.group,
        record.request.group == GROUP_ALL,
        record.state_name(),
        record.is_final(),
        opt_str(record.result.map(result_name)),
        opt_str(record.reason.as_deref()),
        record
            .gateway
            .map_or_else(|| "null".to_string(), |g| format!("\"{g:016x}\"")),
        status.map_or_else(|| "null".to_string(), |s| s.rounds.to_string()),
        count(|s| s.delivered),
        count(|s| s.nonmember),
        count(|s| s.missing_total),
        count(|s| s.unaccounted),
        status.map_or_else(|| "null".to_string(), |s| s.truncated().to_string()),
    )
}

/// The API1 record object (`group.send` / `group.get` result).
pub fn record_json(record: &GroupOpRecord) -> String {
    format!(
        "{{{},\"priority\":\"{}\",\"ordered\":{},\"ttl_ms\":{},\"hop_limit\":{},\"payload_len\":{},\"submitted_ms\":{},\"admitted_ms\":{},\"settled_ms\":{},\"clock\":\"host_unix_ms\"}}",
        summary_fields(record),
        priority_name(record.request.priority),
        record.request.ordered,
        record.request.ttl_ms,
        record.request.hop_limit,
        record.request.payload.len(),
        record.submitted_ms,
        opt_u64(record.admitted_ms),
        opt_u64(record.settled_ms),
    )
}

/// Event-ring body (`"kind":...` fragment) for a record that just settled.
pub fn settled_event(record: &GroupOpRecord) -> String {
    format!(
        "\"kind\":\"group_settled\",{},\"settled_ms\":{}",
        summary_fields(record),
        opt_u64(record.settled_ms),
    )
}

/// Why `GroupOps::submit` refused a request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitError {
    /// Same identity, different request.
    Conflict { existing: u64 },
    /// The identity's record was evicted; its outcome is gone.
    WindowExpired,
    /// Queue or unsettled-record bound reached.
    NoCapacity { queued: usize, live: usize },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    Accepted(u64),
    /// The identity is known: the existing record answers.
    Replay(u64),
}

type Identity = (u32, u64, [u8; 16]);

/// Device input for the lane.
#[derive(Clone, Debug)]
enum Inbound {
    Status {
        request: u64,
        body: Vec<u8>,
    },
    Error {
        request: u64,
        code: u16,
        reason: Option<String>,
    },
}

#[derive(Default)]
struct Inner {
    next_op: u64,
    records: HashMap<u64, GroupOpRecord>,
    identities: HashMap<Identity, u64>,
    queue: VecDeque<u64>,
    terminal_order: VecDeque<u64>,
    tombstones: HashSet<Identity>,
    tombstone_order: VecDeque<Identity>,
    inbox: VecDeque<Inbound>,
    inbox_dropped: u64,
    evicted: u64,
}

impl Inner {
    fn live(&self) -> usize {
        self.records.values().filter(|r| !r.is_final()).count()
    }

    fn evict_one_terminal(&mut self) -> bool {
        while let Some(oldest) = self.terminal_order.pop_front() {
            if let Some(record) = self.records.remove(&oldest) {
                let identity = (record.uid, record.request.network, record.key);
                self.identities.remove(&identity);
                if self.tombstone_order.len() >= TOMBSTONE_CAP {
                    if let Some(old) = self.tombstone_order.pop_front() {
                        self.tombstones.remove(&old);
                    }
                }
                if self.tombstones.insert(identity) {
                    self.tombstone_order.push_back(identity);
                }
                self.evicted += 1;
                return true;
            }
        }
        false
    }
}

/// Shared group op hub: api1 submits and reads, the lane thread drives.
/// `lane_cv` wakes the lane (new submit or device reply); `change_cv`
/// wakes API readers waiting for a record to move.
#[derive(Default)]
pub struct GroupOps {
    inner: Mutex<Inner>,
    lane_cv: Condvar,
    change_cv: Condvar,
}

/// Session facts the lane needs, read from the daemon's session mirror.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct GroupLink {
    pub active: bool,
    pub capable: bool,
    pub session: u64,
    pub gateway: u64,
    pub network: u64,
}

pub fn group_link(state: &State) -> GroupLink {
    let info = state.session.lock().expect("session poisoned");
    GroupLink {
        active: info.authenticated && info.id.is_some() && info.node.is_some(),
        capable: info.capability.is_some_and(group_capable),
        session: info.id.unwrap_or(0),
        gateway: info.node.unwrap_or(0),
        network: info.network.unwrap_or(0),
    }
}

/// Lane-private state (request id source, current session).
#[derive(Default)]
pub struct GroupLane {
    session: Option<u64>,
    next_request: u64,
}

impl GroupLane {
    fn request_id(&mut self) -> u64 {
        self.next_request = self.next_request.wrapping_add(1);
        REQUEST_BASE | (self.next_request & !REQUEST_MASK)
    }
}

/// One lane pass result: frames to write, event bodies, diagnostic notes.
#[derive(Default, Debug)]
pub struct StepOutput {
    pub frames: Vec<(u64, Vec<u8>)>,
    pub events: Vec<String>,
    pub notes: Vec<String>,
}

impl GroupOps {
    /// Op ids namespace the daemon incarnation (as config ops do): a token
    /// from before a restart can never resolve to a different operation.
    pub fn with_boot(host_boot: u64) -> Self {
        let tag = ((host_boot as u32) ^ ((host_boot >> 32) as u32)) | 1;
        Self {
            inner: Mutex::new(Inner {
                next_op: u64::from(tag) << 32,
                ..Inner::default()
            }),
            ..Self::default()
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("group ops poisoned")
    }

    /// Admit one request for `uid`. A known identity answers its existing
    /// record (Replay) or CONFLICT; an evicted one WindowExpired.
    pub fn submit(
        &self,
        uid: u32,
        key: [u8; 16],
        request: GroupRequest,
        now_ms: u64,
    ) -> Result<SubmitOutcome, SubmitError> {
        let mut inner = self.lock();
        let identity = (uid, request.network, key);
        if let Some(&existing) = inner.identities.get(&identity) {
            let same = inner
                .records
                .get(&existing)
                .is_some_and(|record| record.request == request);
            return if same {
                Ok(SubmitOutcome::Replay(existing))
            } else {
                Err(SubmitError::Conflict { existing })
            };
        }
        if inner.tombstones.contains(&identity) {
            return Err(SubmitError::WindowExpired);
        }
        let live = inner.live();
        if inner.queue.len() >= QUEUE_CAP || live >= LIVE_CAP {
            return Err(SubmitError::NoCapacity {
                queued: inner.queue.len(),
                live,
            });
        }
        if inner.records.len() >= RECORD_CAP && !inner.evict_one_terminal() {
            return Err(SubmitError::NoCapacity {
                queued: inner.queue.len(),
                live,
            });
        }
        let op_id = inner.next_op.wrapping_add(1).max(1);
        inner.next_op = op_id;
        inner.records.insert(
            op_id,
            GroupOpRecord {
                op_id,
                uid,
                key,
                request,
                phase: Phase::HostQueued,
                result: None,
                status: None,
                reason: None,
                gateway: None,
                submitted_ms: now_ms,
                admitted_ms: None,
                settled_ms: None,
            },
        );
        inner.identities.insert(identity, op_id);
        inner.queue.push_back(op_id);
        drop(inner);
        self.lane_cv.notify_all();
        self.change_cv.notify_all();
        Ok(SubmitOutcome::Accepted(op_id))
    }

    /// True when the identity has a record or a tombstone — a resubmit is
    /// then answered from the table, never gated on the live session.
    pub fn knows(&self, uid: u32, network: u64, key: &[u8; 16]) -> bool {
        let inner = self.lock();
        let identity = (uid, network, *key);
        inner.identities.contains_key(&identity) || inner.tombstones.contains(&identity)
    }

    pub fn get(&self, op_id: u64) -> Option<GroupOpRecord> {
        self.lock().records.get(&op_id).cloned()
    }

    /// Wait (bounded) until `done(record)` holds, then return the record.
    /// Never holds the lock across the sleep beyond the condvar wait.
    pub fn wait_for(
        &self,
        op_id: u64,
        wait: Duration,
        done: fn(&GroupOpRecord) -> bool,
    ) -> Option<GroupOpRecord> {
        let deadline = Instant::now() + wait;
        let mut inner = self.lock();
        loop {
            let record = inner.records.get(&op_id)?;
            let now = Instant::now();
            if done(record) || now >= deadline {
                return Some(record.clone());
            }
            inner = self
                .change_cv
                .wait_timeout(inner, deadline - now)
                .expect("group ops poisoned")
                .0;
        }
    }

    /// Wait for admission to be answered (or any terminal state).
    pub fn admission_answered(record: &GroupOpRecord) -> bool {
        record.phase.admission_answered()
    }

    pub fn settled(record: &GroupOpRecord) -> bool {
        record.is_final()
    }

    /// `(records, live, queued, evicted)` — the bounds under test.
    #[cfg(test)]
    pub fn counts(&self) -> (usize, usize, usize, u64) {
        let inner = self.lock();
        (
            inner.records.len(),
            inner.live(),
            inner.queue.len(),
            inner.evicted,
        )
    }

    /// Posted by the USB read thread; never blocks it. A full inbox drops
    /// the body — the lane's poll recovers the state.
    pub fn post_status(&self, request: u64, body: Vec<u8>) -> bool {
        self.post(Inbound::Status { request, body })
    }

    pub fn post_error(&self, request: u64, code: u16, reason: Option<String>) -> bool {
        self.post(Inbound::Error {
            request,
            code,
            reason,
        })
    }

    fn post(&self, item: Inbound) -> bool {
        let mut inner = self.lock();
        if inner.inbox.len() >= INBOX_CAP {
            inner.inbox_dropped += 1;
            return false;
        }
        inner.inbox.push_back(item);
        drop(inner);
        self.lane_cv.notify_all();
        true
    }

    /// Park the lane thread until work arrives or `dur` elapses.
    pub fn wait_lane(&self, dur: Duration) {
        let inner = self.lock();
        if inner.inbox.is_empty() && inner.queue.is_empty() {
            let _ = self.lane_cv.wait_timeout(inner, dur);
        }
    }

    /// The writer queue refused `request`: nothing reached the device, so
    /// an admission goes back to the head of the queue and a poll is
    /// simply re-issued later.
    pub fn emit_dropped(&self, request: u64) {
        let mut inner = self.lock();
        let mut requeue = None;
        for record in inner.records.values_mut() {
            match record.phase {
                Phase::DevicePending { request: r, .. } if r == request => {
                    record.phase = Phase::HostQueued;
                    requeue = Some(record.op_id);
                }
                Phase::InProgress {
                    push_request,
                    push_session,
                    next_poll_ms,
                    poll: Some((r, _)),
                } if r == request => {
                    record.phase = Phase::InProgress {
                        push_request,
                        push_session,
                        next_poll_ms,
                        poll: None,
                    };
                }
                _ => {}
            }
        }
        if let Some(op_id) = requeue {
            inner.queue.push_front(op_id);
        }
    }

    /// One lane pass: session transitions, device replies, timers, then
    /// new frames. Pure with respect to I/O — the caller writes the frames
    /// and publishes the events.
    pub fn step(&self, lane: &mut GroupLane, link: &GroupLink, now: u64) -> StepOutput {
        let mut out = StepOutput::default();
        let mut guard = self.lock();
        // Reborrow once so records/queue can be borrowed disjointly.
        let inner: &mut Inner = &mut guard;
        let mut settled: Vec<u64> = Vec::new();
        let current = link.active.then_some(link.session);
        if lane.session != current {
            // Session boundary: an unanswered 0x50 may or may not have been
            // admitted by the device — INDETERMINATE, never re-sent. An
            // admitted record keeps its MessageId and is re-read with 0x52
            // on the new session (its FINAL push died with the old one).
            for record in inner.records.values_mut() {
                match record.phase {
                    Phase::DevicePending { session, .. } if Some(session) != current => {
                        record.phase = Phase::Indeterminate;
                        record.reason = Some("SESSION_LOST_BEFORE_ADMISSION".to_string());
                        record.settled_ms = Some(now);
                        settled.push(record.op_id);
                    }
                    Phase::InProgress {
                        push_request,
                        push_session,
                        ..
                    } => {
                        record.phase = Phase::InProgress {
                            push_request,
                            push_session,
                            next_poll_ms: now,
                            poll: None,
                        };
                    }
                    _ => {}
                }
            }
            lane.session = current;
        }
        let inbox: Vec<Inbound> = inner.inbox.drain(..).collect();
        for item in inbox {
            match item {
                Inbound::Status { request, body } => {
                    on_status(inner, link, request, &body, now, &mut settled, &mut out)
                }
                Inbound::Error {
                    request,
                    code,
                    reason,
                } => on_error(inner, request, code, reason, now, &mut settled, &mut out),
            }
        }
        // Timers.
        for record in inner.records.values_mut() {
            let lifetime_end = record.submitted_ms + u64::from(record.request.ttl_ms);
            match record.phase {
                Phase::HostQueued if now >= lifetime_end => {
                    record.phase = Phase::NotSent;
                    record.reason = Some("HOST_DEADLINE".to_string());
                    record.settled_ms = Some(now);
                    settled.push(record.op_id);
                }
                Phase::DevicePending { sent_ms, .. }
                    if now.saturating_sub(sent_ms) >= ADMISSION_TIMEOUT_MS =>
                {
                    record.phase = Phase::Indeterminate;
                    record.reason = Some("NO_ADMISSION_REPLY".to_string());
                    record.settled_ms = Some(now);
                    settled.push(record.op_id);
                }
                Phase::InProgress {
                    push_request,
                    push_session,
                    next_poll_ms,
                    poll,
                } => {
                    let admitted = record.admitted_ms.unwrap_or(record.submitted_ms);
                    if now >= admitted + u64::from(record.request.ttl_ms) + FINAL_GRACE_MS {
                        record.phase = Phase::Indeterminate;
                        record.reason = Some("NO_FINAL_STATUS".to_string());
                        record.settled_ms = Some(now);
                        settled.push(record.op_id);
                    } else if poll
                        .is_some_and(|(_, sent)| now.saturating_sub(sent) >= POLL_INTERVAL_MS)
                    {
                        // Unanswered poll: forget it; the schedule re-asks.
                        record.phase = Phase::InProgress {
                            push_request,
                            push_session,
                            next_poll_ms,
                            poll: None,
                        };
                    }
                }
                _ => {}
            }
        }
        let queued: Vec<u64> = inner.queue.iter().copied().collect();
        inner.queue.clear();
        for op_id in queued {
            let Some(record) = inner.records.get_mut(&op_id) else {
                continue;
            };
            if record.phase != Phase::HostQueued {
                continue;
            }
            if !link.active {
                inner.queue.push_back(op_id);
                continue;
            }
            if !link.capable {
                record.phase = Phase::Refused;
                record.reason = Some("GROUP_CAPABILITY_ABSENT".to_string());
                record.settled_ms = Some(now);
                settled.push(op_id);
                continue;
            }
            if link.network != record.request.network {
                record.phase = Phase::NotSent;
                record.reason = Some("NETWORK_CHANGED".to_string());
                record.settled_ms = Some(now);
                settled.push(op_id);
                continue;
            }
            let send = GroupSend {
                group: record.request.group,
                priority: record.request.priority,
                ordered: record.request.ordered,
                lifetime_ms: record.request.ttl_ms,
                hop_limit: record.request.hop_limit,
                data: record.request.payload.clone(),
            };
            match encode_group_send(&send) {
                Ok(body) => {
                    let request = lane.request_id();
                    record.phase = Phase::DevicePending {
                        request,
                        session: link.session,
                        sent_ms: now,
                    };
                    record.gateway = Some(link.gateway);
                    out.frames.push((request, body));
                }
                Err(error) => {
                    // Admission validated every field; an encode failure
                    // is a daemon bug — refuse honestly, never send.
                    record.phase = Phase::Refused;
                    record.reason = Some(format!("HOST_ENCODE_FAILED: {error}"));
                    record.settled_ms = Some(now);
                    settled.push(op_id);
                }
            }
        }
        if link.active && link.capable {
            for record in inner.records.values_mut() {
                let Phase::InProgress {
                    push_request,
                    push_session,
                    next_poll_ms,
                    poll: None,
                } = record.phase
                else {
                    continue;
                };
                if now < next_poll_ms {
                    continue;
                }
                let Some(status) = record.status.as_ref() else {
                    continue;
                };
                let query = GroupQuery {
                    session: status.session,
                    sequence: status.sequence,
                };
                if let Ok(body) = encode_group_query(&query) {
                    let request = lane.request_id();
                    record.phase = Phase::InProgress {
                        push_request,
                        push_session,
                        next_poll_ms: now + POLL_INTERVAL_MS,
                        poll: Some((request, now)),
                    };
                    out.frames.push((request, body));
                }
            }
        }
        // Deterministic order (records live in a HashMap): events and the
        // eviction order follow op ids within one pass.
        settled.sort_unstable();
        for op_id in settled {
            inner.terminal_order.push_back(op_id);
            if let Some(record) = inner.records.get(&op_id) {
                out.events.push(settled_event(record));
            }
        }
        drop(guard);
        self.change_cv.notify_all();
        out
    }
}

fn settle(record: &mut GroupOpRecord, phase: Phase, now: u64, settled: &mut Vec<u64>) {
    record.phase = phase;
    record.settled_ms = Some(now);
    settled.push(record.op_id);
}

fn on_status(
    inner: &mut Inner,
    link: &GroupLink,
    request: u64,
    body: &[u8],
    now: u64,
    settled: &mut Vec<u64>,
    out: &mut StepOutput,
) {
    let Some(record) = inner.records.values_mut().find(|r| match r.phase {
        Phase::DevicePending { request: q, .. } => q == request,
        Phase::InProgress {
            push_request,
            push_session,
            poll,
            ..
        } => {
            (push_request == request && push_session == link.session)
                || poll.is_some_and(|(q, _)| q == request)
        }
        _ => false,
    }) else {
        out.notes.push(format!(
            "group status for unknown request {request:#x} ignored"
        ));
        return;
    };
    let status = match decode_group_status(body) {
        Ok(status) => status,
        Err(error) => {
            out.notes.push(format!("group status rejected: {error}"));
            if matches!(record.phase, Phase::DevicePending { .. }) {
                record.reason = Some("MALFORMED_STATUS".to_string());
                settle(record, Phase::Indeterminate, now, settled);
            } else if let Phase::InProgress {
                push_request,
                push_session,
                next_poll_ms,
                ..
            } = record.phase
            {
                record.phase = Phase::InProgress {
                    push_request,
                    push_session,
                    next_poll_ms,
                    poll: None,
                };
            }
            return;
        }
    };
    match record.phase {
        Phase::DevicePending { .. } => {
            record.result = Some(status.result);
            record.reason = (!status.reason.is_empty()).then(|| status.reason.clone());
            if status.result != ConfigOpsResult::Ok as u16 {
                settle(record, Phase::Refused, now, settled);
                return;
            }
            record.admitted_ms = Some(now);
            let is_final = status.is_final();
            record.status = Some(status);
            if is_final {
                settle(record, Phase::Settled, now, settled);
            } else {
                record.phase = Phase::InProgress {
                    push_request: request,
                    push_session: link.session,
                    next_poll_ms: now + POLL_INTERVAL_MS,
                    poll: None,
                };
            }
        }
        Phase::InProgress {
            push_request,
            push_session,
            ..
        } => {
            let clear_poll = Phase::InProgress {
                push_request,
                push_session,
                next_poll_ms: now + POLL_INTERVAL_MS,
                poll: None,
            };
            let known = record
                .status
                .as_ref()
                .map(|s| (s.session, s.sequence))
                .unwrap_or_default();
            if status.result != ConfigOpsResult::Ok as u16 {
                // A gateway that can no longer answer for the id (e.g. a
                // different firmware after reconnect): its outcome is lost.
                record.reason = Some(format!(
                    "GROUP_QUERY_REFUSED:{}",
                    result_name(status.result)
                ));
                settle(record, Phase::Indeterminate, now, settled);
                return;
            }
            if status.state == STATE_EMPTY {
                // Ok / Empty / NOT_FOUND: the gateway no longer holds the
                // id (reclaimed or rebooted) and the push never reached us.
                record.reason = Some("GROUP_RESULT_RECLAIMED".to_string());
                settle(record, Phase::Indeterminate, now, settled);
                return;
            }
            if (status.session, status.sequence) != known {
                out.notes.push(format!(
                    "group status id mismatch for {}; ignored",
                    op_token(record.op_id)
                ));
                record.phase = clear_poll;
                return;
            }
            record.reason = (!status.reason.is_empty()).then(|| status.reason.clone());
            let is_final = status.is_final();
            record.status = Some(status);
            if is_final {
                settle(record, Phase::Settled, now, settled);
            } else {
                record.phase = clear_poll;
            }
        }
        _ => {}
    }
}

fn on_error(
    inner: &mut Inner,
    request: u64,
    code: u16,
    reason: Option<String>,
    now: u64,
    settled: &mut Vec<u64>,
    out: &mut StepOutput,
) {
    let Some(record) = inner.records.values_mut().find(|r| match r.phase {
        Phase::DevicePending { request: q, .. } => q == request,
        Phase::InProgress { poll, .. } => poll.is_some_and(|(q, _)| q == request),
        _ => false,
    }) else {
        return;
    };
    let detail = reason.unwrap_or_else(|| format!("USB_ERROR_{code}"));
    match record.phase {
        Phase::DevicePending { .. } => {
            // The device refused the frame itself: nothing was sent.
            record.reason = Some(detail);
            settle(record, Phase::Refused, now, settled);
        }
        Phase::InProgress {
            push_request,
            push_session,
            next_poll_ms,
            ..
        } => {
            out.notes
                .push(format!("group query refused by device: {detail}"));
            record.phase = Phase::InProgress {
                push_request,
                push_session,
                next_poll_ms,
                poll: None,
            };
        }
        _ => {}
    }
}

/// One lane pass against the daemon state.
pub fn group_once(
    state: &State,
    outbound: &mpsc::SyncSender<Outbound>,
    lane: &mut GroupLane,
    now: u64,
) {
    let link = group_link(state);
    let out = state.group_ops.step(lane, &link, now);
    for event in out.events {
        push_event(state, now, event);
    }
    for note in out.notes {
        push_event(
            state,
            now,
            format!(
                "\"kind\":\"dispatch\",\"detail\":\"{}\"",
                json_escape(&note)
            ),
        );
    }
    for (request, body) in out.frames {
        let frame = Frame {
            kind: FrameKind::HostOps,
            flags: 0,
            session: 0,
            request,
            body,
        };
        if outbound.try_send(Outbound::Seal(frame)).is_err() {
            state.group_ops.emit_dropped(request);
        }
    }
}

/// The group lane thread: idle while nothing is queued or unsettled.
pub fn group_loop(state: Arc<State>, outbound: mpsc::SyncSender<Outbound>) {
    let mut lane = GroupLane::default();
    loop {
        group_once(&state, &outbound, &mut lane, now_ms());
        state.group_ops.wait_lane(Duration::from_millis(TICK_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_json::Json;
    use routeloom_protocol::group_ops::{
        decode_group_query, decode_group_send, encode_group_status, GROUP_SEQUENCE_FLAG,
        STATE_DELIVERED, STATE_FAILED,
    };
    use std::path::PathBuf;

    const NET: u64 = 7;
    const SESSION: u64 = 0x5e55;
    const GW: u64 = 1;

    fn link() -> GroupLink {
        GroupLink {
            active: true,
            capable: true,
            session: SESSION,
            gateway: GW,
            network: NET,
        }
    }

    fn alarm() -> GroupRequest {
        GroupRequest {
            network: NET,
            group: GROUP_ALL,
            priority: 3,
            ordered: false,
            ttl_ms: 5000,
            hop_limit: 10,
            payload: b"PUMP3 OVERTEMP".to_vec(),
        }
    }

    fn key(n: u8) -> [u8; 16] {
        [n; 16]
    }

    /// Inner bytes of one frame of the shared USB golden scenario.
    pub(crate) fn golden(name: &str) -> Vec<u8> {
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/usb-golden/group-ops/frames")
            .join(name);
        let text = std::fs::read_to_string(&path).expect("golden frame readable");
        let doc = routeloom_json::parse(&text).expect("golden frame is JSON");
        let hex = doc.get("inner_hex").and_then(Json::as_str).unwrap();
        (0..hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
            .collect()
    }

    fn submit(ops: &GroupOps, n: u8, now: u64) -> u64 {
        match ops.submit(501, key(n), alarm(), now).unwrap() {
            SubmitOutcome::Accepted(op) => op,
            other => panic!("expected Accepted, got {other:?}"),
        }
    }

    fn status(state: u8, reason: &str) -> GroupStatus {
        GroupStatus {
            result: ConfigOpsResult::Ok as u16,
            session: 0x1b59,
            sequence: GROUP_SEQUENCE_FLAG | 1,
            group: GROUP_ALL,
            state,
            rounds: 1,
            delivered: 99,
            nonmember: 0,
            missing_total: 0,
            unaccounted: 0,
            missing: Vec::new(),
            reason: reason.to_string(),
        }
    }

    /// Drives one send to admission; returns (op, send request id).
    fn admit(ops: &GroupOps, lane: &mut GroupLane, n: u8, now: u64) -> (u64, u64) {
        let op = submit(ops, n, now);
        let out = ops.step(lane, &link(), now);
        let (request, _) = *out.frames.last().expect("a GROUP_SEND frame");
        ops.post_status(
            request,
            encode_group_status(&status(6, "GROUP_ROUND_PENDING")).unwrap(),
        );
        let out = ops.step(lane, &link(), now + 1);
        assert!(out.events.is_empty());
        assert_eq!(ops.get(op).unwrap().state_name(), "WAITING_FOR_END_RECEIPT");
        (op, request)
    }

    /// The shared golden scenario end to end: the lane's 0x50 is byte-equal
    /// to the golden GROUP_SEND, the golden admitted/FINAL 0x51 bodies move
    /// the record to DELIVERED, and exactly one group_settled is emitted.
    #[test]
    fn golden_send_admit_final_flow() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let op = submit(&ops, 1, 1_000);
        let record = ops.get(op).unwrap();
        assert_eq!(record.state_name(), "HOST_QUEUED");
        assert!(record_json(&record).contains("\"delivered\":null"));
        let out = ops.step(&mut lane, &link(), 1_000);
        assert_eq!(out.frames.len(), 1);
        let (request, body) = &out.frames[0];
        assert!(owns_request(*request));
        assert_eq!(body, &golden("07_group_send.json"));
        assert_eq!(decode_group_send(body).unwrap().lifetime_ms, 5000);
        assert_eq!(ops.get(op).unwrap().state_name(), "DEVICE_PENDING");

        let admitted = golden("09_group_status_admitted.json");
        assert!(owns(&admitted));
        ops.post_status(*request, admitted);
        let out = ops.step(&mut lane, &link(), 1_010);
        assert!(out.events.is_empty() && out.frames.is_empty());
        let record = ops.get(op).unwrap();
        assert_eq!(record.state_name(), "WAITING_FOR_END_RECEIPT");
        assert!(!record.is_final());
        assert_eq!(record.admitted_ms, Some(1_010));
        let json = record_json(&record);
        assert!(
            json.contains(
                "\"message\":{\"session\":\"00001b59\",\"sequence\":\"8000000000000001\"}"
            ),
            "{json}"
        );
        assert!(
            json.contains("\"reason\":\"GROUP_ROUND_PENDING\""),
            "{json}"
        );
        assert!(json.contains("\"gateway\":\"0000000000000001\""), "{json}");

        ops.post_status(*request, golden("10_group_status_final.json"));
        let out = ops.step(&mut lane, &link(), 1_100);
        assert_eq!(out.events.len(), 1);
        let event = &out.events[0];
        assert!(event.starts_with("\"kind\":\"group_settled\""), "{event}");
        assert!(event.contains("\"state\":\"DELIVERED\""), "{event}");
        assert!(event.contains("\"delivered\":1"), "{event}");
        let record = ops.get(op).unwrap();
        assert!(record.is_final());
        assert_eq!(record.settled_ms, Some(1_100));
        let parsed = routeloom_json::parse(&record_json(&record)).unwrap();
        assert_eq!(parsed.get("final").and_then(Json::as_bool), Some(true));
        assert_eq!(parsed.get("rounds").and_then(Json::as_u64), Some(1));
        assert_eq!(parsed.get("missing_total").and_then(Json::as_u64), Some(0));
        assert_eq!(parsed.get("all").and_then(Json::as_bool), Some(true));
        assert_eq!(
            parsed.get("reason").and_then(Json::as_str),
            Some("GROUP_COMPLETE")
        );

        // A duplicate FINAL (e.g. a poll answer racing the push) changes
        // nothing and never emits a second event.
        ops.post_status(*request, golden("10_group_status_final.json"));
        let out = ops.step(&mut lane, &link(), 1_200);
        assert!(out.events.is_empty());
        assert_eq!(out.notes.len(), 1);
        // Nothing left to drive: the lane is idle.
        assert!(ops.step(&mut lane, &link(), 60_000).frames.is_empty());
    }

    #[test]
    fn device_refusal_is_terminal_with_reason() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let op = submit(&ops, 1, 0);
        let out = ops.step(&mut lane, &link(), 0);
        let refusal = GroupStatus {
            result: ConfigOpsResult::Unsupported as u16,
            group: GROUP_ALL,
            reason: "GROUP_REQUIRES_GATEWAY_SCOPED".to_string(),
            ..GroupStatus::default()
        };
        ops.post_status(out.frames[0].0, encode_group_status(&refusal).unwrap());
        let out = ops.step(&mut lane, &link(), 5);
        assert_eq!(out.events.len(), 1);
        let record = ops.get(op).unwrap();
        assert_eq!(record.state_name(), "REFUSED");
        let json = record_json(&record);
        assert!(json.contains("\"result\":\"UNSUPPORTED\""), "{json}");
        assert!(
            json.contains("\"reason\":\"GROUP_REQUIRES_GATEWAY_SCOPED\""),
            "{json}"
        );
        assert!(json.contains("\"message\":null"), "{json}");
        assert!(json.contains("\"delivered\":null"), "{json}");

        // Busy (source table full) is a refusal too — the caller retries
        // with a NEW key if it wants another attempt.
        let op = submit(&ops, 2, 10);
        let out = ops.step(&mut lane, &link(), 10);
        let busy = GroupStatus {
            result: ConfigOpsResult::Busy as u16,
            group: GROUP_ALL,
            reason: "GROUP_QUEUE_FULL".to_string(),
            ..GroupStatus::default()
        };
        ops.post_status(out.frames[0].0, encode_group_status(&busy).unwrap());
        ops.step(&mut lane, &link(), 11);
        assert!(record_json(&ops.get(op).unwrap()).contains("\"result\":\"BUSY\""));

        // A frame-level USB Error for the 0x50: nothing was sent.
        let op = submit(&ops, 3, 20);
        let out = ops.step(&mut lane, &link(), 20);
        ops.post_error(out.frames[0].0, 1, Some("GROUP_MALFORMED".to_string()));
        let out = ops.step(&mut lane, &link(), 21);
        assert_eq!(out.events.len(), 1);
        let record = ops.get(op).unwrap();
        assert_eq!(record.state_name(), "REFUSED");
        assert_eq!(record.reason.as_deref(), Some("GROUP_MALFORMED"));
    }

    #[test]
    fn missing_admission_reply_is_indeterminate_never_resent() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let op = submit(&ops, 1, 0);
        assert_eq!(ops.step(&mut lane, &link(), 0).frames.len(), 1);
        assert!(ops
            .step(&mut lane, &link(), ADMISSION_TIMEOUT_MS - 1)
            .frames
            .is_empty());
        let out = ops.step(&mut lane, &link(), ADMISSION_TIMEOUT_MS);
        assert!(out.frames.is_empty(), "never re-sent");
        assert_eq!(out.events.len(), 1);
        let record = ops.get(op).unwrap();
        assert_eq!(record.state_name(), "INDETERMINATE");
        assert_eq!(record.reason.as_deref(), Some("NO_ADMISSION_REPLY"));
    }

    #[test]
    fn lost_final_push_is_recovered_by_polling() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let (op, _) = admit(&ops, &mut lane, 1, 0);
        // No poll before the interval.
        assert!(ops.step(&mut lane, &link(), 100).frames.is_empty());
        let out = ops.step(&mut lane, &link(), 1 + POLL_INTERVAL_MS);
        assert_eq!(out.frames.len(), 1);
        let (poll, body) = &out.frames[0];
        let query = decode_group_query(body).unwrap();
        assert_eq!(query.sequence, GROUP_SEQUENCE_FLAG | 1);
        assert_eq!(query.session, 0x1b59);
        // Progress answer: still in flight, counts refresh.
        let mut progress = status(6, "GROUP_REPAIRING");
        progress.rounds = 2;
        progress.delivered = 50;
        progress.missing_total = 49;
        progress.missing = vec![41, 42];
        ops.post_status(*poll, encode_group_status(&progress).unwrap());
        ops.step(&mut lane, &link(), 2 + POLL_INTERVAL_MS);
        let json = record_json(&ops.get(op).unwrap());
        assert!(json.contains("\"missing_truncated\":true"), "{json}");
        assert!(
            json.contains("\"missing\":[\"0000000000000029\",\"000000000000002a\"]"),
            "{json}"
        );
        // Next poll answers FAILED/INCOMPLETE: settled via the poll.
        let out = ops.step(&mut lane, &link(), 3 + 2 * POLL_INTERVAL_MS);
        let (poll, _) = out.frames[0];
        let mut failed = progress.clone();
        failed.state = STATE_FAILED;
        failed.rounds = 12;
        failed.reason = "GROUP_INCOMPLETE".to_string();
        ops.post_status(poll, encode_group_status(&failed).unwrap());
        let out = ops.step(&mut lane, &link(), 4 + 2 * POLL_INTERVAL_MS);
        assert_eq!(out.events.len(), 1);
        assert!(out.events[0].contains("\"state\":\"FAILED\""));
        assert!(out.events[0].contains("\"reason\":\"GROUP_INCOMPLETE\""));
    }

    #[test]
    fn unsettled_record_gives_up_after_lifetime_and_grace() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let (op, _) = admit(&ops, &mut lane, 1, 0);
        let give_up = 1 + 5_000 + FINAL_GRACE_MS;
        ops.step(&mut lane, &link(), give_up - 1);
        assert!(!ops.get(op).unwrap().is_final());
        let out = ops.step(&mut lane, &link(), give_up);
        assert_eq!(out.events.len(), 1);
        assert_eq!(
            ops.get(op).unwrap().reason.as_deref(),
            Some("NO_FINAL_STATUS")
        );
    }

    #[test]
    fn session_loss_settles_pending_and_repolls_admitted() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let (admitted, _) = admit(&ops, &mut lane, 1, 0);
        let pending = submit(&ops, 2, 10);
        assert_eq!(ops.step(&mut lane, &link(), 10).frames.len(), 1);
        // The session drops: the unanswered 0x50 is INDETERMINATE (the
        // device may have admitted it); the admitted one waits.
        let down = GroupLink {
            active: false,
            ..link()
        };
        let out = ops.step(&mut lane, &down, 20);
        assert_eq!(out.events.len(), 1);
        assert_eq!(
            ops.get(pending).unwrap().reason.as_deref(),
            Some("SESSION_LOST_BEFORE_ADMISSION")
        );
        assert!(!ops.get(admitted).unwrap().is_final());
        assert!(out.frames.is_empty());
        // A new session: the admitted record is re-read with 0x52 at once.
        let up = GroupLink {
            session: SESSION + 1,
            ..link()
        };
        let out = ops.step(&mut lane, &up, 30);
        assert_eq!(out.frames.len(), 1);
        assert!(decode_group_query(&out.frames[0].1).is_ok());
        // The gateway rebooted meanwhile: Ok / Empty / NOT_FOUND.
        let gone = GroupStatus {
            rounds: 0,
            delivered: 0,
            group: 0,
            ..status(STATE_EMPTY, "NOT_FOUND")
        };
        ops.post_status(out.frames[0].0, encode_group_status(&gone).unwrap());
        let out = ops.step(&mut lane, &up, 40);
        assert_eq!(out.events.len(), 1);
        let record = ops.get(admitted).unwrap();
        assert_eq!(record.state_name(), "INDETERMINATE");
        assert_eq!(record.reason.as_deref(), Some("GROUP_RESULT_RECLAIMED"));
    }

    #[test]
    fn stale_push_from_an_old_session_is_ignored() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let (op, push) = admit(&ops, &mut lane, 1, 0);
        let up = GroupLink {
            session: SESSION + 1,
            ..link()
        };
        let out = ops.step(&mut lane, &up, 5);
        assert_eq!(out.frames.len(), 1); // re-read on the new session
        ops.post_status(
            push,
            encode_group_status(&status(STATE_DELIVERED, "GROUP_COMPLETE")).unwrap(),
        );
        let out = ops.step(&mut lane, &up, 6);
        assert!(out.events.is_empty());
        assert!(!ops.get(op).unwrap().is_final());
    }

    #[test]
    fn host_deadline_incapable_and_network_change_never_send() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let down = GroupLink {
            active: false,
            ..link()
        };
        let late = submit(&ops, 1, 0);
        assert!(ops.step(&mut lane, &down, 4_999).frames.is_empty());
        assert!(!ops.get(late).unwrap().is_final());
        let out = ops.step(&mut lane, &down, 5_000);
        assert_eq!(out.events.len(), 1);
        assert_eq!(ops.get(late).unwrap().state_name(), "NOT_SENT");

        let incapable = GroupLink {
            capable: false,
            ..link()
        };
        let op = submit(&ops, 2, 6_000);
        let out = ops.step(&mut lane, &incapable, 6_000);
        assert!(out.frames.is_empty());
        let record = ops.get(op).unwrap();
        assert_eq!(record.state_name(), "REFUSED");
        assert_eq!(record.reason.as_deref(), Some("GROUP_CAPABILITY_ABSENT"));

        let moved = GroupLink {
            network: NET + 1,
            ..link()
        };
        let op = submit(&ops, 3, 7_000);
        assert!(ops.step(&mut lane, &moved, 7_000).frames.is_empty());
        assert_eq!(
            ops.get(op).unwrap().reason.as_deref(),
            Some("NETWORK_CHANGED")
        );
    }

    #[test]
    fn writer_refusal_requeues_the_send() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        let op = submit(&ops, 1, 0);
        let out = ops.step(&mut lane, &link(), 0);
        ops.emit_dropped(out.frames[0].0);
        assert_eq!(ops.get(op).unwrap().state_name(), "HOST_QUEUED");
        let out = ops.step(&mut lane, &link(), 1);
        assert_eq!(out.frames.len(), 1);
        assert_eq!(ops.get(op).unwrap().state_name(), "DEVICE_PENDING");
    }

    #[test]
    fn idempotency_replay_conflict_and_scope() {
        let ops = GroupOps::default();
        let op = submit(&ops, 1, 0);
        assert!(ops.knows(501, NET, &key(1)));
        assert_eq!(
            ops.submit(501, key(1), alarm(), 5),
            Ok(SubmitOutcome::Replay(op))
        );
        let mut other = alarm();
        other.payload = b"PUMP4".to_vec();
        assert_eq!(
            ops.submit(501, key(1), other.clone(), 5),
            Err(SubmitError::Conflict { existing: op })
        );
        // Another principal / network with the same key is a different
        // identity — never confused with the first.
        assert!(matches!(
            ops.submit(502, key(1), alarm(), 5),
            Ok(SubmitOutcome::Accepted(_))
        ));
        other.network = NET + 1;
        assert!(matches!(
            ops.submit(501, key(1), other, 5),
            Ok(SubmitOutcome::Accepted(_))
        ));
    }

    #[test]
    fn tables_are_bounded() {
        let ops = GroupOps::default();
        let mut lane = GroupLane::default();
        // Host queue bound.
        for n in 0..QUEUE_CAP as u8 {
            submit(&ops, n, 0);
        }
        assert!(matches!(
            ops.submit(501, key(200), alarm(), 0),
            Err(SubmitError::NoCapacity { queued: 8, .. })
        ));
        // Written to the device (DEVICE_PENDING): the unsettled bound
        // still holds at LIVE_CAP.
        assert_eq!(ops.step(&mut lane, &link(), 0).frames.len(), QUEUE_CAP);
        for n in QUEUE_CAP as u8..LIVE_CAP as u8 {
            submit(&ops, n, 1);
        }
        assert!(matches!(
            ops.submit(501, key(201), alarm(), 1),
            Err(SubmitError::NoCapacity { live: 16, .. })
        ));
        // Everything times out (INDETERMINATE / NOT_SENT): terminal.
        let down = GroupLink {
            active: false,
            ..link()
        };
        ops.step(&mut lane, &down, 10_000);
        assert_eq!(ops.counts().1, 0);
        // Terminal records are evicted oldest-first beyond RECORD_CAP and
        // leave a tombstone: the evicted key answers WindowExpired.
        let mut n: u32 = 1_000;
        while ops.counts().0 < RECORD_CAP {
            let mut k = [0_u8; 16];
            k[..4].copy_from_slice(&n.to_be_bytes());
            ops.submit(501, k, alarm(), 20_000).unwrap();
            ops.step(&mut lane, &down, 30_000);
            n += 1;
        }
        assert_eq!(ops.counts().3, 0);
        let mut k = [0_u8; 16];
        k[..4].copy_from_slice(&n.to_be_bytes());
        ops.submit(501, k, alarm(), 40_000).unwrap();
        assert_eq!(ops.counts().0, RECORD_CAP);
        assert_eq!(ops.counts().3, 1);
        assert!(ops.knows(501, NET, &key(0)));
        assert_eq!(
            ops.submit(501, key(0), alarm(), 40_000),
            Err(SubmitError::WindowExpired)
        );
    }

    #[test]
    fn inbox_is_bounded() {
        let ops = GroupOps::default();
        for i in 0..INBOX_CAP as u64 {
            assert!(ops.post_status(i, vec![1, 0x51, 0, 0]));
        }
        assert!(!ops.post_status(99, vec![1, 0x51, 0, 0]));
        let mut lane = GroupLane::default();
        let out = ops.step(&mut lane, &link(), 0);
        assert_eq!(out.notes.len(), INBOX_CAP);
        assert!(ops.post_status(100, vec![]));
    }

    #[test]
    fn tokens_and_names() {
        assert_eq!(op_token(0x1_0000_00a1), "grp00000001000000a1");
        assert_eq!(parse_op_token("grp00000001000000a1"), Some(0x1_0000_00a1));
        for bad in [
            "grp00000001000000A1",
            "grp1",
            "cfg00000001000000a1",
            "grp0000000000000000",
        ] {
            assert_eq!(parse_op_token(bad), None, "{bad}");
        }
        assert!(group_capable(0x84));
        assert!(!group_capable(0x80)); // host_ops_v1 missing
        assert!(!group_capable(0x07));
        assert!(!owns(&golden("07_group_send.json"))); // H→G only
        assert!(owns(&golden("13_group_query_status.json")));
        assert!(!owns_request(400));
        let ops = GroupOps::with_boot(0x1122_3344_5566_7788);
        let op = submit(&ops, 1, 0);
        assert_ne!(op >> 32, 0, "boot tag in the high word");
    }

    /// `wait_for` wakes on the lane's step, not only on its deadline.
    #[test]
    fn wait_for_wakes_on_change() {
        let ops = Arc::new(GroupOps::default());
        let op = submit(&ops, 1, 0);
        let driver = Arc::clone(&ops);
        let handle = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            let mut lane = GroupLane::default();
            let out = driver.step(&mut lane, &link(), 1);
            driver.post_status(
                out.frames[0].0,
                encode_group_status(&status(STATE_DELIVERED, "GROUP_COMPLETE")).unwrap(),
            );
            driver.step(&mut lane, &link(), 2);
        });
        let started = Instant::now();
        let record = ops
            .wait_for(op, Duration::from_secs(10), GroupOps::settled)
            .unwrap();
        handle.join().unwrap();
        assert!(record.is_final(), "{record:?}");
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(record.state_name(), "DELIVERED");
    }
}
