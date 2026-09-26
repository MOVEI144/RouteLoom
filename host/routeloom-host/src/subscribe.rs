//! Subscription hub, per-subscription staging queues, and the
//! per-connection pump behind the API1 push receive surface — issue #7,
//! implemented per docs/design/sdk-completion/05-receive-api.md.
//!
//! Two streams share one delivery model: `messages` follows the bounded
//! per-network `ReceiveLog` by cursor position (the log itself is the
//! replay backlog — a subscriber that falls behind is never re-buffered,
//! it lags and gets an in-band `gap` marker), and `events` mirrors the
//! daemon's diagnostic ring by event seq with an `overflow` marker
//! instead of cursors. Each subscription owns a bounded staging queue
//! between the pump and the socket so a slow reader can never stall
//! ingest or other clients: record lines drop-oldest into coalesced
//! markers, control lines charge a separate small reserve, and a truly
//! stuck socket still dies via the normal client write-timeout path.
//!
//! Lock order (the `DispatchInbox` discipline): producers release
//! `receive_log`/`state.events` BEFORE calling `hub.notify()`; the pump
//! never holds the hub mutex while acquiring either data lock, and the
//! socket writer is only taken for already-assembled lines.

use crate::acl;
use crate::api1::{record_json, record_meta_json};
use crate::receive_log::{Cursor, ReadOutcome, RxRecord, PAGE_LIMIT};
use crate::{now_ms, State};
use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

// Bounds pinned by 05-receive-api.md §5.5 (host.md §8 names the same
// per-subscriber queue contract). capabilities.get advertises the same
// values under receive.*.
pub const SUBS_PER_CONNECTION: usize = 4;
pub const SUBS_PER_PRINCIPAL: usize = 4;
pub const SUBS_TOTAL: usize = 16;
pub const SUB_QUEUE_EVENTS: usize = 128;
pub const SUB_QUEUE_BYTES: usize = 262_144;
/// Markers/heartbeat/ended bypass the data bound but are still bounded —
/// a connection that cannot drain 8 control lines is dead for practical
/// purposes and the pump tears it down (§5.5 rule 1/3).
pub const SUB_CONTROL_RESERVE: usize = 8;
pub const NOTIFY_LINE_MAX: usize = 8192;
/// Records drained per subscription per pass — same bound as a
/// messages.read page so one flooded sibling cannot starve the others.
pub const SUB_PAGE: usize = PAGE_LIMIT;
/// `messages.read` long-poll ceiling.
pub const WAIT_MS_MAX: u64 = 15_000;
pub const HEARTBEAT_MS_MIN: u64 = 1_000;
pub const HEARTBEAT_MS_MAX: u64 = 60_000;
pub const HEARTBEAT_MS_DEFAULT: u64 = 10_000;
/// origins/gateways allow at most 8 entries each; kinds at most 16.
pub const FILTER_MAX: usize = 8;
pub const KINDS_MAX: usize = 16;

/// Charged per staged line on top of the serialized body so the byte
/// bound covers the notification envelope too (subscription token, kind,
/// ordinal n, punctuation — ≈80B worst case).
const LINE_OVERHEAD: usize = 96;

/// Event kinds the daemon's diagnostic ring can actually emit — the
/// `filter.kinds` whitelist for `stream:"events"`. Payloads never appear
/// here by design; `data_from_mesh` entries are summaries only.
pub const EVENT_KINDS: &[&str] = &[
    "adapter",
    "auth_ok",
    "boot",
    "credit",
    "credit_close",
    "credit_grant",
    "credit_query",
    "data_from_mesh",
    "decode_error",
    "delivery_event",
    "diagnostic",
    "diagnostic_loss",
    "dispatch",
    "error",
    "frame",
    "group_settled",
    "gw_ingress",
    "hello_ack",
    "host_ops_rx",
    "keepalive",
    "link_changed",
    "node_joined",
    "node_left",
    "rx_conflict",
    "rx_drop",
    "session",
    "session_drop",
];

/// `sub%016x` — the subscription token handed to clients. Ids carry a
/// per-boot tag in the high word so a token from a previous daemon run
/// can never resolve inside this one.
pub fn token(id: u64) -> String {
    format!("sub{id:016x}")
}

pub fn parse_token(text: &str) -> Option<u64> {
    let hex = text.strip_prefix("sub")?;
    if hex.len() != 16 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(hex, 16).ok()
}

/// Which capacity bound refused a subscribe (§5.3.5 → NO_CAPACITY).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapacityDeny {
    Connection,
    Principal,
    Global,
}

/// Per-network message subscription filter (05 §5.3.1).
#[derive(Clone, Debug)]
pub struct MsgFilter {
    pub network: u64,
    pub origins: Option<Vec<u64>>,
    pub gateways: Option<Vec<u64>>,
    /// true → `message` notifications carrying payload_hex (needs
    /// READ_PAYLOAD); false → `message_meta` with payload_sha256 only
    /// (needs READ_OPERATION).
    pub payloads: bool,
}

/// Diagnostic-ring subscription filter (event kinds, exact names).
#[derive(Clone, Debug)]
pub struct EvFilter {
    pub kinds: Option<Vec<String>>,
}

#[derive(Clone, Debug)]
pub enum SubKind {
    Messages(MsgFilter),
    Events(EvFilter),
}

/// One staged notification: `body` is the payload member list fragment
/// (e.g. `"record":{…}` or `"cause":"gap",…`) — the drain step wraps it
/// in the `{subscription,kind,n,…}` envelope at socket-write time so `n`
/// is monotone per subscription in wire order.
enum StageItem {
    /// Droppable under queue pressure; `seq` is the log/event seq the
    /// line covers, used to name the coalesced marker's lost range.
    Data {
        seq: u64,
        kind: &'static str,
        body: String,
    },
    /// Never dropped — markers and heartbeats charge the separate
    /// SUB_CONTROL_RESERVE bound instead.
    Control { kind: &'static str, body: String },
}

impl StageItem {
    fn kind(&self) -> &'static str {
        match self {
            StageItem::Data { kind, .. } | StageItem::Control { kind, .. } => kind,
        }
    }

    fn body(&self) -> &str {
        match self {
            StageItem::Data { body, .. } | StageItem::Control { body, .. } => body,
        }
    }
}

/// The queue-overflow outcome of pushing one control line.
enum ControlPush {
    Staged,
    /// Reserve exhausted — for a mandatory marker this is fatal to the
    /// connection; a heartbeat just skips this interval.
    Full,
}

/// What one `push_data` did to the queue: record lines dropped and
/// markers inserted, plus whether the control reserve blew out.
#[derive(Default)]
struct StageStat {
    dropped: u64,
    markers: u64,
    fatal: bool,
}

/// Bounded per-subscription staging between pump and socket
/// (§5.5 rule 1). Data lines are bounded by count and bytes; on overflow
/// the oldest contiguous run of data lines drops and is replaced *in
/// place* by one marker, so the marker always precedes the first record
/// delivered after the skipped range (§5.8 rule 3).
#[derive(Default)]
pub struct StageQueue {
    items: VecDeque<StageItem>,
    data_len: usize,
    data_bytes: usize,
    control_len: usize,
    control_bytes: usize,
}

impl StageQueue {
    fn push_data(
        &mut self,
        seq: u64,
        kind: &'static str,
        body: String,
        marker: &MarkerFn,
    ) -> StageStat {
        let charge = body.len() + LINE_OVERHEAD;
        let mut stat = StageStat::default();
        while self.data_len >= SUB_QUEUE_EVENTS || self.data_bytes + charge > SUB_QUEUE_BYTES {
            // Drop the oldest contiguous run of data lines (markers and
            // other control lines between runs stay put).
            let Some(start) = self
                .items
                .iter()
                .position(|item| matches!(item, StageItem::Data { .. }))
            else {
                break;
            };
            let mut end = start;
            let (mut lost_from, mut lost_to) = (u64::MAX, 0_u64);
            while end < self.items.len() {
                if let StageItem::Data { seq: s, .. } = &self.items[end] {
                    lost_from = lost_from.min(*s);
                    lost_to = lost_to.max(*s);
                    end += 1;
                } else {
                    break;
                }
            }
            for _ in start..end {
                if let Some(StageItem::Data { body, .. }) = self.items.remove(start) {
                    self.data_len -= 1;
                    self.data_bytes -= body.len() + LINE_OVERHEAD;
                }
            }
            let (marker_kind, marker_body) = marker(lost_from, lost_to);
            self.control_bytes += marker_body.len() + LINE_OVERHEAD;
            self.control_len += 1;
            self.items.insert(
                start,
                StageItem::Control {
                    kind: marker_kind,
                    body: marker_body,
                },
            );
            stat.dropped += (end - start) as u64;
            stat.markers += 1;
            if self.control_len > SUB_CONTROL_RESERVE {
                stat.fatal = true;
            }
        }
        self.items.push_back(StageItem::Data { seq, kind, body });
        self.data_len += 1;
        self.data_bytes += charge;
        stat
    }

    fn push_control(&mut self, kind: &'static str, body: String) -> ControlPush {
        if self.control_len >= SUB_CONTROL_RESERVE {
            return ControlPush::Full;
        }
        self.control_bytes += body.len() + LINE_OVERHEAD;
        self.control_len += 1;
        self.items.push_back(StageItem::Control { kind, body });
        ControlPush::Staged
    }

    fn pop_front(&mut self) -> Option<StageItem> {
        let item = self.items.pop_front()?;
        match &item {
            StageItem::Data { body, .. } => {
                self.data_len -= 1;
                self.data_bytes -= body.len() + LINE_OVERHEAD;
            }
            StageItem::Control { body, .. } => {
                self.control_len -= 1;
                self.control_bytes -= body.len() + LINE_OVERHEAD;
            }
        }
        Some(item)
    }

    fn queued(&self) -> usize {
        self.items.len()
    }

    fn queued_bytes(&self) -> usize {
        self.data_bytes + self.control_bytes
    }
}

/// One live (or pending) subscription. `position` is the resume point:
/// for messages it is a `last_scanned` seq (the next notification is the
/// first retained record with seq > position); for events it is the next
/// event seq to deliver.
pub struct Subscription {
    pub id: u64,
    pub uid: Option<u32>,
    /// ACL revision the subscription was authorized under — the lazy
    /// per-pass re-check compares it to the live revision and ends the
    /// stream with `acl_view_changed` if they ever diverge (§5.6).
    pub acl_view: u64,
    pub kind: SubKind,
    pub position: u64,
    pub created_ms: u64,
    pub heartbeat_ms: u64,
    pub next_heartbeat_ms: u64,
    /// Lines handed to the socket writer (n == delivered when caught up).
    pub delivered: u64,
    /// Record/event lines lost from the staging queue (markers replace
    /// them, so the loss is auditable).
    pub dropped: u64,
    /// gap/overflow markers emitted.
    pub gaps: u64,
    /// Per-subscription wire ordinal — assigned when a line is taken for
    /// writing, monotone from 1.
    pub emitted: u64,
    /// Registered but not yet on the wire: activates only after the
    /// subscribe ok response is flushed (§5.8 rule 1).
    pub pending: bool,
    /// Server-ended reason; the `ended` line is synthesized once the
    /// queue drains, then the subscription is removed (§5.8 rule 3).
    pub ending: Option<&'static str>,
    pub queue: StageQueue,
}

/// What one produce+stage cycle fed into a subscription's queue.
#[derive(Default)]
pub struct StageWork {
    /// Data lines (kind "message"/"message_meta"/"event") and already
    /// built control markers (kind "gap"/"overflow"), in emit order.
    pub items: Vec<StagedLine>,
    /// New read position for the subscription (None = unchanged).
    pub new_position: Option<u64>,
    /// Heartbeat body fragment when one came due this pass.
    pub heartbeat: Option<String>,
    /// Server-side end reason; the sub drains its queue, emits `ended`
    /// last, then is removed.
    pub end_reason: Option<&'static str>,
}

/// One line to stage: `seq` matters only for data items (it names the
/// marker's lost range if the line is dropped).
pub struct StagedLine {
    pub control: bool,
    pub kind: &'static str,
    pub body: String,
    pub seq: u64,
}

/// Builds the in-queue marker body for a dropped run [lo..=hi] — `gap`
/// for messages (with a resume cursor), `overflow` for events.
pub type MarkerFn<'a> = dyn Fn(u64, u64) -> (&'static str, String) + 'a;

/// Final counters reported by `messages.unsubscribe`.
pub struct SubStats {
    pub delivered: u64,
    pub dropped: u64,
    pub gaps: u64,
    pub lifetime_ms: u64,
}

/// One `messages.subscriptions` entry — the connection's own view.
pub struct SubListEntry {
    pub id: u64,
    pub is_events: bool,
    pub network: Option<u64>,
    pub payloads: bool,
    /// messages: last_scanned; events: next-to-deliver seq.
    pub position: u64,
    pub delivered: u64,
    pub dropped: u64,
    pub gaps: u64,
    pub queued: usize,
    pub queued_bytes: usize,
    pub created_ms: u64,
}

/// A pump-pass snapshot of one subscription (cloned under the hub lock —
/// the pump then reads the log/events WITHOUT holding the hub).
pub struct SubSnap {
    pub id: u64,
    pub uid: Option<u32>,
    pub acl_view: u64,
    pub kind: SubKind,
    pub position: u64,
    pub heartbeat_ms: u64,
    pub next_heartbeat_ms: u64,
}

struct ConnSubs {
    subs: Vec<Subscription>,
    /// The pump thread exists exactly once per connection while its
    /// registry entry lives — set on first activation, cleared only when
    /// the whole connection is removed, so ids can never be double-pumped.
    pump_running: bool,
}

#[derive(Default)]
struct HubInner {
    conns: HashMap<u64, ConnSubs>,
    /// Subscription id cursor — tagged with host_boot in the high word
    /// (ConfigOps::with_boot discipline) so tokens never alias across runs.
    next_sub: u64,
    /// Bumped on every producer notification; the pump and the
    /// messages.read long-poll wait on it.
    dirty: u64,
}

/// The subscription registry shared by api1 (register/unregister/list),
/// the per-connection pump (snapshot/stage/drain), and producers
/// (notify). RAM-only: a daemon restart ends every stream as socket EOF.
pub struct SubscriptionHub {
    inner: Mutex<HubInner>,
    changed: Condvar,
}

impl Default for SubscriptionHub {
    /// Zero tag for tests/fixtures; the daemon uses `with_boot`.
    fn default() -> Self {
        Self::with_boot(0)
    }
}

impl SubscriptionHub {
    /// Mint the hub bound to this daemon incarnation: subscription ids
    /// are `(tag32 << 32) | seq` where the tag folds host_boot (bit0
    /// forced so it is never zero) — the same namespacing ConfigOps uses.
    pub fn with_boot(host_boot: u64) -> Self {
        let tag = ((host_boot as u32) ^ ((host_boot >> 32) as u32)) | 1;
        Self {
            inner: Mutex::new(HubInner {
                next_sub: u64::from(tag) << 32,
                ..HubInner::default()
            }),
            changed: Condvar::new(),
        }
    }

    /// Register a pending subscription. Enforces per-connection,
    /// per-principal and global caps — a denied subscribe costs nothing
    /// and the error is retryable (§5.5 rule 4).
    #[allow(clippy::too_many_arguments)]
    pub fn subscribe(
        &self,
        conn_id: u64,
        uid: Option<u32>,
        kind: SubKind,
        position: u64,
        acl_view: u64,
        heartbeat_ms: u64,
        now_ms: u64,
    ) -> Result<u64, CapacityDeny> {
        let mut inner = self.inner.lock().expect("subscription hub poisoned");
        if inner.conns.get(&conn_id).map_or(0, |c| c.subs.len()) >= SUBS_PER_CONNECTION {
            return Err(CapacityDeny::Connection);
        }
        if inner
            .conns
            .values()
            .flat_map(|c| &c.subs)
            .filter(|s| s.uid == uid)
            .count()
            >= SUBS_PER_PRINCIPAL
        {
            return Err(CapacityDeny::Principal);
        }
        if inner.conns.values().map(|c| c.subs.len()).sum::<usize>() >= SUBS_TOTAL {
            return Err(CapacityDeny::Global);
        }
        let id = inner.next_sub.wrapping_add(1);
        inner.next_sub = id;
        inner
            .conns
            .entry(conn_id)
            .or_insert_with(|| ConnSubs {
                subs: Vec::new(),
                pump_running: false,
            })
            .subs
            .push(Subscription {
                id,
                uid,
                acl_view,
                kind,
                position,
                created_ms: now_ms,
                heartbeat_ms,
                next_heartbeat_ms: if heartbeat_ms == 0 {
                    u64::MAX
                } else {
                    now_ms.saturating_add(heartbeat_ms)
                },
                delivered: 0,
                dropped: 0,
                gaps: 0,
                emitted: 0,
                pending: true,
                ending: None,
                queue: StageQueue::default(),
            });
        Ok(id)
    }

    /// Pending → live, called by the socket layer once the ok response is
    /// on the wire (§5.8 rule 1). Returns true when the connection needs
    /// its pump spawned (first activation while no pump runs).
    pub fn activate(&self, conn_id: u64, id: u64) -> bool {
        let mut inner = self.inner.lock().expect("subscription hub poisoned");
        let Some(conn) = inner.conns.get_mut(&conn_id) else {
            return false;
        };
        let Some(sub) = conn.subs.iter_mut().find(|s| s.id == id) else {
            return false;
        };
        sub.pending = false;
        let spawn = !conn.pump_running;
        conn.pump_running = true;
        inner.dirty += 1;
        drop(inner);
        self.changed.notify_all();
        spawn
    }

    /// Own-connection unsubscribe: foreign/unknown ids resolve NOT_FOUND
    /// in the caller — there is no cross-connection existence oracle.
    pub fn unsubscribe(&self, conn_id: u64, id: u64, now_ms: u64) -> Option<SubStats> {
        let mut inner = self.inner.lock().expect("subscription hub poisoned");
        let conn = inner.conns.get_mut(&conn_id)?;
        let index = conn.subs.iter().position(|s| s.id == id)?;
        let sub = conn.subs.remove(index);
        inner.dirty += 1;
        drop(inner);
        self.changed.notify_all();
        Some(SubStats {
            delivered: sub.delivered,
            dropped: sub.dropped,
            gaps: sub.gaps,
            lifetime_ms: now_ms.saturating_sub(sub.created_ms),
        })
    }

    /// The caller's own subscriptions only — never another connection's.
    pub fn list(&self, conn_id: u64) -> Vec<SubListEntry> {
        let inner = self.inner.lock().expect("subscription hub poisoned");
        inner
            .conns
            .get(&conn_id)
            .map(|conn| {
                conn.subs
                    .iter()
                    .map(|sub| SubListEntry {
                        id: sub.id,
                        is_events: matches!(sub.kind, SubKind::Events(_)),
                        network: match &sub.kind {
                            SubKind::Messages(f) => Some(f.network),
                            SubKind::Events(_) => None,
                        },
                        payloads: match &sub.kind {
                            SubKind::Messages(f) => f.payloads,
                            SubKind::Events(_) => false,
                        },
                        position: sub.position,
                        delivered: sub.delivered,
                        dropped: sub.dropped,
                        gaps: sub.gaps,
                        queued: sub.queue.queued(),
                        queued_bytes: sub.queue.queued_bytes(),
                        created_ms: sub.created_ms,
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Connection teardown: EOF, error, QUIT or panic all end here. No
    /// subscription outlives its socket — a dead peer is owed no `ended`.
    pub fn remove_conn(&self, conn_id: u64) {
        let mut inner = self.inner.lock().expect("subscription hub poisoned");
        inner.conns.remove(&conn_id);
        inner.dirty += 1;
        drop(inner);
        self.changed.notify_all();
    }

    /// Producer-side change signal — O(1) dirty flag + broadcast, never
    /// called while a data lock is held.
    pub fn notify(&self) {
        self.inner.lock().expect("subscription hub poisoned").dirty += 1;
        self.changed.notify_all();
    }

    pub fn dirty_epoch(&self) -> u64 {
        self.inner.lock().expect("subscription hub poisoned").dirty
    }

    /// Wait until the dirty epoch moves or `dur` passes. Returns the new
    /// epoch — callers re-check their own predicate, so spurts and
    /// unrelated notifications are harmless.
    pub fn wait(&self, seen: u64, dur: Duration) -> u64 {
        let mut inner = self.inner.lock().expect("subscription hub poisoned");
        if inner.dirty == seen {
            let (guard, _) = self
                .changed
                .wait_timeout(inner, dur)
                .expect("subscription hub poisoned");
            inner = guard;
        }
        inner.dirty
    }

    /// Live (non-pending, non-ending) subscriptions of one connection for
    /// a pump pass — None when the connection entry is gone.
    pub fn snapshot(&self, conn_id: u64) -> Option<Vec<SubSnap>> {
        let inner = self.inner.lock().expect("subscription hub poisoned");
        inner.conns.get(&conn_id).map(|conn| {
            conn.subs
                .iter()
                .filter(|sub| !sub.pending && sub.ending.is_none())
                .map(|sub| SubSnap {
                    id: sub.id,
                    uid: sub.uid,
                    acl_view: sub.acl_view,
                    kind: sub.kind.clone(),
                    position: sub.position,
                    heartbeat_ms: sub.heartbeat_ms,
                    next_heartbeat_ms: sub.next_heartbeat_ms,
                })
                .collect()
        })
    }

    /// Apply one produce pass: stage the items (data through the bounded
    /// drop-oldest path, control through the reserve), update position,
    /// schedule the next heartbeat, mark a server-ended sub. `marker`
    /// mints the in-queue gap/overflow body for a dropped seq range.
    /// Returns true when the control reserve blew out — the connection
    /// is then dead for practical purposes (§5.5).
    pub fn stage(
        &self,
        conn_id: u64,
        sub_id: u64,
        work: StageWork,
        marker: &MarkerFn,
        now_ms: u64,
    ) -> bool {
        let mut inner = self.inner.lock().expect("subscription hub poisoned");
        let Some(sub) = inner
            .conns
            .get_mut(&conn_id)
            .and_then(|conn| conn.subs.iter_mut().find(|s| s.id == sub_id))
        else {
            return false;
        };
        let mut fatal = false;
        for item in work.items {
            if item.body.len() + LINE_OVERHEAD > NOTIFY_LINE_MAX {
                // A notification is never truncated mid-JSON (SUB20): a
                // data line too big for the wire bound is replaced by the
                // stream's marker naming its own seq; an oversized control
                // line is a daemon bug — fail the connection honestly.
                if item.control {
                    fatal = true;
                    continue;
                }
                let (kind, body) = marker(item.seq, item.seq);
                sub.dropped += 1;
                sub.gaps += 1;
                if matches!(sub.queue.push_control(kind, body), ControlPush::Full) {
                    fatal = true;
                }
                continue;
            }
            if item.control {
                match sub.queue.push_control(item.kind, item.body) {
                    ControlPush::Staged => {
                        if matches!(item.kind, "gap" | "overflow") {
                            sub.gaps += 1;
                        }
                    }
                    ControlPush::Full => fatal = true,
                }
            } else {
                let stat = sub.queue.push_data(item.seq, item.kind, item.body, marker);
                sub.dropped += stat.dropped;
                sub.gaps += stat.markers;
                fatal |= stat.fatal;
            }
        }
        if let Some(body) = work.heartbeat {
            // A heartbeat is best-effort liveness — never let it kill the
            // connection; the interval still reschedules either way.
            let _ = sub.queue.push_control("heartbeat", body);
            sub.next_heartbeat_ms = now_ms.saturating_add(sub.heartbeat_ms);
        }
        if let Some(position) = work.new_position {
            sub.position = position;
        }
        if work.end_reason.is_some() {
            sub.ending = work.end_reason;
        }
        fatal
    }

    /// Pre-stage a control line on a pending subscription (the
    /// `gap{cause:"start_position"}` marker an `on_gap:"skip"` subscribe
    /// must emit before any record). Pending subs are never drained, so
    /// it sits first in line until activation.
    pub fn stage_marker(&self, conn_id: u64, sub_id: u64, kind: &'static str, body: String) {
        let mut inner = self.inner.lock().expect("subscription hub poisoned");
        if let Some(sub) = inner
            .conns
            .get_mut(&conn_id)
            .and_then(|conn| conn.subs.iter_mut().find(|s| s.id == sub_id))
        {
            if matches!(sub.queue.push_control(kind, body), ControlPush::Staged)
                && matches!(kind, "gap" | "overflow")
            {
                sub.gaps += 1;
            }
        }
    }

    /// Pop every staged line on the connection (pending subs excluded —
    /// nothing may be written before their ok response), assemble the
    /// wire envelope, assign `n`, and synthesize the trailing `ended`
    /// line of subs whose end was marked. Ended subs are removed here
    /// once their queue is empty so `ended` is always the last line.
    pub fn drain(&self, conn_id: u64) -> Vec<String> {
        let mut inner = self.inner.lock().expect("subscription hub poisoned");
        let mut out = Vec::new();
        let Some(conn) = inner.conns.get_mut(&conn_id) else {
            return out;
        };
        let mut index = 0;
        while index < conn.subs.len() {
            {
                let sub = &mut conn.subs[index];
                if !sub.pending {
                    while let Some(item) = sub.queue.pop_front() {
                        sub.emitted += 1;
                        sub.delivered += 1;
                        let n = sub.emitted;
                        out.push(format!(
                            "{{\"subscription\":\"{}\",\"kind\":\"{}\",\"n\":{n},{}}}",
                            token(sub.id),
                            item.kind(),
                            item.body(),
                        ));
                    }
                    if let Some(reason) = sub.ending {
                        sub.emitted += 1;
                        let n = sub.emitted;
                        out.push(format!(
                            "{{\"subscription\":\"{}\",\"kind\":\"ended\",\"n\":{n},\"reason\":\"{reason}\",\"delivered\":{},\"dropped\":{}}}",
                            token(sub.id),
                            sub.delivered,
                            sub.dropped,
                        ));
                    }
                }
            }
            if conn.subs[index].ending.is_some() && conn.subs[index].queue.queued() == 0 {
                conn.subs.remove(index);
            } else {
                index += 1;
            }
        }
        out
    }

    /// Time until the next heartbeat is due on this connection — the
    /// pump's sleep bound when nothing notifies.
    pub fn due_in(&self, conn_id: u64, now_ms: u64) -> Duration {
        let inner = self.inner.lock().expect("subscription hub poisoned");
        let mut min = u64::MAX;
        if let Some(conn) = inner.conns.get(&conn_id) {
            for sub in &conn.subs {
                if !sub.pending && sub.ending.is_none() && sub.heartbeat_ms > 0 {
                    min = min.min(sub.next_heartbeat_ms.saturating_sub(now_ms));
                }
            }
        }
        if min == u64::MAX {
            // Nothing time-driven pending — sleep until notified (conn
            // teardown, subscribe/activate and every ingest all notify).
            Duration::from_secs(3600)
        } else {
            Duration::from_millis(min)
        }
    }

    /// The connection's registry entry is gone — its pump must exit.
    pub fn conn_gone(&self, conn_id: u64) -> bool {
        !self
            .inner
            .lock()
            .expect("subscription hub poisoned")
            .conns
            .contains_key(&conn_id)
    }
}

/// Pump-pass result.
enum PassOutcome {
    /// Work happened — run another pass immediately (backlog drain is
    /// round-robin at SUB_PAGE per subscription per pass).
    Worked,
    /// Nothing staged or drained — sleep until notified or a heartbeat.
    Idle,
    /// The connection's registry entry vanished — exit the pump.
    Finished,
    /// Socket write failed / control reserve exhausted — the connection
    /// is being torn down.
    Dead,
}

/// The per-connection pump (05 §5.5/§5.6): waits on the hub's change
/// condvar (bounded by the nearest heartbeat), snapshots this
/// connection's subscriptions, reads the receive log / event ring
/// WITHOUT holding the hub lock, stages lines, then writes the drained
/// queue to the socket under the shared writer mutex.
pub fn pump_connection(
    state: Arc<State>,
    conn_id: u64,
    writer: Arc<Mutex<UnixStream>>,
    conn_alive: Arc<AtomicBool>,
) {
    // The log epoch is fixed per run — cursors minted on this connection
    // all bind to it.
    let epoch = state
        .receive_log
        .lock()
        .expect("receive log poisoned")
        .epoch();
    let mut seen = state.subscriptions.dirty_epoch();
    while conn_alive.load(Ordering::Relaxed) {
        // Run passes while any subscription still has backlog; each pass
        // is bounded (SUB_PAGE per sub) so siblings stay fair.
        loop {
            match pump_pass(&state, conn_id, &writer, &epoch) {
                PassOutcome::Worked => {
                    if !conn_alive.load(Ordering::Relaxed) {
                        return;
                    }
                }
                PassOutcome::Idle => break,
                PassOutcome::Finished => return,
                PassOutcome::Dead => {
                    conn_alive.store(false, Ordering::Relaxed);
                    return;
                }
            }
        }
        if state.subscriptions.conn_gone(conn_id) {
            return;
        }
        let wait = state.subscriptions.due_in(conn_id, now_ms());
        seen = state.subscriptions.wait(seen, wait);
    }
}

fn pump_pass(
    state: &State,
    conn_id: u64,
    writer: &Mutex<UnixStream>,
    epoch: &[u8; 16],
) -> PassOutcome {
    let Some(snaps) = state.subscriptions.snapshot(conn_id) else {
        return PassOutcome::Finished;
    };
    let acl_rev = state.acl.revision();
    let now = now_ms();
    let mut worked = false;
    let mut fatal = false;
    for snap in &snaps {
        let marker = marker_for(state, snap, epoch, acl_rev, now);
        let (work, progressed) = match &snap.kind {
            SubKind::Messages(filter) => produce_messages(state, snap, filter, epoch, acl_rev, now),
            SubKind::Events(filter) => produce_events(state, snap, filter, now),
        };
        worked |= progressed;
        if state
            .subscriptions
            .stage(conn_id, snap.id, work, &marker, now)
        {
            fatal = true;
        }
    }
    let lines = state.subscriptions.drain(conn_id);
    if !lines.is_empty() {
        worked = true;
        let mut socket = writer.lock().expect("client writer poisoned");
        for line in &lines {
            let written = socket
                .write_all(line.as_bytes())
                .and_then(|()| socket.write_all(b"\n"));
            if written.is_err() {
                // Socket stall/error — tear the connection down so the
                // reader thread and all its subscriptions exit too.
                let _ = socket.shutdown(Shutdown::Both);
                return PassOutcome::Dead;
            }
        }
        if socket.flush().is_err() {
            let _ = socket.shutdown(Shutdown::Both);
            return PassOutcome::Dead;
        }
    }
    if fatal {
        // The control reserve itself overflowed — the peer is dead for
        // practical purposes (§5.5).
        if let Ok(socket) = writer.lock() {
            let _ = socket.shutdown(Shutdown::Both);
        }
        return PassOutcome::Dead;
    }
    if worked {
        PassOutcome::Worked
    } else {
        PassOutcome::Idle
    }
}

/// The marker-body factory for one subscription's staging queue.
fn marker_for<'a>(
    state: &'a State,
    snap: &SubSnap,
    epoch: &[u8; 16],
    acl_rev: u64,
    now: u64,
) -> Box<MarkerFn<'a>> {
    match &snap.kind {
        SubKind::Messages(filter) => {
            let (network, epoch) = (filter.network, *epoch);
            Box::new(move |lost_from, lost_to| {
                let resume = Cursor {
                    network,
                    acl_view: acl_rev,
                    epoch,
                    last_scanned: lost_to,
                }
                .encode();
                (
                    "gap",
                    format!(
                        "\"cause\":\"queue_overflow\",\"lost_from\":{lost_from},\"lost_to\":{lost_to},\"resume_cursor\":\"{resume}\",\"recoverable_via_read\":true,\"ms\":{now}"
                    ),
                )
            })
        }
        SubKind::Events(_) => Box::new(move |lost_from, lost_to| {
            (
                "overflow",
                format!(
                    "\"lost_from\":{lost_from},\"lost_to\":{lost_to},\"dropped_total\":{},\"resume_seq\":{},\"ms\":{now}",
                    state.events_dropped.load(Ordering::Relaxed),
                    lost_to.saturating_add(1),
                ),
            )
        }),
    }
}

/// One produce pass for a messages subscription: the lazy per-pass ACL
/// re-check, one bounded page from the shared log at the sub's position
/// (gap → in-band `log_evicted` marker), the filter view, and heartbeat.
/// Never holds the log lock past the read.
fn produce_messages(
    state: &State,
    snap: &SubSnap,
    filter: &MsgFilter,
    epoch: &[u8; 16],
    acl_rev: u64,
    now: u64,
) -> (StageWork, bool) {
    let mut work = StageWork::default();
    let mut progressed = false;
    // Lazy per-pass ACL re-check (§5.6): a view revision change ends the
    // stream honestly instead of silently re-scoping it. The ACL loads
    // once today, so neither arm can fire yet — the contract is ready
    // for when reload lands.
    if snap.acl_view != acl_rev {
        work.end_reason = Some("acl_view_changed");
        return (work, true);
    }
    let perm = if filter.payloads {
        acl::PERM_READ_PAYLOAD
    } else {
        acl::PERM_READ_OPERATION
    };
    if !snap
        .uid
        .is_some_and(|uid| state.acl.permit(uid, filter.network, perm))
    {
        work.end_reason = Some("unauthorized");
        return (work, true);
    }
    let cursor_at = |position: u64| {
        Cursor {
            network: filter.network,
            acl_view: acl_rev,
            epoch: *epoch,
            last_scanned: position,
        }
        .encode()
    };
    let mut position = snap.position;
    let mut tail_seq = None;
    {
        let mut log = state.receive_log.lock().expect("receive log poisoned");
        // A Gap is a position jump, not a failure: emit the marker, move
        // to the reclaim boundary, then read once more into the page.
        for _ in 0..2 {
            match log.read(filter.network, position, SUB_PAGE, now, true) {
                ReadOutcome::Batch(batch) => {
                    tail_seq = Some(batch.tail_seq);
                    for record in &batch.records {
                        // Filtered-out records still advance the position —
                        // a filter is a view, not a second log (§5.4.3).
                        position = record.seq;
                        if !msg_matches(filter, record) {
                            continue;
                        }
                        progressed = true;
                        let (kind, record_body) = if filter.payloads {
                            ("message", record_json(record, &cursor_at(record.seq)))
                        } else {
                            (
                                "message_meta",
                                record_meta_json(record, &cursor_at(record.seq)),
                            )
                        };
                        work.items.push(StagedLine {
                            control: false,
                            kind,
                            body: format!("\"record\":{record_body}"),
                            seq: record.seq,
                        });
                    }
                    // A full page means more retained records wait beyond
                    // it — keep the pass loop alive.
                    progressed |= batch.more || !batch.records.is_empty();
                    break;
                }
                ReadOutcome::Gap {
                    lost_from,
                    lost_to,
                    tail_seq: tail,
                    ..
                } => {
                    tail_seq = Some(tail);
                    work.items.push(StagedLine {
                        control: true,
                        kind: "gap",
                        body: format!(
                            "\"cause\":\"log_evicted\",\"lost_from\":{lost_from},\"lost_to\":{lost_to},\"resume_cursor\":\"{}\",\"recoverable_via_read\":false,\"ms\":{now}",
                            cursor_at(lost_to)
                        ),
                        seq: 0,
                    });
                    position = lost_to;
                    progressed = true;
                }
                // The pump's position can never legitimately run ahead of
                // the tail — positions only advance through real reads.
                ReadOutcome::Future => break,
            }
        }
        if snap.heartbeat_ms > 0 && now >= snap.next_heartbeat_ms && tail_seq.is_none() {
            tail_seq = Some(log.bounds(filter.network, now).1);
        }
    }
    if snap.heartbeat_ms > 0 && now >= snap.next_heartbeat_ms {
        work.heartbeat = Some(format!(
            "\"cursor\":\"{}\",\"tail_seq\":{},\"ms\":{now}",
            cursor_at(position),
            tail_seq.unwrap_or(position),
        ));
        progressed = true;
    }
    work.new_position = Some(position);
    (work, progressed)
}

/// One produce pass for an events subscription: replay/drain ring
/// entries with seq >= position, mark overflow when the ring has already
/// lapped the position, heartbeat on schedule. The events stream has no
/// cursor — positions are bare event seqs living only on this connection.
fn produce_events(state: &State, snap: &SubSnap, filter: &EvFilter, now: u64) -> (StageWork, bool) {
    let mut work = StageWork::default();
    let mut position = snap.position;
    let mut progressed = false;
    let dropped_total = state.events_dropped.load(Ordering::Relaxed);
    {
        let events = state.events.lock().expect("events poisoned");
        if let Some(front) = events.front() {
            if position < front.seq {
                // The ring reclaimed entries this subscriber never saw.
                work.items.push(StagedLine {
                    control: true,
                    kind: "overflow",
                    body: format!(
                        "\"lost_from\":{position},\"lost_to\":{},\"dropped_total\":{dropped_total},\"resume_seq\":{},\"ms\":{now}",
                        front.seq - 1,
                        front.seq,
                    ),
                    seq: 0,
                });
                position = front.seq;
                progressed = true;
            }
            for event in events.iter() {
                if event.seq < position {
                    continue;
                }
                position = event.seq + 1;
                let matches = filter
                    .kinds
                    .as_ref()
                    .map_or(true, |kinds| kinds.iter().any(|k| k == &event.kind));
                if matches {
                    progressed = true;
                    work.items.push(StagedLine {
                        control: false,
                        kind: "event",
                        body: format!("\"event\":{}", event.json),
                        seq: event.seq,
                    });
                }
            }
        }
    }
    if snap.heartbeat_ms > 0 && now >= snap.next_heartbeat_ms {
        work.heartbeat = Some(format!(
            "\"event_seq\":{position},\"dropped_total\":{dropped_total},\"ms\":{now}"
        ));
        progressed = true;
    }
    work.new_position = Some(position);
    (work, progressed)
}

fn msg_matches(filter: &MsgFilter, record: &RxRecord) -> bool {
    filter
        .origins
        .as_ref()
        .map_or(true, |origins| origins.contains(&record.origin))
        && filter.gateways.as_ref().map_or(true, |gateways| {
            record.gateway.is_some_and(|g| gateways.contains(&g))
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg_sub(network: u64) -> SubKind {
        SubKind::Messages(MsgFilter {
            network,
            origins: None,
            gateways: None,
            payloads: true,
        })
    }

    #[test]
    fn boot_is_a_subscribable_event_kind() {
        // The daemon's first ring entry (restart boundary + build/config
        // identity) must survive a kinds filter so journals can select it.
        assert!(EVENT_KINDS.contains(&"boot"));
    }

    #[test]
    fn token_roundtrip_and_rejects() {
        let hub = SubscriptionHub::with_boot(0x1234_5678_9abc_def0);
        let id = hub
            .subscribe(1, Some(501), msg_sub(1), 0, 1, 0, 1_000)
            .unwrap();
        let tok = token(id);
        assert!(tok.starts_with("sub"), "{tok}");
        assert_eq!(parse_token(&tok), Some(id));
        for bad in [
            "",
            "sub",
            "sub1",
            "subzzzzzzzzzzzzzzzz",
            "SUB0000000000000001",
            "x",
        ] {
            assert!(parse_token(bad).is_none(), "{bad}");
        }
        // A token minted under a different boot tag never resolves here.
        let other = SubscriptionHub::with_boot(0xdead_beef);
        let foreign = other
            .subscribe(1, Some(501), msg_sub(1), 0, 1, 0, 1_000)
            .unwrap();
        assert_ne!(token(foreign), tok);
    }

    #[test]
    fn diagnostic_loss_is_a_subscribable_event_kind() {
        // The host-side gap signal must survive a kinds filter so
        // journals can select it alongside the diagnostics themselves.
        assert!(EVENT_KINDS.contains(&"diagnostic_loss"));
    }

    #[test]
    fn capacity_caps() {
        let hub = SubscriptionHub::default();
        // 4 per connection.
        for _ in 0..SUBS_PER_CONNECTION {
            hub.subscribe(1, Some(1), msg_sub(1), 0, 1, 0, 1_000)
                .unwrap();
        }
        assert_eq!(
            hub.subscribe(1, Some(1), msg_sub(1), 0, 1, 0, 1_000),
            Err(CapacityDeny::Connection)
        );
        // A different uid on the same connection is still conn-capped.
        assert_eq!(
            hub.subscribe(1, Some(2), msg_sub(1), 0, 1, 0, 1_000),
            Err(CapacityDeny::Connection)
        );
        // 4 per principal across connections.
        for conn in 2..=3_u64 {
            hub.subscribe(conn, Some(2), msg_sub(1), 0, 1, 0, 1_000)
                .unwrap();
        }
        // uid 2 has 4 total (1 on conn 1 was uid 1 — recount: uid2 has 2).
        hub.subscribe(4, Some(2), msg_sub(1), 0, 1, 0, 1_000)
            .unwrap();
        hub.subscribe(4, Some(2), msg_sub(1), 0, 1, 0, 1_000)
            .unwrap();
        assert_eq!(
            hub.subscribe(5, Some(2), msg_sub(1), 0, 1, 0, 1_000),
            Err(CapacityDeny::Principal)
        );
        // Global cap: fill remaining slots with distinct uids/conns.
        let mut conn = 10_u64;
        let mut uid = 100_u32;
        loop {
            match hub.subscribe(conn, Some(uid), msg_sub(1), 0, 1, 0, 1_000) {
                Ok(_) => {}
                Err(CapacityDeny::Global) => break,
                other => panic!("unexpected {other:?}"),
            }
            conn += 1;
            uid += 1;
        }
        assert_eq!(
            hub.subscribe(999, Some(999), msg_sub(1), 0, 1, 0, 1_000),
            Err(CapacityDeny::Global)
        );
    }

    #[test]
    fn remove_conn_frees_counts() {
        let hub = SubscriptionHub::default();
        for _ in 0..SUBS_PER_CONNECTION {
            hub.subscribe(1, Some(1), msg_sub(1), 0, 1, 0, 1_000)
                .unwrap();
        }
        assert!(hub
            .subscribe(1, Some(1), msg_sub(1), 0, 1, 0, 1_000)
            .is_err());
        hub.remove_conn(1);
        assert!(hub.conn_gone(1));
        hub.subscribe(1, Some(1), msg_sub(1), 0, 1, 0, 1_000)
            .unwrap();
    }

    #[test]
    fn unsubscribe_stats_and_ownership() {
        let hub = SubscriptionHub::default();
        let id = hub
            .subscribe(7, Some(1), msg_sub(1), 5, 1, 0, 1_000)
            .unwrap();
        // Foreign connection sees no oracle.
        assert!(hub.unsubscribe(8, id, 2_000).is_none());
        let stats = hub.unsubscribe(7, id, 2_000).expect("own sub");
        assert_eq!(stats.delivered, 0);
        assert_eq!(stats.lifetime_ms, 1_000);
        // Already-removed id is NOT_FOUND-shaped again.
        assert!(hub.unsubscribe(7, id, 2_000).is_none());
    }

    #[test]
    fn pending_subs_never_drain() {
        let hub = SubscriptionHub::default();
        let id = hub
            .subscribe(1, Some(1), msg_sub(1), 0, 1, 0, 1_000)
            .unwrap();
        hub.stage_marker(1, id, "gap", "\"cause\":\"start_position\"".to_string());
        // Still pending: drain must not emit it (ordering §5.8.1).
        assert!(hub.drain(1).is_empty());
        assert!(hub.activate(1, id));
        let lines = hub.drain(1);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"kind\":\"gap\""), "{}", lines[0]);
        assert!(lines[0].contains("\"n\":1"), "{}", lines[0]);
    }

    /// Marker closure used by queue tests (messages shape is irrelevant —
    /// the queue only needs (kind, body)).
    fn test_marker() -> impl Fn(u64, u64) -> (&'static str, String) {
        move |lo, hi| {
            (
                "gap",
                format!("\"cause\":\"queue_overflow\",\"lost_from\":{lo},\"lost_to\":{hi}"),
            )
        }
    }

    #[test]
    fn stage_queue_drop_oldest_coalesces() {
        let mut queue = StageQueue::default();
        let marker = test_marker();
        for seq in 1..=SUB_QUEUE_EVENTS as u64 {
            let stat = queue.push_data(seq, "message", format!("\"record\":{seq}"), &marker);
            assert_eq!(stat.dropped, 0);
        }
        // One more overflows: the whole front run is replaced by ONE marker.
        let stat = queue.push_data(200, "message", "\"record\":200".to_string(), &marker);
        assert_eq!(stat.dropped, SUB_QUEUE_EVENTS as u64);
        assert_eq!(stat.markers, 1);
        let first = queue.pop_front().expect("marker first");
        assert!(matches!(first, StageItem::Control { .. }));
        assert!(first.body().contains("\"lost_from\":1"), "{}", first.body());
        assert!(first.body().contains("\"lost_to\":128"), "{}", first.body());
        // The new record sits right behind the marker.
        let second = queue.pop_front().expect("record after marker");
        assert!(matches!(second, StageItem::Data { seq: 200, .. }));
    }

    #[test]
    fn stage_queue_control_lines_never_drop() {
        let mut queue = StageQueue::default();
        let marker = test_marker();
        queue.push_control("gap", "\"cause\":\"log_evicted\"".to_string());
        for seq in 1..=SUB_QUEUE_EVENTS as u64 {
            queue.push_data(seq, "message", "\"r\":1".to_string(), &marker);
        }
        // Overflow drops the data run AFTER the front control line — the
        // control line stays first, marker lands where the run began.
        let stat = queue.push_data(300, "message", "\"r\":2".to_string(), &marker);
        assert!(stat.dropped > 0);
        let first = queue.pop_front().expect("control survives");
        assert!(matches!(first, StageItem::Control { body, .. } if body.contains("log_evicted")));
    }

    #[test]
    fn stage_queue_control_reserve_bounds() {
        let mut queue = StageQueue::default();
        for _ in 0..SUB_CONTROL_RESERVE {
            assert!(matches!(
                queue.push_control("gap", "\"cause\":\"x\"".to_string()),
                ControlPush::Staged
            ));
        }
        assert!(matches!(
            queue.push_control("gap", "\"cause\":\"y\"".to_string()),
            ControlPush::Full
        ));
    }

    #[test]
    fn drain_assigns_monotone_n_and_ends() {
        let hub = SubscriptionHub::default();
        let id = hub
            .subscribe(3, Some(1), msg_sub(1), 0, 1, 0, 1_000)
            .unwrap();
        hub.activate(3, id);
        let marker = |_: u64, _: u64| ("gap", "\"cause\":\"queue_overflow\"".to_string());
        for seq in 1..=3_u64 {
            let work = StageWork {
                items: vec![StagedLine {
                    control: false,
                    kind: "message",
                    body: format!("\"record\":{{\"seq\":{seq}}}"),
                    seq,
                }],
                new_position: Some(seq),
                heartbeat: None,
                end_reason: None,
            };
            hub.stage(3, id, work, &marker, 100);
        }
        let lines = hub.drain(3);
        assert_eq!(lines.len(), 3);
        for (i, line) in lines.iter().enumerate() {
            assert!(line.contains(&format!("\"n\":{}", i + 1)), "{line}");
        }
        // Now end it: the ended line is synthesized last, then the sub
        // is gone.
        hub.stage(
            3,
            id,
            StageWork {
                items: vec![],
                new_position: None,
                heartbeat: None,
                end_reason: Some("unauthorized"),
            },
            &marker,
            200,
        );
        let lines = hub.drain(3);
        assert_eq!(lines.len(), 1);
        assert!(lines[0].contains("\"kind\":\"ended\""), "{}", lines[0]);
        assert!(
            lines[0].contains("\"reason\":\"unauthorized\""),
            "{}",
            lines[0]
        );
        assert!(lines[0].contains("\"delivered\":3"), "{}", lines[0]);
        assert!(hub.unsubscribe(3, id, 300).is_none(), "ended id is gone");
    }

    #[test]
    fn hub_list_reports_own_connection_only() {
        let hub = SubscriptionHub::default();
        let id = hub
            .subscribe(1, Some(1), msg_sub(9), 4, 1, 0, 1_000)
            .unwrap();
        hub.subscribe(
            2,
            Some(1),
            SubKind::Events(EvFilter { kinds: None }),
            7,
            1,
            0,
            1_000,
        )
        .unwrap();
        let mine = hub.list(1);
        assert_eq!(mine.len(), 1);
        assert_eq!(mine[0].id, id);
        assert_eq!(mine[0].network, Some(9));
        assert!(!mine[0].is_events);
        let theirs = hub.list(2);
        assert_eq!(theirs.len(), 1);
        assert!(theirs[0].is_events);
        assert!(hub.list(99).is_empty());
    }

    #[test]
    fn wait_wakes_on_notify() {
        let hub = std::sync::Arc::new(SubscriptionHub::default());
        let seen = hub.dirty_epoch();
        let other = std::sync::Arc::clone(&hub);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(30));
            other.notify();
        });
        let start = std::time::Instant::now();
        let now = hub.wait(seen, Duration::from_secs(10));
        assert!(now != seen);
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn wait_times_out() {
        let hub = SubscriptionHub::default();
        let seen = hub.dirty_epoch();
        let start = std::time::Instant::now();
        let now = hub.wait(seen, Duration::from_millis(50));
        assert_eq!(now, seen);
        assert!(start.elapsed() >= Duration::from_millis(40));
    }
}
