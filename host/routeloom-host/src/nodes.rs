//! Per-node status table and the node_status_v1 USB lane (HostOps
//! 0x40-0x42) — the daemon's source of truth for `nodes.list`/`nodes.get`,
//! the legacy `NODES` view and the `node_joined`/`node_left`/`link_changed`
//! events.
//!
//! Model. The attached gateway reports what IT knows about every other
//! node: whether it is an active direct neighbor, the effective link cost
//! and RSSI for that link, and whether a feasible route is selected. The
//! daemon mirrors that into [`NodeTable`]; "connected" means exactly "the
//! gateway currently has a selected route to the node" (the attached
//! gateway itself is connected while the USB session is authenticated).
//! Join/leave/link-change events are derived HERE from table transitions —
//! whether the transition was learned from a device 0x42 event or from a
//! periodic paginated resync — so a lost device event can delay an event
//! but never lose or duplicate one, and a USB session loss turns every
//! connected node into `node_left{reason:"gateway_lost"}`.
//!
//! Clock domain. Every timestamp in this module is host wall-clock UNIX
//! milliseconds (the daemon's `now_ms()`, the same axis as the event ring's
//! `ms`). The device only ever sends durations (`heard_age_ms`), so
//! `last_heard_ms = host receive time - heard_age_ms`; it is therefore an
//! upper bound on freshness (USB queueing delay is attributed to the node),
//! and `updated_ms` says when the gateway last confirmed the record.

use routeloom_protocol::host_ops::CAP_HOST_OPS_V1;
use routeloom_protocol::node_status::{
    decode_node_event, decode_node_status_page, encode_node_status_query, node_status_sub,
    NodeEventKind, NodeStatusEntry, NodeStatusQuery, CAP_NODE_STATUS_V1, INFINITE_METRIC, PAGE_MAX,
    QUERY_SUBSCRIBE, SUB_NODE_EVENT, SUB_NODE_STATUS_PAGE,
};
use routeloom_protocol::{Frame, FrameKind};
use std::collections::{BTreeMap, VecDeque};
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::Duration;

use crate::{json_escape, now_ms, push_event, Outbound, State};

/// Table bound: the device can list at most 160 nodes (128 route entries +
/// 32 neighbor records); departed records are kept for `last_heard` until
/// this bound evicts the oldest disconnected one.
pub const TABLE_CAP: usize = 512;
/// Full resync cadence — refreshes RSSI/age/metrics that change without a
/// membership transition and reconciles anything an event missed.
pub const SWEEP_INTERVAL_MS: u64 = 10_000;
/// A page request unanswered this long is re-issued (same cursor).
pub const PAGE_TIMEOUT_MS: u64 = 1_500;
/// Consecutive undecodable pages before a sweep is abandoned until the
/// next interval — a broken device answer can never spin the lane.
const PAGE_FAILURES_MAX: u32 = 3;
const INBOX_CAP: usize = 256;
const TICK_MS: u64 = 50;
/// Request ids for this lane live in their own high range so an Error
/// frame echoing one can never alias a DataToMesh or dispatcher request.
const REQUEST_BASE: u64 = 0x4E53_0000_0000_0000;

/// Verified 0x41/0x42 inner bodies posted by the USB read thread, FIFO so
/// events and pages are applied in wire order. Never blocks the reader: a
/// full inbox drops the body (a dropped page times out and is re-issued; a
/// dropped event is reconciled by the event-sequence gap check).
#[derive(Default)]
pub struct NodeInbox {
    queue: Mutex<VecDeque<(u64, Vec<u8>)>>,
    cv: Condvar,
}

impl NodeInbox {
    pub fn post(&self, request: u64, body: Vec<u8>) -> bool {
        let mut queue = self.queue.lock().expect("node inbox poisoned");
        if queue.len() >= INBOX_CAP {
            return false;
        }
        queue.push_back((request, body));
        drop(queue);
        self.cv.notify_one();
        true
    }

    fn drain(&self) -> Vec<(u64, Vec<u8>)> {
        self.queue
            .lock()
            .expect("node inbox poisoned")
            .drain(..)
            .collect()
    }

    fn wait(&self, dur: Duration) {
        let guard = self.queue.lock().expect("node inbox poisoned");
        if guard.is_empty() {
            let _ = self.cv.wait_timeout(guard, dur);
        }
    }
}

/// True for the HostOps bodies this lane owns (the frame router's test).
pub fn owns(inner: &[u8]) -> bool {
    node_status_sub(inner).is_some()
}

/// Where the table's view currently comes from.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Source {
    /// No authenticated gateway session: nothing is known to be connected.
    #[default]
    Unavailable,
    /// The gateway does not advertise CAP_NODE_STATUS_V1.
    Unsupported,
    /// Session up, first full sweep still in progress.
    Syncing,
    /// At least one full sweep completed in this session; events flow.
    Live,
}

impl Source {
    pub fn name(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Unsupported => "unsupported",
            Self::Syncing => "syncing",
            Self::Live => "live",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NodeRecord {
    pub node: u64,
    /// The attached gateway itself (connected while the session lives).
    pub gateway: bool,
    pub connected: bool,
    /// Present in the gateway's most recent view (page or event).
    pub listed: bool,
    /// Last entry the gateway reported (None for the gateway record).
    pub status: Option<NodeStatusEntry>,
    /// Host UNIX ms of the last frame the gateway authenticated from the
    /// node as the immediate transmitter (receive time − heard_age_ms).
    pub last_heard_ms: Option<u64>,
    /// Host UNIX ms the gateway last confirmed this record.
    pub updated_ms: u64,
    /// Host UNIX ms of the last connected/disconnected transition.
    pub changed_ms: u64,
    sweep: u64,
}

impl NodeRecord {
    fn new(node: u64, now: u64) -> Self {
        Self {
            node,
            gateway: false,
            connected: false,
            listed: false,
            status: None,
            last_heard_ms: None,
            updated_ms: now,
            changed_ms: now,
            sweep: 0,
        }
    }

    /// The gateway's entry while it is CURRENT (the node is listed in the
    /// gateway's live view). After the node vanished or the gateway session
    /// was lost the last entry is history: link fields then read as unknown
    /// and only `last_heard_ms` keeps its meaning.
    pub fn live_status(&self) -> Option<NodeStatusEntry> {
        if self.listed {
            self.status
        } else {
            None
        }
    }

    pub fn neighbor(&self) -> bool {
        self.live_status().is_some_and(|s| s.neighbor_active())
    }

    /// Hop count when it is actually known: 0 for the gateway, 1 for a node
    /// the gateway reaches directly. Multi-hop distance is not carried by
    /// the route metric, so it stays unknown (None) rather than guessed.
    pub fn hops(&self) -> Option<u8> {
        if self.gateway {
            return self.connected.then_some(0);
        }
        self.live_status()
            .filter(|s| s.reachable() && s.direct())
            .map(|_| 1)
    }
}

/// One table transition, rendered into the event ring by [`change_event`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Change {
    Joined { node: u64, reason: &'static str },
    Left { node: u64, reason: &'static str },
    LinkChanged { node: u64, change: &'static str },
}

/// How an entry reached the table (drives the event `reason`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    Sync,
    Event(NodeEventKind),
}

#[derive(Default)]
pub struct NodeTable {
    records: BTreeMap<u64, NodeRecord>,
    source: Source,
    gateway: Option<u64>,
    session: Option<u64>,
    synced_ms: Option<u64>,
    sweep: u64,
    evicted: u64,
}

impl NodeTable {
    /// Const constructor (static fixtures); same value as `default()`.
    #[cfg(test)]
    pub const fn empty() -> Self {
        Self {
            records: BTreeMap::new(),
            source: Source::Unavailable,
            gateway: None,
            session: None,
            synced_ms: None,
            sweep: 0,
            evicted: 0,
        }
    }

    pub fn source(&self) -> Source {
        self.source
    }
    pub fn gateway(&self) -> Option<u64> {
        self.gateway
    }
    pub fn session(&self) -> Option<u64> {
        self.session
    }
    pub fn synced_ms(&self) -> Option<u64> {
        self.synced_ms
    }
    pub fn len(&self) -> usize {
        self.records.len()
    }
    pub fn evicted(&self) -> u64 {
        self.evicted
    }
    pub fn get(&self, node: u64) -> Option<&NodeRecord> {
        self.records.get(&node)
    }

    /// Records with id > `after`, ascending, at most `limit`, optionally
    /// only (dis)connected ones; the second value says more exist.
    pub fn list(
        &self,
        after: u64,
        limit: usize,
        connected: Option<bool>,
    ) -> (Vec<&NodeRecord>, bool) {
        let mut out = Vec::new();
        let mut iter = self
            .records
            .range(after.saturating_add(1)..)
            .map(|(_, record)| record)
            .filter(|record| connected.map_or(true, |want| record.connected == want));
        for record in iter.by_ref() {
            if out.len() == limit {
                return (out, true);
            }
            out.push(record);
        }
        (out, false)
    }

    /// A new authenticated session: the gateway record connects; remote
    /// records wait for the first sweep (they were all disconnected when
    /// the previous session was lost).
    pub fn attach(&mut self, gateway: u64, session: u64, supported: bool, now: u64) -> Vec<Change> {
        let mut changes = Vec::new();
        self.session = Some(session);
        self.synced_ms = None;
        self.source = if supported {
            Source::Syncing
        } else {
            Source::Unsupported
        };
        if let Some(old) = self.gateway.filter(|old| *old != gateway) {
            // A different gateway: its records described another vantage.
            if let Some(record) = self.records.get_mut(&old) {
                record.gateway = false;
            }
        }
        self.gateway = Some(gateway);
        let record = self.upsert(gateway, now);
        if let Some(record) = record {
            record.gateway = true;
            record.listed = true;
            record.status = None;
            record.updated_ms = now;
            if !record.connected {
                record.connected = true;
                record.changed_ms = now;
                changes.push(Change::Joined {
                    node: gateway,
                    reason: "gateway_attached",
                });
            }
        }
        changes
    }

    /// Session/USB loss: the host can no longer reach any node. Every
    /// connected record (gateway included) leaves with `gateway_lost`.
    pub fn detach(&mut self, now: u64) -> Vec<Change> {
        let mut changes = Vec::new();
        for record in self.records.values_mut() {
            record.listed = false;
            if record.connected {
                record.connected = false;
                record.changed_ms = now;
                changes.push(Change::Left {
                    node: record.node,
                    reason: "gateway_lost",
                });
            }
        }
        self.source = Source::Unavailable;
        self.session = None;
        self.synced_ms = None;
        changes
    }

    pub fn begin_sweep(&mut self) -> u64 {
        self.sweep += 1;
        self.sweep
    }

    /// Applies one gateway-reported entry and returns the transitions.
    pub fn apply(
        &mut self,
        entry: &NodeStatusEntry,
        origin: Origin,
        sweep: Option<u64>,
        now: u64,
    ) -> Vec<Change> {
        let mut changes = Vec::new();
        if Some(entry.node) == self.gateway {
            return changes; // the gateway never lists itself; defensive
        }
        let current_sweep = self.sweep;
        let Some(record) = self.upsert(entry.node, now) else {
            return changes;
        };
        let previous = record.live_status();
        let was_connected = record.connected;
        record.status = Some(*entry);
        record.listed = true;
        record.updated_ms = now;
        record.sweep = sweep.unwrap_or(current_sweep);
        if entry.heard_valid() {
            record.last_heard_ms = Some(now.saturating_sub(u64::from(entry.heard_age_ms)));
        }
        let was_neighbor = previous.is_some_and(|p| p.neighbor_active());
        if was_neighbor != entry.neighbor_active() {
            changes.push(Change::LinkChanged {
                node: entry.node,
                change: if entry.neighbor_active() {
                    "neighbor_up"
                } else {
                    "neighbor_down"
                },
            });
        }
        if was_connected != entry.reachable() {
            record.connected = entry.reachable();
            record.changed_ms = now;
            changes.push(if entry.reachable() {
                Change::Joined {
                    node: entry.node,
                    reason: match origin {
                        Origin::Event(_) => "route_up",
                        Origin::Sync => "sync",
                    },
                }
            } else {
                Change::Left {
                    node: entry.node,
                    reason: match origin {
                        Origin::Event(_) => "route_down",
                        Origin::Sync => "sync",
                    },
                }
            });
        } else if was_connected
            && previous.is_some_and(|p| p.reachable() && p.next_hop != entry.next_hop)
        {
            changes.push(Change::LinkChanged {
                node: entry.node,
                change: "next_hop",
            });
        }
        changes
    }

    /// Completes a sweep: records the gateway no longer lists at all are
    /// marked unlisted (and leave if they were connected).
    pub fn finish_sweep(&mut self, sweep: u64, now: u64) -> Vec<Change> {
        let mut changes = Vec::new();
        for record in self.records.values_mut() {
            if record.gateway || record.sweep >= sweep || !record.listed {
                continue;
            }
            record.listed = false;
            if record.connected {
                record.connected = false;
                record.changed_ms = now;
                changes.push(Change::Left {
                    node: record.node,
                    reason: "vanished",
                });
            }
        }
        self.source = Source::Live;
        self.synced_ms = Some(now);
        changes
    }

    pub fn mark_unsupported(&mut self) {
        self.source = Source::Unsupported;
    }

    fn upsert(&mut self, node: u64, now: u64) -> Option<&mut NodeRecord> {
        if !self.records.contains_key(&node) && self.records.len() >= TABLE_CAP {
            // Evict the stalest disconnected record; connected ones are the
            // live view and are never displaced.
            let victim = self
                .records
                .values()
                .filter(|r| !r.connected && !r.gateway)
                .min_by_key(|r| r.updated_ms)
                .map(|r| r.node)?;
            self.records.remove(&victim);
            self.evicted += 1;
        }
        Some(
            self.records
                .entry(node)
                .or_insert_with(|| NodeRecord::new(node, now)),
        )
    }
}

fn hex_opt(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |v| format!("\"{v:016x}\""))
}

fn u64_opt(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |v| v.to_string())
}

fn metric_opt(value: u16) -> String {
    if value == INFINITE_METRIC {
        "null".to_string()
    } else {
        value.to_string()
    }
}

/// The API1 node object shared by `nodes.list`, `nodes.get` and the event
/// bodies. Unknown values are JSON null — never an inferred zero.
pub fn node_json(record: &NodeRecord, now: u64) -> String {
    let status = record.live_status();
    let rssi = status.filter(|s| s.rssi_valid());
    let reachable = status.filter(|s| s.reachable());
    format!(
        "{{\"node\":\"{:016x}\",\"role\":\"{}\",\"connected\":{},\"listed\":{},\"neighbor\":{},\"direct\":{},\"hops\":{},\"next_hop\":{},\"route_metric\":{},\"link_cost\":{},\"rssi_dbm\":{},\"rssi_avg_dbm\":{},\"telemetry_stale\":{},\"last_heard_ms\":{},\"heard_age_ms\":{},\"updated_ms\":{},\"changed_ms\":{}}}",
        record.node,
        if record.gateway { "gateway" } else { "peer" },
        record.connected,
        record.listed,
        record.neighbor(),
        record.gateway || reachable.is_some_and(|s| s.direct()),
        record
            .hops()
            .map_or_else(|| "null".to_string(), |h| h.to_string()),
        hex_opt(reachable.map(|s| s.next_hop)),
        reachable.map_or_else(|| "null".to_string(), |s| metric_opt(s.route_metric)),
        status
            .filter(|s| s.neighbor_active())
            .map_or_else(|| "null".to_string(), |s| metric_opt(s.link_cost)),
        rssi.map_or_else(|| "null".to_string(), |s| s.rssi_last_dbm.to_string()),
        rssi.map_or_else(
            || "null".to_string(),
            |s| format!("{:.2}", f64::from(s.rssi_ewma_q8_8) / 256.0)
        ),
        status.is_some_and(|s| s.telemetry_stale()),
        u64_opt(record.last_heard_ms),
        u64_opt(record.last_heard_ms.map(|t| now.saturating_sub(t))),
        record.updated_ms,
        record.changed_ms,
    )
}

/// `"source":{...}` object for the API: where the view comes from and the
/// clock domain every timestamp uses.
pub fn source_json(table: &NodeTable) -> String {
    format!(
        "{{\"state\":\"{}\",\"gateway\":{},\"session_id\":{},\"synced_ms\":{},\"tracked\":{},\"evicted\":{},\"clock\":\"host_unix_ms\"}}",
        table.source().name(),
        hex_opt(table.gateway()),
        u64_opt(table.session()),
        u64_opt(table.synced_ms()),
        table.len(),
        table.evicted(),
    )
}

/// Event-ring body (`"kind":...` fragment) for one transition.
pub fn change_event(table: &NodeTable, change: &Change, now: u64) -> String {
    let (kind, node, key, value) = match change {
        Change::Joined { node, reason } => ("node_joined", *node, "reason", *reason),
        Change::Left { node, reason } => ("node_left", *node, "reason", *reason),
        Change::LinkChanged { node, change } => ("link_changed", *node, "change", *change),
    };
    let body = table
        .get(node)
        .map_or_else(|| "null".to_string(), |record| node_json(record, now));
    format!(
        "\"kind\":\"{kind}\",\"node\":\"{node:016x}\",\"gateway\":{},\"{key}\":\"{}\",\"status\":{body}",
        hex_opt(table.gateway()),
        json_escape(value),
    )
}

/// Session facts the lane needs, read from the daemon's session mirror.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct NodeLink {
    pub active: bool,
    pub node_status: bool,
    pub session: u64,
    pub gateway: u64,
}

/// The family rides the HostOps carrier, which the device serves only with
/// host_ops_v1 (bit 2) — so both bits must be advertised; a device with
/// bit 6 alone would answer every query with an Unsupported Error frame.
pub fn node_status_capable(capability: u32) -> bool {
    capability & CAP_NODE_STATUS_V1 != 0 && capability & CAP_HOST_OPS_V1 != 0
}

pub fn node_link(state: &State) -> NodeLink {
    let info = state.session.lock().expect("session poisoned");
    NodeLink {
        active: info.authenticated && info.id.is_some() && info.node.is_some(),
        node_status: info.capability.is_some_and(node_status_capable),
        session: info.id.unwrap_or(0),
        gateway: info.node.unwrap_or(0),
    }
}

#[derive(Clone, Copy, Debug)]
struct InFlight {
    request: u64,
    after: u64,
    subscribe: bool,
    sent_ms: u64,
}

/// The 0x40 page driver + 0x42 event consumer. Pure state machine: the
/// caller feeds link snapshots, replies and the clock, and ships the
/// returned request bodies.
#[derive(Default)]
pub struct NodeStatusLane {
    session: Option<u64>,
    supported: bool,
    armed: bool,
    last_event_seq: u32,
    sweep: Option<u64>,
    cursor: u64,
    in_flight: Option<InFlight>,
    next_sweep_ms: u64,
    failures: u32,
    next_request: u64,
    notes: Vec<String>,
}

impl NodeStatusLane {
    #[cfg(test)]
    pub fn armed(&self) -> bool {
        self.armed
    }

    pub fn take_notes(&mut self) -> Vec<String> {
        std::mem::take(&mut self.notes)
    }

    fn request_id(&mut self) -> u64 {
        self.next_request = self.next_request.wrapping_add(1);
        REQUEST_BASE | (self.next_request & 0x0000_FFFF_FFFF_FFFF)
    }

    fn issue(&mut self, after: u64, subscribe: bool, now: u64) -> Option<(u64, Vec<u8>)> {
        let body = encode_node_status_query(&NodeStatusQuery {
            after,
            max_entries: PAGE_MAX as u8,
            flags: if subscribe { QUERY_SUBSCRIBE } else { 0 },
        })
        .ok()?;
        let request = self.request_id();
        self.in_flight = Some(InFlight {
            request,
            after,
            subscribe,
            sent_ms: now,
        });
        Some((request, body))
    }

    /// One scheduling step. Returns the request to send (if any) and the
    /// table transitions the step caused.
    pub fn tick(
        &mut self,
        table: &mut NodeTable,
        link: &NodeLink,
        now: u64,
    ) -> (Option<(u64, Vec<u8>)>, Vec<Change>) {
        let mut changes = Vec::new();
        if !link.active {
            if self.session.is_some() || table.source() != Source::Unavailable {
                changes = table.detach(now);
                *self = Self {
                    next_request: self.next_request,
                    ..Self::default()
                };
            }
            return (None, changes);
        }
        if self.session != Some(link.session) {
            // New session: nothing from the old one (arming, sequence,
            // cursor, in-flight request) carries over.
            if self.session.is_some() {
                changes.extend(table.detach(now));
            }
            *self = Self {
                session: Some(link.session),
                supported: link.node_status,
                next_sweep_ms: now,
                next_request: self.next_request,
                ..Self::default()
            };
            changes.extend(table.attach(link.gateway, link.session, link.node_status, now));
        }
        if !self.supported {
            return (None, changes);
        }
        if let Some(flight) = self.in_flight {
            if now.saturating_sub(flight.sent_ms) < PAGE_TIMEOUT_MS {
                return (None, changes);
            }
            self.notes
                .push("node status page timed out; re-issued".to_string());
            return (self.issue(flight.after, flight.subscribe, now), changes);
        }
        if self.sweep.is_none() {
            if now < self.next_sweep_ms {
                return (None, changes);
            }
            self.sweep = Some(table.begin_sweep());
            self.cursor = 0;
            self.failures = 0;
        }
        let subscribe = !self.armed && self.cursor == 0;
        (self.issue(self.cursor, subscribe, now), changes)
    }

    /// The writer queue refused the request: forget it so the next tick
    /// re-issues (nothing reached the device).
    pub fn emit_dropped(&mut self, request: u64) {
        if self.in_flight.is_some_and(|f| f.request == request) {
            self.in_flight = None;
        }
    }

    /// Applies one verified 0x41/0x42 body.
    pub fn handle(
        &mut self,
        table: &mut NodeTable,
        request: u64,
        inner: &[u8],
        now: u64,
    ) -> Vec<Change> {
        match node_status_sub(inner) {
            Some(SUB_NODE_STATUS_PAGE) => self.on_page(table, request, inner, now),
            Some(SUB_NODE_EVENT) => self.on_event(table, inner, now),
            _ => Vec::new(),
        }
    }

    fn on_page(
        &mut self,
        table: &mut NodeTable,
        request: u64,
        inner: &[u8],
        now: u64,
    ) -> Vec<Change> {
        let Some(flight) = self.in_flight.filter(|f| f.request == request) else {
            return Vec::new(); // stale or foreign reply
        };
        self.in_flight = None;
        let page = match decode_node_status_page(inner) {
            Ok(page) => page,
            Err(error) => {
                self.failures += 1;
                self.notes
                    .push(format!("node status page rejected: {error}"));
                if self.failures >= PAGE_FAILURES_MAX {
                    self.sweep = None;
                    self.next_sweep_ms = now + SWEEP_INTERVAL_MS;
                }
                return Vec::new();
            }
        };
        if !page.ok() {
            self.supported = false;
            self.sweep = None;
            table.mark_unsupported();
            self.notes
                .push(format!("node status unsupported (result {})", page.result));
            return Vec::new();
        }
        if flight.subscribe {
            self.armed = page.armed();
            self.last_event_seq = page.event_seq;
        } else if !page.armed() {
            self.armed = false; // the device lost the arming: re-subscribe
        } else if page.event_seq != self.last_event_seq {
            // Events the device issued before this page never reached us;
            // this sweep reconciles them — resync the sequence tracker.
            self.last_event_seq = page.event_seq;
        }
        let sweep = self.sweep;
        let mut changes = Vec::new();
        for entry in &page.entries {
            changes.extend(table.apply(entry, Origin::Sync, sweep, now));
        }
        if page.more() {
            self.cursor = page.next_after;
        } else {
            if let Some(sweep) = self.sweep.take() {
                changes.extend(table.finish_sweep(sweep, now));
            }
            self.cursor = 0;
            self.next_sweep_ms = now + SWEEP_INTERVAL_MS;
        }
        changes
    }

    fn on_event(&mut self, table: &mut NodeTable, inner: &[u8], now: u64) -> Vec<Change> {
        if !self.armed {
            return Vec::new();
        }
        let event = match decode_node_event(inner) {
            Ok(event) => event,
            Err(error) => {
                self.notes.push(format!("node event rejected: {error}"));
                self.next_sweep_ms = now; // reconcile by paging
                return Vec::new();
            }
        };
        if event.sequence <= self.last_event_seq {
            return Vec::new(); // already covered by a page's event_seq
        }
        if event.sequence != self.last_event_seq.wrapping_add(1) {
            self.notes.push(format!(
                "node event gap: expected {}, got {}",
                self.last_event_seq.wrapping_add(1),
                event.sequence
            ));
            if self.sweep.is_none() {
                self.next_sweep_ms = now;
            }
        }
        self.last_event_seq = event.sequence;
        let sweep = self.sweep;
        table.apply(&event.status, Origin::Event(event.kind), sweep, now)
    }
}

/// One lane pass against the daemon state: apply inbound bodies, run the
/// scheduler, publish transitions as events, queue the next request.
pub fn node_status_once(
    state: &State,
    outbound: &mpsc::SyncSender<Outbound>,
    lane: &mut NodeStatusLane,
    now: u64,
) {
    let inbound = state.node_inbox.drain();
    let link = node_link(state);
    let mut events = Vec::new();
    let request = {
        let mut table = state.node_table.lock().expect("node table poisoned");
        let mut changes = Vec::new();
        for (request, body) in inbound {
            changes.extend(lane.handle(&mut table, request, &body, now));
        }
        let (request, tick_changes) = lane.tick(&mut table, &link, now);
        changes.extend(tick_changes);
        for change in &changes {
            events.push(change_event(&table, change, now));
        }
        request
    };
    // The table lock is released before the ring/hub are touched.
    for event in events {
        push_event(state, now, event);
    }
    for note in lane.take_notes() {
        push_event(
            state,
            now,
            format!(
                "\"kind\":\"dispatch\",\"detail\":\"{}\"",
                json_escape(&note)
            ),
        );
    }
    if let Some((request, body)) = request {
        let frame = Frame {
            kind: FrameKind::HostOps,
            flags: 0,
            session: 0,
            request,
            body,
        };
        if outbound.try_send(Outbound::Seal(frame)).is_err() {
            lane.emit_dropped(request);
        }
    }
}

/// The node-status thread: runs for the daemon's lifetime; idle (no
/// frames) while no capable session exists.
pub fn node_status_loop(state: Arc<State>, outbound: mpsc::SyncSender<Outbound>) {
    let mut lane = NodeStatusLane::default();
    loop {
        node_status_once(&state, &outbound, &mut lane, now_ms());
        state.node_inbox.wait(Duration::from_millis(TICK_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_protocol::node_status::{
        decode_node_status_query, encode_node_event, encode_node_status_page, NodeEvent,
        NodeStatusPage, FLAG_DIRECT, FLAG_HEARD_VALID, FLAG_NEIGHBOR, FLAG_NEIGHBOR_ACTIVE,
        FLAG_REACHABLE, FLAG_RSSI_VALID, PAGE_ARMED, PAGE_MORE,
    };

    const GW: u64 = 0x0abc;
    const SESSION: u64 = 0x5e55;

    fn link() -> NodeLink {
        NodeLink {
            active: true,
            node_status: true,
            session: SESSION,
            gateway: GW,
        }
    }

    fn direct(node: u64) -> NodeStatusEntry {
        NodeStatusEntry {
            node,
            flags: FLAG_NEIGHBOR
                | FLAG_NEIGHBOR_ACTIVE
                | FLAG_REACHABLE
                | FLAG_DIRECT
                | FLAG_RSSI_VALID
                | FLAG_HEARD_VALID,
            rssi_last_dbm: -61,
            rssi_ewma_q8_8: -60 * 256 - 128,
            link_cost: 2,
            route_metric: 2,
            next_hop: node,
            heard_age_ms: 250,
        }
    }

    fn via(node: u64, hop: u64) -> NodeStatusEntry {
        NodeStatusEntry {
            node,
            flags: FLAG_REACHABLE,
            rssi_last_dbm: 0,
            rssi_ewma_q8_8: 0,
            link_cost: INFINITE_METRIC,
            route_metric: 5,
            next_hop: hop,
            heard_age_ms: 0,
        }
    }

    fn gone(node: u64) -> NodeStatusEntry {
        NodeStatusEntry {
            node,
            flags: FLAG_NEIGHBOR,
            rssi_last_dbm: 0,
            rssi_ewma_q8_8: 0,
            link_cost: INFINITE_METRIC,
            route_metric: INFINITE_METRIC,
            next_hop: 0,
            heard_age_ms: 0,
        }
    }

    fn page(entries: Vec<NodeStatusEntry>, more: bool, event_seq: u32) -> Vec<u8> {
        encode_node_status_page(&NodeStatusPage {
            result: 0,
            flags: PAGE_ARMED | if more { PAGE_MORE } else { 0 },
            next_after: entries.last().map_or(0, |e| e.node),
            event_seq,
            entries,
        })
        .unwrap()
    }

    fn event(sequence: u32, kind: NodeEventKind, status: NodeStatusEntry) -> Vec<u8> {
        encode_node_event(&NodeEvent {
            sequence,
            kind,
            status,
        })
        .unwrap()
    }

    #[test]
    fn full_sync_then_events_drive_membership() {
        let mut table = NodeTable::default();
        let mut lane = NodeStatusLane::default();
        let now = 1_000_000;

        // Session attach: the gateway joins, the first page subscribes.
        let (request, changes) = lane.tick(&mut table, &link(), now);
        assert_eq!(
            changes,
            vec![Change::Joined {
                node: GW,
                reason: "gateway_attached"
            }]
        );
        let (req1, body) = request.expect("first page request");
        let query = decode_node_status_query(&body).unwrap();
        assert_eq!((query.after, query.flags), (0, QUERY_SUBSCRIBE));
        assert_eq!(table.source(), Source::Syncing);
        // In flight: no second request until the reply or the timeout.
        assert!(lane.tick(&mut table, &link(), now + 10).0.is_none());

        // Two pages: 2 and 3 direct, then 9 via 3.
        let changes = lane.handle(
            &mut table,
            req1,
            &page(vec![direct(2), direct(3)], true, 0),
            now + 20,
        );
        assert_eq!(changes.len(), 4); // neighbor_up + joined, twice
        assert!(lane.armed());
        let (req2, body) = lane.tick(&mut table, &link(), now + 30).0.unwrap();
        let query = decode_node_status_query(&body).unwrap();
        assert_eq!((query.after, query.flags), (3, 0));
        let changes = lane.handle(&mut table, req2, &page(vec![via(9, 3)], false, 0), now + 40);
        assert_eq!(
            changes,
            vec![Change::Joined {
                node: 9,
                reason: "sync"
            }]
        );
        assert_eq!(table.source(), Source::Live);
        assert_eq!(table.synced_ms(), Some(now + 40));
        let r2 = table.get(2).unwrap();
        assert!(r2.connected && r2.neighbor());
        assert_eq!(r2.hops(), Some(1));
        assert_eq!(r2.last_heard_ms, Some(now + 20 - 250));
        assert_eq!(table.get(9).unwrap().hops(), None); // multi-hop: unknown
        assert_eq!(table.get(GW).unwrap().hops(), Some(0));

        // Idle until the sweep interval.
        assert!(lane.tick(&mut table, &link(), now + 50).0.is_none());

        // Device events: 3 leaves (neighbor + route), 9 re-routes via 2.
        let mut changes = lane.handle(
            &mut table,
            0,
            &event(1, NodeEventKind::NeighborDown, gone(3)),
            now + 60,
        );
        changes.extend(lane.handle(
            &mut table,
            0,
            &event(2, NodeEventKind::RouteDown, gone(3)),
            now + 61,
        ));
        changes.extend(lane.handle(
            &mut table,
            0,
            &event(3, NodeEventKind::RouteChanged, via(9, 2)),
            now + 62,
        ));
        assert_eq!(
            changes,
            vec![
                Change::LinkChanged {
                    node: 3,
                    change: "neighbor_down"
                },
                Change::Left {
                    node: 3,
                    reason: "route_down"
                },
                Change::LinkChanged {
                    node: 9,
                    change: "next_hop"
                },
            ]
        );
        // A replayed/old event is ignored; a gap schedules a resync.
        assert!(lane
            .handle(
                &mut table,
                0,
                &event(3, NodeEventKind::RouteChanged, via(9, 2)),
                now + 63
            )
            .is_empty());
        let changes = lane.handle(
            &mut table,
            0,
            &event(5, NodeEventKind::RouteUp, direct(3)),
            now + 64,
        );
        assert_eq!(
            changes,
            vec![
                Change::LinkChanged {
                    node: 3,
                    change: "neighbor_up"
                },
                Change::Joined {
                    node: 3,
                    reason: "route_up"
                }
            ]
        );
        assert!(lane.take_notes().iter().any(|n| n.contains("gap")));
        let (req3, body) = lane
            .tick(&mut table, &link(), now + 70)
            .0
            .expect("gap resync");
        assert_eq!(decode_node_status_query(&body).unwrap().flags, 0); // still armed

        // The resync no longer lists 9 at all: it vanishes and leaves.
        let changes = lane.handle(
            &mut table,
            req3,
            &page(vec![direct(2), direct(3)], false, 5),
            now + 80,
        );
        assert_eq!(
            changes,
            vec![Change::Left {
                node: 9,
                reason: "vanished"
            }]
        );
        assert!(!table.get(9).unwrap().listed);

        // Session loss: everyone connected leaves with gateway_lost.
        let offline = NodeLink::default();
        let (_, changes) = lane.tick(&mut table, &offline, now + 90);
        let mut left: Vec<u64> = changes
            .iter()
            .map(|c| match c {
                Change::Left {
                    node,
                    reason: "gateway_lost",
                } => *node,
                other => panic!("unexpected {other:?}"),
            })
            .collect();
        left.sort_unstable();
        assert_eq!(left, vec![2, 3, GW]);
        assert_eq!(table.source(), Source::Unavailable);
        assert!(table.list(0, 100, Some(true)).0.is_empty());
        // Last-heard survives for the "no communication since" display.
        assert!(table.get(2).unwrap().last_heard_ms.is_some());
    }

    #[test]
    fn capability_needs_the_host_ops_carrier_too() {
        assert!(node_status_capable(CAP_NODE_STATUS_V1 | CAP_HOST_OPS_V1));
        assert!(node_status_capable(0x47));
        assert!(!node_status_capable(CAP_NODE_STATUS_V1));
        assert!(!node_status_capable(CAP_HOST_OPS_V1 | 0x3));
    }

    #[test]
    fn unsupported_devices_timeouts_and_stale_replies() {
        let mut table = NodeTable::default();
        let mut lane = NodeStatusLane::default();
        let no_cap = NodeLink {
            node_status: false,
            ..link()
        };
        let (request, changes) = lane.tick(&mut table, &no_cap, 10);
        assert!(request.is_none());
        assert_eq!(changes.len(), 1); // gateway still joins
        assert_eq!(table.source(), Source::Unsupported);

        // A capable session: timeout re-issues the SAME cursor/subscribe.
        let session2 = NodeLink {
            session: SESSION + 1,
            ..link()
        };
        let (req, _) = lane
            .tick(&mut table, &session2, 100)
            .0
            .map_or((0, ()), |(r, _)| (r, ()));
        assert_ne!(req, 0);
        assert!(lane
            .tick(&mut table, &session2, 100 + PAGE_TIMEOUT_MS - 1)
            .0
            .is_none());
        let (retry, body) = lane
            .tick(&mut table, &session2, 100 + PAGE_TIMEOUT_MS)
            .0
            .expect("timeout re-issue");
        assert_ne!(retry, req);
        assert_eq!(
            decode_node_status_query(&body).unwrap().flags,
            QUERY_SUBSCRIBE
        );
        // The late reply to the first request is stale and ignored.
        assert!(lane
            .handle(&mut table, req, &page(vec![direct(2)], false, 0), 2_000)
            .is_empty());
        assert!(table.get(2).is_none());
        // A queue refusal forgets the request so the next tick re-issues.
        lane.emit_dropped(retry);
        assert!(lane.tick(&mut table, &session2, 2_001).0.is_some());

        // An Unsupported page switches the lane off.
        let mut lane = NodeStatusLane::default();
        let mut table = NodeTable::default();
        let (req, _) = lane.tick(&mut table, &link(), 0).0.unwrap();
        let unsupported = encode_node_status_page(&NodeStatusPage {
            result: 4,
            flags: 0,
            next_after: 0,
            event_seq: 0,
            entries: Vec::new(),
        })
        .unwrap();
        lane.handle(&mut table, req, &unsupported, 1);
        assert_eq!(table.source(), Source::Unsupported);
        assert!(lane.tick(&mut table, &link(), 100_000).0.is_none());
    }

    #[test]
    fn table_is_bounded_and_keeps_connected_records() {
        let mut table = NodeTable::default();
        table.attach(GW, SESSION, true, 0);
        for node in 1..=TABLE_CAP as u64 + 10 {
            let entry = if node % 2 == 0 {
                direct(node + 1_000)
            } else {
                gone(node + 1_000)
            };
            table.apply(&entry, Origin::Sync, None, node);
        }
        assert_eq!(table.len(), TABLE_CAP);
        assert!(table.evicted() > 0);
        // Every connected record survived eviction.
        let connected = table.list(0, TABLE_CAP, Some(true)).0.len();
        assert_eq!(connected, (TABLE_CAP + 10) / 2 + 1);
        // Pagination by cursor is ascending and complete.
        let mut seen = Vec::new();
        let mut after = 0;
        loop {
            let (records, more) = table.list(after, 7, None);
            seen.extend(records.iter().map(|r| r.node));
            match records.last() {
                Some(last) if more => after = last.node,
                _ => break,
            }
        }
        assert_eq!(seen.len(), TABLE_CAP);
        assert!(seen.windows(2).all(|w| w[0] < w[1]));
    }

    /// The application facade (routeloom-client) must understand exactly
    /// what this daemon emits: node objects and event-ring membership
    /// entries round-trip into its LinkStatus / MembershipEvent types.
    #[test]
    fn facade_parses_daemon_shapes() {
        use routeloom_client::api1::{link_status_from_json, membership_from_event};
        use routeloom_client::MembershipKind;
        let mut table = NodeTable::default();
        table.attach(GW, SESSION, true, 1_000);
        let changes = table.apply(&direct(2), Origin::Sync, None, 2_000);
        let status = link_status_from_json(
            &routeloom_json::parse(&node_json(table.get(2).unwrap(), 3_000)).unwrap(),
        )
        .unwrap();
        assert!(status.connected);
        assert_eq!(status.rssi_dbm, Some(-61));
        assert_eq!(status.rssi_avg_dbm, Some(-60.5));
        assert_eq!(status.last_heard_ms, Some(1_750));
        assert_eq!(
            (status.hops, status.next_hop, status.link_cost),
            (Some(1), Some(2), Some(2))
        );
        // The event ring wraps the change body as {"seq":..,"ms":..,<body>}.
        let joined = changes
            .iter()
            .find(|c| matches!(c, Change::Joined { .. }))
            .unwrap();
        let line = format!(
            "{{\"seq\":1,\"ms\":2000,{}}}",
            change_event(&table, joined, 2_000)
        );
        let event = membership_from_event(&routeloom_json::parse(&line).unwrap()).unwrap();
        assert_eq!(event.kind, MembershipKind::Joined);
        assert_eq!(
            (event.node, event.reason.as_str(), event.at_ms),
            (2, "sync", 2_000)
        );
        assert!(event.status.unwrap().connected);
        let link = changes
            .iter()
            .find(|c| matches!(c, Change::LinkChanged { .. }))
            .unwrap();
        let line = format!(
            "{{\"seq\":2,\"ms\":2000,{}}}",
            change_event(&table, link, 2_000)
        );
        let event = membership_from_event(&routeloom_json::parse(&line).unwrap()).unwrap();
        assert_eq!(
            (event.kind, event.reason.as_str()),
            (MembershipKind::LinkChanged, "neighbor_up")
        );
        // After detach, the node reads as not connected with last-heard kept.
        let changes = table.detach(4_000);
        let left = changes
            .iter()
            .find(|c| matches!(c, Change::Left { node: 2, .. }))
            .unwrap();
        let line = format!(
            "{{\"seq\":3,\"ms\":4000,{}}}",
            change_event(&table, left, 4_000)
        );
        let event = membership_from_event(&routeloom_json::parse(&line).unwrap()).unwrap();
        assert_eq!(
            (event.kind, event.reason.as_str()),
            (MembershipKind::Left, "gateway_lost")
        );
        let status = event.status.unwrap();
        assert!(!status.connected && status.last_heard_ms == Some(1_750));
    }

    #[test]
    fn json_shapes_are_explicit_about_unknowns() {
        let mut table = NodeTable::default();
        table.attach(GW, SESSION, true, 1_000);
        table.apply(&direct(2), Origin::Sync, None, 2_000);
        table.apply(&via(9, 2), Origin::Sync, None, 2_000);
        let direct_json = node_json(table.get(2).unwrap(), 3_000);
        let parsed = routeloom_json::parse(&direct_json).unwrap();
        assert_eq!(
            parsed.get("node").and_then(routeloom_json::Json::as_str),
            Some("0000000000000002")
        );
        assert_eq!(
            parsed.get("hops").and_then(routeloom_json::Json::as_u64),
            Some(1)
        );
        assert_eq!(
            parsed
                .get("rssi_dbm")
                .and_then(routeloom_json::Json::as_i64),
            Some(-61)
        );
        assert!(direct_json.contains("\"rssi_avg_dbm\":-60.50"));
        assert!(direct_json.contains("\"last_heard_ms\":1750"));
        assert!(direct_json.contains("\"heard_age_ms\":1250"));
        assert!(direct_json.contains("\"connected\":true"));
        let multi = node_json(table.get(9).unwrap(), 3_000);
        for unknown in [
            "\"hops\":null",
            "\"rssi_dbm\":null",
            "\"rssi_avg_dbm\":null",
            "\"link_cost\":null",
            "\"last_heard_ms\":null",
        ] {
            assert!(multi.contains(unknown), "{unknown} in {multi}");
        }
        assert!(multi.contains("\"next_hop\":\"0000000000000002\""));
        let gw = node_json(table.get(GW).unwrap(), 3_000);
        assert!(gw.contains("\"role\":\"gateway\"") && gw.contains("\"hops\":0"));
        let source = source_json(&table);
        assert!(
            source.contains("\"state\":\"syncing\"")
                && source.contains("\"clock\":\"host_unix_ms\"")
        );
        let event = change_event(
            &table,
            &Change::Joined {
                node: 2,
                reason: "sync",
            },
            3_000,
        );
        let parsed = routeloom_json::parse(&format!("{{{event}}}")).unwrap();
        assert_eq!(
            parsed.get("kind").and_then(routeloom_json::Json::as_str),
            Some("node_joined")
        );
        assert!(parsed
            .get("status")
            .and_then(|s| s.get("connected"))
            .is_some());
    }
}
