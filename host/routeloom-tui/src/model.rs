//! Data model mirroring the daemon's JSON surface. The daemon is the only
//! source of truth; anything it cannot observe stays `Obs::Unknown` and is
//! rendered as such — the TUI never fabricates mesh state.

use crate::json::{self, Json, JsonError};
use std::collections::VecDeque;

/// Client-side event ring capacity. Matches the daemon's bounded buffer so a
/// slow render loop drops oldest rather than blocking.
pub const EVENT_CAP: usize = 256;

/// Whether a value was reported by the daemon, locally estimated, or has no
/// source of truth at all.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Obs<T> {
    Observed(T),
    Estimated(T),
    #[default]
    Unknown,
}

impl<T> Obs<T> {
    pub fn observed(value: T) -> Self {
        Obs::Observed(value)
    }

    pub fn is_unknown(&self) -> bool {
        matches!(self, Obs::Unknown)
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum Conn {
    Connected,
    Disconnected {
        since_ms: u64,
        attempts: u32,
        next_retry_ms: u64,
        error: Option<String>,
    },
}

impl Default for Conn {
    fn default() -> Self {
        Conn::Disconnected {
            since_ms: 0,
            attempts: 0,
            next_retry_ms: 0,
            error: None,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct AdapterInfo {
    pub device: Option<String>,
    pub connected: Option<bool>,
    pub authenticated: Option<bool>,
    pub session_id: Option<u64>,
    pub node: Option<u64>,
    pub boot: Option<u64>,
    pub network: Option<u64>,
    pub capability: Option<u64>,
    pub version: Option<u64>,
    pub credit_observed: bool,
    pub grant_frames: Option<u64>,
    pub grant_bytes: Option<u64>,
    pub rx_frames: Option<u64>,
    pub tx_frames: Option<u64>,
    pub tx_bytes: Option<u64>,
    pub protocol_errors: Option<u64>,
    pub last_error: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct NodeInfo {
    pub id: u64,
    /// "adapter" | "peer" as reported by the daemon.
    pub role: String,
    pub seen_ms: u64,
    pub membership: Obs<String>,
    pub reachability: Obs<String>,
    pub sleeping: Obs<bool>,
    pub rssi_dbm: Obs<i64>,
    pub lr250: Obs<bool>,
    pub hop_count: Obs<u64>,
    pub queue_depth: Obs<u64>,
    pub peer_slots: Obs<u64>,
    pub primary_route: Obs<String>,
    pub backup_route: Obs<String>,
}

#[derive(Clone, Debug)]
pub struct DeliveryInfo {
    pub request: u64,
    pub destination: u64,
    pub state: String,
    pub reason: Option<String>,
    pub msg_session: Option<u64>,
    pub msg_seq: Option<u64>,
    pub updated_ms: u64,
}

#[derive(Clone, Debug)]
pub struct EventInfo {
    pub seq: u64,
    pub ms: u64,
    pub kind: String,
    pub detail: String,
}

#[derive(Clone, Debug, Default)]
pub struct AuthorityInfo {
    /// "unknown" until the daemon reports otherwise.
    pub state: String,
    pub source: Option<String>,
    pub network: Option<u64>,
    pub detail: Option<String>,
}

/// Experimental autonomy view. Every field is `None` until the daemon has
/// observed a real device diagnostic carrying it — the TUI renders nulls as
/// unknown rather than inventing mesh state.
#[derive(Clone, Debug, Default)]
pub struct AutonomyInfo {
    /// Coordinator mode from MIGRATION_MODE_* device events.
    pub migration_mode: Option<String>,
    /// Participant phase from PHASE_* events.
    pub participant_phase: Option<String>,
    /// Latest coordinator judgment from ASSESS_* events.
    pub assess_verdict: Option<String>,
    /// Latest gated-operation detail (AUTOGUARDED_*/AUTOSURVEY_*/SURVEY_*).
    pub gate_detail: Option<String>,
    pub last_discovery: Option<String>,
    pub last_discovery_ms: Option<u64>,
    pub last_migration: Option<String>,
    pub last_migration_ms: Option<u64>,
    pub discovery_events: u64,
    pub migration_events: u64,
}

/// Bounded drop-oldest event ring. `local_dropped` counts events discarded
/// here; `daemon_dropped` is the daemon's own overflow counter.
#[derive(Clone, Debug)]
pub struct EventLog {
    events: VecDeque<EventInfo>,
    cap: usize,
    pub local_dropped: u64,
    pub daemon_dropped: u64,
    last_seq: u64,
}

impl Default for EventLog {
    fn default() -> Self {
        Self::with_cap(EVENT_CAP)
    }
}

impl EventLog {
    pub fn with_cap(cap: usize) -> Self {
        Self {
            events: VecDeque::new(),
            cap,
            local_dropped: 0,
            daemon_dropped: 0,
            last_seq: 0,
        }
    }

    /// Bounded append. Deduplication is the caller's job (apply_events knows
    /// the daemon's seq semantics); this ring only enforces the cap.
    pub fn push(&mut self, event: EventInfo) {
        self.last_seq = self.last_seq.max(event.seq);
        if self.events.len() >= self.cap {
            self.events.pop_front();
            self.local_dropped += 1;
        }
        self.events.push_back(event);
    }

    pub fn contains_seq(&self, seq: u64) -> bool {
        self.events.iter().any(|e| e.seq == seq)
    }

    /// Drop everything (daemon restart: seq space resets to 0).
    pub fn clear(&mut self) {
        self.events.clear();
        self.local_dropped = 0;
        self.last_seq = 0;
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    pub fn iter(&self) -> impl DoubleEndedIterator<Item = &EventInfo> {
        self.events.iter()
    }
}

#[derive(Default)]
pub struct State {
    pub socket: String,
    pub conn: Conn,
    pub adapter: AdapterInfo,
    pub nodes: Vec<NodeInfo>,
    pub deliveries: Vec<DeliveryInfo>,
    pub events: EventLog,
    pub authority: AuthorityInfo,
    pub autonomy: AutonomyInfo,
    pub last_refresh_ms: Option<u64>,
    /// Poll cycles that failed mid-way (daemon vanished between commands).
    pub poll_failures: u64,
    /// Latched when a diagnostic event reports the development security
    /// profile: the warning must stay visible, not scroll out of the event
    /// ring.
    pub security_experimental: bool,
}

fn obs_str(json: Option<&Json>) -> Obs<String> {
    match json {
        Some(Json::String(text)) if text != "unknown" => Obs::Observed(text.clone()),
        _ => Obs::Unknown,
    }
}

fn obs_num(json: Option<&Json>) -> Obs<u64> {
    json.and_then(Json::as_u64)
        .map_or(Obs::Unknown, Obs::Observed)
}

fn opt_u64(json: Option<&Json>) -> Option<u64> {
    json.and_then(Json::as_u64)
}

fn opt_str(json: Option<&Json>) -> Option<String> {
    json.and_then(Json::as_str).map(str::to_string)
}

fn opt_bool(json: Option<&Json>) -> Option<bool> {
    json.and_then(Json::as_bool)
}

/// Render the non-envelope fields of an event object as `k=v` pairs. Honest
/// and generic: whatever the daemon reports is what the user sees.
fn event_detail(event: &Json) -> String {
    let mut parts = Vec::new();
    if let Json::Object(entries) = event {
        for (key, value) in entries {
            if matches!(key.as_str(), "seq" | "ms" | "kind") {
                continue;
            }
            let rendered = match value {
                Json::Null => continue,
                Json::Bool(v) => v.to_string(),
                Json::Number(v) => v.clone(),
                Json::String(v) => v.clone(),
                other => format!("{other:?}"),
            };
            parts.push(format!("{key}={rendered}"));
        }
    }
    parts.join(" ")
}

impl State {
    pub fn new(socket: impl Into<String>) -> Self {
        State {
            socket: socket.into(),
            ..State::default()
        }
    }

    /// Apply one daemon response line. `command` is the verb that produced it
    /// (STATUS, ADAPTER, NODES, DELIVERIES, EVENTS, AUTHORITY, AUTONOMY).
    pub fn apply(&mut self, command: &str, line: &str) -> Result<(), JsonError> {
        let root = json::parse(line)?;
        match command {
            "STATUS" | "DIAGNOSTICS" => self.apply_status(&root),
            "ADAPTER" => self.apply_adapter(&root),
            "NODES" => self.apply_nodes(&root),
            "DELIVERIES" => self.apply_deliveries(&root),
            "EVENTS" => self.apply_events(&root),
            "AUTHORITY" => self.apply_authority(&root),
            "AUTONOMY" => self.apply_autonomy(&root),
            _ => {}
        }
        Ok(())
    }

    fn apply_status(&mut self, root: &Json) {
        self.adapter.connected = opt_bool(root.get("connected"));
        self.adapter.device = opt_str(root.get("device"));
        self.adapter.rx_frames = opt_u64(root.get("rx_frames"));
        self.adapter.tx_frames = opt_u64(root.get("tx_frames"));
        self.adapter.protocol_errors = opt_u64(root.get("protocol_errors"));
        // Assign unconditionally: a null last_error must clear a stale one.
        self.adapter.last_error = opt_str(root.get("last_error"));
    }

    fn apply_adapter(&mut self, root: &Json) {
        self.adapter.device = opt_str(root.get("device"));
        self.adapter.connected = opt_bool(root.get("connected"));
        if let Some(session) = root.get("session") {
            self.adapter.authenticated = opt_bool(session.get("authenticated"));
            self.adapter.session_id = opt_u64(session.get("id"));
            self.adapter.node = opt_u64(session.get("node"));
            self.adapter.boot = opt_u64(session.get("boot"));
            self.adapter.network = opt_u64(session.get("network"));
            self.adapter.capability = opt_u64(session.get("capability"));
            self.adapter.version = opt_u64(session.get("version"));
        }
        if let Some(credit) = root.get("credit") {
            self.adapter.credit_observed = opt_bool(credit.get("observed")).unwrap_or(false);
            self.adapter.grant_frames = opt_u64(credit.get("grant_frames"));
            self.adapter.grant_bytes = opt_u64(credit.get("grant_bytes"));
        }
        self.adapter.rx_frames = opt_u64(root.get("rx_frames"));
        self.adapter.tx_frames = opt_u64(root.get("tx_frames"));
        self.adapter.tx_bytes = opt_u64(root.get("tx_bytes"));
        self.adapter.protocol_errors = opt_u64(root.get("protocol_errors"));
        // Assign unconditionally: a null last_error must clear a stale one.
        self.adapter.last_error = opt_str(root.get("last_error"));
    }

    fn apply_nodes(&mut self, root: &Json) {
        let mut nodes = Vec::new();
        if let Some(list) = root.get("nodes").and_then(Json::as_array) {
            for item in list {
                nodes.push(NodeInfo {
                    id: opt_u64(item.get("id")).unwrap_or(0),
                    role: opt_str(item.get("role")).unwrap_or_else(|| "peer".into()),
                    seen_ms: opt_u64(item.get("seen_ms")).unwrap_or(0),
                    membership: obs_str(item.get("membership")),
                    reachability: obs_str(item.get("reachability")),
                    sleeping: match item.get("sleeping").and_then(Json::as_bool) {
                        Some(v) => Obs::Observed(v),
                        None => Obs::Unknown,
                    },
                    rssi_dbm: match item.get("rssi_dbm").and_then(Json::as_i64) {
                        Some(v) => Obs::Observed(v),
                        None => Obs::Unknown,
                    },
                    lr250: match item.get("lr250") {
                        Some(Json::Bool(v)) => Obs::Observed(*v),
                        _ => Obs::Unknown,
                    },
                    hop_count: obs_num(item.get("hop_count")),
                    queue_depth: obs_num(item.get("queue_depth")),
                    peer_slots: obs_num(item.get("peer_slots")),
                    primary_route: obs_str(item.get("primary_route")),
                    backup_route: obs_str(item.get("backup_route")),
                });
            }
        }
        self.nodes = nodes;
    }

    fn apply_deliveries(&mut self, root: &Json) {
        let mut deliveries = Vec::new();
        if let Some(list) = root.get("deliveries").and_then(Json::as_array) {
            for item in list {
                deliveries.push(DeliveryInfo {
                    request: opt_u64(item.get("request")).unwrap_or(0),
                    destination: opt_u64(item.get("destination")).unwrap_or(0),
                    state: opt_str(item.get("state")).unwrap_or_else(|| "unknown".into()),
                    reason: opt_str(item.get("reason")),
                    msg_session: opt_u64(item.get("msg_session")),
                    msg_seq: opt_u64(item.get("msg_seq")),
                    updated_ms: opt_u64(item.get("updated_ms")).unwrap_or(0),
                });
            }
        }
        self.deliveries = deliveries;
    }

    fn apply_events(&mut self, root: &Json) {
        self.events.daemon_dropped = opt_u64(root.get("dropped")).unwrap_or(0);
        let next_seq = opt_u64(root.get("next_seq")).unwrap_or(0);
        let list = root.get("events").and_then(Json::as_array).unwrap_or(&[]);
        // Daemon restart detection: its seq space resets to 0. Either the
        // daemon's total counter is behind our watermark, or it serves a
        // seq==0 event that is not the one we already hold.
        let restarted = next_seq < self.events.last_seq
            || list.iter().any(|item| {
                opt_u64(item.get("seq")) == Some(0)
                    && !self.events.iter().any(|held| {
                        held.seq == 0 && held.ms == opt_u64(item.get("ms")).unwrap_or(0)
                    })
            });
        if restarted {
            self.events.clear();
        }
        for item in list {
            let seq = opt_u64(item.get("seq")).unwrap_or(0);
            if seq < self.events.last_seq || self.events.contains_seq(seq) {
                continue; // replayed tail of the daemon ring
            }
            let kind = opt_str(item.get("kind")).unwrap_or_else(|| "event".into());
            let detail = event_detail(item);
            if kind == "diagnostic" && detail.contains("SECURITY_PROFILE") {
                self.security_experimental = true;
            }
            self.events.push(EventInfo {
                seq,
                ms: opt_u64(item.get("ms")).unwrap_or(0),
                kind,
                detail,
            });
        }
    }

    fn apply_authority(&mut self, root: &Json) {
        self.authority.state = opt_str(root.get("state")).unwrap_or_else(|| "unknown".into());
        self.authority.source = opt_str(root.get("source"));
        self.authority.network = opt_u64(root.get("network"));
        self.authority.detail = opt_str(root.get("detail"));
    }

    fn apply_autonomy(&mut self, root: &Json) {
        self.autonomy.migration_mode = opt_str(root.get("migration_mode"));
        self.autonomy.participant_phase = opt_str(root.get("participant_phase"));
        self.autonomy.assess_verdict = opt_str(root.get("assess_verdict"));
        self.autonomy.gate_detail = opt_str(root.get("gate_detail"));
        if let Some(last) = root.get("last_discovery") {
            self.autonomy.last_discovery = opt_str(last.get("reason"));
            self.autonomy.last_discovery_ms = opt_u64(last.get("ms"));
        }
        if let Some(last) = root.get("last_migration") {
            self.autonomy.last_migration = opt_str(last.get("reason"));
            self.autonomy.last_migration_ms = opt_u64(last.get("ms"));
        }
        self.autonomy.discovery_events = opt_u64(root.get("discovery_events")).unwrap_or(0);
        self.autonomy.migration_events = opt_u64(root.get("migration_events")).unwrap_or(0);
    }

    pub fn deliveries_by_state(&self, state: &str) -> usize {
        self.deliveries.iter().filter(|d| d.state == state).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_ring_drops_oldest() {
        let mut log = EventLog::with_cap(4);
        for seq in 0..10 {
            log.push(EventInfo {
                seq,
                ms: seq,
                kind: "k".into(),
                detail: String::new(),
            });
        }
        assert_eq!(log.len(), 4);
        assert_eq!(log.local_dropped, 6);
        assert_eq!(log.iter().next().unwrap().seq, 6);
    }

    #[test]
    fn unknown_fields_stay_unknown() {
        let mut state = State::default();
        state
            .apply(
                "NODES",
                r#"{"nodes":[{"id":7,"role":"peer","seen_ms":5,"membership":"unknown","reachability":"unknown","rssi_dbm":null,"lr250":"unknown","hop_count":null}]}"#,
            )
            .unwrap();
        let node = &state.nodes[0];
        assert_eq!(node.id, 7);
        assert!(node.membership.is_unknown());
        assert!(node.rssi_dbm.is_unknown());
        assert!(node.hop_count.is_unknown());
    }

    #[test]
    fn events_dedup_across_polls() {
        let mut state = State::default();
        let line = r#"{"events":[{"seq":0,"ms":1,"kind":"keepalive"},{"seq":1,"ms":2,"kind":"keepalive"}],"dropped":0}"#;
        state.apply("EVENTS", line).unwrap();
        state.apply("EVENTS", line).unwrap();
        assert_eq!(state.events.len(), 2);
    }
}
