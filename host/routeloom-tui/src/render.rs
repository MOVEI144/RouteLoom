//! Pure renderer: `State` + active tab → frame text. No terminal IO here, so
//! every screen is snapshot-testable. Rendering rules: daemon-observed values
//! are shown plainly, locally estimated values carry a `~` prefix, and fields
//! the daemon cannot know render as `unknown` — never fabricated.

use crate::model::{Conn, Obs, State};
use std::fmt::Display;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Tab {
    Overview,
    Nodes,
    Routes,
    Links,
    Deliveries,
    Events,
    Adapter,
    Authority,
    Autonomy,
}

pub const TABS: [Tab; 9] = [
    Tab::Overview,
    Tab::Nodes,
    Tab::Routes,
    Tab::Links,
    Tab::Deliveries,
    Tab::Events,
    Tab::Adapter,
    Tab::Authority,
    Tab::Autonomy,
];

impl Tab {
    pub fn title(self) -> &'static str {
        match self {
            Tab::Overview => "Overview",
            Tab::Nodes => "Nodes",
            Tab::Routes => "Routes",
            Tab::Links => "Links",
            Tab::Deliveries => "Deliveries",
            Tab::Events => "Events",
            Tab::Adapter => "Adapter/USB",
            Tab::Authority => "Authority",
            Tab::Autonomy => "Autonomy",
        }
    }

    pub fn index(self) -> usize {
        TABS.iter().position(|t| *t == self).unwrap_or(0)
    }

    pub fn from_index(index: usize) -> Tab {
        TABS[index % TABS.len()]
    }

    pub fn next(self) -> Tab {
        Tab::from_index(self.index() + 1)
    }

    pub fn prev(self) -> Tab {
        Tab::from_index(self.index() + TABS.len() - 1)
    }
}

fn cut(line: &str, width: usize) -> String {
    line.chars()
        .take(width)
        .collect::<String>()
        .trim_end()
        .to_string()
}

fn opt<T: Display>(value: &Option<T>) -> String {
    value
        .as_ref()
        .map_or_else(|| "unknown".into(), |v| v.to_string())
}

fn opt_bool(value: Option<bool>) -> String {
    value.map_or_else(|| "unknown".into(), |v| if v { "yes" } else { "no" }.into())
}

/// While the daemon is disconnected every observed value is stale — render
/// it with the estimated marker rather than silently presenting old data as
/// current.
fn obs<T: Display>(value: &Obs<T>, stale: bool) -> String {
    match value {
        Obs::Observed(v) if stale => format!("~{v}"),
        Obs::Observed(v) => format!("{v}"),
        Obs::Estimated(v) => format!("~{v}"),
        Obs::Unknown => "unknown".into(),
    }
}

fn obs_bool(value: &Obs<bool>, stale: bool) -> String {
    match value {
        Obs::Observed(v) if stale => format!("~{}", if *v { "yes" } else { "no" }),
        Obs::Observed(v) => if *v { "yes" } else { "no" }.to_string(),
        Obs::Estimated(v) => format!("~{}", if *v { "yes" } else { "no" }),
        Obs::Unknown => "unknown".into(),
    }
}

fn stale(state: &State) -> bool {
    !matches!(state.conn, Conn::Connected)
}

/// Relative age of a daemon millisecond timestamp.
fn age(now_ms: u64, ms: u64) -> String {
    if ms == 0 {
        return "unknown".into();
    }
    let delta = now_ms.saturating_sub(ms);
    if delta < 1000 {
        format!("{delta}ms")
    } else if delta < 60_000 {
        format!("{}s", delta / 1000)
    } else if delta < 3_600_000 {
        format!("{}m", delta / 60_000)
    } else {
        format!("{}h", delta / 3_600_000)
    }
}

fn conn_line(state: &State, now_ms: u64) -> String {
    match &state.conn {
        Conn::Connected => "connected".to_string(),
        Conn::Disconnected {
            attempts,
            next_retry_ms,
            error,
            ..
        } => {
            let retry = next_retry_ms.saturating_sub(now_ms);
            format!(
                "disconnected · attempt {attempts} · retry in {}ms{}",
                retry,
                error
                    .as_ref()
                    .map_or_else(String::new, |e| format!(" · {e}"))
            )
        }
    }
}

/// Full frame: header, tab bar, screen body, footer. Lines are clipped to
/// `width` and the frame to `height` lines.
pub fn render(state: &State, tab: Tab, width: usize, height: usize, now_ms: u64) -> String {
    let mut lines: Vec<String> = Vec::new();
    lines.push(format!(
        "RouteLoom TUI  ·  daemon {}  ·  {}",
        state.socket,
        conn_line(state, now_ms)
    ));
    let mut bar = String::new();
    for (index, candidate) in TABS.iter().enumerate() {
        if index > 0 {
            bar.push_str("  ");
        }
        if *candidate == tab {
            bar.push_str(&format!("[*{} {}]", index + 1, candidate.title()));
        } else {
            bar.push_str(&format!(" {}  {} ", index + 1, candidate.title()));
        }
    }
    lines.push(bar);
    lines.push("-".repeat(width.min(78)));

    let body = match tab {
        Tab::Overview => overview(state, now_ms),
        Tab::Nodes => nodes(state, now_ms),
        Tab::Routes => routes(state, now_ms),
        Tab::Links => links(state),
        Tab::Deliveries => deliveries(state, now_ms),
        Tab::Events => events(state, now_ms),
        Tab::Adapter => adapter(state),
        Tab::Authority => authority(state),
        Tab::Autonomy => autonomy(state, now_ms),
    };
    lines.extend(body);

    lines.push("-".repeat(width.min(78)));
    lines.push(
        "tab/arrows/1-9 switch · q quit · values: observed plain, ~estimated, unknown = no source"
            .to_string(),
    );

    lines
        .iter()
        .take(height)
        .map(|line| cut(line, width))
        .collect::<Vec<_>>()
        .join("\n")
}

fn overview(state: &State, now_ms: u64) -> Vec<String> {
    let a = &state.adapter;
    let mut out = vec![
        format!("daemon connection : {}", conn_line(state, now_ms)),
        format!(
            "adapter           : {} ({})",
            opt_bool(a.connected),
            a.device.clone().unwrap_or_else(|| "no device".into())
        ),
        format!(
            "session           : auth={} node={} network={} version={}",
            opt_bool(a.authenticated),
            opt(&a.node),
            opt(&a.network),
            opt(&a.version)
        ),
        format!(
            "frames            : rx={} tx={} tx_bytes={} protocol_errors={}",
            opt(&a.rx_frames),
            opt(&a.tx_frames),
            opt(&a.tx_bytes),
            opt(&a.protocol_errors)
        ),
        format!(
            "credit grant      : {}",
            if a.credit_observed {
                format!(
                    "{} frames / {} bytes",
                    opt(&a.grant_frames),
                    opt(&a.grant_bytes)
                )
            } else {
                "unknown".into()
            }
        ),
        format!("last adapter error: {}", opt(&a.last_error)),
        String::new(),
        format!("nodes observed    : {}", state.nodes.len()),
        format!(
            "deliveries        : {} tracked (delivered={} failed={} in-flight={})",
            state.deliveries.len(),
            state.deliveries_by_state("delivered"),
            state.deliveries_by_state("failed") + state.deliveries_by_state("rejected"),
            state.deliveries.len()
                - state.deliveries_by_state("delivered")
                - state.deliveries_by_state("failed")
                - state.deliveries_by_state("expired")
                - state.deliveries_by_state("cancelled-before-tx")
                - state.deliveries_by_state("rejected")
        ),
        format!(
            "events            : {} buffered (daemon dropped={}, local dropped={})",
            state.events.len(),
            state.events.daemon_dropped,
            state.events.local_dropped
        ),
        format!("authority         : {}", state.authority.state),
    ];
    if state.security_experimental {
        out.push(
            "security          : EXPERIMENTAL — development PSK profile, not production".into(),
        );
    }
    if let Some(ms) = state.last_refresh_ms {
        out.push(format!("last refresh      : {} ago", age(now_ms, ms)));
    }
    out
}

fn nodes(state: &State, now_ms: u64) -> Vec<String> {
    let mut out = vec![format!(
        "{:<20} {:<8} {:<8} {:<12} {:<12} {:<8} {:<8} {}",
        "node id", "role", "seen", "membership", "reachable", "sleeping", "rssi", "lr250"
    )];
    if state.nodes.is_empty() {
        out.push("(no nodes observed by the daemon)".into());
    }
    for node in &state.nodes {
        out.push(format!(
            "{:<20} {:<8} {:<8} {:<12} {:<12} {:<8} {:<8} {}",
            node.id,
            node.role,
            age(now_ms, node.seen_ms),
            obs(&node.membership, stale(state)),
            obs(&node.reachability, stale(state)),
            obs_bool(&node.sleeping, stale(state)),
            obs(&node.rssi_dbm, stale(state)),
            obs_bool(&node.lr250, stale(state)),
        ));
    }
    out.push(String::new());
    out.push("membership/reachability/rssi are not visible to the host daemon → unknown".into());
    out
}

fn routes(state: &State, now_ms: u64) -> Vec<String> {
    let mut out = vec![format!(
        "{:<20} {:<24} {:<24} {}",
        "destination", "primary route", "backup route", "hops"
    )];
    if state.nodes.is_empty() {
        out.push("(no destinations observed)".into());
    }
    for node in &state.nodes {
        out.push(format!(
            "{:<20} {:<24} {:<24} {}",
            node.id,
            obs(&node.primary_route, stale(state)),
            obs(&node.backup_route, stale(state)),
            obs(&node.hop_count, stale(state)),
        ));
    }
    out.push(String::new());
    out.push(
        "the USB adapter owns the routing table; the daemon does not decode it → unknown".into(),
    );
    let _ = now_ms;
    out
}

fn links(state: &State) -> Vec<String> {
    let a = &state.adapter;
    let mut out = vec![
        "USB link (daemon ↔ adapter):".to_string(),
        format!(
            "  device={} connected={} tx_bytes={}",
            opt(&a.device),
            opt_bool(a.connected),
            opt(&a.tx_bytes)
        ),
        String::new(),
        format!(
            "{:<20} {:<10} {:<10} {}",
            "peer", "rssi", "peer slot", "queue"
        ),
    ];
    if state.nodes.iter().filter(|n| n.role == "peer").count() == 0 {
        out.push("(no mesh peers observed)".into());
    }
    for node in state.nodes.iter().filter(|n| n.role == "peer") {
        out.push(format!(
            "{:<20} {:<10} {:<10} {}",
            node.id,
            obs(&node.rssi_dbm, stale(state)),
            obs(&node.peer_slots, stale(state)),
            obs(&node.queue_depth, stale(state)),
        ));
    }
    out.push(String::new());
    out.push("mesh link metrics are radio-local; not forwarded over USB → unknown".into());
    out
}

fn deliveries(state: &State, now_ms: u64) -> Vec<String> {
    let mut out = vec![format!(
        "{:<10} {:<20} {:<22} {:<14} {:<8} {}",
        "request", "destination", "state", "msg id", "updated", "reason"
    )];
    if state.deliveries.is_empty() {
        out.push("(no deliveries tracked)".into());
    }
    for delivery in state.deliveries.iter().rev() {
        let msg = match (delivery.msg_session, delivery.msg_seq) {
            (Some(s), Some(q)) => format!("{s}:{q}"),
            _ => "unknown".into(),
        };
        out.push(format!(
            "{:<10} {:<20} {:<22} {:<14} {:<8} {}",
            delivery.request,
            delivery.destination,
            delivery.state,
            msg,
            age(now_ms, delivery.updated_ms),
            delivery.reason.clone().unwrap_or_default(),
        ));
    }
    out
}

fn events(state: &State, now_ms: u64) -> Vec<String> {
    let mut out = vec![
        format!("{:<8} {:<8} {:<18} {}", "seq", "age", "kind", "detail"),
        format!(
            "buffered={} dropped: daemon={} local={}",
            state.events.len(),
            state.events.daemon_dropped,
            state.events.local_dropped
        ),
    ];
    if state.events.is_empty() {
        out.push("(no events received)".into());
    }
    for event in state.events.iter().rev() {
        out.push(format!(
            "{:<8} {:<8} {:<18} {}",
            event.seq,
            age(now_ms, event.ms),
            event.kind,
            event.detail,
        ));
    }
    out
}

fn adapter(state: &State) -> Vec<String> {
    let a = &state.adapter;
    vec![
        format!("device            : {}", opt(&a.device)),
        format!("connected         : {}", opt_bool(a.connected)),
        format!("authenticated     : {}", opt_bool(a.authenticated)),
        format!("session id        : {}", opt(&a.session_id)),
        format!("node id           : {}", opt(&a.node)),
        format!("boot id           : {}", opt(&a.boot)),
        format!("network           : {}", opt(&a.network)),
        format!("capability digest : {}", opt(&a.capability)),
        format!("protocol version  : {}", opt(&a.version)),
        String::new(),
        format!(
            "tx credit grant   : {}",
            if a.credit_observed {
                format!(
                    "{} frames / {} bytes (cumulative, observed)",
                    opt(&a.grant_frames),
                    opt(&a.grant_bytes)
                )
            } else {
                "unknown (no Credit frame observed)".into()
            }
        ),
        String::new(),
        format!("rx frames         : {}", opt(&a.rx_frames)),
        format!("tx frames         : {}", opt(&a.tx_frames)),
        format!("tx bytes          : {}", opt(&a.tx_bytes)),
        format!("protocol errors   : {}", opt(&a.protocol_errors)),
        format!("last error        : {}", opt(&a.last_error)),
    ]
}

fn authority(state: &State) -> Vec<String> {
    let a = &state.authority;
    vec![
        format!("authority state   : {}", a.state),
        format!("source            : {}", opt(&a.source)),
        format!("network           : {}", opt(&a.network)),
        format!("detail            : {}", opt(&a.detail)),
        String::new(),
        "the control-plane ledger is not attached to the host daemon;".to_string(),
        "membership authority, config revision and quorum are unknown here.".to_string(),
    ]
}

fn autonomy(state: &State, now_ms: u64) -> Vec<String> {
    let a = &state.autonomy;
    let last = |ms: Option<u64>, reason: &Option<String>| -> String {
        match (ms, reason) {
            (Some(ms), Some(reason)) => format!("{} ({} ago)", reason, age(now_ms, ms)),
            _ => "unknown".into(),
        }
    };
    vec![
        "EXPERIMENTAL lane — simulated/host events only; not RF validation,".to_string(),
        "not production-qualified, no atomic-cutover or zero-outage claim.".to_string(),
        String::new(),
        format!("migration mode    : {}", opt(&a.migration_mode)),
        format!("participant phase : {}", opt(&a.participant_phase)),
        format!("assessment        : {}", opt(&a.assess_verdict)),
        format!("last gate detail  : {}", opt(&a.gate_detail)),
        String::new(),
        format!("discovery events  : {}", a.discovery_events),
        format!(
            "last discovery    : {}",
            last(a.last_discovery_ms, &a.last_discovery)
        ),
        format!("migration events  : {}", a.migration_events),
        format!(
            "last migration    : {}",
            last(a.last_migration_ms, &a.last_migration)
        ),
        String::new(),
        "fields stay unknown until the device emits a diagnostic for them;".to_string(),
        "AutoGuarded remains opt-in — see Events for the raw event stream.".to_string(),
    ]
}
