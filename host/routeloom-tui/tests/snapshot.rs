//! Snapshot fixture tests: canned daemon JSON (same bytes routeloomctl would
//! print) → State → rendered frame text, compared verbatim.

use routeloom_tui::model::{Conn, State};
use routeloom_tui::render::{render, Tab};

const STATUS: &str = "{\"connected\":true,\"device\":\"/dev/ttyUSB0\",\"rx_frames\":128,\"tx_frames\":12,\"protocol_errors\":1,\"last_error\":\"CREDIT_EXCEEDED\"}";

const ADAPTER: &str = "{\"device\":\"/dev/ttyUSB0\",\"connected\":true,\"session\":{\"authenticated\":true,\"id\":99,\"node\":42,\"boot\":7,\"network\":9,\"capability\":3,\"version\":1},\"credit\":{\"observed\":true,\"grant_frames\":64,\"grant_bytes\":8192},\"rx_frames\":128,\"tx_frames\":12,\"tx_bytes\":612,\"protocol_errors\":1,\"last_error\":\"CREDIT_EXCEEDED\"}";

const NODES: &str = "{\"nodes\":[{\"id\":42,\"role\":\"adapter\",\"seen_ms\":1999000,\"membership\":\"unknown\",\"reachability\":\"unknown\",\"rssi_dbm\":null,\"lr250\":\"unknown\",\"hop_count\":null},{\"id\":77,\"role\":\"peer\",\"seen_ms\":1998000,\"membership\":\"unknown\",\"reachability\":\"unknown\",\"rssi_dbm\":null,\"lr250\":\"unknown\",\"hop_count\":null}]}";

const DELIVERIES: &str = "{\"deliveries\":[{\"request\":9,\"destination\":5,\"state\":\"delivered\",\"reason\":null,\"msg_session\":5,\"msg_seq\":900,\"updated_ms\":1995000},{\"request\":10,\"destination\":8,\"state\":\"queued\",\"reason\":null,\"msg_session\":null,\"msg_seq\":null,\"updated_ms\":1999900}]}";

const EVENTS: &str = "{\"events\":[{\"seq\":0,\"ms\":1990000,\"kind\":\"hello_ack\",\"version\":1,\"node\":42,\"boot\":7,\"network\":9,\"capability\":3},{\"seq\":1,\"ms\":1995000,\"kind\":\"delivery_event\",\"request\":9,\"state\":\"delivered\",\"msg_session\":5,\"msg_seq\":900,\"reason\":null},{\"seq\":2,\"ms\":1998000,\"kind\":\"data_from_mesh\",\"origin\":77,\"msg_session\":5,\"msg_seq\":901,\"payload_len\":2}],\"dropped\":0,\"next_seq\":3}";

const AUTHORITY: &str = "{\"state\":\"unknown\",\"source\":null,\"network\":9,\"detail\":\"no control-plane ledger is attached to this daemon\"}";

const NOW: u64 = 2_000_000;
const WIDTH: usize = 100;
const HEIGHT: usize = 30;

fn loaded_state() -> State {
    let mut state = State::new("/tmp/routeloom.sock");
    state.conn = Conn::Connected;
    for (command, line) in [
        ("STATUS", STATUS),
        ("ADAPTER", ADAPTER),
        ("NODES", NODES),
        ("DELIVERIES", DELIVERIES),
        ("EVENTS", EVENTS),
        ("AUTHORITY", AUTHORITY),
    ] {
        state.apply(command, line).expect("fixture parses");
    }
    state.last_refresh_ms = Some(1_999_500);
    state
}

fn check(tab: Tab, expected: &str) {
    let actual = render(&loaded_state(), tab, WIDTH, HEIGHT, NOW);
    assert_eq!(actual, expected, "snapshot mismatch for {tab:?}");
}

#[test]
fn overview_snapshot() {
    check(
        Tab::Overview,
        "\
RouteLoom TUI  ·  daemon /tmp/routeloom.sock  ·  connected
[*1 Overview]   2  Nodes    3  Routes    4  Links    5  Deliveries    6  Events    7  Adapter/USB
------------------------------------------------------------------------------
daemon connection : connected
adapter           : yes (/dev/ttyUSB0)
session           : auth=yes node=42 network=9 version=1
frames            : rx=128 tx=12 tx_bytes=612 protocol_errors=1
credit grant      : 64 frames / 8192 bytes
last adapter error: CREDIT_EXCEEDED

nodes observed    : 2
deliveries        : 2 tracked (delivered=1 failed=0 in-flight=1)
events            : 3 buffered (daemon dropped=0, local dropped=0)
authority         : unknown
last refresh      : 500ms ago
------------------------------------------------------------------------------
tab/arrows/1-8 switch · q quit · values: observed plain, ~estimated, unknown = no source",
    );
}

#[test]
fn nodes_snapshot() {
    check(
        Tab::Nodes,
        "\
RouteLoom TUI  ·  daemon /tmp/routeloom.sock  ·  connected
 1  Overview   [*2 Nodes]   3  Routes    4  Links    5  Deliveries    6  Events    7  Adapter/USB
------------------------------------------------------------------------------
node id              role     seen     membership   reachable    sleeping rssi     lr250
42                   adapter  1s       unknown      unknown      unknown  unknown  unknown
77                   peer     2s       unknown      unknown      unknown  unknown  unknown

membership/reachability/rssi are not visible to the host daemon → unknown
------------------------------------------------------------------------------
tab/arrows/1-8 switch · q quit · values: observed plain, ~estimated, unknown = no source",
    );
}

#[test]
fn routes_snapshot() {
    check(
        Tab::Routes,
        "\
RouteLoom TUI  ·  daemon /tmp/routeloom.sock  ·  connected
 1  Overview    2  Nodes   [*3 Routes]   4  Links    5  Deliveries    6  Events    7  Adapter/USB
------------------------------------------------------------------------------
destination          primary route            backup route             hops
42                   unknown                  unknown                  unknown
77                   unknown                  unknown                  unknown

the USB adapter owns the routing table; the daemon does not decode it → unknown
------------------------------------------------------------------------------
tab/arrows/1-8 switch · q quit · values: observed plain, ~estimated, unknown = no source",
    );
}

#[test]
fn links_snapshot() {
    check(
        Tab::Links,
        "\
RouteLoom TUI  ·  daemon /tmp/routeloom.sock  ·  connected
 1  Overview    2  Nodes    3  Routes   [*4 Links]   5  Deliveries    6  Events    7  Adapter/USB
------------------------------------------------------------------------------
USB link (daemon ↔ adapter):
  device=/dev/ttyUSB0 connected=yes tx_bytes=612

peer                 rssi       peer slot  queue
77                   unknown    unknown    unknown

mesh link metrics are radio-local; not forwarded over USB → unknown
------------------------------------------------------------------------------
tab/arrows/1-8 switch · q quit · values: observed plain, ~estimated, unknown = no source",
    );
}

#[test]
fn deliveries_snapshot() {
    check(
        Tab::Deliveries,
        "\
RouteLoom TUI  ·  daemon /tmp/routeloom.sock  ·  connected
 1  Overview    2  Nodes    3  Routes    4  Links   [*5 Deliveries]   6  Events    7  Adapter/USB
------------------------------------------------------------------------------
request    destination          state                  msg id         updated  reason
10         8                    queued                 unknown        100ms
9          5                    delivered              5:900          5s
------------------------------------------------------------------------------
tab/arrows/1-8 switch · q quit · values: observed plain, ~estimated, unknown = no source",
    );
}

#[test]
fn events_snapshot() {
    check(
        Tab::Events,
        "\
RouteLoom TUI  ·  daemon /tmp/routeloom.sock  ·  connected
 1  Overview    2  Nodes    3  Routes    4  Links    5  Deliveries   [*6 Events]   7  Adapter/USB
------------------------------------------------------------------------------
seq      age      kind               detail
buffered=3 dropped: daemon=0 local=0
2        2s       data_from_mesh     origin=77 msg_session=5 msg_seq=901 payload_len=2
1        5s       delivery_event     request=9 state=delivered msg_session=5 msg_seq=900
0        10s      hello_ack          version=1 node=42 boot=7 network=9 capability=3
------------------------------------------------------------------------------
tab/arrows/1-8 switch · q quit · values: observed plain, ~estimated, unknown = no source",
    );
}

#[test]
fn adapter_snapshot() {
    check(
        Tab::Adapter,
        "\
RouteLoom TUI  ·  daemon /tmp/routeloom.sock  ·  connected
 1  Overview    2  Nodes    3  Routes    4  Links    5  Deliveries    6  Events   [*7 Adapter/USB]
------------------------------------------------------------------------------
device            : /dev/ttyUSB0
connected         : yes
authenticated     : yes
session id        : 99
node id           : 42
boot id           : 7
network           : 9
capability digest : 3
protocol version  : 1

tx credit grant   : 64 frames / 8192 bytes (cumulative, observed)

rx frames         : 128
tx frames         : 12
tx bytes          : 612
protocol errors   : 1
last error        : CREDIT_EXCEEDED
------------------------------------------------------------------------------
tab/arrows/1-8 switch · q quit · values: observed plain, ~estimated, unknown = no source",
    );
}

#[test]
fn authority_snapshot() {
    check(
        Tab::Authority,
        "\
RouteLoom TUI  ·  daemon /tmp/routeloom.sock  ·  connected
 1  Overview    2  Nodes    3  Routes    4  Links    5  Deliveries    6  Events    7  Adapter/USB
------------------------------------------------------------------------------
authority state   : unknown
source            : unknown
network           : 9
detail            : no control-plane ledger is attached to this daemon

the control-plane ledger is not attached to the host daemon;
membership authority, config revision and quorum are unknown here.
------------------------------------------------------------------------------
tab/arrows/1-8 switch · q quit · values: observed plain, ~estimated, unknown = no source",
    );
}

#[test]
fn disconnected_state_renders() {
    let mut state = loaded_state();
    state.conn = Conn::Disconnected {
        since_ms: 1_999_000,
        attempts: 2,
        next_retry_ms: 2_001_000,
        error: Some("connection refused".into()),
    };
    let frame = render(&state, Tab::Overview, WIDTH, HEIGHT, NOW);
    assert!(frame.contains("disconnected · attempt 2 · retry in 1000ms · connection refused"));
}
