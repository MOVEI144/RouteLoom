//! Bounded-queue test: flood the client-side event ring and assert the cap
//! holds with drop-oldest semantics — rendering never blocks on event volume.

use routeloom_tui::model::{EventInfo, EventLog, State, EVENT_CAP};

fn events_json(count: usize, first_seq: u64) -> String {
    let mut out = String::from("{\"events\":[");
    for index in 0..count {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"seq\":{},\"ms\":1,\"kind\":\"keepalive\"}}",
            first_seq + index as u64
        ));
    }
    out.push_str(&format!(
        "],\"dropped\":0,\"next_seq\":{}}}",
        first_seq + count as u64
    ));
    out
}

#[test]
fn flooded_event_ring_stays_bounded() {
    let mut state = State::new("/tmp/x.sock");
    // Three daemon floods of 200 events each: 600 total, cap is 256.
    state.apply("EVENTS", &events_json(200, 0)).unwrap();
    state.apply("EVENTS", &events_json(200, 200)).unwrap();
    state.apply("EVENTS", &events_json(200, 400)).unwrap();
    assert_eq!(state.events.len(), EVENT_CAP);
    assert_eq!(state.events.local_dropped, 600 - EVENT_CAP as u64);
    // Drop-oldest: the retained window is the newest events.
    let oldest = state.events.iter().next().unwrap();
    assert_eq!(oldest.seq, 600 - EVENT_CAP as u64);
    let newest = state.events.iter().last().unwrap();
    assert_eq!(newest.seq, 599);
}

#[test]
fn raw_log_cap_is_enforced() {
    let mut log = EventLog::with_cap(8);
    for seq in 0..1000_u64 {
        log.push(EventInfo {
            seq,
            ms: seq,
            kind: "k".into(),
            detail: String::new(),
        });
    }
    assert_eq!(log.len(), 8);
    assert_eq!(log.local_dropped, 992);
}

#[test]
fn render_does_not_block_on_event_volume() {
    use routeloom_tui::render::{render, Tab};
    let mut state = State::new("/tmp/x.sock");
    state.apply("EVENTS", &events_json(10_000, 0)).unwrap();
    assert_eq!(state.events.len(), EVENT_CAP);
    let frame = render(&state, Tab::Events, 100, 30, 2_000);
    // Height is bounded: header + separator + footer + at most height lines.
    assert!(frame.lines().count() <= 30);
    assert!(frame.contains("dropped: daemon=0 local=9744"));
}
