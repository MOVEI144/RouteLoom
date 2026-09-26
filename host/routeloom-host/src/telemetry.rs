//! On-demand RF telemetry lane (HostOps 0x30/0x31): API1
//! `diagnostics.snapshot` submits one TelemetryQuery per call, the lane
//! thread issues it on the outbound queue, and the API waiter renders the
//! 0x31 answer — snapshot, mesh refusal, or device result — verbatim.
//! Queries never queue across a session change: a pending query whose USB
//! session died resolves SessionLost instead of matching a new
//! incarnation's replies.

use routeloom_protocol::host_ops::{ConfigOpsResult, CAP_HOST_OPS_V1};
use routeloom_protocol::telemetry::{
    decode_diagnostic_reject, decode_diagnostic_reply, decode_telemetry_snapshot,
    encode_diagnostic_request, TelemetryQuery, CAP_M1_DIAGNOSTICS_V1, DIAG_PREFIX_SIZE,
    DIAG_SUB_DIAGNOSTIC_REJECT, DIAG_SUB_TELEMETRY_SNAPSHOT, REJECT_BODY_SIZE, SNAPSHOT_BODY_SIZE,
    SOURCE_INJECTED_TEST, SOURCE_LOCAL_DRIVER, STALE, SUB_DIAGNOSTIC_RESPONSE, VALID_BUCKET,
    VALID_DRIVER_EWMA, VALID_HOP_RTT_EWMA, VALID_RSSI, WINDOW_INCOMPLETE,
};
use routeloom_protocol::{Frame, FrameKind};
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::{mono_ms, Outbound, State};

/// Request ids for this lane live in their own high range ("TL") so an
/// Error frame echoing one can be routed back here and can never alias a
/// DataToMesh, dispatcher, node-status or group request.
const REQUEST_BASE: u64 = 0x544C_0000_0000_0000;
const REQUEST_MASK: u64 = 0xFFFF_0000_0000_0000;

/// Queries in flight at once (submitted, sent or not, outcome untaken);
/// beyond this the API answers NO_CAPACITY instead of queueing blindly.
pub const MAX_IN_FLIGHT: usize = 4;
/// Device query lifetime (5000 ms) plus USB margin; the API waiter holds
/// a slightly longer budget so the lane always resolves first.
pub const QUERY_TIMEOUT_MS: u64 = 5_500;
pub const API_WAIT_MS: u64 = 6_000;
/// A resolved-but-untaken outcome (its waiter already left) is reaped
/// after this long so abandoned queries cannot pin table slots.
const SETTLE_GRACE_MS: u64 = API_WAIT_MS;
const TICK_MS: u64 = 50;

/// True for the HostOps bodies this lane owns (0x31 replies; 0x30 is
/// host→device and never arrives from a well-behaved device).
pub fn owns(inner: &[u8]) -> bool {
    routeloom_protocol::telemetry::diagnostic_sub(inner) == Some(SUB_DIAGNOSTIC_RESPONSE)
}

/// True when an Error frame's request id is one this lane minted.
pub fn owns_request(request: u64) -> bool {
    request & REQUEST_MASK == REQUEST_BASE
}

/// The family rides the HostOps carrier: both bits must be advertised.
pub fn telemetry_capable(capability: u32) -> bool {
    capability & CAP_M1_DIAGNOSTICS_V1 != 0 && capability & CAP_HOST_OPS_V1 != 0
}

/// One API1 `diagnostics.snapshot` call, validated by the method layer.
#[derive(Clone, Copy, Debug)]
pub struct TelemetryQueryParams {
    pub observer: u64,
    pub peer: u64,
    pub direction: u8,
    pub length_class: u8,
    pub max_age_ms: u32,
}

/// Terminal state of one query: the 0x31 answer decoded, or the reason no
/// answer arrived. Every variant renders honestly — a refusal is data,
/// never mapped onto a snapshot-shaped null.
#[derive(Debug)]
pub enum QueryOutcome {
    Snapshot(routeloom_protocol::telemetry::TelemetrySnapshot),
    Reject(routeloom_protocol::telemetry::DiagnosticReject),
    Device(ConfigOpsResult),
    DecodeError(String),
    Timeout,
    SessionLost,
    ErrorFrame(u16),
}

#[derive(Debug)]
struct PendingQuery {
    token: u64,
    session: u64,
    request: u64,
    params: TelemetryQueryParams,
    submitted_ms: u64,
    sent: bool,
    outcome: Option<QueryOutcome>,
    settled_ms: Option<u64>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubmitError {
    NoCapacity,
}

/// Bounded table of in-flight telemetry queries. The API layer submits
/// and waits; the lane thread sends, expires and reaps; the USB read
/// thread posts replies. All three meet only here.
#[derive(Default)]
pub struct TelemetryOps {
    ops: Mutex<HashMap<u64, PendingQuery>>,
    next: Mutex<u64>,
    change: Condvar,
}

impl TelemetryOps {
    fn mint(&self) -> (u64, u64) {
        let mut next = self.next.lock().expect("telemetry ops poisoned");
        *next = next.wrapping_add(1);
        let token = if *next == 0 { 1 } else { *next };
        *next = token;
        (token, REQUEST_BASE | (token & !REQUEST_MASK))
    }

    pub fn submit(
        &self,
        params: TelemetryQueryParams,
        session: u64,
        now_ms: u64,
    ) -> Result<u64, SubmitError> {
        let mut ops = self.ops.lock().expect("telemetry ops poisoned");
        if ops.len() >= MAX_IN_FLIGHT {
            return Err(SubmitError::NoCapacity);
        }
        let (token, request) = self.mint();
        ops.insert(
            token,
            PendingQuery {
                token,
                session,
                request,
                params,
                submitted_ms: now_ms,
                sent: false,
                outcome: None,
                settled_ms: None,
            },
        );
        drop(ops);
        self.change.notify_all();
        Ok(token)
    }

    /// Takes a completed outcome (removing the query); None while pending
    /// or for an unknown/reaped token. Production waits via `wait_for`;
    /// tests drive the lane step by step and poll.
    #[cfg(test)]
    pub fn poll(&self, token: u64) -> Option<QueryOutcome> {
        let mut ops = self.ops.lock().expect("telemetry ops poisoned");
        let done = ops.get(&token).is_some_and(|op| op.outcome.is_some());
        if !done {
            return None;
        }
        ops.remove(&token).and_then(|op| op.outcome)
    }

    /// Bounded wait for `poll` to resolve. A timeout here only abandons
    /// the waiter — the lane still resolves and reaps the query.
    pub fn wait_for(&self, token: u64, wait: Duration) -> Option<QueryOutcome> {
        let deadline = Instant::now() + wait;
        let mut ops = self.ops.lock().expect("telemetry ops poisoned");
        loop {
            let done = ops.get(&token).is_some_and(|op| op.outcome.is_some());
            if done {
                return ops.remove(&token).and_then(|op| op.outcome);
            }
            if !ops.contains_key(&token) {
                return None;
            }
            let now = Instant::now();
            if now >= deadline {
                return None;
            }
            ops = self
                .change
                .wait_timeout(ops, deadline - now)
                .expect("telemetry ops poisoned")
                .0;
        }
    }

    pub fn pending(&self) -> usize {
        self.ops.lock().expect("telemetry ops poisoned").len()
    }

    #[cfg(test)]
    pub fn tokens(&self) -> Vec<u64> {
        self.ops
            .lock()
            .expect("telemetry ops poisoned")
            .keys()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub fn request_for(&self, token: u64) -> Option<u64> {
        self.ops
            .lock()
            .expect("telemetry ops poisoned")
            .get(&token)
            .map(|op| op.request)
    }

    #[cfg(test)]
    pub fn submitted_ms_for(&self, token: u64) -> Option<u64> {
        self.ops
            .lock()
            .expect("telemetry ops poisoned")
            .get(&token)
            .map(|op| op.submitted_ms)
    }

    fn resolve(&self, request: u64, session: u64, outcome: QueryOutcome, now_ms: u64) -> bool {
        let mut ops = self.ops.lock().expect("telemetry ops poisoned");
        let Some(op) = ops
            .values_mut()
            .find(|op| op.request == request && op.session == session)
        else {
            return false;
        };
        if op.outcome.is_none() {
            op.outcome = Some(outcome);
            op.settled_ms = Some(now_ms);
        }
        drop(ops);
        self.change.notify_all();
        true
    }

    /// Posted by the USB read thread; never blocks it. Decodes eagerly —
    /// parsing is cheap and keeps the lane state machine to one shape
    /// (pending vs resolved). Unknown requests are stale/foreign replies
    /// (a late answer past our timeout): ignored, never an event.
    pub fn post_reply(&self, request: u64, session: u64, body: Vec<u8>) -> bool {
        let mut ops = self.ops.lock().expect("telemetry ops poisoned");
        let Some(op) = ops
            .values_mut()
            .find(|op| op.request == request && op.session == session)
        else {
            return false;
        };
        if op.outcome.is_none() {
            let outcome = match decode_diagnostic_reply(&body) {
                Ok(reply) if reply.observer != op.params.observer => {
                    QueryOutcome::DecodeError("reply observer does not match query".to_string())
                }
                Ok(reply) if reply.result == ConfigOpsResult::Ok => {
                    match decode_reply_body(&reply.body) {
                        QueryOutcome::Snapshot(snapshot)
                            if snapshot.request_id != query_id_for(op.token)
                                || snapshot.observer != op.params.observer
                                || snapshot.peer != op.params.peer
                                || snapshot.direction != op.params.direction
                                || snapshot.length_class != op.params.length_class =>
                        {
                            QueryOutcome::DecodeError("snapshot does not match query".to_string())
                        }
                        QueryOutcome::Reject(reject)
                            if reject.request_id != query_id_for(op.token)
                                || reject.observer != op.params.observer =>
                        {
                            QueryOutcome::DecodeError("reject does not match query".to_string())
                        }
                        outcome => outcome,
                    }
                }
                Ok(reply) => QueryOutcome::Device(reply.result),
                Err(error) => QueryOutcome::DecodeError(error.to_string()),
            };
            op.outcome = Some(outcome);
            op.settled_ms = Some(mono_ms());
        }
        drop(ops);
        self.change.notify_all();
        true
    }

    /// Posted by the USB read thread for an Error frame echoing our
    /// request id (a malformed 0x30 would land here — a daemon bug made
    /// visible, never a silent timeout).
    pub fn post_error(&self, request: u64, session: u64, code: u16) -> bool {
        self.resolve(request, session, QueryOutcome::ErrorFrame(code), mono_ms())
    }
}

fn decode_reply_body(body: &[u8]) -> QueryOutcome {
    if body.len() < DIAG_PREFIX_SIZE {
        return QueryOutcome::DecodeError("reply body too short".to_string());
    }
    match body[1] {
        DIAG_SUB_TELEMETRY_SNAPSHOT if body.len() == SNAPSHOT_BODY_SIZE => {
            match decode_telemetry_snapshot(body) {
                Ok(snapshot) => QueryOutcome::Snapshot(snapshot),
                Err(error) => QueryOutcome::DecodeError(error.to_string()),
            }
        }
        DIAG_SUB_DIAGNOSTIC_REJECT if body.len() == REJECT_BODY_SIZE => {
            match decode_diagnostic_reject(body) {
                Ok(reject) => QueryOutcome::Reject(reject),
                Err(error) => QueryOutcome::DecodeError(error.to_string()),
            }
        }
        _ => QueryOutcome::DecodeError(format!(
            "unexpected reply body: sub {} len {}",
            body[1],
            body.len()
        )),
    }
}

/// One lane step: resolve session losses and timeouts, issue unsent
/// queries, reap abandoned outcomes. Pure driver — the caller owns the
/// outbound queue and the clock.
pub fn telemetry_once(state: &State, outbound: &mpsc::SyncSender<Outbound>, now_ms: u64) {
    let live = {
        let info = state.session.lock().expect("session poisoned");
        if info.authenticated {
            info.id
        } else {
            None
        }
    };
    let mut send: Vec<(u64, Vec<u8>)> = Vec::new();
    {
        let ops = &state.telemetry_ops;
        let mut table = ops.ops.lock().expect("telemetry ops poisoned");
        let mut reap: Vec<u64> = Vec::new();
        for op in table.values_mut() {
            if let Some(settled) = op.settled_ms {
                if now_ms.saturating_sub(settled) >= SETTLE_GRACE_MS {
                    reap.push(op.token);
                }
                continue;
            }
            if live != Some(op.session) {
                op.outcome = Some(QueryOutcome::SessionLost);
                op.settled_ms = Some(now_ms);
                continue;
            }
            if now_ms.saturating_sub(op.submitted_ms) >= QUERY_TIMEOUT_MS {
                op.outcome = Some(QueryOutcome::Timeout);
                op.settled_ms = Some(now_ms);
                continue;
            }
            if op.sent {
                continue;
            }
            let query = TelemetryQuery {
                request_id: query_id_for(op.token),
                peer: op.params.peer,
                direction: op.params.direction,
                length_class: op.params.length_class,
                max_age_ms: op.params.max_age_ms,
            };
            match encode_diagnostic_request(op.params.observer, &query) {
                Ok(body) => send.push((op.request, body)),
                Err(error) => {
                    op.outcome = Some(QueryOutcome::DecodeError(error.to_string()));
                    op.settled_ms = Some(now_ms);
                }
            }
        }
        for token in reap {
            table.remove(&token);
        }
    }
    let mut progressed = false;
    for (request, body) in send {
        let frame = Frame {
            kind: FrameKind::HostOps,
            flags: 0,
            session: 0,
            request,
            body,
        };
        // The writer queue refused the frame: provably never sent, so the
        // query stays unsent for the next tick (its timeout still bounds
        // the wait — a clogged queue resolves Timeout, honestly).
        if outbound.try_send(Outbound::Seal(frame)).is_ok() {
            let mut table = state
                .telemetry_ops
                .ops
                .lock()
                .expect("telemetry ops poisoned");
            if let Some(op) = table.values_mut().find(|op| op.request == request) {
                op.sent = true;
            }
            progressed = true;
        }
    }
    if progressed {
        state.telemetry_ops.change.notify_all();
    }
}

/// Nonzero u32 mesh correlation id derived from the op token (the frame
/// request id lives in the u64 lane range instead).
fn query_id_for(token: u64) -> u32 {
    let id = token as u32;
    if id == 0 {
        1
    } else {
        id
    }
}

/// The telemetry thread: runs for the daemon's lifetime; idle (no frames)
/// while no query is submitted.
pub fn telemetry_loop(state: Arc<State>, outbound: mpsc::SyncSender<Outbound>) {
    loop {
        telemetry_once(&state, &outbound, mono_ms());
        let ops = state
            .telemetry_ops
            .ops
            .lock()
            .expect("telemetry ops poisoned");
        let _ = state
            .telemetry_ops
            .change
            .wait_timeout(ops, Duration::from_millis(TICK_MS));
    }
}

/// Renders one snapshot exactly as received: measurement groups stay
/// readable-as-stale (the device fills them whenever the source has
/// them) while `validity` flags freshness. Only the EWMAs the device
/// zeroes-when-absent become null — never an inferred zero.
pub fn snapshot_json(snapshot: &routeloom_protocol::telemetry::TelemetrySnapshot) -> String {
    let validity = snapshot.validity;
    let bit = |mask: u8| validity & mask != 0;
    let source = if bit(SOURCE_LOCAL_DRIVER) {
        "local_driver"
    } else if bit(SOURCE_INJECTED_TEST) {
        "injected_test"
    } else {
        "unknown"
    };
    let ewma = |present: bool, value: u32| {
        if present {
            value.to_string()
        } else {
            "null".to_string()
        }
    };
    let saturated = saturation_names(snapshot.saturation_mask);
    format!(
        "{{\"request_id\":{},\"observer\":\"{:016x}\",\"observer_boot\":{},\"peer\":\"{:016x}\",\"binding\":{},\"radio\":{},\"channel_epoch\":{},\"channel\":{},\"direction\":\"{}\",\"length_class\":{},\"validity\":{{\"rssi\":{},\"bucket\":{},\"driver_ewma\":{},\"hop_rtt_ewma\":{},\"source\":\"{source}\",\"window_incomplete\":{},\"stale\":{},\"validity_bits\":{}}},\"sampled_at_ms\":{},\"window_ms\":{},\"sample_age_ms\":{},\"rssi\":{{\"last_dbm\":{},\"min_dbm\":{},\"max_dbm\":{},\"ewma_q8_8\":{},\"samples\":{}}},\"tx\":{{\"submitted\":{},\"mac_success\":{},\"mac_fail\":{},\"unknown\":{}}},\"sdk_retries\":{},\"hop\":{{\"accepts\":{},\"timeouts\":{}}},\"busy\":{},\"queue_us_ewma\":{},\"driver_us_ewma\":{},\"hop_rtt_us_ewma\":{},\"event_drops\":{},\"saturated\":[{}],\"saturation_mask\":{}}}",
        snapshot.request_id,
        snapshot.observer,
        snapshot.observer_boot,
        snapshot.peer,
        snapshot.binding,
        snapshot.radio,
        snapshot.channel_epoch,
        snapshot.channel,
        if snapshot.direction == 0 { "egress" } else { "ingress" },
        snapshot.length_class,
        bit(VALID_RSSI),
        bit(VALID_BUCKET),
        bit(VALID_DRIVER_EWMA),
        bit(VALID_HOP_RTT_EWMA),
        bit(WINDOW_INCOMPLETE),
        bit(STALE),
        validity,
        snapshot.sampled_at_ms,
        snapshot.window_ms,
        snapshot.sample_age_ms,
        snapshot.rssi_last,
        snapshot.rssi_min,
        snapshot.rssi_max,
        snapshot.rssi_ewma_q8_8,
        snapshot.rssi_samples,
        snapshot.tx_submitted,
        snapshot.tx_mac_success,
        snapshot.tx_mac_fail,
        snapshot.tx_unknown,
        snapshot.sdk_retries,
        snapshot.hop_accepts,
        snapshot.hop_timeouts,
        snapshot.busy,
        if snapshot.queue_us_ewma == 0 {
            "null".to_string()
        } else {
            snapshot.queue_us_ewma.to_string()
        },
        ewma(bit(VALID_DRIVER_EWMA), snapshot.driver_us_ewma),
        ewma(bit(VALID_HOP_RTT_EWMA), snapshot.hop_rtt_us_ewma),
        snapshot.event_drops,
        saturated,
        snapshot.saturation_mask,
    )
}

fn saturation_names(mask: u32) -> String {
    // Bit order follows the snapshot field order (telemetry.hpp).
    const NAMES: &[&str] = &[
        "rssi_samples",
        "tx_submitted",
        "tx_mac_success",
        "tx_mac_fail",
        "tx_unknown",
        "sdk_retries",
        "hop_accepts",
        "hop_timeouts",
        "busy",
        "event_drops",
        "time_ewma",
    ];
    let mut names = Vec::new();
    for (index, name) in NAMES.iter().enumerate() {
        if mask & (1 << index) != 0 {
            names.push(format!("\"{name}\""));
        }
    }
    names.join(",")
}

pub fn reject_json(reject: &routeloom_protocol::telemetry::DiagnosticReject) -> String {
    format!(
        "{{\"reason\":\"{}\",\"observer\":\"{:016x}\",\"request_id\":{},\"detail\":{}}}",
        reject.reason.name(),
        reject.observer,
        reject.request_id,
        reject.detail,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_protocol::host_ops::ConfigOpsResult;
    use routeloom_protocol::telemetry::{
        decode_diagnostic_reject, decode_telemetry_snapshot, DIRECTION_EGRESS,
        LENGTH_CLASS_PEER_SUMMARY, SUB_DIAGNOSTIC_RESPONSE,
    };
    use std::sync::mpsc;
    use std::time::Duration;

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    // C++-encoded oracle bodies (components/routeloom/src/telemetry.cpp).
    const SNAPSHOT_HEX: &str = "010400000000004d00000000000000c300000000deadbeef00000000000000050000000700000003000000010b00011300000000075bcd15000007d000000028c9b0ce00c40000000000000c00000064000000600000000300000001000000040000005f0000000200000001000004d20000162e000023340000000200000200";
    const REJECT_HEX: &str = "010600000000002a00040000000000000000009900000000";

    fn reply_inner(result: u16, observer: u64, body: &[u8]) -> Vec<u8> {
        let mut inner = vec![0x01, SUB_DIAGNOSTIC_RESPONSE];
        inner.extend_from_slice(&((12 + body.len()) as u16).to_be_bytes());
        inner.extend_from_slice(&result.to_be_bytes());
        inner.extend_from_slice(&observer.to_be_bytes());
        inner.extend_from_slice(&(body.len() as u16).to_be_bytes());
        inner.extend_from_slice(body);
        inner
    }

    fn params() -> TelemetryQueryParams {
        TelemetryQueryParams {
            observer: 0x0abc,
            peer: 0x05,
            direction: DIRECTION_EGRESS,
            length_class: LENGTH_CLASS_PEER_SUMMARY,
            max_age_ms: 0,
        }
    }

    fn matching_snapshot(token: u64) -> Vec<u8> {
        let mut body = hex(SNAPSHOT_HEX);
        body[4..8].copy_from_slice(&query_id_for(token).to_be_bytes());
        body[8..16].copy_from_slice(&params().observer.to_be_bytes());
        body[24..32].copy_from_slice(&params().peer.to_be_bytes());
        body[45] = params().direction;
        body[46] = params().length_class;
        body
    }

    fn matching_reject(token: u64) -> Vec<u8> {
        let mut body = hex(REJECT_HEX);
        body[4..8].copy_from_slice(&query_id_for(token).to_be_bytes());
        body[12..20].copy_from_slice(&params().observer.to_be_bytes());
        body
    }

    fn live_state(session: u64) -> State {
        let state = State::default();
        let mut info = state.session.lock().expect("session poisoned");
        info.authenticated = true;
        info.id = Some(session);
        info.node = Some(0x0abc);
        info.capability = Some(0xFFFFFFFF);
        drop(info);
        state
    }

    #[test]
    fn submit_rejects_when_table_full() {
        let ops = TelemetryOps::default();
        for _ in 0..MAX_IN_FLIGHT {
            ops.submit(params(), 0x5e55, 1_000).unwrap();
        }
        assert_eq!(ops.pending(), MAX_IN_FLIGHT);
        assert!(matches!(
            ops.submit(params(), 0x5e55, 1_000),
            Err(SubmitError::NoCapacity)
        ));
    }

    #[test]
    fn reply_resolves_waiter_with_snapshot() {
        let ops = TelemetryOps::default();
        let token = ops.submit(params(), 0x5e55, 1_000).unwrap();
        let request = ops.request_for(token).unwrap();
        assert!(owns_request(request));
        let body = reply_inner(0, 0x0abc, &matching_snapshot(token));
        assert!(owns(&body));
        assert!(ops.post_reply(request, 0x5e55, body));
        // A reply for an unknown request is a stale/foreign answer: ignored.
        assert!(!ops.post_reply(request ^ 0xFFFF, 0x5e55, vec![0x01, 0x31, 0, 0]));
        let outcome = ops.wait_for(token, Duration::from_millis(100)).unwrap();
        match outcome {
            QueryOutcome::Snapshot(snapshot) => {
                assert_eq!(snapshot.peer, 0x05);
                assert_eq!(snapshot.sample_age_ms, 40);
            }
            other => panic!("expected snapshot, got {other:?}"),
        }
        // Taken outcomes leave the table.
        assert_eq!(ops.pending(), 0);
    }

    #[test]
    fn settled_reply_survives_the_api_wait_budget() {
        let state = live_state(0x5e55);
        let (tx, _rx) = mpsc::sync_channel(8);
        let token = state
            .telemetry_ops
            .submit(params(), 0x5e55, mono_ms())
            .unwrap();
        let request = state.telemetry_ops.request_for(token).unwrap();
        assert!(state.telemetry_ops.post_reply(
            request,
            0x5e55,
            reply_inner(0, 0x0abc, &matching_snapshot(token))
        ));
        telemetry_once(&state, &tx, mono_ms() + API_WAIT_MS - 1);
        assert!(matches!(
            state
                .telemetry_ops
                .wait_for(token, Duration::from_millis(1)),
            Some(QueryOutcome::Snapshot(_))
        ));
    }

    #[test]
    fn reply_from_a_new_usb_session_cannot_resolve_an_old_query() {
        let state = live_state(0x5e55);
        let token = state
            .telemetry_ops
            .submit(params(), 0x5e55, mono_ms())
            .unwrap();
        let request = state.telemetry_ops.request_for(token).unwrap();
        state.session.lock().unwrap().id = Some(0x6000);
        assert!(!state.telemetry_ops.post_reply(
            request,
            0x6000,
            reply_inner(0, 0x0abc, &matching_snapshot(token)),
        ));
    }

    #[test]
    fn reply_must_match_the_requested_observer_peer_and_query() {
        for field in [
            "outer_observer",
            "query_id",
            "observer",
            "peer",
            "direction",
            "class",
        ] {
            let ops = TelemetryOps::default();
            let token = ops.submit(params(), 0x5e55, 1_000).unwrap();
            let request = ops.request_for(token).unwrap();
            let mut body = matching_snapshot(token);
            let outer = if field == "outer_observer" {
                0xc3
            } else {
                0x0abc
            };
            match field {
                "query_id" => body[7] ^= 1,
                "observer" => body[15] ^= 1,
                "peer" => body[31] ^= 1,
                "direction" => body[45] ^= 1,
                "class" => body[46] = 2,
                _ => {}
            }
            assert!(ops.post_reply(request, 0x5e55, reply_inner(0, outer, &body)));
            assert!(
                matches!(
                    ops.wait_for(token, Duration::from_millis(100)),
                    Some(QueryOutcome::DecodeError(_))
                ),
                "accepted wrong {field}"
            );
        }
        for field in ["query_id", "observer"] {
            let ops = TelemetryOps::default();
            let token = ops.submit(params(), 0x5e55, 1_000).unwrap();
            let request = ops.request_for(token).unwrap();
            let mut body = matching_reject(token);
            if field == "query_id" {
                body[7] ^= 1;
            } else {
                body[19] ^= 1;
            }
            assert!(ops.post_reply(request, 0x5e55, reply_inner(0, 0x0abc, &body)));
            assert!(
                matches!(
                    ops.wait_for(token, Duration::from_millis(100)),
                    Some(QueryOutcome::DecodeError(_))
                ),
                "accepted wrong reject {field}"
            );
        }
    }

    #[test]
    fn reject_and_device_results_resolve_verbatim() {
        let ops = TelemetryOps::default();
        let token = ops.submit(params(), 0x5e55, 1_000).unwrap();
        let request = ops.request_for(token).unwrap();
        assert!(ops.post_reply(
            request,
            0x5e55,
            reply_inner(0, 0x0abc, &matching_reject(token))
        ));
        match ops.wait_for(token, Duration::from_millis(100)).unwrap() {
            QueryOutcome::Reject(reject) => assert_eq!(reject.reason.name(), "NO_PEER"),
            other => panic!("expected reject, got {other:?}"),
        }
        let token = ops.submit(params(), 0x5e55, 1_000).unwrap();
        let request = ops.request_for(token).unwrap();
        assert!(ops.post_reply(request, 0x5e55, reply_inner(1, 0x0abc, &[])));
        match ops.wait_for(token, Duration::from_millis(100)).unwrap() {
            QueryOutcome::Device(ConfigOpsResult::Busy) => {}
            other => panic!("expected device busy, got {other:?}"),
        }
        // Garbage from the device is a decode error, never a snapshot.
        let token = ops.submit(params(), 0x5e55, 1_000).unwrap();
        let request = ops.request_for(token).unwrap();
        assert!(ops.post_reply(request, 0x5e55, reply_inner(0, 0x0abc, &[0x01, 0x04])));
        match ops.wait_for(token, Duration::from_millis(100)).unwrap() {
            QueryOutcome::DecodeError(_) => {}
            other => panic!("expected decode error, got {other:?}"),
        }
        // An Error frame echoing our request resolves as an error.
        let token = ops.submit(params(), 0x5e55, 1_000).unwrap();
        let request = ops.request_for(token).unwrap();
        assert!(ops.post_error(request, 0x5e55, 3));
        assert!(!ops.post_error(request ^ 0xFFFF, 0x5e55, 3));
        match ops.wait_for(token, Duration::from_millis(100)).unwrap() {
            QueryOutcome::ErrorFrame(3) => {}
            other => panic!("expected error frame, got {other:?}"),
        }
    }

    #[test]
    fn lane_sends_times_out_and_drops_session_lost() {
        let state = live_state(0x5e55);
        let (tx, rx) = mpsc::sync_channel(8);
        let token = state.telemetry_ops.submit(params(), 0x5e55, 1_000).unwrap();
        telemetry_once(&state, &tx, 1_000);
        let frame = rx.try_recv().unwrap();
        match frame {
            Outbound::Seal(frame) => {
                assert_eq!(frame.kind, routeloom_protocol::FrameKind::HostOps);
                assert!(owns_request(frame.request));
                assert_eq!(&frame.body[0..2], &[0x01, 0x30]);
            }
            Outbound::Raw(_) => panic!("telemetry requests are sealed"),
        }
        // No reply: the query times out on its own deadline.
        assert!(state.telemetry_ops.poll(token).is_none());
        telemetry_once(&state, &tx, 1_000 + QUERY_TIMEOUT_MS);
        match state.telemetry_ops.poll(token).unwrap() {
            QueryOutcome::Timeout => {}
            other => panic!("expected timeout, got {other:?}"),
        }
        // A session change loses pending queries instead of answering
        // them from a new incarnation's replies.
        let token = state.telemetry_ops.submit(params(), 0x5e55, 2_000).unwrap();
        {
            let mut info = state.session.lock().expect("session poisoned");
            info.id = Some(0x6000);
        }
        telemetry_once(&state, &tx, 2_000);
        match state.telemetry_ops.poll(token).unwrap() {
            QueryOutcome::SessionLost => {}
            other => panic!("expected session lost, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_json_gates_validity_and_names_source() {
        let snapshot = decode_telemetry_snapshot(&hex(SNAPSHOT_HEX)).unwrap();
        let json = snapshot_json(&snapshot);
        assert!(json.contains("\"peer\":\"0000000000000005\""), "{json}");
        assert!(json.contains("\"observer\":\"00000000000000c3\""), "{json}");
        assert!(json.contains("\"sample_age_ms\":40"), "{json}");
        assert!(json.contains("\"rssi\":{\"last_dbm\":-55"), "{json}");
        assert!(json.contains("\"source\":\"local_driver\""), "{json}");
        assert!(json.contains("\"stale\":false"), "{json}");
        // Bits clear: measurement groups stay readable-as-stale (the
        // device fills them whenever the source has them) while the
        // validity object flags the staleness. Only the EWMAs the device
        // zeroes-when-absent become null.
        let mut bare = snapshot;
        bare.validity = 0;
        bare.driver_us_ewma = 0;
        bare.hop_rtt_us_ewma = 0;
        bare.queue_us_ewma = 0;
        let json = snapshot_json(&bare);
        assert!(json.contains("\"rssi\":{\"last_dbm\":-55"), "{json}");
        assert!(json.contains("\"tx\":{\"submitted\":100"), "{json}");
        assert!(json.contains("\"driver_us_ewma\":null"), "{json}");
        assert!(json.contains("\"hop_rtt_us_ewma\":null"), "{json}");
        assert!(json.contains("\"queue_us_ewma\":null"), "{json}");
        assert!(json.contains("\"validity_bits\":0"), "{json}");
        assert!(json.contains("\"rssi\":false"), "{json}");
        let reject = decode_diagnostic_reject(&hex(REJECT_HEX)).unwrap();
        let json = reject_json(&reject);
        assert!(json.contains("\"reason\":\"NO_PEER\""), "{json}");
        assert!(json.contains("\"observer\":\"0000000000000099\""), "{json}");
    }
}
