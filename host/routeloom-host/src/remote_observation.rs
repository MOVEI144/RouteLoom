//! Remote observation lane (Diagnostic 0x30/0x31 subtype 7/8): API1
//! `health.get` / `topology.get` with a foreign observer submit one
//! RemoteObservationQuery per call, the lane thread issues it on the
//! outbound queue, and the API waiter renders the 0x31 answer —
//! snapshot, mesh refusal, or device result — verbatim. The section
//! bytes are the 0x71 page bodies, so both legs decode with one codec.
//!
//! Radio discipline: telemetry and this lane share one daemon RF slot
//! and a two-second interval; concurrent identical calls join the in-flight row
//! (singleflight) instead of doubling the radio; and recent mesh
//! failures are served from a bounded negative cache instead of
//! re-querying. Every answer reports its radio cost (`radio_queries`)
//! so callers see the load, never just the sample.
//!
//! Queries never queue across a session change: a pending query whose
//! USB session died resolves SessionLost instead of matching a new
//! incarnation's replies. Like telemetry, the inner mesh correlation id
//! is minted by the bridge — never matched here; the USB request id
//! binds a reply to its row.

use routeloom_protocol::host_ops::ConfigOpsResult;
use routeloom_protocol::observation::{
    decode_remote_observation_snapshot, encode_remote_observation_query, RemoteObservationQuery,
    RemoteObservationSnapshot, REMOTE_QUERY_EXACT,
};
use routeloom_protocol::telemetry::{
    decode_diagnostic_reject, decode_diagnostic_reply, encode_diagnostic_request_raw,
    DiagnosticReject, RejectReason, DIAG_SUB_DIAGNOSTIC_REJECT,
    DIAG_SUB_REMOTE_OBSERVATION_SNAPSHOT, REJECT_BODY_SIZE,
};
use routeloom_protocol::{Frame, FrameKind};
use std::collections::HashMap;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use crate::{mono_ms, Outbound, State};

/// Request ids for this lane live in their own high range ("RO") so a
/// 0x31 reply or Error frame echoing one routes back here and can never
/// alias a telemetry, observation, node-status, group or data request.
const REQUEST_BASE: u64 = 0x524F_0000_0000_0000;
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
/// Transient mesh refusals are briefly cached; unsupported peers and
/// timeouts need a longer probe interval to bound repeated RF work.
const NEG_TTL_MS: u64 = 5_000;
const UNSUPPORTED_NEG_TTL_MS: u64 = 60_000;
/// Negative cache rows; the oldest-victim eviction keeps it bounded.
const NEG_MAX: usize = 16;

/// True when a 0x31 reply's (or Error frame's) request id is one this
/// lane minted. The body sub alone cannot demux 0x31: telemetry and
/// remote observation share it.
pub fn owns_request(request: u64) -> bool {
    request & REQUEST_MASK == REQUEST_BASE
}

/// One API1 remote observation call, validated by the method layer.
#[derive(Clone, Copy, Debug)]
pub struct RemoteObservationParams {
    pub observer: u64,
    pub section: u8,
    pub max_entries: u8,
    pub exact: bool,
    pub after: u64,
}

/// Terminal state of one query: the 0x31 answer decoded, or the reason
/// no answer arrived. Every variant renders honestly — a refusal is
/// data, never mapped onto a snapshot-shaped null.
#[derive(Clone, Debug)]
pub enum QueryOutcome {
    Snapshot(RemoteObservationSnapshot),
    Reject(DiagnosticReject),
    Device(ConfigOpsResult),
    DecodeError(String),
    Timeout,
    SessionLost,
    ErrorFrame(u16),
}

/// One resolved row handed to a waiter: the outcome plus the envelope
/// readings. `sent` tells whether the row rode the radio — the caller
/// multiplies by its own `fresh` for the marginal cost of ITS call (a
/// singleflight join reports 0: the leader's radio is not its own).
#[derive(Clone, Debug)]
pub struct RemoteAnswer {
    pub outcome: QueryOutcome,
    pub received_ms: u64,
    pub received_mono_ms: u64,
    pub rtt_ms: u64,
    pub sent: bool,
}

#[derive(Debug)]
struct PendingQuery {
    token: u64,
    session: u64,
    request: u64,
    params: RemoteObservationParams,
    submitted_ms: u64,
    sent: bool,
    outcome: Option<QueryOutcome>,
    received_ms: u64,
    received_mono_ms: u64,
    settled_ms: Option<u64>,
}

/// Negative-cache key: the exact question the mesh already refused.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct NegKey {
    session: u64,
    observer: u64,
    section: u8,
    after: u64,
    exact: bool,
}

#[derive(Clone, Debug)]
enum NegOutcome {
    Reject(DiagnosticReject),
    Timeout,
}

#[derive(Clone, Debug)]
struct NegEntry {
    outcome: NegOutcome,
    until_ms: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SubmitError {
    NoCapacity,
}

/// What `submit` hands back: a live row to wait on (fresh when this
/// call created the radio work, joined when it shares an in-flight
/// row), or a cached mesh failure that cost no radio.
#[derive(Debug)]
pub enum SubmitOutcome {
    Live { token: u64, fresh: bool },
    Cached(QueryOutcome),
}

/// Bounded table of in-flight remote queries plus the negative cache.
/// The API layer submits and waits; the lane thread sends, expires and
/// reaps; the USB read thread posts replies. All three meet only here.
#[derive(Default)]
pub struct RemoteObservationOps {
    ops: Mutex<HashMap<u64, PendingQuery>>,
    next: Mutex<u64>,
    neg: Mutex<HashMap<NegKey, NegEntry>>,
    change: Condvar,
}

impl RemoteObservationOps {
    pub fn request_pending(&self, request: u64) -> bool {
        self.ops
            .lock()
            .expect("remote observation ops poisoned")
            .values()
            .any(|op| op.request == request && op.outcome.is_none())
    }
    pub fn request_pending_in_session(&self, request: u64, session: u64) -> bool {
        self.ops
            .lock()
            .expect("remote observation ops poisoned")
            .values()
            .any(|op| op.request == request && op.session == session && op.outcome.is_none())
    }
    fn mint(&self) -> (u64, u64) {
        let mut next = self.next.lock().expect("remote observation ops poisoned");
        *next = next.wrapping_add(1);
        let token = if *next == 0 { 1 } else { *next };
        *next = token;
        (token, REQUEST_BASE | (token & !REQUEST_MASK))
    }

    fn neg_key(params: &RemoteObservationParams, session: u64) -> NegKey {
        NegKey {
            session,
            observer: params.observer,
            section: params.section,
            after: params.after,
            exact: params.exact,
        }
    }

    fn neg_lookup(&self, key: &NegKey, now_ms: u64) -> Option<QueryOutcome> {
        let mut neg = self.neg.lock().expect("remote observation ops poisoned");
        neg.retain(|_, entry| entry.until_ms > now_ms);
        neg.get(key).map(|entry| match &entry.outcome {
            NegOutcome::Reject(reject) => QueryOutcome::Reject(*reject),
            NegOutcome::Timeout => QueryOutcome::Timeout,
        })
    }

    fn neg_record(&self, key: NegKey, outcome: NegOutcome, now_ms: u64) {
        let mut neg = self.neg.lock().expect("remote observation ops poisoned");
        neg.retain(|_, entry| entry.until_ms > now_ms);
        let ttl_ms = match &outcome {
            NegOutcome::Timeout => UNSUPPORTED_NEG_TTL_MS,
            NegOutcome::Reject(reject) if reject.reason == RejectReason::Unsupported => {
                UNSUPPORTED_NEG_TTL_MS
            }
            NegOutcome::Reject(_) => NEG_TTL_MS,
        };
        if neg.len() >= NEG_MAX && !neg.contains_key(&key) {
            // Bounded victim: drop an arbitrary row (all rows are fresh
            // here — a wrong victim only costs one re-query).
            if let Some(victim) = neg.keys().next().copied() {
                neg.remove(&victim);
            }
        }
        neg.insert(
            key,
            NegEntry {
                outcome,
                until_ms: now_ms.saturating_add(ttl_ms),
            },
        );
    }

    pub fn submit(
        &self,
        params: RemoteObservationParams,
        session: u64,
        now_ms: u64,
    ) -> Result<SubmitOutcome, SubmitError> {
        // A failure the mesh just gave us is served without touching the
        // radio — and without consuming an in-flight slot.
        if let Some(cached) = self.neg_lookup(&Self::neg_key(&params, session), now_ms) {
            return Ok(SubmitOutcome::Cached(cached));
        }
        let mut ops = self.ops.lock().expect("remote observation ops poisoned");
        // Singleflight: an identical unresolved row on the live session
        // is shared — the second caller waits on the first call's radio.
        if let Some(op) = ops.values().find(|op| {
            op.session == session
                && op.outcome.is_none()
                && op.params.observer == params.observer
                && op.params.section == params.section
                && op.params.after == params.after
                && op.params.exact == params.exact
        }) {
            return Ok(SubmitOutcome::Live {
                token: op.token,
                fresh: false,
            });
        }
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
                received_ms: 0,
                received_mono_ms: 0,
                settled_ms: None,
            },
        );
        drop(ops);
        self.change.notify_all();
        Ok(SubmitOutcome::Live { token, fresh: true })
    }

    fn answer_of(op: &PendingQuery) -> Option<RemoteAnswer> {
        op.outcome.clone().map(|outcome| RemoteAnswer {
            outcome,
            received_ms: op.received_ms,
            received_mono_ms: op.received_mono_ms,
            rtt_ms: op.received_mono_ms.saturating_sub(op.submitted_ms),
            sent: op.sent,
        })
    }

    /// Reads a completed outcome (cloned — singleflight waiters share
    /// the row); None while pending or for an unknown/reaped token.
    /// Production waits via `wait_for`; tests drive the lane step by
    /// step and poll; rows are reaped by the lane.
    #[cfg(test)]
    pub fn poll(&self, token: u64) -> Option<RemoteAnswer> {
        let ops = self.ops.lock().expect("remote observation ops poisoned");
        ops.get(&token).and_then(Self::answer_of)
    }

    /// Bounded wait for `poll` to resolve. A timeout here only abandons
    /// the waiter — the lane still resolves and reaps the query.
    pub fn wait_for(&self, token: u64, wait: Duration) -> Option<RemoteAnswer> {
        let deadline = Instant::now() + wait;
        let mut ops = self.ops.lock().expect("remote observation ops poisoned");
        loop {
            if let Some(answer) = ops.get(&token).and_then(Self::answer_of) {
                return Some(answer);
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
                .expect("remote observation ops poisoned")
                .0;
        }
    }

    pub fn pending(&self) -> usize {
        self.ops
            .lock()
            .expect("remote observation ops poisoned")
            .values()
            .filter(|op| op.outcome.is_none())
            .count()
    }

    #[cfg(test)]
    pub fn tokens(&self) -> Vec<u64> {
        self.ops
            .lock()
            .expect("remote observation ops poisoned")
            .keys()
            .copied()
            .collect()
    }

    #[cfg(test)]
    pub fn request_for(&self, token: u64) -> Option<u64> {
        self.ops
            .lock()
            .expect("remote observation ops poisoned")
            .get(&token)
            .map(|op| op.request)
    }

    fn resolve(
        &self,
        request: u64,
        session: u64,
        outcome: QueryOutcome,
        received_ms: u64,
        received_mono_ms: u64,
    ) -> bool {
        let mut ops = self.ops.lock().expect("remote observation ops poisoned");
        let Some(op) = ops
            .values_mut()
            .find(|op| op.request == request && op.session == session)
        else {
            return false;
        };
        if op.outcome.is_none() {
            op.outcome = Some(outcome);
            op.received_ms = received_ms;
            op.received_mono_ms = received_mono_ms;
            op.settled_ms = Some(received_mono_ms);
        }
        drop(ops);
        self.change.notify_all();
        true
    }

    /// Posted by the USB read thread; never blocks it. Decodes eagerly —
    /// parsing is cheap and keeps the lane state machine to one shape
    /// (pending vs resolved). Unknown requests are stale/foreign replies
    /// (a late answer past our timeout): ignored, never an event.
    ///
    /// The inner mesh correlation id is NOT matched: the bridge mints its
    /// own for the mesh leg and relays the body verbatim, so the USB
    /// request id (plus observer/section agreement) is the binding.
    pub fn post_reply(
        &self,
        request: u64,
        session: u64,
        body: Vec<u8>,
        received_ms: u64,
        received_mono_ms: u64,
    ) -> bool {
        let mut ops = self.ops.lock().expect("remote observation ops poisoned");
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
                            if snapshot.observer != op.params.observer
                                || snapshot.section != op.params.section =>
                        {
                            QueryOutcome::DecodeError("snapshot does not match query".to_string())
                        }
                        QueryOutcome::Reject(reject) if reject.observer != op.params.observer => {
                            QueryOutcome::DecodeError("reject does not match query".to_string())
                        }
                        outcome => outcome,
                    }
                }
                Ok(reply) => QueryOutcome::Device(reply.result),
                Err(error) => QueryOutcome::DecodeError(error.to_string()),
            };
            // A mesh refusal is negative-cacheable evidence; device and
            // decode failures are not (they name the gateway or the
            // daemon, never the observer's state).
            let neg = match &outcome {
                QueryOutcome::Reject(reject) => Some(NegOutcome::Reject(*reject)),
                _ => None,
            };
            op.outcome = Some(outcome);
            op.received_ms = received_ms;
            op.received_mono_ms = received_mono_ms;
            op.settled_ms = Some(received_mono_ms);
            let key = Self::neg_key(&op.params, op.session);
            drop(ops);
            if let Some(neg) = neg {
                self.neg_record(key, neg, received_mono_ms);
            }
            self.change.notify_all();
            return true;
        }
        drop(ops);
        self.change.notify_all();
        true
    }

    /// Posted by the USB read thread for an Error frame echoing our
    /// request id (a malformed 0x30 would land here — a daemon bug made
    /// visible, never a silent timeout).
    pub fn post_error(&self, request: u64, session: u64, code: u16) -> bool {
        let now = mono_ms();
        self.resolve(request, session, QueryOutcome::ErrorFrame(code), now, now)
    }
}

fn decode_reply_body(body: &[u8]) -> QueryOutcome {
    if body.len() < 4 {
        return QueryOutcome::DecodeError("reply body too short".to_string());
    }
    match body[1] {
        DIAG_SUB_REMOTE_OBSERVATION_SNAPSHOT => match decode_remote_observation_snapshot(body) {
            Ok(snapshot) => QueryOutcome::Snapshot(snapshot),
            Err(error) => QueryOutcome::DecodeError(error.to_string()),
        },
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
pub fn remote_observation_once(state: &State, outbound: &mpsc::SyncSender<Outbound>, now_ms: u64) {
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
        let ops = &state.remote_observation_ops;
        let mut table = ops.ops.lock().expect("remote observation ops poisoned");
        let mut reap: Vec<u64> = Vec::new();
        let mut timeouts: Vec<NegKey> = Vec::new();
        for op in table.values_mut() {
            if let Some(settled) = op.settled_ms {
                if now_ms.saturating_sub(settled) >= SETTLE_GRACE_MS {
                    reap.push(op.token);
                }
                continue;
            }
            if live != Some(op.session) {
                op.outcome = Some(QueryOutcome::SessionLost);
                op.received_ms = now_ms;
                op.received_mono_ms = now_ms;
                op.settled_ms = Some(now_ms);
                continue;
            }
            if now_ms.saturating_sub(op.submitted_ms) >= QUERY_TIMEOUT_MS {
                op.outcome = Some(QueryOutcome::Timeout);
                op.received_ms = now_ms;
                op.received_mono_ms = now_ms;
                op.settled_ms = Some(now_ms);
                timeouts.push(RemoteObservationOps::neg_key(&op.params, op.session));
                continue;
            }
            if op.sent {
                continue;
            }
            let query = RemoteObservationQuery {
                request_id: query_id_for(op.token),
                section: op.params.section,
                max_entries: op.params.max_entries,
                flags: if op.params.exact {
                    REMOTE_QUERY_EXACT
                } else {
                    0
                },
                after: op.params.after,
            };
            match encode_remote_observation_query(&query)
                .ok()
                .and_then(|query_body| {
                    encode_diagnostic_request_raw(op.params.observer, &query_body).ok()
                }) {
                Some(body) => send.push((op.request, body)),
                None => {
                    op.outcome = Some(QueryOutcome::DecodeError(
                        "remote query failed to encode".to_string(),
                    ));
                    op.received_ms = now_ms;
                    op.received_mono_ms = now_ms;
                    op.settled_ms = Some(now_ms);
                }
            }
        }
        for token in reap {
            table.remove(&token);
        }
        drop(table);
        for key in timeouts {
            ops.neg_record(key, NegOutcome::Timeout, now_ms);
        }
    }
    let mut progressed = false;
    state.refresh_radio_budget();
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
        if state.radio_budget.send(request, now_ms, || {
            outbound.try_send(Outbound::Seal(frame)).is_ok()
        }) {
            let mut table = state
                .remote_observation_ops
                .ops
                .lock()
                .expect("remote observation ops poisoned");
            if let Some(op) = table.values_mut().find(|op| op.request == request) {
                op.sent = true;
            }
            progressed = true;
        } else {
            break;
        }
    }
    if progressed {
        state.remote_observation_ops.change.notify_all();
    }
}

/// Nonzero u32 mesh correlation id derived from the op token (the frame
/// request id lives in the u64 lane range instead). The bridge replaces
/// it with its own for the mesh leg — echoed back verbatim, never
/// matched here.
fn query_id_for(token: u64) -> u32 {
    let id = token as u32;
    if id == 0 {
        1
    } else {
        id
    }
}

/// The remote observation thread: runs for the daemon's lifetime; idle
/// (no frames) while no query is submitted.
pub fn remote_observation_loop(state: Arc<State>, outbound: mpsc::SyncSender<Outbound>) {
    loop {
        remote_observation_once(&state, &outbound, mono_ms());
        let ops = state
            .remote_observation_ops
            .ops
            .lock()
            .expect("remote observation ops poisoned");
        let _ = state
            .remote_observation_ops
            .change
            .wait_timeout(ops, Duration::from_millis(TICK_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_protocol::observation::SECTION_NEIGHBORS;
    use routeloom_protocol::telemetry::SUB_DIAGNOSTIC_RESPONSE;

    #[test]
    fn telemetry_and_observation_share_one_radio_budget() {
        let state = State::default();
        {
            let mut session = state.session.lock().unwrap();
            session.authenticated = true;
            session.id = Some(0x5e55);
        }
        let (tx, rx) = mpsc::sync_channel(4);
        state
            .telemetry_ops
            .submit(
                crate::telemetry::TelemetryQueryParams {
                    observer: 0x0abc,
                    peer: 2,
                    direction: 0,
                    length_class: 0,
                    max_age_ms: 0,
                },
                0x5e55,
                1_000,
            )
            .unwrap();
        state
            .remote_observation_ops
            .submit(
                RemoteObservationParams {
                    observer: 0x0abc,
                    section: SECTION_NEIGHBORS,
                    max_entries: 3,
                    exact: false,
                    after: 0,
                },
                0x5e55,
                1_000,
            )
            .unwrap();
        crate::telemetry::telemetry_once(&state, &tx, 1_000);
        remote_observation_once(&state, &tx, 1_000);
        let first = rx.try_recv().unwrap();
        assert!(
            rx.try_recv().is_err(),
            "only one RF transaction may be outstanding"
        );
        let Outbound::Seal(first) = first else {
            panic!("diagnostic requests are sealed")
        };
        assert!(state.telemetry_ops.post_error(first.request, 0x5e55, 1));
        remote_observation_once(&state, &tx, 2_999);
        assert!(rx.try_recv().is_err(), "the shared interval is two seconds");
        remote_observation_once(&state, &tx, 3_000);
        assert!(rx.try_recv().is_ok());
    }

    fn hex(text: &str) -> Vec<u8> {
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect()
    }

    // C++-encoded oracle bodies (components/routeloom/src/telemetry.cpp).
    // The snapshot's inner request id (0x01020304) deliberately differs
    // from any lane-minted id: the bridge mints its own for the mesh leg
    // and the lane must NOT match on it.
    const SNAPSHOT_HEX: &str = "01080000010203040000000000000abc112233445566778805010100a5a5a5a500000000000003e800000000000000020000007800013880000100000607b900";
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

    fn params() -> RemoteObservationParams {
        RemoteObservationParams {
            observer: 0x0abc,
            section: SECTION_NEIGHBORS,
            max_entries: 3,
            exact: false,
            after: 0,
        }
    }

    fn matching_snapshot() -> Vec<u8> {
        hex(SNAPSHOT_HEX)
    }

    fn matching_reject() -> Vec<u8> {
        let mut body = hex(REJECT_HEX);
        body[12..20].copy_from_slice(&params().observer.to_be_bytes());
        body
    }

    #[test]
    fn unsupported_observer_is_not_reprobed_within_a_minute() {
        let ops = RemoteObservationOps::default();
        let token = live_token(&ops);
        let request = ops.request_for(token).unwrap();
        let mut reject = matching_reject();
        reject[8..10].copy_from_slice(&1u16.to_be_bytes());
        assert!(ops.post_reply(
            request,
            0x5e55,
            reply_inner(0, params().observer, &reject),
            2_000,
            2_000
        ));
        assert!(matches!(
            ops.submit(params(), 0x5e55, 31_000),
            Ok(SubmitOutcome::Cached(_))
        ));
        assert!(matches!(
            ops.submit(params(), 0x5e55, 62_001),
            Ok(SubmitOutcome::Live { fresh: true, .. })
        ));
    }

    fn live_token(ops: &RemoteObservationOps) -> u64 {
        match ops.submit(params(), 0x5e55, 1_000).unwrap() {
            SubmitOutcome::Live { token, fresh } => {
                assert!(fresh);
                token
            }
            SubmitOutcome::Cached(_) => panic!("expected a live row"),
        }
    }

    #[test]
    fn request_range_does_not_alias_other_lanes() {
        let ops = RemoteObservationOps::default();
        let token = live_token(&ops);
        let request = ops.request_for(token).unwrap();
        assert!(owns_request(request));
        assert!(!owns_request(0x544C_0000_0000_0001));
        assert!(!owns_request(0x4F42_0000_0000_0001));
        assert!(!owns_request(request ^ 0xFFFF_0000_0000_0000));
    }

    #[test]
    fn submit_rejects_when_table_full() {
        let ops = RemoteObservationOps::default();
        for cursor in 0..MAX_IN_FLIGHT as u64 {
            // Distinct cursors are distinct questions (no singleflight).
            let mut distinct = params();
            distinct.after = cursor + 1;
            assert!(matches!(
                ops.submit(distinct, 0x5e55, 1_000).unwrap(),
                SubmitOutcome::Live { fresh: true, .. }
            ));
        }
        let mut overflow = params();
        overflow.after = 0xFFFF;
        assert!(matches!(
            ops.submit(overflow, 0x5e55, 1_000),
            Err(SubmitError::NoCapacity)
        ));
    }

    #[test]
    fn identical_submit_joins_the_in_flight_row() {
        let ops = RemoteObservationOps::default();
        let first = live_token(&ops);
        match ops.submit(params(), 0x5e55, 1_100).unwrap() {
            SubmitOutcome::Live { token, fresh } => {
                assert_eq!(token, first);
                assert!(!fresh);
            }
            SubmitOutcome::Cached(_) => panic!("expected a singleflight join"),
        }
        // One row, two waiters: both read the same cloned outcome.
        assert_eq!(ops.tokens().len(), 1);
        let request = ops.request_for(first).unwrap();
        assert!(ops.post_reply(
            request,
            0x5e55,
            reply_inner(0, 0x0abc, &matching_snapshot()),
            2_000,
            2_000
        ));
        let one = ops.poll(first).unwrap();
        let two = ops.poll(first).unwrap();
        // No lane ran, so the row never sent — sharing is what matters.
        assert!(!one.sent);
        assert!(matches!(one.outcome, QueryOutcome::Snapshot(_)));
        assert!(matches!(two.outcome, QueryOutcome::Snapshot(_)));
    }

    #[test]
    fn reply_resolves_waiter_without_matching_inner_id() {
        let ops = RemoteObservationOps::default();
        let token = live_token(&ops);
        let request = ops.request_for(token).unwrap();
        let body = reply_inner(0, 0x0abc, &matching_snapshot());
        assert!(ops.post_reply(request, 0x5e55, body, 2_000, 2_100));
        // A reply for an unknown request is a stale/foreign answer: ignored.
        assert!(!ops.post_reply(
            request ^ 0xFFFF,
            0x5e55,
            vec![0x01, 0x31, 0, 0],
            2_000,
            2_100
        ));
        let answer = ops.wait_for(token, Duration::from_millis(100)).unwrap();
        match answer.outcome {
            QueryOutcome::Snapshot(snapshot) => {
                assert_eq!(snapshot.observer, 0x0abc);
                assert_eq!(snapshot.section, SECTION_NEIGHBORS);
                assert_eq!(snapshot.count, 1);
            }
            other => panic!("expected snapshot, got {other:?}"),
        }
        assert_eq!(
            (answer.received_ms, answer.received_mono_ms),
            (2_000, 2_100)
        );
        assert_eq!(answer.rtt_ms, 1_100);
    }

    #[test]
    fn mismatched_observer_or_section_is_decode_error() {
        let ops = RemoteObservationOps::default();
        let token = live_token(&ops);
        let request = ops.request_for(token).unwrap();
        // Wrong 0x31 envelope observer.
        assert!(ops.post_reply(
            request,
            0x5e55,
            reply_inner(0, 0x0abd, &matching_snapshot()),
            2_000,
            2_000
        ));
        assert!(matches!(
            ops.poll(token).unwrap().outcome,
            QueryOutcome::DecodeError(_)
        ));
        // Wrong section inside an otherwise valid snapshot.
        let mut other = params();
        other.after = 7;
        let token = match ops.submit(other, 0x5e55, 1_000).unwrap() {
            SubmitOutcome::Live { token, .. } => token,
            SubmitOutcome::Cached(_) => panic!("expected a live row"),
        };
        let request = ops.request_for(token).unwrap();
        let mut body = matching_snapshot();
        body[24] = routeloom_protocol::observation::SECTION_ROUTES;
        assert!(ops.post_reply(request, 0x5e55, reply_inner(0, 0x0abc, &body), 2_000, 2_000));
        assert!(matches!(
            ops.poll(token).unwrap().outcome,
            QueryOutcome::DecodeError(_)
        ));
    }

    #[test]
    fn mesh_reject_is_served_from_negative_cache() {
        let ops = RemoteObservationOps::default();
        let token = live_token(&ops);
        let request = ops.request_for(token).unwrap();
        assert!(ops.post_reply(
            request,
            0x5e55,
            reply_inner(0, 0x0abc, &matching_reject()),
            2_000,
            2_000
        ));
        assert!(matches!(
            ops.poll(token).unwrap().outcome,
            QueryOutcome::Reject(_)
        ));
        // The same question inside the TTL is a cached failure: no radio,
        // no new row.
        let rows = ops.tokens().len();
        match ops
            .submit(params(), 0x5e55, 2_000 + NEG_TTL_MS - 1)
            .unwrap()
        {
            SubmitOutcome::Cached(QueryOutcome::Reject(reject)) => {
                assert_eq!(reject.observer, 0x0abc);
            }
            other => panic!("expected a cached reject, got {other:?}"),
        }
        assert_eq!(ops.tokens().len(), rows);
        assert!(
            matches!(
                ops.submit(params(), 0x5e56, 2_001).unwrap(),
                SubmitOutcome::Live { fresh: true, .. }
            ),
            "a refusal from an old USB session cannot answer a new one"
        );
        // Past the TTL the mesh is asked again.
        assert!(matches!(
            ops.submit(params(), 0x5e55, 2_000 + NEG_TTL_MS + 1)
                .unwrap(),
            SubmitOutcome::Live { fresh: true, .. }
        ));
    }

    #[test]
    fn pump_sends_the_unsent_query_on_the_lane_range() {
        let state = State::default();
        {
            let mut info = state.session.lock().expect("session poisoned");
            info.authenticated = true;
            info.id = Some(0x5e55);
            info.node = Some(0x01);
            info.capability = Some(0xFFFF_FFFF);
        }
        let (tx, rx) = mpsc::sync_channel(8);
        let token = match state
            .remote_observation_ops
            .submit(params(), 0x5e55, 1_000)
            .unwrap()
        {
            SubmitOutcome::Live { token, .. } => token,
            SubmitOutcome::Cached(_) => panic!("expected a live row"),
        };
        remote_observation_once(&state, &tx, 1_010);
        let frame = match rx.try_recv().unwrap() {
            Outbound::Seal(frame) => frame,
            Outbound::Raw(_) => panic!("expected a sealed frame"),
        };
        assert!(owns_request(frame.request));
        assert_eq!(frame.kind, FrameKind::HostOps);
        // 0x30 inner: schema, sub, len, observer, then the subtype-7 body.
        assert_eq!(&frame.body[0..4], &[0x01, 0x30, 0x00, 0x20]);
        assert_eq!(&frame.body[4..12], &0x0abc_u64.to_be_bytes());
        assert_eq!(&frame.body[12..16], &[0x01, 0x07, 0x00, 0x00]);
        // Still pending (no reply yet) but marked sent.
        assert!(state.remote_observation_ops.poll(token).is_none());
        // A second pump sends nothing new.
        remote_observation_once(&state, &tx, 1_020);
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn timeout_is_negatively_cached_by_the_pump() {
        let state = State::default();
        {
            let mut info = state.session.lock().expect("session poisoned");
            info.authenticated = true;
            info.id = Some(0x5e55);
            info.node = Some(0x01);
            info.capability = Some(0xFFFF_FFFF);
        }
        let (tx, _rx) = mpsc::sync_channel(8);
        let token = match state
            .remote_observation_ops
            .submit(params(), 0x5e55, 1_000)
            .unwrap()
        {
            SubmitOutcome::Live { token, .. } => token,
            SubmitOutcome::Cached(_) => panic!("expected a live row"),
        };
        remote_observation_once(&state, &tx, 1_000 + QUERY_TIMEOUT_MS);
        assert!(matches!(
            state.remote_observation_ops.poll(token).unwrap().outcome,
            QueryOutcome::Timeout
        ));
        // Same question: the timeout is served cached, without radio.
        assert!(matches!(
            state
                .remote_observation_ops
                .submit(params(), 0x5e55, 1_000 + QUERY_TIMEOUT_MS)
                .unwrap(),
            SubmitOutcome::Cached(QueryOutcome::Timeout)
        ));
    }
}
