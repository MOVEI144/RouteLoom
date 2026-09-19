#[cfg(not(unix))]
compile_error!("routeloom-host v0.1 currently requires a Unix platform");

use routeloom_protocol::dev_session::{
    derive_session_proof, open_body, seal_body, SessionProof, Transcript, DIRECTION_DEVICE_TO_HOST,
    DIRECTION_HOST_TO_DEVICE, FLAG_AUTH, PROTECTED_BODY_OVERHEAD,
};
use routeloom_protocol::{encode_frame, CumulativeCredit, Frame, FrameKind, StreamDecoder};
use std::collections::VecDeque;
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// Bounded observation buffers. The daemon keeps only what it legitimately
/// observes on the USB stream; mesh truth it cannot see stays `unknown`.
const MAX_EVENTS: usize = 256;
const MAX_DELIVERIES: usize = 512;
const MAX_NODES: usize = 256;
const MAX_OUTBOUND: usize = 64;
/// Concurrent control-socket clients. Each connection owns a thread and a
/// BufReader — bound the count so a connection storm cannot exhaust fd/memory.
const MAX_CLIENTS: usize = 16;

/// Decoded (pre-COBS) frame overhead charged against cumulative credit:
/// header + CRC, matching the device-side accounting.
const WIRE_HEADER_SIZE: usize = 26;
const WIRE_CRC_SIZE: usize = 4;
/// Cumulative grant the daemon extends to the device for its sends
/// (DataFromMesh/DeliveryEvent/Diagnostic); topped up on CREDIT_QUERY.
const DEVICE_TX_GRANT_FRAMES: u64 = 16;
const DEVICE_TX_GRANT_BYTES: u64 = 65_536;
/// Development session secret — EXPERIMENTAL profile only, never production
/// (docs/spec/security.md).
const DEV_SECRET: &[u8] = b"routeloom-dev-secret";
const DEV_PRINCIPAL: &[u8] = b"routeloom-host";
/// Idle interval between session keepalives.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// After AUTH every session frame body is `counter || tag || inner`
/// (dev_session.rs). The daemon owns the host role of the dev-session
/// handshake and opens inbound bodies before parsing the inner layouts used
/// by the device bridge (components/routeloom/src/usb_bridge.cpp).
const DIAG_FLAG_HAS_MESSAGE: u8 = 0x01;
const CREDIT_GRANT: u8 = 0;
const CREDIT_QUERY: u8 = 1;
const CREDIT_CLOSE: u8 = 2;

#[derive(Default)]
struct SessionInfo {
    authenticated: bool,
    id: Option<u64>,
    node: Option<u64>,
    boot: Option<u64>,
    network: Option<u64>,
    capability: Option<u32>,
    version: Option<u8>,
}

#[derive(Default)]
struct CreditInfo {
    /// True once at least one Credit grant frame has been observed. Until
    /// then the grant values are meaningless and must be shown as unknown.
    observed: bool,
    grant_frames: u64,
    grant_bytes: u64,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SessionPhase {
    Disconnected,
    AwaitHelloAck,
    AwaitAuthOk,
    Active,
}

/// One frame the adapter writer must emit. Everything flows through the
/// single writer thread so session-counter assignment and wire order can
/// never diverge: `Seal` items are protected (counter || tag || inner) at
/// write time, `Raw` items go out unprotected by design (Hello/AUTH).
enum Outbound {
    Raw(Frame),
    Seal(Frame),
}

/// Result of feeding one inbound wire frame to the session layer.
#[derive(Default)]
struct SessionInbound {
    /// Verified inner body for record_frame (None when the session layer
    /// consumed the frame: handshake step, replay, or malformed).
    inner: Option<Vec<u8>>,
    /// Frames to emit through the writer queue (AUTH, grants, re-hellos).
    /// Produced unsealed: the writer assigns the session counter.
    outbound: Vec<Outbound>,
    /// `"kind":...` JSON field fragments for the event log.
    notes: Vec<String>,
    /// Device identity learned from HelloAck (version,node,boot,network,capability).
    hello_info: Option<(u8, u64, u64, u64, u32)>,
    /// Session id once AUTH completes.
    auth_session: Option<u64>,
}

/// Host-side dev-session state machine; the protocol/usb-golden vectors are
/// the byte-level reference. Hello/HelloAck bodies are unprotected; every
/// other kind inside an active session is `counter || tag || inner`.
struct DeviceSession {
    phase: SessionPhase,
    secret: Vec<u8>,
    principal: Vec<u8>,
    host_nonce: u64,
    request_seq: u64,
    proof: Option<SessionProof>,
    session_id: u64,
    h2d_counter: u64,
    d2h_counter: u64,
    /// Cumulative device→host grant consumed per non-control frame we send.
    send_credit: CumulativeCredit,
    /// Cumulative grant we extend to the device for its sends.
    tx_grant_frames: u64,
    tx_grant_bytes: u64,
}

/// Control kinds ride the zero-credit reservation on the device side: they
/// are sealed and countered like everything else but do not consume the
/// data-credit budget.
fn is_control_kind(kind: FrameKind) -> bool {
    matches!(
        kind,
        FrameKind::Hello
            | FrameKind::HelloAck
            | FrameKind::Credit
            | FrameKind::KeepAlive
            | FrameKind::Error
    )
}

impl DeviceSession {
    fn new() -> Self {
        Self {
            phase: SessionPhase::Disconnected,
            secret: DEV_SECRET.to_vec(),
            principal: DEV_PRINCIPAL.to_vec(),
            host_nonce: 0,
            request_seq: 1,
            proof: None,
            session_id: 0,
            h2d_counter: 0,
            d2h_counter: 0,
            send_credit: CumulativeCredit::default(),
            tx_grant_frames: 0,
            tx_grant_bytes: 0,
        }
    }

    fn next_request(&mut self) -> u64 {
        let request = self.request_seq;
        self.request_seq += 1;
        request
    }

    /// Link lost: stop authenticating new outbound frames immediately. The
    /// next connect calls begin(), which resets all counters and keys.
    fn disconnect(&mut self) {
        self.phase = SessionPhase::Disconnected;
        self.proof = None;
    }

    /// Adapter (re)connected: reset all session state and produce the Hello.
    /// Nothing from the old session (counters, grants, requests) is reused.
    fn begin(&mut self) -> Frame {
        let secret = std::mem::take(&mut self.secret);
        let principal = std::mem::take(&mut self.principal);
        *self = Self::new();
        self.secret = secret;
        self.principal = principal;
        self.phase = SessionPhase::AwaitHelloAck;
        // Session nonce: uniqueness is what the transcript needs (replay
        // isolation), not secrecy — mix the monotonic clock with pid.
        self.host_nonce = now_ms() ^ (u64::from(std::process::id()) << 32);
        let mut body = Vec::with_capacity(12 + self.principal.len());
        body.extend_from_slice(&self.host_nonce.to_be_bytes());
        body.push(1); // min version
        body.push(1); // max version
        body.push(self.principal.len() as u8);
        body.extend_from_slice(&self.principal);
        Frame {
            kind: FrameKind::Hello,
            flags: 0,
            session: 0,
            request: self.next_request(),
            body,
        }
    }

    /// Seals `frame` for transmission inside the active session. Control
    /// kinds skip the data-credit charge but are still sealed and countered.
    fn protect(&mut self, frame: &mut Frame) -> Result<(), &'static str> {
        if self.phase != SessionPhase::Active {
            return Err("session not authenticated");
        }
        let key = match self.proof.as_ref() {
            Some(proof) => proof.key,
            None => return Err("session proof missing"),
        };
        let sealed_len = PROTECTED_BODY_OVERHEAD + frame.body.len();
        if !is_control_kind(frame.kind)
            && self
                .send_credit
                .consume(WIRE_HEADER_SIZE + sealed_len + WIRE_CRC_SIZE)
                .is_err()
        {
            return Err("device send credit exhausted");
        }
        frame.body = seal_body(
            &key,
            DIRECTION_HOST_TO_DEVICE,
            self.h2d_counter,
            frame.kind,
            frame.flags,
            frame.request,
            &frame.body,
        );
        self.h2d_counter += 1;
        frame.session = self.session_id;
        Ok(())
    }

    /// Credit grant for the device→host direction. Returned UNSEALED: the
    /// single writer thread seals it at write time so session counters are
    /// assigned in wire order.
    fn grant_frame(&mut self) -> Frame {
        let mut inner = Vec::with_capacity(17);
        inner.push(CREDIT_GRANT);
        inner.extend_from_slice(&self.tx_grant_frames.to_be_bytes());
        inner.extend_from_slice(&self.tx_grant_bytes.to_be_bytes());
        Frame {
            kind: FrameKind::Credit,
            flags: 0,
            session: 0,
            request: self.next_request(),
            body: inner,
        }
    }

    /// Process one inbound wire frame. Handshake frames are unprotected by
    /// definition; in Active every other kind must open against the session
    /// key — a body that fails authentication is never parsed as plaintext.
    fn handle(&mut self, frame: &Frame) -> SessionInbound {
        let mut result = SessionInbound::default();
        match self.phase {
            SessionPhase::Disconnected => {
                result.notes.push(
                    "\"kind\":\"session_drop\",\"reason\":\"frame before hello\"".to_string(),
                );
            }
            SessionPhase::AwaitHelloAck => {
                if frame.kind != FrameKind::HelloAck || frame.flags & FLAG_AUTH != 0 {
                    result.notes.push(
                        "\"kind\":\"session_drop\",\"reason\":\"expected hello_ack\"".to_string(),
                    );
                    return result;
                }
                let body = frame.body.as_slice();
                if body.len() < 8 + 1 + 8 + 8 + 8 + 4 + 16 {
                    result.notes.push(
                        "\"kind\":\"session_drop\",\"reason\":\"malformed hello_ack\"".to_string(),
                    );
                    return result;
                }
                let transcript = Transcript {
                    host_nonce: self.host_nonce,
                    device_nonce: u64::from_be_bytes(body[0..8].try_into().expect("nonce")),
                    version: body[8],
                    node: u64::from_be_bytes(body[9..17].try_into().expect("node")),
                    boot: u64::from_be_bytes(body[17..25].try_into().expect("boot")),
                    network: u64::from_be_bytes(body[25..33].try_into().expect("network")),
                    capability: u32::from_be_bytes(body[33..37].try_into().expect("capability")),
                    principal: self.principal.clone(),
                };
                let encoded = match transcript.encode() {
                    Ok(encoded) => encoded,
                    Err(_) => {
                        result.notes.push(
                            "\"kind\":\"session_drop\",\"reason\":\"principal too long\""
                                .to_string(),
                        );
                        return result;
                    }
                };
                let proof = derive_session_proof(&self.secret, &encoded);
                if body[37..53] != proof.hello_tag {
                    result.notes.push(
                        "\"kind\":\"session_drop\",\"reason\":\"HELLO_TAG_INVALID\"".to_string(),
                    );
                    // Restart the handshake: the device holding a dead
                    // half-session would otherwise never recover.
                    result.outbound.push(Outbound::Raw(self.begin()));
                    return result;
                }
                result.hello_info = Some((
                    transcript.version,
                    transcript.node,
                    transcript.boot,
                    transcript.network,
                    transcript.capability,
                ));
                result.notes.push(format!(
                    "\"kind\":\"hello_ack\",\"version\":{},\"node\":{},\"boot\":{},\"network\":{},\"capability\":{}",
                    transcript.version,
                    transcript.node,
                    transcript.boot,
                    transcript.network,
                    transcript.capability,
                ));
                let auth = Frame {
                    kind: FrameKind::Hello,
                    flags: FLAG_AUTH,
                    session: 0,
                    request: self.next_request(),
                    body: proof.auth_tag.to_vec(),
                };
                self.proof = Some(proof);
                self.phase = SessionPhase::AwaitAuthOk;
                result.outbound.push(Outbound::Raw(auth));
            }
            SessionPhase::AwaitAuthOk => {
                if frame.kind != FrameKind::HelloAck || frame.flags & FLAG_AUTH == 0 {
                    result.notes.push(
                        "\"kind\":\"session_drop\",\"reason\":\"expected auth_ok\"".to_string(),
                    );
                    return result;
                }
                let proof = match self.proof.as_ref() {
                    Some(proof) => proof.clone(),
                    None => return result,
                };
                if frame.body.len() != 16 + 8 || frame.body[..16] != proof.auth_ok_tag[..] {
                    result
                        .notes
                        .push("\"kind\":\"session_drop\",\"reason\":\"AUTH_REJECTED\"".to_string());
                    return result;
                }
                self.session_id =
                    u64::from_be_bytes(frame.body[16..24].try_into().expect("session id"));
                self.phase = SessionPhase::Active;
                self.send_credit = CumulativeCredit::new(self.session_id);
                self.tx_grant_frames = DEVICE_TX_GRANT_FRAMES;
                self.tx_grant_bytes = DEVICE_TX_GRANT_BYTES;
                result.outbound.push(Outbound::Seal(self.grant_frame()));
                result.auth_session = Some(self.session_id);
                result.notes.push(format!(
                    "\"kind\":\"auth_ok\",\"session\":{}",
                    self.session_id
                ));
            }
            SessionPhase::Active => {
                let key = match self.proof.as_ref() {
                    Some(proof) => proof.key,
                    None => {
                        self.phase = SessionPhase::Disconnected;
                        return result;
                    }
                };
                // frame_tag does not cover the session id — check it
                // explicitly so a stale-session frame is dropped before
                // the (also-failing) tag check.
                if frame.session != self.session_id {
                    result
                        .notes
                        .push("\"kind\":\"session_drop\",\"reason\":\"stale session\"".to_string());
                    return result;
                }
                match open_body(&key, DIRECTION_DEVICE_TO_HOST, frame) {
                    Ok((counter, inner)) => {
                        if counter < self.d2h_counter {
                            result.notes.push(
                                "\"kind\":\"session_drop\",\"reason\":\"replay\"".to_string(),
                            );
                            return result;
                        }
                        self.d2h_counter = counter + 1;
                        let inner = inner.to_vec();
                        if frame.kind == FrameKind::Credit {
                            match inner.first() {
                                Some(&CREDIT_GRANT) if inner.len() >= 17 => {
                                    let frames =
                                        u64::from_be_bytes(inner[1..9].try_into().expect("frames"));
                                    let bytes =
                                        u64::from_be_bytes(inner[9..17].try_into().expect("bytes"));
                                    let _ = self.send_credit.update(self.session_id, frames, bytes);
                                }
                                Some(&CREDIT_QUERY) => {
                                    // The query body is a single opcode byte:
                                    // device asks for more headroom, so
                                    // extend the cumulative grant.
                                    self.tx_grant_frames += DEVICE_TX_GRANT_FRAMES;
                                    self.tx_grant_bytes += DEVICE_TX_GRANT_BYTES;
                                    result.outbound.push(Outbound::Seal(self.grant_frame()));
                                }
                                _ => {}
                            }
                        }
                        // KeepAlive is never echoed from the host (the
                        // device already answers each inbound KeepAlive —
                        // usb_bridge.cpp — so a host echo would ping-pong
                        // forever) and never reaches the event ring: a
                        // liveness event every few seconds would flush it.
                        if frame.kind == FrameKind::KeepAlive {
                            return result;
                        }
                        // Session-fatal error codes (inner: code(2) ||
                        // request(8) || reason_len || reason): the device
                        // dropped our session or the counter stream
                        // desynced — restart the handshake instead of
                        // sending frames it will keep rejecting.
                        if frame.kind == FrameKind::Error && inner.len() >= 2 {
                            let code = u16::from_be_bytes([inner[0], inner[1]]);
                            if matches!(code, 2 | 3 | 4 | 11) {
                                result.inner = Some(inner);
                                result.outbound.push(Outbound::Raw(self.begin()));
                                return result;
                            }
                        }
                        result.inner = Some(inner);
                    }
                    Err(_) => {
                        // A body that fails authentication is dropped — never
                        // parsed as plaintext. Desync (e.g. device restart
                        // that kept the link) restarts the handshake.
                        result.notes.push(
                            "\"kind\":\"session_drop\",\"reason\":\"SESSION_TAG_INVALID\""
                                .to_string(),
                        );
                        result.outbound.push(Outbound::Raw(self.begin()));
                    }
                }
            }
        }
        result
    }
}

struct NodeObs {
    id: u64,
    /// "adapter" for the node identity reported in HelloAck, "peer" for
    /// origins/peers observed in mesh traffic or diagnostics.
    role: &'static str,
    seen_ms: u64,
}

struct Delivery {
    request: u64,
    destination: u64,
    /// Local states: "queued" (accepted for the adapter writer), "sent"
    /// (frame written to the device), "rejected" (never reached the device).
    /// DeliveryEvent frames overwrite this with mesh-side state names.
    state: String,
    reason: Option<String>,
    msg_session: Option<u64>,
    msg_seq: Option<u64>,
    updated_ms: u64,
}

/// One ring-buffer entry; `seq` lives inside `json` so clients can
/// deduplicate across polls.
struct Event {
    json: String,
}

#[derive(Default)]
struct State {
    device: Option<PathBuf>,
    connected: AtomicBool,
    rx_frames: AtomicU64,
    tx_frames: AtomicU64,
    tx_bytes: AtomicU64,
    protocol_errors: AtomicU64,
    last_error: Mutex<Option<String>>,
    session: Mutex<SessionInfo>,
    credit: Mutex<CreditInfo>,
    nodes: Mutex<Vec<NodeObs>>,
    deliveries: Mutex<VecDeque<Delivery>>,
    events: Mutex<VecDeque<Event>>,
    event_seq: AtomicU64,
    events_dropped: AtomicU64,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Escapes for JSON string contexts: quotes, backslashes and every C0
/// control character (which would otherwise produce invalid JSON — e.g. a
/// raw newline in a device-supplied reason string).
fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c < ' ' => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn json_opt_str(value: Option<&str>) -> String {
    value.map_or_else(|| "null".to_string(), |v| format!("\"{}\"", json_escape(v)))
}

fn json_opt_u64(value: Option<u64>) -> String {
    value.map_or_else(|| "null".to_string(), |v| v.to_string())
}

fn set_error(state: &State, message: String) {
    *state.last_error.lock().expect("last_error poisoned") = Some(message);
}

fn push_event(state: &State, ms: u64, fields: String) {
    // Allocate the sequence under the events lock: concurrent producers
    // otherwise interleave fetch_add and push_back so stored order diverges
    // from seq order.
    let mut events = state.events.lock().expect("events poisoned");
    let seq = state.event_seq.fetch_add(1, Ordering::Relaxed);
    let json = format!("{{\"seq\":{seq},\"ms\":{ms},{fields}}}");
    if events.len() >= MAX_EVENTS {
        events.pop_front();
        state.events_dropped.fetch_add(1, Ordering::Relaxed);
    }
    events.push_back(Event { json });
}

fn touch_node(state: &State, id: u64, role: &'static str, seen_ms: u64) {
    let mut nodes = state.nodes.lock().expect("nodes poisoned");
    if let Some(node) = nodes.iter_mut().find(|node| node.id == id) {
        node.seen_ms = seen_ms;
        if node.role != "adapter" && role == "adapter" {
            node.role = role;
        }
        return;
    }
    if nodes.len() >= MAX_NODES {
        nodes.remove(0);
    }
    nodes.push(NodeObs { id, role, seen_ms });
}

/// Optional fields a caller may attach to a delivery transition.
#[derive(Default)]
struct DeliveryPatch {
    destination: Option<u64>,
    reason: Option<String>,
    msg_session: Option<u64>,
    msg_seq: Option<u64>,
}

fn delivery_update(
    state: &State,
    request: u64,
    new_state: &str,
    patch: DeliveryPatch,
    updated_ms: u64,
) {
    let mut deliveries = state.deliveries.lock().expect("deliveries poisoned");
    if let Some(delivery) = deliveries.iter_mut().find(|d| d.request == request) {
        delivery.state = new_state.to_string();
        if patch.reason.is_some() {
            delivery.reason = patch.reason;
        }
        if patch.msg_session.is_some() {
            delivery.msg_session = patch.msg_session;
        }
        if patch.msg_seq.is_some() {
            delivery.msg_seq = patch.msg_seq;
        }
        delivery.updated_ms = updated_ms;
        return;
    }
    if deliveries.len() >= MAX_DELIVERIES {
        deliveries.pop_front();
    }
    deliveries.push_back(Delivery {
        request,
        destination: patch.destination.unwrap_or(0),
        state: new_state.to_string(),
        reason: patch.reason,
        msg_session: patch.msg_session,
        msg_seq: patch.msg_seq,
        updated_ms,
    });
}

fn u16_at(body: &[u8], offset: usize) -> Option<u16> {
    body.get(offset..offset + 2)
        .map(|b| u16::from_be_bytes([b[0], b[1]]))
}

fn u32_at(body: &[u8], offset: usize) -> Option<u32> {
    body.get(offset..offset + 4)
        .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn u64_at(body: &[u8], offset: usize) -> Option<u64> {
    body.get(offset..offset + 8)
        .map(|b| u64::from_be_bytes(b.try_into().expect("8 bytes")))
}

fn reason_at(body: &[u8], len_offset: usize) -> Option<String> {
    let len = usize::from(*body.get(len_offset)?);
    let bytes = body.get(len_offset + 1..len_offset + 1 + len)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

/// Mesh-side delivery state names mirror `DeliveryState` in
/// components/routeloom/include/routeloom/types.hpp.
fn delivery_state_name(value: u8) -> &'static str {
    match value {
        0 => "empty",
        1 => "accepted",
        2 => "waiting-for-route",
        3 => "queued",
        4 => "waiting-for-mac",
        5 => "waiting-for-hop-accept",
        6 => "waiting-for-end-receipt",
        7 => "delivered",
        8 => "failed",
        9 => "expired",
        10 => "cancelled-before-tx",
        11 => "indeterminate",
        _ => "unknown",
    }
}

fn usb_error_name(code: u16) -> &'static str {
    match code {
        1 => "protocol-error",
        2 => "auth-failed",
        3 => "replay-rejected",
        4 => "stale-session",
        5 => "credit-exhausted",
        6 => "conflict",
        7 => "unsupported",
        8 => "payload-too-large",
        9 => "draining",
        10 => "connection-stalled",
        11 => "not-authenticated",
        12 => "no-capacity",
        13 => "mesh-rejected",
        _ => "unknown",
    }
}

/// Interpret one decoded adapter frame: update session/credit/node/delivery
/// state and append a bounded event. Everything recorded here is observed
/// from the device stream — nothing is inferred.
/// Parses the verified session inner body (never the protected envelope:
/// unauthenticated bytes are dropped by the session layer before this).
fn record_frame(state: &State, frame: &Frame, inner: &[u8], ms: u64) {
    let body = inner;
    match frame.kind {
        // HelloAck bodies are consumed by the session layer (handshake),
        // which emits hello_ack/auth_ok events itself; an inner reaching
        // here would be a protocol anomaly worth noting, not parsing.
        FrameKind::HelloAck => {
            push_event(
                state,
                ms,
                format!("\"kind\":\"frame\",\"frame_kind\":{}", frame.kind as u8),
            );
        }
        FrameKind::DataFromMesh => {
            if body.len() >= 20 {
                let (origin, msg_session, msg_seq) =
                    (u64_at(body, 0), u32_at(body, 8), u64_at(body, 12));
                if let Some(origin) = origin {
                    touch_node(state, origin, "peer", ms);
                }
                push_event(
                    state,
                    ms,
                    format!(
                        "\"kind\":\"data_from_mesh\",\"origin\":{},\"msg_session\":{},\"msg_seq\":{},\"payload_len\":{}",
                        json_opt_u64(origin),
                        msg_session.map_or_else(|| "null".to_string(), |v| v.to_string()),
                        json_opt_u64(msg_seq),
                        body.len() - 20,
                    ),
                );
            } else {
                push_event(
                    state,
                    ms,
                    "\"kind\":\"data_from_mesh\",\"malformed\":true".to_string(),
                );
            }
        }
        FrameKind::DeliveryEvent => {
            if body.len() >= 22 {
                let request = u64_at(body, 0).unwrap_or(frame.request);
                let msg_session = u32_at(body, 8).map(u64::from);
                let msg_seq = u64_at(body, 12);
                let name = delivery_state_name(body[20]);
                let reason = reason_at(body, 21);
                delivery_update(
                    state,
                    request,
                    name,
                    DeliveryPatch {
                        reason: reason.clone(),
                        msg_session,
                        msg_seq,
                        ..DeliveryPatch::default()
                    },
                    ms,
                );
                push_event(
                    state,
                    ms,
                    format!(
                        "\"kind\":\"delivery_event\",\"request\":{request},\"state\":\"{name}\",\"msg_session\":{},\"msg_seq\":{},\"reason\":{}",
                        msg_session.map_or_else(|| "null".to_string(), |v| v.to_string()),
                        json_opt_u64(msg_seq),
                        json_opt_str(reason.as_deref()),
                    ),
                );
            } else {
                push_event(
                    state,
                    ms,
                    "\"kind\":\"delivery_event\",\"malformed\":true".to_string(),
                );
            }
        }
        FrameKind::Diagnostic => {
            if body.len() >= 10 {
                let peer = u64_at(body, 0);
                let flags = body[8];
                let (msg_session, msg_seq, reason_offset) = if flags & DIAG_FLAG_HAS_MESSAGE != 0 {
                    (u32_at(body, 9).map(u64::from), u64_at(body, 13), 21)
                } else {
                    (None, None, 9)
                };
                let reason = reason_at(body, reason_offset);
                if let Some(peer) = peer {
                    touch_node(state, peer, "peer", ms);
                }
                push_event(
                    state,
                    ms,
                    format!(
                        "\"kind\":\"diagnostic\",\"peer\":{},\"reason\":{},\"msg_session\":{},\"msg_seq\":{}",
                        json_opt_u64(peer),
                        json_opt_str(reason.as_deref()),
                        msg_session.map_or_else(|| "null".to_string(), |v| v.to_string()),
                        json_opt_u64(msg_seq),
                    ),
                );
            } else {
                push_event(
                    state,
                    ms,
                    "\"kind\":\"diagnostic\",\"malformed\":true".to_string(),
                );
            }
        }
        FrameKind::Error => {
            let code = u16_at(body, 0);
            let request = u64_at(body, 2);
            let reason = reason_at(body, 10);
            if let Some(request) = request {
                // Error requests share the session request space (credit,
                // auth, data): only transition a delivery we actually track —
                // never invent one.
                let tracked = state
                    .deliveries
                    .lock()
                    .expect("deliveries poisoned")
                    .iter()
                    .any(|d| d.request == request);
                if request != 0 && tracked {
                    delivery_update(
                        state,
                        request,
                        "failed",
                        DeliveryPatch {
                            reason: reason.clone(),
                            ..DeliveryPatch::default()
                        },
                        ms,
                    );
                }
            }
            if let Some(reason) = reason.as_ref() {
                set_error(state, reason.clone());
            }
            push_event(
                state,
                ms,
                format!(
                    "\"kind\":\"error\",\"code\":{},\"error\":\"{}\",\"request\":{},\"reason\":{}",
                    code.map_or_else(|| "null".to_string(), |v| v.to_string()),
                    code.map_or("unknown", usb_error_name),
                    json_opt_u64(request),
                    json_opt_str(reason.as_deref()),
                ),
            );
        }
        FrameKind::Credit => match body.first() {
            Some(&CREDIT_GRANT) if body.len() >= 17 => {
                let (frames, bytes) = (u64_at(body, 1), u64_at(body, 9));
                {
                    let mut credit = state.credit.lock().expect("credit poisoned");
                    credit.observed = true;
                    credit.grant_frames = frames.unwrap_or(0);
                    credit.grant_bytes = bytes.unwrap_or(0);
                }
                push_event(
                    state,
                    ms,
                    format!(
                        "\"kind\":\"credit_grant\",\"grant_frames\":{},\"grant_bytes\":{}",
                        json_opt_u64(frames),
                        json_opt_u64(bytes),
                    ),
                );
            }
            Some(&CREDIT_QUERY) => {
                push_event(state, ms, "\"kind\":\"credit_query\"".to_string());
            }
            Some(&CREDIT_CLOSE) => {
                push_event(state, ms, "\"kind\":\"credit_close\"".to_string());
            }
            _ => {
                push_event(
                    state,
                    ms,
                    "\"kind\":\"credit\",\"malformed\":true".to_string(),
                );
            }
        },
        FrameKind::KeepAlive => {
            push_event(state, ms, "\"kind\":\"keepalive\"".to_string());
        }
        // Hello/DataToMesh are host→device kinds; if they arrive from the
        // device we still record them as observed frames.
        FrameKind::Hello | FrameKind::DataToMesh => {
            push_event(
                state,
                ms,
                format!("\"kind\":\"frame\",\"frame_kind\":{}", frame.kind as u8),
            );
        }
    }
}

fn status_json(state: &State) -> String {
    let error = state
        .last_error
        .lock()
        .expect("last_error poisoned")
        .clone();
    format!(
        "{{\"connected\":{},\"device\":{},\"rx_frames\":{},\"tx_frames\":{},\"protocol_errors\":{},\"last_error\":{}}}",
        state.connected.load(Ordering::Relaxed),
        state.device.as_ref().map_or_else(|| "null".to_string(), |path| format!("\"{}\"", json_escape(&path.display().to_string()))),
        state.rx_frames.load(Ordering::Relaxed),
        state.tx_frames.load(Ordering::Relaxed),
        state.protocol_errors.load(Ordering::Relaxed),
        json_opt_str(error.as_deref()),
    )
}

fn adapter_json(state: &State) -> String {
    let session = state.session.lock().expect("session poisoned");
    let credit = state.credit.lock().expect("credit poisoned");
    let error = state
        .last_error
        .lock()
        .expect("last_error poisoned")
        .clone();
    format!(
        "{{\"device\":{},\"connected\":{},\"session\":{{\"authenticated\":{},\"id\":{},\"node\":{},\"boot\":{},\"network\":{},\"capability\":{},\"version\":{}}},\"credit\":{{\"observed\":{},\"grant_frames\":{},\"grant_bytes\":{}}},\"rx_frames\":{},\"tx_frames\":{},\"tx_bytes\":{},\"protocol_errors\":{},\"last_error\":{}}}",
        state.device.as_ref().map_or_else(|| "null".to_string(), |path| format!("\"{}\"", json_escape(&path.display().to_string()))),
        state.connected.load(Ordering::Relaxed),
        session.authenticated,
        json_opt_u64(session.id),
        json_opt_u64(session.node),
        json_opt_u64(session.boot),
        json_opt_u64(session.network),
        session.capability.map_or_else(|| "null".to_string(), |v| v.to_string()),
        session.version.map_or_else(|| "null".to_string(), |v| v.to_string()),
        credit.observed,
        credit.grant_frames,
        credit.grant_bytes,
        state.rx_frames.load(Ordering::Relaxed),
        state.tx_frames.load(Ordering::Relaxed),
        state.tx_bytes.load(Ordering::Relaxed),
        state.protocol_errors.load(Ordering::Relaxed),
        json_opt_str(error.as_deref()),
    )
}

fn nodes_json(state: &State) -> String {
    let nodes = state.nodes.lock().expect("nodes poisoned");
    let mut out = String::from("{\"nodes\":[");
    for (index, node) in nodes.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        // membership/reachability/rssi/hop_count have no source of truth in
        // this daemon; they are emitted explicitly as unknown so the API
        // contract distinguishes observed from absent data.
        out.push_str(&format!(
            "{{\"id\":{},\"role\":\"{}\",\"seen_ms\":{},\"membership\":\"unknown\",\"reachability\":\"unknown\",\"rssi_dbm\":null,\"lr250\":\"unknown\",\"hop_count\":null}}",
            node.id, node.role, node.seen_ms,
        ));
    }
    out.push_str("]}");
    out
}

fn deliveries_json(state: &State) -> String {
    let deliveries = state.deliveries.lock().expect("deliveries poisoned");
    let mut out = String::from("{\"deliveries\":[");
    for (index, delivery) in deliveries.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&format!(
            "{{\"request\":{},\"destination\":{},\"state\":\"{}\",\"reason\":{},\"msg_session\":{},\"msg_seq\":{},\"updated_ms\":{}}}",
            delivery.request,
            delivery.destination,
            json_escape(&delivery.state),
            json_opt_str(delivery.reason.as_deref()),
            delivery
                .msg_session
                .map_or_else(|| "null".to_string(), |v| v.to_string()),
            json_opt_u64(delivery.msg_seq),
            delivery.updated_ms,
        ));
    }
    out.push_str("]}");
    out
}

fn events_json(state: &State) -> String {
    let events = state.events.lock().expect("events poisoned");
    let mut out = String::from("{\"events\":[");
    for (index, event) in events.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(&event.json);
    }
    out.push_str(&format!(
        "],\"dropped\":{},\"next_seq\":{}}}",
        state.events_dropped.load(Ordering::Relaxed),
        state.event_seq.load(Ordering::Relaxed),
    ));
    out
}

fn authority_json(state: &State) -> String {
    let network = state.session.lock().expect("session poisoned").network;
    format!(
        "{{\"state\":\"unknown\",\"source\":null,\"network\":{},\"detail\":\"no control-plane ledger is attached to this daemon\"}}",
        json_opt_u64(network),
    )
}

fn parse_hex(input: &str) -> Result<Vec<u8>, String> {
    if input.len() % 2 != 0 {
        return Err("hex payload must have even length".into());
    }
    input
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).map_err(|_| "invalid hex")?;
            u8::from_str_radix(text, 16).map_err(|_| "invalid hex".to_string())
        })
        .collect()
}

/// Encodes and writes one wire-ready frame under the writer-slot lock.
/// Shared by the writer loop (queued data) and the read loop (session
/// responses such as AUTH, grants and keepalive acks).
fn transmit(
    writer_slot: &Arc<Mutex<Option<File>>>,
    state: &State,
    frame: &Frame,
) -> io::Result<usize> {
    let encoded = encode_frame(frame).map_err(io::Error::other)?;
    let len = encoded.len();
    let mut guard = writer_slot.lock().expect("writer slot poisoned");
    match guard.as_mut() {
        Some(writer) => writer
            .write_all(&encoded)
            .and_then(|()| writer.flush())
            .map(|()| {
                state.tx_frames.fetch_add(1, Ordering::Relaxed);
                state.tx_bytes.fetch_add(len as u64, Ordering::Relaxed);
                len
            }),
        None => Err(io::Error::new(
            io::ErrorKind::NotConnected,
            "adapter not connected",
        )),
    }
}

fn adapter_read_loop(
    mut reader: File,
    state: &State,
    session: &Arc<Mutex<DeviceSession>>,
    outbound: &mpsc::SyncSender<Outbound>,
) -> io::Result<()> {
    let mut decoder = StreamDecoder::default();
    let mut buffer = [0_u8; 512];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "adapter disconnected",
                ))
            }
            Ok(count) => {
                for result in decoder.push(&buffer[..count]) {
                    match result {
                        Ok(frame) => {
                            state.rx_frames.fetch_add(1, Ordering::Relaxed);
                            let mut inbound = {
                                let mut guard = session.lock().expect("device session poisoned");
                                guard.handle(&frame)
                            };
                            // Session responses go through the SAME bounded
                            // writer queue as client data: only the writer
                            // thread seals (assigns the session counter) and
                            // writes, so counter order is always wire order.
                            for item in std::mem::take(&mut inbound.outbound) {
                                match outbound.try_send(item) {
                                    Ok(()) => {}
                                    Err(mpsc::TrySendError::Full(_)) => {
                                        set_error(state, "outbound queue full".to_string());
                                        push_event(
                                            state,
                                            now_ms(),
                                            "\"kind\":\"session_drop\",\"reason\":\"outbound queue full\""
                                                .to_string(),
                                        );
                                    }
                                    Err(mpsc::TrySendError::Disconnected(_)) => {
                                        return Err(io::Error::new(
                                            io::ErrorKind::BrokenPipe,
                                            "adapter writer gone",
                                        ));
                                    }
                                }
                            }
                            merge_session_inbound(state, &inbound, &frame, now_ms());
                        }
                        Err(error) => {
                            state.protocol_errors.fetch_add(1, Ordering::Relaxed);
                            set_error(state, error.to_string());
                            push_event(
                                state,
                                now_ms(),
                                format!(
                                    "\"kind\":\"decode_error\",\"detail\":\"{}\"",
                                    json_escape(&error.to_string())
                                ),
                            );
                        }
                    }
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
}

/// Applies a verified session-layer result to daemon state: device
/// identity, authenticated session id, session notes as events, and the
/// verified inner body to record_frame.
fn merge_session_inbound(state: &State, inbound: &SessionInbound, frame: &Frame, ms: u64) {
    if let Some((version, node, boot, network, capability)) = inbound.hello_info {
        {
            let mut info = state.session.lock().expect("session poisoned");
            info.version = Some(version);
            info.node = Some(node);
            info.boot = Some(boot);
            info.network = Some(network);
            info.capability = Some(capability);
        }
        touch_node(state, node, "adapter", ms);
    }
    if let Some(session_id) = inbound.auth_session {
        let mut info = state.session.lock().expect("session poisoned");
        info.authenticated = true;
        info.id = Some(session_id);
    }
    for note in &inbound.notes {
        push_event(state, ms, note.clone());
    }
    if let Some(inner) = &inbound.inner {
        record_frame(state, frame, inner, ms);
    }
}

fn adapter_writer_loop(
    outbound: mpsc::Receiver<Outbound>,
    writer_slot: Arc<Mutex<Option<File>>>,
    state: Arc<State>,
    session: Arc<Mutex<DeviceSession>>,
) {
    loop {
        // recv_timeout doubles as the keepalive tick: an idle active session
        // gets a sealed KeepAlive so the device sees liveness (and a dead
        // session is noticed at the next failed authentication).
        let item = match outbound.recv_timeout(KEEPALIVE_INTERVAL) {
            Ok(item) => item,
            Err(mpsc::RecvTimeoutError::Timeout) => Outbound::Seal(Frame {
                kind: FrameKind::KeepAlive,
                flags: 0,
                session: 0,
                request: 0,
                body: Vec::new(),
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let mut frame = match item {
            // Handshake frames are unprotected by design — write as-is.
            Outbound::Raw(frame) => {
                if let Err(error) = transmit(&writer_slot, &state, &frame) {
                    set_error(&state, error.to_string());
                }
                continue;
            }
            Outbound::Seal(frame) => frame,
        };
        // Seal the queued inner body under the session key. Sealing happens
        // here — on the ONLY thread that writes — so direction counters are
        // strictly sequential with wire order even when a send is rejected
        // or the queue drops frames.
        let protected = {
            let mut guard = session.lock().expect("device session poisoned");
            guard.protect(&mut frame)
        };
        let sent = protected
            .map_err(str::to_string)
            .and_then(|()| transmit(&writer_slot, &state, &frame).map_err(|e| e.to_string()));
        match sent {
            Ok(_) => {
                if frame.kind == FrameKind::DataToMesh {
                    delivery_update(
                        &state,
                        frame.request,
                        "sent",
                        DeliveryPatch::default(),
                        now_ms(),
                    );
                }
            }
            Err(reason) => {
                let reason = reason.to_string();
                set_error(&state, reason.clone());
                if frame.kind == FrameKind::DataToMesh {
                    delivery_update(
                        &state,
                        frame.request,
                        "rejected",
                        DeliveryPatch {
                            reason: Some(reason),
                            ..DeliveryPatch::default()
                        },
                        now_ms(),
                    );
                }
            }
        }
    }
}

/// A serial TTY left in canonical mode corrupts the binary framing (echo,
/// line buffering, ICRNL/ONLCR/XON translation both ways). Configure raw
/// mode via stty — this workspace carries no termios crate — and continue on
/// failure: plain files and PTYs used by tests need nothing.
fn configure_raw_tty(path: &Path) {
    let flag = if cfg!(target_os = "macos") {
        "-f"
    } else {
        "-F"
    };
    let _ = std::process::Command::new("stty")
        .arg(flag)
        .arg(path)
        .args(["raw", "-echo"])
        .status();
}

fn adapter_supervisor(
    device: PathBuf,
    state: Arc<State>,
    writer_slot: Arc<Mutex<Option<File>>>,
    session: Arc<Mutex<DeviceSession>>,
    outbound: mpsc::SyncSender<Outbound>,
) {
    let mut backoff_ms = 500_u64;
    loop {
        configure_raw_tty(&device);
        match OpenOptions::new()
            .read(true)
            .write(true)
            .open(&device)
            .and_then(|reader| reader.try_clone().map(|writer| (reader, writer)))
        {
            Ok((reader, writer)) => {
                *writer_slot.lock().expect("writer slot poisoned") = Some(writer);
                state.connected.store(true, Ordering::Relaxed);
                backoff_ms = 500;
                {
                    let mut info = state.session.lock().expect("session poisoned");
                    *info = SessionInfo::default();
                }
                push_event(
                    &state,
                    now_ms(),
                    "\"kind\":\"adapter\",\"state\":\"connected\"".to_string(),
                );
                // A reconnect is always a brand-new session: counters,
                // grants and request ids from the old one are never reused.
                let hello = {
                    let mut guard = session.lock().expect("device session poisoned");
                    guard.begin()
                };
                // Even Hello goes through the writer queue: a stale-session
                // frame left over from the previous link must not overtake
                // it on the wire.
                if outbound.send(Outbound::Raw(hello)).is_err() {
                    set_error(&state, "hello queue failed: writer gone".to_string());
                }
                let result = adapter_read_loop(reader, &state, &session, &outbound);
                state.connected.store(false, Ordering::Relaxed);
                *writer_slot.lock().expect("writer slot poisoned") = None;
                session
                    .lock()
                    .expect("device session poisoned")
                    .disconnect();
                {
                    let mut info = state.session.lock().expect("session poisoned");
                    *info = SessionInfo::default();
                }
                if let Err(error) = result {
                    set_error(&state, error.to_string());
                }
                push_event(
                    &state,
                    now_ms(),
                    "\"kind\":\"adapter\",\"state\":\"disconnected\"".to_string(),
                );
            }
            Err(error) => {
                set_error(&state, format!("adapter open failed: {error}"));
            }
        }
        // Bounded exponential backoff: cable reconnects do not require a
        // daemon restart, and a missing device cannot spin the retry loop.
        thread::sleep(std::time::Duration::from_millis(backoff_ms));
        backoff_ms = (backoff_ms.saturating_mul(2)).min(5_000);
    }
}

fn serve_client(
    stream: UnixStream,
    state: Arc<State>,
    outbound: mpsc::SyncSender<Outbound>,
    session: u64,
    next_request: Arc<AtomicU64>,
    next_idem_key: Arc<AtomicU64>,
    device_session: Arc<Mutex<DeviceSession>>,
) -> io::Result<()> {
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    let mut writer = stream;
    let mut line = String::new();
    loop {
        line.clear();
        if reader.read_line(&mut line)? == 0 {
            return Ok(());
        }
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.is_empty() {
            continue;
        }
        let response = match fields[0].to_ascii_uppercase().as_str() {
            "STATUS" | "DIAGNOSTICS" => status_json(&state),
            "ADAPTER" => adapter_json(&state),
            "NODES" => nodes_json(&state),
            "DELIVERIES" => deliveries_json(&state),
            "EVENTS" => events_json(&state),
            "AUTHORITY" => authority_json(&state),
            "SEND" if fields.len() == 3 => {
                let destination = fields[1].parse::<u64>();
                let payload = parse_hex(fields[2]);
                // The device bridge only accepts DataToMesh inside an
                // authenticated session — reject early with a clear error
                // instead of queueing a frame the writer must drop.
                let authenticated = device_session
                    .lock()
                    .expect("device session poisoned")
                    .phase
                    == SessionPhase::Active;
                match (destination, payload) {
                    _ if !authenticated => {
                        "{\"accepted\":false,\"error\":\"session not authenticated\"}".into()
                    }
                    (Ok(destination), Ok(payload)) if payload.len() <= 128 => {
                        // Body: idempotency_key(8) || destination(8) ||
                        // payload. The key is a daemon-unique identity the
                        // device may persist across sessions; the CLI does
                        // not resubmit, so a fresh key per SEND suffices.
                        let mut body = next_idem_key
                            .fetch_add(1, Ordering::Relaxed)
                            .to_be_bytes()
                            .to_vec();
                        body.extend_from_slice(&destination.to_be_bytes());
                        body.extend_from_slice(&payload);
                        let request = next_request.fetch_add(1, Ordering::Relaxed);
                        // try_send: a full bounded queue rejects the SEND
                        // instead of blocking this client thread while the
                        // adapter is disconnected. The writer seals the body
                        // under the session key before writing.
                        match outbound.try_send(Outbound::Seal(Frame {
                            kind: FrameKind::DataToMesh,
                            flags: 0,
                            session,
                            request,
                            body,
                        })) {
                            Ok(()) => {
                                delivery_update(
                                    &state,
                                    request,
                                    "queued",
                                    DeliveryPatch {
                                        destination: Some(destination),
                                        ..DeliveryPatch::default()
                                    },
                                    now_ms(),
                                );
                                format!("{{\"accepted\":true,\"request\":{request}}}")
                            }
                            Err(_) => {
                                delivery_update(
                                    &state,
                                    request,
                                    "rejected",
                                    DeliveryPatch {
                                        destination: Some(destination),
                                        reason: Some(
                                            "adapter unavailable or queue full".to_string(),
                                        ),
                                        ..DeliveryPatch::default()
                                    },
                                    now_ms(),
                                );
                                "{\"accepted\":false,\"error\":\"adapter unavailable or queue full\"}".into()
                            }
                        }
                    }
                    (Ok(_), Ok(_)) => {
                        "{\"accepted\":false,\"error\":\"payload exceeds 128 bytes\"}".into()
                    }
                    _ => "{\"accepted\":false,\"error\":\"invalid SEND syntax\"}".into(),
                }
            }
            "QUIT" => return Ok(()),
            _ => "{\"error\":\"commands: STATUS, DIAGNOSTICS, SEND <node> <hex>, ADAPTER, NODES, DELIVERIES, EVENTS, AUTHORITY, QUIT\"}".into(),
        };
        writer.write_all(response.as_bytes())?;
        writer.write_all(b"\n")?;
        writer.flush()?;
    }
}

fn parse_args() -> Result<(PathBuf, Option<PathBuf>), String> {
    let mut socket = PathBuf::from("/tmp/routeloom.sock");
    let mut device = None;
    let mut args = env::args().skip(1);
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--socket" => socket = PathBuf::from(args.next().ok_or("--socket requires a path")?),
            "--device" => {
                device = Some(PathBuf::from(
                    args.next().ok_or("--device requires a path")?,
                ))
            }
            "--help" | "-h" => {
                println!("routeloom-host [--socket PATH] [--device TTY]");
                process::exit(0);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    Ok((socket, device))
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let (socket_path, device) = parse_args().map_err(io::Error::other)?;
    // Only remove a leftover unix socket — never unlink a regular file or a
    // path a second instance happens to point at.
    if let Ok(meta) = std::fs::metadata(&socket_path) {
        use std::os::unix::fs::FileTypeExt;
        if meta.file_type().is_socket() {
            std::fs::remove_file(&socket_path)?;
        } else {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                format!("{} exists and is not a socket", socket_path.display()),
            )
            .into());
        }
    }
    let state = Arc::new(State {
        device: device.clone(),
        ..State::default()
    });
    // Bounded outbound queue: SEND is back-pressured at MAX_OUTBOUND pending
    // frames instead of growing memory without limit while the adapter is
    // down.
    let (outbound_tx, outbound_rx) = mpsc::sync_channel(MAX_OUTBOUND);
    let device_session = Arc::new(Mutex::new(DeviceSession::new()));
    if let Some(device_path) = device {
        let writer_slot: Arc<Mutex<Option<File>>> = Arc::new(Mutex::new(None));
        {
            let writer_state = Arc::clone(&state);
            let writer_slot = Arc::clone(&writer_slot);
            let writer_session = Arc::clone(&device_session);
            thread::spawn(move || {
                adapter_writer_loop(outbound_rx, writer_slot, writer_state, writer_session)
            });
        }
        let adapter_state = Arc::clone(&state);
        let supervisor_session = Arc::clone(&device_session);
        let supervisor_outbound = outbound_tx.clone();
        thread::spawn(move || {
            adapter_supervisor(
                device_path,
                adapter_state,
                writer_slot,
                supervisor_session,
                supervisor_outbound,
            )
        });
    }
    let listener = UnixListener::bind(&socket_path)?;
    let session =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64 ^ u64::from(process::id());
    let next_request = Arc::new(AtomicU64::new(1));
    let next_idem_key = Arc::new(AtomicU64::new(session.rotate_left(32) | 1));
    println!("RouteLoom host listening on {}", socket_path.display());
    let active_clients = Arc::new(AtomicUsize::new(0));
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let count = active_clients.fetch_add(1, Ordering::Relaxed);
                if count >= MAX_CLIENTS {
                    active_clients.fetch_sub(1, Ordering::Relaxed);
                    // Drop the connection immediately — an unbounded accept
                    // loop would otherwise grow threads without limit.
                    drop(stream);
                    continue;
                }
                let client_state = Arc::clone(&state);
                let client_outbound = outbound_tx.clone();
                let client_requests = Arc::clone(&next_request);
                let client_idem_keys = Arc::clone(&next_idem_key);
                let client_session = Arc::clone(&device_session);
                let clients = Arc::clone(&active_clients);
                thread::spawn(move || {
                    let _ = serve_client(
                        stream,
                        client_state,
                        client_outbound,
                        session,
                        client_requests,
                        client_idem_keys,
                        client_session,
                    );
                    clients.fetch_sub(1, Ordering::Relaxed);
                });
            }
            Err(error) => eprintln!("accept failed: {error}"),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: FrameKind, flags: u16, request: u64, body: Vec<u8>) -> Frame {
        Frame {
            kind,
            flags,
            session: 0,
            request,
            body,
        }
    }

    /// Device-side half of the handshake, mirroring the golden vectors: a
    /// HelloAck carrying the device's hello_tag, then AUTH_OK.
    fn device_hello_ack(host_nonce: u64) -> (Vec<u8>, SessionProof) {
        let transcript = Transcript {
            host_nonce,
            device_nonce: 0xAABB,
            version: 1,
            node: 42,
            boot: 7,
            network: 9,
            capability: 3,
            principal: DEV_PRINCIPAL.to_vec(),
        };
        let proof = derive_session_proof(DEV_SECRET, &transcript.encode().unwrap());
        let mut body = Vec::new();
        body.extend_from_slice(&0xAABB_u64.to_be_bytes());
        body.push(1);
        body.extend_from_slice(&42_u64.to_be_bytes());
        body.extend_from_slice(&7_u64.to_be_bytes());
        body.extend_from_slice(&9_u64.to_be_bytes());
        body.extend_from_slice(&3_u32.to_be_bytes());
        body.extend_from_slice(&proof.hello_tag);
        (body, proof)
    }

    fn complete_handshake(session: &mut DeviceSession) -> SessionProof {
        let hello = session.begin();
        assert_eq!(hello.kind, FrameKind::Hello);
        let host_nonce = u64::from_be_bytes(hello.body[0..8].try_into().unwrap());
        let (ack_body, proof) = device_hello_ack(host_nonce);
        let inbound = session.handle(&frame(FrameKind::HelloAck, 0, 100, ack_body));
        assert_eq!(inbound.outbound.len(), 1);
        let auth = match &inbound.outbound[0] {
            Outbound::Raw(frame) => frame,
            Outbound::Seal(_) => panic!("AUTH must be a raw handshake frame"),
        };
        assert_eq!(auth.kind, FrameKind::Hello);
        assert_eq!(auth.flags & FLAG_AUTH, FLAG_AUTH);
        assert_eq!(auth.body, proof.auth_tag.to_vec());
        let mut ok_body = proof.auth_ok_tag.to_vec();
        ok_body.extend_from_slice(&proof.session_id.to_be_bytes());
        let inbound = session.handle(&frame(FrameKind::HelloAck, FLAG_AUTH, 0, ok_body));
        assert_eq!(session.phase, SessionPhase::Active);
        assert_eq!(inbound.auth_session, Some(proof.session_id));
        // The host must answer AUTH_OK with its TX grant immediately — the
        // device cannot send protected traffic without it.
        assert_eq!(inbound.outbound.len(), 1);
        match &inbound.outbound[0] {
            Outbound::Seal(frame) => assert_eq!(frame.kind, FrameKind::Credit),
            Outbound::Raw(_) => panic!("TX grant must be sealed at write time"),
        }
        proof
    }

    #[test]
    fn session_handshake_activates_and_opens_bodies() {
        let mut session = DeviceSession::new();
        let proof = complete_handshake(&mut session);
        let inner = {
            let mut v = Vec::new();
            v.extend_from_slice(&77_u64.to_be_bytes());
            v.extend_from_slice(&5_u32.to_be_bytes());
            v.extend_from_slice(&900_u64.to_be_bytes());
            v.extend_from_slice(b"hi");
            v
        };
        let sealed = seal_body(
            &proof.key,
            DIRECTION_DEVICE_TO_HOST,
            0,
            FrameKind::DataFromMesh,
            0,
            0,
            &inner,
        );
        let mut wire = frame(FrameKind::DataFromMesh, 0, 0, sealed.clone());
        wire.session = proof.session_id;
        let inbound = session.handle(&wire);
        assert_eq!(inbound.inner, Some(inner));
        // Tampered ciphertext is dropped, never parsed.
        let mut bad = sealed;
        let n = bad.len();
        bad[n - 1] ^= 1;
        let mut wire = frame(FrameKind::DataFromMesh, 0, 0, bad);
        wire.session = proof.session_id;
        let inbound = session.handle(&wire);
        assert!(inbound.inner.is_none());
        // A replayed counter is rejected.
        let replayed = seal_body(
            &proof.key,
            DIRECTION_DEVICE_TO_HOST,
            0,
            FrameKind::DataFromMesh,
            0,
            0,
            &[],
        );
        let mut wire = frame(FrameKind::DataFromMesh, 0, 0, replayed);
        wire.session = proof.session_id;
        let inbound = session.handle(&wire);
        assert!(inbound.inner.is_none());
        // A stale session id is dropped before the tag check.
        let stale = seal_body(
            &proof.key,
            DIRECTION_DEVICE_TO_HOST,
            1,
            FrameKind::DataFromMesh,
            0,
            0,
            &[],
        );
        let inbound = session.handle(&frame(FrameKind::DataFromMesh, 0, 0, stale));
        assert!(inbound.inner.is_none());
    }

    #[test]
    fn session_rejects_bad_tags_and_unauthenticated_frames() {
        let mut session = DeviceSession::new();
        let hello = session.begin();
        let host_nonce = u64::from_be_bytes(hello.body[0..8].try_into().unwrap());
        let (mut ack_body, _proof) = device_hello_ack(host_nonce);
        // Wrong hello_tag → no AUTH is emitted, session stays in handshake.
        let n = ack_body.len();
        ack_body[n - 1] ^= 0xFF;
        let inbound = session.handle(&frame(FrameKind::HelloAck, 0, 0, ack_body));
        assert_eq!(session.phase, SessionPhase::AwaitHelloAck);
        assert_eq!(inbound.outbound.len(), 1);
        match &inbound.outbound[0] {
            Outbound::Raw(frame) => assert_eq!(frame.kind, FrameKind::Hello), // re-hello
            Outbound::Seal(_) => panic!("re-hello must be a raw frame"),
        }
        // Active-session traffic before AUTH_OK cannot be opened.
        let mut session2 = DeviceSession::new();
        session2.begin();
        let inbound = session2.handle(&frame(FrameKind::DataFromMesh, 0, 0, vec![0; 40]));
        assert!(inbound.inner.is_none());
    }

    /// A Credit grant frame from the device, sealed under its direction key
    /// and stamped with the authenticated session id.
    fn device_credit_grant(proof: &SessionProof, counter: u64, frames: u64, bytes: u64) -> Frame {
        let mut inner = Vec::new();
        inner.push(CREDIT_GRANT);
        inner.extend_from_slice(&frames.to_be_bytes());
        inner.extend_from_slice(&bytes.to_be_bytes());
        let body = seal_body(
            &proof.key,
            DIRECTION_DEVICE_TO_HOST,
            counter,
            FrameKind::Credit,
            0,
            0,
            &inner,
        );
        let mut f = frame(FrameKind::Credit, 0, 0, body);
        f.session = proof.session_id;
        f
    }

    #[test]
    fn session_protect_seals_and_enforces_credit() {
        let mut session = DeviceSession::new();
        let proof = complete_handshake(&mut session);
        // No device grant yet — data sends are refused but control frames
        // (KeepAlive, our own Credit grant) still flow.
        let mut data = frame(FrameKind::DataToMesh, 0, 1, vec![0; 16]);
        assert!(session.protect(&mut data).is_err());
        let mut keepalive = frame(FrameKind::KeepAlive, 0, 0, vec![]);
        assert!(session.protect(&mut keepalive).is_ok());
        // A device Credit grant opens the data path; each send consumes
        // header + sealed body + crc bytes of byte credit and one frame.
        session.handle(&device_credit_grant(&proof, 0, 2, 1_000_000));
        assert!(session.protect(&mut data).is_ok());
        assert_eq!(data.body.len(), 16 + PROTECTED_BODY_OVERHEAD);
        let mut second = frame(FrameKind::DataToMesh, 0, 2, vec![0; 16]);
        assert!(session.protect(&mut second).is_ok());
        // The two-frame grant is exhausted.
        let mut third = frame(FrameKind::DataToMesh, 0, 3, vec![0; 16]);
        assert!(session.protect(&mut third).is_err());
        // Outbound bodies verify under the host→device direction key.
        let (counter, inner) = open_body(&proof.key, DIRECTION_HOST_TO_DEVICE, &data).unwrap();
        // Counters are assigned by the writer thread: the TX grant produced
        // by AUTH_OK is emitted unsealed, so this session sees 0 → KeepAlive,
        // 1 → data. On the wire the grant seals first since it queued first.
        assert_eq!(counter, 1);
        assert_eq!(inner, &[0; 16]);
    }

    #[test]
    fn session_answers_one_byte_credit_query() {
        // The device's CREDIT_QUERY body is a single opcode byte — it must
        // not be discarded by a grant-sized length check.
        let mut session = DeviceSession::new();
        let proof = complete_handshake(&mut session);
        let query_body = seal_body(
            &proof.key,
            DIRECTION_DEVICE_TO_HOST,
            0,
            FrameKind::Credit,
            0,
            0,
            &[CREDIT_QUERY],
        );
        let mut query = frame(FrameKind::Credit, 0, 0, query_body);
        query.session = proof.session_id;
        let inbound = session.handle(&query);
        assert_eq!(inbound.outbound.len(), 1);
        match &inbound.outbound[0] {
            Outbound::Seal(frame) => {
                assert_eq!(frame.kind, FrameKind::Credit);
                // Still unsealed here: the writer assigns the session
                // counter at write time, so the body is the raw 17-byte
                // grant (opcode || frames || bytes).
                assert_eq!(frame.body.len(), 17);
                assert_eq!(frame.body[0], CREDIT_GRANT);
            }
            Outbound::Raw(_) => panic!("credit response must be sealed"),
        }
    }

    #[test]
    fn data_from_mesh_records_origin_node() {
        let state = State::default();
        let mut body = Vec::new();
        body.extend_from_slice(&77_u64.to_be_bytes());
        body.extend_from_slice(&5_u32.to_be_bytes());
        body.extend_from_slice(&900_u64.to_be_bytes());
        body.extend_from_slice(b"hi");
        record_frame(
            &state,
            &frame(FrameKind::DataFromMesh, 0, 0, body.clone()),
            &body,
            1000,
        );
        let json = events_json(&state);
        assert!(json.contains("\"kind\":\"data_from_mesh\""));
        assert!(json.contains("\"origin\":77"));
        assert!(json.contains("\"payload_len\":2"));
        assert!(nodes_json(&state).contains("\"id\":77"));
    }

    #[test]
    fn delivery_event_transitions_tracked_delivery() {
        let state = State::default();
        delivery_update(
            &state,
            9,
            "queued",
            DeliveryPatch {
                destination: Some(5),
                ..DeliveryPatch::default()
            },
            100,
        );
        let mut body = Vec::new();
        body.extend_from_slice(&9_u64.to_be_bytes());
        body.extend_from_slice(&5_u32.to_be_bytes());
        body.extend_from_slice(&900_u64.to_be_bytes());
        body.push(7); // delivered
        body.push(0);
        record_frame(
            &state,
            &frame(FrameKind::DeliveryEvent, 0, 9, body.clone()),
            &body,
            200,
        );
        let json = deliveries_json(&state);
        assert!(json.contains("\"state\":\"delivered\""));
        assert!(json.contains("\"msg_seq\":900"));
    }

    #[test]
    fn error_frame_marks_delivery_failed() {
        let state = State::default();
        delivery_update(
            &state,
            3,
            "sent",
            DeliveryPatch {
                destination: Some(8),
                ..DeliveryPatch::default()
            },
            100,
        );
        let mut body = Vec::new();
        body.extend_from_slice(&13_u16.to_be_bytes());
        body.extend_from_slice(&3_u64.to_be_bytes());
        body.push(4);
        body.extend_from_slice(b"NACK");
        record_frame(
            &state,
            &frame(FrameKind::Error, 0, 3, body.clone()),
            &body,
            200,
        );
        let json = deliveries_json(&state);
        assert!(json.contains("\"state\":\"failed\""));
        assert!(json.contains("\"reason\":\"NACK\""));
    }

    #[test]
    fn credit_grant_is_observed() {
        let state = State::default();
        assert!(adapter_json(&state).contains("\"observed\":false"));
        let mut body = vec![CREDIT_GRANT];
        body.extend_from_slice(&64_u64.to_be_bytes());
        body.extend_from_slice(&8192_u64.to_be_bytes());
        record_frame(
            &state,
            &frame(FrameKind::Credit, 0, 0, body.clone()),
            &body,
            100,
        );
        let json = adapter_json(&state);
        assert!(json.contains("\"observed\":true"));
        assert!(json.contains("\"grant_frames\":64"));
        assert!(json.contains("\"grant_bytes\":8192"));
    }

    #[test]
    fn diagnostic_with_message_parses() {
        let state = State::default();
        let mut body = Vec::new();
        body.extend_from_slice(&55_u64.to_be_bytes());
        body.push(DIAG_FLAG_HAS_MESSAGE);
        body.extend_from_slice(&2_u32.to_be_bytes());
        body.extend_from_slice(&300_u64.to_be_bytes());
        body.push(6);
        body.extend_from_slice(b"RETRY!");
        record_frame(
            &state,
            &frame(FrameKind::Diagnostic, 0, 0, body.clone()),
            &body,
            100,
        );
        let json = events_json(&state);
        assert!(json.contains("\"peer\":55"));
        assert!(json.contains("\"reason\":\"RETRY!\""));
        assert!(json.contains("\"msg_seq\":300"));
    }

    #[test]
    fn event_ring_is_bounded() {
        let state = State::default();
        for _ in 0..MAX_EVENTS + 40 {
            push_event(&state, 0, "\"kind\":\"keepalive\"".to_string());
        }
        assert_eq!(state.events.lock().unwrap().len(), MAX_EVENTS);
        assert_eq!(state.events_dropped.load(Ordering::Relaxed), 40);
        let json = events_json(&state);
        assert!(json.contains("\"dropped\":40"));
    }

    #[test]
    fn authority_reports_unknown() {
        let state = State::default();
        let json = authority_json(&state);
        assert!(json.contains("\"state\":\"unknown\""));
        assert!(json.contains("\"source\":null"));
    }

    #[test]
    fn malformed_frames_still_emit_events() {
        let state = State::default();
        record_frame(
            &state,
            &frame(FrameKind::DataFromMesh, 0, 0, vec![1, 2]),
            &[1, 2],
            100,
        );
        record_frame(
            &state,
            &frame(FrameKind::DeliveryEvent, 0, 0, vec![]),
            &[],
            100,
        );
        let json = events_json(&state);
        assert!(json.contains("\"malformed\":true"));
    }

    /// Schema drift guard: every JSON document this daemon emits must parse
    /// through the TUI's client model — the same JSON routeloomctl prints.
    /// Drives the real session path (handshake → sealed data → merge) so
    /// node/session info arrives exactly as it does from the adapter loop.
    #[test]
    fn emitted_json_is_consumed_by_client_model() {
        let state = State::default();
        let mut session = DeviceSession::new();
        let hello = session.begin();
        let host_nonce = u64::from_be_bytes(hello.body[0..8].try_into().unwrap());
        let (ack_body, proof) = device_hello_ack(host_nonce);
        let ack = frame(FrameKind::HelloAck, 0, 100, ack_body);
        merge_session_inbound(&state, &session.handle(&ack), &ack, 100);
        let mut ok_body = proof.auth_ok_tag.to_vec();
        ok_body.extend_from_slice(&proof.session_id.to_be_bytes());
        let ok = frame(FrameKind::HelloAck, FLAG_AUTH, 0, ok_body);
        merge_session_inbound(&state, &session.handle(&ok), &ok, 105);
        let mut data = Vec::new();
        data.extend_from_slice(&77_u64.to_be_bytes());
        data.extend_from_slice(&5_u32.to_be_bytes());
        data.extend_from_slice(&900_u64.to_be_bytes());
        data.extend_from_slice(b"hi");
        let mut sealed = frame(
            FrameKind::DataFromMesh,
            0,
            0,
            seal_body(
                &proof.key,
                DIRECTION_DEVICE_TO_HOST,
                0,
                FrameKind::DataFromMesh,
                0,
                0,
                &data,
            ),
        );
        sealed.session = proof.session_id;
        merge_session_inbound(&state, &session.handle(&sealed), &sealed, 110);
        delivery_update(
            &state,
            9,
            "queued",
            DeliveryPatch {
                destination: Some(5),
                ..DeliveryPatch::default()
            },
            120,
        );
        let mut client = routeloom_tui::model::State::new("/tmp/x.sock");
        for (command, line) in [
            ("STATUS", status_json(&state)),
            ("ADAPTER", adapter_json(&state)),
            ("NODES", nodes_json(&state)),
            ("DELIVERIES", deliveries_json(&state)),
            ("EVENTS", events_json(&state)),
            ("AUTHORITY", authority_json(&state)),
        ] {
            client.apply(command, &line).expect(command);
        }
        assert_eq!(client.nodes.len(), 2);
        assert_eq!(client.deliveries.len(), 1);
        assert_eq!(client.events.len(), 3);
        assert_eq!(client.authority.state, "unknown");
        assert_eq!(client.adapter.node, Some(42));
    }
}
