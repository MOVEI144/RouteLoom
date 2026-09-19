#[cfg(not(unix))]
compile_error!("routeloom-host v0.1 currently requires a Unix platform");

use routeloom_protocol::{encode_frame, Frame, FrameKind, StreamDecoder};
use std::collections::VecDeque;
use std::env;
use std::fs::OpenOptions;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

/// Bounded observation buffers. The daemon keeps only what it legitimately
/// observes on the USB stream; mesh truth it cannot see stays `unknown`.
const MAX_EVENTS: usize = 256;
const MAX_DELIVERIES: usize = 512;
const MAX_NODES: usize = 256;

/// Session-protected bodies (counter || tag || inner, see dev_session.rs) are
/// not unpacked: this daemon does not hold a session key yet. Frame bodies are
/// interpreted with the unprotected v0.1 inner layouts used by the device
/// bridge (components/routeloom/src/usb_bridge.cpp).
const DIAG_FLAG_HAS_MESSAGE: u8 = 0x01;
const HELLO_ACK_FLAG_AUTH: u16 = 0x0001;
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

fn json_escape(input: &str) -> String {
    input.replace('\\', "\\\\").replace('"', "\\\"")
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
    let seq = state.event_seq.fetch_add(1, Ordering::Relaxed);
    let json = format!("{{\"seq\":{seq},\"ms\":{ms},{fields}}}");
    let mut events = state.events.lock().expect("events poisoned");
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
fn record_frame(state: &State, frame: &Frame, ms: u64) {
    let body = frame.body.as_slice();
    match frame.kind {
        FrameKind::HelloAck => {
            if frame.flags & HELLO_ACK_FLAG_AUTH != 0 {
                let session_id = u64_at(body, 16);
                {
                    let mut session = state.session.lock().expect("session poisoned");
                    session.authenticated = true;
                    session.id = session_id;
                }
                push_event(
                    state,
                    ms,
                    format!(
                        "\"kind\":\"auth_ok\",\"session\":{}",
                        json_opt_u64(session_id)
                    ),
                );
            } else if body.len() >= 37 {
                let (version, node, boot, network, capability) = (
                    body[8],
                    u64_at(body, 9),
                    u64_at(body, 17),
                    u64_at(body, 25),
                    u32_at(body, 33),
                );
                {
                    let mut session = state.session.lock().expect("session poisoned");
                    session.version = Some(version);
                    session.node = node;
                    session.boot = boot;
                    session.network = network;
                    session.capability = capability;
                }
                if let Some(node) = node {
                    touch_node(state, node, "adapter", ms);
                }
                push_event(
                    state,
                    ms,
                    format!(
                        "\"kind\":\"hello_ack\",\"version\":{version},\"node\":{},\"boot\":{},\"network\":{},\"capability\":{}",
                        json_opt_u64(node),
                        json_opt_u64(boot),
                        json_opt_u64(network),
                        capability.map_or_else(|| "null".to_string(), |v| v.to_string()),
                    ),
                );
            } else {
                push_event(
                    state,
                    ms,
                    format!("\"kind\":\"frame\",\"frame_kind\":{}", frame.kind as u8),
                );
            }
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

fn adapter_thread(
    device: PathBuf,
    state: Arc<State>,
    outbound: mpsc::Receiver<Frame>,
) -> io::Result<()> {
    let mut reader = OpenOptions::new().read(true).write(true).open(&device)?;
    let mut writer = reader.try_clone()?;
    state.connected.store(true, Ordering::Relaxed);
    push_event(
        &state,
        now_ms(),
        "\"kind\":\"adapter\",\"state\":\"connected\"".to_string(),
    );

    let writer_state = Arc::clone(&state);
    thread::spawn(move || {
        while let Ok(frame) = outbound.recv() {
            let result = encode_frame(&frame)
                .map_err(io::Error::other)
                .and_then(|encoded| {
                    let len = encoded.len();
                    writer
                        .write_all(&encoded)
                        .and_then(|()| writer.flush())
                        .map(|()| len)
                });
            match result {
                Ok(written) => {
                    writer_state.tx_frames.fetch_add(1, Ordering::Relaxed);
                    writer_state
                        .tx_bytes
                        .fetch_add(written as u64, Ordering::Relaxed);
                    if frame.kind == FrameKind::DataToMesh {
                        delivery_update(
                            &writer_state,
                            frame.request,
                            "sent",
                            DeliveryPatch::default(),
                            now_ms(),
                        );
                    }
                }
                Err(error) => {
                    writer_state.connected.store(false, Ordering::Relaxed);
                    set_error(&writer_state, error.to_string());
                    break;
                }
            }
        }
    });

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
                            record_frame(&state, &frame, now_ms());
                        }
                        Err(error) => {
                            state.protocol_errors.fetch_add(1, Ordering::Relaxed);
                            set_error(&state, error.to_string());
                            push_event(
                                &state,
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

fn serve_client(
    stream: UnixStream,
    state: Arc<State>,
    outbound: mpsc::Sender<Frame>,
    session: u64,
    next_request: Arc<AtomicU64>,
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
                match (destination, payload) {
                    (Ok(destination), Ok(payload)) if payload.len() <= 128 => {
                        let mut body = destination.to_be_bytes().to_vec();
                        body.extend_from_slice(&payload);
                        let request = next_request.fetch_add(1, Ordering::Relaxed);
                        match outbound.send(Frame {
                            kind: FrameKind::DataToMesh,
                            flags: 0,
                            session,
                            request,
                            body,
                        }) {
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
                                        reason: Some("adapter unavailable".to_string()),
                                        ..DeliveryPatch::default()
                                    },
                                    now_ms(),
                                );
                                "{\"accepted\":false,\"error\":\"adapter unavailable\"}".into()
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
    if Path::new(&socket_path).exists() {
        std::fs::remove_file(&socket_path)?;
    }
    let state = Arc::new(State {
        device: device.clone(),
        ..State::default()
    });
    let (outbound_tx, outbound_rx) = mpsc::channel();
    if let Some(device_path) = device {
        let adapter_state = Arc::clone(&state);
        thread::spawn(move || {
            if let Err(error) = adapter_thread(device_path, Arc::clone(&adapter_state), outbound_rx)
            {
                adapter_state.connected.store(false, Ordering::Relaxed);
                set_error(&adapter_state, error.to_string());
                push_event(
                    &adapter_state,
                    now_ms(),
                    "\"kind\":\"adapter\",\"state\":\"disconnected\"".to_string(),
                );
            }
        });
    }
    let listener = UnixListener::bind(&socket_path)?;
    let session =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64 ^ u64::from(process::id());
    let next_request = Arc::new(AtomicU64::new(1));
    println!("RouteLoom host listening on {}", socket_path.display());
    for incoming in listener.incoming() {
        match incoming {
            Ok(stream) => {
                let client_state = Arc::clone(&state);
                let client_outbound = outbound_tx.clone();
                let client_requests = Arc::clone(&next_request);
                thread::spawn(move || {
                    let _ = serve_client(
                        stream,
                        client_state,
                        client_outbound,
                        session,
                        client_requests,
                    );
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

    #[test]
    fn hello_ack_updates_session_and_node() {
        let state = State::default();
        let mut body = vec![0_u8; 37 + 16];
        body[8] = 1;
        body[9..17].copy_from_slice(&42_u64.to_be_bytes());
        body[17..25].copy_from_slice(&7_u64.to_be_bytes());
        body[25..33].copy_from_slice(&9_u64.to_be_bytes());
        body[33..37].copy_from_slice(&3_u32.to_be_bytes());
        record_frame(&state, &frame(FrameKind::HelloAck, 0, 0, body), 1000);
        let session = state.session.lock().unwrap();
        assert_eq!(session.node, Some(42));
        assert_eq!(session.network, Some(9));
        assert_eq!(session.version, Some(1));
        drop(session);
        assert!(adapter_json(&state).contains("\"node\":42"));
        assert!(nodes_json(&state).contains("\"id\":42"));
        assert!(nodes_json(&state).contains("\"role\":\"adapter\""));
    }

    #[test]
    fn data_from_mesh_records_origin_node() {
        let state = State::default();
        let mut body = Vec::new();
        body.extend_from_slice(&77_u64.to_be_bytes());
        body.extend_from_slice(&5_u32.to_be_bytes());
        body.extend_from_slice(&900_u64.to_be_bytes());
        body.extend_from_slice(b"hi");
        record_frame(&state, &frame(FrameKind::DataFromMesh, 0, 0, body), 1000);
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
        record_frame(&state, &frame(FrameKind::DeliveryEvent, 0, 9, body), 200);
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
        record_frame(&state, &frame(FrameKind::Error, 0, 3, body), 200);
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
        record_frame(&state, &frame(FrameKind::Credit, 0, 0, body), 100);
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
        record_frame(&state, &frame(FrameKind::Diagnostic, 0, 0, body), 100);
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
            100,
        );
        record_frame(&state, &frame(FrameKind::DeliveryEvent, 0, 0, vec![]), 100);
        let json = events_json(&state);
        assert!(json.contains("\"malformed\":true"));
    }

    /// Schema drift guard: every JSON document this daemon emits must parse
    /// through the TUI's client model — the same JSON routeloomctl prints.
    #[test]
    fn emitted_json_is_consumed_by_client_model() {
        let state = State::default();
        let mut hello = vec![0_u8; 37 + 16];
        hello[8] = 1;
        hello[9..17].copy_from_slice(&42_u64.to_be_bytes());
        record_frame(&state, &frame(FrameKind::HelloAck, 0, 0, hello), 100);
        let mut data = Vec::new();
        data.extend_from_slice(&77_u64.to_be_bytes());
        data.extend_from_slice(&5_u32.to_be_bytes());
        data.extend_from_slice(&900_u64.to_be_bytes());
        data.extend_from_slice(b"hi");
        record_frame(&state, &frame(FrameKind::DataFromMesh, 0, 0, data), 110);
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
        assert_eq!(client.events.len(), 2);
        assert_eq!(client.authority.state, "unknown");
        assert_eq!(client.adapter.node, Some(42));
    }
}
