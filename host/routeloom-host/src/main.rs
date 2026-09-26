#[cfg(not(unix))]
compile_error!("routeloom-host v0.1 currently requires a Unix platform");

mod acl;
mod api1;
mod canonical;
mod config;
mod dispatch;
mod group;
mod nodes;
mod receive_log;
mod send_store;
mod site;
mod sqlite_store;
mod subscribe;
mod telemetry;

use acl::Acl;
use receive_log::{Ingress, ReceiveLog};
use routeloom_protocol::dev_session::{
    derive_session_proof, open_body, seal_body, SessionProof, Transcript, DIRECTION_DEVICE_TO_HOST,
    DIRECTION_HOST_TO_DEVICE, FLAG_AUTH, PROTECTED_BODY_OVERHEAD,
};
use routeloom_protocol::{encode_frame, CumulativeCredit, Frame, FrameKind, StreamDecoder};
use send_store::{mint_id128, MemoryOperationStore, OperationStore, StoreBackend};
use std::collections::{HashMap, VecDeque};
use std::env;
use std::fs::{File, OpenOptions};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::process;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Bounded observation buffers. The daemon keeps only what it legitimately
/// observes on the USB stream; mesh truth it cannot see stays `unknown`.
const MAX_EVENTS: usize = 256;
const MAX_DELIVERIES: usize = 512;
const MAX_NODES: usize = 256;
const MAX_OUTBOUND: usize = 64;
/// Concurrent control-socket clients. Each connection owns a thread and a
/// BufReader — bound the count so a connection storm cannot exhaust fd/memory.
/// contracts.json `ipc.max_connections` = 32; a per-principal cap of 4
/// (`connections_per_principal`) is enforced separately at accept time.
const MAX_CLIENTS: usize = 32;
const MAX_CLIENTS_PER_PRINCIPAL: usize = 4;
/// Bound on a single socket write: a slow client must not pin the shared
/// receive log or hang a client thread forever (ipc.write_timeout_ms).
const CLIENT_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(2_000);

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
/// Default dev-permit master, hex-encoded — the same placeholder the
/// firmware Kconfig default ships (ROUTELOOM_DEVELOPMENT_KEY_HEX), so an
/// unconfigured daemon↔device pair agrees on the EXPERIMENTAL dev profile.
/// Deployments must provision a different key on both sides; this provider
/// never claims a production identity.
const DEFAULT_CONFIG_DEV_KEY_HEX: &str =
    "524f5554454c4f4f4d2d444556454c4f504d454e542d4b45592d4f4e4c592121";
/// Idle interval between session keepalives.
const KEEPALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
/// Re-Hello cadence while the handshake is unfinished: a Hello sent while
/// the device is still booting is lost forever, so without a retry the
/// session would sit in AwaitHelloAck until the next cable reconnect
/// (observed on real hardware after a device reset).
const HELLO_RETRY_MS: u64 = 1_000;
/// An Active session that has seen no inbound frame for this long is dead
/// at the far end even when the adapter fd stays healthy — the silent
/// reboot/half-open case no wire error can signal. A live session always
/// sees traffic at least every KEEPALIVE_INTERVAL (the device echoes each
/// keepalive); three missed intervals is a dead peer, not a busy one.
const SESSION_LIVENESS_MS: u64 = 3 * KEEPALIVE_INTERVAL.as_millis() as u64;

/// The liveness predicate the writer loop applies each tick: `last_rx` is
/// the wall ms of the last decoded inbound frame (0 = none yet — harmless,
/// Active requires a completed handshake which itself produced inbound).
fn session_stalled(now: u64, last_rx: u64) -> bool {
    now.saturating_sub(last_rx) >= SESSION_LIVENESS_MS
}

/// After AUTH every session frame body is `counter || tag || inner`
/// (dev_session.rs). The daemon owns the host role of the dev-session
/// handshake and opens inbound bodies before parsing the inner layouts used
/// by the device bridge (components/routeloom/src/usb_bridge.cpp).
const DIAG_FLAG_HAS_MESSAGE: u8 = 0x01;
/// Set on every Diagnostic from a loss-accounting bridge: boot(8) ||
/// seq(4) || dropped_total(8), big-endian, appended after the reason.
const DIAG_FLAG_HAS_ACCOUNTING: u8 = 0x02;
const DIAG_ACCOUNTING_TAIL: usize = 20;
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
    /// The frame proved the far end no longer holds our session (a
    /// stale-session echo, a session-fatal error, a tag desync, or a lost
    /// proof): the authenticated mirror and the gateway registration bound
    /// to it are dead and must be cleared, never inherited by the session
    /// the re-hello is starting.
    session_lost: bool,
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
    /// Timestamp of the last begin() so the writer can pace handshake retries.
    last_begin_ms: u64,
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
            last_begin_ms: 0,
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

    /// The writer paces handshake retries with this: a Hello lost while the
    /// device booted would otherwise stall the session until a reconnect.
    fn handshake_retry_due(&self, now: u64) -> bool {
        matches!(
            self.phase,
            SessionPhase::AwaitHelloAck | SessionPhase::AwaitAuthOk
        ) && now.saturating_sub(self.last_begin_ms) >= HELLO_RETRY_MS
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
        self.last_begin_ms = now_ms();
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
        // A lane may bind an enqueued body to the session that authorized
        // it. Refuse a stale queue item before charging credit or counters.
        if frame.session != 0 && frame.session != self.session_id {
            return Err("queued frame session changed");
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
                        // Defensive: Active without a proof cannot serve
                        // traffic — fall back to a fresh handshake rather
                        // than wedging the lane.
                        result.session_lost = true;
                        result.outbound.push(Outbound::Raw(self.begin()));
                        return result;
                    }
                };
                // frame_tag does not cover the session id — check it
                // explicitly. A frame under any other session id proves
                // the far end lost our binding (the device holds exactly
                // one session; a reboot that kept the serial link answers
                // our traffic with unsealed, session-0 errors). Dropping
                // it without re-helloing would wedge the session forever:
                // restart the handshake so the link recovers on its own.
                if frame.session != self.session_id {
                    result
                        .notes
                        .push("\"kind\":\"session_drop\",\"reason\":\"stale session\"".to_string());
                    result.session_lost = true;
                    result.outbound.push(Outbound::Raw(self.begin()));
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
                                result.session_lost = true;
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
                        result.session_lost = true;
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

/// One ring-buffer entry. `seq`/`kind` are stored alongside `json` (which
/// also embeds them) so the events subscription stream can filter and
/// resume without re-parsing every line.
pub struct Event {
    pub seq: u64,
    pub kind: String,
    pub json: String,
}

/// Autonomy-lane view derived from device Diagnostic frames (discovery
/// engine reasons + migration agent events). Every field stays `None`
/// until the device actually emits it — unknown is reported as null,
/// never synthesized.
#[derive(Default)]
struct AutonomyState {
    /// Participant phase from PHASE_* events (stable/assess/...).
    phase: Option<String>,
    /// Coordinator judgment from ASSESS_* events.
    assess: Option<String>,
    /// Coordinator mode from MIGRATION_MODE_* events.
    migration_mode: Option<String>,
    /// Latest gated-operation detail (AUTOGUARDED_*/AUTOSURVEY_*/SURVEY_*).
    gate_detail: Option<String>,
    last_discovery_ms: Option<u64>,
    last_discovery: Option<String>,
    last_migration_ms: Option<u64>,
    last_migration: Option<String>,
    discovery_events: u64,
    migration_events: u64,
}

/// Baseline for device-diagnostic loss detection: the last accounted
/// (boot, seq, dropped_total) triple the read loop ingested. `boot` is
/// None until the first accounted frame — legacy frames (no trailer)
/// never touch the baseline.
#[derive(Default)]
struct DiagLossBaseline {
    boot: Option<u64>,
    seq: u32,
    dropped: u64,
}

/// Discovery-engine reason strings (components/routeloom/src/discovery.cpp).
/// Everything else autonomy-related is a migration-lane event.
const DISCOVERY_REASONS: &[&str] = &[
    "PEER_CAPACITY",
    "KIND_REJECT",
    "COOKIE_REJECT",
    "AUTH_FAILED",
    "DATA_REJECT",
    "REACHABLE",
    "BINDING_CONFLICT",
    "MEMBERSHIP_PENDING",
    "BOUND",
    "STALE",
    "REVOKED",
];

/// Classify a device diagnostic reason into the autonomy view. Reasons are
/// bounded engine strings — classified, never parsed for data.
/// Compares one accounted diagnostic against the baseline and pushes a
/// `diagnostic_loss` event when device-side drops left a seq gap, when a
/// fresh boot's counter already moved (pre-history loss, range unknown),
/// or — defensively — when the counter jumped without a gap. Duplicates,
/// out-of-order arrivals, and legacy frames never move the baseline.
fn check_diag_loss(state: &State, ms: u64, boot: u64, seq: u32, dropped: u64) {
    let mut base = state.diag_loss.lock().expect("diag loss poisoned");
    // (lost_from, lost_to, lost) — the range stays None when only the
    // counter proves the loss.
    let mut loss: Option<(Option<u32>, Option<u32>, u64)> = None;
    let mut advance = true;
    match base.boot {
        Some(known) if known == boot => {
            let ahead = seq.wrapping_sub(base.seq);
            if ahead == 1 {
                if dropped > base.dropped {
                    loss = Some((None, None, dropped - base.dropped));
                }
            } else if ahead != 0 && ahead <= u32::MAX / 2 {
                // USB never reorders: every seq between the baseline and
                // this arrival was dropped on the device. Wrapping math
                // keeps the u32 rollover exact.
                loss = Some((
                    Some(base.seq.wrapping_add(1)),
                    Some(seq.wrapping_sub(1)),
                    u64::from(ahead - 1),
                ));
            } else {
                advance = false;
            }
        }
        _ => {
            if dropped > 0 {
                loss = Some((None, None, dropped));
            }
        }
    }
    if advance {
        base.boot = Some(boot);
        base.seq = seq;
        base.dropped = dropped;
    }
    drop(base);
    if let Some((from, to, lost)) = loss {
        push_event(
            state,
            ms,
            format!(
                "\"kind\":\"diagnostic_loss\",\"boot\":{boot},\"lost_from\":{},\"lost_to\":{},\"lost\":{lost},\"dropped_total\":{dropped}",
                json_opt_u64(from.map(u64::from)),
                json_opt_u64(to.map(u64::from)),
            ),
        );
    }
}

fn note_autonomy(state: &State, ms: u64, reason: &str) {
    let migration = reason.starts_with("PHASE_")
        || reason.starts_with("ASSESS_")
        || reason.starts_with("AUTOSURVEY_")
        || reason.starts_with("AUTOGUARDED_")
        || reason.starts_with("MIGRATION_")
        || reason.starts_with("PLAN_")
        || reason.starts_with("COMMIT_")
        || reason.starts_with("SNAPSHOT_")
        || reason.starts_with("CHANNEL_NOTICE")
        || reason.starts_with("HELPER_")
        || reason.starts_with("PENDING_SEND")
        || reason.starts_with("READINESS_")
        || reason.starts_with("RESULT_")
        // Only the migration agent's divergence diagnostic is a migration
        // event — the power coordinator's RESUME_* reasons (RESUME_CONFIRMED,
        // RESUME_DISCOVERY_STARTED, RESUME_UNCONFIRMED) are unrelated.
        || reason == "RESUME_CHANNEL_DIVERGED"
        || reason.starts_with("TIME_SYNC")
        || reason.starts_with("CONTROL_OBJECT")
        || reason.starts_with("OBJECT_")
        || reason.starts_with("SURVEY_")
        || reason.starts_with("PROTECTED_CUT_")
        || reason.starts_with("LEGACY_")
        || reason.starts_with("CLOCK_");
    let discovery = !migration && DISCOVERY_REASONS.contains(&reason);
    if !migration && !discovery {
        return;
    }
    let mut autonomy = state.autonomy.lock().expect("autonomy poisoned");
    if discovery {
        autonomy.discovery_events += 1;
        autonomy.last_discovery_ms = Some(ms);
        autonomy.last_discovery = Some(reason.to_string());
        return;
    }
    autonomy.migration_events += 1;
    autonomy.last_migration_ms = Some(ms);
    autonomy.last_migration = Some(reason.to_string());
    if let Some(phase) = reason.strip_prefix("PHASE_") {
        autonomy.phase = Some(phase.to_ascii_lowercase());
    } else if let Some(verdict) = reason.strip_prefix("ASSESS_") {
        autonomy.assess = Some(verdict.to_ascii_lowercase());
    } else if let Some(mode) = reason.strip_prefix("MIGRATION_MODE_") {
        autonomy.migration_mode = Some(mode.to_ascii_lowercase());
    }
    if reason.starts_with("AUTOGUARDED_")
        || reason.starts_with("AUTOSURVEY_")
        || reason.starts_with("SURVEY_")
    {
        autonomy.gate_detail = Some(reason.to_string());
    }
}

#[derive(Default)]
struct State {
    device: Option<PathBuf>,
    connected: AtomicBool,
    /// Wall-clock ms of the last successfully decoded inbound frame — the
    /// writer loop's session-liveness signal. Any decodable frame proves
    /// the far end is emitting; silence while Active means the session
    /// died without a wire error (e.g. a gateway reboot that kept the
    /// serial link up).
    last_rx_ms: AtomicU64,
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
    /// Push-receive subscription registry (issue #7): per-connection
    /// subscriptions, bounded staging queues and the pump wakeup channel.
    /// Ids are tagged with host_boot so a pre-restart token can never
    /// resolve into this incarnation.
    subscriptions: subscribe::SubscriptionHub,
    /// Per-connection id source for subscription hub scoping — ids are
    /// process-local and never on the wire.
    next_conn: AtomicU64,
    autonomy: Mutex<AutonomyState>,
    diag_loss: Mutex<DiagLossBaseline>,
    /// Bounded receive log for the API1 `messages.read` surface (Issue #7):
    /// retains actual DataFromMesh payloads as HOST_RAM_RETAINED evidence.
    /// Separate from `events` — the diagnostic ring never carried bodies.
    receive_log: Mutex<ReceiveLog>,
    /// IPC principal→permission table loaded from --api-acl-file; empty ACL
    /// = default deny for privileged API1 methods while diagnostics verbs
    /// keep working.
    acl: Acl,
    /// Operation table for `messages.submit` and the operation queries:
    /// the memory provider by default, the durable SQLite provider once
    /// `--op-store` names a database file. Capabilities and evidence
    /// follow whichever backend is bound.
    operation_store: Mutex<StoreBackend>,
    /// Token buckets guarding `messages.submit`/`operations.open_epoch`
    /// (capacity.host_rate_per_minute + burst). Daemon-wide so the
    /// per-principal and global budgets hold across connections.
    rate_limiter: Mutex<send_store::AdmissionLimiter>,
    /// Verified HostOps response bodies (keyed by our request id) waiting
    /// for the TX-I2 dispatch thread. The read thread posts; the dispatch
    /// thread drains — never the other way, so the USB read path can
    /// never be blocked by store work.
    dispatch_inbox: dispatch::DispatchInbox,
    /// Device-issued GATEWAY_INGRESS (0x11) bodies waiting for the
    /// dispatch thread's storage pass. Separate from `dispatch_inbox`:
    /// these are requests to US (their request id is the device's), and
    /// the ACK must follow storage, never precede it.
    ingress_inbox: dispatch::DispatchInbox,
    /// The host's live registration mirror at the attached gateway —
    /// published once per dispatch pass by the registration lane. api1
    /// reads it for `gateway.resolve` and the schema-2 submit binding.
    gateway_lane: dispatch::GatewayLane,
    /// Config operation registry (P5): api1 submits `config.*` requests and
    /// reads outcomes; the dispatch thread drives them through the lane.
    config_ops: dispatch::ConfigOps,
    /// The daemon's configured config issuer node id (--config-authority).
    /// None means no authority is provisioned — `config.propose` is refused
    /// honestly while challenge/status queries still run.
    config_authority: Option<u64>,
    /// The authority generation bound into each signed permit command
    /// (--config-authority-generation). Provisioned, never auto-incremented.
    config_authority_generation: u32,
    /// Dev-permit master key bytes (--config-dev-key-hex): the issuer and
    /// the target's DevConfigAuthorityVerifier must derive from the same
    /// master — SHA256("RouteLoom/config-dev/v1" || master) on both sides.
    config_dev_key: Vec<u8>,
    /// The issuance profile the lane signs under (--config-profile):
    /// ISSUE_PROFILE_DEV (0) or ISSUE_PROFILE_COSE (1). Reported by
    /// capabilities.get; the lane refuses when the profile's key is absent.
    config_profile: u8,
    /// COSE authority key file (--config-authority-key): the development
    /// `routeloom-config-authority-key-v1` document the lane loads when
    /// the COSE profile is selected. Required iff profile is COSE.
    config_authority_key: Option<PathBuf>,
    /// This daemon run's incarnation id, minted at startup — bound into
    /// every HOST_REGISTER so a restarted daemon is provably a different
    /// host boot to the device (05 §5.6).
    host_boot: u64,
    /// node_status_v1 (HostOps 0x41/0x42) bodies waiting for the node
    /// status thread — separate from `dispatch_inbox` so the page/event
    /// stream never competes with the send lane's replies.
    node_inbox: nodes::NodeInbox,
    /// Per-node link/route status mirrored from the attached gateway: the
    /// source of truth for NODES, `nodes.list`/`nodes.get` and the
    /// node_joined/node_left/link_changed events.
    node_table: Mutex<nodes::NodeTable>,
    /// group_delivery_v1 operation table + lane inbox (HostOps 0x50-0x52):
    /// api1 `group.send`/`group.get` submit and read here, the group lane
    /// thread drives the device exchange and emits `group_settled`.
    group_ops: group::GroupOps,
    /// m1 diagnostics query table (HostOps 0x30/0x31): api1
    /// `diagnostics.snapshot` submits and waits here, the telemetry lane
    /// thread drives the device exchange.
    telemetry_ops: telemetry::TelemetryOps,
    /// SDK v1 Site Authority (--site-authority DIR): EDHOC Responder, member
    /// ledger and the KGuard decision surface. None when not configured.
    site: Option<Arc<site::SiteService>>,
    /// Verified join-relay (HostOps 0x60-0x63) bodies waiting for the site
    /// lane — separate from `dispatch_inbox` so relay traffic never
    /// competes with the send lane's replies. Posted only for
    /// session-verified bodies; the lane additionally gates on the
    /// gateway's CAP_JOIN_RELAY_V2 bit before touching the authority.
    site_inbox: site::usb::SiteInbox,
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

/// Process-monotonic milliseconds — the rewind-proof counterpart of
/// `now_ms` used for deadline budgets (TX-I2 records it on every admitted
/// operation so a wall-clock rewind can never stretch a TTL).
/// `accepted_mono_ms == 0` is the "no monotonic anchor" sentinel in the
/// operation store, so the first sub-millisecond observation clamps to 1.
fn mono_ms() -> u64 {
    static BASE: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
    mono_ms_from_elapsed(BASE.get_or_init(Instant::now).elapsed())
}

/// The sub-millisecond clamp behind `mono_ms`, kept pure so the
/// 0-sentinel boundary is testable without racing the process clock.
fn mono_ms_from_elapsed(elapsed: Duration) -> u64 {
    elapsed.as_millis().max(1) as u64
}

/// Escapes for JSON string contexts: quotes, backslashes and every C0
/// control character (which would otherwise produce invalid JSON — e.g. a
/// raw newline in a device-supplied reason string).
pub(crate) fn json_escape(input: &str) -> String {
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

/// Every event body carries `"kind":"..."`; extract it for the events
/// subscription filter (the serialized json keeps it too).
fn event_kind(fields: &str) -> String {
    const KEY: &str = "\"kind\":\"";
    let Some(start) = fields.find(KEY) else {
        return "unknown".to_string();
    };
    let rest = &fields[start + KEY.len()..];
    let end = rest.find('"').unwrap_or(rest.len());
    rest[..end].to_string()
}

/// First ring entry of every daemon run (seq 0): the journal's restart
/// boundary. Besides the incarnation id it carries the build/config
/// identity an offline inspection record needs — daemon version,
/// operation-store durability, config profile, site authority presence.
/// Values only; no secrets (host_boot is a random per-run tag).
fn boot_event_fields(host_boot: u64, storage: &str, config_profile: u8, site: bool) -> String {
    format!(
        "\"kind\":\"boot\",\"host_boot\":{host_boot},\"daemon\":\"routeloom-host\",\"version\":\"{}\",\"storage\":\"{storage}\",\"config_profile\":{config_profile},\"site\":{site}",
        env!("CARGO_PKG_VERSION"),
    )
}

fn push_event(state: &State, ms: u64, fields: String) {
    // Allocate the sequence under the events lock: concurrent producers
    // otherwise interleave fetch_add and push_back so stored order diverges
    // from seq order.
    let kind = event_kind(&fields);
    {
        let mut events = state.events.lock().expect("events poisoned");
        let seq = state.event_seq.fetch_add(1, Ordering::Relaxed);
        let json = format!("{{\"seq\":{seq},\"ms\":{ms},{fields}}}");
        if events.len() >= MAX_EVENTS {
            events.pop_front();
            state.events_dropped.fetch_add(1, Ordering::Relaxed);
        }
        events.push_back(Event { seq, kind, json });
    }
    // Lock order (DispatchInbox discipline): the data lock is released
    // before the hub is woken, and the pump never holds the hub mutex
    // while acquiring the ring.
    state.subscriptions.notify();
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

fn apply_delivery_patch(
    delivery: &mut Delivery,
    new_state: &str,
    patch: DeliveryPatch,
    updated_ms: u64,
) {
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
}

/// Updates the legacy delivery tracked under `request`; true when one
/// was found. The DeliveryEvent pump uses this to route: a SUBMIT
/// request id must never invent a legacy delivery entry (its outcome
/// attaches to the operation by message key instead).
fn delivery_update_tracked(
    state: &State,
    request: u64,
    new_state: &str,
    patch: DeliveryPatch,
    updated_ms: u64,
) -> bool {
    let mut deliveries = state.deliveries.lock().expect("deliveries poisoned");
    if let Some(delivery) = deliveries.iter_mut().find(|d| d.request == request) {
        apply_delivery_patch(delivery, new_state, patch, updated_ms);
        return true;
    }
    false
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
        apply_delivery_patch(delivery, new_state, patch, updated_ms);
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
                // Feed the bounded receive log: the payload only reaches
                // here after the session layer verified the body, and the
                // network/gateway attribution comes from the authenticated
                // session — never from the payload itself.
                receive_ingest(state, origin, msg_session, msg_seq, &body[20..], ms);
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
                let tail = 22 + usize::from(body[21]);
                let operation_id: Option<&[u8; 24]> = body
                    .get(tail..)
                    .filter(|bytes| bytes.len() == 24)
                    .and_then(|bytes| bytes.try_into().ok());
                // Route by request: a legacy SEND tracks its request id
                // in the deliveries table; a SUBMIT (host-ops) request id
                // never appears there, so its event carries the device
                // outcome for the exact dispatch operation in the trailer.
                // The message key alone can recur after a mesh restart.
                let tracked = delivery_update_tracked(
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
                if !tracked {
                    if let (Some(id), Some(session), Some(seq)) =
                        (operation_id, u32_at(body, 8), u64_at(body, 12))
                    {
                        if let Ok(mut store) = state.operation_store.lock() {
                            let _ = store.attach_device_outcome(
                                id,
                                session,
                                seq,
                                name,
                                reason.as_deref(),
                            );
                        }
                    }
                }
                let dispatch_operation = operation_id.map_or_else(
                    || "null".to_string(),
                    |id| format!("\"{}\"", crate::receive_log::hex_lower(id)),
                );
                push_event(
                    state,
                    ms,
                    format!(
                        "\"kind\":\"delivery_event\",\"request\":{request},\"state\":\"{name}\",\"msg_session\":{},\"msg_seq\":{},\"reason\":{},\"dispatch_operation\":{dispatch_operation}",
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
                // Loss-accounting trailer after the reason (absent on
                // legacy builds — unknown stays null, never synthesized).
                let reason_len = body.get(reason_offset).copied().unwrap_or(0) as usize;
                let tail = reason_offset + 1 + reason_len;
                let (diag_boot, diag_seq, diag_dropped) = if flags & DIAG_FLAG_HAS_ACCOUNTING != 0
                    && body.len() >= tail + DIAG_ACCOUNTING_TAIL
                {
                    (
                        u64_at(body, tail),
                        u32_at(body, tail + 8),
                        u64_at(body, tail + 12),
                    )
                } else {
                    (None, None, None)
                };
                if let Some(peer) = peer {
                    touch_node(state, peer, "peer", ms);
                }
                if let Some(reason_text) = reason.as_deref() {
                    note_autonomy(state, ms, reason_text);
                }
                push_event(
                    state,
                    ms,
                    format!(
                        "\"kind\":\"diagnostic\",\"peer\":{},\"reason\":{},\"msg_session\":{},\"msg_seq\":{},\"diag_boot\":{},\"diag_seq\":{},\"diag_dropped\":{}",
                        json_opt_u64(peer),
                        json_opt_str(reason.as_deref()),
                        msg_session.map_or_else(|| "null".to_string(), |v| v.to_string()),
                        json_opt_u64(msg_seq),
                        json_opt_u64(diag_boot),
                        json_opt_u64(diag_seq.map(u64::from)),
                        json_opt_u64(diag_dropped),
                    ),
                );
                // Gap check after the arrival itself: the ring reads
                // "frame N arrived, and it revealed seqs X..Y missing".
                if let (Some(boot), Some(seq), Some(dropped)) = (diag_boot, diag_seq, diag_dropped)
                {
                    check_diag_loss(state, ms, boot, seq, dropped);
                }
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
            if let Some(request) = request.filter(|r| group::owns_request(*r)) {
                // A 0x50/0x52 the device refused at the frame level: the
                // group lane settles or re-polls the record it belongs to.
                state
                    .group_ops
                    .post_error(request, code.unwrap_or(0), reason.clone());
            }
            if let Some(request) = request.filter(|r| telemetry::owns_request(*r)) {
                // A 0x30 the device refused at the frame level: the query
                // resolves as an error, never a silent timeout.
                state
                    .telemetry_ops
                    .post_error(request, frame.session, code.unwrap_or(0));
            }
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
        // HostOps splits two ways by subcommand: device-issued
        // GATEWAY_INGRESS (0x11) goes to the ingress lane — its ACK must
        // follow storage, and its request id is the device's own — while
        // every other body is a reply to a request WE issued and lands in
        // the dispatcher inbox keyed by our request id. Posting never
        // blocks: a full inbox drops the body and the lane re-queries or
        // the device resends inside its own ack window.
        // node_status_v1 pages/events belong to the node lane. They are not
        // mirrored as host_ops_rx: a resync every few seconds would flush
        // the bounded ring — the lane publishes the transitions instead.
        // group_delivery_v1 0x51 statuses belong to the group lane (same
        // no-mirroring rule: the lane publishes `group_settled` instead).
        FrameKind::HostOps if group::owns(body) => {
            if !state.group_ops.post_status(frame.request, body.to_vec()) {
                push_event(
                    state,
                    ms,
                    "\"kind\":\"rx_drop\",\"reason\":\"group_inbox_full\"".to_string(),
                );
            }
        }
        FrameKind::HostOps if nodes::owns(body) => {
            if !state.node_inbox.post(frame.request, body.to_vec()) {
                push_event(
                    state,
                    ms,
                    "\"kind\":\"rx_drop\",\"reason\":\"node_inbox_full\"".to_string(),
                );
            }
        }
        // m1 diagnostics 0x31 replies belong to the telemetry lane. A
        // refused post is a stale answer past our timeout — expected and
        // silent, never ring spam.
        FrameKind::HostOps if telemetry::owns(body) => {
            state
                .telemetry_ops
                .post_reply(frame.request, frame.session, body.to_vec());
        }
        FrameKind::HostOps if site::owns(body) => {
            if !state.site_inbox.post(frame.request, body.to_vec()) {
                push_event(
                    state,
                    ms,
                    "\"kind\":\"rx_drop\",\"reason\":\"site_inbox_full\"".to_string(),
                );
            }
        }
        FrameKind::HostOps => {
            if routeloom_protocol::host_ops::gateway_sub(body)
                == Some(routeloom_protocol::host_ops::SUB_GATEWAY_INGRESS)
            {
                state.ingress_inbox.post(frame.request, body.to_vec());
            } else {
                state.dispatch_inbox.post(frame.request, body.to_vec());
            }
            push_event(
                state,
                ms,
                format!(
                    "\"kind\":\"host_ops_rx\",\"request\":{},\"body_len\":{}",
                    frame.request,
                    body.len(),
                ),
            );
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

/// Resolve a record's origin assurance from the effective security
/// profile: no Site Authority means the development shared-key profile;
/// otherwise the origin must be ledger-enrolled on this network, or the
/// claim stays unattributed. Runs before the receive-log lock is taken
/// (sequential locks only — site, then ring, then log) and forwards any
/// authority events the lookup drained, so a read never swallows them.
pub(crate) fn ingress_assurance(
    state: &State,
    network: u64,
    origin: u64,
) -> receive_log::RxAssurance {
    let Some(site) = state.site.as_deref() else {
        return receive_log::RxAssurance::DevPskClaim;
    };
    let ((site_network, member), events) = site.with(|a| (a.acl_network(), a.member_state(origin)));
    for (ms, fields) in events {
        push_event(state, ms, fields);
    }
    if site_network == network && member == Some("member") {
        receive_log::RxAssurance::MemberEnrolled
    } else {
        receive_log::RxAssurance::Unverified
    }
}

/// Copy one verified mesh payload into the bounded receive log. Network and
/// gateway attribution come from the authenticated session, never from the
/// payload. Non-stored outcomes (conflict, caps, oversize) surface as bounded
/// diagnostic events — the log is never silently rewritten.
fn receive_ingest(
    state: &State,
    origin: Option<u64>,
    msg_session: Option<u32>,
    msg_seq: Option<u64>,
    payload: &[u8],
    ms: u64,
) {
    let (Some(origin), Some(msg_session), Some(msg_seq)) = (origin, msg_session, msg_seq) else {
        return;
    };
    let (network, gateway) = {
        let session = state.session.lock().expect("session poisoned");
        (session.network, session.node)
    };
    let Some(network) = network else {
        push_event(
            state,
            ms,
            "\"kind\":\"rx_drop\",\"reason\":\"network_unknown\"".to_string(),
        );
        return;
    };
    // Wire v1 networks are 1..=0xffffffff; anything else from the adapter
    // cannot be attributed to a valid network, so it is dropped + noted.
    if !(1..=0xffff_ffff).contains(&network) {
        push_event(
            state,
            ms,
            "\"kind\":\"rx_drop\",\"reason\":\"network_out_of_range\"".to_string(),
        );
        return;
    }
    // Reserved node ids can never appear on the wire (01 §6): an adapter
    // minting origin 0/u64::MAX is dropped + noted like the other guards.
    if canonical::is_reserved_node_id(origin) {
        push_event(
            state,
            ms,
            "\"kind\":\"rx_drop\",\"reason\":\"origin_reserved\"".to_string(),
        );
        return;
    }
    // Attribution is fixed before the record is stored, from the
    // ledger — never from payload self-claims.
    let assurance = ingress_assurance(state, network, origin);
    let outcome = {
        let outcome = state
            .receive_log
            .lock()
            .expect("receive log poisoned")
            .ingest(
                Ingress {
                    network,
                    gateway,
                    origin,
                    msg_session,
                    msg_seq,
                    payload: payload.to_vec(),
                    assurance,
                },
                ms,
            );
        outcome
    };
    // Wake subscription pumps and parked messages.read waiters — the log
    // lock is already released before the hub is notified (lock order).
    state.subscriptions.notify();
    if let Some(fields) = api1::ingest_diagnostic(&outcome) {
        push_event(state, ms, fields);
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

/// Legacy `NODES` view: the union of nodes observed in USB traffic and the
/// node_status_v1 table. Reachability/rssi/hop_count come from the
/// gateway's status report when one exists; membership comes from the
/// Site Authority ledger when one is configured — a route state must
/// never pose as membership ("left" for a lost route misled triage).
/// A node the report does not cover — or any node while no capable
/// session is live — stays "unknown"/null: absent data is never
/// presented as observed.
fn nodes_json(state: &State) -> String {
    let observed: Vec<(u64, &'static str, u64)> = state
        .nodes
        .lock()
        .expect("nodes poisoned")
        .iter()
        .map(|node| (node.id, node.role, node.seen_ms))
        .collect();
    let table = state.node_table.lock().expect("node table poisoned");
    let live = matches!(table.source(), nodes::Source::Live | nodes::Source::Syncing);
    let mut ids: Vec<u64> = observed.iter().map(|(id, ..)| *id).collect();
    let (records, _) = table.list(0, nodes::TABLE_CAP, None);
    ids.extend(records.iter().map(|record| record.node));
    ids.sort_unstable();
    ids.dedup();
    let mut out = format!("{{\"source\":{},\"nodes\":[", nodes::source_json(&table));
    for (index, id) in ids.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        let seen = observed.iter().find(|(node, ..)| node == id);
        let record = table.get(*id);
        let role = match (record, seen) {
            (Some(record), _) if record.gateway => "adapter",
            (_, Some((_, role, _))) => role,
            _ => "peer",
        };
        let reachability = match record {
            Some(record) if live || record.gateway => {
                if record.connected {
                    "reachable"
                } else {
                    "unreachable"
                }
            }
            _ => "unknown",
        };
        // Membership is a ledger fact, not a route observation: without
        // a site authority — or for a node the ledger never admitted —
        // it stays honestly unknown.
        let membership = state
            .site
            .as_ref()
            .and_then(|service| service.with(|a| a.member_state(*id)).0)
            .unwrap_or("unknown");
        let status = record.and_then(nodes::NodeRecord::live_status);
        let rssi = status
            .filter(|s| s.rssi_valid())
            .map_or_else(|| "null".to_string(), |s| s.rssi_last_dbm.to_string());
        let hops = record
            .and_then(nodes::NodeRecord::hops)
            .map_or_else(|| "null".to_string(), |h| h.to_string());
        let link_cost = status
            .filter(|s| s.neighbor_active())
            .map_or_else(|| "null".to_string(), |s| s.link_cost.to_string());
        out.push_str(&format!(
            "{{\"id\":{id},\"role\":\"{role}\",\"seen_ms\":{},\"membership\":\"{membership}\",\"reachability\":\"{reachability}\",\"rssi_dbm\":{rssi},\"lr250\":\"unknown\",\"hop_count\":{hops},\"last_heard_ms\":{},\"link_cost\":{link_cost}}}",
            json_opt_u64(seen.map(|(_, _, ms)| *ms)),
            json_opt_u64(record.and_then(|r| r.last_heard_ms)),
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

/// The autonomy view is assembled only from real device Diagnostic events;
/// every field is null until the device emits it. This is a host-side view
/// of an EXPERIMENTAL lane — it is not RF validation and carries no
/// production-qualification claim.
fn autonomy_json(state: &State) -> String {
    let autonomy = state.autonomy.lock().expect("autonomy poisoned");
    let last = |ms: Option<u64>, reason: &Option<String>| -> String {
        match (ms, reason.as_deref()) {
            (Some(ms), Some(reason)) => {
                format!("{{\"ms\":{ms},\"reason\":\"{}\"}}", json_escape(reason))
            }
            _ => "null".to_string(),
        }
    };
    format!(
        "{{\"migration_mode\":{},\"participant_phase\":{},\"assess_verdict\":{},\"gate_detail\":{},\"last_discovery\":{},\"last_migration\":{},\"discovery_events\":{},\"migration_events\":{},\"experimental\":true}}",
        json_opt_str(autonomy.migration_mode.as_deref()),
        json_opt_str(autonomy.phase.as_deref()),
        json_opt_str(autonomy.assess.as_deref()),
        json_opt_str(autonomy.gate_detail.as_deref()),
        last(autonomy.last_discovery_ms, &autonomy.last_discovery),
        last(autonomy.last_migration_ms, &autonomy.last_migration),
        autonomy.discovery_events,
        autonomy.migration_events,
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
                // Timed decode: a partial frame stalled past one second is
                // dropped before these bytes, so it can never glue onto a
                // later frame (usb-protocol.md §framing, firmware rule).
                for result in decoder.push_timed(&buffer[..count], mono_ms()) {
                    match result {
                        Ok(frame) => {
                            state.rx_frames.fetch_add(1, Ordering::Relaxed);
                            // Any well-formed frame is link liveness — the
                            // session layer separately decides whether it
                            // belongs to the live session.
                            state.last_rx_ms.store(now_ms(), Ordering::Relaxed);
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
    if inbound.session_lost {
        // The session died at the far end (stale-session echo, fatal
        // error, tag desync): the mirror and the gateway registration
        // bound to that session can never be inherited — clear them
        // before the re-hello's new binding lands. Mirrors the adapter
        // teardown in adapter_supervisor, minus the fd.
        {
            let mut info = state.session.lock().expect("session poisoned");
            *info = SessionInfo::default();
        }
        state.gateway_lane.clear();
    }
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
        if info.id != Some(session_id) {
            // A new authenticated session can never inherit the previous
            // session's gateway registration — clear the mirror
            // immediately; the dispatch lane re-registers under the new
            // binding on its next pass.
            state.gateway_lane.clear();
        }
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
    let mut last_tx_ms = 0_u64;
    loop {
        // The tick serves two timers: a lost handshake frame is re-sent every
        // HELLO_RETRY_MS until the session reaches Active, and an idle active
        // session gets a sealed KeepAlive so the device sees liveness (and a
        // dead session is noticed at the next failed authentication).
        let item = match outbound.recv_timeout(std::time::Duration::from_millis(HELLO_RETRY_MS)) {
            Ok(item) => item,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let now = now_ms();
                let mut guard = session.lock().expect("device session poisoned");
                // Silent-peer watchdog: the adapter can stay open while the
                // gateway reboots behind it — our sealed frames are then
                // dropped unanswered and nothing ever errors the read. A
                // session with no inbound traffic for SESSION_LIVENESS_MS
                // is torn down and re-handshaken in place; the link layer
                // is provably alive, so no adapter reopen is needed.
                if guard.phase == SessionPhase::Active
                    && session_stalled(now, state.last_rx_ms.load(Ordering::Relaxed))
                {
                    let hello = guard.begin();
                    drop(guard);
                    // The registration mirror and the authenticated view
                    // belong to the dead session — same teardown as an
                    // adapter drop, minus the fd.
                    {
                        let mut info = state.session.lock().expect("session poisoned");
                        *info = SessionInfo::default();
                    }
                    state.gateway_lane.clear();
                    push_event(
                        &state,
                        now,
                        "\"kind\":\"session\",\"state\":\"stalled\",\"detail\":\"no inbound traffic; restarting handshake\""
                            .to_string(),
                    );
                    match transmit(&writer_slot, &state, &hello) {
                        Ok(_) => last_tx_ms = now,
                        Err(error) => set_error(&state, error.to_string()),
                    }
                    continue;
                }
                if guard.handshake_retry_due(now) {
                    // The writer is the only place allowed to emit frames,
                    // so the re-Hello is written here directly rather than
                    // re-enqueued into our own queue.
                    let hello = guard.begin();
                    drop(guard);
                    if let Err(error) = transmit(&writer_slot, &state, &hello) {
                        set_error(&state, error.to_string());
                    } else {
                        last_tx_ms = now;
                    }
                    continue;
                }
                let keepalive_due = guard.phase == SessionPhase::Active
                    && now.saturating_sub(last_tx_ms) >= KEEPALIVE_INTERVAL.as_millis() as u64;
                drop(guard);
                if !keepalive_due {
                    continue;
                }
                Outbound::Seal(Frame {
                    kind: FrameKind::KeepAlive,
                    flags: 0,
                    session: 0,
                    request: 0,
                    body: Vec::new(),
                })
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return,
        };
        let mut frame = match item {
            // Handshake frames are unprotected by design — write as-is.
            Outbound::Raw(frame) => {
                match transmit(&writer_slot, &state, &frame) {
                    Ok(_) => last_tx_ms = now_ms(),
                    Err(error) => set_error(&state, error.to_string()),
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
                last_tx_ms = now_ms();
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

/// Bounded exponential backoff for adapter (re)open attempts: an unplugged
/// cable can come back at any time, but a permanently missing device must
/// not spin the retry loop. Doubles from 500ms to a 5s ceiling; a
/// successful attach resets the streak to the fast retry.
struct ReconnectBackoff {
    delay_ms: u64,
}

impl ReconnectBackoff {
    const INITIAL_MS: u64 = 500;
    const MAX_MS: u64 = 5_000;

    fn new() -> Self {
        Self {
            delay_ms: Self::INITIAL_MS,
        }
    }

    /// The delay before the next attempt; doubles toward the cap.
    fn next(&mut self) -> std::time::Duration {
        let delay = self.delay_ms;
        self.delay_ms = self.delay_ms.saturating_mul(2).min(Self::MAX_MS);
        std::time::Duration::from_millis(delay)
    }

    /// A successful attach restarts the streak from the fast retry.
    fn reset(&mut self) {
        self.delay_ms = Self::INITIAL_MS;
    }
}

/// Renders the `adapter/disconnected` event: the read-loop error (OS
/// message plus errno when the OS supplied one) rides along so a cut
/// cable, a dead writer, and a clean EOF read differently in the journal.
fn adapter_drop_event(result: &io::Result<()>) -> String {
    match result {
        Ok(()) => "\"kind\":\"adapter\",\"state\":\"disconnected\"".to_string(),
        Err(error) => format!(
            "\"kind\":\"adapter\",\"state\":\"disconnected\",\"detail\":\"{}\",\"os_error\":{}",
            json_escape(&error.to_string()),
            error
                .raw_os_error()
                .map_or_else(|| "null".to_string(), |code| code.to_string()),
        ),
    }
}

fn adapter_supervisor(
    device: PathBuf,
    state: Arc<State>,
    writer_slot: Arc<Mutex<Option<File>>>,
    session: Arc<Mutex<DeviceSession>>,
    outbound: mpsc::SyncSender<Outbound>,
) {
    let mut backoff = ReconnectBackoff::new();
    // Open failures are logged once per streak, not per retry — the event
    // ring must not flush on a missing device.
    let mut open_failed = false;
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
                backoff.reset();
                open_failed = false;
                {
                    let mut info = state.session.lock().expect("session poisoned");
                    *info = SessionInfo::default();
                }
                // A reconnect is a brand-new USB session: the gateway
                // registration bound to the dead session can never be
                // inherited — the lane re-registers on its next pass.
                state.gateway_lane.clear();
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
                // Link lost: the registration bound to the dead session is
                // stale — clear it so no schema-2 canonical can still cite
                // the token (a reconnect re-registers under a fresh one).
                state.gateway_lane.clear();
                if let Err(error) = &result {
                    set_error(&state, error.to_string());
                }
                push_event(&state, now_ms(), adapter_drop_event(&result));
            }
            Err(error) => {
                if !open_failed {
                    open_failed = true;
                    push_event(
                        &state,
                        now_ms(),
                        format!(
                            "\"kind\":\"adapter\",\"state\":\"open_failed\",\"detail\":\"{}\"",
                            json_escape(&error.to_string())
                        ),
                    );
                }
                set_error(&state, format!("adapter open failed: {error}"));
            }
        }
        // Bounded exponential backoff: cable reconnects do not require a
        // daemon restart, and a missing device cannot spin the retry loop.
        thread::sleep(backoff.next());
    }
}

// The argument list mirrors the accept loop's per-connection handoff;
// boxing it into a struct would only rename the same state.
#[allow(clippy::too_many_arguments)]
fn serve_client(
    stream: UnixStream,
    state: Arc<State>,
    outbound: mpsc::SyncSender<Outbound>,
    _process_session: u64,
    next_request: Arc<AtomicU64>,
    next_idem_key: Arc<AtomicU64>,
    device_session: Arc<Mutex<DeviceSession>>,
    peer_uid: Option<u32>,
) -> io::Result<()> {
    // A slow socket must never pin the shared log or hang this thread.
    let _ = stream.set_write_timeout(Some(CLIENT_WRITE_TIMEOUT));
    let reader_stream = stream.try_clone()?;
    let mut reader = BufReader::new(reader_stream);
    // The writer is shared with this connection's subscription pump:
    // notification lines and response lines serialize under one mutex so
    // neither can interleave mid-line.
    let writer = Arc::new(Mutex::new(stream));
    // Process-local connection id scoping this connection's subscriptions;
    // the drop guard fails the pump's liveness flag even on early returns.
    let conn_id = state.next_conn.fetch_add(1, Ordering::Relaxed);
    let conn_alive = Arc::new(AtomicBool::new(true));
    struct ConnTeardown {
        alive: Arc<AtomicBool>,
        state: Arc<State>,
        conn_id: u64,
    }
    impl Drop for ConnTeardown {
        fn drop(&mut self) {
            self.alive.store(false, Ordering::Relaxed);
            self.state.subscriptions.remove_conn(self.conn_id);
        }
    }
    let _conn_guard = ConnTeardown {
        alive: conn_alive.clone(),
        state: Arc::clone(&state),
        conn_id,
    };
    // Raw byte line buffer: IPC requests are validated as UTF-8 *after*
    // framing so an invalid API1 line gets an explicit error, not a dropped
    // connection.
    let mut raw: Vec<u8> = Vec::with_capacity(256);
    loop {
        raw.clear();
        // Bounded line read — `take` caps consumption at the IPC request
        // budget (8192B, newline included). A line that fills the cap
        // without a terminating newline is oversize: it cannot be resynced
        // safely, so it gets one error response and the connection closes.
        let read = reader
            .by_ref()
            .take(api1::REQUEST_MAX_BYTES as u64)
            .read_until(b'\n', &mut raw)?;
        if read == 0 {
            return Ok(());
        }
        if raw.len() == api1::REQUEST_MAX_BYTES && !raw.ends_with(b"\n") {
            {
                let mut w = writer.lock().expect("writer poisoned");
                let _ = w.write_all(
                    b"{\"v\":1,\"request_id\":null,\"ok\":false,\"error\":{\"code\":\"INVALID_REQUEST\",\"detail\":{\"message\":\"request exceeds 8192 bytes\"},\"retryable\":false}}\n",
                );
                let _ = w.flush();
                // Lingering close: half-close our write side, then drain
                // whatever the client still has in flight. Closing with
                // unread inbound data makes Linux send RST, which can
                // destroy the error response we just wrote.
                let _ = w.shutdown(std::net::Shutdown::Write);
                let _ = w.set_read_timeout(Some(Duration::from_millis(200)));
            }
            let mut sink = [0u8; 4096];
            let mut drained = 0usize;
            while drained < 1_048_576 {
                match reader.read(&mut sink) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => drained += n,
                }
            }
            return Ok(());
        }
        while matches!(raw.last(), Some(b'\n' | b'\r')) {
            raw.pop();
        }
        if raw.is_empty() {
            continue;
        }
        let (response, effect) = if raw.starts_with(b"API1 ") {
            let ctx = api1::ApiContext {
                uid: peer_uid,
                acl: &state.acl,
                receive_log: &state.receive_log,
                operation_store: &state.operation_store,
                rate_limiter: &state.rate_limiter,
                session: &state.session,
                gateway_lane: &state.gateway_lane,
                node_table: &state.node_table,
                config_ops: &state.config_ops,
                group_ops: &state.group_ops,
                telemetry_ops: &state.telemetry_ops,
                site: state.site.as_deref(),
                config_authority: state.config_authority,
                config_profile: state.config_profile,
                link: api1::LinkStatus {
                    configured: state.device.is_some(),
                    connected: state.connected.load(Ordering::Relaxed),
                    last_error: state
                        .last_error
                        .lock()
                        .expect("last_error poisoned")
                        .clone(),
                },
                subscriptions: &state.subscriptions,
                conn_id,
                event_ring: api1::EventRing {
                    events: &state.events,
                    next_seq: &state.event_seq,
                    dropped: &state.events_dropped,
                },
                now_ms: now_ms(),
                now_mono: mono_ms(),
            };
            api1::handle_conn(&raw[b"API1 ".len()..], &ctx)
        } else {
            (
                match std::str::from_utf8(&raw) {
                    Err(_) => "{\"error\":\"request line is not valid UTF-8\"}".to_string(),
                    Ok(line) => {
                        let fields: Vec<&str> = line.split_whitespace().collect();
                        if fields.is_empty() {
                            continue;
                        }
                        match fields[0].to_ascii_uppercase().as_str() {
            "STATUS" | "DIAGNOSTICS" => status_json(&state),
            "ADAPTER" => adapter_json(&state),
            "NODES" => nodes_json(&state),
            "DELIVERIES" => deliveries_json(&state),
            "EVENTS" => events_json(&state),
            "AUTHORITY" => authority_json(&state),
            "AUTONOMY" => autonomy_json(&state),
            "SEND" if fields.len() == 3 => {
                let destination = fields[1].parse::<u64>();
                let payload = parse_hex(fields[2]);
                // The device bridge only accepts DataToMesh inside an
                // authenticated session — reject early with a clear error
                // instead of queueing a frame the writer must drop.
                let active_session = {
                    let guard = device_session.lock().expect("device session poisoned");
                    (guard.phase == SessionPhase::Active).then_some(guard.session_id)
                };
                // Legacy mode is still gated by the same contract as
                // messages.submit: the USB host authority is never granted
                // unconditionally to every local client
                // (05-production-security.md). The peer's OS uid must hold
                // SEND on the session's own network — an unknown
                // credential or an absent session network denies.
                let session_network = state
                    .session
                    .lock()
                    .expect("session poisoned")
                    .network;
                let send_uid = match (peer_uid, session_network) {
                    (Some(uid), Some(network))
                        if state.acl.permit(uid, network, acl::PERM_SEND) =>
                    {
                        Some(uid)
                    }
                    _ => None,
                };
                match (destination, payload) {
                    _ if send_uid.is_none() => {
                        "{\"accepted\":false,\"error\":\"authorization failed\"}".into()
                    }
                    _ if active_session.is_none() => {
                        "{\"accepted\":false,\"error\":\"session not authenticated\"}".into()
                    }
                    (Ok(destination), Ok(payload)) if payload.len() <= 128 => {
                        if canonical::is_reserved_node_id(destination) {
                            "{\"accepted\":false,\"error\":\"reserved destination node id\"}".into()
                        } else if let Err(deny) = state
                            .rate_limiter
                            .lock()
                            .expect("rate limiter poisoned")
                            .admit(send_uid.expect("authorized above"), now_ms())
                        {
                            format!(
                                "{{\"accepted\":false,\"error\":\"rate limited ({} scope, retry in {} ms)\"}}",
                                deny.scope, deny.retry_after_ms
                            )
                        } else {
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
                            session: active_session.expect("authenticated above"),
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
                    }
                    (Ok(_), Ok(_)) => {
                        "{\"accepted\":false,\"error\":\"payload exceeds 128 bytes\"}".into()
                    }
                    _ => "{\"accepted\":false,\"error\":\"invalid SEND syntax\"}".into(),
                }
            }
            "QUIT" => return Ok(()),
            _ => "{\"error\":\"commands: STATUS, DIAGNOSTICS, SEND <node> <hex>, ADAPTER, NODES, DELIVERIES, EVENTS, AUTHORITY, AUTONOMY, QUIT — or API1 <json>\"}".into(),
                    }
                    }
                },
                None,
            )
        };
        {
            let mut w = writer.lock().expect("writer poisoned");
            w.write_all(response.as_bytes())?;
            w.write_all(b"\n")?;
            w.flush()?;
        }
        // §5.8 rule 1 (05-receive-api): a subscription's first notification
        // must never precede the ok that created it — the effect is applied
        // only after the response line is flushed.
        if let Some(api1::ConnEffect::Subscribed { id }) = effect {
            if state.subscriptions.activate(conn_id, id) {
                // First live subscription on this connection — spawn its
                // pump. The pump exits on conn_alive (guard above) or when
                // the hub reports the connection gone.
                let pump_state = Arc::clone(&state);
                let pump_writer = Arc::clone(&writer);
                let pump_alive = Arc::clone(&conn_alive);
                thread::spawn(move || {
                    subscribe::pump_connection(pump_state, conn_id, pump_writer, pump_alive);
                });
            }
        }
    }
}

struct DaemonArgs {
    socket: PathBuf,
    device: Option<PathBuf>,
    acl_file: Option<PathBuf>,
    op_store: Option<PathBuf>,
    config_authority: Option<u64>,
    config_authority_generation: u32,
    config_dev_key: Vec<u8>,
    config_profile: u8,
    config_authority_key: Option<PathBuf>,
    site_authority: Option<PathBuf>,
}

/// Parse a node/authority id argument as hexadecimal — the codebase's node
/// id convention (e.g. `3` or `0000000000000003`). Accepts an optional `0x`.
fn parse_hex_id(text: &str, flag: &str) -> Result<u64, String> {
    u64::from_str_radix(text.trim_start_matches("0x"), 16)
        .map_err(|_| format!("{flag} requires a hexadecimal id"))
}

/// Decode a `--config-dev-key-hex` master: an even-length hex string whose
/// bytes feed `SHA256("RouteLoom/config-dev/v1" || master)` — the identical
/// derivation the firmware target performs on its own Kconfig key.
fn parse_dev_key_hex(text: &str, flag: &str) -> Result<Vec<u8>, String> {
    let hex = text.trim_start_matches("0x");
    if hex.len() % 2 != 0 || hex.is_empty() {
        return Err(format!("{flag} requires an even-length hex string"));
    }
    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("{flag} requires an even-length hex string"))
        })
        .collect()
}

fn parse_args() -> Result<DaemonArgs, String> {
    parse_args_from(env::args().skip(1))
}

fn parse_args_from(args: impl Iterator<Item = String>) -> Result<DaemonArgs, String> {
    let mut socket = PathBuf::from("/tmp/routeloom.sock");
    let mut device = None;
    let mut acl_file = None;
    let mut op_store = None;
    let mut config_authority = None;
    let mut config_authority_generation = 1;
    let mut config_dev_key_hex = DEFAULT_CONFIG_DEV_KEY_HEX.to_string();
    let mut config_profile = config::ISSUE_PROFILE_DEV;
    let mut config_authority_key = None;
    let mut site_authority = None;
    let mut args = args;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--socket" => socket = PathBuf::from(args.next().ok_or("--socket requires a path")?),
            "--device" => {
                device = Some(PathBuf::from(
                    args.next().ok_or("--device requires a path")?,
                ))
            }
            // uid → per-network permission map for privileged API1 methods;
            // see acl.rs for the file format. Absent = default deny.
            "--api-acl-file" => {
                acl_file = Some(PathBuf::from(
                    args.next().ok_or("--api-acl-file requires a path")?,
                ))
            }
            // Durable operation-store file (CAP-I1). Absent = memory
            // provider: RAM_ONLY submits only, storage_durable:false.
            "--op-store" => {
                op_store = Some(PathBuf::from(
                    args.next().ok_or("--op-store requires a path")?,
                ))
            }
            // Config issuer node id the daemon signs permits under (P5).
            // Absent = no authority provisioned: config.propose is refused
            // while challenge/status queries still run.
            "--config-authority" => {
                let text = args.next().ok_or("--config-authority requires a hex id")?;
                config_authority = Some(parse_hex_id(&text, "--config-authority")?);
            }
            // Authority generation bound into each signed command — must
            // match the generation the target permits.
            "--config-authority-generation" => {
                config_authority_generation = args
                    .next()
                    .ok_or("--config-authority-generation requires a number")?
                    .parse::<u32>()
                    .map_err(|_| "--config-authority-generation must be an integer")?;
            }
            // Dev-profile permit master (hex) — must equal the target's
            // ROUTELOOM_DEVELOPMENT_KEY_HEX or every signed permit fails
            // AuthorityDenied on the device. Default = the firmware's own
            // Kconfig placeholder so a default pair agrees end to end.
            "--config-dev-key-hex" => {
                config_dev_key_hex = args
                    .next()
                    .ok_or("--config-dev-key-hex requires a hex key")?;
            }
            // Issuance profile: `dev` (HMAC under the dev master) or
            // `cose` (RLCP1_COSE_ESP256 under --config-authority-key).
            // The COSE key's authority id must equal --config-authority.
            "--config-profile" => {
                let text = args.next().ok_or("--config-profile requires dev|cose")?;
                config_profile = match text.as_str() {
                    "dev" => config::ISSUE_PROFILE_DEV,
                    "cose" => config::ISSUE_PROFILE_COSE,
                    _ => return Err("--config-profile must be dev or cose".to_string()),
                };
            }
            // COSE authority key file (development
            // `routeloom-config-authority-key-v1` document — see
            // `routeloomctl provision-authority-keygen`). Required iff
            // --config-profile=cose; refused otherwise (a key the
            // selected profile would never consult must not linger).
            "--config-authority-key" => {
                config_authority_key = Some(PathBuf::from(
                    args.next()
                        .ok_or("--config-authority-key requires a path")?,
                ));
            }
            // SDK v1 Site Authority directory (site-authority.json, sak.key,
            // site.db — site::config). Absent = no Site Authority: the
            // site methods answer SITE_AUTHORITY_UNAVAILABLE.
            "--site-authority" => {
                site_authority = Some(PathBuf::from(
                    args.next().ok_or("--site-authority requires a directory")?,
                ))
            }
            "--help" | "-h" => {
                println!(
                    "routeloom-host [--socket PATH] [--device TTY] [--api-acl-file PATH] [--op-store PATH] [--config-authority HEX] [--config-authority-generation N] [--config-dev-key-hex HEX] [--config-profile dev|cose] [--config-authority-key PATH] [--site-authority DIR]"
                );
                process::exit(0);
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    // Reserved ids are never a valid issuer: capabilities would report an
    // authority configured while every propose is denied downstream, and
    // generation 0 can never satisfy the firmware Kconfig minimum of 1.
    if matches!(config_authority, Some(0) | Some(u64::MAX)) {
        return Err("--config-authority must not be a reserved id".to_string());
    }
    if config_authority_generation == 0 {
        return Err("--config-authority-generation must be >= 1".to_string());
    }
    // The COSE profile without its key would refuse every issuance at
    // runtime; the dev profile with a key file would silently ignore the
    // file — both are arg errors, not runtime mysteries.
    if config_profile == config::ISSUE_PROFILE_COSE && config_authority_key.is_none() {
        return Err("--config-profile=cose requires --config-authority-key".to_string());
    }
    if config_profile != config::ISSUE_PROFILE_COSE && config_authority_key.is_some() {
        return Err("--config-authority-key requires --config-profile=cose".to_string());
    }
    Ok(DaemonArgs {
        socket,
        device,
        acl_file,
        op_store,
        config_authority,
        config_authority_generation,
        config_dev_key: parse_dev_key_hex(&config_dev_key_hex, "--config-dev-key-hex")?,
        config_profile,
        config_authority_key,
        site_authority,
    })
}

/// Bind the control socket and tighten its file mode before any client
/// can connect: 0600 restricts IPC to the owning uid on Linux (macOS
/// ignores unix-socket file perms on connect() — the mode still
/// documents intent). A world-writable parent outside the system temp
/// dir warns but does not fail: dev environments bind there legitimately.
fn bind_api_listener(socket_path: &Path) -> io::Result<UnixListener> {
    let listener = UnixListener::bind(socket_path)?;
    std::fs::set_permissions(socket_path, std::fs::Permissions::from_mode(0o600))?;
    if let Some(parent) = socket_path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let world_writable = std::fs::metadata(parent)
            .map(|m| m.permissions().mode() & 0o002 != 0)
            .unwrap_or(false);
        if world_writable {
            let canonical_parent = parent.canonicalize().ok();
            let is_temp = [
                env::temp_dir(),
                PathBuf::from("/tmp"),
                PathBuf::from("/var/tmp"),
            ]
            .iter()
            .any(|d| {
                d == parent
                    || (canonical_parent.is_some()
                        && d.canonicalize().ok().as_ref() == canonical_parent.as_ref())
            });
            if !is_temp {
                eprintln!(
                    "warning: socket directory {} is world-writable; another local user could replace the socket file — prefer a private directory",
                    parent.display()
                );
            }
        }
    }
    Ok(listener)
}

/// Restores the global and per-principal connection counts when a client
/// thread exits — normally or by panic (unwinding runs Drop). Without it
/// a panicking handler would leak a slot forever: MAX_CLIENTS panics
/// would permanently refuse every new client. Zeroed per-principal
/// entries are removed so the map cannot accumulate dead principals.
struct ClientGuard {
    active: Arc<AtomicUsize>,
    principals: Arc<Mutex<HashMap<Option<u32>, usize>>>,
    uid: Option<u32>,
}

impl Drop for ClientGuard {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
        // Poison-tolerant: a panic elsewhere that poisoned this mutex must
        // not turn the decrement into a second panic during unwind.
        let mut counts = self
            .principals
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let emptied = match counts.get_mut(&self.uid) {
            Some(entry) => {
                *entry = entry.saturating_sub(1);
                *entry == 0
            }
            None => false,
        };
        if emptied {
            counts.remove(&self.uid);
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Anchor the monotonic base at process start — `mono_ms` is the
    // rewind-proof deadline axis, so it should measure daemon uptime rather
    // than time-since-first-admitted-operation.
    let _ = mono_ms();
    let args = parse_args().map_err(io::Error::other)?;
    let socket_path = args.socket;
    let device = args.device;
    let acl_path = args.acl_file;
    // A malformed ACL file is a hard startup error — silently degrading to
    // default-deny could surprise operators who believe grants are active.
    let acl = match &acl_path {
        Some(path) => {
            Acl::load(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?
        }
        None => Acl::empty(),
    };
    if acl_path.is_some() {
        eprintln!("api acl loaded: revision {}", acl.revision());
    }
    // Same for the durable store: a suspect database refuses to start
    // rather than serving old keys under a fresh empty lineage.
    let operation_store = match &args.op_store {
        Some(path) => {
            let store = sqlite_store::SqliteOperationStore::open(path)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            eprintln!(
                "operation store: sqlite at {} (lineage {})",
                path.display(),
                receive_log::hex_lower(&store.lineage())
            );
            // The store lineage IS the dispatcher identity on the wire —
            // same lane hazard as the memory store below: a freshly
            // created database means a new lineage, and a gateway still
            // bound to a lost store's lineage rejects every dispatch
            // verb with LaneMismatch until it reboots. First-ever boots
            // hit this too, so the wording stays conditional.
            if store.was_created_fresh() {
                eprintln!(
                    "warning: operation store created fresh (lineage {}) — if this replaces a lost or corrupt store, any gateway still bound to the old lineage rejects dispatch with LaneMismatch until it is rebooted",
                    receive_log::hex_lower(&store.lineage())
                );
            }
            StoreBackend::Sqlite(Box::new(store))
        }
        None => {
            eprintln!("operation store: memory (RAM_ONLY only; pass --op-store for durability)");
            // The store lineage IS the dispatcher identity on the wire.
            // A memory store mints a fresh lineage at every start, so a
            // daemon restart moves the dispatch lane and the device
            // answers LaneMismatch until the gateway reboots. Dispatch
            // is deliberately not blocked — RAM_ONLY operations are
            // best-effort — but the restart semantics are documented
            // loudly here and in capabilities (storage_durable:false).
            eprintln!(
                "warning: memory operation store — a daemon restart requires a gateway reboot for dispatch (the device rejects the new lane with LaneMismatch); pass --op-store for a durable lane"
            );
            StoreBackend::Memory(Box::new(MemoryOperationStore::new(mint_id128())))
        }
    };
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
    // The daemon's incarnation id for HOST_REGISTER: fresh per run,
    // nonzero and non-reserved so a restarted daemon can never alias the
    // previous run's registration (05 §5.6 host_boot).
    let mut host_boot = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64
        ^ u64::from(process::id()).rotate_left(32);
    if host_boot == 0 || host_boot == u64::MAX {
        host_boot ^= 0x5A;
    }
    // SDK v1 Site Authority: a directory that does not open (wrong SAK,
    // store of another site, broken ledger) is a hard start error.
    let site = match &args.site_authority {
        Some(dir) => {
            let authority = site::config::open_dir(dir, now_ms())
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            eprintln!(
                "site authority: site {:016x} network {:016x} (EXPERIMENTAL; USB join relay 0x60-0x63 serves capable sessions)",
                authority.site_id(),
                authority.network()
            );
            Some(Arc::new(site::SiteService::new(authority)))
        }
        None => None,
    };
    let state = Arc::new(State {
        device: device.clone(),
        site,
        receive_log: Mutex::new(ReceiveLog::new(mint_id128())),
        operation_store: Mutex::new(operation_store),
        acl,
        host_boot,
        // Config op tokens are namespaced to this daemon incarnation so a
        // `config.get` token from before a restart can never resolve to a
        // different op minted by the new boot (RAM-only ids).
        config_ops: dispatch::ConfigOps::with_boot(host_boot),
        group_ops: group::GroupOps::with_boot(host_boot),
        subscriptions: subscribe::SubscriptionHub::with_boot(host_boot),
        config_authority: args.config_authority,
        config_authority_generation: args.config_authority_generation,
        config_dev_key: args.config_dev_key,
        config_profile: args.config_profile,
        config_authority_key: args.config_authority_key.clone(),
        ..State::default()
    });
    // The ring opens with the run's own restart boundary — before the
    // dispatch thread or any client can push, so it is always seq 0.
    push_event(
        &state,
        now_ms(),
        boot_event_fields(
            host_boot,
            if args.op_store.is_some() {
                "sqlite"
            } else {
                "memory"
            },
            args.config_profile,
            args.site_authority.is_some(),
        ),
    );
    // Fail fast on an unloadable COSE key: the lane would otherwise refuse
    // every issuance at runtime with the cause buried in a dispatch log.
    if args.config_profile == config::ISSUE_PROFILE_COSE {
        let path = args.config_authority_key.as_ref().expect("arg-validated");
        match routeloom_provision::signer::FileAuthoritySigner::load(path) {
            Ok(signer) => {
                if Some(signer.authority_id()) != args.config_authority {
                    eprintln!(
                        "config authority key {} names authority {:016x}, not the configured {:016x}",
                        path.display(),
                        signer.authority_id(),
                        args.config_authority.unwrap_or(0)
                    );
                    process::exit(1);
                }
            }
            Err(error) => {
                eprintln!(
                    "cannot load config authority key {}: {error}",
                    path.display()
                );
                process::exit(1);
            }
        }
    }
    if let Some(authority) = args.config_authority {
        let profile = if args.config_profile == config::ISSUE_PROFILE_COSE {
            "cose-esp256"
        } else {
            "dev-hmac"
        };
        eprintln!(
            "config authority: node {authority:016x} generation {} (permit profile {profile} — EXPERIMENTAL, not a production identity)",
            args.config_authority_generation
        );
    } else {
        eprintln!("config authority: none — config.propose refused; challenge/status queries still run (pass --config-authority)");
    }
    // Bounded outbound queue: SEND is back-pressured at MAX_OUTBOUND pending
    // frames instead of growing memory without limit while the adapter is
    // down.
    let (outbound_tx, outbound_rx) = mpsc::sync_channel(MAX_OUTBOUND);
    let device_session = Arc::new(Mutex::new(DeviceSession::new()));
    // The TX-I2 dispatch thread runs whether or not a device is attached:
    // it performs the host-side expiry/cancel sweeps while USB is absent
    // and starts driving SUBMIT/QUERY/SKIP/RETIRE/TIME_SAMPLE the moment
    // an authenticated host_ops session exists. It shares the single
    // writer queue — counter assignment and wire order stay in one place.
    {
        let dispatch_state = Arc::clone(&state);
        let dispatch_outbound = outbound_tx.clone();
        thread::spawn(move || dispatch::dispatch_loop(dispatch_state, dispatch_outbound));
    }
    // node_status_v1 lane: pages the gateway's per-node view into the
    // node table and consumes its join/leave events. Idle until a session
    // advertising CAP_NODE_STATUS_V1 authenticates; same writer queue.
    {
        let node_state = Arc::clone(&state);
        let node_outbound = outbound_tx.clone();
        thread::spawn(move || nodes::node_status_loop(node_state, node_outbound));
    }
    // Site Authority lane (USB join relay 0x60-0x63 + authority timers):
    // pumps the site inbox through the USB adapter and drains its down
    // queue onto the same writer queue. Idle without a capable session;
    // its events go to the same ring as every other lane's.
    if state.site.is_some() {
        let site_state = Arc::clone(&state);
        let site_outbound = outbound_tx.clone();
        thread::spawn(move || site::usb::site_loop(site_state, site_outbound));
    }
    // group_delivery_v1 lane: writes 0x50/0x52 for group.send records and
    // settles them from the 0x51 answers. Idle while nothing is queued or
    // unsettled; same writer queue.
    {
        let group_state = Arc::clone(&state);
        let group_outbound = outbound_tx.clone();
        thread::spawn(move || group::group_loop(group_state, group_outbound));
    }
    // m1 diagnostics lane: issues 0x30 telemetry queries for
    // `diagnostics.snapshot` and resolves them from the 0x31 answers.
    // Idle while nothing is submitted; same writer queue.
    {
        let telemetry_state = Arc::clone(&state);
        let telemetry_outbound = outbound_tx.clone();
        thread::spawn(move || telemetry::telemetry_loop(telemetry_state, telemetry_outbound));
    }
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
    let listener = bind_api_listener(&socket_path)?;
    let session =
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos() as u64 ^ u64::from(process::id());
    let next_request = Arc::new(AtomicU64::new(1));
    let next_idem_key = Arc::new(AtomicU64::new(session.rotate_left(32) | 1));
    println!("RouteLoom host listening on {}", socket_path.display());
    let active_clients = Arc::new(AtomicUsize::new(0));
    // Per-principal connection cap (ipc.connections_per_principal = 4). The
    // principal is the socket peer's OS uid — `None` (credential lookup
    // unsupported/failed) shares one bucket, so unidentified principals are
    // bounded rather than trusted.
    let principal_clients: Arc<Mutex<HashMap<Option<u32>, usize>>> =
        Arc::new(Mutex::new(HashMap::new()));
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
                let peer_uid = routeloom_peercred::peer_uid(&stream).ok();
                {
                    let mut counts = principal_clients.lock().expect("client counts poisoned");
                    let entry = counts.entry(peer_uid).or_insert(0);
                    if *entry >= MAX_CLIENTS_PER_PRINCIPAL {
                        drop(counts);
                        active_clients.fetch_sub(1, Ordering::Relaxed);
                        drop(stream);
                        continue;
                    }
                    *entry += 1;
                }
                let client_state = Arc::clone(&state);
                let client_outbound = outbound_tx.clone();
                let client_requests = Arc::clone(&next_request);
                let client_idem_keys = Arc::clone(&next_idem_key);
                let client_session = Arc::clone(&device_session);
                let clients = Arc::clone(&active_clients);
                let client_counts = Arc::clone(&principal_clients);
                thread::spawn(move || {
                    // RAII: the counts are restored even when serve_client
                    // unwinds — a panic must never leak a connection slot.
                    let _guard = ClientGuard {
                        active: clients,
                        principals: client_counts,
                        uid: peer_uid,
                    };
                    let _ = serve_client(
                        stream,
                        client_state,
                        client_outbound,
                        session,
                        client_requests,
                        client_idem_keys,
                        client_session,
                        peer_uid,
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
    fn queued_site_frame_cannot_cross_usb_session() {
        let mut session = DeviceSession::new();
        let proof = complete_handshake(&mut session);
        session.handle(&device_credit_grant(&proof, 0, 1, 1_000));
        let before = session.h2d_counter;
        let mut stale = frame(FrameKind::HostOps, 0, 7, vec![1, 0x65]);
        stale.session = proof.session_id ^ 1;
        assert!(session.protect(&mut stale).is_err());
        assert_eq!(session.h2d_counter, before);
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

    /// TX-I2 wiring check: `dispatch_once` must pull replies from the
    /// daemon inbox, drive the dispatcher against the real `State`, and
    /// push HostOps frames onto the single writer queue — the same path
    /// `dispatch_loop` runs in production.
    #[test]
    fn dispatch_once_round_trips_through_inbox_and_writer_queue() {
        use routeloom_protocol::host_ops::{
            decode_time_sample_request, encode_receipt, encode_time_sample_response, BootLease,
            Evidence, HostOpsResult, Receipt, SlotState, TimeSampleResponse, CAP_HOST_OPS_V1,
            SUB_RETIRE_THROUGH, SUB_SUBMIT, SUB_TIME_SAMPLE,
        };

        let state = State::default();
        {
            let mut info = state.session.lock().unwrap();
            info.authenticated = true;
            info.node = Some(0x0abc);
            info.boot = Some(7);
            info.network = Some(1);
            info.capability = Some(CAP_HOST_OPS_V1);
        }
        // Admit one RELIABLE operation on network 1 into the memory store.
        let now = now_ms();
        let (seq, op_hash) = {
            let payload = vec![0x2a, 0x55];
            let canonical = canonical::canonical_bytes(
                1,
                canonical::DEST_NODE,
                3,
                canonical::DELIVERY_RELIABLE,
                canonical::PRIORITY_NORMAL,
                canonical::STORAGE_RAM,
                30_000,
                canonical::HOP_DEFAULT,
                &payload,
            );
            let hash = canonical::sha256(&canonical);
            let request = canonical::SendRequest {
                network: 1,
                epoch: 1,
                key: [9; 16],
                dest_kind: canonical::DEST_NODE,
                dest: 3,
                delivery: canonical::DELIVERY_RELIABLE,
                priority: canonical::PRIORITY_NORMAL,
                ttl_ms: 30_000,
                storage: canonical::STORAGE_RAM,
                hop_limit: canonical::HOP_DEFAULT,
                gateway: None,
                payload,
                hash,
                canonical,
            };
            let mut store = state.operation_store.lock().unwrap();
            store.open_epoch((501, 1), now).unwrap();
            match store.submit(501, &request, now) {
                send_store::SubmitOutcome::Accepted { seq } => (seq, hash),
                _ => panic!("submit failed"),
            }
        };

        let (tx, rx) = mpsc::sync_channel::<Outbound>(MAX_OUTBOUND);
        let mut dispatcher = dispatch::Dispatcher::new([0x77; 16]);

        // First pass: no mapping yet → lease probe (RETIRE_THROUGH 0) and a
        // TIME_SAMPLE request go to the writer queue as sealed HostOps.
        dispatch::dispatch_once(&state, &tx, &mut dispatcher, now, now);
        let mut sample_request = None;
        let mut saw_probe = false;
        while let Ok(outbound) = rx.try_recv() {
            let frame = match outbound {
                Outbound::Seal(frame) => frame,
                Outbound::Raw(_) => panic!("host ops must queue for sealing"),
            };
            assert_eq!(frame.kind, FrameKind::HostOps);
            match frame.body[1] {
                SUB_RETIRE_THROUGH => saw_probe = true,
                SUB_TIME_SAMPLE => sample_request = Some((frame.request, frame.body)),
                other => panic!("unexpected host op {other}"),
            }
        }
        assert!(saw_probe && sample_request.is_some());
        // Nothing submitted until the clock mapping exists.
        {
            let store = state.operation_store.lock().unwrap();
            let op = store.get_by_seq(seq).unwrap().unwrap();
            assert_eq!(op.dispatch_state, send_store::DispatchState::HostQueued);
        }

        // The device answers the sample through the inbox — the same slot
        // `record_frame` fills for verified HostOps frames.
        let (request_id, body) = sample_request.unwrap();
        let sample = decode_time_sample_request(&body).unwrap();
        state.dispatch_inbox.post(
            request_id,
            encode_time_sample_response(&TimeSampleResponse {
                result: HostOpsResult::Ok,
                lease: sample.lease,
                nonce: sample.nonce,
                device_time: 1_000,
            }),
        );
        dispatch::dispatch_once(&state, &tx, &mut dispatcher, now + 1, now + 1);
        let mut submit_request = None;
        while let Ok(outbound) = rx.try_recv() {
            let Outbound::Seal(frame) = outbound else {
                panic!("host ops must queue for sealing")
            };
            if frame.body[1] == SUB_SUBMIT {
                submit_request = Some(frame.request);
            }
        }
        let submit_request = submit_request.expect("mapped clock must release the SUBMIT");
        {
            let store = state.operation_store.lock().unwrap();
            let op = store.get_by_seq(seq).unwrap().unwrap();
            assert_eq!(
                op.dispatch_state,
                send_store::DispatchState::DispatchPrepared
            );
            assert!(op.dispatch.as_ref().unwrap().submitted);
        }

        // A Sent receipt posted by the read thread promotes the record to
        // GATEWAY_ACCEPTED on the next pass. The device echoes the bound
        // canonical hash — a divergent echo would park the record
        // Indeterminate instead.
        state.dispatch_inbox.post(
            submit_request,
            encode_receipt(&Receipt {
                sub: SUB_SUBMIT,
                result: HostOpsResult::Ok,
                state: SlotState::Sent,
                lease: BootLease::derive(7, 0x0abc),
                dispatch_seq: 1,
                hash: op_hash,
                msg_session: 5,
                msg_seq: 1,
                msg_valid: true,
                evidence: Evidence::GatewayAccepted,
            }),
        );
        dispatch::dispatch_once(&state, &tx, &mut dispatcher, now + 2, now + 2);
        let store = state.operation_store.lock().unwrap();
        let op = store.get_by_seq(seq).unwrap().unwrap();
        assert_eq!(
            op.dispatch_state,
            send_store::DispatchState::GatewayAccepted
        );
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
    fn session_retries_lost_handshake() {
        // A Hello lost while the device boots must be retried by the writer
        // until the session reaches Active — observed on real hardware: a
        // reconnect that lands during device startup otherwise stalls in
        // AwaitHelloAck forever.
        let mut session = DeviceSession::new();
        session.begin();
        assert!(!session.handshake_retry_due(session.last_begin_ms));
        assert!(session.handshake_retry_due(session.last_begin_ms + HELLO_RETRY_MS));
        complete_handshake(&mut session);
        assert!(!session.handshake_retry_due(session.last_begin_ms + HELLO_RETRY_MS));
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
    fn delivery_event_for_submit_request_attaches_to_operation() {
        use crate::send_store::{PrepareOutcome, SubmitOutcome};
        let state = State::default();
        // Admit an operation and bind its message key, as the dispatch
        // lane does when the SUBMIT receipt lands.
        let (seq, seq2) = {
            let mut store = state.operation_store.lock().unwrap();
            store.open_epoch((501, 1), 0).unwrap();
            let json = "{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00ff\",\"payload_len\":2,\"options\":{\"storage\":\"RAM_ONLY\"}}";
            let mut req =
                crate::canonical::parse_submit(&routeloom_json::parse(json).unwrap(), None)
                    .unwrap();
            req.epoch = 1;
            let seq = match store.submit(501, &req, 1000) {
                SubmitOutcome::Accepted { seq } => seq,
                _ => panic!("expected accept"),
            };
            match store.prepare_dispatch(seq, [7; 16], [8; 16]) {
                Ok(PrepareOutcome::Prepared(_)) => {}
                _ => panic!("expected prepare"),
            }
            store
                .update_operation(seq, &mut |op| {
                    let d = op.dispatch.as_mut().unwrap();
                    d.msg_session = Some(5);
                    d.msg_seq = Some(900);
                    true
                })
                .unwrap();
            // A previously retained operation can carry the same message
            // key after a mesh session restart. The event belongs to the
            // second operation named by its dispatch identity.
            let second_json = json.replace(
                "00112233445566778899aabbccddeeff",
                "00112233445566778899aabbccddeeee",
            );
            let mut second =
                crate::canonical::parse_submit(&routeloom_json::parse(&second_json).unwrap(), None)
                    .unwrap();
            second.epoch = 1;
            let seq2 = match store.submit(501, &second, 1001) {
                SubmitOutcome::Accepted { seq } => seq,
                _ => panic!("expected second accept"),
            };
            assert!(matches!(
                store.prepare_dispatch(seq2, [7; 16], [8; 16]),
                Ok(PrepareOutcome::Prepared(_))
            ));
            store
                .update_operation(seq2, &mut |op| {
                    let d = op.dispatch.as_mut().unwrap();
                    d.msg_session = Some(5);
                    d.msg_seq = Some(900);
                    true
                })
                .unwrap();
            (seq, seq2)
        };
        // A reason-carrying DeliveryEvent for the SUBMIT request id
        // (never tracked by the legacy SEND path).
        let mut body = Vec::new();
        body.extend_from_slice(&4242_u64.to_be_bytes());
        body.extend_from_slice(&5_u32.to_be_bytes());
        body.extend_from_slice(&900_u64.to_be_bytes());
        body.push(8); // failed
        body.extend_from_slice(b"\x08NO_ROUTE");
        body.extend_from_slice(&[8; 16]);
        body.extend_from_slice(&seq2.to_be_bytes());
        record_frame(
            &state,
            &frame(FrameKind::DeliveryEvent, 0, 4242, body.clone()),
            &body,
            200,
        );
        // No legacy delivery entry is invented for the SUBMIT request...
        assert!(!deliveries_json(&state).contains("4242"));
        // ...the device outcome attaches to the keyed operation instead.
        let store = state.operation_store.lock().unwrap();
        assert!(store
            .get_by_seq(seq)
            .unwrap()
            .unwrap()
            .dispatch
            .unwrap()
            .device_reason
            .is_none());
        let dispatch = store.get_by_seq(seq2).unwrap().unwrap().dispatch.unwrap();
        assert_eq!(dispatch.device_state.as_deref(), Some("failed"));
        assert_eq!(dispatch.device_reason.as_deref(), Some("NO_ROUTE"));
        // And the event ring still carries the reason for triage.
        assert!(events_json(&state).contains("NO_ROUTE"));
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

    /// Diagnostic body with the loss-accounting trailer: peer(8) ||
    /// flags(1) || reason_len(1) || reason || boot(8) || seq(4) ||
    /// dropped_total(8).
    fn diag_body(peer: u64, reason: &str, boot: u64, seq: u32, dropped: u64) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&peer.to_be_bytes());
        body.push(DIAG_FLAG_HAS_ACCOUNTING);
        body.push(reason.len() as u8);
        body.extend_from_slice(reason.as_bytes());
        body.extend_from_slice(&boot.to_be_bytes());
        body.extend_from_slice(&seq.to_be_bytes());
        body.extend_from_slice(&dropped.to_be_bytes());
        body
    }

    fn record_diag(state: &State, body: &[u8], ms: u64) {
        record_frame(
            state,
            &frame(FrameKind::Diagnostic, 0, 0, body.to_vec()),
            body,
            ms,
        );
    }

    #[test]
    fn diagnostic_seq_gap_raises_loss_event() {
        let state = State::default();
        record_diag(&state, &diag_body(2, "EVT0", 7, 0, 0), 100);
        record_diag(&state, &diag_body(2, "EVT1", 7, 1, 0), 101);
        // Seq 2 was dropped on the device; the marker + next diagnostic
        // arrive with the gap visible.
        record_diag(&state, &diag_body(1, "DIAG_LOSS", 7, 3, 1), 102);
        let json = events_json(&state);
        assert!(json.contains("\"kind\":\"diagnostic_loss\""), "{json}");
        assert!(json.contains("\"boot\":7"), "{json}");
        assert!(json.contains("\"lost_from\":2"), "{json}");
        assert!(json.contains("\"lost_to\":2"), "{json}");
        assert!(json.contains("\"lost\":1"), "{json}");
        assert!(json.contains("\"dropped_total\":1"), "{json}");
        // The arrivals themselves carry the accounting fields.
        assert!(json.contains("\"diag_boot\":7"), "{json}");
        assert!(json.contains("\"diag_seq\":3"), "{json}");
        assert!(json.contains("\"diag_dropped\":1"), "{json}");
    }

    #[test]
    fn diagnostic_boot_change_rebaselines() {
        let state = State::default();
        record_diag(&state, &diag_body(2, "EVT0", 7, 5, 0), 100);
        // Same-device reboot: seq restarts, no loss claimed.
        record_diag(&state, &diag_body(2, "EVT0", 8, 0, 0), 101);
        let json = events_json(&state);
        assert!(!json.contains("\"kind\":\"diagnostic_loss\""), "{json}");
        // A fresh boot whose counter already moved lost pre-history
        // diagnostics the host never saw — reported without a range.
        record_diag(&state, &diag_body(2, "EVT4", 9, 4, 2), 102);
        let json = events_json(&state);
        assert!(json.contains("\"kind\":\"diagnostic_loss\""), "{json}");
        assert!(json.contains("\"boot\":9"), "{json}");
        assert!(json.contains("\"lost\":2"), "{json}");
        assert!(json.contains("\"lost_from\":null"), "{json}");
    }

    #[test]
    fn legacy_diagnostic_without_trailer_is_untracked() {
        let state = State::default();
        let mut body = Vec::new();
        body.extend_from_slice(&55_u64.to_be_bytes());
        body.push(0);
        body.push(6);
        body.extend_from_slice(b"RETRY!");
        record_diag(&state, &body, 100);
        let json = events_json(&state);
        assert!(json.contains("\"reason\":\"RETRY!\""), "{json}");
        assert!(json.contains("\"diag_boot\":null"), "{json}");
        assert!(!json.contains("\"kind\":\"diagnostic_loss\""), "{json}");
        // Untracked frames never disturb the baseline.
        record_diag(&state, &diag_body(2, "EVT0", 7, 0, 0), 101);
        record_diag(&state, &body, 102);
        record_diag(&state, &diag_body(2, "EVT1", 7, 1, 0), 103);
        let json = events_json(&state);
        assert!(!json.contains("\"kind\":\"diagnostic_loss\""), "{json}");
    }

    #[test]
    fn adapter_drop_event_carries_the_os_reason() {
        // The disconnect event names the read-loop error (OS message +
        // errno) so a cut cable reads differently from a dead writer.
        let fields = adapter_drop_event(&Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No such device (os error 19)",
        )));
        assert!(fields.contains("\"state\":\"disconnected\""), "{fields}");
        assert!(fields.contains("No such device (os error 19)"), "{fields}");
    }

    #[test]
    fn boot_event_opens_the_ring() {
        // Every daemon run starts the ring with its own restart boundary:
        // seq 0 carries the incarnation id plus the build/config identity
        // an offline journal needs.
        let state = State::default();
        push_event(
            &state,
            1_700_000_000_000,
            boot_event_fields(0x505, "sqlite", 1, true),
        );
        push_event(
            &state,
            1_700_000_000_001,
            "\"kind\":\"keepalive\"".to_string(),
        );
        let json = events_json(&state);
        assert!(
            json.contains("\"seq\":0,\"ms\":1700000000000,\"kind\":\"boot\""),
            "{json}"
        );
        assert!(json.contains("\"host_boot\":1285"), "{json}");
        assert!(json.contains("\"version\":\""), "{json}");
        assert!(json.contains("\"storage\":\"sqlite\""), "{json}");
        assert!(json.contains("\"config_profile\":1"), "{json}");
        assert!(json.contains("\"site\":true"), "{json}");
        assert!(json.contains("\"dropped\":0,\"next_seq\":2"), "{json}");
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

    /// Spin `serve_client` on a socketpair and exchange request/response
    /// lines. `peer_uid` is injected the same way the accept loop injects
    /// the OS credential. Returns the outbound receiver so tests can keep
    /// the writer queue alive (dropping it makes try_send fail).
    fn spawn_client_with(
        state: Arc<State>,
        peer_uid: Option<u32>,
        session: Arc<Mutex<DeviceSession>>,
    ) -> (BufReader<UnixStream>, UnixStream, mpsc::Receiver<Outbound>) {
        let (client, server) = UnixStream::pair().expect("socketpair");
        let (tx, rx) = mpsc::sync_channel(4);
        thread::spawn(move || {
            let _ = serve_client(
                server,
                state,
                tx,
                0,
                Arc::new(AtomicU64::new(1)),
                Arc::new(AtomicU64::new(1)),
                session,
                peer_uid,
            );
        });
        let reader = BufReader::new(client.try_clone().expect("clone"));
        (reader, client, rx)
    }

    fn spawn_client(
        state: Arc<State>,
        peer_uid: Option<u32>,
    ) -> (BufReader<UnixStream>, UnixStream) {
        let (reader, client, _rx) =
            spawn_client_with(state, peer_uid, Arc::new(Mutex::new(DeviceSession::new())));
        (reader, client)
    }

    fn exchange(reader: &mut BufReader<UnixStream>, writer: &mut UnixStream, line: &str) -> String {
        writer.write_all(line.as_bytes()).expect("write");
        writer.write_all(b"\n").expect("write");
        let mut response = String::new();
        reader.read_line(&mut response).expect("read");
        response
    }

    #[test]
    fn api1_and_legacy_share_one_socket() {
        let state = Arc::new(State::default());
        let (mut reader, mut writer) = spawn_client(Arc::clone(&state), Some(501));
        // Legacy verb works unchanged.
        let status = exchange(&mut reader, &mut writer, "STATUS");
        assert!(status.contains("\"connected\""), "{status}");
        // API1 on the same connection.
        let caps = exchange(
            &mut reader,
            &mut writer,
            "API1 {\"v\":1,\"request_id\":\"t1\",\"method\":\"capabilities.get\"}",
        );
        assert!(caps.contains("\"ok\":true"), "{caps}");
        assert!(caps.contains("\"messages.read\":true"), "{caps}");
        // Default deny: no ACL → messages.read fails AuthorizationFailed,
        // while the legacy diagnostic verbs above still worked.
        let denied = exchange(
            &mut reader,
            &mut writer,
            "API1 {\"v\":1,\"request_id\":\"t2\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
        );
        assert!(denied.contains("AuthorizationFailed"), "{denied}");
        // Bad framing is an explicit error, not a dropped connection.
        let bad = exchange(&mut reader, &mut writer, "API1 {\"v\":1,,\"x\":2}");
        assert!(bad.contains("INVALID_REQUEST"), "{bad}");
        let still_alive = exchange(&mut reader, &mut writer, "STATUS");
        assert!(still_alive.contains("\"connected\""));
    }

    #[test]
    fn api1_oversize_line_gets_error_then_close() {
        let state = Arc::new(State::default());
        let (mut reader, mut writer) = spawn_client(Arc::clone(&state), None);
        let huge = format!("API1 {{\"v\":1,\"pad\":\"{}\"}}", "x".repeat(9000));
        // The server reads at most 8192 bytes, answers once, and closes —
        // the tail of this oversized line can race the close (EPIPE).
        match writer
            .write_all(huge.as_bytes())
            .and_then(|()| writer.write_all(b"\n"))
        {
            Ok(()) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::BrokenPipe | io::ErrorKind::WriteZero
                ) => {}
            Err(error) => panic!("write: {error}"),
        }
        let mut response = String::new();
        reader.read_line(&mut response).expect("read");
        assert!(response.contains("INVALID_REQUEST"), "{response}");
        // Connection closed after the unrecoverable framing error.
        let mut eof = String::new();
        assert_eq!(reader.read_line(&mut eof).expect("read"), 0);
    }

    #[test]
    fn api1_reads_back_ingested_payloads() {
        let acl = Acl::parse(
            "{\"principals\":{\"501\":{\"networks\":{\"0000000000000001\":[\"READ_PAYLOAD\"]}}}}",
        )
        .unwrap();
        let state = Arc::new(State {
            acl,
            ..State::default()
        });
        {
            let mut session = state.session.lock().expect("session");
            session.network = Some(1);
            session.node = Some(2);
        }
        let mut body = Vec::new();
        body.extend_from_slice(&77_u64.to_be_bytes());
        body.extend_from_slice(&5_u32.to_be_bytes());
        body.extend_from_slice(&900_u64.to_be_bytes());
        body.extend_from_slice(&[0x00, 0xff]); // non-UTF-8, includes NUL
        record_frame(
            &state,
            &frame(FrameKind::DataFromMesh, 0, 0, body.clone()),
            &body,
            // The API1 read path timestamps with the real clock, so the
            // ingest must too — a synthetic ms would expire before the read.
            now_ms(),
        );
        let (mut reader, mut writer) = spawn_client(Arc::clone(&state), Some(501));
        let response = exchange(
            &mut reader,
            &mut writer,
            "API1 {\"v\":1,\"request_id\":\"rx\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
        );
        assert!(response.contains("\"ok\":true"), "{response}");
        assert!(response.contains("\"payload_hex\":\"00ff\""), "{response}");
        assert!(response.contains("\"payload_len\":2"), "{response}");
        assert!(
            response.contains("\"origin\":\"000000000000004d\""),
            "{response}"
        );
        // A different uid is denied even though the record exists (RX06).
        drop(writer);
        let (mut reader2, mut writer2) = spawn_client(Arc::clone(&state), Some(7));
        let denied = exchange(
            &mut reader2,
            &mut writer2,
            "API1 {\"v\":1,\"request_id\":\"rx2\",\"method\":\"messages.read\",\"params\":{\"network\":\"0000000000000001\",\"from\":\"earliest\"}}",
        );
        assert!(denied.contains("AuthorizationFailed"), "{denied}");
    }

    #[test]
    fn ingest_assurance_follows_site_ledger() {
        use crate::site::testkit::{self, Outcome, SimDevice};
        use crate::site::{DecideRequest, SiteService};
        let now = 1_790_000_000_000;
        let store = Box::<crate::site::store::MemoryStore>::default();
        let service = Arc::new(SiteService::new(testkit::authority(store, now)));
        let transport = crate::site::transport::InProcessTransport::new();
        service.set_transport(transport.clone());
        // Enroll one member through the real join flow.
        let node = 0x00A1_0000_0000_7001;
        let mut device = SimDevice::new(node, 0x79);
        let (_, outcome, events) = device.start(&service, &transport, now);
        assert!(matches!(outcome, Outcome::Waiting));
        let request = testkit::request_id(&events).expect("join request");
        service
            .with(|a| {
                a.decide(
                    501,
                    DecideRequest {
                        join_request_id: request,
                        device: node,
                        verdict: crate::site::records::Verdict::Allow {
                            role: crate::site::records::ROLE_ENDPOINT,
                        },
                        key: "allow-7001".into(),
                    },
                    now + 10,
                )
            })
            .0
            .unwrap();
        let network = u64::from(testkit::NETWORK_LOW);
        let state = State {
            site: Some(Arc::clone(&service)),
            ..State::default()
        };
        {
            let mut session = state.session.lock().expect("session");
            session.network = Some(network);
            session.node = Some(1);
        }
        // A ledger-enrolled origin on the site network carries member
        // assurance; an unenrolled origin on the same deployment is
        // unattributed rather than mislabeled as a dev-PSK claim.
        for (origin, seq) in [(node, 11u64), (0x99, 12)] {
            receive_ingest(&state, Some(origin), Some(5), Some(seq), &[0xaa], now + 20);
        }
        let mut log = state.receive_log.lock().expect("receive log");
        let crate::receive_log::ReadOutcome::Batch(batch) =
            log.read(network, 0, 8, now + 20, false)
        else {
            panic!("ingested records must be readable");
        };
        assert_eq!(batch.records.len(), 2);
        assert_eq!(
            batch.records[0].assurance,
            crate::receive_log::RxAssurance::MemberEnrolled
        );
        assert_eq!(
            batch.records[1].assurance,
            crate::receive_log::RxAssurance::Unverified
        );
        // Without an authority there is no ledger to consult: the dev
        // profile claim is the honest attribution.
        let bare = State::default();
        assert_eq!(
            ingress_assurance(&bare, network, node),
            crate::receive_log::RxAssurance::DevPskClaim
        );
    }

    #[test]
    fn api1_submit_and_query_roundtrip() {
        let acl = Acl::parse(
            "{\"principals\":{\"501\":{\"networks\":{\"0000000000000001\":[\"SEND\",\"READ_OPERATION\"]}}}}",
        )
        .unwrap();
        let state = Arc::new(State {
            acl,
            ..State::default()
        });
        let (mut reader, mut writer) = spawn_client(Arc::clone(&state), Some(501));
        let epoch = exchange(
            &mut reader,
            &mut writer,
            "API1 {\"v\":1,\"request_id\":\"e\",\"method\":\"operations.open_epoch\",\"params\":{\"network\":\"0000000000000001\"}}",
        );
        assert!(epoch.contains("\"ok\":true"), "{epoch}");
        assert!(
            epoch.contains("\"admission_epoch\":\"0000000000000001\""),
            "{epoch}"
        );
        let submit = exchange(
            &mut reader,
            &mut writer,
            "API1 {\"v\":1,\"request_id\":\"s\",\"method\":\"messages.submit\",\"params\":{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00ff\",\"payload_len\":2,\"options\":{\"storage\":\"RAM_ONLY\"}}}",
        );
        assert!(submit.contains("\"ok\":true"), "{submit}");
        assert!(
            submit.contains("\"dispatch_state\":\"HOST_QUEUED\""),
            "{submit}"
        );
        let id = {
            let parsed = routeloom_json::parse(&submit).unwrap();
            parsed
                .get("result")
                .unwrap()
                .get("operation_id")
                .unwrap()
                .as_str()
                .unwrap()
                .to_string()
        };
        // Same key+payload replays the same id over the socket too.
        let replay = exchange(
            &mut reader,
            &mut writer,
            "API1 {\"v\":1,\"request_id\":\"s2\",\"method\":\"messages.submit\",\"params\":{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{\"kind\":\"node\",\"id\":\"0000000000000003\"},\"payload_hex\":\"00ff\",\"payload_len\":2,\"options\":{\"storage\":\"RAM_ONLY\"}}}",
        );
        assert!(
            replay.contains(&format!("\"operation_id\":\"{id}\"")),
            "{replay}"
        );
        let by_id = exchange(
            &mut reader,
            &mut writer,
            &format!(
                "API1 {{\"v\":1,\"request_id\":\"q\",\"method\":\"operations.get\",\"params\":{{\"operation_id\":\"{id}\"}}}}"
            ),
        );
        assert!(by_id.contains("\"ok\":true"), "{by_id}");
        assert!(by_id.contains("\"payload_len\":2"), "{by_id}");
        assert!(!by_id.contains("payload_hex"), "{by_id}");
        let by_key = exchange(
            &mut reader,
            &mut writer,
            "API1 {\"v\":1,\"request_id\":\"q2\",\"method\":\"operations.get_by_key\",\"params\":{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"00112233445566778899aabbccddeeff\"}}",
        );
        assert!(
            by_key.contains(&format!("\"operation_id\":\"{id}\"")),
            "{by_key}"
        );
        // Legacy SEND still speaks its own verb on the same socket (explicit
        // legacy mode — never auto-converted to the new API).
        let legacy = exchange(&mut reader, &mut writer, "SEND 3 00ff");
        assert!(legacy.contains("\"accepted\":false"), "{legacy}");
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

    /// P0: the legacy SEND verb is gated by the same contract as
    /// messages.submit — the peer's OS uid must hold SEND on the
    /// session's own network (05-production-security.md: USB host
    /// authority is never granted to every local client). Denials keep
    /// the {"accepted":false,...} shape legacy clients parse.
    #[test]
    fn legacy_send_requires_send_grant_and_session_network() {
        let acl = Acl::parse(
            "{\"principals\":{\"501\":{\"networks\":{\"0000000000000001\":[\"SEND\"]}},\"7\":{\"networks\":{\"0000000000000002\":[\"SEND\"]}}}}",
        )
        .unwrap();
        let state = Arc::new(State {
            acl,
            ..State::default()
        });
        // Session reports network 1: uid 501's grant scopes to it and the
        // request reaches the session-state check.
        state.session.lock().unwrap().network = Some(1);
        let (mut reader, mut writer, _rx) = spawn_client_with(
            Arc::clone(&state),
            Some(501),
            Arc::new(Mutex::new(DeviceSession::new())),
        );
        let response = exchange(&mut reader, &mut writer, "SEND 3 00ff");
        assert!(response.contains("\"accepted\":false"), "{response}");
        assert!(response.contains("session not authenticated"), "{response}");
        drop(writer);
        // A uid with no grant on this network and an unidentified peer
        // are denied before any session state is consulted.
        for uid in [Some(7), None] {
            let (mut reader, mut writer, _rx) = spawn_client_with(
                Arc::clone(&state),
                uid,
                Arc::new(Mutex::new(DeviceSession::new())),
            );
            let response = exchange(&mut reader, &mut writer, "SEND 3 00ff");
            assert!(response.contains("\"accepted\":false"), "{response}");
            assert!(response.contains("authorization failed"), "{response}");
            drop(writer);
        }
        // Network scope follows the session: on network 2 the grant map
        // flips — uid 7 reaches the session check, uid 501 is denied.
        state.session.lock().unwrap().network = Some(2);
        let (mut reader, mut writer, _rx) = spawn_client_with(
            Arc::clone(&state),
            Some(7),
            Arc::new(Mutex::new(DeviceSession::new())),
        );
        let response = exchange(&mut reader, &mut writer, "SEND 3 00ff");
        assert!(response.contains("session not authenticated"), "{response}");
        drop(writer);
        let (mut reader, mut writer, _rx) = spawn_client_with(
            Arc::clone(&state),
            Some(501),
            Arc::new(Mutex::new(DeviceSession::new())),
        );
        let response = exchange(&mut reader, &mut writer, "SEND 3 00ff");
        assert!(response.contains("authorization failed"), "{response}");
    }

    /// With a grant and an authenticated device session the verb queues —
    /// but reserved destinations (0/u64::MAX, the canonical.rs rule) and
    /// an exhausted admission budget still refuse, in the same shape.
    #[test]
    fn legacy_send_accepts_granted_and_rejects_reserved_and_limits() {
        let acl = Acl::parse(
            "{\"principals\":{\"501\":{\"networks\":{\"0000000000000001\":[\"SEND\"]}}}}",
        )
        .unwrap();
        let state = Arc::new(State {
            acl,
            ..State::default()
        });
        state.session.lock().unwrap().network = Some(1);
        let mut device = DeviceSession::new();
        complete_handshake(&mut device);
        let expected_session = device.session_id;
        let (mut reader, mut writer, rx) =
            spawn_client_with(Arc::clone(&state), Some(501), Arc::new(Mutex::new(device)));
        // Reserved node ids are refused with the same rule canonical.rs
        // applies — never queued for the writer to discover.
        for bad in ["SEND 0 00ff", "SEND 18446744073709551615 00ff"] {
            let response = exchange(&mut reader, &mut writer, bad);
            assert!(response.contains("\"accepted\":false"), "{response}");
            assert!(response.contains("reserved"), "{response}");
        }
        // A normal send queues a sealed DataToMesh for the writer.
        let response = exchange(&mut reader, &mut writer, "SEND 3 00ff");
        assert!(response.contains("\"accepted\":true"), "{response}");
        assert!(response.contains("\"request\":"), "{response}");
        let Ok(Outbound::Seal(frame)) = rx.try_recv() else {
            panic!("expected a sealed DataToMesh frame");
        };
        assert_eq!(frame.session, expected_session);
        // The shared admission budget binds the legacy verb too.
        {
            let mut limiter = state.rate_limiter.lock().unwrap();
            let now = now_ms();
            while limiter.admit(501, now).is_ok() {}
        }
        let response = exchange(&mut reader, &mut writer, "SEND 3 00ff");
        assert!(response.contains("\"accepted\":false"), "{response}");
        assert!(response.contains("rate limited"), "{response}");
    }

    /// The control socket file mode is tightened to 0600 before any
    /// accept — restricting IPC to the owning uid where the OS honors
    /// socket perms (Linux), and documenting intent elsewhere.
    #[test]
    fn api_listener_mode_is_owner_only() {
        let dir = env::temp_dir().join(format!("routeloom-sock-test-{}", process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let sock = dir.join("api.sock");
        let listener = bind_api_listener(&sock).expect("bind");
        let mode = std::fs::metadata(&sock).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket mode {mode:o}");
        drop(listener);
        let _ = std::fs::remove_file(&sock);
        let _ = std::fs::remove_dir(&dir);
    }

    /// The RAII connection guard restores the global and per-principal
    /// counts even when the client handler panics — a panic must not
    /// leak a slot toward MAX_CLIENTS. A zeroed per-principal entry is
    /// removed rather than left in the map.
    #[test]
    fn client_guard_restores_counts_on_panic() {
        let active = Arc::new(AtomicUsize::new(1));
        let principals: Arc<Mutex<HashMap<Option<u32>, usize>>> =
            Arc::new(Mutex::new(HashMap::from([(Some(501_u32), 1)])));
        let outcome = std::panic::catch_unwind({
            let active = Arc::clone(&active);
            let principals = Arc::clone(&principals);
            move || {
                let _guard = ClientGuard {
                    active,
                    principals,
                    uid: Some(501),
                };
                panic!("simulated client handler panic");
            }
        });
        assert!(outcome.is_err());
        assert_eq!(active.load(Ordering::Relaxed), 0);
        assert!(!principals.lock().unwrap().contains_key(&Some(501)));
    }

    /// Reserved origins (0/u64::MAX) can never appear on the wire: the
    /// adapter minting one is dropped with an rx_drop diagnostic, and
    /// nothing reaches the receive log.
    #[test]
    fn receive_ingest_drops_reserved_origin() {
        let state = State::default();
        {
            let mut session = state.session.lock().unwrap();
            session.network = Some(1);
            session.node = Some(2);
        }
        for origin in [0_u64, u64::MAX] {
            let mut body = Vec::new();
            body.extend_from_slice(&origin.to_be_bytes());
            body.extend_from_slice(&5_u32.to_be_bytes());
            body.extend_from_slice(&900_u64.to_be_bytes());
            body.extend_from_slice(b"x");
            record_frame(
                &state,
                &frame(FrameKind::DataFromMesh, 0, 0, body.clone()),
                &body,
                now_ms(),
            );
        }
        let json = events_json(&state);
        assert!(json.contains("\"kind\":\"rx_drop\""), "{json}");
        assert!(json.contains("\"reason\":\"origin_reserved\""), "{json}");
        let mut log = state.receive_log.lock().unwrap();
        assert_eq!(log.bounds(1, now_ms()), (1, 0, 0, 0));
    }

    #[test]
    fn op_store_flag_parses() {
        let args =
            |words: &[&str]| parse_args_from(words.iter().map(|w| w.to_string())).expect("parse");
        let defaults = args(&[]);
        assert_eq!(defaults.socket, PathBuf::from("/tmp/routeloom.sock"));
        assert!(defaults.device.is_none());
        assert!(defaults.acl_file.is_none());
        assert!(defaults.op_store.is_none());
        let durable = args(&["--op-store", "/var/lib/routeloom/ops.db"]);
        assert_eq!(
            durable.op_store,
            Some(PathBuf::from("/var/lib/routeloom/ops.db"))
        );
        assert!(parse_args_from(["--op-store".to_string()].into_iter()).is_err());
        assert!(parse_args_from(["--bogus".to_string()].into_iter()).is_err());
    }

    #[test]
    fn config_dev_key_defaults_to_the_firmware_master() {
        // The default decodes to the same master the firmware Kconfig ships
        // ("ROUTELOOM-DEVELOPMENT-KEY-ONLY!!"), so a default daemon↔device
        // pair derives matching permit keys. A mismatched master signs
        // permits the target can only deny — the arg must not drift.
        let parse =
            |words: &[&str]| parse_args_from(words.iter().map(|w| w.to_string())).expect("parse");
        let defaults = parse(&[]);
        assert_eq!(
            defaults.config_dev_key,
            b"ROUTELOOM-DEVELOPMENT-KEY-ONLY!!".to_vec()
        );
        let custom = parse(&["--config-dev-key-hex", "deadbeef"]);
        assert_eq!(custom.config_dev_key, vec![0xde, 0xad, 0xbe, 0xef]);
        for bad_args in [
            vec!["--config-dev-key-hex"],
            vec!["--config-dev-key-hex", "abc"],
            vec!["--config-dev-key-hex", "zz"],
        ] {
            assert!(parse_args_from(bad_args.into_iter().map(String::from)).is_err());
        }
    }

    #[test]
    fn config_authority_rejects_reserved_and_zero_generation() {
        for authority in ["0", "0x0", "ffffffffffffffff"] {
            assert!(parse_args_from(
                ["--config-authority".to_string(), authority.to_string()].into_iter()
            )
            .is_err());
        }
        assert!(parse_args_from(
            ["--config-authority-generation".to_string(), "0".to_string()].into_iter()
        )
        .is_err());
    }

    #[test]
    fn config_profile_and_key_are_jointly_validated() {
        let args = |flags: &[&str]| parse_args_from(flags.iter().map(|s| s.to_string()));
        // Default is the dev profile with no key file.
        let parsed = args(&[]).unwrap();
        assert_eq!(parsed.config_profile, config::ISSUE_PROFILE_DEV);
        assert!(parsed.config_authority_key.is_none());
        // COSE selects the profile and keeps the key path.
        let parsed = args(&[
            "--config-profile",
            "cose",
            "--config-authority-key",
            "/tmp/a.key",
        ])
        .unwrap();
        assert_eq!(parsed.config_profile, config::ISSUE_PROFILE_COSE);
        assert_eq!(
            parsed.config_authority_key,
            Some(std::path::PathBuf::from("/tmp/a.key"))
        );
        // Unknown profile, keyless COSE, and key-with-dev all refuse.
        assert!(args(&["--config-profile", "psk"]).is_err());
        assert!(args(&["--config-profile", "cose"]).is_err());
        assert!(args(&["--config-authority-key", "/tmp/a.key"]).is_err());
    }

    /// node_status_v1 wiring: the lane queues a sealed 0x40 query on the
    /// writer queue once a capable session is up, `record_frame` routes the
    /// 0x41 reply (and 0x42 events) into the node inbox — never the
    /// dispatcher inbox — and the next pass updates the table, the legacy
    /// NODES view and the event ring.
    #[test]
    fn node_status_lane_round_trips_through_record_frame() {
        use routeloom_protocol::node_status::{
            decode_node_status_query, encode_node_event, encode_node_status_page, NodeEvent,
            NodeEventKind, NodeStatusEntry, NodeStatusPage, CAP_NODE_STATUS_V1, FLAG_DIRECT,
            FLAG_NEIGHBOR, FLAG_NEIGHBOR_ACTIVE, FLAG_REACHABLE, FLAG_RSSI_VALID, PAGE_ARMED,
        };
        let state = State::default();
        {
            let mut info = state.session.lock().unwrap();
            info.authenticated = true;
            info.id = Some(42);
            info.node = Some(1);
            info.network = Some(7);
            info.capability = Some(0x7 | CAP_NODE_STATUS_V1);
        }
        // Before any report the legacy view is explicit about unknowns.
        touch_node(&state, 2, "peer", 10);
        assert!(nodes_json(&state).contains("\"membership\":\"unknown\""));

        let (tx, rx) = mpsc::sync_channel::<Outbound>(MAX_OUTBOUND);
        let mut lane = nodes::NodeStatusLane::default();
        let now = now_ms();
        nodes::node_status_once(&state, &tx, &mut lane, now);
        let Ok(Outbound::Seal(query)) = rx.try_recv() else {
            panic!("expected a sealed node status query");
        };
        assert_eq!(query.kind, FrameKind::HostOps);
        let decoded = decode_node_status_query(&query.body).unwrap();
        assert_eq!(decoded.after, 0);

        let entry = NodeStatusEntry {
            node: 2,
            flags: FLAG_NEIGHBOR
                | FLAG_NEIGHBOR_ACTIVE
                | FLAG_REACHABLE
                | FLAG_DIRECT
                | FLAG_RSSI_VALID,
            rssi_last_dbm: -64,
            rssi_ewma_q8_8: -64 * 256,
            link_cost: 1,
            route_metric: 1,
            next_hop: 2,
            heard_age_ms: 0,
        };
        let page = encode_node_status_page(&NodeStatusPage {
            result: 0,
            flags: PAGE_ARMED,
            next_after: 2,
            event_seq: 0,
            entries: vec![entry],
        })
        .unwrap();
        record_frame(
            &state,
            &frame(FrameKind::HostOps, 0, query.request, page.clone()),
            &page,
            now,
        );
        nodes::node_status_once(&state, &tx, &mut lane, now + 1);
        let view = nodes_json(&state);
        // No site authority here: membership is unknown — reachability
        // carries the route state, never the membership column.
        assert!(view.contains("\"membership\":\"unknown\""), "{view}");
        assert!(view.contains("\"reachability\":\"reachable\""), "{view}");
        assert!(view.contains("\"rssi_dbm\":-64"));
        assert!(view.contains("\"hop_count\":1"));
        assert!(view.contains("\"state\":\"live\""));
        {
            let events = state.events.lock().unwrap();
            assert!(events.iter().any(
                |e| e.kind == "node_joined" && e.json.contains("\"node\":\"0000000000000002\"")
            ));
            assert!(events
                .iter()
                .any(|e| e.kind == "node_joined"
                    && e.json.contains("\"reason\":\"gateway_attached\"")));
            assert!(!events.iter().any(|e| e.kind == "host_ops_rx"));
        }

        // A device event: node 2 leaves.
        let gone = NodeStatusEntry {
            flags: FLAG_NEIGHBOR,
            link_cost: u16::MAX,
            route_metric: u16::MAX,
            next_hop: 0,
            ..entry
        };
        let body = encode_node_event(&NodeEvent {
            sequence: 1,
            kind: NodeEventKind::RouteDown,
            status: gone,
        })
        .unwrap();
        record_frame(
            &state,
            &frame(FrameKind::HostOps, 0, 0, body.clone()),
            &body,
            now + 2,
        );
        nodes::node_status_once(&state, &tx, &mut lane, now + 3);
        // A lost route reads as unreachable — never as "left".
        let view = nodes_json(&state);
        assert!(view.contains("\"membership\":\"unknown\""), "{view}");
        assert!(view.contains("\"reachability\":\"unreachable\""), "{view}");
        assert!(state
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.kind == "node_left" && e.json.contains("\"reason\":\"route_down\"")));

        // Session loss: the gateway leaves too; NODES stays honest.
        state.session.lock().unwrap().authenticated = false;
        nodes::node_status_once(&state, &tx, &mut lane, now + 4);
        let view = nodes_json(&state);
        assert!(view.contains("\"state\":\"unavailable\""), "{view}");
        assert!(state
            .events
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.kind == "node_left" && e.json.contains("\"reason\":\"gateway_lost\"")));
    }

    #[test]
    fn nodes_membership_follows_ledger_not_route() {
        use crate::site::testkit::{self, Outcome, SimDevice};
        use crate::site::{DecideRequest, SiteService};
        use routeloom_protocol::node_status::{
            encode_node_event, encode_node_status_page, NodeEvent, NodeEventKind, NodeStatusEntry,
            NodeStatusPage, CAP_NODE_STATUS_V1, FLAG_DIRECT, FLAG_NEIGHBOR, FLAG_NEIGHBOR_ACTIVE,
            FLAG_REACHABLE, FLAG_RSSI_VALID, PAGE_ARMED,
        };
        let now = 1_790_000_000_000;
        let store = Box::<crate::site::store::MemoryStore>::default();
        let service = Arc::new(SiteService::new(testkit::authority(store, now)));
        let transport = crate::site::transport::InProcessTransport::new();
        service.set_transport(transport.clone());
        let state = State {
            site: Some(Arc::clone(&service)),
            ..State::default()
        };
        // Join a member through the real flow.
        let node = 0x00A1_0000_0000_7001;
        let mut device = SimDevice::new(node, 0x79);
        let (_, outcome, events) = device.start(&service, &transport, now);
        assert!(matches!(outcome, Outcome::Waiting));
        let request = testkit::request_id(&events).expect("join request");
        service
            .with(|a| {
                a.decide(
                    501,
                    DecideRequest {
                        join_request_id: request,
                        device: node,
                        verdict: crate::site::records::Verdict::Allow {
                            role: crate::site::records::ROLE_ENDPOINT,
                        },
                        key: "allow-7001".into(),
                    },
                    now + 10,
                )
            })
            .0
            .unwrap();
        // Ledger admission alone names the membership (no route needed).
        touch_node(&state, node, "peer", now + 11);
        let view = nodes_json(&state);
        assert!(view.contains("\"membership\":\"member\""), "{view}");

        // A lost route reads as unreachable — the member stays a member.
        {
            let mut info = state.session.lock().unwrap();
            info.authenticated = true;
            info.id = Some(42);
            info.node = Some(1);
            info.network = Some(7);
            info.capability = Some(0x7 | CAP_NODE_STATUS_V1);
        }
        let (tx, rx) = mpsc::sync_channel::<Outbound>(MAX_OUTBOUND);
        let mut lane = nodes::NodeStatusLane::default();
        nodes::node_status_once(&state, &tx, &mut lane, now + 12);
        let Ok(Outbound::Seal(query)) = rx.try_recv() else {
            panic!("expected a sealed node status query");
        };
        let entry = NodeStatusEntry {
            node,
            flags: FLAG_NEIGHBOR
                | FLAG_NEIGHBOR_ACTIVE
                | FLAG_REACHABLE
                | FLAG_DIRECT
                | FLAG_RSSI_VALID,
            rssi_last_dbm: -64,
            rssi_ewma_q8_8: -64 * 256,
            link_cost: 1,
            route_metric: 1,
            next_hop: node,
            heard_age_ms: 0,
        };
        let page = encode_node_status_page(&NodeStatusPage {
            result: 0,
            flags: PAGE_ARMED,
            next_after: node,
            event_seq: 0,
            entries: vec![entry],
        })
        .unwrap();
        record_frame(
            &state,
            &frame(FrameKind::HostOps, 0, query.request, page.clone()),
            &page,
            now + 12,
        );
        nodes::node_status_once(&state, &tx, &mut lane, now + 13);
        let view = nodes_json(&state);
        assert!(view.contains("\"membership\":\"member\""), "{view}");
        assert!(view.contains("\"reachability\":\"reachable\""), "{view}");
        let gone = NodeStatusEntry {
            flags: FLAG_NEIGHBOR,
            link_cost: u16::MAX,
            route_metric: u16::MAX,
            next_hop: 0,
            ..entry
        };
        let body = encode_node_event(&NodeEvent {
            sequence: 1,
            kind: NodeEventKind::RouteDown,
            status: gone,
        })
        .unwrap();
        record_frame(
            &state,
            &frame(FrameKind::HostOps, 0, 0, body.clone()),
            &body,
            now + 14,
        );
        nodes::node_status_once(&state, &tx, &mut lane, now + 15);
        let view = nodes_json(&state);
        assert!(view.contains("\"membership\":\"member\""), "{view}");
        assert!(view.contains("\"reachability\":\"unreachable\""), "{view}");

        // Revocation flips the ledger state, not the route.
        service
            .with(|a| {
                a.revoke(
                    501,
                    crate::site::RevokeRequest {
                        device: node,
                        expected_generation: 1,
                        reason: crate::site::parse_reason("removed").unwrap(),
                        key: "revoke-7001".into(),
                    },
                    crate::site::group_keys::HostTime::sync(now + 16),
                )
            })
            .0
            .unwrap();
        let view = nodes_json(&state);
        assert!(view.contains("\"membership\":\"removed\""), "{view}");
    }

    /// Inner bytes of one frame of protocol/usb-golden/group-ops.
    fn group_golden(name: &str) -> Vec<u8> {
        let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../protocol/usb-golden/group-ops/frames")
            .join(name);
        let doc = routeloom_json::parse(&std::fs::read_to_string(path).unwrap()).unwrap();
        let hex = doc
            .get("inner_hex")
            .and_then(routeloom_json::Json::as_str)
            .unwrap();
        parse_hex(hex).unwrap()
    }

    /// group_delivery_v1 end to end through the daemon plumbing: an admitted
    /// group.send record is written as the golden 0x50 on the writer queue,
    /// `record_frame` routes the golden 0x51 answers to the group lane (never
    /// the dispatcher inbox or the host_ops_rx mirror), the FINAL settles the
    /// record and the ring carries exactly one `group_settled`; a USB Error
    /// frame echoing a group request id settles the next send as REFUSED.
    #[test]
    fn group_lane_round_trips_through_record_frame() {
        use crate::group::{GroupLane, GroupRequest, SubmitOutcome};
        let state = State::default();
        {
            let mut info = state.session.lock().unwrap();
            info.authenticated = true;
            info.id = Some(42);
            info.node = Some(1);
            info.network = Some(7);
            info.capability = Some(0x87);
        }
        let request = GroupRequest {
            network: 7,
            group: 0xFFFF,
            priority: 3,
            ordered: false,
            ttl_ms: 5000,
            hop_limit: 10,
            payload: b"PUMP3 OVERTEMP".to_vec(),
        };
        let now = now_ms();
        let Ok(SubmitOutcome::Accepted(op)) =
            state.group_ops.submit(501, [1; 16], request.clone(), now)
        else {
            panic!("admitted");
        };
        let (tx, rx) = mpsc::sync_channel::<Outbound>(MAX_OUTBOUND);
        let mut lane = GroupLane::default();
        group::group_once(&state, &tx, &mut lane, now);
        let Ok(Outbound::Seal(send)) = rx.try_recv() else {
            panic!("expected a sealed GROUP_SEND");
        };
        assert_eq!(send.kind, FrameKind::HostOps);
        assert_eq!(send.body, group_golden("07_group_send.json"));

        for name in [
            "09_group_status_admitted.json",
            "10_group_status_final.json",
        ] {
            let body = group_golden(name);
            record_frame(
                &state,
                &frame(FrameKind::HostOps, 0, send.request, body.clone()),
                &body,
                now,
            );
        }
        group::group_once(&state, &tx, &mut lane, now + 1);
        let record = state.group_ops.get(op).unwrap();
        assert_eq!(record.state_name(), "DELIVERED");
        {
            let events = state.events.lock().unwrap();
            let settled: Vec<&Event> = events
                .iter()
                .filter(|e| e.kind == "group_settled")
                .collect();
            assert_eq!(settled.len(), 1);
            assert!(settled[0].json.contains("\"state\":\"DELIVERED\""));
            assert!(settled[0].json.contains("\"reason\":\"GROUP_COMPLETE\""));
            assert!(!events.iter().any(|e| e.kind == "host_ops_rx"));
        }

        // A second send the device rejects at the frame level.
        let Ok(SubmitOutcome::Accepted(op)) =
            state.group_ops.submit(501, [2; 16], request, now + 2)
        else {
            panic!("admitted");
        };
        group::group_once(&state, &tx, &mut lane, now + 2);
        let Ok(Outbound::Seal(send)) = rx.try_recv() else {
            panic!("expected a sealed GROUP_SEND");
        };
        let mut error = 1_u16.to_be_bytes().to_vec();
        error.extend_from_slice(&send.request.to_be_bytes());
        error.push(15);
        error.extend_from_slice(b"GROUP_MALFORMED");
        record_frame(
            &state,
            &frame(FrameKind::Error, 0, send.request, error.clone()),
            &error,
            now + 3,
        );
        group::group_once(&state, &tx, &mut lane, now + 4);
        let record = state.group_ops.get(op).unwrap();
        assert_eq!(record.state_name(), "REFUSED");
        assert_eq!(record.reason.as_deref(), Some("GROUP_MALFORMED"));
    }

    #[test]
    fn mono_ms_stamps_a_nonzero_anchor() {
        // Issue #60-1: `accepted_mono_ms == 0` is the operation store's "no
        // monotonic anchor" sentinel — a record stamped 0 loses the
        // rewind-proof deadline cap. A sub-millisecond observation (the
        // first ms after BASE is anchored) must clamp to 1, never 0.
        assert_eq!(mono_ms_from_elapsed(Duration::ZERO), 1);
        assert_eq!(mono_ms_from_elapsed(Duration::from_micros(999)), 1);
        assert_eq!(mono_ms_from_elapsed(Duration::from_millis(1)), 1);
        assert_eq!(mono_ms_from_elapsed(Duration::from_millis(1500)), 1500);
        // The live clock honours the same contract and never runs backwards.
        let first = mono_ms();
        assert!(first >= 1);
        assert!(mono_ms() >= first);
    }
}
