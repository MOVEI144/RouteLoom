//! Host-side USB Site Authority adapter (design G-SEC P4 §8.3): the
//! gateway between HostOps 0x60-0x63 (join inner schema 2, #116) and the
//! Site Authority.
//!
//! Trust boundary. Frames reach the inbox only after the session layer
//! verified them, and the lane feeds this adapter only while a session is
//! authenticated AND advertises [`site_capable`] (bit 9 +
//! `CAP_HOST_OPS_V1`; bit 8 is v1 history — never accepted). The adapter
//! additionally binds the constructor's gateway identity into every
//! [`RelayKey`][super::transport::RelayKey] it builds and refuses ups
//! naming any other gateway; the USB incarnation (the authenticated
//! session id) binds by instance scoping — one adapter per session,
//! closed on any boundary, so delayed downs or request mappings can
//! never leak into a new session.
//!
//! Shapes. The authority only speaks EDHOC, so every down echoes phase 4;
//! a phase-5 up is refused with an H→G 0x62 `HostAborted` (P3-5 resume is
//! not implemented, and 0x62 needs no relay object — the peer's phase-5
//! object support is unknown). 0x60 ups carrying an abort object end the
//! relay like a 0x62. Authority aborts are 0x62 only (the key carries the
//! full #116 token) — never a 0x61 status-2 body. There are no USB chunk
//! helpers in the protocol crate: the host always sends single 0x61
//! frames (a valid relay object tops out at 992 B, inside the 1005 B
//! item bound) and the gateway chunks onward on the Wire lane.
//!
//! Mapping tables. The provisional [`AbortReason`][super::transport::AbortReason]
//! values collide numerically with the USB enums, so they are NEVER cast
//! — each table matches every variant explicitly (no wildcard), and a new
//! variant breaks the build until the table names it:
//!
//! ```text
//! authority abort → H→G 0x62 reason (full token from the relay key):
//!   every reason → HostAborted(4): the host side owns reason 4 only.
//! G→H 0x62 reason → lane action (all end the attempt; an abort is never
//! answered with an abort):
//!   ProxyAborted(1)   → end attempt (proxy gave up)
//!   GatewayExpired(2)  → end attempt (proxy slot timed out)
//!   DeliveryFailed(3)  → end attempt (m2 bytes are not retained: no resend)
//!   HostAborted(4)     → end attempt (our abort echoed, or a confused peer)
//!   Superseded(5)      → end attempt (a newer key replaced this relay)
//! G→H 0x63 result → lane action (Ok = queued on the gateway's Wire lane,
//! NOT device delivery — usb-protocol.md §9; strictly correlated to our
//! request id, stray results ignored):
//!   Ok            → continue (next up / 0x62 / timers decide)
//!   Busy, NoRoute, Indeterminate, Denied, Unsupported, Invalid → end attempt
//! ```
//!
//! Queue. [`JoinTransport::deliver`][super::transport::JoinTransport]
//! admits one encoded frame into a bounded queue ([`DOWN_QUEUE_CAP`]
//! items, [`DOWN_ITEM_MAX`] bytes each, [`DOWN_TTL_MS`]ms TTL); admission
//! failures end the attempt via `fail_attempt` (see `SiteService::with`).
//! Expired items are dropped at drain time — their attempts already ended
//! by the authority timers — and a writer-full remainder is requeued at
//! the front WITHOUT refreshing its TTL.

use std::collections::{HashMap, VecDeque};
use std::sync::{mpsc, Arc, Condvar, Mutex, MutexGuard};
use std::time::Duration;

use routeloom_protocol::authority::CarrierKind;
use routeloom_protocol::host_ops::{
    decode_authority_up, decode_site_state_report, encode_authority_down, encode_site_state_set,
    AuthorityFragment, SiteStateAction, SiteStateSet, AUTHORITY_FRAGMENT_DATA_MAX,
    AUTHORITY_FRAGMENT_TOTAL_MAX, CAP_AUTHORITY_CHANNEL_V1, HOST_OPS_SCHEMA, SUB_AUTHORITY_UP,
    SUB_SITE_STATE_REPORT,
};
use routeloom_protocol::host_ops::{ConfigOpsResult, CAP_HOST_OPS_V1};
use routeloom_protocol::join_relay::{
    decode_join_relay_abort, decode_join_relay_result, decode_join_relay_up,
    encode_join_relay_abort, encode_join_relay_down, join_relay_sub, JoinRelayAbort, JoinRelayDown,
    RelayAbortReason, RelayBody, RelayDirection, RelayHeader, RelayObject, RelayState, RelayToken,
    CAP_JOIN_RELAY_V2, PHASE_RESUME, SUB_JOIN_RELAY_ABORT, SUB_JOIN_RELAY_RESULT,
    SUB_JOIN_RELAY_UP,
};
use routeloom_protocol::{Frame, FrameKind};
use routeloom_provision::signer::fill_random;

use super::authority_channel::{AuthorityOutbound, AuthorityTransport};
use super::group_keys::HostTime;
use super::transport::{
    AbortReason, DeliverReject, DownStatus, JoinTransport, Outbound, RelayDown, RelayKey, RelayUp,
};
use crate::{mono_ms, now_ms, push_event, State};

/// Down-queue depth (G-SEC P4 §8.3).
pub const DOWN_QUEUE_CAP: usize = 8;
/// One queued frame, inner bytes (a valid 0x61 tops out at
/// 4 + 8 + 992 = 1004 B).
pub const DOWN_ITEM_MAX: usize = 1005;
/// A queued down older than this never goes on the wire.
pub const DOWN_TTL_MS: u64 = 20_000;
/// Outstanding 0x61/0x62 requests awaiting their 0x63 (oldest evicted).
const REQUEST_MAP_CAP: usize = 32;
/// Verified 0x60-0x63 bodies waiting for the lane.
const INBOX_CAP: usize = 64;
const RELAY_SLOTS_CAP: usize = 64;
const RELAY_SLOT_TTL_MS: u64 = 30_000;
const TICK_MS: u64 = 100;
/// Request ids for this lane live in their own high range ("ST") so they
/// can never alias a DataToMesh, dispatcher, node-status or group id.
const REQUEST_BASE: u64 = 0x5354_0000_0000_0000;
const REQUEST_MASK: u64 = 0xFFFF_0000_0000_0000;

/// True for the HostOps bodies this lane owns (0x60-0x63 join relay
/// plus 0x64-0x67 authority; the frame router's test — the bodies only
/// reach it session-verified).
pub fn owns(inner: &[u8]) -> bool {
    join_relay_sub(inner).is_some() || authority_sub(inner).is_some()
}

/// The authority subcommand of an inner body, if any (HostOps schema 1,
/// 0x64-0x67 — the mirror of `join_relay_sub` for schema 2).
pub fn authority_sub(inner: &[u8]) -> Option<u8> {
    if inner.len() < 2 || inner[0] != HOST_OPS_SCHEMA {
        return None;
    }
    (SUB_AUTHORITY_UP..=SUB_SITE_STATE_REPORT)
        .contains(&inner[1])
        .then_some(inner[1])
}

/// The family rides the HostOps carrier: both bits must be advertised.
/// The lane applies this gate before any up touches the authority, and
/// before any down goes out — join never opens to uncapable callers.
pub fn site_capable(capability: u32) -> bool {
    capability & CAP_JOIN_RELAY_V2 != 0 && capability & CAP_HOST_OPS_V1 != 0
}

/// The authority twin of [`site_capable`]: bit 10 (never bit 9, which
/// join-relay-v2 owns) plus the HostOps carrier bit. The lane binds the
/// authority adapter independently — an authority-only gateway gets no
/// relay downs, and a relay-only one gets no 0x65.
pub fn authority_capable(capability: u32) -> bool {
    capability & CAP_AUTHORITY_CHANNEL_V1 != 0 && capability & CAP_HOST_OPS_V1 != 0
}

/// Authority abort → the reason of an H→G 0x62. Explicit per variant;
/// the host side owns reason 4 only.
pub fn abort_reason_62(reason: AbortReason) -> RelayAbortReason {
    match reason {
        AbortReason::Busy => RelayAbortReason::HostAborted,
        AbortReason::UnknownRelay => RelayAbortReason::HostAborted,
        AbortReason::Timeout => RelayAbortReason::HostAborted,
        AbortReason::AuthorityError => RelayAbortReason::HostAborted,
    }
}

/// 0x63 result → does the attempt continue? Only Ok (queued on the
/// gateway's Wire lane — never device delivery). Every other result ends
/// the attempt; `Timeout` cannot arrive (the codec rejects it on 0x63)
/// but is still named so no future result slips through a wildcard.
fn result_continues(result: ConfigOpsResult) -> bool {
    match result {
        ConfigOpsResult::Ok => true,
        ConfigOpsResult::Busy => false,
        ConfigOpsResult::Denied => false,
        ConfigOpsResult::Unsupported => false,
        ConfigOpsResult::Invalid => false,
        ConfigOpsResult::Indeterminate => false,
        ConfigOpsResult::NoRoute => false,
        ConfigOpsResult::Timeout => false,
    }
}

/// Adapter counters (lane diagnostics; the authority counts ended
/// attempts separately as `relay_failed`).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AdapterStats {
    pub admitted: u64,
    pub rejected_full: u64,
    pub rejected_large: u64,
    pub rejected_closed: u64,
    pub expired: u64,
    pub requeue_dropped: u64,
    pub requests_evicted: u64,
    pub phase5_refused: u64,
    pub malformed: u64,
    pub unexpected_gateway: u64,
    pub stray_aborts: u64,
    pub stray_results: u64,
    pub relay_full: u64,
    pub binding_conflicts: u64,
}

/// One queued down-link frame, ready for the writer queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadyDown {
    pub bytes: Vec<u8>,
    pub key: RelayKey,
    /// A Final down, any abort, or a phase-5 refusal: the relay is over
    /// once its 0x63 arrives (or fails to).
    pub terminal: bool,
    /// Admission time (host wall ms); never refreshed by requeueing.
    pub admitted_ms: u64,
}

/// A live relay the adapter knows: the full key (0x62/0x63 name the
/// same #116 token). Keyed by proxy plus the full token — epochs are
/// part of the identity, so a recycled relay id from a new incarnation
/// (or a same-numbered epoch from another proxy) never aliases a live
/// relay.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RelaySlot {
    key: RelayKey,
    expires_ms: u64,
}

fn slot_of(key: RelayKey) -> (u64, RelayToken) {
    (
        key.proxy,
        RelayToken {
            gateway_epoch: key.gateway_epoch,
            proxy_epoch: key.proxy_epoch,
            relay_id: key.relay_id,
        },
    )
}

struct Inner {
    closed: bool,
    queue: VecDeque<ReadyDown>,
    relays: HashMap<(u64, RelayToken), RelaySlot>,
    requests: VecDeque<(u64, RelayKey, bool)>,
    stats: AdapterStats,
}

/// The USB gateway adapter: one instance per authenticated session,
/// constructed with the session's gateway identity and USB incarnation
/// (session id). Implements [`JoinTransport`] (admission into the
/// bounded down queue) and decodes the 0x60/0x62/0x63 inbox.
pub struct UsbSiteAdapter {
    gateway: u64,
    usb_incarnation: u64,
    inner: Mutex<Inner>,
}

impl UsbSiteAdapter {
    pub fn new(gateway: u64, usb_incarnation: u64) -> Arc<Self> {
        Arc::new(Self {
            gateway,
            usb_incarnation,
            inner: Mutex::new(Inner {
                closed: false,
                queue: VecDeque::new(),
                relays: HashMap::new(),
                requests: VecDeque::new(),
                stats: AdapterStats::default(),
            }),
        })
    }

    /// The gateway identity bound into every RelayKey this adapter builds.
    pub fn gateway(&self) -> u64 {
        self.gateway
    }

    /// The USB session id this adapter serves; the lane drops the adapter
    /// on any session boundary so incarnations never mix.
    pub fn usb_incarnation(&self) -> u64 {
        self.usb_incarnation
    }

    pub fn stats(&self) -> AdapterStats {
        self.lock().stats
    }

    /// Session end: drops the down queue, the relay directory and the
    /// request mapping. Later `deliver` calls fail Closed (their attempts
    /// end via `fail_attempt`) and later inbox calls refuse — a closed
    /// adapter never feeds a new session.
    pub fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        inner.queue.clear();
        inner.relays.clear();
        inner.requests.clear();
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().expect("site usb adapter poisoned")
    }

    /// Decodes a 0x60 into an authority input. Phase 4 only: phase 5 is
    /// refused with an H→G 0x62 (queued, may itself be refused when the
    /// queue is full — the relay then dies at the proxy, with no
    /// authority state either way), and an abort object ends the relay.
    pub fn handle_up(&self, inner: &[u8], now_ms: u64) -> Result<UpOutcome, UpError> {
        let mut guard = self.lock();
        if guard.closed {
            return Err(UpError::Closed);
        }
        let Ok(up) = decode_join_relay_up(inner) else {
            guard.stats.malformed += 1;
            return Err(UpError::Malformed);
        };
        if up.gateway != self.gateway {
            guard.stats.unexpected_gateway += 1;
            return Err(UpError::UnexpectedGateway);
        }
        let Ok(object) = up.relay_object() else {
            guard.stats.malformed += 1;
            return Err(UpError::Malformed);
        };
        let header = &object.header;
        // The constructor identity binds the key — not the wire claim
        // (verified equal above, so a confused gateway cannot smuggle a
        // foreign gateway id into the authority's ledger attribution).
        let key = RelayKey {
            gateway: self.gateway,
            proxy: up.from_proxy,
            gateway_epoch: header.gateway_epoch,
            proxy_epoch: header.proxy_epoch,
            relay_id: header.relay_id,
            joiner_mac: header.joiner_mac,
        };
        let slot = slot_of(key);
        let expired: Vec<_> = guard
            .relays
            .iter()
            .filter_map(|(slot, relay)| (relay.expires_ms <= now_ms).then_some(*slot))
            .collect();
        for expired_slot in expired {
            guard.relays.remove(&expired_slot);
            drop_queued(&mut guard.queue, expired_slot);
            guard
                .requests
                .retain(|(_, key, _)| slot_of(*key) != expired_slot);
        }
        if header.state == RelayState::Abort {
            // The proxy ended the relay with an abort object rather than
            // 0x62: drop anything queued for it; the lane fails the
            // attempt. Never answer an abort with an abort.
            guard.relays.remove(&slot);
            drop_queued(&mut guard.queue, slot);
            return Ok(UpOutcome::ProxyAbort { key });
        }
        if header.phase == PHASE_RESUME {
            // P3-5 RLRES1 resume is not implemented: refuse with 0x62, not
            // a 0x61 — the peer's phase-5 relay-object support is unknown.
            guard.stats.phase5_refused += 1;
            if let Ok(bytes) = abort62_bytes(key, RelayAbortReason::HostAborted) {
                let _ = admit_bytes_locked(&mut guard, bytes, key, true, now_ms);
            }
            return Ok(UpOutcome::Phase5Refused);
        }
        let RelayBody::Message(body) = &object.body else {
            guard.stats.malformed += 1;
            return Err(UpError::Malformed);
        };
        if let Some(existing) = guard.relays.get_mut(&slot) {
            if existing.key != key {
                guard.stats.binding_conflicts += 1;
                return Err(UpError::BindingConflict);
            }
            existing.expires_ms = now_ms.saturating_add(RELAY_SLOT_TTL_MS);
        } else {
            if guard.relays.len() >= RELAY_SLOTS_CAP {
                guard.stats.relay_full += 1;
                if let Ok(bytes) = abort62_bytes(key, RelayAbortReason::HostAborted) {
                    let _ = admit_bytes_locked(&mut guard, bytes, key, true, now_ms);
                }
                return Ok(UpOutcome::CapacityRefused);
            }
            guard.relays.insert(
                slot,
                RelaySlot {
                    key,
                    expires_ms: now_ms.saturating_add(RELAY_SLOT_TTL_MS),
                },
            );
        }
        Ok(UpOutcome::Relay(RelayUp {
            key,
            hops: up.hops,
            phase: header.phase,
            step: header.step,
            joiner_rssi_dbm: header.joiner_rssi_dbm,
            body: body.clone(),
        }))
    }

    /// Handles a G→H 0x62. Every reason ends the attempt (see the module
    /// table); queued downs for the relay are dropped and its directory
    /// entry retired here, the lane fails the authority attempt.
    pub fn handle_abort(&self, inner: &[u8]) -> Result<AbortOutcome, AbortError> {
        let mut guard = self.lock();
        if guard.closed {
            return Err(AbortError::Closed);
        }
        let Ok(abort) = decode_join_relay_abort(inner) else {
            guard.stats.malformed += 1;
            return Err(AbortError::Malformed);
        };
        // Full-slot match: an abort for a recycled relay id from
        // another incarnation (or another proxy) retires nothing.
        let slot = (abort.proxy, abort.token());
        let Some(entry) = guard.relays.remove(&slot) else {
            guard.stats.stray_aborts += 1;
            return Ok(AbortOutcome::Unknown);
        };
        drop_queued(&mut guard.queue, slot);
        Ok(AbortOutcome::RelayOver {
            key: entry.key,
            reason: abort.reason,
        })
    }

    /// Handles a G→H 0x63, strictly correlated to our 0x61/0x62 request
    /// id: a result for an unknown request, or one naming a different
    /// relay than the request did, is consumed and ignored.
    pub fn handle_result(&self, request: u64, inner: &[u8]) -> Result<ResultOutcome, ResultError> {
        let mut guard = self.lock();
        if guard.closed {
            return Err(ResultError::Closed);
        }
        let Ok(result) = decode_join_relay_result(inner) else {
            guard.stats.malformed += 1;
            return Err(ResultError::Malformed);
        };
        let Some(index) = guard.requests.iter().position(|(id, _, _)| *id == request) else {
            guard.stats.stray_results += 1;
            return Ok(ResultOutcome::Stray);
        };
        let (_, key, terminal) = guard.requests.remove(index).expect("request index");
        // Answered our request id but named a different relay: the entry
        // is consumed (a request is answered once) and the body ignored —
        // the named relay's fate is decided by its own result or the
        // authority timers, never by a mismatched id. An Ok always
        // carries the complete token; a failed result may name only
        // (proxy, relay_id), so epochs gate only when valid.
        let token_mismatch = result.token().valid() && result.token() != slot_of(key).1;
        if result.proxy != key.proxy || result.relay_id != key.relay_id || token_mismatch {
            guard.stats.stray_results += 1;
            return Ok(ResultOutcome::Stray);
        }
        if !result_continues(result.result) {
            let slot = slot_of(key);
            guard.relays.remove(&slot);
            drop_queued(&mut guard.queue, slot);
            return Ok(ResultOutcome::Failed { key });
        }
        if terminal {
            guard.relays.remove(&slot_of(key));
        }
        Ok(ResultOutcome::Acked { key })
    }

    /// Takes every unexpired queued down (oldest first). Expired items are
    /// dropped and counted — their attempts already ended by the
    /// authority timers, so no lane action follows them.
    pub fn take_ready(&self, now_ms: u64) -> Vec<ReadyDown> {
        let mut guard = self.lock();
        if guard.closed {
            return Vec::new();
        }
        let before = guard.queue.len();
        guard
            .queue
            .retain(|q| now_ms.saturating_sub(q.admitted_ms) <= DOWN_TTL_MS);
        guard.stats.expired += (before - guard.queue.len()) as u64;
        guard.queue.drain(..).collect()
    }

    /// Returns unsent downs (writer queue full) to the front, order kept,
    /// WITHOUT refreshing their TTL. A concurrent admit may have filled
    /// the queue meanwhile: the older requeued items win and newest
    /// excess is dropped and counted (its relay still ends by the
    /// authority timers).
    pub fn requeue_front(&self, downs: Vec<ReadyDown>) {
        if downs.is_empty() {
            return;
        }
        let mut guard = self.lock();
        if guard.closed {
            return;
        }
        for down in downs.into_iter().rev() {
            guard.queue.push_front(down);
        }
        while guard.queue.len() > DOWN_QUEUE_CAP {
            guard.queue.pop_back();
            guard.stats.requeue_dropped += 1;
        }
    }

    /// Records a 0x61/0x62 actually handed to the writer queue under
    /// `request`, for 0x63 correlation. Call only after `try_send`
    /// succeeded — never for a frame still in this adapter's queue.
    pub fn note_sent(&self, request: u64, key: RelayKey, terminal: bool) {
        let mut guard = self.lock();
        if guard.closed {
            return;
        }
        guard.requests.push_back((request, key, terminal));
        while guard.requests.len() > REQUEST_MAP_CAP {
            guard.requests.pop_front();
            guard.stats.requests_evicted += 1;
        }
    }
}

fn drop_queued(queue: &mut VecDeque<ReadyDown>, slot: (u64, RelayToken)) {
    queue.retain(|q| slot_of(q.key) != slot);
}

fn admit_bytes_locked(
    inner: &mut Inner,
    bytes: Vec<u8>,
    key: RelayKey,
    terminal: bool,
    now_ms: u64,
) -> Result<(), DeliverReject> {
    if bytes.len() > DOWN_ITEM_MAX {
        inner.stats.rejected_large += 1;
        return Err(DeliverReject::TooLarge);
    }
    // A terminal shape ends the relay whether or not it fits: the lane
    // fails the attempt on rejection, so no later 0x62 may resurrect it.
    if terminal {
        inner.relays.remove(&slot_of(key));
    }
    if inner.queue.len() >= DOWN_QUEUE_CAP {
        inner.stats.rejected_full += 1;
        return Err(DeliverReject::QueueFull);
    }
    inner.queue.push_back(ReadyDown {
        bytes,
        key,
        terminal,
        admitted_ms: now_ms,
    });
    inner.stats.admitted += 1;
    Ok(())
}

/// An authority down → one 0x61 frame. Single frames only: the protocol
/// crate has no USB chunk helpers, and the gateway chunks onward on the
/// Wire lane itself.
fn down_object(down: &RelayDown) -> Result<Vec<u8>, DeliverReject> {
    let object = RelayObject {
        header: RelayHeader {
            dir: RelayDirection::Down,
            relay_id: down.key.relay_id,
            proxy: down.key.proxy,
            joiner_mac: down.key.joiner_mac,
            // Echoes the inbound exchange's phase (the authority only
            // speaks EDHOC, so this is 4 — never inferred from `step`).
            phase: down.phase,
            step: down.step,
            state: match down.status {
                DownStatus::Continue => RelayState::Continue,
                DownStatus::Final => RelayState::Final,
            },
            joiner_rssi_dbm: 0,
            gateway_epoch: down.key.gateway_epoch,
            proxy_epoch: down.key.proxy_epoch,
        },
        body: RelayBody::Message(down.body.clone()),
    };
    // Authority-produced shapes always validate (nonzero token, valid
    // proxy, unicast joiner MAC, down step 2/4/5 with its matching
    // state); the reachable failure is an oversize message body.
    let encoded = object.encode().map_err(|_| DeliverReject::TooLarge)?;
    encode_join_relay_down(&JoinRelayDown {
        to_proxy: down.key.proxy,
        object: encoded,
    })
    .map_err(|_| DeliverReject::TooLarge)
}

fn abort62_bytes(key: RelayKey, reason: RelayAbortReason) -> Result<Vec<u8>, DeliverReject> {
    encode_join_relay_abort(&JoinRelayAbort {
        proxy: key.proxy,
        relay_id: key.relay_id,
        gateway_epoch: key.gateway_epoch,
        proxy_epoch: key.proxy_epoch,
        reason,
    })
    .map_err(|_| DeliverReject::TooLarge)
}

impl JoinTransport for UsbSiteAdapter {
    fn deliver(&self, outbound: Outbound) -> Result<(), DeliverReject> {
        let mut guard = self.lock();
        if guard.closed {
            guard.stats.rejected_closed += 1;
            return Err(DeliverReject::Closed);
        }
        let key = outbound.key();
        let encoded: Result<(Vec<u8>, bool), DeliverReject> = match &outbound {
            Outbound::Down(down) => {
                down_object(down).map(|bytes| (bytes, down.status == DownStatus::Final))
            }
            // The key carries the full token, so an abort for even an
            // unknown relay still names it exactly on 0x62.
            Outbound::Abort { reason, .. } => {
                abort62_bytes(key, abort_reason_62(*reason)).map(|bytes| (bytes, true))
            }
        };
        // The encoders only fail TooLarge (oversize bodies — see
        // down_object), so a failure counts as a large rejection, like
        // the explicit item bound below.
        let (bytes, terminal) = encoded.inspect_err(|_| guard.stats.rejected_large += 1)?;
        admit_bytes_locked(&mut guard, bytes, key, terminal, now_ms())
    }
}

/// What a decoded 0x60 asks the lane to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum UpOutcome {
    /// A phase-4 message for the authority.
    Relay(RelayUp),
    /// A proxy abort object: queued downs already dropped, the directory
    /// entry retired; the lane ends the authority attempt.
    ProxyAbort { key: RelayKey },
    /// A phase-5 up, refused with an H→G 0x62 (queued if it fits —
    /// nothing further either way, no authority state exists for it).
    Phase5Refused,
    /// The bounded relay directory is full; a host abort was queued if possible.
    CapacityRefused,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum UpError {
    Malformed,
    UnexpectedGateway,
    BindingConflict,
    Closed,
}

/// What a decoded G→H 0x62 asks the lane to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortOutcome {
    /// The named relay is over: queued downs already dropped, the
    /// directory entry retired; the lane ends the authority attempt.
    RelayOver {
        key: RelayKey,
        reason: RelayAbortReason,
    },
    /// No live relay by that name (already retired): nothing to do.
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AbortError {
    Malformed,
    Closed,
}

/// What a decoded G→H 0x63 asks the lane to do.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultOutcome {
    /// Queued on the gateway's Wire lane (NOT device delivery): the
    /// attempt continues.
    Acked { key: RelayKey },
    /// Queue admission failed at the gateway: the lane ends the attempt.
    Failed { key: RelayKey },
    /// No matching request, or a relay mismatch: consumed and ignored.
    Stray,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResultError {
    Malformed,
    Closed,
}

/// Live up-fragments for one (device, transfer): the 960 B-grid slots
/// filled so far plus the byte image. At most 3 slots (2048 B ceiling);
/// a duplicate slot must repeat its bytes exactly, or the whole
/// assembly drops as a conflict (P5 §3.3: no content swap under a live
/// token). Stale slots (10 s) purge on the next up.
struct AuthoritySlot {
    kind: CarrierKind,
    total: u16,
    filled: [bool; 3],
    bytes: Vec<u8>,
    first_ms: u64,
}

struct AuthorityInner {
    closed: bool,
    queue: VecDeque<AuthorityDown>,
    slots: HashMap<(u64, u32), AuthoritySlot>,
    requests: VecDeque<(u64, u64, u32)>,
    next_transfer: u32,
    stats: AuthorityStats,
}

/// Adapter counters for the authority side (the relay side counts
/// separately in [`AdapterStats`]).
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuthorityStats {
    pub admitted: u64,
    pub rejected_full: u64,
    pub rejected_closed: u64,
    pub encode_refused: u64,
    pub expired: u64,
    pub requeue_dropped: u64,
    pub requests_evicted: u64,
    pub assemblies: u64,
    pub slots_busy: u64,
    pub conflicts: u64,
    pub malformed: u64,
    pub hop_mismatch: u64,
    pub reports_consumed: u64,
    pub reports_stray: u64,
    pub state_sets: u64,
}

/// One reassembled G→H carrier for the authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityUp {
    pub device: u64,
    pub kind: CarrierKind,
    pub bytes: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityUpError {
    Malformed,
    Closed,
}

/// What a decoded G→H 0x67 asks of the lane: nothing — receipts are
/// transport diagnostics, never decrypt/apply evidence, so the lane
/// only consumes them. Returned for tests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthorityReportOutcome {
    Consumed { device: u64, transfer_id: u32 },
    Stray,
}

/// One queued down-link authority frame (an encoded 0x65/0x66 body),
/// ready for the writer queue.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorityDown {
    pub bytes: Vec<u8>,
    pub device: u64,
    pub transfer_id: u32,
    /// Admission time (host wall ms); never refreshed by requeueing.
    pub admitted_ms: u64,
}

/// Up-fragment assemblies in flight (the gateway holds 2 object slots;
/// the host mirrors that bound per session).
const AUTHORITY_SLOTS: usize = 2;
/// An assembly older than this never completes (P5 §3.2: 10 s).
const AUTHORITY_WINDOW_MS: u64 = 10_000;

/// The USB authority adapter: one instance per authenticated session,
/// constructed with the session's gateway identity and USB incarnation
/// (session id). Implements [`AuthorityTransport`] (fragmentation into
/// the bounded 0x65 down queue) and reassembles the 0x64 inbox; 0x67
/// receipts only release request tracking, and 0x66 carries the
/// session-(re)bind QueryLocal plus WakeLocal for the gateway's own
/// channel-less Wake. Like the relay adapter, `close` drops
/// everything and later calls fail — a closed adapter never feeds a
/// new session.
pub struct UsbAuthorityAdapter {
    gateway: u64,
    usb_incarnation: u64,
    inner: Mutex<AuthorityInner>,
}

impl UsbAuthorityAdapter {
    pub fn new(gateway: u64, usb_incarnation: u64) -> Arc<Self> {
        Arc::new(Self {
            gateway,
            usb_incarnation,
            inner: Mutex::new(AuthorityInner {
                closed: false,
                queue: VecDeque::new(),
                slots: HashMap::new(),
                requests: VecDeque::new(),
                next_transfer: 1,
                stats: AuthorityStats::default(),
            }),
        })
    }

    /// The gateway identity 0x64 ups must name (or be relayed by — the
    /// hops rule pins `device == gateway` to `hops == 0`).
    pub fn gateway(&self) -> u64 {
        self.gateway
    }

    /// The USB session id this adapter serves; the lane drops the adapter
    /// on any session boundary so incarnations never mix.
    pub fn usb_incarnation(&self) -> u64 {
        self.usb_incarnation
    }

    pub fn stats(&self) -> AuthorityStats {
        self.lock().stats
    }

    fn lock(&self) -> MutexGuard<'_, AuthorityInner> {
        self.inner.lock().expect("authority adapter poisoned")
    }

    /// Session end: drops the down queue, assemblies and request mapping.
    /// Later `deliver` calls count `rejected_closed` (their rotation
    /// targets stay due and retry) and later inbox calls refuse — a
    /// closed adapter never feeds a new session.
    pub fn close(&self) {
        let mut inner = self.lock();
        inner.closed = true;
        inner.queue.clear();
        inner.slots.clear();
        inner.requests.clear();
    }

    /// Decodes one G→H 0x64 fragment into its assembly, returning the
    /// completed carriers (at most one: a fragment completes exactly the
    /// assembly it fills). Malformed input counts and refuses; nothing
    /// partial ever reaches the authority.
    pub fn handle_up(
        &self,
        inner_body: &[u8],
        now_ms: u64,
    ) -> Result<Vec<AuthorityUp>, AuthorityUpError> {
        let mut guard = self.lock();
        if guard.closed {
            return Err(AuthorityUpError::Closed);
        }
        let fragment = match decode_authority_up(inner_body) {
            Ok(fragment) => fragment,
            Err(_) => {
                guard.stats.malformed += 1;
                return Err(AuthorityUpError::Malformed);
            }
        };
        // The codec cannot see the gateway identity; the bridge enforces
        // the binding here: a 0-hop up names the gateway itself, and a
        // relayed up names someone else with 1..=16 hops.
        if fragment.device == self.gateway && fragment.hops != 0
            || fragment.device != self.gateway && fragment.hops == 0
        {
            guard.stats.hop_mismatch += 1;
            return Err(AuthorityUpError::Malformed);
        }
        guard
            .slots
            .retain(|_, slot| now_ms.saturating_sub(slot.first_ms) <= AUTHORITY_WINDOW_MS);
        let key = (fragment.device, fragment.transfer_id);
        let slot = match guard.slots.get_mut(&key) {
            Some(slot) => {
                if slot.kind != fragment.kind || slot.total != fragment.total {
                    guard.slots.remove(&key);
                    guard.stats.conflicts += 1;
                    return Err(AuthorityUpError::Malformed);
                }
                slot
            }
            None => {
                if guard.slots.len() >= AUTHORITY_SLOTS {
                    guard.stats.slots_busy += 1;
                    return Err(AuthorityUpError::Malformed);
                }
                guard.slots.insert(
                    key,
                    AuthoritySlot {
                        kind: fragment.kind,
                        total: fragment.total,
                        filled: [false; 3],
                        bytes: vec![0; fragment.total as usize],
                        first_ms: now_ms,
                    },
                );
                guard.slots.get_mut(&key).expect("slot inserted")
            }
        };
        let index = fragment.offset as usize / AUTHORITY_FRAGMENT_DATA_MAX;
        let start = fragment.offset as usize;
        let end = start + fragment.data.len();
        if slot.filled[index] {
            // A re-sent slot must repeat its bytes exactly.
            if slot.bytes[start..end] != fragment.data[..] {
                guard.slots.remove(&key);
                guard.stats.conflicts += 1;
                return Err(AuthorityUpError::Malformed);
            }
            return Ok(Vec::new());
        }
        slot.bytes[start..end].copy_from_slice(&fragment.data);
        slot.filled[index] = true;
        // The 960 B grid plus the codec's exact-length checks make the
        // slot count exact: total 960 needs slot 0, 961 needs 0 and 1.
        let need = (fragment.total as usize).div_ceil(AUTHORITY_FRAGMENT_DATA_MAX);
        if (0..need).all(|i| slot.filled[i]) {
            let slot = guard.slots.remove(&key).expect("slot filled");
            guard.stats.assemblies += 1;
            return Ok(vec![AuthorityUp {
                device: fragment.device,
                kind: fragment.kind,
                bytes: slot.bytes,
            }]);
        }
        Ok(Vec::new())
    }

    /// Consumes one G→H 0x67 receipt: releases the request tracking when
    /// the echoed request id is ours, counts everything else as stray.
    /// Results never touch member state (P5 §3.3: 0/1 are transport
    /// receipts, not decrypt/apply evidence).
    pub fn handle_report(
        &self,
        request: u64,
        inner_body: &[u8],
    ) -> Result<AuthorityReportOutcome, AuthorityUpError> {
        let mut guard = self.lock();
        if guard.closed {
            return Err(AuthorityUpError::Closed);
        }
        let report = match decode_site_state_report(inner_body) {
            Ok(report) => report,
            Err(_) => {
                guard.stats.malformed += 1;
                return Err(AuthorityUpError::Malformed);
            }
        };
        let position = guard.requests.iter().position(|(id, _, _)| *id == request);
        match position {
            Some(index) => {
                let (_, device, transfer_id) =
                    guard.requests.remove(index).expect("report tracked");
                let _ = report;
                guard.stats.reports_consumed += 1;
                Ok(AuthorityReportOutcome::Consumed {
                    device,
                    transfer_id,
                })
            }
            None => {
                guard.stats.reports_stray += 1;
                Ok(AuthorityReportOutcome::Stray)
            }
        }
    }

    /// Queues one H→G 0x66 (the lane sends QueryLocal on every capable
    /// bind so a reconnected gateway resyncs its local epochs; a Wake
    /// for the gateway itself leaves as WakeLocal from `deliver`).
    pub fn send_state_set(&self, set: &SiteStateSet, now_ms: u64) -> Result<(), DeliverReject> {
        let mut guard = self.lock();
        self.send_state_set_locked(&mut guard, set, now_ms)
    }

    fn send_state_set_locked(
        &self,
        inner: &mut AuthorityInner,
        set: &SiteStateSet,
        now_ms: u64,
    ) -> Result<(), DeliverReject> {
        if inner.closed {
            inner.stats.rejected_closed += 1;
            return Err(DeliverReject::Closed);
        }
        if inner.queue.len() >= DOWN_QUEUE_CAP {
            inner.stats.rejected_full += 1;
            return Err(DeliverReject::QueueFull);
        }
        inner.stats.state_sets += 1;
        inner.stats.admitted += 1;
        inner.queue.push_back(AuthorityDown {
            bytes: encode_site_state_set(set),
            device: self.gateway,
            transfer_id: 0,
            admitted_ms: now_ms,
        });
        Ok(())
    }

    /// The session-(re)bind resync: asks the gateway for its local
    /// authority epochs. Keyless and read-only — never an install.
    pub fn query_local(
        &self,
        site_epoch: u32,
        rs_epoch_hint: u32,
        gk_epoch_hint: u32,
        now_ms: u64,
    ) -> Result<(), DeliverReject> {
        self.send_state_set(
            &SiteStateSet {
                action: SiteStateAction::QueryLocal,
                site_epoch,
                rs_epoch_hint,
                gk_epoch_hint,
            },
            now_ms,
        )
    }

    /// Fragments one sealed carrier into 0x65 downs (960 B grid, one
    /// nonzero token per carrier). Fire-and-forget: a full queue or a
    /// closed session drops and counts — the channel layer already
    /// counted the send, and the rotation timers keep every target due
    /// and retry, so a drop is delay, never loss. The one exception is
    /// a Wake for the bound gateway itself, which leaves as 0x66
    /// WakeLocal instead of a relay-slot round trip (P5 §6.2).
    fn deliver_locked(&self, inner: &mut AuthorityInner, outbound: AuthorityOutbound, now_ms: u64) {
        if inner.closed {
            inner.stats.rejected_closed += 1;
            return;
        }
        if outbound.device == self.gateway && outbound.kind == CarrierKind::Wake {
            if let Some(set) = wake_local_set(&outbound.bytes) {
                let _ = self.send_state_set_locked(inner, &set, now_ms);
                return;
            }
        }
        if outbound.bytes.len() > AUTHORITY_FRAGMENT_TOTAL_MAX || outbound.bytes.is_empty() {
            inner.stats.encode_refused += 1;
            return;
        }
        let transfer_id = inner.next_transfer;
        inner.next_transfer = inner.next_transfer.wrapping_add(1).max(1);
        let total = outbound.bytes.len() as u16;
        let mut offset = 0_usize;
        let mut frames = Vec::new();
        while offset < outbound.bytes.len() {
            let end = (offset + AUTHORITY_FRAGMENT_DATA_MAX).min(outbound.bytes.len());
            let fragment = AuthorityFragment {
                device: outbound.device,
                transfer_id,
                kind: outbound.kind,
                hops: 0,
                total,
                offset: offset as u16,
                data: outbound.bytes[offset..end].to_vec(),
            };
            match encode_authority_down(&fragment) {
                Ok(bytes) => frames.push(bytes),
                Err(_) => {
                    inner.stats.encode_refused += 1;
                    return;
                }
            }
            offset = end;
        }
        // Admit atomically: a carrier's fragments never strand half
        // queued (the gateway would hold a partial assembly to timeout).
        if inner.queue.len() + frames.len() > DOWN_QUEUE_CAP {
            inner.stats.rejected_full += 1;
            return;
        }
        for bytes in frames {
            inner.stats.admitted += 1;
            inner.queue.push_back(AuthorityDown {
                bytes,
                device: outbound.device,
                transfer_id,
                admitted_ms: now_ms,
            });
        }
    }

    /// Drains the down queue: expired items (TTL, never refreshed) drop
    /// and count — their rotation targets already went due again by the
    /// authority timers.
    pub fn take_ready(&self, now_ms: u64) -> Vec<AuthorityDown> {
        let mut guard = self.lock();
        if guard.closed {
            return Vec::new();
        }
        let before = guard.queue.len();
        guard
            .queue
            .retain(|q| now_ms.saturating_sub(q.admitted_ms) <= DOWN_TTL_MS);
        guard.stats.expired += (before - guard.queue.len()) as u64;
        guard.queue.drain(..).collect()
    }

    /// Returns unsent downs (writer queue full) to the front, order kept,
    /// WITHOUT refreshing their TTL — mirroring the relay adapter: a
    /// concurrent admit may have filled the queue meanwhile, and then
    /// the older requeued items win while newest excess drops counted.
    pub fn requeue_front(&self, downs: Vec<AuthorityDown>) {
        if downs.is_empty() {
            return;
        }
        let mut guard = self.lock();
        if guard.closed {
            return;
        }
        for down in downs.into_iter().rev() {
            guard.queue.push_front(down);
        }
        while guard.queue.len() > DOWN_QUEUE_CAP {
            guard.queue.pop_back();
            guard.stats.requeue_dropped += 1;
        }
    }

    /// Remembers one in-flight 0x65/0x66 request id so its 0x67 receipt
    /// can release it (oldest evicted past the cap — the receipt for an
    /// evicted id just counts as stray).
    pub fn note_sent(&self, request: u64, device: u64, transfer_id: u32) {
        let mut guard = self.lock();
        if guard.closed {
            return;
        }
        guard.requests.push_back((request, device, transfer_id));
        while guard.requests.len() > REQUEST_MAP_CAP {
            guard.requests.pop_front();
            guard.stats.requests_evicted += 1;
        }
    }
}

/// Splits an 8 B Wake body (site_epoch, gk_epoch) into its 0x66
/// WakeLocal equivalent. Anything else is not a Wake-shaped body:
/// the carrier path (with its kind/total check) decides its fate,
/// never a guessed 0x66. The RS hint is unknown on this path — the
/// gateway acts on the GK hint only, like any QueryLocal mismatch.
fn wake_local_set(body: &[u8]) -> Option<SiteStateSet> {
    if body.len() != 8 {
        return None;
    }
    Some(SiteStateSet {
        action: SiteStateAction::WakeLocal,
        site_epoch: u32::from_be_bytes(body[0..4].try_into().ok()?),
        rs_epoch_hint: 0,
        gk_epoch_hint: u32::from_be_bytes(body[4..8].try_into().ok()?),
    })
}

impl AuthorityTransport for UsbAuthorityAdapter {
    fn deliver(&self, outbound: AuthorityOutbound) {
        let mut inner = self.lock();
        self.deliver_locked(&mut inner, outbound, now_ms());
    }
}

/// Verified 0x60-0x67 inner bodies posted by the USB read thread, FIFO so
/// ups, aborts, results, fragments and receipts are applied in wire order.
/// Never blocks the reader: a full inbox drops the body (the device
/// resends inside its own ack window, or the authority timers end the
/// attempt).
#[derive(Default)]
pub struct SiteInbox {
    queue: Mutex<VecDeque<(u64, Vec<u8>)>>,
    cv: Condvar,
}

impl SiteInbox {
    pub fn post(&self, request: u64, body: Vec<u8>) -> bool {
        let mut queue = self.queue.lock().expect("site inbox poisoned");
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
            .expect("site inbox poisoned")
            .drain(..)
            .collect()
    }

    fn wait(&self, dur: Duration) {
        let guard = self.queue.lock().expect("site inbox poisoned");
        if guard.is_empty() {
            let _ = self.cv.wait_timeout(guard, dur);
        }
    }
}

/// The USB link as the site lane sees it, sampled from the daemon's
/// authenticated session mirror (same construction as `group_link`).
struct SiteLink {
    active: bool,
    capable: bool,
    authority_capable: bool,
    session: u64,
    gateway: u64,
}

fn site_link(state: &State) -> SiteLink {
    let info = state.session.lock().expect("session poisoned");
    SiteLink {
        active: info.authenticated && info.id.is_some() && info.node.is_some(),
        capable: info.capability.is_some_and(site_capable),
        authority_capable: info.capability.is_some_and(authority_capable),
        session: info.id.unwrap_or(0),
        gateway: info.node.unwrap_or(0),
    }
}

/// Lane-private state: the bound session and its adapters (relay and
/// authority bind independently — a session may serve either family).
#[derive(Default)]
pub struct SiteLane {
    bound: Option<(u64, u64)>,
    adapter: Option<Arc<UsbSiteAdapter>>,
    authority_bound: Option<(u64, u64)>,
    authority: Option<Arc<UsbAuthorityAdapter>>,
    next_request: u64,
    noted_unbound_drop: bool,
}

impl SiteLane {
    fn request_id(&mut self) -> u64 {
        self.next_request = self.next_request.wrapping_add(1);
        REQUEST_BASE | (self.next_request & !REQUEST_MASK)
    }
}

/// One lane pass: session binding, authority timers, inbox pump, then the
/// down-queue drain onto the writer queue. Pure with respect to I/O
/// except the frame writes and event pushes, like the group lane's pass.
pub fn site_once(
    state: &State,
    outbound: &mpsc::SyncSender<crate::Outbound>,
    lane: &mut SiteLane,
    now: u64,
) {
    let Some(service) = state.site.as_deref() else {
        return;
    };
    let link = site_link(state);
    let want = (link.active && link.capable).then_some((link.session, link.gateway));
    // The bound adapter must serve exactly this session: incarnation and
    // gateway are verified, not assumed — any drift is a boundary, never
    // a reuse.
    let drifted = lane.adapter.as_ref().is_some_and(|a| match want {
        Some((session, gateway)) => a.usb_incarnation() != session || a.gateway() != gateway,
        None => true,
    });
    if lane.bound != want || drifted {
        if let Some(old) = lane.adapter.take() {
            // Session boundary (id, gateway, or capability changed): the
            // old session's relays, down queue and request mapping die
            // with its adapter — nothing is carried over, and the closed
            // adapter fails any in-flight delivery so its attempts end
            // instead of hanging.
            old.close();
            let (dropped, _) = service.with(|a| a.drop_gateway_relays(old.gateway()));
            if dropped > 0 {
                push_event(
                    state,
                    now,
                    format!("\"kind\":\"site.session_drop\",\"relays\":{dropped}"),
                );
            }
        }
        lane.bound = want;
        lane.noted_unbound_drop = false;
        lane.adapter = want.map(|(session, gateway)| {
            let adapter = UsbSiteAdapter::new(gateway, session);
            service.set_transport(adapter.clone());
            adapter
        });
        // Unbound: the transport slot keeps the closed adapter, whose
        // rejections fail attempts honestly until a session binds.
    }
    // The authority twin of the bind above: same boundary discipline,
    // but the transport slot clears to `None` on unbind (a kept closed
    // adapter would still report `attached: true`), and every fresh
    // bind opens with a QueryLocal so a reconnected gateway resyncs
    // its local epochs before any carrier flows.
    let want_authority =
        (link.active && link.authority_capable).then_some((link.session, link.gateway));
    let authority_drifted = lane
        .authority
        .as_ref()
        .is_some_and(|a| match want_authority {
            Some((session, gateway)) => a.usb_incarnation() != session || a.gateway() != gateway,
            None => true,
        });
    if lane.authority_bound != want_authority || authority_drifted {
        if let Some(old) = lane.authority.take() {
            old.close();
        }
        lane.authority_bound = want_authority;
        lane.noted_unbound_drop = false;
        lane.authority = want_authority.map(|(session, gateway)| {
            let adapter = UsbAuthorityAdapter::new(gateway, session);
            service.set_authority_transport(Some(adapter.clone()));
            let (site_epoch, rs_epoch, gk_epoch) = service.authority_epochs();
            let _ = adapter.query_local(site_epoch, rs_epoch, gk_epoch, now);
            adapter
        });
        if want_authority.is_none() {
            service.set_authority_transport(None);
        }
    }
    for (ms, fields) in service.tick(super::group_keys::HostTime {
        mono_ms: mono_ms(),
        unix_ms: now,
    }) {
        push_event(state, ms, fields);
    }
    let relay = lane.adapter.clone();
    let authority = lane.authority.clone();
    if relay.is_none() && authority.is_none() {
        // No capable session: drop anything posted — a stale up must
        // never be replayed into a future session's adapter. One event
        // per unbound stretch, not per frame: a chatty peer must not
        // flush the ring.
        if !state.site_inbox.drain().is_empty() && !lane.noted_unbound_drop {
            lane.noted_unbound_drop = true;
            push_event(
                state,
                now,
                "\"kind\":\"rx_drop\",\"reason\":\"site_no_session\"".to_string(),
            );
        }
        return;
    }
    let mut rng = |buf: &mut [u8]| fill_random(buf).is_ok();
    for (request, body) in state.site_inbox.drain() {
        if let Some(adapter) = relay.as_ref() {
            match join_relay_sub(&body) {
                Some(SUB_JOIN_RELAY_UP) => match adapter.handle_up(&body, now) {
                    Ok(UpOutcome::Relay(up)) => {
                        for (ms, fields) in service.handle_up(up, now) {
                            push_event(state, ms, fields);
                        }
                    }
                    Ok(UpOutcome::ProxyAbort { key }) => {
                        service.with(|a| a.fail_attempt(key));
                    }
                    Ok(UpOutcome::Phase5Refused | UpOutcome::CapacityRefused) | Err(_) => {}
                },
                Some(SUB_JOIN_RELAY_ABORT) => {
                    if let Ok(AbortOutcome::RelayOver { key, .. }) = adapter.handle_abort(&body) {
                        service.with(|a| a.fail_attempt(key));
                    }
                }
                Some(SUB_JOIN_RELAY_RESULT) => {
                    if let Ok(ResultOutcome::Failed { key }) = adapter.handle_result(request, &body)
                    {
                        service.with(|a| a.fail_attempt(key));
                    }
                }
                _ => {}
            }
        }
        if let Some(adapter) = authority.as_ref() {
            match authority_sub(&body) {
                Some(SUB_AUTHORITY_UP) => {
                    if let Ok(ups) = adapter.handle_up(&body, now) {
                        for up in ups {
                            let time = HostTime {
                                mono_ms: mono_ms(),
                                unix_ms: now,
                            };
                            for (ms, fields) in service
                                .handle_authority_up(up.device, up.kind, &up.bytes, time, &mut rng)
                            {
                                push_event(state, ms, fields);
                            }
                        }
                    }
                }
                // Receipts only release request tracking; host→device
                // subs (0x65/0x66) inbound are a confused peer, ignored.
                Some(SUB_SITE_STATE_REPORT) => {
                    let _ = adapter.handle_report(request, &body);
                }
                _ => {}
            }
        }
    }
    if let Some(adapter) = relay.as_ref() {
        let pending = adapter.take_ready(now);
        let mut unsent = Vec::new();
        let mut blocked = false;
        for item in pending {
            if blocked {
                unsent.push(item);
                continue;
            }
            let ReadyDown {
                bytes,
                key,
                terminal,
                admitted_ms,
            } = item;
            let request = lane.request_id();
            let frame = Frame {
                kind: FrameKind::HostOps,
                flags: 0,
                session: 0,
                request,
                body: bytes,
            };
            match outbound.try_send(crate::Outbound::Seal(frame)) {
                Ok(()) => adapter.note_sent(request, key, terminal),
                Err(mpsc::TrySendError::Full(item))
                | Err(mpsc::TrySendError::Disconnected(item)) => {
                    blocked = true;
                    let bytes = match item {
                        crate::Outbound::Seal(sent) => sent.body,
                        // Unreachable: the item above was just sealed.
                        crate::Outbound::Raw(_) => Vec::new(),
                    };
                    unsent.push(ReadyDown {
                        bytes,
                        key,
                        terminal,
                        admitted_ms,
                    });
                }
            }
        }
        adapter.requeue_front(unsent);
    }
    if let Some(adapter) = authority.as_ref() {
        let pending = adapter.take_ready(now);
        let mut unsent = Vec::new();
        let mut blocked = false;
        for item in pending {
            if blocked {
                unsent.push(item);
                continue;
            }
            let AuthorityDown {
                bytes,
                device,
                transfer_id,
                admitted_ms,
            } = item;
            let request = lane.request_id();
            let frame = Frame {
                kind: FrameKind::HostOps,
                flags: 0,
                session: 0,
                request,
                body: bytes,
            };
            match outbound.try_send(crate::Outbound::Seal(frame)) {
                Ok(()) => adapter.note_sent(request, device, transfer_id),
                Err(mpsc::TrySendError::Full(item))
                | Err(mpsc::TrySendError::Disconnected(item)) => {
                    blocked = true;
                    let bytes = match item {
                        crate::Outbound::Seal(sent) => sent.body,
                        // Unreachable: the item above was just sealed.
                        crate::Outbound::Raw(_) => Vec::new(),
                    };
                    unsent.push(AuthorityDown {
                        bytes,
                        device,
                        transfer_id,
                        admitted_ms,
                    });
                }
            }
        }
        adapter.requeue_front(unsent);
    }
}

/// The site lane thread: authority timers, USB inbox pump and down-queue
/// drain. Idle on the inbox condvar between 100 ms ticks.
pub fn site_loop(state: Arc<State>, outbound: mpsc::SyncSender<crate::Outbound>) {
    let mut lane = SiteLane::default();
    loop {
        site_once(&state, &outbound, &mut lane, now_ms());
        state.site_inbox.wait(Duration::from_millis(TICK_MS));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_protocol::join_relay::{
        encode_join_relay_result, encode_join_relay_up, JoinRelayResult, JoinRelayUp,
        RelayBody as Body, RelayStatusCode, PHASE_EDHOC,
    };

    const GATEWAY: u64 = 1;
    const PROXY: u64 = 2;
    const RELAY: u32 = 9;
    const GW_EPOCH: u32 = 7;
    const PX_EPOCH: u32 = 3;
    const SESSION: u64 = 7;
    const MAC: [u8; 6] = [2, 0, 0, 0, 0x12, 0x34];

    fn key() -> RelayKey {
        RelayKey {
            gateway: GATEWAY,
            proxy: PROXY,
            gateway_epoch: GW_EPOCH,
            proxy_epoch: PX_EPOCH,
            relay_id: RELAY,
            joiner_mac: MAC,
        }
    }

    fn up_object(phase: u8, step: u8, state: RelayState, body: Vec<u8>) -> Vec<u8> {
        RelayObject {
            header: RelayHeader {
                dir: RelayDirection::Up,
                relay_id: RELAY,
                proxy: PROXY,
                joiner_mac: MAC,
                phase,
                step,
                state,
                joiner_rssi_dbm: -70,
                gateway_epoch: GW_EPOCH,
                proxy_epoch: PX_EPOCH,
            },
            body: if state == RelayState::Abort {
                Body::Abort {
                    status: RelayStatusCode::Aborted,
                    retry_after_ms: 0,
                }
            } else {
                Body::Message(body)
            },
        }
        .encode()
        .unwrap()
    }

    fn up_inner(phase: u8, step: u8, body: Vec<u8>) -> Vec<u8> {
        encode_join_relay_up(&JoinRelayUp {
            gateway: GATEWAY,
            from_proxy: PROXY,
            hops: 3,
            object: up_object(phase, step, RelayState::Continue, body),
        })
        .unwrap()
    }

    fn up_inner_named(relay_id: u32, mac: [u8; 6]) -> Vec<u8> {
        let mut object =
            RelayObject::decode(&up_object(4, 1, RelayState::Continue, vec![1])).unwrap();
        object.header.relay_id = relay_id;
        object.header.joiner_mac = mac;
        encode_join_relay_up(&JoinRelayUp {
            gateway: GATEWAY,
            from_proxy: PROXY,
            hops: 3,
            object: object.encode().unwrap(),
        })
        .unwrap()
    }

    #[test]
    fn relay_directory_is_bounded_and_binding_is_stable() {
        let adapter = UsbSiteAdapter::new(GATEWAY, SESSION);
        for relay_id in 1..=RELAY_SLOTS_CAP as u32 {
            let up = up_inner_named(relay_id, MAC);
            assert!(matches!(
                adapter.handle_up(&up, 1000),
                Ok(UpOutcome::Relay(_))
            ));
        }
        assert_eq!(adapter.lock().relays.len(), RELAY_SLOTS_CAP);
        assert_eq!(
            adapter.handle_up(&up_inner_named(65, MAC), 1001),
            Ok(UpOutcome::CapacityRefused)
        );
        assert_eq!(adapter.lock().relays.len(), RELAY_SLOTS_CAP);
        assert_eq!(adapter.stats().relay_full, 1);
        let changed_mac = [2, 0, 0, 0, 0x12, 0x35];
        assert_eq!(
            adapter.handle_up(&up_inner_named(1, changed_mac), 1002),
            Err(UpError::BindingConflict)
        );
        let first = (
            PROXY,
            RelayToken {
                gateway_epoch: GW_EPOCH,
                proxy_epoch: PX_EPOCH,
                relay_id: 1,
            },
        );
        assert_eq!(
            adapter.lock().relays.get(&first).unwrap().key.joiner_mac,
            MAC
        );
        assert_eq!(adapter.stats().binding_conflicts, 1);
        assert!(matches!(
            adapter.handle_up(&up_inner_named(65, MAC), 1000 + RELAY_SLOT_TTL_MS + 1),
            Ok(UpOutcome::Relay(_))
        ));
        assert_eq!(adapter.lock().relays.len(), 1);
    }

    fn abort_object_up() -> Vec<u8> {
        encode_join_relay_up(&JoinRelayUp {
            gateway: GATEWAY,
            from_proxy: PROXY,
            hops: 3,
            object: up_object(PHASE_EDHOC, 1, RelayState::Abort, Vec::new()),
        })
        .unwrap()
    }

    fn down(key: RelayKey, step: u8, status: DownStatus, body: Vec<u8>) -> Outbound {
        Outbound::Down(RelayDown {
            key,
            phase: PHASE_EDHOC,
            step,
            status,
            body,
        })
    }

    fn abort62_inner(reason: RelayAbortReason) -> Vec<u8> {
        encode_join_relay_abort(&JoinRelayAbort {
            proxy: PROXY,
            relay_id: RELAY,
            gateway_epoch: GW_EPOCH,
            proxy_epoch: PX_EPOCH,
            reason,
        })
        .unwrap()
    }

    fn result_inner(request: u64, result: ConfigOpsResult) -> (u64, Vec<u8>) {
        let inner = encode_join_relay_result(&JoinRelayResult {
            result,
            proxy: PROXY,
            relay_id: RELAY,
            gateway_epoch: GW_EPOCH,
            proxy_epoch: PX_EPOCH,
        })
        .unwrap();
        (request, inner)
    }

    /// Feeds an m1 up and queues its m2, returning the adapter: the
    /// standard live-relay fixture.
    fn live_relay() -> Arc<UsbSiteAdapter> {
        let adapter = UsbSiteAdapter::new(GATEWAY, SESSION);
        let up = adapter
            .handle_up(&up_inner(4, 1, vec![1, 2, 3]), 1000)
            .unwrap();
        assert!(matches!(up, UpOutcome::Relay(_)));
        assert!(
            adapter.lock().relays.contains_key(&slot_of(key())),
            "m1 registers the relay"
        );
        adapter
    }

    #[test]
    fn owns_matches_only_the_join_relay_family() {
        assert!(owns(&up_inner(4, 1, vec![1])));
        assert!(owns(&abort62_inner(RelayAbortReason::ProxyAborted)));
        assert!(owns(&result_inner(1, ConfigOpsResult::Ok).1));
        assert!(owns(&[2, 0x60, 0, 0]));
        assert!(!owns(&[]));
        assert!(!owns(&[1, 0x60, 0, 0]));
        assert!(!owns(&[2, 0x41, 0, 0]));
        assert!(!owns(&[2, 0x6F, 0, 0]));
    }

    #[test]
    fn site_capable_needs_both_bits() {
        assert!(site_capable(CAP_JOIN_RELAY_V2 | CAP_HOST_OPS_V1));
        assert!(!site_capable(CAP_JOIN_RELAY_V2));
        assert!(!site_capable(CAP_HOST_OPS_V1));
        assert!(!site_capable(0));
        // Bit 8 is v1 history: never accepted, even with the carrier bit.
        assert!(!site_capable(
            routeloom_protocol::join_relay::CAP_JOIN_RELAY_V1 | CAP_HOST_OPS_V1
        ));
    }

    #[test]
    fn phase_gate_accepts_4_refuses_5() {
        let adapter = UsbSiteAdapter::new(GATEWAY, SESSION);
        let up = adapter
            .handle_up(&up_inner(4, 1, vec![1, 2, 3]), 1000)
            .unwrap();
        let UpOutcome::Relay(relay) = up else {
            panic!("phase 4 must relay");
        };
        assert_eq!(relay.key, key());
        assert_eq!(relay.phase, PHASE_EDHOC);
        assert_eq!(relay.step, 1);
        assert_eq!(relay.hops, 3);
        assert_eq!(relay.joiner_rssi_dbm, -70);
        assert_eq!(relay.body, vec![1, 2, 3]);

        let refused = adapter.handle_up(&up_inner(5, 1, vec![9]), 1000).unwrap();
        assert_eq!(refused, UpOutcome::Phase5Refused);
        assert_eq!(adapter.stats().phase5_refused, 1);
        // The refusal is an H→G 0x62 HostAborted on the down queue, naming
        // the refused relay's full token.
        let ready = adapter.take_ready(1000);
        assert_eq!(ready.len(), 1);
        assert!(ready[0].terminal);
        let abort = decode_join_relay_abort(&ready[0].bytes).unwrap();
        assert_eq!(abort.proxy, PROXY);
        assert_eq!(abort.relay_id, RELAY);
        assert_eq!(abort.gateway_epoch, GW_EPOCH);
        assert_eq!(abort.proxy_epoch, PX_EPOCH);
        assert_eq!(abort.reason, RelayAbortReason::HostAborted);
        // …and the refused relay holds no directory entry.
        assert!(!adapter.lock().relays.contains_key(&slot_of(key())));
    }

    #[test]
    fn unexpected_gateway_is_refused() {
        let adapter = UsbSiteAdapter::new(GATEWAY, SESSION);
        let foreign = encode_join_relay_up(&JoinRelayUp {
            gateway: 99,
            from_proxy: PROXY,
            hops: 3,
            object: up_object(PHASE_EDHOC, 1, RelayState::Continue, vec![1]),
        })
        .unwrap();
        assert_eq!(
            adapter.handle_up(&foreign, 1000),
            Err(UpError::UnexpectedGateway)
        );
        assert_eq!(adapter.stats().unexpected_gateway, 1);
        assert!(adapter.lock().relays.is_empty());
    }

    #[test]
    fn abort_reason_tables_are_explicit() {
        // 0x62 table: the host side owns reason 4 only — each row
        // asserted, so a silent numeric cast fails loudly instead.
        for reason in [
            AbortReason::Busy,
            AbortReason::UnknownRelay,
            AbortReason::Timeout,
            AbortReason::AuthorityError,
        ] {
            assert_eq!(abort_reason_62(reason), RelayAbortReason::HostAborted);
        }
        // An authority abort encodes as 0x62 with the relay's full
        // token (never a 0x61 status-2 body).
        let adapter = live_relay();
        let transport: &dyn JoinTransport = adapter.as_ref();
        transport
            .deliver(Outbound::Abort {
                key: key(),
                reason: AbortReason::Busy,
            })
            .unwrap();
        let ready = adapter.take_ready(1000);
        assert_eq!(ready.len(), 1);
        assert!(ready[0].terminal);
        let abort = decode_join_relay_abort(&ready[0].bytes).unwrap();
        assert_eq!(abort.proxy, PROXY);
        assert_eq!(abort.relay_id, RELAY);
        assert_eq!(abort.gateway_epoch, GW_EPOCH);
        assert_eq!(abort.proxy_epoch, PX_EPOCH);
        assert_eq!(abort.reason, RelayAbortReason::HostAborted);
        // ... and the aborted relay holds no directory entry.
        assert!(!adapter.lock().relays.contains_key(&slot_of(key())));
    }

    #[test]
    fn downs_carry_phase_4_and_final_maps_to_status_1() {
        let adapter = live_relay();
        let transport: &dyn JoinTransport = adapter.as_ref();
        transport
            .deliver(down(key(), 4, DownStatus::Final, vec![7; 64]))
            .unwrap();
        let ready = adapter.take_ready(1000);
        assert_eq!(ready.len(), 1);
        assert!(ready[0].terminal);
        let down = routeloom_protocol::join_relay::decode_join_relay_down(&ready[0].bytes).unwrap();
        assert_eq!(down.to_proxy, PROXY);
        let object = RelayObject::decode(&down.object).unwrap();
        assert_eq!(object.header.phase, PHASE_EDHOC);
        assert_eq!(object.header.step, 4);
        assert_eq!(object.header.state, RelayState::Final);
        assert_eq!(object.header.joiner_rssi_dbm, 0);
        assert_eq!(object.header.gateway_epoch, GW_EPOCH);
        assert_eq!(object.header.proxy_epoch, PX_EPOCH);
        assert_eq!(object.body, Body::Message(vec![7; 64]));
    }

    #[test]
    fn queue_bounds_and_ttl_hold() {
        let adapter = live_relay();
        let transport: &dyn JoinTransport = adapter.as_ref();
        for _ in 0..DOWN_QUEUE_CAP {
            assert_eq!(
                transport.deliver(down(key(), 2, DownStatus::Continue, vec![1])),
                Ok(())
            );
        }
        assert_eq!(
            transport.deliver(down(key(), 2, DownStatus::Continue, vec![1])),
            Err(DeliverReject::QueueFull)
        );
        assert_eq!(adapter.stats().rejected_full, 1);
        // An oversize message is refused even with room …
        adapter.take_ready(1000);
        assert_eq!(
            transport.deliver(down(key(), 2, DownStatus::Continue, vec![0; 961])),
            Err(DeliverReject::TooLarge)
        );
        assert_eq!(adapter.stats().rejected_large, 1);
        // … and a full-size message is one frame inside the item bound.
        transport
            .deliver(down(key(), 4, DownStatus::Final, vec![0; 960]))
            .unwrap();
        let ready = adapter.take_ready(1000);
        assert_eq!(ready.len(), 1);
        assert!(ready[0].bytes.len() <= DOWN_ITEM_MAX);
        // TTL: fresh items drain, old ones expire silently.
        transport
            .deliver(down(key(), 2, DownStatus::Continue, vec![1]))
            .unwrap();
        // (deliver stamps the wall clock; age it by draining in the future)
        let ready = adapter.take_ready(crate::now_ms() + DOWN_TTL_MS + 1);
        assert!(ready.is_empty());
        assert_eq!(adapter.stats().expired, 1);
    }

    #[test]
    fn session_drop_closes_everything() {
        let adapter = live_relay();
        let transport: &dyn JoinTransport = adapter.as_ref();
        transport
            .deliver(down(key(), 2, DownStatus::Continue, vec![1]))
            .unwrap();
        adapter.note_sent(0x5354_0000_0000_0001, key(), false);
        adapter.close();
        // Queue, directory and request map are gone …
        assert!(adapter.take_ready(2000).is_empty());
        // … and every entry point refuses or fails closed.
        assert_eq!(
            transport.deliver(down(key(), 2, DownStatus::Continue, vec![1])),
            Err(DeliverReject::Closed)
        );
        assert_eq!(
            adapter.handle_up(&up_inner(4, 1, vec![1]), 2000),
            Err(UpError::Closed)
        );
        assert_eq!(
            adapter.handle_abort(&abort62_inner(RelayAbortReason::ProxyAborted)),
            Err(AbortError::Closed)
        );
        assert_eq!(
            adapter.handle_result(1, &result_inner(1, ConfigOpsResult::Ok).1),
            Err(ResultError::Closed)
        );
        adapter.requeue_front(vec![ReadyDown {
            bytes: vec![1],
            key: key(),
            terminal: false,
            admitted_ms: 2000,
        }]);
        assert!(adapter.take_ready(2000).is_empty());
    }

    #[test]
    fn gateway_aborts_end_the_relay_explicitly() {
        // Every G→H reason — including HostAborted from the gateway side —
        // retires the same relay; nothing is answered with an abort.
        for reason in [
            RelayAbortReason::ProxyAborted,
            RelayAbortReason::GatewayExpired,
            RelayAbortReason::DeliveryFailed,
            RelayAbortReason::HostAborted,
            RelayAbortReason::Superseded,
        ] {
            let adapter = live_relay();
            let transport: &dyn JoinTransport = adapter.as_ref();
            transport
                .deliver(down(key(), 2, DownStatus::Continue, vec![1]))
                .unwrap();
            let outcome = adapter.handle_abort(&abort62_inner(reason)).unwrap();
            assert_eq!(outcome, AbortOutcome::RelayOver { key: key(), reason });
            assert!(adapter.take_ready(1000).is_empty());
            // Second abort for the same relay: already retired.
            assert_eq!(
                adapter.handle_abort(&abort62_inner(reason)).unwrap(),
                AbortOutcome::Unknown
            );
        }
        // An abort object riding 0x60 ends the relay the same way.
        let adapter = live_relay();
        let outcome = adapter.handle_up(&abort_object_up(), 1000).unwrap();
        assert_eq!(outcome, UpOutcome::ProxyAbort { key: key() });
    }

    #[test]
    fn results_correlate_and_fail_closed() {
        let adapter = live_relay();
        let transport: &dyn JoinTransport = adapter.as_ref();
        transport
            .deliver(down(key(), 2, DownStatus::Continue, vec![1]))
            .unwrap();
        let ready = adapter.take_ready(1000);
        assert_eq!(ready.len(), 1);
        adapter.note_sent(41, key(), false);
        // Ok continues the relay (queued on the Wire lane, not delivered).
        let (request, inner) = result_inner(41, ConfigOpsResult::Ok);
        assert_eq!(
            adapter.handle_result(request, &inner).unwrap(),
            ResultOutcome::Acked { key: key() }
        );
        // The request is consumed: a duplicate is stray.
        assert_eq!(
            adapter.handle_result(request, &inner).unwrap(),
            ResultOutcome::Stray
        );
        assert_eq!(adapter.stats().stray_results, 1);
        // Every non-Ok result fails the relay — the named table rows plus
        // the definitive refusals (Timeout cannot arrive: the codec
        // rejects it on 0x63).
        for result in [
            ConfigOpsResult::Busy,
            ConfigOpsResult::NoRoute,
            ConfigOpsResult::Indeterminate,
            ConfigOpsResult::Denied,
            ConfigOpsResult::Unsupported,
            ConfigOpsResult::Invalid,
        ] {
            let adapter = live_relay();
            let transport: &dyn JoinTransport = adapter.as_ref();
            transport
                .deliver(down(key(), 2, DownStatus::Continue, vec![1]))
                .unwrap();
            assert_eq!(adapter.take_ready(1000).len(), 1);
            adapter.note_sent(42, key(), false);
            let (_, inner) = result_inner(42, result);
            assert_eq!(
                adapter.handle_result(42, &inner).unwrap(),
                ResultOutcome::Failed { key: key() },
                "{result:?} must fail the relay"
            );
        }
        // A mismatched relay name is consumed and ignored.
        let adapter = live_relay();
        adapter.note_sent(43, key(), false);
        let foreign = encode_join_relay_result(&JoinRelayResult {
            result: ConfigOpsResult::NoRoute,
            proxy: PROXY,
            relay_id: RELAY + 1,
            gateway_epoch: GW_EPOCH,
            proxy_epoch: PX_EPOCH,
        })
        .unwrap();
        assert_eq!(
            adapter.handle_result(43, &foreign).unwrap(),
            ResultOutcome::Stray
        );
        // ... as is a mismatched epoch on an otherwise valid token.
        let adapter = live_relay();
        adapter.note_sent(44, key(), false);
        let foreign_epoch = encode_join_relay_result(&JoinRelayResult {
            result: ConfigOpsResult::Ok,
            proxy: PROXY,
            relay_id: RELAY,
            gateway_epoch: GW_EPOCH + 1,
            proxy_epoch: PX_EPOCH,
        })
        .unwrap();
        assert_eq!(
            adapter.handle_result(44, &foreign_epoch).unwrap(),
            ResultOutcome::Stray
        );
    }

    #[test]
    fn inbox_is_bounded_and_fifo() {
        let inbox = SiteInbox::default();
        for n in 0..INBOX_CAP {
            assert!(inbox.post(n as u64, vec![n as u8]));
        }
        assert!(!inbox.post(999, vec![9]));
        let drained = inbox.drain();
        assert_eq!(drained.len(), INBOX_CAP);
        assert_eq!(drained[0], (0, vec![0]));
        assert!(inbox.drain().is_empty());
    }

    // --- authority (0x64-0x67) ---

    use routeloom_protocol::host_ops::{
        decode_authority_down, encode_authority_up, encode_site_state_report, SiteStateReport,
        SiteStateResult, SUB_AUTHORITY_DOWN, SUB_SITE_STATE_SET,
    };

    const DEVICE: u64 = 0x101;
    const NOW: u64 = 1_790_000_000_000;

    fn up_bytes(
        device: u64,
        transfer: u32,
        kind: CarrierKind,
        hops: u8,
        total: u16,
        offset: u16,
        data: Vec<u8>,
    ) -> Vec<u8> {
        encode_authority_up(&AuthorityFragment {
            device,
            transfer_id: transfer,
            kind,
            hops,
            total,
            offset,
            data,
        })
        .unwrap()
    }

    fn r3_up(device: u64, hops: u8, transfer: u32, fill: u8) -> Vec<u8> {
        up_bytes(
            device,
            transfer,
            CarrierKind::R3,
            hops,
            16,
            0,
            vec![fill; 16],
        )
    }

    fn envelope_up(device: u64, transfer: u32, total: usize, offset: usize, fill: u8) -> Vec<u8> {
        let end = (offset + AUTHORITY_FRAGMENT_DATA_MAX).min(total);
        up_bytes(
            device,
            transfer,
            CarrierKind::Envelope,
            1,
            total as u16,
            offset as u16,
            vec![fill; end - offset],
        )
    }

    #[test]
    fn authority_sub_routes_0x64_to_0x67_only() {
        for sub in [
            SUB_AUTHORITY_UP,
            SUB_AUTHORITY_DOWN,
            SUB_SITE_STATE_SET,
            SUB_SITE_STATE_REPORT,
        ] {
            assert_eq!(authority_sub(&[HOST_OPS_SCHEMA, sub, 0, 0]), Some(sub));
        }
        // Join relay (schema 2) and foreign schemas never route here.
        assert_eq!(authority_sub(&[2, SUB_AUTHORITY_UP, 0, 0]), None);
        assert_eq!(authority_sub(&[HOST_OPS_SCHEMA, 0x60, 0, 0]), None);
        assert_eq!(authority_sub(&[HOST_OPS_SCHEMA]), None);
        assert_eq!(authority_sub(&[]), None);
        assert!(owns(&r3_up(DEVICE, 1, 5, 0xA5)));
        assert!(!owns(&[HOST_OPS_SCHEMA, 0x60, 0, 0]));
    }

    #[test]
    fn authority_capable_needs_bit10_never_bit9() {
        assert!(authority_capable(
            CAP_AUTHORITY_CHANNEL_V1 | CAP_HOST_OPS_V1
        ));
        // Bit 9 is join-relay-v2: an authority lane must not open on it.
        assert!(!authority_capable(CAP_JOIN_RELAY_V2 | CAP_HOST_OPS_V1));
        assert!(!authority_capable(CAP_AUTHORITY_CHANNEL_V1));
        assert!(!authority_capable(CAP_HOST_OPS_V1));
        assert!(!authority_capable(0));
    }

    #[test]
    fn up_single_fragment_assembles() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        let ups = adapter.handle_up(&r3_up(GATEWAY, 0, 9, 0xA5), NOW).unwrap();
        assert_eq!(
            ups,
            vec![AuthorityUp {
                device: GATEWAY,
                kind: CarrierKind::R3,
                bytes: vec![0xA5; 16],
            }]
        );
        assert_eq!(adapter.stats().assemblies, 1);
    }

    #[test]
    fn up_multi_fragment_envelope_assembles_out_of_order() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        let total = 1500_usize;
        // Second fragment first: held, nothing delivered.
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 3, total, 960, 0xBB), NOW)
            .unwrap()
            .is_empty());
        let ups = adapter
            .handle_up(&envelope_up(DEVICE, 3, total, 0, 0xAA), NOW)
            .unwrap();
        assert_eq!(ups.len(), 1);
        assert_eq!(ups[0].device, DEVICE);
        assert_eq!(ups[0].kind, CarrierKind::Envelope);
        assert_eq!(&ups[0].bytes[..960], &vec![0xAA; 960][..]);
        assert_eq!(&ups[0].bytes[960..], &vec![0xBB; 540][..]);
        assert_eq!(adapter.stats().assemblies, 1);
    }

    #[test]
    fn up_duplicate_slot_must_repeat_bytes_exactly() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        // First half of a 1500 B envelope.
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 11, 1500, 0, 0xA5), NOW)
            .unwrap()
            .is_empty());
        // The same slot re-sent with different bytes: the whole assembly
        // drops as a conflict (no content swap under a live token).
        let mut tampered = vec![0xA5; 960];
        tampered[959] = 0x5A;
        let tampered = up_bytes(DEVICE, 11, CarrierKind::Envelope, 1, 1500, 0, tampered);
        assert_eq!(
            adapter.handle_up(&tampered, NOW),
            Err(AuthorityUpError::Malformed)
        );
        assert_eq!(adapter.stats().conflicts, 1);
        // The slot is gone: the orphaned second half cannot complete it.
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 11, 1500, 960, 0xBB), NOW)
            .unwrap()
            .is_empty());
        assert_eq!(adapter.stats().assemblies, 0);
        // ...but an exact re-send of a live slot is a harmless no-op.
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 12, 1500, 0, 0xA5), NOW)
            .unwrap()
            .is_empty());
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 12, 1500, 0, 0xA5), NOW)
            .unwrap()
            .is_empty());
        assert_eq!(adapter.stats().conflicts, 1);
        let ups = adapter
            .handle_up(&envelope_up(DEVICE, 12, 1500, 960, 0xBB), NOW)
            .unwrap();
        assert_eq!(ups.len(), 1);
    }

    #[test]
    fn up_token_reuse_with_new_total_conflicts() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        // First half of a 1500 B envelope under token 7.
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 7, 1500, 0, 0xAA), NOW)
            .unwrap()
            .is_empty());
        // Same token claiming a new total: conflict, slot dropped.
        assert_eq!(
            adapter.handle_up(&envelope_up(DEVICE, 7, 1200, 0, 0xAA), NOW),
            Err(AuthorityUpError::Malformed)
        );
        assert_eq!(adapter.stats().conflicts, 1);
        // The orphaned second half of the original total cannot complete.
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 7, 1500, 960, 0xBB), NOW)
            .unwrap()
            .is_empty());
        assert_eq!(adapter.stats().assemblies, 0);
    }

    #[test]
    fn up_third_assembly_is_refused() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 1, 1500, 0, 1), NOW)
            .unwrap()
            .is_empty());
        assert!(adapter
            .handle_up(&envelope_up(DEVICE + 1, 1, 1500, 0, 2), NOW)
            .unwrap()
            .is_empty());
        assert_eq!(
            adapter.handle_up(&envelope_up(DEVICE + 2, 1, 1500, 0, 3), NOW),
            Err(AuthorityUpError::Malformed)
        );
        assert_eq!(adapter.stats().slots_busy, 1);
    }

    #[test]
    fn up_window_expires_stale_slots() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        assert!(adapter
            .handle_up(&envelope_up(DEVICE, 1, 1500, 0, 0xAA), NOW)
            .unwrap()
            .is_empty());
        // Past the 10 s window the first half is gone: the second half
        // opens a fresh (incomplete) assembly instead of completing.
        assert!(adapter
            .handle_up(
                &envelope_up(DEVICE, 1, 1500, 960, 0xBB),
                NOW + AUTHORITY_WINDOW_MS + 1
            )
            .unwrap()
            .is_empty());
        assert_eq!(adapter.stats().assemblies, 0);
        // Re-sending the first half completes the fresh assembly.
        let ups = adapter
            .handle_up(
                &envelope_up(DEVICE, 1, 1500, 0, 0xAA),
                NOW + AUTHORITY_WINDOW_MS + 1,
            )
            .unwrap();
        assert_eq!(ups.len(), 1);
        assert_eq!(adapter.stats().assemblies, 1);
    }

    #[test]
    fn up_hop_rule_pins_gateway_to_zero_hops() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        // Gateway-originated ups travel 0 hops; anything else mismatches.
        assert_eq!(
            adapter.handle_up(&r3_up(GATEWAY, 1, 1, 0), NOW),
            Err(AuthorityUpError::Malformed)
        );
        assert_eq!(
            adapter.handle_up(&r3_up(DEVICE, 0, 2, 0), NOW),
            Err(AuthorityUpError::Malformed)
        );
        assert_eq!(adapter.stats().hop_mismatch, 2);
        // 17 hops never reaches the bridge rule: the codec refuses it
        // (patched by hand — the encoder would refuse to build it).
        let mut bad_hops = r3_up(DEVICE, 1, 3, 0);
        bad_hops[4 + 8 + 4 + 1] = 17;
        assert_eq!(
            adapter.handle_up(&bad_hops, NOW),
            Err(AuthorityUpError::Malformed)
        );
        assert_eq!(adapter.stats().malformed, 1);
        assert_eq!(adapter.stats().assemblies, 0);
    }

    #[test]
    fn deliver_fragments_carriers_with_one_token() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        let mut bytes = vec![0xCC; 1500];
        bytes[0] = 0x01;
        adapter.deliver(AuthorityOutbound {
            device: DEVICE,
            kind: CarrierKind::Envelope,
            bytes,
        });
        let ready = adapter.take_ready(crate::now_ms());
        assert_eq!(ready.len(), 2);
        let first = decode_authority_down(&ready[0].bytes).unwrap();
        let second = decode_authority_down(&ready[1].bytes).unwrap();
        assert_eq!(first.device, DEVICE);
        assert_eq!(first.total, 1500);
        assert_eq!(first.offset, 0);
        assert_eq!(first.data.len(), 960);
        assert_eq!(second.offset, 960);
        assert_eq!(second.data.len(), 540);
        assert_eq!(first.transfer_id, second.transfer_id);
        assert_ne!(first.transfer_id, 0);
        assert_eq!(first.hops, 0);
        // Every fragment frame fits the HostOps item bound (4 + 20 + 960).
        for down in &ready {
            assert!(down.bytes.len() <= DOWN_ITEM_MAX);
        }
    }

    #[test]
    fn deliver_admits_atomically_or_refuses() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        for _ in 0..DOWN_QUEUE_CAP {
            adapter.deliver(AuthorityOutbound {
                device: DEVICE,
                kind: CarrierKind::Wake,
                bytes: vec![0; 8],
            });
        }
        // A 2-fragment carrier against a full queue: refused whole, the
        // queue keeps its 8 — no half-stranded assembly on the gateway.
        adapter.deliver(AuthorityOutbound {
            device: DEVICE,
            kind: CarrierKind::Envelope,
            bytes: vec![0xCC; 1500],
        });
        assert_eq!(adapter.stats().rejected_full, 1);
        assert_eq!(adapter.take_ready(crate::now_ms()).len(), DOWN_QUEUE_CAP);
    }

    #[test]
    fn report_consumes_tracked_requests_only() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        let request = 0x5354_0000_0000_0001;
        adapter.note_sent(request, DEVICE, 9);
        let report = encode_site_state_report(&SiteStateReport {
            result: SiteStateResult::ObjectQueued,
            local_state_valid: true,
            device: DEVICE,
            transfer_id: 9,
            received_len: 1500,
            local_current: 4,
            local_next: 0,
        });
        assert_eq!(
            adapter.handle_report(request, &report),
            Ok(AuthorityReportOutcome::Consumed {
                device: DEVICE,
                transfer_id: 9,
            })
        );
        assert_eq!(adapter.stats().reports_consumed, 1);
        // The same receipt twice: the tracking is gone, the second is stray.
        assert_eq!(
            adapter.handle_report(request, &report),
            Ok(AuthorityReportOutcome::Stray)
        );
        assert_eq!(adapter.stats().reports_stray, 1);
        assert_eq!(
            adapter.handle_report(request, &[HOST_OPS_SCHEMA, SUB_SITE_STATE_REPORT, 0, 1, 0]),
            Err(AuthorityUpError::Malformed)
        );
    }

    #[test]
    fn query_local_queues_a_keyless_state_set() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        adapter.query_local(3, 5, 9, NOW).unwrap();
        let ready = adapter.take_ready(NOW);
        assert_eq!(ready.len(), 1);
        assert_eq!(authority_sub(&ready[0].bytes), Some(SUB_SITE_STATE_SET));
        let set = routeloom_protocol::host_ops::decode_site_state_set(&ready[0].bytes).unwrap();
        assert_eq!(set.action, SiteStateAction::QueryLocal);
        assert_eq!(set.site_epoch, 3);
        assert_eq!(set.rs_epoch_hint, 5);
        assert_eq!(set.gk_epoch_hint, 9);
        assert_eq!(adapter.stats().state_sets, 1);
    }

    #[test]
    fn gateway_self_wake_leaves_as_wake_local() {
        // P5 §6.2: a Wake for the bound gateway itself is its local
        // equivalent — 0x66 WakeLocal — not a relay-slot round trip.
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        let mut body = Vec::new();
        body.extend_from_slice(&3_u32.to_be_bytes());
        body.extend_from_slice(&9_u32.to_be_bytes());
        adapter.deliver(AuthorityOutbound {
            device: GATEWAY,
            kind: CarrierKind::Wake,
            bytes: body,
        });
        let ready = adapter.take_ready(crate::now_ms());
        assert_eq!(ready.len(), 1);
        assert_eq!(authority_sub(&ready[0].bytes), Some(SUB_SITE_STATE_SET));
        let set = routeloom_protocol::host_ops::decode_site_state_set(&ready[0].bytes).unwrap();
        assert_eq!(set.action, SiteStateAction::WakeLocal);
        assert_eq!(set.site_epoch, 3);
        assert_eq!(set.gk_epoch_hint, 9);
        // A foreign Wake keeps the 0x65 carrier path.
        adapter.deliver(AuthorityOutbound {
            device: DEVICE,
            kind: CarrierKind::Wake,
            bytes: vec![0; 8],
        });
        let ready = adapter.take_ready(crate::now_ms());
        assert_eq!(ready.len(), 1);
        assert_eq!(authority_sub(&ready[0].bytes), Some(SUB_AUTHORITY_DOWN));
    }

    #[test]
    fn misshapen_gateway_wake_queues_no_state_set() {
        // Not an 8 B Wake body: never a malformed 0x66 — the carrier
        // path refuses it at encode, exactly like a foreign Wake of
        // the same shape.
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        adapter.deliver(AuthorityOutbound {
            device: GATEWAY,
            kind: CarrierKind::Wake,
            bytes: vec![0; 12],
        });
        assert!(adapter.take_ready(crate::now_ms()).is_empty());
        assert_eq!(adapter.stats().encode_refused, 1);
        assert_eq!(adapter.stats().state_sets, 0);
    }

    #[test]
    fn authority_close_refuses_everything() {
        let adapter = UsbAuthorityAdapter::new(GATEWAY, SESSION);
        adapter.deliver(AuthorityOutbound {
            device: DEVICE,
            kind: CarrierKind::Wake,
            bytes: vec![0; 8],
        });
        adapter.close();
        assert_eq!(
            adapter.handle_up(&r3_up(GATEWAY, 0, 1, 0), NOW),
            Err(AuthorityUpError::Closed)
        );
        adapter.deliver(AuthorityOutbound {
            device: DEVICE,
            kind: CarrierKind::Wake,
            bytes: vec![0; 8],
        });
        assert_eq!(adapter.stats().rejected_closed, 1);
        assert!(adapter.take_ready(NOW).is_empty());
        assert_eq!(
            adapter.handle_report(1, &[HOST_OPS_SCHEMA, SUB_SITE_STATE_REPORT, 0, 28]),
            Err(AuthorityUpError::Closed)
        );
    }
}
