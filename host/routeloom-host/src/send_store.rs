//! Operation table for the send path (Issues #8/#9, TX-I1 + CAP-I1).
//!
//! `OperationStore` is the seam between the API layer and storage: epochs,
//! idempotency records and lookups behind one interface so api1.rs never
//! touches storage directly. Two providers share this contract —
//! `MemoryOperationStore` (bounded RAM only, no persistence) and the SQLite
//! store in `sqlite_store.rs` (durable). TX-I2's dispatcher (`dispatch.rs`)
//! drives records past HOST_QUEUED through the same store boundary —
//! `prepare_dispatch` persists the dispatch identity before any USB write,
//! `update_operation` linearizes every later transition, and
//! `cancel_operation` shares that boundary so a cancel and a submit can
//! never both win.
//!
//! Identity is `(uid, network, admission_epoch, caller_key)`; the first
//! submit assigns `lineage:seq` and replays return the same id. Same
//! identity with different canonical bytes is a CONFLICT and the stored
//! record is never overwritten. Admission epochs rotate one hour after
//! opening; a closed epoch still answers known keys but rejects new ones
//! with EPOCH_CLOSED. Epochs retire only as a contiguous prefix once every
//! record in them is terminal and past its 24h protection; indeterminate
//! records pin their epoch. Quotas (contracts.json `capacity.*`) reject
//! with NO_CAPACITY — protected records are never evicted to make room.

use crate::canonical::SendRequest;
use crate::sqlite_store::SqliteOperationStore;
use std::collections::{BTreeSet, HashMap};

// contracts.json `capacity.*`.
pub const RECORD_CAP: usize = 4096;
pub const ACTIVE_CAP: usize = 32;
pub const ACTIVE_PER_PRINCIPAL_CAP: usize = 8;
pub const MAX_UNRETIRED_EPOCHS: usize = 32;
pub const EPOCH_WINDOW_MS: u64 = 3_600_000;
pub const RETENTION_MS: u64 = 86_400_000;
pub const STORE_BYTES_CAP: u64 = 33_554_432;
pub const RECORD_RESERVATION_BYTES: u64 = 4096;
/// TX-I1 RAM bound kept by the memory provider; the durable store pages
/// scopes to disk and does not cap their count.
pub const SCOPE_CAP: usize = 64;

// contracts.json `capacity.host_rate_per_minute` / `burst`
// (HOST_CONTROL_SMALL): 2 admission calls per minute, bursts to 16.
// The same budget applies per principal and summed over all principals
// (04 §4: 主体/全体rate limit), and it is charged even on duplicates and
// CONFLICT resubmits so epoch-/replay-spam cannot bypass it.
pub const HOST_RATE_PER_MINUTE: u64 = 2;
pub const HOST_RATE_BURST: u64 = 16;
pub const RATE_TOKEN_INTERVAL_MS: u64 = 60_000 / HOST_RATE_PER_MINUTE;
/// Bound on principals with tracked buckets. A bucket refilled to full
/// holds no state a fresh one would not, so those are pruned first.
const MAX_TRACKED_PRINCIPALS: usize = 1024;

/// Dispatch states (03-send-api.md §5). The TX-I2 dispatcher in
/// `dispatch.rs` drives records through them via the store-level
/// transitions; the API layer only ever admits HOST_QUEUED.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DispatchState {
    HostQueued,
    DispatchPrepared,
    GatewayAccepted,
    EndSdkReceived,
    ExpiredBeforeDispatch,
    CancelledBeforeDispatch,
    RejectedNotAccepted,
    Indeterminate,
    TimeUncertain,
}

impl DispatchState {
    pub fn name(self) -> &'static str {
        match self {
            Self::HostQueued => "HOST_QUEUED",
            Self::DispatchPrepared => "DISPATCH_PREPARED",
            Self::GatewayAccepted => "GATEWAY_ACCEPTED",
            Self::EndSdkReceived => "END_SDK_RECEIVED",
            Self::ExpiredBeforeDispatch => "EXPIRED_BEFORE_DISPATCH",
            Self::CancelledBeforeDispatch => "CANCELLED_BEFORE_DISPATCH",
            Self::RejectedNotAccepted => "REJECTED_NOT_ACCEPTED",
            Self::Indeterminate => "INDETERMINATE",
            Self::TimeUncertain => "TIME_UNCERTAIN",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "HOST_QUEUED" => Self::HostQueued,
            "DISPATCH_PREPARED" => Self::DispatchPrepared,
            "GATEWAY_ACCEPTED" => Self::GatewayAccepted,
            "END_SDK_RECEIVED" => Self::EndSdkReceived,
            "EXPIRED_BEFORE_DISPATCH" => Self::ExpiredBeforeDispatch,
            "CANCELLED_BEFORE_DISPATCH" => Self::CancelledBeforeDispatch,
            "REJECTED_NOT_ACCEPTED" => Self::RejectedNotAccepted,
            "INDETERMINATE" => Self::Indeterminate,
            "TIME_UNCERTAIN" => Self::TimeUncertain,
            _ => return None,
        })
    }

    /// Terminal states end the gateway's send/resend responsibility and may
    /// retire after their protection lapses. INDETERMINATE is deliberately
    /// excluded: unknown outcomes pin their epoch instead of freeing it.
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::EndSdkReceived
                | Self::ExpiredBeforeDispatch
                | Self::CancelledBeforeDispatch
                | Self::RejectedNotAccepted
        )
    }

    /// In-flight against the dispatch pipeline (dispatch_seq/outbox slots).
    /// Merely queued records hold a record slot, not an active slot.
    pub fn is_active(self) -> bool {
        matches!(self, Self::DispatchPrepared | Self::GatewayAccepted)
    }
}

/// Scope whose admission epoch is tracked: one epoch per principal×network.
pub type EpochScope = (u32, u64);

/// Full identity of one caller submission (03-send-api.md §3).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct OpIdentity {
    pub uid: u32,
    pub network: u64,
    pub epoch: u64,
    pub key: [u8; 16],
}

#[derive(Clone, Debug)]
pub struct StoredOperation {
    pub seq: u64,
    /// Owning principal — queries authorize on the network grant;
    /// `operations.cancel` additionally requires the owning uid.
    pub uid: u32,
    pub network: u64,
    pub epoch: u64,
    pub key: [u8; 16],
    pub dest_kind: u8,
    pub dest: u64,
    pub delivery: u8,
    pub priority: u8,
    pub ttl_ms: u32,
    pub storage: u8,
    pub hop_limit: u8,
    /// Payload bytes are retained for the TX-I2 dispatcher handoff: the
    /// dispatcher rebuilds the SUBMIT body (canonical bytes) from them.
    pub payload: Vec<u8>,
    pub canonical: Vec<u8>,
    pub hash: [u8; 32],
    pub accepted_ms: u64,
    /// Process-monotonic admit stamp on the dispatcher's monotonic axis —
    /// the rewind-proof counterpart of `accepted_ms` (TX-I2 deadline
    /// arithmetic caps the wall deadline at `accepted_mono_ms + ttl`).
    /// 0 means no anchor: records loaded after a daemon restart and lane
    /// tombstones cannot prove trusted elapsed time and keep the
    /// pre-anchor wall-clock semantics.
    pub accepted_mono_ms: u64,
    pub dispatch_state: DispatchState,
    /// Set when the record enters a terminal state; protection lapses
    /// RETENTION_MS later. None for non-terminal records.
    pub terminal_ms: Option<u64>,
    /// Device-position binding once the TX-I2 dispatcher prepares this
    /// record (DISPATCH_PREPARED commit). None while HOST_QUEUED and never
    /// reassigned: one record owns at most one dispatch position.
    pub dispatch: Option<DispatchAttachment>,
}

impl StoredOperation {
    /// The host committed a final outcome for this record: a terminal
    /// vocabulary state, or `terminal_ms` set for a resolved device-terminal
    /// outcome that has no terminal vocabulary name (03 §5 has none for a
    /// completed BEST_EFFORT MAC attempt — the record stays
    /// GATEWAY_ACCEPTED with MAC_ATTEMPT_REPORTED evidence but leaves the
    /// active set and becomes retirable).
    pub fn concluded(&self) -> bool {
        self.dispatch_state.is_terminal() || self.terminal_ms.is_some()
    }
}

/// Result of an atomic HOST_QUEUED → DISPATCH_PREPARED transition.
#[derive(Debug)]
pub enum PrepareOutcome {
    /// Bound and state-committed; carries the new attachment.
    Prepared(DispatchAttachment),
    /// The record moved on (cancel/expiry raced in); carries its state.
    NotQueued(DispatchState),
    NotFound,
}

/// Result of `operations.cancel` (03 §5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CancelOutcome {
    /// Linearized before any external write could start.
    Cancelled,
    /// A USB write may already have left; carries the current state. The
    /// store still records the late `cancel_requested` observation.
    TooLate(DispatchState),
    NotFound,
}

/// Shared cancel transition used by both store providers. Cancellable iff
/// HOST_QUEUED or DISPATCH_PREPARED with `submitted == false` — the only
/// states where the host can still prove no external write began.
/// TIME_UNCERTAIN is only a wrapper the clock-rewind sweep parks records
/// in; the honesty rule is unchanged, so a provably-unsubmitted record
/// cancels regardless of the wrapper.
fn cancel_transition(op: &mut StoredOperation, now_ms: u64) -> CancelOutcome {
    let cancellable = match op.dispatch_state {
        DispatchState::HostQueued => true,
        DispatchState::DispatchPrepared => op.dispatch.as_ref().is_some_and(|d| !d.submitted),
        DispatchState::TimeUncertain => !op.dispatch.as_ref().is_some_and(|d| d.submitted),
        _ => false,
    };
    if let Some(d) = op.dispatch.as_mut() {
        d.cancel_requested = true;
    }
    if !cancellable {
        return CancelOutcome::TooLate(op.dispatch_state);
    }
    op.dispatch_state = DispatchState::CancelledBeforeDispatch;
    op.terminal_ms = Some(now_ms);
    if let Some(d) = op.dispatch.as_mut() {
        // The allocated position is now a known hole; a SKIP must fill it
        // before the device retire prefix can pass.
        d.skip_pending = true;
    }
    CancelOutcome::Cancelled
}

/// TX-I2 dispatch bookkeeping persisted alongside a prepared record
/// (04-capacity-storage.md §5: Gateway BootLease × dispatcher × dispatch_seq
/// identity, plus what the host has proven about the USB write so far).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DispatchAttachment {
    pub lease: [u8; 16],
    pub dispatcher: [u8; 16],
    pub dispatch_seq: u64,
    /// True once the SUBMIT may have left the host — claimed toward the
    /// single writer before enqueue. While false the device provably holds
    /// no record at this dispatch_seq: the frame either never reached the
    /// writer, the write was torn (a COBS prefix without a delimiter cannot
    /// decode), or a device response proved the position empty
    /// (NotRetained/WindowFull/MeshRejected). CANCELLED_BEFORE_DISPATCH and
    /// EXPIRED_BEFORE_DISPATCH proofs require this to be false.
    pub submitted: bool,
    /// A SKIP is owed to fill this position (cancelled, expired or refused
    /// holes block the device retire prefix until skipped).
    pub skip_pending: bool,
    /// True once a device receipt/query reported a terminal slot state for
    /// this dispatch_seq, or a SKIP confirmed the hole. Only such positions
    /// count toward the host-driven RETIRE_THROUGH floor.
    pub device_terminal: bool,
    /// Stable message key once the gateway accepts (None until then).
    pub msg_session: Option<u32>,
    pub msg_seq: Option<u64>,
    /// Evidence stages reached (01 §5: distinct proofs, never one bool).
    /// `ev_end_sdk` is only set for reliable delivery; a best-effort mesh
    /// completion sets `ev_mac_attempt` without promoting the evidence.
    /// `ev_host_receive` is the scope-2 gateway terminal: a verified
    /// Service Receipt proving the registered host's ReceiveLog stored
    /// the payload — it is never promoted to an ordinary SDK receipt.
    pub ev_gateway_accepted: bool,
    pub ev_mac_attempt: bool,
    pub ev_end_sdk: bool,
    pub ev_host_receive: bool,
    /// A cancel request was observed; retained even when it arrived too
    /// late so the record keeps the honest observation.
    pub cancel_requested: bool,
    pub time_uncertain: bool,
}

/// Versioned blob layout for the durable `operations.dispatch` column
/// (55 bytes). A single opaque column lets later fields extend the inner
/// version without another schema migration.
const ATTACH_BLOB_VERSION: u8 = 1;
const ATTACH_BLOB_SIZE: usize = 55;

impl DispatchAttachment {
    pub fn fresh(lease: [u8; 16], dispatcher: [u8; 16], dispatch_seq: u64) -> Self {
        Self {
            lease,
            dispatcher,
            dispatch_seq,
            submitted: false,
            skip_pending: false,
            device_terminal: false,
            msg_session: None,
            msg_seq: None,
            ev_gateway_accepted: false,
            ev_mac_attempt: false,
            ev_end_sdk: false,
            ev_host_receive: false,
            cancel_requested: false,
            time_uncertain: false,
        }
    }

    /// Serialize for the durable `operations.dispatch` column.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ATTACH_BLOB_SIZE);
        out.push(ATTACH_BLOB_VERSION);
        out.extend_from_slice(&self.lease);
        out.extend_from_slice(&self.dispatcher);
        out.extend_from_slice(&self.dispatch_seq.to_be_bytes());
        let mut flags = 0u8;
        if self.submitted {
            flags |= 1;
        }
        if self.skip_pending {
            flags |= 2;
        }
        if self.device_terminal {
            flags |= 4;
        }
        if self.msg_session.is_some() {
            flags |= 8;
        }
        if self.cancel_requested {
            flags |= 16;
        }
        if self.time_uncertain {
            flags |= 32;
        }
        out.push(flags);
        // Highest stage reached; stages are cumulative proofs, and a
        // reader that predates HOST_RAM (4) still sees >=1 — the honest
        // subset of what the device proved.
        let evidence = if self.ev_host_receive {
            4u8
        } else if self.ev_end_sdk {
            3u8
        } else if self.ev_mac_attempt {
            2
        } else if self.ev_gateway_accepted {
            1
        } else {
            0
        };
        out.push(evidence);
        out.extend_from_slice(&self.msg_session.unwrap_or(0).to_be_bytes());
        out.extend_from_slice(&self.msg_seq.unwrap_or(0).to_be_bytes());
        out
    }

    /// Parse the durable blob; `None` on wrong version or length.
    pub fn decode(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != ATTACH_BLOB_SIZE || bytes[0] != ATTACH_BLOB_VERSION {
            return None;
        }
        let mut lease = [0u8; 16];
        lease.copy_from_slice(&bytes[1..17]);
        let mut dispatcher = [0u8; 16];
        dispatcher.copy_from_slice(&bytes[17..33]);
        let mut seq = [0u8; 8];
        seq.copy_from_slice(&bytes[33..41]);
        let flags = bytes[41];
        let evidence = bytes[42];
        let mut session = [0u8; 4];
        session.copy_from_slice(&bytes[43..47]);
        let mut msg_seq = [0u8; 8];
        msg_seq.copy_from_slice(&bytes[47..55]);
        let msg_session = u32::from_be_bytes(session);
        let msg_seq = u64::from_be_bytes(msg_seq);
        Some(Self {
            lease,
            dispatcher,
            dispatch_seq: u64::from_be_bytes(seq),
            submitted: flags & 1 != 0,
            skip_pending: flags & 2 != 0,
            device_terminal: flags & 4 != 0,
            msg_session: (flags & 8 != 0).then_some(msg_session),
            msg_seq: (flags & 8 != 0).then_some(msg_seq),
            ev_gateway_accepted: evidence >= 1,
            ev_mac_attempt: evidence == 2,
            ev_end_sdk: evidence == 3,
            ev_host_receive: evidence == 4,
            cancel_requested: flags & 16 != 0,
            time_uncertain: flags & 32 != 0,
        })
    }
}

pub enum SubmitOutcome {
    Accepted {
        seq: u64,
    },
    Replay {
        seq: u64,
    },
    Conflict {
        existing_seq: u64,
    },
    /// Epoch well-formed but never opened for this scope in this store.
    UnknownEpoch,
    /// Epoch closed or retired and the key is not a known record in it.
    EpochClosed,
    NoCapacity,
    /// The durable store failed mid-operation; the daemon cannot vouch for
    /// the outcome. Never used by the memory provider.
    StoreFault,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OpenEpochError {
    NoCapacity,
    StoreFault,
}

/// Advisory capacity detail for NO_CAPACITY responses (04 §6): free record
/// slots and bytes plus the oldest time at which a terminal protection
/// lapses (None when no reclaim is foreseeable). Unknown means unknown —
/// a store that cannot measure reports zero rather than guessing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CapacityStatus {
    pub free_slots: usize,
    pub free_bytes: u64,
    pub reclaimable_at_ms: Option<u64>,
}

pub trait OperationStore {
    fn lineage(&self) -> [u8; 16];
    /// True when admitted HOST_DURABLE records survive daemon restarts.
    fn durable(&self) -> bool;
    /// Bind the scope's admission epoch, rotating hourly. `Ok((epoch,
    /// created))` with `created` true when a new epoch was issued;
    /// `NoCapacity` at the unretired-epoch ceiling or scope bound.
    fn open_epoch(&mut self, scope: EpochScope, now_ms: u64)
        -> Result<(u64, bool), OpenEpochError>;
    /// Wall-clock-only admit used by tests and legacy callers: leaves the
    /// record unanchored (`accepted_mono_ms == 0`), which keeps the
    /// pre-anchor deadline semantics.
    #[cfg(test)]
    fn submit(&mut self, uid: u32, req: &SendRequest, now_ms: u64) -> SubmitOutcome {
        self.submit_at(uid, req, now_ms, 0)
    }
    /// `submit` with an explicit monotonic admit stamp: production callers
    /// pass `mono_ms()` so the dispatcher can bound deadlines by real
    /// elapsed time even when the wall clock rewinds. `mono_ms == 0`
    /// leaves the record unanchored (legacy/tests).
    fn submit_at(
        &mut self,
        uid: u32,
        req: &SendRequest,
        now_ms: u64,
        mono_ms: u64,
    ) -> SubmitOutcome;
    /// Err(()) is a store fault, not absence — the API answers
    /// STORE_RECOVERY_REQUIRED rather than NOT_FOUND.
    fn get_by_seq(&self, seq: u64) -> Result<Option<StoredOperation>, ()>;
    fn get_by_key(&self, identity: &OpIdentity) -> Result<Option<StoredOperation>, ()>;
    fn capacity_status(&self, now_ms: u64) -> CapacityStatus;
    /// Every record the dispatch loop must see: all non-concluded records
    /// plus every record still holding a dispatch attachment (concluded
    /// attachments are needed to drive the device retire floor).
    fn dispatch_view(&self) -> Result<Vec<StoredOperation>, ()>;
    /// Atomic HOST_QUEUED → DISPATCH_PREPARED: allocates the next
    /// dispatch_seq for `lease` (per-lease allocator, persisted by durable
    /// stores) and binds the attachment in the same transition.
    fn prepare_dispatch(
        &mut self,
        op_seq: u64,
        lease: [u8; 16],
        dispatcher: [u8; 16],
    ) -> Result<PrepareOutcome, ()>;
    /// Linearized read-modify-write on one record. `mutate` returns false
    /// to veto; Ok(false) means the record is missing or the veto held —
    /// and a veto leaves the record untouched (non-durable providers
    /// snapshot and restore, the durable one rolls back).
    /// The dispatcher uses this for every post-prepare transition so a
    /// racing cancel or expiry is linearized at the same boundary.
    /// Only `dispatch_state`, `terminal_ms` and `dispatch` are written
    /// back by the durable provider: a mutate that touches any other
    /// field is silently lost there, so mutates must confine themselves
    /// to those fields.
    fn update_operation(
        &mut self,
        op_seq: u64,
        mutate: &mut dyn FnMut(&mut StoredOperation) -> bool,
    ) -> Result<bool, ()>;
    /// Atomic cancel, linearized with dispatch: cancellable only while no
    /// external write may have begun (HOST_QUEUED or DISPATCH_PREPARED
    /// without `submitted`). A late request still lands the
    /// `cancel_requested` observation.
    fn cancel_operation(&mut self, op_seq: u64, now_ms: u64) -> Result<CancelOutcome, ()> {
        let mut outcome = CancelOutcome::NotFound;
        let found = self.update_operation(op_seq, &mut |op| {
            outcome = cancel_transition(op, now_ms);
            // Commit even on TooLate so the observation is appended.
            true
        })?;
        Ok(if found {
            outcome
        } else {
            CancelOutcome::NotFound
        })
    }
}

/// The SingleAuthority-style config ledger: a monotonically increasing
/// `authority_sequence` handed out once per proposed permit (scope-gateway-
/// config P5, 04-remote-config.md §4.3). A value is allocated and committed
/// together so a crash between allocate and sign can never re-issue the same
/// sequence for a different command — gaps from failed proposes are fine,
/// reuse is not. The memory provider keeps the counter in RAM (honest
/// caveat: a restart restarts numbering, matching its RAM_ONLY durability);
/// the durable provider persists it in the `meta` table.
pub trait ConfigAuthorityLedger {
    /// Allocate the next authority sequence and commit the bump. Returns the
    /// value bound into this permit's command; Err(()) is a store fault —
    /// the caller must refuse the propose, never guess a sequence.
    fn config_authority_next(&mut self) -> Result<u64, ()>;
}

/// Fresh 128-bit id minted once per store lineage. Falls back to time^pid
/// if /dev/urandom is unavailable — still non-repeating.
pub fn mint_id128() -> [u8; 16] {
    let mut id = [0_u8; 16];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| std::io::Read::read_exact(&mut f, &mut id))
        .is_err()
    {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
            ^ u128::from(std::process::id());
        id = seed.to_be_bytes();
    }
    id
}

/// Admission state of one epoch number inside a scope.
#[derive(Clone, Copy, PartialEq, Eq)]
enum EpochStatus {
    Open,
    Closed,
    Unknown,
}

struct ScopeEpochs {
    floor: u64,
    next: u64,
    open: Option<(u64, u64)>,
    closed: BTreeSet<u64>,
}

impl ScopeEpochs {
    fn fresh(now_ms: u64) -> Self {
        Self {
            floor: 0,
            next: 2,
            open: Some((1, now_ms)),
            closed: BTreeSet::new(),
        }
    }

    fn unretired(&self) -> usize {
        self.closed.len() + usize::from(self.open.is_some())
    }

    fn status(&self, epoch: u64, now_ms: u64) -> EpochStatus {
        if let Some((open, opened_ms)) = self.open {
            if open == epoch {
                // The hourly window binds admission itself, not just
                // rotation: a still-open epoch past its window is closed
                // to new keys even before open_epoch runs again.
                return if now_ms < opened_ms.saturating_add(EPOCH_WINDOW_MS) {
                    EpochStatus::Open
                } else {
                    EpochStatus::Closed
                };
            }
        }
        if epoch <= self.floor || self.closed.contains(&epoch) {
            EpochStatus::Closed
        } else {
            // Never issued — or an invariant gap, which fails closed too.
            EpochStatus::Unknown
        }
    }
}

/// Token bucket in whole tokens; `last_ms` keeps the sub-token remainder
/// so refill stays exact over many small gaps.
struct RateBucket {
    tokens: u64,
    last_ms: u64,
}

impl RateBucket {
    fn full(now_ms: u64) -> Self {
        Self {
            tokens: HOST_RATE_BURST,
            last_ms: now_ms,
        }
    }

    fn refill(&mut self, now_ms: u64) {
        // A rewound clock mints nothing — debt is never forgiven by time.
        if now_ms <= self.last_ms {
            return;
        }
        let gained = (now_ms - self.last_ms) / RATE_TOKEN_INTERVAL_MS;
        if gained == 0 {
            return;
        }
        self.tokens = self.tokens.saturating_add(gained).min(HOST_RATE_BURST);
        self.last_ms += gained * RATE_TOKEN_INTERVAL_MS;
    }

    /// Milliseconds until the next token lands (empty bucket only).
    fn retry_after_ms(&self, now_ms: u64) -> u64 {
        RATE_TOKEN_INTERVAL_MS - now_ms.saturating_sub(self.last_ms) % RATE_TOKEN_INTERVAL_MS
    }
}

/// Why an admission call was throttled (04 §4). `scope` is `"principal"`
/// when the caller's own bucket is empty, `"global"` when the shared
/// all-principals bucket is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RateDeny {
    pub scope: &'static str,
    pub retry_after_ms: u64,
}

/// Per-principal plus global token buckets guarding the admission calls
/// (`messages.submit`, `operations.open_epoch`). Charged before any
/// admission work, so replays and CONFLICTs count too. RAM state only —
/// a restart simply reopens full buckets.
pub struct AdmissionLimiter {
    global: RateBucket,
    per_principal: HashMap<u32, RateBucket>,
}

impl AdmissionLimiter {
    pub fn new(now_ms: u64) -> Self {
        Self {
            global: RateBucket::full(now_ms),
            per_principal: HashMap::new(),
        }
    }

    /// Charge one admission call at both scopes. The principal bucket is
    /// consulted first so a lone spammer is blamed on its own budget;
    /// denial consumes nothing.
    pub fn admit(&mut self, uid: u32, now_ms: u64) -> Result<(), RateDeny> {
        self.global.refill(now_ms);
        if self.per_principal.len() >= MAX_TRACKED_PRINCIPALS
            && !self.per_principal.contains_key(&uid)
        {
            self.per_principal
                .retain(|_, bucket| bucket.tokens < HOST_RATE_BURST);
        }
        let trackable = self.per_principal.len() < MAX_TRACKED_PRINCIPALS
            || self.per_principal.contains_key(&uid);
        if trackable {
            let bucket = self
                .per_principal
                .entry(uid)
                .or_insert_with(|| RateBucket::full(now_ms));
            bucket.refill(now_ms);
            if bucket.tokens == 0 {
                return Err(RateDeny {
                    scope: "principal",
                    retry_after_ms: bucket.retry_after_ms(now_ms),
                });
            }
        }
        if self.global.tokens == 0 {
            return Err(RateDeny {
                scope: "global",
                retry_after_ms: self.global.retry_after_ms(now_ms),
            });
        }
        if trackable {
            self.per_principal
                .get_mut(&uid)
                .expect("inserted above")
                .tokens -= 1;
        }
        self.global.tokens -= 1;
        Ok(())
    }
}

impl Default for AdmissionLimiter {
    fn default() -> Self {
        Self::new(0)
    }
}

pub struct MemoryOperationStore {
    lineage: [u8; 16],
    next_seq: u64,
    /// Per-lease dispatch_seq allocator: the lease currently bound to the
    /// lane and the next sequence to hand out. A lease change restarts the
    /// lane at 1 — the device's window restarted with its boot.
    dispatch_lease: Option<[u8; 16]>,
    dispatch_next: u64,
    /// Config SingleAuthority sequence (RAM-only: a restart restarts at 1,
    /// matching this provider's RAM_ONLY durability — never silently
    /// presented as durable).
    config_auth_next: u64,
    epochs: HashMap<EpochScope, ScopeEpochs>,
    by_identity: HashMap<OpIdentity, u64>,
    by_seq: HashMap<u64, StoredOperation>,
}

impl MemoryOperationStore {
    pub fn new(lineage: [u8; 16]) -> Self {
        Self {
            lineage,
            next_seq: 1,
            dispatch_lease: None,
            dispatch_next: 1,
            config_auth_next: 1,
            epochs: HashMap::new(),
            by_identity: HashMap::new(),
            by_seq: HashMap::new(),
        }
    }

    /// Next dispatch_seq under `lease`; a different lease rebinds the lane
    /// and restarts numbering at 1.
    fn alloc_dispatch_seq(&mut self, lease: [u8; 16]) -> u64 {
        if self.dispatch_lease != Some(lease) {
            self.dispatch_lease = Some(lease);
            self.dispatch_next = 1;
        }
        let seq = self.dispatch_next.max(1);
        self.dispatch_next = seq.saturating_add(1).max(1);
        seq
    }

    /// Zero lineage for unit tests; the daemon mints a fresh one per start.
    pub fn test_store() -> Self {
        Self::new([0; 16])
    }

    /// Retire the contiguous prefix of closed epochs whose records are all
    /// terminal and past protection. Stops at the first ineligible epoch —
    /// never skips over a pinned or live one.
    fn retire_scope(&mut self, scope: EpochScope, now_ms: u64) {
        let Some(state) = self.epochs.get_mut(&scope) else {
            return;
        };
        loop {
            let candidate = state.floor.saturating_add(1);
            if state.open.is_some_and(|(open, _)| open == candidate)
                || !state.closed.contains(&candidate)
            {
                break;
            }
            let eligible = self
                .by_seq
                .values()
                .filter(|op| op.uid == scope.0 && op.network == scope.1 && op.epoch == candidate)
                .all(|op| {
                    op.concluded()
                        && op
                            .terminal_ms
                            .is_some_and(|t| t.saturating_add(RETENTION_MS) <= now_ms)
                });
            if !eligible {
                break;
            }
            state.floor = candidate;
            state.closed.remove(&candidate);
            let stale: Vec<OpIdentity> = self
                .by_identity
                .keys()
                .filter(|id| id.uid == scope.0 && id.network == scope.1 && id.epoch == candidate)
                .copied()
                .collect();
            for identity in stale {
                if let Some(seq) = self.by_identity.remove(&identity) {
                    self.by_seq.remove(&seq);
                }
            }
        }
    }

    fn counts(&self) -> (usize, usize, HashMap<u32, usize>) {
        let mut active = 0;
        let mut per_principal: HashMap<u32, usize> = HashMap::new();
        for op in self.by_seq.values() {
            if op.dispatch_state.is_active() && !op.concluded() {
                active += 1;
                *per_principal.entry(op.uid).or_default() += 1;
            }
        }
        (self.by_seq.len(), active, per_principal)
    }

    fn reclaimable_at(&self, now_ms: u64) -> Option<u64> {
        self.by_seq
            .values()
            .filter(|op| op.concluded())
            .filter_map(|op| op.terminal_ms.map(|t| t.saturating_add(RETENTION_MS)))
            .filter(|lapse| *lapse > now_ms)
            .min()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.by_seq.len()
    }

    #[cfg(test)]
    pub fn scope_count(&self) -> usize {
        self.epochs.len()
    }

    /// Test hook standing in for the CAP-I2/TX-I2 dispatcher: drives a
    /// record into any state so retire, quota and recovery rules can be
    /// exercised before their production writers exist.
    #[cfg(test)]
    pub fn set_state_for_test(&mut self, seq: u64, state: DispatchState, terminal_ms: Option<u64>) {
        if let Some(op) = self.by_seq.get_mut(&seq) {
            op.dispatch_state = state;
            op.terminal_ms = terminal_ms;
        }
    }

    /// Test hook: run the retire pass directly and report the new floor.
    #[cfg(test)]
    pub fn retire_for_test(&mut self, scope: EpochScope, now_ms: u64) -> u64 {
        self.retire_scope(scope, now_ms);
        self.epochs.get(&scope).map(|s| s.floor).unwrap_or(0)
    }
}

impl Default for MemoryOperationStore {
    fn default() -> Self {
        Self::test_store()
    }
}

impl OperationStore for MemoryOperationStore {
    fn lineage(&self) -> [u8; 16] {
        self.lineage
    }

    fn durable(&self) -> bool {
        false
    }

    fn open_epoch(
        &mut self,
        scope: EpochScope,
        now_ms: u64,
    ) -> Result<(u64, bool), OpenEpochError> {
        if !self.epochs.contains_key(&scope) {
            if self.epochs.len() >= SCOPE_CAP {
                return Err(OpenEpochError::NoCapacity);
            }
            self.epochs.insert(scope, ScopeEpochs::fresh(now_ms));
            return Ok((1, true));
        }
        self.retire_scope(scope, now_ms);
        let state = self.epochs.get_mut(&scope).expect("scope inserted above");
        if let Some((open, opened_ms)) = state.open {
            if now_ms < opened_ms.saturating_add(EPOCH_WINDOW_MS) {
                return Ok((open, false));
            }
            state.closed.insert(open);
            state.open = None;
        }
        if state.unretired() >= MAX_UNRETIRED_EPOCHS || state.next == u64::MAX {
            // At the ceiling the old epoch stays closed with no successor:
            // admission stops, queries keep working.
            return Err(OpenEpochError::NoCapacity);
        }
        let epoch = state.next;
        state.next = state.next.saturating_add(1);
        state.open = Some((epoch, now_ms));
        Ok((epoch, true))
    }

    fn submit_at(
        &mut self,
        uid: u32,
        req: &SendRequest,
        now_ms: u64,
        mono_ms: u64,
    ) -> SubmitOutcome {
        let identity = OpIdentity {
            uid,
            network: req.network,
            epoch: req.epoch,
            key: req.key,
        };
        // Known identity first: same bytes replay, different bytes conflict —
        // ahead of epoch/capacity checks so a lost response stays recoverable.
        if let Some(seq) = self.by_identity.get(&identity) {
            let stored = self.by_seq.get(seq).expect("identity without record");
            return if stored.canonical == req.canonical {
                SubmitOutcome::Replay { seq: *seq }
            } else {
                SubmitOutcome::Conflict { existing_seq: *seq }
            };
        }
        let scope = (uid, req.network);
        self.retire_scope(scope, now_ms);
        match self.epochs.get(&scope).map(|s| s.status(req.epoch, now_ms)) {
            Some(EpochStatus::Open) => {}
            Some(EpochStatus::Closed) => return SubmitOutcome::EpochClosed,
            Some(EpochStatus::Unknown) | None => return SubmitOutcome::UnknownEpoch,
        }
        let (records, active, per_principal) = self.counts();
        if records >= RECORD_CAP
            || active >= ACTIVE_CAP
            || per_principal.get(&uid).copied().unwrap_or(0) >= ACTIVE_PER_PRINCIPAL_CAP
        {
            return SubmitOutcome::NoCapacity;
        }
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1).max(1);
        self.by_identity.insert(identity, seq);
        self.by_seq.insert(
            seq,
            StoredOperation {
                seq,
                uid,
                network: req.network,
                epoch: req.epoch,
                key: req.key,
                dest_kind: req.dest_kind,
                dest: req.dest,
                delivery: req.delivery,
                priority: req.priority,
                ttl_ms: req.ttl_ms,
                storage: req.storage,
                hop_limit: req.hop_limit,
                payload: req.payload.clone(),
                canonical: req.canonical.clone(),
                hash: req.hash,
                accepted_ms: now_ms,
                accepted_mono_ms: mono_ms,
                dispatch_state: DispatchState::HostQueued,
                terminal_ms: None,
                dispatch: None,
            },
        );
        SubmitOutcome::Accepted { seq }
    }

    fn get_by_seq(&self, seq: u64) -> Result<Option<StoredOperation>, ()> {
        Ok(self.by_seq.get(&seq).cloned())
    }

    fn get_by_key(&self, identity: &OpIdentity) -> Result<Option<StoredOperation>, ()> {
        Ok(self
            .by_identity
            .get(identity)
            .and_then(|seq| self.by_seq.get(seq))
            .cloned())
    }

    fn capacity_status(&self, now_ms: u64) -> CapacityStatus {
        let free_slots = RECORD_CAP.saturating_sub(self.by_seq.len());
        CapacityStatus {
            free_slots,
            free_bytes: free_slots as u64 * RECORD_RESERVATION_BYTES,
            reclaimable_at_ms: self.reclaimable_at(now_ms),
        }
    }

    fn dispatch_view(&self) -> Result<Vec<StoredOperation>, ()> {
        Ok(self
            .by_seq
            .values()
            .filter(|op| !op.concluded() || op.dispatch.is_some())
            .cloned()
            .collect())
    }

    fn prepare_dispatch(
        &mut self,
        op_seq: u64,
        lease: [u8; 16],
        dispatcher: [u8; 16],
    ) -> Result<PrepareOutcome, ()> {
        match self.by_seq.get(&op_seq) {
            None => return Ok(PrepareOutcome::NotFound),
            Some(op) if op.dispatch_state != DispatchState::HostQueued || op.dispatch.is_some() => {
                return Ok(PrepareOutcome::NotQueued(op.dispatch_state));
            }
            Some(_) => {}
        }
        let dispatch_seq = self.alloc_dispatch_seq(lease);
        let attachment = DispatchAttachment::fresh(lease, dispatcher, dispatch_seq);
        let op = self.by_seq.get_mut(&op_seq).expect("record checked above");
        op.dispatch = Some(attachment.clone());
        op.dispatch_state = DispatchState::DispatchPrepared;
        Ok(PrepareOutcome::Prepared(attachment))
    }

    fn update_operation(
        &mut self,
        op_seq: u64,
        mutate: &mut dyn FnMut(&mut StoredOperation) -> bool,
    ) -> Result<bool, ()> {
        let Some(op) = self.by_seq.get_mut(&op_seq) else {
            return Ok(false);
        };
        // No rollback log here: snapshot so a veto cannot leave a partial
        // mutation committed (the durable provider gets this for free
        // from its transaction).
        let before = op.clone();
        Ok(if mutate(op) {
            true
        } else {
            *op = before;
            false
        })
    }
}

/// The daemon's operation store: the memory provider by default, the
/// durable SQLite provider once `--op-store` names a database file. One
/// generic `OperationStore` so the API layer never branches on backend.
pub enum StoreBackend {
    // Both variants boxed: the providers are much larger than a pointer
    // and this enum is matched on every store call.
    Memory(Box<MemoryOperationStore>),
    Sqlite(Box<SqliteOperationStore>),
}

impl Default for StoreBackend {
    fn default() -> Self {
        Self::Memory(Box::default())
    }
}

impl OperationStore for StoreBackend {
    fn lineage(&self) -> [u8; 16] {
        match self {
            Self::Memory(store) => store.lineage(),
            Self::Sqlite(store) => store.lineage(),
        }
    }

    fn durable(&self) -> bool {
        match self {
            Self::Memory(store) => store.durable(),
            Self::Sqlite(store) => store.durable(),
        }
    }

    fn open_epoch(
        &mut self,
        scope: EpochScope,
        now_ms: u64,
    ) -> Result<(u64, bool), OpenEpochError> {
        match self {
            Self::Memory(store) => store.open_epoch(scope, now_ms),
            Self::Sqlite(store) => store.open_epoch(scope, now_ms),
        }
    }

    fn submit_at(
        &mut self,
        uid: u32,
        req: &SendRequest,
        now_ms: u64,
        mono_ms: u64,
    ) -> SubmitOutcome {
        match self {
            Self::Memory(store) => store.submit_at(uid, req, now_ms, mono_ms),
            Self::Sqlite(store) => store.submit_at(uid, req, now_ms, mono_ms),
        }
    }

    fn get_by_seq(&self, seq: u64) -> Result<Option<StoredOperation>, ()> {
        match self {
            Self::Memory(store) => store.get_by_seq(seq),
            Self::Sqlite(store) => store.get_by_seq(seq),
        }
    }

    fn get_by_key(&self, identity: &OpIdentity) -> Result<Option<StoredOperation>, ()> {
        match self {
            Self::Memory(store) => store.get_by_key(identity),
            Self::Sqlite(store) => store.get_by_key(identity),
        }
    }

    fn capacity_status(&self, now_ms: u64) -> CapacityStatus {
        match self {
            Self::Memory(store) => store.capacity_status(now_ms),
            Self::Sqlite(store) => store.capacity_status(now_ms),
        }
    }

    fn dispatch_view(&self) -> Result<Vec<StoredOperation>, ()> {
        match self {
            Self::Memory(store) => store.dispatch_view(),
            Self::Sqlite(store) => store.dispatch_view(),
        }
    }

    fn prepare_dispatch(
        &mut self,
        op_seq: u64,
        lease: [u8; 16],
        dispatcher: [u8; 16],
    ) -> Result<PrepareOutcome, ()> {
        match self {
            Self::Memory(store) => store.prepare_dispatch(op_seq, lease, dispatcher),
            Self::Sqlite(store) => store.prepare_dispatch(op_seq, lease, dispatcher),
        }
    }

    fn update_operation(
        &mut self,
        op_seq: u64,
        mutate: &mut dyn FnMut(&mut StoredOperation) -> bool,
    ) -> Result<bool, ()> {
        match self {
            Self::Memory(store) => store.update_operation(op_seq, mutate),
            Self::Sqlite(store) => store.update_operation(op_seq, mutate),
        }
    }
}

impl ConfigAuthorityLedger for MemoryOperationStore {
    fn config_authority_next(&mut self) -> Result<u64, ()> {
        let seq = self.config_auth_next.max(1);
        self.config_auth_next = seq.saturating_add(1).max(1);
        Ok(seq)
    }
}

impl ConfigAuthorityLedger for SqliteOperationStore {
    fn config_authority_next(&mut self) -> Result<u64, ()> {
        self.config_authority_next_tx()
    }
}

impl ConfigAuthorityLedger for StoreBackend {
    fn config_authority_next(&mut self) -> Result<u64, ()> {
        match self {
            Self::Memory(store) => store.config_authority_next(),
            Self::Sqlite(store) => store.config_authority_next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical::{parse_submit, STORAGE_RAM};

    fn request(key: &str, epoch: u64, payload_hex: &str, payload_len: u64) -> SendRequest {
        let json = format!(
            "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"{epoch:016x}\",\"key\":\"{key}\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"{payload_hex}\",\"payload_len\":{payload_len},\"options\":{{\"storage\":\"RAM_ONLY\"}}}}"
        );
        let mut req = parse_submit(&routeloom_json::parse(&json).unwrap(), None).unwrap();
        assert_eq!(req.storage, STORAGE_RAM);
        req.epoch = epoch;
        req
    }

    fn submit(store: &mut MemoryOperationStore, req: &SendRequest) -> u64 {
        match store.submit(501, req, 1000) {
            SubmitOutcome::Accepted { seq } => seq,
            _ => panic!("expected accept"),
        }
    }

    #[test]
    fn open_epoch_binds_one_per_scope() {
        let mut store = MemoryOperationStore::test_store();
        assert_eq!(store.open_epoch((501, 1), 0), Ok((1, true)));
        assert_eq!(store.open_epoch((501, 1), 0), Ok((1, false)));
        assert_eq!(store.open_epoch((501, 2), 0), Ok((1, true)));
        assert_eq!(store.open_epoch((7, 1), 0), Ok((1, true)));
        assert_eq!(store.scope_count(), 3);
    }

    #[test]
    fn submit_assigns_stable_ids_and_replays() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1), 0).unwrap();
        let req = request("00112233445566778899aabbccddeeff", 1, "00ff", 2);
        let seq = submit(&mut store, &req);
        assert_eq!(seq, 1);
        // Same key+payload replays the same id without a new record.
        match store.submit(501, &req, 2000) {
            SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
            _ => panic!("expected replay"),
        }
        assert_eq!(store.len(), 1);
        // Same key under another principal is a separate identity.
        store.open_epoch((7, 1), 0).unwrap();
        match store.submit(7, &req, 2000) {
            SubmitOutcome::Accepted { seq } => assert_eq!(seq, 2),
            _ => panic!("expected separate accept"),
        }
        // Lookups resolve both ways.
        let by_seq = store.get_by_seq(1).unwrap().unwrap();
        assert_eq!(by_seq.payload, vec![0x00, 0xff]);
        assert_eq!(by_seq.accepted_ms, 1000); // replay does not re-stamp
        let identity = OpIdentity {
            uid: 501,
            network: 1,
            epoch: 1,
            key: req.key,
        };
        assert_eq!(store.get_by_key(&identity).unwrap().unwrap().seq, 1);
        assert!(store.get_by_seq(99).unwrap().is_none());
    }

    #[test]
    fn same_key_different_payload_conflicts_and_preserves() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1), 0).unwrap();
        let first = request("00112233445566778899aabbccddeeff", 1, "00", 1);
        submit(&mut store, &first);
        for alt in [
            request("00112233445566778899aabbccddeeff", 1, "01", 1),
            request("00112233445566778899aabbccddeeff", 1, "", 0),
        ] {
            match store.submit(501, &alt, 2000) {
                SubmitOutcome::Conflict { existing_seq } => assert_eq!(existing_seq, 1),
                _ => panic!("expected conflict"),
            }
        }
        assert_eq!(store.len(), 1);
        assert_eq!(store.get_by_seq(1).unwrap().unwrap().payload, vec![0x00]);
    }

    #[test]
    fn option_changes_conflict_too() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1), 0).unwrap();
        let json = |ttl: u32| {
            format!(
                "{{\"network\":\"0000000000000001\",\"admission_epoch\":\"0000000000000001\",\"key\":\"00112233445566778899aabbccddeeff\",\"destination\":{{\"kind\":\"node\",\"id\":\"0000000000000003\"}},\"payload_hex\":\"\",\"payload_len\":0,\"options\":{{\"storage\":\"RAM_ONLY\",\"ttl_ms\":{ttl}}}}}"
            )
        };
        let a = parse_submit(&routeloom_json::parse(&json(5000)).unwrap(), None).unwrap();
        let b = parse_submit(&routeloom_json::parse(&json(6000)).unwrap(), None).unwrap();
        submit(&mut store, &a);
        assert!(matches!(
            store.submit(501, &b, 2000),
            SubmitOutcome::Conflict { .. }
        ));
    }

    #[test]
    fn unknown_epoch_rejects_new_key() {
        let mut store = MemoryOperationStore::test_store();
        // Scope never opened.
        let req = request("00112233445566778899aabbccddeeff", 1, "", 0);
        assert!(matches!(
            store.submit(501, &req, 1000),
            SubmitOutcome::UnknownEpoch
        ));
        // Open epoch is 1; epoch 2 was never issued to this scope.
        store.open_epoch((501, 1), 0).unwrap();
        let req = request("00112233445566778899aabbccddeeff", 2, "", 0);
        assert!(matches!(
            store.submit(501, &req, 1000),
            SubmitOutcome::UnknownEpoch
        ));
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn table_and_scope_caps_reject() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1), 0).unwrap();
        for i in 0..RECORD_CAP {
            let req = request(&format!("{i:032x}"), 1, "", 0);
            assert!(matches!(
                store.submit(501, &req, 1000),
                SubmitOutcome::Accepted { .. }
            ));
        }
        let extra = request(&format!("{:032x}", RECORD_CAP), 1, "", 0);
        assert!(matches!(
            store.submit(501, &extra, 1000),
            SubmitOutcome::NoCapacity
        ));
        // Replays and conflicts still resolve when full — they add nothing.
        let known = request(&format!("{:032x}", 7), 1, "", 0);
        assert!(matches!(
            store.submit(501, &known, 2000),
            SubmitOutcome::Replay { .. }
        ));
        // Every protected record is still there: full means reject, never
        // evict (CAP01/CAP06).
        assert_eq!(store.len(), RECORD_CAP);
        assert!(store.get_by_seq(1).unwrap().is_some());
        let mut scopes = MemoryOperationStore::test_store();
        for uid in 0..SCOPE_CAP as u32 {
            assert!(scopes.open_epoch((uid, 1), 0).is_ok());
        }
        assert!(matches!(
            scopes.open_epoch((9999, 1), 0),
            Err(OpenEpochError::NoCapacity)
        ));
    }

    /// CAP04: hourly rotation closes the old epoch; known keys stay
    /// answerable, unknown keys fail closed.
    #[test]
    fn epoch_rotates_hourly_and_closes() {
        let mut store = MemoryOperationStore::test_store();
        assert_eq!(store.open_epoch((501, 1), 0), Ok((1, true)));
        assert_eq!(
            store.open_epoch((501, 1), EPOCH_WINDOW_MS - 1),
            Ok((1, false))
        );
        let known = request("00112233445566778899aabbccddeeff", 1, "00", 1);
        submit(&mut store, &known);
        assert_eq!(store.open_epoch((501, 1), EPOCH_WINDOW_MS), Ok((2, true)));
        // New key into the closed epoch fails closed.
        let fresh = request("ffffffffffffffffffffffffffffffff", 1, "", 0);
        assert!(matches!(
            store.submit(501, &fresh, EPOCH_WINDOW_MS),
            SubmitOutcome::EpochClosed
        ));
        assert_eq!(store.len(), 1);
        // Known key replays and stays queryable after the close.
        match store.submit(501, &known, EPOCH_WINDOW_MS + 1) {
            SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
            _ => panic!("expected replay"),
        }
        let identity = OpIdentity {
            uid: 501,
            network: 1,
            epoch: 1,
            key: known.key,
        };
        assert!(store.get_by_key(&identity).unwrap().is_some());
        // The new epoch admits.
        let next = request("ffffffffffffffffffffffffffffffff", 2, "", 0);
        match store.submit(501, &next, EPOCH_WINDOW_MS + 1) {
            SubmitOutcome::Accepted { seq } => assert_eq!(seq, 2),
            _ => panic!("expected accept"),
        }
    }

    /// CAP04: the hourly window binds submit, not just rotation — a
    /// still-open epoch past its window rejects new keys while known
    /// keys keep replaying.
    #[test]
    fn expired_epoch_rejects_new_keys_before_rotation() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1), 0).unwrap();
        let known = request("00112233445566778899aabbccddeeff", 1, "00", 1);
        submit(&mut store, &known);
        // The last instant inside the window still admits.
        let in_window = request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, "", 0);
        assert!(matches!(
            store.submit(501, &in_window, EPOCH_WINDOW_MS - 1),
            SubmitOutcome::Accepted { .. }
        ));
        // At and past the window a new key fails closed even though
        // open_epoch never ran to rotate.
        let late = request("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, "", 0);
        for now in [EPOCH_WINDOW_MS, EPOCH_WINDOW_MS + 60_000] {
            assert!(matches!(
                store.submit(501, &late, now),
                SubmitOutcome::EpochClosed
            ));
        }
        assert_eq!(store.len(), 2);
        // The known key still replays inside the expired epoch.
        match store.submit(501, &known, EPOCH_WINDOW_MS + 1) {
            SubmitOutcome::Replay { seq } => assert_eq!(seq, 1),
            _ => panic!("expected replay"),
        }
        // Rotation recovers admission under the next epoch.
        assert_eq!(
            store.open_epoch((501, 1), EPOCH_WINDOW_MS + 1),
            Ok((2, true))
        );
        let next = request("cccccccccccccccccccccccccccccccc", 2, "", 0);
        assert!(matches!(
            store.submit(501, &next, EPOCH_WINDOW_MS + 1),
            SubmitOutcome::Accepted { .. }
        ));
    }

    /// Rate budget (capacity.host_rate_per_minute/burst): burst drains
    /// both scopes, denial names the tighter one, refill and clock
    /// behavior stay honest.
    #[test]
    fn admission_limiter_burst_throttle_and_refill() {
        let mut limiter = AdmissionLimiter::new(0);
        for _ in 0..HOST_RATE_BURST {
            assert!(limiter.admit(1, 0).is_ok());
        }
        let deny = limiter.admit(1, 0).unwrap_err();
        assert_eq!(deny.scope, "principal");
        assert_eq!(deny.retry_after_ms, RATE_TOKEN_INTERVAL_MS);
        // Another principal is bound by the shared bucket, not by uid 1's.
        let deny = limiter.admit(2, 0).unwrap_err();
        assert_eq!(deny.scope, "global");
        // Denial consumed nothing: each interval refills exactly one
        // call, and a rewound clock mints no tokens.
        assert!(limiter.admit(1, RATE_TOKEN_INTERVAL_MS).is_ok());
        assert!(limiter.admit(1, RATE_TOKEN_INTERVAL_MS).is_err());
        assert!(limiter.admit(1, 0).is_err());
        assert!(limiter.admit(2, 2 * RATE_TOKEN_INTERVAL_MS).is_ok());
    }

    /// CAP06: at 32 unretired epochs admission stops; once retire frees
    /// the prefix, the scope admits again (progress, not just safe stop).
    #[test]
    fn epoch_ceiling_stops_and_recovers_admission() {
        let mut store = MemoryOperationStore::test_store();
        let scope = (501, 1);
        for epoch in 1..=MAX_UNRETIRED_EPOCHS as u64 {
            let now = (epoch - 1) * EPOCH_WINDOW_MS;
            assert_eq!(store.open_epoch(scope, now), Ok((epoch, true)));
            // One live record per epoch so nothing can retire yet.
            let req = request(&format!("{epoch:032x}"), epoch, "", 0);
            assert!(matches!(
                store.submit(501, &req, now),
                SubmitOutcome::Accepted { .. }
            ));
        }
        // The next rotation would exceed the ceiling: the old epoch closes
        // with no successor.
        let stuck = MAX_UNRETIRED_EPOCHS as u64 * EPOCH_WINDOW_MS;
        assert!(matches!(
            store.open_epoch(scope, stuck),
            Err(OpenEpochError::NoCapacity)
        ));
        let fresh = request(
            "ffffffffffffffffffffffffffffffff",
            MAX_UNRETIRED_EPOCHS as u64,
            "",
            0,
        );
        assert!(matches!(
            store.submit(501, &fresh, stuck),
            SubmitOutcome::EpochClosed
        ));
        // Complete everything and let protection lapse: the whole prefix
        // retires and admission resumes at the next epoch.
        for seq in 1..=MAX_UNRETIRED_EPOCHS as u64 {
            store.set_state_for_test(seq, DispatchState::EndSdkReceived, Some(0));
        }
        let later = stuck + RETENTION_MS;
        assert_eq!(
            store.retire_for_test(scope, later),
            MAX_UNRETIRED_EPOCHS as u64
        );
        assert_eq!(
            store.open_epoch(scope, later),
            Ok((MAX_UNRETIRED_EPOCHS as u64 + 1, true))
        );
        let resumed = request(
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
            MAX_UNRETIRED_EPOCHS as u64 + 1,
            "",
            0,
        );
        assert!(matches!(
            store.submit(501, &resumed, later),
            SubmitOutcome::Accepted { .. }
        ));
    }

    /// CAP05: retire advances only over the contiguous eligible prefix.
    #[test]
    fn retire_advances_only_over_contiguous_prefix() {
        let mut store = MemoryOperationStore::test_store();
        let scope = (501, 1);
        for epoch in 1..=4 {
            store
                .open_epoch(scope, (epoch - 1) * EPOCH_WINDOW_MS)
                .unwrap();
            if epoch < 4 {
                let req = request(&format!("{epoch:032x}"), epoch, "", 0);
                assert!(matches!(
                    store.submit(501, &req, 0),
                    SubmitOutcome::Accepted { .. }
                ));
            }
        }
        // Epochs 1 and 3 are terminal and lapsed, but 2 is still queued.
        store.set_state_for_test(1, DispatchState::EndSdkReceived, Some(0));
        store.set_state_for_test(3, DispatchState::CancelledBeforeDispatch, Some(0));
        let floor = store.retire_for_test(scope, RETENTION_MS);
        assert_eq!(floor, 1);
        // Epoch 1's record is gone; epoch 3's survives behind the live one.
        assert!(store.get_by_seq(1).unwrap().is_none());
        assert!(store.get_by_seq(2).unwrap().is_some());
        assert!(store.get_by_seq(3).unwrap().is_some());
        // Resolving epoch 2 retires 2 and 3 together.
        store.set_state_for_test(2, DispatchState::ExpiredBeforeDispatch, Some(0));
        assert_eq!(store.retire_for_test(scope, RETENTION_MS), 3);
        assert!(store.get_by_seq(3).unwrap().is_none());
    }

    /// CAP05/CAP06: indeterminate records never free by elapsed time, and
    /// terminal records hold their full 24h protection.
    #[test]
    fn indeterminate_pins_and_terminal_holds_protection() {
        let mut store = MemoryOperationStore::test_store();
        let scope = (501, 1);
        store.open_epoch(scope, 0).unwrap();
        let stuck = request("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", 1, "", 0);
        let done = request("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", 1, "", 0);
        let stuck_seq = submit(&mut store, &stuck);
        let done_seq = submit(&mut store, &done);
        store.set_state_for_test(stuck_seq, DispatchState::Indeterminate, None);
        store.set_state_for_test(done_seq, DispatchState::EndSdkReceived, Some(1000));
        store.open_epoch(scope, EPOCH_WINDOW_MS).unwrap();
        // Even far past retention, the pinned epoch does not retire.
        assert_eq!(store.retire_for_test(scope, 10 * RETENTION_MS), 0);
        assert!(store.get_by_seq(stuck_seq).unwrap().is_some());
        // A terminal record alone still holds its 24h before retiring.
        let mut solo = MemoryOperationStore::test_store();
        solo.open_epoch(scope, 0).unwrap();
        let req = request("cccccccccccccccccccccccccccccccc", 1, "", 0);
        let seq = match solo.submit(501, &req, 0) {
            SubmitOutcome::Accepted { seq } => seq,
            _ => panic!("expected accept"),
        };
        solo.set_state_for_test(seq, DispatchState::EndSdkReceived, Some(1000));
        solo.open_epoch(scope, EPOCH_WINDOW_MS).unwrap();
        assert_eq!(solo.retire_for_test(scope, 1000 + RETENTION_MS - 1), 0);
        assert!(solo.get_by_seq(seq).unwrap().is_some());
        assert_eq!(solo.retire_for_test(scope, 1000 + RETENTION_MS), 1);
        assert!(solo.get_by_seq(seq).unwrap().is_none());
    }

    /// CAP05: a retired key is never re-executed — resubmit fails closed.
    #[test]
    fn retired_keys_never_reexecute() {
        let mut store = MemoryOperationStore::test_store();
        let scope = (501, 1);
        store.open_epoch(scope, 0).unwrap();
        let req = request("00112233445566778899aabbccddeeff", 1, "00", 1);
        let seq = submit(&mut store, &req);
        store.set_state_for_test(seq, DispatchState::EndSdkReceived, Some(0));
        store.open_epoch(scope, EPOCH_WINDOW_MS).unwrap();
        assert_eq!(store.retire_for_test(scope, RETENTION_MS), 1);
        match store.submit(501, &req, RETENTION_MS) {
            SubmitOutcome::EpochClosed => {}
            _ => panic!("retired key must fail closed, not re-execute"),
        }
        let identity = OpIdentity {
            uid: 501,
            network: 1,
            epoch: 1,
            key: req.key,
        };
        assert!(store.get_by_key(&identity).unwrap().is_none());
        assert_eq!(store.len(), 0);
    }

    /// CAP03: queries and replays never extend protection.
    #[test]
    fn reads_and_replays_do_not_extend_protection() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1), 0).unwrap();
        let req = request("00112233445566778899aabbccddeeff", 1, "00", 1);
        let seq = submit(&mut store, &req);
        store.set_state_for_test(seq, DispatchState::EndSdkReceived, Some(1000));
        let identity = OpIdentity {
            uid: 501,
            network: 1,
            epoch: 1,
            key: req.key,
        };
        for _ in 0..3 {
            let _ = store.get_by_seq(seq).unwrap();
            let _ = store.get_by_key(&identity).unwrap();
            match store.submit(501, &req, 50_000) {
                SubmitOutcome::Replay { .. } => {}
                _ => panic!("expected replay"),
            }
        }
        let op = store.get_by_seq(seq).unwrap().unwrap();
        assert_eq!(op.accepted_ms, 1000);
        assert_eq!(op.terminal_ms, Some(1000));
    }

    /// CAP06: per-principal (8) and global (32) active quotas reject new
    /// admission while in-flight records hold dispatch slots.
    #[test]
    fn active_quotas_reject_per_principal_and_global() {
        let mut store = MemoryOperationStore::test_store();
        for uid in [501, 7, 8, 9, 10] {
            store.open_epoch((uid, 1), 0).unwrap();
        }
        for i in 0..ACTIVE_PER_PRINCIPAL_CAP {
            let req = request(&format!("{i:032x}"), 1, "", 0);
            let seq = submit(&mut store, &req);
            store.set_state_for_test(seq, DispatchState::DispatchPrepared, None);
        }
        // Ninth in-flight for uid 501: refused, while others still admit.
        let ninth = request(&format!("{:032x}", 100), 1, "", 0);
        assert!(matches!(
            store.submit(501, &ninth, 1000),
            SubmitOutcome::NoCapacity
        ));
        for (n, uid) in [7, 8, 9].iter().enumerate() {
            for i in 0..ACTIVE_PER_PRINCIPAL_CAP {
                let req = request(&format!("{:032x}", 1000 + n * 100 + i), 1, "", 0);
                let seq = match store.submit(*uid, &req, 1000) {
                    SubmitOutcome::Accepted { seq } => seq,
                    _ => panic!("expected accept"),
                };
                store.set_state_for_test(seq, DispatchState::GatewayAccepted, None);
            }
        }
        // Global 32 in-flight: a fresh principal is refused too.
        let blocked = request(&format!("{:032x}", 2000), 1, "", 0);
        assert!(matches!(
            store.submit(10, &blocked, 1000),
            SubmitOutcome::NoCapacity
        ));
        assert_eq!(store.len(), ACTIVE_CAP);
    }

    /// NO_CAPACITY detail: free slots/bytes plus the oldest lapse time,
    /// or null when nothing will free.
    #[test]
    fn capacity_status_reports_slots_bytes_and_lapse() {
        let mut store = MemoryOperationStore::test_store();
        let empty = store.capacity_status(0);
        assert_eq!(empty.free_slots, RECORD_CAP);
        assert_eq!(
            empty.free_bytes,
            RECORD_CAP as u64 * RECORD_RESERVATION_BYTES
        );
        assert_eq!(empty.reclaimable_at_ms, None);
        store.open_epoch((501, 1), 0).unwrap();
        let req = request("00112233445566778899aabbccddeeff", 1, "", 0);
        let seq = submit(&mut store, &req);
        let full = store.capacity_status(0);
        assert_eq!(full.free_slots, RECORD_CAP - 1);
        assert_eq!(full.reclaimable_at_ms, None); // queued: no lapse known
        store.set_state_for_test(seq, DispatchState::EndSdkReceived, Some(1000));
        let lapsing = store.capacity_status(0);
        assert_eq!(lapsing.reclaimable_at_ms, Some(1000 + RETENTION_MS));
        // Past the lapse with no retire path, the time is no longer a
        // forecast — back to unknown.
        let stale = store.capacity_status(1000 + RETENTION_MS);
        assert_eq!(stale.reclaimable_at_ms, None);
    }

    /// A vetoed update must leave the record untouched — same rule as the
    /// durable provider's rollback, so a mutate-then-veto cannot leak a
    /// partial mutation.
    #[test]
    fn update_veto_leaves_record_untouched() {
        let mut store = MemoryOperationStore::test_store();
        store.open_epoch((501, 1), 0).unwrap();
        let req = request("00112233445566778899aabbccddeeff", 1, "", 0);
        let seq = submit(&mut store, &req);
        assert_eq!(
            store.update_operation(seq, &mut |o| {
                o.dispatch_state = DispatchState::Indeterminate;
                o.terminal_ms = Some(9);
                false
            }),
            Ok(false)
        );
        let op = store.get_by_seq(seq).unwrap().unwrap();
        assert_eq!(op.dispatch_state, DispatchState::HostQueued);
        assert_eq!(op.terminal_ms, None);
    }
}
