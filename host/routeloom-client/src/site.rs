//! KGuard's side of the SDK v1 zero-touch join (docs/design/sdk-v1/07 §2,
//! §5; plan P3-3): the Site Authority's decision surface as a transport-
//! neutral trait, plus [`KGuardMock`], a minimal assignment-table policy for
//! tests and demos.
//!
//! KGuard answers "may this device join here?"; RouteLoom enforces the
//! answer cryptographically. The facade exposes exactly that:
//!
//! | facade | API1 (RouteLoom backend) |
//! |---|---|
//! | [`SiteAdmin::site_status`] | `site.status` |
//! | [`SiteAdmin::join_requests`] | `join.requests.list` |
//! | [`SiteAdmin::decide`] | `join.decide` |
//! | [`SiteAdmin::discovered`] | `devices.discovered.list` (all pages) |
//! | [`SiteAdmin::members`] / [`SiteAdmin::member`] | `members.list` / `members.get` |
//! | [`SiteAdmin::revoke`] | `membership.revoke` |
//! | [`SiteAdmin::group_key_status`] | `group_keys.status` |
//! | [`SiteAdmin::rotate_group_key`] | `group_keys.rotate` |
//! | [`SiteAdmin::site_events`] | `messages.subscribe {stream:"events", filter.kinds: SITE_EVENT_KINDS}` |
//!
//! Grants (routeloom-host `--api-acl-file`, on the site's wire network):
//! `MEMBERSHIP_READ` for reads and events, `MEMBERSHIP_DECIDE` for
//! `decide` / `revoke`, `MEMBERSHIP_ADMIN` for `rotate_group_key`.

use std::collections::HashMap;
use std::sync::Mutex;

use crate::{NodeId, TransportError};

/// Event kinds the Site Authority emits (07 §2.3 as implemented).
pub const SITE_EVENT_KINDS: [&str; 12] = [
    "join.request",
    "join.decided",
    "device.discovered",
    "member.reissued",
    "member.confirmed",
    "member.revoked",
    "member.removal_notified",
    "rrs.published",
    "gk.staged",
    "gk.rotated",
    "gk.member_applied",
    "authority.error",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteStatus {
    pub site_id: u64,
    /// Full 64-bit network (site_epoch << 32 | network_low32).
    pub network: u64,
    pub site_epoch: u32,
    pub rs_epoch: u32,
    pub gk_epoch: u32,
    pub members: u32,
    pub members_unconfirmed: u32,
    pub removed: u32,
    pub discovered: u32,
    pub join_requests: u32,
    pub storage_durable: bool,
}

/// Unauthenticated routing facts of an attempt (proxy's observation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Via {
    pub gateway: NodeId,
    pub proxy: NodeId,
    pub authority_hops: u8,
    pub joiner_rssi_dbm: i8,
}

/// A verified device asking to join (07 §2.1 `join.request`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JoinRequest {
    /// `jr-…` token to pass back in [`SiteAdmin::decide`].
    pub id: String,
    pub device: NodeId,
    /// SHA-256 of the device key (hex) — the key identity KGuard can pin.
    pub kid: String,
    pub model: u16,
    pub hw_rev: u8,
    pub cert_serial: u32,
    pub fw_version: u32,
    pub capability: Vec<String>,
    pub requested_role: String,
    /// The device was removed from this site before.
    pub previously_removed: bool,
    /// Another key already holds this device id here (never auto-allowed).
    pub kid_conflict: bool,
    pub via: Via,
    pub attempt: u32,
    /// Time left in the current attempt's decision window.
    pub remaining_ms: u64,
    /// A verdict is already on record.
    pub decided: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveredDevice {
    pub device: NodeId,
    pub kid: String,
    pub model: u16,
    pub hw_rev: u8,
    pub cert_serial: u32,
    pub fw_version: u32,
    pub first_seen_ms: u64,
    pub last_seen_ms: u64,
    pub attempts: u32,
    pub via: Via,
    /// `awaiting` / `pending` / `not_here` / `blocked` / `busy` / `allowed`.
    pub last_verdict: String,
    pub previously_removed: bool,
    pub kid_conflict: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    pub device: NodeId,
    pub kid: String,
    /// false once removed (the row stays for its history).
    pub member: bool,
    pub generation: u32,
    pub role: String,
    pub member_cert_serial: u32,
    /// `allowed_unconfirmed` / `active`; None for a removed device.
    pub confirm_state: Option<String>,
    /// The Allow reached the relay at least once.
    pub delivered: bool,
    pub approved_ms: u64,
    pub removed_ms: Option<u64>,
    pub removal_reason: Option<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Endpoint,
    Relay,
    Gateway,
}

impl Role {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Endpoint => "endpoint",
            Self::Relay => "relay",
            Self::Gateway => "gateway",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow(Role),
    /// Not assigned (yet): the device retries after `retry_after_s`
    /// (30..=3600) and stays on the discovered list.
    Pending {
        retry_after_s: u32,
    },
    /// Assigned to another site.
    DenyNotHere,
    /// Must not join anywhere.
    DenyBlocked,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionOutcome {
    /// `committed` (allow: ledger commit done) or `recorded`.
    pub state: String,
    pub generation: Option<u32>,
    pub member_cert_serial: Option<u32>,
    pub operation_id: Option<String>,
    /// `current_attempt` (the waiting device got it) or `next_attempt`.
    pub applied: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RemovalReason {
    Removed,
    Lost,
    Replaced,
    Blocked,
}

impl RemovalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Removed => "removed",
            Self::Lost => "lost",
            Self::Replaced => "replaced",
            Self::Blocked => "blocked",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevokeOutcome {
    pub operation_id: String,
    /// `committed` — the ledger entry and the new revocation set exist;
    /// distribution to the mesh is reported separately.
    pub state: String,
    pub generation: u32,
    pub rs_epoch: u32,
}

/// The last converged rotation (07 §2.2 `group_keys.status`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LastRotation {
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub cause: String,
    pub activated_ms: u64,
}

/// Group-key lifecycle state (07 §2.2 `group_keys.status`): phases, causes
/// and counts only — never secrets, GK-id arrays or DAMS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GroupKeyStatus {
    pub active: u32,
    pub staged: Option<u32>,
    /// `stable` / `staging` / `activating` / `catching_up`.
    pub phase: String,
    pub cause: Option<String>,
    pub targets: u32,
    pub staged_ack: u32,
    pub active_ack: u32,
    pub unknown: u32,
    pub last_rotation: Option<LastRotation>,
    pub next_due_ms: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RotateOutcome {
    pub operation_id: String,
    /// `committed` — the staged key exists; distribution to the mesh is
    /// reported separately (`operations.get`, `group_keys.status`).
    pub state: String,
    pub from_epoch: u32,
    pub to_epoch: u32,
    pub targets: u32,
}

/// RRS1 distribution progress of a revoke operation (P6-1):
/// `pending` (committed, nothing sent), `distributing`, `converged`, or
/// `unknown` (pre-P6-1 operation, or a target without an Applied ACK).
/// Nothing counts as applied/retired without evidence.
///
/// `converged` means the RRS-enforcement snapshot has no `unknown`
/// recipient left. It is neither the target's erase confirmation nor
/// GK-rotation completion — display it as RRS convergence only, and
/// never collapse `unknown > 0` (or a missing view) into success.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DistributionProgress {
    pub state: String,
    pub applied: u64,
    pub retired: u64,
    pub unknown: u64,
    pub total: u64,
}

/// A revoke operation with its distribution progress.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OperationProgress {
    pub operation_id: String,
    pub kind: String,
    /// `committed`, `distributing`, or `converged` (V1-R01). `converged`
    /// is RRS snapshot convergence only — not target erase, not GK done.
    pub state: String,
    pub device: NodeId,
    pub generation: u32,
    pub rs_epoch: u32,
    pub distribution: DistributionProgress,
}

/// One Site Authority event (the raw JSON is kept for fields this type
/// does not model).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SiteEvent {
    pub kind: String,
    pub at_ms: u64,
    pub device: Option<NodeId>,
    pub join_request_id: Option<String>,
    pub raw: String,
}

pub type SiteEventStream = Box<dyn Iterator<Item = Result<SiteEvent, TransportError>> + Send>;

/// The KGuard decision surface of a Site Authority.
pub trait SiteAdmin: Send + Sync {
    fn site_status(&self) -> Result<SiteStatus, TransportError>;
    /// Open join requests (awaiting a verdict, or decided but not yet
    /// delivered to the device).
    fn join_requests(&self) -> Result<Vec<JoinRequest>, TransportError>;
    /// Answers a join request. The same `idempotency_key` repeats the same
    /// answer; a different verdict for a decided request is `CONFLICT`.
    fn decide(
        &self,
        request: &JoinRequest,
        decision: Decision,
        idempotency_key: &str,
    ) -> Result<DecisionOutcome, TransportError>;
    fn discovered(&self) -> Result<Vec<DiscoveredDevice>, TransportError>;
    fn members(&self) -> Result<Vec<Member>, TransportError>;
    fn member(&self, device: NodeId) -> Result<Option<Member>, TransportError>;
    /// Removes a member. `expected_generation` guards against acting on a
    /// stale screen (`CONFLICT` when it moved on).
    fn revoke(
        &self,
        device: NodeId,
        expected_generation: u32,
        reason: RemovalReason,
        idempotency_key: &str,
    ) -> Result<RevokeOutcome, TransportError>;
    fn group_key_status(&self) -> Result<GroupKeyStatus, TransportError>;
    /// Starts a manual rotation. `expected_active_epoch` guards against
    /// acting on a stale screen (`CONFLICT` when it moved on); while a
    /// rotation distributes the call is `BUSY` (retryable).
    fn rotate_group_key(
        &self,
        expected_active_epoch: u32,
        idempotency_key: &str,
    ) -> Result<RotateOutcome, TransportError>;
    /// Reads back a revoke operation with its RRS1 distribution progress
    /// (`operations.get`). `None` when the id is unknown.
    fn operation(&self, operation_id: &str) -> Result<Option<OperationProgress>, TransportError>;

    fn site_events(&self) -> Result<SiteEventStream, TransportError>;
}

/// Where KGuard's assignment table puts a device.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Assignment {
    Here(Role),
    Elsewhere,
    Blocked,
}

/// A stand-in for KGuard: an assignment table and the rule
/// "assigned here → allow, assigned elsewhere → deny not_here, blocked →
/// deny blocked, unknown → pending" (07 §5). A key conflict is never
/// allowed automatically.
pub struct KGuardMock {
    assignments: Mutex<HashMap<NodeId, Assignment>>,
    pub pending_retry_s: u32,
}

impl Default for KGuardMock {
    fn default() -> Self {
        Self {
            assignments: Mutex::new(HashMap::new()),
            pending_retry_s: 60,
        }
    }
}

impl KGuardMock {
    pub fn assign(&self, device: NodeId, assignment: Assignment) {
        self.assignments
            .lock()
            .expect("assignments poisoned")
            .insert(device, assignment);
    }

    pub fn unassign(&self, device: NodeId) {
        self.assignments
            .lock()
            .expect("assignments poisoned")
            .remove(&device);
    }

    pub fn decision_for(&self, request: &JoinRequest) -> Decision {
        if request.kid_conflict {
            return Decision::Pending {
                retry_after_s: self.pending_retry_s,
            };
        }
        match self
            .assignments
            .lock()
            .expect("assignments poisoned")
            .get(&request.device)
        {
            Some(Assignment::Here(role)) => Decision::Allow(*role),
            Some(Assignment::Elsewhere) => Decision::DenyNotHere,
            Some(Assignment::Blocked) => Decision::DenyBlocked,
            None => Decision::Pending {
                retry_after_s: self.pending_retry_s,
            },
        }
    }

    /// Decides every open, undecided request once. Returns what it did.
    pub fn serve_once(
        &self,
        admin: &dyn SiteAdmin,
    ) -> Result<Vec<(JoinRequest, Decision, DecisionOutcome)>, TransportError> {
        let mut done = Vec::new();
        for request in admin.join_requests()? {
            if request.decided {
                continue;
            }
            let decision = self.decision_for(&request);
            let key = format!("kgmock-{}-{}", request.id, request.attempt);
            let outcome = admin.decide(&request, decision, &key)?;
            done.push((request, decision, outcome));
        }
        Ok(done)
    }
}
