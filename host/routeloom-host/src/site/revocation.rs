//! RRS1 distribution (04-removal-revocation.md §9, plan P6-1 PR A).
//!
//! `membership.revoke` commits first (ledger + RRS1 + staged GK, one
//! transaction) and only then distributes: every revoke snapshots its
//! surviving members as distribution targets, and the tick-driven
//! distributor pushes the latest RRS1 over the authority channel until
//! each target proves it applied the set — or stays honestly `unknown`.
//! Nothing is ever counted as a success without an Applied ACK.
//!
//! The transport is a port ([`RevocationTransport`]): production holds
//! none until the P5 authority channel lands (`capabilities.get` reports
//! `rrs_no_transport`), while tests inject an in-process fake. The
//! scheduler, backoff, coalescing and persistence below are transport
//! agnostic and fully exercised that way.
//!
//! Durability: each operation's target snapshot lives in its operation
//! doc (SQLite `docs` table), so a restart resumes the same operation —
//! the ≤4 mail outbox and the backoff timers are RAM-only and rebuild
//! from the snapshot. Operations written before P6-1 carry no snapshot
//! and read back as state `unknown`.

use std::collections::BTreeMap;

use routeloom_json::Json;
use routeloom_provision::sdkv1::revocation::RevocationEntry;

use super::records::{h16, parse_h16, parse_hex};
use super::store::{Batch, DocKind};
use super::{SiteAuthority, SiteError};
use crate::receive_log::hex_lower;

/// Targets snapshotted per operation (the P6 profile: ~100 deployed
/// boards plus headroom, gateway included). Members beyond the cap are
/// counted as `overflow` (honestly `unknown`, never silently dropped).
pub const DISTRIBUTION_TARGET_MAX: usize = 128;
/// Shared mail outbox (RRS1 now; GrantRenew joins it in PR C).
pub const DISTRIBUTION_OUTBOX_MAX: usize = 4;
/// At most 10 object sends per second, authority-wide.
pub const DISTRIBUTION_DISPATCH_GAP_MS: u64 = 100;
/// Send attempts per target per operation; afterwards the target stays
/// `unknown` for this operation (gossip and later snapshots cover it).
pub const DISTRIBUTION_ATTEMPTS_MAX: u32 = 3;
/// Backoff schedule (seconds): targets consume the 5/10/20 s levels for
/// their three attempts; transport refusals back the whole outbox off up
/// to the 60 s cap.
pub const DISTRIBUTION_BACKOFF_S: [u64; 5] = [5, 10, 20, 40, 60];
/// Meta row recording that the currently staged GK left the Host (set by
/// the P5 GK scheduler; read by `revoke` before reusing a staged key).
pub const META_GK_STAGED_DISTRIBUTED: &str = "gk_staged_distributed";

/// Adds one, refusing to wrap: the generation/rs_epoch/gk_epoch counters
/// stop at u32::MAX with an explicit error instead of aliasing an older
/// credential. Checked before the revoke transaction.
pub fn checked_next(value: u32, what: &str) -> Result<u32, SiteError> {
    value.checked_add(1).ok_or_else(|| {
        SiteError::new(
            "COUNTER_EXHAUSTED",
            format!("{what} counter exhausted; a site_epoch cutover must reset it"),
        )
    })
}

/// Same-network entry coverage, mirroring the device-side
/// `revocation_covers` (04 §2): every entry of `older` is still present
/// in `newer` with a min_generation that did not decrease. The Host uses
/// it to coalesce Applied ACKs: an ACK for epoch E counts for operation O
/// only when the issued set E covers O's set — `ack.rs_epoch >=
/// op.rs_epoch` alone never decides.
pub fn rrs_covers(older: &[RevocationEntry], newer: &[RevocationEntry]) -> bool {
    older.iter().all(|old| {
        newer
            .iter()
            .any(|n| n.node_id == old.node_id && n.min_generation >= old.min_generation)
    })
}

/// The P5 authority channel's RRS1 send half (PR A: port only). Returns
/// false when the object was not sent (backpressure / no route); the
/// distributor retries with backoff and never treats a refusal as an ACK.
pub trait RevocationTransport {
    fn send_rrs(&mut self, node: u64, object: &[u8]) -> bool;
}

/// Per-target delivery state. `Pending` never left the Host; `Unknown`
/// was sent but never proved; both count as `unknown` in the API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TargetState {
    Pending,
    Unknown,
    Applied,
    Retired,
}

impl TargetState {
    fn name(self) -> &'static str {
        match self {
            TargetState::Pending => "pending",
            TargetState::Unknown => "unknown",
            TargetState::Applied => "applied",
            TargetState::Retired => "retired",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(TargetState::Pending),
            "unknown" => Some(TargetState::Unknown),
            "applied" => Some(TargetState::Applied),
            "retired" => Some(TargetState::Retired),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DistributionTarget {
    pub node: u64,
    pub kid: [u8; 32],
    pub generation: u32,
    pub network: u64,
    pub state: TargetState,
    pub attempts: u32,
    pub next_retry_ms: u64,
    /// The rs_epoch the target proved (Applied only).
    pub ack_rs_epoch: Option<u32>,
}

impl DistributionTarget {
    fn doc(&self) -> String {
        let ack = self
            .ack_rs_epoch
            .map_or_else(|| "null".to_string(), |e| e.to_string());
        format!(
            "{{\"node\":\"{}\",\"kid\":\"{}\",\"generation\":{},\"network\":\"{}\",\"state\":\"{}\",\"attempts\":{},\"next_retry_ms\":{},\"ack_rs_epoch\":{ack}}}",
            h16(self.node),
            hex_lower(&self.kid),
            self.generation,
            h16(self.network),
            self.state.name(),
            self.attempts,
            self.next_retry_ms,
        )
    }

    fn from_doc(json: &Json) -> Option<Self> {
        let ack = match json.get("ack_rs_epoch")? {
            Json::Null => None,
            value => Some(u32::try_from(value.as_u64()?).ok()?),
        };
        let kid = parse_hex(json.get("kid")?.as_str()?, 32)?;
        Some(Self {
            node: parse_h16(json.get("node")?.as_str()?)?,
            kid: kid.try_into().ok()?,
            generation: u32::try_from(json.get("generation")?.as_u64()?).ok()?,
            network: parse_h16(json.get("network")?.as_str()?)?,
            state: TargetState::parse(json.get("state")?.as_str()?)?,
            attempts: u32::try_from(json.get("attempts")?.as_u64()?).ok()?,
            next_retry_ms: json.get("next_retry_ms")?.as_u64()?,
            ack_rs_epoch: ack,
        })
    }
}

/// Operation-level distribution state. `Unknown` is legacy-only:
/// operations committed before P6-1 have no snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DistState {
    Pending,
    Distributing,
    Converged,
    Unknown,
}

impl DistState {
    fn name(self) -> &'static str {
        match self {
            DistState::Pending => "pending",
            DistState::Distributing => "distributing",
            DistState::Converged => "converged",
            DistState::Unknown => "unknown",
        }
    }

    fn parse(text: &str) -> Option<Self> {
        match text {
            "pending" => Some(DistState::Pending),
            "distributing" => Some(DistState::Distributing),
            "converged" => Some(DistState::Converged),
            "unknown" => Some(DistState::Unknown),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OperationDistribution {
    pub state: DistState,
    pub rs_epoch: u32,
    pub network: u64,
    pub object_sha256: [u8; 32],
    pub targets: Vec<DistributionTarget>,
    /// Members beyond [`DISTRIBUTION_TARGET_MAX`]: counted `unknown`.
    pub overflow: u32,
}

impl OperationDistribution {
    pub fn counts(&self) -> (u64, u64, u64, u64) {
        let mut applied = 0_u64;
        let mut retired = 0_u64;
        let mut unknown = u64::from(self.overflow);
        for target in &self.targets {
            match target.state {
                TargetState::Applied => applied += 1,
                TargetState::Retired => retired += 1,
                TargetState::Pending | TargetState::Unknown => unknown += 1,
            }
        }
        (applied, retired, unknown, applied + retired + unknown)
    }

    pub fn doc(&self) -> String {
        let targets = self
            .targets
            .iter()
            .map(DistributionTarget::doc)
            .collect::<Vec<_>>()
            .join(",");
        format!(
            "{{\"state\":\"{}\",\"rs_epoch\":{},\"network\":\"{}\",\"object_sha256\":\"{}\",\"overflow\":{},\"targets\":[{targets}]}}",
            self.state.name(),
            self.rs_epoch,
            h16(self.network),
            hex_lower(&self.object_sha256),
            self.overflow,
        )
    }

    pub fn from_doc(json: &Json) -> Option<Self> {
        let targets = json
            .get("targets")?
            .as_array()?
            .iter()
            .map(DistributionTarget::from_doc)
            .collect::<Option<Vec<_>>>()?;
        if targets.len() > DISTRIBUTION_TARGET_MAX {
            return None;
        }
        let sha = parse_hex(json.get("object_sha256")?.as_str()?, 32)?;
        Some(Self {
            state: DistState::parse(json.get("state")?.as_str()?)?,
            rs_epoch: u32::try_from(json.get("rs_epoch")?.as_u64()?).ok()?,
            network: parse_h16(json.get("network")?.as_str()?)?,
            object_sha256: sha.try_into().ok()?,
            targets,
            overflow: u32::try_from(json.get("overflow")?.as_u64()?).ok()?,
        })
    }
}

/// One queued object send (RAM-only; rebuilt from the snapshot).
pub struct OutboundRrs {
    pub op: u64,
    pub node: u64,
    pub due_ms: u64,
}

/// (entries by epoch, digests by epoch, latest object bytes).
pub(super) type RrsHistory = (
    BTreeMap<u32, Vec<RevocationEntry>>,
    BTreeMap<u32, [u8; 32]>,
    Vec<u8>,
);

/// Decodes the durable RRS1 history for ACK validation and coalescing.
pub(super) fn decode_rrs_history(snapshot: &super::store::Snapshot) -> Result<RrsHistory, String> {
    let mut history = BTreeMap::new();
    let mut digests = BTreeMap::new();
    let mut latest = Vec::new();
    let mut latest_epoch = 0;
    for (epoch, object) in &snapshot.rrs {
        let set = super::revocation_object_decode(object)
            .map_err(|e| format!("stored RRS1 corrupt: {e}"))?;
        digests.insert(*epoch, super::sha256(object));
        history.insert(*epoch, set.entries);
        if *epoch >= latest_epoch {
            latest_epoch = *epoch;
            latest = object.clone();
        }
    }
    Ok((history, digests, latest))
}

impl SiteAuthority {
    /// Installs the RRS1 transport (the P5 authority channel; tests
    /// inject a fake). `None` is the production PR-A state: nothing is
    /// sent and every target honestly stays `unknown`.
    pub fn set_rrs_transport(&mut self, transport: Option<Box<dyn RevocationTransport + Send>>) {
        self.rrs_transport = transport;
    }

    /// Snapshots the surviving members as distribution targets for a
    /// freshly committed revoke. Sorted by node, capped at
    /// [`DISTRIBUTION_TARGET_MAX`] with the rest counted as `overflow`.
    pub(super) fn snapshot_targets(
        &self,
        removed: u64,
        rs_epoch: u32,
        object_sha256: [u8; 32],
    ) -> OperationDistribution {
        let mut members: Vec<u64> = self
            .devices
            .values()
            .filter(|row| row.member && row.node != removed)
            .map(|row| row.node)
            .collect();
        members.sort_unstable();
        let overflow = members.len().saturating_sub(DISTRIBUTION_TARGET_MAX);
        let targets = members
            .into_iter()
            .take(DISTRIBUTION_TARGET_MAX)
            .map(|node| {
                let row = &self.devices[&node];
                DistributionTarget {
                    node,
                    kid: row.kid,
                    generation: row.generation,
                    network: self.id.network,
                    state: TargetState::Pending,
                    attempts: 0,
                    next_retry_ms: 0,
                    ack_rs_epoch: None,
                }
            })
            .collect();
        OperationDistribution {
            state: DistState::Pending,
            rs_epoch,
            network: self.id.network,
            object_sha256,
            targets,
            overflow: overflow as u32,
        }
    }

    /// Previews `node` retired in every open distribution (a later
    /// revoke removed it: no ACK is owed anymore). Pure: the caller folds
    /// the returned operations into its own commit.
    pub(super) fn retired_operations(&self, node: u64) -> Vec<super::records::Operation> {
        let mut out = Vec::new();
        for op in self.operations.values() {
            let mut updated = match op.distribution.as_ref() {
                Some(dist) if dist.state != DistState::Converged => op.clone(),
                _ => continue,
            };
            let mut changed = false;
            if let Some(dist) = updated.distribution.as_mut() {
                for target in dist.targets.iter_mut() {
                    if target.node == node
                        && matches!(target.state, TargetState::Pending | TargetState::Unknown)
                    {
                        target.state = TargetState::Retired;
                        changed = true;
                    }
                }
                if changed && dist.counts().2 == 0 {
                    dist.state = DistState::Converged;
                }
            }
            if changed {
                out.push(updated);
            }
        }
        out
    }

    fn refresh_distribution_state(&mut self, op: u64) {
        let converged = self
            .operations
            .get(&op)
            .and_then(|o| o.distribution.as_ref())
            .is_some_and(|dist| dist.counts().2 == 0);
        if !converged {
            return;
        }
        if let Some(operation) = self.operations.get_mut(&op) {
            if let Some(dist) = operation.distribution.as_mut() {
                dist.state = DistState::Converged;
            }
        }
    }

    /// Writes one operation doc back after distribution progress. This is
    /// a pure update: unlike `operation_doc` (commit path) it never moves
    /// the op allocator and never evicts siblings.
    fn persist_operation(&mut self, op: u64, now_ms: u64) {
        let Some(operation) = self.operations.get(&op).cloned() else {
            return;
        };
        let batch = Batch {
            docs: vec![(DocKind::Operation, h16(operation.id), Some(operation.doc()))],
            ..Batch::default()
        };
        if self.store.commit(&batch).is_err() {
            // The RAM mirror stays ahead; the next successful write-back
            // carries the same state — distribution progress is never
            // lost, only delayed.
            self.counters.store_failures += 1;
            let _ = now_ms;
        }
    }

    /// The distribution half of [`SiteAuthority::tick`]: queues due
    /// targets into the shared outbox and dispatches at most 10 objects
    /// per second, newest operation first (an ACK for a newer set
    /// coalesces onto older operations, so older sends give way).
    pub(super) fn tick_distribution(&mut self, now_ms: u64) {
        // Convergence is transport-agnostic (an empty snapshot converges
        // with no transport at all); only queueing and dispatch need one.
        self.converge_distributions(now_ms);
        if self.rrs_transport.is_none() {
            return;
        }
        // Queue due targets, newest operation first.
        let mut ops: Vec<u64> = self.operations.keys().copied().collect();
        ops.sort_by_key(|id| std::cmp::Reverse(*id));
        for id in ops {
            if self.rrs_outbox.len() >= DISTRIBUTION_OUTBOX_MAX {
                break;
            }
            let dist = match self
                .operations
                .get(&id)
                .and_then(|op| op.distribution.as_ref())
            {
                Some(dist) => dist,
                None => continue,
            };
            if dist.state == DistState::Converged {
                continue;
            }
            let mut queue = Vec::new();
            for target in &dist.targets {
                if self.rrs_outbox.len() + queue.len() >= DISTRIBUTION_OUTBOX_MAX {
                    break;
                }
                if !matches!(target.state, TargetState::Pending | TargetState::Unknown) {
                    continue;
                }
                if target.attempts >= DISTRIBUTION_ATTEMPTS_MAX {
                    continue;
                }
                if target.state == TargetState::Unknown && target.next_retry_ms > now_ms {
                    continue;
                }
                if self
                    .rrs_outbox
                    .iter()
                    .any(|o| o.op == id && o.node == target.node)
                {
                    continue;
                }
                // Coalesce: a target that already proved a newer set for
                // the same network owes this older operation nothing.
                if self.target_proved_newer(target.node, dist.rs_epoch, dist.network) {
                    continue;
                }
                queue.push(target.node);
            }
            for node in queue {
                self.rrs_outbox.push_back(OutboundRrs {
                    op: id,
                    node,
                    due_ms: now_ms,
                });
            }
        }
        // Dispatch the outbox head at the paced rate.
        let mut sent: Vec<(u64, u64)> = Vec::new();
        while now_ms >= self.rrs_next_dispatch_ms {
            let Some(head) = self.rrs_outbox.pop_front() else {
                break;
            };
            if head.due_ms > now_ms {
                self.rrs_outbox.push_front(head);
                break;
            }
            if !self.target_still_due(head.op, head.node, now_ms) {
                continue; // converged/retired/applied meanwhile: drop, no airtime
            }
            let object = self.rrs_latest_object.clone();
            let delivered = match self.rrs_transport.as_mut() {
                Some(transport) => transport.send_rrs(head.node, &object),
                None => false,
            };
            if !delivered {
                // Transport refusal backs the whole outbox off (5..60 s
                // capped); the target keeps its attempt and retries.
                let level =
                    (self.rrs_transport_backoff as usize).min(DISTRIBUTION_BACKOFF_S.len() - 1);
                let wait = DISTRIBUTION_BACKOFF_S[level].saturating_mul(1000);
                self.rrs_next_dispatch_ms = now_ms.saturating_add(wait);
                self.rrs_transport_backoff = self.rrs_transport_backoff.saturating_add(1);
                let due = self.rrs_next_dispatch_ms;
                self.rrs_outbox.push_front(OutboundRrs {
                    due_ms: due,
                    ..head
                });
                break;
            }
            self.rrs_transport_backoff = 0;
            self.rrs_next_dispatch_ms = now_ms.saturating_add(DISTRIBUTION_DISPATCH_GAP_MS);
            sent.push((head.op, head.node));
        }
        let mut touched: Vec<u64> = sent.iter().map(|(op, _)| *op).collect();
        touched.sort_unstable();
        touched.dedup();
        for (op, node) in sent {
            self.note_sent(op, node, now_ms);
        }
        for id in touched {
            self.persist_operation(id, now_ms);
        }
        // Converge what the sends (and coalescing) completed.
        self.converge_distributions(now_ms);
    }

    fn converge_distributions(&mut self, now_ms: u64) {
        let ids: Vec<u64> = self.operations.keys().copied().collect();
        for id in ids {
            let dirty = self
                .operations
                .get(&id)
                .and_then(|op| op.distribution.as_ref())
                .is_some_and(|dist| dist.counts().2 == 0 && dist.state != DistState::Converged);
            if dirty {
                self.refresh_distribution_state(id);
                self.persist_operation(id, now_ms);
            }
        }
    }

    fn target_still_due(&self, op: u64, node: u64, now_ms: u64) -> bool {
        match self
            .operations
            .get(&op)
            .and_then(|o| o.distribution.as_ref())
        {
            Some(dist) => dist.targets.iter().any(|t| {
                t.node == node
                    && matches!(t.state, TargetState::Pending | TargetState::Unknown)
                    && t.attempts < DISTRIBUTION_ATTEMPTS_MAX
                    && (t.state == TargetState::Pending || t.next_retry_ms <= now_ms)
            }),
            None => false,
        }
    }

    /// True when `node` proved any same-network set newer than `rs_epoch`
    /// in a remembered operation (send/ACK coalescing).
    fn target_proved_newer(&self, node: u64, rs_epoch: u32, network: u64) -> bool {
        self.operations.values().any(|op| {
            op.distribution.as_ref().is_some_and(|dist| {
                dist.network == network
                    && dist.targets.iter().any(|t| {
                        t.node == node
                            && t.state == TargetState::Applied
                            && t.ack_rs_epoch.is_some_and(|e| e > rs_epoch)
                    })
            })
        })
    }

    fn note_sent(&mut self, op: u64, node: u64, now_ms: u64) {
        let Some(operation) = self.operations.get_mut(&op) else {
            return;
        };
        let Some(dist) = operation.distribution.as_mut() else {
            return;
        };
        if dist.state == DistState::Pending {
            dist.state = DistState::Distributing;
        }
        for target in dist.targets.iter_mut() {
            if target.node != node {
                continue;
            }
            if !matches!(target.state, TargetState::Pending | TargetState::Unknown) {
                continue;
            }
            target.state = TargetState::Unknown;
            target.attempts += 1;
            let wait = DISTRIBUTION_BACKOFF_S
                [(target.attempts as usize - 1).min(DISTRIBUTION_BACKOFF_S.len() - 1)]
            .saturating_mul(1000);
            target.next_retry_ms = now_ms.saturating_add(wait);
        }
    }

    /// Records an Applied ACK from a device (called by the P5 authority
    /// channel with the context-bound node/generation/network). The ACK
    /// counts for an operation only when the acknowledged set covers the
    /// operation's set on the same network; anything else is ignored.
    /// Returns true when at least one target moved to `applied`.
    pub fn handle_rrs_applied(
        &mut self,
        node: u64,
        generation: u32,
        network: u64,
        rs_epoch: u32,
        object_sha256: &[u8; 32],
        now_ms: u64,
    ) -> bool {
        let live = match self.devices.get(&node) {
            Some(row) => row.member && row.generation == generation,
            None => false,
        };
        if !live || network != self.id.network {
            return false;
        }
        let Some(acked) = self.rrs_history.get(&rs_epoch).cloned() else {
            return false;
        };
        // The ACK must name the exact issued bytes, not just the epoch.
        if self.rrs_history_digests.get(&rs_epoch) != Some(object_sha256) {
            return false;
        }
        let mut moved = false;
        let ids: Vec<u64> = self.operations.keys().copied().collect();
        for id in ids {
            let covers = match self.operations.get(&id) {
                Some(op) => match op.distribution.as_ref() {
                    Some(dist) => {
                        if dist.network != network || dist.rs_epoch > rs_epoch {
                            false
                        } else {
                            match self.rrs_history.get(&dist.rs_epoch) {
                                Some(older) => rrs_covers(older, &acked),
                                None => false,
                            }
                        }
                    }
                    None => false,
                },
                None => continue,
            };
            if !covers {
                continue;
            }
            let changed = match self.operations.get_mut(&id) {
                Some(op) => match op.distribution.as_mut() {
                    Some(dist) => {
                        let mut changed = false;
                        for target in dist.targets.iter_mut() {
                            if target.node == node
                                && matches!(
                                    target.state,
                                    TargetState::Pending | TargetState::Unknown
                                )
                            {
                                target.state = TargetState::Applied;
                                target.ack_rs_epoch = Some(rs_epoch);
                                changed = true;
                            }
                        }
                        changed
                    }
                    None => false,
                },
                None => false,
            };
            if changed {
                moved = true;
                self.refresh_distribution_state(id);
                self.persist_operation(id, now_ms);
            }
        }
        moved
    }

    /// Answers an RRS1 Get from a device (called by the P5 authority
    /// channel). `wanted_rs_epoch` 0 asks for the latest; a floor above
    /// the Host's latest is an integrity error, never a downgrade. On a
    /// site that never revoked, the first Get bootstraps (and durably
    /// commits) the empty baseline set at rs_epoch 1.
    pub fn handle_rrs_get(
        &mut self,
        wanted_rs_epoch: u32,
        now_ms: u64,
    ) -> Result<Vec<u8>, SiteError> {
        if wanted_rs_epoch > self.rs_epoch {
            return Err(SiteError::new(
                "INTEGRITY_ERROR",
                "the requester cites an RRS1 epoch newer than the Host's latest",
            ));
        }
        if self.rs_epoch == 0 {
            self.ensure_baseline_rrs(now_ms)?;
        }
        Ok(self.rrs_latest_object.clone())
    }

    /// Lazily issues the empty baseline RRS1 (rs_epoch 1, no entries, the
    /// current site floor) on a site that never revoked, in its own
    /// transaction. No operation and no event: the set is served on
    /// demand until the first real revoke publishes it.
    fn ensure_baseline_rrs(&mut self, now_ms: u64) -> Result<(), SiteError> {
        if self.rs_epoch != 0 {
            return Ok(());
        }
        let set = super::RevocationSet {
            site_id: self.id.site_id,
            network: self.id.network,
            rs_epoch: 1,
            site_epoch_floor: self.id.site_claims.site_epoch,
            entries: Vec::new(),
        };
        let object = super::revocation_issue(&set, self.sak.as_ref())
            .map_err(|e| SiteError::new("AUTHORITY_ERROR", format!("baseline RRS1 failed: {e}")))?;
        let batch = Batch {
            rrs: vec![(1, object.clone())],
            meta: vec![("rs_epoch", 1_u32.to_be_bytes().to_vec())],
            ..Batch::default()
        };
        if let Err(error) = self.store.commit(&batch) {
            self.store_error(now_ms, &error);
            return Err(super::store_failure(&error));
        }
        self.rs_epoch = 1;
        self.rrs_entries = Vec::new();
        self.rrs_history.insert(1, Vec::new());
        self.rrs_history_digests.insert(1, super::sha256(&object));
        self.rrs_latest_object = object;
        Ok(())
    }

    /// Drops remembered RRS1 history below the oldest remembered
    /// operation (the store keeps every issued object; RAM only needs
    /// what live operations can coalesce against).
    pub(super) fn prune_rrs_history(&mut self) {
        let floor = self
            .operations
            .values()
            .filter_map(|op| op.distribution.as_ref().map(|d| d.rs_epoch))
            .min()
            .unwrap_or(self.rs_epoch);
        self.rrs_history.retain(|epoch, _| *epoch >= floor);
        self.rrs_history_digests.retain(|epoch, _| *epoch >= floor);
    }

    /// Records that the currently staged GK left the Host over P5 (called
    /// by the P5 GK scheduler when distribution starts). The next revoke
    /// then stages a fresh key instead of reusing the exposed one.
    pub fn mark_gk_staged_distributed(&mut self) -> bool {
        if self.gk_staged.is_none() {
            return false;
        }
        let batch = Batch {
            meta: vec![(META_GK_STAGED_DISTRIBUTED, vec![1])],
            ..Batch::default()
        };
        if self.store.commit(&batch).is_err() {
            return false;
        }
        self.gk_staged_distributed = true;
        true
    }
}

pub(super) fn distribution_view(dist: Option<&OperationDistribution>) -> String {
    match dist {
        Some(d) => {
            let (applied, retired, unknown, total) = d.counts();
            format!(
                "{{\"state\":\"{}\",\"applied\":{applied},\"retired\":{retired},\"unknown\":{unknown},\"total\":{total},\"reached\":{applied},\"members\":{total}}}",
                d.state.name(),
            )
        }
        None => "{\"state\":\"unknown\",\"applied\":0,\"retired\":0,\"unknown\":0,\"total\":0,\"reached\":0,\"members\":0}"
            .to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use routeloom_provision::sdkv1::revocation::RevocationReason;

    fn entry(node: u64, generation: u32) -> RevocationEntry {
        RevocationEntry {
            node_id: node,
            min_generation: generation,
            reason: RevocationReason::Lost,
        }
    }

    #[test]
    fn covers_mirrors_the_device_rule() {
        let older = vec![entry(1, 2), entry(7, 3)];
        assert!(rrs_covers(&[], &older));
        assert!(rrs_covers(&older, &older));
        assert!(rrs_covers(&older, &[entry(1, 2), entry(7, 4), entry(9, 1)]));
        assert!(!rrs_covers(&older, &[entry(1, 2)]));
        assert!(!rrs_covers(&older, &[entry(1, 2), entry(7, 2)]));
    }

    #[test]
    fn checked_next_stops_before_wrap() {
        assert_eq!(checked_next(41, "rs_epoch").unwrap(), 42);
        assert_eq!(
            checked_next(u32::MAX, "rs_epoch").unwrap_err().code,
            "COUNTER_EXHAUSTED"
        );
    }

    #[test]
    fn snapshot_caps_targets_and_counts_overflow() {
        let mut auth = super::super::testkit::authority(
            Box::<super::super::store::MemoryStore>::default(),
            1_790_000_000_000,
        );
        for i in 0..140_u64 {
            let node = 0x00A1_0000_0001_0000 + i;
            auth.devices.insert(
                node,
                super::super::store::DeviceRow {
                    node,
                    member: true,
                    generation: 1,
                    ..Default::default()
                },
            );
        }
        let dist = auth.snapshot_targets(0x00A1_0000_0001_0000, 9, [0x11; 32]);
        assert_eq!(dist.targets.len(), DISTRIBUTION_TARGET_MAX);
        assert_eq!(dist.overflow, 139 - DISTRIBUTION_TARGET_MAX as u32);
        // Every survivor counts unknown: tracked targets plus overflow.
        assert_eq!(dist.counts(), (0, 0, 139, 139));
        // First-node-wins order: the lowest survivors are tracked.
        assert_eq!(dist.targets[0].node, 0x00A1_0000_0001_0001);
    }

    #[test]
    fn distribution_doc_round_trip() {
        let dist = OperationDistribution {
            state: DistState::Distributing,
            rs_epoch: 15,
            network: 0x0003_0000_0A1B_2C3D,
            object_sha256: [0xAB; 32],
            targets: vec![
                DistributionTarget {
                    node: 0x00A1_0000_0000_7001,
                    kid: [0xCD; 32],
                    generation: 3,
                    network: 0x0003_0000_0A1B_2C3D,
                    state: TargetState::Applied,
                    attempts: 1,
                    next_retry_ms: 555,
                    ack_rs_epoch: Some(15),
                },
                DistributionTarget {
                    node: 0x00A1_0000_0000_7002,
                    kid: [0xEF; 32],
                    generation: 1,
                    network: 0x0003_0000_0A1B_2C3D,
                    state: TargetState::Unknown,
                    attempts: 3,
                    next_retry_ms: 777,
                    ack_rs_epoch: None,
                },
            ],
            overflow: 2,
        };
        let text = dist.doc();
        let json = routeloom_json::parse(&text).unwrap();
        assert_eq!(OperationDistribution::from_doc(&json).unwrap(), dist);
        assert_eq!(dist.counts(), (1, 0, 3, 4));
        assert!(distribution_view(Some(&dist)).contains("\"state\":\"distributing\""));
        assert!(distribution_view(None).contains("\"state\":\"unknown\""));
    }
}
